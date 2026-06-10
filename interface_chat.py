"""Interface gráfica do chat seguro (duas aplicações, formato chat online)."""

import threading
from datetime import datetime
from tkinter import messagebox
from typing import Optional

import customtkinter as ctk

from protocolo import SessaoChat

# Cores distintas para diferenciar Aplicação A (azul) e B (roxo) na apresentação
TEMAS = {
    "a": {
        "accent": "#0ea5e9",
        "accent_hover": "#0284c7",
        "bubble_own": "#0369a1",
        "bubble_peer": "#1e293b",
        "header": "#0c4a6e",
        "badge": "#38bdf8",
    },
    "b": {
        "accent": "#8b5cf6",
        "accent_hover": "#7c3aed",
        "bubble_own": "#6d28d9",
        "bubble_peer": "#1e293b",
        "header": "#4c1d95",
        "badge": "#a78bfa",
    },
}


class JanelaChat(ctk.CTk):
    """Janela principal do chat — exibe mensagens, status do túnel e autenticação."""

    def __init__(self, titulo: str, nome_usuario: str, modo: str, host: str, porta: int, tema: str = "a"):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.tema = TEMAS.get(tema, TEMAS["a"])
        self.title(titulo)
        self.geometry("720x680")
        self.minsize(520, 480)
        self.configure(fg_color="#0f172a")

        self.nome_usuario = nome_usuario
        self.modo = modo
        self.host = host
        self.porta = porta
        self.sessao: Optional[SessaoChat] = None
        self._conectado = False

        self._montar_interface()
        self._exibir_mensagem(
            "Sistema",
            "Aguardando conexão...\n"
            + ("Inicie a Aplicação B em outro terminal:\npython aplicacao_b.py"
               if modo == "servidor"
               else f"Conectando ao servidor em {host}:{porta}..."),
        )
        # Conexão roda em thread separada para não travar a interface
        threading.Thread(target=self._iniciar_conexao, daemon=True).start()

    def _montar_interface(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._montar_cabecalho()
        self._montar_area_chat()
        self._montar_entrada()
        self.protocol("WM_DELETE_WINDOW", self._fechar)

    def _montar_cabecalho(self) -> None:
        header = ctk.CTkFrame(self, fg_color=self.tema["header"], corner_radius=0, height=96)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        icone = ctk.CTkLabel(header, text="🔒", font=ctk.CTkFont(size=28))
        icone.grid(row=0, column=0, rowspan=2, padx=(20, 12), pady=16)

        papel = "Servidor" if self.modo == "servidor" else "Cliente"
        ctk.CTkLabel(
            header,
            text=self.nome_usuario,
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color="#f8fafc",
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(18, 0))

        # Destaca os 4 conceitos da disciplina no cabeçalho
        ctk.CTkLabel(
            header,
            text=f"{papel}  ·  RSA  ·  SHA-256  ·  Tunneling  ·  {self.host}:{self.porta}",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#cbd5e1",
            anchor="w",
        ).grid(row=1, column=1, sticky="nw", pady=(2, 16))

        self.indicador_status = ctk.CTkLabel(
            header,
            text="● Aguardando",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#fbbf24",
            fg_color="#1e293b",
            corner_radius=20,
            width=130,
            height=32,
        )
        self.indicador_status.grid(row=0, column=2, rowspan=2, padx=20, pady=16)

    def _montar_area_chat(self) -> None:
        container = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=16)
        container.grid(row=1, column=0, sticky="nsew", padx=16, pady=(12, 8))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self.chat_frame = ctk.CTkScrollableFrame(
            container,
            fg_color="#0f172a",
            corner_radius=12,
            scrollbar_button_color=self.tema["accent"],
            scrollbar_button_hover_color=self.tema["accent_hover"],
        )
        self.chat_frame.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.chat_frame.grid_columnconfigure(0, weight=1)

    def _montar_entrada(self) -> None:
        barra = ctk.CTkFrame(self, fg_color="transparent")
        barra.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 16))
        barra.grid_columnconfigure(0, weight=1)

        self.campo_mensagem = ctk.CTkEntry(
            barra,
            placeholder_text="Aguardando conexão...",
            height=44,
            corner_radius=22,
            border_width=2,
            border_color="#334155",
            fg_color="#1e293b",
            text_color="#f1f5f9",
            font=ctk.CTkFont(family="Segoe UI", size=14),
            state="disabled",
        )
        self.campo_mensagem.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.campo_mensagem.bind("<Return>", lambda _: self._enviar())

        self.botao_enviar = ctk.CTkButton(
            barra,
            text="Enviar  ➤",
            width=110,
            height=44,
            corner_radius=22,
            fg_color=self.tema["accent"],
            hover_color=self.tema["accent_hover"],
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self._enviar,
            state="disabled",
        )
        self.botao_enviar.grid(row=0, column=1)

        # Barra inferior: mostra o passo atual do tunneling / autenticação
        self.label_status = ctk.CTkLabel(
            self,
            text="Inicializando...",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#64748b",
            anchor="w",
        )
        self.label_status.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 10))

    def _iniciar_conexao(self) -> None:
        try:
            self.sessao = SessaoChat(
                nome_local=self.nome_usuario,
                on_mensagem=lambda r, t, h, a: self.after(0, self._exibir_mensagem, r, t, h, a),
                on_status=lambda msg: self.after(0, self._atualizar_status, msg),
            )
            if self.modo == "servidor":
                self.sessao.iniciar_servidor(self.host, self.porta)
            else:
                self.sessao.conectar(self.host, self.porta)

            self.after(0, self._habilitar_chat)
            self.after(
                0,
                self._exibir_mensagem,
                "Sistema",
                "Túnel seguro estabelecido.\n"
                "Mensagens: criptografadas (AES) + hash SHA-256 + assinatura RSA.",
            )
        except OSError as exc:
            self.after(0, lambda: messagebox.showerror("Erro de conexão", str(exc)))
            self.after(0, self._atualizar_status, f"Erro: {exc}", conectado=False)
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Erro", str(exc)))
            self.after(0, self._atualizar_status, f"Erro: {exc}", conectado=False)

    def _habilitar_chat(self) -> None:
        self._conectado = True
        self.campo_mensagem.configure(state="normal", placeholder_text="Digite sua mensagem...")
        self.botao_enviar.configure(state="normal")
        self.campo_mensagem.focus_set()

    def _atualizar_status(self, mensagem: str, conectado: Optional[bool] = None) -> None:
        self.label_status.configure(text=mensagem)

        if conectado is None:
            conectado = "ativo" in mensagem.lower() or "estabelecida" in mensagem.lower()

        if "erro" in mensagem.lower() or "perdida" in mensagem.lower():
            self.indicador_status.configure(text="● Offline", text_color="#f87171")
        elif conectado or "ativo" in mensagem.lower() or "pronto" in mensagem.lower():
            self.indicador_status.configure(text="● Seguro", text_color="#4ade80")
        elif "aguardando" in mensagem.lower():
            self.indicador_status.configure(text="● Aguardando", text_color="#fbbf24")
        elif "negociando" in mensagem.lower() or "conectando" in mensagem.lower() or "tunneling" in mensagem.lower():
            self.indicador_status.configure(text="● Tunneling", text_color="#38bdf8")

    def _exibir_mensagem(
        self,
        remetente: str,
        texto: str,
        hash_sha256: Optional[str] = None,
        autenticada: Optional[bool] = None,
    ) -> None:
        is_system = remetente == "Sistema"
        is_own = remetente == self.nome_usuario

        linha = ctk.CTkFrame(self.chat_frame, fg_color="transparent")
        linha.grid_columnconfigure(0, weight=1)
        linha.pack(fill="x", padx=6, pady=4)

        if is_system:
            bubble = ctk.CTkFrame(linha, fg_color="#334155", corner_radius=14)
            bubble.pack(anchor="center", padx=40)
            ctk.CTkLabel(
                bubble,
                text=f"ℹ  {texto}",
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color="#cbd5e1",
                wraplength=420,
                justify="center",
            ).pack(padx=16, pady=10)
        else:
            alinhamento = "e" if is_own else "w"
            cor_bubble = self.tema["bubble_own"] if is_own else self.tema["bubble_peer"]

            coluna = ctk.CTkFrame(linha, fg_color="transparent")
            coluna.pack(anchor=alinhamento, fill="x")

            autor = "Você" if is_own else remetente
            hora = datetime.now().strftime("%H:%M")
            ctk.CTkLabel(
                coluna,
                text=f"{autor}  ·  {hora}",
                font=ctk.CTkFont(family="Segoe UI", size=10),
                text_color="#64748b",
                anchor=alinhamento,
            ).pack(anchor=alinhamento, padx=4, pady=(0, 2))

            bubble = ctk.CTkFrame(coluna, fg_color=cor_bubble, corner_radius=18)
            bubble.pack(anchor=alinhamento)

            ctk.CTkLabel(
                bubble,
                text=texto,
                font=ctk.CTkFont(family="Segoe UI", size=14),
                text_color="#f8fafc",
                wraplength=380,
                justify="left" if not is_own else "right",
                anchor="w",
            ).pack(padx=16, pady=(10, 4))

            # Exibe hash SHA-256 e status da assinatura RSA (autenticador de documentos)
            if hash_sha256:
                if autenticada is True:
                    selo = "✓ Autenticada (SHA-256 + RSA)"
                    cor_selo = "#4ade80"
                elif autenticada is False:
                    selo = "✗ Assinatura inválida"
                    cor_selo = "#f87171"
                else:
                    selo = "SHA-256 calculado"
                    cor_selo = "#94a3b8"

                hash_curto = f"{hash_sha256[:12]}...{hash_sha256[-8:]}"
                ctk.CTkLabel(
                    bubble,
                    text=f"{selo}  ·  hash: {hash_curto}",
                    font=ctk.CTkFont(family="Consolas", size=9),
                    text_color=cor_selo,
                    anchor="w",
                ).pack(padx=16, pady=(0, 10))

        self.after(50, self._rolar_para_fim)

    def _rolar_para_fim(self) -> None:
        try:
            self.chat_frame._parent_canvas.yview_moveto(1.0)
        except AttributeError:
            pass

    def _enviar(self) -> None:
        texto = self.campo_mensagem.get().strip()
        if not texto or not self.sessao or not self._conectado:
            return
        try:
            hash_sha256, _ = self.sessao.enviar_mensagem(texto)
            # Mensagem própria: hash exibido; autenticada=None (não precisa verificar a si mesmo)
            self._exibir_mensagem(self.nome_usuario, texto, hash_sha256, None)
            self.campo_mensagem.delete(0, "end")
        except Exception as exc:
            messagebox.showerror("Erro ao enviar", str(exc))

    def _fechar(self) -> None:
        if self.sessao:
            self.sessao.encerrar()
        self.destroy()


def executar_chat(
    titulo: str,
    nome_usuario: str,
    modo: str,
    host: str = "127.0.0.1",
    porta: int = 5555,
    tema: str = "a",
) -> None:
    app = JanelaChat(titulo, nome_usuario, modo, host, porta, tema=tema)
    app.mainloop()
