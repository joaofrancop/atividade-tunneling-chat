"""
Protocolo de rede: tunneling com RSA e troca de mensagens criptografadas.

Fluxo do túnel seguro (tunneling):
  1. Troca de chaves públicas RSA entre as duas aplicações
  2. Cliente gera chave AES e envia criptografada com RSA do servidor
  3. A partir daí, todo tráfego trafega dentro do túnel AES-GCM
  4. Cada mensagem também leva hash SHA-256 + assinatura RSA (autenticador)
"""

import json
import socket
import struct
import threading
from typing import Callable, Optional

from autenticador_documentos import autenticar_documento, verificar_documento
from crypto_utils import (
    chave_publica_de_pem,
    chave_publica_para_pem,
    criptografar_chave_simetrica,
    criptografar_mensagem,
    descriptografar_chave_simetrica,
    descriptografar_mensagem,
    gerar_chave_aes,
    gerar_par_chaves,
)


def enviar_json(sock: socket.socket, payload: dict) -> None:
    """Envia um dicionário JSON com prefixo de 4 bytes indicando o tamanho."""
    dados = json.dumps(payload).encode("utf-8")
    sock.sendall(struct.pack("!I", len(dados)) + dados)


def receber_json(sock: socket.socket) -> dict:
    """Recebe um pacote JSON (tamanho + conteúdo) do socket."""
    tamanho_bytes = _recv_exact(sock, 4)
    tamanho = struct.unpack("!I", tamanho_bytes)[0]
    dados = _recv_exact(sock, tamanho)
    return json.loads(dados.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Garante leitura de exatamente n bytes (TCP pode entregar em partes)."""
    buffer = b""
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo peer.")
        buffer += chunk
    return buffer


class SessaoChat:
    """
    Gerencia conexão TCP, negociação RSA (tunneling) e envio/recebimento seguro.

    on_mensagem(remetente, texto, hash_sha256, autenticada)
    """

    def __init__(
        self,
        nome_local: str,
        on_mensagem: Callable[[str, str, Optional[str], Optional[bool]], None],
        on_status: Callable[[str], None],
    ):
        self.nome_local = nome_local
        self.on_mensagem = on_mensagem
        self.on_status = on_status
        self._sock: Optional[socket.socket] = None
        # Cada aplicação gera seu próprio par RSA ao iniciar
        self._chave_privada, self._chave_publica = gerar_par_chaves()
        self._chave_publica_peer = None
        self._chave_aes_sessao: Optional[bytes] = None
        self._thread_recebimento: Optional[threading.Thread] = None
        self._ativo = False

    def iniciar_servidor(self, host: str, porta: int) -> None:
        """Aplicação A: escuta na porta e aguarda o cliente conectar."""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((host, porta))
        servidor.listen(1)
        self.on_status(f"Aguardando conexão em {host}:{porta}...")
        self._sock, endereco = servidor.accept()
        servidor.close()
        self.on_status(f"Conexão estabelecida com {endereco[0]}:{endereco[1]}")
        self._negociar_chaves(iniciador=False)
        self._iniciar_recebimento()

    def conectar(self, host: str, porta: int) -> None:
        """Aplicação B: conecta ao servidor e abre o túnel."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.on_status(f"Conectando a {host}:{porta}...")
        self._sock.connect((host, porta))
        self.on_status("Conexão TCP estabelecida.")
        self._negociar_chaves(iniciador=True)
        self._iniciar_recebimento()

    def _negociar_chaves(self, iniciador: bool) -> None:
        """
        Tunneling com RSA — fase de abertura do túnel seguro.

        Passo 1: troca de chaves públicas RSA
        Passo 2: chave AES enviada criptografada com RSA (só o destinatário abre)
        """
        assert self._sock is not None
        self.on_status("Tunneling: negociando chaves RSA...")

        # --- Fase 1: troca de chaves públicas RSA ---
        if iniciador:
            enviar_json(self._sock, {"tipo": "pubkey", "chave": chave_publica_para_pem(self._chave_publica)})
            resposta = receber_json(self._sock)
        else:
            resposta = receber_json(self._sock)
            enviar_json(self._sock, {"tipo": "pubkey", "chave": chave_publica_para_pem(self._chave_publica)})

        if resposta.get("tipo") != "pubkey":
            raise ValueError("Resposta inválida na negociação de chaves.")

        self._chave_publica_peer = chave_publica_de_pem(resposta["chave"])
        self.on_status("Chaves públicas RSA trocadas.")

        # --- Fase 2: chave de sessão AES protegida por RSA (abertura do túnel) ---
        self._chave_aes_sessao = gerar_chave_aes()
        chave_cifrada = criptografar_chave_simetrica(self._chave_aes_sessao, self._chave_publica_peer)

        if iniciador:
            enviar_json(self._sock, {"tipo": "session_key", "chave": chave_cifrada})
            confirmacao = receber_json(self._sock)
        else:
            pacote = receber_json(self._sock)
            if pacote.get("tipo") != "session_key":
                raise ValueError("Pacote de chave de sessão inválido.")
            self._chave_aes_sessao = descriptografar_chave_simetrica(pacote["chave"], self._chave_privada)
            enviar_json(self._sock, {"tipo": "session_ok"})
            confirmacao = {"tipo": "session_ok"}

        if confirmacao.get("tipo") != "session_ok":
            raise ValueError("Falha ao confirmar chave de sessão.")

        self.on_status("Túnel seguro ativo (RSA + AES-GCM). Pronto para chat.")

    def _iniciar_recebimento(self) -> None:
        """Inicia thread que fica escutando mensagens do peer."""
        self._ativo = True
        self._thread_recebimento = threading.Thread(target=self._loop_recebimento, daemon=True)
        self._thread_recebimento.start()

    def _loop_recebimento(self) -> None:
        """Recebe pacotes do túnel, descriptografa e verifica autenticidade."""
        assert self._sock is not None and self._chave_aes_sessao is not None
        try:
            while self._ativo:
                pacote = receber_json(self._sock)
                if pacote.get("tipo") == "mensagem":
                    # Descriptografa conteúdo que veio pelo túnel AES
                    texto = descriptografar_mensagem(pacote["conteudo"], self._chave_aes_sessao)
                    remetente = pacote.get("remetente", "Peer")

                    # Verifica hash SHA-256 + assinatura RSA (autenticador de documentos)
                    hash_recebido = pacote.get("hash_sha256", "")
                    assinatura = pacote.get("assinatura_rsa", "")
                    autenticada = False
                    if self._chave_publica_peer and hash_recebido and assinatura:
                        autenticada = verificar_documento(
                            texto, hash_recebido, assinatura, self._chave_publica_peer
                        )

                    self.on_mensagem(remetente, texto, hash_recebido, autenticada)
                elif pacote.get("tipo") == "desconectar":
                    self.on_status("Peer encerrou a conversa.")
                    break
        except (ConnectionError, OSError, json.JSONDecodeError):
            if self._ativo:
                self.on_status("Conexão perdida.")
        finally:
            self._ativo = False

    def enviar_mensagem(self, texto: str) -> tuple[str, str]:
        """
        Envia mensagem pelo túnel seguro.

        1. Calcula hash SHA-256 e assina com RSA (autenticador)
        2. Criptografa o texto com AES-GCM (tráfego dentro do túnel)
        """
        if not self._ativo or self._sock is None or self._chave_aes_sessao is None:
            raise RuntimeError("Sessão não está pronta para envio.")

        # Autenticador de documentos: SHA-256 + assinatura RSA
        hash_sha256, assinatura_rsa = autenticar_documento(texto, self._chave_privada)

        # Criptografia da mensagem dentro do túnel
        conteudo_cifrado = criptografar_mensagem(texto, self._chave_aes_sessao)

        enviar_json(
            self._sock,
            {
                "tipo": "mensagem",
                "remetente": self.nome_local,
                "conteudo": conteudo_cifrado,
                "hash_sha256": hash_sha256,
                "assinatura_rsa": assinatura_rsa,
            },
        )
        return hash_sha256, assinatura_rsa

    def encerrar(self) -> None:
        """Fecha o túnel e encerra a conexão TCP."""
        self._ativo = False
        if self._sock:
            try:
                enviar_json(self._sock, {"tipo": "desconectar"})
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
