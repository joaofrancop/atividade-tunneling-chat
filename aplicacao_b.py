"""
Aplicação B — Cliente do chat seguro (requisito a do enunciado).

Papel:
  - Conecta à Aplicação A pelo endereço/porta informados
  - Inicia o tunneling RSA e troca mensagens criptografadas
  - Exibe o chat na tela (requisito b do enunciado)

Execute DEPOIS da aplicacao_a.py estar aguardando conexão.
"""

import argparse

from interface_chat import executar_chat


def main() -> None:
    parser = argparse.ArgumentParser(description="Aplicação B — Chat criptografado (cliente)")
    parser.add_argument("--host", default="127.0.0.1", help="Endereço do servidor (padrão: 127.0.0.1)")
    parser.add_argument("--porta", type=int, default=5555, help="Porta TCP (padrão: 5555)")
    args = parser.parse_args()

    executar_chat(
        titulo="Aplicação B — Chat Seguro (Cliente)",
        nome_usuario="Aplicação B",
        modo="cliente",
        host=args.host,
        porta=args.porta,
        tema="b",
    )


if __name__ == "__main__":
    main()
