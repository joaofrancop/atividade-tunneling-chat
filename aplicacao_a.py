"""
Aplicação A — Servidor do chat seguro (requisito a do enunciado).

Papel:
  - Escuta conexões TCP na porta configurada
  - Aguarda a Aplicação B conectar
  - Participa da negociação RSA (tunneling) e exibe o chat na tela

Execute PRIMEIRO esta aplicação, depois a aplicacao_b.py.
"""

import argparse

from interface_chat import executar_chat


def main() -> None:
    parser = argparse.ArgumentParser(description="Aplicação A — Chat criptografado (servidor)")
    parser.add_argument("--host", default="127.0.0.1", help="Endereço de escuta (padrão: 127.0.0.1)")
    parser.add_argument("--porta", type=int, default=5555, help="Porta TCP (padrão: 5555)")
    args = parser.parse_args()

    executar_chat(
        titulo="Aplicação A — Chat Seguro (Servidor)",
        nome_usuario="Aplicação A",
        modo="servidor",
        host=args.host,
        porta=args.porta,
        tema="a",
    )


if __name__ == "__main__":
    main()
