# Atividade Prática — Sistema de Troca de Mensagens Criptografadas

Implementação de **duas aplicações** Python que trocam mensagens de texto em formato de chat online, com **criptografia baseada em chaves assimétricas negociadas** entre os peers.

## Requisitos atendidos

| Item | Implementação |
|------|---------------|
| (a) Duas aplicações | `aplicacao_a.py` (servidor) e `aplicacao_b.py` (cliente) |
| (b) Chat online | Interface gráfica com histórico e campo de envio |
| (c) Criptografia assimétrica | Troca de chaves públicas RSA + chave de sessão AES criptografada com RSA |

## Como funciona a segurança

1. **Cada aplicação** gera um par de chaves **RSA 2048 bits**.
2. As **chaves públicas** são trocadas pela rede (negociação assimétrica).
3. A Aplicação B gera uma **chave de sessão AES-256** e envia-a criptografada com a chave pública RSA da Aplicação A.
4. Todas as mensagens do chat são criptografadas com **AES-GCM** usando a chave de sessão.

> Esse esquema híbrido (RSA + AES) é o padrão usado em TLS/HTTPS: RSA negocia a chave simétrica; AES criptografa o tráfego de mensagens.

## Instalação

```bash
pip install -r requirements.txt
```

## Execução

Abra **dois terminais** na pasta do projeto.

**Terminal 1 — Aplicação A (servidor):**
```bash
python aplicacao_a.py
```

**Terminal 2 — Aplicação B (cliente):**
```bash
python aplicacao_b.py
```

Opcionalmente, altere host/porta:
```bash
python aplicacao_a.py --host 0.0.0.0 --porta 5555
python aplicacao_b.py --host 192.168.1.10 --porta 5555
```

## Estrutura do projeto

```
├── aplicacao_a.py      # Aplicação 1 — escuta conexões
├── aplicacao_b.py      # Aplicação 2 — conecta ao servidor
├── interface_chat.py   # GUI compartilhada (Tkinter)
├── protocolo.py        # Negociação de chaves e protocolo de mensagens
├── crypto_utils.py     # RSA, AES-GCM e serialização de chaves
└── requirements.txt
```

## Protocolo de rede (resumo)

```
Aplicação A (servidor)              Aplicação B (cliente)
        |                                    |
        |<-------- pubkey B -----------------|
        |--------- pubkey A ----------------->|
        |<---- session_key (RSA) -------------|
        |--------- session_ok --------------->|
        |<==== mensagens AES-GCM ===========>|
```

## Dependências

- Python 3.10+
- [cryptography](https://pypi.org/project/cryptography/) — operações RSA e AES
- [customtkinter](https://pypi.org/project/customtkinter/) — interface gráfica moderna
