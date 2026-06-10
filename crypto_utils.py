"""
Utilitários de criptografia para o chat seguro.

Conceitos implementados:
  - RSA 2048: chaves assimétricas para negociação e assinaturas
  - SHA-256: hash de integridade e algoritmo do padding OAEP/PSS
  - AES-GCM: criptografia simétrica das mensagens dentro do túnel
"""

import base64
import hashlib
import json
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# RSA — geração e serialização de chaves assimétricas
# ---------------------------------------------------------------------------

def gerar_par_chaves() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Gera par de chaves RSA 2048 bits (pública + privada)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def chave_publica_para_pem(public_key: rsa.RSAPublicKey) -> str:
    """Converte chave pública RSA para formato PEM (texto), para envio na rede."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def chave_publica_de_pem(pem: str) -> rsa.RSAPublicKey:
    """Carrega chave pública RSA a partir de texto PEM."""
    return serialization.load_pem_public_key(pem.encode("utf-8"))


# ---------------------------------------------------------------------------
# SHA-256 — hash de integridade de documentos/mensagens
# ---------------------------------------------------------------------------

def calcular_hash_sha256(texto: str) -> str:
    """
    Calcula o hash SHA-256 de um texto.

    O hash é uma "impressão digital" fixa (64 caracteres hex) que muda
    se qualquer caractere do documento for alterado.
    """
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# RSA — assinatura digital (autenticador de documentos)
# ---------------------------------------------------------------------------

def assinar_hash_sha256(hash_hex: str, private_key: rsa.RSAPrivateKey) -> str:
    """
    Assina um hash SHA-256 com a chave privada RSA (esquema PSS + SHA-256).

    Só quem possui a chave privada pode gerar uma assinatura válida.
    """
    assinatura = private_key.sign(
        hash_hex.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(assinatura).decode("utf-8")


def verificar_assinatura_sha256(
    hash_hex: str,
    assinatura_b64: str,
    public_key: rsa.RSAPublicKey,
) -> bool:
    """Verifica assinatura RSA de um hash SHA-256 com a chave pública do remetente."""
    assinatura = base64.b64decode(assinatura_b64.encode("utf-8"))
    try:
        public_key.verify(
            assinatura,
            hash_hex.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# RSA — criptografia da chave de sessão (tunneling: abertura do túnel seguro)
# ---------------------------------------------------------------------------

def criptografar_chave_simetrica(chave_aes: bytes, public_key: rsa.RSAPublicKey) -> str:
    """
    Criptografa a chave de sessão AES com RSA-OAEP + SHA-256.

    Usado no tunneling: a chave simétrica trafega protegida pela chave
    pública do destinatário — só ele (com a privada) consegue abrir o túnel.
    """
    cifrado = public_key.encrypt(
        chave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(cifrado).decode("utf-8")


def descriptografar_chave_simetrica(cifrado_b64: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """Descriptografa a chave de sessão AES com a chave privada RSA."""
    cifrado = base64.b64decode(cifrado_b64.encode("utf-8"))
    return private_key.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# AES-GCM — criptografia das mensagens dentro do túnel
# ---------------------------------------------------------------------------

def gerar_chave_aes() -> bytes:
    """Gera chave simétrica AES-256 para a sessão do túnel."""
    return AESGCM.generate_key(bit_length=256)


def criptografar_mensagem(mensagem: str, chave_aes: bytes) -> str:
    """
    Criptografa texto com AES-GCM (dentro do túnel seguro).

    Cada mensagem recebe um nonce aleatório; o resultado é empacotado em JSON/base64.
    """
    aesgcm = AESGCM(chave_aes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, mensagem.encode("utf-8"), None)
    pacote = {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    return base64.b64encode(json.dumps(pacote).encode("utf-8")).decode("utf-8")


def descriptografar_mensagem(pacote_b64: str, chave_aes: bytes) -> str:
    """Descriptografa mensagem AES-GCM recebida pelo túnel."""
    pacote_json = base64.b64decode(pacote_b64.encode("utf-8")).decode("utf-8")
    pacote = json.loads(pacote_json)
    nonce = base64.b64decode(pacote["nonce"].encode("utf-8"))
    ciphertext = base64.b64decode(pacote["ciphertext"].encode("utf-8"))
    aesgcm = AESGCM(chave_aes)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
