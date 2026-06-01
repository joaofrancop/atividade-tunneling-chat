"""Utilitários de criptografia assimétrica e simétrica para o chat."""

import base64
import json
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def gerar_par_chaves() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Gera par de chaves RSA 2048 bits."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def chave_publica_para_pem(public_key: rsa.RSAPublicKey) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def chave_publica_de_pem(pem: str) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def criptografar_chave_simetrica(chave_aes: bytes, public_key: rsa.RSAPublicKey) -> str:
    """Criptografa a chave de sessão AES com a chave pública do destinatário."""
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
    cifrado = base64.b64decode(cifrado_b64.encode("utf-8"))
    return private_key.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def gerar_chave_aes() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def criptografar_mensagem(mensagem: str, chave_aes: bytes) -> str:
    """Criptografa texto com AES-GCM. Retorna JSON em base64."""
    aesgcm = AESGCM(chave_aes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, mensagem.encode("utf-8"), None)
    pacote = {"nonce": base64.b64encode(nonce).decode("utf-8"), "ciphertext": base64.b64encode(ciphertext).decode("utf-8")}
    return base64.b64encode(json.dumps(pacote).encode("utf-8")).decode("utf-8")


def descriptografar_mensagem(pacote_b64: str, chave_aes: bytes) -> str:
    pacote_json = base64.b64decode(pacote_b64.encode("utf-8")).decode("utf-8")
    pacote = json.loads(pacote_json)
    nonce = base64.b64decode(pacote["nonce"].encode("utf-8"))
    ciphertext = base64.b64decode(pacote["ciphertext"].encode("utf-8"))
    aesgcm = AESGCM(chave_aes)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
