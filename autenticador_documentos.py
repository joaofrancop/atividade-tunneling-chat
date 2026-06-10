"""
Autenticador de documentos — SHA-256 + assinatura digital RSA.

Cada mensagem do chat é tratada como um "documento":
  1. Calcula o hash SHA-256 do texto (integridade)
  2. Assina o hash com a chave privada RSA do remetente (autenticidade)
  3. O destinatário verifica a assinatura com a chave pública do remetente
"""

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import assinar_hash_sha256, calcular_hash_sha256, verificar_assinatura_sha256


def autenticar_documento(texto: str, chave_privada: rsa.RSAPrivateKey) -> Tuple[str, str]:
    """
    Gera hash SHA-256 e assinatura RSA de um documento (mensagem).

    Retorna (hash_hex, assinatura_base64).
    """
    hash_hex = calcular_hash_sha256(texto)
    assinatura = assinar_hash_sha256(hash_hex, chave_privada)
    return hash_hex, assinatura


def verificar_documento(
    texto: str,
    hash_recebido: str,
    assinatura_b64: str,
    chave_publica_remetente: rsa.RSAPublicKey,
) -> bool:
    """
    Verifica se o documento é autêntico e íntegro.

    Confere:
      - se o hash SHA-256 recalculado bate com o hash recebido
      - se a assinatura RSA é válida para aquele hash
    """
    hash_calculado = calcular_hash_sha256(texto)
    if hash_calculado != hash_recebido:
        return False
    return verificar_assinatura_sha256(hash_recebido, assinatura_b64, chave_publica_remetente)
