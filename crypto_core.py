"""
Desarrollo criptográfico del sistema "Securing documents in a law firm".

- Integridad:        SHA-256 (hasheo de 32 bytes)
- Confidencialidad:  AES-256-GCM (cifrado autenticado del documento)
- No repudio:        Ed25519 (firma digital sobre el hasheo)

Flujo (sign-then-encrypt):
  1. El firmante calcula SHA-256(documento) y lo firma con su llave privada.
  2. Se genera una llave AES aleatoria (DEK) y se cifra el documento con GCM.
  3. Para abrirlo, se descifra con la DEK y se verifica la firma con la
     llave pública del firmante.
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


TAM_LLAVE = 32   # 256 bits
TAM_NONCE = 12   # 96 bits, recomendado para GCM


# Integridad
def huella(documento: bytes) -> bytes:
    """SHA-256 del documento."""
    return hashlib.sha256(documento).digest()


# Confidencialidad
# Llave AES-256 aleatoria obtenida del CSPRNG del sistema operativo.

def generar_llave() -> bytes:
    return AESGCM.generate_key(bit_length=256)

"""
AES-256-GCM. Devuelve nonce || texto_cifrado || etiqueta.
`datos_asociados` (p. ej. el id del documento) se autentica pero no se cifra:
si alguien cambia el id, el descifrado falla.
El nonce es aleatorio y nuevo en cada cifrado: nunca se reutiliza con la misma llave.
"""
def cifrar(llave: bytes, texto_claro: bytes, datos_asociados: bytes) -> bytes:
   
    nonce = os.urandom(TAM_NONCE)
    return nonce + AESGCM(llave).encrypt(nonce, texto_claro, datos_asociados)

# Lanza cryptography.exceptions.InvalidTag si la llave o los datos no son correctos.

def descifrar(llave: bytes, paquete: bytes, datos_asociados: bytes) -> bytes:
    nonce, cifrado = paquete[:TAM_NONCE], paquete[TAM_NONCE:]
    return AESGCM(llave).decrypt(nonce, cifrado, datos_asociados)


# No repudio
def generar_par_firma() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    privada = Ed25519PrivateKey.generate()
    return privada, privada.public_key()


def firmar(privada: Ed25519PrivateKey, documento: bytes) -> bytes:
    return privada.sign(huella(documento))


def verificar_firma(publica: Ed25519PublicKey, documento: bytes, firma: bytes) -> bool:
    try:
        publica.verify(firma, huella(documento))
        return True
    except Exception:
        return False