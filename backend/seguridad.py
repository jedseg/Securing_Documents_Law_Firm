"""
Contraseñas y sesiones del servidor.

- Contraseñas: nunca se guardan. Se guarda scrypt(contraseña, sal), una función
  de derivación de llaves (KDF) lenta y con mucha memoria a propósito, para que
  un atacante que robe la base de datos no pueda probar millones de contraseñas.
- Sesiones: al iniciar sesión se entrega un token aleatorio de 256 bits. En la
  base de datos solo se guarda su SHA-256, así que robar la tabla de sesiones
  no permite suplantar a nadie.
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
DURACION_SESION = timedelta(hours=2)
LONGITUD_MINIMA = 8


def derivar(contrasena: str, sal: bytes) -> bytes:
    return hashlib.scrypt(contrasena.encode(), salt=sal, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)


def nueva_contrasena(contrasena: str) -> tuple[bytes, bytes]:
    """Devuelve (sal, hash) para guardar en la base de datos."""
    sal = secrets.token_bytes(16)
    return sal, derivar(contrasena, sal)


def verificar_contrasena(contrasena: str, sal: bytes, hash_guardado: bytes) -> bool:
    # compare_digest compara en tiempo constante (evita ataques de tiempo)
    return hmac.compare_digest(derivar(contrasena, sal), hash_guardado)


def nuevo_token() -> tuple[str, str, str]:
    """Devuelve (token para el usuario, hash para la base de datos, fecha de expiración)."""
    token = secrets.token_urlsafe(32)
    expira = (datetime.now(timezone.utc) + DURACION_SESION).strftime("%Y-%m-%d %H:%M:%S")
    return token, hash_token(token), expira


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ======================================================= Secretos TOTP (MFA)
# A diferencia de una contraseña, el secreto TOTP no se puede guardar como hash:
# el servidor lo necesita para calcular el código. Por eso se guarda CIFRADO con
# AES-256-GCM, con una llave del servidor que no vive en la base de datos.
#   - Producción: variable TOTP_LLAVE (64 caracteres hex) desde un gestor de secretos.
#   - Desarrollo: si no existe, se genera en TOTP_LLAVE_ARCHIVO (solo lectura del dueño).
# El nombre de usuario va como dato asociado (AAD): el secreto cifrado de un
# usuario no sirve si alguien lo copia a la fila de otro.
LLAVE_TOTP_ARCHIVO = Path(os.environ.get("TOTP_LLAVE_ARCHIVO", "datos/totp.key"))


@lru_cache(maxsize=1)
def _llave_totp() -> bytes:
    if os.environ.get("TOTP_LLAVE"):
        llave = bytes.fromhex(os.environ["TOTP_LLAVE"])
        if len(llave) != 32:
            raise ValueError("TOTP_LLAVE debe ser de 32 bytes (64 caracteres hex)")
        return llave
    if not LLAVE_TOTP_ARCHIVO.exists():
        LLAVE_TOTP_ARCHIVO.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(LLAVE_TOTP_ARCHIVO, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    return LLAVE_TOTP_ARCHIVO.read_bytes()


def cifrar_secreto_totp(secreto: bytes, usuario: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_llave_totp()).encrypt(nonce, secreto, usuario.encode())


def descifrar_secreto_totp(cifrado: bytes, usuario: str) -> bytes:
    return AESGCM(_llave_totp()).decrypt(cifrado[:12], cifrado[12:], usuario.encode())
