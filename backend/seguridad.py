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
import secrets
from datetime import datetime, timedelta, timezone

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
