"""
TOTP: contraseñas de un solo uso basadas en el tiempo (implementación propia).

Es el segundo factor de autenticación (MFA) del portal: además de la contraseña
("algo que sabe"), el usuario demuestra que tiene su teléfono ("algo que tiene"),
donde una app autenticadora (Google Authenticator, Microsoft Authenticator...)
guarda un secreto compartido con el servidor.

- HOTP (RFC 4226):  código = Truncar( HMAC-SHA1(secreto, contador) ) mod 10^6
- TOTP (RFC 6238):  contador = floor(tiempo_unix / 30)
  Cada 30 segundos cambia el contador y, por lo tanto, el código.

Truncamiento dinámico: los 4 bits bajos del último byte del HMAC indican desde
qué posición se toman 4 bytes; se quita el bit de signo y se reduce a 6 dígitos.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PERIODO = 30          # segundos que dura cada código
DIGITOS = 6
VENTANA = 1           # acepta el periodo anterior y el siguiente (desfase de reloj)
TAM_SECRETO = 20      # 160 bits, el tamaño que recomienda RFC 4226 para HMAC-SHA1
EMISOR = "Portal Legal Seguro"


def nuevo_secreto() -> bytes:
    return secrets.token_bytes(TAM_SECRETO)


def a_base32(secreto: bytes) -> str:
    """Formato que entienden las apps autenticadoras (sin el relleno '=')."""
    return base64.b32encode(secreto).decode().rstrip("=")


def hotp(secreto: bytes, contador: int, digitos: int = DIGITOS, algoritmo=hashlib.sha1) -> str:
    """HOTP (RFC 4226): código de un solo uso para un contador."""
    mac = hmac.new(secreto, struct.pack(">Q", contador), algoritmo).digest()
    desplazamiento = mac[-1] & 0x0F                                   # truncamiento dinámico
    binario = struct.unpack(">I", mac[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF
    return str(binario % 10 ** digitos).zfill(digitos)


def paso(t: float | None = None) -> int:
    """Contador de TOTP: número de periodos de 30 s desde 1970."""
    return int((time.time() if t is None else t) // PERIODO)


def codigo(secreto: bytes, t: float | None = None) -> str:
    """Código TOTP vigente (lo que muestra la app del teléfono)."""
    return hotp(secreto, paso(t))


def verificar(secreto: bytes, codigo_usuario: str, ultimo_paso: int = 0,
              t: float | None = None) -> int | None:
    """
    Verifica un código. Devuelve el paso aceptado (para guardarlo) o None.

    - Acepta ±VENTANA periodos por si el reloj del teléfono está desfasado.
    - Rechaza pasos ya usados (<= ultimo_paso): un código interceptado no se
      puede reutilizar (ataque de repetición).
    - Compara en tiempo constante y revisa toda la ventana sin salir antes.
    """
    codigo_usuario = (codigo_usuario or "").strip()
    if len(codigo_usuario) != DIGITOS or not codigo_usuario.isdigit():
        return None
    actual = paso(t)
    aceptado = None
    for p in range(actual - VENTANA, actual + VENTANA + 1):
        if hmac.compare_digest(hotp(secreto, p), codigo_usuario) and p > ultimo_paso:
            aceptado = p
    return aceptado


def uri(secreto: bytes, usuario: str, emisor: str = EMISOR) -> str:
    """URI otpauth:// que se convierte en el código QR para la app autenticadora."""
    etiqueta = quote(f"{emisor}:{usuario}")
    return (f"otpauth://totp/{etiqueta}?secret={a_base32(secreto)}&issuer={quote(emisor)}"
            f"&algorithm=SHA1&digits={DIGITOS}&period={PERIODO}")
