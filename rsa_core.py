"""
RSA para el sistema "Securing documents in a law firm".

- RSA-OAEP (cifrado):  envuelve cada fragmento de Shamir con la llave pública de
                       su dueño, para que el servidor guarde los fragmentos sin
                       poder leerlos (cifrado híbrido: AES para el documento,
                       RSA para la llave).
- RSA-PSS (firma):     cada actor firma su "consentimiento de apertura"; el
                       servidor lo verifica y lo guarda en la bitácora
                       (autenticación y no repudio de la apertura).

Parámetros: RSA-3072, e = 65537, SHA-256 y MGF1-SHA-256.
Cada actor tiene DOS pares de llaves distintos: uno para cifrar (OAEP) y otro
para firmar (PSS). Usar la misma llave para ambas cosas es mala práctica.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

TAM_LLAVE_RSA = 3072
EXPONENTE = 65537

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


TAM_X = 2
TAM_Y = 66


# ------------------------------------------------------------------- Llaves
def generar_llave_rsa() -> RSAPrivateKey:
    """Par de llaves RSA-3072 (se devuelve la privada; la pública se obtiene de ella)."""
    return rsa.generate_private_key(public_exponent=EXPONENTE, key_size=TAM_LLAVE_RSA)


@dataclass
class Actor:
    """Cliente o abogado: un par de llaves para cifrar y otro para firmar."""
    nombre: str
    privada_cifrado: RSAPrivateKey = field(default_factory=generar_llave_rsa, repr=False)
    privada_firma: RSAPrivateKey = field(default_factory=generar_llave_rsa, repr=False)

    @property
    def publica_cifrado(self) -> RSAPublicKey:
        return self.privada_cifrado.public_key()

    @property
    def publica_firma(self) -> RSAPublicKey:
        return self.privada_firma.public_key()


def exportar_privada(privada: RSAPrivateKey, contrasena: bytes) -> bytes:
    """Llave privada en PEM (PKCS#8) cifrada con contraseña, para guardarla en disco."""
    return privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(contrasena),
    )


def importar_privada(pem: bytes, contrasena: bytes) -> RSAPrivateKey:
    """Carga una llave privada PEM; lanza ValueError si la contraseña es incorrecta."""
    return serialization.load_pem_private_key(pem, password=contrasena)


# --------------------------------------------- RSA-OAEP: envolver fragmentos
def fragmento_a_bytes(fragmento: tuple[int, int]) -> bytes:
    x, y = fragmento
    return x.to_bytes(TAM_X, "big") + y.to_bytes(TAM_Y, "big")


def bytes_a_fragmento(datos: bytes) -> tuple[int, int]:
    return int.from_bytes(datos[:TAM_X], "big"), int.from_bytes(datos[TAM_X:], "big")


def envolver_fragmento(publica: RSAPublicKey, fragmento: tuple[int, int]) -> bytes:
    """Cifra un fragmento con RSA-OAEP. El resultado mide 384 bytes (RSA-3072)."""
    return publica.encrypt(fragmento_a_bytes(fragmento), OAEP)


def desenvolver_fragmento(privada: RSAPrivateKey, envuelto: bytes) -> tuple[int, int]:
    """Descifra un fragmento; lanza ValueError si la llave privada no corresponde."""
    return bytes_a_fragmento(privada.decrypt(envuelto, OAEP))


# ------------------------------------ RSA-PSS: consentimiento de apertura
def crear_consentimiento(nombre: str, id_documento: str) -> bytes:
    return json.dumps({
        "accion": "autorizo_apertura",
        "actor": nombre,
        "documento": id_documento,
        "fecha": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, sort_keys=True).encode()


def firmar_consentimiento(privada_firma: RSAPrivateKey, consentimiento: bytes) -> bytes:
    """Firma RSA-PSS (sal aleatoria de 32 bytes): firmar lo mismo dos veces da firmas distintas."""
    return privada_firma.sign(consentimiento, PSS, hashes.SHA256())


def verificar_consentimiento(publica_firma: RSAPublicKey, consentimiento: bytes,
                             firma: bytes) -> bool:
    try:
        publica_firma.verify(firma, consentimiento, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
