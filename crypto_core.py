"""
Desarrollo criptográfico del sistema "Securing documents in a law firm".

- Integridad:        SHA-256 (hasheo de 32 bytes)
- Confidencialidad:  AES-256-GCM (cifrado autenticado del documento)
- No repudio:        Ed25519 (firma digital sobre el hasheo)
- Acceso conjunto:   Shamir t de n sobre la llave AES (ver shamir.py)
- Custodia:          cada fragmento se cifra con RSA-OAEP para su dueño (ver rsa_core.py)

Flujo (sign-then-encrypt):
  1. El firmante calcula SHA-256(documento) y lo firma con su llave privada.
  2. Se genera una llave AES aleatoria (DEK) y se cifra el documento con GCM.
  3. La DEK se divide con Shamir en n fragmentos (uno por actor) y se descarta.
     Cada fragmento se cifra con la llave pública RSA de su dueño (OAEP).
  4. Para abrirlo, cada actor firma su consentimiento (RSA-PSS) y descifra
     su fragmento con su llave privada; se juntan t fragmentos, se reconstruye
     la DEK, se descifra y se verifica la firma con la llave pública del firmante.
"""

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import rsa_core
import shamir


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


# Acceso conjunto (Shamir)
@dataclass
class DocumentoProtegido:
    """Lo que se guarda en el almacenamiento: nunca contiene la llave."""
    id_documento: str
    paquete_cifrado: bytes   # nonce || texto_cifrado || etiqueta
    firma: bytes             # firma Ed25519 sobre SHA-256(documento)
    t: int                   # fragmentos necesarios para abrir
    n: int                   # fragmentos repartidos


def proteger(documento: bytes, id_documento: str, privada_firmante: Ed25519PrivateKey,
             t: int, n: int) -> tuple[DocumentoProtegido, list[tuple[int, int]]]:
    """Firma, cifra y divide la llave. Devuelve el documento protegido y los n fragmentos."""
    firma = firmar(privada_firmante, documento)
    dek = generar_llave()
    paquete = cifrar(dek, documento, id_documento.encode())
    fragmentos = shamir.dividir_secreto(dek, t, n)
    del dek  # la llave completa no se guarda en ningún lado
    return DocumentoProtegido(id_documento, paquete, firma, t, n), fragmentos


def abrir(protegido: DocumentoProtegido, fragmentos: list[tuple[int, int]],
          publica_firmante: Ed25519PublicKey) -> bytes:
    """
    Reconstruye la llave con los fragmentos aportados, descifra y verifica la firma.
    Con menos de t fragmentos la llave sale incorrecta y AES-GCM lanza InvalidTag.
    """
    dek = shamir.reconstruir_secreto(fragmentos, TAM_LLAVE)
    documento = descifrar(dek, protegido.paquete_cifrado, protegido.id_documento.encode())
    if not verificar_firma(publica_firmante, documento, protegido.firma):
        raise ValueError("La firma no corresponde al documento")
    return documento


def proteger_para_actores(documento: bytes, id_documento: str,
                          privada_firmante: Ed25519PrivateKey, t: int,
                          publicas_cifrado: dict[str, rsa_core.RSAPublicKey]
                          ) -> tuple[DocumentoProtegido, dict[str, bytes]]:
    """
    Igual que proteger(), pero reparte un fragmento por actor y lo cifra con
    RSA-OAEP usando la llave pública de ese actor. Devuelve
    {nombre: fragmento_cifrado}: esto es lo que se guarda en el servidor.
    """
    protegido, fragmentos = proteger(documento, id_documento, privada_firmante,
                                     t, len(publicas_cifrado))
    envueltos = {
        nombre: rsa_core.envolver_fragmento(publica, fragmento)
        for (nombre, publica), fragmento in zip(publicas_cifrado.items(), fragmentos)
    }
    del fragmentos  # los fragmentos en claro no se guardan en ningún lado
    return protegido, envueltos
