"""
Llavero local: Guarda las llaves privadas de cada usuario en su propio equipo

Por usuario se guardan:
  <carpeta>/<usuario>_cifrado.pem   RSA-3072 para OAEP
  <carpeta>/<usuario>_firma.pem     RSA-3072 para PSS
  <carpeta>/<usuario>_ed25519.pem   Ed25519 para firmar documentos (solo abogados)
"""

import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rsa_core as rc

CARPETA = Path(os.environ.get("LLAVERO_DIR", "llaves_locales"))


def _archivo(usuario: str, uso: str) -> Path:
    seguro = re.sub(r"[^\w-]", "_", usuario)
    return CARPETA / f"{seguro}_{uso}.pem"


def _guardar(ruta: Path, privada, contrasena: bytes) -> None:
    ruta.write_bytes(rc.exportar_privada(privada, contrasena))
    ruta.chmod(0o600)  # solo el dueño del equipo puede leer el archivo


def existe(usuario: str) -> bool:
    return _archivo(usuario, "cifrado").exists()


def generar(usuario: str, con_ed25519: bool):
    """Genera las llaves en memoria (todavía no las guarda). Devuelve (Actor, privada_ed25519|None)."""
    actor = rc.Actor(usuario)
    privada_ed = Ed25519PrivateKey.generate() if con_ed25519 else None
    return actor, privada_ed


def guardar(actor: rc.Actor, privada_ed, contrasena: bytes) -> None:
    """Guarda las llaves del usuario cifradas con su contraseña."""
    CARPETA.mkdir(parents=True, exist_ok=True)
    _guardar(_archivo(actor.nombre, "cifrado"), actor.privada_cifrado, contrasena)
    _guardar(_archivo(actor.nombre, "firma"), actor.privada_firma, contrasena)
    if privada_ed is not None:
        _guardar(_archivo(actor.nombre, "ed25519"), privada_ed, contrasena)


def cargar(usuario: str, contrasena: bytes):
    """Carga las llaves del usuario. Lanza ValueError si la contraseña es incorrecta."""
    leer = lambda uso: rc.importar_privada(_archivo(usuario, uso).read_bytes(), contrasena)
    actor = rc.Actor(usuario, privada_cifrado=leer("cifrado"), privada_firma=leer("firma"))
    privada_ed = leer("ed25519") if _archivo(usuario, "ed25519").exists() else None
    return actor, privada_ed
