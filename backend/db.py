"""
Base de datos del servidor del bufete (SQLite) y almacén de documentos cifrados.

- La base de datos guarda usuarios (con su contraseña derivada con scrypt),
  sesiones, llaves PÚBLICAS, fragmentos CIFRADOS y la bitácora de auditoría.
- Los documentos cifrados (nonce || cifrado || etiqueta) se guardan como
  archivos .bin en la carpeta del almacén (Secure Content Storage).

Nada de lo que se guarda aquí permite leer un documento: el servidor no tiene
llaves privadas, ni fragmentos en claro, ni la llave AES.
"""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.environ.get("BACKEND_DB", "datos/bufete.db"))
ALMACEN_DIR = Path(os.environ.get("ALMACEN_DIR", "datos/almacen"))

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    usuario          TEXT PRIMARY KEY,
    nombre           TEXT NOT NULL,
    rol              TEXT NOT NULL CHECK (rol IN ('cliente', 'abogado')),
    sal              BLOB NOT NULL,          -- sal aleatoria de 16 bytes
    hash_contrasena  BLOB NOT NULL,          -- scrypt(contraseña, sal)
    abogado          TEXT REFERENCES usuarios(usuario),  -- abogado que dio de alta al cliente
    debe_cambiar     INTEGER NOT NULL DEFAULT 0,          -- 1 = contraseña temporal
    publica_cifrado  TEXT,                   -- RSA-3072 (OAEP), PEM
    publica_firma    TEXT,                   -- RSA-3072 (PSS), PEM
    publica_ed25519  TEXT,                   -- Ed25519, PEM (solo abogados)
    creado           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sesiones (
    token_hash  TEXT PRIMARY KEY,            -- SHA-256 del token (el token no se guarda)
    usuario     TEXT NOT NULL REFERENCES usuarios(usuario),
    expira      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documentos (
    id         TEXT PRIMARY KEY,
    firmante   TEXT NOT NULL REFERENCES usuarios(usuario),
    titulo     TEXT NOT NULL,
    firma      TEXT NOT NULL,                -- firma Ed25519 en base64
    t          INTEGER NOT NULL,
    n          INTEGER NOT NULL,
    archivo    TEXT NOT NULL,                -- ruta del .bin en el almacén
    creado     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS fragmentos (
    id_documento       TEXT NOT NULL REFERENCES documentos(id),
    usuario            TEXT NOT NULL REFERENCES usuarios(usuario),
    fragmento_cifrado  TEXT NOT NULL,        -- RSA-OAEP para su dueño, base64
    PRIMARY KEY (id_documento, usuario)
);

-- Para la apertura conjunta: un participante vuelve a cifrar SU fragmento con
-- RSA-OAEP para otro participante. El servidor solo lo retransmite.
CREATE TABLE IF NOT EXISTS aportes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    id_documento       TEXT NOT NULL REFERENCES documentos(id),
    de                 TEXT NOT NULL REFERENCES usuarios(usuario),
    para               TEXT NOT NULL REFERENCES usuarios(usuario),
    fragmento_cifrado  TEXT NOT NULL,        -- RSA-OAEP para "para", base64
    fecha              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bitacora (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha           TEXT NOT NULL DEFAULT (datetime('now')),
    evento          TEXT NOT NULL,
    usuario         TEXT,
    id_documento    TEXT,
    consentimiento  TEXT,                    -- texto firmado (JSON)
    firma           TEXT,                    -- firma RSA-PSS en base64
    valida          INTEGER,                 -- 1 = firma verificada, 0 = rechazada
    detalle         TEXT
);
"""


def iniciar() -> None:
    """Crea la carpeta de datos, el almacén y las tablas si no existen."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    ALMACEN_DIR.mkdir(parents=True, exist_ok=True)
    with conexion() as con:
        con.executescript(ESQUEMA)


@contextmanager
def conexion():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def registrar_evento(con, evento: str, usuario: str | None = None, id_documento: str | None = None,
                     consentimiento: str | None = None, firma: str | None = None,
                     valida: bool | None = None, detalle: str | None = None) -> None:
    con.execute(
        "INSERT INTO bitacora (evento, usuario, id_documento, consentimiento, firma, valida, detalle) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (evento, usuario, id_documento, consentimiento, firma,
         None if valida is None else int(valida), detalle))


# ------------------------------------------------------------------ Almacén
def ruta_documento(id_documento: str) -> Path:
    return ALMACEN_DIR / f"{id_documento}.bin"


def guardar_archivo(id_documento: str, paquete_cifrado: bytes) -> Path:
    ruta = ruta_documento(id_documento)
    ruta.write_bytes(paquete_cifrado)
    return ruta


def leer_archivo(id_documento: str) -> bytes:
    return ruta_documento(id_documento).read_bytes()
