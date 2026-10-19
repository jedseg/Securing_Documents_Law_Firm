"""
Empaqueta un archivo (nombre + tipo + contenido) en un solo bloque de bytes,
que es lo que se firma y se cifra con crypto_core.

Así el NOMBRE del archivo (p. ej. "Testamento Juan Pérez.pdf") también queda
cifrado y firmado: el servidor no lo ve y nadie puede cambiarlo sin que se note.

Formato:  b"SDLF1" || longitud del encabezado (4 bytes) || encabezado JSON || contenido
"""

import json
import struct

MAGICO = b"SDLF1"
TAM_MAXIMO = 20 * 1024 * 1024   # 20 MB


def empaquetar(nombre: str, tipo: str, contenido: bytes) -> bytes:
    encabezado = json.dumps({"nombre": nombre, "tipo": tipo, "tam": len(contenido)},
                            ensure_ascii=False).encode()
    return MAGICO + struct.pack(">I", len(encabezado)) + encabezado + contenido


def desempaquetar(paquete: bytes) -> tuple[dict, bytes]:
    """Devuelve (encabezado, contenido). Lanza ValueError si el formato no es válido."""
    if not paquete.startswith(MAGICO) or len(paquete) < len(MAGICO) + 4:
        raise ValueError("Formato de documento desconocido")
    inicio = len(MAGICO) + 4
    (largo,) = struct.unpack(">I", paquete[len(MAGICO):inicio])
    encabezado = json.loads(paquete[inicio:inicio + largo])
    contenido = paquete[inicio + largo:]
    if len(contenido) != encabezado.get("tam"):
        raise ValueError("El tamaño del contenido no coincide")
    return encabezado, contenido
