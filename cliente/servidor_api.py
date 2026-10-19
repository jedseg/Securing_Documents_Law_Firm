"""
Conexión del cliente local con el servidor del bufete.

Convierte entre objetos de Python (llaves, bytes, DocumentoProtegido) y el
formato JSON de la API (PEM y base64). Por aquí solo viajan datos cifrados,
firmas y llaves PÚBLICAS: nunca llaves privadas ni documentos en claro.
"""

import base64
import os

import requests
from cryptography.hazmat.primitives import serialization

import crypto_core as cc

URL = os.environ.get("SERVIDOR_URL", "http://127.0.0.1:8000")
# Con TLS y certificado autofirmado: SERVIDOR_CA=ruta/al/certificado.pem
VERIFICAR = os.environ.get("SERVIDOR_CA", True)
TIEMPO = 15


class ErrorServidor(Exception):
    def __init__(self, estado: int, detalle: str):
        super().__init__(detalle)
        self.estado, self.detalle = estado, detalle


def b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode()


def desde_b64(valor: str) -> bytes:
    return base64.b64decode(valor)


def publica_a_pem(publica) -> str:
    return publica.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def pem_a_publica(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def _pedir(metodo: str, ruta: str, token: str | None = None, **kwargs):
    cabeceras = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.request(metodo, URL + ruta, headers=cabeceras, timeout=TIEMPO,
                             verify=VERIFICAR, **kwargs)
    except requests.RequestException:
        raise ErrorServidor(503, f"No hay conexión con el servidor del bufete ({URL})")
    if r.status_code >= 400:
        try:
            detalle = r.json().get("detail", r.text)
        except ValueError:
            detalle = r.text
        if isinstance(detalle, list):  # errores de validación de FastAPI
            detalle = "; ".join(e.get("msg", "") for e in detalle)
        raise ErrorServidor(r.status_code, str(detalle))
    return r.json()


def disponible() -> bool:
    try:
        return _pedir("GET", "/salud").get("estado") == "ok"
    except ErrorServidor:
        return False


# ------------------------------------------------------- Cuentas y sesión
def registrar_abogado(usuario, nombre, contrasena, codigo, actor, publica_ed) -> None:
    _pedir("POST", "/auth/registro-abogado", json={
        "usuario": usuario, "nombre": nombre, "contrasena": contrasena, "codigo_bufete": codigo,
        "publica_cifrado": publica_a_pem(actor.publica_cifrado),
        "publica_firma": publica_a_pem(actor.publica_firma),
        "publica_ed25519": publica_a_pem(publica_ed)})


def login(usuario: str, contrasena: str) -> dict:
    return _pedir("POST", "/auth/login", json={"usuario": usuario, "contrasena": contrasena})


def logout(token: str) -> None:
    try:
        _pedir("POST", "/auth/logout", token)
    except ErrorServidor:
        pass


def activar(token, contrasena_actual, contrasena_nueva, actor) -> None:
    _pedir("POST", "/yo/activar", token, json={
        "contrasena_actual": contrasena_actual, "contrasena_nueva": contrasena_nueva,
        "publica_cifrado": publica_a_pem(actor.publica_cifrado),
        "publica_firma": publica_a_pem(actor.publica_firma)})


def alta_cliente(token, usuario, nombre, contrasena_temporal) -> None:
    _pedir("POST", "/clientes", token, json={
        "usuario": usuario, "nombre": nombre, "contrasena_temporal": contrasena_temporal})


def mis_clientes(token) -> list[dict]:
    return _pedir("GET", "/clientes", token)


def llaves(token, usuario) -> dict:
    """Llaves públicas de un usuario, ya convertidas a objetos."""
    datos = _pedir("GET", f"/usuarios/{usuario}/llaves", token)
    for campo in ("publica_cifrado", "publica_firma", "publica_ed25519"):
        if datos.get(campo):
            datos[campo] = pem_a_publica(datos[campo])
    return datos


# -------------------------------------------------------------- Documentos
def subir_documento(token, protegido: cc.DocumentoProtegido, titulo: str, cliente: str,
                    envueltos: dict[str, bytes]) -> None:
    _pedir("POST", "/documentos", token, json={
        "id": protegido.id_documento, "titulo": titulo, "cliente": cliente,
        "paquete_cifrado": b64(protegido.paquete_cifrado), "firma": b64(protegido.firma),
        "fragmentos": {u: b64(f) for u, f in envueltos.items()}})


def mis_documentos(token) -> list[dict]:
    return _pedir("GET", "/documentos", token)


def documento(token, id_documento) -> tuple[cc.DocumentoProtegido, dict]:
    datos = _pedir("GET", f"/documentos/{id_documento}", token)
    protegido = cc.DocumentoProtegido(datos["id"], desde_b64(datos["paquete_cifrado"]),
                                      desde_b64(datos["firma"]), datos["t"], datos["n"])
    return protegido, datos


def consentir(token, id_documento, consentimiento: bytes, firma: bytes) -> bytes:
    """Si el servidor acepta el consentimiento, devuelve el fragmento cifrado del usuario."""
    datos = _pedir("POST", f"/documentos/{id_documento}/consentimientos", token,
                   json={"consentimiento": b64(consentimiento), "firma": b64(firma)})
    return desde_b64(datos["fragmento_cifrado"])


def aportar(token, id_documento, para: str, fragmento_cifrado: bytes) -> None:
    _pedir("POST", f"/documentos/{id_documento}/aportes", token,
           json={"para": para, "fragmento_cifrado": b64(fragmento_cifrado)})


def aportes_recibidos(token, id_documento) -> list[dict]:
    return _pedir("GET", f"/documentos/{id_documento}/aportes", token)


def bitacora(token) -> list[dict]:
    return _pedir("GET", "/bitacora", token)
