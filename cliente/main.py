"""
Cliente local: corre en la computadora de cada usuario (cliente o abogado).

Ejecutar desde la carpeta raíz del proyecto:
    uvicorn cliente.main:app --port 8080
y abrir  http://127.0.0.1:8080  en el navegador.

- Sirve la interfaz web (HTML + Bootstrap) de la carpeta static/.
- Guarda las llaves privadas del usuario en su llavero local (cifradas con su
  contraseña) y hace TODA la criptografía con crypto_core, shamir y rsa_core.
- Al servidor del bufete solo le envía datos cifrados, firmas y llaves públicas.

Solo acepta conexiones desde esta misma computadora (127.0.0.1).
"""

import secrets
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import crypto_core as cc
import llavero
import rsa_core as rc
from cliente import paquete
from cliente import servidor_api as srv

ESTATICOS = Path(__file__).parent / "static"
HOSTS_PERMITIDOS = {"127.0.0.1", "localhost"}
TIPOS_VISIBLES = {"application/pdf", "image/png", "image/jpeg", "image/gif", "text/plain"}

app = FastAPI(title="Cliente local - Portal Legal Seguro", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ESTATICOS), name="static")


@dataclass
class Sesion:
    token: str
    usuario: str
    nombre: str
    rol: str
    debe_activar: bool = False
    actor: rc.Actor | None = None
    privada_ed: object | None = None
    # Fragmentos propios ya descifrados, solo en memoria: id_documento -> (x, y)
    fragmentos: dict = field(default_factory=dict)
    # Documentos ya abiertos, solo en memoria: id_documento -> (encabezado, contenido)
    abiertos: dict = field(default_factory=dict)


SESIONES: dict[str, Sesion] = {}


# ======================================================== Protección local
@app.middleware("http")
async def solo_local(request: Request, call_next):
    """
    - Solo atiende peticiones dirigidas a 127.0.0.1 / localhost (evita DNS rebinding).
    - Las llamadas a /api que modifican algo exigen la cabecera X-Cliente-Local:
      un sitio web ajeno no puede enviarla sin permiso CORS (evita CSRF).
    """
    host = (request.headers.get("host") or "").rsplit(":", 1)[0]
    if host not in HOSTS_PERMITIDOS:
        return JSONResponse({"detail": "Host no permitido"}, status_code=403)
    if (request.url.path.startswith("/api/") and request.method != "GET"
            and request.headers.get("x-cliente-local") != "1"):
        return JSONResponse({"detail": "Petición no permitida"}, status_code=403)
    return await call_next(request)


@app.exception_handler(srv.ErrorServidor)
async def error_servidor(_request, e: srv.ErrorServidor):
    return JSONResponse({"detail": e.detalle}, status_code=e.estado)


def nombre_cookie(request: Request) -> str:
    # Las cookies no distinguen puertos: con el puerto en el nombre se pueden usar
    # dos clientes locales a la vez (por ejemplo abogado en 8080 y cliente en 8081)
    return f"sesion_local_{request.url.port or 80}"


def abrir_sesion(request: Request, response: Response, sesion: Sesion) -> None:
    sid = secrets.token_urlsafe(32)
    SESIONES[sid] = sesion
    response.set_cookie(nombre_cookie(request), sid, httponly=True, samesite="strict")


def sesion_actual(request: Request) -> Sesion:
    sesion = SESIONES.get(request.cookies.get(nombre_cookie(request), ""))
    if not sesion:
        raise HTTPException(401, "Inicie sesión")
    return sesion


def sesion_lista(s: Sesion = Depends(sesion_actual)) -> Sesion:
    if s.debe_activar or s.actor is None:
        raise HTTPException(403, "Primero active su cuenta")
    return s


def solo_abogado(s: Sesion = Depends(sesion_lista)) -> Sesion:
    if s.rol != "abogado":
        raise HTTPException(403, "Solo un abogado puede hacer esto")
    return s


def datos_sesion(s: Sesion) -> dict:
    return {"usuario": s.usuario, "nombre": s.nombre, "rol": s.rol, "debe_activar": s.debe_activar}


# ================================================================= Modelos
class LoginEntrada(BaseModel):
    usuario: str
    contrasena: str


class RegistroEntrada(BaseModel):
    usuario: str
    nombre: str
    contrasena: str
    codigo_bufete: str


class ActivarEntrada(BaseModel):
    contrasena_actual: str
    contrasena_nueva: str


class ClienteEntrada(BaseModel):
    usuario: str
    nombre: str
    contrasena_temporal: str


# ================================================================== Páginas
@app.get("/")
def inicio():
    return FileResponse(ESTATICOS / "index.html")


@app.get("/api/estado")
def estado():
    return {"servidor": srv.disponible(), "url_servidor": srv.URL}


# ================================================================ Cuentas
@app.post("/api/registro-abogado")
def registro_abogado(e: RegistroEntrada):
    if llavero.existe(e.usuario):
        raise HTTPException(409, "Este equipo ya tiene llaves para ese usuario")
    # 1. Se generan las llaves EN ESTE EQUIPO
    actor, privada_ed = llavero.generar(e.usuario, con_ed25519=True)
    # 2. Al servidor solo se envían las llaves públicas
    srv.registrar_abogado(e.usuario, e.nombre, e.contrasena, e.codigo_bufete,
                          actor, privada_ed.public_key())
    # 3. Las privadas se guardan cifradas con la contraseña del abogado
    llavero.guardar(actor, privada_ed, e.contrasena.encode())
    return {"ok": True}


@app.post("/api/login")
def login(e: LoginEntrada, request: Request, response: Response):
    datos = srv.login(e.usuario, e.contrasena)
    sesion = Sesion(token=datos["token"], usuario=datos["usuario"], nombre=datos["nombre"],
                    rol=datos["rol"])

    if datos["debe_cambiar"]:
        # Cliente nuevo: debe crear su contraseña y sus llaves en este equipo
        sesion.debe_activar = True
    else:
        if not llavero.existe(e.usuario):
            srv.logout(datos["token"])
            raise HTTPException(409, "Este equipo no tiene las llaves privadas de este usuario. "
                                     "Inicie sesión desde el equipo donde activó su cuenta.")
        try:
            sesion.actor, sesion.privada_ed = llavero.cargar(e.usuario, e.contrasena.encode())
        except ValueError:
            srv.logout(datos["token"])
            raise HTTPException(401, "No se pudo abrir el llavero local con esa contraseña")
        # Comprueba que el servidor tenga registradas exactamente MIS llaves públicas
        registradas = srv.llaves(sesion.token, sesion.usuario)
        if (srv.publica_a_pem(registradas["publica_cifrado"]) != srv.publica_a_pem(sesion.actor.publica_cifrado)
                or srv.publica_a_pem(registradas["publica_firma"]) != srv.publica_a_pem(sesion.actor.publica_firma)):
            srv.logout(datos["token"])
            raise HTTPException(409, "Las llaves públicas del servidor no coinciden con las de "
                                     "este equipo. Posible suplantación.")

    abrir_sesion(request, response, sesion)
    return datos_sesion(sesion)


@app.post("/api/activar")
def activar(e: ActivarEntrada, s: Sesion = Depends(sesion_actual)):
    if not s.debe_activar:
        raise HTTPException(400, "La cuenta ya está activada")
    if llavero.existe(s.usuario):
        raise HTTPException(409, "Este equipo ya tiene llaves para ese usuario")
    actor, _ = llavero.generar(s.usuario, con_ed25519=False)
    srv.activar(s.token, e.contrasena_actual, e.contrasena_nueva, actor)
    llavero.guardar(actor, None, e.contrasena_nueva.encode())
    s.actor, s.debe_activar = actor, False
    return datos_sesion(s)


@app.post("/api/logout")
def logout(request: Request, response: Response):
    sesion = SESIONES.pop(request.cookies.get(nombre_cookie(request), ""), None)
    if sesion:
        sesion.abiertos.clear()
        sesion.fragmentos.clear()
        srv.logout(sesion.token)
    response.delete_cookie(nombre_cookie(request))
    return {"ok": True}


@app.get("/api/yo")
def yo(s: Sesion = Depends(sesion_actual)):
    return datos_sesion(s)


# =============================================================== Clientes
@app.get("/api/clientes")
def clientes(s: Sesion = Depends(solo_abogado)):
    return srv.mis_clientes(s.token)


@app.post("/api/clientes")
def alta_cliente(e: ClienteEntrada, s: Sesion = Depends(solo_abogado)):
    srv.alta_cliente(s.token, e.usuario, e.nombre, e.contrasena_temporal)
    return {"ok": True}


# ============================================================= Documentos
@app.post("/api/documentos")
async def proteger_documento(id: str = Form(...), titulo: str = Form(...),
                             cliente: str = Form(...), archivo: UploadFile = File(...),
                             s: Sesion = Depends(solo_abogado)):
    """Firma (Ed25519), cifra (AES-256-GCM), divide la llave (Shamir 2 de 2) y cifra
    cada fragmento con RSA-OAEP para su dueño. Al servidor solo llega lo cifrado."""
    contenido = await archivo.read(paquete.TAM_MAXIMO + 1)
    if not contenido:
        raise HTTPException(400, "El archivo está vacío")
    if len(contenido) > paquete.TAM_MAXIMO:
        raise HTTPException(413, "El archivo supera el máximo de 20 MB")
    nombre = Path(archivo.filename or "documento").name
    tipo = archivo.content_type or "application/octet-stream"

    # El nombre y el tipo viajan DENTRO del documento cifrado y firmado
    documento = paquete.empaquetar(nombre, tipo, contenido)
    publicas = {s.usuario: s.actor.publica_cifrado,
                cliente: srv.llaves(s.token, cliente)["publica_cifrado"]}
    protegido, envueltos = cc.proteger_para_actores(documento, id, s.privada_ed, t=2,
                                                    publicas_cifrado=publicas)
    srv.subir_documento(s.token, protegido, titulo, cliente, envueltos)
    return {
        "id": id,
        "nombre": nombre,
        "sha256": cc.huella(contenido).hex(),       # huella del archivo original
        "firma": srv.b64(protegido.firma),
        "tam_original": len(contenido),
        "tam_cifrado": len(protegido.paquete_cifrado),
        "fragmentos": {u: len(f) for u, f in envueltos.items()},
    }


@app.get("/api/documentos")
def documentos(s: Sesion = Depends(sesion_lista)):
    lista = srv.mis_documentos(s.token)
    for d in lista:
        d["autorice"] = d["id"] in s.fragmentos and s.usuario in d["autorizaciones"]
    return lista


@app.post("/api/documentos/{id_documento}/autorizar")
def autorizar(id_documento: str, s: Sesion = Depends(sesion_lista)):
    # 1. Firma el consentimiento con RSA-PSS (en este equipo)
    consentimiento = rc.crear_consentimiento(s.usuario, id_documento)
    firma = rc.firmar_consentimiento(s.actor.privada_firma, consentimiento)
    # 2. El servidor lo verifica y entrega MI fragmento cifrado; lo descifro con RSA-OAEP
    envuelto = srv.consentir(s.token, id_documento, consentimiento, firma)
    fragmento = rc.desenvolver_fragmento(s.actor.privada_cifrado, envuelto)
    s.fragmentos[id_documento] = fragmento
    # 3. Se lo envío a cada otro participante, cifrado con SU llave pública (RSA-OAEP)
    _, meta = srv.documento(s.token, id_documento)
    otros = [p for p in meta["participantes"] if p != s.usuario]
    for otro in otros:
        publica = srv.llaves(s.token, otro)["publica_cifrado"]
        srv.aportar(s.token, id_documento, otro, rc.envolver_fragmento(publica, fragmento))
    return {"ok": True, "enviado_a": otros}


@app.post("/api/documentos/{id_documento}/abrir")
def abrir(id_documento: str, s: Sesion = Depends(sesion_lista)):
    if id_documento not in s.fragmentos:
        raise HTTPException(409, "Primero autorice la apertura de este documento")
    protegido, meta = srv.documento(s.token, id_documento)

    # Fragmentos: el mío + los que otros me enviaron cifrados para mí
    fragmentos = [s.fragmentos[id_documento]]
    for aporte in srv.aportes_recibidos(s.token, id_documento):
        try:
            fragmentos.append(rc.desenvolver_fragmento(s.actor.privada_cifrado,
                                                       srv.desde_b64(aporte["fragmento_cifrado"])))
        except ValueError:
            pass  # un aporte que no está cifrado para mí se ignora
    if len(fragmentos) < protegido.t:
        faltan = [meta.get("nombres", {}).get(p, p) for p in meta["participantes"]
                  if p != s.usuario and p not in meta["autorizaciones"]]
        raise HTTPException(409, "Falta la autorización de: " + ", ".join(faltan or ["otro participante"]))

    publica_ed = srv.llaves(s.token, meta["firmante"])["publica_ed25519"]
    try:
        # Shamir reconstruye la llave, AES-GCM descifra y Ed25519 verifica la firma
        documento = cc.abrir(protegido, fragmentos, publica_ed)
    except InvalidTag:
        raise HTTPException(422, "Rechazado por AES-GCM: la llave reconstruida es incorrecta "
                                 "o el documento cifrado fue alterado en el servidor")
    except ValueError:
        raise HTTPException(422, "La firma digital del abogado no corresponde al documento")
    try:
        encabezado, contenido = paquete.desempaquetar(documento)
    except ValueError:
        # Documentos creados antes de la subida de archivos: eran texto plano
        encabezado, contenido = {"nombre": f"{id_documento}.txt", "tipo": "text/plain"}, documento
    # El archivo descifrado solo vive en la memoria de este equipo
    s.abiertos[id_documento] = (encabezado, contenido)
    return {"id": id_documento, "titulo": meta["titulo"], "firmante": meta["firmante"],
            "nombre": encabezado["nombre"], "tipo": encabezado["tipo"],
            "tam": len(contenido), "sha256": cc.huella(contenido).hex()}


@app.get("/api/documentos/{id_documento}/archivo")
def descargar(id_documento: str, ver: bool = False, s: Sesion = Depends(sesion_lista)):
    """Entrega el archivo ya descifrado (solo si se abrió en esta sesión)."""
    if id_documento not in s.abiertos:
        raise HTTPException(404, "Primero abra el documento")
    encabezado, contenido = s.abiertos[id_documento]
    # Solo se muestran en el navegador tipos seguros; un HTML o SVG subido podría
    # ejecutar código en esta página, así que esos siempre se descargan.
    tipo = encabezado["tipo"] if encabezado["tipo"] in TIPOS_VISIBLES else "application/octet-stream"
    disposicion = "inline" if ver and tipo != "application/octet-stream" else "attachment"
    cabeceras = {
        "Content-Disposition": f"{disposicion}; filename*=UTF-8''{quote(encabezado['nombre'])}",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if tipo != "application/pdf":  # el visor de PDF del navegador no funciona en modo sandbox
        cabeceras["Content-Security-Policy"] = "sandbox"
    return Response(content=contenido, media_type=tipo, headers=cabeceras)


@app.get("/api/bitacora")
def bitacora(s: Sesion = Depends(sesion_actual)):
    return srv.bitacora(s.token)
