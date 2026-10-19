"""
Servidor del bufete: "Securing documents in a law firm" (FastAPI).

Ejecutar desde la carpeta raíz del proyecto:
    uvicorn backend.main:app --port 8000

Documentación interactiva de la API:  http://127.0.0.1:8000/docs

Principio de diseño: el servidor es de "conocimiento cero". Toda la
criptografía que usa llaves privadas ocurre en el cliente local de cada
usuario. El servidor solo guarda datos cifrados, verifica firmas con llaves
PÚBLICAS y controla quién puede hacer qué (roles cliente / abogado).
"""

import base64
import binascii
import json
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import rsa_core as rc
from backend import db, seguridad

# Código que un abogado necesita para registrarse (lo entrega el bufete)
CODIGO_BUFETE = os.environ.get("BUFETE_CODIGO", "BUFETE-2026")
# Un consentimiento y sus aportes valen este tiempo: ambos deben autorizar "juntos"
VIGENCIA = timedelta(minutes=5)
# Bloqueo tras varios intentos fallidos de inicio de sesión
MAX_INTENTOS, BLOQUEO_SEG = 5, 300

PATRON_ID = r"^[A-Za-z0-9_-]{1,64}$"          # también se usa como nombre de archivo
PATRON_USUARIO = r"^[a-z0-9_.-]{3,32}$"
_intentos_fallidos: dict[str, list[float]] = {}


@asynccontextmanager
async def ciclo_de_vida(_app):
    db.iniciar()
    yield


app = FastAPI(title="Servidor del bufete", lifespan=ciclo_de_vida)


# ================================================================== Modelos
class LlavesPublicas(BaseModel):
    publica_cifrado: str              # PEM RSA (OAEP)
    publica_firma: str                # PEM RSA (PSS)


class RegistroAbogado(LlavesPublicas):
    usuario: str = Field(pattern=PATRON_USUARIO)
    nombre: str = Field(min_length=2, max_length=80)
    contrasena: str = Field(min_length=seguridad.LONGITUD_MINIMA, max_length=128)
    codigo_bufete: str
    publica_ed25519: str              # PEM Ed25519, para firmar documentos


class Login(BaseModel):
    usuario: str
    contrasena: str


class AltaCliente(BaseModel):
    usuario: str = Field(pattern=PATRON_USUARIO)
    nombre: str = Field(min_length=2, max_length=80)
    contrasena_temporal: str = Field(min_length=seguridad.LONGITUD_MINIMA, max_length=128)


class ActivarCliente(LlavesPublicas):
    contrasena_actual: str
    contrasena_nueva: str = Field(min_length=seguridad.LONGITUD_MINIMA, max_length=128)


class DocumentoEntrada(BaseModel):
    id: str = Field(pattern=PATRON_ID)
    titulo: str = Field(min_length=1, max_length=120)
    cliente: str
    paquete_cifrado: str              # base64: nonce || cifrado || etiqueta
    firma: str                        # base64: firma Ed25519
    fragmentos: dict[str, str]        # usuario -> fragmento cifrado con RSA-OAEP (base64)


class ConsentimientoEntrada(BaseModel):
    consentimiento: str               # base64 del JSON firmado
    firma: str                        # base64: firma RSA-PSS


class AporteEntrada(BaseModel):
    para: str
    fragmento_cifrado: str            # base64: RSA-OAEP con la llave pública de "para"


# =============================================================== Utilidades
def b64_a_bytes(valor: str, campo: str) -> bytes:
    try:
        return base64.b64decode(valor, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, f"El campo '{campo}' no es base64 válido")


def cargar_publica(pem: str, campo: str):
    try:
        return serialization.load_pem_public_key(pem.encode())
    except ValueError:
        raise HTTPException(400, f"'{campo}' no es una llave pública PEM válida")


def validar_llaves_rsa(llaves: LlavesPublicas) -> None:
    for campo in ("publica_cifrado", "publica_firma"):
        llave = cargar_publica(getattr(llaves, campo), campo)
        if not isinstance(llave, rc.RSAPublicKey) or llave.key_size < rc.TAM_LLAVE_RSA:
            raise HTTPException(400, f"'{campo}' debe ser RSA de al menos {rc.TAM_LLAVE_RSA} bits")
    if llaves.publica_cifrado == llaves.publica_firma:
        raise HTTPException(400, "Las llaves de cifrado y de firma deben ser distintas")


def validar_id(id_documento: str) -> None:
    if not re.fullmatch(PATRON_ID, id_documento):
        raise HTTPException(400, "ID de documento inválido")


def hace(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%d %H:%M:%S")


# ============================================================ Autenticación
def usuario_actual(authorization: str = Header(default="")) -> dict:
    """Dependencia: obtiene el usuario a partir del token 'Bearer <token>'."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Inicie sesión")
    token_hash = seguridad.hash_token(authorization.removeprefix("Bearer "))
    with db.conexion() as con:
        fila = con.execute(
            "SELECT u.* FROM sesiones s JOIN usuarios u ON u.usuario = s.usuario "
            "WHERE s.token_hash = ? AND s.expira > ?", (token_hash, seguridad.ahora())).fetchone()
    if not fila:
        raise HTTPException(401, "Sesión inválida o expirada")
    return dict(fila)


def solo_abogado(u: dict = Depends(usuario_actual)) -> dict:
    if u["rol"] != "abogado":
        raise HTTPException(403, "Solo un abogado puede hacer esto")
    return u


def activo(u: dict = Depends(usuario_actual)) -> dict:
    """El usuario debe tener sus llaves registradas (cliente ya activado)."""
    if u["debe_cambiar"] or not u["publica_cifrado"]:
        raise HTTPException(403, "Primero active su cuenta")
    return u


def datos_publicos(u: dict) -> dict:
    return {"usuario": u["usuario"], "nombre": u["nombre"], "rol": u["rol"],
            "abogado": u["abogado"], "debe_cambiar": bool(u["debe_cambiar"]),
            "llaves_registradas": bool(u["publica_cifrado"])}


def participantes(con, id_documento: str) -> list[str]:
    return [f["usuario"] for f in con.execute(
        "SELECT usuario FROM fragmentos WHERE id_documento = ?", (id_documento,))]


def exigir_participante(con, id_documento: str, usuario: str) -> list[str]:
    validar_id(id_documento)
    if not con.execute("SELECT 1 FROM documentos WHERE id = ?", (id_documento,)).fetchone():
        raise HTTPException(404, "Documento no encontrado")
    lista = participantes(con, id_documento)
    if usuario not in lista:
        raise HTTPException(403, "No participa en este documento")
    return lista


def autorizaciones_vigentes(con, id_documento: str) -> list[str]:
    filas = con.execute(
        "SELECT DISTINCT usuario FROM bitacora WHERE evento = 'consentimiento' AND valida = 1 "
        "AND id_documento = ? AND fecha >= ?", (id_documento, hace(VIGENCIA))).fetchall()
    return [f["usuario"] for f in filas]


# ================================================================ Endpoints
@app.get("/salud")
def salud():
    return {"estado": "ok"}


@app.post("/auth/registro-abogado", status_code=201)
def registro_abogado(entrada: RegistroAbogado):
    if not seguridad.hmac.compare_digest(entrada.codigo_bufete, CODIGO_BUFETE):
        raise HTTPException(403, "Código del bufete incorrecto")
    validar_llaves_rsa(entrada)
    if not isinstance(cargar_publica(entrada.publica_ed25519, "publica_ed25519"), Ed25519PublicKey):
        raise HTTPException(400, "'publica_ed25519' debe ser una llave Ed25519")
    sal, hash_c = seguridad.nueva_contrasena(entrada.contrasena)
    with db.conexion() as con:
        if con.execute("SELECT 1 FROM usuarios WHERE usuario = ?", (entrada.usuario,)).fetchone():
            raise HTTPException(409, "Ese usuario ya existe")
        con.execute(
            "INSERT INTO usuarios (usuario, nombre, rol, sal, hash_contrasena, publica_cifrado, "
            "publica_firma, publica_ed25519) VALUES (?, ?, 'abogado', ?, ?, ?, ?, ?)",
            (entrada.usuario, entrada.nombre, sal, hash_c, entrada.publica_cifrado,
             entrada.publica_firma, entrada.publica_ed25519))
        db.registrar_evento(con, "abogado_registrado", usuario=entrada.usuario)
    return {"usuario": entrada.usuario}


@app.post("/auth/login")
def login(entrada: Login):
    ahora = time.time()
    recientes = [t for t in _intentos_fallidos.get(entrada.usuario, []) if ahora - t < BLOQUEO_SEG]
    if len(recientes) >= MAX_INTENTOS:
        raise HTTPException(429, "Demasiados intentos fallidos. Espere unos minutos.")

    with db.conexion() as con:
        u = con.execute("SELECT * FROM usuarios WHERE usuario = ?", (entrada.usuario,)).fetchone()
        # Si el usuario no existe se deriva de todos modos: tarda lo mismo y no revela si existe
        sal, hash_g = (u["sal"], u["hash_contrasena"]) if u else (b"\0" * 16, b"\0" * 32)
        if not seguridad.verificar_contrasena(entrada.contrasena, sal, hash_g) or not u:
            _intentos_fallidos[entrada.usuario] = recientes + [ahora]
            db.registrar_evento(con, "login_fallido", usuario=entrada.usuario if u else None)
            con.commit()
            raise HTTPException(401, "Usuario o contraseña incorrectos")
        _intentos_fallidos.pop(entrada.usuario, None)
        token, token_hash, expira = seguridad.nuevo_token()
        con.execute("DELETE FROM sesiones WHERE expira <= ?", (seguridad.ahora(),))
        con.execute("INSERT INTO sesiones (token_hash, usuario, expira) VALUES (?, ?, ?)",
                    (token_hash, u["usuario"], expira))
        db.registrar_evento(con, "login", usuario=u["usuario"])
    return {"token": token, "expira": expira, **datos_publicos(dict(u))}


@app.post("/auth/logout")
def logout(authorization: str = Header(default=""), u: dict = Depends(usuario_actual)):
    with db.conexion() as con:
        con.execute("DELETE FROM sesiones WHERE token_hash = ?",
                    (seguridad.hash_token(authorization.removeprefix("Bearer ")),))
    return {"ok": True}


@app.get("/yo")
def yo(u: dict = Depends(usuario_actual)):
    return datos_publicos(u)


@app.post("/yo/activar")
def activar_cliente(entrada: ActivarCliente, u: dict = Depends(usuario_actual)):
    """Primer acceso del cliente: cambia la contraseña temporal y registra sus llaves públicas."""
    if u["rol"] != "cliente" or not u["debe_cambiar"]:
        raise HTTPException(400, "La cuenta ya está activada")
    if not seguridad.verificar_contrasena(entrada.contrasena_actual, u["sal"], u["hash_contrasena"]):
        raise HTTPException(401, "La contraseña actual no es correcta")
    if entrada.contrasena_nueva == entrada.contrasena_actual:
        raise HTTPException(400, "La contraseña nueva debe ser distinta de la temporal")
    validar_llaves_rsa(entrada)
    sal, hash_c = seguridad.nueva_contrasena(entrada.contrasena_nueva)
    with db.conexion() as con:
        con.execute(
            "UPDATE usuarios SET sal = ?, hash_contrasena = ?, debe_cambiar = 0, "
            "publica_cifrado = ?, publica_firma = ? WHERE usuario = ?",
            (sal, hash_c, entrada.publica_cifrado, entrada.publica_firma, u["usuario"]))
        db.registrar_evento(con, "cliente_activado", usuario=u["usuario"])
    return {"ok": True}


@app.post("/clientes", status_code=201)
def alta_cliente(entrada: AltaCliente, abogado: dict = Depends(solo_abogado)):
    sal, hash_c = seguridad.nueva_contrasena(entrada.contrasena_temporal)
    with db.conexion() as con:
        if con.execute("SELECT 1 FROM usuarios WHERE usuario = ?", (entrada.usuario,)).fetchone():
            raise HTTPException(409, "Ese usuario ya existe")
        con.execute(
            "INSERT INTO usuarios (usuario, nombre, rol, sal, hash_contrasena, abogado, debe_cambiar) "
            "VALUES (?, ?, 'cliente', ?, ?, ?, 1)",
            (entrada.usuario, entrada.nombre, sal, hash_c, abogado["usuario"]))
        db.registrar_evento(con, "cliente_creado", usuario=abogado["usuario"],
                            detalle=f"cliente: {entrada.usuario}")
    return {"usuario": entrada.usuario}


@app.get("/clientes")
def mis_clientes(abogado: dict = Depends(solo_abogado)):
    with db.conexion() as con:
        filas = con.execute("SELECT * FROM usuarios WHERE abogado = ? ORDER BY nombre",
                            (abogado["usuario"],)).fetchall()
    return [datos_publicos(dict(f)) for f in filas]


@app.get("/usuarios/{usuario}/llaves")
def llaves_publicas(usuario: str, u: dict = Depends(activo)):
    """Llaves públicas de uno mismo, de un cliente propio o del abogado propio."""
    with db.conexion() as con:
        otro = con.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
    if not otro:
        raise HTTPException(404, "Usuario no encontrado")
    relacionado = (otro["usuario"] == u["usuario"] or otro["abogado"] == u["usuario"]
                   or u["abogado"] == otro["usuario"])
    if not relacionado:
        raise HTTPException(403, "No tiene relación con ese usuario")
    if not otro["publica_cifrado"]:
        raise HTTPException(409, "Ese usuario aún no activa su cuenta")
    return {k: otro[k] for k in ("usuario", "nombre", "rol", "publica_cifrado",
                                 "publica_firma", "publica_ed25519")}


@app.post("/documentos", status_code=201)
def subir_documento(entrada: DocumentoEntrada, abogado: dict = Depends(solo_abogado)):
    paquete = b64_a_bytes(entrada.paquete_cifrado, "paquete_cifrado")
    b64_a_bytes(entrada.firma, "firma")
    for usuario, frag in entrada.fragmentos.items():
        b64_a_bytes(frag, f"fragmentos[{usuario}]")
    if abogado["debe_cambiar"] or not abogado["publica_ed25519"]:
        raise HTTPException(403, "Cuenta sin llaves registradas")
    if set(entrada.fragmentos) != {abogado["usuario"], entrada.cliente}:
        raise HTTPException(400, "Debe haber un fragmento para el abogado y otro para el cliente")

    with db.conexion() as con:
        cliente = con.execute("SELECT * FROM usuarios WHERE usuario = ?", (entrada.cliente,)).fetchone()
        if not cliente or cliente["abogado"] != abogado["usuario"]:
            raise HTTPException(403, "Ese cliente no pertenece a este abogado")
        if not cliente["publica_cifrado"]:
            raise HTTPException(409, "El cliente aún no activa su cuenta")
        if con.execute("SELECT 1 FROM documentos WHERE id = ?", (entrada.id,)).fetchone():
            raise HTTPException(409, "Ya existe un documento con ese ID")

        ruta = db.guardar_archivo(entrada.id, paquete)
        con.execute(
            "INSERT INTO documentos (id, firmante, titulo, firma, t, n, archivo) "
            "VALUES (?, ?, ?, ?, 2, 2, ?)",
            (entrada.id, abogado["usuario"], entrada.titulo, entrada.firma, str(ruta)))
        con.executemany(
            "INSERT INTO fragmentos (id_documento, usuario, fragmento_cifrado) VALUES (?, ?, ?)",
            [(entrada.id, usuario, frag) for usuario, frag in entrada.fragmentos.items()])
        db.registrar_evento(con, "documento_creado", usuario=abogado["usuario"],
                            id_documento=entrada.id, detalle=f"cliente: {entrada.cliente}")
    return {"id": entrada.id}


def nombres(con, usuarios: list[str]) -> dict[str, str]:
    """Nombre con el que se registró cada usuario, para mostrarlo en la interfaz."""
    marcas = ",".join("?" * len(usuarios))
    return dict(con.execute(f"SELECT usuario, nombre FROM usuarios WHERE usuario IN ({marcas})",
                            usuarios).fetchall())


@app.get("/documentos")
def mis_documentos(u: dict = Depends(usuario_actual)):
    with db.conexion() as con:
        filas = con.execute(
            "SELECT d.id, d.titulo, d.firmante, d.t, d.n, d.creado FROM documentos d "
            "JOIN fragmentos f ON f.id_documento = d.id WHERE f.usuario = ? "
            "ORDER BY d.creado DESC", (u["usuario"],)).fetchall()
        resultado = []
        for f in filas:
            doc = dict(f)
            doc["participantes"] = participantes(con, f["id"])
            doc["autorizaciones"] = autorizaciones_vigentes(con, f["id"])
            doc["nombres"] = nombres(con, doc["participantes"])
            resultado.append(doc)
    return resultado


@app.get("/documentos/{id_documento}")
def obtener_documento(id_documento: str, u: dict = Depends(usuario_actual)):
    with db.conexion() as con:
        lista = exigir_participante(con, id_documento, u["usuario"])
        doc = con.execute("SELECT * FROM documentos WHERE id = ?", (id_documento,)).fetchone()
        autorizaciones = autorizaciones_vigentes(con, id_documento)
        nombres_lista = nombres(con, lista)
    return {
        "id": doc["id"], "titulo": doc["titulo"], "firmante": doc["firmante"],
        "firma": doc["firma"], "t": doc["t"], "n": doc["n"], "creado": doc["creado"],
        "participantes": lista, "autorizaciones": autorizaciones, "nombres": nombres_lista,
        "paquete_cifrado": base64.b64encode(db.leer_archivo(id_documento)).decode(),
    }


@app.post("/documentos/{id_documento}/consentimientos")
def registrar_consentimiento(id_documento: str, entrada: ConsentimientoEntrada,
                             u: dict = Depends(activo)):
    """
    El usuario envía su consentimiento firmado con RSA-PSS. Si la firma es válida,
    vigente y corresponde a este documento, se registra en la bitácora y se le
    entrega SU fragmento cifrado (que solo él puede descifrar con RSA-OAEP).
    """
    consentimiento = b64_a_bytes(entrada.consentimiento, "consentimiento")
    firma = b64_a_bytes(entrada.firma, "firma")
    with db.conexion() as con:
        exigir_participante(con, id_documento, u["usuario"])

        def rechazar(motivo: str):
            db.registrar_evento(con, "consentimiento", usuario=u["usuario"], id_documento=id_documento,
                                consentimiento=consentimiento.decode(errors="replace"),
                                firma=entrada.firma, valida=False, detalle=motivo)
            con.commit()
            raise HTTPException(403, motivo)

        # 1. Firma RSA-PSS con la llave pública registrada del usuario
        publica = serialization.load_pem_public_key(u["publica_firma"].encode())
        if not rc.verificar_consentimiento(publica, consentimiento, firma):
            rechazar("Firma RSA-PSS inválida")

        # 2. Contenido: debe autorizar ESTE documento, por ESTE usuario, y ser reciente
        try:
            datos = json.loads(consentimiento)
            fecha = datetime.fromisoformat(datos["fecha"])
        except (ValueError, KeyError, TypeError):
            rechazar("Consentimiento con formato inválido")
        if fecha.tzinfo is None:
            rechazar("La fecha del consentimiento debe incluir zona horaria")
        if datos.get("accion") != "autorizo_apertura":
            rechazar("El consentimiento no autoriza una apertura")
        if datos.get("documento") != id_documento or datos.get("actor") != u["usuario"]:
            rechazar("El consentimiento es de otro documento o de otro usuario")
        if abs(datetime.now(timezone.utc) - fecha) > VIGENCIA:
            rechazar("Consentimiento vencido")

        # 3. No se acepta reenviar la misma firma (ataque de repetición)
        if con.execute("SELECT 1 FROM bitacora WHERE evento = 'consentimiento' AND valida = 1 "
                       "AND firma = ?", (entrada.firma,)).fetchone():
            rechazar("Consentimiento ya utilizado (repetición)")

        db.registrar_evento(con, "consentimiento", usuario=u["usuario"], id_documento=id_documento,
                            consentimiento=consentimiento.decode(), firma=entrada.firma,
                            valida=True, detalle="fragmento entregado")
        fragmento = con.execute(
            "SELECT fragmento_cifrado FROM fragmentos WHERE id_documento = ? AND usuario = ?",
            (id_documento, u["usuario"])).fetchone()["fragmento_cifrado"]
    return {"fragmento_cifrado": fragmento}


@app.post("/documentos/{id_documento}/aportes", status_code=201)
def aportar(id_documento: str, entrada: AporteEntrada, u: dict = Depends(activo)):
    """
    Un participante que ya autorizó entrega su fragmento al otro participante,
    cifrado con RSA-OAEP para él. El servidor no puede leerlo: solo lo guarda.
    """
    b64_a_bytes(entrada.fragmento_cifrado, "fragmento_cifrado")
    with db.conexion() as con:
        lista = exigir_participante(con, id_documento, u["usuario"])
        if entrada.para not in lista or entrada.para == u["usuario"]:
            raise HTTPException(400, "El destinatario debe ser otro participante del documento")
        if u["usuario"] not in autorizaciones_vigentes(con, id_documento):
            raise HTTPException(403, "Primero debe firmar su consentimiento de apertura")
        con.execute("DELETE FROM aportes WHERE id_documento = ? AND de = ? AND para = ?",
                    (id_documento, u["usuario"], entrada.para))
        con.execute("INSERT INTO aportes (id_documento, de, para, fragmento_cifrado) "
                    "VALUES (?, ?, ?, ?)",
                    (id_documento, u["usuario"], entrada.para, entrada.fragmento_cifrado))
        db.registrar_evento(con, "aporte", usuario=u["usuario"], id_documento=id_documento,
                            detalle=f"fragmento cifrado para {entrada.para}")
    return {"ok": True}


@app.get("/documentos/{id_documento}/aportes")
def aportes_recibidos(id_documento: str, u: dict = Depends(activo)):
    """Fragmentos que otros participantes le enviaron (cifrados para usted) y siguen vigentes."""
    with db.conexion() as con:
        exigir_participante(con, id_documento, u["usuario"])
        filas = con.execute(
            "SELECT de, fragmento_cifrado, fecha FROM aportes WHERE id_documento = ? AND para = ? "
            "AND fecha >= ?", (id_documento, u["usuario"], hace(VIGENCIA))).fetchall()
    return [dict(f) for f in filas]


@app.get("/bitacora")
def bitacora(u: dict = Depends(usuario_actual)):
    """Eventos del usuario, de sus documentos y, si es abogado, de sus clientes."""
    with db.conexion() as con:
        filas = con.execute(
            "SELECT * FROM bitacora WHERE usuario = ? "
            "OR id_documento IN (SELECT id_documento FROM fragmentos WHERE usuario = ?) "
            "OR usuario IN (SELECT usuario FROM usuarios WHERE abogado = ?) "
            "ORDER BY id DESC LIMIT 200", (u["usuario"], u["usuario"], u["usuario"])).fetchall()
    return [{k: f[k] for k in ("fecha", "evento", "usuario", "id_documento", "valida", "detalle")}
            for f in filas]
