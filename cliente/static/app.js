// Interfaz del Portal Legal Seguro. Toda la criptografía ocurre en el cliente
// local (Python); este archivo solo muestra la información y llama a /api.

let usuarioActual = null;

// ------------------------------------------------------------- Utilidades
async function api(metodo, ruta, cuerpo) {
  const opciones = { method: metodo, credentials: "same-origin", headers: {} };
  if (metodo !== "GET") opciones.headers["X-Cliente-Local"] = "1";   // protección CSRF
  if (cuerpo !== undefined) {
    opciones.headers["Content-Type"] = "application/json";
    opciones.body = JSON.stringify(cuerpo);
  }
  const r = await fetch(ruta, opciones);
  const datos = await r.json().catch(() => ({}));
  if (!r.ok) {
    const error = new Error(datos.detail || `Error ${r.status}`);
    error.estado = r.status;
    throw error;
  }
  return datos;
}

// Envía un formulario con archivo (multipart) al cliente local
async function apiFormulario(ruta, formulario) {
  const r = await fetch(ruta, { method: "POST", credentials: "same-origin",
                                headers: { "X-Cliente-Local": "1" }, body: formulario });
  const datos = await r.json().catch(() => ({}));
  if (!r.ok) {
    const error = new Error(datos.detail || `Error ${r.status}`);
    error.estado = r.status;
    throw error;
  }
  return datos;
}

// Crea elementos sin usar innerHTML con datos del usuario (evita XSS)
function el(etiqueta, atributos = {}, ...hijos) {
  const nodo = document.createElement(etiqueta);
  for (const [k, v] of Object.entries(atributos)) {
    if (k === "class") nodo.className = v;
    else if (k.startsWith("on")) nodo.addEventListener(k.slice(2), v);
    else nodo.setAttribute(k, v);
  }
  for (const h of hijos.flat()) {
    if (h === null || h === undefined || h === false) continue;
    nodo.append(h instanceof Node ? h : document.createTextNode(String(h)));
  }
  return nodo;
}

function alerta(mensaje, tipo = "danger") {
  const caja = el("div", { class: `alert alert-${tipo} alert-dismissible fade show`, role: "alert" },
    mensaje, el("button", { type: "button", class: "btn-close", "data-bs-dismiss": "alert" }));
  const cont = document.getElementById("alertas");
  cont.replaceChildren(caja);
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (tipo === "success") setTimeout(() => caja.remove(), 6000);
}

function mostrarVista(id) {
  document.querySelectorAll(".vista").forEach(v => v.classList.add("d-none"));
  document.getElementById(id).classList.remove("d-none");
  document.getElementById("alertas").replaceChildren();
}

async function conCarga(boton, accion) {
  const original = boton.innerHTML;
  boton.disabled = true;
  boton.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Procesando...';
  try { await accion(); }
  catch (e) { alerta(e.message); }
  finally { boton.disabled = false; boton.innerHTML = original; }
}

const valor = id => document.getElementById(id).value.trim();

// --------------------------------------------------------------- Sesión
function entrarAlPanel(usuario) {
  usuarioActual = usuario;
  if (usuario.debe_activar) { mostrarVista("vista-activar"); return; }

  document.getElementById("nav-usuario").classList.replace("d-none", "d-flex");
  document.getElementById("nav-nombre").textContent = `${usuario.nombre} (${usuario.usuario})`;
  const rol = document.getElementById("nav-rol");
  rol.textContent = usuario.rol === "abogado" ? "Abogado" : "Cliente";
  rol.className = `badge badge-${usuario.rol}`;

  // Cada rol ve solo sus funciones (el servidor también lo impone)
  document.querySelectorAll(".solo-abogado").forEach(e =>
    e.classList.toggle("d-none", usuario.rol !== "abogado"));
  bootstrap.Tab.getOrCreateInstance(document.querySelector('[data-bs-target="#tab-documentos"]')).show();

  mostrarVista("vista-panel");
  cargarDocumentos();
  if (usuario.rol === "abogado") { cargarClientes(); sugerirId(); }
}

function salirAlLogin() {
  usuarioActual = null;
  document.getElementById("nav-usuario").classList.replace("d-flex", "d-none");
  document.querySelectorAll("form").forEach(f => f.reset());
  mostrarVista("vista-login");
}

document.getElementById("form-login").addEventListener("submit", e => {
  e.preventDefault();
  conCarga(e.submitter, async () => {
    const usuario = await api("POST", "/api/login",
      { usuario: valor("login-usuario"), contrasena: document.getElementById("login-contrasena").value });
    entrarAlPanel(usuario);
  });
});

document.getElementById("form-registro").addEventListener("submit", e => {
  e.preventDefault();
  const contrasena = document.getElementById("reg-contrasena").value;
  if (contrasena !== document.getElementById("reg-confirmar").value) {
    alerta("Las contraseñas no coinciden"); return;
  }
  conCarga(e.submitter, async () => {
    await api("POST", "/api/registro-abogado", {
      usuario: valor("reg-usuario"), nombre: valor("reg-nombre"),
      contrasena, codigo_bufete: valor("reg-codigo"),
    });
    const usuario = valor("reg-usuario");
    e.target.reset();
    mostrarVista("vista-login");
    document.getElementById("login-usuario").value = usuario;
    alerta("Registro exitoso. Sus llaves se generaron en este equipo. Ya puede iniciar sesión.", "success");
  });
});

document.getElementById("form-activar").addEventListener("submit", e => {
  e.preventDefault();
  const nueva = document.getElementById("act-nueva").value;
  if (nueva !== document.getElementById("act-confirmar").value) {
    alerta("Las contraseñas nuevas no coinciden"); return;
  }
  conCarga(e.submitter, async () => {
    const usuario = await api("POST", "/api/activar",
      { contrasena_actual: document.getElementById("act-actual").value, contrasena_nueva: nueva });
    entrarAlPanel(usuario);
    alerta("Cuenta activada. Sus llaves RSA se generaron y guardaron cifradas en este equipo.", "success");
  });
});

document.getElementById("btn-salir").addEventListener("click", async () => {
  await api("POST", "/api/logout").catch(() => {});
  salirAlLogin();
});

document.querySelectorAll("[data-ir]").forEach(a => a.addEventListener("click", e => {
  e.preventDefault();
  mostrarVista(a.dataset.ir);
}));

// ----------------------------------------------------------- Documentos
async function cargarDocumentos() {
  const lista = document.getElementById("lista-documentos");
  try {
    const documentos = await api("GET", "/api/documentos");
    if (!documentos.length) {
      lista.replaceChildren(el("p", { class: "text-muted" }, "Aún no participa en ningún documento."));
      return;
    }
    lista.replaceChildren(...documentos.map(tarjetaDocumento));
  } catch (e) { manejarError(e); }
}

function tarjetaDocumento(d) {
  const nombre = u => (d.nombres && d.nombres[u]) || u;
  const participantes = d.participantes.map(p => {
    const autorizo = d.autorizaciones.includes(p);
    return el("span", { class: `badge participante me-1 ${autorizo ? "text-bg-success" : "text-bg-secondary"}` },
      el("i", { class: `bi ${autorizo ? "bi-check-circle" : "bi-hourglass-split"}` }), " ", nombre(p),
      autorizo ? " · autorizó" : " · pendiente");
  });

  const botones = el("div", { class: "d-flex flex-wrap gap-2 mt-3" },
    el("button", {
      class: `btn btn-sm ${d.autorice ? "btn-outline-success" : "btn-success"}`,
      onclick: ev => conCarga(ev.currentTarget, async () => {
        await api("POST", `/api/documentos/${encodeURIComponent(d.id)}/autorizar`);
        alerta("Su autorización se registró correctamente. El documento se abrirá cuando ambos participantes autoricen.", "success");
        await cargarDocumentos();
      }),
    }, el("i", { class: "bi bi-pen" }), d.autorice ? " Autorizar de nuevo" : " Autorizar apertura"),
    el("button", {
      class: "btn btn-sm btn-primary",
      onclick: ev => conCarga(ev.currentTarget, () => abrirDocumento(d.id)),
    }, el("i", { class: "bi bi-unlock" }), " Abrir documento"),
  );

  return el("div", { class: "col-lg-6" },
    el("div", { class: "card shadow-sm tarjeta-doc h-100" },
      el("div", { class: "card-body" },
        el("div", { class: "d-flex justify-content-between" },
          el("h3", { class: "h6 mb-1" }, d.titulo),
          el("code", { class: "small" }, d.id)),
        el("p", { class: "small text-muted mb-2" },
          `Firmado por ${nombre(d.firmante)} · ${d.creado} UTC`),
        el("div", {}, ...participantes),
        botones)));
}

function tamLegible(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function abrirDocumento(id) {
  const r = await api("POST", `/api/documentos/${encodeURIComponent(id)}/abrir`);
  const url = `/api/documentos/${encodeURIComponent(id)}/archivo`;
  document.getElementById("modal-titulo").textContent = `${r.titulo} (${r.id})`;
  document.getElementById("modal-verificacion").textContent =
    "Documento abierto y verificado con éxito.";
  document.getElementById("modal-nombre").textContent = r.nombre;
  document.getElementById("modal-tam").textContent = tamLegible(r.tam);
  document.getElementById("modal-descargar").href = url;

  // Vista previa solo para tipos seguros; el resto se descarga
  const vista = document.getElementById("modal-vista");
  if (r.tipo === "application/pdf") {
    vista.replaceChildren(el("iframe", { src: `${url}?ver=1`, title: r.nombre, class: "visor-pdf" }));
  } else if (["image/png", "image/jpeg", "image/gif"].includes(r.tipo)) {
    vista.replaceChildren(el("img", { src: `${url}?ver=1`, alt: r.nombre, class: "img-fluid rounded border" }));
  } else if (r.tipo === "text/plain") {
    const texto = await (await fetch(`${url}?ver=1`, { credentials: "same-origin" })).text();
    vista.replaceChildren(el("pre", { class: "documento-texto" }, texto));
  } else {
    vista.replaceChildren(el("div", { class: "alert alert-light border small mb-0" },
      "Este tipo de archivo no tiene vista previa. Use el botón Descargar para abrirlo."));
  }
  bootstrap.Modal.getOrCreateInstance(document.getElementById("modal-documento")).show();
}

document.getElementById("btn-recargar").addEventListener("click", cargarDocumentos);
document.getElementById("modal-documento").addEventListener("hidden.bs.modal", () =>
  document.getElementById("modal-vista").replaceChildren());

// ----------------------------------------------------- Nuevo documento
function sugerirId() {
  const hoy = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const azar = Math.random().toString(36).slice(2, 6).toUpperCase();
  document.getElementById("doc-id").value = `DOC-${hoy}-${azar}`;
}

document.getElementById("form-documento").addEventListener("submit", e => {
  e.preventDefault();
  const archivo = document.getElementById("doc-archivo").files[0];
  if (!archivo) { alerta("Seleccione un archivo"); return; }
  if (archivo.size > 20 * 1024 * 1024) { alerta("El archivo supera el máximo de 20 MB"); return; }
  conCarga(e.submitter, async () => {
    const datos = new FormData();
    datos.append("id", valor("doc-id"));
    datos.append("titulo", valor("doc-titulo"));
    datos.append("cliente", document.getElementById("doc-cliente").value);
    datos.append("archivo", archivo);
    const r = await apiFormulario("/api/documentos", datos);
    document.getElementById("resultado-documento").replaceChildren(
      el("div", { class: "alert alert-success mb-0" },
        el("strong", {}, "Documento enviado con éxito."),
        el("div", { class: "mt-2" }, "Archivo: ", el("strong", {}, r.nombre))));
    alerta(`Documento ${r.id} protegido y guardado en el servidor.`, "success");
    e.target.querySelector("#doc-archivo").value = "";
    sugerirId();
    cargarDocumentos();
  });
});

// ------------------------------------------------------------ Clientes
async function cargarClientes() {
  try {
    const clientes = await api("GET", "/api/clientes");
    document.getElementById("tabla-clientes").replaceChildren(...(clientes.length ? clientes.map(c =>
      el("tr", {},
        el("td", {}, c.nombre),
        el("td", {}, el("code", {}, c.usuario))))
      : [el("tr", {}, el("td", { colspan: "2", class: "text-muted" }, "Aún no tiene clientes."))]));

    const select = document.getElementById("doc-cliente");
    const activos = clientes.filter(c => c.llaves_registradas);
    select.replaceChildren(...(activos.length
      ? activos.map(c => el("option", { value: c.usuario }, `${c.nombre} (${c.usuario})`))
      : [el("option", { value: "" }, "No hay clientes activos")]));
  } catch (e) { manejarError(e); }
}

document.getElementById("form-cliente").addEventListener("submit", e => {
  e.preventDefault();
  conCarga(e.submitter, async () => {
    const usuario = valor("cli-usuario");
    await api("POST", "/api/clientes", {
      usuario, nombre: valor("cli-nombre"), contrasena_temporal: valor("cli-temporal"),
    });
    e.target.reset();
    alerta(`Cliente ${usuario} dado de alta. Entréguele su usuario y contraseña temporal; ` +
           "deberá activar su cuenta desde su propio equipo.", "success");
    cargarClientes();
  });
});

// ------------------------------------------------------------ Bitácora
const NOMBRES_EVENTO = {
  abogado_registrado: "Abogado registrado", cliente_creado: "Cliente dado de alta",
  cliente_activado: "Cliente activó su cuenta", login: "Inicio de sesión",
  login_fallido: "Inicio de sesión fallido", documento_creado: "Documento creado",
  consentimiento: "Consentimiento de apertura", aporte: "Fragmento enviado",
};

async function cargarBitacora() {
  try {
    const registros = await api("GET", "/api/bitacora");
    document.getElementById("tabla-bitacora").replaceChildren(...registros.map(r =>
      el("tr", {},
        el("td", {}, r.fecha),
        el("td", {}, NOMBRES_EVENTO[r.evento] || r.evento),
        el("td", {}, r.usuario || ""),
        el("td", {}, r.id_documento || ""),
        el("td", {}, r.detalle || ""))));
  } catch (e) { manejarError(e); }
}

document.getElementById("btn-bitacora").addEventListener("click", cargarBitacora);
document.querySelector('[data-bs-target="#tab-bitacora"]').addEventListener("shown.bs.tab", cargarBitacora);
document.querySelector('[data-bs-target="#tab-clientes"]').addEventListener("shown.bs.tab", cargarClientes);
// Al entrar a "Nuevo documento" se recarga la lista: un cliente pudo activarse mientras tanto
document.querySelector('[data-bs-target="#tab-nuevo"]').addEventListener("shown.bs.tab", cargarClientes);
document.querySelector('[data-bs-target="#tab-documentos"]').addEventListener("shown.bs.tab", cargarDocumentos);

function manejarError(e) {
  if (e.estado === 401) { salirAlLogin(); alerta("Su sesión expiró. Inicie sesión de nuevo.", "warning"); }
  else alerta(e.message);
}

// Actualiza la lista de documentos cada 10 s mientras esté visible, para ver
// cuándo el otro participante autoriza la apertura
setInterval(() => {
  const visible = !document.getElementById("vista-panel").classList.contains("d-none")
    && document.getElementById("tab-documentos").classList.contains("active")
    && !document.querySelector(".modal.show") && !document.querySelector("button:disabled");
  if (usuarioActual && !usuarioActual.debe_activar && visible) cargarDocumentos();
}, 10000);

// ---------------------------------------------------------------- Inicio
(async () => {
  try {
    const estado = await api("GET", "/api/estado");
    if (!estado.servidor) {
      const aviso = document.getElementById("aviso-servidor");
      aviso.textContent = `No hay conexión con el servidor del bufete (${estado.url_servidor}). ` +
                          "Inícielo con: uvicorn backend.main:app --port 8000";
      aviso.classList.remove("d-none");
    }
  } catch { /* el cliente local siempre responde */ }
  try { entrarAlPanel(await api("GET", "/api/yo")); }
  catch { mostrarVista("vista-login"); }
})();
