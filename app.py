import base64

import streamlit as st
from cryptography.exceptions import InvalidTag

import crypto_core as cc
import rsa_core as rc

st.set_page_config(page_title="Portal Legal Seguro", layout="wide")

st.title("Portal Legal Seguro")
st.write("Firma (Ed25519), cifrado (AES-256-GCM), acceso conjunto (Shamir 2 de 2), "
         "custodia de fragmentos (RSA-OAEP) y consentimiento de apertura (RSA-PSS)")


def corto(datos: bytes, n: int = 32) -> str:
    """Muestra los primeros caracteres en base64 de un valor binario."""
    return base64.b64encode(datos).decode()[:n] + "..."


# ------------------------------------------------------------------ Estado
# En el sistema real cada actor tiene sus llaves en SU dispositivo y el
# "servidor" es el back-end. Aquí se simulan en la sesión de Streamlit.
if "actores" not in st.session_state:
    with st.spinner("Generando llaves RSA-3072 del cliente y del abogado..."):
        st.session_state.actores = {
            "Cliente": rc.Actor("Cliente"),
            "Abogado": rc.Actor("Abogado"),
        }
        # Firma Ed25519 del abogado para el documento legal
        st.session_state.privada_ed, st.session_state.publica_ed = cc.generar_par_firma()
        st.session_state.servidor = {"documentos": {}, "bitacora": []}
        st.session_state.aportes = {}   # id_doc -> {actor: fragmento}

actores = st.session_state.actores
servidor = st.session_state.servidor

tab_redactar, tab_acceder, tab_servidor = st.tabs(
    ["1. Redactar y Proteger", "2. Abrir Documento (Acceso Conjunto)", "3. Servidor y Bitácora"])

# ================================================================ PESTAÑA 1
with tab_redactar:
    st.header("Redactar y proteger documento (Abogado)")
    st.caption("Cada actor tiene dos pares de llaves RSA-3072: uno para cifrar (OAEP) "
               "y otro para firmar (PSS). El abogado además firma el documento con Ed25519.")

    documento_texto = st.text_area("Contenido del Documento Legal", height=150,
                                   value="Testamento de Juan Perez: lego mi casa a mi hija Maria.")
    id_doc = st.text_input("ID del Documento (Metadato)", value="DOC-2026-0001")

    if st.button("Firmar, Cifrar y Repartir Fragmentos", type="primary"):
        if id_doc in servidor["documentos"]:
            st.error("Ya existe un documento con ese ID.")
        else:
            doc_bytes = documento_texto.encode("utf-8")
            protegido, envueltos = cc.proteger_para_actores(
                doc_bytes, id_doc, st.session_state.privada_ed, t=2,
                publicas_cifrado={n: a.publica_cifrado for n, a in actores.items()})

            # Lo único que se envía al servidor: nada de esto permite leer el documento
            servidor["documentos"][id_doc] = {"protegido": protegido, "fragmentos": envueltos}
            st.session_state.aportes[id_doc] = {}

            st.success("Documento protegido y enviado al servidor.")
            st.write(f"**SHA-256:** `{cc.huella(doc_bytes).hex()}`")
            st.write(f"**Firma Ed25519 del abogado:** `{corto(protegido.firma, 48)}`")
            st.write(f"**Documento cifrado (AES-256-GCM):** `{corto(protegido.paquete_cifrado, 48)}` "
                     f"({len(protegido.paquete_cifrado)} bytes)")
            st.write("### Fragmentos de la llave (Shamir 2 de 2), cifrados con RSA-OAEP")
            for nombre, env in envueltos.items():
                st.write(f"**{nombre}:** `{corto(env, 48)}` ({len(env)} bytes) "
                         f"— solo lo descifra la llave privada del {nombre.lower()}")
            st.info("La llave AES completa se borró. El servidor guarda los fragmentos, "
                    "pero no puede reconstruirla.")

# ================================================================ PESTAÑA 2
with tab_acceder:
    st.header("Acceso a Documento Cifrado")

    if not servidor["documentos"]:
        st.warning("Aún no hay documentos en el servidor. Vaya a la pestaña 'Redactar' primero.")
    else:
        id_sel = st.selectbox("Documento", list(servidor["documentos"]))
        registro = servidor["documentos"][id_sel]
        aportes = st.session_state.aportes.setdefault(id_sel, {})

        st.info("Se requiere que el Cliente y el Abogado autoricen la apertura. "
                "En el sistema real cada uno lo hace desde su propio dispositivo.")

        col1, col2 = st.columns(2)
        for col, nombre in zip((col1, col2), actores):
            actor = actores[nombre]
            with col:
                st.markdown(f"#### {nombre}")
                if nombre in aportes:
                    st.success("Consentimiento firmado y fragmento aportado.")
                elif st.button(f"Autorizar apertura y aportar fragmento", key=f"aportar_{nombre}"):
                    # 1. Firma su consentimiento con RSA-PSS
                    consentimiento = rc.crear_consentimiento(nombre, id_sel)
                    firma = rc.firmar_consentimiento(actor.privada_firma, consentimiento)
                    # 2. El servidor verifica la firma y la registra en la bitácora
                    valida = rc.verificar_consentimiento(actor.publica_firma, consentimiento, firma)
                    servidor["bitacora"].append(
                        {"consentimiento": consentimiento, "firma": firma,
                         "actor": nombre, "valida": valida})
                    if not valida:
                        st.error("El servidor rechazó la firma del consentimiento.")
                    else:
                        # 3. Descifra SU fragmento con su llave privada RSA-OAEP
                        aportes[nombre] = rc.desenvolver_fragmento(
                            actor.privada_cifrado, registro["fragmentos"][nombre])
                        st.rerun()

        st.write(f"Fragmentos aportados: **{len(aportes)} de {registro['protegido'].t}**")

        c1, c2 = st.columns(2)
        with c1:
            abrir = st.button("Reconstruir llave y Descifrar", type="primary")
        with c2:
            if st.button("Reiniciar aportes"):
                st.session_state.aportes[id_sel] = {}
                st.rerun()

        if abrir:
            if not aportes:
                st.warning("Ningún actor ha aportado su fragmento.")
            else:
                try:
                    # Reconstruye la llave (Shamir), descifra (AES-GCM) y verifica la firma (Ed25519)
                    doc_bytes = cc.abrir(registro["protegido"], list(aportes.values()),
                                         st.session_state.publica_ed)
                    st.success("Llave reconstruida con los fragmentos de ambos actores.")
                    st.info("Firma digital del abogado verificada sobre el documento "
                            "descifrado: el documento es auténtico (No repudio).")
                    st.text_area("Contenido del Documento", value=doc_bytes.decode("utf-8"),
                                 height=150, disabled=True)
                except InvalidTag:
                    st.error("Rechazado: la llave reconstruida es incorrecta o el documento "
                             "fue alterado. Se requieren los fragmentos de ambos actores.")
                except ValueError:
                    st.error("Rechazado: la firma digital no corresponde al documento.")

# ================================================================ PESTAÑA 3
with tab_servidor:
    st.header("Lo que ve el servidor")

    if not servidor["documentos"]:
        st.write("El servidor no tiene documentos.")
    for id_d, reg in servidor["documentos"].items():
        with st.expander(f"{id_d}", expanded=False):
            p = reg["protegido"]
            st.write(f"Documento cifrado: `{corto(p.paquete_cifrado, 60)}`")
            st.write(f"Firma Ed25519: `{corto(p.firma, 60)}`")
            for nombre, env in reg["fragmentos"].items():
                st.write(f"Fragmento cifrado del {nombre.lower()}: `{corto(env, 60)}`")
            st.caption("Ningún dato permite leer el documento ni reconstruir la llave.")

            if st.button("Simular ataque: alterar 1 byte del documento cifrado",
                         key=f"ataque_{id_d}"):
                alterado = bytearray(p.paquete_cifrado)
                alterado[20] ^= 0x01
                p.paquete_cifrado = bytes(alterado)
                st.warning("Documento alterado en el servidor. Intente abrirlo en la "
                           "pestaña 2: AES-GCM debe rechazarlo.")

    st.header("Bitácora de aperturas (consentimientos firmados con RSA-PSS)")
    if not servidor["bitacora"]:
        st.write("Sin registros.")
    else:
        filas = []
        for r in servidor["bitacora"]:
            datos = r["consentimiento"].decode()
            filas.append({"Actor": r["actor"], "Consentimiento": datos,
                          "Firma RSA-PSS": corto(r["firma"], 24),
                          "Verificada": "Sí" if r["valida"] else "No"})
        st.table(filas)
