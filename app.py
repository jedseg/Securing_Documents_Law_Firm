import streamlit as st
import crypto_core as cc
import shamir
import os

st.set_page_config(page_title="Portal Legal Seguro", layout="wide")

st.title("Portal Legal Seguro")
st.write("Interfaz completa: Firma, Cifrado y Control de Acceso Conjunto")

# Pestañas para dividir el flujo
tab_redactar, tab_acceder = st.tabs(["1. Redactar y Proteger", "2. Abrir Documento (Acceso Conjunto)"])

with tab_redactar:
    st.header("Solicitar / Redactar Documento")
    
    # Simulación de la identidad del firmante
    st.info("Generando par de llaves (Pública/Privada) temporales para esta sesión...")
    if "privada" not in st.session_state:
        st.session_state.privada, st.session_state.publica = cc.generar_par_firma()
    
    documento_texto = st.text_area("Contenido del Documento Legal", height=150, value="Testamento de Juan Perez: lego mi casa a mi hija Maria.")
    id_doc = st.text_input("ID del Documento (Metadato)", value="DOC-2026-0001")
    
    if st.button("Firmar, Cifrar y Generar Llaves de Acceso", type="primary"):
        doc_bytes = documento_texto.encode('utf-8')
        id_bytes = id_doc.encode('utf-8')
        
        #Firmar
        firma = cc.firmar(st.session_state.privada, doc_bytes)
        
        #Generar llave AES y cifrar
        llave_aes = cc.generar_llave()
        paquete_cifrado = cc.cifrar(llave_aes, doc_bytes, id_bytes)
        
        #Dividir llave (Shamir 2 de 2)
        fragmentos = shamir.dividir_secreto(llave_aes, t=2, n=2)
        
        #Guardamos en sesión simulando el backend/base de datos
        st.session_state.paquete_cifrado = paquete_cifrado
        st.session_state.firma = firma
        st.session_state.id_doc = id_bytes
        st.session_state.doc_bytes_original = doc_bytes #para verificar la firma después
        
        st.success("Documento protegido con éxito.")
        st.write("### Guarde sus llaves de acceso (Fragmentos)")
        st.write("Entregue este fragmento al **Cliente** (Actor 1):")
        st.code(fragmentos[0][1])
        st.write("Entregue este fragmento al **Abogado** (Actor 2):")
        st.code(fragmentos[1][1])



#PESTAÑA 2

with tab_acceder:
    st.header("Acceso a Documento Cifrado")
    
    if "paquete_cifrado" not in st.session_state:
        st.warning("Aún no hay un documento cifrado en el sistema. Vaya a la pestaña 'Redactar' primero.")
    else:
        st.info(f"Se requiere acceso conjunto para abrir el documento con ID: {st.session_state.id_doc.decode('utf-8')}")
        
        # Captura de fragmentos
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Actor 1: Cliente")
            y_cliente = st.text_input("Fragmento (Y) Cliente", type="password", key="yc")
        with col2:
            st.markdown("#### Actor 2: Abogado")
            y_abogado = st.text_input("Fragmento (Y) Abogado", type="password", key="ya")
            
        if st.button("Aportar fragmentos y Descifrar", type="primary"):
            if y_cliente and y_abogado:
                try:
                    #Preparar fragmentos
                    frag_aportados = [(1, int(y_cliente)), (2, int(y_abogado))]
                    
                    #Reconstruir llave
                    llave_recuperada = shamir.reconstruir_secreto(frag_aportados)
                    
                    #Descifrar documento
                    doc_descifrado_bytes = cc.descifrar(llave_recuperada, st.session_state.paquete_cifrado, st.session_state.id_doc)
                    doc_texto = doc_descifrado_bytes.decode('utf-8')
                    
                    #Verificar firma
                    firma_valida = cc.verificar_firma(st.session_state.publica, st.session_state.doc_bytes_original, st.session_state.firma)
                    
                    st.success("¡Autenticación por umbral exitosa! Llave reconstruida.")
                    
                    if firma_valida:
                        st.info("Firma digital verificada: El documento es auténtico (No repudio).")
                    else:
                        st.error("La firma digital no coincide. El documento pudo haber sido alterado.")
                        
                    st.write("### Contenido del Documento:")
                    st.text_area("Documento Original", value=doc_texto, height=150, disabled=True)
                    
                except ValueError:
                     st.error("Error: Asegúrese de ingresar solo números en los fragmentos.")
                except Exception as e:
                     st.error("Rechazado: La llave reconstruida es incorrecta o los fragmentos no corresponden al documento.")
            else:
                st.warning("Ambos actores deben proporcionar sus fragmentos.")