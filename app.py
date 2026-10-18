import streamlit as st

# Configuración básica de la página
st.set_page_config(page_title="Portal Legal Seguro", layout="centered")

st.title("Portal Legal Seguro")
st.write("Interfaz de captura y aportación de llaves")

#Selección de Rol
rol = st.selectbox("Seleccione su rol:", ["Cliente", "Abogado del Bufete"])

st.subheader("Acceso a Documento Cifrado")
st.write("Por favor, ingrese su fragmento de llave (Share) para la reconstrucción por umbral.")

col1, col2 = st.columns(2)
with col1:
    share_x = st.number_input("ID de Fragmento (X)", min_value=1, step=1)
with col2:
    share_y = st.text_input("Valor del Fragmento (Y)")

if st.button("Aportar fragmento"):
    if share_y:
        st.success(f"Fragmento aportado exitosamente por el {rol}.")
        st.info(f"Datos enviados al Motor Criptográfico: X={share_x}, Y={share_y}")
    else:
        st.error("Por favor, ingrese el valor de su fragmento.")