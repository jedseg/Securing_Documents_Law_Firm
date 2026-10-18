# Securing documents in a law firm

Sistema para proteger documentos legales (testamentos, fideicomisos, contratos) de un bufete. Un documento solo puede abrirse cuando **el cliente y su abogado están juntos**.

## Archivos

| Archivo | Contenido |
|---|---|
| `app.py` | Interfaz en Streamlit: redactar y proteger, apertura conjunta, servidor y bitácora |
| `crypto_core.py` | Hash SHA-256, firma Ed25519, cifrado AES-256-GCM y el flujo completo `proteger()` / `abrir()` |
| `shamir.py` | Esquema de Shamir *t* de *n*, implementación propia sobre el campo primo 2^521 − 1 |
| `rsa_core.py` | RSA-3072: OAEP para cifrar los fragmentos y PSS para firmar el consentimiento de apertura |

## Servicios criptográficos

| Servicio | Mecanismo |
|---|---|
| Confidencialidad | AES-256-GCM |
| Integridad | SHA-256 y etiqueta de autenticación de GCM |
| No repudio | Firma Ed25519 del abogado sobre el documento |
| Acceso conjunto | Shamir 2 de 2 (cliente + abogado) sobre la llave AES |
| Custodia de fragmentos | RSA-OAEP con la llave pública de cada actor |
| Autenticación y no repudio de la apertura | Consentimiento firmado con RSA-PSS |

## Ejecutar

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Flujo (sign-then-encrypt)

1. El abogado firma `SHA-256(documento)` con su llave privada Ed25519.
2. Se genera una llave AES-256 aleatoria (DEK) y se cifra el documento con AES-GCM (nonce aleatorio de 12 bytes; el id del documento va como dato asociado).
3. La DEK se divide con Shamir en 2 fragmentos, uno para el cliente y otro para el abogado (umbral 2 de 2), y la llave completa se descarta.
4. Cada fragmento se cifra con **RSA-OAEP** usando la llave pública de su dueño. El servidor guarda los fragmentos cifrados sin poder leerlos.
5. Para abrir el documento, cada participante firma un **consentimiento de apertura con RSA-PSS** (queda en la bitácora) y descifra su fragmento con su llave privada.
6. Se juntan los 2 fragmentos, se reconstruye la DEK por interpolación de Lagrange, se descifra y se verifica la firma del abogado.

Cada actor tiene **dos pares de llaves RSA-3072 distintos**: uno para cifrar (OAEP) y otro para firmar (PSS). Ambos usan SHA-256 y MGF1-SHA-256.
