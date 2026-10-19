# Securing documents in a law firm

Sistema para proteger documentos legales (testamentos, fideicomisos, contratos) de un bufete. Un documento solo puede abrirse cuando **el cliente y su abogado autorizan juntos**.

## Arquitectura

```
 Computadora del ABOGADO                     Computadora del CLIENTE
 ┌──────────────────────────┐               ┌──────────────────────────┐
 │ Navegador (HTML+Bootstrap)│               │ Navegador (HTML+Bootstrap)│
 │            │ localhost    │               │            │ localhost    │
 │ Cliente local (Python)    │               │ Cliente local (Python)    │
 │  - llavero (llaves priv.) │               │  - llavero (llaves priv.) │
 │  - crypto_core / shamir / │               │  - crypto_core / shamir / │
 │    rsa_core               │               │    rsa_core               │
 └────────────┬─────────────┘               └─────────────┬────────────┘
              │      solo datos cifrados, firmas y llaves públicas
              └──────────────────┐   ┌───────────────────┘
                                 ▼   ▼
                    ┌──────────────────────────────┐
                    │ Servidor del bufete (FastAPI) │
                    │ login, roles, sesiones        │
                    │ SQLite + almacén de .bin      │
                    └──────────────────────────────┘
```

- **El servidor es de conocimiento cero**: nunca recibe llaves privadas, fragmentos en claro ni documentos en claro. Solo guarda datos cifrados, verifica firmas con llaves públicas y controla los permisos.
- **Toda la criptografía con llaves privadas ocurre en el cliente local** de cada usuario, con los módulos `crypto_core.py`, `shamir.py` y `rsa_core.py`.

## Roles

| Función | Abogado | Cliente |
|---|:---:|:---:|
| Registrarse (con el código del bufete) | ✅ | ❌ |
| Dar de alta clientes | ✅ | ❌ |
| Activar su cuenta (primer acceso, cambia la contraseña temporal) | — | ✅ |
| Subir, firmar y proteger documentos (PDF, Word, imagen, texto) | ✅ | ❌ |
| Ver los documentos en los que participa | ✅ | ✅ |
| Autorizar la apertura (consentimiento firmado) | ✅ | ✅ |
| Abrir y descargar un documento (cuando ambos autorizaron) | ✅ | ✅ |
| Bitácora de auditoría | ✅ (suya y de sus clientes) | ✅ (suya) |

Los permisos se aplican en el **servidor**; la interfaz solo oculta lo que cada rol no puede usar.

## Archivos

| Archivo | Contenido |
|---|---|
| `crypto_core.py` | Hash SHA-256, firma Ed25519, cifrado AES-256-GCM y el flujo `proteger()` / `abrir()` |
| `shamir.py` | Esquema de Shamir *t* de *n*, implementación propia sobre el campo primo 2^521 − 1 |
| `rsa_core.py` | RSA-3072: OAEP para cifrar fragmentos y PSS para firmar consentimientos |
| `llavero.py` | Guarda las llaves privadas en el equipo del usuario, cifradas con su contraseña |
| `backend/main.py` | API del servidor: login, roles, documentos, consentimientos, aportes y bitácora |
| `backend/db.py` | Base de datos SQLite y almacén de documentos cifrados |
| `backend/seguridad.py` | Contraseñas con scrypt y tokens de sesión |
| `cliente/main.py` | Cliente local: sirve la interfaz y hace la criptografía |
| `cliente/paquete.py` | Junta nombre, tipo y contenido del archivo en un solo bloque que se firma y se cifra |
| `cliente/servidor_api.py` | Conexión del cliente local con el servidor |
| `cliente/static/` | Interfaz web: `index.html`, `app.js`, `estilos.css` (Bootstrap 5) |

## Servicios criptográficos

| Servicio | Mecanismo |
|---|---|
| Confidencialidad | AES-256-GCM |
| Integridad | SHA-256 y etiqueta de autenticación de GCM |
| No repudio del documento | Firma Ed25519 del abogado |
| Acceso conjunto | Shamir 2 de 2 (cliente + abogado) sobre la llave AES |
| Custodia de fragmentos | RSA-OAEP con la llave pública de cada usuario |
| Autenticación y no repudio de la apertura | Consentimiento firmado con RSA-PSS, verificado por el servidor |
| Protección de llaves privadas | PKCS#8 cifrado con la contraseña del usuario |
| Contraseñas en el servidor | scrypt con sal aleatoria (nunca se guardan en claro) |
| Sesiones | Token aleatorio de 256 bits; el servidor solo guarda su SHA-256 |

## Ejecutar

La primera vez:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Servidor del bufete (una sola vez para todos)

```bash
uvicorn backend.main:app --port 8000
```

El código del bufete para registrar abogados es `BUFETE-2026`. Se puede cambiar con la variable `BUFETE_CODIGO`.

### Cliente local (uno por usuario)

```bash
uvicorn cliente.main:app --port 8080
```

Abra http://127.0.0.1:8080 en el navegador.

### Demostración con abogado y cliente en la misma computadora

Cada usuario necesita **su propio cliente local**, con su propia carpeta de llaves (simula dos computadoras). Use tres terminales con el `venv` activado:

```bash
# Terminal 1: servidor
uvicorn backend.main:app --port 8000

# Terminal 2: equipo del abogado
LLAVERO_DIR=llaves_abogado uvicorn cliente.main:app --port 8080

# Terminal 3: equipo del cliente
LLAVERO_DIR=llaves_cliente uvicorn cliente.main:app --port 8081
```

- Abogado: http://127.0.0.1:8080
- Cliente: http://127.0.0.1:8081

### Flujo de la demostración

1. **Abogado (8080):** "Registrarse" con el código `BUFETE-2026` e iniciar sesión.
2. **Abogado:** en *Mis clientes*, dar de alta al cliente con una contraseña temporal.
3. **Cliente (8081):** iniciar sesión con la contraseña temporal y activar la cuenta (crea su contraseña y sus llaves en su equipo).
4. **Abogado:** en *Nuevo documento*, elegir al cliente, poner un título, seleccionar el archivo (máximo 20 MB) y enviar.
5. **Cliente:** en *Documentos*, "Autorizar apertura". Si intenta abrir, el sistema dice que falta la autorización del abogado.
6. **Abogado:** "Autorizar apertura" y "Abrir documento": se muestra la vista previa (PDF, imagen o texto) y el botón *Descargar* entrega el archivo original. El cliente también puede abrirlo.
7. *Bitácora*: muestra todo lo ocurrido.

## El archivo

- El archivo se lee **en el equipo del abogado**. Su nombre y tipo se guardan **junto con el contenido** (`cliente/paquete.py`) y todo se firma y se cifra: el servidor no ve ni el nombre del archivo. Lo único visible para el servidor es el **título** que escribe el abogado.
- Al abrirlo, el archivo descifrado solo vive en la memoria del cliente local. La vista previa se muestra solo para PDF, imágenes y texto; cualquier otro tipo (Word, HTML…) solo se descarga, para que no pueda ejecutar código en la página.
- El SHA-256 que se muestra al subir y al abrir es el del archivo original: se puede comparar con `shasum -a 256 archivo` en la Terminal.

## Cómo funciona la apertura conjunta

1. Cada participante firma un **consentimiento de apertura con RSA-PSS**. El servidor verifica que la firma sea válida, que corresponda a ese documento y usuario, que sea reciente (5 minutos) y que no se haya usado antes; si todo está bien, lo registra en la bitácora y le entrega **su** fragmento cifrado.
2. El participante descifra su fragmento con su llave privada (**RSA-OAEP**) y lo **vuelve a cifrar con la llave pública del otro participante** antes de enviarlo por el servidor. El servidor solo lo retransmite, sin poder leerlo.
3. Cuando ambos autorizaron dentro de la ventana de 5 minutos, cada uno tiene los 2 fragmentos: se reconstruye la llave con **Shamir** (interpolación de Lagrange), se descifra con **AES-256-GCM** y se verifica la firma **Ed25519** del abogado.

## Protecciones adicionales

- **Servidor:** bloqueo tras 5 inicios de sesión fallidos; mismo tiempo de respuesta exista o no el usuario; código del bufete para registrar abogados; contraseña temporal obligatoria de cambiar para clientes.
- **Cliente local:** solo acepta conexiones desde la propia computadora (`127.0.0.1`/`localhost`, evita *DNS rebinding*); exige una cabecera propia en cada operación (evita CSRF); cookie de sesión `HttpOnly` y `SameSite=Strict`; la interfaz nunca inserta datos del usuario como HTML (evita XSS).
- Al iniciar sesión, el cliente local comprueba que las llaves públicas registradas en el servidor sean las de su llavero (detecta una suplantación de llaves).

## Datos locales

Las carpetas `datos/` (base de datos y documentos cifrados) y `llaves_*` (llaves privadas) se crean al usar el sistema y **no se suben al repositorio** (`.gitignore`).
