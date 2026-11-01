# Una sola imagen para el servidor del bufete y para el cliente local.
# El comando (servidor o cliente) lo define docker-compose.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Usuario sin privilegios (uid 1000 = usuario normal en Lightsail/Ubuntu y en Mac)
RUN useradd --uid 1000 --create-home bufete

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY crypto_core.py shamir.py rsa_core.py llavero.py totp.py ./
COPY backend/ backend/
COPY cliente/ cliente/

# Los archivos llegan con los permisos de la computadora donde se construye la
# imagen (en Mac pueden ser 600). El código queda legible pero no modificable.
RUN chmod -R a+rX,go-w /app

USER bufete

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
