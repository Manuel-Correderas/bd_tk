FROM python:3.11-slim

WORKDIR /app

# Mejoras runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BACKEND_URL=http://127.0.0.1:8001

# Dependencias del sistema (si tu requirements tiene wheels que compilan)
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar proyecto
COPY backend.py .
COPY app_streamlit.py .
COPY pages ./pages
COPY personas.db .
COPY .env .

# Puertos
EXPOSE 8501 8001

# FastAPI + Streamlit (1 container)
CMD ["bash", "-lc", "uvicorn backend:app --host 0.0.0.0 --port 8001 & streamlit run app_streamlit.py --server.address=0.0.0.0 --server.port=8501"]
