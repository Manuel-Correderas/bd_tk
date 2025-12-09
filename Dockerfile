FROM python:3.11-slim

WORKDIR /app

# Instalamos dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiamos requirements e instalamos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el código
COPY backend.py .
COPY app_streamlit.py .

# Streamlit expone el servicio web
EXPOSE 8501

# Backend para uso interno dentro del contenedor
ENV BACKEND_URL=http://localhost:8000

# Levanta FastAPI y Streamlit juntos
CMD ["bash", "-c", "\
uvicorn backend:app --host 0.0.0.0 --port 8000 & \
streamlit run app_streamlit.py --server.address=0.0.0.0 --server.port=8501 \
"]
