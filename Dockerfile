FROM python:3.11-slim

WORKDIR /app

# Dependencias del sistema (para compilar algunas libs)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Copiamos requirements e instalamos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos código
COPY backend.py .
COPY app_streamlit.py .

# 👉 Ahora el backend escucha en 8001 y Streamlit en 8000
# Streamlit será el puerto "público"
ENV BACKEND_URL=http://localhost:8001

# Render va a exponer este puerto
EXPOSE 8000

CMD ["bash", "-c", "\
uvicorn backend:app --host 0.0.0.0 --port 8001 & \
streamlit run app_streamlit.py --server.address=0.0.0.0 --server.port=8000 \
"]
