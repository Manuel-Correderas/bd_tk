FROM python:3.11-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BACKEND_URL=http://127.0.0.1:8001

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend.py .
COPY app_streamlit.py .
COPY pages ./pages

EXPOSE 8001

CMD ["bash", "-lc", "uvicorn backend:app --host 0.0.0.0 --port 8001 & streamlit run app_streamlit.py --server.address=0.0.0.0 --server.port=${PORT} --server.enableCORS=false --server.enableXsrfProtection=false"]
