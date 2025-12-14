# pages/3_📥_Importar.py
import os
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8001").rstrip("/")


st.set_page_config(page_title="Importar", layout="wide")

if "token" not in st.session_state:
    st.session_state["token"] = None
if "page" not in st.session_state:
    st.session_state["page"] = 0

def auth_headers():
    t = st.session_state.get("token")
    return {"x-token": t} if t else {}

def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

def show_http_error(resp, default="Error"):
    data = safe_json(resp)
    detail = data.get("detail") if isinstance(data, dict) else None
    st.error(detail or f"{default}: {resp.status_code} - {resp.text}")

def request_post(url, **kwargs):
    try:
        return requests.post(url, **kwargs)
    except Exception as e:
        st.error(f"Error conexión (POST): {e}")
        return None

st.title("📥 Importar personas (CSV o Excel)")

if not st.session_state.get("token"):
    st.warning("No estás logueado. Volvé a Home y hacé login.")
    st.stop()

st.info(
    "Subí el archivo y el backend se encarga de: crear nuevas por DNI y "
    "actualizar existentes completando datos/meses sin duplicar."
)

up = st.file_uploader("Cargar archivo", type=["csv", "xls", "xlsx"], key="uploader_page")

# ✅ botón siempre visible
if st.button("Importar archivo", key="btn_importar_page"):
    if up is None:
        st.warning("Primero cargá un archivo.")
    else:
        files = {"file": (up.name, up.getvalue(), up.type or "application/octet-stream")}
        r = request_post(
            f"{BACKEND_URL}/import-personas",
            headers=auth_headers(),
            files=files,
            timeout=300,
        )
        if r is None:
            st.stop()
        if r.status_code == 200:
            data = safe_json(r) or {}
            st.success(data.get("detail", "Importación OK"))
            st.session_state["page"] = 0
            st.rerun()
        else:
            show_http_error(r, "Importación fallida")
