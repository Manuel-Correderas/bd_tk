# pages/2_👤_Crear_Editar.py
import os
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8001").rstrip("/")


st.set_page_config(page_title="Crear/Editar", layout="wide")

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

def request_put(url, **kwargs):
    try:
        return requests.put(url, **kwargs)
    except Exception as e:
        st.error(f"Error conexión (PUT): {e}")
        return None

st.title("👤 Crear / Editar Persona")

if not st.session_state.get("token"):
    st.warning("No estás logueado. Volvé a Home y hacé login.")
    st.stop()

modo = st.radio("Modo", ["Crear nueva", "Editar por ID"], horizontal=True, key="modo_ce_page")

nombre = st.text_input("Nombre", key="ce_nombre_page")
apellido = st.text_input("Apellido", key="ce_apellido_page")
telefono = st.text_input("Teléfono", key="ce_telefono_page")
dnis_text = st.text_input("DNIs (separados por coma)", key="ce_dnis_page", placeholder="12345678, 23456789")
dnis_list = [{"dni": d.strip()} for d in dnis_text.split(",") if d.strip()]

st.caption("✅ Los botones siempre se ven. Si no los ves, estás ejecutando otra app/otro archivo.")

if modo == "Crear nueva":
    if st.button("Crear persona", key="btn_crear_page"):
        if not nombre.strip() or not apellido.strip():
            st.error("Nombre y apellido son obligatorios")
        elif not dnis_list:
            st.error("Debe ingresar al menos un DNI")
        else:
            r = request_post(
                f"{BACKEND_URL}/persons",
                json={
                    "nombre": nombre.strip(),
                    "apellido": apellido.strip(),
                    "telefono": telefono.strip(),
                    "dnis": dnis_list,
                },
                headers=auth_headers(),
                timeout=30,
            )
            if r is None:
                st.stop()
            if r.status_code in (200, 201):
                st.success("OK (creada o actualizada por DNI)")
                st.session_state["page"] = 0
                st.rerun()
            else:
                show_http_error(r, "No se pudo crear")
else:
    person_id = st.number_input("ID de la persona", min_value=1, step=1, key="ce_id_page")
    if st.button("Actualizar persona", key="btn_update_page"):
        if not nombre.strip() or not apellido.strip():
            st.error("Nombre y apellido son obligatorios")
        elif not dnis_list:
            st.error("Debe ingresar al menos un DNI")
        else:
            r = request_put(
                f"{BACKEND_URL}/persons/{int(person_id)}",
                json={
                    "nombre": nombre.strip(),
                    "apellido": apellido.strip(),
                    "telefono": telefono.strip(),
                    "dnis": dnis_list,
                },
                headers=auth_headers(),
                timeout=30,
            )
            if r is None:
                st.stop()
            if r.status_code == 200:
                st.success("Persona actualizada")
                st.session_state["page"] = 0
                st.rerun()
            else:
                show_http_error(r, "No se pudo actualizar")
