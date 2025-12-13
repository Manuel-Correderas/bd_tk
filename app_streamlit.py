# app_streamlit.py
import os
import pandas as pd
import requests
import streamlit as st

# =========================
# CONFIG
# =========================
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")

st.set_page_config(page_title="CRUD Personas + Observaciones", layout="wide")

if "token" not in st.session_state:
    st.session_state["token"] = None

if "page" not in st.session_state:
    st.session_state["page"] = 0

PAGE_SIZE = 50  # paginado tabla


# =========================
# HELPERS HTTP
# =========================
def auth_headers():
    return {"x-token": st.session_state["token"]} if st.session_state["token"] else {}


def safe_json(resp: requests.Response):
    try:
        return resp.json()
    except Exception:
        return None


def show_http_error(resp: requests.Response, default_msg="Error"):
    data = safe_json(resp) or {}
    detail = data.get("detail") if isinstance(data, dict) else None
    st.error(detail or f"{default_msg}: {resp.status_code} - {resp.text}")


# =========================
# LOGIN
# =========================
def do_login():
    st.title("Login")

    username = st.text_input("Usuario")
    password = st.text_input("Contraseña", type="password")

    if st.button("Ingresar"):
        if not username or not password:
            st.error("Ingrese usuario y contraseña.")
            return

        try:
            r = requests.post(
                f"{BACKEND_URL}/login",
                json={"username": username, "password": password},
                timeout=10,
            )
        except Exception as e:
            st.error(f"Error al conectar con backend: {e}")
            return

        if r.status_code == 200:
            data = safe_json(r) or {}
            st.session_state["token"] = data.get("token")
            st.rerun()
        else:
            show_http_error(r, "Login fallido")


# =========================
# UI PRINCIPAL
# =========================
def main_app():
    st.sidebar.title("Menú")
    opcion = st.sidebar.radio("Opciones", ["Personas", "Salir"])

    if opcion == "Salir":
        st.session_state["token"] = None
        st.rerun()

    if opcion == "Personas":
        personas_view()


def personas_view():
    st.title("CRUD de Personas con DNI y Observaciones por Mes")

    tab1, tab2, tab3 = st.tabs(["📋 Listado", "👤 Crear/Editar", "📥 Importar"])

    # =========================
    # TAB 1: LISTADO + BUSCADOR + OBS
    # =========================
    with tab1:
        st.subheader("Listado (paginado) y buscador")

        q = st.text_input("Buscar por nombre, apellido o DNI", placeholder="Ej: Juan, Pérez, 30111222")

        # Si hay búsqueda: usar endpoint search (rápido, sin traer todo)
        if q.strip():
            try:
                resp = requests.get(
                    f"{BACKEND_URL}/persons/search",
                    headers=auth_headers(),
                    params={"q": q.strip(), "limit": 50},
                    timeout=20,
                )
            except Exception as e:
                st.error(f"No se pudo conectar al backend: {e}")
                return

            if resp.status_code != 200:
                show_http_error(resp, "No se pudo buscar")
                return

            persons = resp.json() or []
            st.caption(f"Resultados: {len(persons)} (máx 50)")
        else:
            # Paginado normal
            skip = st.session_state["page"] * PAGE_SIZE
            try:
                resp = requests.get(
                    f"{BACKEND_URL}/persons",
                    headers=auth_headers(),
                    params={"skip": skip, "limit": PAGE_SIZE},
                    timeout=20,
                )
            except Exception as e:
                st.error(f"No se pudo conectar al backend: {e}")
                return

            if resp.status_code != 200:
                show_http_error(resp, "No se pudo obtener listado")
                return

            persons = resp.json() or []

            # Controles paginado
            col_prev, col_mid, col_next = st.columns([1, 2, 1])
            with col_prev:
                if st.button("⬅ Anterior", disabled=(st.session_state["page"] == 0)):
                    st.session_state["page"] -= 1
                    st.rerun()
            with col_mid:
                st.caption(f"Página {st.session_state['page'] + 1} — mostrando {len(persons)} registros")
            with col_next:
                if st.button("Siguiente ➡", disabled=(len(persons) < PAGE_SIZE)):
                    st.session_state["page"] += 1
                    st.rerun()

        if not persons:
            st.info("No hay resultados.")
            return

        # Tabla resumen (liviana)
        rows = []
        for p in persons:
            rows.append({
                "ID": p["id"],
                "Nombre": p["nombre"],
                "Apellido": p["apellido"],
                "Teléfono": p.get("telefono", "") or "",
                "DNIs": ", ".join(d["dni"] for d in p.get("dnis", [])),
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Observaciones (abrí una persona)")

        meses = {
            1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril",
            5: "Mayo", 6: "Junio", 7: "Julio", 8: "Agosto",
            9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"
        }

        # Expanders (solo para lo que ya trajimos: página actual o resultados búsqueda)
        for p in persons:
            titulo = f"{p['nombre']} {p['apellido']} (ID {p['id']})"
            with st.expander(titulo):
                st.write("**DNIs:**", ", ".join(d["dni"] for d in p.get("dnis", [])))
                st.write("**Teléfono:**", p.get("telefono", "") or "")

                obs = p.get("observations", []) or []
                obs_by_month = {o["month"]: o.get("text", "") for o in obs}

                edited = []
                for m in range(1, 13):
                    existing_text = (obs_by_month.get(m) or "").strip()
                    default_checked = bool(existing_text)

                    c1m, c2m = st.columns([1, 3])
                    with c1m:
                        chk = st.checkbox(
                            f"{meses[m]} ✔",
                            value=default_checked,
                            key=f"flag_{p['id']}_{m}",
                        )
                    with c2m:
                        txt = st.text_area(
                            f"Detalle {meses[m]}",
                            value=existing_text,
                            key=f"obs_{p['id']}_{m}",
                        )

                    # regla: destildado y sin texto -> vacío
                    final_text = "" if (not chk and not txt.strip()) else txt
                    edited.append({"month": m, "text": final_text})

                if st.button("Guardar observaciones", key=f"save_obs_{p['id']}"):
                    try:
                        r = requests.put(
                            f"{BACKEND_URL}/persons/{p['id']}/observations",
                            json=edited,
                            headers=auth_headers(),
                            timeout=20,
                        )
                    except Exception as e:
                        st.error(f"Error al conectar con backend: {e}")
                        continue

                    if r.status_code == 200:
                        st.success("Observaciones actualizadas")
                        st.rerun()
                    else:
                        show_http_error(r, "No se pudo guardar observaciones")

    # =========================
    # TAB 2: CREAR / EDITAR
    # =========================
    with tab2:
        st.subheader("Crear o editar persona (sin cargar todo)")

        modo = st.radio("Modo", ["Crear nueva", "Editar por ID"], horizontal=True)

        nombre = st.text_input("Nombre", key="ce_nombre")
        apellido = st.text_input("Apellido", key="ce_apellido")
        telefono = st.text_input("Teléfono", key="ce_telefono")
        dnis_text = st.text_input("DNIs (separados por coma)", key="ce_dnis", placeholder="12345678, 23456789")

        dnis_list = [{"dni": dni.strip()} for dni in dnis_text.split(",") if dni.strip()]

        if modo == "Crear nueva":
            if st.button("Crear persona"):
                if not nombre.strip() or not apellido.strip():
                    st.error("Nombre y apellido son obligatorios")
                elif not dnis_list:
                    st.error("Debe ingresar al menos un DNI")
                else:
                    try:
                        r = requests.post(
                            f"{BACKEND_URL}/persons",
                            json={
                                "nombre": nombre.strip(),
                                "apellido": apellido.strip(),
                                "telefono": telefono.strip(),
                                "dnis": dnis_list,
                            },
                            headers=auth_headers(),
                            timeout=20,
                        )
                    except Exception as e:
                        st.error(f"Error al conectar con backend: {e}")
                        return

                    if r.status_code in (200, 201):
                        st.success("OK (creada o actualizada por DNI)")
                        st.rerun()
                    else:
                        show_http_error(r, "No se pudo crear")

        else:
            person_id = st.number_input("ID de la persona", min_value=1, step=1)
            if st.button("Actualizar persona"):
                if not nombre.strip() or not apellido.strip():
                    st.error("Nombre y apellido son obligatorios")
                elif not dnis_list:
                    st.error("Debe ingresar al menos un DNI")
                else:
                    try:
                        r = requests.put(
                            f"{BACKEND_URL}/persons/{int(person_id)}",
                            json={
                                "nombre": nombre.strip(),
                                "apellido": apellido.strip(),
                                "telefono": telefono.strip(),
                                "dnis": dnis_list,
                            },
                            headers=auth_headers(),
                            timeout=20,
                        )
                    except Exception as e:
                        st.error(f"Error al conectar con backend: {e}")
                        return

                    if r.status_code == 200:
                        st.success("Persona actualizada")
                        st.rerun()
                    else:
                        show_http_error(r, "No se pudo actualizar")

    # =========================
    # TAB 3: IMPORTAR (archivo completo al backend)
    # =========================
    with tab3:
        st.subheader("Importar personas (CSV o Excel) — rápido y sin cuelgues")

        st.info(
            "Subí el archivo y el backend se encarga de: crear nuevas por DNI y "
            "actualizar existentes completando datos/meses sin duplicar."
        )

        up = st.file_uploader("Cargar archivo", type=["csv", "xls", "xlsx"])

        if up is not None:
            if st.button("Importar archivo"):
                try:
                    files = {"file": (up.name, up.getvalue(), up.type)}
                    r = requests.post(
                        f"{BACKEND_URL}/import-personas",
                        headers=auth_headers(),
                        files=files,
                        timeout=120,  # import puede tardar
                    )
                except Exception as e:
                    st.error(f"Error al conectar con backend: {e}")
                    return

                if r.status_code == 200:
                    data = safe_json(r) or {}
                    st.success(data.get("detail", "Importación OK"))
                else:
                    show_http_error(r, "Importación fallida")


# =========================
# ENTRYPOINT
# =========================
if st.session_state["token"] is None:
    do_login()
else:
    main_app()
