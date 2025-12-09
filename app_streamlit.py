# app_streamlit.py
import os
import requests
import streamlit as st

# El backend se toma de ENV, y si no existe, usa localhost para desarrollo
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="CRUD Personas + Observaciones", layout="wide")

if "token" not in st.session_state:
    st.session_state["token"] = None


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
                timeout=5,
            )

            if r.status_code == 200:
                data = r.json()
                st.session_state["token"] = data["token"]
                st.rerun()
            else:
                # Intentamos leer el mensaje de detalle del backend
                detail = None
                try:
                    data = r.json()
                    detail = data.get("detail")
                except Exception:
                    detail = None

                if r.status_code == 429 and detail:
                    # 429 = demasiados intentos: backend manda mensaje con mail
                    st.error(detail)
                elif detail:
                    st.error(detail)
                else:
                    st.error("Error en el login. Revise usuario/contraseña.")
        except Exception as e:
            st.error(f"Error al conectar con backend: {e}")


def auth_headers():
    return {"x-token": st.session_state["token"]}


# =========================
# UI PRINCIPAL
# =========================
def main_app():
    st.sidebar.title("Menú")
    opcion = st.sidebar.radio(
        "Opciones",
        ["Personas", "Salir"]
    )

    if opcion == "Salir":
        st.session_state["token"] = None
        st.rerun()

    if opcion == "Personas":
        personas_view()


def personas_view():
    st.title("CRUD de Personas con DNI, Nacionalidad y Observaciones por Mes")

    col1, col2 = st.columns(2)

    # ----- Alta / Edición -----
    with col1:
        st.subheader("Crear / Editar persona")

        modo = st.radio("Modo", ["Crear nueva", "Editar existente"])

        # Datos básicos
        nombre = st.text_input("Nombre")
        apellido = st.text_input("Apellido")

        # Nacionalidad (aunque el backend actual no la guarda, la dejamos en la UI)
        nacionalidades = [
            "Argentina", "Brasil", "Chile", "Uruguay", "Paraguay",
            "Bolivia", "Perú", "Otro"
        ]
        nacionalidad = st.selectbox("Nacionalidad", nacionalidades, index=0)

        # Varios DNIs (simple: lista separada por comas)
        dnis_text = st.text_input("DNIs (separados por coma)", placeholder="12345678, 23456789")

        if modo == "Crear nueva":
            if st.button("Crear persona"):
                dnis_list = [
                    {"dni": dni.strip()}
                    for dni in dnis_text.split(",")
                    if dni.strip()
                ]
                if not nombre or not apellido:
                    st.error("Nombre y apellido son obligatorios")
                elif not dnis_list:
                    st.error("Debe ingresar al menos un DNI")
                else:
                    r = requests.post(
                        f"{BACKEND_URL}/persons",
                        json={
                            "nombre": nombre,
                            "apellido": apellido,
                            # el backend actual ignora 'nacionalidad' si no la tiene en el modelo
                            "nacionalidad": nacionalidad,
                            "dnis": dnis_list,
                        },
                        headers=auth_headers(),
                    )
                    if r.status_code == 201:
                        st.success("Persona creada")
                    else:
                        st.error(f"Error: {r.text}")
        else:
            # Edición: elegimos persona y actualizamos datos básicos + DNIs + nacionalidad
            resp_personas = requests.get(
                f"{BACKEND_URL}/persons", headers=auth_headers()
            )
            if resp_personas.status_code != 200:
                st.error("No se pudo obtener el listado de personas")
            else:
                personas = resp_personas.json()
                ids = {
                    f"{p['id']} - {p['nombre']} {p['apellido']}": p["id"]
                    for p in personas
                }
                if ids:
                    seleccion = st.selectbox("Seleccionar persona", list(ids.keys()))
                    person_id = ids[seleccion]

                    if st.button("Actualizar persona"):
                        dnis_list = [
                            {"dni": dni.strip()}
                            for dni in dnis_text.split(",")
                            if dni.strip()
                        ]
                        if not nombre or not apellido:
                            st.error("Nombre y apellido son obligatorios")
                        elif not dnis_list:
                            st.error("Debe ingresar al menos un DNI")
                        else:
                            r = requests.put(
                                f"{BACKEND_URL}/persons/{person_id}",
                                json={
                                    "nombre": nombre,
                                    "apellido": apellido,
                                    "nacionalidad": nacionalidad,
                                    "dnis": dnis_list,
                                },
                                headers=auth_headers(),
                            )
                            if r.status_code == 200:
                                st.success("Persona actualizada")
                            else:
                                st.error(f"Error: {r.text}")
                else:
                    st.info("No hay personas para editar.")

    # ----- Listado + Observaciones -----
    with col2:
        st.subheader("Listado, Buscador y Observaciones")

        # 🔎 Buscador por nombre / apellido / DNI (el backend puede ignorar q si no lo implementaste)
        search = st.text_input("Buscar persona (nombre, apellido o DNI)")

        params = {}
        if search.strip():
            params["q"] = search.strip()

        try:
            resp = requests.get(
                f"{BACKEND_URL}/persons",
                headers=auth_headers(),
                params=params,
                timeout=5,
            )
        except Exception as e:
            st.error(f"No se pudo conectar al backend: {e}")
            return

        if resp.status_code != 200:
            st.error("No se pudo obtener el listado de personas")
            return

        data = resp.json()
        if not data:
            st.info("Sin personas cargadas (o ninguna coincide con la búsqueda).")
            return

        for p in data:
            titulo = f"{p['nombre']} {p['apellido']} (ID {p['id']})"
            if p.get("nacionalidad"):
                titulo += f" - {p['nacionalidad']}"
            with st.expander(titulo):
                st.write("**DNIs:**", ", ".join(d["dni"] for d in p["dnis"]))
                if p.get("nacionalidad"):
                    st.write("**Nacionalidad:**", p["nacionalidad"])

                # Observaciones por mes
                observaciones_por_mes = {
                    o["month"]: o["text"] for o in p["observations"]
                }
                flags_por_mes = {
                    o["month"]: o.get("flag", False) for o in p["observations"]
                }

                edited = []
                meses = {
                    1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril",
                    5: "Mayo", 6: "Junio", 7: "Julio", 8: "Agosto",
                    9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"
                }

                st.write("### Observaciones por mes")
                for m in range(1, 13):
                    c1m, c2m = st.columns([1, 3])
                    with c1m:
                        chk = st.checkbox(
                            f"{meses[m]} ✔",
                            value=flags_por_mes.get(m, False),
                            key=f"flag_{p['id']}_{m}",
                        )
                    with c2m:
                        txt = st.text_area(
                            f"Detalle {meses[m]}",
                            value=observaciones_por_mes.get(m, ""),
                            key=f"obs_{p['id']}_{m}"
                        )
                    # el backend actual solo usa month/text, flag se ignora (no rompe)
                    edited.append({"month": m, "text": txt, "flag": chk})

                c1, c2 = st.columns(2)
                with c1:
                    if st.button("Guardar observaciones", key=f"save_obs_{p['id']}"):
                        r = requests.put(
                            f"{BACKEND_URL}/persons/{p['id']}/observations",
                            json=edited,
                            headers=auth_headers(),
                        )
                        if r.status_code == 200:
                            st.success("Observaciones actualizadas")
                        else:
                            st.error(f"Error: {r.text}")
                with c2:
                    if st.button("Eliminar persona", key=f"del_{p['id']}"):
                        r = requests.delete(
                            f"{BACKEND_URL}/persons/{p['id']}",
                            headers=auth_headers(),
                        )
                        if r.status_code == 204:
                            st.warning("Persona eliminada")
                            st.rerun()
                        else:
                            st.error(f"Error: {r.text}")



# =========================
# ENTRYPOINT
# =========================
if st.session_state["token"] is None:
    do_login()
else:
    main_app()
