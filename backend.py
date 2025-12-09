# backend.py
import os
import time
import hashlib
from typing import List

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Header,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# =========================
# CONFIG DB
# =========================
DATABASE_URL = "sqlite:///./personas.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# =========================
# MODELOS SQLALCHEMY
# =========================
class Person(Base):
    __tablename__ = "persons"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100), nullable=False)
    apellido = Column(String(100), nullable=False)

    dnis = relationship("DNI", back_populates="person", cascade="all, delete-orphan")
    observations = relationship(
        "Observation", back_populates="person", cascade="all, delete-orphan"
    )


class DNI(Base):
    __tablename__ = "dnis"
    id = Column(Integer, primary_key=True, index=True)
    dni = Column(String(20), nullable=False)
    person_id = Column(Integer, ForeignKey("persons.id"), nullable=False)

    person = relationship("Person", back_populates="dnis")


class Observation(Base):
    __tablename__ = "observations"
    id = Column(Integer, primary_key=True, index=True)
    month = Column(Integer, nullable=False)   # 1..12
    text = Column(Text, nullable=False)
    person_id = Column(Integer, ForeignKey("persons.id"), nullable=False)

    person = relationship("Person", back_populates="observations")

    __table_args__ = (
        UniqueConstraint("person_id", "month", name="uix_person_month"),
    )


Base.metadata.create_all(bind=engine)

# =========================
# ESQUEMAS Pydantic
# =========================
class DNIIn(BaseModel):
    dni: str

    class Config:
        orm_mode = True


class ObservationIn(BaseModel):
    month: int
    text: str

    class Config:
        orm_mode = True


class PersonBase(BaseModel):
    nombre: str
    apellido: str


class PersonCreate(PersonBase):
    dnis: List[DNIIn]


class PersonUpdate(PersonBase):
    dnis: List[DNIIn]


class PersonOut(PersonBase):
    id: int
    dnis: List[DNIIn]
    observations: List[ObservationIn]

    class Config:
        orm_mode = True


class LoginIn(BaseModel):
    username: str
    password: str


class LoginOut(BaseModel):
    token: str


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str


# =========================
# CONFIG SEGURIDAD / LOGIN
# =========================

# TODO: todos los secretos vienen del entorno
ADMIN_USER = os.getenv("ADMIN_USER")              # obligatorio
ADMIN_PASS_HASH = os.getenv("ADMIN_PASS_HASH")    # obligatorio (SHA256 de la pass)
API_TOKEN = os.getenv("API_TOKEN")                # obligatorio (token que usa el front)
RESET_MASTER_TOKEN = os.getenv("RESET_MASTER_TOKEN")  # obligatorio
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")  # opcional

# Validación: si falta algo crítico, no levantamos la API
missing = []
if not ADMIN_USER:
    missing.append("ADMIN_USER")
if not ADMIN_PASS_HASH:
    missing.append("ADMIN_PASS_HASH")
if not API_TOKEN:
    missing.append("API_TOKEN")
if not RESET_MASTER_TOKEN:
    missing.append("RESET_MASTER_TOKEN")

if missing:
    raise RuntimeError(
        f"Faltan variables de entorno críticas para seguridad: {', '.join(missing)}"
    )

# Config anti fuerza bruta
MAX_FAILED_ATTEMPTS = 5            # intentos máximos antes de bloquear
LOCK_TIME_SECONDS = 15 * 60        # tiempo de bloqueo en segundos (15 min)

# Memoria en RAM de intentos fallidos: clave -> {count, lock_until}
FAILED_LOGINS: dict[str, dict] = {}


def hash_password(raw: str) -> str:
    """Hashea una contraseña en SHA256."""
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_admin_password(raw: str) -> bool:
    """Compara contra el hash configurado por env."""
    return hash_password(raw) == ADMIN_PASS_HASH


# =========================
# FASTAPI APP
# =========================
app = FastAPI(title="Backend Personas + Observaciones")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # para pruebas
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# DEPENDENCIAS
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_token(x_token: str = Header(default="")):
    if x_token != API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
        )


# =========================
# ENDPOINTS LOGIN
# =========================
@app.post("/login", response_model=LoginOut)
def login(data: LoginIn, request: Request):
    """
    Login con protección anti fuerza bruta.
    Limita intentos por IP + usuario y bloquea temporalmente.
    """
    client_ip = request.client.host
    key = f"{client_ip}:{data.username}"
    now = time.time()

    info = FAILED_LOGINS.get(key)
    if info and info.get("lock_until", 0) > now:
        minutos = int((info["lock_until"] - now) // 60) + 1
        raise HTTPException(
            status_code=429,
            detail=(
                "Cuenta bloqueada temporalmente por demasiados intentos fallidos. "
                f"Esperá {minutos} minuto(s) o contactá al administrador: {ADMIN_EMAIL}"
            ),
        )

    # Verificar credenciales
    if data.username == ADMIN_USER and verify_admin_password(data.password):
        # Login OK → limpiar contador
        FAILED_LOGINS.pop(key, None)
        return LoginOut(token=API_TOKEN)

    # Credenciales incorrectas → acumular fallo
    if not info:
        info = {"count": 0, "lock_until": 0}
    info["count"] += 1

    if info["count"] >= MAX_FAILED_ATTEMPTS:
        info["lock_until"] = now + LOCK_TIME_SECONDS

    FAILED_LOGINS[key] = info

    raise HTTPException(status_code=401, detail="Credenciales inválidas")


@app.post("/admin/generar-hash-password")
def generar_hash_password(body: ResetPasswordRequest):
    """
    Genera el hash SHA256 de una nueva contraseña SOLO si se envía
    el RESET_MASTER_TOKEN correcto.

    Flujo:
      1) Enviás reset_token = RESET_MASTER_TOKEN y new_password = "TuPassNueva"
      2) El endpoint devuelve new_password_hash
      3) Ese hash lo ponés en ADMIN_PASS_HASH (env) y redeployás.
    """
    if body.reset_token != RESET_MASTER_TOKEN:
        raise HTTPException(status_code=403, detail="Reset token inválido")

    new_hash = hash_password(body.new_password)
    return {
        "detail": "Hash generado. Copialo en ADMIN_PASS_HASH y redeployá.",
        "new_password_hash": new_hash,
    }


# =========================
# CRUD PERSONAS
# =========================
@app.get(
    "/persons",
    response_model=List[PersonOut],
    dependencies=[Depends(require_token)],
)
def list_persons(db: Session = Depends(get_db)):
    persons = db.query(Person).all()
    return persons


@app.post(
    "/persons",
    response_model=PersonOut,
    status_code=201,
    dependencies=[Depends(require_token)],
)
def create_person(payload: PersonCreate, db: Session = Depends(get_db)):
    p = Person(nombre=payload.nombre, apellido=payload.apellido)

    for dni_in in payload.dnis:
        p.dnis.append(DNI(dni=dni_in.dni))

    # al crear persona, inicializamos 12 observaciones vacías
    for m in range(1, 13):
        p.observations.append(Observation(month=m, text=""))

    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@app.get(
    "/persons/{person_id}",
    response_model=PersonOut,
    dependencies=[Depends(require_token)],
)
def get_person(person_id: int, db: Session = Depends(get_db)):
    p = db.query(Person).filter(Person.id == person_id).first()
    if not p:
        raise HTTPException(404, "Persona no encontrada")
    return p


@app.put(
    "/persons/{person_id}",
    response_model=PersonOut,
    dependencies=[Depends(require_token)],
)
def update_person(person_id: int, payload: PersonUpdate, db: Session = Depends(get_db)):
    p = db.query(Person).filter(Person.id == person_id).first()
    if not p:
        raise HTTPException(404, "Persona no encontrada")

    p.nombre = payload.nombre
    p.apellido = payload.apellido

    # reemplazar DNIs
    p.dnis.clear()
    for dni_in in payload.dnis:
        p.dnis.append(DNI(dni=dni_in.dni))

    db.commit()
    db.refresh(p)
    return p


@app.delete(
    "/persons/{person_id}",
    status_code=204,
    dependencies=[Depends(require_token)],
)
def delete_person(person_id: int, db: Session = Depends(get_db)):
    p = db.query(Person).filter(Person.id == person_id).first()
    if not p:
        raise HTTPException(404, "Persona no encontrada")
    db.delete(p)
    db.commit()
    return


# =========================
# OBSERVACIONES POR MES
# =========================
@app.put(
    "/persons/{person_id}/observations",
    response_model=PersonOut,
    dependencies=[Depends(require_token)],
)
def update_observations(
    person_id: int, payload: List[ObservationIn], db: Session = Depends(get_db)
):
    p = db.query(Person).filter(Person.id == person_id).first()
    if not p:
        raise HTTPException(404, "Persona no encontrada")

    # Validar meses
    for obs in payload:
        if obs.month < 1 or obs.month > 12:
            raise HTTPException(400, f"Mes inválido: {obs.month}")

    existing_by_month = {o.month: o for o in p.observations}
    for obs_in in payload:
        if obs_in.month in existing_by_month:
            existing_by_month[obs_in.month].text = obs_in.text
        else:
            p.observations.append(
                Observation(month=obs_in.month, text=obs_in.text)
            )

    db.commit()
    db.refresh(p)
    return p
