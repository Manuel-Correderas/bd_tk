import os
import io
import time
import hashlib
from typing import List, Optional, Dict

import pandas as pd
from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Header,
    Request,
    File,
    UploadFile,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    ForeignKey,
    Text,
    UniqueConstraint,
    or_,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session, selectinload
from sqlalchemy.exc import IntegrityError

# =========================
# ENV
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(BASE_DIR, ".env")
load_dotenv(env_path)

# =========================
# CONFIG DB
# =========================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./personas.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
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
    telefono = Column(String(30), nullable=True)

    dnis = relationship("DNI", back_populates="person", cascade="all, delete-orphan")
    observations = relationship("Observation", back_populates="person", cascade="all, delete-orphan")


class DNI(Base):
    __tablename__ = "dnis"
    id = Column(Integer, primary_key=True, index=True)
    dni = Column(String(20), nullable=False, unique=True)  # clave única global
    person_id = Column(Integer, ForeignKey("persons.id"), nullable=False)

    person = relationship("Person", back_populates="dnis")


class Observation(Base):
    __tablename__ = "observations"
    id = Column(Integer, primary_key=True, index=True)
    month = Column(Integer, nullable=False)  # 1..12
    text = Column(Text, nullable=False, default="")
    person_id = Column(Integer, ForeignKey("persons.id"), nullable=False)

    person = relationship("Person", back_populates="observations")
    __table_args__ = (UniqueConstraint("person_id", "month", name="uix_person_month"),)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


# =========================
# Pydantic compat (v1/v2)
# =========================
def _pydantic_compat_config():
    # Pydantic v2: model_config
    # Pydantic v1: class Config
    class _Cfg:
        orm_mode = True  # v1
    return _Cfg

class ORMBase(BaseModel):
    # v2
    model_config = {"from_attributes": True}
    # v1
    class Config(_pydantic_compat_config()):
        pass

class DNIIn(ORMBase):
    dni: str

class ObservationIn(ORMBase):
    month: int
    text: str = ""

class PersonBase(ORMBase):
    nombre: str
    apellido: str
    telefono: Optional[str] = ""

class PersonCreate(PersonBase):
    dnis: List[DNIIn] = Field(default_factory=list)

class PersonUpdate(PersonBase):
    dnis: List[DNIIn] = Field(default_factory=list)

class PersonOut(PersonBase):
    id: int
    dnis: List[DNIIn] = Field(default_factory=list)
    observations: List[ObservationIn] = Field(default_factory=list)

class LoginIn(BaseModel):
    username: str
    password: str

class LoginOut(BaseModel):
    token: str

class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str

# =========================
# SEGURIDAD / LOGIN
# =========================
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS_HASH = os.getenv("ADMIN_PASS_HASH")  # SHA256
API_TOKEN = os.getenv("API_TOKEN")
RESET_MASTER_TOKEN = os.getenv("RESET_MASTER_TOKEN")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")  # opcional

missing = []
if not ADMIN_USER: missing.append("ADMIN_USER")
if not ADMIN_PASS_HASH: missing.append("ADMIN_PASS_HASH")
if not API_TOKEN: missing.append("API_TOKEN")
if not RESET_MASTER_TOKEN: missing.append("RESET_MASTER_TOKEN")
if missing:
    raise RuntimeError(f"Faltan variables de entorno críticas para seguridad: {', '.join(missing)}")

MAX_FAILED_ATTEMPTS = 5
LOCK_TIME_SECONDS = 15 * 60
FAILED_LOGINS: Dict[str, Dict] = {}

def hash_password(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

def verify_admin_password(raw: str) -> bool:
    return hash_password(raw) == ADMIN_PASS_HASH

# =========================
# APP
# =========================
app = FastAPI(title="Backend Personas + Observaciones")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

# =========================
# HELPERS
# =========================
MESES = {
    1: ["enero", "ene", "january", "jan"],
    2: ["febrero", "feb", "february"],
    3: ["marzo", "mar", "march"],
    4: ["abril", "abr", "april"],
    5: ["mayo", "may"],
    6: ["junio", "jun", "june"],
    7: ["julio", "jul", "july"],
    8: ["agosto", "ago", "aug", "august"],
    9: ["septiembre", "sep", "set", "september"],
    10: ["octubre", "oct", "october"],
    11: ["noviembre", "nov", "november"],
    12: ["diciembre", "dic", "dec", "december"],
}

def normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df

def get_col(df: pd.DataFrame, *names: str) -> Optional[str]:
    for n in names:
        if n in df.columns:
            return n
    return None

def find_month_cols(df: pd.DataFrame) -> Dict[int, str]:
    month_cols = {}
    for month_num, candidates in MESES.items():
        for cand in candidates:
            if cand in df.columns:
                month_cols[month_num] = cand
                break
    return month_cols

def ensure_12_observations(p: Person):
    existing = {o.month for o in p.observations}
    for m in range(1, 13):
        if m not in existing:
            p.observations.append(Observation(month=m, text=""))

# =========================
# LOGIN
# =========================
@app.post("/login", response_model=LoginOut)
def login(data: LoginIn, request: Request):
    client_ip = request.client.host if request.client else "unknown"
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

    if data.username == ADMIN_USER and verify_admin_password(data.password):
        FAILED_LOGINS.pop(key, None)
        return LoginOut(token=API_TOKEN)

    if not info:
        info = {"count": 0, "lock_until": 0}
    info["count"] += 1
    if info["count"] >= MAX_FAILED_ATTEMPTS:
        info["lock_until"] = now + LOCK_TIME_SECONDS
    FAILED_LOGINS[key] = info

    raise HTTPException(status_code=401, detail="Credenciales inválidas")

@app.post("/admin/generar-hash-password")
def generar_hash_password(body: ResetPasswordRequest):
    if body.reset_token != RESET_MASTER_TOKEN:
        raise HTTPException(status_code=403, detail="Reset token inválido")

    new_hash = hash_password(body.new_password)
    return {
        "detail": "Hash generado. Copialo en ADMIN_PASS_HASH y redeployá.",
        "new_password_hash": new_hash,
    }

# =========================
# CRUD / SEARCH
# =========================
@app.get("/persons/search", response_model=List[PersonOut], dependencies=[Depends(require_token)])
def search_persons(q: str, limit: int = 50, db: Session = Depends(get_db)):
    q = q.strip()
    if not q:
        return []

    persons = (
        db.query(Person)
        .options(selectinload(Person.dnis), selectinload(Person.observations))
        .outerjoin(DNI)
        .filter(
            or_(
                Person.nombre.ilike(f"%{q}%"),
                Person.apellido.ilike(f"%{q}%"),
                DNI.dni.ilike(f"%{q}%"),
            )
        )
        .limit(limit)
        .all()
    )

    for p in persons:
        ensure_12_observations(p)
    db.commit()
    for p in persons:
        db.refresh(p)

    # ✅ devolvemos ORM, FastAPI lo serializa con PersonOut (orm_mode/from_attributes)
    return persons

@app.get("/persons/by-dni", response_model=PersonOut, dependencies=[Depends(require_token)])
def get_by_dni(dni: str = Query(...), db: Session = Depends(get_db)):
    dni = dni.strip()
    d = (
        db.query(DNI)
        .options(
            selectinload(DNI.person).selectinload(Person.dnis),
            selectinload(DNI.person).selectinload(Person.observations),
        )
        .filter(DNI.dni == dni)
        .first()
    )
    if not d:
        raise HTTPException(404, "Persona no encontrada")

    ensure_12_observations(d.person)
    db.commit()
    db.refresh(d.person)
    return d.person

@app.get("/persons", response_model=List[PersonOut], dependencies=[Depends(require_token)])
def list_persons(skip: int = 0, limit: int = 200, db: Session = Depends(get_db)):
    persons = (
        db.query(Person)
        .options(selectinload(Person.dnis), selectinload(Person.observations))
        .offset(skip)
        .limit(limit)
        .all()
    )

    for p in persons:
        ensure_12_observations(p)
    db.commit()
    for p in persons:
        db.refresh(p)

    return persons

@app.post("/persons", response_model=PersonOut, status_code=201, dependencies=[Depends(require_token)])
def create_person(payload: PersonCreate, db: Session = Depends(get_db)):
    if not payload.dnis:
        raise HTTPException(status_code=400, detail="Se requiere al menos un DNI")

    dni_principal = payload.dnis[0].dni.strip()
    if not dni_principal:
        raise HTTPException(status_code=400, detail="DNI principal vacío")

    existing_dni = db.query(DNI).filter(DNI.dni == dni_principal).first()

    if existing_dni:
        p = existing_dni.person

        p.nombre = payload.nombre.strip()
        p.apellido = payload.apellido.strip()
        p.telefono = (payload.telefono or "").strip()

        for dni_in in payload.dnis[1:]:
            dni_norm = dni_in.dni.strip()
            if not dni_norm:
                continue
            if not any(d.dni == dni_norm for d in p.dnis):
                try:
                    p.dnis.append(DNI(dni=dni_norm))
                    db.flush()
                except IntegrityError:
                    db.rollback()  # DNI ya existe en otra persona => lo ignoramos

        ensure_12_observations(p)
        db.commit()
        db.refresh(p)
        return p

    p = Person(
        nombre=payload.nombre.strip(),
        apellido=payload.apellido.strip(),
        telefono=(payload.telefono or "").strip(),
    )

    for dni_in in payload.dnis:
        dni_norm = dni_in.dni.strip()
        if dni_norm:
            p.dnis.append(DNI(dni=dni_norm))

    ensure_12_observations(p)

    db.add(p)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="DNI duplicado: ya existe en la base")
    db.refresh(p)
    return p

@app.get("/persons/{person_id}", response_model=PersonOut, dependencies=[Depends(require_token)])
def get_person(person_id: int, db: Session = Depends(get_db)):
    p = (
        db.query(Person)
        .options(selectinload(Person.dnis), selectinload(Person.observations))
        .filter(Person.id == person_id)
        .first()
    )
    if not p:
        raise HTTPException(404, "Persona no encontrada")

    ensure_12_observations(p)
    db.commit()
    db.refresh(p)
    return p

@app.put("/persons/{person_id}", response_model=PersonOut, dependencies=[Depends(require_token)])
def update_person(person_id: int, payload: PersonUpdate, db: Session = Depends(get_db)):
    p = (
        db.query(Person)
        .options(selectinload(Person.dnis), selectinload(Person.observations))
        .filter(Person.id == person_id)
        .first()
    )
    if not p:
        raise HTTPException(404, "Persona no encontrada")

    p.nombre = payload.nombre.strip()
    p.apellido = payload.apellido.strip()
    p.telefono = (payload.telefono or "").strip()

    # Reemplazar DNIs (cuidado con duplicados globales)
    p.dnis.clear()
    for dni_in in payload.dnis:
        dni_norm = dni_in.dni.strip()
        if dni_norm:
            p.dnis.append(DNI(dni=dni_norm))

    ensure_12_observations(p)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="DNI duplicado: ya existe en la base")
    db.refresh(p)
    return p

@app.delete("/persons/{person_id}", status_code=204, dependencies=[Depends(require_token)])
def delete_person(person_id: int, db: Session = Depends(get_db)):
    p = db.query(Person).filter(Person.id == person_id).first()
    if not p:
        raise HTTPException(404, "Persona no encontrada")
    db.delete(p)
    db.commit()
    return

# =========================
# OBSERVACIONES
# =========================
@app.put("/persons/{person_id}/observations", response_model=PersonOut, dependencies=[Depends(require_token)])
def update_observations(person_id: int, payload: List[ObservationIn], db: Session = Depends(get_db)):
    p = (
        db.query(Person)
        .options(selectinload(Person.dnis), selectinload(Person.observations))
        .filter(Person.id == person_id)
        .first()
    )
    if not p:
        raise HTTPException(404, "Persona no encontrada")

    for obs in payload:
        if obs.month < 1 or obs.month > 12:
            raise HTTPException(400, f"Mes inválido: {obs.month}")

    ensure_12_observations(p)
    existing_by_month = {o.month: o for o in p.observations}

    for obs_in in payload:
        existing_by_month[obs_in.month].text = (obs_in.text or "")

    db.commit()
    db.refresh(p)
    return p

# =========================
# IMPORT CSV/EXCEL
# =========================
@app.post("/import-personas", dependencies=[Depends(require_token)])
async def import_personas(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = (file.filename or "").lower()
    raw = await file.read()

    if filename.endswith(".csv"):
        df = pd.read_csv(io.BytesIO(raw), sep=None, engine="python")
    elif filename.endswith(".xls") or filename.endswith(".xlsx"):
        df = pd.read_excel(io.BytesIO(raw))
    else:
        raise HTTPException(status_code=400, detail="El archivo debe ser CSV o Excel (.csv, .xls, .xlsx)")

    df = normalize_cols(df)

    col_nombre = get_col(df, "nombre", "name")
    col_apellido = get_col(df, "apellido", "apellidos", "last_name", "apellido/s")
    col_tel = get_col(df, "telefono", "tel", "teléfono", "phone", "celular")
    col_dni = get_col(df, "dni", "documento", "documento_nro", "doc")

    if not col_nombre or not col_apellido or not col_dni:
        raise HTTPException(status_code=400, detail="Faltan columnas requeridas: nombre, apellido, dni")

    month_cols = find_month_cols(df)

    creadas = 0
    actualizadas = 0
    saltadas = 0

    existing = {d.dni: d for d in db.query(DNI).all()}

    for _, row in df.iterrows():
        nombre = str(row.get(col_nombre) or "").strip()
        apellido = str(row.get(col_apellido) or "").strip()
        telefono = str(row.get(col_tel) or "").strip() if col_tel else ""
        dni = str(row.get(col_dni) or "").strip()

        if not nombre or not apellido or not dni:
            saltadas += 1
            continue

        d_exist = existing.get(dni)

        if d_exist:
            p = d_exist.person
            actualizadas += 1

            if (not p.nombre or not p.nombre.strip()) and nombre:
                p.nombre = nombre
            if (not p.apellido or not p.apellido.strip()) and apellido:
                p.apellido = apellido
            if (not p.telefono or not p.telefono.strip()) and telefono:
                p.telefono = telefono

        else:
            p = Person(nombre=nombre, apellido=apellido, telefono=telefono)
            p.dnis.append(DNI(dni=dni))
            ensure_12_observations(p)
            db.add(p)
            creadas += 1

            db.flush()
            d_new = next((d for d in p.dnis if d.dni == dni), None)
            if d_new:
                existing[dni] = d_new

        ensure_12_observations(p)
        by_month = {o.month: o for o in p.observations}

        for month_num, col_name in month_cols.items():
            value = row.get(col_name)
            if pd.isna(value) or str(value).strip() == "":
                continue
            text = str(value).strip()

            obs = by_month.get(month_num)
            if obs and (not obs.text or not obs.text.strip()):
                obs.text = text

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Error de integridad: DNI duplicado durante la importación")

    return {
        "detail": (
            "Importación completa. "
            f"Nuevas: {creadas}. "
            f"Existentes actualizadas: {actualizadas}. "
            f"Filas saltadas: {saltadas}."
        )
    }
