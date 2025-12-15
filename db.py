##BBDD_TURKIA/db.py
# BBDD_TURKIA/db.py
import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

def clean_database_url(url: str) -> str:
    if not url:
        return url

    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))

    # Render: a veces agrega esto
    q.pop("pgbouncer", None)

    return urlunparse(parts._replace(query=urlencode(q)))

DATABASE_URL = clean_database_url(os.getenv("DATABASE_URL", "sqlite:///./personas.db"))

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
