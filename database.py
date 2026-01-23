from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
import os

# Database URL: default to SQLite, support PostgreSQL via env var
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///sentinel.db")

engine = create_engine(DATABASE_URL, echo=True)  # Set echo=False in production

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()