import hmac
import os
import uuid
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from sqlalchemy import String, create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .common import identity, instrument

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True, pool_size=3, max_overflow=2)
Session = sessionmaker(engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("constant-time-nonexistent-account")
INTERNAL_KEY = os.environ["INTERNAL_AUTH_KEY"]
if len(INTERNAL_KEY) < 32:
    raise RuntimeError("INTERNAL_AUTH_KEY must contain at least 32 characters")

class Base(DeclarativeBase):
    pass

class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password: Mapped[str] = mapped_column(String(512))

@asynccontextmanager
async def lifespan(app):
    # First-release schema only; subsequent schema changes require migrations.
    with engine.begin() as connection:
        # Serialize the first schema creation across replicas on PostgreSQL.
        if connection.dialect.name == "postgresql":
            connection.execute(text("SELECT pg_advisory_xact_lock(20261109)"))
        Base.metadata.create_all(connection)
    yield
    engine.dispose()

app = FastAPI(title="Store Account", lifespan=lifespan)
instrument(app)

class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)

class Registration(Credentials):
    name: str = Field(min_length=1, max_length=120)

def normalized_email(value):
    value = value.strip().lower()
    if value.count("@") != 1 or any(c.isspace() for c in value):
        raise HTTPException(422, "Invalid email")
    return value

def public(account):
    return {"id": account.id, "name": account.name, "email": account.email}

@app.get("/ready")
def ready():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ready"}

@app.post("/accounts", status_code=201)
def register(body: Registration):
    account = Account(id=str(uuid.uuid4()), name=body.name, email=normalized_email(body.email),
                      password=password_hash.hash(body.password))
    with Session() as session:
        session.add(account)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise HTTPException(409, "Email already registered")
        return public(account)

@app.get("/accounts/me")
def me(account_id: str = Depends(identity)):
    with Session() as session:
        account = session.get(Account, account_id)
        if account is None:
            raise HTTPException(404, "Account not found")
        return public(account)

@app.post("/internal/credentials/verify")
def verify(body: Credentials, request: Request):
    if not hmac.compare_digest(request.headers.get("x-internal-auth-key", ""), INTERNAL_KEY):
        raise HTTPException(403, "Internal access only")
    with Session() as session:
        account = session.query(Account).filter_by(email=normalized_email(body.email)).one_or_none()
        valid = password_hash.verify(body.password, account.password if account else DUMMY_HASH)
        if not account or not valid:
            raise HTTPException(401, "Invalid credentials")
        return {"id": account.id}
