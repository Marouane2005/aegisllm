import hashlib
import secrets
from cryptography.fernet import Fernet
from passlib.context import CryptContext
from app.core.config import get_settings

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def generate_api_key() -> tuple:
    raw = f"aegis_live_{secrets.token_urlsafe(48)}"
    prefix = raw[:16] + "..."
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, prefix, key_hash


def hash_incoming_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def encrypt_secret(plaintext: str) -> str:
    settings = get_settings()
    f = Fernet(settings.FERNET_MASTER_KEY.get_secret_value().encode())
    return f.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    settings = get_settings()
    f = Fernet(settings.FERNET_MASTER_KEY.get_secret_value().encode())
    return f.decrypt(ciphertext.encode()).decode()
