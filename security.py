from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import os

SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-this-secret")
ALGORITHM = "HS256"
EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_token(user_id: int):
    exp = datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def token_user_id(token: str):
    try:
        return int(jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"])
    except (JWTError, ValueError, KeyError):
        return None
