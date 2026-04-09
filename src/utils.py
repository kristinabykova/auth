from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import bcrypt

from config import settings
import uuid

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


def generate_jti() -> str:
    return str(uuid.uuid4())


def encode_jwt(
    payload: dict,
    key: str = settings.SECRET_KEY,
    algorithm: str = settings.ALGORITHM,
    expire_minutes: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    expire_delta: timedelta | None = None,
) -> str:
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    if expire_delta:
        expire = now + expire_delta
    else:
        expire = now + timedelta(minutes=expire_minutes)
    to_encode.update(
        exp=expire,
        iat=now,
        jti=generate_jti(),
    )
    encoded = jwt.encode(to_encode, key, algorithm=algorithm)
    return encoded


def decode_jwt(
    token: str | bytes,
    key: str = settings.SECRET_KEY,
    algorithm: str = settings.ALGORITHM,
) -> dict[str, Any]:
    decoded = jwt.decode(token, key, algorithms=algorithm)
    return decoded


def create_access_token(user) -> str:
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "type": ACCESS_TOKEN_TYPE,
    }
    return encode_jwt(payload=payload)


def create_refresh_token(user) -> str:
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "type": REFRESH_TOKEN_TYPE,
    }
    return encode_jwt(
        payload=payload,
        expire_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    pwd_bytes = password.encode()
    return bcrypt.hashpw(pwd_bytes, salt)


def validate_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())
