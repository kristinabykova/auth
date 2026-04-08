from typing import Optional
import uuid

from fastapi import Depends, HTTPException, status, Cookie
from fastapi.security import OAuth2PasswordBearer
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from utils import validate_password, decode_jwt, validate_password
from crud import User
from db.dependencies import get_session
from crud import get_user_by_email, get_user_by_id
from schemas import UserLogin

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def validate_auth_user(
    data: UserLogin, session: AsyncSession = Depends(get_session)
) -> Optional[User]:
    unauthed_ex = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
    )
    user = await get_user_by_email(session, data.email)
    if not user:
        raise unauthed_ex
    pwd = data.password
    pwd_hash = user.password_hash
    val = validate_password(pwd, pwd_hash)
    if not val:
        raise unauthed_ex

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="user inactive",
        )

    return user


async def get_current_user(
    access_token: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> Optional[User]:
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        payload = decode_jwt(access_token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user id",
        )

    user = await get_user_by_id(session, user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User inactive",
        )

    return user
