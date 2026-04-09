from typing import Optional
import uuid

from fastapi import Depends, HTTPException, Header, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from utils import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    validate_password,
    decode_jwt,
    validate_password,
)
from db.dependencies import get_session
from crud import User, get_user_by_email, get_user_by_id
from schemas.user import UserLogin


bearer_scheme = HTTPBearer(auto_error=False)


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


def get_token_payload(token: str) -> dict:
    try:
        payload = decode_jwt(token)
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
    return payload


def validate_token_type(payload: dict, token_type: str) -> None:
    current_type = payload.get("type")
    if current_type != token_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token type. Expected {token_type}",
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> Optional[User]:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No token",
        )

    token = credentials.credentials
    payload = get_token_payload(token)
    validate_token_type(payload, ACCESS_TOKEN_TYPE)

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


async def get_current_user_for_refresh(
    authorization: str = Header(None),
    session: AsyncSession = Depends(get_session),
) -> Optional[User]:

    if not authorization:
        raise HTTPException(401, "No token")

    token = authorization.replace("Bearer ", "")

    payload = get_token_payload(token)
    payload = get_token_payload(token)
    validate_token_type(payload, REFRESH_TOKEN_TYPE)

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
