from fastapi import APIRouter, Depends, HTTPException, status, Response
from utils import create_access_token, create_refresh_token, encode_jwt
from service import get_current_user, get_current_user_for_refresh, validate_auth_user
from db.dependencies import get_session
from user import User
from schemas.user import UserLogin, UserRead, Token
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login", response_model=Token)
async def login_user(
    data: UserLogin,
    session: AsyncSession = Depends(get_session),
) -> Token:
    user = await validate_auth_user(data, session)

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
    )


@router.post("/refresh", response_model=Token)
async def refresh_tokens(
    current_user: User = Depends(get_current_user_for_refresh),
) -> Token:
    access_token = create_access_token(current_user)
    refresh_token = create_refresh_token(current_user)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
    )


@router.get("/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)) -> UserRead:
    return current_user
