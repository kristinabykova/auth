from typing import Optional
from uuid import UUID

from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from schemas import UserCreate
from user import User
from utils import hash_password


async def get_user_by_email(
    session: AsyncSession, email_user: EmailStr
) -> Optional[User]:
    query = select(User).where(User.email == email_user)
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def get_user_by_id(session: AsyncSession, user_id: UUID) -> Optional[User]:
    query = select(User).where(User.id == user_id)
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def create_user(session: AsyncSession, data: UserCreate) -> User:
    hash_pwd = hash_password(data.password).decode()
    user = User(email=data.email, password_hash=hash_pwd)
    session.add(user)
    await session.commit()
    await session.refresh(user)  # разобраться
    return user
