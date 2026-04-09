from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(UserCreate):
    pass


class UserRead(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool
    role: str
    created_at: datetime

    model_config = ConfigDict(strict=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "Bearer"


class Logout(BaseModel):
    message: str
