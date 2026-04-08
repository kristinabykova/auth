from datetime import datetime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.db.base import Base, str_255, pk, created_time


class User(Base):
    __tablename__ = "users"
    id: Mapped[pk]
    email: Mapped[str_255] = mapped_column(unique=True)
    password_hash: Mapped[str_255]
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[created_time]
    portfolio = relationship("Portfolio", back_populates="user")
