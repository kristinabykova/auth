from datetime import datetime
from typing import Annotated
import uuid
from sqlalchemy import String, func, text
from sqlalchemy.orm import DeclarativeBase, mapped_column

str_255 = Annotated[str, 255]
pk = Annotated[
    uuid.UUID, mapped_column(primary_key=True, server_default=func.gen_random_uuid())
]
created_time = Annotated[
    datetime, mapped_column(server_default=text("TIMEZONE('utc', now())"))
]
updated_time = Annotated[
    datetime, mapped_column(server_default=text("TIMEZONE('utc', now())"))
]


class Base(DeclarativeBase):
    type_annotation_map = {str_255: String(255)}
