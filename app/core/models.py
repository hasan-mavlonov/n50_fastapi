from datetime import datetime
from typing import Optional

from sqlmodel import SQLModel, Field

from app.core.database import engine


class Author(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=3, max_length=50)
    first_name: str = Field(min_length=3, max_length=50)
    last_name: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=7, max_length=50)
    age: int
    is_active: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Book(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    title: str = Field(min_length=3, max_length=100)
    description: Optional[str] = None
    author_id: int = Field(foreign_key="author.id")


class BlockedToken(SQLModel, table=True):
    id: int = Field(primary_key=True)
    token: str


def create_tables():
    SQLModel.metadata.create_all(engine)
