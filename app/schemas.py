from typing import Optional

from pydantic import BaseModel, Field


class AuthorIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    first_name: str = Field(min_length=3, max_length=50)
    last_name: str = Field(min_length=3, max_length=50)
    age: int


class AuthorOut(BaseModel):
    id: int
    username: str = Field(min_length=3, max_length=50)
    first_name: str = Field(min_length=3, max_length=50)
    last_name: str = Field(min_length=3, max_length=50)
    age: int

    class Config:
        orm_mode = True


class AuthorUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None


class BookIn(BaseModel):
    title: str = Field(min_length=3, max_length=100)
    description: Optional[str] = None
    author_id: int


class BookOut(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    author_id: int

    class Config:
        orm_mode = True


class BookUpdate(BaseModel):
    title: Optional[str] = Field(min_length=3, max_length=100)
    description: Optional[str] = None
