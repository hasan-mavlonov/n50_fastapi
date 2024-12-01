from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AuthorBase(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=7, max_length=50)
    first_name: str = Field(min_length=3, max_length=50)
    last_name: str = Field(min_length=3, max_length=50)
    age: int


class Login(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    access_token: str
    token_type: str


class Logout(BaseModel):
    access_token: str


class StandardResponse(BaseModel):
    success: bool
    message: str

class AuthorIn(AuthorBase):
    password: str = Field(min_length=3, max_length=100)
    confirm_password: str = Field(min_length=3, max_length=100)


class AuthorOut(AuthorBase):
    id: int

    class Config:
        from_attributes = True


class AuthorUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None
