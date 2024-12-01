from typing import Optional

from pydantic import BaseModel, Field


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
        from_attributes = True


class BookUpdate(BaseModel):
    title: Optional[str] = Field(min_length=3, max_length=100)
    description: Optional[str] = None
