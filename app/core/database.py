from typing import Annotated

from fastapi import Depends
from sqlmodel import Session, create_engine

from app.core.config import DB_HOST, DB_NAME, DB_PASS, DB_PORT, DB_USER

database_url = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(database_url)


def get_session() -> Session:
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
