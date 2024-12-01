from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import select
from app.core.database import SessionDep
from app.core.models import Author
from app.schemas.authors import AuthorIn, AuthorOut, AuthorUpdate

router = APIRouter(
    tags=['authors'],
)


@router.post('/authors/', status_code=201, response_model=AuthorOut)
async def create_author(author: AuthorIn, session: SessionDep) -> AuthorOut:
    try:
        author_in = Author(**author.dict())
        session.add(author_in)
        session.commit()
        session.refresh(author_in)
        return author_in
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail='Something went wrong')


@router.get('/authors/', status_code=200, response_model=list[AuthorOut])
async def get_authors(session: SessionDep) -> list[AuthorOut]:
    authors = session.exec(select(Author)).all()
    return authors


@router.get('/authors/{author_id}', status_code=200, response_model=AuthorOut)
async def get_author(author_id: int, session: SessionDep) -> AuthorOut:
    author = session.get(Author, author_id)
    if not author:
        raise HTTPException(status_code=404, detail='Author not found')
    return author


@router.put('/authors/{author_id}', status_code=200, response_model=AuthorOut)
async def update_author(
        author_id: int, updated_data: AuthorUpdate, session: SessionDep
) -> AuthorOut:
    author = session.get(Author, author_id)
    if not author:
        raise HTTPException(status_code=404, detail='Author not found')

    for key, value in updated_data.dict(exclude_unset=True).items():
        setattr(author, key, value)

    session.add(author)
    session.commit()
    session.refresh(author)
    return author


@router.delete('/authors/{author_id}', status_code=204)
async def delete_author(author_id: int, session: SessionDep):
    author = session.get(Author, author_id)
    if not author:
        raise HTTPException(status_code=404, detail='Author not found')

    session.delete(author)
    session.commit()
    return None
