from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import select
from app.core.database import SessionDep
from app.core.models import Book
from app.schemas.books import BookIn, BookOut, BookUpdate

router = APIRouter(
    tags=['books'],
)


@router.post('/books/', status_code=201, response_model=BookOut)
async def create_book(book: BookIn, session: SessionDep) -> BookOut:
    try:
        book_in = Book(**book.dict())
        session.add(book_in)
        session.commit()
        session.refresh(book_in)
        return book_in
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail='Something went wrong')


@router.get('/books/', status_code=200, response_model=list[BookOut])
async def get_books(session: SessionDep) -> list[BookOut]:
    books = session.exec(select(Book)).all()
    return books


@router.get('/books/{book_id}', status_code=200, response_model=BookOut)
async def get_book(book_id: int, session: SessionDep) -> BookOut:
    book = session.get(Book, book_id)
    if not book:
        raise HTTPException(status_code=404, detail='Book not found')
    return book


@router.put('/books/{book_id}', status_code=200, response_model=BookOut)
async def update_book(
        book_id: int, updated_data: BookUpdate, session: SessionDep
) -> BookOut:
    book = session.get(Book, book_id)
    if not book:
        raise HTTPException(status_code=404, detail='Book not found')

    for key, value in updated_data.dict(exclude_unset=True).items():
        setattr(book, key, value)

    session.add(book)
    session.commit()
    session.refresh(book)
    return book


@router.delete('/books/{book_id}', status_code=204)
async def delete_book(book_id: int, session: SessionDep):
    book = session.get(Book, book_id)
    if not book:
        raise HTTPException(status_code=404, detail='Book not found')

    session.delete(book)
    session.commit()
    return None
