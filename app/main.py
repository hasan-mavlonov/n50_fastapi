from fastapi import FastAPI
from starlette.responses import RedirectResponse

from app.core.models import create_tables
from app.routers import authors, books, auth

app = FastAPI()


@app.on_event("startup")
async def startup():
    create_tables()


@app.get("/")
async def root():
    return RedirectResponse(url="/docs/")


app.include_router(authors.router)
app.include_router(books.router)
app.include_router(auth.router)
