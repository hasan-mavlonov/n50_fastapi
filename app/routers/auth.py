from fastapi import APIRouter, HTTPException
from starlette import status
from starlette.responses import JSONResponse

from app.core.database import SessionDep
from app.core.models import Author, BlockedToken
from app.core.security.auth import get_password_hash, validate_password, get_author_by_username, get_author_by_email, \
    verify_password
from app.core.security.jwt_token import create_access_token
from app.schemas.authors import AuthorOut, AuthorIn, Login, TokenData, Logout, StandardResponse

router = APIRouter()


@router.post('/register/', status_code=status.HTTP_201_CREATED, response_model=None)
async def register(author_in: AuthorIn, session: SessionDep) -> AuthorOut | JSONResponse:
    author_dict = author_in.dict()
    error_message = None
    if not validate_password(author_dict['password'], author_dict['confirm_password']):
        error_message = "Password should contain at least 8 characters, have an uppercase letter and a digit, and should be the same."
    elif get_author_by_username(username=author_in.username, session=session):
        error_message = "Username already exists."
    elif get_author_by_email(email=author_in.email, session=session):
        error_message = "Email already exists."
    if error_message:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    author_dict.pop('confirm_password')
    author_dict["password"] = get_password_hash(author_in.password)
    author = Author(**author_dict)
    session.add(author)
    session.commit()
    session.refresh(author)
    return AuthorOut.from_orm(author)


@router.post('/login/')
async def login(data: Login, session: SessionDep) -> TokenData:
    author = get_author_by_username(username=data.username, session=session)
    if not author or not verify_password(plain_password=data.password, hashed_password=author.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Username or password invalid.")
    access_token = create_access_token(data={"sub": author.username})
    return TokenData(access_token=access_token, token_type="Bearer")


@router.post('/logout/')
async def logout(token: Logout, session: SessionDep) -> dict:
    blocked_token = BlockedToken(token=token.access_token)
    session.add(blocked_token)
    session.commit()
    session.refresh(blocked_token)
    response = StandardResponse(success=True, message="Successfully logged out.")
    return response.dict()
