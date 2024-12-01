from passlib.context import CryptContext

from app.core.database import SessionDep
from app.core.models import Author

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def validate_password(password, confirm_password):
    if ((len(password) > 8) and (any(char.isupper() for char in password)) and
            (any(char.isdigit() for char in password))):
        if password == confirm_password:
            return True
        else:
            print("The passwords do not match")
            return False
    else:
        print("The password should contains at one uppercase letter and one digit!")
        return False


def get_author_by_username(username: str, session: SessionDep) -> Author | None:
    author = session.query(Author).filter(Author.username == username).first()
    return author


def get_author_by_email(email: str, session: SessionDep) -> Author | None:
    author = session.query(Author).filter(Author.email == email).first()
    return author
