from typing import Annotated, List

from fastapi import APIRouter
from app.core.security.auth import validate_password, get_password_hash, get_user_by_username, get_user_by_email, \
    verify_password, UserChangePassword

from app.core.security.permissions import is_user, is_user_or_admin, is_admin

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select, Session
from app.schemas.user import UserIn, UserOut
from app.core.models import User
from app.core.security.user import get_current_active_user
from app.core.database import get_session
from app.core.security.permissions import is_admin

router = APIRouter(
    tags=["users"]
)


# Create (register) current user - only accessible to admins (you might customize this based on your needs)
@router.post("/users/me/", status_code=status.HTTP_201_CREATED, dependencies=[Depends(is_user_or_admin)])
async def create_user_me(
        user_in: UserIn,
        session: Session = Depends(get_session)
) -> UserOut:
    error_message = None
    if get_user_by_username(username=user_in.username, session=session):
        error_message = "Username already taken"
    elif get_user_by_email(email=user_in.email, session=session):
        error_message = "Email already exists"

    if error_message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    user_dict = user_in.dict()
    user_dict.pop('confirm_password')
    user_dict["password"] = get_password_hash(user_in.password)

    user = User(**user_dict)
    session.add(user)
    session.commit()
    session.refresh(user)
    return UserOut.from_orm(user)


# Get the current user
@router.get("/users/me/", response_model=UserOut)
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
) -> UserOut:
    return current_user


# Update current user's profile
@router.put("/users/me/", response_model=UserOut)
async def update_user_me(
        user_data: UserIn,
        current_user: Annotated[User, Depends(get_current_active_user)],
        session: Session = Depends(get_session)
) -> UserOut:
    if user_data.password and not validate_password(user_data.password, user_data.confirm_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    for key, value in user_data.dict(exclude_unset=True).items():
        if key == "password":
            value = get_password_hash(value)
        setattr(current_user, key, value)

    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return UserOut.from_orm(current_user)


# Delete current user profile
@router.delete("/users/me/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
        session: Session = Depends(get_session)
):
    session.delete(current_user)
    session.commit()
    return {"detail": "User successfully deleted."}


@router.get("/users/", dependencies=[Depends(is_admin)])
def read_users(
        session: Session = Depends(get_session),
) -> List[UserOut]:
    query = select(User)
    result = session.execute(query)
    users = result.scalars().all()
    return [UserOut.from_orm(user) for user in users]


@router.get("/users/{user_id}/", dependencies=[Depends(is_admin)])
def read_user(
        user_id: int,
        session: Session = Depends(get_session),
) -> UserOut:
    query = select(User).where(User.id == user_id)
    result = session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserOut.from_orm(user)


# Update user details (PUT or PATCH)
@router.put("/users/{user_id}/", dependencies=[Depends(is_admin)])
@router.patch("/users/{user_id}/", dependencies=[Depends(is_admin)])
def update_user(
        user_id: int,
        user_data: User,
        session: Session = Depends(get_session),
) -> UserOut:
    query = select(User).where(User.id == user_id)
    result = session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user_data.password and not validate_password(user_data.password, user_data.confirm_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    for key, value in user_data.dict(exclude_unset=True).items():
        if key == "password":
            value = get_password_hash(value)
        setattr(user, key, value)

    session.add(user)
    session.commit()
    session.refresh(user)
    return UserOut.from_orm(user)


# Delete a user by ID
@router.delete("/users/{user_id}/", dependencies=[Depends(is_admin)])
def delete_user(
        user_id: int,
        session: Session = Depends(get_session),
):
    query = select(User).where(User.id == user_id)
    result = session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    session.delete(user)
    session.commit()
    return {"detail": f"User with ID {user_id} has been deleted."}


@router.put("/users/change/password/", status_code=status.HTTP_200_OK)
async def change_password(
        user_data: UserChangePassword,
        current_user: Annotated[User, Depends(get_current_active_user)],
        session: Session = Depends(get_session)
):
    # Step 1: Verify that the current password is correct
    if not verify_password(user_data.current_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Step 2: Check that the new passwords match
    if user_data.new_password != user_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirm password do not match"
        )

    # Step 3: Hash the new password
    hashed_new_password = get_password_hash(user_data.new_password)

    # Step 4: Update the user's password
    current_user.password = hashed_new_password

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return {"detail": "Password successfully updated"}
