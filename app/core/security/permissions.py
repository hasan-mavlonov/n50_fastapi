from fastapi import Depends, HTTPException
from starlette import status

from app.core.constants import UserRole
from app.core.models import User
from typing import Annotated

from app.core.security.user import get_current_active_user


async def is_admin(user: Annotated[User, Depends(get_current_active_user)]) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to perform this action. Only Admin does!")
    return user


async def is_user(user: Annotated[User, Depends(get_current_active_user)]) -> User:
    if user.role != UserRole.USER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to perform this action. Only User does!")
    return user


async def is_user_or_admin(user: Annotated[User, Depends(get_current_active_user)]) -> User:
    if user.role != UserRole.USER or user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to perform this action. Only User or Admin does!")
    return user
