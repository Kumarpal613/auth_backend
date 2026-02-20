from fastapi import APIRouter, Depends

from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas import users


router =   APIRouter(prefix="/users",tags=["Users"])

@router.get("/me", response_model= users.UserProfileRes)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user