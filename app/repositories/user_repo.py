from app.core.security import hash_password
from app.models.user import User


def get_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(db, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def create_user(db, user_data):
    user_data.password = hash_password(user_data.password)
    new_user = User(email=user_data.email, password_hash=user_data.password)  
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def record_temp_password_token(db, email: str, token: str):
    pass

def verify_temp_password_token(db, email: str, token: str) -> bool:  # type: ignore
    pass