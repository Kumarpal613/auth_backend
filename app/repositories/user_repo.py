from app.core.security import hash_password
from app.models.user import TempUser, User


def db_get_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(db, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def db_create_user(db, user_data):
    user_data.password = hash_password(user_data.password)
    new_user = User(email=user_data.email, password_hash=user_data.password)  
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def db_record_temp_password_token(db, email: str, token: str):
    pass

def db_verify_temp_password_token(db, email: str, token: str) -> bool:  # type: ignore
    pass

def db_create_temp_user(db, email: str, password: str):
    password_hash = hash_password(password)
    temp_user = TempUser(email=email, password_hash=password_hash)
    db.add(temp_user)
    db.commit()
    db.refresh(temp_user)
    return temp_user