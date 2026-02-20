from app.core.security import hash_password
from app.models.user import TempUser, User


def get_user_by_email(db, email: str,temp:bool = False):
    if temp:
        return db.query(TempUser).filter(TempUser.email == email).first()
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(db, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def create_user(db, user_data:TempUser):
    new_user = User(email=user_data.email, password=user_data.password)  
    db.add(new_user)
    db.flush()
    return new_user

def record_temp_password_token(db, email: str, token: str):
    pass

def verify_temp_password_token(db, email: str, token: str) -> bool:  # type: ignore
    pass

def create_temp_user(db,user_data):
    temp_user = TempUser(**user_data.model_dump())
    db.add(temp_user)
    db.flush()
    return temp_user

def get_temp_user_by_email(db, email: str):
    return db.query(TempUser).filter(TempUser.email == email).first()

def delete_temp_user_by_email(db,email:str):
    db.query(TempUser).filter(TempUser.email == email).delete()
    db.flush()
    return True
