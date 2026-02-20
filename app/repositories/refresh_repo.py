import token
from app.models.tokens import RefreshToken
from datetime import datetime, timezone


def get_refresh_token(db, token_hash: str):
    return db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).first()

def revoke_token(db, db_token):
    db_token.revoked = True
    db.flush()

def create_refresh_record(db, user_id: int, token_hash: str, token_version: int, expires_at):
    new_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        token_version=token_version,
        expires_at=expires_at,
    )
    db.add(new_token)
    db.flush()
    return new_token
