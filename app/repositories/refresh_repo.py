from app.models.tokens import RefreshToken
from datetime import datetime, timezone


def query_refresh_token(db, token_hash: str):
    return db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    )


def revoke_token(db, db_token):
    db_token.revoked = True
    db.commit()


def create_refresh_record(db, user_id: int, token_hash: str, expires_at):
    new_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(new_token)
    db.commit()
    db.refresh(new_token)
    return new_token
