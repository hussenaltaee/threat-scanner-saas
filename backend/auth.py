import os
import secrets

from fastapi import HTTPException, Request
import jwt

ALGORITHM = "HS256"


def get_secret() -> str:
    secret = os.getenv("SECRET_KEY") or os.getenv("JWT_SECRET")
    if not secret:
        secret = secrets.token_hex(32)
    return secret


SECRET = get_secret()


def create_token(data: dict):
    return jwt.encode(data, SECRET, algorithm=ALGORITHM)


def get_current_user(request: Request):
    auth = request.headers.get("Authorization")

    if not auth:
        raise HTTPException(status_code=401, detail="No token")

    token = auth.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")