from fastapi import Depends, HTTPException, Request
from jose import jwt, JWTError

SECRET = "SUPER_SECRET_KEY_123456789"
ALGORITHM = "HS256"

def create_token(data: dict):
    return jwt.encode(data, SECRET, algorithm=ALGORITHM)

def get_current_user(request: Request):
    auth = request.headers.get("Authorization")

    if not auth:
        raise HTTPException(status_code=401, detail="No token")

    token = auth.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")