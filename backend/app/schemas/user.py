from pydantic import BaseModel, EmailStr
from typing import Optional
import uuid


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    password: str
    role: str = "tester"


class UserLogin(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    full_name: str
    role: str
    xp_points: int
    level: int
    badges: list
    streak_days: int = 0

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
