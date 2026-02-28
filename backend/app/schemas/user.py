from pydantic import BaseModel, EmailStr
from typing import Optional
import uuid


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    password: str
    role: str = "tester"
    organization_id: Optional[str] = None  # Required when role=admin (super_admin sets this)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    organization_id: Optional[str] = None
    is_active: Optional[bool] = None
    xp_points: Optional[int] = None
    level: Optional[int] = None


class UserPasswordUpdate(BaseModel):
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


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


class UserAdminOut(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    full_name: str
    role: str
    organization_id: Optional[uuid.UUID] = None
    organization_name: Optional[str] = None
    is_active: bool
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
