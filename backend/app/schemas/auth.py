from pydantic import BaseModel, EmailStr, Field, field_validator


PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 72


def _validate_password(value: str) -> str:
    if len(value) < PASSWORD_MIN_LENGTH:
        raise ValueError("Password must be at least 12 characters long.")
    if len(value) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters long.")
    if not any(char.islower() for char in value):
        raise ValueError("Password must include a lowercase letter.")
    if not any(char.isupper() for char in value):
        raise ValueError("Password must include an uppercase letter.")
    if not any(char.isdigit() for char in value):
        raise ValueError("Password must include a digit.")
    if not any(not char.isalnum() for char in value):
        raise ValueError("Password must include a symbol.")
    return value


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=128)
    full_name: str | None = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> EmailStr:
        return str(value).strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return _validate_password(value)


class UserUpdate(BaseModel):
    full_name: str | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_password(value)


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None = None
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
