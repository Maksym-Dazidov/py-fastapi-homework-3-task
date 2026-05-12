from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBaseSchema(BaseModel):
    email: EmailStr

class UserRegistrationSchema(UserBaseSchema):
    password: str

class UserActivationSchema(UserBaseSchema):
    token: str

class MessageResponseSchema(BaseModel):
    message: str

class PasswordResetCompleteSchema(UserBaseSchema):
    token: str
    password: str
class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
