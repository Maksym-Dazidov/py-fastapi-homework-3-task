from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from database.validators.accounts import validate_password_strength, validate_email


class UserBaseSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        validate_email(value)
        return value


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBaseSchema):
    token: str


class PasswordResetRequestSchema(UserBaseSchema):
    pass


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(UserBaseSchema):
    token: str
    password: str


class UserLoginRequestSchema(UserBaseSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
