from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token
from config import get_jwt_auth_manager, get_settings, BaseAppSettings, get_db
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from exceptions import BaseSecurityError
from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def user_register(
        user_data: UserRegistrationRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db)
):
    group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    hashed_password = hash_password(user_data.password)
    access_token = jwt_manager.create_access_token(user_data.model_dump())
    user = UserModel(
        email=user_data.email,
        _hashed_password=hashed_password,
        group_id=group.id
    )
    try:
        db.add(user)
        await db.flush()
        activation_token = ActivationTokenModel(
            token=access_token,
            user_id=user.id
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(user)
        return UserRegistrationResponseSchema(
            id=user.id,
            email=user.email
        )
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=200)
async def account_activation(
        validation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = cast(
        UserModel,
        await db.scalar(select(UserModel)
                        .where(UserModel.email == validation_data.email)
                        .options(selectinload(UserModel.activation_token)))
    )
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    if not user.activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    expires_at = user.activation_token.expires_at.replace(tzinfo=timezone.utc)
    if user.activation_token.token != validation_data.token or expires_at < datetime.now(tz=timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(user.activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user = cast(
        UserModel,
        await db.scalar(select(UserModel)
                        .where(UserModel.email == reset_data.email)
                        .options(selectinload(UserModel.password_reset_token)))
    )
    if not user or not user.is_active:
        return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")

    if user.password_reset_token:
        await db.delete(user.password_reset_token)

    user.password_reset_token = PasswordResetTokenModel(
        token=generate_secure_token(),
        user_id=user.id
    )

    await db.commit()
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/", status_code=200)
async def complete_reset_password(
        complete_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user = cast(
        UserModel,
        await db.scalar(select(UserModel)
                        .where(UserModel.email == complete_data.email)
                        .options(selectinload(UserModel.password_reset_token)))
    )
    if not user or not user.password_reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = user.password_reset_token.expires_at.replace(tzinfo=timezone.utc)
    if user.password_reset_token.token != complete_data.token or expires_at < datetime.now(tz=timezone.utc):
        await db.delete(user.password_reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user._hashed_password = hash_password(complete_data.password)
        await db.delete(user.password_reset_token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=200)
async def user_login(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = cast(
        UserModel,
        await db.scalar(select(UserModel)
                        .where(UserModel.email == login_data.email)
                        .options(selectinload(UserModel.activation_token)))
    )
    if not user or not verify_password(login_data.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
        db_refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(db_refresh_token)
        await db.flush()
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=db_refresh_token.token,
            token_type="bearer"
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def refresh_token(
        refresh_token_data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db)
):
    try:
        jwt_manager.decode_refresh_token(refresh_token_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    db_token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token_data.refresh_token)
    )
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.scalar(select(UserModel).where(UserModel.id == db_token.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": db_token.user_id})

    return {"access_token": access_token}
