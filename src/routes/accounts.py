from datetime import datetime, timezone
from typing import cast
from sqlalchemy.ext import IntegrityError
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password, hash_password
from schemas import (
    UserRegistrationRequestSchema,
    UserActivationSchema,
    UserBaseSchema,
    MessageResponseSchema,
    PasswordResetCompleteSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)

from src.exceptions.security import TokenExpiredError, InvalidTokenError
from src.security.utils import generate_secure_token

router = APIRouter()


@router.post("/register/", status_code=201)
async def register(user: UserRegistrationRequrstSchema, db: AsyncSession = Depends(get_db), jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    db_user = await db.scalar(select(UserModel).where(UserModel.email == user.email))
    access_token = jwt_manager.create_access_token(user.model_dump())
    group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
    new_user = UserModel(email=user.email, password=hash_password(user.password), group_id=group.id)
    try:
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            token=access_token,
            user_id=new_user.id
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return {"id": f"{new_user.id}", "email": f"{new_user.email}"}
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate(user: UserActivationSchema, db: AsyncSession = Depends(get_db)):
    db_user = await db.scalar(select(UserModel).where(UserModel.email == user.email))

    if not db_user:
        raise HTTPException(status_code=404, detail="Not found")
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    if not db_user.activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    expires_at = db_user.activation_token.expires_at.replace(tzinfo=timezone.utc)
    if db_user.activation_token.token != user.token or expires_at < datetime.now(tz=timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True
    await db.delete(db_user.activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def request_password_reset_token(user: UserBaseSchema, db: AsyncSession = Depends(get_db)):
    db_user = await db.scalar(select(UserModel).where(UserModel.email == user.email))
    if not db_user or not db_user.is_active:
        return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")
    if db_user.password_reset_token:
        await db.delete(user.password_reset_token)
    db_user.password_reset_token = PasswordResetTokenModel(
        token=generate_secure_token(),
        user_id=db_user.id
    )
    await db.commit()
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/")
async def reset_password_complete(user: PasswordResetCompleteSchema, db: AsyncSession = Depends(get_db)):
    db_user = await db.scalar(select(UserModel).where(UserModel.email == user.email))

    if not db_user or not db_user.password_reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    expires_at = db_user.password_reset_token.expires_at.replace(tzinfo=timezone.utc)
    if db_user.password_reset_token.token != user.token or expires_at < datetime.now(tz=timezone.utc):
        await db.delete(db_user.password_reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        db_user.password = hash_password(user.password)
        await db.delete(db_user.password_reset_token)
        await db.commit()
        return MessageResponseSchema(message="Password reset complete.")
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/")
async def login(user: UserRegistrationSchema, db: AsyncSession = Depends(get_db),
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    db_user = await db.scalar(select(UserModel).where(UserModel.email == user.email))
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    try:
        access_token = jwt_manager.create_access_token({"user_id": db_user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})
        db_refresh_token = RefreshTokenModel.create(token=refresh_token, user_id=db_user.id, days_valid=7)
        db.add(db_refresh_token)
        await db.flush()
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/api/v1/accounts/refresh/")
async def refresh_account_token(refresh_token: TokenRefreshRequestSchema,
                                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                                db: AsyncSession = Depends(get_db)):
    try:
        jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")
    db_token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token.refresh_token)
    )
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user = await db.scalar(select(UserModel).where(UserModel.id == db_token.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": db_token.user_id})

    return {"access_token": access_token}
