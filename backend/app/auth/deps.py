from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.clerk import fetch_clerk_user, verify_clerk_token
from app.config import get_settings
from app.database import get_db
from app.models.user import User

security = HTTPBearer(auto_error=False)
settings = get_settings()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if not settings.clerk_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured. Set Clerk environment variables.",
        )

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_clerk_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    clerk_id = payload.get("sub")
    if not clerk_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(select(User).where(User.clerk_id == clerk_id))
    user = result.scalar_one_or_none()

    if user:
        return user

    try:
        clerk_user = await fetch_clerk_user(clerk_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch user from Clerk",
        ) from exc

    email = _extract_primary_email(clerk_user)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Clerk user has no primary email",
        )

    user = User(
        clerk_id=clerk_id,
        email=email,
        first_name=clerk_user.get("first_name"),
        last_name=clerk_user.get("last_name"),
        avatar_url=clerk_user.get("image_url"),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _extract_primary_email(clerk_user: dict) -> str | None:
    for entry in clerk_user.get("email_addresses", []):
        if entry.get("id") == clerk_user.get("primary_email_address_id"):
            return entry.get("email_address")
    emails = clerk_user.get("email_addresses", [])
    if emails:
        return emails[0].get("email_address")
    return None
