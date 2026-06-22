from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.user import GithubPatUpdate, UserResponse, UserUpdate
from app.services.subscription_service import has_feature

router = APIRouter(prefix="/users", tags=["users"])


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        clerk_id=user.clerk_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        avatar_url=user.avatar_url,
        github_pat_configured=bool(user.github_pat),
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    return _user_response(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_me(
    payload: UserUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    if payload.first_name is not None:
        current_user.first_name = payload.first_name
    if payload.last_name is not None:
        current_user.last_name = payload.last_name

    await db.commit()
    await db.refresh(current_user)
    return _user_response(current_user)


@router.patch("/me/github-pat", response_model=UserResponse)
async def update_github_pat(
    payload: GithubPatUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    if not has_feature(current_user, "private_repos"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GitHub PAT requires Pro or Team plan.",
        )
    pat = (payload.github_pat or "").strip()
    current_user.github_pat = pat or None
    await db.commit()
    await db.refresh(current_user)
    return _user_response(current_user)
