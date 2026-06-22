import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enterprise import ApiKey
from app.models.user import User


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, hash)."""
    raw = secrets.token_urlsafe(32)
    full_key = f"aud_{raw}"
    prefix = full_key[:12]
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, prefix, key_hash


async def create_api_key_record(
    db: AsyncSession,
    user: User,
    name: str,
    organization_id=None,
) -> tuple[ApiKey, str]:
    full_key, prefix, key_hash = generate_api_key()
    record = ApiKey(
        user_id=user.id,
        organization_id=organization_id,
        name=name,
        key_prefix=prefix,
        key_hash=key_hash,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record, full_key


async def authenticate_api_key(db: AsyncSession, raw_key: str) -> User | None:
    if not raw_key.startswith("aud_"):
        return None
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
    api_key = result.scalar_one_or_none()
    if not api_key:
        return None

    api_key.last_used_at = datetime.now(timezone.utc)
    user = await db.get(User, api_key.user_id)
    await db.commit()
    return user
