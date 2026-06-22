from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache
def get_sync_engine():
    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True)


@lru_cache
def get_sync_session_factory():
    return sessionmaker(bind=get_sync_engine(), expire_on_commit=False)


def get_sync_session() -> Session:
    return get_sync_session_factory()()
