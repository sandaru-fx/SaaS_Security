from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache
def get_sync_engine():
    settings = get_settings()
    kwargs: dict = {"pool_pre_ping": True}
    if not settings.is_sqlite:
        kwargs["connect_args"] = {"connect_timeout": 15}
    return create_engine(settings.sync_database_url, **kwargs)


@lru_cache
def get_sync_session_factory():
    return sessionmaker(bind=get_sync_engine(), expire_on_commit=False)


def get_sync_session() -> Session:
    return get_sync_session_factory()()
