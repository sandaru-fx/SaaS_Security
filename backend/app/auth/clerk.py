from typing import Any

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError

from app.config import get_settings

settings = get_settings()
_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        if not settings.clerk_jwks_url:
            raise RuntimeError("CLERK_JWKS_URL is not configured")
        _jwks_client = PyJWKClient(settings.clerk_jwks_url)
    return _jwks_client


def verify_clerk_token(token: str) -> dict[str, Any]:
    if not settings.clerk_enabled:
        raise RuntimeError("Clerk authentication is not configured")

    try:
        signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
        decode_options: dict[str, Any] = {"verify_aud": False}

        payload: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=settings.clerk_jwt_issuer or None,
            options=decode_options,
        )
        return payload
    except InvalidTokenError as exc:
        raise ValueError("Invalid or expired token") from exc


async def fetch_clerk_user(clerk_user_id: str) -> dict[str, Any]:
    if not settings.clerk_secret_key:
        raise RuntimeError("CLERK_SECRET_KEY is not configured")

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"https://api.clerk.com/v1/users/{clerk_user_id}",
            headers={"Authorization": f"Bearer {settings.clerk_secret_key}"},
        )
        response.raise_for_status()
        return response.json()
