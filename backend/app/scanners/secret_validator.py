"""Live secret validator.

For each secret finding that carries `_secret_value` metadata, calls the
relevant provider API to determine whether the credential is currently
active. Results:

  metadata.validated = "active" | "inactive" | "rate_limited" | "skipped" | "unknown"
  metadata.validated_principal = <account id / username / etc> (when active)
  metadata.validated_method = "<provider api endpoint>"

Active secrets get `confidence=critical-confirmed` and severity is
preserved/promoted. Inactive (404/401/403 on validation) keeps severity
but adds explanatory note.

Privacy: the `_secret_value` is stripped from metadata after validation
so no plaintext credential is ever persisted.
"""

from __future__ import annotations

import logging
import os
from typing import Callable

import httpx

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

VALIDATION_TIMEOUT = 6.0
MAX_VALIDATIONS_PER_SCAN = 50
USER_AGENT = "AI-Software-Auditor-SecretValidator/1.0"


def _truthy(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def is_validation_enabled() -> bool:
    return _truthy(os.getenv("LIVE_SECRET_VALIDATION"), default=True)


def validate_secret_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Mutate findings in-place: validate where possible, strip raw secret."""
    if not is_validation_enabled():
        for finding in findings:
            if finding.metadata.get("_secret_value"):
                finding.metadata.pop("_secret_value", None)
                finding.metadata["validated"] = "skipped"
                finding.metadata["validated_reason"] = "LIVE_SECRET_VALIDATION=false"
        return findings

    seen_hashes: set[str] = set()
    calls_made = 0

    with httpx.Client(
        timeout=VALIDATION_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        follow_redirects=True,
    ) as client:
        for finding in findings:
            value = finding.metadata.get("_secret_value")
            if not value:
                continue

            value_hash = str(hash(value))
            if value_hash in seen_hashes:
                finding.metadata["validated"] = "duplicate"
                finding.metadata.pop("_secret_value", None)
                continue
            seen_hashes.add(value_hash)

            if calls_made >= MAX_VALIDATIONS_PER_SCAN:
                finding.metadata["validated"] = "skipped"
                finding.metadata["validated_reason"] = "Validation budget exhausted"
                finding.metadata.pop("_secret_value", None)
                continue

            validator = VALIDATORS.get(finding.rule_id)
            if validator is None:
                finding.metadata["validated"] = "no_validator"
                finding.metadata.pop("_secret_value", None)
                continue

            try:
                result = validator(client, value)
                calls_made += 1
            except Exception as exc:
                logger.debug("Validator %s failed: %s", finding.rule_id, exc)
                result = {"validated": "unknown", "validated_reason": str(exc)[:120]}

            finding.metadata.update(result)
            finding.metadata.pop("_secret_value", None)

            if result.get("validated") == "active":
                finding.severity = "critical"
                finding.confidence = "high"
                principal = result.get("validated_principal")
                if principal:
                    finding.title = f"{finding.title} — VALIDATED ACTIVE ({principal})"
                else:
                    finding.title = f"{finding.title} — VALIDATED ACTIVE"

    return findings


def _result(
    *,
    validated: str,
    method: str,
    principal: str | None = None,
    reason: str | None = None,
) -> dict[str, str]:
    out: dict[str, str] = {"validated": validated, "validated_method": method}
    if principal:
        out["validated_principal"] = principal[:160]
    if reason:
        out["validated_reason"] = reason[:160]
    return out


def validate_github(client: httpx.Client, token: str) -> dict[str, str]:
    response = client.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {token}"},
    )
    method = "GET api.github.com/user"
    if response.status_code == 200:
        data = response.json()
        login = data.get("login", "<unknown>")
        return _result(validated="active", method=method, principal=f"GitHub user @{login}")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    if response.status_code == 429:
        return _result(validated="rate_limited", method=method)
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_stripe(client: httpx.Client, key: str) -> dict[str, str]:
    response = client.get(
        "https://api.stripe.com/v1/account",
        auth=(key, ""),
    )
    method = "GET api.stripe.com/v1/account"
    if response.status_code == 200:
        data = response.json()
        principal = data.get("display_name") or data.get("id") or "Stripe account"
        livemode = key.startswith("sk_live_") or key.startswith("rk_live_")
        return _result(
            validated="active",
            method=method,
            principal=f"Stripe {'LIVE' if livemode else 'test'}: {principal}",
        )
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_slack_bot(client: httpx.Client, token: str) -> dict[str, str]:
    response = client.post(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
    )
    method = "POST slack.com/api/auth.test"
    if response.status_code == 200:
        data = response.json()
        if data.get("ok"):
            team = data.get("team", "?")
            user = data.get("user", "?")
            return _result(validated="active", method=method, principal=f"Slack workspace {team} as {user}")
        return _result(validated="inactive", method=method, reason=str(data.get("error", "")))
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_slack_webhook(client: httpx.Client, url: str) -> dict[str, str]:
    # Posting empty payload returns 400 + "no_text" on valid endpoint, 404 on invalid.
    response = client.post(url, json={"text": ""})
    method = "POST slack hooks"
    body_lower = response.text.lower()
    if response.status_code == 400 and "no_text" in body_lower:
        return _result(validated="active", method=method, principal="Slack incoming webhook")
    if response.status_code == 200:
        return _result(validated="active", method=method, principal="Slack incoming webhook")
    if response.status_code == 404 or "no_service" in body_lower or "invalid_token" in body_lower:
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_discord_webhook(client: httpx.Client, url: str) -> dict[str, str]:
    response = client.get(url)
    method = "GET discord webhook"
    if response.status_code == 200:
        try:
            data = response.json()
        except Exception:
            data = {}
        name = data.get("name") or data.get("channel_id") or "discord webhook"
        return _result(validated="active", method=method, principal=f"Discord: {name}")
    if response.status_code in (401, 404):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_sendgrid(client: httpx.Client, key: str) -> dict[str, str]:
    response = client.get(
        "https://api.sendgrid.com/v3/scopes",
        headers={"Authorization": f"Bearer {key}"},
    )
    method = "GET api.sendgrid.com/v3/scopes"
    if response.status_code == 200:
        try:
            scopes = response.json().get("scopes", [])
        except Exception:
            scopes = []
        return _result(
            validated="active",
            method=method,
            principal=f"SendGrid key with {len(scopes)} scopes",
        )
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_mailgun(client: httpx.Client, key: str) -> dict[str, str]:
    response = client.get(
        "https://api.mailgun.net/v3/domains",
        auth=("api", key),
    )
    method = "GET api.mailgun.net/v3/domains"
    if response.status_code == 200:
        try:
            count = response.json().get("total_count", "?")
        except Exception:
            count = "?"
        return _result(validated="active", method=method, principal=f"Mailgun account ({count} domains)")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_digitalocean(client: httpx.Client, token: str) -> dict[str, str]:
    response = client.get(
        "https://api.digitalocean.com/v2/account",
        headers={"Authorization": f"Bearer {token}"},
    )
    method = "GET api.digitalocean.com/v2/account"
    if response.status_code == 200:
        try:
            account = response.json().get("account", {})
            email = account.get("email", "?")
        except Exception:
            email = "?"
        return _result(validated="active", method=method, principal=f"DigitalOcean {email}")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_npm(client: httpx.Client, token: str) -> dict[str, str]:
    response = client.get(
        "https://registry.npmjs.org/-/whoami",
        headers={"Authorization": f"Bearer {token}"},
    )
    method = "GET registry.npmjs.org/-/whoami"
    if response.status_code == 200:
        try:
            user = response.json().get("username", "?")
        except Exception:
            user = "?"
        return _result(validated="active", method=method, principal=f"npm user {user}")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_openai(client: httpx.Client, key: str) -> dict[str, str]:
    response = client.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {key}"},
    )
    method = "GET api.openai.com/v1/models"
    if response.status_code == 200:
        return _result(validated="active", method=method, principal="OpenAI API key")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_google_api(client: httpx.Client, key: str) -> dict[str, str]:
    response = client.get(
        f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
    )
    method = "GET generativelanguage.googleapis.com/v1beta/models"
    if response.status_code == 200:
        return _result(validated="active", method=method, principal="Google AI key")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


def validate_cloudflare(client: httpx.Client, token: str) -> dict[str, str]:
    response = client.get(
        "https://api.cloudflare.com/client/v4/user/tokens/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    method = "GET api.cloudflare.com/client/v4/user/tokens/verify"
    if response.status_code == 200:
        try:
            data = response.json()
            ok = bool(data.get("success"))
        except Exception:
            ok = False
        if ok:
            return _result(validated="active", method=method, principal="Cloudflare API token")
        return _result(validated="inactive", method=method, reason="success=false")
    if response.status_code in (401, 403):
        return _result(validated="inactive", method=method, reason=f"HTTP {response.status_code}")
    return _result(validated="unknown", method=method, reason=f"HTTP {response.status_code}")


VALIDATORS: dict[str, Callable[[httpx.Client, str], dict[str, str]]] = {
    "github-token": validate_github,
    "github-fine-grained-token": validate_github,
    "stripe-secret-key": validate_stripe,
    "stripe-restricted-key": validate_stripe,
    "slack-bot-token": validate_slack_bot,
    "slack-webhook": validate_slack_webhook,
    "discord-webhook": validate_discord_webhook,
    "sendgrid-api-key": validate_sendgrid,
    "mailgun-api-key": validate_mailgun,
    "digitalocean-token": validate_digitalocean,
    "npm-token": validate_npm,
    "openai-key": validate_openai,
    "google-api-key": validate_google_api,
}
