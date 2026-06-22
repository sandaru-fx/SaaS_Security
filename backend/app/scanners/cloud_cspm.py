"""Cloud CSPM orchestrator — AWS, Azure, GCP read-only scans."""

from __future__ import annotations

from typing import Any

from app.scanners.base import ScanFinding
from app.scanners.cloud.aws_cspm import scan_aws
from app.scanners.cloud.azure_cspm import scan_azure
from app.scanners.cloud.gcp_cspm import scan_gcp


def scan_cloud(provider: str, config: dict[str, Any]) -> list[ScanFinding]:
    provider = (provider or "").lower().strip()
    if provider == "aws":
        return scan_aws(config)
    if provider == "azure":
        return scan_azure(config)
    if provider == "gcp":
        return scan_gcp(config)
    return []


def validate_cloud_credentials(provider: str, config: dict[str, Any]) -> None:
    """Raise ValueError when cloud credentials cannot authenticate."""
    provider = (provider or "").lower().strip()
    if provider == "aws":
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:
            raise ValueError("AWS scanning requires boto3 on the server") from exc
        region = config.get("region") or "us-east-1"
        session = boto3.Session(
            aws_access_key_id=config.get("access_key_id"),
            aws_secret_access_key=config.get("secret_access_key"),
            aws_session_token=config.get("session_token"),
            region_name=region,
        )
        try:
            session.client("sts").get_caller_identity()
        except (BotoCoreError, ClientError) as exc:
            raise ValueError(f"AWS credential validation failed: {exc}") from exc
        return

    if provider == "azure":
        from app.scanners.cloud.azure_cspm import _get_token

        token = _get_token(
            config.get("tenant_id", "").strip(),
            config.get("client_id", "").strip(),
            config.get("client_secret", "").strip(),
        )
        if not token:
            raise ValueError("Azure authentication failed — check tenant, client ID, and secret")
        return

    if provider == "gcp":
        import json

        try:
            from google.oauth2 import service_account
        except ImportError as exc:
            raise ValueError("GCP scanning requires google-cloud-storage on the server") from exc
        raw_json = config.get("service_account_json", "").strip()
        if not raw_json:
            raise ValueError("GCP service account JSON is required")
        try:
            info = json.loads(raw_json)
            service_account.Credentials.from_service_account_info(info)
        except Exception as exc:
            raise ValueError(f"GCP authentication failed: {exc}") from exc
        return

    raise ValueError(f"Unsupported cloud provider: {provider}")
