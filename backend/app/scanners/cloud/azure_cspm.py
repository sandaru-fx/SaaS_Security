"""Azure CSPM-lite — read-only checks via Azure REST API."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.scanners.base import ScanFinding
from app.scanners.cloud.aws_cspm import _finding

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 1433}


def scan_azure(config: dict[str, Any]) -> list[ScanFinding]:
    tenant = config.get("tenant_id", "").strip()
    client_id = config.get("client_id", "").strip()
    client_secret = config.get("client_secret", "").strip()
    subscription_id = config.get("subscription_id", "").strip()

    if not all([tenant, client_id, client_secret, subscription_id]):
        return [
            _finding(
                rule_id="cloud-azure-config-incomplete",
                severity="high",
                title="Azure credentials incomplete",
                description="tenant_id, client_id, client_secret, and subscription_id are required.",
                impact="Azure CSPM scan cannot run.",
                fix_recommendation="Create a service principal with Reader role on the subscription.",
                file_path="azure://subscription",
            )
        ]

    token = _get_token(tenant, client_id, client_secret)
    if not token:
        return [
            _finding(
                rule_id="cloud-azure-auth-failed",
                severity="high",
                title="Azure authentication failed",
                description="Could not obtain access token from Azure AD.",
                impact="Cloud scan could not run.",
                fix_recommendation="Verify tenant ID, client ID, and client secret.",
                file_path=f"azure://{subscription_id}",
            )
        ]

    findings: list[ScanFinding] = []
    findings.extend(_check_storage_public(token, subscription_id))
    findings.extend(_check_nsg_open(token, subscription_id))
    return findings


def _get_token(tenant: str, client_id: str, client_secret: str) -> str | None:
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
    }
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(url, data=data)
            if resp.status_code != 200:
                return None
            return resp.json().get("access_token")
    except httpx.HTTPError:
        return None


def _check_storage_public(token: str, subscription_id: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        "/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
    )
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return findings
            accounts = resp.json().get("value", [])
    except httpx.HTTPError:
        return findings

    for acct in accounts[:40]:
        name = acct.get("name", "")
        props = acct.get("properties", {})
        if props.get("allowBlobPublicAccess") is True:
            findings.append(
                _finding(
                    rule_id="cloud-azure-storage-public-blob",
                    severity="critical",
                    title=f"Azure Storage allows public blob access — {name}",
                    description="allowBlobPublicAccess is true on the storage account.",
                    impact="Blob containers may be readable or writable by anonymous users.",
                    fix_recommendation="Set allowBlobPublicAccess to false at the account level.",
                    file_path=f"azure://storage/{name}",
                )
            )
        if props.get("supportsHttpsTrafficOnly") is False:
            findings.append(
                _finding(
                    rule_id="cloud-azure-storage-http-allowed",
                    severity="medium",
                    title=f"Azure Storage allows HTTP — {name}",
                    description="supportsHttpsTrafficOnly is false.",
                    impact="Data in transit may be intercepted.",
                    fix_recommendation="Enable secure transfer required (HTTPS only).",
                    file_path=f"azure://storage/{name}",
                )
            )
    return findings


def _check_nsg_open(token: str, subscription_id: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        "/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01"
    )
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return findings
            nsgs = resp.json().get("value", [])
    except httpx.HTTPError:
        return findings

    for nsg in nsgs[:40]:
        name = nsg.get("name", "")
        for rule in nsg.get("properties", {}).get("securityRules", []):
            props = rule.get("properties", {})
            if props.get("access") != "Allow" or props.get("direction") != "Inbound":
                continue
            src = props.get("sourceAddressPrefix", "")
            if src not in ("*", "0.0.0.0/0", "Internet"):
                continue
            port = props.get("destinationPortRange", "")
            if port == "*" or str(port) in {str(p) for p in SENSITIVE_PORTS}:
                try:
                    port_num = int(port) if str(port).isdigit() else 0
                except ValueError:
                    port_num = 0
                if port == "*" or port_num in SENSITIVE_PORTS:
                    findings.append(
                        _finding(
                            rule_id="cloud-azure-nsg-open-port",
                            severity="high",
                            title=f"Azure NSG allows internet inbound — {name} port {port}",
                            description=f"Rule `{rule.get('name')}` allows {src} → port {port}.",
                            impact="Management or database ports exposed to the internet.",
                            fix_recommendation="Restrict source prefixes to trusted CIDRs.",
                            file_path=f"azure://nsg/{name}",
                        )
                    )
    return findings
