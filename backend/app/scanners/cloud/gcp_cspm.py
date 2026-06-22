"""GCP CSPM-lite — read-only bucket IAM checks."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.scanners.base import ScanFinding
from app.scanners.cloud.aws_cspm import _finding

logger = logging.getLogger(__name__)

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def scan_gcp(config: dict[str, Any]) -> list[ScanFinding]:
    raw_json = config.get("service_account_json", "").strip()
    if not raw_json:
        return [
            _finding(
                rule_id="cloud-gcp-config-incomplete",
                severity="high",
                title="GCP service account JSON missing",
                description="service_account_json is required for GCP CSPM.",
                impact="GCP scan cannot run.",
                fix_recommendation="Create a service account with roles/storage.objectViewer and iam.securityReviewer.",
                file_path="gcp://project",
            )
        ]

    try:
        from google.oauth2 import service_account
        from google.cloud import storage
    except ImportError:
        logger.warning("google-cloud-storage not installed")
        return []

    try:
        info = json.loads(raw_json)
        credentials = service_account.Credentials.from_service_account_info(info)
        client = storage.Client(credentials=credentials, project=info.get("project_id"))
    except Exception as exc:
        return [
            _finding(
                rule_id="cloud-gcp-auth-failed",
                severity="high",
                title="GCP authentication failed",
                description=str(exc),
                impact="Cloud scan could not run.",
                fix_recommendation="Verify service account JSON and IAM roles.",
                file_path="gcp://project",
            )
        ]

    findings: list[ScanFinding] = []
    try:
        for bucket in list(client.list_buckets())[:40]:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                public_members = PUBLIC_MEMBERS.intersection(set(binding.get("members", [])))
                if public_members:
                    findings.append(
                        _finding(
                            rule_id="cloud-gcp-bucket-public-iam",
                            severity="critical",
                            title=f"GCS bucket publicly accessible — {bucket.name}",
                            description=(
                                f"IAM binding `{binding.get('role')}` includes "
                                f"{', '.join(public_members)}."
                            ),
                            impact="Anyone on the internet may read or write bucket objects.",
                            fix_recommendation="Remove allUsers/allAuthenticatedUsers from bucket IAM.",
                            file_path=f"gcs://{bucket.name}",
                            metadata={"role": binding.get("role")},
                        )
                    )
            if bucket.iam_configuration.uniform_bucket_level_access_enabled is False:
                findings.append(
                    _finding(
                        rule_id="cloud-gcp-bucket-legacy-acl",
                        severity="medium",
                        title=f"GCS uniform bucket-level access disabled — {bucket.name}",
                        description="Legacy ACLs may allow unintended public access.",
                        impact="ACL-based public access can bypass centralized IAM policies.",
                        fix_recommendation="Enable uniform bucket-level access on all buckets.",
                        file_path=f"gcs://{bucket.name}",
                    )
                )
    except Exception as exc:
        logger.warning("GCP bucket scan failed: %s", exc)

    return findings
