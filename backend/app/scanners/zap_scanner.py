"""OWASP ZAP integration — baseline scan via Docker when available."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from app.config import get_settings
from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)
settings = get_settings()

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_SEVERITY_MAP = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "low",
}


def is_zap_available() -> bool:
    if not settings.zap_enabled:
        return False
    if settings.zap_api_url:
        return True
    return shutil.which("docker") is not None


def scan_zap_baseline(target_url: str) -> list[ScanFinding]:
    """Run OWASP ZAP baseline scan against a verified live URL."""
    if not settings.zap_enabled:
        return []

    if settings.zap_api_url:
        return _scan_via_api(target_url)

    if not shutil.which("docker"):
        logger.warning("ZAP enabled but Docker not found")
        return []

    return _scan_via_docker(target_url)


def _scan_via_docker(target_url: str) -> list[ScanFinding]:
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "zap-report.json"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{tmp}:/zap/wrk:rw",
            ZAP_IMAGE,
            "zap-baseline.py",
            "-t", target_url,
            "-J", "zap-report.json",
            "-I",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.zap_timeout_seconds,
                check=False,
            )
            if result.returncode not in (0, 2):
                logger.warning("ZAP baseline exit %s: %s", result.returncode, result.stderr[:500])
        except subprocess.TimeoutExpired:
            logger.warning("ZAP baseline timed out for %s", target_url)
            return []
        except Exception as exc:
            logger.warning("ZAP docker scan failed: %s", exc)
            return []

        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return _parse_zap_json(data, target_url)


def _scan_via_api(target_url: str) -> list[ScanFinding]:
    import httpx

    api = settings.zap_api_url.rstrip("/")
    params = {"url": target_url}
    if settings.zap_api_key:
        params["apikey"] = settings.zap_api_key

    try:
        with httpx.Client(timeout=settings.zap_timeout_seconds) as client:
            spider = client.get(f"{api}/JSON/spider/action/scan/", params=params)
            if spider.status_code != 200:
                return []
            scan_id = spider.json().get("scan")
            if not scan_id:
                return []

            import time
            for _ in range(60):
                status = client.get(
                    f"{api}/JSON/spider/view/status/",
                    params={"apikey": settings.zap_api_key, "scanId": scan_id},
                )
                if status.json().get("status") == "100":
                    break
                time.sleep(2)

            ascan = client.get(f"{api}/JSON/ascan/action/scan/", params=params)
            ascan_id = ascan.json().get("scan")
            if ascan_id:
                for _ in range(90):
                    st = client.get(
                        f"{api}/JSON/ascan/view/status/",
                        params={"apikey": settings.zap_api_key, "scanId": ascan_id},
                    )
                    if st.json().get("status") == "100":
                        break
                    time.sleep(3)

            alerts = client.get(
                f"{api}/JSON/core/view/alerts/",
                params={"apikey": settings.zap_api_key, "baseurl": target_url},
            )
            if alerts.status_code != 200:
                return []
            return _parse_zap_alerts(alerts.json().get("alerts", []), target_url)
    except Exception as exc:
        logger.warning("ZAP API scan failed: %s", exc)
        return []


def _parse_zap_json(data: dict, target_url: str) -> list[ScanFinding]:
    alerts = data.get("site", [])
    if isinstance(alerts, list) and alerts:
        return _parse_zap_alerts(alerts[0].get("alerts", []), target_url)
    return _parse_zap_alerts(data.get("alerts", []), target_url)


def _parse_zap_alerts(alerts: list, target_url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    host = urlparse(target_url).netloc or target_url
    seen: set[str] = set()

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        name = alert.get("alert") or alert.get("name") or "ZAP finding"
        risk = str(alert.get("riskcode", alert.get("risk", "1")))
        severity = ZAP_SEVERITY_MAP.get(risk, "medium")
        plugin_id = str(alert.get("pluginid", alert.get("pluginId", "")))
        rule_id = f"zap-{plugin_id}" if plugin_id else f"zap-{re.sub(r'[^a-z0-9]+', '-', name.lower())[:40]}"
        if rule_id in seen:
            continue
        seen.add(rule_id)

        desc = alert.get("desc", alert.get("description", name))
        if isinstance(desc, str):
            desc = re.sub(r"<[^>]+>", "", desc)[:500]

        findings.append(
            ScanFinding(
                category="security",
                severity=severity,
                title=f"ZAP: {name}",
                description=str(desc),
                impact="OWASP ZAP baseline scan detected a live vulnerability or misconfiguration.",
                fix_recommendation=alert.get("solution", "Review ZAP report and remediate per OWASP guidance."),
                file_path=f"https://{host}/",
                line_start=0,
                line_end=0,
                rule_id=rule_id,
                scanner="zap-dast",
                confidence="high",
                metadata={"zap_plugin_id": plugin_id, "cwe_id": alert.get("cweid")},
            )
        )

    return findings[:80]
