"""CycloneDX SBOM generation from project lockfiles."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from app.scanners.dependencies import collect_packages

PURL_ECOSYSTEM = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "crates.io": "cargo",
    "Packagist": "composer",
    "RubyGems": "gem",
}


def build_cyclonedx_sbom(project_dir: Path, project_name: str) -> dict:
    """Build a CycloneDX 1.5 JSON SBOM from discovered dependencies."""
    packages = collect_packages(project_dir)
    components = []
    seen: set[str] = set()

    for name, version, ecosystem in packages:
        purl_eco = PURL_ECOSYSTEM.get(ecosystem, ecosystem.lower())
        purl = f"pkg:{purl_eco}/{quote(name, safe='@')}@{version}"
        if purl in seen:
            continue
        seen.add(purl)
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "properties": [{"name": "ecosystem", "value": ecosystem}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:auditor-sbom-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": project_name,
            },
            "tools": [
                {
                    "vendor": "AI Software Auditor",
                    "name": "sbom-generator",
                    "version": "1.0",
                }
            ],
        },
        "components": sorted(components, key=lambda c: c["name"].lower()),
    }


def sbom_to_json_bytes(sbom: dict) -> bytes:
    return json.dumps(sbom, indent=2).encode("utf-8")
