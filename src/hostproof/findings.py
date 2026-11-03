"""Read scanner reports: Trivy JSON, or a simple native format."""

import json
from pathlib import Path

from .models import Finding

MAX_TEXT = 4000


def load_findings(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "Results" in data:
        return from_trivy(data)
    if isinstance(data, dict) and "findings" in data:
        return [Finding.model_validate(item) for item in data["findings"]]
    raise ValueError("unrecognised report: expected Trivy JSON, or an object with a 'findings' list")


def from_trivy(data):
    findings = []
    seen = set()
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            key = (vuln.get("VulnerabilityID", ""), vuln.get("PkgName", ""))
            if not all(key) or key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    vulnerability_id=key[0],
                    package=key[1],
                    installed_version=str(vuln.get("InstalledVersion", "")),
                    fixed_version=str(vuln.get("FixedVersion", "")),
                    severity=str(vuln.get("Severity", "UNKNOWN")),
                    title=str(vuln.get("Title", ""))[:500],
                    description=str(vuln.get("Description", ""))[:MAX_TEXT],
                )
            )
    return findings
