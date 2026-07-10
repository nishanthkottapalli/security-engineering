from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from secops_lab.triage.models import Finding, Severity

SEVERITIES = {"unknown", "negligible", "low", "medium", "high", "critical"}


def _severity(value: Any) -> Severity:
    text = str(value or "unknown").strip().lower()
    if text in SEVERITIES:
        return text  # type: ignore[return-value]
    if text in {"moderate", "important"}:
        return "medium" if text == "moderate" else "high"
    return "unknown"


def _id(source: str, component: str, vulnerability_ids: Iterable[str]) -> str:
    raw = "|".join([source, component, *sorted(vulnerability_ids)])
    return f"FND-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"


def parse_pip_audit(data: Any, *, source: str = "pip-audit") -> list[Finding]:
    dependencies = data.get("dependencies", []) if isinstance(data, dict) else data
    findings: list[Finding] = []
    for dependency in dependencies or []:
        component = str(dependency.get("name", "unknown"))
        installed = dependency.get("version")
        for vuln in dependency.get("vulns", []) or []:
            identifiers = [str(vuln.get("id", "UNKNOWN")), *map(str, vuln.get("aliases", []) or [])]
            identifiers = sorted(set(filter(None, identifiers)))
            findings.append(
                Finding(
                    finding_id=_id(source, component, identifiers),
                    source=source,
                    component=component,
                    installed_version=str(installed) if installed is not None else None,
                    fixed_versions=list(map(str, vuln.get("fix_versions", []) or [])),
                    vulnerability_ids=identifiers,
                    severity=_severity(vuln.get("severity", "unknown")),
                    title=str(vuln.get("id", "Python dependency vulnerability")),
                    description=str(vuln.get("description", "Reported by pip-audit.")),
                    references=list(map(str, vuln.get("references", []) or [])),
                    exploit_available=bool(vuln.get("exploit_available", False)),
                )
            )
    return findings


def parse_trivy(data: dict[str, Any], *, source: str = "trivy") -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        target = str(result.get("Target", "repository"))
        for vuln in result.get("Vulnerabilities", []) or []:
            component = str(vuln.get("PkgName", "unknown"))
            identifiers = [str(vuln.get("VulnerabilityID", "UNKNOWN"))]
            findings.append(
                Finding(
                    finding_id=_id(source, component, identifiers),
                    source=source,
                    component=component,
                    installed_version=str(vuln.get("InstalledVersion") or "") or None,
                    fixed_versions=[str(vuln["FixedVersion"])] if vuln.get("FixedVersion") else [],
                    vulnerability_ids=identifiers,
                    severity=_severity(vuln.get("Severity")),
                    title=str(vuln.get("Title") or identifiers[0]),
                    description=str(vuln.get("Description") or "Reported by Trivy."),
                    asset=target,
                    references=list(map(str, vuln.get("References", []) or [])),
                    exploit_available=bool(vuln.get("ExploitAvailable", False)),
                )
            )
        for misconfig in result.get("Misconfigurations", []) or []:
            identifiers = [str(misconfig.get("ID", "MISCONFIG"))]
            component = str(misconfig.get("CauseMetadata", {}).get("Resource", target))
            findings.append(
                Finding(
                    finding_id=_id(source, component, identifiers),
                    source=source,
                    component=component,
                    installed_version=None,
                    fixed_versions=[],
                    vulnerability_ids=identifiers,
                    severity=_severity(misconfig.get("Severity")),
                    title=str(misconfig.get("Title") or identifiers[0]),
                    description=str(
                        misconfig.get("Description") or "Reported by Trivy configuration scan."
                    ),
                    asset=target,
                    references=list(map(str, misconfig.get("References", []) or [])),
                )
            )
    return findings


def parse_grype(data: dict[str, Any], *, source: str = "grype") -> list[Finding]:
    findings: list[Finding] = []
    for match in data.get("matches", []) or []:
        artifact = match.get("artifact", {}) or {}
        vulnerability = match.get("vulnerability", {}) or {}
        component = str(artifact.get("name", "unknown"))
        identifiers = [str(vulnerability.get("id", "UNKNOWN"))]
        fix = vulnerability.get("fix", {}) or {}
        findings.append(
            Finding(
                finding_id=_id(source, component, identifiers),
                source=source,
                component=component,
                installed_version=str(artifact.get("version") or "") or None,
                fixed_versions=list(map(str, fix.get("versions", []) or [])),
                vulnerability_ids=identifiers,
                severity=_severity(vulnerability.get("severity")),
                title=str(vulnerability.get("description") or identifiers[0]),
                description=str(vulnerability.get("description") or "Reported by Grype."),
                references=[
                    str(item.get("url"))
                    for item in vulnerability.get("urls", [])
                    if isinstance(item, dict) and item.get("url")
                ]
                + [str(item) for item in vulnerability.get("urls", []) if isinstance(item, str)],
                exploit_available=bool(vulnerability.get("knownExploited", False)),
            )
        )
    return findings


def parse_checkov(data: dict[str, Any], *, source: str = "checkov") -> list[Finding]:
    failed = (data.get("results", {}) or {}).get("failed_checks", []) or []
    findings: list[Finding] = []
    for check in failed:
        check_id = str(check.get("check_id", "CHECKOV"))
        resource = str(check.get("resource", "terraform-resource"))
        findings.append(
            Finding(
                finding_id=_id(source, resource, [check_id]),
                source=source,
                component=resource,
                installed_version=None,
                fixed_versions=[],
                vulnerability_ids=[check_id],
                severity=_severity(check.get("severity") or "medium"),
                title=str(check.get("check_name") or check_id),
                description=str(
                    check.get("guideline") or check.get("check_name") or "Reported by Checkov."
                ),
                asset=str(check.get("file_path") or "terraform"),
                references=[str(check.get("guideline"))] if check.get("guideline") else [],
            )
        )
    return findings


def parse_file(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    name = path.name.lower()
    if "pip" in name:
        return parse_pip_audit(data)
    if "trivy" in name:
        return parse_trivy(data)
    if "grype" in name:
        return parse_grype(data)
    if "checkov" in name:
        return parse_checkov(data)
    if isinstance(data, dict) and "Results" in data:
        return parse_trivy(data)
    if isinstance(data, dict) and "matches" in data:
        return parse_grype(data)
    if isinstance(data, dict) and "results" in data and "failed_checks" in data.get("results", {}):
        return parse_checkov(data)
    if isinstance(data, (dict, list)):
        return parse_pip_audit(data)
    raise ValueError(f"cannot identify scanner format for {path}")
