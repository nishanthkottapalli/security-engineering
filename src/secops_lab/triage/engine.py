from __future__ import annotations

from dataclasses import replace

from secops_lab.triage.models import Finding

SEVERITY_WEIGHT = {
    "critical": 45,
    "high": 35,
    "medium": 22,
    "low": 10,
    "negligible": 3,
    "unknown": 12,
}
CRITICALITY_WEIGHT = {"critical": 15, "high": 12, "medium": 7, "low": 2}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = finding.deduplication_key()
        if key not in merged:
            merged[key] = replace(finding)
            continue
        current = merged[key]
        current.sources = sorted(set(current.sources + finding.sources))
        current.vulnerability_ids = sorted(
            set(current.vulnerability_ids + finding.vulnerability_ids)
        )
        current.fixed_versions = sorted(set(current.fixed_versions + finding.fixed_versions))
        current.references = sorted(set(current.references + finding.references))
        if SEVERITY_WEIGHT[finding.severity] > SEVERITY_WEIGHT[current.severity]:
            current.severity = finding.severity
        current.exploit_available = current.exploit_available or finding.exploit_available
    return list(merged.values())


def score(finding: Finding) -> Finding:
    score_value = SEVERITY_WEIGHT[finding.severity]
    rationale = [f"severity={finding.severity}"]
    if finding.exploit_available:
        score_value += 20
        rationale.append("public/known exploitation signal")
    if finding.internet_exposed:
        score_value += 15
        rationale.append("internet-exposed asset")
    if finding.environment.lower() == "production":
        score_value += 10
        rationale.append("production environment")
    criticality = finding.asset_criticality.lower()
    score_value += CRITICALITY_WEIGHT.get(criticality, 7)
    rationale.append(f"asset_criticality={criticality}")
    if finding.fixed_versions:
        score_value += 5
        rationale.append("fixed version available")
    score_value = min(score_value, 100)
    priority = (
        "P1"
        if score_value >= 75
        else "P2"
        if score_value >= 55
        else "P3"
        if score_value >= 30
        else "P4"
    )
    finding.risk_score = score_value
    finding.priority = priority
    finding.rationale = rationale
    return finding


def prioritise(
    findings: list[Finding],
    *,
    environment: str,
    asset_criticality: str,
    internet_exposed: bool,
) -> list[Finding]:
    for finding in findings:
        finding.environment = environment
        finding.asset_criticality = asset_criticality
        finding.internet_exposed = internet_exposed
        score(finding)
    return sorted(findings, key=lambda item: (-item.risk_score, item.component, item.finding_id))
