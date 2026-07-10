from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from secops_lab.triage.models import Finding


def _markdown(findings: list[Finding]) -> str:
    by_priority = Counter(item.priority for item in findings)
    by_severity = Counter(item.severity for item in findings)
    lines = [
        "# Vulnerability Triage Report",
        "",
        "## Executive summary",
        "",
        f"- Normalised findings: **{len(findings)}**",
        f"- Priority distribution: **{dict(sorted(by_priority.items()))}**",
        f"- Severity distribution: **{dict(sorted(by_severity.items()))}**",
        "",
        "The priority is risk-based rather than CVSS-only. It combines scanner severity,",
        "known/public exploitation, internet exposure, production context, asset criticality,",
        "and whether a fixed version is available.",
        "",
        "## Remediation backlog",
        "",
        "| Priority | Score | Severity | Component | IDs | Installed | Fixed | Sources |",
        "| --- | ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for item in findings:
        row_template = (
            "| {priority} | {score} | {severity} | `{component}` | {ids} | "
            "{installed} | {fixed} | {sources} |"
        )
        lines.append(
            row_template.format(
                priority=item.priority,
                score=item.risk_score,
                severity=item.severity,
                component=item.component.replace("|", "\\|"),
                ids=", ".join(item.vulnerability_ids),
                installed=item.installed_version or "n/a",
                fixed=", ".join(item.fixed_versions) or "not published",
                sources=", ".join(item.sources),
            )
        )
    lines.extend(["", "## Finding detail", ""])
    for item in findings:
        lines.extend(
            [
                f"### {item.finding_id}: {item.title}",
                "",
                f"- **Priority:** {item.priority} ({item.risk_score}/100)",
                f"- **Component:** `{item.component}`",
                f"- **Vulnerability/control IDs:** {', '.join(item.vulnerability_ids)}",
                f"- **Rationale:** {', '.join(item.rationale)}",
                "",
                item.description.strip(),
                "",
                "**Remediation:** "
                + (
                    f"Upgrade to one of: {', '.join(item.fixed_versions)}."
                    if item.fixed_versions
                    else (
                        "Review vendor guidance, compensating controls, and formal risk acceptance."
                    )
                ),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_reports(findings: list[Finding], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "findings.json").write_text(
        json.dumps([item.to_dict() for item in findings], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(_markdown(findings), encoding="utf-8")
    with (output_dir / "findings.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "finding_id",
                "priority",
                "risk_score",
                "severity",
                "component",
                "installed_version",
                "fixed_versions",
                "vulnerability_ids",
                "environment",
                "asset_criticality",
                "internet_exposed",
                "sources",
                "status",
            ],
        )
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "finding_id": item.finding_id,
                    "priority": item.priority,
                    "risk_score": item.risk_score,
                    "severity": item.severity,
                    "component": item.component,
                    "installed_version": item.installed_version or "",
                    "fixed_versions": ";".join(item.fixed_versions),
                    "vulnerability_ids": ";".join(item.vulnerability_ids),
                    "environment": item.environment,
                    "asset_criticality": item.asset_criticality,
                    "internet_exposed": item.internet_exposed,
                    "sources": ";".join(item.sources),
                    "status": item.status,
                }
            )
