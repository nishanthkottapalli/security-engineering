from pathlib import Path

from secops_lab.triage.engine import deduplicate, prioritise
from secops_lab.triage.parsers import parse_file
from secops_lab.triage.reporting import write_reports

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_scanner_results_are_normalised_deduplicated_and_prioritised(tmp_path: Path) -> None:
    findings = []
    for relative in [
        "pip_audit/pip-audit.json",
        "trivy/trivy.json",
        "grype/grype.json",
        "checkov/checkov.json",
    ]:
        findings.extend(parse_file(FIXTURES / relative))
    normalised = prioritise(
        deduplicate(findings),
        environment="production",
        asset_criticality="high",
        internet_exposed=True,
    )
    assert normalised
    assert normalised[0].priority in {"P1", "P2"}
    requests = [item for item in normalised if item.component == "requests"]
    assert len(requests) == 1
    assert sorted(requests[0].sources) == ["grype", "pip-audit", "trivy"]
    write_reports(normalised, tmp_path)
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "findings.csv").exists()
