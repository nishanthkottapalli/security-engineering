# detection-engineering
> This repository demonstrates detection engineering as a repeatable security capability

The first completed capability package focuses on SSH brute-force activity against a Linux host monitored by Wazuh. The lab validates both low-level authentication failure alerts and higher-confidence correlation alerts where repeated failures are followed by a successful login. This pattern is stronger than failed logins alone because it indicates probable valid-account compromise.


## Model

Detection engineering in this repository follows this lifecycle:

```text
Threat hypothesis
    ↓
Telemetry requirements
    ↓
Detection design
    ↓
Detection implementation or platform validation
    ↓
Positive and negative test cases
    ↓
Validation evidence
    ↓
False-positive tuning
    ↓
SOC response runbook
    ↓
Lifecycle review and coverage tracking
```

## Capability packages

| Detection package | Domain | Primary behaviour | Platform | MITRE | Status |
| --- | --- | --- | --- | --- | --- |
| [SSH brute force followed by successful login](detections/linux/ssh/ssh-bruteforce-followed-by-success/) | Linux / SSH | Repeated authentication failures followed by success | Wazuh validated, Sigma draft | T1110, T1110.001, T1078 | Production candidate |

## Validation labs

| Lab | Focus | Platform | Evidence | Status |
| --- | --- | --- | --- | --- |
| [01 Wazuh SSH Brute Force](labs/01-wazuh-ssh-bruteforce/) | End-to-end validation of SSH brute-force detection and compromise correlation | Wazuh 4.14.6 | Screenshots and analyst report | Complete |

## Methodology

| Document | Purpose |
| --- | --- |
| [Detection lifecycle](methodology/detection-lifecycle.md) | Defines how detections move from hypothesis to maintained control |
| [Telemetry requirements](methodology/telemetry-requirements.md) | Defines required log sources, fields, parsers, and failure modes |
| [Severity and confidence model](methodology/severity-confidence-model.md) | Separates business impact from evidence confidence |
| [False-positive management](methodology/false-positive-management.md) | Defines how tuning decisions are documented and controlled |
| [MITRE mapping standard](methodology/mitre-mapping-standard.md) | Defines how ATT&CK mappings are chosen and justified |

## Current capability status

The repository currently contains one completed validation lab and one corresponding detection package. The initial focus is Linux authentication telemetry and Wazuh correlation behaviour. Future packages should extend the same lifecycle to identity, endpoint, network, cloud, and SaaS telemetry.


## Notes

- Threat hypothesis
- Telemetry requirements
- Attack simulation
- Detection logic
- Detection validation
- MITRE mapping
- False-positive analysis
- Response runbooks
- Detection lifecycle management
