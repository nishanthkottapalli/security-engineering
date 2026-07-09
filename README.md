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

- Threat hypothesis
- Telemetry requirements
- Attack simulation
- Detection logic
- Detection validation
- MITRE mapping
- False-positive analysis
- Response runbooks
- Detection lifecycle management
