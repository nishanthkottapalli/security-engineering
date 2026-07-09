# Detection Lifecycle

Detection engineering is the process of turning an adversary behaviour into a reliable, testable, tunable, and operational security control. This repository uses the lifecycle below for every detection package.

## 1. Threat hypothesis

A detection starts with a clear hypothesis about attacker behaviour. The hypothesis should state what the attacker is trying to do, which system or identity surface is involved, and why the behaviour matters.

Example:

```text
An attacker may attempt to gain access to a Linux server by repeatedly guessing SSH credentials. If repeated failures are followed by a successful login from the same source IP, username, and destination host, the account should be treated as likely compromised.
```

## 2. Telemetry requirements

Before writing or validating a rule, document the required telemetry. This includes the log source, parser or decoder, required fields, expected event types, and known failure modes.

A detection should not be considered reliable if its required fields are missing, inconsistently parsed, or unavailable on production systems.

## 3. Detection design

The detection design explains the behavioural logic in plain language before encoding it in a SIEM, EDR, Sigma rule, Wazuh rule, query, or correlation pipeline.

The design should capture:

- selection criteria
- thresholds
- time windows
- grouping keys
- severity
- confidence
- expected analyst context

## 4. Implementation or platform validation

Some detections are custom-authored. Others validate native platform content such as Wazuh, GuardDuty, Microsoft Defender, or cloud-native findings. Both are valid detection-engineering activities, but the repository must clearly distinguish between them.

For native platform detections, document which rules fired and what behaviour they represent. For custom detections, include the rule or query artifact.

## 5. Testing

Every detection should include at least one positive test and at least one negative test.

Positive tests prove the detection fires when malicious or suspicious behaviour occurs. Negative tests prove the detection does not fire on common benign patterns.

Minimum expected test coverage:

- positive malicious pattern
- benign typo or operational pattern
- noisy but non-compromise pattern
- missing-success or missing-follow-on condition, where relevant

## 6. Validation evidence

Validation evidence can include screenshots, raw events, alert summaries, command output, lab notes, or exported SIEM records. Evidence should be sufficient for a reviewer to understand what happened without trusting undocumented claims.

## 7. Tuning and false-positive management

Document expected false positives and how the detection should be tuned. Tuning should be explicit and reviewable. Suppressions, allowlists, threshold changes, and severity downgrades should have a reason.

## 8. Response runbook

A detection is only useful if an analyst knows what to do next. Every production-candidate detection should include triage, containment, investigation, recovery, and post-incident actions.

## 9. Lifecycle review

Detections should be reviewed periodically. A review should confirm that telemetry still exists, fields are still parsed correctly, platform rules have not changed, false positives remain acceptable, and the MITRE mapping still matches the behaviour.

## Detection status model

| Status | Meaning |
| --- | --- |
| draft | Detection idea is documented but not implemented or validated |
| experimental | Detection logic exists but requires more testing |
| validated | Detection fired successfully in a controlled lab or test environment |
| production_candidate | Detection has metadata, tuning notes, expected alert, and runbook |
| production | Detection is deployed and monitored in an operational environment |
| deprecated | Detection is no longer recommended or has been replaced |

## Review checklist

A detection package is complete when a reviewer can answer:

1. What behaviour is being detected?
2. Why does the behaviour matter?
3. Which telemetry is required?
4. Which fields are required?
5. What is the detection logic?
6. What alert should be produced?
7. What are the likely false positives?
8. How was the detection tested?
9. What should the analyst do?
10. How is the detection mapped to MITRE ATT&CK?
