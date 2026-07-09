# Telemetry Requirements Standard

Telemetry requirements define what data must exist for a detection to work. A detection that does not document its telemetry assumptions is difficult to deploy, test, tune, or troubleshoot.

## Required sections

Each detection package should document the following telemetry sections.

## Log sources

List the exact source systems or event streams required by the detection.

Examples:

- Linux authentication logs
- sshd logs
- PAM authentication logs
- Windows Security Event Log
- Sysmon
- CloudTrail
- GuardDuty findings
- DNS logs
- proxy logs

## Collector or integration

Document how telemetry reaches the detection platform.

Examples:

- Wazuh agent on Linux host
- CloudTrail to S3 and SIEM
- EDR sensor
- Sysmon forwarded through Winlogbeat
- Suricata EVE JSON

## Required fields

List the fields needed for matching, grouping, correlation, severity, and analyst triage.

For SSH brute force, required fields include:

- timestamp
- hostname
- source IP
- username
- authentication result
- service name
- event message
- rule ID or detection ID
- severity level

## Field quality expectations

The detection package should define whether fields must be exact, normalized, enriched, or optional.

Examples:

| Field | Requirement | Reason |
| --- | --- | --- |
| source IP | required | groups repeated attempts and supports containment |
| username | required | identifies targeted account |
| hostname | required | identifies affected asset |
| authentication result | required | distinguishes failure from success |
| user privilege | optional enrichment | increases severity when privileged users are involved |

## Failure modes

Every detection should document how it can fail. Common failure modes include:

- log source disabled
- parser or decoder mismatch
- missing source IP due to proxying or NAT
- hostname mismatch
- clock skew
- event delay
- endpoint not enrolled
- cloud trail not enabled in all regions
- retention too short for investigation

## Coverage boundaries

A telemetry requirement should also state what the detection does not cover.

For example, an SSH brute-force detection grouped by one source IP may not detect distributed password spraying from many IP addresses. That behaviour should be covered by a separate detection.

## Minimum telemetry contract template

```yaml
telemetry:
  sources:
    - linux_auth_logs
    - sshd
    - pam
  collector: wazuh_agent
  required_fields:
    - timestamp
    - hostname
    - source_ip
    - username
    - auth_result
  optional_enrichments:
    - user_privilege
    - asset_criticality
    - source_ip_reputation
  failure_modes:
    - missing_auth_logs
    - missing_source_ip
    - parser_mismatch
    - clock_skew
```
