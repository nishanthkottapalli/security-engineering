# SSH password guessing followed by successful login

**Detection ID:** `DET-LINUX-SSH-001`  
**Status:** `production_candidate`  
**Platforms:** deterministic Python reference engine and Wazuh 4.14 rule validation  
**Primary ATT&CK:** T1110, T1110.001, T1078  
**Supporting ATT&CK:** T1021.004

## Threat hypothesis

An attacker may repeatedly guess an SSH password and then authenticate with a
valid credential. Five failures followed by a success for the same source IP,
username and destination host inside 120 seconds is materially stronger evidence
than failed authentication alone.

## Detection logic

```text
key = (hostname, username, source_ip)
retain failures for 120 seconds
when a success occurs:
    if failure_count(key) >= 5:
        create high-severity, high-confidence alert
        raise severity to critical for privileged users or production hosts
```

The Python engine is deterministic and is the portable reference
implementation. The Wazuh package validates equivalent decoder and correlation
behaviour with `wazuh-logtest`.

## Run

```bash
make detection-demo
make wazuh-test
```

The first command writes `lab-output/detection-alerts.json`. The second pulls the
pinned Wazuh manager image, loads the custom decoder/rules and replays positive
and negative fixtures through the Wazuh rules engine.

## Required telemetry

See [`telemetry.yml`](telemetry.yml). The detection fails closed when username or
source IP cannot be parsed. A separate detection is required for distributed
password spraying across many source IP addresses.

## Severity and confidence

- failures only: medium severity, medium confidence; this package does not emit a
  compromise alert for this condition
- failures followed by success: high severity, high confidence
- privileged account or production destination: critical severity, high confidence

## Operational status

`production_candidate` means implementation, tests, tuning guidance and a
runbook exist. It does not claim deployment in a maintained customer production
environment.
