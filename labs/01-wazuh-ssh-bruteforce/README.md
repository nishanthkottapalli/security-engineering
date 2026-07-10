# Lab 01 — Wazuh SSH compromise correlation

This lab replays bounded, synthetic OpenSSH telemetry through two implementations:

1. the deterministic Python reference correlator; and
2. the pinned Wazuh 4.14.6 `wazuh-logtest` rules engine.

No network attack is performed. This makes the demonstration safe, repeatable and
suitable for CI.

```bash
make detection-demo
make wazuh-test
```

Expected outputs:

- `lab-output/detection-alerts.json`
- `lab-output/wazuh-positive.txt`
- `lab-output/wazuh-failures-only.txt`
- `lab-output/wazuh-different-source.txt`

The positive fixture must generate `DET-LINUX-SSH-001` in the Python engine and
Wazuh rule `100111`. The two negative fixtures must not generate the compromise
correlation.
