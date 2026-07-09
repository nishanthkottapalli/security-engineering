# False-Positive Management

False-positive management is part of detection engineering. A detection that cannot be tuned will either overwhelm analysts or be ignored.

## Principles

1. Tune with evidence, not assumptions.
2. Prefer scoped suppressions over broad exclusions.
3. Document the reason for every threshold or allowlist.
4. Do not suppress high-impact behaviours without compensating monitoring.
5. Revisit suppressions periodically.

## False-positive categories

| Category | Description | Example |
| --- | --- | --- |
| benign user behaviour | legitimate mistakes or retries | user forgot password |
| administrative activity | expected operations by IT or security teams | helpdesk testing SSH access |
| scanner noise | approved vulnerability or compliance scanning | scanner testing SSH credentials |
| infrastructure aggregation | many users appearing behind one source | NAT, VPN, bastion host |
| lab or test activity | approved detection validation | controlled Hydra test |

## Tuning controls

Tuning may include:

- threshold adjustment
- time-window adjustment
- grouping-key adjustment
- asset criticality enrichment
- user privilege enrichment
- source IP allowlist
- scanner suppression
- scheduled testing suppression
- severity downgrading with explicit context

## Tuning record template

```yaml
tuning_decision:
  detection_id: DET-LINUX-SSH-001
  date: 2026-07-09
  change: suppress approved scanner IP 10.0.10.25
  reason: scanner generates repeated failed SSH attempts during weekly assessment
  risk: may hide malicious activity if scanner host is compromised
  compensating_control: monitor scanner host authentication and outbound connections
  review_date: 2026-10-09
```

## SSH brute-force considerations

Expected false positives:

- user forgot password and later logged in successfully
- password manager retry behaviour
- administrator testing access
- vulnerability scanner
- NAT or VPN source aggregation
- bastion-host activity

Recommended approach:

- keep high severity when success follows failures
- suppress only approved scanner IPs or test accounts
- increase severity for privileged accounts and production systems
- create a separate detection for distributed password spraying
