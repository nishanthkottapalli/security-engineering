# MITRE ATT&CK Mapping Standard

MITRE ATT&CK mapping should explain the adversary behaviour being detected. It should not be added only as a label.

## Mapping principles

1. Map to the behaviour, not the tool.
2. Prefer the most specific technique or sub-technique available.
3. Separate primary mappings from supporting mappings.
4. Include evidence for each mapping.
5. Avoid over-mapping unrelated tactics.

## Primary and supporting mappings

A primary mapping is the main attacker behaviour the detection is designed to identify.

A supporting mapping is relevant context but not the main detection objective.

For SSH brute force followed by success:

Primary mappings:

- T1110 Brute Force
- T1110.001 Password Guessing
- T1078 Valid Accounts

Supporting mapping:

- T1021.004 SSH, when the successful login represents remote access over SSH

## Evidence standard

Each mapping should answer:

- What event or alert proves this behaviour?
- Which fields support the mapping?
- Is this the main detection behaviour or supporting context?

Example:

| Technique | Role | Evidence |
| --- | --- | --- |
| T1110 Brute Force | Primary | repeated SSH/PAM authentication failures |
| T1110.001 Password Guessing | Primary | repeated guesses against user `james` |
| T1078 Valid Accounts | Primary | successful login after repeated failures |
| T1021.004 SSH | Supporting | access occurred through SSH service |

## Anti-patterns

Avoid:

- mapping every possible tactic mentioned in a vendor rule
- mapping based only on a tool name
- mapping lateral movement when there is only single-host access unless the detection specifically observes movement
- using MITRE tags without explaining why they apply
