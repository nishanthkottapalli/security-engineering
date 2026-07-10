# False-positive and tuning guidance

Potential benign explanations include a user correcting a forgotten password,
approved access testing, a vulnerability scanner, or many users sharing a NAT or
bastion address.

Tune in this order:

1. Enrich the account and destination with privilege and criticality.
2. Validate whether the source belongs to an approved scanner or bastion.
3. Scope any allowlist to source, account, destination and an expiry date.
4. Prefer a severity downgrade to full suppression where residual risk remains.
5. Revalidate the rule after every parser, OpenSSH or Wazuh upgrade.

Never create an unbounded source-IP allowlist for an internet-facing destination.
