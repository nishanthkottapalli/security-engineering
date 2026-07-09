# Severity and Confidence Model

Severity and confidence should be treated separately.

Severity describes the potential impact of the behaviour. Confidence describes how strongly the available evidence supports the conclusion.

## Severity

| Severity | Meaning | Example |
| --- | --- | --- |
| Low | Suspicious or informational, low immediate risk | isolated failed login |
| Medium | Potential attack activity, no confirmed impact | repeated failed SSH attempts without success |
| High | Strong attack signal or likely compromise | repeated failures followed by successful login |
| Critical | Confirmed or high-impact compromise path | privileged account compromise on production host |

## Confidence

| Confidence | Meaning | Example |
| --- | --- | --- |
| Low | Weak or incomplete evidence | missing source IP or username |
| Medium | Suspicious pattern but benign explanations are plausible | repeated failures from one IP |
| High | Multiple related signals support the finding | failures followed by success for same user/IP/host |
| Very high | Follow-on activity confirms malicious use | successful login followed by privilege escalation or persistence |

## Applying the model

A detection can be high severity but medium confidence if the potential impact is large but the evidence is incomplete. A detection can be medium severity but high confidence if the behaviour is clearly suspicious but not yet a confirmed compromise.

For SSH brute force followed by successful login:

- repeated failures only: medium severity, medium confidence
- repeated failures followed by success: high severity, high confidence
- repeated failures followed by success on a privileged production account: critical severity, high confidence
- repeated failures followed by success and suspicious post-login commands: critical severity, very high confidence

## Escalation factors

Increase severity when:

- the account is privileged
- the destination host is production or internet-facing
- the source IP is external or known malicious
- the login occurs outside normal business hours
- successful login is followed by sudo, data access, persistence, or lateral movement

Reduce severity or confidence only when there is documented context such as approved testing, known scanners, or expected administrative behaviour.
