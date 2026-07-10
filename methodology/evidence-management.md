# Evidence management

Evidence should allow an independent reviewer to reproduce a claim. Store the
command, tool/version, timestamp, input scope, output digest, result and reviewer.
Do not commit credentials, customer data or unredacted production findings.

Evidence freshness is part of the control: stale scan output or an expired risk
acceptance is an open governance issue even when the underlying file still exists.
