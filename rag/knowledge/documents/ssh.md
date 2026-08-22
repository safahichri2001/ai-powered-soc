# SSH Security

SSH authentication events should be analyzed using the source IP, destination user,
authentication result, frequency, and temporal context.

A successful SSH authentication is not automatically malicious.
Repeated authentication attempts from an unusual source, access to privileged accounts,
or authentication outside expected patterns may indicate suspicious activity.

Relevant investigation questions:

- What is the source IP?
- Which user authenticated?
- Was the authentication successful or failed?
- Is the source IP expected?
- Are there repeated attempts?
- Does the event correlate with other suspicious activity?