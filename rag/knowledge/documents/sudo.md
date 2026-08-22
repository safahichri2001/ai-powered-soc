# Sudo and Privilege Escalation

Sudo allows a user to execute commands with elevated privileges.

A successful sudo event is not automatically malicious.
The security significance depends on the user, command, timing, context, and authorization.

Relevant investigation questions:

- Which user invoked sudo?
- Which target account was used?
- What command was executed?
- Is the user authorized to perform the action?
- Did the event occur after a suspicious login?
- Are there related authentication or process events?