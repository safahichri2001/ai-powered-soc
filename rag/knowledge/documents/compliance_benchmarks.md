# CIS Benchmark and Configuration Compliance Alerts

Wazuh's Security Configuration Assessment (SCA) module periodically checks
a host's configuration against benchmarks such as CIS Ubuntu Linux. These
alerts report a configuration finding -- for example, an SSH daemon
setting that does not match the recommended value -- rather than an event
that just occurred.

A compliance alert is not evidence of an ongoing attack. It reflects the
current state of the system's configuration at the time of the scan, and
the same finding will keep re-appearing on every scan until the
configuration is actually changed or the check is explicitly disabled.

Relevant investigation questions:

- Which specific control failed (e.g. MaxAuthTries, permitted ciphers)?
- Is this a new finding, or has it been present since the last scan?
- Does fixing it require a configuration change on this host, or is it
  already covered by a compensating control elsewhere?
- Is the severity level appropriate for a configuration gap rather than an
  active compromise?
