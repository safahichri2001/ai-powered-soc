# Brute Force Detection and Active Response

Repeated authentication failures against the same account or from the same
source, in a short time window, are the primary signal for a brute force
attempt. A single failed login is common and usually not significant; a
cluster of failures, especially against multiple accounts or from an
unfamiliar source, is what raises the concern.

Active Response is Wazuh's mechanism for automatically triggering a script
on the monitored host in reaction to an alert -- for example, isolating
the host from the network by rewriting its firewall rules. It is
disruptive and not easily reversible without direct access to the host,
so it should be reserved for confirmed, high-confidence threats, and a
human should approve it before it runs rather than triggering it
automatically from alert severity alone.

Relevant investigation questions:

- How many failed attempts occurred, over what time window, against how
  many distinct accounts?
- Did any of the attempts succeed?
- Is the source IP already known to be hostile (internal test host,
  external scanner, etc.)?
- Does isolating the host outweigh the cost of losing connectivity to it,
  given what is currently known?
