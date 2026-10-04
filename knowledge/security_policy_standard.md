# SEC-STD-FW — Internal Firewall Security Standard (sample)

> Sample internal standard for RuleGate demos. Replace with your organization's approved standard.
> Each section lists the RuleGate checks it relates to.

## SEC-STD-FW 2.1 Least privilege
Related checks: RG-001, RG-002, RG-004, RG-005
Every permit rule must name specific sources, destinations and services. `any` is prohibited in source,
destination or service of a permit rule unless approved by the Security Architecture board. Address scopes
broader than /16 (IPv4) or /48 (IPv6) require documented justification. On Palo Alto firewalls, permit rules
must use App-ID with `application-default` where the application is identifiable.

## SEC-STD-FW 2.2 Inspection
Related checks: RG-006, RG-007, RG-008
All permit rules must apply threat inspection: the `Strict-Inspection` Security Profile Group on PAN-OS, and an
Intrusion Policy (plus a File Policy for HTTP, FTP, SMB and SMTP) on Cisco FTD. FTD Trust actions and Prefilter
Fastpath rules require a documented performance exception, reviewed every 90 days.

## SEC-STD-FW 2.3 Logging
Related checks: RG-009
All permit and deny rules must log at session end and forward to the central SIEM. Logging may not be disabled
on any rule that crosses a trust boundary.

## SEC-STD-FW 2.4 Secure protocols
Related checks: RG-010
Telnet and FTP are prohibited. Cleartext HTTP and SMB from untrusted zones are prohibited. Use SSH, SFTP,
HTTPS and SMB3 within an encrypted tunnel.

## SEC-STD-FW 2.5 Inbound access from untrusted networks
Related checks: RG-003
Inbound access from the internet or partner networks must terminate in a DMZ, be restricted to known partner
source addresses, and apply full inspection. Direct inbound access to internal zones is prohibited.

## SEC-STD-FW 3.1 Change records
Related checks: RG-012
Every rule must reference a change ticket, a named requester and a business justification. Temporary access
must carry an expiry date of no more than 30 days and is removed automatically on expiry.

## SEC-STD-FW 3.2 Rulebase hygiene
Related checks: RG-013, RG-014, RG-015
Requests for access that already exists are closed as duplicates. New rules must not be shadowed and must not
be placed above explicit deny rules they overlap; such placements require a policy exception from Security
Architecture. Disabled rules older than 90 days are removed at the quarterly recertification.

## SEC-STD-FW 4.1 Cardholder data environment
Related checks: RG-016 (zones pci, pci-cde, cde)
Traffic into or out of the CDE is limited to documented business need, specific hosts and ports, with full
inspection and logging. CDE changes require sign-off from the PCI compliance owner.

## SEC-STD-FW 4.2 Management plane
Related checks: RG-011, RG-016 (zone mgmt)
Management protocols (SSH, RDP, SNMP, HTTPS management interfaces) are reachable only from the management zone
and PAM jump hosts.

## SEC-STD-FW 4.3 Operational technology
Related checks: RG-016 (zone ot)
Access into OT zones follows the IEC 62443 zone-and-conduit model and requires OT security owner approval.
