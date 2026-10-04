# PCI DSS v4.0 Requirement 1 — Summary (paraphrased)

> Paraphrased summary for review context. Consult the official PCI DSS v4.0 standard for authoritative text.

## PCI DSS v4.0 Req. 1.2 Network security controls are configured and maintained
Related checks: RG-012, RG-013, RG-014, RG-016
Configuration standards for network security controls are defined and maintained. All changes to network
connections and NSC configurations are approved and managed through the change control process. All services,
protocols and ports allowed are identified, approved and have a defined business need. NSC rulesets are
reviewed at least every six months.

## PCI DSS v4.0 Req. 1.3 Network access to and from the CDE is restricted
Related checks: RG-001, RG-002, RG-003, RG-016 (zones pci, pci-cde, cde)
Inbound and outbound traffic for the CDE is restricted to only that which is necessary; all other traffic is
specifically denied. Wireless networks are not connected to the CDE without controls.

## PCI DSS v4.0 Req. 1.4 Connections between trusted and untrusted networks are controlled
Related checks: RG-003, RG-010
NSCs are implemented between trusted and untrusted networks. Inbound traffic from untrusted networks is
restricted to system components that provide authorized publicly accessible services. Anti-spoofing measures
are implemented. System components that store cardholder data are not directly accessible from untrusted networks.

## PCI DSS v4.0 Req. 10.2 Audit logs
Related checks: RG-009
Audit logs are enabled and active for all system components and cardholder data, capturing events needed to
detect anomalies and support forensic analysis.

## CIS Control 12.2 Secure network architecture
Related checks: RG-011, RG-016 (zone mgmt)
Establish and maintain a secure network architecture, including segmentation and least privilege; administer
infrastructure through dedicated management networks.
