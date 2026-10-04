# MITRE ATT&CK Coverage Matrix

Each rule in this pack mapped to tactic and technique.

| Rule | Tactic | Technique | ATT&CK Link |
|------|--------|-----------|-------------|
| Potential LSASS Credential Dumping via Process Access | Credential Access | T1003.001 — LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| Suspicious PowerShell Encoded Command or Download Cradle | Execution | T1059.001 — PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| Suspicious Windows Service Installation | Persistence, Privilege Escalation | T1543.003 — Windows Service | https://attack.mitre.org/techniques/T1543/003/ |
| RDP Brute Force Burst | Credential Access | T1110 — Brute Force | https://attack.mitre.org/techniques/T1110/ |
| Suspicious Cron Persistence Activity | Persistence, Privilege Escalation | T1053.003 — Cron | https://attack.mitre.org/techniques/T1053/003/ |
| SSH Authorized Keys File Modification | Persistence | T1098.004 — SSH Authorized Keys | https://attack.mitre.org/techniques/T1098/004/ |
| Anomalous Entra ID Sign-In with Elevated Risk | Initial Access | T1078 — Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| AWS IAM Privilege Escalation or Root Account Usage | Persistence, Privilege Escalation | T1136 — Create Account · T1484 — Domain Policy Modification | https://attack.mitre.org/techniques/T1136/ · https://attack.mitre.org/techniques/T1484/ |

## Coverage summary

- **Tactics covered:** Initial Access, Execution, Persistence, Privilege Escalation, Credential Access
- **Techniques covered:** 8 (across Windows, Linux, Azure, and AWS telemetry)
- **Platforms:** Windows (Sysmon + Security/System logs), Linux (auditd), Azure (Entra ID sign-in logs), AWS (CloudTrail)
