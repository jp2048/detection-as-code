# Detection-as-Code Rules Pack

A portfolio-grade Sigma rule pack demonstrating detection engineering rigor:
version-controlled detections, MITRE ATT&CK mapping, automated validation, and a
documented path from rule to tested SIEM content.

## What is detection-as-code?

Detection-as-code treats security detections like software: rules live in
version control, go through review, are validated automatically (schema,
ATT&CK tags, UUIDs), and are compiled to each SIEM's native query language
from a single Sigma source of truth. One rule, written once, deploys to Splunk,
Microsoft Sentinel, Elastic, and more — with tests proving it fires on real
adversary behavior and stays quiet on benign activity.

## Repository layout

```
detection-as-code/
├── rules/
│   ├── windows/   # Sysmon + Windows Security/System log rules
│   ├── linux/     # Linux auditd rules
│   └── cloud/     # Azure Entra ID + AWS CloudTrail rules
├── validate.py        # rule schema / UUID / ATT&CK tag validator
├── attack_matrix.md   # rule → tactic/technique mapping
├── testing.md         # Atomic Red Team validation plan per rule
└── README.md
```

## Rule catalog

| Rule | Platform | Technique | Severity |
|------|----------|-----------|----------|
| Potential LSASS Credential Dumping via Process Access | Windows (Sysmon EID 10) | T1003.001 — LSASS Memory | High |
| Suspicious PowerShell Encoded Command or Download Cradle | Windows (Sysmon EID 1) | T1059.001 — PowerShell | High |
| Suspicious Windows Service Installation | Windows (System EID 7045) | T1543.003 — Windows Service | Medium |
| RDP Brute Force Burst | Windows (Security EID 4625) | T1110 — Brute Force | Medium |
| Suspicious Cron Persistence Activity | Linux (auditd) | T1053.003 — Cron | Medium |
| SSH Authorized Keys File Modification | Linux (auditd) | T1098.004 — SSH Authorized Keys | High |
| Anomalous Entra ID Sign-In with Elevated Risk | Azure (sign-in logs) | T1078 — Valid Accounts | High |
| AWS IAM Privilege Escalation or Root Account Usage | AWS (CloudTrail) | T1136 / T1484 | High |

## Validating rules

```bash
python3 validate.py
```

Checks required Sigma fields, UUID format, ATT&CK tag format
(`attack.tXXXX[.XXX]`), allowed level/status values, and that every detection
block has a condition. Requires PyYAML (`pip install pyyaml`).

## Converting Sigma to SIEM queries

Use [pySigma](https://github.com/SigmaHQ/pySigma) backends to compile any rule
to native queries. Examples:

**Splunk (SPL):**
```bash
pip install pysigma-backend-splunk
python -m sigma convert -t splunk -p splunk_windows \
  rules/windows/win_lsass_process_access.yml
```

**Microsoft Sentinel (KQL):**
```bash
pip install pysigma-backend-microsoft365defender  # or azure sentinel backend
python -m sigma convert -t sentinel \
  rules/windows/win_powershell_encoded_cradle.yml
```

The legacy `sigmac` compiler works the same way for older backends:
```bash
sigmac -t splunk -c splunk_windows rules/windows/win_lsass_process_access.yml
```

After conversion, deploy in monitor-only mode, run the mapped Atomic Red Team
test from `testing.md`, and confirm exactly one well-formed alert fires.

## Contributing

1. One technique per rule; keep detection logic focused.
2. Every rule needs: `title`, UUID `id`, `status`, `description`, `author`,
   `logsource`, `detection` with `condition`, `falsepositives`, `level`,
   `tags` (tactic + `attack.tXXXX[.XXX]`), and `references`.
3. Include a `filter` block for known-benign activity — document why.
4. Add the rule to the catalog table above and `attack_matrix.md`.
5. Add a validation plan to `testing.md` (ART atomic + expected evidence).
6. Run `python3 validate.py` — it must pass before merge.

## Roadmap

- [ ] SigmaHQ-style `date`/`modified` hygiene automation via CI
- [ ] Expand Linux coverage: container escape (T1611), sudo abuse (T1548.003)
- [ ] Expand cloud coverage: Azure PIM role activation abuse, AWS STS token theft
- [ ] Add pySigma conversion smoke tests in CI (compile every rule to SPL + KQL)
- [ ] MITRE ATT&CK Navigator layer export for visual coverage
- [ ] Correlation rules: LSASS access → suspicious service install chains
