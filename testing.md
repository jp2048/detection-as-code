# Rule Validation & Testing

How each rule was (or can be) validated. Where Atomic Red Team (ART) ships an
atomic test for the technique, the expected true-positive evidence is listed.
Exact ART test IDs vary by ART release — validate against the version you run.

## Windows

### Potential LSASS Credential Dumping via Process Access (T1003.001)
- **ART mapping:** T1003.001 atomics, e.g. the *Mimikatz - LogonPasswords* test and
  the *Dump LSASS via Procdump / rundll32* tests.
- **Expected true positive:** Sysmon Event ID 10 with `TargetImage` ending in
  `lsass.exe` and `GrantedAccess` of `0x1010`, `0x1438`, or `0x143a`.
- **Negative control:** normal EDR agent LSASS inspection should hit the
  `filter` block and not alert.

### Suspicious PowerShell Encoded Command or Download Cradle (T1059.001)
- **ART mapping:** T1059.001 atomics, e.g. the *PowerShell - Mimikatz* test and
  download-cradle tests using `IEX` / `Invoke-WebRequest`.
- **Expected true positive:** Sysmon Event ID 1, `Image` `powershell.exe`, with
  `-EncodedCommand` or an `IEX(`/`Net.WebClient` download cradle in
  `CommandLine`.
- **Negative control:** plain interactive PowerShell use with no encoded or
  download-cradle strings should not alert.

### Suspicious Windows Service Installation (T1543.003)
- **ART mapping:** T1543.003 service-persistence atomics, e.g. service creation
  via `sc.exe` or `New-Service` with a binary path in a temp or AppData location.
- **Expected true positive:** Security log Event ID 7045 with `ImagePath`
  containing `\Temp\`, `\AppData\`, or a script interpreter/extension.
- **Negative control:** legitimate software installs registering services from
  `Program Files` should not alert.

### RDP Brute Force Burst (T1110)
- **ART mapping:** T1110 atomics, e.g. the seeded-user credential brute-force test
  run against RDP (LogonType 10).
- **Expected true positive:** >10 Security log Event ID 4625 failures with
  `LogonType: 10` and status `0xC000006D` from one `IpAddress` inside 5 minutes.
- **Negative control:** a handful of mistyped logons stays under the aggregation
  threshold.

## Linux

### Suspicious Cron Persistence Activity (T1053.003)
- **ART mapping:** T1053.003 Linux atomics, e.g. cron persistence tests that write
  to `/etc/cron.d/` or replace the crontab file.
- **Expected true positive:** auditd `PATH` record with `name` under
  `/etc/cron.d/` (or sibling cron paths) from a non-allowlisted `exe`.
- **Negative control:** admin `crontab` edits and package installs shipping cron
  files should be baselined/filtered.

### SSH Authorized Keys File Modification (T1098.004)
- **ART mapping:** T1098.004 atomics, e.g. the SSH authorized-keys addition test
  that appends a key to `~/.ssh/authorized_keys`.
- **Expected true positive:** auditd `PATH` record with `name` ending in
  `/authorized_keys` from a process other than `sshd`.
- **Negative control:** routine sshd reads of the file hit the `filter_sshd_read`
  block and do not alert.

## Cloud

### Anomalous Entra ID Sign-In with Elevated Risk (T1078)
- **ART mapping:** no direct ART atomic — valid-account abuse is scenario-based.
  Validate by replaying a simulated anomalous sign-in (e.g. sign-in from an
  unusual country via VPN) in a lab tenant and confirming Entra ID Protection
  raises `riskState: atRisk` with `unfamiliarFeatures` / `impossibleTravel`.
- **Expected true positive:** sign-in log with `riskState` `atRisk` or
  `confirmedCompromised`.
- **Negative control:** normal sign-ins with `riskState: none` should not alert.

### AWS IAM Privilege Escalation or Root Account Usage (T1136 / T1484)
- **ART mapping:** limited ART cloud coverage; validate with controlled AWS CLI
  calls in a lab account (e.g. `aws iam create-user`, `aws iam attach-user-policy`,
  `aws iam update-assume-role-policy`).
- **Expected true positive:** CloudTrail `CreateUser` / `AttachUserPolicy` /
  `UpdateAssumeRolePolicy` events, or any event with `userIdentity.type: Root`.
- **Negative control:** Terraform/CloudFormation IAM runs from known automation
  roles should be allowlisted.

## General validation workflow

1. `python3 validate.py` — schema and format checks (runs in CI).
2. Convert with pySigma to the target SIEM and deploy in monitor-only mode.
3. Execute the mapped ART atomic (or lab simulation) and confirm a single,
   well-formed alert fires with the expected fields.
4. Run for 7 days, review false positives, tune filters/thresholds, then promote.
