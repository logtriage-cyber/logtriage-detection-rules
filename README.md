# LogTriage Detection Rules

A free, open library of **[Sigma](https://github.com/SigmaHQ/sigma) detection rules** — every rule
is **validated against a real sample log** before it ships: it must fire on a known-malicious sample
and stay silent on the benign one. Each rule is mapped to its log source and MITRE ATT&CK technique,
with false-positive notes.

Full write-ups (detection logic, evidence, FP notes) for each rule live at
**[https://logtriage.app/rules/](https://logtriage.app/rules/)**. Or upload your own logs and let LogTriage detect these
automatically at **[https://logtriage.app](https://logtriage.app)**.

## Why "validated"?

Most rule collections are published untested. Here, a build step confirms each rule's detection
literals actually appear in a real malicious sample (and not in the matching benign sample), so
nothing ships that doesn't provably fire. It's the difference between a paper rule and a working one.

## Rules (28)

| ID | Rule | Log source | MITRE ATT&CK | Severity |
|----|------|-----------|--------------|----------|
| `LTR-0011` | [Detect SSH Brute Force and User Enumeration in Linux auth.log](https://logtriage.app/rules/authlog-ssh-brute-force/) | Linux auth.log / secure | T1110.001, T1110.003 | medium |
| `LTR-0019` | [Detect Web Attack Tools (sqlmap, Nikto, Nmap) in AWS ALB / ELB Access Logs](https://logtriage.app/rules/aws-alb-scanner-scripted-access/) | AWS ALB / ELB | T1595.002, T1190 | medium |
| `LTR-0020` | [Detect CloudTrail Deletion and All-Traffic Security Groups in AWS Config History](https://logtriage.app/rules/aws-config-security-control-tampering/) | AWS Config | T1562.007, T1562.008 | high |
| `LTR-0021` | [Detect Managed Rule Group Exploit Blocks in AWS WAF Logs (SQLi, Log4Shell, XSS)](https://logtriage.app/rules/aws-waf-managed-rule-exploit-block/) | AWS WAF | T1190 | medium |
| `LTR-0022` | [Detect Owner and User Access Administrator Role Assignments in Azure Activity Logs](https://logtriage.app/rules/azure-activity-privileged-role-assignment/) | Azure Activity Log | T1098.003 | high |
| `LTR-0004` | [Detect Legacy-Protocol Sign-Ins With a Correct Password in Entra ID Logs](https://logtriage.app/rules/azure-legacy-auth-mfa-bypass/) | Azure AD Sign-In Logs | T1078.004 | high |
| `LTR-0023` | [Detect Mimikatz Credential Dumping in Carbon Black EDR Process Events](https://logtriage.app/rules/carbonblack-mimikatz-credential-dumping/) | Carbon Black | T1003.001, T1003.006, T1558.001 | critical |
| `LTR-0024` | [Detect Blocked Exploits, Spyware and Malware in Palo Alto PAN-OS CEF Logs](https://logtriage.app/rules/cef-firewall-threat-prevention-block/) | CEF (Common Event Format) | T1190, T1071 | medium |
| `LTR-0025` | [Detect Botnet Traffic Filter Blacklist Hits in Cisco ASA Logs](https://logtriage.app/rules/cisco-asa-botnet-traffic-filter/) | Cisco ASA / FTD | T1071 | high |
| `LTR-0010` | [Detect Path Traversal & Sensitive-File Recon in Cloudflare Logs](https://logtriage.app/rules/cloudflare-path-traversal-recon/) | Cloudflare Logs | T1190, T1595.003 | medium |
| `LTR-0002` | [Detect IAM Privilege Escalation in AWS CloudTrail](https://logtriage.app/rules/cloudtrail-iam-privilege-escalation/) | AWS CloudTrail | T1098, T1078.004, T1484 | high |
| `LTR-0026` | [Detect Encoded PowerShell Commands in CrowdStrike Falcon Process Events](https://logtriage.app/rules/crowdstrike-encoded-powershell/) | CrowdStrike Falcon | T1059.001, T1027.010 | medium |
| `LTR-0027` | [Detect SSH Brute Force Authentication Failures in Linux auditd Logs](https://logtriage.app/rules/detect-ssh-brute-force-in-linux-auditd-logs/) | Linux audit log (auditd) | T1110.001, T1110 | high |
| `LTR-0013` | [Detect MFA Fatigue and Bypass Abuse in Duo Security Logs](https://logtriage.app/rules/duo-mfa-fatigue-bypass/) | Duo Security | T1621, T1078.004, T1556.006 | high |
| `LTR-0008` | [Detect IAM Privilege Escalation in GCP Cloud Audit Logs](https://logtriage.app/rules/gcp-iam-privilege-escalation/) | GCP Cloud Audit Log | T1098, T1078.004 | high |
| `LTR-0014` | [Detect Two-Factor Authentication Being Disabled in GitHub Audit Logs](https://logtriage.app/rules/github-audit-org-takeover/) | GitHub Audit Log | T1556.006 | high |
| `LTR-0017` | [Detect Admin Grants and 2-Step Verification Removal in Google Workspace Audit Logs](https://logtriage.app/rules/google-workspace-admin-takeover/) | Google Workspace | T1098, T1556.006, T1078.004 | high |
| `LTR-0009` | [Detect Kubernetes Secret Exfiltration in Audit Logs](https://logtriage.app/rules/k8s-secret-exfiltration/) | Kubernetes Audit Log | T1552.007, T1078 | high |
| `LTR-0028` | [Detect Mimikatz Credential Dumping in Elastic Common Schema Process Logs](https://logtriage.app/rules/ltr-0028-ecs-credential-dumping/) | Elastic Common Schema | T1003.001, T1003 | critical |
| `LTR-0006` | [Detect Business Email Compromise via Forwarding and Deleting Inbox Rules (Microsoft 365)](https://logtriage.app/rules/m365-bec-inbox-rule/) | Microsoft 365 Unified Audit Log | T1114.003, T1564.008 | high |
| `LTR-0001` | [Detect Credential Stuffing Against Authentication Endpoints (nginx / web logs)](https://logtriage.app/rules/nginx-credential-stuffing/) | nginx / Apache access logs | T1110.004, T1110.001 | high |
| `LTR-0015` | [Detect SQL Injection Probing and sqlmap in nginx Access Logs](https://logtriage.app/rules/nginx-sqli-data-exfiltration/) | nginx / Apache access logs | T1190, T1595.002 | high |
| `LTR-0007` | [Detect Credential Stuffing in Okta System Log](https://logtriage.app/rules/okta-credential-stuffing/) | Okta System Log | T1110.004, T1110.001 | high |
| `LTR-0016` | [Detect Anonymous S3 Object Reads in Server Access Logs](https://logtriage.app/rules/s3-anonymous-access-exfiltration/) | AWS S3 Server Access Logs | T1530 | high |
| `LTR-0003` | [Detect LSASS Credential Dumping with Sysmon](https://logtriage.app/rules/sysmon-lsass-credential-dumping/) | Microsoft Sysmon | T1003.001 | high |
| `LTR-0005` | [Detect Port Scanning in AWS VPC Flow Logs](https://logtriage.app/rules/vpc-flow-port-scanning/) | AWS VPC Flow Logs | T1046, T1595.001 | medium |
| `LTR-0012` | [Detect Windows Password Spraying with Event ID 4625](https://logtriage.app/rules/windows-4625-password-spray/) | Windows Event Log | T1110.003 | high |
| `LTR-0018` | [Detect Web Attack Recon and SQL Injection in Zeek HTTP Logs](https://logtriage.app/rules/zeek-http-web-attack-recon/) | Zeek | T1595.002, T1595.003, T1190 | high |

New rules added regularly. Each `rules/*.yml` is standard Sigma — drop it into your SIEM/converter.

## Usage

```bash
# Convert to your backend with sigma-cli (example: Splunk)
pip install sigma-cli
sigma convert -t splunk rules/nginx-credential-stuffing.yml
```

## Contributing

Spotted a false positive or an improvement? Open an issue or PR. Rules follow the standard Sigma
schema.

## License

Released under the MIT License (see [LICENSE](LICENSE)) — free to use, adapt, and redistribute.

---

Maintained by [LogTriage](https://logtriage.app). Generated 2026-10-27.
