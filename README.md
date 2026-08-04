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

## Rules (14)

| ID | Rule | Log source | MITRE ATT&CK | Severity |
|----|------|-----------|--------------|----------|
| `LTR-0011` | [Detect SSH Brute Force and User Enumeration in Linux auth.log](https://logtriage.app/rules/authlog-ssh-brute-force/) | Linux auth.log / secure | T1110.001, T1110.003, T1078 | high |
| `LTR-0004` | [Detect Legacy-Auth MFA Bypass in Azure AD Sign-In Logs](https://logtriage.app/rules/azure-legacy-auth-mfa-bypass/) | Azure AD Sign-In Logs | T1078.004, T1556 | high |
| `LTR-0010` | [Detect Path Traversal & Sensitive-File Recon in Cloudflare Logs](https://logtriage.app/rules/cloudflare-path-traversal-recon/) | Cloudflare Logs | T1190, T1083, T1595.001 | high |
| `LTR-0002` | [Detect IAM Privilege Escalation in AWS CloudTrail](https://logtriage.app/rules/cloudtrail-iam-privilege-escalation/) | AWS CloudTrail | T1098, T1078.004, T1484 | high |
| `LTR-0013` | [Detect MFA Fatigue and Bypass Abuse in Duo Security Logs](https://logtriage.app/rules/duo-mfa-fatigue-bypass/) | Duo Security | T1621, T1078.004, T1556.006 | critical |
| `LTR-0008` | [Detect IAM Privilege Escalation in GCP Cloud Audit Logs](https://logtriage.app/rules/gcp-iam-privilege-escalation/) | GCP Cloud Audit Log | T1098, T1078.004 | high |
| `LTR-0014` | [Detect GitHub Organization Takeover and Backdooring in Audit Logs](https://logtriage.app/rules/github-audit-org-takeover/) | GitHub Audit Log | T1098, T1195.002, T1562.001, T1537 | critical |
| `LTR-0009` | [Detect Kubernetes Secret Exfiltration in Audit Logs](https://logtriage.app/rules/k8s-secret-exfiltration/) | Kubernetes Audit Log | T1552.007, T1078 | high |
| `LTR-0006` | [Detect Business Email Compromise via Malicious Inbox Rules (Microsoft 365)](https://logtriage.app/rules/m365-bec-inbox-rule/) | Microsoft 365 Unified Audit Log | T1114.003, T1564.008 | high |
| `LTR-0001` | [Detect Credential Stuffing Against Authentication Endpoints (nginx / web logs)](https://logtriage.app/rules/nginx-credential-stuffing/) | nginx / Apache access logs | T1110.004, T1110.001 | high |
| `LTR-0007` | [Detect Credential Stuffing in Okta System Log](https://logtriage.app/rules/okta-credential-stuffing/) | Okta System Log | T1110.004, T1110.001 | high |
| `LTR-0003` | [Detect LSASS Credential Dumping with Sysmon](https://logtriage.app/rules/sysmon-lsass-credential-dumping/) | Microsoft Sysmon | T1003.001, T1055 | critical |
| `LTR-0005` | [Detect Port Scanning in AWS VPC Flow Logs](https://logtriage.app/rules/vpc-flow-port-scanning/) | AWS VPC Flow Logs | T1046, T1595.001 | medium |
| `LTR-0012` | [Detect Windows Password Spraying with Event ID 4625](https://logtriage.app/rules/windows-4625-password-spray/) | Windows Event Log | T1110.003, T1110.001, T1078.002 | high |

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

Maintained by [LogTriage](https://logtriage.app). Generated 2026-08-04.
