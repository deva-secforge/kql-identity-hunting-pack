# KQL Identity Threat Hunting Pack

KQL hunting queries for Microsoft Sentinel and Microsoft Defender XDR, each written from an attack I investigated or defended against in production: device code phishing, cross-tenant Teams help desk impersonation, OAuth consent abuse, attacker-registered MFA methods, password spray, macro-launched PowerShell and anti-forensic log deletion on Linux.

Every query maps to MITRE ATT&CK and comes with tuning notes and a triage playbook: what to check, when it closes, when it escalates. Every push is validated against the table schemas with the Kusto.Language parser in GitHub Actions, with the actions pinned to commit SHAs.

## Coverage

| # | Query | Data source | ATT&CK | Investigation it came from |
|---|---|---|---|---|
| 01 | Device code flow sign-ins | Sentinel: SigninLogs, AADNonInteractiveUserSignInLogs | T1528, T1566.002 | Audited sign-in logs by protocol and original transfer method before enforcing a tenant-wide device code block |
| 02 | Teams help desk impersonation from a first-seen tenant | Defender XDR: CloudAppEvents | T1566.003, T1656 | Cross-tenant "Maintenance Service" 1:1 Teams chat surfaced by an MDR threat hunt (Storm-1811 style) |
| 03 | High-privilege OAuth consent | Sentinel: AuditLogs | T1528, T1550.001 | Enterprise app admin consent review mapping each delegated permission to a control |
| 04 | Auth method change near a risky sign-in | Sentinel: AuditLogs, SigninLogs | T1098.005, T1556.006 | Sign-in anomaly traced to an SSPR email method stored outside the directory mail attributes |
| 05 | Password spray with any success | Sentinel: SigninLogs | T1110.003 | Service account policy: block at high risk so a sprayed password cannot be used to enroll a method |
| 06 | Office spawns encoded or bypass PowerShell | Defender XDR: DeviceProcessEvents | T1204.002, T1059.001, T1027 | Malicious-macro mitigation pilot and a detect-only macro case with a PowerShell child |
| 07 | Linux security log and shell history tampering | Defender XDR: DeviceProcessEvents | T1070.002, T1070.003, T1562.001 | Root session that deleted EDR logs and edited shell history, kept open as a high-risk case |

## Triage playbooks

**01 Device code flow.** Check: is the app on the approved list (meeting room devices, CLIs)? Is the sign-in from the user's usual country and ASN? Did a non-interactive refresh follow from a different IP? Close when a known device or tool is confirmed with the user. Escalate when the IP or country is new, a refresh follows from a different IP, or the user does not recall entering a code. Contain by revoking sessions (`Revoke-MgUserSignInSession`) and reviewing mailbox rules.

**02 Teams impersonation.** Check: the external tenant's display name and creation pattern (fresh onmicrosoft.com), whether the target accepted the chat, and whether screen sharing, Quick Assist or a remote tool followed on the endpoint. Close when the tenant is a validated vendor with a business owner. Escalate when the sender poses as IT or help desk, or when any remote access tool runs on the target within 24 hours. Block the tenant now; the structural fix is an allow-list external access policy.

**03 OAuth consent.** Check: the publisher (verified or not), the reply URLs, who consented, and whether the app is used by more than one user. Close when the publisher is verified, a business owner is named and the scopes are least privilege. Escalate on an unverified publisher with mail or file scopes, or a consent from a risky sign-in. Contain by disabling the service principal and revoking its grants.

**04 Auth method change.** Check: was the method added from the same IP as the risky sign-in, and is the new method an external email or phone the user does not own? Close when the user confirms the change through an out-of-band channel. Escalate when the change IP matches the risky sign-in IP (`SameIP > 0`). Contain by deleting the method, resetting the password and revoking sessions.

**05 Password spray.** Check: the source ASN (hosting or residential proxy), the user agent, and `AnySuccess`. Close when the source is a misconfigured internal service. Escalate on any success from the spraying IP. Contain by resetting succeeded accounts, blocking the source and checking for legacy authentication paths.

**06 Office to PowerShell.** Check: decode the encoded command, read what the child does, and see whether a network connection or file write followed. Known false positive: document preview and PDF rendering helpers. Close when the child's purpose is confirmed benign. Escalate on any download cradle, base64 payload or outbound connection. Contain by isolating the device.

**07 Linux log tampering.** Check: who owns the root session (sudo source, SSH key, change ticket), what was deleted, and whether agent health dropped afterwards. Close only with a matching change record and a named operator. Escalate otherwise. Preserve the remaining logs and the host image before any cleanup.

## Run and validate

```bash
npm install
npm run validate        # semantic check of every query against the expected table schemas
```

Paste a query into Microsoft Sentinel (Logs) or Defender XDR (Advanced hunting). The tuning constants are at the top of each query (`lookback`, `approvedApps`, `minUsers`, `lureTerms`).

Schema notes: `LocationDetails` is dynamic in `SigninLogs` but a string in `AADNonInteractiveUserSignInLogs`, so query 01 parses it in each leg before the union. `OriginalTransferMethod` is read with `column_ifexists` because not every workspace has it yet.

Before the first push, move `ci/validate.yml` to `.github/workflows/validate.yml` so GitHub runs the check on every push.

## Disclaimer

For environments you own or are authorized to monitor. The queries read telemetry only.
