# Incident Report: RDP Brute-Force and Account Compromise (`tsmith`)

**Analyst:** Corey Bigby | **Environment:** SOC Home Lab (`Superbee.local`) | **Date:** 2026-11-10
**Severity:** High | **Status:** Closed (simulated attack, lab environment) | **Classification:** True Positive

---

## 1. Summary
An attacker at **192.168.10.250** ran an automated RDP password-guessing attack (brute force) against the domain account **`tsmith`** on the Windows 11 host **192.168.10.100**. The attack recovered the account's password on **attempt 21 of a 24-password list**, and the attacker then logged in interactively over RDP. Splunk captured the burst of failed logons (Event ID **4625**) followed by a successful logon (Event ID **4624**) from the same source, confirming the account was compromised.

## 2. Timeline
*Times are from the attacker VM's clock and Splunk event timestamps (lab time, 2026-11-10).*

| Time | Event | Source |
|---|---|---|
| ~03:10 | Attacker prepares the `rockyou`-derived wordlist and targets `tsmith` over RDP (port 3389) | Kali terminal |
| 03:10:55 – 03:11:17 | RDP session established with `xfreerdp` as `SUPERBEE\tsmith` (credential validation) | xfreerdp log |
| ~03:11 – 03:17 | `hydra` runs 4 parallel RDP login attempts against `tsmith`; failed attempts generate Event ID 4625 | hydra output / Splunk |
| 03:17:18 | `hydra` finishes: valid password found for `tsmith` (attempt 21 of 24) | hydra output |
| After 03:17 | Successful logon (Event ID 4624) for `tsmith` from 192.168.10.250 | Splunk |

## 3. Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| Attacker IP | `192.168.10.250` (Kali Linux) |
| Target host / IP | Windows 11 client, `192.168.10.100` |
| Compromised account | `SUPERBEE\tsmith` |
| Protocol / port | RDP, TCP 3389 |
| Tools | `hydra` (brute force), `xfreerdp` (interactive RDP login) |
| Event IDs | 4625 (failed logon burst) → 4624 (successful logon) |
| MITRE ATT&CK | **T1110: Brute Force**, T1021.001: Remote Services: RDP, T1078: Valid Accounts |

## 4. Detection and Analysis
**Detection query (failed-logon burst):**
```spl
index=endpoint EventCode=4625 user=tsmith
| stats count by Account_Name, host, src_ip
| where count >= 5
```

**Confirmation query (successful logon after the burst):**
```spl
index=endpoint EventCode=4624 user=tsmith
| table _time, Account_Name, host, src_ip, Logon_Type
```

**Findings**
- Splunk recorded **87 authentication-related events** tied to `tsmith` during the attack window.
- Many 4625 failures for one account from one source IP in a short period, followed by a 4624 success from the **same IP**, is the classic brute-force pattern.
- The domain controller's authentication mix during the window (4624: 34, 4634: 34, 4769: 9, 4768: 6, 4776: 4) shows the Kerberos and NTLM activity that came with the logons.
- **Verdict: True Positive.** The account's password was guessed and used to log in.

## 5. Impact
- **Account:** `tsmith` is compromised. The attacker had valid domain credentials and an interactive session on the target host.
- **Exposure:** RDP was reachable from an untrusted host with **no account lockout policy**, and the password was weak enough to appear in a common wordlist.
- **Scope:** Lab only. No real systems or data were involved.

## 6. Response
1. **Contain:** Disable or reset `tsmith`, end any active RDP sessions, and block `192.168.10.250` at the host firewall.
2. **Investigate:** Review all 4624 logons for `tsmith` after 03:17 for follow-on activity (new processes, account changes, lateral movement).
3. **Recover:** Set a strong, unique password and re-enable the account once verified clean.

## 7. Recommendations
- **Account lockout policy:** lock an account after 5–10 failed attempts. This alone would have stopped this attack.
- **MFA** for remote access, especially RDP.
- **Restrict RDP:** allow it only from approved management IPs (firewall or network rules), or put it behind a VPN.
- **Stronger password policy:** longer passphrases, and block passwords found in common breach lists.
- **Alerting:** turn the 4625 query into a scheduled Splunk alert (for example, 5 or more failures for one account in 5 minutes).

---

## Additional Finding: Detection Gap (Atomic Red Team)
| Test | Result in Splunk |
|---|---|
| **T1136.001-9**: Create a new Windows admin user via .NET | Ran successfully (`NewLocalUser` created, added to Administrators, then deleted) |
| **T1059.001-22**: SOAPHound build cache (PowerShell) | **Not detected**: no events in Splunk |

**Why the PowerShell test was missed:**
1. **PowerShell script-block logging (Event ID 4104) is turned off**, so PowerShell activity like this isn't logged.
2. The test also **failed to reach a domain controller**. It used its default target (`10.0.1.14:9389`, which isn't in this lab) and got "connection refused."

**Follow-up:** turn on script-block logging (Group Policy → Administrative Templates → Windows Components → Windows PowerShell), re-run the test pointed at the real DC (`192.168.10.7`), and confirm Event ID 4104 appears in Splunk.

**Lesson:** a technique can run without producing any alertable logs. Testing your detections means checking for what *didn't* alert, not just what did.
