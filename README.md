# SOC Home Lab — Active Directory Attack & Detection with Splunk

**By [Corey Bigby](https://www.linkedin.com/in/coreybigby/)**

A home SOC lab that builds a small Active Directory domain, forwards Windows Security and Sysmon logs into Splunk, simulates an RDP brute-force attack and MITRE ATT&CK techniques from Kali Linux, and detects them with SPL. Built to practice the day-to-day work of a Tier 1 SOC analyst: log collection, detection, and investigation.

---

## Architecture

```
                         Internet
                            |
                        [ Router ]
                            |
                        [ Switch ] -------------------- Kali Linux (Attacker)
                         |      |                        192.168.10.250
         ----------------        ----------------
         |                                      |
  Splunk Server                          Windows 11 (Target)
  192.168.10.10                          192.168.10.100
  (Ubuntu 22.04)                         Splunk UF + Sysmon + Atomic Red Team
         |                                      |
  Active Directory DC (ADDC01)  ----------------
  192.168.10.7  (Windows Server 2022)
  Splunk UF + Sysmon
  Domain: Superbee.local
```

| Host | Role | IP | Notes |
|---|---|---|---|
| ADDC01 | Domain Controller (Windows Server 2022) | 192.168.10.7 | AD DS, domain `Superbee.local`, Splunk UF + Sysmon |
| Splunk | SIEM (Ubuntu 22.04) | 192.168.10.10 | Splunk Enterprise, index `endpoint`, receiver on 9997 |
| Target | Windows 11 client | 192.168.10.100 | Domain-joined, Splunk UF + Sysmon + Atomic Red Team |
| Kali | Attacker | 192.168.10.250 | hydra, xfreerdp, rockyou wordlist |

> The lab follows the MyDFIR "Active Directory" project.

---

## What I built

1. **Active Directory** — Installed AD DS on Windows Server 2022, promoted it to a domain controller (`Superbee.local`), and created user **Tom Smith (tsmith)** across **IT** and **HR** organizational units. AD DS provides Kerberos authentication/authorization and a directory of users, computers, and groups.
2. **Log pipeline** — Installed the Splunk Universal Forwarder and Sysmon (Olaf Hartong config) on the DC and the Windows 11 target, forwarding Windows Security, System, Application, and Sysmon Operational logs to the Splunk server's `endpoint` index over port 9997.
3. **Attack simulation** — From Kali, ran an RDP brute-force attack against `tsmith` using hydra and the rockyou wordlist, recovering the password **Bubblegum69**.
4. **Detection & investigation** — Wrote SPL to surface the failed-logon burst (Event ID 4625), confirmed the successful logon that followed, and reviewed the broader authentication event mix on the DC.
5. **MITRE ATT&CK with Atomic Red Team** — Ran atomic tests on the target and checked which ones my logging actually caught, including one that it **did not**.

---

## Detections (SPL)

**Brute force — failed logons for one account (T1110)**
```spl
index=endpoint EventCode=4625 user=tsmith
| stats count by Account_Name, host, src_ip
| where count >= 5
```

**Successful logon after the brute force (true-positive check)**
```spl
index=endpoint EventCode=4624 user=tsmith
| table _time, Account_Name, host, src_ip, Logon_Type
```

**New local admin account created (T1136.001)**
```spl
index=endpoint (EventCode=4720 OR EventCode=4732)
| table _time, Account_Name, Group_Name, host
```

See [`incident-report.md`](incident-report.md) for the full investigation.

---

## Key results

- **4,820** events ingested into the `endpoint` index over a 24-hour window
- **87** authentication-related events tied to `tsmith` during the attack window
- Event ID mix on the DC during the attack: 4624 (34), 4634 (34), 4769 (9), 4768 (6), 4776 (4)
- Brute force recovered the password on attempt **21 of 24** (hydra, rockyou-derived list)
- Atomic test **T1136.001** (create local admin) generated events; **T1059.001 / SOAPHound build-cache** test was **not detected** — a logging gap identified for follow-up

---

## Repo structure

```
soc-home-lab/
├── README.md              ← this file
├── incident-report.md     ← 1-page brute-force incident write-up
└── Screenshots/           ← lab build, attack, and detection images
```

---

## What I learned

- Standing up AD DS and promoting a domain controller, and why domain join needs the client's DNS pointed at the DC.
- Building an end-to-end log pipeline (Sysmon + Universal Forwarder → Splunk index) and verifying events actually arrive.
- Reading Windows authentication events (4624/4625/4634) and Kerberos events (4768/4769/4776) to tell a brute force from normal activity.
- That **detection coverage is not automatic**: a technique can execute successfully and still produce no alertable logs, which is exactly the kind of gap a SOC has to find and close.

---

## Lab hygiene

Everything runs in isolated VirtualBox VMs on a NAT network with no personal data. VMs are snapshotted before each major step and powered off when not in use.

---

*Built by Corey Bigby — [LinkedIn](https://www.linkedin.com/in/coreybigby/)*
