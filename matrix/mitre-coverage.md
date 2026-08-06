# MITRE ATT&CK Coverage Map & Detection Roadmap

Self-derived detection candidate list, built by walking the full ATT&CK
Enterprise matrix (15 tactics) and filtering each technique against this
environment: two Windows Server 2016 endpoints (one running a database engine),
RDP-accessible, internal network behind a Sophos XG firewall. Telemetry: default
Windows event logs + Sysmon + PowerShell Script Block Logging (4104) + audit
policy. No network IDS (Suricata) yet.

> Sanitized. Real IPs/hostnames masked with `XXX`.

## How this list was built (repeatable procedure)
1. Walk the ATT&CK tactics from Initial Access through Impact (Reconnaissance and
   Resource Development happen off our systems and are not endpoint-detectable).
2. Under each tactic, keep only techniques that are (a) relevant to a Windows
   server role, (b) detectable with telemetry we actually collect, and (c)
   reasonably likely / damaging.
3. Deduplicate overlaps (many techniques appear under several tactics).
4. Prioritize by value-and-detectability to get a build order.

Legend: [x] built · [~] built, needs live-fire validation · [ ] planned gap

---

## Priority build order

### Tier 1 — highest value, telemetry ready, build first
| # | Detection | Technique | ID | Tactic(s) | Telemetry | Status |
|---|-----------|-----------|----|-----------|-----------|--------|
| 1 | Brute force (remote failed logons) | Brute Force | T1110 | Initial/Cred Access | 4625 logon type 3/10 | [~] rule 100201 |
| 2 | Malicious PowerShell (encoded / download cradle) | Command & Scripting Interpreter: PowerShell | T1059.001 | Execution | PowerShell 4104 | [ ] |
| 3 | Credential dumping (LSASS memory access) | OS Credential Dumping: LSASS | T1003.001 | Credential Access | Sysmon ID 10 (ProcessAccess) | [ ] |
| 4 | Clear Windows event logs | Indicator Removal: Clear Event Logs | T1070.001 | Stealth | Event 1102 | [ ] |
| 5 | Disable security tools / services (AV, Defender, agent) | Impair Defenses: Disable Tools | T1562.001 | Defense Impairment | Service-stop / registry | [ ] |
| 6 | Ransomware: shadow-copy / backup deletion (early warning) | Inhibit System Recovery | T1490 | Impact | Sysmon cmdline (vssadmin) | [ ] |

### Tier 2 — high value, build next
| # | Detection | Technique | ID | Tactic(s) | Telemetry | Status |
|---|-----------|-----------|----|-----------|-----------|--------|
| 7 | Masquerading (system name from wrong path) | Masquerading | T1036 | Stealth | Sysmon ID 1 (image path) | [ ] |
| 8 | Suspicious process lineage (e.g. DB/web app spawns shell) | Command & Scripting Interpreter | T1059 | Execution | Sysmon ID 1 (parent/child) | [ ] |
| 9 | New account creation (esp. admin) | Create Account | T1136 | Persistence | Event 4720 | [ ] |
| 10 | Abnormal privileged logon (unexpected account) | Valid Accounts / Token abuse | T1078 / T1134 | Priv Esc | Event 4672 + baselined admins | [ ] |
| 11 | New / suspicious service creation | Create or Modify System Process | T1543.003 | Persist/Exec/PrivEsc | Event 7045 / Sysmon | [ ] |
| 12 | Scheduled task creation | Scheduled Task/Job | T1053.005 | Persist/Exec | Audit / Sysmon | [ ] |
| 13 | Ransomware: mass rapid file changes | Data Encrypted for Impact | T1486 | Impact | FIM (syscheck) | [ ] |
| 14 | LOLBins (rundll32/mshta/regsvr32 abuse) | System Binary Proxy Execution | T1218 | Stealth | Sysmon cmdline | [ ] |

### Tier 3 — useful, build later
| # | Detection | Technique | ID | Tactic(s) | Telemetry | Status |
|---|-----------|-----------|----|-----------|-----------|--------|
| 15 | Lateral movement: RDP/SMB from unexpected source | Remote Services | T1021 | Lateral Movement | Logon type 3/10 + baseline IPs | [ ] |
| 16 | Registry run-key persistence | Boot/Logon Autostart | T1547 | Persistence | Sysmon / FIM | [ ] |
| 17 | WMI execution | Windows Management Instrumentation | T1047 | Execution | Sysmon cmdline | [ ] |
| 18 | Firewall disabled | Impair Defenses: Disable Firewall | T1562.004 | Defense Impairment | Registry / cmdline | [ ] |
| 19 | Logging disabled (e.g. PowerShell logging off) | Impair Defenses: Prevent History Logging | T1562.003 | Defense Impairment | Registry / cmdline | [ ] |
| 20 | Unexpected remote-access tool installed (RAT) | Remote Access Tools | T1219 | C2 | Sysmon process | [ ] |
| 21 | Tool download onto host | Ingress Tool Transfer | T1105 | C2 | Sysmon / PowerShell | [ ] |
| 22 | Pass-the-hash / alternate auth material | Use Alternate Authentication Material | T1550 | Lateral Movement | Logon patterns (NTLM/Kerberos) | [ ] |
| 23 | Process injection | Process Injection | T1055 | Priv Esc / Stealth | Sysmon ID 8/10 | [ ] |
| 24 | Kerberoasting (if domain-joined) | Steal or Forge Kerberos Tickets | T1558 | Credential Access | Event 4769 | [ ] |
| 25 | Data staged / archived before exfil | Archive Collected Data | T1560 | Collection | Sysmon (rar/7z/Compress-Archive) | [ ] |
| 26 | Rapid discovery activity (behavioral) | multiple (T1087/T1082/T1016...) | — | Discovery | Sysmon cmdline (frequency) | [ ] |

---

## Tuning already in place (see docs/tuning-log.md)
- Type 5 (service) failed logons down-ranked (rule 100200) so brute-force
  detection is not polluted by benign service-auth noise.

## Known coverage boundary (honest scoping)
Host telemetry covers the early-to-mid attack chain well: Initial Access,
Execution, Persistence, Privilege Escalation, Credential Access, Defense
Evasion/Impairment, and host-visible Impact. It does NOT cover the network
stages — Command & Control and Exfiltration are largely invisible without a
network IDS (Suricata). These tactics are a known gap that a network sensor
would close; they are out of scope for the current host-based deployment.

Low-yield tactics (Discovery, Collection) are intentionally under-weighted:
their techniques blend with normal admin activity, so per-technique rules would
be noisy. Only behavioral/frequency detections there are worthwhile.

## Validation note
Rules are validated in two steps: (1) `wazuh-analysisd -t` / `wazuh-logtest`
confirms the rule logic loads and matches a sample; (2) live-fire — generate the
attack safely on a LAB VM (never production) and confirm the alert fires. A
detection moves from [~] to [x] only after step 2.
