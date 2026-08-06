# MITRE ATT&CK Coverage Map

What this SIEM detects, mapped to MITRE ATT&CK — and, just as important, the
gaps not yet covered (goals to fill). The rules themselves live in
`rules/local_rules.xml` (with inline comments); this file is the coverage view
the rules file cannot provide, because it also lists what is MISSING.

> Sanitized. Real IPs/hostnames masked with `XXX`.

Legend: [x] detected · [~] partial / needs validation · [ ] gap (planned)

---

## Coverage table

| Tactic | Technique | ID | Rule | Status | Validation |
|--------|-----------|----|------|--------|------------|
| Credential Access | Brute Force | T1110 | 100201 | [~] | Rule loaded & valid; needs live-fire test on lab (8+ Type 3/10 failures in 120s) |
| Credential Access | Brute Force: RDP | T1110.001 | 100201 | [~] | Covered by same rule (Type 10 = RDP); needs lab test |
| Privilege Escalation | (4672 abnormal account) | T1078 | — | [ ] | GAP — planned: 4672 from unexpected (non-admin) account |
| Persistence | Create/modify service | T1543.003 | — | [ ] | GAP — planned: new service creation in unexpected context |
| Lateral Movement | Remote Services (RDP) | T1021.001 | — | [ ] | GAP — planned: RDP logon from IP not in trusted-admin list |
| Execution | Command/Scripting: PowerShell | T1059.001 | — | [ ] | GAP — planned once PowerShell 4104 baselined (telemetry now flowing) |
| Execution | Suspicious process (Sysmon) | T1059 | — | [ ] | GAP — planned once Sysmon process events baselined |

---

## Notes on current coverage

- **Detected now:** Windows brute force (T1110), scoped to real remote failed
  logons (Logon Type 3/10) via rule 100201. Service-noise (Type 5) is tuned out
  by rule 100200 so it does not create false positives (see docs/tuning-log.md).
- **Telemetry just enabled** (Sysmon, PowerShell Script Block Logging, audit
  policy on both Windows servers) unlocks the Execution and process-based
  techniques above — those become buildable now that the logs flow.
- **Inherited free coverage:** Wazuh's built-in ruleset already detects many
  base events (failed logons, privileged logons, service changes, registry
  integrity via FIM). Custom rules ADD to and TUNE this, not replace it.

## Validation status
- Rules are written and the ruleset compiles cleanly (`wazuh-analysisd -t`).
- Live-fire validation (generating the attack safely on a lab VM, never on
  production) is pending for the detection rules — this moves [~] entries to [x].

## Next techniques to build (priority order)
1. Suspicious PowerShell (T1059.001) — telemetry now available (4104).
2. Suspicious process execution (T1059 / Sysmon event 1) — after Sysmon baseline.
3. Privilege escalation (T1078) — 4672 abnormal account.
4. Lateral movement / RDP from unknown IP (T1021.001).
5. Linux track (lablinux): SSH brute force (T1110 on Linux), sudo abuse.
