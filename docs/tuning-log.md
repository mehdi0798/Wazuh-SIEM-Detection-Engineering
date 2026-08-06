# Tuning Log

Record of every built-in rule tuning decision. Each entry answers: what was
noisy, why it's benign here, and what was changed. The actual tuning rules live
in `rules/local_rules.xml`; this file explains WHY.

> Sanitized. Real IPs/hostnames masked with `XXX`.

Principle: never edit built-in rule files (updates overwrite them). Tune by
adding an override rule in `local_rules.xml` that hooks the built-in via
`if_sid` and adjusts its level (or silences it) for a specific benign case.

---

## Entry 1 — Windows failed-logon service noise (Logon Type 5)

- **Built-in rule affected:** 60122 (Windows failed logon, event 4625), level 5
- **What was noisy:** ~46 failed-logon alerts over ~2 weeks on the monitored
  Windows server, most of them Logon Type 5.
- **Why it's benign:** field inspection showed these are SERVICE authentication
  failures — subject is a computer account (`XXX$`), caller process
  `svchost.exe`, Source Network Address `-` (no remote source). This is the OS
  failing to authenticate a service internally, not a login attempt.
- **Why it matters to tune:** left alone, this noise pollutes failed-logon
  analysis and could mask a real brute-force pattern.
- **Action:** added override rule **100200** (level 2) that matches 60122 where
  `win.eventdata.logonType = 5` and drops it below the alert threshold (3).
- **Real attacks preserved:** genuine brute force is Logon Type 3 (network) or
  10 (RDP); those are NOT affected by this tuning and are detected by rule
  100201.
- **Status:** applied, ruleset validated (`wazuh-analysisd -t` clean).

---

## (Template for future entries)

## Entry N — <short title>
- **Built-in rule affected:**
- **What was noisy:**
- **Why it's benign:**
- **Why it matters to tune:**
- **Action:** (override rule id + what it does)
- **Real attacks preserved:**
- **Status:**

---

## Pending tuning to watch for
- **Sysmon process noise:** the monitored server runs a database engine that
  spawns many processes continuously. When writing Sysmon-based detection rules,
  expect to tune out this routine process activity so it doesn't false-alarm.
- Revisit tuning after each new telemetry source and whenever a custom rule
  fires too often on benign activity.
