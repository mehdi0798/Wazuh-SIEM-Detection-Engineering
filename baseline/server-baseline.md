# Observation Baseline — Windows Production Server

> Sanitized. Real IPs/hostnames masked with `XXX`.

**Phase:** Observation (complete)
**Endpoint:** Windows Server 2016 (agent id 003)
**Window:** ~2 weeks of alerts, default logs only (pre-Sysmon)
**Built-in rules in deployment:** 4515

---

## Purpose
Before writing any custom rule, characterize what *normal* looks like, to:
1. Learn routine activity, so deviations stand out.
2. Identify what the built-in ruleset already detects, so effort isn't wasted.

**Method:** rank fired alerts by frequency, then field-inspect the
security-relevant ones.

Reusable commands (run inside the manager container):
```bash
# Rank alerts by frequency (excludes verbose SCA/compliance noise)
zgrep -h '"name":"XXX"' /var/ossec/logs/alerts/*/*/*.json.gz /var/ossec/logs/alerts/alerts.json 2>/dev/null \
  | grep -oP '"description":"[^"]{1,60}"' | sort | uniq -c | sort -rn | head -20

# Pull one real sample of any event (searches archives too)
zgrep -h '"name":"XXX"' /var/ossec/logs/alerts/*/*/*.json.gz /var/ossec/logs/alerts/alerts.json 2>/dev/null \
  | grep -i "SEARCH_TERM" | tail -1 | python3 -m json.tool

# Check if a detection already exists (3 angles)
grep -ri "brute force" /var/ossec/ruleset/rules/    # by name
grep -rl "4625" /var/ossec/ruleset/rules/           # by event ID
grep -ri "T1110" /var/ossec/ruleset/rules/          # by MITRE technique
```

---

## Part 1 — Normal activity baseline (ranked by frequency)

| Event (rule.description)                        | ~Count | Verdict |
|-------------------------------------------------|--------|---------|
| Software protection service scheduled           | 237    | Routine — licensing housekeeping. Ignore. |
| Registry Value/Key Integrity Checksum Changed   | ~290   | Routine FIM noise from normal OS operation. |
| Registry entries added                          | ~130   | Routine FIM noise. |
| Service startup type was changed                | 53     | Usually routine (updates/admin). Watch if unexpected. |
| Logon Failure - unknown user/bad password       | 46     | See Field-check 1 — mostly service noise. |
| Special privileges assigned to new logon (4672) | 28     | See Field-check 2 — real admin, benign. |
| Non service account logged off                  | 28     | Routine. |
| New Windows Service Created                      | 10     | Normal here; persistence-relevant type. Watch. |

---

## Field-check 1 — Failed logons (rule 60122, event 4625)
Real sample fields:
- `logonType: 5` → a **service** logon, not a user/remote connection
- account = computer account (`XXX$`), process = `svchost.exe`
- Source Network Address = `-` (no source IP)

**Verdict:** benign service-authentication noise, NOT brute force.
Real brute force = logon type **3** (network) or **10** (RDP), external IP,
real user account.

**Implication:** the brute-force rule must scope to logon type 3/10 and ignore
type 5. Measured normal floor ≈ single digits/day, never clustered → a threshold
like "8 failures in 120s" sits safely above normal.

## Field-check 2 — Special privileges assigned (rule 67028, event 4672)
Real sample fields:
- account = built-in Administrator (SID ...-500)
- standard admin privilege set, rule level 3, MITRE T1484

**Verdict:** benign — real admin with normal rights.
**Watch if:** account is not the expected admin, or count spikes.

## Known-good admin access
Administrator logs in via RDP from known IPs (`XXX`). Any RDP logon from a
different IP = deviation worth alerting on.

---

## Part 2 — Built-in coverage already working (do NOT rebuild)
Rules already firing: failed logons (60122), privileged logons (67028), service
changes, new service creation, registry integrity (FIM).
Modules running by default: FIM, Vulnerability Detection, SCA (CIS), Rootcheck.

**Implication:** custom work ADDS to or TUNES this — it doesn't recreate it.

---

## Status: COMPLETE
Normal characterized · scary-sounding events field-checked (both benign) ·
free coverage inventoried.

**Caveats:** default-log telemetry only (re-baseline after Sysmon); one endpoint
only (others need their own baseline).

## Next
Write the first custom rule — brute force, scoped to logon type 3/10, threshold
above the measured floor — then validate with `wazuh-logtest`.
