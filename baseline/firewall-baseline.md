# Firewall Observation Baseline — Sophos XG

> Sanitized. Real IPs masked with `XXX` where sensitive; internal lab subnet
> shown as 192.168.40.x for structure.

**Phase:** Observation (complete)
**Source:** Sophos XG firewall (network perimeter sensor)
**How it reaches Wazuh:** syslog over **UDP 514** — NOT an agent. The firewall
cannot run a Wazuh agent, so it pushes its own logs via syslog to the manager.
(Contrast: the Windows servers use a Wazuh **agent** over encrypted **TCP 1514**.)
**Where the data lands:** `/var/ossec/logs/alerts/alerts.json` — the denied-traffic
events match custom rule **100101** ("Sophos XG: Traffic denied by firewall"),
so they become alerts, not just raw archive lines.

---

## Purpose
Characterize what NORMAL firewall activity looks like, so future firewall rules
fire on abnormal patterns (e.g. port scans) and not on routine denied noise.

## Method (reusable)
The firewall data sits inside the JSON `full_log` field with **escaped quotes**
(`device_name=\"sophos-xg\"`). Searching for `"sophos-xg"` with plain quotes
returns nothing — search for the bare substring instead:

```bash
# Count firewall events
grep "sophos-xg" /var/ossec/logs/alerts/alerts.json | wc -l

# See one real event (ground truth for structure)
grep -i "sophos" /var/ossec/logs/alerts/alerts.json | tail -1

# Rank by a field (protocol / dst_port / src_ip)
grep "sophos-xg" /var/ossec/logs/alerts/alerts.json | grep -oP 'protocol=.{0,8}' | sort | uniq -c | sort -rn
grep "sophos-xg" /var/ossec/logs/alerts/alerts.json | grep -oP 'dst_port=.{0,8}' | sort | uniq -c | sort -rn
grep "sophos-xg" /var/ossec/logs/alerts/alerts.json | grep -oP 'src_ip=.{0,18}' | sort | uniq -c | sort -rn
```

**Lesson learned:** when a search returns empty but the data exists, pull one
real raw line and read how it's actually written (escaping, field names) instead
of assuming. Escaped quotes were the trap here.

---

## Baseline data (~319 firewall denied events observed)

### By protocol
| Protocol | Count | Note |
|----------|-------|------|
| UDP | 183 | Bulk of denied traffic — routine |
| ICMP (type 2) | 40 | Ping/network control |
| TCP | 21 | Fewer TCP denials |

### By destination port
| dst_port | Count | Meaning |
|----------|-------|---------|
| 43561, 57621, 44444, 46060, 40260... | ~180 | High ephemeral ports — late-returning replies / chatter. Benign. |
| 138 | 9 | NetBIOS name service (broadcast). Benign. |
| 67, 68 | 9 | DHCP. Benign. |

### By source IP
| src_ip | Count | Meaning |
|--------|-------|---------|
| 192.168.40.10 | 119 | Internal lab host — normal chatter |
| 192.168.40.95 | 46 | Internal lab host |
| 0.0.0.0 | 46 | DHCP discovery (device with no IP yet). Benign. |
| 192.168.40.197, .1, .103, .101 | ~30 | Internal lab hosts / gateway |
| 108.133.20.209, 108.129.48.233, 52.212.68.80 | 1-5 each | External internet noise — firewall correctly blocking |

---

## The shape of NORMAL (the key takeaway)
Normal firewall activity here = **mostly internal lab hosts (192.168.40.x)
sending UDP traffic to high random (ephemeral) ports that gets denied, plus
routine NetBIOS/DHCP broadcasts, plus a small amount of external internet noise
the firewall blocks.**

Why this is benign: late-arriving replies to ephemeral ports, cross-segment
broadcast/multicast announcements (that shouldn't cross zones), and background
application probes — all correctly denied by the firewall doing its job.
**Denied != attack.** The firewall denies lots of benign chatter.

## What ABNORMAL would look like (what to detect later)
- A single **external** IP hitting **many different / sequential ports** = port scan.
- A sudden **spike** of denials from a normally-quiet source.
- Denied traffic to a **specific sensitive port** that's usually never touched.
Distinguishing tell: scattered internal chatter = benign; systematic external
probing = suspicious.

---

## Role of the firewall in this SIEM
The firewall is the network checkpoint controlling what traffic crosses between
zones (lab .40 / infrastructure .10 / internet), blocking what's not permitted
and logging those decisions. In the SIEM it is the **network-level sensor** —
perimeter visibility — complementing the **host-level** visibility from the
server agents.

## Status: COMPLETE
Normal characterized; abnormal patterns defined; method documented.
Caveat: baseline reflects lab traffic while lab VMs were running; production
firewall traffic patterns may differ and should be re-checked if scope expands.

## Next (if building firewall rules)
Gap-check for existing scan-detection rules, then a rule for external port-scan
patterns (single external src_ip → many dst_ports in a short window), scoped
above this normal denied-noise baseline.
