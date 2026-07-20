# Incident Timeline
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Reconstruction Notes

All timestamps are recorded in **local time (UTC-4)** as observed in the Elastic SIEM dashboard.  
Raw log timestamps for WKSTN-MKT-04 events are stored in UTC (`14:xx:xxZ`); the 4-hour offset was applied consistently during ingestion.

> **Timestamp Anomaly — CONFIRMED limitation:** The SRV-APP-INT authentication failure (Event ID 4625) was recorded at `10:05:15.000Z` in UTC with no offset applied, indicating a possible NTP misconfiguration or clock desync on that host. The 3-second delta between the PsExec execution (10:05:12 local) and the failed logon (10:05:15 local) is operationally consistent and the correlation is treated as **INFERRED** rather than CONFIRMED due to this clock discrepancy.

---

## Event Timeline

### Event 1 — 10:05:12 | PsExec Remote Execution Attempt

| Field | Value |
|---|---|
| **Timestamp (local)** | 10:05:12 |
| **Host** | WKSTN-MKT-04 |
| **Source IP** | 192.168.15.44 |
| **User** | m.perez |
| **Log Source** | Sysmon + Windows Security Event Log |
| **Event ID** | Sysmon ID 1 / Event ID 4688 |
| **Process** | `psexec.exe` |
| **Parent Process** | `cmd.exe` |
| **Command Line** | `C:\Windows\System32\psexec.exe \\SRV-APP-INT -u admin -p [REDACTED] cmd.exe` |
| **Target Host** | SRV-APP-INT |
| **Classification** | CONFIRMED |

**Analysis:** User `m.perez` — a plant engineering account with no authorized administrative role — executed PsExec from an active command shell targeting `SRV-APP-INT`. A separate administrative account (`admin`) was used with credentials passed in plaintext via the `-p` argument. The use of a privileged account distinct from the authenticated session user indicates either credential theft or unauthorized access to administrative credentials.

---

### Event 2 — 10:05:15 | Authentication Failure on SRV-APP-INT

| Field | Value |
|---|---|
| **Timestamp (local)** | 10:05:15 |
| **Host** | SRV-APP-INT |
| **Host IP** | 10.0.50.88 |
| **Log Source** | Windows Security Event Log |
| **Event ID** | 4625 |
| **Logon Type** | 3 (Network) |
| **Action** | An account failed to log on |
| **Source IP** | 192.168.15.44 |
| **Classification** | CONFIRMED (event) / INFERRED (direct causal link to Event 1 — see timestamp note above) |

**Analysis:** Network authentication against `SRV-APP-INT` failed 3 seconds after the PsExec execution on `WKSTN-MKT-04`. The Logon Type 3 (network logon) is consistent with PsExec's authentication mechanism. The causal link is operationally sound but technically INFERRED due to the clock discrepancy on `SRV-APP-INT`. No successful follow-up authentication (Event ID 4624) was observed in available telemetry — remote execution against this target is classified as **UNKNOWN**.

---

### Event 3 — 10:08:45 | Account Enumeration via WMIC

| Field | Value |
|---|---|
| **Timestamp (local)** | 10:08:45 |
| **Host** | WKSTN-MKT-04 |
| **Source IP** | 192.168.15.44 |
| **User** | m.perez |
| **Log Source** | Sysmon |
| **Event ID** | Sysmon ID 1 |
| **Process** | `wmic.exe` |
| **Parent Process** | `cmd.exe` |
| **Command Line** | `C:\Windows\System32\wbem\WMIC.exe useraccount get name,sid` |
| **Classification** | CONFIRMED |

**Analysis:** 3 minutes and 33 seconds after the PsExec attempt, `WMIC.exe` was executed under the same user session to enumerate local user accounts and their Security Identifiers (SIDs). The parent process `cmd.exe` is consistent with the active command shell from Event 1, suggesting this is a continuation of the same operator session. This query returns account names and SIDs only — credential material was not directly accessible through this command.

---

### Event 4 — 10:15:02 | Outbound RDP Connection Permitted

| Field | Value |
|---|---|
| **Timestamp (local)** | 10:15:02 |
| **Host** | WKSTN-MKT-04 |
| **Source IP** | 192.168.15.44 |
| **Destination IP** | 10.0.50.99 |
| **Destination Port** | 3389 |
| **Protocol** | RDP |
| **Firewall Action** | ALLOW |
| **Log Source** | Windows Defender Firewall |
| **Classification** | CONFIRMED (connection permitted) / UNKNOWN (session outcome) |

**Analysis:** An outbound RDP connection to a third internal host (`10.0.50.99`) was permitted by Windows Defender Firewall. The identity and role of `10.0.50.99` were not determinable from available telemetry. A firewall ALLOW indicates the packet left the source host — it does not confirm that a Remote Desktop session was successfully established. Session outcome is **UNKNOWN** without PCAP or EDR data.

---

### Event 5 — 10:15:06 | Outbound SMB Connection Blocked

| Field | Value |
|---|---|
| **Timestamp (local)** | 10:15:06 |
| **Host** | WKSTN-MKT-04 |
| **Source IP** | 192.168.15.44 |
| **Destination IP** | 10.0.50.99 |
| **Destination Port** | 445 |
| **Protocol** | SMB |
| **Firewall Action** | DROP |
| **Log Source** | Windows Defender Firewall |
| **Log Level** | Warning |
| **Classification** | CONFIRMED |

**Analysis:** Four seconds after the RDP connection attempt, the same host targeted `10.0.50.99` on port 445 (SMB). The firewall blocked this connection. The combined RDP + SMB pattern against the same destination within 4 seconds is consistent with active host scanning or lateral movement preparation. The SMB attempt was effectively contained at the network layer.

---

## Consolidated Timeline View

```
10:05:12  [WKSTN-MKT-04]  Sysmon ID 1 / 4688  →  psexec.exe → \\SRV-APP-INT  (m.perez / admin creds)
10:05:15  [SRV-APP-INT  ]  Event ID 4625        →  Network logon failure (Logon Type 3)
10:08:45  [WKSTN-MKT-04]  Sysmon ID 1          →  wmic.exe useraccount get name,sid
10:15:02  [WKSTN-MKT-04]  Firewall ALLOW        →  → 10.0.50.99:3389 (RDP)
10:15:06  [WKSTN-MKT-04]  Firewall DROP         →  → 10.0.50.99:445  (SMB) ← blocked
```

**Total observed window:** 9 minutes 54 seconds

---

## Out-of-Scope Activity Identified

During log review the following events were identified in available telemetry but fall **outside the scope of this incident**. They are flagged here for separate investigation:

| Observable | Host | Concern |
|---|---|---|
| `chrome.exe` executing as `SYSTEM` from `C:\Windows\System32\` | SRV-DC-01 | Anomalous process path and privilege for a browser binary on a Domain Controller |
| Administrative account accessing external APIs | IT workstation (unspecified) | Potential data exfiltration or unauthorized external communication |
| RDP connections between unverified network segments | Multiple (unspecified) | Possible additional lateral movement outside this incident scope |

These findings do not form part of INC-2026-03-01 and require independent investigation.

---

## Related Documents

- [← Incident Overview](01-incident-overview.md)
- [Evidence Analysis →](03-evidence-analysis.md)
- [Attack Hypothesis →](04-attack-hypothesis.md)
