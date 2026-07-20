# Evidence Analysis
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Analytical Approach

Each piece of evidence is presented as collected from Elastic SIEM, followed by field-level analysis identifying what each observable confirms, implies, or leaves unknown. Evidence is never interpreted beyond what the data supports.

---

## Evidence 1 — PsExec Execution
**Source:** WKSTN-MKT-04 | 10:05:12 local

```json
{
  "@timestamp": "2026-05-01T14:05:12.000Z",
  "event.code": "1",
  "event.provider": "Microsoft-Windows-Sysmon",
  "host.name": "WKSTN-MKT-04",
  "host.ip": "192.168.15.44",
  "process.command_line": "C:\\Windows\\System32\\psexec.exe \\\\SRV-APP-INT -u admin -p [REDACTED] cmd.exe",
  "process.name": "psexec.exe",
  "parent.name": "cmd.exe",
  "user.name": "m.perez"
}
```

### Field Analysis

| Field | Value | Significance |
|---|---|---|
| `event.code: 1` | Sysmon Process Creation | Full command-line logging captured — this event class is the primary source for LotL detection |
| `process.name` | `psexec.exe` | Not a native Windows binary — requires deliberate download and placement; presence on a plant engineering workstation is anomalous |
| `parent.name` | `cmd.exe` | Indicates an active interactive command shell session; PsExec was not launched by a scheduled task or service |
| `user.name` | `m.perez` | The authenticated session user — a plant engineering account with no documented administrative authorization |
| `-u admin` | Separate account specified | The operator explicitly supplied a different administrative account, distinct from the logged-on user |
| `-p [REDACTED]` | Plaintext credential in command line | Credential was passed as a command-line argument — recorded in Sysmon logs, exposable in process listings and log forwarding pipelines |
| `\\SRV-APP-INT` | Target host named explicitly | Indicates the operator knew the hostname of the target — consistent with prior reconnaissance or insider knowledge |

### Findings

- **CONFIRMED:** `m.perez` executed `psexec.exe` from an active `cmd.exe` session on `WKSTN-MKT-04`
- **CONFIRMED:** An administrative account (`admin`) was used with a plaintext credential argument
- **INFERRED:** The operator had prior knowledge of `SRV-APP-INT` as a target
- **UNKNOWN:** How `m.perez` obtained the `admin` account credentials

---

## Evidence 2 — Authentication Failure on SRV-APP-INT
**Source:** SRV-APP-INT | 10:05:15 local

```json
{
  "@timestamp": "2026-05-01T10:05:15.000Z",
  "event.code": "4625",
  "event.provider": "Microsoft-Windows-Security-Auditing",
  "event.action": "An account failed to log on",
  "host.name": "SRV-APP-INT",
  "host.ip": "10.0.50.88",
  "event.category": "authentication"
}
```

### Field Analysis

| Field | Value | Significance |
|---|---|---|
| `event.code: 4625` | Logon failure | Network authentication was attempted and rejected |
| `event.action` | An account failed to log on | The target host received and processed the authentication request — it was not blocked at the network layer |
| `@timestamp: 10:05:15.000Z` | UTC — no offset applied | Other WKSTN-MKT-04 events are stored at `14:xx:xxZ` (UTC-4 offset). SRV-APP-INT records in local time as UTC, indicating a clock sync discrepancy between hosts |
| `host.ip: 10.0.50.88` | Different subnet from source | WKSTN-MKT-04 is on `192.168.15.0/24`; SRV-APP-INT is on `10.0.50.0/24` — cross-segment authentication was permitted |
| Logon Type | Not captured in available fields | Type 3 (Network) is inferred from the PsExec mechanism — not directly confirmed from this log entry |

### Findings

- **CONFIRMED:** Authentication against `SRV-APP-INT` failed at approximately the same time as the PsExec execution
- **CONFIRMED:** No Event ID 4624 (successful logon) was observed on `SRV-APP-INT` in available telemetry
- **INFERRED:** This failure is the direct result of the PsExec attempt in Evidence 1
- **INFERRED:** Logon Type 3 (network logon), consistent with PsExec behavior
- **UNKNOWN:** Whether additional authentication attempts occurred outside the available log window
- **UNKNOWN:** Whether remote execution on `SRV-APP-INT` was ultimately achieved

> **Timestamp Note:** The 3-second delta between Evidence 1 (14:05:12Z on WKSTN-MKT-04) and this event (10:05:15Z on SRV-APP-INT) is operationally consistent but reflects a clock discrepancy. This was identified during analysis and documented as an investigation limitation. NTP synchronization across hosts should be verified as part of remediation.

---

## Evidence 3 — WMIC Account Enumeration
**Source:** WKSTN-MKT-04 | 10:08:45 local

```json
{
  "@timestamp": "2026-05-01T14:08:45.000Z",
  "event.code": "1",
  "event.provider": "Microsoft-Windows-Sysmon",
  "host.name": "WKSTN-MKT-04",
  "host.ip": "192.168.15.44",
  "process.command_line": "C:\\Windows\\System32\\wbem\\WMIC.exe useraccount get name,sid",
  "process.name": "wmic.exe",
  "parent.name": "cmd.exe",
  "user.name": "m.perez"
}
```

### Field Analysis

| Field | Value | Significance |
|---|---|---|
| `event.code: 1` | Sysmon Process Creation | Command-line arguments fully captured |
| `process.name` | `wmic.exe` | Native Windows binary — signed Microsoft tool, bypasses application allowlisting unless explicitly blocked |
| `process.command_line` | `useraccount get name,sid` | Enumerates all local user accounts and their Security Identifiers; does not return passwords or hashes |
| `parent.name` | `cmd.exe` | Same parent process class as Evidence 1 — consistent with a single continuous operator session |
| `user.name` | `m.perez` | Same user context as Evidence 1 |
| **Delta from Evidence 1** | +3 minutes 33 seconds | Sufficient time for the operator to observe the PsExec failure and pivot to reconnaissance |

### Findings

- **CONFIRMED:** `m.perez` executed `WMIC.exe` to enumerate local user accounts and SIDs on `WKSTN-MKT-04`
- **CONFIRMED:** The parent `cmd.exe` process is consistent with the session established prior to the PsExec attempt
- **INFERRED:** This activity represents a Discovery phase following the failed remote execution attempt
- **INFERRED:** The operator used the session to gather account information to inform subsequent lateral movement
- **UNKNOWN:** Whether enumerated account data was recorded, exfiltrated, or used in subsequent actions

> **Scope note:** `WMIC useraccount get name,sid` returns account names and SIDs only. No credential material is directly accessible through this query. Claims of credential exposure from this specific command are not supported by evidence.

---

## Evidence 4 — Outbound RDP Connection Permitted
**Source:** WKSTN-MKT-04 | 10:15:02 local

```json
{
  "@timestamp": "2026-05-01T10:15:02.000Z",
  "event.action": "Firewall ALLOW rule triggered",
  "event.provider": "Windows Defender Firewall",
  "host.name": "WKSTN-MKT-04",
  "host.ip": "192.168.15.44",
  "destination.ip": "10.0.50.99",
  "destination.port": "3389",
  "destination.service.name": "RDP"
}
```

### Field Analysis

| Field | Value | Significance |
|---|---|---|
| `event.action` | Firewall ALLOW rule triggered | The outbound packet was permitted to leave the host — this does not confirm session establishment |
| `destination.ip` | `10.0.50.99` | A third internal host, distinct from `SRV-APP-INT` (10.0.50.88) — same subnet, different target |
| `destination.port` | `3389` | Standard RDP port — indicates intent to establish a graphical remote desktop session |
| `destination.service.name` | RDP | Confirmed by the firewall rule metadata |
| **Host identity** | Unknown | The role, hostname, and ownership of `10.0.50.99` cannot be determined from available telemetry |

### Findings

- **CONFIRMED:** An outbound connection to `10.0.50.99:3389` was initiated from `WKSTN-MKT-04` and permitted by the local firewall
- **INFERRED:** This represents an attempt to establish a Remote Desktop session on a third internal host
- **UNKNOWN:** Whether the RDP session was successfully established
- **UNKNOWN:** The identity, hostname, and role of `10.0.50.99`
- **UNKNOWN:** Whether this host is related to the out-of-scope activity observed on `SRV-DC-01`

---

## Evidence 5 — Outbound SMB Connection Blocked
**Source:** WKSTN-MKT-04 | 10:15:06 local

```json
{
  "@timestamp": "2026-05-01T10:15:06.000Z",
  "event.action": "Firewall DROP rule triggered",
  "event.provider": "Windows Defender Firewall",
  "host.name": "WKSTN-MKT-04",
  "host.ip": "192.168.15.44",
  "destination.ip": "10.0.50.99",
  "destination.port": "445",
  "destination.service.name": "SMB",
  "log.level": "warning"
}
```

### Field Analysis

| Field | Value | Significance |
|---|---|---|
| `event.action` | Firewall DROP rule triggered | Connection was blocked at the host firewall — SMB traffic did not reach the destination |
| `destination.ip` | `10.0.50.99` | Same target as Evidence 4 — same host targeted on two protocols within 4 seconds |
| `destination.port` | `445` | SMB port — used for file share access, lateral movement via Admin Shares (C$, ADMIN$), and PsExec service installation |
| `log.level` | warning | Firewall logged this as elevated severity relative to standard traffic |
| **Delta from Evidence 4** | +4 seconds | RDP and SMB attempts to the same host in 4 seconds is consistent with scripted scanning or automated lateral movement tooling |

### Findings

- **CONFIRMED:** An outbound SMB connection to `10.0.50.99:445` was attempted and blocked by Windows Defender Firewall
- **CONFIRMED:** The combined RDP + SMB pattern against the same host within 4 seconds indicates active host targeting, not coincidental traffic
- **INFERRED:** The operator was attempting to access `10.0.50.99` via multiple remote access protocols simultaneously — consistent with lateral movement preparation
- **CONFIRMED:** The SMB attempt was effectively contained at the network layer on this host

---

## Evidence Cross-Reference

| Event | Time | Source | Key Observable | Links To |
|---|---|---|---|---|
| PsExec execution | 10:05:12 | WKSTN-MKT-04 | Remote exec attempt, plaintext creds | → Ev. 2 (auth failure) |
| Auth failure 4625 | 10:05:15 | SRV-APP-INT | Network logon rejected | ← Ev. 1 |
| WMIC enumeration | 10:08:45 | WKSTN-MKT-04 | Account discovery, same cmd.exe parent | ← Ev. 1 session |
| RDP ALLOW | 10:15:02 | WKSTN-MKT-04 | New target, port 3389 permitted | → Ev. 5 (same target) |
| SMB DROP | 10:15:06 | WKSTN-MKT-04 | Same target, port 445 blocked | ← Ev. 4 |

---

## Related Documents

- [← Timeline](02-timeline.md)
- [Attack Hypothesis →](04-attack-hypothesis.md)
- [IOC List →](../iocs/ioc-list.md)
