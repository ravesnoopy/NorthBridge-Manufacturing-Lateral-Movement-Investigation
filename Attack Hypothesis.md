# Attack Hypothesis
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Hypothesis Statement

Based on available telemetry, the activity observed on `WKSTN-MKT-04` between 10:05:12 and 10:15:06 is consistent with an operator conducting **internal reconnaissance and lateral movement preparation** using exclusively native Windows tooling (Living-off-the-Land).

The operator authenticated as `m.perez` — a plant engineering account — and leveraged a separate administrative credential to attempt remote execution against an internal application server. Following a failed authentication attempt, the operator pivoted to local account enumeration before initiating multi-protocol connection attempts against a third internal host.

No malware was involved. No exploits were observed. The entire attack surface relied on signed Microsoft binaries and built-in Windows services.

**Investigative phase classification: Discovery + Lateral Movement (active, early-stage)**

---

## Attack Phases

### Phase 1 — Initial Access / Credential Use

**Classification: CONFIRMED (execution) / UNKNOWN (access method)**

The operator gained access to `WKSTN-MKT-04` using valid credentials for `m.perez`. The method by which the operator obtained access to the workstation — and subsequently to the `admin` account credentials — cannot be determined from available telemetry.

Possible access vectors (not confirmed by evidence):
- Compromised `m.perez` credentials via phishing or credential reuse
- Physical or remote access to an unattended authenticated session
- Insider threat — `m.perez` acting as the operator

The distinction between these scenarios cannot be resolved without memory acquisition, EDR live response, or authentication history beyond the available log window.

---

### Phase 2 — Execution via PsExec

**Classification: CONFIRMED**

The operator launched `psexec.exe` from an active `cmd.exe` session targeting `SRV-APP-INT` using a separate `admin` account. The credential was supplied as a plaintext `-p` argument, recording it in Sysmon process creation logs.

This technique is consistent with **T1569.002 (System Services: Service Execution)** — PsExec operates by copying a service binary (`PSEXESVC`) to the target host and executing it via the Windows Service Control Manager — in addition to the remote services component.

The authentication against `SRV-APP-INT` failed (Event ID 4625), and no successful logon (Event ID 4624) was observed. Remote execution on `SRV-APP-INT` is **UNKNOWN**.

---

### Phase 3 — Discovery via WMIC

**Classification: CONFIRMED**

Following the failed PsExec attempt, the operator executed `WMIC.exe useraccount get name,sid` from the same `cmd.exe` session. This query enumerates all local user accounts and their Security Identifiers.

This behavior is consistent with an operator who failed to move laterally and is now gathering account information to identify alternative targets or valid credentials for a subsequent attempt.

The output of this command — account names and SIDs — does not include credential material. No evidence of the enumerated data being used or exfiltrated was observed in available telemetry.

---

### Phase 4 — Lateral Movement Attempt

**Classification: CONFIRMED (attempts) / UNKNOWN (outcomes)**

Six minutes and 17 seconds after the WMIC enumeration, the operator initiated two rapid outbound connections from `WKSTN-MKT-04` to `10.0.50.99`:

- **RDP (3389):** Permitted by Windows Defender Firewall
- **SMB (445):** Blocked by Windows Defender Firewall

The 4-second interval between both attempts against the same destination is consistent with scripted or semi-automated lateral movement tooling rather than manual navigation. Whether the RDP connection resulted in an established session cannot be confirmed without PCAP or EDR data.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observable | Classification |
|---|---|---|---|---|
| Execution | T1569.002 | System Services: Service Execution | `psexec.exe` deploys PSEXESVC on target | INFERRED |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | `psexec.exe \\SRV-APP-INT` | CONFIRMED |
| Discovery | T1087.001 | Account Discovery: Local Account | `wmic useraccount get name,sid` | CONFIRMED |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | Outbound port 3389 → 10.0.50.99 (ALLOW) | CONFIRMED |
| Lateral Movement | T1021 | Remote Services | Outbound port 445 → 10.0.50.99 (DROP) | CONFIRMED |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Plaintext `-p` argument in PsExec command line | CONFIRMED |

---

## Kill Chain Visualization

```
[WKSTN-MKT-04 / m.perez / 192.168.15.44]
         │
         │  10:05:12  psexec.exe \\SRV-APP-INT -u admin -p [REDACTED]
         │            T1021.002 + T1569.002 + T1552.001
         ▼
[SRV-APP-INT / 10.0.50.88]
         │
         │  10:05:15  Event ID 4625 — Network logon FAILED
         │            Execution on SRV-APP-INT: UNKNOWN
         │
         └──────────── operator pivots ────────────┐
                                                    │
         │  10:08:45  wmic useraccount get name,sid │
         │            T1087.001                     │
         ▼                                          │
[Local Account Enumeration — WKSTN-MKT-04]         │
         │                                          │
         │  10:15:02  → 10.0.50.99:3389  ALLOW ◄───┘
         │            T1021.001
         │
         │  10:15:06  → 10.0.50.99:445   DROP  ← contained
                      T1021
```

---

## Living-off-the-Land Assessment

Every tool used in this incident is a signed Microsoft binary or a publicly available administration utility:

| Binary | Legitimate Purpose | Abuse in This Incident |
|---|---|---|
| `psexec.exe` | Remote administration | Remote command execution with alternate credentials |
| `cmd.exe` | Command interpreter | Interactive session host for tool execution |
| `wmic.exe` | WMI administration | Local account and SID enumeration |
| Windows Defender Firewall | Network protection | RDP permitted outbound — no rule blocked it |

No custom malware, no exploit code, no packed binaries, no script interpreters beyond `cmd.exe`. This attack surface is entirely invisible to signature-based detection.

---

## Alternative Hypotheses Considered

| Hypothesis | Assessment |
|---|---|
| Legitimate administrative activity by `m.perez` | **Rejected.** Plant engineering users have no documented authorization to execute PsExec against application servers or use administrative accounts. |
| Authorized IT administrator using `m.perez` session | **Cannot be confirmed or excluded.** No evidence of remote control of the `m.perez` session is available. Requires additional investigation. |
| Automated script running under `m.perez` context | **Possible but unsupported.** The parent `cmd.exe` is consistent with interactive use. No scheduled task or service trigger was observed. |
| Insider threat — `m.perez` as the actor | **Cannot be excluded.** Physical access to the workstation and knowledge of `admin` credentials cannot be ruled out without additional context. |

---

## Confidence Assessment

| Finding | Confidence | Basis |
|---|---|---|
| LotL techniques were used | High | Direct Sysmon command-line evidence |
| Activity is malicious in nature | High | No authorization, cross-account credential use, multi-target behavior |
| Lateral movement to SRV-APP-INT succeeded | Low | Authentication failed; no 4624 observed |
| Lateral movement to 10.0.50.99 succeeded | Low | Firewall ALLOW ≠ established session; no further telemetry |
| Full attacker objective | Unknown | Available telemetry does not support a conclusion |

---

## Related Documents

- [← Evidence Analysis](03-evidence-analysis.md)
- [Risk Assessment →](05-risk-assessment.md)
- [Detection Opportunities →](../detections/detection-opportunities.md)
