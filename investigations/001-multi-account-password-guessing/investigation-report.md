# SOC L1 Investigation — Suspicious Windows Authentication Activity

> **Hands-on investigation | Splunk Enterprise / BOTS v2 training dataset**

| Field | Details |
|---|---|
| **Case** | 001 — Multiple Failed Login Attempts |
| **Detection** | `SOC-L1 - Multiple Failed Login Attempts` |
| **Incident date** | 19 August 2017 (Splunk-displayed time) |
| **Source** | `172.16.0.1` / `STARRAIDERS` |
| **Destination** | `venus.frothly.local` (`FROTHLY`) |
| **Priority** | Medium (proposed) |
| **SOC L1 assessment** | Suspicious authentication activity; malicious intent unconfirmed |
| **Disposition** | Recommend escalation to SOC L2; not submitted |

## 1. Executive Summary

While investigating Windows Security logs in Splunk, I identified **14 failed logon events against three account names** from the same internal source IP, `172.16.0.1`, within approximately **9 minutes and 30 seconds**. Eight failures targeted `administrator`.

Fifteen seconds after the last failure involving `mkraeusen`, a **successful network logon** occurred from the same IP and workstation using a *different* account, `FROTHLY\mallory.kraeusen`. The successful session received special Windows privileges (EventCode `4672`).

This sequence warrants investigation for **multi-account password guessing or possible password spraying**. The logs do **not** prove that the attempts were malicious, that passwords were sprayed across accounts, or that the successful login was unauthorized. **SOC L2 escalation is recommended** to validate the activity and investigate the source workstation.

## 2. Detection and Initial Triage

The Splunk alert was designed to identify **five or more Windows failed logons** (`EventCode=4625`) from one source IP against one account within a five-minute window.

The initial alert reported **six failures** for `Administrator`. A follow-up investigation revealed two more events recorded as `administrator`. After normalizing the account name to lowercase for analysis, the count was **eight**. The existing saved alert was **not changed**.

<img width="1779" height="365" alt="2" src="https://github.com/user-attachments/assets/159d3c0d-3376-425e-8dcc-a546ea39966f" />

*Screenshot 2 — Eight failed `administrator` logons after normalizing account-name capitalization.*

## 3. Failed Authentication Analysis

All 14 failed events were associated with `172.16.0.1` and involved these account names:

| Account | Failed logons | First seen | Last seen |
|---|---:|---|---|
| `administrator` | 8 | 08:13:24 | 08:14:50 |
| `hawkeye` | 2 | 08:13:47 | 08:13:47 |
| `mkraeusen` | 4 | 08:22:36 | 08:22:54 |
| **Total** | **14** | **08:13:24** | **08:22:54** |

*All times in this table are Splunk-displayed times on 19 August 2017.*

<img width="1780" height="472" alt="3" src="https://github.com/user-attachments/assets/91607db5-5109-4db5-8aae-f494f78db3fe" />

*Screenshot 3 — Failed authentication counts by account.*

<img width="1779" height="468" alt="4" src="https://github.com/user-attachments/assets/4622619b-0061-4e6d-827d-0bebb28e4c6d" />

*Screenshot 4 — First and last observed failed logon times by account.*

A raw Windows Security `4625` event confirmed:

- **Target:** `FROTHLY\administrator`
- **Source IP / workstation:** `172.16.0.1` / `STARRAIDERS`
- **Destination:** `venus.frothly.local`
- **Logon type:** `3` (network)
- **Status:** `0xC000006D` (authentication failure)
- **Sub-status:** `0xC000006A` (incorrect password)

Another reviewed `4625` event for `mkraeusen` returned `0xC0000064` (user account not found). These failures are consistent with password guessing and possible account-name probing. The actual passwords attempted are not visible in these logs.

<img width="945" height="863" alt="7" src="https://github.com/user-attachments/assets/344d13df-ee14-4e0b-bedf-83e30e7ac087" />

*Screenshot 7 — Raw EventCode `4625`, showing the targeted account, source, and failure codes.*

## 4. Subsequent Successful Logon

At **08:23:09**, a Windows Security `4624` event showed a successful network logon with the following attributes:

| Field | Value |
|---|---|
| Account | `FROTHLY\mallory.kraeusen` |
| Source IP | `172.16.0.1` |
| Source workstation | `STARRAIDERS` |
| Destination | `venus.frothly.local` |
| Logon type | `3` — Network |
| Authentication | NTLMv2 |
| Logon ID | `0xB34894` |

The successful event occurred **15 seconds after** the last `mkraeusen` failure. The shared source, workstation, destination, and close timing make the events worth correlating, but **`mkraeusen` and `mallory.kraeusen` are different account names**. The evidence does not establish that the failures caused the successful login.

<img width="918" height="878" alt="8" src="https://github.com/user-attachments/assets/24e69ef0-0f17-4a04-a144-01cf08d229fb" />

*Screenshot 8 — EventCode `4624`, confirming a successful network logon from the investigated source.*

## 5. Special Privileges Assigned

A Windows Security `4672` event was recorded at **08:23:09** for `FROTHLY\mallory.kraeusen` on `venus.frothly.local`, with the same session Logon ID: `0xB34894`.

The privileges included `SeSecurityPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeDebugPrivilege`, `SeSystemEnvironmentPrivilege`, `SeLoadDriverPrivilege`, and `SeImpersonatePrivilege`.

**Important distinction:** EventCode `4672` indicates that special privileges were assigned to the logon session. It does **not** by itself prove privilege escalation, malicious privilege use, or account compromise.

<img width="1250" height="554" alt="5" src="https://github.com/user-attachments/assets/2505063a-5f83-4e3b-86ab-106c723299c9" />

*Screenshot 5 — EventCode `4672`, showing the account, Logon ID, and assigned privileges.*

## 6. Post-Authentication Review

A search associated with session `0xB34894` identified the following Windows Security events:

| EventCode | Observation |
|---|---|
| `4624` | Successful logon |
| `4672` | Special privileges assigned |
| `4634` | Session logoff, around 09:26 |

The observed session lasted approximately **one hour and three minutes**.

I also reviewed `4688` process creation events on `VENUS` between **08:23 and 09:27**. The search returned **537 events**, predominantly involving Splunk Universal Forwarder components and Windows system processes.

Three `cmd.exe` events were examined in more detail. Their command lines involved Splunk's `win_listening_ports.bat`, `netstat` with `findstr`, and `date /t`. All three ran as `NT AUTHORITY\SYSTEM`, with Logon ID `0x3E7`, **not** the investigated session ID `0xB34894`.

No `4688` record containing `0xB34894` was found in the targeted search. **No suspicious process execution was directly linked to the session in the reviewed records.** This does not rule out other activity, including remote file access, that might not appear in those process logs.

<img width="1761" height="690" alt="6" src="https://github.com/user-attachments/assets/da5a4533-03c4-4fe2-a04e-cadff3637e13" />

*Screenshot 6 — EventCode `4688` process summary for the relevant time window; the counts represent all matching host activity, not processes attributed to `mallory.kraeusen`.*

## 7. SOC L1 Assessment

**Confirmed:** The failed logon events occurred; multiple account names were targeted from one internal IP; a successful network logon followed from the same source; and the successful session received special privileges.

**Not confirmed:** Password spraying as a specific attack technique, malicious intent, unauthorized use of `mallory.kraeusen`, privilege abuse, or account compromise.

The behavior could indicate **multi-account password guessing**. Password spraying remains a possibility, but Windows authentication logs do not show whether the same password was tried against several users. The eight attempts against `administrator` could also reflect targeted guessing. Legitimate user errors or authorized activity have not been excluded.

**Detection validation:** The investigated failed-logon activity was real and consistent with the detection's purpose. This is **not** a confirmed malicious-incident verdict.

**Proposed priority:** Medium, pending further assessment.

## 8. Escalation Recommendation

I recommend escalating this case to **SOC L2** to:

1. Identify the owner and expected activity of `STARRAIDERS` (`172.16.0.1`).
2. Verify whether `FROTHLY\mallory.kraeusen` was authorized to log on to `VENUS` at that time.
3. Confirm whether the special privileges assigned to that account were expected.
4. Correlate additional endpoint, file-access, authentication, and network logs from the source and destination systems.
5. Determine whether the failed attempts and successful session are related and whether incident response is necessary.

**Final SOC L1 disposition:** Investigation completed; **escalation recommended, not yet submitted**. No confirmed compromise was established from the available evidence.

---

*Training note: This case uses the Splunk BOTS v2 dataset. Times above follow Splunk's displayed event time; the raw Windows log text uses a different clock representation. A timezone normalization check would be required before correlating with other data sources.*
