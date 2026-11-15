# Detection Rules

13 deterministic, ATT&CK-mapped rules (`backend/app/detection/rules.py`). Every rule is an O(n) pass over
time-ordered events (sliding windows or bursts; no pairwise comparisons). Detections are idempotent: the id
derives from rule, entity and window start. **v3:** a late-arriving event that overlaps an existing
detection of the same rule extends that detection instead of creating a duplicate.

**Evidence base.** *Synthetic* is the seeded 7-stage scenario; recall 1.0 and 0 false positives on
100,000 benign background events (PERFORMANCE.md), but the background is generated, so this is not a
real-world false-positive rate. *OTRF* is five public lab datasets (REAL_WORLD_DATA_EVALUATION.md).
**No real-world false-positive rate is claimed for any rule:** the public datasets have no benign-only
ground truth.

| Rule | Technique | Purpose | Required fields | Condition / window | Evidence |
|---|---|---|---|---|---|
| TL-AUTH-001 Password brute force | T1110 | Many failed logins from one source | `auth.login` failure, `src_ip` | ≥ 10 failures from one IP within 10 min | Synthetic ✓ (42 failures). OTRF: none present |
| TL-AUTH-002 Success after failures | T1078 | A guess that worked | `auth.login`, `src_ip`, `outcome` | Success from an IP with ≥ 5 failures in the previous 30 min | Synthetic ✓ |
| TL-AUTH-003 Impossible travel | T1078 | Same account, distant places, too fast | `auth.login` success, `username`, `country` | Great-circle speed > 900 km/h between consecutive logins | Synthetic ✓. OTRF has no geo fields |
| TL-EXEC-001 Suspicious command execution | T1059 / T1003 / T1105 / T1136.001 / T1098 … | Known tradecraft in command lines | `process.start` `command_line` | Signature match (encoded PowerShell, certutil download, mimikatz, LSASS minidump, `net user /add`, shadow-copy deletion, …); bursts ≤ 60 min | Synthetic ✓. OTRF ✓ (`net user /add`, encoded PowerShell) |
| TL-PRIV-001 Privileged group change | T1098 | Membership of admin groups | `iam.change` `group_add`, `group`, `member` | Group ∈ {Administrators, Domain Admins, Enterprise Admins, sudo, wheel, admins} | Synthetic ✓. OTRF: correctly silent on a "None"-group add |
| TL-LAT-001 Rapid multi-host logons | T1021 | One account fanning out | `auth.login` success, `username`, `host` | ≥ 5 distinct hosts within 30 min | Synthetic ✓ |
| TL-EXFIL-001 Large outbound transfer | T1048 | Data leaving to an external IP | `network.flow` `bytes_out`, external `dst_ip` | ≥ 50 MB in 60 min (critical ≥ 500 MB) | Synthetic ✓ (384 MiB). OTRF flows carry no byte counts |
| TL-DEF-001 Security log cleared | T1070.001 | Evidence destruction | `log.cleared`, or a `process.start` command line | Event 1102, or `wevtutil cl`, `Clear-EventLog`, `history -c` | Synthetic ✓ |
| TL-AI-001 Instructions aimed at AI | ATLAS AML.T0051 | Prompt injection planted in logs | any event's `tags` | Ingest-time `llm_injection_suspected` tag | Synthetic ✓ |
| TL-EXEC-002 Process execution through WMI | T1047 | Remote/local process creation via WMI | `process.start`, `command_line`, `parent_process` | `wmic … process call create`, or `WmiPrvSE.exe` spawning a shell/LOLBin; bursts ≤ 30 min | OTRF dev ✓; **OTRF v2 held-out ✓** (via the WmiPrvSE branch) |
| TL-PERS-001 New account created | T1136.001 | Account creation | `iam.change` `account_create` | Security 4720 | OTRF dev ✓ |
| TL-CRED-001 LSASS memory access *(v3)* | T1003.001 | Credential dumping | `process.access`, `target_process`, `granted_access` | Target `lsass.exe`, read-capable mask (e.g. 0x1010, 0x1410, 0x1fffff), source not a known system accessor; bursts ≤ 30 min | **Fresh OTRF Mimikatz dataset ✓** (written before download); 0 alerts on four other datasets |
| TL-PERS-002 Registry Run key *(v3)* | T1547.001 | Autostart persistence | `registry.change` (Sysmon 13), `registry_key` | Value set under `…\CurrentVersion\Run`, `RunOnce`, `RunServices*`, `Policies\Explorer\Run` | **Fresh OTRF Run-key dataset ✓** (written before download); 0 alerts on four other datasets |

## Known false-positive scenarios

| Rule | Will fire on benign activity such as | Mitigation available |
|---|---|---|
| TL-AUTH-001 | A misconfigured service retrying a stale password; a user locked out after a password change | Allow-list service sources; tune the threshold per environment |
| TL-AUTH-002 | A user who forgets their password and then gets it right | Severity is high because of the pattern, so the analyst confirms |
| TL-AUTH-003 | VPNs, cloud egress, mobile carriers, inaccurate GeoIP | Treat as a correlation input, not a verdict |
| TL-EXEC-001 | Admin scripts using `-EncodedCommand`; IT using `certutil` legitimately; help-desk account provisioning (`net user /add`) | Context from correlation and the case owner |
| TL-PRIV-001 | Planned admin onboarding | Change-ticket correlation (not implemented) |
| TL-LAT-001 | Admins and backup or monitoring accounts that touch many hosts | Service-account allow-list |
| TL-EXFIL-001 | Backups and large uploads to sanctioned cloud storage | Destination allow-list |
| TL-DEF-001 | Log rotation scripts that clear logs | Rare in practice; always worth a look |
| TL-EXEC-002 | SCCM/Intune and management tools that use WMI | Parent and child allow-lists |
| TL-PERS-001 | Normal account provisioning | Correlate with the actor's role |
| TL-CRED-001 | EDR/AV products, crash-dump tools, Task Manager "create dump file" | Benign source list (7 entries); extend per environment |
| TL-PERS-002 | Software installers and updaters registering autostart entries | Signed-publisher allow-list (not implemented) |

## Telemetry limitations

- **Coverage depends on what is logged.** TL-CRED-001 needs Sysmon event 10 with a configuration that logs
  LSASS access; TL-PERS-002 needs Sysmon registry events; TL-EXEC-001 needs command-line auditing (4688
  with command lines, or Sysmon 1). Without them, these rules are blind, and the case view lists
  "telemetry blind spots" per host.
- **OTRF flows have no byte counts**, so TL-EXFIL-001 cannot fire on that data.
- **No geolocation in Windows logs**, so TL-AUTH-003 depends on sources that supply a country.
- **Not covered:** discovery techniques (the T1069 control dataset produced no alert: correctly silent
  for TL-CRED-001/TL-PERS-002, but a gap), Kerberos attacks (4769 is raw-only), scheduled tasks, services
  (7045/4697), DLL hijacking (Sysmon 7 is normalised, but no rule uses it yet), and named-pipe C2 patterns.

## Quality checks in the test suite

`test_detection.py` (v1 thresholds and false-positive regressions at scale), and `test_detection_v3.py`:
LSASS masks and benign accessors; Run-key exact paths (a `\Runtime\` look-alike is ignored, and key
creation is not a value set); timezone offsets converging on one UTC burst; duplicates adding nothing;
late arrivals extending the existing detection; and a missing `GrantedAccess` never being guessed.
