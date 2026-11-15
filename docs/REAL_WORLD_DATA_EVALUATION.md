# Real-World Telemetry Evaluation

**Question:** does TraceLayer's pipeline (parsing, hashing, detection, correlation) hold up on
publicly recorded attack telemetry rather than its own synthetic scenario?

**Short answer:** the ingestion and provenance layers handled 18,661 real Windows events with zero
rejections and correct UTC ordering. The v1 detection rules *saw* the attack but mislabelled it, and had
no rule for remote WMI execution. After v2 changes written from ATT&CK definitions, a held-out dataset
was detected (1/1 labelled technique). That is a small sample from a lab, not evidence of
enterprise-grade coverage.

All numbers below are reproducible with `tracelayer dataset import <id>` and were saved to
`benchmarks/results/otrf-*.json`.

---

## 1. Dataset selection

| Candidate | Licence (checked against upstream LICENSE) | Format | Notes |
|---|---|---|---|
| **OTRF Security-Datasets (Mordor)** | **MIT**, © 2021 Open Threat Research Forge | NXLog/Logstash JSON lines in ZIP; Security, Sysmon, PowerShell, WMI channels | Small atomic datasets (10 KB–6 MB), ATT&CK-labelled metadata per dataset, lab AD environment |
| Splunk attack_data | Apache-2.0 | Raw logs per sourcetype (XML WinEventLog, JSON), Git LFS | Larger, Splunk-sourcetype oriented; good second adapter target |

OTRF was selected: permissive licence, small files, per-dataset ATT&CK labels, and a JSON format
close to what Windows collectors really emit.

### What the data is, and is not

- **Lab-recorded**: OTRF's "Mordor shire" simulated Active Directory (fictional domain `THESHIRE`,
  lab accounts such as `pgustavo`). No real people or organisations, so no personal data. The
  "credentials" in it are throwaway lab passwords.
- **Not enterprise production data**: only a ~1-minute attack window per dataset, little benign
  background, three hosts.
- **Labels are technique-level** (e.g. "T1047"), from the dataset's metadata YAML. There are **no
  per-event labels and no benign-only baseline**.

### Datasets used

| ID | Name | Role | Records | Archive SHA-256 (pinned) |
|---|---|---|---|---|
| `otrf-sdwin-200914080546` | Empire remote WMIC add-user backdoor | **development**: inspected while building | 12,278 | `88502d9a…1c6e1` |
| `otrf-sdwin-200921001437` | Empire Invoke-WMI remote execution | **held-out**: only its label metadata was read before the single evaluation run | 6,383 | `96f1dbd9…46d88` |

Imports fail if the archive's SHA-256 differs from the pinned value. Download URLs are constants in
`app/datasets/catalog.py`, so users cannot make the server fetch arbitrary URLs.

## 2. The adapter (`otrf_windows` parser)

One complete adapter rather than several partial ones. Every imported event preserves:

| Requirement | How |
|---|---|
| Original timestamp | `@timestamp` (UTC) → `timestamp`; local `EventTime` → `attributes.event_time_local` |
| Source format | `parser = otrf_windows`, `attributes.channel`, `attributes.provider` |
| Original event identifier | `attributes.event_id`, `attributes.record_number`, `attributes.source_event_id` (`fqdn/channel/record`) |
| Dataset provenance | `source = dataset:<id>`; the import row stores the archive hash, batch ids, actor and time |
| Raw event hash | unchanged pipeline: SHA-256 of source + canonical raw JSON; Merkle root per batch; hash chain |
| Normalised fields | mapping table below (also on the Datasets page) |
| Import batch | ordinary ledger batches, 5,000 records each |

Unmapped channels/event IDs are kept as `event_type = other` with the full raw record. Nothing is dropped.

### Real-world problems found by the adapter

1. **Timezone trap.** `EventTime` is wall-clock local time without an offset. In all 18,661 records it
   is exactly **−4 h** from `@timestamp` (EDT). An adapter that parsed `EventTime` would have shifted the
   whole attack by four hours and broken cross-source ordering. The parser uses `@timestamp` and
   **refuses** records that only have `EventTime`, instead of guessing.
2. **Credentials in telemetry.** The attacker's `net user /add backdoor <password>` appears in
   cleartext in 20 command lines (Sysmon 1, Security 4688, and nested in the WMIC command). Normalised
   `command_line` values are redacted (`[REDACTED]`, tag `credential_redacted`). The raw record is
   kept byte-exact because it is the evidence and its hash must still verify. Raw records are only
   visible to authenticated users.
3. **Inconsistent identities.** `THESHIRE\pgustavo` (Sysmon), `pgustavo` (Security), and `WORKSTATION6$`
   machine accounts. The parser strips the domain into `attributes.user_domain` and lower-cases names.
   Without this, the correlation engine would treat one actor as two.
4. **Group-add noise.** Event 4728 here records the new account being added to the default `None` group.
   The privilege-escalation rule correctly did **not** fire (it only matches administrative groups).

## 3. Detection results

### v1 rules on the development dataset (baseline)

| Metric | Value |
|---|---|
| Accepted / rejected | 12,278 / 0 |
| Typed (not `other`) | 428 events (3.5%) |
| Alerts | 2 × `TL-EXEC-001 Account manipulation` (one per attack host) |
| Labelled-technique recall | **0 / 2** |

The v1 rules *did* fire on the attack (`net user /add`), but tagged it **T1098 Account Manipulation**.
ATT&CK classifies creating an account as **T1136.001 Create Account: Local Account**. Remote WMI
execution (**T1047**) had no rule at all.

### v2 changes (written from ATT&CK technique definitions)

- `TL-EXEC-001`: `net user … /add` → T1136.001 (group changes stay T1098). A mapping fix.
- `TL-EXEC-002` **Process execution through WMI (T1047)**: `wmic … process call create` (with
  `/node:` target extraction), **or** `WmiPrvSE.exe` spawning a shell/LOLBin (the ATT&CK detection
  guidance for T1047).
- `TL-PERS-001` **New account created (T1136.001)**: `iam.change` with `action = account_create`.

### v2 results

| Dataset | Role | Alerts | Alerts on labelled technique | Technique recall | Correlation |
|---|---|---|---|---|---|
| Dev (`…200914080546`) | seen during development | 5 | 5 | 2 / 2 | 1 investigation, "execution → persistence", single source |
| **Held-out** (`…200921001437`) | **unseen** | 2 | 1 | **1 / 1** | 1 investigation, single source |

Held-out alerts:
- `TL-EXEC-002` T1047: *WmiPrvSE spawned powershell.exe on workstation6*. This came from the generic
  branch. This dataset never uses `wmic.exe`, so the dev-specific branch could not have helped.
- `TL-EXEC-001` T1059.001: *Encoded PowerShell on workstation6*, at the same time, same user.
  Consistent with Empire's stager, but **not in the OTRF label**. It is counted as neither a true nor
  a false positive.

**Not reported:** alert precision, F1, and false-positive rates. The datasets have no per-event labels
and no benign baseline, so any such number would be invented.

### Unexpected correlations

None. Each dataset produced one investigation containing only its own events. On a database that
also holds the synthetic scenario, the two did not merge: different hosts, users and time ranges.
This is checked by `cross_source_correlations` on every import.

## 4. Where the normalised schema loses information

96.5% (dev) and 98.3% (held-out) of events map to `other`. The largest unmapped groups:

| Source | Dev count | Lost meaning |
|---|---|---|
| Sysmon 10 (ProcessAccess) | 1,655 | process-to-process handle access (e.g. LSASS reads): key for credential-dumping detection |
| Sysmon 12/13 (Registry) | 2,639 | registry persistence and defence-evasion changes |
| Security 5447/5158/5154 (WFP) | 4,095 | firewall filter changes, binds, listens |
| Sysmon 7 (ImageLoad) | 1,262 | DLL loads (e.g. `wbemcomn.dll` hijacks) |
| Security 4656/4658/4663 (object access) | ~1,200 | file/registry object auditing |

The raw records are retained, so this is lost *queryability* and *detectability*, not lost data.
Adding `process.access` and `registry.change` event types is the highest-value next step.

## 5. Performance on real records

| Dataset | Records | Ingest (parse + hash + persist) | Detect + correlate |
|---|---|---|---|
| Dev | 12,278 | 1,236 ms (~9,900 events/s) | 113 ms |
| Held-out | 6,383 | 606 ms (~10,500 events/s) | 51 ms |

SQLite, MacBook Air (Apple Silicon, 16 GB). Real records average ~2.2 kB of raw JSON, several times
the synthetic events. This is why throughput is about half the ~22k events/s synthetic benchmark.

## 6. Limitations

- Two small lab datasets and one held-out technique are not a coverage claim.
- The development dataset was inspected while writing the v2 rules, so its 2/2 is optimistic by
  construction. The held-out 1/1 is the honest generalisation figure, with n = 1.
- No benign traffic means rule noise on a real network is unmeasured. A benign corpus would be needed
  before quoting any false-positive rate.
- Only the host-log ZIPs were used. OTRF's network captures (PCAP/Zeek) for the same scenarios were not.
