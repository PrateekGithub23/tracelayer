# Real-World Telemetry Evaluation

> **v3 update (2026-11-15):** normalisation coverage rose from 3.5% typed to 97.7–99.8% *fully* normalised,
> two new rules were validated on fresh labelled datasets, and three real-data bugs were fixed. See
> [v3: normalisation coverage and detection](#v3-normalisation-coverage-and-detection) at the end. The v2 sections
> below are kept as the historical record.

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


---

## v3: normalisation coverage and detection

### Why ~97% of events were "other" in v2

They were **not rejected**: every record was accepted, hashed and stored with its raw content. They were
*raw-only*: the v2 adapter mapped only about a dozen (channel, event id) pairs. Investigation of all 18,661
events (82 distinct channel and event-id pairs) showed four causes:

1. **Unmapped event classes:** Sysmon process access (10), registry (12/13), image load (7), object-access
   auditing (4656/4658/4663/4690), Windows Filtering Platform bind/listen/policy (5154/5158/5447), PowerShell
   pipeline (800/4103), logon context (4627), and privilege use (4672/4673/4674/4703).
2. **A real bug:** the channel name appears as both `Security` and `security` in the same dataset. v2
   compared it case-sensitively, so even *supported* events (e.g. network connections, 5156) fell through.
3. **Rich fields discarded:** process GUIDs, PIDs, parent paths, user SIDs, logon ids, hashes and integrity
   levels were present but not normalised, so parent-child relationships could not be followed.
4. **Free-text details:** PowerShell 800 and 4103 put the host command line (here Empire's
   `powershell -noP -enc …` launcher) in key/value text with inconsistent spacing (`HostApplication=` vs
   `Host Application = `).

### What v3 changed

A **versioned** adapter, `otrf_windows.v3` (50 mappings), with schema `tl-event/3`, OCSF-style class hints
(class *names* only; not an OCSF-compliant format), identity, device, process, parent, network, registry and
module fields, credential redaction (also in parent command lines and registry values), and **per-event
normalisation diagnostics**: `full`, `partial` (with missing fields named) or `raw_only` (with the reason).

Events are immutable evidence and verification re-runs the recorded parser, so v2 is **frozen** (existing
events still verify, as tested). An owner-only, audited `tracelayer dataset renormalize` moves events to v3
without touching raw records, hashes, ids or batches (also tested).

**Classification criteria were fixed before measuring.** `full` means every field *that source event
provides* for its type was normalised. While auditing the result, one criterion was found too lenient (WMI
events counted as full with just a message) and was **tightened**, which lowered the full count; one
extraction bug (PowerShell key spacing) was **fixed**, which raised it. Both are recorded in the git history.

### Coverage results (same parser, same criteria, all five datasets)

| Dataset | Records | Rejected | Full | Partial | Raw-only | v2 typed |
|---|---|---|---|---|---|---|
| Empire WMIC backdoor (dev) | 12,278 | 0 | **99.59%** | 0.03% | 0.37% | 3.5% |
| Empire Invoke-WMI (v2 held-out) | 6,383 | 0 | **97.74%** | 1.55% | 0.70% | 1.7% |
| Empire Run keys (v3 validation) | 657 | 0 | **99.24%** | 0.00% | 0.76% | n/a |
| Empire Mimikatz logonpasswords (v3 validation) | 6,026 | 0 | **99.80%** | 0.02% | 0.18% | n/a |
| Empire net localgroup (v3 control) | 884 | 0 | **99.66%** | 0.00% | 0.34% | n/a |

Remaining partials are genuine source gaps (e.g. 94 PowerShell 800 messages truncated before the host
application line). Remaining raw-only events: Security 4670/4769/4702/5058/5061, Sysmon 2/23, TaskScheduler
129, PowerShell 400/600. They are listed, with counts and reasons, on **Datasets → Telemetry coverage**.

Caveat: field profiling for this work looked at both v2 datasets, so the v2 held-out dataset is **no longer
unseen** for anything built in v3. New rules were therefore validated only on datasets downloaded after the
rules were committed.

### Detection results (13 rules, v3 parser)

| Dataset (OTRF label) | Alerts | Labelled technique detected | Notes |
|---|---|---|---|
| WMIC backdoor (T1047, T1136.001) | 5 | 2 / 2 | unchanged from v2: no new noise from 4× more typed events |
| Invoke-WMI (T1047) | 2 | 1 / 1 | plus encoded PowerShell (T1059.001), consistent with Empire's stager but not in the label |
| **Run keys (T1547)** | **1** | **1 / 1** | TL-PERS-002: `powershell.exe` set autostart value `Updater` |
| **Mimikatz (T1003)** | **1** | **1 / 1** | TL-CRED-001: `powershell.exe` opened `lsass.exe` with `0x1010` |
| net localgroup (T1069) | 0 | 0 / 1 | **miss**: no discovery rule exists; also shows the new rules stayed silent |

TL-CRED-001 and TL-PERS-002 were committed (`459eb26`) **before** their validating datasets were
downloaded. Across the five datasets, the two new rules fired exactly once each, both times on their
labelled technique. Five small lab datasets cannot establish a false-positive rate; none is claimed.

No unexpected cross-source correlations occurred (each dataset produced at most one case, from its own events).
