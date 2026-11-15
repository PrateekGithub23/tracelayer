# Sample log files

Synthetic files (seed 11) for trying the upload flow in **Ingest & system**. The data is generated; the parsing and analysis applied to it are real.

| File | Format (parser) | Notes |
|---|---|---|
| `native-events.ndjson` | TraceLayer JSON, one event per line (`native`) | background noise plus the full intrusion |
| `sshd-auth.log` | OpenSSH syslog lines (`sshd`) | SSH brute force on `bastion-01`; set the log year to **2026** |
| `winsec-events.json` | Windows Security JSON array (`winsec`) | 4728 group add, 4688 `wevtutil`, 1102 log cleared |

After uploading, click **Run detection + correlation**. Uploading the same file twice shows deduplication (every record is reported as a duplicate).
