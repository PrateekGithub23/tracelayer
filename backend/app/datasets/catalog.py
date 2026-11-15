"""
Catalogue of public datasets TraceLayer can import.

Entries are pinned: a fixed URL and the SHA-256 of the exact archive that was reviewed. An import fails
if the bytes differ, so an upstream change (or a tampered mirror) can never silently enter the
evidence ledger. URLs are constants: users cannot make the server fetch arbitrary addresses (no SSRF).

Licensing was checked against the upstream LICENSE file on 2026-11-14:
  OTRF Security-Datasets: MIT (Copyright (c) 2021 Open Threat Research Forge). Redistribution is permitted
  with the copyright and permission notice, which TraceLayer shows on the dataset page and includes with samples.
"""

from dataclasses import dataclass, field
from typing import Any

OTRF_ATTRIBUTION = ("Open Threat Research Forge (OTRF) Security-Datasets, https://github.com/OTRF/Security-Datasets. "
                    "MIT License, Copyright (c) 2021 Open Threat Research Forge.")  # fmt: skip

OTRF_LICENSE_TEXT = """MIT License

Copyright (c) 2021 Open Threat Research Forge

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""  # verbatim upstream LICENSE, retrieved 2026-11-14

OTRF_FIELD_MAPPING: list[dict[str, str]] = [
    {"source": "@timestamp", "target": "timestamp", "note": "UTC from the collector; authoritative"},
    {
        "source": "EventTime",
        "target": "attributes.event_time_local",
        "note": "local time with no offset: kept, never used for ordering",
    },
    {"source": "Hostname", "target": "host (+ attributes.fqdn)", "note": "first DNS label, lower-cased"},
    {
        "source": "Channel / EventID / RecordNumber",
        "target": "attributes.channel / event_id / record_number, source_event_id",
        "note": "original identifiers preserved",
    },
    {
        "source": "Security 4624/4625 TargetUserName, IpAddress, LogonType",
        "target": "auth.login: username, src_ip, attributes.logon_type",
    },
    {
        "source": "Security 4688 NewProcessName, CommandLine, SubjectUserName",
        "target": "process.start: process, command_line, username",
    },
    {
        "source": "Sysmon 1 Image, CommandLine, User, ParentImage",
        "target": "process.start: process, command_line, username, attributes.parent_process",
    },
    {
        "source": "Sysmon 3 / Security 5156 addresses and ports",
        "target": "network.flow: src_ip, dst_ip, dst_port, process",
    },
    {"source": "Sysmon 22 QueryName", "target": "dns.query: message"},
    {"source": "Sysmon 11 TargetFilename", "target": "file.access: message"},
    {"source": "Security 4720/4722/4724/4726", "target": "iam.change: attributes.action, target_user"},
    {
        "source": "Security 4728/4732/4756 TargetUserName, MemberName",
        "target": "iam.change group_add: attributes.group, member",
    },
    {"source": "Security 1102", "target": "log.cleared"},
    {"source": "PowerShell 4104 ScriptBlockText", "target": "other: message (scanned for prompt injection)"},
    {
        "source": "any other channel/event",
        "target": "other: message (first 512 chars)",
        "note": "kept, not dropped; full record in raw",
    },
    {
        "source": "credentials in command lines",
        "target": "[REDACTED] in command_line",
        "note": "raw record unchanged (hash integrity)",
    },
]


@dataclass(frozen=True)
class Dataset:
    id: str
    name: str
    url: str
    sha256: str
    max_bytes: int
    parser: str
    license: str
    license_url: str
    attribution: str
    description: str
    environment: str
    labels: str
    redistribution: str
    role: str  # "development" (seen while building) or "held-out" (only evaluated)
    techniques: tuple[str, ...]
    ground_truth: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "source_url": self.url, "license": self.license,
                "license_url": self.license_url, "attribution": self.attribution, "description": self.description,
                "environment": self.environment, "labels": self.labels, "redistribution": self.redistribution,
                "format": "OTRF/Mordor NXLog JSON lines in a ZIP archive", "expected_sha256": self.sha256,
                "role": self.role, "techniques": list(self.techniques), "ground_truth": self.ground_truth,
                "field_mapping": OTRF_FIELD_MAPPING, "parser": self.parser}  # fmt: skip


_OTRF_LICENSE = "MIT"
_OTRF_LICENSE_URL = "https://github.com/OTRF/Security-Datasets/blob/master/LICENSE"
_LAB = ("Lab-recorded: the OTRF 'Mordor shire' simulated Active Directory environment (fictional domain "
        "THESHIRE, lab accounts). Not enterprise production data: no real users or organisations, little "
        "background activity, and only the attack window is captured.")  # fmt: skip

DATASETS: dict[str, Dataset] = {
    d.id: d
    for d in (
        Dataset(
            id="otrf-sdwin-200914080546",
            name="Empire remote WMIC add-user backdoor",
            url="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_wmic_add_user_backdoor.zip",
            sha256="88502d9a8d90f17aa638d7331120d52e7295480ea5fc4a156463399181d1c6e1",
            max_bytes=2_000_000,
            parser="otrf_windows.v3",
            license=_OTRF_LICENSE,
            license_url=_OTRF_LICENSE_URL,
            attribution=OTRF_ATTRIBUTION,
            description=(
                "An Empire agent on WORKSTATION5 runs `wmic /node:WORKSTATION6 process call create "
                '"net user /add backdoor ..."`, creating a local backdoor account on WORKSTATION6 through '
                "WMI Win32_Process.Create. Security, Sysmon, PowerShell and WMI channels from three hosts."
            ),
            environment=_LAB,
            labels=(
                "Technique-level label from OTRF metadata (SDWIN-200914080546): T1047; the adversary view also shows "
                "account creation (T1136.001). No per-event labels and no benign-only baseline, so false-positive "
                "rates cannot be computed."
            ),
            redistribution="MIT: redistribution permitted with the copyright and permission notice",
            role="development",
            techniques=("T1047", "T1136.001"),
            ground_truth={
                "attacker_host": "workstation5",
                "target_host": "workstation6",
                "actor": "pgustavo",
                "created_account": "backdoor",
                "window_utc": ["2020-09-14T12:06:02Z", "2020-09-14T12:06:04Z"],
            },
        ),
        Dataset(
            id="otrf-sdwin-200921001437",
            name="Empire Invoke-WMI remote execution",
            url="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip",
            sha256="96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88",
            max_bytes=1_500_000,
            parser="otrf_windows.v3",
            license=_OTRF_LICENSE,
            license_url=_OTRF_LICENSE_URL,
            attribution=OTRF_ATTRIBUTION,
            description=(
                "An Empire agent executes code on a remote host through the WMI Win32_Process Create method "
                "(IWbemServices::ExecMethod over DCERPC). Used as a held-out set: its events were not inspected "
                "while the v2 adapter and rules were written."
            ),
            environment=_LAB,
            labels="Technique-level label from OTRF metadata (SDWIN-200921001437): T1047. No per-event labels.",
            redistribution="MIT: redistribution permitted with the copyright and permission notice",
            role="held-out",
            techniques=("T1047",),
        ),
        Dataset(
            id="otrf-sdwin-200722001847",
            name="Empire elevated registry Run keys",
            url="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip",
            sha256="2809354d679025859d723be3ceb1e2c9f9e5dde2ebec5bbea7c398e165a9b67d",
            max_bytes=500_000,
            parser="otrf_windows.v3",
            license=_OTRF_LICENSE,
            license_url=_OTRF_LICENSE_URL,
            attribution=OTRF_ATTRIBUTION,
            description="An Empire agent sets a value under the HKLM Run key for persistence, and the persistence later executes. Used to validate TL-PERS-002 (written before this data was downloaded).",
            environment=_LAB,
            labels="Technique-level label from OTRF metadata (SDWIN-200722001847): T1547. No per-event labels.",
            redistribution="MIT: redistribution permitted with the copyright and permission notice",
            role="v3 validation",
            techniques=("T1547",),
        ),
        Dataset(
            id="otrf-sdwin-190518202151",
            name="Empire Mimikatz logonpasswords",
            url="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip",
            sha256="bb4c057b62d781be5426e011872ba1a15070c07afbb24848a14458f4b22b06fb",
            max_bytes=1_500_000,
            parser="otrf_windows.v3",
            license=_OTRF_LICENSE,
            license_url=_OTRF_LICENSE_URL,
            attribution=OTRF_ATTRIBUTION,
            description="An Empire agent runs Mimikatz sekurlsa::logonpasswords, reading credentials from lsass.exe memory. Used to validate TL-CRED-001 (written before this data was downloaded).",
            environment=_LAB,
            labels="Technique-level label from OTRF metadata (SDWIN-190518202151): T1003. No per-event labels.",
            redistribution="MIT: redistribution permitted with the copyright and permission notice",
            role="v3 validation",
            techniques=("T1003",),
        ),
        Dataset(
            id="otrf-sdwin-190319020147",
            name="Empire net localgroup Administrators",
            url="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/discovery/host/empire_shell_net_localgroup_administrators.zip",
            sha256="7331af9e09f7cb457e7b5a44494e4b2612a810ae50254c6a2d996914d66fe663",
            max_bytes=500_000,
            parser="otrf_windows.v3",
            license=_OTRF_LICENSE,
            license_url=_OTRF_LICENSE_URL,
            attribution=OTRF_ATTRIBUTION,
            description="An Empire agent enumerates the local Administrators group with net.exe. Noise control: neither v3 rule's technique is labelled here.",
            environment=_LAB,
            labels="Technique-level label from OTRF metadata (SDWIN-190319020147): T1069. No per-event labels.",
            redistribution="MIT: redistribution permitted with the copyright and permission notice",
            role="v3 validation",
            techniques=("T1069",),
        ),
    )
}
