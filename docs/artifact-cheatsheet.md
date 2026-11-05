# Windows triage artifact cheat sheet

What each artifact proves, where it lives on disk, the Eric Zimmerman / KAPE
tool that parses it, and the pitfalls that trip up a Tier 1 analyst. This is the
reference the detectors in `dfirt/` are built against.

| Artifact | Proves | On-disk location | Parser (tool) | Pitfalls |
| --- | --- | --- | --- | --- |
| **Prefetch** | **Execution** (file ran), run count, last up-to-8 run times | `C:\Windows\Prefetch\*.pf` | `PECmd.exe` -> CSV | Disabled by default on servers and on SSDs in some builds; only last 8 runs kept; file name hash is of the path, so two paths = two .pf |
| **Amcache** | Presence, usually execution, + SHA1/size/publisher | `C:\Windows\AppCompat\Programs\Amcache.hve` | `AmcacheParser.exe` -> CSV | An entry can be created by program-compatibility *scanning*, not only execution, so it is strong-but-not-proof on its own; SHA1 (not SHA256) |
| **Shimcache (AppCompatCache)** | **Presence / enumeration only** - NOT execution on Win8.1+ | `SYSTEM` hive, `ControlSet*\Control\Session Manager\AppCompatCache` | `AppCompatCacheParser.exe` -> CSV | The `Executed` flag is **not populated on Windows 8.1 / 10 / 11**; the timestamp is the file's `$SI` last-modified, not an execution time; order is most-recent-first |
| **Sysmon EventID 1** | **Execution** (process actually started), full lineage, hashes | `Microsoft-Windows-Sysmon/Operational` | `EvtxECmd.exe` or JSON export | Requires Sysmon deployed with a config; `ProcessGuid` is the stable key, not PID (PIDs are reused) |
| **Security 4688** | **Execution** (process created) | `Security.evtx` | `EvtxECmd.exe` -> CSV | Off by default; command line capture is a separate policy; no hashes |
| **Security 4624 / 4634** | Logon / logoff, with LogonType | `Security.evtx` | `EvtxECmd.exe` | Type 3 = network, Type 10 = RDP, Type 2 = interactive; map SourceNetworkAddress carefully |
| **Security 4672** | Admin/sensitive privileges at logon | `Security.evtx` | `EvtxECmd.exe` | Fires for every admin logon incl. legitimate ones |
| **Security 4769** | Kerberos TGS request (Kerberoasting signal) | `Security.evtx` (DC only) | `EvtxECmd.exe` | Only on domain controllers; `0x17` = RC4 (crackable), `0x12` = AES; machine accounts end in `$` |
| **Security 4698** / task XML | Scheduled task created / its definition | `Security.evtx`, `C:\Windows\System32\Tasks\` | `EvtxECmd.exe`, raw XML | Task XML on disk is the ground truth for the action/trigger |
| **Security 1102 / System 104** | Event log was cleared (anti-forensics) | `Security.evtx`, `System.evtx` | `EvtxECmd.exe` | A cleared log is itself evidence; reconcile with forwarded SIEM copies |
| **System 7045** | A service was installed | `System.evtx` | `EvtxECmd.exe` | PSEXESVC / PAExec / RemCom names indicate remote-exec tooling |
| **PowerShell 4104** | Script-block text (decoded) | `Microsoft-Windows-PowerShell/Operational` | `EvtxECmd.exe` | Needs Script Block Logging enabled; large scripts are split across records |
| **TerminalServices 1149** | RDP session authentication succeeded | `...TerminalServices-RemoteConnectionManager/Operational` | `EvtxECmd.exe` | 1149 is pre-logon; correlate with 4624 Type 10 |
| **Defender 5001 / 5007** | Real-time protection disabled / config changed | `Microsoft-Windows-Windows Defender/Operational` | `EvtxECmd.exe` | A legitimate admin can pause Defender; corroborate |
| **Registry Run keys** | Autostart persistence | `NTUSER.DAT` / `SOFTWARE` hive, `...\CurrentVersion\Run` | `RECmd.exe` -> CSV | Legit updaters live here too; judge by the *target path* |
| **WMI subscription (Sysmon 19/20/21)** | Fileless persistence | `OBJECTS.DATA`, Sysmon operational log | `EvtxECmd.exe` | 19 = filter, 20 = consumer, 21 = binding; the consumer holds the command |
| **$MFT** | File creation/rename truth; timestomp detection | `\$MFT` on each volume | `MFTECmd.exe` -> CSV | `$SI` times are user-writable (stompable); `$FN` times are kernel-set - compare the two |

## The execution hierarchy (most to least conclusive)

1. **Prefetch** - a `.pf` exists only because the program ran. Gives run count
   and the last 8 run times. This is proof.
2. **Sysmon 1 / Security 4688** - the kernel recorded a process starting. Proof.
3. **Amcache** - the file was present and most likely executed, but an entry can
   also come from compatibility scanning. Strong, not proof.
4. **Shimcache** - the file existed and was enumerated by the shim engine. On
   Windows 10+, the `Executed` flag is not set, so **Shimcache alone does not
   prove execution.** Presence only.

`dfirt execution <binary>` encodes exactly this hierarchy; see
[execution-evidence.md](execution-evidence.md).

## Column names used by the synthetic exports

The generator (`scripts/generate_case.py`) mirrors the real tool columns as
closely as practical. The exact columns consumed by each parser:

- **EvtxECmd**: `RecordNumber, TimeCreated, EventId, Level, Provider, Channel,
  Computer, UserName, MapDescription, RemoteHost, PayloadData1..6,
  ExecutableInfo, Payload`. Real EvtxECmd puts free text such as
  `LogonType 3` or `Target: svc_sql` in the PayloadData columns according to its
  per-event maps; the synthetic export keeps the field the detector needs in a
  fixed PayloadData slot per EventID (4769: service account, requester,
  encryption type; 7045/4697: service name, image, start type, signer) and the
  parser reads those slots.
- **PECmd**: `SourceFilename, SourceCreated, SourceModified, ExecutableName,
  Hash, RunCount, LastRun, PreviousRun0..6, Volume0Name, Directories,
  FilesLoaded` (the executable's full path is taken from `FilesLoaded`, with the
  `\VOLUME{...}` prefix mapped to `C:`)
- **AmcacheParser**: `FileKeyLastWriteTimestamp, SHA1, FullPath, Name, Size,
  ProductName, Publisher, IsOsComponent`
- **AppCompatCacheParser**: `ControlSet, CacheEntryPosition, Path,
  LastModifiedTimeUTC, Executed, Duplicate, SourceFile`
- **RECmd**: `LastWriteTimestamp, KeyPath, ValueName, ValueData, HivePath,
  Comment`
- **MFTECmd**: `EntryNumber, ParentPath, FileName, Extension, FileSize,
  Created0x10 ($SI), Created0x30 ($FN), LastModified0x10, LastModified0x30`
- **Scheduled task XML**: the Task Scheduler 1.2 schema (`RegistrationInfo/URI`,
  `Principals/Principal/UserId`, `RunLevel`, `Triggers/*`, `Actions/Exec/Command`,
  `Settings/Hidden`), parsed with the stdlib ElementTree.
- **Sysmon JSONL**: one JSON object per line with `EventID`, `UtcTime`,
  `Computer`, and the per-event fields (`ProcessGuid`, `ParentProcessGuid`,
  `Image`, `CommandLine`, `Hashes`, `GrantedAccess`, `TargetObject`, ...).
