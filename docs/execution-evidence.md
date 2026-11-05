# Proving execution: the confidence model

A Tier 1 analyst sees a hit and closes the ticket. A Tier 2 analyst has to
*prove* that a binary ran, to whom and when, and defend that claim in a report.
Different artifacts carry very different evidentiary weight, and the single most
common mistake is treating a Shimcache entry as proof of execution. It is not.

`dfirt/execution.py` implements the model below; `dfirt execution <binary>`
runs it over a case.

## The four confidence levels

| Confidence | Meaning | Triggered by |
| --- | --- | --- |
| **confirmed** | The binary executed; defensible in a report | Any proof-grade source: Prefetch, Sysmon EventID 1, or Security 4688 |
| **probable** | Present and most likely executed, with a caveat | Amcache entry, but no proof-grade source |
| **possible** | The file existed and was enumerated - NOT proof it ran | Shimcache only |
| **none** | No supporting artifact found | - |

## Why each source sits where it does

**Prefetch - proof.** Windows writes `C:\Windows\Prefetch\<NAME>-<HASH>.pf` the
first time a program runs and updates it on subsequent runs. The file's very
existence means the program executed. PECmd also recovers the run count and the
last up-to-eight run times, which lets you place the execution on a timeline.
Caveat for the report: Prefetch may be disabled on servers and on some SSD
configurations, so its *absence* proves nothing.

**Sysmon 1 / Security 4688 - proof.** These are process-creation events emitted
by the kernel as the process starts. They carry the full command line and, for
Sysmon, the image hashes and the parent lineage. If you have one of these, the
process ran.

**Amcache - strong, not proof.** Amcache records a file's metadata (SHA1, size,
publisher, first-seen) when the system references it. In the large majority of
cases an Amcache entry corresponds to execution, but entries can also be created
by the Program Compatibility Assistant scanning a directory. So Amcache on its
own is "probable", and the report should say "present, execution likely" rather
than "executed".

**Shimcache - presence only.** The AppCompatCache (Shimcache) stores a path and
the file's `$StandardInformation` last-modified time when the application
compatibility engine sees the file - for example when a directory is browsed.
Crucially, on **Windows 8.1, 10 and 11 the `Executed` flag is not populated**
(it existed on Windows 7 / XP). So a Shimcache entry tells you the file *existed*
and was *enumerated*, not that it *ran*. Reporting a Shimcache-only hit as
"executed" is a factual error that a defense expert will catch.

## Worked examples from this case

`python -m dfirt execution case svchost.exe` splits the bare name by full path,
because evidence for `C:\Windows\System32\svchost.exe` must never be counted
for the masquerading copy in AppData (or the other way round):

```text
[WS-ACCT-07] C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe
  verdict : CONFIRMED (proves execution: True)
  sources : amcache, evt4688, prefetch, shimcache, sysmon1
  prefetch: run count 3; last runs 2026-10-19T14:02:11.000Z, 2026-10-19T13:31:05.000Z, 2026-10-19T13:06:31.000Z
  ...
[WS-ACCT-07] C:\Windows\System32\svchost.exe
  verdict : CONFIRMED (proves execution: True)
  sources : amcache, shimcache, sysmon1
```

The three Prefetch run times line up with the story: the first run at drop
time (13:06:31), then two later runs triggered by its persistence. The payload's
Shimcache `LastModifiedTimeUTC` is 2019-03-19, the *backdated* `$SI` time.
That is a second reason not to read Shimcache times as execution times: they
are file modification times, and an attacker can set them.

The case also holds a binary that appears **only** in Shimcache, a portable
tool the user downloaded a week earlier and never ran:

```text
$ python -m dfirt execution case procexp64.exe
[WS-ACCT-07] C:\Users\jsmith\Downloads\ProcessExplorer\procexp64.exe
  verdict : POSSIBLE (proves execution: False)
  sources : shimcache
  why     : Only Shimcache references this path. Shimcache records that the file
            existed and was enumerated by the shim engine; on Windows 8.1/10/11 the
            'Executed' flag is not populated, so this is NOT evidence of execution.
```

The honest finding is "present on disk, no evidence it ran". Tests in
`tests/test_execution.py` pin each of these verdicts.

## Common reporting mistakes

| Mistake | Correct statement |
| --- | --- |
| "Shimcache shows it ran at 04:10" | "Shimcache shows the file was present; 04:10 is its `$SI` modified time" |
| "No Prefetch, so it never ran on the DC" | "Prefetch is off by default on Server; absence is not evidence" |
| "Amcache proves execution" | "Amcache shows presence and probable execution" |
| "svchost.exe executed" (one name, two binaries) | Cite the full path and its hash |
