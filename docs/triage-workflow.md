# Tier 2 endpoint triage workflow

The order of work when Tier 1 escalates a Windows endpoint, and how this repo
maps onto each step. It follows the NIST SP 800-61 detection-and-analysis phase
and RFC 3227 (order of volatility).

## 0. Accept the escalation

- Read the Tier 1 ticket: alert, host, user, first-seen time, what was already done
  (isolated? rebooted? user interviewed?). A reboot destroys memory and resets
  some artifacts, so note it.
- Open a case number and start the chain-of-custody log *before* touching the host.
- Agree the working time zone. Everything in this repo is UTC; convert local
  user statements ("I opened it after lunch") explicitly.

## 1. Contain without destroying evidence

- Prefer EDR network isolation over pulling the cable or powering off: isolation
  keeps memory and running processes intact and still lets you collect remotely.
- Do **not** reboot, run AV full scans, or "clean up" before collection. All three
  overwrite the artifacts you are about to rely on (Prefetch, Amcache, event logs).

## 2. Collect in order of volatility

| Order | What | Why it goes first | How |
| --- | --- | --- | --- |
| 1 | Memory | Lost on reboot; holds injected code, network sockets, decrypted strings, credential material | WinPMem / EDR memory capture |
| 2 | Running state | Processes, network connections, logged-on sessions, scheduled tasks in memory | EDR live response, `tasklist /v`, `netstat -ano`, `qwinsta` |
| 3 | Event logs | Can be cleared (1102) or roll over | KAPE `EventLogs` target |
| 4 | Execution / persistence artifacts | Overwritten by normal use and by remediation | KAPE targets below |
| 5 | File system metadata | `$MFT`, `$J` (USN journal), `$LogFile` | KAPE `FileSystem` target |
| 6 | Full disk image | Slowest; only if the case needs it | FTK Imager / EDR |

### KAPE targets that produce this repo's inputs

```text
kape.exe --tsource C: --tdest D:\case\WS-ACCT-07\raw --target !SANS_Triage
kape.exe --msource D:\case\WS-ACCT-07\raw --mdest D:\case\WS-ACCT-07 --module !EZParser
```

| KAPE target | Collects | EZ tool module | `case/<host>/` file |
| --- | --- | --- | --- |
| `EventLogs` | `C:\Windows\System32\winevt\Logs\*.evtx` | EvtxECmd | `*_EvtxECmd.csv`, Sysmon export as `sysmon.jsonl` |
| `Prefetch` | `C:\Windows\Prefetch\*.pf` | PECmd | `prefetch_PECmd.csv` |
| `Amcache` | `C:\Windows\AppCompat\Programs\Amcache.hve` | AmcacheParser | `amcache_AmcacheParserAssociated.csv` |
| `RegistryHivesSystem` | `SYSTEM` (Shimcache) | AppCompatCacheParser | `appcompatcache_AppCompatCacheParser.csv` |
| `RegistryHivesUser` | `NTUSER.DAT`, `UsrClass.dat` | RECmd (Run-key batch) | `runkeys_RECmd.csv` |
| `ScheduledTasks` | `C:\Windows\System32\Tasks\**` | (raw XML) | `tasks/*.xml` |
| `$MFT` | `C:\$MFT` | MFTECmd | `mft_MFTECmd.csv` |

`!SANS_Triage` is a compound target that already includes all of the above.

## 3. Hash and verify before analysis

```bash
python -m dfirt manifest case/ --out examples/MANIFEST.json   # at collection
python -m dfirt verify case/ --manifest examples/MANIFEST.json  # before every analysis session
python -m dfirt triage case/ --manifest examples/MANIFEST.json --out output/report.md
```

`triage --manifest` refuses to write a report if any file changed, went
missing, or appeared after collection. That is the property a defence expert
will test: can you show the analysed evidence is the collected evidence.

## 4. Analyse: patient zero first, then outward

1. **Initial access on the escalated host.** Rebuild the process tree
   (`python -m dfirt proctree case/WS-ACCT-07`). Look for Office or a browser
   spawning a script host, and anything running from a user-writable path.
2. **Prove execution of the payload.** `python -m dfirt execution case/ <name>`.
   Report the verdict (confirmed / probable / possible) and *why*. Never write
   "executed" on Shimcache alone.
3. **Persistence.** Run keys, services, scheduled tasks, WMI, Startup folder.
   Judge each by where it points and who wrote it; check the allowlist before
   calling it malicious.
4. **Credential access.** LSASS handles (Sysmon 10) on the host; Kerberoasting
   (4769 RC4) on the DCs. Credential access changes the scope: every account
   that could have been exposed is now in scope.
5. **Lateral movement.** On every other host, look for Type 3 / Type 10 logons
   from the compromised host or account, service installs right after a network
   logon, and RDP 1149. Each confirmed destination becomes a new "patient zero"
   for steps 1-4.
6. **Evasion and collection.** Log clears, Defender changes, timestomping,
   archives in staging directories.

## 5. Scope: when to stop expanding

Scope is the set of hosts and accounts the attacker touched. Expand it when:

- a host received a logon from an in-scope host or account,
- an in-scope account's credential could have been exposed (LSASS read,
  Kerberoast, cached creds on a host the attacker controlled),
- an IOC (hash, C2 domain, path pattern) is found on a new host.

Stop when a full pass over the in-scope hosts adds no new host or account.
In this case: WS-ACCT-07 -> FS-01 (service) and WS-ACCT-07 -> DC-01 (RDP); the
four Kerberoasted service accounts are in scope as *accounts* even though no
host shows them being used yet.

## 6. Report

`python -m dfirt triage` produces the report. Before sending, check that every
claim cites an artifact row, every time is UTC, the collection gaps section is
honest about what was not collected, and IOCs are defanged.
