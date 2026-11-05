# Key events (rows cited by triage findings)

34 events, all times UTC. Synthetic case data.

| Time (UTC) | Host | Source:row | Kind | Actor | Detail |
| --- | --- | --- | --- | --- | --- |
| 2026-10-19T13:06:00.000Z | WS-ACCT-07 | sysmon.jsonl:6 | process_create | NORTHWIND\jsmith | winword.exe -> powershell.exe :: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAEkATgBFAFIAVAAtAFMA |
| 2026-10-19T13:06:04.000Z | WS-ACCT-07 | sysmon.jsonl:7 | sysmon:dns_query | powershell.exe | DNS sync-cdn.example -> type:  5 198.51.100.25; |
| 2026-10-19T13:06:05.000Z | WS-ACCT-07 | sysmon.jsonl:8 | sysmon:network_connect | powershell.exe | -> 198.51.100.25:443 sync-cdn.example |
| 2026-10-19T13:06:30.112Z | WS-ACCT-07 | mft_MFTECmd.csv:1 | mft:file_created | - | $FN created \Users\jsmith\AppData\Roaming\Microsoft\svchost.exe ($SI claims 2019-03-19T04:10:11.000Z |
| 2026-10-19T13:06:31.000Z | WS-ACCT-07 | sysmon.jsonl:10 | process_create | NORTHWIND\jsmith | powershell.exe -> svchost.exe :: "C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe" |
| 2026-10-19T13:06:40.000Z | WS-ACCT-07 | runkeys_RECmd.csv:1 | registry:run_key | - | Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync = C:\Users\jsmith\AppData\Roaming\Microso |
| 2026-10-19T13:06:40.000Z | WS-ACCT-07 | sysmon.jsonl:12 | sysmon:registry_set | svchost.exe | HKU\S-1-5-21-1988-1001\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync = C:\Users\jsmith\ |
| 2026-10-19T13:06:45.000Z | WS-ACCT-07 | tasks/MicrosoftEdgeUpdateTaskUser.xml | scheduled_task | NORTHWIND\jsmith | MicrosoftEdgeUpdateTaskUser -> C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe |
| 2026-10-19T13:07:00.000Z | WS-ACCT-07 | Security_EvtxECmd.csv:4 | security:task_create | jsmith | 4698 task MicrosoftEdgeUpdateTaskUser -> C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe |
| 2026-10-19T13:07:10.000Z | WS-ACCT-07 | sysmon.jsonl:14 | sysmon:process_access | - | svchost.exe -> lsass.exe 0x1410 |
| 2026-10-19T13:08:00.000Z | WS-ACCT-07 | sysmon.jsonl:15 | sysmon:wmi_subscription | - | WMI filter NorthwindUpdater: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstanc |
| 2026-10-19T13:08:01.000Z | WS-ACCT-07 | sysmon.jsonl:16 | sysmon:wmi_subscription | - | WMI consumer NorthwindUpdater (CommandLineEventConsumer) -> "C:\Users\jsmith\AppData\Roaming\Microso |
| 2026-10-19T13:08:02.000Z | WS-ACCT-07 | sysmon.jsonl:17 | sysmon:wmi_subscription | - | WMI binding NorthwindUpdater -> NorthwindUpdater |
| 2026-10-19T13:08:30.000Z | WS-ACCT-07 | sysmon.jsonl:18 | process_create | NORTHWIND\jsmith | svchost.exe -> net.exe :: net user /domain |
| 2026-10-19T13:09:00.000Z | WS-ACCT-07 | Defender_EvtxECmd.csv:1 | defender:defender_rtp_disabled | jsmith | Microsoft Defender Real-time Protection disabled |
| 2026-10-19T13:10:00.000Z | DC-01 | Security_EvtxECmd.csv:2 | security:kerberos_tgs | jsmith | TGS svc_sql etype=0x17 |
| 2026-10-19T13:10:12.000Z | DC-01 | Security_EvtxECmd.csv:3 | security:kerberos_tgs | jsmith | TGS svc_web etype=0x17 |
| 2026-10-19T13:10:25.000Z | DC-01 | Security_EvtxECmd.csv:4 | security:kerberos_tgs | jsmith | TGS svc_fileshare etype=0x17 |
| 2026-10-19T13:10:41.000Z | DC-01 | Security_EvtxECmd.csv:5 | security:kerberos_tgs | jsmith | TGS svc_erp etype=0x17 |
| 2026-10-19T13:15:10.000Z | FS-01 | Security_EvtxECmd.csv:1 | security:logon | jsmith | LogonType 3 from 10.20.5.17 |
| 2026-10-19T13:15:11.000Z | FS-01 | Security_EvtxECmd.csv:2 | security:special_privileges | jsmith | Special privileges assigned to new logon |
| 2026-10-19T13:15:15.000Z | FS-01 | Security_EvtxECmd.csv:3 | security:service_install | jsmith | service PSEXESVC (C:\Windows\PSEXESVC.exe) |
| 2026-10-19T13:15:15.000Z | FS-01 | System_EvtxECmd.csv:2 | system:service_install | SYSTEM | service PSEXESVC (%SystemRoot%\PSEXESVC.exe) |
| 2026-10-19T13:15:20.000Z | FS-01 | sysmon.jsonl:2 | process_create | NT AUTHORITY\SYSTEM | services.exe -> psexesvc.exe :: C:\Windows\PSEXESVC.exe |
| 2026-10-19T13:16:00.000Z | FS-01 | sysmon.jsonl:4 | process_create | NT AUTHORITY\SYSTEM | cmd.exe -> net.exe :: net view \\DC-01 |
| 2026-10-19T13:19:58.000Z | DC-01 | TerminalServices_EvtxECmd.csv:1 | terminalservices:event_1149 | jsmith | Remote Desktop Services: User authentication succeeded |
| 2026-10-19T13:20:00.000Z | DC-01 | Security_EvtxECmd.csv:6 | security:logon | jsmith | LogonType 10 from 10.20.5.17 |
| 2026-10-19T13:20:01.000Z | DC-01 | Security_EvtxECmd.csv:7 | security:special_privileges | jsmith | Special privileges assigned to new logon |
| 2026-10-19T13:20:30.000Z | DC-01 | sysmon.jsonl:3 | process_create | NORTHWIND\jsmith | cmd.exe -> net.exe :: net group "domain admins" /domain |
| 2026-10-19T13:20:45.000Z | DC-01 | sysmon.jsonl:4 | process_create | NORTHWIND\jsmith | cmd.exe -> nltest.exe :: nltest /dclist:northwind.example |
| 2026-10-19T13:21:00.000Z | DC-01 | sysmon.jsonl:5 | process_create | NORTHWIND\jsmith | cmd.exe -> whoami.exe :: whoami /all |
| 2026-10-19T13:25:00.000Z | FS-01 | sysmon.jsonl:5 | process_create | NT AUTHORITY\SYSTEM | cmd.exe -> 7za.exe :: 7za.exe a -p<redacted> C:\PerfLogs\data.7z \\FS-01\Finance\* |
| 2026-10-19T13:25:40.000Z | FS-01 | sysmon.jsonl:6 | sysmon:file_create | system | wrote C:\PerfLogs\data.7z |
| 2026-10-19T13:30:00.000Z | FS-01 | Security_EvtxECmd.csv:4 | security:log_cleared | jsmith | The audit log was cleared by NORTHWIND\jsmith |
