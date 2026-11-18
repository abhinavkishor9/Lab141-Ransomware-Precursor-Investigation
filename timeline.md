# Lab 141 – Investigation Timeline

## 18 November 2026

| Time (IST) | Activity | Evidence / Observation | Assessment |
|---|---|---|---|
| 12:20:35 | Sysmon telemetry review | Recent Event ID 1 and Event ID 11 records were present. | Confirms recent Sysmon event generation. |
| 12:20:40 | Sysmon service validation | Sysmon64 service reported Running. | Monitoring service was running. |
| 12:24 (approx.) | Defender status review | Defender health events reported protection features as disabled. | Required additional configuration context. |
| 12:41:14 | Wazuh VSS event | Rule 60702 reported VSS service shutdown due to idle timeout. | Informational VSS event; no deletion reported. |
| During investigation | Controlled PowerShell execution | Lab141 controlled PowerShell execution completed successfully. | Harmless test command. |
| During investigation | Shadow-copy inspection | `vssadmin.exe list shadows` returned no items. | No shadow copies listed at inspection time. |
| During investigation | Backup status inspection | `wbadmin.exe get status` reported no active operation. | No backup or recovery operation running. |
| During investigation | Boot configuration inspection | Current Windows Boot Loader entry displayed through `bcdedit`. | No suspicious modification established from displayed values. |
| During investigation | Event-log metadata inspection | `wevtutil.exe gli System` returned log metadata and record count. | System log metadata was available. |
| During investigation | Wazuh validation | Manager active and Windows agent 001 listed as active. | Wazuh components were available. |

## 24-Hour Sysmon Event ID 11 Baseline

The following counts were obtained by grouping Sysmon Event ID 11 records by minute.

| Date and Time (IST) | Event Count | Observation |
|---|---:|---|
| 17 Nov 13:32 | 182 | Elevated file-creation activity |
| 17 Nov 14:50 | 23 | Moderate increase |
| 17 Nov 16:20 | 183 | Elevated file-creation activity |
| 17 Nov 17:43 | 81 | Elevated file-creation activity |
| 17 Nov 18:01 | 46 | Elevated file-creation activity |
| 18 Nov 11:46 | 26 | Moderate increase |

Most other observed minutes contained approximately 11–14 events.

These counts identify periods requiring further investigation. The responsible processes and target paths were not conclusively attributed.

## Investigation Summary

- Sysmon telemetry was available.
- Wazuh manager and Windows agent were active when checked.
- No shadow copies were listed during inspection.
- No backup or recovery operation was running during inspection.
- Defender was observed in SxS Passive Mode during further checks.
- Wazuh recorded an informational VSS idle-timeout event.
- No matching event-log clearing records were identified in the queried 30-day history.
- Elevated file-creation periods were identified but not conclusively attributed.

## Timeline Limitations

- PowerShell timestamps were displayed in local time (IST).
- The Wazuh event timestamp was `2026-11-18T07:11:14.8906972Z` in UTC, equivalent to approximately `12:41:14 IST`.
- Entries marked During investigation do not have exact timestamps in the supplied evidence.
- The timeline records observed checks and telemetry, not an assumed sequence of attacker actions.
