# Lab 141 – Investigation Notes

## 1. Investigation Overview

The objective was to examine Windows endpoint activity that could be associated with ransomware preparation. Particular attention was given to recovery interference, security-control status, suspicious process execution, event-log integrity, and unusual file activity.

The investigation used PowerShell, Sysmon, and Wazuh. Only non-destructive inspection and controlled test execution were performed.

## 2. Controlled PowerShell Execution

A harmless PowerShell command was executed:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Lab141 controlled PowerShell execution'"
```

Observed output:

```text
Lab141 controlled PowerShell execution
```

The command completed successfully.

This provided a controlled execution example for the lab. It was not a malicious payload and did not perform any system modification.

## 3. Volume Shadow Copy Inspection

Command:

```powershell
vssadmin.exe list shadows
```

Observed result:

```text
No items found that satisfy the query.
```

### Assessment

No Volume Shadow Copies were listed at the time of inspection.

This result does not establish why shadow copies were unavailable. They may not have been created, may have expired, or may have been removed through normal administration or another process.

No malicious deletion was established from this command output.

## 4. Windows Backup Status

Command:

```powershell
wbadmin.exe get status
```

Observed result:

```text
ERROR - No backup or recovery operation is currently running.
```

### Assessment

No backup or recovery operation was running when the command was executed.

This does not establish whether backup schedules exist, whether backup data is available, or whether a backup catalog was deleted.

## 5. Boot Configuration Inspection

Command:

```powershell
bcdedit.exe /enum "{current}"
```

The current Windows Boot Loader entry contained:

| Setting | Observed Value |
|---|---|
| Identifier | `{current}` |
| Device | `partition=C:` |
| OS Device | `partition=C:` |
| Path | `\WINDOWS\system32\winload.efi` |
| Description | Windows 11 |
| NX | `OptIn` |
| Boot Menu Policy | `Standard` |
| Hypervisor Launch Type | `Auto` |

### Assessment

The displayed configuration did not establish suspicious boot-recovery tampering.

No conclusion was drawn about settings that were not displayed in the output.

## 6. Microsoft Defender Status

Command:

```powershell
Get-MpComputerStatus |
Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
```

Observed result:

| Property | Value |
|---|---|
| AntivirusEnabled | True |
| RealTimeProtectionEnabled | False |
| BehaviorMonitorEnabled | False |

Further inspection reported:

```text
AMRunningMode : SxS Passive Mode
```

McAfee components were also registered with Windows Security Center. McAfee Framework Host and WebAdvisor services were observed running.

### Assessment

Defender's passive mode provides a plausible configuration explanation for its inactive protection features.

The available evidence does not establish that an attacker disabled Defender. The registration and service information also does not independently confirm that McAfee's antivirus engine was fully operational.

## 7. Windows Event Log Inspection

Command:

```powershell
wevtutil.exe gli System
```

Observed metadata:

| Property | Value |
|---|---|
| Creation Time | `2026-08-30T09:25:07.8522055Z` |
| Last Access Time | `2026-11-18T06:54:02.0389084Z` |
| Last Write Time | `2026-11-18T06:54:02.0389084Z` |
| File Size | `20975616` bytes |
| Number of Records | `40098` |
| Oldest Record Number | `56079` |

The event history was also checked for:

- Security Event ID `1102` – Security audit log cleared.
- System Event ID `104` – Event log cleared.

No matching records were found in the queried 30-day history.

### Assessment

No evidence of these specific event-log clearing events was identified in the available queried history.

This does not prove that logs have never been cleared. Event retention and collection coverage remain relevant limitations.

## 8. Sysmon Monitoring Validation

Command:

```powershell
Get-Service -Name Sysmon64
```

Observed result:

```text
Status   Name      DisplayName
------   ----      -----------
Running  Sysmon64  Sysmon64
```

Recent Sysmon events were inspected:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
Select-Object TimeCreated, Id, Message
```

Recent records included:

- Event ID `1` – Process Create.
- Event ID `11` – File Create.

### Assessment

Sysmon was running and generating endpoint telemetry during the investigation.

The presence of recent events confirms event generation but does not independently establish that every relevant endpoint action was captured.

## 9. File-Creation Activity Baseline

Sysmon Event ID 11 records from the preceding 24 hours were grouped by minute.

Several elevated periods were identified:

| Date and Time | Event Count |
|---|---:|
| 17 Nov 13:32 | 182 |
| 17 Nov 14:50 | 23 |
| 17 Nov 16:20 | 183 |
| 17 Nov 17:43 | 81 |
| 17 Nov 18:01 | 46 |
| 18 Nov 11:46 | 26 |

Most other observed minutes contained approximately 11–14 events.

### Assessment

The elevated counts indicate periods of increased file-creation activity.

Event volume alone does not establish ransomware encryption. Legitimate application activity, updates, installations, and background operations can also generate high file-event volumes.

Further investigation should correlate:

- Process image.
- Target file path.
- User account.
- Event timestamps.
- Related process-creation events.

A limited search for selected extensions, including `.locked`, `.encrypted`, `.crypt`, `.lockbit`, and `.ryk`, returned no matching records in the 500 most recent Event ID 11 events within the queried seven-day window.

This search was limited to selected extensions and a bounded event sample. Ransomware may use different extensions or modify files without changing their extensions.

## 10. Wazuh Manager and Agent Validation

The Wazuh manager was checked on Rocky Linux:

```bash
systemctl is-active wazuh-manager
```

Observed result:

```text
active
```

The agent list was checked:

```bash
/var/ossec/bin/agent_control -l
```

Observed Windows agent:

```text
ID: 001, Name: DESKTOP-9MMM37V, IP: any, Active
```

### Assessment

The Wazuh manager was active and the Windows endpoint agent was listed as active during the check.

## 11. Wazuh VSS Event Investigation

Wazuh Discover displayed the following alert:

| Field | Value |
|---|---|
| Rule ID | `60702` |
| Rule Level | `5` |
| Provider | `VSS` |
| Severity | `INFORMATION` |
| Event Time (UTC) | `2026-11-18T07:11:14.8906972Z` |
| Rule Fired Times | `3` |
| Rule Groups | `windows`, `windows_application` |

Alert description:

```text
The VSS service is shutting down due to idle timeout.
```

### Assessment

The event describes a VSS service shutdown due to an idle timeout.

It does not report shadow-copy deletion, backup destruction, or an attacker action.

The event was retained as contextual telemetry and was not classified as confirmed ransomware activity.

## 12. Overall Investigation Assessment

### Confirmed Observations

- Sysmon64 service was running.
- Recent Sysmon Event ID 1 and Event ID 11 records were available.
- Controlled PowerShell execution completed successfully.
- No shadow copies were listed during inspection.
- No backup or recovery operation was running during inspection.
- Defender reported SxS Passive Mode during further inspection.
- Wazuh manager and Windows agent were active when checked.
- Wazuh recorded an informational VSS idle-timeout event.
- Elevated file-creation activity was observed at selected times.

### Not Established

- Malicious shadow-copy deletion.
- Backup catalog destruction.
- Unauthorized boot recovery configuration changes.
- Event-log clearing during the queried period.
- Malicious Defender tampering.
- Mass file encryption.
- Confirmed ransomware execution or impact.

### Conclusion

The available evidence supports an endpoint security assessment, not a confirmed ransomware incident.

The elevated Sysmon file-creation periods remain the most relevant unresolved investigation leads. Their responsible processes and target paths should be examined before assigning a security classification.
