# Lab141-Ransomware-Precursor-Investigation
## Overview
### Introduction

Ransomware attacks may involve preparation activities before files are encrypted. Attackers may attempt to reduce recovery options, interfere with security controls, manipulate system configuration, or execute commands that support later stages of an attack.

Ransomware precursor investigation focuses on identifying these behaviors through endpoint telemetry and system configuration checks.

An important part of the investigation is distinguishing legitimate administrative activity from suspicious or unauthorized behavior.

### 1. Shadow Copy and Backup Interference

Windows Volume Shadow Copy Service (VSS) maintains point-in-time copies that can support file recovery.

Backup utilities also provide recovery capabilities. Attackers may attempt to remove or interfere with these resources.

Examples of relevant commands include:

```powershell
vssadmin.exe delete shadows /all /quiet
wbadmin.exe delete catalog -quiet
wmic.exe shadowcopy delete
```

These commands require contextual investigation. Their presence alone does not prove malicious activity.

Analysts should inspect command-line arguments, execution account, parent process, timestamp, and related events.

### 2. Boot and Recovery Configuration Changes

Windows Boot Configuration Data (BCD) controls important boot settings.

An attacker may attempt to interfere with recovery functionality by modifying boot configuration.

Example:

```powershell
bcdedit.exe /set {default} recoveryenabled no
```

Analysts can inspect the current configuration using:

```powershell
bcdedit.exe /enum "{current}"
```

A configuration value alone does not establish when or why a setting changed. Historical telemetry and process execution evidence are important for attribution.

### 3. Event Log Clearing

Windows event logs contain information useful for security investigations.

Attackers may attempt to remove evidence by clearing event logs.

Examples:

```powershell
wevtutil.exe cl System
wevtutil.exe cl Security
```

Relevant Windows event IDs include:

- Security Event ID `1102` – Security audit log cleared.
- System Event ID `104` – An event log was cleared.

The absence of these events in available history does not prove that logs were never cleared. Collection coverage and retention must be considered.

### 4. Security-Control Interference

Ransomware operators may attempt to disable or weaken endpoint protection.

Useful Microsoft Defender inspection commands include:

```powershell
Get-MpComputerStatus
Get-MpPreference
Get-Service WinDefend, WdNisSvc
```

Analysts should examine protection status, operating mode, configuration changes, service state, and related process activity.

An inactive protection feature is not automatically evidence of an attack. Passive mode, another antivirus product, policy settings, and product health can affect reported status.

### 5. Suspicious PowerShell and Process Execution

PowerShell is a legitimate Windows administration tool, but attackers may also misuse it to execute commands and scripts.

Potential investigation leads include:

- Encoded PowerShell commands.
- Unexpected execution-policy arguments.
- Unusual parent-child process relationships.
- Unexpected SYSTEM-level execution.
- Commands related to backup or recovery interference.

Relevant telemetry includes:

| Event ID | Source | Description |
|---|---|---|
| 1 | Sysmon | Process creation |
| 4688 | Windows Security | Process creation, when auditing is enabled |

Analysts should inspect the full command line, user, parent process, image path, timestamp, and surrounding activity.

A suspicious-looking command is not sufficient proof of malicious intent.

### 6. Unusual File Activity

Ransomware may modify large numbers of files in a short period.

Sysmon Event ID `11` records file-creation activity and can help establish a baseline or identify unusual activity.

Useful attributes include:

- Process image.
- Target file path.
- User account.
- Event timestamp.
- File extension.
- Related process-creation events.

High file-event volume alone does not prove encryption. Legitimate applications, software updates, installers, and background processes can also produce large numbers of events.

File activity should be correlated with process execution and other available evidence.

### 7. Role of Sysmon and Wazuh

Sysmon provides detailed Windows endpoint telemetry that can support process, file, and registry investigations.

Relevant Sysmon event IDs include:

| Event ID | Description |
|---|---|
| 1 | Process creation |
| 11 | File creation |
| 12 | Registry object creation or deletion |
| 13 | Registry value set |
| 14 | Registry key or value rename |

Wazuh collects and analyzes supported endpoint events and provides searchable records and alerts through its dashboard.

A Wazuh rule match should be treated as an investigation lead. Analysts should inspect the original event details and validate the available indexed fields.

### 8. Investigation Methodology

A structured ransomware precursor investigation can follow these steps:

1. Validate endpoint monitoring and log availability.
2. Inspect shadow-copy and backup status.
3. Review boot and recovery configuration.
4. Check security-product status and relevant events.
5. Search for suspicious process execution.
6. Review event-log clearing indicators.
7. Establish a baseline for file activity.
8. Investigate unusual activity by correlating process, user, file path, and timestamp.
9. Document confirmed observations, suspicious leads, unknowns, and limitations.

### Key Takeaway

Ransomware precursor investigation involves identifying behaviors that may reduce recovery options or prepare an endpoint for destructive activity.

No single command, event, service state, or file-creation spike is sufficient to confirm ransomware.

The analyst must correlate evidence, validate context, and distinguish suspicious activity from confirmed malicious behavior.

This lab investigates Windows endpoint activity that may indicate preparation for a ransomware attack. The investigation focuses on backup and recovery availability, Volume Shadow Copy status, boot configuration, endpoint protection, event-log integrity, process execution, and unusual file activity.

The investigation uses Windows PowerShell, Sysmon, and Wazuh to inspect endpoint state and analyze available security telemetry. All activities are non-destructive. No ransomware or destructive payloads are executed.

## Lab Objectives

### Primary Objectives

- Understand common activities that may precede ransomware execution.
- Identify Windows commands that can interfere with shadow copies and backups.
- Inspect Volume Shadow Copy availability using `vssadmin`.
- Review Windows Backup operation status using `wbadmin`.
- Examine the current Windows boot configuration using `bcdedit`.
- Understand how event-log clearing can affect incident investigations.
- Assess Microsoft Defender protection status and operating mode.
- Validate Sysmon service availability and endpoint event generation.
- Examine process-creation and file-creation telemetry.
- Establish a baseline for file-creation activity.
- Identify unusual file-creation periods requiring further investigation.
- Validate Wazuh manager and Windows agent connectivity.
- Interpret VSS-related Wazuh alerts using their event details and context.

### Investigation Objectives

- Correlate process execution with user identity, parent process, command-line arguments, and timestamps.
- Distinguish routine administrative activity from potentially suspicious behavior.
- Understand the limitations of searching for selected ransomware-related file extensions.
- Differentiate an observed system state from evidence of a historical action.
- Identify telemetry and retention limitations.
- Document findings without making unsupported claims about ransomware execution or impact.

### Expected Learning Outcome

After completing this lab, the analyst should be able to conduct a basic ransomware precursor investigation using Windows-native tools, Sysmon, and Wazuh.

The analyst should also be able to classify findings as confirmed observations, suspicious leads, plausible explanations, or unresolved questions based on available evidence.

## Lab Scenario

### Scenario

A Windows 11 endpoint is monitored through Sysmon and Wazuh as part of routine security operations.

During an endpoint security review, the analyst is asked to assess whether the system shows activity that could indicate preparation for a ransomware attack.

The investigation focuses on behaviors that may reduce the endpoint's ability to recover from an incident, including interference with shadow copies, backups, boot recovery settings, event logs, and endpoint security controls.

### Investigation Context

The endpoint reports that no Volume Shadow Copies are currently available and that no backup or recovery operation is running.

Microsoft Defender reports some protection features as inactive. Further inspection is required to understand its operating mode and determine whether another antivirus product is registered with Windows Security Center.

Sysmon is running and generating process-creation and file-creation events. A review of the preceding 24 hours identifies several periods of elevated file-creation activity.

Wazuh also records an informational VSS event indicating that the service is shutting down due to an idle timeout.

These observations require contextual investigation. None independently establishes ransomware activity.

### Analyst Tasks

The analyst must:

- Inspect shadow-copy availability and backup status.
- Review the current Windows boot configuration.
- Check available indicators of event-log clearing.
- Examine Microsoft Defender status and relevant security events.
- Validate Sysmon and Wazuh monitoring availability.
- Search process-creation telemetry for potentially suspicious backup, recovery, and log-clearing commands.
- Review file-creation activity and identify unusual event-volume spikes.
- Correlate Wazuh alerts with underlying Windows event information.
- Document findings and investigation limitations.

### Investigation Constraints

The investigation must use safe, non-destructive inspection.

The analyst must not:

- Delete shadow copies.
- Interfere with backups.
- Disable endpoint security products.
- Modify boot-recovery settings.
- Clear Windows event logs.
- Execute ransomware or destructive payloads.

All findings must be based on collected evidence. The absence of selected indicators must not be presented as proof that the endpoint has never experienced malicious activity.

### Expected Result

The analyst should produce an evidence-based assessment of the endpoint's observed state and available telemetry.

The final report should distinguish confirmed observations from suspicious leads, plausible explanations, and unresolved questions.

The objective is not to force a ransomware detection, but to determine what the available evidence supports and identify what additional investigation would be necessary.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint OS | Windows 11 Pro |
| Hostname | DESKTOP-9MMM37V |
| Sysmon | 15.21 |
| SIEM | Wazuh 4.13.1 |
| Wazuh Agent ID | 001 |
| Wazuh Manager | Rocky Linux 9.8 |
| Investigation Tools | PowerShell, Sysmon, Wazuh Discover |

## Investigation Scope

- Volume Shadow Copy inspection using VSS administration tools.
- Windows Backup status verification.
- Boot Configuration Data inspection.
- Microsoft Defender protection status assessment.
- Windows event-log integrity checks.
- Suspicious PowerShell and process execution.
- Sysmon process-creation and file-creation analysis.
- Wazuh manager and agent validation.
- Identification of unusual file-creation activity.

## Key Findings

### Backup and Recovery

- `vssadmin.exe list shadows` returned no existing shadow copies.
- `wbadmin.exe get status` reported that no backup or recovery operation was running.
- The current Windows Boot Loader configuration was inspected using `bcdedit`.
- No suspicious boot configuration modification was established from the displayed values.

These results describe the observed system state. They do not prove that backup data or shadow copies were maliciously deleted.

### Microsoft Defender

The endpoint reported the following status:

| Property | Value |
|---|---|
| AntivirusEnabled | True |
| RealTimeProtectionEnabled | False |
| BehaviorMonitorEnabled | False |

Further investigation identified Defender operating in `SxS Passive Mode`. McAfee components were also registered with Windows Security Center, and selected McAfee services were running.

This provides context for Defender's passive state. It does not independently establish the operational health of McAfee's antivirus engine or indicate malicious Defender tampering.

### Sysmon Monitoring

- Sysmon64 service was running.
- Recent Event ID 1 and Event ID 11 records were available.
- A controlled PowerShell command executed successfully.
- A 24-hour Event ID 11 baseline identified several periods of elevated file-creation activity.

The elevated periods remain investigation leads because the responsible processes and target paths were not conclusively attributed.

### Wazuh Monitoring

- Wazuh manager service was active.
- Windows endpoint `DESKTOP-9MMM37V` was listed as active under agent ID `001`.
- Wazuh recorded VSS event rule ID `60702`, describing the VSS service shutting down due to an idle timeout.

The event was informational and did not report shadow-copy deletion.

### Event Log Integrity

No matching Security Event ID `1102` or System Event ID `104` records were found in the queried 30-day history.

This conclusion is limited to available event history and collection coverage. It does not prove that event logs were never cleared.

## Investigation Conclusion

The investigation confirmed that endpoint telemetry was available through Sysmon and Wazuh. Backup and recovery status, Defender operating mode, and VSS-related events were also inspected.

No matching process-creation records for the selected backup-deletion, recovery-tampering, or event-log-clearing command patterns were identified in the queried Sysmon history.

A limited search for selected ransomware-related file extensions returned no matches. However, several periods of elevated file-creation activity were observed and require further process and file-path correlation.

**No confirmed ransomware execution or impact was established from the available evidence.**

