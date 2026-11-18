# Lab 141 – Ransomware Precursor Investigation

## Overview

This lab investigates Windows endpoint activity that may indicate preparation for a ransomware attack. The investigation focuses on backup and recovery availability, Volume Shadow Copy status, boot configuration, endpoint protection, event-log integrity, process execution, and unusual file activity.

The investigation uses Windows PowerShell, Sysmon, and Wazuh to inspect endpoint state and analyze available security telemetry. All activities are non-destructive. No ransomware or destructive payloads are executed.

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

## Skills Demonstrated

- Windows endpoint investigation
- PowerShell-based security inspection
- Sysmon event analysis
- Wazuh monitoring and alert investigation
- Backup and recovery assessment
- Microsoft Defender status analysis
- Windows event-log integrity checks
- Process and file activity correlation
- Evidence-based incident triage

## Investigation Principle

Follow the evidence, not the assumption. A missing shadow copy, inactive protection feature, VSS idle-timeout event, or file-creation spike is not independently proof of ransomware activity.
