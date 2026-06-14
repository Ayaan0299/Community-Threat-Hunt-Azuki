<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>

# 🛡️ Threat Hunt Report: The Azuki Compromise

---

## 📌 Executive Summary

Azuki Import/Export Trading Co., a Japan/SE Asia shipping logistics firm, suffered a full compromise of its IT admin workstation (AZUKI-SL) after an attacker gained access via an exposed Remote Desktop Protocol (RDP) connection using the credentials of `kenji.sato`. The attacker conducted network reconnaissance, staged tooling in `C:\ProgramData\WindowsCache`, disabled Windows Defender via exclusions, deployed a credential dumping tool (Mimikatz, renamed `mm.exe`), and exfiltrated sensitive supplier contract and pricing data via Discord. The attacker established multiple persistence mechanisms (a scheduled task and a hidden local administrator account), attempted lateral movement to a secondary host, and cleared event logs to hinder investigation. This activity is consistent with the leak of pricing data described in the incident brief, which a competitor used to undercut Azuki's shipping contract by exactly 3%.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behaviour to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Sentinel / Microsoft Defender for Endpoint (MDE), single Windows endpoint `AZUKI-SL`
- **Data Sources:** DeviceProcessEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents
- **Timeframe:** 2025-11-19 to 2025-11-20
- **Compromised Account:** `kenji.sato`

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The attack began with an external RDP logon to `AZUKI-SL` from `88.97.178.12`, authenticating as `kenji.sato`. Once inside, the attacker performed basic network reconnaissance (`ARP -a`), then created a hidden staging directory at `C:\ProgramData\WindowsCache`. To operate undetected, the attacker added three file extension exclusions and a folder path exclusion (`C:\Users\KENJI~1.SAT\AppData\Local\Temp`) to Windows Defender. A PowerShell script (`wupdate.ps1`) automated the download of tooling via `certutil.exe`, including a backdoor disguised as `svchost.exe` and a renamed Mimikatz binary (`mm.exe`) used to run `sekurlsa::logonpasswords` and dump credentials from LSASS.

The fake `svchost.exe` established persistence via a scheduled task (`Windows Update Check`) and communicated with a C2 server at `78.141.196.6` over port `443`. Stolen supplier and pricing data was compressed into `export-data.zip` and exfiltrated via Discord. The attacker then created a hidden local administrator account (`support`) for future access, attempted lateral movement to `10.1.0.188` using `mstsc.exe`, and finally cleared the Security event log first (followed by System and Application) to cover their tracks.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Initial Access (External Remote Services / RDP) | T1133 / T1021.001 | High |
| 2 | Initial Access (Valid Accounts) | T1078 | High |
| 3 | Discovery (System Network Connections Discovery) | T1049 | Medium |
| 4 | Defense Evasion (Data Staged: Local) | T1074.001 | Medium |
| 5 | Defense Evasion (Impair Defenses: Defender Exclusions) | T1562.001 | High |
| 6 | Defense Evasion (Impair Defenses: Defender Exclusions) | T1562.001 | High |
| 7 | Defense Evasion / Ingress Tool Transfer (LOLBin abuse) | T1105 / T1218.011 | Medium |
| 8 | Persistence (Scheduled Task) | T1053.005 | High |
| 9 | Persistence (Scheduled Task Action / Masquerading) | T1053.005 / T1036.005 | High |
| 10 | Command and Control (Application Layer Protocol) | T1071.001 | High |
| 11 | Command and Control (Encrypted Channel/Port) | T1573 | Medium |
| 12 | Credential Access (LSASS Memory: Tool Drop) | T1003.001 | High |
| 13 | Credential Access (LSASS Memory: Execution) | T1003.001 | High |
| 14 | Collection (Archive Collected Data) | T1560.001 | High |
| 15 | Exfiltration Over Web Service | T1567.001 | High |
| 16 | Defense Evasion (Indicator Removal: Clear Logs) | T1070.001 | High |
| 17 | Persistence (Create Account: Local) | T1136.001 | High |
| 18 | Execution (PowerShell) | T1059.001 | High |
| 19 | Lateral Movement (Remote Services: target identification) | T1021 | Medium |
| 20 | Lateral Movement (Remote Desktop Protocol) | T1021.001 | Medium |

---

## 🔍 Flag Analysis

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Remote Access Source</strong></summary>

### 🎯 Objective
Identify the external IP address used to gain unauthorised RDP access to AZUKI-SL.

### 📌 Finding
An external host at `88.97.178.12` established an interactive logon session against AZUKI-SL, consistent with an internet facing RDP service being exposed and accessed with compromised credentials.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Source IP | 88.97.178.12 |
| Logon Type | Remote Interactive (RDP) |
| Account | kenji.sato |

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
```

### 🖼️ Screenshot
<img width="1648" height="184" alt="image" src="https://github.com/user-attachments/assets/222afe43-6d04-4352-b5cf-6ff5ca32415c" />

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Compromised User Account</strong></summary>

### 🎯 Objective
Identify which user account authenticated during the suspicious external RDP session.

### 📌 Finding
The account `kenji.sato` successfully authenticated from the external IP `88.97.178.12`, confirming this account was compromised and used for initial access.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Account | kenji.sato |
| Action Type | LogonSuccess |
| Remote IP | 88.97.178.12 |

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == 'LogonSuccess'
| project TimeGenerated, AccountDomain, DeviceName, ActionType, RemoteIP, AccountName
```

### 🖼️ Screenshot
<img width="1325" height="100" alt="image" src="https://github.com/user-attachments/assets/e279bf3f-bad7-4300-ada5-832a16535a71" />

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Network Reconnaissance</strong></summary>

### 🎯 Objective
Identify the command used by the attacker to enumerate the local network after gaining access.

### 📌 Finding
The attacker ran `ARP.EXE -a` under the `kenji.sato` account, listing the ARP cache to enumerate other devices on the local network segment, a precursor to lateral movement planning.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Account | kenji.sato |
| Process | ARP.EXE |
| Command Line | "ARP.EXE" -a |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where AccountName == 'kenji.sato'
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("arp.exe", "ipconfig.exe", "net.exe", "nbtstat.exe", "route.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="1803" height="363" alt="image" src="https://github.com/user-attachments/assets/296ab5d1-7440-47c0-b2a2-8dfdb7b32d01" />

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Malware Staging Directory</strong></summary>

### 🎯 Objective
Identify the primary directory used by the attacker to stage tools and stolen data.

### 📌 Finding
The attacker created and used `C:\ProgramData\WindowsCache` as the primary staging directory for downloaded tools, the fake `svchost.exe` backdoor, and the credential dumping tool `mm.exe`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Account | kenji.sato |
| Staging Directory | C:\ProgramData\WindowsCache |

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
```

### 🖼️ Screenshot
<img width="2166" height="379" alt="image" src="https://github.com/user-attachments/assets/b88424e7-4160-47e6-9f55-4c0303433bb5" />

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: File Extension Exclusions</strong></summary>

### 🎯 Objective
Determine how many file extensions the attacker excluded from Windows Defender scanning.

### 📌 Finding
Three unique file extensions were added to the Windows Defender `Exclusions\Extensions` registry key, allowing files with those extensions to execute without being scanned.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Account | kenji.sato |
| Registry Key | ...\Windows Defender\Exclusions\Extensions |
| Count of Extensions Excluded | 3 |

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where RegistryKey contains "Exclusions\\Extensions"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

### 🖼️ Screenshot
<img width="2230" height="374" alt="image" src="https://github.com/user-attachments/assets/ea4360e0-7da0-4052-b15a-27af1e27480e" />

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Temporary Folder Exclusion</strong></summary>

### 🎯 Objective
Identify the folder path excluded from Windows Defender scanning to allow malware in the user's temp directory to run undetected.

### 📌 Finding
The attacker added `C:\Users\KENJI~1.SAT\AppData\Local\Temp` (the 8.3 short path form of kenji.sato's Temp directory) as a Defender exclusion, allowing tools staged there to execute without being scanned.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Registry Key | ...\Windows Defender\Exclusions\Paths |
| Excluded Path | C:\Users\KENJI~1.SAT\AppData\Local\Temp |

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains "Exclusions\\Paths"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1409" height="370" alt="image" src="https://github.com/user-attachments/assets/b452b8be-afc1-4a5e-b3f5-9af255c1f07f" />

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Download Utility Abuse</strong></summary>

### 🎯 Objective
Identify the native Windows binary abused to download attacker tooling.

### 📌 Finding
`certutil.exe` was used to download both the fake `svchost.exe` backdoor and the `mm.exe` credential dumping tool from an external source into the staging directory, a classic Living Off The Land Binary (LOLBin) technique.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Process | certutil.exe |
| Behaviour | Downloaded files containing URL and output path arguments |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http://", "https://")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="2167" height="701" alt="image" src="https://github.com/user-attachments/assets/8f22f778-dc25-415c-bed4-b5f8a5f67b54" />

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Scheduled Task Name</strong></summary>

### 🎯 Objective
Identify the name of the scheduled task created for persistence.

### 📌 Finding
A scheduled task named `Windows Update Check` was created via `schtasks /create`, designed to blend in with legitimate Windows Update maintenance tasks.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Process | schtasks.exe |
| Task Name | Windows Update Check |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1485" height="445" alt="image" src="https://github.com/user-attachments/assets/806510bc-634f-4cad-969d-014a636277da" />

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Scheduled Task Target</strong></summary>

### 🎯 Objective
Identify the executable path configured to run via the persistence scheduled task.

### 📌 Finding
The `Windows Update Check` task was configured (via the `/tr` parameter) to execute `C:\ProgramData\WindowsCache\svchost.exe`, the attacker's renamed backdoor, masquerading as the legitimate Windows `svchost.exe` process.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Task Action (/tr) | C:\ProgramData\WindowsCache\svchost.exe |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
See Flag 8 screenshot above, the `/tr` value in the same result shows this path.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: C2 Server Address</strong></summary>

### 🎯 Objective
Identify the external IP address the malicious `svchost.exe` communicated with for command and control.

### 📌 Finding
The fake `svchost.exe` running from `C:\ProgramData\WindowsCache\` established outbound connections to `78.141.196.6`, identified as the C2 server.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Process | C:\ProgramData\WindowsCache\svchost.exe |
| Remote IP (C2) | 78.141.196.6 |

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFolderPath has "C:\\ProgramData\\WindowsCache\\svchost.exe"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1086" height="334" alt="image" src="https://github.com/user-attachments/assets/e8af10e4-27da-45fd-95c9-881e68be4221" />

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: C2 Communication Port</strong></summary>

### 🎯 Objective
Identify the destination port used for C2 communications.

### 📌 Finding
The malicious `svchost.exe` communicated with the C2 server `78.141.196.6` over port `443`, using HTTPS to blend in with normal encrypted web traffic.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Remote IP | 78.141.196.6 |
| Remote Port | 443 |

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFolderPath has "C:\\ProgramData\\WindowsCache\\svchost.exe"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
See Flag 10 screenshot above, the `RemotePort` column in the same result shows this value.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Credential Theft Tool</strong></summary>

### 🎯 Objective
Identify the filename of the credential dumping tool dropped onto the host.

### 📌 Finding
A file named `mm.exe`, a renamed Mimikatz binary, was downloaded into `C:\ProgramData\WindowsCache\` via `certutil.exe`, shortly before LSASS memory access occurred.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| File | mm.exe |
| Folder Path | C:\ProgramData\WindowsCache\mm.exe |
| Downloaded via | certutil.exe |

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath has "C:\\ProgramData\\WindowsCache"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
See Flag 7 screenshot above, `mm.exe` appears in the same result set as `svchost.exe`.

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Memory Extraction Module</strong></summary>

### 🎯 Objective
Identify the specific Mimikatz module and command used to extract credentials from memory.

### 📌 Finding
`mm.exe` was executed with the argument `sekurlsa::logonpasswords`, the standard Mimikatz command for dumping plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory for all logged on users.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Process | mm.exe |
| Command Line Argument | sekurlsa::logonpasswords |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "mm.exe"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="955" height="420" alt="image" src="https://github.com/user-attachments/assets/541d92a5-90e8-4604-a746-bb56f33b638f" />

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Data Staging Archive</strong></summary>

### 🎯 Objective
Identify the archive file used to compress stolen data prior to exfiltration.

### 📌 Finding
A ZIP archive named `export-data.zip` was created by the `kenji.sato` account, consistent with the attacker compressing stolen supplier contract and pricing data ahead of exfiltration.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Account | kenji.sato |
| Archive File | export-data.zip |

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where InitiatingProcessAccountName == "kenji.sato"
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName contains ".zip"
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="2100" height="529" alt="image" src="https://github.com/user-attachments/assets/5be4c01b-8713-4d08-84b9-42db1791a847" />

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Exfiltration Channel</strong></summary>

### 🎯 Objective
Identify the cloud service used to exfiltrate the stolen archive.

### 📌 Finding
Outbound connections to `discord.com` were observed from the `kenji.sato` account shortly after `export-data.zip` was created, indicating Discord was used as the exfiltration channel.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Account | kenji.sato |
| Destination | discord.com |

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where TimeGenerated >= todatetime('11/19/2025, 7:08:58.024 PM')
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
```

### 🖼️ Screenshot
<img width="2531" height="834" alt="image" src="https://github.com/user-attachments/assets/62aae0da-61ad-43a3-a8ff-9cb38762b8b6" />

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Log Tampering</strong></summary>

### 🎯 Objective
Identify the first Windows event log cleared by the attacker.

### 📌 Finding
The attacker ran `wevtutil cl Security`, `wevtutil cl System`, and `wevtutil cl Application` in rapid succession via PowerShell, with the Security log cleared first.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Process | wevtutil.exe |
| First Log Cleared | Security |
| Initiating Process | powershell.exe |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1289" height="309" alt="image" src="https://github.com/user-attachments/assets/10bc6c34-b951-4743-b1c9-bad64398395f" />

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Persistence Account</strong></summary>

### 🎯 Objective
Identify the backdoor account created by the attacker for future access.

### 📌 Finding
The attacker created a local account named `support` and added it to the local Administrators group via `net user ... /add` and `net localgroup administrators support /add`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| New Account | support |
| Group | Administrators |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/add"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1476" height="586" alt="image" src="https://github.com/user-attachments/assets/9174da47-63e7-4ca8-a966-9c3a229c491c" />

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Malicious Script</strong></summary>

### 🎯 Objective
Identify the PowerShell script used to automate the attack chain.

### 📌 Finding
`wupdate.ps1` was created in kenji.sato's Temp directory, disguised as a Windows Update related script, and used to automate downloading and executing the attacker's tooling.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Script | wupdate.ps1 |
| Location | C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1 |

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName endswith ".ps1"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1258" height="588" alt="image" src="https://github.com/user-attachments/assets/125514b8-3b55-4d56-89ea-63bf0cc8a1a7" />

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Secondary Target</strong></summary>

### 🎯 Objective
Identify the IP address targeted for lateral movement.

### 📌 Finding
The attacker used `cmdkey` and `mstsc` to target the internal host `10.1.0.188` for lateral movement from AZUKI-SL.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Target IP | 10.1.0.188 |
| Tooling | cmdkey / mstsc |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("cmdkey", "mstsc")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1908" height="678" alt="image" src="https://github.com/user-attachments/assets/e0f5a211-1cc4-45d3-bbf1-8438a5621be4" />

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Remote Access Tool</strong></summary>

### 🎯 Objective
Identify the tool used by the attacker for lateral movement to the secondary target.

### 📌 Finding
`mstsc.exe`, the built in Windows Remote Desktop Connection client, was used to attempt RDP access to `10.1.0.188`, leveraging credentials likely cached via `cmdkey`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | AZUKI-SL |
| Tool | mstsc.exe |
| Target | 10.1.0.188 |

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("cmdkey", "mstsc")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
See Flag 19 screenshot above, the `FileName` column in the same result shows `mstsc.exe`.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- RDP was exposed and reachable from an external IP without MFA, enabling initial access using a single set of credentials
- Windows Defender exclusion changes (both file extensions and folder paths) were not alerted on, allowing malware to run and persist undetected
- LOLBin abuse (`certutil.exe` for downloads) was not flagged despite command line arguments containing URLs and output paths
- No alerting on local administrator account creation, allowing a hidden backdoor account (`support`) to persist undetected
- Outbound traffic to consumer platforms (Discord) was not restricted or monitored from an admin workstation, enabling data exfiltration
- Event log clearing (`wevtutil cl`) went undetected, weakening forensic visibility

### Recommendations
- Remove direct internet exposure of RDP; require VPN access with MFA for all remote administrative sessions
- Implement alerting and automation for any change to Windows Defender exclusion lists (extensions and paths)
- Build detection rules for `certutil`, `bitsadmin`, and similar LOLBins when used with URL arguments
- Alert on local account creation and group membership changes (`net user /add`, `net localgroup administrators /add`)
- Restrict or monitor outbound connections to consumer collaboration and file sharing platforms from privileged workstations
- Forward Windows event logs to a centralised SIEM in near real time and alert on `wevtutil cl` / `Clear-EventLog` execution
- Reset credentials for kenji.sato and all accounts active on AZUKI-SL during the incident window; remove the `support` account
- Isolate and investigate `10.1.0.188` as a potential secondary compromise

---

## 🧾 Final Assessment

This incident represents a complete, end to end compromise of an IT admin workstation, progressing from external RDP access through reconnaissance, defence evasion, credential theft, persistence, command and control, data staging, exfiltration, and anti forensics. The attacker demonstrated moderate sophistication: deliberate use of LOLBins, Defender exclusion abuse, masquerading techniques (fake `svchost.exe`, disguised task and script names), and prioritised log clearing. The exfiltrated supplier contract and pricing data directly correlates with the competitor's 3% undercut described in the incident brief, confirming this breach as the root cause of the commercial impact. Remediation requires full credential rotation, removal of all identified persistence mechanisms (scheduled task, `support` account, fake `svchost.exe`), and investigation of the secondary target host `10.1.0.188`.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via advanced hunting in Microsoft Sentinel / MDE
- Techniques mapped directly to MITRE ATT&CK

---
