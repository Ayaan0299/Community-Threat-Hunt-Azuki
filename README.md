724
725
726
727
728
729
730
731
732
733
734
735
736
737
738
739
740
741
742
743
744
745
746
747
748
749
750
751
752
753
754
755
756
757
758
759
760
761
762
763
764
765
766
767
768
769
770
771
772
773
774
775
776
777
778
779
780
781
782
783
784
785
786
787
788
789
790
791
792
793
794
795
796
797
798
799
800
801
802
803
804
805
806
807
808
809
810
811
812
813
814
815
816
817
818
819
<p align="center">

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

Use Control + Shift + m to toggle the tab key moving focus. Alternatively, use esc then tab to move to the next interactive element on the page.
No file chosen
Attach files by dragging & dropping, selecting or pasting them.
