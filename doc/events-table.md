# WHIDS Events Enrichment Table

<table>
 <tr>
  <th>Event ID</th>
  <th>Channel</th>
  <th>Fields</th>
 </tr>
 <tr>
  <td>
   1
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Ancestors</b>: System|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\wininit.exe|C:\\Windows\\System32\\services.exe|C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1907.4-0\\MsMpEng.exe|C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1907.4-0\\MpCmdRun.exe <br>
   <b>CommandLine</b>: \\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1 <br>
   <b>Company</b>: Microsoft Corporation <br>
   <b>CurrentDirectory</b>: C:\\Windows <br>
   <b>Description</b>: Console Window Host <br>
   <b>FileVersion</b>: 10.0.18362.1 (WinBuild.160101.0800) <br>
   <b>Hashes</b>: SHA1=11996F32DD85863A8C3BFF6D520F788A9211C8F7,MD5=C5E9B1D1103EDCEA2E408E9497A5A88F,SHA256=BAF97B2A629723947539CFF84E896CD29565AB4BB68B0CEC515EB5C5D6637B69,IMPHASH=F8DD0EF565DE87D97ABF9C62EA63EC21 <br>
   <b>Image</b>: C:\\Windows\\System32\\conhost.exe <br>
   <b>ImageSize</b>: 885760 <br>
   <b>IntegrityLevel</b>: System <br>
   <b>IntegrityTimeout</b>: false <br>
   <b>LogonGuid</b>: {515cd0d1-564a-5d5e-0000-0020e7030000} <br>
   <b>LogonId</b>: 0x3e7 <br>
   <b>OriginalFileName</b>: CONHOST.EXE <br>
   <b>ParentCommandLine</b>: \C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.1907.4-0\\MpCmdRun.exe\ SignatureUpdate -ScheduleJob -RestrictPrivileges <br>
   <b>ParentImage</b>: C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1907.4-0\\MpCmdRun.exe <br>
   <b>ParentIntegrityLevel</b>: System <br>
   <b>ParentProcessGuid</b>: {515cd0d1-565c-5d5e-0000-00106aa10400} <br>
   <b>ParentProcessId</b>: 4160 <br>
   <b>ParentProcessIntegrity</b>: -1 <br>
   <b>ParentUser</b>: NT AUTHORITY\\SYSTEM <br>
   <b>ProcessGuid</b>: {515cd0d1-565c-5d5e-0000-001067a80400} <br>
   <b>ProcessId</b>: 4196 <br>
   <b>ProcessIntegrity</b>: -1 <br>
   <b>Product</b>: Microsoft® Windows® Operating System <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>TerminalSessionId</b>: 0 <br>
   <b>User</b>: NT AUTHORITY\\SYSTEM <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   2
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>CreationUtcTime</b>: 2019-06-12 09:57:04.691 <br>
   <b>Image</b>: C:\\Program Files\\Microsoft VS Code\\Code.exe <br>
   <b>IntegrityLevel</b>: Medium <br>
   <b>PreviousCreationUtcTime</b>: 2019-08-22 08:50:15.032 <br>
   <b>ProcessGuid</b>: {515cd0d1-5742-5d5e-0000-00105c222700} <br>
   <b>ProcessId</b>: 5200 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>TargetFilename</b>: C:\\Users\\Generic\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\6O594XQHGMHB1T7XXZ2T.temp <br>
   <b>User</b>: DESKTOP-LJRVE06\\Generic <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   3
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>CommandLine</b>: C:\\Windows\\system32\\svchost.exe -k NetworkService -p -s Dnscache <br>
   <b>DestinationHostname</b>:  <br>
   <b>DestinationIp</b>: ff02:0:0:0:0:0:1:3 <br>
   <b>DestinationIsIpv6</b>: true <br>
   <b>DestinationPort</b>: 5355 <br>
   <b>DestinationPortName</b>: llmnr <br>
   <b>Image</b>: C:\\Windows\\System32\\svchost.exe <br>
   <b>Initiated</b>: true <br>
   <b>IntegrityLevel</b>: System <br>
   <b>ProcessGuid</b>: {515cd0d1-564c-5d5e-0000-00106a4a0100} <br>
   <b>ProcessId</b>: 1580 <br>
   <b>Protocol</b>: udp <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: Dnscache <br>
   <b>SourceHostname</b>: DESKTOP-LJRVE06 <br>
   <b>SourceIp</b>: fe80:0:0:0:2ccd:2156:e8b4:895d <br>
   <b>SourceIsIpv6</b>: true <br>
   <b>SourcePort</b>: 59514 <br>
   <b>SourcePortName</b>:  <br>
   <b>User</b>: NT AUTHORITY\\NETWORK SERVICE <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   4
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>IntegrityLevel</b>: ? <br>
   <b>SchemaVersion</b>: 4.21 <br>
   <b>State</b>: Started <br>
   <b>User</b>: ? <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422 <br>
   <b>Version</b>: 10.0
  </td>
 </tr>
 <tr>
  <td>
   5
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Image</b>: C:\\Windows\\System32\\conhost.exe <br>
   <b>IntegrityLevel</b>: System <br>
   <b>ProcessGuid</b>: {515cd0d1-565c-5d5e-0000-001067a80400} <br>
   <b>ProcessId</b>: 4196 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>User</b>: NT AUTHORITY\\SYSTEM <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   6
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Hashes</b>: SHA1=E9AC7F28883867C91CD940E6F2EC6E98AA2197AF,MD5=1E683E20DDD61ECBDD0D046DB7FB6027,SHA256=374FF85925CBDD75D64180E7D2B20A13F6EF2ABD248E6CB7D4FF2B7A42DBE5C8,IMPHASH=D6B88475B1759078DD0B119777B66A37 <br>
   <b>ImageLoaded</b>: C:\\Windows\\System32\\drivers\\VBoxMouse.sys <br>
   <b>ImageLoadedSize</b>: 186528 <br>
   <b>RuleName</b>:  <br>
   <b>Signature</b>: Oracle Corporation <br>
   <b>SignatureStatus</b>: Valid <br>
   <b>Signed</b>: true <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   7
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Company</b>: Microsoft Corporation <br>
   <b>Description</b>: NT Layer DLL <br>
   <b>FileVersion</b>: 10.0.18362.1 (WinBuild.160101.0800) <br>
   <b>Hashes</b>: SHA1=C5085044059F466DF8C513B615AAF2F43DCD2ADA,MD5=3239D9CDC68757AB4620B3AC127E18C5,SHA256=D6DA3BB97F6839436A9399D087138CA44B50E5674C4C8093CE41A4C1658C7259,IMPHASH=00000000000000000000000000000000 <br>
   <b>Image</b>: C:\\Windows\\System32\\svchost.exe <br>
   <b>ImageLoaded</b>: C:\\Windows\\System32\\ntdll.dll <br>
   <b>ImageLoadedSize</b>: 1999648 <br>
   <b>IntegrityLevel</b>: System <br>
   <b>OriginalFileName</b>: ? <br>
   <b>ParentCommandLine</b>: C:\\Windows\\system32\\services.exe <br>
   <b>ParentImage</b>: C:\\Windows\\System32\\services.exe <br>
   <b>ProcessGuid</b>: {515cd0d1-564c-5d5e-0000-001048340100} <br>
   <b>ProcessId</b>: 1416 <br>
   <b>Product</b>: Microsoft® Windows® Operating System <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: UserManager <br>
   <b>Signature</b>: Microsoft Windows <br>
   <b>SignatureStatus</b>: Valid <br>
   <b>Signed</b>: true <br>
   <b>User</b>: NT AUTHORITY\\SYSTEM <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   8
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>NewThreadId</b>: 7100 <br>
   <b>RuleName</b>:  <br>
   <b>SourceImage</b>: C:\\Windows\\System32\\VBoxTray.exe <br>
   <b>SourceIntegrityLevel</b>: Medium <br>
   <b>SourceProcessGuid</b>: {515cd0d1-568a-5d5e-0000-0010e83e0f00} <br>
   <b>SourceProcessId</b>: 7016 <br>
   <b>SourceServices</b>: N/A <br>
   <b>SourceUser</b>: DESKTOP-LJRVE06\\Generic <br>
   <b>StartAddress</b>: 0xFFFFC01961C72460 <br>
   <b>StartFunction</b>:  <br>
   <b>StartModule</b>:  <br>
   <b>TargetImage</b>: C:\\Windows\\System32\\csrss.exe <br>
   <b>TargetIntegrityLevel</b>: System <br>
   <b>TargetParentProcessGuid</b>: {515cd0d1-5648-5d5e-0000-0010085c0000} <br>
   <b>TargetProcessGuid</b>: {515cd0d1-5648-5d5e-0000-0010365d0000} <br>
   <b>TargetProcessId</b>: 500 <br>
   <b>TargetServices</b>: N/A <br>
   <b>TargetUser</b>: NT AUTHORITY\\SYSTEM <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   9
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Device</b>: \\Device\\HarddiskVolume1 <br>
   <b>Image</b>: System <br>
   <b>IntegrityLevel</b>:  <br>
   <b>ProcessGuid</b>: {515cd0d1-563d-5d5e-0000-0010eb030000} <br>
   <b>ProcessId</b>: 4 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>User</b>:  <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   10
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>CallTrace</b>: C:\\Windows\\SYSTEM32\\ntdll.dll+9c524|C:\\Windows\\System32\\KERNELBASE.dll+6a685|c:\\windows\\system32\\lsm.dll+17803|c:\\windows\\system32\\lsm.dll+175d1|C:\\Windows\\SYSTEM32\\ntdll.dll+33478|C:\\Windows\\SYSTEM32\\ntdll.dll+799b2|C:\\Windows\\SYSTEM32\\ntdll.dll+345c4|C:\\Windows\\System32\\KERNEL32.DLL+17944|C:\\Windows\\SYSTEM32\\ntdll.dll+6ce71 <br>
   <b>GrantedAccess</b>: 0x1000 <br>
   <b>RuleName</b>:  <br>
   <b>SourceImage</b>: C:\\Windows\\system32\\svchost.exe <br>
   <b>SourceIntegrityLevel</b>: System <br>
   <b>SourceProcessGUID</b>: {515cd0d1-564b-5d5e-0000-00107adb0000} <br>
   <b>SourceProcessId</b>: 920 <br>
   <b>SourceServices</b>: LSM <br>
   <b>SourceThreadId</b>: 944 <br>
   <b>SourceUser</b>: NT AUTHORITY\\SYSTEM <br>
   <b>TargetImage</b>: C:\\Windows\\system32\\csrss.exe <br>
   <b>TargetIntegrityLevel</b>: System <br>
   <b>TargetParentProcessGuid</b>: {515cd0d1-5647-5d5e-0000-00109b560000} <br>
   <b>TargetProcessGUID</b>: {515cd0d1-5647-5d5e-0000-00108a570000} <br>
   <b>TargetProcessId</b>: 416 <br>
   <b>TargetServices</b>: N/A <br>
   <b>TargetUser</b>: NT AUTHORITY\\SYSTEM <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   11
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>CreationUtcTime</b>: 2019-08-22 08:46:45.656 <br>
   <b>Image</b>: C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe <br>
   <b>IntegrityLevel</b>: AppContainer <br>
   <b>ProcessGuid</b>: {515cd0d1-566d-5d5e-0000-0010deab0700} <br>
   <b>ProcessId</b>: 5652 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>TargetFilename</b>: C:\\Users\\Generic\\AppData\\Local\\Packages\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\TempState\\~tartUnifiedTileModelCache.tmp <br>
   <b>User</b>: DESKTOP-LJRVE06\\Generic <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   12
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>EventType</b>: CreateKey <br>
   <b>Image</b>: System <br>
   <b>IntegrityLevel</b>: ? <br>
   <b>ProcessGuid</b>: {515cd0d1-563d-5d5e-0000-0010eb030000} <br>
   <b>ProcessId</b>: 4 <br>
   <b>RuleName</b>:  <br>
   <b>TargetObject</b>: HKLM\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\MonitorDataStore <br>
   <b>User</b>: ? <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   13
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Details</b>: STORAGE\\Volume\\{1eeaac07-8cf7-11e9-9661-806e6f6e6963}#0000000000100000 <br>
   <b>EventType</b>: SetValue <br>
   <b>Image</b>: System <br>
   <b>IntegrityLevel</b>: ? <br>
   <b>ProcessGuid</b>: {515cd0d1-563d-5d5e-0000-0010eb030000} <br>
   <b>ProcessId</b>: 4 <br>
   <b>RuleName</b>:  <br>
   <b>TargetObject</b>: HKLM\\System\\CurrentControlSet\\Services\\volume\\Enum\\0 <br>
   <b>User</b>: ? <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   14
  </td>
  <td>
  </td>
  <td>
  </td>
 </tr>
 <tr>
  <td>
   15
  </td>
  <td>
  </td>
  <td>
  </td>
 </tr>
 <tr>
  <td>
   16
  </td>
  <td>
  </td>
  <td>
  </td>
 </tr>
 <tr>
  <td>
   17
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>EventType</b>: CreatePipe <br>
   <b>Image</b>: C:\\Program Files\\Microsoft VS Code\\Code.exe <br>
   <b>IntegrityLevel</b>: Medium <br>
   <b>PipeName</b>: \\uv\\00000187263B19B0-6316 <br>
   <b>ProcessGuid</b>: {515cd0d1-574e-5d5e-0000-00104a042800} <br>
   <b>ProcessId</b>: 6316 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>User</b>: DESKTOP-LJRVE06\\Generic <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   18
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>EventType</b>: ConnectPipe <br>
   <b>Image</b>: C:\\Windows\\system32\\wbem\\wmiprvse.exe <br>
   <b>IntegrityLevel</b>: System <br>
   <b>PipeName</b>: \\lsass <br>
   <b>ProcessGuid</b>: {515cd0d1-5650-5d5e-0000-001074330200} <br>
   <b>ProcessId</b>: 2748 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>User</b>: NT AUTHORITY\\NETWORK SERVICE <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
 <tr>
  <td>
   19
  </td>
  <td>
  </td>
  <td>
  </td>
 </tr>
 <tr>
  <td>
   20
  </td>
  <td>
  </td>
  <td>
  </td>
 </tr>
 <tr>
  <td>
   21
  </td>
  <td>
  </td>
  <td>
  </td>
 </tr>
 <tr>
  <td>
   22
  </td>
  <td>
   Microsoft-Windows-Sysmon/Operational
  </td>
  <td>
   <b>Image</b>: C:\\Windows\\System32\\wermgr.exe <br>
   <b>IntegrityLevel</b>: System <br>
   <b>ProcessGuid</b>: {515cd0d1-57c3-5d5e-0000-001092da3000} <br>
   <b>ProcessId</b>: 6204 <br>
   <b>QueryName</b>: watson.telemetry.microsoft.com <br>
   <b>QueryResults</b>:  <br>
   <b>QueryStatus</b>: 1460 <br>
   <b>RuleName</b>:  <br>
   <b>Services</b>: N/A <br>
   <b>User</b>: NT AUTHORITY\\SYSTEM <br>
   <b>UtcTime</b>: 4242-04-24 13:37:42.422
  </td>
 </tr>
</table>
