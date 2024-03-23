---
subtitle: ​​Deployment Documentation​ 
author:
  - Pavel Formanek
  - Michael Grafnetter
date: March 23, 2024
lang: en-US
keywords:
  - Active Directory
  - Firewall
  - Domain Controller
  - PowerShell
  - Group Policy
  - Security
header-includes:
- |
  ```{=latex}
  \let\oldsection\section
  \renewcommand{\section}{\clearpage\oldsection}
  ```
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

[Admin Model]: https://petri.com/use-microsofts-active-directory-tier-administrative-model/
[System Center Operations Manager]: https://learn.microsoft.com/en-us/system-center/scom/get-started
[Network Location Awareness]: https://learn.microsoft.com/en-us/windows/win32/winsock/network-location-awareness-service-provider-nla--2
[Privileged Access Workstation]: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices

## Summary

The goal of this tool is to simplify deployment of specific set of firewall rules and filters that can significantly decrease the Domain Controller attack surface without compromising impacting the Active Directory functionality.
  
The tool provides a flexible and repeatable way to deploy secure configuration in your environment within minutes.  

![Windows Firewall with Advanced Security](../Screenshots/windows-firewall.png)

## Design

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
- Both Inbound and Outbound rules are configured and enforced by default (can be changed in the configuration file).
- All rules are configured for all 3 profiles (Domain, Private and Public), to avoid DC unavailability in case of incorrect network type detection by NLA.
- Many of the services, which normally use dynamic ports, are configured with static port by the tool, to allow easier tracing and troubleshooting on the network level and to simplify rule configuration for network firewalls.

## Prerequisites

- Domain administrator role or adequate role, allowing for creation of a GPO, creation of folders and files in SYSVOL and linking the GPO to Domain Controllers OU.
- PowerShell version 5.1
- PowerShell modules
  - GroupPolicy
  - ActiveDirectory
- Supported OS: Windows 2016 / Windows 10

## Configuration

All settings that are configurable are stored in `Set-ADDSFirewallPolicy.json`, it is essential to review them and change as necessary for your environment. Improper configuration can cause network outages in your environment!

Note, that “Default value” in the configuration items below, refers to default value, that is set in the `Set-ADDSFirewallPolicy.json`, not Windows system defaults.

```json
{
    "GroupPolicyObjectName": "Domain Controller Firewall",
    "GroupPolicyObjectComment": "This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.",
    "EnforceOutboundRules": true,
    "LogDroppedPackets": true,
    "LogMaxSizeKilobytes": 128,
    "ClientAddresses": [ "10.220.2.0/24", "10.220.4.0/24", "10.220.5.0/24", "10.220.6.0/24" ],
    "ManagementAddresses": [ "10.220.3.0/24" ],
    "DomainControllerAddresses": [ "10.220.1.0/24" ],
    "NtdsStaticPort": 38901,
    "NetlogonStaticPort": 38902,
    "DfsrStaticPort": 5722,
    "WmiStaticPort": true,
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
    "EnableInternetTraffic": true
}
```

The following settings are contained in the configuration file:

### GroupPolicyObjectName

Default value: "Domain Controller Firewall"

Description: Name of the GPO, that will be created in your environment, feel free to change it so it complies with your naming policy.

### GroupPolicyObjectComment

Default value: "This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script."

Description: Comment that will be visible on the GPO object.  

### EnforceOutboundRules

Default value: true

Possible values: true / false

Description: If true, enforces the firewall outbound rules. If false, only inbound firewall rules are enforced.

### LogDroppedPackets

Default value: true

Possible values: true / false

Description: If true, all dropped packets will be logged into the firewall text log. If false, no packets are logged.  

### LogMaxSizeKilobytes

Default value: 128

Possible values: 1 - 32767

Description: Size of the firewall log in KB.  The file won't grow beyond this size; when the limit is reached, old log entries are deleted to make room for the newly created ones.

### ClientAddresses

Default value: N/A

Possible values: IPv4 address, IPv4 subnet or IPv4 address range, separated by a comma, e.g. "10.220.2.0/24", "10.220.4.0/24", "10.220.5.0/24", "10.220.6.0/24".

Description: Specify IPv4 address, IPv4 subnet or address range of all your clients. Anything what acts as a client from a DC perspective is considered client here, so you should specify all your server and user/client subnets.  
Everything that needs to interact with your DCs should be included here, except other DCs and secure endpoints (PAWs) used to manage Domain Controllers or Tier 0.

**This is a critical configuration setting!** With improper configuration, this could cause network outage for your clients.

### ManagementAddresses

Default value: N/A

Possible values: IPv4 address, IPv4 subnet or IPv4 address range, separated by a comma, e.g. "10.220.3.0/24"

Description: Specify IPv4 address, IPv4 subnet or address range of all secure endpoints (PAWs) used to manage Domain Controllers or Tier 0.  

**This is a critical configuration setting!** With improper configuration, this could cause network outage for your management workstations.

### DomainControllerAddresses

Default value: N/A

Possible values: IPv4 address, IPv4 subnet or IPv4 address range, separated by a comma, e.g. "10.220.1.0/24"

Description: Specify IPv4 address, IPv4 subnet or address range of all your Domain Controllers in the forest.

**This is a critical configuration setting!** With improper configuration, this could cause network outage for your DCs.

### NtdsStaticPort

Default value: 38901

Possible values: null / 0 / 1024 - 49151

Description: By default, the RPC is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for Active Directory RPC traffic. See the [How to restrict Active Directory RPC traffic to a specific port](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/restrict-ad-rpc-traffic-to-specific-port) article for more information.
If set to 0 (zero), the port is set to dynamic.
If this is configured, you also need to configure the `NetlogonStaticPort` value.

### NetlogonStaticPort

Default value: 38902

Possible values: null / 0 / 1024 - 49151

Description: By default, the RPC is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for Active Directory RPC traffic. See the [How to restrict Active Directory RPC traffic to a specific port](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/restrict-ad-rpc-traffic-to-specific-port) article for more information.
If set to 0 (zero), the port is set to dynamic.
If this is configured, you also need to configure `NtdsStaticPort` value.

### DfsrStaticPort

Default value: 5722

Possible values: null / 0 / 1024 - 49151

Description: By default, the DFSR is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If value is defined, this value will be set as static port for DFS Replication traffic, for more info, see the [Configuring DFSR to a Static Port - The rest of the story](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/configuring-dfsr-to-a-static-port-the-rest-of-the-story/ba-p/396746) article.
If set to 0 (zero), the port is set to dynamic.

### WmiStaticPort

Default value: true

Possible values: null / true / false

Description: By default, the WMI is using dynamic ports 49152 – 65535. If null, this setting is not managed through GPO. If true, WMI will use static port 24158, if false, WMI will use dynamic port. For more info, see the [Setting Up a Fixed Port for WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-up-a-fixed-port-for-wmi) article.

### DisableLLMNR

Default value: true

Possible values: true / false

Description: If true, Link Local Multicast Name Resolution (LLMNR) is disabled. If false, LLMNR is enabled. For more info, please refer to the *AZ-WIN-00145* configuration item in the [Windows security baseline](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows).

### DisableMDNS

Default value: true

Possible values: null / true / false

Description: If null, this setting is not managed through GPO. If true, multicast DNS (mDNS) is disabled. If false, mDNS is enabled. For more info, see the following [Microsoft article](https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777).

### EnableServiceManagement

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote services management will be available. If false, services cannot be managed remotely.

### EnableEventLogManagement

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote Event Log management will be available. If false, Event Log cannot be managed remotely.

### EnableScheduledTaskManagement

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote scheduled tasks management will be available. If false, scheduled tasks cannot be managed remotely.

### EnableWindowsRemoteManagement

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and Windows Remote Management (WinRM) will be available. If false, WinRM ports won’t be open. For more info, see the following [Microsoft article](https://learn.microsoft.com/en-us/windows/win32/winrm/about-windows-remote-management).

### EnablePerformanceLogAccess

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote Performance Log management will be available. If false, Performance Log cannot be managed remotely.  

### EnableOpenSSHServer

TODO

### EnableRemoteDesktop

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote desktop connection (RDP) will be available. If false, RDP is not available.  

### EnableDiskManagement

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote disk management will be available. If false, disks cannot be managed remotely.  

### EnableBackupManagement

Default value: true

Possible values: true / false

Description: If true, corresponding ports are open and remote Windows Backup management will be available. If false, Windows Backup cannot be managed remotely.  

### EnableFirewallManagement

Default value: false

Possible values: true / false

Description: If true, corresponding ports are open and remote Windows Defender Firewall management will be available. If false, Windows Defender Firewall cannot be managed remotely.

### EnableComPlusManagement

Default value: false

Possible values: true / false

Description: If true, corresponding ports are open and remote DCOM traffic for COM+ System Application management is allowed. If false, COM+ System Application cannot be managed remotely. For more info, see the following [Microsoft article](https://learn.microsoft.com/en-us/windows/win32/cossdk/com--application-overview).

### EnableLegacyFileReplication

Default value: false

Possible values: true / false

Description: If true, corresponding ports are open for NTFRS replication. If you still haven’t migrated your SYSVOL replication to modern DFSR, you need to enable this setting. If false, NTFRS ports won’t be open. For more info, see the following [Microsoft article](https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr).

### EnableNetbiosNameService

Default value: false

Possible values: true / false

Description: If true, corresponding ports (UDP 137) are open and NetBIOS will be available. If false, NetBIOS ports are not open.

### EnableNetbiosDatagramService

Default value: false

Possible values: true / false

Description: If true, corresponding ports (UDP 138) are open and NetBIOS will be available. If false, NetBIOS ports are not open.

### EnableNetbiosSessionService

Default value: false

Possible values: true / false

Description: If true, corresponding ports (TCP 139) are open and NetBIOS will be available. If false, NetBIOS ports are not open.  

### EnableWINS

Default value: false

Possible values: true / false

Description: If true, corresponding ports are open and Windows Internet Naming Service (WINS) will be available. If false, WINS ports are not open.  

### EnableNetworkProtection

TODO

### EnableInternetTraffic

TODO

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

## Rollback

If you need to rollback the changes, simply unlink the GPO from Domain Controllers OU and either wait 5 minutes or do gpupdate /force on the DCs.

## Issues

### Services with User Impersonation

- Windows Update (wuauserv)
- Cryptographic Services (CryptSvc)
- Microsoft Account Sign-in Assistant (wlidsvc)
- Background Intelligent Transfer Service (BITS)

### Dynamic Keywords

https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords

### taskhostw.exe

![Scheduled task with a custom handler](../Screenshots/scheduled-task-custom-handler.png)

### Azure Arc

PowerShell, msiexec

![Azure Arc binaries](../Screenshots/azure-arc-binaries.png)

Any process

![Azure Arc built-in firewall rule](../Screenshots/azure-arc-firewall.png)

### Predefined Address Sets

![Predefined address sets in Windows Firwall](../Screenshots/firewall-predefined-sets.png)

- Internet
- Intranet
- DNS Servers

### Proxy

![Listing the advanced WinHTTP proxy configuration](../Screenshots/proxy-config.png)

![WinHTTP proxy configuration error](../Screenshots/proxy-error.png)

### Log File Not Created

![Firewall log file configuration](../Screenshots/firewall-log-config.png)

```bat
netsh advfirewall set allprofiles logging filename "%systemroot%\system32\logfiles\firewall\pfirewall.log"
```

## Troubleshooting

`Show-WindowsFirewallLog.ps1`

![Parsing firewall log files](../Screenshots/firewall-log-parser.png)

## Static RPC Ports

TODO: Rationale

- [How to restrict Active Directory RPC traffic to a specific port](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/restrict-ad-rpc-traffic-to-specific-port)
- [Configuring DFSR to a Static Port - The rest of the story](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/configuring-dfsr-to-a-static-port-the-rest-of-the-story/ba-p/396746)
- [Setting Up a Fixed Port for WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-up-a-fixed-port-for-wmi)

## RPC Filters

## References

- [MSRPC-To-ATT&CK](https://github.com/jsecurity101/MSRPC-to-ATTACK)
- [A Definitive Guide to the Remote Procedure Call (RPC) Filter](https://www.akamai.com/blog/security/guide-rpc-filter#using)
- [server22_rpc_servers_scrape.csv](https://github.com/akamai/akamai-security-research/blob/main/rpc_toolkit/rpc_interface_lists/server22_rpc_servers_scrape.csv)

## Inbound Rules

### References

- [How to configure a firewall for Active Directory domains and trusts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Service overview and network port requirements for Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

### Client Traffic

#### Active Directory Domain Controller - W32Time (NTP-UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - W32Time (NTP-UDP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | UDP |
| Port        | 123 |
| Program     | `%systemroot%\System32\svchost.exe` |
| Service     | `w32time` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow NTP traffic for the Windows Time service. [UDP 123] |
| Notes       | - |

#### Active Directory Domain Controller (RPC-EPMAP)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | Active Directory Domain Controller (RPC-EPMAP) |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | 135 |
| Program     | `%systemroot%\system32\svchost.exe` |
| Service     | `rpcss` |
| Description | Inbound rule for the RPCSS service to allow RPC/TCP traffic to the Active Directory Domain Controller service. |
| Notes       | - |

#### Kerberos Key Distribution Center - PCR (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Kerberos Key Distribution Center - PCR (UDP-In)** |
| Group       | Kerberos Key Distribution Center |
| Protocol    | UDP |
| Port        | 464 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [UDP 464] |
| Notes       | - |

#### Kerberos Key Distribution Center - PCR (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Kerberos Key Distribution Center - PCR (TCP-In)** |
| Group       | Kerberos Key Distribution Center |
| Protocol    | TCP |
| Port        | 464 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [TCP 464] |
| Notes       | - |

#### Active Directory Domain Controller (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller (RPC)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule to allow remote RPC/TCP access to the Active Directory Domain Controller service. |
| Notes       | - |

#### Active Directory Domain Controller - LDAP (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - LDAP (UDP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | UDP |
| Port        | 389 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [UDP 389] |
| Notes       | - |

#### Active Directory Domain Controller - LDAP (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - LDAP (TCP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | 389 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [TCP 389] |
| Notes       | - |

#### Active Directory Domain Controller - Secure LDAP (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - Secure LDAP (TCP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | 636 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote Secure LDAP traffic. [TCP 636] |
| Notes       | - |

#### Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | 3268 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote Global Catalog traffic. [TCP 3268] |
| Notes       | - |

#### Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | 3269 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow remote Secure Global Catalog traffic. [TCP 3269] |
| Notes       | - |

#### DNS (UDP, Incoming)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **DNS (UDP, Incoming)** |
| Group       | DNS Service |
| Protocol    | UDP |
| Port        | 53 |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Inbound rule to allow remote UDP access to the DNS service. |
| Notes       | - |

#### DNS (TCP, Incoming)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **DNS (TCP, Incoming)** |
| Group       | DNS Service |
| Protocol    | TCP |
| Port        | 53 |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Inbound rule to allow remote TCP access to the DNS service. |
| Notes       | - |

#### Kerberos Key Distribution Center (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Kerberos Key Distribution Center (TCP-In)** |
| Group       | Kerberos Key Distribution Center |
| Protocol    | TCP |
| Port        | 88 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service. [TCP 88] |
| Notes       | - |

#### Kerberos Key Distribution Center (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Kerberos Key Distribution Center (UDP-In)** |
| Group       | Kerberos Key Distribution Center |
| Protocol    | UDP |
| Port        | 88 |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Inbound rule for the Kerberos Key Distribution Center service. [UDP 88] |
| Notes       | - |

#### Active Directory Domain Controller - SAM/LSA (NP-UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - SAM/LSA (NP-UDP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | UDP |
| Port        | 445 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [UDP 445] |
| Notes       | - |

#### Active Directory Domain Controller - SAM/LSA (NP-TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - SAM/LSA (NP-TCP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | 445 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [TCP 445] |
| Notes       | - |

#### Active Directory Domain Controller - Echo Request (ICMPv4-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - Echo Request (ICMPv4-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | ICMPv4 |
| ICMP Type   | 8 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping). |
| Notes       | - |

#### Active Directory Domain Controller - Echo Request (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - Echo Request (ICMPv6-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | ICMPv6 |
| ICMP Type   | 128 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping). |
| Notes       | - |

#### Active Directory Domain Controller - NetBIOS name resolution (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller - NetBIOS name resolution (UDP-In)** |
| Group       | Active Directory Domain Services |
| Protocol    | UDP |
| Port        | 138 |
| Program     | `System` |
| Description | Inbound rule for the Active Directory Domain Controller service to allow NetBIOS name resolution. [UDP 138] |
| Notes       | - |

#### Core Networking - Destination Unreachable (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Destination Unreachable (ICMPv6-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 1 |
| Program     | `System` |
| Description | Destination Unreachable error messages are sent from any node that a packet traverses which is unable to forward the packet for any reason except congestion. |
| Notes       | - |

#### Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv4 |
| ICMP Type   | 3:4 |
| Program     | `System` |
| Description | Destination Unreachable Fragmentation Needed error messages are sent from any node that a packet traverses which is unable to forward the packet because fragmentation was needed and the don't fragment bit was set. |
| Notes       | - |

#### Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 136 |
| Program     | `System` |
| Description | Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request. |
| Notes       | - |

#### Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 135 |
| Program     | `System` |
| Description | Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node. |
| Notes       | - |

#### Core Networking - Packet Too Big (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Packet Too Big (ICMPv6-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 2 |
| Program     | `System` |
| Description | Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link. |
| Notes       | - |

#### Core Networking - Parameter Problem (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Parameter Problem (ICMPv6-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 4 |
| Program     | `System` |
| Description | Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets. |
| Notes       | - |

#### Core Networking - Time Exceeded (ICMPv6-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Time Exceeded (ICMPv6-In)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 3 |
| Program     | `System` |
| Description | Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path. |
| Notes       | - |

### Management Traffic

#### Active Directory Web Services (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Web Services (TCP-In)** |
| Group       | Active Directory Web Services |
| Protocol    | TCP |
| Port        | 9389 |
| Program     | `%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe` |
| Service     | `adws` |
| Description | Inbound rule for the Active Directory Web Services. [TCP] |
| Notes       | - |

#### Windows Remote Management (HTTP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Windows Remote Management (HTTP-In)** |
| Group       | Windows Remote Management |
| Protocol    | TCP |
| Port        | 5985 |
| Program     | `System` |
| Description | Inbound rule for Windows Remote Management via WS-Management. [TCP 5985] |
| Notes       | - |

#### Windows Management Instrumentation (WMI-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Windows Management Instrumentation (WMI-In)** |
| Group       | Windows Management Instrumentation (WMI) |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `winmgmt` |
| Description | Inbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP] |
| Notes       | - |

#### Remote Desktop - User Mode (UDP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Desktop - User Mode (UDP-In)** |
| Group       | Remote Desktop |
| Protocol    | UDP |
| Port        | 3389 |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `termservice` |
| Description | Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389] |
| Notes       | - |

#### Remote Desktop - User Mode (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Desktop - User Mode (TCP-In)** |
| Group       | Remote Desktop |
| Protocol    | TCP |
| Port        | 3389 |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `termservice` |
| Description | Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389] |
| Notes       | - |

#### OpenSSH SSH Server (sshd)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **OpenSSH SSH Server (sshd)** |
| Group       | OpenSSH Server |
| Protocol    | TCP |
| Port        | 22 |
| Program     | `%SystemRoot%\system32\OpenSSH\sshd.exe` |
| Description | Inbound rule for OpenSSH SSH Server (sshd) |
| Notes       | - |

#### DFS Management (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **DFS Management (TCP-In)** |
| Group       | DFS Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\system32\dfsfrsHost.exe` |
| Description | Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM. |
| Notes       | - |

#### RPC (TCP, Incoming)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **RPC (TCP, Incoming)** |
| Group       | DNS Service |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Inbound rule to allow remote RPC/TCP access to the DNS service. |
| Notes       | - |

#### Windows Backup (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Windows Backup (RPC)** |
| Group       | Windows Backup |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\system32\wbengine.exe` |
| Service     | `wbengine` |
| Description | Inbound rule for the Windows Backup Service to be remotely managed via RPC/TCP |
| Notes       | - |

#### DFS Management (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **DFS Management (TCP-In)** |
| Group       | DFS Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%systemroot%\system32\dfsfrsHost.exe` |
| Description | Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM. |
| Notes       | - |

#### Performance Logs and Alerts (TCP-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Performance Logs and Alerts (TCP-In)** |
| Group       | Performance Logs and Alerts |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%systemroot%\system32\plasrv.exe` |
| Description | Inbound rule for Performance Logs and Alerts traffic. [TCP-In] |
| Notes       | - |

#### Remote Event Log Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Event Log Management (RPC)** |
| Group       | Remote Event Log Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `Eventlog` |
| Description | Inbound rule for the local Event Log service to be remotely managed via RPC/TCP. |
| Notes       | - |

#### Remote Scheduled Tasks Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Scheduled Tasks Management (RPC)** |
| Group       | Remote Scheduled Tasks Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `schedule` |
| Description | Inbound rule for the Task Scheduler service to be remotely managed via RPC/TCP. |
| Notes       | - |

#### Remote Service Management (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Service Management (RPC)** |
| Group       | Remote Service Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\services.exe` |
| Description | Inbound rule for the local Service Control Manager to be remotely managed via RPC/TCP. |
| Notes       | - |

#### Remote Volume Management - Virtual Disk Service (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Volume Management - Virtual Disk Service (RPC)** |
| Group       | Remote Volume Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\vds.exe` |
| Service     | `vds` |
| Description | Inbound rule for the Remote Volume Management - Virtual Disk Service to be remotely managed via RPC/TCP. |
| Notes       | - |

#### Remote Volume Management - Virtual Disk Service Loader (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Remote Volume Management - Virtual Disk Service Loader (RPC)** |
| Group       | Remote Volume Management |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\vdsldr.exe` |
| Description | Inbound rule for the Remote Volume Management - Virtual Disk Service Loader to be remotely managed via RPC/TCP. |
| Notes       | - |

### DC Replication Traffic

#### DFS Replication (RPC-In)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **DFS Replication (RPC-In)** |
| Group       | DFS Replication |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\dfsrs.exe` |
| Service     | `Dfsr` |
| Description | Inbound rule to allow DFS Replication RPC traffic. |
| Notes       | - |

#### File Replication (RPC)

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **File Replication (RPC)** |
| Group       | File Replication |
| Protocol    | TCP |
| Port        | RPC |
| Program     | `%SystemRoot%\system32\NTFRS.exe` |
| Service     | `NTFRS` |
| Description | Inbound rule to allow File Replication RPC traffic. |
| Notes       | - |

## Outbound Rules

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller -  Echo Request (ICMPv4-Out)** |
| Group       | Active Directory Domain Services |
| Protocol    | ICMPv4 |
| ICMP Type   | 8 |
| Program     | `System` |
| Description | Outbound rule for the Active Directory Domain Controller service to allow Echo requests (ping). |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller -  Echo Request (ICMPv6-Out)** |
| Group       | Active Directory Domain Services |
| Protocol    | ICMPv6 |
| ICMP Type   | 128 |
| Program     | `System` |

| Description | Outbound rule for the Active Directory Domain Controller service to allow Echo requests (ping). |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller (TCP-Out)** |
| Group       | Active Directory Domain Services |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Outbound rule for the Active Directory Domain Controller service. [TCP] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Domain Controller (UDP-Out)** |
| Group       | Active Directory Domain Services |
| Protocol    | UDP |
| Port        | Any |
| Program     | `%systemroot%\System32\lsass.exe` |
| Description | Outbound rule for the Active Directory Domain Controller service. [UDP] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Active Directory Web Services (TCP-Out)** |
| Group       | Active Directory Web Services |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe` |
| Service     | `adws` |
| Description | Outbound rule for the Active Directory Web Services. [TCP] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - DNS (UDP-Out)** |
| Group       | Core Networking |
| Protocol    | UDP |
| Port        | 53 |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `dnscache` |
| Description | Outbound rule to allow DNS requests. DNS responses based on requests that matched this rule will be permitted regardless of source address.  This behavior is classified as loose source mapping. [LSM] [UDP 53] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Group Policy (NP-Out)** |
| Group       | Core Networking |
| Protocol    | TCP |
| Port        | 445 |
| Program     | `System` |
| Description | Core Networking - Group Policy (NP-Out) |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Group Policy (TCP-Out)** |
| Group       | Core Networking |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `gpsvc` |
| Description | Outbound rule to allow remote RPC traffic for Group Policy updates. [TCP] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 136 |
| Program     | `System` |
| Description | Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Neighbor Discovery Solicitation (ICMPv6-Out)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 135 |
| Program     | `System` |
| Description | Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Packet Too Big (ICMPv6-Out)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 2 |
| Program     | `System` |
| Description | Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Parameter Problem (ICMPv6-Out)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 4 |
| Program     | `System` |
| Description | Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Core Networking - Time Exceeded (ICMPv6-Out)** |
| Group       | Core Networking |
| Protocol    | ICMPv6 |
| ICMP Type   | 3 |
| Program     | `System` |
| Description | Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **All Outgoing (TCP)** |
| Group       | DNS Service |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Outbound rule to allow all TCP traffic from the DNS service. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **All Outgoing (UDP)** |
| Group       | DNS Service |
| Protocol    | UDP |
| Port        | Any |
| Program     | `%systemroot%\System32\dns.exe` |
| Service     | `dns` |
| Description | Outbound rule to allow all UDP traffic from the DNS service. |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **File and Printer Sharing (NB-Datagram-Out)** |
| Group       | File and Printer Sharing |
| Protocol    | UDP |
| Port        | 138 |
| Program     | `System` |
| Description | Outbound rule for File and Printer Sharing to allow NetBIOS Datagram transmission and reception. [UDP 138] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **File and Printer Sharing (NB-Name-Out)** |
| Group       | File and Printer Sharing |
| Protocol    | UDP |
| Port        | 137 |
| Program     | `System` |
| Description | Outbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **File and Printer Sharing (NB-Session-Out)** |
| Group       | File and Printer Sharing |
| Protocol    | TCP |
| Port        | 139 |
| Program     | `System` |
| Description | Outbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **Windows Management Instrumentation (WMI-Out)** |
| Group       | Windows Management Instrumentation (WMI) |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `winmgmt` |
| Description | Outbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP] |
| Notes       | - |

| Property    | Value |
|-------------|---------------------------------------------------|
| Name        | **iSCSI Service (TCP-Out)** |
| Group       | iSCSI Service |
| Protocol    | TCP |
| Port        | Any |
| Program     | `%SystemRoot%\system32\svchost.exe` |
| Service     | `Msiscsi` |
| Description | Outbound rule for the iSCSI Service to allow communications with an iSCSI server or device. [TCP] |
| Notes       | - |
