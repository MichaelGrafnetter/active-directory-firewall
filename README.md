# Active Directory Firewall

## Intro

![Windows Firewall with Advanced Security Screenshot](Screenshots/windows-firewall.png)

## Active Directory Domain Services

### References

- [How to configure a firewall for Active Directory domains and trusts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Service overview and network port requirements for Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

### Inbound Rules

#### Client Traffic

| <!-- --> | <!-- -->                                                      |
|----------|---------------------------------------------------------------|
| Name     | Active Directory Domain Controller - Echo Request (ICMPv4-In) |
| Group    | Active Directory Domain Services |
| Protocol | ICMPv4 |
| Program  | System |
| Notes    | - |

| <!-- --> | <!-- -->                                                      |
|----------|---------------------------------------------------------------|
| Name     | Active Directory Domain Controller - Echo Request (ICMPv6-In) |
| Group    | Active Directory Domain Services |
| Protocol | ICMPv6 |
| Program  | System |
| Notes    | - |

| <!-- --> | <!-- -->                                                      |
|----------|---------------------------------------------------------------|
| Name     | Active Directory Domain Controller - LDAP (TCP-In)            |
| Group    | Active Directory Domain Services |
| Protocol | TCP |
| Port     | 389 |
| Program  | %systemroot%\System32\lsass.exe |
| Notes    | - |

| <!-- --> | <!-- -->                                                      |
|----------|---------------------------------------------------------------|
| Name     | Active Directory Domain Controller - LDAP (UDP-In)            |
| Group    | Active Directory Domain Services |
| Protocol | UDP |
| Port     | 389 |
| Program  | %systemroot%\System32\lsass.exe |
| Notes    | - |

#### Management Traffic

#### DC Replication Traffic

### Outbound Rules

### Static RPC Ports

### RPC Filters 

#### References

- [MSRPC-To-ATT&CK](https://github.com/jsecurity101/MSRPC-to-ATTACK)
- [A Definitive Guide to the Remote Procedure Call (RPC) Filter](https://www.akamai.com/blog/security/guide-rpc-filter#using)
- [server22_rpc_servers_scrape.csv](https://github.com/akamai/akamai-security-research/blob/main/rpc_toolkit/rpc_interface_lists/server22_rpc_servers_scrape.csv)

## Active Directory Certificate Services

- [Firewall Rules for Active Directory Certificate Services](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/firewall-rules-for-active-directory-certificate-services/ba-p/1128612)

## Active Directory Federation Services

- [AD FS Required Ports and Protocols](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs#ports-required)