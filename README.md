# Active Directory Firewall

## Intro

![Windows Firewall with Advanced Security Screenshot](Screenshots/windows-firewall.png)

## Active Directory Domain Services

### References

- [How to configure a firewall for Active Directory domains and trusts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Service overview and network port requirements for Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

### Inbound Rules

#### Client Traffic

| Name | Group | Protocol | Port | Program | Service |
|------|-------|----------|------------|---------|---------|
| Active Directory Domain Controller - Echo Request (ICMPv4-In) | Active Directory Domain Services | ICMPv4 | - | System | - |
| Active Directory Domain Controller - Echo Request (ICMPv6-In) | Active Directory Domain Services | ICMPv6 | - | System | - |
| Active Directory Domain Controller - LDAP (TCP-In) |  Active Directory Domain Services | TCP | 389 | %systemroot%\System32\lsass.exe | - |
| Active Directory Domain Controller - LDAP (UDP-In) |  Active Directory Domain Services | UDP | 389 | %systemroot%\System32\lsass.exe | - |

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

## Active Directory Federation Services
