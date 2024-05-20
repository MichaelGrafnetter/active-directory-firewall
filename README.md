# Active Directory Firewall

## Introduction

This project aims to provide production-ready and well-tested guidelines on configuring the Windows Firewall for Active Directory-related server roles.

![Windows Firewall with Advanced Security Screenshot](Images/Screenshots/windows-firewall.png)

## Domain Controller Firewall

The following materials are currently available:

- [🛠️Domain Controller Firewall Tool (DCFWTool)](ADDS/DCFWTool/)
- [📄Deployment Documentation](https://github.com/MichaelGrafnetter/active-directory-firewall/releases/latest) (PDF [generated](.github/workflows/generate-whitepaper.yml) from the [ADDS/README.md](ADDS/README.md) file)
- [📜Sample Firewall GPO HTML Report](ADDS/GPOReport.html)
- [📋List of Built-In Firewall Rules](ADDS/inbound-builtin-firewall-rules.csv)

## References

### Active Directory Domain Services

- [🌐 How to configure a firewall for Active Directory domains and trusts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [🌐 Service overview and network port requirements for Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

### Active Directory Certificate Services

- [🌐 Firewall Rules for Active Directory Certificate Services](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/firewall-rules-for-active-directory-certificate-services/ba-p/1128612)

### Active Directory Federation Services

- [🌐 AD FS Required Ports and Protocols](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs#ports-required)
