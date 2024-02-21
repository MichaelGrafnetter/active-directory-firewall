<#
.SYNOPSIS
Creates a Group Policy Object (GPO) that configures the Windows Firewall for Domain Controllers (DCs).

.DESCRIPTION

.NOTES
Author:  Michael Grafnetter
Version: 1.0

#>

#Requires -Modules NetSecurity,GroupPolicy
#Requires -Version 5

Set-StrictMode -Version Latest -ErrorAction Stop
Import-Module -Name NetSecurity,GroupPolicy -ErrorAction Stop

[string] $gpoName = 'DC Firewall'
[string] $gpoComment = 'Created by script.'
[bool] $blockOutboundTraffic = $false
[bool] $logDroppedPackets = $true

# Try to fetch the target GPO
[Microsoft.GroupPolicy.Gpo] $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

if($null -eq $gpo)
{
    # Create the GPO if it does not exist
    $gpo = New-GPO -Name $gpoName -Comment $gpoComment -Verbose -ErrorAction Stop
}

if($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled)
{
    # Fix the GPO status
    # TODO: Verbose
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if($gpo.Description -ne $gpoComment)
{
    # Fix the GPO description
    # TODO: Verbose
    $gpo.Description = $gpoComment
}

# Contruct the qualified GPO name
[string] $policyStore = '{0}\{1}' -f $gpo.DomainName,$gpo.DisplayName

# Remove any pre-existing firewall rules
Remove-NetFirewallRule -All -PolicyStore $policyStore -Verbose -ErrorAction Stop

# Open the GPO
[string] $gpoSession = Open-NetGPO -PolicyStore $policyStore -ErrorAction Stop

# Determine the default outbound action
[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action] $defaultOutboundAction = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Allow

if($blockOutboundTraffic)
{
    $defaultOutboundAction = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Block
}

# Determine the dropped packet logging settings
[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean] $logBlocled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False

if($logDroppedPackets)
{
    $logBlocled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True
}

[int] $maxLogFileSize = 32MB # Logs really cannot be bigger than 32MB!

# Configure all firewall profiles (Domain, Private, and Public)
Set-NetFirewallProfile -GPOSession $gpoSession `
                       -All `
                       -Enabled True `
                       -DefaultInboundAction Block `
                       -DefaultOutboundAction $defaultOutboundAction `
                       -AllowLocalFirewallRules False `
                       -AllowUnicastResponseToMulticast False `
                       -NotifyOnListen False `
                       -LogFileName '%systemroot%\system32\logfiles\firewall\pfirewall.log' `
                       -LogMaxSizeKilobytes ($maxLogFileSize/1KB-1) `
                       -LogBlocked $logBlocled `
                       -LogAllowed False `
                       -LogIgnored False `
                       -Verbose `
                       -ErrorAction Stop

# Create Inbound rule "Active Directory Domain Controller - W32Time (NTP-UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'W32Time-NTP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - W32Time (NTP-UDP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow NTP traffic for the Windows Time service. [UDP 123]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 123 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\svchost.exe' `
                    -Service 'w32time' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller (RPC-EPMAP)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-RPCEPMAP-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller (RPC-EPMAP)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the RPCSS service to allow RPC/TCP traffic to the Active Directory Domain Controller service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPCEPMap `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'rpcss' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center - PCR (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{04C4FC79-D3F1-4597-A4E2-724C7E544ABF}' `
                    -DisplayName 'Kerberos Key Distribution Center - PCR (UDP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [UDP 464]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 464 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center - PCR (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{DBC7B56C-1058-4DAC-8994-A6AC2A9D35CE}' `
                    -DisplayName 'Kerberos Key Distribution Center - PCR (TCP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [TCP 464]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 464 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-RPC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller (RPC)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule to allow remote RPC/TCP access to the Active Directory Domain Controller service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - LDAP (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - LDAP (UDP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [UDP 389]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 389 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - LDAP (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAP-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - LDAP (TCP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote LDAP traffic. [TCP 389]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 389 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - Secure LDAP (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAPSEC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - Secure LDAP (TCP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote Secure LDAP traffic. [TCP 636]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 636 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAPGC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote Global Catalog traffic. [TCP 3268]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3268 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-LDAPGCSEC-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow remote Secure Global Catalog traffic. [TCP 3269]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3269 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DNS (UDP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{4C695187-A3B5-4CDB-999C-386D3ADF2B98}' `
                    -DisplayName 'DNS (UDP, Incoming)' `
                    -Group '@firewallapi.dll,-53012' `
                    -Description 'Inbound rule to allow remote UDP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 53 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DNS (TCP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{B227B296-DB1A-43DD-AD6B-B94FDB2A807C}' `
                    -DisplayName 'DNS (TCP, Incoming)' `
                    -Group '@firewallapi.dll,-53012' `
                    -Description 'Inbound rule to allow remote TCP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 53 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "File Replication (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{13C054C8-7F03-4BA3-9B4A-439700CD56F8}' `
                    -DisplayName 'File Replication (RPC)' `
                    -Group '@ntfrsres.dll,-525' `
                    -Description 'Inbound rule to allow File Replication RPC traffic.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\NTFRS.exe' `
                    -Service 'NTFRS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{46F8569F-DAA4-45EC-BFEA-EA40FA214DB0}' `
                    -DisplayName 'Kerberos Key Distribution Center (TCP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service. [TCP 88]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 88 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{35BAD697-2FFD-498A-AF8A-8941507899F3}' `
                    -DisplayName 'Kerberos Key Distribution Center (UDP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service. [UDP 88]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 88 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - SAM/LSA (NP-UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-NP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - SAM/LSA (NP-UDP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [UDP 445]' `
                    -Enabled False `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 445 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - SAM/LSA (NP-TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-NP-TCP-In' `
                    -DisplayName 'Active Directory Domain Controller - SAM/LSA (NP-TCP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [TCP 445]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 445 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DFS Replication (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{C1DFBB01-2307-498C-8107-592E37B7EC81}' `
                    -DisplayName 'DFS Replication (RPC-In)' `
                    -Group '@FirewallAPI.dll,-37702' `
                    -Description 'Inbound rule to allow DFS Replication RPC traffic.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dfsrs.exe' `
                    -Service 'Dfsr' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller -  Echo Request (ICMPv4-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP4-In' `
                    -DisplayName 'Active Directory Domain Controller -  Echo Request (ICMPv4-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv4 `
                    -IcmpType 8 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller -  Echo Request (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP6-In' `
                    -DisplayName 'Active Directory Domain Controller -  Echo Request (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 128 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - NetBIOS name resolution (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{F371EA70-3231-43CB-93BE-3E8230615589}' `
                    -DisplayName 'Active Directory Domain Controller - NetBIOS name resolution (UDP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow NetBIOS name resolution. [UDP 138]' `
                    -Enabled False `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 138 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Destination Unreachable (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{A5C294FC-1DB0-435B-B45F-E0B42DBAB4A5}' `
                    -DisplayName 'Core Networking - Destination Unreachable (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Destination Unreachable error messages are sent from any node that a packet traverses which is unable to forward the packet for any reason except congestion.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 1 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{132A3D94-52EE-4C8F-8B95-2244FC667C45}' `
                    -DisplayName 'Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Destination Unreachable Fragmentation Needed error messages are sent from any node that a packet traverses which is unable to forward the packet because fragmentation was needed and the don''t fragment bit was set.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv4 `
                    -IcmpType 3:4 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{AD224DDF-0DEE-4B32-BF07-33CEFF9AE2CA}' `
                    -DisplayName 'Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 136 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{7A244106-8B29-4E42-A6FF-A281EFD3A0A4}' `
                    -DisplayName 'Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 135 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Packet Too Big (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{D7B7AF15-6EF0-4857-B8C6-189B8F415977}' `
                    -DisplayName 'Core Networking - Packet Too Big (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 2 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Parameter Problem (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{AE4EC77A-23DD-4AB2-9974-EE53FB704584}' `
                    -DisplayName 'Core Networking - Parameter Problem (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 4 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Time Exceeded (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{20F352EA-DFED-4874-8A09-201C4DFB8F2F}' `
                    -DisplayName 'Core Networking - Time Exceeded (ICMPv6-In)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 3 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Web Services (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADWS-TCP-In' `
                    -DisplayName 'Active Directory Web Services (TCP-In)' `
                    -Group '@%SystemRoot%\system32\firewallapi.dll,-53426' `
                    -Description 'Inbound rule for the Active Directory Web Services. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 9389 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe' `
                    -Service 'adws' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Remote Management (HTTP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINRM-HTTP-In-TCP-PUBLIC' `
                    -DisplayName 'Windows Remote Management (HTTP-In)' `
                    -Group '@FirewallAPI.dll,-30267' `
                    -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 5985 `
                    -RemoteAddress LocalSubnet `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Management Instrumentation (WMI-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WMI-WINMGMT-In-TCP' `
                    -DisplayName 'Windows Management Instrumentation (WMI-In)' `
                    -Group '@FirewallAPI.dll,-34251' `
                    -Description 'Inbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'winmgmt' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Desktop - User Mode (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteDesktop-UserMode-In-UDP' `
                    -DisplayName 'Remote Desktop - User Mode (UDP-In)' `
                    -Group '@FirewallAPI.dll,-28752' `
                    -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 3389 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Desktop - User Mode (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteDesktop-UserMode-In-TCP' `
                    -DisplayName 'Remote Desktop - User Mode (TCP-In)' `
                    -Group '@FirewallAPI.dll,-28752' `
                    -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3389 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DFS Management (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{A48BE1C2-DCD0-4ED9-BD81-65CA684038A7}' `
                    -DisplayName 'DFS Management (TCP-In)' `
                    -Group '@FirewallAPI.dll,-37802' `
                    -Description 'Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\dfsfrsHost.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "RPC (TCP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{EB15F1AF-B208-4EFD-AA60-B3B3DEA87F17}' `
                    -DisplayName 'RPC (TCP, Incoming)' `
                    -Group '@firewallapi.dll,-53012' `
                    -Description 'Inbound rule to allow remote RPC/TCP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Domain Controller -  Echo Request (ICMPv4-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{B0379302-26BF-46E0-B731-9ECCCA2549A2}' `
                    -DisplayName 'Active Directory Domain Controller -  Echo Request (ICMPv4-Out)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Outbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv4 `
                    -IcmpType 8 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Domain Controller -  Echo Request (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{D1EA7D65-980E-42C0-B462-A865840813D3}' `
                    -DisplayName 'Active Directory Domain Controller -  Echo Request (ICMPv6-Out)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Outbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 128 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Domain Controller (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{BA86A0A2-68E3-4366-811D-A3B794EA6359}' `
                    -DisplayName 'Active Directory Domain Controller (TCP-Out)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Outbound rule for the Active Directory Domain Controller service. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Domain Controller (UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{F1C5912B-0663-4344-A0CD-4CC5544C99F4}' `
                    -DisplayName 'Active Directory Domain Controller (UDP-Out)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Outbound rule for the Active Directory Domain Controller service. [UDP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Web Services (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{3B5E6FD9-45EF-46CA-B96A-4DD0383E9BBD}' `
                    -DisplayName 'Active Directory Web Services (TCP-Out)' `
                    -Group '@%SystemRoot%\system32\firewallapi.dll,-53426' `
                    -Description 'Outbound rule for the Active Directory Web Services. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe' `
                    -Service 'adws' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - DNS (UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{E23FCABD-E4FA-4E47-8343-C61E3CDAFB9F}' `
                    -DisplayName 'Core Networking - DNS (UDP-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Outbound rule to allow DNS requests. DNS responses based on requests that matched this rule will be permitted regardless of source address.  This behavior is classified as loose source mapping. [LSM] [UDP 53]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 53 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'dnscache' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Group Policy (NP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{3536ED0C-9C2D-4A61-87A7-4940E49748EE}' `
                    -DisplayName 'Core Networking - Group Policy (NP-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Core Networking - Group Policy (NP-Out)' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 445 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Group Policy (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{E2A89153-2599-4758-90F0-2FFE9B641466}' `
                    -DisplayName 'Core Networking - Group Policy (TCP-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Outbound rule to allow remote RPC traffic for Group Policy updates. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'gpsvc' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{A191FCFE-7D79-4ED1-B4BC-73A5CACCFCC5}' `
                    -DisplayName 'Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 136 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Neighbor Discovery Solicitation (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{D1EE65ED-4B17-418C-B7F6-7CDBC7D73AFB}' `
                    -DisplayName 'Core Networking - Neighbor Discovery Solicitation (ICMPv6-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 135 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Packet Too Big (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{15AC1073-64C7-4CC2-9E04-A407F1F652DF}' `
                    -DisplayName 'Core Networking - Packet Too Big (ICMPv6-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 2 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Parameter Problem (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{B42AA23D-A67C-4DAC-97F7-71FD6E4090D0}' `
                    -DisplayName 'Core Networking - Parameter Problem (ICMPv6-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 4 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Time Exceeded (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{8059CAC7-AD9D-40E7-81EA-0C7F19752ECB}' `
                    -DisplayName 'Core Networking - Time Exceeded (ICMPv6-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol ICMPv6 `
                    -IcmpType 3 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "All Outgoing (TCP)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{CA18A5B1-3113-421B-8022-9A7DEE157497}' `
                    -DisplayName 'All Outgoing (TCP)' `
                    -Group '@firewallapi.dll,-53012' `
                    -Description 'Outbound rule to allow all TCP traffic from the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "All Outgoing (UDP)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{D105FFEF-5BD4-4AC5-ADC8-8BFE2437DC1F}' `
                    -DisplayName 'All Outgoing (UDP)' `
                    -Group '@firewallapi.dll,-53012' `
                    -Description 'Outbound rule to allow all UDP traffic from the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "File and Printer Sharing (NB-Datagram-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{9E3C996B-A69B-47FA-A780-DCE75F4EA9B8}' `
                    -DisplayName 'File and Printer Sharing (NB-Datagram-Out)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Outbound rule for File and Printer Sharing to allow NetBIOS Datagram transmission and reception. [UDP 138]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 138 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "File and Printer Sharing (NB-Name-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{DCC4C794-DBF3-4E21-8A42-1A3DBF36547C}' `
                    -DisplayName 'File and Printer Sharing (NB-Name-Out)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Outbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 137 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "File and Printer Sharing (NB-Session-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{2BFA65F4-D6B4-4AC4-ACE0-97217F3438EC}' `
                    -DisplayName 'File and Printer Sharing (NB-Session-Out)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Outbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 139 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Management Instrumentation (WMI-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{39691525-BC5D-4497-B8FA-365898EE4A70}' `
                    -DisplayName 'Windows Management Instrumentation (WMI-Out)' `
                    -Group '@FirewallAPI.dll,-34251' `
                    -Description 'Outbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'winmgmt' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "iSCSI Service (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{47CE3FB7-D494-452B-85F3-75717F9D7383}' `
                    -DisplayName 'iSCSI Service (TCP-Out)' `
                    -Group '@FirewallAPI.dll,-29002' `
                    -Description 'Outbound rule for the iSCSI Service to allow communications with an iSCSI server or device. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'Msiscsi' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

Save-NetGPO -GPOSession $gpoSession -ErrorAction Stop
