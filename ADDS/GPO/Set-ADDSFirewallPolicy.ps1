<#
.SYNOPSIS
Creates a Group Policy Object (GPO) that configures the Windows Firewall for Domain Controllers (DCs).

.DESCRIPTION

.PARAMETER ConfigurationFileName
Specifies the name of the configuration file from which some firewall settings are applied.

.NOTES
Author:  Michael Grafnetter
Version: 1.0

#>

#Requires -Modules NetSecurity,GroupPolicy,ActiveDirectory
#Requires -Version 5

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigurationFileName = 'Set-ADDSFirewallPolicy.json'
)

# Apply additional runtime validation
Set-StrictMode -Version Latest -ErrorAction Stop

# Preload the required modules
Import-Module -Name NetSecurity,GroupPolicy,ActiveDirectory -ErrorAction Stop

#region Configuration

# Set the default configuration values, which can be overridden by an external JSON file
class ScriptSettings {
    # The name of the Group Policy Object (GPO) that will be created or updated.
    [string]           $GroupPolicyObjectName         = 'Domain Controller Firewall'

    # The comment that will be added to the Group Policy Object (GPO).
    [string]           $GroupPolicyObjectComment      = 'This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.'

    # Indicates whether the outbound traffic should be blocked by default.
    [bool]             $EnforceOutboundRules          = $false

    # Indicates whether the packets dropped by the firewall should be logged.
    [bool]             $LogDroppedPackets             = $false

    # The path to the log file that will be used to store information about the dropped packets.
    [string]           $LogFilePath                   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'

    # The maximum size of the firewall log file in kilobytes.
    [uint16]           $LogMaxSizeKilobytes           = [int16]::MaxValue

    # List of client IP adresses from which inbound traffic should be allowed.
    [string[]]         $ClientAddresses               = 'Any'

    # List of IP addresses from which inbound management traffic should be allowed.
    [string[]]         $ManagementAddresses           = 'Any'

    # List of domain controller IP addresses, between which replication and management traffic will be allowed.
    [string[]]         $DomainControllerAddresses     = 'Any'

    # Static port to be used for inbound Active Directory RPC traffic.
    [Nullable[uint16]] $NtdsStaticPort                = $null

    # Static port to be used for inbound Netlogon traffic.
    [Nullable[uint16]] $NetlogonStaticPort            = $null

    # Static port to be used for DFSR traffic.
    [Nullable[uint16]] $DfsrStaticPort                = $null

    # Static port to be used for legacy FRS traffic.
    [Nullable[uint16]] $FrsStaticPort                 = $null

    # Indicates whether WMI traffic should use a static port.
    [Nullable[bool]]   $WmiStaticPort                 = $null

    # Indicates whether the NetBIOS protocol should be switched to P-node (point-to-point).
    [Nullable[bool]]   $DisableNetbiosBroadcasts      = $null

    # "Indicates whether the Link-Local Multicast Name Resolution (LLMNR) client should be disabled.
    [bool]             $DisableLLMNR                  = $false

    # Indicates whether the Multicast DNS (mDNS) client should be disabled.
    [Nullable[bool]]   $DisableMDNS                   = $null

    # Indicates whether remote service management should be enabled.
    [bool]             $EnableServiceManagement       = $true

    # Indicates whether remote event log management should be enabled.
    [bool]             $EnableEventLogManagement      = $true

    # Indicates whether remote scheduled task management should be enabled.
    [bool]             $EnableScheduledTaskManagement = $true

    # Indicates whether inbound Windows Remote Management traffic should be enabled.
    [bool]             $EnableWindowsRemoteManagement = $true

    # Indicates whether remote performance log access should be enabled.
    [bool]             $EnablePerformanceLogAccess    = $true

    # Indicates whether inbound OpenSSH traffic should be enabled.
    [bool]             $EnableOpenSSHServer           = $true

    # Indicates whether inbound Remote Desktop traffic should be enabled.
    [bool]             $EnableRemoteDesktop           = $true

    # Indicates whether remote disk management should be enabled.
    [bool]             $EnableDiskManagement          = $true

    # Indicates whether remote backup management should be enabled.
    [bool]             $EnableBackupManagement        = $true

    # Indicates whether remote firewall management should be enabled.
    [bool]             $EnableFirewallManagement      = $true

    # Indicates whether inbound COM+ management traffic should be enabled.
    [bool]             $EnableComPlusManagement       = $true

    # Indicates whether inbound legacy file replication traffic should be enabled.
    [bool]             $EnableLegacyFileReplication   = $true

    # Indicates whether inbound and outbound NetBIOS Name Service should be allowed.
    [bool]             $EnableNetbiosNameService      = $true

    # Indicates whether inbound and outbound NetBIOS Datagram Service traffic should be allowed.
    [bool]             $EnableNetbiosDatagramService  = $true

    # Indicates whether inbound and outbound NetBIOS Session Service (NBSS) traffic should be allowed.
    [bool]             $EnableNetbiosSessionService   = $true

    # Indicates whether inbound and outbound Windows Internet Name Service (WINS) traffic should be allowed.
    [bool]             $EnableWINS                    = $true

    # Indicates whether the Network protection feature of Microsoft Defender Antivirus should be enabled.
    [bool]             $EnableNetworkProtection       = $false

    # Indicates whether outbound internet traffic (HTTP/HTTPS) should be enabled for all processes.
    [bool]             $EnableInternetTraffic         = $true
}

[ScriptSettings] $configuration = [ScriptSettings]::new()

# Load the configuration from the JSON file
[string] $configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFileName -ErrorAction Stop

[System.Runtime.Serialization.Json.DataContractJsonSerializer] $serializer = [System.Runtime.Serialization.Json.DataContractJsonSerializer]::new([ScriptSettings])
[System.IO.FileStream] $stream = [System.IO.File]::Open($configurationFilePath, [System.IO.FileMode]::Open)
try {
    $configuration = $serializer.ReadObject($stream)
}
catch {
    # Do not continue if there is any issue reading the configuration file
    throw
}
finally {
    $stream.Close()
}

#endregion Configuration
#region Create and Configure the GPO

# Try to fetch the target GPO
[Microsoft.GroupPolicy.Gpo] $gpo = Get-GPO -Name $configuration.GroupPolicyObjectName -ErrorAction SilentlyContinue

if($null -eq $gpo) {
    # Create the GPO if it does not exist
    $gpo = New-GPO -Name $configuration.GroupPolicyObjectName -Comment $configuration.GroupPolicyObjectComment -Verbose -ErrorAction Stop
}

if($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled) {
    # Fix the GPO status
    # TODO: Verbose
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if($gpo.Description -ne $configuration.GroupPolicyObjectComment) {
    # Fix the GPO description
    # TODO: Verbose
    $gpo.Description = $configuration.GroupPolicyObjectComment
}

#endregion Create and configure the GPO
#region Firewall Profiles

# Contruct the qualified GPO name
[string] $policyStore = '{0}\{1}' -f $gpo.DomainName,$gpo.DisplayName

# Open the GPO
# Note: The Open-NetGPO cmdlet by default contacts a random DC instead of PDC-E
# TODO: Verbose
[Microsoft.ActiveDirectory.Management.ADDomain] $domain = Get-ADDomain -Current LoggedOnUser -ErrorAction Stop
[string] $gpoSession = Open-NetGPO -PolicyStore $policyStore -DomainController $domain.PDCEmulator -ErrorAction Stop

# Remove any pre-existing firewall rules
# Note: As Microsoft removed the -GPOSession parameter from the Remove-NetFirewallRule in Windows Server 2022, low-level CIM operations need to be used instead.

# The source GPO session is provided as a custom CIM operation option.
[Microsoft.Management.Infrastructure.Options.CimOperationOptions] $cimOperationOptions =
    [Microsoft.Management.Infrastructure.Options.CimOperationOptions]::new()
$cimOperationOptions.SetCustomOption('GPOSession', $gpoSession, $false)

# Open a temporary local CIM session
[CimSession] $localSession = New-CimSession -ErrorAction Stop

try {
    # Fetch all firewall rules from the GPO
    [ciminstance[]] $gpoFirewallRules = $localSession.EnumerateInstances('ROOT\StandardCimv2','MSFT_NetFirewallRule', $cimOperationOptions)

    # Remove all firewall rules from the GPO
    foreach($rule in $gpoFirewallRules) {
        Write-Verbose -Message ('Deleting firewall rule {0}.' -f $rule.Name) -Verbose
        $localSession.DeleteInstance('ROOT\StandardCimv2', $rule, $cimOperationOptions)
    }
}
finally {
    # Close the temporary local CIM session
    Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue
}

# Determine the default outbound action
[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action] $defaultOutboundAction = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Allow

if($configuration.EnforceOutboundRules) {
    $defaultOutboundAction = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Block
}

# Determine the dropped packet logging settings
[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean] $logBlocled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False

if($configuration.LogDroppedPackets) {
    $logBlocled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True
}

# Sanitize the maximum log file size
if($configuration.LogMaxSizeKilobytes -gt [int16]::MaxValue -or $configuration.LogMaxSizeKilobytes -le 0) {
    # Windows only accepts 1KB-32MB as the maximum log file size.
    $configuration.LogMaxSizeKilobytes = [int16]::MaxValue # = 32MB
}

# Configure all firewall profiles (Domain, Private, and Public)
Set-NetFirewallProfile -GPOSession $gpoSession `
                       -All `
                       -Enabled True `
                       -AllowInboundRules True `
                       -DefaultInboundAction Block `
                       -DefaultOutboundAction $defaultOutboundAction `
                       -AllowLocalFirewallRules False `
                       -AllowUnicastResponseToMulticast False `
                       -NotifyOnListen False `
                       -LogFileName $configuration.LogFilePath `
                       -LogMaxSizeKilobytes $configuration.LogMaxSizeKilobytes `
                       -LogBlocked $logBlocled `
                       -LogAllowed False `
                       -LogIgnored False `
                       -Verbose `
                       -ErrorAction Stop

[string[]] $allAddresses =
    ($configuration.ClientAddresses + $configuration.DomainControllerAddresses + $configuration.ManagementAddresses) |
    Sort-Object -Unique

if($allAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $allAddresses = @('Any')
}

[string[]] $dcAndManagementAddresses =
    ($configuration.DomainControllerAddresses + $configuration.ManagementAddresses) |
    Sort-Object -Unique

if($dcAndManagementAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $dcAndManagementAddresses = @('Any')
}

#endregion Firewall Profiles
#region Helper Functions

<#
.SYNOPSIS
Converts a boolean value to a NetSecurity.Enabled enumeration value, which is accepted by the New-NetFirewallRule cmdlet.

.PARAMETER Value
The boolean value to convert.

#>
function ConvertTo-NetSecurityEnabled {
    [OutputType([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [bool] $Value
    )

    if($Value) {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True
    }
    else {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False
    }
}

#endregion Helper Functions
#region Inbound Firewall Rules

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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'rpcss' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center - PCR (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-Password-UDP-In' `
                    -DisplayName 'Kerberos Key Distribution Center - PCR (UDP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [UDP 464]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 464 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center - PCR (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-Password-TCP-In' `
                    -DisplayName 'Kerberos Key Distribution Center - PCR (TCP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service to allow for password change requests. [TCP 464]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 464 `
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DNS (UDP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-DNS-UDP-In' `
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
                    -Name 'DNSSrv-DNS-TCP-In' `
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
                    -Name 'NTFRS-NTFRSSvc-In-TCP' `
                    -DisplayName 'File Replication (RPC)' `
                    -Group '@ntfrsres.dll,-525' `
                    -Description 'Inbound rule to allow File Replication RPC traffic.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableLegacyFileReplication) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%SystemRoot%\system32\NTFRS.exe' `
                    -Service 'NTFRS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-TCP-In' `
                    -DisplayName 'Kerberos Key Distribution Center (TCP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service. [TCP 88]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 88 `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\System32\lsass.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Kerberos Key Distribution Center (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-Kerberos-UDP-In' `
                    -DisplayName 'Kerberos Key Distribution Center (UDP-In)' `
                    -Group '@kdcsvc.dll,-1008' `
                    -Description 'Inbound rule for the Kerberos Key Distribution Center service. [UDP 88]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 88 `
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DFS Replication (RPC-In)"
# Note that a static port 5722 was used before Windows Server 2012
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DFSR-DFSRSvc-In-TCP' `
                    -DisplayName 'DFS Replication (RPC-In)' `
                    -Group '@FirewallAPI.dll,-37702' `
                    -Description 'Inbound rule to allow DFS Replication RPC traffic.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.DomainControllerAddresses `
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
                    -RemoteAddress $allAddresses `
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
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Active Directory Domain Controller - NetBIOS name resolution (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-NB-Datagram-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - NetBIOS name resolution (UDP-In)' `
                    -Group '@FirewallAPI.dll,-37601' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to allow NetBIOS name resolution. [UDP 138]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosDatagramService) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 138 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "File and Printer Sharing (NB-Name-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FPS-NB_Name-In-UDP' `
                    -DisplayName 'File and Printer Sharing (NB-Name-In)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Inbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosNameService) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 137 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "File and Printer Sharing (NB-Session-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FPS-NB_Session-In-TCP' `
                    -DisplayName 'File and Printer Sharing (NB-Session-In)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Inbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosSessionService) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 139 `
                    -RemoteAddress $allAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Internet Naming Service (WINS) (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-In-UDP' `
                    -DisplayName 'Windows Internet Naming Service (WINS) (UDP-In)' `
                    -Group ' @%SystemRoot%\System32\firewallapi.dll,-53300' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow WINS requests. [UDP 42]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 42 `
                    -RemoteAddress $allAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Internet Naming Service (WINS) (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-In-TCP' `
                    -DisplayName 'Windows Internet Naming Service (WINS) (TCP-In)' `
                    -Group ' @%SystemRoot%\System32\firewallapi.dll,-53300' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow WINS requests. [TCP 42]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 42 `
                    -RemoteAddress $allAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Internet Naming Service (WINS) - Remote Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-In-RPC' `
                    -DisplayName 'Windows Internet Naming Service (WINS) - Remote Management (RPC)' `
                    -Group '@%SystemRoot%\System32\firewallapi.dll,-53311' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow remote management via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Destination Unreachable (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-DU-In' `
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
                    -Name 'CoreNet-ICMP4-DUFRAG-In' `
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
                    -Name 'CoreNet-ICMP6-NDA-In' `
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
                    -Name 'CoreNet-ICMP6-NDS-In' `
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
                    -Name 'CoreNet-ICMP6-PTB-In' `
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
                    -Name 'CoreNet-ICMP6-PP-In' `
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
                    -Name 'CoreNet-ICMP6-TE-In' `
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
                    -RemoteAddress $dcAndManagementAddresses `
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
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWindowsRemoteManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 5985 `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Remote Management (HTTPS-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINRM-HTTPS-In-TCP-PUBLIC' `
                    -DisplayName 'Windows Remote Management (HTTPS-In)' `
                    -Group '@FirewallAPI.dll,-30267' `
                    -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWindowsRemoteManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 5986 `
                    -RemoteAddress $dcAndManagementAddresses `
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
                    -RemoteAddress $dcAndManagementAddresses `
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
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableRemoteDesktop) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 3389 `
                    -RemoteAddress $configuration.ManagementAddresses `
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
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableRemoteDesktop) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3389 `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "DFS Management (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DfsMgmt-In-TCP' `
                    -DisplayName 'DFS Management (TCP-In)' `
                    -Group '@FirewallAPI.dll,-37802' `
                    -Description 'Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%systemroot%\system32\dfsfrsHost.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "RPC (TCP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-RPC-TCP-In' `
                    -DisplayName 'RPC (TCP, Incoming)' `
                    -Group '@firewallapi.dll,-53012' `
                    -Description 'Inbound rule to allow remote RPC/TCP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Backup (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WindowsServerBackup-wbengine-In-TCP-NoScope' `
                    -DisplayName 'Windows Backup (RPC)' `
                    -Group '@wbengine.exe,-106' `
                    -Description 'Inbound rule for the Windows Backup Service to be remotely managed via RPC/TCP' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableBackupManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%systemroot%\system32\wbengine.exe' `
                    -Service 'wbengine' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Performance Logs and Alerts (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'PerfLogsAlerts-PLASrv-In-TCP-NoScope' `
                    -DisplayName 'Performance Logs and Alerts (TCP-In)' `
                    -Group '@FirewallAPI.dll,-34752' `
                    -Description 'Inbound rule for Performance Logs and Alerts traffic. [TCP-In]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnablePerformanceLogAccess) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort Any `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%systemroot%\system32\plasrv.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Event Log Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteEventLogSvc-In-TCP' `
                    -DisplayName 'Remote Event Log Management (RPC)' `
                    -Group '@FirewallAPI.dll,-29252' `
                    -Description 'Inbound rule for the local Event Log service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableEventLogManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'Eventlog' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Scheduled Tasks Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteTask-In-TCP' `
                    -DisplayName 'Remote Scheduled Tasks Management (RPC)' `
                    -Group '@FirewallAPI.dll,-33252' `
                    -Description 'Inbound rule for the Task Scheduler service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableScheduledTaskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'schedule' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Service Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteSvcAdmin-In-TCP' `
                    -DisplayName 'Remote Service Management (RPC)' `
                    -Group '@FirewallAPI.dll,-29502' `
                    -Description 'Inbound rule for the local Service Control Manager to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableServiceManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\services.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "COM+ Remote Administration (DCOM-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ComPlusRemoteAdministration-DCOM-In' `
                    -DisplayName 'COM+ Remote Administration (DCOM-In)' `
                    -Group '@%systemroot%\system32\firewallapi.dll,-3405' `
                    -Description 'Inbound rule to allow DCOM traffic to the COM+ System Application for remote administration.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableComPlusManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%systemroot%\system32\dllhost.exe' `
                    -Service 'COMSysApp' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Defender Firewall Remote Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteFwAdmin-In-TCP' `
                    -DisplayName 'Windows Defender Firewall Remote Management (RPC)' `
                    -Group '@FirewallAPI.dll,-30002' `
                    -Description 'Inbound rule for the Windows Defender Firewall to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFirewallManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'policyagent' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Volume Management - Virtual Disk Service (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RVM-VDS-In-TCP' `
                    -DisplayName 'Remote Volume Management - Virtual Disk Service (RPC)' `
                    -Group '@FirewallAPI.dll,-34501' `
                    -Description 'Inbound rule for the Remote Volume Management - Virtual Disk Service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDiskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\vds.exe' `
                    -Service 'vds' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Volume Management - Virtual Disk Service Loader (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RVM-VDSLDR-In-TCP' `
                    -DisplayName 'Remote Volume Management - Virtual Disk Service Loader (RPC)' `
                    -Group '@FirewallAPI.dll,-34501' `
                    -Description 'Inbound rule for the Remote Volume Management - Virtual Disk Service Loader to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDiskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\vdsldr.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "OpenSSH SSH Server (sshd)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'OpenSSH-Server-In-TCP' `
                    -DisplayName 'OpenSSH SSH Server (sshd)' `
                    -Group 'OpenSSH Server' `
                    -Description 'Inbound rule for OpenSSH SSH Server (sshd)' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableOpenSSHServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 22 `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\OpenSSH\sshd.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

#endregion Inbound Firewall Rules
#region Outbound Firewall Rules

# Create Outbound rule "Active Directory Domain Controller -  Echo Request (ICMPv4-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP4-Out' `
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
                    -Name 'ADDS-ICMP6-Out' `
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
                    -Name 'ADDS-TCP-Out' `
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
                    -Name 'ADDS-UDP-Out' `
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
                    -Name 'ADWS-TCP-Out' `
                    -DisplayName 'Active Directory Web Services (TCP-Out)' `
                    -Group '@%SystemRoot%\system32\firewallapi.dll,-53426' `
                    -Description 'Outbound rule for the Active Directory Web Services. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe' `
                    -Service 'adws' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - DNS (UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-DNS-Out-UDP' `
                    -DisplayName 'Core Networking - DNS (UDP-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Outbound rule to allow DNS requests. DNS responses based on requests that matched this rule will be permitted regardless of source address.  This behavior is classified as loose source mapping. [LSM] [UDP 53]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 53 `
                    -RemoteAddress 'DNS' `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'dnscache' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - DNS (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-DNS-Out-TCP' `
                    -DisplayName 'Core Networking - DNS (TCP-Out)' `
                    -Description 'Outbound rule to allow DNS requests.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 53 `
                    -RemoteAddress 'DNS' `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'dnscache' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Group Policy (NP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-GP-NP-Out-TCP' `
                    -DisplayName 'Core Networking - Group Policy (NP-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Core Networking - Group Policy (NP-Out)' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 445 `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Group Policy (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-GP-Out-TCP' `
                    -DisplayName 'Core Networking - Group Policy (TCP-Out)' `
                    -Group '@FirewallAPI.dll,-25000' `
                    -Description 'Outbound rule to allow remote RPC traffic for Group Policy updates. [TCP]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'gpsvc' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-NDA-Out' `
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
                    -Name 'CoreNet-ICMP6-NDS-Out' `
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
                    -Name 'CoreNet-ICMP6-PTB-Out' `
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
                    -Name 'CoreNet-ICMP6-PP-Out' `
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
                    -Name 'CoreNet-ICMP6-TE-Out' `
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
                    -Name 'DNSSrv-TCP-Out' `
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
                    -Name 'DNSSrv-UDP-Out' `
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
                    -Name 'FPS-NB_Datagram-Out-UDP' `
                    -DisplayName 'File and Printer Sharing (NB-Datagram-Out)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Outbound rule for File and Printer Sharing to allow NetBIOS Datagram transmission and reception. [UDP 138]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosDatagramService) `
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
                    -Name 'FPS-NB_Name-Out-UDP' `
                    -DisplayName 'File and Printer Sharing (NB-Name-Out)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Outbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosNameService) `
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
                    -Name 'FPS-NB_Session-Out-TCP' `
                    -DisplayName 'File and Printer Sharing (NB-Session-Out)' `
                    -Group '@FirewallAPI.dll,-28502' `
                    -Description 'Outbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNetbiosSessionService) `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 139 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Internet Naming Service (WINS) (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-Out-TCP' `
                    -DisplayName 'Windows Internet Naming Service (WINS) (TCP-Out)' `
                    -Group '@%SystemRoot%\System32\firewallapi.dll,-53300' `
                    -Description 'Outbound rule for the Windows Internet Naming Service. [TCP]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Internet Naming Service (WINS) (UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WINS-Service-Out-UDP' `
                    -DisplayName 'Windows Internet Naming Service (WINS) (UDP-Out)' `
                    -Group '@%SystemRoot%\System32\firewallapi.dll,-53300' `
                    -Description 'Outbound rule for the Windows Internet Naming Service. [UDP]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Management Instrumentation (WMI-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WMI-WINMGMT-Out-TCP' `
                    -DisplayName 'Windows Management Instrumentation (WMI-Out)' `
                    -Group '@FirewallAPI.dll,-34251' `
                    -Description 'Outbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP]' `
                    -Enabled False `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'winmgmt' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "iSCSI Service (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'MsiScsi-Out-TCP' `
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

# Create Outbound rule "DFS Replication (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DFSR-TCP-Out' `
                    -DisplayName 'DFS Replication (TCP-Out)' `
                    -Description 'Outbound rule to allow DFS Replication RPC traffic.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%SystemRoot%\system32\dfsrs.exe' `
                    -Service 'Dfsr' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Microsoft Management Console (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-MMC-TCP-Out' `
                    -DisplayName 'Administrative Tools - Microsoft Management Console (TCP-Out)' `
                    -Description 'Outbound rule for the MMC console to allow AD management, certificate requests, and other administrative actions.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\mmc.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Remote Procedure Call (RPC-EPMAP)"
# Note: It is not possible to limit the rule to the RpcEptMapper service, because of user impersonation.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RPCEPMAP-TCP-Out' `
                    -DisplayName 'Remote Procedure Call (RPC-EPMAP)' `
                    -Description 'Outbound rule for the RPCSS service to allow RPC/TCP traffic to other servers, including Certification Authority.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 135 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service Any `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Activation - KMS Connection Broker (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'KMS-Client-TCP-Out' `
                    -DisplayName 'Windows Activation - KMS Connection Broker (TCP-Out)' `
                    -Description 'Outbound rule to allow Windows activation against a KMS server.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 1688 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\SppExtComObj.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Active Directory Administrative Center (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsac-TCP-Out' `
                    -DisplayName 'Administrative Tools - Active Directory Administrative Center (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Active Directory Administrative Center.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsac.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Repadmin (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Repadmin-TCP-Out' `
                    -DisplayName 'Administrative Tools - Repadmin (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Repadmin tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\repadmin.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Setspn (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Setspn-TCP-Out' `
                    -DisplayName 'Administrative Tools - Setspn (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Setspn tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\setspn.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Server Manager (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-ServerManager-TCP-Out' `
                    -DisplayName 'Administrative Tools - Server Manager (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Server Manager.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\ServerManager.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dcdiag (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dcdiag-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dcdiag (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dcdiag tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dcdiag.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Ntdsutil (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Ntdsutil-TCP-Out' `
                    -DisplayName 'Administrative Tools - Ntdsutil (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Ntdsutil tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\ntdsutil.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dfsrdiag (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dfsrdiag-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dfsrdiag (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dfsrdiag tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dfsrdiag.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Nltest (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Nltest-TCP-Out' `
                    -DisplayName 'Administrative Tools - Nltest (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Nltest tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\nltest.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Ldifde (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Ldifde-TCP-Out' `
                    -DisplayName 'Administrative Tools - Ldifde (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Ldifde tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\ldifde.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Csvde (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Csvde-TCP-Out' `
                    -DisplayName 'Administrative Tools - Csvde (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Csvde tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\csvde.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dcpromo (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dcpromo-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dcpromo (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dcpromo tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dcpromo.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsacls (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsacls-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsacls (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsacls tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsacls.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsquery (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsquery-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsquery (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsquery tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsquery.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsget (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsget-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsget (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsget tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsget.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsadd (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsadd-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsadd (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsadd tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsadd.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsmod (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsmod-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsmod (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsmod tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsmod.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsmove (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsmove-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsmove (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsmove tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsmove.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Dsrm (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Dsrm-TCP-Out' `
                    -DisplayName 'Administrative Tools - Dsrm (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Dsrm tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\dsrm.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Ldp (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Ldp-TCP-Out' `
                    -DisplayName 'Administrative Tools - Ldp (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Ldp tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\ldp.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Netdom (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Netdom-TCP-Out' `
                    -DisplayName 'Administrative Tools - Netdom (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Netdom tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\netdom.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Net (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Net-TCP-Out' `
                    -DisplayName 'Administrative Tools - Net (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Net tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\net.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Redircmp (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Redircmp-TCP-Out' `
                    -DisplayName 'Administrative Tools - Redircmp (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Redircmp tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\redircmp.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Redirusr (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Redirusr-TCP-Out' `
                    -DisplayName 'Administrative Tools - Redirusr (TCP-Out)' `
                    -Description 'Outbound rule to allow AD management using the Redirusr tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\redirusr.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Certutil (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Certutil-TCP-Out' `
                    -DisplayName 'Administrative Tools - Certutil (TCP-Out)' `
                    -Description 'Outbound rule to allow certificate and CA management using the Certutil tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\certutil.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Certreq (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Certreq-TCP-Out' `
                    -DisplayName 'Administrative Tools - Certreq (TCP-Out)' `
                    -Description 'Outbound rule to allow certificate request submission using the Certreq tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\certreq.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - Nslookup (UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-Nslookup-UDP-Out' `
                    -DisplayName 'Administrative Tools - Nslookup (UDP-Out)' `
                    -Description 'Outbound rule to allow DNS queries using the Nslookup tool.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 53 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\nslookup.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Administrative Tools - W32tm (UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'AdminTools-W32tm-UDP-Out' `
                    -DisplayName 'Administrative Tools - W32tm (UDP-Out)' `
                    -Description 'Outbound rule to allow Windows Time service configuration and monitoring.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 123 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\w32tm.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Domain Controller - W32Time (NTP-UDP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'W32Time-NTP-UDP-Out' `
                    -DisplayName 'Active Directory Domain Controller - W32Time (NTP-UDP-Out)' `
                    -Description 'Outbound rule for the Active Directory Domain Controller service to allow NTP traffic for the Windows Time service. [UDP 123]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 123 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\System32\svchost.exe' `
                    -Service 'w32time' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Active Directory Domain Controller - Forest DC Connectivity (TCP-Out)"
# TODO: Parametrize
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-RemoteDC-TCP-Out' `
                    -DisplayName 'Active Directory Domain Controller - Forest DC Connectivity (TCP-Out)' `
                    -Description 'Outbound rule to allow DC-DC management.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program Any `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Core Networking - Network Location Awareness (HTTP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-NlaSvc-HTTP-Out' `
                    -DisplayName 'Core Networking - Network Location Awareness (HTTP-Out)' `
                    -Description 'Collects and stores configuration information for the network and notifies programs when this information is modified.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 80 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'NlaSvc' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Internet Traffic (HTTP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Internet-HTTP-Out' `
                    -DisplayName 'Internet Traffic (HTTP-Out)' `
                    -Description 'Outbound rule to allow unlimited HTTP traffic to the Internet. Required by cloud-enabled components, including Windows Update for Business and Azure Arc.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableInternetTraffic) `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 80,443 `
                    -RemoteAddress Any `
                    -Program Any `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

#endregion Outbound Firewall Rules
#region Windows Update Outbound Firewall Rules

<#
Enabling outbound communication for Windows Update and Windows Server Update Services is tricky.
The Windows Update, Delivery Optimization, Background Intelligent Transfer Service,
Cryptographic Services, and Device Setup Manager services are all hosted in the shared svchost.exe process.
These services sometimes impersonate the user, which makes it impossible to create a rule that only allows the services to communicate.
#>

# Create Outbound rule "Windows Update - Internet (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WindowsUpdate-TCP-Out' `
                    -DisplayName 'Windows Update - Internet (TCP-Out)' `
                    -Description 'Outbound rule to allow the Windows Update client to communicate with Microsoft public IP addresses.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 80,443 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service Any `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

<#
The same is true for Windows Server Update Services (WSUS) communication.
It is at least possible to distinguish the traffic based on the port numbers 8530 (HTTP) and 8531 (HTTPS),
which are used by WSUS by default.
#>

# Create Outbound rule "Windows Update - Windows Server Update Services (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-Client-TCP-Out' `
                    -DisplayName 'Windows Update - Windows Server Update Services (TCP-Out)' `
                    -Description 'Outbound rule for the detection, download and installation of device-related software from WSUS.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 8530,8531 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service Any `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Update - Update Session Orchestrator (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WindowsUpdate-USO-TCP-Out' `
                    -DisplayName 'Windows Update - Update Session Orchestrator (TCP-Out)' `
                    -Description 'A Windows OS component that orchestrates the sequence of downloading and installing various update types from Windows Update.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\MoUsoCoreWorker.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Cryptographic Service (TCP-Out)"
# The Cryptographic Services (CryptSvc) communicates with non-Microsoft IPs, including Akamai CDN.
[ciminstance] $cryptSvcRule = New-NetFirewallRule `
    -GPOSession $gpoSession `
    -Name 'CryptSvc-TCP-Out' `
    -DisplayName 'Cryptographic Service (TCP-Out)' `
    -Description 'Provides Catalog Database Service, Protected Root Service, and Automatic Root Certificate Update Service.' `
    -Enabled True `
    -Profile Any `
    -Direction Outbound `
    -Action Allow `
    -Protocol TCP `
    -RemotePort 80,443 `
    -RemoteAddress Any `
    -Verbose `
    -ErrorAction Stop

[string] $cryptSvcSid = 'S-1-5-80-242729624-280608522-2219052887-3187409060-2225943459'
Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $cryptSvcRule -ErrorAction Stop | Set-NetFirewallApplicationFilter -Package $cryptSvcSid -ErrorAction Stop -Verbose
                    
# TODO: Communication with Windows Update is sometimes also initiated by taskhostw.exe (Scheduled Task).

#endregion Windows Update Outbound Firewall Rules
#region Defender Outbound Firewall Rules

# Create Outbound rule "Microsoft Defender Antivirus - Command-Line Utility (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
# Windows 8.1 and Windows Server 2016 (MMA Based)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-MpCmdRun-TCP-Out' `
                    -DisplayName 'Microsoft Defender Antivirus - Command-Line Utility (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\MpCmdRun.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Endpoint DLP - Command-Line Utility (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-MpDlpCmd-TCP-Out' `
                    -DisplayName 'Microsoft Endpoint DLP - Command-Line Utility (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\MpDlpCmd.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender Antivirus - Service Executable (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
# Windows 8.1 and Windows Server 2016 (MMA Based)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-MsMpEng-TCP-Out' `
                    -DisplayName 'Microsoft Defender Antivirus - Service Executable (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\MsMpEng.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender Antivirus - Policy Configuration Tool (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
# Windows 8.1 and Windows Server 2016 (MMA Based)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-ConfigSecurityPolicy-TCP-Out' `
                    -DisplayName 'Microsoft Defender Antivirus - Policy Configuration Tool (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\ConfigSecurityPolicy.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender Antivirus - Core Service (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
# Windows 8.1 and Windows Server 2016 (MMA Based)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-MpDefenderCoreService-TCP-Out' `
                    -DisplayName 'Microsoft Defender Antivirus - Core Service (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\MpDefenderCoreService.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Endpoint DLP - Data Loss Prevention Service (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-MpDlpService-TCP-Out' `
                    -DisplayName 'Microsoft Endpoint DLP - Data Loss Prevention Service (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\MpDlpService.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender Antivirus - Network Realtime Inspection (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
# Windows 8.1 and Windows Server 2016 (MMA Based)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-NisSrv-TCP-Out' `
                    -DisplayName 'Microsoft Defender Antivirus - Network Realtime Inspection (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 80,443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender\NisSrv.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Service Executable (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-MsSense-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Service Executable (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Communication Module (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseCnCProxy-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Communication Module (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseCnCProxy.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Incident Response Module (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseIR-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Incident Response Module (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseIR.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Classification Engine Module (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseCE-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Classification Engine Module (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\Classification\SenseCE.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Sample Upload Module (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseSampleUploader-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Sample Upload Module (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseSampleUploader.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Network Detection and Response Module (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseNdr-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Network Detection and Response Module (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseNdr.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Screenshot Capture Module (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseSC-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Screenshot Capture Module (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseSC.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Configuration Management (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseCM-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Configuration Management (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseCM.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Microsoft Defender for Endpoint - Threat Vulnerability Management (TCP-Out)"
# Windows 11, Windows 10, Windows Server 2022 and Windows Server 2019
# Windows Server 2016 and Windows Server 2012 R2 (Unified Agent)
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DefenderAV-SenseTVM-TCP-Out' `
                    -DisplayName 'Microsoft Defender for Endpoint - Threat Vulnerability Management (TCP-Out)' `
                    -Description 'Outbound rule .' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 443 `
                    -RemoteAddress Any `
                    -Program '%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseTVM.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null
<# TODO: Add more rules for the following executables:
# Windows 8.1 and Windows Server 2016 (MMA Based)
# Windows 7 SP1, Windows Server 2012 R2 and Windows Server 2008 R2 (MMA Based)

                    MonitoringHost.exe	C:\Program Files\Microsoft Monitoring Agent\Agent	Microsoft Monitoring Agent Service Host Process
                    HealthService.exe	C:\Program Files\Microsoft Monitoring Agent\Agent	Microsoft Monitoring Agent Service
                    TestCloudConnection.exe	C:\Program Files\Microsoft Monitoring Agent\Agent	Microsoft Monitoring Agent Cloud Connection Test utility

# Windows 7 SP1, Windows Server 2012 R2 and Windows Server 2008 R2 (MMA Based)
MpCmdRun.exe	C:\Program Files\Microsoft Security Client	Microsoft Defender Antivirus command-line utility (SCEP)
MsMpEng.exe	C:\Program Files\Microsoft Security Client	Microsoft Defender Antivirus service executable (SCEP)
ConfigSecurityPolicy.exe	C:\Program Files\Microsoft Security Client	Microsoft Security Client Policy Configuration Tool (SCEP)
NisSrv.exe	C:\Program Files\Microsoft Security Client	Microsoft Defender Antivirus Network Realtime Inspection (SCEP)
#>

#endregion Defender Outbound Firewall Rules                  

# TODO: Verbose
Save-NetGPO -GPOSession $gpoSession -ErrorAction Stop

#region Registry Settings

# Set the Delivery Optimization Download Mode to Simple
# DCs should not be downloading updates from peers.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization' `
                    -ValueName 'DODownloadMode' `
                    -Value 99 `
                    -Type DWord `
                    -Verbose | Out-Null

# Set Allow Telemetry to Security [Enterprise Only]
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
                    -ValueName 'AllowTelemetry' `
                    -Value 0 `
                    -Type DWord `
                    -Verbose | Out-Null

# Turn off Application Telemetry
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
                    -ValueName 'AITEnable' `
                    -Value 0 `
                    -Type DWord `
                    -Verbose | Out-Null

<#
TODO: Add more registry settings
OneSettings

 Allow Diagnostic Data to Disabled.
Administrative Template > Windows Components > Data Collection and Preview Builds

#>

# Prevent users and apps from accessing dangerous websites
# (Enables Microsoft Defender Exploit Guard Network Protection)
# This might block some Internet C2 traffic.

# We will enable the audit mode by default
[int] $networkProtectionState = 2

if($configuration.EnableNetworkProtection) {
    # Switch Network Protection to Block mode
    $networkProtectionState = 1
}

Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                    -ValueName 'EnableNetworkProtection' `
                    -Value $networkProtectionState `
                    -Type DWord `
                    -Verbose | Out-Null

# Disable MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'EnableICMPRedirect' `
                    -Value 0 `
                    -Type DWord `
                    -Verbose | Out-Null

# MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'DisableIPSourceRouting' `
                    -Value 2 `
                    -Type DWord `
                    -Verbose | Out-Null

# MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)	
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters' `
                    -ValueName 'DisableIPSourceRouting' `
                    -Value 2 `
                    -Type DWord `
                    -Verbose | Out-Null

# Disable MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'PerformRouterDiscovery' `
                    -Value 0 `
                    -Type DWord `
                    -Verbose | Out-Null

# MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                    -ValueName 'NoNameReleaseOnDemand' `
                    -Value 1 `
                    -Type DWord `
                    -Verbose | Out-Null

if($null -ne $configuration.DisableNetbiosBroadcasts) {
    # NetBT NodeType configuration
    [int] $nodeType = 8 # Default to H-node (use WINS servers first, then use broadcast)

    if($configuration.DisableNetbiosBroadcasts) {
        $nodeType = 2 # P-node (use WINS servers only, recommended)
    }

    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                        -ValueName 'NodeType' `
                        -Value $nodeType `
                        -Type DWord `
                        -Verbose | Out-Null

    # Configure NetBIOS settings
    [int] $enableNetbios = 3 # Default to learning mode

    if($configuration.DisableNetbiosBroadcasts) {
        $enableNetbios = 0 # Disable NetBIOS
    }

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                        -ValueName 'EnableNetbios' `
                        -Value $enableNetbios `
                        -Type DWord `
                        -Verbose | Out-Null
} else {
    # Remove the NetBIOS-related settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                           -ValueName 'NodeType' `
                           -ErrorAction SilentlyContinue `
                           -Verbose | Out-Null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableNetbios' `
                           -ErrorAction SilentlyContinue `
                           -Verbose | Out-Null
}

# Turn off Link-Local Multicast Name Resolution (LLMNR)
if($configuration.DisableLLMNR -eq $true) {
    Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -Value 0 -Type DWord -Verbose | Out-Null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -ErrorAction SilentlyContinue -Verbose | Out-Null
}

# Turn off Multicast DNS (mDNS)
# Note: This is not a managed GPO setting.
if($null -ne $configuration.DisableMDNS) {
    Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'EnableMDNS' -Value ([int](-not $configuration.DisableMDNS)) -Type DWord -Verbose | Out-Null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'EnableMDNS' -ErrorAction SilentlyContinue -Verbose | Out-Null
}

# Configure the DRS-R protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.NtdsStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'TCP/IP Port' -Value ([int] $configuration.NtdsStaticPort) -Type DWord -Verbose | Out-Null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'TCP/IP Port' -ErrorAction SilentlyContinue -Verbose | Out-Null
}

# Configure the NETLOGON protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.NetlogonStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'DCTcpipPort' -Value ([int] $configuration.NetlogonStaticPort) -Type DWord -Verbose | Out-Null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'DCTcpipPort' -ErrorAction SilentlyContinue -Verbose | Out-Null
}

# Configure the FRS protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.FrsStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters' -ValueName 'RPC TCP/IP Port Assignment' -Value ([int] $configuration.FrsStaticPort) -Type DWord -Verbose | Out-Null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters' -ValueName 'RPC TCP/IP Port Assignment' -ErrorAction SilentlyContinue -Verbose | Out-Null
}

#endregion Registry Settings

#region Startup Script

# Fetch the GPO info from the PDC emulator
[Microsoft.ActiveDirectory.Management.ADObject] $gpoContainer = Get-ADObject -Identity $gpo.Path -Properties 'gPCFileSysPath','gPCMachineExtensionNames' -Server $domain.PDCEmulator -ErrorAction Stop
[string] $startupScriptDirectory = Join-Path -Path $gpoContainer.gPCFileSysPath -ChildPath 'Machine\Scripts\Startup' -ErrorAction Stop
[string] $scriptPath = Join-Path -Path $startupScriptDirectory -ChildPath 'FirewallConfiguration.bat' -ErrorAction Stop
[string] $scriptsIniPath = Join-Path -Path $gpoContainer.gPCFileSysPath -ChildPath 'Machine\Scripts\scripts.ini' -ErrorAction Stop

# Create the directory for startup scripts if it does not exist
New-Item -Path $startupScriptDirectory -ItemType Directory -Force -Verbose | Out-Null

# Startup script header
[System.Text.StringBuilder] $startupScript = [System.Text.StringBuilder]::new()
$startupScript.AppendLine('@ECHO OFF') | Out-Null
$startupScript.AppendLine('REM This script is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.') | Out-Null

# Configure the WMI  protocol to use the deafult static port 24158
if($configuration.WmiStaticPort -eq $true) {
    $startupScript.AppendLine() | Out-Null
    $startupScript.AppendLine('echo Move the WMI service to a standalone process listening on TCP port 24158 with authentication level set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY.') | Out-Null
    $startupScript.AppendLine('winmgmt.exe /standalonehost 6') | Out-Null
} elseif($configuration.WmiStaticPort -eq $false) {
    $startupScript.AppendLine() | Out-Null
    $startupScript.AppendLine('echo Move the WMI service into the shared Svchost process.') | Out-Null
    $startupScript.AppendLine('winmgmt.exe /sharedhost') | Out-Null
}

# Configure the DFS-R protocol to use a specific port
[string] $dfsrDiagInstallScript = @'
echo Install the dfsrdiag.exe tool if absent.
if not exist "%SystemRoot%\system32\dfsrdiag.exe" (
    dism.exe /Online /Enable-Feature /FeatureName:DfsMgmt
)
'@

if($configuration.DfsrStaticPort -ge 1) {
    $startupScript.AppendLine() | Out-Null
    $startupScript.AppendLine($dfsrDiagInstallScript) | Out-Null
    $startupScript.AppendLine('echo Set static RPC port for DFS Replication.') | Out-Null
    $startupScript.AppendFormat('dfsrdiag.exe StaticRPC /Port:{0}', $configuration.DfsrStaticPort) | Out-Null
    $startupScript.AppendLine() | Out-Null
} elseif($configuration.DfsrStaticPort -eq 0) {
    $startupScript.AppendLine() | Out-Null
    $startupScript.AppendLine($dfsrDiagInstallScript) | Out-Null
    $startupScript.AppendLine('echo Set dynamic RPC port for DFS Replication.') | Out-Null
    $startupScript.AppendLine('dfsrdiag.exe StaticRPC /Port:0') | Out-Null
}

# Create the firewall log file
$startupScript.AppendLine() | Out-Null
$startupScript.AppendLine('echo Create the firewall log file and configure its DACL.') | Out-Null
$startupScript.AppendFormat('netsh advfirewall set allprofiles logging filename "{0}"', $configuration.LogFilePath) | Out-Null

# Overwrite the script file
Set-Content -Path $scriptPath -Value $startupScript.ToString() -Encoding Ascii -Force -ErrorAction Stop -Verbose

# Register the startup script in the scripts.ini file
[string] $scriptsIni = @'
[Startup]
0CmdLine=FirewallConfiguration.bat
0Parameters=
'@

Set-Content -Path $scriptsIniPath -Value $scriptsIni -Encoding Ascii -Force -ErrorAction Stop -Verbose

# Register the Scripts client-side extension in AD if necessary
[string] $machineScriptsExtension = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'

if(-not $gpoContainer.gPCMachineExtensionNames.Contains($machineScriptsExtension)) {
    [string] $updatedMachineExtensionNames = $machineScriptsExtension + $gpoContainer.gPCMachineExtensionNames
    
    # The CSE GUIDs must be sorted in case-insensitive ascending order
    [string[]] $sortedExtensions =
        $updatedMachineExtensionNames.Split('[]') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($PSItem) } |
        Sort-Object -Culture ([cultureinfo]::InvariantCulture)
    $updatedMachineExtensionNames = '[' + ($sortedExtensions -join '][') + ']'

    # Update the GPO
    Set-ADObject -Identity $gpoContainer -Replace @{ gPCMachineExtensionNames = $updatedMachineExtensionNames } -Server $domain.PDCEmulator -ErrorAction Stop -Verbose
}

#endregion Startup Script

#region Administrative Templates

# Resolve the paths to the ADMX files
[string] $policiesDirectory = Split-Path -Path $gpoContainer.gPCFileSysPath -Parent -ErrorAction Stop
[string] $admxSourceDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'PolicyDefinitions' -ErrorAction Stop

# Check if the ADMX Central Store exists
if(Test-Path -Path $admxTargetDirectory -PathType Container) {
    # Copy the ADMX and ADML files to the Central Store
    Copy-Item -Path $admxSourceDirectory -Destination $policiesDirectory -Container -Recurse -Force -Verbose -ErrorAction Stop | Out-Null
}
else {
    Write-Warning -Message 'The ADMX Central Store does not exist. ADMX files have not been copied.'
}
#endregion Administrative Templates
