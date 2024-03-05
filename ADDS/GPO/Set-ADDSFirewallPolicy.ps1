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
Param(
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
class ScriptSettings
{
    [string]           $GroupPolicyObjectName         = 'Domain Controller Firewall'
    [string]           $GroupPolicyObjectComment      = 'This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.'
    [bool]             $EnforceOutboundRules          = $false
    [bool]             $LogDroppedPackets             = $false
    [string]           $LogFilePath                   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'
    [uint16]           $LogMaxSizeKilobytes           = [int16]::MaxValue
    [string[]]         $ClientAddresses               = 'Any'
    [string[]]         $ManagementAddresses           = 'Any'
    [string[]]         $DomainControllerAddresses     = 'Any'
    [Nullable[uint16]] $NtdsStaticPort                = $null
    [Nullable[uint16]] $NetlogonStaticPort            = $null
    [Nullable[uint16]] $DfsrStaticPort                = $null
    [Nullable[bool]]   $WmiStaticPort                 = $null
    [bool]             $DisableLLMNR                  = $false
    [Nullable[bool]]   $DisableMDNS                   = $null
    [bool]             $EnableServiceManagement       = $true
    [bool]             $EnableEventLogManagement      = $true
    [bool]             $EnableScheduledTaskManagement = $true
    [bool]             $EnableWindowsRemoteManagement = $true
    [bool]             $EnablePerformanceLogAccess    = $true
    [bool]             $EnableRemoteDesktop           = $true
    [bool]             $EnableDiskManagement          = $true
    [bool]             $EnableBackupManagement        = $true
    [bool]             $EnableLegacyFileReplication   = $true
    [bool]             $EnableNetbiosNameService      = $true
    [bool]             $EnableNetbiosDatagramService  = $true
    [bool]             $EnableNetbiosSessionService   = $true
    [bool]             $EnableWINS                    = $true
}

[ScriptSettings] $configuration = [ScriptSettings]::new()

# Load the configuration from the JSON file
[string] $configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFileName -ErrorAction Stop

[System.Runtime.Serialization.Json.DataContractJsonSerializer] $serializer = [System.Runtime.Serialization.Json.DataContractJsonSerializer]::new([ScriptSettings])
[System.IO.FileStream] $stream = [System.IO.File]::Open($configurationFilePath, [System.IO.FileMode]::Open)
try
{
    $configuration = $serializer.ReadObject($stream)
}
catch
{
    # Do not continue if there is any issue reading the configuration file
    throw
}
finally
{
    $stream.Close()
}

#endregion Configuration
#region Create and configure the GPO

# Try to fetch the target GPO
[Microsoft.GroupPolicy.Gpo] $gpo = Get-GPO -Name $configuration.GroupPolicyObjectName -ErrorAction SilentlyContinue

if($null -eq $gpo)
{
    # Create the GPO if it does not exist
    $gpo = New-GPO -Name $configuration.GroupPolicyObjectName -Comment $configuration.GroupPolicyObjectComment -Verbose -ErrorAction Stop
}

if($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled)
{
    # Fix the GPO status
    # TODO: Verbose
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if($gpo.Description -ne $configuration.GroupPolicyObjectComment)
{
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
$cimOperationOptions = [Microsoft.Management.Infrastructure.Options.CimOperationOptions]::new()
$cimOperationOptions.SetCustomOption('GPOSession', $gpoSession, $false)

# Open a temporary local CIM session
[CimSession] $localSession = New-CimSession -ErrorAction Stop

try
{
    # Fetch all firewall rules from the GPO
    [ciminstance[]] $gpoFirewallRules = $localSession.EnumerateInstances('ROOT\StandardCimv2','MSFT_NetFirewallRule', $cimOperationOptions)

    # Remove all firewall rules from the GPO
    foreach($rule in $gpoFirewallRules)
    {
        Write-Verbose -Message ('Deleting firewall rule {0}.' -f $rule.Name) -Verbose
        $localSession.DeleteInstance('ROOT\StandardCimv2', $rule, $cimOperationOptions)
    }
}
finally
{
    # Close the temporary local CIM session
    Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue
}

# Determine the default outbound action
[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action] $defaultOutboundAction = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Allow

if($configuration.EnforceOutboundRules)
{
    $defaultOutboundAction = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Block
}

# Determine the dropped packet logging settings
[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean] $logBlocled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False

if($configuration.LogDroppedPackets)
{
    $logBlocled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True
}

# Sanitize the maximum log file size
if($configuration.LogMaxSizeKilobytes -gt [int16]::MaxValue -or $configuration.LogMaxSizeKilobytes -le 0)
{
    # Windows only accepts 1KB-32MB as the maximum log file size.
    $configuration.LogMaxSizeKilobytes = [int16]::MaxValue # = 32MB
}

# TODO: -AllowUserPorts -AllowUserApps

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

if($allAddresses -contains 'Any')
{
    # Consolidate the remote addresses
    $allAddresses = @('Any')
}

[string[]] $dcAndManagementAddresses =
    ($configuration.DomainControllerAddresses + $configuration.ManagementAddresses) |
    Sort-Object -Unique

if($dcAndManagementAddresses -contains 'Any')
{
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
function ConvertTo-NetSecurityEnabled
{
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
                    -LocalPort Any `
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
                    -LocalPort Any `
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
                    -LocalPort Any `
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
                    -LocalPort Any `
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
                    -LocalPort Any `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\services.exe' `
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
                    -LocalPort Any `
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
                    -LocalPort Any `
                    -RemoteAddress $configuration.ManagementAddresses `
                    -Program '%SystemRoot%\system32\vdsldr.exe' `
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

# Create Outbound rule "Windows Server Update Services Client - Device Setup Manager (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-Client-DsmSvc-TCP-Out' `
                    -DisplayName 'Windows Server Update Services Client - Device Setup Manager (TCP-Out)' `
                    -Description 'Outbound rule for the detection, download and installation of device-related software from WSUS.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 8530,8531 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'DsmSvc' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Outbound rule "Windows Server Update Services Client - Windows Update (TCP-Out)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-Client-Wuauserv-TCP-Out' `
                    -DisplayName 'Windows Server Update Services Client - Windows Update (TCP-Out)' `
                    -Description 'Outbound rule for the detection, download, and installation of updates for Windows and other programs from WSUS.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort 8530,8531 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'wuauserv' `
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

#endregion Outbound Firewall Rules

# TODO: Verbose
Save-NetGPO -GPOSession $gpoSession -ErrorAction Stop

#region Registry Settings

# Turn off Link-Local Multicast Name Resolution (LLMNR)
if($configuration.DisableLLMNR) {
    Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -Value 0 -Type DWord -Verbose | Out-Null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -ErrorAction SilentlyContinue -Verbose | Out-Null
}

# Delete any previous GP Preferences registry values, so that we do not create duplicates.
Remove-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'EnableMDNS' -Verbose -ErrorAction SilentlyContinue | Out-Null
Remove-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'TCP/IP Port' -Verbose -ErrorAction SilentlyContinue | Out-Null
Remove-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'DCTcpipPort' -Verbose -ErrorAction SilentlyContinue | Out-Null

# Turn off Multicast DNS (mDNS)
if($configuration.DisableMDNS -eq $true) {
    Set-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Action Update -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'EnableMDNS' -Value 0 -Type DWord -Verbose | Out-Null
} elseif($configuration.DisableMDNS -eq $false) {
    Set-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Action Delete -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ValueName 'EnableMDNS' -Value 0 -Type DWord -Verbose | Out-Null
}

# Configure the DRS-R protocol to use a specific port
if($configuration.NtdsStaticPort -ge 1) {
    Set-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Action Update -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'TCP/IP Port' -Value ([int] $configuration.NtdsStaticPort) -Type DWord -Verbose | Out-Null
} elseif($configuration.NtdsStaticPort -eq 0) {
    Set-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Action Delete -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'TCP/IP Port' -Value 0 -Type DWord -Verbose | Out-Null
}

# Configure the NETLOGON protocol to use a specific port
if($configuration.NetlogonStaticPort -ge 1) {
    Set-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Action Update -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'DCTcpipPort' -Value ([int] $configuration.NetlogonStaticPort) -Type DWord -Verbose | Out-Null
} elseif($configuration.NetlogonStaticPort -eq 0) {
    Set-GPPrefRegistryValue -Guid $gpo.Id -Context Computer -Action Delete -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'DCTcpipPort' -Value 0 -Type DWord -Verbose | Out-Null
}
#endregion Registry Settings

#region Startup Script

# Fetch the GPO info from the PDC emulator
[Microsoft.ActiveDirectory.Management.ADObject] $gpoContainer = Get-ADObject -Identity $gpo.Path -Properties 'gPCFileSysPath','gPCMachineExtensionNames' -Server $domain.PDCEmulator -ErrorAction Stop

[string] $scriptPath = '{0}\Machine\Scripts\Startup\FirewallConfiguration.bat' -f $gpoContainer.gPCFileSysPath
[string] $scriptsIniPath = '{0}\Machine\Scripts\scripts.ini' -f $gpoContainer.gPCFileSysPath
[System.Text.StringBuilder] $startupScript = [System.Text.StringBuilder]::new()

# Startup script header
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
    Set-ADObject -Identity $gpoContainer -Replace @{ gPCMachineExtensionNames = $updatedMachineExtensionNames } -Server $domain.PDCEmulator -ErrorAction Stop -Verbose
}

#endregion Startup Script

# TODO: Disable Print Spooler
