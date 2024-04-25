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

    # Indicates whether the NetBIOS protocol should be switched to P-node (point-to-point) mode.
    [Nullable[bool]]   $DisableNetbiosBroadcasts      = $null

    # Indicates whether the Link-Local Multicast Name Resolution (LLMNR) client should be disabled.
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

    # Indicates whether inbound Remote Desktop Protocol traffic should be enabled.
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

    # Indicates whether inbound NetBIOS Name Service should be allowed.
    [bool]             $EnableNetbiosNameService      = $true

    # Indicates whether inbound NetBIOS Datagram Service traffic should be allowed.
    [bool]             $EnableNetbiosDatagramService  = $true

    # Indicates whether inbound NetBIOS Session Service (NBSS) traffic should be allowed.
    [bool]             $EnableNetbiosSessionService   = $true

    # Indicates whether inbound Windows Internet Name Service (WINS) traffic should be allowed.
    [bool]             $EnableWINS                    = $true

    # Indicates whether the Network protection feature of Microsoft Defender Antivirus should be enabled.
    [Nullable[bool]]   $EnableNetworkProtection       = $null

    # Indicates whether to block process creations originating from PSExec and WMI commands using Defender ASR.
    [Nullable[bool]]   $BlockWmiCommandExecution      = $null

    # Indicates whether additional filtering of RPC over Named Pipes should be applied.
    [Nullable[bool]]   $EnableRpcFilters              = $null
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
    Write-Verbose -Message ('Disabling user settings for GPO {0}.' -f $gpo.DisplayName) -Verbose
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if($gpo.Description -ne $configuration.GroupPolicyObjectComment) {
    # Fix the GPO description
    Write-Verbose -Message ('Updating the description for GPO {0}.' -f $gpo.DisplayName) -Verbose
    $gpo.Description = $configuration.GroupPolicyObjectComment
}

#endregion Create and configure the GPO

#region Firewall Profiles

# Contruct the qualified GPO name
[string] $policyStore = '{0}\{1}' -f $gpo.DomainName,$gpo.DisplayName

# Open the GPO
# Note: The Open-NetGPO cmdlet by default contacts a random DC instead of PDC-E
Write-Verbose -Message ('Opening GPO {0}.' -f $gpo.DisplayName) -Verbose
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
                       -DefaultOutboundAction Allow `
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
# As the NTP service might be used by non-Windows clients, we do not limit the remote addresses.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'W32Time-NTP-UDP-In' `
                    -DisplayName 'Active Directory Domain Controller - W32Time (NTP-UDP-In)' `
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Kerberos Key Distribution Center' `
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
                    -Group 'Kerberos Key Distribution Center' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
# As the DNS service might be used by non-Windows clients, we do not limit the remote addresses.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-DNS-UDP-In' `
                    -DisplayName 'DNS (UDP, Incoming)' `
                    -Group 'DNS Service' `
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
# As the DNS service might be used by non-Windows clients, we do not limit the remote addresses.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-DNS-TCP-In' `
                    -DisplayName 'DNS (TCP, Incoming)' `
                    -Group 'DNS Service' `
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
                    -Group 'File Replication' `
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
                    -Group 'Kerberos Key Distribution Center' `
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
                    -Group 'Kerberos Key Distribution Center' `
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
                    -Group 'Active Directory Domain Services' `
                    -Description 'Inbound rule for the Active Directory Domain Controller service to be remotely managed over Named Pipes. [UDP 445]' `
                    -Enabled True `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'DFS Replication' `
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

# Create Inbound rule "Active Directory Domain Controller - Echo Request (ICMPv4-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP4-In' `
                    -DisplayName 'Active Directory Domain Controller - Echo Request (ICMPv4-In)' `
                    -Group 'Active Directory Domain Services' `
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

# Create Inbound rule "Active Directory Domain Controller - Echo Request (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ADDS-ICMP6-In' `
                    -DisplayName 'Active Directory Domain Controller - Echo Request (ICMPv6-In)' `
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'Active Directory Domain Services' `
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
                    -Group 'File and Printer Sharing' `
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
                    -Group 'File and Printer Sharing' `
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
                    -Group 'Windows Internet Naming Service (WINS)' `
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
                    -Group 'Windows Internet Naming Service (WINS)' `
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
                    -Group 'Windows Internet Naming Service (WINS) - Remote Management' `
                    -Description 'Inbound rule for the Windows Internet Naming Service to allow remote management via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWINS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Core Networking - Destination Unreachable (ICMPv6-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'CoreNet-ICMP6-DU-In' `
                    -DisplayName 'Core Networking - Destination Unreachable (ICMPv6-In)' `
                    -Group 'Core Networking' `
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
                    -Group 'Core Networking' `
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
                    -Group 'Core Networking' `
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
                    -Group 'Core Networking' `
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
                    -Group 'Core Networking' `
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
                    -Group 'Core Networking' `
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
                    -Group 'Core Networking' `
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
                    -Group 'Active Directory Web Services' `
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
                    -Group 'Windows Remote Management' `
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
                    -Group 'Windows Remote Management' `
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
                    -Group 'Windows Management Instrumentation (WMI)' `
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
                    -Group 'Remote Desktop' `
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
                    -Group 'Remote Desktop' `
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
                    -Group 'DFS Management' `
                    -Description 'Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%systemroot%\system32\dfsfrsHost.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "RPC (TCP, Incoming)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'DNSSrv-RPC-TCP-In' `
                    -DisplayName 'RPC (TCP, Incoming)' `
                    -Group 'DNS Service' `
                    -Description 'Inbound rule to allow remote RPC/TCP access to the DNS service.' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Backup (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WindowsServerBackup-wbengine-In-TCP-NoScope' `
                    -DisplayName 'Windows Backup (RPC)' `
                    -Group 'Windows Backup' `
                    -Description 'Inbound rule for the Windows Backup Service to be remotely managed via RPC/TCP' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableBackupManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%systemroot%\system32\wbengine.exe' `
                    -Service 'wbengine' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Performance Logs and Alerts (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'PerfLogsAlerts-PLASrv-In-TCP-NoScope' `
                    -DisplayName 'Performance Logs and Alerts (TCP-In)' `
                    -Group 'Performance Logs and Alerts' `
                    -Description 'Inbound rule for Performance Logs and Alerts traffic. [TCP-In]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnablePerformanceLogAccess) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort Any `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%systemroot%\system32\plasrv.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Event Log Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteEventLogSvc-In-TCP' `
                    -DisplayName 'Remote Event Log Management (RPC)' `
                    -Group 'Remote Event Log Management' `
                    -Description 'Inbound rule for the local Event Log service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableEventLogManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'Eventlog' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Scheduled Tasks Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteTask-In-TCP' `
                    -DisplayName 'Remote Scheduled Tasks Management (RPC)' `
                    -Group 'Remote Scheduled Tasks Management' `
                    -Description 'Inbound rule for the Task Scheduler service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableScheduledTaskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'schedule' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Service Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteSvcAdmin-In-TCP' `
                    -DisplayName 'Remote Service Management (RPC)' `
                    -Group 'Remote Service Management' `
                    -Description 'Inbound rule for the local Service Control Manager to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableServiceManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%SystemRoot%\system32\services.exe' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "COM+ Remote Administration (DCOM-In)"
# This rule is required for remote connections using the Computer Management console.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'ComPlusRemoteAdministration-DCOM-In' `
                    -DisplayName 'COM+ Remote Administration (DCOM-In)' `
                    -Group 'COM+ Remote Administration' `
                    -Description 'Inbound rule to allow DCOM traffic to the COM+ System Application for remote administration.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableComPlusManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%systemroot%\system32\dllhost.exe' `
                    -Service 'COMSysApp' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Windows Defender Firewall Remote Management (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteFwAdmin-In-TCP' `
                    -DisplayName 'Windows Defender Firewall Remote Management (RPC)' `
                    -Group 'Windows Defender Firewall Remote Management' `
                    -Description 'Inbound rule for the Windows Defender Firewall to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFirewallManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'policyagent' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Volume Management - Virtual Disk Service (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RVM-VDS-In-TCP' `
                    -DisplayName 'Remote Volume Management - Virtual Disk Service (RPC)' `
                    -Group 'Remote Volume Management' `
                    -Description 'Inbound rule for the Remote Volume Management - Virtual Disk Service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDiskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
                    -Program '%SystemRoot%\system32\vds.exe' `
                    -Service 'vds' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

# Create Inbound rule "Remote Volume Management - Virtual Disk Service Loader (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RVM-VDSLDR-In-TCP' `
                    -DisplayName 'Remote Volume Management - Virtual Disk Service Loader (RPC)' `
                    -Group 'Remote Volume Management' `
                    -Description 'Inbound rule for the Remote Volume Management - Virtual Disk Service Loader to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDiskManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $dcAndManagementAddresses `
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

Write-Verbose -Message 'Saving the GPO changes...' -Verbose
Save-NetGPO -GPOSession $gpoSession -ErrorAction Stop

#endregion Inbound Firewall Rules

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
- OneSettings
- Allow Diagnostic Data to Disabled.
  Administrative Template > Windows Components > Data Collection and Preview Builds
#>

# Prevent users and apps from accessing dangerous websites
# (Enables Microsoft Defender Exploit Guard Network Protection)
# This might block some Internet C2 traffic.
if($null -ne $configuration.EnableNetworkProtection) {
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
} else {
    # Remove the Network Protection setting
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'EnableNetworkProtection' `
                           -ErrorAction SilentlyContinue `
                           -Verbose | Out-Null
}

# Block process creations originating from PSExec and WMI commands
# Block persistence through WMI event subscription
# Uses Microsoft Defender Exploit Guard Attack Surface Reduction
if($null -ne $configuration.BlockWmiCommandExecution) {
    # Audit (Evaluate how the attack surface reduction rule would impact your organization if enabled)
    [int] $blockPsExecAndWmi = 2

    if($configuration.BlockWmiCommandExecution -eq $true) {
        # Block (Enable the attack surface reduction rule)
        $blockPsExecAndWmi = 1
    }

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' `
                        -ValueName 'ExploitGuard_ASR_Rules' `
                        -Value 1 `
                        -Type DWord `
                        -Verbose | Out-Null

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Verbose | Out-Null
    
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Verbose | Out-Null
} else {
    # Remove the ASR settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' `
                           -ValueName 'ExploitGuard_ASR_Rules' `
                           -ErrorAction SilentlyContinue `
                           -Verbose | Out-Null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                           -ErrorAction SilentlyContinue `
                           -Verbose | Out-Null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                           -ErrorAction SilentlyContinue `
                           -Verbose | Out-Null
}

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
[string] $startupScriptPath = Join-Path -Path $startupScriptDirectory -ChildPath 'FirewallConfiguration.bat' -ErrorAction Stop
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
$startupScript.AppendFormat('netsh.exe advfirewall set allprofiles logging filename "{0}"', $configuration.LogFilePath) | Out-Null
$startupScript.AppendLine() | Out-Null

# Register RPC filters
[string] $rpcFilterScriptName = 'RpcNamedPipesFilters.txt'
[string] $rpcFilterScriptSourcePath = Join-Path -Path $PSScriptRoot -ChildPath $rpcFilterScriptName -ErrorAction Stop
[string] $rpcFilterScriptTargetPath = Join-Path -Path $startupScriptDirectory -ChildPath $rpcFilterScriptName -ErrorAction Stop

if($configuration.EnableRpcFilters -eq $true) {
    $startupScript.AppendLine() | Out-Null
    $startupScript.AppendLine('echo Register the RPC filters.') | Out-Null
    $startupScript.AppendFormat('netsh.exe -f "{0}"', $rpcFilterScriptTargetPath) | Out-Null
    $startupScript.AppendLine() | Out-Null
} elseif($null -ne $configuration.EnableRpcFilters) {
    $startupScript.AppendLine() | Out-Null
    $startupScript.AppendLine('echo Remove all RPC filters.') | Out-Null
    $startupScript.AppendLine('netsh.exe rpc filter delete filter filterkey=all') | Out-Null
}

# Overwrite the script files
Set-Content -Path $startupScriptPath -Value $startupScript.ToString() -Encoding Ascii -Force -ErrorAction Stop -Verbose
Copy-Item -Path $rpcFilterScriptSourcePath -Destination $rpcFilterScriptTargetPath -Verbose -Force -Confirm:$false -ErrorAction Stop

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
[string] $admxTargetDirectory = Join-Path -Path $policiesDirectory -ChildPath 'PolicyDefinitions' -ErrorAction Stop
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
