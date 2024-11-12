<#
.SYNOPSIS
Creates or modifies a Group Policy Object (GPO) that configures the Windows Firewall for Domain Controllers (DCs).

.DESCRIPTION

.PARAMETER ConfigurationFileName
Specifies the name of the configuration file from which some firewall settings are applied.

.EXAMPLE
PS> .\Set-ADDSFirewallPolicy.ps1 -Verbose

.EXAMPLE
PS> .\Set-ADDSFirewallPolicy.ps1 -ConfigurationFileName Set-ADDSFirewallPolicy.Contoso.json -Verbose

.LINK
Online documentation: https://github.com/MichaelGrafnetter/active-directory-firewall

.NOTES
Author:  Michael Grafnetter
Version: 2.7

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

# Stop script execution if any error occurs, to be on the safe side.
# Overrides the -ErrorAction parameter of all cmdlets.
$script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Not all cmdlets inherit the -Verbose parameter, so we need to explicitly override it.
[bool] $isVerbose = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue

# Preload the required modules
# Ignore any warnings, including 'Unable to find a default server with Active Directory Web Services running.'
# Suppress the verbosity for module loading
Import-Module -Name NetSecurity,GroupPolicy,ActiveDirectory -WarningAction SilentlyContinue -Verbose:$false

#region Configuration

# Set the default configuration values, which can be overridden by an external JSON file
class ScriptSettings {
    # The name of the Group Policy Object (GPO) that will be created or updated.
    [string]           $GroupPolicyObjectName         = 'Domain Controller Firewall'

    # The comment that will be added to the Group Policy Object (GPO).
    [string]           $GroupPolicyObjectComment      = 'This GPO is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.'

    # The domain in which the Group Policy Object (GPO) will be created or updated.
    [string]           $TargetDomain                  = $null

    # Indicates whether the packets dropped by the firewall should be logged.
    [bool]             $LogDroppedPackets             = $false
    
    # Indicates whether the packets allowed by the firewall should be logged.
    [bool]             $LogAllowedPackets             = $false

    # The path to the log file that will be used to store information about the allowed and/or dropped packets.
    [string]           $LogFilePath                   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'

    # The maximum size of the firewall log file in kilobytes.
    [uint16]           $LogMaxSizeKilobytes           = [int16]::MaxValue

    # List of client IP adresses from which inbound traffic should be allowed.
    [string[]]         $ClientAddresses               = @('Any')

    # List of IP addresses from which inbound management traffic should be allowed.
    [string[]]         $ManagementAddresses           = @('Any')

    # List of domain controller IP addresses, between which replication and optionally management traffic should be allowed.
    [string[]]         $DomainControllerAddresses     = @('Any')

    # List of RADIUS client IP adresses from which inbound traffic should be allowed.
    [string[]]         $RadiusClientAddresses         = @('Any')

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

    # Indicates whether management traffic from other domain controllers should be blocked.
    [bool]             $BlockManagementFromDomainControllers = $false

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

    # Indicates whether inbound Dynamic Host Configuration Protocol (DHCP) server traffic should be allowed.
    [bool]             $EnableDhcpServer              = $true

    # Indicates whether inbound Network Policy Server (NPS) / RADIUS traffic should be allowed.
    [bool]             $EnableNPS                     = $true

    # Indicates whether inbound Key Management Service (KMS) traffic should be allowed.
    [bool]             $EnableKMS                     = $true

    # Indicates whether inbound Windows Server Update Services (WSUS) traffic should be allowed.
    [bool]             $EnableWSUS                    = $true
    
    # Indicates whether inbound Windows Deployment Services (WDS) traffic should be allowed.
    [bool]             $EnableWDS                     = $true
    
    # Indicates whether inbound http.sys-based web server traffic on default HTTP and HTTPS ports should be allowed.
    [bool]             $EnableWebServer               = $true
    
    # Indicates whether inbound File Server Resource Manager (FSRM) management traffic should be allowed.
    [bool]             $EnableFSRMManagement          = $true

    # Indicates whether inbound Print Spooler traffic through RPC over TCP should be allowed.
    [bool]             $EnablePrintSpooler            = $true

    # Indicates whether the Network protection feature of Microsoft Defender Antivirus should be enabled.
    [Nullable[bool]]   $EnableNetworkProtection       = $null

    # Indicates whether to block process creations originating from PSExec and WMI commands using Defender ASR.
    [Nullable[bool]]   $BlockWmiCommandExecution      = $null

    # Indicates whether additional filtering of RPC over Named Pipes should be applied.
    [Nullable[bool]]   $EnableRpcFilters              = $null

    # Indicates whether local IPSec rules should be enabled.
    [bool]             $EnableLocalIPsecRules         = $true

    # Specifies the name(s) of additional script file(s) containing firewall rules that will be imported into the Group Policy Object (GPO).
    [string[]]         $CustomRuleFileNames           = $null
}

[ScriptSettings] $configuration = [ScriptSettings]::new()

# Load the configuration from the JSON file
[string] $configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFileName

[bool] $configurationFileExists = Test-Path -Path $configurationFilePath -PathType Leaf

if(-not $configurationFileExists) {
    # Abort script execution if the configuration file does not exist.
    [string] $message = 'The configuration file {0} was not found. Check the Set-ADDSFirewallPolicy.Starter.json and Set-ADDSFirewallPolicy.Sample.json files to see how the configuration file should look like.' -f $ConfigurationFileName
    throw [System.IO.FileNotFoundException]::new($message, $ConfigurationFileName)
}

Write-Verbose -Message "Reading the $ConfigurationFileName configuration file."
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

#region Configuration Validation

if($configuration.ManagementAddresses -contains 'Any' -or $configuration.DomainControllerAddresses -contains 'Any' -and -not $configuration.BlockManagementFromDomainControllers) {
    Write-Warning -Message 'The current configuration allows management traffic from any IP address.'
}

if($configuration.EnableWINS -or $configuration.EnableDhcpServer -or $configuration.EnableNPS -or $configuration.EnableKMS -or $configuration.EnableWSUS -or $configuration.EnableWDS -or $configuration.EnableWebServer -or $configuration.EnableFSRMManagement) {
    Write-Warning -Message 'It is not recommended to host additional Windows Server roles on Domain Controllers.'
}

if($configuration.EnablePrintSpooler) {
    Write-Warning -Message 'The Print Spooler service should be disabled on Domain Controllers.'

    if($configuration.EnableRpcFilters) {
        Write-Warning -Message 'Older Windows clients use the SMB protocol to communicate with the Print Spooler service. RPC filters will block this traffic.'
    }
}

if($configuration.EnableLegacyFileReplication) {
    Write-Warning -Message 'The File Replication Service (FRS) is deprecated. Migration to Distributed File System Replication (DFSR) is highly recommended.'
}

if($configuration.EnableNetbiosNameService -or $configuration.EnableNetbiosDatagramService -or $configuration.EnableNetbiosSessionService -or -not $configuration.DisableNetbiosBroadcasts) {
    Write-Warning -Message 'NetBIOS is a legacy protocol and should be disabled in modern networks.'
}

if(-not($configuration.DisableLLMNR -and $configuration.DisableMDNS)) {
    Write-Warning -Message 'Only the DNS protocol should be used for name resolution in modern networks. Protocols using distributed name resolution, including LLMNR and mDNS, should be disabled on DCs.'
}

if(-not($configuration.LogMaxSizeKilobytes -ge 16384 -and $configuration.LogDroppedPackets -and $configuration.LogAllowedPackets)) {
    Write-Warning -Message 'The firewall log settings do not meet the standardized security baselines.'
}

if($configuration.BlockWmiCommandExecution -eq $true) {
    Write-Warning -Message 'SCCM client and DP do not work properly on systems where command execution over WMI is blocked.'
}

#endregion Configuration Validation

#region Create and Configure the GPO

[Microsoft.ActiveDirectory.Management.ADDomain] $domain = $null

if([string]::IsNullOrWhiteSpace($configuration.TargetDomain)) {
    # Use the current domain if no target domain is specified.
    # Detection of the current domain based on the local computer works well with RDP/WinRM connections
    # to multiple domains made by Enterprise Admins.
    $domain = Get-ADDomain -Current LocalComputer
}
else {
    # Use the specified target domain
    $domain = Get-ADDomain -Identity $configuration.TargetDomain
}

# To avoid potential replication conflicts, GPOs should only be edited on the PDC Emulator.
[string] $targetDomainController = $domain.PDCEmulator

# Try to fetch the target GPO
[Microsoft.GroupPolicy.Gpo] $gpo = Get-GPO -Name $configuration.GroupPolicyObjectName `
                                           -Domain $domain.DNSRoot `
                                           -Server $targetDomainController `
                                           -ErrorAction SilentlyContinue

if($null -eq $gpo) {
    # Create the GPO if it does not exist
    $gpo = New-GPO -Name $configuration.GroupPolicyObjectName `
                   -Comment $configuration.GroupPolicyObjectComment `
                   -Domain $domain.DNSRoot `
                   -Server $targetDomainController `
                   -Verbose:$isVerbose
}

if($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled) {
    # Fix the GPO status
    Write-Verbose -Message ('Disabling user settings for GPO {0}.' -f $gpo.DisplayName)
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if($gpo.Description -ne $configuration.GroupPolicyObjectComment) {
    # Fix the GPO description
    Write-Verbose -Message ('Updating the description for GPO {0}.' -f $gpo.DisplayName)
    $gpo.Description = $configuration.GroupPolicyObjectComment
}

#endregion Create and configure the GPO

#region Helper Functions

<#
.SYNOPSIS
Converts a boolean value to a NetSecurity.GpoBoolean enumeration value, which is accepted by the Set-NetFirewallProfile cmdlet.

.PARAMETER Value
The boolean value to convert.

#>
function ConvertTo-GpoBoolean {
    [OutputType([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [bool] $Value
    )

    if($Value) {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True
    }
    else {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False
    }
}

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

#region Firewall Profiles

# Contruct the qualified GPO name
[string] $policyStore = '{0}\{1}' -f $gpo.DomainName,$gpo.DisplayName

# Open the GPO
# Note: The Open-NetGPO cmdlet by default contacts a random DC instead of PDC-E
Write-Verbose -Message ('Opening GPO {0}.' -f $gpo.DisplayName)

[string] $gpoSession = Open-NetGPO -PolicyStore $policyStore -DomainController $targetDomainController

# Remove any pre-existing firewall rules
# Note: As Microsoft removed the -GPOSession parameter from the Remove-NetFirewallRule in Windows Server 2022, low-level CIM operations need to be used instead.

# The source GPO session is provided as a custom CIM operation option.
[Microsoft.Management.Infrastructure.Options.CimOperationOptions] $cimOperationOptions =
    [Microsoft.Management.Infrastructure.Options.CimOperationOptions]::new()
$cimOperationOptions.SetCustomOption('GPOSession', $gpoSession, $false)

# Open a temporary local CIM session
[CimSession] $localSession = New-CimSession -Verbose:$false

try {
    # Fetch all firewall rules from the GPO
    [ciminstance[]] $gpoFirewallRules = $localSession.EnumerateInstances('ROOT\StandardCimv2','MSFT_NetFirewallRule', $cimOperationOptions)

    # Remove all firewall rules from the GPO
    foreach($rule in $gpoFirewallRules) {
        Write-Verbose -Message ('Deleting firewall rule {0}.' -f $rule.Name)
        $localSession.DeleteInstance('ROOT\StandardCimv2', $rule, $cimOperationOptions)
    }
}
finally {
    # Close the temporary local CIM session
    Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue
}

# Sanitize the maximum log file size
if($configuration.LogMaxSizeKilobytes -gt [int16]::MaxValue -or $configuration.LogMaxSizeKilobytes -le 0) {
    # Windows only accepts 1KB-32MB as the maximum log file size.
    Write-Warning -Message 'The LogMaxSizeKilobytes value is out of the supported range. Setting it to the value of 32MB.'
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
                       -AllowLocalIPsecRules (ConvertTo-GpoBoolean -Value $configuration.EnableLocalIPsecRules) `
                       -AllowUnicastResponseToMulticast False `
                       -NotifyOnListen False `
                       -LogFileName $configuration.LogFilePath `
                       -LogMaxSizeKilobytes $configuration.LogMaxSizeKilobytes `
                       -LogBlocked (ConvertTo-GpoBoolean -Value $configuration.LogDroppedPackets) `
                       -LogAllowed (ConvertTo-GpoBoolean -Value $configuration.LogAllowedPackets) `
                       -LogIgnored False

[string[]] $allAddresses =
    @($configuration.ClientAddresses + $configuration.DomainControllerAddresses + $configuration.ManagementAddresses) |
    Sort-Object -Unique

if($allAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $allAddresses = @('Any')
}

[string[]] $remoteManagementAddresses = $configuration.ManagementAddresses

if(-not $configuration.BlockManagementFromDomainControllers) {
    # Add the domain controller addresses to the remote management addresses
    $remoteManagementAddresses = @($configuration.ManagementAddresses + $configuration.DomainControllerAddresses) |
        Sort-Object -Unique
}

if($remoteManagementAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $remoteManagementAddresses = @('Any')
}

[string[]] $radiusClientAndDomainControllerAddresses =
    @($configuration.RadiusClientAddresses + $configuration.DomainControllerAddresses) |
    Sort-Object -Unique

if($radiusClientAndDomainControllerAddresses -contains 'Any') {
    # Consolidate the remote addresses
    $radiusClientAndDomainControllerAddresses = @('Any')
}

#endregion Firewall Profiles

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\System32\wins.exe' `
                    -Service 'WINS' `
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null

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
                    -Verbose:$isVerbose > $null
                   
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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe' `
                    -Service 'adws' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'winmgmt' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'termservice' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote Desktop (TCP-In)"
# Note: This redundant rule is created for backward compatibility with Windows Server 2008 R2 and earlier.
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'RemoteDesktop-In-TCP' `
                    -DisplayName 'Remote Desktop (TCP-In)' `
                    -Group 'Remote Desktop' `
                    -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableRemoteDesktop) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 3389 `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\dfsfrsHost.exe' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\System32\dns.exe' `
                    -Service 'dns' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\wbengine.exe' `
                    -Service 'wbengine' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\plasrv.exe' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'Eventlog' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'schedule' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\services.exe' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\dllhost.exe' `
                    -Service 'COMSysApp' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\svchost.exe' `
                    -Service 'policyagent' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\vds.exe' `
                    -Service 'vds' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\vdsldr.exe' `
                    -Verbose:$isVerbose > $null

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
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%SystemRoot%\system32\OpenSSH\sshd.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v4 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-ClientSvc-DHCPv4-In' `
                    -DisplayName 'DHCP Server v4 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic to the IPv4 Dynamic Host Control Protocol Server. [UDP 67]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 67 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v4 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-SrvSvc-DHCPv4-In' `
                    -DisplayName 'DHCP Server v4 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic so that rogue detection works in V4. [UDP 68]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 68 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v6 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-SrvSvc-DHCPv6-In' `
                    -DisplayName 'DHCP Server v6 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic so that rogue detection works in V6. [UDP 546]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 546 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server v6 (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-ClientSvc-DHCPv6-In' `
                    -DisplayName 'DHCP Server v6 (UDP-In)' `
                    -Group 'DHCP Server' `
                    -Description 'An inbound rule to allow traffic to the IPv6 Dynamic Host Control Protocol Server. [UDP 547]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 547 `
                    -RemoteAddress Any `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server Failover (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-Failover-TCP-In' `
                    -DisplayName 'DHCP Server Failover (TCP-In)' `
                    -Group 'DHCP Server Management' `
                    -Description 'An inbound rule to allow DHCP failover messages to the IPv4 Dynamic Host Configuration Protocol Server. [TCP 647]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 647 `
                    -RemoteAddress $configuration.DomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "DHCP Server (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'Microsoft-Windows-DHCP-ClientSvc-RPC-TCP-In' `
                    -DisplayName 'DHCP Server (RPC-In)' `
                    -Group 'DHCP Server Management' `
                    -Description 'An inbound rule to allow traffic to allow RPC traffic for DHCP Server management.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableDhcpServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'dhcpserver' `
                    -Verbose:$isVerbose > $null
                    
# Create Inbound rule "Network Policy Server (Legacy RADIUS Authentication - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1645' `
                    -DisplayName 'Network Policy Server (Legacy RADIUS Authentication - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1645]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1645 `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (Legacy RADIUS Accounting - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1646' `
                    -DisplayName 'Network Policy Server (Legacy RADIUS Accounting - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1646]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1646 `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (RADIUS Authentication - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1812' `
                    -DisplayName 'Network Policy Server (RADIUS Authentication - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1812]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1812 `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (RADIUS Accounting - UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-UDP-1813' `
                    -DisplayName 'Network Policy Server (RADIUS Accounting - UDP-In)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1813]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort 1813 `
                    -RemoteAddress $radiusClientAndDomainControllerAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'ias' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Network Policy Server (RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'NPS-NPSSvc-In-RPC' `
                    -DisplayName 'Network Policy Server (RPC)' `
                    -Group 'Network Policy Server' `
                    -Description 'Inbound rule for the Network Policy Server to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableNPS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\iashost.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "World Wide Web Services (HTTP Traffic-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'IIS-WebServerRole-HTTP-In-TCP' `
                    -DisplayName 'World Wide Web Services (HTTP Traffic-In)' `
                    -Group 'World Wide Web Services (HTTP)' `
                    -Description 'An inbound rule to allow HTTP traffic for Internet Information Services (IIS) [TCP 80]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWebServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 80 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "World Wide Web Services (HTTPS Traffic-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'IIS-WebServerRole-HTTPS-In-TCP' `
                    -DisplayName 'World Wide Web Services (HTTPS Traffic-In)' `
                    -Group 'Secure World Wide Web Services (HTTPS)' `
                    -Description 'An inbound rule to allow HTTPS traffic for Internet Information Services (IIS) [TCP 443]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWebServer) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 443 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Deployment Services (UDP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WDS-WdsServer-In-UDP' `
                    -DisplayName 'Windows Deployment Services (UDP-In)' `
                    -Group 'Windows Deployment Services' `
                    -Description 'Inbound rule for Windows Deployment Services to allow UDP traffic.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWDS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol UDP `
                    -LocalPort Any `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'WdsServer' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Deployment Services (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WDS-RPC-In-TCP' `
                    -DisplayName 'Windows Deployment Services (RPC-In)' `
                    -Group 'Windows Deployment Services' `
                    -Description 'Inbound rule for Windows Deployment Services to allow RPC/TCP traffic.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWDS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $allAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'WdsServer' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Key Management Service (TCP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'SPPSVC-In-TCP' `
                    -DisplayName 'Key Management Service (TCP-In)' `
                    -Group 'Key Management Service' `
                    -Description 'Inbound rule for the Key Management Service to allow for machine counting and license compliance. [TCP 1688]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableKMS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 1688 `
                    -RemoteAddress Any `
                    -Program '%SystemRoot%\system32\sppextcomobj.exe' `
                    -Service 'sppsvc' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote File Server Resource Manager Management - FSRM Service (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FSRM-SrmSvc-In (RPC)' `
                    -DisplayName 'Remote File Server Resource Manager Management - FSRM Service (RPC-In)' `
                    -Group 'Remote File Server Resource Manager Management' `
                    -Description 'Inbound rule for the File Server Resource Manager service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFSRMManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\svchost.exe' `
                    -Service 'SrmSvc' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Remote File Server Resource Manager Management - FSRM Reports Service (RPC-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FSRM-SrmReports-In (RPC)' `
                    -DisplayName 'Remote File Server Resource Manager Management - FSRM Reports Service (RPC-In)' `
                    -Group 'Remote File Server Resource Manager Management' `
                    -Description 'Inbound rule for the File Server Storage Reports Manager service to be remotely managed via RPC/TCP.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableFSRMManagement) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $remoteManagementAddresses `
                    -Program '%systemroot%\system32\srmhost.exe' `
                    -Service 'SrmReports' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "File and Printer Sharing (Spooler Service - RPC)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'FPS-SpoolSvc-In-TCP' `
                    -DisplayName 'File and Printer Sharing (Spooler Service - RPC)' `
                    -Group 'File and Printer Sharing' `
                    -Description 'Inbound rule for File and Printer Sharing to allow the Print Spooler Service to communicate via TCP/RPC.' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnablePrintSpooler) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort RPC `
                    -RemoteAddress $allAddresses `
                    -Program '%SystemRoot%\system32\spoolsv.exe' `
                    -Service 'Spooler' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Server Update Services (HTTP-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-In-HTTP' `
                    -DisplayName 'Windows Server Update Services (HTTP-In)' `
                    -Group 'Windows Server Update Services (WSUS)' `
                    -Description 'Inbound rule for Windows Server Update Services to allow HTTP traffic. [TCP 8530]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWSUS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8530 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Windows Server Update Services (HTTPS-In)"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name 'WSUS-In-HTTPS' `
                    -DisplayName 'Windows Server Update Services (HTTPS-In)' `
                    -Group 'Windows Server Update Services (WSUS)' `
                    -Description 'Inbound rule for Windows Server Update Services to allow HTTPS traffic. [TCP 8531]' `
                    -Enabled (ConvertTo-NetSecurityEnabled $configuration.EnableWSUS) `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8531 `
                    -RemoteAddress Any `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Import custom firewall rules from script files
foreach($ruleFileName in $configuration.CustomRuleFileNames) {
    [string] $ruleFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ruleFileName

    [bool] $ruleFileExists = Test-Path -Path $ruleFilePath -PathType Leaf

    if($ruleFileExists) {
        Write-Verbose -Message "Importing custom firewall rules from '$ruleFilePath'..."
        # Execute the custom rule script file, while suppressing any output.
        & $ruleFilePath -GPOSession $gpoSession `
                        -DomainControllerAddresses $configuration.DomainControllerAddresses `
                        -RemoteManagementAddresses $remoteManagementAddresses `
                        -AllAddresses $allAddresses > $null
    } else {
        [System.Exception] $ex = [System.IO.FileNotFoundException]::new('Could not locate the custom rule file.', $ruleFilePath)
        Write-Error -Exception $ex `
                    -Category OpenError `
                    -ErrorId CustomRuleOpenError `
                    -TargetObject $ruleFilePath
    }
}

# Commit the firewall-related GPO changes
Write-Verbose -Message 'Saving the GPO changes...'
Save-NetGPO -GPOSession $gpoSession

#endregion Inbound Firewall Rules

#region Registry Settings

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
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
                            
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                        -ValueName 'AllowNetworkProtectionOnWinServer' `
                        -Value 1 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    # Remove the Network Protection settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'EnableNetworkProtection' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
    
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'AllowNetworkProtectionOnWinServer' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
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
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
    
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    # Remove the ASR settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' `
                           -ValueName 'ExploitGuard_ASR_Rules' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Disable MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'EnableICMPRedirect' `
                    -Value 0 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'DisableIPSourceRouting' `
                    -Value 2 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)	
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters' `
                    -ValueName 'DisableIPSourceRouting' `
                    -Value 2 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# Disable MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                    -ValueName 'PerformRouterDiscovery' `
                    -Value 0 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

# MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
# Note: This is not a managed GPO setting.
Set-GPRegistryValue -Guid $gpo.Id `
                    -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                    -ValueName 'NoNameReleaseOnDemand' `
                    -Value 1 `
                    -Type DWord `
                    -Domain $domain.DNSRoot `
                    -Server $targetDomainController `
                    -Verbose:$isVerbose > $null

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
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null

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
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    # Remove the NetBIOS-related settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                           -ValueName 'NodeType' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableNetbios' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Turn off Link-Local Multicast Name Resolution (LLMNR)
if($configuration.DisableLLMNR -eq $true) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                        -ValueName 'EnableMulticast' `
                        -Value 0 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableMulticast' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Turn off Multicast DNS (mDNS)
# Note: This is not a managed GPO setting.
if($null -ne $configuration.DisableMDNS) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                        -ValueName 'EnableMDNS' `
                        -Value ([int](-not $configuration.DisableMDNS)) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                           -ValueName 'EnableMDNS' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Configure the DRS-R protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.NtdsStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                        -ValueName 'TCP/IP Port' `
                        -Value ([int] $configuration.NtdsStaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                           -ValueName 'TCP/IP Port' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Configure the NETLOGON protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.NetlogonStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                        -ValueName 'DCTcpipPort' `
                        -Value ([int] $configuration.NetlogonStaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                           -ValueName 'DCTcpipPort' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

# Configure the FRS protocol to use a specific port
# Note: This is not a managed GPO setting.
if($null -ne $configuration.FrsStaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters' `
                        -ValueName 'RPC TCP/IP Port Assignment' `
                        -Value ([int] $configuration.FrsStaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$isVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters' `
                           -ValueName 'RPC TCP/IP Port Assignment' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$isVerbose > $null
}

#endregion Registry Settings

#region Startup Script

# Fetch the GPO info from the PDC emulator
[Microsoft.ActiveDirectory.Management.ADObject] $gpoContainer = Get-ADObject -Identity $gpo.Path -Properties 'gPCFileSysPath','gPCMachineExtensionNames' -Server $targetDomainController
[string] $startupScriptDirectory = Join-Path -Path $gpoContainer.gPCFileSysPath -ChildPath 'Machine\Scripts\Startup'
[string] $startupScriptPath = Join-Path -Path $startupScriptDirectory -ChildPath 'FirewallConfiguration.bat'
[string] $scriptsIniPath = Join-Path -Path $gpoContainer.gPCFileSysPath -ChildPath 'Machine\Scripts\scripts.ini'

# Create the directory for startup scripts if it does not exist
New-Item -Path $startupScriptDirectory -ItemType Directory -Force -Verbose:$isVerbose > $null

# Startup script header
[System.Text.StringBuilder] $startupScript = [System.Text.StringBuilder]::new()
$startupScript.AppendLine('@ECHO OFF') > $null
$startupScript.AppendLine('REM This script is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.') > $null

# Configure the WMI  protocol to use the deafult static port 24158
if($configuration.WmiStaticPort -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Move the WMI service to a standalone process listening on TCP port 24158 with authentication level set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY.') > $null
    $startupScript.AppendLine('winmgmt.exe /standalonehost 6') > $null
} elseif($configuration.WmiStaticPort -eq $false) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Move the WMI service into the shared Svchost process.') > $null
    $startupScript.AppendLine('winmgmt.exe /sharedhost') > $null
}

# Configure the DFS-R protocol to use a specific port
[string] $dfsrDiagInstallScript = @'
echo Install the dfsrdiag.exe tool if absent.
if not exist "%SystemRoot%\system32\dfsrdiag.exe" (
    dism.exe /Online /Enable-Feature /FeatureName:DfsMgmt
)
'@

if($configuration.DfsrStaticPort -ge 1) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine($dfsrDiagInstallScript) > $null
    $startupScript.AppendLine('echo Set static RPC port for DFS Replication.') > $null
    $startupScript.AppendFormat('dfsrdiag.exe StaticRPC /Port:{0}', $configuration.DfsrStaticPort) > $null
    $startupScript.AppendLine() > $null
} elseif($configuration.DfsrStaticPort -eq 0) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine($dfsrDiagInstallScript) > $null
    $startupScript.AppendLine('echo Set dynamic RPC port for DFS Replication.') > $null
    $startupScript.AppendLine('dfsrdiag.exe StaticRPC /Port:0') > $null
}

# Create the firewall log file
$startupScript.AppendLine() > $null
$startupScript.AppendLine('echo Create the firewall log file and configure its DACL.') > $null
$startupScript.AppendFormat('netsh.exe advfirewall set allprofiles logging filename "{0}"', $configuration.LogFilePath) > $null
$startupScript.AppendLine() > $null

# Register RPC filters
[string] $rpcFilterScriptName = 'RpcNamedPipesFilters.txt'
[string] $rpcFilterScriptSourcePath = Join-Path -Path $PSScriptRoot -ChildPath $rpcFilterScriptName
[string] $rpcFilterScriptTargetPath = Join-Path -Path $startupScriptDirectory -ChildPath $rpcFilterScriptName

if($configuration.EnableRpcFilters -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Register the RPC filters.') > $null
    $startupScript.AppendFormat('netsh.exe -f "%~dp0{0}"', $rpcFilterScriptName) > $null
    $startupScript.AppendLine() > $null
} elseif($null -ne $configuration.EnableRpcFilters) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Remove all RPC filters.') > $null
    $startupScript.AppendLine('netsh.exe rpc filter delete filter filterkey=all') > $null
}

# Fix the Network Policy Server (NPS) to work with Windows Firewall on Windows Server 2016 and Windows Server 2019.
# This is not required on Windows Server 2022.
if($configuration.EnableNPS -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Fix the NPS service to work with Windows Firewall on downlevel Windows Server versions.') > $null
    $startupScript.AppendLine('sc.exe sidtype IAS unrestricted') > $null
}

# Overwrite the script files
Set-Content -Path $startupScriptPath -Value $startupScript.ToString() -Encoding Ascii -Force -Verbose:$isVerbose
Copy-Item -Path $rpcFilterScriptSourcePath -Destination $rpcFilterScriptTargetPath -Force -Confirm:$false -Verbose:$isVerbose

# Register the startup script in the scripts.ini file
[string] $scriptsIni = @'
[Startup]
0CmdLine=FirewallConfiguration.bat
0Parameters=
'@

Set-Content -Path $scriptsIniPath -Value $scriptsIni -Encoding Ascii -Verbose:$isVerbose -Force

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
    Set-ADObject -Identity $gpoContainer -Replace @{ gPCMachineExtensionNames = $updatedMachineExtensionNames } -Server $targetDomainController  -Verbose:$isVerbose
}

#endregion Startup Script

#region Administrative Templates

# Resolve the paths to the ADMX files
[string] $policiesDirectory = Split-Path -Path $gpoContainer.gPCFileSysPath -Parent
[string] $admxTargetDirectory = Join-Path -Path $policiesDirectory -ChildPath 'PolicyDefinitions'
[string] $admxSourceDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'PolicyDefinitions'

# Check if the ADMX Central Store exists
if(Test-Path -Path $admxTargetDirectory -PathType Container) {
    # Copy the ADMX and ADML files to the Central Store
    Copy-Item -Path $admxSourceDirectory -Destination $policiesDirectory -Container -Recurse -Verbose:$isVerbose -Force > $null
}
else {
    Write-Warning -Message 'The ADMX Central Store does not exist. ADMX files have not been copied.'
}
#endregion Administrative Templates
