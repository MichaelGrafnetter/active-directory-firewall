<#
.SYNOPSIS
Creates or modifies a Group Policy Object (GPO) that configures the Windows Firewall.

.DESCRIPTION

.PARAMETER ConfigurationFileName
Specifies the name of the configuration file from which some firewall settings are applied.

.EXAMPLE
PS> .\Set-WindowsFirewallPolicy.ps1 -Verbose

.EXAMPLE
PS> .\Set-WindowsFirewallPolicy.ps1 -ConfigurationFileName FileServer.Contoso.json -Verbose

.LINK
Online documentation: https://firewall.dsinternals.com

.NOTES
Author:  Michael Grafnetter
Version: 1.0

#>

##############Requires -Modules NetSecurity,GroupPolicy,ActiveDirectory
#Requires -Version 5

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigurationFileName = 'FileServer.Sample.json' ################################'Set-WindowsFirewallPolicy.json'
)

# Apply additional runtime validation
Set-StrictMode -Version Latest -ErrorAction Stop

# Stop script execution if any error occurs, to be on the safe side.
# Overrides the -ErrorAction parameter of all cmdlets.
$script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Not all cmdlets inherit the -Verbose parameter, so we need to explicitly override it.
[bool] $script:IsVerbose = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue

# Preload the required modules
# Ignore any warnings, including 'Unable to find a default server with Active Directory Web Services running.'
# Suppress the verbosity for module loading
###########################################################Import-Module -Name NetSecurity,GroupPolicy,ActiveDirectory -WarningAction SilentlyContinue -Verbose:$false

#region Configuration Data Model

# Define constant values for predefined IP address sets
[string] $script:PredefinedAddressSet_AllAddresses        = 'AllAddresses'
[string] $script:PredefinedAddressSet_ManagementAddresses = 'ManagementAddresses'
[string] $script:AnyKeyWord                               = 'Any'

# Set the default configuration values, which can be overridden by an external JSON file
class CoreNetworkingSettings {
    # Indicates whether the default ICMPv4 and ICMPv6 rules should be enabled.
    [bool]             $EnableIcmp                    = $true

    # Indicates whether the default DHCP client rules should be enabled.
    [bool]             $EnableDhcpClient              = $true

    # Indicates whether ICMP redirects should be blocked, based on the Microsoft Security Guidance.
    [Nullable[bool]]   $BlockRedirects                = $true

   # Indicates whether inbound NetBIOS Name Service should be allowed.
    [bool]             $EnableNetbiosNameService      = $false

    # Indicates whether inbound NetBIOS Datagram Service traffic should be allowed.
    [bool]             $EnableNetbiosDatagramService  = $false

    # Indicates whether inbound NetBIOS Session Service (NBSS) traffic should be allowed.
    [bool]             $EnableNetbiosSessionService   = $false

    # Indicates whether the NetBIOS protocol should be switched to P-node (point-to-point) mode.
    [Nullable[bool]]   $DisableNetbiosBroadcasts      = $true

    # Indicates whether the Link-Local Multicast Name Resolution (LLMNR) client should be disabled.
    [bool]             $DisableLLMNR                  = $true

    # Indicates whether the Multicast DNS (mDNS) client should be disabled.
    [Nullable[bool]]   $DisableMDNS                   = $true

    # Indicates whether the Network protection feature of Microsoft Defender Antivirus should be enabled.
    [Nullable[bool]]   $EnableNetworkProtection       = $null

    <#
    .SYNOPSIS
    Validates the core networking-related firewall rules.
    #>
    [void] Validate() {
        if ($this.EnableNetbiosNameService -or $this.EnableNetbiosDatagramService -or $this.EnableNetbiosSessionService -or -not $this.DisableNetbiosBroadcasts) {
            Write-Warning -Message 'NetBIOS is a legacy protocol and should be disabled in modern networks.'
        }

        if (-not($this.DisableLLMNR -and $this.DisableMDNS)) {
            Write-Warning -Message 'Only the DNS protocol should be used for name resolution in modern networks. Protocols using distributed name resolution, including LLMNR and mDNS, should be disabled on DCs.'
        }
    }
}

class WmiSettings {
    # Indicates whether inbound Windows Management Instrumentation (WMI) traffic should be enabled.
    [bool]             $Enabled                       = $false

    # Indicates whether WMI traffic should use a static port.
    [Nullable[bool]]   $StaticPort                    = $null

    # Indicates whether to block process creations originating from PSExec and WMI commands using Defender ASR.
    [Nullable[bool]]   $BlockCommandExecution         = $null

    <#
    .SYNOPSIS
    Validates the WMI-related settings.
    #>
    [void] Validate() {
        if ($this.BlockCommandExecution) {
            Write-Warning -Message 'SCCM client and DP do not work properly on systems where command execution over WMI is blocked.'
        }
    }
}

class RemoteManagementSettings {
    # Default set of IP addresses from which inbound management traffic should be allowed.
    [string[]]         $ManagementAddressSet         = @($PredefinedAddressSet_ManagementAddresses)

    # Indicates whether inbound Windows Remote Management traffic should be enabled.
    [bool]             $EnableWindowsRemoteManagement = $true

    # Windows Management Instrumentation (WMI) settings.
    [WmiSettings]      $WMI                           = [WmiSettings]::new()

     # Indicates whether remote service management should be enabled.
    [bool]             $EnableServiceManagement       = $false

    # Indicates whether remote scheduled task management should be enabled.
    [bool]             $EnableScheduledTaskManagement = $false

    # Indicates whether remote event log management should be enabled.
    [bool]             $EnableEventLogManagement      = $false

    # Indicates whether remote performance log access should be enabled.
    [bool]             $EnablePerformanceLogAccess    = $false

    # Indicates whether inbound OpenSSH traffic should be enabled.
    [bool]             $EnableOpenSSHServer           = $false

    # Indicates whether inbound Remote Desktop Protocol traffic should be enabled.
    [bool]             $EnableRemoteDesktop           = $true

    # Indicates whether remote disk management should be enabled.
    [bool]             $EnableDiskManagement          = $false

    # Indicates whether remote firewall management should be enabled.
    [bool]             $EnableFirewallManagement      = $false

    # Indicates whether inbound COM+ management traffic should be enabled.
    [bool]             $EnableComPlusManagement       = $false

    <#
    .SYNOPSIS
    Validates the configuration of the remote management-related firewall rules.
    #>
    [void] Validate() {
        $this.WMI.Validate()
    }
}

class FileServerSettings {
    # Indicates whether inbound Server Message Block (SMB) traffic should be allowed.
    [bool]             $EnableSMB                     = $false

    # Indicates whether inbound Distributed File System Replication (DFSR) traffic should be allowed.
    [bool]             $EnableDFSR                    = $false

    # Static port to be used for DFSR traffic.
    [Nullable[uint16]] $DfsrStaticPort                = $null

    # Indicates whether inbound File Server Resource Manager (FSRM) management traffic should be allowed.
    [bool]             $EnableFSRMManagement          = $false

    # Indicates whether inbound iSCSI traffic should be allowed.
    [bool]             $EnableISCSI                   = $false

    # Indicates whether inbound Network File System (NFS) traffic should be allowed.
    [bool]             $EnableNFS                     = $false

    # Indicates whether additional filtering of RPC over Named Pipes should be applied.
    [Nullable[bool]]   $EnableRpcFilters              = $null
}

class PrintServerSettings {
    # Indicates whether inbound Print Spooler traffic through RPC over TCP should be allowed.
    [bool]               $Enabled                        = $false

    # Static port to be used by the Print Spooler listener.
    [Nullable[uint16]]   $StaticPort                     = $null
}

class DhcpServerSettings {
    # Indicates whether inbound Dynamic Host Configuration Protocol (DHCP) server traffic should be allowed.
    [bool]               $Enabled                        = $false
}

class DnsServerSettings {
    # Indicates whether inbound Domain Name System (DNS) traffic should be allowed.
    [bool]               $Enabled                        = $false
}

class NetworkPolicyServerSettings {
    # Indicates whether inbound Network Policy Server (NPS) / RADIUS traffic should be allowed.
    [bool]               $Enabled                        = $false

    # One or more names of IP address sets from which RADIUS client traffic should be allowed.
    [string[]]           $ClientAddressSet               = $null
}

class WebServerSettings {
    # Indicates whether inbound HTTP web server traffic should be allowed.
    [bool]               $EnableHTTP                     = $false

    # Indicates whether inbound HTTPS web server traffic should be allowed.
    [bool]               $EnableHTTPS                    = $false

    # Indicates whether inbound HTTP/3 web server traffic should be allowed.
    [bool]               $EnableQUIC                     = $false
}

class CertificationAuthoritySettings {
    # Indicates whether inbound Certification Authority (CA) traffic should be allowed.
    [bool]               $Enabled                        = $false

    # Static port to be used by the Certification Authority DCOM interface.
    [Nullable[uint16]]   $StaticPort                     = $null

    # Indicates whether remote access to the ICertAdmin interface should be blocked.
    [Nullable[bool]]     $BlockRemoteManagement          = $null

    # Indicates whether the legacy ICertPassage Remote Protocol (MS-ICPR) should be blocked.
    [Nullable[bool]]     $BlockLegacyRpc                 = $null
}

class ServerRoleSettings {
    # Firewall configuration for the File Server role.
    [FileServerSettings] $FileServer                     = [FileServerSettings]::new()

    # Firewall configuration for the Print Server role.
    [PrintServerSettings] $PrintServer                   = [PrintServerSettings]::new()

    # Firewall configuration for the DHCP Server role.
    [DhcpServerSettings] $DHCP                           = [DhcpServerSettings]::new()

    # Firewall configuration for the DNS Server role.
    [DnsServerSettings]  $DNS                            = [DnsServerSettings]::new()

    # Firewall configuration for the Network Policy Server (NPS) / RADIUS role.
    [NetworkPolicyServerSettings] $RADIUS               = [NetworkPolicyServerSettings]::new()

    # Firewall configuration for http.sys-based web server traffic.
    [WebServerSettings]  $WebServer                      = [WebServerSettings]::new()

    # Firewall configuration for the Certification Authority (CA) role.
    [CertificationAuthoritySettings] $CA                = [CertificationAuthoritySettings]::new()

    # Indicates whether inbound Windows Internet Name Service (WINS) traffic should be allowed.
    [bool]               $EnableWINS                    = $false

    # Indicates whether inbound Key Management Service (KMS) traffic should be allowed.
    [bool]               $EnableKMS                     = $false

    # Indicates whether inbound Windows Server Update Services (WSUS) traffic should be allowed.
    [bool]               $EnableWSUS                    = $false

    # Indicates whether inbound Windows Deployment Services (WDS) traffic should be allowed.
    [bool]               $EnableWDS                     = $false

    # Indicates whether remote backup management should be enabled.
    [bool]               $EnableBackupManagement        = $false

    # Indicates whether inbound Web Application Proxy traffic should be allowed."
    [bool]               $EnableWebApplicationProxy     = $false

    # Indicates whether inbound Remote Desktop Licensing traffic should be allowed."
    [bool]               $EnableRemoteDesktopLicensing  = $false

    # Indicates whether inbound Message Queuing (MSMQ) traffic should be allowed."
    [bool]               $EnableMessageQueuing          = $false

    # Indicates whether inbound SQL Server traffic should be allowed."
    [bool]               $EnableSQLServer               = $false

    # One or more names of IP address sets from which client traffic should be allowed.
    [string[]]           $ClientAddressSet              = @($PredefinedAddressSet_AllAddresses)

    # TODO: Remote Access Role (RRAS, VPN, DirectAccess)?
    <#
    .SYNOPSIS
    Validates the configuration of the server role-related firewall rules.
    #>
    [void] Validate() {
        if ($this.PrintServer.Enabled -and $this.FileServer.EnableRpcFilters) {
            Write-Warning -Message 'Older Windows versions used the SMB protocol to communicate with the Print Spooler service. RPC filters will block this traffic.'
        }
    }

    [bool] IsServerRoleEnabled() {
        return $this.FileServer.EnableSMB -or
               $this.FileServer.EnableDFSR -or
               $this.FileServer.EnableISCSI -or
               $this.FileServer.EnableNFS -or
               $this.DHCP.Enabled -or
               $this.DNS.Enabled -or
               $this.PrintServer.Enabled -or
               $this.WebServer.EnableHTTP -or
               $this.WebServer.EnableHTTPS -or
               $this.WebServer.EnableQUIC -or
               $this.CA.Enabled -or
               $this.RADIUS.Enabled -or
               $this.EnableWINS -or
               $this.EnableKMS -or
               $this.EnableWSUS -or
               $this.EnableWDS -or
               $this.EnableBackupManagement -or
               $this.EnableWebApplicationProxy -or
               $this.EnableRemoteDesktopLicensing -or
               $this.EnableMessageQueuing -or
               $this.EnableSQLServer
    }
}

class WindowsFirewallRule {
    # The unique name of the rule.
    [string] $Name

    # The display name of the rule.
    [string] $DisplayName = $null

    # The group to which the rule belongs.
    [string] $Group = $null

    # A brief description of the rule.
    [string] $Description = $null

    # Indicates whether the rule is enabled.
    [bool] $Enabled = $true

    # Indicates whether the rule blocks traffic (true) or allows traffic (false).
    [bool] $Block = $false

    # The network protocol specified by name or number.
    [string] $Protocol = $null

    # The local port or port range for the rule.
    [string] $LocalPort = $AnyKeyWord

    # The ICMP type for the rule (only applicable if Protocol is ICMPv4 or ICMPv6).
    [string] $IcmpType = $null

    # The remote IP addresses, subnets, or predefined keywords to which the rule applies.
    [string[]] $RemoteAddress = $null

    # One or more names of IP address sets defined in the IPAddressSets section.
    [string[]] $RemoteAddressSet = $null

    # The name of the program associated with the rule.
    [string] $Program = $null

    # The name of the service associated with the rule.
    [string] $Service = $null

    # The network profile(s) to which the rule applies.
    [string] $Profile = $script:AnyKeyWord

    <#
    .SYNOPSIS
    Validates the configuration of the firewall rule.
    #>
    [void] Validate() {
        if ([string]::IsNullOrWhiteSpace($this.Name)) {
            throw [System.ArgumentNullException]::new('Name', 'The Name property of a firewall rule must be provided.')
        }

        if ($this.Profile -ne $script:AnyKeyWord) {
            Write-Warning -Message ('The firewall rule {0} is configured to apply to a specific profile. Firewall profiles are not recommended for use on Windows Servers.' -f $this.Name)
        }

        if ([string]::IsNullOrWhiteSpace($this.DisplayName)) {
            # Set a default display name if none is provided
            $this.DisplayName = $this.Name
        }
    }
}

class IPAddressSet {
    # The name of the IP address set.
    [string] $Name

    # The list of IP addresses, subnets, or predefined keywords included in the set.
    [string[]] $Addresses

    IPAddressSet() {
        $this.Name = 'UnnamedSet'
        $this.Addresses = @($script:AnyKeyWord)
    }

    IPAddressSet([string] $name, [string[]] $addresses) {
        $this.Name = $name
        $this.Addresses = $addresses
    }

    IPAddressSet([String] $name) {
        $this.Name = $name
        $this.Addresses = @($script:AnyKeyWord)
    }
}

class ScriptSettings {
    # The name of the Group Policy Object (GPO) that will be created or updated.
    [string]           $GroupPolicyObjectName         = 'Domain Controller Firewall'

    # The comment that will be added to the Group Policy Object (GPO).
    [string]           $GroupPolicyObjectComment      = 'This GPO is managed by the Set-WindowsFirewallPolicy.ps1 PowerShell script.'

    # The unique identifier (GUID) of the Group Policy Object (GPO). If specified, the script will attempt to update the GPO with this ID instead of searching by name.
    [Nullable[System.Guid]] $GroupPolicyObjectId      = $null
    
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

    # Indicates whether local IPSec rules should be enabled.
    [bool]             $EnableLocalIPsecRules         = $true

    [bool]             $IncludeDisabledRules          = $false

    # Predefined sets of IP addresses that can be referenced in custom firewall rules.
    [System.Collections.Generic.List[IPAddressSet]] $IPAddressSets = @()

    # Configuration of core networking-related firewall rules.
    [CoreNetworkingSettings] $CoreNetworking          = [CoreNetworkingSettings]::new()

    # Configuration of remote management-related firewall rules.
    [RemoteManagementSettings] $RemoteManagement      = [RemoteManagementSettings]::new()

    # Firewall configuration for natively supported Windows Server roles.
    [ServerRoleSettings] $ServerRoles                 = [ServerRoleSettings]::new()

    # List of custom firewall rules that should be created or updated.
    [WindowsFirewallRule[]] $CustomRules              = @()

    <#
    .SYNOPSIS
    Validates the overall configuration settings.
    #>
    [void] Validate() {
        # Handle fatal configuration issues
        if ([string]::IsNullOrWhiteSpace($this.GroupPolicyObjectName)) {
            throw [System.ArgumentNullException]::new('GroupPolicyObjectName', 'The name of the target GPO must be provided.')
        }

        if ([string]::IsNullOrWhiteSpace($this.LogFilePath)) {
            throw [System.ArgumentNullException]::new('LogFilePath', 'The path to the firewall log file must be provided.')
        }

        # Add default values
        if (@($this.IPAddressSets.Where({$PSItem.Name -eq $script:PredefinedAddressSet_ManagementAddresses}, 'First')).Count -eq 0) {
            # Add the default management address set if it does not exist
            $this.IPAddressSets.Add([IPAddressSet]::new($script:PredefinedAddressSet_ManagementAddresses, @($script:AnyKeyWord)))
        }

        if ($this.IPAddressSets.Where({$PSItem.Name -eq $script:PredefinedAddressSet_ManagementAddresses}, 'First').Addresses -contains $script:AnyKeyWord) {
            Write-Warning -Message 'The current configuration allows management traffic from any IP address.'
        }

        if (@($this.IPAddressSets.Where({$PSItem.Name -eq $script:PredefinedAddressSet_AllAddresses}, 'First')).Count -eq 0) {
            # Add the default set containing all IP addresses if it does not exist
            $this.IPAddressSets.Add([IPAddressSet]::new($script:PredefinedAddressSet_AllAddresses, @($script:AnyKeyWord)))
        }

        # Sanitize the maximum log file size
        if ($this.LogMaxSizeKilobytes -gt [int16]::MaxValue -or $this.LogMaxSizeKilobytes -le 0) {
            # Windows only accepts 1KB-32MB as the maximum log file size.
            Write-Warning -Message 'The LogMaxSizeKilobytes value is out of the supported range. Setting it to the value of 32MB.'
            $this.LogMaxSizeKilobytes = [int16]::MaxValue # = 32MB
        }

        if (-not($this.LogMaxSizeKilobytes -ge 16384 -and $this.LogDroppedPackets -and $this.LogAllowedPackets)) {
            Write-Warning -Message 'The firewall log settings do not meet some standardized security baselines.'
        }

        if ($this.EnableLocalIPsecRules) {
            Write-Warning -Message 'Local IPSec rules are enabled, which violates some standardized security baselines.'
        }

        $this.CoreNetworking.Validate()
        $this.RemoteManagement.Validate()
        $this.ServerRoles.Validate()
    }
}

#endregion Configuration Data Model

#region Helper Functions

<#
.SYNOPSIS
Reads and deserializes the script configuration from a JSON file.

.PARAMETER ConfigurationFilePath
The path to the JSON configuration file.

.OUTPUTS
A ScriptSettings object containing the deserialized configuration.

#>
function Read-ScriptConfiguration {
    [OutputType([ScriptSettings])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ConfigurationFilePath
    )

    [bool] $configurationFileExists = Test-Path -Path $ConfigurationFilePath -PathType Leaf

    if (-not $configurationFileExists) {
        # Abort script execution if the configuration file does not exist.
        [string] $message = 'The configuration file {0} was not found. See the *.sample.json files for examples.' -f $ConfigurationFilePath
        throw [System.IO.FileNotFoundException]::new($message, $ConfigurationFilePath)
    }

    Write-Verbose -Message "Reading the $ConfigurationFilePath configuration file."
    [System.Runtime.Serialization.Json.DataContractJsonSerializer] $serializer = [System.Runtime.Serialization.Json.DataContractJsonSerializer]::new([ScriptSettings])
    [System.IO.FileStream] $stream = [System.IO.File]::Open($ConfigurationFilePath, [System.IO.FileMode]::Open)

    try {
        [ScriptSettings] $configuration = $serializer.ReadObject($stream)
        
        # Validate the configuration and quit if there are any serious issues
        $configuration.Validate()

        return $configuration
    }
    catch {
        # Do not continue if there is any issue reading the configuration file
        throw
    }
    finally {
        $stream.Close()
    }
}

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

    if ($Value) {
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

    if ($Value) {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True
    }
    else {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False
    }
}

<#
.SYNOPSIS
Converts a profile name to a NetSecurity.Profile enumeration value, which is accepted by the New-NetFirewallRule cmdlet.

.PARAMETER Profile
Comma separated profile names to convert.

#>
function ConvertTo-NetSecurityProfile {
    [OutputType([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Profile
    )
    
    # Parse the profile names
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile] $profileEnum = $Profile

    # Optionally replace "Public,Private,Domain" with "Any"
    if ($profileEnum.HasFlag([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Domain) -and `
        $profileEnum.HasFlag([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Private) -and `
        $profileEnum.HasFlag([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Public)) {
        $profileEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Any
    }

    return $profileEnum
}

<#
.SYNOPSIS
Converts a boolean value to a NetSecurity.Action enumeration value, which is accepted by the New-NetFirewallRule cmdlet.

.PARAMETER Allow
The boolean value to convert.

#>
function ConvertTo-NetSecurityAction {
    [OutputType([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [bool] $Allow
    )

    if ($Allow) {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Allow
    }
    else {
        return [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Block
    }
}

<#
.SYNOPSIS
Creates a new custom firewall rule in the specified GPO.

.PARAMETER GpoSession
The GPO session to use for creating the firewall rule.

.PARAMETER CustomRule
The custom firewall rule to create.

#>
function Add-FirewallRule {
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Microsoft.GroupPolicy.GpoSession] $GpoSession,

        [Parameter(Mandatory = $true, Position = 1)]
        [Aliases('CustomRule')]
        [WindowsFirewallRule] $Rule,

        [Parameter(Mandatory = $true, Position = 2)]
        [IPAddressSet[]] $IPAddressSets,

        [Parameter(Mandatory = $false)]
        [switch] $IncludeDisabled
    )

    if (-not $Rule.Enabled -and -not $IncludeDisabled) {
        # Skip creating disabled rules unless explicitly requested
        return
    }

    [string[]] $remoteAddresses = Resolve-IPAddressSet -IPAddressSetName $Rule.RemoteAddressSet -IPAddressSets $IPAddressSets -AdditionalAddresses $Rule.RemoteAddress

    # Use parameter splatting to add optional parameters only if they have values
    [hashtable] $additionalParameters = @{}

    if (-not [string]::IsNullOrWhiteSpace($Rule.Group)) {
        $additionalParameters['Group'] = $Rule.Group
    }

    if (-not [string]::IsNullOrWhiteSpace($Rule.Description)) {
        $additionalParameters['Description'] = $Rule.Description
    }

    if (-not [string]::IsNullOrWhiteSpace($Rule.Protocol)) {
        $additionalParameters['Protocol'] = $Rule.Protocol
    }

    if (-not [string]::IsNullOrWhiteSpace($Rule.LocalPort)) {
        $additionalParameters['LocalPort'] = @($Rule.LocalPort)
    }

    if (-not [string]::IsNullOrWhiteSpace($Rule.IcmpType)) {
        $additionalParameters['IcmpType'] = @($Rule.IcmpType)
    }

    if ($remoteAddresses.Count -gt 0) {
        $additionalParameters['RemoteAddress'] = $remoteAddresses
    }

    if (-not [string]::IsNullOrWhiteSpace($Rule.Program)) {
        $additionalParameters['Program'] = $Rule.Program
    }

    if (-not [string]::IsNullOrWhiteSpace($Rule.Service)) {
        $additionalParameters['Service'] = $Rule.Service
    }

    New-NetFirewallRule `
        -GPOSession $GpoSession `
        -Name $Rule.Name `
        -DisplayName $Rule.DisplayName `
        -Enabled (ConvertTo-NetSecurityEnabled -Value $Rule.Enabled) `
        -Profile (ConvertTo-NetSecurityProfile -Profile $Rule.Profile) `
        -Action (ConvertTo-NetSecurityAction -Allow (-not $Rule.Block)) `
        -Direction Inbound `
        @additionalParameters `
        -Verbose:$script:IsVerbose > $null
}

<#
.SYNOPSIS
Resolves the specified IP address set names to their corresponding IP addresses.

.PARAMETER IpAddressSetNames
The names of the IP address sets to resolve.

.PARAMETER IPAddressSets
The collection of available IP address sets.

.PARAMETER AdditionalAddresses
Additional IP addresses to include in the resolved list.

.OUTPUTS
An array of resolved IP addresses.
#>
function Resolve-IPAddressSet {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]] $IPAddressSetName,

        [Parameter(Mandatory = $true, Position = 1)]
        [IPAddressSet[]] $IPAddressSets,

        [Parameter(Mandatory = $false, Position = 2)]
        [string[]] $AdditionalAddresses = @()
    )

    [System.Collections.Generic.List[string]] $resolvedAddresses = @()

    foreach ($setName in $IPAddressSetName) {
        [IPAddressSet] $addressSet = $IPAddressSets | Where-Object Name -eq $setName | Select-Object -First 1

        if ($null -eq $addressSet) {
            # Abort script execution if an unknown address set is referenced.
            throw [System.ArgumentException]::new(('The IP address set {0} could not be found in the configuration.' -f $setName), 'IPAddressSetName')
        }

        $resolvedAddresses.AddRange($addressSet.Addresses)
    }

    # Duplicates might exist across address sets
    [string[]] $uniqueAddresses = Sort-Object -InputObject $resolvedAddresses -Unique

    if ($uniqueAddresses -contains $script:AnyKeyWord) {
        # If "Any" is included, return only that keyword
        $uniqueAddresses = @($script:AnyKeyWord)
    }

    return $uniqueAddresses
}

<#
.SYNOPSIS
Removes all existing firewall rules from the specified GPO.

.NOTES
As Microsoft removed the -GPOSession parameter from the Remove-NetFirewallRule in Windows Server 2022, low-level CIM operations need to be used instead.

.PARAMETER GpoSession
The GPO session from which the firewall rules should be removed.

#>
function Remove-NetFirewallRuleEx {
    [OutputType([void])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $GpoSession
    )

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
        foreach ($rule in $gpoFirewallRules) {
            Write-Verbose -Message ('Deleting firewall rule {0}.' -f $rule.Name)
            $localSession.DeleteInstance('ROOT\StandardCimv2', $rule, $cimOperationOptions)
        }
    }
    finally {
        # Close the temporary local CIM session
        Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue
    }
}

#endregion Helper Functions

#region Core Networking Rules

# Load the configuration from the JSON file
[string] $configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFileName
[ScriptSettings] $configuration = Read-ScriptConfiguration -ConfigurationFilePath $configurationFilePath

# Build a collection of firewall rules to be created
[System.Collections.Generic.List[WindowsFirewallRule]] $firewallRules = @()
$firewallRules.AddRange($configuration.CustomRules)

# Create Inbound rule "Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)"
[WindowsFirewallRule] $icmp4DuFragRule = @{
    Name         = 'CoreNet-ICMP4-DUFRAG-In'
    DisplayName  = 'Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)'
    Group        = 'Core Networking'
    Description  = 'Destination Unreachable Fragmentation Needed error messages are sent from any node that a packet traverses which is unable to forward the packet because fragmentation was needed and the don''t fragment bit was set.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv4'
    IcmpType     = '3:4'
    Program      = 'System'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($icmp4DuFragRule)

# Create Inbound rule "Core Networking - Destination Unreachable (ICMPv6-In)"
[WindowsFirewallRule] $icmp6DuRule = @{
    Name         = 'CoreNet-ICMP6-DU-In'
    DisplayName  = 'Core Networking - Destination Unreachable (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Destination Unreachable error messages are sent from any node that a packet traverses which is unable to forward the packet for any reason except congestion.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 1
    Program      = 'System'
    RemoteAddress = @($script:AnyKeyWord)
}

$firewallRules.Add($icmp6DuRule)

# Create Inbound rule "Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)"
[WindowsFirewallRule] $icmp6NdaRule = @{
    Name         = 'CoreNet-ICMP6-NDA-In'
    DisplayName  = 'Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Neighbor Discovery Advertisement messages are sent by nodes to notify other nodes of link-layer address changes or in response to a Neighbor Discovery Solicitation request.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 136
    Program      = 'System'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($icmp6NdaRule)

# Create Inbound rule "Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)"
[WindowsFirewallRule] $icmp6NdsRule = @{
    Name         = 'CoreNet-ICMP6-NDS-In'
    DisplayName  = 'Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Neighbor Discovery Solicitations are sent by nodes to discover the link-layer address of another on-link IPv6 node.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 135
    Program      = 'System'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($icmp6NdsRule)

# Create Inbound rule "Core Networking - Packet Too Big (ICMPv6-In)"
[WindowsFirewallRule] $icmp6PtbRule = @{
    Name         = 'CoreNet-ICMP6-PTB-In'
    DisplayName  = 'Core Networking - Packet Too Big (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Packet Too Big error messages are sent from any node that a packet traverses which is unable to forward the packet because the packet is too large for the next link.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 2
    Program      = 'System'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($icmp6PtbRule)

# Create Inbound rule "Core Networking - Parameter Problem (ICMPv6-In)"
[WindowsFirewallRule] $icmp6PpRule = @{
    Name         = 'CoreNet-ICMP6-PP-In'
    DisplayName  = 'Core Networking - Parameter Problem (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Parameter Problem error messages are sent by nodes as a result of incorrectly generated packets.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 4
    Program      = 'System'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($icmp6PpRule)

# Create Inbound rule "Core Networking - Time Exceeded (ICMPv6-In)"
[WindowsFirewallRule] $icmp6TeRule = @{
    Name         = 'CoreNet-ICMP6-TE-In'
    DisplayName  = 'Core Networking - Time Exceeded (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Time Exceeded error messages are generated from any node that a packet traverses if the Hop Limit value is decremented to zero at any point on the path.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 3
    Program      = 'System'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($icmp6TeRule)

# Create Inbound rule "Core Networking - Router Advertisement (ICMPv6-In)"
[WindowsFirewallRule] $icmp6RaRule = @{
    Name          = 'CoreNet-ICMP6-RA-In'
    DisplayName   = 'Core Networking - Router Advertisement (ICMPv6-In)'
    Group         = 'Core Networking'
    Description   = 'Router Advertisement messages are sent by routers to other nodes for stateless auto-configuration.'
    Enabled       = $configuration.CoreNetworking.EnableIcmp
    Protocol      = 'ICMPv6'
    IcmpType      = 134
    Program       = 'System'
    RemoteAddress = 'fe80::/64'
}

$firewallRules.Add($icmp6RaRule)

# Create Inbound rule "Core Networking - Multicast Listener Done (ICMPv6-In)"
[WindowsFirewallRule] $icmp6LdRule = @{
    Name         = 'CoreNet-ICMP6-LD-In'
    DisplayName  = 'Core Networking - Multicast Listener Done (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Multicast Listener Done messages inform local routers that there are no longer any members remaining for a specific multicast address on the subnet.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 132
    Program      = 'System'
    RemoteAddress = 'LocalSubnet6'
}

$firewallRules.Add($icmp6LdRule)

# Create Inbound rule "Core Networking - Multicast Listener Report v2 (ICMPv6-In)"
[WindowsFirewallRule] $icmp6Lr2Rule = @{
    Name         = 'CoreNet-ICMP6-LR2-In'
    DisplayName  = 'Core Networking - Multicast Listener Report v2 (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'Multicast Listener Report v2 message is used by a listening node to either immediately report its interest in receiving multicast traffic at a specific multicast address or in response to a Multicast Listener Query.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 143
    Program      = 'System'
    RemoteAddress = 'LocalSubnet6'
}

$firewallRules.Add($icmp6Lr2Rule)

# Create Inbound rule "Core Networking - Multicast Listener Query (ICMPv6-In)"
[WindowsFirewallRule] $icmp6LqRule = @{
    Name         = 'CoreNet-ICMP6-LQ-In'
    DisplayName  = 'Core Networking - Multicast Listener Query (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'An IPv6 multicast-capable router uses the Multicast Listener Query message to query a link for multicast group membership.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 130
    Program      = 'System'
    RemoteAddress = 'LocalSubnet6'
}

$firewallRules.Add($icmp6LqRule)

# Create Inbound rule "Core Networking - Multicast Listener Report (ICMPv6-In)"
[WindowsFirewallRule] $icmp6LrRule = @{
    Name         = 'CoreNet-ICMP6-LR-In'
    DisplayName  = 'Core Networking - Multicast Listener Report (ICMPv6-In)'
    Group        = 'Core Networking'
    Description  = 'The Multicast Listener Report message is used by a listening node to either immediately report its interest in receiving multicast traffic at a specific multicast address or in response to a Multicast Listener Query.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 131
    Program      = 'System'
    RemoteAddress = 'LocalSubnet6'
}

$firewallRules.Add($icmp6LrRule)

# Create Inbound rule "Core Networking - Internet Group Management Protocol (IGMP-In)"
[WindowsFirewallRule] $igmpRule = @{
    Name         = 'CoreNet-IGMP-In'
    DisplayName  = 'Core Networking - Internet Group Management Protocol (IGMP-In)'
    Group        = 'Core Networking'
    Description  = 'IGMP messages are sent and received by nodes to create, join and depart multicast groups.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 2 # IGMP
    Program      = 'System'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($igmpRule)

# Profile for incoming Pings: Any for servers, Domain and Private for workstations
[string] $pingProfile = if ($configuration.ServerRoles.IsServerRoleEnabled()) {
    $script:AnyKeyWord
} else {
    'Domain,Private'
}

# Create Inbound rule "Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)"
[WindowsFirewallRule] $pingV4Rule = @{
    Name         = 'CoreNet-Diag-ICMP4-EchoRequest-In'
    DisplayName  = 'Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)'
    Group        = 'Core Networking Diagnostics'
    Description  = 'ICMP Echo Request messages are sent as ping requests to other nodes.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv4'
    IcmpType     = 8
    Program      = 'System'
    Profile      = $pingProfile
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # This falls back to all addresses if not configured.
}

$firewallRules.Add($pingV4Rule)

# Create Inbound rule "Core Networking Diagnostics - ICMP Echo Request (ICMPv6-In)"
[WindowsFirewallRule] $pingV6Rule = @{
    Name         = 'CoreNet-Diag-ICMP6-EchoRequest-In'
    DisplayName  = 'Core Networking Diagnostics - ICMP Echo Request (ICMPv6-In)'
    Group        = 'Core Networking Diagnostics'
    Description  = 'ICMP Echo Request messages are sent as ping requests to other nodes.'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 128
    Program      = 'System'
    Profile      = $pingProfile
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # This falls back to all addresses if not configured.
}

$firewallRules.Add($pingV6Rule)

# Create Inbound rule "Core Networking - Dynamic Host Configuration Protocol (DHCP-In)"
[WindowsFirewallRule] $dhcpClientV4Rule = @{
    Name          = 'CoreNet-DHCP-In'
    DisplayName   = 'Core Networking - Dynamic Host Configuration Protocol (DHCP-In)'
    Group         = 'Core Networking'
    Description   = 'Allows DHCP (Dynamic Host Configuration Protocol) messages for stateful auto-configuration.'
    Enabled       = $configuration.CoreNetworking.EnableDhcpClient
    Protocol      = 'UDP'
    LocalPort     = 68
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'dhcp'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($dhcpClientV4Rule)

# Create Inbound rule "Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)"
[WindowsFirewallRule] $dhcpClientV6Rule = @{
    Name          = 'CoreNet-DHCPv6-In'
    DisplayName   = 'Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)'
    Group         = 'Core Networking'
    Description   = 'Allows DHCPv6 (Dynamic Host Configuration Protocol for IPv6) messages for stateful and stateless configuration.'
    Enabled       = $configuration.CoreNetworking.EnableDhcpClient
    Protocol      = 'UDP'
    LocalPort     = 546
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'dhcp'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($dhcpClientV6Rule)

# NetBIOS rule profile and scope should be more strict on workstations than on servers
# (and ideally not enabled at all if possible)

# Profile: Any for servers, Domain only for workstations
[string] $netbiosProfile = if ($configuration.ServerRoles.IsServerRoleEnabled()) { $script:AnyKeyWord } else { 'Domain' }

# Remote Address: ClientAddressSet (with fallback to Any) for servers, LocalSubnet for workstations
[string[]] $netbiosRemoteAddress = if ($configuration.ServerRoles.IsServerRoleEnabled()) {
    Resolve-IPAddressSet -IPAddressSetName $configuration.ServerRoles.ClientAddressSet -IPAddressSets $configuration.IPAddressSets
} else {
    'LocalSubnet'
}

# Create Inbound rule "File and Printer Sharing (NB-Name-In)"
[WindowsFirewallRule] $nbNameRule = @{
    Name         = 'FPS-NB_Name-In-UDP'
    DisplayName  = 'File and Printer Sharing (NB-Name-In)'
    Group        = 'File and Printer Sharing'
    Description  = 'Inbound rule for File and Printer Sharing to allow NetBIOS Name Resolution. [UDP 137]'
    Enabled      = $configuration.CoreNetworking.EnableNetbiosNameService
    Protocol     = 'UDP'
    LocalPort    = 137
    Program      = 'System'
    Profile      = $netbiosProfile
    RemoteAddress = $netbiosRemoteAddress
}

$firewallRules.Add($nbNameRule)

# Create Inbound rule "File and Printer Sharing (NB-Datagram-In)"
[WindowsFirewallRule] $nbDatagramRule = @{
    Name         = 'FPS-NB_Datagram-In-UDP'
    DisplayName  = 'File and Printer Sharing (NB-Datagram-In)'
    Group        = 'File and Printer Sharing'
    Description  = 'Inbound rule for File and Printer Sharing to allow NetBIOS Datagram transmission and reception. [UDP 138]'
    Enabled      = $configuration.CoreNetworking.EnableNetbiosDatagramService
    Protocol     = 'UDP'
    LocalPort    = 138
    Program      = 'System'
    Profile      = $netbiosProfile
    RemoteAddress = $netbiosRemoteAddress
}

$firewallRules.Add($nbDatagramRule)

# Create Inbound rule "File and Printer Sharing (NB-Session-In)"
[WindowsFirewallRule] $nbSessionRule = @{
    Name         = 'FPS-NB_Session-In-TCP'
    DisplayName  = 'File and Printer Sharing (NB-Session-In)'
    Group        = 'File and Printer Sharing'
    Description  = 'Inbound rule for File and Printer Sharing to allow NetBIOS Session Service connections. [TCP 139]'
    Enabled      = $configuration.CoreNetworking.EnableNetbiosSessionService
    Protocol     = 'TCP'
    LocalPort    = 139
    Program      = 'System'
    Profile      = $netbiosProfile
    RemoteAddress = $netbiosRemoteAddress
}

$firewallRules.Add($nbSessionRule)

# Create Inbound rule "Network Discovery (LLMNR-UDP-In)"
[WindowsFirewallRule] $llmnrRule = @{
    Name          = 'NETDIS-LLMNR-In-UDP-Active'
    DisplayName   = 'Network Discovery (LLMNR-UDP-In)'
    Group         = 'Network Discovery'
    Description   = 'Inbound rule for Network Discovery to allow Link Local Multicast Name Resolution. [UDP 5355]'
    Enabled       = $configuration.CoreNetworking.EnableLlmnr
    Protocol      = 'UDP'
    LocalPort     = 5355
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'dnscache'
    Profile       = 'Domain,Private' # Exclude Public profile for LLMNR
    RemoteAddress = 'LocalSubnet'
}

$firewallRules.Add($llmnrRule)

# Create Inbound rule "mDNS (UDP-In)"
[WindowsFirewallRule] $mdnsRule = @{
    Name          = 'MDNS-In-UDP-Private-Active'
    DisplayName   = 'mDNS (UDP-In)'
    Group         = 'mDNS'
    Description   = 'Inbound rule for mDNS traffic [UDP]'
    Enabled       = $configuration.CoreNetworking.EnableMdns
    Protocol      = 'UDP'
    LocalPort     = 5353
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'dnscache'
    Profile       = 'Domain,Private' # Exclude Public profile for mDNS
    RemoteAddress = 'LocalSubnet'
}

$firewallRules.Add($mdnsRule)

#endregion Core Networking Rules

#region Remote Management Rules

# Create Inbound rule "Windows Remote Management (HTTP-In)"
[WindowsFirewallRule] $winrmHttpInRule = @{
    Name         = 'WINRM-HTTP-In-TCP-PUBLIC'
    DisplayName  = 'Windows Remote Management (HTTP-In)'
    Group        = 'Windows Remote Management'
    Description  = 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]'
    Enabled      = $configuration.RemoteManagement.EnableWindowsRemoteManagement
    Protocol     = 'TCP'
    LocalPort    = 5985
    Program      = 'System'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($winrmHttpInRule)

# Create Inbound rule "Windows Remote Management (HTTPS-In)"
[WindowsFirewallRule] $winrmHttpsInRule = @{
    Name         = 'WINRM-HTTPS-In-TCP-PUBLIC'
    DisplayName  = 'Windows Remote Management (HTTPS-In)'
    Group        = 'Windows Remote Management'
    Description  = 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]'
    Enabled      = $configuration.RemoteManagement.EnableWindowsRemoteManagement
    Protocol     = 'TCP'
    LocalPort    = 5986
    Program      = 'System'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($winrmHttpsInRule)

# Create Inbound rule "Windows Management Instrumentation (WMI-In)"
[WindowsFirewallRule] $wmiRule = @{
    Name         = 'WMI-WINMGMT-In-TCP'
    DisplayName  = 'Windows Management Instrumentation (WMI-In)'
    Group        = 'Windows Management Instrumentation (WMI)'
    Description  = 'Inbound rule to allow WMI traffic for remote Windows Management Instrumentation. [TCP]'
    Enabled      = $configuration.RemoteManagement.WMI.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'Any'
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'winmgmt'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($wmiRule)

# Create Inbound rule "Windows Management Instrumentation (ASync-In)"
[WindowsFirewallRule] $wmiAsyncRule = @{
    Name         = 'WMI-ASYNC-In-TCP'
    DisplayName  = 'Windows Management Instrumentation (ASync-In)'
    Group        = 'Windows Management Instrumentation (WMI)'
    Description  = 'Inbound rule to allow Asynchronous WMI traffic for remote Windows Management Instrumentation. [TCP]'
    Enabled      = $configuration.RemoteManagement.WMI.EnableAsyncTraffic
    Protocol     = 'TCP'
    LocalPort    = 'Any'
    Program      = '%systemroot%\system32\wbem\unsecapp.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($wmiAsyncRule)

# Create Inbound rule "Performance Logs and Alerts (TCP-In)"
[WindowsFirewallRule] $perfLogRule = @{
    Name         = 'PerfLogsAlerts-PLASrv-In-TCP-NoScope'
    DisplayName  = 'Performance Logs and Alerts (TCP-In)'
    Group        = 'Performance Logs and Alerts'
    Description  = 'Inbound rule for Performance Logs and Alerts traffic. [TCP-In]'
    Enabled      = $configuration.RemoteManagement.EnablePerformanceLogAccess
    Protocol     = 'TCP'
    LocalPort    = 'Any'
    Program      = '%systemroot%\system32\plasrv.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($perfLogRule)

# Create Inbound rule "Remote Event Log Management (RPC)"
[WindowsFirewallRule] $eventLogRule = @{
    Name         = 'RemoteEventLogSvc-In-TCP'
    DisplayName  = 'Remote Event Log Management (RPC)'
    Group        = 'Remote Event Log Management'
    Description  = 'Inbound rule for the local Event Log service to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.RemoteManagement.EnableEventLogManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'Eventlog'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet # TODO: Allow override
}

$firewallRules.Add($eventLogRule)

# Create Inbound rule "Remote Scheduled Tasks Management (RPC)"
[WindowsFirewallRule] $taskSchedulerRule = @{
    Name         = 'RemoteTask-In-TCP'
    DisplayName  = 'Remote Scheduled Tasks Management (RPC)'
    Group        = 'Remote Scheduled Tasks Management'
    Description  = 'Inbound rule for the Task Scheduler service to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.RemoteManagement.EnableScheduledTaskManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'schedule'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($taskSchedulerRule)

# Create Inbound rule "Remote Service Management (RPC)"
[WindowsFirewallRule] $serviceManagementRule = @{
    Name         = 'RemoteSvcAdmin-In-TCP'
    DisplayName  = 'Remote Service Management (RPC)'
    Group        = 'Remote Service Management'
    Description  = 'Inbound rule for the local Service Control Manager to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.RemoteManagement.EnableServiceManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\services.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($serviceManagementRule)

# Create Inbound rule "OpenSSH SSH Server (sshd)"
[WindowsFirewallRule] $sshRule = @{
    Name         = 'OpenSSH-Server-In-TCP'
    DisplayName  = 'OpenSSH SSH Server (sshd)'
    Group        = 'OpenSSH Server'
    Description  = 'Inbound rule for OpenSSH SSH Server (sshd)'
    Enabled      = $configuration.RemoteManagement.EnableOpenSSHServer
    Protocol     = 'TCP'
    LocalPort    = 22
    Program      = '%SystemRoot%\system32\OpenSSH\sshd.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($sshRule)

# Create Inbound rule "Remote Desktop - User Mode (UDP-In)"

[WindowsFirewallRule] $rdpUdpRule = @{
    Name         = 'RemoteDesktop-UserMode-In-UDP'
    DisplayName  = 'Remote Desktop - User Mode (UDP-In)'
    Group        = 'Remote Desktop'
    Description  = 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]'
    Enabled      = $configuration.RemoteManagement.EnableRemoteDesktop
    Protocol     = 'UDP'
    LocalPort    = 3389
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'termservice'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet # TODO: Allow RDP set override
}

$firewallRules.Add($rdpUdpRule)

# Create Inbound rule "Remote Desktop - User Mode (TCP-In)"
[WindowsFirewallRule] $rdpTcpRule = @{
    Name         = 'RemoteDesktop-UserMode-In-TCP'
    DisplayName  = 'Remote Desktop - User Mode (TCP-In)'
    Group        = 'Remote Desktop'
    Description  = 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]'
    Enabled      = $configuration.RemoteManagement.EnableRemoteDesktop
    Protocol     = 'TCP'
    LocalPort    = 3389
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'termservice'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet # TODO: Allow RDP set override
}

$firewallRules.Add($rdpTcpRule)

# Create Inbound rule "Remote Desktop (TCP-In)"
# Note: This redundant rule is created for backward compatibility with Windows Server 2008 R2 and earlier.
[WindowsFirewallRule] $rdpLegacyRule = @{
    Name         = 'RemoteDesktop-In-TCP'
    DisplayName  = 'Remote Desktop (TCP-In)'
    Group        = 'Remote Desktop'
    Description  = 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]'
    Enabled      = $configuration.RemoteManagement.EnableRemoteDesktop
    Protocol     = 'TCP'
    LocalPort    = 3389
    Program      = 'System'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet # TODO: Allow RDP set override
}

$firewallRules.Add($rdpLegacyRule)

# Create Inbound rule "COM+ Remote Administration (DCOM-In)"
# This rule is required for remote connections using the Computer Management console.
[WindowsFirewallRule] $comPlusRemoteAdminRule = @{
    Name         = 'ComPlusRemoteAdministration-DCOM-In'
    DisplayName  = 'COM+ Remote Administration (DCOM-In)'
    Group        = 'COM+ Remote Administration'
    Description  = 'Inbound rule to allow DCOM traffic to the COM+ System Application for remote administration.'
    Enabled      = $configuration.RemoteManagement.EnableComPlusManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\dllhost.exe'
    Service      = 'COMSysApp'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($comPlusRemoteAdminRule)

# Create Inbound rule "Windows Defender Firewall Remote Management (RPC)"
[WindowsFirewallRule] $fwAdminRule = @{
    Name         = 'RemoteFwAdmin-In-TCP'
    DisplayName  = 'Windows Defender Firewall Remote Management (RPC)'
    Group        = 'Windows Defender Firewall Remote Management'
    Description  = 'Inbound rule for the Windows Defender Firewall to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.RemoteManagement.EnableFirewallManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'policyagent'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($fwAdminRule)

# Create Inbound rule "Remote Volume Management - Virtual Disk Service (RPC)"
[WindowsFirewallRule] $virtualDiskServiceRule = @{
    Name         = 'RVM-VDS-In-TCP'
    DisplayName  = 'Remote Volume Management - Virtual Disk Service (RPC)'
    Group        = 'Remote Volume Management'
    Description  = 'Inbound rule for the Remote Volume Management - Virtual Disk Service to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.RemoteManagement.EnableDiskManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\vds.exe'
    Service      = 'vds'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($virtualDiskServiceRule)

# Create Inbound rule "Remote Volume Management - Virtual Disk Service Loader (RPC)"
[WindowsFirewallRule] $virtualDiskServiceLoaderRule = @{
    Name         = 'RVM-VDSLDR-In-TCP'
    DisplayName  = 'Remote Volume Management - Virtual Disk Service Loader (RPC)'
    Group        = 'Remote Volume Management'
    Description  = 'Inbound rule for the Remote Volume Management - Virtual Disk Service Loader to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.RemoteManagement.EnableDiskManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\vdsldr.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($virtualDiskServiceLoaderRule)

#endregion Remote Management Rules

#region Server Role Rules

# Create Inbound rule "File and Printer Sharing (SMB-In)"
[WindowsFirewallRule] $smbRule = @{
    Name         = 'FPS-SMB-In-TCP'
    DisplayName  = 'File and Printer Sharing (SMB-In)'
    Group        = 'File and Printer Sharing'
    Description  = 'Inbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes. [TCP 445]'
    Enabled      = $configuration.ServerRoles.FileServer.EnableSMB
    Protocol     = 'TCP'
    LocalPort    = 445
    Program      = 'System'
    Profile      = $script:AnyKeyWord # TODO: Filter profiles on workstations?
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($smbRule)

# Create Inbound rule "File and Printer Sharing over SMBDirect (iWARP-In)"
[WindowsFirewallRule] $smbDirectiWarpRule = @{
    Name         = 'FPSSMBD-iWARP-In-TCP'
    DisplayName  = 'File and Printer Sharing over SMBDirect (iWARP-In)'
    Group        = 'File and Printer Sharing over SMBDirect'
    Description  = 'Inbound rule for File and Printer Sharing over SMBDirect to allow iWARP [TCP 5445]'
    Enabled      = $configuration.ServerRoles.FileServer.EnableSMBDirect
    Protocol     = 'TCP'
    LocalPort    = 5445
    Program      = 'System'
    Profile      = $script:AnyKeyWord # TODO: Filter profiles on workstations?
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($smbDirectiWarpRule)

# Create Inbound rule "Server for NFS (NFS-UDP-In)"
[WindowsFirewallRule] $nfsUdpRule = @{
    Name         = 'Microsoft-Windows-NFS-ServerCore-NfsSvc-NFS-UDP-In'
    DisplayName  = 'Server for NFS (NFS-UDP-In)'
    Group        = 'Server for NFS'
    Description  = 'Inbound rule for Server for NFS to allow NFS traffic. [UDP 2049]'
    Enabled      = $configuration.ServerRoles.FileServer.EnableNFS
    Protocol     = 'UDP'
    LocalPort    = 2049
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($nfsUdpRule)

# Create Inbound rule "Server for NFS (NFS-TCP-In)"
[WindowsFirewallRule] $nfsTcpRule = @{
    Name         = 'Microsoft-Windows-NFS-ServerCore-NfsSvc-NFS-TCP-In'
    DisplayName  = 'Server for NFS (NFS-TCP-In)'
    Group        = 'Server for NFS'
    Description  = 'Inbound rule for Server for NFS to allow NFS traffic. [TCP 2049]'
    Enabled      = $configuration.ServerRoles.FileServer.EnableNFS
    Protocol     = 'TCP'
    LocalPort    = 2049
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($nfsTcpRule)

# Create Inbound rule "Portmap for UNIX-based Software (UDP-In)"
[WindowsFirewallRule] $portmapUdpRule = @{
    Name         = 'Microsoft-Windows-NFS-OpenPortMapper-Portmap-UDP-In'
    DisplayName  = 'Portmap for UNIX-based Software (UDP-In)'
    Group        = 'Portmap for UNIX-based Software'
    Description  = 'Inbound rule for Portmap for Unix-based Software to allow traffic for the Portmap service. [UDP 111]'
    Enabled      = $configuration.ServerRoles.FileServer.EnableNFS
    Protocol     = 'UDP'
    LocalPort    = 111
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($portmapUdpRule)

# Create Inbound rule "Portmap for UNIX-based Software (TCP-In)"
[WindowsFirewallRule] $portmapTcpRule = @{
    Name         = 'Microsoft-Windows-NFS-OpenPortMapper-Portmap-TCP-In'
    DisplayName  = 'Portmap for UNIX-based Software (TCP-In)'
    Group        = 'Portmap for UNIX-based Software'
    Description  = 'Inbound rule for Portmap for Unix-based Software to allow traffic for the Portmap service. [TCP 111]'
    Enabled      = $configuration.ServerRoles.FileServer.EnableNFS
    Protocol     = 'TCP'
    LocalPort    = 111
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($portmapTcpRule)

# Create Inbound rule "iSCSI Service (TCP-In)"
[WindowsFirewallRule] $iscsiRule = @{
    Name         = 'MsiScsi-In-TCP'
    DisplayName  = 'iSCSI Service (TCP-In)'
    Group        = 'iSCSI Service'
    Description  = 'Inbound rule for the iSCSI Service to allow communications with an iSCSI server or device. [TCP]'
    Enabled      = $configuration.ServerRoles.iSCSI.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'Any'
    Program      = '%SystemRoot%\system32\svchost.exe'
    Service      = 'Msiscsi'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

$firewallRules.Add($iscsiRule)

# Create Inbound rule "iSCSI Target (TCP-In)"
[WindowsFirewallRule] $iscsiTargetRule = @{
    Name         = 'iSCSITarget-Service-iSCSI-In-TCP'
    DisplayName  = 'iSCSI Target (TCP-In)'
    Group        = 'iSCSI Target group'
    Description  = 'Inbound rule for the iSCSI Target Service to allow communications with iSCSI clients. [TCP 3260]'
    Enabled      = $configuration.ServerRoles.iSCSI.TargetEnabled
    Protocol     = 'TCP'
    LocalPort    = 3260
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'WinTarget'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Allow override
}

# Create Inbound rule "DNS (UDP, Incoming)"
# As the DNS service might be used by non-Windows clients, we do not limit the remote addresses.
[WindowsFirewallRule] $dnsUdpRule = @{
    Name         = 'DNSSrv-DNS-UDP-In'
    DisplayName  = 'DNS (UDP, Incoming)'
    Group        = 'DNS Service'
    Description  = 'Inbound rule to allow remote UDP access to the DNS service.'
    Enabled      = $configuration.ServerRoles.DNS.Enabled
    Protocol     = 'UDP'
    LocalPort    = 53
    Program      = '%systemroot%\System32\dns.exe'
    Service      = 'dns'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($dnsUdpRule)

# Create Inbound rule "DNS (TCP, Incoming)"
# As the DNS service might be used by non-Windows clients, we do not limit the remote addresses.
[WindowsFirewallRule] $dnsTcpRule = @{
    Name         = 'DNSSrv-DNS-TCP-In'
    DisplayName  = 'DNS (TCP, Incoming)'
    Group        = 'DNS Service'
    Description  = 'Inbound rule to allow remote TCP access to the DNS service.'
    Enabled      = $configuration.ServerRoles.DNS.Enabled
    Protocol     = 'TCP'
    LocalPort    = 53
    Program      = '%systemroot%\System32\dns.exe'
    Service      = 'dns'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($dnsTcpRule)

# Create Inbound rule "DFS Replication (RPC-In)"
# Note that a static port 5722 was used before Windows Server 2012.
[WindowsFirewallRule] $dfsrRpcRule = @{
    Name         = 'DFSR-DFSRSvc-In-TCP'
    DisplayName  = 'DFS Replication (RPC-In)'
    Group        = 'DFS Replication'
    Description  = 'Inbound rule to allow DFS Replication RPC traffic.'
    Enabled      = $configuration.ServerRoles.FileServer.EnableDFSR
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\system32\dfsrs.exe'
    Service      = 'Dfsr'
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses) # TODO: Define a proper set for replication partners
}

$firewallRules.Add($dfsrRpcRule)

# Create Inbound rule "Windows Internet Naming Service (WINS) (UDP-In)"
[WindowsFirewallRule] $winsUdpRule = @{
    Name         = 'WINS-Service-In-UDP'
    DisplayName  = 'Windows Internet Naming Service (WINS) (UDP-In)'
    Group        = 'Windows Internet Naming Service (WINS)'
    Description  = 'Inbound rule for the Windows Internet Naming Service to allow WINS requests. [UDP 42]'
    Enabled      = $configuration.ServerRoles.EnableWINS
    Protocol     = 'UDP'
    LocalPort    = 42
    Program      = '%SystemRoot%\System32\wins.exe'
    Service      = 'WINS'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($winsUdpRule)

# Create Inbound rule "Windows Internet Naming Service (WINS) (TCP-In)"
[WindowsFirewallRule] $winsTcpRule = @{
    Name         = 'WINS-Service-In-TCP'
    DisplayName  = 'Windows Internet Naming Service (WINS) (TCP-In)'
    Group        = 'Windows Internet Naming Service (WINS)'
    Description  = 'Inbound rule for the Windows Internet Naming Service to allow WINS requests. [TCP 42]'
    Enabled      = $configuration.ServerRoles.EnableWINS
    Protocol     = 'TCP'
    LocalPort    = 42
    Program      = '%SystemRoot%\System32\wins.exe'
    Service      = 'WINS'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($winsTcpRule)

# Create Inbound rule "Windows Internet Naming Service (WINS) - Remote Management (RPC)"
[WindowsFirewallRule] $winsRpcRule = @{
    Name         = 'WINS-Service-In-RPC'
    DisplayName  = 'Windows Internet Naming Service (WINS) - Remote Management (RPC)'
    Group        = 'Windows Internet Naming Service (WINS) - Remote Management'
    Description  = 'Inbound rule for the Windows Internet Naming Service to allow remote management via RPC/TCP.'
    Enabled      = $configuration.ServerRoles.EnableWINS
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%SystemRoot%\System32\wins.exe'
    Service      = 'WINS'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($winsRpcRule)

# Create Inbound rule "DFS Management (TCP-In)"
[WindowsFirewallRule] $dfsMgmtTcpRule = @{
    Name         = 'DfsMgmt-In-TCP'
    DisplayName  = 'DFS Management (TCP-In)'
    Group        = 'DFS Management'
    Description  = 'Inbound rule for DFS Management to allow the DFS Management service to be remotely managed via DCOM.'
    Enabled      = $configuration.ServerRoles.FileServer.EnableDFSR
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\dfsfrsHost.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($dfsMgmtTcpRule)

# Create Inbound rule "RPC (TCP, Incoming)"
[WindowsFirewallRule] $dnsManagementRule = @{
    Name         = 'DNSSrv-RPC-TCP-In'
    DisplayName  = 'RPC (TCP, Incoming)'
    Group        = 'DNS Service'
    Description  = 'Inbound rule to allow remote RPC/TCP access to the DNS service.'
    Enabled      = $configuration.ServerRoles.DNS.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\System32\dns.exe'
    Service      = 'dns'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($dnsManagementRule)

# Create Inbound rule "Windows Backup (RPC)"
[WindowsFirewallRule] $backupManagementRule = @{
    Name         = 'WindowsServerBackup-wbengine-In-TCP-NoScope'
    DisplayName  = 'Windows Backup (RPC)'
    Group        = 'Windows Backup'
    Description  = 'Inbound rule for the Windows Backup Service to be remotely managed via RPC/TCP'
    Enabled      = $configuration.ServerRoles.EnableBackupManagement
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\wbengine.exe'
    Service      = 'wbengine'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($backupManagementRule)

# Create Inbound rule "DHCP Server v4 (UDP-In)"
[WindowsFirewallRule] $dhcpSnoopingV4Rule = @{
    Name         = 'Microsoft-Windows-DHCP-SrvSvc-DHCPv4-In'
    DisplayName  = 'DHCP Server v4 (UDP-In)'
    Group        = 'DHCP Server'
    Description  = 'An inbound rule to allow traffic so that rogue detection works in V4. [UDP 68]'
    Enabled      = $configuration.ServerRoles.DHCP.Enabled
    Protocol     = 'UDP'
    LocalPort    = 68
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'dhcpserver'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($dhcpSnoopingV4Rule)

# Create Inbound rule "DHCP Server v6 (UDP-In)"
[WindowsFirewallRule] $dhcpSnoopingV6Rule = @{
    Name         = 'Microsoft-Windows-DHCP-SrvSvc-DHCPv6-In'
    DisplayName  = 'DHCP Server v6 (UDP-In)'
    Group        = 'DHCP Server'
    Description  = 'An inbound rule to allow traffic so that rogue detection works in V6. [UDP 546]'
    Enabled      = $configuration.ServerRoles.DHCP.Enabled
    Protocol     = 'UDP'
    LocalPort    = 546
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'dhcpserver'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($dhcpSnoopingV6Rule)

# Create Inbound rule "DHCP Server v6 (UDP-In)"
[WindowsFirewallRule] $dhcpServerV6Rule = @{
    Name         = 'Microsoft-Windows-DHCP-ClientSvc-DHCPv6-In'
    DisplayName  = 'DHCP Server v6 (UDP-In)'
    Group        = 'DHCP Server'
    Description  = 'An inbound rule to allow traffic to the IPv6 Dynamic Host Control Protocol Server. [UDP 547]'
    Enabled      = $configuration.ServerRoles.DHCP.Enabled
    Protocol     = 'UDP'
    LocalPort    = 547
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'dhcpserver'
    RemoteAddress = $script:AnyKeyWord
}

$firewallRules.Add($dhcpServerV6Rule)

# Create Inbound rule "DHCP Server Failover (TCP-In)"
[WindowsFirewallRule] $dhcpServerFailoverRule = @{
    Name         = 'Microsoft-Windows-DHCP-Failover-TCP-In'
    DisplayName  = 'DHCP Server Failover (TCP-In)'
    Group        = 'DHCP Server Management'
    Description  = 'An inbound rule to allow DHCP failover messages to the IPv4 Dynamic Host Configuration Protocol Server. [TCP 647]'
    Enabled      = $configuration.ServerRoles.DHCP.Enabled
    Protocol     = 'TCP'
    LocalPort    = 647
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'dhcpserver'
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses # TODO: Create the $configuration.ServerRoles.DhcpFailoverAddresses variable
}

$firewallRules.Add($dhcpServerFailoverRule)

# Create Inbound rule "DHCP Server (RPC-In)"
[WindowsFirewallRule] $dhcpServerManagementRule = @{
    Name         = 'Microsoft-Windows-DHCP-ClientSvc-RPC-TCP-In'
    DisplayName  = 'DHCP Server (RPC-In)'
    Group        = 'DHCP Server Management'
    Description  = 'An inbound rule to allow traffic to allow RPC traffic for DHCP Server management.'
    Enabled      = $configuration.ServerRoles.DHCP.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'dhcpserver'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($dhcpServerManagementRule)
                    
# Create Inbound rule "Network Policy Server (Legacy RADIUS Authentication - UDP-In)"
[WindowsFirewallRule] $npsLegacyAuthRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1645'
    DisplayName  = 'Network Policy Server (Legacy RADIUS Authentication - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1645]'
    Enabled      = $configuration.ServerRoles.RADIUS.Enabled
    Protocol     = 'UDP'
    LocalPort    = 1645
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    # TODO: Fallback to ClientAddressSet or Any if not defined
    RemoteAddressSet = $configuration.ServerRoles.RADIUS.ClientAddressSet
}

$firewallRules.Add($npsLegacyAuthRule)

# Create Inbound rule "Network Policy Server (Legacy RADIUS Accounting - UDP-In)"
[WindowsFirewallRule] $npsLegacyAccountingRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1646'
    DisplayName  = 'Network Policy Server (Legacy RADIUS Accounting - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1646]'
    Enabled      = $configuration.ServerRoles.RADIUS.Enabled
    Protocol     = 'UDP'
    LocalPort    = 1646
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    # TODO: Fallback to ClientAddressSet or Any if not defined
    RemoteAddressSet = $configuration.ServerRoles.RADIUS.ClientAddressSet
}

$firewallRules.Add($npsLegacyAccountingRule)

# Create Inbound rule "Network Policy Server (RADIUS Authentication - UDP-In)"
[WindowsFirewallRule] $npsRadiusAuthRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1812'
    DisplayName  = 'Network Policy Server (RADIUS Authentication - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1812]'
    Enabled      = $configuration.ServerRoles.RADIUS.Enabled
    Protocol     = 'UDP'
    LocalPort    = 1812
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    # TODO: Fallback to ClientAddressSet or Any if not defined
    RemoteAddressSet = $configuration.ServerRoles.RADIUS.ClientAddressSet
}

$firewallRules.Add($npsRadiusAuthRule)

# Create Inbound rule "Network Policy Server (RADIUS Accounting - UDP-In)"
[WindowsFirewallRule] $npsRadiusAccountingRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1813'
    DisplayName  = 'Network Policy Server (RADIUS Accounting - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1813]'
    Enabled      = $configuration.ServerRoles.RADIUS.Enabled
    Protocol     = 'UDP'
    LocalPort    = 1813
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    # TODO: Fallback to ClientAddressSet or Any if not defined
    RemoteAddressSet = $configuration.ServerRoles.RADIUS.ClientAddressSet
}

$firewallRules.Add($npsRadiusAccountingRule)

# Create Inbound rule "Network Policy Server (RPC)"
[WindowsFirewallRule] $npsManagementRule = @{
    Name         = 'NPS-NPSSvc-In-RPC'
    DisplayName  = 'Network Policy Server (RPC)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule for the Network Policy Server to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.ServerRoles.RADIUS.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\iashost.exe'
    # TODO: Fallback to ClientAddressSet or Any if not defined
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($npsManagementRule)

# Create Inbound rule "World Wide Web Services (HTTP Traffic-In)"
[WindowsFirewallRule] $iisHttpRule = @{
    Name          = 'IIS-WebServerRole-HTTP-In-TCP'
    DisplayName   = 'World Wide Web Services (HTTP Traffic-In)'
    Group         = 'World Wide Web Services (HTTP)'
    Description   = 'An inbound rule to allow HTTP traffic for Internet Information Services (IIS) [TCP 80]'
    Enabled       = $configuration.ServerRoles.WebServer.EnableHTTP
    Protocol      = 'TCP'
    LocalPort     = 80
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($iisHttpRule)

# Create Inbound rule "World Wide Web Services (HTTPS Traffic-In)"
[WindowsFirewallRule] $iisHttpsRule = @{
    Name          = 'IIS-WebServerRole-HTTPS-In-TCP'
    DisplayName   = 'World Wide Web Services (HTTPS Traffic-In)'
    Group         = 'Secure World Wide Web Services (HTTPS)'
    Description   = 'An inbound rule to allow HTTPS traffic for Internet Information Services (IIS) [TCP 443]'
    Enabled       = $configuration.ServerRoles.WebServer.EnableHTTPS
    Protocol      = 'TCP'
    LocalPort     = 443
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($iisHttpsRule)

# Create Inbound rule "World Wide Web Services (QUIC Traffic-In)"
# The port can also be used for SMB over QUIC.
[WindowsFirewallRule] $iisQuicRule = @{
    Name          = 'IIS-WebServerRole-QUIC-In-UDP'
    DisplayName   = 'World Wide Web Services (QUIC Traffic-In)'
    Group         = 'Secure World Wide Web Services (QUIC)'
    Description   = 'An inbound rule to allow QUIC traffic for Internet Information Services (IIS) [UDP 443]'
    Enabled       = $configuration.ServerRoles.WebServer.EnableQUIC
    Protocol      = 'UDP'
    LocalPort     = 443
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($iisQuicRule)

# Create Inbound rule "Windows Deployment Services (UDP-In)"
[WindowsFirewallRule] $wdsUdpRule = @{
    Name          = 'WDS-WdsServer-In-UDP'
    DisplayName   = 'Windows Deployment Services (UDP-In)'
    Group         = 'Windows Deployment Services'
    Description   = 'Inbound rule for Windows Deployment Services to allow UDP traffic.'
    Enabled       = $configuration.ServerRoles.EnableWDS
    Protocol      = 'UDP'
    LocalPort     = 'Any'
    Program       = '%systemroot%\system32\svchost.exe'
    Service       = 'WdsServer'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($wdsUdpRule)

# Create Inbound rule "Windows Deployment Services (RPC-In)"
[WindowsFirewallRule] $wdsRpcRule = @{
    Name          = 'WDS-RPC-In-TCP'
    DisplayName   = 'Windows Deployment Services (RPC-In)'
    Group         = 'Windows Deployment Services'
    Description   = 'Inbound rule for Windows Deployment Services to allow RPC/TCP traffic.'
    Enabled       = $configuration.ServerRoles.EnableWDS
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%systemroot%\system32\svchost.exe'
    Service       = 'WdsServer'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($wdsRpcRule)

# Create Inbound rule "Key Management Service (TCP-In)"
[WindowsFirewallRule] $kmsRule = @{
    Name          = 'SPPSVC-In-TCP'
    DisplayName   = 'Key Management Service (TCP-In)'
    Group         = 'Key Management Service'
    Description   = 'Inbound rule for the Key Management Service to allow for machine counting and license compliance. [TCP 1688]'
    Enabled       = $configuration.ServerRoles.EnableKMS
    Protocol      = 'TCP'
    LocalPort     = 1688
    Program       = '%SystemRoot%\system32\sppextcomobj.exe'
    Service       = 'sppsvc'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($kmsRule)

# Create Inbound rule "Remote File Server Resource Manager Management - FSRM Service (RPC-In)"
[WindowsFirewallRule] $fsrmManagementRule = @{
    Name          = 'FSRM-SrmSvc-In (RPC)'
    DisplayName   = 'Remote File Server Resource Manager Management - FSRM Service (RPC-In)'
    Group         = 'Remote File Server Resource Manager Management'
    Description   = 'Inbound rule for the File Server Resource Manager service to be remotely managed via RPC/TCP.'
    Enabled       = $configuration.ServerRoles.FileServer.EnableFSRMManagement
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%systemroot%\system32\svchost.exe'
    Service       = 'SrmSvc'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($fsrmManagementRule)

# Create Inbound rule "Remote File Server Resource Manager Management - FSRM Reports Service (RPC-In)"
[WindowsFirewallRule] $fsrmReportsRule = @{
    Name          = 'FSRM-SrmReports-In (RPC)'
    DisplayName   = 'Remote File Server Resource Manager Management - FSRM Reports Service (RPC-In)'
    Group         = 'Remote File Server Resource Manager Management'
    Description   = 'Inbound rule for the File Server Storage Reports Manager service to be remotely managed via RPC/TCP.'
    Enabled       = $configuration.ServerRoles.FileServer.EnableFSRMManagement
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%systemroot%\system32\srmhost.exe'
    Service       = 'SrmReports'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($fsrmReportsRule)

# Create Inbound rule "File and Printer Sharing (Spooler Service - RPC)"

[WindowsFirewallRule] $printSpoolerRule = @{
    Name          = 'FPS-SpoolSvc-In-TCP'
    DisplayName   = 'File and Printer Sharing (Spooler Service - RPC)'
    Group         = 'File and Printer Sharing'
    Description   = 'Inbound rule for File and Printer Sharing to allow the Print Spooler Service to communicate via TCP/RPC.'
    Enabled       = $configuration.ServerRoles.PrintServer.Enabled
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%SystemRoot%\system32\spoolsv.exe'
    Service       = 'Spooler'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($printSpoolerRule)

# Create Inbound rule "File and Printer Sharing (Spooler Service Worker - RPC)"
[WindowsFirewallRule] $printSpoolWorkerRule = @{
    Name          = 'FPS-SpoolWorker-In-TCP'
    DisplayName   = 'File and Printer Sharing (Spooler Service Worker - RPC)'
    Group         = 'File and Printer Sharing'
    Description   = 'Inbound rule for File and Printer Sharing to allow the Print Spooler Service Worker to communicate via TCP/RPC.'
    Enabled       = $configuration.ServerRoles.PrintServer.Enabled
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%SystemRoot%\system32\spoolsvworker.exe'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($printSpoolWorkerRule)

# Create Inbound rule "LPD Service"
[WindowsFirewallRule] $lpdServiceRule = @{
    Name          = 'LPDPrinterServer-TCP-In'
    DisplayName   = 'LPD Service'
    Group         = 'LPD Service'
    Description   = 'Opens the default port used by the Line Printer Daemon protocol.'
    Enabled       = $configuration.ServerRoles.PrintServer.EnableLPD
    Protocol      = 'TCP'
    LocalPort     = 515
    Program       = '%SystemRoot%\System32\svchost.exe'
    Service       = 'LPDSVC'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($lpdServiceRule)

# Create Inbound rule "Windows Server Update Services (HTTP-In)"
[WindowsFirewallRule] $wsusHttpRule = @{
    Name          = 'WSUS-In-HTTP'
    DisplayName   = 'Windows Server Update Services (HTTP-In)'
    Group         = 'Windows Server Update Services (WSUS)'
    Description   = 'Inbound rule for Windows Server Update Services to allow HTTP traffic. [TCP 8530]'
    Enabled       = $configuration.ServerRoles.EnableWSUS
    Protocol      = 'TCP'
    LocalPort     = 8530
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($wsusHttpRule)

# Create Inbound rule "Windows Server Update Services (HTTPS-In)"
[WindowsFirewallRule] $wsusHttpsRule = @{
    Name          = 'WSUS-In-HTTPS'
    DisplayName   = 'Windows Server Update Services (HTTPS-In)'
    Group         = 'Windows Server Update Services (WSUS)'
    Description   = 'Inbound rule for Windows Server Update Services to allow HTTPS traffic. [TCP 8531]'
    Enabled       = $configuration.ServerRoles.EnableWSUS
    Protocol      = 'TCP'
    LocalPort     = 8531
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($wsusHttpsRule)

# Create Inbound rule "Certification Authority Enrollment and Management Protocol (CERTSVC-RPC-TCP-IN)"
[WindowsFirewallRule] $caRule = @{
    Name          = 'Microsoft-Windows-CertificateServices-CertSvc-RPC-TCP-In'
    DisplayName   = 'Certification Authority Enrollment and Management Protocol (CERTSVC-RPC-TCP-IN)'
    Group         = 'Certification Authority'
    Description   = 'An inbound rule to allow traffic to the Certification Authority for certificate enrollment'
    Enabled       = $configuration.ServerRoles.CA.Enabled
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%systemroot%\system32\certsrv.exe'
    Service       = 'CertSvc'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($caRule)

# TODO: Remote Desktop Services Rules
<#
# Create Inbound rule "Remote Desktop Gateway UDP Listener"
[WindowsFirewallRule] $rdgUdpRule = @{
    Name         = 'TSG-UDP-Transport-In-UDP'
    DisplayName  = 'Remote Desktop Gateway UDP Listener'
    Group        = 'Remote Desktop Gateway Server Transport'
    Description  = 'Inbound rule to allow connections to remote computers on your corporate network through UDP protocol on the Remote Desktop Gateway server.'
    Enabled      = $configuration.ServerRoles.RemoteDesktopGateway.EnableUDPTransport
    Protocol     = 'UDP'
    LocalPort    = 3391
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'tsgateway'
    RemoteAddressSet = $configuration.ServerRoles.RemoteDesktopGateway.ClientAddressSet
}

$firewallRules.Add($rdgUdpRule)

# Create Inbound rule "Remote Desktop Gateway Server Farm (RPC HTTP Load Balancing Service)"
[WindowsFirewallRule] $rdgRpcLoadBalancerRule = @{
    Name         = 'TSG-RPC-LoadBalancer-RPC-In-TCP'
    DisplayName  = 'Remote Desktop Gateway Server Farm (RPC HTTP Load Balancing Service)'
    Group        = 'Remote Desktop Gateway Server Farm'
    Description  = 'Inbound rule for the Remote Desktop Gateway Server Farm to allow RPC Load balancing communications.'
    Enabled      = $configuration.ServerRoles.RemoteDesktopGateway.EnableRPCLoadBalancing
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'rpchttplbs'
    RemoteAddressSet = $configuration.ServerRoles.RemoteDesktopGateway.ClientAddressSet
}

$firewallRules.Add($rdgRpcLoadBalancerRule)

# Create Inbound rule "Remote Desktop Gateway Server Farm (TCP-In)"
[WindowsFirewallRule] $rdgTcpLoadBalancerRule = @{
    Name         = 'TSG-LoadBalancer-In-TCP'
    DisplayName  = 'Remote Desktop Gateway Server Farm (TCP-In)'
    Group        = 'Remote Desktop Gateway Server Farm'
    Description  = 'Inbound rule to allow connections from other members of the Remote Desktop Gateway Server farm. [TCP 3388]'
    Enabled      = $configuration.ServerRoles.RemoteDesktopGateway.EnableTCPLoadBalancing
    Protocol     = 'TCP'
    LocalPort    = 3388
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'tsgateway'
    RemoteAddressSet = $configuration.ServerRoles.RemoteDesktopGateway.ClientAddressSet
}

$firewallRules.Add($rdgTcpLoadBalancerRule)

# Create Inbound rule "Remote Desktop - (TCP-WS-In)"
[WindowsFirewallRule] $rdpWebSocketRule = @{
    Name         = 'RemoteDesktop-In-TCP-WS'
    DisplayName  = 'Remote Desktop - (TCP-WS-In)'
    Group        = 'Remote Desktop (WebSocket)'
    Description  = 'Inbound rule for the Remote Desktop service to allow RDP over WebSocket traffic. [TCP 3387]'
    Enabled      = $configuration.ServerRoles.RemoteDesktop.EnableWebSocketRDP
    Protocol     = 'TCP'
    LocalPort    = 3387
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($rdpWebSocketRule)

# Create Inbound rule "Remote Desktop - (TCP-WSS-In)"
[WindowsFirewallRule] $rdpWebSocketSecureRule = @{
    Name         = 'RemoteDesktop-In-TCP-WSS'
    DisplayName  = 'Remote Desktop - (TCP-WSS-In)'
    Group        = 'Remote Desktop (WebSocket)'
    Description  = 'Inbound rule for the Remote Desktop service to allow RDP traffic over secure WebSocket. [TCP 3392]'
    Enabled      = $configuration.ServerRoles.RemoteDesktop.EnableWebSocketSecureRDP
    Protocol     = 'TCP'
    LocalPort    = 3392
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($rdpWebSocketSecureRule)
#>

# Create Inbound rule "Remote Desktop Licensing Server(RPC)"
[WindowsFirewallRule] $rdpLicensingRule = @{
    Name          = 'TermServLicensing-In-TCP'
    DisplayName   = 'Remote Desktop Licensing Server(RPC)'
    Group         = 'Remote Desktop Licensing Server'
    Description   = 'Inbound rule for Remote Desktop Licensing Server to be remotely managed via RPC / TCP'
    Enabled       = $configuration.ServerRoles.RemoteDesktopLicensing.Enabled
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%systemroot%\system32\svchost.exe'
    Service       = 'TermServLicensing'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet # Define a proper set for RDL management
}

$firewallRules.Add($rdpLicensingRule)

# Create Inbound rule "SMB Witness (RPC-In)"
[WindowsFirewallRule] $smbWitnessRule = @{
    Name          = 'WITNESS-WITNESSSvc-In-TCP'
    DisplayName   = 'SMB Witness (RPC-In)'
    Group         = 'SMB Witness'
    Description   = 'Inbound rule to allow the SMB Witness RPC traffic.'
    Enabled       = $configuration.ServerRoles.FileServer.EnableSMBWitness
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'SmbWitness'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Define a proper set for SMB Witness clients
}

$firewallRules.Add($smbWitnessRule)

# Create Inbound rule "TargetMgr Service (RPC)"
[WindowsFirewallRule] $targetMgrServiceRule = @{
    Name          = 'FailoverCluster-TargetMgr-TCP-In'
    DisplayName   = 'TargetMgr Service (RPC)'
    Group         = 'Failover Clusters'
    Description   = 'Inbound rule for to allow the TargetMgr service to be remotely managed via RPC/TCP.'
    Enabled       = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol      = 'TCP'
    LocalPort     = 'RPC'
    Program       = '%systemroot%\cluster\targetmgr.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($targetMgrServiceRule)

# Create Inbound rule "Failover Clusters (UDP-In)"
[WindowsFirewallRule] $failoverClustersUdpRule = @{
    Name         = 'FailoverClustering-NetFt-UDP-In'
    DisplayName  = 'Failover Clusters (UDP-In)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for Failover Clusters to allow internal cluster communication by the cluster virtual network adapter. [UDP 3343]'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'UDP'
    LocalPort    = 3343
    Program      = 'System'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($failoverClustersUdpRule)

# Create Inbound rule "Failover Clusters (TCP-In)"
[WindowsFirewallRule] $failoverClustersTcpRule = @{
    Name         = 'FailoverClustering-ClusSvc-TCP-In'
    DisplayName  = 'Failover Clusters (TCP-In)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for Failover Clusters to allow internal cluster communication by the cluster service. [TCP 3343]'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'TCP'
    LocalPort    = 3343
    Program      = '%systemroot%\cluster\clussvc.exe'
    Service      = 'ClusSvc'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($failoverClustersTcpRule)

# Create Inbound rule "Failover Clusters (DCOM TCP-In)"
[WindowsFirewallRule] $failoverClustersCprepsrvRule = @{
    Name         = 'FailoverCluster-CPREPSRV-TCP-In'
    DisplayName  = 'Failover Clusters (DCOM TCP-In)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for Failover Clusters to allow invocation of cluster server validation, configuration, and cleanup via DCOM.'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\cprepsrv.exe'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($failoverClustersCprepsrvRule)

# Create Inbound rule "Failover Clusters (DCOM server FcSrv TCP-In)"
[WindowsFirewallRule] $failoverClustersFcsrvRule = @{
    Name         = 'FailoverCluster-FCSRV-TCP-In'
    DisplayName  = 'Failover Clusters (DCOM server FcSrv TCP-In)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for Failover Clusters to allow invocation of cluster server setup and cleanup via DCOM.'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\fcsrv.exe'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($failoverClustersFcsrvRule)

# Create Inbound rule "Failover Clusters (RPC)"
[WindowsFirewallRule] $failoverClustersRpcRule = @{
    Name         = 'FailoverClustering-ClusSvcRPC-TCP-In'
    DisplayName  = 'Failover Clusters (RPC)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for Failover Clusters to allow the cluster service to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\cluster\clussvc.exe'
    Service      = 'ClusSvc'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($failoverClustersRpcRule)

# Create Inbound rule "Cluster Set (TCP-In)"
[WindowsFirewallRule] $failoverClusterSetTcpRule = @{
    Name         = 'FailoverClusterSet-TCP-In'
    DisplayName  = 'Cluster Set (TCP-In)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for cluster sets to allow communication between clusters. [TCP 4433]'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'TCP'
    LocalPort    = 4433
    Program      = '%systemroot%\cluster\rhs.exe'
    RemoteAddressSet = $script:AnyKeyWord
}

$firewallRules.Add($failoverClusterSetTcpRule)

# Create Inbound rule "Failover Clusters - Remote Registry (RPC)"
<#
MS-RRP:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/85f43046-e27d-4122-93ba-bc278f986fbe

Enforce Packet Privacy on server using RPC filters?

[MSFT-CVE-2024-43532], will read a 
DWORD value “TransportFallbackPolicy” from the registry key 
“HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RemoteRegistryClient”.
The value is set to one of the following:
 0 – NONE – The remote registry client may try each of the protocol sequences listed above in that 
order.
 1 – DEFAULT – The remote registry client will try to use ncacn_np but may fall back on other 
transports if the caller specifically requests that behavior.
 2 – STRICT – The remote registry client will only try to use ncacn_np.
 If the value does not exist or is not one of those listed above, the remote registry client will use 
the DEFAULT policy

Additionally, Windows 7 and later and Windows Server 2008 and later, with [MSFT-CVE-2024-43532], 
will read a DWORD value “SecureModePolicy” from the registry key 
“HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RemoteRegistryClient”.
The value is set to one of the following:
 0 – NONE – The remote registry client maintains the same behavior as listed above where it will 
fall back on Connection security if Packet Privacy fails.
 1 – DEFAULT – Same behavior as NONE.
 2 – STRICT – If the connection with packet privacy fails the remote registry client will not attempt 
to fall back on a less secure connection

#>


# TODO: Check this riule and consider moving it to the standard remote management section
[WindowsFirewallRule] $failoverClustersRemoteRegistryRule = @{
    Name         = 'FailoverCluster-RemoteRegistry-TCP-In'
    DisplayName  = 'Failover Clusters - Remote Registry (RPC)'
    Group        = 'Failover Clusters'
    Description  = 'Inbound rule for Failover Clusters to allow the registry to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.ServerRoles.FailoverClustering.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'RemoteRegistry'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($failoverClustersRemoteRegistryRule)

# Create Inbound rule "Hyper-V (REMOTE_DESKTOP_TCP_IN)"
[WindowsFirewallRule] $hypervRemoteDesktopRule = @{
    Name         = 'VIRT-REMOTEDESKTOP-In-TCP-NoScope'
    DisplayName  = 'Hyper-V (REMOTE_DESKTOP_TCP_IN)'
    Group        = 'Hyper-V'
    Description  = 'Inbound rule for Hyper-V to allow remote connection to virtual machine. [TCP 2179]'
    Enabled      = $configuration.ServerRoles.HyperV.Enabled
    Protocol     = 'TCP'
    LocalPort    = 2179
    Program      = '%systemroot%\system32\vmms.exe'
    Service      = 'vmms'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($hypervRemoteDesktopRule)

# Create Inbound rule "Hyper-V (MIG-TCP-In)"
[WindowsFirewallRule] $hypervMigrationRule = @{
    Name         = 'VIRT-MIGL-In-TCP-NoScope'
    DisplayName  = 'Hyper-V (MIG-TCP-In)'
    Group        = 'Hyper-V'
    Description  = 'Inbound rule for Hyper-V to allow planned failover of virtual machines. [TCP 6600]'
    Enabled      = $configuration.ServerRoles.HyperV.Enabled
    Protocol     = 'TCP'
    LocalPort    = 6600
    Program      = '%systemroot%\system32\vmms.exe'
    Service      = 'vmms'
    RemoteAddressSet = $configuration.ServerRoles.HyperV.MigrationAddressSet
}

$firewallRules.Add($hypervMigrationRule)

# Create Inbound rule "Hyper-V (RPC)"
# TODO: Investigate if the Program should be 'System' or '%systemroot%\system32\vmms.exe'
[WindowsFirewallRule] $hypervRpcRule = @{
    Name         = 'VIRT-VMMS-RPC-In-NoScope'
    DisplayName  = 'Hyper-V (RPC)'
    Group        = 'Hyper-V'
    Description  = 'Inbound rule for Hyper-V to allow remote management via RPC/TCP.'
    Enabled      = $configuration.ServerRoles.HyperV.Enabled
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = 'System'
}

$firewallRules.Add($hypervRpcRule)

# Collect the addresses used by all RPC-based protocols and merge them into the EPMAP rule
[System.Collections.Generic.List[string]] $epmapAddresses = @()
[System.Collections.Generic.List[string]] $epmapAddressSets = @()

foreach ($rule in $firewallRules) {
    # Validate the built-in and custom firewall rules
    $rule.Validate()

    if ($rule.Enabled -and $rule.LocalPort -eq 'RPC') {
        if ($null -ne $rule.RemoteAddressSet) {
            $epmapAddressSets.AddRange($rule.RemoteAddressSet)
        }

        if ($null -ne $rule.RemoteAddress) {
            $epmapAddresses.AddRange($rule.RemoteAddress)
        }        
    }
}

# Only enable the EPMAP rule if there are any addresses to allow
[bool] $epmapEnabled = $epmapAddresses.Count -gt 0 -or $epmapAddressSets.Count -gt 0

# Create Inbound rule "RPC Endpoint Mapper (RPC-EPMAP, DCOM-In)", common for all RPC-based services
[WindowsFirewallRule] $epmapRule = @{
    Name         = 'RPCEPMAP-TCP-In'
    DisplayName  = 'RPC Endpoint Mapper (RPC-EPMAP, DCOM-In)'
    Description  = 'Inbound rule for the RPCSS service to allow RPC/TCP and DCOM traffic to the server.'
    Enabled      = $epmapEnabled
    Protocol     = 'TCP'
    LocalPort    = 'RPCEPMap'
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'rpcss'
    RemoteAddress = $epmapAddresses
    RemoteAddressSet = $epmapAddressSets
}

$firewallRules.Add($epmapRule)

#endregion Server Role Rules

### SENTINEL ###

return

#region Create and Configure the GPO

# Determine the target Active Directory domain
[Microsoft.ActiveDirectory.Management.ADDomain] $domain = $null

if ([string]::IsNullOrWhiteSpace($configuration.TargetDomain)) {
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
[Microsoft.GroupPolicy.Gpo] $gpo = $null

if ($null -ne $configuration.GroupPolicyObjectId) {
    # The GUID of the GPO is specified, so try to fetch it by its ID
    $gpo = Get-GPO -Guid $configuration.GroupPolicyObjectId `
                   -Domain $domain.DNSRoot `
                   -Server $targetDomainController `
                   -ErrorAction SilentlyContinue
    
    if ($null -eq $gpo) {
        # Abort script execution if no GPO with the specified ID does exists
        throw [System.ArgumentException]::new('GroupPolicyObjectId', 'The specified GPO ID does not exist in the target domain.')
    }
    elseif ($gpo.DisplayName -ne $configuration.GroupPolicyObjectName) {
        # Check GPO name consistency, but do not try to fix it.
        Write-Warning -Message 'The actual GPO name does not match the name specified in the configuration file.'
    }
} else {
    # Try to fetch the GPO by its name
    $gpo = Get-GPO -Name $configuration.GroupPolicyObjectName `
                   -Domain $domain.DNSRoot `
                   -Server $targetDomainController `
                   -ErrorAction SilentlyContinue

    if ($null -eq $gpo) {
        # Create the GPO if it does not exist
        $gpo = New-GPO -Name $configuration.GroupPolicyObjectName `
                       -Comment $configuration.GroupPolicyObjectComment `
                       -Domain $domain.DNSRoot `
                       -Server $targetDomainController `
                       -Verbose:$script:IsVerbose
    } else {
        Write-Verbose -Message ('Modifying a pre-existing GPO named {0}. Its ID {1} should be added to the configuration file to sustain object renames.' -f $gpo.DisplayName, $gpo.Id)
    }
}

if ($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled) {
    # Fix the GPO status
    Write-Verbose -Message ('Disabling user settings for GPO {0}.' -f $gpo.DisplayName)
    $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
}

if ($gpo.Description -ne $configuration.GroupPolicyObjectComment) {
    # Fix the GPO description
    Write-Verbose -Message ('Updating the description for GPO {0}.' -f $gpo.DisplayName)
    $gpo.Description = $configuration.GroupPolicyObjectComment
}

# Contruct the qualified GPO name
[string] $policyStore = '{0}\{1}' -f $gpo.DomainName,$gpo.DisplayName

# Make sure the GPO firewall configuration is atomic and only saved on successful completion
try {
    # Open the GPO
    # Note: The Open-NetGPO cmdlet by default contacts a random DC instead of PDC-E
    Write-Verbose -Message ('Opening GPO {0}.' -f $gpo.DisplayName)
    [string] $gpoSession = Open-NetGPO -PolicyStore $policyStore -DomainController $targetDomainController

    # Remove any pre-existing firewall rules
    Remove-NetFirewallRuleEx -GpoSession $gpoSession

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

    # Create built-in and custom firewall rules
    foreach ($rule in $firewallRules) {
        Add-FirewallRule -GpoSession $gpoSession -Rule $rule -IPAddressSets $configuration.IPAddressSets -IncludeDisabled:$configuration.IncludeDisabledRules
    }

    # Commit the firewall-related GPO changes
    Write-Verbose -Message 'Saving the GPO changes...'
    Save-NetGPO -GPOSession $gpoSession
} catch {
    # Abort the GPO changes on error
    Write-Verbose -Message 'An error occurred. Aborting the GPO changes...'
    throw
}

#endregion Create and configure the GPO

#region Registry Settings

# Prevent users and apps from accessing dangerous websites
# (Enables Microsoft Defender Exploit Guard Network Protection)
# This might block some Internet C2 traffic.
if ($null -ne $configuration.CoreNetworking.EnableNetworkProtection) {
    # We will enable the audit mode by default
    [int] $networkProtectionState = 2

    if ($configuration.CoreNetworking.EnableNetworkProtection) {
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
                        -Verbose:$script:IsVerbose > $null
                            
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                        -ValueName 'AllowNetworkProtectionOnWinServer' `
                        -Value 1 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    # Remove the Network Protection settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'EnableNetworkProtection' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
    
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' `
                           -ValueName 'AllowNetworkProtectionOnWinServer' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

# Block process creations originating from PSExec and WMI commands
# Block persistence through WMI event subscription
# Uses Microsoft Defender Exploit Guard Attack Surface Reduction
if ($null -ne $configuration.RemoteManagement.WMI.BlockCommandExecution) {
    # Audit (Evaluate how the attack surface reduction rule would impact your organization if enabled)
    [int] $blockPsExecAndWmi = 2

    if ($configuration.RemoteManagement.WMI.BlockCommandExecution -eq $true) {
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
                        -Verbose:$script:IsVerbose > $null

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
    
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                        -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                        -Value $blockPsExecAndWmi.ToString() `
                        -Type String `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    # Remove the ASR settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' `
                           -ValueName 'ExploitGuard_ASR_Rules' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' `
                           -ValueName 'e6db77e5-3df2-4cf1-b95a-636979351e5b' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

if ($null -ne $configuration.CoreNetworking.BlockRedirects) {
    # Disable ICMP Redirects by default
    [int] $enableIcmpRedirect = 0

    if ($configuration.CoreNetworking.BlockRedirects -eq $false) {
        # Enable ICMP Redirects
        $enableIcmpRedirect = 1
    }

    # Disable MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                        -ValueName 'EnableICMPRedirect' `
                        -Value $enableIcmpRedirect `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null

    # Disable source routing by default
    [int] $disableSourceRouting = 2

    if ($configuration.CoreNetworking.BlockRedirects -eq $false) {
        # Enable source routing
        $disableSourceRouting = 0
    }

    # MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                        -ValueName 'DisableIPSourceRouting' `
                        -Value $disableSourceRouting `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null

    # MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)	
    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters' `
                        -ValueName 'DisableIPSourceRouting' `
                        -Value $disableSourceRouting `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null

    # Disable router discovery by default    
    [int] $performRouterDiscovery = 0

    if ($configuration.CoreNetworking.BlockRedirects -eq $false) {
        # Enable router discovery
        $performRouterDiscovery = 1
    }

    # Disable MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                        -ValueName 'PerformRouterDiscovery' `
                        -Value $performRouterDiscovery `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null

    # Ignore NetBIOS name release requests by default
    [int] $noNameReleaseOnDemand = 1

    if ($configuration.CoreNetworking.BlockRedirects -eq $false) {
        # Process NetBIOS name release requests normally
        $noNameReleaseOnDemand = 0
    }

    # MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
    # Note: This is not a managed GPO setting.
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                        -ValueName 'NoNameReleaseOnDemand' `
                        -Value $noNameReleaseOnDemand `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    # Remove the EnableICMPRedirect setting
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                           -ValueName 'EnableICMPRedirect' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null

    # Remove the DisableIPSourceRouting IPv4 setting
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                           -ValueName 'DisableIPSourceRouting' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null

    # Remove the DisableIPSourceRouting IPv6 setting
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters' `
                           -ValueName 'DisableIPSourceRouting' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
    
    # Remove the PerformRouterDiscovery setting
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters' `
                           -ValueName 'PerformRouterDiscovery' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null

    # Remove the NoNameReleaseOnDemand setting
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                           -ValueName 'NoNameReleaseOnDemand' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

if ($null -ne $configuration.CoreNetworking.DisableNetbiosBroadcasts) {
    # NetBT NodeType configuration
    [int] $nodeType = 8 # Default to H-node (use WINS servers first, then use broadcast)

    if ($configuration.CoreNetworking.DisableNetbiosBroadcasts) {
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
                        -Verbose:$script:IsVerbose > $null

    # Configure NetBIOS settings
    [int] $enableNetbios = 3 # Default to learning mode

    if ($configuration.CoreNetworking.DisableNetbiosBroadcasts) {
        $enableNetbios = 0 # Disable NetBIOS
    }

    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                        -ValueName 'EnableNetbios' `
                        -Value $enableNetbios `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    # Remove the NetBIOS-related settings
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\System\CurrentControlSet\Services\NetBT\Parameters' `
                           -ValueName 'NodeType' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null

    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableNetbios' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

# Turn off Link-Local Multicast Name Resolution (LLMNR)
if ($configuration.CoreNetworking.DisableLLMNR -eq $true) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                        -ValueName 'EnableMulticast' `
                        -Value 0 `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
                           -ValueName 'EnableMulticast' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

# Turn off Multicast DNS (mDNS)
# Note: This is not a managed GPO setting.
if ($null -ne $configuration.CoreNetworking.DisableMDNS) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                        -ValueName 'EnableMDNS' `
                        -Value ([int](-not $configuration.CoreNetworking.DisableMDNS)) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                           -ValueName 'EnableMDNS' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

# Configure Print Spooler RPC over TCP static port
if ($null -ne $configuration.ServerRoles.PrintServer.StaticPort) {
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' `
                        -ValueName 'RpcTcpPort' `
                        -Value ([int] $configuration.ServerRoles.PrintServer.StaticPort) `
                        -Type DWord `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' `
                           -ValueName 'RpcTcpPort' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

# Configure Certification Authority (CA) static DCOM port
# Registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{D99E6E74-FC88-11D0-B498-00A0C90312F3}
# The CA service must be restarted for the changes to apply.
if ($null -ne $configuration.ServerRoles.CA.StaticPort) {
    [string] $caEndpoints = 'ncacn_ip_tcp,0,{0}' -f $configuration.ServerRoles.CA.StaticPort
    Set-GPRegistryValue -Guid $gpo.Id `
                        -Key 'HKLM\SOFTWARE\Classes\AppID\{D99E6E74-FC88-11D0-B498-00A0C90312F3}' `
                        -ValueName 'Endpoints' `
                        -Value $caEndpoints `
                        -Type MultiString `
                        -Domain $domain.DNSRoot `
                        -Server $targetDomainController `
                        -Verbose:$script:IsVerbose > $null
} else {
    Remove-GPRegistryValue -Guid $gpo.Id `
                           -Key 'HKLM\SOFTWARE\Classes\AppID\{D99E6E74-FC88-11D0-B498-00A0C90312F3}' `
                           -ValueName 'Endpoints' `
                           -Domain $domain.DNSRoot `
                           -Server $targetDomainController `
                           -ErrorAction SilentlyContinue `
                           -Verbose:$script:IsVerbose > $null
}

#endregion Registry Settings

#region Startup Script

# Fetch the GPO info from the PDC emulator
[Microsoft.ActiveDirectory.Management.ADObject] $gpoContainer = Get-ADObject -Identity $gpo.Path -Properties 'gPCFileSysPath','gPCMachineExtensionNames' -Server $targetDomainController

# Adjust the GPO SYSVOL path to use the PDC emulator instead of the DFS namespace
[string] $gpoFileSystemPath = $gpoContainer.gPCFileSysPath -replace "^\\$($domain.DNSRoot)\","\\$targetDomainController\"

[string] $startupScriptDirectory = Join-Path -Path $gpoFileSystemPath -ChildPath 'Machine\Scripts\Startup'
[string] $startupScriptPath = Join-Path -Path $startupScriptDirectory -ChildPath 'FirewallConfiguration.bat'
[string] $scriptsIniPath = Join-Path -Path $gpoFileSystemPath -ChildPath 'Machine\Scripts\scripts.ini'

# Create the directory for startup scripts if it does not exist
New-Item -Path $startupScriptDirectory -ItemType Directory -Force -Verbose:$script:IsVerbose > $null

# Startup script header
[System.Text.StringBuilder] $startupScript = [System.Text.StringBuilder]::new()
$startupScript.AppendLine('@ECHO OFF') > $null
$startupScript.AppendLine('REM This script is managed by the Set-WindowsFirewallPolicy.ps1 PowerShell script.') > $null

# Configure the WMI  protocol to use the deafult static port 24158
if ($configuration.RemoteManagement.WMI.StaticPort -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Move the WMI service to a standalone process listening on TCP port 24158 with authentication level set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY.') > $null
    $startupScript.AppendLine('winmgmt.exe /standalonehost 6') > $null
} elseif ($configuration.RemoteManagement.WMI.StaticPort -eq $false) {
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

if ($configuration.ServerRoles.FileServer.DfsrStaticPort -ge 1) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine($dfsrDiagInstallScript) > $null
    $startupScript.AppendLine('echo Set static RPC port for DFS Replication.') > $null
    $startupScript.AppendFormat('dfsrdiag.exe StaticRPC /Port:{0}', $configuration.ServerRoles.FileServer.DfsrStaticPort) > $null
    $startupScript.AppendLine() > $null
} elseif ($configuration.ServerRoles.FileServer.DfsrStaticPort -eq 0) {
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

if ($configuration.ServerRoles.FileServer.EnableRpcFilters -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Register the RPC filters.') > $null
    $startupScript.AppendFormat('netsh.exe -f "%~dp0{0}"', $rpcFilterScriptName) > $null
    $startupScript.AppendLine() > $null
} elseif ($null -ne $configuration.ServerRoles.FileServer.EnableRpcFilters) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Remove all RPC filters.') > $null
    $startupScript.AppendLine('netsh.exe rpc filter delete filter filterkey=all') > $null
}

# Fix the Network Policy Server (NPS) to work with Windows Firewall on Windows Server 2016 and Windows Server 2019.
# This is not required on Windows Server 2022.
if ($configuration.ServerRoles.RADIUS.Enabled -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Fix the NPS service to work with Windows Firewall on downlevel Windows Server versions.') > $null
    $startupScript.AppendLine('sc.exe sidtype IAS unrestricted') > $null
}

# Configure Certification Authority (CA) interface flags
# See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/b3ac7b46-8ea7-440d-a4c5-656bb1286d56
if ($null -ne $configuration.ServerRoles.CA.BlockRemoteManagement) {
    $startupScript.AppendLine() > $null
    if ($configuration.ServerRoles.CA.BlockRemoteManagement -eq $true) {
        $startupScript.AppendLine('echo Block remote ICertAdmin interface access on the Certification Authority.') > $null
        $startupScript.AppendLine('certutil.exe -setreg ca\interfaceflags +IF_NOREMOTEICERTADMIN') > $null
    } else {
        $startupScript.AppendLine('echo Allow remote ICertAdmin interface access on the Certification Authority.') > $null
        $startupScript.AppendLine('certutil.exe -setreg ca\interfaceflags -IF_NOREMOTEICERTADMIN') > $null
    }
}

if ($null -ne $configuration.ServerRoles.CA.BlockLegacyRpc) {
    $startupScript.AppendLine() > $null
    if ($configuration.ServerRoles.CA.BlockLegacyRpc -eq $true) {
        $startupScript.AppendLine('echo Block the legacy ICertPassage Remote Protocol (MS-ICPR) on the Certification Authority.') > $null
        $startupScript.AppendLine('certutil.exe -setreg ca\interfaceflags +IF_NORPCICERTREQUEST') > $null
    } else {
        $startupScript.AppendLine('echo Allow the legacy ICertPassage Remote Protocol (MS-ICPR) on the Certification Authority.') > $null
        $startupScript.AppendLine('certutil.exe -setreg ca\interfaceflags -IF_NORPCICERTREQUEST') > $null
    }
}

# Overwrite the script files
Set-Content -Path $startupScriptPath -Value $startupScript.ToString() -Encoding Ascii -Force -Verbose:$script:IsVerbose
Copy-Item -Path $rpcFilterScriptSourcePath -Destination $rpcFilterScriptTargetPath -Force -Confirm:$false -Verbose:$script:IsVerbose

# Register the startup script in the scripts.ini file
[string] $scriptsIni = @'
[Startup]
0CmdLine=FirewallConfiguration.bat
0Parameters=
'@

Set-Content -Path $scriptsIniPath -Value $scriptsIni -Encoding Ascii -Verbose:$script:IsVerbose -Force

# Register the Scripts client-side extension in AD if necessary
[string] $machineScriptsExtension = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'

if (-not $gpoContainer.gPCMachineExtensionNames.Contains($machineScriptsExtension)) {
    [string] $updatedMachineExtensionNames = $machineScriptsExtension + $gpoContainer.gPCMachineExtensionNames
    
    # The CSE GUIDs must be sorted in case-insensitive ascending order
    [string[]] $sortedExtensions =
        $updatedMachineExtensionNames.Split('[]') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($PSItem) } |
        Sort-Object -Culture ([cultureinfo]::InvariantCulture)
    $updatedMachineExtensionNames = '[' + ($sortedExtensions -join '][') + ']'

    # Update the GPO
    Set-ADObject -Identity $gpoContainer -Replace @{ gPCMachineExtensionNames = $updatedMachineExtensionNames } -Server $targetDomainController  -Verbose:$script:IsVerbose
}

#endregion Startup Script

#region Administrative Templates

# Resolve the paths to the ADMX files
[string] $policiesDirectory = Split-Path -Path $gpoFileSystemPath -Parent
[string] $admxTargetDirectory = Join-Path -Path $policiesDirectory -ChildPath 'PolicyDefinitions'
[string] $admxSourceDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'PolicyDefinitions'

# Check if the ADMX Central Store exists
if (Test-Path -Path $admxTargetDirectory -PathType Container) {
    # Copy the ADMX and ADML files to the Central Store
    Copy-Item -Path $admxSourceDirectory -Destination $policiesDirectory -Container -Recurse -Verbose:$script:IsVerbose -Force > $null
}
else {
    Write-Warning -Message 'The ADMX Central Store does not exist. ADMX files have not been copied.'
}
#endregion Administrative Templates
