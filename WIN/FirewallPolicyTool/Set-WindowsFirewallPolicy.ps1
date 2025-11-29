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

    # TODO: Wireless display (WiDi) rules?
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

    # Indicates whether remote event log management should be enabled.
    [bool]             $EnableEventLogManagement      = $false

    # Indicates whether remote scheduled task management should be enabled.
    [bool]             $EnableScheduledTaskManagement = $false

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

class ServerRoleSettings {
    # Firewall configuration for the File Server role.
    [FileServerSettings] $FileServer                     = [FileServerSettings]::new()

    # Firewall configuration for the Print Server role.
    [PrintServerSettings] $PrintServer                   = [PrintServerSettings]::new()

    # Firewall configuration for the DHCP Server role.
    [DhcpServerSettings] $DHCP                           = [DhcpServerSettings]::new()

    # Firewall configuration for the DNS Server role.
    [DnsServerSettings]  $DNS                            = [DnsServerSettings]::new()

    # Indicates whether inbound http.sys-based web server traffic on default HTTP and HTTPS ports should be allowed.
    [bool]               $EnableWebServer               = $false

    # Indicates whether inbound Network Policy Server (NPS) / RADIUS traffic should be allowed.
    [bool]               $EnableNPS                     = $false

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

    # Indicates whether inbound Active Directory Federation Services (ADFS) traffic should be allowed."
    [bool]               $EnableADFS                    = $false

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

    # TODO: AD LDS Role
    # TODO: CA Roles?
    # TODO: Failover Clustering Role?
    # TODO: Hyper-V Role
    # TODO: Host Guardian Service?
    # TODO: Remote Access Role (RRAS, VPN, DirectAccess)?
    # TODO: DHCP Relay Agent Role?
    # TODO: Legacy SNMP Service?

    <#
    .SYNOPSIS
    Validates the configuration of the server role-related firewall rules.
    #>
    [void] Validate() {
        if ($this.PrintServer.Enabled -and $this.FileServer.EnableRpcFilters) {
            Write-Warning -Message 'Older Windows versions used the SMB protocol to communicate with the Print Spooler service. RPC filters will block this traffic.'
        }
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
        [System.Collections.Generic.List[IPAddressSet]] $IPAddressSets,

        [Parameter(Mandatory = $false)]
        [switch] $IncludeDisabled
    )

    if (-not $Rule.Enabled -and -not $IncludeDisabled) {
        # Skip creating disabled rules unless explicitly requested
        return
    }

    [string[]] $remoteAddresses = Resolve-IPAddressSet -IPAddressSetName $CustomRule.RemoteAddressSet -IPAddressSets $IPAddressSets

    # Use parameter splatting to add optional parameters only if they have values
    [hashtable] $additionalParameters = @{}

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.Group)) {
        $additionalParameters['Group'] = $CustomRule.Group
    }

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.Description)) {
        $additionalParameters['Description'] = $CustomRule.Description
    }

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.Protocol)) {
        $additionalParameters['Protocol'] = $CustomRule.Protocol
    }

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.LocalPort)) {
        $additionalParameters['LocalPort'] = @($CustomRule.LocalPort)
    }

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.IcmpType)) {
        $additionalParameters['IcmpType'] = @($CustomRule.IcmpType)
    }

    if ($remoteAddresses.Count -gt 0) {
        $additionalParameters['RemoteAddress'] = $remoteAddresses
    }

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.Program)) {
        $additionalParameters['Program'] = $CustomRule.Program
    }

    if (-not [string]::IsNullOrWhiteSpace($CustomRule.Service)) {
        $additionalParameters['Service'] = $CustomRule.Service
    }

    New-NetFirewallRule `
        -GPOSession $GpoSession `
        -Name $CustomRule.Name `
        -DisplayName $CustomRule.DisplayName `
        -Enabled (ConvertTo-NetSecurityEnabled -Value $CustomRule.Enabled) `
        -Profile (ConvertTo-NetSecurityProfile -Profile $CustomRule.Profile) `
        -Action (ConvertTo-NetSecurityAction -Allow (-not $CustomRule.Block)) `
        -Direction Inbound `
        @additionalParameters `
        -Verbose:$script:IsVerbose > $null
}

<#
.SYNOPSIS
Resolves the specified IP address set names to their corresponding IP addresses.

.PARAMETER IpAddressSetNames
The names of the IP address sets to resolve.

.OUTPUTS
An array of resolved IP addresses.
#>
function Resolve-IPAddressSet {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]] $IPAddressSetName,

        [Parameter(Mandatory = $true, Position = 1)]
        [System.Collections.Generic.List[IPAddressSet]] $IPAddressSets
    )

    [System.Collections.Generic.List[string]] $resolvedAddresses = @()

    foreach ($setName in $IPAddressSetName) {
        [IPAddressSet] $addressSet = $IPAddressSets.Where({$PSItem.Name -eq $setName}, 'First')

        if ($null -eq $addressSet) {
            # Abort script execution if an unknown address set is referenced.
            throw [System.ArgumentException]::new(('The IP address set {0} could not be found in the configuration.' -f $setName), 'IPAddressSetName')
        }

        $resolvedAddresses.AddRange($addressSet.Addresses)
    }

    # Duplicates might exist across address sets
    [string[]] $uniqueAddresses = Sort-Object -InputObject $resolvedAddresses -Unique

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

#region Inbound Firewall Rules

# Load the configuration from the JSON file
[string] $configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath $ConfigurationFileName
[ScriptSettings] $configuration = Read-ScriptConfiguration -ConfigurationFilePath $configurationFilePath

# Build a collection of firewall rules to be created
[System.Collections.Generic.List[FirewallRule]] $firewallRules = @()
$firewallRules.AddRange($configuration.CustomRules)

# Create Inbound rule "RPC Endpoint Mapper (RPC-EPMAP, DCOM-In)", common for all RPC-based services

# TODO: Merge EPMAP addresses for this custom rule
[bool] $epmapEnabled = $true
[System.Collections.Generic.List[string]] $epmapAddressSets = @()
$epmapAddressSets.Add($PredefinedAddressSet_AllAddresses)

[WindowsFirewallRule] $epmapRule = @{
    Name         = 'RPCEPMAP-TCP-In'
    DisplayName  = 'RPC Endpoint Mapper (RPC-EPMAP, DCOM-In)'
    Description  = 'Inbound rule for the RPCSS service to allow RPC/TCP and DCOM traffic to the server.'
    Enabled      = $epmapEnabled
    Protocol     = 'TCP'
    LocalPort    = 'RPCEPMap'
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'rpcss'
    RemoteAddressSet = $epmapAddressSets
}

$firewallRules.Add($epmapRule)

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
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
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
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
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

# TODO: Rename to File and printer sharing - ICMPv4-In

# Create Inbound rule "Active Directory Domain Controller - Echo Request (ICMPv4-In)"
[WindowsFirewallRule] $pingV4Rule = @{
    Name         = 'ADDS-ICMP4-In'
    DisplayName  = 'Active Directory Domain Controller - Echo Request (ICMPv4-In)'
    Group        = 'Active Directory Domain Services'
    Description  = 'Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv4'
    IcmpType     = 8
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Reconsider the source addresses
}

$firewallRules.Add($pingV4Rule)

# Create Inbound rule "Active Directory Domain Controller - Echo Request (ICMPv6-In)"
[WindowsFirewallRule] $pingV6Rule = @{
    Name         = 'ADDS-ICMP6-In'
    DisplayName  = 'Active Directory Domain Controller - Echo Request (ICMPv6-In)'
    Group        = 'Active Directory Domain Services'
    Description  = 'Inbound rule for the Active Directory Domain Controller service to allow Echo requests (ping).'
    Enabled      = $configuration.CoreNetworking.EnableIcmp
    Protocol     = 'ICMPv6'
    IcmpType     = 128
    Program      = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Reconsider the source addresses
}

$firewallRules.Add($pingV6Rule)

# TODO: Rename to file and printer sharing - NB-Datagram-UDP-In

# Create Inbound rule "Active Directory Domain Controller - NetBIOS name resolution (UDP-In)"
[WindowsFirewallRule] $nbDatagramRule = @{
    Name         = 'ADDS-NB-Datagram-UDP-In'
    DisplayName  = 'Active Directory Domain Controller - NetBIOS name resolution (UDP-In)'
    Group        = 'Active Directory Domain Services'
    Description  = 'Inbound rule for the Active Directory Domain Controller service to allow NetBIOS name resolution. [UDP 138]'
    Enabled      = $configuration.CoreNetworking.EnableNetbiosDatagramService
    Protocol     = 'UDP'
    LocalPort    = 138
    Program      = 'System'
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
}

$firewallRules.Add($nbDatagramRule)

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
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
}

$firewallRules.Add($nbNameRule)

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
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet
}

$firewallRules.Add($nbSessionRule)

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
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
}

$firewallRules.Add($icmp6DuRule)

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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
}

$firewallRules.Add($icmp4DuFragRule)

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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
}

$firewallRules.Add($icmp6TeRule)

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

# Create Inbound rule "DHCP Server v4 (UDP-In)"
[WindowsFirewallRule] $dhcpServerV4Rule = @{
    Name         = 'Microsoft-Windows-DHCP-ClientSvc-DHCPv4-In'
    DisplayName  = 'DHCP Server v4 (UDP-In)'
    Group        = 'DHCP Server'
    Description  = 'An inbound rule to allow traffic to the IPv4 Dynamic Host Control Protocol Server. [UDP 67]'
    Enabled      = $configuration.ServerRoles.DHCP.Enabled
    Protocol     = 'UDP'
    LocalPort    = 67
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'dhcpserver'
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
}

$firewallRules.Add($dhcpServerV4Rule)

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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    Enabled      = $configuration.ServerRoles.EnableNps
    Protocol     = 'UDP'
    LocalPort    = 1645
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses # TODO: Create the $configuration.ServerRoles.RadiusClients variable
}

$firewallRules.Add($npsLegacyAuthRule)

# Create Inbound rule "Network Policy Server (Legacy RADIUS Accounting - UDP-In)"
[WindowsFirewallRule] $npsLegacyAccountingRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1646'
    DisplayName  = 'Network Policy Server (Legacy RADIUS Accounting - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1646]'
    Enabled      = $configuration.ServerRoles.EnableNps
    Protocol     = 'UDP'
    LocalPort    = 1646
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses # TODO: Create the $configuration.ServerRoles.RadiusClients variable
}

$firewallRules.Add($npsLegacyAccountingRule)

# Create Inbound rule "Network Policy Server (RADIUS Authentication - UDP-In)"
[WindowsFirewallRule] $npsRadiusAuthRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1812'
    DisplayName  = 'Network Policy Server (RADIUS Authentication - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Authentication requests. [UDP 1812]'
    Enabled      = $configuration.ServerRoles.EnableNps
    Protocol     = 'UDP'
    LocalPort    = 1812
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses # TODO: Create the $configuration.ServerRoles.RadiusClients variable
}

$firewallRules.Add($npsRadiusAuthRule)

# Create Inbound rule "Network Policy Server (RADIUS Accounting - UDP-In)"
[WindowsFirewallRule] $npsRadiusAccountingRule = @{
    Name         = 'NPS-NPSSvc-In-UDP-1813'
    DisplayName  = 'Network Policy Server (RADIUS Accounting - UDP-In)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule to allow Network Policy Server to receive RADIUS Accounting requests. [UDP 1813]'
    Enabled      = $configuration.ServerRoles.EnableNps
    Protocol     = 'UDP'
    LocalPort    = 1813
    Program      = '%systemroot%\system32\svchost.exe'
    Service      = 'ias'
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses # TODO: Create the $configuration.ServerRoles.RadiusClients variable
}

$firewallRules.Add($npsRadiusAccountingRule)

# Create Inbound rule "Network Policy Server (RPC)"
[WindowsFirewallRule] $npsManagementRule = @{
    Name         = 'NPS-NPSSvc-In-RPC'
    DisplayName  = 'Network Policy Server (RPC)'
    Group        = 'Network Policy Server'
    Description  = 'Inbound rule for the Network Policy Server to be remotely managed via RPC/TCP.'
    Enabled      = $configuration.ServerRoles.EnableNps
    Protocol     = 'TCP'
    LocalPort    = 'RPC'
    Program      = '%systemroot%\system32\iashost.exe'
    RemoteAddressSet = $configuration.RemoteManagement.ManagementAddressSet
}

$firewallRules.Add($npsManagementRule)

# Create Inbound rule "World Wide Web Services (HTTP Traffic-In)"
[WindowsFirewallRule] $iisHttpRule = @{
    Name          = 'IIS-WebServerRole-HTTP-In-TCP'
    DisplayName   = 'World Wide Web Services (HTTP Traffic-In)'
    Group         = 'World Wide Web Services (HTTP)'
    Description   = 'An inbound rule to allow HTTP traffic for Internet Information Services (IIS) [TCP 80]'
    Enabled       = $configuration.ServerRoles.EnableWebServer # TODO: Differentiate between HTTP and HTTPS
    Protocol      = 'TCP'
    LocalPort     = 80
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Add optional override
}

$firewallRules.Add($iisHttpRule)

# Create Inbound rule "World Wide Web Services (HTTPS Traffic-In)"
[WindowsFirewallRule] $iisHttpsRule = @{
    Name          = 'IIS-WebServerRole-HTTPS-In-TCP'
    DisplayName   = 'World Wide Web Services (HTTPS Traffic-In)'
    Group         = 'Secure World Wide Web Services (HTTPS)'
    Description   = 'An inbound rule to allow HTTPS traffic for Internet Information Services (IIS) [TCP 443]'
    Enabled       = $configuration.ServerRoles.EnableWebServer # TODO: Differentiate between HTTP and HTTPS
    Protocol      = 'TCP'
    LocalPort     = 443
    Program       = 'System'
    RemoteAddressSet = $configuration.ServerRoles.ClientAddressSet # TODO: Add optional override
}

$firewallRules.Add($iisHttpsRule)

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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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
    RemoteAddressSet = $PredefinedAddressSet_AllAddresses
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

# Create Inbound rule "DHCP Client (UDP-In)"
[WindowsFirewallRule] $dhcpClientV4Rule = @{
    Name          = 'CoreNet-DHCP-In'
    DisplayName   = 'DHCP Client (UDP-In)'
    Group         = 'Core Networking'
    Description   = 'Allows DHCP (Dynamic Host Configuration Protocol) messages for stateful auto-configuration.'
    Enabled       = $configuration.CoreNetworking.EnableDhcpClient
    Protocol      = 'UDP'
    LocalPort     = 68
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'dhcp'
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
}

$firewallRules.Add($dhcpClientV4Rule)

# Create Inbound rule "DHCP Client v6 (UDP-In)"
[WindowsFirewallRule] $dhcpClientV6Rule = @{
    Name          = 'CoreNet-DHCPv6-In'
    DisplayName   = 'DHCP Client v6 (UDP-In)'
    Group         = 'Core Networking'
    Description   = 'Allows DHCPv6 (Dynamic Host Configuration Protocol for IPv6) messages for stateful and stateless configuration.'
    Enabled       = $configuration.CoreNetworking.EnableDhcpClient
    Protocol      = 'UDP'
    LocalPort     = 546
    Program       = '%SystemRoot%\system32\svchost.exe'
    Service       = 'dhcp'
    RemoteAddressSet = @($PredefinedAddressSet_AllAddresses)
}

$firewallRules.Add($dhcpClientV6Rule)

# TODO: Add File and Printer Sharing (Restrictive) (Spooler Service Worker - RPC)

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

# Validate the built-in and custom firewall rules
foreach ($rule in $firewallRules) {
    $rule.Validate()
}

#endregion Inbound Firewall Rules

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
$startupScript.AppendLine('REM This script is managed by the Set-ADDSFirewallPolicy.ps1 PowerShell script.') > $null

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
if ($configuration.ServerRoles.EnableNPS -eq $true) {
    $startupScript.AppendLine() > $null
    $startupScript.AppendLine('echo Fix the NPS service to work with Windows Firewall on downlevel Windows Server versions.') > $null
    $startupScript.AppendLine('sc.exe sidtype IAS unrestricted') > $null
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
