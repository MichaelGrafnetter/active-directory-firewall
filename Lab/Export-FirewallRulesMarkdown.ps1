[string] $sourceGpo = 'contoso.com\Domain Controller Firewall'

[Microsoft.ActiveDirectory.Management.ADDomain] $domain = Get-ADDomain -Current LoggedOnUser -ErrorAction Stop
[string] $gpoSession = Open-NetGPO -PolicyStore $sourceGpo -DomainController $domain.PDCEmulator -ErrorAction Stop

# The source GPO session is provided as a custom CIM operation option.
[Microsoft.Management.Infrastructure.Options.CimOperationOptions] $cimOperationOptions =
    [Microsoft.Management.Infrastructure.Options.CimOperationOptions]::new()
$cimOperationOptions.SetCustomOption('GPOSession', $gpoSession, $false)

# Open a temporary local CIM session
[CimSession] $localSession = New-CimSession -ErrorAction Stop

# Fetch all firewall rules from the GPO
[ciminstance[]] $gpoFirewallRules = $localSession.EnumerateInstances('ROOT\StandardCimv2','MSFT_NetFirewallRule', $cimOperationOptions) |
    Sort-Object -Property Direction, DisplayName

foreach ($rule in $gpoFirewallRules) {
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -GPOSession $gpoSession
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -GPOSession $gpoSession
    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -GPOSession $gpoSession
    $serviceFilter = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -GPOSession $gpoSession

    $ruleInfo = [System.Text.StringBuilder]::new()
    $ruleInfo.AppendFormat('#### {0}', $rule.DisplayName) | Out-Null
    $ruleInfo.AppendLine() | Out-Null
    $ruleInfo.AppendLine() | Out-Null
    $ruleInfo.AppendLine('| Property    | Value |') | Out-Null
    $ruleInfo.AppendLine('|-------------|---------------------------------------------------|') | Out-Null
    $ruleInfo.AppendFormat('| Name        | {0} |', $rule.Name) | Out-Null
    $ruleInfo.AppendLine() | Out-Null

    if($null -ne $rule.DisplayGroup)
    {
        $ruleInfo.AppendFormat('| Group       | {0} |', $rule.DisplayGroup) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }
    
    $ruleInfo.AppendFormat('| Direction   | {0} |', $rule.Direction) | Out-Null
    $ruleInfo.AppendLine() | Out-Null
    $ruleInfo.AppendFormat('| Protocol    | {0} |', $portFilter.Protocol) | Out-Null
    $ruleInfo.AppendLine() | Out-Null

    if($portFilter.Protocol -like 'ICMP*')
    {
        $ruleInfo.AppendFormat('| ICMP Type   | {0} |', $portFilter.IcmpType) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }
    elseif($portFilter.Protocol -eq 'TCP' -and $rule.Direction -eq 'Inbound') {
        [string] $port = $portFilter.LocalPort
        if($port -eq 'EPCEPMap')
        {
            $port = '135'
        }
        $ruleInfo.AppendFormat('| Port        | {0} |', $port) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }
    elseif($portFilter.Protocol -eq 'UDP' -and $rule.Direction -eq 'Inbound') {
        $ruleInfo.AppendFormat('| Port        | {0} |', $portFilter.LocalPort) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }
    elseif($portFilter.Protocol -eq 'TCP' -and $rule.Direction -eq 'Outbound') {
        $ruleInfo.AppendFormat('| Port        | {0} |', $portFilter.RemotePort) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }
    elseif($portFilter.Protocol -eq 'UDP' -and $rule.Direction -eq 'Outbound') {
        $ruleInfo.AppendFormat('| Port        | {0} |', $portFilter.RemotePort) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }
    
    $ruleInfo.AppendFormat('| Program     | `{0}` |', $appFilter.Program) | Out-Null
    $ruleInfo.AppendLine() | Out-Null

    if($null -ne $serviceFilter.ServiceName) {
        $ruleInfo.AppendFormat('| Service     | `{0}` |', $serviceFilter.ServiceName) | Out-Null
        $ruleInfo.AppendLine() | Out-Null
    }

    $ruleInfo.AppendFormat('| Description | {0} |', $rule.Description) | Out-Null
    $ruleInfo.AppendLine() | Out-Null
    $ruleInfo.AppendLine('| Notes       | - |') | Out-Null

    $ruleInfo.ToString()
}

# Close the temporary local CIM session
Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue
