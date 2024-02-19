[string] $sourceGpo = 'contoso.com\DC Firewall'

Get-NetFirewallRule -PolicyStore $sourceGpo | foreach {
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $PSItem
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $PSItem
    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $PSItem
    $serviceFilter = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $PSItem
    @'
| <!-- -->    | <!-- --> |
|-------------|----------|
| Name        | **{1}** |
| Group       | {2} |
| Protocol    | {8} |
| Port        | {9} |
| ICMP Type   | {11} |
| Program     | `{12}` |
| Service     | `{13}` |
| Description | {3} |
| Notes       | - |

'@ -f $PSItem.Name,
      $PSItem.DisplayName,
      $PSItem.DisplayGroup,
      $PSItem.Description,
      $PSItem.Enabled,
      $PSItem.Profile,
      $PSItem.Direction,
      $PSItem.Action,
      $portFilter.Protocol,
      $portFilter.LocalPort,
      $addressFilter.RemoteAddress,
      $portFilter.IcmpType,
      $appFilter.Program,
      $serviceFilter.ServiceName
} | Set-Clipboard
