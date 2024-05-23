[string] $sourceGpo = 'contoso.com\DC Firewall'

Get-NetFirewallRule -PolicyStore $sourceGpo | foreach {
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $PSItem
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $PSItem
    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $PSItem
    $serviceFilter = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $PSItem
    @'
# Create {6} rule "{1}"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{0}' `
                    -DisplayName '{1}' `
                    -Group '{2}' `
                    -Description '{3}' `
                    -Enabled {4} `
                    -Profile {5} `
                    -Direction {6} `
                    -Action {7} `
                    -Protocol {8} `
                    -LocalPort {9} `
                    -IcmpType {11} `
                    -RemoteAddress {10} `
                    -Program '{12}' `
                    -Service '{13}'

'@ -f $PSItem.Name,
      $PSItem.DisplayName,
      $PSItem.Group,
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
