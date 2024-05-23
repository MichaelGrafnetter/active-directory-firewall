[string] $sourceGpo = 'contoso.com\DC Firewall'

Get-NetFirewallRule -PolicyStore $sourceGpo | foreach {
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $PSItem
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $PSItem
    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $PSItem
    $serviceFilter = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $PSItem
    # Direction,Name,Group,Protocol,Port,IcmpType,Program,Service,RemoteAddress,Description
    @'
{6},"{1}","{2}",{8},{9},{11},"{12}",{13},{10},"{3}"
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
