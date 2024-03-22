Arc/Windows Admin Center Outbound?
SmeOutboundOpenException from any process to 20.66.2.1,20.62.128.152,20.187.196.201,20.191.160.120,52.146.131.56,20.61.98.73

# TODO: DNS over HTTPS (DoH) must be disabled for dynamic keywords to work
<#
Work or school account:
Package : S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272
Name                          : {11EE8354-1B68-472A-88CD-ED9082BF2424}
DisplayName                   : Work or school account
Description                   : Work or school account
DisplayGroup                  : Work or school account
Group                         : @{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}
Enabled                       : True
#>

# TODO: Azure VM token (Managed Identity, Arc, Automation): "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01" -Headers @{Metadata = "true"} -NoProxy -TimeoutSec 1 -ErrorAction 

<#
Arc: PowerShell scripts, config tool,...
<add key="ArcAgentExecutable" value="azcmagent.exe" />
<add key="DefaultArcTelemetryEndpoint" value="https://gbl.his.arc.azure.com/log" />
 $hisEndpoint = "https://gbl.his.arc.azure.com"
    if ($Show.cloud -eq "AzureUSGovernment") {
        $hisEndpoint = "https://gbl.his.arc.azure.us"
    } elseif ($Show.cloud -eq "AzureChinaCloud") {
        $hisEndpoint = "https://gbl.his.arc.azure.cn"

#>

https://*.smartscreen.microsoft.com URLs are used by Windows Defender Antivirus Network Inspection Service (NisSrv.exe), Windows Defender SmartScreen (smartscreen.exe), and Windows Defender Exploit Guard Network Protection (wdnsfltr.exe).

$fqdn = 'contoso.com'
$id = '{' + (new-guid).ToString() + '}'
New-NetFirewallDynamicKeywordAddress -id $id -Keyword $fqdn -AutoResolve $true
New-NetFirewallRule -DisplayName "allow $fqdn" -Action Allow -Direction Outbound -RemoteDynamicKeywordAddresses $id

$domains = @(
    '*.microsoft.com',
    '*.msftconnecttest.com',
    'assets.msn.com',
    'client.wns.windows.com',
    'config.edge.skype.com',
    'ctldl.windowsupdate.com',
    'dns.msftncsi.com',
    'login.live.com',
    'ntp.msn.com'
)

foreach ($domain in $domains) {
    $id = '{' + (New-Guid).ToString() + '}'
    New-NetFirewallDynamicKeywordAddress -Id $id -Keyword $domain -AutoResolve $true
    New-NetFirewallRule -DisplayName "allow $domain" -Action Allow -Direction Outbound -RemoteDynamicKeywordAddresses $id
}



winrs.exe
powershell.exe
powershell_ise.exe
sc.exe
schtasks.exe
rendom
gpfixup
dnscmd
djoin
dfsutil
dfsrmig
at.exe

# Windows Commands: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands


# TODO: Split services into separate processes

TODO: Enrollment Policy Web Service

	# NisSrv.exe is active when "Network protection" is enabled
	$Program = "$WindowsDefenderRoot\NisSrv.exe"
	if ((Test-ExecutableFile $Program) -or $ForceLoad)
	{
		New-NetFirewallRule -DisplayName "Microsoft Network Realtime Inspection Service" `
			-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
			-Service WdNisSvc -Program $Program -Group $Group `
			-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
			-LocalAddress Any -RemoteAddress Internet4 `
			-LocalPort Any -RemotePort 80, 443 `
			-LocalUser Any `
			-InterfaceType $DefaultInterface `
			-Description "Helps guard against intrusion attempts targeting known and newly
discovered vulnerabilities in network protocols" |
		Format-RuleOutput
	}

    $Program = "%SystemRoot%\System32\MRT.exe"
    if ((Test-ExecutableFile $Program) -or $ForceLoad)
    {
        New-NetFirewallRule -DisplayName "Malicious Software Removal Tool" `
            -Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
            -Service Any -Program $Program -Group $Group `
            -Enabled True -Action Allow -Direction $Direction -Protocol TCP `
            -LocalAddress Any -RemoteAddress Internet4 `
            -LocalPort Any -RemotePort 443 `
            -LocalUser $LocalSystem `
            -InterfaceType $DefaultInterface `
            -Description "" |
        Format-RuleOutput
    }

    $Program = "%SystemRoot%\System32\slui.exe"
    if ((Test-ExecutableFile $Program) -or $ForceLoad)
    {
        New-NetFirewallRule -DisplayName "Activation Client" `
            -Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
            -Service Any -Program $Program -Group $Group `
            -Enabled True -Action Allow -Direction $Direction -Protocol TCP `
            -LocalAddress Any -RemoteAddress Internet4 `
            -LocalPort Any -RemotePort 80, 443 `
            -LocalUser Any `
            -InterfaceType $DefaultInterface `
            -Description "Used to activate Windows." |
        Format-RuleOutput
    }
    

    $Program = "%SystemRoot%\System32\BackgroundTransferHost.exe"
if ((Test-ExecutableFile $Program) -or $ForceLoad)
{
	New-NetFirewallRule -DisplayName "Background transfer host" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 443 `
		-LocalUser $UsersGroupSDDL `
		-InterfaceType $DefaultInterface `
		-Description "Download/Upload Host" |
	Format-RuleOutput
}

$Program = "%SystemRoot%\System32\WerFault.exe"
if ((Test-ExecutableFile $Program) -or $ForceLoad)
{
	New-NetFirewallRule -DisplayName "Error Reporting" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 443 `
		-LocalUser $UsersGroupSDDL `
		-InterfaceType $DefaultInterface `
		-Description "Report Windows errors back to Microsoft." |
	Format-RuleOutput
}

$Program = "%SystemRoot%\System32\wermgr.exe"
if ((Test-ExecutableFile $Program) -or $ForceLoad)
{
	New-NetFirewallRule -DisplayName "Error Reporting" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 443 `
		-LocalUser Any `
		-InterfaceType $DefaultInterface `
		-Description "Report Windows errors back to Microsoft." |
	Format-RuleOutput
}

$Program = "%SystemRoot%\explorer.exe"
if ((Test-ExecutableFile $Program) -or $ForceLoad)
{
	# TODO: remote to local subnet seen for shared folder access
	# TODO: Action is temporarily block to learn LocalUser value
	New-NetFirewallRule -DisplayName "File Explorer" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Block -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 80 `
		-LocalUser Any `
		-InterfaceType $DefaultInterface `
		-Description "File explorer checks for digital signatures verification, windows update." |
	Format-RuleOutput

	New-NetFirewallRule -DisplayName "File Explorer" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 443 `
		-LocalUser $UsersGroupSDDL `
		-InterfaceType $DefaultInterface `
		-Description "Smart Screen Filter" |
	Format-RuleOutput
}


$Program = "%SystemRoot%\System32\smartscreen.exe"
if ((Test-ExecutableFile $Program) -or $ForceLoad)
{
	$SmartScreenUsers = $UsersGroupSDDL
	Merge-SDDL ([ref] $SmartScreenUsers) -From $AdminGroupSDDL -Unique

	New-NetFirewallRule -DisplayName "Smartscreen" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 80, 443 `
		-LocalUser $SmartScreenUsers `
		-InterfaceType $DefaultInterface `
		-Description "Checks downloaded files, webpages and it analyzes pages and determines if
they might be suspicious" |
	Format-RuleOutput
}

$Program = "%SystemRoot%\System32\sihclient.exe"
if ((Test-ExecutableFile $Program) -or $ForceLoad)
{
	New-NetFirewallRule -DisplayName "Service Initiated Healing" `
		-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
		-Service Any -Program $Program -Group $Group `
		-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
		-LocalAddress Any -RemoteAddress Internet4 `
		-LocalPort Any -RemotePort 443 `
		-LocalUser Any `
		-InterfaceType $DefaultInterface `
		-Description "sihclient.exe SIH Client is the client for fixing system components that are
important for automatic Windows updates.
This daily task runs the SIHC client (initiated by the healing server) to detect and
repair system components that are vital to
automatically update Windows and the Microsoft software installed on the computer.
The task can go online, assess the usefulness of the healing effect,
download the necessary equipment to perform the action, and perform therapeutic actions.)" |
	Format-RuleOutput
}


# Accounts needed for Microsoft Edge WebView2 Runtime
$WebViewAccounts = Get-SDDL -Domain "APPLICATION PACKAGE AUTHORITY" -User "ALL APPLICATION PACKAGES"
Merge-SDDL ([ref] $WebViewAccounts) -From $UsersGroupSDDL

# TODO: It seems this executable won't be found on fresh system if MS Edge is not updated?
$EdgeWebView = "%ProgramFiles(x86)%\Microsoft\EdgeWebView\Application\97.0.1072.76"
if ((Confirm-Installation "EdgeWebView" ([ref] $EdgeWebView)) -or $ForceLoad)
{
	$Program = "$EdgeWebView\msedgewebview2.exe"
	if ((Test-ExecutableFile $Program) -or $ForceLoad)
	{
		New-NetFirewallRule -DisplayName "Microsoft Edge WebView2 Runtime" `
			-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
			-Service Any -Program $Program -Group $Group `
			-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
			-LocalAddress Any -RemoteAddress Internet4 `
			-LocalPort Any -RemotePort 443 `
			-LocalUser $WebViewAccounts `
			-InterfaceType $DefaultInterface `
			-Description "Enables embedded web content (HTML, CSS, and JavaScript) in native applications" |
		Format-RuleOutput
	}
}

New-NetFirewallRule -DisplayName "Windows Modules Installer" `
	-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
	-Service TrustedInstaller -Program $ServiceHost -Group $Group `
	-Enabled True -Action Block -Direction $Direction -Protocol TCP `
	-LocalAddress Any -RemoteAddress Internet4 `
	-LocalPort Any -RemotePort 443 `
	-LocalUser Any `
	-InterfaceType $DefaultInterface `
	-Description "Enables installation, modification, and removal of Windows updates and optional
components.
If this service is disabled, install or uninstall of Windows updates might fail for this computer." |
Format-RuleOutput

#
# The following rules are in "ProblematicTraffic" pseudo group, these need extension rules (above)
#

New-NetFirewallRule -DisplayName "Background Intelligent Transfer Service" `
	-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
	-Service BITS -Program $ServiceHost -Group $Group `
	-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
	-LocalAddress Any -RemoteAddress Internet4 `
	-LocalPort Any -RemotePort 80, 443 `
	-LocalUser Any `
	-InterfaceType $DefaultInterface `
	-Description "Used for background update,
note that BITS is used by many third-party tools to download their own updates like AcrobatReader.
Transfers files in the background using idle network bandwidth. If the service is disabled,
then any applications that depend on BITS, such as Windows Update or MSN Explorer,
will be unable to automatically download programs and other information." |
Format-RuleOutput

# BITS to Router info: https://docs.microsoft.com/en-us/windows/win32/bits/network-bandwidth
# NOTE: Port was 48300, but other random ports can be used too
# TODO: BITS can't connect to router according to administrative event log
New-NetFirewallRule -DisplayName "Router capability check (BITS)" `
	-Platform $Platform -PolicyStore $PolicyStore -Profile $DefaultProfile `
	-Service BITS -Program $ServiceHost -Group $Group `
	-Enabled True -Action Allow -Direction $Direction -Protocol TCP `
	-LocalAddress Any -RemoteAddress DefaultGateway4 `
	-LocalPort Any -RemotePort Any `
	-LocalUser Any `
	-InterfaceType $DefaultInterface `
	-Description "BITS (Background Intelligent Transfer Service) monitors the network traffic
at the Internet gateway device (IGD) or the client's network interface card (NIC) and uses only the
idle portion of the network bandwidth.
If BITS uses the network interface card to measure traffic and there are no network applications
running on the client, BITS will consume most of the available bandwidth.
This can be an issue if the client has a fast network adapter but the full internet connection is
through a slow link (like a DSL router) because BITS will compete for the full bandwidth instead
of using only the available bandwidth on the slow link;
To use a gateway device, the device must support byte counters
(the device must respond to the GetTotalBytesSent and GetTotalBytesReceived actions)
and Universal Plug and Play (UPnP) must be enabled." |
Format-RuleOutput
