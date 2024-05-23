[string[]] $adminTools = @(
    'ServerManager.exe',
    'Dcdiag.exe',
    'Ntdsutil.exe',
    'Dfsrdiag.exe',
    'Nltest.exe',
    'Ldifde.exe',
    'Csvde.exe',
    'Dcpromo.exe',
    'Dsacls.exe',
    'Dsquery.exe',
    'Dsget.exe',
	'Dsadd.exe',
    'Dsmod.exe',
    'Dsmove.exe',
    'Dsrm.exe',
	'Dsamain.exe',
    'Ldp.exe',
    'Netdom.exe',
	'Net.exe',
    'Redircmp.exe',
    'Redirusr.exe',
    'Certutil.exe',
    'Certreq.exe'
)

foreach($tool in $adminTools) {
    [string] $programPath = '%SystemRoot%\system32\{0}' -f $tool.ToLowerInvariant()
    [string] $toolName = $tool -replace '.exe'
    [string] $ruleName = 'AdminTools-{0}-TCP-Out' -f $toolName
    [string] $displayName = 'Administrative Tools - {0} (TCP-Out)' -f $toolName
    [string] $description = 'Outbound rule to allow AD management using the {0} tool.' -f $toolName
    [string] $template = @'
# Create Outbound rule "{0}"
New-NetFirewallRule -GPOSession $gpoSession `
                    -Name '{1}' `
                    -DisplayName '{0}' `
                    -Description '{2}' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol TCP `
                    -RemotePort Any `
                    -RemoteAddress Any `
                    -Program '{3}' `
                    -Verbose `
                    -ErrorAction Stop | Out-Null

'@
    $template -f $displayName, $ruleName, $description, $programPath
}

