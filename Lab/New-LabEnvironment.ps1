<#
.SYNOPSIS
Creates a Hyper-V based lab environment for DC firewall tests using AutomatedLab.

.DESCRIPTION
The Hyper-V role should already be installed on the host OS.

Windows 11 and Windows Server 2022 installation media need to be placed into the ISOs subdirectory of the lab sources directory.

TODO: NPS Configuration on ROOT-SRV

TODO: Internet Connectivity
TODO: RSAT on ROOT-PC1 and ROOT-PC2 (Requires Internet)
TODO: Kali Linux on ROOT-PC2 (Requires Internet)

.NOTES
Author:  Michael Grafnetter
Version: 1.0

#>

#Requires -Modules Hyper-V
#Requires -RunAsAdministrator
#Requires -Version 5

# Install AutomatedLab
$labSources = 'E:\LabSources'
$vmPath = 'E:\LabVMs'
$labAdmin = 'Admin'
$adminPassword = 'Pa$$w0rd'
msiexec.exe /i 'https://github.com/AutomatedLab/AutomatedLab/releases/download/5.50.9/AutomatedLab.msi' /qb "LABSOURCESDIR=$labSources"
Enable-LabHostRemoting -Force
gpupdate | Out-Null

# Create lab VMs and install AD
New-LabDefinition -Name DCFW -DefaultVirtualizationEngine HyperV -VmPath $vmPath

Add-LabVirtualNetworkDefinition -Name ContosoDC     -AddressSpace 10.220.1.0/24
Add-LabVirtualNetworkDefinition -Name ContosoServer -AddressSpace 10.220.2.0/24
Add-LabVirtualNetworkDefinition -Name ContosoManage -AddressSpace 10.220.3.0/24
Add-LabVirtualNetworkDefinition -Name ContosoClient -AddressSpace 10.220.4.0/24
Add-LabVirtualNetworkDefinition -Name CorpDC        -AddressSpace 10.220.5.0/24
Add-LabVirtualNetworkDefinition -Name FabrikamDC    -AddressSpace 10.220.6.0/24

Add-LabDomainDefinition -Name 'contoso.com' -AdminUser $labAdmin -AdminPassword $adminPassword
Add-LabDomainDefinition -Name 'corp.contoso.com' -AdminUser $labAdmin -AdminPassword $adminPassword
Add-LabDomainDefinition -Name 'fabrikam.com' -AdminUser $labAdmin -AdminPassword $adminPassword
Set-LabInstallationCredential -Username $labAdmin -Password $adminPassword

$PSDefaultParameterValues = @{ 
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Standard (Desktop Experience)'
    'Add-LabMachineDefinition:Memory' = 2GB
    'Add-LabMachineDefinition:MinMemory' = 1GB
    'Add-LabMachineDefinition:MaxMemory' = 4GB
}

Add-LabMachineDefinition -Name ROOT-DC1    -Network ContosoDC     -Gateway '10.220.1.1' -DomainName 'contoso.com'      -Roles RootDC
Add-LabMachineDefinition -Name ROOT-DC2    -Network ContosoDC     -Gateway '10.220.1.1' -DomainName 'contoso.com'      -Roles DC
Add-LabMachineDefinition -Name ROOT-PC1    -Network ContosoManage -Gateway '10.220.3.1' -DomainName 'contoso.com'      -OperatingSystem 'Windows 11 Enterprise'
Add-LabMachineDefinition -Name ROOT-PC2    -Network ContosoClient -Gateway '10.220.4.1' -DomainName 'contoso.com'      -OperatingSystem 'Windows 11 Enterprise' -Memory 3GB
Add-LabMachineDefinition -Name ROOT-SRV    -Network ContosoServer -Gateway '10.220.2.1' -DomainName 'contoso.com'      -Roles FileServer -Memory 3GB
Add-LabMachineDefinition -Name CORP-DC     -Network CorpDC        -Gateway '10.220.5.1' -DomainName 'corp.contoso.com' -Roles FirstChildDC
Add-LabMachineDefinition -Name FABRIKAM-DC -Network FabrikamDC    -Gateway '10.220.6.1' -DomainName 'fabrikam.com'     -Roles RootDC

Install-Lab

# Perform additional VM configuration.
Invoke-LabCommand -ActivityName 'Create AD Objects' -ComputerName ROOT-DC1 -ScriptBlock {
    New-ADOrganizationalUnit -Name Servers
    New-ADOrganizationalUnit -Name CA -Path 'OU=Servers,DC=contoso,DC=com'
    New-ADOrganizationalUnit -Name Federation -Path 'OU=Servers,DC=contoso,DC=com'
    New-ADOrganizationalUnit -Name File -Path 'OU=Servers,DC=contoso,DC=com'
    New-ADOrganizationalUnit -Name Web -Path 'OU=Servers,DC=contoso,DC=com'
    New-ADOrganizationalUnit -Name Database -Path 'OU=Servers,DC=contoso,DC=com'

    New-ADOrganizationalUnit -Name Employees

    New-ADUser -Name bfu `
                -UserPrincipalName 'bfu@contoso.com' `
                -SamAccountName bfu `
                -Enabled $true `
                -AccountPassword (ConvertTo-SecureString -String 'Pa$$w0rd' -AsPlainText -Force) `
                -Path 'OU=Employees,DC=contoso,DC=com'

    New-ADUser -Name john `
                -UserPrincipalName 'john@contoso.com' `
                -SamAccountName john `
                -Enabled $true `
                -AccountPassword (ConvertTo-SecureString -String 'Pa$$w0rd' -AsPlainText -Force) `
                -Path 'OU=Employees,DC=contoso,DC=com'
}

Invoke-LabCommand -ActivityName 'Enable RDP for Everyone on Members' -ComputerName ROOT-SRV,ROOT-PC1,ROOT-PC2 -ScriptBlock {
    Add-LocalGroupMember -Name 'Remote Desktop Users' -Member 'Authenticated Users' -ErrorAction SilentlyContinue
}
                
Invoke-LabCommand -ActivityName 'Enable RDP for Everyone on DCs' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    Add-ADGroupMember -Identity 'Remote Desktop Users' -Members 'Domain Users' -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure Windows Update' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Configure Windows Update'
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null

    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'NoAutoUpdate' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'UseWUServer' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'WUServer' -Value 'https://update.contoso.com:8531' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'WUStatusServer' -Value 'https://update.contoso.com:8531' -Type String

    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Enable Certificate Auto-Enrollment' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Certificate Auto-Enrollment'
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Value 7 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Value 7 -Type DWord
    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure Server Manager' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Configure Server Manager'
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager' -ValueName 'DoNotPopWACConsoleAtSMLaunch' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager' -ValueName 'DoNotOpenAtLogon' -Value 1 -Type DWord
    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Disable Microsoft Defender' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Disable Microsoft Defender'
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null
            
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'DisableAntiSpyware' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableRealtimeMonitoring' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SubmitSamplesConsent' -Value 2 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SpynetReporting' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen' -ValueName 'ConfigureAppInstallControlEnabled' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen' -ValueName 'ConfigureAppInstallControl' -Value 'Anywhere' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'EnableSmartScreen' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter' -ValueName 'EnabledV9' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -ValueName 'EnabledV9' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'SmartScreenEnabled' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'SmartScreenPuaEnabled' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Microsoft\Windows Defender\Features' -ValueName 'TamperProtection' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy' -ValueName 'VerifiedAndReputablePolicyState' -Value 0 -Type DWord
            
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName 'Exclusions_Paths' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName 'C:\Demo' -Value '0' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName 'C:\Demos' -Value '0' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName 'C:\Install' -Value '0' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName 'C:\Tools' -Value '0' -Type String
            
    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure RDP' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Configure RDP'
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\System\CurrentControlSet\Control\Lsa' -ValueName 'DisableRestrictedAdmin' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\System\CurrentControlSet\Control\Terminal Server' -ValueName 'fDenyTSConnections' -Value 0 -Type DWord
    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure Windows UI' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Configure Windows UI'
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat' -ValueName 'ChatIcon' -Value 3 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Dsh' -ValueName 'AllowNewsAndInterests' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueName 'AllowOnlineTips' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ValueName 'TaskbarMn' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ValueName 'TaskbarDa' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ValueName 'ShowTaskViewButton' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -ValueName 'SearchboxTaskbarMode' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' -ValueName 'DisableSearchBoxSuggestions' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ValueName 'DisableWindowsSpotlightFeatures' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ValueName 'DisableThirdPartySuggestions' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -ValueName 'EnableFeeds' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ValueName 'EnableDynamicContentInWSB' -Value 0 -Type DWord

    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ValueName 'LockScreenImage' -Value 'C:\Windows\web\screen\img105.jpg' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ValueName 'LockScreenOverlaysDisabled' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'DisableLockScreenAppNotifications' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' -ValueName 'RestrictImplicitInkCollection' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' -ValueName 'RestrictImplicitTextCollection' -Value 1 -Type DWord

    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS' -ValueName 'DisableBranchCache' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS' -ValueName 'DisablePeerCachingClient' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS' -ValueName 'DisablePeerCachingServer' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS' -ValueName 'EnablePeerCaching' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service' -ValueName 'Enable' -Value 0 -Type DWord

    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure Edge Browser' -ComputerName ROOT-DC1,CORP-DC,FABRIKAM-DC -ScriptBlock {
    $gpoName = 'Configure Edge Browser'
    $dnsRoot = (Get-ADDomain).DNSRoot
    $intranetUrl1 = 'http://*.{0}' -f $dnsRoot
    $intranetUrl2 = 'https://*.{0}' -f $dnsRoot
    New-GPO -Name $gpoName -ErrorAction SilentlyContinue | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'HideFirstRunExperience' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'NewTabPageContentEnabled' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'NewTabPageQuickLinksEnabled' -Value 0 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'NewTabPageHideDefaultTopSites' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'NewTabPageAllowedBackgroundTypes' -Value 3 -Type DWord

    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'RestoreOnStartup' -Value 4 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName '1' -Value 'about:blank' -Type String

    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ValueName 'ListBox_Support_ZoneMapKey' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey' -ValueName $intranetUrl1 -Value '1' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey' -ValueName $intranetUrl2 -Value '1' -Type String
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey' -ValueName 'https://autologon.microsoftazuread-sso.com' -Value '1' -Type String
    Set-GPRegistryValue -Name $gpoName -Key ('HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\{0}\*' -f $dnsRoot) -ValueName 'http' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key ('HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\{0}\*' -f $dnsRoot) -ValueName 'https' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key ('HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ESCDomains\{0}\*' -f $dnsRoot) -ValueName 'http' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key ('HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ESCDomains\{0}\*' -f $dnsRoot) -ValueName 'https' -Value 1 -Type DWord
    Set-GPRegistryValue -Name $gpoName -Key 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoftazuread-sso.com\autologon' -ValueName 'https' -Value 1 -Type DWord
                    
    New-GPLink -Name $gpoName -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Update GPOs' -ComputerName ROOT-DC1,ROOT-DC2,ROOT-SRV,ROOT-PC1,ROOT-PC2,CORP-DC,FABRIKAM-DC -ScriptBlock {
    gpupdate.exe | Out-Null
}

Invoke-LabCommand -ActivityName 'Enable AD Recycle Bin' -ComputerName ROOT-DC1,FABRIKAM-DC -ScriptBlock {
    # Force AD replication first to make sure that FSMO roles are available
    repadmin.exe /SyncAll /A /e /q
                    
    Import-Module -Name ActiveDirectory
    $forest = Get-ADForest -Current LocalComputer
    Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
            -Scope ForestOrConfigurationSet `
            -Target $forest.RootDomain `
            -WarningAction SilentlyContinue `
            -Confirm:$false
}

Invoke-LabCommand -ActivityName 'Install CA Role' -ComputerName ROOT-SRV -ScriptBlock {
    Import-Module -Name ServerManager -Verbose:$false
    Install-WindowsFeature -Name AD-Certificate,ADCS-Cert-Authority -IncludeManagementTools
    Set-Content -Path "$env:SystemRoot\CAPolicy.inf" -Force -Encoding Ascii -ErrorAction Stop -Value @'
[Version]
Signature="$Windows NT$"
[certsrv_Server]
LoadDefaultTemplates=0
'@
    Import-Module -Name ADCSDeployment -ErrorAction Stop -Verbose:$false
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'Contoso Root CA' -ValidityPeriod Years -ValidityPeriodUnits 10 -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2KB -HashAlgorithmName SHA256 -OverwriteExistingCAinDS -OverwriteExistingDatabase -Force
}

Invoke-LabCommand -ActivityName 'Install CA Web Enrollment Role' -ComputerName ROOT-SRV -ScriptBlock {
    Import-Module -Name ServerManager -Verbose:$false
    Install-WindowsFeature -Name ADCS-Web-Enrollment,Web-Mgmt-Console
    Install-AdcsWebEnrollment -ErrorAction Stop -Force
}

Invoke-LabCommand -ActivityName 'Publish CA Templates' -ComputerName ROOT-SRV -ScriptBlock {
    Import-Module -Name ADCSAdministration -Verbose:$false

    try
    {
        Add-CATemplate -Name KerberosAuthentication -Force -ErrorAction Stop
    }
    catch
    {
        # Probably already added
    }
                    
    try
    {
        Add-CATemplate -Name WebServer -Force -ErrorAction Stop
    }
    catch
    {
        # Probably already added
    }

    try
    {
        Add-CATemplate -Name Machine -Force -ErrorAction Stop
    }
    catch
    {
        # Probably already added
    }
}

Invoke-LabCommand -ActivityName 'Configure CA Template Permissions' -ComputerName ROOT-DC1 -ScriptBlock {
    Import-Module -Name ActiveDirectory -Verbose:$false
    $webServerTemplate = 'CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f (Get-ADRootDSE).ConfigurationNamingContext
    dsacls.exe $webServerTemplate /G 'Domain Computers:CA;Enroll'
    dsacls.exe $webServerTemplate /G 'Domain Controllers:CA;Enroll'
}

Invoke-LabCommand -ActivityName 'Autoenroll Certificates' -ComputerName ROOT-DC1,ROOT-DC2 -ScriptBlock {
    certutil.exe -pulse | Out-Null
}

Invoke-LabCommand -ActivityName 'Install DHCP Server' -ComputerName ROOT-SRV -ScriptBlock {
    Enable-WindowsOptionalFeature -FeatureName DHCPServer,DHCPServer-Tools -NoRestart -Online -WarningAction SilentlyContinue
    Import-Module -Name DhcpServer
    Add-DhcpServerv4Scope -Name Contoso-Client -StartRange 10.220.4.100 -EndRange 10.220.4.254 -SubnetMask 255.255.255.0 -State Active
    Set-DhcpServerv4OptionValue -ScopeId 10.220.4.0 -DnsServer 10.220.4.3 -Router 10.220.4.1 -DnsDomain contoso.com -Force
            
    # Autorize DHCP server in AD
    Add-DhcpServerInDC

    # Restart DHCP for authorization to apply
    Restart-Service -Name DHCPServer -Force -WarningAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Install Remote Desktop Web Access' -ComputerName ROOT-SRV -ScriptBlock {
    Import-Module -Name ServerManager -Verbose:$false
    Add-WindowsFeature -Name RDS-Web-Access,RDS-Gateway -IncludeManagementTools -IncludeAllSubFeature
}

Invoke-LabCommand -ActivityName 'Create RDWA DNS Records' -ComputerName ROOT-DC1 -ScriptBlock {
    Import-Module -Name ActiveDirectory,DnsServer -Verbose:$false
    [string] $dnsZone = (Get-ADDomain).DNSRoot
    [ipaddress] $rdwaIP = (Get-DnsServerResourceRecord -Name ROOT-SRV -ZoneName $dnsZone).RecordData.IPv4Address
    Add-DnsServerResourceRecordA -Name gateway -IPv4Address $rdwaIP -ZoneName $dnsZone -Verbose -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure RDWA SPN' -ComputerName ROOT-DC1 -ScriptBlock {
    Import-Module -Name ActiveDirectory -Verbose:$false
    [string] $dnsRoot = (Get-ADDomain).DNSRoot
    Set-ADComputer -Identity ROOT-SRV -ServicePrincipalNames @{ Add = "http/gateway.$dnsRoot" } -Verbose
    Set-ADComputer -Identity ROOT-SRV -ServicePrincipalNames @{ Add = "http/gateway" } -Verbose
}

Invoke-LabCommand -ActivityName 'Configure IIS TLS Binding for RDWA' -ComputerName ROOT-SRV -ScriptBlock {
    [string] $dnsRoot = $env:USERDNSDOMAIN.ToLower()
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert =
        Get-ChildItem -Path Cert:\LocalMachine\My -DnsName "gateway.$dnsRoot" -ErrorAction SilentlyContinue
                    
    if($null -eq $cert)
    {
        # Refresh Root CAs and Templates from AD 
        certutil -pulse | Out-Null

        Import-Module -Name PKI -Verbose:$false
        $result = Get-Certificate -Template WebServer `
                                -SubjectName "CN=gateway.$dnsRoot" `
                                -DnsName "gateway.$dnsRoot" `
                                -CertStoreLocation cert:\LocalMachine\My
        $cert = $result.Certificate
    }
                    
    Import-Module -Name WebAdministration -Verbose:$false
    [string] $siteName = 'Default Web Site'
    Remove-WebBinding -Name $siteName -BindingInformation '*:443:' -Protocol https -Confirm:$false -ErrorAction SilentlyContinue
    Remove-WebBinding -Name $siteName -BindingInformation "*:443:gateway.$dnsRoot" -Protocol https -Confirm:$false -ErrorAction SilentlyContinue
    New-WebBinding -Name $siteName -Protocol https -Port 443 -HostHeader "gateway.$dnsRoot" -Force
    (Get-WebBinding -Name $siteName -Port 443 -Protocol https).RebindSslCertificate($cert.Thumbprint, 'My')
}

Invoke-LabCommand -ActivityName 'Remove Windows Defender from servers' -ComputerName ROOT-DC1,ROOT-DC2,ROOT-SRV,CORP-DC,FABRIKAM-DC -ScriptBlock {
    Import-Module -Name ServerManager -Verbose:$false
    Uninstall-WindowsFeature -Name Windows-Defender -Restart:$false -WarningAction SilentlyContinue
}

Restart-LabVM -ComputerName ROOT-DC1,ROOT-DC2,ROOT-SRV,CORP-DC,FABRIKAM-DC -Wait -NoNewLine

# Configure Hyper-V
Set-VMhost -EnableEnhancedSessionMode $true

# Enable nested virtualization for WSL
Stop-VM -Name ROOT-PC2 -WarningAction SilentlyContinue
Set-VMProcessor -VMName ROOT-PC2 -ExposeVirtualizationExtensions $true
Set-VMSecurity -VMName ROOT-PC2 -VirtualizationBasedSecurityOptOut $true
Get-VMNetworkAdapter -VMName ROOT-PC2 | Set-VMNetworkAdapter -MacAddressSpoofing On

Invoke-LabCommand -ActivityName 'Install VM Platform' -ComputerName ROOT-PC2 -ScriptBlock {
    Import-Module -Name Dism
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V,VirtualMachinePlatform -NoRestart -All -WarningAction SilentlyContinue
}
                
Restart-LabVM -ComputerName ROOT-PC2 -Wait -NoNewLine

Invoke-LabCommand -ActivityName 'Create Nested Hyper-V External Switch' -ComputerName ROOT-PC2 -ScriptBlock {
    Import-Module -Name Hyper-V
    New-VMSwitch -Name External -AllowManagementOS $true -NetAdapterName (Get-NetAdapter -Name ContosoClient*).Name -ErrorAction SilentlyContinue
                    
    # Reconfigure WSL to use the switch
    Set-Content $env:USERPROFILE\.wslconfig -Value "[wsl2]`nnetworkingMode=bridged`nvmSwitch=External`nmemory=2GB`ndhcp=true`nipv6=true" -Force
}


Invoke-LabCommand -ActivityName 'Install WSUS' -ComputerName ROOT-SRV -ScriptBlock {
    Import-Module -Name ServerManager -Verbose:$false
    Install-WindowsFeature -Name UpdateServices -IncludeManagementTools -Restart:$false -WarningAction SilentlyContinue
    New-Item -Path "$env:SystemDrive\WSUS" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    & "$env:ProgramFiles\Update Services\Tools\wsusutil.exe" postinstall "CONTENT_DIR=$env:SystemDrive\WSUS"
}

Invoke-LabCommand -ActivityName 'Create WSUS DNS Records' -ComputerName ROOT-DC1 -ScriptBlock {
    Import-Module -Name ActiveDirectory,DnsServer -Verbose:$false
    [string] $dnsZone = (Get-ADDomain).DNSRoot
    [ipaddress] $wsusIP = (Get-DnsServerResourceRecord -Name ROOT-SRV -ZoneName $dnsZone).RecordData.IPv4Address
    Add-DnsServerResourceRecordA -Name update -IPv4Address $wsusIP -ZoneName $dnsZone -Verbose -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ActivityName 'Configure WSUS SPN' -ComputerName ROOT-DC1 -ScriptBlock {
    Import-Module -Name ActiveDirectory -Verbose:$false
    [string] $dnsRoot = (Get-ADDomain).DNSRoot
    Set-ADComputer -Identity ROOT-SRV -ServicePrincipalNames @{ Add = "http/update.$dnsRoot" } -Verbose
    Set-ADComputer -Identity ROOT-SRV -ServicePrincipalNames @{ Add = "http/update" } -Verbose
}

Invoke-LabCommand -ActivityName 'Configure IIS TLS Binding for WSUS' -ComputerName ROOT-SRV -ScriptBlock {
    [string] $dnsRoot = $env:USERDNSDOMAIN.ToLower()
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert =
        Get-ChildItem -Path Cert:\LocalMachine\My -DnsName "update.$dnsRoot" -ErrorAction SilentlyContinue
                    
    if($null -eq $cert)
    {
        # Refresh Root CAs and Templates from AD 
        certutil -pulse | Out-Null

        Import-Module -Name PKI -Verbose:$false
        $result = Get-Certificate -Template WebServer `
                                -SubjectName "CN=update.$dnsRoot" `
                                -DnsName "update.$dnsRoot" `
                                -CertStoreLocation cert:\LocalMachine\My
        $cert = $result.Certificate
    }
                    
    Import-Module -Name WebAdministration -Verbose:$false
    [string] $siteName = 'WSUS Administration'
    Remove-WebBinding -Name $siteName -BindingInformation '*:8531:' -Protocol https -Confirm:$false -ErrorAction SilentlyContinue
    Remove-WebBinding -Name $siteName -BindingInformation "*:8531:update.$dnsRoot" -Protocol https -Confirm:$false -ErrorAction SilentlyContinue
    New-WebBinding -Name $siteName -Protocol https -Port 8531 -HostHeader "update.$dnsRoot" -Force
    (Get-WebBinding -Name $siteName -Port 8531 -Protocol https).RebindSslCertificate($cert.Thumbprint, 'My')
}
