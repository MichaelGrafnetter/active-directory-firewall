<#
.SYNOPSIS
Adds custom firewall rules to a pre-existing GPO session.

.DESCRIPTION
This script is not intended to be run directly. Instead, its relative path should be specified in the Set-ADDSFirewallPolicy.json configuration file.
It is then executed by the main Set-ADDSFirewallPolicy.ps1 script.

.PARAMETER GPOSession
Specifies the network GPO session in which the rules are to be created. To load a GPO Session, use the Open-NetGPO cmdlet. To save a GPO Session, use the Save-NetGPO cmdlet.

.PARAMETER DomainControllerAddresses
List of domain controller IP addresses, between which replication traffic should be allowed.

.PARAMETER RemoteManagementAddresses
List of IP addresses from which inbound management traffic should be allowed. This list may optionally include the IP addresses of the domain controllers.

.PARAMETER AllAddresses
List of client IP adresses from which inbound traffic should be allowed. This list should include the IP addresses of the domain controllers and management systems.

.NOTES
Author:  Michael Grafnetter
Version: 2.8

#>

#Requires -Modules NetSecurity
#Requires -Version 5

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $GPOSession,

    [ValidateNotNullOrEmpty()]
    [string[]] $DomainControllerAddresses = @('Any'),

    [ValidateNotNullOrEmpty()]
    [string[]] $RemoteManagementAddresses = @('Any'),

    [ValidateNotNullOrEmpty()]
    [string[]] $AllAddresses = @('Any')
)

# Not all cmdlets inherit the -Verbose parameter, so we need to explicitly override it.
[bool] $isVerbose = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue

#region Custom Rules

<#
Feel free to add your custom firewall rules below to match your environment.
#>

# Create Inbound rule "File and Printer Sharing over SMBDirect (iWARP-In)"
New-NetFirewallRule -GPOSession $GPOSession `
                    -Name 'FPSSMBD-iWARP-In-TCP' `
                    -DisplayName 'File and Printer Sharing over SMBDirect (iWARP-In)' `
                    -Group 'File and Printer Sharing over SMBDirect' `
                    -Description 'Inbound rule for File and Printer Sharing over SMBDirect to allow iWARP [TCP 5445]' `
                    -Enabled False `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 5445 `
                    -RemoteAddress $AllAddresses `
                    -Program 'System' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Dell OpenManage Server Administrator (TCP-In)"
New-NetFirewallRule -GPOSession $GPOSession `
                    -Name 'OMSA-In-TCP' `
                    -DisplayName 'Dell OpenManage Server Administrator (TCP-In)' `
                    -Description 'Inbound rule for Dell OpenManage Server Administrator Web Service [TCP 1311]' `
                    -Enabled False `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 1311 `
                    -RemoteAddress $RemoteManagementAddresses `
                    -Program '%ProgramFiles%\Dell\SysMgt\oma\bin\dsm_om_connsvc64.exe' `
                    -Verbose:$isVerbose > $null

#endregion Custom Rules
