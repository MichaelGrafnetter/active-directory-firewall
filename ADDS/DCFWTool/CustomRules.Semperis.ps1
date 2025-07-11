<#
.SYNOPSIS
Sample script that adds Semperis Active Directory Forest Recovery (ADFR)
and Semperis Directory Services Protector (DSP) domain controller agent firewall rules to a pre-existing GPO session.

.DESCRIPTION
This is a sample script. Always perform review and testing before applying any firewall rules in a production environment.

Also keep in mind that this script only targets DCs, so management server and distribution point-specific rules are not included.

This script is not intended to be run directly. Instead, its relative path should be specified in the Set-ADDSFirewallPolicy.json configuration file.
It is then executed by the main Set-ADDSFirewallPolicy.ps1 script.

.PARAMETER GPOSession
Specifies the network GPO session in which the rules are to be created.
To load a GPO Session, use the Open-NetGPO cmdlet.
To save a GPO Session, use the Save-NetGPO cmdlet.

.PARAMETER DomainControllerAddresses
List of domain controller IP addresses, between which replication traffic should be allowed.

.PARAMETER RemoteManagementAddresses
List of IP addresses from which inbound management traffic should be allowed.

IP addresses of Semperis Semperis DSP and ADFR management servers and distribution points
must be added to this list using the JSON configuration file.

.PARAMETER AllAddresses
List of client IP adresses from which inbound traffic should be allowed.
This list should automatically include the IP addresses of Semperis Semperis DSP and ADFR management servers and distribution points.

.NOTES
Author:  Michael Grafnetter
Version: 1.0

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

#region Semperis ADFR

# Create Inbound rule "Semperis ADFR Agent (TCP-In)"
# Purpose: AD forest backup and recovery orchestration
New-NetFirewallRule -GPOSession $GPOSession `
                    -Name 'Semperis-ADFR-Agent-TCP-In' `
                    -Group 'Semperis Agents' `
                    -DisplayName 'Semperis ADFR Agent (TCP-In)' `
                    -Description 'Inbound rule for Semperis ADFR Agent [TCP 8753]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8753 `
                    -RemoteAddress $RemoteManagementAddresses `
                    -Program '%ProgramFiles%\Semperis\ADFR\Semperis.ForestRecoveryAgentSvcHost.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Semperis ADFR Agent File Transfer (TCP-In)"
# Purpose: ADFR backup file transfer
New-NetFirewallRule -GPOSession $GPOSession `
                    -Name 'Semperis-ADFR-Agent-Transfer-TCP-In' `
                    -Group 'Semperis Agents' `
                    -DisplayName 'Semperis ADFR Agent File Transfer (TCP-In)' `
                    -Description 'Inbound rule for Semperis ADFR Agent File Transfer [TCP 8770]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8770 `
                    -RemoteAddress $RemoteManagementAddresses `
                    -Program '%ProgramFiles%\Semperis\ADFR\Semperis.ForestRecoveryAgentSvcHost.exe' `
                    -Verbose:$isVerbose > $null

#endregion Semperis ADFR
#region Semperis DSP

# Create Inbound rule "Semperis ADSM Agent (TCP-In)"
# Purpose: AD change monitoring and restore
New-NetFirewallRule -GPOSession $GPOSession `
                    -Name 'Semperis-ADSM-Agent-TCP-In' `
                    -Group 'Semperis Agents' `
                    -DisplayName 'Semperis ADSM Agent (TCP-In)' `
                    -Description 'Inbound rule for Semperis ADSM Agent [TCP 8750]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8750 `
                    -RemoteAddress $RemoteManagementAddresses `
                    -Program '%ProgramFiles%\Semperis\ADSM\Semperis.ExecuterSvcHost.exe' `
                    -Verbose:$isVerbose > $null

# Create Inbound rule "Semperis ADSM Agent File Transfer (TCP-In)"
# Purpose: File transfer for GPO backup and restore
New-NetFirewallRule -GPOSession $GPOSession `
                    -Name 'Semperis-ADSM-Agent-Transfer-TCP-In' `
                    -Group 'Semperis Agents' `
                    -DisplayName 'Semperis ADSM Agent File Transfer (TCP-In)' `
                    -Description 'Inbound rule for Semperis ADSM Agent File Transfer [TCP 8772]' `
                    -Enabled True `
                    -Profile Any `
                    -Direction Inbound `
                    -Action Allow `
                    -Protocol TCP `
                    -LocalPort 8772 `
                    -RemoteAddress $RemoteManagementAddresses `
                    -Program '%ProgramFiles%\Semperis\ADSM\Semperis.ExecuterSvcHost.exe' `
                    -Verbose:$isVerbose > $null

#endregion Semperis DSP
