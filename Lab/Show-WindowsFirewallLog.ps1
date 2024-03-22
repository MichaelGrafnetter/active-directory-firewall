<#
.SYNOPSIS
Parses Windows Firewall log file.

.PARAMETER LogFilePath
Path to the log file.

.NOTES
Author:  Michael Grafnetter
Version: 1.1

#>

#Requires -Version 3
#Requires -RunAsAdministrator

Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $LogFilePath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log",

    [Parameter()]
    [switch] $Live
)

Get-Content -Path $LogFilePath -Wait:($Live.IsPresent) |
    Select-Object -Skip 3 |
    ForEach-Object { $PSItem -replace '^#Fields: ' } |
    ConvertFrom-Csv -Delimiter ' ' |
    Select-Object -Property date,time,path,action,pid,src-ip,src-port,dst-ip,dst-port |
    Out-GridView -Title 'Windows Firewall Log' -Wait
