﻿<#
.SYNOPSIS
Parses Windows Firewall log file.

.PARAMETER LogFilePath
Path to the log file.

.NOTES
Author:  Michael Grafnetter
Version: 1.0

#>

#Requires -Version 3
#Requires -RunAsAdministrator

Param(
    [parameter(Mandatory = $false, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $LogFilePath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
)

Get-Content -Path $LogFilePath |
    Select-Object -Skip 3 |
    ForEach-Object { $PSItem -replace '^#Fields: ' } |
    ConvertFrom-Csv -Delimiter ' ' |
    Out-GridView -Title 'Windows Firewall Log' -Wait
