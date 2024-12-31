@ECHO OFF
REM Synopsis: This helper script resets the unmanaged domain controller policy settings to their default values.
REM           It is intended to be executed locally on all domain controllers in the domain.
REM Author:   Michael Grafnetter
REM Version:  2.8

echo Make sure that GPO settings are applied.
gpupdate.exe /Target:Computer

echo Move the WMI service into the shared Svchost process.
winmgmt.exe /sharedhost

echo Configure the DFS Replication service to use a dynamic RPC port.
dfsrdiag.exe StaticRPC /Port:0

echo Remove all RPC filters.
netsh.exe rpc filter delete filter filterkey=all

echo Configure the Active Directory service to use a dynamic RPC port.
reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /f

echo Configure the Netlogon service to use a dynamic RPC port.
reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /DCTcpipPort /f

echo Configure the legacy FRS service to use a dynamic RPC port.
reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /f

echo Reset mDNS settings.
reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableMDNS /f

echo Reset ICMP settings.
reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /f
reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /f
reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /f
reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /f

echo Reset NetBIOS settings.
reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /f
reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /f

echo Restart the NTDS service.
net.exe stop NTDS /y && net.exe start NTDS

echo Restart the NtFrs service.
net.exe stop NtFrs /y && net.exe start NtFrs

echo Restart the Winmgmt service.
net.exe stop Winmgmt /y && net.exe start Winmgmt
