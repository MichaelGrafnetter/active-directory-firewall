@ECHO OFF
REM Synopsis: This helper script ensures that all domain controller firewall policy settings are applied, without requiring DC reboots.
REM           It is intended to be executed locally on all domain controllers in the domain.
REM Author:   Michael Grafnetter
REM Version:  2.8

echo Make sure that the latest GPO settings are applied.
gpupdate.exe /Target:Computer

echo Execute the Group Policy startup scripts.
gpscript.exe /startup

echo Restart the NTDS service.
net.exe stop NTDS /y && net.exe start NTDS

echo Restart the NtFrs service.
net.exe stop NtFrs /y && net.exe start NtFrs

echo Restart the Winmgmt service.
net.exe stop Winmgmt /y && net.exe start Winmgmt

echo Restart the IAS service.
net.exe stop IAS /y && net.exe start IAS
