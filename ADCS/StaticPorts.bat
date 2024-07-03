@ECHO OFF

REM Author: Michael Grafnetter

REM Reconfigure the CA to use port 10509/TCP for RPC traffic
REM instead of a random port from the 49152-65535 dynamic range.
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{D99E6E74-FC88-11D0-B498-00A0C90312F3}" /v Endpoints /d "ncacn_ip_tcp,0,10509" /t REG_MULTI_SZ /f

REM Restart the service for the changes to apply
net.exe stop CertSvc
net.exe start CertSvc

REM Required CA ports are now:
REM 135/TCP   - RPC Endpoint Mapper
REM 10509/TCP - Certificate Request RPC API
REM 80/TCP    - HTTP CRL + OCSP
REM 443/TCP   - HTTPS CA Web Enrolment

REM Press any key...
pause