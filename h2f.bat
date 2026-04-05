@echo off

echo username: %USERNAME%

echo hostname: %COMPUTERNAME%

:: Public IP
for /f "delims=" %%i in ('curl -s https://api.ipify.org') do set PUBLIC_IP=%%i
echo public_ip: %PUBLIC_IP%

:: MAC Address (first active one)
for /f "tokens=2 delims=," %%a in ('getmac /fo csv /nh') do (
    set MAC=%%~a
    goto :done_mac
)
:done_mac
echo mac_address: %MAC%

:: Git Info
for /f "delims=" %%i in ('git config user.name 2^>nul') do set GIT_NAME=%%i
echo git_username: %GIT_NAME%

for /f "delims=" %%i in ('git config user.email 2^>nul') do set GIT_EMAIL=%%i
echo git_email: %GIT_EMAIL%

:: Timestamp
echo timestamp: %DATE% %TIME%
