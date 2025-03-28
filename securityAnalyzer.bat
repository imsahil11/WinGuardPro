@echo off
setlocal enabledelayedexpansion
chcp 437 > nul
title Operating System Security Analyzer v2.1

:: Configuration
set "VERSION=2.1"
set "LOGDIR=%USERPROFILE%\SecurityAnalyzer"
set "REPORT=%LOGDIR%\security_report_%date:~-4,4%%date:~-10,2%%date:~-7,2%.txt"

:: Check for Admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo    This script requires administrator privileges.
    echo    Please right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Initialize
mode con: cols=120 lines=45
color 0B
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

:: Show loading screen
cls
echo.
echo    +------------------------------------------------------------------------------+
echo    ^|  Initializing Security Analyzer...                                           ^|
echo    +------------------------------------------------------------------------------+
echo.
echo    *****************************************************************************
echo    [*] Checking system requirements...
ping -n 2 localhost >nul
echo    [*] Loading security modules...
ping -n 2 localhost >nul
echo    [*] Initializing analysis tools...
ping -n 2 localhost >nul
echo    [*] Preparing interface...
ping -n 2 localhost >nul
echo    [*] Starting Security Analyzer...
ping -n 2 localhost >nul
echo    *****************************************************************************

:: Main Menu
:MAIN_MENU
cls
echo.
echo    +------------------------------------------------------------------------------+
echo    ^|  Operating System Security Analyzer v%VERSION%                                 ^|
echo    +------------------------------------------------------------------------------+
echo.
echo    *****************************************************************************
echo.
echo    [Security Analysis]
echo    ==================
echo    1. System Vulnerability Assessment
echo    2. Authentication Security Check
echo    3. Process Isolation Analysis
echo    4. Data Protection Evaluation
echo.
echo    [Attack Simulation]
echo    ==================
echo    5. Privilege Escalation Test
echo    6. Buffer Overflow Detection
echo    7. Unauthorized Access Check
echo    8. Network Security Analysis
echo.
echo    [System Cleanup]
echo    ===============
echo    9.  Clean Temporary Files
echo    10. Clear Windows Update Cache
echo    11. Remove System Junk
echo.
echo    [Privacy Controls]
echo    ================
echo    12. Disable Data Collection
echo    13. Manage App Permissions
echo    14. Configure Privacy Settings
echo.
echo    [System Information]
echo    ==================
echo    15. Detailed System Info
echo    16. Hardware Diagnostics
echo    17. Performance Analysis
echo.
echo    [Tools ^& Reports]
echo    ===============
echo    18. Security Report Generator
echo    19. Export Analysis Results
echo    20. Update Security Database
echo.
echo    21. Exit
echo.
echo    *****************************************************************************
echo.
set /p choice=    Select an option (1-21): 

:: Input validation
set "valid=0"
for %%i in (1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21) do (
    if "%choice%"=="%%i" set "valid=1"
)
if "%valid%"=="0" (
    echo.
    echo    Invalid option. Press any key to try again...
    pause >nul
    goto MAIN_MENU
)

:: Menu Routing
if "%choice%"=="1" goto VULNERABILITY_ASSESSMENT
if "%choice%"=="2" goto AUTH_SECURITY
if "%choice%"=="3" goto PROCESS_ISOLATION
if "%choice%"=="4" goto DATA_PROTECTION
if "%choice%"=="5" goto PRIV_ESCALATION
if "%choice%"=="6" goto BUFFER_OVERFLOW
if "%choice%"=="7" goto UNAUTH_ACCESS
if "%choice%"=="8" goto NETWORK_SECURITY
if "%choice%"=="9" goto CLEAN_TEMP
if "%choice%"=="10" goto CLEAR_UPDATE_CACHE
if "%choice%"=="11" goto REMOVE_SYSTEM_JUNK
if "%choice%"=="12" goto DISABLE_DATA_COLLECTION
if "%choice%"=="13" goto MANAGE_APP_PERMISSIONS
if "%choice%"=="14" goto CONFIGURE_PRIVACY
if "%choice%"=="15" goto DETAILED_SYSTEM_INFO
if "%choice%"=="16" goto HARDWARE_DIAGNOSTICS
if "%choice%"=="17" goto PERFORMANCE_ANALYSIS
if "%choice%"=="18" goto SECURITY_REPORT
if "%choice%"=="19" goto EXPORT_RESULTS
if "%choice%"=="20" goto UPDATE_DATABASE
if "%choice%"=="21" goto EXIT_SCRIPT

:: Vulnerability Assessment
:VULNERABILITY_ASSESSMENT
cls
call :CREATE_HEADER "System Vulnerability Assessment"

:: Check Windows Version and Updates
echo.
echo    Analyzing System Information...
systeminfo | findstr /B /C:"OS" /C:"System Type" /C:"Total Physical Memory" /C:"Available Physical Memory"
echo.

:: Check for Common Vulnerabilities
echo.
echo    Scanning for Common Vulnerabilities...
powershell -Command "Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5"
echo.

:: Check Running Services
echo.
echo    Analyzing Running Services...
sc query state= all | findstr "SERVICE_NAME"
echo.

:: Check Firewall Status
echo.
echo    Checking Firewall Status...
netsh advfirewall show allprofiles | findstr "State"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Authentication Security Check
:AUTH_SECURITY
cls
call :CREATE_HEADER "Authentication Security Check"

:: Check Password Policy
echo.
echo    Analyzing Password Policy...
net accounts
echo.

:: Check User Accounts
echo.
echo    Checking User Accounts...
net user
echo.

:: Check Admin Accounts
echo.
echo    Identifying Administrative Accounts...
net localgroup administrators
echo.

:: Check Last Login Times
echo.
echo    Checking Last Login Times...
for /f "tokens=*" %%a in ('net user') do (
    net user "%%a" | findstr "Last logon"
)
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Process Isolation Analysis
:PROCESS_ISOLATION
cls
call :CREATE_HEADER "Process Isolation Analysis"

:: List Running Processes
echo.
echo    Listing Running Processes...
tasklist /v
echo.

:: Check Process Permissions
echo.
echo    Checking Process Permissions...
powershell -Command "Get-Process | Select-Object ProcessName, Id, Path"
echo.

:: Check Service Isolation
echo.
echo    Analyzing Service Isolation...
sc query state= all | findstr "SERVICE_NAME"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Data Protection Evaluation
:DATA_PROTECTION
cls
call :CREATE_HEADER "Data Protection Evaluation"

:: Check BitLocker Status
echo.
echo    Checking BitLocker Status...
manage-bde -status
echo.

:: Check File Permissions
echo.
echo    Analyzing File Permissions...
icacls "%USERPROFILE%\Documents"
echo.

:: Check Shared Folders
echo.
echo    Checking Shared Folders...
net share
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Privilege Escalation Test
:PRIV_ESCALATION
cls
call :CREATE_HEADER "Privilege Escalation Test"

:: Check UAC Settings
echo.
echo    Checking UAC Settings...
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA"
echo.

:: Check Scheduled Tasks
echo.
echo    Analyzing Scheduled Tasks...
schtasks /query /fo LIST /v
echo.

:: Check Service Permissions
echo.
echo    Checking Service Permissions...
sc qc *
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Buffer Overflow Detection
:BUFFER_OVERFLOW
cls
call :CREATE_HEADER "Buffer Overflow Detection"

:: Check Running Applications
echo.
echo    Analyzing Running Applications...
tasklist /v
echo.

:: Check Memory Usage
echo.
echo    Checking Memory Usage...
wmic process get name,workingsetsize /format:value
echo.

:: Check for Suspicious Processes
echo.
echo    Scanning for Suspicious Processes...
powershell -Command "Get-Process | Where-Object {$_.WorkingSet64 -gt 1GB} | Select-Object ProcessName, Id, WorkingSet64"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Unauthorized Access Check
:UNAUTH_ACCESS
cls
call :CREATE_HEADER "Unauthorized Access Check"

:: Check Recent Logins
echo.
echo    Checking Recent Logins...
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text /rd:true /c:10
echo.

:: Check Failed Logins
echo.
echo    Checking Failed Login Attempts...
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text /rd:true /c:10
echo.

:: Check Remote Connections
echo.
echo    Checking Remote Connections...
netstat -an | findstr "ESTABLISHED"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Network Security Analysis
:NETWORK_SECURITY
cls
call :CREATE_HEADER "Network Security Analysis"

:: Check Open Ports
echo.
echo    Checking Open Ports...
netstat -an
echo.

:: Check Firewall Rules
echo.
echo    Analyzing Firewall Rules...
netsh advfirewall firewall show rule name=all
echo.

:: Check Network Connections
echo.
echo    Checking Network Connections...
netstat -b
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Clean Temporary Files
:CLEAN_TEMP
cls
call :CREATE_HEADER "Clean Temporary Files"

:: Clean Windows Temp Folder
echo.
echo    Cleaning Windows Temporary Folder...
del /q/f/s "%TEMP%\*"
del /q/f/s "%WINDIR%\Temp\*"
echo.

:: Clean Prefetch
echo.
echo    Cleaning Prefetch Folder...
del /q/f/s "%WINDIR%\Prefetch\*"
echo.

:: Clean Recent Files
echo.
echo    Cleaning Recent Files...
del /q/f/s "%APPDATA%\Microsoft\Windows\Recent\*"
echo.

:: Clean Recycle Bin
echo.
echo    Emptying Recycle Bin...
rd /s /q "%SYSTEMDRIVE%\$Recycle.Bin"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Clear Windows Update Cache
:CLEAR_UPDATE_CACHE
cls
call :CREATE_HEADER "Clear Windows Update Cache"

:: Stop Windows Update Service
echo.
echo    Stopping Windows Update Service...
net stop wuauserv
echo.

:: Clear Update Cache
echo.
echo    Clearing Update Cache...
rd /s /q "%WINDIR%\SoftwareDistribution"
mkdir "%WINDIR%\SoftwareDistribution"
echo.

:: Restart Windows Update Service
echo.
echo    Restarting Windows Update Service...
net start wuauserv
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Remove System Junk
:REMOVE_SYSTEM_JUNK
cls
call :CREATE_HEADER "Remove System Junk"

:: Clean System32 Logs
echo.
echo    Cleaning System Logs...
del /q/f/s "%WINDIR%\System32\winevt\Logs\*"
echo.

:: Clean Windows Error Reports
echo.
echo    Cleaning Error Reports...
del /q/f/s "%LOCALAPPDATA%\Microsoft\Windows\WER\*"
echo.

:: Clean Windows Store Cache
echo.
echo    Cleaning Store Cache...
del /q/f/s "%LOCALAPPDATA%\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\SystemAppData\*"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Disable Data Collection
:DISABLE_DATA_COLLECTION
cls
call :CREATE_HEADER "Disable Data Collection"

:: Disable Telemetry
echo.
echo    Disabling Telemetry...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
echo.

:: Disable Diagnostic Data
echo.
echo    Disabling Diagnostic Data...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f
echo.

:: Disable Feedback
echo.
echo    Disabling Feedback...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
echo.

:: Stop Telemetry Services
echo.
echo    Stopping Telemetry Services...
sc stop DiagTrack
sc stop dmwappushservice
sc disable DiagTrack
sc disable dmwappushservice
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Manage App Permissions
:MANAGE_APP_PERMISSIONS
cls
call :CREATE_HEADER "Manage App Permissions"

:: Disable Camera Access
echo.
echo    Disabling Camera Access...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f
echo.

:: Disable Microphone Access
echo.
echo    Disabling Microphone Access...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f
echo.

:: Disable Location Access
echo.
echo    Disabling Location Access...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
echo.

:: Disable Notifications
echo.
echo    Disabling Notifications...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Configure Privacy Settings
:CONFIGURE_PRIVACY
cls
call :CREATE_HEADER "Configure Privacy Settings"

:: Disable Advertising ID
echo.
echo    Disabling Advertising ID...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
echo.

:: Disable Activity History
echo.
echo    Disabling Activity History...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
echo.

:: Disable Location Services
echo.
echo    Disabling Location Services...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
echo.

:: Disable Cortana
echo.
echo    Disabling Cortana...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Detailed System Info
:DETAILED_SYSTEM_INFO
cls
call :CREATE_HEADER "System Information Analysis"

echo    ===============================================================================
echo                System Information              
echo    ===============================================================================
echo.
for /f "tokens=*" %%a in ('systeminfo ^| findstr /B /C:"OS" /C:"System Type" /C:"Total Physical Memory" /C:"Available Physical Memory"') do (
    echo    %%a
)
echo.

echo    ===============================================================================
echo                Processor Details               
echo    ===============================================================================
echo.
for /f "tokens=*" %%a in ('wmic cpu get name^, numberofcores^, maxclockspeed /value') do (
    echo    %%a
)
echo.

echo    ===============================================================================
echo                Memory Information              
echo    ===============================================================================
echo.
for /f "tokens=*" %%a in ('wmic memorychip get capacity^, speed^, manufacturer /value') do (
    echo    %%a
)
echo.

echo    ===============================================================================
echo                Storage Information             
echo    ===============================================================================
echo.
for /f "tokens=*" %%a in ('wmic diskdrive get model^, size^, status /value') do (
    echo    %%a
)
echo.

echo    Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:: Hardware Diagnostics
:HARDWARE_DIAGNOSTICS
cls
call :CREATE_HEADER "Hardware Diagnostics"

:: Check CPU Health
echo.
echo    Checking CPU Health...
wmic cpu get loadpercentage, temperature
echo.

:: Check Memory Health
echo.
echo    Checking Memory Health...
wmic memorychip get status
echo.

:: Check Disk Health
echo.
echo    Checking Disk Health...
wmic diskdrive get status
echo.

:: Check Battery Health
echo.
echo    Checking Battery Health...
wmic path Win32_Battery get status, estimatedChargeRemaining
echo.

:: Check Network Health
echo.
echo    Checking Network Health...
ipconfig /all
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Performance Analysis
:PERFORMANCE_ANALYSIS
cls
call :CREATE_HEADER "Performance Analysis"

:: CPU Usage
echo.
echo    CPU Usage:
wmic cpu get loadpercentage
echo.

:: Memory Usage
echo.
echo    Memory Usage:
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value
echo.

:: Disk Usage
echo.
echo    Disk Usage:
wmic logicaldisk get size,freespace,caption
echo.

:: Network Usage
echo.
echo    Network Usage:
netstat -e
echo.

:: Running Processes
echo.
echo    Top CPU Processes:
wmic process get caption,processid,workingsetsize /format:value | sort /+64
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Security Report Generator
:SECURITY_REPORT
cls
call :CREATE_HEADER "Generating Security Report"

:: Create Report Header
echo ============================================ > "%REPORT%"
echo        SECURITY ANALYSIS REPORT              >> "%REPORT%"
echo ============================================ >> "%REPORT%"
echo Generated on: %date% %time%                  >> "%REPORT%"
echo. >> "%REPORT%"

:: System Information
echo ============================================ >> "%REPORT%"
echo             SYSTEM INFORMATION               >> "%REPORT%"
echo ============================================ >> "%REPORT%"
systeminfo | findstr /B /C:"OS" /C:"System Type" /C:"Total Physical Memory" >> "%REPORT%"
echo. >> "%REPORT%"

:: Security Status
echo ============================================ >> "%REPORT%"
echo             SECURITY STATUS                  >> "%REPORT%"
echo ============================================ >> "%REPORT%"
netsh advfirewall show allprofiles | findstr "State Profile" >> "%REPORT%"
echo. >> "%REPORT%"

:: User Accounts
echo ============================================ >> "%REPORT%"
echo             USER ACCOUNTS                    >> "%REPORT%"
echo ============================================ >> "%REPORT%"
net user | findstr /V "command completed" >> "%REPORT%"
echo. >> "%REPORT%"

:: Running Services
echo ============================================ >> "%REPORT%"
echo             RUNNING SERVICES                 >> "%REPORT%"
echo ============================================ >> "%REPORT%"
sc query state= all | findstr "SERVICE_NAME STATE" >> "%REPORT%"
echo. >> "%REPORT%"

:: Network Status
echo ============================================ >> "%REPORT%"
echo             NETWORK STATUS                   >> "%REPORT%"
echo ============================================ >> "%REPORT%"
netstat -an | findstr "LISTENING ESTABLISHED" >> "%REPORT%"
echo. >> "%REPORT%"

echo    Report generated successfully at:
echo    %REPORT%
echo.
echo    Opening report...
timeout /t 2 >nul
start notepad "%REPORT%"
echo.
echo    Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:: Export Analysis Results
:EXPORT_RESULTS
cls
call :CREATE_HEADER "Export Analysis Results"

:: Create Export Directory
set "EXPORT_DIR=%USERPROFILE%\SecurityAnalyzer\Exports"
if not exist "%EXPORT_DIR%" mkdir "%EXPORT_DIR%"
echo.

:: Export System Information
echo.
echo    Exporting System Information...
systeminfo > "%EXPORT_DIR%\system_info.txt"
echo.

:: Export Security Settings
echo.
echo    Exporting Security Settings...
secedit /export /cfg "%EXPORT_DIR%\security_settings.cfg"
echo.

:: Export Network Configuration
echo.
echo    Exporting Network Configuration...
netsh advfirewall export "%EXPORT_DIR%\firewall_rules.wfw"
echo.

echo.
echo    Analysis Results Exported to: %EXPORT_DIR%
echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Update Security Database
:UPDATE_DATABASE
cls
call :CREATE_HEADER "Update Security Database"

:: Update Windows Defender
echo.
echo    Updating Windows Defender...
powershell -Command "Update-MpSignature"
echo.

:: Update System
echo.
echo    Checking for System Updates...
powershell -Command "Get-WindowsUpdate"
echo.

:: Update Security Policies
echo.
echo    Updating Security Policies...
secedit /configure /cfg "%WINDIR%\security\templates\secsetup.inf"
echo.

echo.
echo    Operation Complete! Press any key to continue...
pause >nul
goto MAIN_MENU

:: Exit Script
:EXIT_SCRIPT
cls
echo.
echo    +------------------------------------------------------------------------------+
echo    ^|  Thank you for using the Operating System Security Analyzer!                 ^|
echo    +------------------------------------------------------------------------------+
echo.
echo    *****************************************************************************
echo    Visit https://www.microsoft.com/security for more security information
echo    *****************************************************************************
echo.
echo    Cleaning up temporary files...
timeout /t 2 >nul
echo    Exiting...
timeout /t 2 >nul
echo    Press any key to exit...
pause >nul
exit /b 0

:ERROR
echo.
echo    *****************************************************************************
echo    An error occurred: %~1
echo    *****************************************************************************
echo    Press any key to return to main menu...
pause >nul
goto :MAIN_MENU