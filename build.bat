@echo off
setlocal

set "CONFIGURATION=%~1"
if not defined CONFIGURATION set "CONFIGURATION=Release"

where dotnet >nul 2>nul
if errorlevel 1 (
    echo Error: dotnet was not found in PATH. Install a current .NET SDK.
    exit /b 1
)

pushd "%~dp0"
echo Building FileShareAccessScanner ^(%CONFIGURATION%^)...
dotnet msbuild ".\FileShareAccessScanner.csproj" /t:Build /p:Configuration=%CONFIGURATION% /p:Platform=AnyCPU /v:minimal
set "BUILD_EXIT_CODE=%ERRORLEVEL%"

if not "%BUILD_EXIT_CODE%"=="0" (
    echo Build failed with exit code %BUILD_EXIT_CODE%.
    popd
    exit /b %BUILD_EXIT_CODE%
)

echo Build succeeded: bin\%CONFIGURATION%\FileShareAccessScanner.exe
popd
exit /b 0
