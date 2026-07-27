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
set "NUGET_EXE=%TEMP%\FileShareAccessScanner-nuget.exe"
if not exist "%NUGET_EXE%" (
    echo Downloading NuGet package restore tool...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' -OutFile $env:NUGET_EXE"
    if errorlevel 1 (
        echo Error: Unable to download NuGet. Check the internet connection and try again.
        popd
        exit /b 1
    )
)

echo Restoring NuGet packages...
"%NUGET_EXE%" restore ".\packages.config" -PackagesDirectory ".\packages" -NonInteractive
if errorlevel 1 (
    echo Package restore failed.
    popd
    exit /b 1
)

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
