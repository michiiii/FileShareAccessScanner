# FileShareAccessScanner

FileShareAccessScanner is a Windows command-line tool that recursively scans file and directory DACLs for security-sensitive write and ownership permissions. It targets .NET Framework 4.7.2 and follows reparse points by default while detecting repeated directory targets.

> The scanner reports matching DACL ACEs. It does not calculate complete effective access, which also depends on deny ordering, share permissions, privileges, and expanded group membership.

## Build

From PowerShell with a current .NET SDK and the .NET Framework 4.7.2 targeting pack installed:

```powershell
.\build.bat
```

This produces a Release build by default. Pass `Debug` to build the Debug configuration:

```powershell
.\build.bat Debug
```

The equivalent direct command is:

```powershell
dotnet msbuild .\FileShareAccessScanner.csproj /t:Build /p:Configuration=Release /p:Platform=AnyCPU
```

The executable is written to `bin\Release\FileShareAccessScanner.exe`.

## Typical Workflow

### 1. Collect permissions

Scan a share and save matching entries as JSON:

```powershell
.\FileShareAccessScanner.exe collect "\\sccm.lab\sysvol" .\out.json
```

Reparse-point directories are traversed by default, which is required for paths such as SYSVOL. Use `--skip-reparse-points` when those targets must not be followed. Run the executable without arguments to see all collection options.

### 2. Review the overview

`overview` requires the JSON file produced by `collect`:

```powershell
.\FileShareAccessScanner.exe overview .\out.json
```

Example:

```text
Username                              Entries  UniquePaths
--------------------------------------------------------------------------------
NT AUTHORITY\Authenticated Users      8        1
```

Running `overview` without its input prints `Usage: overview <InputFile>` and returns exit code `1`.

### 3. Inspect one identity

Filter by a partial username or SID. Quote account names containing spaces:

```powershell
.\FileShareAccessScanner.exe filter .\out.json "Authenticated Users"
.\FileShareAccessScanner.exe filter .\out.json "S-1-5-11"
```

The result includes the affected path, resolved username, SID, matching right, ACE type, and inheritance state:

```text
Path                                             Username                              SID       AccessRight       Type   Inherited
\\sccm.lab\sysvol\sccm.lab\scripts\login.ps1   NT AUTHORITY\Authenticated Users      S-1-5-11  ChangePermissions Allow  False
```

One ACE may produce multiple rows—for example `Write`, `AppendData`, `WriteData`, and `WriteAttributes`—because each matching critical right is reported separately. Consequently, `Entries` is a rights-entry count rather than an ACE or file count; `UniquePaths` shows the distinct affected paths.

## Handling Results Safely

Scan output can expose server names, directory layouts, usernames, SIDs, and security weaknesses. Store JSON results securely, sanitize examples before sharing them, and do not commit production scan output.
