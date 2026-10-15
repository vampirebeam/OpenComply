# Installs the opencomply CLI for Windows x86_64 from the GitHub release that matches this script, after checking its
# SHA-256, so that `opencomply` works in any new terminal. User-level only (no admin): the binary goes to
# %LOCALAPPDATA%\opencomply\bin, which is added to the user PATH; older versions are replaced.
# `-Uninstall` removes the files and the PATH entry. Prints the command path on the last line.
# Override the version with $env:OPENCOMPLY_VERSION = "X.Y.Z".
param([switch]$Uninstall)
# Runs in its own scope: safe for 'irm … | iex' (no variables or preferences leak into the caller's session).
& {
    param([bool]$Uninstall)
    $ErrorActionPreference = 'Stop'

    $Version = if ($env:OPENCOMPLY_VERSION) { $env:OPENCOMPLY_VERSION } else { '0.2.3' }
    $Repo = 'vampirebeam/OpenComply'
    $Root = Join-Path $env:LOCALAPPDATA 'opencomply'
    $BinDir = Join-Path $Root 'bin'
    $Bin = Join-Path $BinDir 'opencomply.exe'

    # The user PATH is read and written raw (REG_EXPAND_SZ, %VARS% kept as typed), then other programs are notified.
    function Get-UserPath {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
        try { [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
        finally { $key.Close() }
    }
    function Set-UserPath([string]$Value) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        try { $key.SetValue('Path', $Value, [Microsoft.Win32.RegistryValueKind]::ExpandString) }
        finally { $key.Close() }
        [Environment]::SetEnvironmentVariable('OPENCOMPLY_PATH_REFRESH', '1', 'User')
        [Environment]::SetEnvironmentVariable('OPENCOMPLY_PATH_REFRESH', $null, 'User')
    }
    function Split-PathList([string]$Value) { @($Value -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ne $BinDir.TrimEnd('\') }) }

    if ($Uninstall) {
        Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue
        Set-UserPath ((Split-PathList (Get-UserPath)) -join ';')
        $env:Path = (Split-PathList $env:Path) -join ';'
        Write-Output 'opencomply: removed'
        return
    }

    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        Write-Error "opencomply: no release build for Windows $env:PROCESSOR_ARCHITECTURE"
    }

    $Current = if (Test-Path $Bin) { & $Bin --version } else { '' }
    if ($Current -ne "opencomply $Version") {
        $Name = "opencomply-v$Version-x86_64-pc-windows-msvc"
        $Url = "https://github.com/$Repo/releases/download/v$Version/$Name.zip"
        $Tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $Tmp | Out-Null
        try {
            $Zip = Join-Path $Tmp "$Name.zip"
            Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
            Invoke-WebRequest -Uri "$Url.sha256" -OutFile "$Zip.sha256" -UseBasicParsing

            $Expected = ((Get-Content "$Zip.sha256" -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
            $Actual = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($Expected -ne $Actual) {
                Write-Error "opencomply: SHA-256 mismatch for $Name.zip - not installed"
            }

            Expand-Archive $Zip -DestinationPath $Tmp
            Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
            foreach ($f in 'opencomply.exe', 'LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt') {
                Copy-Item (Join-Path $Tmp "$Name\$f") $BinDir -Force
            }
            & $Bin --version | Out-Null
        }
        finally {
            Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
        }
    }

    if (-not ((Get-UserPath) -split ';' | Where-Object { $_.TrimEnd('\') -eq $BinDir.TrimEnd('\') })) {
        Set-UserPath ((@(Split-PathList (Get-UserPath)) + $BinDir) -join ';')
        Write-Host "opencomply: added $BinDir to your user PATH. 'opencomply' works in this window now; other open windows (including terminals inside VS Code or Claude Code) see it after that app is restarted."
    }
    if (-not ($env:Path -split ';' | Where-Object { $_.TrimEnd('\') -eq $BinDir.TrimEnd('\') })) {
        $env:Path = "$env:Path;$BinDir"
    }
    Write-Output $Bin
} $Uninstall.IsPresent
