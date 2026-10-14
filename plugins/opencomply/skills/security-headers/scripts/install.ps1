# Installs the opencomply binary for Windows x86_64 from the GitHub release that matches this skill, after checking
# its SHA-256. User-level only: no admin rights, no PATH changes. Prints the binary path on the last line.
# Override the version with $env:OPENCOMPLY_VERSION = "X.Y.Z".
$ErrorActionPreference = 'Stop'

$Version = if ($env:OPENCOMPLY_VERSION) { $env:OPENCOMPLY_VERSION } else { '0.2.0' }
$Repo = 'vampirebeam/OpenComply'

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Write-Error "opencomply: no release build for Windows $env:PROCESSOR_ARCHITECTURE"
}

$Dest = Join-Path $env:LOCALAPPDATA "opencomply\v$Version"
$Bin = Join-Path $Dest 'opencomply.exe'
if ((Test-Path $Bin) -and ((& $Bin --version) -eq "opencomply $Version")) {
    Write-Output $Bin
    exit 0
}

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
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    foreach ($f in 'opencomply.exe', 'LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt') {
        Copy-Item (Join-Path $Tmp "$Name\$f") $Dest -Force
    }
    & $Bin --version | Out-Null
    Write-Output $Bin
}
finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
