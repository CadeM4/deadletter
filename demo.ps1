[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$linuxRoot = & wsl.exe -e wslpath -a -u $PSScriptRoot
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($linuxRoot)) {
    throw 'Could not translate the project path for WSL.'
}

$linuxRoot = $linuxRoot.Trim()
& wsl.exe -e bash -lc 'cd -- "$1" && exec make demo' bash $linuxRoot
if ($LASTEXITCODE -ne 0) {
    throw "The lab demonstration failed with exit code $LASTEXITCODE."
}
