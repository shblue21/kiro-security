[CmdletBinding()]
param(
    [string]$VsixPath
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Package = Get-Content (Join-Path $Root "package.json") -Raw | ConvertFrom-Json
$Version = $Package.version
if (-not $VsixPath) { $VsixPath = Join-Path $Root "dist\kiro-security-power-$Version.vsix" }
$ExtensionId = "$($Package.publisher).$($Package.name)"

function Find-KiroCli {
    if ($env:KIRO_CLI) { return $env:KIRO_CLI }
    $command = Get-Command kiro -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidates = @()
    if ($env:LOCALAPPDATA) {
        $candidates += (Join-Path $env:LOCALAPPDATA "Programs\Kiro\bin\kiro.cmd")
        $candidates += (Join-Path $env:LOCALAPPDATA "Programs\Kiro\Kiro.exe")
    }
    if ($env:ProgramFiles) { $candidates += (Join-Path $env:ProgramFiles "Kiro\bin\kiro.cmd") }
    if (${env:ProgramFiles(x86)}) { $candidates += (Join-Path ${env:ProgramFiles(x86)} "Kiro\bin\kiro.cmd") }
    if ($env:USERPROFILE) { $candidates += (Join-Path $env:USERPROFILE "AppData\Local\Programs\Kiro\bin\kiro.cmd") }
    $candidates += "C:\Program Files\Kiro\bin\kiro.cmd"
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    return $null
}

if (-not (Test-Path $VsixPath -PathType Leaf)) {
    throw "VSIX not found: $VsixPath. Run npm ci and npm run package first, or pass -VsixPath."
}
$Kiro = Find-KiroCli
if (-not $Kiro) {
    throw "Kiro CLI not found. Set KIRO_CLI, add kiro to PATH, or install Kiro in a common Windows location."
}

$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("kiro-security-power-verify-" + [guid]::NewGuid().ToString("N"))
$UserData = Join-Path $WorkDir "user-data"
$Extensions = Join-Path $WorkDir "extensions"
$Workspace = Join-Path $WorkDir "fixture-workspace"
$ResultFile = Join-Path $WorkDir "local-verification-result.json"
New-Item -ItemType Directory -Force -Path $UserData, $Extensions, $Workspace | Out-Null
Copy-Item (Join-Path $Root "fixtures\vulnerable-repo\*") $Workspace -Recurse -Force
Remove-Item (Join-Path $Workspace ".git"), (Join-Path $Workspace ".kiro") -Recurse -Force -ErrorAction SilentlyContinue
$Git = Get-Command git -ErrorAction SilentlyContinue
if ($Git) {
    & $Git.Source -C $Workspace init -q
    & $Git.Source -C $Workspace config user.email "kiro-security-verification@example.invalid"
    & $Git.Source -C $Workspace config user.name "Kiro Security Verification"
    & $Git.Source -C $Workspace add .
    & $Git.Source -C $Workspace commit -qm "verification fixture"
}

$Common = @("--user-data-dir", $UserData, "--extensions-dir", $Extensions)
Write-Host "Using Kiro CLI: $Kiro"
Write-Host "Using isolated profile: $WorkDir"
& $Kiro @Common --install-extension $VsixPath --force
if ($LASTEXITCODE -ne 0) { throw "Kiro VSIX installation failed with exit code $LASTEXITCODE." }
$Installed = (& $Kiro @Common --list-extensions --show-versions 2>&1 | Out-String)
if ($Installed -notmatch [regex]::Escape($ExtensionId)) {
    throw "Kiro did not report $ExtensionId as installed. Reported extensions:`n$Installed"
}

$Result = [ordered]@{
    schemaVersion = "1.0"
    productVersion = $Version
    vsixPath = (Resolve-Path $VsixPath).Path
    kiroExecutable = $Kiro
    testedAt = $null
    platform = "Windows"
    checks = [ordered]@{
        installed = $true
        activityBarIcon = $null
        secondarySideBar = $null
        agentSetupVerified = $null
        agentCapabilities = $null
        nativePowerPrepared = $null
        standardScan = $null
        diffScan = $null
        deepFourWorker = $null
        deepMultiRound = $null
        canonicalSeal = $null
        liveProgress = $null
        realFinding = $null
        sourceNavigation = $null
        problemsDiagnostic = $null
        exports = $null
        historyAfterRestart = $null
        coordinatorLeaseHandoff = $null
        mcpToVsix = $null
        vsixToMcp = $null
        disableAndUninstall = $null
    }
    notes = @()
}
$Result | ConvertTo-Json -Depth 6 | Set-Content $ResultFile -Encoding UTF8
Write-Host "Installation was reported by Kiro. Complete docs/local-kiro-smoke-test.md."
Write-Host "Record results in $ResultFile. Installation is the only automated check marked true."
& $Kiro @Common --new-window $Workspace
