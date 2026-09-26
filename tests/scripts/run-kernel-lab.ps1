#Requires -Version 7.0
param([int]$Seconds = 210, [string]$Image = 'vgk.sys')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$guestImage = Join-Path (Join-Path $root 'fs_x86_64') $Image
if (-not (Test-Path -LiteralPath $guestImage)) { throw "Guest image missing: $guestImage" }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$run = Join-Path $root "build-conformance\kernel-$stamp"
New-Item -ItemType Directory -Force $run | Out-Null
# Freeze this executable and its runtime DLLs so later builds cannot change the run.
Get-ChildItem (Join-Path $root 'build-x64-whp\Release') -File | Where-Object { $_.Extension -in '.exe', '.dll' } | Copy-Item -Destination $run
$exe = Join-Path $run 'kernemul.exe'
$stdout = Join-Path $run 'stdout.log'
$stderr = Join-Path $run 'stderr.log'
$manifest = [ordered]@{
    started = (Get-Date).ToString('o'); backend = 'whp'; image = $guestImage
    imageSha256 = (Get-FileHash -LiteralPath $guestImage).Hash
    executableSha256 = (Get-FileHash -LiteralPath $exe).Hash
    kernelSha256 = (Get-FileHash -LiteralPath (Join-Path $root 'fs_x86_64\Windows\System32\ntoskrnl.exe')).Hash
    kernelVersion = (Get-Item (Join-Path $root 'fs_x86_64\Windows\System32\ntoskrnl.exe')).VersionInfo.ProductVersion
    requestedSeconds = $Seconds; gitCommit = (& git -C $root rev-parse HEAD)
    stdout = $stdout; stderr = $stderr
}
$guestCi = Join-Path $root 'fs_x86_64\Windows\System32\ci.dll'
if (Test-Path -LiteralPath $guestCi) {
    $manifest.ciSha256 = (Get-FileHash -LiteralPath $guestCi).Hash
    $manifest.ciVersion = (Get-Item -LiteralPath $guestCi).VersionInfo.ProductVersion
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $run 'manifest.json')
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $exe -ArgumentList $Image -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
$exited = $false
while ($timer.Elapsed.TotalSeconds -lt $Seconds) {
    $remainingMs = [Math]::Max(1, [Math]::Min(30000, ($Seconds - $timer.Elapsed.TotalSeconds) * 1000))
    if ($process.WaitForExit([int]$remainingMs)) { $exited = $true; break }
}
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$timer.Stop()
$manifest.elapsedSeconds = $timer.Elapsed.TotalSeconds
$manifest.stoppedAtLimit = -not $exited
$manifest.exitCode = $process.ExitCode
$manifest | ConvertTo-Json | Set-Content (Join-Path $run 'manifest.json')
$manifest | ConvertTo-Json
Get-Content -LiteralPath $stdout -Tail 15
