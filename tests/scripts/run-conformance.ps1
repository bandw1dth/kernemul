param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [string]$Driver = 'timer_conformance',
    [int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$fixture = Join-Path $root "build-conformance\$Driver.sys"
if (-not (Test-Path -LiteralPath $fixture)) { throw 'Build conformance drivers first.' }
Copy-Item -LiteralPath $fixture -Destination (Join-Path $root "fs_x86_64\$Driver.sys") -Force
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$out = Join-Path $root "build-conformance\$Driver-$stamp.stdout.log"
$err = Join-Path $root "build-conformance\$Driver-$stamp.stderr.log"
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $exe -ArgumentList "$Driver.sys" -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$timer.Stop()
$log = Get-Content -LiteralPath $out -Raw
$passed = $exited -and $process.ExitCode -eq 0 -and $log.Contains('CONFORMANCE RESULT failures=0') -and -not $log.Contains('CONFORMANCE FAIL') -and -not $log.Contains('unhandled ') -and -not $log.Contains('unimplemented function') -and -not $log.Contains('DPC dispatch failed')
$result = [ordered]@{
    executable = $exe; executableSha256 = (Get-FileHash -LiteralPath $exe).Hash
    driver = $fixture; driverSha256 = (Get-FileHash -LiteralPath $fixture).Hash
    gitCommit = (& git -C $root rev-parse HEAD); dirty = @(& git -C $root status --porcelain)
    elapsedSeconds = $timer.Elapsed.TotalSeconds; timedOut = -not $exited
    exitCode = $process.ExitCode; passed = $passed; stdout = $out; stderr = $err
}
$result | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $root "build-conformance\$Driver-$stamp.json")
$log -split '\r?\n' | Where-Object { $_ -match 'CONFORMANCE|unhandled |unimplemented function' }
$result | ConvertTo-Json -Depth 4
if (-not $passed) { exit 1 }
