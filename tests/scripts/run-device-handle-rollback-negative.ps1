#Requires -Version 7.0
param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateRange(1,30)][int]$TimeoutSeconds = 20
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$fixture = Join-Path $root 'build-conformance\device_handle_rollback_negative.sys'
$guest = Join-Path $root 'fs_x86_64\device_handle_rollback_negative.sys'
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
Copy-Item -LiteralPath $fixture -Destination $guest -Force
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$prefix = Join-Path $root "build-conformance\device-handle-rollback-negative-$stamp"
$out = "$prefix.stdout.log"
$err = "$prefix.stderr.log"
# The driver is an emulator argument; never load it into the host kernel.
$p = Start-Process -FilePath $exe -ArgumentList 'device_handle_rollback_negative.sys' -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $p.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $p.Id -Force; $p.WaitForExit() }
$log = [string](Get-Content -LiteralPath $out -Raw)
$errors = [string](Get-Content -LiteralPath $err -Raw)
$patterns = @(
    'DbgPrint: DEVICE_ROLLBACK_NEGATIVE BEGIN\r?$',
    'DbgPrint: DEVICE_ROLLBACK_NEGATIVE DISPATCH sequence=1 create=1 cleanup=0 close=0 failures=0\r?$',
    'DbgPrint: DEVICE_ROLLBACK_NEGATIVE DISPATCH sequence=2 create=1 cleanup=1 close=0 failures=0\r?$',
    'DbgPrint: DEVICE_ROLLBACK_NEGATIVE DISPATCH sequence=3 create=1 cleanup=1 close=1 failures=0\r?$',
    'ntoskrnl(?:\.exe)?!(?:Nt|Zw)OpenFile faulted: unmapped virtual address\r?$'
)
$ordered = $true
$last = -1
$evidence = @()
foreach ($pattern in $patterns) {
    $hits = [regex]::Matches($log, $pattern, [Text.RegularExpressions.RegexOptions]::Multiline)
    $index = if ($hits.Count -eq 1) { $hits[0].Index } else { -1 }
    if ($hits.Count -ne 1 -or $index -le $last) { $ordered = $false }
    $last = $index
    $evidence += [ordered]@{ Pattern=$pattern; Count=$hits.Count; Index=$index }
}
$dispatchCount = [regex]::Matches($log, 'DbgPrint: DEVICE_ROLLBACK_NEGATIVE DISPATCH').Count
$faultCount = [regex]::Matches($log, 'faulted:').Count
$forbidden = [regex]::Matches($log + $errors, 'FORBIDDEN_CONTINUATION|UNEXPECTED_COMPLETION|CONFORMANCE FAIL|CONFORMANCE RESULT|unhandled |unimplemented function|rollback IRP .* failed|DPC dispatch failed').Count
$stable = (Get-FileHash -LiteralPath $exe).Hash -eq $exeHash -and
    (Get-FileHash -LiteralPath $fixture).Hash -eq $fixtureHash -and
    (Get-FileHash -LiteralPath $guest).Hash -eq $fixtureHash
$passed = $exited -and $p.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace($errors) -and
    $ordered -and $dispatchCount -eq 3 -and $faultCount -eq 1 -and $forbidden -eq 0 -and $stable
$result = [ordered]@{
    Passed=$passed; Exited=$exited; ExitCode=$p.ExitCode; Executable=$exe; ExecutableHash=$exeHash
    Driver=$fixture; DriverHash=$fixtureHash; HashesStable=$stable; Ordered=$ordered
    DispatchCount=$dispatchCount; FaultCount=$faultCount; ForbiddenCount=$forbidden
    Evidence=$evidence; Stdout=$out; Stderr=$err
}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$prefix.json" -Encoding utf8
$result | ConvertTo-Json -Depth 5
if (-not $passed) { exit 1 }
