#Requires -Version 7.0
param([string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateRange(1,30)][int]$TimeoutSeconds = 30)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$token = [Guid]::NewGuid().ToString('N')
$malformed = "process-malformed-$token.exe"
$missing = "process-missing-$token.exe"
# Keep this two-byte input below sizeof(DOS_HEADER): this is a setup-failure
# test, not a test of the legacy PE parser's malformed-header bounds handling.
$malformedPath = Join-Path $root "fs_x86_64\$malformed"
[IO.File]::WriteAllBytes($malformedPath, [byte[]](0x4d,0x5a))
$cases = @(
    @{Name='delay'; Number=1; Reason='thread notify: process callback cannot delay execution'},
    @{Name='remove'; Number=2; Reason='thread notify: process callback removal inside lifecycle callback is unsupported'},
    @{Name='api'; Number=3; Reason='ntoskrnl\.exe!KeSetTimerEx faulted: negative KeSetTimerEx period'},
    @{Name='metadata'; Number=4; Reason='thread notify: process callback rewrote immutable creation metadata'},
    @{Name='exit'; Number=5; Reason='thread notify: process callback cannot delay execution'},
    @{Name='driver_failure'}, @{Name='malformed'}, @{Name='missing'}
)
$allPassed = $true
foreach ($case in $cases) {
    $artifacts = [ordered]@{}
    $required = [ordered]@{}
    $forbidden = 'PROCESS_NEGATIVE FORBIDDEN_CONTINUATION|PROCESS_NEGATIVE SETUP_FAILED'
    $expectedTerminations = 0
    if ($case.Number) {
        $names = @("process_notify_failure_$($case.Name).sys", 'process_notify_user.exe')
        $required.Ready = 'DbgPrint: PROCESS_NEGATIVE READY\b'
        $required.Begin = "DbgPrint: PROCESS_NEGATIVE BEGIN $($case.Number)\b"
        $required.Reason = $case.Reason
        if ($case.Name -ne 'metadata') {
            $required.Stopped = 'lifecycle notify: callback failed before returning; stopped'
            $required.Restored = 'process notify: restored irql=0, kernel_apc_disable=0, special_apc_disable=0'
        } else { $required.Mutated = 'DbgPrint: PROCESS_NEGATIVE MUTATED\b' }
        $forbidden += '|process notify END: kind=exit|process lifecycle unpublish:.*state=exiting'
        if ($case.Name -eq 'exit') { $expectedTerminations = 1 }
        else { $forbidden += '|user process .*\(pid=' }
    } elseif ($case.Name -eq 'driver_failure') {
        $names = @('process_notify_driver_failure.sys', 'process_notify_user.exe')
        $required.Wait = 'DbgPrint: PROCESS_LAUNCH DRIVER_WAIT\b'
        $required.Failed = 'DbgPrint: PROCESS_LAUNCH DRIVER_FAILED\b'
        $required.Gated = 'not launched: driver initialization failed'
        $forbidden += '|user process .*\(pid=|process notify BEGIN:'
    } elseif ($case.Name -eq 'malformed') {
        $names = @($malformed)
        $required.Status = 'launch ' + [regex]::Escape($malformed) + ': status=0xC000007B'
        $forbidden += '|user process .*\(pid='
    } else {
        $names = @($missing)
        $required.Missing = [regex]::Escape($missing) + ' is not in '
        $forbidden += '|user process .*\(pid='
    }
    foreach ($name in $names) {
        if ($name -eq $missing) { continue }
        $guest = Join-Path $root "fs_x86_64\$name"
        $source = if ($name -eq $malformed) { $malformedPath } else { Join-Path $root "build-conformance\$name" }
        if ($source -ne $guest) { Copy-Item -LiteralPath $source -Destination $guest -Force }
        $artifacts[$name] = [ordered]@{Source=$source; Guest=$guest;
            SourceHash=(Get-FileHash -LiteralPath $source).Hash; GuestHash=(Get-FileHash -LiteralPath $guest).Hash}
    }
    $prefix = Join-Path $root "build-conformance\process-negative-$stamp-$($case.Name)"
    $out = "$prefix.stdout.log"
    $err = "$prefix.stderr.log"
    # The only host executable is the emulator. Every fixture is a guest argument.
    $process = Start-Process -FilePath $exe -ArgumentList $names -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $exited = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $log = [string](Get-Content -LiteralPath $out -Raw)
    $errorLog = [string](Get-Content -LiteralPath $err -Raw)
    $passed = $exited -and $process.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace($errorLog)
    $counts = [ordered]@{}
    $positions = @{}
    foreach ($key in $required.Keys) {
        $matches = [regex]::Matches($log, $required[$key])
        $counts[$key] = $matches.Count
        $positions[$key] = if ($matches.Count) { $matches[0].Index } else { -1 }
        if ($matches.Count -ne 1) { $passed = $false }
    }
    if ($case.Number -and -not ($positions.Ready -lt $positions.Begin -and $positions.Begin -lt $positions.Reason)) { $passed = $false }
    if ($case.Name -eq 'metadata' -and -not ($positions.Begin -lt $positions.Mutated -and $positions.Mutated -lt $positions.Reason)) { $passed = $false }
    if ($case.Name -eq 'driver_failure' -and -not ($positions.Wait -lt $positions.Failed -and $positions.Failed -lt $positions.Gated)) { $passed = $false }
    $forbiddenCount = [regex]::Matches($log + $errorLog, $forbidden).Count
    $terminations = [regex]::Matches($log, 'NtTerminateProcess\(status=0x([0-9A-Fa-f]+)\)')
    if ($forbiddenCount -or $terminations.Count -ne $expectedTerminations) { $passed = $false }
    if ($expectedTerminations -eq 1 -and $terminations.Count -eq 1 -and
        ($terminations[0].Groups[1].Value -notmatch '^0*1234$' -or $terminations[0].Index -gt $positions.Begin)) { $passed = $false }
    $exeAfter = (Get-FileHash -LiteralPath $exe).Hash
    $stable = $exeAfter -eq $exeHash
    foreach ($artifact in $artifacts.Values) {
        $artifact.SourceHashAfter = (Get-FileHash -LiteralPath $artifact.Source).Hash
        $artifact.GuestHashAfter = (Get-FileHash -LiteralPath $artifact.Guest).Hash
        if ($artifact.SourceHash -ne $artifact.GuestHash -or $artifact.SourceHashAfter -ne $artifact.SourceHash -or $artifact.GuestHashAfter -ne $artifact.GuestHash) { $stable = $false }
    }
    if (-not $stable) { $passed = $false }
    $result = [ordered]@{Case=$case.Name; Passed=$passed; Exited=$exited; TimedOut=(-not $exited); ExitCode=$process.ExitCode;
        Executable=$exe; ExecutableHash=$exeHash; ExecutableHashAfter=$exeAfter; Arguments=$names;
        Markers=$counts; ForbiddenCount=$forbiddenCount; TerminationCount=$terminations.Count; HashesStable=$stable;
        Artifacts=$artifacts; Stdout=$out; Stderr=$err}
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$prefix.json" -Encoding utf8
    [pscustomobject]@{Case=$case.Name; Passed=$passed; ExitCode=$process.ExitCode; Manifest="$prefix.json"} | Format-List
    if (-not $passed) { $allPassed = $false }
}
# Retain the uniquely named malformed guest artifact with its manifest for audit.
if (-not $allPassed) { exit 1 }
