#Requires -Version 7.0
param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$fixtures = [ordered]@{}
foreach ($name in @('process_notify_conformance.sys', 'process_notify_user.exe', 'process_notify_reject.exe')) {
    $fixture = Join-Path $root "build-conformance\$name"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
    $guest = Join-Path $root "fs_x86_64\$name"
    $fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
    Copy-Item -LiteralPath $fixture -Destination $guest -Force
    $guestHash = (Get-FileHash -LiteralPath $guest).Hash
    $fixtures[$name] = [ordered]@{ Source = $fixture; Guest = $guest; HashBefore = $fixtureHash; GuestHashBefore = $guestHash }
}
$prefix = Join-Path $root ("build-conformance\process-notify-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$out = "$prefix.stdout.log"
$err = "$prefix.stderr.log"
$manifestPath = "$prefix.json"
# Execute only the emulator; all three fixtures are guest images.
$arguments = 'process_notify_conformance.sys process_notify_user.exe process_notify_reject.exe'
$process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$log = [string](Get-Content -LiteralPath $out -Raw)
$errorLog = [string](Get-Content -LiteralPath $err -Raw)
$passed = $exited -and $process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorLog)
# Inter-process scheduling may interleave the rejected attempt with accepted exit.
# Guest assertions enforce ordering within each process; require every marker once.
$expected = @('READY', 'ACCEPT_EX1', 'ACCEPT_EX2', 'CLASSIC_CREATE', 'THREAD_CREATE',
    'IMAGE_EXE', 'IMAGE_NTDLL', 'THREAD_EXIT', 'EXIT_EX1', 'EXIT_EX2', 'CLASSIC_EXIT',
    'REJECT_EX1', 'REJECT_EX2', 'COMPLETE')
$actual = @([regex]::Matches($log, 'DbgPrint: PROCESS_NOTIFY ([A-Z0-9_]+)\b') | ForEach-Object { $_.Groups[1].Value })
foreach ($marker in $expected) {
    if (@($actual | Where-Object { $_ -ceq $marker }).Count -ne 1) { $passed = $false }
}
if ($actual.Count -ne $expected.Count -or $actual[0] -cne 'READY' -or $actual[-1] -cne 'COMPLETE') { $passed = $false }
$results = [regex]::Matches($log, 'CONFORMANCE RESULT failures=([0-9]+)\b')
if ($results.Count -ne 1 -or $results[0].Groups[1].Value -ne '0') { $passed = $false }
$terminations = [regex]::Matches($log, 'NtTerminateProcess\(status=0x([0-9A-Fa-f]+)\)')
if ($terminations.Count -ne 1 -or $terminations[0].Groups[1].Value -notmatch '^0*1234$') { $passed = $false }
# Identical bytes make any accidental rejected-user execution observable as a
# second termination (or a timeout/fault), not a distinct benign test program.
if ($fixtures['process_notify_user.exe'].HashBefore -ne $fixtures['process_notify_reject.exe'].HashBefore) { $passed = $false }
$forbiddenCounts = [ordered]@{}
# Optional aliases absent from the pinned kernel are reported during hook setup.
# They are not executed by this fixture; runtime calls still fail the checks below.
$optionalSymbolPattern = '(?m)^.*\[error\] symbol ''(KeRaiseIrql|KfLowerIrql|KeRaiseIrqlToSynchLevel)'' not found in ntoskrnl\.exe\r?$'
$optionalMissingSymbols = @([regex]::Matches($log, $optionalSymbolPattern) | ForEach-Object { $_.Groups[1].Value })
$diagnosticLog = [regex]::Replace($log, $optionalSymbolPattern, '')
# Remove only the two known loader probes before the general unhandled check.
$diagnosticLog = [regex]::Replace($diagnosticLog, 'NtQuerySystemInformation: unhandled class (?:192|197)\b', '')
# Match execution diagnostics, not normal symbol names such as RtlpTimeout or
# RtlpUnhandledExceptionFilter. The process deadline is checked via $exited.
foreach ($pattern in @('PROCESS_NOTIFY FAIL', 'CONFORMANCE FAIL', '\[error\]|\[critical\]', '\bunhandled\b', '\bunimplemented\b', 'exception dispatch:', 'forbidden', 'timed out', 'faulted:', 'callback failed', 'DPC dispatch failed')) {
    $forbiddenCounts[$pattern] = [regex]::Matches(($diagnosticLog + "`n" + $errorLog), $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase).Count
    if ($forbiddenCounts[$pattern] -ne 0) { $passed = $false }
}
# The native loader probes these two currently unsupported information classes.
# Record that limitation explicitly and reject any different unhandled class.
$unsupportedClasses = @([regex]::Matches($log, 'NtQuerySystemInformation: unhandled class ([0-9]+)') | ForEach-Object { [int]$_.Groups[1].Value })
if (@($unsupportedClasses | Where-Object { $_ -notin @(192, 197) }).Count) { $passed = $false }
# Missing or replaced artifacts also fail stability without preventing the audit record.
function Get-FinalHash([string]$Path) {
    try { (Get-FileHash -LiteralPath $Path -ErrorAction Stop).Hash } catch { $null }
}
$exeHashAfter = Get-FinalHash $exe
$hashesStable = $exeHashAfter -eq $exeHash
foreach ($fixture in $fixtures.Values) {
    $fixture.HashAfter = Get-FinalHash $fixture.Source
    $fixture.GuestHashAfter = Get-FinalHash $fixture.Guest
    $fixture.Stable = $fixture.HashBefore -eq $fixture.HashAfter -and
        $fixture.HashBefore -eq $fixture.GuestHashBefore -and
        $fixture.GuestHashBefore -eq $fixture.GuestHashAfter
    if (-not $fixture.Stable) { $hashesStable = $false }
}
if (-not $hashesStable) { $passed = $false }
$markerCounts = [ordered]@{}
foreach ($marker in $expected) { $markerCounts[$marker] = @($actual | Where-Object { $_ -ceq $marker }).Count }
$manifest = [ordered]@{
    Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode
    Arguments = $arguments; WorkingDirectory = $root
    Executable = $exe; ExecutableHash = $exeHash; ExecutableHashAfter = $exeHashAfter
    Fixtures = $fixtures; HashesStable = $hashesStable; TimeoutSeconds = $TimeoutSeconds
    Markers = $actual; ExpectedMarkers = $expected; MarkerCounts = $markerCounts
    TerminationStatuses = @($terminations | ForEach-Object { '0x' + $_.Groups[1].Value })
    ForbiddenCounts = $forbiddenCounts; Stdout = $out; Stderr = $err
    KnownLoaderUnsupportedClasses = $unsupportedClasses
    OptionalMissingHookSymbols = $optionalMissingSymbols
    StderrEmpty = [string]::IsNullOrWhiteSpace($errorLog)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
[pscustomobject]@{ Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode; Manifest = $manifestPath; Stdout = $out; Stderr = $err } | Format-List
if (-not $passed) { throw 'Process notification fixture failed; inspect the logs.' }

