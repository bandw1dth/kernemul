#Requires -Version 7.0
param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 25
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$fixtures = [ordered]@{}
foreach ($name in @('ob_notify_user.sys', 'ob_user.exe')) {
    $fixture = Join-Path $root "build-conformance\$name"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
    $guest = Join-Path $root "fs_x86_64\$name"
    $fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
    Copy-Item -LiteralPath $fixture -Destination $guest -Force
    $guestHash = (Get-FileHash -LiteralPath $guest).Hash
    $fixtures[$name] = [ordered]@{ Source = $fixture; Guest = $guest; HashBefore = $fixtureHash; GuestHashBefore = $guestHash }
}
$prefix = Join-Path $root ("build-conformance\ob-user-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$out = "$prefix.stdout.log"
$err = "$prefix.stderr.log"
$manifestPath = "$prefix.json"
# Execute only the emulator; both fixtures are guest images.
$process = Start-Process -FilePath $exe -ArgumentList 'ob_notify_user.sys ob_user.exe' -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$log = [string](Get-Content -LiteralPath $out -Raw)
$errorLog = [string](Get-Content -LiteralPath $err -Raw)
$passed = $exited -and $process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorLog)
$expected = @('READY', 'PRE 1', 'POST 1', 'PRE 2', 'POST 2', 'PRE 3', 'POST 3')
$actual = @([regex]::Matches($log, 'DbgPrint: OB_USER (READY|PRE [0-9]+|POST [0-9]+)\b') | ForEach-Object { $_.Groups[1].Value })
if (($actual -join ',') -cne ($expected -join ',')) { $passed = $false }
$terminations = [regex]::Matches($log, 'NtTerminateProcess\(status=0x([0-9A-Fa-f]+)\)')
if ($terminations.Count -ne 1 -or $terminations[0].Groups[1].Value -ne '0') { $passed = $false }
$forbiddenCounts = [ordered]@{}
# Optional aliases absent from the pinned kernel are reported during hook setup.
# They are not executed by this fixture; runtime calls still fail the checks below.
$optionalSymbolPattern = '(?m)^.*\[error\] symbol ''(KeRaiseIrql|KfLowerIrql|KeRaiseIrqlToSynchLevel)'' not found in ntoskrnl\.exe\r?$'
$optionalMissingSymbols = @([regex]::Matches($log, $optionalSymbolPattern) | ForEach-Object { $_.Groups[1].Value })
$diagnosticLog = [regex]::Replace($log, $optionalSymbolPattern, '')
# Match execution diagnostics, not normal symbol names such as RtlpTimeout or
# RtlpUnhandledExceptionFilter. The process deadline is checked via $exited.
foreach ($pattern in @('OB_USER FAIL', 'CONFORMANCE FAIL', '\[error\]|\[critical\]', 'unhandled (?:page fault|exception)', 'unimplemented function', 'exception dispatch:', 'forbidden', 'timed out', 'faulted:', 'callback failed', 'DPC dispatch failed')) {
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
if (-not $passed) { throw 'OB ring-3 paired fixture failed; inspect the logs.' }
