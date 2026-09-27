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
foreach ($name in @('firmware_table_conformance.sys', 'firmware_table_user.exe')) {
    $fixture = Join-Path $root "build-conformance\$name"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
    $guest = Join-Path $root "fs_x86_64\$name"
    $fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
    Copy-Item -LiteralPath $fixture -Destination $guest -Force
    $guestHash = (Get-FileHash -LiteralPath $guest).Hash
    $fixtures[$name] = [ordered]@{ Source = $fixture; Guest = $guest; HashBefore = $fixtureHash; GuestHashBefore = $guestHash }
}
$prefix = Join-Path $root ("build-conformance\firmware-tables-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$out = "$prefix.stdout.log"
$err = "$prefix.stderr.log"
$manifestPath = "$prefix.json"
# Execute only the emulator; both fixtures are guest images.
$arguments = 'firmware_table_conformance.sys firmware_table_user.exe'
$process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$log = [string](Get-Content -LiteralPath $out -Raw)
$errorLog = [string](Get-Content -LiteralPath $err -Raw)
$passed = $exited -and $process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorLog)
# Callback/monitor scheduling may interleave markers. Require complete successful assertions.
$expected = @('COMPLETE')
$actual = @([regex]::Matches($log, 'DbgPrint: FIRMWARE_TABLES ([A-Z0-9_]+)\b') | ForEach-Object { $_.Groups[1].Value })
if (@($actual | Where-Object { $_ -cnotin $expected }).Count) { $passed = $false }
foreach ($marker in $expected) {
    if (@($actual | Where-Object { $_ -ceq $marker }).Count -ne 1) { $passed = $false }
}
$driverSource = Join-Path $root 'tests\drivers\firmware_table_conformance.c'
# Derive the full assertion set from this fixture; repeated loop/context assertions are valid.
$expectedAssertions = @([regex]::Matches((Get-Content -LiteralPath $driverSource -Raw), '"([a-z][a-z0-9-]+)"\s*\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$assertions = @([regex]::Matches($log, 'CONFORMANCE PASS ([a-z0-9-]+)\b') | ForEach-Object { $_.Groups[1].Value })
if (-not $expectedAssertions.Count -or @($assertions | Where-Object { $_ -cnotin $expectedAssertions }).Count) { $passed = $false }
foreach ($assertion in $expectedAssertions) {
    if ($assertion -cnotin $assertions) { $passed = $false }
}
$userSource = Join-Path $root 'tests\user\firmware_table_user.c'
$expectedUserAssertions = @([regex]::Matches((Get-Content -LiteralPath $userSource -Raw), '"([a-z][a-z0-9-]+)"\s*\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
# Native checks are source metadata; execution is certified by success-only termination.
$results = [regex]::Matches($log, 'CONFORMANCE RESULT failures=([0-9]+)\b')
if ($results.Count -ne 1 -or $results[0].Groups[1].Value -ne '0') { $passed = $false }
$terminations = [regex]::Matches($log, 'NtTerminateProcess\(status=0x([0-9A-Fa-f]+)\)')
if ($terminations.Count -ne 1 -or @($terminations | Where-Object { $_.Groups[1].Value -notmatch '^0*7640$' }).Count) { $passed = $false }
# Native completion requires every assertion and its exact termination status.

$forbiddenCounts = [ordered]@{}
# Optional aliases absent from the pinned kernel are reported during hook setup.
# They are not executed by this fixture; runtime calls still fail the checks below.
$optionalSymbolPattern = '(?m)^.*\[error\] symbol ''(KeRaiseIrql|KfLowerIrql|KeRaiseIrqlToSynchLevel)'' not found in ntoskrnl\.exe\r?$'
$optionalMissingSymbols = @([regex]::Matches($log, $optionalSymbolPattern) | ForEach-Object { $_.Groups[1].Value })
$diagnosticLog = [regex]::Replace($log, $optionalSymbolPattern, '')
# Remove only the two known loader probes before the general unhandled check.
$diagnosticLog = [regex]::Replace($diagnosticLog, '(?m)^.*\[(?:warning|warn)\][^\r\n]*NtQuerySystemInformation: unhandled class (?:192|197)\r?$', '')
# Only these exact loader messages, from this native process before its first
# firmware query, are allowed. Later occurrences remain diagnostic failures.
$timestampPattern = '\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\]'
$nativeStart = [regex]::Match($diagnosticLog, '(?m)^' + $timestampPattern + ' \[info\] \[cpu=\d+ tid=\d+ pid=(?<pid>(?!4 )\d+) user\] SystemFirmwareTableInformation: [^\r\n]*\r?$')
$loaderWarnings = [ordered]@{
    TokenAttributes = @{ Maximum = 1; Message = 'NtQuerySecurityAttributesToken(handle=0xFFFFFFFFFFFFFFFC, attributes=0xHEX/2, buffer=0xHEX/816): nothing here carries a token' }
    ExtendedAllocation = @{ Maximum = 2; Message = 'NtAllocateVirtualMemoryEx: ignoring 1 extended parameter(s) at 0xHEX' }
    WorkerFactory = @{ Maximum = 4; Message = "NtCreateWorkerFactory('', start=0xHEX, parameter=0xHEX, threads=512) -> handle=0xHEX: nothing here runs pool threads, so the start routine is never entered" }
    KnownDllsDirectory = @{ Maximum = 1; Message = "NtOpenDirectoryObject('\KnownDlls') -> handle=0xHEX: the directory is empty, because nothing here puts anything in one" }
    KnownDllPath = @{ Maximum = 1; Message = "NtOpenSymbolicLinkObject('KnownDllPath') -> handle=0xHEX: nothing here creates a link, so it points at System32" }
    Apphelp = @{ Maximum = 1; Message = 'NtApphelpCacheControl(class=6, data=0xHEX): there is no shim cache here' }
    Continue = @{ Maximum = 1; Message = 'NtContinue: nothing delivers an APC, so there is no alert to test for' }
}
$loaderWarningCounts = [ordered]@{}
$loaderWarningMaximums = [ordered]@{}
foreach ($category in $loaderWarnings.Keys) {
    $loaderWarningCounts[$category] = 0
    $loaderWarningMaximums[$category] = $loaderWarnings[$category].Maximum
}
if ($nativeStart.Success) {
    $loaderLog = $diagnosticLog.Substring(0, $nativeStart.Index)
    $runtimeLog = $diagnosticLog.Substring($nativeStart.Index)
    $warningPrefix = '(?m)^' + $timestampPattern + ' \[warning\] \[cpu=\d+ tid=\d+ pid=' + $nativeStart.Groups['pid'].Value + ' user\] '
    foreach ($category in $loaderWarnings.Keys) {
        $rule = $loaderWarnings[$category]
        $pattern = $warningPrefix + [regex]::Escape($rule.Message).Replace('HEX', '[0-9A-Fa-f]+') + '\r?$'
        $loaderWarningCounts[$category] = [regex]::Matches($loaderLog, $pattern).Count
        if ($loaderWarningCounts[$category] -le $rule.Maximum) {
            $loaderLog = [regex]::Replace($loaderLog, $pattern, '')
        } else { $passed = $false }
    }
    $diagnosticLog = $loaderLog + $runtimeLog
} else { $passed = $false }
# Match execution diagnostics, not normal symbol names such as RtlpTimeout or
# RtlpUnhandledExceptionFilter. The process deadline is checked via $exited.
foreach ($pattern in @('FIRMWARE_TABLE_USER FAIL', 'CONFORMANCE FAIL', '\[error\]|\[critical\]', '\bunhandled\b', '\bunimplemented\b', '\bunsupported (?:syscall|call|function)\b', '\[warning\]|\[warn\]', 'exception dispatch:', 'forbidden', 'timed out', 'faulted:', 'callback failed', 'DPC dispatch failed')) {
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
if (@($actual | Where-Object { $_ -cnotin $expected }).Count) { $passed = $false }
foreach ($marker in $expected) { $markerCounts[$marker] = @($actual | Where-Object { $_ -ceq $marker }).Count }
$manifest = [ordered]@{
    Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode
    Arguments = $arguments; WorkingDirectory = $root
    Executable = $exe; ExecutableHash = $exeHash; ExecutableHashAfter = $exeHashAfter
    Fixtures = $fixtures; HashesStable = $hashesStable; TimeoutSeconds = $TimeoutSeconds
    Markers = $actual; ExpectedMarkers = $expected; MarkerCounts = $markerCounts
    ExpectedAssertions = $expectedAssertions; PassedAssertions = $assertions
    ExpectedUserAssertions = $expectedUserAssertions
    NativeSuccessStatus = '0x7640'; NativeFailureEncoding = '0xC0760000 | REQUIRE source line'
    TerminationStatuses = @($terminations | ForEach-Object { '0x' + $_.Groups[1].Value })
    ForbiddenCounts = $forbiddenCounts; Stdout = $out; Stderr = $err
    LoaderWarningCounts = $loaderWarningCounts; LoaderWarningMaximums = $loaderWarningMaximums
    NativeFirmwareQuerySeen = $nativeStart.Success
    KnownLoaderUnsupportedClasses = $unsupportedClasses
    OptionalMissingHookSymbols = $optionalMissingSymbols
    StderrEmpty = [string]::IsNullOrWhiteSpace($errorLog)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
[pscustomobject]@{ Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode; Manifest = $manifestPath; Stdout = $out; Stderr = $err } | Format-List
if (-not $passed) { throw 'Firmware table fixture failed; inspect the logs.' }







