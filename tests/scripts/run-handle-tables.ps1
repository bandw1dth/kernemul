#Requires -Version 7.0
param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$kernel = Join-Path $root 'fs_x86_64\Windows\System32\ntoskrnl.exe'
$pinnedKernelHash = '75665496A75FC020A0573523F3F77D7C719479ACEB5806A98D82FF2D1B5314A1'
$kernelHash = (Get-FileHash -LiteralPath $kernel -Algorithm SHA256).Hash
if ($kernelHash -ne $pinnedKernelHash) { throw 'Private handle-table RVAs require the pinned kernel SHA256.' }
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$fixtures = [ordered]@{}
foreach ($name in @('handle_table_conformance.sys', 'handle_user_a.exe', 'handle_user_b.exe')) {
    $fixture = Join-Path $root "build-conformance\$name"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
    $guest = Join-Path $root "fs_x86_64\$name"
    $fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
    Copy-Item -LiteralPath $fixture -Destination $guest -Force
    $guestHash = (Get-FileHash -LiteralPath $guest).Hash
    $fixtures[$name] = [ordered]@{ Source = $fixture; Guest = $guest; HashBefore = $fixtureHash; GuestHashBefore = $guestHash }
}
$prefix = Join-Path $root ("build-conformance\handle-tables-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$out = "$prefix.stdout.log"
$err = "$prefix.stderr.log"
$manifestPath = "$prefix.json"
# Execute only the emulator; all three fixtures are guest images.
$arguments = 'handle_table_conformance.sys handle_user_a.exe handle_user_b.exe'
$process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$log = [string](Get-Content -LiteralPath $out -Raw)
$errorLog = [string](Get-Content -LiteralPath $err -Raw)
$passed = $exited -and $process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorLog)
# Callback/monitor scheduling may interleave markers. Require complete successful assertions.
$expected = @('READY', 'COMPLETE')
$actual = @([regex]::Matches($log, 'DbgPrint: HANDLE_TABLES ([A-Z0-9_]+)\b') | ForEach-Object { $_.Groups[1].Value })
foreach ($marker in $expected) {
    if (@($actual | Where-Object { $_ -ceq $marker }).Count -ne 1) { $passed = $false }
}
$driverSource = Join-Path $root 'tests\drivers\handle_table_conformance.c'
# Derive the full assertion set from this fixture; repeated loop/context assertions are valid.
$expectedAssertions = @([regex]::Matches((Get-Content -LiteralPath $driverSource -Raw), '"([a-z][a-z0-9-]+)"\s*\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$requiredReferenceAssertions = @(
    'table-ref-release-export', 'table-ref-pinned-image-base', 'table-ref-live-preconditions',
    'table-ref-acquires-process-rundown', 'table-ref-aliased-release-balances',
    'table-ref-null-table-releases-rundown', 'table-ref-foreign-table-releases-rundown',
    'table-ref-active-rundown-refused', 'table-ref-fields-restored'
)
$expectedAssertions = @(@($expectedAssertions) + $requiredReferenceAssertions | Sort-Object -Unique)
$assertions = @([regex]::Matches($log, 'CONFORMANCE PASS ([a-z0-9-]+)\b') | ForEach-Object { $_.Groups[1].Value })
foreach ($assertion in $expectedAssertions) {
    if ($assertion -cnotin $assertions) { $passed = $false }
}
# Each header assertion must cover System, a seeded process, and both real processes.
$processHeaderAssertionCounts = [ordered]@{}
foreach ($assertion in @($expectedAssertions | Where-Object { $_ -clike 'process-*' })) {
    $processHeaderAssertionCounts[$assertion] = @($assertions | Where-Object { $_ -ceq $assertion }).Count
    if ($processHeaderAssertionCounts[$assertion] -ne 4) { $passed = $false }
}
$results = [regex]::Matches($log, 'CONFORMANCE RESULT failures=([0-9]+)\b')
if ($results.Count -ne 1 -or $results[0].Groups[1].Value -ne '0') { $passed = $false }
$terminations = [regex]::Matches($log, 'NtTerminateProcess\(status=0x([0-9A-Fa-f]+)\)')
if ($terminations.Count -ne 2 -or @($terminations | Where-Object { $_.Groups[1].Value -notmatch '^0*[Aa]12[Cc]$' }).Count) { $passed = $false }
# Both CLI subjects must execute identical guest bytes.
# Each native subject checks PreviousMode through NtClose and waits for driver release.
if ($fixtures['handle_user_a.exe'].HashBefore -ne $fixtures['handle_user_b.exe'].HashBefore) { $passed = $false }
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
foreach ($pattern in @('HANDLE_TABLES FAIL', 'CONFORMANCE FAIL', '\[error\]|\[critical\]', '\bunhandled\b', '\bunimplemented\b', 'exception dispatch:', 'forbidden', 'timed out', 'faulted:', 'callback failed', 'DPC dispatch failed')) {
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
$kernelHashAfter = Get-FinalHash $kernel
$hashesStable = $exeHashAfter -eq $exeHash -and $kernelHashAfter -eq $pinnedKernelHash
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
    Kernel = $kernel; PinnedKernelHash = $pinnedKernelHash; KernelHash = $kernelHash; KernelHashAfter = $kernelHashAfter
    Fixtures = $fixtures; HashesStable = $hashesStable; TimeoutSeconds = $TimeoutSeconds
    Markers = $actual; ExpectedMarkers = $expected; MarkerCounts = $markerCounts
    ExpectedAssertions = $expectedAssertions; PassedAssertions = $assertions
    RequiredReferenceAssertions = $requiredReferenceAssertions
    ProcessHeaderAssertionCounts = $processHeaderAssertionCounts
    TerminationStatuses = @($terminations | ForEach-Object { '0x' + $_.Groups[1].Value })
    ForbiddenCounts = $forbiddenCounts; Stdout = $out; Stderr = $err
    KnownLoaderUnsupportedClasses = $unsupportedClasses
    OptionalMissingHookSymbols = $optionalMissingSymbols
    StderrEmpty = [string]::IsNullOrWhiteSpace($errorLog)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
[pscustomobject]@{ Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode; Manifest = $manifestPath; Stdout = $out; Stderr = $err } | Format-List
if (-not $passed) { throw 'Handle table fixture failed; inspect the logs.' }


