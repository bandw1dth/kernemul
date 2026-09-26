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
foreach ($name in @('storage_conformance.sys', 'storage_user.exe')) {
    $fixture = Join-Path $root "build-conformance\$name"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
    $guest = Join-Path $root "fs_x86_64\$name"
    $fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
    Copy-Item -LiteralPath $fixture -Destination $guest -Force
    $guestHash = (Get-FileHash -LiteralPath $guest).Hash
    $fixtures[$name] = [ordered]@{ Source = $fixture; Guest = $guest; HashBefore = $fixtureHash; GuestHashBefore = $guestHash }
}
$prefix = Join-Path $root ("build-conformance\storage-user-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$out = "$prefix.stdout.log"
$err = "$prefix.stderr.log"
$manifestPath = "$prefix.json"
# The only host executable is the emulator; both fixtures are guest images.
$arguments = 'storage_conformance.sys storage_user.exe'
$process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
$exited = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
$log = [string](Get-Content -LiteralPath $out -Raw)
$errorLog = [string](Get-Content -LiteralPath $err -Raw)
$passed = $exited -and $process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorLog)

# The kernel driver's StorageControl records precede the native process. Its
# mode-tagged records let this paired runner assert only the USERMODE calls.
$storagePattern = 'StorageControl\(mode=UserMode, code=0x([0-9A-Fa-f]+), property=([0-9]+), ATAcommand=0x([0-9A-Fa-f]+), status=0x([0-9A-Fa-f]+), bytes=([0-9]+)\)'
$storageMatches = [regex]::Matches($log, $storagePattern)
$storage = @($storageMatches | ForEach-Object {
    [pscustomobject]@{
        Code = $_.Groups[1].Value.ToUpperInvariant()
        Property = [UInt64]$_.Groups[2].Value
        ATAcommand = $_.Groups[3].Value.ToUpperInvariant()
        Status = $_.Groups[4].Value.ToUpperInvariant()
        Bytes = [UInt64]$_.Groups[5].Value
    }
})
# All backend calls are logged, including rejected IOSB pointers and overlap.
# Only the null-IOSB call returns at the native boundary before dispatch.
$expected = @(
    @{ Code='2D1400'; Status='0'; Bytes=8 },
    @{ Code='2D1400'; Status='0'; Bytes='descriptor' },
    @{ Code='4D02C'; Status='C0000022'; Bytes=0 },
    @{ Code='4D02C'; Status='C0000022'; Bytes=0 },
    @{ Code='2D1400'; Status='C0000005'; Bytes=0 },
    @{ Code='2D1400'; Status='C0000005'; Bytes=0 },
    @{ Code='2D1400'; Status='C0000005'; Bytes=0 },
    @{ Code='2D1400'; Status='C0000005'; Bytes=0 },
    @{ Code='2D1400'; Status='C0000005'; Bytes=0 },
    @{ Code='2D1400'; Status='C0000005'; Bytes=0 },
    @{ Code='2D1400'; Status='C000000D'; Bytes=0 },
    @{ Code='2D1400'; Status='C000000D'; Bytes=0 },
    @{ Code='4D02C'; Status='0'; Bytes=560 },
    @{ Code='4D02C'; Status='0'; Bytes=560 }
)
$storageChecks = [ordered]@{ ExpectedCount = $expected.Count; ActualCount = $storage.Count; Entries = @() }
if ($storage.Count -ne $expected.Count) { $passed = $false }
for ($i = 0; $i -lt [Math]::Min($storage.Count, $expected.Count); ++$i) {
    $wanted = $expected[$i]
    $actual = $storage[$i]
    $bytesMatch = if ($wanted.Bytes -eq 'descriptor') { $actual.Bytes -ge 40 -and $actual.Bytes -le 512 } else { $actual.Bytes -eq $wanted.Bytes }
    $entryPassed = $actual.Code -ceq $wanted.Code -and $actual.Status -ceq $wanted.Status -and $bytesMatch
    $storageChecks.Entries += [pscustomobject]@{ Index=$i; Expected=$wanted; Actual=$actual; Passed=$entryPassed }
    if (-not $entryPassed) { $passed = $false }
}
$terminations = [regex]::Matches($log, 'NtTerminateProcess\(status=0x([0-9A-Fa-f]+)\)')
if ($terminations.Count -ne 1 -or $terminations[0].Groups[1].Value -notmatch '^0+$') { $passed = $false }

$forbiddenCounts = [ordered]@{}
$optionalSymbolPattern = '(?m)^.*\[error\] symbol ''(KeRaiseIrql|KfLowerIrql|KeRaiseIrqlToSynchLevel)'' not found in ntoskrnl\.exe\r?$'
$optionalMissingSymbols = @([regex]::Matches($log, $optionalSymbolPattern) | ForEach-Object { $_.Groups[1].Value })
$diagnosticLog = [regex]::Replace($log, $optionalSymbolPattern, '')
$unsupportedClasses = @([regex]::Matches($diagnosticLog, 'NtQuerySystemInformation: unhandled class ([0-9]+)') | ForEach-Object { [int]$_.Groups[1].Value })
if (@($unsupportedClasses | Where-Object { $_ -notin @(192, 197) }).Count) { $passed = $false }
$diagnosticLog = [regex]::Replace($diagnosticLog, 'NtQuerySystemInformation: unhandled class (?:192|197)\b', '')
foreach ($pattern in @('CONFORMANCE FAIL', 'STORAGE_USER FAIL', '\[error\]|\[critical\]', '\bunhandled\b', '\bunimplemented\b', 'exception dispatch:', 'forbidden', 'timed out', 'faulted:', 'callback failed', 'DPC dispatch failed')) {
    $forbiddenCounts[$pattern] = [regex]::Matches(($diagnosticLog + "`n" + $errorLog), $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase).Count
    if ($forbiddenCounts[$pattern] -ne 0) { $passed = $false }
}

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
$manifest = [ordered]@{
    Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode
    Executable = $exe; ExecutableHash = $exeHash; ExecutableHashAfter = $exeHashAfter
    Arguments = $arguments; Fixtures = $fixtures; HashesStable = $hashesStable; TimeoutSeconds = $TimeoutSeconds
    UserStorageControls = $storageChecks; TerminationStatuses = @($terminations | ForEach-Object { '0x' + $_.Groups[1].Value })
    ForbiddenCounts = $forbiddenCounts; Stdout = $out; Stderr = $err
    KnownLoaderUnsupportedClasses = $unsupportedClasses; OptionalMissingHookSymbols = $optionalMissingSymbols
    StderrEmpty = [string]::IsNullOrWhiteSpace($errorLog)
}
$manifest | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $manifestPath -Encoding utf8
[pscustomobject]@{ Passed = $passed; Exited = $exited; TimedOut = -not $exited; ExitCode = $process.ExitCode; Manifest = $manifestPath; Stdout = $out; Stderr = $err } | Format-List
if (-not $passed) { throw 'Storage ring-3 paired fixture failed; inspect the logs.' }
