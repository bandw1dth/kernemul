#Requires -Version 7.0
param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateSet('wait', 'delay', 'yield', 'poll', 'fatal')]
    [string[]]$Case = @('wait', 'delay', 'yield', 'poll', 'fatal'),
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$allPassed = $true
foreach ($kind in $Case) {
    $name = "irql_failure_$kind"
    $fixture = Join-Path $root "build-conformance\$name.sys"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $root "fs_x86_64\$name.sys") -Force
    $prefix = Join-Path $root ("build-conformance\{0}-{1}" -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    $out = "$prefix.stdout.log"
    $err = "$prefix.stderr.log"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    # Only the emulator is executed. The .sys is a guest filesystem input.
    $process = Start-Process -FilePath $exe -ArgumentList "$name.sys" -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $exited = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $timer.Stop()
    $log = [string](Get-Content -LiteralPath $out -Raw)
    $errorLog = [string](Get-Content -LiteralPath $err -Raw)
    $marker = 'IRQL_NEGATIVE PRE_' + $kind.ToUpperInvariant()
    $diagnostic = switch ($kind) {
        # These exports alias the same hook address in the mapped kernel.
        'wait' { 'KeWaitFor(Single|Mutex)Object faulted: current execution level cannot block or yield' }
        'delay' { 'KeDelayExecutionThread faulted: current execution level cannot block or yield' }
        'yield' { '(Nt|Zw)YieldExecution faulted: current execution level cannot block or yield' }
        'poll' { 'KeWaitFor(Single|Mutex)Object faulted: IRQL above DISPATCH_LEVEL cannot poll a wait' }
        'fatal' { 'unhandled page fault on cpu 0' }
    }
    $before = $log.IndexOf($marker, [StringComparison]::Ordinal)
    $fault = [regex]::Match($log, $diagnostic)
    $passed = $exited -and $process.ExitCode -eq 1 -and
        [string]::IsNullOrWhiteSpace($errorLog) -and
        ([regex]::Matches($log, [regex]::Escape($marker)).Count -eq 1) -and
        $fault.Success -and $fault.Index -gt $before -and
        ($log -notmatch 'FORBIDDEN_RETURN|unimplemented function|CONFORMANCE FAIL')
    # A watchdog kill is a failed test, including for the fatal-stop case.
    $result = [ordered]@{
        executable = $exe; executableSha256 = $exeHash
        driver = $fixture; driverSha256 = (Get-FileHash -LiteralPath $fixture).Hash
        elapsedSeconds = $timer.Elapsed.TotalSeconds; timeoutSeconds = $TimeoutSeconds
        timedOut = -not $exited; exitCode = $process.ExitCode; passed = $passed
        preOperation = $before -ge 0; expectedDiagnostic = $fault.Success
        stdout = $out; stderr = $err
    }
    $result | ConvertTo-Json | Set-Content -LiteralPath "$prefix.json"
    $result | ConvertTo-Json
    if (-not $passed) { $allPassed = $false }
}
if (-not $allPassed) { exit 1 }
