#Requires -Version 7.0
param(
    [string]$Executable = 'build-x64-whp\Release\kernemul.exe',
    [ValidateSet('callback_failure_delay', 'callback_failure_wait', 'core_failure_unsupported_dpc', 'core_failure_nested_dpc', 'thread_notify_failure_delay', 'thread_notify_failure_remove', 'thread_notify_failure_api', 'thread_notify_failure_suspend')]
    [string[]]$Driver = @('callback_failure_delay', 'callback_failure_wait', 'core_failure_unsupported_dpc', 'core_failure_nested_dpc', 'thread_notify_failure_delay', 'thread_notify_failure_remove', 'thread_notify_failure_api', 'thread_notify_failure_suspend'),
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 25
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = (Resolve-Path (Join-Path $root $Executable)).Path
$exeHash = (Get-FileHash -LiteralPath $exe).Hash
$allPassed = $true
foreach ($name in $Driver) {
    $fixture = Join-Path $root "build-conformance\$name.sys"
    if (-not (Test-Path -LiteralPath $fixture)) { throw "Build conformance drivers first: $fixture" }
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $root "fs_x86_64\$name.sys") -Force
    $prefix = Join-Path $root ("build-conformance\negative-{0}-{1}" -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    $out = "$prefix.stdout.log"
    $err = "$prefix.stderr.log"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $exe -ArgumentList "$name.sys" -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $exited = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $exited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $timer.Stop()
    $log = [string](Get-Content -LiteralPath $out -Raw)
    $errorLog = [string](Get-Content -LiteralPath $err -Raw)
    $required = [ordered]@{}
    if ($name -like 'thread_notify_failure_*') {
        $kind = $name.Substring('thread_notify_failure_'.Length).ToUpperInvariant()
        $tag = "THREAD_NOTIFY_$kind"
        $required.preCreate = "DbgPrint: $tag PRE_CREATE"
        switch ($kind) {
            'DELAY' { $marker='PRE_WAIT'; $diagnostic='thread notify: blocking guest callbacks are unsupported' }
            'REMOVE' { $marker='PRE_REMOVE'; $diagnostic='thread notify: PsRemoveCreateThreadNotifyRoutine: self-removal or callback rundown deadlock' }
            'API' { $marker='PRE_FAULT'; $diagnostic='ntoskrnl\.exe!KeSetTimerEx faulted: negative KeSetTimerEx period' }
            'SUSPEND' { $marker='PRE_SUSPEND'; $diagnostic='thread notify: NtSuspendThread: self-suspension inside a lifecycle callback is unsupported' }
        }
        $required.callbackBegin = "DbgPrint: $tag $marker"
        $required.diagnostic = $diagnostic
        $forbiddenPattern = 'FORBIDDEN_|SETUP_FAILED|CONFORMANCE FAIL'
    } elseif ($name -eq 'core_failure_unsupported_dpc') {
        $required.armed = 'DbgPrint: CONFORMANCE ARMED threadless-unsupported-dpc'
        $required.threadlessBegin = 'tid=0 pid=0 kernel\] DPC begin:'
        $required.callbackBegin = 'DbgPrint: CONFORMANCE BEGIN threadless-unsupported-dpc'
        $required.unsupported = 'unimplemented function ntoskrnl\.exe!KeQueryActiveGroupCount'
        $required.restoredIrql = 'DPC end: [^\r\n]*restored_irql=0 failed'
        $required.dispatchFailure = 'DPC dispatch failed: guest callback stopped before returning'
        $forbiddenPattern = 'unsupported-dpc-AFTER|CONFORMANCE FAIL|DPC end: [^\r\n]* returned'
    } elseif ($name -eq 'core_failure_nested_dpc') {
        $required.armed = 'DbgPrint: NESTED_DPC ARMED returning-driver-entry'
        $required.threadlessBegin = 'tid=0 pid=0 kernel\] DPC begin:'
        $required.preNotify = 'DbgPrint: NESTED_DPC PRE_NOTIFY'
        $required.preUnsupported = 'DbgPrint: NESTED_DPC PRE_UNSUPPORTED'
        $required.unsupported = 'unimplemented function ntoskrnl\.exe!KeQueryActiveGroupCount'
        $required.restoredIrql = 'DPC end: [^\r\n]*restored_irql=0 failed'
        $required.dispatchFailure = 'DPC dispatch failed: guest callback stopped before returning'
        $forbiddenPattern = 'FORBIDDEN_POST_CALLBACK|FORBIDDEN_POST_NOTIFY|SETUP_FAILED|CONFORMANCE FAIL|DPC end: [^\r\n]* returned'
    } else {
        $tag = if ($name -eq 'callback_failure_delay') { 'CALLBACK_DELAY' } else { 'CALLBACK_WAIT' }
        $required.preNotify = "DbgPrint: $tag PRE_NOTIFY"
        $required.preWait = "DbgPrint: $tag PRE_WAIT"
        $required.blockingFailure = 'ExNotifyCallback faulted: ExNotifyCallback: blocking guest callbacks are unsupported'
        $forbiddenPattern = 'FORBIDDEN_POST_WAIT|FORBIDDEN_POST_NOTIFY|SETUP_FAILED|CONFORMANCE FAIL'
    }
    $markers = [ordered]@{}
    $passed = $exited -and $process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorLog)
    foreach ($key in $required.Keys) {
        $markers[$key] = [regex]::Matches($log, $required[$key]).Count
        if ($markers[$key] -ne 1) { $passed = $false }
    }
    $markers.forbidden = [regex]::Matches($log + $errorLog, $forbiddenPattern).Count
    if ($markers.forbidden -ne 0) { $passed = $false }
    $result = [ordered]@{
        executable = $exe; executableSha256 = $exeHash
        driver = $fixture; driverSha256 = (Get-FileHash -LiteralPath $fixture).Hash
        timeoutSeconds = $TimeoutSeconds; elapsedSeconds = $timer.Elapsed.TotalSeconds
        timedOut = -not $exited; exitCode = $process.ExitCode
        markers = $markers; passed = $passed; stdout = $out; stderr = $err
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$prefix.json"
    $result | ConvertTo-Json -Depth 4
    if (-not $passed) { $allPassed = $false }
}
if (-not $allPassed) { exit 1 }
