#Requires -Version 7.0
param([string]$Executable='build-x64-whp\Release\kernemul.exe',
    [ValidateRange(1,30)][int]$TimeoutSeconds=20)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe=(Resolve-Path (Join-Path $root $Executable)).Path
$hash=(Get-FileHash -LiteralPath $exe).Hash
$cases=@(
    @{Name='empty'; Number=1; Reason='detach: unmatched APC state'},
    @{Name='order'; Number=2; Reason='detach: unmatched APC state'},
    @{Name='reuse'; Number=3; Reason='attach: duplicate active APC state'},
    @{Name='irql'; Number=4; Reason='attach: invalid caller, IRQL, or process'},
    @{Name='balance'; Number=5; Reason='callback returned with unbalanced process attachments'},
    @{Name='failure'; Number=6; Reason='KeSetTimerEx faulted: negative KeSetTimerEx period'},
    @{Name='terminate'; Number=7; Reason='thread cannot terminate while attached'},
    @{Name='target'; Number=8; Reason='process attach: invalid caller or process'},
    @{Name='ex_balance'; Number=9; Reason='callback returned with unbalanced process attachments'},
    @{Name='ex_floor'; Number=10; Reason='detach: unmatched APC state, callback boundary, or invalid IRQL'}
)
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$all=$true
foreach ($case in $cases) {
    $driver="attach_negative_$($case.Name).sys"
    $names=@($driver)
    if ($case.Number -in 5,6) { $names += 'process_notify_user.exe' }
    $artifacts=[ordered]@{}
    foreach ($name in $names) {
        $source=Join-Path $root "build-conformance\$name"
        $guest=Join-Path $root "fs_x86_64\$name"
        Copy-Item -LiteralPath $source -Destination $guest -Force
        $artifacts[$name]=[ordered]@{Source=$source;Guest=$guest;Hash=(Get-FileHash -LiteralPath $source).Hash}
    }
    $prefix=Join-Path $root "build-conformance\attach-negative-$stamp-$($case.Name)"
    $out="$prefix.stdout.log"; $err="$prefix.stderr.log"
    # Guest fixture names are arguments to the emulator, never host executables.
    $p=Start-Process -FilePath $exe -ArgumentList $names -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $exited=$p.WaitForExit($TimeoutSeconds*1000)
    if (-not $exited) { Stop-Process -Id $p.Id -Force; $p.WaitForExit() }
    $log=[string](Get-Content -LiteralPath $out -Raw)
    $errors=[string](Get-Content -LiteralPath $err -Raw)
    $begin=[regex]::Matches($log,"DbgPrint: ATTACH_NEGATIVE BEGIN $($case.Number)\b").Count
    $reason=[regex]::Matches($log,$case.Reason).Count
    $rollback=[regex]::Matches($log,'process attach: callback rollback restored depth=0 process=0x[0-9A-Fa-f]+ space=').Count
    $rollbackOk=($case.Number -notin 5,6,9) -or $rollback -eq 1
    $forbidden=[regex]::Matches($log+$errors,'ATTACH_NEGATIVE FORBIDDEN_CONTINUATION|ATTACH_NEGATIVE SETUP_FAILED|user process .*\(pid=|NtTerminateProcess\(').Count
    $stable=(Get-FileHash -LiteralPath $exe).Hash -eq $hash
    foreach ($a in $artifacts.Values) {
        $a.SourceAfter=(Get-FileHash -LiteralPath $a.Source).Hash
        $a.GuestAfter=(Get-FileHash -LiteralPath $a.Guest).Hash
        if ($a.Hash -ne $a.SourceAfter -or $a.Hash -ne $a.GuestAfter) { $stable=$false }
    }
    $passed=$exited -and $p.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace($errors) -and $begin -eq 1 -and $reason -ge 1 -and -not $forbidden -and $stable -and $rollbackOk
    $result=[ordered]@{Case=$case.Name;Passed=$passed;Exited=$exited;ExitCode=$p.ExitCode;Executable=$exe;ExecutableHash=$hash;Arguments=$names;BeginCount=$begin;ReasonCount=$reason;ForbiddenCount=$forbidden;HashesStable=$stable;Artifacts=$artifacts;Stdout=$out;Stderr=$err}
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$prefix.json" -Encoding utf8
    [pscustomobject]@{Case=$case.Name;Passed=$passed;ExitCode=$p.ExitCode;Manifest="$prefix.json"} | Format-List
    if (-not $passed) { $all=$false }
}
if (-not $all) { exit 1 }
