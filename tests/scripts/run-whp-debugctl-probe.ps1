#Requires -Version 7.0
param(
    [string]$SdkVersion = '10.0.28000.0',
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$out = Join-Path $root 'build-conformance'
New-Item -ItemType Directory -Force $out | Out-Null
$prefix = Join-Path $out ("whp-debugctl-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), $PID)
$source = Join-Path $root 'tests\whp\debugctl_probe.cpp'
$exe = "$prefix.exe"
$manifestPath = "$prefix.json"
$manifest = [ordered]@{
    Passed = $false; Status = 'HarnessError'; Error = $null
    OSVersion = [Environment]::OSVersion.VersionString
    ProcessIsAdministrator = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    WinHvPlatformFileVersion = (Get-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\WinHvPlatform.dll') -ErrorAction SilentlyContinue).VersionInfo.FileVersion
    SdkVersion = $SdkVersion; Compiler = $null; CompileExitCode = $null
    Source = $source; SourceHash = $null; SourceHashAfter = $null
    Executable = $exe; ExecutableHash = $null; ExecutableHashAfter = $null
    HashesStable = $false; TimeoutSeconds = $TimeoutSeconds
    Exited = $false; TimedOut = $false; ExitCode = $null
    CapabilityStatus = 'Unknown'; CapabilityRecords = @(); FindingRecords = @()
    BuildLog = "$prefix.build.log"; Stdout = "$prefix.stdout.log"; Stderr = "$prefix.stderr.log"
}
$process = $null
try {
    $manifest.SourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Visual C++ tools are required.' }
    $vcVersion = (Get-Content (Join-Path $vs 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt')).Trim()
    $vc = Join-Path $vs "VC\Tools\MSVC\$vcVersion"
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
    $manifest.Compiler = "$vc\bin\Hostx64\x64\cl.exe"
    $include = @("/I$vc\include", "/I$sdk\Include\$SdkVersion\um", "/I$sdk\Include\$SdkVersion\shared", "/I$sdk\Include\$SdkVersion\ucrt")
    & $manifest.Compiler /nologo /std:c++17 /EHsc /W4 /MT @include "/Fo$prefix.obj" "/Fe$exe" $source /link WinHvPlatform.lib "/LIBPATH:$vc\lib\x64" "/LIBPATH:$sdk\Lib\$SdkVersion\ucrt\x64" "/LIBPATH:$sdk\Lib\$SdkVersion\um\x64" 2>&1 | Set-Content -LiteralPath $manifest.BuildLog
    $manifest.CompileExitCode = $LASTEXITCODE
    if ($LASTEXITCODE) { throw "Compile failed; inspect $($manifest.BuildLog)" }
    $manifest.ExecutableHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    # This host program uses WHP only. It loads no guest kernel or driver.
    $process = Start-Process -FilePath $exe -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $manifest.Stdout -RedirectStandardError $manifest.Stderr -PassThru
    $manifest.Exited = $process.WaitForExit($TimeoutSeconds * 1000)
    $manifest.TimedOut = -not $manifest.Exited
    if ($manifest.TimedOut) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $manifest.ExitCode = $process.ExitCode
    $log = [string](Get-Content -LiteralPath $manifest.Stdout -Raw)
    $errorLog = [string](Get-Content -LiteralPath $manifest.Stderr -Raw)
    $manifest.CapabilityRecords = @([regex]::Matches($log, '(?m)^CAP .*\r?$') | ForEach-Object { $_.Value.TrimEnd() })
    $manifest.FindingRecords = @([regex]::Matches($log, '(?m)^(?:FINDING|RESULT|LBR|.*REJECTED).*\r?$') | ForEach-Object { $_.Value.TrimEnd() })
    # Preserve raw HRESULTs and explicit unknowns instead of interpreting missing data as zero.
    if ($manifest.CapabilityRecords.Count) { $manifest.CapabilityStatus = 'Recorded; inspect CapabilityRecords for per-query status' }
    $manifest.SourceHashAfter = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $manifest.ExecutableHashAfter = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    $manifest.HashesStable = $manifest.SourceHash -eq $manifest.SourceHashAfter -and $manifest.ExecutableHash -eq $manifest.ExecutableHashAfter
    $manifest.Passed = $manifest.Exited -and $manifest.ExitCode -eq 0 -and $manifest.HashesStable -and [string]::IsNullOrWhiteSpace($errorLog)
    $manifest.Status = if ($manifest.TimedOut) { 'TimedOut' } elseif ($manifest.Passed) { 'Completed' } else { 'Failed' }
} catch {
    $manifest.Error = $_.Exception.Message
} finally {
    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    if ($process) { $process.Dispose() }
}
[pscustomobject]@{ Passed = $manifest.Passed; Status = $manifest.Status; ExitCode = $manifest.ExitCode; Manifest = $manifestPath; Stdout = $manifest.Stdout; Stderr = $manifest.Stderr } | Format-List
if (-not $manifest.Passed) { throw "WHP DEBUGCTL probe failed: $($manifest.Error); inspect $manifestPath" }
