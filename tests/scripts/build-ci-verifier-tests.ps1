param(
    [string]$SdkVersion = '10.0.28000.0',
    [switch]$FixturesOnly,
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual C++ x64 tools are required.' }
$version = (Get-Content "$vs/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").Trim()
$vc = "$vs/VC/Tools/MSVC/$version"
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10'
$out = "$root/build-conformance/ci-host-tests"
New-Item -ItemType Directory -Force $out | Out-Null
$inc = @("/I$vc/include", "/I$sdk/Include/$SdkVersion/um", "/I$sdk/Include/$SdkVersion/shared", "/I$sdk/Include/$SdkVersion/ucrt", "/I$root/src")
$libs = @("/LIBPATH:$vc/lib/x64", "/LIBPATH:$sdk/Lib/$SdkVersion/um/x64", "/LIBPATH:$sdk/Lib/$SdkVersion/ucrt/x64", 'crypt32.lib', 'wintrust.lib', 'bcrypt.lib', 'advapi32.lib')
Push-Location $out
try {
    $sources = @("$root/tests/ci/verifier_tests.cpp")
    $exe = "$out/ci-verifier-tests.exe"
    if ($FixturesOnly) {
        $inc += '/DCI_FIXTURE_PROBE'
        $exe = "$out/ci-fixture-probe.exe"
    } else { $sources += "$root/src/kernel/win/code_integrity.cpp" }
    & "$vc/bin/Hostx64/x64/cl.exe" /nologo /std:c++20 /EHsc /W4 /MD /DNOMINMAX /DWIN32_LEAN_AND_MEAN @inc @sources "/Fe$exe" /link @libs
    if ($LASTEXITCODE) { throw 'Host verifier test compilation failed.' }
    if ($Run) {
        & $exe "$root/build-conformance/ci-fixtures"
        if ($LASTEXITCODE) { throw 'Host verifier tests failed.' }
    }
} finally { Pop-Location }
Write-Output $exe
