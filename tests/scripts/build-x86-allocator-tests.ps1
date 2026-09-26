param(
    [string]$SdkVersion = '10.0.28000.0',
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
$out = "$root/build-conformance/x86-allocator-tests"
New-Item -ItemType Directory -Force $out | Out-Null
$inc = @("/I$vc/include", "/I$sdk/Include/$SdkVersion/um", "/I$sdk/Include/$SdkVersion/shared", "/I$sdk/Include/$SdkVersion/ucrt", "/I$root/src", "/I$root/vendor/ia32-doc/out")
$libs = @("/LIBPATH:$vc/lib/x64", "/LIBPATH:$sdk/Lib/$SdkVersion/um/x64", "/LIBPATH:$sdk/Lib/$SdkVersion/ucrt/x64")
$sources = @('src/emu/mmu.cpp', 'src/emu/x86/mmu.cpp', 'tests/emu/x86_allocator_tests.cpp')
Push-Location $out
try {
    $objects = @()
    foreach ($source in $sources) {
        $obj = "$out/" + ($source -replace '[/\\.]', '_') + '.obj'
        & "$vc/bin/Hostx64/x64/cl.exe" /nologo /std:c++20 /EHsc /W4 /MD /O2 /DNOMINMAX /DWIN32_LEAN_AND_MEAN @inc /c "$root/$source" "/Fo$obj"
        if ($LASTEXITCODE) { throw "Compilation failed: $source" }
        $objects += $obj
    }
    $exe = "$out/x86-allocator-tests.exe"
    & "$vc/bin/Hostx64/x64/link.exe" /nologo @objects "/OUT:$exe" @libs
    if ($LASTEXITCODE) { throw 'Allocator test link failed.' }
    if ($Run) {
        $process = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -RedirectStandardOutput "$out/stdout.log" -RedirectStandardError "$out/stderr.log"
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw 'Allocator tests timed out (possible deadlock).'
        }
        $process.WaitForExit()
        Get-Content "$out/stdout.log"
        Get-Content "$out/stderr.log"
        if ($process.ExitCode) { throw 'Allocator tests failed.' }
    }
} finally { Pop-Location }
Write-Output $exe
