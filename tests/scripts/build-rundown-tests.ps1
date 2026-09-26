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
$out = "$root/build-conformance/rundown-tests"
New-Item -ItemType Directory -Force $out | Out-Null
$inc = @("/I$vc/include", "/I$sdk/Include/$SdkVersion/um", "/I$sdk/Include/$SdkVersion/shared", "/I$sdk/Include/$SdkVersion/ucrt", "/I$root/src", "/I$root/vendor/ia32-doc/out", "/I$root/build-x64-whp/vcpkg_installed/x64-windows/include")
$libs = @("/LIBPATH:$vc/lib/x64", "/LIBPATH:$sdk/Lib/$SdkVersion/um/x64", "/LIBPATH:$sdk/Lib/$SdkVersion/ucrt/x64")
$libs += @("/LIBPATH:$root/build-x64-whp/vcpkg_installed/x64-windows/lib", "spdlog.lib", "fmt.lib")
$sources = @('src/emu/mmu.cpp', 'src/emu/x86/mmu.cpp', 'tests/emu/rundown_tests.cpp')
Push-Location $out
try {
    $objects = @()
    foreach ($source in $sources) {
        $obj = "$out/" + ($source -replace '[/\\.]', '_') + '.obj'
        & "$vc/bin/Hostx64/x64/cl.exe" /nologo /std:c++20 /utf-8 /Zc:preprocessor /EHsc /W4 /MD /O2 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /DSPDLOG_FMT_EXTERNAL /DSPDLOG_COMPILED_LIB /DSPDLOG_SHARED_LIB /DFMT_SHARED @inc /c "$root/$source" "/Fo$obj"
        if ($LASTEXITCODE) { throw "Compilation failed: $source" }
        $objects += $obj
    }
    $exe = "$out/rundown-tests.exe"
    & "$vc/bin/Hostx64/x64/link.exe" /nologo @objects "/OUT:$exe" @libs
    if ($LASTEXITCODE) { throw 'Rundown test link failed.' }
    Copy-Item "$root/build-x64-whp/vcpkg_installed/x64-windows/bin/spdlog.dll", "$root/build-x64-whp/vcpkg_installed/x64-windows/bin/fmt.dll" $out -Force
    if ($Run) {
        $process = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -RedirectStandardOutput "$out/stdout.log" -RedirectStandardError "$out/stderr.log"
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw 'Rundown tests timed out (possible deadlock).'
        }
        $process.WaitForExit()
        Get-Content "$out/stdout.log"
        Get-Content "$out/stderr.log"
        if ($process.ExitCode) { throw 'Rundown tests failed.' }
    }
} finally { Pop-Location }
Write-Output $exe
