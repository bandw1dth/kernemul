param([string]$SdkVersion = '10.0.28000.0')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual C++ tools are required.' }
$vcVersion = (Get-Content (Join-Path $vs 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt')).Trim()
$vc = Join-Path $vs "VC\Tools\MSVC\$vcVersion"
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$out = Join-Path $root 'build-conformance'
New-Item -ItemType Directory -Force $out | Out-Null
$sources = @(Get-ChildItem (Join-Path $root 'tests\time\*.cpp') -ErrorAction SilentlyContinue)
if (-not $sources.Count) { throw 'No model tests found.' }
foreach ($source in $sources) {
    $exe = Join-Path $out ($source.BaseName + '.exe')
    $obj = Join-Path $out ($source.BaseName + '.obj')
    & "$vc\bin\Hostx64\x64\cl.exe" /nologo /std:c++latest /EHsc /W4 /MT "/I$root\src" "/I$vc\include" "/I$sdk\Include\$SdkVersion\ucrt" "/I$sdk\Include\$SdkVersion\um" "/I$sdk\Include\$SdkVersion\shared" "/Fo$obj" "/Fe$exe" $source.FullName /link "/LIBPATH:$vc\lib\x64" "/LIBPATH:$sdk\Lib\$SdkVersion\ucrt\x64" "/LIBPATH:$sdk\Lib\$SdkVersion\um\x64"
    if ($LASTEXITCODE) { throw "Compile failed: $($source.Name)" }
    & $exe
    if ($LASTEXITCODE) { throw "Test failed: $($source.Name)" }
}
