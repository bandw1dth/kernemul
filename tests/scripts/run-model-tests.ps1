param([string]$SdkVersion = '10.0.28000.0', [string]$BuildDirectory = 'build-x64-whp')
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
    $extra = @()
    $runtime = '/MT'
    $libraries = @()
    if ($source.BaseName -eq 'filesystem_catalog_model') {
        # Match production logging: header-only spdlog pulls host Windows types
        # into the same translation unit as the guest kernel ABI declarations.
        $deps = "$root\$BuildDirectory\vcpkg_installed\x64-windows"
        $extra = @("$root\src\kernel\win\filesystem.cpp", "/I$deps\include", '/DSPDLOG_COMPILED_LIB', '/DSPDLOG_SHARED_LIB', '/DSPDLOG_FMT_EXTERNAL', '/DFMT_SHARED', '/DNOMINMAX', '/DKERNEMUL_ARCH_X64=1', '/Zc:preprocessor')
        $extra += '/utf-8'
        $runtime = '/MD'
        $libraries = @("$deps\lib\spdlog.lib", "$deps\lib\fmt.lib")
        Copy-Item "$deps\bin\spdlog.dll", "$deps\bin\fmt.dll" $out -Force
        $obj = "$out\"
    }
    if ($source.BaseName -eq 'win_user_mem_model') {
        # Compile the actual allocator, using the configured build's logging headers.
        $extra = @("$root\src\kernel\win\win_user_mem.cpp", "/I$root\$BuildDirectory\vcpkg_installed\x64-windows\include", '/DSPDLOG_USE_STD_FORMAT', '/Zc:preprocessor')
        $obj = "$out\"
    }
    if ($source.BaseName -eq 'registry_value_model') {
        # Exercise the production registry store and its copied-value synchronization.
        $extra = @("$root\src\kernel\win\registry.cpp", "/I$root\$BuildDirectory\vcpkg_installed\x64-windows\include", '/DSPDLOG_USE_STD_FORMAT', '/Zc:preprocessor')
        $obj = "$out\"
    }
    & "$vc\bin\Hostx64\x64\cl.exe" /nologo /std:c++latest /EHsc /W4 $runtime "/I$root\src" "/I$root\vendor\pe\src" "/I$vc\include" "/I$sdk\Include\$SdkVersion\ucrt" "/I$sdk\Include\$SdkVersion\um" "/I$sdk\Include\$SdkVersion\shared" "/Fo$obj" "/Fe$exe" $source.FullName @extra /link @libraries "/LIBPATH:$vc\lib\x64" "/LIBPATH:$sdk\Lib\$SdkVersion\ucrt\x64" "/LIBPATH:$sdk\Lib\$SdkVersion\um\x64"
    if ($LASTEXITCODE) { throw "Compile failed: $($source.Name)" }
    & $exe
    if ($LASTEXITCODE) { throw "Test failed: $($source.Name)" }
}
