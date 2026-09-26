param([string]$SdkVersion = '10.0.28000.0', [string]$Driver = '*')
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
$include = @("/I$vc\include", "/I$sdk\Include\$SdkVersion\km", "/I$sdk\Include\$SdkVersion\shared", "/I$sdk\Include\$SdkVersion\ucrt")
$sources = @(Get-ChildItem (Join-Path $root "tests\drivers\$Driver.c"))
if (-not $sources.Count) { throw "No guest fixtures match: $Driver" }
foreach ($source in $sources) {
    $obj = Join-Path $out ($source.BaseName + '.obj')
    $sys = Join-Path $out ($source.BaseName + '.sys')
    & "$vc\bin\Hostx64\x64\cl.exe" /nologo /c /TC /O1 /GS- /Zl /W4 /D_AMD64_ /DAMD64 /D_KERNEL_MODE @include "/Fo$obj" $source.FullName
    if ($LASTEXITCODE) { throw "Compile failed: $($source.Name)" }
    $extraObjects = @()
    if ($source.BaseName -eq 'exception_conformance') {
        $asmObj = Join-Path $out 'exception_conformance_asm.obj'
        & "$vc\bin\Hostx64\x64\ml64.exe" /nologo /c "/Fo$asmObj" (Join-Path $source.DirectoryName 'exception_conformance.asm')
        if ($LASTEXITCODE) { throw 'Exception fixture assembly failed.' }
        $extraObjects += $asmObj
    }
    $extraLibraries = @()
    $extraLinkFlags = @()
    # Ex process-notify registration checks the containing image's FORCE_INTEGRITY bit.
    # This sets the PE characteristic; it does not sign or install a host driver.
    if ($source.BaseName -like 'process_notify_*' -and $source.BaseName -ne 'process_notify_integrity') {
        $extraLinkFlags += '/integritycheck'
    }
    if ($source.BaseName -like 'ci_*') {
        $ciLibrary = Join-Path $out 'ci_fixture.lib'
        & "$vc\bin\Hostx64\x64\lib.exe" /nologo /machine:x64 "/def:$root\tests\drivers\ci_exports.def" "/out:$ciLibrary"
        if ($LASTEXITCODE) { throw 'CI fixture import library failed.' }
        $extraLibraries += $ciLibrary
    }
    & "$vc\bin\Hostx64\x64\link.exe" /nologo /driver /subsystem:native /entry:DriverEntry /nodefaultlib /machine:x64 "/out:$sys" $obj @extraObjects "$sdk\Lib\$SdkVersion\km\x64\ntoskrnl.lib" "$sdk\Lib\$SdkVersion\km\x64\hal.lib" @extraLibraries @extraLinkFlags
    if ($LASTEXITCODE) { throw "Link failed: $($source.Name)" }
    Write-Output $sys
}
