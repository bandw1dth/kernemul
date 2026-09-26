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
$include = @("/I$vc\include", "/I$sdk\Include\$SdkVersion\um", "/I$sdk\Include\$SdkVersion\shared", "/I$sdk\Include\$SdkVersion\ucrt")
& "$vc\bin\Hostx64\x64\cl.exe" /nologo /c /TC /O1 /GS- /Zl /W4 @include "/Fo$out\handle_user_a.obj" "$root\tests\user\handle_table_user.c"
if ($LASTEXITCODE) { throw 'User fixture compilation failed.' }
& "$vc\bin\Hostx64\x64\ml64.exe" /nologo /c "/Fo$out\handle_cpl.obj" "$root\tests\user\ob_user_cpl.asm"
if ($LASTEXITCODE) { throw 'CPL helper assembly failed.' }
& "$vc\bin\Hostx64\x64\link.exe" /nologo /subsystem:native /entry:entry /nodefaultlib /machine:x64 "/out:$out\handle_user_a.exe" "$out\handle_user_a.obj" "$out\handle_cpl.obj" "$sdk\Lib\$SdkVersion\um\x64\ntdll.lib"
if ($LASTEXITCODE) { throw 'User fixture link failed.' }
Copy-Item -LiteralPath "$out\handle_user_a.exe" -Destination "$out\handle_user_b.exe" -Force
Write-Output "$out\handle_user_a.exe"
Write-Output "$out\handle_user_b.exe"

