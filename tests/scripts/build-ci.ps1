param([string]$SdkVersion = '10.0.28000.0')
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build-drivers.ps1') -SdkVersion $SdkVersion -Driver ci_conformance
