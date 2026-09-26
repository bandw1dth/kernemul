#Requires -Version 7
param([Parameter(Mandatory)][string]$Image)
$ErrorActionPreference = 'Stop'
# Native user-mode reference only: maps data, never calls mapped code or loads a driver.
$path = (Resolve-Path -LiteralPath $Image).Path
$bytes = [IO.File]::ReadAllBytes($path)
$nt = [BitConverter]::ToInt32($bytes, 0x3c)
$sections = [BitConverter]::ToUInt16($bytes, $nt + 6)
$table = $nt + 24 + [BitConverter]::ToUInt16($bytes, $nt + 20)
$codeRva = $null
for ($i = 0; $i -lt $sections; $i++) {
    $entry = $table + 40 * $i
    if ([BitConverter]::ToUInt32($bytes, $entry + 36) -band 0x20000000) {
        $codeRva = [BitConverter]::ToUInt32($bytes, $entry + 12)
        break
    }
}
if ($null -eq $codeRva) { throw 'No executable PE section found.' }
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ImageProtectionReference {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr sa,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateFileMappingW(IntPtr f,IntPtr a,uint p,uint h,uint l,string n);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr MapViewOfFile(IntPtr m,uint a,uint h,uint l,UIntPtr s);
 [DllImport("kernel32.dll")] public static extern bool UnmapViewOfFile(IntPtr p);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
 [DllImport("ntdll.dll")] public static extern uint NtProtectVirtualMemory(IntPtr process,ref IntPtr address,ref UIntPtr size,uint protect,out uint old);
}
'@
$rows = @()
$file = [ImageProtectionReference]::CreateFileW($path,2147483648,7,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
if ($file -eq [IntPtr]::new(-1)) { throw 'CreateFile failed.' }
try {
    foreach ($kind in @('image','noexecute')) {
        $flags = if ($kind -eq 'image') { 0x01000002 } else { 0x11000002 }
        $mapping = [ImageProtectionReference]::CreateFileMappingW($file,[IntPtr]::Zero,$flags,0,0,$null)
        if ($mapping -eq [IntPtr]::Zero) { throw "CreateFileMapping failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
        try {
            foreach ($rva in @(0,$codeRva)) {
                foreach ($protection in @(2,4,0x20,0x40)) {
                    $view = [ImageProtectionReference]::MapViewOfFile($mapping,4,0,0,[UIntPtr]::Zero)
                    if ($view -eq [IntPtr]::Zero) { throw 'MapViewOfFile failed.' }
                    try {
                        $at = [IntPtr]::new($view.ToInt64() + $rva)
                        $size = [UIntPtr]::new(4096)
                        $old = [uint32]0
                        $status = [ImageProtectionReference]::NtProtectVirtualMemory([IntPtr]::new(-1),[ref]$at,[ref]$size,$protection,[ref]$old)
                        $rows += [ordered]@{kind=$kind;rva=$rva;protection=('0x{0:X}' -f $protection);status=('0x{0:X8}' -f $status);previous=('0x{0:X}' -f $old)}
                    } finally { [void][ImageProtectionReference]::UnmapViewOfFile($view) }
                }
            }
        } finally { [void][ImageProtectionReference]::CloseHandle($mapping) }
    }
} finally { [void][ImageProtectionReference]::CloseHandle($file) }
[ordered]@{os=[Environment]::OSVersion.Version.ToString();imageHash=(Get-FileHash -LiteralPath $path).Hash;note='Data mapping only; no mapped code executed.';results=$rows} | ConvertTo-Json -Depth 5
