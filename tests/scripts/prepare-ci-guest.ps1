#Requires -Version 7.0
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# Read catalog membership with the host SDK; this does not add catalogs or roots.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CiCatalogFixture {
  [StructLayout(LayoutKind.Sequential)] public struct Blob { public uint Size; public IntPtr Data; }
  [StructLayout(LayoutKind.Sequential)] public struct Attribute { public IntPtr Oid; public Blob Value; }
  [StructLayout(LayoutKind.Sequential)] public struct Algorithm { public IntPtr Oid; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] public struct Indirect { public Attribute Data; public Algorithm Algorithm; public Blob Digest; }
  [StructLayout(LayoutKind.Sequential)] public struct Member {
    public uint Size; public IntPtr Tag, File; public Guid Subject; public uint Flags;
    public IntPtr Indirect; public uint Version, Reserved; public IntPtr Handle;
    public Blob EncodedIndirect, EncodedMember;
  }
  [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr CryptCATOpen(string path, uint flags, IntPtr provider, uint version, uint encoding);
  [DllImport("wintrust.dll")] static extern IntPtr CryptCATEnumerateMember(IntPtr catalog, IntPtr previous);
  [DllImport("wintrust.dll")] static extern bool CryptCATClose(IntPtr catalog);
  public static byte[] FirstDigest(string path) {
    IntPtr cat=CryptCATOpen(path,4,IntPtr.Zero,0,0);
    if(cat==IntPtr.Zero || cat==new IntPtr(-1)) return null;
    try {
      IntPtr member=IntPtr.Zero;
      while((member=CryptCATEnumerateMember(cat,member))!=IntPtr.Zero) {
        var m=Marshal.PtrToStructure<Member>(member);
        if(m.Indirect==IntPtr.Zero) continue;
        var d=Marshal.PtrToStructure<Indirect>(m.Indirect);
        string oid=Marshal.PtrToStringAnsi(d.Algorithm.Oid);
        uint alg=oid=="2.16.840.1.101.3.4.2.1" ? 0x800cu : oid=="1.3.14.3.2.26" ? 0x8004u : 0;
        uint expected=alg==0x800c ? 32u : 20u;
        if(alg==0 || d.Digest.Size!=expected || d.Digest.Data==IntPtr.Zero) continue;
        byte[] output=new byte[8+expected];
        Buffer.BlockCopy(BitConverter.GetBytes(alg),0,output,0,4);
        Buffer.BlockCopy(BitConverter.GetBytes(expected),0,output,4,4);
        Marshal.Copy(d.Digest.Data,output,8,(int)expected);
        return output;
      }
    } finally { CryptCATClose(cat); }
    return null;
  }
}
'@
$output=Join-Path $root 'fs_x86_64/ci_catalog_input.bin'
foreach($file in (Get-ChildItem (Join-Path $root 'fs_x86_64/Windows/System32/catroot') -File -Recurse -Filter '*.cat' | Sort-Object FullName)) {
    $bytes=[CiCatalogFixture]::FirstDigest($file.FullName)
    if($null -eq $bytes) { continue }
    [IO.File]::WriteAllBytes($output,$bytes)
    $evidence=[ordered]@{Catalog=$file.FullName;CatalogHash=(Get-FileHash $file.FullName).Hash;Algorithm=[BitConverter]::ToUInt32($bytes,0);Digest=[Convert]::ToHexString($bytes[8..($bytes.Length-1)]);Output=$output;OutputHash=(Get-FileHash $output).Hash}
    $evidence | ConvertTo-Json | Set-Content (Join-Path $root 'build-conformance/ci-guest-evidence.json')
    $evidence | ConvertTo-Json
    exit 0
}
throw 'No supported member digest found in guest catalogs.'
