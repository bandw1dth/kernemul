# Requires PowerShell 7; all certificates remain in memory or test-only PFX files.
param([string]$SdkVersion = '10.0.28000.0')
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run with pwsh (PowerShell 7).' }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$out = Join-Path $root 'build-conformance/ci-fixtures'
$inputImage = Join-Path $root 'build-conformance/ci_conformance.sys'
$sdkBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits/10/bin/$SdkVersion/x64"
foreach ($path in @($inputImage, "$sdkBin/signtool.exe", "$sdkBin/makecat.exe")) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing prerequisite: $path" }
}
$original = [IO.File]::ReadAllBytes($inputImage)
$pe = [BitConverter]::ToInt32($original, 0x3c)
$optional = $pe + 24
$magic = [BitConverter]::ToUInt16($original, $optional)
if ($magic -notin @(0x10b, 0x20b)) { throw 'Input must be a PE image.' }
$security = $optional + $(if ($magic -eq 0x20b) { 112 } else { 96 }) + 32
if ([BitConverter]::ToUInt32($original, $security + 4) -ne 0) { throw 'Input must be unsigned; refusing to replace a signature.' }
New-Item -ItemType Directory -Force $out | Out-Null
[IO.File]::WriteAllBytes("$out/unsigned.sys", $original)
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$password = 'ci-fixtures-only-not-a-secret'
$now = [DateTimeOffset]::UtcNow
$rootKey = [Security.Cryptography.RSA]::Create(2048)
$rootRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Kernemul CI private fixture root', $rootKey, 'SHA256', [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$rootRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
$rootRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign, $true))
$anchor = $rootRequest.CreateSelfSigned($now.AddYears(-3), $now.AddYears(3))
[IO.File]::WriteAllBytes("$out/root.der", $anchor.RawData)
$certificates = @{}
foreach ($kind in @('valid', 'wrong-eku', 'expired', 'tsa', 'untrusted-tsa')) {
    $key = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=Kernemul CI $kind fixture", $key, 'SHA256', [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $oids = [Security.Cryptography.OidCollection]::new()
    $oid = if ($kind -like '*tsa') { '1.3.6.1.5.5.7.3.8' } elseif ($kind -eq 'wrong-eku') { '1.3.6.1.5.5.7.3.1' } else { '1.3.6.1.5.5.7.3.3' }
    [void]$oids.Add([Security.Cryptography.Oid]::new($oid))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $true))
    $until = if ($kind -eq 'expired') { $now.AddDays(-1) } else { $now.AddYears(1) }
    if ($kind -eq 'untrusted-tsa') {
        $public = $request.CreateSelfSigned($now.AddYears(-1), $until)
        $cert = $public
    } else {
        $public = $request.Create($anchor, $now.AddYears(-1), $until, [Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
        $cert = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($public, $key)
    }
    $certificates[$kind] = $cert
    $collection = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$collection.Add($cert)
    [void]$collection.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($anchor.RawData))
    [IO.File]::WriteAllBytes("$out/$kind.pfx", $collection.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password))
    if ($kind -ne 'untrusted-tsa') { $public.Dispose() }
    $key.Dispose()
}
Copy-Item -LiteralPath "$out/unsigned.sys" -Destination "$out/valid.sys" -Force
& "$sdkBin/signtool.exe" sign /fd SHA256 /sha1 $certificates['valid'].Thumbprint /f "$out/valid.pfx" /p $password "$out/valid.sys"
if ($LASTEXITCODE) { throw 'signtool signing failed.' }
Copy-Item -LiteralPath "$out/unsigned.sys" -Destination "$out/valid-sha1.sys" -Force
& "$sdkBin/signtool.exe" sign /fd SHA1 /sha1 $certificates['valid'].Thumbprint /f "$out/valid.pfx" /p $password "$out/valid-sha1.sys"
if ($LASTEXITCODE) { throw 'signtool SHA1 signing failed.' }
# Re-sign the same SPC content without signtool's certificate eligibility filter.
# Include a valid re-signed control, and verify each CMS signature independently.
$signed = [IO.File]::ReadAllBytes("$out/valid.sys")
$offset = [BitConverter]::ToInt32($signed, $security)
$length = [BitConverter]::ToInt32($signed, $offset)
$cms = [Security.Cryptography.Pkcs.SignedCms]::new()
$cms.Decode([byte[]]$signed[($offset + 8)..($offset + $length - 1)])
function Write-SignedImage([string]$Name, [byte[]]$Encoded) {
    $padded = ($Encoded.Length + 8 + 7) -band -8
    $image = [byte[]]::new($offset + $padded)
    [Array]::Copy($signed, $image, $offset)
    [Array]::Copy([BitConverter]::GetBytes($padded), 0, $image, $security + 4, 4)
    [Array]::Copy([BitConverter]::GetBytes($Encoded.Length + 8), 0, $image, $offset, 4)
    $image[$offset + 5] = 2 # WIN_CERT_REVISION_2_0
    $image[$offset + 6] = 2 # WIN_CERT_TYPE_PKCS_SIGNED_DATA
    [Array]::Copy($Encoded, 0, $image, $offset + 8, $Encoded.Length)
    [IO.File]::WriteAllBytes("$out/$Name.sys", $image)
}
foreach ($kind in @('valid', 'wrong-eku', 'expired')) {
    $replacement = [Security.Cryptography.Pkcs.SignedCms]::new($cms.ContentInfo, $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificates[$kind])
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $replacement.ComputeSignature($signer, $true)
    $replacement.CheckSignature($true)
    $encoded = $replacement.Encode()
    Write-SignedImage "$kind-resigned" $encoded
    if ($kind -eq 'expired') { $expiredCms = $encoded }
}
# Fully offline RFC3161: the imprint binds the original code signer's signature.
# Rfc3161TimestampTokenInfo.Encode supplies DER TSTInfo, including generalized genTime.
foreach ($kind in @('bound', 'wrong-imprint', 'untrusted-tsa', 'future')) {
    $outer = [Security.Cryptography.Pkcs.SignedCms]::new()
    $outer.Decode($expiredCms)
    $originalSignature = $outer.SignerInfos[0].GetSignature()
    $imprint = [Security.Cryptography.SHA256]::HashData($originalSignature)
    if ($kind -eq 'wrong-imprint') { $imprint[0] = $imprint[0] -bxor 1 }
    $time = if ($kind -eq 'future') { $now.AddDays(7) } else { $now.AddDays(-7) }
    if ($kind -ne 'future' -and ($time.UtcDateTime -le $certificates['expired'].NotBefore.ToUniversalTime() -or
        $time.UtcDateTime -ge $certificates['expired'].NotAfter.ToUniversalTime())) {
        throw 'Timestamp must fall inside the expired code signer validity window.'
    }
    $tsa = if ($kind -eq 'untrusted-tsa') { $certificates['untrusted-tsa'] } else { $certificates['tsa'] }
    $info = [Security.Cryptography.Pkcs.Rfc3161TimestampTokenInfo]::new(
        [Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.99999.1'),
        [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1'),
        [ReadOnlyMemory[byte]]::new($imprint), [ReadOnlyMemory[byte]]::new([byte[]]@(1)),
        $time, $null, $false, $null, $null, $null)
    $token = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new([Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.1.4'), $info.Encode()), $false)
    $tsaSigner = [Security.Cryptography.Pkcs.CmsSigner]::new($tsa)
    $tsaSigner.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $tsaSigner.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    # SigningCertificateV2: SEQUENCE { certs SEQUENCE { ESSCertIDv2 { certHash OCTET STRING } } }.
    # The omitted hashAlgorithm defaults to SHA-256 per RFC5035.
    $ess = [byte[]](@(0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20) + [Security.Cryptography.SHA256]::HashData($tsa.RawData))
    [void]$tsaSigner.SignedAttributes.Add([Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.2.47'), $ess))
    $token.ComputeSignature($tsaSigner, $true)
    $token.CheckSignature($true)
    $encodedToken = $token.Encode()
    $decodedToken = $null
    $consumed = 0
    if (-not [Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode(
        [ReadOnlyMemory[byte]]::new($encodedToken), [ref]$decodedToken, [ref]$consumed) -or $consumed -ne $encodedToken.Length) {
        throw "Cannot independently decode RFC3161 token: $kind"
    }
    $verifiedTsa = $null
    $bindingValid = $decodedToken.VerifySignatureForSignerInfo($outer.SignerInfos[0], [ref]$verifiedTsa, $null)
    if ($bindingValid -ne ($kind -ne 'wrong-imprint')) { throw "Unexpected RFC3161 signature/imprint validation: $kind" }
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
    [void]$chain.ChainPolicy.CustomTrustStore.Add($anchor)
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.DisableCertificateDownloads = $true
    $chain.ChainPolicy.VerificationTime = $time.UtcDateTime
    [void]$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.8'))
    $tsaTrusted = $chain.Build($tsa)
    $chain.Dispose()
    if ($tsaTrusted -ne ($kind -ne 'untrusted-tsa')) { throw "Unexpected private-root TSA trust: $kind" }
    $outer.SignerInfos[0].AddUnsignedAttribute([Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.3.3.1'), $encodedToken))
    $outer.CheckSignature($true)
    if ([Convert]::ToHexString($outer.SignerInfos[0].GetSignature()) -ne [Convert]::ToHexString($originalSignature)) {
        throw 'Adding timestamp changed the code signature.'
    }
    Write-SignedImage "timestamp-$kind" $outer.Encode()
    [IO.File]::WriteAllBytes("$out/timestamp-$kind.der", $encodedToken)
    Write-Output "RFC3161 fixture ${kind}: token signature valid; binding=$bindingValid; private-root trust=$tsaTrusted; genTime=$time"
}
# Catalog entries use an explicit member file; tests read pIndirectData, not a guessed hash.
@'
[CatalogHeader]
Name=trusted.cat
PublicVersion=0x0000001
EncodingType=0x00010001
CATATTR1=0x10010001:OSAttr:2:10.0
[CatalogFiles]
<HASH>unsigned.sys=unsigned.sys
'@ | Set-Content -LiteralPath "$out/fixture.cdf" -Encoding ascii
Push-Location $out
try {
    & "$sdkBin/makecat.exe" /v fixture.cdf
    if ($LASTEXITCODE) { throw 'makecat failed.' }
    & "$sdkBin/signtool.exe" sign /fd SHA256 /sha1 $certificates['valid'].Thumbprint /f valid.pfx /p $password trusted.cat
    if ($LASTEXITCODE) { throw 'Catalog signing failed.' }
} finally { Pop-Location }
foreach ($cert in $certificates.Values) { $cert.Dispose() }
$anchor.Dispose()
$rootKey.Dispose()
Write-Output "Prepared offline fixtures in $out; no certificates installed and no guest image executed."
