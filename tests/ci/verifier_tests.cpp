// Host-only executable. Guest PE files are treated exclusively as inert byte arrays.
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <mssip.h>
#include "kernel/win/code_integrity.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using bytes = std::vector<std::uint8_t>;
using namespace win::ci;
namespace {
int failures = 0, checks = 0;
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
bytes read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot read " + path.string());
    return bytes(std::istreambuf_iterator<char>(input), {});
}
template<class T> T scalar(const bytes& input, size_t offset) {
    require(offset <= input.size() && sizeof(T) <= input.size() - offset, "Truncated PE");
    T value;
    std::memcpy(&value, input.data() + offset, sizeof(value));
    return value;
}
struct pe_info { size_t directory, offset, length, payload; };
pe_info pe(const bytes& input) {
    require(scalar<WORD>(input, 0) == IMAGE_DOS_SIGNATURE, "Not MZ");
    auto nt = scalar<DWORD>(input, 0x3c);
    require(scalar<DWORD>(input, nt) == IMAGE_NT_SIGNATURE, "Not PE");
    size_t optional = size_t(nt) + 24;
    WORD magic = scalar<WORD>(input, optional);
    require(magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC || magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC, "Unknown PE format");
    size_t directory = optional + (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112 : 96) + 32;
    size_t section = optional + scalar<WORD>(input, size_t(nt) + 20);
    size_t payload = scalar<DWORD>(input, section + 20);
    require(scalar<DWORD>(input, section + 16) > 0 && payload < input.size(), "No first-section payload");
    size_t offset = scalar<DWORD>(input, directory), length = scalar<DWORD>(input, directory + 4);
    require(offset <= input.size() && length <= input.size() - offset, "Invalid security directory");
    return {directory, offset, length, payload};
}
bytes security(const bytes& input) {
    auto info = pe(input);
    require(info.length >= 8, "Missing WIN_CERTIFICATE");
    return bytes(input.begin() + info.offset, input.begin() + info.offset + info.length);
}
struct indirect { bytes digest; DWORD algorithm; };
DWORD algorithm(const char* oid) {
    require(oid != nullptr, "Missing digest OID");
    if (std::strcmp(oid, szOID_NIST_sha256) == 0) return CALG_SHA_256;
    if (std::strcmp(oid, szOID_OIWSEC_sha1) == 0) return CALG_SHA1;
    throw std::runtime_error("Unexpected fixture digest OID");
}
struct message {
    HCRYPTMSG handle = nullptr;
    ~message() { if (handle) CryptMsgClose(handle); }
};
// Decode the authentic signed SPC digest using Windows, independently of the backend.
indirect decode(const bytes& table, bytes* signature = nullptr) {
    DWORD length = scalar<DWORD>(table, 0);
    require(length >= 8 && length <= table.size(), "Invalid fixture certificate length");
    message msg{CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, nullptr, nullptr)};
    require(msg.handle && CryptMsgUpdate(msg.handle, table.data() + 8, length - 8, TRUE), "Cannot decode fixture PKCS7");
    // Verify fixtures cryptographically with CryptoAPI, without applying chain policy.
    DWORD certificateCount = 0, countSize = sizeof(certificateCount);
    require(CryptMsgGetParam(msg.handle, CMSG_CERT_COUNT_PARAM, 0, &certificateCount, &countSize), "Missing fixture certificates");
    bool signatureVerified = false;
    for (DWORD i = 0; i < certificateCount; ++i) {
        DWORD certSize = 0;
        require(CryptMsgGetParam(msg.handle, CMSG_CERT_PARAM, i, nullptr, &certSize), "Cannot size certificate");
        bytes certBytes(certSize);
        require(CryptMsgGetParam(msg.handle, CMSG_CERT_PARAM, i, certBytes.data(), &certSize), "Cannot get certificate");
        auto cert = CertCreateCertificateContext(X509_ASN_ENCODING, certBytes.data(), certSize);
        require(cert != nullptr, "Cannot decode certificate");
        if (CryptMsgControl(msg.handle, 0, CMSG_CTRL_VERIFY_SIGNATURE, cert->pCertInfo)) signatureVerified = true;
        CertFreeCertificateContext(cert);
    }
    require(signatureVerified, "Fixture signature fails independent CryptoAPI verification");
    DWORD size = 0;
    require(CryptMsgGetParam(msg.handle, CMSG_CONTENT_PARAM, 0, nullptr, &size), "Missing SPC content");
    bytes content(size);
    require(CryptMsgGetParam(msg.handle, CMSG_CONTENT_PARAM, 0, content.data(), &size), "Cannot get SPC content");
    SIP_INDIRECT_DATA* decoded = nullptr;
    require(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID,
        content.data(), size, CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &size), "Cannot decode SPC indirect data");
    indirect result{{decoded->Digest.pbData, decoded->Digest.pbData + decoded->Digest.cbData}, algorithm(decoded->DigestAlgorithm.pszObjId)};
    LocalFree(decoded);
    if (signature) {
        require(CryptMsgGetParam(msg.handle, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &size), "Missing signer info");
        bytes storage(size);
        require(CryptMsgGetParam(msg.handle, CMSG_SIGNER_INFO_PARAM, 0, storage.data(), &size), "Cannot read signer info");
        const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(storage.data());
        signature->assign(signer->EncryptedHash.pbData, signer->EncryptedHash.pbData + signer->EncryptedHash.cbData);
    }
    return result;
}
bytes mutate_occurrence(bytes input, const bytes& needle) {
    require(!needle.empty(), "Empty mutation target");
    auto at = std::search(input.begin(), input.end(), needle.begin(), needle.end());
    require(at != input.end(), "Cannot find mutation target");
    require(std::search(at + 1, input.end(), needle.begin(), needle.end()) == input.end(), "Ambiguous mutation target");
    *at ^= 1;
    return input;
}
std::int64_t timestamp_fixture(const std::filesystem::path& folder, const char* kind) {
    const auto image = read(folder / (std::string("timestamp-") + kind + ".sys"));
    const auto table = security(image);
    const auto token = read(folder / (std::string("timestamp-") + kind + ".der"));
    require(pe(image).length % 8 == 0 && pe(image).offset + pe(image).length == image.size(), "Timestamp PE table padding/size invalid");
    bytes signature, originalSignature;
    const auto digest = decode(table, &signature);
    const auto originalDigest = decode(security(read(folder / "expired-resigned.sys")), &originalSignature);
    require(signature == originalSignature && digest.digest == originalDigest.digest, "Timestamp changed original signature/content");
    message outer{CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, nullptr, nullptr)};
    require(outer.handle && CryptMsgUpdate(outer.handle, table.data() + 8, scalar<DWORD>(table, 0) - 8, TRUE), "Cannot decode timestamped CMS");
    DWORD size = 0;
    require(CryptMsgGetParam(outer.handle, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &size), "Missing timestamped signer");
    bytes storage(size);
    require(CryptMsgGetParam(outer.handle, CMSG_SIGNER_INFO_PARAM, 0, storage.data(), &size), "Cannot get timestamped signer");
    const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(storage.data());
    require(signerInfo->UnauthAttrs.cAttr == 1, "Expected exactly one unsigned timestamp attribute");
    const auto& attribute = signerInfo->UnauthAttrs.rgAttr[0];
    require(std::strcmp(attribute.pszObjId, "1.3.6.1.4.1.311.3.3.1") == 0 && attribute.cValue == 1, "Wrong timestamp attribute OID/cardinality");
    require(attribute.rgValue[0].cbData == token.size() && std::memcmp(attribute.rgValue[0].pbData, token.data(), token.size()) == 0, "Embedded token differs from independently checked token");
    PCRYPT_TIMESTAMP_CONTEXT context = nullptr;
    PCCERT_CONTEXT tsa = nullptr;
    HCERTSTORE store = nullptr;
    const bool valid = CryptVerifyTimeStampSignature(token.data(), static_cast<DWORD>(token.size()),
        signature.data(), static_cast<DWORD>(signature.size()), nullptr, &context, &tsa, &store) != FALSE;
    std::int64_t time = 0;
    if (valid && context && context->pTimeStamp) {
        const auto value = context->pTimeStamp->ftTime;
        time = (static_cast<std::int64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }
    if (context) CryptMemFree(context);
    if (tsa) CertFreeCertificateContext(tsa);
    if (store) CertCloseStore(store, 0);
    require(valid == (std::strcmp(kind, "wrong-imprint") != 0), "Unexpected CryptoAPI RFC3161 signature/imprint result");
    require(!valid || time > 0, "Verified timestamp has no genTime");
    std::cout << "PASS CryptoAPI RFC3161 fixture: " << kind << ", bound=" << valid << '\n';
    return time;
}
#ifndef CI_FIXTURE_PROBE
void expect(const char* name, const evidence& actual, verdict expected) {
    ++checks;
    bool ok = actual.result == expected;
    if (!ok) ++failures;
    std::cout << (ok ? "PASS " : "FAIL ") << name << ": " << verdict_name(actual.result)
              << " (expected " << verdict_name(expected) << ") " << actual.detail << '\n';
}
void reject(const char* name, const evidence& actual) {
    ++checks;
    // unavailable/unsupported are not evidence of correct rejection for supported fixture inputs.
    bool ok = actual.result != verdict::trusted && actual.result != verdict::unavailable && actual.result != verdict::unsupported;
    if (!ok) ++failures;
    std::cout << (ok ? "PASS " : "FAIL ") << name << ": " << verdict_name(actual.result) << ' ' << actual.detail << '\n';
}
void timestamp_evidence(const char* name, const evidence& actual, std::int64_t expectedTime) {
    expect(name, actual, verdict::trusted);
    ++checks;
    const bool ok = actual.signing_time == expectedTime && actual.signing_time != 0 && !actual.timestamp_chain.empty();
    if (!ok) ++failures;
    std::cout << (ok ? "PASS " : "FAIL ") << name << "/verified genTime and TSA chain\n";
}
#endif
struct catalog_handle {
    HANDLE handle;
    ~catalog_handle() { if (handle != INVALID_HANDLE_VALUE) CryptCATClose(handle); }
};
std::vector<indirect> members(const std::filesystem::path& path) {
    auto filename = path.wstring();
    catalog_handle cat{CryptCATOpen(filename.data(), CRYPTCAT_OPEN_EXISTING, 0, 0, 0)};
    require(cat.handle != INVALID_HANDLE_VALUE, "Cannot open fixture catalog");
    std::vector<indirect> result;
    CRYPTCATMEMBER* member = nullptr;
    while ((member = CryptCATEnumerateMember(cat.handle, member)) != nullptr) {
        require(member->pIndirectData != nullptr, "Catalog member has no pIndirectData");
        const auto* data = member->pIndirectData;
        result.push_back({{data->Digest.pbData, data->Digest.pbData + data->Digest.cbData}, algorithm(data->DigestAlgorithm.pszObjId)});
    }
    require(!result.empty(), "Catalog contains no indirect-data members");
    return result;
}
#ifndef CI_FIXTURE_PROBE
void integration(const std::filesystem::path& imagePath, const std::vector<catalog_snapshot>& cats) {
    verifier system;
    auto result = system.verify_file(read(imagePath), cats);
    expect(imagePath.string().c_str(), result, verdict::trusted);
}
#endif
}
#ifdef CI_FIXTURE_PROBE
int wmain(int argc, wchar_t** argv) {
    try {
        require(argc == 2, "Usage: ci-fixture-probe FIXTURE_DIR");
        std::filesystem::path folder(argv[1]);
        auto original = decode(security(read(folder / "valid.sys")));
        for (const auto* kind : {"valid", "wrong-eku", "expired"}) {
            auto value = decode(security(read(folder / (std::string(kind) + "-resigned.sys"))));
            require(value.digest == original.digest && value.algorithm == original.algorithm, "Re-signed SPC content differs");
            std::cout << "PASS CryptoAPI signature and SPC digest: " << kind << '\n';
        }
        for (const auto& member : members(folder / "trusted.cat"))
            std::cout << "PASS catalog pIndirectData: algorithm=" << member.algorithm << ", digest bytes=" << member.digest.size() << '\n';
        for (const auto* kind : {"bound", "wrong-imprint", "untrusted-tsa", "future"}) timestamp_fixture(folder, kind);
        std::cout << "Fixture validation only; backend verification NOT run.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FIXTURE ERROR: " << error.what() << '\n';
        return 2;
    }
}
#else
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: ci-verifier-tests FIXTURE_DIR [--system-pe PATH] [--system-cat PATH]\n"
                         "Optional catalog snapshots apply to every optional system PE. All files are read only.\n";
            return 2;
        }
        const std::filesystem::path folder(argv[1]);
        options privateOptions;
        privateOptions.exclusive_roots = true;
        privateOptions.roots.push_back(read(folder / "root.der"));
        verifier trusted(privateOptions);
        options emptyOptions;
        emptyOptions.exclusive_roots = true;
        verifier untrusted(emptyOptions);
        const auto valid = read(folder / "valid.sys");
        auto table = security(valid);
        bytes signature;
        auto spc = decode(table, &signature);
        require(spc.algorithm == CALG_SHA_256 && spc.digest.size() == 32, "Expected SHA256 SPC fixture");
        expect("signed digest/private root", trusted.verify_signed_digest(spc.digest, spc.algorithm, table), verdict::trusted);
        auto changed = spc.digest;
        changed[0] ^= 1;
        expect("signed digest/changed hash", trusted.verify_signed_digest(changed, spc.algorithm, table), verdict::digest_mismatch);
        for (size_t size : {size_t(0), size_t(31), size_t(33)}) {
            bytes wrong(size, 0);
            reject("signed digest/bad size", trusted.verify_signed_digest(wrong, spc.algorithm, table));
        }
        expect("signed digest/unknown algorithm", trusted.verify_signed_digest(spc.digest, 0xdeadbeef, table), verdict::unsupported);
        reject("signed digest/known wrong algorithm", trusted.verify_signed_digest(bytes(20, 0), CALG_SHA1, table));
        reject("signed digest/no anchor", untrusted.verify_signed_digest(spc.digest, spc.algorithm, table));
        reject("signed digest/truncated table", trusted.verify_signed_digest(spc.digest, spc.algorithm, bytes{1, 2, 3}));
        auto invalidLength = table;
        std::fill_n(invalidLength.begin(), 4, std::uint8_t{0xff});
        reject("signed digest/overflow length", trusted.verify_signed_digest(spc.digest, spc.algorithm, invalidLength));
        auto tamperedSignature = mutate_occurrence(table, signature);
        reject("signed digest/tampered signature", trusted.verify_signed_digest(spc.digest, spc.algorithm, tamperedSignature));
        auto tamperedContent = mutate_occurrence(table, spc.digest);
        reject("signed digest/forged SPC digest with matching supplied hash", trusted.verify_signed_digest(changed, spc.algorithm, tamperedContent));
        auto malformedPkcs = table;
        malformedPkcs[8] = 0xff;
        reject("signed digest/malformed PKCS7", trusted.verify_signed_digest(spc.digest, spc.algorithm, malformedPkcs));

        expect("PE/valid", trusted.verify_file(valid, {}), verdict::trusted);
        const auto sha1Image = read(folder / "valid-sha1.sys");
        const auto sha1Result = trusted.verify_file(sha1Image, {});
        expect("PE/SHA1 embedded", sha1Result, verdict::trusted);
        require(sha1Result.algorithm == CALG_SHA1 && sha1Result.digest.size() == 20,
            "SHA1 image must report the authenticated SIP algorithm and digest");
        reject("PE/SHA1 without anchor", untrusted.verify_file(sha1Image, {}));
        auto changedSha1Image = sha1Image;
        changedSha1Image[pe(sha1Image).payload] ^= 1;
        expect("PE/SHA1 modified payload", trusted.verify_file(changedSha1Image, {}), verdict::digest_mismatch);
        auto modified = valid;
        modified[pe(valid).payload] ^= 1;
        expect("PE/modified hashed payload", trusted.verify_file(modified, {}), verdict::digest_mismatch);
        expect("PE/unsigned", trusted.verify_file(read(folder / "unsigned.sys"), {}), verdict::no_signature);
        reject("PE/truncated", trusted.verify_file(bytes{0x4d, 0x5a}, {}));
        reject("PE/no anchor", untrusted.verify_file(valid, {}));
        for (const auto* kind : {"valid", "wrong-eku", "expired"}) {
            auto variant = read(folder / (std::string(kind) + "-resigned.sys"));
            auto variantTable = security(variant);
            auto digest = decode(variantTable);
            require(digest.digest == spc.digest && digest.algorithm == spc.algorithm, "Re-signed fixture content changed");
            auto result = trusted.verify_signed_digest(digest.digest, digest.algorithm, variantTable);
            auto fileResult = trusted.verify_file(variant, {});
            if (std::strcmp(kind, "valid") == 0) {
                expect("re-signed valid CMS control", result, verdict::trusted);
                expect("re-signed valid PE control", fileResult, verdict::trusted);
            } else if (std::strcmp(kind, "expired") == 0) {
                expect("expired signer/no timestamp", result, verdict::expired);
                expect("expired PE/no timestamp", fileResult, verdict::expired);
            } else {
                expect("wrong EKU signer", result, verdict::untrusted_chain);
                expect("wrong EKU PE", fileResult, verdict::untrusted_chain);
            }
        }
        for (const auto* kind : {"bound", "wrong-imprint", "untrusted-tsa", "future"}) {
            const auto expectedTime = timestamp_fixture(folder, kind);
            const auto variant = read(folder / (std::string("timestamp-") + kind + ".sys"));
            const auto variantTable = security(variant);
            const auto result = trusted.verify_signed_digest(spc.digest, spc.algorithm, variantTable);
            const auto fileResult = trusted.verify_file(variant, {});
            const auto label = std::string("RFC3161/") + kind;
            if (std::strcmp(kind, "bound") == 0) {
                timestamp_evidence((label + "/digest").c_str(), result, expectedTime);
                timestamp_evidence((label + "/PE").c_str(), fileResult, expectedTime);
                reject("RFC3161/bound without trust roots", untrusted.verify_signed_digest(spc.digest, spc.algorithm, variantTable));
            } else {
                reject((label + "/does not rescue expired digest").c_str(), result);
                reject((label + "/does not rescue expired PE").c_str(), fileResult);
            }
        }
        auto catalogPath = folder / "trusted.cat";
        std::vector<catalog_snapshot> catalogs{{"fixture/trusted.cat", read(catalogPath)}};
        const auto entries = members(catalogPath);
        for (const auto& entry : entries) {
            expect("catalog/actual pIndirectData member", trusted.verify_catalog(entry.digest, entry.algorithm, catalogs), verdict::trusted);
            auto absent = entry.digest;
            absent[0] ^= 1;
            expect("catalog/absent member", trusted.verify_catalog(absent, entry.algorithm, catalogs), verdict::no_catalog);
            reject("catalog/no anchor", untrusted.verify_catalog(entry.digest, entry.algorithm, catalogs));
            expect("catalog/no snapshots", trusted.verify_catalog(entry.digest, entry.algorithm, {}), verdict::no_catalog);
            auto badCatalogs = catalogs;
            badCatalogs[0].bytes = mutate_occurrence(badCatalogs[0].bytes, entry.digest);
            reject("catalog/tampered member with matching supplied digest", trusted.verify_catalog(absent, entry.algorithm, badCatalogs));
        }
        expect("unsigned PE/catalog fallback", trusted.verify_file(read(folder / "unsigned.sys"), catalogs), verdict::trusted);
        auto mixedCatalogs = catalogs;
        mixedCatalogs.insert(mixedCatalogs.begin(), {"fixture/corrupt.cat", bytes{1, 2, 3}});
        expect("unsigned PE/SHA1 catalog after corrupt catalog", trusted.verify_file(read(folder / "unsigned.sys"), mixedCatalogs), verdict::trusted);
        std::reverse(mixedCatalogs.begin(), mixedCatalogs.end());
        expect("unsigned PE/SHA1 catalog before corrupt catalog", trusted.verify_file(read(folder / "unsigned.sys"), mixedCatalogs), verdict::trusted);
        std::vector<std::filesystem::path> images;
        std::vector<catalog_snapshot> systemCatalogs;
        for (int i = 2; i < argc; i += 2) {
            require(i + 1 < argc, "Optional argument needs a path");
            std::wstring argument(argv[i]);
            std::filesystem::path path(argv[i + 1]);
            if (argument == L"--system-pe") images.push_back(path);
            else if (argument == L"--system-cat") systemCatalogs.push_back({path.string(), read(path)});
            else throw std::runtime_error("Unknown optional argument");
        }
        for (const auto& path : images) integration(path, systemCatalogs);
        if (!systemCatalogs.empty()) {
            verifier system;
            for (int i = 2; i < argc; i += 2) {
                if (std::wstring(argv[i]) != L"--system-cat") continue;
                for (const auto& entry : members(argv[i + 1]))
                    expect("system catalog/actual member", system.verify_catalog(entry.digest, entry.algorithm, systemCatalogs), verdict::trusted);
            }
        }
        std::cout << "GAP: legacy countersignatures, multiple timestamp tokens, and revocation-cache policy are not covered.\n";
        if (images.empty() && systemCatalogs.empty()) std::cout << "SKIP: optional real-system PE/catalog integration (no arguments supplied).\n";
        std::cout << checks << " checks, " << failures << " failures\n";
        return failures ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << "FIXTURE/TEST ERROR: " << error.what() << '\n';
        return 2;
    }
}
#endif
