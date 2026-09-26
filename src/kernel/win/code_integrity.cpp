#include "code_integrity.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mssip.h>
#include <mscat.h>
#include <bcrypt.h>
#include <sddl.h>
#endif

namespace win::ci {
const char* verdict_name(verdict value) {
    switch (value) {
#define CI_VERDICT(v) case verdict::v: return #v
        CI_VERDICT(trusted); CI_VERDICT(malformed); CI_VERDICT(unsupported);
        CI_VERDICT(digest_mismatch); CI_VERDICT(bad_signature); CI_VERDICT(untrusted_chain);
        CI_VERDICT(expired); CI_VERDICT(revoked); CI_VERDICT(no_signature);
        CI_VERDICT(no_catalog); CI_VERDICT(unavailable);
#undef CI_VERDICT
    }
    return "unavailable";
}
namespace {
evidence failure(verdict result, const char* detail, std::uint32_t error = 0) {
    evidence e;
    e.result = result; e.detail = detail; e.native_error = error;
    return e;
}
}
#ifdef _WIN32
namespace {
constexpr DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
constexpr std::size_t signature_limit = 16 * 1024 * 1024;
constexpr std::size_t image_limit = 512 * 1024 * 1024;
constexpr std::size_t catalog_limit = 4096;
constexpr std::size_t catalog_total_limit = 256 * 1024 * 1024;
constexpr DWORD signer_limit = 32, attribute_limit = 128, chain_limit = 64;
constexpr const char* nested_oid = "1.3.6.1.4.1.311.2.4.1";
using bytes = std::vector<std::uint8_t>;
struct store_handle {
    HCERTSTORE value = nullptr;
    ~store_handle() { if (value) CertCloseStore(value, 0); }
};
struct message_handle {
    HCRYPTMSG value = nullptr;
    ~message_handle() { if (value) CryptMsgClose(value); }
};
struct cert_handle {
    PCCERT_CONTEXT value = nullptr;
    ~cert_handle() { if (value) CertFreeCertificateContext(value); }
};
struct chain_handle {
    PCCERT_CHAIN_CONTEXT value = nullptr;
    ~chain_handle() { if (value) CertFreeCertificateChain(value); }
};
struct local_buffer {
    void* value = nullptr;
    ~local_buffer() { if (value) LocalFree(value); }
    template<class T> T* as() const { return static_cast<T*>(value); }
};
struct timestamp_handle {
    PCRYPT_TIMESTAMP_CONTEXT value = nullptr;
    ~timestamp_handle() { if (value) CryptMemFree(value); }
};
std::int64_t ticks(FILETIME time) {
    return static_cast<std::int64_t>((std::uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime);
}
const char* algorithm_oid(std::uint32_t algorithm) {
    switch (algorithm) {
    case CALG_SHA1: return szOID_OIWSEC_sha1;
    case CALG_SHA_256: return szOID_NIST_sha256;
    case CALG_SHA_384: return szOID_NIST_sha384;
    case CALG_SHA_512: return szOID_NIST_sha512;
    default: return nullptr;
    }
}
std::size_t digest_size(std::uint32_t algorithm) {
    switch (algorithm) {
    case CALG_SHA1: return 20;
    case CALG_SHA_256: return 32;
    case CALG_SHA_384: return 48;
    case CALG_SHA_512: return 64;
    default: return 0;
    }
}
bool same_digest(const CRYPT_ALGORITHM_IDENTIFIER& algorithm, const CRYPT_HASH_BLOB& actual,
                 std::span<const std::uint8_t> expected, std::uint32_t requested) {
    const auto oid = algorithm_oid(requested);
    return oid && algorithm.pszObjId && !std::strcmp(algorithm.pszObjId, oid)
        && expected.size() == digest_size(requested) && actual.cbData == expected.size()
        && actual.pbData && !std::memcmp(actual.pbData, expected.data(), expected.size());
}
bool decode(const char* type, std::span<const std::uint8_t> data, local_buffer& result) {
    DWORD size = 0;
    return !data.empty() && data.size() <= signature_limit && CryptDecodeObjectEx(encoding, type,
        data.data(), static_cast<DWORD>(data.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr, &result.value, &size);
}
bool parameter(HCRYPTMSG message, DWORD kind, DWORD index, bytes& result) {
    DWORD size = 0;
    if (!CryptMsgGetParam(message, kind, index, nullptr, &size) || !size || size > signature_limit) return false;
    result.resize(size);
    if (!CryptMsgGetParam(message, kind, index, result.data(), &size)) return false;
    result.resize(size); return true;
}
// One definite-length sequence, followed only by WIN_CERTIFICATE padding.
bool der_sequence(std::span<const std::uint8_t>& data) {
    if (data.size() < 2 || data[0] != 0x30) return false;
    std::size_t offset = 2, length = data[1];
    if (length & 0x80) {
        auto count = length & 0x7f;
        if (!count || count > 4 || count > data.size() - offset || data[offset] == 0) return false;
        length = 0;
        for (std::size_t i = 0; i < count; ++i) length = (length << 8) | data[offset++];
        if (length < 128) return false;
    }
    if (length > data.size() - offset) return false;
    const auto end = offset + length;
    if (data.size() - end > 7 || !std::all_of(data.begin() + end, data.end(), [](auto c) { return c == 0; })) return false;
    data = data.first(end); return true;
}
std::uint16_t u16(std::span<const std::uint8_t> data, std::size_t offset) {
    return std::uint16_t(data[offset]) | (std::uint16_t(data[offset + 1]) << 8);
}
std::uint32_t u32(std::span<const std::uint8_t> data, std::size_t offset) {
    return std::uint32_t(u16(data, offset)) | (std::uint32_t(u16(data, offset + 2)) << 16);
}

// Algorithm discovery only selects which snapshot hashes to compute. Neither
// this content nor nested unsigned attributes constitute verification evidence.
std::vector<std::uint32_t> embedded_algorithms(std::span<const std::uint8_t> table) {
    std::vector<std::uint32_t> result;
    unsigned budget = 32;
    auto visit = [&](auto&& self, std::span<const std::uint8_t> data, unsigned depth) -> void {
        if (!budget || depth > 4) return;
        --budget;
        if (data.size() > signature_limit || !der_sequence(data)) return;
        message_handle message;
        message.value = CryptMsgOpenToDecode(encoding, 0, 0, 0, nullptr, nullptr);
        if (!message.value || !CryptMsgUpdate(message.value, data.data(), static_cast<DWORD>(data.size()), TRUE)) return;
        bytes content;
        local_buffer decoded;
        if (parameter(message.value, CMSG_CONTENT_PARAM, 0, content)
            && decode(SPC_INDIRECT_DATA_CONTENT_STRUCT, content, decoded)) {
            auto oid = decoded.as<SPC_INDIRECT_DATA_CONTENT>()->DigestAlgorithm.pszObjId;
            std::uint32_t algorithm = 0;
            for (auto supported : {CALG_SHA_256, CALG_SHA1, CALG_SHA_384, CALG_SHA_512})
                if (oid && !std::strcmp(oid, algorithm_oid(supported))) algorithm = supported;
            if (std::find(result.begin(), result.end(), algorithm) == result.end()) result.push_back(algorithm);
        }
        DWORD count = 0, size = sizeof(count);
        if (!CryptMsgGetParam(message.value, CMSG_SIGNER_COUNT_PARAM, 0, &count, &size) || count > signer_limit) return;
        for (DWORD i = 0; i < count && budget; ++i) {
            bytes info;
            if (!parameter(message.value, CMSG_SIGNER_INFO_PARAM, i, info)) continue;
            auto signer = reinterpret_cast<PCMSG_SIGNER_INFO>(info.data());
            if (signer->UnauthAttrs.cAttr > attribute_limit) continue;
            for (DWORD j = 0; j < signer->UnauthAttrs.cAttr && budget; ++j) {
                auto& attr = signer->UnauthAttrs.rgAttr[j];
                if (std::strcmp(attr.pszObjId, nested_oid)) continue;
                for (DWORD k = 0; k < attr.cValue && budget; ++k)
                    self(self, {attr.rgValue[k].pbData, attr.rgValue[k].cbData}, depth + 1);
            }
        }
    };
    unsigned entries = 0;
    for (std::size_t offset = 0; offset < table.size() && budget && entries++ < 2048;) {
        if (table.size() - offset < 8) break;
        auto length = std::size_t(u32(table, offset));
        if (length < 8 || length > table.size() - offset) break;
        if (u16(table, offset + 4) == WIN_CERT_REVISION_2_0 && u16(table, offset + 6) == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            visit(visit, table.subspan(offset + 8, length - 8), 0);
        offset += (length + 7) & ~std::size_t(7);
    }
    return result;
}

void remember_failure(evidence& current, evidence candidate) {
    auto priority = [](verdict value) {
        switch (value) {
        case verdict::revoked: return 8;
        case verdict::expired: return 7;
        case verdict::untrusted_chain: return 6;
        case verdict::bad_signature: return 5;
        case verdict::unavailable: return 4;
        case verdict::malformed: return 3;
        case verdict::unsupported: return 2;
        case verdict::digest_mismatch: return 1;
        default: return 0;
        }
    };
    if (priority(candidate.result) > priority(current.result)) current = std::move(candidate);
}

// Never derive a host path from a guest path. The owner-only file is created
// exclusively, then reopened denying writes/deletion and compared under that
// pin to ensure SIP/catalog parsing sees exactly the supplied snapshot.
struct snapshot_file {
    std::wstring path;
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~snapshot_file() {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        if (!path.empty()) DeleteFileW(path.c_str());
    }
    bool create(std::span<const std::uint8_t> content) {
        wchar_t temporary[MAX_PATH + 1]{};
        auto length = GetTempPathW(MAX_PATH, temporary);
        if (!length || length >= MAX_PATH) return false;
        std::array<unsigned char, 16> random{};
        if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return false;
        std::wstring candidate(temporary);
        candidate += L"kernemul-ci-";
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (auto b : random) { candidate += hex[b >> 4]; candidate += hex[b & 15]; }
        candidate += L".tmp";
        local_buffer descriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;OW)",
            SDDL_REVISION_1, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value), nullptr)) return false;
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor.value, FALSE};
        HANDLE writer = CreateFileW(candidate.c_str(), GENERIC_WRITE, 0, &security, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
        if (writer == INVALID_HANDLE_VALUE) return false;
        path = std::move(candidate);
        DWORD written = 0;
        bool ok = WriteFile(writer, content.data(), static_cast<DWORD>(content.size()), &written, nullptr)
            && written == content.size();
        CloseHandle(writer);
        if (!ok) return false;
        handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(handle, &size) || size.QuadPart != static_cast<LONGLONG>(content.size())) return false;
        std::array<std::uint8_t, 65536> block{};
        for (std::size_t offset = 0; offset < content.size();) {
            DWORD read = 0, count = static_cast<DWORD>(std::min(block.size(), content.size() - offset));
            if (!ReadFile(handle, block.data(), count, &read, nullptr) || read != count
                || std::memcmp(block.data(), content.data() + offset, count)) return false;
            offset += count;
        }
        LARGE_INTEGER zero{};
        return SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) != FALSE;
    }
};

std::string certificate_name(PCCERT_CONTEXT cert, DWORD flags) {
    DWORD length = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
    if (!length || length > 65536) return {};
    std::wstring name(length, L'\0');
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, name.data(), length);
    int count = WideCharToMultiByte(CP_UTF8, 0, name.data(), static_cast<int>(length - 1), nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string result(count, '\0');
    WideCharToMultiByte(CP_UTF8, 0, name.data(), static_cast<int>(length - 1), result.data(), count, nullptr, nullptr);
    return result;
}
bool certificate_evidence(PCCERT_CONTEXT cert, certificate& result) {
    result.der.assign(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
    auto& key = cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    result.public_key.assign(key.pbData, key.pbData + key.cbData);
    result.sha256.resize(32); DWORD size = 32;
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, cert->pbCertEncoded,
        cert->cbCertEncoded, result.sha256.data(), &size) || size != 32) return false;
    result.not_before = ticks(cert->pCertInfo->NotBefore);
    result.not_after = ticks(cert->pCertInfo->NotAfter);
    result.subject = certificate_name(cert, 0);
    result.issuer = certificate_name(cert, CERT_NAME_ISSUER_FLAG);
    size = 0;
    if (CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, nullptr, &size)) {
        if (size > signature_limit) return false;
        bytes storage(size);
        auto usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(storage.data());
        if (!CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, usage, &size)) return false;
        for (DWORD i = 0; i < usage->cUsageIdentifier; ++i) result.ekus.emplace_back(usage->rgpszUsageIdentifier[i]);
    } else if (GetLastError() != static_cast<DWORD>(CRYPT_E_NOT_FOUND)) return false;
    return true;
}
bool explicit_eku(PCCERT_CONTEXT cert, const char* required) {
    DWORD size = 0;
    if (!CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, nullptr, &size) || size > signature_limit) return false;
    bytes storage(size);
    auto usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(storage.data());
    if (!CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, usage, &size)) return false;
    for (DWORD i = 0; i < usage->cUsageIdentifier; ++i)
        if (!std::strcmp(usage->rgpszUsageIdentifier[i], required)) return true;
    return false;
}
}

struct verifier::impl {
    options configuration;
    store_handle roots;
    HCERTCHAINENGINE engine = nullptr;
    DWORD initialization_error = 0;
    explicit impl(options value) : configuration(std::move(value)) {
        if (!configuration.exclusive_roots) return;
        roots.value = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
        if (!roots.value) { initialization_error = GetLastError(); return; }
        std::size_t total = 0;
        if (configuration.roots.size() > 128) { initialization_error = ERROR_INVALID_PARAMETER; return; }
        for (const auto& root : configuration.roots) {
            if (root.empty() || root.size() > signature_limit || total > signature_limit - root.size()) {
                initialization_error = ERROR_INVALID_PARAMETER; return;
            }
            total += root.size();
            if (!CertAddEncodedCertificateToStore(roots.value, encoding, root.data(), static_cast<DWORD>(root.size()),
                CERT_STORE_ADD_ALWAYS, nullptr)) { initialization_error = GetLastError(); return; }
        }
        CERT_CHAIN_ENGINE_CONFIG config{};
        config.cbSize = sizeof(config); config.hExclusiveRoot = roots.value;
        config.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA;
        if (!CertCreateCertificateChainEngine(&config, &engine)) initialization_error = GetLastError();
    }
    ~impl() { if (engine) CertFreeCertificateChainEngine(engine); }

    evidence chain(PCCERT_CONTEXT signer, HCERTSTORE additional, FILETIME* time, bool tsa,
                   PCMSG_SIGNER_INFO signer_info = nullptr) const {
        if (initialization_error) return failure(verdict::unavailable, "private root configuration failed", initialization_error);
        const auto eku = tsa ? szOID_PKIX_KP_TIMESTAMP_SIGNING : szOID_PKIX_KP_CODE_SIGNING;
        if (!explicit_eku(signer, eku)) return failure(verdict::untrusted_chain, "required leaf EKU missing", static_cast<std::uint32_t>(CERT_E_WRONG_USAGE));
        CERT_CHAIN_PARA parameters{}; parameters.cbSize = sizeof(parameters);
        char* usage = const_cast<char*>(eku);
        parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
        parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
        DWORD flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE;
        bool revocation = configuration.revocation == revocation_policy::offline_cache_required;
        if (revocation) flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
        chain_handle built;
        if (!CertGetCertificateChain(engine, signer, time, additional, &parameters, flags, nullptr, &built.value))
            return failure(verdict::untrusted_chain, "offline chain construction failed", GetLastError());
        CERT_CHAIN_POLICY_PARA policy{}; policy.cbSize = sizeof(policy);
        AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA auth{};
        auth.cbSize = sizeof(auth); auth.pSignerInfo = signer_info;
        AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA timestamp{};
        timestamp.cbSize = sizeof(timestamp); timestamp.fCommercial = FALSE;
        policy.pvExtraPolicyPara = tsa ? static_cast<void*>(&timestamp) : static_cast<void*>(&auth);
        CERT_CHAIN_POLICY_STATUS status{}; status.cbSize = sizeof(status);
        if (!CertVerifyCertificateChainPolicy(tsa ? CERT_CHAIN_POLICY_AUTHENTICODE_TS : CERT_CHAIN_POLICY_AUTHENTICODE,
            built.value, &policy, &status)) return failure(verdict::untrusted_chain, "chain policy evaluation failed", GetLastError());
        // Policy TRUE means evaluation succeeded, not that the chain is trusted.
        DWORD errors = built.value->TrustStatus.dwErrorStatus;
        if (status.dwError || errors) {
            auto result = verdict::untrusted_chain;
            if (status.dwError == static_cast<DWORD>(CERT_E_REVOKED) || (errors & CERT_TRUST_IS_REVOKED)) result = verdict::revoked;
            else if (status.dwError == static_cast<DWORD>(CERT_E_EXPIRED) || (errors & CERT_TRUST_IS_NOT_TIME_VALID)) result = verdict::expired;
            return failure(result, "offline chain or Authenticode policy rejected signer", status.dwError ? status.dwError : errors);
        }
        if (!built.value->cChain || !built.value->rgpChain[0]->cElement || built.value->rgpChain[0]->cElement > chain_limit)
            return failure(verdict::malformed, "certificate chain exceeds limit");
        evidence result;
        result.result = verdict::trusted; result.revocation_checked = revocation;
        result.detail = revocation ? "trusted; offline cached revocation checked" : "trusted; revocation unchecked (offline)";
        auto simple = built.value->rgpChain[0];
        for (DWORD i = 0; i < simple->cElement; ++i) {
            certificate cert;
            if (!certificate_evidence(simple->rgpElement[i]->pCertContext, cert))
                return failure(verdict::unavailable, "certificate evidence extraction failed", GetLastError());
            result.signer_chain.push_back(std::move(cert));
        }
        return result;
    }

    bool verified_time(HCRYPTMSG message, DWORD signer_index, PCMSG_SIGNER_INFO signer,
                       HCERTSTORE store, FILETIME& time, evidence& proof) const {
        if (signer->UnauthAttrs.cAttr > attribute_limit) return false;
        bytes encoded_signer;
        unsigned attempts = 0;
        for (DWORD i = 0; i < signer->UnauthAttrs.cAttr; ++i) {
            const auto& attr = signer->UnauthAttrs.rgAttr[i];
            bool rfc = !std::strcmp(attr.pszObjId, szOID_RFC3161_counterSign);
            bool legacy = !std::strcmp(attr.pszObjId, szOID_RSA_counterSign);
            if (!rfc && !legacy) continue;
            for (DWORD j = 0; j < attr.cValue; ++j) {
                if (++attempts > signer_limit) return false;
                const auto& blob = attr.rgValue[j];
                if (!blob.cbData || blob.cbData > signature_limit) continue;
                evidence candidate;
                FILETIME candidate_time{};
                if (rfc) {
                    timestamp_handle context; cert_handle tsa; store_handle tsa_store;
                    if (!CryptVerifyTimeStampSignature(blob.pbData, blob.cbData, signer->EncryptedHash.pbData,
                        signer->EncryptedHash.cbData, store, &context.value, &tsa.value, &tsa_store.value)
                        || !context.value || !tsa.value || !context.value->pTimeStamp) continue;
                    candidate_time = context.value->pTimeStamp->ftTime;
                    candidate = chain(tsa.value, tsa_store.value, &candidate_time, true);
                } else {
                    local_buffer decoded;
                    if (!decode(PKCS7_SIGNER_INFO, {blob.pbData, blob.cbData}, decoded)) continue;
                    auto counter = decoded.as<CMSG_SIGNER_INFO>();
                    if (counter->AuthAttrs.cAttr > attribute_limit) continue;
                    CERT_INFO find{}; find.Issuer = counter->Issuer; find.SerialNumber = counter->SerialNumber;
                    cert_handle tsa;
                    tsa.value = CertFindCertificateInStore(store, encoding, 0, CERT_FIND_SUBJECT_CERT, &find, nullptr);
                    if (!tsa.value) continue;
                    if (encoded_signer.empty() && !parameter(message, CMSG_ENCODED_SIGNER, signer_index, encoded_signer)) continue;
                    if (!CryptMsgVerifyCountersignatureEncoded(0, encoding, encoded_signer.data(), static_cast<DWORD>(encoded_signer.size()),
                        blob.pbData, blob.cbData, tsa.value->pCertInfo)) continue;
                    unsigned times = 0;
                    for (DWORD k = 0; k < counter->AuthAttrs.cAttr; ++k) {
                        auto& signed_attr = counter->AuthAttrs.rgAttr[k];
                        if (std::strcmp(signed_attr.pszObjId, szOID_RSA_signingTime)) continue;
                        ++times;
                        if (signed_attr.cValue != 1) { times = 2; break; }
                        local_buffer decoded_time;
                        auto& value = signed_attr.rgValue[0];
                        if (!decode(szOID_RSA_signingTime, {value.pbData, value.cbData}, decoded_time)) { times = 2; break; }
                        candidate_time = *decoded_time.as<FILETIME>();
                    }
                    if (times != 1) continue;
                    candidate = chain(tsa.value, store, &candidate_time, true);
                }
                FILETIME now{}; GetSystemTimeAsFileTime(&now);
                if (candidate.result != verdict::trusted || ticks(candidate_time) <= 0 || ticks(candidate_time) > ticks(now)) continue;
                time = candidate_time; proof = std::move(candidate); return true;
            }
        }
        return false;
    }

    evidence signed_message(std::span<const std::uint8_t> data, std::span<const std::uint8_t> digest,
                            std::uint32_t algorithm, bool catalog, unsigned depth, unsigned& budget) const {
        if (depth > 4 || !budget) return failure(verdict::unsupported, "nested signature limit exceeded");
        --budget;
        if (data.empty() || data.size() > signature_limit || !der_sequence(data)) return failure(verdict::malformed, "invalid PKCS7 envelope");
        message_handle message;
        message.value = CryptMsgOpenToDecode(encoding, 0, 0, 0, nullptr, nullptr);
        if (!message.value || !CryptMsgUpdate(message.value, data.data(), static_cast<DWORD>(data.size()), TRUE))
            return failure(verdict::malformed, "PKCS7 decode failed", GetLastError());
        DWORD type = 0, count = 0, size = sizeof(DWORD);
        if (!CryptMsgGetParam(message.value, CMSG_TYPE_PARAM, 0, &type, &size) || type != CMSG_SIGNED)
            return failure(verdict::malformed, "PKCS7 is not signed data");
        size = sizeof(DWORD);
        if (!CryptMsgGetParam(message.value, CMSG_SIGNER_COUNT_PARAM, 0, &count, &size) || !count || count > signer_limit)
            return failure(verdict::malformed, "invalid PKCS7 signer count");
        bytes content, inner_type;
        if (!parameter(message.value, CMSG_CONTENT_PARAM, 0, content)
            || !parameter(message.value, CMSG_INNER_CONTENT_TYPE_PARAM, 0, inner_type))
            return failure(verdict::malformed, "missing signed content", GetLastError());
        auto expected_type = catalog ? szOID_CTL : SPC_INDIRECT_DATA_OBJID;
        if (inner_type.back() != 0 || std::strcmp(reinterpret_cast<const char*>(inner_type.data()), expected_type))
            return failure(verdict::unsupported, "unexpected signed content type");
        store_handle store;
        store.value = CertOpenStore(CERT_STORE_PROV_MSG, encoding, 0, CERT_STORE_READONLY_FLAG, message.value);
        if (!store.value) return failure(verdict::malformed, "PKCS7 certificate store unavailable", GetLastError());
        evidence last = failure(verdict::bad_signature, "no valid signer");
        for (DWORD index = 0; index < count; ++index) {
            bytes info;
            if (!parameter(message.value, CMSG_SIGNER_INFO_PARAM, index, info)) continue;
            auto signer = reinterpret_cast<PCMSG_SIGNER_INFO>(info.data());
            CERT_INFO find{}; find.Issuer = signer->Issuer; find.SerialNumber = signer->SerialNumber;
            cert_handle cert;
            cert.value = CertFindCertificateInStore(store.value, encoding, 0, CERT_FIND_SUBJECT_CERT, &find, nullptr);
            if (cert.value) {
                CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA verify{};
                verify.cbSize = sizeof(verify); verify.dwSignerIndex = index;
                verify.dwSignerType = CMSG_VERIFY_SIGNER_CERT; verify.pvSigner = const_cast<PCERT_CONTEXT>(cert.value);
                if (CryptMsgControl(message.value, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &verify)) {
                    bool matches = catalog;
                    if (!catalog) {
                        local_buffer indirect;
                        if (!decode(SPC_INDIRECT_DATA_CONTENT_STRUCT, content, indirect)) last = failure(verdict::malformed, "signed indirect data decode failed", GetLastError());
                        else {
                            auto value = indirect.as<SPC_INDIRECT_DATA_CONTENT>();
                            matches = same_digest(value->DigestAlgorithm, value->Digest, digest, algorithm);
                            if (!matches) last = failure(verdict::digest_mismatch, "signed digest or algorithm differs");
                        }
                    }
                    if (matches) {
                        FILETIME time{}; evidence timestamp;
                        bool has_time = verified_time(message.value, index, signer, store.value, time, timestamp);
                        last = chain(cert.value, store.value, has_time ? &time : nullptr, false, signer);
                        if (last.result == verdict::trusted) {
                            if (has_time) { last.signing_time = ticks(time); last.timestamp_chain = std::move(timestamp.signer_chain); }
                            last.algorithm = algorithm; last.digest.assign(digest.begin(), digest.end());
                            return last;
                        }
                    }
                } else last = failure(verdict::bad_signature, "PKCS7 signer signature invalid", GetLastError());
            }
            // A nested attribute is only a container: independently verify its
            // signed digest, signature and chain before returning any evidence.
            if (!catalog && signer->UnauthAttrs.cAttr <= attribute_limit) {
                for (DWORD i = 0; i < signer->UnauthAttrs.cAttr; ++i) {
                    auto& attr = signer->UnauthAttrs.rgAttr[i];
                    if (std::strcmp(attr.pszObjId, nested_oid)) continue;
                    for (DWORD j = 0; j < attr.cValue && budget; ++j) {
                        auto& value = attr.rgValue[j];
                        auto nested = signed_message({value.pbData, value.cbData}, digest, algorithm, false, depth + 1, budget);
                        if (nested.result == verdict::trusted) return nested;
                    }
                }
            }
        }
        return last;
    }
};

verifier::verifier(options configuration) : impl_(std::make_unique<impl>(std::move(configuration))) {}
verifier::~verifier() = default;

evidence verifier::verify_signed_digest(std::span<const std::uint8_t> digest, std::uint32_t algorithm,
                                         std::span<const std::uint8_t> security_directory) {
    if (!algorithm_oid(algorithm)) return failure(verdict::unsupported, "unsupported digest algorithm");
    if (digest.size() != digest_size(algorithm)) return failure(verdict::malformed, "invalid digest length");
    if (security_directory.empty()) return failure(verdict::no_signature, "empty certificate table");
    if (security_directory.size() > signature_limit || security_directory.size() % 8)
        return failure(verdict::malformed, "invalid certificate table size");
    std::vector<std::span<const std::uint8_t>> entries;
    unsigned entry_count = 0;
    // Validate the entire table before accepting any signature.
    for (std::size_t offset = 0; offset < security_directory.size();) {
        if (++entry_count > 2048) return failure(verdict::unsupported, "certificate entry limit exceeded");
        if (security_directory.size() - offset < 8) return failure(verdict::malformed, "truncated WIN_CERTIFICATE");
        auto length = u32(security_directory, offset);
        if (length < 8 || length > security_directory.size() - offset) return failure(verdict::malformed, "invalid WIN_CERTIFICATE length");
        auto aligned = (std::size_t(length) + 7) & ~std::size_t(7);
        if (aligned > security_directory.size() - offset) return failure(verdict::malformed, "truncated certificate alignment");
        for (std::size_t i = length; i < aligned; ++i)
            if (security_directory[offset + i]) return failure(verdict::malformed, "nonzero certificate padding");
        auto revision = u16(security_directory, offset + 4), type = u16(security_directory, offset + 6);
        if (revision != WIN_CERT_REVISION_1_0 && revision != WIN_CERT_REVISION_2_0)
            return failure(verdict::malformed, "invalid certificate revision");
        if (type == WIN_CERT_TYPE_PKCS_SIGNED_DATA && revision == WIN_CERT_REVISION_2_0) {
            auto entry = security_directory.subspan(offset + 8, length - 8);
            if (!der_sequence(entry)) return failure(verdict::malformed, "malformed certificate PKCS7 envelope");
            // Decode every supported entry up front: a trusted first entry
            // must not hide a malformed SignedData entry later in the table.
            message_handle decoded;
            decoded.value = CryptMsgOpenToDecode(encoding, 0, 0, 0, nullptr, nullptr);
            if (!decoded.value || !CryptMsgUpdate(decoded.value, entry.data(), static_cast<DWORD>(entry.size()), TRUE))
                return failure(verdict::malformed, "malformed certificate SignedData", GetLastError());
            DWORD message_type = 0, size = sizeof(message_type);
            if (!CryptMsgGetParam(decoded.value, CMSG_TYPE_PARAM, 0, &message_type, &size) || message_type != CMSG_SIGNED)
                return failure(verdict::malformed, "certificate is not SignedData");
            bytes content, content_type;
            if (!parameter(decoded.value, CMSG_CONTENT_PARAM, 0, content)
                || !parameter(decoded.value, CMSG_INNER_CONTENT_TYPE_PARAM, 0, content_type))
                return failure(verdict::malformed, "certificate signed content missing", GetLastError());
            if (content_type.back() != 0) return failure(verdict::malformed, "invalid signed content OID");
            if (!std::strcmp(reinterpret_cast<const char*>(content_type.data()), SPC_INDIRECT_DATA_OBJID)) {
                local_buffer indirect;
                if (!decode(SPC_INDIRECT_DATA_CONTENT_STRUCT, content, indirect))
                    return failure(verdict::malformed, "malformed signed indirect data", GetLastError());
            }
            entries.push_back(entry);
        }
        offset += aligned;
        if (entries.size() > signer_limit) return failure(verdict::unsupported, "too many certificate signatures");
    }
    evidence last = failure(verdict::unsupported, "no supported WIN_CERTIFICATE entry");
    unsigned budget = 32;
    for (auto entry : entries) {
        auto result = impl_->signed_message(entry, digest, algorithm, false, 0, budget);
        if (result.result == verdict::trusted) return result;
        last = std::move(result);
    }
    return last;
}

evidence verifier::verify_catalog(std::span<const std::uint8_t> digest, std::uint32_t algorithm,
                                   std::span<const catalog_snapshot> catalogs) {
    if (!algorithm_oid(algorithm)) return failure(verdict::unsupported, "unsupported catalog digest algorithm");
    if (digest.size() != digest_size(algorithm)) return failure(verdict::malformed, "invalid catalog digest length");
    if (catalogs.size() > catalog_limit) return failure(verdict::unsupported, "too many catalog snapshots");
    std::size_t total = 0;
    for (const auto& catalog : catalogs) {
        if (catalog.bytes.size() > catalog_total_limit || total > catalog_total_limit - catalog.bytes.size())
            return failure(verdict::malformed, "catalog snapshot size limit exceeded");
        total += catalog.bytes.size();
    }
    evidence last = failure(verdict::no_catalog, "no supplied catalog contains the digest");
    for (const auto& catalog : catalogs) {
        if (catalog.bytes.empty() || catalog.bytes.size() > signature_limit) {
            remember_failure(last, failure(verdict::malformed, "individual catalog snapshot size limit exceeded"));
            continue;
        }
        snapshot_file file;
        if (!file.create(catalog.bytes)) { remember_failure(last, failure(verdict::unavailable, "catalog snapshot creation failed", GetLastError())); continue; }
        HANDLE handle = CryptCATOpen(file.path.data(), CRYPTCAT_OPEN_EXISTING, 0, 0, encoding);
        if (handle == INVALID_HANDLE_VALUE) { remember_failure(last, failure(verdict::malformed, "catalog decode failed", GetLastError())); continue; }
        bool found = false, exceeded = false;
        CRYPTCATMEMBER* member = nullptr;
        unsigned count = 0;
        while ((member = CryptCATEnumerateMember(handle, member))) {
            if (++count > 65536) { exceeded = true; break; }
            auto indirect = member->pIndirectData;
            if (indirect && same_digest(indirect->DigestAlgorithm, indirect->Digest, digest, algorithm)) found = true;
        }
        CryptCATClose(handle);
        if (exceeded) { remember_failure(last, failure(verdict::unsupported, "catalog member limit exceeded")); continue; }
        if (!found) continue;
        unsigned budget = 32;
        auto result = impl_->signed_message(catalog.bytes, digest, algorithm, true, 0, budget);
        if (result.result == verdict::trusted) { result.catalog_name = catalog.guest_path; return result; }
        remember_failure(last, std::move(result));
    }
    return last;
}

evidence verifier::verify_file(std::span<const std::uint8_t> image, std::span<const catalog_snapshot> catalogs) {
    if (image.size() < 64 || image.size() > image_limit || u16(image, 0) != IMAGE_DOS_SIGNATURE)
        return failure(verdict::malformed, "invalid PE image size or DOS header");
    auto nt = std::size_t(u32(image, 0x3c));
    if (nt > image.size() || image.size() - nt < 24 || u32(image, nt) != IMAGE_NT_SIGNATURE)
        return failure(verdict::malformed, "invalid PE signature");
    auto optional = nt + 24;
    auto optional_size = std::size_t(u16(image, nt + 20));
    if (optional_size > image.size() - optional || optional_size < 2) return failure(verdict::malformed, "truncated optional header");
    auto magic = u16(image, optional);
    std::size_t directory = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 96 : magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112 : 0;
    if (!directory || optional_size < directory || u32(image, optional + directory - 4) <= IMAGE_DIRECTORY_ENTRY_SECURITY
        || optional_size < directory + (IMAGE_DIRECTORY_ENTRY_SECURITY + 1) * 8)
        return failure(verdict::malformed, "missing PE security directory");
    auto security = optional + directory + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    auto offset = std::size_t(u32(image, security)), length = std::size_t(u32(image, security + 4));
    if ((offset == 0) != (length == 0) || offset > image.size() || length > image.size() - offset || offset % 8
        || (length && offset < optional + optional_size)) return failure(verdict::malformed, "invalid PE certificate range");
    snapshot_file file;
    if (!file.create(image)) return failure(verdict::unavailable, "image snapshot creation failed", GetLastError());
    // Resolve the SIP from the pinned snapshot and accept only the PE subject.
    GUID pe_subject{};
    if (!CryptSIPRetrieveSubjectGuid(file.path.c_str(), file.handle, &pe_subject))
        return failure(verdict::unsupported, "PE SIP subject lookup failed", GetLastError());
    constexpr GUID expected_pe_subject{0xc689aab8, 0x8e78, 0x11d0, {0x8c, 0x47, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
    if (!IsEqualGUID(pe_subject, expected_pe_subject))
        return failure(verdict::unsupported, "snapshot SIP subject is not PE");
    auto hash_snapshot = [&](std::uint32_t algorithm, bytes& digest, evidence& error) {
        auto oid = algorithm_oid(algorithm);
        if (!oid) { error = failure(verdict::unsupported, "unsupported embedded digest algorithm"); return false; }
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(file.handle, zero, nullptr, FILE_BEGIN)) {
            error = failure(verdict::unavailable, "PE snapshot rewind failed", GetLastError()); return false;
        }
        SIP_SUBJECTINFO subject{}; subject.cbSize = sizeof(subject);
        subject.pgSubjectType = &pe_subject; subject.hFile = file.handle;
        subject.pwsFileName = file.path.c_str(); subject.DigestAlgorithm.pszObjId = const_cast<char*>(oid);
        subject.dwEncodingType = encoding;
        auto sip_error = [&](const char* detail) {
            auto native = GetLastError();
            auto result = native == static_cast<DWORD>(NTE_BAD_ALGID) || native == ERROR_NOT_SUPPORTED
                ? verdict::unsupported : verdict::malformed;
            error = failure(result, detail, native);
            return false;
        };
        DWORD size = 0;
        if (!CryptSIPCreateIndirectData(&subject, &size, nullptr)) return sip_error("PE SIP digest sizing failed");
        if (!size || size > signature_limit) {
            error = failure(verdict::malformed, "invalid PE SIP digest size"); return false;
        }
        bytes storage(size);
        auto indirect = reinterpret_cast<SIP_INDIRECT_DATA*>(storage.data());
        if (!CryptSIPCreateIndirectData(&subject, &size, indirect)) return sip_error("PE SIP digest failed");
        if (!indirect->DigestAlgorithm.pszObjId || std::strcmp(indirect->DigestAlgorithm.pszObjId, oid)
            || indirect->Digest.cbData != digest_size(algorithm) || !indirect->Digest.pbData) {
            error = failure(verdict::unsupported, "PE SIP did not produce the requested digest"); return false;
        }
        digest.assign(indirect->Digest.pbData, indirect->Digest.pbData + indirect->Digest.cbData);
        return true;
    };
    bytes sha256;
    evidence hash_error;
    if (!hash_snapshot(CALG_SHA_256, sha256, hash_error)) return hash_error;
    auto table = image.subspan(offset, length);
    evidence embedded = length ? verify_signed_digest(sha256, CALG_SHA_256, table)
        : failure(verdict::no_signature, "PE has no embedded certificate");
    if (embedded.result == verdict::trusted || embedded.result == verdict::malformed) return embedded;
    bytes sha1;
    if (length) {
        // Hash algorithms named by the table, including bounded nested
        // signatures. Discovery provides no trust: each candidate goes through
        // full signature, digest and chain verification against the snapshot.
        for (auto algorithm : embedded_algorithms(table)) {
            if (algorithm == CALG_SHA_256) continue;
            bytes digest;
            if (!hash_snapshot(algorithm, digest, hash_error)) {
                remember_failure(embedded, hash_error); continue;
            }
            if (algorithm == CALG_SHA1) sha1 = digest;
            auto result = verify_signed_digest(digest, algorithm, table);
            if (result.result == verdict::trusted || result.result == verdict::malformed) return result;
            remember_failure(embedded, std::move(result));
        }
    }
    if (catalogs.empty()) return embedded;
    auto catalog = verify_catalog(sha256, CALG_SHA_256, catalogs);
    if (catalog.result == verdict::trusted) return catalog;
    // An unrelated malformed/untrusted catalog must not stop SHA1 discovery.
    // Keep the strongest failure if neither algorithm establishes trust.
    if (!sha1.empty() || hash_snapshot(CALG_SHA1, sha1, hash_error)) {
        auto legacy = verify_catalog(sha1, CALG_SHA1, catalogs);
        if (legacy.result == verdict::trusted) return legacy;
        remember_failure(catalog, std::move(legacy));
    } else remember_failure(catalog, hash_error);
    if (!length) return catalog;
    remember_failure(embedded, std::move(catalog));
    return embedded;
}
#else
struct verifier::impl { explicit impl(options) {} };
verifier::verifier(options configuration) : impl_(std::make_unique<impl>(std::move(configuration))) {}
verifier::~verifier() = default;
evidence verifier::verify_signed_digest(std::span<const std::uint8_t>, std::uint32_t, std::span<const std::uint8_t>) {
    return failure(verdict::unavailable, "Windows CryptoAPI backend unavailable");
}
evidence verifier::verify_catalog(std::span<const std::uint8_t>, std::uint32_t, std::span<const catalog_snapshot>) {
    return failure(verdict::unavailable, "Windows CryptoAPI backend unavailable");
}
evidence verifier::verify_file(std::span<const std::uint8_t>, std::span<const catalog_snapshot>) {
    return failure(verdict::unavailable, "Windows CryptoAPI backend unavailable");
}
#endif
}
