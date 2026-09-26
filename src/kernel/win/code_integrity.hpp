#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

// Host verification evidence only. No Windows SDK or guest pointers cross this boundary.
namespace win::ci {
enum class verdict {
    trusted, malformed, unsupported, digest_mismatch, bad_signature,
    untrusted_chain, expired, revoked, no_signature, no_catalog, unavailable
};
enum class revocation_policy { offline_unchecked, offline_cache_required };
struct options {
    revocation_policy revocation = revocation_policy::offline_unchecked;
    // Application-owned test/configuration anchors, never installed in a host store.
    bool exclusive_roots = false;
    std::vector<std::vector<std::uint8_t>> roots;
};
struct certificate {
    std::vector<std::uint8_t> der;
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> sha256;
    std::vector<std::string> ekus;
    std::string subject, issuer;
    std::int64_t not_before = 0, not_after = 0; // Windows FILETIME ticks.
};
struct evidence {
    verdict result = verdict::unavailable;
    std::string detail;
    std::uint32_t native_error = 0;
    bool revocation_checked = false;
    std::vector<certificate> signer_chain, timestamp_chain;
    std::int64_t signing_time = 0;
    std::string catalog_name;
    std::vector<std::uint8_t> digest;
    std::uint32_t algorithm = 0;
};
struct catalog_snapshot {
    std::string guest_path;
    std::vector<std::uint8_t> bytes;
};
class verifier {
public:
    explicit verifier(options configuration = {});
    ~verifier();
    verifier(const verifier&) = delete;
    verifier& operator=(const verifier&) = delete;
    evidence verify_signed_digest(std::span<const std::uint8_t> digest,
        std::uint32_t algorithm, std::span<const std::uint8_t> security_directory);
    evidence verify_catalog(std::span<const std::uint8_t> digest,
        std::uint32_t algorithm, std::span<const catalog_snapshot> catalogs);
    evidence verify_file(std::span<const std::uint8_t> image,
        std::span<const catalog_snapshot> catalogs);
private:
    struct impl;
    std::unique_ptr<impl> impl_;
};
const char* verdict_name(verdict result);
}
