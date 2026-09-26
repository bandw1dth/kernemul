#include "ci.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../code_integrity.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace
{
// Shared policy layout for modern 64-bit Windows 10/11 CI exports.
#pragma pack(push, 8)
struct policy_info_t
{
	std::uint32_t structure_size;
	NTSTATUS verification_status;
	std::uint32_t flags;
	std::uint32_t padding;
	std::uint64_t chain_info;
	std::int64_t revocation_time;
	std::int64_t valid_from;
	std::int64_t valid_to;
};
#pragma pack(pop)

static_assert(sizeof(policy_info_t) == 48);
static_assert(offsetof(policy_info_t, structure_size) == 0);
static_assert(offsetof(policy_info_t, verification_status) == 4);
static_assert(offsetof(policy_info_t, flags) == 8);
static_assert(offsetof(policy_info_t, padding) == 12);
static_assert(offsetof(policy_info_t, chain_info) == 16);
static_assert(offsetof(policy_info_t, revocation_time) == 24);
static_assert(offsetof(policy_info_t, valid_from) == 32);
static_assert(offsetof(policy_info_t, valid_to) == 40);
static_assert(sizeof(_UNICODE_STRING) == 16);

policy_info_t failure_policy(const NTSTATUS status)
{
	policy_info_t info{};
	info.structure_size = sizeof(info);
	info.verification_status = status;
	return info;
}

// All request inputs are captured before constructing or publishing any output.
constexpr std::size_t certificate_limit = 16 * 1024 * 1024;
constexpr std::size_t catalog_total_limit = 256 * 1024 * 1024;

struct staged_output
{
	addr_t address;
	std::vector<std::uint8_t> bytes;
	bool digest_buffer = false;

	template <typename T>
	explicit staged_output(const emu_object<T>& target, const T& value = {})
		: address(target.address()), bytes(sizeof(T))
	{
		static_assert(std::is_trivially_copyable_v<T>);
		std::memcpy(bytes.data(), &value, sizeof(value));
	}
	staged_output(addr_t target, std::span<const std::uint8_t> value)
		: address(target), bytes(value.begin(), value.end()), digest_buffer(true) {}
};

bool mapped_range(addr_space& space, addr_t address, std::size_t size)
{
	if (!size) return true;
	if (!address || address > std::numeric_limits<addr_t>::max() - (size - 1)) return false;
	std::array<std::uint8_t, 4096> scratch{};
	try
	{
		for (std::size_t offset = 0; offset < size;)
		{
			const auto count = std::min(size - offset, scratch.size());
			space.read_mem(address + offset, scratch.data(), count);
			offset += count;
		}
		return true;
	}
	catch (const std::runtime_error&) { return false; }
}

bool preflight(addr_space& space, const std::vector<staged_output>& outputs)
{
	for (const auto& output : outputs)
		if (output.address && !mapped_range(space, output.address, output.bytes.size())) return false;
	return true;
}

bool write_outputs(addr_space& space, const char* operation, const std::vector<staged_output>& outputs)
{
	// Mapped access, not PTE write permission. The MMU has no multi-range transaction;
	// a concurrent mapping change can still cause a partial write after preflight.
	if (!preflight(space, outputs)) return false;
	try
	{
		for (const auto& output : outputs)
			if (output.address && !output.bytes.empty())
				space.write_mem(output.address, output.bytes.data(), output.bytes.size());
		return true;
	}
	catch (const std::runtime_error& error)
	{
		THREAD_LOG_WARN("{}: output write failed: {}", operation, error.what());
		return false;
	}
}

bool capture(addr_space& space, addr_t address, std::size_t size, std::vector<std::uint8_t>& bytes)
{
	if (!address || !size || address > std::numeric_limits<addr_t>::max() - (size - 1)) return false;
	bytes.resize(size);
	try { space.read_mem(address, bytes.data(), size); return true; }
	catch (const std::runtime_error&) { bytes.clear(); return false; }
}

std::size_t digest_length(std::uint32_t algorithm)
{
	switch (algorithm)
	{
	case 0x8004: return 20;
	case 0x800c: return 32;
	case 0x800d: return 48;
	case 0x800e: return 64;
	default: return 0;
	}
}

NTSTATUS capture_digest(addr_space& space, addr_t address, std::uint32_t size,
	std::uint32_t algorithm, std::vector<std::uint8_t>& digest)
{
	const auto expected = digest_length(algorithm);
	if (!expected) return STATUS_NOT_SUPPORTED;
	if (size != expected) return STATUS_INVALID_IMAGE_HASH;
	return capture(space, address, size, digest) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

NTSTATUS evidence_status(const win::ci::evidence& result)
{
	switch (result.result)
	{
	case win::ci::verdict::trusted: return STATUS_SUCCESS;
	case win::ci::verdict::unsupported:
	case win::ci::verdict::unavailable: return STATUS_NOT_SUPPORTED;
	default: return STATUS_INVALID_IMAGE_HASH;
	}
}

std::string hex_bytes(std::span<const std::uint8_t> bytes)
{
	static constexpr char digits[] = "0123456789abcdef";
	std::string text;
	for (const auto byte : bytes.first(std::min<std::size_t>(bytes.size(), 64)))
	{
		text += digits[byte >> 4];
		text += digits[byte & 15];
	}
	return text;
}

void log_evidence(const char* operation, const win::ci::evidence& result)
{
	THREAD_LOG_INFO("{}: verdict={} native=0x{:X} algorithm=0x{:X} "
		"policy=host-chain bits=0 revocation={} source={} digest={} leaf_sha256={} "
		"detail={} authenticated_timestamp={} signing_time={}", operation,
		win::ci::verdict_name(result.result), result.native_error, result.algorithm,
		result.revocation_checked ? "checked" : "offline-unchecked",
		result.catalog_name.empty() ? "embedded" : result.catalog_name,
		hex_bytes(result.digest), result.signer_chain.empty() ? std::string{} : hex_bytes(result.signer_chain.front().sha256),
		result.detail, !result.timestamp_chain.empty() && result.signing_time != 0, result.signing_time);
}

std::vector<win::ci::catalog_snapshot> snapshot_catalogs(win_filesystem& fs)
{
	const auto root = win_filesystem::normalize("C:/Windows/System32/catroot");
	auto enumeration = fs.enumerate_files_under(root, ".cat", 65536, 4096);
	if (enumeration.limit_exceeded) throw std::length_error("catalog enumeration limit");
	auto& paths = enumeration.paths;
	std::sort(paths.begin(), paths.end());
	std::vector<win::ci::catalog_snapshot> catalogs;
	std::size_t total = 0;
	for (const auto& path : paths)
	{
		const auto relative = std::string_view(path).substr(root.size() + 1);
		if (std::count(relative.begin(), relative.end(), '/') > 16)
			throw std::length_error("catalog depth limit");
		const auto file = fs.open(path);
		if (!file) continue;
		const auto bytes = file->data();
		if (bytes.size() > certificate_limit || bytes.size() > catalog_total_limit - total)
			throw std::length_error("catalog byte limit");
		total += bytes.size();
		catalogs.push_back({path, {bytes.begin(), bytes.end()}});
	}
	return catalogs;
}

// Modern x64 MINCRYPT declarations, pack 8: CiDllDemo/CiDemoDriver/ci.h,
// corroborated by Domito 90ceb466fc2ddb04493dc165fc64336ea4b4e561.
// No inferred policy bits or undocumented public-key/EKU blob encodings.
#pragma pack(push, 8)
struct name_blob { std::uint64_t data; std::uint16_t size, unknown; std::uint32_t padding; };
struct byte_blob { std::uint32_t size, padding; std::uint64_t data; };
struct chain_element
{
	std::uint32_t algorithm, hash_size;
	std::uint8_t hash[64];
	name_blob subject, issuer;
	byte_blob certificate;
};
struct chain_info
{
	std::uint32_t size, padding0;
	std::uint64_t public_keys;
	std::uint32_t key_count, padding1;
	std::uint64_t ekus;
	std::uint32_t eku_count, padding2;
	std::uint64_t elements;
	std::uint32_t element_count, unknown;
	byte_blob authenticode_attributes;
};
#pragma pack(pop)
static_assert(sizeof(name_blob) == 16 && offsetof(name_blob, size) == 8);
static_assert(sizeof(byte_blob) == 16 && offsetof(byte_blob, data) == 8);
static_assert(sizeof(chain_element) == 120 && offsetof(chain_element, subject) == 72
	&& offsetof(chain_element, issuer) == 88 && offsetof(chain_element, certificate) == 104);
static_assert(sizeof(chain_info) == 72 && offsetof(chain_info, public_keys) == 8
	&& offsetof(chain_info, key_count) == 16 && offsetof(chain_info, ekus) == 24
	&& offsetof(chain_info, eku_count) == 32 && offsetof(chain_info, elements) == 40
	&& offsetof(chain_info, element_count) == 48 && offsetof(chain_info, authenticode_attributes) == 56);

struct owned_chain { addr_t address = 0; std::size_t size = 0; };
using policy_key = std::pair<addr_space*, addr_t>;
policy_key owner_key(addr_space& space, addr_t address)
{
	// Kernel policy buffers are shared by all guest address spaces.
	return {address >> 63 ? nullptr : &space, address};
}

struct ci_state
{
	std::mutex mutex;
	win::ci::verifier backend;
	// Private pool: ExFreePool cannot release/recycle a chain behind our bookkeeping.
	win_pool chain_pool;
	std::map<policy_key, owned_chain> owners;
	std::size_t owned_bytes = 0;
	explicit ci_state(addr_space& space) : chain_pool(space) {}

	void release(owned_chain& chain)
	{
		if (chain.address)
		{
			chain_pool.free(chain.address);
			owned_bytes -= chain.size;
			chain = {};
		}
	}
	void release_policy(addr_space& space, addr_t address)
	{
		const auto it = owners.find(owner_key(space, address));
		if (it == owners.end()) return;
		release(it->second);
		owners.erase(it);
	}
};

owned_chain make_chain(ci_state& state, addr_space& kernel_space,
	const std::vector<win::ci::certificate>& certificates)
{
	constexpr std::size_t chain_limit = 1024 * 1024;
	constexpr std::size_t ownership_limit = 64 * 1024 * 1024;
	if (certificates.empty() || certificates.size() > 64) throw std::length_error("certificate chain count");
	std::size_t size = sizeof(chain_info) + certificates.size() * sizeof(chain_element);
	for (const auto& certificate : certificates)
	{
		if (certificate.sha256.size() != 32 || certificate.der.empty()
			|| certificate.der.size() > chain_limit || certificate.subject.size() > 65534
			|| certificate.issuer.size() > 65534) throw std::length_error("certificate evidence size");
		size += certificate.der.size() + certificate.subject.size() + certificate.issuer.size() + 2;
		if (size > chain_limit) throw std::length_error("certificate chain byte limit");
	}
	if (size > ownership_limit - state.owned_bytes) throw std::bad_alloc();
	std::vector<std::uint8_t> bytes(size);
	owned_chain owned{state.chain_pool.allocate(size, pool_tag("CiCh"), false), size};
	if (!owned.address) throw std::bad_alloc();
	state.owned_bytes += size;
	try
	{
		chain_info info{};
		info.size = sizeof(info);
		info.elements = owned.address + sizeof(info);
		info.element_count = static_cast<std::uint32_t>(certificates.size());
		std::memcpy(bytes.data(), &info, sizeof(info));
		std::size_t offset = sizeof(info) + certificates.size() * sizeof(chain_element);
		const auto append_name = [&](const std::string& name) -> name_blob
		{
			name_blob blob{};
			blob.data = owned.address + offset;
			blob.size = static_cast<std::uint16_t>(name.size());
			std::memcpy(bytes.data() + offset, name.data(), name.size());
			offset += name.size() + 1;
			return blob;
		};
		for (std::size_t i = 0; i < certificates.size(); ++i)
		{
			const auto& certificate = certificates[i];
			chain_element element{};
			element.algorithm = 0x800c; // SHA-256 of the certificate DER, never the file digest.
			element.hash_size = 32;
			std::memcpy(element.hash, certificate.sha256.data(), 32);
			element.subject = append_name(certificate.subject);
			element.issuer = append_name(certificate.issuer);
			element.certificate.size = static_cast<std::uint32_t>(certificate.der.size());
			element.certificate.data = owned.address + offset;
			std::memcpy(bytes.data() + offset, certificate.der.data(), certificate.der.size());
			offset += certificate.der.size();
			std::memcpy(bytes.data() + sizeof(info) + i * sizeof(element), &element, sizeof(element));
		}
		kernel_space.write_mem(owned.address, bytes.data(), bytes.size());
		return owned;
	}
	catch (...) { state.release(owned); throw; }
}

NTSTATUS publish(ci_state& state, win_kernel_state& kernel, addr_space& space, const char* operation,
	const win::ci::evidence& evidence, NTSTATUS status,
	emu_object<policy_info_t> policy_info, emu_object<policy_info_t> timestamp_policy_info,
	emu_object<std::int64_t> signing_time, std::vector<staged_output> extra = {}, addr_t catalog_name = 0)
{
	auto extras = extra.size();
	bool publication_started = false;
	bool preparation_failed = false;
	owned_chain signer{}, timestamp{};
	addr_t catalog_buffer = 0;
	auto signer_policy = failure_policy(status);
	auto timestamp_policy = failure_policy(status);
	std::int64_t time = 0;
	_UNICODE_STRING catalog{};
	const auto append_outputs = [&]
	{
		extra.erase(extra.begin() + extras, extra.end());
		extra.emplace_back(policy_info, signer_policy);
		extra.emplace_back(timestamp_policy_info, timestamp_policy);
		extra.emplace_back(signing_time, time);
		if (catalog_name) extra.emplace_back(emu_object<_UNICODE_STRING>(space, catalog_name), catalog);
	};
	try
	{
		append_outputs();
		if (!preflight(space, extra)) return STATUS_ACCESS_VIOLATION;
		if (status == STATUS_SUCCESS)
		{
			if (evidence.signer_chain.empty()) throw std::length_error("trusted result lacks certificate evidence");
			// Reserve ownership slots before publication, so allocation failure cannot
			// leave a published pointer without a host owner. Copies are not owners.
			for (const auto address : {policy_info.address(), timestamp_policy_info.address()})
			{
				if (!address) continue;
				const auto key = owner_key(space, address);
				if (!state.owners.contains(key) && state.owners.size() >= 4096) throw std::bad_alloc();
				state.owners.try_emplace(key);
			}
			if (policy_info) signer = make_chain(state, kernel.kernel_space(), evidence.signer_chain);
			signer_policy.chain_info = signer.address;
			signer_policy.valid_from = evidence.signer_chain.front().not_before;
			signer_policy.valid_to = evidence.signer_chain.front().not_after;
			timestamp_policy = failure_policy(STATUS_NOT_FOUND);
			if (!evidence.timestamp_chain.empty() && evidence.signing_time)
			{
				if (timestamp_policy_info) timestamp = make_chain(state, kernel.kernel_space(), evidence.timestamp_chain);
				timestamp_policy = failure_policy(STATUS_SUCCESS);
				timestamp_policy.chain_info = timestamp.address;
				timestamp_policy.valid_from = evidence.timestamp_chain.front().not_before;
				timestamp_policy.valid_to = evidence.timestamp_chain.front().not_after;
				time = evidence.signing_time;
			}
			if (catalog_name && !evidence.catalog_name.empty())
			{
				auto name = widen_string(evidence.catalog_name);
				std::replace(name.begin(), name.end(), u'/', u'\\');
				if (name.size() > 32766) throw std::length_error("catalog name length");
				catalog.Length = static_cast<std::uint16_t>(name.size() * sizeof(char16_t));
				catalog.MaximumLength = catalog.Length + sizeof(char16_t);
				catalog_buffer = kernel.pool.allocate(catalog.MaximumLength, pool_tag("CiNm"), false);
				if (!catalog_buffer) throw std::bad_alloc();
				name.push_back(0);
				kernel.kernel_space().write_mem(catalog_buffer, name.data(), catalog.MaximumLength);
				catalog.Buffer = reinterpret_cast<decltype(catalog.Buffer)>(catalog_buffer);
				// Emulator contract: caller releases Buffer with ExFreePool (or
				// ExFreePoolWithTag). Not owned by CiFreePolicyInfo. Sources do not
				// specify a precise native catalog-name deallocator. No host pointer.
			}
			append_outputs();
		}
		publication_started = true;
		if (!write_outputs(space, operation, extra)) status = STATUS_ACCESS_VIOLATION;
		else
		{
			// Host-side ownership uses the original policy address, never guest pointers.
			// If output ranges overlap, retain only a chain whose pointer survived
			// publication. Process an aliased policy address just once.
			addr_t previous = 0;
			for (const auto address : {policy_info.address(), timestamp_policy_info.address()})
			{
				if (!address || address == previous) continue;
				previous = address;
				auto it = state.owners.find(owner_key(space, address));
				if (it == state.owners.end()) continue;
				state.release(it->second);
				const auto actual = space.read_mem<policy_info_t>(address);
				if (signer.address && actual.chain_info == signer.address)
				{ it->second = signer; signer = {}; }
				else if (timestamp.address && actual.chain_info == timestamp.address)
				{ it->second = timestamp; timestamp = {}; }
			}
			catalog_buffer = 0; // Independent ownership transferred to the guest.
		}
	}
	catch (const std::bad_alloc&) { status = STATUS_INSUFFICIENT_RESOURCES; preparation_failed = true; }
	catch (const std::length_error&) { status = STATUS_INSUFFICIENT_RESOURCES; preparation_failed = true; }
	catch (const std::runtime_error&) { status = STATUS_ACCESS_VIOLATION; preparation_failed = true; }
	state.release(signer);
	state.release(timestamp);
	if (catalog_buffer) kernel.pool.free(catalog_buffer);
	if (preparation_failed && !publication_started)
	{
		// A graph-allocation failure is a verification failure, not a partial success.
		// Never emit a previously staged digest after publication preparation fails.
		try
		{
			extra.erase(extra.begin() + std::min(extras, extra.size()), extra.end());
			std::erase_if(extra, [](const auto& output) { return output.digest_buffer; });
			for (auto& output : extra) std::fill(output.bytes.begin(), output.bytes.end(), 0);
			extras = extra.size();
			signer_policy = timestamp_policy = failure_policy(status);
			time = 0;
			catalog = {};
			append_outputs();
			if (!write_outputs(space, operation, extra)) status = STATUS_ACCESS_VIOLATION;
			else
			{
				state.release_policy(space, policy_info.address());
				state.release_policy(space, timestamp_policy_info.address());
			}
		}
		catch (const std::bad_alloc&) { status = STATUS_INSUFFICIENT_RESOURCES; }
	}
	// Remove unfilled reservations; failure must not consume the ownership budget.
	for (auto it = state.owners.begin(); it != state.owners.end();)
		if (!it->second.address) it = state.owners.erase(it); else ++it;
	THREAD_LOG_INFO("{}: adapter_status=0x{:X}", operation, status);
	return status;
}
}

void modules::register_ci(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	const auto shared = std::make_shared<ci_state>(state.kernel_space());
	LOG_INFO("CI: host trust verification; offline unchecked revocation by default; "
		"WDAC, secure-process and accepted-root policies unsupported; policy bits remain zero");

	state.redirect(mod, "CiCheckSignedFile",
		[st, shared](vcpu& cpu, const addr_t digest, const std::uint32_t digest_size,
			const std::uint32_t digest_identifier, const addr_t win_certificate,
			const std::uint32_t certificate_size, emu_object<policy_info_t> policy_info,
			emu_object<std::int64_t> signing_time,
			emu_object<policy_info_t> timestamp_policy_info) -> NTSTATUS
		{
			std::scoped_lock lock(shared->mutex);
			auto& space = *cpu.curr_addr_space();
			win::ci::evidence result;
			NTSTATUS status;
			try
			{
				std::vector<std::uint8_t> hash, certificate;
				status = capture_digest(space, digest, digest_size, digest_identifier, hash);
				if (status == STATUS_SUCCESS)
				{
					if (!certificate_size || certificate_size > certificate_limit) status = STATUS_INVALID_IMAGE_HASH;
					else if (!capture(space, win_certificate, certificate_size, certificate)) status = STATUS_ACCESS_VIOLATION;
					else
					{
						result = shared->backend.verify_signed_digest(hash, digest_identifier, certificate);
						if (result.digest.empty()) result.digest = hash;
						if (!result.algorithm) result.algorithm = digest_identifier;
						log_evidence("CiCheckSignedFile", result);
						status = evidence_status(result);
					}
				}
			}
			catch (const std::bad_alloc&) { status = STATUS_INSUFFICIENT_RESOURCES; }
			catch (const std::exception&) { status = STATUS_INVALID_IMAGE_HASH; }
			return publish(*shared, *st, space, "CiCheckSignedFile", result, status,
				policy_info, timestamp_policy_info, signing_time);
		});

	state.redirect(mod, "CiFreePolicyInfo", [shared](vcpu& cpu, emu_object<policy_info_t> policy_info)
	{
		std::scoped_lock lock(shared->mutex);
		if (policy_info)
		{
			auto& space = *cpu.curr_addr_space();
			if (write_outputs(space, "CiFreePolicyInfo", {staged_output(policy_info)}))
				shared->release_policy(space, policy_info.address());
		}
	});

	state.redirect(mod, "CiVerifyHashInCatalog",
		[st, shared](vcpu& cpu, const addr_t hash, const std::uint32_t hash_size,
			const std::uint32_t hash_algorithm, const std::uint32_t reload_catalogs,
			const std::uint32_t secure_process, const std::uint32_t accepted_roots,
			emu_object<policy_info_t> policy_info, emu_object<_UNICODE_STRING> catalog_name,
			emu_object<std::int64_t> signing_time,
			emu_object<policy_info_t> timestamp_policy_info) -> NTSTATUS
		{
			std::scoped_lock lock(shared->mutex);
			auto& space = *cpu.curr_addr_space();
			win::ci::evidence result;
			NTSTATUS status = STATUS_NOT_SUPPORTED;
			try
			{
				std::vector<std::uint8_t> digest;
				if (!secure_process && !accepted_roots && reload_catalogs <= 1)
				{
					status = capture_digest(space, hash, hash_size, hash_algorithm, digest);
					if (status == STATUS_SUCCESS)
					{
						// Both reload values take a fresh deterministic snapshot: no stale cache.
						const auto catalogs = snapshot_catalogs(st->fs);
						result = shared->backend.verify_catalog(digest, hash_algorithm, catalogs);
						if (result.digest.empty()) result.digest = digest;
						if (!result.algorithm) result.algorithm = hash_algorithm;
						log_evidence("CiVerifyHashInCatalog", result);
						status = evidence_status(result);
					}
				}
			}
			catch (const std::bad_alloc&) { status = STATUS_INSUFFICIENT_RESOURCES; }
			catch (const std::length_error&) { status = STATUS_INSUFFICIENT_RESOURCES; }
			catch (const std::exception&) { status = STATUS_INVALID_IMAGE_HASH; }
			return publish(*shared, *st, space, "CiVerifyHashInCatalog", result, status,
				policy_info, timestamp_policy_info, signing_time, {}, catalog_name.address());
		});

	state.redirect(mod, "CiValidateFileObject",
		[st, shared](vcpu& cpu, const addr_t file_object, const std::uint32_t flags,
			const std::uint8_t signing_level, emu_object<policy_info_t> policy_info,
			emu_object<policy_info_t> timestamp_policy_info, emu_object<std::int64_t> signing_time,
			const addr_t digest, emu_object<std::uint32_t> digest_size,
			emu_object<std::uint32_t> digest_identifier) -> NTSTATUS
		{
			std::scoped_lock lock(shared->mutex);
			auto& space = *cpu.curr_addr_space();
			win::ci::evidence result;
			NTSTATUS status = STATUS_INVALID_PARAMETER;
			std::uint32_t capacity = 0, required = 0, algorithm = 0;
			std::vector<staged_output> extra;
			try
			{
				// Capacity is input even when it aliases another output.
				if (digest_size)
				{
					std::vector<std::uint8_t> bytes;
					if (!capture(space, digest_size.address(), sizeof(capacity), bytes))
						return STATUS_ACCESS_VIOLATION;
					std::memcpy(&capacity, bytes.data(), sizeof(capacity));
				}
				const auto host = st->objs.get_object<file_host>(file_object);
				if (flags || signing_level) status = STATUS_NOT_SUPPORTED;
				else if (host && host->file)
				{
					const auto bytes = host->file->data();
					if (bytes.size() > catalog_total_limit) throw std::length_error("file byte limit");
					const std::vector<std::uint8_t> image(bytes.begin(), bytes.end());
					const auto catalogs = snapshot_catalogs(st->fs);
					result = shared->backend.verify_file(image, catalogs);
					log_evidence("CiValidateFileObject", result);
					status = evidence_status(result);
					if (status == STATUS_SUCCESS)
					{
						if (!digest_length(result.algorithm) || result.digest.size() != digest_length(result.algorithm))
							status = STATUS_INVALID_IMAGE_HASH;
						else
						{
							required = static_cast<std::uint32_t>(result.digest.size());
							algorithm = result.algorithm;
							if (capacity < required || !digest) status = STATUS_BUFFER_TOO_SMALL;
							else extra.emplace_back(digest, result.digest);
						}
					}
				}
			}
			catch (const std::bad_alloc&) { status = STATUS_INSUFFICIENT_RESOURCES; }
			catch (const std::length_error&) { status = STATUS_INSUFFICIENT_RESOURCES; }
			catch (const std::exception&) { status = STATUS_INVALID_IMAGE_HASH; }
			if (status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL)
			{
				required = algorithm = 0;
				extra.clear();
			}
			extra.emplace_back(digest_size, required);
			extra.emplace_back(digest_identifier, algorithm);
			return publish(*shared, *st, space, "CiValidateFileObject", result, status,
				policy_info, timestamp_policy_info, signing_time, std::move(extra));
		});
}
