#include "ci.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <array>
#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <type_traits>

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

// Fixed-size staging also zeros ABI padding; no guest-controlled allocations or sizes.
struct staged_output
{
	addr_t address;
	std::size_t size;
	std::array<std::uint8_t, sizeof(policy_info_t)> bytes{};

	template <typename T>
	explicit staged_output(const emu_object<T>& target)
		: address(target.address()), size(sizeof(T))
	{
		static_assert(sizeof(T) <= sizeof(policy_info_t));
		static_assert(std::is_trivially_copyable_v<T>);
	}

	staged_output(const emu_object<policy_info_t>& target, const policy_info_t& value)
		: staged_output(target)
	{
		std::memcpy(bytes.data(), &value, sizeof(value));
	}
};

bool write_outputs(addr_space& space, const char* operation,
	const std::initializer_list<staged_output> outputs)
{
	std::array<std::uint8_t, sizeof(policy_info_t)> scratch{};
	// Preflight every present range before any mutation. These MMU reads/writes bypass
	// guest PTE protection: this checks mapped access, not guest write permission.
	for (const auto& output : outputs)
	{
		if (!output.address)
			continue;
		if (output.address > std::numeric_limits<addr_t>::max() - (output.size - 1))
		{
			THREAD_LOG_WARN("{}: preflight range overflow at 0x{:X}, size {}",
				operation, output.address, output.size);
			return false;
		}
		try
		{
			space.read_mem(output.address, scratch.data(), output.size);
		}
		catch (const std::runtime_error& error)
		{
			THREAD_LOG_WARN("{}: preflight read failed at 0x{:X}, size {}: {}",
				operation, output.address, output.size, error.what());
			return false;
		}
	}
	// The MMU does not provide a transaction across these calls. A mapping change after
	// preflight can still cause a partial write; report that memory failure explicitly.
	for (const auto& output : outputs)
	{
		if (!output.address)
			continue;
		try
		{
			space.write_mem(output.address, output.bytes.data(), output.size);
		}
		catch (const std::runtime_error& error)
		{
			THREAD_LOG_WARN("{}: output write failed at 0x{:X}, size {}: {}",
				operation, output.address, output.size, error.what());
			return false;
		}
	}
	return true;
}
}

void modules::register_ci(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "CiCheckSignedFile",
		[](vcpu& cpu, const addr_t digest, const std::uint32_t digest_size,
			const std::uint32_t digest_identifier, const addr_t win_certificate,
			const std::uint32_t certificate_size, emu_object<policy_info_t> policy_info,
			emu_object<std::int64_t> signing_time,
			emu_object<policy_info_t> timestamp_policy_info) -> NTSTATUS
		{
			THREAD_LOG_WARN("CiCheckSignedFile(digest=0x{:X}/{}, algorithm={}, certificate="
				"0x{:X}/{}): verification backend unavailable; returning INVALID_IMAGE_HASH",
				digest, digest_size, digest_identifier, win_certificate, certificate_size);
			const auto policy = failure_policy(STATUS_INVALID_IMAGE_HASH);
			return write_outputs(*cpu.curr_addr_space(), "CiCheckSignedFile", {
				staged_output(policy_info, policy), staged_output(signing_time),
				staged_output(timestamp_policy_info, policy)
			}) ? STATUS_INVALID_IMAGE_HASH : STATUS_ACCESS_VIOLATION;
		});

	// No chains are allocated here. Never follow or free foreign guest pointers.
	state.redirect(mod, "CiFreePolicyInfo", [](vcpu& cpu, emu_object<policy_info_t> policy_info)
	{
		if (policy_info && write_outputs(*cpu.curr_addr_space(), "CiFreePolicyInfo",
			{ staged_output(policy_info) }))
			THREAD_LOG_INFO("CiFreePolicyInfo(0x{:X}): policy cleared", policy_info.address());
	});

	state.redirect(mod, "CiVerifyHashInCatalog",
		[](vcpu& cpu, const addr_t hash, const std::uint32_t hash_size,
			const std::uint32_t hash_algorithm, const std::uint32_t reload_catalogs,
			const std::uint32_t secure_process, const std::uint32_t accepted_roots,
			emu_object<policy_info_t> policy_info, emu_object<_UNICODE_STRING> catalog_name,
			emu_object<std::int64_t> signing_time,
			emu_object<policy_info_t> timestamp_policy_info) -> NTSTATUS
		{
			THREAD_LOG_WARN("CiVerifyHashInCatalog(hash=0x{:X}/{}, algorithm={}, reload={}, "
				"secure={}, roots=0x{:X}): verification backend unavailable; returning INVALID_IMAGE_HASH",
				hash, hash_size, hash_algorithm, reload_catalogs, secure_process, accepted_roots);
			const auto policy = failure_policy(STATUS_INVALID_IMAGE_HASH);
			return write_outputs(*cpu.curr_addr_space(), "CiVerifyHashInCatalog", {
				staged_output(policy_info, policy), staged_output(catalog_name),
				staged_output(signing_time), staged_output(timestamp_policy_info, policy)
			}) ? STATUS_INVALID_IMAGE_HASH : STATUS_ACCESS_VIOLATION;
		});

	state.redirect(mod, "CiValidateFileObject",
		[st](vcpu& cpu, const addr_t file_object, const std::uint32_t flags,
			const std::uint8_t signing_level, emu_object<policy_info_t> policy_info,
			emu_object<policy_info_t> timestamp_policy_info, emu_object<std::int64_t> signing_time,
			const addr_t digest, emu_object<std::uint32_t> digest_size,
			emu_object<std::uint32_t> digest_identifier) -> NTSTATUS
		{
			const auto host = st->objs.get_object<file_host>(file_object);
			const auto status = host && host->file ? STATUS_INVALID_IMAGE_HASH : STATUS_INVALID_PARAMETER;
			if (status == STATUS_INVALID_PARAMETER)
				THREAD_LOG_WARN("CiValidateFileObject: 0x{:X} is not a file object", file_object);
			else
				THREAD_LOG_WARN("CiValidateFileObject(file=0x{:X}, flags=0x{:X}, level={}, digest=0x{:X}): "
					"verification backend unavailable; returning INVALID_IMAGE_HASH",
					file_object, flags, signing_level, digest);

			// No verified digest is available. Leave the variable-size digest buffer untouched.
			// digest_size is an in/out capacity; ignore its input because no digest is emitted.
			// Policy Size is output-only, not an input capacity.
			const auto policy = failure_policy(status);
			return write_outputs(*cpu.curr_addr_space(), "CiValidateFileObject", {
				staged_output(policy_info, policy), staged_output(timestamp_policy_info, policy),
				staged_output(signing_time), staged_output(digest_size), staged_output(digest_identifier)
			}) ? status : STATUS_ACCESS_VIOLATION;
		});
}
