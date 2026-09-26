#include "firmware_query.hpp"
#include "win_kernel.hpp"
#include "execution_mode.hpp"
#include "process_memory.hpp"
#include "../../util/log.hpp"
#include "../../util/string.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <new>

namespace win::firmware {
namespace {
constexpr NTSTATUS variable_not_found = 0xc0000100;
constexpr NTSTATUS privilege_not_held = 0xc0000061;
constexpr NTSTATUS invalid_device_state = 0xc0000184;

bool overlaps(addr_t a, std::size_t an, addr_t b, std::size_t bn)
{
	return an && bn && (a <= b ? b - a < an : a - b < bn);
}

struct write_piece {
	addr_t physical;
	std::vector<std::uint8_t> before, after;
};

NTSTATUS perform(win_kernel_state& state, vcpu& cpu, query_entry entry,
	addr_t name_address, addr_t vendor_address, addr_t value_address,
	addr_t length_address, addr_t attributes_address, std::u16string& name,
	std::uint32_t& required, std::uint32_t& attributes)
{
	// Conservative emulator policy: illegal IRQL returns a deterministic status,
	// rather than terminating the guest. Firmware access requires PASSIVE_LEVEL.
	if (cpu.in_dpc || (state.emulator() && state.emulator()->irql(cpu) != passive_level))
		return invalid_device_state;
	if (!name_address || !vendor_address || !length_address) return STATUS_INVALID_PARAMETER;
	bool user = false;
	if (entry != query_entry::ex)
	{
		const auto thread = std::dynamic_pointer_cast<win_thread>(cpu.thread());
		if (!thread || !thread->ethread()) return STATUS_INVALID_PARAMETER;
		const auto previous = thread->ethread().field(&_ETHREAD::Tcb).field(&_KTHREAD::PreviousMode).read();
		if (previous != 0 && previous != 1) return STATUS_INVALID_PARAMETER;
		user = executing_user_mode(cpu) || (entry == query_entry::nt && previous != 0);
	}
	const auto process = state.current_process(cpu); // Effective (possibly attached) process.
	const auto space = cpu.curr_addr_space();
	if (!space || !space->mmu_) return STATUS_ACCESS_VIOLATION;
	auto* mem = process_memory_copy::memory(process);
	auto lock = process_memory_copy::lock_memory(process);
	auto capture = [&](addr_t address, void* data, std::size_t size, bool write = false) {
		if (!process_memory_copy::permitted(mem, *space, address, size, write, user)) return false;
		if (size) space->read_mem(address, data, size);
		return true;
	};
	_UNICODE_STRING descriptor{};
	guid vendor{};
	std::uint32_t capacity = 0;
	// Capture every input before inspecting or writing any output. No terminator
	// read is needed: UNICODE_STRING.Length is authoritative and bounded.
	if (!capture(name_address, &descriptor, sizeof(descriptor))) return STATUS_ACCESS_VIOLATION;
	if ((descriptor.Length & 1) || (descriptor.MaximumLength & 1)
		|| descriptor.Length > descriptor.MaximumLength || !descriptor.Length
		|| descriptor.Length / 2 > 1024 || !descriptor.Buffer) return STATUS_INVALID_PARAMETER;
	name.resize(descriptor.Length / 2);
	if (!capture(guest_va(descriptor.Buffer), name.data(), descriptor.Length)
		|| !capture(vendor_address, vendor.data(), vendor.size())
		|| !capture(length_address, &capacity, sizeof(capacity))) return STATUS_ACCESS_VIOLATION;
	if (name.find(u'\0') != std::u16string::npos) return STATUS_INVALID_PARAMETER;
	if (!value_address && capacity) return STATUS_INVALID_PARAMETER;
	if (!process_memory_copy::valid_range(value_address, capacity, user)) return STATUS_ACCESS_VIOLATION;
	// Emulator policy: reject overlapping declared output ranges, even for a
	// short buffer. Windows does not promise useful output alias semantics.
	if (overlaps(length_address, 4, attributes_address, attributes_address ? 4 : 0)
		|| overlaps(value_address, capacity, length_address, 4)
		|| overlaps(value_address, capacity, attributes_address, attributes_address ? 4 : 0))
		return STATUS_INVALID_PARAMETER;
	std::uint32_t scratch;
	if (!capture(length_address, &scratch, 4, true)
		|| (attributes_address && !capture(attributes_address, &scratch, 4, true))) return STATUS_ACCESS_VIOLATION;
	const auto* variable = state.firmware.find(vendor, name);
	if (variable && (variable->attributes & 4))
	{
		if (variable->value.size() > std::numeric_limits<std::uint32_t>::max()) return STATUS_INVALID_PARAMETER;
		required = static_cast<std::uint32_t>(variable->value.size());
		attributes = variable->attributes;
	}
	// Check the whole declared writable range, but never copy capacity bytes.
	// Kernel ranges only have backing validation, not permission metadata.
	if (capacity && !process_memory_copy::permitted(mem, *space, value_address, capacity, true, user))
		return STATUS_ACCESS_VIOLATION;
	// No token privilege model exists. Safely captured/probed UserMode queries
	// fail closed instead of pretending SeSystemEnvironmentPrivilege was granted.
	if (user) return privilege_not_held;
	if (state.firmware.type() == mode::legacy_bios) return STATUS_NOT_IMPLEMENTED;
	if (!variable || !(variable->attributes & 4)) return variable_not_found;
	const bool small = capacity < required;

	// Resolve and read all destination backing before any write, holding the
	// process VM metadata lock throughout. Commit uses the captured physical
	// pages so a later virtual translation cannot cause a partial host write.
	// Physical backing is retained for the machine lifetime in this emulator.
	std::vector<write_piece> writes;
	auto stage = [&](addr_t address, const void* bytes, std::size_t size) {
		auto source = static_cast<const std::uint8_t*>(bytes);
		for (std::size_t done = 0; done < size;)
		{
			const auto at = address + done;
			const auto chunk = std::min(size - done, space->mmu_->page_size() - at % space->mmu_->page_size());
			const auto physical = space->mmu_->virt_to_phys(*space, at);
			if (!physical) return false;
			write_piece piece{*physical, std::vector<std::uint8_t>(chunk),
				std::vector<std::uint8_t>(source + done, source + done + chunk)};
			space->mmu_->read_phys(*physical, piece.before.data(), chunk);
			writes.push_back(std::move(piece));
			done += chunk;
		}
		return true;
	};
	if (!stage(length_address, &required, sizeof(required))) return STATUS_ACCESS_VIOLATION;
	if (!small && ((!stage(value_address, variable->value.data(), required))
		|| (attributes_address && !stage(attributes_address, &attributes, sizeof(attributes)))))
		return STATUS_ACCESS_VIOLATION;
	// Distinct virtual output ranges can still alias the same physical bytes.
	for (std::size_t i = 0; i < writes.size(); ++i)
		for (std::size_t j = 0; j < i; ++j)
			if (overlaps(writes[i].physical, writes[i].after.size(), writes[j].physical, writes[j].after.size()))
				return STATUS_INVALID_PARAMETER;
	try
	{
		for (const auto& piece : writes)
			space->mmu_->write_phys(piece.physical, piece.after.data(), piece.after.size());
	}
	catch (...)
	{
		// No guest fault can reach commit after preflight. Restore on an
		// unexpected backend failure too; never let a host exception escape.
		for (const auto& piece : writes)
			try { space->mmu_->write_phys(piece.physical, piece.before.data(), piece.before.size()); }
			catch (...) {}
		throw;
	}
	// Explicit model policy: short buffers update only required length.
	// Attributes and value remain unchanged (Windows leaves attributes unspecified).
	return small ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}
}

NTSTATUS query(win_kernel_state& state, vcpu& cpu, query_entry entry,
	addr_t name_address, addr_t vendor_address, addr_t value_address,
	addr_t length_address, addr_t attributes_address)
{
	std::u16string name;
	std::uint32_t required = 0, attributes = 0;
	NTSTATUS status;
	try { status = perform(state, cpu, entry, name_address, vendor_address, value_address,
		length_address, attributes_address, name, required, attributes); }
	catch (const std::bad_alloc&) { status = STATUS_INSUFFICIENT_RESOURCES; }
	catch (...) { status = STATUS_ACCESS_VIOLATION; }
	// Escape guest control characters so malformed names cannot corrupt the
	// trace. Logging must not turn a completed query into an allocation fault.
	try { THREAD_LOG_INFO("FirmwareQuery(entry={}, name={:?}, status=0x{:X}, required={}, attributes=0x{:X})",
		static_cast<unsigned>(entry), narrow_wstring(name), status, required, attributes); }
	catch (...) {}
	return status;
}
}
