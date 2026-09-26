#include "nt_mem_ops.hpp"
#include "ntoskrnl.hpp"
#include "../win_kernel.hpp"
#include "../mdl.hpp"
#include "../objects.hpp"
#include "../pool.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../map.hpp"
#include "../../../util/log.hpp"
#include <algorithm>
#include <span>
#include <array>
#include <cstring>
#include <vector>
#include <string_view>

namespace
{

constexpr std::uint32_t mm_copy_memory_physical = 0x1;
constexpr std::uint32_t mm_copy_memory_virtual = 0x2;

// There is one kind of memory behind every mapping here, so the type only reaches the log.
std::string_view caching_type_name(const std::uint32_t type)
{
	switch (type)
	{
	case 0:  return "NonCached";
	case 1:  return "Cached";
	case 2:  return "WriteCombined";
	case 3:  return "HardwareCoherentCached";
	case 4:  return "NonCachedUnordered";
	case 5:  return "USWCCached";
	default: return "?";
	}
}


}

// The page tables the mmu walks are the guest's own, not a shadow of the guest's.
void modules::register_ntoskrnl_mem_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "MmIsAddressValid",
		[](vcpu& cpu, const addr_t virtual_address) -> bool
		{
			auto& space = *cpu.curr_addr_space();
			const bool valid = space.mmu_->virt_to_phys(space, virtual_address).has_value();

			THREAD_LOG_INFO("MmIsAddressValid(0x{:X}) -> {}", virtual_address, valid);

			return valid;
		});

	state.redirect(mod, "MmGetPhysicalAddress",
		[st](vcpu& cpu, const addr_t base_address) -> std::uint64_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto pa = space.mmu_->virt_to_phys(space, base_address).value_or(0);

			if (!pa)
				THREAD_LOG_WARN("MmGetPhysicalAddress: 0x{:X} is not mapped", base_address);
			else
				THREAD_LOG_INFO("MmGetPhysicalAddress(0x{:X}) -> 0x{:X}", base_address, pa);

			return pa;
		});

	// Real NT reads it out of the PFN database; here the search reaches whichever mapping is first.
	state.redirect(mod, "MmGetVirtualForPhysical",
		[](vcpu& cpu, const std::uint64_t physical_address) -> addr_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto va = space.mmu_->phys_to_virt(space, physical_address).value_or(0);

			if (!va)
				THREAD_LOG_WARN("MmGetVirtualForPhysical: 0x{:X} is not mapped anywhere",
					physical_address);
			else
				THREAD_LOG_INFO("MmGetVirtualForPhysical(0x{:X}) -> 0x{:X}", physical_address, va);

			return va;
		});

	state.redirect(mod, "MmCopyMemory",
		[](vcpu& cpu, const addr_t target_address, const std::uint64_t source_address,
			const std::uint64_t number_of_bytes, const std::uint32_t flags,
			emu_object<std::uint64_t> number_of_bytes_transferred) -> NTSTATUS
		{
			const auto kind = flags & (mm_copy_memory_physical | mm_copy_memory_virtual);

			if (kind != mm_copy_memory_physical && kind != mm_copy_memory_virtual)
			{
				THREAD_LOG_WARN("MmCopyMemory: flags 0x{:X} name neither a virtual source nor a "
					"physical one", flags);
				return STATUS_INVALID_PARAMETER;
			}

			auto& space = *cpu.curr_addr_space();
			std::vector<std::uint8_t> buffer(number_of_bytes);

			try
			{
				if (kind == mm_copy_memory_physical)
					space.mmu_->read_phys(source_address, buffer.data(), number_of_bytes);
				else
					space.read_mem(source_address, buffer.data(), number_of_bytes);
			}
			catch (const std::exception& e)
			{
				THREAD_LOG_WARN("MmCopyMemory: cannot read {} bytes from {} 0x{:X}: {}",
					number_of_bytes, kind == mm_copy_memory_physical ? "physical" : "virtual",
					source_address, e.what());

				if (number_of_bytes_transferred)
					number_of_bytes_transferred.write(0);

				return STATUS_INVALID_ADDRESS;
			}

			space.write_mem(target_address, buffer.data(), number_of_bytes);

			if (number_of_bytes_transferred)
				number_of_bytes_transferred.write(number_of_bytes);

			THREAD_LOG_INFO("MmCopyMemory(target=0x{:X}, source=0x{:X}, {} bytes, flags=0x{:X})",
				target_address, source_address, number_of_bytes, flags);

			return STATUS_SUCCESS;
		});

	// A fresh kernel window is pointed at the physical pages named; unbacked memory has none.
	auto map_io_space = [](vcpu& cpu, const std::uint64_t physical_address,
		const std::uint64_t number_of_bytes, const std::string_view who) -> addr_t
	{
		auto& space = *cpu.curr_addr_space();

		const auto base = mdl_page_base(physical_address);
		const auto offset = mdl_page_offset(physical_address);

		addr_t va = 0;

		try
		{
			va = space.map_phys(base, number_of_bytes + offset, prot_rw | prot_supervisor);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_WARN("{}: cannot map {} bytes at physical 0x{:X}: {}",
				who, number_of_bytes, physical_address, e.what());
			return 0;
		}

		THREAD_LOG_INFO("{}(physical=0x{:X}, {} bytes) -> 0x{:X}",
			who, physical_address, number_of_bytes, va + offset);

		return va + offset;
	};

	state.redirect(mod, "MmMapIoSpace",
		[map_io_space](vcpu& cpu, const std::uint64_t physical_address,
			const std::uint64_t number_of_bytes, const std::uint32_t cache_type) -> addr_t
		{
			THREAD_LOG_INFO("MmMapIoSpace: cache type {}", caching_type_name(cache_type));
			return map_io_space(cpu, physical_address, number_of_bytes, "MmMapIoSpace");
		});

	// Everything mapped here is readable and writable, so the protection only reaches the log.
	state.redirect(mod, "MmMapIoSpaceEx",
		[map_io_space](vcpu& cpu, const std::uint64_t physical_address,
			const std::uint64_t number_of_bytes, const std::uint32_t protect) -> addr_t
		{
			THREAD_LOG_INFO("MmMapIoSpaceEx: protect=0x{:X}", protect);
			return map_io_space(cpu, physical_address, number_of_bytes, "MmMapIoSpaceEx");
		});

	state.redirect(mod, "MmUnmapIoSpace",
		[](vcpu& cpu, const addr_t base_address, const std::uint64_t number_of_bytes)
		{
			auto& space = *cpu.curr_addr_space();

			THREAD_LOG_INFO("MmUnmapIoSpace(0x{:X}, {} bytes)", base_address, number_of_bytes);

			space.mmu_->unmap_virt(space, mdl_page_base(base_address),
				number_of_bytes + mdl_page_offset(base_address));
		});

	// The pool hands out one run per allocation, so a pool block already is contiguous. What it
	// does not do for a request under a page is start one: it aligns those to 16 bytes. Windows
	// gives a contiguous allocation whole pages however few bytes were asked for, so the address
	// is always page aligned -- and a caller that rounds the pointer down to its page, as a
	// driver storing per-page state does, lands somewhere else entirely when it is not. Asking
	// for the pages the request really costs is what makes the pool's own alignment rule right.
	auto allocate_contiguous = [st](vcpu& cpu, const std::uint64_t number_of_bytes,
		const std::uint64_t highest_acceptable_address, const std::string_view who) -> addr_t
	{
		auto& space = *cpu.curr_addr_space();

		const auto page = space.mmu_->page_size();
		const auto pages = (number_of_bytes + page - 1) & ~(page - 1);

		const auto addr = st->pool.allocate(pages, pool_tag("MmCo"), true);

		if (!addr)
		{
			THREAD_LOG_ERR("{}: out of pool for {} bytes", who, number_of_bytes);
			return 0;
		}

		const auto pa = space.mmu_->virt_to_phys(space, addr).value_or(0);

		if (pa > highest_acceptable_address)
		{
			THREAD_LOG_WARN("{}: physical 0x{:X} is above the limit of 0x{:X} the caller gave",
				who, pa, highest_acceptable_address);

			st->pool.free(addr);
			return 0;
		}

		THREAD_LOG_INFO("{}({} bytes, highest=0x{:X}) -> 0x{:X} (physical 0x{:X})",
			who, number_of_bytes, highest_acceptable_address, addr, pa);

		return addr;
	};

	state.redirect(mod, "MmAllocateContiguousMemorySpecifyCache",
		[allocate_contiguous](vcpu& cpu, const std::uint64_t number_of_bytes,
			const std::uint64_t lowest_acceptable_address,
			const std::uint64_t highest_acceptable_address,
			const std::uint64_t boundary_address_multiple,
			const std::uint32_t cache_type) -> addr_t
		{
			THREAD_LOG_INFO("MmAllocateContiguousMemorySpecifyCache: lowest=0x{:X}, "
				"boundary=0x{:X}, cache type {}",
				lowest_acceptable_address, boundary_address_multiple, caching_type_name(cache_type));

			return allocate_contiguous(cpu, number_of_bytes, highest_acceptable_address,
				"MmAllocateContiguousMemorySpecifyCache");
		});

	state.redirect(mod, "MmAllocateContiguousNodeMemory",
		[allocate_contiguous](vcpu& cpu, const std::uint64_t number_of_bytes,
			const std::uint64_t lowest_acceptable_address,
			const std::uint64_t highest_acceptable_address,
			const std::uint64_t boundary_address_multiple,
			const std::uint32_t protect, const std::uint32_t preferred_node) -> addr_t
		{
			THREAD_LOG_INFO("MmAllocateContiguousNodeMemory: lowest=0x{:X}, boundary=0x{:X}, "
				"protect=0x{:X}, node={}",
				lowest_acceptable_address, boundary_address_multiple, protect, preferred_node);

			return allocate_contiguous(cpu, number_of_bytes, highest_acceptable_address,
				"MmAllocateContiguousNodeMemory");
		});

	// Pages with a page table entry each rather than a large page behind them, which is what
	// the pool hands out anyway. A caller reprotects these page by page afterwards, so the
	// block has to start on a page -- the pool aligns anything a page or larger.
	state.redirect(mod, "MmAllocateIndependentPages",
		[st](vcpu& cpu, const std::uint64_t number_of_bytes,
			const std::uint32_t node_number) -> addr_t
		{
			constexpr std::size_t page = 0x1000;
			const auto rounded = (number_of_bytes + page - 1) & ~(page - 1);

			const auto addr = rounded ? st->pool.allocate(rounded, pool_tag("MmIp"), true) : 0;

			if (!addr)
			{
				THREAD_LOG_ERR("MmAllocateIndependentPages: out of pool for {} bytes",
					number_of_bytes);

				return 0;
			}

			THREAD_LOG_INFO("MmAllocateIndependentPages({} bytes, node={}) -> 0x{:X}",
				number_of_bytes, node_number, addr);

			return addr;
		});

	state.redirect(mod, "MmFreeIndependentPages",
		[st](vcpu&, const addr_t base_address, const std::uint64_t number_of_bytes)
		{
			const auto freed = st->pool.free(base_address);

			if (!freed)
			{
				THREAD_LOG_ERR("MmFreeIndependentPages: 0x{:X} was not allocated here",
					base_address);

				return;
			}

			THREAD_LOG_INFO("MmFreeIndependentPages(0x{:X}, {} bytes): {} freed",
				base_address, number_of_bytes, freed->size);
		});

	// The pages are already mapped in kernel space, so the list describes memory that exists
	// rather than frames waiting for an address. StartVa is unused by this allocator on NT,
	// which leaves it as the place to keep the block the list belongs to.
	state.redirect(mod, "MmAllocatePagesForMdl",
		[st](vcpu& cpu, const std::uint64_t low_address, const std::uint64_t high_address,
			const std::uint64_t skip_bytes, const std::uint64_t total_bytes) -> addr_t
		{
			const auto pages = (total_bytes + mdl_page_size - 1) / mdl_page_size;

			if (!pages)
				return 0;

			const auto buffer = st->pool.allocate(pages * mdl_page_size, pool_tag("MmMd"), true);
			const auto bytes = sizeof(mdl_t) + pages * sizeof(addr_t);
			const auto list = buffer ? st->pool.allocate(bytes, pool_tag("Mdl "), true) : 0;

			if (!buffer || !list)
			{
				THREAD_LOG_ERR("MmAllocatePagesForMdl: out of pool for {} bytes", total_bytes);

				if (buffer)
					st->pool.free(buffer);

				return 0;
			}

			auto& space = *cpu.curr_addr_space();

			mdl_t m{};
			m.size = static_cast<std::int16_t>(bytes);
			m.mdl_flags = mdl_pages_locked;
			m.start_va = buffer;
			m.byte_count = static_cast<std::uint32_t>(pages * mdl_page_size);

			space.write_mem(list, m);

			for (std::size_t i = 0; i < pages; ++i)
			{
				const auto pa = space.mmu_->virt_to_phys(space, buffer + i * mdl_page_size);

				space.write_mem<addr_t>(list + sizeof(mdl_t) + i * sizeof(addr_t),
					pa.value_or(0) / mdl_page_size);
			}

			THREAD_LOG_INFO("MmAllocatePagesForMdl(low=0x{:X}, high=0x{:X}, skip=0x{:X}, "
				"{} bytes) -> 0x{:X} ({} page(s) at 0x{:X})",
				low_address, high_address, skip_bytes, total_bytes, list, pages, buffer);

			return list;
		});

	state.redirect(mod, "MmFreePagesFromMdl",
		[st](vcpu& cpu, emu_object<mdl_t> memory_descriptor_list)
		{
			if (!memory_descriptor_list)
				return;

			const auto m = memory_descriptor_list.read();

			// The list itself belongs to the caller, who frees it separately.
			if (m.start_va)
				st->pool.free(m.start_va);

			THREAD_LOG_INFO("MmFreePagesFromMdl(0x{:X}): {} bytes at 0x{:X}",
				memory_descriptor_list.address(), m.byte_count, m.start_va);
		});

	state.redirect(mod, "MmMapLockedPagesSpecifyCache",
		[](vcpu&, emu_object<mdl_t> memory_descriptor_list, const std::uint8_t access_mode,
			const std::uint32_t cache_type, const addr_t requested_address,
			const std::uint32_t bug_check_on_failure, const std::uint32_t priority) -> addr_t
		{
			if (!memory_descriptor_list)
				return 0;

			auto m = memory_descriptor_list.read();

			// One mapping, the one the pages already have: there is no second address space
			// here to give a user mode caller its own view.
			const auto va = m.mapped_system_va ? m.mapped_system_va : m.start_va;

			m.mapped_system_va = va;
			m.mdl_flags = static_cast<std::int16_t>(m.mdl_flags | mdl_mapped_to_system_va);

			memory_descriptor_list.write(m);

			THREAD_LOG_INFO("MmMapLockedPagesSpecifyCache(0x{:X}, mode={}, {}, requested=0x{:X}, "
				"priority={}) -> 0x{:X}",
				memory_descriptor_list.address(), access_mode, caching_type_name(cache_type),
				requested_address, priority, va);

			return va;
		});

	state.redirect(mod, "MmUnmapLockedPages",
		[](vcpu&, const addr_t base_address, emu_object<mdl_t> memory_descriptor_list)
		{
			if (!memory_descriptor_list)
				return;

			auto m = memory_descriptor_list.read();
			m.mdl_flags = static_cast<std::int16_t>(m.mdl_flags & ~mdl_mapped_to_system_va);
			m.mapped_system_va = 0;

			memory_descriptor_list.write(m);

			THREAD_LOG_INFO("MmUnmapLockedPages(0x{:X}, 0x{:X}): the pages keep the address "
				"they were allocated at", base_address, memory_descriptor_list.address());
		});

	// A probe either returns or raises; nothing here raises, so the check is reported and the
	// caller carries on, which is what it expects for an address that is in fact valid.
	auto probe = [](vcpu& cpu, const addr_t address, const std::uint64_t length,
		const std::uint64_t alignment, const std::string_view who)
	{
		if (!length)
			return;

		auto& space = *cpu.curr_addr_space();
		const bool mapped = space.mmu_->virt_to_phys(space, address).has_value();

		if (!mapped || (alignment && (address & (alignment - 1))))
			THREAD_LOG_ERR("{}(0x{:X}, {} bytes, align {}): {}", who, address, length, alignment,
				mapped ? "misaligned" : "not mapped");
		else
			THREAD_LOG_INFO("{}(0x{:X}, {} bytes, align {})", who, address, length, alignment);
	};

	state.redirect(mod, "ProbeForRead",
		[probe](vcpu& cpu, const addr_t address, const std::uint64_t length,
			const std::uint64_t alignment)
		{
			probe(cpu, address, length, alignment, "ProbeForRead");
		});

	state.redirect(mod, "ProbeForWrite",
		[probe](vcpu& cpu, const addr_t address, const std::uint64_t length,
			const std::uint64_t alignment)
		{
			probe(cpu, address, length, alignment, "ProbeForWrite");
		});

	state.redirect(mod, "MmFreeContiguousMemory", [st](vcpu&, const addr_t base_address)
	{
		const auto freed = st->pool.free(base_address);

		if (!freed)
		{
			THREAD_LOG_ERR("MmFreeContiguousMemory: 0x{:X} was not allocated here", base_address);
			return;
		}

		THREAD_LOG_INFO("MmFreeContiguousMemory(0x{:X}): {} bytes", base_address, freed->size);
	});

	state.redirect(mod, "MmBuildMdlForNonPagedPool",
		[](vcpu& cpu, emu_object<mdl_t> memory_descriptor_list)
		{
			if (!memory_descriptor_list)
				return;

			auto mdl = memory_descriptor_list.read();

			mdl.mapped_system_va = mdl.start_va + mdl.byte_offset;
			mdl.mdl_flags = static_cast<std::int16_t>(mdl.mdl_flags
				| mdl_mapped_to_system_va | mdl_pages_locked | mdl_source_is_nonpaged_pool);

			memory_descriptor_list.write(mdl);

			auto& space = *cpu.curr_addr_space();
			const auto first = mdl_page_base(mdl.start_va);
			const auto pages = mdl_page_count(mdl.start_va, mdl.byte_count);

			for (std::size_t i = 0; i < pages; ++i)
			{
				const auto pa = space.mmu_->virt_to_phys(space, first + i * mdl_page_size).value_or(0);

				space.write_mem<addr_t>(
					memory_descriptor_list.address() + sizeof(mdl_t) + i * sizeof(addr_t),
					pa / mdl_page_size);
			}

			THREAD_LOG_INFO("MmBuildMdlForNonPagedPool(0x{:X}): {} bytes over {} page(s) at 0x{:X}",
				memory_descriptor_list.address(), mdl.byte_count, pages, mdl.mapped_system_va);
		});

	// One run, and the whole of it: the declared memory map rather than the part a bumping
	// cursor has reached. Both halves come from the one expression so they cannot disagree.
	state.redirect(mod, "MmGetPhysicalMemoryRanges", [st](vcpu& cpu) -> addr_t
	{
		const auto [base, bytes] = cpu.curr_addr_space()->mmu_->phys_range();

		const _PHYSICAL_MEMORY_RANGE entries[2] = {
			{ .BaseAddress = { .QuadPart = static_cast<long long>(base) },
			  .NumberOfBytes = { .QuadPart = static_cast<long long>(bytes) } },
			{},
		};

		const auto addr = st->pool.allocate(sizeof(entries), pool_tag("MmPh"), true);

		if (!addr)
		{
			THREAD_LOG_ERR("MmGetPhysicalMemoryRanges: out of pool");
			return 0;
		}

		cpu.curr_addr_space()->write_mem(addr, entries, sizeof(entries));

		THREAD_LOG_INFO("MmGetPhysicalMemoryRanges() -> 0x{:X}: 0x{:X}..0x{:X}",
			addr, base, base + bytes);

		return addr;
	});

	// A section with no file would be pagefile backed, so it is sized by MaximumSize and zeroed.
	state.redirect(mod, "MmCreateSection",
		[st](vcpu& cpu, emu_object<addr_t> section_object, const std::uint32_t desired_access,
			[[maybe_unused]] const addr_t object_attributes,
			emu_object<std::int64_t> maximum_size,
			const std::uint32_t section_page_protection, const std::uint32_t allocation_attributes,
			const std::uint64_t file_handle, const addr_t file_object) -> NTSTATUS
		{
			if (!section_object)
				return STATUS_INVALID_PARAMETER;

			const auto max_size = maximum_size ? maximum_size.read() : 0;

			auto host = std::make_shared<section_host>();
			host->is_image = (allocation_attributes & sec_image) != 0;
			host->allocation_attributes = allocation_attributes;

			if (file_handle)
			{
				const auto file = st->sys_proc->handle_table().get_object<file_host>(file_handle);

				if (!file)
				{
					THREAD_LOG_WARN("MmCreateSection: handle 0x{:X} is not an open file",
						file_handle);
					return STATUS_INVALID_HANDLE;
				}

				host->file = file->file;
				host->path = file->path;
			}

			if (host->file && host->file->size() == 0)
			{
				THREAD_LOG_WARN("MmCreateSection: '{}' is empty", host->path);
				return STATUS_MAPPED_FILE_SIZE_ZERO;
			}

			if (!host->file && max_size <= 0)
			{
				THREAD_LOG_WARN("MmCreateSection: no file and no size, so there is nothing to map");
				return STATUS_INVALID_PARAMETER;
			}

			// An image section is sized by SizeOfImage, not by the file: a driver that maps one
			// walks it as an image, so the sections have to sit at their virtual addresses and
			// the tail past the last one has to be there to be read.
			if (host->is_image && host->file)
				host->image = krnl::pe_virtual_image(host->file->data());

			host->size = !host->image.empty()
				? static_cast<std::uint64_t>(host->image.size())
				: host->file
					? static_cast<std::uint64_t>(host->file->size())
					: static_cast<std::uint64_t>(max_size);

			// The body carries the size at the offset a caller reads it from.
			std::array<std::uint8_t, section_body_size> body{};
			const auto size = static_cast<std::int64_t>(host->size);
			std::memcpy(body.data() + section_body_size_offset, &size, sizeof(size));

			const auto path = host->path;
			const auto is_image = host->is_image;
			const auto section_size = host->size;

			const auto addr = st->objs.create_object(0, body.data(), body.size(),
				std::move(host), prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			section_object.write(addr);

			THREAD_LOG_INFO("MmCreateSection(access=0x{:X}, max_size={}, protection=0x{:X}, "
				"allocation=0x{:X}, file=0x{:X}/0x{:X}) -> 0x{:X} ('{}', {} bytes{})",
				desired_access, max_size, section_page_protection, allocation_attributes,
				file_handle, file_object, addr, path, section_size,
				is_image ? ", image" : "");

			return STATUS_SUCCESS;
		});

	// The view is a copy of the file rather than a mapping, so a write does not reach the file.
	state.redirect(mod, "MmMapViewInSystemSpace",
		[st](vcpu& cpu, const addr_t section, emu_object<addr_t> mapped_base,
			emu_object<std::uint64_t> view_size) -> NTSTATUS
		{
			const auto host = st->objs.get_object<section_host>(section);

			if (!host)
			{
				THREAD_LOG_WARN("MmMapViewInSystemSpace: 0x{:X} is not a section", section);
				return STATUS_INVALID_PARAMETER;
			}

			auto size = view_size ? view_size.read() : 0;

			if (!size)
				size = host->size;

			if (!size)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			const auto base = space.alloc(size, prot_rw | prot_supervisor);

			if (!base)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto source = !host->image.empty()
				? std::span<const std::uint8_t>(host->image)
				: host->file ? host->file->data() : std::span<const std::uint8_t>{};

			if (!source.empty())
			{
				const auto copied = std::min<std::size_t>(size, source.size());
				space.write_mem(base, source.data(), copied);
			}

			if (mapped_base)
				mapped_base.write(base);

			if (view_size)
				view_size.write(size);

			st->system_views.insert(0, base, size);

			THREAD_LOG_INFO("MmMapViewInSystemSpace(section=0x{:X}, '{}') -> 0x{:X}, {} bytes",
				section, host->path, base, size);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "MmUnmapViewInSystemSpace",
		[st](vcpu& cpu, const addr_t mapped_base) -> NTSTATUS
		{
			const bool removed = st->system_views.remove(0, mapped_base, [&](const auto size) {
				auto& space = *cpu.curr_addr_space();
				space.mmu_->unmap_virt(space, mapped_base, size);
				THREAD_LOG_INFO("MmUnmapViewInSystemSpace(0x{:X}): {} bytes", mapped_base, size);
				return true;
			});
			return removed ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
		});
}
