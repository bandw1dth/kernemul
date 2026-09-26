#pragma once
#include "process.hpp"
#include "../../emu/emu.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <mutex>

// A bounded host copy, with permission decisions made from the process's VM
// metadata, never from the permission-blind host MMU copy routines.
struct process_memory_copy
{
	static win_user_mem* memory(const std::shared_ptr<windows_process>& proc)
	{
		const auto user = std::dynamic_pointer_cast<win_user_proc>(proc);
		return user ? &user->mem() : nullptr;
	}

	// Keep validation and a staged transfer under the same effective process's
	// VM metadata lock without exposing the allocator's mutex to API adapters.
	static std::unique_lock<std::mutex> lock_memory(const std::shared_ptr<windows_process>& proc)
	{
		auto* mem = memory(proc);
		return mem ? std::unique_lock<std::mutex>(mem->mtx_) : std::unique_lock<std::mutex>{};
	}

	static bool valid_range(addr_t address, std::uint64_t size, bool user)
	{
		if (!size) return true;
		if (!address || size - 1 > std::numeric_limits<addr_t>::max() - address) return false;
		const auto last = address + size - 1;
		if (address <= win::user_addr_limit) return last <= win::user_addr_limit;
		return !user && address >= 0xffff800000000000ULL;
	}

	// The relevant metadata mutex is held throughout validation and transfer.
	static bool permitted(win_user_mem* mem, addr_space& space, addr_t address,
		std::size_t size, bool write, bool user)
	{
		if (!valid_range(address, size, user)) return false;
		for (std::size_t done = 0; done < size;)
		{
			const auto at = address + done;
			const auto chunk = std::min(size - done, space.mmu_->page_size() - at % space.mmu_->page_size());
			if (at <= win::user_addr_limit)
			{
				if (!mem) return false;
				const auto res = mem->find_reservation(at);
				if (res == mem->reservations_.end()) return false;
				const auto sub = win_user_mem::find_committed(res->second.committed, at);
				if (sub == res->second.committed.end() || chunk > sub->first + sub->second.size - at) return false;
				const auto prot = sub->second.prot;
				if (prot & win::page_guard) return false;
				const auto basic = prot & win::page_prot_mask;
				// COW writes need private-page materialization, which this bounded path does not implement.
				if (write ? (basic != win::page_readwrite && basic != win::page_execute_readwrite)
					: (basic != win::page_readonly && basic != win::page_readwrite
						&& basic != win::page_writecopy && basic != win::page_execute_read
						&& basic != win::page_execute_readwrite && basic != win::page_execute_writecopy)) return false;
			}
			// Kernel buffers have no protection metadata in this model: only backing
			// is verified. Do not describe this check as a kernel permission probe.
			if (!space.mmu_->virt_to_phys(space, at)) return false;
			done += chunk;
		}
		return true;
	}

	// Capture syscall input or preflight output without a permission-blind host
	// access. The lock is released before any guest callback is dispatched.
	static bool capture(const std::shared_ptr<windows_process>& process, addr_space& space,
		addr_t address, void* buffer, std::size_t size, bool write, bool user)
	{
		auto* mem = memory(process);
		std::unique_lock<std::mutex> lock;
		if (mem) lock = std::unique_lock(mem->mtx_);
		try
		{
			if (!permitted(mem, space, address, size, write, user)) return false;
			if (buffer) space.read_mem(address, buffer, size);
			else
			{
				std::array<std::byte, 4096> backing;
				for (std::size_t offset = 0; offset < size;)
				{
					const auto chunk = std::min(size - offset, backing.size());
					space.read_mem(address + offset, backing.data(), chunk);
					offset += chunk;
				}
			}
			return true;
		}
		catch (...) { return false; }
	}

	static bool store_handle(const std::shared_ptr<windows_process>& process, addr_space& space,
		addr_t address, std::uint64_t value, bool user)
	{
		auto* mem = memory(process);
		std::unique_lock<std::mutex> lock;
		if (mem) lock = std::unique_lock(mem->mtx_);
		try
		{
			if (!permitted(mem, space, address, sizeof(value), true, user)) return false;
			// Check every backing page before the first write, including unaligned output.
			std::uint64_t previous;
			space.read_mem(address, &previous, sizeof(previous));
			space.write_mem(address, value);
			return true;
		}
		catch (...) { return false; }
	}

	static NTSTATUS copy(vcpu& cpu, const std::shared_ptr<windows_process>& caller,
		const std::shared_ptr<windows_process>& from, addr_t source,
		const std::shared_ptr<windows_process>& to, addr_t target,
		std::uint64_t size, bool user, addr_t count)
	{
		const auto caller_space = cpu.curr_addr_space(); // Count is always in the original caller's space.
		const auto source_space = from->addr_space(), target_space = to->addr_space();
		auto* const caller_mem = memory(caller);
		auto* const source_mem = memory(from);
		auto* const target_mem = memory(to);
		std::array<win_user_mem*, 3> memories{caller_mem, source_mem, target_mem};
		std::sort(memories.begin(), memories.end(), std::less<win_user_mem*>{});
		std::array<std::unique_lock<std::mutex>, 3> locks;
		win_user_mem* previous = nullptr;
		for (std::size_t i = 0; i < memories.size(); ++i)
			if (memories[i] && memories[i] != previous)
			{
				locks[i] = std::unique_lock(memories[i]->mtx_);
				previous = memories[i];
			}
		std::uint64_t done = 0;
		std::array<std::byte, 4096> staging{};
		try
		{
			if (count)
			{
				if (!permitted(caller_mem, *caller_space, count, sizeof(done), true, user)) return STATUS_ACCESS_VIOLATION;
				// Check physical backing before touching either transfer buffer.
				std::uint64_t saved;
				caller_space->read_mem(count, &saved, sizeof(saved));
			}
			const bool range_ok = valid_range(source, size, user) && valid_range(target, size, user);
			if (range_ok)
				while (done < size)
				{
					const auto src = source + done, dst = target + done;
					const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>({size - done, staging.size(),
						source_space->mmu_->page_size() - src % source_space->mmu_->page_size(),
						target_space->mmu_->page_size() - dst % target_space->mmu_->page_size()}));
					if (!permitted(source_mem, *source_space, src, chunk, false, user)
						|| !permitted(target_mem, *target_space, dst, chunk, true, user)) break;
					try
					{
						source_space->read_mem(src, staging.data(), chunk);
						// Detect absent destination backing before a host write.
						std::array<std::byte, 4096> destination;
						target_space->read_mem(dst, destination.data(), chunk);
						target_space->write_mem(dst, staging.data(), chunk);
					}
					catch (...) { break; }
					done += chunk;
				}
			if (count) caller_space->write_mem(count, done);
			return done == size ? STATUS_SUCCESS : done ? STATUS_PARTIAL_COPY : STATUS_ACCESS_VIOLATION;
		}
		catch (...) { return done ? STATUS_PARTIAL_COPY : STATUS_ACCESS_VIOLATION; }
	}
};
