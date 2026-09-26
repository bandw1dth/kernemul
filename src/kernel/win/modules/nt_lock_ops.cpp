#include "nt_lock_ops.hpp"
#include "../win_kernel.hpp"
#include "../pool.hpp"
#include "../rundown.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <string_view>

namespace
{

// EX_PUSH_LOCK: bit 0 is held, shares above the four state bits; a free shared acquire leaves 0x11.
enum ex_push_lock_state : std::uint64_t
{
	push_lock_locked          = 0x1,
	push_lock_waiting         = 0x2,
	push_lock_multiple_shared = 0x8,
	push_lock_share_increment = 0x10,
	push_lock_state_mask      = 0xF,
};

// The binary bugchecks on any other flag, so this is a validity check.
constexpr std::uint32_t push_lock_known_flags = 0x7;

enum eresource_flag : std::uint16_t
{
	// ERESOURCE::Flag: the resource is held for writing rather than reading.
	resource_owned_exclusive = 0x80,
};

// An OWNER_ENTRY's second word packs three flag bits under the recursion count.
constexpr std::uint32_t owner_flag_mask = 0x7;
constexpr std::uint32_t owner_count_shift = 3;

// KeLargestCacheLine, which is what KeGetRecommendedSharedDataAlignment hands back.
constexpr std::uint32_t largest_cache_line = 64;

addr_t current_ethread(vcpu& cpu)
{
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	return (t && t->ethread()) ? t->ethread().address() : 0;
}

void take_push_lock(emu_object<std::uint64_t> push_lock, const std::uint32_t flags,
	const bool shared, const std::string_view who)
{
	if (flags & ~push_lock_known_flags)
		THREAD_LOG_ERR("{}: flags 0x{:X} are not a push lock's", who, flags);

	const auto value = push_lock.read();
	const auto shares = value / push_lock_share_increment;

	if ((value & push_lock_locked) && (shares == 0 || !shared))
	{
		THREAD_LOG_ERR("{}: 0x{:X} is already held and nothing here can wait",
			who, push_lock.address());
		return;
	}

	const auto taken = shared
		? ((value | push_lock_locked) + push_lock_share_increment)
			| (shares ? push_lock_multiple_shared : 0)
		: (value | push_lock_locked);

	push_lock.write(taken);

	THREAD_LOG_INFO("{}(lock=0x{:X}, flags=0x{:X}) -> 0x{:X}",
		who, push_lock.address(), flags, taken);
}

void give_push_lock(emu_object<std::uint64_t> push_lock, const std::uint32_t flags,
	const std::string_view who)
{
	if (flags & ~push_lock_known_flags)
		THREAD_LOG_ERR("{}: flags 0x{:X} are not a push lock's", who, flags);

	const auto value = push_lock.read();

	if (!(value & push_lock_locked))
	{
		THREAD_LOG_ERR("{}: 0x{:X} was not held", who, push_lock.address());
		return;
	}

	if (value & push_lock_waiting)
		THREAD_LOG_ERR("{}: 0x{:X} has waiters that nothing will wake", who, push_lock.address());

	const auto released = (value & ~push_lock_state_mask) <= push_lock_share_increment
		? 0
		: value - push_lock_share_increment;

	push_lock.write(released);

	THREAD_LOG_INFO("{}(lock=0x{:X}, flags=0x{:X}) -> 0x{:X}",
		who, push_lock.address(), flags, released);
}

// Windows spills further shared owners into an allocated owner table; nothing here has two at once.
std::uint32_t owner_count(const emu_object<_ERESOURCE>& resource)
{
	return resource.field(&_ERESOURCE::OwnerEntry).field(&_OWNER_ENTRY::TableSize).read()
		>> owner_count_shift;
}

void set_owner(const emu_object<_ERESOURCE>& resource, const addr_t owner_thread,
	const std::uint32_t count)
{
	auto entry = resource.field(&_ERESOURCE::OwnerEntry);

	entry.field(&_OWNER_ENTRY::OwnerThread).write(owner_thread);
	entry.field(&_OWNER_ENTRY::TableSize).write(
		(entry.field(&_OWNER_ENTRY::TableSize).read() & owner_flag_mask)
			| (count << owner_count_shift));
}

bool take_resource(const emu_object<_ERESOURCE>& resource, vcpu& cpu,
	const bool exclusive, const std::uint8_t wait, const std::string_view who)
{
	const auto owner = current_ethread(cpu);
	const auto entries = resource.field(&_ERESOURCE::ActiveEntries).read();
	const auto flag = resource.field(&_ERESOURCE::Flag).read();
	const auto held_exclusive = (flag & resource_owned_exclusive) != 0;
	const auto held_by = resource.field(&_ERESOURCE::OwnerEntry)
		.field(&_OWNER_ENTRY::OwnerThread).read();

	if (entries == 0)
	{
		resource.field(&_ERESOURCE::Flag).write(static_cast<std::uint16_t>(
			exclusive ? (flag | resource_owned_exclusive) : (flag & ~resource_owned_exclusive)));

		set_owner(resource, owner, 1);
		resource.field(&_ERESOURCE::ActiveEntries).write(1);
		resource.field(&_ERESOURCE::ActiveCount).write(1);

		THREAD_LOG_INFO("{}(resource=0x{:X}, wait={}) -> true", who, resource.address(), wait);

		return true;
	}

	if (held_by == owner || (!exclusive && !held_exclusive))
	{
		if (held_by != owner)
		{
			resource.field(&_ERESOURCE::ActiveEntries).write(entries + 1);
			resource.field(&_ERESOURCE::ActiveCount).write(
				static_cast<std::int16_t>(resource.field(&_ERESOURCE::ActiveCount).read() + 1));
		}

		set_owner(resource, owner, owner_count(resource) + 1);

		THREAD_LOG_INFO("{}(resource=0x{:X}, wait={}): recursive -> true",
			who, resource.address(), wait);

		return true;
	}

	if (wait)
		THREAD_LOG_ERR("{}: 0x{:X} is held by thread 0x{:X} and nothing here can wait",
			who, resource.address(), held_by);
	else
		THREAD_LOG_INFO("{}(resource=0x{:X}, wait=0) -> false", who, resource.address());

	return false;
}

}

// Rundown hooks share the per-kernel service across concurrently stopped vCPUs.
void modules::register_ntoskrnl_lock_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The linker folds ExInitializeRundownProtection and KeInitializeSpinLock onto this.
	// Use the rundown service for the folded initialization entry as well.
	state.redirect(mod, "KeInitializeSpinLock",
		[st](vcpu&, win::rundown_ref spin_lock)
		{
			if (!spin_lock)
				return;

			st->rundown.initialize(spin_lock);

			THREAD_LOG_INFO("KeInitializeSpinLock(lock=0x{:X})", spin_lock.address());
		});

	// Rundown protection counts users of an object against a teardown that waits for them.
	// Counts remain in guest memory; active rundown refuses new acquisitions.
	state.redirect(mod, "ExInitializeRundownProtection",
		[st](vcpu&, win::rundown_ref rundown_ref)
		{
			if (!rundown_ref)
				return;

			st->rundown.initialize(rundown_ref);

			THREAD_LOG_INFO("ExInitializeRundownProtection(0x{:X})", rundown_ref.address());
		});

	state.redirect(mod, "ExAcquireRundownProtection",
		[st](vcpu&, win::rundown_ref rundown_ref) -> bool
		{
			if (!rundown_ref)
				return false;

			const auto acquired = st->rundown.acquire(rundown_ref);

			THREAD_LOG_INFO("ExAcquireRundownProtection(0x{:X}) -> {}", rundown_ref.address(), acquired);

			return acquired;
		});

	state.redirect(mod, "ExReleaseRundownProtection",
		[st](vcpu&, win::rundown_ref rundown_ref)
		{
			if (!rundown_ref)
				return;

			(void)st->rundown.release(rundown_ref);

			THREAD_LOG_INFO("ExReleaseRundownProtection(0x{:X})", rundown_ref.address());
		});

	state.redirect(mod, "ExAcquireRundownProtectionCacheAwareEx",
		[](vcpu&, const addr_t rundown_ref, const std::uint32_t count) -> bool
		{
			THREAD_LOG_INFO("ExAcquireRundownProtectionCacheAwareEx(0x{:X}, {}) -> true",
				rundown_ref, count);

			return true;
		});

	state.redirect(mod, "ExReleaseRundownProtectionCacheAwareEx",
		[](vcpu&, const addr_t rundown_ref, const std::uint32_t count)
		{
			THREAD_LOG_INFO("ExReleaseRundownProtectionCacheAwareEx(0x{:X}, {})",
				rundown_ref, count);
		});

	state.redirect(mod, "ExInitializePushLock",
		[](vcpu&, emu_object<std::uint64_t> push_lock)
		{
			if (!push_lock)
				return;

			push_lock.write(0);

			THREAD_LOG_INFO("ExInitializePushLock(lock=0x{:X})", push_lock.address());
		});

	state.redirect(mod, "ExAcquirePushLockExclusiveEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				take_push_lock(push_lock, flags, false, "ExAcquirePushLockExclusiveEx");
		});

	state.redirect(mod, "ExAcquirePushLockSharedEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				take_push_lock(push_lock, flags, true, "ExAcquirePushLockSharedEx");
		});

	state.redirect(mod, "ExReleasePushLockEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				give_push_lock(push_lock, flags, "ExReleasePushLockEx");
		});

	state.redirect(mod, "ExReleasePushLockExclusiveEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				give_push_lock(push_lock, flags, "ExReleasePushLockExclusiveEx");
		});

	state.redirect(mod, "ExReleasePushLockSharedEx",
		[](vcpu&, emu_object<std::uint64_t> push_lock, const std::uint32_t flags)
		{
			if (push_lock)
				give_push_lock(push_lock, flags, "ExReleasePushLockSharedEx");
		});

	state.redirect(mod, "ExInitializeResourceLite",
		[](vcpu&, emu_object<_ERESOURCE> resource) -> NTSTATUS
		{
			if (!resource)
				return STATUS_INVALID_PARAMETER;

			resource.write(_ERESOURCE{});

			const auto head = resource.field(&_ERESOURCE::SystemResourcesList).address();
			resource.field(&_ERESOURCE::SystemResourcesList).write(guest_links(head, head));

			THREAD_LOG_INFO("ExInitializeResourceLite(resource=0x{:X})", resource.address());

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "ExAcquireResourceExclusiveLite",
		[](vcpu& cpu, emu_object<_ERESOURCE> resource, const std::uint8_t wait) -> bool
		{
			return resource
				&& take_resource(resource, cpu, true, wait, "ExAcquireResourceExclusiveLite");
		});

	state.redirect(mod, "ExAcquireResourceSharedLite",
		[](vcpu& cpu, emu_object<_ERESOURCE> resource, const std::uint8_t wait) -> bool
		{
			return resource
				&& take_resource(resource, cpu, false, wait, "ExAcquireResourceSharedLite");
		});

	state.redirect(mod, "ExReleaseResourceLite",
		[](vcpu&, emu_object<_ERESOURCE> resource)
		{
			if (!resource)
				return;

			const auto count = owner_count(resource);
			const auto entries = resource.field(&_ERESOURCE::ActiveEntries).read();

			if (!count || !entries)
			{
				// Real NT bugchecks with RESOURCE_NOT_OWNED; the guest is left standing instead.
				THREAD_LOG_ERR("ExReleaseResourceLite: 0x{:X} is not held", resource.address());
				return;
			}

			if (count > 1)
			{
				set_owner(resource, resource.field(&_ERESOURCE::OwnerEntry)
					.field(&_OWNER_ENTRY::OwnerThread).read(), count - 1);

				THREAD_LOG_INFO("ExReleaseResourceLite(resource=0x{:X}): {} recursive holds left",
					resource.address(), count - 1);

				return;
			}

			set_owner(resource, 0, 0);
			resource.field(&_ERESOURCE::ActiveEntries).write(entries - 1);
			resource.field(&_ERESOURCE::Flag).write(static_cast<std::uint16_t>(
				resource.field(&_ERESOURCE::Flag).read() & ~resource_owned_exclusive));

			if (entries == 1)
				resource.field(&_ERESOURCE::ActiveCount).write(0);

			THREAD_LOG_INFO("ExReleaseResourceLite(resource=0x{:X}): {} owners left",
				resource.address(), entries - 1);
		});

	state.redirect(mod, "ExDeleteResourceLite",
		[](vcpu&, emu_object<_ERESOURCE> resource) -> NTSTATUS
		{
			if (!resource)
				return STATUS_INVALID_PARAMETER;

			if (resource.field(&_ERESOURCE::ActiveEntries).read())
				THREAD_LOG_ERR("ExDeleteResourceLite: 0x{:X} is still held", resource.address());

			resource.write(_ERESOURCE{});

			THREAD_LOG_INFO("ExDeleteResourceLite(resource=0x{:X})", resource.address());

			return STATUS_SUCCESS;
		});

	// This marks rundown and reports outstanding references; it does not block.
	state.redirect(mod, "ExWaitForRundownProtectionRelease", [st](vcpu&, win::rundown_ref run_ref)
	{
		if (!run_ref)
			return;

		if (const auto held = st->rundown.begin(run_ref))
			THREAD_LOG_ERR("ExWaitForRundownProtectionRelease: 0x{:X} has {} references and "
				"nothing here can wait", run_ref.address(), held);

		THREAD_LOG_INFO("ExWaitForRundownProtectionRelease(0x{:X}): running down",
			run_ref.address());
	});

	state.redirect(mod, "ExAllocateCacheAwareRundownProtection",
		[st](vcpu& cpu, [[maybe_unused]] const std::uint32_t pool_type,
			const std::uint32_t pool_tag) -> addr_t
		{
			const auto processors = static_cast<std::uint32_t>(cpu.emu()->cpus().size());
			const auto stride = processors > 1
				? largest_cache_line : static_cast<std::uint32_t>(sizeof(_EX_RUNDOWN_REF));

			const auto header = st->pool.allocate(
				sizeof(_EX_RUNDOWN_REF_CACHE_AWARE), pool_tag, true);

			// The pool only aligns to 16, so the per-cpu stride is carved out of the padding.
			const auto pool_to_free = header
				? st->pool.allocate(stride * (processors + 1ull), pool_tag, true) : 0;

			if (!header || !pool_to_free)
			{
				if (header)
					st->pool.free(header);

				THREAD_LOG_ERR("ExAllocateCacheAwareRundownProtection: out of pool for {} "
					"processor(s) (tag '{}')", processors, pool_tag_name(pool_tag));

				return 0;
			}

			emu_object<_EX_RUNDOWN_REF_CACHE_AWARE> run_ref(*cpu.curr_addr_space(), header);

			_EX_RUNDOWN_REF_CACHE_AWARE out{};
			out.RunRefs = guest_ptr<_EX_RUNDOWN_REF>((pool_to_free + stride - 1) & ~(stride - 1ull));
			out.PoolToFree = guest_ptr<void>(pool_to_free);
			out.RunRefSize = stride;
			out.Number = processors;

			run_ref.write(out);

			THREAD_LOG_INFO("ExAllocateCacheAwareRundownProtection(pool_type=0x{:X}, tag='{}') -> "
				"0x{:X} ({} x {} bytes at 0x{:X})", pool_type, pool_tag_name(pool_tag), header,
				processors, stride, guest_va(out.RunRefs));

			return header;
		});

	state.redirect(mod, "ExFreeCacheAwareRundownProtection",
		[st](vcpu&, emu_object<_EX_RUNDOWN_REF_CACHE_AWARE> cache_aware)
		{
			if (!cache_aware)
				return;

			const auto free_block = [st](const addr_t block)
			{
				if (block && !st->pool.free(block))
					THREAD_LOG_ERR("ExFreeCacheAwareRundownProtection: 0x{:X} is not a live "
						"pool allocation", block);
			};

			const auto refs = guest_va(cache_aware
				.field(&_EX_RUNDOWN_REF_CACHE_AWARE::PoolToFree).read());

			free_block(refs);
			free_block(cache_aware.address());

			THREAD_LOG_INFO("ExFreeCacheAwareRundownProtection(0x{:X}): run refs at 0x{:X}",
				cache_aware.address(), refs);
		});

	state.redirect(mod, "ExWaitForRundownProtectionReleaseCacheAware",
		[st](vcpu& cpu, emu_object<_EX_RUNDOWN_REF_CACHE_AWARE> cache_aware)
		{
			if (!cache_aware)
				return;

			const auto entry = cache_aware.read();
			const auto refs = guest_va(entry.RunRefs);

			if (!refs)
			{
				THREAD_LOG_ERR("ExWaitForRundownProtectionReleaseCacheAware: 0x{:X} has no "
					"run refs", cache_aware.address());
				return;
			}

			std::uint64_t held = 0;

			for (std::uint32_t i = 0; i < entry.Number; ++i)
			{
				const win::rundown_ref run_ref(*cpu.curr_addr_space(),
					refs + static_cast<std::uint64_t>(entry.RunRefSize) * i);

				held += st->rundown.begin(run_ref);
			}

			if (held)
				THREAD_LOG_ERR("ExWaitForRundownProtectionReleaseCacheAware: 0x{:X} has {} "
					"references and nothing here can wait", cache_aware.address(), held);

			THREAD_LOG_INFO("ExWaitForRundownProtectionReleaseCacheAware(0x{:X}): {} run refs "
				"running down", cache_aware.address(), entry.Number);
		});
}
