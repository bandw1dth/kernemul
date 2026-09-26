#include "nt_sync_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <string_view>
#include <vector>

namespace
{

// A fast mutex is free while bit 0 of Count is set. Above it, ntoskrnl adds four per waiter, so
// bits 2 and up are the waiter count -- see ExAcquireFastMutex, which loads 4 into the register
// it adds, and KeReleaseGuardedMutex, which subtracts one increment per release.
constexpr std::int32_t fm_lock_bit = 1;
constexpr std::int32_t fm_waiter_increment = 4;

std::int32_t mutex_count(const emu_object<_FAST_MUTEX>& mutex)
{
	return static_cast<std::int32_t>(mutex.field(&_FAST_MUTEX::Count).read());
}

// True when the caller holds the mutex on return, false when it has been queued behind whoever
// does. A contended acquire is not a failure and not an exception: ntoskrnl's own
// ExAcquireFastMutex raises to APC_LEVEL, tries `lock btr` on the free bit, and on losing it
// increments Contention and calls KeWaitForSingleObject on the mutex's own event with no
// timeout. There is no status to hand back, so barging in was the only thing left to get wrong.
bool take_mutex(vcpu& cpu, const emu_object<_FAST_MUTEX>& mutex, const std::string_view who)
{
	const auto count = mutex_count(mutex);

	if (count & fm_lock_bit)
	{
		mutex.field(&_FAST_MUTEX::Count).write(count & ~fm_lock_bit);
		return true;
	}

	// Every dispatcher object carries its own size, so a zero there is memory no initialiser has
	// touched. A FAST_MUTEX in that state is not held -- it is not yet a mutex -- and its Count
	// of zero only reads as ownership because bit 0 is the free bit. Waiting on it would be a
	// wait on an event nobody can ever set, and barging in silently is how the contended case
	// used to be wrong, so it is initialised here and taken, which is what the guest's own
	// ExInitializeFastMutex would have left behind.
	if (!mutex.field(&_FAST_MUTEX::Event).field(&_KEVENT::Header)
		.field(&_DISPATCHER_HEADER::Size).read())
	{
		THREAD_LOG_WARN("{}: 0x{:X} was never initialised, so it is taken rather than waited on",
			who, mutex.address());

		win::init_dispatcher(mutex.field(&_FAST_MUTEX::Event),
			win::event_synchronization_object, 0);

		mutex.field(&_FAST_MUTEX::Contention).write(0);
		mutex.field(&_FAST_MUTEX::Count).write(0);

		return true;
	}

	thread_scheduler::require_can_yield(cpu);
	auto contention = mutex.field(&_FAST_MUTEX::Contention);
	contention.write(contention.read() + 1);

	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

	if (!t)
	{
		// Nothing is running, so nothing can be made to wait, and no waiter is counted either --
		// a count that names a thread which does not exist would be handed the mutex by the next
		// release and never give it back. Barging in leaves a lock held twice; this leaves a
		// guest that never comes back.
		THREAD_LOG_ERR("{}: 0x{:X} is held and there is no thread to wait with",
			who, mutex.address());

		return true;
	}

	mutex.field(&_FAST_MUTEX::Count).write(count + fm_waiter_increment);

	win_thread::wait_state w{};
	w.objects = { mutex.field(&_FAST_MUTEX::Event).address() };

	t->begin_wait(cpu, std::move(w));
	t->try_satisfy(*cpu.curr_addr_space());

	thread_scheduler::yield_current(cpu);

	THREAD_LOG_INFO("{}: 0x{:X} is held, so this thread waits on its event",
		who, mutex.address());

	return false;
}

void own_mutex(const emu_object<_FAST_MUTEX>& mutex, vcpu& cpu)
{
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	const auto owner = (t && t->ethread()) ? t->ethread().address() : 0;

	mutex.field(&_FAST_MUTEX::Owner).write(guest_ptr<void>(owner));
}

// A release with waiters queued hands the mutex to one of them instead of marking it free: the
// event is what wakes that thread, and it owns the mutex the moment it does, so the free bit is
// never set in between. Only an uncontended release puts the bit back.
//
// Returns the event that now needs waking, or zero. Signalling a dispatcher object is only half
// of waking a thread -- a wait is finished by whoever satisfies it, not by the thread noticing --
// and the caller is the one holding the process to walk.
addr_t give_mutex(const emu_object<_FAST_MUTEX>& mutex, const std::string_view who)
{
	const auto count = mutex_count(mutex);

	mutex.field(&_FAST_MUTEX::Owner).write(nullptr);

	if (count & fm_lock_bit)
	{
		THREAD_LOG_ERR("{}: 0x{:X} was not held", who, mutex.address());
		return 0;
	}

	if (count >= fm_waiter_increment)
	{
		mutex.field(&_FAST_MUTEX::Count).write(count - fm_waiter_increment);
		win::set_signal_state(mutex.field(&_FAST_MUTEX::Event), 1);

		THREAD_LOG_INFO("{}: 0x{:X} handed to a waiter", who, mutex.address());

		return mutex.field(&_FAST_MUTEX::Event).address();
	}

	mutex.field(&_FAST_MUTEX::Count).write(count | fm_lock_bit);

	return 0;
}

// The linker folds ExAcquireFastMutex onto KeAcquireGuardedMutex on both, the release on x86-64.
void register_fast_mutexes(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeInitializeGuardedMutex",
		[](vcpu&, emu_object<_FAST_MUTEX> mutex)
		{
			if (!mutex)
				return;

			mutex.field(&_FAST_MUTEX::Count).write(fm_lock_bit);
			mutex.field(&_FAST_MUTEX::Owner).write(nullptr);
			mutex.field(&_FAST_MUTEX::Contention).write(0);

			win::init_dispatcher(mutex.field(&_FAST_MUTEX::Event),
				win::event_synchronization_object, 0);

			THREAD_LOG_INFO("KeInitializeGuardedMutex(mutex=0x{:X})", mutex.address());
		});

	// The IRQL the caller was at is kept in the mutex, because the release is not handed it.
	auto acquire = [st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
	{
		if (!mutex)
			return;

		thread_scheduler::require_can_yield(cpu);
		auto* emulator = st->emulator();
		const auto old_irql = emulator ? emulator->set_irql(cpu, apc_level) : passive_level;

		const auto owned = take_mutex(cpu, mutex, "ExAcquireFastMutex");

		// Recorded now even when the acquire blocked. A redirect that yields does not run again
		// when its thread is rescheduled -- the call has already returned by then -- and the
		// release that wakes this thread is the one handing it the mutex, so it owns it the
		// moment it runs. With several waiters queued the last one in wins this field, which is
		// the one place the simplification shows.
		own_mutex(mutex, cpu);
		mutex.field(&_FAST_MUTEX::OldIrql).write(old_irql);

		THREAD_LOG_INFO("ExAcquireFastMutex(mutex=0x{:X}): old irql {}{}",
			mutex.address(), old_irql, owned ? "" : ", once the waiter ahead releases it");
	};

	auto release = [st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
	{
		if (!mutex)
			return;

		const auto old_irql = static_cast<irql_t>(
			mutex.field(&_FAST_MUTEX::OldIrql).read());

		if (const auto wake = give_mutex(mutex, "ExReleaseFastMutex"))
			st->sys_proc->wake_waiters(*cpu.curr_addr_space(), wake);

		if (auto* emulator = st->emulator())
			emulator->set_irql(cpu, old_irql);

		THREAD_LOG_INFO("ExReleaseFastMutex(mutex=0x{:X}): irql back to {}",
			mutex.address(), old_irql);
	};

	auto try_acquire = [st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex) -> bool
	{
		if (!mutex)
			return false;

		auto* emulator = st->emulator();
		const auto old_irql = emulator ? emulator->set_irql(cpu, apc_level) : passive_level;
		const auto count = mutex_count(mutex);

		if (!(count & fm_lock_bit))
		{
			if (emulator)
				emulator->set_irql(cpu, old_irql);

			THREAD_LOG_INFO("ExTryToAcquireFastMutex(mutex=0x{:X}) -> false", mutex.address());

			return false;
		}

		mutex.field(&_FAST_MUTEX::Count).write(count & ~fm_lock_bit);
		own_mutex(mutex, cpu);
		mutex.field(&_FAST_MUTEX::OldIrql).write(old_irql);

		THREAD_LOG_INFO("ExTryToAcquireFastMutex(mutex=0x{:X}) -> true, old irql {}",
			mutex.address(), old_irql);

		return true;
	};

	state.redirect(mod, "ExAcquireFastMutex", acquire);
	state.redirect(mod, "KeAcquireGuardedMutex", acquire);
	state.redirect(mod, "ExReleaseFastMutex", release);
	state.redirect(mod, "KeReleaseGuardedMutex", release);
	state.redirect(mod, "ExTryToAcquireFastMutex", try_acquire);
	state.redirect(mod, "KeTryToAcquireGuardedMutex", try_acquire);

	state.redirect(mod, "ExAcquireFastMutexUnsafe",
		[](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
		{
			if (!mutex)
				return;

			take_mutex(cpu, mutex, "ExAcquireFastMutexUnsafe");
			own_mutex(mutex, cpu);

			THREAD_LOG_INFO("ExAcquireFastMutexUnsafe(mutex=0x{:X})", mutex.address());
		});

	state.redirect(mod, "ExReleaseFastMutexUnsafe",
		[st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
		{
			if (!mutex)
				return;

			if (const auto wake = give_mutex(mutex, "ExReleaseFastMutexUnsafe"))
				st->sys_proc->wake_waiters(*cpu.curr_addr_space(), wake);

			THREAD_LOG_INFO("ExReleaseFastMutexUnsafe(mutex=0x{:X})", mutex.address());
		});
}

}

// A fast mutex or spin lock below never contends: nothing yields while one is held.
void modules::register_ntoskrnl_sync_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeInitializeEvent",
		[](vcpu&, emu_object<_KEVENT> event, const std::uint32_t type,
			const std::uint8_t state)
		{
			if (!event)
				return;

			win::init_dispatcher(event,
				type == 0 ? win::event_notification_object : win::event_synchronization_object,
				state ? 1 : 0);

			THREAD_LOG_INFO("KeInitializeEvent(event=0x{:X}, type={}, state={})",
				event.address(), type == 0 ? "notification" : "synchronization", state);
		});

	state.redirect(mod, "KeSetEvent",
		[st](vcpu& cpu, emu_object<_KEVENT> event, const std::int32_t increment,
			const std::uint8_t wait) -> std::int32_t
		{
			if (!event)
				return 0;

			const auto previous = win::signal_state(event);
			win::set_signal_state(event, 1);

			THREAD_LOG_INFO("KeSetEvent(event=0x{:X}, increment={}, wait={}) -> {}",
				event.address(), increment, wait, previous);

			st->sys_proc->wake_waiters(*cpu.curr_addr_space(), event.address());

			return previous;
		});

	// KeClearEvent and KeResetEvent fold onto one address on x64 and ARM64 alike.
	auto reset_event = [](vcpu&, emu_object<_KEVENT> event) -> std::int32_t
	{
		if (!event)
			return 0;

		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 0);

		THREAD_LOG_INFO("KeResetEvent(event=0x{:X}) -> {}", event.address(), previous);

		return previous;
	};

	state.redirect(mod, "KeResetEvent", reset_event);
	state.redirect(mod, "KeClearEvent", reset_event);

	state.redirect(mod, "KeInitializeMutex",
		[](vcpu&, emu_object<_KMUTANT> mutex, const std::uint32_t level)
		{
			if (!mutex)
				return;

			win::init_dispatcher(mutex, win::mutant_object, 1);

			mutex.field(&_KMUTANT::MutantListEntry).write(guest_links(0, 0));
			mutex.field(&_KMUTANT::OwnerThread).write(nullptr);
			mutex.field(&_KMUTANT::MutantFlags).write(0);
			mutex.field(&_KMUTANT::ApcDisable).write(1);

			THREAD_LOG_INFO("KeInitializeMutex(mutex=0x{:X}, level={})",
				mutex.address(), level);
		});

	// Real Windows bugchecks on a release without a matching wait, so it is reported.
	state.redirect(mod, "KeReleaseMutex",
		[st](vcpu& cpu, emu_object<_KMUTANT> mutex, const std::uint8_t wait) -> std::int32_t
		{
			if (!mutex)
				return 0;

			const auto previous = win::signal_state(mutex);

			if (previous > 0)
				THREAD_LOG_WARN("KeReleaseMutex: mutex 0x{:X} was not held (state={})",
					mutex.address(), previous);

			win::set_signal_state(mutex, previous + 1);
			mutex.field(&_KMUTANT::OwnerThread).write(nullptr);

			THREAD_LOG_INFO("KeReleaseMutex(mutex=0x{:X}, wait={}) -> {}",
				mutex.address(), wait, previous);

			st->sys_proc->wake_waiters(*cpu.curr_addr_space(), mutex.address());

			return previous;
		});

	state.redirect(mod, "KeInitializeSemaphore",
		[](vcpu&, emu_object<_KSEMAPHORE> semaphore, const std::int32_t count,
			const std::int32_t limit)
		{
			if (!semaphore)
				return;

			win::init_dispatcher(semaphore, win::semaphore_object, count);
			semaphore.field(&_KSEMAPHORE::Limit).write(limit);

			THREAD_LOG_INFO("KeInitializeSemaphore(semaphore=0x{:X}, count={}, limit={})",
				semaphore.address(), count, limit);
		});

	// What is missing is the raise, so going past the limit is reported and the count left alone.
	state.redirect(mod, "KeReleaseSemaphore",
		[st](vcpu& cpu, emu_object<_KSEMAPHORE> semaphore, const std::int32_t increment,
			const std::int32_t adjustment, const std::uint8_t wait) -> std::int32_t
		{
			if (!semaphore)
				return 0;

			const auto previous = win::signal_state(semaphore);
			const auto limit = static_cast<std::int32_t>(
				semaphore.field(&_KSEMAPHORE::Limit).read());

			if (previous + adjustment > limit)
			{
				THREAD_LOG_ERR("KeReleaseSemaphore: 0x{:X} count {} + {} exceeds limit {}",
					semaphore.address(), previous, adjustment, limit);
				return previous;
			}

			win::set_signal_state(semaphore, previous + adjustment);

			THREAD_LOG_INFO(
				"KeReleaseSemaphore(semaphore=0x{:X}, increment={}, adjustment={}, wait={}) -> {}",
				semaphore.address(), increment, adjustment, wait, previous);

			st->sys_proc->wake_waiters(*cpu.curr_addr_space(), semaphore.address());

			return previous;
		});

	// Nothing here delivers an APC, so the count is only ever read back.
	auto apc_disable = [](vcpu& cpu, const std::int32_t delta) -> std::int32_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
			return 0;

		auto count = t->kernel_apc_disable();
		const auto updated = static_cast<std::int32_t>(count.read() + delta);

		count.write(static_cast<std::int16_t>(updated));

		return updated;
	};

	// Nothing pushes or pops one yet -- the Ex*SList routines do -- but the guest reads the head.
	state.redirect(mod, "InitializeSListHead",
		[](vcpu&, emu_object<_SLIST_HEADER> slist_head)
		{
			if (!slist_head)
				return;

			slist_head.write(_SLIST_HEADER{});

			THREAD_LOG_INFO("InitializeSListHead(0x{:X})", slist_head.address());
		});

	// KeReadStateEvent, KeReadStateMutex, KeReadStateQueue and KeReadStateSemaphore all fold here.
	state.redirect(mod, "KeReadStateMutant",
		[](vcpu&, emu_object<_DISPATCHER_HEADER> object) -> std::int32_t
		{
			if (!object)
				return 0;

			const auto state = object.field(&_DISPATCHER_HEADER::SignalState).read();

			THREAD_LOG_INFO("KeReadState*(object=0x{:X}) -> {}", object.address(), state);

			return state;
		});

	state.redirect(mod, "KeEnterCriticalRegion", [apc_disable](vcpu& cpu)
	{
		THREAD_LOG_INFO("KeEnterCriticalRegion: apc disable count now {}",
			apc_disable(cpu, -1));
	});

	state.redirect(mod, "KeLeaveCriticalRegion", [apc_disable](vcpu& cpu)
	{
		const auto count = apc_disable(cpu, 1);

		if (count > 0)
			THREAD_LOG_ERR("KeLeaveCriticalRegion: left more regions than were entered (count={})",
				count);
		else
			THREAD_LOG_INFO("KeLeaveCriticalRegion: apc disable count now {}", count);
	});

	auto special_apc_disable = [](vcpu& cpu, const std::int32_t delta) -> std::int32_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
			return 0;

		auto count = t->special_apc_disable();
		const auto updated = static_cast<std::int32_t>(count.read() + delta);

		count.write(static_cast<std::int16_t>(updated));

		return updated;
	};

	state.redirect(mod, "KeEnterGuardedRegion", [special_apc_disable](vcpu& cpu)
	{
		THREAD_LOG_INFO("KeEnterGuardedRegion: special apc disable count now {}",
			special_apc_disable(cpu, -1));
	});

	state.redirect(mod, "KeLeaveGuardedRegion", [special_apc_disable](vcpu& cpu)
	{
		const auto count = special_apc_disable(cpu, 1);

		if (count > 0)
			THREAD_LOG_ERR("KeLeaveGuardedRegion: left more regions than were entered (count={})",
				count);
		else
			THREAD_LOG_INFO("KeLeaveGuardedRegion: special apc disable count now {}", count);
	});

	register_fast_mutexes(state, mod);
}
