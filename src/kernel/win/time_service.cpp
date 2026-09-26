#include "win_kernel.hpp"
#include "dispatcher.hpp"
#include <array>
#include <algorithm>

NTSTATUS win_kernel_state::delay_thread(vcpu& cpu, std::int64_t due)
{
	if (process_notify.in_callback(cpu.id())) fail_thread_notify(cpu, "process callback cannot delay execution");
	if (cpu.in_dpc) throw std::runtime_error("DPC cannot delay execution");
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	if (!t) return STATUS_INVALID_PARAMETER;
	const auto now = clock.sample();
	win_thread::wait_state wait{};
	wait.timed = true;
	wait.monotonic = due < 0;
	wait.deadline = due < 0 ? win::saturated_add(now.interrupt_time,
		std::uint64_t{0} - static_cast<std::uint64_t>(due)) : static_cast<std::uint64_t>(due);
	wait.timeout_status = STATUS_SUCCESS;
	t->begin_wait(std::move(wait));
	thread_scheduler::yield_current(cpu);
	return STATUS_SUCCESS;
}

bool win_kernel_state::insert_dpc(emu_object<_KDPC> dpc, addr_t arg1, addr_t arg2)
{
	if (!dpc) return false;
	{
		std::scoped_lock lock(dpc_mutex);
		if (std::ranges::any_of(dpcs, [&](const auto& e) { return e.address == dpc.address(); }))
		{
			THREAD_LOG_INFO("DPC queue rejected: dpc=0x{:X} already queued", dpc.address());
			return false;
		}
		auto entry = dpc.read();
		if (!guest_va(entry.DeferredRoutine))
		{
			THREAD_LOG_WARN("DPC queue rejected: dpc=0x{:X} has no routine", dpc.address());
			return false;
		}
		dpcs.push_back({dpc.address(), guest_va(entry.DeferredRoutine),
			guest_va(entry.DeferredContext), arg1, arg2});
		entry.SystemArgument1 = guest_ptr<void>(arg1);
		entry.SystemArgument2 = guest_ptr<void>(arg2);
		entry.DpcData = guest_ptr<void>(dpc.address());
		dpc.write(entry);
		dpc_count = dpcs.size();
		THREAD_LOG_INFO("DPC queued: dpc=0x{:X} routine=0x{:X} context=0x{:X} args=(0x{:X},0x{:X}) depth={}",
			dpc.address(), guest_va(entry.DeferredRoutine), guest_va(entry.DeferredContext), arg1, arg2, dpcs.size());
	}
	if (auto* s = sys_proc->scheduler()) s->request_kernel_work();
	return true;
}

bool win_kernel_state::remove_dpc(addr_t address)
{
	std::scoped_lock lock(dpc_mutex);
	const auto old = dpcs.size();
	std::erase_if(dpcs, [&](const auto& e) { return e.address == address; });
	if (old == dpcs.size())
	{
		THREAD_LOG_INFO("DPC remove: dpc=0x{:X} not queued (running callbacks are not cancelled)", address);
		return false;
	}
	emu_object<_KDPC>(kernel_space(), address).field(&_KDPC::DpcData).write(nullptr);
	dpc_count = dpcs.size();
	THREAD_LOG_INFO("DPC removed: dpc=0x{:X} depth={}", address, dpcs.size());
	return true;
}

void win_kernel_state::dispatch_dpcs(vcpu& cpu, bool flush)
{
	if (!emulator_ || emulator_->irql(cpu) >= dispatch_level) return;
	std::unique_lock dispatch_lock(dpc_dispatch_mutex, std::defer_lock);
	if (flush) dispatch_lock.lock();
	else if (!dispatch_lock.try_lock()) return;
	dpc_running = true;
	const auto old_irql = emulator_->irql(cpu);
	try
	{
		for (;;)
		{
			queued_dpc item;
			{
				std::scoped_lock lock(dpc_mutex);
				if (dpcs.empty()) break;
				item = dpcs.front();
				dpcs.pop_front();
				dpc_count = dpcs.size();
				// Running is not queued. The callback may enqueue this same object again.
				emu_object<_KDPC>(kernel_space(), item.address).field(&_KDPC::DpcData).write(nullptr);
			}
			// guest_caller restores all registers, including the original execution mode.
			// Save mode before raising it by using the caller's own register snapshot.
			const auto regs = cpu.arch()->regs();
			std::vector<reg_val> saved(regs.size());
			for (std::size_t i = 0; i < regs.size(); ++i)
				cpu.reg_read(regs[i], &saved[i], cpu.arch()->reg_size(regs[i]));
			auto restore = [&] {
				cpu.in_dpc = false;
				win::in_dpc_callback = false;
				emulator_->set_irql(cpu, old_irql);
				for (std::size_t i = 0; i < regs.size(); ++i)
					cpu.reg_write(regs[i], &saved[i], cpu.arch()->reg_size(regs[i]));
			};
			try
			{
				emulator_->set_kernel_mode(cpu, true);
				if (const auto pcpu = per_cpu(cpu.id())) emulator_->set_pcr(cpu, pcpu->address());
				auto& stack = dpc_stacks[cpu.id()];
				if (!stack) stack = kernel_space().alloc(process::default_stack_size, prot_rw | prot_supervisor);
				if (!stack) throw std::runtime_error("DPC stack allocation failed");
				cpu.set_sp(stack + process::default_stack_size - process::stack_reserve);
				emulator_->set_irql(cpu, dispatch_level);
				cpu.in_dpc = true;
				cpu.dpc_failed = false;
				win::in_dpc_callback = true;
				const auto borrowed = std::dynamic_pointer_cast<win_thread>(cpu.thread());
				const bool was_waiting = borrowed && borrowed->is_waiting();
				const std::array<std::uint64_t, 4> args{item.address, item.context, item.arg1, item.arg2};
				THREAD_LOG_INFO("DPC begin: dpc=0x{:X} routine=0x{:X} cpu={} irql={} previous_irql={}",
					item.address, item.routine, cpu.id(), emulator_->irql(cpu), old_irql);
				win::call_with_attachment_checkpoint(calls, cpu, item.routine, args, 0, [&] {
					return cpu.dpc_failed || sys_proc->scheduler()->stopped() ||
						(borrowed && (borrowed->is_finished() || (!was_waiting && borrowed->is_waiting())));
				});
			}
			catch (...)
			{
				restore();
				THREAD_LOG_ERR("DPC end: dpc=0x{:X} cpu={} restored_irql={} failed", item.address, cpu.id(), emulator_->irql(cpu));
				throw;
			}
			restore();
			THREAD_LOG_INFO("DPC end: dpc=0x{:X} cpu={} restored_irql={} returned", item.address, cpu.id(), emulator_->irql(cpu));
		}
	}
	catch (const std::exception& e)
	{
		THREAD_LOG_ERR("DPC dispatch failed: {}", e.what());
		if (auto* s = sys_proc->scheduler()) s->stop();
	}
	dpc_running = false;
}

bool win_kernel_state::set_timer(emu_object<_KTIMER> timer, std::int64_t due,
	std::uint64_t period, addr_t dpc)
{
	std::scoped_lock lock(timer_mutex, win::dispatcher_mutex);
	const auto now = clock.sample();
	std::uint64_t deadline = 0;
	const auto old = timers.set(timer.address(), due, period, dpc, now, [&](const win::timer_queue::entry& prepared) {
		auto entry = timer.read();
		deadline = prepared.deadline;
		entry.DueTime.QuadPart = deadline;
		entry.Period = static_cast<std::uint32_t>(period / 10000);
		entry.Dpc = guest_ptr<_KDPC>(dpc);
		entry.Header.SignalState = 0;
		timer.write(entry);
	});
	timer_count = timers.size();
	THREAD_LOG_INFO("Timer set: timer=0x{:X} due={} deadline={} domain={} period_100ns={} dpc=0x{:X} replaced={} signal=0",
		timer.address(), due, deadline, due < 0 ? "interrupt" : "system", period, dpc, old);
	return old;
}

bool win_kernel_state::cancel_timer(addr_t timer)
{
	std::scoped_lock lock(timer_mutex);
	const auto old = timers.cancel(timer);
	timer_count = timers.size();
	THREAD_LOG_INFO("Timer cancel: timer=0x{:X} was_inserted={} (signal and queued DPC unchanged)", timer, old);
	if (auto* s = sys_proc->scheduler()) s->request_kernel_work();
	return old;
}

void win_kernel_state::update_time()
{
	// Also serializes explicit updates with the timekeeper and timer rearming.
	std::scoped_lock lock(timer_mutex);
	const auto now = clock.sample();
	const auto write_time = [](const emu_object<_KSYSTEM_TIME>& out, std::uint64_t ticks) {
		const auto high = static_cast<std::int32_t>(ticks >> 32);
		out.field(&_KSYSTEM_TIME::High2Time).write(high);
		std::atomic_thread_fence(std::memory_order_seq_cst);
		out.field(&_KSYSTEM_TIME::LowPart).write(static_cast<std::uint32_t>(ticks));
		std::atomic_thread_fence(std::memory_order_seq_cst);
		out.field(&_KSYSTEM_TIME::High1Time).write(high);
	};
	if (kuser_shared_data)
	{
		write_time(kuser_shared_data.field(&_KUSER_SHARED_DATA::SystemTime), now.system_time);
		write_time(kuser_shared_data.field(&_KUSER_SHARED_DATA::InterruptTime), now.interrupt_time);
		write_time(kuser_shared_data.field(&_KUSER_SHARED_DATA::TickCount), now.interrupt_time / clock_increment_100ns);
	}
	std::scoped_lock dispatcher_lock(win::dispatcher_mutex);
	const auto expired_timers = timers.expire(now);
	for (const auto& expired : expired_timers)
	{
		win::set_state_at(kernel_space(), expired.timer, 1);
		LOG_INFO("Timer expired: timer=0x{:X} due={} domain={} now={} period_100ns={} dpc=0x{:X} signal=1 action={}",
			expired.timer, expired.deadline, expired.absolute ? "system" : "interrupt",
			expired.absolute ? now.system_time : now.interrupt_time, expired.period, expired.dpc,
			expired.period ? "periodic rearm" : "remove one-shot");
		// Kernel dispatcher objects can be waited on by threads in any process.
		{
			std::shared_lock processes_lock(proc_mtx_);
			for (const auto& [id, process] : processes)
				if (const auto p = std::dynamic_pointer_cast<windows_process>(process))
					p->wake_waiters(kernel_space(), expired.timer);
		}
		if (expired.dpc)
			insert_dpc(emu_object<_KDPC>(kernel_space(), expired.dpc),
				static_cast<std::uint32_t>(now.system_time), now.system_time >> 32);
	}
	timer_count = timers.size();
	if (!expired_timers.empty())
		if (auto* s = sys_proc->scheduler()) s->request_kernel_work();
}
