#include "thread.hpp"
#include <utility>
#include <map>
#include <chrono>
#include "dispatcher.hpp"
#include "status.hpp"
#include "../../emu/calling_conv.hpp"
#include "win_kernel.hpp"

bool win_thread::can_switch(vcpu& cpu) const
{
	return !emulator_ || emulator_->irql(cpu) < dispatch_level;
}

void win_thread::save(vcpu& cpu)
{
	thread::save(cpu);
	if (emulator_) saved_irql_ = emulator_->irql(cpu);

	if (const auto* pcpu = emulator_ ? emulator_->per_cpu(cpu) : nullptr)
		pcpu->set_current_thread(0);

	if (!ethread_)
		return;

	const auto state = is_finished() ? Terminated : (is_sleeping() ? Waiting : Ready);

	set_thread_state(ethread_, state, false);

	if (state == Waiting)
		set_thread_wait_reason(ethread_, DelayExecution);
}

void win_thread::restore(vcpu& cpu) const
{
	thread::restore(cpu);

	if (!emulator_)
		return;

	emulator_->set_irql(cpu, saved_irql_);

	const auto* pcpu = emulator_->per_cpu(cpu);

	if (!pcpu)
		return;

	// Restore put back the KPCR register of whichever cpu it ran on before, so point it here.
	if (is_system_thread())
		emulator_->set_pcr(cpu, pcpu->address());

	if (!ethread_)
		return;

	// Nothing else says which thread a cpu is running: the guest reads it out of that KPRCB.
	pcpu->set_current_thread(ethread_.address());

	set_thread_state(ethread_, Running, true);
	set_thread_processor(ethread_, static_cast<std::uint32_t>(cpu.id()));
	count_thread_switch(ethread_);
}

namespace
{
void check_wait_callbacks()
{
	if (win::process_callback_depth) throw std::runtime_error("process notify: callback cannot begin a wait");
	if (win::ob_callback_depth) throw std::runtime_error("ob notify: callback cannot begin a wait");
	if (win::registry_callback_depth) throw std::runtime_error("registry notify: callback cannot begin a wait");
	if (win::image_callback_depth) throw std::runtime_error("image callback cannot begin a wait");
}
}

void win_thread::begin_wait(vcpu& cpu, wait_state w)
{
	check_wait_callbacks();
	if (win::in_dpc_callback) throw std::runtime_error("DPC cannot begin a wait");
	thread_scheduler::require_can_yield(cpu);
	std::scoped_lock lock(wait_mutex_);
	if (w.timed)
	{
		const auto now = wait_now(w.monotonic);
		const auto remaining = w.deadline > now ? std::min<std::uint64_t>(w.deadline - now, INT64_MAX / 100) : 0;

		// Rounded up: truncating would arm the host sleep to run out before the guest deadline.
		sleep_for(std::chrono::ceil<std::chrono::milliseconds>(win_ticks(remaining)));
	}

	wait_ = std::move(w);
}

bool win_thread::try_satisfy(addr_space& space)
{
	std::scoped_lock dispatcher_lock(win::dispatcher_mutex);
	std::scoped_lock lock(wait_mutex_);
	if (!wait_ || wait_->satisfied)
		return false;
	return try_satisfy(space, *wait_);
}

NTSTATUS win_thread::poll_wait(vcpu& cpu, wait_state w)
{
	check_wait_callbacks();
	if (emulator_ && emulator_->irql(cpu) > dispatch_level)
		thread_scheduler::reject_current(cpu, "IRQL above DISPATCH_LEVEL cannot poll a wait");
	std::scoped_lock dispatcher_lock(win::dispatcher_mutex);
	return try_satisfy(*cpu.curr_addr_space(), w) ? w.status : STATUS_TIMEOUT;
}

// Caller holds dispatcher_mutex. A poll uses a local wait, never publishing it.
bool win_thread::try_satisfy(addr_space& space, wait_state& wait)
{
	const auto self = ethread_.address();

	// WaitAll takes none of the objects until every one is available.
	std::size_t taken = wait.objects.size();

	if (wait.all)
	{
		for (const auto object : wait.objects)
		{
			if (!win::is_signalled(space, object, self))
				return false;
		}
	}
	else
	{
		taken = wait.objects.size() + 1;

		for (std::size_t i = 0; i < wait.objects.size(); ++i)
		{
			if (win::is_signalled(space, wait.objects[i], self))
			{
				taken = i;
				break;
			}
		}

		if (taken > wait.objects.size())
			return false;
	}

	if (wait.all)
	{
		for (const auto object : wait.objects)
			win::take(space, object, self);

		wait.status = STATUS_SUCCESS;
	}
	else
	{
		win::take(space, wait.objects[taken], self);

		// STATUS_WAIT_0 is zero, so the index of the object that released it is the status.
		wait.status = static_cast<NTSTATUS>(taken);
	}

	wait.satisfied = true;

	return true;
}

void win_thread::alert()
{
	std::scoped_lock lock(wait_mutex_);
	if (wait_ && !wait_->satisfied && wait_->objects.empty())
	{
		wait_->status = STATUS_SUCCESS;
		wait_->satisfied = true;
		return;
	}

	alerted_ = true;
}

bool win_thread::take_alert()
{
	std::scoped_lock lock(wait_mutex_);
	return std::exchange(alerted_, false);
}

std::uint32_t win_thread::suspend()
{
	std::scoped_lock lock(wait_mutex_);
	const auto previous = suspend_count_++;

	if (ethread_)
		ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::SuspendCount)
			.write(static_cast<char>(suspend_count_));

	return previous;
}

std::uint32_t win_thread::resume()
{
	std::unique_lock lock(wait_mutex_);
	const auto previous = suspend_count_;

	if (suspend_count_)
		--suspend_count_;

	if (ethread_)
		ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::SuspendCount)
			.write(static_cast<char>(suspend_count_));

	// Runnable again without being queued, so a cpu parked on an empty answer is told to look.
	if (!suspend_count_ && previous)
	{
		lock.unlock();
		if (const auto p = proc(); p && p->scheduler())
			p->scheduler()->wake();
	}

	return previous;
}

// The same question is_ready() answers, minus the answering: a wait is read, never finished. An
// unsatisfied wait whose deadline has passed still counts, since the cpu that takes the thread is
// the one that turns that into STATUS_TIMEOUT.
bool win_thread::may_run() const
{
	std::scoped_lock lock(wait_mutex_);
	if (suspend_count_)
		return false;

	if (wait_)
	{
		return wait_->satisfied
			|| (wait_->timed && wait_->deadline <= wait_now(wait_->monotonic));
	}

	return thread::may_run();
}

bool win_thread::is_ready(vcpu& cpu)
{
	std::scoped_lock lock(wait_mutex_);
	// Ahead of the wait, so a thread suspended while parked stays off the cpu.
	if (suspend_count_)
		return false;

	if (!wait_)
		return thread::is_ready(cpu);

	const auto conv = cpu.emu()->call_conv();

	const auto finish = [&](const NTSTATUS status)
	{
		conv->set_ret(cpu, *this, status);

		// Leaving the deadline behind would make a thread released early look asleep.
		sleep_for(std::chrono::milliseconds(0));
		wait_.reset();
	};

	if (wait_->satisfied)
	{
		finish(wait_->status);
		return true;
	}

	if (wait_->timed)
	{
		const auto now = wait_now(wait_->monotonic);
		const auto remaining = wait_->deadline > now ? std::min<std::uint64_t>(wait_->deadline - now, INT64_MAX / 100) : 0;

		if (remaining <= 0)
		{
			finish(wait_->timeout_status);
			return true;
		}

		// The deadline is guest time and the sleep host time, so the two do not run out together.
		sleep_for(std::chrono::ceil<std::chrono::milliseconds>(win_ticks(remaining)));
	}

	return false;
}

std::uint64_t win_thread::wait_now(bool monotonic) const
{
	const auto now = emulator_ ? emulator_->kernel().clock.sample() : win::clock_sample{static_cast<std::uint64_t>(win_system_time()), 0};
	return monotonic ? now.interrupt_time : now.system_time;
}

std::shared_ptr<windows_process> win_thread::effective_process() const
{
	return attachments_.empty() ? std::dynamic_pointer_cast<windows_process>(proc()) : attachments_.back().target;
}

std::shared_ptr<addr_space> win_thread::execution_addr_space() const
{
	return attachments_.empty() ? proc()->addr_space() : attachments_.back().target_space;
}

namespace {
std::mutex active_attachment_mutex;
std::map<std::pair<const emu*, addr_t>, const win_thread*> active_attachment_states;
[[noreturn]] void attachment_failure(vcpu& cpu, const char* reason)
{
	THREAD_LOG_ERR("process attach: {}", reason);
	if (const auto t = cpu.thread(); t && t->proc()->scheduler()) t->proc()->scheduler()->stop();
	cpu.checked_calls.fail();
	cpu.stop();
	throw std::runtime_error(reason);
}
}

win_thread::~win_thread()
{
	std::scoped_lock lock(active_attachment_mutex);
	std::erase_if(active_attachment_states, [this](const auto& entry) { return entry.second == this; });
}

void win_thread::attach(vcpu& cpu, std::shared_ptr<windows_process> target, const addr_t state)
{
	if (!ethread_ || !emulator_ || emulator_->irql(cpu) >= dispatch_level || cpu.in_dpc
		|| !target || target->lifecycle == process_lifecycle::exiting
		|| target->lifecycle == process_lifecycle::exited || target->lifecycle == process_lifecycle::rejected)
		attachment_failure(cpu, "attach: invalid caller, IRQL, or process");
	// All modeled kernel allocations are resident. Never accept user state buffers.
	if (state < 0xffff800000000000ULL || state > UINT64_MAX - sizeof(_KAPC_STATE)
		|| state % alignof(_KAPC_STATE))
		attachment_failure(cpu, "attach: invalid kernel APC state buffer");
	for (const auto& frame : attachments_)
		if (frame.state_address == state) attachment_failure(cpu, "attach: duplicate active APC state");
	// A root copied before a new kernel top-level slot was populated cannot
	// safely host this continuation. Reject it before touching APC state.
	const auto source_space = cpu.curr_addr_space();
	const auto target_space = target->addr_space();
	auto shared_backing = [&](addr_t address, std::size_t bytes)
	{
		if (address < 0xffff800000000000ULL || address > UINT64_MAX - bytes)
			attachment_failure(cpu, "continuation is not on a kernel stack");
		for (std::size_t offset = 0; offset < bytes;)
		{
			const auto at = address + offset;
			const auto from = source_space->mmu_->virt_to_phys(*source_space, at);
			const auto to = target_space->mmu_->virt_to_phys(*target_space, at);
			if (!from || !to || *from != *to)
				attachment_failure(cpu, "target space does not share kernel stack/state backing");
			offset += std::min(bytes - offset, source_space->mmu_->page_size() - at % source_space->mmu_->page_size());
		}
	};
	shared_backing(cpu.sp(), sizeof(addr_t));
	shared_backing(cpu.pc(), 1);
	if (cpu.sp() >= stack_limit() && cpu.sp() < stack_base() && stack_limit() >= 0xffff800000000000ULL)
		shared_backing(stack_limit(), stack_base() - stack_limit());
	shared_backing(state, sizeof(_KAPC_STATE));
	shared_backing(ethread_.address(), sizeof(_ETHREAD));
	auto current = ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::ApcState);
	// Reject aliasing ETHREAD state: it would destroy the state being saved.
	if (state < ethread_.address() + sizeof(_ETHREAD) && state + sizeof(_KAPC_STATE) > ethread_.address())
		attachment_failure(cpu, "attach: APC state aliases ETHREAD");
	_KAPC_STATE original_buffer{};
	try { cpu.curr_addr_space()->read_mem(state, &original_buffer, sizeof(original_buffer)); }
	catch (...) { attachment_failure(cpu, "attach: APC state has no backing"); }
	std::unique_lock process_lock(target->lifecycle_mutex);
	const auto life = target->lifecycle.load();
	if (life == process_lifecycle::exiting || life == process_lifecycle::exited || life == process_lifecycle::rejected)
		attachment_failure(cpu, "target process has exited");
	const auto saved = current.read();
	for (std::size_t i = 0; i < 2; ++i)
	{
		const auto head = current.address() + offsetof(_KAPC_STATE, ApcListHead) + i * sizeof(_LIST_ENTRY);
		const auto& links = saved.ApcListHead[i];
		if ((guest_va(links.Flink) != head || guest_va(links.Blink) != head)
			&& (links.Flink || links.Blink))
			attachment_failure(cpu, "nonempty APC queues are unsupported");
	}
	attachment_frame frame{state, target, effective_process(), target->addr_space(), cpu.curr_addr_space(), saved};
	// The state buffers live in the shared kernel half, so ownership is global
	// to this emulator, including callers on another CPU.
	std::unique_lock state_lock(active_attachment_mutex);
	const auto key = std::make_pair(static_cast<const emu*>(cpu.emu()), state);
	for (const auto& [active, owner] : active_attachment_states)
		if (active.first == cpu.emu() && state < active.second + sizeof(_KAPC_STATE)
			&& active.second < state + sizeof(_KAPC_STATE))
			attachment_failure(cpu, "APC state overlaps an active state on a thread");
	attachments_.reserve(attachments_.size() + 1);
	active_attachment_states.emplace(key, this);
	attachments_.push_back(frame); // Capacity and registry allocated before guest mutation.
	try
	{
		auto guest_saved = saved;
		for (std::size_t i = 0; i < 2; ++i)
		{
			const auto head = state + offsetof(_KAPC_STATE, ApcListHead) + i * sizeof(_LIST_ENTRY);
			guest_saved.ApcListHead[i] = guest_links(head, head);
		}
		frame.previous_space->write_mem(state, guest_saved);
		// APC delivery queues are not emulated. A different process gets empty
		// queues; same-process nesting preserves the complete current state.
		auto attached = target == frame.previous ? saved : _KAPC_STATE{};
		if (target != frame.previous)
			for (std::size_t i = 0; i < 2; ++i)
			{
				const auto head = current.address() + offsetof(_KAPC_STATE, ApcListHead) + i * sizeof(_LIST_ENTRY);
				attached.ApcListHead[i] = guest_links(head, head);
			}
		attached.Process = guest_ptr<_KPROCESS>(target->eprocess().address());
		current.write(attached);
		cpu.emu()->mem()->switch_to(cpu, frame.target_space);
		THREAD_LOG_INFO("process attach: attached old_pid={} new_pid={} depth={}",
			frame.previous->id(), target->id(), attachments_.size());
	}
	catch (...)
	{
		attachments_.pop_back();
		active_attachment_states.erase(key);
		current.write(saved);
		frame.previous_space->write_mem(state, original_buffer);
		cpu.emu()->mem()->switch_to(cpu, frame.previous_space);
		attachment_failure(cpu, "attach: address-space transition failed");
	}
}

void win_thread::detach(vcpu& cpu, const addr_t state)
{
	if (!ethread_ || !emulator_ || emulator_->irql(cpu) >= dispatch_level || cpu.in_dpc
		|| attachments_.empty() || attachments_.back().state_address != state
		|| (!attachment_floors_.empty() && attachments_.size() <= attachment_floors_.back()))
		attachment_failure(cpu, "detach: unmatched APC state, callback boundary, or invalid IRQL");
	rollback_attachments(cpu, attachments_.size() - 1);
	THREAD_LOG_INFO("process attach: detached restored_pid={} depth={}", effective_process()->id(), attachments_.size());
}

void win_thread::rollback_attachments(vcpu& cpu, const std::size_t depth)
{
	while (attachments_.size() > depth)
	{
		const auto& frame = attachments_.back();
		cpu.emu()->mem()->switch_to(cpu, frame.previous_space);
		ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::ApcState).write(frame.saved);
		{
			std::scoped_lock lock(active_attachment_mutex);
			active_attachment_states.erase(std::make_pair(static_cast<const emu*>(cpu.emu()), frame.state_address));
		}
		attachments_.pop_back();
	}
}

win_attachment_checkpoint::~win_attachment_checkpoint()
{
	const bool rollback = thread_.attachment_depth() != depth_;
	try
	{
		thread_.rollback_attachments(cpu_, depth_);
		cpu_.emu()->mem()->switch_to(cpu_, space_);
		if (rollback)
			THREAD_LOG_INFO("process attach: callback rollback restored depth={} process=0x{:X} space={}",
				depth_, thread_.effective_process()->eprocess().address(), static_cast<const void*>(space_.get()));
	}
	catch (...)
	{
		if (const auto scheduler = thread_.proc()->scheduler()) scheduler->stop();
		cpu_.checked_calls.fail();
		cpu_.stop();
	}
	thread_.pop_attachment_floor();
}

void win_attachment_checkpoint::validate() const
{
	if (thread_.attachment_depth() != depth_)
		attachment_failure(cpu_, "callback returned with unbalanced process attachments");
}

std::uint64_t win::call_with_attachment_checkpoint(guest_caller& calls, vcpu& cpu,
	const addr_t routine, const std::span<const std::uint64_t> args,
	const std::size_t scratch, const std::function<bool()>& cancelled)
{
	const auto caller = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	// A CPU without a Windows thread cannot create or consume attachments.
	if (!caller) return calls.call(cpu, routine, args, scratch, cancelled);
	win_attachment_checkpoint attachments(*caller, cpu);
	const auto result = calls.call(cpu, routine, args, scratch, cancelled);
	attachments.validate();
	return result;
}
