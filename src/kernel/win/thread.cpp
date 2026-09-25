#include "thread.hpp"
#include <utility>
#include <chrono>
#include "dispatcher.hpp"
#include "status.hpp"
#include "../../emu/calling_conv.hpp"
#include "win_kernel.hpp"

void win_thread::save(vcpu& cpu)
{
	thread::save(cpu);

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

void win_thread::begin_wait(wait_state w)
{
	if (win::in_dpc_callback) throw std::runtime_error("DPC cannot begin a wait");
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

	const auto self = ethread_.address();

	// WaitAll takes none of the objects until every one is available.
	std::size_t taken = wait_->objects.size();

	if (wait_->all)
	{
		for (const auto object : wait_->objects)
		{
			if (!win::is_signalled(space, object, self))
				return false;
		}
	}
	else
	{
		taken = wait_->objects.size() + 1;

		for (std::size_t i = 0; i < wait_->objects.size(); ++i)
		{
			if (win::is_signalled(space, wait_->objects[i], self))
			{
				taken = i;
				break;
			}
		}

		if (taken > wait_->objects.size())
			return false;
	}

	if (wait_->all)
	{
		for (const auto object : wait_->objects)
			win::take(space, object, self);

		wait_->status = STATUS_SUCCESS;
	}
	else
	{
		win::take(space, wait_->objects[taken], self);

		// STATUS_WAIT_0 is zero, so the index of the object that released it is the status.
		wait_->status = static_cast<NTSTATUS>(taken);
	}

	wait_->satisfied = true;

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
