#pragma once
#include <format>
#include "../thread_scheduler.hpp"
#include "ethread.hpp"
#include "process.hpp"
#include "status.hpp"
#include "user_setup.hpp"

#include <algorithm>
#include <optional>
#include <vector>

class windows_emulator;

class win_thread : public thread
{
public:
	win_thread(const id_type id, std::shared_ptr<windows_process> proc,
		const addr_t start_addr, const addr_t stack_base,
		const std::size_t stack_size, vcpu& cpu)
		:	thread(id, std::move(proc), start_addr,
				stack_base + stack_size - process::stack_reserve, cpu),
			stack_low_(stack_base), stack_size_(stack_size) {}

	void save(vcpu& cpu) override;
	void restore(vcpu& cpu) const override;

	void set_ethread(emu_object<_ETHREAD> et) { ethread_ = std::move(et); }
	[[nodiscard]] const emu_object<_ETHREAD>& ethread() const { return ethread_; }

	void set_emulator(windows_emulator* e) { emulator_ = e; }

	struct wait_state
	{
		std::vector<addr_t> objects;
		bool all = false;
		// The selected guest clock domain; zero is a legitimate deadline.
		std::uint64_t deadline = 0;
		bool timed = false;
		bool monotonic = false;

		// Filled in by whoever satisfied the wait; reading the objects is the signaller's job.
		bool satisfied = false;
		NTSTATUS status = 0;
		NTSTATUS timeout_status = STATUS_TIMEOUT;
	};

	void begin_wait(wait_state w);

	[[nodiscard]] bool is_waiting() const { std::scoped_lock lock(wait_mutex_); return wait_.has_value(); }
	[[nodiscard]] bool waiting_on(const addr_t object) const
	{
		std::scoped_lock lock(wait_mutex_);
		return wait_ && std::ranges::find(wait_->objects, object) != wait_->objects.end();
	}

	bool try_satisfy(addr_space& space);

	// Aimed at the thread, not at anything it waits on; one arriving before the wait is kept.
	void alert();
	bool take_alert();

	std::uint32_t suspend();
	std::uint32_t resume();

	[[nodiscard]] std::uint32_t suspend_count() const { return suspend_count_; }

	// What the thread ended with. A handle to it is still asked for this after it has gone,
	// so it outlives the thread rather than being read back out of a running context.
	void set_exit_status(const NTSTATUS status) { exit_status_ = status; }
	[[nodiscard]] NTSTATUS exit_status() const noexcept { return exit_status_; }

	// Host/boot seeded threads do not synthesize a create event. Only a committed
	// PsCreateSystemThread transitions to live_guest before publication.
	enum class notify_origin { host_seeded, live_guest };
	notify_origin notification_origin = notify_origin::host_seeded;
	bool exit_notification_started = false; // Owned by the executing target CPU.

	// Neither answer needs guest memory, which is why the scheduler can ask.
	[[nodiscard]] bool is_ready(vcpu& cpu) override;
	[[nodiscard]] bool may_run() const override;

	// Kernel APCs are disabled while this is negative, and the guest checks it directly.
	[[nodiscard]] auto kernel_apc_disable() const
	{
		return ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::KernelApcDisable);
	}

	// KeAreAllApcsDisabled reads this one rather than the count above.
	[[nodiscard]] auto special_apc_disable() const
	{
		return ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::SpecialApcDisable);
	}

	// Cid.UniqueProcess: which process the guest believes this thread runs in.
	[[nodiscard]] auto client_id() const
	{
		return ethread_.field(&_ETHREAD::Cid);
	}

	[[nodiscard]] addr_t stack_limit() const { return stack_low_; }
	[[nodiscard]] addr_t stack_base() const { return stack_low_ + stack_size_; }

	[[nodiscard]] const emu_object<_TEB64>& teb() const { return teb_; }
	[[nodiscard]] bool is_system_thread() const { return !teb_; }

	[[nodiscard]] bool is_user_mode() const override { return !is_system_thread(); }

protected:
	mutable std::recursive_mutex wait_mutex_;
	std::uint64_t wait_now(bool monotonic) const;
	std::optional<wait_state> wait_;
	bool alerted_ = false;
	std::uint32_t suspend_count_ = 0;
	NTSTATUS exit_status_ = STATUS_PENDING;
	addr_t stack_low_;
	std::size_t stack_size_;
	emu_object<_TEB64> teb_;
	emu_object<_ETHREAD> ethread_;
	windows_emulator* emulator_ = nullptr;
};

class win_user_thread : public win_thread
{
public:
	win_user_thread(id_type id, std::shared_ptr<windows_process> proc, win_user_mem& mem,
		addr_t start_addr, addr_t stack_base, std::size_t stack_size,
		vcpu& cpu)
		:	win_thread(id, proc, start_addr, stack_base, stack_size, cpu)
	{
		const auto teb_va = mem.alloc(teb64_alloc_size, prot_rw);
		teb_ = emu_object<_TEB64>(mem.space(), teb_va, std::format("TEB[tid={}]", id), true);
		// The affinity mask must cover the processors the PEB advertises, so it comes from there.
		teb_.write(make_default_teb(teb_va, stack_base, stack_size, proc->id(), id,
			proc->peb().address(), proc->peb().field(&_PEB64::NumberOfProcessors).read()));
	}
};

class win_kernel_thread : public win_thread
{
public:
	using win_thread::win_thread;
};
