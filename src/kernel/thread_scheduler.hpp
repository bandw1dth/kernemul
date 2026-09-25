#pragma once
#include <span>
#include "../emu/calling_conv.hpp"
#include "../emu/emu.hpp"
#include "../util/log.hpp"
#include "process.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <optional>
#include <memory>
#include <mutex>
#include <thread>

class thread
{
public:
	using id_type = std::uint32_t;
	using clock = std::chrono::steady_clock;
	using time_point = clock::time_point;

	thread(const id_type id, std::shared_ptr<process> proc,
		   const addr_t start_addr, const addr_t stack_ptr,
		   vcpu& cpu)
		: id_(id), process_(std::move(proc)),
		  values_(cpu.arch()->regs().size())
	{
		save(cpu);

		const auto a = cpu.arch();
		const auto regs = a->regs();

		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == a->pc()) values_[i].gp = start_addr;
			else if (regs[i] == a->sp()) values_[i].gp = stack_ptr;
		}
	}

	virtual ~thread() = default;

	virtual void save(vcpu& cpu)
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_read(regs[i], &values_[i], a->reg_size(regs[i]));
	}

	virtual void restore(vcpu& cpu) const
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_write(regs[i], &values_[i], a->reg_size(regs[i]));
	}

	void set_reg(vcpu& cpu, const reg_t r, const std::uint64_t value)
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) { values_[i].gp = value; return; }
		}
	}

	[[nodiscard]] std::uint64_t get_reg(vcpu& cpu, const reg_t r) const
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) return values_[i].gp;
		}
		return 0;
	}

	template <typename T>
	void set_reg_val(vcpu& cpu, const reg_t r, const T& value)
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) { std::memcpy(&values_[i], &value, sizeof(T)); return; }
		}
	}

	template <typename T>
	[[nodiscard]] T get_reg_val(vcpu& cpu, const reg_t r) const
	{
		static_assert(sizeof(T) <= sizeof(reg_val), "a banked register is kept in a reg_val");

		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r)
			{
				T value{};
				std::memcpy(&value, &values_[i], sizeof(T));
				return value;
			}
		}
		return T{};
	}

	// A waiting thread stays on the ready queue with a time on it rather than leaving it.
	void sleep_for(const std::chrono::milliseconds ms) { sleep_until_ = clock::now() + ms; }
	[[nodiscard]] bool is_sleeping() const { return clock::now() < sleep_until_; }

	// Queued but not yet started stays off every cpu: the thread is not finished being built.
	[[nodiscard]] virtual bool is_ready(vcpu&) { return started_ && !is_sleeping(); }

	// Whether this thread wants a cpu, asked without taking one. is_ready() is the real answer,
	// but it finishes a wait as it finds it, so only a cpu about to run the thread may call it.
	[[nodiscard]] virtual bool may_run() const { return started_ && !is_sleeping(); }

	// Runnable from here on. Defined below, where the scheduler it wakes is a complete type.
	void start();
	[[nodiscard]] bool is_started() const noexcept { return started_; }
	[[nodiscard]] time_point sleep_until() const { return sleep_until_; }

	void finish() { finished_ = true; }
	[[nodiscard]] bool is_finished() const { return finished_; }

	[[nodiscard]] virtual bool is_user_mode() const { return false; }

	[[nodiscard]] id_type id() const noexcept { return id_; }
	[[nodiscard]] std::shared_ptr<process> proc() const noexcept { return process_; }

protected:
	id_type id_;
	std::shared_ptr<class process> process_;
	std::atomic<bool> started_{false};
	std::vector<reg_val> values_;

private:
	time_point sleep_until_{};
	bool finished_{false};
};

struct reg_view
{
	vcpu& cpu;
	// Null for the thread the cpu is running.
	thread* banked = nullptr;

	[[nodiscard]] std::uint64_t get(const reg_t r) const
	{
		return banked ? banked->get_reg(cpu, r) : cpu.reg(r);
	}

	void set(const reg_t r, const std::uint64_t value) const
	{
		if (banked)
			banked->set_reg(cpu, r, value);
		else
			cpu.reg(r, value);
	}

	// A register too wide for get() and set() to carry, such as a segment or an
	// xmm.
	template <typename T>
	void set_reg(const reg_t r, const T& value) const
	{
		if (banked)
			banked->set_reg_val(cpu, r, value);
		else
			cpu.reg(r, value);
	}

	template <typename T>
	[[nodiscard]] T get_reg(const reg_t r) const
	{
		return banked ? banked->get_reg_val<T>(cpu, r) : cpu.reg<T>(r);
	}

	[[nodiscard]] bool is_user() const
	{
		if (banked)
			return banked->is_user_mode();

		const auto curr = cpu.thread();
		return curr && curr->is_user_mode();
	}
};

class thread_scheduler
{
public:
	thread_scheduler() = default;
	void set_kernel_work(std::function<bool(vcpu&)> pending, std::function<void(vcpu&)> dispatch,
		std::function<bool()> alive)
	{
		work_pending_ = std::move(pending);
		dispatch_work_ = std::move(dispatch);
		work_alive_ = std::move(alive);
	}
	void request_kernel_work()
	{
		{ std::scoped_lock lock(mtx_); }
		cv_.notify_all();
		if (emu_)
			for (const auto& cpu : emu_->cpus()) cpu->try_stop();
	}
	bool stopped() const { std::scoped_lock lock(mtx_); return stopped_; }

	std::shared_ptr<thread> create_thread(vcpu& cpu, const addr_t start_addr,
		std::shared_ptr<process> proc, thread::id_type id,
		std::span<const std::uint64_t> args = {})
	{
		auto space = proc->addr_space();
		const addr_t stack_base = space->alloc(process::default_stack_size, prot_rw | prot_supervisor);
		const addr_t stack_top = stack_base + process::default_stack_size - process::stack_reserve;
		auto t = std::make_shared<thread>(id, std::move(proc), start_addr, stack_top, cpu);

		enqueue(cpu, t, args);
		return t;
	}

	void enqueue(vcpu& cpu, std::shared_ptr<thread> t,
		const std::span<const std::uint64_t> args = {})
	{
		const auto& conv = *cpu.emu()->call_conv();

		conv.set_ret_addr(cpu, *t, t->proc()->thread_exit_addr());

		// Before the push below, not after: on the queue, the thread can be taken by another cpu.
		for (std::size_t i = 0; i < args.size(); ++i)
			conv.set_arg(cpu, *t, i, args[i]);

		{
			std::scoped_lock lock(mtx_);
			ready_queue_.push_back(std::move(t));
		}

		cv_.notify_one();
	}

	// A thread that became runnable without being queued -- one being started, or coming off a
	// suspend -- is not noticed by a cpu already parked, so whoever made it runnable says so.
	void wake()
	{
		cv_.notify_all();

		// Every cpu may already be busy, in which case nobody is listening for that and the
		// thread would wait out a whole tick before the timekeeper noticed it.
		if (emu_)
			preempt_for_waiting(emu_->cpus());
	}

	// The cpus a thread can be handed to. Set once, before any of them is running.
	void set_emu(class emu* const e) { emu_ = e; }

	// Takes a cpu off the thread holding it for each queued thread that wants one, and no more.
	// A stop buys a switch only if somebody is waiting to be switched to; with nobody there it
	// costs a whole context saved and restored to put the same thread back where it was.
	void preempt_for_waiting(const std::span<const std::shared_ptr<vcpu>> cpus)
	{
		// try_stop only raises a flag on the cpu, so nothing here waits on a cpu to notice it.
		std::scoped_lock lock(mtx_);

		auto spare = std::ranges::count_if(ready_queue_,
			[](const auto& t) { return t->may_run(); });

		for (const auto& cpu : cpus)
		{
			if (spare <= 0)
				break;

			// Parked in schedule() with no thread of its own: it takes the next one itself, and
			// spending a stop on it would leave a cpu that is actually running somebody alone.
			if (!cpu->thread())
				continue;

			cpu->try_stop();
			--spare;
		}
	}

	void remove(const thread::id_type id)
	{
		{
			std::scoped_lock lock(mtx_);
			std::erase_if(ready_queue_, [id](const auto& t) { return t->id() == id; });
		}

		cv_.notify_all();
	}

	void stop()
	{
		{
			std::scoped_lock lock(mtx_);
			stopped_ = true;
		}

		cv_.notify_all();
	}

	static void yield_current(vcpu& cpu)
	{
		if (cpu.in_dpc) throw std::runtime_error("DPC cannot block or yield");
		cpu.stop();
	}

	static void sleep_current(vcpu& cpu, const std::chrono::milliseconds ms)
	{
		if (cpu.in_dpc) throw std::runtime_error("DPC cannot sleep");
		if (const auto t = cpu.thread())
			t->sleep_for(ms);

		yield_current(cpu);
	}

	// Returns only once every thread has finished; any cpu can create work at any point.
	void run(vcpu& cpu)
	{
		std::shared_ptr<thread> curr;

		for (;;)
		{
			curr = schedule(cpu, std::move(curr));

			if (!curr)
				break;

			cpu.run();

			// Anything that stops a cpu without ending its thread is the quantum running out.
			if (!curr->is_finished())
				continue;

			curr->save(cpu);
			release(cpu);
			curr->proc()->terminate_thread(curr->id());
			curr = nullptr;
		}

		release(cpu);
	}

	std::shared_ptr<thread> schedule(vcpu& cpu, std::shared_ptr<thread> prev = nullptr)
	{
		std::unique_lock lock(mtx_);

		if (prev)
		{
			prev->save(cpu);
			cpu.set_thread(nullptr);
			ready_queue_.push_back(std::move(prev));
			cv_.notify_one();
		}

		for (;;)
		{
			if (stopped_ || nothing_left(cpu))
				return nullptr;

			// Borrow a parked context for kernel work, without making its wait runnable.
			// The callback restores registers before this context is saved again.
			if (work_pending_ && work_pending_(cpu))
			{
				const auto available = std::ranges::find_if(ready_queue_,
					[](const auto& t) { return t->is_started(); });
				auto work_thread = available == ready_queue_.end() ? nullptr : *available;
				if (work_thread) ready_queue_.erase(available);
				cpu.set_thread(work_thread);
				lock.unlock();
				if (work_thread) resume(cpu, *work_thread);
				dispatch_work_(cpu);
				if (work_thread) work_thread->save(cpu);
				lock.lock();
				cpu.set_thread(nullptr);
				if (work_thread) ready_queue_.push_back(std::move(work_thread));
				if (stopped_ || nothing_left(cpu)) return nullptr;
			}

			if (const auto it = first_runnable(cpu); it != ready_queue_.end())
			{
				auto next = *it;
				ready_queue_.erase(it);

				// One step, so no other cpu sees the thread gone from both the queue and a cpu.
				cpu.set_thread(next);
				lock.unlock();

				resume(cpu, *next);
				return next;
			}

			// Waiting drops the lock so the holder can get back in to requeue or retire.
			if (const auto wake = next_wake())
				cv_.wait_until(lock, *wake);
			else
				cv_.wait(lock);
		}
	}

private:
	// Called with the lock held.
	std::deque<std::shared_ptr<thread>>::iterator first_runnable(vcpu& cpu)
	{
		return std::ranges::find_if(ready_queue_,
			[&cpu](const auto& t) { return t->is_ready(cpu); });
	}

	// Nothing if no queued thread is sleeping: one parked on something is woken by whoever does it.
	std::optional<thread::time_point> next_wake() const
	{
		std::optional<thread::time_point> earliest;

		for (const auto& t : ready_queue_)
		{
			if (t->is_sleeping() && (!earliest || t->sleep_until() < *earliest))
				earliest = t->sleep_until();
		}

		return earliest;
	}

	// Page tables are not part of the context, so the cpu follows the thread.
	static void resume(vcpu& cpu, const thread& t)
	{
		if (const auto space = t.proc()->addr_space(); cpu.curr_addr_space() != space)
			cpu.emu()->mem()->switch_to(cpu, space);

		t.restore(cpu);
	}

	void release(vcpu& cpu)
	{
		{
			std::scoped_lock lock(mtx_);
			cpu.set_thread(nullptr);
		}

		cv_.notify_all();
	}

	// Only a running thread creates threads, so none queued or running means nothing to wait for.
	bool nothing_left(vcpu& cpu) const
	{
		if (work_alive_ && work_alive_()) return false;
		if (!ready_queue_.empty())
			return false;

		for (const auto& c : cpu.emu()->cpus())
		{
			if (c->thread())
				return false;
		}

		return true;
	}

	std::deque<std::shared_ptr<thread>> ready_queue_;
	mutable std::mutex mtx_;
	std::condition_variable cv_;
	class emu* emu_ = nullptr;
	bool stopped_ = false;
	std::function<bool(vcpu&)> work_pending_;
	std::function<void(vcpu&)> dispatch_work_;
	std::function<bool()> work_alive_;
};

// Here rather than in the class: waking the scheduler needs it to be a complete type.
inline void thread::start()
{
	started_ = true;

	// The thread is already on the queue, so nothing enqueues it -- but a cpu parked because
	// nothing was ready has to be told to look again.
	if (const auto p = process_; p && p->scheduler())
		p->scheduler()->wake();
}
