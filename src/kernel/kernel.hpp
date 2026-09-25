#pragma once
#include "process.hpp"
#include "map.hpp"
#include "thread_scheduler.hpp"
#include "../sym/symbol.hpp"
#include "../emu/emu.hpp"
#include "../emu/calling_conv.hpp"
#include "../util/log.hpp"
#include <atomic>
#include <chrono>
#include <exception>
#include <span>
#include <format>
#include <functional>
#include <filesystem>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>
#include <unordered_map>

using redirect_fn = std::function<void(vcpu&)>;

struct os_exception
{
	virtual ~os_exception() = default;
	virtual bool handle(vcpu& cpu, cpu_exception ex) = 0;
};

class os_emulator
{
public:
	explicit os_emulator(std::shared_ptr<emu> emu)
		: emu_(std::move(emu))
	{
		scheduler_.set_emu(emu_.get());

		emu_->hook_exception([this](vcpu& cpu, cpu_exception ex) {
			if (handle_exception(cpu, ex))
				return true;

			const auto t = cpu.thread();

			LOG_ERR("unhandled {} on cpu {}: nothing anywhere claimed it, so the "
				"machine stops here", to_string(ex), cpu.id());
			LOG_ERR("  pc      0x{:X}", cpu.pc());
			LOG_ERR("  address 0x{:X}", cpu.arch()->fault_addr(cpu));

			if (t)
				LOG_ERR("  thread  {} of process {}", t->id(), t->proc()->id());

			scheduler_.stop();
			cpu.stop();

			return false;
		});
	}

	virtual ~os_emulator() = default;

	emu& emu() { return *emu_; }
	thread_scheduler& scheduler() { return scheduler_; }
	std::shared_ptr<os_exception> excp() const { return excp_; }

	bool handle_exception(vcpu& cpu, cpu_exception ex)
	{
		return excp_ && excp_->handle(cpu, ex);
	}

	virtual std::shared_ptr<vcpu> add_vcpu() = 0;
	virtual std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, addr_t start_addr) = 0;

	virtual void create_vcpus(const std::size_t count)
	{
		for (std::size_t i = 0; i < count; ++i)
			add_vcpu();
	}

	[[nodiscard]] std::span<const std::shared_ptr<vcpu>> cpus() const noexcept
	{
		return emu_->cpus();
	}

	static constexpr auto default_thread_runtime = std::chrono::milliseconds(50);

	// A thread that never returns would own its cpu forever, so the waiting thread keeps time. It
	// only takes a cpu away when there is a thread queued to put on it: an idle machine is left
	// to run flat out rather than paying a context save and restore every tick for nothing.
	void run_all(const std::chrono::milliseconds runtime = default_thread_runtime)
	{
		std::atomic<std::size_t> live{0};
		std::atomic<bool> failed{false};
		std::mutex failure_mutex;
		std::exception_ptr failure;
		const auto record_failure = [&] {
			std::scoped_lock lock(failure_mutex);
			if (!failure) failure = std::current_exception();
			failed = true;
		};
		std::vector<std::thread> hosts;
		hosts.reserve(cpus().size());
		try
		{
			for (const auto& cpu : cpus())
			{
				++live;
				try
				{
					hosts.emplace_back([this, cpu, &live, &record_failure]
					{
						try
						{
							set_log_cpu(cpu.get());
							scheduler_.run(*cpu);
						}
						catch (...) { record_failure(); }
						--live;
					});
				}
				catch (...) { --live; throw; }
			}
		}
		catch (...) { record_failure(); }

		auto next_quantum = std::chrono::steady_clock::now() + runtime;
		while (live.load())
		{
			if (failed.load())
			{
				scheduler_.stop();
				// Repeat until joined: a CPU might not yet have entered run() when
				// the first cancellation was requested.
				for (const auto& cpu : cpus())
				{
					try { cpu->try_stop(); }
					catch (...) { record_failure(); }
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
			if (failed.load()) continue;
			try
			{
				timekeeper_tick();
				const auto now = std::chrono::steady_clock::now();
				if (now >= next_quantum)
				{
					scheduler_.preempt_for_waiting(cpus());
					next_quantum = now + runtime;
				}
			}
			catch (...) { record_failure(); }
		}

		for (auto& host : hosts) host.join();
		if (failure)
		{
			scheduler_.stop();
			std::rethrow_exception(failure);
		}
	}

protected:
	virtual void timekeeper_tick() {}
	std::shared_ptr<class emu> emu_;
	std::shared_ptr<os_exception> excp_;
	thread_scheduler scheduler_;
};

struct kernel_state
{
	virtual ~kernel_state() = default;

	virtual std::shared_ptr<process> create_process(std::string_view name) = 0;

	std::shared_ptr<process> find_process(const process::id_type id)
	{
		std::shared_lock lock(proc_mtx_);
		const auto it = processes.find(id);
		return it != processes.end() ? it->second : nullptr;
	}

	// Thread ids are handed out machine wide rather than per process, so this searches all of them.
	std::shared_ptr<thread> find_thread(const process::thread_id_type id)
	{
		std::shared_lock lock(proc_mtx_);

		for (const auto& [_, proc] : processes)
		{
			if (auto t = proc->find_thread(id))
				return t;
		}

		return nullptr;
	}

	std::shared_ptr<proc_module> map_redirect_module(process& proc, const std::string_view name,
		const std::span<const std::uint8_t> image, bool supervisor)
	{
		auto mod = krnl::map_img(proc, name, image, supervisor, true);

		if (!mod)
			return nullptr;

		hook_module_redirects(*mod);

		return mod;
	}

	static std::string name_at(const proc_module& mod, const addr_t addr)
	{
		if (const auto sym = mod.symbols.resolve(addr))
			return sym->format();

		return std::format("+0x{:X}", addr - mod.addr);
	}

	void hook_module_redirects(proc_module& mod)
	{
		auto* redirections = &redirections_;
		auto* m = &mod;
		auto a = emu_->arch();

		emu_->hook_code(mod.addr, mod.addr + mod.size - 1,
			[redirections, m, a](vcpu& cpu, addr_t addr, std::size_t)
			{
				const auto it = redirections->find(addr);

				if (it != redirections->end())
				{
					// The throw would otherwise unwind through the emulator's own C frames.
					try
					{
						it->second(cpu);
					}
					catch (const std::exception& e)
					{
						THREAD_LOG_ERR("{}!{} faulted: {}", m->name,
							name_at(*m, addr), e.what());
						if (cpu.in_dpc) { cpu.dpc_failed = true; cpu.stop(); }
						if (cpu.checked_calls.fail()) cpu.stop();
					}
					catch (...)
					{
						THREAD_LOG_ERR("{}!{} faulted: unknown host exception", m->name, name_at(*m, addr));
						if (cpu.in_dpc) { cpu.dpc_failed = true; cpu.stop(); }
						if (cpu.checked_calls.fail()) cpu.stop();
					}

					// Stopping the cpu moves the pc on some architectures, so it is put back.
					if (cpu.pc() == addr)
						cpu.set_pc(a->ret_addr(cpu));

					return;
				}

				THREAD_LOG_ERR("unimplemented function {}!{}", m->name, name_at(*m, addr));
				const bool checked_failed = cpu.checked_calls.fail();
				if (cpu.in_dpc)
				{
					// The checked caller will stop the scheduler after restoring context.
					// This must also work on an idle CPU with no associated thread.
					cpu.dpc_failed = true;
					cpu.stop();
					return;
				}
				if (checked_failed)
				{
					cpu.stop();
					return;
				}

				// Left running, the thread would be rescheduled onto this address forever.
				if (const auto t = cpu.thread())
					t->finish();

				cpu.stop();
			});
	}

	bool try_redirect(proc_module& mod, const std::string_view name, redirect_fn fn)
	{
		const auto addr = mod.find_symbol(name);

		if (!addr)
			return false;

		redirections_[*addr] = std::move(fn);

		return true;
	}

	void redirect(proc_module& mod, const std::string_view name, redirect_fn fn)
	{
		if (!try_redirect(mod, name, std::move(fn)))
			LOG_ERR("symbol '{}' not found in {}", name, mod.name);
	}

	template <typename F>
	void redirect(proc_module& mod, const std::string_view name, F&& fn)
	{
		redirect(mod, name, make_redirect(emu_->call_conv(), std::forward<F>(fn)));
	}

	[[nodiscard]] const redirect_fn* find_redirect(const addr_t addr) const
	{
		const auto it = redirections_.find(addr);
		return it != redirections_.end() ? &it->second : nullptr;
	}

protected:
	std::shared_ptr<class emu> emu_;
	std::shared_mutex proc_mtx_;
	std::map<process::id_type, std::shared_ptr<process>> processes;
	std::unordered_map<addr_t, redirect_fn> redirections_;
};
