#pragma once
#include "emu.hpp"
#include "../util/log.hpp"

#include <unicorn/unicorn.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <unordered_map>
#include <list>

struct unicorn_hook : emu_hook
{
	int uc_type;

	// UC_<arch>_INS_*, or the QEMU exception index to match when insn_via_intr is set.
	int uc_insn;

	bool insn_via_intr = false;

	// See insn_answers_instruction.
	bool insn_answers = false;

	std::vector<uc_hook> handles;
};

class unicorn_vcpu_base : public vcpu
{
public:
	unicorn_vcpu_base(class emu* e, std::shared_ptr<const struct arch> arch, uc_engine* uc,
		const std::size_t id)
		:	vcpu(e, std::move(arch), id), uc_(uc) { }

	~unicorn_vcpu_base() override
	{
		if (uc_) uc_close(uc_);
	}

	// A cpu inside a hook is not executing guest code; it only has to be kept from resuming.
	struct hook_guard
	{
		explicit hook_guard(vcpu& cpu)
			: cpu_(static_cast<unicorn_vcpu_base&>(cpu)) { ++cpu_.in_hook_; }

		~hook_guard()
		{
			while (cpu_.pending_pause_.load()) {}
			--cpu_.in_hook_;
		}

		unicorn_vcpu_base& cpu_;
	};

	void run() override
	{
		execution_failed_ = false;
		const bool nested = running_.load() != 0;
		for (;;)
		{
			auto pc = reg<addr_t>(arch_->pc());

			// A nested run executes guest code, so this cpu is not at a hook's safe point.
			const auto hooks = in_hook_.exchange(0);

			// Before running_, or it would be waiting on a cpu that is waiting on it.
			while (pending_pause_.load()) {}

			++running_;
			const auto res = uc_emu_start(uc_, pc, 0, 0, 0);
			--running_;
			in_hook_ = hooks;

			if (res != UC_ERR_OK)
			{
				execution_failed_ = true;
				LOG_ERR("cpu {}: emulation stopped at 0x{:X}: {}", id(), pc, uc_strerror(res));
			}

			if (redirect_.exchange(false))
			{
				// Helpers can advance pc after a hook returns; restore what the callback asked for.
				reg(arch_->pc(), redirect_pc_);
				continue;
			}

			// Stopped for an engine-wide operation, not by a hook: carry on from the same pc.
			if (!pending_pause_.load())
				break;

			while (pending_pause_.load()) {}
		}
	}

	// Only ever called from this cpu's own host thread -- see try_stop.
	void stop() override
	{
		uc_emu_stop(uc_);
	}

	// Touches no engine: uc_emu_stop racing uc_emu_start leaves the cpu where the guest never was.
	void try_stop() override
	{
		if (running_.load() == 1)
			stop_requested_.store(true);
	}

	// The one place a cpu leaves guest code without the engine being touched from outside.
	void poll_stop()
	{
		if (pending_pause_.load())
		{
			stop();
			return;
		}

		// Only the outermost run can be taken away; a nested one ends at its caller's trampoline.
		if (running_.load() == 1 && stop_requested_.exchange(false))
			stop();
	}

	void flush_tlb() override
	{
		uc_ctl_flush_tlb(uc_);
	}
	bool execution_failed() const override { return execution_failed_; }
	bool execution_failed_ = false;

	void reg_read(reg_t reg, void* value, std::size_t size) override = 0;
	void reg_write(reg_t reg, const void* value, std::size_t size) override = 0;

	uc_engine* native() const { return uc_; }

	void request_redirect()
	{
		redirect_pc_ = reg<addr_t>(arch_->pc());
		redirect_ = true;
	}

	uc_engine* uc_;

	// 0 is not executing, 1 is the outermost run, more is a hook that started its own.
	std::atomic<int> running_{0};
	std::atomic<int> in_hook_{0};
	std::atomic<bool> pending_pause_{false};
	std::atomic<bool> stop_requested_{false};
	std::atomic<bool> redirect_{false};
	addr_t redirect_pc_{0};
};

class unicorn_emu_base : public emu
{
public:
	unicorn_emu_base(std::shared_ptr<struct arch> arch, std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {})
		:	emu(std::move(arch), std::move(mem), std::move(call_conv)) { }

	void map_phys_mem(addr_t addr, std::size_t size) override
	{
		std::unique_lock mem_lk(mem_mtx_);

		auto it = mem_.find(addr);
		std::size_t old_size = (it != mem_.end()) ? it->second.size() : 0;

		auto& buf = mem_[addr];
		buf.resize(size);

		run_on_all([&] {
			for (auto& cpu : cpus_)
			{
				if (old_size)
					uc_mem_unmap(engine(cpu), addr, old_size);
				uc_mem_map_ptr(engine(cpu), addr, size, prot_rwx, buf.data());
			}
		});
	}

	void unmap_phys_mem(addr_t addr, std::size_t size, mem_prot) override
	{
		std::unique_lock mem_lk(mem_mtx_);

		run_on_all([&] {
			for (auto& cpu : cpus_)
				uc_mem_unmap(engine(cpu), addr, size);
		});

		mem_.erase(addr);
	}

	void read_phys_mem(addr_t addr, void* buf, std::size_t size) override
	{
		std::shared_lock mem_lk(mem_mtx_);

		auto [src, avail] = find_backing(addr);
		if (src)
			std::memcpy(buf, src, std::min(size, avail));
	}

	void write_phys_mem(addr_t addr, const void* buf, std::size_t size) override
	{
		std::shared_lock mem_lk(mem_mtx_);

		auto [dst, avail] = find_backing(addr);
		if (dst)
			std::memcpy(dst, buf, std::min(size, avail));
	}

	void run_on_all(const std::function<void()>& fn) override
	{
		std::lock_guard lk(op_mtx_);

		for (auto& cpu : cpus_)
			static_cast<unicorn_vcpu_base*>(cpu.get())->pending_pause_ = true;

		// in_hook_ is re-read every round: a cpu can still enter a hook after the flag went up.
		for (auto& cpu : cpus_)
		{
			auto* uc = static_cast<unicorn_vcpu_base*>(cpu.get());
			while (uc->running_.load() && !uc->in_hook_.load()) {}
		}

		fn();

		for (auto& cpu : cpus_)
			static_cast<unicorn_vcpu_base*>(cpu.get())->pending_pause_ = false;
	}

	// The range is handed to Unicorn as the virtual one it already is, so the space it belongs
	// to says nothing this backend needs.
	hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb cb,
		addr_space*) override
	{
		return add_hook(start_addr, end_addr, prot_to_uc_hook(prot), 0, std::move(cb));
	}

	hook_handle hook_insn(addr_t start_addr, addr_t end_addr, hook_insn_t insn, insn_hk_cb cb) override
	{
		if (const int uc_insn = to_uc_insn(insn); uc_insn >= 0)
			return add_hook(start_addr, end_addr, UC_HOOK_INSN, uc_insn, std::move(cb),
				false, insn_answers_instruction(insn));

		if (const int intno = insn_as_intr(insn); intno >= 0)
			return add_hook(start_addr, end_addr, UC_HOOK_INTR, intno, std::move(cb), true);

		throw std::runtime_error("instruction hook unsupported on this architecture");
	}

	hook_handle hook_code(addr_t start_addr, addr_t end_addr, code_hk_cb cb) override
	{
		return add_hook(start_addr, end_addr, UC_HOOK_CODE, 0, std::move(cb));
	}

	hook_handle hook_basic_block(addr_t start_addr, addr_t end_addr, code_hk_cb cb) override
	{
		return add_hook(start_addr, end_addr, UC_HOOK_BLOCK, 0, std::move(cb));
	}

	hook_handle hook_invalid_mem(mem_prot access, invalid_mem_hk_cb cb) override
	{
		return add_hook(1, 0, prot_to_uc_hook_unmapped(access), 0, std::move(cb));
	}

	hook_handle hook_exception(exception_hk_cb cb) override
	{
		// Every vector; exception_hook_trampoline sorts the faults from the interrupts.
		return add_hook(1, 0, UC_HOOK_INTR, 0, std::move(cb));
	}

	void remove_hook(hook_handle handle) override
	{
		auto* hk = static_cast<unicorn_hook*>(handle);

		for (std::size_t i = 0; i < hk->handles.size(); ++i)
			uc_hook_del(engine(cpus_[i]), hk->handles[i]);

		hooks_.remove_if([hk](const unicorn_hook& h) { return &h == hk; });
	}

protected:
	virtual uc_engine* open_engine() = 0;

	virtual std::shared_ptr<unicorn_vcpu_base> wrap_engine(uc_engine* uc, std::size_t id) = 0;

	virtual int to_uc_insn(hook_insn_t insn) const = 0;

	// Whether Unicorn takes the callback's answer as the instruction's result and leaves it
	// unexecuted. Syscall is the exception: its callback moves the pc instead.
	static constexpr bool insn_answers_instruction(const hook_insn_t insn)
	{
		return insn != hook_insn_t::syscall;
	}

	// The QEMU exception index the instruction raises, or -1 if it does not raise one.
	virtual int insn_as_intr(hook_insn_t) const { return -1; }

	// The exception is raised with pc already past it, so the trampoline rewinds by this much.
	virtual addr_t insn_as_intr_len() const { return 0; }

	std::shared_ptr<vcpu> create_vcpu(const std::size_t id) final
	{
		uc_engine* uc = open_engine();

		for (auto& [addr, buf] : mem_)
			uc_mem_map_ptr(uc, addr, buf.size(), prot_rwx, buf.data());

		for (auto& hk : hooks_)
			add_uc_hook(hk, uc);

		// Use the CPU's own MMU, so the guest page tables are actually walked.
		uc_ctl_tlb_mode(uc, UC_TLB_CPU);

		auto cpu = wrap_engine(uc, id);

		// Turns a stop asked from another thread into one this cpu performs at a block boundary.
		uc_hook stop_poll{};
		if (uc_hook_add(uc, &stop_poll, UC_HOOK_BLOCK,
				reinterpret_cast<void*>(&stop_poll_trampoline), cpu.get(), 1, 0)
			!= UC_ERR_OK)
			throw std::runtime_error("failed to hook the cpu's own stop point");

		return cpu;
	}

	static void stop_poll_trampoline(uc_engine*, std::uint64_t, std::uint32_t,
		void* user_data)
	{
		static_cast<unicorn_vcpu_base*>(user_data)->poll_stop();
	}

private:
	template <typename Cb>
	hook_handle add_hook(addr_t start_addr, addr_t end_addr, int uc_type, int uc_insn, Cb cb,
		bool insn_via_intr = false, bool insn_answers = false)
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = start_addr;
		hk.end = end_addr;
		hk.uc_type = uc_type;
		hk.uc_insn = uc_insn;
		hk.insn_via_intr = insn_via_intr;
		hk.insn_answers = insn_answers;

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	static void mem_hook_trampoline(uc_engine* uc, uc_mem_type type, std::uint64_t addr,
		int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<mem_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);
				cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
				return;
			}
		}
	}

	// Both contracts: Unicorn calls this through a bool-returning pointer for the instructions a
	// hook may answer, and a void one for syscall, which ignores what is returned.
	static int insn_hook_trampoline(uc_engine* uc, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<insn_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) != uc)
				continue;

			unicorn_vcpu_base::hook_guard guard(*cpu);
			const bool handled = cb(*cpu);

			// The instruction's result, which leaves it unexecuted.
			if (hk->insn_answers)
				return handled ? 1 : 0;

			// A new pc, which the cpu has to stop to resume from.
			if (handled)
			{
				static_cast<unicorn_vcpu_base*>(cpu.get())->request_redirect();
				uc_emu_stop(uc);
			}

			break;
		}

		return 0;
	}

	static void insn_intr_trampoline(uc_engine* uc, std::uint32_t intno, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);

		if (static_cast<int>(intno) != hk->uc_insn)
			return;

		auto& cb = std::get<insn_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) != uc)
				continue;

			const addr_t len = self->insn_as_intr_len();
			const addr_t insn_pc = cpu->pc() - len;

			// UC_HOOK_INTR ignores the address range Unicorn was given, so it is applied here.
			if (hk->start <= hk->end && (insn_pc < hk->start || insn_pc > hk->end))
				return;

			cpu->set_pc(insn_pc);

			unicorn_vcpu_base::hook_guard guard(*cpu);

			if (cb(*cpu))
			{
				static_cast<unicorn_vcpu_base*>(cpu.get())->request_redirect();
				uc_emu_stop(uc);
			}
			else
			{
				cpu->set_pc(insn_pc + len);
			}
			return;
		}
	}

	static void code_hook_trampoline(uc_engine* uc, std::uint64_t addr,
		std::uint32_t size, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<code_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);
				cb(*cpu, addr, static_cast<std::size_t>(size));
				return;
			}
		}
	}

	static bool invalid_mem_hook_trampoline(uc_engine* uc, uc_mem_type type,
		std::uint64_t addr, int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<invalid_mem_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);
				return cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
			}
		}

		return false;
	}

	// Every callback gets every index; without this an SVC also becomes an access violation.
	[[nodiscard]] bool claimed_by_insn_hook(const int intno) const
	{
		for (const auto& hk : hooks_)
		{
			if (hk.insn_via_intr && hk.uc_insn == intno)
				return true;
		}

		return false;
	}

	static void exception_hook_trampoline(uc_engine* uc, std::uint32_t intno, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<exception_hk_cb>(hk->cb);

		if (self->claimed_by_insn_hook(static_cast<int>(intno)))
			return;

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);

				auto ex = cpu->arch()->intr_to_excp(static_cast<int>(intno));

				// Not a fault the os dispatches. Returning without claiming it leaves Unicorn
				// to discard the vector and resume, so the instruction after it runs -- but the
				// guest's handler never does, which a check for that would see through.
				if (ex == cpu_exception::interrupt)
					return;

				if (cb(*cpu, ex))
				{
					static_cast<unicorn_vcpu_base*>(cpu.get())->request_redirect();
					uc_emu_stop(uc);
				}
				return;
			}
		}
	}

	static void add_uc_hook(unicorn_hook& hk, uc_engine* uc)
	{
		uc_hook h{};
		if (hk.uc_type == UC_HOOK_INSN)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(insn_hook_trampoline),
				&hk, hk.start, hk.end, hk.uc_insn);
		else if (hk.uc_type == UC_HOOK_INTR)
			// Unbounded: Unicorn would read the range as vectors, and for an instruction taken
			// as an interrupt it is addresses, which insn_intr_trampoline checks itself.
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(
					hk.insn_via_intr ? insn_intr_trampoline : exception_hook_trampoline),
				&hk, 1, 0);
		else if (hk.uc_type == UC_HOOK_CODE || hk.uc_type == UC_HOOK_BLOCK)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(code_hook_trampoline),
				&hk, hk.start, hk.end);
		else if (hk.uc_type & (UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED))
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(invalid_mem_hook_trampoline),
				&hk, hk.start, hk.end);
		else
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(mem_hook_trampoline),
				&hk, hk.start, hk.end);
		hk.handles.push_back(h);
	}

	static int prot_to_uc_hook(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH;
		return type;
	}

	static int prot_to_uc_hook_unmapped(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ_UNMAPPED;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE_UNMAPPED;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH_UNMAPPED;
		return type;
	}

	static mem_prot uc_type_to_prot(uc_mem_type type)
	{
		switch (type)
		{
		case UC_MEM_READ:       return prot_read;
		case UC_MEM_WRITE:      return prot_write;
		case UC_MEM_FETCH:      return prot_exec;
		case UC_MEM_READ_AFTER: return prot_read;
		default:                return prot_none;
		}
	}

	static uc_engine* engine(const std::shared_ptr<vcpu>& cpu)
	{
		return static_cast<unicorn_vcpu_base*>(cpu.get())->native();
	}

	std::pair<std::uint8_t*, std::size_t> find_backing(addr_t addr)
	{
		for (auto& [base, buf] : mem_)
		{
			if (addr >= base && addr < base + buf.size())
			{
				auto off = addr - base;
				return { buf.data() + off, buf.size() - off };
			}
		}
		return { nullptr, 0 };
	}


	std::unordered_map<addr_t, std::vector<std::uint8_t>> mem_;
	std::list<unicorn_hook> hooks_;
	std::mutex op_mtx_;

	// The phys read/write paths only look the region up, so they share; growing it is exclusive.
	mutable std::shared_mutex mem_mtx_;
};
