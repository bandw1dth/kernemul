#pragma once
#include <optional>
#include <utility>
#include "arch.hpp"
#include "defs.hpp"
#include "mmu.hpp"
#include "guest_call_completion.hpp"
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

class emu;
class thread;
struct calling_conv;

class vcpu
{
public:
	vcpu(emu* const emu, std::shared_ptr<const arch> arch, const std::size_t id)
		:	emu_(emu), arch_(std::move(arch)), id_(id) { }

	virtual ~vcpu() = default;

	virtual void run() = 0;
	virtual void stop() = 0;

	virtual void try_stop() { stop(); }
	virtual bool execution_failed() const { return false; }
	// Owned by this vCPU's host thread, for checked deferred guest callbacks only.
	bool in_dpc = false;
	bool dpc_failed = false;
	checked_guest_calls checked_calls;
	virtual void flush_tlb() = 0;

	virtual void reg_read(reg_t reg, void* value, std::size_t size) = 0;
	virtual void reg_write(reg_t reg, const void* value, std::size_t size) = 0;

	template <reg_t R, typename T = std::uint64_t>
	T reg()
	{
		T v{};
		reg_read(R, &v, sizeof(v));
		return v;
	}

	template <reg_t R, typename T = std::uint64_t>
	void reg(const T& v)
	{
		reg_write(R, &v, sizeof(v));
	}

	template <typename T = std::uint64_t>
	T reg(reg_t r)
	{
		T v{};
		reg_read(r, &v, sizeof(v));
		return v;
	}

	template <typename T = std::uint64_t>
	void reg(reg_t r, const T& v)
	{
		reg_write(r, &v, sizeof(v));
	}

	[[nodiscard]] std::shared_ptr<const arch> arch() const noexcept
	{
		return arch_;
	}

	[[nodiscard]] class emu* emu() const noexcept { return emu_; }

	[[nodiscard]] std::size_t id() const noexcept { return id_; }

	[[nodiscard]] std::shared_ptr<thread> thread() const noexcept { return thread_; }
	void set_thread(std::shared_ptr<class thread> t) { thread_ = std::move(t); }

	addr_t pc() { return reg(arch_->pc()); }
	void set_pc(addr_t v) { reg(arch_->pc(), v); }

	addr_t sp() { return reg(arch_->sp()); }
	void set_sp(addr_t v) { reg(arch_->sp(), v); }

	std::shared_ptr<addr_space> curr_addr_space();

	void read_virt_mem(addr_t va, void* buf, std::size_t size)
	{
		curr_addr_space()->read_mem(va, buf, size);
	}

	void write_virt_mem(addr_t va, const void* buf, std::size_t size)
	{
		curr_addr_space()->write_mem(va, buf, size);
	}

	template <typename T>
	T read_virt_mem(addr_t va)
	{
		return curr_addr_space()->read_mem<T>(va);
	}

	template <typename T>
	void write_virt_mem(addr_t va, const T& val)
	{
		curr_addr_space()->write_mem<T>(va, val);
	}

protected:
	class emu* emu_;
	std::shared_ptr<const struct arch> arch_;
	std::shared_ptr<class thread> thread_;
	const std::size_t id_;
};

enum class hook_insn_t : std::uint8_t
{
	cpuid,
	rdtsc,
	rdmsr,
	wrmsr,
	syscall,
};

enum class cpu_exception : std::uint8_t
{
	divide_by_zero,
	debug,
	breakpoint,
	illegal_instruction,
	page_fault,
	interrupt,
	other,
};

constexpr std::string_view to_string(const cpu_exception ex)
{
	switch (ex)
	{
	case cpu_exception::divide_by_zero:      return "divide by zero";
	case cpu_exception::debug:               return "debug trap";
	case cpu_exception::breakpoint:          return "breakpoint";
	case cpu_exception::illegal_instruction: return "illegal instruction";
	case cpu_exception::page_fault:          return "page fault";
	case cpu_exception::interrupt:           return "interrupt";
	case cpu_exception::other:               return "exception";
	}

	return "exception";
}

using mem_hk_cb = std::function<void(vcpu&, addr_t, std::size_t, mem_prot)>;
using insn_hk_cb = std::function<bool(vcpu&)>;
using code_hk_cb = std::function<void(vcpu&, addr_t, std::size_t)>;
using invalid_mem_hk_cb = std::function<bool(vcpu&, addr_t, std::size_t, mem_prot)>;
using exception_hk_cb = std::function<bool(vcpu&, cpu_exception)>;

struct emu_hook
{
	virtual ~emu_hook() = default;

	std::variant<mem_hk_cb, insn_hk_cb, code_hk_cb, invalid_mem_hk_cb, exception_hk_cb> cb;
	emu* owner;
	addr_t start, end;
};

class emu
{
public:
	emu(std::shared_ptr<struct arch> arch, std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {})
		:	arch_(std::move(arch)), mem_(std::move(mem)), call_conv_(std::move(call_conv))
	{
		if (arch_) arch_->set_emu(this);
		if (mem_) mem_->set_emu(this);
	}

	virtual ~emu() = default;

	using hook_handle = emu_hook*;

	[[nodiscard]] std::shared_ptr<const arch> arch() const noexcept
	{
		return arch_;
	}

	[[nodiscard]] std::shared_ptr<const calling_conv> call_conv() const noexcept
	{
		return call_conv_;
	}

	[[nodiscard]] std::shared_ptr<vcpu> add_vcpu()
	{
		auto cpu = create_vcpu(cpus_.size());
		cpus_.push_back(cpu);

		if (arch_)
			arch_->init_vcpu(*cpu);

		if (mem_)
		{
			if (!default_space_)
				default_space_ = mem_->create_addr_space();

			mem_->init_vcpu(*cpu);
			mem_->switch_to(*cpu, default_space_);
		}

		return cpu;
	}

	// `space` is the address space the range belongs to, for a backend that has to resolve the
	// range as the hook goes in rather than as it fires. A watch put on a process while it is
	// still being built belongs to a space no cpu has entered yet, so there is nothing to infer
	// it from; leaving it null means the range is in whichever space the cpu is already in.
	virtual hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb,
		addr_space* space = nullptr) = 0;
	virtual hook_handle hook_insn(addr_t start_addr, addr_t end_addr, hook_insn_t insn, insn_hk_cb) = 0;
	virtual hook_handle hook_code(addr_t start_addr, addr_t end_addr, code_hk_cb) = 0;
	virtual hook_handle hook_basic_block(addr_t start_addr, addr_t end_addr, code_hk_cb) = 0;
	virtual hook_handle hook_invalid_mem(mem_prot access, invalid_mem_hk_cb) = 0;
	virtual hook_handle hook_exception(exception_hk_cb) = 0;
	virtual void remove_hook(hook_handle handle) = 0;

	// Run fn with no cpu executing guest code.
	virtual void run_on_all(const std::function<void()>& fn) { fn(); }

	// Always mapped rwx so the guest page tables, not this, decide access.
	virtual void map_phys_mem(addr_t addr, std::size_t size) = 0;
	virtual void unmap_phys_mem(addr_t addr, std::size_t size, mem_prot prot) = 0;
	virtual void read_phys_mem(addr_t addr, void* buf, std::size_t size) = 0;
	virtual void write_phys_mem(addr_t addr, const void* buf, std::size_t size) = 0;

	[[nodiscard]] std::span<const std::shared_ptr<vcpu>> cpus() const noexcept
	{
		return cpus_;
	}

	std::shared_ptr<mmu> mem() { return mem_; }
	std::shared_ptr<const mmu> mem() const { return mem_; }

	std::shared_ptr<addr_space> default_addr_space()
	{
		if (!default_space_)
			default_space_ = mem_->create_addr_space();

		return default_space_;
	}

protected:
	virtual std::shared_ptr<vcpu> create_vcpu(std::size_t id) = 0;

	std::shared_ptr<struct arch> arch_;
	std::vector<std::shared_ptr<vcpu>> cpus_;
	std::shared_ptr<mmu> mem_;
	std::shared_ptr<calling_conv> call_conv_;
	std::shared_ptr<addr_space> default_space_;
};

inline std::shared_ptr<addr_space> vcpu::curr_addr_space()
{
	return emu_->mem()->curr_addr_space(*this);
}
