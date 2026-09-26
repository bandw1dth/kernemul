#pragma once
// x86-64, Windows and one cpu only: hypermulator's hook and step state is per partition.
#if defined(KERNEMUL_HAS_WHP)
#include "../emu.hpp"
#include "arch.hpp"

#include <memory>
#include <vector>

namespace hm { class emu; struct emu_hook; }

class x86_whp_emu;

class x86_whp_vcpu final : public vcpu
{
public:
	x86_whp_vcpu(x86_whp_emu* emu, std::shared_ptr<const struct arch> arch, hm::emu& backend,
		std::size_t id);

	void run() override;
	void stop() override;
	void try_stop() override;
	void flush_tlb() override;

	void reg_read(reg_t reg, void* value, std::size_t size) override;
	void reg_write(reg_t reg, const void* value, std::size_t size) override;

private:
	x86_whp_emu& whp_;
	hm::emu& hm_;
};

class x86_whp_emu final : public emu
{
public:
	explicit x86_whp_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {});

	~x86_whp_emu() override;

	hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb,
		addr_space* space) override;
	hook_handle hook_insn(addr_t start_addr, addr_t end_addr, hook_insn_t insn, insn_hk_cb) override;
	hook_handle hook_code(addr_t start_addr, addr_t end_addr, code_hk_cb) override;
	hook_handle hook_basic_block(addr_t start_addr, addr_t end_addr, code_hk_cb) override;
	hook_handle hook_invalid_mem(mem_prot access, invalid_mem_hk_cb) override;
	hook_handle hook_exception(exception_hk_cb) override;
	void remove_hook(hook_handle handle) override;

	void map_phys_mem(addr_t addr, std::size_t size) override;
	void unmap_phys_mem(addr_t addr, std::size_t size, mem_prot prot) override;
	void read_phys_mem(addr_t addr, void* buf, std::size_t size) override;
	void write_phys_mem(addr_t addr, const void* buf, std::size_t size) override;

	[[nodiscard]] hm::emu& native() const noexcept { return *hm_; }

	[[nodiscard]] vcpu* hook_cpu() const;

	// Whether the cpu is left to execute syscall or made to fault on it, decided by the
	// ring it is about to run in. A vm entry is the one place that has to agree with the
	// ring. Thread switches restore cs with the cpu stopped, but nested callbacks can enter
	// kernel mode while WHP is running, so syscall enable is resynchronized after dispatch.
	void sync_syscall_enable(vcpu& cpu);

protected:
	std::shared_ptr<vcpu> create_vcpu(std::size_t id) override;

private:
	struct whp_hook;

	struct phys_run
	{
		addr_t begin, end;
	};

	// The physical runs a virtual range maps to, end exclusive; contiguous pages coalesce.
	[[nodiscard]] std::vector<phys_run> phys_runs(addr_t start_addr, addr_t end_addr,
		addr_space* named = nullptr);

	hook_handle add_hook(std::unique_ptr<whp_hook> hook);

	// True when the #UD is a syscall this backend asked the cpu for, and it has been served.
	bool try_dispatch_syscall(insn_hk_cb& cb, addr_t start, addr_t end);

	std::unique_ptr<hm::emu> hm_;
	std::vector<std::unique_ptr<emu_hook>> hooks_;

	// How many syscall hooks are live. Nothing but their presence decides whether the cpu is
	// allowed to execute syscall, so the count is all this needs to know about them.
	int syscall_hooks_ = 0;
};

#endif
