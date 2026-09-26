#pragma once
#include "win_kernel.hpp"
#include "segments.hpp"
#include "../../emu/x86/mmu.hpp"

#include "syscalls.hpp"
#include "thread.hpp"
#include <algorithm>
#include <cstring>
#include <span>
#include <utility>

inline constexpr context_flags context_amd64    { 0x00100000 };
inline constexpr context_flags context_control  = context_amd64.with(0x1);
inline constexpr context_flags context_integer  = context_amd64.with(0x2);
inline constexpr context_flags context_segments = context_amd64.with(0x4);
inline constexpr context_flags context_float    = context_amd64.with(0x8);

inline constexpr context_flags context_full =
	context_control | context_integer | context_float;

// The service number is in eax, and every usermode stub opens the same way.
struct x86_win_syscall : win_syscall
{
	[[nodiscard]] std::uint32_t id(vcpu& cpu) const override
	{
		return static_cast<std::uint32_t>(cpu.reg<std::uint64_t>(x86::rax));
	}

	[[nodiscard]] std::optional<std::uint32_t> decode_id(
		const std::span<const std::uint8_t> stub) const override
	{
		// 4C 8B D1 mov r10, rcx; B8 XX XX XX XX mov eax, service_number.
		constexpr std::uint8_t opening[]{ 0x4C, 0x8B, 0xD1, 0xB8 };

		if (stub.size() < sizeof(opening) + sizeof(std::uint32_t))
			return std::nullopt;

		if (!std::equal(std::begin(opening), std::end(opening), stub.begin()))
			return std::nullopt;

		std::uint32_t number = 0;
		std::memcpy(&number, stub.data() + sizeof(opening), sizeof(number));

		return number;
	}
};

class x86_win_emulator : public windows_emulator
{
public:
	using windows_emulator::windows_emulator;

	// Windows points one pml4 slot back at the pml4, which is how a driver reads page tables as
	// ordinary memory -- and how it recognises a machine it is running on. It has to be the slot
	// the mapped ntoskrnl was built for: every inlined MiGetPteAddress in it carries
	// 0xFFFFF68000000000 as an immediate, and a guest hunting for the slot walks all 512.
	static constexpr std::size_t self_map_pml4_index = 0x1ED;

	// Every space needs its own. A later space copies the top half of the kernel's and the slot
	// is in that half, so the copy names the kernel's root -- which is the one thing a self map
	// must never do, since a walk through it would then describe another space's page tables.
	// Defined out of line because a page table entry is an ia32 type.
	static void install_self_map(::addr_space& space);

	void prepare_addr_space(::addr_space& space) override { install_self_map(space); }

	// What rdmsr 0x1B reports, so it is the page a driver goes on to map.
	static constexpr addr_t local_apic_phys = 0xFEE00000;

	void map_local_apic(::addr_space& space)
	{
		if (std::exchange(apic_mapped_, true))
			return;

		const auto va = space.alloc_phys(local_apic_phys,
			space.mmu_->page_size(), prot_rw | prot_supervisor);

		LOG_INFO("local apic: physical 0x{:X} -> 0x{:X}", local_apic_phys, va);
	}

	std::shared_ptr<vcpu> add_vcpu() override
	{
		auto cpu = emu_->add_vcpu();

		if (const auto nt = kernel().sys_proc->find_module("ntoskrnl.exe"))
		{
			install_self_map(*cpu->curr_addr_space());
			map_local_apic(*cpu->curr_addr_space());

			const auto tables = x86_win_seg::init_vcpu(*cpu, *nt);

			// After the tables: the KPCR carries the pointers the guest reads back out of it.
			const auto& pcpu = kernel().init_per_cpu(*cpu);
			const auto& kpcr = pcpu.object();

			const auto ptr = [](const addr_t a) { return static_cast<std::uintptr_t>(a); };

			kpcr.field(&_KPCR::GdtBase).write(reinterpret_cast<_KGDTENTRY64*>(ptr(tables.gdt)));
			kpcr.field(&_KPCR::TssBase).write(reinterpret_cast<_KTSS64*>(ptr(tables.tss)));
			kpcr.field(&_KPCR::IdtBase).write(reinterpret_cast<_KIDTENTRY64*>(ptr(tables.idt)));

			set_pcr(*cpu, pcpu.address());
		}

		return cpu;
	}

	void set_pcr(vcpu& cpu, const addr_t kpcr_va) override
	{
		x86_win_seg::set_kernel_gs(cpu, kpcr_va);
	}

	void set_hw_irql(vcpu& cpu, const irql_t irql) override
	{
		cpu.reg(x86::cr8, static_cast<std::uint64_t>(irql));
	}

	[[nodiscard]] irql_t irql(vcpu& cpu) override
	{
		// Guest MOV CR8 bypasses the hooked IRQL APIs. Hardware is authoritative.
		const auto level = static_cast<irql_t>(cpu.reg<std::uint64_t>(x86::cr8));
		if (const auto* pcpu = per_cpu(cpu); pcpu && pcpu->irql() != level)
			pcpu->set_irql(level);
		return level;
	}

	void set_kernel_mode(vcpu& cpu, const bool kernel) override
	{
		if (kernel)
			x86_win_seg::swap_to_kernel_segments(cpu);
		else
			x86_win_seg::swap_to_usermode_segments(cpu);
	}

	void init_thread_teb(thread& t, vcpu& cpu, addr_t teb_addr) override
	{
		t.set_reg_val(cpu, x86::cs, x86_win_seg::make_usermode_cs());
		t.set_reg_val(cpu, x86::ss, x86_win_seg::make_usermode_ss());
		t.set_reg_val(cpu, x86::gs, x86_win_seg::make_usermode_gs(teb_addr));
	}

	// LdrInitializeThunk(context, ntdll_base); the loader hands that context to NtContinue.
	// The context continues into RtlUserThreadStart(entry_point, argument) -- the argument is
	// what the guest passed to NtCreateThreadEx, and zero for the thread the process starts on.
	void setup_loader_frame(thread& t, vcpu& cpu, const addr_t entry_point,
		const addr_t ntdll_base, const addr_t argument) override
	{
		const auto* const ut = dynamic_cast<const win_thread*>(&t);

		if (!ut)
			return;

		auto& space = *t.proc()->addr_space();
		const auto thread_start = t.proc()->thread_exit_addr();

		const addr_t stack_top = (ut->stack_base() - 0x1000) & ~addr_t(0xF);
		const addr_t context_addr = (stack_top - sizeof(_CONTEXT)) & ~addr_t(0xF);

		_CONTEXT ctx{};
		ctx.ContextFlags = context_full.bits;
		ctx.MxCsr = 0x1F80;
		ctx.SegCs = x86_win_seg::user_cs;
		ctx.SegSs = x86_win_seg::user_ds;
		ctx.EFlags = 0x200;
		ctx.Rip = thread_start;
		ctx.Rsp = stack_top - sizeof(addr_t);
		ctx.Rcx = entry_point;
		ctx.Rdx = argument;

		space.write_mem(context_addr, &ctx, sizeof(ctx));

		// enqueue() already pushed a return address, but the stack pointer moves here.
		const addr_t sp = context_addr - sizeof(addr_t);
		space.write_mem<addr_t>(sp, thread_start);

		if (const auto& teb = ut->teb())
			space.write_mem<std::uint8_t>(teb.address() + 0x179C, 1);

		t.set_reg(cpu, x86::rsp, sp);
		t.set_reg(cpu, x86::rcx, context_addr);
		t.set_reg(cpu, x86::rdx, ntdll_base);

		LOG_INFO("user thread {}: context at 0x{:X}, stack 0x{:X}-0x{:X}, "
			"continues to 0x{:X} with entry 0x{:X}",
			t.id(), context_addr, ut->stack_limit(), ut->stack_base(),
			thread_start, entry_point);
	}

	// From the guest's ntdll: "add rcx, 4F0h" the record, "mov rdx, rsp" the context.
	static constexpr addr_t exception_record_offset = 0x4F0;
	static_assert(sizeof(_CONTEXT) <= exception_record_offset,
		"a CONTEXT has to fit under the record the dispatcher expects above it");

	// Unwind codes end UWOP_ALLOC_LARGE 0x590, UWOP_PUSH_MACHFRAME: rip, cs, eflags, rsp, ss.
	static constexpr addr_t machine_frame_offset = 0x590;
	static_assert(exception_record_offset + sizeof(_EXCEPTION_RECORD) <= machine_frame_offset,
		"the record has to fit under the machine frame");

	struct machine_frame
	{
		addr_t rip;
		addr_t cs;
		addr_t eflags;
		addr_t rsp;
		addr_t ss;
	};

	bool setup_exception_frame(vcpu& cpu, const addr_t dispatcher,
		const win::exception_info& info) override
	{
		auto& space = *cpu.curr_addr_space();

		constexpr addr_t frame = machine_frame_offset + sizeof(machine_frame);

		const addr_t context_addr = (cpu.sp() - 0x100 - frame) & ~addr_t(0xF);
		const addr_t record_addr = context_addr + exception_record_offset;

		emu_object<_CONTEXT> context(space, context_addr);
		context.write(_CONTEXT{});
		capture_context({cpu}, context, context_all);

		_EXCEPTION_RECORD record{};
		record.ExceptionCode = static_cast<std::int32_t>(info.code);
		record.ExceptionAddress = reinterpret_cast<void*>(
			static_cast<std::uintptr_t>(info.exception_address));

		if (info.code == win::status_access_violation)
		{
			record.NumberParameters = 2;
			record.ExceptionInformation[1] = info.fault_address;
		}

		space.write_mem(record_addr, record);

		const machine_frame mframe{
			.rip = info.exception_address,
			.cs = x86_win_seg::user_cs,
			.eflags = reg_view{cpu}.get(x86::rflags),
			.rsp = cpu.sp(),
			.ss = x86_win_seg::user_ds,
		};

		space.write_mem(context_addr + machine_frame_offset, mframe);

		cpu.set_sp(context_addr);
		cpu.set_pc(dispatcher);

		return true;
	}

	// The backend has no register for either; an MxCsr of zero unmasks every sse exception.
	static constexpr std::uint32_t default_mxcsr = 0x1F80;
	static constexpr std::uint16_t default_fpcw  = 0x27F;

	void capture_context(const reg_view& regs, emu_object<_CONTEXT> out,
		const context_flags flags) override
	{
		if (!out)
			return;

		auto ctx = out.read();
		auto filled = context_amd64;

		// Or whoever continues through this context does it in the wrong mode.
		const bool user = regs.is_user();
		const auto code_sel = user ? x86_win_seg::user_cs : x86_win_seg::kernel_cs;
		const auto data_sel = user ? x86_win_seg::user_ds : x86_win_seg::kernel_ds;

		if (flags.has(context_integer))
		{
			filled |= context_integer;

			ctx.Rax = regs.get(x86::rax);
			ctx.Rcx = regs.get(x86::rcx);
			ctx.Rdx = regs.get(x86::rdx);
			ctx.Rbx = regs.get(x86::rbx);
			ctx.Rsi = regs.get(x86::rsi);
			ctx.Rdi = regs.get(x86::rdi);
			ctx.R8  = regs.get(x86::r8);
			ctx.R9  = regs.get(x86::r9);
			ctx.R10 = regs.get(x86::r10);
			ctx.R11 = regs.get(x86::r11);
			ctx.R12 = regs.get(x86::r12);
			ctx.R13 = regs.get(x86::r13);
			ctx.R14 = regs.get(x86::r14);
			ctx.R15 = regs.get(x86::r15);
		}

		if (flags.has(context_control))
		{
			filled |= context_control;

			ctx.Rsp = regs.get(x86::rsp);
			ctx.Rbp = regs.get(x86::rbp);
			ctx.Rip = regs.get(x86::rip);
			ctx.EFlags = static_cast<std::uint32_t>(regs.get(x86::rflags));
			ctx.SegCs = code_sel;
			ctx.SegSs = data_sel;
		}

		if (flags.has(context_segments))
		{
			filled |= context_segments;

			ctx.SegDs = data_sel;
			ctx.SegEs = data_sel;
			ctx.SegFs = data_sel;
			ctx.SegGs = data_sel;
		}

		// xmm6-15 are nonvolatile, and leaving the half out had ntdll restore zeroes over them.
		if (flags.has(context_float))
		{
			filled |= context_float;

			ctx.MxCsr = default_mxcsr;
			ctx.FltSave.MxCsr = default_mxcsr;
			ctx.FltSave.ControlWord = default_fpcw;

			for (int i = 0; i < 16; ++i)
			{
				const auto value = regs.get_reg<x86::xmm_t>(x86::xmm0 + i);

				ctx.FltSave.XmmRegisters[i].Low = value.low;
				ctx.FltSave.XmmRegisters[i].High = static_cast<std::int64_t>(value.high);
			}
		}

		ctx.ContextFlags = filled.bits;
		out.write(ctx);
	}

	void apply_context(const reg_view& regs, emu_object<_CONTEXT> in) override
	{
		if (!in)
			return;

		const auto ctx = in.read();
		const context_flags flags{ ctx.ContextFlags };

		if (flags.has(context_integer))
		{
			regs.set(x86::rax, ctx.Rax);
			regs.set(x86::rcx, ctx.Rcx);
			regs.set(x86::rdx, ctx.Rdx);
			regs.set(x86::rbx, ctx.Rbx);
			regs.set(x86::rsi, ctx.Rsi);
			regs.set(x86::rdi, ctx.Rdi);
			regs.set(x86::r8,  ctx.R8);
			regs.set(x86::r9,  ctx.R9);
			regs.set(x86::r10, ctx.R10);
			regs.set(x86::r11, ctx.R11);
			regs.set(x86::r12, ctx.R12);
			regs.set(x86::r13, ctx.R13);
			regs.set(x86::r14, ctx.R14);
			regs.set(x86::r15, ctx.R15);
		}

		if (flags.has(context_float))
		{
			for (int i = 0; i < 16; ++i)
			{
				const auto& saved = ctx.FltSave.XmmRegisters[i];

				regs.set_reg(x86::xmm0 + i, x86::xmm_t{
					.low = saved.Low,
					.high = static_cast<std::uint64_t>(saved.High),
				});
			}
		}

		if (flags.has(context_control))
		{
			regs.set(x86::rsp, ctx.Rsp);
			regs.set(x86::rbp, ctx.Rbp);
			regs.set(x86::rip, ctx.Rip);

			// Bit 1 reads as one, and a hand-built CONTEXT often leaves it clear.
			regs.set(x86::rflags, ctx.EFlags | 0x2u);

			if (static_cast<std::uint16_t>(ctx.SegCs) == x86_win_seg::user_cs)
			{
				regs.set_reg(x86::cs, x86_win_seg::make_usermode_cs());
				regs.set_reg(x86::ss, x86_win_seg::make_usermode_ss());
			}
		}
	}

private:
	bool apic_mapped_ = false;
};
