#pragma once
#include "arch.hpp"
#include "calling_conv.hpp"
#include "emu.hpp"
#include "guest_call_completion.hpp"
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>
#include <unordered_map>
#include <stdexcept>

inline void guest_tail_call(vcpu& cpu, const addr_t routine,
	const std::span<const std::uint64_t> args)
{
	const auto& conv = *cpu.emu()->call_conv();

	for (std::size_t i = 0; i < args.size(); ++i)
		conv.write_arg(cpu, i, args[i]);

	cpu.set_pc(routine);
}

class guest_caller
{
public:
	std::uint64_t call(vcpu& cpu, addr_t routine, std::span<const std::uint64_t> args,
		std::size_t scratch = 0, const std::function<bool()>& cancelled = {})
	{
		checked_guest_calls::scope checked(cpu.checked_calls, static_cast<bool>(cancelled));
		const auto saved_space = cpu.curr_addr_space();
		const auto a = cpu.arch();
		const auto regs = a->regs();
		const auto& conv = *cpu.emu()->call_conv();

		std::vector<reg_val> saved(regs.size());

		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_read(regs[i], &saved[i], a->reg_size(regs[i]));

		// Below the scratch rather than at it: the routine being called owns the shadow space
		// above its return address and spills its arguments there before it reads anything.
		// Starting it at the scratch base would put that space on top of whatever the caller
		// built for it -- an exception record, whose first field is the code the handler then
		// reads back as the low half of its own first argument.
		cpu.set_sp(scratch_base(cpu, scratch) - conv.sp_spadow());
		a->set_ret_addr(cpu, trampoline(cpu));

		for (std::size_t i = 0; i < args.size(); ++i)
			conv.write_arg(cpu, i, args[i]);

		cpu.set_pc(routine);
		guest_call_completions::invocation invocation(completions_, cpu.id());
		try
		{
			do
			{
				if (checked.failed() || (cancelled && cancelled()))
					throw std::runtime_error("guest callback stopped before returning");
				cpu.run();
				if (checked.failed() || (cancelled && cancelled())
					|| (checked.checked() && cpu.execution_failed()))
					throw std::runtime_error("guest callback stopped before returning");
				if (!checked.checked() || invocation.returned()) break;
			} while (true);
		}
		catch (...)
		{
			cpu.checked_calls.fail();
			cpu.emu()->mem()->switch_to(cpu, saved_space);
			for (std::size_t i = 0; i < regs.size(); ++i)
				cpu.reg_write(regs[i], &saved[i], a->reg_size(regs[i]));
			throw;
		}

		const auto result = conv.read_ret(cpu);
		cpu.emu()->mem()->switch_to(cpu, saved_space);

		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_write(regs[i], &saved[i], a->reg_size(regs[i]));

		return result;
	}

	static addr_t scratch_base(vcpu& cpu, const std::size_t size)
	{
		return (cpu.sp() - red_zone - size) & ~addr_t(0xF);
	}

private:
	guest_call_completions completions_;
	// Clear of the handler frame, so a routine reading past its arguments stays off it.
	static constexpr addr_t red_zone = 0x100;

	// Returned to rather than executed: the hook fires on the address.
	addr_t trampoline(vcpu& cpu)
	{
		std::call_once(once_, [&]
		{
			// The trampoline is shared kernel state, even when first called while attached.
			trampoline_ = cpu.emu()->default_addr_space()->alloc(0x1000, prot_rx | prot_supervisor);

			cpu.emu()->hook_code(trampoline_, trampoline_,
				[this](vcpu& c, addr_t, std::size_t) {
					completions_.complete(c.id());
					c.stop();
				});
		});

		return trampoline_;
	}

	std::once_flag once_;
	addr_t trampoline_ = 0;
};
