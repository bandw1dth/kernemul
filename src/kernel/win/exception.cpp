#include "exception.hpp"
#include "execution_mode.hpp"
#include "win_kernel.hpp"
#include "unwind/unwind.hpp"
#include "../process.hpp"
#include "../../sym/symbol.hpp"
#include "../../emu/emu.hpp"
#include "../../util/log.hpp"

namespace win {

std::uint32_t exception_to_status(const cpu_exception ex)
{
	switch (ex)
	{
	case cpu_exception::divide_by_zero:      return status_integer_divide_by_zero;
	case cpu_exception::debug:               return status_single_step;
	case cpu_exception::breakpoint:          return status_breakpoint;
	case cpu_exception::illegal_instruction: return status_illegal_instruction;
	default:                                 return status_access_violation;
	}
}

win_exception::win_exception(win_kernel_state& kernel)
	: kernel_(kernel) { }

bool win_exception::handle_page_fault(vcpu& cpu)
{
	const auto t = cpu.thread();

	if (!t)
		return false;

	auto* const proc = dynamic_cast<win_user_proc*>(kernel_.current_process(cpu).get());

	if (!proc)
		return false;

	return proc->mem().handle_fault(cpu.arch()->fault_addr(cpu));
}

bool win_exception::handle(vcpu& cpu, const cpu_exception ex)
{
	if (ex == cpu_exception::page_fault && handle_page_fault(cpu))
		return true;

	// Some of what usermode may not execute is serviced rather than reported.
	if (ex == cpu_exception::illegal_instruction)
	{
		auto* const emulator = kernel_.emulator();

		if (emulator && emulator->emulate_privileged_insn(cpu))
			return true;
	}

	const bool user_mode = win::executing_user_mode(cpu);
	const auto faulting = user_mode ? kernel_.current_process(cpu) : kernel_.sys_proc;
	auto& proc = faulting ? *faulting : *kernel_.sys_proc;

	const auto original_pc = cpu.pc();
	const auto code = exception_to_status(ex);

	cpu.arch()->on_exception(cpu);

	LOG_INFO("exception dispatch: code=0x{:X}, rip={}, address=0x{:X}", code,
		symbols::format_addr(proc, original_pc), cpu.arch()->fault_addr(cpu));

	exception_info info{};
	info.code = code;
	info.exception_address = original_pc;
	info.fault_address = cpu.arch()->fault_addr(cpu);

	// There is no loader under a driver to own a dispatcher, so the walk below stays here.
	if (user_mode && dynamic_cast<win_user_proc*>(&proc))
	{
		std::optional<addr_t> dispatcher;

		if (const auto ntdll = proc.find_module(ntdll_name))
			dispatcher = ntdll->find_symbol(user_exception_dispatcher);

		auto* const emulator = kernel_.emulator();

		if (!dispatcher || !emulator)
		{
			LOG_ERR("{}!{} is not available, so a user fault cannot be delivered",
				ntdll_name, user_exception_dispatcher);

			return false;
		}

		if (!emulator->setup_exception_frame(cpu, *dispatcher, info))
		{
			LOG_ERR("this architecture cannot build an exception frame yet");
			return false;
		}

		LOG_INFO("  delivered to {}!{} at 0x{:X}", ntdll_name,
			user_exception_dispatcher, *dispatcher);

		return true;
	}

	auto mod = proc.find_module_by_addr(original_pc);
	if (!mod)
	{
		LOG_ERR("exception at 0x{:X}: not in any module this process knows of", original_pc);
		return false;
	}

	std::call_once(unwinder_once_, [&] { unwinder_ = make_unwinder(*mod); });

	if (!unwinder_)
		return false;

	auto& space = *cpu.curr_addr_space();
	const auto saved_pc = cpu.pc();
	const auto saved_sp = cpu.sp();

	auto uw_ctx = unwinder_->context_from_vcpu(cpu);

	for (std::size_t depth = 0; depth < 64; ++depth)
	{
		// Every frame above the faulting one holds a return address, so step back into the call.
		if (depth > 0)
			uw_ctx.pc -= 1;

		mod = proc.find_module_by_addr(uw_ctx.pc);
		if (!mod)
			break;

		const auto control_pc = uw_ctx.pc;

		unwind_result result{};
		if (!unwinder_->unwind_frame(space, *mod, uw_ctx, result))
		{
			LOG_WARN("  frame[{}]: unwind failed at 0x{:X}", depth, control_pc);
			break;
		}

		LOG_INFO("  frame[{}]: rip={}, handler=0x{:X}, ret=0x{:X}",
			depth, symbols::format_addr(proc, control_pc),
			result.handler, uw_ctx.pc);

		if (!result.handler)
			continue;

		auto* emulator = kernel_.emulator();

		if (!emulator)
			break;

		// The frame names its own personality routine, so ask it rather than assume.
		const auto frame = build_dispatch_frame(cpu, *emulator, info);

		dispatcher_context64 dispatch{};
		dispatch.control_pc = control_pc;
		dispatch.image_base = mod->addr;
		dispatch.function_entry = result.function_entry;
		dispatch.establisher_frame = result.establisher_frame;
		dispatch.context_record = frame.context;
		dispatch.language_handler = result.handler;
		dispatch.handler_data = result.handler_data;

		space.write_mem(frame.dispatcher, dispatch);

		const std::uint64_t args[] = {
			frame.record, result.establisher_frame, frame.context, frame.dispatcher };

		LOG_INFO("  calling handler at 0x{:X} (handler_data=0x{:X}, scopes={}, frame=0x{:X})",
			result.handler, result.handler_data,
			result.handler_data ? space.read_mem<std::uint32_t>(result.handler_data) : 0,
			result.establisher_frame);

		const auto disposition = static_cast<std::int32_t>(
			win::call_with_attachment_checkpoint(kernel_.calls, cpu, result.handler, args, frame.scratch));

		const auto answered = space.read_mem<dispatcher_context64>(frame.dispatcher);

		LOG_INFO("  handler returned {} (target=0x{:X})", disposition, answered.target_ip);

		if (disposition == exception_execute_handler && answered.target_ip)
		{
			LOG_INFO("exception handled at frame {} -> 0x{:X}", depth, answered.target_ip);
#if defined(KERNEMUL_ARCH_X64)
			// __C_specific_handler passes the sign-extended exception code to
			// RtlUnwindEx as its return value. The selected handler consumes RAX
			// for GetExceptionCode(); the personality call restored the old RAX.
			emulator->emu().call_conv()->ret(cpu,
				static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(code))));
#endif
			cpu.set_pc(answered.target_ip);
			cpu.set_sp(answered.establisher_frame);
			return true;
		}

		if (disposition == exception_continue_execution)
		{
			LOG_INFO("exception continue execution at 0x{:X}", original_pc);
			cpu.set_pc(original_pc);
			cpu.set_sp(saved_sp);
			return true;
		}

		cpu.set_pc(saved_pc);
		cpu.set_sp(saved_sp);
	}

	LOG_ERR("unhandled exception code=0x{:X} at 0x{:X}", code, original_pc);
	return false;
}

} // namespace win
