#include "unwind.hpp"
#include "../exception.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../emu/object.hpp"
#include "../../../target.hpp"
#include "../../../util/log.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "arm64_unwind.hpp"
#else
	#include "x64_unwind.hpp"
#endif
#include "../../process.hpp"

namespace win {

std::unique_ptr<win_unwinder> make_unwinder(const proc_module& mod)
{
	const auto* img = mod.pe();
	if (!img)
		return nullptr;

#if defined(KERNEMUL_ARCH_ARM64)
	if (img->is_arm64())
		return std::make_unique<arm64_unwinder>();
#else
	if (img->is_x64())
		return std::make_unique<x64_unwinder>();
#endif

	LOG_ERR("{} was built for another architecture than this emulator", mod.name);
	return nullptr;
}

handler_result search_scope_table(vcpu& cpu, guest_caller& calls, const scope_search& search)
{
	auto& space = *cpu.curr_addr_space();

	const auto count = space.read_mem<std::uint32_t>(search.handler_data);
	const auto first = search.handler_data + sizeof(std::uint32_t);
	const auto pc_rva = static_cast<std::uint32_t>(search.control_pc - search.image_base);

	for (auto i = search.first_scope; i < count; ++i)
	{
		const auto scope = space.read_mem<scope_entry>(first + i * sizeof(scope_entry));

		if (pc_rva < scope.begin_address || pc_rva >= scope.end_address)
			continue;

		if (!scope.jump_target)
			continue;

		// 1 is EXCEPTION_EXECUTE_HANDLER written straight into the table, with no filter to ask.
		if (scope.handler_address != 1)
		{
			const auto filter = search.image_base + scope.handler_address;
			const std::uint64_t args[] = { search.exception_pointers, search.establisher_frame };

			LOG_INFO("  calling filter at 0x{:X}", filter);

			const auto verdict = static_cast<std::int32_t>(
				win::call_with_attachment_checkpoint(calls, cpu, filter, args, search.scratch));

			LOG_INFO("  filter returned {}", verdict);

			if (verdict < 0)
				return { exception_continue_execution, 0, 0 };

			if (verdict == 0)
				continue;
		}

		const auto target = search.image_base + scope.jump_target;

		LOG_INFO("  EXCEPTION_EXECUTE_HANDLER -> 0x{:X}", target);

		return { exception_execute_handler, target, search.establisher_frame };
	}

	return { exception_continue_search, 0, 0 };
}

filter_pointers build_exception_pointers(vcpu& cpu, windows_emulator& emulator,
	const exception_info& info)
{
	auto& space = *cpu.curr_addr_space();

	constexpr std::size_t scratch = sizeof(_EXCEPTION_RECORD) + sizeof(_CONTEXT)
		+ sizeof(_EXCEPTION_POINTERS) + 0x30;

	const auto record_addr = guest_caller::scratch_base(cpu, scratch);
	const auto context_addr = (record_addr + sizeof(_EXCEPTION_RECORD) + 0xF) & ~addr_t(0xF);
	const auto pointers_addr = context_addr + sizeof(_CONTEXT);

	const auto ptr = [](const addr_t a) { return static_cast<std::uintptr_t>(a); };

	_EXCEPTION_RECORD record{};
	record.ExceptionCode = static_cast<std::int32_t>(info.code);
	record.ExceptionAddress = reinterpret_cast<void*>(ptr(info.exception_address));

	if (info.code == status_access_violation)
	{
		record.NumberParameters = 2;
		record.ExceptionInformation[1] = info.fault_address;
	}

	space.write_mem(record_addr, record);

	emu_object<_CONTEXT> context(space, context_addr);
	context.write(_CONTEXT{});
	emulator.capture_context({cpu}, context, windows_emulator::context_all);

	_EXCEPTION_POINTERS pointers{};
	pointers.ExceptionRecord = reinterpret_cast<_EXCEPTION_RECORD*>(ptr(record_addr));
	pointers.ContextRecord = reinterpret_cast<_CONTEXT*>(ptr(context_addr));

	space.write_mem(pointers_addr, pointers);

	return { pointers_addr, scratch };
}

dispatch_frame build_dispatch_frame(vcpu& cpu, windows_emulator& emulator,
	const exception_info& info)
{
	auto& space = *cpu.curr_addr_space();

	constexpr std::size_t scratch = sizeof(_EXCEPTION_RECORD) + sizeof(_CONTEXT)
		+ sizeof(dispatcher_context64) + 0x40;

	const auto record_addr = guest_caller::scratch_base(cpu, scratch);
	const auto context_addr = (record_addr + sizeof(_EXCEPTION_RECORD) + 0xF) & ~addr_t(0xF);
	const auto dispatcher_addr = (context_addr + sizeof(_CONTEXT) + 0xF) & ~addr_t(0xF);

	const auto ptr = [](const addr_t a) { return reinterpret_cast<void*>(static_cast<std::uintptr_t>(a)); };

	_EXCEPTION_RECORD record{};
	record.ExceptionCode = static_cast<std::int32_t>(info.code);
	record.ExceptionAddress = ptr(info.exception_address);

	if (info.code == status_access_violation)
	{
		record.NumberParameters = 2;
		record.ExceptionInformation[1] = info.fault_address;
	}

	space.write_mem(record_addr, record);

	emu_object<_CONTEXT> context(space, context_addr);
	context.write(_CONTEXT{});
	emulator.capture_context({cpu}, context, windows_emulator::context_all);

	return { record_addr, context_addr, dispatcher_addr, scratch };
}

std::vector<stack_frame> walk_stack(
	win_unwinder& unwinder, addr_space& mem, const process& proc,
	unwind_context ctx, const std::size_t max_frames)
{
	std::vector<stack_frame> frames;
	frames.push_back({ ctx.pc, ctx.sp });

	for (std::size_t i = 0; i < max_frames; ++i)
	{
		const auto mod = proc.find_module_by_addr(ctx.pc);
		if (!mod)
			break;

		unwind_result result{};
		if (!unwinder.unwind_frame(mem, *mod, ctx, result))
			break;

		frames.push_back({ ctx.pc, ctx.sp });
	}

	return frames;
}

} // namespace win
