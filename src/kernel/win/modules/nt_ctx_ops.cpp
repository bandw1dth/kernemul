#include "nt_ctx_ops.hpp"
#include "../exception.hpp"
#include "../status.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../emu/guest_call.hpp"
#include "../../../util/log.hpp"
#include <cstdint>

namespace
{

// EXCEPTION_RECORD::ExceptionFlags: any of these means already unwinding.
constexpr std::uint32_t exception_unwinding_flags = 0x66;

constexpr std::uint64_t current_thread_handle = ~std::uint64_t{1};

struct target_thread
{
	std::shared_ptr<win_thread> thread;
	bool is_current = false;
};

target_thread resolve_thread(win_kernel_state& state, vcpu& cpu, const std::uint64_t handle)
{
	const auto self = std::dynamic_pointer_cast<win_thread>(cpu.thread());

	if (handle == current_thread_handle)
		return { self, true };

	const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

	if (!entry)
		return {};

	auto t = state.find_ethread(emu_object<_ETHREAD>(*cpu.curr_addr_space(), entry->body_addr));

	return { t, t && self && t->id() == self->id() };
}

}

void modules::register_ntoskrnl_ctx_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// Returning first leaves sp where the caller will find it, making the frame the caller's.
	state.redirect(mod, "RtlCaptureContext",
		[st](vcpu& cpu, emu_object<_CONTEXT> context)
		{
			const auto ret = cpu.arch()->ret_addr(cpu);
			cpu.set_pc(ret);

			if (auto* emulator = st->emulator())
				emulator->capture_context({cpu}, context, windows_emulator::context_all);

			THREAD_LOG_INFO("RtlCaptureContext(0x{:X}): pc=0x{:X}, sp=0x{:X}",
				context.address(), ret, cpu.sp());
		});

	// Returns nothing deliberately: a result would go to x0, a register the context just restored.
	state.redirect_ntzw(mod, "Continue",
		[st](vcpu& cpu, emu_object<_CONTEXT> context, const bool test_alert)
		{
			const auto fail = [&cpu](const NTSTATUS status)
			{
				cpu.emu()->call_conv()->ret(cpu, status);
			};

			if (!context)
				return fail(STATUS_INVALID_PARAMETER);

			auto* emulator = st->emulator();

			if (!emulator)
				return fail(STATUS_NOT_IMPLEMENTED);

			if (test_alert)
				THREAD_LOG_WARN("NtContinue: nothing delivers an APC, so there is no alert to "
					"test for");

			emulator->apply_context({cpu}, context);

			THREAD_LOG_INFO("NtContinue(0x{:X}): pc=0x{:X}, sp=0x{:X}",
				context.address(), cpu.pc(), cpu.sp());
		});

	state.redirect_ntzw(mod, "GetContextThread",
		[st](vcpu& cpu, const std::uint64_t thread_handle,
			emu_object<_CONTEXT> context) -> NTSTATUS
		{
			if (!context)
				return STATUS_INVALID_PARAMETER;

			const auto target = resolve_thread(*st, cpu, thread_handle);

			if (!target.thread)
			{
				THREAD_LOG_WARN("NtGetContextThread: handle 0x{:X} is not a thread",
					thread_handle);
				return STATUS_INVALID_HANDLE;
			}

			auto* emulator = st->emulator();

			if (!emulator)
				return STATUS_NOT_IMPLEMENTED;

			const context_flags wanted{ context.field(&_CONTEXT::ContextFlags).read() };
			const reg_view regs{cpu, target.is_current ? nullptr : target.thread.get()};

			emulator->capture_context(regs, context, wanted);

			THREAD_LOG_INFO("NtGetContextThread(tid={}, flags=0x{:X}) -> 0x{:X}",
				target.thread->id(), wanted.bits,
				context.field(&_CONTEXT::ContextFlags).read());

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "SetContextThread",
		[st](vcpu& cpu, const std::uint64_t thread_handle,
			emu_object<_CONTEXT> context) -> NTSTATUS
		{
			if (!context)
				return STATUS_INVALID_PARAMETER;

			const auto target = resolve_thread(*st, cpu, thread_handle);

			if (!target.thread)
			{
				THREAD_LOG_WARN("NtSetContextThread: handle 0x{:X} is not a thread",
					thread_handle);
				return STATUS_INVALID_HANDLE;
			}

			auto* emulator = st->emulator();

			if (!emulator)
				return STATUS_NOT_IMPLEMENTED;

			const reg_view regs{cpu, target.is_current ? nullptr : target.thread.get()};

			emulator->apply_context(regs, context);

			THREAD_LOG_INFO("NtSetContextThread(tid={}, flags=0x{:X})", target.thread->id(),
				context.field(&_CONTEXT::ContextFlags).read());

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "RaiseException",
		[st](vcpu& cpu, emu_object<_EXCEPTION_RECORD> exception_record,
			[[maybe_unused]] emu_object<_CONTEXT> context, const bool first_chance)
		{
			const auto code = exception_record
				? static_cast<std::uint32_t>(
					exception_record.field(&_EXCEPTION_RECORD::ExceptionCode).read())
				: 0;

			const auto at = exception_record
				? guest_va(exception_record.field(&_EXCEPTION_RECORD::ExceptionAddress).read())
				: 0;

			THREAD_LOG_ERR("NtRaiseException(code=0x{:X}, at=0x{:X}, first_chance={}): nothing "
				"delivers a software exception; stopping the machine without a normal process exit", code, at, first_chance);

			st->sys_proc->scheduler()->stop();
			cpu.stop();
		});

	// The DISPATCHER_CONTEXT fields read below are not in the generated types; same offsets.
	state.redirect(mod, "__C_specific_handler",
		[st](vcpu& cpu, emu_object<_EXCEPTION_RECORD> exception_record,
			const addr_t establisher_frame, emu_object<_CONTEXT> context_record,
			emu_object<win::dispatcher_context64> dispatcher_context) -> std::int32_t
		{
			if (!exception_record || !dispatcher_context)
				return win::exception_continue_search;

			auto& space = *cpu.curr_addr_space();

			const auto dispatch = dispatcher_context.read();
			const auto flags = static_cast<std::uint32_t>(
				exception_record.field(&_EXCEPTION_RECORD::ExceptionFlags).read());

			const auto control_rva = static_cast<std::uint32_t>(
				dispatch.control_pc - dispatch.image_base);

			THREAD_LOG_INFO("__C_specific_handler(code=0x{:X}, flags=0x{:X}, rva=0x{:X}, from={})",
				static_cast<std::uint32_t>(
					exception_record.field(&_EXCEPTION_RECORD::ExceptionCode).read()),
				flags, control_rva, dispatch.scope_index);

			if (flags & exception_unwinding_flags)
			{
				const auto count = space.read_mem<std::uint32_t>(dispatch.handler_data);
				const auto first = dispatch.handler_data + sizeof(std::uint32_t);

				for (auto i = dispatch.scope_index; i < count; ++i)
				{
					const auto scope = space.read_mem<win::scope_entry>(
						first + i * sizeof(win::scope_entry));

					if (control_rva < scope.begin_address || control_rva >= scope.end_address)
						continue;

					if (scope.jump_target)
						continue;

					const auto handler = dispatch.image_base + scope.handler_address;
					const std::uint64_t args[] = { 1, establisher_frame };

					THREAD_LOG_INFO("__C_specific_handler: running __finally at 0x{:X}", handler);

					win::call_with_attachment_checkpoint(st->calls, cpu, handler, args);
				}

				return win::exception_continue_search;
			}

			const auto pointers = guest_caller::scratch_base(cpu, sizeof(_EXCEPTION_POINTERS));

			_EXCEPTION_POINTERS ptrs{};
			ptrs.ExceptionRecord = reinterpret_cast<_EXCEPTION_RECORD*>(
				static_cast<std::uintptr_t>(exception_record.address()));
			ptrs.ContextRecord = reinterpret_cast<_CONTEXT*>(
				static_cast<std::uintptr_t>(context_record.address()));

			space.write_mem(pointers, ptrs);

			const auto found = win::search_scope_table(cpu, st->calls, {
				.image_base = dispatch.image_base,
				.handler_data = dispatch.handler_data,
				.control_pc = dispatch.control_pc,
				.establisher_frame = establisher_frame,
				.exception_pointers = pointers,
				.scratch = sizeof(_EXCEPTION_POINTERS),
				.first_scope = dispatch.scope_index,
			});

			if (found.disposition != win::exception_execute_handler)
				return found.disposition;

			// A language handler does not move the cpu; real Windows leaves through RtlUnwindEx.
			dispatcher_context.field(&win::dispatcher_context64::target_ip)
				.write(found.target_ip);
			dispatcher_context.field(&win::dispatcher_context64::establisher_frame)
				.write(found.establisher_frame);

			return win::exception_execute_handler;
		});
}
