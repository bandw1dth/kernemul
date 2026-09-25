#include "nt_thread_ops.hpp"
#include "../thread.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <chrono>

void modules::register_ntoskrnl_thread_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	auto* sys_proc = state.sys_proc.get();

	// Nothing of this stub is executed; threads are given it as their return address.
	state.redirect(mod, kernel_thread_startup, [](vcpu& cpu)
	{
		const auto t = cpu.thread();

		if (t)
		{
			// A system thread that returns rather than calling PsTerminateSystemThread exits
			// with whatever it returned -- and for a driver's entry thread that is DriverEntry's
			// status, which is otherwise never seen.
			const auto status = static_cast<NTSTATUS>(
				cpu.emu()->call_conv()->read_ret(cpu));

			if (const auto wt = std::dynamic_pointer_cast<win_thread>(t))
				wt->set_exit_status(status);

			THREAD_LOG_INFO("thread {} returned, status=0x{:X}", t->id(),
				static_cast<std::uint32_t>(status));

			t->finish();
		}

		cpu.stop();
	});

	state.redirect(mod, "PsCreateSystemThread",
		[sys_proc](vcpu& cpu, emu_object<std::uint64_t> thread_handle_out,
			[[maybe_unused]] std::uint32_t desired_access,
			[[maybe_unused]] emu_object<void> object_attributes, [[maybe_unused]] std::uint64_t process_handle,
			emu_object<CLIENT_ID> client_id_out, addr_t start_routine, addr_t start_context) -> NTSTATUS
		{
			THREAD_LOG_INFO("PsCreateSystemThread(handle_out=0x{:X}, start=0x{:X}, ctx=0x{:X})",
				thread_handle_out.address(), start_routine, start_context);

			// The context goes in before the thread starts: a started thread is another cpu's.
			auto t = sys_proc->create_suspended_thread(cpu, start_routine);
			cpu.emu()->call_conv()->set_arg(cpu, *t, 0, start_context);
			t->start();

			const auto ethread = std::static_pointer_cast<win_thread>(t)->ethread().address();

			if (!ethread)
			{
				THREAD_LOG_ERR("PsCreateSystemThread: tid={} has no ETHREAD", t->id());
				return STATUS_NO_MEMORY;
			}

			const auto handle = sys_proc->handle_table().create_handle(ethread, THREAD_ALL_ACCESS);

			if (thread_handle_out)
				thread_handle_out.write(handle);

			if (client_id_out)
			{
				CLIENT_ID cid{};
				cid.UniqueProcess = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(sys_proc->id()));
				cid.UniqueThread = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(t->id()));
				client_id_out.write(cid);
			}

			THREAD_LOG_INFO("PsCreateSystemThread: created tid={}, handle=0x{:X}", t->id(), handle);
			return STATUS_SUCCESS;
		});

	// Nothing here queues APCs, so an alertable wait always runs its course.
	state.redirect(mod, "KeDelayExecutionThread",
		[st](vcpu& cpu, [[maybe_unused]] const std::uint8_t wait_mode, [[maybe_unused]] const std::uint8_t alertable,
			emu_object<std::int64_t> interval) -> NTSTATUS
		{
			if (!interval)
			{
				THREAD_LOG_ERR("KeDelayExecutionThread: null interval");
				return STATUS_INVALID_PARAMETER;
			}

			return st->delay_thread(cpu, interval.read());
		});

	// Nothing here schedules by priority, so moving it changes only what the guest reads back.
	state.redirect(mod, "KeSetBasePriorityThread",
		[](vcpu& cpu, emu_object<_KTHREAD> thread, const std::int32_t increment) -> std::int32_t
		{
			if (!thread)
				return 0;

			const auto process = guest_va(thread.field(&_KTHREAD::Process).read());

			const auto process_base = process
				? emu_object<_KPROCESS>(*cpu.curr_addr_space(), process)
					.field(&_KPROCESS::BasePriority).read()
				: 0;

			const auto previous = thread.field(&_KTHREAD::BasePriority).read() - process_base;
			const auto updated = static_cast<char>(process_base + increment);

			thread.field(&_KTHREAD::BasePriority).write(updated);
			thread.field(&_KTHREAD::Priority).write(updated);

			THREAD_LOG_INFO("KeSetBasePriorityThread(thread=0x{:X}, increment={}) -> {}",
				thread.address(), increment, previous);

			return previous;
		});

	state.redirect(mod, "KeSetActualBasePriorityThread",
		[](vcpu&, emu_object<_KTHREAD> thread, const std::int32_t base_priority) -> std::int32_t
		{
			if (!thread)
				return 0;

			const auto previous = thread.field(&_KTHREAD::BasePriority).read();
			const auto updated = static_cast<char>(base_priority);

			thread.field(&_KTHREAD::BasePriority).write(updated);
			thread.field(&_KTHREAD::Priority).write(updated);

			THREAD_LOG_INFO("KeSetActualBasePriorityThread(thread=0x{:X}, base_priority={}) -> {}",
				thread.address(), base_priority, previous);

			return previous;
		});

	// Nothing here builds an irp, so the guest reads back only what the guest put there.
	state.redirect(mod, "IoGetTopLevelIrp", [](vcpu& cpu) -> addr_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
		{
			THREAD_LOG_WARN("IoGetTopLevelIrp: no current thread");
			return 0;
		}

		const auto irp = t->ethread().field(&_ETHREAD::TopLevelIrp).read();

		THREAD_LOG_INFO("IoGetTopLevelIrp() -> 0x{:X}", irp);

		return irp;
	});

	state.redirect(mod, "IoSetTopLevelIrp", [](vcpu& cpu, const addr_t irp)
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
		{
			THREAD_LOG_ERR("IoSetTopLevelIrp: no current thread to set 0x{:X} on", irp);
			return;
		}

		t->ethread().field(&_ETHREAD::TopLevelIrp).write(irp);

		THREAD_LOG_INFO("IoSetTopLevelIrp(0x{:X})", irp);
	});
}
