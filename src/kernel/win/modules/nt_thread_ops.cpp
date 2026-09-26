#include "nt_thread_ops.hpp"
#include "../thread.hpp"
#include "../../thread_scheduler.hpp"
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
	state.redirect(mod, kernel_thread_startup, [st](vcpu& cpu)
	{
		const auto t = cpu.thread();

		if (t)
		{
			// A system thread that returns rather than calling PsTerminateSystemThread exits
			// with whatever it returned -- and for a driver's entry thread that is DriverEntry's
			// status, which is otherwise never seen.
			const auto status = static_cast<NTSTATUS>(
				cpu.emu()->call_conv()->read_ret(cpu));

			THREAD_LOG_INFO("thread {} returned, status=0x{:X}", t->id(),
				static_cast<std::uint32_t>(status));

			st->finish_thread(cpu, status);
		}

		cpu.stop();
	});

	state.redirect(mod, "PsCreateSystemThread",
		[st, sys_proc](vcpu& cpu, emu_object<std::uint64_t> thread_handle_out,
			std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes, std::uint64_t process_handle,
			emu_object<CLIENT_ID> client_id_out, addr_t start_routine, addr_t start_context) -> NTSTATUS
		{
			THREAD_LOG_INFO("PsCreateSystemThread(handle_out=0x{:X}, start=0x{:X}, ctx=0x{:X})",
				thread_handle_out.address(), start_routine, start_context);

			if (st->process_notify.in_callback(cpu.id())) st->fail_thread_notify(cpu, "thread creation inside process callback");
			if (!thread_handle_out || !start_routine) return STATUS_INVALID_PARAMETER;
            if (st->ob_notify.in_callback(cpu.id())) st->fail_ob_notify(cpu, "nested handle operations are unsupported");
            if (process_handle && process_handle != static_cast<std::uint64_t>(-1)) return STATUS_NOT_SUPPORTED;
            if (desired_access & 0xf2000000u) return STATUS_NOT_SUPPORTED;
			// Validate both complete output ranges before allocating a child. Guest writes
			// can still fault later; rollback below keeps that child off the runnable queue.
			try
			{
				thread_handle_out.write(thread_handle_out.read());
				if (client_id_out) client_id_out.write(client_id_out.read());
			}
			catch (...) { return STATUS_ACCESS_VIOLATION; }

			std::shared_ptr<win_thread> t;
			std::uint64_t handle = 0;
			auto rollback = [&]
			{
				if (handle) sys_proc->handle_table().close_handle(handle);
				if (t) sys_proc->terminate_thread(t->id());
			};
			try
			{
				t = std::static_pointer_cast<win_thread>(sys_proc->create_suspended_thread(cpu, start_routine));
				if (!t || !t->ethread())
				{
					rollback();
					return STATUS_NO_MEMORY;
				}
				cpu.emu()->call_conv()->set_arg(cpu, *t, 0, start_context);
				if (client_id_out) client_id_out.write(t->client_id().read());
                const auto attributes = object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0;
                const auto status = st->create_ob_handle(cpu, t->ethread().address(), desired_access,
                    attributes, thread_handle_out);
                if (status != STATUS_SUCCESS) { rollback(); return status; }
                handle = thread_handle_out.read();
                if (!handle)
				{
					rollback();
					return STATUS_NO_MEMORY;
				}

			}
			catch (const std::bad_alloc&) { rollback(); return STATUS_INSUFFICIENT_RESOURCES; }
			catch (...) { rollback(); if (cpu.execution_failed() || (sys_proc->scheduler() && sys_proc->scheduler()->stopped())) throw; return STATUS_ACCESS_VIOLATION; }

			try
			{
				st->notify_thread(cpu, *t, true);
			}
			catch (...)
			{
				rollback();
				st->fail_thread_notify(cpu, "create callback failed before child publication");
			}
			t->notification_origin = win_thread::notify_origin::live_guest;
			t->start();

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
