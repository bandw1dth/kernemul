#include "nt_process_ops.hpp"
#include "../win_kernel.hpp"
#include "../eprocess.hpp"
#include "../process.hpp"
#include "../rundown.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <memory>
#include <set>
#include <string_view>

namespace
{

struct notify_routines
{
	std::set<addr_t> process;
};

// What NT's fixed-size tables hold, and what a driver past the limit is told.
constexpr std::size_t max_process_notify_routines = 64;

NTSTATUS add_notify(std::set<addr_t>& routines, const std::size_t limit,
	const std::string_view who, const addr_t routine)
{
	if (!routine)
		return STATUS_INVALID_PARAMETER;

	if (routines.contains(routine))
	{
		THREAD_LOG_WARN("{}: 0x{:X} is already registered", who, routine);
		return STATUS_INVALID_PARAMETER;
	}

	if (routines.size() >= limit)
	{
		THREAD_LOG_ERR("{}: no room for 0x{:X}, {} already registered", who, routine, limit);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	routines.insert(routine);

	THREAD_LOG_WARN("{}(0x{:X}): registered, but nothing here will call it", who, routine);

	return STATUS_SUCCESS;
}

NTSTATUS remove_notify(std::set<addr_t>& routines, const std::string_view who, const addr_t routine)
{
	if (!routines.erase(routine))
	{
		THREAD_LOG_WARN("{}: 0x{:X} was not registered", who, routine);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	THREAD_LOG_INFO("{}(0x{:X}): removed", who, routine);

	return STATUS_SUCCESS;
}

emu_object<_EPROCESS> process_or_current(win_kernel_state& state, vcpu& cpu,
	const emu_object<_EPROCESS>& process)
{
	if (process)
		return process;

	const auto t = cpu.thread();
	auto proc = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;

	return (proc ? proc : state.sys_proc)->eprocess();
}

}

// Every query here reads the EPROCESS the caller passed, not anything kept beside it.
void modules::register_ntoskrnl_process_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	auto notify = std::make_shared<notify_routines>();

	// The image name is fifteen bytes inside the EPROCESS, so the pointer is into the caller's own.
	state.redirect(mod, "PsGetProcessImageFileName",
		[](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			if (!process)
			{
				THREAD_LOG_WARN("PsGetProcessImageFileName: null process");
				return 0;
			}

			const auto name = process.field(&_EPROCESS::ImageFileName);

			THREAD_LOG_INFO("PsGetProcessImageFileName(0x{:X}) -> 0x{:X}",
				process.address(), name.address());

			return name.address();
		});

	state.redirect(mod, "PsGetProcessPeb",
		[](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			if (!process)
				return 0;

			const auto peb = guest_va(process.field(&_EPROCESS::Peb).read());

			THREAD_LOG_INFO("PsGetProcessPeb(0x{:X}) -> 0x{:X}", process.address(), peb);

			return peb;
		});

	state.redirect(mod, "PsGetProcessSectionBaseAddress",
		[](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			if (!process)
				return 0;

			const auto base = guest_va(process.field(&_EPROCESS::SectionBaseAddress).read());

			THREAD_LOG_INFO("PsGetProcessSectionBaseAddress(0x{:X}) -> 0x{:X}",
				process.address(), base);

			return base;
		});

	// A session id is eight bytes into the session space, which the PDB carries no layout for.
	state.redirect(mod, "PsGetProcessSessionId",
		[](vcpu& cpu, emu_object<_EPROCESS> process) -> std::uint32_t
		{
			if (!process)
				return 0;

			constexpr std::size_t session_id_off = 8;

			const auto session = guest_va(process.field(&_EPROCESS::Session).read());

			const auto id = (!session || win::has_flag(process, win::system_process))
				? 0
				: cpu.curr_addr_space()->read_mem<std::uint32_t>(session + session_id_off);

			THREAD_LOG_INFO("PsGetProcessSessionId(0x{:X}) -> {}", process.address(), id);

			return id;
		});

	state.redirect(mod, "PsGetProcessWow64Process",
		[](vcpu& cpu, emu_object<_EPROCESS> process) -> addr_t
		{
			if (!process)
				return 0;

			const auto wow64 = guest_va(process.field(&_EPROCESS::WoW64Process).read());
			const auto peb32 = wow64 ? cpu.curr_addr_space()->read_mem<addr_t>(wow64) : 0;

			THREAD_LOG_INFO("PsGetProcessWow64Process(0x{:X}) -> 0x{:X}",
				process.address(), peb32);

			return peb32;
		});

	state.redirect(mod, "PsGetProcessExitProcessCalled",
		[](vcpu&, emu_object<_EPROCESS> process) -> bool
		{
			if (!process)
				return false;

			const bool exiting = win::has_flag(process, win::process_exiting);

			THREAD_LOG_INFO("PsGetProcessExitProcessCalled(0x{:X}) -> {}",
				process.address(), exiting);

			return exiting;
		});

	state.redirect(mod, "PsIsProtectedProcess",
		[](vcpu&, emu_object<_EPROCESS> process) -> bool
		{
			if (!process)
				return false;

			const bool protected_ = win::protection_type(process) != PsProtectedTypeNone;

			THREAD_LOG_INFO("PsIsProtectedProcess(0x{:X}) -> {}", process.address(), protected_);

			return protected_;
		});

	state.redirect(mod, "PsIsProtectedProcessLight",
		[](vcpu&, emu_object<_EPROCESS> process) -> bool
		{
			if (!process)
				return false;

			const bool light = win::protection_type(process) == PsProtectedTypeProtectedLight;

			THREAD_LOG_INFO("PsIsProtectedProcessLight(0x{:X}) -> {}", process.address(), light);

			return light;
		});

	state.redirect(mod, "PsLookupProcessByProcessId",
		[st](vcpu&, const std::uint64_t process_id, emu_object<addr_t> process_out) -> NTSTATUS
		{
			const auto proc = std::dynamic_pointer_cast<windows_process>(
				st->find_process(static_cast<process::id_type>(process_id)));

			const auto eprocess = proc ? proc->eprocess().address() : 0;

			if (!eprocess)
			{
				THREAD_LOG_WARN("PsLookupProcessByProcessId: no process {}", process_id);
				return STATUS_INVALID_CID;
			}

			st->objs.reference_object(eprocess);

			if (process_out)
				process_out.write(eprocess);

			THREAD_LOG_INFO("PsLookupProcessByProcessId({}) -> 0x{:X}", process_id, eprocess);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "PsLookupThreadByThreadId",
		[st](vcpu&, const std::uint64_t thread_id, emu_object<addr_t> thread_out) -> NTSTATUS
		{
			const auto t = std::dynamic_pointer_cast<win_thread>(
				st->find_thread(static_cast<process::thread_id_type>(thread_id)));

			const auto ethread = t ? t->ethread().address() : 0;

			if (!ethread)
			{
				THREAD_LOG_WARN("PsLookupThreadByThreadId: no thread {}", thread_id);
				return STATUS_INVALID_CID;
			}

			st->objs.reference_object(ethread);

			if (thread_out)
				thread_out.write(ethread);

			THREAD_LOG_INFO("PsLookupThreadByThreadId({}) -> 0x{:X}", thread_id, ethread);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "PsTerminateSystemThread",
		[st](vcpu& cpu, const NTSTATUS exit_status) -> NTSTATUS
		{
			const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

			if (!t || !t->is_system_thread())
			{
				THREAD_LOG_ERR("PsTerminateSystemThread: not a system thread");
				return STATUS_INVALID_PARAMETER;
			}

			THREAD_LOG_INFO("PsTerminateSystemThread(0x{:X}): tid={} ends here",
				exit_status, t->id());

			st->finish_thread(cpu, exit_status);
			cpu.stop();

			return exit_status;
		});

	state.redirect(mod, "PsAcquireProcessExitSynchronization",
		[st](vcpu& cpu, emu_object<_EPROCESS> process) -> NTSTATUS
		{
			const auto target = process_or_current(*st, cpu, process);

			if (!target)
				return STATUS_INVALID_PARAMETER;

			const auto rundown = target.field(&_EPROCESS::RundownProtect);

			if (!win::acquire_rundown(rundown))
			{
				THREAD_LOG_WARN("PsAcquireProcessExitSynchronization: 0x{:X} is running down",
					target.address());
				return STATUS_PROCESS_IS_TERMINATING;
			}

			THREAD_LOG_INFO("PsAcquireProcessExitSynchronization(0x{:X}): {} references",
				target.address(), win::rundown_references(rundown));

			return STATUS_SUCCESS;
		});

	// On x86-64 the linker folds this onto ObDereferenceProcessHandleTable; on ARM64 it does not.
	auto release_exit_sync = [st](vcpu& cpu, emu_object<_EPROCESS> process)
	{
		const auto target = process_or_current(*st, cpu, process);

		if (!target)
			return;

		const auto rundown = target.field(&_EPROCESS::RundownProtect);

		if (!win::release_rundown(rundown))
		{
			THREAD_LOG_ERR("PsReleaseProcessExitSynchronization: 0x{:X} holds no reference",
				target.address());
			return;
		}

		THREAD_LOG_INFO("PsReleaseProcessExitSynchronization(0x{:X}): {} references left",
			target.address(), win::rundown_references(rundown));
	};

	state.redirect(mod, "PsReleaseProcessExitSynchronization", release_exit_sync);
	state.redirect(mod, "ObDereferenceProcessHandleTable", release_exit_sync);

	// Nothing here builds a token, so this is the shape of the answer without an answer to give.
	state.redirect(mod, "PsReferencePrimaryToken",
		[st](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			if (!process)
				return 0;

			// An EX_FAST_REF keeps a cached reference count in the low bits of the pointer.
			constexpr std::uint64_t fast_ref_count_mask = 0xF;

			const auto token = process.field(&_EPROCESS::Token)
				.field(&_EX_FAST_REF::Value).read() & ~fast_ref_count_mask;

			if (!token)
			{
				THREAD_LOG_WARN("PsReferencePrimaryToken: 0x{:X} has no primary token",
					process.address());
				return 0;
			}

			st->objs.reference_object(token);

			THREAD_LOG_INFO("PsReferencePrimaryToken(0x{:X}) -> 0x{:X}",
				process.address(), token);

			return token;
		});

	// Folded onto IoDeleteController on both architectures.
	state.redirect(mod, "PsDereferencePrimaryToken",
		[st](vcpu&, const addr_t primary_token)
		{
			THREAD_LOG_INFO("PsDereferencePrimaryToken(0x{:X})", primary_token);

			if (primary_token)
				st->objs.dereference_object(primary_token);
		});

	// Nothing here sections an image in, and the out parameter is left untouched on failure.
	state.redirect(mod, "PsReferenceProcessFilePointer",
		[](vcpu&, emu_object<_EPROCESS> process,
			[[maybe_unused]] emu_object<addr_t> file_object_out) -> NTSTATUS
		{
			if (!process)
				return STATUS_INVALID_PARAMETER;

			const auto section = guest_va(process.field(&_EPROCESS::SectionObject).read());

			if (!section)
				THREAD_LOG_WARN("PsReferenceProcessFilePointer: 0x{:X} has no section object",
					process.address());
			else
				THREAD_LOG_ERR("PsReferenceProcessFilePointer: nothing maps a file object onto "
					"section 0x{:X}", section);

			return STATUS_UNSUCCESSFUL;
		});

	// The tables are kept so a remove and a duplicate answer correctly; no notification comes.
	state.redirect(mod, "PsSetCreateProcessNotifyRoutine",
		[notify](vcpu&, const addr_t notify_routine, const std::uint8_t remove) -> NTSTATUS
		{
			return remove
				? remove_notify(notify->process, "PsSetCreateProcessNotifyRoutine", notify_routine)
				: add_notify(notify->process, max_process_notify_routines,
					"PsSetCreateProcessNotifyRoutine", notify_routine);
		});

	state.redirect(mod, "PsSetCreateProcessNotifyRoutineEx",
		[notify](vcpu&, const addr_t notify_routine, const std::uint8_t remove) -> NTSTATUS
		{
			return remove
				? remove_notify(notify->process, "PsSetCreateProcessNotifyRoutineEx", notify_routine)
				: add_notify(notify->process, max_process_notify_routines,
					"PsSetCreateProcessNotifyRoutineEx", notify_routine);
		});

	state.redirect(mod, "PsSetCreateThreadNotifyRoutine",
		[st](vcpu&, const addr_t notify_routine) -> NTSTATUS
		{
			try
			{
				return st->thread_notify.add(notify_routine) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
			}
			catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
		});

	state.redirect(mod, "PsRemoveCreateThreadNotifyRoutine",
		[st](vcpu& cpu, const addr_t notify_routine) -> NTSTATUS
		{
			const auto result = st->thread_notify.remove(notify_routine, cpu.id(), st->in_lifecycle_callback(cpu.id()));
			if (result == win::thread_notify_registry::remove_result::callback_deadlock)
				st->fail_thread_notify(cpu, "PsRemoveCreateThreadNotifyRoutine: self-removal or callback rundown deadlock");
			return result == win::thread_notify_registry::remove_result::removed
				? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND;
		});

	auto add_image_notify = [st](vcpu&, const addr_t routine) -> NTSTATUS
	{
		try { return st->image_notify.add(routine) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES; }
		catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
	};
	state.redirect(mod, "PsSetLoadImageNotifyRoutine", add_image_notify);
	if (mod.find_export("PsSetLoadImageNotifyRoutineEx"))
	{
		state.redirect(mod, "PsSetLoadImageNotifyRoutineEx",
			[add_image_notify](vcpu& cpu, const addr_t routine, const std::uint32_t flags) -> NTSTATUS
			{
				if (flags & ~1u) return STATUS_INVALID_PARAMETER_2;
				// Conflicting-architecture subscriptions require per-registration filtering.
				if (flags) return STATUS_NOT_SUPPORTED;
				return add_image_notify(cpu, routine);
			});
	}
	state.redirect(mod, "PsRemoveLoadImageNotifyRoutine",
		[st](vcpu& cpu, const addr_t routine) -> NTSTATUS
		{
			const auto result = st->image_notify.remove(routine, cpu.id(), st->in_lifecycle_callback(cpu.id()));
			if (result == win::lifecycle_notify_registry::remove_result::callback_deadlock)
				st->fail_thread_notify(cpu, "PsRemoveLoadImageNotifyRoutine: callback rundown deadlock");
			return result == win::lifecycle_notify_registry::remove_result::removed
				? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND;
		});

	// There is one address space here, so a driver reading the target's memory gets its own.
	auto apc_state_of = [](vcpu& cpu) -> emu_object<_KAPC_STATE>
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
			return {};

		return t->ethread().field(&_ETHREAD::Tcb).field(&_KTHREAD::ApcState);
	};

	state.redirect(mod, "KeStackAttachProcess",
		[apc_state_of](vcpu& cpu, emu_object<_KPROCESS> process,
			emu_object<_KAPC_STATE> apc_state)
		{
			const auto current = apc_state_of(cpu);

			if (!current)
			{
				THREAD_LOG_ERR("KeStackAttachProcess: nothing is running, so nothing can attach");
				return;
			}

			const auto previous = guest_va(current.field(&_KAPC_STATE::Process).read());

			if (apc_state)
			{
				_KAPC_STATE saved{};
				saved.Process = reinterpret_cast<_KPROCESS*>(
					static_cast<std::uintptr_t>(previous));
				apc_state.write(saved);

				const auto head = apc_state.address() + offsetof(_KAPC_STATE, ApcListHead);
				apc_state.field(&_KAPC_STATE::ApcListHead)
					.write(guest_links(head, head), 0);
				apc_state.field(&_KAPC_STATE::ApcListHead)
					.write(guest_links(head + sizeof(_LIST_ENTRY), head + sizeof(_LIST_ENTRY)), 1);
			}

			current.field(&_KAPC_STATE::Process).write(guest_ptr<_KPROCESS>(process.address()));

			if (process.address() != previous)
				THREAD_LOG_WARN("KeStackAttachProcess(0x{:X}): there is one address space here, "
					"so the attach moves the thread's apc state and nothing else",
					process.address());
			else
				THREAD_LOG_INFO("KeStackAttachProcess(0x{:X}): already in that process",
					process.address());
		});

	state.redirect(mod, "KeUnstackDetachProcess",
		[apc_state_of](vcpu& cpu, emu_object<_KAPC_STATE> apc_state)
		{
			const auto current = apc_state_of(cpu);

			if (!current)
			{
				THREAD_LOG_ERR("KeUnstackDetachProcess: nothing is running");
				return;
			}

			if (!apc_state)
			{
				THREAD_LOG_ERR("KeUnstackDetachProcess: null apc state, so there is nothing to "
					"go back to");
				return;
			}

			const auto previous = apc_state.field(&_KAPC_STATE::Process).read();

			current.field(&_KAPC_STATE::Process).write(previous);

			THREAD_LOG_INFO("KeUnstackDetachProcess: back in 0x{:X}", guest_va(previous));
		});
}
