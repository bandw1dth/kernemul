#include "nt_task_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../thread.hpp"
#include "../../thread_scheduler.hpp"
#include "../types.hpp"
#include "../../../emu/calling_conv.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <chrono>
#include <string_view>
#include <vector>

namespace
{

enum thread_information_class : std::uint32_t
{
	thread_basic_information       = 0,
	thread_times                   = 1,
	thread_am_i_last_thread        = 12,
	thread_quantum_reset           = 14,
	thread_hide_from_debugger      = 17,
	thread_is_terminated           = 20,
};

enum process_information_class : std::uint32_t
{
	process_basic_information   = 0,
	process_debug_port          = 7,
	process_wow64_information   = 26,
	process_image_file_name     = 27,
	process_debug_object_handle = 30,
	process_debug_flags         = 31,
	process_cookie              = 36,
	process_tls_information     = 35,
};

// Followed by one entry per thread, in the order the kernel keeps them rather than named by id.
#pragma pack(push, 8)
struct process_tls_information_t
{
	std::uint32_t flags;
	std::uint32_t operation;
	std::uint32_t thread_data_count;
	std::uint32_t tls_index;
	std::uint64_t reserved;
};

struct thread_tls_information_t
{
	std::uint64_t new_tls_data;
	std::uint64_t old_tls_data;
};
#pragma pack(pop)

constexpr std::uint32_t process_tls_replace_index = 0;
constexpr std::uint32_t process_tls_replace_vector = 1;

#pragma pack(push, 8)
struct thread_basic_information_t
{
	NTSTATUS      exit_status;
	std::uint32_t padding;
	addr_t        teb_base_address;
	addr_t        unique_process;
	addr_t        unique_thread;
	std::uint64_t affinity_mask;
	std::int32_t  priority;
	std::int32_t  base_priority;
};

struct process_basic_information_t
{
	NTSTATUS      exit_status;
	std::uint32_t padding;
	addr_t        peb_base_address;
	std::uint64_t affinity_mask;
	std::int32_t  base_priority;
	std::uint32_t padding2;
	addr_t        unique_process_id;
	addr_t        inherited_from_unique_process_id;
};

struct kernel_user_times_t
{
	std::int64_t create_time;
	std::int64_t exit_time;
	std::int64_t kernel_time;
	std::int64_t user_time;
};

struct processor_number_t
{
	std::uint16_t group;
	std::uint8_t  number;
	std::uint8_t  reserved;
};
#pragma pack(pop)

static_assert(sizeof(thread_basic_information_t) == 0x30);
static_assert(sizeof(process_basic_information_t) == 0x30);

// Only the calling thread and the one process are addressable.
constexpr std::uint64_t current_thread_handle = ~std::uint64_t{1};
constexpr std::uint64_t current_process_handle = ~std::uint64_t{0};

std::shared_ptr<win_thread> thread_from_handle(win_kernel_state& state, vcpu& cpu,
	const std::uint64_t handle)
{
	if (handle == current_thread_handle)
		return std::dynamic_pointer_cast<win_thread>(cpu.thread());

	const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

	if (!entry)
		return {};

	// Through the object rather than the process's thread list: a thread that has ended is off
	// that list, and a handle to it still answers -- what it exited with is asked for afterwards.
	if (const auto obj = state.objs.get_object<thread_object>(entry->body_addr))
		return std::dynamic_pointer_cast<win_thread>(obj->thread);

	return state.find_ethread(emu_object<_ETHREAD>(*cpu.curr_addr_space(), entry->body_addr));
}

// THREAD_CREATE_FLAGS_CREATE_SUSPENDED: the thread is made but nothing runs it until a resume.
constexpr std::uint32_t thread_create_suspended = 0x1;

// PS_ATTRIBUTE_LIST as ntdll builds it: a total length in bytes, this header included, followed
// by that many attributes. Only the two a thread create is told to fill in are handled.
constexpr std::uint64_t ps_attribute_client_id   = 0x10003;
constexpr std::uint64_t ps_attribute_teb_address = 0x10004;

#pragma pack(push, 1)
struct ps_attribute_t
{
	std::uint64_t attribute;
	std::uint64_t size;
	std::uint64_t value;         // a buffer to write into, for both attributes here
	std::uint64_t return_length; // where the length written goes, when the caller wants it
};
#pragma pack(pop)

static_assert(sizeof(ps_attribute_t) == 0x20);

// An attribute the caller passed but nothing here fills in is left alone rather than refused:
// the thread is made either way, and the caller reads back whatever it initialised.
void write_thread_attributes(vcpu& cpu, const addr_t list, const win_thread& t)
{
	if (!list)
		return;

	auto& space = *cpu.curr_addr_space();
	const auto total = space.read_mem<std::uint64_t>(list);

	if (total < sizeof(std::uint64_t) + sizeof(ps_attribute_t))
		return;

	const auto count = (total - sizeof(std::uint64_t)) / sizeof(ps_attribute_t);

	for (std::uint64_t i = 0; i < count; ++i)
	{
		const auto at = list + sizeof(std::uint64_t) + i * sizeof(ps_attribute_t);
		const auto attr = space.read_mem<ps_attribute_t>(at);

		if (!attr.value)
			continue;

		std::uint64_t written = 0;

		if (attr.attribute == ps_attribute_client_id && attr.size >= sizeof(_CLIENT_ID))
		{
			// The ids the ETHREAD already carries, so the two answers cannot disagree.
			space.write_mem(static_cast<addr_t>(attr.value), t.client_id().read());
			written = sizeof(_CLIENT_ID);
		}
		else if (attr.attribute == ps_attribute_teb_address
			&& attr.size >= sizeof(addr_t) && t.teb())
		{
			space.write_mem<addr_t>(static_cast<addr_t>(attr.value), t.teb().address());
			written = sizeof(addr_t);
		}

		if (written && attr.return_length)
			space.write_mem<std::uint64_t>(static_cast<addr_t>(attr.return_length), written);
	}
}

}

void modules::register_ntoskrnl_task_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto create_thread = [st](vcpu& cpu, emu_object<std::uint64_t> thread_handle,
		const std::uint32_t desired_access,
		[[maybe_unused]] emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint64_t process_handle, const addr_t start_routine, const addr_t argument,
		const std::uint32_t create_flags, [[maybe_unused]] const std::uint64_t zero_bits,
		const std::uint64_t stack_size, const std::uint64_t maximum_stack_size,
		const addr_t attribute_list) -> NTSTATUS
	{
		if (!thread_handle || !start_routine)
            return STATUS_INVALID_PARAMETER;
        if (st->ob_notify.in_callback(cpu.id())) st->fail_ob_notify(cpu, "nested handle operations are unsupported");
        if (desired_access & 0xf2000000u) return STATUS_NOT_SUPPORTED;
        try { thread_handle.write(thread_handle.read()); }
        catch (...) { return STATUS_ACCESS_VIOLATION; }

		if (process_handle != 0 && process_handle != current_process_handle)
		{
			THREAD_LOG_WARN("NtCreateThreadEx: process handle 0x{:X} is not this process",
				process_handle);
			return STATUS_INVALID_HANDLE;
		}

		// A user thread belongs to the process that asked for it: the start routine is a user va,
		// and only that process's address space maps it. A driver calling Zw gets what it always
		// got -- a system thread, in the address space its own code runs in.
		const auto caller = cpu.thread()
			? std::dynamic_pointer_cast<win_user_proc>(cpu.thread()->proc())
			: nullptr;

		std::shared_ptr<thread> t;

		if (caller)
		{
			auto* const emulator = st->emulator();

			if (!emulator)
				return STATUS_NOT_IMPLEMENTED;

			// The reserve is what a thread is given, since the stack is committed outright;
			// the committed size is the smaller of the two and only a hint.
			const auto stack = maximum_stack_size ? maximum_stack_size : stack_size;

			t = emulator->create_user_thread(cpu, *caller, start_routine, argument,
				static_cast<std::size_t>(stack), (create_flags & thread_create_suspended) != 0, false);
		}
		else
		{
			const std::uint64_t args[] = { argument };
			t = st->sys_proc->create_suspended_thread(cpu, start_routine, args);
            if (t && (create_flags & thread_create_suspended)) std::static_pointer_cast<win_thread>(t)->suspend();
		}

		if (!t)
		{
			THREAD_LOG_ERR("NtCreateThreadEx: no thread could be started at 0x{:X}",
				start_routine);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		const auto wt = std::static_pointer_cast<win_thread>(t);
		const auto ethread = wt->ethread().address();
        auto rollback = [&] { t->proc()->terminate_thread(t->id()); };

		if (!ethread)
		{
			THREAD_LOG_ERR("NtCreateThreadEx: tid={} has no ETHREAD", t->id());
			rollback();
			return STATUS_NO_MEMORY;
		}

        try
        {
            // Child remains unstarted until all output and OB delivery succeeds.
            write_thread_attributes(cpu, attribute_list, *wt);
            const auto attributes = object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0;
            const auto status = st->create_ob_handle(cpu, ethread, desired_access, attributes, thread_handle);
            if (status != STATUS_SUCCESS) { rollback(); return status; }
        }
        catch (...)
        {
            rollback();
            if (cpu.execution_failed() || (st->sys_proc->scheduler() && st->sys_proc->scheduler()->stopped())) throw;
            return STATUS_ACCESS_VIOLATION;
        }
        t->start();
        return STATUS_SUCCESS;
    };

	auto open_thread = [st](vcpu& cpu, emu_object<std::uint64_t> thread_handle,
		const std::uint32_t desired_access,
		[[maybe_unused]] emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		emu_object<_CLIENT_ID> client_id) -> NTSTATUS
	{
		if (!thread_handle)
			return STATUS_INVALID_PARAMETER;

		if (st->ob_notify.in_callback(cpu.id())) st->fail_ob_notify(cpu, "nested handle operations are unsupported");
		try { thread_handle.write(0); } catch (...) { return STATUS_ACCESS_VIOLATION; }

		if (!client_id)
		{
			THREAD_LOG_WARN("NtOpenThread: nothing here names a thread, so a client id is the "
				"only way to open one");
			return STATUS_INVALID_PARAMETER;
		}

		const auto tid = guest_va(client_id.field(&_CLIENT_ID::UniqueThread).read());
		const auto t = std::dynamic_pointer_cast<win_thread>(
			st->find_thread(static_cast<process::thread_id_type>(tid)));

		const auto ethread = t ? t->ethread().address() : 0;

		if (!ethread)
		{
			THREAD_LOG_WARN("NtOpenThread: no thread {}", tid);
			return STATUS_INVALID_CID;
		}

        const auto attributes = object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0;
        return st->create_ob_handle(cpu, ethread, desired_access, attributes, thread_handle);
	};

	auto terminate_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		const NTSTATUS exit_status) -> NTSTATUS
	{
		if (st->in_lifecycle_callback(cpu.id())) st->fail_thread_notify(cpu, "termination inside lifecycle callback");
		const auto self = cpu.thread();

		// A thread ending itself passes no handle at all -- RtlExitUserThread does -- and a
		// refusal there sends ntdll on to end the whole process instead.
		const auto t = thread_handle
			? thread_from_handle(*st, cpu, thread_handle)
			: std::dynamic_pointer_cast<win_thread>(self);

		if (!t)
		{
			THREAD_LOG_WARN("NtTerminateThread: handle 0x{:X} is not a thread", thread_handle);
			return STATUS_INVALID_HANDLE;
		}

		THREAD_LOG_INFO("NtTerminateThread(tid={}, status=0x{:X})", t->id(), exit_status);

		if (t == self)
		{
			st->finish_thread(cpu, exit_status);
			cpu.stop();
			return STATUS_SUCCESS;
		}

		// Remote user teardown cannot supply the required last-thread callback context.
		if (std::dynamic_pointer_cast<win_user_proc>(t->proc()) || st->process_notify.has_live())
			return STATUS_NOT_SUPPORTED;
		// The thread's own process: a user thread is not on the system process's lists.
		if (!st->thread_notify.without_live_notifications([&]
		{
			t->set_exit_status(exit_status);
			t->proc()->terminate_thread(t->id());
		}))
		{
			THREAD_LOG_ERR("NtTerminateThread: remote termination with live thread notifications is unsupported");
			return STATUS_NOT_SUPPORTED;
		}

		return STATUS_SUCCESS;
	};

	auto delay_execution = [st](vcpu& cpu, [[maybe_unused]] const bool alertable,
		emu_object<std::int64_t> delay_interval) -> NTSTATUS
	{
		if (!delay_interval)
			return STATUS_INVALID_PARAMETER;

		return st->delay_thread(cpu, delay_interval.read());
	};

	auto query_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t thread_information_class, const addr_t thread_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
			return STATUS_INVALID_HANDLE;

		auto& space = *cpu.curr_addr_space();

		switch (thread_information_class)
		{
		case thread_basic_information:
		{
			if (return_length)
				return_length.write(sizeof(thread_basic_information_t));

			if (length < sizeof(thread_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			thread_basic_information_t info{};
			info.exit_status = t->exit_status();
			info.teb_base_address = t->teb().address();
			info.unique_process = t->proc()->id();
			info.unique_thread = t->id();
			info.affinity_mask = 1;

			emu_object<thread_basic_information_t>(space, thread_information).write(info);

			THREAD_LOG_INFO("NtQueryInformationThread(tid={}, ThreadBasicInformation)", t->id());

			return STATUS_SUCCESS;
		}

		case thread_times:
		{
			if (return_length)
				return_length.write(sizeof(kernel_user_times_t));

			if (length < sizeof(kernel_user_times_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			// Nothing accounts cpu time, so the only honest figure is that none has been charged.
			kernel_user_times_t times{};
			times.create_time = static_cast<std::int64_t>(st->clock.sample().system_time);

			emu_object<kernel_user_times_t>(space, thread_information).write(times);

			THREAD_LOG_WARN("NtQueryInformationThread(tid={}, ThreadTimes): no cpu time is "
				"accounted here, so the kernel and user times are zero", t->id());

			return STATUS_SUCCESS;
		}

		case thread_is_terminated:
		{
			if (return_length)
				return_length.write(sizeof(std::uint32_t));

			if (length < sizeof(std::uint32_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			emu_object<std::uint32_t>(space, thread_information).write(0);

			THREAD_LOG_INFO("NtQueryInformationThread(tid={}, ThreadIsTerminated) -> false",
				t->id());

			return STATUS_SUCCESS;
		}

		case thread_am_i_last_thread:
		{
			if (return_length)
				return_length.write(sizeof(std::uint32_t));

			if (length < sizeof(std::uint32_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			std::size_t live = 0;

			if (const auto proc = std::dynamic_pointer_cast<windows_process>(t->proc()))
				proc->for_each_thread([&](win_thread& other)
				{
					if (!other.is_finished())
						++live;
				});

			const std::uint32_t last = live <= 1 ? 1 : 0;
			emu_object<std::uint32_t>(space, thread_information).write(last);

			THREAD_LOG_INFO("NtQueryInformationThread(tid={}, ThreadAmILastThread) -> {} "
				"({} running)", t->id(), last != 0, live);

			return STATUS_SUCCESS;
		}

		default:
			THREAD_LOG_WARN("NtQueryInformationThread: unhandled class {}",
				thread_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	auto query_process = [st](vcpu& cpu, const std::uint64_t process_handle,
		const std::uint32_t process_information_class, const addr_t process_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		if (process_handle != 0 && process_handle != current_process_handle)
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(process_handle);

			if (!entry)
				return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();

		switch (process_information_class)
		{
		case process_basic_information:
		{
			if (return_length)
				return_length.write(sizeof(process_basic_information_t));

			if (length < sizeof(process_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			process_basic_information_t info{};
			info.unique_process_id = st->sys_proc->id();
			info.affinity_mask = 1;
			info.base_priority = 8;

			emu_object<process_basic_information_t>(space, process_information).write(info);

			THREAD_LOG_INFO("NtQueryInformationProcess(ProcessBasicInformation) -> pid={}",
				st->sys_proc->id());

			return STATUS_SUCCESS;
		}

		case process_debug_port:
		case process_debug_object_handle:
		{
			if (return_length)
				return_length.write(sizeof(addr_t));

			if (length < sizeof(addr_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			emu_object<addr_t>(space, process_information).write(0);

			THREAD_LOG_INFO("NtQueryInformationProcess(class={}) -> no debugger",
				process_information_class);

			return process_information_class == process_debug_object_handle
				? STATUS_PORT_NOT_SET : STATUS_SUCCESS;
		}

		// Everything here is 64-bit, so nothing is running under wow64.
		case process_wow64_information:
		{
			if (return_length)
				return_length.write(sizeof(addr_t));

			if (length < sizeof(addr_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			emu_object<addr_t>(space, process_information).write(0);

			THREAD_LOG_INFO("NtQueryInformationProcess(ProcessWow64Information) -> not wow64");

			return STATUS_SUCCESS;
		}

		// What RtlEncodePointer xors with: any value will do, as long as it is the same every time.
		case process_cookie:
		{
			if (return_length)
				return_length.write(sizeof(std::uint32_t));

			if (length < sizeof(std::uint32_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			constexpr std::uint32_t cookie = 0x1EE7C0DE;
			emu_object<std::uint32_t>(space, process_information).write(cookie);

			THREAD_LOG_INFO("NtQueryInformationProcess(ProcessCookie) -> 0x{:X}", cookie);

			return STATUS_SUCCESS;
		}

		default:
			THREAD_LOG_WARN("NtQueryInformationProcess: unhandled class {}",
				process_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	// Nothing here acts on any of these, so they are recorded in the log rather than acted on.
	auto set_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t thread_information_class, const addr_t thread_information,
		const std::uint32_t length) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
			return STATUS_INVALID_HANDLE;

		switch (thread_information_class)
		{
		case thread_hide_from_debugger:
		case thread_quantum_reset:
			THREAD_LOG_INFO("NtSetInformationThread(tid={}, class={}): accepted, and nothing "
				"here acts on it", t->id(), thread_information_class);
			return STATUS_SUCCESS;

		default:
			THREAD_LOG_WARN("NtSetInformationThread(tid={}, class={}, buffer=0x{:X}/{}): "
				"unhandled class", t->id(), thread_information_class, thread_information, length);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	auto set_process = [](vcpu& cpu, const std::uint64_t process_handle,
		const std::uint32_t process_information_class, const addr_t process_information,
		const std::uint32_t length) -> NTSTATUS
	{
		switch (process_information_class)
		{
		case process_tls_information:
		{
			if (length < sizeof(process_tls_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			auto& space = *cpu.curr_addr_space();
			const auto header =
				emu_object<process_tls_information_t>(space, process_information).read();

			const bool by_index = header.operation == process_tls_replace_index;

			if (!by_index && header.operation != process_tls_replace_vector)
			{
				THREAD_LOG_WARN("NtSetInformationProcess(ProcessTlsInformation): "
					"operation {} is neither the vector swap nor the index swap",
					header.operation);
				return STATUS_INVALID_PARAMETER;
			}

			const auto entries = process_information + sizeof(process_tls_information_t);
			const auto room = (length - sizeof(process_tls_information_t))
				/ sizeof(thread_tls_information_t);

			if (header.thread_data_count > room)
				return STATUS_INFO_LENGTH_MISMATCH;

			const auto t = cpu.thread();
			const auto proc = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;

			if (!proc)
				return STATUS_INVALID_HANDLE;

			std::uint32_t index = 0;
			bool failed = false;

			proc->for_each_thread([&](win_thread& other)
			{
				if (failed)
					return;

				if (index >= header.thread_data_count)
					return;

				const auto& teb = other.teb();

				if (!teb)
					return;

				emu_object<thread_tls_information_t> entry(space,
					entries + index * sizeof(thread_tls_information_t));

				auto data = entry.read();
				auto slot = teb.field(&_TEB64::ThreadLocalStoragePointer);

				if (!by_index)
				{
					data.old_tls_data = slot.read();
					slot.write(data.new_tls_data);
				}
				else
				{
					// One slot of the vector rather than the vector itself: the loader hands
					// out a new index for a module's tls and every thread's vector has to
					// carry the block it names. A thread with no vector has no slot to put
					// it in, so it is reported as having held nothing.
					const auto vector = slot.read();
					const auto at = vector + header.tls_index * sizeof(std::uint64_t);

					data.old_tls_data = 0;

					if (vector)
					{
						try
						{
							data.old_tls_data = space.read_mem<std::uint64_t>(at);
							space.write_mem<std::uint64_t>(at, data.new_tls_data);
						}
						catch (const std::exception& e)
						{
							// The vector is the guest's own allocation and nothing here knows
							// how long it is, so an index past the end is only visible as this.
							THREAD_LOG_ERR("NtSetInformationProcess(ProcessTlsInformation): "
								"tls slot {} of thread {} is at 0x{:X}, which is not there: {}",
								header.tls_index, other.id(), at, e.what());

							failed = true;
							return;
						}
					}
				}

				entry.write(data);
				++index;
			});

			if (failed)
				return STATUS_ACCESS_VIOLATION;

			if (by_index)
				THREAD_LOG_INFO("NtSetInformationProcess(ProcessTlsInformation): put the new "
					"tls block in slot {} of {} of {} thread(s)", header.tls_index, index,
					header.thread_data_count);
			else
				THREAD_LOG_INFO("NtSetInformationProcess(ProcessTlsInformation): swapped the tls "
					"vector of {} of {} thread(s)", index, header.thread_data_count);

			return STATUS_SUCCESS;
		}

		case process_debug_flags:
			THREAD_LOG_INFO("NtSetInformationProcess(class={}): accepted, and nothing here "
				"acts on it", process_information_class);
			return STATUS_SUCCESS;

		default:
			THREAD_LOG_WARN("NtSetInformationProcess(handle=0x{:X}, class={}, buffer=0x{:X}/{}): "
				"unhandled class",
				process_handle, process_information_class, process_information, length);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	// The scheduler passes over a suspended thread, so suspending the calling one gives the cpu up.
	auto suspend_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		emu_object<std::uint32_t> previous_count) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
		{
			THREAD_LOG_WARN("NtSuspendThread: handle 0x{:X} is not a thread", thread_handle);
			return STATUS_INVALID_HANDLE;
		}

		if (st->in_lifecycle_callback(cpu.id()))
			st->fail_thread_notify(cpu, "NtSuspendThread: self-suspension inside a lifecycle callback is unsupported");

		const auto previous = t->suspend();

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtSuspendThread(tid={}) -> was suspended {} time(s)",
			t->id(), previous);

		if (t == cpu.thread())
			thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	auto resume_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		emu_object<std::uint32_t> previous_count) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
		{
			THREAD_LOG_WARN("NtResumeThread: handle 0x{:X} is not a thread", thread_handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto previous = t->resume();

		if (previous_count)
			previous_count.write(previous);

		if (!previous)
			THREAD_LOG_WARN("NtResumeThread: tid={} was not suspended", t->id());
		else
			THREAD_LOG_INFO("NtResumeThread(tid={}) -> was suspended {} time(s)",
				t->id(), previous);

		return STATUS_SUCCESS;
	};

	auto alert_thread = [st](vcpu& cpu, const std::uint64_t thread_id) -> NTSTATUS
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(
			st->find_thread(static_cast<process::thread_id_type>(thread_id)));

		if (!t)
		{
			THREAD_LOG_WARN("NtAlertThreadByThreadId: no thread {}", thread_id);
			return STATUS_INVALID_CID;
		}

		t->alert();

		THREAD_LOG_INFO("NtAlertThreadByThreadId(tid={})", t->id());

		return STATUS_SUCCESS;
	};

	auto wait_for_alert = [st](vcpu& cpu, const addr_t address,
		emu_object<std::int64_t> timeout) -> NTSTATUS
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t)
			return STATUS_INVALID_PARAMETER;

		if (t->take_alert())
		{
			THREAD_LOG_INFO("NtWaitForAlertByThreadId(0x{:X}): an alert was already in hand",
				address);
			return STATUS_SUCCESS;
		}

		const auto when = win::read_timeout(timeout, st->clock.sample());

		win_thread::wait_state wait{};
		wait.deadline = when.deadline;
		wait.timed = when.timed;
		wait.monotonic = when.monotonic;

		THREAD_LOG_INFO("NtWaitForAlertByThreadId(0x{:X}): parked {}",
			address, wait.timed ? "with a timeout" : "with no timeout");

		t->begin_wait(std::move(wait));
		thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	auto open_thread_token = [](vcpu&, const std::uint64_t thread_handle,
		const std::uint32_t desired_access, const bool open_as_self,
		emu_object<std::uint64_t> token_handle) -> NTSTATUS
	{
		if (token_handle)
			token_handle.write(0);

		THREAD_LOG_WARN("NtOpenThreadToken(handle=0x{:X}, access=0x{:X}, as_self={}): nothing "
			"here carries a token", thread_handle, desired_access, open_as_self);

		return STATUS_NO_TOKEN;
	};

	auto open_thread_token_ex = [open_thread_token](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t desired_access, const bool open_as_self,
		[[maybe_unused]] const std::uint32_t handle_attributes,
		emu_object<std::uint64_t> token_handle) -> NTSTATUS
	{
		return open_thread_token(cpu, thread_handle, desired_access, open_as_self,
			std::move(token_handle));
	};

	auto terminate_process = [st](vcpu& cpu, const std::uint64_t process_handle,
		const NTSTATUS exit_status) -> NTSTATUS
	{
		if (st->in_lifecycle_callback(cpu.id())) st->fail_thread_notify(cpu, "process termination inside lifecycle callback");
		if (process_handle != 0 && process_handle != current_process_handle)
		{
			THREAD_LOG_WARN("NtTerminateProcess: handle 0x{:X} is not this process",
				process_handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto self = cpu.thread();

		// The threads of whoever asked, which for a user process is not the system process.
		const auto proc = self
			? std::dynamic_pointer_cast<windows_process>(self->proc())
			: nullptr;
		auto& target = proc ? *proc : *st->sys_proc;

		// Collected first: terminate_thread takes the lock for_each_thread holds.
		std::vector<process::thread_id_type> ids;

		target.for_each_thread([&](win_thread& t)
		{
			if ((!self || t.id() != self->id()) && !t.is_finished())
				ids.push_back(t.id());
		});

		THREAD_LOG_INFO("NtTerminateProcess(status=0x{:X}): ending {} other thread(s)",
			exit_status, ids.size());

		if (!ids.empty() && st->process_notify.has_live()) return STATUS_NOT_SUPPORTED;

		if (!ids.empty() && !st->thread_notify.without_live_notifications([&]
		{
			target.for_each_thread([exit_status](win_thread& t) { t.set_exit_status(exit_status); });
			for (const auto id : ids) target.terminate_thread(id);
		}))
		{
			THREAD_LOG_ERR("NtTerminateProcess: remote thread termination with live thread notifications is unsupported");
			return STATUS_NOT_SUPPORTED;
		}

		if (self)
			st->finish_thread(cpu, exit_status);

		cpu.stop();

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "GetCurrentProcessorNumber", [](vcpu& cpu) -> std::uint32_t
	{
		const auto id = static_cast<std::uint32_t>(cpu.id());
		THREAD_LOG_INFO("NtGetCurrentProcessorNumber() -> {}", id);
		return id;
	});

	auto current_processor_ex = [](vcpu& cpu,
		emu_object<processor_number_t> processor_number) -> std::uint32_t
	{
		const auto id = static_cast<std::uint32_t>(cpu.id());

		if (processor_number)
		{
			processor_number_t number{};
			number.number = static_cast<std::uint8_t>(id);
			processor_number.write(number);
		}

		THREAD_LOG_INFO("NtGetCurrentProcessorNumberEx() -> group 0, {}", id);

		return id;
	};

	state.redirect_ntzw(mod, "GetCurrentProcessorNumberEx", current_processor_ex);

	state.redirect_ntzw(mod, "YieldExecution", [](vcpu& cpu) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtYieldExecution()");
		thread_scheduler::yield_current(cpu);
		return STATUS_SUCCESS;
	});

	state.redirect_ntzw(mod, "CreateThreadEx", create_thread);
	state.redirect_ntzw(mod, "OpenThread", open_thread);
	state.redirect_ntzw(mod, "TerminateThread", terminate_thread);
	state.redirect_ntzw(mod, "DelayExecution", delay_execution);
	state.redirect_ntzw(mod, "QueryInformationThread", query_thread);
	state.redirect_ntzw(mod, "QueryInformationProcess", query_process);
	state.redirect_ntzw(mod, "SetInformationThread", set_thread);
	state.redirect_ntzw(mod, "SetInformationProcess", set_process);
	state.redirect_ntzw(mod, "SuspendThread", suspend_thread);
	state.redirect_ntzw(mod, "ResumeThread", resume_thread);
	// Nothing queues a user APC, so there is never anything pending.
	state.redirect_ntzw(mod, "TestAlert", [](vcpu&) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtTestAlert(): nothing queues an alert here");
		return STATUS_SUCCESS;
	});

	state.redirect_ntzw(mod, "AlertThreadByThreadId", alert_thread);
	state.redirect_ntzw(mod, "WaitForAlertByThreadId", wait_for_alert);
	state.redirect_ntzw(mod, "OpenThreadToken", open_thread_token);
	state.redirect_ntzw(mod, "OpenThreadTokenEx", open_thread_token_ex);
	state.redirect_ntzw(mod, "TerminateProcess", terminate_process);
}
