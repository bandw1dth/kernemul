#include "nt_dispatch_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <array>
#include <limits>
#include <mutex>
#include <string_view>
#include <unordered_map>

namespace
{

constexpr std::uint32_t notification_event = 0;

constexpr std::uint32_t event_basic_information = 0;

#pragma pack(push, 4)
struct event_basic_information_t
{
	std::uint32_t event_type;
	std::int32_t  event_state;
};
#pragma pack(pop)

template <typename T>
std::uint64_t create_dispatcher(win_kernel_state& state, const win::dispatcher_type type,
	const std::int32_t signal_state, const std::uint32_t access, std::string name)
{
	const T zeroed{};
	const auto addr = state.objs.create_object(0, &zeroed, sizeof(T),
		std::make_shared<dispatcher_host>(type, std::move(name)), prot_rw | prot_supervisor);

	if (!addr)
		return 0;

	emu_object<T> obj(*state.emulator()->emu().default_addr_space(), addr);
	win::init_dispatcher(obj, type, signal_state);

	return state.sys_proc->handle_table().create_handle(addr, access);
}

struct resolved
{
	addr_t address = 0;
	std::shared_ptr<dispatcher_host> host;
};

resolved resolve(win_kernel_state& state, const std::uint64_t handle,
	const win::dispatcher_type expected, const std::string_view who)
{
	const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

	if (!entry)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, handle);
		return {};
	}

	auto host = state.objs.get_object<dispatcher_host>(entry->body_addr);

	if (!host)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} is not a dispatcher object", who, handle);
		return {};
	}

	const bool event_pair = (expected == win::event_notification_object
			|| expected == win::event_synchronization_object)
		&& (host->type == win::event_notification_object
			|| host->type == win::event_synchronization_object);

	if (host->type != expected && !event_pair)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} names a type {} object, not {}",
			who, handle, static_cast<int>(host->type), static_cast<int>(expected));
		return {};
	}

	return { entry->body_addr, std::move(host) };
}

constexpr std::size_t keyed_event_body_size = 0x40;

struct keyed_event_host final : win_object
{
	struct gate
	{
		addr_t arrivals = 0;
		addr_t releases = 0;
	};

	gate gate_for(win_kernel_state& state, const addr_t key)
	{
		std::scoped_lock lock(mtx_);

		auto& found = gates_[key];

		if (!found.arrivals)
			found = { make_semaphore(state), make_semaphore(state) };

		return found;
	}

private:
	static addr_t make_semaphore(win_kernel_state& state)
	{
		const _KSEMAPHORE zeroed{};
		const auto addr = state.objs.create_object(0, &zeroed, sizeof(zeroed),
			{}, prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		const emu_object<_KSEMAPHORE> obj(
			*state.emulator()->emu().default_addr_space(), addr);

		win::init_dispatcher(obj, win::semaphore_object, 0);
		obj.field(&_KSEMAPHORE::Limit).write(std::numeric_limits<std::int32_t>::max());

		return addr;
	}

	std::mutex mtx_;
	std::unordered_map<addr_t, gate> gates_;
};

std::string attribute_name(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return narrow_wstring(win::read_unicode_string(name));
}

}

// The body behind each handle is the real KEVENT, KSEMAPHORE or KMUTANT.
void modules::register_ntoskrnl_dispatch_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto create_event = [st](vcpu& cpu, emu_object<std::uint64_t> event_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint32_t event_type, const bool initial_state) -> NTSTATUS
	{
		if (!event_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = attribute_name(cpu, object_attributes);
		const auto type = event_type == notification_event
			? win::event_notification_object : win::event_synchronization_object;

		const auto handle = create_dispatcher<_KEVENT>(*st, type, initial_state ? 1 : 0,
			desired_access, name);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		event_handle.write(handle);

		THREAD_LOG_INFO("NtCreateEvent('{}', {}, state={}) -> handle=0x{:X}",
			name, event_type == notification_event ? "notification" : "synchronization",
			initial_state, handle);

		return STATUS_SUCCESS;
	};

	// Nothing puts an event in a namespace, so there is never one to open by name.
	state.redirect_ntzw(mod, "OpenEvent",
		[](vcpu& cpu, emu_object<std::uint64_t> event_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (event_handle)
				event_handle.write(0);

			THREAD_LOG_WARN("NtOpenEvent('{}', access=0x{:X}): nothing here names an event",
				attribute_name(cpu, object_attributes), desired_access);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		});

	auto set_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		emu_object<std::int32_t> previous_state) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object, "NtSetEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 1);

		if (previous_state)
			previous_state.write(previous);

		THREAD_LOG_INFO("NtSetEvent(0x{:X}, '{}') -> was {}",
			event_handle, found.host->name, previous);

		st->sys_proc->wake_waiters(*cpu.curr_addr_space(), event.address());

		return STATUS_SUCCESS;
	};

	auto reset_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		emu_object<std::int32_t> previous_state) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtResetEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 0);

		if (previous_state)
			previous_state.write(previous);

		THREAD_LOG_INFO("NtResetEvent(0x{:X}, '{}') -> was {}",
			event_handle, found.host->name, previous);

		return STATUS_SUCCESS;
	};

	auto clear_event = [st](vcpu& cpu, const std::uint64_t event_handle) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtClearEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		win::set_signal_state(event, 0);

		THREAD_LOG_INFO("NtClearEvent(0x{:X}, '{}')", event_handle, found.host->name);

		return STATUS_SUCCESS;
	};

	auto query_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		const std::uint32_t event_information_class, const addr_t event_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtQueryEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		if (event_information_class != event_basic_information)
		{
			THREAD_LOG_WARN("NtQueryEvent: unhandled class {}", event_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		if (return_length)
			return_length.write(sizeof(event_basic_information_t));

		if (length < sizeof(event_basic_information_t))
			return STATUS_INFO_LENGTH_MISMATCH;

		auto& space = *cpu.curr_addr_space();
		const emu_object<_KEVENT> event(space, found.address);

		event_basic_information_t info{};
		info.event_type = found.host->type == win::event_notification_object ? 0 : 1;
		info.event_state = win::signal_state(event);

		emu_object<event_basic_information_t>(space, event_information).write(info);

		THREAD_LOG_INFO("NtQueryEvent(0x{:X}, '{}') -> type={}, state={}",
			event_handle, found.host->name, info.event_type, info.event_state);

		return STATUS_SUCCESS;
	};

	auto create_semaphore = [st](vcpu& cpu, emu_object<std::uint64_t> semaphore_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::int32_t initial_count, const std::int32_t maximum_count) -> NTSTATUS
	{
		if (!semaphore_handle)
			return STATUS_INVALID_PARAMETER;

		if (maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count)
			return STATUS_INVALID_PARAMETER;

		const auto name = attribute_name(cpu, object_attributes);
		const auto handle = create_dispatcher<_KSEMAPHORE>(*st, win::semaphore_object,
			initial_count, desired_access, name);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		// The limit lives past the dispatcher header, and KeReleaseSemaphore checks against it.
		const auto entry = st->sys_proc->handle_table().lookup_handle(handle);
		emu_object<_KSEMAPHORE>(*cpu.curr_addr_space(), entry->body_addr)
			.field(&_KSEMAPHORE::Limit).write(maximum_count);

		semaphore_handle.write(handle);

		THREAD_LOG_INFO("NtCreateSemaphore('{}', initial={}, maximum={}) -> handle=0x{:X}",
			name, initial_count, maximum_count, handle);

		return STATUS_SUCCESS;
	};

	auto release_semaphore = [st](vcpu& cpu, const std::uint64_t semaphore_handle,
		const std::int32_t release_count, emu_object<std::int32_t> previous_count) -> NTSTATUS
	{
		const auto found = resolve(*st, semaphore_handle, win::semaphore_object,
			"NtReleaseSemaphore");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		if (release_count <= 0)
			return STATUS_INVALID_PARAMETER;

		emu_object<_KSEMAPHORE> semaphore(*cpu.curr_addr_space(), found.address);

		const auto previous = win::signal_state(semaphore);
		const auto limit = semaphore.field(&_KSEMAPHORE::Limit).read();

		if (previous + release_count > limit)
		{
			THREAD_LOG_WARN("NtReleaseSemaphore(0x{:X}, '{}'): {} + {} is past the limit of {}",
				semaphore_handle, found.host->name, previous, release_count, limit);

			return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
		}

		win::set_signal_state(semaphore, previous + release_count);

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtReleaseSemaphore(0x{:X}, '{}', release={}) -> was {}",
			semaphore_handle, found.host->name, release_count, previous);

		st->sys_proc->wake_waiters(*cpu.curr_addr_space(), semaphore.address());

		return STATUS_SUCCESS;
	};

	// A mutant is signalled when nobody holds it: unowned starts at one, owned at zero.
	auto create_mutant = [st](vcpu& cpu, emu_object<std::uint64_t> mutant_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const bool initial_owner) -> NTSTATUS
	{
		if (!mutant_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = attribute_name(cpu, object_attributes);
		const auto handle = create_dispatcher<_KMUTANT>(*st, win::mutant_object,
			initial_owner ? 0 : 1, desired_access, name);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (initial_owner)
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(handle);
			const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
			const auto ethread = t ? t->ethread().address() : 0;

			emu_object<_KMUTANT>(*cpu.curr_addr_space(), entry->body_addr)
				.field(&_KMUTANT::OwnerThread)
				.write(guest_ptr<_KTHREAD>(ethread));
		}

		mutant_handle.write(handle);

		THREAD_LOG_INFO("NtCreateMutant('{}', initial_owner={}) -> handle=0x{:X}",
			name, initial_owner, handle);

		return STATUS_SUCCESS;
	};

	auto release_mutant = [st](vcpu& cpu, const std::uint64_t mutant_handle,
		emu_object<std::int32_t> previous_count) -> NTSTATUS
	{
		const auto found = resolve(*st, mutant_handle, win::mutant_object, "NtReleaseMutant");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KMUTANT> mutant(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(mutant);

		if (previous > 0)
		{
			THREAD_LOG_WARN("NtReleaseMutant(0x{:X}, '{}'): nobody holds it",
				mutant_handle, found.host->name);

			return STATUS_MUTANT_NOT_OWNED;
		}

		win::set_signal_state(mutant, previous + 1);
		mutant.field(&_KMUTANT::OwnerThread).write(nullptr);

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtReleaseMutant(0x{:X}, '{}') -> was {}",
			mutant_handle, found.host->name, previous);

		st->sys_proc->wake_waiters(*cpu.curr_addr_space(), mutant.address());

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "CreateEvent", create_event);
	state.redirect_ntzw(mod, "SetEvent", set_event);
	state.redirect_ntzw(mod, "ResetEvent", reset_event);
	state.redirect_ntzw(mod, "ClearEvent", clear_event);
	state.redirect_ntzw(mod, "QueryEvent", query_event);
	state.redirect_ntzw(mod, "CreateSemaphore", create_semaphore);
	state.redirect_ntzw(mod, "ReleaseSemaphore", release_semaphore);
	state.redirect_ntzw(mod, "CreateMutant", create_mutant);
	state.redirect_ntzw(mod, "ReleaseMutant", release_mutant);

	auto default_keyed_event = std::make_shared<keyed_event_host>();

	auto keyed_event_from_handle = [st, default_keyed_event](const std::uint64_t handle)
		-> std::shared_ptr<keyed_event_host>
	{
		if (!handle)
			return default_keyed_event;

		return st->sys_proc->handle_table().get_object<keyed_event_host>(handle);
	};

	auto create_keyed_event = [st](vcpu& cpu, emu_object<std::uint64_t> keyed_event_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint32_t flags) -> NTSTATUS
	{
		if (!keyed_event_handle)
			return STATUS_INVALID_PARAMETER;

		if (flags)
			return STATUS_INVALID_PARAMETER_4;

		const auto name = attribute_name(cpu, object_attributes);

		// Opaque: a keyed event is reached only by handle.
		const std::array<std::uint8_t, keyed_event_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(),
			std::make_shared<keyed_event_host>(), prot_rw | prot_supervisor);

		if (!addr)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (!name.empty())
			st->objs.register_named_object(name, addr);

		const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
		keyed_event_handle.write(handle);

		THREAD_LOG_INFO("NtCreateKeyedEvent('{}') -> handle=0x{:X}", name, handle);

		return STATUS_SUCCESS;
	};

	auto rendezvous = [st, keyed_event_from_handle](vcpu& cpu, const std::uint64_t handle,
		const addr_t key, const bool alertable, const emu_object<std::int64_t>& timeout,
		const bool releasing) -> NTSTATUS
	{
		const auto host = keyed_event_from_handle(handle);

		if (!host)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not a keyed event",
				releasing ? "NtReleaseKeyedEvent" : "NtWaitForKeyedEvent", handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t)
			return STATUS_INVALID_PARAMETER;

		const auto gate = host->gate_for(*st, key);

		if (!gate.arrivals || !gate.releases)
			return STATUS_INSUFFICIENT_RESOURCES;

		auto& space = *cpu.curr_addr_space();

		const auto post = releasing ? gate.releases : gate.arrivals;
		const auto wait_on = releasing ? gate.arrivals : gate.releases;

		win::set_state_at(space, post, win::state_at(space, post) + 1);
		st->sys_proc->wake_waiters(space, post);

		if (alertable)
			THREAD_LOG_WARN("{}: nothing delivers an APC, so an alertable wait runs its course",
				releasing ? "NtReleaseKeyedEvent" : "NtWaitForKeyedEvent");

		const auto when = win::read_timeout(timeout, st->clock.sample());

		win_thread::wait_state wait{};
		wait.objects = { wait_on };
		wait.deadline = when.deadline;
		wait.timed = when.timed;
		wait.monotonic = when.monotonic;

		THREAD_LOG_INFO("{}(handle=0x{:X}, key=0x{:X}): posted 0x{:X}, waiting on 0x{:X}",
			releasing ? "NtReleaseKeyedEvent" : "NtWaitForKeyedEvent",
			handle, key, post, wait_on);

		t->begin_wait(std::move(wait));
		t->try_satisfy(space);

		thread_scheduler::yield_current(cpu);

		// Overwritten by the scheduler once it decides the wait.
		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "CreateKeyedEvent", create_keyed_event);

	state.redirect_ntzw(mod, "WaitForKeyedEvent",
		[rendezvous](vcpu& cpu, const std::uint64_t handle, const addr_t key,
			const bool alertable, emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			return rendezvous(cpu, handle, key, alertable, timeout, false);
		});

	state.redirect_ntzw(mod, "ReleaseKeyedEvent",
		[rendezvous](vcpu& cpu, const std::uint64_t handle, const addr_t key,
			const bool alertable, emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			return rendezvous(cpu, handle, key, alertable, timeout, true);
		});
}
