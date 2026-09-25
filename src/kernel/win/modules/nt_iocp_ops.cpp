#include "nt_iocp_ops.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <deque>
#include <mutex>
#include <string_view>

namespace
{

#pragma pack(push, 8)
struct file_io_completion_information_t
{
	addr_t        key_context;
	addr_t        apc_context;
	NTSTATUS      status;
	std::uint32_t padding;
	std::uint64_t information;
};
#pragma pack(pop)

static_assert(sizeof(file_io_completion_information_t) == 0x20);

struct completion_packet
{
	addr_t key_context = 0;
	addr_t apc_context = 0;
	NTSTATUS status = STATUS_SUCCESS;
	std::uint64_t information = 0;
};

struct io_completion_host final : win_object
{
	std::string name;
	addr_t body = 0;

	void push(addr_space& space, const completion_packet& packet)
	{
		{
			std::scoped_lock lock(mtx_);
			packets_.push_back(packet);
		}

		resync(space);
	}

	std::optional<completion_packet> pop(addr_space& space)
	{
		std::optional<completion_packet> packet;

		{
			std::scoped_lock lock(mtx_);

			if (!packets_.empty())
			{
				packet = packets_.front();
				packets_.pop_front();
			}
		}

		resync(space);

		return packet;
	}

	[[nodiscard]] std::size_t depth()
	{
		std::scoped_lock lock(mtx_);
		return packets_.size();
	}

private:
	void resync(addr_space& space)
	{
		std::scoped_lock lock(mtx_);

		if (!body)
			return;

		const emu_object<_KQUEUE> queue(space, body);

		win::set_signal_state(queue, static_cast<std::int32_t>(packets_.size()));
		queue.field(&_KQUEUE::CurrentCount).write(static_cast<std::uint32_t>(packets_.size()));
	}

	std::recursive_mutex mtx_;
	std::deque<completion_packet> packets_;
};

struct wait_packet_host final : win_object
{
	std::shared_ptr<io_completion_host> port;
	completion_packet packet;
	bool associated = false;
};

struct worker_factory_host final : win_object
{
	std::shared_ptr<io_completion_host> port;
	addr_t start_routine = 0;
	addr_t start_parameter = 0;
	std::uint32_t maximum_thread_count = 0;
	bool shut_down = false;
};

constexpr std::uint32_t worker_factory_basic_information = 7;

#pragma pack(push, 8)
struct worker_factory_basic_information_t
{
	std::int64_t  timeout;
	std::int64_t  retry_timeout;
	std::int64_t  idle_timeout;
	std::uint8_t  paused;
	std::uint8_t  timer_set;
	std::uint8_t  queued_to_ex_worker;
	std::uint8_t  may_create;
	std::uint8_t  created_during_scan;
	std::uint8_t  padding[3];
	std::uint32_t binding_count;
	std::uint32_t thread_minimum;
	std::uint32_t thread_maximum;
	std::uint32_t total_worker_count;
	std::uint32_t ready_worker_count;
	std::uint32_t waiting_worker_count;
	std::uint32_t releasable_worker_count;
	addr_t        start_routine;
	addr_t        start_parameter;
	addr_t        process_id;
	std::uint64_t stack_reserve;
	std::uint64_t stack_commit;
	NTSTATUS      last_thread_creation_status;
	std::uint32_t padding2;
};
#pragma pack(pop)

// The four bytes before start_routine are an alignment hole, so the size pins the tail down.
static_assert(sizeof(worker_factory_basic_information_t) == 0x70);

std::string attribute_name(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return narrow_wstring(win::read_unicode_string(name));
}

}

// What is missing is blocking inside the remove, so an empty port answers STATUS_TIMEOUT.
void modules::register_ntoskrnl_iocp_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto port_from_handle = [st](const std::uint64_t handle)
	{
		return st->sys_proc->handle_table().get_object<io_completion_host>(handle);
	};

	state.redirect_ntzw(mod, "CreateIoCompletion",
		[st](vcpu& cpu, emu_object<std::uint64_t> handle_out, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const std::uint32_t concurrent_threads) -> NTSTATUS
		{
			if (!handle_out)
				return STATUS_INVALID_PARAMETER;

			auto host = std::make_shared<io_completion_host>();
			host->name = attribute_name(cpu, object_attributes);

			const _KQUEUE zeroed{};
			const auto addr = st->objs.create_object(0, &zeroed, sizeof(zeroed),
				host, prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			auto& space = *cpu.curr_addr_space();
			const emu_object<_KQUEUE> queue(space, addr);

			win::init_dispatcher(queue, win::queue_object, 0);
			queue.field(&_KQUEUE::MaximumCount).write(concurrent_threads
				? concurrent_threads : 1);

			const auto head = addr + offsetof(_KQUEUE, EntryListHead);
			queue.field(&_KQUEUE::EntryListHead).write(guest_links(head, head));

			const auto thread_head = addr + offsetof(_KQUEUE, ThreadListHead);
			queue.field(&_KQUEUE::ThreadListHead).write(guest_links(thread_head, thread_head));

			host->body = addr;

			if (!host->name.empty())
				st->objs.register_named_object(host->name, addr);

			const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
			handle_out.write(handle);

			THREAD_LOG_INFO("NtCreateIoCompletion('{}', threads={}) -> handle=0x{:X}",
				host->name, concurrent_threads, handle);

			return STATUS_SUCCESS;
		});

	auto set_completion = [st, port_from_handle](vcpu& cpu, const std::uint64_t handle,
		const addr_t key_context, const addr_t apc_context, const NTSTATUS status,
		const std::uint64_t information) -> NTSTATUS
	{
		const auto port = port_from_handle(handle);

		if (!port)
		{
			THREAD_LOG_WARN("NtSetIoCompletion: handle 0x{:X} is not a completion port", handle);
			return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();

		port->push(space, { key_context, apc_context, status, information });

		THREAD_LOG_INFO("NtSetIoCompletion(0x{:X}, key=0x{:X}, apc=0x{:X}, status=0x{:X}, "
			"information=0x{:X}): depth now {}",
			handle, key_context, apc_context, status, information, port->depth());

		st->sys_proc->wake_waiters(space, port->body);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "SetIoCompletion", set_completion);

	state.redirect_ntzw(mod, "SetIoCompletionEx",
		[st, set_completion](vcpu& cpu, const std::uint64_t handle,
			const std::uint64_t packet_handle, const addr_t key_context,
			const addr_t apc_context, const NTSTATUS status,
			const std::uint64_t information) -> NTSTATUS
		{
			if (!st->sys_proc->handle_table().get_object<wait_packet_host>(packet_handle))
			{
				THREAD_LOG_WARN("NtSetIoCompletionEx: handle 0x{:X} is not a wait completion "
					"packet", packet_handle);
				return STATUS_INVALID_HANDLE;
			}

			return set_completion(cpu, handle, key_context, apc_context, status, information);
		});

	state.redirect_ntzw(mod, "RemoveIoCompletion",
		[st, port_from_handle](vcpu& cpu, const std::uint64_t handle,
			emu_object<addr_t> key_context, emu_object<addr_t> apc_context,
			emu_object<_IO_STATUS_BLOCK> io_status_block,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			const auto port = port_from_handle(handle);

			if (!port)
			{
				THREAD_LOG_WARN("NtRemoveIoCompletion: handle 0x{:X} is not a completion port",
					handle);
				return STATUS_INVALID_HANDLE;
			}

			const auto packet = port->pop(*cpu.curr_addr_space());

			if (!packet)
			{
				THREAD_LOG_WARN("NtRemoveIoCompletion(0x{:X}): the port is empty, and nothing "
					"here blocks on one -> STATUS_TIMEOUT (timeout={})",
					handle, win::read_timeout(timeout, st->clock.sample()).timed ? "given" : "none");

				return STATUS_TIMEOUT;
			}

			if (key_context)
				key_context.write(packet->key_context);

			if (apc_context)
				apc_context.write(packet->apc_context);

			if (io_status_block)
			{
				_IO_STATUS_BLOCK block{};
				block.Status = static_cast<std::int32_t>(packet->status);
				block.Information = packet->information;
				io_status_block.write(block);
			}

			THREAD_LOG_INFO("NtRemoveIoCompletion(0x{:X}) -> key=0x{:X}, apc=0x{:X}, "
				"status=0x{:X}, depth now {}",
				handle, packet->key_context, packet->apc_context, packet->status, port->depth());

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "RemoveIoCompletionEx",
		[st, port_from_handle](vcpu& cpu, const std::uint64_t handle,
			emu_object<file_io_completion_information_t> entries, const std::uint32_t count,
			emu_object<std::uint32_t> removed_out, emu_object<std::int64_t> timeout,
			const bool alertable) -> NTSTATUS
		{
			const auto port = port_from_handle(handle);

			if (!port)
			{
				THREAD_LOG_WARN("NtRemoveIoCompletionEx: handle 0x{:X} is not a completion port",
					handle);
				return STATUS_INVALID_HANDLE;
			}

			if (!entries || !count)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			std::uint32_t removed = 0;

			while (removed < count)
			{
				const auto packet = port->pop(space);

				if (!packet)
					break;

				file_io_completion_information_t info{};
				info.key_context = packet->key_context;
				info.apc_context = packet->apc_context;
				info.status = packet->status;
				info.information = packet->information;

				entries.write(info, removed);
				++removed;
			}

			if (removed_out)
				removed_out.write(removed);

			if (!removed)
			{
				THREAD_LOG_WARN("NtRemoveIoCompletionEx(0x{:X}, alertable={}): the port is empty, "
					"and nothing here blocks on one -> STATUS_TIMEOUT (timeout={})",
					handle, alertable, win::read_timeout(timeout, st->clock.sample()).timed ? "given" : "none");

				return STATUS_TIMEOUT;
			}

			THREAD_LOG_INFO("NtRemoveIoCompletionEx(0x{:X}) -> {} of {} packet(s), depth now {}",
				handle, removed, count, port->depth());

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "CreateWaitCompletionPacket",
		[st](vcpu& cpu, emu_object<std::uint64_t> handle_out,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!handle_out)
				return STATUS_INVALID_PARAMETER;

			const std::uint64_t body = 0;
			const auto addr = st->objs.create_object(0, &body, sizeof(body),
				std::make_shared<wait_packet_host>(), prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
			handle_out.write(handle);

			THREAD_LOG_INFO("NtCreateWaitCompletionPacket('{}') -> handle=0x{:X}",
				attribute_name(cpu, object_attributes), handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AssociateWaitCompletionPacket",
		[st, port_from_handle](vcpu& cpu, const std::uint64_t packet_handle,
			const std::uint64_t port_handle, const std::uint64_t target_handle,
			const addr_t key_context, const addr_t apc_context, const NTSTATUS status,
			const std::uint64_t information, emu_object<std::uint8_t> already_signalled) -> NTSTATUS
		{
			const auto packet =
				st->sys_proc->handle_table().get_object<wait_packet_host>(packet_handle);
			const auto port = port_from_handle(port_handle);

			if (!packet || !port)
			{
				THREAD_LOG_WARN("NtAssociateWaitCompletionPacket: packet 0x{:X} or port 0x{:X} "
					"is not open", packet_handle, port_handle);
				return STATUS_INVALID_HANDLE;
			}

			const auto target = st->sys_proc->handle_table().lookup_handle(target_handle);

			if (!target)
			{
				THREAD_LOG_WARN("NtAssociateWaitCompletionPacket: target handle 0x{:X} is not "
					"open", target_handle);
				return STATUS_INVALID_HANDLE;
			}

			auto& space = *cpu.curr_addr_space();

			packet->port = port;
			packet->packet = { key_context, apc_context, status, information };
			packet->associated = true;

			const bool signalled = win::is_signalled(space, target->body_addr, 0);

			if (signalled)
			{
				port->push(space, packet->packet);
				packet->associated = false;
				st->sys_proc->wake_waiters(space, port->body);

				THREAD_LOG_INFO("NtAssociateWaitCompletionPacket: 0x{:X} is signalled, so the "
					"packet is posted now", target->body_addr);
			}
			else
			{
				THREAD_LOG_WARN("NtAssociateWaitCompletionPacket: 0x{:X} is not signalled, and "
					"nothing here watches an object, so the packet never fires",
					target->body_addr);
			}

			if (already_signalled)
				already_signalled.write(signalled ? 1 : 0);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "CancelWaitCompletionPacket",
		[st](vcpu&, const std::uint64_t packet_handle,
			const bool remove_signalled_packet) -> NTSTATUS
		{
			const auto packet =
				st->sys_proc->handle_table().get_object<wait_packet_host>(packet_handle);

			if (!packet)
			{
				THREAD_LOG_WARN("NtCancelWaitCompletionPacket: handle 0x{:X} is not a wait "
					"completion packet", packet_handle);
				return STATUS_INVALID_HANDLE;
			}

			const bool was_associated = packet->associated;

			packet->associated = false;
			packet->port.reset();

			THREAD_LOG_INFO("NtCancelWaitCompletionPacket(0x{:X}, remove_signalled={}): {}",
				packet_handle, remove_signalled_packet,
				was_associated ? "cancelled" : "was not associated");

			return STATUS_SUCCESS;
		});

	// Nothing here runs pool threads, so the start routine is never entered.
	state.redirect_ntzw(mod, "CreateWorkerFactory",
		[st, port_from_handle](vcpu& cpu, emu_object<std::uint64_t> handle_out,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const std::uint64_t completion_port_handle,
			[[maybe_unused]] const std::uint64_t worker_process_handle,
			const addr_t start_routine, const addr_t start_parameter,
			const std::uint32_t maximum_thread_count,
			[[maybe_unused]] const std::uint64_t stack_reserve,
			[[maybe_unused]] const std::uint64_t stack_commit) -> NTSTATUS
		{
			if (!handle_out || !start_routine)
				return STATUS_INVALID_PARAMETER;

			auto port = port_from_handle(completion_port_handle);

			if (!port)
			{
				THREAD_LOG_WARN("NtCreateWorkerFactory: handle 0x{:X} is not a completion port",
					completion_port_handle);
				return STATUS_INVALID_HANDLE;
			}

			auto host = std::make_shared<worker_factory_host>();
			host->port = std::move(port);
			host->start_routine = start_routine;
			host->start_parameter = start_parameter;
			host->maximum_thread_count = maximum_thread_count;

			const std::uint64_t body = 0;
			const auto addr = st->objs.create_object(0, &body, sizeof(body), host,
				prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
			handle_out.write(handle);

			THREAD_LOG_WARN("NtCreateWorkerFactory('{}', start=0x{:X}, parameter=0x{:X}, "
				"threads={}) -> handle=0x{:X}: nothing here runs pool threads, so the start "
				"routine is never entered",
				attribute_name(cpu, object_attributes), start_routine, start_parameter,
				maximum_thread_count, handle);

			return STATUS_SUCCESS;
		});

	auto factory_from_handle = [st](const std::uint64_t handle)
	{
		return st->sys_proc->handle_table().get_object<worker_factory_host>(handle);
	};

	state.redirect_ntzw(mod, "SetInformationWorkerFactory",
		[factory_from_handle](vcpu&, const std::uint64_t handle,
			const std::uint32_t information_class, const addr_t buffer,
			const std::uint32_t length) -> NTSTATUS
		{
			const auto factory = factory_from_handle(handle);

			if (!factory)
				return STATUS_INVALID_HANDLE;

			THREAD_LOG_INFO("NtSetInformationWorkerFactory(0x{:X}, class={}, buffer=0x{:X}/{}): "
				"accepted, and nothing here acts on it",
				handle, information_class, buffer, length);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "QueryInformationWorkerFactory",
		[factory_from_handle](vcpu& cpu, const std::uint64_t handle,
			const std::uint32_t information_class, const addr_t buffer,
			const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto factory = factory_from_handle(handle);

			if (!factory)
				return STATUS_INVALID_HANDLE;

			if (information_class != worker_factory_basic_information)
			{
				THREAD_LOG_WARN("NtQueryInformationWorkerFactory: unhandled class {}",
					information_class);
				return STATUS_INVALID_INFO_CLASS;
			}

			if (return_length)
				return_length.write(sizeof(worker_factory_basic_information_t));

			if (length < sizeof(worker_factory_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			worker_factory_basic_information_t info{};
			info.thread_maximum = factory->maximum_thread_count;
			info.start_routine = factory->start_routine;
			info.start_parameter = factory->start_parameter;

			emu_object<worker_factory_basic_information_t>(*cpu.curr_addr_space(), buffer)
				.write(info);

			THREAD_LOG_INFO("NtQueryInformationWorkerFactory(0x{:X}, Basic) -> start=0x{:X}, "
				"maximum={}, no workers", handle, factory->start_routine,
				factory->maximum_thread_count);

			return STATUS_SUCCESS;
		});

	auto worker_call = [factory_from_handle](const std::uint64_t handle,
		const std::string_view who) -> NTSTATUS
	{
		const auto factory = factory_from_handle(handle);

		if (!factory)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not a worker factory", who, handle);
			return STATUS_INVALID_HANDLE;
		}

		if (factory->shut_down)
		{
			THREAD_LOG_INFO("{}(0x{:X}): the factory is shut down", who, handle);
			return STATUS_TOO_LATE;
		}

		THREAD_LOG_WARN("{}(0x{:X}): nothing here runs pool threads, so there is no worker to "
			"account for", who, handle);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "WorkerFactoryWorkerReady",
		[worker_call](vcpu&, const std::uint64_t handle) -> NTSTATUS
		{
			return worker_call(handle, "NtWorkerFactoryWorkerReady");
		});

	state.redirect_ntzw(mod, "ReleaseWorkerFactoryWorker",
		[worker_call](vcpu&, const std::uint64_t handle) -> NTSTATUS
		{
			return worker_call(handle, "NtReleaseWorkerFactoryWorker");
		});

	state.redirect_ntzw(mod, "ShutdownWorkerFactory",
		[factory_from_handle](vcpu&, const std::uint64_t handle,
			emu_object<std::int32_t> pending_worker_count) -> NTSTATUS
		{
			const auto factory = factory_from_handle(handle);

			if (!factory)
				return STATUS_INVALID_HANDLE;

			factory->shut_down = true;

			if (pending_worker_count)
				pending_worker_count.write(0);

			THREAD_LOG_INFO("NtShutdownWorkerFactory(0x{:X}): no workers to wait for", handle);

			return STATUS_SUCCESS;
		});
}
