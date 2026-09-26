#include "nt_lpc_ops.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr std::size_t alpc_port_body_size = 0x20;

// Bounds what a caller claiming an enormous TotalLength can make this allocate.
constexpr std::size_t maximum_message_length = 0x10000;

constexpr std::uint32_t default_maximum_message_length = 0x148;
constexpr std::uint64_t maximum_port_view_size = 0x100000;

struct alpc_port_host final : win_object
{
	std::string name;
	addr_t body = 0;
	bool is_server = false;
	std::weak_ptr<alpc_port_host> peer;

	void post(std::vector<std::uint8_t> message)
	{
		std::scoped_lock lock(mtx_);
		messages_.push_back(std::move(message));
	}

	std::optional<std::vector<std::uint8_t>> take()
	{
		std::scoped_lock lock(mtx_);

		if (messages_.empty())
			return {};

		auto message = std::move(messages_.front());
		messages_.pop_front();

		return message;
	}

	[[nodiscard]] std::size_t queued()
	{
		std::scoped_lock lock(mtx_);
		return messages_.size();
	}

private:
	std::mutex mtx_;
	std::deque<std::vector<std::uint8_t>> messages_;
};

std::vector<std::uint8_t> read_message(vcpu& cpu, const emu_object<_PORT_MESSAGE>& message)
{
	auto& space = *cpu.curr_addr_space();

	const auto header = message.read();
	const auto total = static_cast<std::size_t>(header.u1.s1.TotalLength);
	const auto size = std::clamp(total, sizeof(_PORT_MESSAGE), maximum_message_length);

	std::vector<std::uint8_t> bytes(size);
	space.read_mem(message.address(), bytes.data(), bytes.size());

	auto* stamped = reinterpret_cast<_PORT_MESSAGE*>(bytes.data());
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

	stamped->ClientId.UniqueProcess = reinterpret_cast<void*>(
		static_cast<std::uintptr_t>(t ? t->proc()->id() : 0));
	stamped->ClientId.UniqueThread = reinterpret_cast<void*>(
		static_cast<std::uintptr_t>(t ? t->id() : 0));

	return bytes;
}

void clear_connection_information(vcpu& cpu, const addr_t information,
	const emu_object<std::uint32_t>& information_length)
{
	if (!information || !information_length)
		return;

	const auto length = information_length.read();

	if (!length || length > maximum_message_length)
		return;

	const std::vector<std::uint8_t> zeros(length, 0);
	cpu.curr_addr_space()->write_mem(information, zeros.data(), zeros.size());
}

// These names do not resolve RootDirectory-relative object paths.
std::string attribute_name(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return narrow_wstring(win::read_unicode_string(name));
}

}

// A port this guest did not create belongs to a process that is not running.
void modules::register_ntoskrnl_lpc_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto port_from_handle = [st](vcpu& cpu, const std::uint64_t handle)
	{
		return st->get_handle_object<alpc_port_host>(cpu, handle);
	};

	auto create_port_object = [st](vcpu& cpu, std::shared_ptr<alpc_port_host> host,
		const std::uint32_t desired_access, const std::uint32_t attributes) -> std::uint64_t
	{
		const std::array<std::uint8_t, alpc_port_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(), host,
			prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		host->body = addr;

		return st->create_handle(cpu, addr, desired_access, attributes);
	};

	state.redirect_ntzw(mod, "AlpcCreatePort",
		[st, create_port_object](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			emu_object<_ALPC_PORT_ATTRIBUTES> port_attributes) -> NTSTATUS
		{
			if (!port_handle)
				return STATUS_INVALID_PARAMETER;

			auto host = std::make_shared<alpc_port_host>();
			host->name = attribute_name(cpu, object_attributes);
			host->is_server = true;

			if (!host->name.empty() && st->objs.lookup_named_object(host->name))
			{
				THREAD_LOG_WARN("NtAlpcCreatePort: '{}' is already in the namespace", host->name);
				return STATUS_OBJECT_NAME_COLLISION;
			}

			const auto handle = create_port_object(cpu, host, PORT_ALL_ACCESS,
				object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			if (!host->name.empty())
			{
				// Another create may have published this name while our handle was being made.
				if (!st->objs.try_register_named_object(host->name, host->body))
				{
					st->close_handle(cpu, handle, 0);
					return STATUS_OBJECT_NAME_COLLISION;
				}
			}

			try { port_handle.write(handle); }
			catch (...)
			{
				if (!host->name.empty())
					st->objs.unregister_named_object(host->name, host->body);
				st->close_handle(cpu, handle, 0);
				return STATUS_ACCESS_VIOLATION;
			}

			THREAD_LOG_INFO("NtAlpcCreatePort('{}', attributes=0x{:X}) -> handle=0x{:X}",
				host->name, port_attributes.address(), handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AlpcConnectPort",
		[st, create_port_object](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_UNICODE_STRING> port_name,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			[[maybe_unused]] emu_object<_ALPC_PORT_ATTRIBUTES> port_attributes,
			const std::uint32_t flags, [[maybe_unused]] const addr_t required_server_sid,
			emu_object<_PORT_MESSAGE> connection_message, emu_object<std::uint64_t> buffer_length,
			[[maybe_unused]] const addr_t out_message_attributes,
			[[maybe_unused]] const addr_t in_message_attributes,
			[[maybe_unused]] emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			if (!port_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = narrow_wstring(win::read_unicode_string(port_name));
			const auto server_addr = st->objs.lookup_named_object(name);
			const auto server = server_addr
				? st->objs.get_object<alpc_port_host>(server_addr) : nullptr;

			if (!server || !server->is_server)
			{
				THREAD_LOG_WARN("NtAlpcConnectPort('{}'): no port of that name here", name);
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			auto client = std::make_shared<alpc_port_host>();
			client->name = name;
			client->peer = server;

			const auto handle = create_port_object(cpu, client, PORT_ALL_ACCESS,
				object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto previous_peer = server->peer;
			try
			{
				server->peer = client;

				port_handle.write(handle);

				if (connection_message)
				{
					auto message = read_message(cpu, connection_message);
					const auto size = message.size();

					server->post(std::move(message));

					THREAD_LOG_INFO("NtAlpcConnectPort('{}'): connection message of {} bytes queued "
						"to the server", name, size);
				}

				if (buffer_length)
					buffer_length.write(0);
			}
			catch (...)
			{
				server->peer = previous_peer;
				st->close_handle(cpu, handle, 0);
				return STATUS_ACCESS_VIOLATION;
			}

			THREAD_LOG_INFO("NtAlpcConnectPort('{}', flags=0x{:X}) -> handle=0x{:X}",
				name, flags, handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AlpcSendWaitReceivePort",
		[st, port_from_handle](vcpu& cpu, const std::uint64_t port_handle, const std::uint32_t flags,
			emu_object<_PORT_MESSAGE> send_message,
			[[maybe_unused]] const addr_t send_message_attributes,
			emu_object<_PORT_MESSAGE> receive_message, emu_object<std::uint64_t> buffer_length,
			[[maybe_unused]] const addr_t receive_message_attributes,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			const auto port = port_from_handle(cpu, port_handle);

			if (!port)
			{
				THREAD_LOG_WARN("NtAlpcSendWaitReceivePort: handle 0x{:X} is not a port",
					port_handle);
				return STATUS_INVALID_HANDLE;
			}

			if (send_message)
			{
				const auto peer = port->peer.lock();

				if (!peer)
				{
					THREAD_LOG_WARN("NtAlpcSendWaitReceivePort(0x{:X}): nothing is connected to "
						"this port", port_handle);
					return STATUS_PORT_DISCONNECTED;
				}

				auto message = read_message(cpu, send_message);
				const auto size = message.size();

				peer->post(std::move(message));

				THREAD_LOG_INFO("NtAlpcSendWaitReceivePort(0x{:X}, flags=0x{:X}): sent {} bytes, "
					"peer now holds {}", port_handle, flags, size, peer->queued());
			}

			if (!receive_message)
				return STATUS_SUCCESS;

			const auto message = port->take();

			if (!message)
			{
				THREAD_LOG_WARN("NtAlpcSendWaitReceivePort(0x{:X}): nothing queued, and nothing "
					"here blocks on a port -> STATUS_TIMEOUT (timeout={})",
					port_handle, win::read_timeout(timeout, st->clock.sample()).timed ? "given" : "none");

				return STATUS_TIMEOUT;
			}

			const auto room = buffer_length
				? static_cast<std::size_t>(buffer_length.read()) : message->size();
			const auto copied = std::min(room, message->size());

			cpu.curr_addr_space()->write_mem(receive_message.address(), message->data(), copied);

			if (buffer_length)
				buffer_length.write(copied);

			THREAD_LOG_INFO("NtAlpcSendWaitReceivePort(0x{:X}): received {} of {} bytes, {} left",
				port_handle, copied, message->size(), port->queued());

			return copied < message->size() ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
		});

	auto connect_port = [st, create_port_object](vcpu& cpu,
		emu_object<std::uint64_t> port_handle, emu_object<_UNICODE_STRING> port_name,
		const addr_t client_view, emu_object<_REMOTE_PORT_VIEW> server_view,
		emu_object<std::uint32_t> maximum_message_length,
		const std::string_view who) -> NTSTATUS
	{
		if (!port_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = narrow_wstring(win::read_unicode_string(port_name));

		auto client = std::make_shared<alpc_port_host>();
		client->name = name;

		const auto handle = create_port_object(cpu, client, PORT_ALL_ACCESS, 0);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		try
		{
			port_handle.write(handle);

			auto& space = *cpu.curr_addr_space();

			// PORT_VIEW is not in the generated types: the bases sit past the handle and offset.
			if (client_view)
			{
				const auto view_size = space.read_mem<std::uint64_t>(client_view + 0x18);

				if (view_size && view_size <= maximum_port_view_size)
				{
					const auto base = space.alloc(static_cast<std::size_t>(view_size), prot_rw);

					space.write_mem<std::uint64_t>(client_view + 0x20, base);
					space.write_mem<std::uint64_t>(client_view + 0x28, base);

					THREAD_LOG_INFO("{}: client view of 0x{:X} bytes at 0x{:X}",
						who, view_size, base);
				}
			}

			// No server maps a view, but a zero size reads as a broken connection.
			if (server_view)
			{
				auto value = server_view.read();
				value.ViewSize = maximum_port_view_size;
				value.ViewBase = nullptr;
				server_view.write(value);
			}

			if (maximum_message_length)
				maximum_message_length.write(default_maximum_message_length);
		}
		catch (...)
		{
			st->close_handle(cpu, handle, 0);
			return STATUS_ACCESS_VIOLATION;
		}

		THREAD_LOG_WARN("{}('{}') -> handle=0x{:X}: nothing here runs an LPC server, so nothing "
			"will answer a message sent to it", who, name, handle);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "ConnectPort",
		[connect_port](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_UNICODE_STRING> port_name,
			[[maybe_unused]] const addr_t security_qos, const addr_t client_view,
			emu_object<_REMOTE_PORT_VIEW> server_view,
			emu_object<std::uint32_t> maximum_message_length,
			const addr_t connection_information,
			emu_object<std::uint32_t> connection_information_length) -> NTSTATUS
		{
			clear_connection_information(cpu, connection_information,
				connection_information_length);

			return connect_port(cpu, std::move(port_handle), std::move(port_name), client_view,
				std::move(server_view), std::move(maximum_message_length), "NtConnectPort");
		});

	state.redirect_ntzw(mod, "SecureConnectPort",
		[connect_port](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_UNICODE_STRING> port_name,
			[[maybe_unused]] const addr_t security_qos, const addr_t client_view,
			[[maybe_unused]] const addr_t server_sid,
			emu_object<_REMOTE_PORT_VIEW> server_view,
			emu_object<std::uint32_t> maximum_message_length,
			const addr_t connection_information,
			emu_object<std::uint32_t> connection_information_length) -> NTSTATUS
		{
			clear_connection_information(cpu, connection_information,
				connection_information_length);

			return connect_port(cpu, std::move(port_handle), std::move(port_name), client_view,
				std::move(server_view), std::move(maximum_message_length),
				"NtSecureConnectPort");
		});
}
