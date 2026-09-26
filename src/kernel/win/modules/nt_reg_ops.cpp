#include "nt_reg_ops.hpp"
#include "../win_kernel.hpp"
#include "../registry.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../callback_registry.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <exception>
#include <memory>
#include <optional>
#include <new>
#include <cstring>
#include <vector>
#include <string_view>

namespace
{

struct registry_key_host final : win_object
{
	std::shared_ptr<win_registry_key> key;
	std::string path;
	addr_t body = 0;
};

// WDK 64-bit CM layouts, shared by the x64 and ARM64 profiles.
struct reg_set_value_info
{
	std::uint64_t object, value_name;
	std::uint32_t title_index, type;
	std::uint64_t data;
	std::uint32_t data_size, padding = 0;
	std::uint64_t call_context = 0, object_context = 0, reserved = 0;
	bool operator==(const reg_set_value_info&) const = default;
};
struct reg_query_value_info
{
	std::uint64_t object, value_name;
	std::uint32_t info_class, padding = 0;
	std::uint64_t information;
	std::uint32_t length, padding2 = 0;
	std::uint64_t result_length, call_context = 0, object_context = 0, reserved = 0;
	bool operator==(const reg_query_value_info&) const = default;
};
struct reg_delete_value_info
{
	std::uint64_t object, value_name, call_context = 0, object_context = 0, reserved = 0;
	bool operator==(const reg_delete_value_info&) const = default;
};
struct reg_post_info
{
	std::uint64_t object;
	std::uint32_t status, padding = 0;
	std::uint64_t pre_information;
	std::uint32_t return_status, padding2 = 0;
	std::uint64_t call_context, object_context = 0, reserved = 0;
};
static_assert(sizeof(reg_set_value_info) == 64 && offsetof(reg_set_value_info, call_context) == 40);
static_assert(sizeof(reg_query_value_info) == 72 && offsetof(reg_query_value_info, call_context) == 48);
static_assert(sizeof(reg_delete_value_info) == 40);
static_assert(sizeof(reg_post_info) == 56 && offsetof(reg_post_info, call_context) == 32);

// Mapping validation only: the emulator's MMU host-copy interface does not expose
// guest access-permission probing. Check every page and overflow before copying.
bool registry_buffer(addr_space& space, addr_t address, std::size_t size)
{
	if (!size) return true;
	if (!address || size - 1 > std::numeric_limits<addr_t>::max() - address) return false;
	const auto last = address + size - 1;
	const auto page = space.mmu_->page_size();
	for (;;)
	{
		if (!space.mmu_->virt_to_phys(space, address)) return false;
		if (last - address < page - address % page) return true;
		address += page - address % page;
	}
}

NTSTATUS capture_value_name(addr_space& space, emu_object<_UNICODE_STRING> input,
	std::u16string& name)
{
	if (!registry_buffer(space, input.address(), sizeof(_UNICODE_STRING))) return STATUS_ACCESS_VIOLATION;
	const auto us = input.read();
	if (us.Length % sizeof(char16_t) || us.MaximumLength < us.Length) return STATUS_INVALID_PARAMETER;
	if (!registry_buffer(space, guest_va(us.Buffer), us.Length)) return STATUS_ACCESS_VIOLATION;
	name.resize(us.Length / sizeof(char16_t));
	if (us.Length) space.read_mem(guest_va(us.Buffer), name.data(), us.Length);
	return STATUS_SUCCESS;
}

template <typename Info, typename Body>
NTSTATUS registry_value_operation(win_kernel_state& state, vcpu& cpu,
	const std::shared_ptr<registry_key_host>& host, const Info& original,
	std::uint32_t pre_class, std::uint32_t post_class, Body&& body)
{
	// Keep both representations alive even if a pre callback closes the handle.
	struct key_reference
	{
		win_obj_manager& manager;
		addr_t object;
		key_reference(win_obj_manager& m, addr_t o) : manager(m), object(o) { manager.reference_object(object); }
		~key_reference() { manager.dereference_object(object); }
	} reference(state.objs, host->body);
	auto& space = *cpu.curr_addr_space();
	struct frame { std::unique_ptr<pool_block> scratch; std::uint64_t context = 0; };
	std::vector<frame> frames;
	return state.registry_notify.dispatch(cpu.id(),
		[&](const auto& registration, std::size_t index) -> NTSTATUS {
			auto scratch = std::make_unique<pool_block>(state.pool, sizeof(Info) + sizeof(reg_post_info), pool_tag("CmNt"));
			if (!scratch->addr()) return STATUS_INSUFFICIENT_RESOURCES;
			space.write_mem(scratch->addr(), original);
			frames.push_back({std::move(scratch)});
			const auto result = state.call_registry_notify(cpu, *registration, pre_class, frames[index].scratch->addr());
			auto returned = space.read_mem<Info>(frames[index].scratch->addr());
			frames[index].context = returned.call_context;
			returned.call_context = original.call_context;
			// Stopping filters may completely handle the request. For continuing
			// filters only CallContext is writable; IN-field redirection is deferred.
			if (result != win::registry_notify_service::bypass && !(result & 0x80000000u)
				&& returned != original) return STATUS_NOT_SUPPORTED;
			return result;
		}, std::forward<Body>(body),
		[&](const auto& registration, std::size_t index, std::uint32_t status) {
			const auto pre = frames[index].scratch->addr();
			const auto post = pre + sizeof(Info);
			space.write_mem(post, reg_post_info{.object = host->body, .status = status,
				.pre_information = pre, .return_status = status, .call_context = frames[index].context});
			const auto result = state.call_registry_notify(cpu, *registration, post_class, post);
			return win::registry_notify_service::post_result{result, space.read_mem<reg_post_info>(post).return_status};
		});
}

constexpr NTSTATUS status_flt_instance_altitude_collision = 0xC01C0011;

std::optional<std::u16string> callback_altitude(addr_space& space,
	const _UNICODE_STRING& altitude)
{
	if (!altitude.Length || (altitude.Length % sizeof(char16_t)) != 0
		|| (altitude.MaximumLength % sizeof(char16_t)) != 0
		|| altitude.MaximumLength < altitude.Length || !guest_va(altitude.Buffer))
		return std::nullopt;

	auto value = win::read_unicode_string(space, altitude);
	if (value.empty())
		return std::nullopt;

	return value;
}

enum key_information_class : std::uint32_t
{
	key_basic_information = 0,
	key_node_information  = 1,
	key_full_information  = 2,
};

enum key_value_information_class : std::uint32_t
{
	key_value_basic_information   = 0,
	key_value_full_information    = 1,
	key_value_partial_information = 2,
};

enum key_disposition : std::uint32_t
{
	reg_created_new_key     = 1,
	reg_opened_existing_key = 2,
};

enum rtl_registry_relative : std::uint32_t
{
	rtl_registry_absolute  = 0,
	rtl_registry_services  = 1,
	rtl_registry_control   = 2,
	rtl_registry_windows_nt = 3,
	rtl_registry_devicemap = 4,
	rtl_registry_user      = 5,

	rtl_registry_optional  = 0x80000000,
	rtl_registry_handle    = 0x40000000,
};

enum rtl_query_registry_flags : std::uint32_t
{
	rtl_query_registry_subkey   = 0x01,
	rtl_query_registry_topkey   = 0x02,
	rtl_query_registry_required = 0x04,
	rtl_query_registry_novalue  = 0x08,
	rtl_query_registry_noexpand = 0x10,
	rtl_query_registry_direct   = 0x20,
	rtl_query_registry_delete   = 0x40,
};

// Not in the PDB, and packed to 4 so a LARGE_INTEGER does not pad the tail past the array start.
#pragma pack(push, 4)

struct key_basic_information_t
{
	std::int64_t  last_write_time;
	std::uint32_t title_index;
	std::uint32_t name_length;
};

struct key_full_information_t
{
	std::int64_t  last_write_time;
	std::uint32_t title_index;
	std::uint32_t class_offset;
	std::uint32_t class_length;
	std::uint32_t sub_keys;
	std::uint32_t max_name_len;
	std::uint32_t max_class_len;
	std::uint32_t values;
	std::uint32_t max_value_name_len;
	std::uint32_t max_value_data_len;
};

struct key_value_basic_information_t
{
	std::uint32_t title_index;
	std::uint32_t type;
	std::uint32_t name_length;
};

struct key_value_partial_information_t
{
	std::uint32_t title_index;
	std::uint32_t type;
	std::uint32_t data_length;
};

struct key_value_full_information_t
{
	std::uint32_t title_index;
	std::uint32_t type;
	std::uint32_t data_offset;
	std::uint32_t data_length;
	std::uint32_t name_length;
};

struct rtl_query_registry_table_t
{
	std::uint64_t query_routine;
	std::uint32_t flags;
	std::uint32_t padding;
	std::uint64_t name;
	std::uint64_t entry_context;
	std::uint32_t default_type;
	std::uint32_t padding2;
	std::uint64_t default_data;
	std::uint32_t default_length;
	std::uint32_t padding3;
};

#pragma pack(pop)

static_assert(sizeof(key_basic_information_t) == 0x10);
static_assert(sizeof(key_full_information_t) == 0x2C);
static_assert(sizeof(key_value_basic_information_t) == 0x0C);
static_assert(sizeof(key_value_partial_information_t) == 0x0C);
static_assert(sizeof(key_value_full_information_t) == 0x14);

std::uint32_t byte_length(const std::u16string& str)
{
	return static_cast<std::uint32_t>(str.size() * sizeof(char16_t));
}

// ResultLength is written on every path: a caller sizing a buffer asks with a length of zero.
NTSTATUS write_info(addr_space& space, const std::vector<std::uint8_t>& response,
	const addr_t buffer, const std::uint32_t length,
	emu_object<std::uint32_t> result_length, const std::string_view who)
{
	const auto required = static_cast<std::uint32_t>(response.size());

	if (result_length)
		result_length.write(required);

	if (!buffer || length == 0)
	{
		THREAD_LOG_INFO("{}: needs {} bytes", who, required);
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (length < required)
	{
		space.write_mem(buffer, response.data(), length);
		THREAD_LOG_INFO("{}: {} bytes given, {} needed", who, length, required);
		return STATUS_BUFFER_OVERFLOW;
	}

	space.write_mem(buffer, response.data(), required);
	THREAD_LOG_INFO("{}: wrote {} bytes", who, required);

	return STATUS_SUCCESS;
}

template <typename T>
std::vector<std::uint8_t> with_tail(const T& head, const void* tail, const std::size_t tail_size,
	const std::size_t tail_offset = sizeof(T))
{
	std::vector<std::uint8_t> out(tail_offset + tail_size, 0);
	std::memcpy(out.data(), &head, sizeof(T));

	if (tail_size)
		std::memcpy(out.data() + tail_offset, tail, tail_size);

	return out;
}

std::vector<std::uint8_t> value_response(const std::uint32_t info_class,
	const std::u16string& value_name, const registry_value& value)
{
	const auto type = static_cast<std::uint32_t>(value.type);
	const auto name_bytes = byte_length(value_name);
	const auto data_bytes = static_cast<std::uint32_t>(value.data.size());

	switch (info_class)
	{
	case key_value_basic_information:
	{
		const key_value_basic_information_t head{0, type, name_bytes};
		return with_tail(head, value_name.data(), name_bytes);
	}

	case key_value_partial_information:
	{
		const key_value_partial_information_t head{0, type, data_bytes};
		return with_tail(head, value.data.data(), data_bytes);
	}

	case key_value_full_information:
	{
		// The name sits behind the head and the data behind the name, as DataOffset says.
		const auto data_offset = static_cast<std::uint32_t>(
			sizeof(key_value_full_information_t) + name_bytes);

		const key_value_full_information_t head{0, type, data_offset, data_bytes, name_bytes};

		auto out = with_tail(head, value_name.data(), name_bytes);
		out.resize(data_offset + data_bytes, 0);

		if (data_bytes)
			std::memcpy(out.data() + data_offset, value.data.data(), data_bytes);

		return out;
	}

	default:
		return {};
	}
}

std::shared_ptr<registry_key_host> key_from_handle(win_kernel_state& state, vcpu& cpu,
	const std::uint64_t handle)
{
	return state.get_handle_object<registry_key_host>(cpu, handle);
}

std::uint64_t open_key_handle(win_kernel_state& state, vcpu& cpu, std::shared_ptr<win_registry_key> key,
	std::string path, const std::uint32_t access, const std::uint32_t attributes)
{
	auto host = std::make_shared<registry_key_host>();
	host->key = std::move(key);
	host->path = std::move(path);

	const std::uint8_t body[sizeof(addr_t)] = {};
	const auto addr = state.objs.create_object(0, body, sizeof(body),
		host, prot_rw | prot_supervisor);
	host->body = addr;

	return addr ? state.create_handle(cpu, addr, access, attributes) : 0;
}

std::string resolve_key_path(win_kernel_state& state, vcpu& cpu, addr_space& space,
	const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	if (!object_attributes)
		return {};

	const auto attrs = object_attributes.read();

	const emu_object<_UNICODE_STRING> name_obj(space, guest_va(attrs.ObjectName));
	const auto relative = win_registry::normalize_path(win::read_unicode_string(name_obj));

	const auto root = guest_va(attrs.RootDirectory);

	if (!root)
		return relative;

	const auto parent = key_from_handle(state, cpu, root);

	if (!parent)
	{
		THREAD_LOG_WARN("registry: root handle 0x{:X} is not an open key", root);
		return relative;
	}

	return relative.empty() ? parent->path : parent->path + "/" + relative;
}

// RTL_REGISTRY_HANDLE means Path is a handle, which nothing here hands out for this purpose.
std::string resolve_rtl_path(const std::uint32_t relative_to, const std::u16string& path)
{
	const auto relative = win_registry::normalize_path(path);

	switch (relative_to & ~(rtl_registry_optional | rtl_registry_handle))
	{
	case rtl_registry_services:
		return "system/currentcontrolset/services/" + relative;
	case rtl_registry_control:
		return "system/currentcontrolset/control/" + relative;
	case rtl_registry_windows_nt:
		return "software/microsoft/windows nt/currentversion/" + relative;
	case rtl_registry_devicemap:
		return "hardware/devicemap/" + relative;
	case rtl_registry_user:
		return "user/" + relative;
	default:
		return relative;
	}
}

}

// win_registry is a real store, so a value written through one is found again by every other.
void modules::register_ntoskrnl_reg_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto create_key = [st](vcpu& cpu, emu_object<std::uint64_t> key_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		[[maybe_unused]] const std::uint32_t title_index,
		[[maybe_unused]] emu_object<_UNICODE_STRING> class_name,
		[[maybe_unused]] const std::uint32_t create_options,
		emu_object<std::uint32_t> disposition) -> NTSTATUS
	{
		auto& space = *cpu.curr_addr_space();
		const auto path = resolve_key_path(*st, cpu, space, object_attributes);

		if (!key_handle || path.empty())
			return STATUS_INVALID_PARAMETER;

		const bool existed = st->reg.key_exists(path);
		auto key = st->reg.create_key(path);

		if (!key)
		{
			THREAD_LOG_ERR("ZwCreateKey('{}'): the store refused the key", path);
			return STATUS_UNSUCCESSFUL;
		}

		const auto handle = open_key_handle(*st, cpu, std::move(key), path, desired_access,
			object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		try
		{
			if (disposition)
				disposition.write(existed ? reg_opened_existing_key : reg_created_new_key);
			key_handle.write(handle);
		}
		catch (...)
		{
			st->close_handle(cpu, handle, 0);
			return STATUS_ACCESS_VIOLATION;
		}

		THREAD_LOG_INFO("ZwCreateKey('{}', access=0x{:X}) -> handle=0x{:X} ({})",
			path, desired_access, handle, existed ? "existing" : "new");

		return STATUS_SUCCESS;
	};

	auto open_key = [st](vcpu& cpu, emu_object<std::uint64_t> key_handle,
		const std::uint32_t desired_access,
		emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
	{
		auto& space = *cpu.curr_addr_space();
		const auto path = resolve_key_path(*st, cpu, space, object_attributes);

		if (!key_handle)
			return STATUS_INVALID_PARAMETER;

		auto key = st->reg.open_key(path);

		if (!key)
		{
			THREAD_LOG_WARN("ZwOpenKey('{}'): no such key", path);
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}

		const auto handle = open_key_handle(*st, cpu, std::move(key), path, desired_access,
			object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		try { key_handle.write(handle); }
		catch (...)
		{
			st->close_handle(cpu, handle, 0);
			return STATUS_ACCESS_VIOLATION;
		}

		THREAD_LOG_INFO("ZwOpenKey('{}', access=0x{:X}) -> handle=0x{:X}",
			path, desired_access, handle);

		return STATUS_SUCCESS;
	};

	auto query_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		const std::uint32_t key_information_class, const addr_t key_information,
		const std::uint32_t length, emu_object<std::uint32_t> result_length) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);

		if (!host)
		{
			THREAD_LOG_WARN("ZwQueryKey: handle 0x{:X} is not an open key", key_handle);
			return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();

		const auto slash = host->path.rfind('/');
		const auto name = widen_string(slash == std::string::npos
			? host->path : host->path.substr(slash + 1));

		if (key_information_class == key_basic_information
			|| key_information_class == key_node_information)
		{
			const key_basic_information_t head{0, 0, byte_length(name)};
			const auto response = with_tail(head, name.data(), byte_length(name));

			return write_info(space, response, key_information, length, result_length,
				"ZwQueryKey");
		}

		if (key_information_class == key_full_information)
		{
			const auto subkeys = st->reg.enumerate_subkeys(host->path);
			const auto values = host->key->enumerate_values();

			std::uint32_t max_name = 0;
			for (const auto& sub : subkeys)
				max_name = std::max(max_name, static_cast<std::uint32_t>(sub.size() * sizeof(char16_t)));

			std::uint32_t max_value_name = 0;
			std::uint32_t max_value_data = 0;
			for (const auto& value_name : values)
			{
				max_value_name = std::max(max_value_name,
					static_cast<std::uint32_t>(value_name.size() * sizeof(char16_t)));

				if (const auto value = host->key->copy_value(value_name))
					max_value_data = std::max(max_value_data,
						static_cast<std::uint32_t>(value->data.size()));
			}

			key_full_information_t head{};
			head.class_offset = sizeof(key_full_information_t);
			head.sub_keys = static_cast<std::uint32_t>(subkeys.size());
			head.max_name_len = max_name;
			head.values = static_cast<std::uint32_t>(values.size());
			head.max_value_name_len = max_value_name;
			head.max_value_data_len = max_value_data;

			const auto response = with_tail(head, nullptr, 0);

			return write_info(space, response, key_information, length, result_length,
				"ZwQueryKey");
		}

		THREAD_LOG_WARN("ZwQueryKey: unhandled class {}", key_information_class);

		return STATUS_INVALID_INFO_CLASS;
	};

	auto enumerate_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		const std::uint32_t index, const std::uint32_t key_information_class,
		const addr_t key_information, const std::uint32_t length,
		emu_object<std::uint32_t> result_length) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto subkeys = st->reg.enumerate_subkeys(host->path);

		if (index >= subkeys.size())
		{
			THREAD_LOG_INFO("ZwEnumerateKey('{}', index={}): {} subkeys, so that is the end",
				host->path, index, subkeys.size());
			return STATUS_NO_MORE_ENTRIES;
		}

		if (key_information_class != key_basic_information
			&& key_information_class != key_node_information)
		{
			THREAD_LOG_WARN("ZwEnumerateKey: unhandled class {}", key_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		const auto name = widen_string(subkeys[index]);
		const key_basic_information_t head{0, 0, byte_length(name)};
		const auto response = with_tail(head, name.data(), byte_length(name));

		THREAD_LOG_INFO("ZwEnumerateKey('{}', index={}) -> '{}'",
			host->path, index, subkeys[index]);

		return write_info(*cpu.curr_addr_space(), response, key_information, length,
			result_length, "ZwEnumerateKey");
	};

	auto query_value_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		emu_object<_UNICODE_STRING> value_name,
		const std::uint32_t key_value_information_class, const addr_t key_value_information,
		const std::uint32_t length, emu_object<std::uint32_t> result_length) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);
		if (!host) return STATUS_INVALID_HANDLE;
		auto& space = *cpu.curr_addr_space();
		std::u16string name;
		const auto captured = capture_value_name(space, value_name, name);
		if (captured != STATUS_SUCCESS) return captured;
		if (!registry_buffer(space, result_length.address(), sizeof(std::uint32_t))
			|| !registry_buffer(space, key_value_information, length)) return STATUS_ACCESS_VIOLATION;
		const auto narrow = narrow_wstring(name);
		const reg_query_value_info info{.object = host->body, .value_name = value_name.address(),
			.info_class = key_value_information_class, .information = key_value_information,
			.length = length, .result_length = result_length.address()};
		return registry_value_operation(*st, cpu, host, info, 8, 23, [&]() -> NTSTATUS {
			// Lookup after pre: a nested write must be visible to this query. Copy
			// while holding the store lock, then release it before guest output/post.
			const auto value = host->key->copy_value(narrow);
			if (!registry_buffer(space, result_length.address(), sizeof(std::uint32_t))
				|| !registry_buffer(space, key_value_information, length)) return STATUS_ACCESS_VIOLATION;
			if (!value) { result_length.write(0); return STATUS_OBJECT_NAME_NOT_FOUND; }
			const auto response = value_response(key_value_information_class, name, *value);
			if (response.empty()) return STATUS_INVALID_INFO_CLASS;
			return write_info(space, response, key_value_information, length, result_length, "ZwQueryValueKey");
		});
	};

	auto enumerate_value_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		const std::uint32_t index, const std::uint32_t key_value_information_class,
		const addr_t key_value_information, const std::uint32_t length,
		emu_object<std::uint32_t> result_length) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto names = host->key->enumerate_values();

		if (index >= names.size())
		{
			THREAD_LOG_INFO("ZwEnumerateValueKey('{}', index={}): {} values, so that is the end",
				host->path, index, names.size());
			return STATUS_NO_MORE_ENTRIES;
		}

		const auto value = host->key->copy_value(names[index]);

		if (!value)
			return STATUS_OBJECT_NAME_NOT_FOUND;

		const auto response = value_response(key_value_information_class,
			widen_string(names[index]), *value);

		if (response.empty())
		{
			THREAD_LOG_WARN("ZwEnumerateValueKey: unhandled class {}", key_value_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		THREAD_LOG_INFO("ZwEnumerateValueKey('{}', index={}) -> '{}'",
			host->path, index, names[index]);

		return write_info(*cpu.curr_addr_space(), response, key_value_information, length,
			result_length, "ZwEnumerateValueKey");
	};

	auto set_value_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		emu_object<_UNICODE_STRING> value_name, const std::uint32_t title_index,
		const std::uint32_t type, const addr_t data, const std::uint32_t data_size) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);
		if (!host) return STATUS_INVALID_HANDLE;
		auto& space = *cpu.curr_addr_space();
		std::u16string name;
		const auto captured = capture_value_name(space, value_name, name);
		if (captured != STATUS_SUCCESS) return captured;
		if (!registry_buffer(space, data, data_size)) return STATUS_ACCESS_VIOLATION;
		std::vector<std::uint8_t> bytes(data_size);
		if (data_size) space.read_mem(data, bytes.data(), data_size);
		const auto narrow = narrow_wstring(name);
		const reg_set_value_info info{.object = host->body, .value_name = value_name.address(),
			.title_index = title_index, .type = type, .data = data, .data_size = data_size};
		return registry_value_operation(*st, cpu, host, info, 1, 16, [&]() -> NTSTATUS {
			host->key->set_value(narrow, static_cast<registry_type>(type), bytes);
			return STATUS_SUCCESS;
		});
	};

	auto delete_value_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		emu_object<_UNICODE_STRING> value_name) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);
		if (!host) return STATUS_INVALID_HANDLE;
		std::u16string name;
		const auto captured = capture_value_name(*cpu.curr_addr_space(), value_name, name);
		if (captured != STATUS_SUCCESS) return captured;
		const auto narrow = narrow_wstring(name);
		const reg_delete_value_info info{.object = host->body, .value_name = value_name.address()};
		return registry_value_operation(*st, cpu, host, info, 2, 17, [&]() -> NTSTATUS {
			return host->key->delete_value(narrow) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
		});
	};

	auto delete_key = [st](vcpu& cpu, const std::uint64_t key_handle) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const bool deleted = st->reg.delete_key(host->path);

		THREAD_LOG_INFO("ZwDeleteKey('{}') -> {}", host->path, deleted);

		return deleted ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
	};

	// Nothing is behind the store but memory, so there is no write to push out.
	auto flush_key = [st](vcpu& cpu, const std::uint64_t key_handle) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, cpu, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		THREAD_LOG_INFO("ZwFlushKey('{}'): the store is memory, so there is nothing to flush",
			host->path);

		return STATUS_SUCCESS;
	};

	// Nt and Zw are one function at one address here, so both names bind to one handler.
	state.redirect_ntzw(mod, "CreateKey", create_key);
	state.redirect_ntzw(mod, "OpenKey", open_key);
	state.redirect_ntzw(mod, "QueryKey", query_key);
	state.redirect_ntzw(mod, "EnumerateKey", enumerate_key);
	state.redirect_ntzw(mod, "QueryValueKey", query_value_key);
	state.redirect_ntzw(mod, "EnumerateValueKey", enumerate_value_key);
	state.redirect_ntzw(mod, "SetValueKey", set_value_key);
	state.redirect_ntzw(mod, "DeleteValueKey", delete_value_key);
	state.redirect_ntzw(mod, "DeleteKey", delete_key);
	state.redirect_ntzw(mod, "FlushKey", flush_key);

	state.redirect(mod, "RtlWriteRegistryValue",
		[st](vcpu& cpu, const std::uint32_t relative_to, const addr_t path,
			const addr_t value_name, const std::uint32_t value_type,
			const addr_t value_data, const std::uint32_t value_length) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();
			const auto key_path = resolve_rtl_path(relative_to, guest::read_wstring(space, path));
			const auto name = narrow_wstring(guest::read_wstring(space, value_name));

			auto key = st->reg.create_key(key_path);

			if (!key)
				return STATUS_UNSUCCESSFUL;

			std::vector<std::uint8_t> bytes(value_length);

			if (value_length && value_data)
				space.read_mem(value_data, bytes.data(), value_length);

			key->set_value(name, static_cast<registry_type>(value_type), bytes);

			THREAD_LOG_INFO("RtlWriteRegistryValue('{}', '{}', type={}, {} bytes)",
				key_path, name, value_type, value_length);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "RtlDeleteRegistryValue",
		[st](vcpu& cpu, const std::uint32_t relative_to, const addr_t path,
			const addr_t value_name) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();
			const auto key_path = resolve_rtl_path(relative_to, guest::read_wstring(space, path));
			const auto name = narrow_wstring(guest::read_wstring(space, value_name));

			auto key = st->reg.open_key(key_path);

			if (!key)
			{
				THREAD_LOG_WARN("RtlDeleteRegistryValue('{}'): no such key", key_path);
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			const bool deleted = key->delete_value(name);

			THREAD_LOG_INFO("RtlDeleteRegistryValue('{}', '{}') -> {}", key_path, name, deleted);

			return deleted ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
		});

	// Nothing here calls back into the guest, so entries naming a QueryRoutine are refused.
	state.redirect(mod, "RtlQueryRegistryValues",
		[st](vcpu& cpu, const std::uint32_t relative_to, const addr_t path,
			const addr_t query_table, [[maybe_unused]] const addr_t context,
			[[maybe_unused]] const addr_t environment) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();
			const auto key_path = resolve_rtl_path(relative_to, guest::read_wstring(space, path));

			auto key = st->reg.open_key(key_path);

			THREAD_LOG_INFO("RtlQueryRegistryValues('{}', table=0x{:X}){}",
				key_path, query_table, key ? "" : ": no such key");

			for (std::size_t i = 0; i < 64; ++i)
			{
				const emu_object<rtl_query_registry_table_t> entry(space,
					query_table + i * sizeof(rtl_query_registry_table_t));

				const auto row = entry.read();

				if (!row.name && !row.query_routine)
					break;

				const auto name = narrow_wstring(guest::read_wstring(space, row.name));

				if (!(row.flags & rtl_query_registry_direct))
				{
					THREAD_LOG_WARN("RtlQueryRegistryValues: entry '{}' wants its QueryRoutine "
						"at 0x{:X} called, and nothing here calls back into the guest",
						name, row.query_routine);

					continue;
				}

				const auto value = key ? key->copy_value(name) : std::nullopt;

				if (!value)
				{
					if (row.flags & rtl_query_registry_required)
					{
						THREAD_LOG_WARN("RtlQueryRegistryValues: required value '{}' is not in '{}'",
							name, key_path);
						return STATUS_OBJECT_NAME_NOT_FOUND;
					}

					if (row.default_data && row.default_length && row.entry_context)
					{
						std::vector<std::uint8_t> bytes(row.default_length);
						space.read_mem(row.default_data, bytes.data(), row.default_length);
						space.write_mem(row.entry_context, bytes.data(), bytes.size());

						THREAD_LOG_INFO("RtlQueryRegistryValues: '{}' defaulted, {} bytes",
							name, row.default_length);
					}

					continue;
				}

				if (row.entry_context)
				{
					space.write_mem(row.entry_context, value->data.data(), value->data.size());

					THREAD_LOG_INFO("RtlQueryRegistryValues: '{}' -> {} bytes into 0x{:X}",
						name, value->data.size(), row.entry_context);
				}
			}

			return STATUS_SUCCESS;
		});

	// Registrations and whole-operation rundown belong to this emulator instance.
	state.redirect(mod, "CmRegisterCallbackEx",
		[st](vcpu& cpu, const addr_t function, emu_object<_UNICODE_STRING> altitude,
			const addr_t driver, const addr_t context,
			emu_object<std::int64_t> cookie, const addr_t reserved) -> NTSTATUS
		{
			if (!function || !altitude || !driver || !cookie || reserved) return STATUS_INVALID_PARAMETER;
			try
			{
				auto& space = *cpu.curr_addr_space();
				if (!registry_buffer(space, altitude.address(), sizeof(_UNICODE_STRING))) return STATUS_ACCESS_VIOLATION;
				const auto us = altitude.read();
				if (!registry_buffer(space, guest_va(us.Buffer), us.Length)) return STATUS_ACCESS_VIOLATION;
				const auto value = callback_altitude(space, us);
				if (!value) return STATUS_INVALID_PARAMETER;
				const auto result = st->registry_notify.add({function, context, *value, driver}, [&](std::int64_t id) {
					if (!registry_buffer(space, cookie.address(), sizeof(id))) throw std::runtime_error("invalid cookie output");
					cookie.write(id);
				});
				using status = win::registry_notify_service::add_status;
				switch (result)
				{
				case status::success: return STATUS_SUCCESS;
				case status::invalid_altitude: return STATUS_INVALID_PARAMETER;
				case status::collision: return status_flt_instance_altitude_collision;
				case status::output_failed: return STATUS_ACCESS_VIOLATION;
				case status::exhausted: return STATUS_INSUFFICIENT_RESOURCES;
				}
			}
			catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
			catch (const std::exception&) { return STATUS_ACCESS_VIOLATION; }
			return STATUS_UNSUCCESSFUL;
		});

	state.redirect(mod, "CmUnRegisterCallback",
		[st](vcpu& cpu, const std::int64_t cookie) -> NTSTATUS {
			const auto result = st->registry_notify.remove(cookie, st->in_lifecycle_callback(cpu.id()));
			if (result == win::registry_notify_service::remove_status::callback_deadlock)
			{
				THREAD_LOG_ERR("registry notify: CmUnRegisterCallback: callback rundown deadlock");
				st->fail_thread_notify(cpu, "registry callback rundown deadlock");
			}
			return result == win::registry_notify_service::remove_status::removed
				? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
		});

	// Nothing here notices a registry write, so the watch is accepted and the event stays unset.
	state.redirect_ntzw(mod, "NotifyChangeKey",
		[st](vcpu& cpu, const std::uint64_t key_handle, const addr_t event, const addr_t apc_routine,
			const addr_t apc_context, emu_object<_IO_STATUS_BLOCK> io_status_block,
			const std::uint32_t completion_filter, const bool watch_tree, const addr_t buffer,
			const std::uint32_t buffer_size, const bool asynchronous) -> NTSTATUS
		{
			if (!st->lookup_handle(cpu, key_handle))
			{
				THREAD_LOG_WARN("NtNotifyChangeKey: handle 0x{:X} is not open", key_handle);
				return STATUS_INVALID_HANDLE;
			}

			if (io_status_block)
			{
				_IO_STATUS_BLOCK status{};
				status.Status = static_cast<std::int32_t>(STATUS_SUCCESS);
				io_status_block.write(status);
			}

			THREAD_LOG_WARN("NtNotifyChangeKey(0x{:X}, filter=0x{:X}, tree={}, async={}, "
				"event=0x{:X}, apc=0x{:X}/0x{:X}, buffer=0x{:X}/{}): nothing here notices a "
				"registry write, so no notification ever arrives",
				key_handle, completion_filter, watch_tree, asynchronous, event, apc_routine,
				apc_context, buffer, buffer_size);

			return asynchronous ? STATUS_PENDING : STATUS_SUCCESS;
		});
}
