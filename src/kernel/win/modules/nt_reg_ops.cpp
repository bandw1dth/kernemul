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
};

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

std::shared_ptr<registry_key_host> key_from_handle(win_kernel_state& state,
	const std::uint64_t handle)
{
	return state.sys_proc->handle_table().get_object<registry_key_host>(handle);
}

std::uint64_t open_key_handle(win_kernel_state& state, std::shared_ptr<win_registry_key> key,
	std::string path, const std::uint32_t access)
{
	auto host = std::make_shared<registry_key_host>();
	host->key = std::move(key);
	host->path = std::move(path);

	const std::uint8_t body[sizeof(addr_t)] = {};
	const auto addr = state.objs.create_object(0, body, sizeof(body),
		std::move(host), prot_rw | prot_supervisor);

	return addr ? state.sys_proc->handle_table().create_handle(addr, access) : 0;
}

std::string resolve_key_path(win_kernel_state& state, addr_space& space,
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

	const auto parent = key_from_handle(state, root);

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
		const auto path = resolve_key_path(*st, space, object_attributes);

		if (!key_handle || path.empty())
			return STATUS_INVALID_PARAMETER;

		const bool existed = st->reg.key_exists(path);
		auto key = st->reg.create_key(path);

		if (!key)
		{
			THREAD_LOG_ERR("ZwCreateKey('{}'): the store refused the key", path);
			return STATUS_UNSUCCESSFUL;
		}

		const auto handle = open_key_handle(*st, std::move(key), path, desired_access);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		key_handle.write(handle);

		if (disposition)
			disposition.write(existed ? reg_opened_existing_key : reg_created_new_key);

		THREAD_LOG_INFO("ZwCreateKey('{}', access=0x{:X}) -> handle=0x{:X} ({})",
			path, desired_access, handle, existed ? "existing" : "new");

		return STATUS_SUCCESS;
	};

	auto open_key = [st](vcpu& cpu, emu_object<std::uint64_t> key_handle,
		const std::uint32_t desired_access,
		emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
	{
		auto& space = *cpu.curr_addr_space();
		const auto path = resolve_key_path(*st, space, object_attributes);

		if (!key_handle)
			return STATUS_INVALID_PARAMETER;

		auto key = st->reg.open_key(path);

		if (!key)
		{
			THREAD_LOG_WARN("ZwOpenKey('{}'): no such key", path);
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}

		const auto handle = open_key_handle(*st, std::move(key), path, desired_access);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		key_handle.write(handle);

		THREAD_LOG_INFO("ZwOpenKey('{}', access=0x{:X}) -> handle=0x{:X}",
			path, desired_access, handle);

		return STATUS_SUCCESS;
	};

	auto query_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		const std::uint32_t key_information_class, const addr_t key_information,
		const std::uint32_t length, emu_object<std::uint32_t> result_length) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, key_handle);

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

				if (const auto* value = host->key->query_value(value_name))
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
		const auto host = key_from_handle(*st, key_handle);

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
		const auto host = key_from_handle(*st, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto name = win::read_unicode_string(value_name);
		const auto narrow = narrow_wstring(name);
		const auto* value = host->key->query_value(narrow);

		if (!value)
		{
			THREAD_LOG_INFO("ZwQueryValueKey('{}'): no value '{}'", host->path, narrow);

			if (result_length)
				result_length.write(0);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		}

		const auto response = value_response(key_value_information_class, name, *value);

		if (response.empty())
		{
			THREAD_LOG_WARN("ZwQueryValueKey: unhandled class {}", key_value_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		THREAD_LOG_INFO("ZwQueryValueKey('{}', '{}', class={}): type={}, {} bytes",
			host->path, narrow, key_value_information_class,
			static_cast<std::uint32_t>(value->type), value->data.size());

		return write_info(*cpu.curr_addr_space(), response, key_value_information, length,
			result_length, "ZwQueryValueKey");
	};

	auto enumerate_value_key = [st](vcpu& cpu, const std::uint64_t key_handle,
		const std::uint32_t index, const std::uint32_t key_value_information_class,
		const addr_t key_value_information, const std::uint32_t length,
		emu_object<std::uint32_t> result_length) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto names = host->key->enumerate_values();

		if (index >= names.size())
		{
			THREAD_LOG_INFO("ZwEnumerateValueKey('{}', index={}): {} values, so that is the end",
				host->path, index, names.size());
			return STATUS_NO_MORE_ENTRIES;
		}

		const auto* value = host->key->query_value(names[index]);

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
		emu_object<_UNICODE_STRING> value_name, [[maybe_unused]] const std::uint32_t title_index,
		const std::uint32_t type, const addr_t data, const std::uint32_t data_size) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto narrow = narrow_wstring(win::read_unicode_string(value_name));

		std::vector<std::uint8_t> bytes(data_size);

		if (data_size && data)
			cpu.curr_addr_space()->read_mem(data, bytes.data(), data_size);

		host->key->set_value(narrow, static_cast<registry_type>(type), bytes);

		THREAD_LOG_INFO("ZwSetValueKey('{}', '{}', type={}, {} bytes)",
			host->path, narrow, type, data_size);

		return STATUS_SUCCESS;
	};

	auto delete_value_key = [st](vcpu&, const std::uint64_t key_handle,
		emu_object<_UNICODE_STRING> value_name) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const auto narrow = narrow_wstring(win::read_unicode_string(value_name));
		const bool deleted = host->key->delete_value(narrow);

		THREAD_LOG_INFO("ZwDeleteValueKey('{}', '{}') -> {}", host->path, narrow, deleted);

		return deleted ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
	};

	auto delete_key = [st](vcpu&, const std::uint64_t key_handle) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, key_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		const bool deleted = st->reg.delete_key(host->path);

		THREAD_LOG_INFO("ZwDeleteKey('{}') -> {}", host->path, deleted);

		return deleted ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
	};

	// Nothing is behind the store but memory, so there is no write to push out.
	auto flush_key = [st](vcpu&, const std::uint64_t key_handle) -> NTSTATUS
	{
		const auto host = key_from_handle(*st, key_handle);

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
	state.redirect(mod, "ZwFlushKey", flush_key);

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

				const auto* value = key ? key->query_value(name) : nullptr;

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

	// The records live with these per-emulator handlers; registry callback delivery is unsupported.
	auto cm_callbacks = std::make_shared<win::callbacks::registry<std::int64_t,
		win::callbacks::cm_registration>>(1);
	state.redirect(mod, "CmRegisterCallbackEx",
		[cm_callbacks](vcpu& cpu, const addr_t function, emu_object<_UNICODE_STRING> altitude,
			const addr_t driver, const addr_t context,
			emu_object<std::int64_t> cookie, const addr_t reserved) -> NTSTATUS
		{
			if (!function || !altitude || !driver || !cookie || reserved)
				return STATUS_INVALID_PARAMETER;

			win::callbacks::registry<std::int64_t,
				win::callbacks::cm_registration>::insert_result inserted{
					.status = win::callbacks::insert_status::identifier_exhausted,
				};
			std::string altitude_log;
			try
			{
				auto& space = *cpu.curr_addr_space();
				const auto altitude_value = callback_altitude(space, altitude.read());
				if (!altitude_value)
					return STATUS_INVALID_PARAMETER;
				altitude_log = narrow_wstring(*altitude_value);

				win::callbacks::cm_registration copied{
					.function = function,
					.context = context,
					.altitude = *altitude_value,
					.driver = driver,
				};
				inserted = cm_callbacks->insert(std::move(copied),
					[&cookie](const std::int64_t value)
					{
						cookie.write(value);
					});
			}
			catch (const std::bad_alloc&)
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			catch (const std::exception&)
			{
				return STATUS_INVALID_PARAMETER;
			}

			switch (inserted.status)
			{
			case win::callbacks::insert_status::altitude_collision:
				return status_flt_instance_altitude_collision;
			case win::callbacks::insert_status::output_write_failed:
				return STATUS_ACCESS_VIOLATION;
			case win::callbacks::insert_status::identifier_exhausted:
				return STATUS_INSUFFICIENT_RESOURCES;
			case win::callbacks::insert_status::success:
				THREAD_LOG_WARN("CmRegisterCallbackEx(function=0x{:X}, altitude='{}', driver=0x{:X}, "
					"context=0x{:X}) -> cookie={}: registry callback delivery is unsupported",
					function, altitude_log, driver, context, inserted.id);
				return STATUS_SUCCESS;
			}
			return STATUS_UNSUCCESSFUL;
		});

	state.redirect(mod, "CmUnRegisterCallback",
		[cm_callbacks](vcpu&, const std::int64_t cookie) -> NTSTATUS
		{
			if (!cm_callbacks->unregister(cookie))
			{
				THREAD_LOG_WARN("CmUnRegisterCallback(cookie={}) -> STATUS_INVALID_PARAMETER", cookie);
				return STATUS_INVALID_PARAMETER;
			}

			THREAD_LOG_INFO("CmUnRegisterCallback(cookie={}) -> removed; registry callback delivery "
				"is unsupported", cookie);
			return STATUS_SUCCESS;
		});

	// Nothing here notices a registry write, so the watch is accepted and the event stays unset.
	state.redirect_ntzw(mod, "NotifyChangeKey",
		[st](vcpu&, const std::uint64_t key_handle, const addr_t event, const addr_t apc_routine,
			const addr_t apc_context, emu_object<_IO_STATUS_BLOCK> io_status_block,
			const std::uint32_t completion_filter, const bool watch_tree, const addr_t buffer,
			const std::uint32_t buffer_size, const bool asynchronous) -> NTSTATUS
		{
			if (!st->sys_proc->handle_table().lookup_handle(key_handle))
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
