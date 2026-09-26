#include "nt_object_ops.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../process_params.hpp"
#include "../process.hpp"
#include "../rundown.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../callback_registry.hpp"
#include "../../../util/string.hpp"
#include "../../../util/log.hpp"
#include <array>
#include <exception>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr std::size_t namespace_object_body_size = 0x10;
constexpr std::uint16_t ob_flt_registration_version = 0x0100;
constexpr std::uint32_t ob_operation_handle_create = 0x00000001;
constexpr std::uint32_t ob_operation_handle_duplicate = 0x00000002;
constexpr NTSTATUS status_flt_instance_altitude_collision = 0xC01C0011;

struct directory_host final : win_object {};

// WDK types the kernel does not store, so not in the PDB; both are the same on each architecture.
#pragma pack(push, 8)
struct ob_callback_registration_t
{
	std::uint16_t   version;
	std::uint16_t   operation_count;
	std::uint32_t   padding;
	_UNICODE_STRING altitude;
	addr_t          registration_context;
	addr_t          operation_registration;
};

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

bool is_supported_object_type(addr_space& space, const proc_module& mod,
	const addr_t object_type, const addr_t type)
{
	if (!object_type || !type)
		return false;

	for (const auto symbol : { "PsProcessType", "PsThreadType" })
	{
		const auto global = mod.find_symbol(symbol);
		if (global && object_type == *global)
			return space.read_mem<addr_t>(*global) == type;
	}

	return false;
}

struct ob_operation_registration_t
{
	addr_t        object_type;
	std::uint32_t operations;
	std::uint32_t padding;
	addr_t        pre_operation;
	addr_t        post_operation;
};
#pragma pack(pop)

}

void modules::register_ntoskrnl_object_ops(win_kernel_state& state, proc_module& mod)
{
    state.redirect(mod, "ObReferenceObjectByHandle",
        [st = &state](vcpu& cpu, std::uint64_t handle, std::uint32_t desired_access,
            addr_t object_type, std::uint8_t access_mode, emu_object<addr_t> object_out,
            emu_object<void> handle_information) -> NTSTATUS
        {
            if (access_mode > 1) return STATUS_INVALID_PARAMETER;
            auto entry = st->lookup_handle(cpu, handle, access_mode);
            if (handle == ~std::uint64_t{0})
            {
                const auto process = st->current_process(cpu);
                if (process) entry = win_handle_table::handle_entry{process->eprocess().address(), 0x001fffffu, 0};
            }
            else if (handle == ~std::uint64_t{1})
            {
                const auto thread = std::dynamic_pointer_cast<win_thread>(cpu.thread());
                if (thread) entry = win_handle_table::handle_entry{thread->ethread().address(), 0x001fffffu, 0};
            }
            if (!entry) return STATUS_INVALID_HANDLE;
            const auto actual = st->ob_object_type(entry->body_addr);
            if (object_type && (actual || object_type == st->ob_process_type || object_type == st->ob_thread_type)
                && object_type != actual) return STATUS_OBJECT_TYPE_MISMATCH;
            if (access_mode && (desired_access & ~entry->access)) return STATUS_ACCESS_DENIED;
            if (access_mode && (desired_access & 0xf2000000u)) return STATUS_NOT_SUPPORTED;
            if (!object_out) return STATUS_INVALID_PARAMETER;
            try
            {
                // Probe outputs before publishing either result.
                object_out.write(object_out.read());
                if (handle_information)
                {
                    struct information { std::uint32_t attributes, granted; };
                    auto output = emu_object<information>(*handle_information.space(), handle_information.address());
                    output.write(output.read());
                }
                if (handle_information)
                {
                    struct information { std::uint32_t attributes, granted; };
                    emu_object<information>(*handle_information.space(), handle_information.address())
                        .write({entry->attributes, entry->access});
                }
                object_out.write(entry->body_addr);
            }
            catch (...) { return STATUS_ACCESS_VIOLATION; }
            st->objs.reference_object(entry->body_addr);
            return STATUS_SUCCESS;
        });

	state.redirect(mod, "ObfReferenceObject",
		[&objs = state.objs](vcpu&, addr_t object) -> void
		{
			THREAD_LOG_INFO("ObfReferenceObject(object=0x{:X})", object);
			objs.reference_object(object);
		});

	// Only four object types exist here and nothing ties one to an object, so the type a caller
	// asks for is logged rather than enforced: a mismatch it never made is worse than no check.
	state.redirect(mod, "ObReferenceObjectByPointer",
		[&objs = state.objs](vcpu&, const addr_t object,
			[[maybe_unused]] const std::uint32_t desired_access, const addr_t object_type,
			[[maybe_unused]] const std::uint8_t access_mode) -> NTSTATUS
		{
			if (!object)
				return STATUS_INVALID_PARAMETER;

			if (!objs.has_object(object))
				THREAD_LOG_WARN("ObReferenceObjectByPointer: 0x{:X} is not an object here, so "
					"the reference is not counted", object);
			else
				objs.reference_object(object);

			THREAD_LOG_INFO("ObReferenceObjectByPointer(object=0x{:X}, type=0x{:X})",
				object, object_type);

			return STATUS_SUCCESS;
		});

	auto deref = [&objs = state.objs](vcpu&, addr_t object) -> void
	{
		THREAD_LOG_INFO("ObfDereferenceObject(object=0x{:X})", object);
		objs.dereference_object(object);
	};

	state.redirect(mod, "ObfDereferenceObject", deref);
	state.redirect(mod, "ObfDereferenceObjectWithTag", deref);

	auto close_fn = [st = &state](vcpu& cpu, std::uint64_t handle) -> NTSTATUS
	{
		const auto entry = st->lookup_handle(cpu, handle);
		if (!entry) return STATUS_INVALID_HANDLE;
		if (entry->attributes & 1u) return static_cast<NTSTATUS>(0xC0000235); // STATUS_HANDLE_NOT_CLOSABLE
		const auto host = st->objs.get_object<file_host>(entry->body_addr);
		if (host && host->is_device())
		{
			std::scoped_lock lock(host->close_mutex);
			if (!st->close_handle(cpu, handle)) return STATUS_INVALID_HANDLE;
			const auto header = st->objs.header_of(entry->body_addr).read();
			if (header.HandleCount == 0 && host->file_object)
			{
				if (auto* emulator = st->emulator())
					for (const auto major : {irp_mj_cleanup, irp_mj_close})
						emulator->dispatch_irp(cpu, {.major = major, .device_object = host->device_object,
							.file_object = host->file_object});
				st->pool.free(host->file_object);
				host->file_object = 0;
			}
			return STATUS_SUCCESS;
		}
		return st->close_handle(cpu, handle) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
	};

	state.redirect_ntzw(mod, "Close", close_fn);

    state.redirect(mod, "ObRegisterCallbacks",
        [st = &state, &mod](vcpu& cpu, emu_object<void> callback_registration,
            emu_object<addr_t> registration_handle) -> NTSTATUS
        {
            if (!callback_registration || !registration_handle) return STATUS_INVALID_PARAMETER;
            if (cpu.in_dpc || !st->emulator() || st->emulator()->irql(cpu) > apc_level)
                return STATUS_INVALID_PARAMETER;
            try
            {
                auto& space = *cpu.curr_addr_space();
                const auto reg = emu_object<ob_callback_registration_t>(space, callback_registration.address()).read();
                if (reg.version != ob_flt_registration_version || !reg.operation_count || !reg.operation_registration)
                    return STATUS_INVALID_PARAMETER;
                const auto altitude = callback_altitude(space, reg.altitude);
                if (!altitude) return STATUS_INVALID_PARAMETER;
                win::callbacks::ob_registration copied{reg.version, reg.registration_context, *altitude, {}};
                for (std::uint16_t i = 0; i < reg.operation_count; ++i)
                {
                    const auto offset = static_cast<addr_t>(i) * sizeof(ob_operation_registration_t);
                    if (reg.operation_registration > std::numeric_limits<addr_t>::max() - offset)
                        return STATUS_INVALID_PARAMETER;
                    const auto entry = space.read_mem<ob_operation_registration_t>(reg.operation_registration + offset);
                    if (const auto desktop = mod.find_symbol("ExDesktopObjectType"); desktop && entry.object_type == *desktop)
                        return STATUS_NOT_SUPPORTED;
                    if (!entry.object_type || !entry.operations || (entry.operations & ~3u)
                        || (!entry.pre_operation && !entry.post_operation)) return STATUS_INVALID_PARAMETER;
                    const auto type = space.read_mem<addr_t>(entry.object_type);
                    if (!is_supported_object_type(space, mod, entry.object_type, type)) return STATUS_INVALID_PARAMETER;
                    copied.operations.push_back({entry.object_type, type, entry.operations, entry.pre_operation, entry.post_operation});
                }
                const auto result = st->ob_notify.add(std::move(copied), [&](addr_t cookie) { registration_handle.write(cookie); });
                using result_t = win::ob_notify_service::add_status;
                switch (result)
                {
                case result_t::success: return STATUS_SUCCESS;
                case result_t::collision: return status_flt_instance_altitude_collision;
                case result_t::output_failed: return STATUS_ACCESS_VIOLATION;
                case result_t::exhausted: return STATUS_INSUFFICIENT_RESOURCES;
                default: return STATUS_INVALID_PARAMETER;
                }
            }
            catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
            catch (...) { return STATUS_ACCESS_VIOLATION; }
        });
    state.redirect(mod, "ObUnRegisterCallbacks",
        [st = &state](vcpu& cpu, addr_t cookie) {
            if (st->in_lifecycle_callback(cpu.id())) st->fail_ob_notify(cpu, "unregister inside lifecycle callback is unsupported");
            if (!st->emulator() || cpu.in_dpc || st->emulator()->irql(cpu) > apc_level)
                st->fail_ob_notify(cpu, "unregister requires IRQL <= APC_LEVEL");
            st->ob_notify.remove(cookie, false);
        });

	// Nothing here builds a type index table, so the kind comes from the host object instead.
	state.redirect(mod, "ObGetObjectType",
		[st = &state, m = &mod](vcpu& cpu, const addr_t object) -> addr_t
		{
			std::string_view symbol;

			if (st->objs.get_object<process_identity_object>(object))
				symbol = "PsProcessType";
			else if (st->objs.get_object<file_host>(object))
				symbol = "IoFileObjectType";
			else if (st->objs.get_object<section_host>(object))
				symbol = "MmSectionObjectType";
			else if (st->objs.get_object<thread_object>(object))
				symbol = "PsThreadType";

			if (symbol.empty())
			{
				THREAD_LOG_WARN("ObGetObjectType(0x{:X}): nothing here knows what kind of object "
					"that is", object);
				return 0;
			}

			const auto global = m->find_symbol(symbol);

			if (!global)
			{
				THREAD_LOG_WARN("ObGetObjectType: {} is not in {}", symbol, m->name);
				return 0;
			}

			const auto type = cpu.curr_addr_space()->read_mem<addr_t>(*global);

			THREAD_LOG_INFO("ObGetObjectType(0x{:X}) -> 0x{:X} ({})", object, type, symbol);

			return type;
		});

    state.redirect(mod, "ObOpenObjectByPointer",
        [st = &state](vcpu& cpu, addr_t object, std::uint32_t attributes,
            addr_t passed_access_state, std::uint32_t access, addr_t object_type,
            std::uint8_t access_mode, emu_object<std::uint64_t> handle) -> NTSTATUS
        {
            if (st->ob_notify.in_callback(cpu.id())) st->fail_ob_notify(cpu, "nested handle operations are unsupported");
            if (access_mode > 1) return STATUS_INVALID_PARAMETER;
            const auto actual = st->ob_object_type(object);
            if (object_type && (actual || object_type == st->ob_process_type || object_type == st->ob_thread_type)
                && object_type != actual) return STATUS_OBJECT_TYPE_MISMATCH;
            if (actual && passed_access_state) return STATUS_NOT_SUPPORTED;
            if (access_mode && (attributes & 0x200u)) return STATUS_INVALID_PARAMETER;
            return st->create_ob_handle(cpu, object, access, attributes, handle,
                1, 0xffffffff, {}, nullptr, nullptr, access_mode);
        });

	state.redirect(mod, "ObReferenceProcessHandleTable",
		[st = &state](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			const auto owner = st->find_process_by_object(process.address());
			if (!owner) return 0;
			const auto address = owner->handle_table().guest_address();
			if (!address) return 0;
			const auto rundown = process.field(&_EPROCESS::RundownProtect);
			if (!st->rundown.acquire(rundown)) return 0;
			if (guest_va(process.field(&_EPROCESS::ObjectTable).read()) != address)
			{
				(void)st->rundown.release(rundown);
				return 0;
			}
			// The release alias is registered by nt_process_ops; no host table reference.
			return address;
		});

	// Windows 10.0.26100: callback(table, entry, handle, context), with entry locked.
	state.redirect(mod, "ExEnumHandleTable",
		[st = &state](vcpu& cpu, const addr_t table_address, const addr_t callback,
			const addr_t context, emu_object<std::uint64_t> found_handle) -> bool
		{
			if (!table_address || !callback) return false;
			const auto selected = st->find_handle_table(table_address);
			if (!selected || !selected->reference()) return false;
			auto& table = *selected;
			struct table_reference
			{
				win_handle_table& table;
				~table_reference() { table.dereference(); }
			} reference{table};
			const auto caller = std::dynamic_pointer_cast<win_thread>(cpu.thread());
			if (!caller || !caller->ethread()) st->fail_ob_notify(cpu, "handle enumeration requires a Windows thread");
			const auto apc_disable = caller->kernel_apc_disable().read();
			if (apc_disable == std::numeric_limits<std::int16_t>::min())
				st->fail_ob_notify(cpu, "handle enumeration critical-region counter overflow");
			struct critical_region
			{
				win_thread& thread;
				std::int16_t previous;
				~critical_region() { thread.kernel_apc_disable().write(previous); }
			} critical{*caller, apc_disable};
			caller->kernel_apc_disable().write(static_cast<std::int16_t>(apc_disable - 1));
			const auto snapshot = table.snapshot();
			auto& space = st->kernel_space();
			for (const auto& item : snapshot)
			{
				if (!item.guest_entry) continue;
				const auto live = table.lookup_handle(item.handle);
				if (!live || live->body_addr != item.entry.body_addr) continue;
				const auto original = space.read_mem<_HANDLE_TABLE_ENTRY>(item.guest_entry);
				if (!original.Unlocked) st->fail_ob_notify(cpu, "nested enumeration of a locked handle entry");
				auto locked = original;
				locked.Unlocked = 0;
				space.write_mem(item.guest_entry, locked);
				auto restore = [&]
				{
					// A callback may close this handle; never resurrect its guest entry.
					if (table.lookup_handle(item.handle)) space.write_mem(item.guest_entry, original);
				};
				bool found = false;
				try
				{
					const std::uint64_t args[] = {table_address, item.guest_entry, item.handle, context};
					const auto sleep = caller ? caller->sleep_until() : thread::time_point{};
					struct callback_scope
					{
						callback_scope() { ++win::ob_callback_depth; }
						~callback_scope() { --win::ob_callback_depth; }
					} callback_guard;
					found = (win::call_with_attachment_checkpoint(st->calls, cpu, callback, args, 0,
						[&] { return cpu.execution_failed() || (caller &&
							(caller->is_finished() || caller->is_waiting() || caller->sleep_until() != sleep)); }) & 0xffu) != 0;
					if (caller->kernel_apc_disable().read() != apc_disable - 1)
						st->fail_ob_notify(cpu, "handle enumeration callback returned with unbalanced critical region");
					if (table.lookup_handle(item.handle))
					{
						const auto after = space.read_mem<_HANDLE_TABLE_ENTRY>(item.guest_entry);
						if (std::memcmp(&after, &original, sizeof(after)) != 0)
							st->fail_ob_notify(cpu, "ExEnumHandleTable callback must unlock entry without changing metadata");
					}
				}
				catch (...) { restore(); throw; }
				restore();
				if (found)
				{
					if (found_handle) found_handle.write(item.handle);
					return true;
				}
			}
			return false;
		});

	// Some PDBs expose this private helper; exported-only images use an inline increment.
	if (mod.find_symbol("ExUnlockHandleTableEntry"))
		state.redirect(mod, "ExUnlockHandleTableEntry",
			[st = &state](vcpu&, addr_t table_address, addr_t entry_address)
			{
				if (const auto table = st->find_handle_table(table_address))
					for (const auto& entry : table->snapshot())
						if (entry.guest_entry == entry_address)
						{
							auto value = st->kernel_space().read_mem<_HANDLE_TABLE_ENTRY>(entry_address);
							value.Unlocked = 1;
							st->kernel_space().write_mem(entry_address, value);
							return;
						}
			});

	// Nothing builds the directories these names would hang off, so opening one makes it.
	auto attribute_name = [](vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
	{
		auto& space = *cpu.curr_addr_space();

		const emu_object<_UNICODE_STRING> name(space, object_attributes
			? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
			: 0);

		return narrow_wstring(win::read_unicode_string(name));
	};

	auto open_namespace_object = [st = &state](vcpu& cpu, std::shared_ptr<win_object> host,
		const std::string& name, const std::uint32_t desired_access, const std::uint32_t attributes) -> std::uint64_t
	{
		if (const auto existing = st->objs.lookup_named_object(name))
			return st->create_handle(cpu, existing, desired_access, attributes);

		const std::array<std::uint8_t, namespace_object_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(), std::move(host),
			prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		st->objs.register_named_object(name, addr);

		return st->create_handle(cpu, addr, desired_access, attributes);
	};

	state.redirect_ntzw(mod, "OpenDirectoryObject",
		[attribute_name, open_namespace_object](vcpu& cpu,
			emu_object<std::uint64_t> directory_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!directory_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = attribute_name(cpu, object_attributes);
			const auto handle = open_namespace_object(cpu, std::make_shared<directory_host>(),
				name, desired_access, object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			directory_handle.write(handle);

			THREAD_LOG_WARN("NtOpenDirectoryObject('{}') -> handle=0x{:X}: the directory is "
				"empty, because nothing here puts anything in one", name, handle);

			return STATUS_SUCCESS;
		});

	// Nothing puts anything in a directory here, so an enumeration of one has nothing to
	// return -- which is a result a caller handles, unlike a failure.
	state.redirect_ntzw(mod, "QueryDirectoryObject",
		[](vcpu&, const std::uint64_t directory_handle, const addr_t buffer,
			const std::uint32_t length, const std::uint8_t return_single_entry,
			const std::uint8_t restart_scan, emu_object<std::uint32_t> context,
			emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			if (context)
				context.write(0);

			if (return_length)
				return_length.write(0);

			THREAD_LOG_WARN("NtQueryDirectoryObject(handle=0x{:X}, buffer=0x{:X}/{}, single={}, "
				"restart={}): the directory is empty",
				directory_handle, buffer, length, return_single_entry != 0, restart_scan != 0);

			return STATUS_NO_MORE_ENTRIES;
		});

	state.redirect_ntzw(mod, "OpenSymbolicLinkObject",
		[attribute_name, open_namespace_object](vcpu& cpu, emu_object<std::uint64_t> link_handle,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!link_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = attribute_name(cpu, object_attributes);

			auto host = std::make_shared<symbolic_link_host>();
			host->target = system32_dir_narrow;

			// Windows spells a device path without the trailing separator.
			if (host->target.size() > 1 && host->target.back() == '\\')
				host->target.pop_back();

			const auto handle = open_namespace_object(cpu, std::move(host), name, desired_access,
				object_attributes ? object_attributes.field(&_OBJECT_ATTRIBUTES::Attributes).read() : 0);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			link_handle.write(handle);

			THREAD_LOG_WARN("NtOpenSymbolicLinkObject('{}') -> handle=0x{:X}: nothing here "
				"creates a link, so it points at System32", name, handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "QuerySymbolicLinkObject",
		[st = &state](vcpu& cpu, const std::uint64_t link_handle,
			emu_object<_UNICODE_STRING> link_target,
			emu_object<std::uint32_t> returned_length) -> NTSTATUS
		{
			const auto host =
				st->get_handle_object<symbolic_link_host>(cpu, link_handle);

			if (!host)
			{
				THREAD_LOG_WARN("NtQuerySymbolicLinkObject: handle 0x{:X} is not a symbolic link",
					link_handle);
				return STATUS_OBJECT_TYPE_MISMATCH;
			}

			const auto target = widen_string(host->target);
			const auto needed = static_cast<std::uint16_t>(target.size() * sizeof(char16_t));

			if (returned_length)
				returned_length.write(needed);

			if (!link_target)
				return STATUS_INVALID_PARAMETER;

			auto value = link_target.read();

			if (value.MaximumLength < needed || !value.Buffer)
				return STATUS_BUFFER_TOO_SMALL;

			link_target.space()->write_mem(guest_va(value.Buffer), target.data(), needed);

			value.Length = needed;
			link_target.write(value);

			THREAD_LOG_INFO("NtQuerySymbolicLinkObject(0x{:X}) -> '{}'", link_handle, host->target);

			return STATUS_SUCCESS;
		});
}
