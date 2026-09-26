#include "boot_seed.hpp"
#include "storage_device.hpp"
#include "win_kernel.hpp"
#include "process_params.hpp"
#include "../../util/log.hpp"

#include <string>

// Nothing in the emulator itself reads the registry -- it exists purely as a guest visible store
// -- so what belongs here is decided entirely by what real drivers look for. Keys are stored
// exactly as win_registry::normalize_path leaves a guest path: lowercase, forward slashes, hive
// prefix stripped, no leading or trailing slash. win_registry does no folding of its own, so a
// seed spelled any other way would simply never be found.
//
// Value names are the opposite: query_value is a raw lookup on the name the guest spells, so
// those keep their real Windows casing.

namespace
{

constexpr std::string_view control_key = "system/currentcontrolset/control";

}

void win::seed_registry(win_kernel_state& state)
{
	auto& reg = state.reg;

	static_cast<void>(reg.create_key(control_key));

	// Code integrity. A driver reading this is asking whether it is being watched.
	reg.create_key(std::string(control_key) + "/ci")->set_dword("Protected", 0);

	static_cast<void>(reg.create_key(std::string(control_key) + "/wmi/restrictions"));

	// On builds where the key is absent the segment heap is the default, and it wants
	// ProcessPrng out of bcryptprimitives before it can encode its keys.
	reg.create_key(std::string(control_key) + "/session manager/segment heap")
		->set_dword("Enabled", 0);

	reg.create_key(std::string(control_key))
		->set_string("SystemStartOptions", u"NOEXECUTE=OPTIN");

	// The build here has to agree with what ntoskrnl reported, or a driver that reads the
	// registry and a driver that calls RtlGetVersion disagree about which Windows this is.
	{
		const auto ver = reg.create_key("software/microsoft/windows nt/currentversion");
		const auto build = std::to_string(state.nt_build_number);

		ver->set_string("CurrentBuildNumber", build);
		ver->set_string("CurrentVersion", "6.3");
		ver->set_string("ProductName", "Windows 10 Pro");
		ver->set_string("BuildLab", build + ".amd64fre.vb_release.191206-1406");
		ver->set_string("SystemRoot", std::string(windows_dir_narrow));
	}

	// Certificate stores. Empty is a legitimate answer; absent is not, because the caller
	// cannot tell "no certificates" from "no such key".
	for (const std::string_view store : {
		"software/microsoft/systemcertificates/root/certificates",
		"software/microsoft/systemcertificates/authroot/certificates",
		"software/microsoft/systemcertificates/authroot/autoupdate",
		"software/microsoft/systemcertificates/ca/certificates",
		"software/microsoft/systemcertificates/flightroot/certificates",
	})
	{
		static_cast<void>(reg.create_key(store));
	}

	// Device enumeration roots, so a walk over them finds an empty list rather than nothing.
	static_cast<void>(reg.create_key("system/currentcontrolset/enum/pci"));
	static_cast<void>(reg.create_key("system/currentcontrolset/enum/display"));

	// RtlQueryRegistryValues resolves a relative path against one of these, so each has to be
	// openable even when it holds nothing.
	static_cast<void>(reg.create_key("system/currentcontrolset/services"));
	static_cast<void>(reg.create_key("hardware/devicemap"));

	LOG_INFO("registry: seeded boot state, build {}", state.nt_build_number);
}

void win::seed_filesystem(win_kernel_state& state)
{
	auto& fs = state.fs;

	// load_dir mirrors a flat host directory into system32, so these have no files under them
	// and would not otherwise exist. A driver that stats \SystemRoot before writing into it
	// gets a real answer now.
	for (const std::string_view dir : {
		"c:/windows",
		"c:/windows/system32",
		"c:/windows/system32/drivers",
		"c:/windows/system32/catroot",
		"c:/windows/inf",
		"c:/windows/temp",
		"c:/windows/prefetch",
	})
	{
		fs.create_directory(dir);
	}

	LOG_INFO("filesystem: seeded boot directories");
}

void win::seed_storage_device(win_kernel_state& state)
{
    auto& space = state.kernel_space();
    auto driver = make_default_driver_object({});
    const auto driver_address = state.objs.create_object(0, &driver, sizeof(driver),
        std::make_shared<win_object>(), prot_rw | prot_supervisor);
    _DEVICE_OBJECT device{};
    device.Type = io_type_device;
    device.Size = sizeof(device);
    device.DriverObject = reinterpret_cast<_DRIVER_OBJECT*>(driver_address);
    device.DeviceType = 7; // FILE_DEVICE_DISK
    device.StackSize = 1;
    device.SectorSize = 512;
    auto host = std::make_shared<device_host>();
    host->driver_object = driver_address;
    host->name = "\\Device\\Harddisk0\\DR0";
    host->builtin = make_storage_device();
    const auto address = state.objs.create_object(0, &device, sizeof(device), host,
        prot_rw | prot_supervisor);
    space.write_mem<addr_t>(driver_address + offsetof(_DRIVER_OBJECT, DeviceObject), address);
    state.register_device(host->name, address);
    state.register_device_link("\\DosDevices\\PhysicalDrive0", host->name);
    state.register_device_link("\\GLOBAL??\\PhysicalDrive0", host->name);
}
