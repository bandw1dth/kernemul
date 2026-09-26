#include "target.hpp"
#include "kernel/map.hpp"
#include "kernel/win/win_kernel.hpp"
#include "emu/calling_conv.hpp"
#include "util/log.hpp"
#include "util/string.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "emu/guest_emu.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "kernel/win/arm64_win.hpp"
	#include "emu/arm64/mmu.hpp"
	#include "emu/arm64/calling_conv.hpp"

	namespace guest
	{
		using mmu          = arm64::mmu;
		using calling_conv = arm64_win_conv;
		using win_emulator = arm64_win_emulator;
	}
#else
	#include "kernel/win/x86_win.hpp"
	#include "emu/x86/mmu.hpp"
	#include "emu/x86/calling_conv.hpp"

	namespace guest
	{
		using mmu          = x86::mmu;
		using calling_conv = x86_win_conv;
		using win_emulator = x86_win_emulator;
	}
#endif

namespace
{

struct guest_image
{
	std::string name;
	bool driver = false;

	std::shared_ptr<thread> entry;
};

void print_usage()
{
	LOG_INFO("usage: kernemul [image...]");
	LOG_INFO("examples:");
	LOG_INFO("  kernemul test_driver.sys");
	LOG_INFO("  kernemul test_printf.exe test_seh.exe");
	LOG_INFO("  kernemul test_driver.sys test_user.exe");
}

std::shared_ptr<thread> setup_driver(guest::win_emulator& win,
	const std::shared_ptr<guest::calling_conv>& conv, vcpu& cpu, const std::string& name)
{
	auto& kernel = win.kernel();
	auto& proc = *kernel.sys_proc;

	const auto driver = krnl::map_img(proc, std::string(target::guest_fs_dir) + name, true);

	if (!driver)
	{
		LOG_ERR("failed to map {}", name);
		return {};
	}

	// Up to the first dot, not the last: a variant build is named <service>.<variant>.sys, and
	// stem() would make vgk.calvin.sys a service called "vgk.calvin" that no driver expects.
	const auto file = std::filesystem::path(name).filename().string();
	const auto service = widen_string(file.substr(0, file.find('.')));

	const auto args = kernel.create_driver(*driver, service);

	const auto entry = win.create_kernel_thread(cpu, driver->entry_point);

	if (!entry)
	{
		LOG_ERR("failed to create a thread for {}", name);
		return {};
	}

	conv->set_arg(cpu, *entry, 0, args.driver_object.address());
	conv->set_arg(cpu, *entry, 1, args.registry_path.address());

	return entry;
}


}

int main(const int argc, const char* const* const argv)
{
	LOG_INFO("kernemul targeting {}", target::name);

	std::vector<std::string> names(argv + 1, argv + argc);

	if (names.empty())
	{
		print_usage();
		return 1;
	}

	std::vector<guest_image> images;
	images.reserve(names.size());

	for (auto& name : names)
	{
		if (!std::filesystem::exists(std::string(target::guest_fs_dir) + name))
		{
			LOG_ERR("{} is not in {}", name, target::guest_fs_dir);
			return 1;
		}

		const bool driver = name.ends_with(".sys");

		images.push_back({ std::move(name), driver, {} });
	}

	auto mem = std::make_shared<guest::mmu>();
	auto conv = std::make_shared<guest::calling_conv>();
	auto e = make_guest_emu(mem, conv);

	guest::win_emulator win(e);

	win.create_vcpus(vcpu_count);

	const auto cpu = win.cpus().front();

	set_log_cpu(cpu.get());

	// Every DriverEntry is queued before any user launcher is made runnable.
	for (auto& image : images)
	{
		if (!image.driver) continue;
		image.entry = setup_driver(win, conv, *cpu, image.name);
		if (!image.entry) return 1;
	}

	std::atomic<bool> driver_failed{false};
	std::atomic<bool> launch_setup_failed{false};
	for (auto& image : images)
	{
		if (image.driver) continue;
		// An internal executable hook address, never a fabricated kernel export.
		const auto stub = e->default_addr_space()->alloc(0x1000, prot_rx | prot_supervisor);
		if (!stub) return 1;
		e->hook_code(stub, stub, [&win, &images, &driver_failed, &launch_setup_failed, name = image.name](vcpu& c, addr_t, std::size_t) {
			bool waiting = false;
			for (const auto& driver : images)
			{
				if (!driver.driver) continue;
				const auto entry = std::dynamic_pointer_cast<win_thread>(driver.entry);
				if (!entry || !entry->is_finished()) { waiting = true; continue; }
				if (entry->exit_status() & 0x80000000u) driver_failed = true;
			}
			if (driver_failed)
			{
				LOG_ERR("{} not launched: driver initialization failed", name);
				win.kernel().finish_thread(c, STATUS_UNSUCCESSFUL);
				c.stop();
				return;
			}
			if (waiting)
			{
				c.thread()->sleep_for(std::chrono::milliseconds(1));
				c.stop();
				return;
			}
			const auto app = win.create_user_process(c, name);
			LOG_INFO("launch {}: status=0x{:08X}", name, app.status);
			if ((app.status & 0x80000000u) && !app.admission_vetoed)
				launch_setup_failed = true;
			// An admission veto is an individual launch outcome. Other queued
			// launches and already accepted applications keep running.
			win.kernel().finish_thread(c, STATUS_SUCCESS);
			c.stop();
		});
		image.entry = win.create_kernel_thread(*cpu, stub);
		if (!image.entry) return 1;
	}

	try { win.run_all(); }
	catch (const std::exception& error)
	{
		LOG_ERR("emulation failed: {}", error.what());
		return 1;
	}

	bool failed = driver_failed || launch_setup_failed || win.scheduler().stopped();
	for (const auto& image : images)
	{
		if (image.driver)
		{
			const auto entry = std::dynamic_pointer_cast<win_thread>(image.entry);
			const bool finished = entry && entry->is_finished();
			const auto status = finished ? entry->exit_status() : STATUS_UNSUCCESSFUL;
			LOG_INFO("{} returned, status=0x{:X}", image.name, status);
			if (!finished || (status & 0x80000000u)) failed = true;
		}
		else LOG_INFO("{} launch completed", image.name);
	}
	return failed ? 1 : 0;
}
