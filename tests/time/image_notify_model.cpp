#include "kernel/win/lifecycle_notify.hpp"
#include "kernel/win/section_image.hpp"
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

int main()
{
	using registry = win::lifecycle_notify_registry;
	using result = registry::remove_result;
	registry a{64}, b{64};
	assert(!a.add(0));
	assert(a.add(0x1000));
	assert(!a.add(0x1000));
	assert(b.add(0x1000)); // Registrations belong to a machine.
	assert(a.remove(0x2000, 0) == result::absent);

	auto stale = a.snapshot();
	assert(a.remove(0x1000, 0) == result::removed);
	assert(!a.acquire(stale.front(), 0)); // Removal cancels not-yet-admitted snapshots.
	assert(a.add(0x1000));
	assert(!a.acquire(stale.front(), 0)); // Re-registration cannot revive an old snapshot.
	auto current = a.snapshot().front();
	assert(a.acquire(current, 0));
	assert(a.acquire(current, 0)); // Nested deliveries count separately.
	assert(a.remove(0x1000, 0) == result::callback_deadlock);
	assert(a.in_callback(0));
	a.release(current, 0);
	assert(a.in_callback(0));

	auto removal = std::async(std::launch::async, [&] { return a.remove(0x1000, 1); });
	// Observe the closed admission gate before checking that removal still waits.
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (a.acquire(current, 2))
	{
		a.release(current, 2);
		assert(std::chrono::steady_clock::now() < deadline);
		std::this_thread::yield();
	}
	assert(removal.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout);
	assert(!a.add(0x1000)); // Address remains reserved through rundown.
	assert(a.remove(0x1000, 0) == result::callback_deadlock); // Even if another CPU is draining it.
	a.release(current, 0);
	assert(removal.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
	assert(removal.get() == result::removed);
	assert(!a.in_callback(0) && !a.has_live());
	bool torn_down = false;
	assert(a.without_live_notifications([&] { torn_down = true; }));
	assert(torn_down);
	assert(!b.without_live_notifications([&] { assert(false); }));

	assert(a.add(0x1000) && a.add(0x2000));
	auto pair = a.snapshot();
	assert(a.acquire(pair[0], 0) && a.acquire(pair[1], 1));
	assert(a.remove(0x2000, 0) == result::callback_deadlock);
	assert(a.remove(0x1000, 1) == result::callback_deadlock);
	a.release(pair[0], 0);
	a.release(pair[1], 1);
	assert(a.remove(0x1000, 0) == result::removed);
	assert(a.remove(0x2000, 0) == result::removed);
	for (std::uint64_t i = 1; i <= 64; ++i) assert(a.add(i));
	assert(!a.add(65));
	assert(a.snapshot().size() == 64);
	assert(a.remove(64, 0) == result::removed);
	assert(a.add(65));
	// A callback from a different lifecycle registry cannot drain a live owner.
	auto live = a.snapshot().front();
	assert(a.acquire(live, 1));
	assert(a.remove(live->routine, 0, true) == result::callback_deadlock);
	a.release(live, 1);
	assert(a.remove(live->routine, 0, true) == result::removed);
	assert(b.snapshot().size() == 1);
	// Exercise hostile PE offsets before any guest allocation or materialization.
	std::vector<std::uint8_t> raw(0x400);
	pe::dos_header dos{};
	dos.magic = pe::dos_header::dos_magic;
	dos.lfanew = 0x80;
	pe::nt_headers nt{};
	nt.signature = pe::nt_headers::nt_signature;
	nt.file_hdr.size_of_optional_header = sizeof(pe::optional_header64);
	nt.file_hdr.number_of_sections = 1;
	nt.optional_hdr.magic = pe::optional_header64::hdr64_magic;
	nt.optional_hdr.size_of_headers = 0x200;
	nt.optional_hdr.size_of_image = 0x2000;
	pe::section_header section{};
	section.virtual_address = 0x1000;
	section.virtual_size = 0x200;
	section.pointer_to_raw_data = 0x200;
	section.size_of_raw_data = 0x200;
	auto write = [&] {
		std::memcpy(raw.data(), &dos, sizeof(dos));
		std::memcpy(raw.data() + 0x80, &nt, sizeof(nt));
		std::memcpy(raw.data() + 0x80 + sizeof(nt), &section, sizeof(section));
	};
	write();
	assert(win::valid_section_image(raw));
	dos.lfanew = 0x7ffffff0; write(); assert(!win::valid_section_image(raw));
	dos.lfanew = -1; write(); assert(!win::valid_section_image(raw));
	dos.lfanew = 0x80; nt.optional_hdr.size_of_image = 0x100; write();
	assert(!win::valid_section_image(raw));
	nt.optional_hdr.size_of_image = 0x2000; nt.file_hdr.number_of_sections = 0xffff; write();
	assert(!win::valid_section_image(raw));
	nt.file_hdr.number_of_sections = 1; section.pointer_to_raw_data = 0xffffff00; write();
	assert(!win::valid_section_image(raw));
	section.pointer_to_raw_data = 0x200; section.virtual_address = 0xfffffff0; write();
	assert(!win::valid_section_image(raw));
	section.virtual_address = 0; write(); assert(!win::valid_section_image(raw));
	section.virtual_address = 0x1000; write();
	assert(!win::valid_section_image(std::span(raw).first(64)));
	assert(win::valid_section_image(raw));
	std::cout << "image_notify_model: PASS\n";
}
