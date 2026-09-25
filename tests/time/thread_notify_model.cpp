#include "kernel/win/thread_notify.hpp"
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

int main()
{
	using registry = win::thread_notify_registry;
	using result = registry::remove_result;
	registry a, b;
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
	for (std::uint64_t i = 1; i <= 256; ++i) assert(a.add(i)); // No invented 64-entry cap.
	assert(a.snapshot().size() == 256);
	assert(b.snapshot().size() == 1);
	std::cout << "thread_notify_model: PASS\n";
}
