#include "kernel/win/process_notify.hpp"
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

int main()
{
	using registry = win::process_notify_registry;
	using kind = win::process_notify_kind;
	using result = registry::remove_result;

	registry limited;
	assert(!limited.add(0, kind::classic));
	for (std::uint64_t routine = 1; routine <= 64; ++routine)
		assert(limited.add(routine, routine % 2 ? kind::classic : kind::extended));
	assert(!limited.add(65, kind::classic)); // The default limit is shared across both kinds.
	assert(!limited.add(1, kind::extended)); // An address is unique regardless of kind.
	auto limited_entries = limited.snapshot();
	assert(limited_entries.size() == 64);
	for (std::size_t i = 0; i < limited_entries.size(); ++i)
		assert(limited_entries[i]->kind == (i % 2 == 0 ? kind::classic : kind::extended));
	assert(limited.remove(64, kind::extended, 0) == result::removed);
	assert(limited.add(65, kind::extended));

	registry a, b;
	assert(a.add(0x1000, kind::classic));
	assert(!a.add(0x1000, kind::extended));
	assert(b.add(0x1000, kind::extended)); // Registrations belong to a machine.
	assert(a.remove(0x1000, kind::extended, 0) == result::absent); // Wrong kind does not remove it.
	auto classic = a.snapshot().front();
	assert(classic->routine == 0x1000 && classic->kind == kind::classic);
	assert(a.remove(0x2000, kind::classic, 0) == result::absent);
	assert(a.remove(0x1000, kind::classic, 0) == result::removed);
	assert(!a.acquire(classic, 0)); // A stale snapshot cannot be admitted.
	assert(a.add(0x1000, kind::extended));
	auto extended = a.snapshot().front();
	assert(extended->kind == kind::extended);
	assert(!a.acquire(classic, 0)); // Re-registration cannot revive an old snapshot.
	assert(a.remove(0x1000, kind::classic, 0) == result::absent);
	assert(a.has_live());
	assert(a.remove(0x1000, kind::extended, 0) == result::removed);

	// A CPU cannot remove any registration while it owns any process callback.
	assert(a.add(0x1000, kind::classic) && a.add(0x2000, kind::extended));
	auto pair = a.snapshot();
	assert(a.acquire(pair[0], 3));
	assert(a.in_callback(3));
	assert(a.remove(0x2000, kind::extended, 3) == result::callback_deadlock);
	assert(a.remove(0x1000, kind::classic, 3) == result::callback_deadlock); // Self-removal is rejected without waiting.
	a.release(pair[0], 3);
	assert(!a.in_callback(3));
	assert(a.remove(0x1000, kind::classic, 0) == result::removed);
	assert(a.remove(0x2000, kind::extended, 0, true) == result::callback_deadlock);
	assert(a.remove(0x2000, kind::extended, 0) == result::removed);

	// Per-instance callback ownership does not leak between machines.
	assert(a.add(0x3000, kind::classic) && b.add(0x3000, kind::extended));
	auto a_entry = a.snapshot().front();
	assert(a.acquire(a_entry, 4));
	assert(a.in_callback(4) && !b.in_callback(4));
	assert(b.remove(0x3000, kind::extended, 4) == result::removed);
	a.release(a_entry, 4);
	assert(a.remove(0x3000, kind::classic, 4) == result::removed);

	// Removal closes admission first, then waits without holding the registry mutex.
	registry rundown;
	assert(rundown.add(0x4000, kind::classic));
	auto held = rundown.snapshot().front();
	assert(rundown.acquire(held, 0));
	auto removal = std::async(std::launch::async, [&] { return rundown.remove(0x4000, kind::classic, 1); });
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (rundown.acquire(held, 2))
	{
		rundown.release(held, 2);
		assert(std::chrono::steady_clock::now() < deadline);
		std::this_thread::yield();
	}
	assert(removal.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout);
	assert(!rundown.add(0x4000, kind::extended)); // Address remains reserved through rundown.
	assert(rundown.remove(0x4000, kind::classic, 0) == result::callback_deadlock);
	rundown.release(held, 0);
	assert(removal.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
	assert(removal.get() == result::removed);
	assert(!rundown.has_live() && !rundown.in_callback(0));
	assert(!rundown.acquire(held, 0));
	assert(rundown.add(0x4000, kind::extended));
	assert(!rundown.acquire(held, 0)); // The removed snapshot stays inactive after re-registration.

	std::cout << "process_notify_model: PASS\n";
}
