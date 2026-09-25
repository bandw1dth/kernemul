#include "kernel/win/timer_queue.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>

int main()
{
	win::timer_queue q;
	win::clock_sample now{10000, 100};
	const auto fault = [](const win::timer_queue::entry&) { throw std::runtime_error("guest memory fault"); };
	try { q.set(99, -1, 0, 0, now, fault); assert(false); }
	catch (const std::runtime_error&) {}
	assert(q.size() == 0 && !q.contains(99));
	assert(!q.set(99, -50, 10, 7, now));
	try { q.set(99, 0, 0, 8, now, fault); assert(false); }
	catch (const std::runtime_error&) {}
	assert(q.size() == 1 && q.expire({10000, 149}).empty());
	const auto preserved = q.expire({10000, 150});
	assert(preserved.size() == 1 && preserved[0].dpc == 7 && preserved[0].period == 10);
	assert(q.cancel(99));
	assert(!q.set(1, -50, 0, 7, now));
	assert(q.expire({99999999, 149}).empty()); // Wall jump cannot expire a relative timer.
	auto expired = q.expire({1, 150});
	assert(expired.size() == 1 && expired[0].dpc == 7);
	assert(!q.cancel(1));
	assert(!q.set(1, 20000, 0, 0, now));
	assert(q.expire({19999, 99999}).empty());
	assert(q.expire({20000, 99999}).size() == 1);
	assert(!q.set(1, 0, 0, 0, now));
	assert(q.cancel(1)); // Zero due time is still inserted.
	assert(!q.cancel(1));
	assert(!q.set(1, -10, 0, 0, now));
	assert(q.set(1, -100, 0, 0, now));
	assert(q.expire({10000, 110}).empty());
	assert(q.expire({10000, 200}).size() == 1);
	assert(!q.set(1, 10001, 10, 0, now));
	assert(q.expire({10001, 101}).size() == 1);
	assert(q.expire({UINT64_MAX, 110}).empty()); // Periods after absolute expiry are relative.
	assert(q.expire({0, 145}).size() == 1); // Coalesce missed periods.
	assert(q.expire({0, 150}).empty());
	assert(q.expire({0, 151}).size() == 1);
	assert(q.cancel(1));
	assert(!q.set(2, INT64_MIN, 0, 0, now));
	assert(q.expire({UINT64_MAX, 1000}).empty());
	assert(q.cancel(2));
	assert(win::saturated_add(UINT64_MAX - 2, 3) == UINT64_MAX);
	win::guest_clock clock(500000);
	const auto before = clock.sample();
	clock.set_system_time(1);
	const auto after = clock.sample();
	assert(after.interrupt_time >= before.interrupt_time);
	assert(after.system_time < before.system_time);
	std::cout << "timer_model: PASS\n";
}
