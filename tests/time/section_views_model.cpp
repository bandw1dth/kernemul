#include "kernel/win/section_views.hpp"
#include <cassert>
#include <atomic>
#include <future>
#include <iostream>

int main()
{
	win::section_views views;
	assert(views.insert(4, 0x1000, 0x2000));
	assert(!views.insert(4, 0x1000, 0x3000));
	assert(views.insert(8, 0x1000, 0x4000));
	assert(!views.remove(12, 0x1000, [](auto) { assert(false); return true; }));
	assert(!views.remove(4, 0x1000, [](auto size) { assert(size == 0x2000); return false; }));
	assert(views.remove(4, 0x1000, [](auto size) { assert(size == 0x2000); return true; }));
	assert(!views.remove(4, 0x1000, [](auto) { assert(false); return true; }));
	assert(views.remove(8, 0x1000, [](auto size) { assert(size == 0x4000); return true; }));
	assert(views.insert(4, 0x1000, 0x2000));
	std::atomic<unsigned> teardown_count{0};
	auto remove = [&] { return views.remove(4, 0x1000, [&](auto) { ++teardown_count; return true; }); };
	auto first = std::async(std::launch::async, remove);
	auto second = std::async(std::launch::async, remove);
	assert(first.get() != second.get());
	assert(teardown_count == 1);
	assert(views.insert(4, 0x2000, 0x2000, true));
	assert(views.insert(4, 0x4000, 0x2000));
	assert(views.overlaps(4, 0x4000, 1)); // ordinary data/image views also block NtFree
	assert(views.overlaps(4, 0x5fff, 1));
	assert(views.overlaps(4, 0x1000, 0x6000));
	assert(!views.overlaps(4, 0x6000, 1));
	assert(!views.overlaps(8, 0x4000, 1));
	assert(!views.overlaps(4, 0x4000, 0));
	assert(!views.execution_blocked(8, 0x2000, 0x1000));
	assert(!views.execution_blocked(4, 0x2000, 0));
	assert(!views.execution_blocked(4, 0x1000, 0x1000));
	assert(!views.execution_blocked(4, 0x4000, 0x1000));
	assert(views.execution_blocked(4, 0x1000, 0x1001));
	assert(views.execution_blocked(4, 0x2000, 1));
	assert(views.execution_blocked(4, 0x3fff, 2));
	assert(views.execution_blocked(4, 0x1000, 0x6000)); // mixed ordinary/NX range
	assert(!views.remove(4, 0x2000, [](auto) { return false; }));
	assert(views.execution_blocked(4, 0x2000, 0x1000));
	assert(views.remove(4, 0x2000, [](auto) { return true; }));
	assert(!views.execution_blocked(4, 0x1000, 0x6000));
	assert(views.insert(4, 0x2000, 0x2000)); // reused base must not retain NX
	assert(!views.execution_blocked(4, 0x2000, 0x1000));
	assert(views.insert(4, ~std::uint64_t{0} - 0x1000, 0x1000, true));
	assert(views.execution_blocked(4, ~std::uint64_t{0} - 0x800, 0x800));
	assert(!views.execution_blocked(4, 0, 0x1000));
	std::cout << "section_views_model: PASS\n";
}
