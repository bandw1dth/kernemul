#include "kernel/win/registry_notify.hpp"
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

using service = win::registry_notify_service;
constexpr std::uint32_t wdk_bypass = 0xC0000503u;
static_assert(service::bypass == wdk_bypass);
constexpr std::uint32_t denied = 0xc0000022;
constexpr std::uint32_t missing = 0xc0000034;

static std::int64_t add(service& registry, std::u16string altitude, std::uint64_t routine = 1)
{
	std::int64_t cookie = 0;
	assert(registry.add({routine, routine + 100, std::move(altitude), 2}, [&](auto id) { cookie = id; })
		== service::add_status::success);
	return cookie;
}

static void ordering_and_rollback()
{
	service r;
	add(r, u"9.99", 1);
	add(r, u"10.00000000000000000000001", 3);
	add(r, u"10", 2);
	assert(r.add({1, 0, u"0010.000", 2}, [](auto) {}) == service::add_status::collision);
	for (const auto* invalid : {u"", u".1", u"1.", u"-1", u"1.2.3", u"NaN"})
		assert(r.add({1, 0, invalid, 2}, [](auto) {}) == service::add_status::invalid_altitude);
	assert(r.add({1, 0, u"20", 2}, [](auto) { throw std::runtime_error("bad output"); })
		== service::add_status::output_failed);
	const auto cookie = add(r, u"20", 4);
	assert(r.remove(cookie, false) == service::remove_status::removed);
	assert(r.remove(cookie, false) == service::remove_status::absent);
	std::vector<int> order;
	assert(r.dispatch(0, [&](const auto& e, auto) { order.push_back(static_cast<int>(e->value.function)); return 0u; },
		[] { return 0u; }, [&](const auto& e, auto, auto s) {
			order.push_back(-static_cast<int>(e->value.function)); return service::post_result{0, s};
		}) == 0);
	assert((order == std::vector{3, 2, 1, -1, -2, -3}));
}

static void unwind_and_context()
{
	service r;
	add(r, u"3", 3); add(r, u"2", 2); add(r, u"1", 1);
	for (const auto stopping : {denied, wdk_bypass})
	{
		std::vector<int> order;
		std::vector<std::uint64_t> contexts;
		bool body = false;
		const auto result = r.dispatch(0, [&](const auto& e, auto index) {
			order.push_back(static_cast<int>(e->value.function));
			contexts.push_back(e->value.context + index);
			return index == 1 ? stopping : 0u;
		}, [&] { body = true; return 0u; }, [&](const auto& e, auto index, auto status) {
			assert(index == 0 && contexts[index] == e->value.context);
			assert(status == (stopping == wdk_bypass ? 0u : denied));
			order.push_back(-static_cast<int>(e->value.function));
			return service::post_result{0, missing}; // normal return ignores ReturnStatus
		});
		assert(!body && (order == std::vector{3, 2, -3}));
		assert(result == (stopping == wdk_bypass ? 0u : denied));
	}
	bool committed = false;
	const auto result = r.dispatch(0, [](const auto&, auto) { return 0x106u; }, // STATUS_NOT_ALL_ASSIGNED is not bypass
		[&] { committed = true; return 0u; }, [](const auto&, auto index, auto status) {
			if (index == 2) return service::post_result{wdk_bypass, denied};
			assert(status == denied);
			return service::post_result{missing, 0}; // failing post is ignored too
		});
	assert(committed && result == denied);
}

static void nesting()
{
	service r;
	const auto top = add(r, u"100", 3); add(r, u"20", 2); add(r, u"3", 1);
	auto nested = [&](int invoking) {
		std::vector<int> called;
		r.dispatch(0, [&](const auto& e, auto) { called.push_back(static_cast<int>(e->value.function)); return 0u; },
			[] { return 0u; }, [](const auto&, auto, auto s) { return service::post_result{0, s}; });
		const auto expected = invoking == 3 ? std::vector{2, 1} : invoking == 2 ? std::vector{1} : std::vector<int>{};
		assert(called == expected);
	};
	r.dispatch(0, [&](const auto& e, auto) {
		assert(r.in_callback(0));
		assert(r.remove(top, true) == service::remove_status::callback_deadlock);
		nested(static_cast<int>(e->value.function)); return 0u;
	}, [] { return 0u; }, [&](const auto& e, auto, auto s) {
		nested(static_cast<int>(e->value.function)); return service::post_result{0, s};
	});
	assert(!r.in_callback(0));
	assert(r.remove(top, false) == service::remove_status::removed);
}

static void rundown()
{
	service r;
	const auto id = add(r, u"10");
	std::promise<void> in_body, finish_body, in_post, finish_post;
	auto body_gate = finish_body.get_future();
	auto post_gate = finish_post.get_future();
	auto operation = std::async(std::launch::async, [&] {
		return r.dispatch(0, [](const auto&, auto) { return 0u; }, [&] {
			in_body.set_value(); body_gate.wait(); return 0u;
		}, [&](const auto&, auto, auto s) {
			in_post.set_value(); post_gate.wait(); return service::post_result{0, s};
		});
	});
	in_body.get_future().wait();
	auto removal = std::async(std::launch::async, [&] { return r.remove(id, false); });
	// Observe deactivation without assuming host scheduling or sleeping a fixed duration.
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	for (;;)
	{
		bool admitted = false;
		r.dispatch(1, [&](const auto&, auto) { admitted = true; return 0u; }, [] { return 0u; },
			[](const auto&, auto, auto s) { return service::post_result{0, s}; });
		if (!admitted) break;
		assert(std::chrono::steady_clock::now() < deadline);
		std::this_thread::yield();
	}
	assert(removal.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout);
	assert(r.add({1, 0, u"10.0", 2}, [](auto) {}) == service::add_status::collision);
	finish_body.set_value();
	in_post.get_future().wait();
	assert(removal.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout);
	finish_post.set_value();
	assert(operation.get() == 0);
	assert(removal.get() == service::remove_status::removed);
	const auto after_rundown = add(r, u"10");
	try
	{
		r.dispatch(0, [](const auto&, auto) -> std::uint32_t { throw std::runtime_error("fault"); },
			[] { return 0u; }, [](const auto&, auto, auto s) { return service::post_result{0, s}; });
		assert(false);
	}
	catch (const std::runtime_error&) {}
	assert(!r.in_callback(0));
	assert(r.remove(after_rundown, false) == service::remove_status::removed);
}

int main()
{
	ordering_and_rollback(); unwind_and_context(); nesting(); rundown();
	std::cout << "registry_notify_model: PASS\n";
}
