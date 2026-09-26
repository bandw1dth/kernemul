#include "kernel/win/registry.hpp"
#include "kernel/win/registry_notify.hpp"
#include <cassert>
#include <future>
#include <iostream>

int main()
{
	win_registry store;
	auto key = store.create_key("system/model");
	key->set_dword("value", 1);
	const auto captured = key->copy_value("value");
	assert(captured && captured->data[0] == 1);
	win::registry_notify_service filters;
	assert(filters.add({1, 0, u"10", 2}, [](auto) {}) == win::registry_notify_service::add_status::success);
	assert(filters.dispatch(0, [&](const auto&, auto) {
		// A nested pre write precedes the outer query's BODY snapshot.
		return filters.dispatch(0, [](const auto&, auto) { assert(false); return 0u; },
			[&] { key->set_dword("value", 2); return 0u; },
			[](const auto&, auto, auto s) { return win::registry_notify_service::post_result{0, s}; });
	}, [&] {
		const auto observed = key->copy_value("value");
		assert(observed && observed->data[0] == 2);
		return 0u;
	}, [&](const auto&, auto, auto s) {
		assert(key->delete_value("value"));
		// Previously copied query results survive post deletion/reallocation.
		assert(captured->data[0] == 1);
		return win::registry_notify_service::post_result{0, s};
	}) == 0);
	assert(!key->copy_value("value"));
	assert(store.delete_key("system/model"));
	// An open host key remains usable after namespace removal.
	key->set_dword("retained", 7);
	assert(key->copy_value("retained")->data[0] == 7);
	const std::vector<std::uint8_t> first(2048, 0x55), second(8192, 0xaa);
	key->set_binary("shared", first);
	auto writer = std::async(std::launch::async, [&] {
		for (int i = 0; i < 2000; ++i) key->set_binary("shared", i % 2 ? first : second);
	});
	for (int i = 0; i < 2000; ++i)
	{
		const auto value = key->copy_value("shared");
		assert(value && (value->data == first || value->data == second));
	}
	writer.get();
	assert(captured->data[0] == 1);
	std::cout << "registry_value_model: PASS\n";
}
