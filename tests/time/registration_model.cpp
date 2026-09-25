#include "kernel/win/callback_registry.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>

int main()
{
    using namespace win::callbacks;
    registry<std::int64_t, cm_registration> a(1), b(1);
    cm_registration entry{0x1000, 0x2000, u"13371", 0x3000};
    std::int64_t id = 0;
    auto result = a.insert(entry, [&](auto value) { id = value; });
    assert(result.status == insert_status::success && id == 1);
    entry.context = 99;
    assert(a.find(id)->value.context == 0x2000); // Caller storage is not the registry.
    assert(a.insert(entry, [](auto) {}).status == insert_status::altitude_collision);
    assert(b.insert(entry, [](auto) {}).id == 1); // No process-global cookie allocator.
    auto snapshot = a.snapshot();
    assert(a.unregister(id));
    assert(!snapshot.front()->active && !a.find(id));
    assert(!a.unregister(id));
    result = a.insert(entry, [](auto) { throw std::runtime_error("guest write failed"); });
    assert(result.status == insert_status::output_write_failed && a.snapshot().empty());
    result = a.insert(entry, [&](auto value) { id = value; });
    assert(result.status == insert_status::success && id != 1); // No stale-handle reuse.
    assert(a.find(id)->value.context == 99);
    std::cout << "registration_model: PASS\n";
}
