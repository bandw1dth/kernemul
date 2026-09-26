#include "kernel/win/ob_notify.hpp"
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

using service = win::ob_notify_service;
static addr_t add(service& s, std::u16string altitude, addr_t type = 10,
    unsigned operations = 3, bool pre = true)
{
    addr_t id = 0;
    assert(s.add({0x100, 123, std::move(altitude), {{1, type, operations, pre ? 1u : 0u, 2}}},
        [&](auto cookie) { id = cookie; }) == service::add_status::success);
    return id;
}
static void matching_order_and_rights()
{
    service s;
    const auto low = add(s, u"9.9");
    const auto high = add(s, u"10");
    add(s, u"100", 11); // wrong object
    add(s, u"200", 10, 2); // wrong operation
    const auto post_only = add(s, u"9", 10, 1, false);
    assert(s.add({0x100, 0, u"0010.000", {{1, 10, 1, 1, 2}}}, [](auto) {}) == service::add_status::collision);
    assert(s.add({0x100, 0, u"invalid", {{1, 10, 1, 1, 2}}}, [](auto) {}) == service::add_status::invalid_altitude);
    assert(s.add({0x100, 0, u"3", {{1, 10, 1, 1, 2}}}, [](auto) { throw 1; }) == service::add_status::output_failed);
    assert(s.add({0x100, 0, u"3", {{1, 10, 1, 1, 2}, {1, 10, 2, 1, 2}}}, [](auto) {}) == service::add_status::invalid_registration);
    std::vector<addr_t> before, after, contexts;
    auto access = 0x31u; // terminate, read, write
    s.dispatch(0, 10, 1, [&](const auto& e, const auto& op, auto i) {
        contexts.push_back(op.pre_operation ? e->cookie + i : 0);
        if (!op.pre_operation) return;
        before.push_back(e->cookie);
        if (e->cookie == high) access = win::ob_reduce_access(access, 0, win::ob_process_modifiable);
        else access = win::ob_reduce_access(access, 0xffffffff, win::ob_process_modifiable);
    }, [&] { assert(access == 0x10); return 0u; }, [&](const auto& e, const auto& op, auto i, auto status) {
        assert(!status && contexts[i] == (op.pre_operation ? e->cookie + i : 0));
        after.push_back(e->cookie);
    });
    assert((before == std::vector<addr_t>{high, low}));
    assert((after == std::vector<addr_t>{post_only, low, high}));
    static_assert(win::ob_process_modifiable == 0xbebu);
    static_assert(win::ob_thread_modifiable == 0x7b3u);
    // Duplicate SAME_ACCESS starts with the reduced source; cannot resurrect it.
    assert(win::ob_reduce_access(access, 0xffffffff, win::ob_process_modifiable) == 0x10);
    assert(win::ob_reduce_access(0x51, 0, win::ob_thread_modifiable) == 0x40);
}
static void rundown_and_failure()
{
    service s;
    const auto id = add(s, u"1");
    std::promise<void> in_body, release_body, in_post, release_post;
    auto body_gate = release_body.get_future(), post_gate = release_post.get_future();
    auto operation = std::async(std::launch::async, [&] {
        s.dispatch(0, 10, 1, [&](const auto&, const auto&, auto) {
            assert(s.remove(id, true) == service::remove_status::callback_deadlock);
            bool nested = false;
            try { s.dispatch(0, 10, 1, [](auto&&...) {}, [] { return 0u; }, [](auto&&...) {}); }
            catch (const std::runtime_error&) { nested = true; }
            assert(nested);
        }, [&] { in_body.set_value(); body_gate.wait(); return 0xc0000001u; },
        [&](const auto&, const auto&, auto, auto status) {
            assert(status == 0xc0000001u);
            in_post.set_value(); post_gate.wait();
        });
    });
    in_body.get_future().wait();
    auto remove = std::async(std::launch::async, [&] { return s.remove(id, false); });
    assert(remove.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
    release_body.set_value();
    in_post.get_future().wait();
    assert(remove.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
    release_post.set_value();
    operation.get();
    assert(remove.get() == service::remove_status::removed);
    bool called = false;
    s.dispatch(1, 10, 1, [&](auto&&...) { called = true; }, [] { return 0u; }, [](auto&&...) {});
    assert(!called);
    const auto other = add(s, u"1");
    try { s.dispatch(0, 10, 1, [](auto&&...) { throw 1; }, [] { return 0u; }, [](auto&&...) {}); }
    catch (int) {}
    assert(!s.in_callback(0) && s.remove(other, false) == service::remove_status::removed);
}
int main()
{
    matching_order_and_rights();
    rundown_and_failure();
    std::cout << "ob_notify_model: PASS\n";
}
