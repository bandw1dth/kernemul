#pragma once
#include "registry_notify.hpp"
#include <stdexcept>

namespace win
{
inline thread_local unsigned ob_callback_depth = 0;

// WDK process/thread pre-operation writable rights. All other bits survive.
inline constexpr std::uint32_t ob_process_modifiable = 0x0001 | 0x0002 | 0x0008
    | 0x0020 | 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x0800;
inline constexpr std::uint32_t ob_thread_modifiable = 0x0001 | 0x0002 | 0x0010
    | 0x0020 | 0x0080 | 0x0100 | 0x0200 | 0x0400;
inline std::uint32_t ob_reduce_access(std::uint32_t current, std::uint32_t requested,
    std::uint32_t modifiable)
{ return current & (requested | ~modifiable); }

class ob_notify_service
{
public:
    struct record
    {
        const addr_t cookie;
        const callbacks::ob_registration value;
        const registry_altitude altitude;
        record(addr_t id, callbacks::ob_registration v, registry_altitude a)
            : cookie(id), value(std::move(v)), altitude(std::move(a)) {}
    private:
        friend class ob_notify_service;
        bool active = true;
        std::size_t admitted = 0;
    };
    using entry = std::shared_ptr<record>;
    enum class add_status { success, invalid_altitude, invalid_registration, collision, output_failed, exhausted };
    enum class remove_status { removed, absent, callback_deadlock };
    template <typename Output>
    add_status add(callbacks::ob_registration value, Output&& output)
    {
        auto altitude = registry_altitude::parse(value.altitude);
        if (!altitude) return add_status::invalid_altitude;
        if (value.version != 0x100 || value.operations.empty()) return add_status::invalid_registration;
        for (std::size_t i = 0; i < value.operations.size(); ++i)
        {
            const auto& op = value.operations[i];
            if (!op.type || !op.operations || (op.operations & ~3u)
                || (!op.pre_operation && !op.post_operation)) return add_status::invalid_registration;
            for (std::size_t j = 0; j < i; ++j)
                if (value.operations[j].type == op.type) return add_status::invalid_registration;
        }
        std::lock_guard lock(mutex_);
        for (const auto& e : entries_) if (e->altitude == *altitude) return add_status::collision;
        if (next_ == std::numeric_limits<addr_t>::max()) return add_status::exhausted;
        auto e = std::make_shared<record>(next_++, std::move(value), std::move(*altitude));
        entries_.push_back(e);
        try { output(e->cookie); }
        catch (...) { entries_.pop_back(); return add_status::output_failed; }
        std::ranges::sort(entries_, [](const auto& a, const auto& b) { return b->altitude < a->altitude; });
        return add_status::success;
    }
    bool in_callback(std::size_t cpu) const
    {
        std::lock_guard lock(mutex_);
        return invoking_.contains(cpu);
    }
    remove_status remove(addr_t cookie, bool from_callback)
    {
        std::unique_lock lock(mutex_);
        if (from_callback) return remove_status::callback_deadlock;
        const auto it = std::ranges::find_if(entries_, [=](const auto& e) { return e->cookie == cookie; });
        if (it == entries_.end() || !(*it)->active) return remove_status::absent;
        auto e = *it;
        e->active = false;
        drained_.wait(lock, [&] { return e->admitted == 0; });
        std::erase(entries_, e);
        return remove_status::removed;
    }

    // Emulator convention: descending pre, reverse post; admission spans body
    // and post, including post-only records. No recursive handle operations.
    template <typename Pre, typename Body, typename Post>
    std::uint32_t dispatch(std::size_t cpu, addr_t type, std::uint32_t operation,
        Pre&& pre, Body&& body, Post&& post)
    {
        struct admitted_entry { entry registration; const callbacks::ob_operation* operation; };
        std::vector<admitted_entry> admitted;
        {
            std::lock_guard lock(mutex_);
            if (invoking_.contains(cpu)) throw std::runtime_error("ob notify: nested handle operation");
            for (const auto& e : entries_) if (e->active)
                for (const auto& op : e->value.operations)
                    if (op.type == type && (op.operations & operation)) admitted.push_back({e, &op});
            invoking_.emplace(cpu, true);
            for (const auto& e : admitted) ++e.registration->admitted;
        }
        struct rundown
        {
            ob_notify_service& service;
            std::size_t cpu;
            std::vector<admitted_entry>& entries;
            ~rundown()
            {
                std::lock_guard lock(service.mutex_);
                for (const auto& e : entries) --e.registration->admitted;
                service.invoking_.erase(cpu);
                service.drained_.notify_all();
            }
        } release{*this, cpu, admitted};
        for (std::size_t i = 0; i < admitted.size(); ++i)
            pre(admitted[i].registration, *admitted[i].operation, i);
        const auto status = body();
        for (std::size_t i = admitted.size(); i; --i)
            post(admitted[i-1].registration, *admitted[i-1].operation, i-1, status);
        return status;
    }
private:
    mutable std::mutex mutex_;
    std::condition_variable drained_;
    std::vector<entry> entries_;
    std::unordered_map<std::size_t, bool> invoking_;
    addr_t next_ = 0x10000;
};
}
