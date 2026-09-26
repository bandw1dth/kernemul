#include "nt_timer_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../status.hpp"
#include <limits>
#include <unordered_set>

void modules::register_ntoskrnl_timer_ops(win_kernel_state& state, proc_module& mod)
{
    auto* st = &state;
    state.redirect(mod, "KeInitializeDpc", [st](vcpu&, emu_object<_KDPC> dpc,
        addr_t routine, addr_t context) {
        if (!dpc) return;
        st->remove_dpc(dpc.address());
        _KDPC out{};
        out.Type = 19;
        out.Importance = 1;
        out.DeferredRoutine = guest_ptr<void>(routine);
        out.DeferredContext = guest_ptr<void>(context);
        dpc.write(out);
        THREAD_LOG_INFO("KeInitializeDpc(0x{:X}, routine=0x{:X}, context=0x{:X})", dpc.address(), routine, context);
    });
    state.redirect(mod, "KeInsertQueueDpc", [st](vcpu&, emu_object<_KDPC> dpc,
        addr_t arg1, addr_t arg2) -> bool { return st->insert_dpc(dpc, arg1, arg2); });
    state.redirect(mod, "KeRemoveQueueDpc", [st](vcpu&, addr_t dpc) -> bool {
        return st->remove_dpc(dpc);
    });
    state.redirect(mod, "KeFlushQueuedDpcs", [st](vcpu& cpu) {
        if (st->emulator()->irql(cpu) != passive_level)
            throw std::runtime_error("KeFlushQueuedDpcs requires PASSIVE_LEVEL");
        THREAD_LOG_INFO("KeFlushQueuedDpcs begin: cpu={} irql={}", cpu.id(), st->emulator()->irql(cpu));
        st->dispatch_dpcs(cpu, true);
        THREAD_LOG_INFO("KeFlushQueuedDpcs end: cpu={} stopped={}", cpu.id(), st->sys_proc->scheduler()->stopped());
    });
    const auto init_timer = [st](emu_object<_KTIMER> timer, std::uint32_t type) {
        if (!timer) return;
        std::scoped_lock lock(st->timer_mutex, win::dispatcher_mutex);
        st->cancel_timer(timer.address());
        timer.write(_KTIMER{});
        win::init_dispatcher(timer, type == 1 ? win::timer_synchronization_object
            : win::timer_notification_object, 0);
        THREAD_LOG_INFO("Timer initialized: timer=0x{:X} type={}", timer.address(), type == 1 ? "synchronization" : "notification");
    };
    state.redirect(mod, "KeInitializeTimer", [init_timer](vcpu&, emu_object<_KTIMER> timer) {
        init_timer(timer, 0);
    });
    state.redirect(mod, "KeInitializeTimerEx", [init_timer](vcpu&, emu_object<_KTIMER> timer,
        std::uint32_t type) { init_timer(timer, type); });
    state.redirect(mod, "KeSetTimer", [st](vcpu&, emu_object<_KTIMER> timer,
        std::int64_t due, emu_object<_KDPC> dpc) -> bool {
        return timer && st->set_timer(timer, due, 0, dpc.address());
    });
    state.redirect(mod, "KeSetTimerEx", [st](vcpu&, emu_object<_KTIMER> timer,
        std::int64_t due, std::int32_t period, emu_object<_KDPC> dpc) -> bool {
        if (period < 0) throw std::runtime_error("negative KeSetTimerEx period");
        return timer && st->set_timer(timer, due, static_cast<std::uint64_t>(period) * 10000, dpc.address());
    });
    state.redirect(mod, "KeCancelTimer", [st](vcpu&, addr_t timer) -> bool {
        return timer && st->cancel_timer(timer);
    });
    state.redirect(mod, "KeReadStateTimer", [](vcpu&, emu_object<_KTIMER> timer) -> bool {
        std::scoped_lock lock(win::dispatcher_mutex);
        const bool signalled = timer && win::signal_state(timer) != 0;
        THREAD_LOG_INFO("KeReadStateTimer(0x{:X}) -> {}", timer.address(), signalled);
        return signalled;
    });

    // Timer2 handles must be ours, not merely any handle to a dispatcher-shaped body.
    auto timer2 = std::make_shared<std::unordered_set<addr_t>>();
    state.redirect_ntzw(mod, "CreateTimer2", [st, timer2, init_timer](vcpu& cpu,
        emu_object<std::uint64_t> handle, addr_t reserved1, addr_t reserved2,
        std::uint32_t attributes, std::uint32_t access) -> NTSTATUS {
        if (!handle || reserved1 || reserved2) return STATUS_INVALID_PARAMETER;
        if (attributes & ~1u) return STATUS_NOT_SUPPORTED;
        const _KTIMER zero{};
        const auto addr = st->objs.create_object(0, &zero, sizeof(zero), {}, prot_rw | prot_supervisor);
        if (!addr) return STATUS_INSUFFICIENT_RESOURCES;
        init_timer(emu_object<_KTIMER>(*cpu.curr_addr_space(), addr), attributes & 1);
        const auto created = st->create_handle(cpu, addr, access);
        if (!created) return STATUS_INSUFFICIENT_RESOURCES;
        try
        {
            { std::scoped_lock lock(st->timer_mutex); timer2->insert(addr); }
            handle.write(created);
        }
        catch (...)
        {
            { std::scoped_lock lock(st->timer_mutex); timer2->erase(addr); }
            st->close_handle(cpu, created, 0);
            return STATUS_ACCESS_VIOLATION;
        }
        return STATUS_SUCCESS;
    });
    state.redirect_ntzw(mod, "SetTimer2", [st, timer2](vcpu& cpu, std::uint64_t handle,
        emu_object<std::int64_t> due, emu_object<std::int64_t> period, addr_t parameters) -> NTSTATUS {
        std::scoped_lock lock(st->timer_mutex);
        const auto entry = st->lookup_handle(cpu, handle);
        if (!entry) return STATUS_INVALID_HANDLE;
        if (!timer2->contains(entry->body_addr)) return STATUS_OBJECT_TYPE_MISMATCH;
        if (!due) return STATUS_INVALID_PARAMETER;
        // Coalescing/tolerable-delay parameter blocks are deliberately unsupported.
        if (parameters) return STATUS_NOT_SUPPORTED;
        const auto interval = period ? period.read() : 0;
        if (interval < 0) return STATUS_INVALID_PARAMETER;
        if (interval / 10000 > UINT32_MAX) return STATUS_NOT_SUPPORTED;
        st->set_timer(emu_object<_KTIMER>(*cpu.curr_addr_space(), entry->body_addr),
            due.read(), static_cast<std::uint64_t>(interval), 0);
        return STATUS_SUCCESS;
    });
    state.redirect_ntzw(mod, "CancelTimer2", [st, timer2](vcpu& cpu, std::uint64_t handle,
        addr_t parameters) -> NTSTATUS {
        std::scoped_lock lock(st->timer_mutex);
        const auto entry = st->lookup_handle(cpu, handle);
        if (!entry) return STATUS_INVALID_HANDLE;
        if (!timer2->contains(entry->body_addr)) return STATUS_OBJECT_TYPE_MISMATCH;
        if (parameters) return STATUS_NOT_SUPPORTED;
        st->cancel_timer(entry->body_addr);
        return STATUS_SUCCESS;
    });
}
