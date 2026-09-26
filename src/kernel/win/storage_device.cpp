#include "storage_device.hpp"
#include "storage.hpp"
#include "win_kernel.hpp"
#include "process_memory.hpp"
#include <algorithm>
#include <cstring>

namespace {
bool failed_status(NTSTATUS status) noexcept
{
    return (status & 0x80000000u) != 0;
}

bool overlaps(addr_t a, std::size_t an, addr_t b, std::size_t bn)
{
    return an && bn && (a <= b ? b - a < an : a - b < bn);
}
struct piece {
    addr_t physical;
    std::size_t offset;
    std::vector<std::uint8_t> before, after;
};

class storage_device final : public builtin_device
{
    win::storage::disk disk_;
public:
    irp_result dispatch(win_kernel_state& state, vcpu& cpu, const irp_request& req,
        const builtin_io_context& context) noexcept override
    {
        irp_result result{STATUS_INVALID_DEVICE_REQUEST, 0};
        std::uint32_t property = 0xffffffff;
        unsigned command = 0;
        try
        {
            result = [&]() -> irp_result {
            if (req.major == irp_mj_create || req.major == irp_mj_cleanup || req.major == irp_mj_close)
                return {STATUS_SUCCESS, 0};
            const auto process = state.current_process(cpu);
            const auto space = cpu.curr_addr_space();
            if (!space || !space->mmu_) return {STATUS_ACCESS_VIOLATION, 0};
            auto* mem = process_memory_copy::memory(process);
            auto lock = process_memory_copy::lock_memory(process);
            auto permitted = [&](addr_t address, std::size_t size, bool write) {
                return process_memory_copy::permitted(mem, *space, address, size, write, context.user);
            };
            // Output/IOSB overlap has no meaningful atomic result: reject without writes.
            if (context.status_block && overlaps(req.output_buffer, req.output_length,
                context.status_block, sizeof(_IO_STATUS_BLOCK))) return {STATUS_INVALID_PARAMETER, 0};
            std::vector<piece> status, output;
            auto stage = [&](std::vector<piece>& pieces, addr_t address, std::size_t size) {
                if (!permitted(address, size, true)) return false;
                for (std::size_t done = 0; done < size;)
                {
                    const auto at = address + done;
                    const auto chunk = std::min(size - done,
                        space->mmu_->page_size() - at % space->mmu_->page_size());
                    const auto physical = space->mmu_->virt_to_phys(*space, at);
                    if (!physical) return false;
                    piece p{*physical, done, std::vector<std::uint8_t>(chunk), {}};
                    space->mmu_->read_phys(*physical, p.before.data(), chunk);
                    pieces.push_back(std::move(p));
                    done += chunk;
                }
                return true;
            };
            if (context.status_block && !stage(status, context.status_block, sizeof(_IO_STATUS_BLOCK)))
                return {STATUS_ACCESS_VIOLATION, 0};
            std::vector<std::uint8_t> input;
            auto evaluate = [&]() -> irp_result {
                constexpr NTSTATUS invalid_device_state = 0xc0000184;
                if (cpu.in_dpc || (state.emulator() && state.emulator()->irql(cpu) != passive_level))
                    return {invalid_device_state, 0};
                if (const auto thread = std::dynamic_pointer_cast<win_thread>(cpu.thread()); thread && thread->ethread())
                    if (thread->ethread().field(&_ETHREAD::Tcb).field(&_KTHREAD::SpecialApcDisable).read() != 0)
                        return {invalid_device_state, 0};
                if (failed_status(context.rejection)) return {context.rejection, 0};
                if (req.major != irp_mj_device_control) return {STATUS_INVALID_DEVICE_REQUEST, 0};
                if (req.input_length > win::storage::max_request_bytes
                    || req.output_length > win::storage::max_request_bytes)
                    return {STATUS_INVALID_PARAMETER, 0};
                if (!permitted(req.input_buffer, req.input_length, false))
                    return {STATUS_ACCESS_VIOLATION, 0};
                input.resize(req.input_length);
                if (!input.empty()) space->read_mem(req.input_buffer, input.data(), input.size());
                if (req.control_code == 0x2d1400 && input.size() >= 4)
                    std::memcpy(&property, input.data(), 4);
                if (req.control_code == 0x4d02c && input.size() >= 47) command = input[46];
                if (!stage(output, req.output_buffer, req.output_length))
                    return {STATUS_ACCESS_VIOLATION, 0};
                auto reply = disk_.control(req.control_code, input, req.output_length);
                if (failed_status(static_cast<NTSTATUS>(reply.status))) return {static_cast<NTSTATUS>(reply.status), 0};
                if (reply.information > req.output_length || reply.output.size() < reply.information)
                    return {STATUS_INVALID_DEVICE_REQUEST, 0};
                for (auto& p : output)
                    if (p.offset < reply.information)
                    {
                        const auto count = std::min<std::size_t>(p.before.size(), reply.information - p.offset);
                        p.after.assign(reply.output.begin() + p.offset, reply.output.begin() + p.offset + count);
                    }
                return {static_cast<NTSTATUS>(reply.status), reply.information};
            };
            try { result = evaluate(); }
            catch (const std::bad_alloc&) { result = {STATUS_INSUFFICIENT_RESOURCES, 0}; }
            catch (...) { result = {STATUS_ACCESS_VIOLATION, 0}; }
            // Virtual aliases of the IOSB are rejected too, before any commit.
            for (const auto& a : output)
                for (const auto& b : status)
                    if (overlaps(a.physical, a.before.size(), b.physical, b.before.size()))
                        return {STATUS_INVALID_PARAMETER, 0};
            if (failed_status(result.status)) for (auto& p : output) p.after.clear();
            _IO_STATUS_BLOCK iosb{};
            iosb.Status = result.status;
            iosb.Information = result.information;
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(&iosb);
            for (auto& p : status) p.after.assign(bytes + p.offset, bytes + p.offset + p.before.size());
            try
            {
                for (const auto* pieces : {&output, &status})
                    for (const auto& p : *pieces)
                        if (!p.after.empty()) space->mmu_->write_phys(p.physical, p.after.data(), p.after.size());
            }
            catch (...)
            {
                for (const auto* pieces : {&output, &status})
                    for (const auto& p : *pieces)
                        try { space->mmu_->write_phys(p.physical, p.before.data(), p.before.size()); }
                        catch (...) {}
                result = {STATUS_ACCESS_VIOLATION, 0};
            }
            return result;
            }();
        }
        catch (const std::bad_alloc&) { result = {STATUS_INSUFFICIENT_RESOURCES, 0}; }
        catch (...) { result = {STATUS_ACCESS_VIOLATION, 0}; }
        try { if (req.major == irp_mj_device_control) THREAD_LOG_INFO("StorageControl(mode={}, code=0x{:X}, property={}, ATAcommand=0x{:X}, status=0x{:X}, bytes={})",
            context.user ? "UserMode" : "KernelMode", req.control_code, property, command, static_cast<std::uint32_t>(result.status), result.information); }
        catch (...) {}
        return result;
    }
};
}

std::shared_ptr<builtin_device> make_storage_device() { return std::make_shared<storage_device>(); }

bool reserved_raw_device_path(std::string_view name) noexcept
{
    if (name.starts_with("/global??/")) name.remove_prefix(10);
    auto digits = [](std::string_view s) {
        return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
    };
    if (name.starts_with("physicaldrive")) return digits(name.substr(13));
    constexpr std::string_view harddisk_prefix = "/device/harddisk";
    if (!name.starts_with(harddisk_prefix)) return false;
    name.remove_prefix(harddisk_prefix.size());
    const auto slash = name.find("/dr");
    return slash != std::string_view::npos && digits(name.substr(0, slash)) && digits(name.substr(slash + 3));
}
