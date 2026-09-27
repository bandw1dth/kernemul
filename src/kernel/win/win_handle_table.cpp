#include "win_handle_table.hpp"
#include "../../util/log.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace {
constexpr std::uint64_t max_handle = 131071ull * 4;
constexpr std::size_t page_size = 4096;
static_assert(sizeof(_HANDLE_TABLE_ENTRY) == 16);
addr_t allocate_page(addr_space& space)
{
    const auto address = space.alloc(page_size, prot_rw | prot_supervisor);
    if (!address || (address & (page_size - 1)))
        throw std::runtime_error("handle table page allocation failed");
    const std::array<std::uint8_t, page_size> zero{};
    space.write_mem(address, zero.data(), zero.size());
    return address;
}
}

win_handle_table::win_handle_table(win_obj_manager& objs) : objs_(objs) {}

void win_handle_table::initialize_guest(addr_space& space, addr_t eprocess, std::uint32_t pid)
{
    std::unique_lock lock(mtx_);
    if (guest_address_) return;
    if (rundown_) throw std::runtime_error("initializing a rundown handle table");
    // Allocations remain mapped for the object's lifetime, including failed setup.
    const auto header = allocate_page(space);
    const auto root = allocate_page(space);
    space_ = &space;
    root_ = root;
    try
    {
        ensure_leaf(4);
        for (const auto& [handle, entry] : handles_)
        {
            ensure_leaf(handle);
            write_entry(handle, entry);
        }
        _HANDLE_TABLE table{};
        table.TableCode = root_ | 1;
        table.QuotaProcess = reinterpret_cast<_EPROCESS*>(eprocess);
        table.UniqueProcessId = pid;
        table.NextHandleNeedingPool = pool_boundary();
        table.FreeLists[0].HandleCount = static_cast<int>(handles_.size());
        space.write_mem(header, table);
        guest_address_ = header;
    }
    catch (...)
    {
        space_ = nullptr;
        root_ = 0;
        leaves_.fill(0);
        throw;
    }
}

addr_t win_handle_table::guest_address() const
{
    std::shared_lock lock(mtx_);
    return guest_address_;
}

addr_t win_handle_table::entry_address(handle_t handle) const
{
    const auto index = handle / 4;
    const auto leaf = leaves_[index / 256];
    return leaf ? leaf + (index % 256) * sizeof(_HANDLE_TABLE_ENTRY) : 0;
}

addr_t win_handle_table::ensure_leaf(handle_t handle)
{
    if (!space_) return 0;
    auto& leaf = leaves_[(handle / 4) / 256];
    if (!leaf)
    {
        const auto page = allocate_page(*space_);
        space_->write_mem(root_ + ((handle / 4) / 256) * sizeof(addr_t), page);
        leaf = page;
    }
    return entry_address(handle);
}

void win_handle_table::write_entry(handle_t handle, const handle_entry& entry)
{
    if (!space_) return;
    _HANDLE_TABLE_ENTRY value{};
    value.Unlocked = 1;
    value.RefCnt = 0x7fff;
    value.Attributes = entry.attributes & 7;
    value.ObjectPointerBits = objs_.header_of(entry.body_addr).address() >> 4;
    value.GrantedAccessBits = entry.access;
    space_->write_mem(entry_address(handle), value);
}

std::uint32_t win_handle_table::pool_boundary() const
{
    for (std::size_t i = leaves_.size(); i; --i)
        if (leaves_[i - 1]) return static_cast<std::uint32_t>(i * 1024);
    return 0;
}

void win_handle_table::update_header()
{
    if (!guest_address_) return;
    auto table = space_->read_mem<_HANDLE_TABLE>(guest_address_);
    table.NextHandleNeedingPool = pool_boundary();
    table.FreeLists[0].HandleCount = static_cast<int>(handles_.size());
    table.Rundown = rundown_;
    space_->write_mem(guest_address_, table);
}

win_handle_table::handle_t win_handle_table::create_handle(addr_t body_addr, access_t access, std::uint32_t attributes)
{
    if (!objs_.has_object(body_addr)) return 0;
    std::unique_lock lock(mtx_);
    if (rundown_ || next_handle_ > max_handle) return 0;
    const auto handle = next_handle_;
    bool inserted = false, counted = false;
    try
    {
        ensure_leaf(handle);
        // Only handle attributes survive name resolution/object creation.
        handles_.emplace(handle, handle_entry{body_addr, access, attributes & 0x207u});
        inserted = true;
        objs_.increment_handle_count(body_addr);
        counted = true;
        write_entry(handle, handles_.at(handle));
        next_handle_ += 4;
        if (!(next_handle_ & 0x3ff)) next_handle_ += 4;
        update_header();
        return handle;
    }
    catch (...)
    {
        if (inserted) handles_.erase(handle);
        next_handle_ = handle;
        if (counted) objs_.decrement_handle_count(body_addr);
        if (space_ && entry_address(handle)) space_->write_mem(entry_address(handle), _HANDLE_TABLE_ENTRY{});
        update_header();
        return 0;
    }
}

bool win_handle_table::close_handle(handle_t handle)
{
    std::unique_lock lock(mtx_);
    const auto it = handles_.find(handle);
    if (it == handles_.end()) return false;
    if (space_) space_->write_mem(entry_address(handle), _HANDLE_TABLE_ENTRY{});
    objs_.decrement_handle_count(it->second.body_addr);
    handles_.erase(it);
    update_header();
    return true;
}

std::optional<win_handle_table::handle_entry> win_handle_table::lookup_handle(handle_t handle) const
{
    std::shared_lock lock(mtx_);
    const auto it = handles_.find(handle);
    if (it == handles_.end()) return std::nullopt;
    return it->second;
}

std::size_t win_handle_table::count() const
{
    std::shared_lock lock(mtx_);
    return handles_.size();
}

std::vector<win_handle_table::snapshot_entry> win_handle_table::snapshot() const
{
    std::shared_lock lock(mtx_);
    std::vector<snapshot_entry> entries;
    entries.reserve(handles_.size());
    for (const auto& [handle, entry] : handles_)
        entries.push_back({handle, entry, entry_address(handle)});
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.handle < b.handle; });
    return entries;
}

bool win_handle_table::reference()
{
    std::unique_lock lock(mtx_);
    if (rundown_ || references_ == std::numeric_limits<std::uint32_t>::max()) return false;
    ++references_;
    return true;
}

bool win_handle_table::dereference()
{
    std::unique_lock lock(mtx_);
    if (!references_) return false;
    --references_;
    return true;
}

void win_handle_table::rundown()
{
    std::unique_lock lock(mtx_);
    rundown_ = true;
    // No guest callbacks run here. Driver cleanup/close IRPs require a live CPU
    // and remain the caller's responsibility; guest storage is never reclaimed.
    while (!handles_.empty())
    {
        const auto it = handles_.begin();
        if (space_) space_->write_mem(entry_address(it->first), _HANDLE_TABLE_ENTRY{});
        objs_.decrement_handle_count(it->second.body_addr);
        handles_.erase(it);
    }
    update_header();
}
