#pragma once
#include "win_obj_manager.hpp"

#include <array>
#include <vector>
#include <cstdint>
#include <shared_mutex>
#include <optional>
#include <unordered_map>

class win_handle_table
{
public:
	using handle_t = std::uint64_t;
	using access_t = std::uint32_t;

	struct handle_entry
	{
		addr_t body_addr;
		access_t access;
		std::uint32_t attributes = 0;
	};

	struct snapshot_entry
	{
		handle_t handle;
		handle_entry entry;
		addr_t guest_entry;
	};

	void initialize_guest(addr_space& space, addr_t eprocess, std::uint32_t pid);
	[[nodiscard]] addr_t guest_address() const;
	[[nodiscard]] std::vector<snapshot_entry> snapshot() const;
	[[nodiscard]] std::size_t count() const;
	// Bounded host references protect lookup bookkeeping, not native blocking
	// rundown. The kernel registry retains exposed owners/storage after exit.
	bool reference();
	bool dereference();
	void rundown();

	explicit win_handle_table(win_obj_manager& objs);

	handle_t create_handle(addr_t body_addr, access_t access, std::uint32_t attributes = 0);
	bool close_handle(handle_t handle);
	[[nodiscard]] std::optional<handle_entry> lookup_handle(handle_t handle) const;
	[[nodiscard]] win_obj_manager& objs() { return objs_; }

	template <typename T>
	[[nodiscard]] std::shared_ptr<T> get_object(handle_t handle) const
	{
		auto entry = lookup_handle(handle);
		if (!entry) return {};
		return objs_.get_object<T>(entry->body_addr);
	}

private:
	addr_t ensure_leaf(handle_t handle);
	addr_t entry_address(handle_t handle) const;
	void write_entry(handle_t handle, const handle_entry& entry);
	void update_header();
	std::uint32_t pool_boundary() const;

	win_obj_manager& objs_;
	// Looked up on every call that takes a handle, written only on open/close.
	mutable std::shared_mutex mtx_;
	std::unordered_map<handle_t, handle_entry> handles_;
	handle_t next_handle_ = 4;
	addr_space* space_ = nullptr;
	addr_t guest_address_ = 0, root_ = 0;
	std::array<addr_t, 512> leaves_{};
	std::uint32_t references_ = 0;
	bool rundown_ = false;
};
