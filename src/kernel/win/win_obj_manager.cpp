#include "win_obj_manager.hpp"
#include <algorithm>

win_obj_manager::win_obj_manager(addr_space& space)
	:	space_(space) {}

addr_t win_obj_manager::create_object(const std::uint8_t type_index,
	const void* body_data, const std::size_t body_size,
	std::shared_ptr<win_object> host, const mem_prot prot)
{
	// Body is the first bytes of the object, not trailing header storage.
	// Handle-table entries encode the header; native consumers add this offset.
	constexpr auto hdr_size = offsetof(_OBJECT_HEADER, Body);
	const auto base = space_.alloc(std::max(sizeof(_OBJECT_HEADER), hdr_size + body_size), prot);
	if (!base) return 0;
	const auto body_addr = base + hdr_size;

	_OBJECT_HEADER hdr{};
	hdr.PointerCount = 1;
	hdr.TypeIndex = type_index;

	emu_object<_OBJECT_HEADER> hdr_obj(space_, base,
		std::format("OBJECT_HEADER[0x{:X}]", body_addr), true);
	space_.write_mem(base, &hdr, hdr_size);

	if (body_data && body_size > 0)
		space_.write_mem(body_addr, body_data, body_size);

	std::scoped_lock lock(mtx_);
	objects_[body_addr] = { hdr_obj, std::move(host) };
	return body_addr;
}

void win_obj_manager::register_object(addr_t body_addr, std::shared_ptr<win_object> host)
{
	std::scoped_lock lock(mtx_);
	objects_[body_addr] = { emu_object<_OBJECT_HEADER>{}, std::move(host) };
}

void win_obj_manager::register_named_object(std::string name, const addr_t body_addr)
{
	if (name.empty())
		return;

	std::scoped_lock lock(mtx_);
	named_[std::move(name)] = body_addr;
}

bool win_obj_manager::try_register_named_object(std::string name, const addr_t body_addr)
{
	if (name.empty() || !body_addr) return false;
	std::scoped_lock lock(mtx_);
	return named_.emplace(std::move(name), body_addr).second;
}

addr_t win_obj_manager::lookup_named_object(const std::string_view name) const
{
	std::scoped_lock lock(mtx_);
	const auto it = named_.find(name);
	return it != named_.end() ? it->second : 0;
}

void win_obj_manager::unregister_named_object(const std::string_view name)
{
	std::scoped_lock lock(mtx_);

	if (const auto it = named_.find(name); it != named_.end())
		named_.erase(it);
}

bool win_obj_manager::unregister_named_object(const std::string_view name, const addr_t expected_body)
{
	std::scoped_lock lock(mtx_);
	const auto it = named_.find(name);
	if (it == named_.end() || it->second != expected_body) return false;
	named_.erase(it);
	return true;
}

bool win_obj_manager::has_object(addr_t body_addr) const
{
	std::scoped_lock lock(mtx_);
	return objects_.contains(body_addr);
}

void win_obj_manager::reference_object(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto count = it->second.header.field(&_OBJECT_HEADER::PointerCount);
	count.write(count.read() + 1);
}

void win_obj_manager::dereference_object(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto count = it->second.header.field(&_OBJECT_HEADER::PointerCount);
	count.write(count.read() - 1);
}

void win_obj_manager::increment_handle_count(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto count = it->second.header.field(&_OBJECT_HEADER::HandleCount);
	count.write(count.read() + 1);
}

void win_obj_manager::decrement_handle_count(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto count = it->second.header.field(&_OBJECT_HEADER::HandleCount);
	count.write(count.read() - 1);
}

win_obj_manager::id_type win_obj_manager::allocate_id()
{
	const auto id = next_id_;
	next_id_ += 4;
	return id;
}
