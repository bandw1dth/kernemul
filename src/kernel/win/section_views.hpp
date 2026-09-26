#pragma once
#include <cstdint>
#include <map>
#include <mutex>

namespace win
{
// A guest virtual address is only an identity together with its owning process.
class section_views
{
public:
	bool insert(std::uint64_t owner, std::uint64_t base, std::uint64_t size, bool no_execute = false)
	{
		std::scoped_lock lock(mutex_);
		return views_.emplace(std::make_pair(owner, base), view{size, no_execute}).second;
	}
	bool execution_blocked(std::uint64_t owner, std::uint64_t base, std::uint64_t size) const
	{
		return overlaps(owner, base, size, true);
	}
	bool overlaps(std::uint64_t owner, std::uint64_t base, std::uint64_t size,
		bool no_execute_only = false) const
	{
		std::scoped_lock lock(mutex_);
		if (!size) return false;
		for (auto it = views_.lower_bound({owner, 0}); it != views_.end() && it->first.first == owner; ++it)
		{
			const auto start = it->first.second;
			const auto& v = it->second;
			// Subtraction avoids overflow at the end of the address space.
			if ((!no_execute_only || v.no_execute) && v.size
				&& (base <= start ? start - base < size : base - start < v.size))
				return true;
		}
		return false;
	}
	// Host-only teardown is serialized with ownership changes. Failed teardown
	// preserves the record; guest callbacks must be dispatched after returning.
	template <typename F>
	bool remove(std::uint64_t owner, std::uint64_t base, F&& teardown)
	{
		std::scoped_lock lock(mutex_);
		const auto it = views_.find({owner, base});
		if (it == views_.end() || !teardown(it->second.size)) return false;
		views_.erase(it);
		return true;
	}
private:
	struct view { std::uint64_t size; bool no_execute; };
	mutable std::mutex mutex_;
	std::map<std::pair<std::uint64_t, std::uint64_t>, view> views_;
};
}
