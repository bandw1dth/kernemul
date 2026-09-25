#pragma once
#include "guest_clock.hpp"
#include <map>
#include <vector>

namespace win
{
// Externally serialized by the kernel timer lock; contains no guest pointers or host clocks.
class timer_queue
{
public:
	struct entry
	{
		std::uint64_t timer, deadline, period, dpc;
		bool absolute;
	};
	bool set(std::uint64_t timer, std::int64_t due, std::uint64_t period,
		std::uint64_t dpc, clock_sample now)
	{
		return set(timer, due, period, dpc, now, [](const entry&) {});
	}
	// Prepare allocation before guest access, then publish only after it succeeds.
	// A throwing publisher leaves both an existing timer and queue membership untouched.
	template <typename Publish>
	bool set(std::uint64_t timer, std::int64_t due, std::uint64_t period,
		std::uint64_t dpc, clock_sample now, Publish publish)
	{
		const bool previous = entries_.contains(timer);
		// Unsigned subtraction also handles INT64_MIN without signed overflow.
		const auto deadline = due < 0 ? saturated_add(now.interrupt_time,
			std::uint64_t{0} - static_cast<std::uint64_t>(due)) : static_cast<std::uint64_t>(due);
		std::map<std::uint64_t, entry> prepared;
		prepared.emplace(timer, entry{ timer, deadline, period, dpc, due >= 0 });
		auto node = prepared.extract(timer);
		publish(node.mapped());
		if (previous) entries_.find(timer)->second = node.mapped();
		else entries_.insert(std::move(node));
		return previous;
	}
	bool cancel(std::uint64_t timer) { return entries_.erase(timer) != 0; }
	bool contains(std::uint64_t timer) const { return entries_.contains(timer); }
	std::size_t size() const { return entries_.size(); }
	std::vector<entry> expire(clock_sample now)
	{
		std::vector<entry> result;
		for (auto it = entries_.begin(); it != entries_.end();)
		{
			auto& e = it->second;
			const auto current = e.absolute ? now.system_time : now.interrupt_time;
			if (current < e.deadline) { ++it; continue; }
			result.push_back(e);
			if (!e.period) { it = entries_.erase(it); continue; }
			// Coalesce missed periods; future periodic intervals are always monotonic.
			const auto remaining = e.period - (current - e.deadline) % e.period;
			e.deadline = saturated_add(now.interrupt_time, remaining);
			e.absolute = false;
			++it;
		}
		return result;
	}
private:
	std::map<std::uint64_t, entry> entries_;
};
}
