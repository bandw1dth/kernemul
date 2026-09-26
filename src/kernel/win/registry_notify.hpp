#pragma once
#include "callback_registry.hpp"
#include <algorithm>
#include <condition_variable>
#include <optional>
#include <unordered_map>

namespace win
{
inline thread_local unsigned registry_callback_depth = 0;

// Decimal strings, not floating point: arbitrarily close altitudes stay distinct.
struct registry_altitude
{
	std::u16string integer, fraction;
	static std::optional<registry_altitude> parse(std::u16string_view s)
	{
		const auto dot = s.find(u'.');
		const auto whole = s.substr(0, dot);
		const auto fractional = dot == s.npos ? std::u16string_view{} : s.substr(dot + 1);
		auto digits = [](auto v) { return std::ranges::all_of(v, [](auto c) { return c >= u'0' && c <= u'9'; }); };
		if (whole.empty() || !digits(whole) || !digits(fractional)
			|| (dot != s.npos && fractional.empty())) return {};
		registry_altitude a{std::u16string(whole), std::u16string(fractional)};
		const auto first = a.integer.find_first_not_of(u'0');
		a.integer = first == a.integer.npos ? u"0" : a.integer.substr(first);
		while (!a.fraction.empty() && a.fraction.back() == u'0') a.fraction.pop_back();
		return a;
	}
	bool operator==(const registry_altitude&) const = default;
	bool operator<(const registry_altitude& b) const
	{
		if (integer.size() != b.integer.size()) return integer.size() < b.integer.size();
		if (integer != b.integer) return integer < b.integer;
		return fraction < b.fraction;
	}
};

class registry_notify_service
{
public:
	static constexpr std::uint32_t bypass = 0xC0000503u; // STATUS_CALLBACK_BYPASS (WDK)
	struct record
	{
		const std::int64_t cookie;
		const callbacks::cm_registration value;
		const registry_altitude altitude;
		record(std::int64_t id, callbacks::cm_registration v, registry_altitude a)
			: cookie(id), value(std::move(v)), altitude(std::move(a)) {}
	private:
		friend class registry_notify_service;
		bool active = true;
		std::size_t admitted = 0;
	};
	using entry = std::shared_ptr<record>;
	enum class add_status { success, invalid_altitude, collision, output_failed, exhausted };
	enum class remove_status { removed, absent, callback_deadlock };
	struct post_result { std::uint32_t callback_status, return_status; };

	template <typename Output>
	add_status add(callbacks::cm_registration value, Output&& output)
	{
		auto altitude = registry_altitude::parse(value.altitude);
		if (!altitude) return add_status::invalid_altitude;
		std::lock_guard lock(mutex_);
		for (const auto& e : entries_) if (e->altitude == *altitude) return add_status::collision;
		if (next_ == std::numeric_limits<std::int64_t>::max()) return add_status::exhausted;
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
		const auto it = invoking_.find(cpu);
		return it != invoking_.end() && !it->second.empty();
	}

	remove_status remove(std::int64_t cookie, bool from_callback)
	{
		std::unique_lock lock(mutex_);
		// Conservatively forbid all cross-callback drain, including nested callbacks.
		if (from_callback) return remove_status::callback_deadlock;
		const auto it = std::ranges::find_if(entries_, [=](const auto& e) { return e->cookie == cookie; });
		if (it == entries_.end() || !(*it)->active) return remove_status::absent;
		const auto e = *it;
		e->active = false;
		drained_.wait(lock, [&] { return e->admitted == 0; });
		std::erase(entries_, e);
		return remove_status::removed;
	}

	// Admission covers the entire operation, including reverse post unwind. Both
	// the snapshot and its counters are committed atomically with removal.
	template <typename Pre, typename Body, typename Post>
	std::uint32_t dispatch(std::size_t cpu, Pre&& pre, Body&& body, Post&& post)
	{
		std::vector<entry> admitted;
		{
			std::lock_guard lock(mutex_);
			const auto it = invoking_.find(cpu);
			const auto ceiling = it == invoking_.end() || it->second.empty() ? entry{} : it->second.back();
			for (const auto& e : entries_)
				if (e->active && (!ceiling || e->altitude < ceiling->altitude)) admitted.push_back(e);
			for (const auto& e : admitted) ++e->admitted;
		}
		struct rundown
		{
			registry_notify_service& service;
			std::vector<entry>& entries;
			~rundown()
			{
				std::lock_guard lock(service.mutex_);
				for (const auto& e : entries) --e->admitted;
				service.drained_.notify_all();
			}
		} release{*this, admitted};
		std::size_t completed = 0;
		std::uint32_t status = 0;
		for (; completed < admitted.size(); ++completed)
		{
			invocation scope(*this, cpu, admitted[completed]);
			status = pre(admitted[completed], completed);
			if (status == bypass) { status = 0; break; }
			if ((status & 0x80000000u) != 0) break;
		}
		if (completed == admitted.size()) status = body();
		while (completed)
		{
			--completed;
			invocation scope(*this, cpu, admitted[completed]);
			const auto result = post(admitted[completed], completed, status);
			if (result.callback_status == bypass) status = result.return_status;
		}
		return status;
	}

private:
	struct invocation
	{
		registry_notify_service& service;
		std::size_t cpu;
		invocation(registry_notify_service& s, std::size_t c, const entry& e) : service(s), cpu(c)
		{
			std::lock_guard lock(s.mutex_);
			s.invoking_[cpu].push_back(e);
		}
		~invocation()
		{
			std::lock_guard lock(service.mutex_);
			auto& stack = service.invoking_.at(cpu);
			stack.pop_back();
			if (stack.empty()) service.invoking_.erase(cpu);
		}
	};
	mutable std::mutex mutex_;
	std::condition_variable drained_;
	std::vector<entry> entries_;
	std::unordered_map<std::size_t, std::vector<entry>> invoking_;
	std::int64_t next_ = 1;
};
}
