#pragma once
#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace win
{
enum class process_notify_kind { classic, extended };

// Host-only ownership; snapshots never retain pointers into guest memory.
class process_notify_registry
{
public:
	explicit process_notify_registry(std::size_t limit = 64) : limit_(limit) {}

	struct record
	{
		record(std::uint64_t address, process_notify_kind callback_kind) : routine(address), kind(callback_kind) {}
		const std::uint64_t routine;
		const process_notify_kind kind;
	private:
		friend class process_notify_registry;
		bool active = true;
		std::unordered_map<std::size_t, std::size_t> owners;
	};
	using entry = std::shared_ptr<record>;
	enum class remove_result { removed, absent, callback_deadlock };

	bool add(std::uint64_t routine, process_notify_kind kind)
	{
		std::scoped_lock lock(mutex_);
		if (entries_.size() >= limit_ || !routine || std::ranges::any_of(entries_, [=](const auto& e) { return e->routine == routine; }))
			return false;
		entries_.push_back(std::make_shared<record>(routine, kind));
		return true;
	}

	std::vector<entry> snapshot() const
	{
		std::scoped_lock lock(mutex_);
		return entries_;
	}

	bool has_live() const
	{
		std::scoped_lock lock(mutex_);
		return !entries_.empty();
	}

	bool in_callback(std::size_t cpu) const
	{
		std::scoped_lock lock(mutex_);
		return in_callback_locked(cpu);
	}

	// Admission and deactivation share one lock. No lock survives admission.
	bool acquire(const entry& e, std::size_t cpu)
	{
		std::scoped_lock lock(mutex_);
		if (!e->active) return false;
		++e->owners[cpu];
		return true;
	}

	void release(const entry& e, std::size_t cpu)
	{
		std::scoped_lock lock(mutex_);
		const auto it = e->owners.find(cpu);
		if (--it->second == 0) e->owners.erase(it);
		drained_.notify_all();
	}

	remove_result remove(std::uint64_t routine, process_notify_kind kind, std::size_t cpu, bool lifecycle_callback = false)
	{
		std::unique_lock lock(mutex_);
		const auto it = std::ranges::find_if(entries_, [=](const auto& e) { return e->routine == routine && e->kind == kind; });
		if (it == entries_.end()) return remove_result::absent;
		const auto e = *it;
		// Process callback removal may not drain from lifecycle context or any
		// callback already owned by this CPU, even when it targets another entry.
		if (lifecycle_callback || in_callback_locked(cpu)) return remove_result::callback_deadlock;
		if (!e->active) return remove_result::absent;
		e->active = false;
		drained_.wait(lock, [&] { return e->owners.empty(); });
		// Keep the address reserved until rundown completes, including against add().
		std::erase(entries_, e);
		return remove_result::removed;
	}

private:
	bool in_callback_locked(std::size_t cpu) const
	{
		return std::ranges::any_of(entries_, [=](const auto& e) { return e->owners.contains(cpu); });
	}
	const std::size_t limit_;
	mutable std::mutex mutex_;
	std::condition_variable drained_;
	std::vector<entry> entries_;
};
}
