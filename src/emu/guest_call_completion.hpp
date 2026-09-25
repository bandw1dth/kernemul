#pragma once
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

// One per vCPU, accessed only by its executing host thread. A failure belongs to
// the entire checked call stack, even after an inner invocation has unwound.
class checked_guest_calls
{
public:
	class scope
	{
	public:
		scope(checked_guest_calls& owner, bool checked) : owner_(owner), checked_(checked || owner.active())
		{
			if (checked_ && owner_.depth_++ == 0) owner_.baseline_ = owner_.generation_;
		}
		scope(const scope&) = delete;
		scope& operator=(const scope&) = delete;
		~scope() { if (checked_) --owner_.depth_; }
		bool checked() const { return checked_; }
		bool failed() const { return checked_ && owner_.generation_ != owner_.baseline_; }
	private:
		checked_guest_calls& owner_;
		bool checked_;
	};
	bool active() const { return depth_ != 0; }
	bool fail()
	{
		if (!active()) return false;
		++generation_;
		return true;
	}
private:
	std::size_t depth_ = 0;
	std::uint64_t generation_ = 0;
	std::uint64_t baseline_ = 0;
};

// Each trampoline return belongs only to the innermost invocation on that CPU.
class guest_call_completions
{
public:
	class invocation
	{
	public:
		invocation(guest_call_completions& owner, std::size_t cpu) : owner_(owner), cpu_(cpu)
		{
			std::scoped_lock lock(owner_.mutex_);
			owner_.stacks_[cpu_].push_back(this);
		}
		invocation(const invocation&) = delete;
		invocation& operator=(const invocation&) = delete;
		~invocation()
		{
			std::scoped_lock lock(owner_.mutex_);
			auto& stack = owner_.stacks_.at(cpu_);
			std::erase(stack, this);
			if (stack.empty()) owner_.stacks_.erase(cpu_);
		}
		bool returned() const { return returned_.load(); }
	private:
		friend class guest_call_completions;
		guest_call_completions& owner_;
		std::size_t cpu_;
		std::atomic<bool> returned_{false};
	};
	void complete(std::size_t cpu)
	{
		std::scoped_lock lock(mutex_);
		const auto it = stacks_.find(cpu);
		if (it != stacks_.end() && !it->second.empty()) it->second.back()->returned_ = true;
	}
private:
	std::mutex mutex_;
	std::unordered_map<std::size_t, std::vector<invocation*>> stacks_;
};
