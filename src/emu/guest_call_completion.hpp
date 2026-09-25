#pragma once
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <mutex>
#include <unordered_map>
#include <vector>

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
