#pragma once
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>

namespace win
{
struct clock_sample
{
	std::uint64_t system_time;
	std::uint64_t interrupt_time;
};

inline constexpr std::uint64_t saturated_add(std::uint64_t a, std::uint64_t b)
{
	return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

// One host steady clock drives both domains. Host wall time is sampled only at boot.
class guest_clock
{
public:
	using ticks = std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>;
	static constexpr std::int64_t frequency = 10000000;
	guest_clock() : guest_clock(static_cast<std::uint64_t>(116444736000000000LL +
		std::chrono::duration_cast<ticks>(std::chrono::system_clock::now().time_since_epoch()).count())) {}
	explicit guest_clock(std::uint64_t wall) : wall_(wall) {}
	clock_sample sample() const
	{
		std::scoped_lock lock(mutex_);
		const auto elapsed = elapsed_ticks();
		return { saturated_add(wall_, elapsed - wall_at_), elapsed };
	}
	void set_system_time(std::uint64_t wall)
	{
		std::scoped_lock lock(mutex_);
		wall_at_ = elapsed_ticks();
		wall_ = wall;
	}
private:
	std::uint64_t elapsed_ticks() const
	{
		return static_cast<std::uint64_t>(std::chrono::duration_cast<ticks>(
			std::chrono::steady_clock::now() - origin_).count());
	}
	const std::chrono::steady_clock::time_point origin_ = std::chrono::steady_clock::now();
	mutable std::mutex mutex_;
	std::uint64_t wall_;
	std::uint64_t wall_at_ = 0;
};
}
