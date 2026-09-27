#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Copied model values only: no guest views or host process lifetimes escape collection.
struct process_thread_snapshot
{
	std::uint64_t process_id, thread_id, start_address;
	std::int64_t create_time;
	std::int32_t priority, base_priority;
	std::uint32_t context_switches, state, wait_reason;
};

struct process_snapshot
{
	std::uint64_t process_id;
	std::int64_t create_time;
	std::uint64_t parent_id;
	std::string name;
	std::int32_t base_priority;
	std::uint32_t handle_count;
	std::vector<process_thread_snapshot> threads;
};
