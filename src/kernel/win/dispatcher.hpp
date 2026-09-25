#pragma once
#include "defs.hpp"
#include "types.hpp"
#include "guest_clock.hpp"
#include "../../emu/object.hpp"
#include <chrono>
#include <cstdint>
#include <mutex>

namespace win
{
inline std::recursive_mutex dispatcher_mutex;
inline thread_local bool in_dpc_callback = false;

// KOBJECTS. The guest reads these back: the verifier checks an object header before touching it.
enum dispatcher_type : std::uint8_t
{
	event_notification_object    = 0,
	event_synchronization_object = 1,
	mutant_object                = 2,
	process_object               = 3,
	queue_object                 = 4,
	semaphore_object             = 5,
	thread_object                = 6,
	gate_object                  = 7,
	timer_notification_object    = 8,
	timer_synchronization_object = 9,
};

// ntoskrnl's own initialisers write Size in ULONGs rather than bytes.
template <typename T>
constexpr std::uint8_t dispatcher_size()
{
	return static_cast<std::uint8_t>(sizeof(T) / sizeof(std::uint32_t));
}

template <typename T>
[[nodiscard]] std::int32_t signal_state(const emu_object<T>& obj)
{
	return static_cast<std::int32_t>(
		obj.field(&T::Header).field(&_DISPATCHER_HEADER::SignalState).read());
}

template <typename T>
void set_signal_state(const emu_object<T>& obj, const std::int32_t state)
{
	obj.field(&T::Header).field(&_DISPATCHER_HEADER::SignalState).write(state);
}

// A wait list is circular and anchored in the object, so an empty one points at its own head.
template <typename T>
void init_dispatcher(const emu_object<T>& obj, const dispatcher_type type,
	const std::int32_t state)
{
	auto header = obj.field(&T::Header);

	header.field(&_DISPATCHER_HEADER::Type).write(type);
	header.field(&_DISPATCHER_HEADER::Signalling).write(0);
	header.field(&_DISPATCHER_HEADER::Size).write(dispatcher_size<T>());
	header.field(&_DISPATCHER_HEADER::SignalState).write(state);

	const auto head = header.address() + offsetof(_DISPATCHER_HEADER, WaitListHead);
	header.field(&_DISPATCHER_HEADER::WaitListHead).write(guest_links(head, head));
}


// The header is at the front of every one of them, so the type and signal state are readable.
[[nodiscard]] inline emu_object<_DISPATCHER_HEADER> header_at(addr_space& space,
	const addr_t object)
{
	return emu_object<_DISPATCHER_HEADER>(space, object);
}

[[nodiscard]] inline dispatcher_type type_at(addr_space& space, const addr_t object)
{
	return static_cast<dispatcher_type>(
		header_at(space, object).field(&_DISPATCHER_HEADER::Type).read());
}

[[nodiscard]] inline std::int32_t state_at(addr_space& space, const addr_t object)
{
	return header_at(space, object).field(&_DISPATCHER_HEADER::SignalState).read();
}

inline void set_state_at(addr_space& space, const addr_t object, const std::int32_t state)
{
	header_at(space, object).field(&_DISPATCHER_HEADER::SignalState).write(state);
}

// Null is no timeout, negative an interval from now in 100ns ticks, positive absolute guest time.
struct timeout
{
	std::uint64_t deadline = 0;
	bool timed = false;
	bool monotonic = false;
};

[[nodiscard]] inline timeout read_timeout(const emu_object<std::int64_t>& value, clock_sample now)
{
	if (!value)
		return {};

	const auto ticks = value.read();

	return { ticks < 0 ? saturated_add(now.interrupt_time,
		std::uint64_t{0} - static_cast<std::uint64_t>(ticks)) : static_cast<std::uint64_t>(ticks), true, ticks < 0 };
}

// Nothing here keeps a wait queue: a thread that cannot proceed is entered again at the same call.
inline constexpr auto wait_poll_interval = std::chrono::milliseconds(1);

[[nodiscard]] inline bool is_signalled(addr_space& space, const addr_t object,
	const addr_t waiter)
{
	const auto state = state_at(space, object);

	// A mutant its own owner is waiting on is always available to it, which makes it recursive.
	if (state <= 0 && type_at(space, object) == mutant_object)
		return waiter && guest_va(emu_object<_KMUTANT>(space, object)
			.field(&_KMUTANT::OwnerThread).read()) == waiter;

	return state > 0;
}

inline void take(addr_space& space, const addr_t object, const addr_t waiter)
{
	const auto type = type_at(space, object);
	const auto state = state_at(space, object);

	switch (type)
	{
	case event_notification_object:
	case process_object:
	case thread_object:
	case timer_notification_object:
		break;

	case mutant_object:
		set_state_at(space, object, state - 1);
		emu_object<_KMUTANT>(space, object).field(&_KMUTANT::OwnerThread)
			.write(guest_ptr<_KTHREAD>(waiter));
		break;

	case semaphore_object:
	case queue_object:
		set_state_at(space, object, state - 1);
		break;

	default:
		set_state_at(space, object, 0);
		break;
	}
}

}
