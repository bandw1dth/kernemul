#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include <cstdint>
#include <limits>
#include <mutex>

namespace win
{

// Bit 0 marks rundown; each held reference contributes two to the guest count.
enum rundown_state : std::uint64_t
{
	rundown_active    = 0x1,
	rundown_reference = 0x2,
};

using rundown_ref = emu_object<_EX_RUNDOWN_REF>;

// One service per kernel serializes host hooks, with guest memory as the sole
// count authority. Guest inline atomic instructions do not participate in this
// mutex: interoperability with concurrently executing guest atomics is not guaranteed.
class rundown_service
{
public:
	[[nodiscard]] bool acquire(const rundown_ref& ref)
	{
		if (!ref) return false;
		std::lock_guard lock(mutex_);
		auto count = ref.field(&_EX_RUNDOWN_REF::Count);
		const auto value = count.read();
		if ((value & rundown_active) ||
			value > std::numeric_limits<std::uint64_t>::max() - rundown_reference)
			return false;
		count.write(value + rundown_reference);
		return true;
	}

	[[nodiscard]] bool release(const rundown_ref& ref)
	{
		if (!ref) return false;
		std::lock_guard lock(mutex_);
		auto count = ref.field(&_EX_RUNDOWN_REF::Count);
		const auto value = count.read();
		if ((value & ~rundown_active) < rundown_reference) return false;
		count.write(value - rundown_reference);
		return true;
	}

	[[nodiscard]] std::uint64_t references(const rundown_ref& ref)
	{
		if (!ref) return 0;
		std::lock_guard lock(mutex_);
		return ref.field(&_EX_RUNDOWN_REF::Count).read() / rundown_reference;
	}

	// Return the held count at the transition for diagnostics. This does not wait;
	// outstanding holders may still release, preserving the active bit.
	std::uint64_t begin(const rundown_ref& ref)
	{
		if (!ref) return 0;
		std::lock_guard lock(mutex_);
		auto count = ref.field(&_EX_RUNDOWN_REF::Count);
		const auto value = count.read();
		count.write(value | rundown_active);
		return value / rundown_reference;
	}

	void initialize(const rundown_ref& ref)
	{
		if (!ref) return;
		std::lock_guard lock(mutex_);
		ref.field(&_EX_RUNDOWN_REF::Count).write(0);
	}

private:
	std::mutex mutex_;
};

}
