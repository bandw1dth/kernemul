#include "emu/guest_call_completion.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>

int main()
{
	checked_guest_calls checked_cpu, other_checked_cpu;
	assert(!checked_cpu.fail()); // Legacy redirects outside a checked call still recover.
	{
		checked_guest_calls::scope unchecked(checked_cpu, false);
		assert(!unchecked.checked() && !checked_cpu.active());
		assert(!checked_cpu.fail() && !unchecked.failed());
	}
	{
		checked_guest_calls::scope checked_outer(checked_cpu, true);
		assert(checked_outer.checked() && !checked_outer.failed());
		{
			checked_guest_calls::scope checked_inner(checked_cpu, false);
			checked_guest_calls::scope independent(other_checked_cpu, true);
			assert(checked_inner.checked()); // Nested legacy calls inherit checked execution.
			assert(checked_cpu.fail()); // Models a swallowed redirect exception.
			assert(checked_inner.failed() && checked_outer.failed());
			assert(!independent.failed());
		}
		assert(checked_cpu.active() && checked_outer.failed());
		{
			checked_guest_calls::scope retry(checked_cpu, true);
			assert(retry.failed()); // A fresh nested call cannot erase the outer failure.
		}
		assert(checked_outer.failed());
	}
	assert(!checked_cpu.active());
	try
	{
		checked_guest_calls::scope fresh(checked_cpu, true);
		assert(!fresh.failed()); // Independent later calls have a fresh baseline.
		throw std::runtime_error("unwind scope");
	}
	catch (const std::runtime_error&) {}
	assert(!checked_cpu.active() && !checked_cpu.fail());

	guest_call_completions completions;
	guest_call_completions::invocation outer(completions, 0);
	{
		guest_call_completions::invocation inner(completions, 0);
		completions.complete(0);
		assert(inner.returned());
		assert(!outer.returned());
	}
	// Preemption following the inner return must not count as outer completion.
	assert(!outer.returned());
	{
		guest_call_completions::invocation other_cpu(completions, 1);
		completions.complete(1);
		assert(other_cpu.returned() && !outer.returned());
	}
	try
	{
		guest_call_completions::invocation aborted(completions, 0);
		throw std::runtime_error("callback fault");
	}
	catch (const std::runtime_error&) {}
	assert(!outer.returned());
	completions.complete(0);
	assert(outer.returned());
	std::cout << "guest_call_completion: PASS\n";
}
