#include "emu/guest_call_completion.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>

int main()
{
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
