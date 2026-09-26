#pragma once

struct win_kernel_state;

namespace win
{
	// The registry and filesystem state a real boot would already have left behind. Both stores
	// start completely empty, so without this every key a driver opens is missing and every
	// path it stats is absent.
	void seed_registry(win_kernel_state& state);
	void seed_filesystem(win_kernel_state& state);
	void seed_storage_device(win_kernel_state& state);
}
