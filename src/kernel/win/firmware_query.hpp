#pragma once
#include "status.hpp"
#include "../../emu/defs.hpp"

class vcpu;
struct win_kernel_state;
namespace win::firmware {
enum class query_entry { ex, nt, zw };
NTSTATUS query(win_kernel_state& state, vcpu& cpu, query_entry entry,
	addr_t name, addr_t vendor, addr_t value, addr_t length, addr_t attributes);
}
