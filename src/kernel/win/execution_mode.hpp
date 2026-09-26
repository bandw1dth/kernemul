#pragma once
#include "../../emu/emu.hpp"
#if defined(KERNEMUL_ARCH_ARM64)
#include "../../emu/arm64/arch.hpp"
#else
#include "../../emu/x86/arch.hpp"
#endif

namespace win {
inline bool executing_user_mode(vcpu& cpu)
{
#if defined(KERNEMUL_ARCH_ARM64)
	return (cpu.reg<std::uint64_t>(arm64::pstate) & 0xf) == 0;
#else
	return (cpu.reg<x86::seg_reg>(x86::cs).selector & 3) == 3;
#endif
}
}
