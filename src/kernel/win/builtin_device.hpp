#pragma once
#include "irp.hpp"

struct win_kernel_state;
class vcpu;

// Native entry metadata is separate from the driver-facing IRP contract.
struct builtin_io_context
{
	addr_t status_block = 0;
	bool user = false;
	NTSTATUS rejection = STATUS_SUCCESS;
};

struct builtin_device
{
	virtual ~builtin_device() = default;
	virtual irp_result dispatch(win_kernel_state&, vcpu&, const irp_request&,
		const builtin_io_context&) noexcept = 0;
};
