#include "nt_ex_ops.hpp"
#include "../win_kernel.hpp"
#include "../firmware_query.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"

void modules::register_ntoskrnl_ex_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The timezone bias comes from shared data, which the guest reads for itself.
	state.redirect(mod, "ExSystemTimeToLocalTime",
		[st](vcpu&, emu_object<std::int64_t> system_time, emu_object<std::int64_t> local_time)
		{
			if (!system_time || !local_time)
				return;

			const auto bias_low = st->kuser_shared_data.field(&_KUSER_SHARED_DATA::TimeZoneBias)
				.field(&_KSYSTEM_TIME::LowPart).read();
			const auto bias_high = st->kuser_shared_data.field(&_KUSER_SHARED_DATA::TimeZoneBias)
				.field(&_KSYSTEM_TIME::High1Time).read();

			const auto bias = (static_cast<std::int64_t>(bias_high) << 32) | bias_low;
			const auto local = system_time.read() - bias;

			local_time.write(local);

			THREAD_LOG_INFO("ExSystemTimeToLocalTime({}) -> {} (bias {})",
				system_time.read(), local, bias);
		});

	// There is no worker pool here, so a work item gets a system thread of its own.
	state.redirect(mod, "ExQueueWorkItem",
		[st](vcpu& cpu, emu_object<_WORK_QUEUE_ITEM> work_item, const std::uint32_t queue_type)
		{
			if (!work_item)
			{
				THREAD_LOG_ERR("ExQueueWorkItem: null work item");
				return;
			}

			const auto routine = guest_va(work_item.field(&_WORK_QUEUE_ITEM::WorkerRoutine).read());
			const auto parameter = guest_va(work_item.field(&_WORK_QUEUE_ITEM::Parameter).read());

			if (!routine)
			{
				THREAD_LOG_ERR("ExQueueWorkItem: 0x{:X} has no worker routine", work_item.address());
				return;
			}

			const std::uint64_t args[] = { parameter };
			auto t = st->sys_proc->create_thread(cpu, routine, args);

			THREAD_LOG_INFO("ExQueueWorkItem(item=0x{:X}, queue={}): routine 0x{:X}(0x{:X}) "
				"runs as tid={}", work_item.address(), queue_type, routine, parameter, t->id());
		});

	// Nothing delivers a software exception, so the thread ends where the unwind would have.
	state.redirect(mod, "ExRaiseAccessViolation", [](vcpu& cpu)
	{
		THREAD_LOG_ERR("ExRaiseAccessViolation: nothing delivers the exception, so the thread "
			"ends here");

		if (const auto t = cpu.thread())
			t->finish();

		cpu.stop();
	});

	state.redirect(mod, "ExGetFirmwareEnvironmentVariable",
		[st](vcpu& cpu, emu_object<_UNICODE_STRING> name, emu_object<void> vendor,
			addr_t value, emu_object<std::uint32_t> length, emu_object<std::uint32_t> attributes) -> NTSTATUS
		{
			return win::firmware::query(*st, cpu, win::firmware::query_entry::ex,
				name.address(), vendor.address(), value, length.address(), attributes.address());
		});
}
