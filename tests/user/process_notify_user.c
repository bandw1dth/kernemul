/* Emulator guest only. Never execute this native image on the host. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
extern unsigned int ob_user_cpl(void);

void NTAPI entry(void)
{
    ULONG_PTR teb = __readgsqword(0x30);
    ULONG_PTR pid = __readgsqword(0x40);
    ULONG_PTR tid = __readgsqword(0x48);
    NTSTATUS status = (NTSTATUS)0x1234;
    if (ob_user_cpl() != 3 || !teb || !pid || pid == 4 || !tid)
        status = (NTSTATUS)0xC0B00501u;
    NtTerminateProcess((HANDLE)(LONG_PTR)-1, status);
    for (;;) { /* The runner's deadline catches termination returning. */ }
}
