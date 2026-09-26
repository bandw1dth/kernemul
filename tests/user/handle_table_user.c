/* Native emulator guest only. Never execute on the host. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN,PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
extern unsigned int ob_user_cpl(void);
void NTAPI entry(void) {
    volatile ULONG *control=(volatile ULONG *)(ULONG_PTR)0x200000000ULL;
    LARGE_INTEGER delay; ULONG n; HANDLE kernel; NTSTATUS result=(NTSTATUS)0xC0A12001u;
    delay.QuadPart=-100000;
    if(ob_user_cpl()!=3 || __readgsqword(0x40)==4) goto done;
    control[3]=1;
    for(n=0;n<1000 && control[0]!=1;++n) if(NtDelayExecution(FALSE,&delay)!=0) goto done;
    if(n==1000) goto done;
    kernel=(HANDLE)(ULONG_PTR)((ULONGLONG)control[4]|((ULONGLONG)control[5]<<32));
    if(((ULONG_PTR)kernel&0xffffffff80000000ULL)!=0xffffffff80000000ULL) goto done;
    control[1]=NtClose(kernel)==(NTSTATUS)0xC0000008u?1:2;
    for(n=0;n<1000 && control[2]!=1;++n) if(NtDelayExecution(FALSE,&delay)!=0) goto done;
    if(n==1000) goto done;
    if(control[1]==1) result=(NTSTATUS)0xA12C;
 done:
    NtTerminateProcess((HANDLE)(LONG_PTR)-1,result);
    for(;;) {}
}


