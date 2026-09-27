/* Native emulator guest only. Never execute on the host. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE,PVOID *,ULONG_PTR,PSIZE_T,ULONG,ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE,PVOID *,PSIZE_T,ULONG);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE,PVOID *,PSIZE_T,ULONG,PULONG);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
#define SELF ((HANDLE)(LONG_PTR)-1)
#define MISMATCH ((NTSTATUS)0xC0000004u)
#define AV ((NTSTATUS)0xC0000005u)
#define ALIGNMENT ((NTSTATUS)0x80000002u)
/* Labels remain source metadata; failure status encodes the REQUIRE source line. */
#define REQUIRE(expr,label) do { if(!(expr)) { result=(NTSTATUS)(0xC0510000u | (ULONG)__LINE__); goto done; } } while(0)
void NTAPI entry(void) {
    PVOID allocation=NULL,ro=NULL,freed=NULL,protectBase; SIZE_T size,zero,protectSize;
    ULONG need=0,got=0,i,o,old; ULONG_PTR pid=__readgsqword(0x40),tid=__readgsqword(0x48);
    PUCHAR b,p,t; ULONG n,span,count,j; UNICODE_STRING *name;
    BOOLEAN self=FALSE,thread=FALSE,ended=FALSE;
    NTSTATUS result=(NTSTATUS)0xC0515001u,s;
    REQUIRE(pid!=0 && pid!=4 && tid!=0,"native-self-identity");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,NULL,0,&need)==MISMATCH && need>=0x100,"null-zero-required-length");
    size=(SIZE_T)need+65536;
    REQUIRE(NtAllocateVirtualMemory(SELF,&allocation,0,&size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE)==0,"allocate-snapshot-buffer");
    b=(PUCHAR)allocation;
    for(i=0;i<64;++i) b[i]=0xA5;
    s=NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b,1,&got);
    for(i=0;i<64 && b[i]==0xA5;++i) {}
    REQUIRE(s==MISMATCH && got>=0x100 && i==64,"short-canary-untouched");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,NULL,1,&got)==AV,"null-nonzero-access-violation");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b+1,1,&got)==ALIGNMENT,"offset-one-misaligned");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b+2,1,&got)==ALIGNMENT,"offset-two-misaligned");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b+1,0,&got)==MISMATCH,"zero-ignores-alignment");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b,(ULONG)size,(PULONG)(ULONG_PTR)1)==AV,"invalid-return-pointer");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,(PVOID)(ULONG_PTR)0xfffff80000000000ULL,16,&got)==AV,"supervisor-output-rejected");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,(PVOID)(ULONG_PTR)0xfffffffffffffffcULL,16,&got)==AV,"overflow-output-rejected");
    protectSize=4096;
    REQUIRE(NtAllocateVirtualMemory(SELF,&ro,0,&protectSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE)==0,"allocate-protection-page");
    *(ULONG *)ro=0x1234ABCD; protectBase=ro;
    REQUIRE(NtProtectVirtualMemory(SELF,&protectBase,&protectSize,PAGE_READONLY,&old)==0,"make-page-read-only");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,ro,16,&got)==AV && *(ULONG *)ro==0x1234ABCD,"read-only-output-rejected");
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b,0,(PULONG)ro)==AV && *(ULONG *)ro==0x1234ABCD,"read-only-return-pointer-rejected");
    freed=ro; zero=0;
    REQUIRE(NtFreeVirtualMemory(SELF,&ro,&zero,MEM_RELEASE)==0,"release-protection-page"); ro=NULL;
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,freed,16,&got)==AV,"unmapped-output-rejected");
    /* ULONG alignment is sufficient even though the record has 64-bit fields. */
    b=(PUCHAR)allocation+4;
    REQUIRE(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5,b,(ULONG)size-4,&got)==0 && got<=size-4,"offset-four-success");
    o=0;
    while(o+0x100<=got) {
        p=b+o; n=*(ULONG *)p; count=*(ULONG *)(p+4); span=n?n:got-o;
        name=(UNICODE_STRING *)(p+0x38);
        REQUIRE(span>=0x100 && span<=got-o && !(n&7) && count<=(span-0x100)/0x50,"record-thread-bounds");
        REQUIRE(!(name->Length&1) && name->Length<=30 && name->MaximumLength==name->Length+2 &&
            (ULONG_PTR)name->Buffer>=(ULONG_PTR)p+0x100+(ULONG_PTR)count*0x50 &&
            (ULONG_PTR)name->Buffer<=(ULONG_PTR)p+span &&
            name->MaximumLength<=(ULONG_PTR)p+span-(ULONG_PTR)name->Buffer,"name-storage-bounds");
        REQUIRE(name->Buffer[name->Length/2]==0,"name-terminator");
        if(*(ULONG_PTR *)(p+0x50)==pid) {
            self=TRUE;
            REQUIRE(*(LONGLONG *)(p+0x20)!=0 && *(ULONG_PTR *)(p+0x58)==4,"self-create-time-parent-system");
            for(j=0;j<count;++j) {
                t=p+0x100+j*0x50;
                if(*(ULONG_PTR *)(t+0x30)==tid && *(ULONG_PTR *)(t+0x28)==pid) thread=TRUE;
            }
        }
        if(!n) { ended=TRUE; break; } o+=n;
    }
    REQUIRE(ended && self && thread,"complete-walk-self-real-thread");
    zero=0; REQUIRE(NtFreeVirtualMemory(SELF,&allocation,&zero,MEM_RELEASE)==0,"release-snapshot-buffer"); allocation=NULL;
    result=(NTSTATUS)0x5150;
done:
    if(ro) { zero=0; NtFreeVirtualMemory(SELF,&ro,&zero,MEM_RELEASE); }
    if(allocation) { zero=0; NtFreeVirtualMemory(SELF,&allocation,&zero,MEM_RELEASE); }
    NtTerminateProcess(SELF,result);
    for(;;) {}
}
