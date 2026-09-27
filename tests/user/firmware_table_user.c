/* Native emulator guest only. Never execute on the host; no DbgPrint syscall. */
#include <windows.h>
#include <winternl.h>
#include <string.h>
/* Keep the freestanding native image independent of CRT imports. */
#pragma function(memcpy, memset)
void *memcpy(void *dst,const void *src,size_t n) {
    volatile unsigned char *d=(volatile unsigned char *)dst;
    const volatile unsigned char *s=(const volatile unsigned char *)src;
    size_t i; for(i=0;i<n;++i) d[i]=s[i]; return dst;
}
void *memset(void *dst,int c,size_t n) {
    volatile unsigned char *d=(volatile unsigned char *)dst;
    size_t i; for(i=0;i<n;++i) d[i]=(unsigned char)c; return dst;
}
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE,PVOID *,ULONG_PTR,PSIZE_T,ULONG,ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE,PVOID *,PSIZE_T,ULONG);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE,PVOID *,PSIZE_T,ULONG,PULONG);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
#define SELF ((HANDLE)(LONG_PTR)-1)
#define QUERY(b,n,r) NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)76,b,n,r)
#define AV ((NTSTATUS)0xC0000005u)
#define ALIGNMENT ((NTSTATUS)0x80000002u)
/* Labels are source metadata. Only exact 0x7640 certifies all checks passed. */
#define REQUIRE(expr,label) do { if(!(expr)) { result=(NTSTATUS)(0xC0760000u | (ULONG)__LINE__); goto done; } } while(0)
#define CAP 4096
#define RSMB 0x52534D42u
#define MISMATCH ((NTSTATUS)0xC0000004u)
#define SMALL ((NTSTATUS)0xC0000023u)
#define NOTIMPL ((NTSTATUS)0xC0000002u)
#define BADARG ((NTSTATUS)0xC00000EFu)
#define INVALID ((NTSTATUS)0xC000000Du)

static ULONG word(PUCHAR p,ULONG o) { return *(ULONG *)(p+o); }
static void fill(PUCHAR p,ULONG n,UCHAR v) { ULONG i; for(i=0;i<n;++i) p[i]=v; }
static BOOLEAN same(PUCHAR a,PUCHAR b,ULONG n) { ULONG i; for(i=0;i<n;++i) if(a[i]!=b[i]) return FALSE; return TRUE; }
static BOOLEAN canary(PUCHAR p,ULONG n) { ULONG i; for(i=0;i<n;++i) if(p[i]!=0xA5) return FALSE; return TRUE; }
static void request(PUCHAR p,ULONG provider,ULONG action,ULONG id,ULONG capacity) {
    fill(p,CAP,0xA5); *(ULONG *)p=provider; *(ULONG *)(p+4)=action;
    *(ULONG *)(p+8)=id; *(ULONG *)(p+12)=capacity;
}
/* Bounds precede every dereference; exactly the bounded 0/1/127 profile. */
static BOOLEAN smbios(PUCHAR p,ULONG n) {
    ULONG o=8,k,j,end,strings; USHORT handles[3];
    if(n<8 || p[1]!=2 || p[2]!=8 || word(p,4)!=n-8) return FALSE;
    for(k=0;k<3;++k) {
        ULONG type=k==2?127:k, len=k==0?24:(k==1?27:4);
        if(o>n || n-o<len+2 || p[o]!=type || p[o+1]!=len) return FALSE;
        handles[k]=(USHORT)(p[o+2]|((USHORT)p[o+3]<<8));
        for(j=0;j<k;++j) if(handles[j]==handles[k]) return FALSE;
        end=o+len; strings=0;
        if(p[end]==0) { if(p[end+1]!=0) return FALSE; end+=2; }
        else {
            for(;;) {
                ++strings;
                while(end<n && p[end]!=0) ++end;
                if(end+1>=n) return FALSE;
                if(p[end+1]==0) { end+=2; break; }
                ++end;
            }
        }
        if(k==0 && (p[o+4]>strings || p[o+5]>strings || p[o+8]>strings)) return FALSE;
        if(k==1 && (p[o+4]>strings || p[o+5]>strings || p[o+6]>strings ||
            p[o+7]>strings || p[o+25]>strings || p[o+26]>strings)) return FALSE;
        if(k==2 && strings!=0) return FALSE;
        o=end;
    }
    return o==n;
}
void NTAPI entry(void) {
    PVOID allocation=NULL,ro=NULL,freed=NULL,protectBase;
    SIZE_T allocationSize=2*(CAP+16),size=4096,zero=0;
    ULONG old; NTSTATUS result=(NTSTATUS)0xC076FFFFu;
    PUCHAR storage,saved,b; ULONG got=0,need=0,i,j; NTSTATUS s;
    ULONG providers[]={0,0x41435049u,0x4649524Du,0xffffffffu};
    REQUIRE(NtAllocateVirtualMemory(SELF,&allocation,0,&allocationSize,
        MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE)==0 && allocation!=NULL &&
        allocationSize>=2*(CAP+16),"allocate-working-buffers");
    storage=(PUCHAR)allocation; saved=storage+CAP+16; b=storage;
    REQUIRE(QUERY(NULL,0,&got)==MISMATCH && got==16,"null-zero-header-length");
    for(i=1;i<16;++i) {
        fill(b,CAP,0xA5); got=0;
        s=QUERY(b,i,&got);
        REQUIRE(s==MISMATCH && got==16 && canary(b,CAP),"short-header-untouched");
    }
    for(i=16;i<=20;i+=i==16?3:1) {
        request(b,RSMB,0,0,0); got=0; s=QUERY(b,i,&got);
        REQUIRE(s==(i<20?SMALL:0) && got==20 && word(b,12)==4 &&
            word(b,0)==RSMB && word(b,4)==0 && word(b,8)==0,"enum-length-status-header");
        REQUIRE(i<20?canary(b+16,CAP-16):(word(b,16)==0 && canary(b+20,CAP-20)),"enum-payload-canaries");
    }
    request(b,RSMB,0,0,0xffffffffu);
    REQUIRE(QUERY(b,CAP,&got)==0 && got==20 && word(b,12)==4 &&
        word(b,16)==0 && canary(b+20,CAP-20),"enum-oversized-ignores-input-capacity");
    request(b,RSMB,1,0,0); got=0;
    s=QUERY(b,16,&got); need=got;
    REQUIRE(s==SMALL && need>24 && need<=CAP && word(b,12)==need-16 &&
        canary(b+16,CAP-16),"get-size-probe");
    request(b,RSMB,1,0,0xffffffffu);
    s=QUERY(b,need-1,&got);
    REQUIRE(s==SMALL && got==need && word(b,12)==need-16 &&
        canary(b+16,CAP-16),"get-one-byte-short-no-partial-payload");
    request(b,RSMB,1,0,0);
    REQUIRE(QUERY(b,need,&got)==0 && got==need && word(b,12)==need-16 &&
        word(b,0)==RSMB && word(b,4)==1 && word(b,8)==0 &&
        canary(b+need,CAP-need),"get-exact-ignores-zero-input-capacity");
    REQUIRE(smbios(b+16,need-16),"smbios-version-rawlength-types-handles-strings-end");
    for(i=0;i<need;++i) saved[i]=b[i];
    for(j=0;j<3;++j) {
        request(b,RSMB,1,0,0xffffffffu);
        REQUIRE(QUERY(b,CAP,&got)==0 && got==need && same(b,saved,need) &&
            canary(b+need,CAP-need),"get-repeat-oversized-stable");
    }
    request(b,RSMB,1,1,0);
    REQUIRE(QUERY(b,need,&got)==0 && got==need && word(b,8)==1 &&
        word(b,12)==need-16 && same(b+16,saved+16,need-16) &&
        canary(b+need,CAP-need),"table-id-one-alias-stable");
    for(j=0;j<sizeof(providers)/sizeof(providers[0]);++j) {
        request(b,providers[j],1,0,0x12345678);
        for(i=0;i<CAP;++i) saved[i]=b[i];
        got=0xcccccccc;
        REQUIRE(QUERY(b,CAP,&got)==NOTIMPL && got==0 && same(b,saved,CAP),"unsupported-provider-untouched");
        *(ULONG *)(b+4)=0xffffffffu; *(ULONG *)(saved+4)=0xffffffffu; got=0xcccccccc;
        REQUIRE(QUERY(b,CAP,&got)==NOTIMPL && got==0 && same(b,saved,CAP),"unsupported-provider-precedes-action-untouched");
    }
    for(j=0;j<2;++j) {
        request(b,RSMB,j?0xffffffffu:2,0,0x12345678);
        for(i=0;i<CAP;++i) saved[i]=b[i];
        got=0;
        REQUIRE(QUERY(b,CAP,&got)==BADARG && got==CAP && same(b,saved,CAP),"invalid-action-untouched");
    }
    request(b,RSMB,0,0,0);
    for(i=0;i<CAP;++i) saved[i]=b[i];
    REQUIRE(QUERY(b,20,(PULONG)b)==INVALID && same(b,saved,CAP),"return-overlap-header-rejected");
    REQUIRE(QUERY(b,20,(PULONG)(b+16))==INVALID && same(b,saved,CAP),"return-overlap-payload-rejected");
    request(b,RSMB,0,0,0);
    REQUIRE(QUERY(b,20,NULL)==0 && word(b,16)==0 && canary(b+20,CAP-20),"optional-return-length");
    request(b,RSMB,0,0,0);
    for(i=0;i<CAP;++i) saved[i]=b[i];
    REQUIRE(QUERY(NULL,16,&got)==AV,"null-output");
    REQUIRE(QUERY((PVOID)(ULONG_PTR)4,20,&got)==AV,"invalid-aligned-output");
    REQUIRE(QUERY(b+1,16,&got)==ALIGNMENT && same(b,saved,CAP),"offset-one-rejected-untouched");
    REQUIRE(QUERY(b+2,16,&got)==ALIGNMENT && same(b,saved,CAP),"offset-two-rejected-untouched");
    REQUIRE(QUERY(b+1,0,&got)==MISMATCH && got==16,"zero-ignores-alignment");
    REQUIRE(QUERY(b,20,(PULONG)(ULONG_PTR)1)==AV && same(b,saved,CAP),"invalid-return-pointer-untouched");
    REQUIRE(QUERY((PVOID)(ULONG_PTR)0xfffff80000000000ULL,20,&got)==AV,"supervisor-output");
    REQUIRE(QUERY((PVOID)(ULONG_PTR)0xfffffffffffffffcULL,20,&got)==AV,"overflow-output");
    REQUIRE(QUERY(b,20,(PULONG)(ULONG_PTR)0xfffff80000000000ULL)==AV && same(b,saved,CAP),"supervisor-return-untouched");
    REQUIRE(NtAllocateVirtualMemory(SELF,&ro,0,&size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE)==0,"allocate-protection-page");
    request((PUCHAR)ro,RSMB,0,0,0);
    protectBase=ro;
    REQUIRE(NtProtectVirtualMemory(SELF,&protectBase,&size,PAGE_READONLY,&old)==0,"protect-readonly");
    REQUIRE(QUERY(ro,20,&got)==AV && same((PUCHAR)ro,saved,CAP),"readonly-output-untouched");
    REQUIRE(QUERY(b,20,(PULONG)ro)==AV && same(b,saved,CAP) &&
        same((PUCHAR)ro,saved,CAP),"readonly-return-untouched");
    freed=ro;
    REQUIRE(NtFreeVirtualMemory(SELF,&ro,&zero,MEM_RELEASE)==0,"free-protection-page"); ro=NULL;
    REQUIRE(QUERY(freed,20,&got)==AV,"unmapped-output");
    REQUIRE(QUERY(b,20,(PULONG)freed)==AV && same(b,saved,CAP),"unmapped-return-untouched");
    b=storage+4; request(b,RSMB,0,0,0);
    REQUIRE(QUERY(b,20,&got)==0 && got==20 && word(b,16)==0 &&
        canary(b+20,CAP-20),"offset-four-accepted");
    zero=0;
    REQUIRE(NtFreeVirtualMemory(SELF,&allocation,&zero,MEM_RELEASE)==0,"free-working-buffers");
    allocation=NULL;
    result=(NTSTATUS)0x7640;
done:
    if(ro) { zero=0; NtFreeVirtualMemory(SELF,&ro,&zero,MEM_RELEASE); }
    if(allocation) { zero=0; NtFreeVirtualMemory(SELF,&allocation,&zero,MEM_RELEASE); }
    NtTerminateProcess(SELF,result);
    for(;;) {}
}





