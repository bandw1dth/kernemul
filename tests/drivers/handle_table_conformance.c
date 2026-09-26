/* Guest only, fixed repository x64 profile. Never load on the host.
 * EPROCESS.ObjectTable=0x300; HANDLE_TABLE TableCode=8, PID=0x28,
 * FreeLists[0].HandleCount=0x58. Entry=16 bytes; compressed object header
 * pointer bits [63:20], canonical sign extension, OBJECT_HEADER.Body=0x30.
 * Root has 512 pointers, each leaf 256 entries, leaf slot zero reserved.
 * Negative statuses are INVALID_HANDLE for wrong table/user kernel handles,
 * ACCESS_DENIED for access upgrades and missing PROCESS_DUP_HANDLE.
 */
#include <ntifs.h>
#include <intrin.h>
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
NTKERNELAPI UCHAR *PsGetProcessImageFileName(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG);
typedef BOOLEAN (NTAPI *ENUM_CB)(PVOID,PVOID,HANDLE,PVOID);
typedef BOOLEAN (NTAPI *ENUM_FN)(PVOID,ENUM_CB,PVOID,PHANDLE);

#define CONTROL ((PULONG)(ULONG_PTR)0x200000000ULL)
#define SELF ((HANDLE)(LONG_PTR)-1)
#define MARKER 0xffffffff80000000ULL
static volatile LONG failures, ready[2], exits[2];
static PEPROCESS subjects[2];
static HANDLE pids[2], local[2], kernel[2];
static PVOID objects[2], tables[2];
static LONG64 pointer_baseline[2];
static ENUM_FN enumerate;

static void check(BOOLEAN ok,const char *label) {
    DbgPrint("CONFORMANCE %s %s\n",ok?"PASS":"FAIL",label);
    if(!ok) InterlockedIncrement(&failures);
}
static ULONG peek(ULONG index) {
    ULONG v; ULONG_PTR f=__readeflags() & ~(1ULL<<8);
    __writeeflags(f|(1ULL<<18)); v=CONTROL[index]; __writeeflags(f); return v;
}
static void poke(ULONG index,ULONG v) {
    ULONG_PTR f=__readeflags() & ~(1ULL<<8);
    __writeeflags(f|(1ULL<<18)); CONTROL[index]=v; __writeeflags(f);
}
static PVOID table(PEPROCESS p) { return *(PVOID *)((PUCHAR)p+0x300); }
static LONG count(PVOID t) { return *(volatile LONG *)((PUCHAR)t+0x58); }
static volatile ULONG64 *entry(PVOID t,HANDLE h) {
    ULONG_PTR code=*(ULONG_PTR *)((PUCHAR)t+8), index=(ULONG_PTR)h/4;
    ULONG_PTR leaf;
    if((code&3)!=1 || index>=512*256 || !code) return NULL;
    leaf=((ULONG_PTR *)(code&~3ULL))[index/256];
    return leaf?(volatile ULONG64 *)(leaf+(index%256)*16):NULL;
}
static LONG64 object_handles(PVOID o) { return *(volatile LONG64 *)((PUCHAR)o-0x28); }
static void raw(PVOID t,HANDLE h,PVOID o,ACCESS_MASK rights,ULONG attrs) {
    volatile ULONG64 *e=entry(t,h);
    ULONG64 decoded=e?((e[0]>>20)<<4):0;
    if(decoded&(1ULL<<47)) decoded|=0xffff000000000000ULL;
    check(e && decoded+0x30==(ULONG64)o && (e[1]&0x1ffffff)==rights &&
        ((e[0]>>17)&7)==attrs,"raw-entry-object-access-attributes");
}
static NTSTATUS reference(HANDLE h,ACCESS_MASK access,KPROCESSOR_MODE mode,PVOID expected) {
    PVOID o=NULL; NTSTATUS s=ObReferenceObjectByHandle(h,access,NULL,mode,&o,NULL);
    if(NT_SUCCESS(s)) { check(o==expected,"reference-object-identity"); ObDereferenceObject(o); }
    return s;
}
static NTSTATUS open_local(PVOID o,ACCESS_MASK access,ULONG attrs,PHANDLE h) {
    return ObOpenObjectByPointer(o,attrs,NULL,access,NULL,KernelMode,h);
}
static void process_header_tests(PEPROCESS p,HANDLE pid) {
    HANDLE h=NULL; PVOID referenced=NULL; PEPROCESS found=NULL;
    PVOID t=table(PsGetCurrentProcess()); volatile ULONG64 *e;
    ULONG64 decoded; LONG64 pointers=*(volatile LONG64 *)((PUCHAR)p-0x30);
    LONG64 handles=object_handles(p); LONG table_count=count(t); NTSTATUS s;
    check(pointers>=1 && handles>=0,"process-header-initial-counts");
    s=PsLookupProcessByProcessId(pid,&found);
    check(s==STATUS_SUCCESS && found==p &&
        *(volatile LONG64 *)((PUCHAR)p-0x30)==pointers+1,"process-lookup-increments-pointer-count");
    if(NT_SUCCESS(s) && found) ObDereferenceObject(found);
    check(*(volatile LONG64 *)((PUCHAR)p-0x30)==pointers,"process-lookup-restores-pointer-count");
    s=open_local(p,PROCESS_DUP_HANDLE,0,&h);
    check(s==STATUS_SUCCESS && h && count(t)==table_count+1 &&
        object_handles(p)==handles+1,"process-open-increments-handle-count");
    if(!NT_SUCCESS(s) || !h) return;
    raw(t,h,p,PROCESS_DUP_HANDLE,0);
    e=entry(t,h); decoded=e?((e[0]>>20)<<4):0;
    if(decoded&(1ULL<<47)) decoded|=0xffff000000000000ULL;
    check(e && decoded==(ULONG64)p-0x30 &&
        *(volatile LONG64 *)(ULONG_PTR)decoded==pointers &&
        *(volatile LONG64 *)(ULONG_PTR)(decoded+8)==handles+1,"process-raw-header-live-counts");
    s=ObReferenceObjectByHandle(h,PROCESS_DUP_HANDLE,NULL,KernelMode,&referenced,NULL);
    check(s==STATUS_SUCCESS && referenced==p &&
        *(volatile LONG64 *)((PUCHAR)p-0x30)==pointers+1 &&
        object_handles(p)==handles+1,"process-reference-increments-pointer-count");
    if(NT_SUCCESS(s) && referenced) ObDereferenceObject(referenced);
    check(*(volatile LONG64 *)((PUCHAR)p-0x30)==pointers,"process-dereference-restores-pointer-count");
    check(ZwClose(h)==STATUS_SUCCESS && count(t)==table_count && object_handles(p)==handles &&
        *(volatile LONG64 *)((PUCHAR)p-0x30)==pointers,"process-close-restores-header-counts");
    e=entry(t,h); check(e && !e[0] && !e[1],"process-close-clears-raw-entry");
}
static void notify(HANDLE parent,HANDLE pid,BOOLEAN create) {
    PEPROCESS p=NULL; UCHAR *name; ULONG slot; KAPC_STATE state;
    NTSTATUS s; PVOID base=CONTROL; SIZE_T size=PAGE_SIZE;
    UNREFERENCED_PARAMETER(parent);
    if(!create) {
        if(pid==pids[0]) InterlockedIncrement(&exits[0]);
        if(pid==pids[1]) InterlockedIncrement(&exits[1]);
        return;
    }
    s=PsLookupProcessByProcessId(pid,&p);
    if(!NT_SUCCESS(s)||!p) return;
    name=PsGetProcessImageFileName(p);
    if(!name || RtlCompareMemory(name,"handle_user_",12)!=12 ||
        (name[12]!='a' && name[12]!='b')) { ObDereferenceObject(p); return; }
    slot=name[12]=='a'?0:1;
    check(!subjects[slot],"single-create-per-subject");
    if(subjects[slot]) { ObDereferenceObject(p); return; }
    subjects[slot]=p; pids[slot]=pid; tables[slot]=table(p);
    KeStackAttachProcess(p,&state);
    check(PsGetCurrentProcess()==p,"callback-attached-process");
    s=open_local(objects[slot],slot?EVENT_MODIFY_STATE:SYNCHRONIZE,OBJ_INHERIT,&local[slot]);
    check(s==STATUS_SUCCESS && local[slot],"callback-open-local");
    s=ZwAllocateVirtualMemory(SELF,&base,0,&size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    check(s==STATUS_SUCCESS && base==CONTROL,"callback-control-page");
    if(s==STATUS_SUCCESS && base==CONTROL) { poke(0,0); poke(1,0); poke(2,0); }
    KeUnstackDetachProcess(&state);
    InterlockedExchange(&ready[slot],s==STATUS_SUCCESS && base==CONTROL?1:-1);
}
typedef struct { PVOID table; HANDLE wanted; ULONG visits; BOOLEAN stop; } ENUM_CONTEXT;
static BOOLEAN NTAPI visit(PVOID t,PVOID e,HANDLE h,PVOID opaque) {
    ENUM_CONTEXT *c=(ENUM_CONTEXT *)opaque;
    check(t==c->table && e==(PVOID)entry(t,h),"enum-four-argument-abi");
    ++c->visits;
    InterlockedIncrement64((volatile LONG64 *)e);
    if(c->stop) { c->wanted=h; return TRUE; }
    return FALSE;
}
static void enum_tests(PVOID t) {
    ENUM_CONTEXT c; HANDLE matched=(HANDLE)(ULONG_PTR)0x12345678; BOOLEAN result;
    if(!enumerate) return;
    c.table=t; c.wanted=NULL; c.visits=0; c.stop=TRUE;
    result=enumerate(t,visit,&c,&matched);
    check(result && matched==c.wanted && matched!=NULL && c.visits==1,"enum-true-stops-and-returns-match");
    c.visits=0; c.stop=FALSE; matched=(HANDLE)(ULONG_PTR)0x12345678;
    result=enumerate(t,visit,&c,&matched);
    check(!result && c.visits==(ULONG)count(t) && matched==(HANDLE)(ULONG_PTR)0x12345678,
        "enum-no-match-preserves-output");
}
static void exercise(void) {
    KAPC_STATE state; HANDLE extra=NULL, duplicate=NULL, moved=NULL, ph[2]={NULL,NULL}, denied=NULL;
    HANDLE grown[270]={0}; ULONG i; LONG before; NTSTATUS s; volatile ULONG64 *e;
    PEPROCESS seeded=NULL; PVOID seeded_table=NULL;
    check(tables[0] && tables[1] && tables[0]!=tables[1] &&
        tables[0]!=table(PsGetCurrentProcess()) && tables[1]!=table(PsGetCurrentProcess()),"distinct-live-system-tables");
    if(!tables[0] || !tables[1]) return;
    process_header_tests(PsGetCurrentProcess(),PsGetCurrentProcessId());
    s=PsLookupProcessByProcessId((HANDLE)8,&seeded);
    check(s==STATUS_SUCCESS && seeded,"seeded-process-lookup");
    if(seeded) {
        seeded_table=table(seeded);
        check(seeded_table && seeded_table!=tables[0] && seeded_table!=tables[1] &&
            seeded_table!=table(PsGetCurrentProcess()),"distinct-seeded-table");
        process_header_tests(seeded,(HANDLE)8);
        ObDereferenceObject(seeded);
    }
    check(local[0]==local[1] && local[0],"same-numeric-local-handle-collision");
    for(i=0;i<2;++i) {
        process_header_tests(subjects[i],pids[i]);
        check(*(ULONG *)((PUCHAR)tables[i]+0x28)==(ULONG)(ULONG_PTR)pids[i] &&
            (*(ULONG_PTR *)((PUCHAR)tables[i]+8)&3)==1,"table-profile-pid-level-one");
        KeStackAttachProcess(subjects[i],&state);
        check(reference(local[i],i?EVENT_MODIFY_STATE:SYNCHRONIZE,UserMode,objects[i])==STATUS_SUCCESS,
            "collision-resolves-local-object-rights");
        check(reference(local[i],i?SYNCHRONIZE:EVENT_MODIFY_STATE,UserMode,objects[i])==STATUS_ACCESS_DENIED,
            "collision-wrong-rights-denied");
        raw(tables[i],local[i],objects[i],i?EVENT_MODIFY_STATE:SYNCHRONIZE,2);
        check(reference(kernel[0],0,KernelMode,objects[0])==STATUS_SUCCESS,"kernel-handle-global-lookup");
        check(reference(kernel[0],0,UserMode,objects[0])==STATUS_INVALID_HANDLE,"user-reference-kernel-handle-denied");
        KeUnstackDetachProcess(&state);
    }
    KeStackAttachProcess(subjects[0],&state);
    before=count(tables[0]);
    check(open_local(objects[0],SYNCHRONIZE,0,&extra)==STATUS_SUCCESS && count(tables[0])==before+1,
        "attached-open-updates-local-count");
    KeUnstackDetachProcess(&state);
    KeStackAttachProcess(subjects[1],&state);
    e=entry(tables[1],extra);
    check(!e || (!e[0] && !e[1]),"wrong-process-slot-confirmed-absent");
    check(reference(extra,0,KernelMode,objects[0])==STATUS_INVALID_HANDLE,"wrong-process-absent-handle-rejected");
    check(ZwClose(extra)==STATUS_INVALID_HANDLE,"wrong-process-close-rejected");
    KeUnstackDetachProcess(&state);
    KeStackAttachProcess(subjects[0],&state);
    check(ZwClose(extra)==STATUS_SUCCESS && count(tables[0])==before,"attached-close-updates-local-count");
    e=entry(tables[0],extra); check(e && !e[0] && !e[1],"close-clears-raw-entry");
    enum_tests(tables[0]);
    for(i=0;i<270;++i) if(open_local(objects[0],SYNCHRONIZE,0,&grown[i])!=STATUS_SUCCESS) break;
    check(i==270 && count(tables[0])==before+270,"growth-live-count");
    if(i==270) {
        check((ULONG_PTR)grown[269]/4>=256 && ((ULONG_PTR)grown[269]/4)%256!=0,"growth-crosses-leaf-boundary");
        raw(tables[0],grown[269],objects[0],SYNCHRONIZE,0);
        for(i=0;i<270;++i) check(((ULONG_PTR)grown[i]/4)%256!=0,"leaf-slot-zero-reserved");
        {
            ULONG_PTR root=*(ULONG_PTR *)((PUCHAR)tables[0]+8)&~3ULL;
            ULONG64 *leaf0=(ULONG64 *)((ULONG_PTR *)root)[0], *leaf1=(ULONG64 *)((ULONG_PTR *)root)[1];
            check(leaf0 && leaf1 && leaf0!=leaf1 && !leaf0[0] && !leaf0[1] && !leaf1[0] && !leaf1[1],
                "root-distinct-leaves-reserved-entries-zero");
        }
    }
    for(i=0;i<270;++i) if(grown[i]) {
        check(ZwClose(grown[i])==STATUS_SUCCESS,"growth-close");
        e=entry(tables[0],grown[i]); check(e && !e[0] && !e[1],"growth-close-clears-entry");
    }
    check(count(tables[0])==before,"growth-restores-count");
    KeUnstackDetachProcess(&state);
    for(i=0;i<2;++i) check(open_local(subjects[i],PROCESS_DUP_HANDLE,OBJ_KERNEL_HANDLE,&ph[i])==STATUS_SUCCESS,
        "open-duplicate-process-handle");
    check(open_local(subjects[1],0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */,OBJ_KERNEL_HANDLE,&denied)==STATUS_SUCCESS,
        "open-process-without-duplicate-right");
    /* Zw runs KernelMode, so explicit access ceilings must still be enforced by duplication. */
    s=ZwDuplicateObject(ph[0],local[0],denied,&duplicate,0,0,DUPLICATE_SAME_ACCESS);
    check(s==STATUS_ACCESS_DENIED && !duplicate,"duplicate-target-process-right-denied");
    s=ZwDuplicateObject(denied,local[1],ph[0],&duplicate,0,0,DUPLICATE_SAME_ACCESS);
    check(s==STATUS_ACCESS_DENIED && !duplicate,"duplicate-source-process-right-denied");
    s=ZwDuplicateObject(ph[0],local[0],ph[1],&duplicate,EVENT_MODIFY_STATE,0,0);
    check(s==STATUS_ACCESS_DENIED && !duplicate,"duplicate-access-upgrade-denied");
    s=ZwDuplicateObject(ph[0],local[0],ph[1],&duplicate,EVENT_MODIFY_STATE,0,
        DUPLICATE_SAME_ACCESS|DUPLICATE_SAME_ATTRIBUTES);
    check(s==STATUS_SUCCESS && duplicate,"duplicate-a-to-b-same-access");
    KeStackAttachProcess(subjects[1],&state);
    if(duplicate) {
        raw(tables[1],duplicate,objects[0],SYNCHRONIZE,2);
        check(reference(duplicate,EVENT_MODIFY_STATE,UserMode,objects[0])==STATUS_ACCESS_DENIED,"duplicate-no-rights-upgrade");
        check(ZwClose(duplicate)==STATUS_SUCCESS,"close-target-duplicate");
    }
    KeUnstackDetachProcess(&state);
    s=ZwDuplicateObject(ph[0],local[0],ph[1],&moved,0,0,DUPLICATE_SAME_ACCESS|DUPLICATE_CLOSE_SOURCE);
    check(s==STATUS_SUCCESS && moved,"duplicate-close-source");
    KeStackAttachProcess(subjects[0],&state);
    check(reference(local[0],0,KernelMode,objects[0])==STATUS_INVALID_HANDLE,"duplicate-source-now-invalid");
    e=entry(tables[0],local[0]); check(e && !e[0] && !e[1],"duplicate-source-raw-cleared");
    KeUnstackDetachProcess(&state);
    KeStackAttachProcess(subjects[1],&state);
    if(moved) check(reference(moved,SYNCHRONIZE,UserMode,objects[0])==STATUS_SUCCESS,"moved-target-survives-source-close");
    KeUnstackDetachProcess(&state);
    /* Leave moved and B's local handle open: process rundown must release both. */
    for(i=0;i<2;++i) if(ph[i]) check(ZwClose(ph[i])==STATUS_SUCCESS,"close-process-duplicate-handle");
    if(denied) check(ZwClose(denied)==STATUS_SUCCESS,"close-process-denied-handle");
}
static void monitor(PVOID unused) {
    LARGE_INTEGER delay; ULONG attempt,i; KAPC_STATE state;
    UNREFERENCED_PARAMETER(unused); delay.QuadPart=-100000;
    for(attempt=0;attempt<1000 && (!ready[0] || !ready[1]);++attempt)
        if(KeDelayExecutionThread(KernelMode,FALSE,&delay)!=STATUS_SUCCESS) break;
    check(ready[0]==1 && ready[1]==1,"two-native-subjects-ready");
    if(ready[0]==1 && ready[1]==1) {
        /* Wait for both native loaders to finish before asserting exact table counts. */
        for(attempt=0;attempt<1000;++attempt) {
            ULONG started=0;
            for(i=0;i<2;++i) {
                KeStackAttachProcess(subjects[i],&state); started+=peek(3)==1;
                KeUnstackDetachProcess(&state);
            }
            if(started==2) break;
            if(KeDelayExecutionThread(KernelMode,FALSE,&delay)!=STATUS_SUCCESS) break;
        }
        check(attempt<1000,"both-native-loaders-quiescent");
        exercise();
        for(i=0;i<2;++i) {
            KeStackAttachProcess(subjects[i],&state);
            poke(4,(ULONG)(ULONG_PTR)kernel[0]); poke(5,(ULONG)((ULONG_PTR)kernel[0]>>32)); poke(0,1);
            KeUnstackDetachProcess(&state);
        }
        for(attempt=0;attempt<1000;++attempt) {
            ULONG done=0;
            for(i=0;i<2;++i) {
                KeStackAttachProcess(subjects[i],&state); done+=peek(1)!=0;
                KeUnstackDetachProcess(&state);
            }
            if(done==2) break;
            if(KeDelayExecutionThread(KernelMode,FALSE,&delay)!=STATUS_SUCCESS) break;
        }
        check(attempt<1000,"native-ntclose-user-mode-denied");
        check(reference(kernel[0],0,KernelMode,objects[0])==STATUS_SUCCESS,"native-denial-preserves-kernel-handle");
        for(i=0;i<2;++i) {
            KeStackAttachProcess(subjects[i],&state);
            check(peek(1)==1,"native-ntclose-exact-invalid-handle");
            poke(2,1); KeUnstackDetachProcess(&state);
        }
    }
    for(attempt=0;attempt<1000;++attempt) {
        if(KeDelayExecutionThread(KernelMode,FALSE,&delay)!=STATUS_SUCCESS) break;
        if(exits[0]==1 && exits[1]==1 && tables[0] && tables[1] && !count(tables[0]) && !count(tables[1])) break;
    }
    check(attempt<1000 && exits[0]==1 && exits[1]==1,"two-native-exits-table-rundown");
    for(i=0;i<2;++i) if(tables[i]) {
        ULONG j; ULONG_PTR root=*(ULONG_PTR *)((PUCHAR)tables[i]+8)&~3ULL; BOOLEAN zero=TRUE;
        for(j=0;j<512;++j) if(((ULONG_PTR *)root)[j]) {
            ULONG k; ULONG64 *leaf=(ULONG64 *)((ULONG_PTR *)root)[j];
            for(k=0;k<512;++k) if(leaf[k]) zero=FALSE;
        }
        check(zero && count(tables[i])==0,"exit-clears-all-entries-and-count");
    }
    check(*(volatile LONG64 *)((PUCHAR)objects[0]-0x30)==pointer_baseline[0] &&
        *(volatile LONG64 *)((PUCHAR)objects[1]-0x30)==pointer_baseline[1],"balanced-object-pointer-references");
    check(object_handles(objects[0])==1 && object_handles(objects[1])==1,"rundown-no-object-handle-count-leak");
    check(PsSetCreateProcessNotifyRoutine(notify,TRUE)==STATUS_SUCCESS,"unregister-notify");
    for(i=0;i<2;++i) {
        if(subjects[i]) ObDereferenceObject(subjects[i]);
        check(ZwClose(kernel[i])==STATUS_SUCCESS,"zw-kernel-close-succeeds");
        check(object_handles(objects[i])==0,"all-object-handle-counts-restored");
        ObDereferenceObject(objects[i]);
    }
    DbgPrint("HANDLE_TABLES COMPLETE\n"); DbgPrint("CONFORMANCE RESULT failures=%ld\n",failures);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path) {
    UNICODE_STRING name; OBJECT_ATTRIBUTES oa; HANDLE thread=NULL; NTSTATUS s; ULONG i;
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    RtlInitUnicodeString(&name,L"ExEnumHandleTable"); enumerate=(ENUM_FN)MmGetSystemRoutineAddress(&name);

    check(enumerate!=NULL,"enum-export-available");
    InitializeObjectAttributes(&oa,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
    for(i=0;i<2;++i) {
        s=ZwCreateEvent(&kernel[i],EVENT_ALL_ACCESS,&oa,NotificationEvent,FALSE);
        check(s==STATUS_SUCCESS && ((ULONG_PTR)kernel[i]&MARKER)==MARKER,"kernel-handle-marker");
        if(!NT_SUCCESS(s)) return s;
        s=ObReferenceObjectByHandle(kernel[i],0,NULL,KernelMode,&objects[i],NULL);
        check(s==STATUS_SUCCESS && objects[i],"retain-test-event");
        if(!NT_SUCCESS(s)) return s;
        pointer_baseline[i]=*(volatile LONG64 *)((PUCHAR)objects[i]-0x30);
    }
    s=PsSetCreateProcessNotifyRoutine(notify,FALSE); check(s==STATUS_SUCCESS,"register-notify");
    if(!NT_SUCCESS(s)) return s;
    s=PsCreateSystemThread(&thread,THREAD_ALL_ACCESS,NULL,NULL,NULL,monitor,NULL);
    check(s==STATUS_SUCCESS && thread,"create-monitor");
    if(!NT_SUCCESS(s)) { PsSetCreateProcessNotifyRoutine(notify,TRUE); return s; }
    check(ZwClose(thread)==STATUS_SUCCESS,"close-monitor-handle");
    DbgPrint("HANDLE_TABLES READY\n"); return STATUS_SUCCESS;
}




