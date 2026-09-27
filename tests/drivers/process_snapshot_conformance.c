/* Emulator guest only: public x64 class-5 wire layout; no private object offsets. */
#include <ntifs.h>
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);
NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG);
#define SELF ((HANDLE)(LONG_PTR)-1)
#define CAP 131072
static DECLSPEC_ALIGN(8) UCHAR data[CAP];
static LONG failures;
static ULONG used;
static KEVENT stop;
static HANDLE ownerId, childId;
static void check(BOOLEAN ok,const char *name) {
    DbgPrint("CONFORMANCE %s %s\n",ok?"PASS":"FAIL",name);
    if(!ok) ++failures;
}
static ULONG u32(PUCHAR p,ULONG o) { return *(ULONG *)(p+o); }
static HANDLE ptr(PUCHAR p,ULONG o) { return *(HANDLE *)(p+o); }
static PUCHAR find(HANDLE pid) {
    ULONG o=0;
    while(o+0x100<=used) {
        PUCHAR p=data+o; ULONG n=u32(p,0);
        if(ptr(p,0x50)==pid) return p;
        if(!n || n>used-o || n<0x100) break;
        o+=n;
    }
    return NULL;
}
static BOOLEAN snapshot(void) {
    ULONG o=0; BOOLEAN valid=TRUE, registry=FALSE, ended=FALSE;
    NTSTATUS s=ZwQuerySystemInformation(5,data,CAP,&used);
    check(s==STATUS_SUCCESS && used<=CAP && used>=0x100,"snapshot-success");
    if(s!=STATUS_SUCCESS || used>CAP) { used=0; return FALSE; }
    while(o+0x100<=used) {
        PUCHAR p=data+o; ULONG n=u32(p,0), count=u32(p,4), span=n?n:used-o;
        UNICODE_STRING *name=(UNICODE_STRING *)(p+0x38);
        ULONG_PTR start=(ULONG_PTR)name->Buffer, lo=(ULONG_PTR)p;
        if(span<0x100 || span>used-o || (n&7) || count>(span-0x100)/0x50 ||
           name->Length>30 || (name->Length&1) || name->MaximumLength!=name->Length+2 ||
           start<lo+0x100+(ULONG_PTR)count*0x50 || start>lo+span ||
           name->MaximumLength>lo+span-start) { valid=FALSE; break; }
        if(name->Buffer[name->Length/2]!=0) { valid=FALSE; break; }
        if(name->Length==16 && RtlCompareMemory(name->Buffer,L"Registry",16)==16) {
            registry=TRUE; check(count==0,"registry-zero-threads");
        }
        if(!n) { ended=TRUE; break; } o+=n;
    }
    check(valid && ended,"walk-offset-name-thread-bounds-nul");
    check(registry,"registry-eight-character-name-present");
    if(!valid || !ended) used=0; /* Never walk a rejected record in later checks. */
    return valid && ended;
}
static ULONG handles(HANDLE pid) {
    PUCHAR p=find(pid); check(p!=NULL,"count-process-present"); return p?u32(p,0x60):0;
}
static ULONG threads(HANDLE pid) { PUCHAR p=find(pid); return p?u32(p,4):0; }
static PUCHAR thread(HANDLE pid,HANDLE tid) {
    PUCHAR p=find(pid); ULONG i;
    if(p) for(i=0;i<u32(p,4);++i) {
        PUCHAR t=p+0x100+i*0x50;
        if(ptr(t,0x30)==tid && ptr(t,0x28)==pid) return t;
    }
    return NULL;
}
static void child(PVOID unused) {
    LARGE_INTEGER timeout; UNREFERENCED_PARAMETER(unused);
    timeout.QuadPart=-100000000;
    KeWaitForSingleObject(&stop,Executive,KernelMode,FALSE,&timeout);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path) {
    ULONG need=0,i,base,targetBase,beforeThreads; NTSTATUS s;
    HANDLE event=NULL,ph=NULL,copy=NULL,th=NULL; PEPROCESS target=NULL;
    CLIENT_ID cid; KAPC_STATE apc; OBJECT_ATTRIBUTES oa; LARGE_INTEGER timeout;
    PUCHAR t; HANDLE currentTid=PsGetCurrentThreadId();
    UNREFERENCED_PARAMETER(driver); UNREFERENCED_PARAMETER(path);
    ownerId=PsGetProcessId(PsGetThreadProcess(PsGetCurrentThread()));
    check(ZwQuerySystemInformation(5,NULL,0,&need)==STATUS_INFO_LENGTH_MISMATCH && need>=0x100,"zero-query-required-length");
    RtlFillMemory(data,sizeof(data),0xA5);
    s=ZwQuerySystemInformation(5,data,1,&used);
    for(i=0;i<CAP && data[i]==0xA5;++i) {}
    check(s==STATUS_INFO_LENGTH_MISMATCH && used==need && i==CAP,"short-buffer-entire-canary-untouched");
    if(!snapshot()) goto done;
    check(thread(ownerId,currentTid)!=NULL,"current-real-cid-present");
    s=PsLookupProcessByProcessId((HANDLE)8,&target);
    check(s==STATUS_SUCCESS && target!=NULL,"seed-target-lookup");
    if(!target) goto done;
    s=ObOpenObjectByPointer(target,0,NULL,0x40,NULL,KernelMode,&ph);
    check(s==STATUS_SUCCESS && ph,"open-target-process");
    if(!ph) goto done;
    snapshot(); base=handles(ownerId); targetBase=handles((HANDLE)8);
    InitializeObjectAttributes(&oa,NULL,0,NULL,NULL);
    s=ZwCreateEvent(&event,EVENT_ALL_ACCESS,&oa,NotificationEvent,FALSE);
    check(s==STATUS_SUCCESS && event,"open-local-event");
    snapshot(); check(handles(ownerId)==base+1,"open-increments-owner-count");
    KeStackAttachProcess(target,&apc);
    check(PsGetProcessId(PsGetThreadProcess(PsGetCurrentThread()))==ownerId,"attached-thread-retains-original-owner");
    snapshot(); check(thread(ownerId,currentTid)!=NULL && threads((HANDLE)8)==0,"attached-snapshot-thread-owner");
    KeUnstackDetachProcess(&apc);
    s=ZwDuplicateObject(SELF,event,ph,&copy,0,0,DUPLICATE_SAME_ACCESS);
    check(s==STATUS_SUCCESS && copy,"duplicate-into-seeded-target");
    snapshot(); check(handles(ownerId)==base+1 && handles((HANDLE)8)==targetBase+1,"duplicate-source-target-counts");
    KeStackAttachProcess(target,&apc);
    if(copy) { check(ZwClose(copy)==STATUS_SUCCESS,"close-attached-duplicate"); copy=NULL; }
    KeUnstackDetachProcess(&apc);
    snapshot(); check(handles(ownerId)==base+1 && handles((HANDLE)8)==targetBase,"duplicate-close-restores-target-count");
    if(event) { check(ZwClose(event)==STATUS_SUCCESS,"close-local-event"); event=NULL; }
    snapshot(); check(handles(ownerId)==base,"close-restores-owner-count");
    beforeThreads=threads(ownerId); KeInitializeEvent(&stop,NotificationEvent,FALSE);
    s=PsCreateSystemThread(&th,THREAD_ALL_ACCESS,NULL,NULL,&cid,child,NULL);
    check(s==STATUS_SUCCESS && th,"create-held-system-thread");
    if(th) {
        childId=cid.UniqueThread; snapshot(); t=thread(ownerId,childId);
        check(cid.UniqueProcess==ownerId && t && ptr(t,0x20)==(HANDLE)child &&
            *(LONGLONG *)(t+0x10)!=0 && (LONG)u32(t,0x38)>0 && u32(t,0x44)<=7,
            "held-thread-real-cid-start-time-priority-state");
        check(threads(ownerId)==beforeThreads+1,"held-thread-owner-count-delta");
        KeSetEvent(&stop,IO_NO_INCREMENT,FALSE); timeout.QuadPart=-20000000;
        check(ZwWaitForSingleObject(th,FALSE,&timeout)==STATUS_SUCCESS,"wait-held-thread-exit");
        snapshot(); check(!thread(ownerId,childId) && threads(ownerId)==beforeThreads,"exited-thread-removed");
        check(ZwClose(th)==STATUS_SUCCESS,"close-thread-handle");
    }
done:
    if(event) ZwClose(event);
    if(ph) check(ZwClose(ph)==STATUS_SUCCESS,"close-process-handle");
    if(target) ObDereferenceObject(target);
    DbgPrint("PROCESS_SNAPSHOTS COMPLETE\n");
    DbgPrint("CONFORMANCE RESULT failures=%ld\n",failures);
    return failures?STATUS_UNSUCCESSFUL:STATUS_SUCCESS;
}

