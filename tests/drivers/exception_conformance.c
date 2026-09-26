#include <ntifs.h>

/* Emulator guest only. Never install or load this fixture on the host. */
extern void ExceptionInvalidMsr(void);
extern void ExceptionIllegalInstruction(void);
extern ULONGLONG ExceptionHandlerRax(void);

static LONG failures;

static void check(BOOLEAN ok, const char *name)
{
    DbgPrint("CONFORMANCE %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
    volatile BOOLEAN entered = FALSE;
    volatile ULONG code = 0;
    ULONGLONG handlerRax;
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(path);

    /* Both leaf helpers set EAX=0x13579bdf immediately before faulting.
       GetExceptionCode here reads the compiler's handler-entry EAX, rather
       than the exception record passed to an exception filter. */
    __try {
        ExceptionInvalidMsr();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
        entered = TRUE;
    }
    DbgPrint("CONFORMANCE INFO rdmsr code=%08lx\n", code);
    check(entered, "rdmsr-handler-entered");
    check(code == (ULONG)STATUS_ACCESS_VIOLATION, "rdmsr-GetExceptionCode");

    entered = FALSE;
    code = 0;
    __try {
        ExceptionIllegalInstruction();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
        entered = TRUE;
    }
    DbgPrint("CONFORMANCE INFO ud2 code=%08lx\n", code);
    check(entered, "ud2-handler-entered");
    check(code == (ULONG)STATUS_ILLEGAL_INSTRUCTION, "ud2-GetExceptionCode");

    /* A C GetExceptionCode check cannot detect zero-extension of RAX. */
    handlerRax = ExceptionHandlerRax();
    DbgPrint("CONFORMANCE INFO handler-rax=%016I64x\n", handlerRax);
    check(handlerRax == 0xffffffffc0000005ui64, "rdmsr-handler-rax-sign-extended");

    DbgPrint("CONFORMANCE RESULT failures=%ld\n", failures);
    return failures ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
