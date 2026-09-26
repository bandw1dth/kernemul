; Emulator guest only. Never execute on the host.
OPTION DOTNAME
OPTION NOSCOPED
EXTERN __C_specific_handler:PROC
PUBLIC ExceptionInvalidMsr, ExceptionIllegalInstruction, ExceptionHandlerRax

.code
ExceptionInvalidMsr PROC
    mov ecx, 0ffffffffh
    mov eax, 13579bdfh
    rdmsr
    ret
ExceptionInvalidMsr ENDP

ExceptionIllegalInstruction PROC
    mov eax, 13579bdfh
    ud2
    ret
ExceptionIllegalInstruction ENDP

; Minimal equivalent of __try { invalid RDMSR; }
; __except(EXCEPTION_EXECUTE_HANDLER) { return handler_entry_rax; }
; Hand-written unwind metadata below keeps the handler from truncating RAX.
ExceptionHandlerRax PROC
    sub rsp, 28h
RaxPrologEnd:
RaxTryBegin:
    mov ecx, 0ffffffffh
    mov eax, 13579bdfh
    rdmsr
RaxTryEnd:
    xor eax, eax                 ; No fault must fail the comparison.
RaxHandler:
    add rsp, 28h                 ; Preserve all 64 bits of handler-entry RAX.
    ret
RaxFunctionEnd:
ExceptionHandlerRax ENDP

.pdata SEGMENT READONLY
    DD imagerel ExceptionHandlerRax
    DD imagerel RaxFunctionEnd
    DD imagerel RaxUnwind
.pdata ENDS

.xdata SEGMENT READONLY
ALIGN 4
RaxUnwind LABEL BYTE
    DB 09h                      ; Version 1, UNW_FLAG_EHANDLER.
    DB RaxPrologEnd - ExceptionHandlerRax
    DB 1, 0                     ; One unwind code, no frame register.
    DB RaxPrologEnd - ExceptionHandlerRax, 42h ; UWOP_ALLOC_SMALL: 40 bytes.
    DW 0                        ; Pad unwind codes to DWORD boundary.
    DD imagerel __C_specific_handler
    DD 1                        ; One SCOPE_TABLE entry.
    DD imagerel RaxTryBegin
    DD imagerel RaxTryEnd
    DD 1                        ; EXCEPTION_EXECUTE_HANDLER constant filter.
    DD imagerel RaxHandler
.xdata ENDS
END
