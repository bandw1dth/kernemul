.code
ob_user_cpl PROC
    xor eax, eax
    mov ax, cs
    and eax, 3
    ret
ob_user_cpl ENDP
END
