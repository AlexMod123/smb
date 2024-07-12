
.data
;x$ = 8
.code
_htons32 PROC
	mov	 eax, ecx
	bswap eax
	ret 
_htons32 ENDP
_htons16 PROC
	mov ax, cx
	xchg ah, al
	ret
_htons16 ENDP
END  