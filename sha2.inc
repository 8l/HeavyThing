	; ------------------------------------------------------------------------
	; HeavyThing x86_64 assembly language library and showcase programs
	; Copyright © 2015, 2016 2 Ton Digital 
	; Homepage: https://2ton.com.au/
	; Author: Jeff Marrison <jeff@2ton.com.au>
	;       
	; This file is part of the HeavyThing library.
	;       
	; HeavyThing is free software: you can redistribute it and/or modify
	; it under the terms of the GNU General Public License, or
	; (at your option) any later version.
	;       
	; HeavyThing is distributed in the hope that it will be useful, 
	; but WITHOUT ANY WARRANTY; without even the implied warranty of
	; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
	; GNU General Public License for more details.
	;       
	; You should have received a copy of the GNU General Public License along
	; with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
	; ------------------------------------------------------------------------
	;       
	; sha2.inc: SHA2-{224,256,384,512} goods
	;
	;
	; lots of different ways to skin this cat floating around on the net..
	; someday when I am bored, implement the different ones ;-)
	;
	; these perform as good or better than anything else i could find that
	; was non-SSE4/AVX/AVX2
	; translated loosely from some of the public domain goods from Wei Dai
	; and modified to suit my environment
	;


sha224_state_size = 144
sha256_state_size = 144
sha384_state_size = 240
sha512_state_size = 240

sha_stateptr_ofs = 0
sha_bitcountptr_ofs = 8
sha_bufferptr_ofs = 16

; sha224/sha256 == 32 bytes for stateptr, 16 bytes for bitcount, 64 bytes for buffer, _after_ our three pointers
; sha384/sha512 == 64 bytes for stateptr, 16 bytes for bitcount, 128 bytes for buffer, _after_ our three pointers
;
; on init, we make sure all three of the pointer values are 16 byte aligned

if used sha224$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the sha224$init on it
	; returns initialized state
falign
sha224$new:
	prolog	sha224$new
	mov	edi, sha224_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha224$init
	pop	rax
	epilog

end if

if used sha224$init | defined include_everything
	; single argument in rdi: our sha state
	; void return
falign
sha224$init:
	prolog	sha224$init
	; if rdi is 16 aligned on entry, then stateptr == rdi+32, bitcountptr == rdi+64, bufferptr = rdi+80
	; if it is not aligned on entry, then stateptr == rdi+24, bitcountptr == rdi+56, bufferptr = rdi+72
	lea	rax, [rdi+32]
	lea	rcx, [rdi+64]
	lea	rdx, [rdi+80]
	lea	r8, [rdi+24]
	lea	r9, [rdi+56]
	lea	r10, [rdi+72]
	test	rdi, 0xf
	cmovnz	rax, r8
	cmovnz	rcx, r9
	cmovnz	rdx, r10
	xor	esi, esi
	mov	[rdi+sha_stateptr_ofs], rax
	mov	[rdi+sha_bitcountptr_ofs], rcx
	mov	[rdi+sha_bufferptr_ofs], rdx
	; so now, each of the 3 pointers is 16 byte aligned within our own state
	push	rax
	add	rdi, 24
	mov	edx, sha224_state_size - 24
	call	memset32
	pop	rdi
	mov	rsi, .initial_hash
	mov	edx, 32
	call	memcpy
	epilog
dalign
.initial_hash:
	dd	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4

end if


if used sha256$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the sha256$init on it
	; returns initialized state
falign
sha256$new:
	prolog	sha256$new
	mov	rdi, sha256_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha256$init
	pop	rax
	epilog

end if


if used sha256$init | defined include_everything
	; single argument in rdi: our sha state
	; void return
falign
sha256$init:
	prolog	sha256$init
	; if rdi is 16 aligned on entry, then stateptr == rdi+32, bitcountptr == rdi+64, bufferptr = rdi+80
	; if it is not aligned on entry, then stateptr == rdi+24, bitcountptr == rdi+56, bufferptr = rdi+72
	lea	rax, [rdi+32]
	lea	rcx, [rdi+64]
	lea	rdx, [rdi+80]
	lea	r8, [rdi+24]
	lea	r9, [rdi+56]
	lea	r10, [rdi+72]
	test	rdi, 0xf
	cmovnz	rax, r8
	cmovnz	rcx, r9
	cmovnz	rdx, r10
	xor	esi, esi
	mov	[rdi+sha_stateptr_ofs], rax
	mov	[rdi+sha_bitcountptr_ofs], rcx
	mov	[rdi+sha_bufferptr_ofs], rdx
	; so now, each of the 3 pointers is 16 byte aligned within our own state
	push	rax
	add	rdi, 24
	mov	edx, sha256_state_size - 24
	call	memset32
	pop	rdi
	mov	rsi, .initial_hash
	mov	edx, 32
	call	memcpy
	epilog
dalign
.initial_hash:
	dd	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19


end if



if used sha256$update | used sha224$update | defined include_everything
	; three arguments: rdi == sha state, rsi == byte buffer, rdx == length of same
	; void return
falign
sha256$update:
sha224$update:
	prolog	sha256$update
	mov	r8, [rdi+sha_bitcountptr_ofs]
	test	rdx, rdx
	jz	.nothingtodo
	mov	rcx, [r8]
	mov	r9d, 64
	shr	rcx, 3
	and	rcx, 0x3f
	test	rcx, rcx
	jz	.noused
	sub	r9d, ecx			; 64 - bytes used in the buffer
	cmp	rdx, r9				; are we adding less than the full block?
	jb	.needmore
	; otherwise, we need to fill our buffer, transform that, and then
	; leave the rest to a normal non-buffer based fill
	push	rdi rsi rdx
	mov	rdi, [rdi+sha_bufferptr_ofs]
	mov	rdx, r9
	add	qword [rsp+8], r9
	sub	qword [rsp], r9
	shl	r9, 3
	add	rdi, rcx
	add	qword [r8], r9
	call	memcpy
	mov	rdi, [rsp+16]
	; we need rdx to be set here to a flat 64 bytes for our buffer
	mov	edx, 64
	mov	rsi, [rdi+sha_bufferptr_ofs]
	call	sha256$transform
	pop	rdx rsi rdi
	mov	r8, [rdi+sha_bitcountptr_ofs]
	jmp	.noused
calign
.needmore:
	; rdx is less than the number of bytes we have left in our buffer
	mov	r10, rdx
	shl	r10, 3
	mov	rdi, [rdi+sha_bufferptr_ofs]
	add	qword [r8], r10
	add	rdi, rcx
	call	memcpy
	epilog
calign
.noused:
	; update our bitcount in its entirety beforehand
	mov	rcx, rdx
	shl	rcx, 3
	add	qword [r8], rcx
	cmp	rdx, 64
	jb	.partial
	call	sha256$transform
	; it returns us with how many bytes it did _not_ process
	; and rsi/rdx is the goods that we'd need to copy if there are leftovers
	test	rdx, rdx
	jnz	.partial
	epilog
calign
.partial:
	mov	rdi, [rdi+sha_bufferptr_ofs]
	call	memcpy
	epilog
calign
.nothingtodo:
	epilog


end if


if used sha256$transform | defined include_everything
	; note: not meant to be called externally, but for profiling reasons down the track
	; is made with the normal profiler/public symbol entries
	; called from sha256$update and sha256$final


	; note: keeping the state (8 dwords) in registers is marginally faster than doing it
	; entirely on the stack... though some quality time really needs to be spent in here
	; actually optimizing it properly, hahah, crazy that decoder speed really does matter
	; through here...
sha256_stateregisters = 1

falign
sha256$transform:
	prolog	sha256$transform
	; rdi == our state, rsi == (dd) data
	; we must preserve rdi, rsi, and rdx (updating rsi/rdx as we go), but we are free to kill everything else
	sub	rsp, 288
	mov	eax, 288
	mov	ecx, 280
	lea	r8, [rsp+8]
	test	rsp, 0xf
	cmovnz	rsp, r8
	cmovnz	eax, ecx

	mov	[rsp+0x88], rbx
	mov	[rsp+0x90], rdi
	mov	[rsp+0x98], rsi
	mov	[rsp+0xa0], rdx

	mov	rdi, [rdi+sha_stateptr_ofs]

	mov	qword [rsp+0x80], rax		; amount to add to the stack when we are done
	; so now, we have an aligned 16 stack with the ability to correctly replace it when we are done
if sha256_stateregisters
	; save four more of our callee-saves
	mov	[rsp+0xa8], r12
	mov	[rsp+0xb0], r13
	mov	[rsp+0xb8], r14
	mov	[rsp+0xc0], r15
end if

	; so now we have an aligned-16 working block at rcx on our stack
	; rsi still pointed at our data
	
	mov	qword [rsp+0x68], rdi	; STATE_SAVE

if sha256_stateregisters
	; we want to use r8d..r15d for our state instead of the aligned first 32 bytes of our stack
	mov	r8d, [rdi]
	mov	r9d, [rdi+4]
	mov	r10d, [rdi+8]
	mov	r11d, [rdi+12]
	mov	r12d, [rdi+16]
	mov	r13d, [rdi+20]
	mov	r14d, [rdi+24]
	mov	r15d, [rdi+28]
else
	movdqa	xmm0, [rdi]
	movdqa	xmm1, [rdi+16]
	movdqa	[rsp], xmm0
	movdqa	[rsp+16], xmm1
end if

calign
.nextblock:	; here is where we jump to from the bottom if there was more to do

	; setup rest of message from our data
if use_movbe
	mov	rax, [rsi]
	mov	rbx, [rsi+0x8]
	mov	rcx, [rsi+0x10]
	movbe	[rsp+0x58], rax
	movbe	[rsp+0x50], rbx
	movbe	[rsp+0x48], rcx
	mov	rdx, [rsi+0x18]
	mov	rax, [rsi+0x20]
	mov	rbx, [rsi+0x28]
	movbe	[rsp+0x40], rdx
	movbe	[rsp+0x38], rax
	movbe	[rsp+0x30], rbx
	mov	rcx, [rsi+0x30]
	mov	rdx, [rsi+0x38]
	movbe	[rsp+0x28], rcx
	movbe	[rsp+0x20], rdx
else
	mov	rax, [rsi]
	mov	rbx, [rsi+0x8]
	mov	rcx, [rsi+0x10]
	bswap	rax
	bswap	rbx
	bswap	rcx
	mov	[rsp+0x58], rax
	mov	[rsp+0x50], rbx
	mov	[rsp+0x48], rcx
	mov	rdx, [rsi+0x18]
	mov	rax, [rsi+0x20]
	mov	rbx, [rsi+0x28]
	bswap	rdx
	bswap	rax
	bswap	rbx
	mov	[rsp+0x40], rdx
	mov	[rsp+0x38], rax
	mov	[rsp+0x30], rbx
	mov	rcx, [rsi+0x30]
	mov	rdx, [rsi+0x38]
	bswap	rcx
	bswap	rdx
	mov	[rsp+0x28], rcx
	mov	[rsp+0x20], rdx
end if

if sha256_stateregisters
	mov	eax, r9d		; B
	mov	edi, r12d		; E
	mov	ecx, r8d		; A
	xor	eax, r10d		; B^C
else
	mov	eax, dword [rsp+0x4]	; B
	mov	edi, [rsp+0x10]		; E
	mov	ecx, dword [rsp]	; A
	xor	eax, dword [rsp+0x8]	; B^C
end if

macro sha256_rb1 i*, r1*, r2*, kofs* {
	local	H,Hr,Wt,Wt2,Wt7,Wt15
	H = ((1024 + 7 - i) and 7)
	Wt= (((1024 + 15 - i) and 15) * 4) + 32
	Wt2=(((1024 + 15 - (i - 2)) and 15) * 4) + 32
	Wt7=(((1024 + 15 - (i - 7)) and 15) * 4) + 32
	Wt15=(((1024 + 15 - (i - 15)) and 15) * 4) + 32
	
	mov	esi, [rsp+Wt2]				; W reference
	mov	r2, [rsp+Wt15]				; W reference
	mov	ebx, esi
	shr	esi, 10
	ror	ebx, 17
	xor	esi, ebx
	ror	ebx, 2
	xor	ebx, esi
	mov	esi, r2
	add	ebx, [rsp+Wt7]				; W reference
	shr	esi, 3
	ror	r2, 7
	add	ebx, [rsp+Wt]				; W reference
	xor	esi, r2
	add	r1, [.k + kofs + i*4]				; k reference
	ror	r2, 11
if sha256_stateregisters
	; add	r1, [rsp+H*4]				; state reference
if H = 0
	add	r1, r8d
else if H = 1
	add	r1, r9d
else if H = 2
	add	r1, r10d
else if H = 3
	add	r1, r11d
else if H = 4
	add	r1, r12d
else if H = 5
	add	r1, r13d
else if H = 6
	add	r1, r14d
else if H = 7
	add	r1, r15d
end if
else
	add	r1, [rsp+H*4]				; state reference
end if
	xor	esi, r2
	add	esi, ebx
	mov	[rsp+Wt], esi				; W reference
	add	r1, esi
}

macro sha256_round i*, r*, r1*, r2*, r3*, r4*, kofs* {
	; r1 == eax
	; r2 == ecx
	; r3 == edi
	; r4 == edx
	local	H,G,F,E,D,C,B,A,Wt
	H = ((1024 + 7 - i) and 7)
	G = ((1024 + 7 - (i + 1)) and 7)
	F = ((1024 + 7 - (i + 2)) and 7)
	E = ((1024 + 7 - (i + 3)) and 7)
	D = ((1024 + 7 - (i + 4)) and 7)
	C = ((1024 + 7 - (i + 5)) and 7)
	B = ((1024 + 7 - (i + 6)) and 7)
	A = ((1024 + 7 - (i + 7)) and 7)
	Wt= (((1024 + 15 - i) and 15) * 4) + 32
	
	mov	esi, r3
if sha256_stateregisters
	; mov	r4, [rsp+F*4]				; state reference
if F = 0
	mov	r4, r8d
else if F = 1
	mov	r4, r9d
else if F = 2
	mov	r4, r10d
else if F = 3
	mov	r4, r11d
else if F = 4
	mov	r4, r12d
else if F = 5
	mov	r4, r13d
else if F = 6
	mov	r4, r14d
else if F = 7
	mov	r4, r15d
end if
else
	mov	r4, [rsp+F*4]				; state reference
end if
if sha256_stateregisters
	; xor	r4, [rsp+G*4]				; state reference
if G = 0
	xor	r4, r8d
else if G = 1
	xor	r4, r9d
else if G = 2
	xor	r4, r10d
else if G = 3
	xor	r4, r11d
else if G = 4
	xor	r4, r12d
else if G = 5
	xor	r4, r13d
else if G = 6
	xor	r4, r14d
else if G = 7
	xor	r4, r15d
end if
else
	xor	r4, [rsp+G*4]				; state reference
end if
	ror	esi, 25
	and	r4, r3
if sha256_stateregisters
	; xor	r4, [rsp+G*4]				; state reference
if G = 0
	xor	r4, r8d
else if G = 1
	xor	r4, r9d
else if G = 2
	xor	r4, r10d
else if G = 3
	xor	r4, r11d
else if G = 4
	xor	r4, r12d
else if G = 5
	xor	r4, r13d
else if G = 6
	xor	r4, r14d
else if G = 7
	xor	r4, r15d
end if
else
	xor	r4, [rsp+G*4]				; state reference
end if

	ror	r3, 6
if r = 0
	add	r4, [.k + kofs + i*4]				; k reference
end if
	xor	esi, r3
if r = 0
	add	r4, [rsp+Wt]				; W reference
end if
	ror	r3, 5
if r = 0
if sha256_stateregisters
	; add	r4, [rsp+H*4]				; state reference
if H = 0
	add	r4, r8d
else if H = 1
	add	r4, r9d
else if H = 2
	add	r4, r10d
else if H = 3
	add	r4, r11d
else if H = 4
	add	r4, r12d
else if H = 5
	add	r4, r13d
else if H = 6
	add	r4, r14d
else if H = 7
	add	r4, r15d
end if
else
	add	r4, [rsp+H*4]				; state reference
end if

end if
	xor	esi, r3
	add	r4, esi

if r = 1
	sha256_rb1 i, r4, r3, kofs
end if

	mov	ebx, r2
	mov	esi, r2
if sha256_stateregisters
	; xor	r2, [rsp+B*4]				; state reference
if B = 0
	xor	r2, r8d
else if B = 1
	xor	r2, r9d
else if B = 2
	xor	r2, r10d
else if B = 3
	xor	r2, r11d
else if B = 4
	xor	r2, r12d
else if B = 5
	xor	r2, r13d
else if B = 6
	xor	r2, r14d
else if B = 7
	xor	r2, r15d
end if
else
	xor	r2, [rsp+B*4]				; state reference
end if
	and	r1, r2
	ror	ebx, 2
if sha256_stateregisters
	; xor	r1, [rsp+B*4]				; state reference
if B = 0
	xor	r1, r8d
else if B = 1
	xor	r1, r9d
else if B = 2
	xor	r1, r10d
else if B = 3
	xor	r1, r11d
else if B = 4
	xor	r1, r12d
else if B = 5
	xor	r1, r13d
else if B = 6
	xor	r1, r14d
else if B = 7
	xor	r1, r15d
end if
else
	xor	r1, [rsp+B*4]				; state reference
end if
	add	r1, r4
	ror	esi, 22
if sha256_stateregisters
	; add	r4, [rsp+D*4]				; state reference
if D = 0
	add	r4, r8d
else if D = 1
	add	r4, r9d
else if D = 2
	add	r4, r10d
else if D = 3
	add	r4, r11d
else if D = 4
	add	r4, r12d
else if D = 5
	add	r4, r13d
else if D = 6
	add	r4, r14d
else if D = 7
	add	r4, r15d
end if
else
	add	r4, [rsp+D*4]				; state reference
end if
	xor	esi, ebx
if sha256_stateregisters
	; mov	[rsp+D*4], r4				; state reference (write)
if D = 0
	mov	r8d, r4
else if D = 1
	mov	r9d, r4
else if D = 2
	mov	r10d, r4
else if D = 3
	mov	r11d, r4
else if D = 4
	mov	r12d, r4
else if D = 5
	mov	r13d, r4
else if D = 6
	mov	r14d, r4
else if D = 7
	mov	r15d, r4
end if
else
	mov	[rsp+D*4], r4				; state reference (write)
end if
	ror	ebx, 11
	xor	esi, ebx
	add	r1, esi
if sha256_stateregisters
	; mov	[rsp+H*4], r1				; state reference (write)
if H = 0
	mov	r8d, r1
else if H = 1
	mov	r9d, r1
else if H = 2
	mov	r10d, r1
else if H = 3
	mov	r11d, r1
else if H = 4
	mov 	r12d, r1
else if H = 5
	mov	r13d, r1
else if H = 6
	mov	r14d, r1
else if H = 7
	mov	r15d, r1
end if
else
	mov	[rsp+H*4], r1				; state reference (write)
end if
}
        sha256_round 0, 0, eax, ecx, edi, edx, 0x0
        sha256_round 1, 0, ecx, eax, edx, edi, 0x0
        sha256_round 2, 0, eax, ecx, edi, edx, 0x0
        sha256_round 3, 0, ecx, eax, edx, edi, 0x0
        sha256_round 4, 0, eax, ecx, edi, edx, 0x0
        sha256_round 5, 0, ecx, eax, edx, edi, 0x0
        sha256_round 6, 0, eax, ecx, edi, edx, 0x0
        sha256_round 7, 0, ecx, eax, edx, edi, 0x0
        sha256_round 8, 0, eax, ecx, edi, edx, 0x0
        sha256_round 9, 0, ecx, eax, edx, edi, 0x0
        sha256_round 10, 0, eax, ecx, edi, edx, 0x0
        sha256_round 11, 0, ecx, eax, edx, edi, 0x0
        sha256_round 12, 0, eax, ecx, edi, edx, 0x0
        sha256_round 13, 0, ecx, eax, edx, edi, 0x0
        sha256_round 14, 0, eax, ecx, edi, edx, 0x0
        sha256_round 15, 0, ecx, eax, edx, edi, 0x0

        sha256_round 0, 1, eax, ecx, edi, edx, 0x40
        sha256_round 1, 1, ecx, eax, edx, edi, 0x40
        sha256_round 2, 1, eax, ecx, edi, edx, 0x40
        sha256_round 3, 1, ecx, eax, edx, edi, 0x40
        sha256_round 4, 1, eax, ecx, edi, edx, 0x40
        sha256_round 5, 1, ecx, eax, edx, edi, 0x40
        sha256_round 6, 1, eax, ecx, edi, edx, 0x40
        sha256_round 7, 1, ecx, eax, edx, edi, 0x40
        sha256_round 8, 1, eax, ecx, edi, edx, 0x40
        sha256_round 9, 1, ecx, eax, edx, edi, 0x40
        sha256_round 10, 1, eax, ecx, edi, edx, 0x40
        sha256_round 11, 1, ecx, eax, edx, edi, 0x40
        sha256_round 12, 1, eax, ecx, edi, edx, 0x40
        sha256_round 13, 1, ecx, eax, edx, edi, 0x40
        sha256_round 14, 1, eax, ecx, edi, edx, 0x40
        sha256_round 15, 1, ecx, eax, edx, edi, 0x40

        sha256_round 0, 1, eax, ecx, edi, edx, 0x80
        sha256_round 1, 1, ecx, eax, edx, edi, 0x80
        sha256_round 2, 1, eax, ecx, edi, edx, 0x80
        sha256_round 3, 1, ecx, eax, edx, edi, 0x80
        sha256_round 4, 1, eax, ecx, edi, edx, 0x80
        sha256_round 5, 1, ecx, eax, edx, edi, 0x80
        sha256_round 6, 1, eax, ecx, edi, edx, 0x80
        sha256_round 7, 1, ecx, eax, edx, edi, 0x80
        sha256_round 8, 1, eax, ecx, edi, edx, 0x80
        sha256_round 9, 1, ecx, eax, edx, edi, 0x80
        sha256_round 10, 1, eax, ecx, edi, edx, 0x80
        sha256_round 11, 1, ecx, eax, edx, edi, 0x80
        sha256_round 12, 1, eax, ecx, edi, edx, 0x80
        sha256_round 13, 1, ecx, eax, edx, edi, 0x80
        sha256_round 14, 1, eax, ecx, edi, edx, 0x80
        sha256_round 15, 1, ecx, eax, edx, edi, 0x80

        sha256_round 0, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 1, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 2, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 3, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 4, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 5, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 6, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 7, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 8, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 9, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 10, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 11, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 12, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 13, 1, ecx, eax, edx, edi, 0xc0
        sha256_round 14, 1, eax, ecx, edi, edx, 0xc0
        sha256_round 15, 1, ecx, eax, edx, edi, 0xc0


	mov	rdx, [rsp+0xa0]
	mov	rcx, [rsp+0x68]		; STATE_SAVE
	mov	rsi, [rsp+0x98]
	sub	rdx, 64
	add	rsi, 64
	cmp	rdx, 64
	jae	.moretogo
	; else, remaining bytes is < a full block, so bailout

	; store our updated state and restore our goods
if sha256_stateregisters
	add	dword [rcx], r8d
	add	dword [rcx+4], r9d
	add	dword [rcx+8], r10d

	mov	rax, [rsp+0x80]			; amount to add to the stack
	mov	rbx, [rsp+0x88]
	mov	rdi, [rsp+0x90]

	add	dword [rcx+12], r11d
	add	dword [rcx+16], r12d
	add	dword [rcx+20], r13d
	add	dword [rcx+24], r14d
	add	dword [rcx+28], r15d

	mov	r12, [rsp+0xa8]
	mov	r13, [rsp+0xb0]
	mov	r14, [rsp+0xb8]
	mov	r15, [rsp+0xc0]
else
	movdqa	xmm0, [rcx]
	movdqa	xmm1, [rcx+16]

	mov	rax, [rsp+0x80]			; amount to add to the stack
	mov	rbx, [rsp+0x88]
	mov	rdi, [rsp+0x90]

	paddd	xmm0, [rsp]
	paddd	xmm1, [rsp+16]
	movdqa	[rcx], xmm0
	movdqa	[rcx+16], xmm1
end if
	add	rsp, rax
	epilog
calign
.moretogo:
if sha256_stateregisters
	; at the end of each block, we still need to add the original state:
	; we need to put them back too
	add	r8d, dword [rcx]
	add	r9d, dword [rcx+4]
	add	r10d, dword [rcx+8]

	mov	dword [rcx], r8d
	mov	dword [rcx+4], r9d
	mov	dword [rcx+8], r10d

	add	r11d, dword [rcx+12]
	add	r12d, dword [rcx+16]
	add	r13d, dword [rcx+20]

	mov	dword [rcx+12], r11d
	mov	dword [rcx+16], r12d
	mov	dword [rcx+20], r13d

	add	r14d, dword [rcx+24]
	add	r15d, dword [rcx+28]

	mov	dword [rcx+24], r14d
	mov	dword [rcx+28], r15d
else
	movdqa	xmm0, [rcx]
	movdqa	xmm1, [rcx+16]
	paddd	xmm0, [rsp]
	paddd	xmm1, [rsp+16]
	movdqa	[rcx], xmm0
	movdqa	[rcx+16], xmm1
	; also need to udpate them in our state/stackframe:
	movdqa	[rsp], xmm0
	movdqa	[rsp+16], xmm1

end if

	; and we need to store our updated rsi/rdx for the next fallthrough
	mov	[rsp+0x98], rsi
	mov	[rsp+0xa0], rdx
	jmp	.nextblock
align 16
.k:
	dd	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
        dd	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
        dd	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
        dd	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
        dd	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
        dd	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
        dd	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
        dd	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2


end if

if used sha224$final | defined include_everything
	; three arguments: rdi == sha state, rsi == pointer to 28 byte buffer for the final digest, bool in edx as to whether we should heap$free the state
	; void return
falign
sha224$final:
	prolog	sha224$final
	push	rdi rsi
	sub	rsp, 32
	mov	rsi, rsp
	call	sha256$final
	mov	rdi, [rsp+32]	; rsi of 28 byte buffer
	mov	rsi, rsp
	mov	edx, 28
	call	memcpy
	add	rsp, 32
	pop	rsi rdi
	epilog
end if


if used sha224$mgf1 | defined include_everything
	; one-pass MGF1 as defined by rfc2437 (one-pass == we do stack-based state)
	; four arguments: rdi == seed, rsi == seed length, rdx == destination, rcx == dest length
falign
sha224$mgf1:
	prolog	sha224$mgf1
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	sub	rsp, sha224_state_size + 28 + 8
	mov	rdi, rsp
	call	sha224$init
	mov	qword [rsp+sha224_state_size+28], 0
calign
.doit:
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	sha224$update
	mov	eax, [rsp+sha224_state_size+28]
if use_movbe
	add	dword [rsp+sha224_state_size+28], 1
	movbe	[rsp+sha224_state_size+32], eax
else
	bswap	eax
	add	dword [rsp+sha224_state_size+28], 1
	mov	[rsp+sha224_state_size+32], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha224_state_size+32]
	mov	edx, 4
	call	sha224$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha224_state_size]
	xor	edx, edx
	call	sha224$final
	mov	rdi, r14
	lea	rsi, [rsp+sha224_state_size]
	mov	edx, 28
	cmp	rdx, r15
	cmova	rdx, r15
	add	r14, rdx
	sub	r15, rdx
	call	memcpy
	test	r15, r15
	jnz	.doit
	add	rsp, sha224_state_size + 28 + 8
	pop	r15 r14 r13 r12
	epilog

end if


if used sha256$final | defined include_everything
	; three arguments: rdi == sha state, rsi == pointer to 32 byte buffer for the final digest, bool in edx as to whether we should heap$free the state
	; void return
falign
sha256$final:
	prolog	sha256$final
	push	rdx rsi rdi

	mov	r8, [rdi+sha_bitcountptr_ofs]
if use_movbe
	mov	rcx, [r8]
	movbe	[r8], rcx
	shr	ecx, 3
	and	ecx, 0x3f
else
	mov	rcx, [r8]
	mov	r9, rcx
	bswap	r9
	shr	rcx, 3
	mov	[r8], r9		; bitcount reversed 64 bits
	and	rcx, 0x3f	
end if
	test	ecx, ecx		; usedspace?
	jz	.noused


	; else, we have to begin our padding with 1 bit: 0x80
	; short block length == 56
	mov	r10, [rdi+sha_bufferptr_ofs]
	mov	byte [r10+rcx], 0x80
	add	rcx, 1
	cmp	rcx, 56
	jle	.zeroremaining
	cmp	rcx, 64
	jae	.dosecondtolast
	; else, zero the remaining 64 - usedspace
	mov	rdi, r10
	add	rdi, rcx
	xor	esi, esi
	mov	edx, 64
	sub	edx, ecx
	call	memset
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
calign
.dosecondtolast:
	mov	rsi, [rdi+sha_bufferptr_ofs]
	mov	edx, 64
	call	sha256$transform
	; setup for final:
	mov	rdi, [rsp]
	xor	esi, esi
	mov	edx, 56
	mov	rdi, [rdi+sha_bufferptr_ofs]
	call	memset32
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	jmp	.dofinal
calign
.zeroremaining:
	mov	rdi, r10
	add	rdi, rcx
	xor	esi, esi
	mov	edx, 56
	sub	edx, ecx
	call	memset
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	jmp	.dofinal
calign
.noused:
	mov	rdi, [rdi+sha_bufferptr_ofs]
	xor	esi, esi
	mov	edx, 56
	call	memset32
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	r9, [rdi+sha_bufferptr_ofs]
	mov	dword [r9], 0x80
calign
.dofinal:
	mov	r8, [rdi+sha_bitcountptr_ofs]
	mov	rcx, [r8]
	mov	r9, [rdi+sha_bufferptr_ofs]
	mov	qword [r9+56], rcx
	mov	edx, 64
	mov	rsi, r9
	call	sha256$transform
	; rdi and rsi both stay in tact across that call
	mov	rsi, [rsp+8]
	mov	rdx, [rdi+sha_stateptr_ofs]
if use_movbe
	mov	eax, dword [rdx]
	mov	r8d, dword [rdx+4]
	mov	r9d, dword [rdx+8]
	movbe	dword [rsi], eax
	movbe	dword [rsi+4], r8d
	movbe	dword [rsi+8], r9d
	mov	r10d, dword [rdx+12]
	mov	eax, dword [rdx+16]
	mov	r8d, dword [rdx+20]
	movbe	dword [rsi+12], r10d
	movbe	dword [rsi+16], eax
	movbe	dword [rsi+20], r8d
	mov	r9d, dword [rdx+24]
	mov	r10d, dword [rdx+28]
	movbe	dword [rsi+24], r9d
	movbe	dword [rsi+28], r10d
else
	mov	eax, dword [rdx]
	mov	r8d, dword [rdx+4]
	mov	r9d, dword [rdx+8]
	bswap	eax
	bswap	r8d
	bswap	r9d
	mov	dword [rsi], eax
	mov	dword [rsi+4], r8d
	mov	dword [rsi+8], r9d
	mov	r10d, dword [rdx+12]
	mov	eax, dword [rdx+16]
	mov	r8d, dword [rdx+20]
	bswap	r10d
	bswap	eax
	bswap	r8d
	mov	dword [rsi+12], r10d
	mov	dword [rsi+16], eax
	mov	dword [rsi+20], r8d
	mov	r9d, dword [rdx+24]
	mov	r10d, dword [rdx+28]
	bswap	r9d
	bswap	r10d
	mov	dword [rsi+24], r9d
	mov	dword [rsi+28], r10d
end if
	; last but not least, reinitialize our state for further use
	; rdi is still intact
	call	sha256$init
	cmp	dword [rsp+16], 0
	jne	.freeandreturn
	add	rsp, 24
	epilog
calign
.freeandreturn:
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 24
	epilog

end if

if used sha256$mgf1 | defined include_everything
	; one-pass MGF1 as defined by rfc2437 (one-pass == we do stack-based state)
	; four arguments: rdi == seed, rsi == seed length, rdx == destination, rcx == dest length
falign
sha256$mgf1:
	prolog	sha256$mgf1
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	sub	rsp, sha256_state_size + 32 + 8
	mov	rdi, rsp
	call	sha256$init
	mov	qword [rsp+sha256_state_size+32], 0
calign
.doit:
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	sha256$update
	mov	eax, [rsp+sha256_state_size+32]
if use_movbe
	add	dword [rsp+sha256_state_size+32], 1
	movbe	[rsp+sha256_state_size+36], eax
else
	bswap	eax
	add	dword [rsp+sha256_state_size+32], 1
	mov	[rsp+sha256_state_size+36], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size+36]
	mov	edx, 4
	call	sha256$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	xor	edx, edx
	call	sha256$final
	mov	rdi, r14
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 32
	cmp	rdx, r15
	cmova	rdx, r15
	add	r14, rdx
	sub	r15, rdx
	call	memcpy
	test	r15, r15
	jnz	.doit
	add	rsp, sha256_state_size + 32 + 8
	pop	r15 r14 r13 r12
	epilog

end if



if used sha384$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the sha384$init on it
	; returns initialized state
falign
sha384$new:
	prolog	sha384$new
	mov	rdi, sha384_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha384$init
	pop	rax
	epilog

end if


if used sha384$init | defined include_everything
	; single argument in rdi: our sha state
	; void return
falign
sha384$init:
	prolog	sha384$init
	; if rdi is 16 aligned on entry, then stateptr == rdi+32, bitcountptr == rdi+96, bufferptr == rdi+112
	; if it is not aligned on entry, then stateptr == rdi+24, bitcountptr == rdi+88, bufferptr == rdi+104
	lea	rax, [rdi+32]
	lea	rcx, [rdi+96]
	lea	rdx, [rdi+112]
	lea	r8, [rdi+24]
	lea	r9, [rdi+88]
	lea	r10, [rdi+104]
	test	rdi, 0xf
	cmovnz	rax, r8
	cmovnz	rcx, r9
	cmovnz	rdx, r10
	xor	esi, esi
	mov	[rdi+sha_stateptr_ofs], rax
	mov	[rdi+sha_bitcountptr_ofs], rcx
	mov	[rdi+sha_bufferptr_ofs], rdx
	; so now, each of the 3 pointers is 16 byte aligned within our state
	push	rax
	add	rdi, 24
	mov	edx, sha384_state_size - 24
	call	memset32
	pop	rdi
	mov	rsi, .initial_hash
	mov	edx, 64
	call	memcpy
	epilog
dalign
.initial_hash:
	dq	        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4

end if


if used sha384$final | defined include_everything
	; three arguments: rdi == sha state, rsi == pointer to 48 byte buffer for the final digest, bool in edx as to whether we should heap$free the state
	; void return
falign
sha384$final:
	prolog	sha384$final
	push	rdi rsi
	sub	rsp, 64
	mov	rsi, rsp
	call	sha512$final
	mov	rdi, [rsp+64]	; rsi of 28 byte buffer
	mov	rsi, rsp
	mov	edx, 48
	call	memcpy
	add	rsp, 64
	pop	rsi rdi
	epilog

end if


if used sha384$mgf1 | defined include_everything
	; one-pass MGF1 as defined by rfc2437 (one-pass == we do stack-based state)
	; four arguments: rdi == seed, rsi == seed length, rdx == destination, rcx == dest length
falign
sha384$mgf1:
	prolog	sha384$mgf1
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	sub	rsp, sha384_state_size + 48 + 8
	mov	rdi, rsp
	call	sha384$init
	mov	qword [rsp+sha384_state_size+48], 0
calign
.doit:
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	sha384$update
	mov	eax, [rsp+sha384_state_size+48]
if use_movbe
	add	dword [rsp+sha384_state_size+48], 1
	movbe	[rsp+sha384_state_size+52], eax
else
	bswap	eax
	add	dword [rsp+sha384_state_size+48], 1
	mov	[rsp+sha384_state_size+52], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha384_state_size+52]
	mov	edx, 4
	call	sha384$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha384_state_size]
	xor	edx, edx
	call	sha384$final
	mov	rdi, r14
	lea	rsi, [rsp+sha384_state_size]
	mov	edx, 48
	cmp	rdx, r15
	cmova	rdx, r15
	add	r14, rdx
	sub	r15, rdx
	call	memcpy
	test	r15, r15
	jnz	.doit
	add	rsp, sha384_state_size + 48 + 8
	pop	r15 r14 r13 r12
	epilog

end if



if used sha512$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the sha512$init on it
	; returns initialized state
falign
sha512$new:
	prolog	sha512$new
	mov	rdi, sha512_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha512$init
	pop	rax
	epilog

end if


if used sha512$init | defined include_everything
	; single argument in rdi: our sha state
	; void return
falign
sha512$init:
	prolog	sha512$init
	; if rdi is 16 aligned on entry, then stateptr == rdi+32, bitcountptr == rdi+96, bufferptr == rdi+112
	; if it is not aligned on entry, then stateptr == rdi+24, bitcountptr == rdi+88, bufferptr == rdi+104
	lea	rax, [rdi+32]
	lea	rcx, [rdi+96]
	lea	rdx, [rdi+112]
	lea	r8, [rdi+24]
	lea	r9, [rdi+88]
	lea	r10, [rdi+104]
	test	rdi, 0xf
	cmovnz	rax, r8
	cmovnz	rcx, r9
	cmovnz	rdx, r10
	xor	esi, esi
	mov	[rdi+sha_stateptr_ofs], rax
	mov	[rdi+sha_bitcountptr_ofs], rcx
	mov	[rdi+sha_bufferptr_ofs], rdx
	; so now, each of the 3 pointers is 16 byte aligned within our state
	push	rax
	add	rdi, 24
	mov	edx, sha512_state_size - 24
	call	memset32
	pop	rdi
	mov	rsi, .initial_hash
	mov	edx, 64
	call	memcpy
	epilog
dalign
.initial_hash:
        dq	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179


end if


if used sha512$update | used sha384$update | defined include_everything
	; three arguments: rdi == sha state, rsi == byte buffer, rdx == length of same
	; void return
falign
sha512$update:
sha384$update:
	prolog	sha512$update
	test	rdx, rdx
	jz	.nothingtodo
	mov	r8, [rdi+sha_bitcountptr_ofs]
	mov	rcx, [r8]
	shr	rcx, 3
	and	rcx, 0x7f
	test	rcx, rcx
	jz	.noused
	mov	r9d, 128
	sub	r9d, ecx			; 128 - bytes used in the buffer
	cmp	rdx, r9				; are we adding less than the full block?
	jb	.needmore
	; otherwise, we need to fill our buffer, transform that, and then
	; leave the rest to a normal non-buffer based fill
	push	rdi rsi rdx
	mov	rdi, [rdi+sha_bufferptr_ofs]
	add	rdi, rcx
	mov	rdx, r9
	add	qword [rsp+8], r9
	sub	qword [rsp], r9
	shl	r9, 3
	add	qword [r8], r9
	call	memcpy
	mov	rdi, [rsp+16]
	mov	rsi, [rdi+sha_bufferptr_ofs]
	; we need rdx to be set here to a flat 128 bytes for our buffer
	mov	edx, 128
	call	sha512$transform
	pop	rdx rsi rdi
	mov	r8, [rdi+sha_bitcountptr_ofs]
	jmp	.noused
calign
.needmore:
	; rdx is less than the number of bytes we have left in our buffer
	mov	r10, rdx
	shl	r10, 3
	add	qword [r8], r10
	mov	rdi, [rdi+sha_bufferptr_ofs]
	add	rdi, rcx
	call	memcpy
	epilog
calign
.noused:
	; update our bitcount in its entirety beforehand
	; TODO: check overflow of 2^64-1 and update the SECOND bitcount (none of my goods use 2^64-1+ messages, hahah)
	mov	rcx, rdx
	shl	rcx, 3
	add	qword [r8], rcx
	cmp	rdx, 128
	jb	.partial
	call	sha512$transform
	; it returns us with how many bytes it did _not_ process
	; and rsi/rdx is the goods that we'd need to copy if there are leftovers
	test	rdx, rdx
	jnz	.partial
	epilog
calign
.partial:
	mov	rdi, [rdi+sha_bufferptr_ofs]
	call	memcpy
	epilog
calign
.nothingtodo:
	epilog

end if



if used sha512$transform | defined include_everything
	; note: not meant to be called externall, but for profiling reasons down the track
	; is made with the normal profiler/public symbol entries
	; called from sha512$update and sha512$final

	; TODO: see if a loop w/ .k reference is actually faster than the currently unrolled kofs method

falign
sha512$transform:
	prolog	sha512$transform

	mov	eax, 576
	mov	ecx, 568
	sub	rsp, 576
	mov	r8, rsp
	add	r8, 8
	test	rsp, 0xf
	cmovnz	rsp, r8
	cmovnz	eax, ecx
	mov	qword [rsp+0x1d0], rax		; amount to add to the stack when we are done
	mov	[rsp+0x1d8], rbx
	mov	[rsp+0x1e0], rdi
	mov	[rsp+0x1e8], rsi
	mov	[rsp+0x1f0], rdx
	; save four more of our callee-saves
	mov	[rsp+0x1f8], r12
	mov	[rsp+0x200], r13
	mov	[rsp+0x208], r14
	mov	[rsp+0x210], r15

	mov	rdi, [rdi+sha_stateptr_ofs]
	mov	[rsp+0x218], rdi		; STATE_SAVE

	; state -> working vars
	mov	r8, [rdi]
	mov	r9, [rdi+8]
	mov	r10, [rdi+16]
	mov	r11, [rdi+24]
	mov	r12, [rdi+32]
	mov	r13, [rdi+40]
	mov	r14, [rdi+48]
	mov	r15, [rdi+56]

calign
.nextblock:

	; set W to our 16 qwords of input data
if use_movbe
	mov	rax, [rsi]
	mov	rbx, [rsi+8]
	mov	rcx, [rsi+16]
	movbe	[rsp+64], rax
	movbe	[rsp+72], rbx
	movbe	[rsp+80], rcx
	mov	rdx, [rsi+24]
	mov	rax, [rsi+32]
	mov	rbx, [rsi+40]
	movbe	[rsp+88], rdx
	movbe	[rsp+96], rax
	movbe	[rsp+104], rbx
	mov	rcx, [rsi+48]
	mov	rdx, [rsi+56]
	mov	rax, [rsi+64]
	movbe	[rsp+112], rcx
	movbe	[rsp+120], rdx
	movbe	[rsp+128], rax
	mov	rbx, [rsi+72]
	mov	rcx, [rsi+80]
	mov	rdx, [rsi+88]
	movbe	[rsp+136], rbx
	movbe	[rsp+144], rcx
	movbe	[rsp+152], rdx
	mov	rax, [rsi+96]
	mov	rbx, [rsi+104]
	mov	rcx, [rsi+112]
	movbe	[rsp+160], rax
	movbe	[rsp+168], rbx
	movbe	[rsp+176], rcx
	mov	rdx, [rsi+120]
	movbe	[rsp+184], rdx
else

	mov	rax, [rsi]
	mov	rbx, [rsi+8]
	mov	rcx, [rsi+16]
	bswap	rax
	bswap	rbx
	bswap	rcx
	mov	[rsp+64], rax
	mov	[rsp+72], rbx
	mov	[rsp+80], rcx

	mov	rdx, [rsi+24]
	mov	rax, [rsi+32]
	mov	rbx, [rsi+40]
	bswap	rdx
	bswap	rax
	bswap	rbx
	mov	[rsp+88], rdx
	mov	[rsp+96], rax
	mov	[rsp+104], rbx
	
	mov	rcx, [rsi+48]
	mov	rdx, [rsi+56]
	mov	rax, [rsi+64]
	bswap	rcx
	bswap	rdx
	bswap	rax
	mov	[rsp+112], rcx
	mov	[rsp+120], rdx
	mov	[rsp+128], rax

	mov	rbx, [rsi+72]
	mov	rcx, [rsi+80]
	mov	rdx, [rsi+88]
	bswap	rbx
	bswap	rcx
	bswap	rdx
	mov	[rsp+136], rbx
	mov	[rsp+144], rcx
	mov	[rsp+152], rdx

	mov	rax, [rsi+96]
	mov	rbx, [rsi+104]
	mov	rcx, [rsi+112]
	mov	rdx, [rsi+120]
	bswap	rax
	bswap	rbx
	bswap	rcx
	bswap	rdx
	mov	[rsp+160], rax
	mov	[rsp+168], rbx
	mov	[rsp+176], rcx
	mov	[rsp+184], rdx

end if

	mov	rax, r9				; B
	mov	rdi, r12			; E
	mov	rcx, r8				; A
	xor	rax, r10			; B^C

macro sha512_rb1 i*, r1*, r2*, kofs* {
	local	H,Wt,Wt2,Wt7,Wt15
	H = ((1024 + 7 - i) and 7)
	Wt= (i * 8) + 64
	Wt2 = (((i - 2) and 15) * 8) + 64
	Wt7 = (((i - 7) and 15) * 8) + 64
	Wt15 = (((i - 15) and 15) * 8) + 64

	mov	rsi, [rsp+Wt2]		; Wt2 into rsi
	mov	r2, [rsp+Wt15]		; Wt15 into r2
	mov	rbx, rsi		; rsi into rbx
	shr	rsi, 6			; shr rsi, 6 (Wt2 >> 6)
	ror	rbx, 19			; ror rbx, 19 (Wt2 >>> 19)
	xor	rsi, rbx		; xor rsi, rbx (so in rsi we have: (Wt2 >> 6) xor (Wt2 >>> 19))
	ror	rbx, 42			; ror rbx, 42 (Wt2 >>> 61)
	xor	rbx, rsi		; s1 complete

	mov	rsi, r2
	add	rbx, [rsp+Wt7]

	shr	rsi, 7			; Wt15 >> 7
	ror	r2, 1			; Wt15 >>> 1
	add	rbx, [rsp+Wt]

	xor	rsi, r2			; (Wt15 >> 7) xor (Wt15 >>> 1)
	add	r1, [.k + kofs + i*8]
	ror	r2, 7			; Wt15 >>> 8
if H = 0
	add	r1, r8
else if H = 1
	add	r1, r9
else if H = 2
	add	r1, r10
else if H = 3
	add	r1, r11
else if H = 4
	add	r1, r12
else if H = 5
	add	r1, r13
else if H = 6
	add	r1, r14
else if H = 7
	add	r1, r15
end if
	xor	rsi, r2			; s0 complete
	add	rsi, rbx
	mov	[rsp+Wt], rsi
	add	r1, rsi
}

macro sha512_round i*, r*, r1*, r2*, r3*, r4*, kofs* {
	local	H,G,F,E,D,C,B,A,Wt
	H = ((1024 + 7 - i) and 7)
	G = ((1024 + 7 - (i + 1)) and 7)
	F = ((1024 + 7 - (i + 2)) and 7)
	E = ((1024 + 7 - (i + 3)) and 7)
	D = ((1024 + 7 - (i + 4)) and 7)
	C = ((1024 + 7 - (i + 5)) and 7)
	B = ((1024 + 7 - (i + 6)) and 7)
	A = ((1024 + 7 - (i + 7)) and 7)
	Wt = (i * 8) + 64
	
	mov	rsi, r3
if F = 0
	mov	r4, r8
else if F = 1
	mov	r4, r9
else if F = 2
	mov	r4, r10
else if F = 3
	mov	r4, r11
else if F = 4
	mov	r4, r12
else if F = 5
	mov	r4, r13
else if F = 6
	mov	r4, r14
else if F = 7
	mov	r4, r15
end if
if G = 0
	xor	r4, r8
else if G = 1
	xor	r4, r9
else if G = 2
	xor	r4, r10
else if G = 3
	xor	r4, r11
else if G = 4
	xor	r4, r12
else if G = 5
	xor	r4, r13
else if G = 6
	xor	r4, r14
else if G = 7
	xor	r4, r15
end if
	ror	rsi, 41			; S1, e >>> 41
	and	r4, r3
if G = 0
	xor	r4, r8
else if G = 1
	xor	r4, r9
else if G = 2
	xor	r4, r10
else if G = 3
	xor	r4, r11
else if G = 4
	xor	r4, r12
else if G = 5
	xor	r4, r13
else if G = 6
	xor	r4, r14
else if G = 7
	xor	r4, r15
end if
	ror	r3, 14			; S1, e >>> 14
if r = 0
	add	r4, [.k + kofs + i*8]
end if
	xor	rsi, r3
if r = 0
	add	r4, [rsp+Wt]
end if
	ror	r3, 4			; S1, e >>> 18
if r = 0
if H = 0
	add	r4, r8
else if H = 1
	add	r4, r9
else if H = 2
	add	r4, r10
else if H = 3
	add	r4, r11
else if H = 4
	add	r4, r12
else if H = 5
	add	r4, r13
else if H = 6
	add	r4, r14
else if H = 7
	add	r4, r15
end if
end if
	xor	rsi, r3
	add	r4, rsi
if r = 1
	sha512_rb1 i, r4, r3, kofs
end if
	mov	rbx, r2
	mov	rsi, r2
if B = 0
	xor	r2, r8
else if B = 1
	xor	r2, r9
else if B = 2
	xor	r2, r10
else if B = 3
	xor	r2, r11
else if B = 4
	xor	r2, r12
else if B = 5
	xor	r2, r13
else if B = 6
	xor	r2, r14
else if B = 7
	xor	r2, r15
end if
	and	r1, r2
	ror	rbx, 28			; S0, a >>> 28
if B = 0
	xor	r1, r8
else if B = 1
	xor	r1, r9
else if B = 2
	xor	r1, r10
else if B = 3
	xor	r1, r11
else if B = 4
	xor	r1, r12
else if B = 5
	xor	r1, r13
else if B = 6
	xor	r1, r14
else if B = 7
	xor	r1, r15
end if
	add	r1, r4
	ror	rsi, 39			; S0, a >>> 39
if D = 0
	add	r4, r8
else if D = 1
	add	r4, r9
else if D = 2
	add	r4, r10
else if D = 3
	add	r4, r11
else if D = 4
	add	r4, r12
else if D = 5
	add	r4, r13
else if D = 6
	add	r4, r14
else if D = 7
	add	r4, r15
end if
	xor	rsi, rbx
if D = 0
	mov	r8, r4
else if D = 1
	mov	r9, r4
else if D = 2
	mov	r10, r4
else if D = 3
	mov	r11, r4
else if D = 4
	mov	r12, r4
else if D = 5
	mov	r13, r4
else if D = 6
	mov	r14, r4
else if D = 7
	mov	r15, r4
end if
	; rbx is already ror'd 28 (which in the original is 2), we need 34
	ror	rbx, 6			; S0, a >>> 34
	xor	rsi, rbx
	add	r1, rsi
if H = 0
	mov	r8, r1
else if H = 1
	mov	r9, r1
else if H = 2
	mov	r10, r1
else if H = 3
	mov	r11, r1
else if H = 4
	mov	r12, r1
else if H = 5
	mov	r13, r1
else if H = 6
	mov	r14, r1
else if H = 7
	mov	r15, r1
end if
}
	sha512_round 0, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 1, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 2, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 3, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 4, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 5, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 6, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 7, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 8, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 9, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 10, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 11, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 12, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 13, 0, rcx, rax, rdx, rdi, 0x0
	sha512_round 14, 0, rax, rcx, rdi, rdx, 0x0
	sha512_round 15, 0, rcx, rax, rdx, rdi, 0x0

	sha512_round 0, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 1, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 2, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 3, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 4, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 5, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 6, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 7, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 8, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 9, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 10, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 11, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 12, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 13, 1, rcx, rax, rdx, rdi, 0x80
	sha512_round 14, 1, rax, rcx, rdi, rdx, 0x80
	sha512_round 15, 1, rcx, rax, rdx, rdi, 0x80

	sha512_round 0, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 1, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 2, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 3, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 4, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 5, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 6, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 7, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 8, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 9, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 10, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 11, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 12, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 13, 1, rcx, rax, rdx, rdi, 0x100
	sha512_round 14, 1, rax, rcx, rdi, rdx, 0x100
	sha512_round 15, 1, rcx, rax, rdx, rdi, 0x100

	sha512_round 0, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 1, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 2, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 3, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 4, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 5, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 6, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 7, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 8, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 9, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 10, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 11, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 12, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 13, 1, rcx, rax, rdx, rdi, 0x180
	sha512_round 14, 1, rax, rcx, rdi, rdx, 0x180
	sha512_round 15, 1, rcx, rax, rdx, rdi, 0x180

	sha512_round 0, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 1, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 2, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 3, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 4, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 5, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 6, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 7, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 8, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 9, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 10, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 11, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 12, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 13, 1, rcx, rax, rdx, rdi, 0x200
	sha512_round 14, 1, rax, rcx, rdi, rdx, 0x200
	sha512_round 15, 1, rcx, rax, rdx, rdi, 0x200

	mov	rcx, [rsp+0x218]		; STATE_SAVE
	mov	rsi, [rsp+0x1e8]
	mov	rdx, [rsp+0x1f0]
	add	rsi, 128
	sub	rdx, 128
	cmp	rdx, 128
	jae	.moretogo
	; else, remaining bytes < a full block, so bailout

	add	[rcx], r8
	add	[rcx+8], r9
	add	[rcx+16], r10
	add	[rcx+24], r11
	add	[rcx+32], r12
	add	[rcx+40], r13
	add	[rcx+48], r14
	add	[rcx+56], r15

	mov	rax, [rsp+0x1d0]		; amount to add to the stack
	mov	rbx, [rsp+0x1d8]
	mov	rdi, [rsp+0x1e0]
	mov	r12, [rsp+0x1f8]
	mov	r13, [rsp+0x200]
	mov	r14, [rsp+0x208]
	mov	r15, [rsp+0x210]

	add	rsp, rax
	epilog
calign
.moretogo:
	add	r8, [rcx]
	add	r9, [rcx+8]
	add	r10, [rcx+16]
	add	r11, [rcx+24]
	add	r12, [rcx+32]
	add	r13, [rcx+40]
	add	r14, [rcx+48]
	add	r15, [rcx+56]

	; we need to put them back too
	mov	[rcx], r8
	mov	[rcx+8], r9
	mov	[rcx+16], r10
	mov	[rcx+24], r11
	mov	[rcx+32], r12
	mov	[rcx+40], r13
	mov	[rcx+48], r14
	mov	[rcx+56], r15

	; store our updated rsi/rdx for the next fallthrough
	mov	[rsp+0x1e8], rsi
	mov	[rsp+0x1f0], rdx
	jmp	.nextblock
align 16
.k:
	dq	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019
	dq	0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	dq	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
	dq	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	dq	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725
	dq	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	dq	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001
	dq	0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
	dq	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
	dq	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
	dq	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207
	dq	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
	dq	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
	dq	0x5fcb6fab3ad6faec, 0x6c44198c4a475817 
	

end if



if used sha512$final | defined include_everything
	; three arguments: rdi == sha state, rsi == pointer to 64 byte buffer for the final digest, bool in edx as to whether we should heap$free the state
	; void return
falign
sha512$final:
	prolog	sha512$final
	push	rdx rsi rdi

	mov	r8, [rdi+sha_bitcountptr_ofs]
if use_movbe
	mov	rcx, [r8]
	mov	rax, [r8+8]
	movbe	[r8], rcx
	movbe	[r8+8], rax
	shr	ecx, 3
	and	ecx, 0x7f
else
	mov	rcx, [r8]
	mov	r9, rcx
	bswap	r9
	shr	rcx, 3
	mov	[r8], r9		; bitcount reversed 64 bits

	mov	rax, [r8+8]		; bitcount reversed high 64 bits
	bswap	rax
	mov	[r8+8], rax

	and	rcx, 0x7f	
end if
	test	ecx, ecx		; usedspace?
	jz	.noused
	; else, we have to begin our padding with 1 bit: 0x80
	; short block length == 112
	mov	r10, [rdi+sha_bufferptr_ofs]
	mov	byte [r10+rcx], 0x80
	add	rcx, 1
	cmp	rcx, 112
	jle	.zeroremaining
	cmp	rcx, 128
	jae	.dosecondtolast
	; else, zero the remaining 128 - usedspace
	mov	rdi, r10
	add	rdi, rcx
	xor	esi, esi
	mov	edx, 128
	sub	edx, ecx
	call	memset
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
calign
.dosecondtolast:
	mov	rsi, [rdi+sha_bufferptr_ofs]
	mov	edx, 128
	call	sha512$transform
	; setup for final:
	mov	rdi, [rsp]
	xor	esi, esi
	mov	edx, 112
	mov	rdi, [rdi+sha_bufferptr_ofs]
	call	memset32
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	jmp	.dofinal
calign
.zeroremaining:
	mov	rdi, r10
	add	rdi, rcx
	xor	esi, esi
	mov	edx, 112
	sub	edx, ecx
	call	memset
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	jmp	.dofinal
calign
.noused:
	mov	rdi, [rdi+sha_bufferptr_ofs]
	xor	esi, esi
	mov	edx, 112
	call	memset32
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	r9, [rdi+sha_bufferptr_ofs]
	mov	dword [r9], 0x80
calign
.dofinal:
	mov	r8, [rdi+sha_bitcountptr_ofs]
	mov	rcx, [r8]
	mov	rax, [r8+8]
	mov	r9, [rdi+sha_bufferptr_ofs]
	mov	qword [r9+112], rax		; high first
	mov	qword [r9+120], rcx		; low after
	mov	edx, 128
	mov	rsi, r9
	call	sha512$transform
	; rdi and rsi both stay in tact across that call
	mov	rsi, [rsp+8]
	mov	rdx, [rdi+sha_stateptr_ofs]

if use_movbe
	mov	rax, [rdx]
	mov	r8, [rdx+8]
	mov	r9, [rdx+16]
	movbe	[rsi], rax
	movbe	[rsi+8], r8
	movbe	[rsi+16], r9
	mov	r10, [rdx+24]
	mov	rax, [rdx+32]
	mov	r8, [rdx+40]
	movbe	[rsi+24], r10
	movbe	[rsi+32], rax
	movbe	[rsi+40], r8
	mov	r9, [rdx+48]
	mov	r10, [rdx+56]
	movbe	[rsi+48], r9
	movbe	[rsi+56], r10
else
	mov	rax, [rdx]
	mov	r8, [rdx+8]
	mov	r9, [rdx+16]
	mov	r10, [rdx+24]
	bswap	rax
	bswap	r8
	bswap	r9
	bswap	r10
	mov	[rsi], rax
	mov	[rsi+8], r8
	mov	[rsi+16], r9
	mov	[rsi+24], r10

	mov	rax, [rdx+32]
	mov	r8, [rdx+40]
	mov	r9, [rdx+48]
	mov	r10, [rdx+56]
	bswap	rax
	bswap	r8
	bswap	r9
	bswap	r10
	mov	[rsi+32], rax
	mov	[rsi+40], r8
	mov	[rsi+48], r9
	mov	[rsi+56], r10
end if
	; last but not least, reinitialize our state for further use
	call	sha512$init
	cmp	dword [rsp+16], 0
	jne	.freeandreturn
	add	rsp, 24
	epilog
calign
.freeandreturn:
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 24
	epilog

end if


if used sha512$mgf1 | defined include_everything
	; one-pass MGF1 as defined by rfc2437 (one-pass == we do stack-based state)
	; four arguments: rdi == seed, rsi == seed length, rdx == destination, rcx == dest length
falign
sha512$mgf1:
	prolog	sha512$mgf1
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	sub	rsp, sha512_state_size + 64 + 8
	mov	rdi, rsp
	call	sha512$init
	mov	qword [rsp+sha512_state_size+64], 0
calign
.doit:
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	sha512$update
	mov	eax, [rsp+sha512_state_size+64]
if use_movbe
	add	dword [rsp+sha512_state_size+64], 1
	movbe	[rsp+sha512_state_size+68], eax
else
	bswap	eax
	add	dword [rsp+sha512_state_size+64], 1
	mov	[rsp+sha512_state_size+68], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha512_state_size+68]
	mov	edx, 4
	call	sha512$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha512_state_size]
	xor	edx, edx
	call	sha512$final
	mov	rdi, r14
	lea	rsi, [rsp+sha512_state_size]
	mov	edx, 64
	cmp	rdx, r15
	cmova	rdx, r15
	add	r14, rdx
	sub	r15, rdx
	call	memcpy
	test	r15, r15
	jnz	.doit
	add	rsp, sha512_state_size + 64 + 8
	pop	r15 r14 r13 r12
	epilog

end if

