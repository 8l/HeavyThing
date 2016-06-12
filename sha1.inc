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
	; sha1.inc: sha160 goods required by TLS 1.0/1.1
	;
	; NOTE: not using SSE3+/AVX does carry its penalties... SSE2 is my own requirement though...
	; so we have to suck it a bit... it certainly isn't painfully slower than other implementations,
	; 
	; and where SSE3 or better is _not_ used, this routine is faster than anything else. works for me.
	; were it not for the older TLS implementations that are rampant, this file wouldn't exist here.
	;
sha160_state_size = 144

if used sha160$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the sha160$init on it
	; returns initialized state
falign
sha160$new:
	prolog	sha160$new
	mov	edi, sha160_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha160$init
	pop	rax
	epilog

end if

if used sha160$init | defined include_everything
	; single argument in rdi: our sha state
	; void return
falign
sha160$init:
	prolog	sha160$init
	; if rdi is 16 aligned on entry, then stateptr == rdi+32, bitcountptr == rdi+64, bufferptr == rdi+80
	; if it is not aligned on entry, then stateptr == rdi+24, bitcountptr == rdi+56, bufferptr == rdi+72
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
	mov	edx, sha160_state_size - 24
	call	memset32
	pop	rdi
	mov	rsi, .initial_hash
	mov	edx, 20
	call	memcpy
	epilog
dalign
.initial_hash:
	dd	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0

end if

if used sha160$update | defined include_everything
	; three arguments: rdi == sha state, rsi == byte buffer, rdx == length of same
	; void return
falign
sha160$update:
	prolog	sha160$update
	test	rdx, rdx
	jz	.nothingtodo
	mov	r8, [rdi+sha_bitcountptr_ofs]
	mov	rcx, [r8]
	shr	rcx, 3
	and	rcx, 0x3f
	test	rcx, rcx
	jz	.noused
	mov	r9d, 64
	sub	r9d, ecx			; 64 - bytes used in the buffer
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
	; we need rdx to be set here to a flat 64 bytes for our buffer
	mov	edx, 64
	call	sha160$transform
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
	mov	rcx, rdx
	shl	rcx, 3
	add	qword [r8], rcx
	cmp	rdx, 64
	jb	.partial
	call	sha160$transform
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


if used sha160$transform | defined include_everything
	; note: not meant to be called externally, but for profiling reasons down the track
	; is made with the normal profiler/public symbol entries
	; called from sha160$update and sha160$final
	; NONSTANDARD returns/register preservation
falign
sha160$transform:
	prolog	sha160$transform
	; rdi == our state, rsi == (dd) data
	; we preserve rdi, rsi and rdx (updating rsi/rdx as we go)
	mov	eax, 288
	mov	ecx, 280
	sub	rsp, 288
	mov	r8, rsp
	add	r8, 8
	test	rsp, 0xf
	cmovnz	rsp, r8
	cmovnz	eax, ecx
	mov	qword [rsp+0x80], rax		; amount to add to the stack when we are done
	; so now, we have an aligned 16 stack with the ability to correctly replace it when we are done
	mov	[rsp+0x88], rbx
	mov	[rsp+0x90], rdi
	mov	[rsp+0x98], rsi
	mov	[rsp+0xa0], rdx
	mov	rdi, [rdi+sha_stateptr_ofs]
	mov	[rsp+0xa8], r12
	mov	[rsp+0x68], rdi			; STATE_SAVE

	; r8d..r12d for our state instead of the aligned first 20 bytes of our stack
	mov	r8d, [rdi]			; a
	mov	r9d, [rdi+4]			; b
	mov	r10d, [rdi+8]			; c
	mov	r11d, [rdi+12]			; d
	mov	r12d, [rdi+16]			; e
calign
.nextblock:	; here is where we jump to from the bottom if there was more to do
	; note: we reverse W entirely so we can use 64 bit bswaps here
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

macro sha160_round0 r1*, r2*, r3*, r4*, r5*, i* {
	local Wt
	Wt=(((1024 + 15 - i) and 15) * 4) + 32
	mov	eax, r3
	mov	ebx, r2
	mov	ecx, r4
	xor	eax, r4			; r3 ^ r4
	add	r5, 0x5a827999		; += fixed
	and	ebx, eax		; r2 & (r3 ^ r4)
	add	r5, dword [rsp+Wt]	; += W[i]
	mov	eax, r1
	xor	ecx, ebx		; r4 ^ (r2 & (r3 ^ r4))
	rol	eax, 5
	add	r5, ecx
	add	r5, eax			; += r1 rol 5
	rol	r2, 30
}

macro sha160_round1 r1*, r2*, r3*, r4*, r5*, i* {
	local Wt,Wt13,Wt8,Wt2
	Wt=(((1024 + 15 - i) and 15) * 4) + 32
	Wt13=(((1024 + 15 - ((i + 13) and 15)) and 15) * 4) + 32
	Wt8=(((1024 + 15 - ((i + 8) and 15)) and 15) * 4) + 32
	Wt2=(((1024 + 15 - ((i + 2) and 15)) and 15) * 4) + 32
	mov	eax, r3
	mov	edx, dword [rsp+Wt13]
	mov	ebx, r2
	xor	edx, dword [rsp+Wt8]
	mov	ecx, r4
	xor	edx, dword [rsp+Wt2]
	xor	eax, r4			; r3 ^ r4
	xor	edx, dword [rsp+Wt]
	add	r5, 0x5a827999		; += fixed
	rol	edx, 1
	and	ebx, eax		; r2 & (r3 ^ r4)
	add	r5, edx			; += fixedup W[i&15]
	mov	dword [rsp+Wt], edx
	mov	eax, r1
	xor	ecx, ebx		; r4 ^ (r2 & (r3 ^ r4))
	rol	eax, 5
	add	r5, ecx
	add	r5, eax			; += r1 rol 5
	rol	r2, 30
}

macro sha160_round2 r1*, r2*, r3*, r4*, r5*, i* {
	local Wt,Wt13,Wt8,Wt2
	Wt=(((1024 + 15 - i) and 15) * 4) + 32
	Wt13=(((1024 + 15 - ((i + 13) and 15)) and 15) * 4) + 32
	Wt8=(((1024 + 15 - ((i + 8) and 15)) and 15) * 4) + 32
	Wt2=(((1024 + 15 - ((i + 2) and 15)) and 15) * 4) + 32
	mov	eax, r2
	mov	edx, dword [rsp+Wt13]
	xor	eax, r3			; r2 ^ r3
	xor	edx, dword [rsp+Wt8]
	xor	eax, r4			; r2 ^ r3 ^ r4
	xor	edx, dword [rsp+Wt2]
	add	r5, eax
	xor	edx, dword [rsp+Wt]
	add	r5, 0x6ed9eba1		; += fixed
	rol	edx, 1
	mov	eax, r1
	add	r5, edx			; += fixed up W[i&15]
	rol	eax, 5
	mov	dword [rsp+Wt], edx
	add	r5, eax			; += r1 rol 5
	rol	r2, 30
}

macro sha160_round3 r1*, r2*, r3*, r4*, r5*, i* {
	local Wt,Wt13,Wt8,Wt2
	Wt=(((1024 + 15 - i) and 15) * 4) + 32
	Wt13=(((1024 + 15 - ((i + 13) and 15)) and 15) * 4) + 32
	Wt8=(((1024 + 15 - ((i + 8) and 15)) and 15) * 4) + 32
	Wt2=(((1024 + 15 - ((i + 2) and 15)) and 15) * 4) + 32
	mov	eax, r2
	mov	edx, dword [rsp+Wt13]
	mov	ebx, r4
	xor	edx, dword [rsp+Wt8]
	mov	ecx, r2
	xor	edx, dword [rsp+Wt2]
	or	eax, r3				; r2 | r3
	xor	edx, dword [rsp+Wt]
	and	ecx, r3				; r2 & r3
	rol	edx, 1
	and	ebx, eax			; r4 & (r2 | r3)
	add	r5, edx				; += fixed up W[i&15]
	or	ecx, ebx			; (r2 & r3) | (r4 & (r2 | r3))
	mov	dword [rsp+Wt], edx
	add	r5, 0x8f1bbcdc			; += fixed
	mov	eax, r1
	add	r5, ecx
	rol	eax, 5
	rol	r2, 30
	add	r5, eax				; += r1 rol 5
}

macro sha160_round4 r1*, r2*, r3*, r4*, r5*, i* {
	local Wt,Wt13,Wt8,Wt2
	Wt=(((1024 + 15 - i) and 15) * 4) + 32
	Wt13=(((1024 + 15 - ((i + 13) and 15)) and 15) * 4) + 32
	Wt8=(((1024 + 15 - ((i + 8) and 15)) and 15) * 4) + 32
	Wt2=(((1024 + 15 - ((i + 2) and 15)) and 15) * 4) + 32
	mov	eax, r2
	mov	edx, dword [rsp+Wt13]
	xor	eax, r3				; r2 ^ r3
	xor	edx, dword [rsp+Wt8]
	xor	eax, r4				; r2 ^ r3 ^ r4
	xor	edx, dword [rsp+Wt2]
	add	r5, eax
	xor	edx, dword [rsp+Wt]
	add	r5, 0xca62c1d6			; += fixed
	rol	edx, 1
	mov	eax, r1
	add	r5, edx				; += fixed up W[i&15]
	rol	eax, 5
	mov	dword [rsp+Wt], edx
	add	r5, eax				; += r1 rol 5
	rol	r2, 30
}

	sha160_round0 r8d,r9d,r10d,r11d,r12d, 0
	sha160_round0 r12d,r8d,r9d,r10d,r11d, 1
	sha160_round0 r11d,r12d,r8d,r9d,r10d, 2
	sha160_round0 r10d,r11d,r12d,r8d,r9d, 3
	sha160_round0 r9d,r10d,r11d,r12d,r8d, 4
	sha160_round0 r8d,r9d,r10d,r11d,r12d, 5
	sha160_round0 r12d,r8d,r9d,r10d,r11d, 6
	sha160_round0 r11d,r12d,r8d,r9d,r10d, 7
	sha160_round0 r10d,r11d,r12d,r8d,r9d, 8
	sha160_round0 r9d,r10d,r11d,r12d,r8d, 9
	sha160_round0 r8d,r9d,r10d,r11d,r12d,10
	sha160_round0 r12d,r8d,r9d,r10d,r11d,11
	sha160_round0 r11d,r12d,r8d,r9d,r10d,12
	sha160_round0 r10d,r11d,r12d,r8d,r9d,13
	sha160_round0 r9d,r10d,r11d,r12d,r8d,14
	sha160_round0 r8d,r9d,r10d,r11d,r12d,15
	sha160_round1 r12d,r8d,r9d,r10d,r11d,16
	sha160_round1 r11d,r12d,r8d,r9d,r10d,17
	sha160_round1 r10d,r11d,r12d,r8d,r9d,18
	sha160_round1 r9d,r10d,r11d,r12d,r8d,19
	sha160_round2 r8d,r9d,r10d,r11d,r12d,20
	sha160_round2 r12d,r8d,r9d,r10d,r11d,21
	sha160_round2 r11d,r12d,r8d,r9d,r10d,22
	sha160_round2 r10d,r11d,r12d,r8d,r9d,23
	sha160_round2 r9d,r10d,r11d,r12d,r8d,24
	sha160_round2 r8d,r9d,r10d,r11d,r12d,25
	sha160_round2 r12d,r8d,r9d,r10d,r11d,26
	sha160_round2 r11d,r12d,r8d,r9d,r10d,27
	sha160_round2 r10d,r11d,r12d,r8d,r9d,28
	sha160_round2 r9d,r10d,r11d,r12d,r8d,29
	sha160_round2 r8d,r9d,r10d,r11d,r12d,30
	sha160_round2 r12d,r8d,r9d,r10d,r11d,31
	sha160_round2 r11d,r12d,r8d,r9d,r10d,32
	sha160_round2 r10d,r11d,r12d,r8d,r9d,33
	sha160_round2 r9d,r10d,r11d,r12d,r8d,34
	sha160_round2 r8d,r9d,r10d,r11d,r12d,35
	sha160_round2 r12d,r8d,r9d,r10d,r11d,36
	sha160_round2 r11d,r12d,r8d,r9d,r10d,37
	sha160_round2 r10d,r11d,r12d,r8d,r9d,38
	sha160_round2 r9d,r10d,r11d,r12d,r8d,39
	sha160_round3 r8d,r9d,r10d,r11d,r12d,40
	sha160_round3 r12d,r8d,r9d,r10d,r11d,41
	sha160_round3 r11d,r12d,r8d,r9d,r10d,42
	sha160_round3 r10d,r11d,r12d,r8d,r9d,43

	sha160_round3 r9d,r10d,r11d,r12d,r8d,44
	sha160_round3 r8d,r9d,r10d,r11d,r12d,45
	sha160_round3 r12d,r8d,r9d,r10d,r11d,46
	sha160_round3 r11d,r12d,r8d,r9d,r10d,47
	sha160_round3 r10d,r11d,r12d,r8d,r9d,48
	sha160_round3 r9d,r10d,r11d,r12d,r8d,49
	sha160_round3 r8d,r9d,r10d,r11d,r12d,50
	sha160_round3 r12d,r8d,r9d,r10d,r11d,51
	sha160_round3 r11d,r12d,r8d,r9d,r10d,52
	sha160_round3 r10d,r11d,r12d,r8d,r9d,53
	sha160_round3 r9d,r10d,r11d,r12d,r8d,54
	sha160_round3 r8d,r9d,r10d,r11d,r12d,55
	sha160_round3 r12d,r8d,r9d,r10d,r11d,56
	sha160_round3 r11d,r12d,r8d,r9d,r10d,57
	sha160_round3 r10d,r11d,r12d,r8d,r9d,58
	sha160_round3 r9d,r10d,r11d,r12d,r8d,59
	sha160_round4 r8d,r9d,r10d,r11d,r12d,60
	sha160_round4 r12d,r8d,r9d,r10d,r11d,61
	sha160_round4 r11d,r12d,r8d,r9d,r10d,62
	sha160_round4 r10d,r11d,r12d,r8d,r9d,63
	sha160_round4 r9d,r10d,r11d,r12d,r8d,64
	sha160_round4 r8d,r9d,r10d,r11d,r12d,65
	sha160_round4 r12d,r8d,r9d,r10d,r11d,66
	sha160_round4 r11d,r12d,r8d,r9d,r10d,67
	sha160_round4 r10d,r11d,r12d,r8d,r9d,68
	sha160_round4 r9d,r10d,r11d,r12d,r8d,69
	sha160_round4 r8d,r9d,r10d,r11d,r12d,70
	sha160_round4 r12d,r8d,r9d,r10d,r11d,71
	sha160_round4 r11d,r12d,r8d,r9d,r10d,72
	sha160_round4 r10d,r11d,r12d,r8d,r9d,73
	sha160_round4 r9d,r10d,r11d,r12d,r8d,74
	sha160_round4 r8d,r9d,r10d,r11d,r12d,75
	sha160_round4 r12d,r8d,r9d,r10d,r11d,76
	sha160_round4 r11d,r12d,r8d,r9d,r10d,77
	sha160_round4 r10d,r11d,r12d,r8d,r9d,78
	sha160_round4 r9d,r10d,r11d,r12d,r8d,79


	mov	rcx, [rsp+0x68]			; STATE_SAVE
	mov	rsi, [rsp+0x98]
	mov	rdx, [rsp+0xa0]
	add	rsi, 64
	sub	rdx, 64
	cmp	rdx, 64
	jae	.moretogo
	; else, remaining bytes is < a full block, so bailout
	add	dword [rcx], r8d
	add	dword [rcx+4], r9d
	add	dword [rcx+8], r10d
	add	dword [rcx+12], r11d
	add	dword [rcx+16], r12d
	; restore our callee-saves and stack
	mov	rax, [rsp+0x80]			; amount to add to the stack
	mov	rbx, [rsp+0x88]
	mov	rdi, [rsp+0x90]
	mov	r12, [rsp+0xa8]
	add	rsp, rax
	epilog
calign
.moretogo:
	; at the end of each block, we still need to add the original state
	add	r8d, dword [rcx]
	add	r9d, dword [rcx+4]
	add	r10d, dword [rcx+8]
	add	r11d, dword [rcx+12]
	add	r12d, dword [rcx+16]

	; put them back too:
	mov	dword [rcx], r8d
	mov	dword [rcx+4], r9d
	mov	dword [rcx+8], r10d
	mov	dword [rcx+12], r11d
	mov	dword [rcx+16], r12d

	; and we need to store our updated rsi/rdx for the next fallthrough
	mov	[rsp+0x98], rsi
	mov	[rsp+0xa0], rdx
	jmp	.nextblock

end if

if used sha160$final | defined include_everything
	; three arguments: rdi == sha state, rsi == pointer to 20 byte buffer for the final digest, bool in edx as to whether we should heap$free the state
	; void return, reinitializes our state for further use if !edx
falign
sha160$final:
	prolog	sha160$final
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
	call	sha160$transform
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
	call	sha160$transform
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
	mov	r11d, dword [rdx+16]
	movbe	dword [rsi+12], r10d
	movbe	dword [rsi+16], r11d
else
	mov	eax, dword [rdx]
	mov	r8d, dword [rdx+4]
	mov	r9d, dword [rdx+8]
	mov	r10d, dword [rdx+12]
	mov	r11d, dword [rdx+16]
	bswap	eax
	bswap	r8d
	bswap	r9d
	bswap	r10d
	bswap	r11d
	mov	dword [rsi], eax
	mov	dword [rsi+4], r8d
	mov	dword [rsi+8], r9d
	mov	dword [rsi+12], r10d
	mov	dword [rsi+16], r11d
end if
	; last but not least, zero our entire contents
	; rdi is still intact
	cmp	dword [rsp+16], 0
	jne	.freeandreturn
	call	sha160$init
	add	rsp, 24
	epilog
calign
.freeandreturn:
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 24
	epilog

end if


if used sha160$mgf1 | defined include_everything
	; one-pass MGF1 as defined by rfc2437 (one-pass == we do stack-based state)
	; four arguments: rdi == seed, rsi == seed length, rdx == destination, rcx == dest length
falign
sha160$mgf1:
	prolog	sha160$mgf1
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	sub	rsp, sha160_state_size + 20 + 8
	mov	rdi, rsp
	call	sha160$init
	mov	qword [rsp+sha160_state_size+20], 0
calign
.doit:
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	sha160$update
	mov	eax, [rsp+sha160_state_size+20]
if use_movbe
	add	dword [rsp+sha160_state_size+20], 1
	movbe	[rsp+sha160_state_size+24], eax
else
	bswap	eax
	add	dword [rsp+sha160_state_size+20], 1
	mov	[rsp+sha160_state_size+24], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size+24]
	mov	edx, 4
	call	sha160$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx
	call	sha160$final
	mov	rdi, r14
	lea	rsi, [rsp+sha160_state_size]
	mov	edx, 20
	cmp	rdx, r15
	cmova	rdx, r15
	add	r14, rdx
	sub	r15, rdx
	call	memcpy
	test	r15, r15
	jnz	.doit
	add	rsp, sha160_state_size + 20 + 8
	pop	r15 r14 r13 r12
	epilog

end if
