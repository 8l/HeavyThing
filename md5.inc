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
	; md5.inc: MD5 goods required by TLS 1.0/1.1
	;
	; copy-paste from the other hashes, guts of this one are Marc Bevand's public domain method
	; 
md5_state_size = 128

if used md5$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the md5$init on it
	; returns initialized state
falign
md5$new:
	prolog	md5$new
	mov	edi, md5_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	md5$init
	pop	rax
	epilog

end if

if used md5$init | defined include_everything
	; single argument in rdi: our md5 state
	; void return
falign
md5$init:
	prolog	md5$init
	; if rdi is 16 aligned on entry, then stateptr == rdi+32, bitcountptr == rdi+48, bufferptr == rdi+64
	; if it is not aligned on entry, then stateptr == rdi+24, bitcountptr == rdi+40, bufferptr == rdi+56
	lea	rax, [rdi+32]
	lea	rcx, [rdi+48]
	lea	rdx, [rdi+64]
	lea	r8, [rdi+24]
	lea	r9, [rdi+40]
	lea	r10, [rdi+56]
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
	mov	edx, md5_state_size - 24
	call	memset32
	pop	rdi
	mov	rax, qword [.initial_hash]
	mov	rcx, qword [.initial_hash+8]
	mov	[rdi], rax
	mov	[rdi+8], rcx
	epilog
dalign
.initial_hash:
	dd	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

end if

if used md5$update | defined include_everything
	; three arguments: rdi == md5 state, rsi == byte buffer, rdx == length of same
	; void return
falign
md5$update:
	prolog	md5$update
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
	call	md5$transform
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
	call	md5$transform
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


if used md5$transform | defined include_everything
	; note: not meant to be called externally, but for profiling reasons down the track
	; is made with the normal profiler/public symbol entries
	; called from md5$update and md5$final
	; NONSTANDARD returns/register preservation
falign
md5$transform:
	prolog	md5$transform
	; rdi == our state, rsi == (dd) data
	; TODO: md5 uses much less stack than the other hashing algos, come back and clean this one up from the copy-paste-modify mess i made, haha
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
	mov	[rsp+0xa8], r14
	mov	[rsp+0xb0], r15
	mov	[rsp+0xb8], r12
	mov	rdi, [rdi+sha_stateptr_ofs]
	mov	[rsp+0x68], rdi			; STATE_SAVE

	mov	eax, [rdi]			; a
	mov	ebx, [rdi+4]			; b
	mov	ecx, [rdi+8]			; c
	mov	edx, [rdi+12]			; d

calign
.nextblock:	; here is where we jump to from the bottom if there was more to do
	; save the old values of a-d
	mov	r8d, eax
	mov	r9d, ebx
	mov	r14d, ecx
	mov	r15d, edx

	; rsi[0..15] is our input data that we don't need to molest

macro md5_round0 initial*, dest*, x*, y*, z*, next*, data*, s* {
	if initial = 1
		mov	r10d, [rsi]
		mov	r11d, edx
	end if
	xor	r11d, y
	lea	dest, [dest+r10d+data]
	and	r11d, x
	xor	r11d, z
	mov	r10d, [rsi+next*4]
	add	dest, r11d
	rol	dest, s
	mov	r11d, y
	add	dest, x
}

macro md5_round1 initial*, dest*, x*, y*, z*, next*, data*, s* {
	if initial = 1
		mov	r10d, [rsi+4]
		mov	r11d, edx
		mov	r12d, edx
	end if
	not	r11d
	lea	dest, [dest+r10d+data]
	and	r12d, x
	and	r11d, y
	mov	r10d, [rsi+next*4]
	or	r12d, r11d
	mov	r11d, y
	add	dest, r12d
	mov	r12d, y
	rol	dest, s
	add	dest, x
}

macro md5_round2 initial*, dest*, x*, y*, z*, next*, data*, s* {
	if initial = 1
		mov	r10d, [rsi+20]
		mov	r11d, ecx
	end if
	lea	dest, [dest+r10d+data]
	mov	r10d, [rsi+next*4]
	xor	r11d, z
	xor	r11d, x
	add	dest, r11d
	rol	dest, s
	mov	r11d, x
	add	dest, x
}

macro md5_round3 initial*, dest*, x*, y*, z*, next*, data*, s* {
	if initial = 1
		mov	r10d, [rsi]
		mov	r11d, 0xffffffff
		xor	r11d, edx
	end if
	lea	dest, [dest+r10d+data]
	or	r11d, x
	xor	r11d, y
	add	dest, r11d
	mov	r10d, [rsi+next*4]
	mov	r11d, 0xffffffff
	rol	dest, s
	xor	r11d, y
	add	dest, x
}


	md5_round0 1, eax, ebx, ecx, edx, 1, 0xd76aa478, 7
	md5_round0 0, edx, eax, ebx, ecx, 2, 0xe8c7b756, 12
	md5_round0 0, ecx, edx, eax, ebx, 3, 0x242070db, 17
	md5_round0 0, ebx, ecx, edx, eax, 4, 0xc1bdceee, 22
	md5_round0 0, eax, ebx, ecx, edx, 5, 0xf57c0faf, 7
	md5_round0 0, edx, eax, ebx, ecx, 6, 0x4787c62a, 12
	md5_round0 0, ecx, edx, eax, ebx, 7, 0xa8304613, 17
	md5_round0 0, ebx, ecx, edx, eax, 8, 0xfd469501, 22
	md5_round0 0, eax, ebx, ecx, edx, 9, 0x698098d8, 7
	md5_round0 0, edx, eax, ebx, ecx, 10, 0x8b44f7af, 12
	md5_round0 0, ecx, edx, eax, ebx, 11, 0xffff5bb1, 17
	md5_round0 0, ebx, ecx, edx, eax, 12, 0x895cd7be, 22
	md5_round0 0, eax, ebx, ecx, edx, 13, 0x6b901122, 7
	md5_round0 0, edx, eax, ebx, ecx, 14, 0xfd987193, 12
	md5_round0 0, ecx, edx, eax, ebx, 15, 0xa679438e, 17
	md5_round0 0, ebx, ecx, edx, eax, 0, 0x49b40821, 22

	md5_round1 1, eax, ebx, ecx, edx, 6, 0xf61e2562, 5
	md5_round1 0, edx, eax, ebx, ecx, 11, 0xc040b340, 9
	md5_round1 0, ecx, edx, eax, ebx, 0, 0x265e5a51, 14
	md5_round1 0, ebx, ecx, edx, eax, 5, 0xe9b6c7aa, 20
	md5_round1 0, eax, ebx, ecx, edx, 10, 0xd62f105d, 5
	md5_round1 0, edx, eax, ebx, ecx, 15, 0x2441453, 9
	md5_round1 0, ecx, edx, eax, ebx, 4, 0xd8a1e681, 14
	md5_round1 0, ebx, ecx, edx, eax, 9, 0xe7d3fbc8, 20
	md5_round1 0, eax, ebx, ecx, edx, 14, 0x21e1cde6, 5
	md5_round1 0, edx, eax, ebx, ecx, 3, 0xc33707d6, 9
	md5_round1 0, ecx, edx, eax, ebx, 8, 0xf4d50d87, 14
	md5_round1 0, ebx, ecx, edx, eax, 13, 0x455a14ed, 20
	md5_round1 0, eax, ebx, ecx, edx, 2, 0xa9e3e905, 5
	md5_round1 0, edx, eax, ebx, ecx, 7, 0xfcefa3f8, 9
	md5_round1 0, ecx, edx, eax, ebx, 12, 0x676f02d9, 14
	md5_round1 0, ebx, ecx, edx, eax, 0, 0x8d2a4c8a, 20

	md5_round2 1, eax, ebx, ecx, edx, 8, 0xfffa3942, 4
	md5_round2 0, edx, eax, ebx, ecx, 11, 0x8771f681, 11
	md5_round2 0, ecx, edx, eax, ebx, 14, 0x6d9d6122, 16
	md5_round2 0, ebx, ecx, edx, eax, 1, 0xfde5380c, 23
	md5_round2 0, eax, ebx, ecx, edx, 4, 0xa4beea44, 4
	md5_round2 0, edx, eax, ebx, ecx, 7, 0x4bdecfa9, 11
	md5_round2 0, ecx, edx, eax, ebx, 10, 0xf6bb4b60, 16
	md5_round2 0, ebx, ecx, edx, eax, 13, 0xbebfbc70, 23
	md5_round2 0, eax, ebx, ecx, edx, 0, 0x289b7ec6, 4
	md5_round2 0, edx, eax, ebx, ecx, 3, 0xeaa127fa, 11
	md5_round2 0, ecx, edx, eax, ebx, 6, 0xd4ef3085, 16
	md5_round2 0, ebx, ecx, edx, eax, 9, 0x4881d05, 23
	md5_round2 0, eax, ebx, ecx, edx, 12, 0xd9d4d039, 4
	md5_round2 0, edx, eax, ebx, ecx, 15, 0xe6db99e5, 11
	md5_round2 0, ecx, edx, eax, ebx, 2, 0x1fa27cf8, 16
	md5_round2 0, ebx, ecx, edx, eax, 0, 0xc4ac5665, 23

	md5_round3 1, eax, ebx, ecx, edx, 7, 0xf4292244, 6
	md5_round3 0, edx, eax, ebx, ecx, 14, 0x432aff97, 10
	md5_round3 0, ecx, edx, eax, ebx, 5, 0xab9423a7, 15
	md5_round3 0, ebx, ecx, edx, eax, 12, 0xfc93a039, 21
	md5_round3 0, eax, ebx, ecx, edx, 3, 0x655b59c3, 6
	md5_round3 0, edx, eax, ebx, ecx, 10, 0x8f0ccc92, 10
	md5_round3 0, ecx, edx, eax, ebx, 1, 0xffeff47d, 15
	md5_round3 0, ebx, ecx, edx, eax, 8, 0x85845dd1, 21
	md5_round3 0, eax, ebx, ecx, edx, 15, 0x6fa87e4f, 6
	md5_round3 0, edx, eax, ebx, ecx, 6, 0xfe2ce6e0, 10
	md5_round3 0, ecx, edx, eax, ebx, 13, 0xa3014314, 15
	md5_round3 0, ebx, ecx, edx, eax, 4, 0x4e0811a1, 21
	md5_round3 0, eax, ebx, ecx, edx, 11, 0xf7537e82, 6
	md5_round3 0, edx, eax, ebx, ecx, 2, 0xbd3af235, 10
	md5_round3 0, ecx, edx, eax, ebx, 9, 0x2ad7d2bb, 15
	md5_round3 0, ebx, ecx, edx, eax, 0, 0xeb86d391, 21

	; add old values of a-d
	add	eax, r8d
	add	ebx, r9d
	add	ecx, r14d
	add	edx, r15d

	sub	qword [rsp+0xa0], 64
	add	rsi, 64
	cmp	qword [rsp+0xa0], 64
	jae	.nextblock
	; else, remaining bytes is < a full block, so bailout
	mov	r8, [rsp+0x68]			; STATE_SAVE
	mov	dword [r8], eax
	mov	dword [r8+4], ebx
	mov	dword [r8+8], ecx
	mov	dword [r8+12], edx
	mov	rcx, r8
	mov	rdx, [rsp+0xa0]
	mov	rax, [rsp+0x80]
	mov	rbx, [rsp+0x88]	
	mov	rdi, [rsp+0x90]
	mov	r12, [rsp+0xb8]
	mov	r14, [rsp+0xa8]
	mov	r15, [rsp+0xb0]
	add	rsp, rax
	epilog

end if

if used md5$final | defined include_everything
	; three arguments: rdi == md5 state, rsi == pointer to 16 byte buffer for the final digest, bool in edx as to whether we should heap$free the state
	; void return, reinitializes our state for further use again if !edx
falign
md5$final:
	prolog	md5$final
	push	rdx rsi rdi
	mov	r8, [rdi+sha_bitcountptr_ofs]
	mov	rcx, [r8]
	mov	r9, rcx
	; little endian for md5, no bswap bswap	r9
	shr	rcx, 3
	mov	[r8], r9		; bitcount reversed 64 bits
	and	rcx, 0x3f
	test	rcx, rcx		; usedspace?
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
	call	md5$transform
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
	call	md5$transform
	; rdi and rsi both stay in tact across that call
	mov	rsi, [rsp+8]
	mov	rdx, [rdi+sha_stateptr_ofs]
	mov	eax, dword [rdx]
	mov	r8d, dword [rdx+4]
	mov	r9d, dword [rdx+8]
	mov	r10d, dword [rdx+12]
	mov	dword [rsi], eax
	mov	dword [rsi+4], r8d
	mov	dword [rsi+8], r9d
	mov	dword [rsi+12], r10d
	; last but not least, reinitialize ourselves:
	mov	rdi, [rsp]
	call	md5$init
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



if used md5$mgf1 | defined include_everything
	; one-pass MGF1 as defined by rfc2437 (one-pass == we do stack-based state)
	; four arguments: rdi == seed, rsi == seed length, rdx == destination, rcx == dest length
falign
md5$mgf1:
	prolog	md5$mgf1
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	sub	rsp, md5_state_size + 16 + 8
	mov	rdi, rsp
	call	md5$init
	mov	qword [rsp+md5_state_size+16], 0
calign
.doit:
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	md5$update
	mov	eax, [rsp+md5_state_size+16]
if use_movbe
	add	dword [rsp+md5_state_size+16], 1
	movbe	[rsp+md5_state_size+20], eax
else
	bswap	eax
	add	dword [rsp+md5_state_size+16], 1
	mov	[rsp+md5_state_size+20], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+md5_state_size+20]
	mov	edx, 4
	call	md5$update
	mov	rdi, rsp
	lea	rsi, [rsp+md5_state_size]
	xor	edx, edx
	call	md5$final
	mov	rdi, r14
	lea	rsi, [rsp+md5_state_size]
	mov	edx, 16
	cmp	rdx, r15
	cmova	rdx, r15
	add	r14, rdx
	sub	r15, rdx
	call	memcpy
	test	r15, r15
	jnz	.doit
	add	rsp, md5_state_size + 16 + 8
	pop	r15 r14 r13 r12
	epilog

end if
