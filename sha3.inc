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
	; sha3.inc: SHA3-{224,256,384,512} goods
	;
	; translated loosely from the public domain original Ronny Van Keer/Wei Dai
	; and modified to suit my environment.
	;
	; NOTE: This is certainly not the fastest SHA3 implementation in existence,
	; but is on-par with its kin here so consider this v1 until I get around to
	; redoing it with xmm regs.
	;
	; these are "wrapped" to behave like the sha2 variants re: calling convention
	; if you want truncated variants from these, you'll have to do the truncation
	; externally (e.g. post $final call)
	;

sha3_state_size = 216

sha3_state_ofs = 0
sha3_digestsize_ofs = 200
sha3_r_ofs = 204
sha3_counter_ofs = 208


if used sha3_224$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the init on it
	; returns initialized state
falign
sha3_224$new:
	prolog	sha3_224$new
	mov	edi, sha3_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha3_224$init
	pop	rax
	epilog

end if


if used sha3_224$init | defined include_everything
	; single argument in rdi: our sha3 state
	; void return, leaves rdi in tact
falign
sha3_224$init:
	prolog	sha3_224$init
	push	rdi
	xor	esi, esi
	mov	edx, sha3_state_size
	call	memset32
	pop	rdi
	mov	dword [rdi+sha3_digestsize_ofs], 28		; sha3-224
	mov	dword [rdi+sha3_r_ofs], 200 - (2 * 28)
	epilog

end if


if used sha3_256$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the init on it
	; returns initialized state
falign
sha3_256$new:
	prolog	sha3_256$new
	mov	edi, sha3_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha3_256$init
	pop	rax
	epilog

end if


if used sha3_256$init | defined include_everything
	; single argument in rdi: our sha3 state
	; void return, leaves rdi in tact
falign
sha3_256$init:
	prolog	sha3_256$init
	push	rdi
	xor	esi, esi
	mov	edx, sha3_state_size
	call	memset32
	pop	rdi
	mov	dword [rdi+sha3_digestsize_ofs], 32		; sha3-256
	mov	dword [rdi+sha3_r_ofs], 200 - (2 * 32)
	epilog

end if


if used sha3_384$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the init on it
	; returns initialized state
falign
sha3_384$new:
	prolog	sha3_384$new
	mov	edi, sha3_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha3_384$init
	pop	rax
	epilog

end if


if used sha3_384$init | defined include_everything
	; single argument in rdi: our sha3 state
	; void return, leaves rdi in tact
falign
sha3_384$init:
	prolog	sha3_384$init
	push	rdi
	xor	esi, esi
	mov	edx, sha3_state_size
	call	memset32
	pop	rdi
	mov	dword [rdi+sha3_digestsize_ofs], 48		; sha3-384
	mov	dword [rdi+sha3_r_ofs], 200 - (2 * 48)
	epilog

end if


if used sha3_512$new | defined include_everything
	; no arguments, does a heap$alloc of the required state and performs the init on it
	; returns initialized state
falign
sha3_512$new:
	prolog	sha3_512$new
	mov	edi, sha3_state_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	sha3_512$init
	pop	rax
	epilog

end if


if used sha3_512$init | defined include_everything
	; single argument in rdi: our sha3 state
	; void return, leaves rdi in tact
falign
sha3_512$init:
	prolog	sha3_512$init
	push	rdi
	xor	esi, esi
	mov	edx, sha3_state_size
	call	memset32
	pop	rdi
	mov	dword [rdi+sha3_digestsize_ofs], 64		; sha3-512
	mov	dword [rdi+sha3_r_ofs], 200 - (2 * 64)
	epilog

end if


if used sha3_224$update | used sha3_256$update | used sha3_384$update | used sha3_512$update | defined include_everything
	; three arguments: rdi == sha3 state, rsi == byte buffer, rdx == length of same
	; void return
falign
sha3_common$update:
if used sha3_224$update
sha3_224$update:
end if
if used sha3_256$update
sha3_256$update:
end if
if used sha3_384$update
sha3_384$update:
end if
if used sha3_512$update
sha3_512$update:
end if
	prolog	sha3_common$update
	test	rdx, rdx
	jz	.nothingtodo
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	push	r14
calign
.outer:
	mov	r14d, [rbx+sha3_r_ofs]
	mov	rdi, rbx
	mov	rsi, r12
	sub	r14d, [rbx+sha3_counter_ofs]
	add	rdi, [rbx+sha3_counter_ofs]
	cmp	r13, r14
	jb	.outer_done
	mov	edx, r14d
	call	memxor
	mov	rdi, rbx
	call	sha3_common$keccakf1600
	add	r12, r14
	mov	dword [rbx+sha3_counter_ofs], 0
	sub	r13, r14
	jz	.outer_reallydone
	jmp	.outer
calign
.outer_done:
	mov	edx, r13d
	call	memxor
	add	dword [rbx+sha3_counter_ofs], r13d
.outer_reallydone:
	pop	r14 r13 r12 rbx
.nothingtodo:
	epilog

end if


if used sha3_224$final | used sha3_256$final | used sha3_384$final | used sha3_512$final | defined include_everything
	; three arguments: rdi == sha3 state, rsi == pointer to digestsize buffer, bool in edx as to whether we hsould heap$free the state
	; void return
falign
sha3_common$final:
if used sha3_224$final
sha3_224$final:
end if
if used sha3_256$final
sha3_256$final:
end if
if used sha3_384$final
sha3_384$final:
end if
if used sha3_512$final
sha3_512$final:
end if
	prolog	sha3_common$final
	push	rbx r12 rdx
	mov	r8d, [rdi+sha3_r_ofs]
	mov	ecx, [rdi+sha3_counter_ofs]
	mov	rbx, rdi
	sub	r8d, 1
	mov	r12, rsi
	xor	byte [rdi+rcx], 6
	xor	byte [rdi+r8], 0x80
	call	sha3_common$keccakf1600
	mov	rdi, r12
	mov	rsi, rbx
	mov	edx, [rbx+sha3_digestsize_ofs]
	call	memcpy
	; regardless of whether we are freeing the state, we reset the lot
	push	qword [rbx+sha3_digestsize_ofs]	; save digestsize and r
	mov	rdi, rbx
	xor	esi, esi
	mov	edx, sha3_state_size
	call	memset32
	pop	rcx rax r12
	test	eax, eax
	jnz	.withfree
	mov	[rbx+sha3_digestsize_ofs], rcx
	pop	rbx
	epilog
.withfree:
	mov	rdi, rbx
	pop	rbx
	call	heap$free
	epilog

end if


if used sha3_common$keccakf1600 | defined include_everything
	; single argument in rdi: sha3 state
	; A{bgkms}{aeiou} point directly to the state offsets 0..192
	; E{bgkms}{aeiou} point to what ends up stack state 0..192
	; BC{aeiou} end up rdi, rsi, r8, r9, r10
	; D{aeiou} end up r11..r15
	; current round number sits in stack[200]
falign
sha3_common$keccakf1600:
	prolog	sha3_common$keccakf1600
	push	rbx r12 r13
	mov	rbx, rdi
	push	r14 r15 rbp
	sub	rsp, 200
	xor	rbp, rbp
calign
.roundloop:
	; prepareTheta
	mov	rdi, [rbx+0]
	mov	rsi, [rbx+8]
	mov	r8, [rbx+16]
	mov	r9, [rbx+24]
	mov	r10, [rbx+32]
	xor	rdi, [rbx+40]
	xor	rsi, [rbx+48]
	xor	r8, [rbx+56]
	xor	r9, [rbx+64]
	xor	r10, [rbx+72]
	xor	rdi, [rbx+80]
	xor	rsi, [rbx+88]
	xor	r8, [rbx+96]
	xor	r9, [rbx+104]
	xor	r10, [rbx+112]
	xor	rdi, [rbx+120]
	xor	rsi, [rbx+128]
	xor	r8, [rbx+136]
	xor	r9, [rbx+144]
	xor	r10, [rbx+152]
	xor	rdi, [rbx+160]
	xor	rsi, [rbx+168]
	xor	r8, [rbx+176]
	xor	r9, [rbx+184]
	xor	r10, [rbx+192]

	; thetaRhoPiChiIotaPrepareTheta(round, A, E)
	mov	r11, rsi
	mov	r12, r8
	mov	r13, r9
	rol	r11, 1
	rol	r12, 1
	rol	r13, 1
	xor	r11, r10		; Da = BCu^rol(BCe, 1)
	xor	r12, rdi		; De = BCa^rol(BCi, 1)
	xor	r13, rsi		; Di = BCe^rol(BCo, 1)
	mov	r14, r10
	mov	r15, rdi
	xor	[rbx+0], r11		; Aba ^= Da
	rol	r14, 1
	rol	r15, 1
	xor	[rbx+48], r12		; Age ^= De
	xor	r14, r8			; Do = BCi^rol(BCu, 1)
	xor	r15, r9			; Du = BCo^rol(BCa, 1)
	xor	[rbx+96], r13		; Aki ^= Di
	mov	rdi, [rbx+0]		; BCa = Aba
	mov	rsi, [rbx+48]		; BCe = Age
	mov	r8, [rbx+96]		; BCi = Aki
	xor	[rbx+144], r14		; Amo ^= Do
	xor	[rbx+192], r15		; Asu ^= Du
	mov	r9, [rbx+144]		; BCo = Amo
	mov	r10, [rbx+192]		; BCu = Asu
	rol	rsi, 44			; rol(BCe, 44)
	rol	r8, 43			; rol(BCi, 43)
	rol	r9, 21			; rol(BCo, 21)
	rol	r10, 14			; rol(BCu, 14)

macro sha3_keccak_setstack use_rc*, eofs* {
	mov	rdx, rsi		; Temp0 = BCe
	mov	rcx, r8			; Temp1 = BCi

	not	rdx			; ~Temp0
	not	rcx			; ~Temp1

	and	rdx, r8			; Temp0 &= BCi
	and	rcx, r9			; Temp1 &= BCo

	xor	rdx, rdi		; Temp0 ^= BCa
	xor	rcx, rsi		; Temp1 ^= BCe
if use_rc
	xor	rdx, [ebp*8+.round_constants]	; Temp0 ^= roundconstants[round]
	add	ebp, 1

	mov	[rsp+8+eofs], rcx		; Ebe = Temp1
	mov	[rsp+0+eofs], rdx		; Eba = Temp0
else
	mov	[rsp+0+eofs], rdx		; Eba = Temp0
	mov	[rsp+8+eofs], rcx		; Ebe = Temp1
end if

	mov	rdx, r9			; Temp0 = BCo
	mov	rcx, r10		; Temp1 = BCu
	mov	rax, rdi		; Temp2 = BCa

	not	rdx			; ~Temp0
	not	rcx			; ~Temp1
	not	rax			; ~Temp2

	and	rdx, r10		; Temp0 &= BCu
	and	rcx, rdi		; Temp1 &= BCa
	and	rax, rsi		; Temp2 &= BCe

	xor	rdx, r8			; Temp0 ^= BCi
	xor	rcx, r9			; Temp1 ^= BCo
	xor	rax, r10		; Temp2 ^= BCu

	mov	[rsp+16+eofs], rdx		; Ebi = Temp0
	mov	[rsp+24+eofs], rcx		; Ebo = Temp1
	mov	[rsp+32+eofs], rax		; Ebu = Temp2
}

	sha3_keccak_setstack 1, 0

macro sha3_keccak_memset b1*, b2*, b3*, b4*, b5*, r1*, r2*, r3*, r4*, r5*, s1*, s2*, s3*, s4*, s5* {
	xor	b1, r1
	xor	b2, r2
	xor	b3, r3
	xor	b4, r4
	xor	b5, r5
	mov	rdi, b1
	mov	rsi, b2
	mov	r8, b3
	mov	r9, b4
	mov	r10, b5
	rol	rdi, s1
	rol	rsi, s2
	rol	r8, s3
	rol	r9, s4
	rol	r10, s5
}

	sha3_keccak_memset [rbx+24], [rbx+72], [rbx+80], [rbx+128], [rbx+176], r14, r15, r11, r12, r13, 28, 20, 3, 45, 61
	sha3_keccak_setstack 0, 40

	sha3_keccak_memset [rbx+8], [rbx+56], [rbx+104], [rbx+152], [rbx+160], r12, r13, r14, r15, r11, 1, 6, 25, 8, 18
	sha3_keccak_setstack 0, 80

	sha3_keccak_memset [rbx+32], [rbx+40], [rbx+88], [rbx+136], [rbx+184], r15, r11, r12, r13, r14, 27, 36, 10, 15, 56
	sha3_keccak_setstack 0, 120

	sha3_keccak_memset [rbx+16], [rbx+64], [rbx+112], [rbx+120], [rbx+168], r13, r14, r15, r11, r12, 62, 55, 39, 41, 2
	sha3_keccak_setstack 0, 160

	; do the same again but with A,E swapped
macro sha3_keccak_setstate use_rc*, eofs* {
	mov	rdx, rsi		; Temp0 = BCe
	mov	rcx, r8			; Temp1 = BCi

	not	rdx			; ~Temp0
	not	rcx			; ~Temp1

	and	rdx, r8			; Temp0 &= BCi
	and	rcx, r9			; Temp1 &= BCo

	xor	rdx, rdi		; Temp0 ^= BCa
	xor	rcx, rsi		; Temp1 ^= BCe
if use_rc
	xor	rdx, [ebp*8+.round_constants]	; Temp0 ^= roundconstants[round]
	add	ebp, 1

	mov	[rbx+8+eofs], rcx		; Abe = Temp1
	mov	[rbx+0+eofs], rdx		; Aba = Temp0
else
	mov	[rbx+0+eofs], rdx		; Aba = Temp0
	mov	[rbx+8+eofs], rcx		; Abe = Temp1
end if

	mov	rdx, r9			; Temp0 = BCo
	mov	rcx, r10		; Temp1 = BCu
	mov	rax, rdi		; Temp2 = BCa

	not	rdx			; ~Temp0
	not	rcx			; ~Temp1
	not	rax			; ~Temp2

	and	rdx, r10		; Temp0 &= BCu
	and	rcx, rdi		; Temp1 &= BCa
	and	rax, rsi		; Temp2 &= BCe

	xor	rdx, r8			; Temp0 ^= BCi
	xor	rcx, r9			; Temp1 ^= BCo
	xor	rax, r10		; Temp2 ^= BCu

	mov	[rbx+16+eofs], rdx		; Ebi = Temp0
	mov	[rbx+24+eofs], rcx		; Ebo = Temp1
	mov	[rbx+32+eofs], rax		; Ebu = Temp2
}

	; prepareTheta
	mov	rdi, [rsp+0]
	mov	rsi, [rsp+8]
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	r10, [rsp+32]
	xor	rdi, [rsp+40]
	xor	rsi, [rsp+48]
	xor	r8, [rsp+56]
	xor	r9, [rsp+64]
	xor	r10, [rsp+72]
	xor	rdi, [rsp+80]
	xor	rsi, [rsp+88]
	xor	r8, [rsp+96]
	xor	r9, [rsp+104]
	xor	r10, [rsp+112]
	xor	rdi, [rsp+120]
	xor	rsi, [rsp+128]
	xor	r8, [rsp+136]
	xor	r9, [rsp+144]
	xor	r10, [rsp+152]
	xor	rdi, [rsp+160]
	xor	rsi, [rsp+168]
	xor	r8, [rsp+176]
	xor	r9, [rsp+184]
	xor	r10, [rsp+192]
	; thetaRhoPiChiIotaPrepareTheta(round+1, E, A)

	mov	r11, rsi
	mov	r12, r8
	mov	r13, r9
	rol	r11, 1
	rol	r12, 1
	rol	r13, 1
	xor	r11, r10		; Da = BCu^rol(BCe, 1)
	xor	r12, rdi		; De = BCa^rol(BCi, 1)
	xor	r13, rsi		; Di = BCe^rol(BCo, 1)
	mov	r14, r10
	mov	r15, rdi
	xor	[rsp+0], r11		; Aba ^= Da
	rol	r14, 1
	rol	r15, 1
	xor	[rsp+48], r12		; Age ^= De
	xor	r14, r8			; Do = BCi^rol(BCu, 1)
	xor	r15, r9			; Du = BCo^rol(BCa, 1)
	xor	[rsp+96], r13		; Aki ^= Di
	mov	rdi, [rsp+0]		; BCa = Aba
	mov	rsi, [rsp+48]		; BCe = Age
	mov	r8, [rsp+96]		; BCi = Aki
	xor	[rsp+144], r14		; Amo ^= Do
	xor	[rsp+192], r15		; Asu ^= Du
	mov	r9, [rsp+144]		; BCo = Amo
	mov	r10, [rsp+192]		; BCu = Asu
	rol	rsi, 44			; rol(BCe, 44)
	rol	r8, 43			; rol(BCi, 43)
	rol	r9, 21			; rol(BCo, 21)
	rol	r10, 14			; rol(BCu, 14)
	
	sha3_keccak_setstate 1, 0

	sha3_keccak_memset [rsp+24], [rsp+72], [rsp+80], [rsp+128], [rsp+176], r14, r15, r11, r12, r13, 28, 20, 3, 45, 61
	sha3_keccak_setstate 0, 40

	sha3_keccak_memset [rsp+8], [rsp+56], [rsp+104], [rsp+152], [rsp+160], r12, r13, r14, r15, r11, 1, 6, 25, 8, 18
	sha3_keccak_setstate 0, 80

	sha3_keccak_memset [rsp+32], [rsp+40], [rsp+88], [rsp+136], [rsp+184], r15, r11, r12, r13, r14, 27, 36, 10, 15, 56
	sha3_keccak_setstate 0, 120

	sha3_keccak_memset [rsp+16], [rsp+64], [rsp+112], [rsp+120], [rsp+168], r13, r14, r15, r11, r12, 62, 55, 39, 41, 2
	sha3_keccak_setstate 0, 160

	cmp	ebp, 24
	jb	.roundloop

	add	rsp, 200

	; Wei Dai/Ronny didn't worry about cleaning the stackvars, so we leave it alone
	pop	rbp r15 r14 r13 r12 rbx
	epilog
dalign
.round_constants:
	dq	0x0000000000000001, 0x0000000000008082, 0x800000000000808a
	dq	0x8000000080008000, 0x000000000000808b, 0x0000000080000001
	dq	0x8000000080008081, 0x8000000000008009, 0x000000000000008a
	dq	0x0000000000000088, 0x0000000080008009, 0x000000008000000a
	dq	0x000000008000808b, 0x800000000000008b, 0x8000000000008089
	dq	0x8000000000008003, 0x8000000000008002, 0x8000000000000080
	dq	0x000000000000800a, 0x800000008000000a, 0x8000000080008081
	dq	0x8000000000008080, 0x0000000080000001, 0x8000000080008008


end if

