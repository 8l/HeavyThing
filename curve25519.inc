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
	; curve25519.inc: Implementation of the SSE2 public domain variant at
	; https://github.com/floodyberry/curve25519-donna
	;
	; to generate a public 32 byte key from 32 bytes random (as his docs
	; mention, clamping beforehand not necessary), use curve25519$donna_basepoint
	; 
	; to generate a 32 byte shared key, use curve25519$donna
	;

if used curve25519$donna_basepoint | defined include_everything
	; two arguments: rdi == ptr to 32 byte public key (output), rsi == ptr to 32 bytes rng output
	; unlike the C version, we modify the rsi buffer inpace (rather than make a stack copy of it)
falign
curve25519$donna_basepoint:
	prolog	curve25519$donna_basepoint
	and	byte [rsi], 0xf8
	and	byte [rsi+0x1f], 0x7f
	or	byte [rsi+0x1f], 0x40
	mov	rdx, .basepoint
	call	curve25519$scalarmult_donna
	epilog
dalign
.basepoint:
	db	9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

end if

if used curve25519$donna | defined include_everything
	; three arguments: rdi == ptr to 32 byte shared (output), rsi == ptr to 32 byte secret, rdx == ptr to 32 byte other public
falign
curve25519$donna:
	prolog	curve25519$donna
	and	byte [rsi], 0xf8
	and	byte [rsi+0x1f], 0x7f
	or	byte [rsi+0x1f], 0x40
	call	curve25519$scalarmult_donna
	epilog

end if


if used curve25519$scalarmult_donna | defined include_everything
	; three args (see above)
falign
curve25519$scalarmult_donna:
	prolog	curve25519$scalarmult_donna
	mov	rcx, rsp
	pxor	xmm0, xmm0
	pxor	xmm15, xmm15
	push	rbp rbx r12
	and	rcx, 0xf		; misaligned stack on entry?
	mov	rbp, rdi
	xor	eax, eax
	add	rcx, 0x4d0
	push	r13 r14 r15
	sub	rsp, rcx
	mov	[rsp+0x4c8], rcx	; our stack modification amount

	mov	r12d, [rdx]
	mov	r11d, [rdx+4]
	mov	r10d, [rdx+8]
	movaps	[rsp+0x310], xmm0
	movaps	[rsp+0x320], xmm0
	movaps	[rsp+0x330], xmm0
	mov	r9d, [rdx+12]
	mov	r8d, [rdx+16]
	lea	rbx, [rsp+0x310]
	movaps	[rsp+0x340], xmm0
	movaps	[rsp+0x350], xmm0
	movaps	[rsp+0x360], xmm0
	movaps	xmm7, [.sse2_top64bitmask]
	movaps	xmm8, [.packednineteen]
	mov	eax, r12d
	mov	edi, [rdx+0x14]

	mov	dword [rsp+0x310], 1
	mov	dword [rsp+0x340], 1
	mov	[rsp+0x3c8], rax	; dwords 3c8 and 3cc == 0
	
	mov	ecx, [rdx+0x18]
	and	eax, 0x3ffffff
	movaps	xmm9, xmm7
	mov 	edx, [rdx+0x1c]
	mov	dword [rsp+0x3a0], eax
	
	mov	eax, r11d
	shl	rax, 0x20
	or	rax, r12
	shr	rax, 0x1a
	and	eax, 0x1ffffff
	mov	dword [rsp+0x3a4], eax
	
	mov	eax, r10d
	shl	rax, 0x20
	or	rax, r11
	shr	rax, 0x13
	and	eax, 0x3ffffff
	mov	dword [rsp+0x3a8], eax

	mov	eax, r9d
	shr	r9d, 0x6
	shl	rax, 0x20
	mov	dword [rsp+0x3b0], r9d
	or	rax, r10
	shr	rax, 0xd
	and	eax, 0x1ffffff
	mov	dword [rsp+0x3ac], eax

	mov	eax, r8d
	and	eax, 0x1ffffff
	movaps	xmm5, [rsp+0x3a0]
	mov	dword [rsp+0x3b4], eax

	mov	eax, edi
	shl	rax, 0x20
	pshufd	xmm0, xmm5, 0x55
	or	rax, r8
	pshufd	xmm2, xmm5, 0xaa
	shr	rax, 0x19
	xor	r8d, r8d
	and	eax, 0x3ffffff
	pand	xmm7, xmm0
	mov	dword [rsp+0x3b8], eax

	mov	eax, ecx
	shl	rax, 0x20
	movaps	xmm6, xmm2
	or	rax, rdi
	paddq	xmm7, xmm0
	pshufd	xmm0, xmm5, 0xff
	shr	rax, 0x13
	movaps	xmm10, xmm6
	and	eax, 0x1ffffff
	mov	dword [rsp+0x3bc], eax

	mov	eax, edx
	shl	rax, 0x20
	or	rax, rcx
	shr	rax, 0xc
	and	eax, 0x3ffffff
	mov	dword [rsp+0x3c0], eax

	mov	eax, edx
	mov	edx, 0xfe
	shr	eax, 0x6
	and	eax, 0x1ffffff
	mov	dword [rsp+0x3c4], eax
	movaps	[rsp+0xb0], xmm2

	
	; xmm1, 3, 4, 9, 11, 12, 13, 14 are all unused so far
	pmuludq	xmm10, xmm8
	pshufd	xmm2, xmm5, 0
	movaps	[rsp+0x260], xmm7
	pshufd	xmm7, xmm7, 0xa
	movaps	[rsp+0x50], xmm2
	movaps	xmm3, xmm9
	pand	xmm3, xmm0
	movaps	xmm13, [rsp+0x3b0]
	paddq	xmm3, xmm0
	pshufd	xmm0, xmm13, 0x55
	movaps	xmm2, xmm9
	pshufd	xmm4, xmm13, 0xaa
	pand	xmm2, xmm0
	movaps	xmm1, xmm9
	movaps	xmm14, xmm4
	paddq	xmm2, xmm0
	pshufd	xmm0, xmm13, 0xff
	movaps	[rsp+0x1c0], xmm4
	
	pshufd	xmm4, xmm13, 0
	pand	xmm1, xmm0
	movaps	xmm6, xmm14
	movaps	[rsp+0xc0], xmm3
	movaps	xmm11, xmm4
	pmuludq	xmm6, xmm8
	movaps	[rsp+0x110], xmm4

	paddq	xmm1, xmm0
	pshufd	xmm3, xmm3, 0xa
	movaps	[rsp+0x120], xmm2
	pshufd	xmm2, xmm2, 0xa
	movaps	[rsp+0x1d0], xmm1
	pmuludq	xmm3, xmm8
	pshufd	xmm1, xmm1, 0xa
	movaps	xmm9, xmm11
	movaps	xmm11, xmm7
	pmuludq	xmm2, xmm8
	
	movaps	xmm14, xmm15
	movaps	xmm12, [rsp+0x3c0]
	pmuludq	xmm11, xmm8
	pmuludq	xmm9, xmm8
	pmuludq	xmm1, xmm8
	
	pshufd	xmm4, xmm12, 0xdd
	movaps	xmm0, [.sse2_top64bitmask]
	pand	xmm0, xmm4
	movaps	xmm8, [rsp+0x340]
	paddq	xmm0, xmm4
	pshufd	xmm4, xmm12, 0xcc
	movaps	[rsp+0x270], xmm0
	pshufd	xmm0, xmm0, 0xa
	movaps	[rsp+0x250], xmm4
	pmuludq	xmm4, [.packednineteen]
	pmuludq	xmm0, [.packednineteen]
	movaps	[rsp+0x2a0], xmm2
	movaps	xmm2, xmm15
	movaps	[rsp+0x2c0], xmm3
	movaps	xmm3, xmm15
	movaps	[rsp+0x2d0], xmm6
	movaps	xmm6, xmm8
	movaps	[rsp+0x280], xmm0
	movaps	[rsp+0x290], xmm1
	movaps	[rsp+0x2b0], xmm4
	movaps	[rsp+0x2e0], xmm9
	
	movaps	xmm7, [rsp+0x310]
	movaps	[rsp+0x2f0], xmm10
	movaps	xmm10, xmm12
	movaps	[rsp+0x300], xmm11
	movaps	xmm12, xmm13
	movaps	[rsp+0x1a0], xmm15
	movaps	xmm11, xmm15
	movaps	[rsp+0x1b0], xmm15
	
	movaps	xmm13, xmm10
	movaps	xmm15, xmm5
	movaps	xmm10, xmm14
	movaps	xmm5, xmm14
	jmp	.highentry
align 16
.packednineteen:
	dq	19, 19
.packedmask26:
	dq	0x3ffffff, 0x3ffffff
.packedmask25:
	dq	0x1ffffff, 0x1ffffff
.packed32zeromodp0:
	dd	0x7ffffda, 0x7ffffda, 0x3fffffe, 0x3fffffe
.packed32zeromodp1:
	dd	0x7fffffe, 0x7fffffe, 0x3fffffe, 0x3fffffe
.packedmask26262626:
	dd	0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff
.packedmask25252525:
	dd	0x1ffffff, 0x1ffffff, 0x1ffffff, 0x1ffffff
.packedthirtyeight:
	dq	38, 38
.packed121666121665:
	dq	121666, 121665
.packed2p0:
	dd	0x7ffffda, 0x3fffffe, 0x7fffffe, 0x3fffffe
.packed2p2:
	dd	0x7fffffe, 0x3fffffe, 0x0000000, 0x0000000
.packed2p1:
	dd	0x7fffffe, 0x3fffffe, 0x7fffffe, 0x3fffffe
.sse2_bot32bitmask:
	dd	0xffffffff, 0x00000000, 0xffffffff, 0x00000000
.sse2_top64bitmask:
	dd	0x00000000, 0x00000000, 0xffffffff, 0xffffffff
.packed3819:
	dq	38, 19
.sse2_bot64bitmask:
	dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000
calign
.highloop:
	movaps	xmm6, [rsp+0x200]
	mov	r8, r9
	movaps	xmm13, [rsp+0x210]
	movaps	xmm12, [rsp+0x1f0]
	movaps	xmm15, [rsp+0x1e0]
	movaps	xmm10, [rsp+0x1b0]
calign
.highentry:
	mov	rax, rdx
	mov	ecx, edx
	sub	rdx, 1
	shr	rax, 3
	and	ecx, 7
	movzx	eax, byte [rsi+rax]
	pxor	xmm13, xmm11
	pxor	xmm15, xmm7
	sar	eax, cl
	mov	ecx, r8d

	pxor	xmm12, xmm5
	movaps	xmm9, xmm13

	and	eax, 1
	pxor	xmm6, xmm2
	movaps	xmm1, xmm15
	xor	ecx, eax
	neg	ecx
	pxor	xmm10, xmm3
	movaps	xmm0, xmm12
	movd	xmm4, ecx
	cmp	rdx, 2
	movsxd	r9, eax

	pshufd	xmm4, xmm4, 0
	pand	xmm9, xmm4
	pand	xmm1, xmm4
	pand	xmm0, xmm4
	pxor	xmm9, xmm11
	movaps	xmm11, [rsp+0x1a0]

	pxor	xmm1, xmm7
	pxor	xmm11, xmm14
	movaps	xmm7, xmm6
	pxor	xmm0, xmm5
	pand	xmm7, xmm4
	movaps	xmm5, xmm11
	pxor	xmm15, xmm1
	pxor	xmm12, xmm0
	pand	xmm5, xmm4
	pxor	xmm7, xmm2
	movaps	xmm2, xmm0
	pand	xmm4, xmm10
	pxor	xmm5, xmm14
	pxor	xmm6, xmm7
	movaps	xmm8, xmm7

	punpckldq xmm2, xmm12
	pxor	xmm11, xmm5
	punpckldq xmm8, xmm6
	punpckhdq xmm7, xmm6
	movaps	xmm6, xmm5
	pxor	xmm4, xmm3
	punpckldq xmm6, xmm11
	movaps	xmm3, xmm1
	punpckhdq xmm0, xmm12
	movaps	xmm14, xmm2
	punpckhdq xmm5, xmm11
	paddd	xmm2, [.packed32zeromodp1]

	punpckldq xmm3, xmm15
	psubd	xmm2, xmm6
	pxor	xmm13, xmm9
	paddd	xmm14, xmm6
	movaps	xmm11, xmm14
	movaps	xmm14, xmm0
	paddd	xmm0, [.packed32zeromodp1]
	
	psubd	xmm0, xmm5
	punpckhdq xmm1, xmm15
	pxor	xmm10, xmm4
	paddd	xmm14, xmm5
	punpckldq xmm9, xmm13
	movaps	xmm13, xmm3
	paddd	xmm3, [.packed32zeromodp0]

	psubd	xmm3, xmm8
	movaps	xmm5, xmm3
	punpckldq xmm4, xmm10
	movaps	xmm10, xmm1
	paddd	xmm1, [.packed32zeromodp1]

	punpcklqdq xmm5, xmm2
	psubd	xmm1, xmm7
	paddd	xmm13, xmm8
	punpckhqdq xmm3, xmm2
	movaps	xmm2, xmm1
	paddd	xmm10, xmm7
	movaps	xmm15, xmm9
	paddd	xmm9, [.packed32zeromodp1]

	psubd	xmm9, xmm4
	punpcklqdq xmm2, xmm0
	punpckhqdq xmm1, xmm0
	paddd	xmm15, xmm4
	movaps	[rsp+0x60], xmm14
	movaps	xmm6, xmm2
	movaps	xmm2, xmm5
	pshufd	xmm14, xmm10, 0xfa
	movaps	[rsp+0x70], xmm15
	psrld	xmm2, 0x1a
	movaps	xmm4, xmm2
	movaps	xmm2, xmm6
	pshufd	xmm15, xmm10, 0x50
	paddd	xmm4, xmm3
	movaps	xmm0, xmm4
	pand	xmm5, [.packedmask26262626]
	
	psrld	xmm2, 0x1a
	paddd	xmm2, xmm1
	movaps	xmm1, xmm2
	psrld	xmm0, 0x19
	pand	xmm4, [.packedmask25252525]

	psrld	xmm1, 0x19
	movaps	xmm3, xmm1
	pslldq	xmm1, 0x8
	pand	xmm6, [.packedmask26262626]

	paddd	xmm5, xmm1
	psrldq	xmm3, 0x8
	paddd	xmm3, xmm9
	movaps	xmm8, xmm3
	movaps	xmm3, xmm5
	pand	xmm2, [.packedmask25252525]

	movaps	[rsp+0x140], xmm10
	movaps	[rsp+0x130], xmm13
	punpcklqdq xmm3, xmm4
	paddd	xmm0, xmm6
	pshufd	xmm12, xmm13, 0xfa
	movaps	xmm7, xmm3
	movaps	xmm3, xmm0
	pshufd	xmm9, xmm11, 0x50
	movaps	[rsp+0x150], xmm11
	movaps	[rsp+0x170], xmm7
	punpcklqdq xmm3, xmm2

	pshufd	xmm11, xmm11, 0xfa
	movaps	xmm1, xmm3
	movaps	xmm3, xmm5
	punpckhqdq xmm3, xmm4
	movaps	xmm6, [rsp+0x60]
	movaps	xmm4, [rsp+0x70]
	movaps	xmm5, xmm3
	movaps	xmm3, xmm0
	pshufd	xmm0, xmm6, 0x50
	pshufd	xmm6, xmm6, 0xfa
	punpckhqdq xmm3, xmm2
	pshufd	xmm2, xmm4, 0x50
	pshufd	xmm4, xmm4, 0xfa
	movaps	[rsp+0x190], xmm5
	movaps	[rsp+0x80], xmm3
	movaps	[rsp+0xa0], xmm6
	pshufd	xmm6, xmm5, 0x5
	movaps	[rsp+0x90], xmm0
	movaps	xmm0, xmm1
	movaps	xmm10, xmm6
	pshufd	xmm6, [rsp+0x190], 0xaf
	movaps	[rsp+0x1a0], xmm4
	movaps	[rsp+0x180], xmm0

	pshufd	xmm4, xmm7, 0x5
	pshufd	xmm3, xmm13, 0x50
	movaps	[rsp+0xd0], xmm2
	pshufd	xmm13, [rsp+0x80], 0xaf
	pshufd	xmm2, [rsp+0x170], 0xaf
	pshufd	xmm0, [rsp+0x180], 0xaf
	movaps	xmm5, [rsp+0x80]

	pshufd	xmm1, xmm1, 0x5
	pshufd	xmm7, xmm5, 0x5
	pshufd	xmm5, xmm8, 0x5
	movaps	[rsp], xmm6
	movaps	[rsp+0x20], xmm7
	movaps	xmm7, xmm15
	movaps	[rsp+0x40], xmm5
	movaps	[rsp+0x160], xmm8
	movaps	xmm5, xmm3
	pmuludq	xmm7, xmm4
	pshufd	xmm8, xmm8, 0xaf
	pmuludq	xmm5, xmm4
	movaps	[rsp+0xe0], xmm5
	movaps	[rsp+0x30], xmm8
	movaps	xmm5, xmm12
	movaps	xmm8, xmm3
	pmuludq	xmm5, xmm4
	movaps	[rsp+0x10], xmm10
	pmuludq	xmm8, xmm2
	paddq	xmm5, xmm8
	movaps	xmm8, xmm12
	movaps	[rsp+0xf0], xmm5

	pslld	xmm8, 1
	movaps	xmm5, xmm8
	movaps	xmm6, xmm8
	movaps	xmm8, xmm3
	pmuludq	xmm6, xmm2
	pmuludq	xmm8, xmm1
	paddq	xmm6, xmm7
	movaps	xmm7, xmm15
	paddq	xmm6, xmm8
	movaps	[rsp+0x100], xmm6
	
	movaps	xmm6, xmm14
	pmuludq	xmm7, xmm2
	movaps	xmm8, xmm3
	pmuludq	xmm6, xmm4
	paddq	xmm7, xmm6
	movaps	xmm6, xmm12
	pmuludq	xmm8, xmm0
	pmuludq	xmm6, xmm1
	paddq	xmm6, xmm7
	movaps	xmm7, xmm6
	paddq	xmm7, xmm8
	movaps	xmm8, xmm14
	movaps	[rsp+0x210], xmm7
	
	pslld	xmm8, 1
	movaps	xmm6, xmm8
	movaps	xmm8, xmm9
	movaps	xmm7, xmm6
	pmuludq	xmm8, xmm4
	pmuludq	xmm7, xmm2
	paddq	xmm7, xmm8
	movaps	xmm8, xmm15
	pmuludq	xmm8, xmm1
	paddq	xmm8, xmm7
	movaps	xmm7, xmm5
	pmuludq	xmm7, xmm0
	paddq	xmm7, xmm8
	movaps	xmm8, xmm10
	pmuludq	xmm8, xmm3
	paddq	xmm7, xmm8
	movaps	xmm8, xmm9
	movaps	[rsp+0x1e0], xmm7
	
	movaps	xmm7, xmm11
	pmuludq	xmm8, xmm2
	pmuludq	xmm7, xmm4
	paddq	xmm8, xmm7
	movaps	xmm7, xmm14
	pmuludq	xmm7, xmm1
	paddq	xmm7, xmm8
	movaps	xmm8, xmm15
	pmuludq	xmm8, xmm0
	paddq	xmm8, xmm7
	movaps	xmm7, xmm10
	pmuludq	xmm7, xmm12
	paddq	xmm7, xmm8
	movaps	xmm8, [rsp]
	movaps	xmm10, xmm7
	pmuludq	xmm8, xmm3
	paddq	xmm10, xmm8
	movaps	xmm8, xmm11
	movaps	[rsp+0x1f0], xmm10
	
	pslld	xmm8, 1
	movaps	xmm10, xmm8
	movaps	xmm7, xmm10
	pmuludq	xmm10, xmm0
	movaps	xmm8, [rsp+0x90]
	
	pmuludq	xmm7, xmm2
	pmuludq	xmm8, xmm4
	paddq	xmm7, xmm8
	movaps	xmm8, xmm9
	pmuludq	xmm8, xmm1
	paddq	xmm8, xmm7
	movaps	xmm7, xmm6
	pmuludq	xmm7, xmm0
	paddq	xmm7, xmm8
	movaps	xmm8, [rsp+0x10]
	pmuludq	xmm8, xmm15
	paddq	xmm8, xmm7
	movaps	xmm7, [rsp]
	pmuludq	xmm7, xmm5
	paddq	xmm7, xmm8
	movaps	xmm8, [rsp+0x20]
	pmuludq	xmm5, xmm13
	pmuludq	xmm8, xmm3
	paddq	xmm7, xmm8
	movaps	xmm8, [rsp+0x90]
	
	movaps	[rsp+0x200], xmm7
	movaps	xmm7, [rsp+0xa0]
	
	pmuludq	xmm8, xmm2
	
	pmuludq	xmm7, xmm4
	paddq	xmm8, xmm7
	movaps	xmm7, xmm11
	pmuludq	xmm7, xmm1
	paddq	xmm7, xmm8
	movaps	xmm8, xmm9
	pmuludq	xmm8, xmm0
	paddq	xmm8, xmm7
	movaps	xmm7, [rsp+0x10]
	pmuludq	xmm7, xmm14
	paddq	xmm7, xmm8
	movaps	xmm8, [rsp]
	pmuludq	xmm8, xmm15
	paddq	xmm8, xmm7
	movaps	xmm7, [rsp+0x20]
	pmuludq	xmm7, xmm12
	paddq	xmm7, xmm8
	movaps	xmm8, xmm3
	pmuludq	xmm8, xmm13
	paddq	xmm7, xmm8
	movaps	[rsp+0x220], xmm7
	
	movaps	xmm7, [rsp+0xa0]
	
	pslld	xmm7, 1
	movaps	xmm8, xmm7
	movaps	xmm7, [rsp+0xd0]
	
	pmuludq	xmm8, xmm2
	pmuludq	xmm7, xmm4
	paddq	xmm8, xmm7
	movaps	xmm7, [rsp+0x90]
	
	pmuludq	xmm4, [rsp+0x1a0]
	
	pmuludq	xmm7, xmm1
	paddq	xmm7, xmm8
	movaps	xmm8, [rsp+0x10]
	paddq	xmm10, xmm7
	movaps	xmm7, xmm8
	pmuludq	xmm7, xmm9
	paddq	xmm7, xmm10
	movaps	xmm10, [rsp]
	pmuludq	xmm6, xmm10
	paddq	xmm6, xmm7
	movaps	xmm7, [rsp+0x20]
	pmuludq	xmm7, xmm15
	paddq	xmm7, xmm6
	movaps	xmm6, [rsp+0x40]
	paddq	xmm5, xmm7
	movaps	xmm7, xmm6
	pmuludq	xmm7, xmm3
	paddq	xmm5, xmm7
	movaps	[rsp+0x230], xmm5
	
	movaps	xmm5, [rsp+0xd0]
	movaps	xmm7, [rsp+0x90]
	
	pmuludq	xmm5, xmm2
	paddq	xmm5, xmm4
	movaps	xmm4, [rsp+0xa0]
	
	pmuludq	xmm4, xmm1
	paddq	xmm4, xmm5
	movaps	xmm5, xmm7
	pmuludq	xmm5, xmm0
	paddq	xmm5, xmm4
	movaps	xmm4, xmm8
	pmuludq	xmm4, xmm11
	paddq	xmm4, xmm5
	movaps	xmm5, xmm10
	pmuludq	xmm5, xmm9
	paddq	xmm5, xmm4
	movaps	xmm4, [rsp+0x20]
	pmuludq	xmm4, xmm14
	paddq	xmm4, xmm5
	movaps	xmm5, xmm15
	pmuludq	xmm5, xmm13
	paddq	xmm5, xmm4
	movaps	xmm4, xmm6
	movaps	xmm6, xmm3
	pmuludq	xmm4, xmm12
	paddq	xmm4, xmm5
	pmuludq	xmm6, [rsp+0x30]
	paddq	xmm4, xmm6
	movaps	[rsp+0x240], xmm4
	
	pmuludq	xmm14, [.packednineteen]
	pmuludq	xmm15, [.packednineteen]
	pmuludq	xmm12, [.packednineteen]
	movaps	xmm3, xmm14
	movaps	xmm4, xmm7
	pslld	xmm12, 1
	pslld	xmm3, 1

	pmuludq	xmm9, [.packednineteen]
	pmuludq	xmm4, [.packednineteen]
	movaps	[rsp+0x1b0], xmm3
	
	movaps	xmm3, xmm11
	pmuludq	xmm12, [rsp+0x30]
	pmuludq	xmm14, [rsp+0x40]
	pmuludq	xmm3, [.packednineteen]
	movaps	xmm11, [rsp+0xa0]
	movaps	xmm6, [rsp+0x1a0]
	movaps	xmm10, xmm3
	pslld	xmm3, 1
	
	pmuludq	xmm11, [.packednineteen]
	pmuludq	xmm6, [.packednineteen]
	movaps	xmm8, xmm11
	movaps	[rsp+0x90], xmm3
	pslld	xmm11, 1
	movaps	xmm7, xmm11
	movaps	xmm11, xmm6
	
	pslld	xmm11, 1
	movaps	xmm5, xmm11
	pmuludq	xmm2, xmm5
	movaps	xmm11, [rsp+0x40]
	pmuludq	xmm11, xmm15
	paddq	xmm11, xmm12
	movaps	xmm12, [rsp+0x1b0]
	
	pmuludq	xmm15, [rsp+0x30]
	paddq	xmm14, xmm15
	movaps	xmm15, xmm9
	pmuludq	xmm12, xmm13
	paddq	xmm12, xmm11
	movaps	xmm11, [rsp+0x20]
	pmuludq	xmm15, xmm13
	pmuludq	xmm11, xmm9
	paddq	xmm11, xmm12

	movaps	xmm12, [rsp+0x90]
	pmuludq	xmm12, [rsp]
	paddq	xmm12, xmm11

	movaps	xmm11, [rsp+0x10]
	movaps	xmm3, [rsp+0xd0]
	
	pmuludq	xmm11, xmm4
	paddq	xmm11, xmm12
	movaps	xmm12, xmm7
	pmuludq	xmm3, [.packednineteen]
	pmuludq	xmm12, xmm0
	paddq	xmm12, xmm11
	movaps	xmm11, xmm3
	pmuludq	xmm11, xmm1
	paddq	xmm11, xmm12
	paddq	xmm2, xmm11
	paddq	xmm2, [rsp+0xe0]
	
	pmuludq	xmm1, xmm6

	movaps	[rsp+0xe0], xmm2
	movaps	xmm2, xmm15
	paddq	xmm2, xmm14
	movaps	xmm15, [rsp+0x20]
	movaps	xmm12, [rsp]
	movaps	xmm14, [rsp+0x10]
	movaps	xmm11, xmm15
	pmuludq	xmm11, xmm10
	paddq	xmm11, xmm2
	movaps	xmm2, xmm12

	pmuludq	xmm2, xmm4
	paddq	xmm2, xmm11
	movaps	xmm11, xmm14
	pmuludq	xmm11, xmm8
	paddq	xmm11, xmm2
	movaps	xmm2, xmm3
	pmuludq	xmm2, xmm0
	paddq	xmm2, xmm11
	movaps	xmm11, [rsp+0x40]
	paddq	xmm1, xmm2
	paddq	xmm1, [rsp+0xf0]
	
	pmuludq	xmm0, xmm5
	movaps	[rsp+0xf0], xmm1
	
	pmuludq	xmm10, xmm11
	movaps	xmm1, [rsp+0x1b0]
	
	pmuludq	xmm1, [rsp+0x30]
	movaps	xmm2, xmm1
	movaps	xmm1, xmm11
	pmuludq	xmm1, xmm9
	paddq	xmm1, xmm2
	movaps	xmm2, [rsp+0x90]
	
	pmuludq	xmm2, xmm13
	paddq	xmm2, xmm1
	movaps	xmm1, xmm15
	pmuludq	xmm1, xmm4
	paddq	xmm1, xmm2
	movaps	xmm2, xmm12
	pmuludq	xmm2, xmm7
	paddq	xmm2, xmm1
	movaps	xmm1, xmm14
	pmuludq	xmm1, xmm3
	paddq	xmm1, xmm2
	paddq	xmm0, xmm1
	movaps	xmm1, xmm4
	paddq	xmm0, [rsp+0x100]
	
	pmuludq	xmm9, [rsp+0x30]
	movaps	[rsp+0x100], xmm0
	
	paddq	xmm10, xmm9
	pmuludq	xmm1, xmm13
	movaps	xmm9, xmm12
	movaps	xmm0, xmm1
	movaps	xmm1, xmm15
	pmuludq	xmm9, xmm3
	movaps	xmm2, xmm12
	paddq	xmm0, xmm10
	pmuludq	xmm1, xmm8
	paddq	xmm1, xmm0
	movaps	xmm0, xmm9
	pmuludq	xmm8, xmm11
	movaps	xmm9, xmm11
	movaps	xmm12, [rsp+0x30]
	paddq	xmm0, xmm1
	movaps	xmm1, xmm14
	pmuludq	xmm9, xmm4
	movaps	xmm10, xmm15
	pmuludq	xmm4, xmm12
	pmuludq	xmm1, xmm6
	paddq	xmm1, xmm0
	movaps	xmm0, xmm9
	paddq	xmm1, [rsp+0x210]
	
	movaps	xmm14, xmm1
	movaps	xmm1, [rsp+0x90]
	
	movaps	xmm9, xmm15
	paddq	xmm8, xmm4
	pmuludq	xmm1, xmm12
	pmuludq	xmm9, xmm3
	movaps	xmm4, xmm12
	paddq	xmm0, xmm1
	movaps	xmm1, xmm7
	pmuludq	xmm7, xmm12
	pmuludq	xmm1, xmm13
	movaps	xmm12, [rsp+0x200]
	paddq	xmm1, xmm0
	movaps	xmm0, xmm9
	movaps	xmm9, [rsp+0x1f0]
	
	paddq	xmm0, xmm1
	movaps	xmm1, xmm2
	movaps	xmm2, xmm11
	
	pmuludq	xmm1, xmm5
	paddq	xmm1, xmm0
	paddq	xmm1, [rsp+0x1e0]
	
	movaps	xmm15, xmm1
	movaps	xmm1, xmm3
	pmuludq	xmm1, xmm13
	movaps	xmm0, xmm1
	movaps	xmm1, xmm10
	paddq	xmm0, xmm8
	pmuludq	xmm1, xmm6
	paddq	xmm1, xmm0
	paddq	xmm9, xmm1
	movaps	xmm1, xmm11
	pmuludq	xmm6, xmm2
	pmuludq	xmm1, xmm3
	movaps	xmm0, xmm1
	pmuludq	xmm3, xmm4
	movaps	xmm1, xmm13
	paddq	xmm6, xmm3
	paddq	xmm0, xmm7
	paddq	xmm6, [rsp+0x220]
	pmuludq	xmm1, xmm5
	movaps	xmm7, xmm6
	paddq	xmm1, xmm0
	paddq	xmm12, xmm1
	pmuludq	xmm5, xmm4
	movaps	xmm11, xmm12
	movaps	xmm12, [rsp+0x230]
	
	paddq	xmm12, xmm5
	movaps	xmm4, [rsp+0xe0]
	movaps	xmm10, xmm12
	movaps	xmm12, xmm15
	
	psrlq	xmm12, 0x1a
	movaps	xmm0, xmm12
	movaps	xmm12, [.packedmask26]
	movaps	xmm1, xmm4
	pand	xmm4, xmm12
	psrlq	xmm1, 0x1a
	paddq	xmm1, [rsp+0xf0]
	
	pand	xmm12, xmm15
	movaps	xmm15, xmm1
	pand	xmm1, [.packedmask25]
	movaps	xmm2, xmm12
	psrlq	xmm15, 0x19
	movaps	xmm12, xmm0
	movaps	xmm5, xmm15
	movaps	xmm15, [.packedmask25]
	paddq	xmm12, xmm9
	movaps	xmm3, xmm12
	pand	xmm15, xmm12
	movaps	xmm12, [rsp+0x100]
	
	psrlq	xmm3, 0x19
	paddq	xmm3, xmm11
	paddq	xmm12, xmm5
	movaps	xmm0, xmm15
	movaps	xmm6, xmm12
	movaps	xmm15, xmm3
	psrlq	xmm3, 0x1a
	movaps	xmm9, xmm12
	psrlq	xmm6, 0x1a
	paddq	xmm6, xmm14
	pand	xmm15, [.packedmask26]
	movaps	xmm12, xmm6
	paddq	xmm3, xmm7
	movaps	xmm11, xmm3
	psrlq	xmm12, 0x19
	movaps	xmm7, xmm12
	movaps	xmm12, [.packedmask25]
	pand	xmm9, [.packedmask26]
	paddq	xmm2, xmm7
	movaps	xmm5, xmm15
	movaps	xmm15, xmm6
	movaps	xmm6, xmm3
	pand	xmm12, xmm15
	psrlq	xmm6, 0x19
	paddq	xmm6, xmm10
	movaps	xmm15, xmm6
	movaps	xmm3, xmm12
	psrlq	xmm15, 0x1a
	movaps	xmm12, [.packedmask25]
	movaps	xmm7, xmm15
	pand	xmm12, xmm11
	movaps	xmm15, [.packedmask26]
	pand	xmm15, xmm6
	movaps	xmm8, xmm12
	movaps	xmm12, [rsp+0x240]
	
	movaps	xmm6, xmm15
	paddq	xmm12, xmm7
	movaps	xmm15, xmm12
	psrlq	xmm15, 0x19
	movaps	xmm7, xmm15
	movaps	xmm15, [.packedmask25]
	pmuludq	xmm7, [.packednineteen]
	paddq	xmm4, xmm7
	movaps	xmm11, xmm4
	pand	xmm4, [.packedmask26]
	psrlq	xmm11, 0x1a
	paddq	xmm1, xmm11
	pand	xmm15, xmm12
	movaps	xmm12, xmm2
	pand	xmm2, [.packedmask26]
	psrlq	xmm12, 0x1a
	paddq	xmm0, xmm12
	movaps	xmm12, xmm4
	punpckhqdq xmm4, xmm1
	movaps	xmm10, xmm15
	punpcklqdq xmm12, xmm1
	movaps	xmm1, xmm9
	movaps	xmm15, xmm5
	movaps	xmm7, xmm4
	punpcklqdq xmm1, xmm3
	movaps	xmm4, xmm12
	paddd	xmm12, [.packed32zeromodp0]
	punpcklqdq xmm15, xmm8
	psubd	xmm12, xmm7
	paddd	xmm4, xmm7
	movaps	xmm11, xmm1
	movaps	xmm1, xmm9
	movaps	xmm9, xmm2
	punpckhqdq xmm2, xmm0
	punpcklqdq xmm9, xmm0
	movaps	xmm0, xmm15
	movaps	xmm15, xmm5
	punpckhqdq xmm1, xmm3
	movaps	xmm3, xmm6
	punpckhqdq xmm15, xmm8
	punpcklqdq xmm3, xmm10
	punpckhqdq xmm6, xmm10
	movaps	xmm13, xmm15
	movaps	xmm15, xmm11
	paddd	xmm11, [.packed32zeromodp1]
	psubd	xmm11, xmm1
	paddd	xmm15, xmm1
	movaps	xmm1, xmm12
	movaps	xmm5, xmm15
	movaps	xmm15, xmm9
	paddd	xmm9, [.packed32zeromodp1]
	psubd	xmm9, xmm2
	punpcklqdq xmm1, xmm9
	paddd	xmm15, xmm2
	movaps	xmm10, xmm15
	movaps	xmm15, xmm0
	paddd	xmm0, [.packed32zeromodp1]
	psubd	xmm0, xmm13
	movaps	xmm14, xmm6
	movaps	xmm7, xmm1
	movaps	xmm1, xmm11
	paddd	xmm15, xmm13
	movaps	xmm6, xmm3
	paddd	xmm3, [.packed32zeromodp1]
	psubd	xmm3, xmm14
	punpcklqdq xmm1, xmm0
	movaps	xmm8, xmm15
	paddd	xmm6, xmm14
	punpckhqdq xmm12, xmm9
	punpckhqdq xmm11, xmm0
	movaps	xmm15, [.packedmask26262626]
	movaps	xmm14, xmm1
	movaps	xmm1, xmm7
	pand	xmm15, xmm7
	movaps	xmm9, [.packedmask25252525]
	psrld	xmm1, 0x1a
	movaps	xmm2, xmm1
	movaps	xmm1, xmm14
	pand	xmm14, [.packedmask26262626]
	paddd	xmm2, xmm12
	movaps	xmm12, xmm2
	psrld	xmm1, 0x1a
	paddd	xmm1, xmm11
	pand	xmm9, xmm2
	movaps	xmm13, xmm6
	psrld	xmm12, 0x19
	movaps	xmm0, xmm12
	movaps	xmm12, xmm1
	pand	xmm1, [.packedmask25252525]
	paddd	xmm0, xmm14
	movaps	xmm11, xmm0
	psrld	xmm12, 0x19
	movaps	xmm7, xmm12
	psrldq	xmm12, 0x8
	paddd	xmm3, xmm12
	punpcklqdq xmm13, xmm3
	movaps	xmm12, xmm7
	punpcklqdq xmm11, xmm1
	pslldq	xmm12, 0x8
	movaps	xmm2, xmm12
	paddd	xmm2, xmm15
	movaps	xmm12, xmm2
	punpckhqdq xmm2, xmm9
	movaps	xmm15, xmm8
	punpcklqdq xmm12, xmm9
	movaps	xmm9, xmm0
	punpckhqdq xmm9, xmm1
	movaps	xmm1, xmm4
	punpckhqdq xmm4, xmm12
	punpcklqdq xmm1, xmm12
	movaps	xmm12, xmm5
	punpckhqdq xmm5, xmm11
	punpcklqdq xmm15, xmm9
	punpcklqdq xmm12, xmm11
	movaps	xmm11, xmm8
	punpckhqdq xmm11, xmm9
	movaps	xmm7, xmm12
	movaps	xmm12, xmm10
	movaps	xmm9, xmm6
	punpcklqdq xmm12, xmm2
	punpckhqdq xmm10, xmm2
	movaps	xmm2, xmm15
	punpckhqdq xmm9, xmm3
	movaps	xmm0, xmm12
	movaps	xmm12, xmm1
	movaps	xmm3, xmm4
	pmuludq	xmm12, xmm1
	pslld	xmm1, 1
	movaps	xmm15, xmm1
	movaps	xmm6, xmm1
	pslld	xmm3, 1
	pmuludq	xmm15, xmm4
	pmuludq	xmm4, xmm3
	movaps	[rsp], xmm9
	pmuludq	xmm6, xmm7
	paddq	xmm4, xmm6
	movaps	xmm6, xmm1
	movaps	[rsp+0x1a0], xmm4
	
	pmuludq	xmm6, xmm5
	movaps	xmm4, xmm3
	movaps	xmm8, xmm6
	movaps	xmm9, xmm7
	pmuludq	xmm4, xmm7
	movaps	xmm6, xmm3
	paddq	xmm8, xmm4
	movaps	xmm4, xmm5
	pmuludq	xmm9, xmm7
	pslld	xmm7, 1
	movaps	[rsp+0x20], xmm12
	pslld	xmm4, 1
	pmuludq	xmm6, xmm4
	paddq	xmm6, xmm9
	movaps	xmm9, xmm1
	movaps	[rsp+0x30], xmm15
	pmuludq	xmm9, xmm0
	paddq	xmm6, xmm9
	movaps	xmm9, xmm7
	movaps	[rsp+0xf0], xmm6
	
	movaps	xmm6, xmm3
	pmuludq	xmm9, xmm5
	pmuludq	xmm5, xmm4
	movaps	xmm12, xmm10
	movaps	xmm15, xmm1
	pmuludq	xmm6, xmm0
	paddq	xmm6, xmm9
	movaps	xmm9, xmm1
	pslld	xmm12, 1
	pmuludq	xmm15, xmm2
	movaps	[rsp+0x40], xmm13
	pmuludq	xmm9, xmm10
	paddq	xmm6, xmm9
	movaps	xmm9, xmm7
	movaps	[rsp+0x100], xmm6
	
	pmuludq	xmm9, xmm0
	paddq	xmm9, xmm5
	movaps	xmm5, xmm3
	movaps	xmm6, xmm12
	pmuludq	xmm5, xmm12
	movaps	xmm12, xmm1
	paddq	xmm5, xmm9
	movaps	xmm9, xmm7
	paddq	xmm15, xmm5
	movaps	xmm5, xmm4
	pmuludq	xmm12, xmm11
	movaps	xmm14, xmm12
	pmuludq	xmm5, xmm0
	pmuludq	xmm9, xmm10
	paddq	xmm9, xmm5
	movaps	xmm5, xmm3
	movaps	xmm12, xmm11
	pmuludq	xmm5, xmm2
	paddq	xmm5, xmm9
	movaps	xmm9, xmm0
	paddq	xmm14, xmm5
	movaps	xmm5, xmm4
	pslld	xmm12, 1
	pmuludq	xmm9, xmm0
	movaps	[rsp+0xa0], xmm12
	
	pmuludq	xmm5, xmm6
	paddq	xmm5, xmm9
	movaps	xmm9, xmm7
	pmuludq	xmm9, xmm2
	paddq	xmm9, xmm5
	movaps	xmm5, xmm12
	pmuludq	xmm5, xmm3
	paddq	xmm5, xmm9
	movaps	xmm9, xmm13
	pmuludq	xmm9, xmm1
	movaps	xmm12, xmm9
	movaps	xmm9, xmm0
	paddq	xmm12, xmm5
	movaps	xmm5, xmm4
	pmuludq	xmm9, xmm6
	pmuludq	xmm5, xmm2
	paddq	xmm5, xmm9
	movaps	xmm9, xmm7
	pmuludq	xmm9, xmm11
	paddq	xmm9, xmm5
	movaps	xmm5, xmm13
	pmuludq	xmm5, xmm3
	paddq	xmm5, xmm9
	movaps	xmm9, xmm1
	movaps	xmm1, [rsp]
	pmuludq	xmm9, xmm1
	paddq	xmm5, xmm9
	movaps	xmm9, xmm1
	movaps	[rsp+0x1b0], xmm5
	
	movaps	xmm5, xmm10
	pmuludq	xmm9, [.packedthirtyeight]
	movaps	xmm1, xmm9
	movaps	xmm9, xmm0
	pmuludq	xmm5, [.packedthirtyeight]
	movaps	[rsp+0xd0], xmm5
	
	movaps	xmm5, xmm2
	pslld	xmm9, 1
	pmuludq	xmm3, xmm1
	movaps	[rsp+0x90], xmm9
	
	pmuludq	xmm5, [.packednineteen]
	movaps	xmm13, xmm5
	movaps	xmm5, xmm11
	movaps	xmm9, xmm2
	pmuludq	xmm5, [.packedthirtyeight]
	movaps	[rsp+0x10], xmm5
	pslld	xmm9, 1
	movaps	[rsp+0xe0], xmm9
	
	movaps	xmm9, xmm10
	pmuludq	xmm9, [rsp+0xd0]
	
	movaps	xmm10, [rsp+0x90]
	
	pmuludq	xmm10, xmm13
	paddq	xmm10, xmm9
	movaps	xmm9, [rsp+0x10]
	pmuludq	xmm9, xmm4
	paddq	xmm10, xmm9
	movaps	[rsp+0xd0], xmm10
	
	movaps	xmm5, [rsp+0x40]
	movaps	xmm10, [rsp+0xd0]
	
	pmuludq	xmm5, [.packednineteen]
	movaps	xmm9, xmm5
	pmuludq	xmm9, xmm7
	paddq	xmm10, xmm9
	movaps	xmm9, xmm13
	paddq	xmm3, xmm10
	paddq	xmm3, [rsp+0x20]
	movaps	[rsp+0x20], xmm3
	pmuludq	xmm9, xmm6
	movaps	xmm3, xmm9
	psrld	xmm7, 1
	pmuludq	xmm7, xmm1
	movaps	xmm9, [rsp+0x10]
	pmuludq	xmm9, xmm0
	movaps	xmm10, xmm9
	pmuludq	xmm0, xmm1
	movaps	xmm9, xmm5
	paddq	xmm10, xmm3
	pmuludq	xmm9, xmm4
	movaps	xmm3, xmm9
	pmuludq	xmm4, xmm1
	movaps	xmm9, xmm13
	paddq	xmm3, xmm10
	movaps	xmm10, [rsp+0x10]
	paddq	xmm7, xmm3
	pmuludq	xmm9, xmm2
	paddq	xmm7, [rsp+0x30]
	movaps	[rsp+0x30], xmm7
	movaps	xmm7, xmm9
	movaps	xmm9, xmm10
	pmuludq	xmm9, xmm6
	movaps	xmm3, xmm9
	movaps	xmm9, [rsp+0x90]
	
	paddq	xmm3, xmm7
	pmuludq	xmm9, xmm5
	movaps	xmm13, xmm9
	movaps	xmm9, [rsp+0x1a0]
	
	paddq	xmm13, xmm3
	paddq	xmm4, xmm13
	paddq	xmm9, xmm4
	movaps	xmm7, xmm9
	movaps	xmm9, xmm10
	movaps	xmm13, [rsp+0x40]
	pmuludq	xmm9, xmm2
	movaps	xmm4, xmm9
	pmuludq	xmm2, xmm1
	movaps	xmm9, xmm5
	pmuludq	xmm9, xmm6
	movaps	xmm3, xmm9
	pmuludq	xmm6, xmm1
	movaps	xmm9, xmm10
	paddq	xmm3, xmm4
	movaps	xmm4, [rsp+0xa0]
	
	paddq	xmm0, xmm3
	pmuludq	xmm9, xmm11
	movaps	xmm3, xmm9
	paddq	xmm8, xmm0
	movaps	xmm9, [rsp+0xe0]
	
	movaps	xmm11, xmm4
	pmuludq	xmm9, xmm5
	movaps	xmm0, xmm9
	pmuludq	xmm11, xmm1
	movaps	xmm9, xmm4
	paddq	xmm0, xmm3
	movaps	xmm3, [rsp+0x20]
	paddq	xmm6, xmm0
	pmuludq	xmm9, xmm5
	paddq	xmm2, xmm9
	movaps	xmm9, xmm13
	paddq	xmm6, [rsp+0xf0]
	
	movaps	xmm4, xmm6
	pmuludq	xmm5, xmm13
	pmuludq	xmm9, xmm1
	pmuludq	xmm1, [rsp]
	paddq	xmm12, xmm1
	movaps	xmm1, xmm3
	psrlq	xmm4, 0x1a
	paddq	xmm2, [rsp+0x100]
	
	pand	xmm3, [.packedmask26]
	paddq	xmm11, xmm5
	paddq	xmm15, xmm11
	movaps	xmm11, [.packedmask26]
	psrlq	xmm1, 0x1a
	paddq	xmm1, [rsp+0x30]
	paddq	xmm14, xmm9
	pand	xmm11, xmm6
	movaps	xmm13, xmm3
	movaps	xmm3, xmm4
	paddq	xmm3, xmm2
	movaps	xmm4, xmm3
	movaps	xmm3, xmm1
	psrlq	xmm1, 0x19
	paddq	xmm1, xmm7
	movaps	xmm6, xmm4
	pand	xmm3, [.packedmask25]
	psrlq	xmm6, 0x19
	paddq	xmm15, xmm6
	movaps	xmm9, xmm15
	pand	xmm15, [.packedmask26]
	psrlq	xmm9, 0x1a
	paddq	xmm14, xmm9
	movaps	xmm6, [.packedmask25]
	movaps	xmm2, xmm3
	movaps	xmm3, [.packedmask25]
	movaps	xmm5, xmm15
	movaps	xmm15, xmm14
	pand	xmm3, xmm4
	psrlq	xmm15, 0x19
	movaps	xmm4, xmm1
	movaps	xmm0, xmm15
	psrlq	xmm1, 0x1a
	paddq	xmm8, xmm1
	movaps	xmm1, xmm8
	paddq	xmm12, xmm0
	pand	xmm4, [.packedmask26]
	psrlq	xmm1, 0x19
	paddq	xmm11, xmm1
	movaps	xmm1, xmm12
	pand	xmm12, [.packedmask26]
	psrlq	xmm1, 0x1a
	movaps	xmm0, xmm1
	movaps	xmm15, [.packedmask25]
	pand	xmm6, xmm8
	paddq	xmm0, [rsp+0x1b0]
	
	movaps	xmm1, xmm0
	movaps	xmm10, xmm0
	pand	xmm15, xmm14
	psrlq	xmm1, 0x19
	movaps	xmm0, xmm1
	movaps	xmm8, xmm12
	movaps	xmm12, xmm11
	pmuludq	xmm0, [.packednineteen]
	paddq	xmm13, xmm0
	movaps	xmm9, xmm13
	pand	xmm13, [.packedmask26]
	psrlq	xmm12, 0x1a
	paddq	xmm3, xmm12
	psrlq	xmm9, 0x1a
	movaps	xmm12, xmm4
	paddq	xmm2, xmm9
	pand	xmm11, [.packedmask26]
	movaps	xmm7, xmm15
	movaps	xmm1, [.packedmask25]
	punpckldq xmm12, xmm6
	movaps	xmm9, xmm13
	punpckhdq xmm4, xmm6
	punpckhdq xmm13, xmm2
	punpckldq xmm9, xmm2
	movaps	xmm0, xmm12
	pand	xmm1, xmm10
	punpcklqdq xmm13, xmm4
	movaps	xmm12, xmm9
	movaps	xmm9, xmm5
	punpckhdq xmm5, xmm7
	punpckldq xmm9, xmm15
	movaps	xmm15, xmm8
	punpcklqdq xmm12, xmm0
	pshufd	xmm6, xmm13, 0xfa
	movaps	xmm0, xmm9
	movaps	xmm9, xmm11
	punpckhdq xmm11, xmm3
	punpckldq xmm9, xmm3
	movaps	[rsp+0x1e0], xmm12
	
	punpcklqdq xmm11, xmm5
	pshufd	xmm5, xmm13, 0xd8
	punpckldq xmm15, xmm1
	movaps	xmm3, [rsp+0x260]
	
	punpcklqdq xmm9, xmm0
	punpckhdq xmm8, xmm1
	movaps	xmm0, [rsp+0xc0]
	
	movaps	xmm1, xmm3
	pshufd	xmm7, xmm11, 0xd8
	pmuludq	xmm0, xmm5
	pmuludq	xmm1, xmm6
	movaps	xmm2, xmm3
	paddq	xmm1, xmm0
	movaps	xmm0, [rsp+0xc0]
	
	movaps	xmm4, xmm3
	pmuludq	xmm2, xmm7
	pshufd	xmm12, xmm11, 0xa5
	movaps	[rsp+0x1f0], xmm9
	
	pmuludq	xmm0, xmm6
	paddq	xmm2, xmm0
	pshufd	xmm9, xmm11, 0xfa
	movaps	[rsp+0x210], xmm15
	
	pshufd	xmm14, xmm13, 0xa5
	psrldq	xmm13, 0xc
	movaps	[rsp+0x220], xmm15
	
	pmuludq	xmm4, xmm9
	movaps	xmm15, xmm3
	punpcklqdq xmm13, xmm11
	psrldq	xmm11, 0xc
	punpcklqdq xmm11, xmm8
	pmuludq	xmm15, xmm5
	movaps	xmm0, [rsp+0xc0]
	
	pshufd	xmm8, xmm8, 0xd8
	pmuludq	xmm0, xmm7
	paddq	xmm4, xmm0
	movaps	xmm0, xmm3
	movaps	xmm3, [rsp+0x120]
	
	pshufd	xmm10, xmm8, 0xfa
	pmuludq	xmm0, xmm8
	pmuludq	xmm3, xmm5
	paddq	xmm2, xmm3
	movaps	xmm3, [rsp+0x120]
	
	pmuludq	xmm3, xmm6
	paddq	xmm4, xmm3
	movaps	xmm3, [rsp+0xc0]
	
	pmuludq	xmm3, xmm9
	paddq	xmm0, xmm3
	movaps	xmm3, [rsp+0x1d0]
	
	pmuludq	xmm3, xmm5
	paddq	xmm4, xmm3
	movaps	xmm3, [rsp+0x120]
	
	pmuludq	xmm3, xmm7
	paddq	xmm0, xmm3
	movaps	xmm3, [rsp+0x1d0]
	
	pmuludq	xmm3, xmm6
	paddq	xmm0, xmm3
	movaps	xmm3, [rsp+0x270]
	
	pmuludq	xmm3, xmm5
	paddq	xmm0, xmm3
	movaps	xmm3, xmm4
	pslldq	xmm0, 0x8
	pslldq	xmm4, 0x8
	punpckhqdq xmm3, xmm0
	movaps	xmm0, xmm2
	pslldq	xmm2, 0x8
	punpckhqdq xmm0, xmm4
	movaps	xmm4, xmm0
	movaps	xmm0, xmm1
	pslldq	xmm1, 0x8
	punpckhqdq xmm0, xmm2
	movaps	xmm2, xmm0
	movaps	xmm0, xmm15
	pslldq	xmm15, 0x8
	punpckhqdq xmm0, xmm1
	movaps	xmm1, xmm0
	pxor	xmm0, xmm0
	punpckhqdq xmm0, xmm15
	movaps	xmm15, [rsp+0x50]
	pmuludq	xmm15, xmm5
	paddq	xmm0, xmm15
	movaps	xmm15, [rsp+0x50]
	pmuludq	xmm15, xmm6
	paddq	xmm1, xmm15
	movaps	xmm15, [rsp+0x50]
	pmuludq	xmm15, xmm7
	paddq	xmm2, xmm15
	movaps	xmm15, [rsp+0x50]
	pmuludq	xmm15, xmm9
	paddq	xmm4, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	pmuludq	xmm15, xmm5
	paddq	xmm1, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	pmuludq	xmm15, xmm6
	paddq	xmm2, xmm15
	movaps	xmm15, [rsp+0x110]
	
	pmuludq	xmm15, xmm6
	paddq	xmm4, xmm15
	movaps	xmm15, [rsp+0x50]
	pmuludq	xmm15, xmm8
	paddq	xmm3, xmm15
	movaps	xmm15, [rsp+0x110]
	
	pmuludq	xmm15, xmm5
	paddq	xmm2, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	pmuludq	xmm15, xmm7
	paddq	xmm4, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	pmuludq	xmm15, xmm9
	paddq	xmm3, xmm15
	movaps	xmm15, [rsp+0x1c0]
	
	pmuludq	xmm15, xmm5
	paddq	xmm4, xmm15
	movaps	xmm15, [rsp+0x110]
	
	pmuludq	xmm5, [rsp+0x250]
	
	pmuludq	xmm15, xmm7
	paddq	xmm3, xmm15
	movaps	xmm15, [rsp+0x1c0]
	
	pmuludq	xmm15, xmm6
	paddq	xmm3, xmm15
	movaps	xmm15, [rsp+0x280]
	
	paddq	xmm3, xmm5
	movaps	xmm5, xmm15
	pmuludq	xmm14, xmm15
	paddq	xmm0, xmm14
	movaps	xmm14, [rsp+0x290]
	
	pmuludq	xmm5, xmm13
	paddq	xmm1, xmm5
	movaps	xmm5, xmm15
	pmuludq	xmm13, xmm14
	paddq	xmm0, xmm13
	pmuludq	xmm5, xmm12
	paddq	xmm2, xmm5
	movaps	xmm5, xmm15
	pmuludq	xmm5, xmm11
	paddq	xmm4, xmm5
	movaps	xmm5, xmm14
	pmuludq	xmm5, xmm12
	paddq	xmm1, xmm5
	movaps	xmm5, xmm14
	pmuludq	xmm5, xmm11
	paddq	xmm2, xmm5
	movaps	xmm5, xmm14
	movaps	xmm14, [rsp+0x2a0]
	
	pmuludq	xmm5, xmm10
	paddq	xmm4, xmm5
	pmuludq	xmm12, xmm14
	paddq	xmm0, xmm12
	movaps	xmm12, xmm14
	movaps	xmm5, [rsp+0x2c0]
	
	pmuludq	xmm12, xmm11
	paddq	xmm1, xmm12
	movaps	xmm12, xmm14
	movaps	xmm14, [rsp+0x2b0]
	
	pmuludq	xmm11, xmm5
	paddq	xmm0, xmm11
	pmuludq	xmm12, xmm10
	paddq	xmm2, xmm12
	movaps	xmm12, xmm14
	pmuludq	xmm6, xmm14
	paddq	xmm0, xmm6
	movaps	xmm11, [rsp+0x2d0]
	
	pmuludq	xmm12, xmm8
	paddq	xmm4, xmm12
	movaps	xmm12, xmm5
	movaps	xmm6, [rsp+0x2e0]
	
	pmuludq	xmm12, xmm10
	paddq	xmm1, xmm12
	movaps	xmm12, xmm11
	pmuludq	xmm12, xmm8
	paddq	xmm2, xmm12
	movaps	xmm12, xmm15
	pmuludq	xmm12, xmm10
	paddq	xmm3, xmm12
	movaps	xmm12, xmm14
	pmuludq	xmm10, [rsp+0x300]
	
	pmuludq	xmm12, xmm7
	paddq	xmm1, xmm12
	movaps	xmm12, xmm14
	pmuludq	xmm7, xmm11
	paddq	xmm0, xmm7
	pmuludq	xmm12, xmm9
	paddq	xmm2, xmm12
	movaps	xmm12, xmm11
	pmuludq	xmm12, xmm9
	pmuludq	xmm9, xmm6
	paddq	xmm0, xmm9
	movaps	xmm9, xmm6
	paddq	xmm1, xmm12
	pmuludq	xmm9, xmm8
	pmuludq	xmm8, [rsp+0x2f0]
	
	paddq	xmm0, xmm8
	paddq	xmm0, xmm10
	movaps	xmm5, xmm0
	paddq	xmm1, xmm9
	movaps	xmm6, xmm1
	punpckhqdq xmm1, xmm4
	punpcklqdq xmm5, xmm2
	punpcklqdq xmm6, xmm4
	punpckhqdq xmm0, xmm2
	movaps	xmm2, xmm3
	movaps	xmm4, xmm5
	punpcklqdq xmm2, xmm3
	psrlq	xmm4, 0x1a
	movaps	xmm7, xmm4
	movaps	xmm4, xmm6
	pand	xmm6, [.packedmask26]
	paddq	xmm0, xmm7
	psrlq	xmm4, 0x1a
	paddq	xmm1, xmm4
	movaps	xmm4, xmm0
	punpckhqdq xmm3, xmm3
	psrlq	xmm4, 0x19
	movaps	xmm7, xmm4
	movaps	xmm4, xmm1
	pand	xmm5, [.packedmask26]
	paddq	xmm6, xmm7
	psrlq	xmm4, 0x19
	paddq	xmm2, xmm4
	movaps	xmm7, xmm2
	pslldq	xmm4, 0x8
	pand	xmm1, [.packedmask25]
	psrlq	xmm7, 0x1a
	paddq	xmm3, xmm7
	movaps	xmm7, xmm3
	pand	xmm0, [.packedmask25]
	psrlq	xmm7, 0x19
	pmuludq	xmm7, [.packednineteen]
	punpckhqdq xmm7, xmm4
	pand	xmm3, [.packedmask25]
	paddq	xmm5, xmm7
	movaps	xmm4, xmm5
	pand	xmm5, [.packedmask26]
	psrlq	xmm4, 0x1a
	movaps	xmm7, xmm4
	movaps	xmm4, xmm6
	pand	xmm6, [.packedmask26]
	paddq	xmm0, xmm7
	psrlq	xmm4, 0x1a
	paddq	xmm1, xmm4
	pand	xmm2, [.packedmask26]
	movaps	xmm4, xmm5
	punpckhdq xmm5, xmm0
	punpckldq xmm4, xmm0
	movaps	xmm0, xmm6
	punpckhdq xmm6, xmm1
	punpckldq xmm0, xmm1
	movaps	xmm1, xmm5
	punpckhdq xmm2, xmm3
	punpcklqdq xmm1, xmm6
	punpcklqdq xmm4, xmm0
	movaps	[rsp+0x200], xmm4
	
	movaps	[rsp+0x1a0], xmm1
	
	movaps	[rsp+0x1b0], xmm2
	
	movaps	xmm13, [rsp+0x130]
	
	movaps	xmm7, [rsp+0x170]
	
	movaps	xmm1, xmm13
	movaps	xmm10, [rsp+0x140]
	
	punpcklqdq xmm1, xmm7
	movaps	xmm0, [rsp+0x180]
	
	movaps	xmm4, xmm1
	movaps	xmm1, xmm13
	movaps	xmm14, [rsp+0x150]
	
	punpckhqdq xmm1, xmm7
	movaps	xmm7, xmm10
	movaps	xmm11, [rsp+0x80]
	
	movaps	xmm5, xmm1
	movaps	xmm1, xmm10
	punpcklqdq xmm7, xmm0
	movaps	xmm10, xmm14
	punpckhqdq xmm1, xmm0
	movaps	xmm0, xmm14
	movaps	xmm14, [rsp+0x60]
	movaps	xmm9, xmm7
	movaps	xmm3, xmm14
	movaps	xmm13, [rsp+0x70]
	pmuludq	xmm9, xmm7
	punpckhqdq xmm3, xmm11
	movaps	xmm2, [rsp+0x190]
	
	movaps	xmm12, xmm3
	movaps	xmm8, [rsp+0x160]
	
	movaps	xmm3, xmm13
	punpcklqdq xmm0, xmm2
	punpckhqdq xmm10, xmm2
	movaps	xmm2, xmm14
	movaps	xmm14, xmm4
	punpcklqdq xmm3, xmm8
	punpcklqdq xmm2, xmm11
	pmuludq	xmm14, xmm4
	pslld	xmm4, 1
	punpckhqdq xmm13, xmm8
	movaps	xmm11, xmm4
	movaps	xmm8, xmm5
	movaps	xmm15, xmm4
	pmuludq	xmm11, xmm5
	pslld	xmm8, 1
	movaps	[rsp], xmm3
	pmuludq	xmm5, xmm8
	movaps	xmm3, xmm8
	pmuludq	xmm15, xmm7
	paddq	xmm15, xmm5
	movaps	xmm5, xmm8
	movaps	xmm8, xmm4
	movaps	xmm6, xmm3
	pmuludq	xmm8, xmm1
	pmuludq	xmm5, xmm7
	paddq	xmm5, xmm8
	movaps	[rsp+0xf0], xmm5
	
	pslld	xmm7, 1
	movaps	xmm5, xmm1
	movaps	[rsp+0x60], xmm11
	pslld	xmm5, 1
	pmuludq	xmm6, xmm5
	paddq	xmm6, xmm9
	movaps	xmm9, xmm4
	movaps	xmm8, xmm10
	movaps	xmm11, xmm4
	pmuludq	xmm9, xmm0
	paddq	xmm6, xmm9
	movaps	xmm9, xmm7
	movaps	[rsp+0xd0], xmm6
	
	pslld	xmm8, 1
	pmuludq	xmm11, xmm2
	movaps	xmm6, xmm3
	pmuludq	xmm9, xmm1
	pmuludq	xmm1, xmm5
	movaps	[rsp+0x40], xmm14
	pmuludq	xmm6, xmm0
	paddq	xmm6, xmm9
	movaps	xmm9, xmm7
	movaps	xmm14, xmm12
	pmuludq	xmm9, xmm0
	paddq	xmm9, xmm1
	movaps	xmm1, xmm3
	movaps	[rsp+0x10], xmm13
	pmuludq	xmm14, xmm4
	pmuludq	xmm1, xmm8
	paddq	xmm1, xmm9
	movaps	xmm9, xmm7
	paddq	xmm11, xmm1
	movaps	xmm1, xmm5
	movaps	xmm13, xmm4
	pmuludq	xmm9, xmm10
	pmuludq	xmm1, xmm0
	paddq	xmm9, xmm1
	movaps	xmm1, xmm3
	pmuludq	xmm13, xmm10
	paddq	xmm6, xmm13
	movaps	xmm13, xmm12
	pmuludq	xmm1, xmm2
	paddq	xmm1, xmm9
	paddq	xmm14, xmm1
	movaps	xmm1, xmm12
	movaps	[rsp+0xe0], xmm6
	
	pslld	xmm1, 1
	movaps	xmm12, xmm1
	movaps	xmm1, xmm0
	movaps	xmm6, xmm8
	movaps	[rsp+0x90], xmm12
	
	pmuludq	xmm1, xmm0
	movaps	xmm9, xmm1
	movaps	xmm1, xmm5
	movaps	[rsp+0x70], xmm13
	pmuludq	xmm1, xmm8
	paddq	xmm1, xmm9
	movaps	xmm9, xmm7
	pmuludq	xmm9, xmm2
	paddq	xmm9, xmm1
	movaps	xmm1, xmm12
	movaps	xmm8, [rsp]
	pmuludq	xmm1, xmm3
	paddq	xmm1, xmm9
	movaps	xmm12, xmm8
	pmuludq	xmm12, xmm4
	paddq	xmm12, xmm1
	movaps	xmm1, xmm0
	pmuludq	xmm1, xmm6
	movaps	xmm9, xmm1
	movaps	xmm1, xmm5
	pmuludq	xmm1, xmm2
	paddq	xmm1, xmm9
	movaps	xmm9, xmm13
	movaps	xmm13, [rsp+0x10]
	pmuludq	xmm9, xmm7
	paddq	xmm9, xmm1
	movaps	xmm1, xmm8
	pmuludq	xmm1, xmm3
	paddq	xmm1, xmm9
	movaps	xmm9, xmm4
	movaps	xmm4, xmm10
	pmuludq	xmm9, xmm13
	paddq	xmm9, xmm1
	movaps	xmm1, xmm8
	pmuludq	xmm4, [.packedthirtyeight]
	movaps	[rsp+0x80], xmm4
	
	movaps	xmm4, xmm2
	pmuludq	xmm1, [.packednineteen]
	movaps	xmm8, xmm0
	pmuludq	xmm4, [.packednineteen]
	movaps	[rsp+0x20], xmm4
	pmuludq	xmm10, [rsp+0x80]
	
	pslld	xmm8, 1
	movaps	xmm4, [rsp+0x70]
	pmuludq	xmm4, [.packedthirtyeight]
	movaps	[rsp+0x30], xmm4
	movaps	xmm4, xmm1
	movaps	xmm1, xmm13
	movaps	xmm13, xmm2
	pmuludq	xmm1, [.packedthirtyeight]
	movaps	[rsp+0xa0], xmm10
	
	pmuludq	xmm3, xmm1
	pslld	xmm13, 1
	movaps	[rsp+0x80], xmm8
	
	movaps	xmm10, [rsp+0x20]
	pmuludq	xmm10, xmm8
	movaps	xmm8, [rsp+0x30]
	paddq	xmm10, [rsp+0xa0]
	
	pmuludq	xmm8, xmm5
	paddq	xmm10, xmm8
	movaps	xmm8, xmm10
	movaps	xmm10, xmm4
	pmuludq	xmm10, xmm7
	paddq	xmm10, xmm8
	movaps	xmm8, [rsp+0x20]
	paddq	xmm3, xmm10
	paddq	xmm3, [rsp+0x40]
	psrld	xmm7, 1
	movaps	[rsp+0x40], xmm3
	pmuludq	xmm8, xmm6
	pmuludq	xmm7, xmm1
	movaps	xmm3, xmm8
	movaps	xmm8, [rsp+0x30]
	pmuludq	xmm8, xmm0
	movaps	xmm10, xmm8
	pmuludq	xmm0, xmm1
	movaps	xmm8, xmm4
	paddq	xmm10, xmm3
	pmuludq	xmm8, xmm5
	movaps	xmm3, xmm8
	pmuludq	xmm5, xmm1
	movaps	xmm8, [rsp+0x20]
	paddq	xmm3, xmm10
	paddq	xmm7, xmm3
	paddq	xmm7, [rsp+0x60]
	movaps	xmm10, [rsp+0x30]
	pmuludq	xmm8, xmm2
	movaps	[rsp+0x60], xmm7
	movaps	xmm7, xmm8
	movaps	xmm8, xmm10
	pmuludq	xmm8, xmm6
	movaps	xmm3, xmm8
	paddq	xmm3, xmm7
	movaps	xmm7, [rsp+0x80]
	
	pmuludq	xmm7, xmm4
	paddq	xmm7, xmm3
	paddq	xmm5, xmm7
	movaps	xmm7, xmm10
	paddq	xmm15, xmm5
	movaps	xmm5, xmm10
	movaps	xmm10, xmm4
	pmuludq	xmm10, xmm6
	movaps	xmm3, xmm10
	pmuludq	xmm5, xmm2
	pmuludq	xmm6, xmm1
	pmuludq	xmm2, xmm1
	paddq	xmm3, xmm5
	paddq	xmm0, xmm3
	paddq	xmm0, [rsp+0xf0]
	
	movaps	xmm8, xmm0
	movaps	xmm0, xmm7
	movaps	xmm7, [rsp+0x90]
	
	pmuludq	xmm0, [rsp+0x70]
	movaps	xmm3, xmm0
	movaps	xmm0, xmm13
	pmuludq	xmm0, xmm4
	paddq	xmm0, xmm3
	paddq	xmm6, xmm0
	movaps	xmm0, xmm7
	paddq	xmm6, [rsp+0xd0]
	
	movaps	xmm3, [rsp]
	movaps	xmm10, xmm6
	pmuludq	xmm0, xmm4
	paddq	xmm2, xmm0
	movaps	xmm0, xmm7
	pmuludq	xmm4, xmm3
	paddq	xmm2, [rsp+0xe0]
	
	movaps	xmm5, xmm2
	pmuludq	xmm0, xmm1
	paddq	xmm0, xmm4
	paddq	xmm11, xmm0
	movaps	xmm0, xmm3
	movaps	xmm3, [rsp+0x40]
	pmuludq	xmm0, xmm1
	pmuludq	xmm1, [rsp+0x10]
	paddq	xmm12, xmm1
	movaps	xmm1, xmm3
	paddq	xmm14, xmm0
	movaps	xmm0, xmm6
	pand	xmm3, [.packedmask26]
	psrlq	xmm1, 0x1a
	paddq	xmm1, [rsp+0x60]
	movaps	xmm2, xmm1
	psrlq	xmm0, 0x1a
	psrlq	xmm1, 0x19
	paddq	xmm0, xmm5
	paddq	xmm15, xmm1
	movaps	xmm13, xmm0
	psrlq	xmm0, 0x19
	paddq	xmm11, xmm0
	movaps	xmm1, xmm11
	pand	xmm2, [.packedmask25]
	movaps	xmm0, [.packedmask26]
	psrlq	xmm1, 0x1a
	paddq	xmm14, xmm1
	movaps	xmm1, xmm14
	pand	xmm10, [.packedmask26]
	psrlq	xmm1, 0x19
	paddq	xmm12, xmm1
	movaps	xmm1, xmm12
	movaps	xmm4, xmm2
	movaps	xmm2, xmm15
	psrlq	xmm1, 0x1a
	paddq	xmm9, xmm1
	movaps	xmm1, xmm9
	pand	xmm14, [.packedmask25]
	psrlq	xmm2, 0x1a
	paddq	xmm2, xmm8
	psrlq	xmm1, 0x19
	movaps	xmm5, xmm2
	pmuludq	xmm1, [.packednineteen]
	pand	xmm12, [.packedmask26]
	paddq	xmm3, xmm1
	psrlq	xmm2, 0x19
	paddq	xmm10, xmm2
	movaps	xmm2, xmm3
	movaps	xmm8, [.packedmask25]
	pand	xmm3, [.packedmask26]
	movaps	xmm1, xmm10
	psrlq	xmm2, 0x1a
	paddq	xmm2, xmm4
	pand	xmm10, [.packedmask26]
	movaps	xmm7, xmm14
	movaps	xmm4, xmm2
	psrlq	xmm1, 0x1a
	pand	xmm11, [.packedmask26]
	movaps	xmm14, xmm12
	pand	xmm9, [.packedmask25]
	pand	xmm8, xmm5
	pand	xmm13, [.packedmask25]
	movaps	xmm5, xmm3
	movaps	xmm6, xmm11
	pand	xmm0, xmm15
	pmuludq	xmm5, [.packed121666121665]
	movaps	xmm15, xmm9
	movaps	[rsp], xmm2
	pmuludq	xmm4, [.packed121666121665]
	pmuludq	xmm6, [.packed121666121665]
	movaps	xmm2, xmm4
	movaps	[rsp+0x10], xmm8
	paddq	xmm13, xmm1
	movaps	xmm9, xmm8
	movaps	[rsp+0x40], xmm7
	movaps	xmm4, xmm10
	pmuludq	xmm9, [.packed121666121665]
	movaps	[rsp+0x60], xmm14
	movaps	xmm8, xmm7
	pmuludq	xmm4, [.packed121666121665]
	movaps	xmm7, xmm14
	movaps	xmm14, xmm5
	movaps	[rsp+0x30], xmm11
	pmuludq	xmm8, [.packed121666121665]
	movaps	xmm1, xmm13
	psrlq	xmm14, 0x1a
	pmuludq	xmm7, [.packed121666121665]
	movaps	[rsp+0x70], xmm15
	movaps	xmm11, xmm6
	pmuludq	xmm1, [.packed121666121665]
	movaps	xmm6, xmm15
	movaps	xmm15, xmm14
	movaps	xmm14, xmm4
	paddq	xmm2, xmm15
	movaps	xmm12, xmm0
	pand	xmm5, [.packedmask26]
	psrlq	xmm14, 0x1a
	paddq	xmm1, xmm14
	movaps	xmm14, xmm2
	pmuludq	xmm12, [.packed121666121665]
	pmuludq	xmm6, [.packed121666121665]
	pand	xmm4, [.packedmask26]
	psrlq	xmm14, 0x19
	movaps	xmm15, xmm14
	movaps	xmm14, xmm1
	pand	xmm1, [.packedmask25]
	paddq	xmm12, xmm15
	psrlq	xmm14, 0x19
	paddq	xmm11, xmm14
	movaps	xmm14, xmm12
	pand	xmm2, [.packedmask25]
	psrlq	xmm14, 0x1a
	movaps	xmm15, xmm14
	movaps	xmm14, xmm11
	pand	xmm12, [.packedmask26]
	paddq	xmm9, xmm15
	psrlq	xmm14, 0x1a
	paddq	xmm8, xmm14
	movaps	xmm14, xmm9
	pand	xmm9, [.packedmask25]
	psrlq	xmm14, 0x19
	movaps	xmm15, xmm14
	movaps	xmm14, xmm8
	pand	xmm11, [.packedmask26]
	paddq	xmm4, xmm15
	psrlq	xmm14, 0x19
	paddq	xmm7, xmm14
	movaps	xmm14, xmm7
	pand	xmm8, [.packedmask25]
	psrlq	xmm14, 0x1a
	paddq	xmm6, xmm14
	movaps	xmm14, xmm6
	pand	xmm7, [.packedmask26]
	psrlq	xmm14, 0x19
	pmuludq	xmm14, [.packednineteen]
	paddq	xmm5, xmm14
	movaps	xmm14, xmm5
	pand	xmm5, [.packedmask26]
	psrlq	xmm14, 0x1a
	movaps	xmm15, xmm14
	movaps	xmm14, xmm4
	pand	xmm4, [.packedmask26]
	paddq	xmm2, xmm15
	psrlq	xmm14, 0x1a
	paddq	xmm1, xmm14
	pand	xmm6, [.packedmask25]
	movaps	xmm14, xmm5
	punpckhqdq xmm5, xmm2
	punpcklqdq xmm14, xmm2
	movaps	xmm2, xmm3
	punpckhqdq xmm2, [rsp]
	pslldq	xmm5, 0x4
	movaps	xmm15, xmm14
	movaps	xmm14, xmm3
	pslldq	xmm15, 0x4
	punpcklqdq xmm14, [rsp]
	por	xmm2, xmm5
	movaps	xmm5, xmm12
	punpckhqdq xmm12, xmm9
	punpcklqdq xmm5, xmm9
	movaps	xmm9, xmm0
	por	xmm14, xmm15
	pslldq	xmm12, 0x4
	punpckhqdq xmm9, [rsp+0x10]
	movaps	xmm15, xmm5
	paddd	xmm14, [.packed32zeromodp0]
	psubd	xmm14, xmm2
	movaps	xmm5, xmm0
	movaps	xmm2, xmm14
	pslldq	xmm15, 0x4
	punpcklqdq xmm5, [rsp+0x10]
	por	xmm9, xmm12
	movaps	xmm12, xmm4
	punpckhqdq xmm4, xmm1
	punpcklqdq xmm12, xmm1
	por	xmm5, xmm15
	movaps	xmm1, xmm10
	pslldq	xmm4, 0x4
	movaps	xmm15, xmm12
	movaps	xmm12, xmm10
	punpckhqdq xmm1, xmm13
	paddd	xmm5, [.packed32zeromodp1]
	pslldq	xmm15, 0x4
	psubd	xmm5, xmm9
	punpcklqdq xmm12, xmm13
	por	xmm12, xmm15
	movaps	xmm15, xmm1
	movaps	xmm1, xmm11
	punpckhqdq xmm11, xmm8
	por	xmm15, xmm4
	movaps	xmm4, [rsp+0x30]
	paddd	xmm12, [.packed32zeromodp1]
	punpcklqdq xmm1, xmm8
	punpcklqdq xmm4, [rsp+0x40]
	pslldq	xmm11, 0x4
	movaps	xmm8, [rsp+0x60]
	psubd	xmm12, xmm15
	pslldq	xmm1, 0x4
	punpcklqdq xmm2, xmm12
	punpcklqdq xmm8, [rsp+0x70]
	movaps	xmm15, [rsp]
	por	xmm4, xmm1
	movaps	xmm9, xmm2
	movaps	xmm1, [rsp+0x30]
	movaps	xmm2, xmm5
	punpckhqdq xmm14, xmm12
	punpckhqdq xmm1, [rsp+0x40]
	por	xmm1, xmm11
	movaps	xmm11, xmm7
	punpckhqdq xmm7, xmm6
	punpcklqdq xmm11, xmm6
	movaps	xmm6, [rsp+0x60]
	pslldq	xmm7, 0x4
	punpckhqdq xmm6, [rsp+0x70]
	pslldq	xmm11, 0x4
	por	xmm8, xmm11
	por	xmm6, xmm7
	movaps	xmm7, [.packed32zeromodp1]
	paddd	xmm7, xmm4
	psubd	xmm7, xmm1
	punpcklqdq xmm2, xmm7
	movaps	xmm4, [.packed32zeromodp1]
	punpckhqdq xmm5, xmm7
	paddd	xmm4, xmm8
	psubd	xmm4, xmm6
	movaps	xmm6, xmm2
	movaps	xmm2, xmm9
	movaps	xmm7, [.packedmask26262626]
	pand	xmm9, [.packedmask26262626]
	movaps	xmm1, xmm6
	psrld	xmm2, 0x1a
	paddd	xmm2, xmm14
	movaps	xmm11, xmm2
	pand	xmm7, xmm6
	pand	xmm2, [.packedmask25252525]
	psrld	xmm1, 0x1a
	paddd	xmm1, xmm5
	psrld	xmm11, 0x19
	movaps	xmm5, xmm1
	movaps	xmm6, xmm11
	pand	xmm1, [.packedmask25252525]
	psrld	xmm5, 0x19
	paddd	xmm6, xmm7
	movaps	xmm7, xmm5
	pslldq	xmm5, 0x8
	paddd	xmm9, xmm5
	movaps	xmm5, xmm9
	movaps	xmm8, xmm6
	punpckhqdq xmm9, xmm2
	psrldq	xmm7, 0x8
	paddd	xmm4, xmm7
	punpcklqdq xmm5, xmm2
	movaps	xmm2, xmm3
	punpcklqdq xmm8, xmm1
	punpckhqdq xmm6, xmm1
	pshufd	xmm12, xmm5, 0x50
	pshufd	xmm1, xmm5, 0xfa
	pshufd	xmm14, xmm8, 0x50
	punpcklqdq xmm2, xmm12
	punpckhqdq xmm3, xmm12
	movaps	xmm12, xmm15
	punpckhqdq xmm15, xmm1
	punpcklqdq xmm12, xmm1
	pshufd	xmm8, xmm8, 0xfa
	movaps	xmm1, xmm15
	movaps	xmm15, xmm0
	punpckhqdq xmm0, xmm14
	punpcklqdq xmm15, xmm14
	pshufd	xmm11, xmm9, 0x50
	movaps	[rsp], xmm0
	pshufd	xmm9, xmm9, 0xfa
	pshufd	xmm7, xmm6, 0x50
	pshufd	xmm6, xmm6, 0xfa
	movaps	xmm0, [rsp+0x10]
	pshufd	xmm5, xmm4, 0x50
	pshufd	xmm4, xmm4, 0xfa
	movaps	xmm14, xmm0
	punpckhqdq xmm0, xmm8
	punpcklqdq xmm14, xmm8
	movaps	xmm8, xmm10
	punpckhqdq xmm10, xmm11
	punpcklqdq xmm8, xmm11
	movaps	xmm11, xmm13
	movaps	[rsp+0x10], xmm10
	punpckhqdq xmm11, xmm9
	movaps	xmm10, xmm13
	movaps	xmm13, [rsp+0x30]
	punpcklqdq xmm10, xmm9
	movaps	[rsp+0x20], xmm11
	movaps	xmm11, xmm13
	punpckhqdq xmm13, xmm7
	punpcklqdq xmm11, xmm7
	movaps	xmm9, [rsp+0x40]
	movaps	xmm7, xmm9
	movaps	[rsp+0x30], xmm13
	punpcklqdq xmm7, xmm6
	punpckhqdq xmm9, xmm6
	movaps	xmm13, [rsp+0x60]
	movaps	[rsp+0x80], xmm7
	
	movaps	xmm7, xmm13
	punpckhqdq xmm13, xmm5
	punpcklqdq xmm7, xmm5
	movaps	xmm6, [rsp+0x70]
	movaps	xmm5, xmm6
	punpckhqdq xmm6, xmm4
	punpcklqdq xmm5, xmm4
	movaps	xmm4, xmm2
	movaps	[rsp+0x60], xmm13
	pmuludq	xmm4, xmm3
	movaps	xmm13, xmm6
	movaps	[rsp+0x90], xmm4
	
	movaps	xmm6, xmm2
	movaps	xmm4, xmm12
	pmuludq	xmm6, xmm1
	movaps	[rsp+0x100], xmm5
	
	pmuludq	xmm4, xmm3
	paddq	xmm4, xmm6
	movaps	xmm6, xmm12
	movaps	[rsp+0xa0], xmm4
	
	pslld	xmm6, 1
	movaps	xmm4, xmm6
	movaps	xmm6, xmm15
	movaps	xmm5, xmm4
	movaps	[rsp+0x40], xmm9
	pmuludq	xmm6, xmm3
	pmuludq	xmm5, xmm1
	paddq	xmm5, xmm6
	movaps	xmm6, xmm2
	movaps	[rsp+0xf0], xmm7
	
	movaps	xmm9, [rsp]
	pmuludq	xmm6, xmm9
	paddq	xmm5, xmm6
	movaps	xmm6, xmm15
	movaps	[rsp+0xd0], xmm5
	
	movaps	xmm5, xmm14
	pmuludq	xmm6, xmm1
	pmuludq	xmm5, xmm3
	paddq	xmm6, xmm5
	movaps	xmm5, xmm12
	pmuludq	xmm5, xmm9
	paddq	xmm5, xmm6
	movaps	xmm6, xmm0
	movaps	xmm9, [rsp+0x10]
	pmuludq	xmm6, xmm2
	paddq	xmm5, xmm6
	movaps	xmm6, xmm14
	movaps	[rsp+0xe0], xmm5
	
	pslld	xmm6, 1
	movaps	xmm5, xmm6
	movaps	xmm6, xmm8
	pmuludq	xmm6, xmm3
	movaps	xmm7, xmm6
	movaps	xmm6, xmm5
	pmuludq	xmm6, xmm1
	paddq	xmm6, xmm7
	movaps	xmm7, xmm15
	pmuludq	xmm7, [rsp]
	paddq	xmm7, xmm6
	movaps	xmm6, xmm0
	pmuludq	xmm6, xmm4
	paddq	xmm6, xmm7
	movaps	xmm7, xmm9
	pmuludq	xmm7, xmm2
	paddq	xmm6, xmm7
	movaps	xmm7, xmm8
	movaps	[rsp+0x130], xmm6
	
	movaps	xmm6, xmm10
	pmuludq	xmm7, xmm1
	pmuludq	xmm6, xmm3
	paddq	xmm7, xmm6
	movaps	xmm6, xmm14
	pmuludq	xmm6, [rsp]
	paddq	xmm6, xmm7
	movaps	xmm7, xmm0
	pmuludq	xmm7, xmm15
	paddq	xmm7, xmm6
	movaps	xmm6, xmm9
	pmuludq	xmm6, xmm12
	paddq	xmm6, xmm7
	movaps	xmm7, [rsp+0x20]
	pmuludq	xmm7, xmm2
	paddq	xmm6, xmm7
	movaps	xmm7, xmm10
	movaps	[rsp+0x140], xmm6
	
	pslld	xmm7, 1
	movaps	xmm6, xmm11
	movaps	xmm9, xmm7
	pmuludq	xmm6, xmm3
	movaps	xmm7, xmm6
	movaps	xmm6, xmm9
	pmuludq	xmm9, xmm0
	pmuludq	xmm6, xmm1
	paddq	xmm6, xmm7
	movaps	xmm7, xmm8
	pmuludq	xmm7, [rsp]
	paddq	xmm7, xmm6
	movaps	xmm6, xmm0
	pmuludq	xmm6, xmm5
	paddq	xmm6, xmm7
	movaps	xmm7, [rsp+0x10]
	pmuludq	xmm7, xmm15
	paddq	xmm7, xmm6
	movaps	xmm6, [rsp+0x20]
	pmuludq	xmm6, xmm4
	paddq	xmm6, xmm7
	movaps	xmm7, [rsp+0x30]
	pmuludq	xmm7, xmm2
	paddq	xmm6, xmm7
	movaps	xmm7, xmm11
	movaps	[rsp+0x150], xmm6
	
	pmuludq	xmm7, xmm1
	movaps	xmm6, [rsp+0x80]
	
	pmuludq	xmm6, xmm3
	paddq	xmm7, xmm6
	movaps	xmm6, xmm10
	pmuludq	xmm6, [rsp]
	paddq	xmm6, xmm7
	movaps	xmm7, xmm0
	pmuludq	xmm7, xmm8
	paddq	xmm7, xmm6
	movaps	xmm6, [rsp+0x10]
	pmuludq	xmm6, xmm14
	paddq	xmm6, xmm7
	movaps	xmm7, [rsp+0x20]
	pmuludq	xmm7, xmm15
	paddq	xmm7, xmm6
	movaps	xmm6, [rsp+0x30]
	pmuludq	xmm6, xmm12
	paddq	xmm6, xmm7
	movaps	xmm7, [rsp+0x40]
	pmuludq	xmm7, xmm2
	paddq	xmm6, xmm7
	movaps	[rsp+0x160], xmm6
	
	pmuludq	xmm5, [rsp+0x20]
	pmuludq	xmm4, [rsp+0x40]
	movaps	xmm7, [rsp+0x80]
	
	movaps	xmm6, [rsp+0xf0]
	
	pslld	xmm7, 1
	pmuludq	xmm7, xmm1
	pmuludq	xmm6, xmm3
	paddq	xmm7, xmm6
	movaps	xmm6, xmm11
	pmuludq	xmm3, [rsp+0x100]
	
	pmuludq	xmm6, [rsp]
	paddq	xmm6, xmm7
	paddq	xmm9, xmm6
	movaps	xmm6, [rsp+0x10]
	pmuludq	xmm6, xmm8
	paddq	xmm6, xmm9
	movaps	xmm9, [rsp+0x60]
	paddq	xmm5, xmm6
	movaps	xmm6, [rsp+0x30]
	pmuludq	xmm6, xmm15
	paddq	xmm6, xmm5
	movaps	xmm5, [rsp+0xf0]
	
	paddq	xmm4, xmm6
	movaps	xmm6, xmm9
	movaps	xmm7, [rsp+0x80]
	
	pmuludq	xmm6, xmm2
	paddq	xmm6, xmm4
	movaps	xmm4, xmm5
	pmuludq	xmm2, xmm13
	pmuludq	xmm4, xmm1
	paddq	xmm4, xmm3
	movaps	xmm3, xmm7
	pmuludq	xmm7, [.packednineteen]
	pmuludq	xmm3, [rsp]
	paddq	xmm3, xmm4
	movaps	xmm4, xmm0
	pmuludq	xmm4, xmm11
	paddq	xmm4, xmm3
	movaps	xmm3, [rsp+0x10]
	pmuludq	xmm3, xmm10
	paddq	xmm3, xmm4
	movaps	xmm4, [rsp+0x20]
	pmuludq	xmm10, [.packednineteen]
	pmuludq	xmm4, xmm8
	paddq	xmm4, xmm3
	movaps	xmm3, [rsp+0x30]
	pmuludq	xmm8, [.packednineteen]
	pmuludq	xmm3, xmm14
	paddq	xmm3, xmm4
	movaps	xmm4, [rsp+0x40]
	pmuludq	xmm14, [.packednineteen]
	pmuludq	xmm4, xmm15
	paddq	xmm4, xmm3
	movaps	xmm3, xmm9
	movaps	xmm9, xmm2
	movaps	xmm2, xmm14
	pmuludq	xmm15, [.packednineteen]
	pmuludq	xmm3, xmm12
	paddq	xmm3, xmm4
	movaps	xmm4, xmm7
	pslld	xmm2, 1
	movaps	[rsp+0xf0], xmm2
	
	paddq	xmm9, xmm3
	movaps	xmm2, xmm10
	pslld	xmm4, 1
	pmuludq	xmm12, [.packednineteen]
	movaps	xmm3, xmm11
	pslld	xmm12, 1
	pmuludq	xmm12, xmm13
	pslld	xmm2, 1
	movaps	[rsp+0x70], xmm2
	movaps	xmm2, xmm5
	pmuludq	xmm3, [.packednineteen]
	movaps	[rsp+0x80], xmm4
	
	pmuludq	xmm2, [.packednineteen]
	movaps	xmm5, [rsp+0x100]
	
	pmuludq	xmm5, [.packednineteen]
	movaps	xmm11, xmm5
	pslld	xmm11, 1
	movaps	xmm4, xmm11
	movaps	xmm11, [rsp+0x60]
	pmuludq	xmm1, xmm4
	pmuludq	xmm11, xmm15
	paddq	xmm11, xmm12
	movaps	xmm12, [rsp+0xf0]
	
	pmuludq	xmm15, xmm13
	pmuludq	xmm12, [rsp+0x40]
	paddq	xmm12, xmm11
	movaps	xmm11, [rsp+0x30]
	pmuludq	xmm11, xmm8
	paddq	xmm11, xmm12
	movaps	xmm12, [rsp+0x70]
	pmuludq	xmm12, [rsp+0x20]
	paddq	xmm12, xmm11
	movaps	xmm11, [rsp+0x10]
	pmuludq	xmm11, xmm3
	paddq	xmm11, xmm12
	movaps	xmm12, [rsp+0x80]
	
	pmuludq	xmm12, xmm0
	paddq	xmm12, xmm11
	movaps	xmm11, xmm2
	pmuludq	xmm11, [rsp]
	paddq	xmm11, xmm12
	paddq	xmm1, xmm11
	paddq	xmm1, [rsp+0x90]
	
	movaps	[rsp+0x90], xmm1
	
	movaps	xmm12, [rsp+0x60]
	pmuludq	xmm14, xmm12
	paddq	xmm14, xmm15
	movaps	xmm15, [rsp+0x40]
	movaps	xmm1, xmm15
	movaps	xmm11, [rsp+0x30]
	pmuludq	xmm1, xmm8
	paddq	xmm1, xmm14
	movaps	xmm14, [rsp+0x20]
	pmuludq	xmm11, xmm10
	paddq	xmm11, xmm1
	pmuludq	xmm14, xmm3
	movaps	xmm1, xmm14
	movaps	xmm14, xmm0
	paddq	xmm1, xmm11
	movaps	xmm11, [rsp+0x10]
	pmuludq	xmm14, xmm2
	pmuludq	xmm11, xmm7
	movaps	[rsp+0x40], xmm0
	paddq	xmm11, xmm1
	movaps	xmm1, xmm14
	paddq	xmm1, xmm11
	movaps	xmm11, xmm15
	movaps	xmm0, [rsp]
	movaps	xmm14, [rsp+0xf0]
	
	pmuludq	xmm0, xmm5
	paddq	xmm0, xmm1
	paddq	xmm0, [rsp+0xa0]
	
	pmuludq	xmm14, xmm13
	movaps	[rsp+0xa0], xmm0
	
	movaps	xmm1, xmm14
	movaps	xmm0, xmm12
	movaps	xmm14, xmm12
	pmuludq	xmm0, xmm8
	paddq	xmm0, xmm1
	movaps	xmm1, [rsp+0x70]
	pmuludq	xmm8, xmm13
	pmuludq	xmm10, xmm14
	paddq	xmm10, xmm8
	pmuludq	xmm1, xmm15
	movaps	xmm15, [rsp+0x30]
	paddq	xmm1, xmm0
	movaps	xmm8, xmm11
	movaps	xmm0, xmm15
	movaps	xmm12, [rsp+0x10]
	pmuludq	xmm0, xmm3
	paddq	xmm0, xmm1
	movaps	xmm1, [rsp+0x80]
	
	pmuludq	xmm1, [rsp+0x20]
	paddq	xmm1, xmm0
	movaps	xmm0, xmm12
	pmuludq	xmm0, xmm2
	paddq	xmm0, xmm1
	movaps	xmm1, [rsp+0x40]
	pmuludq	xmm1, xmm4
	paddq	xmm1, xmm0
	movaps	xmm0, xmm11
	paddq	xmm1, [rsp+0xd0]
	
	movaps	xmm11, xmm15
	pmuludq	xmm0, xmm3
	paddq	xmm0, xmm10
	movaps	xmm10, xmm15
	movaps	[rsp+0xd0], xmm1
	
	pmuludq	xmm10, xmm7
	movaps	xmm1, xmm10
	movaps	xmm10, xmm12
	paddq	xmm1, xmm0
	movaps	xmm15, [rsp+0x20]
	pmuludq	xmm10, xmm5
	movaps	xmm0, xmm15
	movaps	xmm12, [rsp+0x80]
	
	pmuludq	xmm0, xmm2
	paddq	xmm0, xmm1
	movaps	xmm1, xmm10
	movaps	xmm10, [rsp+0xe0]
	
	paddq	xmm1, xmm0
	movaps	xmm0, [rsp+0x70]
	paddq	xmm10, xmm1
	pmuludq	xmm0, xmm13
	movaps	xmm1, xmm0
	movaps	xmm0, xmm14
	movaps	[rsp+0xe0], xmm10
	
	pmuludq	xmm0, xmm3
	paddq	xmm0, xmm1
	movaps	xmm1, xmm12
	movaps	xmm10, xmm14
	movaps	xmm14, xmm8
	pmuludq	xmm3, xmm13
	pmuludq	xmm1, xmm8
	movaps	xmm8, xmm11
	paddq	xmm1, xmm0
	movaps	xmm0, xmm11
	movaps	xmm11, xmm15
	pmuludq	xmm7, xmm10
	paddq	xmm7, xmm3
	movaps	xmm3, xmm8
	pmuludq	xmm11, xmm4
	pmuludq	xmm0, xmm2
	paddq	xmm0, xmm1
	movaps	xmm1, xmm11
	pmuludq	xmm3, xmm5
	pmuludq	xmm5, xmm10
	movaps	xmm8, [.packedmask25]
	paddq	xmm1, xmm0
	movaps	xmm0, [rsp+0x130]
	
	paddq	xmm0, xmm1
	movaps	xmm1, xmm3
	movaps	xmm11, xmm0
	movaps	xmm0, xmm14
	movaps	xmm3, [rsp+0x140]
	
	pmuludq	xmm0, xmm2
	paddq	xmm0, xmm7
	paddq	xmm1, xmm0
	movaps	xmm0, xmm12
	paddq	xmm3, xmm1
	movaps	xmm7, xmm14
	movaps	xmm14, [.packedmask26]
	pmuludq	xmm0, xmm13
	movaps	xmm1, xmm0
	movaps	xmm0, xmm10
	pmuludq	xmm7, xmm4
	pmuludq	xmm4, xmm13
	paddq	xmm6, xmm4
	movaps	xmm4, [rsp+0x90]
	
	pand	xmm14, xmm11
	pmuludq	xmm0, xmm2
	paddq	xmm0, xmm1
	movaps	xmm1, xmm7
	movaps	xmm7, [rsp+0x150]
	
	pmuludq	xmm2, xmm13
	paddq	xmm5, xmm2
	paddq	xmm1, xmm0
	movaps	xmm0, xmm11
	paddq	xmm5, [rsp+0x160]
	
	paddq	xmm7, xmm1
	movaps	xmm1, xmm4
	pand	xmm4, [.packedmask26]
	psrlq	xmm0, 0x1a
	paddq	xmm0, xmm3
	movaps	xmm2, xmm0
	psrlq	xmm1, 0x1a
	paddq	xmm1, [rsp+0xa0]
	
	movaps	xmm3, xmm1
	psrlq	xmm2, 0x19
	paddq	xmm2, xmm7
	movaps	xmm12, xmm2
	psrlq	xmm2, 0x1a
	paddq	xmm2, xmm5
	movaps	xmm10, xmm2
	psrlq	xmm2, 0x19
	paddq	xmm6, xmm2
	movaps	xmm2, xmm6
	psrlq	xmm3, 0x19
	paddq	xmm3, [rsp+0xd0]
	
	movaps	xmm13, xmm3
	psrlq	xmm2, 0x1a
	paddq	xmm9, xmm2
	movaps	xmm2, xmm9
	pand	xmm13, [.packedmask26]
	psrlq	xmm3, 0x1a
	paddq	xmm3, [rsp+0xe0]
	
	psrlq	xmm2, 0x19
	movaps	xmm15, xmm3
	pmuludq	xmm2, [.packednineteen]
	pand	xmm0, [.packedmask25]
	paddq	xmm4, xmm2
	movaps	xmm5, xmm4
	psrlq	xmm3, 0x19
	paddq	xmm14, xmm3
	movaps	xmm2, xmm14
	pand	xmm4, [.packedmask26]
	psrlq	xmm5, 0x1a
	psrlq	xmm2, 0x1a
	movaps	xmm3, [.packedmask26]
	pand	xmm15, [.packedmask25]
	paddq	xmm0, xmm2
	movaps	xmm2, xmm13
	pand	xmm1, [.packedmask25]
	movaps	xmm7, xmm4
	pand	xmm12, [.packedmask26]
	pand	xmm14, [.packedmask26]
	paddq	xmm1, xmm5
	pand	xmm10, [.packedmask25]
	punpckldq xmm2, xmm15
	punpckldq xmm7, xmm1
	movaps	xmm5, xmm14
	pand	xmm3, xmm6
	pand	xmm8, xmm9
	punpcklqdq xmm7, xmm2
	movaps	xmm2, xmm12
	punpckldq xmm5, xmm0
	punpckldq xmm2, xmm10
	movaps	xmm11, xmm3
	punpckhdq xmm4, xmm1
	punpckhdq xmm14, xmm0
	punpckldq xmm11, xmm8
	punpckhdq xmm13, xmm15
	punpckhdq xmm12, xmm10
	punpckhdq xmm3, xmm8
	movaps	xmm6, xmm11
	punpcklqdq xmm5, xmm2
	movaps	xmm2, xmm4
	punpcklqdq xmm14, xmm12
	movaps	xmm0, xmm3
	punpcklqdq xmm2, xmm13
	jne    .highloop

	neg    eax
	movaps	xmm8, [rsp+0x200]
	
	movd   xmm1, eax
	movaps	xmm11, xmm5
	pxor	xmm8, xmm2
	mov	[rsp], eax
	pshufd	xmm1, xmm1, 0
	mov	eax, 0x3
	movaps	xmm3, [rsp+0x1e0]
	
	movaps	xmm13, [rsp+0x1f0]
	
	pxor	xmm3, xmm7
	movaps	xmm4, [rsp+0x220]
	
	pxor	xmm13, xmm11
	pand	xmm8, xmm1
	movaps	xmm12, [rsp+0x1a0]
	
	pxor	xmm4, xmm6
	pand	xmm3, xmm1
	movaps	xmm15, [rsp+0x1b0]
	
	pxor	xmm12, xmm14
	pand	xmm13, xmm1
	pxor	xmm15, xmm0
	pand	xmm4, xmm1
	pand	xmm12, xmm1
	pand	xmm15, xmm1
	pxor	xmm8, xmm2
	pxor	xmm12, xmm14
	pxor	xmm15, xmm0
	pxor	xmm4, xmm6
	movaps	xmm2, xmm8
	pxor	xmm13, xmm11
	pxor	xmm3, xmm7
calign
.lowloop:
	movaps	xmm7, xmm3
	paddd	xmm3, [.packed2p0]
	psubd	xmm3, xmm2
	pshufd	xmm5, xmm3, 0xa0
	movaps	xmm8, xmm4
	paddd	xmm4, [.packed2p2]
	pshufd	xmm3, xmm3, 0xf5
	paddd	xmm7, xmm2
	psubd	xmm4, xmm15
	paddd	xmm8, xmm15
	movaps	xmm1, xmm13
	paddd	xmm13, [.packed2p1]
	pand	xmm5, [.sse2_bot32bitmask]
	psubd	xmm13, xmm12
	sub	rax, 1
	paddd	xmm1, xmm12
	pand	xmm3, [.sse2_bot32bitmask]
	movaps	xmm0, xmm5
	pand	xmm5, [.packedmask26]
	movaps	xmm2, xmm3
	psrld	xmm0, 0x1a
	pand	xmm3, [.packedmask25]
	psrld	xmm2, 0x19
	movaps	xmm6, xmm2
	psrldq	xmm2, 0x8
	paddd	xmm13, xmm2
	movaps	xmm2, xmm7
	pslldq	xmm6, 0x8
	paddd	xmm5, xmm6
	paddd	xmm0, xmm3
	movaps	xmm3, xmm5
	punpckldq xmm5, xmm0
	punpckhdq xmm3, xmm0
	movaps	xmm0, xmm5
	punpcklqdq xmm0, xmm3
	movaps	xmm3, xmm8
	punpcklqdq xmm3, xmm4
	punpckhqdq xmm7, xmm0
	punpcklqdq xmm2, xmm0
	movaps	xmm0, xmm1
	movaps	xmm6, xmm3
	punpckhqdq xmm1, xmm13
	movaps	[rsp], xmm6
	punpcklqdq xmm0, xmm13
	pshufd	xmm4, xmm2, 0xf5
	pshufd	xmm13, [rsp], 0xf5
	pshufd	xmm3, xmm1, 0xf5
	pshufd	xmm5, xmm7, 0xf5
	movaps	[rsp+0x10], xmm13
	movaps	xmm13, xmm2
	movaps	xmm15, xmm3
	movaps	xmm3, xmm4
	pmuludq	xmm13, xmm2
	pslld	xmm2, 1
	movaps	xmm10, xmm2
	movaps	xmm14, xmm2
	pslld	xmm3, 1
	movaps	xmm12, xmm2
	pmuludq	xmm10, xmm4
	pmuludq	xmm4, xmm3
	movaps	[rsp+0x30], xmm13
	pmuludq	xmm14, xmm7
	paddq	xmm4, xmm14
	pmuludq	xmm12, xmm5
	movaps	[rsp+0x90], xmm4
	
	movaps	xmm4, xmm3
	movaps	[rsp+0x40], xmm10
	pmuludq	xmm4, xmm7
	movaps	xmm10, xmm7
	paddq	xmm12, xmm4
	movaps	xmm6, xmm3
	movaps	xmm4, xmm5
	movaps	xmm13, xmm2
	pmuludq	xmm10, xmm7
	pslld	xmm7, 1
	pslld	xmm4, 1
	pmuludq	xmm6, xmm4
	paddq	xmm6, xmm10
	pmuludq	xmm13, xmm0
	movaps	xmm10, xmm7
	paddq	xmm13, xmm6
	movaps	xmm6, xmm3
	pshufd	xmm11, xmm0, 0xf5
	pmuludq	xmm10, xmm5
	movaps	xmm14, xmm2
	pmuludq	xmm5, xmm4
	pmuludq	xmm6, xmm0
	paddq	xmm6, xmm10
	movaps	xmm10, xmm7
	pmuludq	xmm14, xmm11
	movaps	xmm8, xmm2
	paddq	xmm6, xmm14
	pmuludq	xmm10, xmm0
	movaps	xmm14, xmm11
	paddq	xmm10, xmm5
	movaps	xmm5, xmm3
	pmuludq	xmm8, xmm1
	movaps	xmm9, xmm15
	pslld	xmm14, 1
	movaps	[rsp+0x80], xmm6
	
	pmuludq	xmm5, xmm14
	paddq	xmm5, xmm10
	movaps	xmm10, xmm7
	paddq	xmm5, xmm8
	movaps	[rsp+0xa0], xmm5
	
	pmuludq	xmm9, xmm2
	movaps	xmm5, xmm4
	pmuludq	xmm10, xmm11
	movaps	xmm6, xmm14
	pmuludq	xmm5, xmm0
	paddq	xmm10, xmm5
	movaps	xmm5, xmm3
	movaps	[rsp+0x50], xmm15
	pmuludq	xmm5, xmm1
	paddq	xmm5, xmm10
	paddq	xmm5, xmm9
	movaps	[rsp+0xb0], xmm5
	
	movaps	xmm5, xmm15
	pslld	xmm5, 1
	movaps	xmm14, xmm5
	movaps	xmm5, xmm0
	movaps	xmm9, [rsp]
	pmuludq	xmm5, xmm0
	movaps	xmm10, xmm5
	movaps	xmm5, xmm4
	movaps	xmm8, [rsp+0x10]
	pmuludq	xmm5, xmm6
	paddq	xmm5, xmm10
	movaps	xmm10, xmm7
	movaps	[rsp+0x70], xmm14
	pmuludq	xmm10, xmm1
	paddq	xmm10, xmm5
	movaps	xmm5, xmm14
	movaps	xmm14, xmm9
	pmuludq	xmm5, xmm3
	paddq	xmm5, xmm10
	pmuludq	xmm14, xmm2
	paddq	xmm14, xmm5
	movaps	xmm5, xmm0
	pmuludq	xmm5, xmm6
	movaps	xmm10, xmm5
	movaps	xmm5, xmm4
	pmuludq	xmm5, xmm1
	paddq	xmm5, xmm10
	movaps	xmm10, xmm15
	pmuludq	xmm10, xmm7
	paddq	xmm10, xmm5
	movaps	xmm5, xmm9
	pmuludq	xmm5, xmm3
	paddq	xmm5, xmm10
	movaps	xmm10, xmm2
	movaps	xmm2, xmm11
	pmuludq	xmm10, xmm8
	paddq	xmm10, xmm5
	movaps	xmm5, xmm9
	pmuludq	xmm2, [.packedthirtyeight]
	movaps	xmm15, xmm2
	movaps	xmm2, xmm1
	pmuludq	xmm5, [.packednineteen]
	movaps	xmm9, xmm1
	pmuludq	xmm2, [.packednineteen]
	movaps	[rsp+0x20], xmm2
	pmuludq	xmm15, xmm11
	pslld	xmm9, 1
	movaps	xmm2, [rsp+0x50]
	pmuludq	xmm2, [.packedthirtyeight]
	movaps	[rsp+0x60], xmm2
	movaps	xmm2, xmm8
	movaps	xmm8, xmm0
	pmuludq	xmm2, [.packedthirtyeight]
	pmuludq	xmm3, xmm2
	movaps	xmm11, [rsp+0x20]
	pslld	xmm8, 1
	pmuludq	xmm11, xmm8
	paddq	xmm11, xmm15
	movaps	xmm15, [rsp+0x60]
	pmuludq	xmm15, xmm4
	paddq	xmm15, xmm11
	movaps	xmm11, xmm5
	pmuludq	xmm11, xmm7
	paddq	xmm11, xmm15
	movaps	xmm15, [rsp+0x60]
	paddq	xmm3, xmm11
	psrld	xmm7, 1
	pmuludq	xmm7, xmm2
	movaps	xmm11, [rsp+0x30]
	paddq	xmm11, xmm3
	movaps	xmm3, [rsp+0x20]
	movaps	[rsp+0x30], xmm11
	pmuludq	xmm3, xmm6
	movaps	xmm11, xmm15
	pmuludq	xmm11, xmm0
	paddq	xmm11, xmm3
	movaps	xmm3, xmm5
	pmuludq	xmm0, xmm2
	pmuludq	xmm3, xmm4
	paddq	xmm3, xmm11
	paddq	xmm7, xmm3
	movaps	xmm3, xmm15
	paddq	xmm7, [rsp+0x40]
	pmuludq	xmm4, xmm2
	movaps	[rsp+0x40], xmm7
	pmuludq	xmm3, xmm6
	movaps	xmm7, [rsp+0x20]
	pmuludq	xmm7, xmm1
	paddq	xmm3, xmm7
	movaps	xmm7, xmm8
	movaps	xmm8, [rsp+0x90]
	
	pmuludq	xmm7, xmm5
	paddq	xmm7, xmm3
	movaps	xmm3, xmm5
	paddq	xmm4, xmm7
	paddq	xmm8, xmm4
	movaps	xmm4, xmm15
	pmuludq	xmm3, xmm6
	pmuludq	xmm6, xmm2
	pmuludq	xmm4, xmm1
	paddq	xmm3, xmm4
	paddq	xmm0, xmm3
	paddq	xmm12, xmm0
	movaps	xmm0, xmm15
	pmuludq	xmm1, xmm2
	movaps	xmm4, [rsp+0x70]
	pmuludq	xmm0, [rsp+0x50]
	movaps	xmm3, xmm0
	movaps	xmm0, xmm9
	movaps	xmm9, [.packedmask25]
	pmuludq	xmm0, xmm5
	paddq	xmm0, xmm3
	paddq	xmm6, xmm0
	movaps	xmm0, xmm4
	paddq	xmm13, xmm6
	movaps	xmm3, [rsp]
	pmuludq	xmm0, xmm5
	paddq	xmm1, xmm0
	movaps	xmm0, xmm4
	pmuludq	xmm5, xmm3
	paddq	xmm1, [rsp+0x80]
	
	movaps	xmm15, xmm1
	pmuludq	xmm0, xmm2
	paddq	xmm0, xmm5
	paddq	xmm0, [rsp+0xa0]
	
	movaps	xmm7, xmm0
	movaps	xmm0, xmm3
	movaps	xmm5, [rsp+0x30]
	pmuludq	xmm0, xmm2
	paddq	xmm0, [rsp+0xb0]
	
	movaps	xmm6, xmm0
	movaps	xmm0, xmm13
	pmuludq	xmm2, [rsp+0x10]
	paddq	xmm14, xmm2
	movaps	xmm1, xmm5
	pand	xmm13, [.packedmask26]
	psrlq	xmm0, 0x1a
	paddq	xmm0, xmm15
	movaps	xmm2, xmm0
	pand	xmm5, [.packedmask26]
	psrlq	xmm0, 0x19
	paddq	xmm0, xmm7
	movaps	xmm3, xmm0
	psrlq	xmm0, 0x1a
	paddq	xmm0, xmm6
	pand	xmm2, [.packedmask25]
	movaps	xmm6, xmm0
	psrlq	xmm0, 0x19
	paddq	xmm14, xmm0
	movaps	xmm0, xmm14
	psrlq	xmm1, 0x1a
	paddq	xmm1, [rsp+0x40]
	movaps	xmm15, xmm1
	psrlq	xmm1, 0x19
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm8
	paddq	xmm10, xmm0
	movaps	xmm0, xmm10
	movaps	xmm4, xmm2
	movaps	xmm2, xmm1
	psrlq	xmm1, 0x1a
	paddq	xmm12, xmm1
	movaps	xmm1, xmm12
	psrlq	xmm0, 0x19
	pand	xmm12, [.packedmask25]
	pmuludq	xmm0, [.packednineteen]
	paddq	xmm5, xmm0
	movaps	xmm8, [.packedmask26]
	psrlq	xmm1, 0x19
	paddq	xmm13, xmm1
	pand	xmm2, [.packedmask26]
	movaps	xmm1, xmm5
	movaps	xmm0, xmm13
	pand	xmm5, [.packedmask26]
	psrlq	xmm1, 0x1a
	psrlq	xmm0, 0x1a
	paddq	xmm0, xmm4
	movaps	[rsp+0x10], xmm0
	pand	xmm13, [.packedmask26]
	pmuludq	xmm0, [.packed121666121665]
	movaps	xmm11, xmm2
	pand	xmm8, xmm3
	movaps	xmm3, xmm12
	pand	xmm10, [.packedmask25]
	pmuludq	xmm11, [.packed121666121665]
	movaps	xmm4, xmm5
	pand	xmm15, [.packedmask25]
	movaps	[rsp], xmm3
	pmuludq	xmm4, [.packed121666121665]
	pand	xmm14, [.packedmask26]
	movaps	[rsp+0x20], xmm8
	pand	xmm9, xmm6
	paddq	xmm15, xmm1
	movaps	xmm6, xmm10
	movaps	xmm1, xmm15
	movaps	xmm10, xmm8
	movaps	xmm7, xmm9
	movaps	xmm9, xmm3
	pmuludq	xmm1, [.packed121666121665]
	movaps	xmm3, xmm13
	pmuludq	xmm10, [.packed121666121665]
	pmuludq	xmm9, [.packed121666121665]
	movaps	xmm8, xmm7
	pmuludq	xmm3, [.packed121666121665]
	movaps	[rsp+0x30], xmm7
	movaps	xmm7, xmm14
	pmuludq	xmm8, [.packed121666121665]
	movaps	[rsp+0x70], xmm14
	movaps	xmm14, xmm6
	pmuludq	xmm7, [.packed121666121665]
	movaps	[rsp+0x80], xmm6
	
	pmuludq	xmm14, [.packed121666121665]
	movaps	xmm12, xmm3
	movaps	xmm6, xmm14
	movaps	xmm14, xmm4
	psrlq	xmm12, 0x1a
	paddq	xmm0, xmm12
	movaps	xmm12, xmm0
	psrlq	xmm14, 0x1a
	paddq	xmm1, xmm14
	movaps	xmm14, xmm1
	pand	xmm3, [.packedmask26]
	psrlq	xmm12, 0x19
	paddq	xmm10, xmm12
	psrlq	xmm14, 0x19
	movaps	xmm12, xmm10
	paddq	xmm11, xmm14
	movaps	xmm14, xmm11
	pand	xmm4, [.packedmask26]
	psrlq	xmm12, 0x1a
	paddq	xmm8, xmm12
	movaps	xmm12, xmm8
	psrlq	xmm14, 0x1a
	paddq	xmm9, xmm14
	movaps	xmm14, xmm9
	psrlq	xmm12, 0x19
	paddq	xmm7, xmm12
	pand	xmm1, [.packedmask25]
	psrlq	xmm14, 0x19
	paddq	xmm3, xmm14
	movaps	xmm14, xmm7
	pand	xmm11, [.packedmask26]
	psrlq	xmm14, 0x1a
	paddq	xmm6, xmm14
	movaps	xmm14, xmm6
	pand	xmm6, [.packedmask25]
	psrlq	xmm14, 0x19
	pmuludq	xmm14, [.packednineteen]
	paddq	xmm4, xmm14
	movaps	xmm14, xmm4
	pand	xmm4, [.packedmask26]
	psrlq	xmm14, 0x1a
	paddq	xmm1, xmm14
	movaps	xmm12, [rsp]
	pand	xmm9, [.packedmask25]
	movaps	[rsp+0x40], xmm6
	pand	xmm0, [.packedmask25]
	movaps	xmm14, xmm4
	punpckhqdq xmm4, xmm1
	movaps	xmm6, xmm3
	punpcklqdq xmm14, xmm1
	movaps	xmm1, xmm5
	pand	xmm3, [.packedmask26]
	psrlq	xmm6, 0x1a
	pslldq	xmm4, 0x4
	paddq	xmm0, xmm6
	punpckhqdq xmm1, xmm15
	movaps	xmm6, xmm14
	movaps	xmm14, xmm5
	pand	xmm10, [.packedmask26]
	pslldq	xmm6, 0x4
	por	xmm1, xmm4
	movaps	xmm4, xmm11
	punpckhqdq xmm11, xmm9
	punpcklqdq xmm14, xmm15
	punpcklqdq xmm4, xmm9
	movaps	xmm9, xmm2
	pslldq	xmm11, 0x4
	pand	xmm8, [.packedmask25]
	punpckhqdq xmm9, xmm12
	por	xmm14, xmm6
	movaps	xmm6, xmm4
	movaps	xmm4, xmm2
	por	xmm9, xmm11
	movaps	xmm11, xmm3
	pslldq	xmm6, 0x4
	punpcklqdq xmm4, xmm12
	paddd	xmm14, [.packed32zeromodp0]
	psubd	xmm14, xmm1
	punpcklqdq xmm11, xmm0
	movaps	xmm12, [rsp+0x10]
	punpckhqdq xmm3, xmm0
	por	xmm4, xmm6
	movaps	xmm0, xmm13
	movaps	xmm6, xmm11
	movaps	xmm11, xmm13
	punpckhqdq xmm0, xmm12
	pslldq	xmm3, 0x4
	pslldq	xmm6, 0x4
	pand	xmm7, [.packedmask26]
	paddd	xmm4, [.packed32zeromodp1]
	psubd	xmm4, xmm9
	movaps	xmm1, xmm4
	punpcklqdq xmm11, xmm12
	movaps	xmm12, xmm0
	movaps	xmm0, xmm10
	por	xmm12, xmm3
	por	xmm11, xmm6
	movaps	xmm6, [rsp+0x20]
	punpcklqdq xmm0, xmm8
	movaps	xmm3, xmm6
	punpckhqdq xmm10, xmm8
	movaps	xmm8, xmm7
	paddd	xmm11, [.packed32zeromodp1]
	psubd	xmm11, xmm12
	punpcklqdq xmm3, [rsp+0x30]
	pslldq	xmm0, 0x4
	pslldq	xmm10, 0x4
	punpcklqdq xmm8, [rsp+0x40]
	punpckhqdq xmm7, [rsp+0x40]
	por	xmm3, xmm0
	movaps	xmm0, xmm6
	pslldq	xmm8, 0x4
	punpckhqdq xmm0, [rsp+0x30]
	paddd	xmm3, [.packed32zeromodp1]
	pslldq	xmm7, 0x4
	por	xmm0, xmm10
	movaps	xmm10, [rsp+0x70]
	movaps	xmm6, xmm10
	psubd	xmm3, xmm0
	punpcklqdq xmm1, xmm3
	punpcklqdq xmm6, [rsp+0x80]
	
	movaps	xmm9, xmm1
	punpckhqdq xmm4, xmm3
	movaps	xmm3, xmm9
	pand	xmm9, [.packedmask26262626]
	por	xmm6, xmm8
	psrld	xmm3, 0x1a
	movaps	xmm8, xmm10
	movaps	xmm0, xmm3
	punpckhqdq xmm8, [rsp+0x80]
	
	paddd	xmm0, xmm4
	paddd	xmm6, [.packed32zeromodp1]
	movaps	xmm3, xmm0
	pand	xmm0, [.packedmask25252525]
	psrld	xmm3, 0x19
	por	xmm8, xmm7
	movaps	xmm7, xmm14
	punpckhqdq xmm14, xmm11
	punpcklqdq xmm7, xmm11
	psubd	xmm6, xmm8
	movaps	xmm1, xmm7
	pand	xmm7, [.packedmask26262626]
	psrld	xmm1, 0x1a
	paddd	xmm1, xmm14
	movaps	xmm4, xmm1
	pand	xmm1, [.packedmask25252525]
	movaps	xmm14, xmm15
	psrld	xmm4, 0x19
	movaps	xmm8, xmm4
	movaps	xmm4, xmm3
	paddd	xmm8, xmm9
	psrldq	xmm4, 0x8
	paddd	xmm6, xmm4
	movaps	xmm4, xmm3
	pslldq	xmm4, 0x8
	movaps	xmm11, xmm4
	movaps	xmm4, xmm8
	punpckhqdq xmm8, xmm0
	paddd	xmm11, xmm7
	movaps	xmm3, xmm11
	punpcklqdq xmm4, xmm0
	punpcklqdq xmm3, xmm1
	punpckhqdq xmm11, xmm1
	pshufd	xmm9, xmm4, 0x50
	pshufd	xmm12, xmm3, 0x50
	pshufd	xmm3, xmm3, 0xfa
	pshufd	xmm1, xmm4, 0xfa
	movaps	xmm4, xmm5
	pshufd	xmm0, xmm11, 0x50
	punpckhqdq xmm15, xmm3
	punpcklqdq xmm14, xmm3
	punpcklqdq xmm4, xmm12
	movaps	xmm3, xmm15
	movaps	xmm15, xmm2
	punpckhqdq xmm2, xmm9
	punpcklqdq xmm15, xmm9
	movaps	xmm9, [rsp]
	punpckhqdq xmm5, xmm12
	movaps	xmm12, xmm14
	movaps	xmm14, xmm9
	punpckhqdq xmm9, xmm1
	punpcklqdq xmm14, xmm1
	pshufd	xmm11, xmm11, 0xfa
	movaps	xmm1, xmm9
	movaps	xmm9, xmm13
	punpckhqdq xmm13, xmm0
	punpcklqdq xmm9, xmm0
	pshufd	xmm10, xmm8, 0x50
	movaps	[rsp], xmm13
	pshufd	xmm8, xmm8, 0xfa
	pshufd	xmm7, xmm6, 0x50
	pshufd	xmm6, xmm6, 0xfa
	movaps	xmm0, [rsp+0x10]
	movaps	xmm13, xmm0
	punpcklqdq xmm13, xmm11
	movaps	[rsp+0x40], xmm13
	movaps	xmm13, xmm0
	movaps	xmm0, xmm12
	punpckhqdq xmm13, xmm11
	movaps	xmm11, [rsp+0x20]
	pslld	xmm0, 1
	movaps	[rsp+0x10], xmm13
	movaps	xmm13, xmm11
	punpckhqdq xmm11, xmm10
	punpcklqdq xmm13, xmm10
	movaps	[rsp+0x20], xmm11
	movaps	[rsp+0x50], xmm13
	movaps	xmm11, [rsp+0x30]
	movaps	xmm10, xmm11
	punpckhqdq xmm11, xmm8
	punpcklqdq xmm10, xmm8
	movaps	xmm8, [rsp+0x70]
	movaps	xmm13, xmm11
	movaps	[rsp+0x60], xmm10
	movaps	xmm10, xmm8
	punpckhqdq xmm8, xmm7
	punpcklqdq xmm10, xmm7
	movaps	xmm11, [rsp+0x40]
	movaps	[rsp+0x70], xmm10
	movaps	[rsp+0x90], xmm8
	
	movaps	xmm8, xmm15
	pmuludq	xmm8, xmm5
	movaps	xmm10, [rsp+0x80]
	
	movaps	xmm7, xmm10
	punpcklqdq xmm7, xmm6
	movaps	[rsp+0xd0], xmm7
	
	movaps	xmm7, xmm10
	movaps	xmm10, xmm4
	punpckhqdq xmm7, xmm6
	movaps	xmm6, xmm4
	pmuludq	xmm10, xmm3
	pmuludq	xmm6, xmm5
	movaps	[rsp+0x80], xmm6
	
	movaps	xmm6, xmm12
	movaps	[rsp+0x30], xmm7
	movaps	xmm7, xmm0
	pmuludq	xmm6, xmm5
	paddq	xmm6, xmm10
	movaps	[rsp+0xa0], xmm6
	
	pmuludq	xmm7, xmm3
	movaps	xmm6, xmm0
	paddq	xmm7, xmm8
	movaps	xmm8, xmm15
	movaps	xmm0, xmm7
	movaps	xmm7, xmm14
	movaps	xmm10, xmm4
	pmuludq	xmm8, xmm3
	pmuludq	xmm7, xmm5
	paddq	xmm8, xmm7
	movaps	xmm7, xmm12
	pmuludq	xmm10, xmm2
	paddq	xmm0, xmm10
	movaps	xmm10, xmm4
	movaps	[rsp+0xb0], xmm0
	
	pmuludq	xmm7, xmm2
	paddq	xmm7, xmm8
	movaps	xmm0, xmm7
	pmuludq	xmm10, xmm1
	movaps	xmm7, xmm14
	paddq	xmm0, xmm10
	movaps	xmm10, xmm9
	pslld	xmm7, 1
	movaps	xmm8, xmm7
	pmuludq	xmm10, xmm5
	movaps	[rsp+0xc0], xmm0
	
	pmuludq	xmm8, xmm3
	paddq	xmm8, xmm10
	movaps	xmm10, xmm15
	pmuludq	xmm10, xmm2
	paddq	xmm10, xmm8
	movaps	xmm8, xmm6
	movaps	xmm0, [rsp]
	pmuludq	xmm8, xmm1
	paddq	xmm8, xmm10
	movaps	xmm10, xmm4
	pmuludq	xmm10, xmm0
	paddq	xmm8, xmm10
	movaps	xmm10, xmm9
	movaps	[rsp+0xf0], xmm8
	
	movaps	xmm8, xmm11
	pmuludq	xmm10, xmm3
	pslld	xmm11, 1
	pmuludq	xmm8, xmm5
	paddq	xmm10, xmm8
	movaps	xmm8, xmm14
	pmuludq	xmm8, xmm2
	paddq	xmm8, xmm10
	movaps	xmm10, xmm15
	pmuludq	xmm10, xmm1
	paddq	xmm10, xmm8
	movaps	xmm8, xmm12
	pmuludq	xmm8, [rsp]
	paddq	xmm8, xmm10
	movaps	xmm10, [rsp+0x10]
	movaps	xmm0, xmm8
	movaps	xmm8, xmm11
	pmuludq	xmm11, xmm1
	pmuludq	xmm10, xmm4
	paddq	xmm0, xmm10
	movaps	xmm10, [rsp+0x50]
	pmuludq	xmm8, xmm3
	pmuludq	xmm10, xmm5
	paddq	xmm8, xmm10
	movaps	xmm10, xmm9
	movaps	[rsp+0x100], xmm0
	
	pmuludq	xmm10, xmm2
	paddq	xmm10, xmm8
	movaps	xmm8, xmm7
	pmuludq	xmm8, xmm1
	paddq	xmm8, xmm10
	movaps	xmm10, xmm15
	movaps	xmm0, [rsp+0x20]
	pmuludq	xmm10, [rsp]
	paddq	xmm10, xmm8
	movaps	xmm8, [rsp+0x10]
	pmuludq	xmm8, xmm6
	paddq	xmm8, xmm10
	movaps	xmm10, xmm0
	pmuludq	xmm6, xmm13
	pmuludq	xmm10, xmm4
	paddq	xmm8, xmm10
	movaps	xmm10, [rsp+0x50]
	movaps	[rsp+0x110], xmm8
	
	pmuludq	xmm10, xmm3
	movaps	xmm8, [rsp+0x60]
	pmuludq	xmm8, xmm5
	paddq	xmm10, xmm8
	movaps	xmm8, [rsp+0x40]
	pmuludq	xmm8, xmm2
	paddq	xmm8, xmm10
	movaps	xmm10, xmm9
	pmuludq	xmm10, xmm1
	paddq	xmm10, xmm8
	movaps	xmm8, xmm14
	pmuludq	xmm8, [rsp]
	paddq	xmm8, xmm10
	movaps	xmm10, [rsp+0x10]
	pmuludq	xmm10, xmm15
	paddq	xmm10, xmm8
	movaps	xmm8, xmm0
	pmuludq	xmm8, xmm12
	paddq	xmm8, xmm10
	movaps	xmm10, xmm4
	movaps	xmm0, xmm8
	pmuludq	xmm10, xmm13
	paddq	xmm0, xmm10
	movaps	[rsp+0x120], xmm0
	
	movaps	xmm10, [rsp+0x60]
	movaps	xmm8, [rsp+0x70]
	pslld	xmm10, 1
	pmuludq	xmm10, xmm3
	pmuludq	xmm8, xmm5
	paddq	xmm10, xmm8
	movaps	xmm8, [rsp+0x50]
	pmuludq	xmm5, [rsp+0xd0]
	
	pmuludq	xmm8, xmm2
	paddq	xmm8, xmm10
	paddq	xmm11, xmm8
	movaps	xmm8, xmm9
	movaps	xmm0, [rsp+0x10]
	pmuludq	xmm8, [rsp]
	paddq	xmm8, xmm11
	movaps	xmm11, [rsp+0x20]
	pmuludq	xmm7, xmm0
	paddq	xmm7, xmm8
	movaps	xmm8, xmm11
	pmuludq	xmm8, xmm15
	paddq	xmm8, xmm7
	paddq	xmm6, xmm8
	movaps	xmm8, [rsp+0x90]
	
	movaps	xmm10, xmm8
	movaps	xmm7, [rsp+0x50]
	pmuludq	xmm10, xmm4
	paddq	xmm6, xmm10
	movaps	[rsp+0x130], xmm6
	
	movaps	xmm6, [rsp+0x70]
	pmuludq	xmm6, xmm3
	paddq	xmm6, xmm5
	movaps	xmm5, [rsp+0x60]
	movaps	xmm10, [rsp+0x40]
	pmuludq	xmm5, xmm2
	paddq	xmm5, xmm6
	movaps	xmm6, xmm7
	pmuludq	xmm6, xmm1
	paddq	xmm6, xmm5
	movaps	xmm5, xmm10
	pmuludq	xmm10, [.packednineteen]
	pmuludq	xmm5, [rsp]
	paddq	xmm5, xmm6
	movaps	xmm6, xmm0
	movaps	xmm0, [rsp+0x30]
	pmuludq	xmm6, xmm9
	paddq	xmm6, xmm5
	movaps	xmm5, xmm11
	pmuludq	xmm4, xmm0
	movaps	xmm11, xmm8
	pmuludq	xmm9, [.packednineteen]
	pmuludq	xmm5, xmm14
	paddq	xmm5, xmm6
	movaps	xmm6, xmm15
	pmuludq	xmm14, [.packednineteen]
	movaps	xmm0, xmm11
	pmuludq	xmm15, [.packednineteen]
	pmuludq	xmm6, xmm13
	paddq	xmm6, xmm5
	movaps	xmm5, xmm8
	pmuludq	xmm0, xmm15
	movaps	xmm11, xmm0
	movaps	xmm8, [rsp+0x60]
	pmuludq	xmm5, xmm12
	paddq	xmm5, xmm6
	paddq	xmm5, xmm4
	movaps	xmm4, xmm14
	pmuludq	xmm12, [.packednineteen]
	pslld	xmm12, 1
	pmuludq	xmm12, [rsp+0x30]
	paddq	xmm11, xmm12
	pmuludq	xmm8, [.packednineteen]
	pslld	xmm4, 1
	movaps	[rsp+0xe0], xmm4
	
	movaps	xmm4, xmm10
	movaps	xmm6, xmm8
	pslld	xmm4, 1
	movaps	[rsp+0x40], xmm4
	pslld	xmm6, 1
	movaps	[rsp+0x140], xmm5
	
	movaps	xmm5, xmm7
	movaps	[rsp+0x50], xmm6
	pmuludq	xmm5, [.packednineteen]
	movaps	xmm0, [rsp+0xe0]
	
	pmuludq	xmm0, xmm13
	movaps	xmm12, xmm0
	movaps	xmm0, [rsp+0x20]
	paddq	xmm12, xmm11
	pmuludq	xmm0, xmm9
	movaps	xmm11, xmm0
	movaps	xmm0, [rsp+0x40]
	paddq	xmm11, xmm12
	pmuludq	xmm0, [rsp+0x10]
	movaps	xmm12, xmm0
	movaps	xmm0, xmm5
	movaps	xmm4, [rsp+0x70]
	paddq	xmm12, xmm11
	pmuludq	xmm0, [rsp]
	movaps	xmm11, xmm0
	pmuludq	xmm4, [.packednineteen]
	movaps	xmm0, [rsp+0x50]
	paddq	xmm11, xmm12
	pmuludq	xmm0, xmm1
	movaps	xmm7, [rsp+0xd0]
	
	movaps	xmm12, xmm0
	movaps	xmm0, xmm4
	pmuludq	xmm7, [.packednineteen]
	movaps	xmm6, xmm7
	paddq	xmm12, xmm11
	pmuludq	xmm0, xmm2
	movaps	xmm11, xmm0
	movaps	xmm0, xmm9
	pslld	xmm6, 1
	pmuludq	xmm3, xmm6
	paddq	xmm11, xmm12
	paddq	xmm3, xmm11
	paddq	xmm3, [rsp+0x80]
	
	pmuludq	xmm0, xmm13
	movaps	[rsp+0x80], xmm3
	
	pmuludq	xmm15, [rsp+0x30]
	movaps	xmm3, xmm0
	pmuludq	xmm2, xmm7
	movaps	xmm12, [rsp+0x90]
	
	pmuludq	xmm14, xmm12
	paddq	xmm14, xmm15
	paddq	xmm3, xmm14
	movaps	xmm14, [rsp+0x20]
	movaps	xmm15, [rsp+0x10]
	movaps	xmm0, xmm14
	pmuludq	xmm0, xmm10
	movaps	xmm11, xmm0
	movaps	xmm0, xmm15
	paddq	xmm11, xmm3
	pmuludq	xmm0, xmm5
	movaps	xmm3, xmm0
	movaps	xmm0, xmm4
	paddq	xmm3, xmm11
	movaps	xmm11, xmm8
	pmuludq	xmm0, xmm1
	pmuludq	xmm1, xmm6
	pmuludq	xmm11, [rsp]
	paddq	xmm11, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, [rsp+0x40]
	paddq	xmm3, xmm11
	paddq	xmm2, xmm3
	paddq	xmm2, [rsp+0xa0]
	
	movaps	[rsp+0xa0], xmm2
	
	pmuludq	xmm0, xmm13
	movaps	xmm11, xmm12
	pmuludq	xmm10, xmm11
	movaps	xmm2, [rsp+0xe0]
	
	pmuludq	xmm2, [rsp+0x30]
	movaps	xmm3, xmm2
	movaps	xmm2, xmm12
	movaps	xmm12, [rsp+0x30]
	pmuludq	xmm2, xmm9
	paddq	xmm2, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, [rsp+0x50]
	pmuludq	xmm9, xmm12
	paddq	xmm10, xmm9
	paddq	xmm3, xmm2
	movaps	xmm2, xmm14
	pmuludq	xmm0, xmm15
	pmuludq	xmm2, xmm5
	paddq	xmm2, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, xmm15
	paddq	xmm3, xmm2
	movaps	xmm2, xmm4
	pmuludq	xmm0, xmm4
	pmuludq	xmm2, [rsp]
	paddq	xmm2, xmm3
	paddq	xmm1, xmm2
	movaps	xmm2, xmm5
	paddq	xmm1, [rsp+0xb0]
	
	movaps	[rsp+0xb0], xmm1
	
	pmuludq	xmm2, xmm13
	movaps	xmm1, xmm2
	movaps	xmm2, xmm14
	movaps	xmm3, xmm14
	paddq	xmm1, xmm10
	movaps	xmm14, xmm15
	pmuludq	xmm2, xmm8
	movaps	xmm10, [rsp+0xc0]
	
	paddq	xmm2, xmm1
	movaps	xmm1, xmm0
	pmuludq	xmm14, xmm6
	movaps	xmm15, xmm12
	movaps	xmm0, [rsp]
	paddq	xmm1, xmm2
	pmuludq	xmm0, xmm7
	movaps	xmm2, [rsp+0x40]
	paddq	xmm0, xmm1
	paddq	xmm10, xmm0
	movaps	xmm0, xmm11
	movaps	[rsp+0xc0], xmm10
	
	pmuludq	xmm2, xmm12
	movaps	xmm10, xmm11
	pmuludq	xmm0, xmm5
	paddq	xmm0, xmm2
	pmuludq	xmm5, xmm15
	pmuludq	xmm8, xmm10
	paddq	xmm8, xmm5
	movaps	xmm11, [rsp+0x50]
	movaps	xmm2, xmm11
	pmuludq	xmm2, xmm13
	movaps	xmm1, xmm2
	movaps	xmm2, xmm3
	paddq	xmm1, xmm0
	movaps	xmm0, xmm3
	pmuludq	xmm2, xmm7
	pmuludq	xmm7, xmm10
	pmuludq	xmm0, xmm4
	paddq	xmm0, xmm1
	movaps	xmm1, xmm14
	movaps	xmm14, xmm15
	movaps	xmm15, [rsp+0x100]
	
	paddq	xmm1, xmm0
	movaps	xmm0, [rsp+0xf0]
	
	paddq	xmm0, xmm1
	movaps	xmm1, xmm2
	movaps	xmm12, xmm0
	movaps	xmm0, xmm4
	movaps	xmm2, xmm11
	pmuludq	xmm0, xmm13
	pmuludq	xmm13, xmm6
	paddq	xmm0, xmm8
	paddq	xmm1, xmm0
	movaps	xmm0, xmm10
	paddq	xmm15, xmm1
	movaps	xmm1, xmm13
	movaps	xmm13, [rsp+0x110]
	
	pmuludq	xmm2, xmm14
	pmuludq	xmm0, xmm4
	paddq	xmm0, xmm2
	pmuludq	xmm4, xmm14
	paddq	xmm1, xmm0
	paddq	xmm13, xmm1
	movaps	xmm1, [rsp+0x80]
	
	paddq	xmm7, xmm4
	movaps	xmm2, xmm12
	pmuludq	xmm6, xmm14
	movaps	xmm3, xmm1
	movaps	xmm4, [rsp+0x130]
	
	paddq	xmm7, [rsp+0x120]
	
	pand	xmm1, [.packedmask26]
	psrlq	xmm2, 0x1a
	paddq	xmm2, xmm15
	movaps	xmm0, [.packedmask26]
	paddq	xmm4, xmm6
	movaps	xmm5, xmm2
	movaps	xmm14, xmm4
	psrlq	xmm3, 0x1a
	paddq	xmm3, [rsp+0xa0]
	
	movaps	xmm4, xmm3
	pand	xmm0, xmm12
	movaps	xmm2, xmm3
	psrlq	xmm4, 0x19
	movaps	xmm3, xmm5
	paddq	xmm4, [rsp+0xb0]
	
	movaps	xmm8, xmm4
	pand	xmm2, [.packedmask25]
	psrlq	xmm4, 0x1a
	psrlq	xmm3, 0x19
	paddq	xmm4, [rsp+0xc0]
	
	paddq	xmm3, xmm13
	pand	xmm8, [.packedmask26]
	movaps	xmm9, xmm3
	psrlq	xmm3, 0x1a
	paddq	xmm3, xmm7
	movaps	xmm10, xmm4
	movaps	xmm6, xmm3
	psrlq	xmm4, 0x19
	pand	xmm5, [.packedmask25]
	paddq	xmm0, xmm4
	psrlq	xmm3, 0x19
	paddq	xmm3, xmm14
	movaps	xmm15, xmm3
	psrlq	xmm3, 0x1a
	paddq	xmm3, [rsp+0x140]
	
	movaps	xmm4, xmm3
	psrlq	xmm3, 0x19
	pmuludq	xmm3, [.packednineteen]
	paddq	xmm1, xmm3
	movaps	xmm7, xmm1
	pand	xmm1, [.packedmask26]
	movaps	xmm3, xmm0
	psrlq	xmm7, 0x1a
	paddq	xmm2, xmm7
	movaps	xmm7, xmm8
	pand	xmm10, [.packedmask25]
	psrlq	xmm3, 0x1a
	paddq	xmm5, xmm3
	pand	xmm9, [.packedmask26]
	movaps	xmm3, xmm1
	pand	xmm0, [.packedmask26]
	pand	xmm6, [.packedmask25]
	punpckldq xmm7, xmm10
	punpckldq xmm3, xmm2
	movaps	xmm13, xmm0
	pand	xmm15, [.packedmask26]
	punpcklqdq xmm3, xmm7
	movaps	xmm7, xmm9
	pand	xmm4, [.packedmask25]
	punpckldq xmm7, xmm6
	punpckldq xmm13, xmm5
	punpckhdq xmm8, xmm10
	punpckhdq xmm1, xmm2
	punpckhdq xmm9, xmm6
	punpckhdq xmm0, xmm5
	punpcklqdq xmm13, xmm7
	movaps	xmm7, xmm15
	punpcklqdq xmm1, xmm8
	punpckldq xmm7, xmm4
	punpcklqdq xmm0, xmm9
	punpckhdq xmm15, xmm4
	je     .lowloop_done
	movaps	xmm12, xmm0
	movaps	xmm2, xmm1
	movaps	xmm4, xmm7
	jmp	.lowloop
calign
.lowloop_done:
	movaps	xmm2, xmm1
	lea	rsi, [rsp+0x370]
	
	movaps	xmm12, xmm0
	lea	rdi, [rsp+0x3d0]
	
	movaps	xmm0, xmm7
	mov	edx, 1
	movaps	[rsp+0x310], xmm3
	movaps	[rsp+0x330], xmm0
	movaps	[rsp+0x370], xmm2
	movaps	[rsp+0x380], xmm12
	movaps	[rsp+0x390], xmm15
	movaps	[rsp+0x320], xmm13
	call	curve25519$square_times
	pshufd	xmm9, [rsp+0x3f0], 0xd8
	
	mov	eax, 2
	movaps	xmm0, [rsp+0x3d0]
	
	movaps	xmm14, xmm9
	pshufd	xmm2, xmm0, 0xd8
	pshufd	xmm15, xmm0, 0xfa
	movaps	xmm0, [rsp+0x3e0]
	
	pshufd	xmm1, xmm0, 0xd8
	pshufd	xmm0, xmm0, 0xfa
	movaps	xmm3, xmm2
	movaps	xmm12, xmm1
	movaps	xmm10, xmm0
calign
.squaretimes2:
	movaps	xmm0, xmm15
	sub	eax, 1
	movaps	xmm2, xmm3
	pslldq	xmm0, 0x8
	pshufd	xmm1, xmm15, 0
	movaps	xmm4, xmm15
	punpckhqdq xmm2, xmm0
	pshufd	xmm0, xmm3, 0
	movaps	xmm7, [.sse2_top64bitmask]
	pshufd	xmm6, xmm3, 0xaa
	movaps	[rsp], xmm2
	pshufd	xmm5, xmm15, 0xaa
	pslld	xmm6, 1
	movaps	xmm2, [.sse2_top64bitmask]
	pslld	xmm5, 1
	pand	xmm2, xmm0
	paddq	xmm2, xmm0
	movaps	xmm0, [.sse2_top64bitmask]
	pshufd	xmm8, xmm2, 0xe6
	pmuludq	xmm2, xmm3
	movaps	xmm3, xmm12
	pand	xmm0, xmm1
	pmuludq	xmm3, xmm8
	paddq	xmm0, xmm1
	movaps	xmm1, xmm12
	pshufd	xmm13, xmm0, 0xe6
	pmuludq	xmm0, xmm15
	paddq	xmm3, xmm0
	pslldq	xmm1, 0x8
	punpckhqdq xmm4, xmm1
	movaps	xmm0, xmm15
	pshufd	xmm1, xmm12, 0
	pslld	xmm0, 1
	movaps	[rsp+0xb0], xmm0
	
	movaps	xmm0, xmm10
	pand	xmm7, xmm1
	movaps	[rsp+0x10], xmm4
	pmuludq	xmm0, xmm8
	movaps	xmm4, xmm10
	movaps	xmm11, xmm7
	movaps	xmm7, xmm12
	paddq	xmm11, xmm1
	movaps	xmm1, xmm10
	pslldq	xmm1, 0x8
	punpckhqdq xmm7, xmm1
	movaps	xmm1, xmm7
	pmuludq	xmm1, [.packednineteen]
	pshufd	xmm9, xmm1, 0x54
	pshufd	xmm1, xmm1, 0xee
	movaps	[rsp+0x20], xmm9
	movaps	xmm9, xmm10
	movaps	[rsp+0x30], xmm1
	movaps	xmm1, xmm14
	pslldq	xmm1, 0x8
	punpckhqdq xmm9, xmm1
	pxor	xmm1, xmm1
	movaps	[rsp+0x40], xmm9
	pshufd	xmm9, xmm10, 0xaa
	punpcklqdq xmm4, xmm1
	pmuludq	xmm9, [.packed3819]
	pshufd	xmm1, xmm9, 0xfe
	movaps	[rsp+0x50], xmm4
	pxor	xmm4, xmm4
	movaps	[rsp+0x60], xmm1
	movaps	xmm1, xmm14
	punpcklqdq xmm1, xmm4
	movaps	[rsp+0x70], xmm1
	pshufd	xmm1, xmm14, 0
	movaps	xmm4, xmm1
	pshufd	xmm1, xmm14, 0xfe
	pmuludq	xmm4, [.packednineteen]
	movaps	[rsp+0x80], xmm4
	
	pshufd	xmm4, xmm14, 0xaa
	pslld	xmm1, 1
	movaps	[rsp+0x90], xmm1
	
	pmuludq	xmm4, [.packed3819]
	pshufd	xmm1, xmm4, 0xaa
	movaps	[rsp+0xa0], xmm1
	
	movaps	xmm1, xmm15
	movaps	xmm15, xmm12
	pmuludq	xmm1, xmm8
	pmuludq	xmm8, xmm14
	movaps	xmm14, xmm10
	pmuludq	xmm15, xmm13
	pmuludq	xmm13, xmm10
	movaps	xmm10, xmm11
	paddq	xmm8, xmm13
	movaps	xmm11, [rsp+0x10]
	paddq	xmm0, xmm15
	pmuludq	xmm10, xmm12
	paddq	xmm8, xmm10
	pslld	xmm12, 1
	movaps	xmm10, [.sse2_bot64bitmask]
	pslld	xmm14, 1
	pand	xmm10, xmm6
	movaps	xmm15, [rsp]
	paddq	xmm10, xmm6
	pmuludq	xmm6, xmm15
	paddq	xmm1, xmm6
	movaps	xmm6, xmm11
	movaps	xmm13, [.sse2_bot64bitmask]
	pmuludq	xmm6, xmm10
	paddq	xmm3, xmm6
	movaps	xmm6, xmm7
	pand	xmm13, xmm5
	pmuludq	xmm6, xmm10
	paddq	xmm0, xmm6
	movaps	xmm6, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	paddq	xmm13, xmm5
	pslld	xmm6, 1
	pmuludq	xmm5, xmm11
	pmuludq	xmm6, xmm4
	paddq	xmm0, xmm5
	pslld	xmm11, 1
	movaps	xmm5, [rsp+0x40]
	paddq	xmm2, xmm6
	pmuludq	xmm13, xmm7
	movaps	xmm6, xmm11
	pslld	xmm7, 1
	pmuludq	xmm11, xmm4
	pmuludq	xmm10, xmm5
	paddq	xmm8, xmm10
	paddq	xmm8, xmm13
	pmuludq	xmm6, xmm9
	movaps	xmm13, [rsp+0x30]
	paddq	xmm2, xmm6
	pmuludq	xmm9, xmm7
	pslld	xmm5, 1
	paddq	xmm1, xmm11
	movaps	xmm6, [rsp+0x20]
	paddq	xmm1, xmm9
	pmuludq	xmm6, xmm7
	pmuludq	xmm7, xmm4
	paddq	xmm2, xmm6
	paddq	xmm3, xmm7
	movaps	xmm6, xmm13
	pmuludq	xmm4, xmm5
	movaps	xmm7, [rsp+0x80]
	
	paddq	xmm0, xmm4
	pmuludq	xmm6, xmm12
	pmuludq	xmm15, xmm7
	paddq	xmm2, xmm15
	paddq	xmm2, xmm6
	movaps	xmm6, [rsp+0x50]
	pmuludq	xmm12, xmm7
	paddq	xmm1, xmm12
	movaps	xmm12, xmm2
	pmuludq	xmm14, xmm7
	pmuludq	xmm6, xmm13
	movaps	xmm4, [rsp+0x70]
	paddq	xmm1, xmm6
	movaps	xmm10, xmm1
	movaps	xmm6, [rsp+0x60]
	pmuludq	xmm4, xmm7
	paddq	xmm0, xmm4
	punpcklqdq xmm10, xmm0
	pmuludq	xmm6, xmm5
	movaps	xmm4, [rsp+0x90]
	
	paddq	xmm3, xmm6
	paddq	xmm3, xmm14
	punpcklqdq xmm12, xmm3
	punpckhqdq xmm2, xmm3
	pmuludq	xmm4, [rsp+0xa0]
	
	paddq	xmm8, xmm4
	punpckhqdq xmm1, xmm0
	movaps	xmm14, xmm8
	movaps	xmm0, xmm10
	pand	xmm10, [.packedmask26]
	movaps	xmm3, xmm12
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	movaps	xmm0, xmm1
	punpcklqdq xmm14, xmm8
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	movaps	xmm3, xmm2
	punpckhqdq xmm8, xmm8
	psrlq	xmm0, 0x19
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x19
	paddq	xmm14, xmm0
	paddq	xmm10, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, xmm14
	pand	xmm2, [.packedmask25]
	pslldq	xmm3, 0x8
	psrlq	xmm0, 0x1a
	paddq	xmm8, xmm0
	movaps	xmm0, xmm8
	pand	xmm1, [.packedmask25]
	psrlq	xmm0, 0x19
	pmuludq	xmm0, [.packednineteen]
	punpckhqdq xmm0, xmm3
	pand	xmm14, [.packedmask26]
	paddq	xmm12, xmm0
	movaps	xmm0, xmm10
	movaps	xmm3, xmm12
	pand	xmm10, [.packedmask26]
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	pand	xmm8, [.packedmask25]
	movaps	xmm15, xmm10
	punpckhqdq xmm10, xmm1
	movaps	xmm3, xmm12
	punpcklqdq xmm15, xmm1
	punpckhqdq xmm12, xmm2
	punpcklqdq xmm3, xmm2
	punpckhqdq xmm14, xmm8
	jne	.squaretimes2
	pshufd	xmm0, xmm12, 0xf8
	lea	rdx, [rsp+0x370]
	
	pshufd	xmm15, xmm15, 0x8f
	lea	rsi, [rsp+0x400]
	
	pshufd	xmm1, xmm10, 0x8f
	lea	rdi, [rsp+0x430]
	
	pshufd	xmm2, xmm3, 0xf8
	por	xmm1, xmm0
	por	xmm2, xmm15
	pshufd	xmm0, xmm14, 0xf8
	movaps	[rsp+0x410], xmm1
	movaps	[rsp+0x400], xmm2
	movaps	[rsp+0x420], xmm0
	call	curve25519$mul
	lea	rdx, [rsp+0x3d0]
	lea	rsi, [rsp+0x430]
	mov	rdi, rdx
	call	curve25519$mul
	lea	rsi, [rsp+0x3d0]
	lea	rdi, [rsp+0x400]
	mov	edx, 1
	call	curve25519$square_times
	lea	rdx, [rsp+0x430]
	lea	rsi, [rsp+0x400]
	mov	rdi, rdx
	call	curve25519$mul
	lea	rsi, [rsp+0x430]
	lea	rdi, [rsp+0x460]
	mov	edx, 5
	call	curve25519$square_times
	lea	rdx, [rsp+0x430]
	lea	rsi, [rsp+0x460]
	mov	rdi, rdx
	call	curve25519$mul
	lea	rsi, [rsp+0x430]
	lea	rdi, [rsp+0x460]
	mov	edx, 10
	call	curve25519$square_times
	lea	rdx, [rsp+0x430]
	lea	rsi, [rsp+0x460]
	lea	rdi, [rsp+0x490]
	call	curve25519$mul
	movaps	xmm0, [rsp+0x490]
	
	mov	eax, 20
	pshufd	xmm9, [rsp+0x4b0], 0xd8
	
	pshufd	xmm2, xmm0, 0xd8
	pshufd	xmm15, xmm0, 0xfa
	movaps	xmm0, [rsp+0x4a0]
	
	movaps	xmm14, xmm9
	pshufd	xmm1, xmm0, 0xd8
	movaps	xmm3, xmm2
	pshufd	xmm0, xmm0, 0xfa
	movaps	xmm12, xmm1
	movaps	xmm10, xmm0

calign
.squaretimes20:
	movaps	xmm0, xmm15
	sub	eax, 1
	movaps	xmm2, xmm3
	pslldq	xmm0, 0x8
	pshufd	xmm1, xmm15, 0
	movaps	xmm4, xmm15
	punpckhqdq xmm2, xmm0
	pshufd	xmm0, xmm3, 0
	movaps	xmm7, [.sse2_top64bitmask]
	pshufd	xmm6, xmm3, 0xaa
	movaps	[rsp], xmm2
	pshufd	xmm5, xmm15, 0xaa
	pslld	xmm6, 1
	movaps	xmm2, [.sse2_top64bitmask]
	pslld	xmm5, 1
	pand	xmm2, xmm0
	paddq	xmm2, xmm0
	movaps	xmm0, [.sse2_top64bitmask]
	pshufd	xmm8, xmm2, 0xe6
	pmuludq	xmm2, xmm3
	movaps	xmm3, xmm12
	pand	xmm0, xmm1
	pmuludq	xmm3, xmm8
	paddq	xmm0, xmm1
	movaps	xmm1, xmm12
	pshufd	xmm13, xmm0, 0xe6
	pmuludq	xmm0, xmm15
	paddq	xmm3, xmm0
	pslldq	xmm1, 0x8
	punpckhqdq xmm4, xmm1
	movaps	xmm0, xmm15
	pshufd	xmm1, xmm12, 0
	pslld	xmm0, 1
	movaps	[rsp+0xb0], xmm0
	
	movaps	xmm0, xmm10
	pand	xmm7, xmm1
	movaps	[rsp+0x10], xmm4
	pmuludq	xmm0, xmm8
	movaps	xmm4, xmm10
	movaps	xmm11, xmm7
	movaps	xmm7, xmm12
	paddq	xmm11, xmm1
	movaps	xmm1, xmm10
	pslldq	xmm1, 0x8
	punpckhqdq xmm7, xmm1
	movaps	xmm1, xmm7
	pmuludq	xmm1, [.packednineteen]
	pshufd	xmm9, xmm1, 0x54
	pshufd	xmm1, xmm1, 0xee
	movaps	[rsp+0x20], xmm9
	movaps	xmm9, xmm10
	movaps	[rsp+0x30], xmm1
	movaps	xmm1, xmm14
	pslldq	xmm1, 0x8
	punpckhqdq xmm9, xmm1
	pxor	xmm1, xmm1
	movaps	[rsp+0x40], xmm9
	pshufd	xmm9, xmm10, 0xaa
	punpcklqdq xmm4, xmm1
	pmuludq	xmm9, [.packed3819]
	pshufd	xmm1, xmm9, 0xfe
	movaps	[rsp+0x50], xmm4
	pxor	xmm4, xmm4
	movaps	[rsp+0x60], xmm1
	movaps	xmm1, xmm14
	punpcklqdq xmm1, xmm4
	movaps	[rsp+0x70], xmm1
	pshufd	xmm1, xmm14, 0
	movaps	xmm4, xmm1
	pshufd	xmm1, xmm14, 0xfe
	pmuludq	xmm4, [.packednineteen]
	movaps	[rsp+0x80], xmm4
	
	pshufd	xmm4, xmm14, 0xaa
	pslld	xmm1, 1
	movaps	[rsp+0x90], xmm1
	
	pmuludq	xmm4, [.packed3819]
	pshufd	xmm1, xmm4, 0xaa
	movaps	[rsp+0xa0], xmm1
	
	movaps	xmm1, xmm15
	movaps	xmm15, xmm12
	pmuludq	xmm1, xmm8
	pmuludq	xmm8, xmm14
	movaps	xmm14, xmm10
	pmuludq	xmm15, xmm13
	pmuludq	xmm13, xmm10
	movaps	xmm10, xmm11
	paddq	xmm8, xmm13
	movaps	xmm11, [rsp+0x10]
	paddq	xmm0, xmm15
	pmuludq	xmm10, xmm12
	paddq	xmm8, xmm10
	pslld	xmm12, 1
	movaps	xmm10, [.sse2_bot64bitmask]
	pslld	xmm14, 1
	pand	xmm10, xmm6
	movaps	xmm15, [rsp]
	paddq	xmm10, xmm6
	pmuludq	xmm6, xmm15
	paddq	xmm1, xmm6
	movaps	xmm6, xmm11
	movaps	xmm13, [.sse2_bot64bitmask]
	pmuludq	xmm6, xmm10
	paddq	xmm3, xmm6
	movaps	xmm6, xmm7
	pand	xmm13, xmm5
	pmuludq	xmm6, xmm10
	paddq	xmm0, xmm6
	movaps	xmm6, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	paddq	xmm13, xmm5
	pslld	xmm6, 1
	pmuludq	xmm5, xmm11
	pmuludq	xmm6, xmm4
	paddq	xmm0, xmm5
	pslld	xmm11, 1
	movaps	xmm5, [rsp+0x40]
	paddq	xmm2, xmm6
	pmuludq	xmm13, xmm7
	movaps	xmm6, xmm11
	pslld	xmm7, 1
	pmuludq	xmm11, xmm4
	pmuludq	xmm10, xmm5
	paddq	xmm8, xmm10
	paddq	xmm8, xmm13
	pmuludq	xmm6, xmm9
	movaps	xmm13, [rsp+0x30]
	paddq	xmm2, xmm6
	pmuludq	xmm9, xmm7
	pslld	xmm5, 1
	paddq	xmm1, xmm11
	movaps	xmm6, [rsp+0x20]
	paddq	xmm1, xmm9
	pmuludq	xmm6, xmm7
	pmuludq	xmm7, xmm4
	paddq	xmm2, xmm6
	paddq	xmm3, xmm7
	movaps	xmm6, xmm13
	pmuludq	xmm4, xmm5
	movaps	xmm7, [rsp+0x80]
	
	paddq	xmm0, xmm4
	pmuludq	xmm6, xmm12
	pmuludq	xmm15, xmm7
	paddq	xmm2, xmm15
	paddq	xmm2, xmm6
	movaps	xmm6, [rsp+0x50]
	pmuludq	xmm12, xmm7
	paddq	xmm1, xmm12
	movaps	xmm12, xmm2
	pmuludq	xmm14, xmm7
	pmuludq	xmm6, xmm13
	movaps	xmm4, [rsp+0x70]
	paddq	xmm1, xmm6
	movaps	xmm10, xmm1
	movaps	xmm6, [rsp+0x60]
	pmuludq	xmm4, xmm7
	paddq	xmm0, xmm4
	punpcklqdq xmm10, xmm0
	pmuludq	xmm6, xmm5
	movaps	xmm4, [rsp+0x90]
	
	paddq	xmm3, xmm6
	paddq	xmm3, xmm14
	punpcklqdq xmm12, xmm3
	punpckhqdq xmm2, xmm3
	pmuludq	xmm4, [rsp+0xa0]
	
	paddq	xmm8, xmm4
	punpckhqdq xmm1, xmm0
	movaps	xmm14, xmm8
	movaps	xmm0, xmm10
	pand	xmm10, [.packedmask26]
	movaps	xmm3, xmm12
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	movaps	xmm0, xmm1
	punpcklqdq xmm14, xmm8
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	movaps	xmm3, xmm2
	punpckhqdq xmm8, xmm8
	psrlq	xmm0, 0x19
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x19
	paddq	xmm14, xmm0
	paddq	xmm10, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, xmm14
	pand	xmm2, [.packedmask25]
	pslldq	xmm3, 0x8
	psrlq	xmm0, 0x1a
	paddq	xmm8, xmm0
	movaps	xmm0, xmm8
	pand	xmm1, [.packedmask25]
	psrlq	xmm0, 0x19
	pmuludq	xmm0, [.packednineteen]
	punpckhqdq xmm0, xmm3
	pand	xmm14, [.packedmask26]
	paddq	xmm12, xmm0
	movaps	xmm0, xmm10
	movaps	xmm3, xmm12
	pand	xmm10, [.packedmask26]
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	pand	xmm8, [.packedmask25]
	movaps	xmm15, xmm10
	punpckhqdq xmm10, xmm1
	movaps	xmm3, xmm12
	punpcklqdq xmm15, xmm1
	punpckhqdq xmm12, xmm2
	punpcklqdq xmm3, xmm2
	punpckhqdq xmm14, xmm8
	jne	.squaretimes20
	pshufd	xmm0, xmm12, 0xf8
	lea	rsi, [rsp+0x460]
	
	pshufd	xmm15, xmm15, 0x8f
	lea	rdx, [rsp+0x490]
	
	pshufd	xmm1, xmm10, 0x8f
	mov	rdi, rsi
	pshufd	xmm2, xmm3, 0xf8
	por	xmm1, xmm0
	por	xmm2, xmm15
	pshufd	xmm0, xmm14, 0xf8
	movaps	[rsp+0x470], xmm1
	movaps	[rsp+0x460], xmm2
	movaps	[rsp+0x480], xmm0
	call	curve25519$mul
	lea	rsi, [rsp+0x460]
	mov	rdi, rsi
	mov	edx, 10
	call	curve25519$square_times
	lea	rdx, [rsp+0x430]
	lea	rsi, [rsp+0x460]
	mov	rdi, rdx
	call	curve25519$mul
	lea	rsi, [rsp+0x430]
	lea	rdi, [rsp+0x460]
	mov	edx, 50
	call	curve25519$square_times
	lea	rdx, [rsp+0x430]
	lea	rsi, [rsp+0x460]
	lea	rdi, [rsp+0x490]
	call	curve25519$mul
	movaps	xmm0, [rsp+0x490]
	
	mov	eax, 100
	pshufd	xmm9, [rsp+0x4b0], 0xd8
	
	pshufd	xmm2, xmm0, 0xd8
	pshufd	xmm15, xmm0, 0xfa
	movaps	xmm0, [rsp+0x4a0]
	
	movaps	xmm14, xmm9
	pshufd	xmm1, xmm0, 0xd8
	movaps	xmm3, xmm2
	pshufd	xmm0, xmm0, 0xfa
	movaps	xmm12, xmm1
	movaps	xmm10, xmm0
	
calign
.squaretimes100:
	movaps	xmm0, xmm15
	sub	eax, 1
	movaps	xmm2, xmm3
	pslldq	xmm0, 0x8
	pshufd	xmm1, xmm15, 0
	movaps	xmm4, xmm15
	punpckhqdq xmm2, xmm0
	pshufd	xmm0, xmm3, 0
	movaps	xmm7, [.sse2_top64bitmask]
	pshufd	xmm6, xmm3, 0xaa
	movaps	[rsp], xmm2
	pshufd	xmm5, xmm15, 0xaa
	pslld	xmm6, 1
	movaps	xmm2, [.sse2_top64bitmask]
	pslld	xmm5, 1
	pand	xmm2, xmm0
	paddq	xmm2, xmm0
	movaps	xmm0, [.sse2_top64bitmask]
	pshufd	xmm8, xmm2, 0xe6
	pmuludq	xmm2, xmm3
	movaps	xmm3, xmm12
	pand	xmm0, xmm1
	pmuludq	xmm3, xmm8
	paddq	xmm0, xmm1
	movaps	xmm1, xmm12
	pshufd	xmm13, xmm0, 0xe6
	pmuludq	xmm0, xmm15
	paddq	xmm3, xmm0
	pslldq	xmm1, 0x8
	punpckhqdq xmm4, xmm1
	movaps	xmm0, xmm15
	pshufd	xmm1, xmm12, 0
	pslld	xmm0, 1
	movaps	[rsp+0xb0], xmm0
	
	movaps	xmm0, xmm10
	pand	xmm7, xmm1
	movaps	[rsp+0x10], xmm4
	pmuludq	xmm0, xmm8
	movaps	xmm4, xmm10
	movaps	xmm11, xmm7
	movaps	xmm7, xmm12
	paddq	xmm11, xmm1
	movaps	xmm1, xmm10
	pslldq	xmm1, 0x8
	punpckhqdq xmm7, xmm1
	movaps	xmm1, xmm7
	pmuludq	xmm1, [.packednineteen]
	pshufd	xmm9, xmm1, 0x54
	pshufd	xmm1, xmm1, 0xee
	movaps	[rsp+0x20], xmm9
	movaps	xmm9, xmm10
	movaps	[rsp+0x30], xmm1
	movaps	xmm1, xmm14
	pslldq	xmm1, 0x8
	punpckhqdq xmm9, xmm1
	pxor	xmm1, xmm1
	movaps	[rsp+0x40], xmm9
	pshufd	xmm9, xmm10, 0xaa
	punpcklqdq xmm4, xmm1
	pmuludq	xmm9, [.packed3819]
	pshufd	xmm1, xmm9, 0xfe
	movaps	[rsp+0x50], xmm4
	pxor	xmm4, xmm4
	movaps	[rsp+0x60], xmm1
	movaps	xmm1, xmm14
	punpcklqdq xmm1, xmm4
	movaps	[rsp+0x70], xmm1
	pshufd	xmm1, xmm14, 0
	movaps	xmm4, xmm1
	pshufd	xmm1, xmm14, 0xfe
	pmuludq	xmm4, [.packednineteen]
	movaps	[rsp+0x80], xmm4
	
	pshufd	xmm4, xmm14, 0xaa
	pslld	xmm1, 1
	movaps	[rsp+0x90], xmm1
	
	pmuludq	xmm4, [.packed3819]
	pshufd	xmm1, xmm4, 0xaa
	movaps	[rsp+0xa0], xmm1
	
	movaps	xmm1, xmm15
	movaps	xmm15, xmm12
	pmuludq	xmm1, xmm8
	pmuludq	xmm8, xmm14
	movaps	xmm14, xmm10
	pmuludq	xmm15, xmm13
	pmuludq	xmm13, xmm10
	movaps	xmm10, xmm11
	paddq	xmm8, xmm13
	movaps	xmm11, [rsp+0x10]
	paddq	xmm0, xmm15
	pmuludq	xmm10, xmm12
	paddq	xmm8, xmm10
	pslld	xmm12, 1
	movaps	xmm10, [.sse2_bot64bitmask]
	pslld	xmm14, 1
	pand	xmm10, xmm6
	movaps	xmm15, [rsp]
	paddq	xmm10, xmm6
	pmuludq	xmm6, xmm15
	paddq	xmm1, xmm6
	movaps	xmm6, xmm11
	movaps	xmm13, [.sse2_bot64bitmask]
	pmuludq	xmm6, xmm10
	paddq	xmm3, xmm6
	movaps	xmm6, xmm7
	pand	xmm13, xmm5
	pmuludq	xmm6, xmm10
	paddq	xmm0, xmm6
	movaps	xmm6, xmm15
	movaps	xmm15, [rsp+0xb0]
	
	paddq	xmm13, xmm5
	pslld	xmm6, 1
	pmuludq	xmm5, xmm11
	pmuludq	xmm6, xmm4
	paddq	xmm0, xmm5
	pslld	xmm11, 1
	movaps	xmm5, [rsp+0x40]
	paddq	xmm2, xmm6
	pmuludq	xmm13, xmm7
	movaps	xmm6, xmm11
	pslld	xmm7, 1
	pmuludq	xmm11, xmm4
	pmuludq	xmm10, xmm5
	paddq	xmm8, xmm10
	paddq	xmm8, xmm13
	pmuludq	xmm6, xmm9
	movaps	xmm13, [rsp+0x30]
	paddq	xmm2, xmm6
	pmuludq	xmm9, xmm7
	pslld	xmm5, 1
	paddq	xmm1, xmm11
	movaps	xmm6, [rsp+0x20]
	paddq	xmm1, xmm9
	pmuludq	xmm6, xmm7
	pmuludq	xmm7, xmm4
	paddq	xmm2, xmm6
	paddq	xmm3, xmm7
	movaps	xmm6, xmm13
	pmuludq	xmm4, xmm5
	movaps	xmm7, [rsp+0x80]
	
	paddq	xmm0, xmm4
	pmuludq	xmm6, xmm12
	pmuludq	xmm15, xmm7
	paddq	xmm2, xmm15
	paddq	xmm2, xmm6
	movaps	xmm6, [rsp+0x50]
	pmuludq	xmm12, xmm7
	paddq	xmm1, xmm12
	movaps	xmm12, xmm2
	pmuludq	xmm14, xmm7
	pmuludq	xmm6, xmm13
	movaps	xmm4, [rsp+0x70]
	paddq	xmm1, xmm6
	movaps	xmm10, xmm1
	movaps	xmm6, [rsp+0x60]
	pmuludq	xmm4, xmm7
	paddq	xmm0, xmm4
	punpcklqdq xmm10, xmm0
	pmuludq	xmm6, xmm5
	movaps	xmm4, [rsp+0x90]
	
	paddq	xmm3, xmm6
	paddq	xmm3, xmm14
	punpcklqdq xmm12, xmm3
	punpckhqdq xmm2, xmm3
	pmuludq	xmm4, [rsp+0xa0]
	
	paddq	xmm8, xmm4
	punpckhqdq xmm1, xmm0
	movaps	xmm14, xmm8
	movaps	xmm0, xmm10
	pand	xmm10, [.packedmask26]
	movaps	xmm3, xmm12
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	movaps	xmm0, xmm1
	punpcklqdq xmm14, xmm8
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	movaps	xmm3, xmm2
	punpckhqdq xmm8, xmm8
	psrlq	xmm0, 0x19
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x19
	paddq	xmm14, xmm0
	paddq	xmm10, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, xmm14
	pand	xmm2, [.packedmask25]
	pslldq	xmm3, 0x8
	psrlq	xmm0, 0x1a
	paddq	xmm8, xmm0
	movaps	xmm0, xmm8
	pand	xmm1, [.packedmask25]
	psrlq	xmm0, 0x19
	pmuludq	xmm0, [.packednineteen]
	punpckhqdq xmm0, xmm3
	pand	xmm14, [.packedmask26]
	paddq	xmm12, xmm0
	movaps	xmm0, xmm10
	movaps	xmm3, xmm12
	pand	xmm10, [.packedmask26]
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	pand	xmm8, [.packedmask25]
	movaps	xmm15, xmm10
	punpckhqdq xmm10, xmm1
	movaps	xmm3, xmm12
	punpcklqdq xmm15, xmm1
	punpckhqdq xmm12, xmm2
	punpcklqdq xmm3, xmm2
	punpckhqdq xmm14, xmm8
	jne	.squaretimes100
	pshufd	xmm0, xmm12, 0xf8
	lea	rsi, [rsp+0x460]
	
	pshufd	xmm15, xmm15, 0x8f
	lea	rdx, [rsp+0x490]
	
	pshufd	xmm1, xmm10, 0x8f
	mov	rdi, rsi
	pshufd	xmm2, xmm3, 0xf8
	por	xmm1, xmm0
	por	xmm2, xmm15
	pshufd	xmm0, xmm14, 0xf8
	movaps	[rsp+0x470], xmm1
	movaps	[rsp+0x460], xmm2
	movaps	[rsp+0x480], xmm0
	call	curve25519$mul
	lea	rsi, [rsp+0x460]
	mov	rdi, rsi
	mov	edx, 50
	call	curve25519$square_times
	lea	rdx, [rsp+0x430]
	lea	rsi, [rsp+0x460]
	mov	rdi, rdx
	call	curve25519$mul
	lea	rsi, [rsp+0x430]
	mov	rdi, rsi
	mov	edx, 5
	call	curve25519$square_times
	lea	rdx, [rsp+0x3d0]
	lea	rsi, [rsp+0x430]
	lea	rdi, [rsp+0x460]
	call	curve25519$mul
	lea	rdx, [rsp+0x460]
	lea	rdi, [rsp+0x370]
	mov	rsi, rbx
	call	curve25519$mul
	mov	r11d, [rsp+0x370]
	
	mov	edx, [rsp+0x380]
	movaps	xmm2, [rsp+0x370]
	
	mov	eax, [rsp+0x390]
	mov	r9d, r11d
	and	r11d, 0x3ffffff
	movaps	[rsp+0x490], xmm2
	
	shr	r9d, 0x1a
	add	r9d, [rsp+0x494]
	
	movaps	xmm2, [rsp+0x380]
	
	mov	r8d, r9d
	and	r9d, 0x1ffffff
	shr	r8d, 0x19
	add	r8d, [rsp+0x498]
	
	movaps	[rsp+0x4a0], xmm2
	
	mov	edi, r8d
	and	r8d, 0x3ffffff
	shr	edi, 0x1a
	add	edi, [rsp+0x49c]
	movaps	xmm2, [rsp+0x390]
	
	movaps	[rsp+0x4b0], xmm2
	
	mov	r14d, edi
	shr	r14d, 0x19
	add	r14d, edx
	mov	esi, r14d
	shr	esi, 0x1a
	add	esi, [rsp+0x4a4]
	mov	ecx, esi
	shr	ecx, 0x19
	add	ecx, [rsp+0x4a8]
	mov	edx, ecx
	shr	edx, 0x1a
	add	edx, [rsp+0x4ac]
	mov	r12d, edx
	shr	r12d, 0x19
	add	r12d, eax
	mov	eax, r12d
	shr	eax, 0x1a
	add	eax, [rsp+0x4b4]
	mov	r10d, eax
	shr	r10d, 0x19
	lea	ebx, [r10+r10*8]
	lea	ebx, [r10+rbx*2]
	add	ebx, r11d
	mov	r11d, ebx
	shr	r11d, 0x1a
	add	r11d, r9d
	mov	r10d, r11d
	shr	r10d, 0x19
	add	r10d, r8d
	mov	r13d, r10d
	shr	r13d, 0x1a
	and	edi, 0x1ffffff
	and	r14d, 0x3ffffff
	add	r13d, edi
	and	esi, 0x1ffffff
	and	ecx, 0x3ffffff
	mov	r9d, r13d
	and	edx, 0x1ffffff
	and	r12d, 0x3ffffff
	shr	r9d, 0x19
	and	eax, 0x1ffffff
	and	ebx, 0x3ffffff
	add	r9d, r14d
	and	r11d, 0x1ffffff
	and	r10d, 0x3ffffff
	mov	r14d, r9d
	and	r13d, 0x1ffffff
	shr	r14d, 0x1a
	add	r14d, esi
	mov	r8d, r14d
	shr	r8d, 0x19
	add	r8d, ecx
	mov	esi, r8d
	shr	esi, 0x1a
	add	esi, edx
	mov	edx, esi
	shr	edx, 0x19
	add	r12d, edx
	mov	r15d, r12d
	shr	r15d, 0x1a
	add	r15d, eax
	mov	eax, r15d
	shr	eax, 0x19
	lea	edx, [rax*8]
	add	edx, eax
	lea	eax, [rax+rdx*2]
	lea	edi, [rbx+rax+0x13]
	mov	eax, edi
	shr	eax, 0x1a
	add	eax, r11d
	mov	edx, eax
	shr	edx, 0x19
	add	r10d, edx
	mov	r11d, r10d
	shr	r11d, 0x1a
	add	r11d, r13d
	mov	ebx, r11d
	shr	ebx, 0x19
	and	r9d, 0x3ffffff
	and	r14d, 0x1ffffff
	add	ebx, r9d
	and	r8d, 0x3ffffff
	and	esi, 0x1ffffff
	mov	ecx, ebx
	and	r12d, 0x3ffffff
	and	r15d, 0x1ffffff
	shr	ecx, 0x1a
	and	edi, 0x3ffffff
	and	eax, 0x1ffffff
	add	ecx, r14d
	and	r10d, 0x3ffffff
	and	r11d, 0x1ffffff
	mov	edx, ecx
	and	ebx, 0x3ffffff
	and	ecx, 0x1ffffff
	shr	edx, 0x19
	add	edx, r8d
	mov	r13d, edx
	shr	r13d, 0x1a
	add	r13d, esi
	mov	esi, r13d
	shr	esi, 0x19
	add	r12d, esi
	mov	esi, r12d
	shr	esi, 0x1a
	add	esi, r15d
	mov	r8d, esi
	shr	r8d, 0x19
	lea	r9d, [r8*8]
	
	add	r9d, r8d
	lea	r8d, [r8+r9*2]
	lea	r9d, [rdi+r8+0x3ffffed]
	
	mov	edi, r9d
	shr	edi, 0x1a
	lea	eax, [rax+rdi+0x1ffffff]
	mov	edi, eax
	and	eax, 0x1ffffff
	shr	edi, 0x19
	lea	edi, [r10+rdi+0x3ffffff]
	
	mov	r10d, eax
	mov	eax, edi
	and	edi, 0x3ffffff
	shr	eax, 0x1a
	lea	eax, [r11+rax+0x1ffffff]
	
	mov	r11d, edi
	mov	edi, eax
	and	eax, 0x1ffffff
	shr	edi, 0x19
	lea	ebx, [rbx+rdi+0x3ffffff]
	mov	edi, ebx
	shr	edi, 0x1a
	and	edx, 0x3ffffff
	and	r13d, 0x1ffffff
	lea	r8d, [rcx+rdi+0x1ffffff]
	
	and	r12d, 0x3ffffff
	and	r9d, 0x3ffffff
	shl	ebx, 0x6
	and	esi, 0x1ffffff
	mov	ecx, r8d
	and	r8d, 0x1ffffff
	shr	ecx, 0x19
	lea	edx, [rdx+rcx+0x3ffffff]
	mov	ecx, edx
	and	edx, 0x3ffffff
	shr	ecx, 0x1a
	lea	edi, [r13+rcx+0x1ffffff]
	
	mov	r13d, edx
	mov	edx, edi
	and	edi, 0x1ffffff
	shr	edx, 0x19
	lea	ecx, [r12+rdx+0x3ffffff]
	
	mov	r12d, r10d
	shr	r10d, 0x6
	shl	r12d, 0x1a
	or	r12d, r9d
	mov	r9d, r11d
	mov	edx, ecx
	shl	r9d, 0x13
	and	edx, 0x3ffffff
	shr	ecx, 0x1a
	or	r9d, r10d
	shr	r11d, 0xd
	mov	[rbp], r12d
	mov	[rbp+0x4], r9d
	mov	r9d, eax
	shr	eax, 0x13
	or	ebx, eax
	mov	eax, r13d
	shr	r13d, 0x7
	shl	eax, 0x19
	shl	r9d, 0xd
	mov	[rbp+0xc], ebx
	or	eax, r8d
	or	r9d, r11d
	mov	[rbp+0x10], eax
	mov	eax, edi
	shr	edi, 0xd
	shl	eax, 0x13
	mov	[rbp+0x8], r9d
	or	eax, r13d
	mov	[rbp+0x14], eax
	mov	eax, edx
	shl	eax, 0xc
	or	eax, edi
	mov	[rbp+0x18], eax
	lea	eax, [rsi+rcx+0x1ffffff]
	and	eax, 0x1ffffff
	shr	edx, 0x14
	shl	eax, 6
	or	eax, edx
	mov	[rbp+0x1c], eax

	; finish:
	mov	rcx, [rsp+0x4c8]
	add	rsp, rcx
	pop	r15 r14 r13 r12 rbx rbp
	epilog

end if


if used curve25519$square_times | defined include_everything
	; three arguments: rdi == r, rsi == in, edx == count
falign
curve25519$square_times:
	prolog	curve25519$square_times
	sub	rsp, 0x60
	mov	rax, rsp
	and	rax, 0xf
	add	rax, 8
	sub	rsp, rax
	mov	[rsp+0x50], rax
	mov	eax,edx
	movaps	xmm15, [rsi]
	pshufd	xmm9, [rsi+0x20], 0xd8
	movaps	xmm0, [rsi+0x10]
	pshufd	xmm2, xmm15, 0xd8
	movaps	xmm14, xmm9
	pshufd	xmm1, xmm0, 0xd8
	pshufd	xmm0, xmm0, 0xfa
	pshufd	xmm15, xmm15, 0xfa
	movaps	xmm3, xmm2
	movaps	xmm12, xmm1
	movaps	xmm10, xmm0
calign
.square_times_loop:
	movaps	xmm0, xmm15
	sub	eax, 1
	movaps	xmm5, xmm3
	pslldq	xmm0, 0x8
	movaps	xmm2, [.sse2_top64bitmask]
	pshufd	xmm1, xmm15, 0
	punpckhqdq xmm5, xmm0
	pshufd	xmm0, xmm3, 0
	movaps	xmm7, xmm15
	movaps	xmm4, [.sse2_top64bitmask]
	pxor	xmm9, xmm9
	pand	xmm2, xmm0
	pshufd	xmm6, xmm3, 0xaa
	movaps	[rsp-0x78], xmm5
	paddq	xmm2, xmm0
	pshufd	xmm8, xmm2, 0xe6
	pmuludq xmm2, xmm3
	movaps	xmm3, xmm12
	pshufd	xmm5, xmm15, 0xaa
	pslld	xmm6, 1
	movaps	xmm0, [.sse2_top64bitmask]
	pmuludq xmm3, xmm8
	pslld	xmm5, 1
	pand	xmm0, xmm1
	paddq	xmm0, xmm1
	movaps	xmm1, xmm12
	pshufd	xmm13, xmm0, 0xe6
	pmuludq xmm0, xmm15
	paddq	xmm3, xmm0
	pslldq	xmm1, 0x8
	punpckhqdq xmm7, xmm1
	movaps	xmm0, xmm15
	pshufd	xmm1, xmm12, 0
	pslld	xmm0, 1
	movaps	[rsp+0x38], xmm0
	movaps	xmm0, xmm10
	pand	xmm4, xmm1
	movaps	[rsp-0x68], xmm7
	pmuludq xmm0, xmm8
	movaps	xmm7, xmm12
	movaps	xmm11, xmm4
	paddq	xmm11, xmm1
	movaps	xmm1, xmm10
	pslldq	xmm1, 0x8
	punpckhqdq xmm7, xmm1
	movaps	xmm1, xmm7
	pmuludq xmm1, [.packednineteen]
	pshufd	xmm4, xmm1, 0x54
	movaps	[rsp-0x58], xmm4
	pshufd	xmm4, xmm1, 0xee
	movaps	xmm1, xmm14
	movaps	[rsp-0x48], xmm4
	pslldq	xmm1, 0x8
	movaps	xmm4, xmm10
	punpckhqdq xmm4, xmm1
	movaps	xmm1, xmm10
	punpcklqdq xmm1, xmm9
	pshufd	xmm9, xmm10, 0xaa
	movaps	[rsp-0x38], xmm4
	pxor	xmm4, xmm4
	pmuludq xmm9, [.packed3819]
	movaps	[rsp-0x28], xmm1
	pshufd	xmm1, xmm9, 0xfe
	movaps	[rsp-0x18], xmm1
	movaps	xmm1, xmm14
	punpcklqdq xmm1, xmm4
	movaps	[rsp-0x8], xmm1
	pshufd	xmm1, xmm14, 0
	movaps	xmm4, xmm1
	pshufd	xmm1, xmm14, 0xfe
	pmuludq xmm4, [.packednineteen]
	movaps	[rsp+0x8], xmm4
	pshufd	xmm4, xmm14, 0xaa
	pslld	xmm1, 1
	movaps	[rsp+0x18], xmm1
	pmuludq xmm4, [.packed3819]
	pshufd	xmm1, xmm4, 0xaa
	movaps	[rsp+0x28], xmm1
	movaps	xmm1, xmm15
	movaps	xmm15, xmm12
	pmuludq xmm1, xmm8
	pmuludq xmm8, xmm14
	movaps	xmm14, xmm10
	pmuludq xmm15, xmm13
	pmuludq xmm13, xmm10
	movaps	xmm10, xmm11
	paddq	xmm8, xmm13
	movaps	xmm11, [rsp-0x68]
	paddq	xmm0, xmm15
	pmuludq xmm10, xmm12
	paddq	xmm8, xmm10
	pslld	xmm12, 1
	movaps	xmm10, [.sse2_bot64bitmask]
	pslld	xmm14, 1
	pand	xmm10, xmm6
	movaps	xmm15, [rsp-0x78]
	paddq	xmm10, xmm6
	pmuludq xmm6, xmm15
	paddq	xmm1, xmm6
	movaps	xmm6, xmm11
	movaps	xmm13, [.sse2_bot64bitmask]
	pmuludq xmm6, xmm10
	paddq	xmm3, xmm6
	movaps	xmm6, xmm7
	pand	xmm13, xmm5
	pmuludq xmm6, xmm10
	paddq	xmm0, xmm6
	movaps	xmm6, xmm15
	movaps	xmm15, [rsp+0x38]
	paddq	xmm13, xmm5
	pslld	xmm6, 1
	pmuludq xmm5, xmm11
	pmuludq xmm6, xmm4
	pslld	xmm11, 1
	paddq	xmm2, xmm6
	movaps	xmm6, xmm11
	pmuludq xmm13, xmm7
	pmuludq xmm11, xmm4
	pslld	xmm7, 1
	paddq	xmm1, xmm11
	paddq	xmm0, xmm5
	pmuludq xmm6, xmm9
	pmuludq xmm9, xmm7
	paddq	xmm2, xmm6
	paddq	xmm1, xmm9
	movaps	xmm6, [rsp-0x58]
	movaps	xmm9, [rsp-0x48]
	pmuludq xmm6, xmm7
	pmuludq xmm7, xmm4
	paddq	xmm2, xmm6
	paddq	xmm3, xmm7
	movaps	xmm6, xmm9
	movaps	xmm7, [rsp+0x8]
	pmuludq xmm6, xmm12
	movaps	xmm5, [rsp-0x38]
	pmuludq xmm15, xmm7
	paddq	xmm2, xmm15
	paddq	xmm2, xmm6
	pmuludq xmm12, xmm7
	paddq	xmm1, xmm12
	movaps	xmm6, [rsp-0x28]
	pmuludq xmm10, xmm5
	pslld	xmm5, 1
	paddq	xmm8, xmm10
	pmuludq xmm4, xmm5
	paddq	xmm0, xmm4
	pmuludq xmm6, xmm9
	movaps	xmm4, [rsp-0x8]
	paddq	xmm1, xmm6
	movaps	xmm10, xmm1
	movaps	xmm12, xmm2
	pmuludq xmm14, xmm7
	movaps	xmm6, [rsp-0x18]
	pmuludq xmm4, xmm7
	paddq	xmm0, xmm4
	punpcklqdq xmm10, xmm0
	paddq	xmm8, xmm13
	pmuludq xmm6, xmm5
	movaps	xmm4, [rsp+0x18]
	paddq	xmm3, xmm6
	paddq	xmm3, xmm14
	punpcklqdq xmm12, xmm3
	punpckhqdq xmm2, xmm3
	pmuludq xmm4, [rsp+0x28]
	paddq	xmm8, xmm4
	punpckhqdq xmm1, xmm0
	movaps	xmm14, xmm8
	movaps	xmm0, xmm10
	pand	xmm10, [.packedmask26]
	movaps	xmm3, xmm12
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	movaps	xmm0, xmm1
	punpcklqdq xmm14, xmm8
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	movaps	xmm3, xmm2
	punpckhqdq xmm8, xmm8
	psrlq	xmm0, 0x19
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x19
	paddq	xmm14, xmm0
	paddq	xmm10, xmm3
	movaps	xmm3, xmm0
	movaps	xmm0, xmm14
	pand	xmm2, [.packedmask25]
	pslldq	xmm3, 0x8
	psrlq	xmm0, 0x1a
	paddq	xmm8, xmm0
	movaps	xmm0, xmm8
	pand	xmm1, [.packedmask25]
	psrlq	xmm0, 0x19
	pmuludq xmm0, [.packednineteen]
	punpckhqdq xmm0, xmm3
	pand	xmm14, [.packedmask26]
	paddq	xmm12, xmm0
	movaps	xmm0, xmm10
	movaps	xmm3, xmm12
	pand	xmm10, [.packedmask26]
	psrlq	xmm0, 0x1a
	paddq	xmm1, xmm0
	pand	xmm12, [.packedmask26]
	psrlq	xmm3, 0x1a
	paddq	xmm2, xmm3
	pand	xmm8, [.packedmask25]
	movaps	xmm15, xmm10
	punpckhqdq xmm10, xmm1
	movaps	xmm3, xmm12
	punpcklqdq xmm15, xmm1
	punpckhqdq xmm12, xmm2
	punpcklqdq xmm3, xmm2
	punpckhqdq xmm14, xmm8
	jne	.square_times_loop
	pshufd	xmm15, xmm15, 0x8f
	pshufd	xmm2, xmm3, 0xf8
	pshufd	xmm0, xmm10, 0x8f
	pshufd	xmm9, xmm14, 0xf8
	por	xmm2, xmm15
	pshufd	xmm15, xmm12, 0xf8
	movaps	[rdi+0x20], xmm9
	por	xmm0, xmm15
	movaps	[rdi], xmm2
	movaps	[rdi+0x10], xmm0

	mov	rcx, [rsp+0x50]
	add	rsp, rcx
	add	rsp, 0x60
	epilog
align 16
.sse2_top64bitmask:
	dd	0x00000000, 0x00000000, 0xffffffff, 0xffffffff
.packednineteen:
	dq	19, 19
.packed3819:
	dq	38, 19
.sse2_bot64bitmask:
	dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000
.packedmask26:
	dq	0x3ffffff, 0x3ffffff
.packedmask25:
	dq	0x1ffffff, 0x1ffffff

end if


if used curve25519$mul
	; three arguments: rdi == out, rsi == r, rdx == s
falign
curve25519$mul:
	prolog	curve25519$mul
	sub	rsp, 0x50
	movaps	xmm14, [rdx]
	mov	rax, rsp
	and	rax, 0xf
	sub	rsp, rax
	mov	[rsp+0x40], rax
	sub	rsp, 8
	pshufd	xmm3, xmm14, 0xa5
	pshufd	xmm0, xmm14, 0xd8
	movaps	xmm8, [rdx+0x10]
	pshufd	xmm1, xmm14, 0xfa
	psrldq	xmm14, 0xc
	movaps	[rsp-0x8], xmm3
	movaps	xmm3, xmm14
	pshufd	xmm6, xmm8, 0xa5
	punpcklqdq xmm3, xmm8
	movaps	xmm10, [rdx+0x20]
	movaps	[rsp-0x68], xmm6
	pshufd	xmm6, xmm8, 0xfa
	movaps	[rsp-0x38], xmm3
	pshufd	xmm3, xmm8, 0xd8
	psrldq	xmm8, 0xc
	movaps	xmm7, xmm8
	movaps	[rsp-0x58], xmm6
	punpcklqdq xmm7, xmm10
	movaps	[rsp-0x78], xmm7
	pshufd	xmm7, xmm10, 0xd8
	movaps	xmm11, [rsi]
	pshufd	xmm4, xmm7, 0xfa
	movaps	xmm15, xmm7
	movaps	xmm2, [.sse2_top64bitmask]
	pshufd	xmm5, xmm11, 0x55
	movaps	[rsp+0x8], xmm4
	movaps	xmm4, xmm2
	movaps	xmm7, xmm2
	movaps	xmm8, xmm2
	pand	xmm4, xmm5
	movaps	xmm12, [rsi+0x10]
	movaps	xmm9, xmm2
	pshufd	xmm10, xmm11, 0xaa
	paddq	xmm4, xmm5
	pshufd	xmm5, xmm11, 0xff
	movaps	[rsp-0x28], xmm15
	pshufd	xmm11, xmm11, 0
	pand	xmm7, xmm5
	paddq	xmm7, xmm5
	pshufd	xmm5, xmm12, 0x55
	pand	xmm8, xmm5
	paddq	xmm8, xmm5
	pshufd	xmm5, xmm12, 0xaa
	movaps	[rsp-0x48], xmm5
	pshufd	xmm5, xmm12, 0xff
	pshufd	xmm12, xmm12, 0
	pand	xmm9, xmm5
	movaps	xmm14, xmm9
	paddq	xmm14, xmm5
	movaps	xmm5, [rsi+0x20]
	pshufd	xmm9, xmm5, 0xdd
	pand	xmm2, xmm9
	movaps	xmm13, xmm2
	movaps	xmm2, xmm9
	pshufd	xmm9, xmm5, 0xcc
	movaps	xmm5, xmm4
	paddq	xmm2, xmm13
	movaps	xmm13, xmm4
	movaps	[rsp-0x18], xmm2
	pmuludq xmm5, xmm0
	movaps	xmm2, xmm7
	pmuludq xmm13, xmm1
	movaps	[rsp+0x18], xmm9
	pmuludq xmm2, xmm0
	movaps	xmm9, xmm4
	paddq	xmm13, xmm2
	movaps	xmm2, xmm7
	movaps	[rsp+0x28], xmm5
	pmuludq xmm9, xmm3
	pmuludq xmm2, xmm1
	movaps	xmm5, xmm6
	paddq	xmm9, xmm2
	movaps	xmm2, xmm7
	pmuludq xmm5, xmm4
	pmuludq xmm2, xmm3
	paddq	xmm5, xmm2
	movaps	xmm2, xmm15
	movaps	xmm15, xmm8
	pmuludq xmm2, xmm4
	pshufd	xmm4, xmm4, 0xa
	pmuludq xmm15, xmm0
	paddq	xmm9, xmm15
	movaps	xmm15, xmm8
	pmuludq xmm15, xmm1
	paddq	xmm5, xmm15
	movaps	xmm15, xmm6
	movaps	xmm6, xmm9
	pslldq	xmm9, 0x8
	pmuludq xmm15, xmm7
	paddq	xmm2, xmm15
	movaps	xmm15, xmm14
	pshufd	xmm7, xmm7, 0xa
	pmuludq xmm15, xmm0
	paddq	xmm5, xmm15
	movaps	xmm15, xmm8
	pshufd	xmm8, xmm8, 0xa
	pmuludq xmm15, xmm3
	paddq	xmm2, xmm15
	movaps	xmm15, xmm14
	pmuludq xmm15, xmm1
	paddq	xmm2, xmm15
	movaps	xmm15, [rsp-0x18]
	pmuludq xmm15, xmm0
	paddq	xmm2, xmm15
	movaps	xmm15, xmm5
	pslldq	xmm2, 0x8
	pslldq	xmm5, 0x8
	punpckhqdq xmm6, xmm5
	punpckhqdq xmm15, xmm2
	movaps	xmm2, xmm13
	pslldq	xmm13, 0x8
	punpckhqdq xmm2, xmm9
	movaps	xmm9, xmm2
	movaps	xmm2, [rsp+0x28]
	movaps	xmm5, xmm2
	punpckhqdq xmm5, xmm13
	movaps	xmm13, xmm2
	pxor	xmm2, xmm2
	pslldq	xmm13, 0x8
	punpckhqdq xmm2, xmm13
	movaps	xmm13, xmm11
	pmuludq xmm13, xmm0
	paddq	xmm2, xmm13
	movaps	xmm13, xmm11
	pmuludq xmm13, xmm1
	paddq	xmm5, xmm13
	movaps	xmm13, xmm11
	pmuludq xmm13, xmm3
	paddq	xmm9, xmm13
	movaps	xmm13, [rsp-0x58]
	pmuludq xmm13, xmm11
	paddq	xmm6, xmm13
	movaps	xmm13, xmm10
	pmuludq xmm11, [rsp-0x28]
	paddq	xmm15, xmm11
	movaps	xmm11, xmm12
	pmuludq xmm13, xmm0
	paddq	xmm5, xmm13
	movaps	xmm13, xmm10
	pmuludq xmm11, xmm0
	pmuludq xmm13, xmm1
	paddq	xmm9, xmm13
	movaps	xmm13, xmm12
	paddq	xmm9, xmm11
	movaps	xmm11, xmm10
	pmuludq xmm13, xmm1
	paddq	xmm6, xmm13
	movaps	xmm13, [rsp-0x48]
	pmuludq xmm11, xmm3
	paddq	xmm6, xmm11
	movaps	xmm11, [rsp-0x58]
	pmuludq xmm11, xmm10
	paddq	xmm15, xmm11
	movaps	xmm11, xmm13
	pmuludq xmm11, xmm0
	paddq	xmm6, xmm11
	movaps	xmm11, xmm12
	pmuludq xmm11, xmm3
	paddq	xmm15, xmm11
	movaps	xmm11, xmm13
	movaps	xmm13, xmm10
	movaps	xmm10, [rsp-0x48]
	pmuludq xmm11, xmm1
	paddq	xmm15, xmm11
	movaps	xmm11, [rsp+0x18]
	pmuludq xmm0, xmm11
	paddq	xmm15, xmm0
	movaps	xmm0, [.packednineteen]
	pmuludq xmm13, xmm0
	pmuludq xmm10, xmm0
	movaps	[rsp+0x18], xmm13
	movaps	xmm13, xmm10
	pmuludq xmm8, xmm0
	pmuludq xmm7, xmm0
	movaps	xmm10, xmm11
	movaps	xmm11, xmm4
	pmuludq xmm12, xmm0
	pshufd	xmm4, [rsp-0x18], 0xa
	pmuludq xmm11, xmm0
	movaps	[rsp-0x48], xmm11
	pmuludq xmm10, xmm0
	pshufd	xmm11, xmm14, 0xa
	pmuludq xmm1, xmm10
	pmuludq xmm4, xmm0
	movaps	xmm14, [rsp-0x8]
	pmuludq xmm11, xmm0
	pmuludq xmm14, xmm4
	paddq	xmm2, xmm14
	movaps	xmm14, [rsp-0x38]
	pmuludq xmm14, xmm4
	paddq	xmm5, xmm14
	movaps	xmm14, [rsp-0x68]
	pmuludq xmm14, xmm4
	paddq	xmm9, xmm14
	movaps	xmm14, [rsp-0x78]
	pmuludq xmm14, xmm4
	paddq	xmm6, xmm14
	movaps	xmm14, [rsp-0x38]
	pmuludq xmm14, xmm11
	paddq	xmm2, xmm14
	movaps	xmm14, [rsp-0x68]
	pmuludq xmm14, xmm11
	paddq	xmm5, xmm14
	movaps	xmm14, [rsp-0x78]
	pmuludq xmm14, xmm11
	paddq	xmm9, xmm14
	movaps	xmm14, [rsp+0x8]
	pmuludq xmm11, xmm14
	paddq	xmm6, xmm11
	movaps	xmm11, [rsp-0x68]
	pmuludq xmm11, xmm8
	paddq	xmm2, xmm11
	movaps	xmm11, [rsp-0x78]
	pmuludq xmm11, xmm8
	pmuludq xmm8, xmm14
	paddq	xmm5, xmm11
	movaps	xmm11, xmm14
	paddq	xmm9, xmm8
	movaps	xmm14, [rsp-0x28]
	pmuludq xmm4, xmm11
	paddq	xmm15, xmm4
	movaps	xmm8, xmm14
	movaps	xmm4, [rsp-0x48]
	pmuludq xmm8, xmm10
	paddq	xmm6, xmm8
	movaps	xmm8, [rsp-0x78]
	pmuludq xmm4, xmm11
	pmuludq xmm8, xmm7
	pmuludq xmm7, xmm11
	paddq	xmm5, xmm7
	movaps	xmm7, xmm14
	paddq	xmm2, xmm8
	paddq	xmm2, xmm1
	movaps	xmm1, xmm10
	pmuludq xmm7, xmm13
	paddq	xmm9, xmm7
	movaps	xmm7, [rsp-0x58]
	pmuludq xmm1, xmm3
	paddq	xmm5, xmm1
	pmuludq xmm3, xmm13
	pmuludq xmm10, xmm7
	movaps	xmm1, xmm7
	paddq	xmm9, xmm10
	movaps	xmm10, [rsp+0x18]
	paddq	xmm2, xmm3
	pmuludq xmm13, xmm7
	pmuludq xmm1, xmm12
	paddq	xmm5, xmm13
	paddq	xmm2, xmm1
	pmuludq xmm12, xmm14
	pmuludq xmm10, xmm14
	paddq	xmm5, xmm12
	paddq	xmm2, xmm10
	movaps	xmm3, xmm5
	paddq	xmm2, xmm4
	movaps	xmm4, xmm2
	movaps	xmm1, [.packedmask26]
	punpcklqdq xmm3, xmm6
	punpcklqdq xmm4, xmm9
	punpckhqdq xmm2, xmm9
	punpckhqdq xmm5, xmm6
	movaps	xmm6, xmm15
	movaps	xmm8, xmm4
	movaps	xmm7, xmm3
	punpcklqdq xmm6, xmm15
	pand	xmm3, xmm1
	psrlq	xmm8, 0x1a
	paddq	xmm2, xmm8
	psrlq	xmm7, 0x1a
	movaps	xmm9, xmm2
	paddq	xmm5, xmm7
	movaps	xmm8, xmm5
	punpckhqdq xmm15, xmm15
	psrlq	xmm9, 0x19
	paddq	xmm3, xmm9
	pand	xmm4, xmm1
	psrlq	xmm8, 0x19
	paddq	xmm6, xmm8
	movaps	xmm9, xmm6
	pslldq	xmm8, 0x8
	movaps	xmm7, [.packedmask25]
	pand	xmm6, xmm1
	psrlq	xmm9, 0x1a
	paddq	xmm15, xmm9
	movaps	xmm9, xmm15
	pand	xmm2, xmm7
	psrlq	xmm9, 0x19
	pmuludq xmm0, xmm9
	punpckhqdq xmm0, xmm8
	pand	xmm5, xmm7
	pand	xmm15, xmm7
	paddq	xmm4, xmm0
	movaps	xmm7, xmm4
	pand	xmm4, xmm1
	movaps	xmm0, xmm3
	pand	xmm1, xmm3
	psrlq	xmm7, 0x1a
	paddq	xmm2, xmm7
	psrlq	xmm0, 0x1a
	paddq	xmm5, xmm0
	movaps	xmm0, xmm4
	punpckhdq xmm4, xmm2
	punpckldq xmm0, xmm2
	add	rsp, 8
	movaps	xmm2, xmm1
	punpckhdq xmm1, xmm5
	punpckldq xmm2, xmm5
	punpckhdq xmm6, xmm15
	punpcklqdq xmm4, xmm1
	punpcklqdq xmm0, xmm2
	mov	rcx, [rsp+0x40]
	movaps	[rdi], xmm0
	movaps	[rdi+0x10], xmm4
	movaps	[rdi+0x20], xmm6
	add	rsp, rcx
	add	rsp, 0x50
	epilog
align 16
.sse2_top64bitmask:
	dd	0x00000000, 0x00000000, 0xffffffff, 0xffffffff
.packednineteen:
	dq	19, 19
.packedmask26:
	dq	0x3ffffff, 0x3ffffff
.packedmask25:
	dq	0x1ffffff, 0x1ffffff

end if

if used curve25519$contract | defined include_everything
	; two arguments: rdi == out buffer (32 bytes), rsi == ALIGNED 16 input number
falign
curve25519$contract:
	prolog	curve25519$contract

	; uggh this is a giant dependency chain, hahah, someday when I am bored walk back through this

	movaps	xmm2, [rsi]
	movaps	xmm0, [rsi+0x10]
	movaps	xmm1, [rsi+0x20]
	push	rbp rbx r12 r13 r14 r15
	sub	rsp, 0x50
	mov	rax, rsp
	and	rax, 0xf
	add	rax, 8
	sub	rsp, rax
	mov	[rsp+0x40], rax
	
	movaps	[rsp-0x48], xmm2
	movaps	[rsp-0x38], xmm2

	mov	r12d, [rsp-0x48]

	movaps	[rsp-0x68], xmm0
	movaps	[rsp-0x28], xmm0

	mov	r9d, r12d
	and	r12d, 0x3ffffff
	mov	edx, [rsp-0x68]
	shr	r9d, 0x1a
	add	r9d, [rsp-0x34]

	movaps	[rsp-0x58], xmm1
	movaps	[rsp-0x18], xmm1
	
	mov	r8d, r9d
	and	r9d, 0x1ffffff
	mov	eax, [rsp-0x58]
	shr	r8d, 0x19
	add	r8d, [rsp-0x30]

	mov	r10d, r8d
	and	r8d, 0x3ffffff
	shr	r10d, 0x1a
	add	r10d, [rsp-0x2c]
	
	mov	ebx, r10d
	and	r10d, 0x1ffffff
	shr	ebx, 0x19
	add	ebx, edx
	mov	esi, ebx
	and	ebx, 0x3ffffff
	shr	esi, 0x1a
	add	esi, [rsp-0x24]
	
	mov	ecx, esi
	shr	ecx, 0x19
	add	ecx, [rsp-0x20]
	mov	edx, ecx
	shr	edx, 0x1a
	add	edx, [rsp-0x1c]

	mov	r13d, edx
	shr	r13d, 0x19
	add	r13d, eax
	mov	eax, r13d
	shr	eax, 0x1a
	add	eax, [rsp-0x14]

	mov	r11d, eax
	shr	r11d, 0x19
	lea	ebp, [r11+r11*8]
	lea	ebp, [r11+rbp*2]
	add	ebp, r12d
	mov	r12d, ebp
	shr	r12d, 0x1a
	add	r12d, r9d
	mov	r9d, r12d
	shr	r9d, 0x19
	add	r9d, r8d
	mov	r8d, r9d
	shr	r8d, 0x1a
	add	r8d, r10d
	mov	r15d, r8d
	shr	r15d, 0x19
	add	r15d, ebx
	mov	r10d, r15d
	shr	r10d, 0x1a
	and	esi, 0x1ffffff
	and	ecx, 0x3ffffff
	add	esi, r10d
	and	edx, 0x1ffffff
	and	r13d, 0x3ffffff
	
	mov	r10d, esi
	and	eax, 0x1ffffff
	and	ebp, 0x3ffffff
	shr	r10d, 0x19
	and	r12d, 0x1ffffff
	and	r9d, 0x3ffffff
	add	ecx, r10d
	and	r8d, 0x1ffffff
	and	r15d, 0x3ffffff
	mov	r10d, ecx
	and	esi, 0x1ffffff
	shr	r10d, 0x1a
	add	edx, r10d
	mov	r14d, edx
	shr	r14d, 0x19
	add	r14d, r13d
	mov	r10d, r14d
	shr	r10d, 0x1a
	add	eax, r10d
	mov	r10d, eax

	shr	r10d, 0x19
	lea	r11d, [r10*8]
	add	r11d, r10d
	lea	r10d, [r10+r11*2]
	lea	ebp, [rbp+r10+0x13]
	mov	ebx, ebp
	shr	ebx, 0x1a
	add	ebx, r12d
	mov	r11d, ebx
	shr	r11d, 0x19
	add	r11d, r9d
	mov	r13d, r11d
	shr	r13d, 0x1a
	add	r13d, r8d
	mov	r10d, r13d
	shr	r10d, 0x19
	add	r10d, r15d
	mov	r9d, r10d
	shr	r9d, 0x1a
	add	r9d, esi
	mov	r8d, r9d
	shr	r8d, 0x19
	and	ecx, 0x3ffffff
	
	and	edx, 0x1ffffff
	add	r8d, ecx
	and	r14d, 0x3ffffff
	and	eax, 0x1ffffff
	mov	esi, r8d
	and	ebp, 0x3ffffff
	and	ebx, 0x1ffffff
	shr	esi, 0x1a
	and	r11d, 0x3ffffff
	and	r13d, 0x1ffffff
	add	esi, edx
	and	r10d, 0x3ffffff
	and	r9d, 0x1ffffff
	mov	edx, esi
	and	r8d, 0x3ffffff
	and	esi, 0x1ffffff
	shr	edx, 0x19

	add	edx, r14d
	mov	r12d, edx
	and	edx, 0x3ffffff
	shr	r12d, 0x1a
	add	r12d, eax
	mov	eax, r12d
	shr	eax, 0x19
	lea	ecx, [rax*8]
	add	ecx, eax

	lea	eax, [rax+rcx*2]
	lea	ebp, [rbp+rax+0x3ffffed]
	mov	eax, ebp
	and	ebp, 0x3ffffff
	shr	eax, 0x1a
	mov	[rdi], bpl
	lea	ebx, [rbx+rax+0x1ffffff]
	mov	eax, ebx
	
	shr	eax, 0x19
	lea	r11d, [r11+rax+0x3ffffff]
	mov	eax, r11d
	shr	eax, 0x1a
	lea	ecx, [r13+rax+0x1ffffff]
	mov	eax, ecx
	shr	eax, 0x19
	lea	r10d, [r10+rax+0x3ffffff]
	
	mov	eax, r10d
	shr	eax, 0x1a
	lea	r9d, [r9+rax+0x1ffffff]
	mov	eax, r9d
	and	r9d, 0x1ffffff
	shr	eax, 0x19
	lea	r8d, [r8+rax+0x3ffffff]
	mov	eax, r8d
	shr	eax, 0x1a
	lea	esi, [rsi+rax+0x1ffffff]
	mov	eax, esi
	shr	eax, 0x19
	and	ebx, 0x1ffffff
	and	r12d, 0x1ffffff
	lea	eax, [rdx+rax+0x3ffffff]
	shl	ebx, 2
	and	r11d, 0x3ffffff
	shl	r11d, 3
	and	ecx, 0x1ffffff
	shl	r10d, 6
	mov	edx, eax
	shr	eax, 0x1a
	shl	ecx, 5
	lea	eax, [r12+rax+0x1ffffff]

	mov	r12d, ebp
	and	r8d, 0x3ffffff
	shr	r12d, 0x8
	and	esi, 0x1ffffff
	and	edx, 0x3ffffff
	mov [rdi+1], r12b
	mov	r12d, ebp
	shr	ebp, 0x18
	or	ebp, ebx
	shr	r12d, 0x10
	and	eax, 0x1ffffff
	mov	[rdi+3], bpl
	mov	ebp, ebx
	mov	[rdi+2], r12b
	shr	ebp, 8
	add	r8d, r8d
	shl	esi, 3
	mov	[rdi+4], bpl
	mov	ebp, ebx
	shr	ebx, 0x18
	or	ebx, r11d
	shr	ebp, 0x10
	shl	edx, 4
	mov	[rdi+6], bl
	mov	ebx, r11d
	mov	[rdi+5], bpl
	shr	ebx, 8
	shl	eax, 6
	mov	[rdi+7], bl
	mov	ebx, r11d
	shr	r11d, 0x18
	or	r11d, ecx
	shr	ebx, 0x10
	mov	[rdi+8], bl
	mov	[rdi+9], r11b

	mov	r11d, ecx
	shr	r11d, 8
	mov	[rdi+0x10], r9b
	mov	[rdi+0xa], r11b
	mov	r11d, ecx
	shr	ecx, 0x18
	or	ecx, r10d
	shr	r11d, 0x10
	mov	[rdi+0xc], cl
	mov	ecx, r10d
	mov	[rdi+0xb], r11b
	shr	ecx, 8
	mov	[rdi+0xd], cl
	mov	ecx, r10d
	shr	r10d, 0x18
	shr	ecx, 0x10
	mov	[rdi+0xf], r10b
	mov	[rdi+0xe], cl

	mov	ecx, r9d
	shr	ecx, 8
	mov	[rdi+0x11], cl
	mov	ecx, r9d
	shr	r9d, 0x18
	shr	ecx, 0x10
	or	r9d, r8d
	mov	[rdi+0x12], cl
	mov	ecx, r8d
	mov	[rdi+0x13], r9b
	shr	ecx, 8
	mov	[rdi+0x14], cl
	mov	ecx, r8d
	shr	r8d, 0x18
	shr	ecx, 0x10
	or	r8d, esi
	mov	[rdi+0x15], cl

	mov	ecx, esi
	mov	[rdi+0x16], r8b
	shr	ecx, 8
	mov	[rdi+0x17], cl
	mov	ecx, esi
	shr	esi, 0x18
	shr	ecx, 0x10
	or	esi, edx
	mov	[rdi+0x18], cl
	mov	ecx, edx
	mov	[rdi+0x19], sil
	shr	ecx, 8
	mov	[rdi+0x1a], cl
	mov	ecx, edx
	shr	edx, 0x18
	or	edx, eax
	shr	ecx, 0x10
	mov	[rdi+0x1c], dl
	mov	edx, eax
	mov	[rdi+0x1b], cl
	shr	edx, 8
	mov	[rdi+0x1d], dl
	mov	edx, eax
	shr	eax, 0x18
	shr	edx, 0x10
	mov	[rdi+0x1f], al
	mov	[rdi+0x1e], dl

	mov	rcx, [rsp+0x40]
	add	rsp, rcx
	add	rsp, 0x50
	pop	r15 r14 r13 r12 rbx rbp
	epilog

end if
