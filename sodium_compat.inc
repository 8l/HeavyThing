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
	; sodium_compat.inc: libsodium compatibility for the crypto_box_easy
	; and crypto_box_open_easy routines.
	;
	; Some interesting things here, the crypto_stream_salsa20_xor_ic function
	; is a modified version of DJB's/NaCl's amd64_xmm6 version, but for some
	; reason he/they chose to use 'rep movs..' in two spots, aside from a few
	; reorderings and commenting out, the only other change was replacing
	; 'rep movs..' with our own memcpy version and it goes considerably faster.
	; YMMV. It only is crazily apparent when doing large-sized messages.
	;
	; see crypto_box_easy and crypto_box_open_easy for the goods.
	;



if used hsalsa20 | defined include_everything
	; four arguments: rdi == out, rsi == in, rdx == k, rcx == c
falign
hsalsa20:
	prolog	hsalsa20
	; borrowed slow technique from scrypt.inc
	push	rbx rbp r12 r13 r14 r15
	mov	rbx, rdi

	mov	r8d, [rcx+4]		; x5
	mov	r14d, [rcx+8]		; x10
	movd	xmm15, [rcx+12]		; x15
	mov	ecx, [rcx]		; x0

	mov	r9d, [rsi]		; x6
	mov	r11d, [rsi+4]		; x7
	mov	r12d, [rsi+8]		; x8
	mov	r13d, [rsi+12]		; x9

	mov	r15d, [rdx+16]		; x11
	movd	xmm12, [rdx+20]		; x12
	movd	xmm13, [rdx+24]		; x13
	movd	xmm14, [rdx+28]		; x14

	mov	ebp, [rdx+4]		; x2
	mov	edi, [rdx+8]		; x3
	mov	esi, [rdx+12]		; x4
	mov	edx, [rdx]		; x1
	
	; this ends up a fair bit of code bloat...
	repeat 10
		NRRX	esi, ecx, xmm12, 7
		NRRR	r13d, r8d, edx, 7
		NXRR	xmm14, r14d, r9d, 7
		NRXR	edi, xmm15, r15d, 7

		NRRR	r12d, esi, ecx, 9
		NXRR	xmm13, r13d, r8d, 9
		NRXR	ebp, xmm14, r14d, 9
		NRRX	r11d, edi, xmm15, 9

		NXRR	xmm12, r12d, esi, 13
		NRXR	edx, xmm13, r13d, 13
		NRRX	r9d, ebp, xmm14, 13
		NRRR	r15d, r11d, edi, 13

		NRXR	ecx, xmm12, r12d, 18
		NRRX	r8d, edx, xmm13, 18
		NRRR	r14d, r9d, ebp, 18
		NXRR	xmm15, r15d, r11d, 18

		NRRR	edx, ecx, edi, 7
		NRRR	r9d, r8d, esi, 7
		NRRR	r15d, r14d, r13d, 7
		NXXX	xmm12, xmm15, xmm14, 7

		NRRR	ebp, edx, ecx, 9
		NRRR	r11d, r9d, r8d, 9
		NRRR	r12d, r15d, r14d, 9
		NXXX	xmm13, xmm12, xmm15, 9

		NRRR	edi, ebp, edx, 13
		NRRR	esi, r11d, r9d, 13
		NRRR	r13d, r12d, r15d, 13
		NXXX	xmm14, xmm13, xmm12, 13

		NRRR	ecx, edi, ebp, 18
		NRRR	r8d, esi, r11d, 18
		NRRR	r14d, r13d, r12d, 18
		NXXX	xmm15, xmm14, xmm13, 18
	end repeat

	mov	[rbx], ecx
	mov	[rbx+4], r8d
	mov	[rbx+8], r14d
	movd	[rbx+12], xmm15
	mov	[rbx+16], r9d
	mov	[rbx+20], r11d
	mov	[rbx+24], r12d
	mov	[rbx+28], r13d

	pop	r15 r14 r13 r12 rbp rbx
	epilog

end if




if used crypto_stream_salsa20_32 | defined include_everything

	; three arguments: rdi == c, rsi == n, rdx == k
falign
crypto_stream_salsa20_32:
	prolog	crypto_stream_salsa20_32
	xor	r8d, r8d
	mov	r11, rsp		; stackmod
	mov	r9d, 32			; r9d == clen
	mov	r10, rdx		; r10 == k
	mov	rdx, rsi		; rdx == n
	mov	rsi, rdi		; rsi == c
	and	r11, 0x1f		; stackmod
	add	r11, 0x200
	mov	[rdi], r8
	mov	[rdi+8], r8
	mov	[rdi+16], r8
	mov	[rsi+24], r8
	sub	rsp, r11
	mov	[rsp+0x1a0], r11
	; these are needlessly saved in the reference version
	; mov	[rsp+0x1a8], r12
	; mov	[rsp+0x1b0], r13
	; mov	[rsp+0x1b8], r14
	; mov	[rsp+0x1c0], r15
	mov	[rsp+0x1c8], rbx
	; mov	[rsp+0x1d0], rbp
	mov	qword [rsp+0x1d8], 0
	mov	ebx, r9d
	jmp	crypto_stream_salsa_entry

end if


if used crypto_stream_salsa_xor_ic | used crypto_stream_salsa20_32 | defined include_everything

	; six arguments: rdi == c, rsi == m, rdx == mlen, rcx == n, r8 == ic, r9 == k
	; this routine is basically straight from DJB's amd64_xmm6 version, modified slightly and is considerably faster
	; see comments atop for further information
falign
crypto_stream_salsa_xor_ic:
	prolog	crypto_stream_salsa_xor_ic
	mov	r11, rsp
	mov	r10, r9
	and	r11, 0x1f
	mov	r9, rdx
	mov	rdx, rcx
	add	r11, 0x200
	sub	rsp, r11
	mov	[rsp+0x1a0], r11
	; these are needlessly saved in the reference version
	; mov	[rsp+0x1a8], r12
	; mov	[rsp+0x1b0], r13
	; mov	[rsp+0x1b8], r14
	; mov	[rsp+0x1c0], r15
	mov	[rsp+0x1c8], rbx
	; mov	[rsp+0x1d0], rbp
	mov	[rsp+0x1d8], r8
	mov	rbx, r9
	cmp	r9, 0
	jbe	crypto_stream_salsa_xor_ic_atleast64
crypto_stream_salsa_entry:
	mov	ecx, [r10+0x14]
	mov	r8d, [r10]
	mov	eax, [rdx]
	mov	r11d, [r10+0x10]
	mov	[rsp+0x40], ecx
	mov	[rsp+0x44], r8d
	mov	[rsp+0x48], eax
	mov	[rsp+0x4c], r11d
	mov	r8d, [r10+0x18]
	mov	eax, [r10+0x4]
	mov	edx, [rdx+0x4]
	mov	rcx, [rsp+0x1d8]
	mov	[rsp+0x50], ecx
	mov	[rsp+0x54], r8d
	mov	[rsp+0x58], eax
	mov	[rsp+0x5c], edx
	mov	edx, [r10+0xc]
	shr	rcx, 0x20
	mov	r8d, [r10+0x1c]
	mov	eax, [r10+0x8]
	mov	[rsp+0x60], edx
	mov	[rsp+0x64], ecx
	mov	[rsp+0x68], r8d
	mov	[rsp+0x6c], eax
	mov	edx, 0x61707865
	mov	ecx, 0x3320646e
	mov	r8d, 0x79622d32
	mov	eax, 0x6b206574
	mov	[rsp+0x70], edx
	mov	[rsp+0x74], ecx
	mov	[rsp+0x78], r8d
	mov	[rsp+0x7c], eax
	cmp	rbx, 0x100
	jb	.between1and255
	movaps	xmm0, [rsp+0x70]
	movaps	xmm4, [rsp+0x40]
	pshufd	xmm1, xmm0, 0x55
	pshufd	xmm2, xmm0, 0xaa
	pshufd	xmm3, xmm0, 0xff
	pshufd	xmm0, xmm0, 0
	movaps	[rsp+0x80], xmm1
	movaps	[rsp+0x90], xmm2
	pshufd	xmm5, xmm4, 0xaa
	pshufd	xmm6, xmm4, 0xff
	movaps	[rsp+0xa0], xmm3
	movaps	[rsp+0xb0], xmm0
	pshufd	xmm7, xmm4, 0
	pshufd	xmm4, xmm4, 0x55
	movaps	[rsp+0xc0], xmm5
	movaps	[rsp+0xd0], xmm6
	movaps	xmm8, [rsp+0x50]
	movaps	xmm11, [rsp+0x60]
	movaps	[rsp+0xe0], xmm7
	movaps	[rsp+0xf0], xmm4
	pshufd	xmm9, xmm8, 0xff
	pshufd	xmm10, xmm8, 0x55
	movaps	[rsp+0x100], xmm9
	movaps	[rsp+0x110], xmm10
	pshufd	xmm8, xmm8, 0xaa
	pshufd	xmm12, xmm11, 0
	movaps	[rsp+0x120], xmm8
	movaps	[rsp+0x130], xmm12
	pshufd	xmm13, xmm11, 0xaa
	pshufd	xmm11, xmm11, 0xff
	movaps	[rsp+0x140], xmm13
	movaps	[rsp+0x150], xmm11
calign
.atleast256:
	mov	rdx, [rsp+0x1d8]
	mov	rcx, rdx
	shr	rcx, 0x20
	mov	[rsp+0x160], edx
	add	rdx, 1
	mov	[rsp+0x170], ecx
	mov	rcx, rdx
	mov	[rsp+0x164], edx
	shr	rcx, 0x20
	add	rdx, 1
	mov	[rsp+0x174], ecx
	mov	rcx, rdx
	mov	[rsp+0x168], edx
	shr	rcx, 0x20
	add	rdx, 1
	mov	[rsp+0x178], ecx
	mov	rcx, rdx
	mov	[rsp+0x16c], edx
	shr	rcx, 0x20
	add	rdx, 1
	mov	[rsp+0x17c], ecx
	mov	rcx, rdx
	shr	rcx, 0x20
	mov	[rsp+0x50], edx
	mov	[rsp+0x64], ecx
	mov	[rsp+0x1d8], rdx
	mov	[rsp+0x1e0], rbx
	mov	edx, 0x14

	movaps	xmm0, [rsp+0x80]
	movaps	xmm1, [rsp+0x90]
	movaps	xmm2, [rsp+0xa0]
	movaps	xmm3, [rsp+0x140]
	movaps	xmm4, [rsp+0x150]
	movaps	xmm5, [rsp+0xc0]
	movaps	xmm6, [rsp+0xd0]
	movaps	xmm7, [rsp+0xf0]
	movaps	xmm8, [rsp+0x100]
	movaps	xmm9, [rsp+0x110]
	movaps	xmm10, [rsp+0x120]
	movaps	xmm11, [rsp+0x170]
	movaps	xmm12, [rsp+0xb0]
	movaps	xmm13, [rsp+0xe0]
	movaps	xmm14, [rsp+0x130]
	movaps	xmm15, [rsp+0x160]
calign
.mainloop1:
	movaps	[rsp+0x180], xmm1
	movaps	[rsp+0x190], xmm2
	movaps	xmm1, xmm13
	paddd	xmm1, xmm12
	movaps	xmm2, xmm1
	pslld	xmm1, 0x7
	pxor	xmm14, xmm1
	psrld	xmm2, 0x19
	pxor	xmm14, xmm2
	movaps	xmm1, xmm7
	paddd	xmm1, xmm0
	movaps	xmm2, xmm1
	pslld	xmm1, 0x7
	pxor	xmm11, xmm1
	psrld	xmm2, 0x19
	pxor	xmm11, xmm2
	movaps	xmm1, xmm12
	paddd	xmm1, xmm14
	movaps	xmm2, xmm1
	pslld	xmm1, 0x9
	pxor	xmm15, xmm1
	psrld	xmm2, 0x17
	pxor	xmm15, xmm2
	movaps	xmm1, xmm0
	paddd	xmm1, xmm11
	movaps	xmm2, xmm1
	pslld	xmm1, 0x9
	pxor	xmm9, xmm1
	psrld	xmm2, 0x17
	pxor	xmm9, xmm2
	movaps	xmm1, xmm14
	paddd	xmm1, xmm15
	movaps	xmm2, xmm1
	pslld	xmm1, 0xd
	pxor	xmm13, xmm1
	psrld	xmm2, 0x13
	pxor	xmm13, xmm2
	movaps	xmm1, xmm11
	paddd	xmm1, xmm9
	movaps	xmm2, xmm1
	pslld	xmm1, 0xd
	pxor	xmm7, xmm1
	psrld	xmm2, 0x13
	pxor	xmm7, xmm2
	movaps	xmm1, xmm15
	paddd	xmm1, xmm13
	movaps	xmm2, xmm1
	pslld	xmm1, 0x12
	pxor	xmm12, xmm1
	psrld	xmm2, 0xe
	pxor	xmm12, xmm2
	movaps	xmm1, [rsp+0x180]
	movaps	[rsp+0x180], xmm12
	movaps	xmm2, xmm9
	paddd	xmm2, xmm7
	movaps	xmm12, xmm2
	pslld	xmm2, 0x12
	pxor	xmm0, xmm2
	psrld	xmm12, 0xe
	pxor	xmm0, xmm12
	movaps	xmm2, xmm5
	paddd	xmm2, xmm1
	movaps	xmm12, xmm2
	pslld	xmm2, 0x7
	pxor	xmm3, xmm2
	psrld	xmm12, 0x19
	pxor	xmm3, xmm12
	movaps	xmm2, [rsp+0x190]
	movaps	[rsp+0x190], xmm0
	movaps	xmm0, xmm6
	paddd	xmm0, xmm2
	movaps	xmm12, xmm0
	pslld	xmm0, 0x7
	pxor	xmm4, xmm0
	psrld	xmm12, 0x19
	pxor	xmm4, xmm12
	movaps	xmm0, xmm1
	paddd	xmm0, xmm3
	movaps	xmm12, xmm0
	pslld	xmm0, 0x9
	pxor	xmm10, xmm0
	psrld	xmm12, 0x17
	pxor	xmm10, xmm12
	movaps	xmm0, xmm2
	paddd	xmm0, xmm4
	movaps	xmm12, xmm0
	pslld	xmm0, 0x9
	pxor	xmm8, xmm0
	psrld	xmm12, 0x17
	pxor	xmm8, xmm12
	movaps	xmm0, xmm3
	paddd	xmm0, xmm10
	movaps	xmm12, xmm0
	pslld	xmm0, 0xd
	pxor	xmm5, xmm0
	psrld	xmm12, 0x13
	pxor	xmm5, xmm12
	movaps	xmm0, xmm4
	paddd	xmm0, xmm8
	movaps	xmm12, xmm0
	pslld	xmm0, 0xd
	pxor	xmm6, xmm0
	psrld	xmm12, 0x13
	pxor	xmm6, xmm12
	movaps	xmm0, xmm10
	paddd	xmm0, xmm5
	movaps	xmm12, xmm0
	pslld	xmm0, 0x12
	pxor	xmm1, xmm0
	psrld	xmm12, 0xe
	pxor	xmm1, xmm12
	movaps	xmm0, [rsp+0x180]
	movaps	[rsp+0x180], xmm1
	movaps	xmm1, xmm4
	paddd	xmm1, xmm0
	movaps	xmm12, xmm1
	pslld	xmm1, 0x7
	pxor	xmm7, xmm1
	psrld	xmm12, 0x19
	pxor	xmm7, xmm12
	movaps	xmm1, xmm8
	paddd	xmm1, xmm6
	movaps	xmm12, xmm1
	pslld	xmm1, 0x12
	pxor	xmm2, xmm1
	psrld	xmm12, 0xe
	pxor	xmm2, xmm12
	movaps	xmm12, [rsp+0x190]
	movaps	[rsp+0x190], xmm2
	movaps	xmm1, xmm14
	paddd	xmm1, xmm12
	movaps	xmm2, xmm1
	pslld	xmm1, 0x7
	pxor	xmm5, xmm1
	psrld	xmm2, 0x19
	pxor	xmm5, xmm2
	movaps	xmm1, xmm0
	paddd	xmm1, xmm7
	movaps	xmm2, xmm1
	pslld	xmm1, 0x9
	pxor	xmm10, xmm1
	psrld	xmm2, 0x17
	pxor	xmm10, xmm2
	movaps	xmm1, xmm12
	paddd	xmm1, xmm5
	movaps	xmm2, xmm1
	pslld	xmm1, 0x9
	pxor	xmm8, xmm1
	psrld	xmm2, 0x17
	pxor	xmm8, xmm2
	movaps	xmm1, xmm7
	paddd	xmm1, xmm10
	movaps	xmm2, xmm1
	pslld	xmm1, 0xd
	pxor	xmm4, xmm1
	psrld	xmm2, 0x13
	pxor	xmm4, xmm2
	movaps	xmm1, xmm5
	paddd	xmm1, xmm8
	movaps	xmm2, xmm1
	pslld	xmm1, 0xd
	pxor	xmm14, xmm1
	psrld	xmm2, 0x13
	pxor	xmm14, xmm2
	movaps	xmm1, xmm10
	paddd	xmm1, xmm4
	movaps	xmm2, xmm1
	pslld	xmm1, 0x12
	pxor	xmm0, xmm1
	psrld	xmm2, 0xe
	pxor	xmm0, xmm2
	movaps	xmm1, [rsp+0x180]
	movaps	[rsp+0x180], xmm0
	movaps	xmm0, xmm8
	paddd	xmm0, xmm14
	movaps	xmm2, xmm0
	pslld	xmm0, 0x12
	pxor	xmm12, xmm0
	psrld	xmm2, 0xe
	pxor	xmm12, xmm2
	movaps	xmm0, xmm11
	paddd	xmm0, xmm1
	movaps	xmm2, xmm0
	pslld	xmm0, 0x7
	pxor	xmm6, xmm0
	psrld	xmm2, 0x19
	pxor	xmm6, xmm2
	movaps	xmm2, [rsp+0x190]
	movaps	[rsp+0x190], xmm12
	movaps	xmm0, xmm3
	paddd	xmm0, xmm2
	movaps	xmm12, xmm0
	pslld	xmm0, 0x7
	pxor	xmm13, xmm0
	psrld	xmm12, 0x19
	pxor	xmm13, xmm12
	movaps	xmm0, xmm1
	paddd	xmm0, xmm6
	movaps	xmm12, xmm0
	pslld	xmm0, 0x9
	pxor	xmm15, xmm0
	psrld	xmm12, 0x17
	pxor	xmm15, xmm12
	movaps	xmm0, xmm2
	paddd	xmm0, xmm13
	movaps	xmm12, xmm0
	pslld	xmm0, 0x9
	pxor	xmm9, xmm0
	psrld	xmm12, 0x17
	pxor	xmm9, xmm12
	movaps	xmm0, xmm6
	paddd	xmm0, xmm15
	movaps	xmm12, xmm0
	pslld	xmm0, 0xd
	pxor	xmm11, xmm0
	psrld	xmm12, 0x13
	pxor	xmm11, xmm12
	movaps	xmm0, xmm13
	paddd	xmm0, xmm9
	movaps	xmm12, xmm0
	pslld	xmm0, 0xd
	pxor	xmm3, xmm0
	psrld	xmm12, 0x13
	pxor	xmm3, xmm12
	movaps	xmm0, xmm15
	paddd	xmm0, xmm11
	movaps	xmm12, xmm0
	pslld	xmm0, 0x12
	pxor	xmm1, xmm0
	psrld	xmm12, 0xe
	pxor	xmm1, xmm12
	movaps	xmm0, xmm9
	paddd	xmm0, xmm3
	movaps	xmm12, xmm0
	pslld	xmm0, 0x12
	pxor	xmm2, xmm0
	psrld	xmm12, 0xe
	pxor	xmm2, xmm12
	movaps	xmm12, [rsp+0x180]
	movaps	xmm0, [rsp+0x190]
	sub	rdx, 0x2
	ja	.mainloop1
	paddd	xmm12, [rsp+0xb0]
	paddd	xmm7, [rsp+0xf0]
	paddd	xmm10, [rsp+0x120]
	paddd	xmm4, [rsp+0x150]
	movq	rdx, xmm12
	movq	rcx, xmm7
	movq	r8, xmm10
	movq	r9, xmm4
	pshufd	xmm12, xmm12, 0x39
	pshufd	xmm7, xmm7, 0x39
	pshufd	xmm10, xmm10, 0x39
	pshufd	xmm4, xmm4, 0x39
	xor	edx, [rsi]
	xor	ecx, [rsi+0x4]
	xor	r8d, [rsi+0x8]
	xor	r9d, [rsi+0xc]
	mov	[rdi], edx
	mov	[rdi+0x4], ecx
	mov	[rdi+0x8], r8d
	mov	[rdi+0xc], r9d
	movq	rdx, xmm12
	movq	rcx, xmm7
	movq	r8, xmm10
	movq	r9, xmm4
	pshufd	xmm12, xmm12, 0x39
	pshufd	xmm7, xmm7, 0x39
	pshufd	xmm10, xmm10, 0x39
	pshufd	xmm4, xmm4, 0x39
	xor	edx, [rsi+0x40]
	xor	ecx, [rsi+0x44]
	xor	r8d, [rsi+0x48]
	xor	r9d, [rsi+0x4c]
	mov	[rdi+0x40], edx
	mov	[rdi+0x44], ecx
	mov	[rdi+0x48], r8d
	mov	[rdi+0x4c], r9d
	movq	rdx, xmm12
	movq	rcx, xmm7
	movq	r8, xmm10
	movq	r9, xmm4
	pshufd	xmm12, xmm12, 0x39
	pshufd	xmm7, xmm7, 0x39
	pshufd	xmm10, xmm10, 0x39
	pshufd	xmm4, xmm4, 0x39
	xor	edx, [rsi+0x80]
	xor	ecx, [rsi+0x84]
	xor	r8d, [rsi+0x88]
	xor	r9d, [rsi+0x8c]
	mov	[rdi+0x80], edx
	mov	[rdi+0x84], ecx
	mov	[rdi+0x88], r8d
	mov	[rdi+0x8c], r9d
	movq	rdx, xmm12
	movq	rcx, xmm7
	movq	r8, xmm10
	movq	r9, xmm4
	xor	edx, [rsi+0xc0]
	xor	ecx, [rsi+0xc4]
	xor	r8d, [rsi+0xc8]
	xor	r9d, [rsi+0xcc]
	mov	[rdi+0xc0], edx
	mov	[rdi+0xc4], ecx
	mov	[rdi+0xc8], r8d
	mov	[rdi+0xcc], r9d
	paddd	xmm14, [rsp+0x130]
	paddd	xmm0, [rsp+0x80]
	paddd	xmm5, [rsp+0xc0]
	paddd	xmm8, [rsp+0x100]
	movq	rdx, xmm14
	movq	rcx, xmm0
	movq	r8, xmm5
	movq	r9, xmm8
	pshufd	xmm14, xmm14, 0x39
	pshufd	xmm0, xmm0, 0x39
	pshufd	xmm5, xmm5, 0x39
	pshufd	xmm8, xmm8, 0x39
	xor	edx, [rsi+0x10]
	xor	ecx, [rsi+0x14]
	xor	r8d, [rsi+0x18]
	xor	r9d, [rsi+0x1c]
	mov	[rdi+0x10], edx
	mov	[rdi+0x14], ecx
	mov	[rdi+0x18], r8d
	mov	[rdi+0x1c], r9d
	movq	rdx, xmm14
	movq	rcx, xmm0
	movq	r8, xmm5
	movq	r9, xmm8
	pshufd	xmm14, xmm14, 0x39
	pshufd	xmm0, xmm0, 0x39
	pshufd	xmm5, xmm5, 0x39
	pshufd	xmm8, xmm8, 0x39
	xor	edx, [rsi+0x50]
	xor	ecx, [rsi+0x54]
	xor	r8d, [rsi+0x58]
	xor	r9d, [rsi+0x5c]
	mov	[rdi+0x50], edx
	mov	[rdi+0x54], ecx
	mov	[rdi+0x58], r8d
	mov	[rdi+0x5c], r9d
	movq	rdx, xmm14
	movq	rcx, xmm0
	movq	r8, xmm5
	movq	r9, xmm8
	pshufd	xmm14, xmm14, 0x39
	pshufd	xmm0, xmm0, 0x39
	pshufd	xmm5, xmm5, 0x39
	pshufd	xmm8, xmm8, 0x39
	xor	edx, [rsi+0x90]
	xor	ecx, [rsi+0x94]
	xor	r8d, [rsi+0x98]
	xor	r9d, [rsi+0x9c]
	mov	[rdi+0x90], edx
	mov	[rdi+0x94], ecx
	mov	[rdi+0x98], r8d
	mov	[rdi+0x9c], r9d
	movq	rdx, xmm14
	movq	rcx, xmm0
	movq	r8, xmm5
	movq	r9, xmm8
	xor	edx, [rsi+0xd0]
	xor	ecx, [rsi+0xd4]
	xor	r8d, [rsi+0xd8]
	xor	r9d, [rsi+0xdc]
	mov	[rdi+0xd0], edx
	mov	[rdi+0xd4], ecx
	mov	[rdi+0xd8], r8d
	mov	[rdi+0xdc], r9d
	paddd	xmm15, [rsp+0x160]
	paddd	xmm11, [rsp+0x170]
	paddd	xmm1, [rsp+0x90]
	paddd	xmm6, [rsp+0xd0]
	movq	rdx, xmm15
	movq	rcx, xmm11
	movq	r8, xmm1
	movq	r9, xmm6
	pshufd	xmm15, xmm15, 0x39
	pshufd	xmm11, xmm11, 0x39
	pshufd	xmm1, xmm1, 0x39
	pshufd	xmm6, xmm6, 0x39
	xor	edx, [rsi+0x20]
	xor	ecx, [rsi+0x24]
	xor	r8d, [rsi+0x28]
	xor	r9d, [rsi+0x2c]
	mov	[rdi+0x20], edx
	mov	[rdi+0x24], ecx
	mov	[rdi+0x28], r8d
	mov	[rdi+0x2c], r9d
	movq	rdx, xmm15
	movq	rcx, xmm11
	movq	r8, xmm1
	movq	r9, xmm6
	pshufd	xmm15, xmm15, 0x39
	pshufd	xmm11, xmm11, 0x39
	pshufd	xmm1, xmm1, 0x39
	pshufd	xmm6, xmm6, 0x39
	xor	edx, [rsi+0x60]
	xor	ecx, [rsi+0x64]
	xor	r8d, [rsi+0x68]
	xor	r9d, [rsi+0x6c]
	mov	[rdi+0x60], edx
	mov	[rdi+0x64], ecx
	mov	[rdi+0x68], r8d
	mov	[rdi+0x6c], r9d
	movq	rdx, xmm15
	movq	rcx, xmm11
	movq	r8, xmm1
	movq	r9, xmm6
	pshufd	xmm15, xmm15, 0x39
	pshufd	xmm11, xmm11, 0x39
	pshufd	xmm1, xmm1, 0x39
	pshufd	xmm6, xmm6, 0x39
	xor	edx, [rsi+0xa0]
	xor	ecx, [rsi+0xa4]
	xor	r8d, [rsi+0xa8]
	xor	r9d, [rsi+0xac]
	mov	[rdi+0xa0], edx
	mov	[rdi+0xa4], ecx
	mov	[rdi+0xa8], r8d
	mov	[rdi+0xac], r9d
	movq	rdx, xmm15
	movq	rcx, xmm11
	movq	r8, xmm1
	movq	r9, xmm6
	xor	edx, [rsi+0xe0]
	xor	ecx, [rsi+0xe4]
	xor	r8d, [rsi+0xe8]
	xor	r9d, [rsi+0xec]
	mov	[rdi+0xe0], edx
	mov	[rdi+0xe4], ecx
	mov	[rdi+0xe8], r8d
	mov	[rdi+0xec], r9d
	paddd	xmm13, [rsp+0xe0]
	paddd	xmm9, [rsp+0x110]
	paddd	xmm3, [rsp+0x140]
	paddd	xmm2, [rsp+0xa0]
	movq	rdx, xmm13
	movq	rcx, xmm9
	movq	r8, xmm3
	movq	r9, xmm2
	pshufd	xmm13, xmm13, 0x39
	pshufd	xmm9, xmm9, 0x39
	pshufd	xmm3, xmm3, 0x39
	pshufd	xmm2, xmm2, 0x39
	xor	edx, [rsi+0x30]
	xor	ecx, [rsi+0x34]
	xor	r8d, [rsi+0x38]
	xor	r9d, [rsi+0x3c]
	mov	[rdi+0x30], edx
	mov	[rdi+0x34], ecx
	mov	[rdi+0x38], r8d
	mov	[rdi+0x3c], r9d
	movq	rdx, xmm13
	movq	rcx, xmm9
	movq	r8, xmm3
	movq	r9, xmm2
	pshufd	xmm13, xmm13, 0x39
	pshufd	xmm9, xmm9, 0x39
	pshufd	xmm3, xmm3, 0x39
	pshufd	xmm2, xmm2, 0x39
	xor	edx, [rsi+0x70]
	xor	ecx, [rsi+0x74]
	xor	r8d, [rsi+0x78]
	xor	r9d, [rsi+0x7c]
	mov	[rdi+0x70], edx
	mov	[rdi+0x74], ecx
	mov	[rdi+0x78], r8d
	mov	[rdi+0x7c], r9d
	movq	rdx, xmm13
	movq	rcx, xmm9
	movq	r8, xmm3
	movq	r9, xmm2
	pshufd	xmm13, xmm13, 0x39
	pshufd	xmm9, xmm9, 0x39
	pshufd	xmm3, xmm3, 0x39
	pshufd	xmm2, xmm2, 0x39
	xor	edx, [rsi+0xb0]
	xor	ecx, [rsi+0xb4]
	xor	r8d, [rsi+0xb8]
	xor	r9d, [rsi+0xbc]
	mov	[rdi+0xb0], edx
	mov	[rdi+0xb4], ecx
	mov	[rdi+0xb8], r8d
	mov	[rdi+0xbc], r9d
	movq	rdx, xmm13
	movq	rcx, xmm9
	movq	r8, xmm3
	movq	r9, xmm2
	xor	edx, [rsi+0xf0]
	xor	ecx, [rsi+0xf4]
	xor	r8d, [rsi+0xf8]
	xor	r9d, [rsi+0xfc]
	mov	[rdi+0xf0], edx
	mov	[rdi+0xf4], ecx
	mov	[rdi+0xf8], r8d
	mov	[rdi+0xfc], r9d
	sub	rbx, 0x100
	add	rsi, 0x100
	add	rdi, 0x100
	cmp	rbx, 0x100
	jae	.atleast256
	cmp	rbx, 0x0
	jbe	crypto_stream_salsa_xor_ic_atleast64
calign
.between1and255:
	cmp	rbx, 0x40
	jae	.nocopy
	push	rdi
	lea	rdi, [rsp+8]
	mov	rdx, rbx
	call	memcpy
	pop	rdx
	lea	rdi,[rsp]
	lea	rsi,[rsp]
.nocopy:
	movaps	xmm0, [rsp+0x70]
	movaps	xmm1, [rsp+0x40]
	movaps	xmm2, [rsp+0x50]
	movaps	xmm3, [rsp+0x60]
	movaps	xmm4, xmm1
	mov	rcx, 0x14
calign
.mainloop2:
	paddd	xmm4, xmm0
	movaps	xmm5, xmm0
	movaps	xmm6, xmm4
	pslld	xmm4, 0x7
	psrld	xmm6, 0x19
	pxor	xmm3, xmm4
	pxor	xmm3, xmm6
	paddd	xmm5, xmm3
	movaps	xmm4, xmm3
	movaps	xmm6, xmm5
	pslld	xmm5, 0x9
	psrld	xmm6, 0x17
	pxor	xmm2, xmm5
	pshufd	xmm3, xmm3, 0x93
	pxor	xmm2, xmm6
	paddd	xmm4, xmm2
	movaps	xmm5, xmm2
	movaps	xmm6, xmm4
	pslld	xmm4, 0xd
	psrld	xmm6, 0x13
	pxor	xmm1, xmm4
	pshufd	xmm2, xmm2, 0x4e
	pxor	xmm1, xmm6
	paddd	xmm5, xmm1
	movaps	xmm4, xmm3
	movaps	xmm6, xmm5
	pslld	xmm5, 0x12
	psrld	xmm6, 0xe
	pxor	xmm0, xmm5
	pshufd	xmm1, xmm1, 0x39
	pxor	xmm0, xmm6
	paddd	xmm4, xmm0
	movaps	xmm5, xmm0
	movaps	xmm6, xmm4
	pslld	xmm4, 0x7
	psrld	xmm6, 0x19
	pxor	xmm1, xmm4
	pxor	xmm1, xmm6
	paddd	xmm5, xmm1
	movaps	xmm4, xmm1
	movaps	xmm6, xmm5
	pslld	xmm5, 0x9
	psrld	xmm6, 0x17
	pxor	xmm2, xmm5
	pshufd	xmm1, xmm1, 0x93
	pxor	xmm2, xmm6
	paddd	xmm4, xmm2
	movaps	xmm5, xmm2
	movaps	xmm6, xmm4
	pslld	xmm4, 0xd
	psrld	xmm6, 0x13
	pxor	xmm3, xmm4
	pshufd	xmm2, xmm2, 0x4e
	pxor	xmm3, xmm6
	paddd	xmm5, xmm3
	movaps	xmm4, xmm1
	movaps	xmm6, xmm5
	pslld	xmm5, 0x12
	psrld	xmm6, 0xe
	pxor	xmm0, xmm5
	pshufd	xmm3, xmm3, 0x39
	pxor	xmm0, xmm6
	paddd	xmm4, xmm0
	movaps	xmm5, xmm0
	movaps	xmm6, xmm4
	pslld	xmm4, 0x7
	psrld	xmm6, 0x19
	pxor	xmm3, xmm4
	pxor	xmm3, xmm6
	paddd	xmm5, xmm3
	movaps	xmm4, xmm3
	movaps	xmm6, xmm5
	pslld	xmm5, 0x9
	psrld	xmm6, 0x17
	pxor	xmm2, xmm5
	pshufd	xmm3, xmm3, 0x93
	pxor	xmm2, xmm6
	paddd	xmm4, xmm2
	movaps	xmm5, xmm2
	movaps	xmm6, xmm4
	pslld	xmm4, 0xd
	psrld	xmm6, 0x13
	pxor	xmm1, xmm4
	pshufd	xmm2, xmm2, 0x4e
	pxor	xmm1, xmm6
	paddd	xmm5, xmm1
	movaps	xmm4, xmm3
	movaps	xmm6, xmm5
	pslld	xmm5, 0x12
	psrld	xmm6, 0xe
	pxor	xmm0, xmm5
	pshufd	xmm1, xmm1, 0x39
	pxor	xmm0, xmm6
	paddd	xmm4, xmm0
	movaps	xmm5, xmm0
	movaps	xmm6, xmm4
	pslld	xmm4, 0x7
	psrld	xmm6, 0x19
	pxor	xmm1, xmm4
	pxor	xmm1, xmm6
	paddd	xmm5, xmm1
	movaps	xmm4, xmm1
	movaps	xmm6, xmm5
	pslld	xmm5, 0x9
	psrld	xmm6, 0x17
	pxor	xmm2, xmm5
	pshufd	xmm1, xmm1, 0x93
	pxor	xmm2, xmm6
	paddd	xmm4, xmm2
	movaps	xmm5, xmm2
	movaps	xmm6, xmm4
	pslld	xmm4, 0xd
	psrld	xmm6, 0x13
	pxor	xmm3, xmm4
	pshufd	xmm2, xmm2, 0x4e
	pxor	xmm3, xmm6
	sub	rcx, 0x4
	paddd	xmm5, xmm3
	movaps	xmm4, xmm1
	movaps	xmm6, xmm5
	pslld	xmm5, 0x12
	pxor	xmm7, xmm7
	psrld	xmm6, 0xe
	pxor	xmm0, xmm5
	pshufd	xmm3, xmm3, 0x39
	pxor	xmm0, xmm6
	ja	.mainloop2
	paddd	xmm0, [rsp+0x70]
	paddd	xmm1, [rsp+0x40]
	paddd	xmm2, [rsp+0x50]
	paddd	xmm3, [rsp+0x60]
	movq	rcx, xmm0
	movq	r8, xmm1
	movq	r9, xmm2
	movq	rax, xmm3
	pshufd	xmm0, xmm0, 0x39
	pshufd	xmm1, xmm1, 0x39
	pshufd	xmm2, xmm2, 0x39
	pshufd	xmm3, xmm3, 0x39
	xor	ecx, [rsi]
	xor	r8d, [rsi+0x30]
	xor	r9d, [rsi+0x20]
	xor	eax, [rsi+0x10]
	mov	[rdi], ecx
	mov	[rdi+0x30], r8d
	mov	[rdi+0x20], r9d
	mov	[rdi+0x10], eax
	movq	rcx, xmm0
	movq	r8, xmm1
	movq	r9, xmm2
	movq	rax, xmm3
	pshufd	xmm0, xmm0, 0x39
	pshufd	xmm1, xmm1, 0x39
	pshufd	xmm2, xmm2, 0x39
	pshufd	xmm3, xmm3, 0x39
	xor	ecx, [rsi+0x14]
	xor	r8d, [rsi+0x4]
	xor	r9d, [rsi+0x34]
	xor	eax, [rsi+0x24]
	mov	[rdi+0x14], ecx
	mov	[rdi+0x4], r8d
	mov	[rdi+0x34], r9d
	mov	[rdi+0x24], eax
	movq	rcx, xmm0
	movq	r8, xmm1
	movq	r9, xmm2
	movq	rax, xmm3
	pshufd	xmm0, xmm0, 0x39
	pshufd	xmm1, xmm1, 0x39
	pshufd	xmm2, xmm2, 0x39
	pshufd	xmm3, xmm3, 0x39
	xor	ecx, [rsi+0x28]
	xor	r8d, [rsi+0x18]
	xor	r9d, [rsi+0x8]
	xor	eax, [rsi+0x38]
	mov	[rdi+0x28], ecx
	mov	[rdi+0x18], r8d
	mov	[rdi+0x8], r9d
	mov	[rdi+0x38], eax
	movq	rcx, xmm0
	movq	r8, xmm1
	movq	r9, xmm2
	movq	rax, xmm3
	xor	ecx, [rsi+0x3c]
	xor	r8d, [rsi+0x2c]
	xor	r9d, [rsi+0x1c]
	xor	eax, [rsi+0xc]
	mov	[rdi+0x3c], ecx
	mov	[rdi+0x2c], r8d
	mov	[rdi+0x1c], r9d
	mov	[rdi+0xc], eax
	mov	rcx, [rsp+0x1d8]
	add	rcx, 0x1
	mov	r8, rcx
	shr	r8, 0x20
	mov	[rsp+0x50], ecx
	mov	[rsp+0x64], r8d
	mov	[rsp+0x1d8], rcx
	cmp	rbx, 0x40
	ja	.atleast65
	jae	crypto_stream_salsa_xor_ic_atleast64
	mov	rsi, rdi
	mov	rdi, rdx
	mov	rdx, rbx
	call	memcpy
	; atleast64 copied.
	mov	r11, [rsp+0x1a0]
	; mov	r12, [rsp+0x1a8]
	; mov	r13, [rsp+0x1b0]
	; mov	r14, [rsp+0x1b8]
	; mov	r15, [rsp+0x1c0]
	mov	rbx, [rsp+0x1c8]
	; mov	rbp, [rsp+0x1d0]
	add	rsp, r11
	xor	rax, rax
	mov	rdx, rsi
	epilog
calign
.atleast65:
	sub	rbx, 0x40
	add	rdi, 0x40
	add	rsi, 0x40
	jmp	.between1and255
calign
crypto_stream_salsa_xor_ic_atleast64:
	mov	r11, [rsp+0x1a0]
	; mov	r12, [rsp+0x1a8]
	; mov	r13, [rsp+0x1b0]
	; mov	r14, [rsp+0x1b8]
	; mov	r15, [rsp+0x1c0]
	mov	rbx, [rsp+0x1c8]
	; mov	rbp, [rsp+0x1d0]
	add	rsp, r11
	xor	rax, rax
	mov	rdx, rsi
	epilog


end if




if used crypto_box_open_easy | defined include_everything

	; six arguments: rdi == plaintext (space less 16 bytes), rsi == ciphertext, rdx == length of same, rcx == ptr to nonce (24 bytes), r8 == sender pubkey, r9 == recipient private key
	; returns a bool in eax as to whether we succeeded or not
falign
crypto_box_open_easy:
	prolog	crypto_box_open_easy
	push	rbp rbx r12
	mov	rbp, rdi
	mov	rbx, rsi
	mov	r12, rdx		; clen
	push	r13 r14 r15
	mov	r13, rcx
	mov	r14, r8
	mov	r15, r9
	sub	rsp, 128 + poly1305_state_size
	lea	rdi, [rsp+32]
	mov	rsi, r9
	mov	rdx, r8
	call	curve25519$donna
	; hsalsa20(rsp, .before_n, rsp+32, .sigma)
	mov	rdi, rsp			; k
	mov	rsi, .before_n
	lea	rdx, [rsp+32]
	mov	rcx, .sigma
	call	hsalsa20

	; block0 @ rsp+32
	; subkey @ rsp+96

	lea	rdi, [rsp+96]		; subkey
	mov	rsi, r13		; n
	mov	rdx, rsp		; k
	mov	rcx, .sigma
	call	hsalsa20

	; crypto_stream_salsa20(block0, 32, n+16, subkey)
	lea	rdi, [rsp+32]
	lea	rsi, [r13+16]
	lea	rdx, [rsp+96]
	call	crypto_stream_salsa20_32

	lea	rdi, [rsp+128]
	lea	rsi, [rsp+32]		; block0 == key
	call	poly1305$init
	lea	rdi, [rsp+128]
	lea	rsi, [rbx+16]
	lea	rdx, [r12-16]
	call	poly1305$update
	lea	rdi, [rsp+128]
	lea	rsi, [rsp+128]		; we can safely reuse its state space for the final
	xor	edx, edx		; dont try to heap$free its state
	call	poly1305$final
	xor	eax, eax		; return in the event we fail the check
	mov	rdx, [rsp+128]
	mov	rcx, [rsp+136]
	cmp	rdx, [rbx]
	jne	.fail_clear
	cmp	rcx, [rbx+8]
	jne	.fail_clear
	lea	r14, [r12-16]
	mov	ecx, 32
	cmp	r14, 32
	cmova	r14, rcx		; mlen0

	lea	rdi, [rsp+64]		; block0[32]
	lea	rsi, [rbx+16]		; c (after mac)
	mov	rdx, r14		; mlen0
	call	memcpy

	add	r14, 32
	lea	rdi, [rsp+32]		; block0
	lea	rsi, [rsp+32]		; block0
	mov	rdx, r14		; mlen0+32
	lea	rcx, [r13+16]		; n+16
	lea	r9, [rsp+96]		; subkey
	xor	r8d, r8d		; ic=0
	call	crypto_stream_salsa_xor_ic
	sub	r14, 32

	mov	rdi, rbp
	lea	rsi, [rsp+64]
	mov	rdx, r14
	call	memcpy

	cmp	r12, r14
	jbe	.nomore
	lea	rdi, [rbp+r14]			; m + mlen0
	lea	rsi, [rbx+r14+16]		; c + mlen0
	mov	rdx, r12
	lea	rcx, [r13+16]			; n+16
	sub	rdx, r14			; clen - mlen0
	mov	r8d, 1
	sub	rdx, 16				; - 16
	lea	r9, [rsp+96]			; subkey
	call	crypto_stream_salsa_xor_ic
.nomore:
	; done, dusted
	mov	eax, 1
.fail_clear:
	; cleanup
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, 128	; poly1305$final cleans up after itself
	call	memset32
	add	rsp, 128 + poly1305_state_size
	pop	r15 r14 r13 r12 rbx rbp
	epilog
dalign
.sigma:
	db	'expand 32-byte k'
.before_n:
	dq	0,0


end if



if used crypto_box_easy | defined include_everything
	; six arguments: rdi == ciphertext (message len + 16 bytes), rsi == message, rdx == length of same, rcx == ptr to nonce (24 bytes), r8 == recipient pubkey, r9 == sender private key
	; (note: no in-place is allowed here, skipped the memmove check)
falign
crypto_box_easy:
	prolog	crypto_box_easy
	push	rbp rbx r12
	mov	rbp, rdi
	mov	rbx, rsi
	mov	r12, rdx
	push	r13 r14 r15
	mov	r13, rcx
	mov	r14, r8
	mov	r15, r9
	sub	rsp, 128 + poly1305_state_size
	lea	rdi, [rsp+32]
	mov	rsi, r9
	mov	rdx, r8
	call	curve25519$donna
	; hsalsa20(rsp, .before_n, rsp+32, .sigma)
	mov	rdi, rsp
	mov	rsi, .before_n
	lea	rdx, [rsp+32]
	mov	rcx, .sigma
	call	hsalsa20
	pxor	xmm4, xmm4
	; c = rbp+16
	; mac = rbp
	; m = rbx
	; mlen = r12
	; n = r13
	; k = rsp

	; block0 @ rsp+32
	; subkey @ rsp+96

	lea	rdi, [rsp+96]		; subkey
	mov	rsi, r13		; n
	mov	rdx, rsp		; k
	mov	rcx, .sigma
	movups	[rsp+32], xmm4
	movups	[rsp+48], xmm4
	call	hsalsa20

	mov	r14, r12
	mov	ecx, 32
	cmp	r14, 32
	cmova	r14, rcx

	lea	rdi, [rsp+64]		; block0[32]
	mov	rsi, rbx		; m
	mov	rdx, r14		; mlen0
	call	memcpy
	add	r14, 32

	lea	rdi, [rsp+32]		; block0
	lea	rsi, [rsp+32]		; block0
	mov	rdx, r14		; mlen0+32
	lea	rcx, [r13+16]		; n+16
	lea	r9, [rsp+96]		; subkey
	xor	r8d, r8d		; ic=0
	call	crypto_stream_salsa_xor_ic

	sub	r14, 32
	lea	rdi, [rsp+128]
	lea	rsi, [rsp+32]
	call	poly1305$init

	lea	rdi, [rbp+16]		; c
	lea	rsi, [rsp+64]		; block0[32]
	mov	rdx, r14		; mlen0
	call	memcpy
	cmp	r12, r14
	jbe	.nomore
	lea	rdi, [rbp+r14+16]		; c + mlen0
	lea	rsi, [rbx+r14]			; m + mlen0
	mov	rdx, r12
	lea	rcx, [r13+16]			; n+16
	mov	r8d, 1
	lea	r9, [rsp+96]			; subkey
	sub	rdx, r14
	call	crypto_stream_salsa_xor_ic
.nomore:
	lea	rdi, [rsp+128]
	lea	rsi, [rbp+16]		; c
	mov	rdx, r12		; mlen
	call	poly1305$update
	lea	rdi, [rsp+128]
	mov	rsi, rbp		; mac
	xor	edx, edx
	call	poly1305$final
	; cleanup
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, 128	; poly1305$final cleans up after itself
	call	memset32
	add	rsp, 128 + poly1305_state_size
	pop	r15 r14 r13 r12 rbx rbp
	epilog
dalign
.sigma:
	db	'expand 32-byte k'
.before_n:
	dq	0,0

end if
