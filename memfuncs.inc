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
	; memfuncs.inc: memset, memcmp, memcmp16, memcpy
	;
	; Portions of this file are heavily modified routines that Agner Fog released
	; also under the GPL in his excellent optimization resources.
	; Because the heavily modified functions herein are from various source files
	; of his, and that each of his source files contains its own unique copyright
	; notice, included below is the asmlib.h header that covers them all.
	; 
	; Cheers Agner for some of this as usual; All Hail Agner!
	;
	; NOTE re: Agner, where I did in fact follow his fine lead, they are not verbatim
	; copies... because of the way I enforce 16 byte aligned jump targets _everywhere_
	; we had to take some liberties...
	;
	; Agner's asmlib copyright appears below:
	;/*************************** asmlib.h ***************************************
	;* Author:        Agner Fog
	;* Date created:  2003-12-12
	;* Last modified: 2012-03-10
	;* Project:       asmlib.zip
	;* Source URL:    www.agner.org/optimize
	;*
	;* Description:
	;* Header file for the asmlib function library.
	;* This library is available in many versions for different platforms.
	;* See asmlib-instructions.pdf for details.
	;*
	;* (c) Copyright 2003 - 2012 by Agner Fog. 
	;* GNU General Public License http://www.gnu.org/licenses/gpl.html
	;*****************************************************************************/

	; we also include a strlen_latin1 function in here for c strings


if used strlen_latin1 | defined include_everything
	; rdi == c string
falign
strlen_latin1:
	prolog	strlen_latin1
	mov	rax, rdi
	sub	rax, 1
calign
.top:
	add	rax, 1
	test	rax, 3
	jnz	.misaligned
calign
.inner:
	mov	ecx, [rax]
	add	rax, 4
	mov	edx, ecx
	not	ecx
	sub	edx, 0x01010101
	and	ecx, 0x80808080
	and	ecx, edx
	jz	.inner
	sub	rax, 4
calign
.misaligned:
	cmp	byte [rax], 0
	jne	.top
	sub	rax, rdi
	epilog
end if



if used memset | defined include_everything
	; rdi == dest, esi (char), rdx == count

	; rcx == dest2
	; r8 == count2
	; xmm0 == x0
falign
memset:
	prolog memset
	mov	r8, rdx
	imul	esi, 0x01010101
	mov	rcx, rdi
	cmp	rdx, 16
	ja	.m100

	shl	rdx, 3
	add	rdx, .AlignmentDispatch
	jmp	qword [rdx]
calign
.m16:
	mov	[rdi+12], esi
	mov	[rdi+8], esi
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m12:
	mov	[rdi+8], esi
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m08:
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m04:
	mov	[rdi], esi
	epilog
calign
.m15:
	mov	[rdi+11], esi
	mov	[rdi+7], esi
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
	; yeah wow I don't get that.
calign
.m11:
	mov	[rdi+7], esi
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m07:
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m03:
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m01:
	mov	[rdi], sil
	epilog
calign
.m14:
	mov	[rdi+10], esi
	mov	[rdi+6], esi
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m10:
	mov	[rdi+6], esi
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m06:
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m02:
	mov	[rdi], si
	epilog
calign
.m13:
	mov	[rdi+9], esi
	mov	[rdi+5], esi
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m09:
	mov	[rdi+5], esi
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m05:
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m00:
	epilog
dalign
.AlignmentDispatch:
	dq	.m00, .m01, .m02, .m03, .m04, .m05, .m06, .m07, .m08, .m09, .m10, .m11, .m12, .m13, .m14, .m15, .m16


	; note here: i don't do memset64 typically with sizes big enough to warrant his non-temporal goods being
	; actively checked
calign
.m100:
	movd	xmm0, esi
	pshufd	xmm0, xmm0, 0
	movq	[rdi], xmm0
	movq	[rdi+8], xmm0
	lea	rdx, [rdi+rdx-1]
	and	rdx, -10H
	add	rdi, 10H
	and	rdi, -10H
	sub	rdi, rdx
	jnl	.m300
calign
.m200:
	movdqa	[rdx+rdi], xmm0
	add	rdi, 10H
	jnz	.m200
calign
.m300:
	movq	[rcx+r8-10H], xmm0
	movq	[rcx+r8-8], xmm0
	epilog
end if
	



if used memset16 | defined include_everything
	; NOTE NOTE NOTE: this is the same as memset only we do utf16 character setting instead of byte setting
	; it is ASSUMED that rdx & 1 == 0
	; rdi == dest, esi (char), rdx == count (in BYTES, even though it is misleading)

	; rcx == dest2
	; r8 == count2
	; xmm0 == x0
falign
memset16:
	prolog memset16
	mov	r8, rdx
	imul	esi, 0x10001	
	mov	rcx, rdi
	cmp	rdx, 16
	ja	.m100

	shl	rdx, 3
	add	rdx, .AlignmentDispatch
	jmp	qword [rdx]
calign
.m16:
	mov	[rdi+12], esi
	mov	[rdi+8], esi
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m12:
	mov	[rdi+8], esi
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m08:
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m04:
	mov	[rdi], esi
	epilog


	; these will not be called, but we leave them here anyway
calign
.m15:
	mov	[rdi+11], esi
	mov	[rdi+7], esi
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
	; yeah wow I don't get that.
calign
.m11:
	mov	[rdi+7], esi
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m07:
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m03:
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m01:
	mov	[rdi], sil
	epilog

calign
.m14:
	mov	[rdi+10], esi
	mov	[rdi+6], esi
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m10:
	mov	[rdi+6], esi
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m06:
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m02:
	mov	[rdi], si
	epilog
calign
.m13:
	mov	[rdi+9], esi
	mov	[rdi+5], esi
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m09:
	mov	[rdi+5], esi
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m05:
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m00:
	epilog
dalign
.AlignmentDispatch:
	dq	.m00, .m01, .m02, .m03, .m04, .m05, .m06, .m07, .m08, .m09, .m10, .m11, .m12, .m13, .m14, .m15, .m16


	; note here: i don't do memset64 typically with sizes big enough to warrant his non-temporal goods being
	; actively checked
calign
.m100:
	movd	xmm0, esi
	pshufd	xmm0, xmm0, 0
	movq	[rdi], xmm0
	movq	[rdi+8], xmm0
	lea	rdx, [rdi+rdx-1]
	and	rdx, -10H
	add	rdi, 10H
	and	rdi, -10H
	sub	rdi, rdx
	jnl	.m300
calign
.m200:
	movdqa	[rdx+rdi], xmm0
	add	rdi, 10H
	jnz	.m200
calign
.m300:
	movq	[rcx+r8-10H], xmm0
	movq	[rcx+r8-8], xmm0
	epilog

end if


if used memset32 | defined include_everything
	; NOTE NOTE NOTE: this is the same as memset only we do utf32 character setting instead of byte setting
	; it is ASSUMED that rdx & 3 == 0
	; rdi == dest, esi (char), rdx == count (in BYTES, even though it is misleading)

	; rcx == dest2
	; r8 == count2
	; xmm0 == x0
falign
memset32:
	prolog memset32
	mov	r8, rdx
	mov	rcx, rdi
	cmp	rdx, 16
	ja	.m100

	shl	rdx, 3
	add	rdx, .AlignmentDispatch
	jmp	qword [rdx]
calign
.m16:
	mov	[rdi+12], esi
	mov	[rdi+8], esi
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m12:
	mov	[rdi+8], esi
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m08:
	mov	[rdi+4], esi
	mov	[rdi], esi
	epilog
calign
.m04:
	mov	[rdi], esi
	epilog


calign
.m15:
	mov	[rdi+11], esi
	mov	[rdi+7], esi
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m11:
	mov	[rdi+7], esi
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m07:
	mov	[rdi+3], esi
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m03:
	mov	[rdi+1], si
	mov	[rdi], sil
	epilog
calign
.m01:
	mov	[rdi], sil
	epilog

calign
.m14:
	mov	[rdi+10], esi
	mov	[rdi+6], esi
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m10:
	mov	[rdi+6], esi
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m06:
	mov	[rdi+2], esi
	mov	[rdi], si
	epilog
calign
.m02:
	mov	[rdi], si
	epilog
calign
.m13:
	mov	[rdi+9], esi
	mov	[rdi+5], esi
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m09:
	mov	[rdi+5], esi
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m05:
	mov	[rdi+1], esi
	mov	[rdi], sil
	epilog
calign
.m00:
	epilog
dalign
.AlignmentDispatch:
	dq	.m00, .m01, .m02, .m03, .m04, .m05, .m06, .m07, .m08, .m09, .m10, .m11, .m12, .m13, .m14, .m15, .m16


	; note here: i don't do memset64 typically with sizes big enough to warrant his non-temporal goods being
	; actively checked
calign
.m100:
	movd	xmm0, esi
	pshufd	xmm0, xmm0, 0
	movq	[rdi], xmm0
	movq	[rdi+8], xmm0
	lea	rdx, [rdi+rdx-1]
	and	rdx, -10H
	add	rdi, 10H
	and	rdi, -10H
	sub	rdi, rdx
	jnl	.m300
calign
.m200:
	movdqa	[rdx+rdi], xmm0
	add	rdi, 10H
	jnz	.m200
calign
.m300:
	movq	[rcx+r8-10H], xmm0
	movq	[rcx+r8-8], xmm0
	epilog
	
end if



if used memcmp | defined include_everything
	; ok so, this probably is not the best way to do this, but since we have a decently high probability
	; of ALL our memory regions being aligned (due to heap$alloc)
	; the various methods for doing this are all similar, and this way isn't TERRIBLE by any means
	; TODO: study timings better

	; rdi == left, rsi == right, rdx == count
	; return in rax

	; rax == x
falign
memcmp:
	prolog memcmp
	add	rdi, rdx
	add	rsi, rdx
	neg	rdx
calign
.do32:
	cmp	rdx, -32
	jg	.do16
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	mov	rax, [rdi+rdx+8]
	xor	rax, [rsi+rdx+8]
	jnz	.inequal64_8
	mov	rax, [rdi+rdx+0x10]
	xor	rax, [rsi+rdx+0x10]
	jnz	.inequal64_16
	mov	rax, [rdi+rdx+0x18]
	xor	rax, [rsi+rdx+0x18]
	jnz	.inequal64_24
	add	rdx, 0x20
	cmp	rdx, -32
	jbe	.do32
calign
.do16:
	cmp	rdx, -16
	jg	.do8
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	mov	rax, [rdi+rdx+8]
	xor	rax, [rsi+rdx+8]
	jnz	.inequal64_8
	add	rdx, 0x10
calign
.do8:
	cmp	rdx, -8
	jg	.do4
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	add	rdx, 8
calign
.do4:
	cmp	rdx, -4
	jg	.do2
	mov	eax, [rdi+rdx]
	xor	eax, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	add	rdx, 4
calign
.do2:
	cmp	rdx, -2
	jg	.do1
	xor	eax, eax
	mov	ax, [rdi+rdx]
	xor	ax, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	add	rdx, 2
calign
.do1:
	cmp	rdx, -1
	jg	.alldone
	xor	eax, eax
	mov	al, [rdi+rdx]
	xor	al, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	; rax must be zero
	epilog
calign
.alldone:
	xor	eax, eax
	epilog
calign
.inequal64:
	; ok so we did an xor of the right into the left, and it said the result was nonzero
	; so now we can bit scan forward our value in x to determine which byte # it was
	bsf	rax, rax
	; so now rax contains a 0..64 #, and we need that to be converted to a 0..7 number
	shr	rax, 3
	add	rdx, rax
	movzx	rax, byte [rdi+rdx]
	movzx	rdi, byte [rsi+rdx]
	sub	rax, rdi
	epilog
calign
.inequal64_8:
	bsf	rax, rax
	shr	rax, 3
	add	rdx, rax
	movzx	rax, byte [rdi+rdx+8]
	movzx	rdi, byte [rsi+rdx+8]
	sub	rax, rdi
	epilog

calign
.inequal64_16:
	bsf	rax, rax
	shr	rax, 3
	add	rdx, rax
	movzx	rax, byte [rdi+rdx+0x10]
	movzx	rdi, byte [rsi+rdx+0x10]
	sub	rax, rdi
	epilog

calign
.inequal64_24:
	bsf	rax, rax
	shr	rax, 3
	add	rdx, rax
	movzx	rax, byte [rdi+rdx+0x18]
	movzx	rdi, byte [rsi+rdx+0x18]
	sub	rax, rdi
	epilog
end if
	


if used memcmp16 | defined include_everything

	; this is the same as memcmp, but does 16 bits instead of byte comps, useful for my UTF16 goods
	; NOTE: this ASSUMES rdx & 1 is 0
	; rdi == left, rsi == right, rdx == count
falign
memcmp16:
	prolog memcmp16
	add	rdi, rdx
	add	rsi, rdx
	neg	rdx
calign
.do32:
	cmp	rdx, -32
	jg	.do16
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	mov	rax, [rdi+rdx+8]
	xor	rax, [rsi+rdx+8]
	jnz	.inequal64_8
	mov	rax, [rdi+rdx+0x10]
	xor	rax, [rsi+rdx+0x10]
	jnz	.inequal64_16
	mov	rax, [rdi+rdx+0x18]
	xor	rax, [rsi+rdx+0x18]
	jnz	.inequal64_24
	add	rdx, 0x20
	cmp	rdx, -32
	jbe	.do32
calign
.do16:
	cmp	rdx, -16
	jg	.do8
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	mov	rax, [rdi+rdx+8]
	xor	rax, [rsi+rdx+8]
	jnz	.inequal64_8
	add	rdx, 0x10
calign
.do8:
	cmp	rdx, -8
	jg	.do4
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	add	rdx, 8
calign
.do4:
	cmp	rdx, -4
	jg	.do2
	mov	eax, [rdi+rdx]
	xor	eax, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	add	rdx, 4
calign
.do2:
	cmp	rdx, -2
	jg	.do1
	xor	eax, eax
	mov	ax, [rdi+rdx]
	xor	ax, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	add	rdx, 2
calign
.do1:
	; NEVER REACHED (unless our previous assumption was not adhered to)
	cmp	rdx, -1
	jg	.alldone
	xor	eax, eax
	mov	al, [rdi+rdx]
	xor	al, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	; rax must be zero
	epilog
calign
.alldone:
	xor	eax, eax
	epilog
calign
.inequal64:
	; ok so we did an xor of the right into the left, and it said the result was nonzero
	; so now we can bit scan forward our value in x to determine which byte # it was
	bsf	rax, rax
	; so now rax contains a 0..64 #, and we need that to be converted to a 0..7 number
	; which means we need to shr 4 that result to get our word number
	shr	rax, 4
	shl	rax, 1		; hmm, shr 3 and then an and instead? or two adds? TODO
	add	rdx, rax
	movzx	rax, word [rdi+rdx]
	movzx	rdi, word [rsi+rdx]
	sub	rax, rdi
	epilog
calign
.inequal64_8:
	bsf	rax, rax
	shr	rax, 4
	shl	rax, 1
	add	rdx, rax
	movzx	rax, word [rdi+rdx+8]
	movzx	rdi, word [rsi+rdx+8]
	sub	rax, rdi
	epilog

calign
.inequal64_16:
	bsf	rax, rax
	shr	rax, 4
	shl	rax, 1
	add	rdx, rax
	movzx	rax, word [rdi+rdx+0x10]
	movzx	rdi, word [rsi+rdx+0x10]
	sub	rax, rdi
	epilog

calign
.inequal64_24:
	bsf	rax, rax
	shr	rax, 4
	shl	rax, 1
	add	rdx, rax
	movzx	rax, word [rdi+rdx+0x18]
	movzx	rdi, word [rsi+rdx+0x18]
	sub	rax, rdi
	epilog
end if
	


if used memcmp32 | defined include_everything

	; this is the same as memcmp, but does 32 bits instead of byte comps, useful for my UTF32 goods
	; NOTE: this ASSUMES rdx & 3 is 0
	; rdi == left, rsi == right, rdx == count
falign
memcmp32:
	prolog memcmp32
	add	rdi, rdx
	add	rsi, rdx
	neg	rdx
calign
.do32:
	cmp	rdx, -32
	jg	.do16
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	mov	rax, [rdi+rdx+8]
	xor	rax, [rsi+rdx+8]
	jnz	.inequal64_8
	mov	rax, [rdi+rdx+0x10]
	xor	rax, [rsi+rdx+0x10]
	jnz	.inequal64_16
	mov	rax, [rdi+rdx+0x18]
	xor	rax, [rsi+rdx+0x18]
	jnz	.inequal64_24
	add	rdx, 0x20
	cmp	rdx, -32
	jbe	.do32
calign
.do16:
	cmp	rdx, -16
	jg	.do8
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	mov	rax, [rdi+rdx+8]
	xor	rax, [rsi+rdx+8]
	jnz	.inequal64_8
	add	rdx, 0x10
calign
.do8:
	cmp	rdx, -8
	jg	.do4
	mov	rax, [rdi+rdx]
	xor	rax, [rsi+rdx]
	jnz	.inequal64
	add	rdx, 8
calign
.do4:
	cmp	rdx, -4
	jg	.do2
	mov	eax, [rdi+rdx]
	xor	eax, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	add	rdx, 4
calign
.do2:
	; NEVER REACHED (unless our previous assumption was not adhered to)
	cmp	rdx, -2
	jg	.do1
	xor	eax, eax
	mov	ax, [rdi+rdx]
	xor	ax, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	add	rdx, 2
calign
.do1:
	; NEVER REACHED (unless our previous assumption was not adhered to)
	cmp	rdx, -1
	jg	.alldone
	xor	eax, eax
	mov	al, [rdi+rdx]
	xor	al, [rsi+rdx]
	jnz	.inequal64	; this is still okay cuz we are doing BSF
	; rax must be zero
	epilog
calign
.alldone:
	xor	eax, eax
	epilog
calign
.inequal64:
	; ok so we did an xor of the right into the left, and it said the result was nonzero
	; so now we can bit scan forward our value in x to determine which byte # it was
	bsf	rax, rax
	; so now rax contains a 0..64 #, and we need that to be converted to a 0..7 number
	; which means we need to shr 4 that result to get our word number
	shr	rax, 5
	shl	rax, 2		; hmm, shr 3 and then an and instead? or two adds? TODO
	add	rdx, rax
	mov	eax, dword [rdi+rdx]
	mov	edi, dword [rsi+rdx]
	sub	rax, rdi
	epilog
calign
.inequal64_8:
	bsf	rax, rax
	shr	rax, 5
	shl	rax, 2
	add	rdx, rax
	mov	eax, dword [rdi+rdx+8]
	mov	edi, dword [rsi+rdx+8]
	sub	rax, rdi
	epilog

calign
.inequal64_16:
	bsf	rax, rax
	shr	rax, 5
	shl	rax, 2
	add	rdx, rax
	mov	eax, dword [rdi+rdx+0x10]
	mov	edi, dword [rsi+rdx+0x10]
	sub	rax, rdi
	epilog
calign
.inequal64_24:
	bsf	rax, rax
	shr	rax, 5
	shl	rax, 2
	add	rdx, rax
	mov	eax, dword [rdi+rdx+0x18]
	mov	edi, dword [rsi+rdx+0x18]
	sub	rax, rdi
	epilog

end if


if used memmove | defined include_everything
	; rdi == dest, rsi == source, rdx == count
falign
memmove:
	prolog	memmove
	mov	rax, rdi
	sub	rax, rsi
	cmp	rax, rdx
	jae	.memcpyisokay
	mov	rcx, rdx
	mov	r9, rdi
	cmp	rcx, 0x40
	jae	.b0100
	test	ecx, 0x20
	jz	.a100
	sub	ecx, 0x20
	mov	rax, [rsi+rcx+0x18]
	mov	rdx, [rsi+rcx+0x10]
	mov	[rdi+rcx+0x18], rax
	mov	[rdi+rcx+0x10], rdx
	mov	rax, [rsi+rcx+8]
	mov	rdx, [rsi+rcx]
	mov	[rdi+rcx+8], rax
	mov	[rdi+rcx], rdx
calign
.a100:
	test	ecx, 0x10
	jz	.a200
	sub	ecx, 0x10
	mov	rax, [rsi+rcx+8]
	mov	rdx, [rsi+rcx]
	mov	[rdi+rcx+8], rax
	mov	[rdi+rcx], rdx
calign
.a200:
	test	ecx, 8
	jz	.a300
	sub	ecx, 8
	mov	rax, [rsi+rcx]
	mov	[rdi+rcx], rax
calign
.a300:
	test	ecx, 4
	jz	.a400
	sub	ecx, 4
	mov	eax, [rsi+rcx]
	mov	[rdi+rcx], eax
	jz	.a900
calign
.a400:
	test	ecx, 2
	jz	.a500
	sub	ecx, 2
	movzx	eax, word [rsi+rcx]
	mov	[rdi+rcx], ax
calign
.a500:
	test	ecx, 1
	jz	.a900
	movzx	eax, byte [rsi+rcx]
	mov	[rdi+rcx], al
calign
.a900:
	mov	rax, r9	; return value == dest?
	epilog
calign
.b0100:
	; count >= 64
	lea	edx, [rdi+rcx]
	and	edx, 0xf
	jz	.b0300
	test	edx, 3
	jz	.b0210
	test	edx, 1
	jz	.b0201
	sub	rcx, 1
	movzx	eax, byte [rsi+rcx]
	mov	[rdi+rcx], al
calign
.b0200:
	test	edx, 2
	jz	.b0210
calign
.b0201:
	sub	rcx, 2
	movzx	eax, word [rsi+rcx]
	mov	[rdi+rcx], ax
calign
.b0210:
	test	edx, 4
	jz	.b0220
	sub	rcx, 4
	mov	eax, [rsi+rcx]
	mov	[rdi+rcx], eax
calign
.b0220:
	test	edx, 8
	jz	.b0300
	sub	rcx, 8
	mov	rax, [rsi+rcx]
	mov	[rdi+rcx], rax
calign
.b0300:
	; dest aligned 16
	lea	eax, [rsi+rcx]
	and	eax, 0xf
	mov	edx, ecx
	and	rcx, -20H
	sub	edx, ecx
	sub	rsi, rax
	add	rsi, rdx
	add	rdi, rdx
	mov	r8, .alignmentdispatch
	jmp	qword [r8+rax*8]
dalign
.alignmentdispatch:
	dq	.c100, .d101, .d102, .d103, .d104, .d105, .d106, .d107
	dq	.d108, .d109, .d10a, .d10b, .d10c, .d10d, .d10e, .d10f
calign
.c100:
	movaps	xmm0, [rsi+rcx-10h]
	movaps	xmm1, [rsi+rcx-20h]
	movaps	[rdi+rcx-10h], xmm0
	movaps	[rdi+rcx-20h], xmm1
	sub	rcx, 20h
	jnz	.c100
	test	edx, edx
	jz	.c500
	test	edx, 10h
	jz	.c200
	sub	rcx, 10h
	movaps	xmm0, [rsi+rcx]
	movaps	[rdi+rcx], xmm0
calign
.c200:
	test	edx, edx
	jz	.c500
	test	edx, 8
	jz	.c210
	sub	rcx, 8
	mov	rax, [rsi+rcx]
	mov	[rdi+rcx], rax
calign
.c210:
	test	edx, 4
	jz	.c220
	sub	rcx, 4
	mov	eax, [rsi+rcx]
	mov	[rdi+rcx], eax
	jz	.c500
calign
.c220:
	test	edx, 2
	jz	.c230
	sub	rcx, 2
	movzx	eax, word [rsi+rcx]
	mov	[rdi+rcx], ax
calign
.c230:
	test	edx, 1
	jz	.c500
	movzx	eax, byte [rsi+rcx-1]
	mov	[rdi+rcx-1], al
calign
.c500:
	mov	rax, r9	; return value == dest?
	epilog

macro move_reverse_4 {
	local .l1,.l2
	movaps	xmm0, [rsi+rcx]
calign
.l1:
	sub	rcx, 20h
	movaps	xmm1, [rsi+rcx+10h]
	movaps	xmm2, [rsi+rcx]
	movaps	xmm3, xmm0
	movaps	xmm0, xmm2
	movss	xmm2, xmm1
	shufps	xmm2, xmm2, 00111001b
	movss	xmm1, xmm3
	shufps	xmm1, xmm1, 00111001b
	movaps	[rdi+rcx+10h], xmm1
	movaps	[rdi+rcx], xmm2
	jnz	.l1
	test	edx, 10h
	jz	.l2
	sub	rcx, 10h
	movaps	xmm1, [rsi+rcx]
	movss	xmm1, xmm0
	shufps	xmm1, xmm1, 00111001b
	movaps	[rdi+rcx], xmm1
calign
.l2:
	add	rsi, rax
	jmp	.c200
}

macro move_reverse_8 {
	local .l1,.l2
	movaps	xmm0, [rsi+rcx]
	shufps	xmm0, xmm0, 01001110b
calign
.l1:
	sub	rcx, 20h
	movaps	xmm1, [rsi+rcx+10h]
	shufps	xmm1, xmm1, 01001110b
	movsd	xmm0, xmm1
	movaps	[rdi+rcx+10h], xmm0
	movaps	xmm0, [rsi+rcx]
	shufps	xmm0, xmm0, 01001110b
	movsd	xmm1, xmm0
	movaps	[rdi+rcx], xmm1
	jnz	.l1
	test	edx, 10h
	jz	.l2
	sub	rcx, 10h
	movaps	xmm1, [rsi+rcx]
	shufps	xmm1, xmm1, 01001110b
	movsd	xmm0, xmm1
	movaps	[rdi+rcx], xmm0
calign
.l2:
	add	rsi, rax
	jmp	.c200
}

macro move_reverse_12 {
	local .l1,.l2
	movaps	xmm0, [rsi+rcx]
	shufps	xmm0, xmm0, 10010011b
calign
.l1:
	sub	rcx, 20h
	movaps	xmm1, [rsi+rcx+10h]
	shufps	xmm1, xmm1, 10010011b
	movss	xmm0, xmm1
	movaps	[rdi+rcx+10h], xmm0
	movaps	xmm0, [rsi+rcx]
	shufps	xmm0, xmm0, 10010011b
	movss	xmm1, xmm0
	movaps	[rdi+rcx], xmm1
	jnz	.l1
	test	edx, 10h
	jz	.l2
	sub	rcx, 10h
	movaps	xmm1, [rsi+rcx]
	shufps	xmm1, xmm1, 10010011b
	movss	xmm0, xmm1
	movaps	[rdi+rcx], xmm0
calign
.l2:
	add	rsi, rax
	jmp	.c200
}

macro move_reverse u {
	local .l1,.l2
	movdqa	xmm0, [rsi+rcx]
calign
.l1:
	sub	rcx, 20h
	movdqa	xmm1, [rsi+rcx+10h]
	movdqa	xmm2, [rsi+rcx]
	movdqa	xmm3, xmm1
	pslldq	xmm0, 16-u
	psrldq	xmm1, u
	por	xmm0, xmm1
	movdqa	[rdi+rcx+10h], xmm0
	movdqa	xmm0, xmm2
	pslldq	xmm3, 16-u
	psrldq	xmm2, u
	por	xmm3, xmm2
	movdqa	[rdi+rcx], xmm3
	jnz	.l1
	test	edx, 10h
	jz	.l2
	sub	rcx, 10h
	movdqa	xmm1, [rsi+rcx]
	pslldq	xmm0, 16-u
	psrldq	xmm1, u
	por	xmm0, xmm1
	movdqa	[rdi+rcx], xmm0
calign
.l2:
	add	rsi, rax
	jmp	.c200
}

calign
.d104:
	move_reverse_4
calign
.d108:
	move_reverse_8
calign
.d10c:
	move_reverse_12
calign
.d101:
	move_reverse 1
calign
.d102:
	move_reverse 2
calign
.d103:
	move_reverse 3
calign
.d105:
	move_reverse 5
calign
.d106:
	move_reverse 6
calign
.d107:
	move_reverse 7
calign
.d109:
	move_reverse 9
calign
.d10a:
	move_reverse 0xa
calign
.d10b:
	move_reverse 0xb
calign
.d10d:
	move_reverse 0xd
calign
.d10e:
	move_reverse 0xe
calign
.d10f:
	move_reverse 0xf
	
calign
.memcpyisokay:
	call	memcpy
	epilog

end if



; memcpy itself is quite large, and for >64 moves, is very fast, if you know that your copy is going to be small
; it may be better to use an inline version:
macro memcpy_inline {
	local .do32, .do16, .do8, .do4, .do2, .do1, .alldone
	add	rdi, rdx
	add	rsi, rdx
	neg	rdx
calign
.do32:
	cmp	rdx, -32
	jg	.do16
	mov	rcx, [rsi+rdx]
	mov	rax, [rsi+rdx+8]
	mov	[rdi+rdx], rcx
	mov	[rdi+rdx+8], rax
	mov	rcx, [rsi+rdx+0x10]
	mov	rax, [rsi+rdx+0x18]
	mov	[rdi+rdx+0x10], rcx
	mov	[rdi+rdx+0x18], rax
	add	rdx, 0x20
	jz	.alldone
	cmp	rdx, -32
	jle	.do32
calign
.do16:
	cmp	rdx, -16
	jg	.do8
	mov	rcx, [rsi+rdx]
	mov	rax, [rsi+rdx+8]
	mov	[rdi+rdx], rcx
	mov	[rdi+rdx+8], rax
	add	rdx, 0x10
	jz	.alldone
calign
.do8:
	cmp	rdx, -8
	jg	.do4
	mov	rcx, [rsi+rdx]
	mov	[rdi+rdx], rcx
	add	rdx, 8
	jz	.alldone
calign
.do4:
	cmp	rdx, -4
	jg	.do2
	mov	ecx, [rsi+rdx]
	mov	[rdi+rdx], ecx
	add	rdx, 4
	jz	.alldone
calign
.do2:
	cmp	rdx, -2
	jg	.do1
	movzx	ecx, word [rsi+rdx]
	mov	[rdi+rdx], cx
	add	rdx, 2
	jz	.alldone
calign
.do1:
	cmp	rdx, -1
	jg	.alldone
	movzx	ecx, byte [rsi+rdx]
	mov	[rdi+rdx], cl
calign
.alldone:
}




if used memcpy | defined include_everything
	; rdi == dest, rsi == source, rdx == count
falign
memcpy:
	prolog memcpy
	mov	r9, rdi
	cmp	rdx, 0x40
	jae	.loopy
	; count < 64, per agner, better to do 32, 16, 8, 4, 2, 1 for small counts, loopy for bigger
	add	rdi, rdx
	add	rsi, rdx
	neg	rdx
calign
.do32:
	cmp	rdx, -32
	jg	.do16
	mov	rcx, [rsi+rdx]
	mov	r8, [rsi+rdx+8]
	mov	[rdi+rdx], rcx
	mov	[rdi+rdx+8], r8
	mov	rcx, [rsi+rdx+0x10]
	mov	r8, [rsi+rdx+0x18]
	mov	[rdi+rdx+0x10], rcx
	mov	[rdi+rdx+0x18], r8
	add	rdx, 0x20
calign
.do16:
	cmp	rdx, -16
	jg	.do8
	mov	rcx, [rsi+rdx]
	mov	r8, [rsi+rdx+8]
	mov	[rdi+rdx], rcx
	mov	[rdi+rdx+8], r8
	add	rdx, 0x10
calign
.do8:
	cmp	rdx, -8
	jg	.do4
	mov	rcx, [rsi+rdx]
	mov	[rdi+rdx], rcx
	add	rdx, 8
calign
.do4:
	cmp	rdx, -4
	jg	.do2
	mov	ecx, [rsi+rdx]
	mov	[rdi+rdx], ecx
	add	rdx, 4
	jz	.alldone
calign
.do2:
	cmp	rdx, -2
	jg	.do1
	movzx	ecx, word [rsi+rdx]
	mov	[rdi+rdx], cx
	add	rdx, 2
	jz	.alldone
calign
.do1:
	cmp	rdx, -1
	jg	.alldone
	movzx	ecx, byte [rsi+rdx]
	mov	[rdi+rdx], cl
	mov	rax, r9
	epilog

	; rcx == w
	; r8 == x
	; xmm0..3 used

calign
.loopy:
	; count >= 64
	mov	ecx, edi
	neg	ecx
	and	ecx, 0xf
	jz	.l0200

	test	ecx, 3
	jz	.l0030
	test	ecx, 1
	jz	.l0020
	movzx	eax, byte [rsi]
	mov	[rdi], al
	add	rsi, 1
	add	rdi, 1
calign
.l0020:
	test	ecx, 2
	jz	.l0030
	movzx	eax, word [rsi]
	mov	[rdi], ax
	add	rsi, 2
	add	rdi, 2
calign
.l0030:
	test	ecx, 4
	jz	.l0040
	mov	eax, [rsi]
	mov	[rdi], eax
	add	rsi, 4
	add	rdi, 4
calign
.l0040:
	test	ecx, 8
	jz	.l0050
	mov	rax, [rsi]
	mov	[rdi], rax
	add	rsi, 8
	add	rdi, 8
calign
.l0050:
	sub	rdx, rcx
calign
.l0200:
	mov	ecx, edi
	neg	ecx
	and	ecx, 0xf
	jz	.l300
	add	rsi, rcx
	add	rdi, rcx
	sub	rdx, rcx
	neg	rcx
	cmp	ecx, -8
	jg	.l200
	mov	rax, [rsi+rcx]
	mov	[rdi+rcx], rax
	add	rcx, 8
calign
.l200:
	cmp	ecx, -4
	jg	.l210
	mov	eax, [rsi+rcx]
	mov	[rdi+rcx], eax
	add	rcx, 4
	jz	.l300
calign
.l210:
	cmp	ecx, -2
	movzx	eax, word [rsi+rcx]
	mov	[rdi+rcx], ax
	add	rcx, 2
calign
.l220:
	cmp	ecx, -1
	jg	.l300
	movzx	eax, byte [rsi+rcx]
	mov	[rdi+rcx], al
calign
.l300:
	mov	eax, esi
	and	eax, 0xf
	mov	r8d, edx
	and	rdx, -20H
	add	rsi, rdx
	add	rdi, rdx
	sub	r8d, edx		; remaining data after loop
	sub	rsi, rax
	neg	rdx
	shl	rax, 3
	add	rax, .alignmentdispatch
	jmp	qword [rax]



dalign
.alignmentdispatch:
	dq	.c100, .d101, .d102, .d103, .d104, .d105, .d106, .d107
	dq	.d108, .d109, .d10a, .d10b, .d10c, .d10d, .d10e, .d10f

calign
.c100:
	movaps	xmm0, [rsi+rdx]
	movaps	xmm1, [rsi+rdx+0x10]
	movaps	[rdi+rdx], xmm0
	movaps	[rdi+rdx+0x10], xmm1
	add	rdx, 0x20
	jnz	.c100
	add	rsi, r8
	add	rdi, r8
	neg	r8
	jz	.alldone
	cmp	r8d, -16
	jg	.c200
	movaps	xmm0, [rsi+r8]
	movaps	[rdi+r8], xmm0
	add	r8, 0x10
calign
.c200:
	cmp	r8d, -8
	jg	.c210
	mov	rcx, [rsi+r8]
	mov	[rdi+r8], rcx
	add	r8, 8
	jz	.alldone
calign
.c210:
	cmp	r8d, -4
	jg	.c220
	mov	ecx, [rsi+r8]
	mov	[rdi+r8], ecx
	add	r8, 4
	jz	.alldone
calign
.c220:
	cmp	r8d, -2
	jg	.c230
	movzx	ecx, word [rsi+r8]
	mov	[rdi+r8], cx
	add	r8, 2
calign
.c230:
	cmp	r8d, -1
	jg	.alldone
	movzx	ecx, byte [rsi+r8]
	mov	[rdi+r8], cl
	mov	rax, r9
	epilog

macro .move_unaligned_sse2 u* {
	movdqa	xmm0, [rsi+rdx]
calign
@@:
	movdqa	xmm1, [rsi+rdx+0x10]
	movdqa	xmm2, [rsi+rdx+0x20]
	movdqa	xmm3, xmm1
	psrldq	xmm0, u
	pslldq	xmm1, 16-u
	por	xmm0, xmm1
	movdqa	[rdi+rdx], xmm0
	movdqa	xmm0, xmm2
	psrldq	xmm3, u
	pslldq	xmm2, 16-u
	por	xmm3, xmm2
	movdqa	[rdi+rdx+0x10], xmm3
	add	rdx, 0x20
	jnz	@b
	add	rsi, r8
	add	rdi, r8
	neg	r8
	cmp	r8d, -16
	jg	@f
	movdqa	xmm1, [rsi+r8+0x10]
	psrldq	xmm0, u
	pslldq	xmm1, 16-u
	por	xmm0, xmm1
	movdqa	[rdi+r8], xmm0
	add	r8, 0x10
calign
@@:
	add	rsi, u
	jmp	.c200
}

calign
.d101:
	.move_unaligned_sse2 1
calign
.d102:
	.move_unaligned_sse2 2
calign
.d103:
	.move_unaligned_sse2 3
calign
.d104:
	movaps	xmm0, [rsi+rdx]
calign
@@:
	movaps	xmm1, [rsi+rdx+0x10]
	movss	xmm0, xmm1
	shufps	xmm0, xmm0, 00111001b	; rotate
	movaps	[rdi+rdx], xmm0
	movaps	xmm0, [rsi+rdx+0x20]
	movss	xmm1, xmm0
	shufps	xmm1, xmm1, 00111001b
	movaps	[rdi+rdx+0x10], xmm1
	add	rdx, 0x20
	jnz	@b
	add	rsi, r8
	add	rdi, r8
	neg	r8
	cmp	r8d, -10h
	jg	@f
	movaps	xmm1, [rsi+r8+0x10]
	movss	xmm0, xmm1
	shufps	xmm0, xmm0, 00111001b
	movaps	[rdi+r8], xmm0
	add	r8, 10h
calign
@@:
	add	rsi, 4
	jmp	.c200
calign
.d105:
	.move_unaligned_sse2 5
calign
.d106:
	.move_unaligned_sse2 6
calign
.d107:
	.move_unaligned_sse2 7
calign
.d108:
	movaps	xmm0, [rsi+rdx]
calign
@@:
	movaps	xmm1, [rsi+rdx+0x10]
	movsd	xmm0, xmm1
	shufps	xmm0, xmm0, 01001110b
	movaps	[rdi+rdx], xmm0
	movaps	xmm0, [rsi+rdx+0x20]
	movsd	xmm1, xmm0
	shufps	xmm1, xmm1, 01001110b
	movaps	[rdi+rdx+0x10], xmm1
	add	rdx, 0x20
	jnz	@b
	add	rsi, r8
	add	rdi, r8
	neg	r8
	cmp	r8d, -10H
	jg	@f
	movaps	xmm1, [rsi+r8+0x10]
	movsd	xmm0, xmm1
	shufps	xmm0, xmm0, 01001110b
	movaps	[rdi+r8], xmm0
	add	r8, 0x10
calign
@@:
	add	rsi, 8
	jmp	.c200
calign
.d109:
	.move_unaligned_sse2 9
calign
.d10a:
	.move_unaligned_sse2 0xa
calign
.d10b:
	.move_unaligned_sse2 0xb
calign
.d10c:
	movaps	xmm0, [rsi+rdx]
	shufps	xmm0, xmm0, 10010011b
calign
@@:
	movaps	xmm1, [rsi+rdx+0x10]
	movaps	xmm2, [rsi+rdx+0x20]
	shufps	xmm1, xmm1, 10010011b
	shufps	xmm2, xmm2, 10010011b
	movaps	xmm3, xmm2
	movss	xmm2, xmm1
	movss	xmm1, xmm0
	movaps	[rdi+rdx], xmm1
	movaps	[rdi+rdx+0x10], xmm2
	movaps	xmm0, xmm3
	add	rdx, 0x20
	jnz	@b
	add	rsi, r8
	add	rdi, r8
	neg	r8
	cmp	r8d, -10H
	jg	@f
	movaps	xmm1, [rsi+r8+0x10]
	shufps	xmm1, xmm1, 10010011b
	movss	xmm1, xmm0
	movdqa	[rdi+r8], xmm1
	add	r8, 0x10
calign
@@:
	add	rsi, 12
	jmp	.c200
calign
.d10d:
	.move_unaligned_sse2 0xd
calign
.d10e:
	.move_unaligned_sse2 0xe
calign
.d10f:
	.move_unaligned_sse2 0xf
calign
.alldone:
	mov	rax, r9
	epilog
end if


if used memreverse | defined include_everything
	; rdi == byte buffer, rsi == length of same (must be >0)
	; this reverses the bytes, not particularly efficient, but does the deed
falign
memreverse:
	prolog	memreverse
	lea	rsi, [rdi+rsi]
	sub	rsi, 1			; last character pointer
calign
.doit:
	movzx	ecx, byte [rdi]
	movzx	edx, byte [rsi]
	mov	byte [rdi], dl
	mov	byte [rsi], cl
	add	rdi, 1
	sub	rsi, 1
	cmp	rdi, rsi
	jb	.doit
	epilog

end if



if used memxor | defined include_everything
	; rdi == dest, rsi == source, rdx == count
falign
memxor:
	prolog memxor
	add	rdi, rdx
	add	rsi, rdx
	neg	rdx
calign
.do32:
	cmp	rdx, -32
	jg	.do16
	mov	rcx, [rsi+rdx]
	mov	rax, [rsi+rdx+8]
	xor	[rdi+rdx], rcx
	xor	[rdi+rdx+8], rax
	mov	rcx, [rsi+rdx+0x10]
	mov	rax, [rsi+rdx+0x18]
	xor	[rdi+rdx+0x10], rcx
	xor	[rdi+rdx+0x18], rax
	add	rdx, 0x20
	jmp	.do32
calign
.do16:
	cmp	rdx, -16
	jg	.do8
	mov	rcx, [rsi+rdx]
	mov	rax, [rsi+rdx+8]
	xor	[rdi+rdx], rcx
	xor	[rdi+rdx+8], rax
	add	rdx, 0x10
calign
.do8:
	cmp	rdx, -8
	jg	.do4
	mov	rcx, [rsi+rdx]
	xor	[rdi+rdx], rcx
	add	rdx, 8
calign
.do4:
	cmp	rdx, -4
	jg	.do2
	mov	ecx, [rsi+rdx]
	xor	[rdi+rdx], ecx
	add	rdx, 4
	jz	.alldone
calign
.do2:
	cmp	rdx, -2
	jg	.do1
	movzx	ecx, word [rsi+rdx]
	xor	[rdi+rdx], cx
	add	rdx, 2
	jz	.alldone
calign
.do1:
	cmp	rdx, -1
	jg	.alldone
	movzx	ecx, byte [rsi+rdx]
	xor	[rdi+rdx], cl
	epilog
calign
.alldone:
	epilog
end if
