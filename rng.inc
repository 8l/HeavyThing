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
	; rng.inc: RNG goodies
	;
	; this is a loose transcode from a loose transcode from a different assembler enviro
	; which was a loose transcode from agners rng goods, which is a transcode from
	; the SFMT, combined with the mother-of-all rng, which agner states is sufficient
	; for security applications (due to very long cycle lengths, and when used with
	; rng_heavy_init, trying every seed possibility is not viable either).
	; see agner's papers on rng theory and his choices for further info... good enough
	; for agner, good enough for me :-)
	;
	; Our library defaults to make use of a heavy state initialization, which uses
	; an HMAC-DRBG to generate the initial state.
	;
	; Note that we use the combined output of SFMT and Mother-of-all, per Agner's
	; recommendation.
	;
	; Agner states that it is possible to reconstruct a full sequence from a
	; state-sized subsequence, which in our case is 1408 bytes long, and that safety
	; is improved by combining the output of two or more generators only if combined
	; output ONLY is accessible to the attacker. For our purposes, this means that
	; for use in our applications, we must not ever expose contiguous output from our
	; RNG to any would-be attacker. Care must be taken as a direct result of this, and
	; if you are really paranoid, use hmac_drbg instead, it is just very very slow
	; compared to the methods we have chosen here.
	;
	; In summary, using this RNG for our intended crypto use cases is safe, PROVIDED
	; that care is appropriately taken (read: throw away bits, re-init periodically, etc)
	; functions that are used from TLS/SSH (rng$block, rng$block_nzb) automatically
	; throw away bits so that we never expose a complete subsequence.
	;
	; Also, as with most things in this library, calls to here are not thread-safe.
	;
	;
	;
	; someday when I am bored I will come back and recode this properly so it isn't quite
	; so messy, haha
	;
        ; Portions of this file are heavily modified routines that Agner Fog released
        ; also under the GPL in his excellent random number resources.
        ; Because the heavily modified functions herein are from various source files
        ; of his, and that each of his source files contains its own unique copyright
        ; notice, included below is the randoma.h header that covers them all.
        ;
        ; Cheers Agner for some of this as usual; All Hail Agner!
        ;
        ; Agner's randoma copyright appears below:
	;/*****************************   randoma.h   **********************************
	;* Author:        Agner Fog
	;* Date created:  1997
	;* Last modified: 2013-05-04
	;* Project:       randoma
	;* Source URL:    www.agner.org/random
	;*
	;* Description:
	;* This header file contains function prototypes and class declarations for
	;* the randoma library of uniform random number generators optimized in 
	;* assembly language.
	;*
	;* The following random number generators are available:
	;* Mersenne Twister, Mother-Of-All generator and SFMT generator.
	;*
	;* This library is available in many versions for different platforms,
	;* see ran-instructions.pdf for details.
	;*
	;* Copyright 1997-2010 by Agner Fog. 
	;* GNU General Public License http://www.gnu.org/licenses/gpl.html
	;*******************************************************************************
	;

if used rng$init | defined include_everything

globals
{
	; note: these are "weird" on purpose, the previous rendition ordered symbols alphabetically
	; in the data seg
	_rng_dummy_pad		dq 0
	_rng0_m3                dd ?,?
	_rng1_m2                dd ?,?
	_rng2_m1                dd ?,?
	_rng3_m0                dd ?
	_rng4_mc                dd ?
	_rng5_one               dq ?
	_rng6_tempran           dq ?
	align 16
	_rng7_mf3               dd ?,?
	_rng8_mf2               dd ?,?
	_rng9_mf1               dd ?,?
	_rnga_mf0               dd ?,?
	_rngb_lastinterval      dd ?
	_rngc_rlimit            dd ?
	_rngd_unused            dd ?
	_rnge_ix                dd ?
	_rngf_amask             dd ?,?,?,?
	_rngg_state             dd ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
	align 16
	_rngh_initmother	dd 2111111111, 0, 1492, 0, 1776, 0, 5115, 0
	_rngi_initmask		dd 0effff7fbH,0ffffffefH,0dfdfbfffH,07fffdbfdH
	_rngj_initparity	dd 1,0,0e8148000H,0d0c7afa3H
}


if rng_heavy_init

	; Agner's original seed expansion is all well and good, but since we have the much slower
	; and crypto-safe hmac_drbg, we use that to initialize our 1408 main state and 32 byte
	; mother-of-all with entropy

	; (this is versus the non rng_heavy_init version that just uses a single 32 bit seed and expands that per Agner's
	; original methods).

falign
rng$init:
	prolog_silent	rng$init

	; our HMAC_DRBG setup needs non-predictable input of 64 bytes
	; to accomplish that, we do 16 bytes of rdtsc + gettimeofday at either end of the 64 bytes
	; and 32 bytes read from /dev/urandom in the middle to get our initial Key, V
	; NOTE: if the rng_paranoid setting is enabled, we'll pull our 32 bytes from /dev/random, which may stall.

	sub	rsp, 256
	readtsc
	mov	[rsp], rax
	lea	rdi, [rsp+128]
	xor	esi, esi
	; instead of using the VDSO gettimeofday, we are intentionally using the syscall version because
	; it takes a non-deterministic amount of time, thus adding more entropy than otherwise
	mov	eax, syscall_gettimeofday
	syscall
	; since we know microseconds will only ever be 17 bits worth, scoot the seconds over and combine
	mov	rax, [rsp+128]
	shl	rax, 17
	or	rax, [rsp+136]
	mov	[rsp+8], rax

	; so we have a rdtsc + gettimeofday for the first 16 bytes, next add /dev/urandom for 32
	mov	eax, syscall_open
	mov	rdi, .devurandom
	xor	esi, esi
	syscall
	cmp	eax, 0
	jl	.bad_devurandom
	mov	[rsp+128], eax
	mov	edi, eax
	lea	rsi, [rsp+16]
	mov	edx, 32
	mov	eax, syscall_read
	syscall
	mov	[rsp+136], eax
	mov	edi, [rsp+128]
	mov	eax, syscall_close
	syscall
	cmp	dword [rsp+136], 0
	jle	.bad_devurandom
	; that will take a non-deterministic amount of time to perform, so we can add another rdtsc+gettimeofday
	; for the last 16 bytes of our entropy seed to hmac_drbg
calign
.initialseed_ready:
	lea	rdi, [rsp+128]
	xor	esi, esi
	; instead of using the VDSO gettimeofday, we are intentionally using the syscall version because
	; it takes a non-deterministic amount of time, thus adding more entropy than otherwise
	mov	eax, syscall_gettimeofday
	syscall
	; since we know microseconds will only ever be 17 bits worth, scoot the seconds over and combine
	mov	rax, [rsp+128]
	shl	rax, 17
	or	rax, [rsp+136]
	mov	[rsp+48], rax
	; one last readtsc for our final 8 bytes
	readtsc
	mov	[rsp+56], rax

	; so now we have our seed material, fire up an HMAC_DRBG
	mov	rdi, hmac$init_sha512
	mov	rsi, rsp
	mov	edx, 64
	call	hmac_drbg$new
	mov	[rsp], rax

	; so now we can fill up our state
	mov	rdi, rax
	mov	rsi, _rngg_state
	mov	edx, 1408
	call	hmac_drbg$generate

	; m0..m3 next
	mov	rdi, [rsp]
	mov	rsi, _rng0_m3
	mov	edx, 32
	call	hmac_drbg$generate

	; we are finished seeding/expanding
	mov	rdi, [rsp]
	call	hmac_drbg$destroy

	; done with our stackframe
	add	rsp, 256

	movaps	xmm0, dqword [_rngh_initmother]
	movaps	dqword [_rng7_mf3], xmm0
	movaps	xmm0, dqword [_rngh_initmother+16]
	movaps	dqword [_rng9_mf1], xmm0

	movaps	xmm0, dqword [_rngi_initmask]
	movaps	dqword [_rngf_amask], xmm0
	
	xor	eax, eax
	mov	dword [_rng5_one], eax
	mov	dword [_rng5_one+4], 3FF00000H
	mov	dword [_rngb_lastinterval], eax

	movaps	xmm1, dqword [_rngg_state]
	andps	xmm1, dqword [_rngj_initparity]
	movhlps	xmm2, xmm1
	xorps	xmm1, xmm2
	pshufd	xmm2, xmm1, 1
	xorps	xmm1, xmm2
	movd	eax, xmm1
	mov	esi, eax
	shr	eax, 16
	xor	eax, esi
	; hmm TODO: redo so we can access upper 8 bit regs, previous rendition didn't have this luxury
	mov	esi, eax
	shr	esi, 8
	xor	al, sil
	jpo	.l8
	xor	edi, edi
	lea	rsi, [_rngj_initparity]
calign
.l5:
	mov	eax, [rsi+rdi*4]
	test	eax, eax
	jnz	.l6
	inc	edi
	jmp	.l5
calign
.l6:
	bsf	esi, eax
	btc	[_rngg_state+rdi*4], esi
.l8:
	; mothernext inline
	movdqa	xmm1, dqword [_rng0_m3]
	movdqa	xmm2, dqword [_rng2_m1]
	movhps	qword [_rng0_m3], xmm1
	movq	qword [_rng1_m2], xmm2
	movhps	qword [_rng2_m1], xmm2
	pmuludq	xmm1, dqword [_rng7_mf3]
	pmuludq	xmm2, dqword [_rng9_mf1]
	paddq	xmm1, xmm2
	movhlps	xmm2, xmm1
	movq	xmm3, qword [_rng4_mc]
	paddq	xmm1, xmm3
	paddq	xmm1, xmm2
	movq	qword [_rng3_m0], xmm1
	; end mothernext inline


	; copy of _rng_sfmt_generate
	movdqa	xmm1, dqword [_rngg_state+1376]
	movdqa	xmm2, dqword [_rngg_state+1392]
	mov	rsi, _rngg_state
	mov	rax, 320 + _rngg_state
	mov	rdi, 1408 + _rngg_state
calign
.ll1:
	movdqa	xmm0, dqword [rsi+1088]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	dqword [rsi], xmm2
	add	rsi, 16
	cmp	rsi, rax
	jb	.ll1
calign
.ll2:
	movdqa	xmm0, dqword [rsi-320]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	[rsi], xmm2
	add	rsi, 16
	cmp	rsi, rdi
	jb	.ll2
	
	cmp	[_rngf_amask], 0effff7fbH
	jne	.llerror
	mov	[_rnge_ix], 0
	epilog
calign
.llerror:
	xor	eax, eax
	div	eax		; die a thousand deaths quite intentionally
	epilog
dalign
.devurandom:
if rng_paranoid
	db	'/dev/random',0
else
	db	'/dev/urandom',0
end if
calign
.bad_devurandom:
	; we were unable to open /dev/urandom, so fill our middle 32 bytes with more rdtsc+gtod
	readtsc
	mov	[rsp+16], rax
	lea	rdi, [rsp+128]
	xor	esi, esi
	; instead of using the VDSO gettimeofday, we are intentionally using the syscall version because
	; it takes a non-deterministic amount of time, thus adding more entropy than otherwise
	mov	eax, syscall_gettimeofday
	syscall
	; since we know microseconds will only ever be 17 bits worth, scoot the seconds over and combine
	mov	rax, [rsp+128]
	shl	rax, 17
	or	rax, [rsp+136]
	mov	[rsp+24], rax

	readtsc
	mov	[rsp+32], rax
	lea	rdi, [rsp+128]
	xor	esi, esi
	; instead of using the VDSO gettimeofday, we are intentionally using the syscall version because
	; it takes a non-deterministic amount of time, thus adding more entropy than otherwise
	mov	eax, syscall_gettimeofday
	syscall
	; since we know microseconds will only ever be 17 bits worth, scoot the seconds over and combine
	mov	rax, [rsp+128]
	shl	rax, 17
	or	rax, [rsp+136]
	mov	[rsp+40], rax
	jmp	.initialseed_ready



else

	; note: we make a call to readtsc for the seed
	; i dont do fixed seed values anyway and this seems
	; as good or better than gettimeofday calls
	; RDRAND/RDSEED don't seem to be supported on much of my gear
	; and the low order word from readtsc when cascade-multiplied out here
	; seems to be quite sufficient
falign
rng$init:
	prolog_silent	rng$init
	readtsc
	; xmm0..3
	xor	edi, edi
	jmp	.l2
calign
.l1:
	; initsubf0:
	mov	esi, eax
	shr	eax, 30
	xor	eax, esi
	imul	eax, 1812433253
	inc	edi
	add	eax, edi
	; end initsubf0
.l2:
	mov	[_rngg_state+rdi*4], eax
	cmp	edi, 351
	jb	.l1
	; initsubf0:
	mov	esi, eax
	shr	eax, 30
	xor	eax, esi
	imul	eax, 1812433253
	inc	edi
	add	eax, edi
	; end initsubf0
	mov	[_rng3_m0], eax
	; initsubf0:
	mov	esi, eax
	shr	eax, 30
	xor	eax, esi
	imul	eax, 1812433253
	inc	edi
	add	eax, edi
	; end initsubf0
	mov	[_rng2_m1], eax
	; initsubf0:
	mov	esi, eax
	shr	eax, 30
	xor	eax, esi
	imul	eax, 1812433253
	inc	edi
	add	eax, edi
	; end initsubf0
	mov	[_rng1_m2], eax
	; initsubf0:
	mov	esi, eax
	shr	eax, 30
	xor	eax, esi
	imul	eax, 1812433253
	inc	edi
	add	eax, edi
	; end initsubf0
	mov	[_rng0_m3], eax
	; initsubf0:
	mov	esi, eax
	shr	eax, 30
	xor	eax, esi
	imul	eax, 1812433253
	inc	edi
	add	eax, edi
	; end initsubf0
	mov	[_rng4_mc], eax
	
	movaps	xmm0, dqword [_rngh_initmother]
	movaps	dqword [_rng7_mf3], xmm0
	movaps	xmm0, dqword [_rngh_initmother+16]
	movaps	dqword [_rng9_mf1], xmm0

	movaps	xmm0, dqword [_rngi_initmask]
	movaps	dqword [_rngf_amask], xmm0
	
	xor	eax, eax
	mov	dword [_rng5_one], eax
	mov	dword [_rng5_one+4], 3FF00000H
	mov	dword [_rngb_lastinterval], eax

	movaps	xmm1, dqword [_rngg_state]
	andps	xmm1, dqword [_rngj_initparity]
	movhlps	xmm2, xmm1
	xorps	xmm1, xmm2
	pshufd	xmm2, xmm1, 1
	xorps	xmm1, xmm2
	movd	eax, xmm1
	mov	esi, eax
	shr	eax, 16
	xor	eax, esi
	; hmm TODO: redo so we can access upper 8 bit regs, previous rendition didn't have this luxury
	mov	esi, eax
	shr	esi, 8
	xor	al, sil
	jpo	.l8
	xor	edi, edi
	lea	rsi, [_rngj_initparity]
calign
.l5:
	mov	eax, [rsi+rdi*4]
	test	eax, eax
	jnz	.l6
	inc	edi
	jmp	.l5
calign
.l6:
	bsf	esi, eax
	btc	[_rngg_state+rdi*4], esi
.l8:
	; mothernext inline
	movdqa	xmm1, dqword [_rng0_m3]
	movdqa	xmm2, dqword [_rng2_m1]
	movhps	qword [_rng0_m3], xmm1
	movq	qword [_rng1_m2], xmm2
	movhps	qword [_rng2_m1], xmm2
	pmuludq	xmm1, dqword [_rng7_mf3]
	pmuludq	xmm2, dqword [_rng9_mf1]
	paddq	xmm1, xmm2
	movhlps	xmm2, xmm1
	movq	xmm3, qword [_rng4_mc]
	paddq	xmm1, xmm3
	paddq	xmm1, xmm2
	movq	qword [_rng3_m0], xmm1
	; end mothernext inline


	; copy of _rng_sfmt_generate
	movdqa	xmm1, dqword [_rngg_state+1376]
	movdqa	xmm2, dqword [_rngg_state+1392]
	mov	rsi, _rngg_state
	mov	rax, 320 + _rngg_state
	mov	rdi, 1408 + _rngg_state
calign
.ll1:
	movdqa	xmm0, dqword [rsi+1088]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	dqword [rsi], xmm2
	add	rsi, 16
	cmp	rsi, rax
	jb	.ll1
calign
.ll2:
	movdqa	xmm0, dqword [rsi-320]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	[rsi], xmm2
	add	rsi, 16
	cmp	rsi, rdi
	jb	.ll2
	
	cmp	[_rngf_amask], 0effff7fbH
	jne	.llerror
	mov	[_rnge_ix], 0
	epilog
calign
.llerror:
	xor	eax, eax
	div	eax		; die a thousand deaths quite intentionally
	epilog

end if
	
	; eax (32 bits of seed) == a
	; rdi == b
	; rsi == d

end if



if used rng$int | defined include_everything
	; arguments: edi == min, esi == max (inclusive)
falign
rng$int:
	prolog	rng$int
	push	rbx
	mov	rbx, rsi
	sub	rbx, rdi
	jle	.m30
	add	rbx, 1
	cmp	ebx, [_rngb_lastinterval]
	je	.m10
	xor	eax, eax
	lea	edx, [eax+1]
	div	ebx
	mul	ebx
	sub	eax, 1
	mov	[_rngc_rlimit], eax
	mov	[_rngb_lastinterval], ebx
calign
.m10:
	mov	rbx, rdi
	call	rng$u32
	mul	[_rngb_lastinterval]
	cmp	eax, [_rngc_rlimit]
	ja	.m20
	lea	eax, [rbx+rdx]
	pop	rbx
	epilog
calign
.m20:
	call	rng$u32
	mul	[_rngb_lastinterval]
	cmp	eax, [_rngc_rlimit]
	ja	.m20
	lea	eax, [rbx+rdx]
	pop	rbx
	epilog
calign
.m30:
	mov	rax, rsi
	pop	rbx
	epilog

end if


if used rng$intmax | defined include_everything
	; argument: rdi == max (inclusive)
falign
rng$intmax:
	prolog	rng$intmax
	mov	rsi, rdi
	xor	edi, edi
	call	rng$int
	epilog
end if


if used rng$u32 | defined include_everything
	; returns random 32 bits in eax
falign
rng$u32:
	prolog	rng$u32
	mov	eax, [_rnge_ix]
	cmp	eax, 1404
	jnb	.morebits
	add	eax, 4
	mov	[_rnge_ix], eax
	mov	eax, [rax+_rngg_state-4]
	add	eax, [_rng3_m0]
	; mothernext inline
	movdqa	xmm1, dqword [_rng0_m3]
	movdqa	xmm2, dqword [_rng2_m1]
	movhps	qword [_rng0_m3], xmm1
	movq	qword [_rng1_m2], xmm2
	movhps	qword [_rng2_m1], xmm2
	pmuludq	xmm1, dqword [_rng7_mf3]
	pmuludq	xmm2, dqword [_rng9_mf1]
	paddq	xmm1, xmm2
	movhlps	xmm2, xmm1
	movq	xmm3, qword [_rng4_mc]
	paddq	xmm1, xmm3
	paddq	xmm1, xmm2
	movq	qword [_rng3_m0], xmm1
	; end mothernext inline
	epilog
calign
.morebits:
	; modified copy of _rng_sfmt_generate
	movdqa	xmm1, dqword [_rngg_state+1376]
	movdqa	xmm2, dqword [_rngg_state+1392]
	mov	rsi, _rngg_state
	mov	rax, 320 + _rngg_state
	mov	rdi, 1408 + _rngg_state
calign
.ll1:
	movdqa	xmm0, dqword [rsi+1088]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	dqword [rsi], xmm2
	add	rsi, 16
	cmp	rsi, rax
	jb	.ll1
calign
.ll2:
	movdqa	xmm0, dqword [rsi-320]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	[rsi], xmm2
	add	rsi, 16
	cmp	rsi, rdi
	jb	.ll2
	
	cmp	[_rngf_amask], 0effff7fbH
	jne	.llerror
	; modified bit:
	mov	[_rnge_ix], 4

	; and recopy of initial entry
	mov	eax, [_rngg_state]
	add	eax, [_rng3_m0]

	epilog
calign
.llerror:
	xor	eax, eax
	div	eax		; die a thousand deaths quite intentionally
	epilog
end if

if used rng$u64 | defined include_everything
	; returns random 64 bits in eax
falign
rng$u64:
	prolog	rng$u64
	mov	eax, [_rnge_ix]
	cmp	eax, 1396
	jnb	.morebits
	add	eax, 8
	mov	[_rnge_ix], eax
	mov	rax, qword [rax+_rngg_state-8]
	add	rax, qword [_rng3_m0]
	; mothernext inline
	movdqa	xmm1, dqword [_rng0_m3]
	movdqa	xmm2, dqword [_rng2_m1]
	movhps	qword [_rng0_m3], xmm1
	movq	qword [_rng1_m2], xmm2
	movhps	qword [_rng2_m1], xmm2
	pmuludq	xmm1, dqword [_rng7_mf3]
	pmuludq	xmm2, dqword [_rng9_mf1]
	paddq	xmm1, xmm2
	movhlps	xmm2, xmm1
	movq	xmm3, qword [_rng4_mc]
	paddq	xmm1, xmm3
	paddq	xmm1, xmm2
	movq	qword [_rng3_m0], xmm1
	; end mothernext inline
	epilog
calign
.morebits:
	; modified copy of _rng_sfmt_generate
	movdqa	xmm1, dqword [_rngg_state+1376]
	movdqa	xmm2, dqword [_rngg_state+1392]
	mov	rsi, _rngg_state
	mov	rax, 320 + _rngg_state
	mov	rdi, 1408 + _rngg_state
calign
.ll1:
	movdqa	xmm0, dqword [rsi+1088]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	dqword [rsi], xmm2
	add	rsi, 16
	cmp	rsi, rax
	jb	.ll1
calign
.ll2:
	movdqa	xmm0, dqword [rsi-320]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	[rsi], xmm2
	add	rsi, 16
	cmp	rsi, rdi
	jb	.ll2
	
	cmp	[_rngf_amask], 0effff7fbH
	jne	.llerror
	; modified bit:
	mov	[_rnge_ix], 8

	; and recopy of initial entry
	mov	rax, qword [_rngg_state]
	add	rax, qword [_rng3_m0]

	epilog
calign
.llerror:
	xor	eax, eax
	div	eax		; die a thousand deaths quite intentionally
	epilog
end if

if used rng$double | defined include_everything
	; returns random double in xmm0
falign
rng$double:
	prolog	rng$double
	mov	edi, [_rnge_ix]
	cmp	edi, 1396
	jnb	.morebits
	movq	xmm0, qword [rdi+_rngg_state]
	add	edi, 8
	mov	[_rnge_ix], edi
	movq	xmm1, qword [_rng3_m0]
	pshuflw	xmm1, xmm1, 01001011B
	paddq	xmm0, xmm1
	; mothernext inline
	movdqa	xmm1, dqword [_rng0_m3]
	movdqa	xmm2, dqword [_rng2_m1]
	movhps	qword [_rng0_m3], xmm1
	movq	qword [_rng1_m2], xmm2
	movhps	qword [_rng2_m1], xmm2
	pmuludq	xmm1, dqword [_rng7_mf3]
	pmuludq	xmm2, dqword [_rng9_mf1]
	paddq	xmm1, xmm2
	movhlps	xmm2, xmm1
	movq	xmm3, qword [_rng4_mc]
	paddq	xmm1, xmm3
	paddq	xmm1, xmm2
	movq	qword [_rng3_m0], xmm1
	; end mothernext inline
	psrlq	xmm0, 12
	movsd	xmm1, [_rng5_one]
	por	xmm0, xmm1
	subsd	xmm0, xmm1
	epilog
calign
.morebits:
	; modified copy of _rng_sfmt_generate
	movdqa	xmm1, dqword [_rngg_state+1376]
	movdqa	xmm2, dqword [_rngg_state+1392]
	mov	rsi, _rngg_state
	mov	rax, 320 + _rngg_state
	mov	rdi, 1408 + _rngg_state
calign
.ll1:
	movdqa	xmm0, dqword [rsi+1088]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	dqword [rsi], xmm2
	add	rsi, 16
	cmp	rsi, rax
	jb	.ll1
calign
.ll2:
	movdqa	xmm0, dqword [rsi-320]
	psrld	xmm0, 7
	pand	xmm0, dqword [_rngf_amask]
	movdqa	xmm3, dqword [rsi]
	pxor	xmm0, xmm3
	pslldq	xmm3, 3
	psrldq	xmm1, 3
	pxor	xmm0, xmm3
	pxor	xmm0, xmm1
	movdqa	xmm1, xmm2
	pslld	xmm2, 14
	pxor	xmm2, xmm0
	movdqa	[rsi], xmm2
	add	rsi, 16
	cmp	rsi, rdi
	jb	.ll2
	
	cmp	[_rngf_amask], 0effff7fbH
	jne	.llerror

	; modification of the original _rng_sfmt_generate
	mov	dword [_rnge_ix], 8

	; copy of the initial rng$double entry with no morebits check
	movq	xmm0, qword [_rngg_state]
	movq	xmm1, qword [_rng3_m0]
	pshuflw	xmm1, xmm1, 01001011B
	paddq	xmm0, xmm1
	; mothernext inline
	movdqa	xmm1, dqword [_rng0_m3]
	movdqa	xmm2, dqword [_rng2_m1]
	movhps	qword [_rng0_m3], xmm1
	movq	qword [_rng1_m2], xmm2
	movhps	qword [_rng2_m1], xmm2
	pmuludq	xmm1, dqword [_rng7_mf3]
	pmuludq	xmm2, dqword [_rng9_mf1]
	paddq	xmm1, xmm2
	movhlps	xmm2, xmm1
	movq	xmm3, qword [_rng4_mc]
	paddq	xmm1, xmm3
	paddq	xmm1, xmm2
	movq	qword [_rng3_m0], xmm1
	; end mothernext inline
	psrlq	xmm0, 12
	movsd	xmm1, [_rng5_one]
	por	xmm0, xmm1
	subsd	xmm0, xmm1
	epilog
calign
.llerror:
	xor	eax, eax
	div	eax		; die a thousand deaths quite intentionally
	epilog

end if



if used rng$block | defined include_everything

	; two arguments: rdi == byte buffer, rsi == length of same
	; we fill it with repeated calls to rng$u64
	; TODO: make me go faster
falign
rng$block:
	prolog	rng$block
	test	rsi, rsi
	jz	.nothingtodo
	push	rbx rbp r12
	mov	rbx, rdi
	mov	rbp, rsi
	mov	r12d, 48
calign
.do8:
	call	rng$u64
	mov	ecx, 49
	sub	r12d, 1
	cmovz	r12d, ecx
	jz	.do8
	cmp	rbp, 8
	jb	.do4
	mov	[rbx], rax
	add	rbx, 8
	sub	rbp, 8
	jz	.alldone
	jmp	.do8
calign
.do4:
	cmp	rbp, 4
	jb	.do2
	mov	[rbx], eax
	shr	rax, 32
	add	rbx, 4
	sub	rbp, 4
	jz	.alldone
calign
.do2:
	cmp	rbp, 2
	jb	.do1
	mov	[rbx], ax
	shr	rax, 16
	add	rbx, 2
	sub	rbp, 2
	jz	.alldone
calign
.do1:
	mov	[rbx], al
	pop	r12 rbp rbx
	; throw away 64 bits
	call	rng$u64
	epilog
calign
.alldone:
	pop	r12 rbp rbx
	; throw away 64 bits
	call	rng$u64
	epilog
calign
.nothingtodo:
	epilog

end if

if used rng$block_nzb | defined include_everything
	; same as rng$block, only makes sure they are non zero bytes throughout
falign
rng$block_nzb:
	prolog	rng$block_nzb
	test	rsi, rsi
	jz	.nothingtodo
	push	rbx rbp
	mov	rbx, rdi
	mov	rbp, rsi
calign
.do4:
	call	rng$u32
	test	eax, 0xff
	jz	.do4
	test	eax, 0xff00
	jz	.do4
	test	eax, 0xff0000
	jz	.do4
	test	eax, 0xff000000
	jz	.do4
	cmp	rbp, 4
	jb	.do2
	mov	[rbx], eax
	shr	rax, 32
	add	rbx, 4
	sub	rbp, 4
	jmp	.do4
calign
.do2:
	cmp	rbp, 2
	jb	.do1
	mov	[rbx], ax
	shr	rax, 16
	add	rbx, 2
	sub	rbp, 2
	jz	.alldone
calign
.do1:
	mov	[rbx], al
	pop	rbp rbx
	; throw away 64 bits
	call	rng$u64
	epilog
calign
.alldone:
	pop	rbp rbx
	; throw away 64 bits
	call	rng$u64
	epilog
calign
.nothingtodo:
	epilog

end if
