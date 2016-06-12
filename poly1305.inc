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
	; poly1305.inc: Implementation of the SSE2 public domain variant at
	; https://github.com/floodyberry/poly1305-opt ... same as his but modified
	; to better suit our library requirements
	;


if used poly1305$new | used poly1305$init | defined include_everything


poly1305_h_ofs = 0
poly1305_r_ofs = 40
poly1305_r2_ofs = 60
poly1305_r4_ofs = 80
poly1305_pad_ofs = 100
poly1305_flags_ofs = 120
poly1305_leftover_ofs = 124
poly1305_buffer_ofs = 128

poly1305_state_size =  poly1305_buffer_ofs + 32

poly1305_started = 1
poly1305_final_shift8 = 4
poly1305_final_shift16 = 8
poly1305_final_r2_r = 16
poly1305_final_r_1 = 32

end if


if used poly1305$new | defined include_everything
	; single argument in rdi: 32 byte key or null for no init
falign
poly1305$new:
	prolog	poly1305$new
	push	rdi
	mov	edi, poly1305_state_size
	call	heap$alloc
	pop	rsi
	test	rsi, rsi
	jnz	.withinit
	epilog
.withinit:
	push	rax
	mov	rdi, rax
	call	poly1305$init
	pop	rax
	epilog

end if


if used poly1305$init | defined include_everything
	; two arguments: rdi == state, rsi == 32 byte key
falign
poly1305$init:
	prolog	poly1305$init
	pxor	xmm0, xmm0
	push	rbp rbx r12
	mov	r11, -1
	mov	r9, 0xffc0fffffff
	mov	rbp, 0xfffffffffff
	push	r13 r14 r15
	mov	r13, r11
	xor	ebx, ebx
	mov	rax, [rsi]
	mov	rcx, [rsi+8]
	mov	r14, 0xfffffc0ffff
	mov	r15, 0xffffffc0f
	movups	[rdi], xmm0
	movups	[rdi+0x10], xmm0
	movups	[rdi+0x20], xmm0
	mov	rdx, rcx
	shr	rcx, 0x18
	and	r9, rax
	shl	rdx, 0x14
	shr	rax, 0x2c
	mov	r8, r9
	or	rdx, rax
	mov	eax, r9d
	shr	r8, 0x1a
	and	rdx, r14
	and	rcx, r15
	and	eax, 0x3ffffff
	mov	[rdi+0x28], eax
	mov	eax, edx
	shl	eax, 0x12
	or	eax, r8d
	mov	r8, rdx
	and	eax, 0x3ffffff
	shr	r8, 0x22
	mov	[rdi+0x2c], eax
	mov	rax, rdx
	shr	rax, 8
	and	eax, 0x3ffffff
	mov	[rdi+0x30], eax
	mov	eax, ecx
	shl	eax, 10
	or	eax, r8d
	mov	r8, rdi
	and	eax, 0x3ffffff
	mov	[rdi+0x34], eax
	mov	rax, rcx
	mov	r14, [rsi+0x10]
	mov	r15, [rsi+0x18]
	shr	rax, 16
	mov	[rdi+0x38], eax
	mov	[rdi+0x68], r14		; pad0
	mov	[rdi+0x70], r15		; pad1
	mov	rsi, rdx
.outermost:
	test	rbx, rbx	
	jnz	.outermost_nonzero
	cmp	r13, 16
	jbe	.bailout
	xor	eax, eax
	lea	rdi, [r8+0x3c]
	jmp	.innerbulk
calign
.outermost_nonzero:
	cmp	r13, 96
	jb	.bailout
	xor	eax, eax
	lea	rdi, [r8+0x50]
.innerbulk:
	imul	r10, rcx, 0x14
	mov	[rsp-0x30], rax
	mov	[rsp-0x20], rax
	lea	r14, [rsi+rsi]
	lea	r11, [r9+r9]
	mov	rax, r10
	mul	r14
	mov	r14, rax
	mov	rax, r9
	mov	r15, rdx
	mul	r9
	add	r14, rax
	mov	rax, r14
	adc	r15, rdx
	lea	rdx, [rcx+rcx]
	and	rax, rbp
	mov	[rsp-0x10], rax
	mov	rax, r11
	mov	[rsp-0x18], rdx
	mul	rsi
	mov	r11, rax
	mov	rax, r10
	mov	r12, rdx
	mul	rcx
	mov	rcx, [rsp-0x10]
	add	r11, rax
	mov	rax, r14
	adc	r12, rdx
	shrd	rax, r15, 0x2c
	mov	[rsp-0x38], rax
	mov	rax, [rsp-0x18]
	add	r11, [rsp-0x38]
	adc	r12, [rsp-0x30]

	mul	r9
	mov	r14, r11
	and	r14, rbp
	mov	r9, rax
	mov	rax, rsi
	mov	r10, rdx
	mul	rsi
	add	r9, rax
	mov	rax, r11
	adc	r10, rdx
	shrd	rax, r12, 0x2c
	mov	[rsp-0x28], rax
	mov	rax, 0x3ffffffffff
	add	r9, [rsp-0x28]
	adc	r10, [rsp-0x20]

	and	rax, r9
	add	rbx, 1
	shrd	r9, r10, 0x2a
	lea	r9, [r9+r9*4]
	add	rcx, r9
	mov	r9, rcx
	shr	rcx, 0x2c
	add	rcx, r14
	and	r9, rbp
	mov	rsi, rcx
	shr	rcx, 0x2c
	mov	rdx, r9
	add	rcx, rax
	mov	eax, r9d
	and	rsi, rbp
	and	eax, 0x3ffffff
	shr	rdx, 0x1a
	mov	[rdi], eax

	mov	eax, esi
	shl	eax, 0x12
	or	eax, edx
	mov	rdx, rsi
	and	eax, 0x3ffffff
	shr	rdx, 0x22
	mov	[rdi+4], eax
	mov	rax, rsi
	shr	rax, 8
	and	eax, 0x3ffffff
	mov	[rdi+8], eax
	mov	eax, ecx
	shl	eax, 0xa
	or	eax, edx
	and	eax, 0x3ffffff
	mov	[rdi+12], eax

	mov	rax, rcx
	shr	rax, 16
	cmp	rbx, 2
	mov	[rdi+16], eax
	jne	.outermost

.bailout:
	mov	qword [r8+poly1305_flags_ofs], 0	; blasts leftover too
	pop	r15 r14 r13 r12 rbx rbp
	epilog

end if


if used poly1305$update | defined include_everything
	; three arguments: rdi == state, rsi == message, rdx == length of same
falign
poly1305$update:
	prolog	poly1305$update
	mov	eax, 32
	mov	r8d, [rdi+poly1305_leftover_ofs]
	push	rbx r12 r13
	mov	rbx, rdi
	sub	eax, r8d
	mov	r12, rsi
	mov	r13, rdx
	push	r14 r15
	test	r8d, r8d
	jz	.noleftovers
	cmp	rax, rdx
	cmova	eax, edx
	mov	r14d, eax
	mov	r15d, r8d
	lea	rdi, [rdi+r8+poly1305_buffer_ofs]
	mov	edx, eax
	call	memcpy
	sub	r13, r14
	add	r12, r14
	add	[rbx+poly1305_leftover_ofs], r14d
	cmp	dword [rbx+poly1305_leftover_ofs], 32
	jb	.bailout
	mov	rdi, rbx
	lea	rsi, [rbx+poly1305_buffer_ofs]
	mov	edx, 32
	call	poly1305$blocks
	mov	dword [rbx+poly1305_leftover_ofs], 0
.noleftovers:
	mov	rcx, r13
	test	r13, r13
	jz	.bailout
	cmp	r13, 32
	jb	.nofullblocks
	and	rcx, not 31
	; consume(state, in, want)
	test	r12, 7
	jnz	.maligned
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, rcx
	sub	r13, rcx
	add	r12, rcx
	call	poly1305$blocks
	test	r13, r13
	jnz	.addleftover
	pop	r15 r14 r13 r12 rbx
	epilog
.addleftover:
	lea	rdi, [rbx+poly1305_buffer_ofs]
	mov	rsi, r12
	mov	rdx, r13
	call	memcpy
	add	[rbx+poly1305_leftover_ofs], r13d
	pop	r15 r14 r13 r12 rbx
	epilog
.maligned:
	; copy it to a word-aligned stackbuffer first
	sub	rsp, 1024
	mov	edx, 1024
	cmp	r13, rdx
	cmovb	rdx, r13
	mov	rdi, rsp
	mov	rsi, r12
	mov	r14, rdx
	call	memcpy
	mov	rdi, rbx
	mov	rsi, rsp
	mov	rdx, r14
	call	poly1305$blocks
	add	r12, r14
	sub	r13, r14
	add	rsp, 1024
	jnz	.maligned
	; hmmm, I am not sure his implementation deals with this correctly, no ~not 31 here
	; and no leftover additions like the aligned cousin above...
	; ... breakpointing this for now...
	breakpoint
	pop	r15 r14 r13 r12 rbx
	epilog

.nofullblocks:
	mov	r8d, [rbx+poly1305_leftover_ofs]
	mov	rsi, r12
	mov	edx, r13d
	lea	rdi, [rbx+r8+poly1305_buffer_ofs]
	add	[rbx+poly1305_leftover_ofs], r13d
	call	memcpy
.bailout:
	pop	r15 r14 r13 r12 rbx
	epilog

end if

if used poly1305$final | defined include_everything
	; three arguments: rdi == state, rsi == ptr to 16 byte buffer for the mac, edx == bool as to whether we should destroy (heap$free/clear)
	; the state when we're done
falign
poly1305$final:
	prolog	poly1305$final
	push	rbp rbx r12 r13
	pxor	xmm0, xmm0
	mov	ebp, [rdi+poly1305_leftover_ofs]
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	lea	rsi, [rdi+poly1305_buffer_ofs]
	sub	rsp, 32
	test	ebp, ebp
	jz	.noleftover
	xor	eax, eax
	movups	[rsp], xmm0
	movups	[rsp+0x10], xmm0
	sub	rsi, rsp
	test	ebp, 0x10
	mov	rax, rsp
	jz	.b8
	movups	xmm0, [rsp+rsi]
	add	rax, 0x10
	movups	[rsp], xmm0
.b8:
	test	ebp, 8
	jz	.b4
	mov	rdx, [rax+rsi]
	mov	[rax], rdx
	add	rax, 8
.b4:
	test	ebp, 4
	jz	.b2
	mov	edx, [rax+rsi]
	mov	[rax], edx
	add	rax, 4
.b2:
	test	ebp, 2
	jz	.b1
	movzx	edx, word [rax+rsi]
	mov	[rax], dx
	add	rax, 2
.b1:
	test	ebp, 1
	jz	.bleftover
	movzx	edx, byte [rax+rsi]
	mov	[rax], dl
.bleftover:
	cmp	ebp, 0x10
	je	.nolastbyte
	mov	byte [rsp+rbp], 1
.nolastbyte:
	cmp	ebp, 0x10
	mov	edx, 0x20
	mov	rsi, rsp
	sbb	rax, rax
	mov	rdi, rbx
	and	eax, 4
	add	rax, 4
	or	dword [rbx+0x78], eax	; flags
	call	poly1305$blocks
.noleftover:
	mov	eax, [rbx+0x78]		; flags
	test	eax, 1			; started?
	jz	.notstarted
	sub	ebp, 1
	mov	ecx, eax
	mov	edx, eax
	or	ecx, 0x10
	or	edx, 0x20

	cmp	ebp, 0xf
	cmovbe	eax, edx
	cmova	eax, ecx
	mov	edx, 0x20
	xor	esi, esi
	mov	[rbx+0x78], eax
	mov	rdi, rbx
	call	poly1305$blocks
.notstarted:
	pxor	xmm0, xmm0
	mov	rax, [rbx+8]
	mov	rsi, [rbx+0x70]
	mov	rdx, rax
	mov	rcx, rax
	mov	rax, [rbx+0x10]
	shr	rcx, 0x14
	shl	rdx, 0x2c
	or	rdx, [rbx]
	shl	rax, 0x18
	or	rax, rcx
	mov	rcx, [rbx+0x68]
	add	rdx, rcx
	adc	rax, rsi
	movups	[rbx], xmm0
	movups	[rbx+0x10], xmm0
	movups	[rbx+0x20], xmm0
	movups	[rbx+0x30], xmm0
	movups	[rbx+0x40], xmm0
	movups	[rbx+0x50], xmm0
	movups	[rbx+0x60], xmm0
	movups	[rbx+0x70], xmm0
	mov	[r12], rdx
	mov	[r12+0x8], rax
	add	rsp, 0x20
	test	r13d, r13d
	jnz	.withfree
	pop	r13 r12 rbx rbp
	epilog
.withfree:
	; state has already been cleared
	mov	rdi, rbx
	call	heap$free
	pop	r13 r12 rbx rbp
	epilog

end if

if used poly1305$blocks | defined include_everything

falign
poly1305$blocks:
	prolog	poly1305$blocks
	push	rbx
	mov	rax, rsp
	mov	r8, 0x1000000
	mov	r9, 0x3ffffff
	and	rax, 0xf
	sub	rsp, rax
	sub	rsp, 0x158
	movq	xmm0, r9
	movq	xmm1, r8
	mov	[rsp+0x150], rax
	pshufd	xmm0, xmm0, 0x44
	pshufd	xmm1, xmm1, 0x44
	mov	eax, [rdi+poly1305_flags_ofs]
	movaps	[rsp+0x138], xmm1
	test	eax, poly1305_final_shift8
	jz	.noshift8
	psrldq	xmm1, 8
	movaps	[rsp+0x138], xmm1
.noshift8:
	test	eax, poly1305_final_shift16
	jz	.noshift16
	pxor	xmm1, xmm1
	movaps	[rsp+0x138], xmm1
.noshift16:
	test	eax, poly1305_started
	jnz	.alreadystarted
	movq	xmm1, [rsi+0x10]
	movaps	xmm3, xmm0
	movaps	xmm9, xmm0
	movq	xmm15, [rsi]
	or	eax, poly1305_started
	sub	rdx, 32
	movq	xmm12, [rsi+0x8]
	punpcklqdq xmm15, xmm1
	movq	xmm1, [rsi+0x18]
	movaps	xmm8, xmm15
	pand	xmm3, xmm15
	psrlq	xmm15, 0x34
	add	rsi, 0x20
	punpcklqdq xmm12, xmm1
	movaps	xmm1, xmm12
	psrlq	xmm8, 0x1a
	psllq	xmm1, 0xc
	pand	xmm8, xmm0
	mov	[rdi+poly1305_flags_ofs], eax
	por	xmm15, xmm1
	psrlq	xmm12, 0x28
	pand	xmm9, xmm15
	por	xmm12, [rsp+0x138]
	psrlq	xmm15, 0x1a
	pand	xmm15, xmm0
	jmp	.onit
.alreadystarted:
	movups	xmm8, [rdi]
	movups	xmm15, [rdi+0x10]
	movups	xmm12, [rdi+0x20]
	pshufd	xmm3, xmm8, 0x50
	pshufd	xmm8, xmm8, 0xfa
	pshufd	xmm9, xmm15, 0x50
	pshufd	xmm15, xmm15, 0xfa
	pshufd	xmm12, xmm12, 0x50
.onit:
	test	eax, poly1305_final_r2_r
	jnz	.final_r2_r
	test	eax, poly1305_final_r_1
	jnz	.final_r_1
	; otherwise, r squares
	movups	xmm1, [rdi+0x3c]
	movd	xmm2, [rdi+0x4c]
	pshufd	xmm11, xmm1, 0
	pshufd	xmm2, xmm2, 0
	pshufd	xmm7, xmm1, 0x55
	pshufd	xmm4, xmm1, 0xaa
	movaps	[rsp+0xa8], xmm11
	pshufd	xmm1, xmm1, 0xff
.rset:
	mov	r8, 5
	movaps	xmm5, xmm7
	movaps	xmm13, xmm4
	movaps	xmm14, xmm1
	movaps	[rsp+0x108], xmm1
	movaps	xmm1, xmm2
	cmp	rdx, 0x3f
	movq	xmm6, r8
	movaps	[rsp+0x128], xmm4
	pshufd	xmm6, xmm6, 0x44
	movaps	[rsp+0x98], xmm2
	pmuludq xmm5, xmm6
	pmuludq	xmm13, xmm6
	pmuludq xmm14, xmm6
	pmuludq xmm1, xmm6
	movaps	[rsp+0x58], xmm5
	movaps	[rsp+0x48], xmm13
	movaps	[rsp+0x38], xmm14
	movaps	[rsp+0x28], xmm1
	jbe	.check32
	; otherwise >= 64 bytes
	movups	xmm1, [rdi+0x50]
	movd	xmm2, [rdi+0x60]
	mov	rcx, rdx
	pshufd	xmm2, xmm2, 0
	movaps	[rsp+0x18], xmm2
	pmuludq	xmm2, xmm6
	pshufd	xmm4, xmm1, 0x55
	movaps	[rsp+0x118], xmm4
	pmuludq	xmm4, xmm6
	pshufd	xmm13, xmm1, 0xff
	pshufd	xmm5, xmm1, 0xaa
	movaps	xmm14, [rsp+0x48]

	movaps	[rsp+0xd8], xmm5
	pmuludq	xmm5, xmm6
	mov	rax, rsi
	movaps	[rsp-0x18], xmm4
	movaps	xmm4, xmm13
	pshufd	xmm1, xmm1, 0
	pmuludq	xmm4, xmm6
	movaps	[rsp-0x8], xmm14
	movaps	[rsp+8], xmm5
	movaps	xmm5, [rsp+0xa8]
	movaps	[rsp+0xf8], xmm1
	movaps	xmm1, [rsp+0x38]
	movaps	[rsp+0x78], xmm4
	movaps	xmm4, [rsp+0x28]
	movaps	[rsp+0x88], xmm13
	movaps	[rsp+0xc8], xmm2
	movaps	[rsp+0x68], xmm1
	movaps	[rsp+0xb8], xmm4
	movaps	[rsp+0xe8], xmm5

calign
.while64:
	movaps	xmm5, [rsp-0x18]
	movaps	xmm13, xmm8
	sub	rcx, 0x40
	movaps	xmm4, [rsp+0x8]
	movaps	xmm10, [rsp+0x78]
	pmuludq xmm5, xmm12
	pmuludq xmm4, xmm15
	movaps	xmm2, [rsp+0x8]
	pmuludq xmm10, xmm9
	movaps	xmm11, [rsp+0x78]
	movaps	xmm14, [rsp+0xc8]
	pmuludq xmm2, xmm12
	paddq	xmm5, xmm4
	pmuludq xmm11, xmm15
	movaps	xmm1, [rsp+0x78]
	paddq	xmm5, xmm10
	pmuludq xmm14, xmm8
	movaps	xmm10, [rsp+0xc8]
	movaps	xmm4, [rsp+0xc8]
	pmuludq xmm1, xmm12
	movaps	xmm8, [rsp+0xf8]
	pmuludq xmm10, xmm15
	paddq	xmm2, xmm11
	pmuludq xmm4, xmm12
	paddq	xmm5, xmm14
	movaps	xmm11, [rsp+0xc8]
	movaps	xmm14, [rsp+0xf8]
	pmuludq xmm8, xmm15
	pmuludq xmm12, [rsp+0xf8]
	pmuludq xmm11, xmm9
	paddq	xmm1, xmm10
	movaps	xmm10, [rsp+0xf8]
	pmuludq xmm15, [rsp+0x118]
	pmuludq xmm14, xmm3
	paddq	xmm12, xmm15
	paddq	xmm4, xmm8
	pmuludq xmm10, xmm13
	movq	xmm15, [rax+0x18]
	movaps	xmm8, [rsp+0xf8]
	paddq	xmm2, xmm11
	movaps	xmm11, xmm3
	movaps	xmm3, [rsp+0x118]
	paddq	xmm5, xmm14
	pmuludq xmm8, xmm9
	paddq	xmm2, xmm10
	movq	xmm14, [rax+0x10]
	movaps	xmm10, [rsp+0x118]
	pmuludq xmm3, xmm9
	pmuludq xmm9, [rsp+0xd8]
	paddq	xmm12, xmm9
	paddq	xmm1, xmm8
	movq	xmm8, [rax]
	pmuludq xmm10, xmm11
	paddq	xmm4, xmm3
	movaps	xmm3, [rsp+0xd8]
	punpcklqdq xmm8, xmm14
	movaps	xmm14, [rsp+0x118]
	pmuludq xmm3, xmm13
	paddq	xmm2, xmm10
	movq	xmm10, [rax+0x8]
	pmuludq xmm14, xmm13
	pmuludq xmm13, [rsp+0x88]
	paddq	xmm12, xmm13
	punpcklqdq xmm10, xmm15
	movaps	xmm9, xmm10
	movaps	xmm15, [rsp+0xd8]
	paddq	xmm4, xmm3
	psllq	xmm9, 0xc
	movaps	xmm3, xmm0
	paddq	xmm1, xmm14
	pmuludq xmm15, xmm11
	pand	xmm3, xmm8
	movaps	xmm14, [rsp+0x88]
	movaps	[rsp-0x28], xmm3
	movaps	xmm3, xmm8
	movups	xmm13, [rax+0x30]
	psrlq	xmm8, 0x34
	pmuludq xmm14, xmm11
	paddq	xmm1, xmm15
	por	xmm8, xmm9
	pmuludq xmm11, [rsp+0x18]
	paddq	xmm12, xmm11
	movups	xmm11, [rax+0x20]
	movaps	xmm9, xmm10
	psrlq	xmm10, 0x28
	pand	xmm8, xmm0
	movaps	xmm15, xmm11
	paddq	xmm4, xmm14
	pxor	xmm14, xmm14
	punpckldq xmm15, xmm13
	psrlq	xmm9, 0xe
	add	rax, 0x40
	pand	xmm9, xmm0
	psrlq	xmm3, 0x1a
	cmp	rcx, 0x3f
	por	xmm10, [rsp+0x138]
	movaps	[rsp-0x48], xmm13
	movaps	xmm13, xmm15
	punpckldq xmm13, xmm14
	punpckhdq xmm11, [rsp-0x48]
	movaps	[rsp-0x38], xmm13
	movaps	xmm13, xmm11
	punpckhdq xmm11, xmm14
	pand	xmm3, xmm0
	psllq	xmm11, 0x12
	punpckhdq xmm15, xmm14
	punpckldq xmm13, xmm14
	paddq	xmm4, xmm11
	movaps	xmm11, [rsp-0x8]
	psllq	xmm15, 0x6
	psllq	xmm13, 0xc
	movaps	xmm14, [rsp+0x58]
	paddq	xmm2, xmm15
	pmuludq xmm11, xmm10
	paddq	xmm1, xmm13
	movaps	xmm13, [rsp-0x8]
	pmuludq xmm14, xmm10
	paddq	xmm5, [rsp-0x38]
	paddq	xmm12, [rsp+0x138]
	pmuludq xmm13, xmm9
	movaps	xmm15, [rsp+0x68]
	paddq	xmm2, xmm11
	movaps	xmm11, [rsp+0xb8]
	paddq	xmm5, xmm14
	movaps	xmm14, [rsp+0x68]
	pmuludq xmm15, xmm9
	pmuludq xmm11, xmm10
	paddq	xmm5, xmm13
	movaps	xmm13, [rsp+0x68]
	pmuludq xmm14, xmm10
	pmuludq xmm10, [rsp+0xe8]
	paddq	xmm12, xmm10
	pmuludq xmm13, xmm8
	paddq	xmm2, xmm15
	movaps	xmm10, xmm8
	paddq	xmm4, xmm11
	pmuludq xmm10, xmm7
	movaps	xmm11, [rsp+0xe8]
	movaps	xmm15, [rsp+0xb8]
	paddq	xmm1, xmm14
	pmuludq xmm11, xmm9
	paddq	xmm5, xmm13
	movaps	xmm13, [rsp+0xb8]
	movaps	xmm14, [rsp+0xb8]
	pmuludq xmm15, xmm3
	pmuludq xmm13, xmm9
	paddq	xmm4, xmm11
	pmuludq xmm14, xmm8
	movaps	xmm11, [rsp+0xe8]
	paddq	xmm4, xmm10
	paddq	xmm5, xmm15
	pmuludq xmm9, xmm7
	pmuludq xmm11, xmm8
	paddq	xmm1, xmm13
	movaps	xmm13, [rsp+0xe8]
	movaps	xmm10, [rsp+0x128]
	paddq	xmm2, xmm14
	pmuludq xmm8, [rsp+0x128]
	movaps	xmm14, [rsp-0x28]
	pmuludq xmm13, xmm3
	paddq	xmm12, xmm9
	paddq	xmm1, xmm11
	movaps	xmm11, xmm3
	paddq	xmm12, xmm8
	movaps	xmm15, [rsp+0xe8]
	pmuludq xmm11, xmm7
	pmuludq xmm10, xmm3
	paddq	xmm2, xmm13
	movaps	xmm13, xmm14
	movaps	xmm9, [rsp+0x128]
	pmuludq xmm15, xmm14
	pmuludq xmm3, [rsp+0x108]
	paddq	xmm1, xmm11
	pmuludq xmm13, xmm7
	paddq	xmm12, xmm3
	movaps	xmm11, [rsp+0x108]
	paddq	xmm4, xmm10
	pmuludq xmm9, xmm14
	paddq	xmm5, xmm15
	pmuludq xmm11, xmm14
	movaps	xmm8, xmm5
	paddq	xmm2, xmm13
	psrlq	xmm8, 0x1a
	paddq	xmm1, xmm9
	pand	xmm5, xmm0
	pmuludq xmm14, [rsp+0x98]
	paddq	xmm12, xmm14
	paddq	xmm2, xmm8
	paddq	xmm4, xmm11
	movaps	xmm9, xmm2
	movaps	xmm8, xmm2
	movaps	xmm3, xmm4
	psrlq	xmm9, 0x1a
	pand	xmm4, xmm0
	psrlq	xmm3, 0x1a
	paddq	xmm1, xmm9
	pand	xmm8, xmm0
	paddq	xmm12, xmm3
	movaps	xmm10, xmm1
	movaps	xmm9, xmm1
	movaps	xmm3, xmm12
	psrlq	xmm10, 0x1a
	pand	xmm12, xmm0
	psrlq	xmm3, 0x1a
	paddq	xmm4, xmm10
	pand	xmm9, xmm0
	pmuludq xmm3, xmm6
	movaps	xmm1, xmm4
	movaps	xmm15, xmm4
	psrlq	xmm1, 0x1a
	pand	xmm15, xmm0
	paddq	xmm12, xmm1
	paddq	xmm5, xmm3
	movaps	xmm2, xmm5
	movaps	xmm3, xmm5
	psrlq	xmm2, 0x1a
	pand	xmm3, xmm0
	paddq	xmm8, xmm2
	ja	.while64
	lea	rax, [rdx-0x40]
	and	edx, 0x3f
	and	rax, 0xffffffffffffffc0
	lea	rsi, [rsi+rax+0x40]
.check32:
	cmp	rdx, 0x1f
	jbe	.checkm
	movaps	xmm11, [rsp+0x38]
	movaps	xmm1, xmm15
	movaps	xmm14, xmm15
	movaps	xmm5, [rsp+0x48]
	movaps	xmm4, xmm12
	movaps	xmm10, xmm15
	movaps	xmm2, [rsp+0x58]
	pmuludq xmm14, xmm11
	movaps	xmm15, xmm8
	pmuludq xmm1, xmm5
	movaps	xmm13, [rsp+0x28]
	test	rsi, rsi
	pmuludq xmm2, xmm12
	pmuludq xmm5, xmm12
	pmuludq xmm4, xmm11
	paddq	xmm2, xmm1
	pmuludq xmm11, xmm9
	movaps	xmm1, xmm12
	paddq	xmm5, xmm14
	pmuludq xmm15, xmm13
	movaps	xmm14, xmm9
	pmuludq xmm14, xmm13
	pmuludq xmm1, xmm13
	paddq	xmm2, xmm11
	movaps	xmm11, [rsp+0xa8]
	pmuludq xmm13, xmm10
	paddq	xmm2, xmm15
	movaps	xmm15, xmm9
	paddq	xmm5, xmm14
	pmuludq xmm12, xmm11
	movaps	xmm14, xmm3
	pmuludq xmm14, xmm11
	movaps	[rsp+0xf8], xmm13
	movaps	xmm13, xmm10
	pmuludq xmm15, xmm7
	paddq	xmm4, [rsp+0xf8]
	pmuludq xmm13, xmm11
	pmuludq xmm10, xmm7
	paddq	xmm2, xmm14
	movaps	[rsp+0x118], xmm13
	movaps	xmm13, xmm8
	pmuludq xmm13, xmm11
	paddq	xmm12, xmm10
	movaps	xmm10, [rsp+0x128]
	paddq	xmm1, [rsp+0x118]
	pmuludq xmm11, xmm9
	pmuludq xmm9, [rsp+0x128]
	pmuludq xmm10, xmm3
	paddq	xmm12, xmm9
	paddq	xmm5, xmm13
	movaps	xmm13, xmm3
	paddq	xmm1, xmm15
	pmuludq xmm13, xmm7
	paddq	xmm4, xmm11
	movaps	xmm11, [rsp+0x128]
	pmuludq xmm7, xmm8
	pmuludq xmm11, xmm8
	pmuludq xmm8, [rsp+0x108]
	paddq	xmm12, xmm8
	paddq	xmm5, xmm13
	paddq	xmm4, xmm7
	movaps	xmm7, [rsp+0x108]
	paddq	xmm1, xmm11
	paddq	xmm4, xmm10
	pmuludq xmm7, xmm3
	pmuludq xmm3, [rsp+0x98]
	paddq	xmm12, xmm3
	paddq	xmm1, xmm7
	jz	.check32_nom
	movups	xmm7, [rsi]
	pxor	xmm3, xmm3
	paddq	xmm12, [rsp+0x138]
	movups	xmm8, [rsi+0x10]
	movaps	xmm9, xmm7
	punpckldq xmm9, xmm8
	punpckhdq xmm7, xmm8
	movaps	xmm10, xmm9
	movaps	xmm8, xmm7
	punpckldq xmm10, xmm3
	punpckhdq xmm9, xmm3
	punpckhdq xmm7, xmm3
	punpckldq xmm8, xmm3
	movaps	xmm3, xmm8
	psllq	xmm9, 0x6
	paddq	xmm2, xmm10
	psllq	xmm3, 0xc
	paddq	xmm5, xmm9
	psllq	xmm7, 0x12
	paddq	xmm4, xmm3
	paddq	xmm1, xmm7
.check32_nom:
	movaps	xmm8, xmm2
	movaps	xmm3, xmm1
	movaps	xmm15, xmm1
	psrlq	xmm8, 0x1a
	pand	xmm2, xmm0
	pand	xmm15, xmm0
	psrlq	xmm3, 0x1a
	paddq	xmm8, xmm5
	paddq	xmm3, xmm12
	movaps	xmm9, xmm8
	pand	xmm8, xmm0
	movaps	xmm1, xmm3
	psrlq	xmm9, 0x1a
	movaps	xmm12, xmm3
	psrlq	xmm1, 0x1a
	paddq	xmm9, xmm4
	pand	xmm12, xmm0
	pmuludq xmm6, xmm1
	movaps	xmm3, xmm9
	pand	xmm9, xmm0
	psrlq	xmm3, 0x1a
	paddq	xmm15, xmm3
	paddq	xmm2, xmm6
	movaps	xmm3, xmm15
	pand	xmm15, xmm0
	movaps	xmm1, xmm2
	psrlq	xmm3, 0x1a
	psrlq	xmm1, 0x1a
	paddq	xmm12, xmm3
	movaps	xmm3, xmm0
	paddq	xmm8, xmm1
	pand	xmm3, xmm2

.checkm:
	test	rsi, rsi
	jz	.nom
	pshufd	xmm3, xmm3, 0x8
	pshufd	xmm8, xmm8, 0x8
	pshufd	xmm9, xmm9, 0x8
	pshufd	xmm15, xmm15, 0x8
	pshufd	xmm12, xmm12, 0x8
	punpcklqdq xmm3, xmm8
	punpcklqdq xmm9, xmm15
	movups	[rdi], xmm3
	movups	[rdi+0x10], xmm9
	movq	[rdi+0x20], xmm12

	mov	rcx, [rsp+0x150]
	add	rsp, 0x158
	add	rsp, rcx
	pop	rbx
	epilog

calign
.nom:
	movaps	xmm0, xmm3
	movaps	xmm4, xmm8
	movaps	xmm2, xmm9
	psrldq	xmm0, 0x8
	movaps	xmm10, xmm15
	paddq	xmm3, xmm0
	psrldq	xmm4, 0x8
	movaps	xmm0, xmm12
	movd	edx, xmm3
	paddq	xmm8, xmm4
	psrldq	xmm2, 0x8
	mov	ecx, edx
	movd	eax, xmm8
	paddq	xmm9, xmm2
	shr	ecx, 0x1a
	psrldq	xmm10, 0x8
	and	edx, 0x3ffffff
	add	eax, ecx
	movd	ecx, xmm9
	paddq	xmm15, xmm10
	mov	r9d, eax
	shr	eax, 0x1a
	psrldq	xmm0, 0x8
	add	eax, ecx
	movd	ecx, xmm15
	paddq	xmm12, xmm0
	mov	esi, eax
	and	r9d, 0x3ffffff
	movd	r10d, xmm12
	shr	esi, 0x1a
	and	eax, 0x3ffffff
	add	esi, ecx
	shl	rax, 0x8
	mov	ecx, r9d
	shr	r9d, 0x12
	mov	r8d, esi
	shr	esi, 0x1a
	and	r8d, 0x3ffffff
	add	esi, r10d
	or	rax, r9
	shl	rsi, 0x10
	mov	r9, r8
	shr	r8d, 0xa
	shl	rcx, 0x1a
	or	rsi, r8
	shl	r9, 0x22
	or	rcx, rdx
	mov	r11, rsi
	shr	rsi, 0x2a
	mov	rdx, 0xfffffffffff
	or	rax, r9
	mov	r8, 0x3ffffffffff
	and	rcx, rdx
	and	rax, rdx
	and	r11, r8
	lea	rsi, [rsi+rsi*4]
	add	rcx, rsi
	mov	r10, rcx
	shr	rcx, 0x2c
	add	rax, rcx
	and	r10, rdx
	mov	r9, rax
	shr	rax, 0x2c
	add	rax, r11
	and	r9, rdx
	mov	r11, 0xfffffc0000000000
	mov	rcx, rax
	and	rcx, r8
	shr	rax, 0x2a
	lea	rsi, [rax+rax*4]
	add	r11, rcx
	add	rsi, r10
	mov	r8, rsi
	shr	rsi, 0x2c
	and	r8, rdx
	add	rsi, r9
	lea	r9, [r8+0x5]
	mov	rbx, r9
	and	r9, rdx
	shr	rbx, 0x2c
	add	rbx, rsi
	mov	rax, rbx
	and	rdx, rbx
	shr	rax, 0x2c
	add	r11, rax
	mov	rax, r11
	shr	rax, 0x3f
	sub	rax, 1
	mov	r10, rax
	and	r9, rax
	and	rdx, rax
	not	r10
	and	rax, r11
	and	r8, r10
	and	rsi, r10
	and	rcx, r10
	or	r8, r9
	or	rsi, rdx
	or	rcx, rax
	mov	[rdi], r8
	mov	[rdi+0x8], rsi
	mov	[rdi+0x10], rcx

	mov	rcx, [rsp+0x150]
	add	rsp, 0x158
	add	rsp, rcx
	pop	rbx
	epilog

calign
.final_r2_r:
	movd	xmm2, [rdi+0x38]
	lea	rax, [rdi+0x28]

	movups	xmm1, [rdi+0x3c]
	movups	xmm4, [rax]
	movd	eax, xmm2
	movd	xmm2, [rdi+0x4c]
	movaps	xmm7, xmm1
	movd	xmm5, eax
	punpckldq xmm7, xmm4
	punpckhdq xmm1, xmm4
	punpcklqdq xmm2, xmm5

	pshufd	xmm11, xmm7, 0x50
	pshufd	xmm4, xmm1, 0x50
	pshufd	xmm7, xmm7, 0xfa
	movaps	[rsp+0xa8], xmm11

	pshufd	xmm1, xmm1, 0xfa
	jmp	.rset

calign
.final_r_1:
	movd	xmm2, [rdi+0x38]
	lea	rax, [rdi+0x28]

	movups	xmm1, [rax]
	mov	r8d, 1
	movd	xmm4, r8d
	movaps	xmm7, xmm1
	punpckldq xmm7, xmm4
	punpckhdq xmm1, xmm4

	pshufd	xmm11, xmm7, 0x50
	pshufd	xmm4, xmm1, 0x50
	pshufd	xmm7, xmm7, 0xfa
	movaps	[rsp+0xa8], xmm11

	pshufd	xmm1, xmm1, 0xfa
	jmp	.rset

	

end if
