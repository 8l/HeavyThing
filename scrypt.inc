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
	; scrypt.inc: Colin Percival's scrypt goodies
	; see ht_defaults.inc for the parameter settings N, r, and p
	;
	; reference implementation for the most part... for non-parallel, not the fastest
	; but certainly not the slowest either... I was mainly just playing around with this
	; and never really bothered to come back and clean up my work-in-progress.
	; that being said, still does the job and suits my needs despite it not being the
	; most elegant piece ;-) haha
	;
	; I should imagine this could be made to go quite a bit faster if one were
	; properly motivated, haha
	;

        ; SCRYPT settings:
	; scrypt_sha512 determines whether we use sha512 or the normal sha256
        ; scrypt_N = 1024
	;    N _must_ be a power of 2
	; NOTE: i didn't really do this code up for r & p being != 1, started to anyway
	; all of my use cases stick with r and p == 1 so this is fine with me.

if used scrypt | used scrypt_iter | defined include_everything

	scrypt_hmac_ofs = 0
	scrypt_hmacalign_ofs = hmac_size		; hmac_size is not evenly divisible by 16
	scrypt_salt_ofs = scrypt_hmacalign_ofs + 8
	scrypt_saltlen_ofs = scrypt_salt_ofs + 8
	scrypt_dest_ofs = scrypt_saltlen_ofs + 8
	scrypt_destlen_ofs = scrypt_dest_ofs + 8
	scrypt_loop1_ofs = scrypt_destlen_ofs + 8
	scrypt_loop2_ofs = scrypt_loop1_ofs + 8
	scrypt_iter_ofs = scrypt_loop2_ofs + 8
	scrypt_B_ofs = scrypt_iter_ofs + 8
	scrypt_X_ofs = scrypt_B_ofs + (scrypt_p * 128)
	scrypt_scratch_ofs = scrypt_X_ofs + 32 + (scrypt_p * 128)	; +32 to align scratch by 64
	scrypt_size = scrypt_scratch_ofs + (scrypt_N * 128) + 64

	; default size is ~128.5KB

end if


if used scrypt | defined include_everything

	; six arguments: rdi == destination ptr, esi == length of same, rdx == passphrase, ecx == passlen, r8 == salt, r9d == saltlen
	; NOTE: we do all our work on the stack, caution is advised when messing with parameters :-)
falign
scrypt:
	prolog	scrypt
	push	rbp rbx r12 r13 r14 r15
	test	rsp, 0xf
	jz	.maligned
	call	.doit
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.maligned:
	sub	rsp, 8
	call	.doit
	add	rsp, 8
	pop	r15 r14 r13 r12 rbx rbp
	epilog
falign
.doit:
	; rsp is 16 byte aligned and ready to roll
	sub	rsp, scrypt_size
	mov	[rsp+scrypt_dest_ofs], rdi
	mov	[rsp+scrypt_destlen_ofs], esi
	mov	[rsp+scrypt_salt_ofs], r8
	mov	[rsp+scrypt_saltlen_ofs], r9
	mov	rdi, rsp
	mov	rsi, rdx
	mov	edx, ecx
if scrypt_sha512
	call	pbkdf2$init_sha512
else
	call	pbkdf2$init_sha256
end if
	mov	rdi, rsp
	lea	rsi, [rsp+scrypt_B_ofs]
	mov	edx, scrypt_p * 128
	mov	rcx, [rsp+scrypt_salt_ofs]
	mov	r8d, [rsp+scrypt_saltlen_ofs]
	mov	r9d, 1
	call	pbkdf2$doit

	; B is set to go, next up: X
	lea	rdi, [rsp+scrypt_X_ofs]
	lea	rsi, [rsp+scrypt_B_ofs]
	mov	qword [rsp+scrypt_loop1_ofs], scrypt_p

	; X = B
	mov	edx, 128
	call	memcpy

	; do a little salsa dance

macro NRRX a,b,c,rr {
	movd	r10d, c
	lea	eax, [b+r10d]
	rol	eax, rr
	xor	a, eax
}

macro NRRR a,b,c,rr {
	lea	eax, [b+c]
        rol     eax, rr
        xor     a, eax
}

macro NXRR a,b,c,rr {
        movd    r10d, a
	lea	eax, [b+c]
        rol     eax, rr
        xor     r10d, eax
        movd    a, r10d
}

macro NRXR a,b,c,rr {
        movd    eax, b
        add     eax, c
        rol     eax, rr
        xor     a, eax
}

macro NXXX a,b,c,rr {
        movd    eax, b
        movd    r10d, c
        add     eax, r10d
        rol     eax, rr
        movd    r10d, a
        xor     r10d, eax
        movd    a, r10d
}

macro scrypt_xor_salsa8_firsthalf {
	; first half ^= second half
        movaps  xmm0, [rsp+scrypt_X_ofs]
        movaps  xmm1, [rsp+scrypt_X_ofs+16]
        movaps  xmm2, [rsp+scrypt_X_ofs+32]
        movaps  xmm3, [rsp+scrypt_X_ofs+48]

	pxor	xmm0, [rsp+scrypt_X_ofs+64]
	pxor	xmm1, [rsp+scrypt_X_ofs+64+16]
	pxor	xmm2, [rsp+scrypt_X_ofs+64+32]
	pxor	xmm3, [rsp+scrypt_X_ofs+64+48]

        ; put them back now
        movaps  [rsp+scrypt_X_ofs], xmm0
        movaps  [rsp+scrypt_X_ofs+16], xmm1
        movaps  [rsp+scrypt_X_ofs+32], xmm2
        movaps  [rsp+scrypt_X_ofs+48], xmm3

        ; next up, 4 iterations of a pleasant cascading dependency mess
        ; mov     ecx, [rsp+scrypt_X_ofs]
        mov     edx, [rsp+scrypt_X_ofs+4]
        mov     ebp, [rsp+scrypt_X_ofs+8]
        mov     edi, [rsp+scrypt_X_ofs+12]
	movd	ecx, xmm0
	movd	esi, xmm1
	movd	r12d, xmm2
        ; mov     esi, [rsp+scrypt_X_ofs+16]
        mov     r8d, [rsp+scrypt_X_ofs+20]
        mov     r9d, [rsp+scrypt_X_ofs+24]
        mov     r11d, [rsp+scrypt_X_ofs+28]
	movaps	xmm12, xmm3
	pshufd	xmm13, xmm3, 01010101b
	pshufd	xmm14, xmm3, 10101010b
        ; mov     r12d, [rsp+scrypt_X_ofs+32]
        mov     r13d, [rsp+scrypt_X_ofs+36]
        mov     r14d, [rsp+scrypt_X_ofs+40]
        mov     r15d, [rsp+scrypt_X_ofs+44]

	pshufd	xmm15, xmm3, 11111111b

        ; now our iterations
        repeat 4
                NRRX    esi, ecx, xmm12, 7
                NRRR    r13d, r8d, edx, 7
                NXRR    xmm14, r14d, r9d, 7
                NRXR    edi, xmm15, r15d, 7

                NRRR    r12d, esi, ecx, 9
                NXRR    xmm13, r13d, r8d, 9
                NRXR    ebp, xmm14, r14d, 9
                NRRX    r11d, edi, xmm15, 9

                NXRR    xmm12, r12d, esi, 13
                NRXR    edx, xmm13, r13d, 13
                NRRX    r9d, ebp, xmm14, 13
                NRRR    r15d, r11d, edi, 13

                NRXR    ecx, xmm12, r12d, 18
                NRRX    r8d, edx, xmm13, 18
                NRRR    r14d, r9d, ebp, 18
                NXRR    xmm15, r15d, r11d, 18

                NRRR    edx, ecx, edi, 7
                NRRR    r9d, r8d, esi, 7
                NRRR    r15d, r14d, r13d, 7
                NXXX    xmm12, xmm15, xmm14, 7

                NRRR    ebp, edx, ecx, 9
                NRRR    r11d, r9d, r8d, 9
                NRRR    r12d, r15d, r14d, 9
                NXXX    xmm13, xmm12, xmm15, 9

                NRRR    edi, ebp, edx, 13
                NRRR    esi, r11d, r9d, 13
                NRRR    r13d, r12d, r15d, 13
                NXXX    xmm14, xmm13, xmm12, 13

                NRRR    ecx, edi, ebp, 18
                NRRR    r8d, esi, r11d, 18
                NRRR    r14d, r13d, r12d, 18
                NXXX    xmm15, xmm14, xmm13, 18
        end repeat
        ; next up: [B] += x0 .. up to 15, hmm
        add     dword [rsp+scrypt_X_ofs], ecx
        add     dword [rsp+scrypt_X_ofs+4], edx
        add     dword [rsp+scrypt_X_ofs+8], ebp
	movd	eax, xmm12
        add     dword [rsp+scrypt_X_ofs+12], edi
        add     dword [rsp+scrypt_X_ofs+16], esi
        add     dword [rsp+scrypt_X_ofs+20], r8d
	movd	r10d, xmm13
        add     dword [rsp+scrypt_X_ofs+24], r9d
        add     dword [rsp+scrypt_X_ofs+28], r11d
        add     dword [rsp+scrypt_X_ofs+32], r12d
	movd	ecx, xmm14
        add     dword [rsp+scrypt_X_ofs+36], r13d
        add     dword [rsp+scrypt_X_ofs+40], r14d
        add     dword [rsp+scrypt_X_ofs+44], r15d
	movd	edx, xmm15

	add	dword [rsp+scrypt_X_ofs+48], eax
	add	dword [rsp+scrypt_X_ofs+52], r10d
	add	dword [rsp+scrypt_X_ofs+56], ecx
	add	dword [rsp+scrypt_X_ofs+60], edx
}

macro scrypt_xor_salsa8_lasthalf {
        movaps  xmm0, [rsp+scrypt_X_ofs+64]
        movaps  xmm1, [rsp+scrypt_X_ofs+64+16]
        movaps  xmm2, [rsp+scrypt_X_ofs+64+32]
        movaps  xmm3, [rsp+scrypt_X_ofs+64+48]
        movaps  xmm4, [rsp+scrypt_X_ofs]
        movaps  xmm5, [rsp+scrypt_X_ofs+16]
        movaps  xmm6, [rsp+scrypt_X_ofs+32]
        movaps  xmm7, [rsp+scrypt_X_ofs+48]
        pxor    xmm0, xmm4
        pxor    xmm1, xmm5
        pxor    xmm2, xmm6
        pxor    xmm3, xmm7
        ; put them back now (into B)
        movaps  [rsp+scrypt_X_ofs+64], xmm0
        movaps  [rsp+scrypt_X_ofs+64+16], xmm1
        movaps  [rsp+scrypt_X_ofs+64+32], xmm2
        movaps  [rsp+scrypt_X_ofs+64+48], xmm3
        ; next up, 4 iterations of a pleasant cascading dependency mess
        mov     ecx, [rsp+scrypt_X_ofs+64]
        mov     edx, [rsp+scrypt_X_ofs+64+4]
        mov     ebp, [rsp+scrypt_X_ofs+64+8]
        mov     edi, [rsp+scrypt_X_ofs+64+12]
        mov     esi, [rsp+scrypt_X_ofs+64+16]
        mov     r8d, [rsp+scrypt_X_ofs+64+20]
        mov     r9d, [rsp+scrypt_X_ofs+64+24]
        mov     r11d, [rsp+scrypt_X_ofs+64+28]
        mov     r12d, [rsp+scrypt_X_ofs+64+32]
        mov     r13d, [rsp+scrypt_X_ofs+64+36]
        mov     r14d, [rsp+scrypt_X_ofs+64+40]
        mov     r15d, [rsp+scrypt_X_ofs+64+44]

	movaps	xmm12, xmm3
	pshufd	xmm13, xmm3, 01010101b
	pshufd	xmm14, xmm3, 10101010b
	pshufd	xmm15, xmm3, 11111111b

        ; now our iterations
        repeat 4
                NRRX    esi, ecx, xmm12, 7
                NRRR    r13d, r8d, edx, 7
                NXRR    xmm14, r14d, r9d, 7
                NRXR    edi, xmm15, r15d, 7

                NRRR    r12d, esi, ecx, 9
                NXRR    xmm13, r13d, r8d, 9
                NRXR    ebp, xmm14, r14d, 9
                NRRX    r11d, edi, xmm15, 9

                NXRR    xmm12, r12d, esi, 13
                NRXR    edx, xmm13, r13d, 13
                NRRX    r9d, ebp, xmm14, 13
                NRRR    r15d, r11d, edi, 13

                NRXR    ecx, xmm12, r12d, 18
                NRRX    r8d, edx, xmm13, 18
                NRRR    r14d, r9d, ebp, 18
                NXRR    xmm15, r15d, r11d, 18

                NRRR    edx, ecx, edi, 7
                NRRR    r9d, r8d, esi, 7
                NRRR    r15d, r14d, r13d, 7
                NXXX    xmm12, xmm15, xmm14, 7

                NRRR    ebp, edx, ecx, 9
                NRRR    r11d, r9d, r8d, 9
                NRRR    r12d, r15d, r14d, 9
                NXXX    xmm13, xmm12, xmm15, 9

                NRRR    edi, ebp, edx, 13
                NRRR    esi, r11d, r9d, 13
                NRRR    r13d, r12d, r15d, 13
                NXXX    xmm14, xmm13, xmm12, 13

                NRRR    ecx, edi, ebp, 18
                NRRR    r8d, esi, r11d, 18
                NRRR    r14d, r13d, r12d, 18
                NXXX    xmm15, xmm14, xmm13, 18
        end repeat
        ; next up: [B] += x0 .. up to 15, hmm
        add     dword [rsp+scrypt_X_ofs+64], ecx
        add     dword [rsp+scrypt_X_ofs+64+4], edx
        add     dword [rsp+scrypt_X_ofs+64+8], ebp
	movd	eax, xmm12
        add     dword [rsp+scrypt_X_ofs+64+12], edi
        add     dword [rsp+scrypt_X_ofs+64+16], esi
        add     dword [rsp+scrypt_X_ofs+64+20], r8d
	movd	r10d, xmm13
        add     dword [rsp+scrypt_X_ofs+64+24], r9d
        add     dword [rsp+scrypt_X_ofs+64+28], r11d
        add     dword [rsp+scrypt_X_ofs+64+32], r12d
	movd	ecx, xmm14
        add     dword [rsp+scrypt_X_ofs+64+36], r13d
        add     dword [rsp+scrypt_X_ofs+64+40], r14d
        add     dword [rsp+scrypt_X_ofs+64+44], r15d
	movd	edx, xmm15

	add	dword [rsp+scrypt_X_ofs+64+48], eax
	add	dword [rsp+scrypt_X_ofs+64+52], r10d
	add	dword [rsp+scrypt_X_ofs+64+56], ecx
	add	dword [rsp+scrypt_X_ofs+64+60], edx
}
calign
.outerloop:
	lea	rbx, [rsp+scrypt_scratch_ofs]

	mov	qword [rsp+scrypt_loop2_ofs], scrypt_N
calign
.innerloop1:
	lea	rdx, [rsp+scrypt_X_ofs]
	mov	eax, [rsp+scrypt_loop2_ofs+4]
	
	; first up: memcpy(&V[i * 32], X, 128)
	movaps	xmm0, [rdx]
	movaps	xmm1, [rdx+16]
	movaps	xmm2, [rdx+32]
	movaps	[rbx+rax], xmm0
	movaps	[rbx+rax+16], xmm1
	movaps	[rbx+rax+32], xmm2
	movaps	xmm3, [rdx+48]
	movaps	xmm4, [rdx+64]
	movaps	xmm5, [rdx+80]
	movaps	[rbx+rax+48], xmm3
	movaps	[rbx+rax+64], xmm4
	movaps	[rbx+rax+80], xmm5
	movaps	xmm6, [rdx+96]
	movaps	xmm7, [rdx+112]
	movaps	[rbx+rax+96], xmm6
	movaps	[rbx+rax+112], xmm7

	scrypt_xor_salsa8_firsthalf
	scrypt_xor_salsa8_lasthalf

	add	dword [rsp+scrypt_loop2_ofs+4], 128
	sub	dword [rsp+scrypt_loop2_ofs], 1
	jnz	.innerloop1

	mov	qword [rsp+scrypt_loop2_ofs], scrypt_N
calign
.innerloop2:
	mov	eax, [rsp+scrypt_X_ofs+64]
	and	eax, scrypt_N - 1
	; eax now == X[16] & (scrypt_N - 1)
	shl	eax, 7				; byte offset we need for j = 32 *
	repeat (scrypt_p * 128) shr 2
		scrypt_k_iter = % - 1
		scrypt_k_ofs = scrypt_k_iter * 4
		mov	r12d, [rbx+rax+scrypt_k_ofs]
		xor	dword [rsp+scrypt_X_ofs+scrypt_k_ofs], r12d
	end repeat
	scrypt_xor_salsa8_firsthalf
	scrypt_xor_salsa8_lasthalf
	sub	dword [rsp+scrypt_loop2_ofs], 1
	jnz	.innerloop2

	add	dword [rsp+scrypt_loop1_ofs+4], 128
	sub	dword [rsp+scrypt_loop1_ofs], 1
	jnz	.outerloop

	lea	rdi, [rsp+scrypt_B_ofs]
	lea	rsi, [rsp+scrypt_X_ofs]
	mov	edx, scrypt_p * 128
	call	memcpy

	mov	rdi, rsp
	mov	rsi, [rsp+scrypt_dest_ofs]
	mov	edx, [rsp+scrypt_destlen_ofs]
	lea	rcx, [rsp+scrypt_B_ofs]
	mov	r8d, scrypt_p * 128
	mov	r9d, 1
	call	pbkdf2$doit

	add	rsp, scrypt_size
	ret

end if



if used scrypt_iter | defined include_everything

	; seven arguments: rdi == destination ptr, esi == length of same, rdx == passphrase, ecx == passlen, r8 == salt, r9d == saltlen, r10d == PBKDF2 iteration count
	; this is the same thing as above, but with a non-scrypt-spec for PBKDF2 iterations
falign
scrypt_iter:
	prolog	scrypt_iter
	push	rbp rbx r12 r13 r14 r15
	test	rsp, 0xf
	jz	.maligned
	call	.doit
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.maligned:
	sub	rsp, 8
	call	.doit
	add	rsp, 8
	pop	r15 r14 r13 r12 rbx rbp
	epilog
falign
.doit:
	; rsp is 16 byte aligned and ready to roll
	sub	rsp, scrypt_size
	mov	[rsp+scrypt_dest_ofs], rdi
	mov	[rsp+scrypt_destlen_ofs], esi
	mov	[rsp+scrypt_salt_ofs], r8
	mov	[rsp+scrypt_saltlen_ofs], r9
	mov	[rsp+scrypt_iter_ofs], r10
	mov	rdi, rsp
	mov	rsi, rdx
	mov	edx, ecx
if scrypt_sha512
	call	pbkdf2$init_sha512
else
	call	pbkdf2$init_sha256
end if
	mov	rdi, rsp
	lea	rsi, [rsp+scrypt_B_ofs]
	mov	edx, scrypt_p * 128
	mov	rcx, [rsp+scrypt_salt_ofs]
	mov	r8d, [rsp+scrypt_saltlen_ofs]
	mov	r9d, [rsp+scrypt_iter_ofs]
	call	pbkdf2$doit

	; B is set to go, next up: X
	lea	rdi, [rsp+scrypt_X_ofs]
	lea	rsi, [rsp+scrypt_B_ofs]
	mov	qword [rsp+scrypt_loop1_ofs], scrypt_p

	; X = B
	mov	edx, 128
	call	memcpy
calign
.outerloop:
	lea	rbx, [rsp+scrypt_scratch_ofs]

	mov	qword [rsp+scrypt_loop2_ofs], scrypt_N
calign
.innerloop1:
	lea	rdx, [rsp+scrypt_X_ofs]
	mov	eax, [rsp+scrypt_loop2_ofs+4]
	
	; first up: memcpy(&V[i * 32], X, 128)
	movaps	xmm0, [rdx]
	movaps	xmm1, [rdx+16]
	movaps	xmm2, [rdx+32]
	movaps	[rbx+rax], xmm0
	movaps	[rbx+rax+16], xmm1
	movaps	[rbx+rax+32], xmm2
	movaps	xmm3, [rdx+48]
	movaps	xmm4, [rdx+64]
	movaps	xmm5, [rdx+80]
	movaps	[rbx+rax+48], xmm3
	movaps	[rbx+rax+64], xmm4
	movaps	[rbx+rax+80], xmm5
	movaps	xmm6, [rdx+96]
	movaps	xmm7, [rdx+112]
	movaps	[rbx+rax+96], xmm6
	movaps	[rbx+rax+112], xmm7

	scrypt_xor_salsa8_firsthalf
	scrypt_xor_salsa8_lasthalf

	add	dword [rsp+scrypt_loop2_ofs+4], 128
	sub	dword [rsp+scrypt_loop2_ofs], 1
	jnz	.innerloop1

	mov	qword [rsp+scrypt_loop2_ofs], scrypt_N
calign
.innerloop2:
	mov	eax, [rsp+scrypt_X_ofs+64]
	and	eax, scrypt_N - 1
	; eax now == X[16] & (scrypt_N - 1)
	shl	eax, 7				; byte offset we need for j = 32 *
	repeat (scrypt_p * 128) shr 2
		scrypt_k_iter = % - 1
		scrypt_k_ofs = scrypt_k_iter * 4
		mov	r12d, [rbx+rax+scrypt_k_ofs]
		xor	dword [rsp+scrypt_X_ofs+scrypt_k_ofs], r12d
	end repeat
	scrypt_xor_salsa8_firsthalf
	scrypt_xor_salsa8_lasthalf
	sub	dword [rsp+scrypt_loop2_ofs], 1
	jnz	.innerloop2

	add	dword [rsp+scrypt_loop1_ofs+4], 128
	sub	dword [rsp+scrypt_loop1_ofs], 1
	jnz	.outerloop

	lea	rdi, [rsp+scrypt_B_ofs]
	lea	rsi, [rsp+scrypt_X_ofs]
	mov	edx, scrypt_p * 128
	call	memcpy

	mov	rdi, rsp
	mov	rsi, [rsp+scrypt_dest_ofs]
	mov	edx, [rsp+scrypt_destlen_ofs]
	lea	rcx, [rsp+scrypt_B_ofs]
	mov	r8d, scrypt_p * 128
	mov	r9d, [rsp+scrypt_iter_ofs]
	call	pbkdf2$doit

	add	rsp, scrypt_size
	ret

end if
