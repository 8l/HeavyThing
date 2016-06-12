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
	;       hmac_drbg.inc: HMAC_DRBG object for generating random data
	;
	; NOTE: for the hmac_drbg$new, we do _not_ include any external data for
	; the seed material, it is up to the caller to gather and seed it.
	;
	; When we reseed however, we pull the underlying hash size length worth
	; of bytes from /dev/urandom to keep going with (and if you use
	; generate_additional to provide your own external entropy, that will also
	; get included per the spec)
	;


if used hmac_drbg$new | defined include_everything

hmac_drbg_hmac_ofs = 0		; pointer to hmac init function
hmac_drbg_rc_ofs = 8		; reseed counter
hmac_drbg_hs_ofs = 12		; the size of the underlying hash in bytes
hmac_drbg_k_ofs = 16		; K for (what is presently 64 bytes == SHA512 == max hash size)
hmac_drbg_v_ofs = 80		; V

hmac_drbg_size = 144

	; our default reseed interval (512k calls to generate == reseed)
hmac_drbg_reseed_interval = 1 shl 19


	; three arguments: rdi == pointer to one of the hmac$init_* functions, rsi == seed material, edx == length of same
	; returns a new hmac_drbg object in rax
falign
hmac_drbg$new:
	prolog	hmac_drbg$new
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	mov	edi, hmac_drbg_size
	call	heap$alloc_clear
	mov	rcx, rbx
	mov	[rax+hmac_drbg_hmac_ofs], rbx
	mov	dword [rax+hmac_drbg_rc_ofs], hmac_drbg_reseed_interval
	mov	rbx, rax
	sub	rsp, hmac_size
	mov	rdi, rsp
	call	rcx
	mov	eax, [rsp+hmac_macsize_ofs]
	mov	[rbx+hmac_drbg_hs_ofs], eax
	; thanks to the alloc_clear, our key is already zeroes
	; we need V set to all ones
	lea	rdi, [rbx+hmac_drbg_v_ofs]
	mov	esi, 1
	mov	edx, eax
	call	memset
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$key
	; now K = HMAC(K, V || 0x00 || seed material)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	sub	rsp, 8
	mov	dword [rsp], 0
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	lea	rdi, [rsp+8]
	mov	rsi, r12
	mov	edx, r13d
	call	hmac$data
	; set our new K to its final
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; reset the hmac key with that as well
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; now V = HMAC(K, V)
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; now K = HMAC(K, V || 0x01 || seed material)
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	dword [rsp], 1
	lea	rdi, [rsp+8]
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	lea	rdi, [rsp+8]
	mov	rsi, r12
	mov	edx, r13d
	call	hmac$data
	; set our new K to its final
	add	rsp, 8
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	add	rsp, hmac_size
	mov	rax, rbx
	pop	r13 r12 rbx
	epilog

end if

if used hmac_drbg$destroy | defined include_everything
	; single argument in rdi: hmac_drbg object
	; NOTE: we clear our state rather than return it as-is to the heap
falign
hmac_drbg$destroy:
	prolog	hmac_drbg$destroy
	call	heap$free_clear
	epilog

end if


if used hmac_drbg$generate | defined include_everything
	; three arguments: rdi == hmac_drbg object, rsi == destination ptr, edx == nonzero desired length in BYTES.
falign
hmac_drbg$generate:
	prolog	hmac_drbg$generate
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	sub	rsp, hmac_size
	mov	rdi, rsp
	call	qword [rbx+hmac_drbg_hmac_ofs]
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$key
calign
.genloop:
	; V = HMAC(K, V)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; append V to output
	mov	rdi, r12
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, r13d
	mov	ecx, [rbx+hmac_drbg_hs_ofs]
	cmp	edx, ecx
	cmova	edx, ecx
	add	r12, rdx
	sub	r13d, edx
	call	memcpy
	test	r13d, r13d
	jnz	.genloop
	; K = HMAC(K, V || 0x00)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	sub	rsp, 8
	mov	dword [rsp], 0
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	add	rsp, 8
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; check for reseed
	sub	dword [rbx+hmac_drbg_rc_ofs], 1
	jz	.reseed
	add	rsp, hmac_size
	pop	r13 r12 rbx
	epilog
calign
.reseed:
	; per the commentary atop this file, since we have no additional entropy to add
	; we just grab 63 bytes from /dev/urandom for our entropy input
	sub	rsp, 64
	mov	eax, syscall_open
	mov	rdi, .devurandom
	xor	esi, esi
	syscall
	cmp	eax, 0
	jl	.reseed_failed
	mov	r12d, eax
	mov	edi, eax
	lea	rsi, [rsp+1]
	mov	edx, 63
	mov	eax, syscall_read
	syscall
	mov	r13d, eax
	mov	eax, syscall_close
	mov	edi, r12d
	syscall
	cmp	r13d, 0
	jle	.reseed_failed
	; K = HMAC(K, V || 0x00 || entropy)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; K = HMAC(K, V || 0x01 || entropy)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	mov	byte [rsp], 1
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
.reseed_failed:
	; reset our reseed counter
	mov	dword [rbx+hmac_drbg_rc_ofs], hmac_drbg_reseed_interval
	; done
	add	rsp, hmac_size + 64
	pop	r13 r12 rbx
	epilog
dalign
.devurandom:
	db	'/dev/urandom', 0

end if

if used hmac_drbg$generate_additional | defined include_everything
	; five arguments: rdi == hmac_drbg object, rsi == destination ptr, edx == desired length in BYTES, rcx == additional data, r8d == length of same
falign
hmac_drbg$generate_additional:
	prolog	hmac_drbg$generate_additional
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	mov	r14, rcx
	mov	r15d, r8d
	sub	rsp, hmac_size
	mov	rdi, rsp
	call	qword [rbx+hmac_drbg_hmac_ofs]
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$key
	; K = HMAC(K, V || 0x00 || additional)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	sub	rsp, 8
	mov	dword [rsp], 0
	lea	rdi, [rsp+8]
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	lea	rdi, [rsp+8]
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$data
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; K = HMAC(K, V || 0x01 || additional)
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	dword [rsp], 1
	lea	rdi, [rsp+8]
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	add	rsp, 8
	mov	rdi, rsp
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
calign
.genloop:
	; V = HMAC(K, V)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; append V to output
	mov	rdi, r12
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, r13d
	mov	ecx, [rbx+hmac_drbg_hs_ofs]
	cmp	edx, ecx
	cmova	edx, ecx
	add	r12, rdx
	sub	r13d, edx
	call	memcpy
	test	r13d, r13d
	jnz	.genloop
	; repeat of our initial goods
	; K = HMAC(K, V || 0x00 || additional)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	sub	rsp, 8
	mov	dword [rsp], 0
	lea	rdi, [rsp+8]
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	lea	rdi, [rsp+8]
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$data
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; K = HMAC(K, V || 0x01 || additional)
	lea	rdi, [rsp+8]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	dword [rsp], 1
	lea	rdi, [rsp+8]
	mov	rsi, rsp
	mov	edx, 1
	call	hmac$data
	add	rsp, 8
	mov	rdi, rsp
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	mov	rdi, rsp
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; check for whether we need to reseed or not
	sub	dword [rbx+hmac_drbg_rc_ofs], 1
	jz	.reseed
	add	rsp, hmac_size
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.reseed:
	; also per the commentary, we still grab 63 bytes from /dev/urandom, but we also
	; per the spec add the provided additional entropy to it
	sub	rsp, 64
	mov	eax, syscall_open
	mov	rdi, .devurandom
	xor	esi, esi
	syscall
	cmp	eax, 0
	jl	.reseed_failed
	mov	r12d, eax
	mov	edi, eax
	lea	rsi, [rsp+1]
	mov	edx, 63
	mov	eax, syscall_read
	syscall
	mov	r13d, eax
	mov	eax, syscall_close
	mov	edi, r12d
	syscall
	cmp	r13d, 0
	jle	.reseed_failed
	; K = HMAC(K, V || 0x00 || entropy || additional)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	lea	rdi, [rsp+64]
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
	; K = HMAC(K, V || 0x01 || entropy || additional)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	mov	byte [rsp], 1
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	lea	rdi, [rsp+64]
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	call	hmac$final
	; replace the key
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_k_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$replace_key
	; V = HMAC(K, V)
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	mov	edx, [rbx+hmac_drbg_hs_ofs]
	call	hmac$data
	lea	rdi, [rsp+64]
	lea	rsi, [rbx+hmac_drbg_v_ofs]
	call	hmac$final
.reseed_failed:
	; reset our reseed counter
	mov	dword [rbx+hmac_drbg_rc_ofs], hmac_drbg_reseed_interval
	; done
	add	rsp, hmac_size + 64
	pop	r13 r12 rbx
	epilog
dalign
.devurandom:
	db	'/dev/urandom', 0

end if
