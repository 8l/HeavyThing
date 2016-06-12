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
	; pbkdf2.inc: standard PBKDF2 goods
	; NOTE: all of the new_* functions here just wrap hmac$new_* and set its key
	;


if used pbkdf2$new_md5 | defined include_everything
	; two arguments: rdi == passphrase pointer, rsi == length of same
	; returns a new hmac object
falign
pbkdf2$new_md5:
	prolog	pbkdf2$new_md5
	push	rdi rsi
	call	hmac$new_md5
	pop	rdx
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	hmac$key
	pop	rax
	epilog

end if

if used pbkdf2$init_md5 | defined include_everything
	; three arguments: rdi == hmac sized pointer, rsi == passphrase pointer, rdx == length of same
falign
pbkdf2$init_md5:
	prolog	pbkdf2$init_md5
	push	rdi rsi rdx
	call	hmac$init_md5
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if

if used pbkdf2$new_sha1 | defined include_everything
	; two arguments: rdi == passphrase pointer, rsi == length of same
	; returns a new hmac object
falign
pbkdf2$new_sha1:
	prolog	pbkdf2$new_sha1
	push	rdi rsi
	call	hmac$new_sha1
	pop	rdx
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	hmac$key
	pop	rax
	epilog

end if

if used pbkdf2$init_sha1 | defined include_everything
	; three arguments: rdi == hmac sized pointer, rsi == passphrase pointer, rdx == length of same
falign
pbkdf2$init_sha1:
	prolog	pbkdf2$init_sha1
	push	rdi rsi rdx
	call	hmac$init_sha1
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if

if used pbkdf2$new_sha224 | defined include_everything
	; two arguments: rdi == passphrase pointer, rsi == length of same
	; returns a new hmac object
falign
pbkdf2$new_sha224:
	prolog	pbkdf2$new_sha224
	push	rdi rsi
	call	hmac$new_sha224
	pop	rdx
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	hmac$key
	pop	rax
	epilog

end if

if used pbkdf2$init_sha224 | defined include_everything
	; three arguments: rdi == hmac sized pointer, rsi == passphrase pointer, rdx == length of same
falign
pbkdf2$init_sha224:
	prolog	pbkdf2$init_sha224
	push	rdi rsi rdx
	call	hmac$init_sha224
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if

if used pbkdf2$new_sha256 | defined include_everything
	; two arguments: rdi == passphrase pointer, rsi == length of same
	; returns a new hmac object
falign
pbkdf2$new_sha256:
	prolog	pbkdf2$new_sha256
	push	rdi rsi
	call	hmac$new_sha256
	pop	rdx
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	hmac$key
	pop	rax
	epilog

end if

if used pbkdf2$init_sha256 | defined include_everything
	; three arguments: rdi == hmac sized pointer, rsi == passphrase pointer, rdx == length of same
falign
pbkdf2$init_sha256:
	prolog	pbkdf2$init_sha256
	push	rdi rsi rdx
	call	hmac$init_sha256
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if

if used pbkdf2$new_sha384 | defined include_everything
	; two arguments: rdi == passphrase pointer, rsi == length of same
	; returns a new hmac object
falign
pbkdf2$new_sha384:
	prolog	pbkdf2$new_sha384
	push	rdi rsi
	call	hmac$new_sha384
	pop	rdx
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	hmac$key
	pop	rax
	epilog

end if

if used pbkdf2$init_sha384 | defined include_everything
	; three arguments: rdi == hmac sized pointer, rsi == passphrase pointer, rdx == length of same
falign
pbkdf2$init_sha384:
	prolog	pbkdf2$init_sha384
	push	rdi rsi rdx
	call	hmac$init_sha384
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if

if used pbkdf2$new_sha512 | defined include_everything
	; two arguments: rdi == passphrase pointer, rsi == length of same
	; returns a new hmac object
falign
pbkdf2$new_sha512:
	prolog	pbkdf2$new_sha512
	push	rdi rsi
	call	hmac$new_sha512
	pop	rdx
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	hmac$key
	pop	rax
	epilog

end if

if used pbkdf2$init_sha512 | defined include_everything
	; three arguments: rdi == hmac sized pointer, rsi == passphrase pointer, rdx == length of same
falign
pbkdf2$init_sha512:
	prolog	pbkdf2$init_sha512
	push	rdi rsi rdx
	call	hmac$init_sha512
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if



if used pbkdf2$doit | defined include_everything
	; arguments: rdi == pbkdf2 object, rsi == destination, edx == length of same, rcx == salt, r8d == saltlen, r9d == iterations
	; NOTE: rdi must be setup/initialized already
falign
pbkdf2$doit:
	prolog	pbkdf2$doit
	test	edx, edx
	jz	.nothingtodo
	push	rbp rbx r12 r13 r14 r15
	mov	rbp, rdi			; our pbkdf2/hmac object
	mov	r12, rsi			; dest
	mov	r13d, edx			; keylen
	mov	r14, rcx			; salt
	mov	r15d, r8d			; saltlen
	; mov	ebx, r9d			; iteration count
	sub	rsp, 128
	mov	[rsp+120], r9d			; save the iteration count
	mov	dword [rsp+124], 1		; 1-based counter
	mov	rdi, rsi			; dest
	xor	esi, esi
	call	memset
calign
.outer:
	mov	rdi, rbp
	mov	rsi, r14			; salt
	mov	edx, r15d			; saltlen
	call	qword [rbp+hmac_macupdate_ofs]
	mov	eax, [rsp+124]
	mov	rdi, rbp
if use_movbe
	movbe	[rsp], eax
else
	bswap	eax
	mov	[rsp], eax
end if
	mov	rsi, rsp
	mov	edx, 4
	call	qword [rbp+hmac_macupdate_ofs]
	mov	rdi, rbp
	mov	rsi, rsp
	call	hmac$final
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, [rbp+hmac_macsize_ofs]
	cmp	edx, r13d
	cmova	edx, r13d
	call	memxor
	mov	ebx, [rsp+120]			; iteration count
	sub	ebx, 1
	jz	.noinner
calign
.inner:
	mov	rdi, rbp
	mov	rsi, rsp
	mov	edx, [rbp+hmac_macsize_ofs]
	call	qword [rbp+hmac_macupdate_ofs]
	mov	rdi, rbp
	mov	rsi, rsp
	call	hmac$final
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, [rbp+hmac_macsize_ofs]
	cmp	edx, r13d
	cmova	edx, r13d
	call	memxor
	sub	ebx, 1
	jnz	.inner
calign
.noinner:
	mov	edx, [rbp+hmac_macsize_ofs]
	cmp	edx, r13d
	cmova	edx, r13d
	add	r12, rdx
	add	dword [rsp+124], 1
	sub	r13d, edx
	jnz	.outer
	add	rsp, 128
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.nothingtodo:
	epilog

end if
