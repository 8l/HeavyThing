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
	; hmac.inc: HMAC as required by TLS/SSH, supports MD5, SHA1, SHA2, SHA3
	;
hmac_hashstate_ofs = 0
hmac_ikey_ofs = hmac_hashstate_ofs + sha512_state_size
hmac_okey_ofs = hmac_ikey_ofs + 64
hmac_macinit_ofs = hmac_okey_ofs + 64
hmac_macupdate_ofs = hmac_macinit_ofs + 8
hmac_macfinal_ofs = hmac_macupdate_ofs + 8
hmac_macsize_ofs = hmac_macfinal_ofs + 8		; the size of the digest result

hmac_size = hmac_macsize_ofs + 8

hmac_debug = 0

if used hmac$new_md5 | defined include_everything
	; no arguments, returns a new hmac object set to work with md5 function hooks
falign
hmac$new_md5:
	prolog	hmac$new_md5
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], md5$init
	mov	qword [rax+hmac_macupdate_ofs], md5$update
	mov	qword [rax+hmac_macfinal_ofs], md5$final
	mov	dword [rax+hmac_macsize_ofs], 16
	epilog

end if

if used hmac$init_md5 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with md5 function hooks
falign
hmac$init_md5:
	prolog	hmac$init_md5
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], md5$init
	mov	qword [rdi+hmac_macupdate_ofs], md5$update
	mov	qword [rdi+hmac_macfinal_ofs], md5$final
	mov	dword [rdi+hmac_macsize_ofs], 16
	epilog

end if

if used hmac$new_sha1 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha1 function hooks
falign
hmac$new_sha1:
	prolog	hmac$new_sha1
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha160$init
	mov	qword [rax+hmac_macupdate_ofs], sha160$update
	mov	qword [rax+hmac_macfinal_ofs], sha160$final
	mov	dword [rax+hmac_macsize_ofs], 20
	epilog

end if

if used hmac$init_sha1 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha1 function hooks
falign
hmac$init_sha1:
	prolog	hmac$init_sha1
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha160$init
	mov	qword [rdi+hmac_macupdate_ofs], sha160$update
	mov	qword [rdi+hmac_macfinal_ofs], sha160$final
	mov	dword [rdi+hmac_macsize_ofs], 20
	epilog

end if

if used hmac$new_sha224 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha224 function hooks
falign
hmac$new_sha224:
	prolog	hmac$new_sha224
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha224$init
	mov	qword [rax+hmac_macupdate_ofs], sha224$update
	mov	qword [rax+hmac_macfinal_ofs], sha224$final
	mov	dword [rax+hmac_macsize_ofs], 28
	epilog

end if

if used hmac$init_sha224 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha224 function hooks
falign
hmac$init_sha224:
	prolog	hmac$init_sha224
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha224$init
	mov	qword [rdi+hmac_macupdate_ofs], sha224$update
	mov	qword [rdi+hmac_macfinal_ofs], sha224$final
	mov	dword [rdi+hmac_macsize_ofs], 28
	epilog

end if

if used hmac$new_sha3_224 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha3_224 function hooks
falign
hmac$new_sha3_224:
	prolog	hmac$new_sha3_224
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha3_224$init
	mov	qword [rax+hmac_macupdate_ofs], sha3_224$update
	mov	qword [rax+hmac_macfinal_ofs], sha3_224$final
	mov	dword [rax+hmac_macsize_ofs], 28
	epilog

end if

if used hmac$init_sha3_224 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha3_224 function hooks
falign
hmac$init_sha3_224:
	prolog	hmac$init_sha3_224
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha3_224$init
	mov	qword [rdi+hmac_macupdate_ofs], sha3_224$update
	mov	qword [rdi+hmac_macfinal_ofs], sha3_224$final
	mov	dword [rdi+hmac_macsize_ofs], 28
	epilog

end if


if used hmac$new_sha256 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha256 function hooks
falign
hmac$new_sha256:
	prolog	hmac$new_sha256
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha256$init
	mov	qword [rax+hmac_macupdate_ofs], sha256$update
	mov	qword [rax+hmac_macfinal_ofs], sha256$final
	mov	dword [rax+hmac_macsize_ofs], 32
	epilog

end if

if used hmac$init_sha256 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha256 function hooks
falign
hmac$init_sha256:
	prolog	hmac$init_sha256
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha256$init
	mov	qword [rdi+hmac_macupdate_ofs], sha256$update
	mov	qword [rdi+hmac_macfinal_ofs], sha256$final
	mov	dword [rdi+hmac_macsize_ofs], 32
	epilog

end if


if used hmac$new_sha3_256 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha3_256 function hooks
falign
hmac$new_sha3_256:
	prolog	hmac$new_sha3_256
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha3_256$init
	mov	qword [rax+hmac_macupdate_ofs], sha3_256$update
	mov	qword [rax+hmac_macfinal_ofs], sha3_256$final
	mov	dword [rax+hmac_macsize_ofs], 32
	epilog

end if

if used hmac$init_sha3_256 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha3_256 function hooks
falign
hmac$init_sha3_256:
	prolog	hmac$init_sha3_256
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha3_256$init
	mov	qword [rdi+hmac_macupdate_ofs], sha3_256$update
	mov	qword [rdi+hmac_macfinal_ofs], sha3_256$final
	mov	dword [rdi+hmac_macsize_ofs], 32
	epilog

end if


if used hmac$new_sha384 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha384 function hooks
falign
hmac$new_sha384:
	prolog	hmac$new_sha384
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha384$init
	mov	qword [rax+hmac_macupdate_ofs], sha384$update
	mov	qword [rax+hmac_macfinal_ofs], sha384$final
	mov	dword [rax+hmac_macsize_ofs], 48
	epilog

end if

if used hmac$init_sha384 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha384 function hooks
falign
hmac$init_sha384:
	prolog	hmac$init_sha384
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha384$init
	mov	qword [rdi+hmac_macupdate_ofs], sha384$update
	mov	qword [rdi+hmac_macfinal_ofs], sha384$final
	mov	dword [rdi+hmac_macsize_ofs], 48
	epilog

end if


if used hmac$new_sha3_384 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha3_384 function hooks
falign
hmac$new_sha3_384:
	prolog	hmac$new_sha3_384
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha3_384$init
	mov	qword [rax+hmac_macupdate_ofs], sha3_384$update
	mov	qword [rax+hmac_macfinal_ofs], sha3_384$final
	mov	dword [rax+hmac_macsize_ofs], 48
	epilog

end if

if used hmac$init_sha3_384 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha3_384 function hooks
falign
hmac$init_sha3_384:
	prolog	hmac$init_sha3_384
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha3_384$init
	mov	qword [rdi+hmac_macupdate_ofs], sha3_384$update
	mov	qword [rdi+hmac_macfinal_ofs], sha3_384$final
	mov	dword [rdi+hmac_macsize_ofs], 48
	epilog

end if


if used hmac$new_sha512 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha512 function hooks
falign
hmac$new_sha512:
	prolog	hmac$new_sha512
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha512$init
	mov	qword [rax+hmac_macupdate_ofs], sha512$update
	mov	qword [rax+hmac_macfinal_ofs], sha512$final
	mov	dword [rax+hmac_macsize_ofs], 64
	epilog

end if

if used hmac$init_sha512 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha512 function hooks
falign
hmac$init_sha512:
	prolog	hmac$init_sha512
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha512$init
	mov	qword [rdi+hmac_macupdate_ofs], sha512$update
	mov	qword [rdi+hmac_macfinal_ofs], sha512$final
	mov	dword [rdi+hmac_macsize_ofs], 64
	epilog

end if


if used hmac$new_sha3_512 | defined include_everything
	; no arguments, returns a new hmac object set to work with sha3_512 function hooks
falign
hmac$new_sha3_512:
	prolog	hmac$new_sha3_512
	mov	edi, hmac_size
	call	heap$alloc_clear
	mov	qword [rax+hmac_macinit_ofs], sha3_512$init
	mov	qword [rax+hmac_macupdate_ofs], sha3_512$update
	mov	qword [rax+hmac_macfinal_ofs], sha3_512$final
	mov	dword [rax+hmac_macsize_ofs], 64
	epilog

end if

if used hmac$init_sha3_512 | defined include_everything
	; single argument in rdi: ptr to an hmac_size block, initializes it with sha3_512 function hooks
falign
hmac$init_sha3_512:
	prolog	hmac$init_sha3_512
	push	rdi
	xor	esi, esi
	mov	edx, hmac_size
	call	memset32
	pop	rdi
	mov	qword [rdi+hmac_macinit_ofs], sha3_512$init
	mov	qword [rdi+hmac_macupdate_ofs], sha3_512$update
	mov	qword [rdi+hmac_macfinal_ofs], sha3_512$final
	mov	dword [rdi+hmac_macsize_ofs], 64
	epilog

end if

if used hmac$destroy | defined include_everything
	; single argument in rdi: hmac object to free/destroy
	; since we have no dynamic objects, it is safe to just call heap$free_clear
	; so this function is only here for reference
falign
hmac$destroy:
	prolog	hmac$destroy
	call	heap$free_clear
	epilog

end if

if used hmac$key | defined include_everything
	; three arguments: rdi == hmac object, rsi == ptr to key bytes, edx == length of same
	; this sets the ikey/okey, initializes the mac state with the first ikey
	; such that further calls can be made to data directly
	
	; it is assumed that this is only called ONCE for our object (we do not re-clear ikey/okey and assume they are
	; already zeroed on entry to here)
	; use replace_key if this is not the case
falign
hmac$key:
	prolog	hmac$key
	push	rbx
	mov	rbx, rdi

if hmac_debug
	; debug
	push	rsi rdx
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	mov	rsi, [rsp]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdx rsi
	mov	rdi, rbx
	; end debug
end if


	cmp	edx, 64
	ja	.hashed_key
	; copy key into our ikey and okey
	lea	rdi, [rdi+hmac_ikey_ofs]
	call	memcpy
	lea	rdi, [rbx+hmac_okey_ofs]
	lea	rsi, [rbx+hmac_ikey_ofs]
	mov	edx, 64
	call	memcpy
	; xor ikey with 0x36
	mov	rax, qword [.ixor]
	mov	rcx, qword [.oxor]
	xor	[rbx+hmac_ikey_ofs], rax
	xor	[rbx+hmac_ikey_ofs+8], rax
	xor	[rbx+hmac_ikey_ofs+16], rax
	xor	[rbx+hmac_ikey_ofs+24], rax
	xor	[rbx+hmac_ikey_ofs+32], rax
	xor	[rbx+hmac_ikey_ofs+40], rax
	xor	[rbx+hmac_ikey_ofs+48], rax
	xor	[rbx+hmac_ikey_ofs+56], rax
	xor	[rbx+hmac_okey_ofs], rcx
	xor	[rbx+hmac_okey_ofs+8], rcx
	xor	[rbx+hmac_okey_ofs+16], rcx
	xor	[rbx+hmac_okey_ofs+24], rcx
	xor	[rbx+hmac_okey_ofs+32], rcx
	xor	[rbx+hmac_okey_ofs+40], rcx
	xor	[rbx+hmac_okey_ofs+48], rcx
	xor	[rbx+hmac_okey_ofs+56], rcx
	; initialize the mac in readiness for the first data call
	mov	rdi, rbx
	call	qword [rbx+hmac_macinit_ofs]
	mov	rdi, rbx
	lea	rsi, [rbx+hmac_ikey_ofs]
	mov	edx, 64
	call	qword [rbx+hmac_macupdate_ofs]
	pop	rbx
	epilog

if hmac_debug
cleartext .debugstr, 'HMAC KEY IS:'
end if

align 16
.ixor	db	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
.oxor	db	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c
calign
.hashed_key:
	push	rsi rdx
	call	qword [rdi+hmac_macinit_ofs]
	pop	rdx rsi
	mov	rdi, rbx
	call	qword [rbx+hmac_macupdate_ofs]
	sub	rsp, 64
	mov	rdi, rbx
	mov	rsi, rsp
	xor	edx, edx	; do NOT call heap$free, haha
	call	qword [rbx+hmac_macfinal_ofs]
	mov	rdi, rbx
	mov	rsi, rsp
	mov	edx, dword [rbx+hmac_macsize_ofs]
	call	hmac$key
	add	rsp, 64
	pop	rbx
	epilog

end if

if used hmac$replace_key | defined include_everything
	; three arguments: rdi == hmac object, rsi == ptr to key bytes, edx == length of same
	; per above, this zeroes ikey/okey and then calls key
falign
hmac$replace_key:
	prolog	hmac$replace_key
	push	rdi rsi rdx
	lea	rdi, [rdi+hmac_ikey_ofs]
	xor	esi, esi
	mov	edx, 64		; note: we only have to clear ikey (due to hmac$key's copy of ikey to okey anyway)
	call	memset32
	pop	rdx rsi rdi
	call	hmac$key
	epilog

end if

if used hmac$data | defined include_everything
	; three arguments: rdi == hmac object, rsi == ptr to data bytes, rdx == length of same
	; this is mainly here for reference, due to the simplicity of the contents, caller should just do it that way
falign
hmac$data:
	prolog	hmac$data
	call	qword [rdi+hmac_macupdate_ofs]
	epilog

end if





if used hmac$phash | defined include_everything
	; five arguments: rdi == hmac object, rsi == ptr to output, edx == desired length of output, rcx == ptr to concatenated data, r8d == length of same
	; convenience function for TLS PRF goods, key must already be set
falign
hmac$phash:
	prolog	hmac$phash
	; we need space here for two full hashes, + 40 for our state information
	sub	rsp, 168
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	; first up: update our mac with the initial seed in rcx/r8d
	mov	rsi, rcx
	mov	edx, r8d
	call	qword [rdi+hmac_macupdate_ofs]
	; next up: finalize same into our spot for A
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	call	hmac$final

if hmac_debug
	; debug
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	rcx, [rsp]
	lea	rdi, [rsp+104]
	mov	esi, [rcx+hmac_macsize_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	; next up: update our mac with A
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	mov	edx, [rdi+hmac_macsize_ofs]
	call	qword [rdi+hmac_macupdate_ofs]

if hmac_debug
	; debug
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	rdi, [rsp+24]
	mov	esi, [rsp+32]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	; next up: update our mac with our initial seed
	mov	rdi, [rsp]
	mov	rsi, [rsp+24]
	mov	edx, [rsp+32]
	call	qword [rdi+hmac_macupdate_ofs]
	; next up: finalize our mac into our output temporary
	mov	rdi, [rsp]
	lea	rsi, [rsp+40]			; in case we are doing partial writes, we can't use output directly
	call	hmac$final
	; populate our output buffer
	mov	rcx, [rsp]
	mov	rdi, [rsp+8]
	lea	rsi, [rsp+40]
	mov	edx, [rcx+hmac_macsize_ofs]
	mov	ecx, [rsp+16]
	cmp	edx, ecx
	cmova	edx, ecx
	; update our output pointer and remaining count
	add	qword [rsp+8], rdx
	sub	dword [rsp+16], edx
	call	memcpy
	cmp	dword [rsp+16], 0
	je	.alldone
calign
.loop:
	; start of loop interior: update our mac with A
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	mov	edx, [rdi+hmac_macsize_ofs]
	call	qword [rdi+hmac_macupdate_ofs]
	; finalize result into A
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	call	hmac$final
	; update our mac with the new A
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	mov	edx, [rdi+hmac_macsize_ofs]
	call	qword [rdi+hmac_macupdate_ofs]
	; update our mac with the original seed
	mov	rdi, [rsp]
	mov	rsi, [rsp+24]
	mov	edx, [rsp+32]
	call	qword [rdi+hmac_macupdate_ofs]
	; finalize the mac into our output temporary
	mov	rdi, [rsp]
	lea	rsi, [rsp+40]
	call	hmac$final
	; populate our output buffer
	mov	rcx, [rsp]
	mov	rdi, [rsp+8]
	lea	rsi, [rsp+40]
	mov	edx, [rcx+hmac_macsize_ofs]
	mov	ecx, [rsp+16]
	cmp	edx, ecx
	cmova	edx, ecx
	; update our output pointer and remaining count
	add	qword [rsp+8], rdx
	sub	dword [rsp+16], edx
	call	memcpy
	cmp	dword [rsp+16], 0
	jne	.loop
calign
.alldone:
	add	rsp, 168
	epilog

if hmac_debug
cleartext .debugstr, 'feeding into hmac:'
end if

end if


if used hmac$phash_xor | defined include_everything
	; five arguments: rdi == hmac object, rsi == ptr to output, edx == desired length of output, rcx == ptr to concatenated data, r8d == length of same
	; convenience function for TLS PRF goods, key must already be set
	; same as phash, only xors instead of copies
falign
hmac$phash_xor:
	prolog	hmac$phash_xor
	sub	rsp, 168
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	rsi, rcx
	mov	edx, r8d
	call	qword [rdi+hmac_macupdate_ofs]
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	call	hmac$final
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	mov	edx, [rdi+hmac_macsize_ofs]
	call	qword [rdi+hmac_macupdate_ofs]
	mov	rdi, [rsp]
	mov	rsi, [rsp+24]
	mov	edx, [rsp+32]
	call	qword [rdi+hmac_macupdate_ofs]
	mov	rdi, [rsp]
	lea	rsi, [rsp+40]			; in case we are doing partial writes, we can't use output directly
	call	hmac$final
	; populate our output buffer
	mov	rcx, [rsp]
	mov	rdi, [rsp+8]
	lea	rsi, [rsp+40]
	mov	edx, [rcx+hmac_macsize_ofs]
	mov	ecx, [rsp+16]
	cmp	edx, ecx
	cmova	edx, ecx
	; update our output pointer and remaining count
	add	qword [rsp+8], rdx
	sub	dword [rsp+16], edx
	call	memxor
	cmp	dword [rsp+16], 0
	je	.alldone
calign
.loop:
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	mov	edx, [rdi+hmac_macsize_ofs]
	call	qword [rdi+hmac_macupdate_ofs]
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	call	hmac$final
	mov	rdi, [rsp]
	lea	rsi, [rsp+104]
	mov	edx, [rdi+hmac_macsize_ofs]
	call	qword [rdi+hmac_macupdate_ofs]
	mov	rdi, [rsp]
	mov	rsi, [rsp+24]
	mov	edx, [rsp+32]
	call	qword [rdi+hmac_macupdate_ofs]
	mov	rdi, [rsp]
	lea	rsi, [rsp+40]
	call	hmac$final
	; populate our output buffer
	mov	rcx, [rsp]
	mov	rdi, [rsp+8]
	lea	rsi, [rsp+40]
	mov	edx, [rcx+hmac_macsize_ofs]
	mov	ecx, [rsp+16]
	cmp	edx, ecx
	cmova	edx, ecx
	; update our output pointer and remaining count
	add	qword [rsp+8], rdx
	sub	dword [rsp+16], edx
	call	memxor
	cmp	dword [rsp+16], 0
	jne	.loop
calign
.alldone:
	add	rsp, 168
	epilog

end if



if used hmac$final | defined include_everything
	; two arguments: rdi == hmac object, rsi == ptr to 64 byte buffer for the final hmac result (note: macsize will get put in here, but 64 is big enough to cover the biggest one)
	; note: re-initializes the state in readiness for more data to arrive
falign
hmac$final:
	prolog	hmac$final
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	xor	edx, edx	; do NOT call heap$free, haha
	call	qword [rdi+hmac_macfinal_ofs]
	mov	rdi, rbx
	lea	rsi, [rbx+hmac_okey_ofs]
	mov	edx, 64
	call	qword [rbx+hmac_macupdate_ofs]
	mov	rdi, rbx
	mov	rsi, r12
	mov	edx, [rbx+hmac_macsize_ofs]
	call	qword [rbx+hmac_macupdate_ofs]
	mov	rdi, rbx
	mov	rsi, r12
	xor	edx, edx	; do NOT call heap$free, haha
	call	qword [rbx+hmac_macfinal_ofs]

if hmac_debug
	; debug
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	rdi, r12
	mov	esi, [rbx+hmac_macsize_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	pop	r12	; done with r12
	; reinit our goods
	mov	rdi, rbx
	lea	rsi, [rbx+hmac_ikey_ofs]
	mov	edx, 64
	call	qword [rbx+hmac_macupdate_ofs]
	; done
	pop	rbx
	epilog

if hmac_debug
cleartext .debugstr, 'hmac$final result:'
end if

end if


if used hmac$reset | defined include_everything
	; single argument in rdi: hmac object
	; resets the state and calls mac update for ikey in prep for more data (note: final does this automatically anyway)
falign
hmac$reset:
	prolog	hmac$reset
	push	rdi
	call	qword [rdi+hmac_macinit_ofs]
	pop	rdi
	lea	rsi, [rdi+hmac_ikey_ofs]
	mov	edx, 64
	call	qword [rdi+hmac_macupdate_ofs]
	epilog

end if
