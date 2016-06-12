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
	; mapped.inc: mmap "object" helper goods
	;

mapped_base_ofs = 0
mapped_size_ofs = 8
mapped_fd_ofs = 16

mapped_size = 24

if used mapped$new_anon | defined include_everything
	; single argument in rdi == initial size
	; returns new mapped object in rax, or null if it fails
falign
mapped$new_anon:
	prolog	mapped$new_anon
	push	rdi
	mov	edi, mapped_size
	call	heap$alloc
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	mapped$init_anon
	pop	rax
	cmp	qword [rax+mapped_base_ofs], -1
	je	.kakked
	epilog
calign
.kakked:
	mov	rdi, rax
	call	heap$free
	xor	eax, eax
	epilog
end if


if used mapped$new_cstr | defined include_everything
	; two arguments: rdi == initial size (only if we create it new), rsi == null terminated latin1 filename
	; returns new mapped object in rax, or null if it fails
falign
mapped$new_cstr:
	prolog	mapped$new_cstr
	push	rsi rdi
	mov	edi, mapped_size
	call	heap$alloc
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	mov	[rsp], rax
	mov	rdi, rax
	call	mapped$init_cstr
	mov	rax, [rsp]
	add	rsp, 16
	cmp	qword [rax+mapped_fd_ofs], 0
	jl	.kakked
	epilog
calign
.kakked:
	mov	rdi, rax
	call	heap$free
	xor	eax, eax
	epilog

end if

if used mapped$new | defined include_everything
	; two arguments: rdi == initial size (only if we create it new), rsi == string filename
	; returns new mapped object in rax, or null if it fails
falign
mapped$new:
	prolog	mapped$new
	push	rsi rdi
	mov	edi, mapped_size
	call	heap$alloc
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	mov	[rsp], rax
	mov	rdi, rax
	call	mapped$init
	mov	rax, [rsp]
	add	rsp, 16
	cmp	qword [rax+mapped_fd_ofs], 0
	jl	.kakked
	epilog
calign
.kakked:
	mov	rdi, rax
	call	heap$free
	xor	eax, eax
	epilog

end if


if used mapped$init_anon | defined include_everything
	; if you don't want to have a separate 24 byte heap allocation done, the $init* functions
	; accept an address to initialize our 3 state variables

	; two arguments: rdi == mapped object, rsi == initial size
	; [mapped_base_ofs] will be -1 on failure
falign
mapped$init_anon:
	prolog	mapped$init_anon
	push	rdi
	mov	qword [rdi+mapped_base_ofs], -1
	mov	[rdi+mapped_size_ofs], rsi
	mov	qword [rdi+mapped_fd_ofs], -1
	mov	eax, syscall_mmap
	xor	edi, edi
	; rsi as our size is valid
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	pop	rdi
	mov	[rdi+mapped_base_ofs], rax
	epilog
end if

if used mapped$init_cstr | defined include_everything
	; three arguments: rdi == mapped object, rsi == initial size, rdx == null terminated latin1 filename
	; [mapped_fd_ofs] will be <0 on failure
falign
mapped$init_cstr:
	prolog	mapped$init_cstr
	push	rdi
	mov	qword [rdi+mapped_base_ofs], -1
	mov	[rdi+mapped_size_ofs], rsi	; save initial size temporarily
	mov	qword [rdi+mapped_fd_ofs], -1
	; attempt to open our file
	mov	eax, syscall_open
	mov	rdi, rdx
	mov	esi, 0x42			; O_RDWR|O_CREAT
	mov	edx, 0x180			; 0600 mode
	syscall
	cmp	eax, 0
	jl	.openfailed
	mov	rcx, [rsp]
	mov	[rcx+mapped_fd_ofs], rax	; save our fd
	mov	rdi, rax			; fd
	xor	esi, esi			; offset
	mov	edx, 2				; SEEK_END
	mov	eax, syscall_lseek
	syscall
	mov	rcx, [rsp]
	cmp	rax, -1
	je	.failed
	test	rax, rax
	jnz	.sizeokay
	mov	rdi, [rcx+mapped_fd_ofs]	; fd
	mov	rsi, [rcx+mapped_size_ofs]	; size
	mov	eax, syscall_ftruncate
	syscall
	mov	rcx, [rsp]
	mov	rax, [rcx+mapped_size_ofs]
calign
.sizeokay:
	; rax is the size of the file, rcx is our mapped object
	mov	[rcx+mapped_size_ofs], rax
	; mmap is next
	xor	edi, edi			; addr
	mov	rsi, rax			; length
	mov	edx, 0x3			; PROT_READ|PROT_WRITE	prot
	mov	r10d, 0x1			; MAP_SHARED	flags
	mov	r8, [rcx+mapped_fd_ofs]		; fd	fd
	xor	r9d, r9d			; offset
	mov	eax, syscall_mmap
	syscall
	mov	rcx, [rsp]
	mov	[rcx+mapped_base_ofs], rax
	cmp	rax, -1
	je	.failed
	pop	rdi
	epilog
calign
.failed:
	; rcx == our mapped object... close our fd, reset its value to -1 and bail
	mov	rdi, [rcx+mapped_fd_ofs]
	mov	qword [rcx+mapped_fd_ofs], -1
	mov	eax, syscall_close
	syscall
	pop	rdi
	epilog
calign
.openfailed:
	pop	rdi
	epilog
end if

if used mapped$init | defined include_everything
	; three arguments: rdi == mapped object, rsi == initial size, rdx == string filename
	; [mapped_fd_ofs] will be <0 on failure
falign
mapped$init:
	prolog	mapped$init
	mov	qword [rdi+mapped_base_ofs], -1
	mov	[rdi+mapped_size_ofs], rsi	; save initial size temporarily
	mov	qword [rdi+mapped_fd_ofs], -1
	sub	rsp, 256
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	rdi, rdx
	call	string$utf8_length
	test	rax, rax
	jz	.badstring
	cmp	rax, 240
	ja	.badstring
	mov	rsi, rsp
	add	rsi, 16
	mov	byte [rsi+rax], 0		; null terminator in advance
	mov	rdi, [rsp+8]
	call	string$to_utf8
	mov	rdi, [rsp]
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdx, rsp
	add	rdx, 16
	call	mapped$init_cstr
	add	rsp, 256
	epilog
.badstring:
	add	rsp, 256
	epilog

end if


if used mapped$cleanup | defined include_everything
	; single argument in rdi == mapped object
	; munmap, close the fd (if any)
falign
mapped$cleanup:
	prolog	mapped$cleanup
	push	rdi
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdi, [rdi+mapped_base_ofs]
	mov	eax, syscall_munmap
	syscall
	pop	rsi
	mov	rdi, [rsi+mapped_fd_ofs]
	cmp	rdi, -1
	je	.nofile
	mov	eax, syscall_close
	syscall
	epilog
calign
.nofile:
	epilog
end if


if used mapped$destroy | defined include_everything
	; single argument in rdi == mapped object, we'll munmap, close the fd (if any), and heap$free it
falign
mapped$destroy:
	prolog	mapped$destroy
	push	rdi
	call	mapped$cleanup
	pop	rdi
	call	heap$free
	epilog
end if

if used mapped$syncpart | defined include_everything
 	; four arguments: rdi == mapped object, rsi == offset, rdx == length, ecx == bool for whether to do it async or not
falign
mapped$syncpart:
	prolog	mapped$syncpart
	; address passed to msync must be page_size aligned, and we should also make sure the length is too
	mov	r10, rsi
	and	r10, page_size - 1
	sub	rsi, r10
	add	rdx, r10
	; now align length to the nearest page_size
	add	rdx, page_size - 1
	and	rdx, not (page_size - 1)
	mov	rdi, [rdi+mapped_base_ofs]
	add	rdi, rsi
	mov	rsi, rdx
	mov	r8d, 1				; MS_ASYNC
	mov	r9d, 4				; MS_SYNC
	test	ecx, ecx
	cmovz	edx, r9d
	cmovnz	edx, r8d
	mov	eax, syscall_msync
	syscall
	epilog
end if


if used mapped$sync | defined include_everything
	; two arguments: rdi == mapped object, esi == bool for whether to do it async or not
falign
mapped$sync:
	prolog	mapped$sync
	mov	eax, syscall_msync
	mov	r8d, 1				; MS_ASYNC
	mov	r9d, 4				; MS_SYNC
	test	esi, esi
	cmovz	edx, r9d
	cmovnz	edx, r8d
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdi, [rdi+mapped_base_ofs]
	syscall
	epilog
end if

if used mapped$grow | defined include_everything
	; two arguments: rdi == mapped object, rsi == AMOUNT to grow by
	; returns the start of the region we just grew in rax, or null if mremap failed
falign
mapped$grow:
	prolog	mapped$grow
	mov	rdx, [rdi+mapped_size_ofs]
	push	rdx rdi		; save our return and our mapped object
	add	rdx, rsi
	mov	rsi, [rdi+mapped_size_ofs]
	mov	[rdi+mapped_size_ofs], rdx	; new size
	mov	rdi, [rdi+mapped_base_ofs]
	mov	eax, syscall_mremap
	mov	r10d, 1		; MREMAP_MAYMOVE
	syscall
	mov	rdi, [rsp]
	mov	[rdi+mapped_base_ofs], rax
	cmp	qword [rdi+mapped_fd_ofs], -1
	je	.nofile
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdi, [rdi+mapped_fd_ofs]
	mov	eax, syscall_ftruncate
	syscall
.nofile:
	mov	rdi, [rsp]
	cmp	qword [rdi+mapped_base_ofs], -1
	je	.nullret
	mov	rax, [rsp+8]
	add	rax, qword [rdi+mapped_base_ofs]
	add	rsp, 16
	epilog
calign
.nullret:
	xor	eax, eax
	add	rsp, 16
	epilog
end if

if used mapped$growto | defined include_everything
	; two arguments: rdi == mapped object, rsi == new size to grow TO
	; returns the start of the region we just grew in rax, or null if mremap failed
	; NOTE: use the shrink functions instead if you want to shrink it
falign
mapped$growto:
	prolog	mapped$growto
	mov	rdx, [rdi+mapped_size_ofs]
	push	rdx rdi
	mov	[rdi+mapped_size_ofs], rsi	; new size
	xchg	rdx, rsi
	mov	rdi, [rdi+mapped_base_ofs]
	mov	eax, syscall_mremap
	mov	r10d, 1		; MREMAP_MAYMOVE
	syscall
	mov	rdi, [rsp]
	mov	[rdi+mapped_base_ofs], rax
	cmp	qword [rdi+mapped_fd_ofs], -1
	je	.nofile
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdi, [rdi+mapped_fd_ofs]
	mov	eax, syscall_ftruncate
	syscall
.nofile:
	mov	rdi, [rsp]
	cmp	qword [rdi+mapped_base_ofs], -1
	je	.nullret
	mov	rax, [rsp+8]
	add	rax, qword [rdi+mapped_base_ofs]
	add	rsp, 16
	epilog
calign
.nullret:
	xor	eax, eax
	add	rsp, 16
	epilog
end if


if used mapped$shrink | defined include_everything
	; two arguments: rdi == mapped object, rsi == AMOUNT to shrink by
falign
mapped$shrink:
	prolog	mapped$shrink
	mov	rdx, [rdi+mapped_size_ofs]
	push	rdi		; save our mapped object
	sub	rdx, rsi
	mov	rsi, [rdi+mapped_size_ofs]
	mov	[rdi+mapped_size_ofs], rdx	; new size
	mov	rdi, [rdi+mapped_base_ofs]
	mov	eax, syscall_mremap
	mov	r10d, 1		; MREMAP_MAYMOVE
	syscall
	mov	rdi, [rsp]
	mov	[rdi+mapped_base_ofs], rax
	cmp	qword [rdi+mapped_fd_ofs], -1
	je	.nofile
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdi, [rdi+mapped_fd_ofs]
	mov	eax, syscall_ftruncate
	syscall
.nofile:
	pop	rdi
	epilog
end if

if used mapped$shrinkto | defined include_everything
	; two arguments: rdi == mapped object, rsi == new size to shrink TO
falign
mapped$shrinkto:
	prolog	mapped$shrinkto
	mov	rdx, [rdi+mapped_size_ofs]
	push	rdi
	mov	[rdi+mapped_size_ofs], rsi	; new size
	xchg	rdx, rsi
	mov	rdi, [rdi+mapped_base_ofs]
	mov	eax, syscall_mremap
	mov	r10d, 1		; MREMAP_MAYMOVE
	syscall
	mov	rdi, [rsp]
	mov	[rdi+mapped_base_ofs], rax
	cmp	qword [rdi+mapped_fd_ofs], -1
	je	.nofile
	mov	rsi, [rdi+mapped_size_ofs]
	mov	rdi, [rdi+mapped_fd_ofs]
	mov	eax, syscall_ftruncate
	syscall
.nofile:
	pop	rdi
	epilog
end if
