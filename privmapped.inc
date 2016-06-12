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
	; privmapped.inc: mmap "object" helper goods
	;
	; similar to privmapped, only the underlying mmap is not created
	; with MAP_SHARED, and instead is done with PROT_READ & MAP_PRIVATE
	; and we hangon to the cstring representation of the file, as well
	; as populate its mtime. We don't do MAP_POPULATE, because in most
	; cases, privmapped$new should not block while the whole thing loads.
	;
	; NOTE: if privmapped_noatime is enabled in settings, this will
	; require 2.6.8+ kernel, but if you are running as NOBODY, O_NOATIME
	; does weird things and returns EPERM when you try and open something
	; with it, so it is disabled by default.
	;

privmapped_debug = 0

privmapped_base_ofs = 0
privmapped_size_ofs = 8
privmapped_fd_ofs = 16
privmapped_mtime_ofs = 24
privmapped_filename_ofs = 32	; a string$copy of what is passed to privmapped$new
privmapped_fname_ofs = 40	; a heap$alloc'd copy of the null terminated filename
privmapped_etag_ofs = 48	; a string$ etag base64(SHA224(filename+mtime)[0..26])
privmapped_pincount_ofs = 56	; not used in here but initialised to 0
privmapped_zbuf_ofs = 64	; optional buffer$new object, set by calling privmapped$deflate, gets cleaned up

if used webservercfg$new_vhost | used webservercfg$new_sandbox | used webservercfg$host_sandbox | used webservercfg$set_vhost | defined include_everything

privmapped_mtimestr_ofs = 72
privmapped_user_ofs = 80	; not used in here, init'd to zero

privmapped_size = 88

else

privmapped_user_ofs = 72	; not used in here, init'd to zero
privmapped_size = 80

end if


if used privmapped$new | defined include_everything
	; two arguments: rdi == string filename, bool in esi as to whether we should generate a static etag or not
	; returns new privmapped object in rax, or null if it fails
falign
privmapped$new:
	prolog	privmapped$new
	push	rbx r12 r13
	mov	r13d, esi
	call	string$copy
	mov	r12, rax
	mov	edi, privmapped_size
	call	heap$alloc_clear
	mov	rbx, rax
	mov	[rax+privmapped_filename_ofs], r12
	mov	rdi, r12
	call	string$utf8_length
	add	rax, 1
	mov	rdi, rax
	call	heap$alloc_clear
	mov	[rbx+privmapped_fname_ofs], rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$to_utf8
	mov	qword [rbx+privmapped_base_ofs], -1
	mov	qword [rbx+privmapped_fd_ofs], -1
	; attempt to open our file
	mov	eax, syscall_open	
	mov	rdi, [rbx+privmapped_fname_ofs]
if privmapped_noatime
	mov	esi, 0x40000		; O_RDONLY | O_NOATIME, linux kernel >=2.6.8 (see above commentary)
else
	xor	esi, esi		; linux kernel <2.6.8
end if
	; mode is ignored for RDONLY opens, but we'll set it to 0600 anyway
	mov	edx, 0x180		; 0600 mode
	syscall
	cmp	eax, 0
	jl	.openfailed
	mov	[rbx+privmapped_fd_ofs], rax	; save our fd
	; stat the file to get its size and mtime (since we have to stat it anyway, no need to lseek)
	sub	rsp, 0x90			; sizeof(struct stat)
	mov	rsi, rsp
	mov	rdi, [rbx+privmapped_fname_ofs]
	mov	eax, syscall_stat
	syscall
	test	eax, eax
	jnz	.statfailed
	test    dword [rsp+0x18], 0x4000        ; st_mode & S_IFDIR?
	jnz	.statfailed
	cmp	qword [rsp+0x30], 0
	je	.statfailed
	mov	rax, [rsp+0x30]			; st_size
	mov	rcx, [rsp+0x58]			; st_mtime
	mov	[rbx+privmapped_size_ofs], rax
	mov	[rbx+privmapped_mtime_ofs], rcx

if used webservercfg$new_vhost | used webservercfg$new_sandbox | used webservercfg$host_sandbox | used webservercfg$set_vhost | defined include_everything
	mov	rdi, rcx
	xor	esi, esi
	call	ctime$to_jd
	mov	rdi, [webserver$dateformat]
	call	formatter$doit
	mov	[rbx+privmapped_mtimestr_ofs], rax
end if
	add	rsp, 0x90
	; proceed with our mmap
	; mmap is next
	xor	edi, edi			; addr
	mov	rsi, [rbx+privmapped_size_ofs]	; length
	mov	edx, 0x1			; PROT_READ	prot
	mov	r10d, 0x2			; MAP_PRIVATE	flags
	mov	r8, [rbx+privmapped_fd_ofs]	; fd
	xor	r9d, r9d			; offset
	mov	eax, syscall_mmap
	syscall
	mov	[rbx+privmapped_base_ofs], rax
	cmp	rax, -1
	je	.mmapfailed
	test	r13d, r13d
	jz	.noetag
	; generate an etag for this resource based on filename and mtime
	sub	rsp, sha224_state_size + 32
	mov	rdi, rsp
	call	sha224$init
	mov	rax, [rbx+privmapped_mtime_ofs]
	mov	rdi, rsp
	mov	[rsp+sha224_state_size], rax
	lea	rsi, [rsp+sha224_state_size]
	mov	edx, 8
	call	sha224$update
	mov	rax, [rbx+privmapped_filename_ofs]
	mov	rdx, [rax]
	mov	rdi, rsp
	lea	rsi, [rax+8]
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	sha224$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha224_state_size]
	xor	edx, edx			; don't attempt to free the sha224 state
	call	sha224$final
	lea	rdi, [rsp+sha224_state_size]
	mov	esi, 27				; TRUNCATED SHA224 by one byte
	xor	edx, edx
	call	string$from_bintobase64
	add	rsp, sha224_state_size + 32
if base64_linebreaks
	; CRLFs were added that we need to remove
	mov	r12, rax
	mov	rdi, rax
	mov	esi, 13
	call	string$indexof_charcode
	mov	rdi, r12
	xor	esi, esi
	mov	rdx, rax
	call	string$substr
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rax, r12
end if
	; that needs to be quoted
	mov	r12, rax
	mov	rdi, .quote
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .quote
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	[rbx+privmapped_etag_ofs], r12

	mov	rax, rbx
	pop	r13 r12 rbx
	epilog

calign
.noetag:
	call	string$new
	mov	[rbx+privmapped_etag_ofs], rax
	mov	rax, rbx
	pop	r13 r12 rbx
	epilog
cleartext .quote, '"'
if privmapped_debug
cleartext .err_statfailed, 'statfailed'
cleartext .err_mmapfailed, 'mmapfailed'
cleartext .err_openfailed, 'openfailed'
end if
calign
.statfailed:
	
if privmapped_debug
	mov	rdi, .err_statfailed
	call	string$to_stdoutln
end if

	add	rsp, 0x90
.mmapfailed:
if privmapped_debug
	mov	rdi, .err_mmapfailed
	call	string$to_stdoutln
end if
	; our file is open
	mov	eax, syscall_close
	mov	rdi, [rbx+privmapped_fd_ofs]
	syscall
	; fallthrough to openfailed
calign
.openfailed:
if privmapped_debug
	mov	rdi, .err_openfailed
	call	string$to_stdoutln
end if
	mov	rdi, [rbx+privmapped_fname_ofs]
	call	heap$free
	mov	rdi, [rbx+privmapped_filename_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	xor	eax, eax
	pop	r13 r12 rbx
	epilog

end if

if used privmapped$destroy | defined include_everything
	; single argument in rdi == privmapped object to destroy
falign
privmapped$destroy:
	prolog	privmapped$destroy
	push	rbx
	mov	rbx, rdi
	mov	eax, syscall_munmap
	mov	rsi, [rdi+privmapped_size_ofs]
	mov	rdi, [rdi+privmapped_base_ofs]
	syscall
	mov	eax, syscall_close
	mov	rdi, [rbx+privmapped_fd_ofs]
	syscall
	mov	rdi, [rbx+privmapped_fname_ofs]
	call	heap$free
	mov	rdi, [rbx+privmapped_filename_ofs]
	call	heap$free
	mov	rdi, [rbx+privmapped_etag_ofs]
	call	heap$free
if used webservercfg$new_vhost | used webservercfg$new_sandbox | used webservercfg$host_sandbox | used webservercfg$set_vhost | defined include_everything
	mov	rdi, [rbx+privmapped_mtimestr_ofs]
	call	heap$free
end if
	mov	rdi, [rbx+privmapped_zbuf_ofs]
	test	rdi, rdi
	jnz	.with_zbuf
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
calign
.with_zbuf:
	call	buffer$destroy
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog

end if


if used privmapped$deflate | defined include_everything
	; single argument in rdi: a privmapped object to deflate (assumes the map is valid, and that zbuf is null)
falign
privmapped$deflate:
	prolog	privmapped$deflate
	push	rbx
	mov	rbx, rdi
	call	buffer$new
	mov	[rbx+privmapped_zbuf_ofs], rax
	mov	rdx, [rbx+privmapped_base_ofs]
	mov	rcx, [rbx+privmapped_size_ofs]
	mov	rbx, rax
	lea	r8, [rdx+rcx]
	sub	rsp, buffer_object_size + zlib_stream_size
	mov	[rsp], r8		; buffer_endptr_ofs
	mov	[rsp+8], rcx		; buffer_length_ofs
	mov	[rsp+16], rdx		; buffer_itself_ofs
	mov	[rsp+24], rcx		; buffer_size_ofs
	lea	rdi, [rsp+buffer_object_size]
	mov	esi, 2
	call	zlib$deflateInit
	lea	rdi, [rsp+buffer_object_size]
	mov	esi, zlib_finish
	mov	[rdi+zlib_inbuf_ofs], rsp
	mov	[rdi+zlib_outbuf_ofs], rbx
	call	zlib$deflate
	lea	rdi, [rsp+buffer_object_size]
	call	zlib$deflateEnd
	add	rsp, buffer_object_size + zlib_stream_size
	pop	rbx
	epilog
	
end if
