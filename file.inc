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
	; file.inc: file wrapper/helper functions
	; mainly here for convenience/lazy programmer, haha
	; syscalls to deal with file operations aren't rocket science
	;

if used file$mtime_cstr | defined include_everything
	; single argument: null terminated latin1 in rdi
	; returns st_mtime
falign
file$mtime_cstr:
	prolog	file$mtime_cstr
	sub	rsp, 0x90		; sizeof(struct stat)
	mov	rsi, rsp
	mov	eax, syscall_stat
	syscall
	test	eax, eax
	jnz	.zeroret
	mov	rax, [rsp+0x58]		; return st_mtime
	add	rsp, 0x90
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if


if used file$size_cstr | defined include_everything
	; single argument: null terminated latin1 in rdi
	; returns st_size from stat call
falign
file$size_cstr:
	prolog	file$size_cstr
	sub	rsp, 0x90
	mov	rsi, rsp
	mov	eax, syscall_stat
	syscall
	test	eax, eax
	jnz	.zeroret
	mov	rax, [rsp+0x30]
	add	rsp, 0x90
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if

if used file$mtime | defined include_everything

	; single argument in rdi: filename string
	; returns st_mtime
falign
file$mtime:
	prolog	file$mtime
	push	rbx
	mov	rbx, rdi
	call	string$utf8_length
	mov	rdi, rbx
	mov	rbx, rax
	add	rbx, 16
	and	rbx, not 15
	sub	rsp, rbx
	mov	rsi, rsp
	mov	byte [rsp+rax], 0
	call	string$to_utf8
	mov	rdi, rsp
	call	file$mtime_cstr
	add	rsp, rbx
	pop	rbx
	epilog

end if

if used file$size | defined include_everything
	; single argument: rdi: filename string
	; returns st_size
falign
file$size:
	prolog	file$size
	push	rbx
	mov	rbx, rdi
	call	string$utf8_length
	mov	rdi, rbx
	mov	rbx, rax
	add	rbx, 16
	and	rbx, not 15
	sub	rsp, rbx
	mov	rsi, rsp
	mov	byte [rsp+rax], 0
	call	string$to_utf8
	mov	rdi, rsp
	call	file$size_cstr
	add	rsp, rbx
	pop	rbx
	epilog
end if


if used file$proc_cstr | defined include_everything
	; single argument in rdi: null terminated latin1 in rdi of /proc/whatever filename
	; this differs from to_string_cstr insofar as the size of the file (usually 0) is ignored
	; and we attempt the read anyway
falign
file$proc_cstr:
	prolog	file$proc_cstr
	sub	rsp, 40
	mov	[rsp], rdi
	mov	rdi, 131072
	call	heap$alloc
	mov	qword [rsp+8], 0
	mov	[rsp+16], rax	; heap bufptr
	mov	[rsp+32], rax	; current bufptr
	mov	rdi, [rsp]
	xor	esi, esi	; O_RDONLY
	; mode doesn't matter for O_RDONLY
	mov	eax, syscall_open
	syscall
	cmp	eax, 0
	jl	.emptystring_free
	mov	[rsp+24], rax	; fd

	; /proc/whatevers don't give us our entire read request at once, which seems weird
calign
.readloop:
	mov	rdi, [rsp+24]
	mov	rsi, [rsp+32]
	mov	rdx, 131072	; note: will overrun if we try and read more than 128k in total
	mov	eax, syscall_read
	syscall
	cmp	rax, 0
	jle	.do_return
	; otherwise, increment both our counts
	add	qword [rsp+8], rax
	add	qword [rsp+32], rax
	jmp	.readloop
calign
.do_return:
	mov	rdi, [rsp+24]	; fd
	mov	eax, syscall_close
	syscall
	mov	rdi, [rsp+16]	; buffer
	mov	rsi, [rsp+8]	; bytes
	call	string$from_utf8
	mov	[rsp], rax ; save our return
	mov	rdi, [rsp+16]
	call	heap$free
	mov	rax, [rsp]
	add	rsp, 40
	epilog
calign
.emptystring_free:
	mov	rdi, [rsp+16]
	call	heap$free
	call	string$new
	add	rsp, 40
	epilog
calign
.emptystring:
	call	string$new
	add	rsp, 40
	epilog

end if


if used file$to_string_cstr | defined include_everything
	; single argument in rdi: null terminated latin1 in rdi of filename
	; returns file contents as a string, assumes file contains UTF8
falign
file$to_string_cstr:
	prolog	file$to_string_cstr
	sub	rsp, 32
	mov	[rsp], rdi
	call	file$size_cstr
	test	rax, rax
	jz	.emptystring
	mov	rdi, rax
	mov	[rsp+8], rax
	call	heap$alloc
	mov	[rsp+16], rax
	mov	rdi, [rsp]
	xor	esi, esi	; O_RDONLY
	; mode doesn't matter for O_RDONLY
	mov	eax, syscall_open
	syscall
	cmp	eax, 0
	jl	.emptystring_free
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	rsi, [rsp+16]
	mov	rdx, [rsp+8]
	mov	eax, syscall_read
	syscall
	cmp	rax, 0
	jl	.emptystring_free
	mov	[rsp+8], rax
	mov	rdi, [rsp+24]	; fd
	mov	eax, syscall_close
	syscall
	mov	rdi, [rsp+16]	; buffer
	mov	rsi, [rsp+8]	; bytes
	call	string$from_utf8
	mov	[rsp], rax ; save our return
	mov	rdi, [rsp+16]
	call	heap$free
	mov	rax, [rsp]
	add	rsp, 32
	epilog
calign
.emptystring_free:
	mov	rdi, [rsp+16]
	call	heap$free
	call	string$new
	add	rsp, 32
	epilog
calign
.emptystring:
	call	string$new
	add	rsp, 32
	epilog
end if

if used file$to_buffer_cstr | defined include_everything
	; single argument in rdi: null terminated latin1 in rdi of filename
	; returns file contents in a buffer$new (or null if error)
falign
file$to_buffer_cstr:
	prolog	file$to_buffer_cstr
	sub	rsp, 32
	mov	[rsp], rdi
	call	file$size_cstr
	test	rax, rax
	jz	.empty
	mov	[rsp+8], rax	; size
	call	buffer$new
	mov	[rsp+16], rax
	mov	rdi, rax
	mov	rsi, [rsp+8]
	call	buffer$reserve
	
	mov	rdi, [rsp]
	xor	esi, esi	; O_RDONLY
	; mode doesn't matter for O_RDONLY
	mov	eax, syscall_open
	syscall
	cmp	eax, 0
	jl	.empty_free
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	rsi, [rsp+16]
	mov	rsi, [rsi+buffer_endptr_ofs]
	mov	rdx, [rsp+8]
	mov	eax, syscall_read
	syscall
	cmp	rax, 0
	jl	.empty_free
	mov	[rsp+8], rax
	mov	rdi, [rsp+24]	; fd
	mov	eax, syscall_close
	syscall
	mov	rdi, [rsp+16]
	mov	rsi, [rsp+8]	; size
	call	buffer$append_nocopy

	mov	rax, [rsp+16]	; buffer
	add	rsp, 32
	epilog
calign
.empty_free:
	mov	rdi, [rsp+16]
	call	buffer$destroy
	xor	eax, eax
	add	rsp, 32
	epilog
calign
.empty:
	xor	eax, eax
	add	rsp, 32
	epilog
end if


if used file$to_string | defined include_everything
	; single argument: rdi: filename string
	; returns file contents as a string, assumes file contains UTF8
falign
file$to_string:
	prolog	file$to_string
	push	rbx
	mov	rbx, rdi
	call	string$utf8_length
	mov	rdi, rbx
	mov	rbx, rax
	add	rbx, 16
	and	rbx, not 15
	sub	rsp, rbx
	mov	rsi, rsp
	mov	byte [rsp+rax], 0
	call	string$to_utf8
	mov	rdi, rsp
	call	file$to_string_cstr
	add	rsp, rbx
	pop	rbx
	epilog


end if

if used file$to_buffer | defined include_everything
	; single argument: rdi: filename string
	; returns buffer contents, or null on error
falign
file$to_buffer:
	prolog	file$to_buffer
	push	rbx
	mov	rbx, rdi
	call	string$utf8_length
	mov	rdi, rbx
	mov	rbx, rax
	add	rbx, 16
	and	rbx, not 15
	sub	rsp, rbx
	mov	rsi, rsp
	mov	byte [rsp+rax], 0
	call	string$to_utf8
	mov	rdi, rsp
	call	file$to_buffer_cstr
	add	rsp, rbx
	pop	rbx
	epilog
	
end if
