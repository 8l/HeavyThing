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
	; dir.inc: directory reading convenience function
	;

dir_type_ofs = 0
dir_inode_ofs = 8
dir_name_ofs = 16

dir_size = 24

	; constants from dirent.h
DT_UNKNOWN = 0
DT_FIFO = 1
DT_CHR = 2
DT_DIR = 4
DT_BLK = 6
DT_REG = 8
DT_LNK = 10
DT_SOCK = 12

if used dir$read | defined include_everything

	; single argument in rdi: string pathname of directory to read
	; returns null on error, or a list of dir structures
falign
dir$read:
	prolog	dir$read
	push	rbx r12 r13 r14 r15
	xor	ebx, ebx
	sub	rsp, 16384
	mov	rsi, rsp
	call	string$to_utf8
	mov	byte [rsp+rax], 0	; add null terminator for our call to open
	mov	eax, syscall_open
	mov	rdi, rsp
	mov	esi, 0x10000		; O_RDONLY | O_DIRECTORY
	syscall
	cmp	rax, 0
	jle	.return
	mov	r12, rax
	call	list$new
	mov	rbx, rax
calign
.readdir:
	mov	eax, syscall_getdents
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, 16384
	syscall
	cmp	eax, -1
	je	.error
	test	eax, eax
	jz	.dirdone
	xor	r13d, r13d
	mov	r14d, eax
calign
.dirloop:
	mov	edi, dir_size
	call	heap$alloc
	mov	r15, rax
	mov	rdi, rbx
	mov	rsi, rax
	call	list$push_back

	mov	rcx, [rsp+r13]
	movzx	edx, word [rsp+r13+16]
	add	rdx, r13
	sub	rdx, 1
	movzx	eax, byte [rsp+rdx]
	mov	[r15+dir_type_ofs], rax
	mov	[r15+dir_inode_ofs], rcx

	push	rdx
	lea	rdi, [rsp+r13+26]
	call	strlen_latin1
	lea	rdi, [rsp+r13+26]
	mov	rsi, rax
	call	string$from_utf8
	mov	[r15+dir_name_ofs], rax
	pop	r13
	add	r13, 1
	cmp	r13, r14
	jb	.dirloop
	jmp	.readdir
calign
.dirdone:
	mov	eax, syscall_close
	mov	rdi, r12
	syscall
calign
.return:
	mov	rax, rbx
	add	rsp, 16384
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.error:
	mov	rdi, rbx
	call	dir$free
	mov	eax, syscall_close
	mov	rdi, r12
	syscall
	jmp	.return

end if


if used dir$free | defined include_everything
	; single argument in rdi: list as returned from dir$read
falign
dir$free:
	prolog	dir$free
	push	rdi
	mov	rsi, .each
	call	list$clear
	pop	rdi
	call	heap$free
	epilog
falign
.each:
	push	rdi
	mov	rdi, [rdi+dir_name_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	ret

end if
