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
	; vdso.inc: we parse /proc/self/auxv (and die if we can't)
	; to get our kernel-exposed functions we are interested in
	;

globals
{
	vdso_gettimeofday	dq	0
}

gettimeofday equ qword [vdso_gettimeofday]

	; no arguments, called by ht$init if any of our symbols are used
	; NOTE: we _could_ parse the auxv from before our env/argv lists
	; but it is fast enough to just open the buffer directly
falign
vdso$init:
	prolog	vdso$init
	push	rbx r12 r13 r14 r15
	; read it directly onto our stack
	sub	rsp, 1024
	mov	eax, syscall_open
	mov	rdi, .procselfauxv
	xor	esi, esi		; O_RDONLY
	syscall
	cmp	eax, 0
	jl	.failed
	mov	ebx, eax
	mov	edi, eax
	mov	rsi, rsp
	mov	rdx, 1024
	mov	eax, syscall_read
	syscall
	cmp	eax, 0
	jl	.failed
	mov	edi, ebx
	mov	ebx, eax
	mov	eax, syscall_close
	syscall
	shr	ebx, 4			; each entry is 8 byte type, 8 byte value
	test	ebx, ebx
	jz	.failed
	mov	r12, rsp
calign
.ehdr_search:
	cmp	qword [r12], 0x21	; AT_SYSINFO_EHDR
	je	.ehdr_found
	add	r12, 16
	sub	ebx, 1
	jnz	.ehdr_search
	jmp	.failed
calign
.ehdr_found:
	mov	rbx, [r12+8]		; base address of our VDSO
	test	rbx, rbx
	jz	.failed
	; we aren't really interested in validating it, if we got it from the kernel
	; it is most-likely a-okay
	; so all we are really after is the relocation table
	movzx	r12d, word [rbx+0x38]	; Elf64_Ehdr.e_phnum
	mov	r15, [rbx+0x20]		; Elf64_Ehdr.e_phoff
	add	r15, rbx
	test	r12d, r12d
	jz	.failed
	xor	r13d, r13d
	xor	r14d, r14d
	mov	qword [rsp+992], rbx	; save our Ehdr
	mov	qword [rsp+1008], -1	; we'll use this as link base pointer
	mov	qword [rsp+1016], 0	; we'll use this as our dynamic program header
calign
.phdr_scan:
	mov	eax, 0x38
	xor	edx, edx
	mul	r13d
	lea	rdi, [r15+rax]		; Elf64_Phdr[r13d]
	mov	ecx, [rdi]		; Elf64_Phdr.p_type
	mov	rax, [rdi+16]		; Elf64_Phdr.p_vaddr
	cmp	ecx, 1			; PT_LOAD
	je	.phdr_scan_ptload
	cmp	ecx, 2
	je	.phdr_scan_ptdynamic
calign
.phdr_scan_next:
	add	r13d, 1
	sub	r12d, 1
	jnz	.phdr_scan
	cmp	qword [rsp+1008], -1
	je	.failed
	cmp	qword [rsp+1016], 0
	je	.failed
	; so now we can get our dynamic entries out
	mov	rsi, [rsp+1008]
	mov	rdi, [rsp+1016]
	mov	rcx, rbx
	mov	rax, [rdi+16]		; Elf64_Phdr.p_vaddr

	sub	rcx, rsi		; relocation
	add	rax, rcx		; Dyn
	
	mov	r14, rcx
	mov	r15, rax
	
	xor	ebx, ebx		; our symtab
	xor	r12d, r12d		; our strtab

	mov	qword [rsp+1000], 0	; our symbol count (what will be anyway)
	; all we are really interested in here is finding the symbol table
	; and the string table (so we can do name lookups in it for what we are after)
	; well, and the DT_HASH entry so we can figure out how many symbols we have
calign
.findstrsymtab:
	; so we need r15.d_un.d_val + relocation _if_ r15.d_tag == DT_SYMTAB
	; d_tag is the first signed 64 bits of r15, d_un is our union next 64 bits
	cmp	qword [r15], 0
	je	.dyndone
	cmp	qword [r15], 4		; DT_HASH
	je	.foundhash
	cmp	qword [r15], 5		; DT_STRTAB
	je	.foundstrtab
	cmp	qword [r15], 6		; DT_SYMTAB
	je	.foundsymtab
	add	r15, 16
	jmp	.findstrsymtab
calign
.foundhash:
	mov	rcx, [r15+8]
	lea	rsi, [r14+rcx]
	mov	eax, [rsi+4]		; DT_HASH, second word
	; symbol count is in eax
	mov	dword [rsp+1000], eax
	add	r15, 16
	jmp	.findstrsymtab
calign
.foundstrtab:
	; d_un.val + our relocation goods is what we want
	mov	rcx, [r15+8]
	lea	r12, [r14+rcx]		; strtab
	add	r15, 16
	jmp	.findstrsymtab
calign
.foundsymtab:
	; d_un.val + our relocation goods is what we want
	mov	rcx, [r15+8]
	lea	rbx, [r14+rcx]		; symtab
	add	r15, 16
	jmp	.findstrsymtab
calign
.dyndone:
	test	rbx, rbx		; symtab
	jz	.failed
	test	r12, r12		; strtab
	jz	.failed
	cmp	dword [rsp+1000], 0	; count
	je	.failed
	; if we made it to here, everything looks okay, walk our symbols
calign
.symwalk:
	; strtab + [rbx] == st_name of this symbol
	mov	r13d, dword [rbx]
	add	r13, r12
	mov	rdi, r13
	call	strlen_latin1
	cmp	eax, .vdsogtodlen
	jne	.symwalk_next
	mov	rdi, r13
	mov	rsi, .vdsogtod
	mov	edx, .vdsogtodlen
	call	memcmp
	test	eax, eax
	jz	.foundit
calign
.symwalk_next:
	add	rbx, 0x18
	sub	dword [rsp+1000], 1
	jnz	.symwalk
	; if we made it to here, we didn't find what we were looking for
	jmp	.failed
calign
.foundit:
	movzx	eax, word [rbx+6]
	mov	rcx, [rbx+8]
	add	rcx, [rsp+992]	
	sub	rcx, [rsp+1008]	; the address of our symbol

	mov	[vdso_gettimeofday], rcx

	add	rsp, 1024
	pop	r15 r14 r13 r12 rbx
	epilog
dalign
.vdsogtod:
	db	'__vdso_gettimeofday'
.vdsogtodlen = $ - .vdsogtod
calign
.phdr_scan_ptload:
	; make sure it already isn't set
	cmp	qword [rsp+1008], -1
	jne	.phdr_scan_next
	mov	[rsp+1008], rax		; link base pointer == Elf64_Phdr[r13d].p_vaddr
	jmp	.phdr_scan_next
calign
.phdr_scan_ptdynamic:
	mov	[rsp+1016], rdi
	jmp	.phdr_scan_next
dalign
.procselfauxv:
	db	'/proc/self/auxv',0
calign
.failed:
	mov	rdi, .err_auxvfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_auxvfail, 'Fatal: unable to load/read/parse /proc/self/auxv'
