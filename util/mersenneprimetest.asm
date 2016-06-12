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
	; NOTE: using modified ht_defaults.inc for a dramatic increase in bigint_maxwords:
	include 'bigger_int_settings.inc'
	include '../ht.inc'


	; this is a silly (but useful for diagnostics/profiling of bigint) mersenne prime tester
	; if you feed it a mersenne p on the command like (say, 110503) then it will do
	; 2^110503-1 and then call isprime on said number. (remember to increase maxwords if you
	; want to play around with bigger ones still)


public _start
falign
_start:
	call	ht$init

	cmp	qword [argc], 1
	jbe	.usage

	mov	rdi, [argv]
	call	list$pop_back
	mov	rbx, rax
	mov	rdi, rax
	call	string$isnumber
	test	eax, eax
	jz	.usage
	mov	rdi, rbx
	call	string$to_unsigned
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
	test	rbx, rbx
	jz	.usage
	cmp	rbx, 1024
	jb	.toosmall

	; see if an iteration count argument was passed (-XX)
	mov	rdi, [argv]
	call	list$pop_back
	test	rax, rax
	jz	.noiterarg
	mov	r12, rax
	mov	rdi, rax
	mov	esi, '-'
	call	string$indexof_charcode
	cmp	rax, 0
	jne	.noiterarg
	mov	rdi, r12
	mov	esi, 1
	mov	rdx, -1
	call	string$substr
	mov	r13, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	string$isnumber
	test	eax, eax
	jz	.usage
	mov	rdi, r13
	call	string$to_unsigned
	mov	r12, rax
	test	rax, rax
	jz	.usage
	jmp	.doit
calign
.noiterarg:
	mov	r12d, 1
calign
.doit:
	; so we are doing r12d iterations of ebx bit size
	mov	edi, ebx
	call	bigint$new_pow2
	mov	r13, rax
	mov	rdi, rax
	mov	rsi, bigint$one
	call	bigint$subtract

	mov	rdi, r13
	call	bigint$debug

	mov	rdi, r13
	call	bigint$modsmallprimes
	mov	rdx, .isprime
	mov	rcx, .notprime
	test	eax, eax
	cmovnz	rdi, rcx
	cmovz	rdi, rdx
	jnz	.nup

	mov	rdi, r13
	call	bigint$isprime2
	mov	rdx, .isprime
	mov	rcx, .notprime
	test	eax, eax
	cmovz	rdi, rcx
	cmovnz	rdi, rdx
calign
.nup:
	call	string$to_stdoutln

	mov	rdi, r13
	call	bigint$destroy

	sub	r12d, 1
	jnz	.doit

	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .isprime, 'random one we picked was prime'
cleartext .notprime, 'random one we picked was NOT prime'
falign
.usage:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .usagestr
	mov	edx, .usagestrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.usagestr db 'Usage: ./hmmm [-XX] SIZE',10,'Where SIZE is size in bits of number we are testing, XX specifies how many iterations to run (default 1)',10
.usagestrlen = $ - .usagestr
falign
.toosmall:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .smallstr
	mov	edx, .smallstrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.smallstr db 'You have requested a too small to really be useful. If you REALLY want that, edit bigint_tune.asm and lower the limit.',10
.smallstrlen = $ - .smallstr
	include '../ht_data.inc'
