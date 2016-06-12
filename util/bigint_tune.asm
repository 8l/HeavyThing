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
	; bigint_unrollsize is a tricky parameter to get right, there is a crossover point
	; that is architecture-dependent where increasing its size (and thus the codebase
	; of bigint itself) lowers performance rather than increases it due to the lower
	; number of recursive calls to square/mullower/mulupper/etc
	;
	; so, all this does is create a random odd number of command-line argument size in
	; bits, and then do precisely 1 isprime2 operation on it
	; 
	; the number of modular exponentiations is thus deterministic, and will conclusively
	; show which setting is actually best
	;

	include '../ht_defaults.inc'
	include '../ht.inc'

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
	call	bigint$new_random
	mov	r13, rax
	mov	rdi, rax
	mov	esi, 0
	call	bigint$bitset
	mov	rdi, r13
	mov	esi, ebx
	sub	esi, 1
	call	bigint$bitset
	mov	rdi, r13
	mov	esi, ebx
	sub	esi, 2
	call	bigint$bitset

	mov	rdi, r13
	call	primesieve$new

	mov	r14, rax
	mov	rdi, rax
	mov	rsi, r13
	call	primesieve$next

	mov	rdi, r13
	call	bigint$isprime2
	mov	rdx, .isprime
	mov	rcx, .notprime
	test	eax, eax
	cmovz	rdi, rcx
	cmovnz	rdi, rdx
	call	string$to_stdoutln

	mov	rdi, r13
	call	bigint$destroy

	mov	rdi, r14
	call	primesieve$destroy

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
.usagestr db 'Usage: ./bigint_tune [-XX] SIZE',10,'Where SIZE is size in bits of number we are testing, XX specifies how many iterations to run (default 1)',10
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
