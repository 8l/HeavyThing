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
	; make_dh_static.asm: DH public p/g is very expensive to create, and given sufficiently
	; large safe primes p, there is no real benefit to changing them out on the fly. OpenSSL
	; and the rest use fixed DH parameters, and we provide same-same for use in server-side
	; DHE key exchange.
	;
	; Because much of the huge prime sieve operations are what I like to think of as "luck
	; of the draw", we fire up as many execution threads as there are cores available
	; for every sieve candidate, we write a ' ', for every q that passes trial division
	; we write a '.', for every q that is probably prime, we write a '+', and for every
	; p that is probably prime, we write a '$', at which point hardcore verification begins.
	;
	; command line argument is size in bits you want of the DH safe prime
	; 
	; when we have found and verified one, we output the assembler required for dh_static.inc
	; to stdout
	;

	; include a copy of the ht_defaults.inc with a much larger bigint_maxwords setting
	include 'bigger_int_settings.inc'
	include '../ht.inc'

insane_primesize = 131072


	; single epoll object in rdi
calign
parent_receive:
	prolog	parent_receive
	mov	eax, syscall_write
	mov	edi, 1
	syscall

	mov	rdi, [childlist]
	mov	rsi, .killkids
	call	list$clear

	mov	eax, syscall_exit
	xor	edi, edi
	syscall

	epilog

falign
.killkids:
	; single arg in rdi, our child
	mov	eax, syscall_kill
	mov	esi, 0xf		; SIGTERM
	syscall
	ret

dalign
parent_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, parent_receive, io$error, io$timeout

globals
{
	childlist	dq	0
}


public _start
falign
_start:
	call	ht$init

	cmp	qword [argc], 1
	jbe	.usage

	call	list$new
	mov	[childlist], rax

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
	cmp	rbx, insane_primesize
	ja	.yourenuts
	cmp	rbx, 1536
	jb	.toosmall

	; see if a cpucount argument was passed (-XX)
	mov	rdi, [argv]
	call	list$pop_back
	test	rax, rax
	jz	.nocpuarg
	mov	r12, rax
	mov	rdi, rax
	mov	esi, '-'
	call	string$indexof_charcode
	cmp	rax, 0
	jne	.nocpuarg
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
	call	sysinfo$cpucount
	cmp	r12, rax
	ja	.cputoomany
	jmp	.doit
calign
.nocpuarg:
	; basic sanity checks passed, determine how many cores we have available
	call	sysinfo$cpucount
	; at minimum 1 (in case for some jacked reason /proc/cpuinfo gave us bupkiss)
	mov	ecx, 1
	mov	edx, 16384		; hahah, funny, though it will do it, my big machines are only 64 cores... :-/
	cmp	eax, ecx
	cmovl	eax, ecx
	cmp	eax, edx
	cmova	eax, edx

	mov	r12d, eax
calign
.doit:
	; the easiest/most straightforward/lockfree way to shoot it is of course socketpair/fork
	sub	rsp, 8			; for our socketpair
calign
.children:
	mov	eax, syscall_socketpair
	mov	edi, 1			; AF_UNIX
	mov	esi, 0x801		; SOCK_STREAM | SOCK_NONBLOCK
	xor	edx, edx
	mov	r10, rsp
	syscall
	cmp	rax, 0
	jl	.socketpairdeath
	; fork callee-saves are jacked:
	push	rbx r12
	mov	eax, syscall_fork
	syscall
	cmp	rax, 0
	jl	.forkdeath
	je	.inchild
	pop	r12 rbx

	mov	rdi, [childlist]
	mov	rsi, rax		; push our child's pid into our childlist
	call	list$push_back

	; else, we are the parent, make our established goods
	; we'll use the second socketpair fd for the parent side
	; so close the first one
	mov	eax, syscall_close
	mov	edi, [rsp]
	syscall
	mov	rdi, parent_vtable
	xor	esi, esi
	call	epoll$new
	mov	edi, [rsp+4]
	mov	rsi, rax
	call	epoll$established

	sub	r12d, 1
	jnz	.children

	call	epoll$run		; won't come back

falign
.inchild:
	pop	r12 rbx
	; post-fork child entrypoint
	; close the other half of our socketpair
	mov	eax, syscall_close
	mov	edi, [rsp+4]
	syscall

	; our side is blocking on the socketpair, not epoll$run based
	mov	r13d, [rsp]		; our side of the socketpair

	call	bigint$new
	mov	r14, rax
	call	bigint$new
	mov	r15, rax

	; we need to reinit our rng otherwise all children have the same seed:
	call	rng$init

	; no looping required, dh params will return us with one when it finds one
	mov	rdi, r14
	mov	rsi, r15
	mov	edx, ebx		; our desired safe prime bits
	call	bigint$dh_params

	; now, all we need to do is construct a return and send it back to the parent
	sub	rsp, 65536


	mov	rdi, rsp
	mov	rsi, .p_preface
	mov	edx, .p_prefacelen
	call	memcpy
	lea	r12, [rsp+.p_prefacelen]	; use this as our running pointer
	mov	edi, [r14+bigint_size_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, r12
	add	r12, [rax]			; add its string length to our running pointer
	call	string$to_utf8
	mov	rdi, rbx
	call	heap$free
	mov	rdi, r12
	mov	rsi, .mid
	mov	edx, .midlen
	add	r12, .midlen
	call	memcpy
	; write all of our size words
	xor	ebp, ebp
calign
.ploop:
	mov	rdi, r12
	mov	rsi, .ohx
	mov	edx, 2
	add	r12, 2
	call	memcpy
	mov	rcx, [r14+bigint_words_ofs]
	mov	rdi, [rcx+rbp*8]
	mov	esi, 16
	call	string$from_unsigned
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, r12
	add	r12, [rax]
	call	string$to_utf8
	mov	rdi, rbx
	call	heap$free
	add	ebp, 1
	cmp	ebp, [r14+bigint_size_ofs]
	je	.pfinish
	mov	rdi, r12
	mov	rsi, .comma
	mov	edx, .commalen
	add	r12, rdx
	call	memcpy
	jmp	.ploop
calign
.pfinish:
	mov	rdi, r12
	mov	rsi, .finish
	mov	edx, .finishlen
	add	r12, rdx
	call	memcpy

	; do g next and then we are done
	
	mov	rdi, r12
	mov	rsi, .g_preface
	mov	edx, .g_prefacelen
	add	r12, .g_prefacelen
	call	memcpy
	mov	edi, [r15+bigint_size_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, r12
	add	r12, [rax]			; add its string length to our running pointer
	call	string$to_utf8
	mov	rdi, rbx
	call	heap$free
	mov	rdi, r12
	mov	rsi, .mid
	mov	edx, .midlen
	add	r12, .midlen
	call	memcpy
	; write all of our size words
	xor	ebp, ebp
calign
.gloop:
	mov	rdi, r12
	mov	rsi, .ohx
	mov	edx, 2
	add	r12, 2
	call	memcpy
	mov	rcx, [r15+bigint_words_ofs]
	mov	rdi, [rcx+rbp*8]
	mov	esi, 16
	call	string$from_unsigned
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, r12
	add	r12, [rax]
	call	string$to_utf8
	mov	rdi, rbx
	call	heap$free
	add	ebp, 1
	cmp	ebp, [r15+bigint_size_ofs]
	je	.gfinish
	mov	rdi, r12
	mov	rsi, .comma
	mov	edx, .commalen
	add	r12, rdx
	call	memcpy
	jmp	.gloop
calign
.gfinish:
	mov	rdi, r12
	mov	rsi, .finish
	mov	edx, .finishlen
	add	r12, rdx
	call	memcpy

	; so now, r12-rsp is the length of what we just built
	; send it out to r13d
	mov	eax, syscall_write
	mov	edi, r13d
	mov	rsi, rsp
	mov	rdx, r12
	sub	rdx, rsp
	syscall

	sleep 1

	mov	eax, syscall_exit
	mov	edi, 1
	syscall

dalign
.p_preface db 10,'if used dh$fixed_p',10,10,'dalign',10,'dh$fixed_p:',10,9,'dq',9
.p_prefacelen = $ - .p_preface
dalign
.g_preface db 'if used dh$fixed_g',10,10,'dalign',10,'dh$fixed_g:',10,9,'dq',9
.g_prefacelen = $ - .g_preface
dalign
.ohx db '0x'
dalign
.mid db ', .data, 0, 0',10,'align 16',10,'.data:',9,'dq',9
.midlen = $ - .mid
dalign
.comma db ', '
.commalen = 2
dalign
.finish db 10,10,'end if',10,10
.finishlen = $ - .finish


falign
.forkdeath:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .forkmsg
	mov	edx, .forkmsglen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.forkmsg db 'fork syscall failed?!',10
.forkmsglen = $ - .forkmsg

falign
.socketpairdeath:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .socketpairmsg
	mov	edx, .socketpairmsglen
	syscall	
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.socketpairmsg db 'socketpair syscall failed?!',10
.socketpairmsglen = $ - .socketpairmsg

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
.usagestr db 'Usage: ./make_dh_static [-XX] SIZE',10,'Where SIZE is size in bits of the safe prime you want, XX specifies how many cores to use',10
.usagestrlen = $ - .usagestr
falign
.cputoomany:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .cpustr
	mov	edx, .cpustrlen
	syscall	
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.cpustr db 'You requested more CPUs than we have available. If you REALLY want that, edit make_dh_static.asm and remove the check.',10
.cpustrlen = $ - .cpustr

falign
.yourenuts:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .nutsstr
	mov	edx, .nutsstrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.nutsstr db 'You have requested an insane safe prime size. If you REALLY want that, edit make_dh_static.asm and up the limit.',10
.nutsstrlen = $ - .nutsstr

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
.smallstr db 'You have requested a safe prime size that is insecure/too small. If you REALLY want that, edit make_dh_static.asm and lower the limit.',10
.smallstrlen = $ - .smallstr
	include '../ht_data.inc'
