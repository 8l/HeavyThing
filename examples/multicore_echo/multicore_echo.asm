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
	; multicore_echo.asm: simple echo server, command line for CPUCOUNT +
	;   port number to listen on.
	;
	; Note: This was thrown together in response to a tweet from @ErrataRob
	; who said: "I want to write the fastest possible, multi-core echo (tcp/7) 
	; server, running in the Linux kernel. Any suggestions?"
	;
	; He politely replied that he wanted to do it actually from inside the
	; kernel without user-space switching, which I wholly understand, but
	; he may enjoy a decent effort at user-space for his own comparitive
	; purposes anyway, and others have asked for cut-down examples anyway.
	;
	; This is my contribution re: same, and is a very simple copy/modify of the
	; original echo example, but with separate tuning specific to what I
	; would perceive as a benchmarking echo server :-) haha
	;
	; All HeavyThing goods must start with settings and the main include
include 'custom_settings.inc'
include '../../ht.inc'


	; our data receive function, which gets three arguments: rdi == epoll object,
	; rsi == ptr to data, rdx == length of same
falign
echoserver_received:
	prolog	echoserver_received
	; since the epoll layer by default has an input buffer accumulator, we need
	; to clear it similar to how the default epoll$receive function does
	push	qword [rdi+epoll_inbuf_ofs]
	; since we are an echo server, and our arguments are already setup, sending it
	; back is simple:
	call	epoll$send
	; and finally, reset the input buffer so that our received does not accumulate
	pop	rdi
	call	buffer$reset

	; the epoll layer lets the receive function determine whether to close the
	; connection or not, so if we return 1 here, our connection will be closed
	; and 0 will keep it open.
	xor	eax, eax
	epilog

	; globals to hangon to our goods post-fork
globals
{
	cpucount	dd	1
}

	; similar to C++ virtual methods, we need a virtual method table, copied
	; and modified from epoll$default_vtable
	; since we don't have any per-connection state information to keep track of,
	; the default epoll object works fine for our connections.
dalign
echoserver_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, echoserver_received, io$error, io$timeout

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	; arg parsing first:
	cmp	dword [argc], 1
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
	mov	r14, rax
	call	heap$free
	cmp	r14, 1
	jl	.usage
	cmp	r14, 65535
	ja	.usage
	
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
	mov	[cpucount], eax
	test	rax, rax
	jz	.usage
	mov	rdi, r13
	call	heap$free
	; we don't really care how many they specified
calign
.nocpuarg:
	; create our base epoll listener object first up
	mov	rdi, echoserver_vtable
	xor	esi, esi		; epoll$new extra space == 0
	call	epoll$new
	mov	rbx, rax

	; setup a sockaddr_in for our listener:
	sub	rsp, sockaddr_in_size
	mov	rdi, rsp
	mov	esi, r14d
	call	inaddr_any

	; setup our actual socket/listener
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, rbx
	; NOTE: we call epoll$inbound_delayed here
	; such that the real epoll binding doesn't happen
	; until the next call to epoll$init
	call	epoll$inbound_delayed
	; epoll$inbound returns 0 on failure (bind)
	test	eax, eax
	jz	.bindfailed
	
	; display our banner to our controlling terminal, we don't want to be too quiet
	mov	rdi, .banner
	call	string$to_stdoutln


	; if we are forking, do the deed
	sub	dword [cpucount], 1
	jz	.nofork
calign
.fork:
	; callee-saves don't persist across fork...
	mov	eax, syscall_fork
	syscall
	cmp	rax, 0
	jl	.forkfail
	je	.inchild
	; save the child pid in r13
	mov	r13, rax
	cmp	qword [epoll_child_pids], 0
	jne	.listokay
	call	list$new
	mov	[epoll_child_pids], rax
calign
.listokay:
	mov	rdi, [epoll_child_pids]
	mov	rsi, r13
	call	list$push_back

	; keep going
	sub	dword [cpucount], 1
	jnz	.fork
calign
.nofork:
	; recall epoll$init for our inbound_delayed handling
	call	epoll$init
	; and finally, turn control over to the epoll layer, which won't come back.
	call	epoll$run
	; epoll$run does not return.
calign
.inchild:
	; make sure we die gracefully if our parent goes away
	mov	eax, syscall_prctl
	mov	edi, 1			; PR_SET_PDEATHSIG
	mov	esi, 0xf		; SIGTERM
	syscall

	; reinit epoll
	call	epoll$init
	; if we were doing anything else exciting, rng$init here too
	; proceed with epoll$run
	call	epoll$run
	; epoll$run does not return


	; fake a call to epoll_child to make sure the epoll layer includes our death goods
calign
.fakedep:
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
	call	epoll_child
calign
.bindfailed:
	mov	rdi, .bindfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .bindfail, 'bind failed.'
cleartext .banner, 'multicore_echo alive'
calign
.usage:
	mov	rdi, .usagestr
	call	string$to_stdout
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .usagestr, 'Usage: ./multicore_echo [-XX] PORT',10,' where optional XX is process count, PORT is TCP port to bind to',10
calign
.forkfail:
	mov	rdi, .forkfailstr
	call	string$to_stdout
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .forkfailstr, 'fork() syscall failed.',10

	; include the global data segment:
include '../../ht_data.inc'
