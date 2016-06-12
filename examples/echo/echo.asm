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
	;       echo.asm: simple echo server, listens on INADDR_ANY:8001
	;
	; All HeavyThing goods must start with settings and the main include
include '../../ht_defaults.inc'
include '../../ht.inc'

	; the epoll layer provides either io chaining/layers, or direct interaction
	; for our simple echoserver, we'll stick with epoll direct interaction.

	; our "onconnect" function gets called when a new connection arrives.
	; arguments: rdi == epoll object, rsi == sockaddr ptr, edx == length of same
	; we only wish to send our greeting line on connect.
falign
echoserver_connected:
	prolog	echoserver_connected
	mov	rsi, .greeting
	mov	edx, .greetinglen
	call	epoll$send
	epilog
dalign
.greeting:
	db	'HeavyThing library echo server example reporting for duty',13,10
.greetinglen = $ - .greeting


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


	; similar to C++ virtual methods, we need a virtual method table, copied
	; and modified from epoll$default_vtable
	; since we don't have any per-connection state information to keep track of,
	; the default epoll object works fine for our connections.
dalign
echoserver_vtable:
	dq	epoll$destroy, epoll$clone, echoserver_connected, epoll$send, echoserver_received, io$error, io$timeout

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	; create our base epoll listener object first up
	mov	rdi, echoserver_vtable
	xor	esi, esi		; epoll$new extra space == 0
	call	epoll$new
	mov	rbx, rax

	; setup a sockaddr_in for our listener:
	sub	rsp, sockaddr_in_size
	mov	rdi, rsp
	mov	esi, 8001
	call	inaddr_any

	; setup our actual socket/listener
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, rbx
	call	epoll$inbound
	; epoll$inbound returns 0 on failure (bind)
	test	eax, eax
	jz	.bindfailed
	
	; display our banner to our controlling terminal, we don't want to be too quiet
	mov	rdi, .banner
	call	string$to_stdoutln

	; and finally, turn control over to the epoll layer, which won't come back.
	call	epoll$run
	; epoll$run does not return.
calign
.bindfailed:
	mov	rdi, .bindfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .bindfail, 'bind to INADDR_ANY:8001 failed.'
cleartext .banner, 'echo server listening on port 8001'

	; include the global data segment:
include '../../ht_data.inc'
