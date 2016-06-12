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
	;       sshecho.asm: simple SSH2 echo server, listens on INADDR_ANY:8001
	;
	; All HeavyThing goods must start with settings and the main include
include '../../ht_defaults.inc'
include '../../ht.inc'

	; unlike the simple TCP echo server, SSH2 is an IO chain (aka layer).
	; The HeavyThing library design for IO chaining really does mean you could
	; nest them arbitrarily (the webserver is also an IO chain, so you could
	; do TLS -> SSH2 -> TLS -> SSH2 -> webserver, hahah, that hurts my head,
	; but it would work a treat).

	; So, instead of using the epoll vtable for our echoserver virtual methods
	; we need to use the io layer's.


	; our "onconnect" function gets called when a new connection arrives.
	; arguments: rdi == epoll object, rsi == sockaddr ptr, edx == length of same
	; we only wish to send our greeting line on connect.
falign
sshecho_connected:
	prolog	sshecho_connected
	mov	rsi, .greeting
	mov	edx, .greetinglen
	; unlike our simple TCP echo server, which is tied directly to the epoll layer
	; we are an IO chain, so we can't call epoll$send from here, we need to use
	; io$send instead.
	call	io$send
	; Note: we could have also done:
	; mov	rcx, [rdi]		; our virtual method table pointer
	; call	qword [rcx+io_vsend]	; its send function
	; and this would allow us to do "overrides" without modifying code later :-)
	epilog
dalign
.greeting:
	db	'HeavyThing library SSH2 echo server example reporting for duty',13,10
.greetinglen = $ - .greeting


	; our data receive function, which gets three arguments: rdi == epoll object,
	; rsi == ptr to data, rdx == length of same
falign
sshecho_received:
	prolog	sshecho_received
	; also unlike the simple TCP echo server, since we are an io chain and not
	; directly using the epoll object itself, we can just call io$send and be
	; done with it.

	; since we will be getting keystroke-at-a-time, if we get a 3 (Ctrl-C), KO
	; the connection:
	cmp	byte [rsi], 3
	je	.ko
	; so that our echo appears to actually do linefeeds, haha, catch CR too:
	cmp	byte [rsi], 13
	je	.carriagereturn
	call	io$send
	; Also note from above, we could have also done:
	; mov	rcx, [rdi]		; our virtual method table pointer
	; call	qword [rcx+io_vsend]	; its send function
	; and this would allow us to do "overrides" without modifying code later :-)

	; the io layers lets the receive function determine whether to close the
	; connection or not, so if we return 1 here, our connection will be closed
	; and 0 will keep it open.
	xor	eax, eax
	epilog
calign
.carriagereturn:
	mov	rsi, .crlf
	mov	edx, 2
	call	io$send
	xor	eax, eax
	epilog
calign
.ko:
	mov	eax, 1
	epilog
dalign
.crlf:
	db	13, 10


	; similar to C++ virtual methods, we need a virtual method table, copied
	; and modified from io$vtable (because we are an IO layer this time, not a
	; direct epoll layer user).
dalign
sshecho_vtable:
	dq	io$destroy, io$clone, sshecho_connected, io$send, sshecho_received, io$error, io$timeout

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	; first thing we need is a default io object for our sshecho layer:
	call	io$new
	mov	r12, rax
	; set its virtual method table to our own:
	mov	qword [rax+io_vmethods_ofs], sshecho_vtable

	; next in our layers needs to be the SSH server layer:
	xor	edi, edi			; use /etc/ssh by default
	call	ssh$new_server
	test	rax, rax
	jz	.hostkeyerror
	mov	r13, rax
	; we have to link our initial io layer with our ssh layer
	mov	[r12+io_child_ofs], rax		; app layer child == SSH layer
	mov	[rax+io_parent_ofs], r12	; SSH layer parent == app layer

	; and the final layer needs to be an epoll object so that it has network access
	mov	rdi, epoll$default_vtable	; the default vtable is fine, it handles io chaining for us
	xor	esi, esi			; no extra space needed in the epoll object
	call	epoll$new
	mov	r14, rax
	; we have to link the epoll object to the SSH layer:
	mov	[r13+io_child_ofs], rax		; SSH layer child == epoll layer
	mov	[r14+io_parent_ofs], r13	; epoll layer parent == SSH2 layer

	; setup a sockaddr_in for our listener:
	sub	rsp, sockaddr_in_size
	mov	rdi, rsp
	mov	esi, 8001
	call	inaddr_any

	; setup our actual socket/listener, noting here that the epoll$inbound (as well as outbounds)
	; will deal with io chains correctly, so we only have to pass the topmost in our layer, which
	; is our sshecho io object:
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, r12			; topmost layer (though we could do lowest too)
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
calign
.hostkeyerror:
	mov	rdi, .hostkeys
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .bindfail, 'bind to INADDR_ANY:8001 failed.'
cleartext .banner, 'SSH2 echo server listening on port 8001'
cleartext .hostkeys, '/etc/ssh host keys and/or contents error.'

	; include the global data segment:
include '../../ht_data.inc'
