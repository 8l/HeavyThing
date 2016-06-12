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
	; epoll_child.inc: often times, it is useful, especially in tui_terminal environments, to have
	; a blocking fork'd child process, but bound on the parent side to an epoll object
	; 
	; NOTE: if you use epoll_child, take care to call epoll_child_killall before you exit, or you'll have
	; ophans kicking around (if that is not the desired effect, heh)
	;


if used epoll_child | defined include_everything

globals
{
	; we maintain a global list of our child pids, so that they can be killed on receipt of SIGTERM or other natural exit
	epoll_child_pids	dq	0
}


	; two arguments: rdi == parent epoll vtable, rsi == child function to call
	; when called from the parent, this will fork, and return the newly created epoll object
	; in rax to the parent, the child pid in rdx. In the child itself, will call the function in rsi
	; with its sole argument being its file descriptor
	; returns NULL in rax if fork actually failed, or socketpair failed
falign
epoll_child:
	prolog	epoll_child
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	sub	rsp, 8		; for our call to socketpair
	mov	eax, syscall_socketpair
	mov	edi, 1		; AF_UNIX
	mov	esi, 0x1	; SOCK_STREAM
	xor	edx, edx
	mov	r10, rsp
	syscall
	cmp	rax, 0
	jl	.socketpair_failed
	; fork callee-saves don't work
	push	rbx r12 r13
	mov	eax, syscall_fork
	syscall
	cmp	rax, 0
	jl	.forkdeath
	je	.inchild
	pop	r13 r12 rbx
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
	
	; use the second socketpair fd for the parent side, close the first one
	mov	eax, syscall_close
	mov	edi, [rsp]
	syscall
	mov	rdi, rbx
	xor	esi, esi
	call	epoll$new
	mov	rbx, rax
	; set our parent-side fd to nonblocking:
	mov	edi, [rsp+4]
	call	socket$nonblocking
	; let epoll know it is already established
	mov	edi, [rsp+4]
	mov	rsi, rbx
	call	epoll$established
	add	rsp, 8
	
	mov	rax, rbx
	mov	rdx, r13
	pop	r13 r12 rbx
	epilog
calign
.socketpair_failed:
	xor	eax, eax
	add	rsp, 8
	pop	r13 r12 rbx
	epilog
calign
.inchild:
	; make sure we die gracefully if our parent goes away
	mov	eax, syscall_prctl
	mov	edi, 1			; PR_SET_PDEATHSIG
	mov	esi, 0xf		; SIGTERM
	syscall

	pop	r13 r12 rbx
	; close the other half of our socketpair
	mov	eax, syscall_close
	mov	edi, [rsp+4]
	syscall

	; the fd we need to pass to the function in r12 is [rsp]
	mov	edi, [rsp]
	call	r12

	; in the [unlikely] event that returns to us, exit
	mov	eax, syscall_exit
	mov	edi, 0
	syscall

	; not reached:
	pop	r13 r12 rbx
	epilog
	
calign
.forkdeath:
	pop	r13 r12 rbx
	add	rsp, 8
	xor	eax, eax
	pop	r13 rbx rbx
	epilog


end if


if used epoll_child_killall | defined include_everything
	; no arguments, iterates the childpid list and sends a SIGTERM to them
falign
epoll_child_killall:
	prolog	epoll_child_killall
	mov	rdi, [epoll_child_pids]
	test	rdi, rdi
	jz	.nothingtodo
	mov	rsi, .killkids
	call	list$clear
calign
.nothingtodo:
	epilog
falign
.killkids:
	; single arg in rdi: our child
	mov	eax, syscall_kill
	mov	esi, 0xf		; SIGTERM
	syscall
	ret

end if
