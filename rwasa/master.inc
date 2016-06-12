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
	; master.inc: rwasa's startup/forking/master process goods
	;

globals
{
	workers		dq	0

}

	; no arguments, and isn't called, but jumped straight to from _start after
	; all our command line arguments were parsed
falign
masterthread:
	; so, all our configurations/bindings have been done already
	; first step is to change our uid/gid
	mov	eax, syscall_setgid
	mov	rdi, [runasgid]
	syscall
	test	eax, eax
	jnz	.setgidfail
	mov	eax, syscall_setuid
	mov	rdi, [runasuid]
	syscall
	test	eax, eax
	jnz	.setuidfail

	; deal with detaching
	cmp	dword [background], 0
	je	.skip_detach

	mov	eax, syscall_fork
	syscall
	cmp	rax, 0
	jl	.forkfail
	jne	.doexit
	mov	eax, syscall_close
	mov	edi, 0
	syscall
	mov	eax, syscall_close
	mov	edi, 1
	syscall
	mov	eax, syscall_close
	mov	edi, 2
	syscall
	mov	eax, syscall_setsid
	syscall
	call	rng$init

	; reset our syslog pid so they make sense
	mov	eax, syscall_getpid
	syscall
	mov	[syslog_pid], rax
calign
.skip_detach:
	cmp	dword [background], 0
	jne	.nobanner
	mov	rdi, .banner
	call	string$to_stdout
calign
.nobanner:
	; we need our worker children
	call	list$new
	mov	[workers], rax
	push	rbx
	mov	ebx, dword [cpucount]
calign
.childloop:
	mov	rdi, master$vtable
	mov	rsi, workerthread
	call	epoll_child
	test	rax, rax
	jz	.forkfail
	mov	rdi, [workers]
	mov	rsi, rax
	call	list$push_back
	sub	ebx, 1
	jnz	.childloop
	pop	rbx

	; then, we need to close/destroy all our delayed epoll_inbounds
	mov	rdi, [_epoll_inbound_delayed]
	mov	rsi, epoll$fatality
	call	list$clear

if defined newepoll_for_master
	; reinit our epoll layer but only if we did a detach
	cmp	dword [background], 0
	je	.skip_newepoll
	call	epoll$init

	; since we had to call epoll$init, this means we lost our OCSP Stapling timers
	mov	rdi, [tls$pem_byptr]
	mov	rsi, X509$ocsp
	call	unsignedmap$foreach

calign
.skip_newepoll:
end if
if defined children_write_their_own_logs
	cmp	dword [cpucount], 1
	je	.skiplogwriter_timer
end if
	cmp	dword [background], 0
	je	.skiplogwriter_timer
	; we need a new master timer to deal with log buffering
	call	io$new
	mov	qword [rax], logwriter$vtable
	mov	edi, 1500
	mov	rsi, rax
	call	epoll$timer_new
calign
.skiplogwriter_timer:

	; we need to hook the X509 OCSP stapler responses so that we can propagate them
	; to our children
	mov	qword [X509$ocsp_hook], master_ocsp_hook

	; and finally, turn it over to epoll
	call	epoll$run
calign
.doexit:
	mov	eax, syscall_exit
	xor	edi, edi
	syscall
cleartext .banner, 'This is rwasa v1.16 ',0xa9,' 2015, 2016 2 Ton Digital. Author: Jeff Marrison',10,'A showcase piece for the HeavyThing library. Commercial support available',10,'Proudly made in Cooroy, Australia. More info: https://2ton.com.au/rwasa',10
calign
.forkfail:
	mov	rdi, .err_forkfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_forkfail, 'Fatal: fork and/or socketpair failed.'
calign
.setgidfail:
	mov	rdi, .err_setgidfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_setgidfail, 'setgid() failed.'
calign
.setuidfail:
	mov	rdi, .err_setuidfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_setuidfail, 'setuid() failed.'


dalign
logwriter$vtable:
	dq	io$destroy, io$clone, io$connected, io$send, io$receive, io$error, logwriter$timer

dalign
master$vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, master$receive, io$error, io$timeout


falign
master$receive:
	prolog	master$receive
	; got data from one of our workers
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, [rdi+epoll_inbuf_ofs]
calign
.outer:
	mov	rdx, [r12+buffer_length_ofs]
	mov	rcx, [r12+buffer_itself_ofs]
	cmp	rdx, 8
	jb	.needmore
	mov	eax, [rcx+4]
	; sanity only
	cmp	rdx, rax
	jb	.needmore
	cmp	dword [rcx], linkmessage_log
	je	.logmessage
	cmp	dword [rcx], linkmessage_tlsupdate
	jne	.insanity
	; otherwise, we are sitting on a TLS session cache update item
	; we need to broadcast this to all other workers
	mov	r13, rcx	; send buffer
	mov	r14, rax	; total send length
	mov	rdi, [workers]
	mov	r15, [rdi+_list_first_ofs]
calign
.tlsbroadcast:
	mov	rdi, [r15+_list_valueofs]
	cmp	rdi, rbx
	je	.tlsbroadcast_skip
	mov	rsi, r13
	mov	rdx, r14
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
calign
.tlsbroadcast_skip:
	mov	r15, [r15+_list_nextofs]
	test	r15, r15
	jnz	.tlsbroadcast
	; consume and continue
	mov	rdi, r12
	mov	rsi, r14
	call	buffer$consume
	jmp	.outer
calign
.logmessage:
	; [rcx+8] == 8 byte webservercfg ptr (which is valid, even though it originated in a child process)
	; [rcx+16] == 4 byte logtype (0 == normal, 1 == error)
	; [rcx+20] == string itself
	mov	rdi, [rcx+8]
	lea	rsi, [rcx+20]
	cmp	dword [rcx+16], 0
	jne	.logmessage_error
	call	webservercfg$log
	; consume and continue
	mov	rcx, [r12+buffer_itself_ofs]
	mov	rdi, r12
	mov	esi, [rcx+4]
	call	buffer$consume
	jmp	.outer
calign
.logmessage_error:
	call	webservercfg$logerror
	; consume and continue
	mov	rcx, [r12+buffer_itself_ofs]
	mov	rdi, r12
	mov	esi, [rcx+4]
	call	buffer$consume
	jmp	.outer
calign
.needmore:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.insanity:
	; should NOT happen
	mov	rdi, r12
	call	buffer$reset
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog



	; single argument in rdi == an X509cert object that just got its ocspresponse buffer updated
falign
master_ocsp_hook:
	prolog	master_ocsp_hook
	; we need to propagate the ocspresponse buffer object to our children
	mov	rsi, [rdi+X509cert_ocspresponse_ofs]
	mov	r8, [rdi+X509cert_subjectcn_ofs]
	mov	rdx, [rsi+buffer_length_ofs]
	mov	r9, [r8]
if string_bits = 32
	shl	r9, 2
else
	shl	r9, 1
end if
	add	rdx, 16		; +8 for the preface, +8 for string length
	add	rdx, r9
	cmp	rdx, 4096	; 4k == atomic oneshot
	ja	.skipit
	push	rbx r12 r13
	sub	rsp, 4096
	mov	dword [rsp], linkmessage_ocsp
	mov	dword [rsp+4], edx
	mov	rbx, rdx	; save our total length
	mov	r12, rsi
	mov	r13, r9
	lea	rdi, [rsp+8]
	mov	rsi, r8
	mov	edx, r9d
	add	edx, 8
	call	memcpy
	lea	rdi, [rsp+r13+16]
	mov	rsi, [r12+buffer_itself_ofs]
	mov	rdx, [r12+buffer_length_ofs]
	call	memcpy

	mov	rdi, [workers]
	mov	r12, [rdi+_list_first_ofs]
calign
.sendloop:
	mov	rdi, [r12+_list_valueofs]
	mov	rsi, rsp
	mov	rdx, rbx
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jnz	.sendloop
	add	rsp, 4096
	pop	r13 r12 rbx
	epilog
calign
.skipit:
	epilog


falign
logwriter$timer:
	prolog	logwriter$timer
	; fired once every 1.5 seconds to dump our logbuffers
	; bit of evil trickery here, we basically do the same thing as ordinary webservercfg objects do
	; if background=0, then our original config-parsed webservercfg objects still have valid timers
	; so we can just leave them be, and in which case this timer never gets created
	; if cpus=1, then the child writes the logs directly and never sends them to us
	; and otherwise, we just need to iterate through the webservercfg and call its timer handler
	mov	rdi, [configs]
	mov	rsi, webservercfg$timer
	call	list$foreach
	xor	eax, eax
	epilog
