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
	; worker.inc: child process goods for rwasa
	;

globals
{
	; keep an epoll object so we can talk with the master process
	masterlink	dq	0

	; a working buffer so we don't have to continually stack allocate or heap allocate log activities
	logbuffer	dq	0
}


; possible message types that go over the master/worker comms link
linkmessage_ocsp = 0
linkmessage_log = 1
linkmessage_tlsupdate = 2


falign
workerthread:
	prolog	workerthread
	push	rbx
	mov	rbx, rdi		; our fd
if profiling
	call	profiler$reset
end if
	; reinit our states
	call	epoll$init
	call	rng$init

	; reset our syslog pid so they make sense
	mov	eax, syscall_getpid
	syscall
	mov	[syslog_pid], rax

	; create our logbuffer
	call	buffer$new
	mov	[logbuffer], rax
	; setup our masterlink
	mov	rdi, masterlink$vtable
	xor	esi, esi
	call	epoll$new
	mov	rdi, rbx
	mov	rsi, rax
	mov	rbx, rax
	mov	[masterlink], rax
	call	epoll$established
	; setup an epoll object for our comms back to our master
if defined children_write_their_own_logs
	cmp	dword [cpucount], 1
	je	.skip_hooks
end if
	; if cpucount > 1:
	; hook logwriting so that it goes back to the master
	mov	qword [webservercfg$log_hook], worker_loghook
	; hook tls session cache so that it also propagates to our siblings
	cmp	dword [cpucount], 1
	je	.notlshook
	mov	qword [tls$sessioncache_hook], worker_tlscache
.notlshook:
	; we need to go through our webservercfg objects and recreate our timers
	mov	rdi, [configs]
	mov	rsi, .newconfigtimer
	call	list$foreach

	pop	rbx

if profiling
	; make sure cpu count is 1 and we are not backgrounded
	mov	rdi, .profiler_err1
	cmp	dword [background], 0
	jne	.profiler_errmsg
	mov	rdi, .profiler_err2
	cmp	dword [cpucount], 1
	jne	.profiler_errmsg
	
	; otherwise, go ahead and fire up a tui_profiler
	call	tui_profiler$new
	mov	rdi, rax
	call	tui_terminal$new
end if

	call	epoll$run
	epilog
falign
.newconfigtimer:
	mov	rsi, rdi
	mov	edi, 1500
	call	epoll$timer_new
	ret
if profiling
cleartext .profiler_err1, 'ERROR: Profiling TUI component requires foreground mode.'
cleartext .profiler_err2, 'ERROR: Profiling TUI component requires cpu count to be 1.'
calign
.profiler_errmsg:
	call	string$to_stdoutln
	call	epoll$run
	epilog
end if
calign
.skip_hooks:
	; when we called epoll$init for the second time, we lost our configuration timer
	; so we have to create a new one, similar to how the multiprocess version does it
	; in the master thread.
	call	io$new
	mov	qword [rax], logwriter$vtable
	mov	edi, 1500
	mov	rsi, rax
	call	epoll$timer_new
	pop	rbx

if profiling
	; make sure cpu count is 1 and we are not backgrounded
	mov	rdi, .profiler_err1
	cmp	dword [background], 0
	jne	.profiler_errmsg
	mov	rdi, .profiler_err2
	cmp	dword [cpucount], 1
	jne	.profiler_errmsg
	
	; otherwise, go ahead and fire up a tui_profiler
	call	tui_profiler$new
	mov	rdi, rax
	call	tui_terminal$new
end if


	call	epoll$run
	epilog

	; we are called from the webservercfg layer for all webservercfg objects
	; rdi == webservercfg object, rsi == preformatted log string, edx == 0 == normal, 1 == error
falign
worker_loghook:
	prolog	worker_loghook
	; compose and send a masterlink message
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx

	mov	rdi, [logbuffer]
	call	buffer$reset
	mov	rdi, [logbuffer]
	mov	esi, linkmessage_log
	call	buffer$append_dword	; [buf+0] == linkmessage type
	mov	rsi, [r12]
	mov	rdi, [logbuffer]
if string_bits = 32
	shl	rsi, 2
else
	shl	rsi, 1
end if
	add	rsi, 28			; +4 type, +4 totallength, +4 logtype, +webservercfg object 8, +stringlength 8 preface
	call	buffer$append_dword	; [buf+4] == linkmessage length (total, including preface)
	mov	rdi, [logbuffer]
	mov	rsi, rbx
	call	buffer$append_qword	; [buf+8] == webservercfg object pointer
	mov	rdi, [logbuffer]
	mov	esi, r13d
	call	buffer$append_dword	; [buf+16] == logtype
	mov	rdi, [logbuffer]
	mov	rsi, r12
	mov	rdx, [r12]
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	add	rdx, 8
	call	buffer$append
	mov	r8, [logbuffer]
	mov	rdi, [masterlink]
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	pop	r13 r12 rbx
	epilog


	; we are called directly from the tls layer anytime something gets added to our sessioncache
	; rdi == string sessionid, rsi == 72 bytes of possibly encrypted tls state goods
falign
worker_tlscache:
	prolog	worker_tlscache
	; compose and send a masterlink message
	sub	rsp, 128
	mov	dword [rsp], linkmessage_tlsupdate
	mov	dword [rsp+4], 40 + 64
	mov	rcx, rdi
	lea	rdi, [rsp+8]
	push	rsi
	mov	rsi, rcx
	mov	edx, 32
	call	memcpy
	pop	rsi
	lea	rdi, [rsp+40]
	mov	edx, 64
	call	memcpy
	mov	rdi, [masterlink]
	mov	rsi, rsp
	mov	edx, 40 + 64
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	add	rsp, 128
	epilog


dalign
masterlink$vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, masterlink$receive, io$error, io$timeout


falign
masterlink$receive:
	prolog	masterlink$receive
	; first 4 bytes is our message type, next 4 bytes is the length (which includes the 8 byte preface)
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
	cmp	dword [rcx], linkmessage_ocsp
	je	.ocsp
	cmp	dword [rcx], linkmessage_tlsupdate
	jne	.insanity
	; otherwise, we are sitting on a TLS session cache update item
	; which is sessionid at [rcx+8], 64 byte state info at [rcx+40]
	lea	r13, [rcx+8]
	lea	r14, [rcx+40]
	mov	rdi, r13
	mov	rsi, r14
	push	qword [tls$sessioncache_hook]
	mov	qword [tls$sessioncache_hook], 0
	call	tls$sessioncache_set
	pop	rax
	mov	[tls$sessioncache_hook], rax
	; consume and continue
	mov	rcx, [r12+buffer_itself_ofs]
	mov	rdi, r12
	mov	esi, [rcx+4]
	call	buffer$consume
	jmp	.outer
calign
.ocsp:
	lea	r13, [rcx+8]	; our subjectcn string
	; this is a bit inefficient, because we have to walk our certificates every time we get these
	; but a) there aren't many certificates (normally), and b) this doesn't happen very often
	; so we really don't mind

	; so we know that ALL of our certificates live in the tls$pem_byptr map, so we'll walk it by
	; hand searching for our matching subjectcn
	mov	rdi, [tls$pem_byptr]
	mov	r14, [rdi+_avlofs_next]	; first one in the list
calign
.ocsp_search_outer:
	mov	rdi, [r14+_avlofs_key]	; the X509 object
	cmp	qword [rdi+X509_certificates_ofs], 0
	je	.ocsp_search_outer_next
	mov	rdi, [rdi+X509_certificates_ofs]
	mov	r15, [rdi+_list_first_ofs]
	test	r15, r15
	jz	.ocsp_search_outer_next
calign
.ocsp_search_inner:
	mov	rdi, [r15+_list_valueofs]
	mov	rsi, r13
	mov	rdi, [rdi+X509cert_subjectcn_ofs]
	call	string$equals
	test	eax, eax
	jnz	.ocsp_search_found
	mov	r15, [r15+_list_nextofs]
	test	r15, r15
	jnz	.ocsp_search_inner
calign
.ocsp_search_outer_next:
	mov	r14, [r14+_avlofs_next]
	test	r14, r14
	jnz	.ocsp_search_outer
	; if we made it to here, we didn't find it
	mov	rcx, [r12+buffer_itself_ofs]
	mov	rdi, r12
	mov	esi, [rcx+4]
	call	buffer$consume
	jmp	.outer
calign
.ocsp_search_found:
	mov	r14, [r15+_list_valueofs]		; the X509cert object
	cmp	qword [r14+X509cert_ocspresponse_ofs], 0
	jne	.ocsp_nonewbuffer
	call	buffer$new
	mov	[r14+X509cert_ocspresponse_ofs], rax
calign
.ocsp_nonewbuffer:
	mov	rdi, [r14+X509cert_ocspresponse_ofs]
	call	buffer$reset
	mov	rcx, [r13]
	mov	rdi, [r14+X509cert_ocspresponse_ofs]
	mov	rsi, [r12+buffer_itself_ofs]
	mov	edx, [rsi+4]
if string_bits = 32
	shl	rcx, 2
else
	shl	rcx, 1
end if
	sub	edx, 16
	add	rsi, 16
	add	rsi, rcx
	sub	edx, ecx
	call	buffer$append
	; consume and continue
	mov	rcx, [r12+buffer_itself_ofs]
	mov	rdi, r12
	mov	esi, [rcx+4]
	call	buffer$consume
	jmp	.outer
calign
.insanity:
	; should NOT happen
	mov	rdi, r12
	call	buffer$reset
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	epilog
calign
.needmore:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
