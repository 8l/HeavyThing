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
	; worker.inc: webslap worker process goods
	;

globals
{
; this ends up being the pointer to the epoll object that we use to
; send our progress reports back to our master
parentcomms	dq	0
workerid	dq	-1
workerchannels	dq	0
parentaccum	dq	0
workingbuf	dq	0
}

; we need a vtable for our parentaccum timer
dalign
parentaccum$vtable:
	dq	io$destroy, io$clone, io$connected, io$send, io$receive, io$error, parentaccum$timer

; each channel needs its own idea of urls, and its own separate idea of etags/last modifieds
channel_webclient_ofs = 0
channel_urls_ofs = 8
channel_etagmap_ofs = 16
channel_modmap_ofs = 24
channel_donefirst_ofs = 32
channel_cururl_ofs = 40
channel_firstcount_ofs = 48
channel_urlstring_ofs = 56
channel_starttime_ofs = 64
channel_startreceived_ofs = 72
channel_startconnects_ofs = 80

channel_size = 88


; single argument in rdi: a channel object
falign
channel_fire:
	prolog	channel_fire
	cmp	qword [requests], 0
	jle	.nodeal
	push	rbx r12 r13
	mov	rbx, rdi
	mov	rsi, [rdi+channel_cururl_ofs]
	mov	rdx, [firsturl]
	mov	rcx, [rsi+_list_valueofs]
	test	rdx, rdx
	jz	.nofirst
	cmp	dword [rdi+channel_donefirst_ofs], 0
	jne	.nofirst
	; first it is
	mov	rcx, rdx
	mov	dword [rdi+channel_donefirst_ofs], 1
	jmp	.goturl
calign
.nodeal:
	epilog
calign
.nofirst:
	; rcx is our string, but we have to update cururl
	mov	rdx, [rdi+channel_urls_ofs]
	mov	r8, [rdx+_list_first_ofs]
	mov	rsi, [rsi+_list_nextofs]
	test	rsi, rsi
	cmovz	rsi, r8
	mov	[rdi+channel_cururl_ofs], rsi
calign
.goturl:
	; rcx is the url we need to do ... determine whether it is a POST url or not first
	mov	[rbx+channel_urlstring_ofs], rcx
	mov	r12, rcx
	mov	rdi, rcx
	mov	rsi, .postcolon
	call	string$starts_with
	test	eax, eax
	jnz	.posturl
	; otherwise, get the wcrequest object ready to roll as a get request
	mov	rdi, [rbx+channel_webclient_ofs]
	mov	rsi, r12
	mov	rdx, channel_response
	mov	rcx, rbx
	call	webclient$get_nolaunch
	jmp	.wcrequest_ready
cleartext .postcolon, 'POST:'
calign
.posturl:
	push	r14 r15
	mov	rdi, r12
	mov	esi, ':'
	mov	edx, 5
	call	string$indexof_charcode_ofs
	mov	rdi, r12
	mov	esi, 5
	mov	rdx, rax
	call	string$substring	; filename
	mov	r13, rax
	mov	rdi, rax
	call	file$to_buffer
	mov	r14, rax
	mov	rdi, r12
	mov	esi, ':'
	mov	edx, 6
	add	rdx, [r13]
	call	string$indexof_charcode_ofs
	mov	rdi, r12
	mov	esi, 5
	add	rsi, [r13]
	mov	rdx, rax
	sub	rdx, 1
	push	rax
	call	string$substring	; content type
	mov	rdi, r13
	mov	r13, rdi
	call	heap$free
	; r13 == content type string, r14 == post buffer contents
	pop	rax
	mov	rdi, r12
	mov	rsi, rax
	add	rsi, 1
	mov	rdx, -1
	call	string$substr		; url
	mov	r15, rax
	
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, r13
	mov	rcx, r14
	mov	r8, channel_response
	mov	r9, rbx
	call	webclient$post_nolaunch
	mov	rdi, r13
	mov 	r13, rax
	call	heap$free
	mov	rdi, r14
	call	buffer$destroy
	mov	rdi, r15
	call	heap$free
	mov	rax, r13
	
	pop	r15 r14
calign
.wcrequest_ready:
	; since we preparsed all urls to make sure they were valid, we don't have to worry about
	; wcrequest$new returning null
	mov	r13, rax

	; so, we need to check etags/lastmodified maps, and then launch the request
	cmp	dword [do_etag], 0
	je	.skipetag
	mov	rdi, [rbx+channel_etagmap_ofs]
	mov	rsi, [rbx+channel_urlstring_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.skipetag
	mov	rdi, [r13+wcrequest_object_ofs]
	mov	rsi, mimelike$ifnonematch
	call	mimelike$setheader
calign
.skipetag:
	cmp	dword [do_lastmod], 0
	je	.skiplastmod
	mov	rdi, [rbx+channel_modmap_ofs]
	mov	rsi, [rbx+channel_urlstring_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.skiplastmod
	mov	rdi, [r13+wcrequest_object_ofs]
	mov	rsi, mimelike$ifmodifiedsince
	call	mimelike$setheader
calign
.skiplastmod:
	; our wcrequest object is ready to roll out
	mov	rax, [_epoll_tv_msecs]
	mov	[rbx+channel_starttime_ofs], rax
	mov	rdi, [rbx+channel_webclient_ofs]
	mov	rsi, r13
	mov	rcx, [rdi+webclient_totalreceived_ofs]
	mov	r8, [rdi+webclient_connects_ofs]
	mov	qword [rdi+webclient_replystamp_ofs], 0
	mov	[rbx+channel_startreceived_ofs], rcx
	mov	[rbx+channel_startconnects_ofs], r8
	call	webclient$launch

	pop	r13 r12 rbx
	epilog



; four arguments: rdi == channel object, rsi == mimelike result or webclient error, rdx == url object, rcx == time in ms
falign
channel_response:
	prolog	channel_response
	mov	rax, [workingbuf]
	; we need to compose our parent message, which is:
	; url, response code, header size, body size, bytes received, bool for keepalive, ctime, dtime, ttime, wait
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rcx

	mov	r14, rax

	mov	rdi, rax
	mov	rsi, [rbx+channel_urlstring_ofs]
	mov	rdx, [rsi]
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	add	rdx, 8
	call	buffer$append
	cmp	r12, webclient_fail_dns
	je	.failed
	cmp	r12, webclient_fail_preconnect
	je	.failed
	cmp	r12, webclient_fail_closed
	je	.failed
	cmp	r12, webclient_fail_timeout
	je	.failed
	; otherwise, extract the response code from the header
	mov	rdi, [r12+mimelike_preface_ofs]
	mov	esi, 9
	mov	edx, 3
	call	string$substr
	mov	r15, rax
	mov	rdi, rax
	call	string$to_unsigned

	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_dword
	mov	rdi, r15
	call	heap$free
	; header size is next
	mov	rdi, r14
	mov	rsi, [r12+mimelike_hdrlen_ofs]
	call	buffer$append_dword
	; body size is next
	mov	rdi, r14
	mov	rsi, [r12+mimelike_body_ofs]
	mov	rsi, [rsi+buffer_length_ofs]
	call	buffer$append_qword
	cmp	dword [do_etag], 0
	je	.skipetag
	mov	rdi, r12
	mov	rsi, mimelike$etag
	call	mimelike$getheader
	test	rax, rax
	jz	.skipetag
	mov	rdi, rax
	call	string$copy
	mov	r15, rax
	mov	rdi, [rbx+channel_etagmap_ofs]
	mov	rsi, [rbx+channel_urlstring_ofs]
	call	stringmap$find
	test	rax, rax
	jz	.etag_insert
	mov	rdi, [rax+_avlofs_value]
	mov	[rax+_avlofs_value], r15
	call	heap$free
	jmp	.skipetag
calign
.etag_insert:
	mov	rdi, [rbx+channel_etagmap_ofs]
	mov	rsi, [rbx+channel_urlstring_ofs]
	mov	rdx, r15
	call	stringmap$insert_unique
calign
.skipetag:
	cmp	dword [do_lastmod], 0
	je	.skiplastmod
	mov	rdi, r12
	mov	rsi, mimelike$lastmodified
	call	mimelike$getheader
	test	rax, rax
	jz	.skiplastmod
	mov	rdi, rax
	call	string$copy
	mov	r15, rax
	mov	rdi, [rbx+channel_modmap_ofs]
	mov	rsi, [rbx+channel_urlstring_ofs]
	call	stringmap$find
	test	rax, rax
	jz	.lastmod_insert
	mov	rdi, [rax+_avlofs_value]
	mov	[rax+_avlofs_value], r15
	call	heap$free
	jmp	.skiplastmod
calign
.lastmod_insert:
	mov	rdi, [rbx+channel_modmap_ofs]
	mov	rsi, [rbx+channel_urlstring_ofs]
	mov	rdx, r15
	call	stringmap$insert_unique
calign
.skiplastmod:
	; bytes received is next
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rdi, r14
	mov	rsi, [rdx+webclient_totalreceived_ofs]
	sub	rsi, [rbx+channel_startreceived_ofs]
	call	buffer$append_qword
	; bool for whether it was a keepalive or not
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rcx, [rbx+channel_startconnects_ofs]
	mov	rdi, r14
	xor	esi, esi
	mov	eax, 1
	cmp	rcx, [rdx+webclient_connects_ofs]
	cmove	esi, eax
	call	buffer$append_dword
	; ctime is next, which is the (current time - our starttime) - the response time
	mov	rsi, [_epoll_tv_msecs]
	mov	rdi, r14
	sub	rsi, [rbx+channel_starttime_ofs]
	sub	rsi, r13
	call	buffer$append_dword
	; dtime is next, which is current time - replystamp
	mov	rsi, [_epoll_tv_msecs]
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rdi, r14
	sub	rsi, [rdx+webclient_replystamp_ofs]
	call	buffer$append_dword
	; ttime is next, which is the current time - our start time
	mov	rsi, [_epoll_tv_msecs]
	mov	rdi, r14
	sub	rsi, [rbx+channel_starttime_ofs]
	call	buffer$append_dword
	; wait time, which is replystamp - our start time
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rdi, r14
	mov	rsi, [rdx+webclient_replystamp_ofs]
	sub	rsi, [rbx+channel_starttime_ofs]
	call	buffer$append_dword

	; if there is a server identifier, send it too
	mov	rdi, r12
	mov	rsi, .serverheader
	call	mimelike$getheader
	mov	rcx, .emptystr
	test	rax, rax
	cmovz	rax, rcx
	
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	add	rdx, 8
	call	buffer$append

	; and do the same for X-Powered-By if it is here
	mov	rdi, r12
	mov	rsi, .xpoweredbyheader
	call	mimelike$getheader
	mov	rcx, .emptystr
	test	rax, rax
	cmovz	rax, rcx
	
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	add	rdx, 8
	call	buffer$append

calign
.sendit:
if defined webslap_oldway_oneatatime
	; send it to our parent epoll object
	mov	rdi, [parentcomms]
	mov	rsi, [r14+buffer_itself_ofs]
	mov	rdx, [r14+buffer_length_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	
	mov	rdi, r14
	call	buffer$destroy
else
	; otherwise, we added it to the parentaccum, which will get emptied by the timer
	mov	esi, [r14+buffer_length_ofs]
	mov	rdi, [parentaccum]
	call	buffer$append_dword
	mov	rdi, [parentaccum]
	mov	rsi, [r14+buffer_itself_ofs]
	mov	edx, [r14+buffer_length_ofs]
	call	buffer$append
	mov	rdi, r14
	call	buffer$reset
end if
	sub	qword [requests], 1
	jz	.alldone
	mov	rdi, rbx
	call	channel_fire
	pop	r15 r14 r13 r12 rbx
	epilog
cleartext .serverheader, 'Server'
cleartext .emptystr, ''
cleartext .xpoweredbyheader, 'X-Powered-By'
calign
.failed:
	mov	rdi, r14
	mov	rsi, r12
	call	buffer$append_dword	; response code
	mov	rdi, r14
	xor	esi, esi
	call	buffer$append_dword
	mov	rdi, r14
	xor	esi, esi
	call	buffer$append_qword
	
	; bytes received is next
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rdi, r14
	mov	rsi, [rdx+webclient_totalreceived_ofs]
	sub	rsi, [rbx+channel_startreceived_ofs]
	call	buffer$append_qword
	; bool for whether it was a keepalive or not
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rcx, [rbx+channel_startconnects_ofs]
	mov	rdi, r14
	xor	esi, esi
	mov	eax, 1
	cmp	rcx, [rdx+webclient_connects_ofs]
	cmove	esi, eax
	call	buffer$append_dword
	; ctime is next, which is the (current time - our starttime) - the response time
	mov	rsi, [_epoll_tv_msecs]
	mov	rdi, r14
	sub	rsi, [rbx+channel_starttime_ofs]
	sub	rsi, r13
	call	buffer$append_dword
	; dtime is next, which is current time - replystamp
	mov	rsi, [_epoll_tv_msecs]
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rdi, r14
	sub	rsi, [rdx+webclient_replystamp_ofs]
	call	buffer$append_dword
	; ttime is next, which is the current time - our start time
	mov	rsi, [_epoll_tv_msecs]
	mov	rdi, r14
	sub	rsi, [rbx+channel_starttime_ofs]
	call	buffer$append_dword
	; wait time, which is replystamp - our start time
	mov	rdx, [rbx+channel_webclient_ofs]
	mov	rdi, r14
	mov	rsi, [rdx+webclient_replystamp_ofs]
	xor	ecx, ecx
	sub	rsi, [rbx+channel_starttime_ofs]
	cmp	rsi, 0
	cmovl	rsi, rcx
	call	buffer$append_dword

	; and two empty strings for the server/poweredby



	xor	ecx, ecx
	push	rcx rcx
	mov	rdi, r14
	mov	rsi, rsp
	mov	edx, 16
	call	buffer$append
	add	rsp, 16
	jmp	.sendit

calign
.alldone:
	pop	r15 r14 r13 r12 rbx
	epilog


falign
parentaccum$timer:
	prolog	parentaccum$timer
	mov	r8, [parentaccum]
	; send it to our parent epoll object
	mov	rdi, [parentcomms]
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	mov	rcx, [rdi]
	test	rdx, rdx
	jz	.nothingtodo
	call	qword [rcx+io_vsend]
	; reset our buffer
	mov	rdi, [parentaccum]
	call	buffer$reset
	; keep the timer going indefinitely
	xor	eax, eax
	epilog
calign
.nothingtodo:
	xor	eax, eax
	epilog
	


; no arguments, called from the worker function to create a new webclient/channel
falign
worker_channel:
	prolog	worker_channel
	push	rbx
	mov	edi, channel_size
	call	heap$alloc_clear
	mov	rbx, rax
	call	list$new
	mov	[rbx+channel_urls_ofs], rax
	mov	rdi, [urls]
	mov	rsi, .listcopy
	mov	rdx, rax
	call	list$foreach_arg
	cmp	dword [do_random], 0
	je	.noshuffle
	mov	rdi, [rbx+channel_urls_ofs]
	call	list$shuffle
calign
.noshuffle:
	mov	rdi, [rbx+channel_urls_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	[rbx+channel_cururl_ofs], rsi
	mov	edi, 1
	call	stringmap$new
	mov	[rbx+channel_etagmap_ofs], rax
	mov	edi, 1
	call	stringmap$new
	mov	[rbx+channel_modmap_ofs], rax
	xor	edi, edi
	call	webclient$new
	mov	[rbx+channel_webclient_ofs], rax

	; while we of course wait for responses to each request
	; before we fire off a new one, we make sure webclient
	; will never open more than one connection to a given host
	mov	dword [rax+webclient_maxconns_ofs], 1

	mov	rdi, [workerchannels]
	mov	rsi, rbx
	mov	rbx, rax
	call	list$push_back
	cmp	dword [do_keepalive], 1
	je	.noconnclose
	mov	rdi, rbx
	mov	rsi, mimelike$connection
	mov	rdx, .closestr
	call	webclient$addheader
calign
.noconnclose:
	cmp	dword [do_gzip], 1
	je	.noantigzip
	mov	rdi, rbx
	mov	rsi, mimelike$acceptencoding
	mov	rdx, .nonestr
	call	webclient$addheader
calign
.noantigzip:
	cmp	dword [do_cookies], 1
	jne	.skipcookiejar
	call	cookiejar$new
	mov	rdi, rbx
	mov	rsi, rax
	mov	edx, 1
	call	webclient$cookiejar
calign
.skipcookiejar:
	mov	eax, 1
	sub	eax, [do_tlsresume]
	mov	[rbx+webclient_notlsresume_ofs], rax
	; etag and lastmod are handled per-request as they must be
	pop	rbx
	epilog
cleartext .closestr, 'close'
cleartext .nonestr, 'none'
falign
.listcopy:
	; we are passed rdi == key, rsi == list to add
	xchg	rdi, rsi
	call	list$push_back
	ret


; so when the parent process calls epoll_child (and thus forks), this is our
; child process entry main entry point
; single argument in rdi: our file descriptor to talk to our parent with
falign
worker:
	prolog	worker
	; epoll does funny things across forks, and since we know our parent
	; had epoll already running prior to us ever being thought of, we
	; need to redo our own epoll state such that we get our very own
	; epoll$init does take care of CLOEXEC for us though, so it doesn't
	; hurt for us to just call epoll$init again
	push	rdi
if profiling
	call	profiler$reset
end if
	call	epoll$init
	; in addition, we need to make sure our rng is also reinitialized
	; because we don't want to share the same rng state as our siblings
	call	rng$init
	; create our parentaccum
	call	buffer$new
	mov	[parentaccum], rax
	; create our working buffer
	call	buffer$new
	mov	[workingbuf], rax
	; create the parentaccum timer
	call	io$new
	mov	qword [rax], parentaccum$vtable
	mov	edi, 50		; every 50ms
	mov	rsi, rax
	call	epoll$timer_new

	; so now, we can create our own epoll object to talk to our parent with
	; and wait for our first atomic message from the parent telling us
	; which child # we are

	mov	rdi, .worker_parentcomms_vtable
	xor	esi, esi
	call	epoll$new
	mov	[parentcomms], rax
	pop	rdi
	mov	rsi, rax
	call	epoll$established

if profiling
	mov	rdi, .profiler_err1
	cmp	dword [do_ui], 0
	jne	.profiler_errmsg
	mov	rdi, .profiler_err2
	cmp	dword [cpucount], 1
	jne	.profiler_errmsg

	; otherwise, go ahead and fire up a tui_profiler
	call	tui_profiler$new
	mov	rdi, rax
	call	tui_terminal$new
end if
	call	epoll$run		; doesn't come back
	epilog	; not reached
if profiling
cleartext .profiler_err1, 'ERROR: Profiling TUI component requires -noui mode.'
cleartext .profiler_err2, 'ERROR: Profiling TUI component requires cpu count to be 1.'
calign
.profiler_errmsg:
	call	string$to_stdoutln
	call	epoll$run
	epilog	; not reached
end if
falign
.parentcomms:
	push	rbx
	mov	rbx, rdi
	; again, even though this is declared as a private label with our worker
	; function, it is called wholly independently whenever our parent says
	; anything, which in our case is two different possibilities:
	; the first 8 bytes we get is our cpu#, and the next is our starting gun
	cmp	qword [workerid], -1
	je	.parentcomms_initial

	; otherwise, we know this means a starting gun fire, so off we go
	mov	rdi, [rdi+epoll_inbuf_ofs]
	call	buffer$reset

	mov	rdi, [workerchannels]
	mov	rsi, channel_fire
	call	list$foreach
	pop	rbx
	xor	eax, eax		; don't kill our parent comms channel
	ret
calign
.parentcomms_initial:
	push	r12 r13
	mov	rax, [rsi]
	mov	[workerid], rax

	mov	rdi, [rdi+epoll_inbuf_ofs]
	mov	esi, 8
	call	buffer$consume
	; so now, we need to determine how many requests we are handling, and how many
	; webclients we are firing up to deal with them
	xor	edx, edx
	mov	rax, [requests]
	div	qword [cpucount]
	test	rdx, rdx
	jz	.parentcomms_initial_noremainder
	mov	rcx, rax
	add	rcx, 1
	cmp	qword [workerid], rdx
	cmovb	rax, rcx
calign
.parentcomms_initial_noremainder:
	; save that back into requests for our request count
	mov	[requests], rax
	; so now that we know exactly how many requests we have to deal with, do the same
	; for our concurrency
	xor	edx, edx
	mov	rax, [concurrency]
	div	qword [cpucount]
	test	rdx, rdx
	jz	.parentcomms_initial_noremainder2
	mov	rcx, rax
	add	rcx, 1
	cmp	qword [workerid], rdx
	cmovb	rax, rcx
calign
.parentcomms_initial_noremainder2:
	; save that back into concurrency for our webclient count
	mov	[concurrency], rax

if defined workerparamdebug
	; debug
	mov	rdi, [workerid]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, .debug1
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .debug2
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, [requests]
	mov	esi, 10
	call	string$from_unsigned
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r12
	mov	rsi, .debug3
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, [concurrency]
	mov	esi, 10
	call	string$from_unsigned
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r12
	call	string$to_stdoutln
	mov	rdi, r12
	call	heap$free
	; end debug
end if

	; so now, we can create our channels

	call	list$new
	mov	[workerchannels], rax

	mov	r12, [concurrency]
calign
.channelcreate:
	call	worker_channel
	sub	r12d, 1
	jnz	.channelcreate

	pop	r13 r12
	
	mov	rdi, rbx
	pop	rbx
	mov	rsi, [rdi+epoll_inbuf_ofs]
	cmp	qword [rsi+buffer_length_ofs], 0
	jne	.parentcomms
	xor	eax, eax		; don't kill our parent connection
	ret

if defined workerparamdebug
cleartext .debug1, 'Worker ID '
cleartext .debug2, ' Requests: '
cleartext .debug3, ' WebClients: '
end if

dalign
.worker_parentcomms_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, .parentcomms, io$error, io$timeout
