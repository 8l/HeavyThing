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
	; master.inc: webslap master process goods
	;

globals
{
	; so that we can delay launch until after our splash screen:
	workers		dq	0
	; test variables
	begin		dq	0		; timestamp of when we actually started the test
	begin_msecs	dq	0		; ctime in milliseconds of start
	completed	dq	0		; how many requests we have completed
	failed		dq	0		; how many requests actually failed (webclient_fail_{dns,preconnect,closed,timeout})
	non2xx		dq	0		; how many requests returned a non 2xx result (not including fails)
	keepalives	dq	0		; how many requests were sent in an already-open http session
	total_received	dq	0		; how many bytes in total (not including TLS overhead) we received
	header_received	dq	0		; how many bytes of http headers we received
	body_received	dq	0		; how many bytes of decoded body we received (this includes ungzip'd body sizes, unchunking, etc)
	; we keep an unsignedmap of total times
	timing_ttime	dq	0		; ttime == total time it took from the time we issued the request til when it finished

	ctime_min	dq	-1
	ctime_max	dq	0
	ctime_total	dq	0
	dtime_min	dq	-1
	dtime_max	dq	0
	dtime_total	dq	0
	wait_min	dq	-1
	wait_max	dq	0
	wait_total	dq	0
	; per-response timing map (keyed by int of response code)
	responsemap	dq	0
	; per-URL timing map, which is a map of responsemaps
	urlmap		dq	0
	; unique Server header map
	servermap	dq	0
	; unique X-Powered-By header map
	xpoweredbymap	dq	0

	; TSV working buffer
	tsvbuf		dq	0
	; counters for noui status updates
	reqdivten	dq	0
	reqdivctr	dq	0

	; spot that build_json sticks its results into
	master_json	dq	0
	; formatter object for the completed timestamp
	datetimeformat	dq	0
	; noui formatters
	noui_rmap	dq	0
	noui_unsigned	dq	0
	noui_dec2	dq	0
	noui_dec3	dq	0
	noui_timeformat	dq	0
}

include 'master_ui.inc'

; no arguments, main entrypoint from webslap.asm/_start:
; Note to self: Hahah, all my local-labelled functions inside here is pretty poor form, hahah
; TODO: Someday when I am bored, come back through and clean this up.
falign
master:
	prolog	master
	call	list$new
	mov	[workers], rax
	xor	edi, edi
	call	unsignedmap$new
	mov	[timing_ttime], rax

	xor	edi, edi
	call	unsignedmap$new
	mov	[responsemap], rax
	mov	edi, 1
	call	stringmap$new
	mov	[urlmap], rax
	mov	rdi, [urls]
	mov	rsi, .urlmapinit
	mov	rdx, rax
	call	list$foreach_arg
	mov	edi, 1
	call	stringmap$new
	mov	[servermap], rax
	mov	edi, 1
	call	stringmap$new
	mov	[xpoweredbymap], rax
	
	xor	edi, edi
	call	formatter$new
	mov	[datetimeformat], rax
	mov	rdi, rax
	call	formatter$add_rfc5322datetime

	; create our noui_rmap formatter
	xor	edi, edi
	call	formatter$new
	mov	[noui_rmap], rax
	mov	rdi, rax
	mov	rbx, rax
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned		; count
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned		; min
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned		; max
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned		; avg
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 9
	call	formatter$add_unsigned		; hdrs
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 9
	call	formatter$add_unsigned		; total
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 9
	call	formatter$add_unsigned		; body
	mov	rdi, rbx
	mov	rsi, .lf
	call	formatter$add_static

	xor	edi, edi
	call	formatter$new
	mov	[noui_unsigned], rax
	mov	rdi, rax
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned

	xor	edi, edi
	call	formatter$new
	mov	[noui_dec2], rax
	mov	rdi, rax
	mov	esi, double_string_fixed
	mov	edx, 2
	xor	ecx, ecx
	mov	r8d, 1
	call	formatter$add_double

	xor	edi, edi
	call	formatter$new
	mov	[noui_dec3], rax
	mov	rdi, rax
	mov	esi, double_string_fixed
	mov	edx, 3
	xor	ecx, ecx
	mov	r8d, 1
	call	formatter$add_double

	xor	edi, edi
	call	formatter$new
	mov	[noui_timeformat], rax
	mov	rbx, rax
	mov	rdi, rax
	mov	esi, 18
	call	formatter$add_string
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned
	mov	rdi, rbx
	mov	rsi, .doublespace
	call	formatter$add_static
	mov	rdi, rbx
	mov	esi, 1
	mov	edx, 7
	call	formatter$add_unsigned
	mov	rdi, rbx
	mov	rsi, .lf
	call	formatter$add_static

	call	buffer$new
	mov	[tsvbuf], rax

	mov	rdi, rax
	mov	rsi, .tsvheader
	call	buffer$append_string

	xor	edx, edx
	mov	ecx, 10
	mov	rax, [requests]
	div	rcx
	mov	[reqdivten], rax
	mov	[reqdivctr], rax

	mov	rbx, [cpucount]
	xor	r12d, r12d
calign
.spawnloop:
	mov	rdi, .master_childcomms_vtable
	mov	rsi, worker
	call	epoll_child
	test	rax, rax
	jz	.forkfail
	mov	r13, rax
	mov	rdi, [workers]
	mov	rsi, rax
	call	list$push_back
	push	r12
	mov	rdi, r13
	mov	rsi, rsp
	mov	edx, 8
	mov	rcx, [r13]
	call	qword [rcx+io_vsend]
	pop	r12
	add	r12d, 1
	sub	ebx, 1
	jnz	.spawnloop

	call	timestamp
	movq	[begin], xmm0
	call	epoll$timestamp
	mov	[begin_msecs], rax

	; so now all our children are fired up and know which # they are
	; now all thats left is firing up our TUI and waiting for things to complete
	cmp	dword [do_ui], 0
	je	.noui

	call	master_ui

	call	epoll$run	; doesn't come back
	epilog	; not reached
cleartext .tsvheader, 'URL',9,'time',9,'rcode',9,'ctime',9,'dtime',9,'ttime',9,'wait',10
calign
.noui:
	mov	rdi, .startmsg
	call	string$to_stdoutln

	mov	rdi, [workers]
	mov	rsi, .starting_gun
	call	list$foreach

	call	epoll$run	; doesn't come back
	epilog	; not reached
cleartext .startmsg, 'Happily slapping...'
falign
.starting_gun:
	mov	ecx, 'DOIT'
	mov	edx, 8
	mov	rax, [rdi]
	push	rcx
	mov	rsi, rsp
	call	qword [rax+io_vsend]
	add	rsp, 8
	ret
timemap_min_ofs = 0
timemap_max_ofs = 4
timemap_count_ofs = 8
timemap_headers_ofs = 12
timemap_time_ofs = 16
timemap_total_ofs = 24
timemap_body_ofs = 32
timemap_size = 40
falign
.urlmapinit:
	; rdi == string url, rsi == urlmap
	push	rdi rsi
	xor	edi, edi
	call	unsignedmap$new
	pop	rdi rsi
	mov	rdx, rax
	call	stringmap$insert_unique
	ret
cleartext .doublespace, '  '
cleartext .lf, 10

; rdi == timemap object, esi == ttime, edx == hdrlen, rcx == totlen, r8 == bodylen
falign
.timemap_update:
	add	dword [rdi+timemap_count_ofs], 1
	add	dword [rdi+timemap_headers_ofs], edx
	add	qword [rdi+timemap_total_ofs], rcx
	mov	r9d, [rdi+timemap_min_ofs]
	mov	r10d, [rdi+timemap_max_ofs]
	cmp	esi, r9d
	cmovb	r9d, esi
	add	qword [rdi+timemap_time_ofs], rsi
	cmp	esi, r10d
	cmova	r10d, esi
	mov	[rdi+timemap_min_ofs], r9d
	mov	[rdi+timemap_max_ofs], r10d
	add	qword [rdi+timemap_body_ofs], r8
	ret
; rdi == responsemap, esi == response code we are looking for
; returns timemap object in rax
falign
.responsemap_get:
	push	rdi rsi
	call	unsignedmap$find_value
	test	eax, eax
	cmovnz	rax, rdx
	jz	.responsemap_get_newone
	pop	rsi rdi
	ret
calign
.responsemap_get_newone:
	mov	edi, timemap_size
	call	heap$alloc_clear
	mov	dword [rax+timemap_min_ofs], -1
	mov	rdi, [rsp+8]
	mov	rsi, [rsp]
	mov	[rsp], rax
	mov	rdx, rax
	call	unsignedmap$insert_unique
	pop	rax rdi
	ret
	
falign
.childcomms:
	; even though this is declared as a private label with our master function, it is 
	; called wholly independently whenever one of our worker children say anything to us
	; it is up to us to manage epoll_inbuf_ofs, but we get passed its start/end ptr anyway
	push	rbx r12 r13 r14 r15
	; we know our comms from children come through atomically, so we don't bother to validate
	; any of what we receive, it is known good
	mov	rbx, [rdi+epoll_inbuf_ofs]
	mov	r12, [rbx+buffer_itself_ofs]
	mov	r14, [rbx+buffer_length_ofs]
	mov	r15, r12
calign
.childcomms_processinput:
	; each entry is prefaced by its entire length, make sure we have enough
	cmp	r14d, 4
	jbe	.childcomms_needmore

	mov	eax, [r12]
	add	r12, 4		; our pointer
	sub	r14d, 4		; how much remains
	cmp	eax, r14d
	ja	.childcomms_needmore
	lea	r15, [r12+rax]	; pointer to the next record
	sub	r14d, eax	; how much is left after this record
	; otherwise, we have enough to proceed

	push	r12
	mov	rax, [r12]

if string_bits = 32
	shl	rax, 2
else
	shl	rax, 1
end if
	add	rax, 8
	mov	rdi, [tsvout]
	add	r12, rax

	test	rdi, rdi
	jz	.childcomms_skiptsv
	mov	r13, [tsvbuf]
	mov	rdi, r13
	mov	rsi, [rbx+buffer_itself_ofs]
	call	buffer$append_string
	mov	rdi, r13
	mov	esi, 9
	call	buffer$append_byte

	mov	rdi, [_epoll_tv_secs]
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, 9
	call	buffer$append_byte

	movsxd	rdi, dword [r12]	; response code
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, 9
	call	buffer$append_byte
	
	movsxd	rdi, dword [r12+28]	; ctime
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, 9
	call	buffer$append_byte
	
	movsxd	rdi, dword [r12+32]	; dtime
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, 9
	call	buffer$append_byte
	
	movsxd	rdi, dword [r12+36]	; ttime
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, 9
	call	buffer$append_byte
	
	movsxd	rdi, dword [r12+40]	; wait
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, 10
	call	buffer$append_byte
	
	cmp	qword [r13+buffer_length_ofs], 65536
	jb	.childcomms_skiptsv

	mov	rdi, r13
	mov	rsi, [tsvout]
	call	buffer$file_append
	mov	rdi, r13
	call	buffer$reset

calign
.childcomms_skiptsv:
	; find our url in the urlmap
	mov	rdi, [urlmap]
	pop	rsi
	call	stringmap$find_value
	mov	r13, rdx

	mov	eax, [r12]		; response code
	mov	ecx, [r12+4]		; header size
	mov	rdx, [r12+8]		; body size
	mov	r8, [r12+16]		; bytes received
	mov	r9d, [r12+24]		; keepalive
	add	qword [completed], 1
	mov	r10, [failed]
	mov	r11, r10
	add	r11, 1
	cmp	eax, 0
	cmovl	r10, r11
	mov	[failed], r10
	jl	.childcomms_skipnon2xx
	mov	r10, [non2xx]
	mov	r11, r10
	add	r11, 1
	cmp	eax, 200
	cmovb	r10, r11
	cmp	eax, 300
	cmovae	r10, r11
	mov	[non2xx], r10
calign
.childcomms_skipnon2xx:
	mov	r10, [keepalives]
	mov	r11, r10
	add	r11, 1
	test	r9d, r9d
	cmovnz	r10, r11
	mov	[keepalives], r10
	add	[total_received], r8
	add	[header_received], rcx
	add	[body_received], rdx
	mov	edx, [r12+28]
	mov	r8d, [r12+32]
	mov	eax, dword [ctime_min]
	mov	ecx, dword [ctime_max]
	mov	r9d, dword [dtime_min]
	mov	r10d, dword [dtime_max]
	cmp	edx, eax
	cmovb	eax, edx
	cmp	edx, ecx
	cmova	ecx, edx
	add	qword [ctime_total], rdx
	add	qword [dtime_total], r8
	cmp	r8d, r9d
	cmovb	r9d, r8d
	cmp	r8d, r10d
	cmova	r10d, r8d
	mov	[ctime_min], rax
	mov	[ctime_max], rcx
	mov	[dtime_min], r9
	mov	[dtime_max], r10
	mov	rdi, [timing_ttime]
	mov	esi, [r12+36]		; key == ttime
	mov	edx, [r12]		; value == response code
	call	unsignedmap$insert
	mov	edx, [r12+40]
	mov	eax, dword [wait_min]
	mov	ecx, dword [wait_max]
	cmp	edx, eax
	cmovb	eax, edx
	cmp	edx, ecx
	cmova	ecx, edx
	add	qword [wait_total], rdx
	mov	[wait_min], rax
	mov	[wait_max], rcx

	; r13 == urlmap responsemap object
	mov	rdi, r13
	mov	esi, [r12]
	call	.responsemap_get
	mov	rdi, rax
	mov	esi, [r12+36]		; ttime
	mov	edx, [r12+4]		; header length
	mov	rcx, [r12+16]		; total received
	mov	r8, [r12+8]		; bodylen
	call	.timemap_update
	
	; now do the same for the overall responsemap, not just url based
	mov	rdi, [responsemap]
	mov	esi, [r12]
	call	.responsemap_get

	mov	rdi, rax
	mov	esi, [r12+36]		; ttime
	mov	edx, [r12+4]		; header length
	mov	rcx, [r12+16]		; total received
	mov	r8, [r12+8]		; bodylen
	call	.timemap_update
	

	; after the wait time at [r12+40], we have a Server string identifier (which may be empty)
	lea	r12, [r12+44]
	cmp	qword [r12], 0
	je	.childcomms_serverhere
	mov	rdi, [servermap]
	mov	rsi, r12
	call	stringmap$find
	test	rax, rax
	jnz	.childcomms_serverhere
	mov	rdi, r12
	call	string$copy
	mov	rdi, [servermap]
	mov	rsi, rax
	xor	edx, edx
	call	stringmap$insert_unique
calign
.childcomms_serverhere:
	; skip the server, and go to the X-Powered-By
	mov	rsi, [r12]
if string_bits = 32
	shl	rsi, 2
else
	shl	rsi, 1
end if
	lea	r12, [r12+rsi+8]
	cmp	qword [r12], 0
	je	.childcomms_xpoweredbyhere
	mov	rdi, [xpoweredbymap]
	mov	rsi, r12
	call	stringmap$find
	test	rax, rax
	jnz	.childcomms_xpoweredbyhere
	mov	rdi, r12
	call	string$copy
	mov	rdi, [xpoweredbymap]
	mov	rsi, rax
	xor	edx, edx
	call	stringmap$insert_unique
calign
.childcomms_xpoweredbyhere:

	; we already ahve a pointer to our next record

	sub	qword [requests], 1
	jz	.alldone

	cmp	dword [do_ui], 0
	je	.statuscheck

	mov	r12, r15
	jmp	.childcomms_processinput
calign
.statuscheck:
if profiling
	; profiling == no status output
	jmp	.nostatusupdate
end if
	; if reqdivten is zero, no status updates required in the first place
	cmp	qword [reqdivten], 0
	je	.nostatusupdate
	mov	rax, [reqdivten]
	sub	qword [reqdivctr], 1
	jnz	.nostatusupdate
	mov	[reqdivctr], rax
	mov	rdi, .completedpreface
	call	string$to_stdout
	mov	rdi, [completed]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .completedpostface
	call	string$to_stdoutln

	mov	r12, r15
	jmp	.childcomms_processinput
cleartext .completedpreface, 'Completed '
cleartext .finishedpreface, 'Finished '
cleartext .completedpostface, ' requests'
calign
.nostatusupdate:
	; if there is still data sitting in our inbuf, go back around for more
	mov	r12, r15
	jmp	.childcomms_processinput
calign
.alldone:
	mov	rdi, rbx
	call	buffer$reset

if profiling
	jmp	.alldone_profiling
end if

	mov	edi, 1			; final json please
	call	build_json

	cmp	dword [do_ui], 0
	jne	.alldone_ui

	mov	rdi, .finishedpreface
	call	string$to_stdout
	mov	rdi, [completed]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .completedpostface
	call	string$to_stdoutln

	mov	rdi, .emptystr
	call	string$to_stdoutln


	mov	edi, 1			; final text please
	call	build_text
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free

	mov	eax, syscall_exit
	mov	edi, 0
	syscall

calign
.childcomms_needmore:
	; r15 - buffer_itself_ofs == how much we actually used
	mov	rdi, rbx
	mov	rsi, r15
	sub	rsi, [rbx+buffer_itself_ofs]
	jz	.childcomms_needmore_noconsume
	call	buffer$consume
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	ret
calign
.childcomms_needmore_noconsume:
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	ret
calign
.alldone_ui:
	call	master_ui_complete

	pop	r15 r14 r13 r12 rbx
	xor	eax, eax		; don't kill the child connection
	ret
if profiling
calign
.alldone_profiling:
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax		; don't kill the child connection
	ret
end if
	

calign
.forkfail:
	mov	rdi, .err_forkfail
	call	string$to_stdoutln
	call	epoll_child_killall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .emptystr, ''
cleartext .err_forkfail, 'Fatal: fork or socketpair failed.'
dalign
.master_childcomms_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, .childcomms, io$error, io$timeout


cleartext obj$servers, 'Server'
cleartext obj$xpoweredby, 'X-Powered-By'
cleartext obj$concurrency, 'concurrency'
cleartext obj$time_taken, 'time_taken'
cleartext obj$time_completed, 'time_completed'
cleartext obj$completed, 'completed'
cleartext obj$failed, 'failed'
cleartext obj$non2xx, 'non2xx'
cleartext obj$keepalives, 'keepalives'
cleartext obj$total_received, 'total_received'
cleartext obj$header_received, 'header_received'
cleartext obj$body_received, 'body_received'
cleartext obj$response_codes, 'response_codes'
cleartext obj$urls, 'urls'
cleartext obj$url, 'url'
cleartext obj$reqpersec, 'requests_per_second'
cleartext obj$tps, 'time_per_request'
cleartext obj$ctps, 'concurrent_time_per_request'
cleartext obj$wiretransferrate, 'wire_transfer_rate'
cleartext obj$bodytransferrate, 'body_transfer_rate'
cleartext obj$ctime_min, 'ctime_min'
cleartext obj$ctime_max, 'ctime_max'
cleartext obj$ctime_avg, 'ctime_avg'
cleartext obj$dtime_min, 'dtime_min'
cleartext obj$dtime_max, 'dtime_max'
cleartext obj$dtime_avg, 'dtime_avg'
cleartext obj$ttime_min, 'ttime_min'
cleartext obj$ttime_max, 'ttime_max'
cleartext obj$ttime_avg, 'ttime_avg'
cleartext obj$wait_min, 'wait_min'
cleartext obj$wait_max, 'wait_max'
cleartext obj$wait_avg, 'wait_avg'

cleartext obj$code, 'code'
cleartext obj$count, 'count'
cleartext obj$mintime, 'min_time'
cleartext obj$maxtime, 'max_time'
cleartext obj$avgtime, 'avg_time'
cleartext obj$headers, 'header_received'
cleartext obj$total, 'total_received'
cleartext obj$body, 'body_received'


; single argument in edi: bool as to whether it is the final one or not
falign
build_text:
	prolog	build_text

	push	rbx r12 r13 r14 r15
	mov	r15d, edi
	call	buffer$new
	mov	r14, rax

	; if we have a server list, spew it
	mov	rdi, [master_json]
	mov	rsi, obj$servers
	call	json$getvaluebyname
	test	rax, rax
	jz	.skipservers
	mov	rbx, rax
	mov	r12, [rax+json_contents_ofs]	; the list (from a json array)
	mov	r12, [r12+_list_first_ofs]
	test	r12, r12
	jz	.skipservers

	mov	rdi, r14
	mov	rsi, .serverpreface
	call	buffer$append_rawstring
	; dump the first one
	mov	rsi, [r12+_list_valueofs]
	mov	rsi, [rsi+json_value_ofs]
	mov	rdi, r14
	call	buffer$append_rawstring
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jz	.servers_done
calign
.serverloop:
	mov	rdi, r14
	mov	rsi, .commaspace
	call	buffer$append_rawstring
	mov	rsi, [r12+_list_valueofs]
	mov	rsi, [rsi+json_value_ofs]
	mov	rdi, r14
	call	buffer$append_rawstring
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jnz	.serverloop
calign
.servers_done:
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
calign
.skipservers:
	; do the same for our x-poweredby
	mov	rdi, [master_json]
	mov	rsi, obj$xpoweredby
	call	json$getvaluebyname
	test	rax, rax
	jz	.skipxpoweredby
	mov	rbx, rax
	mov	r12, [rax+json_contents_ofs]	; the list (from a json array)
	mov	r12, [r12+_list_first_ofs]
	test	r12, r12
	jz	.skipxpoweredby

	mov	rdi, r14
	mov	rsi, .xpoweredbypreface
	call	buffer$append_rawstring
	; dump the first one
	mov	rsi, [r12+_list_valueofs]
	mov	rsi, [rsi+json_value_ofs]
	mov	rdi, r14
	call	buffer$append_rawstring
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jz	.xpoweredby_done
calign
.xpoweredbyloop:
	mov	rdi, r14
	mov	rsi, .commaspace
	call	buffer$append_rawstring
	mov	rsi, [r12+_list_valueofs]
	mov	rsi, [rsi+json_value_ofs]
	mov	rdi, r14
	call	buffer$append_rawstring
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jnz	.xpoweredbyloop
calign
.xpoweredby_done:
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
calign
.skipxpoweredby:
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	
	mov	rdi, r14
	mov	rsi, .rmapheader
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	
	; iterate our response code map
	; no sense in dealing with the json output really
	mov	rdi, [responsemap]
	mov	rsi, .responsemap_output
	mov	rdx, r14
	call	unsignedmap$foreach_arg

	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	
	; do the same thing again with our urlmap
	mov	rdi, [urlmap]
	mov	rsi, .urlmap_output
	mov	rdx, r14
	call	stringmap$foreach_arg

	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	test	r15d, r15d
	jz	.skiptimecompleted
	mov	rdi, r14
	mov	rsi, .timecompletedpreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$time_completed
	call	json$getvaluebyname
	mov	rdi, r14
	mov	rsi, [rax+json_value_ofs]
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
calign
.skiptimecompleted:
	mov	rdi, r14
	mov	rsi, .concurrencypreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [concurrency]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	mov	rdi, r14
	mov	rsi, .timetakenpreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$time_taken
	call	json$getvaluebyname
	mov	rdi, r14
	mov	rsi, [rax+json_value_ofs]
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .finalcompletedpreface
	mov	rdx, .partcompletedpreface
	test	r15d, r15d
	cmovz	rsi, rdx
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [completed]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	mov	rdi, r14
	mov	rsi, .failedpreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [failed]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	mov	rdi, r14
	mov	rsi, .keepalivepreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [keepalives]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	mov	rdi, r14
	mov	rsi, .non2xxpreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [non2xx]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	mov	rdi, r14
	mov	rsi, .totalpreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [total_received]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .bytespostface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .headerpreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [header_received]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .bytespostface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .bodypreface
	call	buffer$append_rawstring
	mov	rdi, [noui_unsigned]
	mov	rsi, [body_received]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .bytespostface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .rpspreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$reqpersec
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_double
	mov	rdi, [noui_dec2]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .rpspostface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .tpspreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$tps
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_double
	mov	rdi, [noui_dec3]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .tpspostface1
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .tpspreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$ctps
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_double
	mov	rdi, [noui_dec3]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .tpspostface2
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .wirexferpreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$wiretransferrate
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_double
	mov	rdi, [noui_dec2]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .xferpostface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .bodyxferpreface
	call	buffer$append_rawstring
	mov	rdi, [master_json]
	mov	rsi, obj$bodytransferrate
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_double
	mov	rdi, [noui_dec2]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free
	mov	rdi, r14
	mov	rsi, .xferpostface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring
	
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	mov	rdi, r14
	mov	rsi, .timingpreface
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .lf
	call	buffer$append_rawstring

	xor	edx, edx
	mov	rcx, [completed]
	mov	rax, [ctime_total]
	div	rcx
	mov	rdi, [noui_timeformat]
	mov	rsi, .connectpreface
	mov	rdx, [ctime_min]
	mov	rcx, rax
	mov	r8, [ctime_max]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	xor	edx, edx
	mov	rcx, [completed]
	mov	rax, [dtime_total]
	div	rcx
	mov	rdi, [noui_timeformat]
	mov	rsi, .processingpreface
	mov	rdx, [dtime_min]
	mov	rcx, rax
	mov	r8, [dtime_max]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	xor	edx, edx
	mov	rcx, [completed]
	mov	rax, [wait_total]
	div	rcx
	mov	rdi, [noui_timeformat]
	mov	rsi, .waitpreface
	mov	rdx, [wait_min]
	mov	rcx, rax
	mov	r8, [wait_max]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	; so we don't have to calculate ttimes again, just pull them from master_json
	mov	rdi, [master_json]
	mov	rsi, obj$ttime_max
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_unsigned
	push	rax

	mov	rdi, [master_json]
	mov	rsi, obj$ttime_avg
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_unsigned
	push	rax

	mov	rdi, [master_json]
	mov	rsi, obj$ttime_min
	call	json$getvaluebyname
	mov	rdi, [rax+json_value_ofs]
	call	string$to_unsigned

	mov	rdi, [noui_timeformat]
	mov	rsi, .totaltimepreface
	mov	rdx, rax
	pop	rcx
	pop	r8
	call	formatter$doit
	mov	r12, rax
	mov	rdi, r14
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r12
	call	heap$free

	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, [r14+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	mov	rdi, r14
	mov	r14, rax
	call	buffer$destroy
	mov	rax, r14

	pop	r15 r14 r13 r12 rbx

if defined jsondebug
	mov	rdi, [master_json]
	call	json$tostring
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	epilog
cleartext .commaspace, ', '
cleartext .lf, 10
cleartext .serverpreface, 'Server Software:        '
cleartext .xpoweredbypreface, 'X-Powered-By:           '
cleartext .concurrencypreface, 'Concurrency Level:      '
cleartext .timetakenpreface, 'Time taken for tests:   '
cleartext .timecompletedpreface,  'Time completed:         '
cleartext .partcompletedpreface,  'Requests so far:        '
cleartext .finalcompletedpreface, 'Total requests:         '
cleartext .keepalivepreface,      'Keep-alive requests:    '
cleartext .non2xxpreface,         'Non-2xx requests:       '
cleartext .failedpreface, 'Failed requests:        '
cleartext .totalpreface, 'Total transferred:      '
cleartext .headerpreface, 'Headers transferred:    '
cleartext .bodypreface, 'Body transferred:       '
cleartext .bytespostface, ' bytes'
cleartext .rpspreface, 'Requests per second:    '
cleartext .rpspostface, ' [#/sec] (mean)'
cleartext .tpspreface, 'Time per request:       '
cleartext .tpspostface1, ' [ms] (mean)'
cleartext .tpspostface2, ' [ms] (mean, across all concurrent requests)'
cleartext .wirexferpreface, 'Wire Transfer rate:     '
cleartext .bodyxferpreface, 'Body Transfer rate:     '
cleartext .xferpostface, ' [Kbytes/sec] received'
cleartext .rmapheader, '  code    count      min      avg      max     kbhdrs    kbtotal     kbbody'
cleartext .rcodeconnectfail, ' --C--'
cleartext .rcodeclosedfail, ' --R--'
cleartext .rcodetimeoutfail, ' --T--'
cleartext .urlpreface, 'URL: '
cleartext .timingpreface, '                      min      avg      max'
cleartext .connectpreface, 'Connect Time:     '
cleartext .processingpreface, 'Processing Time:  '
cleartext .waitpreface, 'Waiting Time:     '
cleartext .totaltimepreface, 'Total Time:       '
falign
.urlmap_output:
	; rdi == string url, rsi == responsemap object, rdx == buffer to append to
	push	rbx rsi rdi
	mov	rbx, rdx
	mov	rdi, rdx
	mov	rsi, .urlpreface
	call	buffer$append_rawstring
	pop	rsi
	mov	rdi, rbx
	call	buffer$append_rawstring
	mov	rdi, rbx
	mov	rsi, .lf
	call	buffer$append_rawstring
	; we need to add an extra preface for each of our response codes
	pop	rdi
	mov	rsi, .responsemap_output
	mov	rdx, rbx
	call	unsignedmap$foreach_arg
	pop	rbx
	ret
falign
.responsemap_output:
	; edi == responsecode, rsi == timemap object, rdx == buffer to append to
	push	rbx r12
	mov	r12, rdx
	mov	rbx, rsi
	cmp	edi, -2
	je	.responsemap_output_connectfail
	cmp	edi, -3
	je	.responsemap_output_closed
	cmp	edi, -4
	je	.responsemap_output_timeout
	movsxd	rdi, edi
	mov	esi, 10
	call	string$from_int
	push	rax
	mov	rdi, rax
	mov	esi, 6
	mov	edx, ' '
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, [rsp]
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
	jmp	.responsemap_output_timemap
calign
.responsemap_output_connectfail:
	mov	rdi, r12
	mov	rsi, .rcodeconnectfail
	call	buffer$append_rawstring
	jmp	.responsemap_output_timemap
calign
.responsemap_output_closed:
	mov	rdi, r12
	mov	rsi, .rcodeclosedfail
	call	buffer$append_rawstring
	jmp	.responsemap_output_timemap
calign
.responsemap_output_timeout:
	mov	rdi, r12
	mov	rsi, .rcodetimeoutfail
	call	buffer$append_rawstring
calign
.responsemap_output_timemap:
	xor	edx, edx
	mov	rax, [rbx+timemap_time_ofs]
	mov	esi, [rbx+timemap_count_ofs]
	div	rsi
	mov	rcx, rax

	mov	rdi, [noui_rmap]
	mov	esi, [rbx+timemap_count_ofs]
	mov	edx, [rbx+timemap_min_ofs]
	mov	r8d, [rbx+timemap_max_ofs]
	mov	r9d, [rbx+timemap_headers_ofs]
	mov	r10, [rbx+timemap_total_ofs]
	mov	r11, [rbx+timemap_body_ofs]
	shr	r9, 10
	shr	r10, 10
	shr	r11, 10
	call	formatter$doit
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
	pop	r12 rbx
	ret






; single argument in rdi: a responsemap (one is held globally for all requests, and each url gets one too)
; returns a new named json array in rax with the goods (and each array item is a json object)
falign
responsemap_to_json:
	prolog	responsemap_to_json
	push	rdi
	mov	rdi, .arrayname
	call	json$newarray
	mov	rdi, [rsp]
	mov	[rsp], rax
	mov	rsi, .eachitem
	mov	rdx, rax
	call	unsignedmap$foreach_arg
	pop	rax
	epilog
cleartext .arrayname, 'response_codes'
cleartext .emptystr, ''
falign
.eachitem:
	; edi == responsecode, rsi == timemap object, rdx == jsonarray destination
	push	rbx r12 r13 rdx
	mov	r12d, edi
	mov	rbx, rsi
	mov	rdi, .emptystr
	call	json$newobject
	mov	r13, rax
	movsxd	rdi, r12d
	mov	esi, 10
	call	string$from_int
	mov	r12, rax
	mov	rdi, obj$code
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	mov	edi, [rbx+timemap_count_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$count
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	mov	edi, [rbx+timemap_min_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$mintime
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	mov	edi, [rbx+timemap_max_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$maxtime
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	xor	edx, edx
	mov	ecx, [rbx+timemap_count_ofs]
	mov	rax, [rbx+timemap_time_ofs]
	div	rcx
	mov	rdi, rax
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$avgtime
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	mov	edi, [rbx+timemap_headers_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$headers
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	mov	rdi, [rbx+timemap_total_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$total
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	mov	rdi, [rbx+timemap_body_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, obj$body
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	
	pop	rdi
	mov	rsi, r13
	call	json$appendchild
	pop	r13 r12 rbx
	ret

; single argument in edi: bool as to whether or not it is our _final_ json (which will add all of the per-request goods)
falign
build_json:
	prolog	build_json
	push	rbx r12
	mov	ebx, edi
	mov	rdi, [master_json]
	test	rdi, rdi
	jz	.noprior
	call	json$destroy
calign
.noprior:
	mov	rdi, .emptystr
	call	json$newobject
	mov	[master_json], rax
	; servers array, but only if we have a nonzero count in the servermap
	mov	rdi, [servermap]
	cmp	qword [rdi+_avlofs_parent], 0	; its root node
	je	.skipservers
	mov	rdi, obj$servers
	call	json$newarray
	mov	r12, rax
	mov	rdi, [servermap]
	mov	rsi, .stringmap_keytoarray
	mov	rdx, rax
	call	stringmap$foreach_arg
	mov	rdi, [master_json]
	mov	rsi, r12
	call	json$appendchild
calign
.skipservers:
	mov	rdi, [xpoweredbymap]
	cmp	qword [rdi+_avlofs_parent], 0	; its root node
	je	.skipxpoweredby
	mov	rdi, obj$xpoweredby
	call	json$newarray
	mov	r12, rax
	mov	rdi, [xpoweredbymap]
	mov	rsi, .stringmap_keytoarray
	mov	rdx, rax
	call	stringmap$foreach_arg
	mov	rdi, [master_json]
	mov	rsi, r12
	call	json$appendchild
calign
.skipxpoweredby:

macro master_jsnum l*, n* {
	mov	rdi, n
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, l
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild
}
	master_jsnum obj$concurrency, [concurrency]
	
	call	timestamp
	subsd	xmm0, [begin]
	xor	edi, edi		; milliseconds please
	mov	esi, 3			; 3 digits after the decimal point
	call	format$duration
	mov	r12, rax
	mov	rdi, obj$time_taken
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	call	timestamp
	mov	rdi, [datetimeformat]
	call	formatter$doit
	mov	r12, rax
	mov	rdi, obj$time_completed
	call	string$copy
	mov	rdi, rax
	mov	rsi, r12
	call	json$newvalue_nocopy
	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	master_jsnum obj$completed, [completed]
	master_jsnum obj$failed, [failed]
	master_jsnum obj$non2xx, [non2xx]
	master_jsnum obj$keepalives, [keepalives]
	master_jsnum obj$total_received, [total_received]
	master_jsnum obj$header_received, [header_received]
	master_jsnum obj$body_received, [body_received]

	mov	rdi, [responsemap]
	call	responsemap_to_json
	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	mov	rdi, obj$urls
	call	json$newarray
	push	rax
	
	mov	rdi, [urlmap]
	mov	rsi, .makeurls
	mov	rdx, rsp
	call	stringmap$foreach_arg
	
	mov	rdi, [master_json]
	pop	rsi
	call	json$appendchild

	mov	rdi, obj$reqpersec
	call	string$copy
	push	rax

	call	epoll$timestamp
	sub	rax, [begin_msecs]
	mov	r12, rax
	mov	rcx, [completed]
	cvtsi2sd xmm0, rcx

	cvtsi2sd xmm1, rax		; time elapsed in milliseconds
	divsd	xmm0, xmm1
	mulsd	xmm0, [.onethousand]
	
	mov	edi, double_string_fixed
	mov	esi, 2
	call	string$from_double
	pop	rdi
	mov	rsi, rax
	call	json$newvalue_nocopy

	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	; tps: time per request, same as apachebench's idea, concurrency * timetaken / completed
	mov	rdi, obj$tps
	call	string$copy
	push	rax

	mov	rcx, [completed]
	xor	edx, edx
	mov	rax, [concurrency]
	mul	r12
	cvtsi2sd xmm1, rcx
	cvtsi2sd xmm0, rax		; concurrency * timetaken
	divsd	xmm0, xmm1

	mov	edi, double_string_fixed
	mov	esi, 3
	call	string$from_double
	pop	rdi
	mov	rsi, rax
	call	json$newvalue_nocopy
	
	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	; and ctps: concurrent time per request, timetaken / completed
	mov	rdi, obj$ctps
	call	string$copy
	push	rax

	mov	rcx, [completed]
	cvtsi2sd xmm1, rcx
	cvtsi2sd xmm0, r12
	divsd	xmm0, xmm1

	mov	edi, double_string_fixed
	mov	esi, 3
	call	string$from_double
	pop	rdi
	mov	rsi, rax
	call	json$newvalue_nocopy

	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	; wire transfer rate: total_received / 1024 / timetaken / 1000
	mov	rdi, obj$wiretransferrate
	call	string$copy
	push	rax
	
	mov	rcx, [total_received]
	shr	rcx, 10		; / 1024
	cvtsi2sd xmm0, rcx
	cvtsi2sd xmm1, r12
	divsd	xmm1, [.onethousand]
	divsd	xmm0, xmm1
	
	mov	edi, double_string_fixed
	mov	esi, 2
	call	string$from_double
	pop	rdi
	mov	rsi, rax
	call	json$newvalue_nocopy

	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	; body transfer rate: body_received / 1024 / timetaken / 1000
	mov	rdi, obj$bodytransferrate
	call	string$copy
	push	rax
	
	mov	rcx, [body_received]
	shr	rcx, 10		; / 1024
	cvtsi2sd xmm0, rcx
	cvtsi2sd xmm1, r12
	divsd	xmm1, [.onethousand]
	divsd	xmm0, xmm1
	
	mov	edi, double_string_fixed
	mov	esi, 2
	call	string$from_double
	pop	rdi
	mov	rsi, rax
	call	json$newvalue_nocopy

	mov	rdi, [master_json]
	mov	rsi, rax
	call	json$appendchild

	
	master_jsnum obj$ctime_min, [ctime_min]
	master_jsnum obj$ctime_max, [ctime_max]
	xor	edx, edx
	mov	rcx, [completed]
	mov	rax, [ctime_total]
	div	rcx
	master_jsnum obj$ctime_avg, rax
	
	master_jsnum obj$dtime_min, [dtime_min]
	master_jsnum obj$dtime_max, [dtime_max]
	xor	edx, edx
	mov	rcx, [completed]
	mov	rax, [dtime_total]
	div	rcx
	master_jsnum obj$dtime_avg, rax

	mov	rdi, [timing_ttime]
	mov	rsi, [rdi+_avlofs_next]	; map's first node
	mov	rax, [rsi+_avlofs_key]
	master_jsnum obj$ttime_min, rax

	mov	rdi, [timing_ttime]
	mov	rsi, [rdi+_avlofs_prev]	; map's last node
	mov	rax, [rsi+_avlofs_key]
	master_jsnum obj$ttime_max, rax

	xor	ecx, ecx
	mov	rdi, [timing_ttime]
	mov	rsi, .count_ttime
	push	rcx
	mov	rdx, rsp
	call	unsignedmap$foreach_arg
	mov	rdi, [timing_ttime]
	xor	edx, edx
	mov	rsi, [rdi+_avlofs_right]	; map's node count
	pop	rax
	div	rsi
	master_jsnum obj$ttime_avg, rax

	master_jsnum obj$wait_min, [wait_min]
	master_jsnum obj$wait_max, [wait_max]
	xor	edx, edx
	mov	rcx, [completed]
	mov	rax, [dtime_total]
	div	rcx
	master_jsnum obj$wait_avg, rax

	; we could do apachebench's style "percentage of requests served within a certain time" thing
	; but IMO, those numbers can easily be inferred from the min/average/max, and since we keep
	; track per URL, probably not necessary here.
	
	; if people ask for it, despite my not really wanting it, hahah
	; well, all we really have to do is traverse the timing_ttime map, find its middle
	; and walk forward from there in increments, recording its keys at each point

	test	ebx, ebx
	jnz	.checkfinaloutput

	pop	 r12 rbx
	epilog
calign
.checkfinaloutput:
	cmp	qword [jsonout], 0
	je	.nofinaloutput
	mov	rdi, [master_json]
	call	json$tostring
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, [jsonout]
	call	string$file_write
	mov	rdi, rbx
	call	heap$free
	pop	r12 rbx
	epilog
calign
.nofinaloutput:
	pop	r12 rbx
	epilog
dalign
.onethousand	dq	1000.0f

cleartext .emptystr, ''
falign
.count_ttime:
	; rdi == key (ttime), rsi == response code, rdx == pointer we need to add to
	add	qword [rdx], rdi
	ret
falign
.makeurls:
	; rdi == string url, rsi == responsemap, rdx == ptr to jsonarray we need to add to
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	rsi, rdi
	mov	rdi, obj$url
	call	json$newvalue
	mov	rbx, rax

	mov	rdi, .emptystr
	call	json$newobject
	mov	rdi, rax
	mov	rsi, rbx
	mov	rbx, rax
	call	json$appendchild

	mov	rdi, r12
	call	responsemap_to_json
	mov	rdi, rbx
	mov	rsi, rax
	call	json$appendchild
	
	mov	rdi, [r13]
	mov	rsi, rbx
	call	json$appendchild
	
	pop	r13 r12 rbx
	ret
falign
.stringmap_keytoarray:
	; rdi == key, rsi == whatever, rdx == destination json object
	push	rdx
	mov	rsi, rdi
	mov	rdi, .emptystr
	call	json$newvalue
	pop	rdi
	mov	rsi, rax
	call	json$appendchild
	ret
