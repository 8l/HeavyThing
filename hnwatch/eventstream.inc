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
	; eventstream.inc: deal with SSE from firebaseio, noting that we bypass
	; our own webclient goods and do this with "raw tls client" goods.
	;


	; eventstream state/offsets:
eventstream_url_ofs = 0
eventstream_comms_ofs = 8
eventstream_callback_ofs = 16
eventstream_buffer_ofs = 24
eventstream_timer_ofs = 32
eventstream_statuscb_ofs = 40

eventstream_size = 48


	; three arguments: rdi == string, one of: 'topstories', 'updates',
	; 'newstories', 'askstories', 'showstories', 'jobstories'
	; rsi == callback function that will get passed the data json object
	; rdx == callback function that will get passed string status updates
	; (status updates only for connect, get, error, retry)
falign
eventstream$new:
	prolog	eventstream$new
	push	rdx rsi
	mov	rsi, rdi
	mov	rdi, .url_preface
	call	string$concat
	push	rax
	mov	rdi, rax
	mov	rsi, .url_postface
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	xor	edi, edi
	mov	rsi, [rsp]
	call	url$new
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	edi, eventstream_size
	call	heap$alloc_clear
	pop	rsi rdi rdx
	mov	[rax+eventstream_url_ofs], rsi
	mov	[rax+eventstream_callback_ofs], rdi
	mov	[rax+eventstream_statuscb_ofs], rdx
	push	rax
	mov	rdi, rax
	mov	rsi, eventstream_redirect_vtable
	mov	rdx, .firebasedomain
	call	eventstream$launch
	call	buffer$new
	mov	rcx, rax
	pop	rax
	mov	[rax+eventstream_buffer_ofs], rcx
	epilog
cleartext .url_preface, 'https://hacker-news.firebaseio.com/v0/'
cleartext .url_postface, '.json'
cleartext .firebasedomain, 'hacker-news.firebaseio.com'


	; single argument in rdi: an eventstream object to teardown
falign
eventstream$destroy:
	prolog	eventstream$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+eventstream_url_ofs]
	call	url$destroy
	mov	rdi, [rbx+eventstream_buffer_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+eventstream_comms_ofs]
	test	rdi, rdi
	jz	.skipteardown
	mov	rsi, [rdi]	; its virtual method table
	call	qword [rsi+io_vdestroy]
.skipteardown:
	mov	rdi, [rbx+eventstream_timer_ofs]
	test	rdi, rdi
	jz	.skiptimer
	call	epoll$timer_clear
.skiptimer:
	mov	rdi, rbx
	pop	rbx
	call	heap$free
	epilog



	; three arguments: rdi == eventstream object, rsi == vtable to use, rdx == hostname we are connecting to
falign
eventstream$launch:
	prolog	eventstream$launch
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	; construct a status string from our url object
	mov	rdi, [rdi+eventstream_url_ofs]
	call	url$tostring
	push	rax
	mov	rdi, .status_preface
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov 	rdi, [rsp]
	call	qword [rbx+eventstream_statuscb_ofs]
	pop	rdi
	call	heap$free
	; we need a toplevel empty io object, with room for our extra pointer
	mov	edi, io_base_size + 8
	call	heap$alloc_clear
	mov	[rbx+eventstream_comms_ofs], rax
	mov	qword [rax+io_vmethods_ofs], r12
	mov	[rax+io_base_size], rbx		; hangon to our eventstream object pointer
	mov	r12, rax
	; next up, a tls object (note we are not doing TLS session resumption here because I am lazy and these
	; don't get re-created very often if all goes well)
	xor	edi, edi
	xor	esi, esi
	call	tls$new_client
	mov	[r12+io_child_ofs], rax		; link the io chain together
	mov	[rax+io_parent_ofs], r12
	mov	r12, rax
	; and the last link in the chain, our actual epoll object for socket comms
	mov	rdi, epoll$default_vtable
	xor	esi, esi
	call	epoll$new
	mov	[r12+io_child_ofs], rax		; link the io chain together
	mov	[rax+io_parent_ofs], r12
	; set a 60 second timeout for our socket
	mov	qword [rax+epoll_readtimeout_ofs], 60000
	; last but not least, execute our hostname-based outbound connection
	mov	rdx, [rbx+eventstream_comms_ofs]
	mov	rdi, r13
	mov	esi, 443
	call	epoll$outbound_hostname
	pop	r13 r12 rbx
	epilog
cleartext .status_preface, 'Connect: '


	; our redirect vtable
dalign
eventstream_redirect_vtable:
	dq	io$destroy, io$clone, eventstream$connected, io$send, eventstream_redirect$received
	dq	eventstream$error, eventstream$timeout


	; this is shared by both the initial redirect request and the proper one for the SSE stream
falign
eventstream$connected:
	prolog	eventstream$connected
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, [rdi+io_base_size]		; our eventstream object
	; construct a status string
	mov	rdi, [r12+eventstream_url_ofs]
	call	url$tostring
	push	rax
	mov	rdi, .status_preface
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov 	rdi, [rsp]
	call	qword [r12+eventstream_statuscb_ofs]
	pop	rdi
	call	heap$free
	; turn our url into preface-suitable goods first
	mov	rdi, [r12+eventstream_url_ofs]
	call	url$topreface
	mov	r13, rax
	; send our simple HTTP GET request
	sub	rsp, 512
	mov	dword [rsp], 'GET '
	mov	rdi, rax
	lea	rsi, [rsp+4]
	call	string$to_utf8
	mov	rdi, r13
	lea	r13, [rax+4]
	call	heap$free
	mov	rsi, [r12+eventstream_url_ofs]
	mov	rdx, qword [.part1]
	mov	rcx, qword [.part2]
	mov	[rsp+r13], rdx
	mov	[rsp+r13+8], rcx
	mov	byte [rsp+r13+16], ' '
	add	r13, 17
	mov	rdi, [rsi+url_host_ofs]
	lea	rsi, [rsp+r13]
	call	string$to_utf8
	add	r13, rax
	mov	rdx, qword [.part3]
	mov	rcx, qword [.part4]
	mov	r8, qword [.part5]
	mov	r9, qword [.part6]
	mov	[rsp+r13], rdx
	mov	[rsp+r13+8], rcx
	mov	[rsp+r13+16], r8
	mov	[rsp+r13+24], r9
	add	r13, 31
	; send it
	mov	rdi, rbx
	mov	rsi, rsp
	mov	rdx, r13
	call	io$send			; we don't need ot use vmethod send here
	; unwind, done.
	add	rsp, 512
	pop	r13 r12 rbx
	epilog
cleartext .status_preface, 'Get: '
dalign
.part1:
	db	' HTTP/1.'
.part2:
	db	'1',13,10,'Host:'
.part3:
	db	13,10,'Accept'
.part4:
	db	': text/e'
.part5:
	db	'vent-str'
.part6:
	db	'eam',13,10,13,10,0


falign
eventstream_redirect$received:
	prolog	eventstream_redirect$received
	; we cheat here and don't bother to buffer/accumulate the response
	; because the firebaseio servers are nice enough to send it all in
	; a single TLS frame (versus the webclient which is not hackish, haha)
	push	rbx r12
	mov	rbx, rdi
	mov	rdi, rsi
	mov	rsi, rdx
	mov	edx, 1		; headers only please
	mov	ecx, 1		; yes, there is a preface
	call	mimelike$new_parse
	test	rax, rax
	jz	.error
	; our preface must contain a 307 or something went sideways
	mov	r12, rax
	mov	rdi, [rax+mimelike_preface_ofs]
	mov	rsi, .p307
	call	string$indexof
	cmp	rax, -1
	je	.error_mimelike
	; our header must contain a Location line
	mov	rdi, r12
	mov	rsi, mimelike$location
	call	mimelike$getheader
	test	rax, rax
	jz	.error_mimelike
	; otherwise, we can destroy our existing url object and replace it
	xor	edi, edi
	mov	rsi, rax
	call	url$new
	test	rax, rax
	jz	.error_mimelike
	mov	rsi, [rbx+io_base_size]		; our eventstream object
	mov	rdi, [rsi+eventstream_url_ofs]
	mov	[rsi+eventstream_url_ofs], rax
	call	url$destroy
	; so now we are done with our mimelike object
	mov	rdi, r12
	call	mimelike$destroy
	mov	r12, [rbx+io_base_size]		; our eventstream object
	mov	rdi, r12
	mov	rcx, [r12+eventstream_url_ofs]
	mov	rsi, eventstream_vtable
	mov	rdx, [rcx+url_host_ofs]
	call	eventstream$launch
	; last but not least, tear ourselves down by returning true
	mov	eax, 1
	pop	r12 rbx
	epilog
.error_mimelike:
	mov	rdi, r12
	call	mimelike$destroy
.error:
	; something horribly wrong happened, let the error handler deal with it
	mov	rdi, rbx
	call	eventstream$error
	; and return 1 from here to make sure we get torn down
	mov	eax, 1
	pop	r12 rbx
	epilog
cleartext .p307, ' 307 '
	

	; this is also shared with both the redirect request handler and the SSE stream handler
falign
eventstream$error:
	prolog	eventstream$error
	; we get this either from a lame receive, or if the socket got closed on us
	; or the connect failed, etc
	; all we need to do is fire up a timer to try again
	push	rbx
	push	qword [rdi]			; our vtable
	mov	rbx, [rdi+io_base_size]		; our eventstream object
	; construct a status string
	mov	rdi, [rbx+eventstream_url_ofs]
	call	url$tostring
	push	rax
	mov	rdi, .status_preface
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov 	rdi, [rsp]
	call	qword [rbx+eventstream_statuscb_ofs]
	pop	rdi
	call	heap$free
	; we need a new "dummy" epoll object to deal with our timer
	mov	rdi, retry_timer_vtable
	mov	esi, 16				; room extra to hold our eventstream pointer and vtable
	call	epoll$new
	pop	rcx
	mov	[rax+epoll_base_size], rbx	; ""
	mov	[rax+epoll_base_size+8], rcx	; so that our retry gets the same vtable as we had
	; store that in our eventstream object in case it gets destroyed during our wait
	mov	[rbx+eventstream_comms_ofs], rax
	mov	edi, 15000			; 15 seconds and we'll try again
	mov	rsi, rax
	call	epoll$timer_new
	mov	[rbx+eventstream_timer_ofs], rax	; save this too
	pop	rbx
	epilog
cleartext .status_preface, 'Error: '

	; this is also shared with both the redirect request handler and the SSE stream handler
falign
eventstream$timeout:
	prolog	eventstream$timeout
	; we return nonzero from here == destroy us please
	call	eventstream$error
	mov	eax, 1
	epilog


dalign
retry_timer_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, epoll$receive, io$error, eventstream$retry_timeout


falign
eventstream$retry_timeout:
	prolog	eventstream$retry_timeout
	; connect again to the same url we tried before
	push	rbx
	mov	rbx, [rdi+epoll_base_size]	; our eventstream object
	mov	rsi, [rdi+epoll_base_size+8]	; the original vtable for our new connection
	mov	rcx, [rbx+eventstream_url_ofs]
	mov	rdi, rbx
	mov	rdx, [rcx+url_host_ofs]
	; clear the timer pointer in our eventstream object
	mov	qword [rbx+eventstream_timer_ofs], 0
	call	eventstream$launch
	pop	rbx
	mov	eax, 1				; destroy the timer and dummy epoll object
	epilog


	; our vtable for the actual SSE stream:
dalign
eventstream_vtable:
	dq	io$destroy, io$clone, eventstream$connected, io$send, eventstream$received
	dq	eventstream$error, eventstream$timeout



	; this gets called with: rdi == epoll object, rsi == ptr to data, rdx == length of same
falign
eventstream$received:
	prolog	eventstream$received
	push	rbx r12
	mov	rbx, [rdi+io_base_size]
	; buffer this
	mov	rdi, [rbx+eventstream_buffer_ofs]
	call	buffer$append
	; now extract line-by-line from it until exhausted looking for our data: lines
calign
.loop:
	mov	rdi, [rbx+eventstream_buffer_ofs]
	mov	esi, 1				; consume empty/leading lines
	call	buffer$has_more_lines
	test	eax, eax
	jz	.outtahere
	mov	rdi, [rbx+eventstream_buffer_ofs]
	call	buffer$nextline
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, .data_preface
	call	string$starts_with
	test	eax, eax
	jz	.skipline
	; otherwise, this line started with data: {
	; substring it from offset 6
	mov	rdi, r12
	mov	esi, 6
	mov	rdx, -1
	call	string$substr
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	; construct a json object out of it
	mov	rdi, r12
	xor	esi, esi		; no leading object name
	call	json$parse_object
	test	rax, rax		; parse error?
	jz	.skipline
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	; call our callback with rdi set to our json object
	mov	rdi, r12
	call	qword [rbx+eventstream_callback_ofs]
	; cleanup after ourselves
	mov	rdi, r12
	call	json$destroy
	jmp	.loop
.skipline:
	mov	rdi, r12
	call	heap$free
	jmp	.loop
cleartext .data_preface, 'data: {'
.outtahere:
	pop	r12 rbx
	xor	eax, eax		; keep the connection open
	epilog
