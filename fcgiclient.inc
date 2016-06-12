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
	; fcgiclient.inc: a quick and dirty fastcgi client, tied to epoll directly (instead of being an io layer)
	;

if used fcgiclient$new | defined include_everything

	; we keep a static copy of the initial fastcgi send buffer so that we don't need
	; to unnecessarily build it each and every request
globals
{
	fcgiclient$initial_buffer	dq	0
}


fcgiclient_buffer_ofs = epoll_base_size
fcgiclient_errbuf_ofs = epoll_base_size + 8
fcgiclient_callback_ofs = epoll_base_size + 16
fcgiclient_callbackarg_ofs = epoll_base_size + 24
fcgiclient_user_ofs = epoll_base_size + 32

fcgiclient_size = epoll_base_size + 40

dalign
fcgiclient$vtable:
	dq	fcgiclient$destroy, epoll$clone, fcgiclient$connected, epoll$send, fcgiclient$received, fcgiclient$error, io$timeout


	; four arguments: rdi == request url, rsi == mimelike request object, rdx == function ptr for result, rcx == arg to pass in rdi for same
	; returns a new fcgiclient object, suitable for immediate epoll$outbound
falign
fcgiclient$new:
	prolog	fcgiclient$new
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	push	rdx rcx
	mov	rdi, fcgiclient$vtable
	mov	esi, 32
	call	epoll$new
	mov	rbx, rax
	pop	rcx rdx
	mov	[rax+fcgiclient_callback_ofs], rdx
	mov	[rax+fcgiclient_callbackarg_ofs], rcx
	call	buffer$new
	mov	[rbx+fcgiclient_errbuf_ofs], rax
	mov	rdi, [fcgiclient$initial_buffer]
	call	buffer$copy
	mov	[rbx+fcgiclient_buffer_ofs], rax
	mov	r14, rax
	; so now we get to turn our goods into a parameter stream
	; and then set clen/plen for that, and add our stdin (if any) and endrequest
	; the calling later should have set a DOCUMENT_ROOT request header, and we can set all our url parameters
	mov	rdi, r13
	mov	rsi, .docrootstr
	call	mimelike$getheader
	test	rax, rax
	jz	.nodocroot
	; set scriptfilename to that + url_path_ofs
	push	rax
	mov	rdi, rax
	mov	rsi, [r12+url_path_ofs]
	call	string$concat
	push	rax
	mov	rdi, .scriptfilename
	mov	rsi, rax
	call	.addparam
	pop	rdi
	call	heap$free
	pop	rax
	; its length _should_ be less than 128 bytes, and most likely doesn't contain weirdness
	mov	r15, rax
	mov	rdi, rax
	call	string$utf8_length
	cmp	eax, 128
	jae	.bigdocroot
	; otherwise
	shl	eax, 8
	or	eax, 13
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_word
	mov	rdi, r14
	mov	rsi, .docrootstr
	call	buffer$append_string
	mov	rdi, r14
	mov	rsi, r15
	call	buffer$append_string
	mov	rdi, r13
	mov	rsi, .docrootstr
	call	mimelike$removeheader
	jmp	.nodocroot
calign
.bigdocroot:
	bswap	eax
	or	eax, 0x80
	shl	rax, 8
	or	rax, 13
	push	rax
	mov	rdi, r14
	mov	rsi, rsp
	mov	edx, 5
	call	buffer$append
	pop	rax
	mov	rdi, r14
	mov	rsi, .docrootstr
	call	buffer$append_string
	mov	rdi, r14
	mov	rsi, r15
	call	buffer$append_string
	mov	rdi, r13
	mov	rsi, .docrootstr
	call	mimelike$removeheader
calign
.nodocroot:
	; add the rest of our url goods
	mov	rdi, .scriptname
	mov	rsi, [r12+url_path_ofs]
	call	.addparam
	mov	rdi, .documenturi
	mov	rsi, [r12+url_path_ofs]
	call	.addparam
	mov	rcx, [r12+url_user_ofs]
	mov	rdx, [r12+url_query_ofs]
	mov	rdi, .requesturi
	mov	rsi, [r12+url_path_ofs]
	test	rcx, rcx
	cmovnz	rsi, rcx
	cmp	qword [rdx], 0
	jne	.withquerystring
	call	.addparam
	; empty query string
	mov	rdi, .querystring
	call	.addparam_novalue
	jmp	.requesturidone
calign
.withquerystring:
	mov	rdi, rsi
	mov	rsi, .questionmark
	call	string$concat
	push	rax
	mov	rdi, rax
	mov	rsi, [r12+url_query_ofs]
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, .requesturi
	mov	rsi, [rsp]
	call	.addparam
	pop	rdi
	call	heap$free
	mov	rdi, .querystring
	mov	rsi, [r12+url_query_ofs]
	call	.addparam
	; fallthrough to requesturidone
calign
.requesturidone:
	; request method next
	mov	rdi, .requestmethod
	mov	rsi, .get
	mov	rdx, .head
	mov	rcx, .post
	cmp	dword [r13+mimelike_user_ofs], 1
	cmove	rsi, rdx
	cmp	dword [r13+mimelike_user_ofs], 2
	cmove	rsi, rcx
	call	.addparam
	cmp	dword [r13+mimelike_user_ofs], 2
	je	.postcontenttype
calign
.emptycontenttype:
	; otherwise, empty content type and content length
	mov	rdi, .contenttype
	call	.addparam_novalue
	mov	rdi, .contentlength
	call	.addparam_novalue
	jmp	.doremoteaddr
calign
.postcontenttype:
	mov	rdi, r13
	mov	rsi, mimelike$contenttype
	call	mimelike$getheader
	test	rax, rax
	jz	.emptycontenttype
	mov	rdi, .contenttype
	mov	rsi, rax
	call	.addparam
	mov	rdi, r13
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jnz	.postcontentlength
calign
.emptycontentlength:
	mov	rdi, .contentlength
	call	.addparam_novalue
	jmp	.doremoteaddr
calign
.postcontentlength:
	mov	rdi, .contentlength
	mov	rsi, rax
	call	.addparam
calign
.doremoteaddr:
	; like DOCUMENT_ROOT, REMOTE_ADDR and REMOTE_PORT got added to our request object before the call to here
	mov	rdi, r13
	mov	rsi, .remoteaddr
	call	mimelike$getheader
	test	rax, rax
	jz	.emptyremoteaddr
	mov	rdi, .remoteaddr
	mov	rsi, rax
	call	.addparam
	mov	rdi, r13
	mov	rsi, .remoteport
	call	mimelike$getheader
	test	rax, rax
	jz	.emptyremoteport
	mov	rdi, .remoteport
	mov	rsi, rax
	call	.addparam
	jmp	.doservername
calign
.emptyremoteaddr:
	mov	rdi, .remoteaddr
	call	.addparam_novalue
	mov	rdi, .remoteport
	call	.addparam_novalue
	jmp	.doservername
calign
.emptyremoteport:
	mov	rdi, .remoteport
	call	.addparam_novalue
calign
.doservername:
	; remove the REMOTE_ADDR and REMOTE_PORT from the request headers
	mov	rdi, r13
	mov	rsi, .remoteaddr
	call	mimelike$removeheader
	mov	rdi, r13
	mov	rsi, .remoteport
	call	mimelike$removeheader

	mov	rdi, .servername
	mov	rsi, [r12+url_host_ofs]
	call	.addparam
	mov	edi, [r12+url_port_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, .serverport
	mov	rsi, rax
	call	.addparam
	pop	rdi
	call	heap$free

	; if the protocol is https, we need to add an HTTPS: on 
	mov	rdi, [r12+url_protocol_ofs]
	mov	rsi, .https
	call	string$equals
	test	eax, eax
	jz	.doservername_nothttps
	mov	rdi, .httpscaps
	mov	rsi, .onstr
	call	.addparam
calign
.doservername_nothttps:
	
	; add our request headers as parameters next
	mov	rdi, [r13+mimelike_headers_ofs]
	mov	rsi, .addheader
	mov	rdx, r14
	call	stringmap$foreach_arg

	; so we have to pad & close the params block, then check to see whether we have a post or not
	; our params should never exceed 64kb, so we don't bother to check that
	mov	rdi, r14
	mov	esi, 8
	call	buffer$reserve

	; so, our actual length of our params block is: r14.length - 24
	; our padding length just needs to make sure that r14's buffer itself is 8 byte aligned
	mov	eax, [r14+buffer_length_ofs]
	mov	edx, [r14+buffer_length_ofs]
	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, [r14+buffer_endptr_ofs]
	xor	ecx, ecx
	add	edx, 7
	and	edx, not 7
	sub	edx, eax
	sub	eax, 24
	xchg	ah, al
	mov	word [rdi+20], ax
	mov	byte [rdi+22], dl
	mov	qword [rsi], rcx
	mov	rdi, r14
	mov	esi, edx
	call	buffer$append_nocopy
	; and one more empty FCGI_PARAMS block so it knows we are done
	mov	rdi, r14
	mov	esi, 0x01000401		; version 1 type fcgi params (4), request id 1
	call	buffer$append_qword	; we leave the following 4 bytes to zero, up to the fcgiclient itself to set this
	; so that block is done, see if we have post data
	cmp	dword [r13+mimelike_user_ofs], 2
	jne	.nopostdata
	; otherwise, we need a FCGI_STDIN block
	mov	rdi, [r13+mimelike_body_ofs]
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nopostdata
	push	r12 r13
	mov	r12, [rdi+buffer_itself_ofs]
	mov	r13, [rdi+buffer_length_ofs]
calign
.postdataloop:
	mov	rdi, r14
	mov	esi, 0x01000501		; version 1 type fcgi stdin (5), request id 1
	call	buffer$append_dword
	; clen/plen is next
	mov	rax, r13
	mov	ecx, 65535
	cmp	rax, rcx
	cmova	rax, rcx
	; so the resultant buffer size will be its current size + 4 + rax
	mov	rcx, [r14+buffer_length_ofs]
	add	rcx, 4
	add	rcx, rax
	mov	rdx, rcx
	add	rcx, 7
	and	rcx, not 7
	sub	rcx, rdx
	; cl is our padding length
	; content length is in ax
	push	rcx
	push	rax
	xchg	ah, al
	mov	rdi, r14
	mov	esi, eax
	and	ecx, 0xff
	push	rcx
	call	buffer$append_word
	mov	rdi, r14
	pop	rsi
	call	buffer$append_word
	mov	rdi, r14
	mov	rsi, r12
	pop	rdx
	add	r12, rdx
	sub	r13, rdx
	call	buffer$append
	mov	rdi, r14
	mov	esi, 8
	call	buffer$reserve
	mov	rcx, [r14+buffer_endptr_ofs]
	mov	rdi, r14
	pop	rsi
	and	esi, 0xff
	mov	qword [rcx], 0
	call	buffer$append_nocopy
	test	r13, r13
	jnz	.postdataloop
	pop	r13 r12
	; and an empty one to indicate we are done
	mov	rdi, r14
	mov	esi, 0x01000501		; version 1 type fcgi stdin (5), request id 1
	call	buffer$append_qword
calign
.nopostdata:
	; buffer is complete
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	epilog
cleartext .docrootstr, 'DOCUMENT_ROOT'
cleartext .scriptfilename, 'SCRIPT_FILENAME'
cleartext .scriptname, 'SCRIPT_NAME'
cleartext .documenturi, 'DOCUMENT_URI'
cleartext .requesturi, 'REQUEST_URI'
cleartext .questionmark, '?'
cleartext .get, 'GET'
cleartext .head, 'HEAD'
cleartext .post, 'POST'
cleartext .querystring, 'QUERY_STRING'
cleartext .requestmethod, 'REQUEST_METHOD'
cleartext .contenttype, 'CONTENT_TYPE'
cleartext .contentlength, 'CONTENT_LENGTH'
cleartext .remoteaddr, 'REMOTE_ADDR'
cleartext .remoteport, 'REMOTE_PORT'
cleartext .servername, 'SERVER_NAME'
cleartext .serverport, 'SERVER_PORT'
cleartext .https, 'https'
cleartext .httpscaps, 'HTTPS'
cleartext .onstr, 'on'

falign
.addparam:
	; two arguments: rdi == name, rsi == value
	push	rdi rsi
	call	string$utf8_length
	mov	rdi, [rsp]
	push	rax
	call	string$utf8_length
	mov	rcx, rax
	pop	rax
	xor	edx, edx
	xor	r8d, r8d
	mov	r9d, 1
	mov	r10d, 2
	cmp	rax, 128
	cmovae	edx, r9d
	cmp	rcx, 128
	cmovae	r8d, r10d
	or	edx, r8d
	pop	rsi rdi
	jmp	qword [rdx*8+.addparam_dispatch]
dalign
.addparam_dispatch:
	dq	.addparam_bothsmall, .addparam_bigname, .addparam_bigvalue, .addparam_bothbig
calign
.addparam_bothsmall:
	push	rsi rdi rcx
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_byte
	pop	rsi
	mov	rdi, r14
	call	buffer$append_byte
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	ret
calign
.addparam_bigname:
	push	rsi rdi rcx
	bswap	eax
	or	eax, 0x80
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_dword
	pop	rsi
	mov	rdi, r14
	call	buffer$append_byte
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	ret
calign
.addparam_bigvalue:
	push	rsi rdi rcx
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_byte
	pop	rsi
	mov	rdi, r14
	bswap	esi
	or	esi, 0x80
	call	buffer$append_dword
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	ret
calign
.addparam_bothbig:
	push	rsi rdi rcx
	bswap	eax
	or	eax, 0x80
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_dword
	pop	rsi
	mov	rdi, r14
	bswap	esi
	or	esi, 0x80
	call	buffer$append_dword
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	ret

falign
.addparam_novalue:
	; single argument in rdi: name
	push	rdi
	call	string$utf8_length
	cmp	rax, 128
	jae	.addparam_novalue_big
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_word
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	ret
calign
.addparam_novalue_big:
	bswap	eax
	or	eax, 0x80
	mov	rdi, r14
	mov	esi, eax
	call	buffer$append_dword
	mov	rdi, r14
	xor	esi, esi
	call	buffer$append_byte
	pop	rsi
	mov	rdi, r14
	call	buffer$append_string
	ret
	
falign
.addheader:
	; our header needs to be HTTP_ with dashes turend into _ and uppercased
	sub	rsp, 24
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	call	string$to_upper
	mov	[rsp], rax
	mov	rdi, .headerpreface
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp]
	; now, we are going to cheat here and modify the string in place
	; it isn't really cheating as such, but the string library is meant to be
	; immutable, haha, but no harm no foul
	mov	rcx, [rdi]
	lea	r8, [rdi+8]
	mov	r9d, '_'
calign
.headermodloop:
if string_bits = 32
	mov	eax, [r8]
	cmp	eax, '-'
	cmove	eax, r9d
	mov	[r8], eax
	add	r8, 4
else
	movzx	eax, word [r8]
	cmp	eax, '-'
	cmove	eax, r9d
	mov	[r8], ax
	add	r8, 2
end if
	sub	ecx, 1
	jnz	.headermodloop

	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]

	; three arguments: rdi == key, rsi == value, rdx == buffer we are appending it to
	cmp	qword [rsi], 0
	je	.addheader_novalue

	; we know that r14 stays in tact across the calls to stringmap$foreach_arg, CAUTION! haha
	call	.addparam
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 24
	ret
cleartext .headerpreface, 'HTTP_'
calign
.addheader_novalue:
	call	.addparam_novalue
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 24
	ret

end if

if used fcgiclient$init | defined include_everything
	; no args, sets up the static fcgiclient$initial_buffer one-off
falign
fcgiclient$init:
	prolog	fcgiclient$init
	push	rbx
	call	buffer$new
	mov	[fcgiclient$initial_buffer], rax
	mov	rbx, rax
	mov	rdi, rax
	mov	esi, 0x01000101		; version 1 type begin request (1), request id 1
	call	buffer$append_dword
	mov	rdi, rbx
	mov	esi, 0x0800		; content length 8
	call	buffer$append_dword
	mov	rdi, rbx
	mov	esi, 0x0100		; role responder, 1
	call	buffer$append_qword
	; 16 byte begin request done, start our param block
	; start our params block, noting here that of course the length needs to be computed again afterthefact
	mov	rdi, rbx
	mov	esi, 0x01000401		; version 1 type fcgi params (4), request id 1
	call	buffer$append_qword	; we leave the following 4 bytes to zero, up to the fcgiclient itself to set this
					; so, content length is at buffer[20], padding length is buffer[22]
	; add our static fcgiparams:
	mov	rdi, rbx
	mov	rsi, .staticparams
	mov	edx, .staticparamslen
	call	buffer$append
	; we leave that trailing so that the fcgiclient itself can add the ones it wants, then set clen/plen and proceed
	; that really isn't a lot of extra effort, but no sense in doing that bit over and over again for each request
	pop	rbx
	epilog
dalign
.staticparams:
	db	15,8,'SERVER_PROTOCOLHTTP/1.1',17,7,'GATEWAY_INTERFACECGI/1.1',15,10,'SERVER_SOFTWAREHeavyThing'
.staticparamslen = $ - .staticparams

end if



if used fcgiclient$destroy | defined include_everything
	; single argument in rdi: our fcgiclient object to destroy
falign
fcgiclient$destroy:
	prolog	fcgiclient$destroy
	push	rdi
	mov	rdi, [rdi+fcgiclient_buffer_ofs]
	call	buffer$destroy
	mov	rdi, [rsp]
	mov	rdi, [rdi+fcgiclient_errbuf_ofs]
	call	buffer$destroy
	pop	rdi
	call	epoll$destroy
	epilog

end if

if used fcgiclient$connected | defined include_everything
	; single argument in rdi: our fcgiclient
falign
fcgiclient$connected:
	prolog	fcgiclient$connected
	; send and clear our buffer
	mov	rax, [rdi+fcgiclient_buffer_ofs]
	mov	rsi, [rax+buffer_itself_ofs]
	mov	rdx, [rax+buffer_length_ofs]
	push	rax
	call	epoll$send
	pop	rdi
	call	buffer$reset
	epilog

end if

if used fcgiclient$received | defined include_everything
	; three arguments: rdi == our fcgiclient, rsi == ptr to data, rdx == length of same
falign
fcgiclient$received:
	prolog	fcgiclient$received
	; we are expecting a stdout stream, possible stderr stream, and an end request
	; because we are overriding the actual epoll receive method, and because we are not chained io
	; we can manipulate the [rdi+epoll_inbuf_ofs] directly here, which in our case is _perfecto_
	mov	rax, [rdi+epoll_inbuf_ofs]
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, [rax+buffer_itself_ofs]
	mov	r13, [rax+buffer_length_ofs]
	xor	r14d, r14d
	cmp	r13, 8
	jb	.needmore
calign
.recordloop:
	; first byte better be 1 or we fire off an error
	cmp	byte [r12], 1
	jne	.error
	movzx	eax, word [r12+4]		; content length
	movzx	ecx, byte [r12+6]		; padding length
	xchg	ah, al
	; so the length we require is rax + 8 + rcx, our actual content is rax bytes worth at [r12+8]
	add	rcx, 8
	add	rcx, rax
	cmp	r13, rcx
	jb	.needmore_consume
	movzx	r9d, byte [r12+1]
	; otherwise, we have a full frame
	add	r14, rcx			; the entire frame worth
	lea	rsi, [r12+8]
	mov	rdx, rax
	mov	rdi, [rbx+fcgiclient_buffer_ofs]
	mov	r8, [rbx+fcgiclient_errbuf_ofs]
	cmp	r9d, 3				; FCGI_END_REQUEST
	je	.endrequest
	cmp	r9d, 6				; FCGI_STDOUT
	jb	.error
	cmovne	rdi, r8
	cmp	r9d, 7				; FCGI_STDERR
	ja	.error
	add	r12, rcx
	sub	r13, rcx
	call	buffer$append
	cmp	r13, 8
	jae	.recordloop
	; otherwise, fall through to needmore_consume
calign
.needmore_consume:
	test	r14, r14
	jz	.needmore
	mov	rdi, [rbx+epoll_inbuf_ofs]
	mov	rsi, r14
	call	buffer$consume

	xor	eax, eax		; don't kill us off
	pop	r14 r13 r12 rbx
	epilog
calign
.endrequest:
	; we don't really care what the exit code is from the fastcgi layer, just pass it off to our callback
	mov	rdi, [rbx+fcgiclient_callbackarg_ofs]
	mov	rsi, [rbx+fcgiclient_buffer_ofs]
	mov	rdx, [rbx+fcgiclient_errbuf_ofs]
	call	qword [rbx+fcgiclient_callback_ofs]
	mov	eax, 1			; suicide please
	pop	r14 r13 r12 rbx
	epilog
calign
.error:
	mov	rdi, [rbx+fcgiclient_callbackarg_ofs]
	xor	esi, esi
	xor	edx, edx
	call	qword [rbx+fcgiclient_callback_ofs]
	mov	eax, 1			; suicide please
	pop	r14 r13 r12 rbx
	epilog
calign
.needmore:
	xor	eax, eax		; don't kill us off
	pop	r14 r13 r12 rbx
	epilog

end if

if used fcgiclient$error | defined include_everything
	; single argument in rdi: our fcgiclient
falign
fcgiclient$error:
	prolog	fcgiclient$error
	; something happened to our fcgi link, death notify our callback
	mov	rcx, rdi
	mov	rdi, [rdi+fcgiclient_callbackarg_ofs]
	xor	esi, esi
	xor	edx, edx
	call	qword [rcx+fcgiclient_callback_ofs]
	epilog

end if
