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
	; webclient.inc: convenience object to deal with "browser-style" web requests
	; By "browser-style" I mean: host-based persistent http connections, limited
	; similar to how browsers deal with webservers.
	;
	; The library setting webclient_maxconns determins the upper limit on how many
	; simultaneous connections per hostname we'll allow.
	;
	; Note: does not deal with non-HTTP requests
	;
	; Basic usage flow: webclient$new, webclient${get,head,get_ifetag,get_ifmodified,get_range,post}..., webclient$destroy
	;
	; the callbacks from get,head,post,etc will be called with:
	; rdi == the callback argument specified
	; rsi == the mimelike result object, or one of the small negative error numbers from webclient_fail_*
	; rdx == the url object we parsed from the source url (may be different if redirects enabled and we redirected)
	; rcx == the # of milliseconds the request took (from the time we _sent_ the request to the time the response was completed)
	;
	; NOTE/CAUTION: It is very important that you do not call webclient$destroy from _inside_ a webclient callback, hahah
	; while I _could_ decouple the callbacks from the webclient layer somewhat and alleviate the problem, in normal operation
	; this is not required, and the extra overhead of decoupling would be a measurable hit performance-wise.
	; So, if the result of a callback _needs_ to webclient$destroy (versus syscall_exit, haha), you'll need to delay it
	; with a 1ms timer or something creative :-)
	;

webclient_debug = 0


if used webclient$new | defined include_everything


webclient_uagent_ofs = 0			; a string for our user agent
webclient_inflight_ofs = 8			; a list of all pending requests, whether they are being serviced or not
webclient_hosts_ofs = 16			; a map, keyed by wcrequest_hostkey_ofs of our currently active hosts+connections+requestqueue
webclient_maxconns_ofs = 24			; set by default to webclient_maxconns library setting, but you can override it
webclient_notlsresume_ofs = 32			; a bool, defaults to 0, if set though, won't re-use TLS session ids.
webclient_addheaders_ofs = 40			; a stringmap of extra headers to add for every request that goes out
						; Things like: Connection: close, will force no keep-alive action, etc.
webclient_cookiejar_ofs = 48			; defaults to a null (which is to say we ignore Set-Cookie and don't send any either)
						; see webclient$cookiejar for how to set one
webclient_cookiejar_owned_ofs = 56		; bool as to whether we actually own the cookiejar pointer
webclient_connects_ofs = 64			; a count of the # of times we ended up firing up a wcio object
webclient_errors_ofs = 72			; a count of the # of times wcio$error and/or wcio$timeout got called
webclient_requests_ofs = 80			; a count of the # of requests we handled
webclient_totalsent_ofs = 88			; a count of the # of bytes we sent (NOTE: does not include TLS overhead)
webclient_totalreceived_ofs = 96		; a count of the # of bytes we received (again, no TLS overhead)
webclient_bodyreceived_ofs = 104		; a count of the # of bytes of actual bodies we received (above - this == headers)
webclient_replystamp_ofs = 112			; a not-really-useful except for webslap timestamp of when the first byte of a response is received
						; (only works when maxconns == 1 of course, if this is zero, then this gets set, otherwise it is left alone)

webclient_size = 120


; possible fail values that may get passed to the callbacks
webclient_fail_dns = -1
webclient_fail_preconnect = -2
webclient_fail_closed = -3
webclient_fail_timeout = -4



	; Single argument in rdi: a user-agent string, or null and we'll use HeavyThing
falign
webclient$new:
	prolog	webclient$new
	push	rbx
	mov	rsi, .default_uagent
	test	rdi, rdi
	cmovz	rdi, rsi
	call	string$copy
	mov	rbx, rax
	mov	edi, webclient_size
	call	heap$alloc_clear
	mov	[rax+webclient_uagent_ofs], rbx
	mov	rbx, rax
	mov	edi, 1
	call	unsignedmap$new
	mov	[rbx+webclient_inflight_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	[rbx+webclient_hosts_ofs], rax
	mov	edi, 1
	call	stringmap$new
	mov	[rbx+webclient_addheaders_ofs], rax
	mov	dword [rbx+webclient_maxconns_ofs], webclient_maxconns
	mov	rax, rbx
	pop	rbx
	epilog
cleartext .default_uagent, 'HeavyThing'

end if


if used webclient$destroy | defined include_everything
	; single argument in rdi: webclient object
falign
webclient$destroy:
	prolog	webclient$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+webclient_uagent_ofs]
	call	heap$free
	mov	rdi, [rbx+webclient_inflight_ofs]
	xor	esi, esi
	call	unsignedmap$clear
	mov	rdi, [rbx+webclient_inflight_ofs]
	call	heap$free
	; since wchost$destroy removes itself from our hosts map, we need to loop manually
	; instead of using stringmap$clear
calign
.hostclear:
	mov	rcx, [rbx+webclient_hosts_ofs]
	cmp	qword [rcx+_avlofs_parent], 0
	je	.hostcleared
	mov	rsi, [rcx+_avlofs_parent]
	mov	rdi, [rsi+_avlofs_value]
	call	wchost$destroy
	jmp	.hostclear
calign
.hostcleared:
	mov	rdi, [rbx+webclient_addheaders_ofs]
	mov	rsi, .stringstringfree
	call	stringmap$clear
	mov	rdi, [rbx+webclient_addheaders_ofs]
	call	heap$free
	cmp	qword [rbx+webclient_cookiejar_ofs], 0
	je	.skipcookiejar
	cmp	dword [rbx+webclient_cookiejar_owned_ofs], 0
	je	.skipcookiejar
	mov	rdi, [rbx+webclient_cookiejar_ofs]
	call	cookiejar$destroy
calign
.skipcookiejar:
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
falign
.stringstringfree:
	push	rsi
	call	heap$free
	pop	rdi
	call	heap$free
	ret
	
end if


if used webclient$addheader | defined include_everything
	; three arguments: rdi == webclient object, rsi == header name, rdx == header value
	; (we do not assume ownership of either)
falign
webclient$addheader:
	prolog	webclient$addheader
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	rdi, rsi
	call	string$copy
	mov	r12, rax
	mov	rdi, r13
	call	string$copy
	mov	r13, rax
	mov	rdi, [rbx+webclient_addheaders_ofs]
	mov	rsi, r12
	mov	rdx, rax
	call	stringmap$insert_unique
	pop	r13 r12 rbx
	epilog

end if

if used webclient$cookiejar | defined include_everything
	; three arguments: rdi == webclient object, rsi == cookiejar object, edx == bool as to whether we assume ownership of it or not
falign
webclient$cookiejar:
	prolog	webclient$cookiejar
	mov	[rdi+webclient_cookiejar_ofs], rsi
	mov	[rdi+webclient_cookiejar_owned_ofs], edx
	epilog

end if


if used wcrequest$new | defined include_everything

wcrequest_object_ofs = 0
wcrequest_hostkey_ofs = 8
wcrequest_hostname_ofs = 16
wcrequest_port_ofs = 24
wcrequest_istls_ofs = 32
wcrequest_headers_ofs = 36
wcrequest_webclient_ofs = 40
wcrequest_url_ofs = 48
wcrequest_callback_ofs = 56
wcrequest_callbackarg_ofs = 64
wcrequest_starttime_ofs = 72

wcrequest_size = 80

cleartext wcrequest$get, 'GET '
cleartext wcrequest$head, 'HEAD '
cleartext wcrequest$post, 'POST '


	; five arguments: rdi == static string request method (with a trailing space), rsi == webclient object, rdx == string url, rcx == function callback pointer, r8 == function callback argument
	; returns a new wcrequest object in rax, or null if there was a url parse error
falign
wcrequest$new:
	prolog	wcrequest$new
	push	rbx r12 r13
	sub	rsp, 64
	mov	[rsp], rdi				; reqmethod
	mov	[rsp+8], rsi				; webclient
	mov	[rsp+16], rdx				; string url
	mov	[rsp+24], rcx				; cb
	mov	[rsp+32], r8				; cbarg
	xor	edi, edi
	mov	rsi, rdx
	call	url$new
	test	rax, rax
	jz	.nullret
	mov	r12, rax
	mov	edi, wcrequest_size
	call	heap$alloc_clear
	mov	r8, [_epoll_tv_msecs]
	mov	rbx, rax
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+24]
	mov	rdx, [rsp+32]
	mov	[rax+wcrequest_webclient_ofs], rdi
	mov	[rax+wcrequest_url_ofs], r12
	mov	[rax+wcrequest_callback_ofs], rsi
	mov	[rax+wcrequest_callbackarg_ofs], rdx
	mov	[rax+wcrequest_starttime_ofs], r8
	; construct our hostkey which is host:port
	mov	edi, [r12+url_port_ofs]
	mov	esi, 10
	mov	[rax+wcrequest_port_ofs], rdi
	call	string$from_unsigned
	mov	[rsp+56], rax
	mov	rdi, .colon
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free
	mov	rdi, [r12+url_host_ofs]
	mov	rsi, [rsp+56]
	call	string$concat
	mov	rdi, [rsp+56]
	mov	[rbx+wcrequest_hostkey_ofs], rax
	call	heap$free
	; construct our preface
	mov	rdi, r12
	call	url$topreface
	mov	rdi, [rsp]		; request method with a trailing space
	mov	rsi, rax
	mov	[rsp+56], rax
	call	string$concat
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free
	mov	rdi, [rsp+56]
	mov	rsi, .httponedotone
	call	string$concat
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free

	; construct our mimelike request object
	call	mimelike$new
	mov	r13, rax
	mov	[rbx+wcrequest_object_ofs], rax
	mov	rdi, rax
	mov	rsi, [rsp+56]
	call	mimelike$setpreface_nocopy

	; add our normal request headers
	; if the url protocol matches the url schemeportmap, then we don't
	; use our hostkey as the host header, and instead just the host by itself
	mov	rdi, [url$schemeportmap]
	mov	rsi, [r12+url_protocol_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.use_hostkey
	cmp	edx, [r12+url_port_ofs]
	jne	.use_hostkey
	; otherwise, use the host
	mov	rdi, r13
	mov	rsi, .host
	mov	rdx, [r12+url_host_ofs]
	call	mimelike$addheader
	jmp	.hostset
calign
.use_hostkey:
	mov	rdi, r13
	mov	rsi, .host
	mov	rdx, [rbx+wcrequest_hostkey_ofs]
	call	mimelike$addheader
calign
.hostset:
	mov	rdi, r13
	mov	rsi, .accept
	mov	rdx, .stardotstar
	call	mimelike$addheader
	mov	rdi, r13
	mov	rsi, mimelike$connection
	mov	rdx, .keepalive
	call	mimelike$addheader
	mov	rdi, r13
	mov	rsi, mimelike$acceptencoding
	mov	rdx, mimelike$gzip
	call	mimelike$addheader

	mov	rcx, [rbx+wcrequest_webclient_ofs]
	mov	rdi, r13
	mov	rsi, .uagent
	mov	rdx, [rcx+webclient_uagent_ofs]
	call	mimelike$addheader

	; see if we are doing tls
	mov	rdi, [r12+url_protocol_ofs]
	mov	rsi, .https
	call	string$equals
	mov	[rbx+wcrequest_istls_ofs], eax

	mov	rdi, [r12+url_host_ofs]
	call	string$copy
	mov	[rbx+wcrequest_hostname_ofs], rax

	mov	rcx, [rbx+wcrequest_webclient_ofs]
	cmp	qword [rcx+webclient_cookiejar_ofs], 0
	je	.skipcookies
	mov	rdi, [rcx+webclient_cookiejar_ofs]
	mov	rsi, r12
	mov	rdx, r13
	call	cookiejar$get

calign
.skipcookies:
	; add our compulsory headers
	mov	rcx, [rbx+wcrequest_webclient_ofs]
	mov	rdi, [rcx+webclient_addheaders_ofs]
	mov	rsi, .headeradd
	mov	rdx, r13
	call	stringmap$foreach_arg

	mov	rax, rbx
	add	rsp, 64
	pop	r13 r12 rbx
	epilog
calign
.nullret:
	add	rsp, 64
	xor	eax, eax
	pop	r13 r12 rbx
	epilog
cleartext .colon, ':'
cleartext .httponedotone, ' HTTP/1.1'
cleartext .https, 'https'
cleartext .host, 'Host'
cleartext .accept, 'Accept'
cleartext .stardotstar, '*/*'
cleartext .keepalive, 'keep-alive'
cleartext .uagent, 'User-Agent'
falign
.headeradd:
	; called with rdi == key, rsi == value, rdx == mimelike object to add them to
	mov	rcx, rdx
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, rcx
	call	mimelike$setheader
	ret

end if


if used wcrequest$destroy | defined include_everything
	; single argument in rdi: a wcrequest object
falign
wcrequest$destroy:
	prolog	wcrequest$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+wcrequest_object_ofs]
	call	mimelike$destroy
	mov	rdi, [rbx+wcrequest_hostkey_ofs]
	call	heap$free
	mov	rdi, [rbx+wcrequest_hostname_ofs]
	call	heap$free
	mov	rdi, [rbx+wcrequest_url_ofs]
	call	url$destroy
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog

end if


if used webclient$get | defined include_everything
	; four arguments: rdi == webclient object, rsi == string url, rdx == function callback pointer, rcx == function callback argument
	; returns bool in eax as to whether it is in progress, 0 == url parse error occurred
	; (we do not assume ownership of the url string)
falign
webclient$get:
	prolog	webclient$get
	push	rdi
	mov	r8, rcx
	mov	rcx, rdx
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$get
	call	wcrequest$new
	test	rax, rax
	jz	.error
	mov	rsi, rax
	pop	rdi
	call	webclient$launch
	mov	eax, 1
	epilog
calign
.error:
	pop	rdi
	epilog

end if


if used webclient$get_nolaunch | defined include_everything
	; four arguments: rdi == webclient object, rsi == string url, rdx == function callback pointer, rcx == function callback argument
	; similar to the above, but returns the wcrequest object suitable for subsequent manual call to launch
	; (or null on catastrophic error)
falign
webclient$get_nolaunch:
	prolog	webclient$get_nolaunch
	mov	r8, rcx
	mov	rcx, rdx
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$get
	call	wcrequest$new
	epilog

end if


if used webclient$head | defined include_everything
	; four arguments: rdi == webclient object, rsi == string url, rdx == function callback pointer, rcx == function callback argument
	; returns bool in eax as to whether it is in progress, 0 == url parse error occurred
	; (we do not assume ownership of the url string)
falign
webclient$head:
	prolog	webclient$head
	push	rdi
	mov	r8, rcx
	mov	rcx, rdx
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$head
	call	wcrequest$new
	test	rax, rax
	jz	.error
	; specify headers only so that the wcio layer doesn't have to parse the preface
	mov	dword [rax+wcrequest_headers_ofs], 1
	mov	rsi, rax
	pop	rdi
	call	webclient$launch
	mov	eax, 1
	epilog
calign
.error:
	pop	rdi
	epilog

end if


if used webclient$get_ifetag | defined include_everything
	; five arguments: rdi == webclient object, rsi == string url, rdx == string etag, rcx == function callback pointer, r8 == function callback argument
	; returns bool in eax as to whether it is in progress, 0 == url parse error occurred
	; (we do not assume ownership of either string)
falign
webclient$get_ifetag:
	prolog	webclient$get_ifetag
	push	rdi rdx
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$get
	call	wcrequest$new
	test	rax, rax
	jz	.error
	mov	rdx, [rsp]
	mov	[rsp], rax
	mov	rdi, [rax+wcrequest_object_ofs]
	mov	rsi, mimelike$ifnonematch
	call	mimelike$addheader
	pop	rsi rdi
	call	webclient$launch
	mov	eax, 1
	epilog
calign
.error:
	pop	rdx rdi
	epilog

end if


if used webclient$get_ifmodified | defined include_everything
	; five arguments: rdi == webclient object, rsi == string url, rdx == string lastmod, rcx == function callback pointer, r8 == function callback argument
	; returns bool in eax as to whether it is in progress, 0 == url parse error occurred
	; (we do not assume ownership of either string)
falign
webclient$get_ifmodified:
	prolog	webclient$get_ifmodified
	push	rdi rdx
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$get
	call	wcrequest$new
	test	rax, rax
	jz	.error
	mov	rdx, [rsp]
	mov	[rsp], rax
	mov	rdi, [rax+wcrequest_object_ofs]
	mov	rsi, mimelike$ifmodifiedsince
	call	mimelike$addheader
	pop	rsi rdi
	call	webclient$launch
	mov	eax, 1
	epilog
calign
.error:
	pop	rdx rdi
	epilog

end if


if used webclient$get_range | defined include_everything
	; six arguments: rdi == webclient object, rsi == string url, rdx == start offset, rcx == end offset, r8 == function cb, r9 == function cbarg
	; returns bool in eax as to whether it is in progress, 0 == url parse error occurred
	; (we do not assume ownership of the url string)
falign
webclient$get_range:
	prolog	webclient$get_range
	push	rdi rdx rcx
	mov	rcx, r8
	mov	r8, r9
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$get
	call	wcrequest$new
	test	rax, rax
	jz	.error
	; construct our bytes=start-end header
	push	rax
	mov	rdi, [rsp+16]
	mov	esi, 10
	call	string$from_unsigned
	mov	[rsp+16], rax
	mov	rdi, [rsp+8]
	mov	esi, 10
	call	string$from_unsigned
	mov	[rsp+8], rax
	mov	rdi, [rsp+16]
	mov	rsi, .dash
	call	string$concat
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
	mov	rdi, [rsp+16]
	mov	rsi, [rsp+8]
	call	string$concat
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, .bytesequal
	mov	rsi, [rsp+16]
	call	string$concat
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
	mov	rcx, [rsp]
	mov	rdi, [rcx+wcrequest_object_ofs]
	mov	rsi, mimelike$range
	mov	rdx, [rsp+16]
	call	mimelike$addheader_novaluecopy
	; launch it
	pop	rsi r9 r8 rdi
	call	webclient$launch
	mov	eax, 1
	epilog
cleartext .dash, '-'
cleartext .bytesequal, 'bytes='
calign
.error:
	pop	rcx rdx rdi
	epilog

end if


if used webclient$post | defined include_everything
	; six arguments: rdi == webclient object, rsi == string url, rdx == string content type, rcx == buffer object, r8 == function cb, r9 == function cbarg
	; returns bool in eax as to whether it is in progress, 0 == url parse error occurred
	; (we do not assume ownership of either string or the buffer)
falign
webclient$post:
	prolog	webclient$post
	push	rdi rcx rdx
	mov	rcx, r8
	mov	r8, r9
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$post
	call	wcrequest$new
	test	rax, rax
	jz	.error
	mov	rdi, [rax+wcrequest_object_ofs]
	mov	rsi, mimelike$contenttype
	mov	rdx, [rsp]
	mov	[rsp], rax
	call	mimelike$addheader
	mov	rcx, [rsp]
	mov	r8, [rsp+8]
	mov	rdi, [rcx+wcrequest_object_ofs]
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	call	mimelike$setbody
	pop	rsi rdx rdi
	call	webclient$launch
	mov	eax, 1
	epilog
calign
.error:
	add	rsp, 24
	epilog

end if


if used webclient$post_nolaunch | defined include_everything
	; six arguments: rdi == webclient object, rsi == string url, rdx == string content type, rcx == buffer object, r8 == function cb, r9 == function cbarg
	; similar to the above, but returns the wcrequest object suitable for subsequent manual call to launch
	; (or null on catastrophic error)
falign
webclient$post_nolaunch:
	prolog	webclient$post_nolaunch
	push	rdi rcx rdx
	mov	rcx, r8
	mov	r8, r9
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, wcrequest$post
	call	wcrequest$new
	test	rax, rax
	jz	.error
	mov	rdi, [rax+wcrequest_object_ofs]
	mov	rsi, mimelike$contenttype
	mov	rdx, [rsp]
	mov	[rsp], rax
	call	mimelike$addheader
	mov	rcx, [rsp]
	mov	r8, [rsp+8]
	mov	rdi, [rcx+wcrequest_object_ofs]
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	call	mimelike$setbody
	pop	rax rdx rdi
	epilog
calign
.error:
	add	rsp, 24
	epilog

end if



if (webclient_global_dnscache & used wchost$new) | used wcdns$lookup_ipv4

wcdns_pending_ofs = 0
wcdns_good_ofs = 8

wcdns_size = 16

globals
{
	wcdns$pending	dq	0
	wcdns$good	dq	0
}


falign
wcdns$init:
	prolog	wcdns$init
	mov	edi, 1
	call	stringmap$new
	mov	[wcdns$pending], rax
	mov	edi, 1
	call	stringmap$new
	mov	[wcdns$good], rax
	epilog


	; four arguments, same as dns$lookup_ipv4
	; rdi == string hostname, rsi == success callback, rdx == fail callback, rcx == callback arg
falign
wcdns$lookup_ipv4:
	prolog	wcdns$lookup_ipv4
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	mov	rsi, rdi
	mov	rdi, [wcdns$good]
	call	stringmap$find_value
	test	eax, eax
	jnz	.cacheresult
	mov	rdi, [wcdns$pending]
	mov	rsi, r12
	call	stringmap$find_value
	test	eax, eax
	jnz	.alreadyinprogress
	; otherwise, we need to fire up a fresh one
	call	list$new
	mov	rbx, rax
	mov	rdi, [wcdns$pending]
	mov	rsi, r12
	mov	rdx, rax
	call	stringmap$insert_unique
	mov	edi, 40
	call	heap$alloc
	mov	[rax], r12
	mov	[rax+8], r13
	mov	[rax+16], r14
	mov	[rax+24], r15
	mov	qword [rax+32], 0
	mov	rdi, rbx
	mov	rsi, rax
	push	rax
	call	list$push_back
	mov	rdi, r12
	mov	rsi, .wcdns_success
	mov	rdx, .wcdns_failure
	pop	rcx
	call	dns$lookup_ipv4
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.alreadyinprogress:
	; rdx is a list of pendings, that are heap$allocd blocks of our arguments
	mov	rbx, rdx
	mov	edi, 40
	call	heap$alloc
	mov	[rax], r12
	mov	[rax+8], r13
	mov	[rax+16], r14
	mov	[rax+24], r15
	mov	qword [rax+32], 0
	mov	rdi, rbx
	mov	rsi, rax
	call	list$push_back
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.cacheresult:
	mov	rdi, r12
	mov	rsi, r15
	call	r13
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.wcdns_success:
	; rdi == string, rsi == pointer to heap$alloc from above, rdx == result
	push	rbx r12 r13 r14
	mov	rbx, rdi		; string
	mov	r12, rdx		; result
	mov	rsi, rdi
	mov	rdi, [wcdns$pending]
	call	stringmap$find_value
	test	eax, eax		; sanity only
	jz	.whoaoao
	mov	r13, rdx		; list
	mov	r14, [r13+_list_first_ofs]
calign
.wcdns_success_loop:
	mov	rcx, [r14+_list_valueofs]
	mov	rdi, [rcx]
	mov	rsi, [rcx+24]
	mov	rdx, r12
	call	qword [rcx+8]
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jnz	.wcdns_success_loop
	mov	rdi, r13
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r13
	call	heap$free
	mov	rdi, [wcdns$pending]
	mov	rsi, rbx
	call	stringmap$erase
	; make a copy of our string and insert it into our good list
	mov	rdi, rbx
	call	string$copy
	mov	rdi, [wcdns$good]
	mov	rsi, rax
	mov	rdx, r12
	call	stringmap$insert_unique
	pop	r14 r13 r12 rbx
	ret
calign
.whoaoao:
	pop	r14 r13 r12 rbx
	ret
falign
.wcdns_failure:
	; rdi == string, rsi == pointer to heap$alloc from above
	add	dword [rsi+32], 1
	cmp	dword [rsi+32], 3
	jae	.wcdns_properfail
	; otherwise, fire off the query again
	mov	rcx, rsi
	mov	rsi, .wcdns_success
	mov	rdx, .wcdns_failure
	call	dns$lookup_ipv4
	ret
calign
.wcdns_properfail:
	push	rbx r12 r13 r14
	mov	rbx, rdi		; string
	mov	rsi, rdi
	mov	rdi, [wcdns$pending]
	call	stringmap$find_value
	test	eax, eax		; sanity only
	jz	.whoaoao
	mov	r13, rdx		; list
	mov	r14, [r13+_list_first_ofs]
calign
.wcdns_properfail_loop:
	mov	rcx, [r14+_list_valueofs]
	mov	rdi, [rcx]
	mov	rsi, [rcx+24]
	call	qword [rcx+16]
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jnz	.wcdns_properfail_loop
	mov	rdi, r13
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r13
	call	heap$free
	mov	rdi, [wcdns$pending]
	mov	rsi, rbx
	call	stringmap$erase
	pop	r14 r13 r12 rbx
	ret

end if


if used wchost$new | defined include_everything


wchost_hostkey_ofs = 0
wchost_hostname_ofs = 8
wchost_port_ofs = 16
wchost_webclient_ofs = 24
wchost_usedns_ofs = 32
wchost_indns_ofs = 36
wchost_channels_ofs = 40
wchost_queue_ofs = 48
wchost_tlsid_ofs = 56			; 32 bytes max per the spec
wchost_tlsidlen_ofs = 88
wchost_istls_ofs = 92
wchost_dnscount_ofs = 96
wchost_raddr_ofs = 100			; sockaddr_in_size

wchost_size = wchost_raddr_ofs + 16


	; four arguments: rdi == hostkey, rsi == hostname, edx == port, rcx == webclient we belong to
	; we assume ownership of both strings
falign
wchost$new:
	prolog	wchost$new
	push	rbx rdi rsi rdx rcx
	mov	edi, wchost_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	rbx, rax
	mov	[rax+wchost_hostkey_ofs], rdi
	mov	[rax+wchost_hostname_ofs], rsi
	mov	[rax+wchost_port_ofs], rdx
	mov	[rax+wchost_webclient_ofs], rcx
	lea	rdi, [rax+wchost_raddr_ofs]
	call	inet_addr
	test	eax, eax
	jz	.dns
	; make sure it didn't return us with 0.0.0.0 or 255.255.255.255
	lea	rdi, [rbx+wchost_raddr_ofs+4]
	cmp	dword [rdi], 0
	je	.dns
	cmp	dword [rdi], 0xffffffff
	je	.dns
	call	list$new
	mov	[rbx+wchost_channels_ofs], rax
	call	list$new
	mov	[rbx+wchost_queue_ofs], rax
	mov	rax, rbx
	pop	rbx
	epilog
calign
.dns:
	call	list$new
	mov	[rbx+wchost_channels_ofs], rax
	call	list$new
	mov	[rbx+wchost_queue_ofs], rax
	mov	dword [rbx+wchost_usedns_ofs], 1
	mov	dword [rbx+wchost_indns_ofs], 1
	mov	rdi, [rbx+wchost_hostname_ofs]
	mov	rsi, .dns_success
	mov	rdx, .dns_failure
	mov	rcx, rbx
if webclient_global_dnscache
	call	wcdns$lookup_ipv4
else
	call	dns$lookup_ipv4
end if
	mov	rax, rbx
	pop	rbx
	epilog
falign
.dns_success:
	; so we got passed: rdi with our originalstring, rsi == wchost object, rdx == result of the lookup
	mov	dword [rsi+wchost_indns_ofs], 0
	; setup our raddr
	lea	rdi, [rsi+wchost_raddr_ofs]
	mov	eax, [rsi+wchost_port_ofs]
	mov	word [rdi], 2		; AF_INET/PF_INET
	xchg	ah,al
	mov	word [rdi+2], ax	; htons(port)
	mov	dword [rdi+4], edx
	; address is all setup, now we can fire things up
	mov	rdi, rsi
	call	wchost$checkqueue
	ret
falign
.dns_failure:
if webclient_global_dnscache = 0
	; we'll try a few times before we properly give up the ghost
	; so we got passed: rdi with our original string, rsi == wchost object
	add	dword [rsi+wchost_dnscount_ofs], 1
	cmp	dword [rsi+wchost_dnscount_ofs], 3
	jae	.dns_properfail
	; otherwise, do it again
	mov	rcx, rsi
	mov	rsi, .dns_success
	mov	rdx, .dns_failure
	call	dns$lookup_ipv4
	ret
calign
.dns_properfail:
end if
	; so, we need to fail out all our requests, but first remove us from the webclient
	; in case the failure results in immediate retries (cuz then we'd infinite loop)
	mov	rdx, [rsi+wchost_webclient_ofs]
	push	rbx
	mov	rbx, rsi
	mov	rdi, [rdx+webclient_hosts_ofs]
	mov	rsi, [rsi+wchost_hostkey_ofs]
	call	stringmap$erase
	; so now that we are not sitting in its hosts entry again, we need to fail all our wcrequests
	mov	rdi, [rbx+wchost_queue_ofs]
	mov	rsi, .dns_reqfail
	mov	rdx, webclient_fail_dns
	call	list$clear_arg
	; kill ourself and then bailout
	mov	rdi, rbx
	call	wchost$destroy
	pop	rbx
	ret
falign
.dns_reqfail:
	; rdi == wcrequest object, rsi == error code we are sending back
	mov	rcx, [_epoll_tv_msecs]
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+wcrequest_callbackarg_ofs]
	mov	rdx, [rbx+wcrequest_url_ofs]
	sub	rcx, [rbx+wcrequest_starttime_ofs]
	call	qword [rbx+wcrequest_callback_ofs]
	; remove the request from the webclient's inflight list
	mov	rcx, [rbx+wcrequest_webclient_ofs]
	mov	rsi, rbx
	mov	rdi, [rcx+webclient_inflight_ofs]
	call	unsignedmap$erase
	mov	rdi, rbx
	call	wcrequest$destroy
	pop	rbx
	ret

end if


if used wchost$destroy | defined include_everything
	; single argument in rdi: wchost object
falign
wchost$destroy:
	prolog	wchost$destroy
	mov	rcx, [rdi+wchost_webclient_ofs]
	push	rbx
	mov	rbx, rdi
	mov	rsi, [rdi+wchost_hostkey_ofs]
	mov	rdi, [rcx+webclient_hosts_ofs]
	call	stringmap$erase
	mov	rdi, [rbx+wchost_hostkey_ofs]
	call	heap$free
	mov	rdi, [rbx+wchost_hostname_ofs]
	call	heap$free
	mov	rdi, [rbx+wchost_channels_ofs]
	mov	rsi, wcio$destroy
	call	list$clear
	mov	rdi, [rbx+wchost_channels_ofs]
	call	heap$free
	mov	rdi, [rbx+wchost_queue_ofs]
	mov	rsi, wcrequest$destroy
	call	list$clear
	mov	rdi, [rbx+wchost_queue_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog

end if


if used wchost$request | defined include_everything
	; two arguments: rdi == wchost object, rsi == wcrequest object
falign
wchost$request:
	prolog	wchost$request
	; we add this straight to the queue no matter what, then let checkqueue deal with it
	push	rdi
	mov	rdi, [rdi+wchost_queue_ofs]
	call	list$push_back
	pop	rdi
	call	wchost$checkqueue
	epilog

end if




if used wcio$new | defined include_everything

	; so the wcio object is an io layer that deals with the actual HTTP comms, irrespective of whether it is a TLS connection or not.
	; during this function, wcio$new, the necessary io layers are built such that the chain is complete and underway when this function
	; completes

dalign
wcio$vtable:
	dq	wcio$destroy, io$clone, wcio$connected, io$send, wcio$receive, wcio$error, wcio$timeout


wcio_wchost_ofs = io_base_size
wcio_wcrequest_ofs = io_base_size + 8		; if this is null, it means we are not busy
wcio_timerptr_ofs = io_base_size + 16		; our "hey something went whacky" timer, reset on every receive
wcio_timedout_ofs = io_base_size + 24		; if we really did timeout, we need to know so we don't try to free the timerptr
wcio_response_ofs = io_base_size + 32		; our accumulated response buffer

wcio_size = io_base_size + 40



	; two arguments: rdi == wchost object to whom we belong, rsi == wcrequest object we are handling initially
falign
wcio$new:
	prolog	wcio$new
	push	rbx r12 rdi rsi
	call	buffer$new
	push	rax
	mov	edi, wcio_size
	call	heap$alloc_clear
	pop	rdx rsi rdi
	mov	rbx, rax
	mov	qword [rax], wcio$vtable
	mov	[rax+wcio_wchost_ofs], rdi
	mov	[rax+wcio_wcrequest_ofs], rsi
	mov	[rax+wcio_response_ofs], rdx
	mov	r12, rsi
	cmp	dword [rsi+wcrequest_istls_ofs], 0
	jne	.tls
	mov	rcx, [rsi+wcrequest_webclient_ofs]
	; no tls, so we'll use a straight unadulterated epoll layer only below the wcio layer
	mov	rdi, epoll$default_vtable
	xor	esi, esi
	add	qword [rcx+webclient_connects_ofs], 1
	call	epoll$new
	; link that to our own
	mov	[rbx+io_child_ofs], rax
	mov	[rax+io_parent_ofs], rbx
	; fire off the outbound
	mov	rcx, [rbx+wcio_wchost_ofs]
	mov	rdx, rbx
	lea	rdi, [rcx+wchost_raddr_ofs]
	mov	esi, sockaddr_in_size
	call	epoll$outbound
	jmp	.errorcheck
calign
.tls:
	xor	eax, eax
	mov	rcx, [rdi+wchost_webclient_ofs]
	mov	esi, [rdi+wchost_tlsidlen_ofs]
	lea	rdi, [rdi+wchost_tlsid_ofs]
	cmp	dword [rcx+webclient_notlsresume_ofs], 0
	cmovne	rsi, rax
	cmovne	rdi, rax
	add	qword [rcx+webclient_connects_ofs], 1
	call	tls$new_client
	; link that to our own
	mov	[rbx+io_child_ofs], rax
	mov	[rax+io_parent_ofs], rbx
	; now create the epoll layer underneath that
	push	rax
	mov	rdi, epoll$default_vtable
	xor	esi, esi
	call	epoll$new
	pop	rcx
	mov	[rcx+io_child_ofs], rax
	mov	[rax+io_parent_ofs], rcx
	; fire off the outbound
	mov	rcx, [rbx+wcio_wchost_ofs]
	mov	rdx, rbx
	lea	rdi, [rcx+wchost_raddr_ofs]
	mov	esi, sockaddr_in_size
	call	epoll$outbound
calign
.errorcheck:
	; epoll$outbound returns a bool as to whether or not it made it through to EINPROGRESS
	; these can fail immediately though, so we need to check for errors here and now
	test	eax, eax
	jz	.failed
	; create our timer so that we don't sit here indefinitely
	mov	edi, webclient_readtimeout
	mov	rsi, rbx
	call	epoll$timer_new
	mov	[rbx+wcio_timerptr_ofs], rax

if webclient_debug
	mov	rdi, .debug1
	call	string$to_stdoutln
end if

	; normal return
	mov	rax, rbx
	pop	r12 rbx
	epilog
if webclient_debug
cleartext .debug1, '------------------------------------------------------------------ wcio$new ------------------------------------------------------------'
end if
calign
.failed:
	; so here, epoll$outbound _already_ destroyed us and all of our iochain
	; we hungon to the wcrequest object in r12 specifically for this case
	; so we can issue a fail callback and return null from here so that the
	; wchost layer doesn't add us as a channel
	mov	rcx, [_epoll_tv_msecs]
	mov	rdi, [r12+wcrequest_callbackarg_ofs]
	mov	rsi, webclient_fail_preconnect
	mov	rdx, [r12+wcrequest_url_ofs]
	sub	rcx, [r12+wcrequest_starttime_ofs]
	call	qword [r12+wcrequest_callback_ofs]
	; remove the request from the webclient's inflight list
	mov	rcx, [r12+wcrequest_webclient_ofs]
	mov	rsi, r12
	mov	rdi, [rcx+webclient_inflight_ofs]
	add	qword [rcx+webclient_errors_ofs], 1
	call	unsignedmap$erase
	mov	rdi, r12
	call	wcrequest$destroy
	xor	eax, eax
	pop	r12 rbx
	epilog

end if


if used wcio$request | defined include_everything
	; two arguments: rdi == our wcio object, rsi == wcrequest object to deal with
	; this is used for subsequent (keep-alive) requests
falign
wcio$request:
	prolog	wcio$request
	mov	r8, [_epoll_tv_msecs]
	mov	[rdi+wcio_wcrequest_ofs], rsi
	push	rdi
	mov	rdi, [rsi+wcrequest_object_ofs]
	push	qword [rdi+mimelike_xmitbody_ofs]
	push	qword [rsi+wcrequest_webclient_ofs]
	mov	[rsi+wcrequest_starttime_ofs], r8
	xor	esi, esi
	call	mimelike$compose
	pop	r8 rcx rdi
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]
	add	qword [r8+webclient_totalsent_ofs], rdx

if webclient_debug
	push	rdi rsi rdx rcx
	push	rsi rdx
	mov	rdi, .debug1
	call	string$to_stdoutln
	pop	rdx rsi
	mov	eax, syscall_write
	mov	edi, 1
	syscall
	pop	rcx rdx rsi rdi
end if

	call	qword [rcx+io_vsend]
	epilog
if webclient_debug
cleartext .debug1, 'Sending request:'
end if

end if


if used wcio$destroy | defined include_everything
	; single argument in rdi: our wcio object
	; all we do is free our response buffer and kill our timer (if we have one), otherwise we let io$destroy deal with it
	; calls to error will ultimately remove us from the wchost channels list, and we do not touch wcrequest
falign
wcio$destroy:
	prolog	wcio$destroy
	push	rbx
	mov	rbx, rdi
	cmp	dword [rdi+wcio_timedout_ofs], 0
	jne	.skiptimer
	mov	rdi, [rdi+wcio_timerptr_ofs]
	test	rdi, rdi
	jz	.skiptimer
	call	epoll$timer_clear
calign
.skiptimer:
	mov	rdi, [rbx+wcio_response_ofs]
	call	buffer$destroy

	; if we still have a request sitting here, we need to call our error handler
	cmp	qword [rbx+wcio_wcrequest_ofs], 0
	jne	.with_error
	mov	rdi, rbx
	call	io$destroy
	pop	rbx
if webclient_debug
	mov	rdi, .debug1
	call	string$to_stdoutln
end if
	epilog
calign
.with_error:
	mov	rdi, rbx
	call	wcio$error
	mov	rdi, rbx
	call	io$destroy
	pop	rbx
if webclient_debug
	mov	rdi, .debug1
	call	string$to_stdoutln
end if

	epilog
if webclient_debug
cleartext .debug1, '========================================================== wcio$destroy =========================================================='
end if

end if


if used wcio$connected | defined include_everything
	; single argument in rdi: our wcio object
	; NOTE: if we are a tls webclient (and ONLY if), then we get rsi == session id bytes, edx == length of same
	; here is here we compose our xmitbody and send it all down the line
falign
wcio$connected:
	prolog	wcio$connected
	mov	rcx, [rdi+wcio_wcrequest_ofs]
	cmp	dword [rcx+wcrequest_istls_ofs], 0
	jne	.tls_connected
calign
.doit:
	mov	r8, [_epoll_tv_msecs]
	push	rdi
	mov	rdi, [rcx+wcrequest_object_ofs]
	push	qword [rdi+mimelike_xmitbody_ofs]
	mov	[rcx+wcrequest_starttime_ofs], r8
	push	qword [rcx+wcrequest_webclient_ofs]
	xor	esi, esi
	call	mimelike$compose
	pop	r8 rcx rdi
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]
	add	qword [r8+webclient_totalsent_ofs], rdx

if webclient_debug
	push	rdi rsi rdx rcx
	push	rsi rdx
	mov	rdi, .debug1
	call	string$to_stdoutln
	pop	rdx rsi
	mov	eax, syscall_write
	mov	edi, 1
	syscall
	pop	rcx rdx rsi rdi
end if

	call	qword [rcx+io_vsend]
	epilog
if webclient_debug
cleartext .debug1, 'Sending request:'
end if
calign
.tls_connected:
	mov	rcx, [rdi+wcio_wchost_ofs]
	push	rdi
	mov	dword [rcx+wchost_tlsidlen_ofs], edx
	mov	dword [rcx+wchost_istls_ofs], 1
	lea	rdi, [rcx+wchost_tlsid_ofs]
	call	memcpy

	pop	rdi
	mov	rcx, [rdi+wcio_wcrequest_ofs]
	jmp	.doit

end if

if used wcio$receive | defined include_everything
	; three arguments: rdi == our wcio object, rsi == ptr to data, rdx == length of same
falign
wcio$receive:
	prolog	wcio$receive
	mov	rcx, [rdi+wcio_wcrequest_ofs]
	push	rbx
	mov	rbx, rdi
	; webslap required mod here to record when we received the first byte of our reply
	; noting here that it really isn't useful for maxconns >1
	mov	rcx, [rcx+wcrequest_webclient_ofs]
	mov	rax, [_epoll_tv_msecs]
	mov	rdi, [rdi+wcio_response_ofs]
	cmp	qword [rcx+webclient_replystamp_ofs], 0
	jne	.skipinitialstamp
	mov	[rcx+webclient_replystamp_ofs], rax
calign
.skipinitialstamp:
	call	buffer$append
	; reset our timer
	mov	rdi, [rbx+wcio_timerptr_ofs]
	call	epoll$timer_reset
	; see if we got a complete response, noting that we check headers only first
	; as some replies may not contain a response body (namely: HEAD requests)
	mov	r8, [rbx+wcio_response_ofs]
	mov	edx, 1		; headers only to start with
	mov	ecx, 1		; preface exists
	mov	rdi, [r8+buffer_itself_ofs]
	mov	rsi, [r8+buffer_length_ofs]
	xor	r8d, r8d
	call	mimelike$new_parse
	test	rax, rax
	jz	.needmore
	push	r12
	mov	r12, rax
	; otherwise, we got a valid set of headers
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	cmp	dword [rcx+wcrequest_headers_ofs], 0
	jne	.complete_response
	; otherwise, try and intelligently deal with our response buffer rather than
	; perpetually parse it for each and every time we receive data
	; (noting of course that we do parse the headers each and every time, which
	; is of course inefficient... for my purposes though, we don't need the extra
	; overhead of keeping header + expected length precalculations/etc)
	; basically, there are three cases: 1) Content-Length was specified, 2) chunked
	; and 3) we have no easy clue, in which case we'll brute parse it
	mov	rdi, r12
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jnz	.fullresponse_contentlength
	mov	rdi, r12
	mov	rsi, mimelike$transferencoding
	call	mimelike$getheader
	test	rax, rax
	jnz	.fullresponse_transferencoding
	; otherwise, let the mimelike parser work out whether we have the full goods or not
	mov	rdi, r12
	call	mimelike$destroy
calign
.fullparse:
	mov	r8, [rbx+wcio_response_ofs]
	xor	edx, edx	; full body please
	mov	ecx, 1		; preface exists
	mov	rdi, [r8+buffer_itself_ofs]
	mov	rsi, [r8+buffer_length_ofs]
	xor	r8d, r8d
	call	mimelike$new_parse
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	test	rax, rax
	jz	.fullresponse_needmore
	; otherwise, we got the full response, shoot it
	mov	r12, rax
	jmp	.complete_response
dalign
.finalchunk:
	db	13,10,48,13,10,13,10
calign
.fullresponse_transferencoding:
	; if it equals chunked, then we can check the very end of the response buffer (since we don't do pipelined requests)
	mov	rdi, rax
	mov	rsi, mimelike$chunked
	call	string$equals
	push	rax
	mov	rdi, r12
	call	mimelike$destroy
	pop	rax
	test	eax, eax
	jz	.fullparse
	; otherwise, chunked it is... so we know that we have a decent amount of header space
	mov	r8, [rbx+wcio_response_ofs]
	mov	rsi, [r8+buffer_endptr_ofs]
	mov	rdi, .finalchunk
	mov	edx, 7
	sub	rsi, 7
	cmp	dword [rsi], 0x0d300a0d
	jne	.fullresponse_needmore
	call	memcmp
	test	rax, rax
	jnz	.fullresponse_needmore
	jmp	.fullparse
calign
.fullresponse_contentlength:
	; rax is the string of the content length value
	; turn that into a number and see if we have enough before we bother parse attempts
	mov	rdi, rax
	call	string$to_unsigned
	add	rax, [r12+mimelike_hdrlen_ofs]
	push	rax
	mov	rdi, r12
	call	mimelike$destroy
	pop	rax

	; now we can compare that number to our response size
	mov	rcx, [rbx+wcio_response_ofs]
	cmp	rax, [rcx+buffer_length_ofs]
	jbe	.fullparse
	; otherwise, need more
	pop	r12 rbx
	xor	eax, eax	; don't kill us off
	epilog
calign
.fullresponse_needmore:
	pop	r12 rbx
	xor	eax, eax	; don't kill us off
	epilog
calign
.complete_response:
	; special handling here if we got a 301 or 302 and our follow redirects setting is enabled
if webclient_follow_redirects
	mov	rdi, [r12+mimelike_preface_ofs]
	mov	esi, 9
	mov	edx, 3
	call	string$substr
	push	rax
	mov	rdi, rax
	mov	rsi, .s302
	call	string$equals
	test	eax, eax
	jnz	.complete_redirect
	mov	rdi, [rsp]
	mov	rsi, .s301
	call	string$equals
	test	eax, eax
	jnz	.complete_redirect
	pop	rdi
	call	heap$free
calign
.completed_proceed:
end if
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	r8, [rbx+wcio_response_ofs]
	mov	r9, [r12+mimelike_hdrlen_ofs]
	mov	rdx, [rcx+wcrequest_webclient_ofs]
	mov	r10, [r8+buffer_length_ofs]
	add	[rdx+webclient_totalreceived_ofs], r10
	sub	r10, r9
	add	[rdx+webclient_bodyreceived_ofs], r10

if webclient_debug
	mov	rdi, .debug1
	call	string$to_stdoutln
	mov	rcx, [rbx+wcio_response_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	syscall
end if

	; clear our response buffer
	mov	rdi, [rbx+wcio_response_ofs]
	call	buffer$reset

	; if our webclient has a cookiejar, let it deal with cookies
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdx, [rcx+wcrequest_webclient_ofs]
	mov	rdi, [rdx+webclient_cookiejar_ofs]
	test	rdi, rdi
	jz	.skipcookies
	mov	rsi, [rcx+wcrequest_url_ofs]
	mov	rdx, r12
	call	cookiejar$set
calign
.skipcookies:
	; if we got a Connection: close, it is important that we deal with that here and now
	; rather than wait for the connection to actually be torn down, and that is because
	; our wchost parent object will (potentially) immediately queue another request for us
	; that would of course fail, whereas if we deal with it here, we can eliminate that
	; possibility, thus forcing the wchost object to open a new channel
	mov	rdi, r12
	mov	rsi, mimelike$connection
	call	mimelike$getheader
	test	rax, rax
	jz	.completed_keepalive
	mov	rdi, rax
	mov	rsi, .close
	call	string$equals
	test	eax, eax
	jz	.completed_keepalive_nocheck
calign
.completed_closing:
	; otherwise, Connection: close was received
	mov	r8, [_epoll_tv_msecs]
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdi, [rcx+wcrequest_callbackarg_ofs]
	mov	rsi, r12
	mov	rdx, [rcx+wcrequest_url_ofs]
	sub	r8, [rcx+wcrequest_starttime_ofs]
	xchg	r8, rcx
	call	qword [r8+wcrequest_callback_ofs]

	; remove the request from the webclient's inflight list
	mov	rsi, [rbx+wcio_wcrequest_ofs]
	mov	rcx, [rsi+wcrequest_webclient_ofs]
	mov	rdi, [rcx+webclient_inflight_ofs]
	call	unsignedmap$erase

	; cleanup all our goods first
	mov	rdi, r12
	call	mimelike$destroy
	mov	rdi, [rbx+wcio_wcrequest_ofs]
	mov	qword [rbx+wcio_wcrequest_ofs], 0
	call	wcrequest$destroy
	; next up, let the wchost layer know we are outta here
	mov	rdi, [rbx+wcio_wchost_ofs]
	mov	rsi, rbx
	call	wchost$channelclose
	pop	r12 rbx
	mov	eax, 1		; suicide please
	epilog
cleartext .close, 'close'
if webclient_debug
cleartext .debug1, 'Complete Response:'
cleartext .debug2, 'Redirect Response:'
end if
calign
.completed_keepalive:
	; make sure that it isn't a HTTP/1.0 otherwise assume we are closing
	mov	rdi, [r12+mimelike_preface_ofs]
	mov	rsi, .httponedotoh
	call	string$starts_with
	test	eax, eax
	jnz	.completed_closing
calign
.completed_keepalive_nocheck:
	mov	r8, [_epoll_tv_msecs]
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdi, [rcx+wcrequest_callbackarg_ofs]
	mov	rsi, r12
	push	rcx
	mov	rdx, [rcx+wcrequest_url_ofs]
	mov	qword [rbx+wcio_wcrequest_ofs], 0
	sub	r8, [rcx+wcrequest_starttime_ofs]
	xchg	r8, rcx
	call	qword [r8+wcrequest_callback_ofs]

	; remove the request from the webclient's inflight list
	mov	rsi, [rsp]
	mov	rcx, [rsi+wcrequest_webclient_ofs]
	mov	rdi, [rcx+webclient_inflight_ofs]
	call	unsignedmap$erase

	mov	rdi, r12
	call	mimelike$destroy
	pop	rdi
	call	wcrequest$destroy

	; call checkqueue before we are done
	mov	rdi, [rbx+wcio_wchost_ofs]
	call	wchost$checkqueue

	pop	r12 rbx
	xor	eax, eax	; don't kill us off
	epilog
if webclient_follow_redirects
cleartext .s301, '301'
cleartext .s302, '302'
cleartext .location, 'Location'
cleartext .httponedotoh, 'HTTP/1.0 '
calign
.complete_redirect:
	pop	rdi
	call	heap$free

	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	r8, [rbx+wcio_response_ofs]
	mov	r9, [r12+mimelike_hdrlen_ofs]
	mov	rdx, [rcx+wcrequest_webclient_ofs]
	mov	r10, [r8+buffer_length_ofs]
	add	[rdx+webclient_totalreceived_ofs], r10
	sub	r10, r9
	add	[rdx+webclient_bodyreceived_ofs], r10


if webclient_debug
	mov	rdi, .debug2
	call	string$to_stdoutln
	mov	rcx, [rbx+wcio_response_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	syscall
end if

	; clear our response buffer
	mov	rdi, [rbx+wcio_response_ofs]
	call	buffer$reset
	; we require a Location: header, or no deal
	mov	rdi, r12
	mov	rsi, .location
	call	mimelike$getheader
	test	rax, rax
	jz	.completed_proceed
	; otherwise, we need to construct a new url to replace our old one
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rsi, rax
	mov	rdi, [rcx+wcrequest_url_ofs]
	call	url$new
	test	rax, rax
	jz	.completed_proceed
	; otherwise, swap them
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdi, [rcx+wcrequest_url_ofs]
	mov	[rcx+wcrequest_url_ofs], rax
	call	url$destroy
	; construct a new preface from the old one
	; substr the request method, add the rest ourselves
	; we need the preface from the wcrequest_object_ofs
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdx, [rcx+wcrequest_object_ofs]
	mov	rdi, [rdx+mimelike_preface_ofs]
	mov	esi, ' '
	push	rdi
	call	string$indexof_charcode
	pop	rdi
	xor	esi, esi
	mov	edx, eax
	add	edx, 1
	call	string$substr
	push	rax
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdi, [rcx+wcrequest_url_ofs]
	call	url$topreface
	mov	rdi, [rsp]
	push	rax
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+8]
	mov	[rsp+8], rax
	call	heap$free
	pop	rdi
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, .httponedotone
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rcx, [rbx+wcio_wcrequest_ofs]
	mov	rdi, [rcx+wcrequest_object_ofs]
	pop	rsi
	call	mimelike$setpreface_nocopy
	; ok so now we have a new preface with the [possibly relative] redirect location
	; now we have to do the same Connection: close awareness/checking as before for a normal request
	mov	rdi, r12
	mov	rsi, mimelike$connection
	call	mimelike$getheader
	test	rax, rax
	jz	.redirect_keepalive
	mov	rdi, rax
	mov	rsi, .close
	call	string$equals
	test	eax, eax
	jz	.redirect_keepalive_nocheck
calign
.redirect_closing:
	; redirect, but our connection has to die
	; so we have to do similar things to the normal completion, but then immediately requeue a new one
	mov	rdi, r12
	call	mimelike$destroy
	mov	rdi, [rbx+wcio_wchost_ofs]
	mov	rsi, rbx
	call	wchost$channelclose
	; now we can requeue it
	mov	rdi, [rbx+wcio_wchost_ofs]
	mov	rsi, [rbx+wcio_wcrequest_ofs]
	mov	qword [rbx+wcio_wcrequest_ofs], 0
	call	wchost$request
	pop	r12 rbx
	mov	eax, 1			; suicide please
	epilog
calign
.redirect_keepalive:
	; make sure that it isn't a HTTP/1.0 otherwise assume we are closing
	mov	rdi, [r12+mimelike_preface_ofs]
	mov	rsi, .httponedotoh
	call	string$starts_with
	test	eax, eax
	jnz	.redirect_closing
calign
.redirect_keepalive_nocheck:
	mov	rdi, r12
	call	mimelike$destroy
	; we can trick the wchost layer into resending it out over our own connection
	mov	rdi, [rbx+wcio_wchost_ofs]
	mov	rsi, [rbx+wcio_wcrequest_ofs]
	mov	qword [rbx+wcio_wcrequest_ofs], 0
	call	wchost$request
	pop	r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
cleartext .httponedotone, ' HTTP/1.1'
end if
calign
.needmore:
	pop	rbx
	xor	eax, eax	; don't kill us off
	epilog

end if


if used wcio$error | defined include_everything
	; single argument in rdi: our wcio object
falign
wcio$error:
	prolog	wcio$error
	mov	rcx, [rdi+wcio_wcrequest_ofs]
	push	rbx
	mov	rbx, rdi
	; if we have an active request, we need to issue a callback
	test	rcx, rcx
	jz	.norequest
	mov	r8, [_epoll_tv_msecs]
	mov	rdi, [rcx+wcrequest_callbackarg_ofs]
	mov	rsi, webclient_fail_closed
	mov	rdx, [rcx+wcrequest_url_ofs]
	sub	r8, [rcx+wcrequest_starttime_ofs]
	xchg	r8, rcx
	call	qword [r8+wcrequest_callback_ofs]

	; remove the request from the webclient's inflight list
	mov	rsi, [rbx+wcio_wcrequest_ofs]
	mov	rcx, [rsi+wcrequest_webclient_ofs]
	mov	rdi, [rcx+webclient_inflight_ofs]
	add	qword [rcx+webclient_errors_ofs], 1
	call	unsignedmap$erase

	mov	rdi, [rbx+wcio_wcrequest_ofs]
	mov	qword [rbx+wcio_wcrequest_ofs], 0
	call	wcrequest$destroy
calign
.norequest:
	; and we need to notify the wchost layer that we are closing
	mov	rdi, [rbx+wcio_wchost_ofs]
	mov	rsi, rbx
	call	wchost$channelclose

	pop	rbx
	epilog

end if


if used wcio$timeout | defined include_everything
	; single argument in rdi: our wcio object
falign
wcio$timeout:
	prolog	wcio$timeout
	; same thing as error, but different notify to the request layer, and we set our timedout
	; flag so that destroy doesn't attempt to free it twice
	mov	rcx, [rdi+wcio_wcrequest_ofs]
	mov	dword [rdi+wcio_timedout_ofs], 1
	push	rbx
	mov	rbx, rdi
	; if we have an active request, we need to issue a callback
	test	rcx, rcx
	jz	.norequest
	mov	r8, [_epoll_tv_msecs]
	mov	rdi, [rcx+wcrequest_callbackarg_ofs]
	mov	rsi, webclient_fail_timeout
	mov	rdx, [rcx+wcrequest_url_ofs]
	sub	r8, [rcx+wcrequest_starttime_ofs]
	xchg	r8, rcx
	call	qword [r8+wcrequest_callback_ofs]

	; remove the request from the webclient's inflight list
	mov	rsi, [rbx+wcio_wcrequest_ofs]
	mov	rcx, [rsi+wcrequest_webclient_ofs]
	mov	rdi, [rcx+webclient_inflight_ofs]
	add	qword [rcx+webclient_errors_ofs], 1
	call	unsignedmap$erase

	mov	rdi, [rbx+wcio_wcrequest_ofs]
	mov	qword [rbx+wcio_wcrequest_ofs], 0
	call	wcrequest$destroy
calign
.norequest:
	; and we need to notify the wchost layer that we are closing
	mov	rdi, [rbx+wcio_wchost_ofs]
	mov	rsi, rbx
	call	wchost$channelclose
	pop	rbx
	mov	eax, 1		; let epoll layer tear us down
	epilog

end if


if used wchost$channelclose | defined include_everything
	; two arguments: rdi == wchost object, rsi == wcio object that is going away
	; we search for the wcio object in our channels list until we find it, then
	; remove the list _item_ (leaving the wcio object up to elsewhere to teardown)
falign
wchost$channelclose:
	prolog	wchost$channelclose
	push	rdi
	mov	rdi, [rdi+wchost_channels_ofs]
	mov	rdx, [rdi+_list_first_ofs]
	; we know there is at least one here
calign
.search:
	cmp	rsi, qword [rdx+_list_valueofs]
	je	.found
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.search
	; sanity only really, we KNOW it is in the list
	; make sure we recheck the queue
	pop	rdi
	call	wchost$checkqueue
	epilog
calign
.found:
	mov	rsi, rdx
	call	list$remove
	pop	rdi
	call	wchost$checkqueue
	epilog

end if


if used wchost$checkqueue | defined include_everything
	; single argument in rdi: wchost object
falign
wchost$checkqueue:
	prolog	wchost$checkqueue
	; if we are presently in dns, do nothing
	cmp	dword [rdi+wchost_indns_ofs], 0
	jne	.nothingtodo
	push	rbx
	mov	rbx, rdi
calign
.outer:
	mov	rsi, [rbx+wchost_queue_ofs]
	; if our queue size is zero, do nothing
	cmp	qword [rsi+_list_size_ofs], 0
	je	.bailout
	; first order of business: see if there are any non-busy channels
	mov	rdx, [rbx+wchost_channels_ofs]
	cmp	qword [rdx+_list_size_ofs], 0
	je	.checknew
	mov	rdx, [rdx+_list_first_ofs]
calign
.idlecheck:
	mov	rcx, [rdx+_list_valueofs]
	cmp	qword [rcx+wcio_wcrequest_ofs], 0
	je	.foundidle
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.idlecheck
	; failing that, check to see if we can add new connections
calign
.checknew:
	mov	rdx, [rbx+wchost_channels_ofs]
	mov	rcx, [rbx+wchost_webclient_ofs]

	mov	rax, [rdx+_list_size_ofs]
	cmp	rax, [rcx+webclient_maxconns_ofs]
	jae	.bailout
	; otherwise, create a new one
	mov	rdi, rsi
	call	list$pop_front
	mov	rdi, rbx
	mov	rsi, rax
	call	wcio$new
	test	rax, rax
	jz	.outer		; if that failed right out of the gate, the callback was notified
				; and we can safely keep going
	; otherwise, add it to our channels
	mov	rdi, [rbx+wchost_channels_ofs]
	mov	rsi, rax
	call	list$push_back
	jmp	.outer
calign
.foundidle:
	push	rcx
	mov	rdi, rsi
	call	list$pop_front
	pop	rdi
	mov	rsi, rax
	call	wcio$request
	jmp	.outer
	; and failing that, there isn't anything else for us to do
calign
.bailout:
	pop	rbx
	epilog
calign
.nothingtodo:
	epilog

end if



if used webclient$launch | defined include_everything
	; two arguments: rdi == webclient object, rsi == wcrequest object
falign
webclient$launch:
	prolog	webclient$launch
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	add	qword [rdi+webclient_requests_ofs], 1
	; first up, see if we already have a host entry
	mov	rdi, [rdi+webclient_hosts_ofs]
	mov	rsi, [r12+wcrequest_hostkey_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.newhost
calign
.gothost:
	; wchost object is sitting in rdx, pass it our wcrequest object and let it take over
	mov	rdi, rdx
	mov	rsi, r12
	push	rdx
	call	wchost$request
	pop	rdx
	; add it to our inflight list
	mov	rdi, [rbx+webclient_inflight_ofs]
	mov	rsi, r12
	; its value is our wchost object
	call	unsignedmap$insert_unique
	pop	r12 rbx
	epilog
calign
.newhost:
	; no hostkey was found, so create one, we have to make a copy of the hostkey, hostname
	mov	rdi, [r12+wcrequest_hostkey_ofs]
	call	string$copy
	push	rax
	mov	rdi, [r12+wcrequest_hostname_ofs]
	call	string$copy
	mov	rsi, rax
	mov	edx, [r12+wcrequest_port_ofs]
	pop	rdi
	mov	rcx, rbx
	call	wchost$new
	mov	rdi, [rbx+webclient_hosts_ofs]
	mov	rsi, [rax+wchost_hostkey_ofs]
	mov	rdx, rax
	push	rdx
	call	stringmap$insert_unique
	pop	rdx
	jmp	.gothost
	

end if
