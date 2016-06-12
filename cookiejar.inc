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
	; cookiejar.inc: HTTP/1.1 cookie handling
	;
	; NOTE 1: This is by no means an exhaustive/security minded implementation,
	; and is meant to just get the job done as required for automated web agents
	; (which is precisely why this is here.) If you were designing a proper user
	; agent, this would need considerably more attention policy/algorithm wise.
	;
	; NOTE 2: I didn't bother with the public suffix list or anything, as that is
	; not part of my use cases for any of this. Would be easy enough to add if
	; needed though.
	;
	; This implementation just uses a list for its cookies, which is fine for
	; small amounts of them. If the list were to be _huge_ however, we'd want
	; to modify this to a multiple-keyed stringmap or something similar.
	;


cookie_expiry_ofs = 0		; double (0 == session, nonzero == truncated jd timestamp)
cookie_domain_ofs = 8		; string
cookie_path_ofs = 16		; string
cookie_name_ofs = 24		; string
cookie_value_ofs = 32		; string
cookie_secure_ofs = 40		; bool
cookie_httponly_ofs = 44	; bool

cookie_size = 48


if used cookiejar$new | defined include_everything
	; no arguments, all a cookiejar is is a list$new
falign
cookiejar$new:
	prolog	cookiejar$new
	call	list$new
	epilog

end if


if used cookiejar$new_from_buffer | defined include_everything
	; single argument in rdi: a buffer with our "custom" cookie format (which is to say, our UTF8 semicolon delimited goods created in to_buffer below)
falign
cookiejar$new_from_buffer:
	prolog	cookiejar$new_from_buffer
	; because we destroy the buffer as we consume lines from it, make a copy
	push	rbx r12 r13 r14 r15
	call	buffer$copy
	mov	r12, rax
	call	list$new
	mov	rbx, rax
	; use our lazy implementation from buffer to do the deed:
calign
.lineloop:
	mov	rdi, r12
	mov	esi, 1
	call	buffer$has_more_lines
	test	eax, eax
	jz	.linesdone
	mov	rdi, r12
	call	buffer$nextline
	mov	r13, rax
	mov	rdi, rax
	mov	esi, ';'
	call	string$split
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	cmp	qword [r13+_list_size_ofs], 7
	jne	.lineskip
	mov	edi, cookie_size
	call	heap$alloc_clear
	mov	r14, rax

	mov	rdi, r13
	call	list$pop_front
	mov	r15, rax
	mov	rdi, rax
	call	string$to_double
	movq	[r14+cookie_expiry_ofs], xmm0
	mov	rdi, r15
	call	heap$free
	mov	rdi, r13
	call	list$pop_front
	mov	[r14+cookie_domain_ofs], rax
	mov	rdi, r13
	call	list$pop_front
	mov	[r14+cookie_path_ofs], rax
	mov	rdi, r13
	call	list$pop_front
	mov	[r14+cookie_name_ofs], rax
	mov	rdi, r13
	call	list$pop_front
	mov	[r14+cookie_value_ofs], rax
	mov	rdi, r13
	call	list$pop_front
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .one
	call	string$equals
	mov	[r14+cookie_secure_ofs], eax
	mov	rdi, r15
	call	heap$free
	mov	rdi, r13
	call	list$pop_front
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .one
	call	string$equals
	mov	[r14+cookie_httponly_ofs], eax
	mov	rdi, r15
	call	heap$free
	mov	rdi, r13
	call	heap$free
	jmp	.lineloop
cleartext .one, '1'
calign
.lineskip:
	mov	rdi, r13
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r13
	call	heap$free
	jmp	.lineloop
calign
.linesdone:
	mov	rdi, r12
	call	buffer$destroy
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	epilog

end if


if used cookiejar$destroy | defined include_everything
	; single argument in rdi: cookiejar
falign
cookiejar$destroy:
	prolog	cookiejar$destroy
	push	rdi
	mov	rbx, rdi
	mov	rsi, .itemdel
	call	list$clear
	pop	rdi
	call	heap$free
	epilog
falign
.itemdel:
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+cookie_domain_ofs]
	call	heap$free
	mov	rdi, [rbx+cookie_path_ofs]
	call	heap$free
	mov	rdi, [rbx+cookie_name_ofs]
	call	heap$free
	mov	rdi, [rbx+cookie_path_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	ret

end if


if used cookiejar$to_buffer | defined include_everything
	; single argument in rdi: cookiejar object
	; returns a buffer$new with our "custom" cookie format (does not include session ones of course)
	; (NOTE: turns it into UTF8 on the way out)
falign
cookiejar$to_buffer:
	prolog	cookiejar$to_buffer
	push	rbx r12
	mov	rbx, rdi
	call	buffer$new
	mov	r12, rax
	cmp	qword [rbx+_list_size_ofs], 0
	je	.done
	mov	rdi, rbx
	mov	rsi, .each
	mov	rdx, r12
	call	list$foreach_arg
calign
.done:
	mov	rax, r12
	pop	r12 rbx
	epilog
falign
.each:
	; rdi == cookie, rsi == buffer to add it to
	cmp	qword [rdi+cookie_expiry_ofs], 0
	je	.each_nodeal
	push	r12 r13
	mov	r12, rdi
	mov	r13, rsi
	movq	xmm0, [rdi+cookie_expiry_ofs]
	mov	edi, double_string_normal
	mov	esi, 15
	call	string$from_double
	push	rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r13
	mov	esi, ';'
	call	buffer$append_byte
	mov	rdi, r13
	mov	rsi, [r12+cookie_domain_ofs]
	call	buffer$append_string
	mov	rdi, r13
	mov	esi, ';'
	call	buffer$append_byte
	mov	rdi, r13
	mov	rsi, [r12+cookie_path_ofs]
	call	buffer$append_string
	mov	rdi, r13
	mov	esi, ';'
	call	buffer$append_byte
	mov	rdi, r13
	mov	rsi, [r12+cookie_name_ofs]
	call	buffer$append_string
	mov	rdi, r13
	mov	esi, ';'
	call	buffer$append_byte
	mov	rdi, r13
	mov	rsi, [r12+cookie_value_ofs]
	call	buffer$append_string
	mov	rdi, r13
	mov	esi, ';'
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, '0'
	mov	edx, '1'
	cmp	dword [r12+cookie_secure_ofs], 0
	cmovne	esi, edx
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, ';'
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, '0'
	mov	edx, '1'
	cmp	dword [r12+cookie_httponly_ofs], 0
	cmovne	esi, edx
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, 10
	call	buffer$append_byte
	pop	r13 r12
	ret
calign
.each_nodeal:
	ret

end if


if used cookiejar$set | defined include_everything
	; three arguments: rdi == cookiejar object, rsi == url of response, rdx == mimelike response object (which may have Set-Cookie header)
	; bails out if an error
falign
cookiejar$set:
	prolog	cookiejar$set
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	rdi, rdx
	mov	rsi, mimelike$setcookie
	call	mimelike$getheader
	test	rax, rax
	jz	.nothingtodo
	mov	rdi, rax
	call	string$copy
	mov	r13, rax
	; NOTE: this is horrifically inefficient, in part because of the way I decided to smash mimelike duplicate headers together
	; with ', '
	; and since Expires= also contains ', ', we can't split the string by ', ' until we get rid of the sane date formats first
	; hahaha, amusing in a weird sorta way
	; so, first things first, replace all Expires= entries with their parsed double values
calign
.expires_loop:
	mov	rdi, r13
	mov	rsi, .expiresequal
	call	string$indexof
	cmp	rax, -1
	je	.expires_checklowercase
calign
.expires_doit:
	; so from there to Expires=+29 (37 characters)
	mov	rdi, r13
	mov	rsi, rax
	mov	edx, 37
	call	string$substr
	mov	r14, rax		; our search string for our replacement
	mov	rdi, rax
	mov	esi, 8
	mov	rdx, -1
	call	string$substr
	mov	r15, rax		; the actual date
	mov	rdi, rax
	call	datetime$rfc5322_to_timestamp
	; we know heap$free doesn't mess with xmm0
	mov	rdi, r15
	call	heap$free
	xorpd	xmm1, xmm1
	ucomisd	xmm0, xmm1
	je	.bad_expires
	; otherwise, turn that back into a string
	mov	edi, double_string_normal
	mov	esi, 15
	call	string$from_double
	; concat that with our expiresequal
	mov	r15, rax
	mov	rdi, .htexpiryequal
	mov	rsi, rax
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; so now we can replace it
	mov	rdi, r13
	mov	rsi, r14
	mov	rdx, r15
	call	string$replace
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	; free both and keep going
	mov	rdi, r15
	call	heap$free
	mov	rdi, r14
	call	heap$free
	jmp	.expires_loop
calign
.expires_checklowercase:
	mov	rdi, r13
	mov	rsi, .lcexpiresequal
	call	string$indexof
	cmp	rax, -1
	jne	.expires_doit
calign
.expires_done:
	; so now, we can split the string by ', '
	mov	rdi, r13
	mov	rsi, .commaspace
	call	string$split_str
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
calign
.outerloop:
	cmp	qword [r13+_list_size_ofs], 0
	je	.outerdone
	mov	rdi, r13
	call	list$pop_front
	mov	r14, rax
	; split this one by '; '
	mov	rdi, rax
	mov	rsi, .semicolonspace
	call	string$split_str
	mov	rdi, r14
	mov	r14, rax
	call	heap$free
	; so now, prepare a stackframe to hold our parsed goodies
	sub	rsp, cookie_size
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, cookie_size
	call	memset32

	; the first one must be the cookie-pair
	cmp	qword [r14+_list_size_ofs], 0
	je	.innerdone
	mov	rdi, r14
	call	list$pop_front
	mov	r15, rax
	mov	rdi, rax
	mov	esi, '='
	call	string$indexof_charcode
	cmp	rax, -1
	je	.cookie_nameval_error
	; hangon to our offset
	mov	[rsp+cookie_secure_ofs], rax
	mov	rdi, r15
	xor	esi, esi
	mov	rdx, rax
	call	string$substr
	mov	[rsp+cookie_name_ofs], rax
	mov	rdi, r15
	mov	rsi, [rsp+cookie_secure_ofs]
	mov	rdx, -1
	add	rsi, 1
	call	string$substr
	mov	[rsp+cookie_value_ofs], rax
	mov	qword [rsp+cookie_secure_ofs], 0
	mov	rdi, r15
	call	heap$free
calign
.innerloop:
	cmp	qword [r14+_list_size_ofs], 0
	je	.innerdone
	mov	rdi, r14
	call	list$pop_front
	mov	r15, rax
	mov	rdi, rax
	call	string$to_lower
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; check for expires, path, max-age, domain, secure, httponly
	mov	rdi, r15
	mov	rsi, .htexpiryequal
	call	string$starts_with
	test	eax, eax
	jnz	.inner_expires
	mov	rdi, r15
	mov	rsi, .lcpathequal
	call	string$starts_with
	test	eax, eax
	jnz	.inner_path
	mov	rdi, r15
	mov	rsi, .lcmaxageequal
	call	string$starts_with
	test	eax, eax
	jnz	.inner_maxage
	mov	rdi, r15
	mov	rsi, .lcdomainequal
	call	string$starts_with
	test	eax, eax
	jnz	.inner_domain
	mov	rdi, r15
	mov	rsi, .lcsecure
	call	string$equals
	test	eax, eax
	jnz	.inner_secure
	mov	rdi, r15
	mov	rsi, .lchttponly
	call	string$equals
	test	eax, eax
	jnz	.inner_httponly
	; otherwise, we don't recognize it, ignore and keep going
	mov	rdi, r15
	call	heap$free
	jmp	.innerloop
cleartext .htexpiryequal, ';;;expiry;;;='
cleartext .lcexpiresequal, 'expires='
cleartext .lcpathequal, 'path='
cleartext .lcmaxageequal, 'max-age='
cleartext .lcdomainequal, 'domain='
cleartext .lcsecure, 'secure'
cleartext .lchttponly, 'httponly'
cleartext .slash, '/'
calign
.innerdone:
	mov	rdi, r14
	call	heap$free

	; now, deal with our stackframe cookie
	; if our domain is not set, set it from the url
	cmp	qword [rsp+cookie_domain_ofs], 0
	jne	.innerdone_domainokay
	mov	rdi, [r12+url_host_ofs]
	call	string$copy
	mov	[rsp+cookie_domain_ofs], rax
calign
.innerdone_domainokay:
	; if the path is not specified, use the path from the url
	cmp	qword [rsp+cookie_path_ofs], 0
	jne	.innerdone_pathokay
	mov	rdi, [r12+url_path_ofs]
	mov	esi, .slash
	call	string$last_indexof
	; we know that url _will_ have a valid path
	mov	rdi, [r12+url_path_ofs]
	xor	esi, esi
	mov	rdx, rax
	add	rdx, 1
	call	string$substr
	mov	[rsp+cookie_path_ofs], rax
calign
.innerdone_pathokay:
	; if the path doesn't end with /, add one
	mov	rdi, [rsp+cookie_path_ofs]
	mov	rsi, [rdi]
	test	rsi, rsi
	jz	.innerdone_pathokay_slashonly
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	je	.innerdone_pathokay2
	mov	rdi, [rsp+cookie_path_ofs]
	mov	rsi, .slash
	call	string$concat
	mov	rdi, [rsp+cookie_path_ofs]
	mov	[rsp+cookie_path_ofs], rax
	call	heap$free
	jmp	.innerdone_pathokay2
calign
.innerdone_pathokay_slashonly:
	mov	rdi, .slash
	call	string$copy
	mov	rdi, [rsp+cookie_path_ofs]
	mov	[rsp+cookie_path_ofs], rax
	call	heap$free
calign
.innerdone_pathokay2:
	; if we made it to here, name and value were already set
	; figure out whether we are deleting one or not
	mov	r14, [rbx+_list_first_ofs]
	call	timestamp
	mov	rax, [rsp+cookie_expiry_ofs]
	test	rax, rax
	jz	.setcookie_locate
	movq	xmm1, rax
	ucomisd xmm1, xmm0
	jae	.setcookie_locate
	; otherwise, we are deleting one, so cruise the list at rbx and see if we find one that matches
calign
.deletecookie_locate:
	test	r14, r14
	jz	.deletecookie_done
	mov	r15, [r14+_list_valueofs]
	mov	rdi, [r15+cookie_name_ofs]
	mov	rsi, [rsp+cookie_name_ofs]
	call	string$equals
	test	eax, eax
	jz	.deletecookie_next
	mov	rdi, [r15+cookie_domain_ofs]
	mov	rsi, [rsp+cookie_domain_ofs]
	call	string$equals
	test	eax, eax
	jz	.deletecookie_next
	mov	rdi, [r15+cookie_path_ofs]
	mov	rsi, [rsp+cookie_path_ofs]
	call	string$equals
	test	eax, eax
	jz	.deletecookie_next
	; otherwise, we found it, delete it
	mov	rdi, [r15+cookie_domain_ofs]
	call	heap$free
	mov	rdi, [r15+cookie_path_ofs]
	call	heap$free
	mov	rdi, [r15+cookie_name_ofs]
	call	heap$free
	mov	rdi, [r15+cookie_value_ofs]
	call	heap$free
	mov	rdi, r15
	call	heap$free
	mov	rdi, rbx
	mov	rsi, r14
	call	list$remove
	jmp	.deletecookie_done
calign
.deletecookie_next:
	mov	r14, [r14+_list_nextofs]
	jmp	.deletecookie_locate
calign
.deletecookie_done:
	mov	rdi, [rsp+cookie_domain_ofs]
	call	heap$free
	mov	rdi, [rsp+cookie_path_ofs]
	call	heap$free
	mov	rdi, [rsp+cookie_name_ofs]
	call	heap$free
	mov	rdi, [rsp+cookie_value_ofs]
	call	heap$free

	add	rsp, cookie_size
	jmp	.outerloop
calign
.setcookie_locate:
	test	r14, r14
	jz	.setcookie_notfound
	mov	r15, [r14+_list_valueofs]
	mov	rdi, [r15+cookie_name_ofs]
	mov	rsi, [rsp+cookie_name_ofs]
	call	string$equals
	test	eax, eax
	jz	.setcookie_next
	mov	rdi, [r15+cookie_domain_ofs]
	mov	rsi, [rsp+cookie_domain_ofs]
	call	string$equals
	test	eax, eax
	jz	.setcookie_next
	mov	rdi, [r15+cookie_path_ofs]
	mov	rsi, [rsp+cookie_path_ofs]
	call	string$equals
	test	eax, eax
	jz	.setcookie_next
	; otherwise, we found it, delete its old values, set to our new ones and be done
	mov	rdi, [r15+cookie_domain_ofs]
	call	heap$free
	mov	rdi, [r15+cookie_path_ofs]
	call	heap$free
	mov	rdi, [r15+cookie_name_ofs]
	call	heap$free
	mov	rdi, [r15+cookie_value_ofs]
	call	heap$free
	; memcpy straight over the top of it
	mov	rdi, r15
	mov	rsi, rsp
	mov	edx, cookie_size
	call	memcpy

	add	rsp, cookie_size
	jmp	.outerloop
calign
.setcookie_next:
	mov	r14, [r14+_list_nextofs]
	jmp	.setcookie_locate
calign
.setcookie_notfound:
	mov	edi, cookie_size
	call	heap$alloc
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, rsp
	mov	edx, cookie_size
	call	memcpy
	mov	rdi, rbx
	mov	rsi, r15
	call	list$push_back

	add	rsp, cookie_size
	jmp	.outerloop
calign
.inner_expires:
	mov	rdi, r15
	mov	esi, 13
	mov	rdx, -1
	call	string$substr
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	mov	rdi, r15
	call	string$to_double
	movq	rax, xmm0
	mov	rdi, r15
	mov	[rsp+cookie_expiry_ofs], rax
	call	heap$free
	jmp	.innerloop
calign
.inner_path:
	cmp	qword [rsp+cookie_path_ofs], 0
	jne	.inner_duplicatevalue
	mov	rdi, r15
	mov	esi, 5
	mov	rdx, -1
	call	string$substr
	mov	rdi, r15
	mov	[rsp+cookie_path_ofs], rax
	call	heap$free
	jmp	.innerloop
calign
.inner_maxage:
	mov	rdi, r15
	mov	esi, 8
	mov	rdx, -1
	call	string$substr
	mov	rdi, r15
	mov	rdi, rax
	call	heap$free
	call	timestamp
	mov	rdi, r15
	call	string$to_unsigned	; we know this doesn't blast xmm0
	cvtsi2sd xmm1, rax
	addsd	xmm0, xmm1
	movq	[rsp+cookie_expiry_ofs], xmm0
	mov	rdi, r15
	call	heap$free
	jmp	.innerloop
calign
.inner_domain:
	cmp	qword [rsp+cookie_domain_ofs], 0
	jne	.inner_duplicatevalue
	mov	rdi, r15
	mov	esi, 7
	mov	rdx, -1
	call	string$substr
	mov	rdi, r15
	mov	[rsp+cookie_domain_ofs], rax
	call	heap$free
	jmp	.innerloop
calign
.inner_secure:
	mov	dword [rsp+cookie_secure_ofs], 1
	mov	rdi, r15
	call	heap$free
	jmp	.innerloop
calign
.inner_httponly:
	mov	dword [rsp+cookie_httponly_ofs], 1
	mov	rdi, r15
	call	heap$free
	jmp	.innerloop

calign
.outerdone:
	mov	rdi, r13
	call	heap$free
	
	pop	r15 r14 r13 r12 rbx
	epilog

falign
.maybefree:
	test	rdi, rdi
	jz	.maybefree_nah
	call	heap$free
	ret
calign
.maybefree_nah:
	ret
calign
.inner_duplicatevalue:
	mov	rdi, [rsp+cookie_domain_ofs]
	call	.maybefree
	mov	rdi, [rsp+cookie_path_ofs]
	call	.maybefree
	mov	rdi, [rsp+cookie_name_ofs]
	call	.maybefree
	mov	rdi, [rsp+cookie_value_ofs]
	call	.maybefree
	; fallthrough to cookie_nameval_error
calign
.cookie_nameval_error:
	add	rsp, cookie_size
	mov	rdi, r15
	call	heap$free
	mov	rdi, r14
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r14
	call	heap$free
	mov	rdi, r13
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r13
	call	heap$free
	pop	r15 r14 r13 r12 rbx
	epilog
cleartext .expiresequal, 'Expires='
cleartext .commaspace, ', '
cleartext .semicolonspace, '; '

calign
.bad_expires:
	mov	rdi, r14
	call	heap$free
	mov	rdi, r13
	call	heap$free
	; fallthrough
calign
.nothingtodo:
	pop	r15 r14 r13 r12 rbx
	epilog

end if


if used cookiejar$get | defined include_everything
	; three arguments: rdi == cookiejar object, rsi == url of request, rdx == mimelike request object
	; if we have cookies to go for the url, we call mimelike$setheader on rdx with Cookie: accordingly
	; see atop, this is the bare minumum "git 'er done" goods, haha
falign
cookiejar$get:
	prolog	cookiejar$get
	push	rbx r12 r13 r14 r15
	mov	rbx, [rdi+_list_first_ofs]
	mov	r12, rsi
	mov	r13, rdx
	call	timestamp
	movq	r15, xmm0	; save the time
	mov	edi, 1		; insert order
	call	stringmap$new	; our "in progress" list, mapped by cookie name, holds the cookies themselves
	push	r15
	mov	r15, rax
calign
.each:
	test	rbx, rbx
	jz	.done
	mov	r14, [rbx+_list_valueofs]
	mov	rdi, [r14+cookie_domain_ofs]
	xor	esi, esi
	call	string$charat
	mov	rdx, string$equals
	mov	rcx, string$ends_with
	mov	rdi, [r12+url_host_ofs]
	mov	rsi, [r14+cookie_domain_ofs]
	cmp	eax, '.'
	cmove	rdx, rcx
	call	rdx
	test	eax, eax
	jz	.next
	mov	rdi, [r12+url_path_ofs]
	mov	rsi, [r14+cookie_path_ofs]
	call	string$starts_with
	test	eax, eax
	jz	.next
	cmp	qword [r14+cookie_expiry_ofs], 0
	je	.each_notimecheck
	movq	xmm0, [r14+cookie_expiry_ofs]
	movq	xmm1, [rsp]
	ucomisd	xmm0, xmm1
	jb	.next
calign
.each_notimecheck:
	cmp	dword [r14+cookie_secure_ofs], 0
	je	.each_nosecurecheck
	; see if the url's scheme is https or not
	mov	rdi, [r12+url_protocol_ofs]
	mov	rsi, .https
	call	string$equals
	test	eax, eax
	jz	.next
calign
.each_nosecurecheck:
	; so now we get to add it
	; first check, see if this cookie name is already in our map
	mov	rdi, r15
	mov	rsi, [r14+cookie_name_ofs]
	call	stringmap$find
	test	rax, rax
	jz	.each_add
	; otherwise, we have one by this name already, so
	; he with the longest path wins
	mov	rcx, [rdx+_avlofs_value]	; the cookie itself that we already added
	mov	rdi, [r14+cookie_path_ofs]
	mov	rsi, [rcx+cookie_path_ofs]
	mov	rax, [rdi]
	cmp	rax, [rsi]
	jb	.next
	; otherwise, this one's path length is longer, replace the node entry
	mov	[rdx+_avlofs_value], r14
	mov	rbx, [rbx+_list_nextofs]
	jmp	.each
calign
.each_add:
	mov	rdi, r15
	mov	rsi, [r14+cookie_name_ofs]
	mov	rdx, r14
	call	stringmap$insert_unique
	mov	rbx, [rbx+_list_nextofs]
	jmp	.each
cleartext .https, 'https'
calign
.next:
	mov	rbx, [rbx+_list_nextofs]
	jmp	.each
calign
.done:
	add	rsp, 8
	; make sure our map is not empty:
	cmp	qword [r15+_avlofs_parent], 0	; the map's root node
	je	.nocookies
	; using our stringmap, actually build the cookie header
	call	buffer$new
	mov	r14, rax
	mov	rdi, r15
	mov	rsi, .addcookie
	mov	rdx, rax
	call	stringmap$foreach_arg
	; so now our buffer is populated, turn that back into a string
	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, [r14+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	mov	rdi, r13
	mov	rsi, mimelike$cookie
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
	; get rid of our buffer
	mov	rdi, r14
	call	buffer$destroy
	; free our stringmap, no key destruction is necessary, since they are copies from the cookie list
	mov	rdi, r15
	xor	esi, esi
	call	stringmap$clear
calign
.nocookies:
	mov	rdi, r15
	call	heap$free
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.addcookie:
	; rdi == name, rsi == cookie object, rdx == buffer to add to
	push	r12 r13 r14
	mov	r12, rdi
	mov	r13, [rsi+cookie_value_ofs]
	mov	r14, rdx
	; first, if the buffer is non-empty, we have to add our separator
	cmp	qword [rdx+buffer_length_ofs], 0
	je	.noseparator
	mov	rdi, rdx
	mov	rsi, .separator
	call	buffer$append_rawstring
calign
.noseparator:
	mov	rdi, r14
	mov	rsi, r12
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, .equal
	call	buffer$append_rawstring
	mov	rdi, r14
	mov	rsi, r13
	call	buffer$append_rawstring
	pop	r14 r13 r12
	ret
cleartext .separator, '; '
cleartext .equal, '='

end if
