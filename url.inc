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
	; url.inc: URL string parsing and relative handling, as well as url encode/decode
	;
	; This is not intended to be the end-all-be-all in RFC compliance, but does the job
	; that I require nicely. Specifically:
	; During parse, we don't percent decode the protocol (aka scheme), host, port, or the
	; authinfo (aka username and password)
	; The same applies to when we turn it back into a string form with url$tostring.
	; Also, we don't deal with path parameters (any such will just end up as part of the
	; path/file).
	;
	; we populate all strings such that they don't need to be tested for null
	; (though of course they may be empty)
	;

url_protocol_ofs = 0		; string
url_host_ofs = 8		; string
url_port_ofs = 16		; int
url_file_ofs = 24		; string
url_query_ofs = 32		; string
url_authority_ofs = 40		; string
url_path_ofs = 48		; string
url_authinfo_ofs = 56		; string
url_ref_ofs = 64		; string
url_user_ofs = 72		; not used in here, but we initialize it to zero on alloc

url_size = 80


if used url$init | defined include_everything

globals
{
	url$schemeportmap	dq	0
}

	; no arguments, called from ht$init to initialize our default ports for the schemes we are about
	; this list is intentionally short based on my own personal use cases.
falign
url$init:
	prolog	url$init
	xor	edi, edi
	call	stringmap$new
	mov	[url$schemeportmap], rax

macro url_addone port*, [val*] {
common
	local .NAME, .POST
	jmp	.POST
	cleartext .NAME, val
	.POST:
	mov	rdi, [url$schemeportmap]
	mov	rsi, .NAME
	mov	edx, port
	call	stringmap$insert_unique
}

	url_addone 80, 'http'
	url_addone 443, 'https'
	url_addone 21, 'ftp'
	url_addone 3690, 'svn'
	url_addone 9418, 'git'
	url_addone 6667, 'irc'
	url_addone 143, 'imap'
	url_addone 119, 'nntp'

	epilog

end if


if used url$new | defined include_everything
	; two arguments: rdi == optional base context url, rsi == string
	; returns new url object in rax, or null on error (e.g. no context and /some.path passed in == error, bad port)
falign
url$new:
	prolog	url$new
	mov	eax, [rsi]
if string_bits = 32
	mov	ecx, [rsi+8]
else
	movzx	ecx, word [rsi+8]
end if
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	xor	r13d, r13d
	push	r14 r15
	sub	rsp, 128
	mov	r14d, eax
	test	eax, eax
	jz	.initial_nullret
	sub	eax, 1
if string_bits = 32
	mov	edx, [rsi+rax*4+8]
else
	movzx	edx, word [rsi+rax*2+8]
end if
	cmp	ecx, 32
	jbe	.chopspaces
	cmp	edx, 32
	jbe	.chopspaces
calign
.checkurlstart:
	mov	rdi, r12
	mov	rsi, .urlcolon
	mov	edx, r13d
	call	string$indexof_ofs
	lea	edx, [r13d+4]
	cmp	rax, r13
	cmove	r13d, edx
	cmp	r13d, r14d
	jae	.initial_nullret
	call	string$new
	mov	[rsp+url_protocol_ofs], rax
if string_bits = 32
	cmp	dword [r12+r13*4+8], '#'
else
	cmp	word [r12+r13*2+8], '#'
end if
	je	.checkprotocol
	mov	r15d, r13d
calign
.protoloop:
	cmp	r15d, r14d
	jae	.checkprotocol
if string_bits = 32
	mov	eax, [r12+r15*4+8]
else
	movzx	eax, word [r12+r15*2+8]
end if
	cmp	eax, '/'
	je	.checkprotocol
	cmp	eax, ':'
	je	.protoloop_found
	add	r15d, 1
	jmp	.protoloop
cleartext .urlcolon, 'url:'
calign
.chopspaces:
.trailing_ws:
	test	r14d, r14d
	jz	.initial_nullret
	mov	rdi, r12
	mov	esi, r14d
	sub	esi, 1
	call	string$charat
	cmp	eax, 32
	ja	.leading_ws
	sub	r14d, 1
	jnz	.trailing_ws
	jz	.initial_nullret
calign
.leading_ws:
	cmp	r13d, r14d
	jae	.initial_nullret
	mov	rdi, r12
	mov	esi, r13d
	call	string$charat
	cmp	eax, 32
	ja	.checkurlstart
	add	r13d, 1
	jmp	.leading_ws
calign
.protoloop_found:
	mov	rdi, r12
	mov	esi, r13d
	mov	edx, r15d
	call	string$substring
	push	rax
	mov	rdi, rax
	call	string$to_lower_inplace
	mov	rdi, [rsp+8]
	call	heap$free
	pop	rdi
	mov	[rsp+url_protocol_ofs], rdi
	mov	r13d, r15d
	add	r13d, 1
calign
.checkprotocol:
	; so at this point we have a possible protocol string sitting in [rsp]
	test	rbx, rbx
	jz	.verifyprotocol
	mov	rdi, [rsp+url_protocol_ofs]
	mov	rsi, [rbx+url_protocol_ofs]
	call	string$equals
	mov	rsi, [rsp+url_protocol_ofs]
	xor	ecx, ecx
	mov	edx, 1
	cmp	qword [rsi], 0
	cmove	ecx, edx
	or	eax, ecx
	jz	.verifyprotocol
	mov	rdi, [rbx+url_path_ofs]
	mov	esi, '/'
	call	string$indexof_charcode
	test	rax, rax
	jnz	.checkemptyproto
	; otherwise, set it to empty
	call	string$new
	mov	rdi, [rsp]
	mov	[rsp+url_protocol_ofs], rax
	call	heap$free
calign
.checkemptyproto:
	mov	rdi, [rsp+url_protocol_ofs]
	cmp	qword [rdi], 0
	jne	.verifyprotocol
	mov	rdi, [rbx+url_protocol_ofs]
	cmp	qword [rdi], 0
	je	.protocol_nullret
	; otherwise, set us up for full relative action
	call	string$copy
	mov	rdi, [rsp+url_protocol_ofs]
	mov	[rsp+url_protocol_ofs], rax
	call	heap$free
	; set host, port, file, authority, path, authinfo
	mov	rdi, [rbx+url_host_ofs]
	call	string$copy
	mov	[rsp+url_host_ofs], rax
	mov	rdi, [rbx+url_port_ofs]
	mov	[rsp+url_port_ofs], rdi
	mov	rdi, [rbx+url_file_ofs]
	call	string$copy
	mov	[rsp+url_file_ofs], rax
	mov	rdi, [rbx+url_authority_ofs]
	call	string$copy
	mov	[rsp+url_authority_ofs], rax
	mov	rdi, [rbx+url_path_ofs]
	call	string$copy
	mov	[rsp+url_path_ofs], rax
	mov	rdi, [rbx+url_authinfo_ofs]
	call	string$copy
	mov	[rsp+url_authinfo_ofs], rax
	; now, query and ref still need set
	mov	rdi, r12
	mov	esi, '#'
	mov	edx, r13d
	call	string$indexof_charcode_ofs
	cmp	rax, -1
	jne	.relative_withref
	call	string$new
	mov	[rsp+url_ref_ofs], rax

	cmp	r13d, r14d
	je	.relative_withquery
	call	string$new
	mov	[rsp+url_query_ofs], rax
	jmp	.parseurl
calign
.relative_withquery:
	mov	rdi, [rbx+url_query_ofs]
	call	string$copy
	mov	[rsp+url_query_ofs], rax
	mov	rdi, [rsp+url_ref_ofs]
	cmp	qword [rdi], 0
	jne	.parseurl
	mov	rdi, [rsp+url_ref_ofs]
	call	heap$free
	mov	rdi, [rbx+url_ref_ofs]
	call	string$copy
	mov	[rsp+url_ref_ofs], rax
	jmp	.parseurl
calign
.relative_withref:
	mov	rdi, r12
	mov	esi, eax
	mov	edx, r14d
	mov	r14d, eax
	add	esi, 1
	call	string$substring
	mov	[rsp+url_ref_ofs], rax
	cmp	r13d, r14d
	jne	.relative_emptyquery
	mov	rdi, [rbx+url_query_ofs]
	call	string$copy
	mov	[rsp+url_query_ofs], rax
	mov	rdi, [rsp+url_ref_ofs]
	cmp	qword [rdi], 0
	jne	.parseurl
	mov	rdi, [rsp+url_ref_ofs]
	call	heap$free
	mov	rdi, [rbx+url_ref_ofs]
	call	string$copy
	mov	[rsp+url_ref_ofs], rax
	jmp	.parseurl
calign
.relative_emptyquery:
	call	string$new
	mov	[rsp+url_query_ofs], rax
	jmp	.parseurl
calign
.verifyprotocol:
	mov	rdi, [rsp+url_protocol_ofs]
	cmp	qword [rdi], 0
	je	.protocol_nullret
	mov	rdi, r12
	mov	esi, '#'
	mov	edx, r13d
	call	string$indexof_charcode_ofs
	cmp	rax, -1
	je	.empty_ref
	mov	rdi, r12
	mov	esi, eax
	mov	edx, r14d
	mov	r14d, eax
	add	esi, 1
	call	string$substring
	mov	[rsp+url_ref_ofs], rax
	jmp	.notrelative_empties
calign
.empty_ref:
	call	string$new
	mov	[rsp+url_ref_ofs], rax
	; fallthrough to notrelative_empties
calign
.notrelative_empties:
	; so at this point, we have protocol and ref setup, we need to set the rest
	; to all empty strings
	call	string$new
	mov	[rsp+url_host_ofs], rax
	mov	qword [rsp+url_port_ofs], 0
	call	string$new
	mov	[rsp+url_file_ofs], rax
	call	string$new
	mov	[rsp+url_query_ofs], rax
	call	string$new
	mov	[rsp+url_authority_ofs], rax
	call	string$new
	mov	[rsp+url_path_ofs], rax
	call	string$new
	mov	[rsp+url_authinfo_ofs], rax
	; fallthrough to parseurl
calign
.parseurl:
	; let the meaty bits begin
	mov	qword [rsp+72], 0
	cmp	r13d, r14d
	ja	.parseurl_checkstart
	mov	rdi, r12
	mov	esi, '?'
	mov	edx, r13d
	call	string$indexof_charcode_ofs
	xor	ecx, ecx
	mov	edx, 1
	cmp	rax, r13
	cmove	ecx, edx
	mov	[rsp+76], ecx		; are we only sitting on a query?
	cmp	rax, -1
	je	.parseurl_checkstart
	cmp	eax, r14d
	jae	.parseurl_checkstart
	mov	rdi, r12
	mov	esi, eax
	mov	edx, r14d
	cmp	r14d, eax
	cmova	r14d, eax
	add	esi, 1
	call	string$substring
	mov	rdi, [rsp+url_query_ofs]
	mov	[rsp+url_query_ofs], rax
	call	heap$free
calign
.parseurl_checkstart:
	mov	eax, r14d
	sub	eax, r13d
	cmp	eax, 4
	jb	.parseurl_checkpath
if string_bits = 32
	cmp	dword [r12+r13*4+8], '/'
else
	cmp	word [r12+r13*2+8], '/'
end if
	jne	.parseurl_checkpath
if string_bits = 32
	cmp	dword [r12+r13*4+12], '/'
else
	cmp	word [r12+r13*2+10], '/'
end if
	jne	.parseurl_checkpath
if string_bits = 32
	cmp	dword [r12+r13*4+16], '/'
else
	cmp	word [r12+r13*2+12], '/'
end if
	je	.parseurl_checkpath
	; otherwise, we got // as start, do our authority
	add	r13d, 2
	mov	rdi, r12
	mov	esi, '/'
	mov	edx, r13d
	call	string$indexof_charcode_ofs
	mov	r15, rax
	cmp	rax, 0
	jge	.parseurl_setauthority
	mov	rdi, r12
	mov	esi, '?'
	mov	edx, r13d
	call	string$indexof_charcode_ofs
	mov	r15, rax
	cmp	rax, 0
	jge	.parseurl_setauthority
	mov	r15d, r14d
calign
.parseurl_setauthority:
	mov	rdi, r12
	mov	esi, r13d
	mov	edx, r15d
	call	string$substring
	mov	rdi, [rsp+url_host_ofs]
	mov	[rsp+url_host_ofs], rax
	call	heap$free
	mov	rdi, [rsp+url_authority_ofs]
	call	heap$free
	mov	rdi, [rsp+url_host_ofs]
	call	string$copy
	mov	[rsp+url_authority_ofs], rax
	mov	rdi, rax
	mov	esi, '@'
	call	string$indexof_charcode
	cmp	rax, 0
	jl	.parseurl_setauthinfo_empty
	mov	[rsp+80], rax
	mov	rdi, [rsp+url_authority_ofs]
	mov	esi, 0
	mov	edx, eax
	call	string$substr
	mov	rdi, [rsp+url_authinfo_ofs]
	mov	[rsp+url_authinfo_ofs], rax
	call	heap$free
	mov	rdi, [rsp+url_authority_ofs]
	mov	esi, [rsp+80]
	mov	rdx, -1
	add	esi, 1
	call	string$substr
	mov	rdi, [rsp+url_host_ofs]
	mov	[rsp+url_host_ofs], rax
	call	heap$free
	jmp	.parseurl_checkhost
calign
.parseurl_setauthinfo_empty:
	call	string$new
	mov	rdi, [rsp+url_authinfo_ofs]
	mov	[rsp+url_authinfo_ofs], rax
	call	heap$free
calign
.parseurl_checkhost:
	mov	rdi, [rsp+url_host_ofs]
	cmp	qword [rdi], 0
	je	.parseurl_checkport
	; hosts need to be lowercase, authority doesn't
	call	string$to_lower_inplace
	mov	rdi, [rsp+url_host_ofs]
	; if we were going to check for IPv6 hosts, here would be the place if host.charat(0) == '['
	mov	esi, ':'
	call	string$indexof_charcode
	cmp	rax, 0
	jl	.parseurl_checkport
	mov	[rsp+80], rax
	mov	rdi, [rsp+url_host_ofs]
	mov	esi, eax
	add	esi, 1
	cmp	qword [rdi], rsi
	jbe	.parseurl_chophost
	mov	rdx, -1
	call	string$substr
	mov	[rsp+88], rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp+88]
	mov	[rsp+url_port_ofs], rax
	call	heap$free
calign
.parseurl_chophost:
	mov	rdi, [rsp+url_host_ofs]
	xor	esi, esi
	mov	rdx, [rsp+80]
	call	string$substr
	mov	rdi, [rsp+url_host_ofs]
	mov	[rsp+url_host_ofs], rax
	call	heap$free
calign
.parseurl_checkport:
	mov	eax, [rsp+url_port_ofs]
	cmp	eax, 0
	je	.parseurl_defaultport
	jl	.badport_nullret
	cmp	eax, 65536
	jae	.badport_nullret
calign
.parseurl_checkport_okay:
	mov	r13d, r15d
	mov	rdi, [rsp+url_authority_ofs]
	cmp	qword [rdi], 0
	je	.parseurl_checkpath
	call	string$new
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
calign
.parseurl_checkpath:
	cmp	r13d, r14d
	jae	.parseurl_checkpath_qonly
if string_bits = 32
	cmp	dword [r12+r13*4+8], '/'
else
	cmp	word [r12+r13*2+8], '/'
end if
	jne	.parseurl_relativepath
	mov	rdi, r12
	mov	esi, r13d
	mov	edx, r14d
	call	string$substring
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	jmp	.parseurl_construct
calign
.parseurl_defaultport:
	mov	rdi, [url$schemeportmap]
	mov	rsi, [rsp+url_protocol_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.badport_nullret
	mov	[rsp+url_port_ofs], edx
	jmp	.parseurl_checkport_okay
cleartext .emptystr, ''
cleartext .slash, '/'
cleartext .slashslash, '//'
cleartext .dotslash, './'
cleartext .slashdot, '/.'
cleartext .slashdotslash, '/./'
cleartext .slashdotdot, '/..'
cleartext .slashdotdotslash, '/../'
cleartext .percentdoublezero, '%00'
calign
.parseurl_relativepath:
	mov	rdi, [rsp+url_path_ofs]
	cmp	qword [rdi], 0
	je	.parseurl_setpath
	; otherwise, dealing with a relative path
	mov	rsi, .slash
	call	string$last_indexof
	cmp	rax, 0
	jl	.parseurl_setpath
	; otherwise, substr that + the new
	mov	rdi, [rsp+url_path_ofs]
	xor	esi, esi
	mov	rdx, rax
	add	rdx, 1
	call	string$substr
	mov	[rsp+80], rax
	mov	rdi, r12
	mov	esi, r13d
	mov	edx, r14d
	call	string$substring
	mov	[rsp+88], rax
	mov	rdi, [rsp+80]
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	mov	rdi, [rsp+80]
	call	heap$free
	mov	rdi, [rsp+88]
	call	heap$free
	; so now, proceed to construct where we'll fixup any nasties in the path
	jmp	.parseurl_construct
calign
.parseurl_checkpath_qonly:
	cmp	dword [rsp+76], 1
	jne	.parseurl_construct
	mov	rdi, [rsp+url_path_ofs]
	cmp	qword [rdi], 0
	je	.parseurl_construct
	mov	esi, '/'
	call	string$indexof_charcode
	xor	ecx, ecx
	cmp	rax, 0
	cmovl	rax, rcx
	mov	rdi, [rsp+url_path_ofs]
	xor	esi, esi
	mov	rdx, rax
	call	string$substr
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slash
	call	string$concat
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	jmp	.parseurl_construct
calign
.parseurl_setpath:
	mov	rdi, [rsp+url_authority_ofs]
	cmp	qword [rdi], 0
	je	.parseurl_setpath_nosep
	mov	rdi, r12
	mov	esi, r13d
	mov	edx, r14d
	call	string$substring
	mov	[rsp+88], rax
	mov	rdi, .slash
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	mov	rdi, [rsp+88]
	call	heap$free
	jmp	.parseurl_construct
calign
.parseurl_setpath_nosep:
	mov	rdi, r12
	mov	esi, r13d
	mov	edx, r14d
	call	string$substring
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
calign
.parseurl_construct:
	; so before we construct our final return url object:
	; first, we have to urldecode the relevant bits of our url

	; if the path contains %00, die
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .percentdoublezero
	call	string$indexof
	cmp	rax, 0
	jge	.badport_nullret

	mov	rdi, [rsp+url_path_ofs]
	call	url$decode
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free

if defined url_querystring_decode
	mov	rdi, [rsp+url_query_ofs]
	call	url$decode
	mov	rdi, [rsp+url_query_ofs]
	mov	[rsp+url_query_ofs], rax
	call	heap$free
end if

	mov	rdi, [rsp+url_ref_ofs]
	call	url$decode
	mov	rdi, [rsp+url_ref_ofs]
	mov	[rsp+url_ref_ofs], rax
	call	heap$free
	; make sure the path is sane (removing ../../.. etc)

	; string$replace is nasty, so only do this if it actually contains a violator
	xor	r15d, r15d
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashslash
	call	string$indexof
	cmp	rax, 0
	jl	.parseurl_sanepath
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashslash
	mov	rdx, .slash
	call	string$replace
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
calign
.parseurl_sanepath:
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdotslash
	call	string$indexof
	cmp	rax, 0
	jl	.parseurl_sanepath2
	mov	[rsp+80], rax
	mov	rdi, [rsp+url_path_ofs]
	xor	esi, esi
	mov	rdx, rax
	call	string$substr
	mov	[rsp+88], rax
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, [rsp+80]
	mov	rdx, -1
	add	rsi, 2
	call	string$substr
	mov	[rsp+80], rax
	mov	rdi, [rsp+88]
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	mov	rdi, [rsp+88]
	call	heap$free
	mov	rdi, [rsp+80]
	call	heap$free
	jmp	.parseurl_sanepath
calign
.parseurl_sanepath2:
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdotdotslash
	mov	edx, r15d
	call	string$indexof_ofs
	mov	r15, rax
	cmp	rax, 0
	jl	.parseurl_sanepath3
	test	rax, rax
	jz	.parseurl_sanepath2_skip
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slash
	mov	edx, r15d
	sub	edx, 1
	call	string$last_indexof_ofs
	mov	r14, rax
	cmp	rax, 0
	jl	.parseurl_sanepath2_skip
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdotdotslash
	mov	edx, r14d
	call	string$indexof_ofs
	test	rax, rax
	jz	.parseurl_sanepath2_skip
	mov	rdi, [rsp+url_path_ofs]
	xor	esi, esi
	mov	edx, r14d
	call	string$substr
	mov	[rsp+80], rax
	mov	rdi, [rsp+url_path_ofs]
	mov	esi, r15d
	mov	rdx, -1
	add	esi, 3
	call	string$substr
	mov	[rsp+88], rax
	mov	rdi, [rsp+80]
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	mov	rdi, [rsp+80]
	call	heap$free
	mov	rdi, [rsp+88]
	call	heap$free
	xor	r15d, r15d
	jmp	.parseurl_sanepath2
calign
.parseurl_sanepath2_skip:
	add	r15d, 3
	jmp	.parseurl_sanepath2
calign
.parseurl_sanepath3:
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdotdot
	call	string$ends_with
	test	rax, rax
	jz	.parseurl_sanepath4
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdotdot
	call	string$indexof
	mov	r15, rax
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slash
	mov	edx, r15d
	sub	edx, 1
	call	string$last_indexof_ofs
	cmp	rax, 0
	jl	.parseurl_sanepath4
	mov	rdi, [rsp+url_path_ofs]
	xor	esi, esi
	mov	rdx, rax
	add	rdx, 1
	call	string$substr
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	jmp	.parseurl_sanepath3
calign
.parseurl_sanepath4:
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .dotslash
	call	string$starts_with
	test	rax, rax
	jz	.parseurl_sanepath5
	mov	rdi, [rsp+url_path_ofs]
	mov	esi, 2
	mov	rdx, -1
	cmp	qword [rdi], 2
	jbe	.parseurl_sanepath5
	call	string$substr
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
calign
.parseurl_sanepath5:
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdot
	call	string$ends_with
	test	rax, rax
	jz	.parseurl_sanepath6
	mov	rdi, [rsp+url_path_ofs]
	xor	esi, esi
	mov	rdx, [rdi]
	sub	rdx, 1
	call	string$substr
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
calign
.parseurl_sanepath6:
	; any starting backpath references can simply be deleted
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slashdotdot
	call	string$starts_with
	test	rax, rax
	jz	.parseurl_setfile
	mov	rdi, [rsp+url_path_ofs]
	mov	esi, 3
	mov	rdx, -1
	call	string$substr
	mov	rdi, [rsp+url_path_ofs]
	mov	[rsp+url_path_ofs], rax
	call	heap$free
	jmp	.parseurl_sanepath6
calign
.parseurl_setfile:
	; and last but not least, we have to set our file to whatever the last bit of the path is
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, .slash
	call	string$last_indexof
	cmp	rax, 0
	jl	.parseurl_final
	mov	rdi, [rsp+url_path_ofs]
	mov	rsi, rax
	mov	rdx, -1
	add	rsi, 1
	call	string$substr
	mov	rdi, [rsp+url_file_ofs]
	mov	[rsp+url_file_ofs], rax
	call	heap$free
calign
.parseurl_final:
	mov	edi, url_size
	call	heap$alloc_clear
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, rsp
	mov	edx, url_size - 8	; don't write over the user offset (leave it at zero)
	call	memcpy
	mov	rax, rbx
	add	rsp, 128
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.badport_nullret:
	; free all of our strings
	mov	rdi, [rsp+url_host_ofs]
	call	heap$free
	mov	rdi, [rsp+url_file_ofs]
	call	heap$free
	mov	rdi, [rsp+url_query_ofs]
	call	heap$free
	mov	rdi, [rsp+url_authority_ofs]
	call	heap$free
	mov	rdi, [rsp+url_path_ofs]
	call	heap$free
	mov	rdi, [rsp+url_authinfo_ofs]
	call	heap$free
	mov	rdi, [rsp+url_ref_ofs]
	call	heap$free
	; fall through
calign
.protocol_nullret:
	mov	rdi, [rsp+url_protocol_ofs]
	call	heap$free
	; fallthrough
calign
.initial_nullret:
	xor	eax, eax
	add	rsp, 128
	pop	r15 r14 r13 r12 rbx
	epilog

end if


if used url$destroy | defined include_everything
	; single argument in rdi: the url object to destroy
falign
url$destroy:
	prolog	url$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+url_protocol_ofs]
	call	heap$free
	mov	rdi, [rbx+url_host_ofs]
	call	heap$free
	mov	rdi, [rbx+url_file_ofs]
	call	heap$free
	mov	rdi, [rbx+url_query_ofs]
	call	heap$free
	mov	rdi, [rbx+url_authority_ofs]
	call	heap$free
	mov	rdi, [rbx+url_path_ofs]
	call	heap$free
	mov	rdi, [rbx+url_authinfo_ofs]
	call	heap$free
	mov	rdi, [rbx+url_ref_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog

end if

if used url$equals | defined include_everything
	; two arguments: rdi == url object, rsi == other url object to compare
falign
url$equals:
	prolog	url$equals
	push	r12 r13
	mov	r12, rdi
	mov	r13, rsi
	mov	eax, [r12+url_port_ofs]
	cmp	eax, [r13+url_port_ofs]
	jne	.nope
	mov	rdi, [r12+url_protocol_ofs]
	mov	rsi, [r13+url_protocol_ofs]
	call	string$equals
	test	eax, eax
	jz	.nope
	mov	rdi, [r12+url_host_ofs]
	mov	rsi, [r13+url_host_ofs]
	call	string$equals
	test	eax, eax
	jz	.nope
	mov	rdi, [r12+url_file_ofs]
	mov	rsi, [r13+url_file_ofs]
	call	string$equals
	test	eax, eax
	jz	.nope
	mov	rdi, [r12+url_query_ofs]
	mov	rsi, [r13+url_query_ofs]
	call	string$equals
	test	eax, eax
	jz	.nope
	mov	rdi, [r12+url_path_ofs]
	mov	rsi, [r13+url_path_ofs]
	call	string$equals
	test	eax, eax
	jz	.nope
	mov	eax, 1
	pop	r13 r12
	epilog
calign
.nope:
	xor	eax, eax
	pop	r13 r12
	epilog

end if

if used url$debug | defined include_everything
	; single argument in rdi: a url object
	; just dumps everything out to stdout
falign
url$debug:
	prolog	url$debug
	push	rbx
	mov	rbx, rdi
	mov	rdi, .pref
	call	string$to_stdoutln
	mov	rdi, .s1
	call	string$to_stdout
	mov	rdi, [rbx+url_protocol_ofs]
	call	string$to_stdoutln
	mov	rdi, .s2
	call	string$to_stdout
	mov	rdi, [rbx+url_host_ofs]
	call	string$to_stdoutln
	mov	rdi, .s3
	call	string$to_stdout
	mov	rdi, [rbx+url_port_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, .s4
	call	string$to_stdout
	mov	rdi, [rbx+url_file_ofs]
	call	string$to_stdoutln
	mov	rdi, .s5
	call	string$to_stdout
	mov	rdi, [rbx+url_query_ofs]
	call	string$to_stdoutln
	mov	rdi, .s6
	call	string$to_stdout
	mov	rdi, [rbx+url_authority_ofs]
	call	string$to_stdoutln
	mov	rdi, .s7
	call	string$to_stdout
	mov	rdi, [rbx+url_path_ofs]
	call	string$to_stdoutln
	mov	rdi, .s8
	call	string$to_stdout
	mov	rdi, [rbx+url_authinfo_ofs]
	call	string$to_stdoutln
	mov	rdi, .s9
	call	string$to_stdout
	mov	rdi, [rbx+url_ref_ofs]
	call	string$to_stdoutln
	pop	rbx
	epilog
cleartext .pref, '::URL debug::'
cleartext .s1, ' protocol: '
cleartext .s2, '     host: '
cleartext .s3, '     port: '
cleartext .s4, '     file: '
cleartext .s5, '    query: '
cleartext .s6, 'authority: '
cleartext .s7, '     path: '
cleartext .s8, ' authinfo: '
cleartext .s9, '      ref: '

end if



if used url$setprotocol | defined include_everything
	; two arguments: rdi == url object, rsi == string protocol (we copy it)
falign
url$setprotocol:
	prolog	url$setprotocol
	push	rdi rsi
	mov	rdi, [rdi+url_protocol_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_protocol_ofs], rax
	epilog

end if

if used url$sethost | defined include_everything
	; two arguments: rdi == url object, rsi == string host (we copy it)
falign
url$sethost:
	prolog	url$sethost
	push	rdi rsi
	mov	rdi, [rdi+url_host_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_host_ofs], rax
	epilog

end if

if used url$setport | defined include_everything
	; two arguments: rdi == url object, esi == port (integer)
falign
url$setport:
	prolog	url$setport
	mov	[rdi+url_port_ofs], esi
	epilog

end if

if used url$setfile | defined include_everything
	; two arguments: rdi == url object, rsi == string file (we copy it)
falign
url$setfile:
	prolog	url$setfile
	push	rdi rsi
	mov	rdi, [rdi+url_file_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_file_ofs], rax
	epilog

end if

if used url$setquery | defined include_everything
	; two arguments: rdi == url object, rsi == string query (we copy it)
falign
url$setquery:
	prolog	url$setquery
	push	rdi rsi
	mov	rdi, [rdi+url_query_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_query_ofs], rax
	epilog

end if

if used url$setauthority | defined include_everything
	; two arguments: rdi == url object, rsi == string authority (we copy it)
falign
url$setauthority:
	prolog	url$setauthority
	push	rdi rsi
	mov	rdi, [rdi+url_authority_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_authority_ofs], rax
	epilog

end if

if used url$setpath | defined include_everything
	; two arguments: rdi == url object, rsi == string path (we copy it)
falign
url$setpath:
	prolog	url$setpath
	push	rdi rsi
	mov	rdi, [rdi+url_path_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_path_ofs], rax
	epilog

end if

if used url$setauthinfo | defined include_everything
	; two arguments: rdi == url object, rsi == string authinfo (we copy it)
falign
url$setauthinfo:
	prolog	url$setauthinfo
	push	rdi rsi
	mov	rdi, [rdi+url_authinfo_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_authinfo_ofs], rax
	epilog

end if

if used url$setref | defined include_everything
	; two arguments: rdi == url object, rsi == string ref (we copy it)
falign
url$setref:
	prolog	url$setref
	push	rdi rsi
	mov	rdi, [rdi+url_ref_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+url_ref_ofs], rax
	epilog

end if

if used url$topreface | defined include_everything
	; single argument in rdi: url object
	; returns external representation of the url object suitable for an HTTP request preface
falign
url$topreface:
	prolog	url$topreface
	push	rbx r12
	mov	rbx, rdi
	call	buffer$new
	mov	r12, rax
	mov	rsi, [rbx+url_path_ofs]
	cmp	qword [rsi], 0
	je	.slashonly
	; url encode the path:
	mov	rdi, rsi
	mov	esi, 1		; path encoding
	call	url$encode
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
	jmp	.checkquery
cleartext .slash, '/'
calign
.slashonly:
	mov	rdi, r12
	mov	rsi, .slash
	call	buffer$append_rawstring
calign
.checkquery:
	mov	rsi, [rbx+url_query_ofs]
	cmp	qword [rsi], 0
	je	.checkref
	mov	rdi, r12
	mov	rsi, .questionmark
	call	buffer$append_rawstring

if defined url_querystring_decode
	; url encode the query
	mov	rdi, [rbx+url_query_ofs]
	xor	esi, esi
	call	url$encode
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
else
	mov	rdi, r12
	mov	rsi, [rbx+url_query_ofs]
	call	buffer$append_rawstring

end if
calign
.checkref:
	mov	rsi, [rbx+url_ref_ofs]
	cmp	qword [rsi], 0
	je	.alldone
	mov	rdi, r12
	mov	rsi, .hash
	call	buffer$append_rawstring
	; url encode the ref (aka fragment)
	mov	rdi, [rbx+url_ref_ofs]
	xor	esi, esi
	call	url$encode
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
calign
.alldone:
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r12+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	mov	rdi, r12
	mov	r12, rax
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog
cleartext .questionmark, '?'
cleartext .hash, '#'

end if

if used url$tostring | defined include_everything
	; single argument in rdi: url object
	; returns external representation of the url object in a new string (note: does not add authinfo)
falign
url$tostring:
	prolog	url$tostring
	push	rbx r12
	mov	rbx, rdi
	call	buffer$new
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, [rbx+url_protocol_ofs]
	call	buffer$append_rawstring
	mov	rsi, [rbx+url_authority_ofs]
	cmp	qword [rsi], 0
	je	.skipauthority
	mov	rdi, r12
	mov	rsi, .colonslashslash
	call	buffer$append_rawstring
	mov	rdi, r12
	mov	rsi, [rbx+url_authority_ofs]
	call	buffer$append_rawstring
	jmp	.checkpath
calign
.skipauthority:
	mov	rdi, r12
	mov	rsi, .colon
	call	buffer$append_rawstring
calign
.checkpath:
	mov	rsi, [rbx+url_path_ofs]
	cmp	qword [rsi], 0
	je	.checkquery
	; url encode the path:
	mov	rdi, rsi
	mov	esi, 1		; path encoding
	call	url$encode
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
calign
.checkquery:
	mov	rsi, [rbx+url_query_ofs]
	cmp	qword [rsi], 0
	je	.checkref
	mov	rdi, r12
	mov	rsi, .questionmark
	call	buffer$append_rawstring

if defined url_querystring_decode
	; url encode the query
	mov	rdi, [rbx+url_query_ofs]
	xor	esi, esi
	call	url$encode
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
else
	mov	rdi, r12
	mov	rsi, [rbx+url_query_ofs]
	call	buffer$append_rawstring
end if
calign
.checkref:
	mov	rsi, [rbx+url_ref_ofs]
	cmp	qword [rsi], 0
	je	.alldone
	mov	rdi, r12
	mov	rsi, .hash
	call	buffer$append_rawstring
	; url encode the ref (aka fragment)
	mov	rdi, [rbx+url_ref_ofs]
	xor	esi, esi
	call	url$encode
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
calign
.alldone:
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r12+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	mov	rdi, r12
	mov	r12, rax
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog
cleartext .colonslashslash, '://'
cleartext .colon, ':'
cleartext .questionmark, '?'
cleartext .hash, '#'

end if



if used url$encode | defined include_everything
	; two arguments: rdi == string containing [possibly] invalid url characters, bool in esi as to whether it is a path or not
	; returns a new string in rax with the offenders converted to %XX format
	; NOTE: this is not terribly efficient, because it converts to UTF8 and back
falign
url$encode:
	prolog	url$encode
	cmp	qword [rdi], 0
	je	.emptystring
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r15d, esi
	call	string$utf8_length
	mov	r12, rax
	add	rax, 0xf
	and	rax, not 0xf
	sub	rsp, rax
	mov	rdi, rbx
	mov	rsi, rsp
	call	string$to_utf8
	call	buffer$new
	mov	r13, rax
	; determine the buffer length we need
	mov	r14, r12
	mov	rdi, rsp
	mov	rcx, r12
calign
.lengthscan:
	mov	rdx, r14
	movzx	eax, byte [rdi]
	add	rdx, 2
	cmp	byte [rax*4+.enctable], '%'
	cmove	r14, rdx
	add	rdi, 1
	sub	rcx, 1
	jnz	.lengthscan
	mov	rdi, r13
	mov	rsi, r14
	call	buffer$reserve
	mov	rdi, [r13+buffer_itself_ofs]
	mov	rsi, rsp
	mov	rcx, r12
calign
.doit:
	movzx	eax, byte [rsi]
	add	rsi, 1
	mov	r8d, [rax*4+.pathenctable]
	mov	eax, [rax*4+.enctable]
	test	r15d, r15d
	cmovnz	eax, r8d
	cmp	al, '%'
	je	.doit_perc
	mov	byte [rdi], al
	add	rdi, 1
	sub	rcx, 1
	jnz	.doit
	jmp	.done
calign
.doit_perc:
	mov	[rdi], eax
	add	rdi, 3
	sub	rcx, 1
	jnz	.doit
calign
.done:
	mov	rsi, rdi
	mov	rdi, [r13+buffer_itself_ofs]
	sub	rsi, rdi
	call	string$from_utf8
	mov	r14, rax
	mov	rdi, r13
	call	buffer$destroy
	mov	rax, r12
	add	rax, 0xf
	and	rax, not 0xf
	add	rsp, rax
	mov	rax, r14
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.emptystring:
	call	string$new
	epilog
dalign
.enctable:
        db      '%00',0,'%01',0,'%02',0,'%03',0,'%04',0,'%05',0,'%06',0,'%07',0
        db      '%08',0,'%09',0,'%0A',0,'%0B',0,'%0C',0,'%0D',0,'%0E',0,'%0F',0
        db      '%10',0,'%11',0,'%12',0,'%13',0,'%14',0,'%15',0,'%16',0,'%17',0
        db      '%18',0,'%19',0,'%1A',0,'%1B',0,'%1C',0,'%1D',0,'%1E',0,'%1F',0
        db      '+',0,0,0,'!',0,0,0,'%22',0,'%23',0,'$',0,0,0,'%25',0,'%26',0,0x27,0,0,0
        db      '(',0,0,0,')',0,0,0,'*',0,0,0,'%2B',0,',',0,0,0,'-',0,0,0,'.',0,0,0,'%2F',0
        db      '0',0,0,0,'1',0,0,0,'2',0,0,0,'3',0,0,0,'4',0,0,0,'5',0,0,0,'6',0,0,0,'7',0,0,0
        db      '8',0,0,0,'9',0,0,0,'%3A',0,'%3B',0,'%3C',0,'%3D',0,'%3E',0,'%3F',0
        db      '%40',0,'A',0,0,0,'B',0,0,0,'C',0,0,0,'D',0,0,0,'E',0,0,0,'F',0,0,0,'G',0,0,0
        db      'H',0,0,0,'I',0,0,0,'J',0,0,0,'K',0,0,0,'L',0,0,0,'M',0,0,0,'N',0,0,0,'O',0,0,0
        db      'P',0,0,0,'Q',0,0,0,'R',0,0,0,'S',0,0,0,'T',0,0,0,'U',0,0,0,'V',0,0,0,'W',0,0,0
        db      'X',0,0,0,'Y',0,0,0,'Z',0,0,0,'%5B',0,'%5C',0,'%5D',0,'%5E',0,'_',0,0,0
        db      '%60',0,'a',0,0,0,'b',0,0,0,'c',0,0,0,'d',0,0,0,'e',0,0,0,'f',0,0,0,'g',0,0,0
        db      'h',0,0,0,'i',0,0,0,'j',0,0,0,'k',0,0,0,'l',0,0,0,'m',0,0,0,'n',0,0,0,'o',0,0,0
        db      'p',0,0,0,'q',0,0,0,'r',0,0,0,'s',0,0,0,'t',0,0,0,'u',0,0,0,'v',0,0,0,'w',0,0,0
        db      'x',0,0,0,'y',0,0,0,'z',0,0,0,'%7B',0,'%7C',0,'%7D',0,'%7E',0,'%7F',0
        db      '%80',0,'%81',0,'%82',0,'%83',0,'%84',0,'%85',0,'%86',0,'%87',0
        db      '%88',0,'%89',0,'%8A',0,'%8B',0,'%8C',0,'%8D',0,'%8E',0,'%8F',0
        db      '%90',0,'%91',0,'%92',0,'%93',0,'%94',0,'%95',0,'%96',0,'%97',0
        db      '%98',0,'%99',0,'%9A',0,'%9B',0,'%9C',0,'%9D',0,'%9E',0,'%9F',0
        db      '%A0',0,'%A1',0,'%A2',0,'%A3',0,'%A4',0,'%A5',0,'%A6',0,'%A7',0
        db      '%A8',0,'%A9',0,'%AA',0,'%AB',0,'%AC',0,'%AD',0,'%AE',0,'%AF',0
        db      '%B0',0,'%B1',0,'%B2',0,'%B3',0,'%B4',0,'%B5',0,'%B6',0,'%B7',0
        db      '%B8',0,'%B9',0,'%BA',0,'%BB',0,'%BC',0,'%BD',0,'%BE',0,'%BF',0
        db      '%C0',0,'%C1',0,'%C2',0,'%C3',0,'%C4',0,'%C5',0,'%C6',0,'%C7',0
        db      '%C8',0,'%C9',0,'%CA',0,'%CB',0,'%CC',0,'%CD',0,'%CE',0,'%CF',0
        db      '%D0',0,'%D1',0,'%D2',0,'%D3',0,'%D4',0,'%D5',0,'%D6',0,'%D7',0
        db      '%D8',0,'%D9',0,'%DA',0,'%DB',0,'%DC',0,'%DD',0,'%DE',0,'%DF',0
        db      '%E0',0,'%E1',0,'%E2',0,'%E3',0,'%E4',0,'%E5',0,'%E6',0,'%E7',0
        db      '%E8',0,'%E9',0,'%EA',0,'%EB',0,'%EC',0,'%ED',0,'%EE',0,'%EF',0
        db      '%F0',0,'%F1',0,'%F2',0,'%F3',0,'%F4',0,'%F5',0,'%F6',0,'%F7',0
        db      '%F8',0,'%F9',0,'%FA',0,'%FB',0,'%FC',0,'%FD',0,'%FE',0,'%FF'
dalign
.pathenctable:
        db      '%00',0,'%01',0,'%02',0,'%03',0,'%04',0,'%05',0,'%06',0,'%07',0
        db      '%08',0,'%09',0,'%0A',0,'%0B',0,'%0C',0,'%0D',0,'%0E',0,'%0F',0
        db      '%10',0,'%11',0,'%12',0,'%13',0,'%14',0,'%15',0,'%16',0,'%17',0
        db      '%18',0,'%19',0,'%1A',0,'%1B',0,'%1C',0,'%1D',0,'%1E',0,'%1F',0
        db      '%20',0,'!',0,0,0,'%22',0,'%23',0,'$',0,0,0,'%25',0,'%26',0,0x27,0,0,0
        db      '(',0,0,0,')',0,0,0,'*',0,0,0,'+',0,0,0,',',0,0,0,'-',0,0,0,'.',0,0,0,'/',0,0,0
        db      '0',0,0,0,'1',0,0,0,'2',0,0,0,'3',0,0,0,'4',0,0,0,'5',0,0,0,'6',0,0,0,'7',0,0,0
        db      '8',0,0,0,'9',0,0,0,'%3A',0,'%3B',0,'%3C',0,'=',0,0,0,'%3E',0,'%3F',0
        db      '%40',0,'A',0,0,0,'B',0,0,0,'C',0,0,0,'D',0,0,0,'E',0,0,0,'F',0,0,0,'G',0,0,0
        db      'H',0,0,0,'I',0,0,0,'J',0,0,0,'K',0,0,0,'L',0,0,0,'M',0,0,0,'N',0,0,0,'O',0,0,0
        db      'P',0,0,0,'Q',0,0,0,'R',0,0,0,'S',0,0,0,'T',0,0,0,'U',0,0,0,'V',0,0,0,'W',0,0,0
        db      'X',0,0,0,'Y',0,0,0,'Z',0,0,0,'%5B',0,'%5C',0,'%5D',0,'%5E',0,'_',0,0,0
        db      '%60',0,'a',0,0,0,'b',0,0,0,'c',0,0,0,'d',0,0,0,'e',0,0,0,'f',0,0,0,'g',0,0,0
        db      'h',0,0,0,'i',0,0,0,'j',0,0,0,'k',0,0,0,'l',0,0,0,'m',0,0,0,'n',0,0,0,'o',0,0,0
        db      'p',0,0,0,'q',0,0,0,'r',0,0,0,'s',0,0,0,'t',0,0,0,'u',0,0,0,'v',0,0,0,'w',0,0,0
        db      'x',0,0,0,'y',0,0,0,'z',0,0,0,'%7B',0,'%7C',0,'%7D',0,'%7E',0,'%7F',0
        db      '%80',0,'%81',0,'%82',0,'%83',0,'%84',0,'%85',0,'%86',0,'%87',0
        db      '%88',0,'%89',0,'%8A',0,'%8B',0,'%8C',0,'%8D',0,'%8E',0,'%8F',0
        db      '%90',0,'%91',0,'%92',0,'%93',0,'%94',0,'%95',0,'%96',0,'%97',0
        db      '%98',0,'%99',0,'%9A',0,'%9B',0,'%9C',0,'%9D',0,'%9E',0,'%9F',0
        db      '%A0',0,'%A1',0,'%A2',0,'%A3',0,'%A4',0,'%A5',0,'%A6',0,'%A7',0
        db      '%A8',0,'%A9',0,'%AA',0,'%AB',0,'%AC',0,'%AD',0,'%AE',0,'%AF',0
        db      '%B0',0,'%B1',0,'%B2',0,'%B3',0,'%B4',0,'%B5',0,'%B6',0,'%B7',0
        db      '%B8',0,'%B9',0,'%BA',0,'%BB',0,'%BC',0,'%BD',0,'%BE',0,'%BF',0
        db      '%C0',0,'%C1',0,'%C2',0,'%C3',0,'%C4',0,'%C5',0,'%C6',0,'%C7',0
        db      '%C8',0,'%C9',0,'%CA',0,'%CB',0,'%CC',0,'%CD',0,'%CE',0,'%CF',0
        db      '%D0',0,'%D1',0,'%D2',0,'%D3',0,'%D4',0,'%D5',0,'%D6',0,'%D7',0
        db      '%D8',0,'%D9',0,'%DA',0,'%DB',0,'%DC',0,'%DD',0,'%DE',0,'%DF',0
        db      '%E0',0,'%E1',0,'%E2',0,'%E3',0,'%E4',0,'%E5',0,'%E6',0,'%E7',0
        db      '%E8',0,'%E9',0,'%EA',0,'%EB',0,'%EC',0,'%ED',0,'%EE',0,'%EF',0
        db      '%F0',0,'%F1',0,'%F2',0,'%F3',0,'%F4',0,'%F5',0,'%F6',0,'%F7',0
        db      '%F8',0,'%F9',0,'%FA',0,'%FB',0,'%FC',0,'%FD',0,'%FE',0,'%FF'


end if



if used url$decode | defined include_everything
	; single argument in rdi: string containing %XX url characters
	; returns a new string in rax of the decoded goods
falign
url$decode:
	prolog	url$decode
	cmp	qword [rdi], 0
	je	.emptystring
	push	rbx r12 r13
	sub	rsp, 32
	mov	qword [rsp], 4
if string_bits = 32
	mov	dword [rsp+8], '0'
	mov	dword [rsp+12], 'x'
else
	mov	word [rsp+8], '0'
	mov	word [rsp+10], 'x'
end if
	mov	rbx, rdi
	mov	r12, [rdi]
	call	buffer$new
	mov	r13, rax
	mov	rdi, rax
	mov	rsi, r12
	shl	rsi, 2
	call	buffer$reserve
	mov	rdi, [r13+buffer_itself_ofs]
	lea	rsi, [rbx+8]
calign
.doit:
if string_bits = 32
	mov	eax, [rsi]
	add	rsi, 4
else
	movzx	eax, word [rsi]
	add	rsi, 2
end if
	cmp	eax, '%'
	je	.doit_perc
	cmp	eax, '+'
	je	.doit_plus
	mov	[rdi], eax
if string_bits = 32
	add	rdi, 4
else
	add	rdi, 2
end if
	sub	r12, 1
	jnz	.doit
	jmp	.done
calign
.doit_perc:
	sub	r12, 1
	jz	.done
	cmp	r12, 2
	jb	.done
if string_bits = 32
	mov	eax, [rsi]
	mov	ecx, [rsi+4]
	add	rsi, 8
	mov	[rsp+16], eax
	mov	[rsp+20], ecx
	push	rdi rsi
	lea	rdi, [rsp+16]
	call	string$to_unsigned
	pop	rsi rdi
	mov	[rdi], eax
	add	rdi, 4
else
	movzx	eax, word [rsi]
	movzx	ecx, word [rsi+2]
	add	rsi, 4
	mov	[rsp+12], ax
	mov	[rsp+14], cx
	push	rdi rsi
	lea	rdi, [rsp+16]
	call	string$to_unsigned
	pop	rsi rdi
	mov	[rdi], eax
	add	rdi, 2
end if
	sub	r12, 2
	jnz	.doit
	jmp	.done
calign
.doit_plus:
	mov	dword [rdi], ' '
if string_bits = 32
	add	rdi, 4
else
	add	rdi, 2
end if
	sub	r12, 1
	jnz	.doit
calign
.done:
	mov	rsi, rdi
	mov	rdi, [r13+buffer_itself_ofs]
	sub	rsi, rdi
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	mov	r12, rax
	mov	rdi, r13
	call	buffer$destroy
	add	rsp, 32
	mov	rax, r12
	pop	r13 r12 rbx
	epilog
calign
.emptystring:
	call	string$new
	epilog

end if
