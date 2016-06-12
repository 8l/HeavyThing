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
	; mimelike.inc: mime and similar parsing/construction object
	;
	; Burning Purpose:
	; Deal with MIME and HTTP parsing and construction in a nice, relatively
	; pain-free way, haha. I have been carrying around in my stash of goodies
	; variations on the code contained herein for, hmmm, nearly two decades...
	; This is far and away the best implementation I have done, and I have had
	; good success with this being the "MIME multitool" (read: parse a slice of
	; ham and not crash or do anything weird, YMMV, HA!) All of the ones I have
	; come across in the wild don't work quite like mine. Whether that is a
	; matter of personal preference or not I'll leave to you to consider.
	;
	; I have made every effort to allow both email formatted "real" MIME, in
	; addition to parsing/dealing with HTTP/1.1 in a seamless sorta way. It can
	; be (and is) used for both purposes :-)
	; 


if used mimelike$new | used mimelike$new_parse | defined include_everything

mimelike_headers_ofs = 0		; a unique stringmap of keys/values, insert order
mimelike_preface_ofs = 8		; a heap allocated string of the preface, or null if none (think: GET / HTTP/1.0)
mimelike_body_ofs = 16			; a buffer$new for keeping our "body" (of this part)
mimelike_xmitbody_ofs = 24		; a buffer$new of the compiled header+body
mimelike_boundary_ofs = 32		; a heap allocated string of the boundary, or null if none (multipart goods)
mimelike_parts_ofs = 40			; a list$new of mimelike objects (if multipart)
mimelike_parent_ofs = 48		; pointer to our parent (if any)
mimelike_hdrlen_ofs = 56		; set inside new_parse, the length in bytes of the actual header including separator, set during compose as well
mimelike_parselen_ofs = 64		; also set in new_parse, the total length we parsed from the input
mimelike_bodyextend_ofs = 72		; a "fake" partial buffer object contained herein to make things easier
mimelike_bodyextlen_ofs = 80		; length of above
mimelike_bodyext_ofs = 88		; pointer, if nonzero, this and bodyextlen are used _instead_ of body during compose
mimelike_user_ofs = 96			; not used in here, but cleared on mimelike$new/new_parse

mimelike_size = 104

end if


if used mimelike$new | defined include_everything
	; no arguments, returns a new but ready to use mimelike object in rax
falign
mimelike$new:
	prolog	mimelike$new
	mov	edi, 1
	call	stringmap$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	list$new
	push	rax
	mov	edi, mimelike_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	[rax+mimelike_headers_ofs], rdi
	mov	[rax+mimelike_body_ofs], rsi
	mov	[rax+mimelike_xmitbody_ofs], rdx
	mov	[rax+mimelike_parts_ofs], rcx
	epilog

end if

if used mimelike$destroy | defined include_everything
	; single argument in rdi: the mimelike object to destroy
falign
mimelike$destroy:
	prolog	mimelike$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+mimelike_parts_ofs]
	mov	rsi, mimelike$destroy
	call	list$clear
	mov	rdi, [rbx+mimelike_parts_ofs]
	call	heap$free
	mov	rdi, [rbx+mimelike_boundary_ofs]
	call	.maybefree
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+mimelike_body_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+mimelike_preface_ofs]
	call	.maybefree
	mov	rdi, [rbx+mimelike_headers_ofs]
	mov	rsi, .hdrfree
	call	stringmap$clear
	mov	rdi, [rbx+mimelike_headers_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
falign
.hdrfree:
	; called with rdi == key, rsi == value, we need to free both
	push	rsi
	call	heap$free
	pop	rdi
	call	heap$free
	ret
falign
.maybefree:
	test	rdi, rdi
	jz	.nofree
	call	heap$free
	ret
.nofree:
	ret

end if


if used mimelike$setpreface | defined include_everything
	; two arguments: rdi == mimelike object, rsi == string to set preface to (we'll copy it)
falign
mimelike$setpreface:
	prolog	mimelike$setpreface
	push	rbx
	push	qword [rdi+mimelike_preface_ofs]
	mov	rbx, rdi
	mov	rdi, rsi
	call	string$copy
	mov	[rbx+mimelike_preface_ofs], rax
	pop	rdi
	test	rdi, rdi
	jz	.nofree
	call	heap$free
calign
.nofree:
	pop	rbx
	epilog

end if

if used mimelike$setpreface_nocopy | defined include_everything
	; two arguments: rdi == mimelike object, rsi == string to set preface to (we assume ownership of it, no copy)
falign
mimelike$setpreface_nocopy:
	prolog	mimelike$setpreface_nocopy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+mimelike_preface_ofs]
	mov	[rbx+mimelike_preface_ofs], rsi
	test	rdi, rdi
	jz	.nofree
	call	heap$free
calign
.nofree:
	pop	rbx
	epilog

end if

if used mimelike$setheader | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string name, rdx == string value (we copy both)
falign
mimelike$setheader:
	prolog	mimelike$setheader
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdi, rdx
	call	string$copy
	mov	r13, rax
	mov	rdi, r12
	call	string$copy
	mov	r12, rax
	mov	rdi, [rbx+mimelike_headers_ofs]
	mov	rsi, rax
	mov	rdx, r13
	call	stringmap$insert_unique
	test	eax, eax
	jz	.alreadythere
	pop	r13 r12 rbx
	epilog
calign
.alreadythere:
	; we know the node that matched is sitting in r8 as a leftover from stringmap$insert_unique
	mov	rdi, [r8+_avlofs_value]
	mov	[r8+_avlofs_value], r13
	call	heap$free
	mov	rdi, r12
	call	heap$free
	pop	r13 r12 rbx
	epilog

end if

if used mimelike$addheader | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string name, rdx == string value (we copy both)
	; NOTE: this is the same as above, only we do NOT perform a find/replace, so only use this if you know it isn't already here
falign
mimelike$addheader:
	prolog	mimelike$addheader
	push	qword [rdi+mimelike_headers_ofs]
	push	rsi
	mov	rdi, rdx
	call	string$copy
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	string$copy
	pop	rdx
	mov	rsi, rax
	pop	rdi
	call	stringmap$insert_unique
	epilog

end if

if used mimelike$setheader_novaluecopy | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string name, rdx == string value (name gets copied, value does not)
falign
mimelike$setheader_novaluecopy:
	prolog	mimelike$setheader_novaluecopy
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r13, rdx
	mov	rdi, rsi
	call	string$copy
	mov	r12, rax
	mov	rdi, [rbx+mimelike_headers_ofs]
	mov	rsi, rax
	mov	rdx, r13
	call	stringmap$insert_unique
	test	eax, eax
	jz	.alreadythere
	pop	r13 r12 rbx
	epilog
calign
.alreadythere:
	; we know the node that matched is sitting in r8 as a leftover from stringmap$insert_unique
	mov	rdi, [r8+_avlofs_value]
	mov	[r8+_avlofs_value], r13
	call	heap$free
	mov	rdi, r12
	call	heap$free
	pop	r13 r12 rbx
	epilog
	
end if

if used mimelike$addheader_novaluecopy | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string name, rdx == string value (name gets copied, value does not)
	; NOTE: this is the same as above, only we do NOT perform a find/replace, so only use this if you know it isn't already here
falign
mimelike$addheader_novaluecopy:
	prolog	mimelike$addheader_novaluecopy
	push	qword [rdi+mimelike_headers_ofs]
	push	rdx
	mov	rdi, rsi
	call	string$copy
	pop	rdx rdi
	mov	rsi, rax
	call	stringmap$insert_unique
	epilog

end if


if used mimelike$setheader_nocopy | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string name, rdx == string value (assumes ownership of both)
falign
mimelike$setheader_nocopy:
	prolog	mimelike$setheader_nocopy
	push	rbx r12
	mov	rdi, [rdi+mimelike_headers_ofs]
	mov	rbx, rsi
	mov	r12, rdx
	call	stringmap$insert_unique
	test	eax, eax
	jz	.alreadythere
	pop	r12 rbx
	epilog
calign
.alreadythere:
	; we know the node that matched is sitting in r8 as a leftover from stringmap$insert_unique
	mov	rdi, [r8+_avlofs_value]
	mov	[r8+_avlofs_value], r12
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	r12 rbx
	epilog

end if

if used mimelike$addheader_nocopy | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string name, rdx == string value (assumes ownership of both)
	; NOTE: this is the same as above, only we do NOT perform a find/replace, so only use this if you know it isn't already here
falign
mimelike$addheader_nocopy:
	prolog	mimelike$addheader_nocopy
	mov	rdi, [rdi+mimelike_headers_ofs]
	call	stringmap$insert_unique
	epilog

end if


if used mimelike$getheader | defined include_everything
	; two arguments: rdi == mimelike object, rsi == string name
	; returns value string ptr in rax, or null if no such header
falign
mimelike$getheader:
	prolog	mimelike$getheader
	mov	rdi, [rdi+mimelike_headers_ofs]
	call	stringmap$find
	test	rax, rax
	jz	.bailout
	mov	rax, [rax+_avlofs_value]
	epilog
calign
.bailout:
	epilog

end if




if used mimelike$removeheader | defined include_everything
	; two arguments: rdi == mimelike object, rsi == string name
falign
mimelike$removeheader:
	prolog	mimelike$removeheader
	mov	rdi, [rdi+mimelike_headers_ofs]
	call	stringmap$erase
	test	eax, eax
	jz	.nodeal
	; otherwise, rdx == key of the node, r8 == value
	push	rdx
	mov	rdi, r8
	call	heap$free
	pop	rdi
	call	heap$free
	epilog
calign
.nodeal:
	epilog

end if



if used mimelike$setdefaultboundary | defined include_everything
	; two arguments: rdi == mimelike object, rsi == content type (or null for multipart/alternative)
falign
mimelike$setdefaultboundary:
	prolog	mimelike$setdefaultboundary
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	sub	rsp, 16
	mov	rdi, rsp
	mov	esi, 16
	call	rng$block
	mov	rdi, rsp
	mov	esi, 16
	xor	edx, edx
	call	string$from_bintobase64
	mov	[rsp], rax
	mov	rdi, .pref
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, .post
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, [rsp]
	mov	rdx, r12
	call	mimelike$setboundary
	add	rsp, 16
	pop	r12 rbx
	epilog
cleartext .pref, '=_HeavyThing-'
cleartext .post, '_='

end if

if used mimelike$setboundary | defined include_everything
	; three arguments: rdi == mimelike object, rsi == boundary string (assumes ownership of string), rdx == content type (or null for multipart/alternative)
falign
mimelike$setboundary:
	prolog	mimelike$setboundary
	mov	rcx, [rdi+mimelike_boundary_ofs]
	test	rcx, rcx
	jnz	.withfree
	mov	[rdi+mimelike_boundary_ofs], rsi
	mov	rsi, rdx
	call	mimelike$multipartcontenttype
	epilog
calign
.withfree:
	push	rdi rdx
	mov	[rdi+mimelike_boundary_ofs], rsi
	mov	rdi, rcx
	call	heap$free
	pop	rsi rdi
	call	mimelike$multipartcontenttype
	epilog
	
end if

if used mimelike$multipartcontenttype | defined include_everything
	; two arguments: rdi == mimelike object, rsi == content type (or null for multipart/alternative)
	; NOTE: boundary _must_ be set prior to calling this
falign
mimelike$multipartcontenttype:
	prolog	mimelike$multipartcontenttype
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	test	rsi, rsi
	jz	.default
	cmp	qword [rsi], 0
	je	.default
	; ideally, the Content-Type header needs to have the content type, then a semicolon, then a space, then boundary=".."
	; so, we'll be nice and see what the last non-space character of our passed string is and determine which bits to add
	mov	r13d, [rsi]
	sub	r13d, 1
calign
.lastchar:
	mov	rdi, r12
	mov	esi, r13d
	call	string$charat
	cmp	eax, ' '
	jne	.lastchar_done
	test	r13d, r13d
	jz	.lastchar_done
	sub	r13d, 1
	jmp	.lastchar
calign
.lastchar_done:
	cmp	eax, ';'
	jne	.addsemicolon
	mov	r13d, [r12]
	sub	r13d, 1
	mov	rdi, r12
	mov	esi, r13d
	call	string$charat
	cmp	eax, ' '
	jne	.addspace
	; otherwise, add it like it is
	mov	rdi, r12
	mov	rsi, .pref
calign
.doit:
	call	string$concat
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, [rbx+mimelike_boundary_ofs]
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .post
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, .ctype
	mov	rdx, r12
	call	mimelike$setheader_novaluecopy
	pop	r13 r12 rbx
	epilog
calign
.addsemicolon:
	mov	rdi, r12
	mov	rsi, .semipref
	jmp	.doit
calign
.addspace:
	mov	rdi, r12
	mov	rsi, .spacepref
	jmp	.doit
calign
.default:
	mov	rdi, .defaultpref
	mov	rsi, [rbx+mimelike_boundary_ofs]
	call	string$concat
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, .post
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, .ctype
	mov	rdx, r12
	call	mimelike$setheader_novaluecopy
	pop	r13 r12 rbx
	epilog
cleartext .semipref, '; boundary="'
cleartext .spacepref, ' boundary="'
cleartext .pref, 'boundary="'
cleartext .defaultpref, 'multipart/alternative; boundary="'
cleartext .post, '"'
cleartext .ctype, 'Content-Type'

end if


if used mimelike$shouldgzip | defined include_everything
	; single argument in rdi: mimelike object
	; checks for a content-type header, and if present, scans for "best practice" ones that we actually should gzip
	; returns bool in eax
falign
mimelike$shouldgzip:
	prolog	mimelike$shouldgzip
	push	rbx r12
	mov	rbx, rdi
	mov	rsi, mimelike$contenttype
	call	mimelike$getheader
	test	rax, rax
	jz	.nope
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, .textstr
	call	string$starts_with
	test	eax, eax
	jnz	.yep
	mov	rdi, r12
	mov	rsi, .javascript
	call	string$indexof
	cmp	rax, 0
	jge	.yep
	mov	rdi, r12
	mov	rsi, .xml
	call	string$indexof
	cmp	rax, 0
	jge	.yep
	mov	rdi, r12
	mov	rsi, .icon
	call	string$indexof
	cmp	rax, 0
	jge	.yep
	mov	rdi, r12
	mov	rsi, .json
	call	string$indexof
	cmp	rax, 0
	jge	.yep
	mov	rdi, r12
	mov	rsi, .rtf
	call	string$indexof
	cmp	rax, 0
	jge	.yep
	mov	rdi, r12
	mov	rsi, .svg
	call	string$starts_with
	test	eax, eax
	jnz	.yep
	; otherwise, nope
	xor	eax, eax
	pop	r12 rbx
	epilog
cleartext .textstr, 'text/'
cleartext .javascript, 'javascript'
cleartext .xml, 'xml'
cleartext .icon, 'x-icon'
cleartext .rtf, '/rtf'
cleartext .json, 'json'
cleartext .svg, 'image/svg+xml'
calign
.yep:
	mov	eax, 1
	pop	r12 rbx
	epilog
calign
.nope:
	xor	eax, eax
	pop	r12 rbx
	epilog

end if


if used mimelike$static_etag | defined include_everything
	; three arguments: rdi == mimelike object, rsi == string filename, rdx == some integer (usually mtime)
	; NOTE: we truncate a SHA224 by one byte, so that our base64 results don't end up padded with two equal signs
falign
mimelike$static_etag:
	prolog	mimelike$static_etag
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	sub	rsp, sha224_state_size
	mov	rdi, rsp
	call	sha224$init
	mov	rdi, rsp
	push	r13
	mov	rsi, rsp
	mov	edx, 8
	call	sha224$update
	mov	rdx, [r12]
	add	rsp, 8
	mov	rdi, rsp
	lea	rsi, [r12+8]
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	sha224$update
	mov	rdi, rsp
	sub	rsp, 32
	mov	rsi, rsp
	xor	edx, edx		; don't attempt to free the sha224 state
	call	sha224$final
	mov	rdi, rsp
	mov	esi, 27			; TRUNCATED SHA224 by one byte
	xor	edx, edx
	call	string$from_bintobase64

if base64_linebreaks
	; CRLFs were added that we need to remove
	mov	r12, rax
	mov	rdi, rax
	mov	esi, 13
	call	string$indexof_charcode
	mov	rdi, r12
	xor	esi, esi
	mov	rdx, rax
	call	string$substr
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rax, r12
end if
	; that needs to be quoted
	mov	r12, rax
	mov	rdi, .quote
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .quote
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rax, r12

	mov	rdi, rbx
	mov	rsi, mimelike$etag
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
	add	rsp, 32 + sha224_state_size
	pop	r13 r12 rbx
	epilog
cleartext .quote, '"'

end if

if used mimelike$dynamic_etag | defined include_everything
	; three arguments: rdi == mimelike object, rsi == ptr to data, rdx == length of same
	; NOTE: we truncate a SHA224 by one byte, so that our base64 results don't end up padded with two equal signs
falign
mimelike$dynamic_etag:
	prolog	mimelike$dynamic_etag
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	sub	rsp, sha224_state_size + 32
	mov	rdi, rsp
	call	sha224$init
	mov	rdi, rsp
	mov	rsi, r12
	mov	rdx, r13
	call	sha224$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha224_state_size]
	xor	edx, edx		; don't attempt to free the sha224 state
	call	sha224$final
	lea	rdi, [rsp+sha224_state_size]
	mov	esi, 27			; TRUNCATED SHA224 by one byte
	xor	edx, edx
	call	string$from_bintobase64

if base64_linebreaks
	; CRLFs were added that we need to remove
	mov	r12, rax
	mov	rdi, rax
	mov	esi, 13
	call	string$indexof_charcode
	mov	rdi, r12
	xor	esi, esi
	mov	rdx, rax
	call	string$substr
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rax, r12
end if
	; that needs to be quoted
	mov	r12, rax
	mov	rdi, .quote
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .quote
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rax, r12

	mov	rdi, rbx
	mov	rsi, mimelike$etag
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
	add	rsp, sha224_state_size + 32
	pop	r13 r12 rbx
	epilog
cleartext .quote, '"'

end if


if used mimelike$compose | defined include_everything
	; single argument in rdi: mimelike object
	; this populates xmitbody "intelligently" based on header contents
	; e.g. we pay attention to Content-Encoding and Transfer-Encoding headers, etc
falign
mimelike$compose:
	prolog	mimelike$compose
	push	rbx
	mov	rbx, rdi
	; if there is no body length, then no encoding takes place whatsoever (and we leave headers alone)
	mov	rax, [rbx+mimelike_bodyext_ofs]
	mov	rdi, [rbx+mimelike_body_ofs]
	or	rax, [rdi+buffer_length_ofs]
	jz	.doparts
	; determine our xmitbody encoding for our body based on what headers are present:
	push	r12 r13 r14 r15
	; we'll use r13 to determine whether or not we have an intermediate buffer or not
	xor	r13d, r13d
	mov	rdi, rbx
	mov	rsi, mimelike$contenttransferencoding
	call	mimelike$getheader
	test	rax, rax
	jz	.body_checkcontentencoding
	; otherwise, lower case that one and check it for ones we recognize
	mov	rdi, rax
	call	string$to_lower
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, mimelike$base64
	call	string$indexof
	cmp	rax, 0
	jge	.body_base64
	mov	rdi, r12
	mov	rsi, mimelike$quotedprintable
	call	string$indexof
	cmp	rax, 0
	jge	.body_qp
	; so if it is anything ELSE, we just leave it well enough alone
	mov	rdi, r12
	call	heap$free
	; fallthrough to check content encoding
calign
.body_checkcontentencoding:
	; check to see whether we have a gzip content encoding
	mov	rdi, rbx
	mov	rsi, mimelike$contentencoding
	call	mimelike$getheader
	test	rax, rax
	jz	.body_checktransferencoding
	; otherwise, lower case that and check it for gzip
	mov	rdi, rax
	call	string$to_lower
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, mimelike$gzip
	call	string$indexof
	push	rax
	mov	rdi, r12
	call	heap$free
	pop	rax
	cmp	rax, 0
	jl	.body_checktransferencoding
	; otherwise, gzip was specified...
	; our library setting determines whether we actually bother with gzip or not
	lea	rdx, [rbx+mimelike_bodyextend_ofs]		; pointer to our "fake" buffer object
	mov	r14, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	r14, rdx
	test	r13, r13
	cmovnz	r14, r13
	mov	rdi, rbx
	call	mimelike$shouldgzip
	test	eax, eax
	jz	.body_removecontentencoding

	; make sure it isn't already gzipped
	mov	rax, [r14+buffer_itself_ofs]
	mov	edi, [rax]
	mov	esi, [rax]
	and	edi, 0xffffff
	shr	esi, 24
	cmp	edi, 0x88b1f
	jne	.notalreadygzipped
	test	esi, 0xe0
	jz	.body_checktransferencoding
calign
.notalreadygzipped:
	cmp	qword [r14+buffer_length_ofs], mimelike_mingzip
	jb	.body_removecontentencoding
	; otherwise, go ahead and gzip it on the fly
	sub	rsp, zlib_stream_size
	mov	rdi, rsp
	mov	esi, 2
	call	zlib$deflateInit
	mov	r15, r13
	call	buffer$new
	mov	r13, rax
	mov	rdi, rsp
	mov	esi, zlib_finish
	mov	[rsp+zlib_inbuf_ofs], r14
	mov	[rsp+zlib_outbuf_ofs], rax
	call	zlib$deflate
	mov	rdi, rsp
	call	zlib$deflateEnd
	add	rsp, zlib_stream_size
	; now, depending on whether we really had an intermediate buffer or not, destroy it
	test	r15, r15
	jz	.body_checktransferencoding
	mov	rdi, r15
	call	buffer$destroy
	jmp	.body_checktransferencoding
cleartext .headersep, 13,10
macro headers_addheadersep {
        mov     rdi, [rbx+mimelike_xmitbody_ofs]
if string_bits = 32
        mov     rax, [.headersep+8]
else
        mov     eax, [.headersep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
}
falign
.headers:
	mov	rdx, [rbx+mimelike_headers_ofs]
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	mov	esi, [rdx+_avlofs_right]	; node count in headers
	shl	esi, 10				; x 1024 bytes per header
	call	buffer$reset_reserve
	; make sure all our children have valid xmitbodies
	mov	rdi, [rbx+mimelike_parts_ofs]
	mov	rsi, mimelike$compose
	call	list$foreach
	; preface first
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	mov	rsi, [rbx+mimelike_preface_ofs]
	test	rsi, rsi
	jz	.nopreface
	call	buffer$append_rawstring_noreserve
	headers_addheadersep
calign
.nopreface:
	; header lines next
	mov	rdi, [rbx+mimelike_headers_ofs]
	mov	rsi, .headerline
	mov	rdx, [rbx+mimelike_xmitbody_ofs]
	call	stringmap$foreach_arg
	; and maybe a separator line
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nohdrsep
	headers_addheadersep
	; now convert our buffer to UTF8 in place, noting here this is a bit
	; of evil trickery: 1) we know that every heap allocated object has
	; an 8 byte preface before it for heap management
	; so we can pretend our actual header buffer is a real string by
	; placing the value where the heap management 8 bytes is, then
	; calling to_utf8, and then putting our heap management back
	mov	rdx, [rbx+mimelike_xmitbody_ofs]
	mov	rdi, [rdx+buffer_itself_ofs]
	mov	rsi, [rdx+buffer_length_ofs]
	lea	rcx, [rdi-8]
if string_bits = 32
	shr	rsi, 2
else
	shr	rsi, 1
end if
	push	qword [rcx]		; store our heap management value
	mov	[rcx], rsi		; set the number of characters
	mov	rsi, rdi
	mov	rdi, rcx
	push	rcx
	call	string$to_utf8
	; so now, our correct number of characters is in rax
	mov	rcx, [rbx+mimelike_xmitbody_ofs]
	pop	rsi rdx
	mov	rdi, [rcx+buffer_itself_ofs]
	; put back the heap management value
	mov	[rsi], rdx
	; now set our new buffer pointers
	lea	rsi, [rdi+rax]
	mov	[rcx+buffer_endptr_ofs], rsi
	mov	[rcx+buffer_length_ofs], rax
	; so our preface+headers is complete
	; set our hdrlen
	mov	[rbx+mimelike_hdrlen_ofs], rax
	ret
calign
.nohdrsep:
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	mov	rsi, [rdi+buffer_length_ofs]
	mov	[rbx+mimelike_hdrlen_ofs], rsi
	ret

calign
.body_removecontentencoding:
	; the body length didn't meet our minimum required to bother with gzip, so remove
	; the Content-Encoding header and fallthrough to check Transfer-Encoding
	mov	rdi, rbx
	mov	rsi, mimelike$contentencoding
	call	mimelike$removeheader
	; fallthrough
calign
.body_checktransferencoding:
	; check to see whether we have a chunked transfer encoding
	mov	rdi, rbx
	mov	rsi, mimelike$transferencoding
	call	mimelike$getheader
	test	rax, rax
	jz	.body_straightin
	; otherwise, lower case that and check it for chunked
	mov	rdi, rax
	call	string$to_lower
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, mimelike$chunked
	call	string$indexof
	push	rax
	mov	rdi, r12
	call	heap$free
	pop	rax
	cmp	rax, 0
	jl	.body_straightin
	; otherwise, chunked was specified
	; our library setting determines whether we actually bother with chunked encoding or not
	lea	rdx, [rbx+mimelike_bodyextend_ofs]	; pointer to our "fake" buffer object
	mov	r14, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	r14, rdx
	test	r13, r13
	cmovnz	r14, r13
if mimelike_minchunked
	cmp	qword [r14+buffer_length_ofs], mimelike_minchunked
	jb	.body_removetransferencoding
	; we have to remove the content-length if it was specified
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jz	.body_dochunks_noclength
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$removeheader
calign
.body_dochunks_noclength:
	mov	r15, r13
	call	buffer$new
	mov	r13, rax
	mov	r12, [r14+buffer_itself_ofs]
	mov	r14, [r14+buffer_length_ofs]
	sub	rsp, 16
calign
.body_dochunks:
	mov	esi, mimelike_chunksize
	mov	rdi, r14
	cmp	r14, rsi
	cmova	rdi, rsi
	mov	esi, 16
	mov	[rsp], rdi
	call	string$from_unsigned
	mov	[rsp+8], rax
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, r13
	mov	esi, 0xa0d
	call	buffer$append_word
	mov	rdi, r13
	mov	rsi, r12
	mov	rdx, [rsp]
	add	r12, rdx
	sub	r14, rdx
	call	buffer$append
	mov	rdi, r13
	mov	esi, 0xa0d
	call	buffer$append_word
	test	r14, r14
	jnz	.body_dochunks
	; terminator chunk
	mov	rdi, r13
	mov	esi, '0'
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, 0xa0d0a0d
	call	buffer$append_dword
	add	rsp, 16
	; now, depending on whether we really had an intermediate buffer or not, destroy it
	test	r15, r15
	jz	.body_straightin_skiplength
	mov	rdi, r15
	call	buffer$destroy
	jmp	.body_straightin_skiplength
calign
.body_removetransferencoding:
	; so the body length was too small to bother with chunked encoding
	; r14 is the source buffer
end if
	mov	rdi, rbx
	mov	rsi, mimelike$transferencoding
	call	mimelike$removeheader
	; now we need a length representation of our buffer as a string
	; so we can set the content-length header
	mov	rdi, [r14+buffer_length_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
	; all good, dump the body straight in
	jmp	.body_straightin
calign
.body_qp:
	; free our string first
	mov	rdi, r12
	call	heap$free
	; build an intermediate buffer in r13
	; note: the default buffer size starts out with enough room for a single line
	; so we only call buffer$reserve on our intermediate buffer when we finish a line
	call	buffer$new
	lea	rdx, [rbx+mimelike_bodyextend_ofs]		; our "fake" buffer object
	mov	rdi, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	rdi, rdx
	mov	r13, rax
	mov	r12, [rdi+buffer_itself_ofs]
	mov	r14, [rdi+buffer_length_ofs]
	mov	r15d, 75
calign
.body_qp_outer:
	; walk forward while we don't have to do =XX or = encoding
	mov	rdi, r13
	mov	rsi, r12
	xor	edx, edx
calign
.body_qp_linesearch:
	movzx	eax, byte [r12]
	add	r12, 1
	cmp	eax, 13
	je	.body_qp_linesearch_cr
	cmp	eax, 32
	jb	.body_qp_escapechar
	cmp	eax, 61
	je	.body_qp_escapechar
	cmp	eax, 126
	ja	.body_qp_escapechar
	; otherwise, we can leave it as is
	add	edx, 1
	sub	r14, 1
	jz	.body_qp_eod
	sub	r15d, 1
	jnz	.body_qp_linesearch
	; otherwise, soft linebreak
	call	buffer$append
	mov	rdi, r13
	mov	esi, '='
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, 0xa0d
	call	buffer$append_word
	mov	r15d, 75
	jmp	.body_qp_outer
calign
.body_qp_linesearch_cr:
	cmp	r14, 1
	je	.body_qp_escapechar
	cmp	byte [r12], 0x0a
	jne	.body_qp_escapechar
	add	r12, 1
	add	edx, 2
	call	buffer$append
	sub	r14, 2
	jz	.body_qp_eod_noappend
	mov	r15d, 75
	jmp	.body_qp_outer
calign
.body_qp_escapechar:
	cmp	r15d, 3
	jb	.body_qp_escapechar_softbreak
	; otherwise, there is room for =XX
	; add what we have first, if it is nonzero
	push	rax
	test	edx, edx
	jz	.body_qp_escapechar_noappend
	call	buffer$append
calign
.body_qp_escapechar_noappend:
	mov	rax, [rsp]
	mov	ecx, eax
	shr	ecx, 4
	and	eax, 0xf
	and	ecx, 0xf
	mov	eax, [eax+.body_qp_hexchars]
	mov	ecx, [ecx+.body_qp_hexchars]
	mov	byte [rsp], '='
	mov	byte [rsp+1], cl
	mov	byte [rsp+2], al
	mov	rdi, r13
	mov	rsi, rsp
	mov	edx, 3
	call	buffer$append
	add	rsp, 8
	sub	r15d, 3
	jnz	.body_qp_escapechar_next
	; otherwise, soft linebreak
	call	buffer$append
	mov	rdi, r13
	mov	esi, '='
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, 0xa0d
	call	buffer$append_word
	mov	r15d, 75
	sub	r14, 1
	jz	.body_qp_eod_noappend
	jmp	.body_qp_outer
calign
.body_qp_escapechar_next:
	sub	r14, 1
	jz	.body_qp_eod_noappend
	jmp	.body_qp_outer
	
calign
.body_qp_hexchars:
	db	'0123456789ABCDEF'
calign
.body_qp_escapechar_softbreak:
	mov	r15d, eax
	call	buffer$append
	mov	rdi, r13
	mov	esi, '='
	call	buffer$append_byte
	mov	rdi, r13
	mov	esi, 0xa0d
	call	buffer$append_word
	mov	rdi, r13
	mov	rsi, r12
	xor	edx, edx
	mov	eax, r15d
	mov	r15d, 75
	jmp	.body_qp_escapechar
calign
.body_qp_eod:
	; do we need to make sure it ended with a CRLF ? hmm
	test	rdx, rdx
	jz	.body_checkcontentencoding
	call	buffer$append
	jmp	.body_checkcontentencoding
calign
.body_qp_eod_noappend:
	jmp	.body_checkcontentencoding
calign
.body_base64:
	; free our string first
	mov	rdi, r12
	call	heap$free
	; build an intermediate buffer in r13
	call	buffer$new
	lea	rdx, [rbx+mimelike_bodyextend_ofs]	; our "fake" buffer object
	mov	rdi, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	rdi, rdx
	mov	r13, rax
	mov	rdi, [rdi+buffer_length_ofs]
	call	base64$encode_length
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$reserve
	lea	rax, [rbx+mimelike_bodyextend_ofs]	; our "fake" buffer object
	mov	rcx, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	rcx, rax
	mov	rdx, [r13+buffer_itself_ofs]
	mov	rdi, [rcx+buffer_itself_ofs]
	mov	rsi, [rcx+buffer_length_ofs]
	xor	ecx, ecx
	call	base64$encode_latin1
	mov	rdi, r13
	mov	rsi, rax
	call	buffer$append_nocopy
	jmp	.body_checkcontentencoding
calign
.body_straightin:
	; we are either adding r13, or our mimelike body
	mov	rdi, rbx
	mov	rsi, mimelike$contenttransferencoding
	call	mimelike$getheader
	test	rax, rax
	jnz	.body_straightin_skiplength
	lea	rdx, [rbx+mimelike_bodyextend_ofs]	; our "fake" buffer object
	mov	rcx, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	rcx, rdx
	test	r13, r13
	cmovnz	rcx, r13
	mov	rdi, [rcx+buffer_length_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
calign
.body_straightin_skiplength:
	call	.headers
	lea	rdx, [rbx+mimelike_bodyextend_ofs]	; our "fake" buffer object
	mov	rcx, [rbx+mimelike_body_ofs]
	cmp	qword [rbx+mimelike_bodyext_ofs], 0
	cmovne	rcx, rdx
	test	r13, r13
	cmovnz	rcx, r13
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	buffer$append
	test	r13, r13
	jz	.body_straightin_nointermediate
	mov	rdi, r13
	call	buffer$destroy
	pop	r15 r14 r13 r12
	mov	rdi, [rbx+mimelike_parts_ofs]
	cmp	qword [rdi+_list_first_ofs], 0
	je	.skipparts
	mov	rsi, .addpart
	mov	rdx, rbx
	call	list$foreach_arg
	mov	rdi, rbx
	mov	esi, 1			; last part gets extra bits on the boundary marker
	call	.addxmitboundary
	pop	rbx
	epilog
calign
.body_straightin_nointermediate:
	pop	r15 r14 r13 r12
	mov	rdi, [rbx+mimelike_parts_ofs]
	cmp	qword [rdi+_list_first_ofs], 0
	je	.skipparts
	mov	rsi, .addpart
	mov	rdx, rbx
	call	list$foreach_arg
	mov	rdi, rbx
	mov	esi, 1			; last part gets extra bits on the boundary marker
	call	.addxmitboundary
	pop	rbx
	epilog
calign
.doparts:
	call	.headers
	mov	rdi, [rbx+mimelike_parts_ofs]
	cmp	qword [rdi+_list_first_ofs], 0
	je	.skipparts
	mov	rsi, .addpart
	mov	rdx, rbx
	call	list$foreach_arg
	mov	rdi, rbx
	mov	esi, 1			; last part gets extra bits on the boundary marker
	call	.addxmitboundary
	pop	rbx
	epilog
calign
.skipparts:
	pop	rbx
	epilog
falign
.addpart:
	; called with rdi == mimelike object to add, rsi == parent mimelike object that we are adding to
	push	rsi
	push	qword [rdi+mimelike_xmitbody_ofs]
	mov	rdi, rsi
	xor	esi, esi		; not the last part
	call	.addxmitboundary
	pop	rcx rdi
	mov	rdi, [rdi+mimelike_xmitbody_ofs]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	buffer$append
	ret
cleartext .headerlinesep, ': '
falign
.headerline:
	; called with rdi == key, rsi == value, rdx == hdrbuf
if mimelike_setcookie_split
	cmp	qword [rdi], 10
	je	.headerline_checksetcookie
end if
	push	rsi rdx
	mov	rsi, rdi
	mov	rdi, rdx
	call	buffer$append_rawstring_noreserve
	mov	rdi, [rsp]
if string_bits = 32
        mov     rax, [.headerlinesep+8]
else
        mov     eax, [.headerlinesep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	call	buffer$append_rawstring_noreserve
	pop	rdi
if string_bits = 32
        mov     rax, [.headersep+8]
else
        mov     eax, [.headersep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	add	rsp, 8
	ret
if mimelike_setcookie_split
calign
.headerline_checksetcookie:
	push	rsi rdx rbx
	mov	rbx, rdi
	mov	rsi, mimelike$setcookie
	call	string$equals
	test	eax, eax
	jz	.headerline_notsetcookie
	; otherwise, it is Set-Cookie, we need to split concatenated ones out into multiple headerlines
	; we can sorta cheat here, the issue is that the expires= date format _also_ has a ', ' such that
	; splitting on it alone isn't good enough
	push	r12 r13 r14
	mov	r12, [rsp+32]		; our destination buffer
	mov	r13, [rsp+40]		; our value string
	mov	rdi, r13
	mov	rsi, .commaspace
	call	string$split_str
	mov	r14, rax
calign
.headerline_setcookie_outer:
	cmp	qword [r14+_list_first_ofs], 0
	je	.headerline_done_nolinebreak
	mov	rdi, r12
	mov	rsi, mimelike$setcookie
	call	buffer$append_rawstring_noreserve
	mov	rdi, r12
if string_bits = 32
        mov     rax, [.headerlinesep+8]
else
        mov     eax, [.headerlinesep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	; add the first string regardless
	cmp	qword [r14+_list_first_ofs], 0
	je	.headerline_setcookie_done
	mov	rdi, r14
	call	list$pop_front
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_rawstring_noreserve
	pop	rdi
	call	heap$free
	; now, walk the remaining items, and either start a new header line, or add a ', ' and keep going
calign
.headerline_setcookie_inner:
	cmp	qword [r14+_list_first_ofs], 0
	je	.headerline_setcookie_done
	mov	rdi, r14
	call	list$pop_front
	push	rax
	; so, if this starts with '## ', then we have to add a comma-space, then the string, and keep going
	; if it does -not- start with '## ', then we need to add a linebreak, push_front the string and jump back to outer
	mov	rdi, [rsp]
	mov	esi, 2
	call	string$charat
	cmp	eax, '-'
	jne	.headerline_setcookie_checkspace
calign
.headerline_setcookie_keepgoing:
	mov	rdi, [rsp]
	mov	esi, 0
	call	string$charat
	cmp	eax, '0'
	jb	.headerline_setcookie_linebreak
	cmp	eax, '3'
	jae	.headerline_setcookie_linebreak
	mov	rdi, [rsp]
	mov	esi, 1
	call	string$charat
	cmp	eax, '0'
	jb	.headerline_setcookie_linebreak
	cmp	eax, '9'
	ja	.headerline_setcookie_linebreak
	; otherwise, add a ', ' and then our string, and jump to outer
	mov	rdi, r12
	mov	rsi, .commaspace
	call	buffer$append_rawstring_noreserve
	mov	rdi, r12
	mov	rsi, [rsp]
	call	buffer$append_rawstring_noreserve
        mov     rdi, r12
if string_bits = 32
        mov     rax, [.headersep+8]
else
        mov     eax, [.headersep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	pop	rdi
	call	heap$free
	jmp	.headerline_setcookie_outer
calign
.headerline_setcookie_checkspace:
	cmp	eax, ' '
	je	.headerline_setcookie_keepgoing
calign
.headerline_setcookie_linebreak:
	mov	rdi, r14
	pop	rsi
	call	list$push_front
        mov     rdi, r12
if string_bits = 32
        mov     rax, [.headersep+8]
else
        mov     eax, [.headersep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	jmp	.headerline_setcookie_outer
calign
.headerline_setcookie_done:
        mov     rdi, r12
if string_bits = 32
        mov     rax, [.headersep+8]
else
        mov     eax, [.headersep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	mov	rdi, r14
	call	heap$free

	pop	r14 r13 r12 rbx
	add	rsp, 16
	ret
calign
.headerline_done_nolinebreak:
	mov	rdi, r14
	call	heap$free

	pop	r14 r13 r12 rbx
	add	rsp, 16
	ret

cleartext .commaspace, ', '

calign
.headerline_notsetcookie:
	mov	rdi, rbx
	pop	rbx
	mov	rsi, rdi
	mov	rdi, [rsp]
	call	buffer$append_rawstring_noreserve
	mov	rdi, [rsp]
if string_bits = 32
        mov     rax, [.headerlinesep+8]
else
        mov     eax, [.headerlinesep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	call	buffer$append_rawstring_noreserve
	pop	rdi
if string_bits = 32
        mov     rax, [.headersep+8]
else
        mov     eax, [.headersep+8]
end if
        mov     rsi, [rdi+buffer_endptr_ofs]
if string_bits = 32
        add     qword [rdi+buffer_endptr_ofs], 8
        add     qword [rdi+buffer_length_ofs], 8
        mov     [rsi], rax
else
        add     qword [rdi+buffer_endptr_ofs], 4
        add     qword [rdi+buffer_length_ofs], 4
        mov     [rsi], eax
end if
	add	rsp, 8
	ret
end if

falign
.addxmitboundary:
	; called with rdi == the mimelike object, esi == bool for whether it is the last one or not
	; if there is no boundary already set, create a default one
	push	rbx r12
	mov	rbx, rdi
	mov	r12d, esi
	cmp	qword [rdi+mimelike_boundary_ofs], 0
	jne	.boundarygood
	call	mimelike$setdefaultboundary
calign
.boundarygood:
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	mov	esi, 0x2d2d0a0d		; "\r\n--"
	call	buffer$append_dword
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	mov	rsi, [rbx+mimelike_boundary_ofs]
	call	buffer$append_string
	mov	rdi, [rbx+mimelike_xmitbody_ofs]
	test	r12d, r12d
	jnz	.lastone
	mov	esi, 0xa0d
	call	buffer$append_word
	pop	r12 rbx
	ret
calign
.lastone:
	mov	esi, 0xa0d2d2d
	call	buffer$append_dword
	pop	r12 rbx
	ret

end if

if used mimelike$transferencoding | defined include_everything
cleartext mimelike$transferencoding, 'Transfer-Encoding'
end if

if used mimelike$acceptencoding | defined include_everything
cleartext mimelike$acceptencoding, 'Accept-Encoding'
end if

if used mimelike$contenttransferencoding | defined include_everything
cleartext mimelike$contenttransferencoding, 'Content-Transfer-Encoding'
end if

if used mimelike$contenttype | defined include_everything
cleartext mimelike$contenttype, 'Content-Type'
end if

if used mimelike$contentlength | defined include_everything
cleartext mimelike$contentlength, 'Content-Length'
end if

if used mimelike$contentencoding | defined include_everything
cleartext mimelike$contentencoding, 'Content-Encoding'
end if

if used mimelike$connection | defined include_everything
cleartext mimelike$connection, 'Connection'
end if

if used mimelike$base64 | defined include_everything
cleartext mimelike$base64, 'base64'
end if

if used mimelike$7bit | defined include_everything
cleartext mimelike$7bit, '7bit'
end if

if used mimelike$8bit | defined include_everything
cleartext mimelike$8bit, '8bit'
end if

if used mimelike$binary | defined include_everything
cleartext mimelike$binary, 'binary'
end if

if used mimelike$quotedprintable | defined include_everything
cleartext mimelike$quotedprintable, 'quoted-printable'
end if

if used mimelike$chunked | defined include_everything
cleartext mimelike$chunked, 'chunked'
end if

if used mimelike$gzip | defined include_everything
cleartext mimelike$gzip, 'gzip'
end if

if used mimelike$texthtml | defined include_everything
cleartext mimelike$texthtml, 'text/html'
end if

if used mimelike$texthtmlutf8 | defined include_everything
cleartext mimelike$texthtmlutf8, 'text/html; charset=UTF-8'
end if

if used mimelike$textplain | defined include_everything
cleartext mimelike$textplain, 'text/plain'
end if

if used mimelike$pragma | defined include_everything
cleartext mimelike$pragma, 'Pragma'
end if

if used mimelike$cachecontrol | defined include_everything
cleartext mimelike$cachecontrol, 'Cache-Control'
end if

if used mimelike$location | defined include_everything
cleartext mimelike$location, 'Location'
end if

if used mimelike$etag | defined include_everything
cleartext mimelike$etag, 'ETag'
end if

if used mimelike$lastmodified | defined include_everything
cleartext mimelike$lastmodified, 'Last-Modified'
end if

if used mimelike$nocache | defined include_everything
cleartext mimelike$nocache, 'no-cache'
end if

if used mimelike$ifnonematch | defined include_everything
cleartext mimelike$ifnonematch, 'If-None-Match'
end if

if used mimelike$ifmodifiedsince | defined include_everything
cleartext mimelike$ifmodifiedsince, 'If-Modified-Since'
end if

if used mimelike$acceptranges | defined include_everything
cleartext mimelike$acceptranges, 'Accept-Ranges'
end if

if used mimelike$range | defined include_everything
cleartext mimelike$range, 'Range'
end if

if used mimelike$contentrange | defined include_everything
cleartext mimelike$contentrange, 'Content-Range'
end if

if used mimelike$bytes | defined include_everything
cleartext mimelike$bytes, 'bytes'
end if

if used mimelike$cookie | defined include_everything
cleartext mimelike$cookie, 'Cookie'
end if

if used mimelike$setcookie | defined include_everything
cleartext mimelike$setcookie, 'Set-Cookie'
end if


if used mimelike$setbody_external | defined include_everything
	; three arguments: rdi == mimelike object, rsi == ptr to data, rdx == length of same
	; NOTE: this does _not_ assume ownership of rsi, and does _not_ make a copy of it, so rsi/rdx must remain
	;   valid for the lifetime of this mimelike object (or at the very least through its compose stage(s))
	;   The data does _not_ get decoded, and absolutely nothing happens here other than setting our own
	;   internal copies of the values so that during compose we can use these _INSTEAD_ of mimelike_body_ofs
	;   see webserver.inc as to why this is used, but basically, we pass mmap'd base/size straight into here
	;   and we don't make a _double_ copy of it, until it is time for our final composition, at which point
	;   we _do_ make a copy of it
falign
mimelike$setbody_external:
	prolog	mimelike$setbody_external
	mov	[rdi+mimelike_bodyext_ofs], rsi
	mov	[rdi+mimelike_bodyextlen_ofs], rdx
	add	rsi, rdx
	mov	[rdi+mimelike_bodyextend_ofs], rsi
	; so at compose time, if bodyext is nonzero, we use that instead of the body itself
	epilog

end if


if used mimelike$setbody | defined include_everything
	; three arguments: rdi == mimelike object, rsi == ptr to data, rdx == length of same
	; NOTE: this is called by mimelike$new_parse during parse, but can also be used for on the fly body setting
	; NOTE 2: we pay attention to headers to determine the correct decoding action, so caution is advised
	;    if you have headers that don't match the body content you are trying to set
falign
mimelike$setbody:
	prolog	mimelike$setbody
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	rdi, [rbx+mimelike_body_ofs]
	call	buffer$reset
	; clear bodyext
	mov	qword [rbx+mimelike_bodyext_ofs], 0
	test	r13, r13
	jz	.nothingtodo
	mov	rdi, rbx
	mov	rsi, mimelike$transferencoding
	call	mimelike$getheader
	mov	r14, rax
	mov	rdi, rbx
	mov	rsi, mimelike$contentencoding
	call	mimelike$getheader
	mov	r15, rax
	or	rax, r14
	jz	.notgzippedorchunked
	; otherwise, chunked + gzip, chunked, or gzip checks
	; if no transfer encoding header, then check for gzip content encoding
	test	r14, r14
	jz	.check_gziponly
	; otherwise, we got a transfer encoding, see if no content encoding
	test	r15, r15
	jz	.check_chunkedonly
	; and for here, we have both headers, check chunked first, then check gzip
	mov	rdi, r14
	call	string$to_lower
	mov	r14, rax
	mov	rdi, rax
	mov	rsi, mimelike$chunked
	call	string$indexof
	push	rax
	mov	rdi, r14
	call	heap$free
	pop	r14
	cmp	r14, 0
	jl	.check_gziponly
	; otherwise, chunked is specified, see if it is also gzip
	mov	rdi, r15
	call	string$to_lower
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, mimelike$gzip
	call	string$indexof
	push	rax
	mov	rdi, r15
	call	heap$free
	pop	r15
	cmp	r15, 0
	jl	.do_chunkedonly
	; if we made it to here, it is both gzip and chunked, which means we need an intermediate working buffer
	call	buffer$new
	mov	r14, rax
	call	.unchunk
	test	eax, eax
	jz	.gzipunchunkfailed
	sub	rsp, 64
	mov	rdi, rsp
	mov	esi, 2
	call	zlib$inflateInit
	mov	rax, [rbx+mimelike_body_ofs]
	mov	[rsp+zlib_inbuf_ofs], r14
	mov	[rsp+zlib_outbuf_ofs], rax
	mov	rdi, rsp
	mov	esi, zlib_no_flush
	call	zlib$inflate
	mov	rdi, rsp
	call	zlib$inflateEnd
	mov	rdi, r14
	call	buffer$destroy
	add	rsp, 64
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.gzipunchunkfailed:
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	epilog
calign
.check_chunkedonly:
	; this one is different to having both, inthat we don't need an intermediate buffer
	mov	rdi, r14
	call	string$to_lower
	mov	r14, rax
	mov	rdi, rax
	mov	rsi, mimelike$chunked
	call	string$indexof
	push	rax
	mov	rdi, r14
	call	heap$free
	pop	rax
	cmp	rax, 0
	jl	.notgzippedorchunked
	; otherwise, no gzip, but we have chunked goods
calign
.do_chunkedonly:
	mov	r14, [rbx+mimelike_body_ofs]
	call	.unchunk
	; let its return be ours
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.unchunk:
	; TODO: rewrite this hideous mess, hahah
	; r14 is our intended destination buffer, r12/r13 source
	mov	rdi, r14
	mov	rsi, r13
	call	buffer$reserve
	sub	rsp, 64
if string_bits = 32
	mov	dword [rsp+8], '0'
	mov	dword [rsp+12], 'x'
else
	mov	word [rsp+8], '0'
	mov	word [rsp+10], 'x'
end if
calign
.unchunk_outer:
	; walk forward til semicolon or CRLF
	cmp	r13, 5
	jb	.unchunk_done_error
	mov	r15, r12
calign
.unchunk_chunklen:
	cmp	byte [r12], ';'
	je	.unchunk_chunklen_semicolon
	cmp	word [r12], 0xa0d
	je	.unchunk_chunklen_end
	add	r12, 1
	sub	r13, 1
	cmp	r13, 4
	jb	.unchunk_done_error
	jmp	.unchunk_chunklen
calign
.unchunk_chunklen_semicolon:
	mov	rax, r12
if string_bits = 32
	lea	rcx, [rsp+16]
else
	lea	rcx, [rsp+12]
end if
	sub	rax, r15
	test	rax, rax
	jz	.unchunk_done_error
	cmp	rax, 14
	ja	.unchunk_done_error
	mov	[rsp], rax
calign
.unchunk_chunklen_semicolon_expand:
	movzx	edx, byte [r15]
	add	r15, 1
if string_bits = 32
	mov	[rcx], edx
	add	rcx, 4
else
	mov	[rcx], dx
	add	rcx, 2
end if
	sub	eax, 1
	jnz	.unchunk_chunklen_semicolon_expand
	; string at rsp is valid, walk forward to the CRLF
	add	r12, 1
	sub	r13, 1
	cmp	r13, 5
	jb	.unchunk_done_error
calign
.unchunk_chunklen_semicolon_eol:
	cmp	word [r12], 0xa0d
	je	.unchunk_chunklen_doit
	add	r12, 1
	sub	r13, 1
	cmp	r13, 5
	jb	.unchunk_done_error
	jmp	.unchunk_chunklen_semicolon_eol
calign
.unchunk_chunklen_end:
	mov	rax, r12
if string_bits = 32
	lea	rcx, [rsp+16]
else
	lea	rcx, [rsp+12]
end if
	sub	rax, r15
	test	rax, rax
	jz	.unchunk_done_error
	cmp	rax, r14
	ja	.unchunk_done_error
	mov	[rsp], rax
calign
.unchunk_chunklen_expand:
	movzx	edx, byte [r15]
	add	r15, 1
if string_bits = 32
	mov	[rcx], edx
	add	rcx, 4
else
	mov	[rcx], dx
	add	rcx, 2
end if
	sub	eax, 1
	jnz	.unchunk_chunklen_expand
calign
.unchunk_chunklen_doit:
	; skip the CRLF
	add	r12, 2
	sub	r13, 2
	mov	rdi, rsp
	add	qword [rsp], 2		; include the 0x
	call	string$to_unsigned
	test	rax, rax
	jz	.unchunk_done
	cmp	rax, r13
	ja	.unchunk_done_error
	; otehrwise, add r12 for rax bytes to r14
	mov	rdi, r14
	mov	rsi, r12
	mov	rdx, rax
	add	r12, rax
	sub	r13, rax
	call	buffer$append
	; there should be a trailing crlf afterwards
	cmp	r13, 5
	jb	.unchunk_done_error
	cmp	word [r12], 0xa0d
	jne	.unchunk_done_error
	add	r12, 2
	sub	r13, 2
	jmp	.unchunk_outer
calign
.unchunk_done:
	add	rsp, 64
	mov	eax, 1
	ret
calign
.unchunk_done_error:
	add	rsp, 64
	xor	eax, eax
	ret
calign
.check_gziponly:
	; if we have unchunked, plain gzip data, we don't need to copy it into a working buffer, we can create a "phantom/fake" buffer object
	; that has its itself/length set to our passed contents, that way we don't double-copy it for unzip purposes
	; first, lowercase the value in r15
	mov	rdi, r15
	call	string$to_lower
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, mimelike$gzip
	call	string$indexof
	push	rax
	mov	rdi, r15
	call	heap$free
	pop	rax
	cmp	rax, 0
	jl	.notgzippedorchunked
	; otherwise, gzip it is, so inflate it
	mov	rax, r12
	add	rax, r13
	sub	rsp, 128		; buffer_object_size is 56, zlib_stream_size is also 56
	mov	[rsp+buffer_endptr_ofs], rax
	mov	[rsp+buffer_length_ofs], r13
	mov	[rsp+buffer_itself_ofs], r12
	mov	[rsp+buffer_size_ofs], r13
	lea	rdi, [rsp+64]
	mov	esi, 2
	call	zlib$inflateInit
	mov	rax, [rbx+mimelike_body_ofs]
	lea	rdi, [rsp+64]
	mov	[rdi+zlib_inbuf_ofs], rsp
	mov	[rdi+zlib_outbuf_ofs], rax
	mov	esi, zlib_no_flush
	call	zlib$inflate
	; if that did _not_ succeed, well, something still may have ended up in the body
	; we aren't too concerned with it inside here
	lea	rdi, [rsp+64]
	call	zlib$inflateEnd
	add	rsp, 128
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.notgzippedorchunked:
	mov	rdi, rbx
	mov	rsi, mimelike$contenttransferencoding
	call	mimelike$getheader
	test	rax, rax
	jz	.noparse
	; make sure that gets lowercased
	mov	rdi, rax
	call	string$to_lower
	mov	r14, rax
	; TODO: someday when I am bored, enforce the "short line limit" of 1000 here
	; for now, we just pass them straight through if it is 7bit, 8bit, or binary
	mov	rdi, rax
	mov	rsi, mimelike$7bit
	call	string$indexof
	cmp	rax, 0
	jge	.noparse_free
	mov	rdi, r14
	mov	rsi, mimelike$8bit
	call	string$indexof
	cmp	rax, 0
	jge	.noparse_free
	mov	rdi, r14
	mov	rsi, mimelike$binary
	call	string$indexof
	cmp	rax, 0
	jge	.noparse_free
	mov	rdi, r14
	mov	rsi, mimelike$quotedprintable
	call	string$indexof
	cmp	rax, 0
	jge	.quotedprintable
	mov	rdi, r14
	mov	rsi, mimelike$base64
	call	string$indexof
	cmp	rax, 0
	jge	.base64
	; otherwise, we don't recognize it, so pass the body striaght through
calign
.noparse_free:
	mov	rdi, r14
	call	heap$free
	; fallthrough to noparse
calign
.noparse:
	; so, not gzipped, not chunked, and no content transfer encoding, so just toss what we got straight in
	mov	rdi, [rbx+mimelike_body_ofs]
	mov	rsi, r12
	mov	rdx, r13
	call	buffer$append
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.quotedprintable:
	; we have to undo the QP kak and make the actual body out of the decode
	; free our lower case string first
	mov	rdi, r14
	call	heap$free
	test	r13, r13
	jz	.nothingtodo
	mov	rdi, [rbx+mimelike_body_ofs]
	mov	rsi, r13
	call	buffer$reserve
	mov	rdi, [rbx+mimelike_body_ofs]
	mov	r14, [rdi+buffer_itself_ofs]
	sub	rsp, 64
	mov	qword [rsp], 4
if string_bits = 32
	mov	dword [rsp+8], '0'
	mov	dword [rsp+12], 'x'
else
	mov	word [rsp+8], '0'
	mov	word [rsp+10], 'x'
end if
calign
.qploop:
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	cmp	eax, '='
	je	.qploop_equalsign
	mov	byte [r14], al
	add	r14, 1
	test	r13, r13
	jnz	.qploop
calign
.qpdone:
	mov	rsi, r14
	mov	rdi, [rbx+mimelike_body_ofs]
	sub	rsi, [rdi+buffer_itself_ofs]
	call	buffer$append_nocopy
	add	rsp, 64
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.qploop_equalsign:
	cmp	r13, 2
	jb	.qpdone
	; lots of in the wilds don't do CRLF, and just LF instead, so check for that too
	movzx	eax, word [r12]
	cmp	eax, 0xa0d
	je	.qploop_softlinebreak
	cmp	byte [r12], 0xa
	je	.qploop_softlinebreak_lf
	cmp	al, 32
	je	.qploop_paddedline
	; otherwise, this must be 2 hex digits
	add	r12, 2
	movzx	ecx, ah
	and	eax, 0xff
if string_bits = 32
	mov	[rsp+16], eax
	mov	[rsp+20], ecx
else
	mov	[rsp+12], ax
	mov	[rsp+14], cx
end if
	mov	rdi, rsp
	call	string$to_unsigned
	mov	byte [r14], al
	add	r14, 1
	sub	r13, 2
	jnz	.qploop
	jmp	.qpdone
calign
.qploop_softlinebreak:
	add	r12, 2
	sub	r13, 2
	jnz	.qploop
	jmp	.qpdone
calign
.qploop_softlinebreak_lf:
	add	r12, 1
	sub	r13, 1
	jnz	.qploop
	jmp	.qpdone
calign
.qploop_paddedline:
	add	r12, 1
	sub	r13, 1
	jz	.qpdone
calign
.qploop_paddedline_findlf:
	cmp	r13, 2
	jb	.qpdone
	cmp	word [r12], 0xa0d
	je	.qploop_softlinebreak
	cmp	byte [r12], 0xa
	je	.qploop_softlinebreak_lf
	add	r12, 1
	sub	r13, 1
	jnz	.qploop_paddedline_findlf
	jmp	.qpdone
calign
.nothingtodo:
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.base64:
	; free our lower case string first
	mov	rdi, r14
	call	heap$free
	; base64 decode what we got passed
	mov	rdi, [rbx+mimelike_body_ofs]
	mov	rsi, r13
	call	buffer$reserve		; TODO: /4*3 instead lazy, wasting space in the heap here
	mov	rax, [rbx+mimelike_body_ofs]
	mov	rdi, r12
	mov	rsi, r13
	mov	rdx, [rax+buffer_itself_ofs]
	xor	ecx, ecx
	call	base64$decode_latin1
	mov	rdi, [rbx+mimelike_body_ofs]
	mov	rsi, rax
	call	buffer$append_nocopy
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog

end if





if used mimelike$new_parse | defined include_everything
	; four arguments: rdi == ptr to utf8 goods, rsi == length of same, edx == bool for headers only, ecx == bool for whether there is a preface or not
	; returns a mimelike object or null on error
	;
	; NOTE: For duplicate headers, this adds a comma to the previous one, and appends the duplicate value, instead of overwriting it, or actually
	; making a duplicate, all of my use scenarios thus far, this has been fine and dandy, but it might be restricting in certain [rare?] cases, haha
	; NOTE 2: compose will go through a lot of extra trouble to deal with Set-Cookie, which for older browsers, seems to be the only header that doesn't
	; really let me do the ', ' concat + unique headers.
falign
mimelike$new_parse:
	prolog	mimelike$new_parse
	test	rdi, rdi
	jz	.nullret		; sanity only
	cmp	rsi, 8
	jb	.nullret
	test	ecx, ecx
	jz	.nopreface
	; walk forward til EOL
	mov	rcx, rdi
	mov	r9, rsi
calign
.find_preface_eol:
	cmp	word [rcx], 0xa0d
	je	.found_preface_crlf
	cmp	byte [rcx], 0xd
	je	.found_preface_lf
	add	rcx, 1
	sub	r9, 1
	cmp	r9, 2
	ja	.find_preface_eol
calign
.nullret:
	xor	eax, eax
	epilog
calign
.found_preface_crlf:
	mov	rax, rcx
	push	rdi			; save the preface start pointer
	sub	rax, rdi
	push	rax			; and its length
	add	rcx, 2
	sub	rcx, rdi
	sub	rsi, rcx
	add	rdi, rcx
calign
.found_preface_doit:
	add	rsi, rdi
	push	rcx			; save the length of the preface, including the crlf/lf
	call	.parsemimepart
	pop	r8
	test	rax, rax
	jz	.preface_error_ret
	add	[rax+mimelike_hdrlen_ofs], r8
	add	[rax+mimelike_parselen_ofs], r8
	; otherwise, set our preface
	pop	rsi
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	string$from_utf8
	mov	rdi, [rsp]
	mov	rsi, rax
	call	mimelike$setpreface_nocopy
	pop	rax
	epilog
calign
.found_preface_lf:
	mov	rax, rcx
	push	rdi			; save the preface start pointer
	sub	rax, rdi
	push	rax			; and its length
	add	rcx, 1
	sub	rcx, rdi
	sub	rsi, rcx
	add	rdi, rcx
	jmp	.found_preface_doit
calign
.preface_error_ret:
	add	rsp, 16
	epilog
calign
.nopreface:
	add	rsi, rdi
	mov	ecx, r8d
	call	.parsemimepart
	epilog

falign
.parsemimepart:
	; rdi == start ptr, rsi == end ptr, edx == bool for headers only
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdi
	sub	rsp, 64
	mov	[rsp], edx
	mov	dword [rsp+4], 0	; number of header lines we have got
	mov	[rsp+8], rdi		; header start position
	mov	qword [rsp+32], 0	; header key length
	call	mimelike$new
	mov	rbx, rax
	mov	[rax+mimelike_user_ofs], r12	; save the starting pointer
	add	r14, 4
calign
.headers_outer:
	cmp	r14, r13
	ja	.headers_error
	xor	r15d, r15d		; how long the current line is
	mov	dword [rsp+24], 0	; bool as to whether we are on a continuation line or not
	cmp	dword [rsp+4], 0	; no header lines yet means it can't be a continuation
	je	.headers_normal
	xor	eax, eax
	mov	ecx, 1
	xor	edx, edx
	cmp	byte [r12], 32
	cmove	eax, ecx
	cmp	byte [r12], 9
	cmove	edx, ecx
	or	eax, edx
	jz	.headers_normal
	; continuation line
calign
.headers_cont_skipspace:
	cmp	r14, r13
	ja	.headers_error
	cmp	word [r12], 0xa0d
	je	.headers_error
	cmp	byte [r12], 0xa
	je	.headers_error
	xor	eax, eax
	cmp	byte [r12], 32
	cmove	eax, ecx
	cmp	byte [r12], 9
	cmove	eax, ecx
	test	eax, eax
	jz	.headers_cont_spacedone
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	jmp	.headers_cont_skipspace
calign
.headers_cont_spacedone:
	mov	[rsp+16], r12		; value starting position
	mov	dword [rsp+24], 1	; bool set for continuation line
	mov	ecx, 1
	jmp	.headers_valscan
calign
.headers_normal:
	mov	[rsp+8], r12
	; hmmm, probably should redo how this little tidbit works
calign
.headers_normal_loop:
	cmp	r14, r13
	ja	.headers_error
	movzx	edx, byte [r12]
	cmp	word [r12], 0xa0d
	je	.headers_implicit	; this shouldn't happen in normal use, but if a boundary is followed by _exactly_ CRLF
					; then we are supposed to assume Content-Type: text/plain as our header
	cmp	edx, 32
	jb	.headers_error
	cmp	edx, ':'
	je	.headers_normal_keydone
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	jmp	.headers_normal_loop
calign
.headers_normal_keydone:
	cmp	r12, [rsp+8]		; keyless not okay
	je	.headers_error
	cmp	byte [r12+1], ' '
	jne	.headers_normal_keydone_checkemptyvalue
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rsp+32], rax		; header key length
	add	r12, 2
	add	r14, 2
	add	r15d, 2
	; cruise forward and skip spaces
	mov	ecx, 1
	mov	[rsp+16], r12		; value starting position
calign
.headers_normal_skipspace:
	cmp	r14, r13
	ja	.headers_error
	movzx	edx, byte [r12]
	xor	eax, eax
	cmp	edx, 32
	cmove	eax, ecx
	cmp	edx, 9
	cmove	eax, ecx
	test	eax, eax
	jz	.headers_valscan
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	mov	[rsp+16], r12		; value starting position
	jmp	.headers_normal_skipspace
calign
.headers_normal_keydone_checkemptyvalue:
	cmp	word [r12+1], 0xa0d
	je	.headers_normal_emptyvalue
	cmp	byte [r12+1], 0xa
	jne	.headers_error
calign
.headers_normal_emptyvalue:
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rsp+32], rax		; header key length
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	; cruise forward and skip spaces
	mov	ecx, 1
	mov	[rsp+16], r12		; value starting position
calign
.headers_valscan:
	; go til eol
	cmp	r14, r13
	ja	.headers_error
	xor	eax, eax
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	cmp	byte [r12], 0xa
	cmove	eax, ecx
	test	eax, eax
	jnz	.headers_valscan_done
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	jmp	.headers_valscan
calign
.headers_valscan_done:
	; the rfc says the max line length is 998, but apparently no one adheres to that
	cmp	r15d, 8192
	ja	.headers_error
	cmp	qword [rsp+32], 0	; sanity only
	je	.headers_error
	; otherwise, looks like a valid header line
	mov	rax, r12
	sub	rax, [rsp+16]
	mov	[rsp+40], rax		; value length
	add	dword [rsp+4], 1	; number of headerlines we have
	; create strings for both
	mov	rdi, [rsp+8]		; header starting position
	mov	rsi, [rsp+32]		; header key length
	call	string$from_utf8
	mov	[rsp+48], rax
	mov	rdi, [rsp+16]		; value starting position
	mov	rsi, [rsp+40]		; value length
	call	string$from_utf8
	mov	[rsp+56], rax		; save the parsed value for this line
	cmp	dword [rsp+24], 1
	je	.headers_setcontinuation
	mov	rdi, rbx
	mov	rsi, [rsp+48]		; the key we are working with
	call	mimelike$getheader
	test	rax, rax
	jnz	.headers_setduplicate
	mov	rdi, rbx
	mov	rsi, [rsp+48]
	mov	rdx, [rsp+56]
	call	mimelike$setheader_nocopy
	cmp	dword [r12], 0xa0d0a0d
	je	.headers_complete
	cmp	word [r12], 0xa0a
	je	.headers_complete
	mov	eax, 1
	mov	ecx, 2
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	add	r12, rax
	add	r14, rax
	jmp	.headers_outer
calign
.headers_setduplicate:
	mov	rdi, .commaspacestr
	mov	rsi, [rsp+56]
	call	string$concat
	jmp	.headers_append_doit
cleartext .commaspacestr, ', '
cleartext .spacestr, ' '
calign
.headers_setcontinuation:
	; this is horrifically inefficient, probably should redo this, hehe
	mov	rdi, .spacestr
	mov	rsi, rax
	call	string$concat
calign
.headers_append_doit:
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, [rsp+48]		; the key we are working with
	call	mimelike$getheader
	test	rax, rax		; sanity only
	jz	.headers_continuation_error
	mov	rdi, rax
	mov	rsi, [rsp+56]
	call	string$concat
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, [rsp+48]
	mov	rdx, [rsp+56]
	call	mimelike$setheader_nocopy
	cmp	dword [r12], 0xa0d0a0d
	je	.headers_complete
	cmp	word [r12], 0xa0a
	je	.headers_complete
	mov	eax, 1
	mov	ecx, 2
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	add	r12, rax
	add	r14, rax
	jmp	.headers_outer
calign
.headers_continuation_error:
	; free both strings and puke
	mov	rdi, [rsp+48]
	call	heap$free
	mov	rdi, [rsp+56]
	call	heap$free
	jmp	.headers_error
cleartext .mp1, 'multipart/'
cleartext .mp2, 'boundary='
cleartext .mp3, 'boundary="'
calign
.headers_implicit:
	add	r12, 2
	add	r14, 2
	; set the implicit content type
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$textplain
	call	mimelike$setheader
	jmp	.notmultipart
calign
.headers_complete:
	mov	eax, 2
	mov	ecx, 4
	cmp	dword [r12], 0xa0d0a0d
	cmove	eax, ecx
	add	r12, rax
	add	r14, rax
	; set the hdrlen
	mov	rcx, r12
	sub	rcx, [rbx+mimelike_user_ofs]
	mov	[rbx+mimelike_hdrlen_ofs], rcx
	mov	[rbx+mimelike_parselen_ofs], rcx
	; so, we skipped the header end, if headers only was requested, now is the time to return
	cmp	dword [rsp], 0
	jne	.headers_complete_doreturn
	; if we have a content length header, make sure we have enough data, or return null
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jz	.headers_complete_nocontentlength
	mov	rdi, rax
	call	string$to_unsigned
	mov	rcx, r13
	sub	rcx, r12
	cmp	rax, rcx
	ja	.headers_error
	add	[rbx+mimelike_parselen_ofs], rcx
	; for cases where we do NOT have a "preamble" (default body type), _and_ we got presented
	; a content-length (as in the case of POST w/ multipart/form-data et al)
	; set the outermost body to the complete body
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r13
	sub	rdx, r12
	call	mimelike$setbody
calign
.headers_complete_nocontentlength:
	; otherwise, check to see if it is a multipart content type, otherwise set our body
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	call	mimelike$getheader
	test	rax, rax
	jz	.notmultipart
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .mp1
	call	string$indexof
	cmp	rax, 0
	jl	.notmultipart
	mov	rdi, r15
	mov	rsi, .mp2
	call	string$indexof
	cmp	rax, 0
	jl	.notmultipart
	; since our multipart boundary preface includes the preceding CRLF (or just LF)
	; we have to unwind our pointer in r12 by either 1 or 2
	xor	ecx, ecx
	mov	edx, 1
	sub	r12, 2
	cmp	word [r12], 0xa0a
	cmove	ecx, edx
	add	r12, rcx
	; otherwise, it contains multipart/ and boundary=, so parts it is
	; it is possible that the boundary is quoted
	mov	[rsp], rax
	mov	rdi, r15
	mov	rsi, .mp3
	call	string$indexof
	cmp	rax, 0
	jl	.multipart_notquoted
	mov	rdx, [rsp]
	mov	esi, '"'
	mov	rdi, r15
	add	rdx, 11
	call	string$indexof_charcode_ofs
	mov	rdi, r15
	mov	rsi, [rsp]
	mov	rdx, rax
	add	rsi, 10
	call	string$substring
	mov	[rsp+8], rax
	; set the mimelike$boundary
	mov	rdi, r15
	xor	esi, esi
	mov	rdx, [rsp]
	call	string$substring
	mov	[rsp+16], rax
	mov	rdi, rbx
	mov	rsi, [rsp+8]
	mov	rdx, rax
	call	mimelike$setboundary
	mov	rdi, [rsp+16]
	call	heap$free
	; \r\n--boundary\r\n, \n--boundary\n, \r\n--boundary--\r\n, \n--boundary--\n
	; [rsp+8] is our boundary
	; [rsp] is the indexof substring that we are done with now
	jmp	.multipart_boundarycheck
cleartext .crlfdashdash, 13,10,'--'
cleartext .crlf, 13,10
cleartext .lfdashdash, 10,'--'
cleartext .lf, 10
cleartext .dashdashcrlf, '--',13,10
cleartext .dashdashlf, '--',10
calign
.multipart_notquoted:
	mov	rsi, [rsp]
	mov	rdi, r15
	mov	rdx, -1
	add	rsi, 9
	call	string$substr			; boundary substring
	mov	[rsp+8], rax
	; set the mimelike boundary
	mov	rdi, r15
	xor	esi, esi
	mov	rdx, [rsp]
	call	string$substring		; content type substring
	mov	[rsp+16], rax
	mov	rdi, rbx
	mov	rsi, [rsp+8]
	mov	rdx, rax
	call	mimelike$setboundary
	mov	rdi, [rsp+16]
	call	heap$free
calign
.multipart_boundarycheck:
	; to be tolerant, e.g. cutting/pasting a mime encoded session, we may not necessarily
	; have CRLF delimiters, despite the spec demanding it does... so if we can't find a CRLF
	; we check for LF only based ones too
	mov	rdi, .crlfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .crlf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	; make sure we can find it
	mov	[rsp], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+16], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free

	xor	edi, edi		; starting position for search
	mov	rsi, [rsp]		; pattern we are searching for
	mov	rdx, [rsp+16]		; pattern length
	call	.byte_indexof

	; so at this point, [rsp] == our utf8 CRLF--boundaryCRLF
	; [rsp+8] is the actual boundary
	; [rsp+16] is the length of [rsp]
	mov	[rsp+24], rax		; save the starting marker
	cmp	rax, -1
	je	.multipart_boundary_checklf
	; otherwise, it was valid, so create our ending boundary and its utf8 form as well
	mov	rdi, .crlfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .dashdashcrlf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+40], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free
	jmp	.multipart_boundary_doit
calign
.multipart_boundary_checklf:
	; free our UTF8 buffer, and do it again with lf instead of crlf
	mov	rdi, [rsp]
	call	heap$free

	mov	rdi, .lfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .lf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	; make sure we can find it
	mov	[rsp], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+16], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free

	xor	edi, edi
	mov	rsi, [rsp]		; pattern we are searching for
	mov	rdx, [rsp+16]		; pattern length
	call	.byte_indexof
	; so at this point, [rsp] == our utf8 CRLF--boundaryCRLF
	; [rsp+8] is the actual boundary
	; [rsp+16] is the length of [rsp]
	cmp	rax, -1
	je	.multipart_boundary_error
	mov	[rsp+24], rax		; save the starting marker
	; otherwise, we need the same again for the ending boundary
	mov	rdi, .lfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .dashdashlf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+40], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free
calign
.multipart_boundary_doit:
	; so now:
	; [rsp] is our utf non-last boundary
	; [rsp+8] is the actual boundary string
	; [rsp+16] is the length of the non-last boundary
	; [rsp+24] is the starting marker position
	; [rsp+32] is the utf8 of the last boundary
	; [rsp+40] is the length of the last boundary
	
	; so we may have a preamble if the starting marker is >0, in which case
	; we need to set our body to it
	cmp	qword [rsp+24], 0
	je	.multipart_boundary_nopreamble
	; we have to undo the temporary step backward for the prefix start
	mov	eax, 1
	mov	ecx, 2
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	; hmmm, that may not always work exactly right... TODO: come back and redo this by storing the value previously used
	
	mov	rdi, rbx
	mov	rsi, r12
	add	rsi, rax
	mov	rdx, [rsp+24]
	sub	rdx, rax
	call	mimelike$setbody
calign
.multipart_boundary_nopreamble:
	mov	rdi, [rsp+16]
	add	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+16]
	call	.byte_indexof
	cmp	rax, -1
	je	.multipart_boundary_checklast
calign
.multipart_boundary_addpart:
	mov	[rsp+48], rax		; save the ending marker
	mov	rdi, r12
	add	rdi, [rsp+24]
	add	rdi, [rsp+16]
	mov	rsi, r12
	add	rsi, rax
	xor	edx, edx
	call	.parsemimepart
	mov	rcx, [rsp+48]
	mov	[rsp+24], rcx		; starting marker == ending marker for next round
	test	rax, rax
	jz	.multipart_boundary_nopreamble
	mov	rdi, [rbx+mimelike_parts_ofs]
	mov	rsi, rax
	mov	[rax+mimelike_parent_ofs], rbx
	call	list$push_back
	jmp	.multipart_boundary_nopreamble
calign
.multipart_boundary_checklast:
	mov	rdi, [rsp+16]
	add	rdi, [rsp+24]
	mov	rsi, [rsp+32]
	mov	rdx, [rsp+40]
	call	.byte_indexof
	cmp	rax, -1
	jne	.multipart_boundary_addpart
calign
.multipart_boundary_doreturn:
	mov	rdi, [rsp]
	call	heap$free
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, [rsp+32]
	call	heap$free
	jmp	.normal_return
calign
.multipart_boundary_error:
	; free our UTF8 first
	mov	rdi, [rsp]
	call	heap$free
	; free the boundary string itself
	mov	rdi, [rsp+8]
	call	heap$free
	; destroy our mimelike object? if we didn't find a boundary
	; this mime object is invalid, so hmmm, we could be more
	; tolerant, and return it as-is without further parsing I spose
	; hmm, yeah, that is what we'll do for now
	jmp	.normal_return

calign
.notmultipart:
	; some interesting error condition possibilities here that we need to sort:
	; if our transfer encoding is chunked, and setbody returns us with 0, fail
	; if transfer encoding != chunked, then check for content-length, and if
	; content length is set, and we don't have enough data, fail
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jz	.notmultipart_nocl
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdx, r13
	sub	rdx, r12
	cmp	rax, rdx
	ja	.headers_error
	add	[rbx+mimelike_parselen_ofs], rax
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, rax
	call	mimelike$setbody
	test	eax, eax
	jz	.headers_error
	jmp	.normal_return
calign
.notmultipart_nocl:
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r13
	sub	rdx, r12
	call	mimelike$setbody
	test	eax, eax
	jz	.headers_error
calign
.headers_complete_doreturn:
.normal_return:
	add	rsp, 64
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	ret
calign
.headers_error:
	mov	rdi, rbx
	call	mimelike$destroy
	add	rsp, 64
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	ret
falign
.byte_indexof:
	; r12 is our input
	; r13 is our input end
	; rdi = starting position for our search
	; rsi == bytes for search pattern
	; rdx == length of search pattern
	mov	r8, r13
	sub	r8, r12
	sub	r8, rdx
	add	r8, r12			; ending position
	add	rdi, r12		; starting position
	cmp	rdi, r8
	ja	.byte_indexof_negone
calign
.byte_indexof_outer:
	xor	ecx, ecx
	mov	r9, rdx
calign
.byte_indexof_inner:
	movzx	eax, byte [rdi+rcx]
	cmp	al, byte [rsi+rcx]
	jne	.byte_indexof_next
	add	rcx, 1
	sub	r9, 1
	jnz	.byte_indexof_inner
	mov	rax, rdi
	sub	rax, r12
	ret
calign
.byte_indexof_next:
	add	rdi, 1
	cmp	rdi, r8
	jbe	.byte_indexof_outer
calign
.byte_indexof_negone:
	mov	rax, -1
	ret

end if


if used mimelike$new_parse_ext | defined include_everything
	; four arguments: rdi == ptr to utf8 goods, rsi == length of same, edx == bool for headers only, ecx == bool for whether there is a preface or not
	; returns a mimelike object or null on error
	;
	; this is the same thing as new_parse, only instead of setbody, setbody_external is used and no decoding is performed
	; CAUTION: this means that the buffer that is passed in here is referenced by the returned mimelike object, and as a result must exist
	; for the lifetime of this mimelike object!! (unlike the normal new_parse, which decodes/copies it)
falign
mimelike$new_parse_ext:
	prolog	mimelike$new_parse_ext
	test	rdi, rdi
	jz	.nullret		; sanity only
	cmp	rsi, 8
	jb	.nullret
	test	ecx, ecx
	jz	.nopreface
	; walk forward til EOL
	mov	rcx, rdi
	mov	r9, rsi
calign
.find_preface_eol:
	cmp	word [rcx], 0xa0d
	je	.found_preface_crlf
	cmp	byte [rcx], 0xd
	je	.found_preface_lf
	add	rcx, 1
	sub	r9, 1
	cmp	r9, 2
	ja	.find_preface_eol
calign
.nullret:
	xor	eax, eax
	epilog
calign
.found_preface_crlf:
	mov	rax, rcx
	push	rdi			; save the preface start pointer
	sub	rax, rdi
	push	rax			; and its length
	add	rcx, 2
	sub	rcx, rdi
	sub	rsi, rcx
	add	rdi, rcx
calign
.found_preface_doit:
	add	rsi, rdi
	push	rcx			; save the length of the preface, including the crlf/lf
	call	.parsemimepart
	pop	r8
	test	rax, rax
	jz	.preface_error_ret
	add	[rax+mimelike_hdrlen_ofs], r8
	add	[rax+mimelike_parselen_ofs], r8
	; otherwise, set our preface
	pop	rsi
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	string$from_utf8
	mov	rdi, [rsp]
	mov	rsi, rax
	call	mimelike$setpreface_nocopy
	pop	rax
	epilog
calign
.found_preface_lf:
	mov	rax, rcx
	push	rdi			; save the preface start pointer
	sub	rax, rdi
	push	rax			; and its length
	add	rcx, 1
	sub	rcx, rdi
	sub	rsi, rcx
	add	rdi, rcx
	jmp	.found_preface_doit
calign
.preface_error_ret:
	add	rsp, 16
	epilog
calign
.nopreface:
	add	rsi, rdi
	mov	ecx, r8d
	call	.parsemimepart
	epilog

falign
.parsemimepart:
	; rdi == start ptr, rsi == end ptr, edx == bool for headers only
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdi
	sub	rsp, 64
	mov	[rsp], edx
	mov	dword [rsp+4], 0	; number of header lines we have got
	mov	[rsp+8], rdi		; header start position
	mov	qword [rsp+32], 0	; header key length
	call	mimelike$new
	mov	rbx, rax
	mov	[rax+mimelike_user_ofs], r12	; save the starting pointer
	add	r14, 4
calign
.headers_outer:
	cmp	r14, r13
	ja	.headers_error
	xor	r15d, r15d		; how long the current line is
	mov	dword [rsp+24], 0	; bool as to whether we are on a continuation line or not
	cmp	dword [rsp+4], 0	; no header lines yet means it can't be a continuation
	je	.headers_normal
	xor	eax, eax
	mov	ecx, 1
	xor	edx, edx
	cmp	byte [r12], 32
	cmove	eax, ecx
	cmp	byte [r12], 9
	cmove	edx, ecx
	or	eax, edx
	jz	.headers_normal
	; continuation line
calign
.headers_cont_skipspace:
	cmp	r14, r13
	ja	.headers_error
	cmp	word [r12], 0xa0d
	je	.headers_error
	cmp	byte [r12], 0xa
	je	.headers_error
	xor	eax, eax
	cmp	byte [r12], 32
	cmove	eax, ecx
	cmp	byte [r12], 9
	cmove	eax, ecx
	test	eax, eax
	jz	.headers_cont_spacedone
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	jmp	.headers_cont_skipspace
calign
.headers_cont_spacedone:
	mov	[rsp+16], r12		; value starting position
	mov	dword [rsp+24], 1	; bool set for continuation line
	mov	ecx, 1
	jmp	.headers_valscan
calign
.headers_normal:
	mov	[rsp+8], r12
	; hmmm, probably should redo how this little tidbit works
calign
.headers_normal_loop:
	cmp	r14, r13
	ja	.headers_error
	movzx	edx, byte [r12]
	cmp	word [r12], 0xa0d
	je	.headers_implicit	; this shouldn't happen in normal use, but if a boundary is followed by _exactly_ CRLF
					; then we are supposed to assume Content-Type: text/plain as our header
	cmp	edx, 32
	jb	.headers_error
	cmp	edx, ':'
	je	.headers_normal_keydone
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	jmp	.headers_normal_loop
calign
.headers_normal_keydone:
	cmp	r12, [rsp+8]		; keyless not okay
	je	.headers_error
	cmp	byte [r12+1], ' '
	jne	.headers_normal_keydone_checkemptyvalue
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rsp+32], rax		; header key length
	add	r12, 2
	add	r14, 2
	add	r15d, 2
	; cruise forward and skip spaces
	mov	ecx, 1
	mov	[rsp+16], r12		; value starting position
calign
.headers_normal_skipspace:
	cmp	r14, r13
	ja	.headers_error
	movzx	edx, byte [r12]
	xor	eax, eax
	cmp	edx, 32
	cmove	eax, ecx
	cmp	edx, 9
	cmove	eax, ecx
	test	eax, eax
	jz	.headers_valscan
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	mov	[rsp+16], r12		; value starting position
	jmp	.headers_normal_skipspace
calign
.headers_normal_keydone_checkemptyvalue:
	cmp	word [r12+1], 0xa0d
	je	.headers_normal_emptyvalue
	cmp	byte [r12+1], 0xa
	jne	.headers_error
calign
.headers_normal_emptyvalue:
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rsp+32], rax		; header key length
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	; cruise forward and skip spaces
	mov	ecx, 1
	mov	[rsp+16], r12		; value starting position
calign
.headers_valscan:
	; go til eol
	cmp	r14, r13
	ja	.headers_error
	xor	eax, eax
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	cmp	byte [r12], 0xa
	cmove	eax, ecx
	test	eax, eax
	jnz	.headers_valscan_done
	add	r12, 1
	add	r14, 1
	add	r15d, 1
	jmp	.headers_valscan
calign
.headers_valscan_done:
	; the rfc says the max line length is 998, but apparently no one adheres to that
	cmp	r15d, 8192
	ja	.headers_error
	cmp	qword [rsp+32], 0	; sanity only
	je	.headers_error
	; otherwise, looks like a valid header line
	mov	rax, r12
	sub	rax, [rsp+16]
	mov	[rsp+40], rax		; value length
	add	dword [rsp+4], 1	; number of headerlines we have
	; create strings for both
	mov	rdi, [rsp+8]		; header starting position
	mov	rsi, [rsp+32]		; header key length
	call	string$from_utf8
	mov	[rsp+48], rax
	mov	rdi, [rsp+16]		; value starting position
	mov	rsi, [rsp+40]		; value length
	call	string$from_utf8
	mov	[rsp+56], rax		; save the parsed value for this line
	cmp	dword [rsp+24], 1
	je	.headers_setcontinuation
	mov	rdi, rbx
	mov	rsi, [rsp+48]		; the key we are working with
	call	mimelike$getheader
	test	rax, rax
	jnz	.headers_setduplicate
	mov	rdi, rbx
	mov	rsi, [rsp+48]
	mov	rdx, [rsp+56]
	call	mimelike$setheader_nocopy
	cmp	dword [r12], 0xa0d0a0d
	je	.headers_complete
	cmp	word [r12], 0xa0a
	je	.headers_complete
	mov	eax, 1
	mov	ecx, 2
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	add	r12, rax
	add	r14, rax
	jmp	.headers_outer
calign
.headers_setduplicate:
	mov	rdi, .commaspacestr
	mov	rsi, [rsp+56]
	call	string$concat
	jmp	.headers_append_doit
cleartext .commaspacestr, ', '
cleartext .spacestr, ' '
calign
.headers_setcontinuation:
	; this is horrifically inefficient, probably should redo this, hehe
	mov	rdi, .spacestr
	mov	rsi, rax
	call	string$concat
calign
.headers_append_doit:
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, [rsp+48]		; the key we are working with
	call	mimelike$getheader
	test	rax, rax		; sanity only
	jz	.headers_continuation_error
	mov	rdi, rax
	mov	rsi, [rsp+56]
	call	string$concat
	mov	rdi, [rsp+56]
	mov	[rsp+56], rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, [rsp+48]
	mov	rdx, [rsp+56]
	call	mimelike$setheader_nocopy
	cmp	dword [r12], 0xa0d0a0d
	je	.headers_complete
	cmp	word [r12], 0xa0a
	je	.headers_complete
	mov	eax, 1
	mov	ecx, 2
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	add	r12, rax
	add	r14, rax
	jmp	.headers_outer
calign
.headers_continuation_error:
	; free both strings and puke
	mov	rdi, [rsp+48]
	call	heap$free
	mov	rdi, [rsp+56]
	call	heap$free
	jmp	.headers_error
cleartext .mp1, 'multipart/'
cleartext .mp2, 'boundary='
cleartext .mp3, 'boundary="'
calign
.headers_implicit:
	add	r12, 2
	add	r14, 2
	; set the implicit content type
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$textplain
	call	mimelike$setheader
	jmp	.notmultipart
calign
.headers_complete:
	mov	eax, 2
	mov	ecx, 4
	cmp	dword [r12], 0xa0d0a0d
	cmove	eax, ecx
	add	r12, rax
	add	r14, rax
	; set the hdrlen
	mov	rcx, r12
	sub	rcx, [rbx+mimelike_user_ofs]
	mov	[rbx+mimelike_hdrlen_ofs], rcx
	mov	[rbx+mimelike_parselen_ofs], rcx
	; so, we skipped the header end, if headers only was requested, now is the time to return
	cmp	dword [rsp], 0
	jne	.headers_complete_doreturn
	; if we have a content length header, make sure we have enough data, or return null
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jz	.headers_complete_nocontentlength
	mov	rdi, rax
	call	string$to_unsigned
	mov	rcx, r13
	sub	rcx, r12
	cmp	rax, rcx
	ja	.headers_error
	add	[rbx+mimelike_parselen_ofs], rcx
	; for cases where we do NOT have a "preamble" (default body type), _and_ we got presented
	; a content-length (as in the case of POST w/ multipart/form-data et al)
	; set the outermost body to the complete body
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r13
	sub	rdx, r12
	call	mimelike$setbody_external
calign
.headers_complete_nocontentlength:
	; otherwise, check to see if it is a multipart content type, otherwise set our body
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	call	mimelike$getheader
	test	rax, rax
	jz	.notmultipart
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .mp1
	call	string$indexof
	cmp	rax, 0
	jl	.notmultipart
	mov	rdi, r15
	mov	rsi, .mp2
	call	string$indexof
	cmp	rax, 0
	jl	.notmultipart
	; since our multipart boundary preface includes the preceding CRLF (or just LF)
	; we have to unwind our pointer in r12 by either 1 or 2
	xor	ecx, ecx
	mov	edx, 1
	sub	r12, 2
	cmp	word [r12], 0xa0a
	cmove	ecx, edx
	add	r12, rcx
	; otherwise, it contains multipart/ and boundary=, so parts it is
	; it is possible that the boundary is quoted
	mov	[rsp], rax
	mov	rdi, r15
	mov	rsi, .mp3
	call	string$indexof
	cmp	rax, 0
	jl	.multipart_notquoted
	mov	rdx, [rsp]
	mov	esi, '"'
	mov	rdi, r15
	add	rdx, 11
	call	string$indexof_charcode_ofs
	mov	rdi, r15
	mov	rsi, [rsp]
	mov	rdx, rax
	add	rsi, 10
	call	string$substring
	mov	[rsp+8], rax
	; set the mimelike$boundary
	mov	rdi, r15
	xor	esi, esi
	mov	rdx, [rsp]
	call	string$substring
	mov	[rsp+16], rax
	mov	rdi, rbx
	mov	rsi, [rsp+8]
	mov	rdx, rax
	call	mimelike$setboundary
	mov	rdi, [rsp+16]
	call	heap$free
	; \r\n--boundary\r\n, \n--boundary\n, \r\n--boundary--\r\n, \n--boundary--\n
	; [rsp+8] is our boundary
	; [rsp] is the indexof substring that we are done with now
	jmp	.multipart_boundarycheck
cleartext .crlfdashdash, 13,10,'--'
cleartext .crlf, 13,10
cleartext .lfdashdash, 10,'--'
cleartext .lf, 10
cleartext .dashdashcrlf, '--',13,10
cleartext .dashdashlf, '--',10
calign
.multipart_notquoted:
	mov	rsi, [rsp]
	mov	rdi, r15
	mov	rdx, -1
	add	rsi, 9
	call	string$substr			; boundary substring
	mov	[rsp+8], rax
	; set the mimelike boundary
	mov	rdi, r15
	xor	esi, esi
	mov	rdx, [rsp]
	call	string$substring		; content type substring
	mov	[rsp+16], rax
	mov	rdi, rbx
	mov	rsi, [rsp+8]
	mov	rdx, rax
	call	mimelike$setboundary
	mov	rdi, [rsp+16]
	call	heap$free
calign
.multipart_boundarycheck:
	; to be tolerant, e.g. cutting/pasting a mime encoded session, we may not necessarily
	; have CRLF delimiters, despite the spec demanding it does... so if we can't find a CRLF
	; we check for LF only based ones too
	mov	rdi, .crlfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .crlf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	; make sure we can find it
	mov	[rsp], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+16], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free

	xor	edi, edi		; starting position for search
	mov	rsi, [rsp]		; pattern we are searching for
	mov	rdx, [rsp+16]		; pattern length
	call	.byte_indexof

	; so at this point, [rsp] == our utf8 CRLF--boundaryCRLF
	; [rsp+8] is the actual boundary
	; [rsp+16] is the length of [rsp]
	mov	[rsp+24], rax		; save the starting marker
	cmp	rax, -1
	je	.multipart_boundary_checklf
	; otherwise, it was valid, so create our ending boundary and its utf8 form as well
	mov	rdi, .crlfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .dashdashcrlf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+40], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free
	jmp	.multipart_boundary_doit
calign
.multipart_boundary_checklf:
	; free our UTF8 buffer, and do it again with lf instead of crlf
	mov	rdi, [rsp]
	call	heap$free

	mov	rdi, .lfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .lf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	; make sure we can find it
	mov	[rsp], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+16], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free

	xor	edi, edi
	mov	rsi, [rsp]		; pattern we are searching for
	mov	rdx, [rsp+16]		; pattern length
	call	.byte_indexof
	; so at this point, [rsp] == our utf8 CRLF--boundaryCRLF
	; [rsp+8] is the actual boundary
	; [rsp+16] is the length of [rsp]
	cmp	rax, -1
	je	.multipart_boundary_error
	mov	[rsp+24], rax		; save the starting marker
	; otherwise, we need the same again for the ending boundary
	mov	rdi, .lfdashdash
	mov	rsi, [rsp+8]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, .dashdashlf
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; turn that into a UTF8 encoding
	mov	rdi, r15
	call	string$utf8_length
	mov	rdi, rax
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, r15
	mov	rsi, rax
	call	string$to_utf8
	mov	[rsp+40], rax
	; we are done with r15
	mov	rdi, r15
	call	heap$free
calign
.multipart_boundary_doit:
	; so now:
	; [rsp] is our utf non-last boundary
	; [rsp+8] is the actual boundary string
	; [rsp+16] is the length of the non-last boundary
	; [rsp+24] is the starting marker position
	; [rsp+32] is the utf8 of the last boundary
	; [rsp+40] is the length of the last boundary
	
	; so we may have a preamble if the starting marker is >0, in which case
	; we need to set our body to it
	cmp	qword [rsp+24], 0
	je	.multipart_boundary_nopreamble
	; we have to undo the temporary step backward for the prefix start
	mov	eax, 1
	mov	ecx, 2
	cmp	word [r12], 0xa0d
	cmove	eax, ecx
	; hmmm, that may not always work exactly right... TODO: come back and redo this by storing the value previously used
	
	mov	rdi, rbx
	mov	rsi, r12
	add	rsi, rax
	mov	rdx, [rsp+24]
	sub	rdx, rax
	call	mimelike$setbody_external
calign
.multipart_boundary_nopreamble:
	mov	rdi, [rsp+16]
	add	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+16]
	call	.byte_indexof
	cmp	rax, -1
	je	.multipart_boundary_checklast
calign
.multipart_boundary_addpart:
	mov	[rsp+48], rax		; save the ending marker
	mov	rdi, r12
	add	rdi, [rsp+24]
	add	rdi, [rsp+16]
	mov	rsi, r12
	add	rsi, rax
	xor	edx, edx
	call	.parsemimepart
	mov	rcx, [rsp+48]
	mov	[rsp+24], rcx		; starting marker == ending marker for next round
	test	rax, rax
	jz	.multipart_boundary_nopreamble
	mov	rdi, [rbx+mimelike_parts_ofs]
	mov	rsi, rax
	mov	[rax+mimelike_parent_ofs], rbx
	call	list$push_back
	jmp	.multipart_boundary_nopreamble
calign
.multipart_boundary_checklast:
	mov	rdi, [rsp+16]
	add	rdi, [rsp+24]
	mov	rsi, [rsp+32]
	mov	rdx, [rsp+40]
	call	.byte_indexof
	cmp	rax, -1
	jne	.multipart_boundary_addpart
calign
.multipart_boundary_doreturn:
	mov	rdi, [rsp]
	call	heap$free
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, [rsp+32]
	call	heap$free
	jmp	.normal_return
calign
.multipart_boundary_error:
	; free our UTF8 first
	mov	rdi, [rsp]
	call	heap$free
	; free the boundary string itself
	mov	rdi, [rsp+8]
	call	heap$free
	; destroy our mimelike object? if we didn't find a boundary
	; this mime object is invalid, so hmmm, we could be more
	; tolerant, and return it as-is without further parsing I spose
	; hmm, yeah, that is what we'll do for now
	jmp	.normal_return

calign
.notmultipart:
	; some interesting error condition possibilities here that we need to sort:
	; if our transfer encoding is chunked, and setbody returns us with 0, fail
	; if transfer encoding != chunked, then check for content-length, and if
	; content length is set, and we don't have enough data, fail
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$getheader
	test	rax, rax
	jz	.notmultipart_nocl
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdx, r13
	sub	rdx, r12
	cmp	rax, rdx
	ja	.headers_error
	add	[rbx+mimelike_parselen_ofs], rax
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, rax
	call	mimelike$setbody_external
	test	eax, eax
	jz	.headers_error
	jmp	.normal_return
calign
.notmultipart_nocl:
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r13
	sub	rdx, r12
	call	mimelike$setbody_external
	test	eax, eax
	jz	.headers_error
calign
.headers_complete_doreturn:
.normal_return:
	add	rsp, 64
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	ret
calign
.headers_error:
	mov	rdi, rbx
	call	mimelike$destroy
	add	rsp, 64
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	ret
falign
.byte_indexof:
	; r12 is our input
	; r13 is our input end
	; rdi = starting position for our search
	; rsi == bytes for search pattern
	; rdx == length of search pattern
	mov	r8, r13
	sub	r8, r12
	sub	r8, rdx
	add	r8, r12			; ending position
	add	rdi, r12		; starting position
	cmp	rdi, r8
	ja	.byte_indexof_negone
calign
.byte_indexof_outer:
	xor	ecx, ecx
	mov	r9, rdx
calign
.byte_indexof_inner:
	movzx	eax, byte [rdi+rcx]
	cmp	al, byte [rsi+rcx]
	jne	.byte_indexof_next
	add	rcx, 1
	sub	r9, 1
	jnz	.byte_indexof_inner
	mov	rax, rdi
	sub	rax, r12
	ret
calign
.byte_indexof_next:
	add	rdi, 1
	cmp	rdi, r8
	jbe	.byte_indexof_outer
calign
.byte_indexof_negone:
	mov	rax, -1
	ret

end if
