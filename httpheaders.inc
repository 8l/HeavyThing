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
	; httpheaders.inc: HTTP/2 and HTTP/1.x header handling w/o native string
	; conversions. Separated from mimelike.inc for speed/simplicity and
	; HTTP-specific encoding/decoding
	;


if used httpheaders$new | used httpheaders$init | defined include_everything

	; instead of doing individual allocs for each and every header name/value, we preallocate a 6kb-8 byte block to deal with our "scratch"
	; and if for some reason we overflow that space, then we allocate a proper 64k buffer to hold them, but we only do that for overflow
	; and during normal operations, everything stays tightly compacted inside the 6k space

httpheaders_scratch_ofs = 0		; if for some reason we exceeded _our_ SETTINGS_HEADER_TABLE_SIZE of 4096 bytes per the HTTP/2 spec, then
					; this will be a buffer$new, otherwise, NULL for normal use
httpheaders_dtable_ofs = 8		; this will either be a pointer to our own block, or into the scratch area if we went too far
httpheaders_dcount_ofs = 16		; the number of entries in our dynamic table
httpheaders_dlimit_ofs = 20		; the limit of count before it gets popped into the scratch buffer, defaults to 40 to start with
httpheaders_tablesize_ofs = 24		; length(key) + length(val) + 32 for each entry in our dtable is what this gets compared against, default is 4096
httpheaders_hcount_ofs = 28		; how many headers we actually have parsed/sitting on
httpheaders_flags_ofs = 32		; flags storage of 64 bits, lowest 2 bits == http version (0 == HTTP/1.0, 1 == HTTP/1.1, 2 == HTTP/2)
httpheaders_dtableint_ofs = 40		; dtable itself sits at 40 for 40x32(1280) bytes
httpheaders_htable_ofs = 1320		; and the htable sits at 296 for 22x32(704) bytes
httpheaders_endptr_ofs = 2024		; this is a pointer to the "end" of our httpheaders pointer alloc block itself, which is 4104 bytes long to start with
					; (this one's initial value is pointing to the next offset)
httpheaders_scratchint_ofs = 2032

httpheaders_size = 6136


	; no arguments, returns a prepped and ready httpheaders object
falign
httpheaders$new:
	prolog	httpheaders$new
	mov	edi, httpheaders_size
	call	heap$alloc
	xor	ecx, ecx
	lea	rdx, [rax+httpheaders_dtableint_ofs]
	lea	r8, [rax+httpheaders_scratchint_ofs]
	mov	[rax+httpheaders_scratch_ofs], rcx
	mov	[rax+httpheaders_dtable_ofs], rdx
	mov	dword [rax+httpheaders_dcount_ofs], 0
	mov	dword [rax+httpheaders_dlimit_ofs], 40
	mov	qword [rax+httpheaders_tablesize_ofs], 4096	; clears hcount too
	mov	[rax+httpheaders_flags_ofs], rcx	; clear the flags qword
	mov	[rax+httpheaders_endptr_ofs], r8
	epilog

end if

if used httpheaders$init | defined include_everything
	; single argument in rdi: an uninitialized httpheaders object
	; returns ptr in rdi in rax
falign
httpheaders$init:
	prolog	httpheaders$init
	mov	rax, rdi
	xor	ecx, ecx
	lea	rdx, [rax+httpheaders_dtableint_ofs]
	lea	r8, [rax+httpheaders_scratchint_ofs]
	mov	[rax+httpheaders_scratch_ofs], rcx
	mov	[rax+httpheaders_dtable_ofs], rdx
	mov	dword [rax+httpheaders_dcount_ofs], 0
	mov	dword [rax+httpheaders_dlimit_ofs], 40
	mov	qword [rax+httpheaders_tablesize_ofs], 4096	; clears hcount too
	mov	[rax+httpheaders_flags_ofs], rcx	; clear the flags qword
	mov	[rax+httpheaders_endptr_ofs], r8
	epilog

end if

if used httpheaders$cleanup | defined include_everything
	; single argument in rdi: httpheaders object
	; if there is no scratch buffer, does nothing
falign
httpheaders$cleanup:
	prolog	httpheaders$cleanup
	cmp	qword [rdi+httpheaders_scratch_ofs], 0
	jne	.withscratch
	epilog
calign
.withscratch:
	mov	rdi, [rdi+httpheaders_scratch_ofs]
	call	buffer$destroy
	epilog

end if


if used httpheaders$reset | defined include_everything
	; single argument in rdi: our httpheader object
	; puts the state back to what it was at time of $new
falign
httpheaders$reset:
	prolog	httpheaders$reset
	cmp	qword [rdi+httpheaders_scratch_ofs], 0
	jne	.withscratch
	xor	ecx, ecx
	lea	rdx, [rdi+httpheaders_dtableint_ofs]
	lea	r8, [rdi+httpheaders_scratchint_ofs]
	mov	[rdi+httpheaders_dtable_ofs], rdx
	mov	dword [rdi+httpheaders_dcount_ofs], 0
	mov	dword [rdi+httpheaders_dlimit_ofs], 40
	mov	qword [rdi+httpheaders_tablesize_ofs], 4096	; clears hcount too
	mov	[rdi+httpheaders_flags_ofs], rcx	; clear the flags qword
	mov	[rdi+httpheaders_endptr_ofs], r8
	epilog
calign
.withscratch:
	push	rdi
	mov	rdi, [rdi+httpheaders_scratch_ofs]
	call	buffer$destroy
	pop	rdi
	xor	ecx, ecx
	lea	rdx, [rdi+httpheaders_dtableint_ofs]
	lea	r8, [rdi+httpheaders_scratchint_ofs]
	mov	[rdi+httpheaders_scratch_ofs], rcx
	mov	[rdi+httpheaders_dtable_ofs], rdx
	mov	dword [rdi+httpheaders_dcount_ofs], 0
	mov	dword [rdi+httpheaders_dlimit_ofs], 40
	mov	qword [rdi+httpheaders_tablesize_ofs], 4096	; clears hcount too
	mov	[rdi+httpheaders_flags_ofs], rcx	; clear the flags qword
	mov	[rdi+httpheaders_endptr_ofs], r8
	epilog

end if

if used httpheaders$reset_headers | defined include_everything
	; single argument in rdi: our httpheaders object
	; all this does is set hcount to 0 and leaves everything else alone
	; reference only, you should probably just set it yourself :-)
falign
httpheaders$reset_headers:
	prolog	httpheaders$reset_headers
	mov	dword [rdi+httpheaders_hcount_ofs], 0
	epilog

end if


if used httpheaders$tostring | defined include_everything
	; single argument in rdi: our httpheaders object
	; this isn't particularly efficient, we create a buffer, then tostring the buffer contents, but it is useful for
	; debugging purposes
falign
httpheaders$tostring:
	prolog	httpheaders$tostring
	push	rbx r12
	mov	rbx, rdi
	call	buffer$new
	mov	r12, rax
	mov	rdi, rbx
	mov	rsi, rax
	call	httpheaders$tobuffer_http1
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r12+buffer_length_ofs]
	call	string$from_utf8
	mov	rdi, r12
	mov	r12, rax
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog

end if


if used httpheaders$tobuffer_http1 | defined include_everything
	; two arguments: rdi == our httpheaders object, rsi == buffer object that we'll append into
falign
httpheaders$tobuffer_http1:
	prolog	httpheaders$tobuffer_http1
	cmp	dword [rdi+httpheaders_hcount_ofs], 0
	je	.nothingtodo
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	; first up we have to determine whether or not we have a preface line to compose
	; which will be either a pseudo header path, or a pseudo header status
	mov	rsi, httpheaders$pseudo_path
	call	httpheaders$fast_single_get
	test	rax, rax
	jz	.check_response_preface
	; otherwise, we do have a path
	mov	r13, rax
	mov	r14d, edx
	mov	rdi, r12
	lea	esi, [edx+32]
	call	buffer$reserve
	; if we have a path, we _must_ have a method
	mov	rdi, rbx
	mov	rsi, httpheaders$pseudo_method
	call	httpheaders$fast_single_get
	; add that and a space directly to our buffer
	mov	r8, [r12+buffer_endptr_ofs]
	mov	rcx, [rax]
	add	[r12+buffer_endptr_ofs], rdx
	add	[r12+buffer_length_ofs], rdx
	mov	[r8], rcx
	mov	byte [r8+rdx], ' '
	lea	rdi, [r8+rdx+1]
	mov	edx, r14d
	mov	rsi, r13
	add	r14d, 1
	add	[r12+buffer_endptr_ofs], r14
	add	[r12+buffer_length_ofs], r14
	call	memcpy
	mov	r11d, 0xa0d00
	mov	r8, [r12+buffer_endptr_ofs]
	mov	r9d, '0'
	mov	r10d, '1'
	cmp	dword [rbx+httpheaders_flags_ofs], 1
	cmove	r9d, r10d
	mov	rax, qword [.httpslashonedot]
	or	r9d, r11d
	add	qword [r12+buffer_endptr_ofs], 11
	add	qword [r12+buffer_length_ofs], 11
	mov	[r8], rax
	mov	[r8+8], r9d
	jmp	.proceed
calign
.nothingtodo:
	epilog
dalign
.httpslashonedotoh: db 'HTTP/1.0'
.httpslashonedotone: db 'HTTP/1.1'
calign
.check_response_preface:
	mov	rdi, rbx
	mov	rsi, httpheaders$pseudo_status
	call	httpheaders$fast_single_get
	test	rax, rax
	jz	.proceed
	; otehrwise, we do have a status, so add HTTP/1.x status +our own descriptive
	mov	r13, rax
	mov	r14d, edx
	mov	rdi, r12
	lea	esi, [edx+128]
	call	buffer$reserve
	mov	rdx, [r12+buffer_endptr_ofs]
	mov	r8d, [r13]
	mov	rax, qword [.httpslashonedotoh]
	mov	rcx, qword [.httpslashonedotone]
	and	r8d, 0xffffff		; sanity only
	cmp	dword [rbx+httpheaders_flags_ofs], 1
	cmove	rax, rcx
	or	r8d, 0x20000000
	mov	[rdx], rax
	mov	byte [rdx+8], ' '
	mov	[rdx+9], r8d
	; next up, we have to add our descriptives
	mov	r14d, r8d
	lea	rdx, [rdx+13]
	mov	rcx, rdx
	sub	rcx, [r12+buffer_endptr_ofs]
	mov	[r12+buffer_endptr_ofs], rdx
	add	[r12+buffer_length_ofs], rcx
	; unfortunately this isn't very pretty
	mov	rdi, r12
	mov	rsi, .r200
	mov	edx, .r200len
	cmp	r14d, '200 '
	je	.status_doit
	mov	rsi, .r206
	mov	edx, .r206len
	cmp	r14d, '206 '
	je	.status_doit
	mov	rsi, .r301
	mov	edx, .r301len
	cmp	r14d, '301 '
	je	.status_doit
	mov	rsi, .r302
	mov	edx, .r302len
	cmp	r14d, '302 '
	je	.status_doit
	mov	rsi, .r304
	mov	edx, .r304len
	cmp	r14d, '304 '
	je	.status_doit
	mov	rsi, .r400
	mov	edx, .r400len
	cmp	r14d, '400 '
	je	.status_doit
	mov	rsi, .r403
	mov	edx, .r403len
	cmp	r14d, '403 '
	je	.status_doit
	mov	rsi, .r404
	mov	edx, .r404len
	cmp	r14d, '404 '
	je	.status_doit
	mov	rsi, .r405
	mov	edx, .r405len
	cmp	r14d, '405 '
	je	.status_doit
	mov	rsi, .r500
	mov	edx, .r500len
	cmp	r14d, '500 '
	je	.status_doit
	mov	rsi, .r501
	mov	edx, .r501len
	cmp	r14d, '501 '
	je	.status_doit
	mov	rsi, .r502
	mov	edx, .r502len
	cmp	r14d, '502 '
	je	.status_doit
	mov	rsi, .r503
	mov	edx, .r503len
	cmp	r14d, '503 '
	je	.status_doit
	mov	rsi, .r504
	mov	edx, .r504len
	cmp	r14d, '504 '
	je	.status_doit
	mov	rsi, .r505
	mov	edx, .r505len
	cmp	r14d, '505 '
	je	.status_doit
	mov	rsi, .rdefault
	mov	edx, .rdefaultlen
calign
.status_doit:
	call	buffer$append

	; fallthrough to proceed
calign
.proceed:
	; so if we had a preface line, we already composed and added it to our buffer, so next up, get set to walk our htable, which we know is nonzero
	lea	r13, [rbx+httpheaders_htable_ofs]
	mov	r14d, [rbx+httpheaders_hcount_ofs]
calign
.headerloop:
	mov	rdx, [r13]		; name pointer
	mov	rsi, [r13+8]		; name length
	mov	rdi, r12
	add	rsi, [r13+24]		; value length
	cmp	byte [rdx], ':'		; check for a pseudo header
	je	.headerskip
	; otherwise, we need +2 for our ': ' and 2 more for the 0xa0d on the end, and +2 more for good measure
	add	rsi, 6
	call	buffer$reserve
	mov	rdx, [r13+8]		; name length
	mov	rdi, [r12+buffer_endptr_ofs]
	mov	rsi, [r13]		; name pointer
	add	[r12+buffer_endptr_ofs], rdx
	add	[r12+buffer_length_ofs], rdx
	push	rdi
	call	memcpy
	pop	rax
	mov	rdx, [r13+24]		; value length
	mov	rdi, [r12+buffer_endptr_ofs]
	mov	rsi, [r13+16]		; value pointer
	lea	rcx, [rdx+2]
	mov	word [rdi], ': '
	add	rdi, 2
	add	[r12+buffer_endptr_ofs], rcx
	add	[r12+buffer_length_ofs], rcx
	sub	byte [rax], 'a' - 'A'
	call	memcpy
	; and our 0xa0d closer
	mov	rdi, [r12+buffer_endptr_ofs]
	mov	word [rdi], 0xa0d
	add	qword [r12+buffer_endptr_ofs], 2
	add	qword [r12+buffer_length_ofs], 2
	; fallthrough to headerskip
calign
.headerskip:
	add	r13, 32
	sub	r14d, 1
	jnz	.headerloop
	; otherwise, we are done, add our trailing 0xa0d
	mov	rdi, [r12+buffer_endptr_ofs]
	mov	word [rdi], 0xa0d
	add	qword [r12+buffer_endptr_ofs], 2
	add	qword [r12+buffer_length_ofs], 2

	pop	r14 r13 r12 rbx
	epilog
dalign
.httpslashonedot:	db	' HTTP/1.'
dalign
.r200:	db	'She',0x27,'ll be apples',13,10
.r200len = $ - .r200
dalign
.r206:	db	'Just a slice of the whole pie',13,10
.r206len = $ - .r206
dalign
.r301:	db	'She nicked off',13,10
.r301len = $ - .r301
dalign
.r302:	db	'Look here mate',13,10
.r302len = $ - .r302
dalign
.r304:	db	'Same same mate',13,10
.r304len = $ - .r304

dalign
.r400:	db	'Up a gumtree',13,10
.r400len = $ - .r400
dalign
.r403:	db	'I wouldn',0x27,'t be doin that',13,10
.r403len = $ - .r403
dalign
.r404:	db	'Gone Walkabout',13,10
.r404len = $ - .r404
dalign
.r405:	db	'Wrong idea mate',13,10
.r405len = $ - .r405
dalign
.r500:	db	'It',0x27,'s Cactus',13,10
.r500len = $ - .r500
dalign
.r501:	db	'Not Implemented',13,10
.r501len = $ - .r501
dalign
.r502:	db	'Had a blue with the old fella',13,10
.r502len = $ - .r502
dalign
.r503:	db	'You got nits in your network',13,10
.r503len = $ - .r503
dalign
.r504:	db	'Gateway Tuckered Out',13,10
.r504len = $ - .r504
dalign
.r505:	db	'You gone bongers mate?',13,10
.r505len = $ - .r505
dalign
.rdefault:	db	'HeavyThing',13,10
.rdefaultlen = $ - .rdefault

end if


if used httpheaders$tobuffer_http2 | defined include_everything
	; three arguments: rdi == our httpheaders object, rsi == destination buffer object, rdx == _source_ httpheaders object
	; returns a bool as to whether we succeeded (note that if rdx contains no headers/htable entries, then we return true
	; despite not writing anything to rsi)

	; Some fairly involved notes here about how this is all meant to work:
	; So, for an HTTP/2 connection, each connection maintains two separate httpheaders objects, one for encoding, other for decoding
	; During the normal course of operations (e.g. response construction in reply to a request), the webserver layer constructs
	; a wholly independent httpheaders response object, and THAT object gets passed to this one which is ultimately the encoding
	; context. This allows the webserver (and user application layers) to add/remove/reset/do whatever they want to their
	; set of headers all without the encoding context needing to keep track of all of that
	; This also allows external layers (like backpaths, FastCGI, etc) to parse independent HTTP/1 httpheaders objects, and pass
	; those directly to here for the encoding layer as well, nice and clean. The potential downside of this design is that
	; inside this function, we take create care to _merge_ (and thus update the dynamic table) appropriately.
	; This also means that the httpheaders object in rdi is not necessarily meant to have any of its own htable entries, and in fact
	; this function specifically ignores it if it does (because that would not make sense). The object in rdi is meant to be the
	; encoding context's dynamic table updates, and that is what this function maintains.
	;
	; NOTE: We _never index (dynamic table update)_ the following fields:
	; Date, Content-Length, ETag, Last-Modified, If-None-Match, If-Modified-Since, Content-Range, Range
	; over the course of multiple requests tehse are likely to always be different, and thus would waste what is otherwise perfectly
	; good dynamic table space.  (we use 6.2.2 Literal Header Field without Indexing for these)
	;
	; If this returns false, and your source httpheaders' hcount was nonzero, it is likely your peer and you won't be in sync.
	; (won't happen during the course of normal operations, only if you are doing something custom/funky)
falign
httpheaders$tobuffer_http2:
	prolog	httpheaders$tobuffer_http2
	cmp	dword [rdx+httpheaders_hcount_ofs], 0
	je	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	r14d, [rdx+httpheaders_hcount_ofs]	; we know this is nonzero
	lea	r15, [rdx+httpheaders_htable_ofs]

macro hpack_dtable_ceiling n* {
	; make sure our dynamic table size hasn't been exceeded
	; since we know this isn't going to get very big
	local	.start, .loop, .nodeal
	cmp	dword [rbx+httpheaders_dcount_ofs], 0
	je	.nodeal
.start:
	mov	ecx, n
	mov	edx, [rbx+httpheaders_dcount_ofs]
	mov	r8, [rbx+httpheaders_dtable_ofs]
calign
.loop:
	; calculate the current size first
	add	ecx, 32
	add	ecx, [r8+8]
	add	ecx, [r8+24]
	add	r8, 32
	sub	edx, 1
	jnz	.loop
	; if ecx is less than tablesize, allgood
	cmp	ecx, [rbx+httpheaders_tablesize_ofs]
	jbe	.nodeal
	; otherwise, lower dcount and start again
	sub	dword [rbx+httpheaders_dcount_ofs], 1
	jnz	.start
.nodeal:
}

macro hpack_write_integer val*, prefixor*, prefixlen* {
	; r12 == the destination buffer object that we are adding to, val is either fixed or in r8d, prefixor is the leading upper bits
	local	.small, .e, .loop, .last
	; TODO: check the type of val, if it is not a register, then deal with it directly
	mov	rdi, r12
	mov	eax, val
	mov	esi, 16
	push	rax
	call	buffer$reserve
	pop	rax
	mov	rdi, [r12+buffer_endptr_ofs]
	cmp	eax, (1 shl prefixlen) - 1
	jb	.small
	mov	ecx, (1 shl prefixlen) - 1
	sub	eax, ecx
	or	ecx, prefixor
	mov	byte [rdi], cl
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	add	rdi, 1

	mov	ecx, eax
	cmp	eax, 128
	jb	.last
	or	ecx, 0x80
	mov	byte [rdi], cl
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	add	rdi, 1
	shr	eax, 7

	mov	ecx, eax
	cmp	eax, 128
	jb	.last
	or	ecx, 0x80
	mov	byte [rdi], cl
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	add	rdi, 1
	shr	eax, 7

	mov	ecx, eax
	cmp	eax, 128
	jb	.last
	or	ecx, 0x80
	mov	byte [rdi], cl
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	add	rdi, 1
	shr	eax, 7

	mov	ecx, eax
	cmp	eax, 128
	jb	.last
	or	ecx, 0x80
	mov	byte [rdi], cl
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	add	rdi, 1
	shr	eax, 7

.last:
	mov	byte [rdi], al
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	jmp	.e
.small:
	or	eax, prefixor
	mov	byte [rdi], al
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
.e:
}

calign
.top:
	; so, the 32 bytes at r15 is our source htable entry
	; several possibilities for how we will encode this into our buffer (and/or update our own dtable)
	; 1) name and value both exist in the static table: pure indexed encoding
	; 2) name is one of our excluded (never indexed) headers: encode never indexed, indexed name, literal value
	; 3) name exists in the static table, value does not
	;    3.1) name also exists in our dtable, with a matching value entry: pure indexed encoding
	;    3.2) name not in our dtable: indexed name, literal value
	; 4) name exists in our dtable
	;    4.1) value also exists in same entry: pure indexed encoding
	;       4.1.1) search for more matches in the dtable, back to 4
	;    4.2) value does not exist: indexed name, literal value
	; 5) name does not exist in our dtable, add w/ index (provided it isn't excluded, otherwise never indexed)
	mov	rax, [r15]	; the name pointer
	mov	rcx, [r15+16]	; the value pointer
	mov	rdx, httpheaders$static
	xor	r8d, r8d
	mov	r9d, [rbx+httpheaders_dcount_ofs]
	cmp	rax, httpheaders$static_end
	ja	.name_not_static
	; otherwise, the name is one of our static headers
	; if the value is _also_, then case 1 from above, pure indexed it is
	cmp	rcx, httpheaders$static_end
	jb	.name_and_value_static
	; otherwise, name exists in the static table, value is not static
	; if it is our special case Connection header (which we put at index 0, invalid, but we use it for HTTP/1)
	; then we can skip to name_not_static despite it still being in our static table
	cmp	rax, httpheaders$connection
	je	.name_not_static
	; see if we have this name in our dtable _and_ a matching value
	test	r9d, r9d
	jz	.name_static_new_value
	; otherwise, we have to search our nonzero dtable for a matching name _and_ value
	push	rbx r12 r13 r14
	mov	rbx, [rbx+httpheaders_dtable_ofs]
	mov	r12d, r9d
	mov	r13, rax
	mov	r14d, 62
calign
.name_static_dtable_search:
	cmp	r13, [rbx]
	je	.name_static_dtable_search_checkvalue
.name_static_dtable_search_next:
	add	rbx, 32
	add	r14d, 1
	sub	r12d, 1
	jnz	.name_static_dtable_search
	; if we made it to here, we didn't find the name in the dtable
	pop	r14 r13 r12 rbx
	mov	rax, [r15]
	mov	rdx, httpheaders$static
	xor	r8d, r8d
	jmp	.name_static_new_value
calign
.name_static_dtable_search_checkvalue:
	; the value length at [r15+24] must match this dtable entry's value at +24
	mov	rdx, [rbx+24]
	cmp	rdx, [r15+24]
	jne	.name_static_dtable_search_next
	mov	rdi, [rbx+16]
	mov	rsi, [r15+16]
	call	memcmp
	test	eax, eax
	jnz	.name_static_dtable_search_next
	; if we made it to here, r14d is our pure index because we found a matching name
	mov	r8d, r14d
	pop	r14 r13 r12 rbx
	hpack_write_integer r8d, 0x80, 7
	jmp	.next
calign
.name_and_value_static:
	; determine the 1-based index, we know it can't be our special case 0 index
	cmp	rax, [rdx]
	je	.name_and_value_static_indexfound
	add	rdx, 32
	add	r8d, 1
	jmp	.name_and_value_static
calign
.name_and_value_static_indexfound:
	; encode it prefix 0x80, prefix length 7
	hpack_write_integer r8d, 0x80, 7
	; skip to our next header
	jmp	.next
calign
.name_static_new_value:
	; determine the 1-based index, we know it is not our case 0 index
	cmp	rax, [rdx]
	je	.name_static_new_value_indexfound
	add	rdx, 32
	add	r8d, 1
	jmp	.name_static_new_value
calign
.name_static_new_value_indexfound:
	; if this is one of our never-index ones, our encoding must be different:
	mov	edx, [r15+8]
	cmp	rax, httpheaders$date
	je	.never_indexed
	cmp	rax, httpheaders$content_length
	je	.never_indexed
	cmp	rax, httpheaders$etag
	je	.never_indexed
	add	edx, 32
	cmp	rax, httpheaders$last_modified
	je	.never_indexed
	cmp	rax, httpheaders$if_none_match
	je	.never_indexed
	cmp	rax, httpheaders$if_modified_since
	je	.never_indexed
	cmp	rax, httpheaders$content_range
	je	.never_indexed
	cmp	rax, httpheaders$range
	je	.never_indexed
	; otherwise, encode it with an 0x40
	; if our new value for some reason ends up >4096, skip dtable update
	cmp	edx, 4096
	ja	.never_indexed
	; TODO: encode a 0 window update if this condition happens instead of writing the literal
	;    in practice this doesn't happen very often/if ever, so the way we have it now is still sane
	cmp	dword [rbx+httpheaders_dcount_ofs], 40
	jae	.never_indexed
	hpack_write_integer r8d, 0x40, 6
	; weed our dtable with our new size
	mov	edx, [r15+8]
	add	edx, [r15+24]
	add	edx, 32
	hpack_dtable_ceiling edx
	; and our value string itself
	mov	rdi, [r15+16]
	mov	rsi, [r15+24]
	call	.writestorestring	; this will puke if our scratch area was exceeded
	; that returned us with the goods we need in xmm7
	movdqu	xmm6, [r15]		; name_static values are okay
	; make room in our dtable
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	mov	edx, [rbx+httpheaders_dcount_ofs]
	lea	rdi, [rcx+32]
	mov	rsi, rcx
	shl	edx, 5
	call	memmove
	; now we place our xmm6, xmm7 at our 0 index
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	add	dword [rbx+httpheaders_dcount_ofs], 1
	movdqu	[rcx], xmm6
	movdqu	[rcx+16], xmm7
	jmp	.next
calign
.never_indexed:
	; name is one of our statics, but we do NOT want a dynamic table entry for it
	; NOTE: our name here is confusing, because we are doing 6.2.2 without indexing,
	; not the ACTUAL 6.2.3 Never Indexed integer preface
	hpack_write_integer r8d, 0x0, 4
	mov	rdi, [r15+16]
	mov	rsi, [r15+24]
	call	.writestorestring	; this will puke if our scratch area was exceeded
	jmp	.next
calign
.name_not_static:
	; name is not in our static list, which means it is also not one of our reserved ones
	; see if we have an exact match of both name _and_ value in our dtable, if we hit
	; one that name matches, store it so that we can skip writing the name twice if we
	; have a name but different value
	; if we have NO dynamic table entries, new name and new value
	test	r9d, r9d
	jz	.name_not_static_new_both
	; otherwise, commence search for name first
	push	rbx r12 r13 r14
	push	qword 0			
	mov	rbx, [rbx+httpheaders_dtable_ofs]
	mov	r12d, r9d
	mov	r13d, 62		; this is our match index if we find it
	; name is at [r15], value is at [r15+16], store our name length
	mov	r14d, [r15+8]
calign
.name_not_static_search:
	; since these can never be pointer-matched, we must do actual memcmps of the goods
	cmp	r14d, [rbx+8]
	je	.name_not_static_search_lengthmatch
	; otherwise, length of the name does not match, next
	add	rbx, 32
	add	r13d, 1
	sub	r12d, 1
	jnz	.name_not_static_search
	; if we made it to here, we got all the way through our list, new both
	pop	r8 r14 r13 r12 rbx
	; if rax is nonzero, it means we had a previous match for the name
	test	r8, r8
	jnz	.name_not_static_new_value_doit
	jmp	.name_not_static_new_both
calign
.name_not_static_search_lengthmatch:
	mov	rdi, [rbx]
	mov	rsi, [r15]
	mov	edx, r14d
	call	memcmp
	test	eax, eax
	jz	.name_not_static_search_namematch
	; otherwise, go to the next one, names !=
	add	rbx, 32
	add	r13d, 1
	sub	r12d, 1
	jnz	.name_not_static_search
	; if we made it to here, we got all the way through our list, new both
	pop	r8 r14 r13 r12 rbx
	; if rax is nonzero, it means we had a previous match for the name
	test	r8, r8
	jnz	.name_not_static_new_value_doit
	jmp	.name_not_static_new_both
calign
.name_not_static_search_namematch:
	; so the names at our current index match, see if we have an exact value match
	mov	edx, [r15+24]
	cmp	edx, [rbx+24]
	jne	.name_not_static_new_value
	mov	rdi, [rbx+16]
	mov	rsi, [r15+16]
	call	memcmp
	test	eax, eax
	jnz	.name_not_static_new_value
	; otherwise, we have an exact name and value match, store the index at r13d
	; and be done
	mov	r8d, r13d
	pop	rax r14 r13 r12 rbx
	hpack_write_integer r8d, 0x80, 7
	jmp	.next
calign
.name_not_static_new_value:
	; in the event that we have multiple dynamic table entries with the same name
	; but different values, we need to continue to iterate
	; the pointer at [rsp] == our index, but only if it wasn't already set
	mov	rax, [rsp]
	test	rax, rax
	jnz	.name_not_static_new_value_notfirst
	; otherwise, this is the first name match, but the value didn't match
	; so we need to set xmm6 to the first 16 bytes of [rbx]
	movdqu	xmm6, [rbx]
	; and store the index
	mov	[rsp], r13
.name_not_static_new_value_notfirst:
	; keep going
	add	rbx, 32
	add	r13d, 1
	sub	r12d, 1
	jnz	.name_not_static_search
	; if we made it to here, we _know_ we had a name match, the first of which
	; we stored at [rsp], and xmm6 is already set to the first name value goods
	pop	r8 r14 r13 r12 rbx
.name_not_static_new_value_doit:
	; if our new length is >4096, we want it literal without dynamic table updated
	mov	edx, [r15+8]
	add	edx, [r15+24]
	add	edx, 32
	cmp	edx, 4096
	ja	.name_not_static_new_value_nodtable
	; TODO: encode a 0 window update if this condition happens instead of writing the literal
	;    in practice this doesn't happen very often/if ever, so the way we have it now is still sane
	cmp	dword [rbx+httpheaders_dcount_ofs], 40
	jae	.name_not_static_new_value_nodtable
	hpack_write_integer r8d, 0x40, 6
	mov	rdi, [r15+16]
	mov	rsi, [r15+24]
	call	.writestorestring
	; weed our dtable with our new size
	mov	edx, [r15+8]
	add	edx, [r15+24]
	add	edx, 32
	hpack_dtable_ceiling edx
	; that returns us with the goods we need in xmm7, and xmm6 is still set from before
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	mov	edx, [rbx+httpheaders_dcount_ofs]
	lea	rdi, [rcx+32]
	mov	rsi, rcx
	shl	edx, 5
	call	memmove
	; now we place our xmm6, xmm7 at our 0 index
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	add	dword [rbx+httpheaders_dcount_ofs], 1
	movdqu	[rcx], xmm6
	movdqu	[rcx+16], xmm7
	jmp	.next
calign
.name_not_static_new_value_nodtable:
	hpack_write_integer r8d, 0x0, 4
	mov	rdi, [r15+16]
	mov	rsi, [r15+24]
	call	.writestorestring
	jmp	.next
calign
.name_not_static_new_both_nodtable:
	; we need to add a zero byte
	hpack_write_integer 0, 0x0, 4
	mov	rdi, [r15]
	mov	rsi, [r15+8]
	call	.writestorestring
	mov	rdi, [r15+16]
	mov	rsi, [r15+24]
	call	.writestorestring
	jmp	.next
calign
.name_not_static_new_both:
	; we had no dynamic table, so we have to encode both with incremental indexing, but only if the new size
	; is <= 4096
	mov	edx, [r15+8]
	add	edx, [r15+24]
	add	edx, 32
	cmp	edx, 4096
	ja	.name_not_static_new_both_nodtable
	; if our dcount == 40, don't do an update of our dtable either
	; TODO: encode a 0 window update if this condition happens instead of writing the literal
	;    in practice this doesn't happen very often/if ever, so the way we have it now is still sane
	cmp	dword [rbx+httpheaders_dcount_ofs], 40
	jae	.name_not_static_new_both_nodtable
	hpack_write_integer 0, 0x40, 6
	; weed our dtable if we need to
	mov	edx, [r15+8]
	add	edx, [r15+24]
	add	edx, 32
	hpack_dtable_ceiling edx
	mov	rdi, [r15]
	mov	rsi, [r15+8]
	call	.writestorestring	; this will puke if our scratch area was exceeded
	; that returned us with the goods we need in xmm7, move to xmm6
	movaps	xmm6, xmm7
	mov	rdi, [r15+16]
	mov	rsi, [r15+24]
	call	.writestorestring	; this will puke if our scratch area was exceeded
	; that returned us with the goods we need in xmm7
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	mov	edx, [rbx+httpheaders_dcount_ofs]
	lea	rdi, [rcx+32]
	mov	rsi, rcx
	shl	edx, 5
	call	memmove
	; now we place our xmm6, xmm7 at our 0 index
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	add	dword [rbx+httpheaders_dcount_ofs], 1
	movdqu	[rcx], xmm6
	movdqu	[rcx+16], xmm7
	; fallthrough to next
calign
.next:
	add	r15, 32
	sub	r14d, 1
	jnz	.top
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.nothingtodo:
	mov	eax, 1
	epilog
calign
.writestorestring_fail:
	add	rsp, 8		; unwind the callframe stack
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.writestorestring:
	; rdi == ptr to the value we are storing, esi == length of same
	; we have to return a 16 byte block of the goods in xmm7
	; rbx is our httpheaders object
	; we must fail if our scratch area is exceeded (and return false in eax)

	; if our length is zero, we also fail
	test	esi, esi
	jz	.writestorestring_fail
	
	; we do _not_ store huffman encoded strings in our scratch area
	; when we write the output side, we'll attempt to huffman encode it
	; but if the size ends up bigger (unlikely), we'll revert to plain
	; literal encoding
	; so first up, deal with our scratch area and populate xmm7
	lea	rdx, [rbx+(httpheaders_size - httpheaders_scratchint_ofs)]
	mov	r9, [rbx+httpheaders_endptr_ofs]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	push	rsi rdi
	test	r10, r10
	jnz	.writestorestring_scratch
	sub	rdx, r9
	cmp	edx, esi
	jb	.writestorestring_newscratch
	; otherwise, there is room
	; r9 is the write destination, rdi == source, esi == length we are adding to it
	add	[rbx+httpheaders_endptr_ofs], rsi	; move the endptr forward
	mov	edx, esi
	mov	rsi, rdi
	mov	rdi, r9
	; store r9 in place on our stack
	mov	[rsp], r9
	call	memcpy
	; move the 16 bytes on the stack to xmm7
	movdqu	xmm7, [rsp]
.writestorestring_encode:
	; now that the string has been copied to our scratch, next up is to write it
	; to our destination buffer in r12, possibly huffman encoded
	mov	rdi, r12
	mov	rsi, [rsp+8]				; the maximum length of the output
	add	rsi, 8					; + room for the integer preface
	call	buffer$reserve
	; so now we know there is enough room to hold our string in the destination buffer
	; we have two choices here: 1) hope for the best encoding possible being <128 bytes
	; which in most cases _will_ be enough, or 2) prescan the string and get our length
	; beforehand so that we don't have to do a memmove of our encoding when it
	; moves length
	; thoughts here on this: prescan is simpler logic, but it means we have to pass
	; over the source string twice, versus a single pass over it once, with possibly
	; multiple memmoves to accommodate the length prefix. I think prescan seems like
	; a better choice here... TODO: someday when I am bored, write this both ways and 
	; compare performance
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	xor	ecx, ecx				; the length in bits of the huffman encoded goods
calign
.writestorestring_prescan:
	movzx	eax, byte [rsi]
	movzx	r8d, byte [eax+httpheaders$huffyL]
	add	ecx, r8d
	add	rsi, 1
	sub	edx, 1
	jnz	.writestorestring_prescan
	; so now, we have the total bitcount sitting in ecx, round that up to the nearest byte boundary
	add	ecx, 7
	and	ecx, not 7
	; and turn that into bytes and compare to our original length
	shr	ecx, 3
	cmp	ecx, [rsp+8]				; the length of the original
	jae	.writestorestring_encodeasis
	; otherwise, the huffman encoded string is smaller than the source, which is kinda the point
	; so we can write the length we came up with first, and then make our second pass to encode
	hpack_write_integer ecx, 0x80, 7
	mov	rdi, [r12+buffer_endptr_ofs]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	xor	r8d, r8d	; buffer to hold the output
	xor	r9d, r9d	; bitcount of same
calign
.writestorestring_encodeloop:
	mov	ecx, 32
	movzx	eax, byte [rsi]
	movzx	r10d, byte [eax+httpheaders$huffyL]
	mov	r11d, [rax*4+httpheaders$huffyC]
	mov	eax, 64
	sub	ecx, r10d
	shr	r11d, cl
	mov	ecx, r10d
	sub	eax, r9d
	; make sure there is room in our 64 bit buffer to hold this one
	cmp	eax, r10d
	jb	.writestorestring_encode_write32
	; otherwise, there is room here
	shl	r8, cl
	or	r8, r11
	add	r9d, r10d
	; next:
	add	rsi, 1
	sub	edx, 1
	jnz	.writestorestring_encodeloop
	; if we made it to here, we are all done, but we still have to encode what is left in our 64 bit output buffer
.writestorestring_done:
	mov	rax, r8
	mov	ecx, r9d
	cmp	r9d, 32
	jb	.writestorestring_check16
	; otherwise, there is >= 32 bits sitting here, write a dword
	sub	ecx, 32
	shr	rax, cl
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	add	qword [r12+buffer_endptr_ofs], 4
	add	qword [r12+buffer_length_ofs], 4
	sub	r9d, 32
	mov	rax, r8
	mov	ecx, r9d
.writestorestring_check16:
	cmp	r9d, 16
	jb	.writestorestring_check8
	; otherwise, there is >= 16 bits sitting here, write a word
	sub	ecx, 16
	shr	rax, cl
if use_movbe
	movbe	[rdi], ax
else
	xchg	ah, al
	mov	[rdi], ax
end if
	add	rdi, 2
	add	qword [r12+buffer_endptr_ofs], 2
	add	qword [r12+buffer_length_ofs], 2
	sub	r9d, 16
	mov	rax, r8
	mov	ecx, r9d
.writestorestring_check8:
	cmp	r9d, 8
	jb	.writestorestring_checklast
	; otherwise, there is >= 8 bits sitting here, write a byte
	sub	ecx, 8
	shr	rax, cl
	mov	[rdi], al
	add	rdi, 1
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
	sub	r9d, 8
	mov	rax, r8
	mov	ecx, r9d
.writestorestring_checklast:
	mov 	ecx, 8
	test	r9d, r9d
	jz	.writestorestring_alldone
	mov	edx, 0xff
	; add byte-boundary shifted, padded with 1s
	sub	ecx, r9d
	shl	eax, cl
	mov	ecx, r9d
	shr	edx, cl
	or	eax, edx
	mov	[rdi], al
	add	qword [r12+buffer_endptr_ofs], 1
	add	qword [r12+buffer_length_ofs], 1
.writestorestring_alldone:
	add	rsp, 16
	; done, dusted.
	ret
calign
.writestorestring_encode_write32:
	; not enough room in our 64bit buffer to hold the new code, dump the high 32 bits
	mov	rax, r8
	mov	ecx, r9d
	sub	ecx, 32
	shr	rax, cl
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	add	qword [r12+buffer_endptr_ofs], 4
	add	qword [r12+buffer_length_ofs], 4
	sub	r9d, 32
	; we can jump straight back to the encodeloop, and let it redo placement
	jmp	.writestorestring_encodeloop
calign
.writestorestring_encodeasis:
	; so the huffman encoded length was >= the length of the source string
	; length prefix it, and write it directly to the buffer
	mov	r8d, [rsp+8]
	hpack_write_integer r8d, 0x0, 7
	; we know there is enough room for our string directly in the buffer
	mov	rdi, [r12+buffer_endptr_ofs]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	add	[r12+buffer_endptr_ofs], rdx
	add	[r12+buffer_length_ofs], rdx
	add	rsp, 16
	call	memcpy
	; done, dusted.
	ret
calign
.writestorestring_scratch:
	; scratch buffer already exists, make sure there is room
	mov	rcx, [r10+buffer_size_ofs]
	sub	rcx, [r10+buffer_length_ofs]
	cmp	ecx, esi
	jb	.writestorestring_kakked
	; otherwise, we can add it directly to the buffer
.writestorestring_scratch_doit:
	mov	edx, esi
	mov	rsi, rdi
	mov	rdi, [r10+buffer_endptr_ofs]
	add	[r10+buffer_endptr_ofs], rdx
	add	[r10+buffer_length_ofs], rdx
	; store rdi in place on our stack
	mov	[rsp], rdi
	call	memcpy
	; move the 16 bytes on the stack to xmm7
	movdqu	xmm7, [rsp]
	jmp	.writestorestring_encode
calign
.writestorestring_newscratch:
	cmp	esi, 65536
	ja	.writestorestring_kakked
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	jmp	.writestorestring_scratch_doit
calign
.writestorestring_kakked:
	; undo our 16 byte stack vars + the calling stack return
	add	rsp, 24		
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
	
	

end if


if used httpheaders$parse_http2 | defined include_everything
	; three arguments: rdi == our httpheaders object, rsi == ptr to data, rdx == length of same (must be a complete HEADERS block)
	; returns a bool in eax as to whehter we succeeded or not (failure == hpack/encoding/etc error)
falign
httpheaders$parse_http2:
	prolog	httpheaders$parse_http2
	test	rdx, rdx
	jz	.fail

macro hpack_read_integer prefix*, errstack* {
	local .e
	; we smash: eax, ecx, edx, r8d, and assume r12 is our source bytes and r13d is its length
	; returns eax for the value, or jumps to .decode_error on failure
	; despite the hpack spec allowing for infinite sized integers here, nothing in here should use anything more than 32 bits
	; so we don't bother with a loop
	movzx	eax, byte [r12]
	add	r12, 1
	and	eax, (1 shl prefix) - 1
	cmp	eax, (1 shl prefix) - 1
	jne	.e
	sub	r13d, 1
if errstack
	jz	.decode_error_stacked
else
	jz	.decode_error
end if
	movzx	edx, byte [r12]
	mov	eax, (1 shl prefix) - 1
	mov	ecx, 7
	mov	r8d, edx
	add	r12, 1
	and	edx, 0x7f
	add	eax, edx
	test	r8d, 0x80
	jz	.e
	sub	r13d, 1
if errstack
	jz	.decode_error_stacked
else
	jz	.decode_error
end if
	movzx	edx, byte [r12]
	mov	r8d, edx
	add	r12, 1
	and	edx, 0x7f
	shl	edx, cl
	add	ecx, 7
	add	eax, edx
	test	r8d, 0x80
	jz	.e
	sub	r13d, 1
if errstack
	jz	.decode_error_stacked
else
	jz	.decode_error
end if
	movzx	edx, byte [r12]
	mov	r8d, edx
	add	r12, 1
	and	edx, 0x7f
	shl	edx, cl
	add	ecx, 7
	add	eax, edx
	test	r8d, 0x80
	jz	.e
	sub	r13d, 1
if errstack
	jz	.decode_error_stacked
else
	jz	.decode_error
end if
	movzx	edx, byte [r12]
	mov	r8d, edx
	add	r12, 1
	and	edx, 0x7f
	shl	edx, cl
	add	eax, edx
	test	r8d, 0x80
if errstack
	jnz	.decode_error_stacked
else
	jnz	.decode_error
end if
.e:
	sub	r13d, 1
}

	; these Huffman decoder bits are hand-compiled and reworked versions of a much slower C implementation
	; forgive the scarcity of comments, haha

macro huffy_decode {
	; on entry, rdi == our destination pointer, r12 == source pointer, eax == how many bytes we are parsing which is known non-zero
	; this leaves rdi, r10, rax, r12, r13 alone, sets ecx to the number of bytes placed at rdi
	; smashes everything else (including r14, r15 which must be free for us to use)
	local	.t, .t_proceed, .err, .e, .drain, .maybedone
	push	rax r10 r12 r13 rbp
	mov	rsi, r12		; our source pointer
	mov	edx, eax		; how many bytes we are parsing, which is known nonzero
	xor	ebp, ebp		; how many bytes we decoded
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
calign
.t:
	lea	eax, [r8d+r10d]
	lea	ecx, [r8d+r10d]
	xor	r11d, r11d
	mov	r12d, 32

	mov	r13d, 8
	cmp	r10d, 32
	jae	.t_proceed
	shr	eax, 3

	and	ecx, 7
	cmp	eax, edx
	jae	.t_proceed
	sub	r12d, r10d
	sub	r13d, ecx
	add	ecx, 24
	cmp	r12d, r13d
	cmova	r12d, r13d
	
	movzx	r13d, byte [rsi+rax]
	shl	r13d, cl
	mov	ecx, r10d
	mov	r11d, 1
	shr	r13d, cl
	or	r9d, r13d
	add	r10d, r12d
.t_proceed:

	mov	r13d, r9d
	mov	r14, httpheaders$huffyT
	shr	r13d, 23

	repeat 4
	movzx	eax, word [r14+2]
	add	eax, r13d
	movzx	eax, byte [rax*4+httpheaders$huffyE]
	lea	r14, [rax*4+httpheaders$huffyT]
	mov	r13d, r9d
	movzx	ecx, byte [r14]
	shl	r13d, cl
	mov	ecx, 32
	sub	cl, [r14+1]
	shr	r13d, cl
	end repeat
	; yuck this is a horrible dependency chain, TODO: someday when I am bored, redo this
	movzx	eax, word [r14+2]
	add	eax, r13d
	lea	r12d, [ebp+1]
	lea	r15, [rax*4+httpheaders$huffyE]
	movzx	ecx, byte [r15+1]
	movzx	eax, word [r15+2]
	test	ecx, ecx
	jz	.err
	cmp	ecx, r10d
	ja	.maybedone
	mov	[rdi+rbp], al
	test	eax, 256
	cmovz	ebp, r12d

	lea	eax, [r8d+ecx]
	add	r8d, ecx
	shr	eax, 3
	and	r8d, 7
	add	rsi, rax
	sub	edx, eax
	shl	r9d, cl
	sub	r10d, ecx
	jmp	.t
.drain:
	mov	ecx, 8
	sub	ecx, r8d
	lea	eax, [r8d+ecx]
	add	r8d, ecx
	shr	eax, 3
	and	r8d, 7
	add	rsi, rax
	sub	edx, eax
	jz	.e
	; fallthrough to .err
.err:
	pop	rbp r13 r12 r10 rax
	jmp	.decode_error
.maybedone:
	test	r11d, r11d
	jnz	.t
	test	r8d, r8d
	jnz	.drain
	test	edx, edx
	jnz	.err
.e:
	mov	ecx, ebp
	pop	rbp r13 r12 r10 rax
}




	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
calign
.outer:
	cmp	dword [rbx+httpheaders_hcount_ofs], 22
	ja	.decode_error
	movzx	eax, byte [r12]
	test	eax, 0x80
	jnz	.indexed
	test	eax, 0x40
	jnz	.literal
	test	eax, 0xe0
	jnz	.sizeupdate
	; lit w/o Indexing
	test	eax, 0xf
	jz	.literal_noindex_withname
	; otherwise, indexed name, then value
	hpack_read_integer 4, 0
	test	eax, eax
	jz	.decode_error
	; load up xmm0 with the index
	cmp	eax, 61
	ja	.literal_noindex_dyntable
	shl	eax, 5
	; otherwise, load up the name 16 bytes from the static table
	movaps	xmm0, [rax+httpheaders$static]
	; now we have to load and _store_ the value string in our scratch area
	call	.readstorestring
	; rax == pointer to it, edx == length of same, xmm0 still good
	; we have to add this as a dtable entry, even though the name was indexed
	; _and_ add it as an htable entry
	push	rdx rax
	movdqu	xmm1, [rsp]
	add	rsp, 16
.noindex_doit:
	; xmm0 and xmm1 are both setup, all we need to do is add to the htable and continue
	mov	ecx, [rbx+httpheaders_hcount_ofs]
	lea	rdx, [rbx+httpheaders_htable_ofs]
	shl	ecx, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	movdqu	[rdx+rcx], xmm0
	movdqu	[rdx+rcx+16], xmm1
	test	r13d, r13d
	jnz	.outer
	; otherwise, all good/done
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.literal_noindex_dyntable:
	sub	eax, 62
	cmp	eax, [rbx+httpheaders_dcount_ofs]
	jae	.decode_error
	; otherwise, the 16 bytes from the dyntable at index eax get loaded up into xmm0
	shl	eax, 5
	mov	r8, [rbx+httpheaders_dtable_ofs]
	movdqu	xmm0, [r8+rax]
	; now we have to load and _store_ the value string in our scratch area
	call	.readstorestring
	; rax == pointer to it, edx == length of same
	push	rdx rax
	movdqu	xmm1, [rsp]
	add	rsp, 16
	jmp	.noindex_doit
calign
.literal_noindex_withname:
	add	r12, 1
	sub	r13d, 1
	jz	.decode_error
	call	.readstorestring
	; rax == pointer to it, edx == length of same
	; save those so we can call it again
	push	rdx rax
	movdqu	xmm0, [rsp]
	add	rsp, 16
	call	.readstorestring
	push	rdx rax
	movdqu	xmm1, [rsp]
	add	rsp, 16
	jmp	.noindex_doit
calign
.indexed:
	hpack_read_integer 7, 0
	; spec says: index value 0 == error (and we don't want that anyway since we _use_ index 0 elsewhere for HTTP/1)
	test	eax, eax
	jz	.decode_error
	; if the index is less than 62, then it points into our static table, and the VALUE does as well
	; if it is >=62, then it comes from the dynamic table, if the index runs past the end (dcount), then puke
	cmp	eax, 61
	ja	.indexed_dyntable
	shl	eax, 5
	; otherwise, the 32 bytes from the static table get added as an htable entry
	mov	ecx, [rbx+httpheaders_hcount_ofs]
	lea	rdx, [rbx+httpheaders_htable_ofs]
	shl	ecx, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	movaps	xmm0, [rax+httpheaders$static]
	movaps	xmm1, [rax+httpheaders$static+16]
	movdqu	[rdx+rcx], xmm0
	movdqu	[rdx+rcx+16], xmm1
	test	r13d, r13d
	jnz	.outer
	; otherwise, all good
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.indexed_dyntable:
	sub	eax, 62
	cmp	eax, [rbx+httpheaders_dcount_ofs]
	jae	.decode_error
	; otherwise, the 32 bytes from the dynamic table at index eax get added as an htable entry
	shl	eax, 5
	mov	r8, [rbx+httpheaders_dtable_ofs]
	mov	ecx, [rbx+httpheaders_hcount_ofs]
	lea	rdx, [rbx+httpheaders_htable_ofs]
	shl	ecx, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	movdqu	xmm0, [r8+rax]
	movdqu	xmm1, [r8+rax+16]
	movdqu	[rdx+rcx], xmm0
	movdqu	[rdx+rcx+16], xmm1
	test	r13d, r13d
	jnz	.outer
	; otherwise, all good
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
	
calign
.literal:
	mov	ecx, [rbx+httpheaders_dcount_ofs]
	cmp	ecx, [rbx+httpheaders_dlimit_ofs]
	jae	.decode_error
	; regardless of how the name is handled here, these get added into our dtable
	; spec says: prefix == 0 == literal string for the name, otherwise, it is an index for the name
	cmp	eax, 0x40
	je	.literal_withname
	; otherwise, our name is indexed, followed by our literal value length
	; name can come from either table just like the pure indexed version
	hpack_read_integer 6, 0
	; index zero is an error here just the same as pure indexed
	test	eax, eax
	jz	.decode_error
	; if the index is less than 62, then it points into our static table
	; if it is >= 62, then it comes from the dyntable
	cmp	eax, 61
	ja	.literal_dyntable
	shl	eax, 5
	; otherwise, load up the name 16 bytes from the static table
	movaps	xmm0, [rax+httpheaders$static]
	; now we have to load and _store_ the value string in our scratch area
	call	.readstorestring
	; rax == pointer to it, edx == length of same, xmm0 still good
	; we have to add this as a dtable entry, even though the name was indexed
	; _and_ add it as an htable entry
	push	rdx rax
	movdqu	xmm1, [rsp]
	add	rsp, 16
.literal_doit:
	; so now, add it as both a new dtable entry _and_ a new htable entry
	; htable first
	; spec says new dynamic table entries get added at the head, not the tail like we do elsewhere
	; so we can add it to the htable first, then make sure there is room in our dynamic table
	mov	ecx, [rbx+httpheaders_hcount_ofs]
	lea	rdx, [rbx+httpheaders_htable_ofs]
	shl	ecx, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	movdqu	[rdx+rcx], xmm0
	movdqu	[rdx+rcx+16], xmm1
	; now load the size for hpack_dtable_ceiling
	mov	r10, [rdx+rcx+8]
	add	r10, [rdx+rcx+24]
	add	r10d, 32
	hpack_dtable_ceiling r10d
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	mov	edx, [rbx+httpheaders_dcount_ofs]
	; save xmm0 and xmm1 both to a spot we know won't be affected by memcpy or memmove
	movaps	xmm6, xmm0
	movaps	xmm7, xmm1
	lea	rdi, [rcx+32]
	mov	rsi, rcx
	shl	edx, 5
	call	memmove
	; now we place our xmm6, xmm7 at our 0 index
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	add	dword [rbx+httpheaders_dcount_ofs], 1
	movdqu	[rcx], xmm6
	movdqu	[rcx+16], xmm7
	; done, proceed with next or bailout
	test	r13d, r13d
	jnz	.outer
	; otherwise, all good/done
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog

calign
.literal_dyntable:
	sub	eax, 62
	cmp	eax, [rbx+httpheaders_dcount_ofs]
	jae	.decode_error
	; otherwise, the 16 bytes from the dyntable at index eax get loaded up into xmm0
	shl	eax, 5
	mov	r8, [rbx+httpheaders_dtable_ofs]
	movdqu	xmm0, [r8+rax]
	; now we have to load and _store_ the value string in our scratch area
	call	.readstorestring
	; rax == pointer to it, edx == length of same
	push	rdx rax
	movdqu	xmm1, [rsp]
	add	rsp, 16
	jmp	.literal_doit

calign
.literal_withname:
	; no index, so the name we are sitting on is an encoded string, which we need to load and _store_
	; into our scratch area
	add	r12, 1
	sub	r13d, 1
	jz	.decode_error
	call	.readstorestring
	; rax == pointer to it, edx == length of same
	; save those so we can call it again
	push	rdx rax
	movdqu	xmm0, [rsp]
	add	rsp, 16
	call	.readstorestring
	push	rdx rax
	movdqu	xmm1, [rsp]
	add	rsp, 16
	; the spec says that the name _can_ be represented by an index that is already there, but doesn't NEED to be
	; in our case, the distinction doesn't really matter, because we are adding it to the dynamic table anyway
	jmp	.literal_doit

falign
.readstorestring:
	; this is called as a function from various points above

	; every encoded string that we get during the decode process ultimately needs to be stored in the scratch area
	; of our httpheaders object, so we decode the string, store it where it goes into the scratch area, and
	; set rax == the ptr to the string itself (where it lives in the scratch area), and edx set to its length
	; any errors and we jump straight to .decode_error
	lea	rdi, [rbx+(httpheaders_size - httpheaders_scratchint_ofs)]
	mov	r9, [rbx+httpheaders_endptr_ofs]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	test	byte [r12], 0x80
	jnz	.readstorestring_huffy
	hpack_read_integer 7, 1
	cmp	eax, r13d
	ja	.decode_error_stacked
	; we don't do zero length HTTP header names or values
	test	eax, eax
	jz	.decode_error_stacked
	; otherwise, r12 for eax bytes == our unmolested value
	test	r10, r10
	jnz	.readstorestring_scratch
	; make sure there is room in our scratch area
	sub	rdi, r9
	cmp	edi, eax
	jb	.readstorestring_newscratch
	; otherwise, there is room
	mov	rdi, r9		; our final return value
	mov	rsi, r12
	mov	edx, eax	; our final return length
	add	[rbx+httpheaders_endptr_ofs], rax
	add	r12, rax
	sub	r13d, eax
	push	r9 rax
	call	memcpy
	pop	rdx rax
	; rax == our stored local version of the string, edx == length of same
	ret
.readstorestring_scratch:
	; there is already a scratch buffer present, so we need to add it to there
	; we cannot exceed our fixed buffer size
	mov	rcx, [r10+buffer_size_ofs]
	sub	rcx, [r10+buffer_length_ofs]
	cmp	ecx, eax
	jb	.decode_error_stacked	; not enough room
	; otherwise, we can add it directly to the buffer
	mov	rdi, [r10+buffer_endptr_ofs]	; our final return value
	mov	rsi, r12
	mov	edx, eax
	add	[r10+buffer_endptr_ofs], rax
	add	[r10+buffer_length_ofs], rax
	add	r12, rax
	sub	r13d, eax
	push	rdi rax
	call	memcpy
	pop	rdx rax
	; rax == our stored local version of the string, edx == length of same
	ret
.readstorestring_newscratch:
	; not enough room in our scratch area, so create a 64k buffer
	cmp	eax, 65536
	ja	.decode_error_stacked
	push	rax				; save the number of bytes we are doing
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	pop	rdx
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r12
	mov	rdi, [r10+buffer_endptr_ofs]
	add	[r10+buffer_endptr_ofs], rdx
	add	[r10+buffer_length_ofs], rdx
	add	r12, rdx
	sub	r13d, edx
	push	rdi rdx
	call	memcpy
	pop	rdx rax
	; rax == our stored local version of the string, edx == length of same
	ret
.readstorestring_huffy:
	hpack_read_integer 7, 1
	cmp	eax, r13d
	ja	.decode_error_stacked
	; we don't do zero length HTTP header names or values
	test	eax, eax
	jz	.decode_error_stacked
	; otherwise, r12 for eax bytes is our Huffman encoded string literal
	; we are being lazy here for our space reserve requirements
	; and requiring it to be x2, despite the smallest code lenght of 5 bits
	; is actually equal to a maximum ratio of 0.625, or 1.6X what we got in
	; the encoded string, not 2X.
	lea	ecx, [eax*2]
	test	r10, r10
	jnz	.readstorestring_huffy_scratch
	; make sure there is room in our scratch area
	sub	rdi, r9
	cmp	edi, ecx
	jb	.readstorestring_huffy_newscratch
	; otherwise, there is room
	mov	rdi, r9			; this is where huffy_decode will put the goods, it will preserve it
	huffy_decode
	; that leaves eax alone (which was our original encoded length)
	; and sets ecx == the actual number of bytes it put at rdi
	add	r12, rax
	sub	r13d, eax
	add	[rbx+httpheaders_endptr_ofs], rcx
	mov	rax, rdi		; final return
	mov	edx, ecx		; length of same
	; rax == our stored local version of the string, edx == length of same
	ret
.readstorestring_huffy_scratch:
	mov	rdx, [r10+buffer_size_ofs]
	sub	rdx, [r10+buffer_length_ofs]
	cmp	edx, ecx
	jb	.decode_error_stacked		; not enough room to do the deed
	; otherwise, we can add it directly to the buffer
	mov	rdi, [r10+buffer_endptr_ofs]	; this is where huffy_decode will put the goods, it will preserve it
	huffy_decode
	; that leaves eax alone (which was our original encoded length)
	; and sets ecx == the actual number of bytes it put at rdi
	add	r12, rax
	sub	r13d, eax
	; huffy_decode also left r10 alone for us
	add	[r10+buffer_endptr_ofs], rcx
	add	[r10+buffer_length_ofs], rcx
	mov	rax, rdi		; final return
	mov	edx, ecx		; length of same
	; rax == our stored local version of the string, edx == length of same
	ret
.readstorestring_huffy_newscratch:
	cmp	ecx, 65536
	ja	.decode_error_stacked
	push	rax rcx
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	r10, [rbx+httpheaders_scratch_ofs]
	pop	rcx rax
	mov	rdi, [r10+buffer_endptr_ofs]	; this is where huffy_decode will put the goods, it will preserve it
	huffy_decode
	; that leaves eax alone (which was our original encoded length)
	; and sets ecx == the actual number of bytes it put at rdi
	add	r12, rax
	sub	r13d, eax
	; huffy_decode also left r10 alone for us
	add	[r10+buffer_endptr_ofs], rcx
	add	[r10+buffer_length_ofs], rcx
	mov	rax, rdi		; final return
	mov	edx, ecx		; length of same
	; rax == our stored local version of the string, edx == length of same
	ret



calign
.sizeupdate:
	; 6.3 Dynamic Table Size Update
	hpack_read_integer 5, 0
	; so the spec says this value must be less than or equal to the last value of the _maximum_ capacity as set by SETTINGS_HEADER_TABLE_SIZE
	; but we don't really care so long as it doesn't exceed our own _actual_ capacity, and our not following that rule doesn't cause any issues
	cmp	eax, 65536
	ja	.decode_error
	; zero is an acceptable value, which causes us to completely destroy the dynamic table
	mov	[rbx+httpheaders_tablesize_ofs], eax
	hpack_dtable_ceiling 0
	test	r13d, r13d
	jnz	.outer
	; otherwise, all good/done
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.decode_error:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.decode_error_stacked:
	; so, this means that the decode error occurred from within our nested function call to
	; .readstorestring, and as a result, our stack is maligned by 8
	add	rsp, 8
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.fail:
	xor	eax, eax
	epilog

end if


if used httpheaders$parse_http1 | defined include_everything
	; three arguments: rdi == our httpheaders object, rsi == ptr to data, rdx == length of same
	; does NOT assume that a complete header is here
	; if this succeeds, returns the header length (including separator), else returns 0 in rax
	; on error (something nasty/invalid), will return -1 in rax (note that running into EOF w/0 a complete header returns 0)
falign
httpheaders$parse_http1:
	prolog	httpheaders$parse_http1
	cmp	rdx, 1 shl 30
	ja	.biggun
	cmp	edx, 16			; our minimum valid header length
	jb	.needmore
	mov	rax, rsi
	mov	ecx, edx
calign
.findeoh:
	cmp	ecx, 4
	jb	.findeoh_lessthanfourleft
	mov	r8d, 4
	cmp	dword [rax], 0xa0d0a0d
	je	.foundeoh
	mov	r8d, 2
	cmp	word [rax], 0xa0a
	je	.foundeoh
	add	rax, 1
	sub	ecx, 1
	jnz	.findeoh
	; needmore fallthrough copy
	xor	eax, eax
	epilog
calign
.foundeoh:
	; r8d has the number of bytes that represented the terminator
	; if for some crazy reason rax == rsi, we have a nasty problem
	cmp	rax, rsi
	je	.foundeoh_kakked
	add	rax, r8
	; our preface line MUST exist, and must be one of:
	; GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
	; HTTP/1.
	; otherwise, kakked
	lea	rcx, [rsi+4]
	mov	edx, 2
	cmp	dword [rsi], 'GET '
	je	.request
	lea	rcx, [rsi+5]
	mov	edx, 3
	cmp	dword [rsi], 'POST'
	je	.request
	mov	rdx, rsi
	mov	r10d, 4
	cmp	dword [rsi], 'HEAD'
	je	.request
	cmp	dword [rsi], 'HTTP'
	je	.response
	lea	rcx, [rsi+8]
	mov	r10d, 7
	cmp	dword [rsi], 'CONN'
	je	.request
	lea	rcx, [rsi+4]
	mov	r10d, 3
	cmp	dword [rsi], 'PUT '
	je	.request
	lea	rcx, [rsi+7]
	mov	r10d, 6
	cmp	dword [rsi], 'DELE'
	je	.request
	lea	rcx, [rsi+8]
	mov	r10d, 7
	cmp	dword [rsi], 'OPTI'
	je	.request
	lea	rcx, [rsi+6]
	mov	r10d, 5
	cmp	dword [rsi], 'TRAC'
	je	.request
	; otherwise, no deal

	breakpoint
	; HEREHERE, we need to be able to parse CGI responses too, which is to say skip the preface parsing altogether and jump straight to header parsing

	mov	rax, -1
	epilog
calign
.request:
	; at this stage, rcx == start of path, rsi == method of course, rdx == rsi == new one, else index into common, r10d == length of method 
	; if the start of our path is <= 32, die
	cmp	byte [rcx], 32
	jbe	.foundeoh_kakked
	; walk forward til we find a space, CR, or LF
	mov	r11d, 1
	; if the start of our path != '*' and start of our path != '/', die
	cmp	byte [rcx], '*'
	je	.request_findeop
	cmp	byte [rcx], '/'
	jne	.foundeoh_kakked
calign
.request_findeop:
	cmp	byte [rcx+r11], 13
	je	.foundeoh_kakked
	cmp	byte [rcx+r11], 10
	je	.foundeoh_kakked
	cmp	byte [rcx+r11], 32
	je	.request_foundeop
	add	r11d, 1
	jmp	.request_findeop
calign
.response:
	; so, the preface line began with HTTP, and as such this is an HTTP response, get our :status pseudo header out
	; so we know [rsi] for 4 bytes is HTTP, we need to parse the version out from [rsi+7] and verify that [rsi+8] is a space
	xor	r9d, r9d
	mov	r10d, 1
	cmp	byte [rsi+7], '1'
	cmove	r9d, r10d
	cmp	byte [rsi+8], ' '
	jne	.foundeoh_kakked
	cmp	byte [rsi+9], '0'
	jb	.foundeoh_kakked
	cmp	byte [rsi+9], '9'
	ja	.foundeoh_kakked
	mov	dword [rdi+httpheaders_flags_ofs], r9d
	; set our hcount to 1, then parse out the status code
	mov	dword [rdi+httpheaders_hcount_ofs], 1
	mov	r9d, [rsi+8]
	mov	ecx, 256
	cmp	r9d, ' 200'
	je	.response_status_static
	add	ecx, 32
	cmp	r9d, ' 204'
	je	.response_status_static
	add	ecx, 32
	cmp	r9d, ' 206'
	je	.response_status_static
	add	ecx, 32
	cmp	r9d, ' 304'
	je	.response_status_static
	add	ecx, 32
	cmp	r9d, ' 400'
	je	.response_status_static
	add	ecx, 32
	cmp	r9d, ' 404'
	je	.response_status_static
	add	ecx, 32
	cmp	r9d, ' 500'
	je	.response_status_static
	shr	r9d, 8
	; otherwise, use the header name from the static table, and copy our 3 byte value
	mov	r10, [rdi+httpheaders_endptr_ofs]
	movaps	xmm0, [httpheaders$static+256]
	movdqu	[rdi+httpheaders_htable_ofs], xmm0
	mov	[rdi+httpheaders_htable_ofs+16], r10
	mov	qword [rdi+httpheaders_htable_ofs+24], 3
	mov	[r10], r9d
	lea	rcx, [rsi+9]
	jmp	.headers_proceed_eol
calign
.response_status_static:
	movaps	xmm0, [rcx+httpheaders$static]
	movaps	xmm1, [rcx+httpheaders$static+16]
	movdqu	[rdi+httpheaders_htable_ofs], xmm0
	movdqu	[rdi+httpheaders_htable_ofs+16], xmm1
	lea	rcx, [rsi+9]
	jmp	.headers_proceed_eol
calign
.request_foundeop:
	; so now r11 is the number of bytes in our path section, rcx is our path start
	; if rdx == rsi, then it isn't :method: {GET,POST}
	cmp	rdx, rsi
	je	.request_foundeop_fullmethod
	shl	edx, 5
	movaps	xmm0, [rdx+httpheaders$static]
	movaps	xmm1, [rdx+httpheaders$static+16]
	; so now that needs to go into our headerlist as-is
	movdqu	[rdi+httpheaders_htable_ofs], xmm0
	movdqu	[rdi+httpheaders_htable_ofs+16], xmm1
	mov	dword [rdi+httpheaders_hcount_ofs], 2
.request_dopath:
	; so our request method pseudo header is all set, next up is the path itself, which is sitting in rcx for r11 bytes
	; we forced above the path to begin with either a * or /
	cmp	r11d, 1
	je	.request_dopath_length_one
	; otherwise, if the length is /index.html (11), check that too
	cmp	r11d, 11
	je	.request_dopath_length_eleven
.request_dopath_normal:
	; first 16 bytes of our h entry is the header name and length, which we'll copy from our static table (:path)
	movaps	xmm0, [httpheaders$static+128]
	; the next 8 bytes is the pointer into our scratch area
	mov	r10, [rdi+httpheaders_endptr_ofs]
	; and the next 8 bytes is r11
	movdqu	[rdi+httpheaders_htable_ofs+32], xmm0
	mov	[rdi+httpheaders_htable_ofs+48], r10
	mov	[rdi+httpheaders_htable_ofs+56], r11
	; increment our endptr by r11 bytes
	add	[rdi+httpheaders_endptr_ofs], r11
	; now we need to copy what is at rcx for r11 bytes, 8 bytes at a time (it is okay to run past the end cuz our length is already set)
calign
.request_dopath_copy:
	mov	r9, [rcx]
	mov	[r10], r9
	cmp	r11d, 8
	jbe	.request_dopath_done
	add	rcx, 8
	add	r10, 8
	sub	r11d, 8
	jmp	.request_dopath_copy
dalign
.httpslashonedot db ' HTTP/1.'
.indexdoth db '/index.h'
calign
.request_dopath_done:
	; whatever is left in r11 we can add to rcx
	mov	r10, qword [.httpslashonedot]
	add	rcx, r11
	; so now, rcx is pointing to after the path, which we verified contains a space
	; verify that it contains HTTP/1. , or die
	cmp	r10, [rcx]
	jne	.foundeoh_kakked
	; the version number following we need to keep (so other layers can determine whether or not to treat it as HTTP/1.1 or HTTP/1.0)
	xor	r9d, r9d
	mov	r10d, 1
	cmp	byte [rcx+8], '1'
	cmove	r9d, r10d
	mov	dword [rdi+httpheaders_flags_ofs], r9d
	; so now our version is set, we can skip to the header parsing stage now
	; fallthrough to .headers_proceed_eol
calign
.headers_proceed_eol:
	; rcx is pointing to somewhere in the preface line, we need to walk it forward til we hit an LF
	cmp	byte [rcx], 10
	lea	rcx, [rcx+1]
	jne	.headers_proceed_eol
.headers_proceed:
	; rcx is pointing at the start of the first header line
	; our final return will be rax-rsi
	sub	rax, rsi
	; so, now we can proceed with "normal" header setting/acquisition
	push	rbx r12 r13 r14 r15 rax
	mov	rbx, rdi
	mov	r12, rcx
calign
.headers_loop:
	lea	r13, [r12+1]
	cmp	byte [r12], 13
	je	.headers_done
	cmp	byte [r12], 10
	je	.headers_done
	cmp	byte [r12], ':'
	je	.headers_kakked
calign
.headers_findseparator:
	mov	r14, r13
	cmp	byte [r13], ':'
	lea	r13, [r13+1]
	jne	.headers_findseparator
calign
.headers_swallow_whitespace:
	mov	r15, r13
	cmp	byte [r13], 13
	je	.headers_kakked
	cmp	byte [r13], 10
	je	.headers_kakked
	cmp	byte [r13], ' '
	jne	.headers_value
	add	r13, 1
	jmp	.headers_swallow_whitespace
calign
.headers_value:
	; so at this stage, r12 is the start of the key, r14-r12 is its length, r15 is the start of hte value, r13 is dangling
	; so we need to walk forward until we get a 13 or 10
	add	r13, 1
	cmp	byte [r13], 13
	je	.headers_doit
	cmp	byte [r13], 10
	jne	.headers_value
.headers_doit:
	; so from r13 - r15 is the length of the value

	lea	r11, [rbx+(httpheaders_size - httpheaders_scratchint_ofs)]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	r9, [rbx+httpheaders_endptr_ofs]
	mov	rdx, r14
	mov	r8, r13
	mov	rdi, rbx
	mov	rsi, r12
	sub	r11, r9
	sub	rdx, r12
	sub	r8, r15
	mov	rcx, r15

	; we could simply call httpheaders$slow_add directly from here, but for efficiency, we need
	; to deal with the simplest (and most common) case here inline
	test	r10, r10
	jnz	.slow_add
	cmp	r11d, r8d
	jb	.slow_add

	cmp	edx, 27
	ja	.slow_add
	cmp	dword [rdx*4+httpheaders$http1_searchorders_len], 0
	je	.slow_add
	cmp	dword [rbx+httpheaders_hcount_ofs], 22
	jae	.slow_add

	; otherwise, before we add the value to the scratch (slow_add does this first because it knows it will succeed)
	; we can conduct our search here, and only add the value if we succeed, and if we don't find it, let slow_add
	; deal with the redundant search case (which is fine for slow ones)
	push	r12 r13 r14 r15
	mov	r12, [rdx*8+httpheaders$http1_searchorders]
	mov	r13d, [rdx*4+httpheaders$http1_searchorders_len]
	mov	r14d, edx
	mov	r15, rsi
calign
.search:
	mov	rdi, [r12]
	mov	rsi, r15
	mov	edx, r14d
	; add first iteration of search_loop here:
	movzx	eax, word [rsi]
	cmp	ax, word [rdi]
	jne	.search_inequal
	add	rsi, 2
	add	rdi, 2
	sub	edx, 2
	jz	.search_equal
	; fallthrough
calign
.search_loop:
	cmp	edx, 1
	je	.lastone
	movzx	eax, word [rsi]
	cmp	ax, word [rdi]
	jne	.search_inequal
	add	rsi, 2
	add	rdi, 2
	sub	edx, 2
	jnz	.search_loop
	jmp	.search_equal
calign
.lastone:
	movzx	eax, byte [rsi]
	cmp	al, byte [rdi]
	je	.search_equal
calign
.search_inequal:
	mov	cl, al
	sub	al, 'A'
	cmp	al, 'Z' - 'A'
	jbe	.search_loop_lc
	cmp	cl, [rdi]
	jne	.search_next
	add	rsi, 1
	add	rdi, 1
	sub	edx, 1
	jnz	.search_loop
	jmp	.search_equal
calign
.search_loop_lc:
	add	al, 'a'
	cmp	al, [rdi]
	jne	.search_next
	add	rsi, 1
	add	rdi, 1
	sub	edx, 1
	jnz	.search_loop
	jmp	.search_equal
calign
.search_next:
	add	r12, 32
	sub	r13d, 1
	jnz	.search
	; if we made it to here, undo our stack and proceed to slow_add
	mov	rsi, r15
	mov	edx, r14d
	mov	rdi, rbx
	pop	r15 r14 r13 r12
	mov	rcx, r15
	jmp	.slow_add

calign
.search_equal:
	; so we found our header at [r12], which means the first 16 bytes at r12 is our xmm0
	movaps	xmm0, [r12]
	; the next 16 bytes need to be our value, which we already determined fits in our scratch area
	; so we can undo our stack, add it and proceed
	pop	r15 r14 r13 r12
	; add our value to the scratch area and add our htable entry
	mov	eax, [rbx+httpheaders_hcount_ofs]
	lea	rcx, [rbx+httpheaders_htable_ofs]
	mov	rdi, r9
	mov	rsi, r15
	mov	edx, r8d
	shl	eax, 5
	add	qword [rbx+httpheaders_endptr_ofs], r8
	add	dword [rbx+httpheaders_hcount_ofs], 1
	movdqu	[rcx+rax], xmm0
	mov	[rcx+rax+16], r9		; value ptr
	mov	[rcx+rax+24], r8		; value length
	call	memcpy				; place the value onto the scratch area
	
	; next:
	lea	rax, [r13+1]
	lea	rcx, [r13+2]
	cmp	word [r13], 0xa0d
	cmove	rax, rcx
	mov	r12, rax
	jmp	.headers_loop
calign
.slow_add:
	call	httpheaders$slow_add

	lea	rax, [r13+1]
	lea	rcx, [r13+2]
	cmp	word [r13], 0xa0d
	cmove	rax, rcx
	mov	r12, rax
	jmp	.headers_loop
calign
.headers_done:
	pop	rax r15 r14 r13 r12 rbx
	epilog
calign
.request_foundeop_fullmethod:
	push	rax
	mov	rax, [rdi+httpheaders_endptr_ofs]
	; first 16 bytes of our h entry is the header name and length, which we'll copy from our static table (:method)
	movaps	xmm0, [httpheaders$static+64]
	; r10 is going to be at most 7 bytes
	mov	r9, [rdx]
	; so now we need to put this onto our scratch area
	mov	[rax], r9
	add	qword [rdi+httpheaders_endptr_ofs], r10
	; so our next two entries are rax and r10
	movdqu	[rdi+httpheaders_htable_ofs], xmm0
	mov	[rdi+httpheaders_htable_ofs+16], rax
	mov	[rdi+httpheaders_htable_ofs+24], r10
	pop	rax
	mov	dword [rdi+httpheaders_hcount_ofs], 2
	jmp	.request_dopath
calign
.request_dopath_length_one:
	; if the byte at rcx is '/', then we can use the full copy from the static table
	cmp	byte [rcx], '/'
	jne	.request_dopath_normal
	movaps	xmm0, [rdx+httpheaders$static+128]
	movaps	xmm1, [rdx+httpheaders$static+144]
	; so now that needs to go into our headerlist as-is
	movdqu	[rdi+httpheaders_htable_ofs+32], xmm0
	movdqu	[rdi+httpheaders_htable_ofs+48], xmm1
	jmp	.request_dopath_done
calign
.request_dopath_length_eleven:
	mov	r10, qword [.indexdoth]
	; if the bytes at [rcx] == '/index.html' then we can use the full copy from the static table
	cmp	qword [rcx], r10
	jne	.request_dopath_normal
	cmp	word [rcx+8], 'tm'
	jne	.request_dopath_normal
	cmp	byte [rcx+10], 'l'
	jne	.request_dopath_normal
	movaps	xmm0, [rdx+httpheaders$static+160]
	movaps	xmm1, [rdx+httpheaders$static+176]
	; so now that needs to go into our headerlist as-is
	movdqu	[rdi+httpheaders_htable_ofs+32], xmm0
	movdqu	[rdi+httpheaders_htable_ofs+48], xmm1
	jmp	.request_dopath_done
calign
.headers_kakked:
	pop	rcx r15 r14 r13 r12 rbx
	mov	rax, -1
	epilog
calign
.needmore:
	xor	eax, eax
	epilog
calign
.findeoh_lessthanfourleft:
	mov	r8d, 2
	cmp	ecx, 2
	jb	.needmore
	cmp	word [rax], 0xa0a
	je	.foundeoh
	add	rax, 1
	sub	ecx, 1
	jmp	.findeoh_lessthanfourleft
calign
.foundeoh_kakked:
	mov	rax, -1
	epilog
calign
.biggun:
	cmp	rdx, 16
	jb	.needmore
	mov	rax, rsi
	mov	rcx, rdx
calign
.biggun_findeoh:
	cmp	rcx, 4
	jb	.findeoh_lessthanfourleft
	mov	r8d, 4
	cmp	dword [rax], 0xa0d0a0d
	je	.foundeoh
	mov	r8d, 2
	cmp	word [rax], 0xa0a
	je	.foundeoh
	add	rax, 1
	sub	rcx, 1
	jnz	.findeoh
	jmp	.needmore
	

end if



if used httpheaders$slow_add | defined include_everything
	; five arguments: rdi == httpheaders object, rsi == ptr to name, edx == length of same, rcx == ptr to value, r8d == length of same
	; this function will _always_ update the dynamic table if the header name doesn't exist
	; returns a bool in eax as to whether we were able to or not
falign
httpheaders$slow_add:
	prolog	httpheaders$slow_add
	; we walk through both our static table and our dynamic one (if we have one) searching for the header name
	cmp	dword [rdi+httpheaders_hcount_ofs], 22
	jae	.overflow
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	add	rdi, httpheaders_size - httpheaders_scratchint_ofs	; the total size of our scratch area
	mov	r9, [rbx+httpheaders_endptr_ofs]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	r14, rcx
	mov	r15d, r8d

	; we can go ahead and add the value straight up, but we need to make sure we have enough room in our scratch area
	test	r10, r10
	jnz	.scratch_buffer
	; make sure there is room in our scratch area
	sub	rdi, r9
	cmp	edi, r8d
	jb	.scratch_new_buffer
	; otherwise, there is enough room
	mov	rdi, r9
	mov	rsi, rcx
	mov	edx, r8d
	add	qword [rbx+httpheaders_endptr_ofs], r8
	mov	r14, r9		; this is the real value pointer
	call	memcpy
	push	rbp
	xor	ebp, ebp
	cmp	r13d, 27
	ja	.dsearch
	cmp	dword [r13*4+httpheaders$http1_searchorders_len], 0
	je	.dsearch
calign
.search:
	mov	eax, ebp
	mov	r8, [r13*8+httpheaders$http1_searchorders]
	cmp	ebp, [r13*4+httpheaders$http1_searchorders_len]
	jae	.dsearch
	shl	eax, 5
	mov	rsi, r12
	mov	edx, r13d
	mov	rdi, [r8+rax]
	add	ebp, 1
	call	httpheaders$strcasecmp
	test	eax, eax
	jz	.search
	; otherwise, we found the name, its searchorder index is ebp-1
	sub	ebp, 1
	mov	eax, ebp
	mov	r8, [r13*8+httpheaders$http1_searchorders]
	shl	eax, 5
	movaps	xmm0, [r8+rax]
	; fallthrough to addheader
calign
.addheader:
	; so xmm0 is all setup with the pointer and length to our header name
	; we need to add the full htable entry with our r14/r15d and be done
	mov	eax, [rbx+httpheaders_hcount_ofs]
	lea	rcx, [rbx+httpheaders_htable_ofs]
	shl	eax, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	; [rcx+rax] is our destination htable entry for 32 bytes
	movdqu	[rcx+rax], xmm0
	mov	[rcx+rax+16], r14
	mov	[rcx+rax+24], r15
	; all done
	pop	rbp
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.dsearch:
	; we didn't find it in the static table, see if it lives in the dynamic table
	cmp	dword [rbx+httpheaders_dcount_ofs], 0
	je	.new_dynamic
	xor	ebp, ebp
calign
.dsearchloop:
	mov	eax, ebp
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	cmp	ebp, [rbx+httpheaders_dcount_ofs]
	jae	.new_dynamic
	shl	eax, 5
	mov	rsi, r12
	mov	edx, r13d
	add	ebp, 1
	mov	rdi, [rcx+rax]		; first 8 bytes is the value
	cmp	edx, [rcx+rax+8]
	jne	.dsearchloop
	call	httpheaders$strcasecmp
	test	eax, eax
	jz	.dsearchloop
	; otehrwise, we found the name, its index is ebp-1
	sub	ebp, 1
	mov	eax, ebp
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	shl	eax, 5
	movdqu	xmm0, [rcx+rax]
	jmp	.addheader
calign
.new_dynamic:
	; make sure dcount < dlimit, or puke
	lea	rdi, [rbx+(httpheaders_size - httpheaders_scratchint_ofs)]
	mov	r9, [rbx+httpheaders_endptr_ofs]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	eax, [rbx+httpheaders_dcount_ofs]
	cmp	eax, [rbx+httpheaders_dlimit_ofs]
	jae	.new_dynamic_noroom
	; otherwise, we need to first copy the header name into our scratch area
	; and then lower case it
	; and then add a new entry into the dtable with the current value
	; then add both the same again to the htable and we are done
	test	r10, r10
	jnz	.new_dynamic_scratch_buffer
	; make sure there is room in our scratch area
	sub	rdi, r9
	cmp	edi, r13d
	jb	.new_dynamic_new_scratch_buffer
	; otherwise, there is enough room
	mov	rdi, r9
	mov	rsi, r12
	mov	edx, r13d
	add	qword [rbx+httpheaders_endptr_ofs], r13
	mov	r12, rdi	; this is the real name pointer
	call	memcpy
calign
.new_dynamic_proceed:
	; lower case it
	mov	rdi, r12
	mov	esi, r13d
	call	httpheaders$strlowercase
	; now we need a new entry in the dtable with both
	mov	eax, [rbx+httpheaders_dcount_ofs]
	mov	rcx, [rbx+httpheaders_dtable_ofs]
	shl	eax, 5
	add	dword [rbx+httpheaders_dcount_ofs], 1
	; [rcx+rax] is our destination dtable entry for 32 bytes
	mov	[rcx+rax], r12
	mov	[rcx+rax+8], r13
	mov	[rcx+rax+16], r14
	mov	[rcx+rax+24], r15
	; now do the same for our hcount
	mov	eax, [rbx+httpheaders_hcount_ofs]
	lea	rcx, [rbx+httpheaders_htable_ofs]
	shl	eax, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	; [rcx+rax] is our destination htable entry for 32 bytes
	mov	[rcx+rax], r12
	mov	[rcx+rax+8], r13
	mov	[rcx+rax+16], r14
	mov	[rcx+rax+24], r15
	; done, dusted
	pop	rbp
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.new_dynamic_scratch_buffer:
	; we cannot exceed our fixed buffer size, so determine how much space we have left
	mov	rcx, [r10+buffer_size_ofs]
	sub	rcx, [r10+buffer_length_ofs]
	cmp	ecx, r8d
	jb	.new_dynamic_noroom
	; otherwise, we can add it directly to the buffer
	mov	rdi, [r10+buffer_endptr_ofs]
	mov	rsi, r12
	mov	edx, r13d
	add	[r10+buffer_endptr_ofs], r13
	add	[r10+buffer_length_ofs], r13
	mov	r12, rdi
	call	memcpy
	jmp	.new_dynamic_proceed
calign
.new_dynamic_new_scratch_buffer:
	cmp	r13d, 65536
	ja	.new_dynamic_noroom
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r12
	mov	edx, r13d
	mov	rdi, [r10+buffer_endptr_ofs]
	add	[r10+buffer_endptr_ofs], r13
	add	[r10+buffer_length_ofs], r13
	mov	r12, rdi
	call	memcpy
	jmp	.new_dynamic_proceed
calign
.new_dynamic_noroom:
	pop	rbp
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.scratch_buffer:
	; we cannot exceed our fixed buffer size, so determine how much space we have left
	mov	rcx, [r10+buffer_size_ofs]
	sub	rcx, [r10+buffer_length_ofs]
	cmp	ecx, r8d
	jb	.nodeal
	; otherwise, we can add it directly to the buffer
	mov	rdi, [r10+buffer_endptr_ofs]
	mov	rsi, r14
	mov	edx, r15d
	add	[r10+buffer_endptr_ofs], r15
	add	[r10+buffer_length_ofs], r15
	mov	r14, rdi
	call	memcpy
	push	rbp
	xor	ebp, ebp
	jmp	.search
calign
.scratch_new_buffer:
	; not enough room in our scratch area, so create a 64k buffer
	cmp	r15d, 65536
	ja	.nodeal
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r14
	mov	edx, r15d
	mov	rdi, [r10+buffer_endptr_ofs]
	add	[r10+buffer_endptr_ofs], r15
	add	[r10+buffer_length_ofs], r15
	mov	r14, rdi
	call	memcpy
	push	rbp
	xor	ebp, ebp
	jmp	.search
calign
.nodeal:
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	epilog
calign
.overflow:
	xor	eax, eax
	epilog

end if


if used httpheaders$strcasecmp | defined include_everything
	; three arguments: rdi == ptr to latin1 left, rsi == ptr to latin1 right, edx == length of both
	; NOTE: rdi is expected to _already_ be lowercase (from the header search), and edx is assumed >0
	; returns a bool in eax whether they match or not
falign
httpheaders$strcasecmp:
	prolog	httpheaders$strcasecmp
calign
.doit:
	cmp	edx, 1
	je	.lastone
	movzx	eax, word [rsi]
	cmp	ax, word [rdi]
	jne	.search_inequal
	add	rsi, 2
	add	rdi, 2
	sub	edx, 2
	jnz	.doit
	mov	eax, 1
	epilog
calign
.lastone:
	movzx	eax, byte [rsi]
	cmp	al, byte [rdi]
	jne	.search_inequal
	mov	eax, 1
	epilog
calign
.search_inequal:
	mov	cl, al
	sub	al, 'A'
	cmp	al, 'Z' - 'A'
	jbe	.doit_lc
	cmp	cl, [rdi]
	jne	.zeroret
	add	rsi, 1
	add	rdi, 1
	sub	edx, 1
	jnz	.doit
	; if we made it to here, they were equal
	mov	eax, 1
	epilog
calign
.doit_lc:
	add	al, 'a'
	cmp	al, [rdi]
	jne	.zeroret
	add	rsi, 1
	add	rdi, 1
	sub	edx, 1
	jnz	.doit
	; if we made it to here, they were equal
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used httpheaders$strlowercase | defined include_everything
	; two arguments: rdi == ptr to latin1, esi == length of same (nonzero)
falign
httpheaders$strlowercase:
	prolog	httpheaders$strlowercase
calign
.doit:
	mov	al, [rdi]
	sub	al, 'A'
	cmp	al, 'Z' - 'A'
	jbe	.doit_lc
	add	rdi, 1
	sub	esi, 1
	jnz	.doit
	epilog
calign
.doit_lc:
	add	al, 'a'
	mov	[rdi], al
	add	rdi, 1
	sub	esi, 1
	jnz	.doit
	epilog

end if




if used httpheaders$destroy | defined include_everything
	; single argument in rdi == our httpheaders object to teardown
falign
httpheaders$destroy:
	prolog	httpheaders$destroy
	cmp	qword [rdi+httpheaders_scratch_ofs], 0
	jne	.withscratch
	call	heap$free
	epilog
calign
.withscratch:
	push	rdi
	mov	rdi, [rdi+httpheaders_scratch_ofs]
	call	buffer$destroy
	pop	rdi
	call	heap$free
	epilog

end if


if used httpheaders$slow_single_get | defined include_everything
	; three arguments: rdi == httpheaders object, rsi == ptr to LOWER CASE name, edx == length of same
	; this function actually has to do memcmp against the headers to find it, hence the slow name
	; it is also why we wrapped the common ones in function calls because they are much faster
	; returns 0 in rax if not found, otherwise, rax == ptr to the value, edx == length of same
	; NOTE: if more than one header exists with the same name, this will only return the first one
falign
httpheaders$slow_single_get:
	prolog	httpheaders$slow_single_get
	cmp	dword [rdi+httpheaders_hcount_ofs], 0
	je	.nope
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	xor	r14d, r14d
calign
.search:
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	cmp	r14d, [rbx+httpheaders_hcount_ofs]
	jae	.notfound
	shl	eax, 5
	mov	rsi, r12
	mov	edx, r13d
	add	r14d, 1
	mov	rdi, [rcx+rax]
	cmp	edx, [rcx+rax+8]
	jne	.search
	call	memcmp
	test	eax, eax
	jnz	.search
	; otherwise, we found it, its index is r14d-1
	sub	r14d, 1
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	shl	eax, 5
	mov	edx, [rcx+rax+24]		; value length
	mov	rax, [rcx+rax+16]		; its value pointer
	pop	r14 r13 r12 rbx
	epilog
calign
.notfound:
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.nope:
	xor	eax, eax
	epilog

end if

if used httpheaders$fast_single_get | defined include_everything
	; two arguments: rdi == httpheaders object, rsi == one of the httpheaders$static first entries (the pointer to the name itself)
	; returns 0 in rax if not found, otherwise, rax == ptr to the value, edx == length of same
	; NOTE: if more than one header exists with the same name, this will only return the first one
falign
httpheaders$fast_single_get:
	prolog	httpheaders$fast_single_get
	xor	eax, eax
	mov	ecx, [rdi+httpheaders_hcount_ofs]
	lea	rdx, [rdi+httpheaders_htable_ofs]
	test	ecx, ecx
	jz	.nope
calign
.search:
	cmp	rsi, [rdx+rax]
	je	.found
	add	eax, 32
	sub	ecx, 1
	jnz	.search
	xor	eax, eax
	epilog
calign
.found:
	mov	ecx, [rdx+rax+24]		; value length
	mov	rax, [rdx+rax+16]		; its value pointer
	mov	edx, ecx
	epilog
calign
.nope:
	epilog

end if

if used httpheaders$slow_get_index | defined include_everything
	; four arguments: rdi == httpheaders object, rsi == ptr to LOWER CASE name, edx == length of same, ecx == index to retrieve
	; this function is the same as slow_single_get, but lets you specify the # to return
falign
httpheaders$slow_get_index:
	prolog	httpheaders$slow_get_index
	cmp	dword [rdi+httpheaders_hcount_ofs], 0
	je	.nope
	add	ecx, 1
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	xor	r14d, r14d
	mov	r15d, ecx
calign
.search:
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	cmp	r14d, [rbx+httpheaders_hcount_ofs]
	jae	.notfound
	shl	eax, 5
	mov	rsi, r12
	mov	edx, r13d
	add	r14d, 1
	mov	rdi, [rcx+rax]
	cmp	edx, [rcx+rax+8]
	jne	.search
	call	memcmp
	test	eax, eax
	jnz	.search
	; otherwise, we found it, its index is r14d-1
	; see if the index matches, otherwise keep going
	cmp	r14d, r15d
	jne	.search
	sub	r14d, 1
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	shl	eax, 5
	mov	edx, [rcx+rax+24]		; value length
	mov	rax, [rcx+rax+16]		; its value pointer
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.notfound:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.nope:
	xor	eax, eax
	epilog

end if


if used httpheaders$fast_get_index | defined include_everything
	; three arguments: rdi == httpheaders object, rsi == one of the httpheaders$static first entries (the pointer to the name itself), edx == index to retrieve
	; same as fast_single_get, but lets you specify the # to return
falign
httpheaders$fast_get_index:
	prolog	httpheaders$fast_get_index
	mov	ecx, [rdi+httpheaders_hcount_ofs]
	xor	eax, eax
	xor	r9d, r9d
	mov	r8d, edx
	lea	rdx, [rdi+httpheaders_htable_ofs]
	test	ecx, ecx
	jz	.nope
calign
.search:
	cmp	rsi, [rdx+rax]
	je	.found
	add	eax, 32
	sub	ecx, 1
	jnz	.search
	xor	eax, eax
	epilog
calign
.found:
	cmp	r8d, r9d
	je	.found_return
	; otherwise, not the right index
	add	r9d, 1
	add	eax, 32
	sub	ecx, 1
	jnz	.search
	; otherwise, end of the line
	xor	eax, eax
	epilog
calign
.found_return:
	mov	ecx, [rdx+rax+24]		; value length
	mov	rax, [rdx+rax+16]		; its value pointer
	mov	edx, ecx
	epilog
calign
.nope:
	epilog

end if


if used httpheaders$slow_count | defined include_everything
	; three arguments: rdi == httpheaders object, rsi == ptr to LOWER CASE name, edx == length of same
	; returns the number of headers that match, slow-style
falign
httpheaders$slow_count:
	prolog	httpheaders$slow_count
	cmp	dword [rdi+httpheaders_hcount_ofs], 0
	je	.nope
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	xor	r14d, r14d
	xor	r15d, r15d
calign
.search:
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	cmp	r14d, [rbx+httpheaders_hcount_ofs]
	jae	.notfound
	shl	eax, 5
	mov	rsi, r12
	mov	edx, r13d
	add	r14d, 1
	mov	rdi, [rcx+rax]
	cmp	edx, [rcx+rax+8]
	jne	.search
	call	memcmp
	test	eax, eax
	jnz	.search
	; otherwise, we found it, its index is r14d-1
	add	r15d, 1
	jmp	.search
calign
.notfound:
	mov	eax, r15d
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.nope:
	xor	eax, eax
	epilog

end if


if used httpheaders$fast_count | defined include_everything
	; two arguments: rdi == httpheaders object, rsi == one of the httpheaders$static first entries (the pointer to the name itself)
	; returns the number of headers that match
falign
httpheaders$fast_count:
	prolog	httpheaders$fast_count
	mov	ecx, [rdi+httpheaders_hcount_ofs]
	lea	rdx, [rdi+httpheaders_htable_ofs]
	xor	eax, eax
	xor	r8d, r8d
	test	ecx, ecx
	jz	.nope
calign
.search:
	lea	r9d, [r8d+1]
	cmp	rsi, [rdx+rax]
	cmove	r8d, r9d
	add	eax, 32
	sub	ecx, 1
	jnz	.search
	mov	eax, r8d
	epilog
calign
.nope:
	epilog

end if


if used httpheaders$slow_remove | defined include_everything
	; three arguments: rdi == httpheaders object, rsi == ptr to LOWER CASE name, edx == length of same
	; this will remove all headers that match, but is slow thanks to the memcmp that is required
	; returns the # of headers we removed
falign
httpheaders$slow_remove:
	prolog	httpheaders$slow_remove
	cmp	dword [rdi+httpheaders_hcount_ofs], 0
	je	.nope
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	xor	r14d, r14d
	xor	r15d, r15d
calign
.search:
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	cmp	r14d, [rbx+httpheaders_hcount_ofs]
	jae	.notfound
	shl	eax, 5
	mov	rsi, r12
	mov	edx, r13d
	add	r14d, 1
	mov	rdi, [rcx+rax]
	cmp	edx, [rcx+rax+8]
	jne	.search
	call	memcmp
	test	eax, eax
	jnz	.search
	mov	edx, [rbx+httpheaders_hcount_ofs]
	sub	edx, r14d
	jz	.nomove
	; otherwise, we found it, its index is r14d-1
	; so, we need to memmove everything in the htable from this point _forward_
	sub	r14d, 1
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	shl	eax, 5
	shl	edx, 5
	lea	rdi, [rcx+rax]			; destination pointer
	lea	rsi, [rcx+rax+32]		; source pointer
	call	memmove
	sub	dword [rbx+httpheaders_hcount_ofs], 1
	add	r15d, 1
	jmp	.search
calign
.nomove:
	sub	r14d, 1
	add	r15d, 1
	sub	dword [rbx+httpheaders_hcount_ofs], 1
	mov	eax, r15d
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.notfound:
	mov	eax, r15d
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.nope:
	xor	eax, eax
	epilog

end if


if used httpheaders$fast_remove | defined include_everything
	; two arguments: rdi == httpheaders object, rsi == one of the httpheaders$static first entries (the pointer to the name itself)
	; this will remove all headers that match
	; returns the # of headers we removed
falign
httpheaders$fast_remove:
	prolog	httpheaders$fast_remove
	cmp	dword [rdi+httpheaders_hcount_ofs], 0
	je	.nope
	push	rbx r12 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	xor	r14d, r14d
	xor	r15d, r15d
calign
.search:
	mov	eax, r14d
	lea	rcx, [rbx+httpheaders_htable_ofs]
	cmp	r14d, [rbx+httpheaders_hcount_ofs]
	jae	.notfound
	shl	eax, 5
	add	r14d, 1
	cmp	r12, [rcx+rax]
	jne	.search
	mov	edx, [rbx+httpheaders_hcount_ofs]
	sub	edx, r14d
	jz	.nomove
	; otherwise, we found it, its index is r14d-1
	sub	r14d, 1
	lea	rdi, [rcx+rax]
	lea	rsi, [rcx+rax+32]
	shl	edx, 5
	call	memmove
	sub	dword [rbx+httpheaders_hcount_ofs], 1
	add	r15d, 1
	jmp	.search
calign
.nomove:
	sub	r14d, 1
	add	r15d, 1
	sub	dword [rbx+httpheaders_hcount_ofs], 1
	mov	eax, r15d
	pop	r15 r14 r12 rbx
	epilog
calign
.notfound:
	mov	eax, r15d
	pop	r15 r14 r12 rbx
	epilog
calign
.nope:
	xor	eax, eax
	epilog

end if




if used httpheaders$fast_add | defined include_everything
	; five arguments: rdi == httpheaders object, rsi == one of the httpheaders$static first entries (the pointer to the name itself), edx == length of same,
	; 	rcx == ptr to value, r8d == length of same
	; returns a bool in eax as to whether we were able to or not
falign
httpheaders$fast_add:
	prolog	httpheaders$fast_add
	cmp	dword [rdi+httpheaders_hcount_ofs], 22
	jae	.overflow
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	add	rdi, httpheaders_size - httpheaders_scratchint_ofs	; the total size of our scratch area
	mov	r9, [rbx+httpheaders_endptr_ofs]
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	r14, rcx
	mov	r15d, r8d
	; add the value first up
	test	r10, r10
	jnz	.scratch_buffer
	; make sure there is room in our scratch area
	sub	rdi, r9
	cmp	edi, r8d
	jb	.scratch_new_buffer
	; otherwise, there is enough room
	mov	rdi, r9
	mov	rsi, rcx
	mov	edx, r8d
	add	qword [rbx+httpheaders_endptr_ofs], r8
	mov	r14, r9		; this is the real value pointer
	call	memcpy
calign
.addit:
	; add the header
	mov	eax, [rbx+httpheaders_hcount_ofs]
	lea	rcx, [rbx+httpheaders_htable_ofs]
	shl	eax, 5
	add	dword [rbx+httpheaders_hcount_ofs], 1
	; [rcx+rax] is our destination htable entry for 32 bytes
	mov	[rcx+rax], r12
	mov	[rcx+rax+8], r13
	mov	[rcx+rax+16], r14
	mov	[rcx+rax+24], r15
	pop	r15 r14 r13 r12 rbx
	mov	eax, 1
	epilog
calign
.scratch_buffer:
	; we cannot exceed our fixed buffer size, so determine how much space we have left
	mov	rcx, [r10+buffer_size_ofs]
	sub	rcx, [r10+buffer_length_ofs]
	cmp	ecx, r8d
	jb	.nodeal
	; otherwise, we can add it directly to the buffer
	mov	rdi, [r10+buffer_endptr_ofs]
	mov	rsi, r14
	mov	edx, r15d
	add	[r10+buffer_endptr_ofs], r15
	add	[r10+buffer_length_ofs], r15
	mov	r14, rdi
	call	memcpy
	jmp	.addit
calign
.scratch_new_buffer:
	; not enough room in our scratch area, so create a 64k buffer
	cmp	r15d, 65536
	ja	.nodeal
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	r10, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r14
	mov	edx, r15d
	mov	rdi, [r10+buffer_endptr_ofs]
	add	[r10+buffer_endptr_ofs], r15
	add	[r10+buffer_length_ofs], r15
	mov	r14, rdi
	call	memcpy
	jmp	.addit
calign
.nodeal:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.overflow:
	xor	eax, eax
	epilog

end if



; our static tables that everything needs are below:


if used httpheaders$new | defined include_everything

	; our static table for HPACK:
	; each entry in the tables are 32 bytes each: ptr key, qword keylen, ptr value, qword vallen
	; NOTE: since index:0 is reserved, and since we support both HTTP/1 and HTTP/2 here, we added
	; the Connection: header at index 0 so that we don't have to modify any of the rest of it for
	; normal operations
align 16
httpheaders$static:
	dq	httpheaders$connection, httpheaders$connection_len, .s0a, 0	; connection: 
	dq	httpheaders$pseudo_authority, httpheaders$pseudo_authority_len, .s0a, 0	; :authority: 
	dq	httpheaders$pseudo_method, httpheaders$pseudo_method_len, .s2c, 3	; :method: GET
	dq	httpheaders$pseudo_method, httpheaders$pseudo_method_len, .s3c, 4	; :method: POST
	dq	httpheaders$pseudo_path, httpheaders$pseudo_path_len, .s4c, 1	; :path: /
	dq	httpheaders$pseudo_path, httpheaders$pseudo_path_len, .s5c, 11	; :path: /index.html
	dq	httpheaders$pseudo_scheme, httpheaders$pseudo_scheme_len, .s6c, 4	; :scheme: http
	dq	httpheaders$pseudo_scheme, httpheaders$pseudo_scheme_len, .s7c, 5	; :scheme: https
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s8c, 3	; :status: 200
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s9c, 3	; :status: 204
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s10c, 3	; :status: 206
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s11c, 3	; :status: 304
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s12c, 3	; :status: 400
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s13c, 3	; :status: 404
	dq	httpheaders$pseudo_status, httpheaders$pseudo_status_len, .s14c, 3	; :status: 500
	dq	httpheaders$accept_charset, httpheaders$accept_charset_len, .s0a, 0	; accept-charset: 
	dq	httpheaders$accept_encoding, httpheaders$accept_encoding_len, .s16c, 13	; accept-encoding: gzip, deflate
	dq	httpheaders$accept_language, httpheaders$accept_language_len, .s0a, 0	; accept-language: 
	dq	httpheaders$accept_ranges, httpheaders$accept_ranges_len, .s0a, 0	; accept-ranges: 
	dq	httpheaders$accept, httpheaders$accept_len, .s0a, 0	; accept: 
	dq	httpheaders$access_control_allow_origin, httpheaders$access_control_allow_origin_len, .s0a, 0	; access-control-allow-origin: 
	dq	httpheaders$age, httpheaders$age_len, .s0a, 0	; age: 
	dq	httpheaders$allow, httpheaders$allow_len, .s0a, 0	; allow: 
	dq	httpheaders$authorization, httpheaders$authorization_len, .s0a, 0	; authorization: 
	dq	httpheaders$cache_control, httpheaders$cache_control_len, .s0a, 0	; cache-control: 
	dq	httpheaders$content_disposition, httpheaders$content_disposition_len, .s0a, 0	; content-disposition: 
	dq	httpheaders$content_encoding, httpheaders$content_encoding_len, .s0a, 0	; content-encoding: 
	dq	httpheaders$content_language, httpheaders$content_language_len, .s0a, 0	; content-language: 
	dq	httpheaders$content_length, httpheaders$content_length_len, .s0a, 0	; content-length: 
	dq	httpheaders$content_location, httpheaders$content_location_len, .s0a, 0	; content-location: 
	dq	httpheaders$content_range, httpheaders$content_range_len, .s0a, 0	; content-range: 
	dq	httpheaders$content_type, httpheaders$content_type_len, .s0a, 0	; content-type: 
	dq	httpheaders$cookie, httpheaders$cookie_len, .s0a, 0	; cookie: 
	dq	httpheaders$date, httpheaders$date_len, .s0a, 0	; date: 
	dq	httpheaders$etag, httpheaders$etag_len, .s0a, 0	; etag: 
	dq	httpheaders$expect, httpheaders$expect_len, .s0a, 0	; expect: 
	dq	httpheaders$expires, httpheaders$expires_len, .s0a, 0	; expires: 
	dq	httpheaders$from, httpheaders$from_len, .s0a, 0	; from: 
	dq	httpheaders$host, httpheaders$host_len, .s0a, 0	; host: 
	dq	httpheaders$if_match, httpheaders$if_match_len, .s0a, 0	; if-match: 
	dq	httpheaders$if_modified_since, httpheaders$if_modified_since_len, .s0a, 0	; if-modified-since: 
	dq	httpheaders$if_none_match, httpheaders$if_none_match_len, .s0a, 0	; if-none-match: 
	dq	httpheaders$if_range, httpheaders$if_range_len, .s0a, 0	; if-range: 
	dq	httpheaders$if_unmodified_since, httpheaders$if_unmodified_since_len, .s0a, 0	; if-unmodified-since: 
	dq	httpheaders$last_modified, httpheaders$last_modified_len, .s0a, 0	; last-modified: 
	dq	httpheaders$link, httpheaders$link_len, .s0a, 0	; link: 
	dq	httpheaders$location, httpheaders$location_len, .s0a, 0	; location: 
	dq	httpheaders$max_forwards, httpheaders$max_forwards_len, .s0a, 0	; max-forwards: 
	dq	httpheaders$proxy_authenticate, httpheaders$proxy_authenticate_len, .s0a, 0	; proxy-authenticate: 
	dq	httpheaders$proxy_authorization, httpheaders$proxy_authorization_len, .s0a, 0	; proxy-authorization: 
	dq	httpheaders$range, httpheaders$range_len, .s0a, 0	; range: 
	dq	httpheaders$referer, httpheaders$referer_len, .s0a, 0	; referer: 
	dq	httpheaders$retry_after, httpheaders$retry_after_len, .s0a, 0	; retry-after: 
	dq	httpheaders$server, httpheaders$server_len, .s0a, 0	; server: 
	dq	httpheaders$set_cookie, httpheaders$set_cookie_len, .s0a, 0	; set-cookie: 
	dq	httpheaders$strict_transport_security, httpheaders$strict_transport_security_len, .s0a, 0	; strict-transport-security: 
	dq	httpheaders$transfer_encoding, httpheaders$transfer_encoding_len, .s0a, 0	; transfer-encoding: 
	dq	httpheaders$user_agent, httpheaders$user_agent_len, .s0a, 0	; user-agent: 
	dq	httpheaders$vary, httpheaders$vary_len, .s0a, 0	; vary: 
	dq	httpheaders$via, httpheaders$via_len, .s0a, 0	; via: 
	dq	httpheaders$www_authenticate, httpheaders$www_authenticate_len, .s0a, 0	; www-authenticate: 
.s0a:
	; this is only referenced for 0 length default values
.s2c:
	db	'GET'
.s3c:
	db	'POST'
.s4c:
	db	'/'
.s5c:
	db	'/index.html'
.s6c:
	db	'http'
.s7c:
	db	'https'
.s8c:
	db	'200'
.s9c:
	db	'204'
.s10c:
	db	'206'
.s11c:
	db	'304'
.s12c:
	db	'400'
.s13c:
	db	'404'
.s14c:
	db	'500'
.s16c:
	db	'gzip, deflate'
httpheaders$connection:
	db	'connection'
	httpheaders$connection_len = $ - httpheaders$connection
httpheaders$pseudo_authority:
	db	':authority'
	httpheaders$pseudo_authority_len = $ - httpheaders$pseudo_authority
httpheaders$pseudo_method:
	db	':method'
	httpheaders$pseudo_method_len = $ - httpheaders$pseudo_method
httpheaders$pseudo_path:
	db	':path'
	httpheaders$pseudo_path_len = $ - httpheaders$pseudo_path
httpheaders$pseudo_scheme:
	db	':scheme'
	httpheaders$pseudo_scheme_len = $ - httpheaders$pseudo_scheme
httpheaders$pseudo_status:
	db	':status'
	httpheaders$pseudo_status_len = $ - httpheaders$pseudo_status
httpheaders$accept_charset:
	db	'accept-charset'
	httpheaders$accept_charset_len = $ - httpheaders$accept_charset
httpheaders$accept_encoding:
	db	'accept-encoding'
	httpheaders$accept_encoding_len = $ - httpheaders$accept_encoding
httpheaders$accept_language:
	db	'accept-language'
	httpheaders$accept_language_len = $ - httpheaders$accept_language
httpheaders$accept_ranges:
	db	'accept-ranges'
	httpheaders$accept_ranges_len = $ - httpheaders$accept_ranges
httpheaders$accept:
	db	'accept'
	httpheaders$accept_len = $ - httpheaders$accept
httpheaders$access_control_allow_origin:
	db	'access-control-allow-origin'
	httpheaders$access_control_allow_origin_len = $ - httpheaders$access_control_allow_origin
httpheaders$age:
	db	'age'
	httpheaders$age_len = $ - httpheaders$age
httpheaders$allow:
	db	'allow'
	httpheaders$allow_len = $ - httpheaders$allow
httpheaders$authorization:
	db	'authorization'
	httpheaders$authorization_len = $ - httpheaders$authorization
httpheaders$cache_control:
	db	'cache-control'
	httpheaders$cache_control_len = $ - httpheaders$cache_control
httpheaders$content_disposition:
	db	'content-disposition'
	httpheaders$content_disposition_len = $ - httpheaders$content_disposition
httpheaders$content_encoding:
	db	'content-encoding'
	httpheaders$content_encoding_len = $ - httpheaders$content_encoding
httpheaders$content_language:
	db	'content-language'
	httpheaders$content_language_len = $ - httpheaders$content_language
httpheaders$content_length:
	db	'content-length'
	httpheaders$content_length_len = $ - httpheaders$content_length
httpheaders$content_location:
	db	'content-location'
	httpheaders$content_location_len = $ - httpheaders$content_location
httpheaders$content_range:
	db	'content-range'
	httpheaders$content_range_len = $ - httpheaders$content_range
httpheaders$content_type:
	db	'content-type'
	httpheaders$content_type_len = $ - httpheaders$content_type
httpheaders$cookie:
	db	'cookie'
	httpheaders$cookie_len = $ - httpheaders$cookie
httpheaders$date:
	db	'date'
	httpheaders$date_len = $ - httpheaders$date
httpheaders$etag:
	db	'etag'
	httpheaders$etag_len = $ - httpheaders$etag
httpheaders$expect:
	db	'expect'
	httpheaders$expect_len = $ - httpheaders$expect
httpheaders$expires:
	db	'expires'
	httpheaders$expires_len = $ - httpheaders$expires
httpheaders$from:
	db	'from'
	httpheaders$from_len = $ - httpheaders$from
httpheaders$host:
	db	'host'
	httpheaders$host_len = $ - httpheaders$host
httpheaders$if_match:
	db	'if-match'
	httpheaders$if_match_len = $ - httpheaders$if_match
httpheaders$if_modified_since:
	db	'if-modified-since'
	httpheaders$if_modified_since_len = $ - httpheaders$if_modified_since
httpheaders$if_none_match:
	db	'if-none-match'
	httpheaders$if_none_match_len = $ - httpheaders$if_none_match
httpheaders$if_range:
	db	'if-range'
	httpheaders$if_range_len = $ - httpheaders$if_range
httpheaders$if_unmodified_since:
	db	'if-unmodified-since'
	httpheaders$if_unmodified_since_len = $ - httpheaders$if_unmodified_since
httpheaders$last_modified:
	db	'last-modified'
	httpheaders$last_modified_len = $ - httpheaders$last_modified
httpheaders$link:
	db	'link'
	httpheaders$link_len = $ - httpheaders$link
httpheaders$location:
	db	'location'
	httpheaders$location_len = $ - httpheaders$location
httpheaders$max_forwards:
	db	'max-forwards'
	httpheaders$max_forwards_len = $ - httpheaders$max_forwards
httpheaders$proxy_authenticate:
	db	'proxy-authenticate'
	httpheaders$proxy_authenticate_len = $ - httpheaders$proxy_authenticate
httpheaders$proxy_authorization:
	db	'proxy-authorization'
	httpheaders$proxy_authorization_len = $ - httpheaders$proxy_authorization
httpheaders$range:
	db	'range'
	httpheaders$range_len = $ - httpheaders$range
httpheaders$referer:
	db	'referer'
	httpheaders$referer_len = $ - httpheaders$referer
httpheaders$retry_after:
	db	'retry-after'
	httpheaders$retry_after_len = $ - httpheaders$retry_after
httpheaders$server:
	db	'server'
	httpheaders$server_len = $ - httpheaders$server
httpheaders$set_cookie:
	db	'set-cookie'
	httpheaders$set_cookie_len = $ - httpheaders$set_cookie
httpheaders$strict_transport_security:
	db	'strict-transport-security'
	httpheaders$strict_transport_security_len = $ - httpheaders$strict_transport_security
httpheaders$transfer_encoding:
	db	'transfer-encoding'
	httpheaders$transfer_encoding_len = $ - httpheaders$transfer_encoding
httpheaders$user_agent:
	db	'user-agent'
	httpheaders$user_agent_len = $ - httpheaders$user_agent
httpheaders$vary:
	db	'vary'
	httpheaders$vary_len = $ - httpheaders$vary
httpheaders$via:
	db	'via'
	httpheaders$via_len = $ - httpheaders$via
httpheaders$www_authenticate:
	db	'www-authenticate'
	httpheaders$www_authenticate_len = $ - httpheaders$www_authenticate



end if


if used httpheaders$parse_http1 | defined include_everything

	; this is the same as above, but organized a bit easier to do http1 header parsing
	; (and, keeping this separate and presorted by lengths does make things quite a bit
	; more efficient... the code required to use this table is one of the highlights of
	; finally being rid of HTTP/1 :-)

dalign
httpheaders$http1_searchorders_len:
	dd	0, 0, 0, 2, 6, 2, 4, 2, 3, 0, 3, 1, 2, 6, 2, 2, 4, 2, 1, 3, 0, 0, 0, 0, 0, 1, 0, 1
dalign
httpheaders$http1_searchorders:
	dq	.none, .none, .none, .three, .four, .five, .six, .seven, .eight, .none, .ten, .eleven, .twelve, .thirteen, .fourteen, .fifteen, .sixteen, .seventeen, .eighteen, .nineteen, .none, .none, .none, .none, .none, .twentyfive, .none, .twentyseven
align 16
.none:
.three:
	dq	httpheaders$via, httpheaders$via_len, .s0a, 0	; via: 
	dq	httpheaders$age, httpheaders$age_len, .s0a, 0	; age: 
.four:
	dq	httpheaders$host, httpheaders$host_len, .s0a, 0	; host: 
	dq	httpheaders$date, httpheaders$date_len, .s0a, 0	; date: 
	dq	httpheaders$etag, httpheaders$etag_len, .s0a, 0	; etag: 
	dq	httpheaders$from, httpheaders$from_len, .s0a, 0	; from: 
	dq	httpheaders$link, httpheaders$link_len, .s0a, 0	; link: 
	dq	httpheaders$vary, httpheaders$vary_len, .s0a, 0	; vary: 
.five:
	dq	httpheaders$allow, httpheaders$allow_len, .s0a, 0	; allow: 
	dq	httpheaders$range, httpheaders$range_len, .s0a, 0	; range: 
.six:
	dq	httpheaders$accept, httpheaders$accept_len, .s0a, 0	; accept: 
	dq	httpheaders$cookie, httpheaders$cookie_len, .s0a, 0	; cookie: 
	dq	httpheaders$server, httpheaders$server_len, .s0a, 0	; server: 
	dq	httpheaders$expect, httpheaders$expect_len, .s0a, 0	; expect: 
.seven:
	dq	httpheaders$referer, httpheaders$referer_len, .s0a, 0	; referer: 
	dq	httpheaders$expires, httpheaders$expires_len, .s0a, 0	; expires: 
.eight:
	dq	httpheaders$location, httpheaders$location_len, .s0a, 0	; location: 
	dq	httpheaders$if_match, httpheaders$if_match_len, .s0a, 0	; if-match: 
	dq	httpheaders$if_range, httpheaders$if_range_len, .s0a, 0	; if-range: 
.ten:
	dq	httpheaders$connection, httpheaders$connection_len, .s0a, 0	; connection: 
	dq	httpheaders$user_agent, httpheaders$user_agent_len, .s0a, 0	; user-agent: 
	dq	httpheaders$set_cookie, httpheaders$set_cookie_len, .s0a, 0	; set-cookie: 
.eleven:
	dq	httpheaders$retry_after, httpheaders$retry_after_len, .s0a, 0	; retry-after: 
.twelve:
	dq	httpheaders$content_type, httpheaders$content_type_len, .s0a, 0	; content-type: 
	dq	httpheaders$max_forwards, httpheaders$max_forwards_len, .s0a, 0	; max-forwards: 
.thirteen:
	dq	httpheaders$last_modified, httpheaders$last_modified_len, .s0a, 0	; last-modified: 
	dq	httpheaders$if_none_match, httpheaders$if_none_match_len, .s0a, 0	; if-none-match: 
	dq	httpheaders$cache_control, httpheaders$cache_control_len, .s0a, 0	; cache-control: 
	dq	httpheaders$accept_ranges, httpheaders$accept_ranges_len, .s0a, 0	; accept-ranges: 
	dq	httpheaders$content_range, httpheaders$content_range_len, .s0a, 0	; content-range: 
	dq	httpheaders$authorization, httpheaders$authorization_len, .s0a, 0	; authorization: 
.fourteen:
	dq	httpheaders$content_length, httpheaders$content_length_len, .s0a, 0	; content-length: 
	dq	httpheaders$accept_charset, httpheaders$accept_charset_len, .s0a, 0	; accept-charset: 
.fifteen:
	dq	httpheaders$accept_encoding, httpheaders$accept_encoding_len, .s16c, 13	; accept-encoding: gzip, deflate
	dq	httpheaders$accept_language, httpheaders$accept_language_len, .s0a, 0	; accept-language: 
.sixteen:
	dq	httpheaders$content_encoding, httpheaders$content_encoding_len, .s0a, 0	; content-encoding: 
	dq	httpheaders$content_language, httpheaders$content_language_len, .s0a, 0	; content-language: 
	dq	httpheaders$content_location, httpheaders$content_location_len, .s0a, 0	; content-location: 
	dq	httpheaders$www_authenticate, httpheaders$www_authenticate_len, .s0a, 0	; www-authenticate: 
.seventeen:
	dq	httpheaders$if_modified_since, httpheaders$if_modified_since_len, .s0a, 0	; if-modified-since: 
	dq	httpheaders$transfer_encoding, httpheaders$transfer_encoding_len, .s0a, 0	; transfer-encoding: 
.eighteen:
	dq	httpheaders$proxy_authenticate, httpheaders$proxy_authenticate_len, .s0a, 0	; proxy-authenticate: 
.nineteen:
	dq	httpheaders$content_disposition, httpheaders$content_disposition_len, .s0a, 0	; content-disposition: 
	dq	httpheaders$if_unmodified_since, httpheaders$if_unmodified_since_len, .s0a, 0	; if-unmodified-since: 
	dq	httpheaders$proxy_authorization, httpheaders$proxy_authorization_len, .s0a, 0	; proxy-authorization: 
.twentyfive:
	dq	httpheaders$strict_transport_security, httpheaders$strict_transport_security_len, .s0a, 0	; strict-transport-security: 
.twentyseven:
	dq	httpheaders$access_control_allow_origin, httpheaders$access_control_allow_origin_len, .s0a, 0	; access-control-allow-origin: 
.s0a:
.s16c:
	db	'gzip, deflate'



end if

if used httpheaders$new | defined include_everything

	; we use this to determine whether a name/value is in the table or not
httpheaders$static_end = $

end if

if used httpheaders$parse_http2 | defined include_everything

	; our required Huffman encoding static goodies...
	;
	; generated outside of here, but spec says HPACK is static, so static it is
	; specifically, it states that changes require a full rewrite of the spec, so I am happy
	; to leave these pre-generated, I have seen much-larger table versions but there doesn't appear
	; to be any performance gain by going that route at least on all of my hardware, YMMV
dalign
httpheaders$huffyT:
	dd	0x00000900, 0x02000609, 0x0240060f, 0x02800615, 0x02c0031b, 0x02c8011b, 0x02ca011b, 0x02cc011b
	dd	0x02ce011b, 0x02d0011b, 0x02d2011b, 0x02d4011b, 0x02d6011b, 0x02d8011b, 0x02da011b, 0x02dc011b
	dd	0x02de011b, 0x02e0011b, 0x02e2011b, 0x02e40415, 0x02f40315, 0x02fc0215, 0x03000215, 0x03040215
	dd	0x03080215, 0x030c0215, 0x03100215, 0x03140215, 0x03180115, 0x031a0115, 0x031c0115, 0x031e0115
	dd	0x03200115, 0x03220115, 0x03240115, 0x03260115, 0x03280115, 0x032a0115, 0x032c0115, 0x032e0115
	dd	0x03300115, 0x03320209, 0x03360109, 0x03380109
httpheaders$huffyT_len = ($ - httpheaders$huffyT) shr 2

dalign
httpheaders$huffyE:
	dd	0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500
	dd	0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500
	dd	0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500
	dd	0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500
	dd	0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500
	dd	0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500
	dd	0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500
	dd	0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500
	dd	0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500
	dd	0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500
	dd	0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500
	dd	0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500
	dd	0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500
	dd	0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500
	dd	0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500
	dd	0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500
	dd	0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500
	dd	0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500
	dd	0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500
	dd	0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500
	dd	0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600
	dd	0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600
	dd	0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600
	dd	0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600
	dd	0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600
	dd	0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600
	dd	0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600
	dd	0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600
	dd	0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600
	dd	0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600
	dd	0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600
	dd	0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600
	dd	0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600
	dd	0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600
	dd	0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600
	dd	0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600
	dd	0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600
	dd	0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600
	dd	0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600
	dd	0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600
	dd	0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600
	dd	0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600
	dd	0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600
	dd	0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600
	dd	0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600
	dd	0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600
	dd	0x003a0700, 0x003a0700, 0x003a0700, 0x003a0700, 0x00420700, 0x00420700, 0x00420700, 0x00420700
	dd	0x00430700, 0x00430700, 0x00430700, 0x00430700, 0x00440700, 0x00440700, 0x00440700, 0x00440700
	dd	0x00450700, 0x00450700, 0x00450700, 0x00450700, 0x00460700, 0x00460700, 0x00460700, 0x00460700
	dd	0x00470700, 0x00470700, 0x00470700, 0x00470700, 0x00480700, 0x00480700, 0x00480700, 0x00480700
	dd	0x00490700, 0x00490700, 0x00490700, 0x00490700, 0x004a0700, 0x004a0700, 0x004a0700, 0x004a0700
	dd	0x004b0700, 0x004b0700, 0x004b0700, 0x004b0700, 0x004c0700, 0x004c0700, 0x004c0700, 0x004c0700
	dd	0x004d0700, 0x004d0700, 0x004d0700, 0x004d0700, 0x004e0700, 0x004e0700, 0x004e0700, 0x004e0700
	dd	0x004f0700, 0x004f0700, 0x004f0700, 0x004f0700, 0x00500700, 0x00500700, 0x00500700, 0x00500700
	dd	0x00510700, 0x00510700, 0x00510700, 0x00510700, 0x00520700, 0x00520700, 0x00520700, 0x00520700
	dd	0x00530700, 0x00530700, 0x00530700, 0x00530700, 0x00540700, 0x00540700, 0x00540700, 0x00540700
	dd	0x00550700, 0x00550700, 0x00550700, 0x00550700, 0x00560700, 0x00560700, 0x00560700, 0x00560700
	dd	0x00570700, 0x00570700, 0x00570700, 0x00570700, 0x00590700, 0x00590700, 0x00590700, 0x00590700
	dd	0x006a0700, 0x006a0700, 0x006a0700, 0x006a0700, 0x006b0700, 0x006b0700, 0x006b0700, 0x006b0700
	dd	0x00710700, 0x00710700, 0x00710700, 0x00710700, 0x00760700, 0x00760700, 0x00760700, 0x00760700
	dd	0x00770700, 0x00770700, 0x00770700, 0x00770700, 0x00780700, 0x00780700, 0x00780700, 0x00780700
	dd	0x00790700, 0x00790700, 0x00790700, 0x00790700, 0x007a0700, 0x007a0700, 0x007a0700, 0x007a0700
	dd	0x00260800, 0x00260800, 0x002a0800, 0x002a0800, 0x002c0800, 0x002c0800, 0x003b0800, 0x003b0800
	dd	0x00580800, 0x00580800, 0x005a0800, 0x005a0800, 0x00000a2b, 0x00000a2a, 0x00000b29, 0x00001e01
	dd	0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01
	dd	0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01
	dd	0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01
	dd	0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01
	dd	0x00000d01, 0x00000d01, 0x00000d01, 0x00000d01, 0x00240d01, 0x00240d01, 0x00240d01, 0x00240d01
	dd	0x00400d01, 0x00400d01, 0x00400d01, 0x00400d01, 0x005b0d01, 0x005b0d01, 0x005b0d01, 0x005b0d01
	dd	0x005d0d01, 0x005d0d01, 0x005d0d01, 0x005d0d01, 0x007e0d01, 0x007e0d01, 0x007e0d01, 0x007e0d01
	dd	0x005e0e01, 0x005e0e01, 0x007d0e01, 0x007d0e01, 0x003c0f01, 0x00600f01, 0x007b0f01, 0x00001e02
	dd	0x005c1302, 0x005c1302, 0x005c1302, 0x005c1302, 0x00c31302, 0x00c31302, 0x00c31302, 0x00c31302
	dd	0x00d01302, 0x00d01302, 0x00d01302, 0x00d01302, 0x00801402, 0x00801402, 0x00821402, 0x00821402
	dd	0x00831402, 0x00831402, 0x00a21402, 0x00a21402, 0x00b81402, 0x00b81402, 0x00c21402, 0x00c21402
	dd	0x00e01402, 0x00e01402, 0x00e21402, 0x00e21402, 0x00991502, 0x00a11502, 0x00a71502, 0x00ac1502
	dd	0x00b01502, 0x00b11502, 0x00b31502, 0x00d11502, 0x00d81502, 0x00d91502, 0x00e31502, 0x00e51502
	dd	0x00e61502, 0x00001628, 0x00001627, 0x00001626, 0x00001625, 0x00001624, 0x00001623, 0x00001622
	dd	0x00001621, 0x00001620, 0x0000161f, 0x0000161e, 0x0000161d, 0x0000161c, 0x0000171b, 0x0000171a
	dd	0x00001719, 0x00001718, 0x00001717, 0x00001716, 0x00001715, 0x00001814, 0x00001913, 0x00001e03
	dd	0x00c01a03, 0x00c01a03, 0x00c11a03, 0x00c11a03, 0x00c81a03, 0x00c81a03, 0x00c91a03, 0x00c91a03
	dd	0x00ca1a03, 0x00ca1a03, 0x00cd1a03, 0x00cd1a03, 0x00d21a03, 0x00d21a03, 0x00d51a03, 0x00d51a03
	dd	0x00da1a03, 0x00da1a03, 0x00db1a03, 0x00db1a03, 0x00ee1a03, 0x00ee1a03, 0x00f01a03, 0x00f01a03
	dd	0x00f21a03, 0x00f21a03, 0x00f31a03, 0x00f31a03, 0x00ff1a03, 0x00ff1a03, 0x00cb1b03, 0x00cc1b03
	dd	0x00d31b03, 0x00d41b03, 0x00d61b03, 0x00dd1b03, 0x00de1b03, 0x00df1b03, 0x00f11b03, 0x00f41b03
	dd	0x00f51b03, 0x00f61b03, 0x00f71b03, 0x00f81b03, 0x00fa1b03, 0x00fb1b03, 0x00fc1b03, 0x00fd1b03
	dd	0x00fe1b03, 0x00001c12, 0x00001c11, 0x00001c10, 0x00001c0f, 0x00001c0e, 0x00001c0d, 0x00001c0c
	dd	0x00001c0b, 0x00001c0a, 0x00001c09, 0x00001c08, 0x00001c07, 0x00001c06, 0x00001c05, 0x00001e04
	dd	0x00f91c04, 0x00f91c04, 0x00f91c04, 0x00f91c04, 0x000a1e04, 0x000d1e04, 0x00161e04, 0x01001e04
	dd	0x007f1c05, 0x00dc1c05, 0x001e1c06, 0x001f1c06, 0x001c1c07, 0x001d1c07, 0x001a1c08, 0x001b1c08
	dd	0x00181c09, 0x00191c09, 0x00151c0a, 0x00171c0a, 0x00131c0b, 0x00141c0b, 0x00111c0c, 0x00121c0c
	dd	0x000f1c0d, 0x00101c0d, 0x000c1c0e, 0x000e1c0e, 0x00081c0f, 0x000b1c0f, 0x00061c10, 0x00071c10
	dd	0x00041c11, 0x00051c11, 0x00021c12, 0x00031c12, 0x00ab1813, 0x00ab1813, 0x00ce1813, 0x00ce1813
	dd	0x00d71813, 0x00d71813, 0x00e11813, 0x00e11813, 0x00ec1813, 0x00ec1813, 0x00ed1813, 0x00ed1813
	dd	0x00c71913, 0x00cf1913, 0x00ea1913, 0x00eb1913, 0x00ef1714, 0x00ef1714, 0x00091814, 0x008e1814
	dd	0x00901814, 0x00911814, 0x00941814, 0x009f1814, 0x00bc1715, 0x00bf1715, 0x00c51715, 0x00e71715
	dd	0x00af1716, 0x00b41716, 0x00b61716, 0x00b71716, 0x00a51717, 0x00a61717, 0x00a81717, 0x00ae1717
	dd	0x00981718, 0x009b1718, 0x009d1718, 0x009e1718, 0x00931719, 0x00951719, 0x00961719, 0x00971719
	dd	0x008b171a, 0x008c171a, 0x008d171a, 0x008f171a, 0x0001171b, 0x0087171b, 0x0089171b, 0x008a171b
	dd	0x00e8161c, 0x00e9161c, 0x00c6161d, 0x00e4161d, 0x00be161e, 0x00c4161e, 0x00bb161f, 0x00bd161f
	dd	0x00b91620, 0x00ba1620, 0x00b21621, 0x00b51621, 0x00aa1622, 0x00ad1622, 0x00a41623, 0x00a91623
	dd	0x00a01624, 0x00a31624, 0x009a1625, 0x009c1625, 0x00881626, 0x00921626, 0x00851627, 0x00861627
	dd	0x00811628, 0x00841628, 0x003f0a29, 0x003f0a29, 0x00270b29, 0x002b0b29, 0x00280a2a, 0x00290a2a
	dd	0x00210a2b, 0x00220a2b
httpheaders$huffyE_len = ($ - httpheaders$huffyE) shr 2

dalign
httpheaders$huffyC:
	dd	0xffc00000, 0xffffb000, 0xfffffe20, 0xfffffe30, 0xfffffe40, 0xfffffe50, 0xfffffe60, 0xfffffe70
	dd	0xfffffe80, 0xffffea00, 0xfffffff0, 0xfffffe90, 0xfffffea0, 0xfffffff4, 0xfffffeb0, 0xfffffec0
	dd	0xfffffed0, 0xfffffee0, 0xfffffef0, 0xffffff00, 0xffffff10, 0xffffff20, 0xfffffff8, 0xffffff30
	dd	0xffffff40, 0xffffff50, 0xffffff60, 0xffffff70, 0xffffff80, 0xffffff90, 0xffffffa0, 0xffffffb0
	dd	0x50000000, 0xfe000000, 0xfe400000, 0xffa00000, 0xffc80000, 0x54000000, 0xf8000000, 0xff400000
	dd	0xfe800000, 0xfec00000, 0xf9000000, 0xff600000, 0xfa000000, 0x58000000, 0x5c000000, 0x60000000
	dd	0x00000000, 0x08000000, 0x10000000, 0x64000000, 0x68000000, 0x6c000000, 0x70000000, 0x74000000
	dd	0x78000000, 0x7c000000, 0xb8000000, 0xfb000000, 0xfff80000, 0x80000000, 0xffb00000, 0xff000000
	dd	0xffd00000, 0x84000000, 0xba000000, 0xbc000000, 0xbe000000, 0xc0000000, 0xc2000000, 0xc4000000
	dd	0xc6000000, 0xc8000000, 0xca000000, 0xcc000000, 0xce000000, 0xd0000000, 0xd2000000, 0xd4000000
	dd	0xd6000000, 0xd8000000, 0xda000000, 0xdc000000, 0xde000000, 0xe0000000, 0xe2000000, 0xe4000000
	dd	0xfc000000, 0xe6000000, 0xfd000000, 0xffd80000, 0xfffe0000, 0xffe00000, 0xfff00000, 0x88000000
	dd	0xfffa0000, 0x18000000, 0x8c000000, 0x20000000, 0x90000000, 0x28000000, 0x94000000, 0x98000000
	dd	0x9c000000, 0x30000000, 0xe8000000, 0xea000000, 0xa0000000, 0xa4000000, 0xa8000000, 0x38000000
	dd	0xac000000, 0xec000000, 0xb0000000, 0x40000000, 0x48000000, 0xb4000000, 0xee000000, 0xf0000000
	dd	0xf2000000, 0xf4000000, 0xf6000000, 0xfffc0000, 0xff800000, 0xfff40000, 0xffe80000, 0xffffffc0
	dd	0xfffe6000, 0xffff4800, 0xfffe7000, 0xfffe8000, 0xffff4c00, 0xffff5000, 0xffff5400, 0xffffb200
	dd	0xffff5800, 0xffffb400, 0xffffb600, 0xffffb800, 0xffffba00, 0xffffbc00, 0xffffeb00, 0xffffbe00
	dd	0xffffec00, 0xffffed00, 0xffff5c00, 0xffffc000, 0xffffee00, 0xffffc200, 0xffffc400, 0xffffc600
	dd	0xffffc800, 0xfffee000, 0xffff6000, 0xffffca00, 0xffff6400, 0xffffcc00, 0xffffce00, 0xffffef00
	dd	0xffff6800, 0xfffee800, 0xfffe9000, 0xffff6c00, 0xffff7000, 0xffffd000, 0xffffd200, 0xfffef000
	dd	0xffffd400, 0xffff7400, 0xffff7800, 0xfffff000, 0xfffef800, 0xffff7c00, 0xffffd600, 0xffffd800
	dd	0xffff0000, 0xffff0800, 0xffff8000, 0xffff1000, 0xffffda00, 0xffff8400, 0xffffdc00, 0xffffde00
	dd	0xfffea000, 0xffff8800, 0xffff8c00, 0xffff9000, 0xffffe000, 0xffff9400, 0xffff9800, 0xffffe200
	dd	0xfffff800, 0xfffff840, 0xfffeb000, 0xfffe2000, 0xffff9c00, 0xffffe400, 0xffffa000, 0xfffff600
	dd	0xfffff880, 0xfffff8c0, 0xfffff900, 0xfffffbc0, 0xfffffbe0, 0xfffff940, 0xfffff100, 0xfffff680
	dd	0xfffe4000, 0xffff1800, 0xfffff980, 0xfffffc00, 0xfffffc20, 0xfffff9c0, 0xfffffc40, 0xfffff200
	dd	0xffff2000, 0xffff2800, 0xfffffa00, 0xfffffa40, 0xffffffd0, 0xfffffc60, 0xfffffc80, 0xfffffca0
	dd	0xfffec000, 0xfffff300, 0xfffed000, 0xffff3000, 0xffffa400, 0xffff3800, 0xffff4000, 0xffffe600
	dd	0xffffa800, 0xffffac00, 0xfffff700, 0xfffff780, 0xfffff400, 0xfffff500, 0xfffffa80, 0xffffe800
	dd	0xfffffac0, 0xfffffcc0, 0xfffffb00, 0xfffffb40, 0xfffffce0, 0xfffffd00, 0xfffffd20, 0xfffffd40
	dd	0xfffffd60, 0xffffffe0, 0xfffffd80, 0xfffffda0, 0xfffffdc0, 0xfffffde0, 0xfffffe00, 0xfffffb80
	dd	0xfffffffc
httpheaders$huffyC_len = ($ - httpheaders$huffyC) shr 2

dalign
httpheaders$huffyL:
	db	0x0d, 0x17, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x18, 0x1e, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c
	db	0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c
	db	0x06, 0x0a, 0x0a, 0x0c, 0x0d, 0x06, 0x08, 0x0b, 0x0a, 0x0a, 0x08, 0x0b, 0x08, 0x06, 0x06, 0x06
	db	0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x08, 0x0f, 0x06, 0x0c, 0x0a
	db	0x0d, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
	db	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x07, 0x08, 0x0d, 0x13, 0x0d, 0x0e, 0x06
	db	0x0f, 0x05, 0x06, 0x05, 0x06, 0x05, 0x06, 0x06, 0x06, 0x05, 0x07, 0x07, 0x06, 0x06, 0x06, 0x05
	db	0x06, 0x07, 0x06, 0x05, 0x05, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0b, 0x0e, 0x0d, 0x1c
	db	0x14, 0x16, 0x14, 0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x18, 0x17
	db	0x18, 0x18, 0x16, 0x17, 0x18, 0x17, 0x17, 0x17, 0x17, 0x15, 0x16, 0x17, 0x16, 0x17, 0x17, 0x18
	db	0x16, 0x15, 0x14, 0x16, 0x16, 0x17, 0x17, 0x15, 0x17, 0x16, 0x16, 0x18, 0x15, 0x16, 0x17, 0x17
	db	0x15, 0x15, 0x16, 0x15, 0x17, 0x16, 0x17, 0x17, 0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x16, 0x17
	db	0x1a, 0x1a, 0x14, 0x13, 0x16, 0x17, 0x16, 0x19, 0x1a, 0x1a, 0x1a, 0x1b, 0x1b, 0x1a, 0x18, 0x19
	db	0x13, 0x15, 0x1a, 0x1b, 0x1b, 0x1a, 0x1b, 0x18, 0x15, 0x15, 0x1a, 0x1a, 0x1c, 0x1b, 0x1b, 0x1b
	db	0x14, 0x18, 0x14, 0x15, 0x16, 0x15, 0x15, 0x17, 0x16, 0x16, 0x19, 0x19, 0x18, 0x18, 0x1a, 0x17
	db	0x1a, 0x1b, 0x1a, 0x1a, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1c, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1a
	db	0x1e
httpheaders$huffyL_len = ($ - httpheaders$huffyL) shr 2

end if

