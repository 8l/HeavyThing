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
	; http1.inc: HTTP/1.x handling
	;

if used http1$new | used http1$init | used http1$input | used http1$tobuffer | used http1$tocall | used http1$setbody | defined include_everything


http1_headers_ofs = 0				; a spot to hold a full httpheaders object inline and at 0 so
						; that calls are interchangeable with our same pointer
http1_parsestate_ofs = httpheaders_size		; index into our parsing state
http1_parsedata_ofs = httpheaders_size + 8	; depending on state, parser state information
http1_bodyptr_ofs = httpheaders_size + 16	; pointer to a body if we parsed one
http1_bodylen_ofs = httpheaders_size + 24	; length of same if we parsed one
http1_headerlen_ofs = httpheaders_size + 32	; if we parsed via input, this gets set to the header length _including_ separator


http1_size = httpheaders_size + 40


end if


if used http1$init | defined include_everything
	; single argument in rdi: an http1 object, assumed uninitialized (see reset if you already have a valid one)
	; returns the ptr in rdi in rax
falign
http1$init:
	prolog	http1$init
	call	httpheaders$init
	xor	ecx, ecx
	mov	[rax+http1_parsestate_ofs], rcx
	mov	[rax+http1_parsedata_ofs], rcx
	mov	[rax+http1_bodyptr_ofs], rcx
	mov	[rax+http1_bodylen_ofs], rcx
	mov	[rax+http1_headerlen_ofs], rcx
	epilog

end if


if used http1$reset | defined include_everything
	; single argument in rdi: an already initialized http1 object
falign
http1$reset:
	prolog	http1$reset
	xor	ecx, ecx
	mov	[rdi+http1_parsestate_ofs], rcx
	mov	[rdi+http1_parsedata_ofs], rcx
	mov	[rdi+http1_bodyptr_ofs], rcx
	mov	[rdi+http1_bodylen_ofs], rcx
	mov	[rdi+http1_headerlen_ofs], rcx
	call	httpheaders$reset
	epilog

end if


if used http1$new | defined include_everything
	; no arguments, returns a heap$alloc'd initialized http1 object
falign
http1$new:
	prolog	http1$new
	mov	edi, http1_size
	call	heap$alloc
	mov	rdi, rax
	call	http1$init
	epilog

end if

if used http1$cleanup | defined include_everything
	; single argument in rdi: http1 object
falign
http1$cleanup:
	prolog	http1$cleanup
	call	httpheaders$cleanup
	epilog

end if


if used http1$destroy | defined include_everything
	; single argument in rdi: http1 object
falign
http1$destroy:
	prolog	http1$destroy
	call	httpheaders$destroy
	epilog

end if


if used http1$input | defined include_everything
	; three arguments: rdi == http1 object, rsi == ptr to data, rdx == length of same
	; returns -1 on actual error, 0 on "need more data", >0 on success (meaning, input complete, return is # of bytes we parsed, _from this call, not total_)
	; 0 == we consumed all of the data passed here, but still need more
	; and the purpose for the >0 return is in the event requests are pipelined, in which case
	; there may be another request immediately after this one, and the caller to here needs to know that.
falign
http1$input:
	prolog	http1$input
	xor	eax, eax
	mov	ecx, [rdi+http1_parsestate_ofs]
	push	rbx r12 r13 r14
	test	rdx, rdx
	jz	.return
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	r14, rdx
	jmp	qword [rcx*8+.dispatch]
dalign
.dispatch:
	dq	.inheaders, .partialheaders_direct, .partialheaders_buffer, .inbodylength, .inbodychunked
calign
.inheaders:
	; this is our default state, aka: we have received nothing so far
	; _if_ all of the headers are present in a one-shot to here, this is very efficient
	; otherwise, we have to copy what we receive out, and deal "accumulate" it as we go
	; until we get a successful (or error) parse from httpheaders for it
	call	httpheaders$parse_http1
	; if that returned an error, we do same
	cmp	rax, 0
	jl	.return
	; if that returned 0, we have to setup for partial handling/next round
	je	.inheaders_partialsetup
	; otherwise, that succeeded
	mov	r14, rax			; our return value
	; update our pointers first up
	add	r12, rax
	sub	r13, rax
	
	; set our header length (useful for monitoring/etc outside of here)
	mov	[rbx+http1_headerlen_ofs], rax
	; if we have a Content-Length header, _or_ a Transfer-Encoding: chunked header
	; then we need to continue on to parse the body, otherwise we're done
	mov	rdi, rbx
	mov	rsi, httpheaders$content_length
	call	httpheaders$fast_single_get
	test	rax, rax
	jnz	.headersdone_bodylength
	mov	rdi, rbx
	mov	rsi, httpheaders$transfer_encoding
	call	httpheaders$fast_single_get
	test	rax, rax
	jnz	.headersdone_bodyencoding
	; otherwise, neither exists, so only the header length that we parsed
	mov	rax, r14
	pop	r14 r13 r12 rbx
	epilog
calign
.inheaders_partialsetup:
	; in order for httpheaders$parse_http1 to return 0, it means its initial scan
	; did not detect the header separator, and also means it did _not_ modify ANY of its state
	cmp	r13, httpheaders_size - httpheaders_scratchint_ofs	; the actual scratch area size (4K)
	ja	.inheaders_partialsetup_buffer
	; otherwise, the data we have fits inside our headers object, so we will literally
	; overwrite the httpheaders object until we get more data the next goround
	mov	[rbx+http1_parsedata_ofs], r13
	lea	rdi, [rbx+httpheaders_scratchint_ofs]
	mov	rsi, r12
	mov	edx, r13d
	call	memcpy
	mov	dword [rbx+http1_parsestate_ofs], 1		; takes us to .partialheaders_direct next time around
	; and return 0
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.inheaders_partialsetup_buffer:
	; two case scenarios: with and without a scratch bfufer already
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	test	rdi, rdi
	jnz	.inheaders_partialsetup_buffer_preexisting	; TODO: this should _not_ happen, sanity only
	; otherwise, we need a new one
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	rdi, rax
	mov	rsi, r12
	mov	rdx, r13
	call	buffer$append
	mov	dword [rbx+http1_parsestate_ofs], 2		; takes us to .partialheaders_buffer next time around
	; and return 0
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.inheaders_partialsetup_buffer_preexisting:
	mov	rsi, r12
	mov	rdx, r13
	call	buffer$append
	mov	dword [rbx+http1_parsestate_ofs], 2		; takes us to .partialheaders_buffer next time around
	; and return 0
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.partialheaders_direct:
	; so, we are _not_ the first call to input, the first call (and possibly more) landed, and it
	; fit inside the ~4KB scratch area we have for our yet-unparsed headers object
	
	; _if_ our passed length + our parsedata length fits inside 64KB, copy all of the data to the stack
	; otherwise, we have to buffer it
	; rdx and r13 are both set to our inbound length
	add	rdx, [rbx+http1_parsedata_ofs]
	cmp	rdx, 65536
	ja	.partialheaders_direct_tobuffer
	sub	rsp, 65536
	mov	rdi, rsp
	lea	rsi, [rbx+httpheaders_scratchint_ofs]
	mov	rdx, [rbx+http1_parsedata_ofs]
	call	memcpy
	mov	rcx, [rbx+http1_parsedata_ofs]
	mov	rsi, r12
	mov	rdx, r13
	lea	rdi, [rsp+rcx]
	call	memcpy
	mov	rcx, [rbx+http1_parsedata_ofs]
	mov	rdi, rbx
	mov	rsi, rsp
	lea	rdx, [rcx+r13]
	call	httpheaders$parse_http1
	mov	rcx, [rbx+http1_parsedata_ofs]
	cmp	rax, 0
	jl	.partialheaders_direct_failed
	je	.partialheaders_direct_needmore
	; otherwise, it succeeded, so now we have to determine how much data
	; we actually parsed that was passed to us
	; the body must have been included (part or all) in _this_ call to us
	; so we have to adjust r12/r13, and precompute our return value in case it is pipelined
	mov	[rbx+http1_headerlen_ofs], rax
	mov	r14, r13					; save the original amount of data in this call
	; set r12 to our imaginary beginning + the header length in rax
	sub	r12, rcx
	add	r12, rax
	; set r13 to our imaginary end - the header length, how many bytes _remain_ after the header
	add	r13, rcx
	sub	r13, rax
	; set our return value to our original - that
	sub	r14, r13
	
	add	rsp, 65536					; we don't need our stack anymore, cuz we know the body if any is already here
	; if we have a Content-Length header, _or_ a Transfer-Encoding: chunked header
	; then we need to continue on to parse the body, otherwise we're done
	mov	rdi, rbx
	mov	rsi, httpheaders$content_length
	call	httpheaders$fast_single_get
	test	rax, rax
	jnz	.headersdone_bodylength
	mov	rdi, rbx
	mov	rsi, httpheaders$transfer_encoding
	call	httpheaders$fast_single_get
	test	rax, rax
	jnz	.headersdone_bodyencoding
	; otherwise, neither exists, so only the header length
	mov	rax, r14
	pop	r14 r13 r12 rbx
	epilog
calign
.partialheaders_direct_tobuffer:
	; there is more than 65536 all up that we need to parse (possible that a large body accompanies our goods)
	; so pass everything we've got SO FAR (prior to this call) into a buffer
	; and then let partialheaders_buffer deal with the new data
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	test	rdi, rdi
	jnz	.partialheaders_direct_tobuffer_preexisting	; TODO: this should _not_ happen, sanity only
	; otherwise, we need a new one
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	; copy what we _had_ in
	mov	rdi, rax
	lea	rsi, [rbx+httpheaders_scratchint_ofs]
	mov	rdx, [rbx+http1_parsedata_ofs]
	call	buffer$append
	mov	dword [rbx+http1_parsestate_ofs], 2		; fake that we set the state already
	jmp	.partialheaders_buffer
calign
.partialheaders_direct_tobuffer_preexisting:
	lea	rsi, [rbx+httpheaders_scratchint_ofs]
	mov	rdx, [rbx+http1_parsedata_ofs]
	call	buffer$append
	mov	dword [rbx+http1_parsestate_ofs], 2		; fake that we set the state already
	jmp	.partialheaders_buffer
calign
.partialheaders_direct_failed:
	add	rsp, 65536
	mov	rax, -1
	pop	r14 r13 r12 rbx
	epilog
calign
.partialheaders_direct_needmore:
	; regardless, we are going to dump this all into a buffer if it didn't work the first time
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	test	rdi, rdi
	jnz	.partialheaders_direct_needmore_preexisting	; TODO: this should _not_ happen, sanity only
	; otherwise, we need a new one
	call	buffer$new
	mov	[rbx+httpheaders_scratch_ofs], rax
	; copy everything sitting on the stack in
	mov	rcx, [rbx+http1_parsedata_ofs]
	mov	rdi, rax
	mov	rsi, rsp
	lea	rdx, [rcx+r13]
	call	buffer$append
	; set our state properly now to buffered
	mov	dword [rbx+http1_parsestate_ofs], 2
	; return 0
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog

calign
.partialheaders_buffer:
	; so we already have a scratch buffer filled with data, add what we JUST got to it
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r12
	mov	rdx, r13
	; save the amount of data that _was_ there
	mov	r14, [rdi+buffer_length_ofs]
	call	buffer$append
	; now, because a httpheaders parse may actually write/create/spill into its own
	; scratch buffer, we need to clear the one we have before we let parse get ahold of it
	mov	rcx, [rbx+httpheaders_scratch_ofs]
	mov	rdi, rbx
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	; clear the buffer, possibly temporarily
	push	rcx
	mov	qword [rbx+httpheaders_scratch_ofs], 0
	call	httpheaders$parse_http1
	cmp	rax, 0
	jl	.partialheaders_buffer_failed
	je	.partialheaders_buffer_needmore
	; otherwise, header parsing _succeeded_ for rax amount of bytes
	; similar to our stackbased version, we know that the body _start_ was passed in
	; our current call (meaning it lies within r12/r13 or isn't here yet)
	; so we can safely delete our temporary scratch
	mov	[rbx+http1_headerlen_ofs], rax
	mov	rcx, r14				; the amount that was here before this call
	mov	r14, r13				; save the original amount of data in this call
	; set r12 to our imaginary beginning + the header length in rax
	sub	r12, rcx
	add	r12, rax
	; set r13 to our imaginary end - the header length, how many bytes _remain_ afte rthe header
	add	r13, rcx
	sub	r13, rax
	; set our return value to our original - that
	sub	r14, r13

	; destroy our temporary buffer
	pop	rdi
	call	buffer$destroy
	; if we have a Content-Length header, _or_ a Transfer-Encoding: chunked header
	; then we need to continue on to parse the body, otherwise we're done
	mov	rdi, rbx
	mov	rsi, httpheaders$content_length
	call	httpheaders$fast_single_get
	test	rax, rax
	jnz	.headersdone_bodylength
	mov	rdi, rbx
	mov	rsi, httpheaders$transfer_encoding
	call	httpheaders$fast_single_get
	test	rax, rax
	jnz	.headersdone_bodyencoding
	; otherwise, neither exists, so only the header length
	mov	rax, r14
	pop	r14 r13 r12 rbx
	epilog
calign
.partialheaders_buffer_failed:
	pop	rdi
	call	buffer$destroy
	mov	rax, -1
	pop	r14 r13 r12 rbx
	epilog
calign
.partialheaders_buffer_needmore:
	; put our relocated buffer back where it was
	pop	rcx
	mov	[rbx+httpheaders_scratch_ofs], rcx
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog

calign
.headersdone_bodylength:
	; the headers are complete, we have a Content-Length header that we need to deal with
	; before we return success, and we need to parse all of that into whatever the scratch
	; buffers _END_ pointer is, set our own bodyptr to THAT, and our bodylen to our
	; parsed unsigned int value of the value that we have sitting in rax:rdx
	mov	edi, 10		; radix
	mov	rsi, rax
	call	.atou
	; if the specified length is greater than our config max request size, death
	mov	r8, -1
	cmp	rax, webserver_maxrequest
	cmova	rax, r8
	ja	.return

	; if the amount of data we are presently sitting on (r13) is > the content length (rax)
	; then we have additional data sitting _after_ our body (read: pipelining)
	; and thus we may have to adjust our return value to indicate what we are taking
	lea	r8, [r14+rax]
	cmp	r13, rax
	cmova	r14, r8

	; set our initial parsedata to this, we'll use it to countdown
	mov	[rbx+http1_parsedata_ofs], rax
	mov	[rbx+http1_bodylen_ofs], rax

	; add/create space for the body, noting that we have to _save_ the current length of
	; the scratch buffer if there is already one there
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	test	rdi, rdi
	jz	.headersdone_bodylength_new
	mov	rsi, r12
	mov	rdx, r13
	mov	rcx, [rdi+buffer_length_ofs]
	mov	[rdi+buffer_user_ofs], rcx		; store original length
	; if the amount of data we have is greater than the content length, only append the content length
	cmp	r13, rax
	cmova	rdx, rax
	call	buffer$append
	; so now, set our bodyptr to the buffer's main + original
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	mov	rsi, [rdi+buffer_user_ofs]
	add	rsi, [rdi+buffer_itself_ofs]
	mov	[rbx+http1_bodyptr_ofs], rsi

	; set our state to inbodylength in case we still need more data, and if not, doesn't matter
	mov	dword [rbx+http1_parsestate_ofs], 3	; .inbodylength

	; figure out how much we actually used
	mov	rcx, [rbx+http1_bodylen_ofs]
	mov	rax, r14				; our final return, but only if we don't need more
	xor	edx, edx
	cmp	rcx, r13
	cmova	rcx, r13
	sub	qword [rbx+http1_parsedata_ofs], rcx
	cmovnz	rax, rdx				; if we need more data, zero our return

	pop	r14 r13 r12 rbx
	epilog


calign
.inbodylength:
	; we are waiting for at most parsedata worth of bytes
	; we may have received more than that in r13 (pipelining)
	; we have to add the amount we want, adjust our return value accordingly
	mov	rcx, [rbx+http1_parsedata_ofs]
	; our return value must be only what we consume from it, and there is already a scratch
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r12
	mov	rdx, r13
	; if the amount we have is greater than the amount we need, only add the amount we need
	cmp	r13, rcx
	cmova	rdx, rcx
	mov	r14, rdx	; save our return value
	xor	r8d, r8d
	sub	[rbx+http1_parsedata_ofs], rcx
	cmovnz	r14, r8		; if we still have more data to go after this, we need to return 0
	call	buffer$append
	; reset our bodyptr in case the buffer expanded/relocated itself
	mov	rdi, [rbx+httpheaders_scratch_ofs]	
	mov	rsi, [rdi+buffer_user_ofs]
	add	rsi, [rdi+buffer_itself_ofs]
	mov	[rbx+http1_bodyptr_ofs], rsi
	; all good
	mov	rax, r14
	pop	r14 r13 r12 rbx
	epilog
	
calign
.headersdone_bodyencoding:
	; make sure that the value we got contains hunked, or death on a stick (we'll call it an error
	; simply because we have no way of determining the length if content-length was NOT specified
	; and transfer-encoding was specified, but it isn't chunked.)
	mov	rsi, rax
	mov	rax, -1
	cmp	edx, 7
	jb	.return
	cmp	dword [rsi+1], 'hunk'
	jne	.return
	cmp	word [rsi+5], 'ed'
	jne	.return
	; otherwise, chunked it is, so we have some interesting work to do if we have remaining bytes
	; NOTE: we do _not_ unchunk what we get
	mov	qword [rbx+http1_parsedata_ofs], 0
	mov	dword [rbx+http1_parsestate_ofs], 4		; .inbodychunked
	; make sure we have a scratch buffer to put our data in
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	test	rdi, rdi
	jz	.headersdone_bodyencoding_new
	mov	rcx, [rdi+buffer_length_ofs]
	mov	[rdi+buffer_user_ofs], rcx		; store original length of the scratch if it already existed
	add	rcx, [rdi+buffer_itself_ofs]
	mov	[rbx+http1_bodyptr_ofs], rcx		; set our bodyptr to the current end of the buffer
	mov	qword [rbx+http1_bodylen_ofs], 0	; and our current bodylenth to zero

	xor	eax, eax
	test	r13, r13
	jz	.return					; if we are not sitting on more data, bailout with 0 == needmore
	; otherwise, fallthrough to inbodychunked
calign
.inbodychunked:
	; r12 == ptr to data, r13 == length of same, r14 == our possible return value if we succeed (and thus the parse is complete)
	; NOTE: r12/r13 may not be the INITIAL values (we may have been jumped straight to after another was already parsed)

	; we use parsedata as the offset to the last known-good chunk preface

	; we add this in its entirety to our buffer, then determine whether we are done or need more (and if we are done, whether we
	; need to truncate the buffer contents)
	mov	rdi, [rbx+httpheaders_scratch_ofs]
	mov	rsi, r12
	mov	rdx, r13
	call	buffer$append
	; reset our bodyptr in case the buffer expanded/relocated itself
	mov	rdi, [rbx+httpheaders_scratch_ofs]	
	mov	rsi, [rdi+buffer_user_ofs]
	add	rsi, [rdi+buffer_itself_ofs]
	mov	[rbx+http1_bodyptr_ofs], rsi
	; add r13 to our bodylen before our check
	add	[rbx+http1_bodylen_ofs], r13

	; so now, we have to determine whether we have ALL of the chunked goods yet, error, or needmore
	add	rsi, [rbx+http1_parsedata_ofs]		; offset of the last known-good chunk
	mov	rdx, [rbx+http1_bodylen_ofs]		; total length that we have
	xor	eax, eax
	sub	rdx, [rbx+http1_parsedata_ofs]		; less the length we already scanned
	jz	.return
	cmp	rdx, 5
	jb	.return
	; otherwise, we have enough data to commence our check
	mov	rdi, rsi
	mov	rcx, rdx
calign
.inbodychunked_lengthscan:
	cmp	byte [rdi], ';'
	je	.inbodychunked_semicolon
	cmp	word [rdi], 0xa0d
	je	.inbodychunked_crlf
	add	rdi, 1
	sub	rcx, 1
	cmp	rcx, 4
	jae	.inbodychunked_lengthscan
	; otherwise, we are in a partial preface and need more data
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.inbodychunked_crlf:
	; setup our args to atou
	mov	rdx, rdi
	sub	rdx, rsi
	xor	eax, eax
	cmp	rcx, 2
	jae	.inbodychunked_chunklen_done
	pop	r14 r13 r12 rbx
	epilog
calign
.inbodychunked_semicolon:
	; setup our args to atou, and then scan forward til CRLF
	mov	rdx, rdi
	sub	rdx, rsi				; length of chunk hexchars
	xor	eax, eax
	cmp	rcx, 3
	jb	.return				; need more
	add	rdi, 1
calign
.inbodychunked_semicolon_crlfscan:
	cmp	word [rdi], 0xa0d
	je	.inbodychunked_chunklen_done
	add	rdi, 1
	sub	rcx, 1
	cmp	rcx, 2
	jae	.inbodychunked_semicolon_crlfscan
	; otherwise, need more
	pop	r14 r13 r12 rbx
	epilog
calign
.inbodychunked_chunklen_done:
	; skip the CRLF before we proceed
	add	rdi, 2
	sub	rcx, 2
	; so rdi & rcx are both valid for our body, preserve them for the call to .atou
	push	rdi rsi rcx rdx
	mov	edi, 16
	call	.atou
	lea	rdx, [rax+2]
	xor	r8d, r8d
	pop	r11 rcx rsi rdi
	; the actual amount of data we need is the chunklen + the terminator CRLF
	cmp	rdx, rcx
	cmova	rax, r8
	ja	.return				; need more if we don't have enough goods

	; special care must be taken if we are on the last chunk:
	test	rax, rax
	jz	.inbodychunked_last

	; otherwise, we can figure out where our next chunk preface is

	; the offset is rdi + rdx - rsi
	add	rdx, rdi
	sub	rdx, rsi
	mov	[rbx+http1_parsedata_ofs], rdx
	; set everything up to keep going, which is to say: set rsi to the offset in the body of the next chunk preface
	lea	rsi, [rdi+rax+2]

	; rcx is how much data remains, adjust that by our skipped length too
	sub	rcx, rax
	sub	rcx, 2
	mov	rdx, rcx

	xor	eax, eax
	mov	rdi, rsi
	cmp	rcx, 5
	jae	.inbodychunked_lengthscan
	pop	r14 r13 r12 rbx
	epilog
calign
.inbodychunked_last:
	; if the length of the chunklen in r11 is not precisely 1, error return
	cmp	r11, 1
	jne	.inbodychunked_error

	; otherwise, if rcx < 2, needmore
	cmp	rcx, 2
	jb	.return
	; if the word at rdi is 0xa0d, then we are legitimately done, otherwise we may have trailers
	; in which case we need to scan forward for 0xa0d0a0d
	cmp	word [rdi], 0xa0d
	jne	.inbodychunked_trailers
	; otherwise, and this is messy but required, we have to deal with how _much_ of the CURRENT call to this function
	; we actually consumed... (and the reason that we go through all this trouble is in the event that pipelining is
	; in effect, such that the logical next request/response can be dealt with separately)
	add	rdi, 2
	sub	rcx, 2
	; the simplest case is if there is no extra data after our final CRLF
	jnz	.inbodychunked_last_extradata
	; otherwise, our return in r14 should be fine, we are done
	mov	rax, r14
	pop	r14 r13 r12 rbx
	epilog
calign
.inbodychunked_last_extradata:
	; the data remaining in our buffer is in rcx (and that data does not belong to this request/response)
	; so our goal is to set the return up correctly based on what we got in r14
	; our _total_ length is sitting in bodylen, which we now need to reduce by rcx
	; and we can just reduce the value in r14 by rcx also
	mov	rax, r14
	sub	[rbx+http1_bodylen_ofs], rcx
	sub	rax, rcx
	; we also need to truncate (for good measure really) the actual buffer lengths
	mov	rdx, [rbx+httpheaders_scratch_ofs]
	sub	[rdx+buffer_endptr_ofs], rcx
	sub	[rdx+buffer_length_ofs], rcx
	; done, dusted
	pop	r14 r13 r12 rbx
	epilog
calign
.inbodychunked_trailers:
	; so we got a 0CRLF but it wasn't followed by a final CRLF, trailers must be present
	cmp	rcx, 4
	jb	.return			; needmore if there isn't enough for a complete CRLF
	cmp	dword [rdi], 0xa0d0a0d
	je	.inbodychunked_trailersdone
	add	rdi, 1
	sub	rcx, 1
	jmp	.inbodychunked_trailers
calign
.inbodychunked_trailersdone:
	add	rdi, 4
	sub	rcx, 4
	jnz	.inbodychunked_last_extradata
	; otherwise, our return in r14 should be fine, we are done
	mov	rax, r14
	pop	r14 r13 r12 rbx
	epilog


calign
.inbodychunked_error:
	mov	rax, -1
	pop	r14 r13 r12 rbx
	epilog
calign
.headersdone_bodyencoding_new:
	call	buffer$new
	mov	rcx, [rax+buffer_itself_ofs]
	mov	[rbx+httpheaders_scratch_ofs], rax
	mov	qword [rax+buffer_user_ofs], 0		; set the original length to zero (when we add to it this will get updated)
	mov	[rbx+http1_bodyptr_ofs], rcx
	mov	qword [rbx+http1_bodylen_ofs], 0
	xor	eax, eax
	test	r13, r13
	jnz	.inbodychunked

	pop	r14 r13 r12 rbx
	epilog

calign
.return:
	pop	r14 r13 r12 rbx
	epilog
falign
.atou:
	; edi == radix, rsi == pointer to latin1 string, edx == NONZERO length of same, EAX MUST BE CLEARED ON ENTRY!!
	; this skips leading spaces
	movzx	ecx, byte [rsi]
	mov	r9d, edx
	mov	r8d, 1
	cmp	ecx, 32
	ja	.atou_doit
	sub	ecx, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.atou_doit
	; otherwise, 32, 9, 10, or 13
	add	rsi, 1
	sub	r9d, 1
	jnz	.atou
	; if we made it to here, no non-WS chars, bailout
	ret
calign
.atou_doit:
	movzx	ecx, byte [rsi]
	add	rsi, 1
	cmp	ecx, '0'
	jb	.atou_bad
	cmp	ecx, '9'
	jbe	.atou_numeric
	cmp	ecx, 'A'
	jb	.atou_bad
	cmp	ecx, 'F'
	jbe	.atou_caphex
	cmp	ecx, 'a'
	jb	.atou_bad
	cmp	ecx, 'f'
	jbe	.atou_hex
	; invalid if we made it here
	ret
calign
.atou_numeric:
	sub	ecx, '0'
	mul	rdi
	add	rax, rcx
	sub	r9d, 1
	jnz	.atou_doit
	ret
calign
.atou_caphex:
	sub	ecx, 'A' - 10
	mul	rdi
	add	rax, rcx
	sub	r9d, 1
	jnz	.atou_doit
	ret
calign
.atou_hex:
	sub	ecx, 'a' - 10
	mul	rdi
	add	rax, rcx
	sub	r9d, 1
	jnz	.atou_doit
	ret
calign
.atou_bad:
	ret

end if



if used http1$setbody | defined include_everything
	; three arguments: rdi == http1 object, rsi == ptr to body, rdx == length of same
	; NOTE: rsi/rdx must exist for the lifetime of the http1 object
	; NOTE 2: this is mainly just a reference, set them externally rather than calling this
falign
http1$setbody:
	prolog	http1$setbody
	mov	[rdi+http1_bodyptr_ofs], rsi
	mov	[rdi+http1_bodylen_ofs], rdx
	epilog

end if



if used http1$tobuffer | defined include_everything
	; three arguments: rdi == http1 object, rsi == destination buffer object, rdx == how much data to put in
	; this effectively "composes" the http1 object into the destination buffer
	; returns # of bytes we wrote (if < rdx, no more to go)
falign
http1$tobuffer:
	prolog	http1$tobuffer
	mov	rcx, rdx
	mov	rdx, rsi
	mov	rsi, buffer$append
	call	http1$tocall
	epilog

end if



if used http1$tocall | defined include_everything
	; four arguments: rdi == http1 object, rsi == function to call, rdx == argument to pass in rdi for the call, rcx == how much data to put in
	; this effectively "composes" the http1 object, and calls the specified function with rsi/rdx for data
	; returns # of bytes we sent (if < rcx, no more to go)
falign
http1$tocall:
	prolog	http1$tocall
	epilog

end if
