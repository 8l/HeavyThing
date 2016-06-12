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
	;       minigzip.asm: HeavyThing gzip demo
	;
	;	with one arguments, will compress whatever filename it is passed and
	;	send the compressed results to stdout
	;
	;	with two arguments, will uncompress the last argument and
	;	send the uncompressed results to stdout
	;
	;	NOTE: our compression level is a compile-time constant for
	;	the HeavyThing library and defaults to 6, same as the real gzip
	;
	; first things first, include the library defaults, and the
	; library main include:
include '../../ht_defaults.inc'
include '../../ht.inc'

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	cmp	dword [argc], 1
	je	.needinputfile

	; regardless of whether we are inflating or deflating, last arg must be
	; our input file (noting here we could go through a lot more effort for
	; argument parsing of course, but for a minigzip, simple works fine)
	mov	rdi, [argv]
	call	list$pop_back
	; pass that straight to privmapped to get a private mmap of it
	mov	rdi, rax
	xor	esi, esi
	call	privmapped$new
	test	rax, rax
	jz	.badinputfile
	; save our privmapped object
	mov	rbx, rax

	; the HeavyThing zlib requires buffer objects for its i/o
	; since we don't really need/want to read the entire file from our
	; privmapped object into a separate buffer object, we'll create a
	; "fake" buffer object, since we know the zlib routines do not actually
	; modify the input
	call	buffer$new
	; save our buffer object
	mov	r12, rax
	; get our privmapped base and size
	mov	rdx, [rbx+privmapped_base_ofs]
	mov	rcx, [rbx+privmapped_size_ofs]
	; save the actual buffer object for later retrieval
	mov	r13, [rax+buffer_itself_ofs]
	; now set the buffer object's goods to our privmapped object's
	mov	[rax+buffer_itself_ofs], rdx
	mov	[rax+buffer_length_ofs], rcx
	mov	[rax+buffer_size_ofs], rcx

	; additionally, we need an output buffer
	call	buffer$new
	; hangon to our output buffer object as well
	mov	r14, rax

	; now determine whether we are inflating or deflating
	cmp	dword [argc], 2
	jne	.inflate

	; otherwise, deflate it is, use the stack for our zlib_stream
	sub	rsp, zlib_stream_size
	mov	rdi, rsp
	; zlib requires a wrap level to determine what headers if any to use
	; wrap == 2 == gzip
	mov	esi, 2
	call	zlib$deflateInit

	; set the inbuf and outbuf
	mov	[rsp+zlib_inbuf_ofs], r12
	mov	[rsp+zlib_outbuf_ofs], r14

	; do the deflate deed
	mov	rdi, rsp
	mov	esi, zlib_finish
	call	zlib$deflate

	; cleanup our zlib state
	mov	rdi, rsp
	call	zlib$deflateEnd
	add	rsp, zlib_stream_size

	; cleanup the rest and output the results
	jmp	.allgood
calign
.inflate:
	sub	rsp, zlib_stream_size
	mov	rdi, rsp
	; zlib requires a wrap level to determine what headers if any to use
	; wrap == 2 == gzip
	mov	esi, 2
	call	zlib$inflateInit

	; set the inbuf and outbuf
	mov	[rsp+zlib_inbuf_ofs], r12
	mov	[rsp+zlib_outbuf_ofs], r14

	; do the inflate deed
	mov	rdi, rsp
	mov	esi, zlib_finish
	call	zlib$inflate

	; cleanup our zlib state
	mov	rdi, rsp
	call	zlib$inflateEnd
	add	rsp, zlib_stream_size

calign
.allgood:
	; restore the buffer's original pointer
	mov	[r12+buffer_itself_ofs], r13
	; cleanup the buffer and privmapped objects
	mov	rdi, r12
	call	buffer$destroy
	mov	rdi, rbx
	call	privmapped$destroy

	; all thats left is our output
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [r14+buffer_itself_ofs]
	mov	rdx, [r14+buffer_length_ofs]
	syscall

	mov	rdi, r14
	call	buffer$destroy

	mov	eax, syscall_exit
	xor	edi, edi
	syscall

calign
.badinputfile:
	mov	rdi, .badinput
	call	string$to_stderrln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .badinput, 'unable to open input file'
calign
.needinputfile:
	mov	rdi, .inputfile
	call	string$to_stderrln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .inputfile, 'input filename required.'

	; include the global data segment:
include '../../ht_data.inc'

