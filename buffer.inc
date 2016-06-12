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
	; buffer.inc: byte buffer goods with some extra conveniences
	;

	; every buffer object contains a few goodies:
buffer_endptr_ofs = 0
buffer_length_ofs = 8
buffer_itself_ofs = 16
buffer_size_ofs = 24
buffer_user_ofs = 32			; 24 bytes here that we don't use

buffer_object_size = 56

buffer_default_size = 256		; how large is the actual initial buffer by default?


if used buffer$new | defined include_everything
	;  no arguments, returns new initialized buffer in rax
falign
buffer$new:
	prolog	buffer$new
	mov	rdi, buffer_object_size
	call	heap$alloc
	push	rax
	mov	rdi, buffer_default_size
	call	heap$alloc
	mov	rdi, rax
	pop	rax
	xor	edx, edx
	mov	[rax+buffer_endptr_ofs], rdi
	mov	[rax+buffer_length_ofs], rdx
	mov	[rax+buffer_itself_ofs], rdi
	mov	qword [rax+buffer_size_ofs], buffer_default_size
	; leave the user 16 bytes alone
	; return in rax is good
	epilog
end if


if used buffer$destroy | defined include_everything
	; single arg in rdi: buffer object
falign
buffer$destroy:
	prolog	buffer$destroy
	push	rdi
	mov	rdi, [rdi+buffer_itself_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	epilog
end if


if used buffer$copy | defined include_everything
	; single arg in rdi: makes a clone of this buffer and returns the new one in rax
falign
buffer$copy:
	prolog	buffer$copy
	sub	rsp, 16
	mov	[rsp], rdi
	mov	rdi, [rdi+buffer_size_ofs]
	call	heap$alloc
	mov	[rsp+8], rax
	mov	rdi, buffer_object_size
	call	heap$alloc
	mov	rsi, [rsp+8]		; the buffer itself
	mov	rdx, rsi
	mov	rdi, [rsp]
	add	rdx, qword [rdi+buffer_length_ofs]
	mov	[rax+buffer_endptr_ofs], rdx
	mov	rdx, qword [rdi+buffer_length_ofs]
	mov	[rax+buffer_length_ofs], rdx
	mov	[rax+buffer_itself_ofs], rsi
	mov	rdx, [rdi+buffer_size_ofs]
	mov	rcx, [rdi+buffer_user_ofs]
	mov	r8, [rdi+buffer_user_ofs+8]
	mov	[rax+buffer_size_ofs], rdx
	mov	[rax+buffer_user_ofs], rcx
	mov	[rax+buffer_user_ofs+8], r8
	; now we need to preserve oru return in rax, then issue a memcpy
	mov	rdx, [rdi+buffer_length_ofs]
	mov	[rsp], rax
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdi, [rax+buffer_itself_ofs]
	call	memcpy
	mov	rax, [rsp]
	add	rsp, 16
	epilog
end if


if used buffer$reset_reserve | defined include_everything
	; two arguments: rdi == buffer object, rsi == length to reserve/verify enough space for
falign
buffer$reset_reserve:
	prolog	buffer$reset_reserve
	push	rdi
	call	buffer$reserve
	pop	rdi
	call	buffer$reset
	epilog

end if


if used buffer$reserve | defined include_everything
	; two arguments: rdi == buffer object, rsi == length to reserve/verify enough space for
falign
buffer$reserve:
	prolog	buffer$reserve
	mov	r8, [rdi+buffer_size_ofs]
	mov	r9, [rdi+buffer_length_ofs]
	mov	rdx, r8
	sub	rdx, r9
	shl	r8, 1
	cmp	rdx, rsi
	jb	.needmore
	epilog
calign
.needmore:
	mov	rdx, r8
	sub	rdx, r9
	cmp	rdx, rsi
	jae	.increase
	; else, we need to make it bigger
	shl	r8, 1
	jmp	.needmore
calign
.increase:
	; r8 has our new size, r9 has our length
	; we want [rsp] to be rdi, and [rsp+8] to be [rdi+buffer_itself_ofs] , and [rsp+16] to be the new size
	push	r8
	push	qword [rdi+buffer_itself_ofs]
	push	rdi
	mov	rdi, r8
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rdx, [rsp+16]
	mov	[rdi+buffer_size_ofs], rdx
	mov	r9, [rdi+buffer_length_ofs]
	mov	[rdi+buffer_itself_ofs], rax
	add	rax, r9
	mov	[rdi+buffer_endptr_ofs], rax
	test	r9, r9
	jz	.increase_nocopy
	sub	rax, r9
	mov	rdx, r9		; length
	mov	rdi, rax	; destination buffer
	mov	rsi, [rsp+8]	; old buffer
	call	memcpy
	mov	rdi, [rsp+8]	; old buffer
	call	heap$free
	add	rsp, 24
	epilog
calign
.increase_nocopy:
	; length of old spot was zero, but we did increase the buffer
	; so all we need to do is free the old one
	mov	rdi, [rsp+8]
	call	heap$free
	add	rsp, 24
	epilog
end if


if used buffer$reset | defined include_everything
	; single arg rdi: buffer object, sets length to 0 and resets endptr back to the beginning
falign
buffer$reset:
	prolog	buffer$reset
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	qword [rdi+buffer_length_ofs], 0
	mov	[rdi+buffer_endptr_ofs], rsi
	epilog
end if


if used buffer$truncate | defined include_everything
	; two arguments: rdi: buffer object, rsi: number of bytes to remove from the end
falign
buffer$truncate:
	prolog	buffer$truncate
	mov	rcx, [rdi+buffer_length_ofs]
	mov	rdx, [rdi+buffer_endptr_ofs]
	cmp	rsi, rcx
	jae	.resetonly
	sub	rcx, rsi
	sub	rdx, rsi
	mov	[rdi+buffer_length_ofs], rcx
	mov	[rdi+buffer_endptr_ofs], rdx
	epilog
calign
.resetonly:
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	qword [rdi+buffer_length_ofs], 0
	mov	[rdi+buffer_endptr_ofs], rsi
	epilog
end if


if used buffer$consume | defined include_everything
	; two arguments: rdi: buffer object, rsi: number of bytes to remove from the head of the buffer
falign
buffer$consume:
	prolog	buffer$consume
	test	rsi, rsi
	jz	.nothingtodo
	mov	rcx, [rdi+buffer_length_ofs]
	cmp	rsi, rcx
	jae	.resetonly
	mov	r8, [rdi+buffer_itself_ofs]
	mov	rdx, rcx
	mov	r9, r8
	sub	rdx, rsi				; the new nonzero length, and also the size arg for our memmove
	add	rsi, r8					; the source pointer for our memmove
	add	r9, rdx
	mov	[rdi+buffer_length_ofs], rdx
	mov	[rdi+buffer_endptr_ofs], r9
	mov	rdi, [rdi+buffer_itself_ofs]		; the destination
	call	memmove
	epilog
calign
.resetonly:
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	qword [rdi+buffer_length_ofs], 0
	mov	[rdi+buffer_endptr_ofs], rsi
.nothingtodo:
	epilog
end if


if used buffer$append_nocopy | defined include_everything
	; two arguments: rdi: buffer object, rsi: number of bytes to move endptr and length forward by
falign
buffer$append_nocopy:
	prolog	buffer$append_nocopy
	add	qword [rdi+buffer_length_ofs], rsi
	add	qword [rdi+buffer_endptr_ofs], rsi
	epilog
end if


if used buffer$append | defined include_everything
	; three arguments: rdi: buffer object, rsi: source byte buffer, rdx: source byte buffer length (void *, whatever)
falign
buffer$append:
	prolog	buffer$append
	test	rdx, rdx
	jz	.nothingtodo
	; we want [rsp] to be rdi, [rsp+8] to be rsi, [rsp+16] to be rdx
	push	rdx rsi rdi
	mov	rsi, rdx
	call	buffer$reserve
	pop	rdi rsi rdx
	mov	rcx, rdi
	mov	rdi, [rdi+buffer_endptr_ofs]
	add	qword [rcx+buffer_endptr_ofs], rdx
	add	qword [rcx+buffer_length_ofs], rdx
	call	memcpy
	epilog
calign
.nothingtodo:
	epilog
end if


if used buffer$insert | defined include_everything
	; four arguments: rdi == buffer object, rsi == offset, rdx == source byte buffer, rcx == source byte buffer length
falign
buffer$insert:
	prolog	buffer$insert
	cmp	rsi, [rdi+buffer_length_ofs]
	jae	.append
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	rsi, rcx
	call	buffer$reserve
	; make sure the offset is valid
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rsi, rdx
	cmova	rsi, rdx
	mov	[rsp+8], rsi
	; move the contents, only if rsi != buffer_length_ofs
	jae	.nomove
	sub	rdx, rsi			; bytes remaining from offset to end of what was there, bytecount of move
	; source of move is buffer[offset]
	add	rsi, [rdi+buffer_itself_ofs]
	; destination of move is buffer[offset+sourcelength]
	mov	rdi, rsi
	add	rdi, [rsp+24]
	call	memmove
calign
.nomove:
	mov	rdi, [rsp]
	mov	rsi, [rsp+16]
	mov	rdx, [rsp+24]
	mov	rdi, [rdi+buffer_itself_ofs]
	add	rdi, [rsp+8]
	call	memcpy
	; update our buffer length and endptr offset by the source length
	mov	rdi, [rsp]
	mov	rcx, [rsp+24]
	add	qword [rdi+buffer_length_ofs], rcx
	add	qword [rdi+buffer_endptr_ofs], rcx
	add	rsp, 32
	epilog
calign
.append:
	mov	rsi, rdx
	mov	rdx, rcx
	call	buffer$append
	epilog

end if

if used buffer$remove | defined include_everything
	; three arguments: rdi == buffer object, rsi == offset, rdx == length to remove from it
falign
buffer$remove:
	prolog	buffer$remove
	sub	rsp, 24
	mov	rcx, [rdi+buffer_length_ofs]
	mov	rax, rsi
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	; if the offset is past the end, don't do anything
	cmp	rsi, rcx
	jae	.alldone
	; make sure the amount to remove isn't out of bounds either
	; if (offset+length to remove >= current length) truncate length to offset and be done
	add	rax, rdx
	cmp	rax, rcx
	jae	.truncate
	; otherwise, our new length is our current length - rdx, our move destination is buffer[offset], our source is buffer[offset+lengthtoremove]
	; and our move count is current length - (offset+length)
	mov	r8, rcx				; current length
	mov	r9, rsi				; offset
	sub	r8, rdx				; current length - lengthtoremove
	add	r9, rdx				; offset + lengthtoremove
	mov	[rdi+buffer_length_ofs], r8	; new length is current length - length to remove
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	r10, rsi
	add	r10, r8
	mov	[rdi+buffer_endptr_ofs], r10
	sub	rcx, r9				; move count = current length - (offset + length to remove)
	add	rsi, r9				; source of move = offset + length to remove
	mov	rdi, [rdi+buffer_itself_ofs]
	add	rdi, [rsp+8]
	mov	rdx, rcx
	call	memmove
	add	rsp, 24
	epilog
calign
.alldone:
	add	rsp, 24
	epilog
calign
.truncate:
	mov	rax, [rdi+buffer_itself_ofs]
	mov	[rdi+buffer_length_ofs], rsi
	add	rax, rsi
	mov	[rdi+buffer_endptr_ofs], rax
	add	rsp, 24
	epilog

end if



if used buffer$append_byte | defined include_everything
	; two arguments: rdi: buffer object, esi (sil): byte to append
falign
buffer$append_byte:
	prolog	buffer$append_byte
	push	rdi rsi
	mov	esi, 1
	call	buffer$reserve
	pop	rsi rdi
	mov	rdx, [rdi+buffer_endptr_ofs]
	mov	byte [rdx], sil
	add	qword [rdi+buffer_endptr_ofs], 1
	add	qword [rdi+buffer_length_ofs], 1
	epilog
end if


if used buffer$append_byte_noreserve | defined include_everything
	; same as the above, but we do not call reserve (useful if you do that in advance)
falign
buffer$append_byte_noreserve:
	prolog	buffer$append_byte_noreserve
	mov	rdx, [rdi+buffer_endptr_ofs]
	mov	byte [rdx], sil
	add	qword [rdi+buffer_endptr_ofs], 1
	add	qword [rdi+buffer_length_ofs], 1
	epilog

end if

if used buffer$append_word | defined include_everything
	; two arguments: rdi: buffer object, si: word to append
falign
buffer$append_word:
	prolog	buffer$append_word
	push	rdi rsi
	mov	esi, 2
	call	buffer$reserve
	pop	rsi rdi
	mov	rdx, [rdi+buffer_endptr_ofs]
	mov	word [rdx], si
	add	qword [rdi+buffer_endptr_ofs], 2
	add	qword [rdi+buffer_length_ofs], 2
	epilog
end if

if used buffer$append_dword | defined include_everything
	; two arguments: rdi: buffer object, esi: dword to append
falign
buffer$append_dword:
	prolog	buffer$append_dword
	push	rdi rsi
	mov	esi, 4
	call	buffer$reserve
	pop	rsi rdi
	mov	rdx, [rdi+buffer_endptr_ofs]
	mov	dword [rdx], esi
	add	qword [rdi+buffer_endptr_ofs], 4
	add	qword [rdi+buffer_length_ofs], 4
	epilog
end if


if used buffer$append_qword | defined include_everything
	; two arguments: rdi: buffer object, rsi: qword to append
falign
buffer$append_qword:
	prolog	buffer$append_qword
	push	rdi rsi
	mov	esi, 8
	call	buffer$reserve
	pop	rsi rdi
	mov	rdx, [rdi+buffer_endptr_ofs]
	mov	qword [rdx], rsi
	add	qword [rdi+buffer_endptr_ofs], 8
	add	qword [rdi+buffer_length_ofs], 8
	epilog
end if


if used buffer$append_double | defined include_everything
	; two arguments: rdi: buffer object, xmm0: double to append
falign
buffer$append_double:
	prolog	buffer$append_double
	sub	rsp, 16
	mov	[rsp], rdi
	movq	[rsp+8], xmm0
	mov	esi, 8
	call	buffer$reserve
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rdi+buffer_endptr_ofs]
	mov	qword [rdx], rsi
	add	qword [rdi+buffer_endptr_ofs], 8
	add	qword [rdi+buffer_length_ofs], 8
	epilog
end if

if used buffer$append_string | defined include_everything
	; two arguments: rdi: buffer object, rsi: string object
	; NOTE: does a utf8 conversion of the string object into the buffer
falign
buffer$append_string:
	prolog	buffer$append_string

if defined buffer_append_string_conservative
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	rdi, rsi
	call	string$utf8_length
	mov	[rsp+16], rax
	mov	rsi, rax
	mov	rdi, [rsp]
	call	buffer$reserve
	mov	rsi, [rsp]
	mov	rsi, [rsi+buffer_endptr_ofs]
	mov	rdi, [rsp+8]
	call	string$to_utf8
	mov	rdi, [rsp]
	mov	rax, [rsp+16]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 24
	epilog
else
	; this version is considerably faster, but wastes space w/ buffer$reserve
	push	rbx rsi
	mov	rbx, rdi
	mov	rsi, [rsi]
if string_bits = 32
	shl	rsi, 2
else
	shl	rsi, 1
end if
	call	buffer$reserve
	pop	rdi
	mov	rsi, [rbx+buffer_endptr_ofs]
	call	string$to_utf8
	add	qword [rbx+buffer_endptr_ofs], rax
	add	qword [rbx+buffer_length_ofs], rax
	pop	rbx
	epilog
end if

end if


if used buffer$append_rawstring_noreserve | defined include_everything
	; two arguments: rdi == buffer object, rsi: string object
	; NOTE: does not do a utf8 conversion, but takes characters only out of the string (does not call reserve either)
falign
buffer$append_rawstring_noreserve:
	prolog	buffer$append_rawstring_noreserve
	cmp	qword [rsi], 0
	je	.nothingtodo
	mov	rdx, [rsi]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	; modified copy of buffer$append here:
	mov	rcx, rdi
	mov	rdi, [rdi+buffer_endptr_ofs]
	add	qword [rcx+buffer_endptr_ofs], rdx
	add	qword [rcx+buffer_length_ofs], rdx
	call	memcpy
	epilog
calign
.nothingtodo:
	epilog

end if


if used buffer$append_rawstring | defined include_everything
	; two arguments: rdi == buffer object, rsi: string object
	; NOTE: does not do a utf8 conversion, but takes the characters only out of the string
falign
buffer$append_rawstring:
	prolog	buffer$append_rawstring
	cmp	qword [rsi], 0
	je	.nothingtodo
	mov	rdx, [rsi]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	epilog
calign
.nothingtodo:
	epilog

end if


if used buffer$append_hexdecode | defined include_everything
	; two arguments: rdi: buffer object, rsi: string object that contains hex chars only
	; NOTE: input must be sensible, but we skip whitespace (not _between_ 4 bits)
	; returns # of bytes it added to the buffer
falign
buffer$append_hexdecode:
	prolog	buffer$append_hexdecode
	push	rsi rdi
	mov	rsi, [rsi]	; length of the string in characters
	shr	rsi, 1		; in bytes that we'll need room for
	call	buffer$reserve
	mov	rdx, [rsp]
	mov	rdi, [rsp+8]	; source string
	mov	rsi, [rdx+buffer_endptr_ofs]
	call	string$hexdecode	; will return # of bytes it wrote
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 16
	epilog

end if


if used buffer$append_hexdecode_latin1 | defined include_everything
	; this is the same as above, only instead of the source being a native string
	; it is a pointer/length that contains latin1 of the source hex

	; three arguments: rdi: buffer object, rsi: pointer to buffer with latin1 hexchars, rdx: length of same
	; NOTE: input must be sensible, but we skip whitespace (not _between_ 4 bits)
	; returns # of bytes it added to the buffer
falign
buffer$append_hexdecode_latin1:
	prolog	buffer$append_hexdecode_latin1
	xor	eax, eax
	test	rdx, rdx
	jz	.nothingtodo
	push	rdx rsi rdi
	mov	rsi, rdx
	shr	rsi, 1		; in bytes that we'll need room for
	call	buffer$reserve
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rcx, [rsp+16]
	mov	rdi, [rdi+buffer_itself_ofs]
	xor	eax, eax
calign
.doit:
	movzx	edx, word [rsi]
	mov	r8d, edx
	and	edx, 0xff
	shr	r8d, 8
	sub	rcx, 1
	jz	.bailout
	
	cmp	edx, 32
	jbe	.whitespaceordie

	add	rsi, 2
	cmp	edx, 48
	jb	.bailout
	cmp	r8d, 48
	jb	.bailout
	cmp	edx, 102
	ja	.bailout
	cmp	r8d, 102
	ja	.bailout
	sub	edx, 48
	sub	r8d, 48

	mov	r11d, edx
	sub	r11d, 39
	cmp	edx, 10
	cmovb	r9d, edx
	cmovae	r9d, r11d
	test	r9d, 0xf0
	jnz	.bailout

	mov	r11d, r8d
	sub	r11d, 39
	cmp	r8d, 10
	cmovb	r10d, r8d
	cmovae	r10d, r11d
	test	r10d, 0xf0
	jnz	.bailout

	shl	r9d, 4
	or	r9d, r10d
	mov	byte [rdi], r9b
	add	rdi, 1
	add	rax, 1

	sub	rcx, 1	
	jnz	.doit
	; else, done
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 24
	epilog
calign
.whitespaceordie:
	add	rsi, 1
	cmp	edx, 32
	je	.doit
	cmp	edx, 13
	je	.doit
	cmp	edx, 10
	je	.doit
	cmp	edx, 9
	je	.doit
	; fallthrough to bailout
calign
.bailout:
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 24
	epilog
calign
.nothingtodo:
	epilog

end if


if used buffer$append_hexencode_latin1 | defined include_everything
	; this is similar to string$from_bintohex, only we don't bother with creating a native string
	; and instead, write latin1 chars directly to our buffer

	; three arguments: rdi: buffer object, rsi: pointer to byte buffer, rdx: length of same
	; returns # of latin1 characters we added to the buffer
falign
buffer$append_hexencode_latin1:
	prolog	buffer$append_hexencode_latin1
	test	rdx, rdx
	jz	.nothingtodo
	push	rdx rsi rdi
	mov	rsi, rdx
	shl	rsi, 1		; 2 characters per byte of input
	call	buffer$reserve
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rcx, [rsp+16]
	mov	rdi, [rdi+buffer_itself_ofs]
	xor	eax, eax
calign
.doit:
	movzx	edx, byte [rsi]
	add	rsi, 1
	mov	r8d, edx
	and	edx, 0xf
	shr	r8d, 4
if string_bits = 32
	mov	r9d, dword [rdx*4+.hexchars+8]
	mov	r10d, dword [r8*4+.hexchars+8]
else
	movzx	r9d, word [rdx*2+.hexchars+8]
	movzx	r10d, word [r8*2+.hexchars+8]
end if
	shl	r10d, 8
	or	r9d, r10d
	mov	word [rdi], r9w
	add	rdi, 2
	add	rax, 2
	sub	rcx, 1
	jnz	.doit
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 24
	epilog
calign
.nothingtodo:
	xor	eax, eax
	epilog
cleartext .hexchars, '0123456789abcdef'

end if


if used buffer$append_base64decode | defined include_everything
	; three arguments: rdi: buffer object, rsi: string object that contains the base64 encoding, rdx == 0 == default base64 table, else rdx == custom base64 table
	; returns # of bytes it added to the buffer
falign
buffer$append_base64decode:
	prolog	buffer$append_base64decode
	push	rdx rsi rdi
	mov	rdx, [rsi]
	mov	rsi, rdx
	shr	rdx, 2
	sub	rsi, rdx		; length in characters - 25% is how many bytes we'll need to reserve space for
	add	rsi, 32			; plus a bit for good measure
	call	buffer$reserve
	mov	rdx, [rsp]
	mov	rdi, [rsp+8]		; source string
	mov	rsi, [rdx+buffer_endptr_ofs]
	mov	rdx, [rsp+16]
	call	string$base64decode	; will return # of bytes it wrote
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 24
	epilog

end if



if used buffer$append_base64tobin_latin1 | defined include_everything
	; four arguments: rdi: buffer object, rsi: pointer to buffer with latin1 base64 chars, rdx: length of same, rcx == 0 == default base64 table, else rcx == custom base64 table
	; NOTE: we reserve the same # of bytes as the input, though wasteful... TODO: chop by 25% instead, which should still be safe
	; returns # of bytes we added to the buffer
falign
buffer$append_base64tobin_latin1:
	prolog	buffer$append_base64tobin_latin1
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	rsi, rdx
	call	buffer$reserve
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+16]
	mov	rcx, [rsp+24]
	mov	rdx, [rsp]
	mov	rdx, [rdx+buffer_itself_ofs]
	call	base64$decode_latin1
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 32
	epilog

end if


if used buffer$append_bintobase64_latin1 | defined include_everything
	; this is similar to string$from_bintobase64, only we don't bother with creating a native string
	; and instead write latin1 base64 chars directly to the buffer

	; four arguments: rdi: buffer object, rsi: pointer to byte buffer, rdx: length of same, rcx == 0 == default base64 table, else, rcx == STRING custom base64 table
	; returns # of latin1 base64 characters we added to the buffer
falign
buffer$append_bintobase64_latin1:
	prolog	buffer$append_bintobase64_latin1
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	rdi, rdx
	call	base64$encode_length
	mov	rdi, [rsp]
	mov	rsi, rax
	call	buffer$reserve
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+16]	
	mov	rdx, [rsp]
	mov	rcx, [rsp+24]
	mov	rdx, [rdx+buffer_itself_ofs]
	call	base64$encode_latin1
	mov	rdi, [rsp]
	add	qword [rdi+buffer_endptr_ofs], rax
	add	qword [rdi+buffer_length_ofs], rax
	add	rsp, 32
	epilog

end if



if used buffer$has_more_lines | defined include_everything
	; two arguments: rdi: buffer object, bool in esi as to whether or not we should consume leading empty lines (you probably want this)
	; TODO: make this multibyte instead of the slow char-by-char method, lazy boy.
falign
buffer$has_more_lines:
	prolog	buffer$has_more_lines
	test	esi, esi
	jnz	.consumeleadingempties
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_endptr_ofs]
	cmp	rsi, rdx
	je	.falseret
calign
.while:
	cmp	rsi, rdx
	jae	.falseret
	mov	al, byte [rsi]
	cmp	al, 13
	je	.trueret
	cmp	al, 10
	je	.trueret
	add	rsi, 1
	jmp	.while
calign
.falseret:
	xor	eax, eax
	epilog
calign
.trueret:
	mov	eax, 1
	epilog
calign
.consumeleadingempties:
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_endptr_ofs]
	cmp	rsi, rdx
	je	.falseret
calign
.consumewhile:
	cmp	rsi, rdx
	jae	.consumewhiledone
	mov	al, byte [rsi]
	cmp	al, 13
	je	.consumewhilenext
	cmp	al, 10
	je	.consumewhilenext
	; else, consumewhiledone:
	cmp	rsi, [rdi+buffer_itself_ofs]
	jne	.doconsume
	cmp	rsi, rdx
	jae	.falseret
	jmp	.while
calign
.consumewhilenext:
	add	rsi, 1
	jmp	.consumewhile
calign
.consumewhiledone:
	cmp	rsi, [rdi+buffer_itself_ofs]
	jne	.doconsume
	cmp	rsi, rdx
	jae	.falseret
	jmp	.while
calign
.doconsume:
	push	rdi
	sub	rsi, qword [rdi+buffer_itself_ofs]
	call	buffer$consume
	pop	rdi
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_endptr_ofs]
	cmp	rsi, rdx
	jae	.falseret
	jmp	.while
end if


if used buffer$check_last_lf | defined include_everything
	; single arg in rdi: buffer object
	; if length is nonzero, makes sure that the last character in the buffer is a 10
	; and if not, adds one
falign
buffer$check_last_lf:
	prolog	buffer$check_last_lf
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	test	rdx, rdx
	jz	.nothingtodo
	add	rsi, rdx
	sub	rsi, 1
	cmp	byte [rsi], 10
	je	.nothingtodo
	mov	esi, 10
	call	buffer$append_byte
	epilog
calign
.nothingtodo:
	epilog
end if


if used buffer$nextline | defined include_everything
	; single arg in rdi: buffer object
	; returns a _new_ (heap$alloc'd) string in rax and consumes through the linefeed
falign
buffer$nextline:
	prolog	buffer$nextline
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_endptr_ofs]
	cmp	rsi, rdx
	je	.emptystring
calign
.while:
	cmp	rsi, rdx
	jae	.emptystring
	mov	al, byte [rsi]
	cmp	al, 13
	je	.doit
	cmp	al, 10
	je	.doit
	add	rsi, 1
	jmp	.while
calign
.emptystring:
	call	string$new
	epilog
calign
.doit:
	sub	rsp, 24
	mov	[rsp], rdi
	mov	rdi, qword [rdi+buffer_itself_ofs]	; buffer start
	sub	rsi, rdi				; length in bytes
	mov	[rsp+8], rsi
	call	string$from_utf8
	mov	[rsp+16], rax				; save our return string
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rdi+buffer_length_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
calign
.consumewhile:
	cmp	rdx, rcx
	jae	.resetonly
	cmp	byte [rsi+rdx], 13
	je	.consumewhilenext
	cmp	byte [rsi+rdx], 10
	je	.consumewhilenext
	; else, our consume ends here, rdx has # of bytes to consume
	mov	rsi, rdx
	call	buffer$consume
	mov	rax, [rsp+16]	; our return
	add	rsp, 24
	epilog
calign
.consumewhilenext:
	add	rdx, 1
	jmp	.consumewhile
calign
.resetonly:
	call	buffer$reset
	mov	rax, [rsp+16]
	add	rsp, 24
	epilog
end if


if used buffer$cdebug | defined include_everything
	; single argument in rdi == our buffer object
	; this dumps to stdout a c array, useful for external debugging/etc
falign
buffer$cdebug:
	prolog	buffer$cdebug
	push	rbx r12 r13
	mov	rbx, rdi
	mov	rdi, .pref1
	call	string$to_stdout

	mov	rdi, [rbx+buffer_length_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free

	mov	rdi, .pref2
	call	string$to_stdout

	mov	r12, [rbx+buffer_length_ofs]
	test	r12, r12
	jz	.empty
	mov	r13, [rbx+buffer_itself_ofs]
calign
.doit:
	mov	rdi, .pref3
	mov	rsi, .pref4
	cmp	r13, [rbx+buffer_itself_ofs]
	cmovne	rdi, rsi
	call	string$to_stdout
	movzx	edi, byte [r13]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	add	r13, 1
	sub	r12, 1
	jnz	.doit

calign
.empty:
	mov	rdi, .end
	call	string$to_stdoutln
	
	pop	r13 r12 rbx
	epilog
cleartext .pref1, 'unsigned char buffer['
cleartext .pref2, '] = { '
cleartext .pref3, '0x'
cleartext .pref4, ', 0x'
cleartext .end, ' };'

end if


if used buffer$file_write | defined include_everything
	; two arguments: rdi == buffer object, rsi == filename to write to
	; NOTE: does no conversion, writes the buffer as-is to the file
	;       also turns rsi into a null terminated UTF8 suitable for syscall use
	; returns # of bytes written in rax
falign
buffer$file_write:
	prolog	buffer$file_write
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nothingtodo
	push	rbx r12
	mov	r12, rdi
	mov	rbx, rsi
	mov	rdi, rsi
	call	string$utf8_length
	mov	rdi, rbx
	mov	rbx, rax
	add	rbx, 16
	and	rbx, not 15
	sub	rsp, rbx
	mov	rsi, rsp
	mov	byte [rsp+rax], 0
	call	string$to_utf8
	mov	rdi, r12
	mov	rsi, rsp
	call	buffer$file_write_cstr
	add	rsp, rbx
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	epilog

end if

if used buffer$file_write_cstr | defined include_everything
	; two arguments: rdi == buffer object, rsi == null terminated latin1 filename
	; returns # of bytes written in rax
falign
buffer$file_write_cstr:
	prolog	buffer$file_write_cstr
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nothingtodo
	push	rbx r12
	mov	rbx, rdi
	mov	eax, syscall_open
	mov	rdi, rsi
	mov	esi, 0x242	; O_RDWR | O_CREAT | O_TRUNC
	mov	edx, 0x1b6	; mode == 666
	syscall
	mov	r12, rax
	cmp	eax, 0
	jl	.kakked
	mov	rdi, rax
	mov	eax, syscall_write
	mov	rsi, [rbx+buffer_itself_ofs]
	mov	rdx, [rbx+buffer_length_ofs]
	syscall
	mov	rdi, r12
	mov	r12, rax
	mov	eax, syscall_close
	syscall
	mov	rax, r12
	pop	r12 rbx
	epilog
calign
.kakked:
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	epilog

end if

if used buffer$file_append | defined include_everything
	; two arguments: rdi == buffer object, rsi == filename to append to
	; NOTE: does no conversion, appends the buffer as-is to the file
	;       also turns rsi into a null terminated UTF8 suitable for syscall use
	; returns # of bytes written in rax
falign
buffer$file_append:
	prolog	buffer$file_append
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nothingtodo
	push	rbx r12
	mov	r12, rdi
	mov	rbx, rsi
	mov	rdi, rsi
	call	string$utf8_length
	mov	rdi, rbx
	mov	rbx, rax
	add	rbx, 16
	and	rbx, not 15
	sub	rsp, rbx
	mov	rsi, rsp
	mov	byte [rsp+rax], 0
	call	string$to_utf8
	mov	rdi, r12
	mov	rsi, rsp
	call	buffer$file_append_cstr
	add	rsp, rbx
	pop	r12 rbx
calign
.nothingtodo:
	epilog

end if

if used buffer$file_append_cstr | defined include_everything
	; two arguments: rdi == buffer object, rsi == null terminated latin1 filename
	; returns # of bytes written in rax
falign
buffer$file_append_cstr:
	prolog	buffer$file_append_cstr
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nothingtodo
	push	rbx r12
	mov	rbx, rdi
	mov	eax, syscall_open
	mov	rdi, rsi
	mov	esi, 0x442	; O_RDWR | O_CREAT | O_APPEND
	mov	edx, 0x1b6	; mode == 666
	syscall
	mov	r12, rax
	cmp	eax, 0
	jl	.kakked
	mov	rdi, rax
	mov	eax, syscall_write
	mov	rsi, [rbx+buffer_itself_ofs]
	mov	rdx, [rbx+buffer_length_ofs]
	syscall
	mov	rdi, r12
	mov	r12, rax
	mov	eax, syscall_close
	syscall
	mov	rax, r12
	pop	r12 rbx
	epilog
calign
.kakked:
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	epilog

end if
