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
	; base64_latin1.inc: non-string versions of base64 encode/decode
	;
	; because most base64 operations do happen in latin1, there is no benefit/reason
	; to first convert the text to native string{16,32}
	; native string versions are here too, so I suppose it depends on
	; the various use scenarios whether these make sense or the string natives do
	;

if used base64$encode_length | defined include_everything
	; single argument: rdi == byte length
	; returns # of _characters_ that an encoding to base64 would take, taking into account linefeeds/linelengths/etc
falign
base64$encode_length:
	prolog	base64$encode_length
	mov	ecx, 3
	mov	rax, rdi
	xor	edx, edx
	div	rcx
	mov	r8, rax
	add	r8, 1		; was there a remainder? if so, we need one more group of 4 chars
	test	edx, edx
	cmovnz	rax, r8
	shl	rax, 2
if base64_linebreaks
	mov	ecx, base64_maxline
	mov	r8, rax
	xor	edx, edx
	div	rcx
	mov	r9, rax
	add	r9, 1
	test	edx, edx
	cmovnz	rax, r9		; was there a remainder? if so, we need one more line
	shl	rax, 1
	add	rax, r8
end if
	epilog

end if

if used base64$encode_latin1 | defined include_everything

	; four arguments: rdi: byte buffer we are encoding, rsi: length of same, rdx: destination buffer, rcx == 0 == default base64 table, else, STRING of base64 table
	; it is up to the caller to determine the correct amount of space to reserve and make sure the pointer
	; in rdx is large enough
	; returns # of latin1 characters we wrote into rdx
falign
base64$encode_latin1:
	prolog	base64$encode_latin1
	test	rsi, rsi
	jz	.nothingtodo

	push	rbx
if base64_linebreaks
	push	r12
	xor	r12d, r12d
end if
	mov	r9, rsi		; bytes we are processing
	mov	r8, .default_table
	test	rcx, rcx
	cmovz	r10, r8
	cmovnz	r10, rcx	; base64table
	cmp	qword [r10], 64
	jb	.error_return	; table supplied must contain 64 characters
	xor	r11d, r11d	; use this as our reference/byte count
calign
.doit:
	cmp	r9, 3
	jae	.doit_allthree
	cmp	r9, 2
	je	.doit_two
	; else, only one byte left
	movzx	r8d, byte [rdi]
	mov	esi, r8d
	shr	esi, 2
	and	esi, 0x3f
	; get the character out of our table
if string_bits = 32
	mov	ebx, dword [r10+rsi*4+8]
else
	movzx	ebx, word [r10+rsi*2+8]
end if
	; get the next character (partial)
	shl	r8d, 4
	and	r8d, 0x3f
	; get the character out of our table
if string_bits = 32
	mov	eax, dword [r10+r8*4+8]
else
	movzx	eax, word [r10+r8*2+8]
end if
	shl	eax, 8
	or	ebx, eax
	or	ebx, 0x3d3d0000		; add our two padding chars
	mov	dword [rdx+r11], ebx
	add	r11, 4
if base64_linebreaks
	mov	word [rdx+r11], 0x0a0d
	add	r11, 2
end if
	; done
	mov	rax, r11
if base64_linebreaks
	pop	r12
end if
	pop	rbx
	epilog
calign
.doit_two:
	; only two bytes left
	movzx	r8d, word [rdi]

	mov	esi, r8d
	shr	esi, 2
	and	esi, 0x3f
	; get the character out of our table
if string_bits = 32
	mov	ebx, dword [r10+rsi*4+8]
else
	movzx	ebx, word [r10+rsi*2+8]
end if
	; the next character
	mov	esi, r8d
	mov	ecx, r8d
	shl	esi, 4
	shr	ecx, 12
	shr	r8d, 8			; swallow the first byte that is all done now
	and	esi, 0x3f
	and	ecx, 0xf
	or	esi, ecx
	; get the character out of our table
if string_bits = 32
	mov	eax, dword [r10+rsi*4+8]
else
	movzx	eax, word [r10+rsi*2+8]
end if
	shl	eax, 8
	or	ebx, eax
	; get the next character (partial)
	shl	r8d, 2
	and	r8d, 0x3f
	; get the character out of our table
if string_bits = 32
	mov	eax, dword [r10+r8*4+8]
else
	movzx	eax, word [r10+r8*2+8]
end if
	shl	eax, 16
	or	ebx, eax
	or	ebx, 0x3d000000		; add our padding char
	mov	dword [rdx+r11], ebx
	add	r11, 4
if base64_linebreaks
	mov	word [rdx+r11], 0x0a0d
	add	r11, 2
end if
	; done
	mov	rax, r11
if base64_linebreaks
	pop	r12
end if
	pop	rbx
	epilog
calign
.doit_allthree:
	mov	r8d, dword [rdi]
	add	rdi, 3		; all these unaligned accesses is probably bad... TODO: make this an aligned accumulator

	mov	esi, r8d
	shr	esi, 2
	and	esi, 0x3f
	; get the character out of our table
if string_bits = 32
	mov	ebx, dword [r10+rsi*4+8]
else
	movzx	ebx, word [r10+rsi*2+8]
end if
	; the next character
	mov	esi, r8d
	mov	ecx, r8d
	shl	esi, 4
	shr	ecx, 12
	shr	r8d, 8			; swallow the first byte that is all done now
	and	esi, 0x3f
	and	ecx, 0xf
	or	esi, ecx
	; get the character out of our table
if string_bits = 32
	mov	eax, dword [r10+rsi*4+8]
else
	movzx	eax, word [r10+rsi*2+8]
end if
	shl	eax, 8
	or	ebx, eax
	; get the next character
	mov	esi, r8d
	mov	ecx, r8d
	shl	esi, 2
	shr	ecx, 8
	and	esi, 0x3f
	shr	ecx, 6
	and	ecx, 0x3
	or	esi, ecx
	shr	r8d, 8			; swallow the second byte that is all done now
	; get the character out of our table
if string_bits = 32
	mov	eax, dword [r10+rsi*4+8]
else
	movzx	eax, word [r10+rsi*2+8]
end if
	shl	eax, 16
	or	ebx, eax
	; and last but not least, final character
	and	r8d, 0x3f
	; get the character out of our table
if string_bits = 32
	mov	eax, dword [r10+r8*4+8]
else
	movzx	eax, word [r10+r8*2+8]
end if
	shl	eax, 24
	or	ebx, eax
	mov	dword [rdx+r11], ebx
	add	r11, 4
if base64_linebreaks
	add	r12d, 4
	cmp	r12d, base64_maxline
	jb	.doit_allthree_next
	; else, maxline reached, add a crlf here and reset the counter
	mov	word [rdx+r11], 0x0a0d
	add	r11, 2
	xor	r12d, r12d
	
	sub	r9, 3
	jnz	.doit
	; else, all done
	mov	rax, r11
	pop	r12
	pop	rbx
	epilog
calign
.doit_allthree_next:
end if
	sub	r9, 3
	jnz	.doit
if base64_linebreaks
	mov	word [rdx+r11], 0x0a0d
	add	r11, 2
end if
	; done
	mov	rax, r11
if base64_linebreaks
	pop	r12
end if
	pop	rbx
	epilog
calign
.error_return:
if base64_linebreaks
	pop	r12
end if
	pop	rbx
	epilog
calign
.nothingtodo:
	xor	eax, eax
	epilog
cleartext .default_table, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


end if

if used base64$decode_latin1 | defined include_everything

	; four arguments: rdi: buffer containing latin1 base64 chars we are decoding, rsi: length of same, rdx: destination buffer, rcx == 0 == default base64 table, else, array of dword (128 of them) of the table to use

	; it is up to the caller to determine the correct amount of space to reserve and make sure the pointer
	; in rdx is large enough
	; returns # of bytes we wrote into rdx

	; TODO: speed this up a bit by two things:
	; 1) reading dwords at a time instead of byte by byte
	; 2) accumulating the output instead of constantly writing unaligned 3 bytes at a time
falign
base64$decode_latin1:
	prolog	base64$decode_latin1
	xor	eax, eax
	test	rsi, rsi
	jz	.nothingtodo
	mov	r8, .default_table
	test	rcx, rcx
	cmovnz	r8, rcx
	xor	r9d, r9d
	xor	r10d, r10d
	push	rdx			; save the start of our destination so we can compute how many we wrote to it
calign
.doit:
	movzx	ecx, byte [rdi]
	add	rdi, 1
	cmp	ecx, 32
	jbe	.whitespaceordie
	; not whitespace, do our table lookup
	cmp	ecx, 128
	jae	.doret			; invalid
	mov	eax, dword [r8+rcx*4]	; the character
	cmp	eax, -1
	je	.doret			; invalid
	mov	ecx, r10d
	and	eax, 0x3f
	shl	rax, cl
	add	r9, rax
	add	r10d, 8
	cmp	r10d, 32
	jae	.next_dowrite
	sub	rsi, 1
	jnz	.doit
	jmp	.doret
calign
.next_dowrite:
	mov	eax, r9d
	mov	ecx, r9d
	mov	r11d, r9d
	
	and	eax, 0xff	
	shl	eax, 2
	shr	ecx, 12
	and	ecx, 3
	or	eax, ecx
	mov	ecx, r9d
	shr	ecx, 4
	and	ecx, 0xf0
	shr	r11d, 18
	and	r11d, 0xf
	or	ecx, r11d

	mov	r11d, r9d
	shr	r11d, 10
	and	r11d, 0xc0
	shr	r9d, 24
	or	r11d, r9d
	shl	ecx, 8
	shl	r11d, 16
	or	eax, ecx
	or	eax, r11d

	mov	dword [rdx], eax
	add	rdx, 3

	shr	r9, 32
	sub	r10d, 32
	sub	rsi, 1
	jnz	.doit
	; fallthrough to doret
calign
.doret:
	mov	eax, r9d
	mov	ecx, r9d
	mov	r11d, r9d
	
	and	eax, 0xff	
	shl	eax, 2
	shr	ecx, 12
	and	ecx, 3
	or	eax, ecx
	mov	ecx, r9d
	shr	ecx, 4
	and	ecx, 0xf0
	shr	r11d, 18
	and	r11d, 0xf
	or	ecx, r11d

	mov	r11d, r9d
	shr	r11d, 10
	and	r11d, 0xc0
	shr	r9d, 24
	or	r11d, r9d
	shl	ecx, 8
	shl	r11d, 16
	or	eax, ecx
	or	eax, r11d

	mov	dword [rdx], eax

	shr	r10d, 3
	test	r10d, r10d
	jz	.noextra

	mov	eax, 1
	sub	r10d, 1
	cmp	r10d, 1
	cmovb	r10d, eax

	add	rdx, r10
calign
.noextra:
	mov	rax, rdx
	pop	rsi
	sub	rax, rsi
	epilog
calign
.whitespaceordie:
	cmp	ecx, 32
	je	.isspace
	cmp	ecx, 13
	je	.isspace
	cmp	ecx, 10
	je	.isspace
	cmp	ecx, 9
	je	.isspace
	
	; otherwise, puke
	mov	rax, rdx
	pop	rsi
	sub	rax, rsi
	epilog
	
calign
.isspace:
	sub	rsi, 1
	jnz	.doit
	jmp	.doret
calign
.nothingtodo:
	epilog
dalign
.default_table:
	; the <128 character position map for the default base64 table:
	; ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
	dd	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1

end if
