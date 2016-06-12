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
	; string16.inc: utf16 immutable string goodies
	;
	; they are stored with an 8 byte length prefix
	; followed by the utf16 codes (useful for static strings)
	;

if used string$new | defined include_everything
	; no arguments, returns new empty string in rax
falign
string$new:
	prolog	string$new
	mov	edi, 8
	call	heap$alloc
	mov	qword [rax], 0
	epilog
end if


if used string$copy | defined include_everything
	; single argument in rdi, makes a copy of it
falign
string$copy:
	prolog	string$copy
	push	rdi
	mov	rdi, [rdi]
	shl	rdi, 1		; in bytes
	add	rdi, 8
	call	heap$alloc
	mov	rdi, rax	; our destination
	pop	rsi		; our source
	mov	rdx, [rsi]	; our length
	test	rdx, rdx
	jz	.zerolength
	shl	rdx, 1		; in bytes
	add	rdx, 8		; + our length prefix
	push	rdi
	call	memcpy
	pop	rax		; return in rax
	epilog
calign
.zerolength:
	mov	[rax], rdx
	epilog
end if

if used string$reverse | defined include_everything
	; single argument in rdi, makes a copy of it reversed (abcd -> dcba)
falign
string$reverse:
	prolog	string$reverse
	call	string$copy
	lea	rdi, [rax+8]	; first character pointer
	mov	rdx, [rax]	; number of characters in our string
	lea	rsi, [rdi+rdx*2]
	sub	rsi, 2		; last character pointer
calign
.doit:
	movzx	ecx, word [rdi]
	movzx	edx, word [rsi]
	mov	word [rdi], dx
	mov	word [rsi], cx
	add	rdi, 2
	sub	rsi, 2
	cmp	rdi, rsi
	jb	.doit
	epilog
end if

if used string$concat | defined include_everything
	; two arguments, rdi and rsi, both strings, returns new string of concatenated arguments
falign
string$concat:
	prolog	string$concat
	push	r12 r13 r14 r15
	mov	r12, rdi	; save it
	mov	r13, rsi	; save it
	mov	rdi, [rdi]	; first strings length
	add	rdi, [rsi]	; second strings length added
	mov	r14, rdi	; save the combined length
	shl	rdi, 1		; in bytes
	add	rdi, 8		; our required length + length prefix
	call	heap$alloc
	mov	[rax], r14	; combined length in characters
	mov	rdi, rax	; destination
	add	rdi, 8		; actual destination offset
	mov	rsi, r12	; source (first argument)
	add	rsi, 8		; pass its length
	mov	rdx, [r12]	; its length
	shl	rdx, 1		; in bytes
	mov	r15, rdx	; save it so we can add it again
	mov	r12, rax	; save our return across this memcpy call
	call	memcpy
	mov	rdi, r12	; restore our new string
	add	rdi, 8		; pass its length
	add	rdi, r15	; pass the first string
	mov	rsi, r13	; second string
	add	rsi, 8		; pass its length
	mov	rdx, [r13]	; its length
	shl	rdx, 1		; in bytes
	call	memcpy
	mov	rax, r12	; get our return
	pop	r15 r14 r13 r12
	epilog
end if

if used string$lpad | defined include_everything
	; three arguments: string in rdi, width in rsi, padchar in edx, returns new string left padded
	; if string length is >= rsi, unmodified (not truncated) copy is returned
falign
string$lpad:
	prolog	string$lpad
	cmp	rsi, qword [rdi]
	jle	.copyonly
	; allocate space for our new string rsi characters in length
	push	r12 r13 r14
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	rdi, rsi	; length in chars
	shl	rdi, 1		; in bytes
	add	rdi, 8		; + length prefix
	call	heap$alloc
	; pad by calling memset16
	mov	[rax], r13	; save the length in our new string
	mov	rdi, rax	; our buffer
	add	rdi, 8		; pass our length
	mov	rsi, r14	; padchar
	mov	rdx, r13	; length
	sub	rdx, qword [r12]	; less the length of the source string
	shl	rdx, 1		; in bytes
	mov	r14, rax	; save our new string
	call	memset16
	; copy the source string
	mov	rdi, r14	; destination == our buffer
	mov	rsi, r12	; source string == our first argument
	add	rsi, 8		; skip its length prefix
	mov	rax, r13	; our total length
	mov	rdx, [r12]	; source string length
	sub	rax, rdx	; rax now has the # of pad characters we did
	shl	rdx, 1		; in bytes
	shl	rax, 1		; in bytes
	add	rdi, 8		; skip our 8 byte length prefix
	add	rdi, rax	; skip our pad characters
	call	memcpy
	mov	rax, r14	; our return
	pop	r14 r13 r12
	epilog
calign
.copyonly:
	call	string$copy
	epilog
end if


if used string$rpad | defined include_everything
	; three arguments: string in rdi, width in rsi, padchar in edx, returns new string right padded
	; if string length is >= rsi, unmodified (not truncated) copy is returned
falign
string$rpad:
	prolog	string$rpad
	cmp	rsi, qword [rdi]
	jle	.copyonly
	; allocate space for our new string rsi characters in length
	push	r12 r13 r14
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	rdi, rsi	; length in chars
	shl	rdi, 1		; in bytes
	add	rdi, 8		; + length prefix
	call	heap$alloc
	; pad by calling memset16
	mov	[rax], r13	; save the length in our new string
	mov	rdi, qword [r12]	; source string length
	shl	rdi, 1		; in bytes
	add	rdi, rax	; our buffer location
	add	rdi, 8		; pass our length as well
	mov	rsi, r14	; padchar
	mov	rdx, r13	; length
	sub	rdx, qword [r12]	; less the length of the source string
	shl	rdx, 1		; in bytes
	mov	r14, rax	; save our new string
	call	memset16
	; copy the source string
	mov	rdi, r14	; destination == our buffer
	add	rdi, 8		; skip our 8 byte length prefix
	mov	rsi, r12	; source string == our first argument
	add	rsi, 8		; skip its length prefix
	mov	rdx, [r12]	; source string length
	shl	rdx, 1		; in bytes
	call	memcpy
	mov	rax, r14	; our return
	pop	r14 r13 r12
	epilog
calign
.copyonly:
	call	string$copy
	epilog
end if



if used string$from_bool | defined include_everything
	; single argument: bool in rdi, returns new string true or false
falign
string$from_bool:
	prolog	string$from_bool
	test	rdi, rdi
	jz	.falseret
	mov	rdi, .truestr
	call	string$copy
	epilog
calign
.falseret:
	mov	rdi, .falsestr
	call	string$copy
	epilog
cleartext .truestr, 'true'
cleartext .falsestr, 'false'
end if


if used string$from_bintohex | defined include_everything
	; two arguments: pointer to bytes in rdi, length in rsi
	; returns a heap$alloc'd string representation in hex of the binary in rax
falign
string$from_bintohex:
	prolog	string$from_bintohex
	push	rsi rdi
	mov	rdi, rsi
	; string16 == 4 bytes per byte of input
	shl	rdi, 2
	add	rdi, 8		; plus our length prefix
	call	heap$alloc
	mov	rdx, [rsp+8]
	mov	rcx, rdx
	shl	rdx, 1		; in characters
	mov	[rax], rdx	; store the length of our string
	mov	rsi, [rsp]
	mov	rdi, rax
	add	rdi, 8
calign
.doit:
	movzx	edx, byte [rsi]
	add	rsi, 1
	mov	r8d, edx
	and	edx, 0xf
	shr	r8d, 4
	movzx	r9d, word [rdx*2+.hexchars+8]
	movzx	r10d, word [r8*2+.hexchars+8]
	mov	word [rdi+2], r9w
	mov	word [rdi], r10w
	add	rdi, 4
	sub	rcx, 1
	jnz	.doit
	add	rsp, 16
	epilog
cleartext .hexchars, '0123456789abcdef'

end if



if used string$from_bintobase64 | defined include_everything
	; three arguments: pointer to bytes in rdi, length in rsi, rdx == 0 == default base64 table, else string of base64 table to use
	; returns a heap$alloc'd string representation in base64 of the binary in rax

	; a note on the base64 table, this must be a _STRING_ (unlike the decode routine that will accept a custom table instead)

	; NOTE: settings for whether to insert line breaks along with maximum line lengths apply (they are located with the rest of the settings)
falign
string$from_bintobase64:
	prolog	string$from_bintobase64
	test	rsi, rsi
	jz	.emptystring
	; originally I was doing outside calls from in here, hence all the callee-saves, TODO: remove them
	push	rbp rbx r12 r13 r14 r15
if base64_linebreaks
	sub	rsp, 8
	mov	dword [rsp], 0	; current line length
end if
	mov	r12, rdi
	mov	r13, rsi
	mov	rcx, .default_table
	test	rdx, rdx
	cmovz	r14, rcx
	cmovnz	r14, rdx
	cmp	qword [r14], 64
	jb	.error_return	; table supplied must contain 64 characters
	xor	r15d, r15d	; use this as our reference into our new string

	mov	rax, rsi
	xor	edx, edx
	mov	ecx, 3		; / 3 first up
	div	rcx
	shl	rax, 2		; * 4 for the number of characters we need 
if base64_linebreaks
	; figure out how many lines we have
	mov	r8, rax		; save our character count
	xor	edx, edx
	mov	ecx, base64_maxline
	div	rcx
	; so now rax contains the number of lines
	add	rax, 1		; min 1
	shl	rax, 1		; one each for CRLF
	add	rax, r8		; plus our character count
end if
	shl	rax, 1		; in bytes
	add	rax, 16		; plus our prefix length and a bit extra for good measure
	mov	rdi, rax
	call	heap$alloc
	mov	rbx, rax	; save our return string in rbx
calign
.doit:
	cmp	r13, 3
	jae	.doit_allthree
	cmp	r13, 2
	je	.doit_two
	; else, only one byte left
	movzx	ebp, byte [r12]
	add	r12, 1
	
	mov	esi, ebp
	shr	esi, 2
	and	esi, 0x3f
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; get the next character (partial)
	mov	esi, ebp
	shl	esi, 4
	and	esi, 0x3f
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; add our two fillchars
	mov	word [rbx+r15*2+8], '='
	add	r15, 1
	mov	word [rbx+r15*2+8], '='
	add	r15, 1
if base64_linebreaks
	; add a trailing CRLF to the last line
	mov	word [rbx+r15*2+8], 13
	mov	word [rbx+r15*2+10], 10
	add	r15, 2
end if
	; done
	mov	[rbx], r15	; save our character count
	mov	rax, rbx	; return
if base64_linebreaks
	add	rsp, 8
end if
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.doit_two:
	movzx	ebp, word [r12]
	add	r12, 2
	
	mov	esi, ebp
	shr	esi, 2
	and	esi, 0x3f
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; the next character
	mov	esi, ebp
	mov	ecx, ebp
	shl	esi, 4
	shr	ecx, 12
	shr	ebp, 8			; swallow the first byte that is all done now
	and	esi, 0x3f
	and	ecx, 0xf
	or	esi, ecx
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; get the next character (partial)
	mov	esi, ebp
	shl	esi, 2
	and	esi, 0x3f
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; add our single fillchar
	mov	word [rbx+r15*2+8], '='
	add	r15, 1
if base64_linebreaks
	; add a trailing CRLF to the last line
	mov	word [rbx+r15*2+8], 13
	mov	word [rbx+r15*2+10], 10
	add	r15, 2
end if
	; done
	mov	[rbx], r15	; save our character count
	mov	rax, rbx	; return
if base64_linebreaks
	add	rsp, 8
end if
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.doit_allthree:
	mov	ebp, dword [r12]
	add	r12, 3		; all these unaligned accesses is probably bad... TODO: make this an aligned accumulator

	mov	esi, ebp
	shr	esi, 2
	and	esi, 0x3f
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; the next character
	mov	esi, ebp
	mov	ecx, ebp
	shl	esi, 4
	shr	ecx, 12
	shr	ebp, 8			; swallow the first byte that is all done now
	and	esi, 0x3f
	and	ecx, 0xf
	or	esi, ecx
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; get the next character
	mov	esi, ebp
	mov	ecx, ebp
	shl	esi, 2
	shr	ecx, 8
	and	esi, 0x3f
	shr	ecx, 6
	and	ecx, 0x3
	or	esi, ecx
	shr	ebp, 8			; swallow the second byte that is all done now
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1
	; and last but not least, final character
	mov	esi, ebp
	and	esi, 0x3f
	; get the character out of our table
	movzx	eax, word [r14+rsi*2+8]
	; store it in our new string
	mov	word [rbx+r15*2+8], ax
	add	r15, 1

if base64_linebreaks
	add	dword [rsp], 4
	cmp	dword [rsp], base64_maxline
	jb	.doit_allthree_next
	; else, maxline reached, add a crlf here and reset the counter
	mov	word [rbx+r15*2+8], 13
	mov	word [rbx+r15*2+10], 10
	add	r15, 2
	mov	dword [rsp], 0

	sub	r13, 3
	jnz	.doit
	; else, all done
	mov	[rbx], r15	; save our character count
	mov	rax, rbx	; return
	add	rsp, 8
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.doit_allthree_next:
end if
	sub	r13, 3
	jnz	.doit
	; else, all done
if base64_linebreaks
	; add a trailing CRLF to the last line
	mov	word [rbx+r15*2+8], 13
	mov	word [rbx+r15*2+10], 10
	add	r15, 2
end if
	mov	[rbx], r15	; save our character count
	mov	rax, rbx	; return
if base64_linebreaks
	add	rsp, 8
end if
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.error_return:
if base64_linebreaks
	add	rsp, 8
end if
	pop	r15 r14 r13 r12 rbx rbp
	call	string$new
	epilog
calign
.emptystring:
	call	string$new
	epilog
cleartext .default_table, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

end if



if used string$from_int | defined include_everything
	; two arguments: int in rdi, radix in esi returns new string of the integer
	; bad radix passed == 0/null return in rax
falign
string$from_int:
	prolog	string$from_int
	cmp	esi, 2
	jl	.badradix
	cmp	esi, 36
	jg	.badradix
	mov	rax, rdi	; value
	sub	rsp, 64		; 32 characters reserved
	mov	rdi, rsp	; buffer
	mov	word [rsp], 43	; '+'... store our sign at the start
	add	rdi, 62		; work backwards
	cmp	rax, 0
	je	.zerovalue
	jl	.isnegative
calign
.top:
	xor	edx, edx
	div	rsi		; radix
	cmp	dl, 10
	jl	.numeric
	add	dl, 87		; 'a' - 10
	mov	word [rdi], dx
	sub	rdi, 2
	test	rax, rax
	jnz	.top
	jmp	.compose	; hmm, TODO: avoid unconditional jumps?
calign
.numeric:
	add	dl, 48		; '0'
	mov	word [rdi], dx
	sub	rdi, 2
	test	rax, rax
	jnz	.top
	jmp	.compose
calign
.isnegative:
	mov	word [rsp], 45	; '-'
	neg	rax
	jmp	.top
calign
.zerovalue:
	mov	word [rdi], 48	; '0'
	sub	rdi, 2
	; fallthrough to compose
calign
.compose:
	; rdi started out at rsp
	; we placed a sign indicator at its first word
	; then we added 62
	; then we constructed our string backward
	; so the length of our string is (rsp + 64 - (rdi + 1)) > 1
	add	rdi, 2
	mov	rsi, rsp
	add	rsi, 64
	sub	rsi, rdi	; rsi now has our length in bytes

	cmp	word [rsp], 45	; '-'
	je	.composeneg

	push	r13 r14 r15
	mov	r14, rdi
	mov	r15, rsi

	mov	rdi, rsi
	add	rdi, 8		; add room for our length prefix
	call	heap$alloc
	mov	r13, rax	; save our new string
	mov	rdi, rax	; destination
	add	rdi, 8		; skip our length prefix
	mov	rsi, r14	; our integer stack buffer
	mov	rdx, r15	; our length in bytes
	call	memcpy
	shr	r15, 1
	mov	rax, r13
	mov	[rax], r15	; store our length
	pop	r15 r14 r13
	add	rsp, 64
	epilog


calign
.composeneg:
	push	r13 r14 r15
	mov	r14, rdi
	mov	r15, rsi

	mov	rdi, rsi
	add	rdi, 10		; add room for our length prefix and sign character
	call	heap$alloc
	mov	r13, rax	; save our new string
	mov	rdi, rax	; destination
	mov	word [rax+8], 45	; '-'
	add	rdi, 10		; skip our length prefix and sign char
	mov	rsi, r14	; our integer stack buffer
	mov	rdx, r15	; our length in bytes
	call	memcpy
	shr	r15, 1
	add	r15, 1
	mov	rax, r13
	mov	[rax], r15	; store our length
	pop	r15 r14 r13
	add	rsp, 64
	epilog
calign
.badradix:
	xor	eax, eax
	epilog
end if
	

if used string$from_unsigned | defined include_everything
	; two arguments: unsigned in rdi, radix in esi returns new string of the integer
	; bad radix passed == 0/null return in rax
falign
string$from_unsigned:
	prolog	string$from_unsigned
	cmp	esi, 2
	jl	.badradix
	cmp	esi, 36
	jg	.badradix
	mov	rax, rdi	; value
	sub	rsp, 64		; 32 characters reserved
	mov	rdi, rsp	; buffer
	add	rdi, 62		; work backwards
	test	rax, rax
	jz	.zerovalue
calign
.top:
	xor	edx, edx
	div	rsi		; radix
	cmp	dl, 10
	jl	.numeric
	add	dl, 87		; 'a' - 10
	mov	word [rdi], dx
	sub	rdi, 2
	test	rax, rax
	jnz	.top
	jmp	.compose	; hmm, TODO: avoid unconditional jumps?
calign
.numeric:
	add	dl, 48		; '0'
	mov	word [rdi], dx
	sub	rdi, 2
	test	rax, rax
	jnz	.top
	jmp	.compose
calign
.zerovalue:
	mov	word [rdi], 48	; '0'
	sub	rdi, 2
	; fallthrough to compose
calign
.compose:
	; rdi started out at rsp
	; we placed a sign indicator at its first word
	; then we added 62
	; then we constructed our string backward
	; so the length of our string is (rsp + 64 - (rdi + 1)) > 1
	add	rdi, 2
	mov	rsi, rsp
	add	rsi, 64
	sub	rsi, rdi	; rsi now has our length in bytes
	push	r13 r14 r15
	mov	r14, rdi
	mov	r15, rsi

	mov	rdi, rsi
	add	rdi, 8		; add room for our length prefix
	call	heap$alloc
	mov	r13, rax	; save our new string
	mov	rdi, rax	; destination
	add	rdi, 8		; skip our length prefix
	mov	rsi, r14	; our integer stack buffer
	mov	rdx, r15	; our length in bytes
	call	memcpy
	shr	r15, 1
	mov	rax, r13
	mov	[rax], r15	; store our length
	pop	r15 r14 r13
	add	rsp, 64
	epilog
calign
.badradix:
	xor	eax, eax
	epilog
end if

	include 'string_math.inc'


if used string$from_double | defined include_everything
	; THREE ARGUMENTS HERE: double in xmm0, mode in edi, precision in esi
	; mode can be:
double_string_normal = 0
double_string_fixed = 1
double_string_precision = 2
double_string_exponential = 3
	; precision in most of my stuff defaults to 15
	; we return a newly allocated string in rax

        ; NOTE: This is slower by about half of the c++11 method, BUT
        ; this uses: http://www.cs.indiana.edu/~dyb/pubs/FP-Printing-PLDI96.pdf
        ; and as such suits my needs in the wild/net/JS/web perfectly, and
        ; there is no simple way to achieve the same functionality with c++11
        ; that I am aware of.

        ; case in point from their paper: 3/10 comes out as 0.3 instead of 0.2999999
        ; when mode is normal, we produce the shortest possible correctly rounded
        ; string that converts back to the same double the other way around.

        ; fixed == number of digits after the decimal point.. precision 3 = 0.000
falign
string$from_double:
	prolog	string$from_double

	virtual at rsp
		strtod_quadmem	dq	?
	end virtual
	virtual at rsp
		strtod_lsw	dd	?
		strtod_msw	dd	?
	end virtual
	; first up: check for -/+inf
	sub	rsp, 8
	movsd	[strtod_quadmem], xmm0
	mov	eax, [strtod_msw]
	mov	ecx, [strtod_lsw]
	mov	r10, qword [rsp]
	add	rsp, 8

	; make copies of these so we can re-use for our nan-check
	mov	r8d, eax
	mov	r9d, eax

	; eax == hx
	; ecx == lx

	; lx |= (hx & 0x7fffffff) ^ 0x7ff00000
	mov	edx, eax
	and	edx, 0x7fffffff
	xor	edx, 0x7ff00000
	or	ecx, edx

	; lx |= -lx
	mov	edx, ecx
	neg	edx
	or	ecx, edx

	; ~(lx >> 31) & (hx >> 30)
	mov	edx, r8d	; edx == hx now
	sar	edx, 30		; >> 30
	mov	eax, ecx	; eax == resultant lx now
	sar	eax, 31
	not	eax
	and	eax, edx

	cmp	eax, -1
	je	.neginf
	cmp	eax, 1
	je	.posinf
	; check for NaN
	mov	eax, r8d
	mov	ecx, r9d
	and	eax, 0x7fffffff
	mov	edx, ecx
	neg	ecx
	or	edx, ecx
	shr	edx, 31
	or	eax, edx
	mov	edx, 0x7ff00000
	sub	edx, eax
	shr	edx, 31
	test	edx, edx
	jnz	.nan
	; otherwise, not infinity, not NaN, so see if it is a whole number
	; but only if mode is NORMAL
	test	edi, edi
	jnz	.notwholenumber	; mode is not normal, let the double handler take care of it
	cvtsd2si	rax, xmm0
	cvtsi2sd	xmm1, rax
	comisd		xmm0, xmm1
	jne	.notwholenumber
	; verify it isnt an overflow condition
	mov	rdx, rax
	shr	rdx, 32
	cmp	edx, 0x80000000
	je	.notwholenumber
	; else, rax is our number to convert, so use the long variety instead
	mov	rdi, rax
	mov	esi, 10		; radix to use
	call	string$from_int
	; return in rax is sweet
	epilog
; cleartext forces calign
cleartext .neginfstr, '-Infinity'
cleartext .posinfstr, 'Infinity'
cleartext .nanstr, 'NaN'
calign
.neginf:
	mov	rdi, .neginfstr
	call	string$copy
	epilog
calign
.posinf:
	mov	rdi, .posinfstr
	call	string$copy
	epilog
calign
.nan:
	mov	rdi, .nanstr
	call	string$copy
	epilog

calign
.notwholenumber:
	; let the nasties begin, our original parameters are unmolested, and our stackframe is as well
	; double in xmm0, mode in edi, precision in esi

	virtual at rsp
		strtod_negative		dq	?
		strtod_sentinel		dq	?
		strtod_buffer		dq	?
		strtod_mode		dd	?
		strtod_wrotedecimal	dd	?
		strtod_valuezero	dd	?
	end virtual

	push	rbx r12 r13 r14 r15	; we will use all of our callee-save regs
	sub	rsp, 512		; get us a decent amount of stackspace
	mov	[strtod_negative], 0
	mov	dword [strtod_mode], edi
	mov	dword [strtod_wrotedecimal], 0
	mov	rbx, rsp
	add	rbx, 36			; our buffer
	mov	[strtod_buffer], rbx	; save our buffer pointer cuz we can't modify the stack later
	mov	r13, rbx		; s
	mov	[strtod_sentinel], rbx
	mov	r15d, esi		; save our precision
	xor	eax, eax
	mov	ecx, 1
	comisd	xmm0, [_math_zero]
	cmove	eax, ecx
	mov	dword [strtod_valuezero], eax
	comisd	xmm0, [_math_zero]	; TODO, twice? wtf
	jb	.negative
calign
.doit:
	; we have saved our mode and precision already, so we can safely call stringdc$new
	call	stringdc$new
	mov	r12, rax		; r12 is now our stringdc
	mov	r14d, [_dc12_base10exp]
	sub	r14d, 1			
	; so at this point: 
	; rbx == our buffer (past our virtual at rsp vars)
	; r12 == our stringdc
	; r13 == s
	; r14d == exp10
	; r15d == precision
	xor	eax, eax
	cmp	dword [strtod_mode], 0
	jl	.badmode
	cmp	dword [strtod_mode], 3
	jg	.badmode
calign
.modeokay:
	mov	eax, dword [strtod_mode]
	shl	eax, 3
	add	rax, .modejump
	jmp	qword [rax]

calign
.modenormal:
	cmp	r14d, 0
	jge	.modenorm_check20
	cmp	r14d, -7
	jle	.modenorm_check20
	mov	ecx, r15d
	neg	ecx
	cmp	r14d, ecx
	jge	.formatfraction
	sub	ecx, 1
	mov	r15d, ecx
	jmp	.formatfraction
calign
.modenorm_check20:
	cmp	r14d, 20
	jle	.formatnormal
	jmp	.formatexponential
calign
.modefixed:
	cmp	r14d, 0
	jl	.formatfixedfraction
	add	r15d, 1		; precision++
	jmp	.formatnormal
calign
.modeprecision:
	cmp	r14d, 0
	jl	.formatfraction
	cmp	r14d, r15d
	jge	.formatexponential
	jmp	.formatnormal
calign
.modeexponential:
	add	r15d, 1
	jmp	.formatexponential
calign
.formatnormal:
	xor	ebx, ebx
	mov	word [r13], '0'
	add	r13, 2
	mov	rdi, r12
	call	stringdc$nd
	cmp	eax, 0
	jle	.formatnormal_exploop
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	cmp	r14d, 0
	jle	.formatnormal_exploopdone
calign
.formatnormal_exploop:
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	add	ebx, 1		; digits++
	sub	r14d, 1		; exp10--
	jnz	.formatnormal_exploop
calign
.formatnormal_exploopdone:
	cmp	dword [strtod_mode], 1		; mode == fixed?
	jne	.formatnormal_modenotfixed
	xor	ebx, ebx	; digits = 0
calign
.formatnormal_modenotfixed:
	cmp	dword [strtod_mode], 0
	jne	.formatnormal_modenotnormal
	cmp	dword [_dc12_finished], 0
	jne	.formatdone
	mov	word [r13], '.'
	add	r13, 2
	mov	dword [strtod_wrotedecimal], 1
calign
.formatnormal_modenotfixed_loop:
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	cmp	dword [_dc12_finished], 0
	je	.formatnormal_modenotfixed_loop
	jmp	.formatdone
calign
.formatnormal_modenotnormal:
	mov	eax, r15d
	sub	eax, 1
	cmp	ebx, eax
	jge	.formatdone
	sub	r15d, 1		; temporarily modify precision to -1 for loop below
	mov	word [r13], '.'
	add	r13, 2
	mov	dword [strtod_wrotedecimal], 1
calign
.formatnormal_modenotnormal_loop:
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	add	ebx, 1
	cmp	ebx, r15d
	jl	.formatnormal_modenotnormal_loop
	; add the 1 back in to precision
	add	r15d, 1
	jmp	.formatdone
	
calign
.formatexponential:
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	cmp	dword [strtod_mode], 0
	jne	.formatexponential_notnormal
	cmp	dword [_dc12_finished], 0	
	je	.formatexponential_doit
	jmp	.formatdone
calign
.formatexponential_notnormal:
	cmp	r15d, 1
	jle	.formatdone
calign
.formatexponential_doit:
	mov	word [r13], '.'
	add	r13, 2
	mov	dword [strtod_wrotedecimal], 1
	mov	ebx, 1	; for our loop
calign
.formatexponential_loop:
	cmp	ebx, r15d
	jge	.formatdone
	add	ebx, 1
	cmp	dword [_dc12_finished], 0
	je	.formatexponential_loop_notfinished
	cmp	dword [strtod_mode], 0
	je	.formatdone
	mov	word [r13], '0'
	add	r13, 2
	jmp	.formatexponential_loop
calign
.formatexponential_loop_notfinished:
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	jmp	.formatexponential_loop
calign
.formatfraction:
	mov	word [r13], '0'		; sentinel
	mov	word [r13+2], '0'
	mov	word [r13+4], '.'
	add	r13, 6
	mov	dword [strtod_wrotedecimal], 1
	cmp	dword [strtod_valuezero], 1
	je	.formatfraction_valzero
	; else, loop from exp10 to -1 writing more zeroes
	mov	ebx, r14d
calign
.formatfraction_zeroloop:
	cmp	ebx, -1
	jge	.formatfraction_valzero
	add	ebx, 1
	mov	word [r13], '0'
	add	r13, 2
	jmp	.formatfraction_zeroloop
	; TODO: redo these, horrible
calign
.formatfraction_valzero:
	xor	ebx, ebx
	; copy of the valzero_loop
	cmp	dword [_dc12_finished], 0
	jne	.formatfraction_modecheck
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	cmp	dword [strtod_mode], 0
	je	.formatfraction_valzero_loop
	add	ebx, 1
	cmp	ebx, r15d
	jge	.formatfraction_modecheck
	; fallthrough
calign
.formatfraction_valzero_loop:
	cmp	dword [_dc12_finished], 0
	jne	.formatfraction_modecheck
	mov	rdi, r12
	call	stringdc$nd			; infinite loop here sometimes
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	cmp	dword [strtod_mode], 0
	je	.formatfraction_valzero_loop
	add	ebx, 1
	cmp	ebx, r15d
	jge	.formatfraction_modecheck
	jmp	.formatfraction_valzero_loop
calign
.formatfraction_modecheck:
	xor	r14d, r14d
	cmp	dword [strtod_mode], 2
	jne	.formatdone
calign
.formatfraction_modecheck_loop:
	cmp	ebx, r15d
	jge	.formatdone
	add	ebx, 1
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	jmp	.formatfraction_modecheck_loop

calign
.formatfixedfraction:
	mov	word [r13], '0'		; sentinel
	mov	word [r13+2], '0'
	mov	word [r13+4], '.'
	add	r13, 6
	mov	dword [strtod_wrotedecimal], 1
	xor	ebx, ebx		; digits loop
	cmp	r14d, 0
	je	.formatfixedfraction_significand
	jl	.formatfixedfraction_expl
calign
.formatfixedfraction_posexploop:
	add	r14d, 1
	cmp	r14d, 10
	jge	.formatfixedfraction_significand
	cmp	ebx, r15d
	jge	.formatfixedfraction_significand
	mov	word [r13], '0'
	add	r13, 2
	add	ebx, 1
	jmp	.formatfixedfraction_posexploop
calign
.formatfixedfraction_expl:
	add	r14d, 1
	test	r14d, r14d
	jz	.formatfixedfraction_significand
	mov	ecx, r15d
	sub	r15d, 1
	cmp	ecx, 0
	jle	.formatfixedfraction_significand
	mov	word [r13], '0'
	add	r13, 2
	jmp	.formatfixedfraction_expl
calign
.formatfixedfraction_significand:
	cmp	ebx, r15d		; digits < precision?
	jge	.formatfixedfraction_done
	add	ebx, 1			; digits++
	cmp	[_dc12_finished], 0
	je	.formatfixedfraction_notfinished
	cmp	[strtod_mode], 0
	je	.formatfixedfraction_done
	mov	word [r13], '0'
	add	r13, 2
	jmp	.formatfixedfraction_significand
calign
.formatfixedfraction_notfinished:
	mov	rdi, r12
	call	stringdc$nd
	add	eax, '0'
	mov	word [r13], ax
	add	r13, 2
	jmp	.formatfixedfraction_significand
calign
.formatfixedfraction_done:

	; special case here, if exp10 is still < 0, it means precision was too small
	; and as a result, rounding would be _incorrect_ if we grabbed the next digit
	; so we have to assume the next digit is zero in this case, which also means
	; we can skip rounding
	cmp	r14d, 0
	jl	.finalstretch

	xor	r14d, r14d		; exp10 = 0
	; fallthrough to formatdone

calign
.formatdone:
	; rbx got blasted, but the rest are okay (rbx original buffer is stored in rsp goods)
	cmp	dword [_dc12_fastestok], 0
	jne	.formatdone_okay
	cmp	dword [strtod_mode], 1		; mode == fixed?
	je	.formatdone_okay
	cmp	dword [strtod_mode], 2		; mode == precision?
	jne	.checkexp10
calign
.formatdone_okay:
	mov	rdi, r12
	call	stringdc$nd
	cmp	eax, 4
	jle	.formatdone_okay_normalcheck
	mov	rcx, r13	; ptr = s
	sub	rcx, 2		; - 1
calign
.formatdone_okay_loop:
	cmp	rcx, qword [strtod_buffer]
	jl	.formatdone_okay_normalcheck
	movzx	eax, word [rcx]
	cmp	eax, '0'
	jl	.formatdone_okay_loop_keepgoing
	add	eax, 1
	mov	word [rcx], ax
	cmp	eax, 0x3a
	jne	.formatdone_okay_normalcheck
	mov	word [rcx], '0'
	sub	rcx, 2
	jmp	.formatdone_okay_loop
calign
.formatdone_okay_loop_keepgoing:
	sub	rcx, 2
	jmp	.formatdone_okay_loop
calign
.formatdone_okay_normalcheck:
	cmp	dword [strtod_mode], 0
	jne	.checkexp10
	cmp	dword [strtod_wrotedecimal], 0
	je	.checkexp10
	; otherwise, remove trailing zeroes
calign
.formatdone_okay_normalcheck_loop:
	cmp	word [r13-2], '0'
	jne	.formatdone_okay_dcheck
	sub	r13, 2
	jmp	.formatdone_okay_normalcheck_loop
calign
.formatdone_okay_dcheck:
	cmp	word [r13-2], '.'
	jne	.checkexp10
	sub	r13, 2
	; fallthrough to checkexp10

	; so at this point: 
	; rbx == our buffer (past our virtual at rsp vars)
	; r12 == our stringdc
	; r13 == s
	; r14d == exp10
	; r15d == precision

;	virtual at rsp
;		strtod_negative		dq	?
;		strtod_sentinel		dq	?
;		strtod_buffer		dq	?
;		strtod_mode		dd	?
;		strtod_wrotedecimal	dd	?
;	end virtual


calign
.checkexp10:
	test	r14d, r14d
	jz	.finalstretch

	; if (exp10)
	movsxd	rax, dword [strtod_negative]
	shl	rax, 1
	add	rax, qword [strtod_buffer]	; firstnz = buffer + negative
calign
.checkexp10_nzl:
	cmp	rax, r13
	jge	.checkexp10_2
	cmp	word [rax], '0'
	jne	.checkexp10_2
	add	rax, 2
	jmp	.checkexp10_nzl
calign
.checkexp10_2:
	mov	rcx, r13	; lastnz = s
	cmp	rax, r13
	jne	.checkexp10_3
	; all digits got rounded
	mov	word [rax], '1'
	add	r13, 2
	add	r14d, 1
	jmp	.checkexp10_adde
calign
.checkexp10_3:
	; firstnz = rax
	; lastnz = s
	cmp	rcx, rax
	jle	.checkexp10_3_2
	sub	rcx, 2
	cmp	word [rcx], '0'
	je	.checkexp10_3
calign
.checkexp10_3_2:
	cmp	dword [strtod_valuezero], 0
	jne	.checkexp10_adde
	cmp	rax, rcx
	jne	.checkexp10_adde
	; else, exp10 += (s - firstnz - 1)
	mov	rcx, r13
	sub	rcx, rax
	shr	rcx, 1
	sub	rcx, 1
	add	r14d, ecx
	mov	r13, rax
	add	r13, 2
calign
.checkexp10_adde:
	mov	word [r13], 'e'
	add	r13, 2
	cmp	r14d, 0
	jle	.checkexp10_adde_noplus
	mov	word [r13], '+'
	add	r13, 2
calign
.checkexp10_adde_noplus:
	; convert value in r14 to a string at r13
	movsxd	rdi, r14d
	mov	esi, 10
	call	string$from_int
	; now we have a newly allocated string in rax, get its length into rcx
	mov	rsi, rax
	add	rsi, 8
	mov	rdx, [rax]
	shl	rdx, 1
	mov	rdi, r13
	add	r13, rdx
	mov	r14, rax	; save it across our memcpy call
	call	memcpy
	mov	rdi, r14
	call	heap$free	; get rid of our temporary
	; so now, r13 got decimal e added to it
calign
.finalstretch:
	mov	r14, r13
	sub	r14, qword [strtod_buffer]
	; r14 now has our length in bytes
	mov	r13, qword [strtod_buffer]	; s = buffer
	mov	rax, qword [strtod_sentinel]
	cmp	qword [strtod_negative], 0
	jne	.finalnegative
	; not negative
	; check sentinel
	cmp	word [rax], '0'	
	jne	.finalposnosentinel
	cmp	word [rax+2], '.'
	je	.finalposnosentinel
	mov	r13, qword [strtod_sentinel]
	add	r13, 2
	sub	r14, 2
calign
.finalposnosentinel:
	mov	rdi, r14
	add	rdi, 8
	call	heap$alloc
	mov	rdx, r14		; length in bytes
	shr	r14, 1
	mov	qword [rax], r14	; store length in characters
	mov	rbx, rax		; save our return
	mov	rdi, rax
	add	rdi, 8		; destination for memcpy
	mov	rsi, r13	; source == s
	; length already set
	call	memcpy
	; done.
	add	rsp, 512
	mov	rdi, r12
	call	heap$free
	mov	rax, rbx	; restore our return
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.finalnegative:
	add	r13, 2	; s++
	cmp	word [rax], '0'
	jne	.finalnegnosentinel
	cmp	word [rax+2], '.'
	je	.finalnegnosentinel
	mov	r13, qword [strtod_sentinel]
	add	r13, 2
	sub	r14, 2
calign
.finalnegnosentinel:
	sub	r13, 2
	mov	word [r13], '-'
	mov	rdi, r14
	add	rdi, 8
	call	heap$alloc
	mov	rdx, r14
	shr	r14, 1
	mov	qword [rax], r14
	mov	rbx, rax
	mov	rdi, rax
	add	rdi, 8
	mov	rsi, r13
	call	memcpy
	add	rsp, 512
	mov	rdi, r12
	call	heap$free
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.modejump	dq	.modenormal, .modefixed, .modeprecision, .modeexponential
calign
.badmode:
	mov	dword [strtod_mode], 0
	jmp	.modeokay
calign
.negative:
	movsd	xmm1, qword [_math_negzero]
	xorpd	xmm0, xmm1	; negate our value
	mov	qword [rsp], 1		; set negative flag
	add	r13, 2			; s++
	mov	[strtod_sentinel], r13	; sentinel = s, after the negation
	jmp	.doit
	
end if


if used string$from_cstr | defined include_everything
	; single argument in rdi: a null terminated C string
	; returns a new string in rax
	; convenience function that calls strlen_latin1 for you
falign
string$from_cstr:
	prolog  string$from_cstr
	push    rdi
	call    strlen_latin1
	mov     rsi, rax
	pop     rdi
	call    string$from_utf8
	epilog

end if


if used string$from_utf8 | defined include_everything
	; two arguments: pointer in rdi, length in rsi, returns new string decoded from utf8 buffer
	; NOTE: if the setting strict_utf is enabled, and we receive invalid utf8 sequences, you'll get a null return
	; in rax
falign
string$from_utf8:
	prolog	string$from_utf8
	push	rbx		; we'll use this one
	test	rsi, rsi
	jz	.empty_string
	push	rdi rsi
	mov	rdi, rsi
	shl	rdi, 1
	add	rdi, 8		; how much room we actually need
	call	heap$alloc
	pop	rcx rsi
	mov	rdi, rax
	; so at this point, rdi == our new string, rcx == our utf8 buffer length, rsi == our source utf8 buffer
	mov	r8, rax		; save our return in r8
	add	rdi, 8		; skip our length location
calign
.convertloop:
	mov	ebx, dword [rsi]
	mov	eax, ebx
	mov	edx, ebx
	shr	bl, 4
	cmp	bl, 8
	jb	.convert_ascii
	cmp	bl, 12
	jb	.convert_invalid
	cmp	bl, 14
	jb	.convert_w8_or_w16
	je	.convert_w16
	cmp	rcx, 4
	jb	.convert_invalid
if strict_utf
	and	edx, 0x08
	jnz	.convert_invalid
end if
	shr	ebx, 8
	and	bl, 0xc0
	cmp	bl, 0x80
	jne	.convert_invalid
	shr	ebx, 8
	and     bl, 0xc0
	cmp     bl, 0x80
	jne     .convert_invalid
	shr     ebx, 8
	and     bl, 0xc0
	cmp     bl, 0x80
	jne     .convert_invalid
	movzx   edx, al
	shl     edx, 18
	and     edx, 0x1c0000
	mov     ebx, eax
	shr     ebx, 8
	and     ebx, 0xff
	shl     ebx, 12
	and     ebx, 0x3f000
	or      edx, ebx
	mov     ebx, eax
	shr     ebx, 16
	and     ebx, 0xff
	shl     ebx, 6
	and     ebx, 0xfc0
	or      edx, ebx
	mov     ebx, eax
	shr     ebx, 24
	and     ebx, 0x3f
	or      edx, ebx
	mov     ebx, eax
	shr     ebx, 24
	and     ebx, 0x3f
	or      edx, ebx
	cmp     edx, 0x10000
	jb      .convert_invalid
	add     rsi, 4
	mov     ebx, edx
	sub     ebx, 0x10000
	shr     ebx, 10
	and     ebx, 0x3ff
	add     ebx, 0xd800
	mov     word [rdi], bx
	add     rdi, 2
	mov     ebx, edx
	sub     ebx, 0x10000
	and     ebx, 0x3ff
	add     ebx, 0xdc00
	mov     word [rdi], bx
	add     rdi, 2
	sub     rcx, 4
	jnz     .convertloop
	jmp     .convert_done
calign
.convert_w8_or_w16:
	cmp     rcx, 2
	jb      .convert_invalid
	shr     edx, 8
	and     edx, 0xc0
	cmp     edx, 0x80
	jne     .convert_invalid
	movzx   edx, al
	shl     edx, 6
	and     edx, 0x7c0
	mov     ebx, eax
	shr     ebx, 8
	and     ebx, 0x3f
	or      edx, ebx
	cmp     edx, 0x80
	jb      .convert_invalid
	add     rsi, 2
	mov     word [rdi], dx
	add     rdi, 2
	sub     rcx, 2
	jnz     .convertloop
	jmp     .convert_done
calign
.convert_w16:
	cmp     rcx, 3
	jb      .convert_invalid
	shr     ebx, 8
	and     bl, 0xc0
	cmp     bl, 0x80
	jne     .convert_invalid
	shr     ebx, 8
	and     bl, 0xc0
	cmp     bl, 0x80
	jne     .convert_invalid
	movzx   edx, al
	shl     edx, 12
	and     edx, 0xf000
	mov     ebx, eax
	shr     ebx, 8
	and     ebx, 0xff
	shl     ebx, 6
	and     ebx, 0xfc0
	or      edx, ebx
	mov     ebx, eax
	shr     ebx, 16
	and     ebx, 0x3f
	or      edx, ebx
	cmp     edx, 0x800
	jb      .convert_invalid
	add     rsi, 3
	mov     word [rdi], dx
	add     rdi, 2
	sub     rcx, 3
	jnz     .convertloop
	jmp     .convert_done
calign
.convert_ascii:
	and     eax, 0xff
	mov     word [rdi], ax
	add     rdi, 2
	add     rsi, 1
	sub     rcx, 1
	jnz     .convertloop
	jmp     .convert_done
calign
.convert_invalid:
if strict_utf
	mov	rdi, r8
	call	heap$free
	xor	eax, eax	; null ret if we are set to strict
	pop	rbx
	epilog
else
	and     eax, 0xff
	mov     word [rdi], ax
	add     rdi, 2
	add     rsi, 1
	sub     rcx, 1
	jnz     .convertloop
if align_inner
	; convert_done fallthrough to avoid nop fill
	mov     rax, rdi
	sub     rax, r8
	sub     rax, 8          ; r8 has the actual return which includes the 8 byte length field
	shr     rax, 1
	mov     [r8], rax       ; length in characters stored
	mov     rax, r8         ; return pointer sorted.
	pop     rbx             ; restore our callee-saved goods
	epilog
end if

end if
calign
.convert_done:
	mov     rax, rdi
	sub     rax, r8
	sub     rax, 8          ; r8 has the actual return which includes the 8 byte length field
	shr     rax, 1
	mov     [r8], rax       ; length in characters stored
	mov     rax, r8         ; return pointer sorted.
	pop     rbx             ; restore our callee-saved goods
	epilog
calign
.empty_string:
	mov	rdi, 8
	call	heap$alloc
	mov	qword [rax], 0
	pop	rbx
	epilog
end if


if used string$from_utf16 | defined include_everything
	; two arguments: pointer in rdi, length in BYTES in rsi, returns new string from the utf16 buffer
falign
string$from_utf16:
	prolog	string$from_utf16
	push	rdi rsi
	mov	rdi, rsi
	add	rdi, 8
	call	heap$alloc
	pop	rdx rsi
	mov	rcx, rdx
	mov	rdi, rax
	shr	rcx, 1
	mov	qword [rax], rcx
	add	rdi, 8
	push	rax
	call	memcpy
	pop	rax
	epilog
end if

if used string$from_utf32 | defined include_everything
	; two arguments: pointer in rdi, length in BYTES in rsi, returns new string from the utf32 buffer
	; NOTE: if the setting strict_utf is enabled, and we receive invalid utf32, you'll get a null return
falign
string$from_utf32:
	prolog	string$from_utf32
	test	rsi, rsi
	jz	.empty_string
	push	rdi rsi
	mov	rdi, rsi
	call	heap$alloc	; NOTE: this wastes a good deal of memory, but better than parsing the buffer twice.. TODO: reconsider?
	pop	rsi rdi
	mov	rdx, rax
	add	rax, 8
	shr	rsi, 2		; in dwords
calign
.convertloop:
	mov	ecx, dword [rdi]
	cmp	ecx, 0xffff
	jg	.biggun
if strict_utf
	cmp	ecx, 0xd800
	jl	.smallokay
	cmp	ecx, 0xdfff
	jbe	.convert_invalid
calign
.smallokay:
end if
	mov	word [rax], cx
	add	rax, 2
	add	rdi, 4
	sub	rsi, 1
	jnz	.convertloop
	; all done
	sub	rax, rdx
	shr	rax, 1
	mov	qword [rdx], rax	; store the length
	mov	rax, rdx		; setup our return
	epilog
calign
.biggun:
	cmp	ecx, 0x10ffff
	jg	.convert_invalid
	sub	ecx, 0x10000
	shr	ecx, 10
	add	ecx, 0xd800
	mov	word [rax], cx
	add	rax, 2
	mov	ecx, dword [rdi]
	sub	ecx, 0x10000
	and	ecx, 0x3ff
	add	ecx, 0xdc00
	mov	word [rax], cx
	add	rax, 2
	add	rdi, 4
	sub	rsi, 1
	jnz	.convertloop
	; all done
	sub	rax, rdx
	shr	rax, 1
	mov	qword [rdx], rax	; store the length
	mov	rax, rdx		; setup our return
	epilog
calign
.convert_invalid:
if strict_utf
	mov	rdi, rdx
	call	heap$free
	xor	eax, eax
	epilog
else
	mov	word [rax], 0xfffd
	add	rax, 2
	add	rdi, 4
	sub	rsi, 1
	jnz	.convertloop
	; all done
	sub	rax, rdx
	shr	rax, 1
	mov	qword [rdx], rax	; store the length
	mov	rax, rdx		; setup our return
	epilog
end if
calign
.empty_string:
	mov	rdi, 8
	call	heap$alloc
	mov	qword [rax], 0
	epilog
end if


if used string$length | defined include_everything
	; single argument: string in rdi, returns length
	; NOTE: you should not use this, just a convenience function really. qword [rdi] == length anyway.
falign
string$length:
	prolog	string$length
	mov	rax, [rdi]
	epilog
end if

if used string$empty | defined include_everything
	; single argument: string in rdi, returns 1 if qword [rdi] == 0 (probably better to just check it yourself ;-))
falign
string$empty:
	prolog	string$empty
	cmp	qword [rdi], 0
	je	.empty
	xor	eax, eax
	epilog
calign
.empty:
	mov	eax, 1
	epilog
end if


if used string$utf8_length | defined include_everything
	; single argument: string in rdi, returns the length required for this string to be converted to utf8
falign
string$utf8_length:
	prolog	string$utf8_length
	mov     rsi, rdi
	; count in rdi
	xor     edi, edi

	mov     rcx, [rsi]
	add     rsi, 8          ; rsi now pointing to start of our real buffer, rdi pointing to the passed in destination buffer for our resultant utf8
	test    rcx, rcx
	jz      .zerolength
calign
.innerloop:
	movzx   edx, word [rsi]
	cmp     edx, 0x80
	jb      .ascii
	cmp     edx, 0x800
	jb      .twobyte
	cmp     edx, 0xd800
	jb      .threebyte
	cmp     edx, 0xdbff
	ja      .threebyte
	sub     rcx, 1
	jz      .alldone
	add     rsi, 2
	movzx   eax, word [rsi]
	cmp     eax, 0xdc00
	jb      .threebytefffd
	cmp     edx, 0xdfff
	ja      .threebytefffd
	add     rdi, 4
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	epilog
calign
.threebytefffd:
	add     rdi, 3
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	epilog
calign
.threebyte:
	cmp     edx, 0xdc00
	jl      .threebyteproceed
	cmp     edx, 0xdfff
	jg      .threebyteproceed
	jmp     .threebytefffd
calign
.threebyteproceed:
	add     rdi, 3
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	epilog
calign
.twobyte:
	add     rdi, 2
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	epilog
calign
.ascii:
	add     rdi, 1
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
calign
.alldone:
	mov     rax, rdi
	epilog
calign
.zerolength:
	xor     eax, eax
	epilog
end if

if used string$utf32_length | defined include_everything
	; single argument: string in rdi, returns the length in CODEPOINTS (not bytes) required for conversion to utf32
falign
string$utf32_length:
	prolog	string$utf32_length
	xor	eax, eax
	mov	rcx, qword [rdi]
	test	rcx, rcx
	jz	.alldone
	add	rdi, 8
calign
.top:
	movzx	edx, word [rdi]
	cmp	edx, 0xd800
	jb	.nothighsurr
	cmp	edx, 0xdbff
	ja	.nothighsurr
	cmp	word [rdi+2], 0xdc00
	jb	.invalid
	cmp	word [rdi+2], 0xdfff
	ja	.invalid
	add	rax, 1
	add	rdi, 4
	sub	rcx, 1
	jz	.alldone
	sub	rcx, 1
	jz	.alldone
	jmp	.top
calign
.nothighsurr:
if strict_utf
	cmp	edx, 0xdc00
	jb	.nothighokay
	cmp	edx, 0xdfff
	ja	.nothighokay
	jmp	.invalid
calign
.nothighokay:
end if
	add	rax, 1
	add	rdi, 2
	sub	rcx, 1
	jnz	.top
	; else, all done
	epilog
calign
.invalid:
if strict_utf
	xor	eax, eax
	epilog
else
	add	rax, 1
	add	rdi, 2
	sub	rcx, 1
	jnz	.top
	; else, all done
	epilog
end if
calign
.alldone:
	epilog
end if


if used string$to_utf8 | defined include_everything
	; two arguments: string in rdi, destination buffer in rsi
	; NOTE: this assumes there is enough room in rsi for the conversion (caller is expected to have already called utf8_length)
	; also note: we do _not_ add a null terminator
	; but we _do_ return the length we wrote back into rax for convenience
falign
string$to_utf8:
	prolog	string$to_utf8

	mov     rax, rsi
	mov     rsi, rdi
	mov     rdi, rax        ; swap them so they are sensible d/s (unnecessary but nicer to read)

	; save rax above so we can do quickmath to reset it
	mov     r8, rax

	mov     rcx, [rsi]
	add     rsi, 8          ; rsi now pointing to start of our real buffer, rdi pointing to the passed in destination buffer for our resultant utf8
	test    rcx, rcx
	jz      .zerolength
calign
.innerloop:
	movzx   edx, word [rsi]
	cmp     edx, 0x80
	jb      .ascii
	cmp     edx, 0x800
	jb      .twobyte
	cmp     edx, 0xd800
	jb      .threebyte
	cmp     edx, 0xdbff
	ja      .threebyte
	sub     rcx, 1
	jz      .alldone
	add     rsi, 2
	movzx   eax, word [rsi]
	cmp     eax, 0xdc00
	jb      .threebytefffd
	cmp     edx, 0xdfff
	ja      .threebytefffd
	sub     edx, 0xd800
	shl     edx, 10
	sub     eax, 0xdc00
	add     edx, eax
	add     edx, 0x10000
	; edx now has our 32 bit goods to encode
	mov     eax, edx
	shr     eax, 18
	and     eax, 0x07
	or      eax, 0xf0
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	shr     eax, 12
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	shr     eax, 6
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1
	; and continue
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	sub     rax, r8         ; rax now has the # of characters we wrote
	epilog
calign
.threebytefffd:
	mov     edx, 0xfffd

	mov     eax, edx
	shr     eax, 12
	and     eax, 0x0f
	or      eax, 0xe0
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	shr     eax, 6
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1

	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	sub     rax, r8         ; rax now has the # of characters we wrote
	epilog
calign
.threebyte:
	cmp     edx, 0xdc00
	jl      .threebyteproceed
	cmp     edx, 0xdfff
	jg      .threebyteproceed
	jmp     .threebytefffd
calign
.threebyteproceed:
	mov     eax, edx
	shr     eax, 12
	and     eax, 0x0f
	or      eax, 0xe0
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	shr     eax, 6
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1
	mov     eax, edx
	and     eax, 0x3f
	or      eax, 0x80
	mov     byte [rdi], al
	add     rdi, 1

	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	sub     rax, r8         ; rax now has the # of characters we wrote
	epilog
calign
.twobyte:
	mov     eax, edx
	shr     eax, 6
	and     eax, 0x1f
	or      eax, 0xc0
	mov     byte [rdi], al
	add     rdi, 1
	and     edx, 0x3f
	or      edx, 0x80
	mov     byte [rdi], dl
	add     rdi, 1
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
	; copy of alldone fallthrough to avoid unnecessary space saving unconditional jump to .alldone
	mov     rax, rdi
	sub     rax, r8         ; rax now has the # of characters we wrote
	epilog
calign
.ascii:
	mov     byte [rdi], dl
	add     rdi, 1
	add     rsi, 2
	sub     rcx, 1
	jnz     .innerloop
calign
.alldone:
	mov     rax, rdi
	sub     rax, r8         ; rax now has the # of characters we wrote
	epilog
calign
.zerolength:
	; we can store a null byte at rdi
	xor     eax, eax
	epilog

end if


if used string$to_utf32 | defined include_everything
	; two arguments: string in rdi, destination buffer in rsi
	; NOTE: this assumes there is enough room in rsi for the conversion (caller is expected to have already called utf32_length)
	; also, if strict_utf, undefined things happen (e.g. it will stop midway on invalid) (if you have strict_utf enabled, check the length first)
	; this will return the # of codepoints written in rax
falign
string$to_utf32:
	prolog	string$to_utf32
	xor	eax, eax
	mov	rcx, qword [rdi]
	test	rcx, rcx
	jz	.alldone
	add	rdi, 8
calign
.top:
	movzx	edx, word [rdi]
	cmp	edx, 0xd800
	jb	.nothighsurr
	cmp	edx, 0xdbff
	ja	.nothighsurr
	cmp	word [rdi+2], 0xdc00
	jb	.invalid
	cmp	word [rdi+2], 0xdfff
	ja	.invalid
	
	sub	edx, 0xd800
	shl	edx, 10
	movzx	r8d, word [rdi+2]
	sub	r8d, 0xdc00
	add	edx, r8d
	add	edx, 0x10000
	mov	dword [rsi], edx
	add	rsi, 4
	add	rax, 1
	add	rdi, 4
	sub	rcx, 1
	jz	.alldone
	sub	rcx, 1
	jz	.alldone
	jmp	.top
calign
.nothighsurr:
if strict_utf
	cmp	edx, 0xdc00
	jb	.nothighokay
	cmp	edx, 0xdfff
	ja	.nothighokay
	jmp	.invalid
calign
.nothighokay:
end if
	mov	dword [rsi], edx
	add	rsi, 4
	add	rax, 1
	add	rdi, 2
	sub	rcx, 1
	jnz	.top
	; else, all done
	epilog
calign
.invalid:
if strict_utf
	xor	eax, eax
	epilog
else
	mov	dword [rsi], edx
	add	rsi, 4
	add	rax, 1
	add	rdi, 2
	sub	rcx, 1
	jnz	.top
	; else, all done
	epilog
end if
calign
.alldone:
	epilog
end if


if used string$to_stdoutln | defined include_everything
	; single argument; string in rdi... convenience function that tosses a \n on the end via a second syscall_write
falign
string$to_stdoutln:
	prolog	string$to_stdoutln
	call	string$to_stdout
	mov	eax, syscall_write
	mov	rsi, .lf
	mov	edx, 1
	mov	edi, 1
	syscall
	epilog
calign
.lf	db	10
end if
	

if used string$to_stdout | defined include_everything
	; single argument: string in rdi, convenience function to convert to utf8 and send to stdout (uses syscall to write)
falign
string$to_stdout:
	prolog	string$to_stdout
	push	r12 r13
	mov	r12, rdi
	call	string$utf8_length
	cmp	rax, 16384
	jge	.heapbased
	mov	r13, rax
	sub	rsp, rax
	mov	rsi, rsp
	mov	rdi, r12
	call	string$to_utf8

	mov	eax, syscall_write
	mov	rsi, rsp
	mov	rdx, r13
	mov	edi, 1
	syscall
	add	rsp, r13
	pop	r13 r12
	epilog
calign
.heapbased:
	push	r14
	mov	r14, rax	; the # of bytes
	; more than 16k worth of utf8, alloc on the heap instead of using stackspace
	mov	rdi, rax	; the # of bytes we want
	call	heap$alloc
	mov	r13, rax	; save our pointer
	mov	rsi, rax
	mov	rdi, r12
	call	string$to_utf8
	mov	eax, syscall_write
	mov	rsi, r13
	mov	rdx, r14
	mov	edi, 1
	syscall
	pop	r14
	mov	rdi, r13
	call	heap$free
	pop	r13 r12
	epilog
end if


if used string$to_stderrln | defined include_everything
	; single argument; string in rdi... convenience function that tosses a \n on the end via a second syscall_write
falign
string$to_stderrln:
	prolog	string$to_stderrln
	call	string$to_stderr
	mov	eax, syscall_write
	mov	rsi, .lf
	mov	edx, 1
	mov	edi, 2
	syscall
	epilog
calign
.lf	db	10
end if
	
if used string$to_stderr | defined include_everything
	; single argument: string in rdi, convenience function to convert to utf8 and send to stderr (uses syscall to write)
falign
string$to_stderr:
	prolog	string$to_stderr
	push	r12 r13
	mov	r12, rdi
	call	string$utf8_length
	cmp	rax, 16384
	jge	.heapbased
	mov	r13, rax
	sub	rsp, rax
	mov	rsi, rsp
	mov	rdi, r12
	call	string$to_utf8

	mov	eax, syscall_write
	mov	rsi, rsp
	mov	rdx, r13
	mov	edi, 2
	syscall
	add	rsp, r13
	pop	r13 r12
	epilog
calign
.heapbased:
	push	r14
	mov	r14, rax	; the # of bytes
	; more than 16k worth of utf8, alloc on the heap instead of using stackspace
	mov	rdi, rax	; the # of bytes we want
	call	heap$alloc
	mov	r13, rax	; save our pointer
	mov	rsi, rax
	mov	rdi, r12
	call	string$to_utf8
	mov	eax, syscall_write
	mov	rsi, r13
	mov	rdx, r14
	mov	edi, 2
	syscall
	pop	r14
	mov	rdi, r13
	call	heap$free
	pop	r13 r12
	epilog
end if

if used string$skip_whitespace | defined include_everything
	; two arguments: string in rdi, starting offset in rsi
	; returns (possibly unmodified) offset in rsi
falign
string$skip_whitespace:
	prolog	string$skip_whitespace
	mov	rax, rsi
	mov	r9, qword [rdi]
	add	rdi, 8
	cmp	rsi, r9
	jge	.alldone
calign
.spaceskip:
	movzx	ecx, word [rdi+rax*2]
	cmp	ecx, 32
	ja	.alldone
	mov	r8d, 1
	sub	ecx, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.alldone
	; else, we hit either a 32, 9, 10 or 13
	add	rax, 1
	cmp	rax, r9
	jl	.spaceskip
	sub	rdi, 8		; restore rdi as a convenience
	epilog
calign
.alldone:
	sub	rdi, 8		; restore rdi as a convenience
	epilog
end if

if used string$next_whitespace | defined include_everything
	; two arguments: string in rdi, starting offset in rsi
	; returns (possibly unmodified) offset in rax
falign
string$next_whitespace:
	prolog	string$next_whitespace
	mov	rax, rsi
	mov	r9, qword [rdi]
	add	rdi, 8
	cmp	rsi, r9
	jge	.alldone
calign
.spaceskip:
	movzx	ecx, word [rdi+rax*2]
	cmp	ecx, 32
	je	.alldone
	ja	.next
	mov	r8d, 1
	sub	ecx, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.next
	; else, we hit either a 32, 9, 10 or 13
	sub	rdi, 8		; restore rdi as a convenience
	epilog
calign
.next:
	add	rax, 1
	cmp	rax, r9
	jl	.spaceskip
	sub	rdi, 8		; restore rdi as a convenience
	epilog
calign
.alldone:
	sub	rdi, 8		; restore rdi as a convenience
	epilog
end if

if used string$to_int_radix | defined include_everything

	; two arguments: string in rdi, radix in esi
	; shortcuts/jumps into string$to_int
falign
string$to_int_radix:
	prolog	string$to_int_radix
	xor	r11d, r11d
	mov	r10d, esi
	jmp	string$to_int_withradix
end if


if used string$to_int | used string$to_int_radix | defined include_everything
	; single argument: string in rdi, returns integer conversion in rax
	; we are not strict, and will return whatever we can scrape out of it
falign
string$to_int:
	prolog	string$to_int
	xor	r11d, r11d	; default not negative
	mov	r10d, 10	; default radix 10
string$to_int_withradix:
	xor	eax, eax	; clear our result
	mov	r9, qword [rdi]
	add	rdi, 8
	; skip whatever leading spaces exist
	test	r9, r9
	jz	.alldone
calign
.spaceskip:
	movzx	ecx, word [rdi]
	mov	r8d, 1
	cmp	ecx, 32
	jae	.spacesdone
	sub	ecx, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.spacesdone
	; else, we hit either a 32, 9, 10, or 13
	add	rdi, 2
	sub	r9, 1
	jnz	.spaceskip
	; if we made it to here, r9 ran out of characters, alldone
	epilog
calign
.spacesdone:
	; check to see if we got a sign
	cmp	word [rdi], '+'
	jne	.notplus
	add	rdi, 2
	sub	r9, 1
	jz	.alldone
	jmp	.signchecked
calign
.notplus:
	cmp	word [rdi], '-'
	jne	.signchecked
	add	rdi, 2
	mov	r11d, 1		; negative number
	sub	r9, 1
	jz	.alldone
calign
.signchecked:
	cmp	r9, 2
	jb	.doit
	cmp	word [rdi], '0'
	jne	.doit
	cmp	word [rdi+2], 'x'
	jne	.doit
	mov	r10d, 16	; 0x found!
	add	rdi, 4
	sub	r9, 2
	jz	.alldone
calign
.doit:
	; so at this point:
	; rdi is our current buffer location
	; r9 is our current chars left (>0)
	; r10d is our radix
	; r11d is 0 or 1 for whether we have to negate the result
	movzx	ecx, word [rdi]
	add	rdi, 2
	cmp	ecx, '0'
	jb	.invalid
	cmp	ecx, '9'
	jbe	.numeric
	cmp	ecx, 'A'
	jb	.invalid
	cmp	ecx, 'F'
	jbe	.caphex
	cmp	ecx, 'a'
	jb	.invalid
	cmp	ecx, 'f'
	jbe	.hex
	test	r11d, r11d
	jnz	.negret
	epilog		; invalid if we made it to here
calign
.numeric:
	sub	ecx, '0'
	cmp	ecx, r10d
	jae	.invalid
	mul	r10	; rax = rax * radix
	add	rax, rcx	; + c
	sub	r9, 1
	jnz	.doit
	test	r11d, r11d
	jnz	.negret
	epilog
calign
.caphex:
	sub	ecx, 'A'
	add	ecx, 10
	cmp	ecx, r10d
	jae	.invalid
	mul	r10	; rax = rax * radix
	add	rax, rcx	; + c
	sub	r9, 1
	jnz	.doit
	test	r11d, r11d
	jnz	.negret
	epilog
calign
.hex:
	sub	ecx, 'a'
	add	ecx, 10
	cmp	ecx, r10d
	jae	.invalid
	mul	r10	; rax = rax * radix
	add	rax, rcx	; + c
	sub	r9, 1
	jnz	.doit
	test	r11d, r11d
	jnz	.negret
	epilog
calign
.negret:
	neg	rax
	epilog
calign
.invalid:
.alldone:
	epilog

end if


if used string$to_unsigned | defined include_everything
	; single argument: string in rdi, returns unsigned conversion in rax
falign
string$to_unsigned:
	prolog	string$to_unsigned
	mov	r10d, 10	; default radix 10
	xor	eax, eax	; clear our result
	mov	r9, qword [rdi]
	add	rdi, 8
	; skip whatever leading spaces exist
	test	r9, r9
	jz	.alldone
calign
.spaceskip:
	movzx	ecx, word [rdi]
	mov	r8d, 1
	cmp	ecx, 32
	jae	.spacesdone
	sub	ecx, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.spacesdone
	; else, we hit either a 32, 9, 10, or 13
	add	rdi, 2
	sub	r9, 1
	jnz	.spaceskip
	; if we made it to here, r9 ran out of characters, alldone
	epilog
calign
.spacesdone:
	; check to see if we got a sign
	cmp	word [rdi], '+'
	jne	.notplus
	add	rdi, 2
	sub	r9, 1
	jz	.alldone
	jmp	.signchecked
calign
.octal:
	cmp	word [rdi+2], '0'
	je	.doit
	add	rdi, 2
	mov	r10d, 8		; OCTAL
	sub	r9, 1
	jmp	.doit
calign
.notplus:
	cmp	word [rdi], '-'
	je	.invalid
calign
.signchecked:
	cmp	r9, 2
	jb	.doit
	cmp	word [rdi], '0'
	jne	.doit
	cmp	word [rdi+2], 'x'
	jne	.octal
	mov	r10d, 16	; 0x found!
	add	rdi, 4
	sub	r9, 2
	jz	.alldone
calign
.doit:
	; so at this point:
	; rdi is our current buffer location
	; r9 is our current chars left (>0)
	; r10d is our radix
	; r11d is 0 or 1 for whether we have to negate the result
	movzx	ecx, word [rdi]
	add	rdi, 2
	cmp	ecx, '0'
	jb	.invalid
	cmp	ecx, '9'
	jbe	.numeric
	cmp	ecx, 'A'
	jb	.invalid
	cmp	ecx, 'F'
	jbe	.caphex
	cmp	ecx, 'a'
	jb	.invalid
	cmp	ecx, 'f'
	jbe	.hex
	epilog		; invalid if we made it to here
calign
.numeric:
	sub	ecx, '0'
	cmp	ecx, r10d
	jae	.invalid
	mul	r10	; rax = rax * radix
	add	rax, rcx	; + c
	sub	r9, 1
	jnz	.doit
	epilog
calign
.caphex:
	sub	ecx, 'A'
	add	ecx, 10
	cmp	ecx, r10d
	jae	.invalid
	mul	r10	; rax = rax * radix
	add	rax, rcx	; + c
	sub	r9, 1
	jnz	.doit
	epilog
calign
.hex:
	sub	ecx, 'a'
	add	ecx, 10
	cmp	ecx, r10d
	jae	.invalid
	mul	r10	; rax = rax * radix
	add	rax, rcx	; + c
	sub	r9, 1
	jnz	.doit
	epilog
calign
.invalid:
.alldone:
	epilog

end if


if used string$to_double | defined include_everything
	; single argument: string in rdi, returns double conversion in xmm0
falign
string$to_double:
	prolog	string$to_double
	; empty string, or a string full of spaces == return _math_zero
	xor	r11d, r11d
	xor	edx, edx 	; we'll use edx for our digits counter
	xor	eax, eax	; and this for our exponents counter
	mov	r9, qword [rdi]
	add	rdi, 8
	xorpd	xmm0, xmm0
	; skip whatever leading spaces exist
	test	r9, r9
	jz	.alldone
calign
.spaceskip:
	movzx	ecx, word [rdi]
	mov	r8d, 1
	cmp	ecx, 32
	jae	.spacesdone
	sub	ecx, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.spacesdone
	; else, we hit either a 32, 9, 10, or 13
	add	rdi, 2
	sub	r9, 1
	jnz	.spaceskip
	; if we made it to here, r9 ran out of characters, alldone
	epilog
calign
.spacesdone:
	; check to see if we got a sign
	cmp	word [rdi], '+'
	jne	.notplus
	add	rdi, 2
	sub	r9, 1
	jz	.alldone
	mov	rsi, rdi	; save our start position
	mov	r10, r9		; save our charcount
	jmp	.signchecked
calign
.notplus:
	mov	rsi, rdi	; in case we jump, save them here too
	mov	r10, r9
	cmp	word [rdi], '-'
	jne	.signchecked
	add	rdi, 2
	mov	r11d, 1		; negative number
	sub	r9, 1
	jz	.alldone
	mov	rsi, rdi	; save our start position
	mov	r10, r9		; save our charcount
calign
.signchecked:
	; so at this point, r9 == characters left, r11d == bool negate, rdi == pointer to our current buffer position
	; our start pos and chars left have both been saved
	; now we need to scan our goods and figure out how many digits/exponents we are sitting on
	movzx	ecx, word [rdi]
	cmp	ecx, '0'
	jb	.checkdecimal
	cmp	ecx, '9'
	ja	.checkdecimal
	add	edx, 1
	add	rdi, 2
	sub	r9, 1
	jnz	.signchecked
calign
.checkdecimal:
	cmp	ecx, '.'
	jne	.checkexponent
	add	rdi, 2
	sub	r9, 1
	jz	.checknodigits
calign
.decimaldigits:
	movzx	ecx, word [rdi]
	cmp	ecx, '0'
	jb	.checkexponent
	cmp	ecx, '9'
	ja	.checkexponent
	add	edx, 1
	add	rdi, 2
	sub	r9, 1
	jnz	.decimaldigits
calign
.checkexponent:
	test	r9, r9
	jz	.checknodigits
	cmp	ecx, 'e'
	je	.gotexponent
	cmp	ecx, 'E'
	je	.gotexponent
calign
.checknodigits:
	; if our digit count is zero, check for +/- inf, anything else, puke NaN
	test	edx, edx
	jnz	.doit
	cmp	r9, 8
	jne	.parsefail	; we have to be sitting on precisely 8 chars left
	cmp	word [rdi], 'I'
	jne	.parsefail
	cmp	word [rdi+2], 'n'
	jne	.parsefail
	cmp	word [rdi+4], 'f'
	jne	.parsefail
	cmp	word [rdi+6], 'i'
	jne	.parsefail
	cmp	word [rdi+8], 'n'
	jne	.parsefail
	cmp	word [rdi+10], 'i'
	jne	.parsefail
	cmp	word [rdi+12], 't'
	jne	.parsefail
	cmp	word [rdi+14], 'y'
	jne	.parsefail
	; else, our original negation flag applies to infinite return
	test	r11d, r11d
	jnz	.neginf
	; positive infinity return
	movsd	xmm0, qword [_math_posinf]
	epilog
calign
.neginf:
	; negative infinity return
	movsd	xmm0, qword [_math_neginf]
	epilog
calign
.slowdoit:
	push	rbx r11 r12 r13 r14 r15		; we need to make a bunch of calls outta here
	sub	rsp, stringbi_size
	mov	rbx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0
	mov	r12, rdi
	mov	r13, r9
	mov	r14d, -1			; dd
	mov	r15d, eax			; exponents
calign
.slowdoitloop:
	movzx	edx, word [r12]
	cmp	edx, 46
	jb	.slowdoitdone
	cmp	edx, '9'
	ja	.slowdoitdone
	cmp	edx, 47
	je	.slowdoitdone
	cmp	r14d, -1
	je	.slowdoitloop_2
	add	r14d, 1
calign
.slowdoitloop_2:
	cmp	edx, '.'
	je	.slowdoitloop_3
	sub	edx, '0'
	mov	esi, 10
	mov	rdi, rbx
	call	stringbi$maib
	add	r12, 2
	sub	r13, 1
	jnz	.slowdoitloop
calign
.slowdoitdone:
	cmp	r14d, 0
	jle	.slowdoitcheckexp
	sub	r15d, r14d	; exponents -= dd
calign
.slowdoitcheckexp:
	cmp	r15d, 0
	jle	.slowdoit_getvalue
	; else, mbd string$qp10
	movsxd	rdi, r15d
	call	string$qp10
	mov	rdi, rbx
	call	stringbi$mbd
	xor	r15d, r15d
calign
.slowdoit_getvalue:
	mov	rdi, rbx
	call	stringbi$dvo
	cmp	r15d, 0
	jge	.slowdoit_noexpmod
	mov	eax, r15d		; put exponents back where it was
	add	rsp, stringbi_size
	pop	r15 r14 r13 r12 r11 rbx
	jmp	.doitnegexp		; this does the same goods on xmm0
calign
.slowdoit_noexpmod:
	; restore our stack, our value is in xmm0
	add	rsp, stringbi_size
	pop	r15 r14 r13 r12 r11 rbx
	test	r11d, r11d
	jz	.slowdoit_bailout
	; negate xmm0
	movsd	xmm1, qword [_math_negzero]
	xorpd	xmm0, xmm1	; negate our value
	epilog
calign
.slowdoit_bailout:
	epilog
calign
.doit:
	; input checked out, proceed with the dirty deed
	movsd	xmm1, [_math_ten]
	mov	rdi, rsi	; restore our start position
	mov	r9, r10		; restore our charcount
	cmp	edx, 15
	ja	.slowdoit
	mov	edx, -1
calign
.doitloop:
	movzx	ecx, word [rdi]
	cmp	ecx, 46
	jb	.doitdone
	cmp	ecx, '9'
	ja	.doitdone
	cmp	ecx, 47
	je	.doitdone
	cmp	edx, -1
	je	.doitloop_2
	add	edx, 1
calign
.doitloop_2:
	cmp	ecx, '.'
	je	.doitloop_3
	sub	ecx, '0'
	cvtsi2sd	xmm2, ecx
	; result = result * 10 + (ch - '0')
	mulsd	xmm0, xmm1	; * 10
	addsd	xmm0, xmm2	; + (ch - '0')
	add	rdi, 2
	sub	r9, 1
	jnz	.doitloop
calign
.doitdone:
	cmp	edx, 0
	jle	.doitcheckexp
	sub	eax, edx	; exponents -= dd
	; copy of .doitcheckexp to avoid the LONG nopfill
	cmp	eax, 0
	jl	.doitnegexp
	push	r11		; save whether to negate it or not
	sub	rsp, 8
	movsd	qword [rsp], xmm0	; save our actual result
	mov	edi, eax	; arg to string$qp10
	call	string$qp10
	movsd	xmm1, xmm0
	movsd	xmm0, qword [rsp]
	add	rsp, 8
	pop	r11
	mulsd	xmm0, xmm1
	test	r11d, r11d
	jz	.alldone
	; negate xmm0
	movsd	xmm1, qword [_math_negzero]
	xorpd	xmm0, xmm1	; negate our value
	epilog
calign
.doitcheckexp:
	cmp	eax, 0
	jl	.doitnegexp
	push	r11		; save whether to negate it or not
	sub	rsp, 8
	movsd	qword [rsp], xmm0	; save our actual result
	mov	edi, eax	; arg to string$qp10
	call	string$qp10
	movsd	xmm1, xmm0
	movsd	xmm0, qword [rsp]
	add	rsp, 8
	pop	r11
	mulsd	xmm0, xmm1
	test	r11d, r11d
	jz	.alldone
	; negate xmm0
	movsd	xmm1, qword [_math_negzero]
	xorpd	xmm0, xmm1	; negate our value
	epilog
calign
.doitloop_3:
	xor	edx, edx	; dd = 0
	add	rdi, 2
	sub	r9, 1
	jnz	.doitloop
	jmp	.doitdone
calign
.slowdoitloop_3:
	xor	r14d, r14d	; dd = 0
	add	r12, 2
	sub	r13, 1
	jnz	.slowdoitloop
	jmp	.slowdoitdone
calign
.doitnegexp:
	cmp	eax, -307
	jge	.doitnegexp_nomod
	; dont go over... max 308, min -324
	mov	ecx, eax
	add	ecx, 307
	push	rax rcx r11
	neg	ecx
	sub	rsp, 8
	movsd	qword [rsp], xmm0	; save our actual result
	movsxd	rdi, ecx	; arg to string$qp10
	call	string$qp10
	movsd	xmm1, xmm0
	movsd	xmm0, qword [rsp]
	divsd	xmm0, xmm1	; result /= string$qp10(-d)
	add	rsp, 8
	pop	r11 rcx rax
	sub	eax, ecx
calign
.doitnegexp_nomod:
	neg	eax
	push	r11
	sub	rsp, 8
	movsd	qword [rsp], xmm0
	movsxd	rdi, eax
	call	string$qp10
	movsd	xmm1, xmm0
	movsd	xmm0, qword [rsp]
	divsd	xmm0, xmm1
	add	rsp, 8
	pop	r11
	test	r11d, r11d
	jz	.alldone
	; negate xmm0
	movsd	xmm1, qword [_math_negzero]
	xorpd	xmm0, xmm1	; negate our value
	epilog
calign
.gotexponent:
	; we have to parse _after_ the e, and if our parse fails at this point, probably should return NaN or something
	mov	r8d, 10
	add	rdi, 2
	sub	r9, 1
	jz	.parsefail
	movzx	ecx, word [rdi]
	; can be e+23, e23, e-7
	cmp	ecx, '-'
	je	.negativeexp
	cmp	ecx, '+'
	je	.positiveexp
	; else, we can commence our digit loop
	cmp	ecx, '0'
	jb	.parsefail
	cmp	ecx, '9'
	ja	.parsefail
	push	rdx		; save our rdx value cuz we need to blast it w/ mul
	sub	ecx, '0'
	xor	edx, edx	; clear rdx for the mul
	mul	r8d		; eax = eax * 10
	pop	rdx
	add	eax, ecx	; + c - '0'
	add	rdi, 2
	sub	r9, 1
	jz	.checknodigits	; this is ok because we don't have to negate eax
calign
.positivedigits:
	movzx	ecx, word [rdi]
	cmp	ecx, '0'
	jb	.parsefail
	cmp	ecx, '9'
	ja	.parsefail
	push	rdx
	sub	ecx, '0'
	xor	edx, edx
	mul	r8d
	pop	rdx
	add	eax, ecx
	add	rdi, 2
	sub	r9, 1
	jnz	.positivedigits
	jmp	.checknodigits
calign
.negativedigits:
	movzx	ecx, word [rdi]
	cmp	ecx, '0'
	jb	.parsefail
	cmp	ecx, '9'
	ja	.parsefail
	push	rdx
	sub	ecx, '0'
	xor	edx, edx
	mul	r8d
	pop	rdx
	add	eax, ecx
	add	rdi, 2
	sub	r9, 1
	jnz	.positivedigits
	neg	eax			; negate exp10 before we bail
	jmp	.checknodigits
calign
.negativeexp:
	add	rdi, 2
	sub	r9, 1
	jz	.parsefail
	jmp	.negativedigits
calign
.positiveexp:
	add	rdi, 2
	sub	r9, 1
	jz	.parsefail
	jmp	.positivedigits
calign
.parsefail:
	movsd	xmm0, qword [_math_nan]
	epilog
calign
.alldone:
	epilog
end if


if used string$to_upper | defined include_everything
	; single argument: string in rdi, returns NEW string uppercased
falign
string$to_upper:
	prolog	string$to_upper
	push	r12
	call	string$copy
	mov	rdi, rax
	mov	r12, rax
	call	string$to_upper_inplace
	mov	rax, r12
	pop	r12
	epilog
end if

if used string$to_lower | defined include_everything
	; single argument: string in rdi, returns NEW string lowercased
falign
string$to_lower:
	prolog	string$to_lower
	push	r12
	call	string$copy
	mov	rdi, rax
	mov	r12, rax
	call	string$to_lower_inplace
	mov	rax, r12
	pop	r12
	epilog
end if

if used string$to_upper_inplace | defined include_everything
	; unlike the rest of our funcs, this one actually messes with the string in place
	; in other words: do not use this on readonly created strings, haha
	; single argument: string in rdi
falign
string$to_upper_inplace:
	prolog	string$to_upper_inplace
	push	rbx r12
	mov	rbx, [rdi]
	test	rbx, rbx
	jz	.nothingtodo
	mov	r12, rdi
	add	r12, 8
calign
.loop:
	movzx	edi, word [r12]
	call	utf16$upper
	mov	word [r12], ax
	add	r12, 2
	sub	rbx, 1
	jnz	.loop
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	pop	r12 rbx
	epilog
end if


if used string$to_lower_inplace | defined include_everything
	; single argument: string in rdi
falign
string$to_lower_inplace:
	prolog	string$to_lower_inplace
	push	rbx r12
	mov	rbx, [rdi]
	test	rbx, rbx
	jz	.nothingtodo
	mov	r12, rdi
	add	r12, 8
calign
.loop:
	movzx	edi, word [r12]
	call	utf16$lower
	mov	word [r12], ax
	add	r12, 2
	sub	rbx, 1
	jnz	.loop
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	pop	r12 rbx
	epilog
end if

if used string$substr | defined include_everything
	; three arguments: string in rdi, start in rsi, LENGTH in rdx, returns new string
	; pass -1 (0xffff...etc) or length > actual length if you want to the end
falign
string$substr:
	prolog	string$substr
	mov	r9, qword [rdi]	; length of our string
	xor	r8d, r8d		; for our cmov
	cmp	rsi, 0			; is the start < 0
	cmovl	rsi, r8		; if so, set to 0... TODO: are we really treating rsi as signed?
	cmp	rsi, r9		; is the start greater than the length?
	cmovg	rsi, r9

	mov	rax, r9		; get our length
	sub	rax, rsi		; minus our start
	
	cmp	rdx, rax		; is our requested substr length too big?
	cmova	rdx, rax

	add	rdx, rsi		; add our substr length to the start
	cmp	rdx, r9		; past the end?
	cmova	rdx, r9 
	
	jmp	string$substring_goodvals
	
	epilog
end if

if used string$substr | used string$substring | defined include_everything
	; three arguments: string in rdi, start in rsi, END in rdx (actual offset, not length like substr), returns new string
falign
string$substring:
	prolog	string$substring
	mov	r9, qword [rdi]
	xor	r8d, r8d
	cmp	rsi, 0
	cmovl	rsi, r8
	cmp	rsi, r9
	cmovg	rsi, r9

	; start validated, now make sure our length isn't past the end
	cmp	rdx, r9
	cmova	rdx, r9
calign
string$substring_goodvals:
	test	rsi, rsi
	jz	.checksame

	cmp	rdx, rsi
	jle	.emptystring

	; length in characters: end - start
	; in bytes << 1
	sub	rdx, rsi
	shl	rdx, 1
	shl	rsi, 1
	add	rdi, 8
	add	rdi, rsi
	mov	rsi, rdx
	call	string$from_utf16
	epilog
calign
.checksame:
	cmp	rdx, r9
	jne	.notsame
	call	string$copy
	epilog
calign
.notsame:
	cmp	rdx, rsi
	jle	.emptystring
	sub	rdx, rsi
	shl	rdx, 1
	shl	rsi, 1
	add	rdi, 8
	add	rdi, rsi
	mov	rsi, rdx
	call	string$from_utf16
	epilog
calign
.emptystring:
	call	string$new
	epilog
end if

if used string$indexofchar | defined include_everything
	; indexofchar: private routine that does the dirty work
falign
string$indexofchar:
	; no prolog/epilog? hmm
        ; ok, our source string is in rdi, our start is in rsi, our right is in rdx, and our char is in rcx
        sub     rdx, rsi                ; how many characters we have to count
        lea     rsi, [rdi+rsi*2]        ; our starting location is now in rsi
        pxor    xmm0, xmm0
        and     ecx, 0xffff             ; make sure ecx only has the lower word
        mov     eax, ecx
        shl     ecx, 16                 ; move low word in ecx to high word
        or      ecx, eax                ; put them both together so we have 2 words of the same thing
        ; ok, so now we want to make a 128 bit version of it
        movd    xmm1, ecx               ; load up the 32 bit happenin
        pshufd  xmm1, xmm1, 0           ; per the order 0 byte, copy/replicate the 32 bits 4 times
        ; ok, so now xmm1 contains our input cx, unsigned short, packed 8 times
        and     ecx, 0xffff             ; make ecx back to just our word
        test    rdx, rdx
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned              ; if we have <8 chars left, we can't load 16 bytes
        ; our address is in rsi
        test    rsi, 0xf
        jz      .aligned16

	; these are unrolled on purpose

        ; need to copy the fallthrough of .unaligned here to avoid nop fill
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        ;jmp     .unaligned
        ; need to copy the fallthrough of .unaligned here to avoid nop fill
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        ;jmp     .unaligned
        ; need to copy the fallthrough of .unaligned here to avoid nop fill
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        ;jmp     .unaligned
        ; need to copy the fallthrough of .unaligned here to avoid nop fill
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        ;jmp     .unaligned
        ; need to copy the fallthrough of .unaligned here to avoid nop fill
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        ;jmp     .unaligned
        ; need to copy the fallthrough of .unaligned here to avoid nop fill
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        ;jmp     .unaligned
calign
.unaligned:
        ; cx still has our input character in it i am pretty sure
        ; lets just step forward until we are aligned (or done)
        test    rdx, rdx
        jz      .zeroret
        movzx   eax, word [rsi]
        cmp     ecx, eax
        je      .foundit
        add     rsi, 2
        sub     rdx, 1
        jz      .zeroret
        cmp     rdx, 8
        jl      .unaligned
        test    rsi, 0xf
        jz      .aligned16
        jmp     .unaligned
calign
.foundit:
        sub     rsi, rdi
        shr     rsi, 1
        mov     rax, rsi
        ret
calign
.zeroret:
        mov     rax, -1
        ret
calign
.aligned16:
        movaps  xmm2, [rsi]
        add     rsi, 16
        sub     rdx, 8
        pcmpeqw xmm2, xmm1
        pmovmskb        eax, xmm2
        test    eax, eax
        jnz     .foundone
        cmp     rdx, 8
        jl      .unaligned
        jmp     .aligned16
calign
.foundone:
        bsf     eax, eax                ; hmmm
        sub     rsi, 16
        add     rsi, rax
        sub     rsi, rdi
        shr     rsi, 1
        mov     rax, rsi
        ret

end if

if used string$indexof_charcode | defined include_everything
	; two arguments: string in rdi, char in esi, returns index of char or -1 in rax
falign
string$indexof_charcode:
	prolog	string$indexof_charcode
	mov	ecx, esi
	mov	rdx, qword [rdi]
	add	rdx, 1		; hmm, end + 1?
	xor	esi, esi
	add	rdi, 8
	; so now, buffer in rdi, start in rsi, end in rdx, char in ecx
	call	string$indexofchar
	epilog
end if

if used string$indexof_charcode_ofs | defined include_everything
	; three arguments: string in rdi, char in esi, start offset in rdx
falign
string$indexof_charcode_ofs:
	prolog	string$indexof_charcode_ofs
	mov	ecx, esi	; char where it belongs
	mov	rsi, rdx	; start
	mov	rdx, qword [rdi]
	add	rdx, 1		; hmm, end + 1?
	add	rdi, 8
	cmp	rsi, rdx
	jae	.negoneret
	call	string$indexofchar
	epilog
calign
.negoneret:
	mov	rax, -1
	epilog
end if


if used string$indexof_charcode_ofsend | defined include_everything
	; four arguments: string in rdi, char in esi, start = rdx, end = rcx
falign
string$indexof_charcode_ofsend:
	prolog	string$indexof_charcode_ofsend
	mov	rax, rcx	; end save
	mov	ecx, esi	; char where it belongs
	add	rax, 1		; proper end for our indexofchar
	mov	rsi, rdx	; start
	mov	rdx, rax	; end
	mov	rax, [rdi]	; length
	add	rdi, 8		; buffer start
	cmp	rsi, rdx
	jae	.negoneret
	cmp	rdx, rax
	ja	.negoneret
	call	string$indexofchar
	epilog
calign
.negoneret:
	mov	rax, -1
	epilog
end if
	
if used string$indexof | defined include_everything
	; two arguments: string in rdi, string in rsi, returns index of string or -1 in rax
falign
string$indexof:
	prolog	string$indexof
	xor	edx, edx
	call	string$indexof_ofs
	epilog
end if

if used string$indexof_ofs | defined include_everything
	; three arguments: string in rdi, string in rsi, start offset in rdx
falign
string$indexof_ofs:
	prolog	string$indexof_ofs
        ; rdx has our start offset (rdi = this, rsi = other, rdx = start)
        push    rbx r12 r13
        ; first, check the length of _both_ strings are nonzero, else ret negone
        mov     r8, [rdi]
        test    r8, r8
        jz      .negoneret
        mov     r9, r8                  ; save the length(right) of our source string
        cmp     qword [rsi], 0
        je      .negoneret
        ; if the substring length is > our length, also return negone
        cmp     r8, qword [rsi]
        jb      .negoneret
        ; else, sublen < len, so the length of our string that we need to check is len - sublen
        sub     r8, qword [rsi]
        ; r8 is now our "max start"
        ; r9 is our length of our string
        ; we want to save the length of our substring
        mov     r10, [rsi]
        ; r10 now has the length of our substring
        ; rdi doesn't get messed with in string$indexofchar, but the others do, so save rsi too
        mov     r11, rsi
        add     r11, 8                  ; align with our buffer
        add     rdi, 8                  ; align with our buffer
        ; ok, so at this point: r8 = maximum start position to search at (length - sublength)
        ; r9 = length of our string in rdi
        ; r10 is the length of our sub string
        ; r11 is our substring buffer itself
        ; rdi is our string buffer
        ; now we need a "start" offset variable, which we'll use rbx for
        mov     rbx, rdx                ; start position
        ; while (rbx <= r8) ...
calign
.outerloop:
        cmp     rbx, r8
        ja      .negoneret
        ; get the first char of [r11] to search for
        movzx   ecx, word [r11]
        mov     rdx, r8                 ; max length
        add     rdx, 1                  ; proper end for indexofchar
        mov     rsi, rbx                ; our start position
        ; rdi is still valid
        call    string$indexofchar
        cmp     rax, -1
        jne     .checkit
        pop     r13 r12 rbx                     ; string$indexofchar said no such first char, ret -1
        epilog
calign
.checkit:
        ; ok, rax == position that string$indexofchar found our first character at (rdi + this << 1 == spot)
        mov     rdx, rax
        shl     rdx, 1
        add     rdx, rdi                ; [rdx] now at our found position in our source buffer
        ; set rsi to our sub string
        mov     rsi, r11
        ; set rcx to our substring length
        mov     rcx, r10
        ; now, loop through while [rdx] == [rsi]
calign
.subloop:
        movzx   r12d, word [rdx]
        movzx   r13d, word [rsi]
        cmp     r13d, r12d
        jne     .mismatch
        add     rdx, 2
        add     rsi, 2
        sub     rcx, 1
        jnz     .subloop
        ; else, we made it all the way
        ; rax still has our return goods
        pop     r13 r12 rbx     ; restore our callee-saves
        epilog
calign
.mismatch:
        ; we found a char that didn't match, pop rax, set rbx = rax + 1 and keep going
        mov     rbx, rax
        add     rbx, 1
        jmp     .outerloop
calign
.negoneret:
        mov     rax, -1
        pop     r13 r12 rbx
	epilog
end if

if used string$last_indexof | defined include_everything
	; two arguments: string in rdi, string in rsi, returns index of string or -1 in rax
falign
string$last_indexof:
	prolog	string$last_indexof
	xor	rdx, rdx
	call	string$last_indexof_ofs
	epilog
end if

if used string$last_indexof_ofs | defined include_everything
	; three arguments: string in rdi, string in rsi, start offset in rdx
falign
string$last_indexof_ofs:
	prolog	string$last_indexof_ofs
        ; ok, well, there is no pretty/efficient way to do this one... walk backward through our source string like i did in the other implementation
        mov     r8, [rdi]
        test    r8, r8
        jz      .negoneret
        mov     r9, [rsi]
        test    r9, r9
        jz      .negoneret
        cmp     r8, r9
        jl      .negoneret      ; if the substring length > our length, return negone

        add     rdi, 8
        add     rsi, 8          ; both spots pointed into the buffer, now we need to adjust for our starting location of (r8 - r9) << 1
        mov     rax, r8
        sub     rax, r9         ; ok, this is our return value, _if_ we find it... but we need to adjust rdi forward by this much

        ; rax is now pointed to the length of our source string minus the length of our substring
        ; we need to account for _start_ in rdx... if it is nonzero, then rdi and rax need to be adjusted to the start position
        test    rdx, rdx
        jnz     .setup_start_offset
        ; else, go ahead and fallthrough
        add     rdi, rax
        add     rdi, rax        ; ok, rdi is now pointed into the spot where we'd end, rsi is pointed into the spot of our substring, r9 is our substring length
calign
.outerloop:
        xor     ecx, ecx        ; reset the counter
calign
.innerloop:
        mov     r10w, word [rdi+rcx*2]
        cmp     r10w, word [rsi+rcx*2]
        jne     .nextone
        add     rcx, 1
        cmp     rcx, r9         ; did we get to our substring length?
        jl      .innerloop
        ; else, we found it
        ; rax has our offset
        ; so we can just epilog, yeh?
        epilog
calign
.nextone:
        sub     rdi, 2
        sub     rax, 1
        cmp     rax, 0
        jl      .negoneret
        jmp     .outerloop
calign
.negoneret:
        mov     rax, -1
        epilog
calign
.setup_start_offset:
        cmp     rdx, rax                ; start can't be more than this
        ja      .negoneret
        ; else, use rdx as our starting point instead of rax
        mov     rax, rdx
        add     rdi, rax
        add     rdi, rax
        jmp     .outerloop
end if


if used string$starts_with | defined include_everything
	; two arguments: string in rdi, string in rsi, returns bool in rax
falign
string$starts_with:
	prolog	string$starts_with
	mov	rdx, qword [rsi]
	mov	rcx, qword [rdi]
	cmp	rcx, rdx
	jl	.zeroret	; length of first string is less than second
	test	rcx, rcx
	jz	.zeroret	; first string is empty
	test	rdx, rdx
	jz	.oneret		; length of second string is empty, so we'll say, yes yes it does start with it
	; otherwise, first string length is >= second string, do a quick compare of their buffers
	shl	rdx, 1		; length of second string in bytes
	add	rdi, 8
	add	rsi, 8
	call	memcmp16
	test	rax, rax
	jz	.oneret
	xor	eax, eax
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
end if

if used string$ends_with | defined include_everything
	; two arguments: string in rdi, string in rsi, returns bool in rax
falign
string$ends_with:
	prolog	string$ends_with
	mov	rdx, qword [rsi]
	mov	rcx, qword [rdi]
	cmp	rcx, rdx
	jl	.zeroret	; length of first string is less than second
	test	rcx, rcx
	jz	.zeroret	; first string is empty
	test	rdx, rdx
	jz	.oneret		; length of second string is empty, so we'll say, yes yes it does start with it
	; otherwise, first string length is >= second string, do a quick compare of their buffers
	mov	rax, rcx	; length of left string
	sub	rax, rdx	; minus length of right string
	shl	rax, 1
	add	rdi, 8
	add	rdi, rax
	shl	rdx, 1		; length of second string in bytes
	add	rsi, 8
	call	memcmp16
	test	rax, rax
	jz	.oneret
	xor	eax, eax
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
end if


if used string$equals | defined include_everything
	; two arguments: string in rdi, string in rsi, returns bool in rax
falign
string$equals:
	prolog	string$equals
	cmp	rdi, rsi
	je	.oneret
	mov	rdx, qword [rsi]
	mov	rcx, qword [rdi]
	cmp	rcx, rdx
	jne	.zeroret
	test	rcx, rcx
	jz	.oneret
	; else, length nonzero and equal
	shl	rdx, 1	; length in bytes
	add	rdi, 8
	add	rsi, 8
	call	memcmp16
	test	rax, rax
	jz	.oneret
	xor	eax, eax
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
end if

if used string$equals_ignorecase | defined include_everything
	; two arguments: string in rdi, string in rsi, returns bool in rax
falign
string$equals_ignorecase:
	prolog	string$equals_ignorecase
	; messy by nature
	cmp	rdi, rsi
	je	.oneret
	mov	rdx, qword [rsi]
	mov	rcx, qword [rdi]
	cmp	rcx, rdx
	jne	.zeroret
	test	rcx, rcx
	jz	.oneret
	; else, length nonzero and equal
	push	r12 r13
	mov	r13, rsi
	call	string$copy
	mov	r12, rax
	mov	rdi, rax
	call	string$to_upper_inplace
	mov	rdi, r13
	call	string$copy
	mov	r13, rax
	mov	rdi, rax
	call	string$to_upper_inplace
	mov	rdi, r12
	mov	rsi, r13
	call	string$equals
	mov	rdi, r12
	mov	r12, rax		; save our return
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rax, r12
	pop	r13 r12
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
end if


if used string$compare | defined include_everything
	; two arguments: string in rdi, string in rsi, returns sort-style compare in rax
falign
string$compare:
	prolog	string$compare
	mov	rdx, [rdi]			; our length
	mov	rcx, [rsi]			; other length
	xor	eax, eax
	cmp	rdi, rsi
	je	.bailout
	cmp	rdx, rcx
	cmova	rdx, rcx
	test	rdx, rdx
	jz	.skipcomp
	push	rdi rsi
	add	rdi, 8
	add	rsi, 8
calign
.comploop:
	movzx	eax, word [rdi]
	cmp	ax, word [rsi]
	jne	.compdone
	add	rdi, 2
	add	rsi, 2
	sub	rdx, 1
	jnz	.comploop
	pop	rsi rdi
	; if result == 0, do skipcomp, otherwise, rax is our result and bailout
calign
.skipcomp:
	mov	rax, [rsi]
	mov	r8, -1
	mov	r9d, 1
	sub	rax, [rdi]
	cmp	rax, 0
	cmovl	rax, r8
	cmovg	rax, r9
	epilog
calign
.compdone:
	mov	r8, -1
	mov	r9d, 1
	cmovb	rax, r8
	cmova	rax, r9
	pop	rsi rdi
	epilog
calign
.bailout:
	epilog

end if

if used string$charat | defined include_everything
	; two arguments: string in rdi, index in rsi, returns char in rax
	; you should probably just calc/use the buffer directly
falign
string$charat:
	prolog	string$charat
	cmp	rsi, qword [rdi]
	jae	.zeroret
	shl	rsi, 1
	add	rdi, 8
	add	rdi, rsi
	movzx	eax, word [rdi]
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if

if used string$split | defined include_everything
	; two arguments: string in rdi, split character in esi
	; returns a new list (which may be empty)
falign
string$split:
	prolog	string$split
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13d, esi
	xor	r15d, r15d
	call	list$new
	mov	r14, rax
calign
.while:
	cmp	r15, qword [r12]
	jae	.done

	mov	rdi, r12	; string
	mov	esi, r13d	; character
	mov	rdx, r15	; pos
	call	string$indexof_charcode_ofs
	cmp	rax, 0
	jl	.lastone
	; else, we need a substring from r15 to (rax - r15)
	; and then set pos = rax + 1
	mov	rdi, r12	; string
	mov	rsi, r15	; pos
	mov	rdx, rax
	sub	rdx, r15	; length
	mov	r15, rax
	add	r15, 1		; new pos
	call	string$substr
	mov	rdi, r14
	mov	rsi, rax
	call	list$push_back
	jmp	.while
calign
.lastone:
	mov	rdi, r12	; string
	mov	rsi, r15	; pos
	mov	rdx, -1		; length
	call	string$substr
	mov	rdi, r14
	mov	rsi, rax
	call	list$push_back
	mov	rax, r14
	pop	r15 r14 r13 r12
	epilog
calign
.done:
	mov	rax, r14
	pop	r15 r14 r13 r12
	epilog
	

end if

if used string$split_str | defined include_everything
	; two arguments: string in rdi, split string in rsi
	; returns a new list (which may be empty)
falign
string$split_str:
	prolog	string$split_str
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	xor	r15d, r15d
	call	list$new
	mov	r14, rax
calign
.while:
	cmp	r15, qword [r12]
	jae	.done
	
	mov	rdi, r12	; string
	mov	rsi, r13	; split string
	mov	rdx, r15	; pos
	call	string$indexof_ofs
	cmp	rax, 0
	jl	.lastone
	; else, we need a substring from r15 to (rax - r15)
	; and then set pos = rax + length of split string
	mov	rdi, r12	; string
	mov	rsi, r15	; pos
	mov	rdx, rax
	sub	rdx, r15	; length
	mov	r15, rax
	add	r15, [r13]	; new pos
	call	string$substr
	mov	rdi, r14
	mov	rsi, rax
	call	list$push_back
	jmp	.while
calign
.lastone:
	mov	rdi, r12	; string
	mov	rsi, r15	; pos
	mov	rdx, -1		; length
	call	string$substr
	mov	rdi, r14
	mov	rsi, rax
	call	list$push_back
	mov	rax, r14
	pop	r15 r14 r13 r12
	epilog
calign
.done:
	mov	rax, r14
	pop	r15 r14 r13 r12
	epilog

end if

if used string$isnumber | defined include_everything
	; single argument: string in rdi
	; returns bool in eax for true/false
	; NOTE: spaces are not allowed, and this is not entirely correct
	; TODO: come back and make this a bit more robust
falign
string$isnumber:
	prolog	string$isnumber
	mov	rsi, rdi
	mov	rcx, [rdi]
	add	rdi, 8
	test	rcx, rcx
	jz	.zeroret
	xor	r8d, r8d	; ecount
	xor	r9d, r9d	; dcount
	xor	r10d, r10d	; mcount
calign
.loop:
	movzx	eax, word [rdi]
	add	rdi, 2
	cmp	eax, 45		; -
	jb	.zeroret
	je	.dash
	cmp	eax, 46
	je	.decimal
	cmp	eax, 47
	je	.zeroret
	cmp	eax, '9'
	jbe	.next		; digit
	cmp	eax, 'e'
	je	.gote
	cmp	eax, 'E'
	je	.gote
	jmp	.zeroret
calign
.dash:
	test	r10d, r10d
	jnz	.zeroret
	add	r10d, 1
	sub	rcx, 1
	jz	.zeroret
	jmp	.loop
calign
.decimal:
	test	r9d, r9d
	jnz	.zeroret
	add	r9d, 1
	sub	rcx, 1
	jz	.zeroret
	jmp	.loop
calign
.gote:
	test	r8d, r8d
	jnz	.zeroret
	add	r8d, 1
	sub	rcx, 1
	jz	.zeroret
	jmp	.loop
calign
.next:
	sub	rcx, 1
	jnz	.loop
	; otherwise, we made it through
	cmp	qword [rsi], 2
	jb	.oneret
	cmp	dword [rsi+8], '0'
	jne	.oneret
	cmp	dword [rsi+12], '.'
	jne	.zeroret
calign
.oneret:
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if



if used string$hexdecode | defined include_everything
	; two arguments: rdi == string, rsi == pointer to buffer
	; it is assumed on entry that rsi already contains enough space (up to the caller to work that out)
	; returns # of bytes we wrote to rsi in rax
	
	; we are NOT tolerant of rubbish, and will simply abort and return with however many we made it through (though we will skip whitespace)
falign
string$hexdecode:
	prolog	string$hexdecode
	push	rsi rdi
	xor	eax, eax
	mov	rcx, [rdi]
	add	rdi, 8
	test	rcx, rcx
	jz	.bailout
calign
.doit:
	movzx	edx, word [rdi]
	sub	rcx, 1
	jz	.bailout

	cmp	edx, 32
	jbe	.whitespaceordie

	movzx	r8d, word [rdi+2]
	add	rdi, 4
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
	test	r9d, 0xf0
	jnz	.bailout

	shl	r9d, 4
	or	r9d, r10d
	mov	byte [rsi], r9b
	add	rsi, 1
	add	rax, 1
	
	sub	rcx, 1
	jnz	.doit
	add	rsp, 16
	epilog
calign
.whitespaceordie:
	; TODO: test this similar to skip/iswhitespace/etc above
	add	rdi, 2
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
	add	rsp, 16
	epilog

end if


if used string$base64decode | defined include_everything
	; three arguments: rdi == string, rsi == pointer to buffer, rdx == 0 == default base64 table, else rdx == base64 table to use
	; it is assumed on entry that rsi already contains enough space (up to the caller to work that out)

	; note on table in rdx: if a custom one is supplied, it must be a pointer to a table of 128 dwords with the index presupplied
	; for the given character offset

	; CAUTION: we do dword writes at a time only to rsi, so there must be enough trailing space to accommodate an extra few bytes

	; returns # of bytes we wrote to rsi in rax

	; we are NOT tolerant of rubbish, and will simply abort and return with however many we made it through (though we will skip whitespace)
falign
string$base64decode:
	prolog	string$base64decode
	xor	eax, eax
	cmp	qword [rdi], 0
	je	.nothingtodo
	mov	rcx, .default_table
	; originally I was doing outside calls from in here, hence all the callee-saves, TODO: remove them
	push	rbp rbx r12 r13 r14 r15 rsi
	mov	rbx, [rdi]		; characters in our string
	test	rdx, rdx
	cmovz	r12, rcx
	cmovnz	r12, rdx		; our base64 table
	mov	r13, rsi		; our destination buffer
	mov	r14, rdi
	add	r14, 8			; first character of our source string
	xor	r15d, r15d		; our accumulator
	xor	ebp, ebp		; # of bits in our accumulator
calign
.doit:
	movzx	ecx, word [r14]
	add	r14, 2
	cmp	ecx, 32
	jbe	.whitespaceordie
	; not whitespace, do our table lookup
	cmp	ecx, 128
	jae	.doret
	mov	eax, dword [r12+rcx*4]	; the character
	cmp	eax, -1
	je	.doret
	mov	ecx, ebp
	and	eax, 0x3f
	shl	rax, cl
	add	r15, rax
	add	ebp, 8
	cmp	ebp, 32
	jae	.next_dowrite
	sub	rbx, 1
	jnz	.doit
	jmp	.doret
calign
.next_dowrite:
	mov	eax, r15d
	mov	ecx, r15d
	mov	edx, r15d

	and	eax, 0xff
	shl	eax, 2
	shr	ecx, 12
	and	ecx, 3
	or	eax, ecx
	mov	ecx, r15d
	shr	ecx, 4
	and	ecx, 0xf0
	shr	edx, 18
	and	edx, 0xf
	or	ecx, edx

	mov	edx, r15d
	shr	edx, 10
	and	edx, 0xc0
	shr	r15d, 24
	or	edx, r15d
	shl	ecx, 8
	shl	edx, 16
	or	eax, ecx
	or	eax, edx

	mov	dword [r13], eax
	add	r13, 3
	shr	r15, 32
	sub	ebp, 32
	sub	rbx, 1
	jnz	.doit
	; fallthrough to doret
calign
.doret:
	; put whatever remaining bits are in our accum
	mov	eax, r15d
	mov	ecx, r15d
	mov	edx, r15d

	and	eax, 0xff
	shl	eax, 2
	shr	ecx, 12
	and	ecx, 3
	or	eax, ecx
	mov	ecx, r15d
	shr	ecx, 4
	and	ecx, 0xf0
	shr	edx, 18
	and	edx, 0xf
	or	ecx, edx
	mov	edx, r15d
	shr	edx, 10
	and	edx, 0xc0
	shr	r15d, 24
	or	edx, r15d
	shl	ecx, 8
	shl	edx, 16
	or	eax, ecx
	or	eax, edx

	mov	dword [r13], eax
	shr	ebp, 3

        ; A single '=' indicates that the four characters will decode to only two bytes, while '==' indicates that the four characters will decode to only a single byte.
        ; so, if ebp == 4, we got all four base64 chars, and we write 3
        ;     if ebp == 3, we got three base64 chars, and one padding byte, so we write two bytes
        ;     if ebp == 2, we got two base64 chars, and two padding bytes, so we write one byte
        ;     if ebp == 1, (invalid), we got 1 base64 char, and none or three padding bytes, so we write one byte
        ;     if ebp == 0, there were no extra bytes to write in the first place
        test    ebp, ebp
        jz      .noextra

	mov	eax, 1
	sub	ebp, 1
	cmp	ebp, 1
	cmovb	ebp, eax

	add	r13, rbp
calign
.noextra:
	mov	rax, r13
	pop	rsi
	sub	rax, rsi
	pop	r15 r14 r13 r12 rbx rbp
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
	mov	rax, r13
	pop	rsi
	sub	rax, rsi
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.isspace:
	sub	rbx, 1
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


if used string$file_write | defined include_everything
	; two arguments: rdi == string, rsi == string filename to write this string as
	; NOTE: does UTF8 conversion first, and cheats by creating a buffer to do it for us
	; returns how many bytes we wrote in rax
falign
string$file_write:
	prolog	string$file_write
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	call	buffer$new
	mov	rsi, rbx
	mov	rbx, rax
	mov	rdi, rax
	call	buffer$append_string
	mov	rdi, rbx
	mov	rsi, r12
	call	buffer$file_write
	mov	r12, rax
	mov	rdi, rbx
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog

end if

if used string$file_write_cstr | defined include_everything
	; two arguments: rdi == string, rsi == null terminated latin1 of filename
	; NOTE: does UTF8 conversion first, and cheats by creating a buffer to do it for us
	; returns how many bytes we wrote in rax
falign
string$file_write_cstr:
	prolog	string$file_write_cstr
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	call	buffer$new
	mov	rsi, rbx
	mov	rbx, rax
	mov	rdi, rax
	call	buffer$append_string
	mov	rdi, rbx
	mov	rsi, r12
	call	buffer$file_write_cstr
	mov	r12, rax
	mov	rdi, rbx
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog

end if

if used string$file_append | defined include_everything
	; two arguments: rdi == string, rsi == string filename to append this string to
	; NOTE: does UTF8 conversion first, and cheats by creating a buffer to do it for us
	; returns how many bytes we wrote in rax
falign
string$file_append:
	prolog	string$file_append
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	call	buffer$new
	mov	rsi, rbx
	mov	rbx, rax
	mov	rdi, rax
	call	buffer$append_string
	mov	rdi, rbx
	mov	rsi, r12
	call	buffer$file_append
	mov	r12, rax
	mov	rdi, rbx
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog

end if

if used string$file_append_cstr | defined include_everything
	; two arguments: rdi == string, rsi == null terminated latin1 of filename
	; NOTE: does UTF8 conversion first, and cheats by creating a buffer to do it for us
	; returns how many bytes we wrote in rax
falign
string$file_append_cstr:
	prolog	string$file_append_cstr
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	call	buffer$new
	mov	rsi, rbx
	mov	rbx, rax
	mov	rdi, rax
	call	buffer$append_string
	mov	rdi, rbx
	mov	rsi, r12
	call	buffer$file_append_cstr
	mov	r12, rax
	mov	rdi, rbx
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog

end if

if used string$replace | defined include_everything
	; three arguments: rdi == input, rsi == search, rdx == replacement
	; returns a new string in rax
falign
string$replace:
	prolog	string$replace
	push	rbx r12 r13 r14 r15
	mov	r12, rdi		; input string
	mov	r13, rsi		; search string
	mov	r14, rdx		; replacement string
	call	buffer$new
	push	rax			; working buffer
	xor	ebx, ebx
	mov	rdi, r12
	mov	rsi, r13
	call	string$indexof
	mov	r15, rax
calign
.loop:
	cmp	r15, -1
	je	.done
	mov	rdi, r12
	mov	rsi, rbx
	mov	rdx, r15
	call	string$substring
	mov	rdi, [rsp]
	mov	rsi, rax
	push	rax
	call	buffer$append_rawstring
	pop	rdi
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, r14
	call	buffer$append_rawstring
	mov	rbx, r15
	add	rbx, [r13]
	mov	rdi, r12
	mov	rsi, r13
	mov	rdx, rbx
	call	string$indexof_ofs
	mov	r15, rax
	jmp	.loop
calign
.done:
	mov	rdi, r12
	mov	rsi, rbx
	mov	rdx, -1
	call	string$substr
	mov	r13, rax
	mov	rdi, [rsp]
	mov	rsi, rax
	call	buffer$append_rawstring
	mov	rdi, r13
	call	heap$free
	pop	rbx
	mov	rdi, [rbx+buffer_length_ofs]
	add	rdi, 8
	call	heap$alloc
	mov	r12, rax
	mov	rdi, [rbx+buffer_length_ofs]
	shr	rdi, 1
	mov	[rax], rdi
	lea	rdi, [rax+8]
	mov	rsi, [rbx+buffer_itself_ofs]
	mov	rdx, [rbx+buffer_length_ofs]
	call	memcpy
	mov	rdi, rbx
	call	buffer$destroy
	mov	rax, r12
	pop	r15 r14 r13 r12 rbx
	epilog

end if
