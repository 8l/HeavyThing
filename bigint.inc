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
	; bigint.inc: crypto-required big integer handling
	;

bigint_size_ofs = 0		; dd, count in 64 bit words of our "size", see notes below re: actual size
bigint_words_ofs = 8		; pointer into the same bigint object that is aligned 16 offset of our first word
bigint_negative_ofs = 16	; bool, 1 == this is negative, 0 == this is positive (must be 1 or 0)
bigint_monty_powmod_ofs = 24	; dq, -> heap_alloc'd monty_powmod (because reconstructing these is expensive for repeated testing/usage)
bigint_header_size = 32

bigint_size = 64 + (bigint_maxwords shl 3) + 16

	; various settings apply
	
	; for primality checking with isprime2, this setting defines whether or not to check the GCD on it or not.
	; if you are only creating primes with primesieve or primesievemod, leaving this setting off is fine.
	; if you are randomly selecting numbers (and they are LARGE such that modular arithmetic is expensive)
	; then turning this on might be a good thing for you, and you should call modsmallprimes before you call
	; isprime2 (trial division)
; isprime_checkgcd = 1

	; static "cheater" helpers:

if used bigint$zero | defined include_everything

dalign
bigint$zero:
	dq	2, .data, 0, 0
align 16
.data:	dq	0, 0

end if

if used bigint$one | defined include_everything

dalign
bigint$one:
	dq	2, .data, 0, 0
align 16
.data:	dq	1, 0

end if


if used bigint$two | defined include_everything

dalign
bigint$two:
	dq	2, .data, 0, 0
align 16
.data:	dq	2, 0

end if

if used bigint$three | defined include_everything

dalign
bigint$three:
	dq	2, .data, 0, 0
align 16
.data:	dq	3, 0

end if


if used bigint$new | defined include_everything
	; returns a new heap$alloc'd bigint, set to 0
falign
bigint$new:
	prolog	bigint$new
	mov	edi, bigint_size
	call	heap$alloc
	xor	ecx, ecx
	mov	rdx, rax
	mov	qword [rax+bigint_size_ofs], 2
	add	rdx, bigint_header_size + 0xf
	mov	[rax+bigint_negative_ofs], rcx
	and	rdx, not 0xf
	mov	[rax+bigint_words_ofs], rdx
	xorpd	xmm0, xmm0
	mov	[rax+bigint_monty_powmod_ofs], rcx
	movapd	[rdx], xmm0
	epilog
end if

if used bigint$destroy | defined include_everything
	; single argument in rdi: a bigint object
	; "properly" cleans up/heap$free's the bigint and its words buffer
falign
bigint$destroy:
	prolog	bigint$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+bigint_monty_powmod_ofs]
	test	rdi, rdi
	jz	.nomonty
	call	monty$destroy
calign
.nomonty:
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
end if

if used bigint$destroy_clear | defined include_everything
	; single argument in rdi: a bigint object
	; same as normal destroy, but zeros the memory associated with it
falign
bigint$destroy_clear:
	prolog	bigint$destroy_clear
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+bigint_monty_powmod_ofs]
	test	rdi, rdi
	jz	.nomonty
	call	monty$destroy_clear
calign
.nomonty:
	mov	rdi, rbx
	call	heap$free_clear
	pop	rbx
	epilog

end if



if used bigint$new_copy | defined include_everything
	; single argument in rdi: bigint to make a copy of
	; returns copy of it in rax
falign
bigint$new_copy:
	prolog	bigint$new_copy
	push	rdi
	call	bigint$new
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	bigint$assign
	pop	rax
	epilog

end if

if used bigint$new_unsigned | defined include_everything
	; single argument in rdi: 64bit unsigned value to make one from
	; returns heap$alloc'd bigint in rax
falign
bigint$new_unsigned:
	prolog	bigint$new_unsigned
	push	rdi
	mov	edi, bigint_size
	call	heap$alloc
	xor	ecx, ecx
	pop	rdi
	mov	rdx, rax
	mov	qword [rax+bigint_size_ofs], 2
	add	rdx, bigint_header_size + 0xf
	mov	[rax+bigint_negative_ofs], rcx
	and	rdx, not 0xf
	mov	[rax+bigint_words_ofs], rdx
	mov	[rax+bigint_monty_powmod_ofs], rcx
	mov	[rdx], rdi
	mov	[rdx+8], rcx
	epilog
end if

if used bigint$new_size | defined include_everything
	; single argument: edi == # words to set size to, clears/zeroes of course
falign
bigint$new_size:
	prolog	bigint$new_size
	push	rdi
	mov	edi, bigint_size
	call	heap$alloc
	mov	rdx, rax
	xor	ecx, ecx
	add	rdx, bigint_header_size + 0xf
	mov	[rax+bigint_negative_ofs], rcx
	and	rdx, not 0xf
	mov	[rax+bigint_words_ofs], rdx
	mov	[rax+bigint_monty_powmod_ofs], rcx
	mov	rdi, rax

	; 2, 4, 8, 16, 32, 64, 128, 256 are fixed sizes
	pop	r11
	mov	esi, 2
calign
.sizeloop:
	cmp	r11d, esi
	jbe	.sizedone
	shl	esi, 1
	jmp	.sizeloop
calign
.sizedone:
	push	rdi
	mov	[rdi+bigint_size_ofs], esi
	xorpd	xmm0, xmm0
	mov	rdi, [rdi+bigint_words_ofs]
	shr	esi, 1
calign
.loop:
	movapd	[rdi], xmm0
	add	rdi, 16
	sub	esi, 1
	jnz	.loop
	pop	rax
	epilog
calign
.done:
	pop	rax
	epilog

end if

if used bigint$tlz | defined include_everything
	; single argument: rdi == bigint to resize (if we can)
falign
bigint$tlz:
	prolog	bigint$tlz
	call	bigint$wordcount
	mov	esi, 2
calign
.sizeloop:
	cmp	eax, esi
	jbe	.sizedone
	shl	esi, 1
	jmp	.sizeloop
calign
.sizedone:
	mov	dword [rdi+bigint_size_ofs], esi
	epilog

end if


if used bigint$resize | defined include_everything
	; two arguments: rdi == bigint object, esi == new wordcount
	; if shrinking, just sets size and is done, else, clears as we go up
falign
bigint$resize:
	prolog	bigint$resize
	; 2, 4, 8, 16, 32, 64, 128, 256 are fixed increments for sizes
	mov	r11d, esi
	mov	esi, 2
calign
.sizeloop:
	cmp	r11d, esi
	jbe	.sizedone
	shl	esi, 1
	jmp	.sizeloop
calign
.sizedone:
	mov	eax, [rdi+bigint_size_ofs]
	mov	[rdi+bigint_size_ofs], esi
	mov	ecx, eax
	cmp	esi, eax
	jbe	.done
	xorpd	xmm0, xmm0
	shl	ecx, 3
	sub	esi, eax
	mov	rdi, [rdi+bigint_words_ofs]
	shr	esi, 1
	add	rdi, rcx
calign
.loop:
	movapd	[rdi], xmm0
	add	rdi, 16
	sub	esi, 1
	jnz	.loop
	epilog
calign
.done:
	epilog

end if

if used bigint$newsize | defined include_everything
	; two arguments: rdi == bigint object, esi == new size
	; sets a new size same as resize, but doesn't touch the words array
falign
bigint$newsize:
	prolog	bigint$newsize
	mov	r11d, esi
	mov	esi, 2
calign
.sizeloop:
	cmp	r11d, esi
	jbe	.sizedone
	shl	esi, 1
	jmp	.sizeloop
calign
.sizedone:
	mov	eax, [rdi+bigint_size_ofs]
	mov	[rdi+bigint_size_ofs], esi
	mov	ecx, eax
	epilog

end if

if used bigint$newsize_clear | defined include_everything
	; two arguments: rdi == bigint object, esi == new size
	; same as resize, but clears the entirety to zeros, doesn't modify sign flag
falign
bigint$newsize_clear:
	prolog	bigint$newsize_clear
	mov	r11d, esi
	mov	esi, 2
calign
.sizeloop:
	cmp	r11d, esi
	jbe	.sizedone
	shl	esi, 1
	jmp	.sizeloop
calign
.sizedone:
	cmp	esi, bigint_maxwords
	jae	.kakked
	mov	[rdi+bigint_size_ofs], esi
	xorpd	xmm0, xmm0
	mov	rdi, [rdi+bigint_words_ofs]
	shr	esi, 1
calign
.loop:
	movapd	[rdi], xmm0
	add	rdi, 16
	sub	esi, 1
	jnz	.loop
	epilog
calign
.done:
	epilog
calign
.kakked:
	breakpoint

end if



if used bigint$grow | defined include_everything
	; two arguments: rdi == bigint object, esi == new wordcount
	; only modifies rdi if new wordcount is > previous
falign
bigint$grow:
	prolog	bigint$grow
	cmp	esi, [rdi+bigint_size_ofs]
	jbe	.done
	call	bigint$resize
	epilog
calign
.done:
	epilog

end if


if used bigint$new_pow2 | defined include_everything
	; single argument: edi == 2**edi
	; returns a new bigint with the appropriate bit set
falign
bigint$new_pow2:
	prolog	bigint$new_pow2
	push	rdi
	add	edi, 63
	shr	edi, 6
	call	bigint$new_size
	mov	esi, [rsp]
	mov	[rsp], rax
	mov	rdi, rax
	call	bigint$bitset
	pop	rax
	epilog

end if

if used bigint$set_pow2 | defined include_everything
	; two arguments: rdi == bigint object, esi == 2**esi
falign
bigint$set_pow2:
	prolog	bigint$set_pow2
	mov	dword [rdi+bigint_negative_ofs], 0
	push	rdi rsi
	add	esi, 63
	shr	esi, 6
	call	bigint$newsize_clear
	pop	rsi rdi
	call	bigint$bitset
	epilog

end if

if used bigint$set_unsigned | defined include_everything
	; two arguments: rdi == bigint object, rsi == what to set first word as
falign
bigint$set_unsigned:
	prolog	bigint$set_unsigned
	mov	dword [rdi+bigint_negative_ofs], 0
	push	rdi rsi
	mov	esi, 1
	call	bigint$newsize_clear
	pop	rsi rdi
	mov	rdx, [rdi+bigint_words_ofs]
	mov	[rdx], rsi
	epilog

end if

if used bigint$set_randomrange | defined include_everything
	; three arguments: rdi == bigint object, rsi == bigint min, rdx == bigint max
falign
bigint$set_randomrange:
	prolog	bigint$set_randomrange
	mov	dword [rdi+bigint_negative_ofs], 0
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdi, rdx
	call	bigint$new_copy
	mov	r13, rax
	mov	rdi, rax
	mov	rsi, r12
	call	bigint$subtract
	mov	rdi, r13
	call	bigint$bitcount
	mov	r14d, eax
calign
.loop:
	mov	rdi, rbx
	mov	esi, r14d
	call	bigint$set_random
	mov	rdi, rbx
	mov	rsi, r13
	call	bigint$compare
	cmp	eax, 1
	je	.loop
	mov	rdi, rbx
	mov	rsi, r12
	call	bigint$add
	mov	rdi, r13
	call	bigint$destroy
	pop	r14 r13 r12 rbx
	epilog

end if

if used bigint$set_random | defined include_everything
	; two arguments: rdi == bigint object, esi == # of random bits to set
	; TODO: this clears the words buffer up to the size before it sets the random bits
	; and so is doing a double-write unnecessarily for the # of bits when all it really
	; has to do is clear what remains after the # of bits up to the size... lazy me
falign
bigint$set_random:
	prolog	bigint$set_random
	mov	dword [rdi+bigint_negative_ofs], 0
	push	rdi rsi
	add	esi, 63
	shr	esi, 6
	call	bigint$newsize_clear
	mov	rsi, [rsp]
	mov	rdi, [rsp+8]
	mov	[rsp], rbx
	mov	[rsp+8], rbp
	mov	rbx, [rdi+bigint_words_ofs]
	mov	ebp, esi
calign
.do64:
	cmp	ebp, 64
	jb	.partial
	call	rng$u64
	mov	[rbx], rax
	add	rbx, 8
	sub	ebp, 64
	jmp	.do64
calign
.partial:
	test	ebp, ebp
	jz	.nomas
	call	rng$u64
	mov	ecx, ebp
	mov	edx, 1
	shl	rdx, cl
	sub	rdx, 1
	and	rax, rdx
	mov	[rbx], rax
calign
.nomas:
	mov	rbx, [rsp]
	mov	rbp, [rsp+8]
	add	rsp, 16
	epilog

end if

if used bigint$new_random | defined include_everything
	; single argument in edi: number of random bits to create
falign
bigint$new_random:
	prolog	bigint$new_random
	push	rdi
	call	bigint$new
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	bigint$set_random
	pop	rax
	epilog

end if

if used bigint$new_encoded | defined include_everything
	; two arguments: rdi == big endian "encoded" byte order buffer, rsi == length of same
	; returns a heap$alloc'd bigint with the decoded goods in it
falign
bigint$new_encoded:
	prolog	bigint$new_encoded
	push	rsi rdi
	add	rsi, 7
	and	rsi, not 7
	mov	rdi, rsi
	shr	rdi, 3
	call	bigint$new_size
	pop	rsi rdx
	push	rax
	mov	rdi, rax
	call	bigint$set_encoded	; this will re-call room, but we don't really mind
	mov	rdi, [rsp]
	call	bigint$tlz
	pop	rax
	epilog

end if

if used bigint$set_encoded | defined include_everything
	; three arguments: rdi == destination bigint, rsi == big endian "encoded" byte order buffer, rdx == length of same
falign
bigint$set_encoded:
	prolog	bigint$set_encoded
	mov	dword [rdi+bigint_negative_ofs], 0
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	rsi, rdx
	add	rsi, 7
	and	rsi, not 7
	shr	rsi, 3
	call	bigint$newsize_clear
	; we have enough room
	mov	rcx, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	add	rsi, rdx			; rsi now past the end by one
	test	rdx, rdx
	jz	.nothingtodo
	mov	rdi, [rcx+bigint_words_ofs]
calign
.do8:
	cmp	rdx, 8
	jb	.do4
	sub	rsi, 8
	mov	rax, [rsi]
if use_movbe
	movbe	[rdi], rax
else
	bswap	rax
	mov	[rdi], rax
end if
	add	rdi, 8
	sub	rdx, 8
	jz	.nothingtodo
	jmp	.do8
calign
.do4:
	cmp	rdx, 4
	jb	.do2
	sub	rsi, 4
	mov	eax, [rsi]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	sub	rdx, 4
	jz	.nothingtodo
calign
.do2:
	cmp	rdx, 2
	jb	.do1
	sub	rsi, 2
	movzx	eax, word [rsi]
	xchg	ah, al
	mov	[rdi], ax
	add	rdi, 2
	sub	rdx, 2
	jz	.nothingtodo
calign
.do1:
	cmp	rdx, 1
	jb	.nothingtodo
	sub	rsi, 1
	movzx	eax, byte [rsi]
	mov	[rdi], al
	add	rsp, 24
	epilog
calign
.nothingtodo:
	add	rsp, 24
	epilog

end if


if used bigint$encode | defined include_everything
	; two arguments: rdi == source bigint, rsi == buffer (it is assumed you already worked out how much space we'll require by calling bytecount)
	; returns # of bytes we wrote in rax... this big-endian encodes it, opposite of set_encoded
falign
bigint$encode:
	prolog	bigint$encode
	mov	rcx, rsi
	mov	r9, rsi
	mov	rsi, [rdi+bigint_words_ofs]
	mov	eax, [rdi+bigint_size_ofs]
	mov	edx, eax
	shl	edx, 3
	add	rsi, rdx
	sub	rsi, 8
calign
.doit:
	cmp	qword [rsi], 0
	jne	.wordcheck
	sub	eax, 1
	jz	.outtahere
	sub	rsi, 8
	jmp	.doit
calign
.outtahere:
	epilog
calign
.wordcheck:
	; find the topmost byte used and start there
	mov	rdx, [rsi]
	mov	r8d, 8
	sub	rsi, 8
	bswap	rdx
calign
.bytecheck:
	test	dl, 0xff
	jnz	.dopartial
	shr	rdx, 8
	sub	r8d, 1
	jmp	.bytecheck
dalign
.partialjumptable:
	dq	.outtahere, .part1, .part2, .part3, .part4, .part5, .part6, .part7, .part8
calign
.dopartial:
	jmp	qword [r8*8+.partialjumptable]
calign
.part1:
	; one byte is sitting in dl that needs written to rcx
	mov	byte [rcx], dl
	add	rcx, 1
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part2:
	; one word is sitting in dx that needs written to rcx
	mov	word [rcx], dx
	add	rcx, 2
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part3:
	mov	dword [rcx], edx
	add	rcx, 3
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part4:
	mov	dword [rcx], edx
	add	rcx, 4
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part5:
	mov	[rcx], rdx
	add	rcx, 5
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part6:
	mov	[rcx], rdx
	add	rcx, 6
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part7:
	mov	[rcx], rdx
	add	rcx, 7
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part8:
	mov	[rcx], rdx
	add	rcx, 8
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.wholewords:
	mov	rdx, [rsi]
	sub	rsi, 8
if use_movbe
	movbe	[rcx], rdx
else
	bswap	rdx
	mov	[rcx], rdx
end if
	add	rcx, 8
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog

end if


if used bigint$ssh_encode | defined include_everything
	; two arguments: rdi == source bigint, rsi == buffer (it is assumed you already worked out how much space we'll require by calling bytecount and adding 1)
	; returns the # of bytes we wrote to rsi in rax
	; this big-endian encodes it, opposite of set_encoded, and is nearly identical to the bigint$encode above, only
	; per the SSH spec, if the topmost bit is 1, we add a leading zero to the encoding
falign
bigint$ssh_encode:
	prolog	bigint$ssh_encode
	mov	rcx, rsi
	mov	r9, rsi
	mov	rsi, [rdi+bigint_words_ofs]
	mov	eax, [rdi+bigint_size_ofs]
	mov	edx, eax
	shl	edx, 3
	add	rsi, rdx
	sub	rsi, 8
calign
.doit:
	cmp	qword [rsi], 0
	jne	.wordcheck
	sub	eax, 1
	jz	.outtahere
	sub	rsi, 8
	jmp	.doit
calign
.outtahere:
	epilog
calign
.wordcheck:
	; find the topmost byte used and start there
	mov	rdx, [rsi]
	mov	r8d, 8
	sub	rsi, 8
	bswap	rdx
calign
.bytecheck:
	test	dl, 0xff
	jnz	.dopartial
	shr	rdx, 8
	sub	r8d, 1
	jmp	.bytecheck
dalign
.partialjumptable:
	dq	.outtahere, .part1, .part2, .part3, .part4, .part5, .part6, .part7, .part8
calign
.dopartial:
	; this is the different bit of code to the normal bigint$encode
	; because we already bswapped it, we only have to test dl for the topmost bit being set
	; and do our leading zero here
	test	dl, 0x80
	jz	.dopartial_noleading
	mov	byte [rcx], 0
	add	rcx, 1
	jmp	qword [r8*8+.partialjumptable]
calign
.dopartial_noleading:
	jmp	qword [r8*8+.partialjumptable]
calign
.part1:
	; one byte is sitting in dl that needs written to rcx
	mov	byte [rcx], dl
	add	rcx, 1
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part2:
	; one word is sitting in dx that needs written to rcx
	mov	word [rcx], dx
	add	rcx, 2
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part3:
	mov	dword [rcx], edx
	add	rcx, 3
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part4:
	mov	dword [rcx], edx
	add	rcx, 4
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part5:
	mov	[rcx], rdx
	add	rcx, 5
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part6:
	mov	[rcx], rdx
	add	rcx, 6
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part7:
	mov	[rcx], rdx
	add	rcx, 7
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.part8:
	mov	[rcx], rdx
	add	rcx, 8
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog
calign
.wholewords:
	mov	rdx, [rsi]
	sub	rsi, 8
if use_movbe
	movbe	[rcx], rdx
else
	bswap	rdx
	mov	[rcx], rdx
end if
	add	rcx, 8
	sub	eax, 1
	jnz	.wholewords
	mov	rax, rcx
	sub	rax, r9			; # of bytes we wrote
	epilog

end if

if used bigint$bitset | defined include_everything
	; two arguments: rdi == bigint object, esi == bit to set
falign
bigint$bitset:
	prolog	bigint$bitset
	mov	edx, esi
	mov	ecx, esi
	add	edx, 64
	and	ecx, 0x3f
	shr	edx, 6
	mov	r9d, 1
	mov	rax, [rdi+bigint_words_ofs]
	cmp	edx, [rdi+bigint_size_ofs]
	ja	.growit
	; otherwise, our size is big enough
	shl	r9, cl
	shr	esi, 6
	or	[rax+rsi*8], r9
	epilog
calign
.growit:
	push	rdi rsi
	mov	esi, edx
	call	bigint$resize
	pop	rsi rdi
	mov	ecx, esi
	mov	r9d, 1
	and	ecx, 0x3f
	mov	rax, [rdi+bigint_words_ofs]
	; otherwise, our size is big enough
	shl	r9, cl
	shr	esi, 6
	or	[rax+rsi*8], r9
	epilog
	
end if

if used bigint$bitget | defined include_everything
	; two arguments: rdi == bigint object, esi == bit to get
	; returns eax == 0 or 1
falign
bigint$bitget:
	prolog	bigint$bitget
	mov	edx, esi
	mov	ecx, esi
	add	edx, 64
	and	ecx, 0x3f
	shr	edx, 6
	mov	r9d, 1
	mov	r8, [rdi+bigint_words_ofs]
	cmp	edx, [rdi+bigint_size_ofs]
	ja	.zeroret
	; otherwise, our size is big enough
	xor	eax, eax
	shl	r9, cl
	mov	ecx, 1
	shr	esi, 6
	test	[r8+rsi*8], r9
	cmovnz	eax, ecx
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used bigint$bitrange | defined include_everything
	; three arguemnts: rdi == bigint, esi == bit offset, edx == bit count to return
	; TODO: make this an at-most two word op instead of calling bitget like a lazy boy
falign
bigint$bitrange:
	prolog	bigint$bitrange
	; NOTE: we are lazily calling bitget, but since it is right above this func, we know which
	; registers it smashes, so we use regs it doesn't for our state
	test	edx, edx
	jz	.zeroret
	push	rbx r12
	mov	r10d, esi
	mov	r11d, edx
	xor	r12d, r12d
	xor	ebx, ebx
calign
.loop:
	mov	esi, r10d
	call	bigint$bitget
	mov	ecx, r12d
	shl	rsi, cl
	or	rbx, rsi
	add	r10d, 1
	add	r12d, 1
	sub	r11d, 1
	jnz	.loop
	
	mov	rax, rbx
	pop	r12 rbx
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used bigint$bitclear | defined include_everything
	; two arguments: rdi == bigint object, esi == bit to clear
falign
bigint$bitclear:
	prolog	bigint$bitclear
	mov	edx, esi
	mov	ecx, esi
	add	edx, 63
	and	ecx, 0x3f
	shr	edx, 6
	mov	r9d, 1
	mov	rax, [rdi+bigint_words_ofs]
	cmp	edx, [rdi+bigint_size_ofs]
	ja	.growit
	; otherwise, our size is big enough
	shl	r9, cl
	shr	esi, 6
	not	r9
	and	[rax+rsi*8], r9
	epilog
calign
.growit:
	mov	esi, edx
	call	bigint$resize
	epilog

end if


if used bigint$assign | defined include_everything
	; two arguments: destination bigint in rdi, source in rsi
falign
bigint$assign:
	prolog	bigint$assign
	mov	eax, [rsi+bigint_size_ofs]
	mov	ecx, [rsi+bigint_negative_ofs]
	mov	[rdi+bigint_size_ofs], eax
	mov	[rdi+bigint_negative_ofs], ecx
	shr	eax, 1
	mov	rdi, [rdi+bigint_words_ofs]
	mov	rsi, [rsi+bigint_words_ofs]
	xor	edx, edx
calign
.loop:
	movapd	xmm0, [rsi+rdx]
	movapd	[rdi+rdx], xmm0
	add	edx, 16
	sub	eax, 1
	jnz	.loop
	epilog

end if

if used bigint$clear | defined include_everything
	; single argument in rdi: bigint to zeroize
falign
bigint$clear:
	prolog	bigint$clear
	xor	eax, eax
	xorpd	xmm0, xmm0
	mov	rsi, [rdi+bigint_words_ofs]
	mov	[rdi+bigint_negative_ofs], eax
	mov	dword [rdi+bigint_size_ofs], 2
	movapd	[rsi], xmm0
	epilog

end if


if used bigint$byteget | defined include_everything
	; two arguments: rdi == bigint, esi == byte # to return in eax
falign
bigint$byteget:
	prolog	bigint$byteget
	mov	edx, esi
	mov	ecx, esi
	add	edx, 1
	and	ecx, 0x7
	shr	edx, 3
	mov	r8, [rdi+bigint_words_ofs]
	cmp	edx, [rdi+bigint_size_ofs]
	ja	.zeroret
	; otherwise, our size is big enough
	shl	ecx, 3
	shr	esi, 3
	mov	rax, [r8+rsi*8]
	shr	rax, cl
	and	eax, 0xff
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used bigint$wordcount | defined include_everything
	; single argument in rdi: bigint
	; returns # of words used/significant
	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$wordcount:
	prolog	bigint$wordcount
	mov	rsi, [rdi+bigint_words_ofs]
	mov	eax, [rdi+bigint_size_ofs]
	mov	edx, eax
	shl	edx, 3
	add	rsi, rdx
	sub	rsi, 8
calign
.doit:
	cmp	qword [rsi], 0
	jne	.outtahere
	sub	eax, 1
	jz	.outtahere
	sub	rsi, 8
	jmp	.doit
calign
.outtahere:
	epilog

end if
	
if used bigint$debug | defined include_everything
	; single argument in rdi: bigint to spew to screen in little endian form
falign
bigint$debug:
	prolog	bigint$debug
	push	rdi
	call	bigint$wordcount
	test	eax, eax
	jz	.zero
	mov	rcx, [rsp]
	mov	rdi, [rcx+bigint_words_ofs]
	mov	rsi, rax
	shl	rsi, 3
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdi
	epilog
calign
.zero:
	mov	rdi, .zerostr
	call	string$to_stdoutln
	pop	rdi
	epilog
cleartext .zerostr, '(0)'
end if


if used bigint$bytecount | defined include_everything
	; single argument in rdi: bigint
	; returns # of bytes used/significant
	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$bytecount:
	prolog	bigint$bytecount
	mov	rsi, [rdi+bigint_words_ofs]
	mov	eax, [rdi+bigint_size_ofs]
	mov	edx, eax
	shl	edx, 3
	add	rsi, rdx
	sub	rsi, 8
calign
.doit:
	cmp	qword [rsi], 0
	jne	.wordcheck
	sub	eax, 1
	jz	.outtahere
	sub	rsi, 8
	jmp	.doit
calign
.outtahere:
	epilog
calign
.wordcheck:
	mov	rdx, [rsi]
	shl	eax, 3
	bswap	rdx
	mov	ecx, 8
calign
.bytecheck:
	test	dl, 0xff
	jnz	.outtahere
	shr	rdx, 8
	sub	eax, 1
	jmp	.bytecheck

end if

if used bigint$bitcount | defined include_everything
	; single argument in rdi: bigint
	; returns # of bits used/significant
	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$bitcount:
	prolog	bigint$bitcount
	mov     rsi, [rdi+bigint_words_ofs]
	mov     ecx, [rdi+bigint_size_ofs]
	mov     eax, ecx
	mov     edx, ecx
	shl     eax, 6
	shl     edx, 3
	add     rsi, rdx
	sub     rsi, 8
calign
.doit:
	cmp     qword [rsi], 0
	jne     .checkword
	sub     eax, 64
	sub     ecx, 1
	jz      .outtahere
	sub     rsi, 8
	jmp     .doit
calign
.outtahere:
	epilog
calign
.checkword:
	bsr     rdx, qword [rsi]
	mov     ecx, 63
	sub     ecx, edx
	sub     eax, ecx
	epilog

end if

if used bigint$lg2 | defined include_everything
	; single argument in rdi: bigint
	; returns integer lg2
falign
bigint$lg2:
	prolog	bigint$lg2
	push	rdi
	call	bigint$wordcount
	pop	rdi
	mov	rsi, [rdi+bigint_words_ofs]
	sub	rax, 1
	mov	rdx, rax
	shl	rax, 6
	shl	rdx, 3
	add	rsi, rdx
	mov	rcx, [rsi]
	bsr	rdx, rcx
	add	rax, rdx
	epilog

end if


if used bigint$is_zero | defined include_everything
	; single argument in rdi: bigint
	; returns bool in eax as to whether or not it is zero
	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$is_zero:
	prolog	bigint$is_zero
	mov	rsi, [rdi+bigint_words_ofs]
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.zeroret
	cmp	qword [rsi], 0
	jne	.zeroret
	call	bigint$wordcount
	test	eax, eax
	jnz	.zeroret
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used bigint$negate | defined include_everything
	; single argument in rdi: bigint
	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$negate:
	prolog	bigint$negate
	; NOTE: we know is_zero and wordcount both do not smash rdi, so we don't bother pushing it/restoring it
	call	bigint$is_zero
	test	eax, eax
	jnz	.nothingtodo
	mov	eax, 1
	sub	eax, dword [rdi+bigint_negative_ofs]
	mov	[rdi+bigint_negative_ofs], eax
	epilog
calign
.nothingtodo:
	epilog

end if


if used bigint$is_one | defined include_everything
	; single argument in rdi: bigint
	; returns bool in eax as to whether or not it is one
	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$is_one:
	prolog	bigint$is_one
	mov	rsi, [rdi+bigint_words_ofs]
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.zeroret
	cmp	qword [rsi], 1
	jne	.zeroret
	call	bigint$wordcount
	cmp	eax, 1
	jne	.zeroret
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if


if used bigint$compare_unsigned | defined include_everything
	; two arguments: rdi/rsi bigints to compare
	; returns -1, 0, 1 in eax

	; NOTE: other routines in here depend on register smash/no smash (along with several others)
falign
bigint$compare_unsigned:
	prolog	bigint$compare_unsigned
	; first up, figure out the wordcount for rdi
	mov	r8, [rdi+bigint_words_ofs]
	mov	r9d, [rdi+bigint_size_ofs]
	mov	r10, [rsi+bigint_words_ofs]
	mov	r11d, [rsi+bigint_size_ofs]
	mov	edx, r9d
	shl	edx, 3
	add	r8, rdx
	sub	r8, 8
	mov	edx, r11d
	shl	edx, 3
	add	r10, rdx
	sub	r10, 8
calign
.wc1:
	cmp	qword [r8], 0
	jne	.wc2
	sub	r9d, 1
	jz	.wc2
	sub	r8, 8
	jmp	.wc1
calign
.wc2:
	cmp	qword [r10], 0
	jne	.wcdone
	sub	r11d, 1
	jz	.wcdone
	sub	r10, 8
	jmp	.wc2
calign
.wcdone:
	; so r9d is rdi's size, r11d is rsi's size
	cmp	r9d, r11d
	jne	.sizesdiff
	; conveniently, the word at r8 and the word at r10 are both pointing to the last word in each
	test	r9d, r9d
	jz	.zeroret	; no words == bailout with no comparisons, they are equally nada
calign
.compareloop:
	mov	rax, [r8]
	cmp	rax, [r10]
	jne	.wordsdiff
	sub	r8, 8
	sub	r10, 8
	sub	r9d, 1
	jnz	.compareloop
	xor	eax, eax
	epilog
calign
.wordsdiff:
	mov	eax, -1
	mov	ecx, 1
	cmova	eax, ecx
	epilog
calign
.sizesdiff:
	mov	eax, -1
	mov	ecx, 1
	cmova	eax, ecx
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog


end if

if used bigint$compare | defined include_everything
	; two arguments: rdi/rsi bigints to compare
	; returns -1, 0, 1 in eax
falign
bigint$compare:
	prolog	bigint$compare
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.rdineg
	cmp	dword [rsi+bigint_negative_ofs], 0
	jne	.oneret
	call	bigint$compare_unsigned
	epilog
calign
.rdineg:
	cmp	dword [rsi+bigint_negative_ofs], 0
	je	.negoneret
	call	bigint$compare_unsigned
	neg	eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
calign
.negoneret:
	mov	eax, -1
	epilog

end if

if used bigint$shl | defined include_everything
	; two arguments: rdi == bigint object, esi == # of bits to shift
falign
bigint$shl:
	prolog	bigint$shl
	test	esi, esi
	jz	.nothingtodo
calign
.restart:
	mov	r9d, esi
	mov	r10d, esi
	mov	r11d, esi
	mov	rsi, [rdi+bigint_words_ofs]
	mov	eax, [rdi+bigint_size_ofs]
	mov	r8, rsi
	mov	edx, eax
	shl	edx, 3
	add	rsi, rdx
	sub	rsi, 8
calign
.doit:
	cmp	qword [rsi], 0
	jne	.wcdone
	sub	eax, 1
	jz	.nothingtodo
	sub	rsi, 8
	jmp	.doit
calign
.wcdone:
	; so our wordcount is in eax, shift amount in r11d, r8 is pointing to the start of the words, rsi is pointing to the most significant word
	; we need to determine whether or not our size will accommodate the shift, and if not, resize
	mov	edx, r11d
	shr	r9d, 6		; number of whole words to shift
	add	edx, 63
	and	r10d, 63	; number of partial bits to shift
	shr	edx, 6
	add	edx, eax	; new number of words we will require
	cmp	edx, [rdi+bigint_size_ofs]
	ja	.needmore
	test	r9d, r9d
	jz	.nowholewords
	; so we need a pointer to r8 + ((eax + r9d) << 3) - 8, and a pointer to that minus (r9d << 3)
	; and our loop counter is eax
	; we don't really need the original value in r11d anymore, so save our wordcount there
	mov	r11d, eax
	mov	edi, eax
	add	edi, r9d
	shl	edi, 3
	sub	edi, 8
	add	rdi, r8
	shl	r9d, 3
	mov	rsi, rdi
	sub	rsi, r9
calign
.wordmove:
	mov	rdx, [rsi]
	mov	[rdi], rdx
	sub	rsi, 8
	sub	rdi, 8
	sub	eax, 1
	jnz	.wordmove
	shr	r9d, 3
	xor	edx, edx
calign
.zerowords:
	mov	[r8], rdx
	add	r8, 8
	sub	r9d, 1
	jnz	.zerowords
	; if no partial bits, outta here
	test	r10d, r10d
	jz	.nothingtodo
	; otherwise, reg + shiftWords is already sitting in r8, so now we need:
	mov	r9d, 64
	sub	r9d, r10d	; shift carry amount
	add	r11d, 1		; wordcount + 1
	xor	edx, edx	; carry
calign
.partialloop:
	mov	ecx, r10d
	mov	rax, [r8]
	mov	rsi, rax
	shl	rax, cl
	or	rax, rdx
	mov	[r8], rax
	mov	ecx, r9d
	mov	rdx, rsi
	add	r8, 8
	shr	rdx, cl
	sub	r11d, 1
	jnz	.partialloop
	epilog
calign
.nowholewords:
	; r10d _MUST_ be nonzero if we made it to here
	mov	r11d, eax
	mov	r9d, 64
	sub	r9d, r10d	; shift carry amount
	add	r11d, 1		; wordcount + 1
	xor	edx, edx	;carry
	jmp	.partialloop
calign
.needmore:
	; hopefully this doesn't happen too often... TODO: instead of restarting, maybe we need to save our state entirely?
	push	rdi r11
	mov	esi, edx
	call	bigint$resize
	pop	rsi rdi
	jmp	.restart
calign
.nothingtodo:
	epilog

end if

if used bigint$shr | defined include_everything
	; two arguments: rdi == bigint object, esi == # of bits to shift
falign
bigint$shr:
	prolog	bigint$shr
	test	esi, esi
	jz	.nothingtodo
	mov	r9d, esi
	mov	r10d, esi
	mov	r11d, esi
	mov	rsi, [rdi+bigint_words_ofs]
	mov	eax, [rdi+bigint_size_ofs]
	mov	r8, rsi
	mov	edx, eax
	shl	edx, 3
	add	rsi, rdx
	sub	rsi, 8
calign
.doit:
	cmp	qword [rsi], 0
	jne	.wcdone
	sub	eax, 1
	jz	.nothingtodo
	sub	rsi, 8
	jmp	.doit
calign
.wcdone:
	; so our wordcount is in eax, shift amount in r11d, r8 is pointing to the start of the words, rsi is pointing to the most significant word
	shr	r9d, 6		; number of whole words to shift
	and	r10d, 63	; number of partial bits to shift
	test	r9d, r9d
	jz	.nowholewords
	; we need a pointer to r8 + (r9d << 3), and our loop count is wordcount - shiftWords
	; we don't really need r11, so store a copy of r8 there so we can go back to the start
	mov	r11, r8
	mov	ecx, eax
	sub	ecx, r9d
	mov	esi, r9d
	shl	esi, 3
	add	rsi, r8
calign
.wordmove:
	mov	rdx, [rsi]
	mov	[r8], rdx
	add	rsi, 8
	add	r8, 8
	sub	ecx, 1
	jnz	.wordmove
	; zero the words leftover
	mov	ecx, r9d
	xor	edx, edx
calign
.zerowords:
	mov	[r8], rdx
	add	r8, 8
	sub	ecx, 1
	jnz	.zerowords

	; now, so long as our original wordcount is greater than our shift words
	; do the partial goods
	cmp	eax, r9d
	jbe	.checknegzero
	; wordCount is still in eax, shiftWords is in r9d, shiftBits is in r10d
	test	r10d, r10d
	jz	.checknegzero
	; copy of the start of our word buffer is in r11
	; we need a pointer to the word at wordCount-shiftWords, our loop count is wordCount - shiftWords
	mov	ecx, eax
	sub	ecx, r9d	; wordcount - shift words
	mov	r8d, ecx	; loop count
	mov	edx, ecx
	shl	edx, 3
	add	r11, rdx
	sub	r11, 8		; pointer to there -1

	mov	r9d, 64
	sub	r9d, r10d	; shift carry amount
	xor	edx, edx	; carry
calign
.partial:
	mov	ecx, r10d
	mov	rax, [r11]
	mov	rsi, rax
	shr	rax, cl
	or	rax, rdx
	mov	[r11], rax
	mov	ecx, r9d
	mov	rdx, rsi
	shl	rdx, cl
	sub	r11, 8
	sub	r8d, 1
	jnz	.partial
calign
.checknegzero:
	; if is_zero
	cmp	dword [rdi+bigint_negative_ofs], 0
	je	.nothingtodo
	call	bigint$is_zero		; this does not blast rdi
	test	eax, eax
	jz	.nothingtodo
	mov	dword [rdi+bigint_negative_ofs], 0
	epilog
calign
.nowholewords:
	; r10d MUST be nonzero for us to get here
	mov	r11, r8
	mov	ecx, eax
	mov	r8d, ecx
	mov	edx, ecx
	shl	edx, 3
	add	r11, rdx
	sub	r11, 8
	mov	r9d, 64
	sub	r9d, r10d
	xor	edx, edx
	jmp	.partial
calign
.nothingtodo:
	epilog

end if

if used bigint$subtract_unsigned | defined include_everything
	; two arguments: rdi == destination bigint object, rsi == source bigint to subtract
	; NOTE: result _can_ be signed, even though we don't pay ANY attention to the dest/source signs
	; e.g. if source > dest, result will be negative
falign
bigint$subtract_unsigned:
	prolog	bigint$subtract_unsigned
	; NOTE: compare_unsigned does not modify rdi/rsi so we don't bother saving it, and we further depend on its leftover registers
	call	bigint$compare_unsigned
	cmp	eax, 0
	je	.setzero
	jl	.negresult
	; otherwise, destination > source, so proceed with a "normal" sbb operation
	; r11d is leftover source wordcount from compare_unsigned, no sense in recalculating it
	mov	ecx, r11d
	shl	ecx, 3
	mov	rdi, [rdi+bigint_words_ofs]
	mov	rsi, [rsi+bigint_words_ofs]
	add	rdi, rcx
	add	rsi, rcx
	neg	rcx
	jz	.nothingtodo
	clc			; lazy, probably should just start with an add
calign
.doit:
	mov	rax, [rsi+rcx]
	sbb	[rdi+rcx], rax
	lea	rcx, [rcx+8]	; don't mess with the carry flag
	jrcxz	.done		; slow, maybe we should do it in groups instead, hmmm, TODO
	jmp	.doit
calign
.done:
	sbb	qword [rdi+rcx], 0
	; we need to continue the carry operation up to the destination's wordcount
	lea	rcx, [rcx+8]	; TODO: do I need to prevent overrun here?
	jc	.done
	epilog
calign
.setzero:
	call	bigint$clear
	epilog
calign
.nothingtodo:
	epilog
calign
.negresult:
	; source is bigger than dest, create a temporary to do the result
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	rdi, rsi
	call	bigint$new_copy
	mov	[rsp+16], rax
	; so now we have a copy of our source, subtract the destination into it
	mov	rdi, rax
	mov	rsi, [rsp]
	call	bigint$subtract_unsigned
	; assign that result to our real destination
	mov	rdi, [rsp]
	mov	rsi, [rsp+16]
	call	bigint$assign
	; kill our temporary
	mov	rdi, [rsp+16]
	call	bigint$destroy
	; last but not least, set our dest sign to negative
	mov	rdi, [rsp]
	mov	dword [rdi+bigint_negative_ofs], 1
	add	rsp, 24
	epilog

end if


if used bigint$add_unsigned | defined include_everything
	; two arguments: rdi == destination bigint object, rsi == source bigint to add from
	; does not touch/look at the sign
falign
bigint$add_unsigned:
	prolog	bigint$add_unsigned
	; figure out our source's wordcount
	mov	r10, [rsi+bigint_words_ofs]
	mov	r11d, [rsi+bigint_size_ofs]
	mov	edx, r11d
	shl	edx, 3
	add	r10, rdx
	sub	r10, 8
calign
.wc:
	cmp	qword [r10], 0
	jne	.wcdone
	sub	r11d, 1
	jz	.wcdone
	sub	r10, 8
	jmp	.wc
calign
.wcdone:
	test	r11d, r11d
	jz	.nothingtodo
	mov	ecx, r11d
	add	r11d, 1		; we need enough room in our destination for source's wordcount + 1
	cmp	r11d, [rdi+bigint_size_ofs]
	ja	.needmorespace
calign
.keepgoing:
	; loop count is in ecx
	shl	ecx, 3
	mov	rdi, [rdi+bigint_words_ofs]
	mov	rsi, [rsi+bigint_words_ofs]
	add	rdi, rcx
	add	rsi, rcx
	neg	rcx
	clc			; lazy, probably should just start with an add
calign
.doit:
	mov	rax, [rsi+rcx]
	adc	[rdi+rcx], rax
	lea	rcx, [rcx+8]	; don't mess with the carry flag
	jrcxz	.done		; slow, maybe we should do it in groups instead, hmmm, TODO
	jmp	.doit
calign
.done:
	adc	qword [rdi+rcx], 0
	epilog
calign
.needmorespace:
	push	rdi rsi
	mov	esi, r11d
	call	bigint$resize
	pop	rsi rdi
	; refigure our wordcount
	mov	r10, [rsi+bigint_words_ofs]
	mov	ecx, [rsi+bigint_size_ofs]
	mov	edx, ecx
	shl	edx, 3
	add	r10, rdx
	sub	r10, 8
calign
.wc2:
	cmp	qword [r10], 0
	jne	.keepgoing
	sub	ecx, 1
	sub	r10, 8
	jmp	.wc2
	epilog
calign
.nothingtodo:
	epilog

end if

if used bigint$subtract | defined include_everything
	; two arguments: rdi == destination bigint object, rsi == source bigint
falign
bigint$subtract:
	prolog	bigint$subtract
	; we know compare_unsigned doesn't blast rdi and rsi, and leaves source's wordcount in r11
	call	bigint$compare_unsigned
	mov	ecx, [rdi+bigint_negative_ofs]
	mov	edx, [rsi+bigint_negative_ofs]
	mov	r8d, edx
	shl	r8d, 1
	or	r8d, ecx
	; so if both are positive numbers, r8d will be zero
	; if we are negative, and the source is positive, r8d will be 1
	; if we are positive, and the source is negative, r8d will be 2
	; if we are negative, and the source is negative, r8d will be 3
	test	r8d, r8d
	jnz	.checkcases
	test	eax, eax
	jz	.setzero
	push	rdi
	call	bigint$subtract_unsigned
	pop	rdi
	call	bigint$tlz
	epilog
calign
.setzero:
	call	bigint$clear
	epilog
calign
.checkcases:
	cmp	eax, 0
	je	.nums_same
	jl	.we_are_smaller
	; else, we are the bigger number
	cmp	r8d, 3
	je	.proceed	; our number is bigger, no sign change necessary
	; otherwise, signs are different, so we need to do an unsigned add without changing our sign
	push	rdi
	call	bigint$add_unsigned
	pop	rdi
	call	bigint$tlz
	epilog
calign
.we_are_smaller:
	; if the signs are the same, then we need a temporary to subtract our own from, then assign that result to us
	; and then set our sign to whatever the opposite of our source's sign is
	cmp	r8d, 3
	je	.we_are_smaller_signssame
	; if the signs are different, then we need to do an unsigned add of the soruce, and then set the sign
	; to whatever the opposite of the source's sign is
	push	rdi rsi
	call	bigint$add_unsigned
	pop	rsi rdi
	mov	eax, [rsi+bigint_negative_ofs]
	mov	ecx, 1
	sub	ecx, eax
	mov	[rdi+bigint_negative_ofs], ecx
	call	bigint$tlz
	epilog
calign
.we_are_smaller_signssame:
	push	rdi rsi
	call	bigint$subtract_unsigned
	pop	rsi rdi
	mov	eax, [rsi+bigint_negative_ofs]
	mov	ecx, 1
	sub	ecx, eax
	mov	[rdi+bigint_negative_ofs], ecx
	call	bigint$tlz
	epilog
calign
.nums_same:
	cmp	r8d, 3
	je	.nums_same_signssame
	call	bigint$clear
	epilog
calign
.nums_same_signssame:
	mov	esi, 1
	call	bigint$shl
	epilog
calign
.proceed:
	push	rdi
	call	bigint$subtract_unsigned
	pop	rdi
	call	bigint$tlz
	epilog
end if


if used bigint$add | defined include_everything
	; two arguments: rdi == destination bigint object, rsi == source bigint
falign
bigint$add:
	prolog	bigint$add
	mov	eax, [rdi+bigint_negative_ofs]
	cmp	eax, [rsi+bigint_negative_ofs]
	jne	.signsdifferent
	; otherwise, signs are the same, proceed with a normal unsigned add
	call	bigint$add_unsigned
	epilog
calign
.signsdifferent:
	; we know compare_unsigned doesn't blast rdi and rsi, and leaves source's wordcount in r11
	call	bigint$compare_unsigned
	cmp	eax, 0
	je	.setzero
	jl	.we_are_smaller
	; otherwise, we are bigger, no sign changing needs to occur
	call	bigint$subtract_unsigned
	epilog
calign
.setzero:
	call	bigint$clear
	epilog
calign
.we_are_smaller:
	; create a temporary to make a copy of rsi, then subtract our value into that value
	; and then assign ourselves to that value
	; and finally set our sign to whatever the sign of rsi is
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	rdi, rsi
	call	bigint$new_copy
	mov	[rsp+16], rax
	; so now we have a copy of our source, subtract the destination into it
	mov	rdi, rax
	mov	rsi, [rsp]
	call	bigint$subtract_unsigned
	; assign that result to our real destination
	mov	rdi, [rsp]
	mov	rsi, [rsp+16]
	call	bigint$assign
	; kill our temporary
	mov	rdi, [rsp+16]
	call	bigint$destroy
	; last but not least, set our dest sign to negative
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	eax, [rsi+bigint_negative_ofs]
	mov	[rdi+bigint_negative_ofs], eax
	add	rsp, 24
	epilog

end if


if used bigint$multiply_into | defined include_everything
	; three arguments: rdi == destination bigint, rsi == a, rdx == b
falign
bigint$multiply_into:
	prolog	bigint$multiply_into
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	rdi, rdx
	call	bigint$wordcount
	mov	[rsp+24], rax
	test	rax, rax
	jz	.setzero
	mov	rdi, [rsp+8]
	call	bigint$wordcount
	mov	[rsp+32], rax
	test	rax, rax
	jz	.setzero
	add	rax, [rsp+24]
	; so now rax has a wordcount + b wordcount
	mov	esi, eax
	mov	rdi, [rsp]
	call	bigint$resize
	mov	r8, [rsp]	; destination
	mov	r9, [rsp+8]	; a
	mov	r10, [rsp+16]	; b
	mov	rdi, [r8+bigint_words_ofs]
	mov	rsi, [r9+bigint_words_ofs]
	mov	edx, [rsp+32]
	mov	rcx, [r10+bigint_words_ofs]
	mov	r8d, [rsp+24]
	call	wd$multiply
	add	rsp, 40
	epilog
calign
.setzero:
	mov	rdi, [rsp]
	call	bigint$clear
	add	rsp, 40
	epilog

end if

if used bigint$multiply | defined include_everything
	; two arguments: rdi == source/destination bigint, rsi == a (rdi <= rdi * rsi)
	; this has to make a temporary copy of the source for the calculation
falign
bigint$multiply:
	prolog	bigint$multiply
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	bigint$new_copy
	mov	[rsp+16], rax
	mov	rdi, [rsp]
	call	bigint$wordcount
	mov	[rsp+24], rax
	test	rax, rax
	jz	.setzero
	mov	rdi, [rsp+8]
	call	bigint$wordcount
	mov	[rsp+32], rax
	test	rax, rax
	jz	.setzero
	; hmm, wtf was I thinking here? new word count is _added_
	; TODO: scratch myself about what I was thinking here
	; mul	qword [rsp+24]
	add	rax, [rsp+24]
	; so now rax has source wordcount + multipler wordcount, which is our new wordcount
	mov	esi, eax
	mov	rdi, [rsp]
	call	bigint$resize
	mov	r8, [rsp]	; destination
	mov	r9, [rsp+8]	; multiplier
	mov	r10, [rsp+16]	; source/destination copy
	mov	rdi, [r8+bigint_words_ofs]
	mov	rsi, [r9+bigint_words_ofs]
	mov	edx, [rsp+32]
	mov	rcx, [r10+bigint_words_ofs]
	mov	r8d, [rsp+24]
	call	wd$multiply
	mov	rdi, [rsp+16]
	call	bigint$destroy
	add	rsp, 40
	epilog
calign
.setzero:
	mov	rdi, [rsp]
	call	bigint$clear
	add	rsp, 40
	epilog


end if

if used bigint$square_into | defined include_everything
	; two arguments: rdi == destination bigint, rsi == source bigint
falign
bigint$square_into:
	prolog	bigint$square_into
	mov	rdx, [rsi+bigint_words_ofs]		; pointer to our words array
	mov	eax, [rsi+bigint_size_ofs]		; size of said array in words
	mov	ecx, eax
	xor	r8d, r8d
	push	rbx r12
	shl	ecx, 3					; size of said array in bytes
	mov	rbx, rdi
	mov	r12, rsi
	add	rdx, rcx
	sub	rdx, 8					; less one word
calign
.wcloop:
	cmp	qword [rdx], r8
	jne	.wcdone
	sub	eax, 1
	jz	.wcdone
	sub	rdx, 8
	jmp	.wcloop
calign
.wcdone:
	; eax now has the source's wordcount
	shl	eax, 1
	mov	esi, eax
	call	bigint$resize
	mov	rdi, [rbx+bigint_words_ofs]
	mov	rsi, [r12+bigint_words_ofs]
	; wd$square needs size-aligned to work properly (partials not okay)
	mov	edx, [r12+bigint_size_ofs]
	call	wd$square
	pop	r12 rbx
	epilog
end if


if used bigint$square | defined include_everything
	; single argument in rdi: bigint to square
	; this has to make a temporary copy of the source every time it does it
falign
bigint$square:
	prolog	bigint$square
	sub	rsp, 24
	call	bigint$wordcount
	mov	[rsp], rdi
	mov	[rsp+8], rax		; wordcount
	call	bigint$new_copy		; our source
	mov	[rsp+16], rax
	mov	rsi, [rsp+8]
	shl	esi, 1
	mov	rdi, [rsp]
	call	bigint$resize		; this will clear the top goods if it grew, else just sets the size
	mov	r8, [rsp]
	mov	r9, [rsp+16]
	mov	rdi, [r8+bigint_words_ofs]
	mov	rsi, [r9+bigint_words_ofs]
	mov	edx, [r9+bigint_size_ofs]	; wd$square needs size-aligned blocks
	call	wd$square
	mov	rdi, [rsp+16]
	call	bigint$destroy
	add	rsp, 24
	epilog

end if

if used wd$multiply | defined include_everything
	; five arguments: rdi == ptr to result, rsi == multiplier, edx == multiplier wordcount, rcx == multiplicant, r8d == multiplicant wordcount
	; must not be called with !edx or !r8d
falign
wd$multiply:
	prolog	wd$multiply
	push	rbx r12 r13
	cmp	edx, r8d
	jbe	.noswap
	xchg	rsi, rcx
	xchg	edx, r8d
calign
.noswap:
	; clear our result first, edx + r8d words
	mov	r9d, edx
	xorpd	xmm0, xmm0
	add	r9d, r8d
	xor	eax, eax
	mov	r10, rdi
	mov	r11d, r9d
	shl	r9d, 1
	test	rdi, 0xf
	jnz	.unaligned
calign
.clearloop:
	movapd	[r10], xmm0
	add	r10, 16
	sub	r11d, 1
	jnz	.clearloop

	; so now, the smaller of the two is in rsi/edx, bigger is in rcx/r8d
	mov	r9, rcx			; initial copy of the smaller for the first row
	mov	r10d, r8d
	mov	r11d, r8d		; initial copy of the bigger wordcount for the inner loop
	mov	r12, rdi		; copy of the result pointer for resetting it each rowloop
	mov	r13, rcx		; copy of the bigger pointer for resetting it for the inner loop

	mov	ecx, edx		; smaller counter is our outer rowloop
calign
.rowloop:
	mov	rbx, [rsi]
	add	rsi, 8
	mov	rdi, r12		; reset the result buffer
	mov	r9, r13			; reset the inner pointer back to the start
	mov	r10d, r11d		; reset our inner counter
calign
.colloop:
	mov	rax, [r9]
	add	r9, 8
	mul	rbx
	mov	r8d, 8
	add	[rdi], rax
	adc	[rdi+8], rdx
.colcarry:
	lea	r8, [r8+8]
	adc	qword [rdi+r8], 0
	jc	.colcarry
	add	rdi, 8
	sub	r10d, 1
	jnz	.colloop
	add	r12, 8
	sub	ecx, 1
	jnz	.rowloop
	pop	r13 r12 rbx
	epilog
calign
.unaligned:
	mov	[r10], rax
	add	r10, 8
	sub	r9d, 1
	jnz	.unaligned

	mov	r9, rcx			; initial copy of the smaller for the first row
	mov	r10d, r8d
	mov	r11d, r8d		; initial copy of the bigger wordcount for the inner loop
	mov	r12, rdi		; copy of the result pointer for resetting it each rowloop
	mov	r13, rcx		; copy of the bigger pointer for resetting it for the inner loop

	mov	ecx, edx		; smaller counter is our outer rowloop
	jmp	.rowloop
end if



if used wd$asmult | defined include_everything
	; six arguments: rdi == ptr to result, rsi == ptr to scratchpad, rdx == ptr to multiplier, ecx == rdx's wordcount, r8 == ptr to multiplicant, r9d == r8's wordcount
falign
wd$asmult:
	prolog	wd$asmult
	; we are in agreement with the inputs to this function so far
	cmp	ecx, r9d
	je	.samesizes
	mov	rsi, rdx
	mov	edx, ecx
	mov	rcx, r8
	mov	r8d, r9d
	call	wd$multiply
	epilog
calign
.samesizes:
	cmp	rdx, r8
	je	.square
	mov	rsi, rdx	; multiplier
	mov	rdx, r8		; multiplicand
	; ecx already set
	call	wd$smult
	epilog
calign
.square:
	mov	rsi, rdx
	mov	edx, ecx
	call	wd$square
	epilog

end if


; Wei Dai's method is considerably faster than my rolled versions that accomplish the same thing:
; and his square method is also considerably faster than my rolled version
; the s_ macros require rbx in addition to the other normals we used for the other macros

; e lives in r8:rbx
; d lives in r11:r10
; p lives in rdx:rax
; c lives in r9

macro s_nondiag {
	add	r9, r9		; c + c
	adc	r10, r10	; carry into d+d
	adc	r11, r11	; carry into d.high+d.high
}

macro s_beg n* {
	mov	rax, [rsi]	; A[0]
	xor	r8d, r8d	; e.high = 0
	mul	rax		; * A[0]
	mov	[rdi], rax	; into R[0]
	mov	rbx, rdx	; e.low = p.high
	mov	rax, [rsi]	; A[0]
	mul	qword [rsi+8]	; * A[1]
	xor	r11d, r11d	; d.high = 0
	mov	r9, rax		; c = p.low
	mov	r10, rdx	; d.low = p.high
	s_nondiag		; double the result
}

macro s_end n* {
	; Acc3WordsBy2(c, d, e)
	;   haha, gcc does some very interesting optimizations to Wei Dai's inline assembly
	;   and specifically, that is to say that gcc alternates the definition of e/d as the long form implies
	;   all without Wei Dai ever concerning himself with it, haha, nice!
	;   so, with the long form required, here is what it looks like:
	; e += c (with carry), c = e.low, e = d + e.high (with carry)
	add	r9, rbx		; c = (e + c).low
	adc	r8, 0		; make sure we carry into e.high
	mov	rbx, r10	; e.low = d.low
	mov	[rdi+(2*n-3)*8], r9
	mov	rcx, r8		; save e.high
	mov	r8, r11		; e.high = d.high
	add	rbx, rcx	; e = d + e.high
	adc	r8, 0
	;  
	mov	rax, [rsi+(n-1)*8]
	mul	rax
	; Acc2WordsBy2(p, e)
	add	rax, rbx
	adc	rdx, r8

	mov	[rdi+(2*n-2)*8], rax
	mov	[rdi+(2*n-1)*8], rdx
}


; e lives in r8:rbx
; d lives in r11:r10

macro s_sacc k*, i*, j* {
	; Acc3WordsBy2(c, d, e)
	;   haha, gcc does some very interesting optimizations to Wei Dai's inline assembly
	;   and specifically, that is to say that gcc alternates the definition of e/d as the long form implies
	;   all without Wei Dai ever concerning himself with it, haha, nice!
	;   so, with the long form required, here is what it looks like:
	; e += c (with carry), c = e.low, e = d + e.high (with carry)
	mov	rax, [rsi+i*8]
	add	r9, rbx		; c = (e + c).low
	mov	rbx, r10	; e.low = d.low
	mov	[rdi+k*8], r9
	adc	r8, 0		; make sure we carry into e.high
	mov	rcx, r8		; save e.high
	mov	r8, r11		; e.high = d.high
	add	rbx, rcx	; e = d + e.high
	adc	r8, 0
	;  
	mul	qword [rsi+j*8]
	xor	r11d, r11d
	mov	r9, rax
	mov	r10, rdx
}

macro m_beg n* {
	mov	rax, [rsi]	; A[0]
	xor	r11d, r11d	; high word of d clear
	mul	qword [r8]	; * B[0]
	mov	r9, rax		; c = p.low
	mov	r10, rdx	; d = p.high
}

; eliminated unnecessary instructions by combining m_beg w/ m_sacc
macro m_beg_sacc n*, k*, i*, j* {
	mov	rax, [rsi]	; A[0]
	xor	r10d, r10d
	xor	r11d, r11d
	mul	qword [r8]	; * B[0]
	mov	[rdi+k*8], rax
	mov	rax, [rsi+i*8]
	mov	r9, rdx
	mul	qword [r8+j*8]
	add	r9, rax
	adc	r10, rdx
	adc	r11, 0
}


macro t_beg n* {
	mov	rax, [rsi]	; A[0]
	xor	r11d, r11d	; high word of d clear
	mul	qword [r8+(n-2)*8]	; B[n-2]
	mov	r10, rdx
}

macro m_acc i*, j* {
	mov	rax, [rsi+i*8]	; A[i]
	mul	qword [r8+j*8]	; B[j]
	add	r9, rax
	adc	r10, rdx
	adc	r11, 0
}

macro m_acc_acc i*, j*, ii*, jj* {
	mov	rax, [rsi+i*8]	; A[i]
	mul	qword [r8+j*8]	; B[j]
	add	r9, rax
	mov	rax, [rsi+ii*8]	; A[i]
	adc	r10, rdx
	adc	r11, 0

	mul	qword [r8+jj*8]	; B[j]
	add	r9, rax
	adc	r10, rdx
	adc	r11, 0
}

macro s_acc i*, j* {
	mov	rax, [rsi+i*8]
	mul	qword [rsi+j*8]
	add	r9, rax
	adc	r10, rdx
	adc	r11, 0
}

macro s_diag i* {
	s_nondiag
	mov	rax, [rsi+i*8]
	mul	rax
	add	rax, r9
	adc	rdx, 0
	mov	r9, rax
	add	r10, rdx
	adc	r11, 0
}

macro t_acc i*, j* {
	mov	rax, [rsi+i*8]	; A[i]
	mul	qword [r8+j*8]	; B[j]
	add	r10, rdx
	adc	r11, 0
}

macro m_sacc k*, i*, j* {
	mov	[rdi+k*8], r9
	mov	r9, r10
	mov	r10, r11
	xor	r11d, r11d
	m_acc i, j
}

macro m_acc_sacc i*, j*, sk*, si*, sj* {
	mov	rax, [rsi+i*8]	; A[i]
	mul	qword [r8+j*8]	; B[j]
	add	rax, r9
	adc	r10, rdx
	adc	r11, 0
	mov	[rdi+sk*8], rax
	mov	rax, [rsi+si*8]
	mov	r9, r10
	mov	r10, r11
	xor	r11d, r11d
	mul	qword [r8+sj*8]	; B[j]
	add	r9, rax
	adc	r10, rdx
	adc	r11, 0
}

macro t_sacc0 i*, j* {
	mov	r9, r10
	mov	r10, r11
	xor	r11d, r11d
	m_acc i, j
}

macro t_sacc1 i*, j* {
	xor	eax, eax
	mov	edx, 1
	cmp	rcx, r9
	cmovb	eax, edx
	add	r10, rax
	adc	r11, 0
	mov	r9, r10
	mov	r10, r11
	xor	r11d, r11d
	m_acc i, j
}

macro m_end k*, ii* {
	mov	[rdi+k*8], r9
	mov	rax, [rsi+ii*8]
	mul	qword [r8+ii*8]
	add	rax, r10
	adc	rdx, r11
	mov	[rdi+(k+1)*8], rax
	mov	[rdi+(k+2)*8], rdx
}

macro b_sacc k*, ii*, j* {
	mov	[rdi+k*8], r9
	mov	r9, r10
	mov	rax, [rsi+ii*8]
	mul	qword [r8+j*8]
	add	r9, rax
}

macro b_acc ii*, j* {
	mov	rax, [rsi+ii*8]
	mul	qword [r8+j*8]
	add	r9, rax
}

macro b_end n* {
	mov	[rdi+(n-1)*8], r9
}

macro wdsquare c* {
	local dw,r,m,s,g,i

	s_beg c
	dw = 1
	r = 1
	while r < c*2-3
		if r < c - 1
			m = 0
			s = r + 1
		else
			m = r - c + 2
			s = c - 1
		end if
		s_sacc r, m, s
		g = s - 1
		i = m + 1
		while g > dw
			s_acc i, g
			i = i + 1
			g = g - 1
		end while
		i = (s and 1)
		g = (m and 1)
		if m = 0
			if i <> 0
				s_nondiag
				dw = dw + 1
			else
				s_diag dw
			end if
		else if g <> 0
			s_diag dw
		else
			s_nondiag
			dw = dw + 1
		end if
		r = r + 1
	end while
	s_end c
}

if used wd$square | defined include_everything
	; three arguments: rdi == result ptr to words, rsi == word ptr for multiplier, edx == wordcount for same
falign
wd$square:
	prolog	wd$square
	cmp	edx, bigint_unrollsize
	ja	.biggun
if bigint_unrollsize > 16
	cmp	edx, 16
	ja	.bigdispatch
end if
	push	rbx
	cmp	edx, 2
	jbe	.do2
	add	edx, 3
	and	edx, not 3
	shr	edx, 2
	jmp	qword [rdx*8+.unrolleddispatch]
if bigint_unrollsize > 16
calign
.bigdispatch:
	push	rbx
	add	edx, 31
	and	edx, not 31
	shr	edx, 5
	jmp	qword [rdx*8+.bigunrolleddispatch]
end if
calign
.do2:
	s_beg 2
	s_end 2
	pop	rbx
	epilog
calign
.do4:
	s_beg 4
	s_sacc 1, 0, 2
	s_diag 1
	s_sacc 2, 0, 3
	s_acc 1, 2
	s_nondiag
	s_sacc 3, 1, 3
	s_diag 2
	s_sacc 4, 2, 3
	s_nondiag
	s_end 4
	pop	rbx
	epilog

calign
.do8:
	wdsquare 8
	pop	rbx
	epilog
calign
.do12:
	wdsquare 12
	pop	rbx
	epilog

calign
.do16:
	wdsquare 16
	pop	rbx
	epilog

if bigint_unrollsize >= 32
calign
.do32:
	wdsquare 32
	pop	rbx
	epilog
end if
if bigint_unrollsize >= 64
calign
.do64:
	wdsquare 64
	pop	rbx
	epilog
end if
if bigint_unrollsize >= 96
calign
.do96:
	wdsquare 96
	pop	rbx
	epilog
end if
if bigint_unrollsize >= 128
calign
.do128:
	wdsquare 128
	pop	rbx
	epilog
end if

dalign
.unrolleddispatch:
	dq	.do2, .do4, .do8, .do12, .do16
if bigint_unrollsize > 16
dalign
.bigunrolleddispatch:
end if
if bigint_unrollsize = 32
	dq	.do2, .do32
else if bigint_unrollsize = 64
	dq	.do2, .do32, .do64
else if bigint_unrollsize = 96
	dq	.do2, .do32, .do64, .do96
else if bigint_unrollsize = 128
	dq	.do2, .do32, .do64, .do96, .do128
else if bigint_unrollsize <> 16
	err
end if


calign
.biggun:
	; three arguments: rdi == result ptr to words, rsi == word ptr for multiplier, edx == wordcount for same
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	mov	r14d, edx
	
	shr	edx, 1
	call	wd$square

	mov	edx, r13d
	lea	rdi, [rbx+r13*8]	; R2
	lea	rsi, [r12+r13*4]	; A1
	shr	edx, 1
	call	wd$square

	shl	r14d, 3			; this is how much scratchspace we need
	sub	rsp, r14

	mov	ecx, r13d
	mov	rdi, rsp
	mov	rsi, r12		; A0
	lea	rdx, [r12+r13*4]	; A1
	shr	ecx, 1
	call	wd$smult
	
	lea	rdi, [rbx+r13*4]	; R1
	lea	rsi, [rbx+r13*4]	; R1
	mov	rdx, rsp		; T0
	mov	ecx, r13d		; N
	call	wd$add
	
	mov	r12d, eax
	
	lea	rdi, [rbx+r13*4]	; R1
	lea	rsi, [rbx+r13*4]	; R1
	mov	rdx, rsp		; T0
	mov	ecx, r13d		; N
	call	wd$add
	
	add	r12d, eax

	mov	r8d, r13d
	mov	esi, r13d
	shl	r8d, 2			; r13*4
	lea	rdi, [rbx+r13*8]	; R2
	mov	edx, r12d
	add	rdi, r8			; R3
	shr	esi, 1
	call	wd$inc

	add	rsp, r14

	pop	r14 r13 r12 rbx
	epilog
end if


macro wdsmult c* {
	local r,m,s,g1,g2

	m_beg c
	r = 0
	while r < c*2-3
		if r < c - 1
			m = 0
			s = r + 1
		else
			m = r - c + 2
			s = c - 1
		end if
		m_sacc r, m, s
		g1 = m + 1
		g2 = s - 1
		while g2 >= m
			m_acc g1, g2
			g1 = g1 + 1
			g2 = g2 - 1
		end while
		r = r + 1
	end while
	m_end r, s
}


if used wd$smult | defined include_everything
	; four arguments: rdi == result ptr to words, rsi == word ptr for multipler, rdx == word ptr for multiplicand, ecx == wordcount (same for both operands)
falign
wd$smult:
	prolog	wd$smult
	cmp	ecx, bigint_unrollsize
	ja	.biggun
if bigint_unrollsize > 16
	cmp	ecx, 16
	ja	.bigdispatch
end if
	mov	r8, rdx		; we need rdx for the multiplies
	cmp	ecx, 2
	jbe	.do2
	add	ecx, 3
	; and	ecx, not 3
	shr	ecx, 2
	jmp	qword [rcx*8+.unrolleddispatch]
	; rsi == multiplier (A)
	; r8 == multiplicand (B)
	; rdi == result (R)
if bigint_unrollsize > 16
calign
.bigdispatch:
	add	ecx, 31
	; and	ecx, not 31
	shr	ecx, 5
	mov	r8, rdx		; we need rdx for the multiplies
	jmp	qword [rcx*8+.bigunrolleddispatch]
end if
	
dalign
.unrolleddispatch:
	dq	.do2, .do4, .do8, .do12, .do16
if bigint_unrollsize > 16
dalign
.bigunrolleddispatch:
end if
if bigint_unrollsize = 32
	dq	.do2, .do32
else if bigint_unrollsize = 64
	dq	.do2, .do32, .do64
else if bigint_unrollsize = 96
	dq	.do2, .do32, .do64, .do96
else if bigint_unrollsize = 128
	dq	.do2, .do32, .do64, .do96, .do128
else if bigint_unrollsize <> 16
	err
end if

calign
.do2:
	mov     rax, [rsi]              ; A0
	mov     rcx, [rsi+8]            ; A1
	xor     r10d, r10d              ; r2
	xor     r11d, r11d              ; r3
	mul     qword [r8]              ; * B0, r0 == low word of this
	mov     [rdi], rax              ; r0
	mov     r9, rdx                 ; r1
	mov     rax, rcx                ; A1
	mul     qword [r8]              ; * B0, r1 += low word of this, r2 == carry + highword
	add     r9, rax
	adc     r10, rdx
	adc     r11, 0
	mov     rax, [rsi]
	mul     qword [r8+8]            ; B1 * A0, r1 += low word of this, r2 += carry + highword
	add     r9, rax
	adc     r10, rdx
	mov     rax, rcx                ; A1
	adc     r11, 0
	mov     [rdi+8], r9
	mul     qword [r8+8]            ; B1 * A1, r2 += low word of this, r3 += carry + highword
	add     r10, rax
	adc     r11, rdx
	mov     [rdi+16], r10
	mov     [rdi+24], r11
	epilog
calign
.do4:
	m_beg_sacc 4, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc_acc 1, 2, 2, 1
	m_acc_sacc 3, 0, 3, 1, 3
	m_acc 2, 2
	m_acc_sacc 3, 1, 4, 2, 3
	m_acc 3, 2
	m_end 5, 3
	epilog
calign
.do8:
	m_beg_sacc 8, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc_acc 1, 2, 2, 1
	m_acc_sacc 3, 0, 3, 0, 4
	m_acc 1, 3
	m_acc 2, 2
	m_acc 3, 1
	m_acc_sacc 4, 0, 4, 0, 5
	m_acc 1, 4
	m_acc 2, 3
	m_acc 3, 2
	m_acc 4, 1
	m_acc_sacc 5, 0, 5, 0, 6
	m_acc 1, 5
	m_acc 2, 4
	m_acc 3, 3
	m_acc 4, 2
	m_acc 5, 1
	m_acc_sacc 6, 0, 6, 0, 7
	m_acc 1, 6
	m_acc 2, 5
	m_acc 3, 4
	m_acc 4, 3
	m_acc 5, 2
	m_acc 6, 1
	m_acc_sacc 7, 0, 7, 1, 7
	m_acc 2, 6
	m_acc 3, 5
	m_acc 4, 4
	m_acc 5, 3
	m_acc 6, 2
	m_acc_sacc 7, 1, 8, 2, 7
	m_acc 3, 6
	m_acc 4, 5
	m_acc 5, 4
	m_acc 6, 3
	m_acc_sacc 7, 2, 9, 3, 7
	m_acc 4, 6
	m_acc 5, 5
	m_acc 6, 4
	m_acc_sacc 7, 3, 10, 4, 7
	m_acc_acc 5, 6, 6, 5
	m_acc_sacc 7, 4, 11, 5, 7
	m_acc 6, 6
	m_acc_sacc 7, 5, 12, 6, 7
	m_acc 7, 6
	m_end 13, 7
	epilog
calign
.do12:
	m_beg_sacc 12, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc 1, 2
	m_acc 2, 1
	m_acc_sacc 3, 0, 3, 0, 4
	m_acc 1, 3
	m_acc 2, 2
	m_acc 3, 1
	m_acc_sacc 4, 0, 4, 0, 5
	m_acc 1, 4
	m_acc 2, 3
	m_acc 3, 2
	m_acc 4, 1
	m_acc_sacc 5, 0, 5, 0, 6
	m_acc 1, 5
	m_acc 2, 4
	m_acc 3, 3
	m_acc 4, 2
	m_acc 5, 1
	m_acc_sacc 6, 0, 6, 0, 7
	m_acc 1, 6
	m_acc 2, 5
	m_acc 3, 4
	m_acc 4, 3
	m_acc 5, 2
	m_acc 6, 1
	m_acc_sacc 7, 0, 7, 0, 8
	m_acc 1, 7
	m_acc 2, 6
	m_acc 3, 5
	m_acc 4, 4
	m_acc 5, 3
	m_acc 6, 2
	m_acc 7, 1
	m_acc_sacc 8, 0, 8, 0, 9
	m_acc 1, 8
	m_acc 2, 7
	m_acc 3, 6
	m_acc 4, 5
	m_acc 5, 4
	m_acc 6, 3
	m_acc 7, 2
	m_acc 8, 1
	m_acc_sacc 9, 0, 9, 0, 10
	m_acc 1, 9
	m_acc 2, 8
	m_acc 3, 7
	m_acc 4, 6
	m_acc 5, 5
	m_acc 6, 4
	m_acc 7, 3
	m_acc 8, 2
	m_acc 9, 1
	m_acc_sacc 10, 0, 10, 0, 11
	m_acc 1, 10
	m_acc 2, 9
	m_acc 3, 8
	m_acc 4, 7
	m_acc 5, 6
	m_acc 6, 5
	m_acc 7, 4
	m_acc 8, 3
	m_acc 9, 2
	m_acc 10, 1
	m_acc_sacc 11, 0, 11, 1, 11
	m_acc 2, 10
	m_acc 3, 9
	m_acc 4, 8
	m_acc 5, 7
	m_acc 6, 6
	m_acc 7, 5
	m_acc 8, 4
	m_acc 9, 3
	m_acc 10, 2
	m_acc_sacc 11, 1, 12, 2, 11
	m_acc 3, 10
	m_acc 4, 9
	m_acc 5, 8
	m_acc 6, 7
	m_acc 7, 6
	m_acc 8, 5
	m_acc 9, 4
	m_acc 10, 3
	m_acc_sacc 11, 2, 13, 3, 11
	m_acc 4, 10
	m_acc 5, 9
	m_acc 6, 8
	m_acc 7, 7
	m_acc 8, 6
	m_acc 9, 5
	m_acc 10, 4
	m_acc_sacc 11, 3, 14, 4, 11
	m_acc 5, 10
	m_acc 6, 9
	m_acc 7, 8
	m_acc 8, 7
	m_acc 9, 6
	m_acc 10, 5
	m_acc_sacc 11, 4, 15, 5, 11
	m_acc 6, 10
	m_acc 7, 9
	m_acc 8, 8
	m_acc 9, 7
	m_acc 10, 6
	m_acc_sacc 11, 5, 16, 6, 11
	m_acc 7, 10
	m_acc 8, 9
	m_acc 9, 8
	m_acc 10, 7
	m_acc_sacc 11, 6, 17, 7, 11
	m_acc 8, 10
	m_acc 9, 9
	m_acc 10, 8
	m_acc_sacc 11, 7, 18, 8, 11
	m_acc 9, 10
	m_acc 10, 9
	m_acc_sacc 11, 8, 19, 9, 11
	m_acc 10, 10
	m_acc_sacc 11, 9, 20, 10, 11
	m_acc 11, 10
	m_end 21, 11
	epilog
calign
.do16:
	m_beg_sacc 16, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc 1, 2
	m_acc 2, 1
	m_acc_sacc 3, 0, 3, 0, 4
	m_acc 1, 3
	m_acc 2, 2
	m_acc 3, 1
	m_acc_sacc 4, 0, 4, 0, 5
	m_acc 1, 4
	m_acc 2, 3
	m_acc 3, 2
	m_acc 4, 1
	m_acc_sacc 5, 0, 5, 0, 6
	m_acc 1, 5
	m_acc 2, 4
	m_acc 3, 3
	m_acc 4, 2
	m_acc 5, 1
	m_acc_sacc 6, 0, 6, 0, 7
	m_acc 1, 6
	m_acc 2, 5
	m_acc 3, 4
	m_acc 4, 3
	m_acc 5, 2
	m_acc 6, 1
	m_acc_sacc 7, 0, 7, 0, 8
	m_acc 1, 7
	m_acc 2, 6
	m_acc 3, 5
	m_acc 4, 4
	m_acc 5, 3
	m_acc 6, 2
	m_acc 7, 1
	m_acc_sacc 8, 0, 8, 0, 9
	m_acc 1, 8
	m_acc 2, 7
	m_acc 3, 6
	m_acc 4, 5
	m_acc 5, 4
	m_acc 6, 3
	m_acc 7, 2
	m_acc 8, 1
	m_acc_sacc 9, 0, 9, 0, 10
	m_acc 1, 9
	m_acc 2, 8
	m_acc 3, 7
	m_acc 4, 6
	m_acc 5, 5
	m_acc 6, 4
	m_acc 7, 3
	m_acc 8, 2
	m_acc 9, 1
	m_acc_sacc 10, 0, 10, 0, 11
	m_acc 1, 10
	m_acc 2, 9
	m_acc 3, 8
	m_acc 4, 7
	m_acc 5, 6
	m_acc 6, 5
	m_acc 7, 4
	m_acc 8, 3
	m_acc 9, 2
	m_acc 10, 1
	m_acc_sacc 11, 0, 11, 0, 12
	m_acc 1, 11
	m_acc 2, 10
	m_acc 3, 9
	m_acc 4, 8
	m_acc 5, 7
	m_acc 6, 6
	m_acc 7, 5
	m_acc 8, 4
	m_acc 9, 3
	m_acc 10, 2
	m_acc 11, 1
	m_acc_sacc 12, 0, 12, 0, 13
	m_acc 1, 12
	m_acc 2, 11
	m_acc 3, 10
	m_acc 4, 9
	m_acc 5, 8
	m_acc 6, 7
	m_acc 7, 6
	m_acc 8, 5
	m_acc 9, 4
	m_acc 10, 3
	m_acc 11, 2
	m_acc 12, 1
	m_acc_sacc 13, 0, 13, 0, 14
	m_acc 1, 13
	m_acc 2, 12
	m_acc 3, 11
	m_acc 4, 10
	m_acc 5, 9
	m_acc 6, 8
	m_acc 7, 7
	m_acc 8, 6
	m_acc 9, 5
	m_acc 10, 4
	m_acc 11, 3
	m_acc 12, 2
	m_acc 13, 1
	m_acc_sacc 14, 0, 14, 0, 15
	m_acc 1, 14
	m_acc 2, 13
	m_acc 3, 12
	m_acc 4, 11
	m_acc 5, 10
	m_acc 6, 9
	m_acc 7, 8
	m_acc 8, 7
	m_acc 9, 6
	m_acc 10, 5
	m_acc 11, 4
	m_acc 12, 3
	m_acc 13, 2
	m_acc 14, 1
	m_acc_sacc 15, 0, 15, 1, 15
	m_acc 2, 14
	m_acc 3, 13
	m_acc 4, 12
	m_acc 5, 11
	m_acc 6, 10
	m_acc 7, 9
	m_acc 8, 8
	m_acc 9, 7
	m_acc 10, 6
	m_acc 11, 5
	m_acc 12, 4
	m_acc 13, 3
	m_acc 14, 2
	m_acc_sacc 15, 1, 16, 2, 15
	m_acc 3, 14
	m_acc 4, 13
	m_acc 5, 12
	m_acc 6, 11
	m_acc 7, 10
	m_acc 8, 9
	m_acc 9, 8
	m_acc 10, 7
	m_acc 11, 6
	m_acc 12, 5
	m_acc 13, 4
	m_acc 14, 3
	m_acc_sacc 15, 2, 17, 3, 15
	m_acc 4, 14
	m_acc 5, 13
	m_acc 6, 12
	m_acc 7, 11
	m_acc 8, 10
	m_acc 9, 9
	m_acc 10, 8
	m_acc 11, 7
	m_acc 12, 6
	m_acc 13, 5
	m_acc 14, 4
	m_acc_sacc 15, 3, 18, 4, 15
	m_acc 5, 14
	m_acc 6, 13
	m_acc 7, 12
	m_acc 8, 11
	m_acc 9, 10
	m_acc 10, 9
	m_acc 11, 8
	m_acc 12, 7
	m_acc 13, 6
	m_acc 14, 5
	m_acc_sacc 15, 4, 19, 5, 15
	m_acc 6, 14
	m_acc 7, 13
	m_acc 8, 12
	m_acc 9, 11
	m_acc 10, 10
	m_acc 11, 9
	m_acc 12, 8
	m_acc 13, 7
	m_acc 14, 6
	m_acc_sacc 15, 5, 20, 6, 15
	m_acc 7, 14
	m_acc 8, 13
	m_acc 9, 12
	m_acc 10, 11
	m_acc 11, 10
	m_acc 12, 9
	m_acc 13, 8
	m_acc 14, 7
	m_acc_sacc 15, 6, 21, 7, 15
	m_acc 8, 14
	m_acc 9, 13
	m_acc 10, 12
	m_acc 11, 11
	m_acc 12, 10
	m_acc 13, 9
	m_acc 14, 8
	m_acc_sacc 15, 7, 22, 8, 15
	m_acc 9, 14
	m_acc 10, 13
	m_acc 11, 12
	m_acc 12, 11
	m_acc 13, 10
	m_acc 14, 9
	m_acc_sacc 15, 8, 23, 9, 15
	m_acc 10, 14
	m_acc 11, 13
	m_acc 12, 12
	m_acc 13, 11
	m_acc 14, 10
	m_acc_sacc 15, 9, 24, 10, 15
	m_acc 11, 14
	m_acc 12, 13
	m_acc 13, 12
	m_acc 14, 11
	m_acc_sacc 15, 10, 25, 11, 15
	m_acc 12, 14
	m_acc 13, 13
	m_acc 14, 12
	m_acc_sacc 15, 11, 26, 12, 15
	m_acc 13, 14
	m_acc 14, 13
	m_acc_sacc 15, 12, 27, 13, 15
	m_acc 14, 14
	m_acc_sacc 15, 13, 28, 14, 15
	m_acc 15, 14
	m_end 29, 15
	epilog
if bigint_unrollsize >= 32
calign
.do32:
	wdsmult 32
	epilog
end if
if bigint_unrollsize >= 64
calign
.do64:
	wdsmult 64
	epilog
end if
if bigint_unrollsize >= 96
calign
.do96:
	wdsmult 96
	epilog
end if
if bigint_unrollsize >= 128
calign
.do128:
	wdsmult 128
	epilog
end if
calign
.biggun:
	; we'll use our stackframe as our scratch area
	push	rbx r12 r13 r14 r15
	mov	r15d, ecx
	mov	rbx, rdi	; copy of result ptr (R)
	mov	r12, rsi	; copy of multiplier ptr (A)
	shl	r15d, 4		; x 8 x 2 == stackframe size
	mov	r13, rdx	; copy of multiplicand ptr (B)
	mov	r14d, ecx	; copy of wordcount
	sub	rsp, r15	; scratchpad at rsp upward

	mov	edx, ecx
	mov	rdi, r12
	lea	rsi, [r12+rcx*4]	; A1
	shr	edx, 1
	call	wd$cmp
	mov	r9d, r14d
	mov	r8d, 0
	shr	r9d, 1		; n2
	cmp	eax, 1
	cmovne	r8d, r9d	; an2
	push	r8

	mov	rdi, rbx	; R
	lea	rsi, [r12+r8*8]	; A + an2
	mov	ecx, r9d	; count for sub
	xor	r9d, r8d	; n2 ^ an2
	lea	rdx, [r12+r9*8]	; A + (n2 ^ an2)
	call	wd$sub

	mov	edx, r14d
	mov	rdi, r13
	lea	rsi, [r13+rdx*4]	; B1
	shr	edx, 1		; n1
	call	wd$cmp

	mov	r9d, r14d
	mov	r8d, 0
	shr	r9d, 1		; n2
	cmp	eax, 1
	cmovne	r8d, r9d	; bn2
	push	r8

	lea	rdi, [rbx+r9*8]	; R1
	lea	rsi, [r13+r8*8]	; B + bn2
	mov	ecx, r9d	; count for sub
	xor	r9d, r8d	; n2 ^ bn2
	lea	rdx, [r13+r9*8]	; B + (n2 ^ bn2)
	call	wd$sub

	mov	ecx, r14d
	lea	rdi, [rbx+r14*8]; R2
	lea	rsi, [r12+r14*4]; A1
	lea	rdx, [r13+r14*4]; B1
	shr	ecx, 1
	call	wd$smult

	mov	ecx, r14d
	lea	rdi, [rsp+16]	; T0
	mov	rsi, rbx	; R0
	lea	rdx, [rbx+r14*4]; R1
	shr	ecx, 1
	call	wd$smult

	mov	ecx, r14d
	mov	rdi, rbx	; R0
	mov	rsi, r12	; A0
	mov	rdx, r13	; B0
	shr	ecx, 1
	call	wd$smult

	; we are done with r12 and r13
	mov	ecx, r14d
	lea	rdi, [rbx+r14*8]	; R2
	lea	rdx, [rbx+r14*4]	; R1
	shr	ecx, 1
	mov	rsi, rdi		; R2
	call	wd$add
	mov	r12d, eax
	mov	r13d, eax
	
	mov	ecx, r14d
	lea	rdi, [rbx+r14*4]	; R1
	lea	rsi, [rbx+r14*8]	; R2
	mov	rdx, rbx		; R0
	shr	ecx, 1
	call	wd$add
	add	r12d, eax

	lea	rdx, [rbx+r14*8]	; R2
	mov	r8d, r14d
	mov	ecx, r14d
	mov	rdi, rdx		; R2
	shl	r8d, 2			; r14*4
	mov	rsi, rdx		; R2
	shr	ecx, 1
	add	rdx, r8			; R3
	call	wd$add
	add	r13d, eax
	
	pop	r9 r8	; bn2 in r9, an2 in r8

	mov	ecx, r14d
	lea	rdi, [rbx+r14*4]	; R1

	mov	rdx, rsp		; T0
	mov	rsi, rdi		; R1

	cmp	r9, r8
	je	.biggun_subtract
	
	call	wd$add
	add	r13d, eax

	; we are all done with our temporary stack now, reclaim it
	add	rsp, r15

	mov	esi, r14d
	lea	rdi, [rbx+r14*8]	; R2
	shr	esi, 1
	mov	edx, r12d

	; we can pop r15 here too
	pop	r15

	; copy of final fallthrough to avoid extra branch
	call	wd$inc
	add	r13d, eax

	lea	rdi, [rbx+r14*8]	;
	mov	r8d, r14d
	mov	esi, r14d
	pop	r14
	shl	r8d, 2			; r14*4
	mov	edx, r13d
	pop	r13
	add	rdi, r8			; R3
	shr	esi, 1
	pop	r12
	call	wd$inc

	pop	rbx
	epilog
calign
.biggun_subtract:
	call	wd$sub
	sub	r13d, eax

	; we are all done with our temporary stack now, reclaim it
	add	rsp, r15

	mov	esi, r14d
	lea	rdi, [rbx+r14*8]	; R2
	shr	esi, 1
	mov	edx, r12d

	; we can pop r15 here too
	pop	r15

	call	wd$inc
	add	r13d, eax

	lea	rdi, [rbx+r14*8]	;
	mov	r8d, r14d
	mov	esi, r14d
	pop	r14
	shl	r8d, 2			; r14*4
	mov	edx, r13d
	pop	r13
	add	rdi, r8			; R3
	shr	esi, 1
	pop	r12
	call	wd$inc

	pop	rbx
	epilog
end if

macro wdlowmul c* {
	local r,m,s,g1,g2
	r = 0
	m = 0

	m_beg c
	while r < c*2-3 & m = 0
		if r < c - 1
			m = 0
			s = r + 1
		else
			m = r - c + 2
			s = c - 1
		end if
		if m > 0
			break
		end if
		if r <> c-2
			m_sacc r, m, s
		else
			b_sacc r, m, s
		end if
		g1 = m + 1
		g2 = s - 1
		while g2 >= m
			if r <> c-2
				m_acc g1, g2
			else
				b_acc g1, g2
			end if
			g1 = g1 + 1
			g2 = g2 - 1
		end while
		r = r + 1
	end while
	b_end c
}

; the lower half, upper half and symmetric adds are support functions for the montgomery reducer/exponentiator

if used wd$mullower | defined include_everything
	; four arguments: rdi == result ptr to words, rsi == word ptr for multiplier, rdx == word ptr for multiplicand, ecx == wordcount (same for both operands)
	; calculates the lower half only of multiplier * multipicand
falign
wd$mullower:
	prolog	wd$mullower
	cmp	ecx, bigint_unrollsize
	ja	.biggun
	mov	r8, rdx		; we need rdx for the multiplies
if bigint_unrollsize > 16
	cmp	ecx, 16
	ja	.bigdispatch
end if
	cmp	ecx, 2
	jbe	.do2
	add	ecx, 3
	and	ecx, not 3
	shr	ecx, 2
	jmp	qword [rcx*8+.unrolleddispatch]
	; rsi == multiplier (A)
	; r8 == multiplicand (B)
	; rdi == result (R)
if bigint_unrollsize > 16
calign
.bigdispatch:
	add	ecx, 31
	and	ecx, not 31
	shr	ecx, 5
	jmp	qword [rcx*8+.bigunrolleddispatch]
end if
calign
.do2:
	m_beg 2
	b_sacc 0, 0, 1
	b_acc 1, 0
	b_end 2
	epilog
calign
.do4:
	m_beg_sacc 4, 0, 0, 1
	m_acc_sacc 1, 0, 1, 2, 0
	m_acc 1, 1
	m_acc 0, 2
	b_sacc 2, 0, 3
	b_acc 1, 2
	b_acc 2, 1
	b_acc 3, 0
	b_end 4
	epilog

calign
.do8:
	m_beg_sacc 8, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc 1, 2
	m_acc 2, 1
	m_acc_sacc 3, 0, 3, 0, 4
	m_acc 1, 3
	m_acc 2, 2
	m_acc 3, 1
	m_acc_sacc 4, 0, 4, 0, 5
	m_acc 1, 4
	m_acc 2, 3
	m_acc 3, 2
	m_acc 4, 1
	m_acc_sacc 5, 0, 5, 0, 6
	m_acc 1, 5
	m_acc 2, 4
	m_acc 3, 3
	m_acc 4, 2
	m_acc 5, 1
	m_acc 6, 0
	b_sacc 6, 0, 7
	b_acc 1, 6
	b_acc 2, 5
	b_acc 3, 4
	b_acc 4, 3
	b_acc 5, 2
	b_acc 6, 1
	b_acc 7, 0
	b_end 8
	epilog

calign
.do12:
	m_beg_sacc 12, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc 1, 2
	m_acc 2, 1
	m_acc_sacc 3, 0, 3, 0, 4
	m_acc 1, 3
	m_acc 2, 2
	m_acc 3, 1
	m_acc_sacc 4, 0, 4, 0, 5
	m_acc 1, 4
	m_acc 2, 3
	m_acc 3, 2
	m_acc 4, 1
	m_acc_sacc 5, 0, 5, 0, 6
	m_acc 1, 5
	m_acc 2, 4
	m_acc 3, 3
	m_acc 4, 2
	m_acc 5, 1
	m_acc_sacc 6, 0, 6, 0, 7
	m_acc 1, 6
	m_acc 2, 5
	m_acc 3, 4
	m_acc 4, 3
	m_acc 5, 2
	m_acc 6, 1
	m_acc_sacc 7, 0, 7, 0, 8
	m_acc 1, 7
	m_acc 2, 6
	m_acc 3, 5
	m_acc 4, 4
	m_acc 5, 3
	m_acc 6, 2
	m_acc 7, 1
	m_acc_sacc 8, 0, 8, 0, 9
	m_acc 1, 8
	m_acc 2, 7
	m_acc 3, 6
	m_acc 4, 5
	m_acc 5, 4
	m_acc 6, 3
	m_acc 7, 2
	m_acc 8, 1
	m_acc_sacc 9, 0, 9, 0, 10
	m_acc 1, 9
	m_acc 2, 8
	m_acc 3, 7
	m_acc 4, 6
	m_acc 5, 5
	m_acc 6, 4
	m_acc 7, 3
	m_acc 8, 2
	m_acc 9, 1
	m_acc 10, 0
	b_sacc 10, 0, 11
	b_acc 1, 10
	b_acc 2, 9
	b_acc 3, 8
	b_acc 4, 7
	b_acc 5, 6
	b_acc 6, 5
	b_acc 7, 4
	b_acc 8, 3
	b_acc 9, 2
	b_acc 10, 1
	b_acc 11, 0
	b_end 12
	epilog
calign
.do16:
	m_beg_sacc 16, 0, 0, 1
	m_acc_sacc 1, 0, 1, 0, 2
	m_acc 1, 1
	m_acc_sacc 2, 0, 2, 0, 3
	m_acc 1, 2
	m_acc 2, 1
	m_acc_sacc 3, 0, 3, 0, 4
	m_acc 1, 3
	m_acc 2, 2
	m_acc 3, 1
	m_acc_sacc 4, 0, 4, 0, 5
	m_acc 1, 4
	m_acc 2, 3
	m_acc 3, 2
	m_acc 4, 1
	m_acc_sacc 5, 0, 5, 0, 6
	m_acc 1, 5
	m_acc 2, 4
	m_acc 3, 3
	m_acc 4, 2
	m_acc 5, 1
	m_acc_sacc 6, 0, 6, 0, 7
	m_acc 1, 6
	m_acc 2, 5
	m_acc 3, 4
	m_acc 4, 3
	m_acc 5, 2
	m_acc 6, 1
	m_acc_sacc 7, 0, 7, 0, 8
	m_acc 1, 7
	m_acc 2, 6
	m_acc 3, 5
	m_acc 4, 4
	m_acc 5, 3
	m_acc 6, 2
	m_acc 7, 1
	m_acc_sacc 8, 0, 8, 0, 9
	m_acc 1, 8
	m_acc 2, 7
	m_acc 3, 6
	m_acc 4, 5
	m_acc 5, 4
	m_acc 6, 3
	m_acc 7, 2
	m_acc 8, 1
	m_acc_sacc 9, 0, 9, 0, 10
	m_acc 1, 9
	m_acc 2, 8
	m_acc 3, 7
	m_acc 4, 6
	m_acc 5, 5
	m_acc 6, 4
	m_acc 7, 3
	m_acc 8, 2
	m_acc 9, 1
	m_acc_sacc 10, 0, 10, 0, 11
	m_acc 1, 10
	m_acc 2, 9
	m_acc 3, 8
	m_acc 4, 7
	m_acc 5, 6
	m_acc 6, 5
	m_acc 7, 4
	m_acc 8, 3
	m_acc 9, 2
	m_acc 10, 1
	m_acc_sacc 11, 0, 11, 0, 12
	m_acc 1, 11
	m_acc 2, 10
	m_acc 3, 9
	m_acc 4, 8
	m_acc 5, 7
	m_acc 6, 6
	m_acc 7, 5
	m_acc 8, 4
	m_acc 9, 3
	m_acc 10, 2
	m_acc 11, 1
	m_acc_sacc 12, 0, 12, 0, 13
	m_acc 1, 12
	m_acc 2, 11
	m_acc 3, 10
	m_acc 4, 9
	m_acc 5, 8
	m_acc 6, 7
	m_acc 7, 6
	m_acc 8, 5
	m_acc 9, 4
	m_acc 10, 3
	m_acc 11, 2
	m_acc 12, 1
	m_acc_sacc 13, 0, 13, 0, 14
	m_acc 1, 13
	m_acc 2, 12
	m_acc 3, 11
	m_acc 4, 10
	m_acc 5, 9
	m_acc 6, 8
	m_acc 7, 7
	m_acc 8, 6
	m_acc 9, 5
	m_acc 10, 4
	m_acc 11, 3
	m_acc 12, 2
	m_acc 13, 1
	m_acc 14, 0
	b_sacc 14, 0, 15
	b_acc 1, 14
	b_acc 2, 13
	b_acc 3, 12
	b_acc 4, 11
	b_acc 5, 10
	b_acc 6, 9
	b_acc 7, 8
	b_acc 8, 7
	b_acc 9, 6
	b_acc 10, 5
	b_acc 11, 4
	b_acc 12, 3
	b_acc 13, 2
	b_acc 14, 1
	b_acc 15, 0
	b_end 16
	epilog
if bigint_unrollsize >= 32
calign
.do32:
	wdlowmul 32
	epilog
end if
if bigint_unrollsize >= 64
calign
.do64:
	wdlowmul 64
	epilog
end if
if bigint_unrollsize >= 96
calign
.do96:
	wdlowmul 96
	epilog
end if
if bigint_unrollsize >= 128
calign
.do128:
	wdlowmul 128
	epilog
end if

dalign
.unrolleddispatch:
	dq	.do2, .do4, .do8, .do12, .do16
if bigint_unrollsize > 16
dalign
.bigunrolleddispatch:
end if
if bigint_unrollsize = 32
	dq	.do2, .do32
else if bigint_unrollsize = 64
	dq	.do2, .do32, .do64
else if bigint_unrollsize = 96
	dq	.do2, .do32, .do64, .do96
else if bigint_unrollsize = 128
	dq	.do2, .do32, .do64, .do96, .do128
else if bigint_unrollsize <> 16
	err
end if

calign
.biggun:
	; four arguments: rdi == result ptr to words, rsi == word ptr for multiplier, rdx == word ptr for multiplicand, ecx == wordcount (same for both operands)
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	r14d, ecx
	mov	r15d, ecx

	shr	ecx, 1
	call	wd$smult

	shl	r15d, 2
	sub	rsp, r15
	
	mov	ecx, r14d
	mov	rdi, rsp		; T0
	lea	rsi, [r12+r14*4]	; A1
	mov	rdx, r13		; B0
	shr	ecx, 1
	call	wd$mullower

	mov	ecx, r14d
	lea	rdi, [rbx+r14*4]
	lea	rsi, [rbx+r14*4]
	mov	rdx, rsp
	shr	ecx, 1
	call	wd$add

	mov	ecx, r14d
	mov	rdi, rsp		; T0
	mov	rsi, r12		; A0
	lea	rdx, [r13+r14*4]	; B1
	shr	ecx, 1
	call	wd$mullower
	
	mov	ecx, r14d
	lea	rdi, [rbx+r14*4]
	lea	rsi, [rbx+r14*4]
	mov	rdx, rsp
	shr	ecx, 1
	call	wd$add

	add	rsp, r15
	pop	r15 r14 r13 r12 rbx
	epilog

end if


macro wdhighmul c* {
	local r,m,s,g1,g2

	t_beg c
	m = 1
	s = c - 3
	while s >= 0
		t_acc m, s
		m = m + 1
		s = s - 1
	end while
	r = 0
	while r < 2
		s = c - 1
		if r = 0
			t_sacc0 r, s
		else
			t_sacc1 r, s
		end if
		s = s - 1
		m = r + 1
		while s >= r
			m_acc m, s
			m = m + 1
			s = s - 1
		end while
		r = r + 1
	end while
	r = 0
	while r < c-3
		m = r + 2
		s = c - 1
		m_sacc r, m, s
		g1 = m + 1
		g2 = s - 1
		while g1 < c
			m_acc g1, g2
			g1 = g1 + 1
			g2 = g2 - 1
		end while
		r = r + 1
	end while
	m = c - 1
	m_end r, m
}



if used wd$mulupper | defined include_everything
	; five arguments: rdi == result ptr to words, rsi == word ptr to lower half, rdx == word ptr for multiplier, rcx == word ptr for multipicand, r8d == wordcount
	; calculates the upper half only of multiplier * multipicand
	; for smallish multiplies, this doesn't really save a huge amount of effort, and if anything, the overhead makes it worse
	; than just multiplying it out and copying the upper half in
	; for larger ones however, this can make quite a difference in how much work is actually done
	; this will die a thousand deaths if the wordcount is too small
falign
wd$mulupper:
	prolog	wd$mulupper
	cmp	r8d, 2
	je	.simple
	cmp	r8d, bigint_unrollsize
	ja	.biggun
	mov	r10d, r8d
	; rearrange our registers such that rcx becomes our word from the lower half's MSW
	mov	r9, [rsi+r8*8-8]
	mov	rsi, rdx
	mov	r8, rcx
	mov	rcx, r9			; rcx now has the MSB of the lower half (L)
	cmp	r10d, 2
	jbe	.do2
if bigint_unrollsize > 16
	cmp	r10d, 16
	ja	.bigdispatch
end if
	add	r10d, 3
	and	r10d, not 3
	shr	r10d, 2
	jmp	qword [r10*8+.unrolleddispatch]
	; rsi == multiplier (A)
	; r8 == multiplicand (B)
	; rdi == result (R)
	; rcx == MSB of lower half
if bigint_unrollsize > 16
calign
.bigdispatch:
	add	r10d, 31
	and	r10d, not 31
	shr	r10d, 5
	jmp	qword [r10*8+.bigunrolleddispatch]
end if
calign
.do2:
	breakpoint
calign
.do4:
	t_beg 4
	t_acc 1, 1
	t_acc 2, 0
	t_sacc0 0, 3
	m_acc 1, 2
	m_acc 2, 1
	m_acc 3, 0
	t_sacc1 1, 3
	m_acc 2, 2
	m_acc_sacc 3, 1, 0, 2, 3
	m_acc 3, 2
	m_end 1, 3
	epilog
calign
.do8:
	t_beg 8
	t_acc 1, 5
	t_acc 2, 4
	t_acc 3, 3
	t_acc 4, 2
	t_acc 5, 1
	t_acc 6, 0
	t_sacc0 0, 7
	m_acc 1, 6
	m_acc 2, 5
	m_acc 3, 4
	m_acc 4, 3
	m_acc 5, 2
	m_acc 6, 1
	m_acc 7, 0
	t_sacc1 1, 7
	m_acc 2, 6
	m_acc 3, 5
	m_acc 4, 4
	m_acc 5, 3
	m_acc 6, 2
	m_acc_sacc 7, 1, 0, 2, 7
	m_acc 3, 6
	m_acc 4, 5
	m_acc 5, 4
	m_acc 6, 3
	m_acc_sacc 7, 2, 1, 3, 7
	m_acc 4, 6
	m_acc 5, 5
	m_acc 6, 4
	m_acc_sacc 7, 3, 2, 4, 7
	m_acc 5, 6
	m_acc 6, 5
	m_acc_sacc 7, 4, 3, 5, 7
	m_acc 6, 6
	m_acc_sacc 7, 5, 4, 6, 7
	m_acc 7, 6
	m_end 5, 7
	epilog

calign
.do12:
	t_beg 12
	t_acc 1, 9
	t_acc 2, 8
	t_acc 3, 7
	t_acc 4, 6
	t_acc 5, 5
	t_acc 6, 4
	t_acc 7, 3
	t_acc 8, 2
	t_acc 9, 1
	t_acc 10, 0
	t_sacc0 0, 11
	m_acc 1, 10
	m_acc 2, 9
	m_acc 3, 8
	m_acc 4, 7
	m_acc 5, 6
	m_acc 6, 5
	m_acc 7, 4
	m_acc 8, 3
	m_acc 9, 2
	m_acc 10, 1
	m_acc 11, 0
	t_sacc1 1, 11
	m_acc 2, 10
	m_acc 3, 9
	m_acc 4, 8
	m_acc 5, 7
	m_acc 6, 6
	m_acc 7, 5
	m_acc 8, 4
	m_acc 9, 3
	m_acc 10, 2
	m_acc_sacc 11, 1, 0, 2, 11
	m_acc 3, 10
	m_acc 4, 9
	m_acc 5, 8
	m_acc 6, 7
	m_acc 7, 6
	m_acc 8, 5
	m_acc 9, 4
	m_acc 10, 3
	m_acc_sacc 11, 2, 1, 3, 11
	m_acc 4, 10
	m_acc 5, 9
	m_acc 6, 8
	m_acc 7, 7
	m_acc 8, 6
	m_acc 9, 5
	m_acc 10, 4
	m_acc_sacc 11, 3, 2, 4, 11
	m_acc 5, 10
	m_acc 6, 9
	m_acc 7, 8
	m_acc 8, 7
	m_acc 9, 6
	m_acc 10, 5
	m_acc_sacc 11, 4, 3, 5, 11
	m_acc 6, 10
	m_acc 7, 9
	m_acc 8, 8
	m_acc 9, 7
	m_acc 10, 6
	m_acc_sacc 11, 5, 4, 6, 11
	m_acc 7, 10
	m_acc 8, 9
	m_acc 9, 8
	m_acc 10, 7
	m_acc_sacc 11, 6, 5, 7, 11
	m_acc 8, 10
	m_acc 9, 9
	m_acc 10, 8
	m_acc_sacc 11, 7, 6, 8, 11
	m_acc 9, 10
	m_acc 10, 9
	m_acc_sacc 11, 8, 7, 9, 11
	m_acc 10, 10
	m_acc_sacc 11, 9, 8, 10, 11
	m_acc 11, 10
	m_end 9, 11
	epilog
calign
.do16:
	t_beg 16
	t_acc 1, 13
	t_acc 2, 12
	t_acc 3, 11
	t_acc 4, 10
	t_acc 5, 9
	t_acc 6, 8
	t_acc 7, 7
	t_acc 8, 6
	t_acc 9, 5
	t_acc 10, 4
	t_acc 11, 3
	t_acc 12, 2
	t_acc 13, 1
	t_acc 14, 0
	t_sacc0 0, 15
	m_acc 1, 14
	m_acc 2, 13
	m_acc 3, 12
	m_acc 4, 11
	m_acc 5, 10
	m_acc 6, 9
	m_acc 7, 8
	m_acc 8, 7
	m_acc 9, 6
	m_acc 10, 5
	m_acc 11, 4
	m_acc 12, 3
	m_acc 13, 2
	m_acc 14, 1
	m_acc 15, 0
	t_sacc1 1, 15
	m_acc 2, 14
	m_acc 3, 13
	m_acc 4, 12
	m_acc 5, 11
	m_acc 6, 10
	m_acc 7, 9
	m_acc 8, 8
	m_acc 9, 7
	m_acc 10, 6
	m_acc 11, 5
	m_acc 12, 4
	m_acc 13, 3
	m_acc 14, 2
	m_acc_sacc 15, 1, 0, 2, 15
	m_acc 3, 14
	m_acc 4, 13
	m_acc 5, 12
	m_acc 6, 11
	m_acc 7, 10
	m_acc 8, 9
	m_acc 9, 8
	m_acc 10, 7
	m_acc 11, 6
	m_acc 12, 5
	m_acc 13, 4
	m_acc 14, 3
	m_acc_sacc 15, 2, 1, 3, 15
	m_acc 4, 14
	m_acc 5, 13
	m_acc 6, 12
	m_acc 7, 11
	m_acc 8, 10
	m_acc 9, 9
	m_acc 10, 8
	m_acc 11, 7
	m_acc 12, 6
	m_acc 13, 5
	m_acc 14, 4
	m_acc_sacc 15, 3, 2, 4, 15
	m_acc 5, 14
	m_acc 6, 13
	m_acc 7, 12
	m_acc 8, 11
	m_acc 9, 10
	m_acc 10, 9
	m_acc 11, 8
	m_acc 12, 7
	m_acc 13, 6
	m_acc 14, 5
	m_acc_sacc 15, 4, 3, 5, 15
	m_acc 6, 14
	m_acc 7, 13
	m_acc 8, 12
	m_acc 9, 11
	m_acc 10, 10
	m_acc 11, 9
	m_acc 12, 8
	m_acc 13, 7
	m_acc 14, 6
	m_acc_sacc 15, 5, 4, 6, 15
	m_acc 7, 14
	m_acc 8, 13
	m_acc 9, 12
	m_acc 10, 11
	m_acc 11, 10
	m_acc 12, 9
	m_acc 13, 8
	m_acc 14, 7
	m_acc_sacc 15, 6, 5, 7, 15
	m_acc 8, 14
	m_acc 9, 13
	m_acc 10, 12
	m_acc 11, 11
	m_acc 12, 10
	m_acc 13, 9
	m_acc 14, 8
	m_acc_sacc 15, 7, 6, 8, 15
	m_acc 9, 14
	m_acc 10, 13
	m_acc 11, 12
	m_acc 12, 11
	m_acc 13, 10
	m_acc 14, 9
	m_acc_sacc 15, 8, 7, 9, 15
	m_acc 10, 14
	m_acc 11, 13
	m_acc 12, 12
	m_acc 13, 11
	m_acc 14, 10
	m_acc_sacc 15, 9, 8, 10, 15
	m_acc 11, 14
	m_acc 12, 13
	m_acc 13, 12
	m_acc 14, 11
	m_acc_sacc 15, 10, 9, 11, 15
	m_acc 12, 14
	m_acc 13, 13
	m_acc 14, 12
	m_acc_sacc 15, 11, 10, 12, 15
	m_acc 13, 14
	m_acc 14, 13
	m_acc_sacc 15, 12, 11, 13, 15
	m_acc 14, 14
	m_acc_sacc 15, 13, 12, 14, 15
	m_acc 15, 14
	m_end 13, 15
	epilog

if bigint_unrollsize >= 32
calign
.do32:
	wdhighmul 32
	epilog
end if
if bigint_unrollsize >= 64
calign
.do64:
	wdhighmul 64
	epilog
end if
if bigint_unrollsize >= 96
calign
.do96:
	wdhighmul 96
	epilog
end if
if bigint_unrollsize >= 128
calign
.do128:
	wdhighmul 128
	epilog
end if

dalign
.unrolleddispatch:
	dq	.do2, .do4, .do8, .do12, .do16
if bigint_unrollsize > 16
dalign
.bigunrolleddispatch:
end if
if bigint_unrollsize = 32
	dq	.do2, .do32
else if bigint_unrollsize = 64
	dq	.do2, .do32, .do64
else if bigint_unrollsize = 96
	dq	.do2, .do32, .do64, .do96
else if bigint_unrollsize = 128
	dq	.do2, .do32, .do64, .do96, .do128
else if bigint_unrollsize <> 16
	err
end if


calign
.biggun:
	; five arguments: rdi == result ptr to words, rsi == word ptr to lower half, rdx == word ptr for multiplier, rcx == word ptr for multipicand, r8d == wordcount
	push	rbp rbx r12 r13 r14 r15
	mov	rbp, rsi	; save copy of the lower half

	mov	r15d, r8d
	mov	rbx, rdi	; copy of result ptr (R)
	mov	r12, rdx	; copy of multiplier ptr (A)
	shl	r15d, 4		; x 8 x 2 == stackframe size
	mov	r13, rcx	; copy of multiplicand ptr (B)
	mov	r14d, r8d	; copy of wordcount
	sub	rsp, r15	; scratchpad at rsp upward

	mov	edx, r8d
	mov	rdi, r12	; A0
	lea	rsi, [r12+r8*4]	; A1
	shr	edx, 1

	call	wd$cmp
	mov	r9d, r14d
	mov	r8d, 0
	shr	r9d, 1		; n2
	cmp	eax, 1
	cmovne	r8d, r9d	; an2
	push	r8

	mov	rdi, rbx	; R
	lea	rsi, [r12+r8*8]	; A + an2
	mov	ecx, r9d	; count for sub
	xor	r9d, r8d	; n2 ^ an2
	lea	rdx, [r12+r9*8]	; A + (n2 ^ an2)
	call	wd$sub

	mov	edx, r14d
	mov	rdi, r13	; B0
	lea	rsi, [r13+rdx*4]; B1
	shr	edx, 1		; n1
	call	wd$cmp

	mov	r9d, r14d
	mov	r8d, 0
	shr	r9d, 1		; n2
	cmp	eax, 1
	cmovne	r8d, r9d	; bn2
	push	r8

	lea	rdi, [rbx+r9*8]	; R1
	lea	rsi, [r13+r8*8]	; B + bn2
	mov	ecx, r9d	; count for sub
	xor	r9d, r8d	; n2 ^ bn2
	lea	rdx, [r13+r9*8]	; B + (n2 ^ bn2)
	call	wd$sub

	mov	ecx, r14d
	lea	rdi, [rsp+16]	; T0
	mov	rsi, rbx	; R0
	lea	rdx, [rbx+r14*4]; R1
	shr	ecx, 1
	call	wd$smult

	mov	ecx, r14d
	mov	rdi, rbx	; R0
	lea	rsi, [r12+r14*4]; A1
	lea	rdx, [r13+r14*4]; B1
	shr	ecx, 1
	call	wd$smult

	; we are done with A and B, next is call to subtract, and then we are done with L (rbp) as well
	mov	ecx, r14d
	lea	rdi, [rsp+r14*8+16]	; T2
	lea	rsi, [rbp+r14*4]	; L+N2
	mov	rdx, rbp		; L
	shr	ecx, 1
	call	wd$sub

	pop	r9 r8			; bn2 in r9, an2 in r8
	mov	r12d, eax		; c2

	cmp	r8, r9
	jne	.biggun_subadd
	; else, addsub
	mov	ecx, r14d
	lea	rdi, [rsp+r14*8]	; T2
	lea	rsi, [rsp+r14*8]	; T2
	mov	rdx, rsp		; T0
	shr	ecx, 1
	call	wd$add
	sub	r12d, eax

	mov	edx, r14d
	lea	rdi, [rsp+r14*8]	; T2
	mov	rsi, rbx		; R0
	shr	edx, 1
	call	wd$cmp
	xor	ebp, ebp
	mov	ecx, 1
	cmp	eax, -1
	cmove	ebp, ecx		; t = cmp == -1
	mov	ecx, r14d
	lea	rdi, [rsp+r14*8]	; T2
	lea	rsi, [rsp+r14*8]	; T2
	lea	rdx, [rsp+r14*4]	; T1
	shr	ecx, 1
	call	wd$sub
	mov	r13d, ebp
	sub	r13d, eax
	jmp	.biggun_nearlythere
calign
.biggun_subadd:
	mov	ecx, r14d
	lea	rdi, [rsp+r14*8]	; T2
	lea	rsi, [rsp+r14*8]	; T2
	mov	rdx, rsp		; T0
	shr	ecx, 1
	call	wd$sub
	add	r12d, eax

	mov	edx, r14d
	lea	rdi, [rsp+r14*8]	; T2
	mov	rsi, rbx		; R0
	shr	edx, 1
	call	wd$cmp
	xor	ebp, ebp
	mov	ecx, 1
	cmp	eax, -1
	cmove	ebp, ecx		; t = cmp == -1
	mov	ecx, r14d
	lea	rdi, [rsp+r14*8]	; T2
	lea	rsi, [rsp+r14*8]	; T2
	lea	rdx, [rsp+r14*4]	; T1
	shr	ecx, 1
	call	wd$add
	mov	r13d, ebp
	add	r13d, eax
calign
.biggun_nearlythere:
	add	r12d, ebp		; c2 += t
	mov	esi, r14d
	lea	rdi, [rsp+r14*8]	; T2
	shr	esi, 1
	mov	edx, r12d
	cmp	r12d, 0
	jge	.biggun_final_incfirst
	; else, dec first
	neg	edx
	call	wd$dec
	sub	r13d, eax

	mov	ecx, r14d
	mov	rdi, rbx		; R
	lea	rsi, [rsp+r14*8]	; T2
	lea	rdx, [rbx+r14*4]	; R1
	shr	ecx, 1
	jmp	.biggun_final
calign
.biggun_final_incfirst:
	call	wd$inc
	add	r13d, eax

	mov	ecx, r14d
	mov	rdi, rbx		; R
	lea	rsi, [rsp+r14*8]	; T2
	lea	rdx, [rbx+r14*4]	; R1
	shr	ecx, 1
calign
.biggun_final:
	call	wd$add
	add	r13d, eax
	
	mov	esi, r14d
	mov	edx, r13d
	shr	esi, 1
	lea	rdi, [rbx+r14*4]	; R1
	call	wd$inc

	add	rsp, r15
	pop	r15 r14 r13 r12 rbx rbp
	epilog

calign
.simple:
	sub	rsp, 32
	mov	r8, rdx
	
	mov	r9, [r8]

	mov	rax, [rcx]
	mul	r9
	mov	[rsp], rax
	mov	[rsp+8], rdx
	mov	rax, [rcx+8]
	mul	r9
	add	[rsp+8], rax
	adc	rdx, 0
	mov	[rsp+16], rdx
	
	mov	r9, [r8+8]

	mov	rax, [rcx]
	mul	r9
	xor	r10d, r10d
	add	[rsp+8], rax
	adc	[rsp+16], rdx
	adc	r10, 0
	mov	[rsp+24], r10

	mov	rax, [rcx+8]
	mul	r9
	add	[rsp+16], rax
	adc	[rsp+24], rdx

	mov	rax, [rsp+16]
	mov	rdx, [rsp+24]
	mov	[rdi], rax
	mov	[rdi+8], rdx
	add	rsp, 32
	epilog
end if

if used wd$inc | defined include_everything
	; three arguments: rdi == ptr to words, esi == wordcount of same, rdx == amount to add
falign
wd$inc:
	prolog	wd$inc
	sub	esi, 1
	add	[rdi], rdx
	jc	.carryloop
	xor	eax, eax
	epilog
calign
.carryloop:
	lea	rdi, [rdi+8]
	add	qword [rdi], 1
	jnc	.zeroret
	sub	esi, 1
	jnz	.carryloop
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used wd$dec | defined include_everything
	; three arguments: rdi == ptr to words, esi == wordcount of same, rdx == amount to sub
falign
wd$dec:
	prolog	wd$dec
	sub	esi, 1
	sub	[rdi], rdx
	jc	.carryloop
	xor	eax, eax
	epilog
calign
.carryloop:
	lea	rdi, [rdi+8]
	sub	qword [rdi], 1
	jnc	.zeroret
	sub	esi, 1
	jnz	.carryloop
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if

if used wd$add | defined include_everything
	; four arguments: rdi == result ptr to words, rsi == word ptr to left, rdx == word ptr to right, ecx == wordcount of same
falign
wd$add:
	prolog	wd$add
	shl	ecx, 3
	add	rdi, rcx
	add	rsi, rcx
	add	rdx, rcx
	neg	rcx
	jz	.do_return
	mov	rax, [rsi+rcx]
	add	rax, [rdx+rcx]
	mov	[rdi+rcx], rax
calign
.loop:
	mov	rax, [rsi+rcx+8]
	adc	rax, [rdx+rcx+8]
	mov	[rdi+rcx+8], rax
	lea	rcx, [rcx+16]
	jrcxz	.do_return
	mov	rax, [rsi+rcx]
	adc	rax, [rdx+rcx]
	mov	[rdi+rcx], rax
	jmp	.loop
calign
.do_return:
	mov	rax, 0
	adc	rax, rax
	epilog

end if


if used wd$sub | defined include_everything
	; four arguments: rdi == result ptr to words, rsi == word ptr to left, rdx == word ptr to right, ecx == wordcount of same
falign
wd$sub:
	prolog	wd$sub
	shl	ecx, 3
	add	rdi, rcx
	add	rsi, rcx
	add	rdx, rcx
	neg	rcx
	jz	.do_return
	mov	rax, [rsi+rcx]
	sub	rax, [rdx+rcx]
	mov	[rdi+rcx], rax
calign
.loop:
	mov	rax, [rsi+rcx+8]
	sbb	rax, [rdx+rcx+8]
	mov	[rdi+rcx+8], rax
	lea	rcx, [rcx+16]
	jrcxz	.do_return
	mov	rax, [rsi+rcx]
	sbb	rax, [rdx+rcx]
	mov	[rdi+rcx], rax
	jmp	.loop
calign
.do_return:
	mov	rax, 0
	adc	rax, rax
	epilog


end if

if used wd$cmp | defined include_everything
	; three arguments: rdi == word ptr to left, rsi == word ptr to right, edx == wordcount of same
	; returns -1, 0, 1 in eax
falign
wd$cmp:
	prolog	wd$cmp
	test	edx, edx
	jz	.zeroret
	shl	edx, 3
	mov	rax, [rdi+rdx-8]
	cmp	rax, [rsi+rdx-8]
	ja	.oneret
	jb	.negoneret
	sub	edx, 8
	jz	.zeroret
calign
.loop:
	mov	rax, [rdi+rdx-8]
	cmp	rax, [rsi+rdx-8]
	ja	.oneret
	jb	.negoneret
	sub	edx, 8
	jz	.zeroret
	mov	rax, [rdi+rdx-8]
	cmp	rax, [rsi+rdx-8]
	ja	.oneret
	jb	.negoneret
	sub	edx, 8
	jz	.zeroret
	mov	rax, [rdi+rdx-8]
	cmp	rax, [rsi+rdx-8]
	ja	.oneret
	jb	.negoneret
	sub	edx, 8
	jz	.zeroret
	mov	rax, [rdi+rdx-8]
	cmp	rax, [rsi+rdx-8]
	ja	.oneret
	jb	.negoneret
	sub	edx, 8
	jnz	.loop
	xor	eax, eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
calign
.negoneret:
	mov	eax, -1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if


if used wd$twoscomp | defined include_everything
	; two arguments: rdi == ptr to words, esi == count of same
falign
wd$twoscomp:
	prolog	wd$twoscomp
	mov	rdx, rdi
	mov	ecx, esi
	sub	qword [rdx], 1
.borrow:
	lea	rdx, [rdx+8]
	sbb	qword [rdx], 0
	jc	.borrow
calign
.notloop:
	not	qword [rdi]
	add	rdi, 8
	sub	esi, 1
	jnz	.notloop
	epilog

end if


if used wd$invmodpow2 | defined include_everything
	; four arguments: rdi == result ptr to words, rsi == scratchpad, rdx == word ptr for source, ecx == wordcount of same (rounded?)
falign
wd$invmodpow2:
	prolog	wd$invmodpow2
	sub	rsp, 32
	shr	ecx, 1
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	cmp	ecx, 1
	je	.norecursion
	call	wd$invmodpow2

if defined analdebug
	; test loop
	mov	rdi, [rsp]
	mov	rcx, [rsp+24]
	xor	esi, esi
calign
.debug:
	mov	rax, [rdi]
	add	rdi, 8
	breakpoint
	add	esi, 1
	sub	ecx, 1
	jnz	.debug

	; end test
end if

	mov	rdi, [rsp]			; R
	mov	rsi, [rsp+8]			; T
	mov	rdx, [rsp+16]			; A
	mov	rcx, [rsp+24]			; N
	mov	r9, rsi
	mov	qword [rsi], 1		; T[0] = 1
	xor	eax, eax
	mov	r8d, ecx
	mov	r10d, ecx
	add	r9, 8
	sub	r8d, 1
calign
.clearloop:
	mov	[r9], rax		; T[1..N2-1] = 0
	add	r9, 8
	sub	r8d, 1
	jnz	.clearloop
	shl	r10d, 3
	;                         rdi rsi rdx rcx r8
	; we want to call mulupper(R1, T0, R0, A0, N2)
	mov	r8d, ecx
	mov	rcx, rdx
	mov	rdx, rdi
	; T0 already set
	; R1 set at R, add r10
	add	rdi, r10		; R1
	call	wd$mulupper




	;                         rdi rsi rdx rcx
	; we want to call mullower(T0, R0, A1, N2)
	mov	rcx, [rsp+24]	; N2
	mov	rdx, [rsp+16]	; A
	mov	r10d, ecx
	mov	rdi, [rsp+8]	; T
	shl	r10d, 3
	mov	rsi, [rsp]	; R
	add	rdx, r10
	call	wd$mullower


if defined analdebug
	; test loop
	mov	rdi, [rsp+8]			; T
	mov	rcx, [rsp+24]
	mov	r10, rcx
	shl	r10, 3
	; add	rdi, r10
	xor	esi, esi
calign
.debug2:
	mov	rax, [rdi]
	add	rdi, 8
	breakpoint
	add	esi, 1
	sub	ecx, 1
	jnz	.debug2

	; end test
end if


	mov	ecx, [rsp+24]
	mov	rdx, [rsp+8]
	mov	rsi, [rsp]
	mov	r8d, ecx
	mov	rdi, rdx
	shl	r8d, 3
	add	rsi, r8
	call	wd$add




	mov	rdi, [rsp+8]
	mov	esi, [rsp+24]
	call	wd$twoscomp



	;
	; we want to call mullower(R1, R0, T0, N2)
	mov	rcx, [rsp+24]	; N2
	mov	rdx, [rsp+8]	; T0
	mov	r10d, ecx
	mov	rsi, [rsp]	; R0
	shl	r10d, 3
	mov	rdi, rsi
	add	rdi, r10
	call	wd$mullower




	add	rsp, 32
	epilog
calign
.norecursion:
	; this section validated

	; T[0] = AtomicInverseModPower2(A[0])
	; T[1] = 0
	mov	r8, [rdx]	; A[0]
	mov	r9, r8
	and	r9d, 7		; invmod result
	mov	ecx, 3
	mov	r11, rdx	; save rdx cuz our mults will blast it
calign
.invmodloop:
	mov	r10d, 2
	mov	rax, r9
	mul	r8
	sub	r10, rax
	mov	rax, r9
	mul	r10
	mov	r9, rax
	shl	ecx, 1
	cmp	ecx, 64
	jb	.invmodloop
	mov	[rsi], r9	; T[0] = r9
	mov	qword [rsi+8], 0

	;                     R   A  B (in the context of the macro defs)
	; next up: s_pBot[0](T+2, T, A) == Baseline_MultiplyBottom2 == Bot_2 ==
	mov	rax, [r11]	; B[0]
	mul	qword [rsi]	; A[0] p = A[0] * B[0]
	mov	[rsi+16], rax	; R[0] = c (which was set to p.low)
	mov	r10, rdx	; c = p.high
	mov	rax, [r11+8]	; B[1]
	mul	qword [rsi]	; A[0]
	add	r10, rax
	; next one is zero from our previous set rsi+8, so we skip that one
	; mov	rax, [rsi+8]	; A[1]
	; mul	qword [r11]	; B[0]
	; add	r10, rax
	mov	[rsi+24], r10
	
	; next up:
	; TwosComplement(T+2, 2)
	; T+2 == rsi+16
	sub	qword [rsi+16], 1
	sbb	qword [rsi+24], 0
	not	qword [rsi+16]
	not	qword [rsi+24]

	; next up: Increment(T+2, 2, 2)
	add	qword [rsi+16], 2
	adc	qword [rsi+24], 0

	;                    R  A   B
	; next up: s_pBot[0](R, T, T+2) == Baseline_MultiplyBottom2 == Bot_2 ==
	; R is still in rdi, T == rsi, T+2 == rsi+16
	mov	rax, [rsi+16]	; B[0]
	mul	qword [rsi]	; A[0]
	mov	[rdi], rax	; R[0] = c (which was set to p.low)
	mov	r10, rdx	; c = p.high
	mov	rax, [rsi+24]	; B[1]
	mul	qword [rsi]	; A[0]
	add	r10, rax

	mov	rax, [rsi+8]	; A[1]
	mul	qword [rsi+16]	; B[0]
	add	r10, rax
	mov	[rdi+8], r10

	mov	rax, [rdi]
	mov	rcx, [rdi+8]

	add	rsp, 32
	epilog

end if


if used wd$partinverse | defined include_everything
	; six arguments: rdi == result wordptr, rsi == scratchpad, rdx == source wordptr, ecx == source wordcount, r8 == modulus wordptr, r9d == modulus wordcount
	; solves k by: source^(-1) * 2^k mod modulus
	; returns k in eax
falign
wd$partinverse:
	prolog	wd$partinverse
	; rdx == A == only used to initialize F, re-use.
	; rdi == R == used throughout
	; rsi == T == only used once, re-use.
	; ecx == NA == only used once to initialize F, re-use.
	; r8 == M == used throughout
	; r9d == N == used throughout

	; so that means we have:
	; rdi == R
	; rsi == T initially, we'll re-init it as B
	; rdx == A initially, we'll re-init it as C
	; rcx == NA initially, we'll re-init it as F
	; r8 == M
	; r9d == N
	; r10 == G
	; r11 == bcLen
	; r12 == fgLen
	; r13d == K
	; r14d == S

	; which leaves us rbx, rax, r15, (rbp if we need it)

	push	rbp rbx r12 r13 r14 r15
	xorpd	xmm0, xmm0
	lea	ebx, [r9d*2+r9d]
	shl	ebx, 3
	mov	r12, rsi
	add	r12, rbx
	neg	rbx
calign
.clearloop:
	movapd	[r12+rbx], xmm0
	add	rbx, 16
	jnz	.clearloop
	lea	ebx, [r9d*8]		; N in bytes
	lea	r12, [rsi+rbx*2]	; F's location
calign
.copyloop:
	mov	rax, [rdx]
	mov	[r12], rax
	add	rdx, 8
	add	r12, 8
	sub	ecx, 1
	jnz	.copyloop
	lea	rdx, [rsi+rbx]		; C set
	lea	rcx, [rsi+rbx*2]	; F set
	lea	rbx, [rbx*2+rbx]
	lea	r10, [rsi+rbx]		; G set
	; next up, copy M into g r9d times
	xor	ebx, ebx
	mov	r11d, r9d
calign
.copyloop2:
	mov	rax, [r8+rbx]
	mov	[r10+rbx], rax
	add	rbx, 8
	sub	r11d, 1
	jnz	.copyloop2
	mov	qword [rsi], 1		; b[0] = 1
	; next up, fgLen (r12) = EvenWordCount(r8, r9d)
	mov	r12d, r9d
	mov	r11d, 2			; bcLen = 2
	xor	r13d, r13d		; k = 0
	xor	r14d, r14d		; s = false
	mov	r15, [rcx]		; t = f[0]
calign
.fgloop:
	test	r12d, r12d
	jz	.mainloop		; fgLen set
	cmp	qword [r8+r12*8-16], 0
	jne	.mainloop		; fgLen set
	cmp	qword [r8+r12*8-8], 0
	jne	.mainloop		; fgLen set
	sub	r12d, 2
	jmp	.fgloop
calign
.mainloop:
	; so at this point, rbx, rax are free
	test	r15, r15
	jnz	.mainloop_tz
	; calc evenwordcount for f using a temporary rax
	mov	eax, r12d
	mov	ebx, 1
calign
.fgloop2:
	test	eax, eax
	jz	.zeroret
	cmp	qword [rcx+rax*8-16], 0
	jne	.mainloop_doshift
	cmp	qword [rcx+rax*8-8], 0
	jne	.mainloop_doshift
	sub	eax, 2
	jmp	.fgloop2
calign
.mainloop_doshift:
	; F >>= 64
	cmp	ebx, r12d
	jae	.mainloop_shiftdone
	mov	rax, [rcx+rbx*8]
	mov	[rcx+rbx*8-8], rax
	add	ebx, 1
	jmp	.mainloop_doshift
calign
.mainloop_shiftdone:
	mov	qword [rcx+rbx*8-8], 0
	; next up: bcLen += 2 * (c[bcLen-1] != 0)
	xor	ebx, ebx
	mov	eax, 2
	cmp	qword [rdx+r11*8-8], 0
	cmovne	ebx, eax
	add	r11d, ebx
	; next up: C <<= 64
	mov	ebx, r11d
	sub	ebx, 1
calign
.mainloop_doshift2:
	mov	rax, [rdx+rbx*8-8]
	mov	[rdx+rbx*8], rax
	sub	ebx, 1
	jnz	.mainloop_doshift2
	mov	qword [rdx], 0
	; k += 64
	add	r13d, 64
calign
.mainloop_tz:
	; i = trailingzeros(t)
	; t >>= i
	; k += i
	mov	rax, rcx		; save F because we need to use cl for our shift
	bsf	rcx, r15
	shr	r15, cl
	add	r13d, ecx
	xchg	rcx, rax		; put F back, but hang onto the bsf result
	cmp	r15, 1
	jne	.mainloop_setupshift3
	cmp	qword [rcx+8], 0
	jne	.mainloop_setupshift3
	; evenwordcount(f+2, fgLen-2) == 0 ?
	mov	ebp, r12d
	sub	ebp, 2
calign
.fgloop3:
	test	ebp, ebp
	jz	.mainloop_suborcopy_return
	cmp	qword [rcx+rbp*8], 0
	jne	.mainloop_setupshift3
	cmp	qword [rcx+rbp*8+8], 0
	jne	.mainloop_setupshift3
	sub	ebp, 2
	jmp	.fgloop3
calign
.mainloop_setupshift3:
	test	eax, eax
	jz	.mainloop_noshift3
	; f >>= bsf amount, which is still sitting in eax
	; we are free to use r15, rbp, rbx
	; shift amount in eax is nonzero, so we need to do f (rcx) for fgLen (r12d), with a carry
	; swap rax and rcx so we can use cl for our shifts
	; we need more regs here:
	push	r8 r9
	mov	r8d, eax	; shift counter
	mov	rax, rcx	; save F in rax so we can use cl for our shr/shl
	mov	ebx, r12d	; shift word counter
	xor	r15d, r15d	; carry
calign
.mainloop_shift3:
	mov	rbp, [rax+rbx*8-8]	; u = F[counter-1]
	mov	ecx, r8d
	mov	r9, rbp
	shr	r9, cl			; u >> bsf amount
	or	r9, r15			; | previous carry
	mov	ecx, 64
	mov	[rax+rbx*8-8], r9
	sub	ecx, r8d
	mov	r15, rbp
	shl	r15, cl
	sub	ebx, 1
	jnz	.mainloop_shift3
	; we aren't interested in the remaining carry, so setup our next shift:
	; c <<= bsf amount, c (rdx) for bcLen (r11d), with a carry
	; r8d is still our shift counter (bsf result)
	; rax is still set to F, which we'll have to restore when we are done
	xor	ebx, ebx		; shift word counter
	xor	r15d, r15d
calign
.mainloop_shift4:
	mov	rbp, [rdx+rbx*8]	; u = C[counter]
	mov	ecx, r8d
	mov	r9, rbp
	shl	r9, cl			; u << bsf amount
	or	r9, r15			; | previous carry
	mov	ecx, 64
	mov	[rdx+rbx*8], r9
	sub	ecx, r8d
	mov	r15, rbp
	shr	r15, cl
	add	ebx, 1
	cmp	ebx, r11d
	jb	.mainloop_shift4
	; so now, we need to restore F
	mov	rcx, rax
	; and restore r8, r9
	pop	r9 r8
	; carry sitting in t is fine
	add	[rdx+rbx*8], r15	; c[bcLen] += t
	xor	eax, eax
	mov	ebx, 2
	test	r15, r15
	cmovnz	eax, ebx
	add	r11d, eax
calign
.mainloop_noshift3:
	xor	r15d, r15d		; swap = false
	; next up: swap = (Compare(f, g, fgLen) == -1)
	; ... we _really_ don't want to have to do a function call out of here, so we will copy the wd$cmp function directly
	; we are free to use rbp, rax, r15, rbx
	; f == rdi, g == rsi
	mov	ebx, r12d
	mov	rax, [rcx+rbx*8-8]
	cmp	rax, [r10+rbx*8-8]
	ja	.mainloop_noswap
	jb	.mainloop_swap
	sub	ebx, 1
	jz	.mainloop_noswap
calign
.mainloop_compare:
	mov	rax, [rcx+rbx*8-8]
	cmp	rax, [r10+rbx*8-8]
	ja	.mainloop_noswap
	jb	.mainloop_swap
	sub	ebx, 1
	jz	.mainloop_noswap
	mov	rax, [rcx+rbx*8-8]
	cmp	rax, [r10+rbx*8-8]
	ja	.mainloop_noswap
	jb	.mainloop_swap
	sub	ebx, 1
	jz	.mainloop_noswap
	mov	rax, [rcx+rbx*8-8]
	cmp	rax, [r10+rbx*8-8]
	ja	.mainloop_noswap
	jb	.mainloop_swap
	sub	ebx, 1
	jz	.mainloop_noswap
	mov	rax, [rcx+rbx*8-8]
	cmp	rax, [r10+rbx*8-8]
	ja	.mainloop_noswap
	jb	.mainloop_swap
	sub	ebx, 1
	jnz	.mainloop_compare
	jmp	.mainloop_noswap
calign
.mainloop_swap:
	; swap f with g
	; swap b with c
	xchg	rcx, r10
	xchg	rsi, rdx
	mov	r15d, 1			; swap = true
calign
.mainloop_noswap:
	; s ^= swap
	xor	r14d, r15d
	; next up: fgLen -= 2 * !(f[fgLen-2] | f[fgLen-1])
	xor	ebx, ebx
	mov	ebp, 2
	mov	rax, [rcx+r12*8-16]
	or	rax, [rcx+r12*8-8]
	cmovz	ebx, ebp
	sub	r12d, ebx
	; save the real rcx value (F) in r15, because we need jrcxz for our sub/add loops
	mov	r15, rcx
	; next up: we have to subtract(f, f, g, fgLen)
	; but like the above, we _really_ don't want to do a function callout here, copy it is.
	mov	rbx, rcx	; f (result pointer and left pointer)
	mov	ecx, r12d	; fg len
	shl	ecx, 3
	mov	rbp, r10	; g (right pointer)
	add	rbx, rcx
	add	rbp, rcx
	neg	rcx
	jz	.mainloop_doadd
	mov	rax, [rbx+rcx]
	sub	rax, [rbp+rcx]
	mov	[rbx+rcx], rax
calign
.mainloop_subloop:
	mov	rax, [rbx+rcx+8]
	sbb	rax, [rbp+rcx+8]
	mov	[rbx+rcx+8], rax
	lea	rcx, [rcx+16]
	jrcxz	.mainloop_doadd
	mov	rax, [rbx+rcx]
	sbb	rax, [rbp+rcx]
	mov	[rbx+rcx], rax
	jmp	.mainloop_subloop
calign
.mainloop_doadd:
	; next up: t = add(b, b, c, bcLen)
	mov	rbx, rsi	; b (result pointer and left pointer)
	mov	ecx, r11d	; bc len
	shl	ecx, 3
	mov	rbp, rdx	; c (right pointer)
	add	rbx, rcx
	add	rbp, rcx
	neg	rcx
	jz	.mainloop_next
	mov	rax, [rbx+rcx]
	add	rax, [rbp+rcx]
	mov	[rbx+rcx], rax
calign
.mainloop_addloop:
	mov	rax, [rbx+rcx+8]
	adc	rax, [rbp+rcx+8]
	mov	[rbx+rcx+8], rax
	lea	rcx, [rcx+16]
	jrcxz	.mainloop_next
	mov	rax, [rbx+rcx]
	adc	rax, [rbp+rcx]
	mov	[rbx+rcx], rax
	jmp	.mainloop_addloop
calign
.mainloop_next:
	mov	rax, 0
	adc	rax, rax
	; next up: b[bcLen] += rax
	add	qword [rsi+r11*8], rax
	; bcLen += 2*t
	shl	rax, 1
	add	r11, rax
	mov	rcx, r15	; restore our F
	mov	r15, [rcx]	; t = F[0]
	jmp	.mainloop
calign
.mainloop_suborcopy_return:
	test	r14d, r14d
	jnz	.mainloop_subreturn
	mov	edx, r9d
	shl	edx, 3
	call	memcpy
	mov	rax, r13
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.mainloop_subreturn:
	; subtract r, m, b, n
	mov	rdx, rsi	; b
	mov	rsi, r8		; m
	mov	ecx, r9d	; n
	call	wd$sub
	mov	rax, r13
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.zeroret:
	; clear R, return 0, R is still sitting in rdi
	call	bigint$clear
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx rbp
	epilog

end if


if used wd$divpow2mod | defined include_everything
	; five arguments: rdi == result wordptr, rsi == input wordptr, rdx == k, rcx == modulus wordptr, r8d == wordcount
	; result = input/(2**k) mod modulus
falign
wd$divpow2mod:
	prolog	wd$divpow2mod
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi	; result
	mov	r12, rsi	; input
	mov	r13, rdx	; k
	mov	r14, rcx	; modulus
	mov	r15d, r8d	; wordcount

	mov	edx, r8d
	shl	edx, 3
	call	memcpy
	test	r13, r13
	jz	.outtahere
calign
.outer:
	test	qword [rbx], 1
	jnz	.addshift
	; else, result >>= 1
	mov	ecx, r15d
	xor	edx, edx	; carry
calign
.shiftloop:
	mov	rax, [rbx+rcx*8-8]
	mov	r8, rax
	shr	r8, 1
	or	r8, rdx
	mov	[rbx+rcx*8-8], r8
	mov	rdx, rax
	shl	rdx, 63
	sub	ecx, 1
	jnz	.shiftloop
	sub	r13, 1
	jnz	.outer
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.addshift:
	mov	rdi, rbx
	mov	rsi, rbx
	mov	rdx, r14
	mov	ecx, r15d
	call	wd$add
	mov	r9, rax		; save the carry result from the addition
	; result >>= 1
	mov	ecx, r15d
	xor	edx, edx	; carry
calign
.shiftloop2:
	mov	rax, [rbx+rcx*8-8]
	mov	r8, rax
	shr	r8, 1
	or	r8, rdx
	mov	[rbx+rcx*8-8], r8
	mov	rdx, rax
	shl	rdx, 63
	sub	ecx, 1
	jnz	.shiftloop2
	shl	r9, 63
	add	qword [rbx+r15*8-8], r9
	sub	r13, 1
	jnz	.outer
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.outtahere:
	pop	r15 r14 r13 r12 rbx
	epilog

end if



if used bigint$divide | defined include_everything
	; four arguments: rdi == bigint remainder, rsi == bigint quotient, rdx == bigint dividend, rcx == bigint divisor
falign
bigint$divide:
	prolog	bigint$divide
	mov	r8, [rdx+bigint_words_ofs]
	mov	r9d, [rdx+bigint_size_ofs]
	mov	r10, [rcx+bigint_words_ofs]
	mov	r11d, [rcx+bigint_size_ofs]
	mov	eax, r9d
	shl	eax, 3
	add	r8, rax
	sub	r8, 8
	mov	eax, r11d
	shl	eax, 3
	add	r10, rax
	sub	r10, 8
calign
.wc1:
	cmp	qword [r8], 0
	jne	.wc2
	sub	r9d, 1
	jz	.wc2
	sub	r8, 8
	jmp	.wc1
calign
.wc2:
	cmp	qword [r10], 0
	jne	.wcdone
	sub	r11d, 1
	jz	.wcdone
	sub	r10, 8
	jmp	.wc2
calign
.wcdone:
	; so r9d is dividend's (rdx) size, r11d is divisor's (rcx) size
	cmp	r9d, r11d
	jb	.divisorbigger
	sub	rsp, 192
	add	r9d, 1
	mov	[rsp], rdi		; remainder
	add	r11d, 1
	mov	[rsp+8], rsi		; quotient
	and	r9d, not 1
	mov	[rsp+16], rdx		; dividend
	and	r11d, not 1
	mov	[rsp+24], rcx		; divisor
	mov	[rsp+32], r9		; dividend's wordcount rounded up to even
	mov	[rsp+40], r11		; divisor's wordcount rounded up to even
	mov	dword [rdi+bigint_negative_ofs], 0
	mov	dword [rsi+bigint_negative_ofs], 0
	mov	esi, r11d
	call	bigint$newsize_clear

	mov	rdi, [rsp+8]
	mov	esi, [rsp+32]
	sub	esi, [rsp+40]
	add	esi, 2
	call	bigint$newsize_clear
	mov	edi, [rsp+32]
	mov	ecx, [rsp+40]
	mov	[rsp+56], rbx
	add	ecx, 2
	mov	[rsp+64], r12
	shl	ecx, 1
	mov	[rsp+72], r13
	add	ecx, ecx
	mov	[rsp+80], r14
	add	edi, ecx
	mov	[rsp+88], r15

	shl	edi, 3
	call	heap$alloc
	mov	[rsp+48], rax		; our scratchpad
	mov	ecx, [rsp+32]
	mov	r13, rax		; TA
	mov	rdx, [rsp+40]
	shl	ecx, 3			; NA in bytes
	mov	r8, [rsp+16]
	mov	ebx, edx		; NB into ebx
	shl	edx, 3			; NB in bytes
	mov	r9, [rsp+24]
	mov	r14, r13
	add	r14, rcx
	add	r14, 16			; TB
	mov	r15, r14
	add	r15, rdx		; TP

	mov	r11, [r8+bigint_words_ofs]	; A
	xor	eax, eax
	mov	r12, [r9+bigint_words_ofs]	; B
	xor	r10d, r10d
	mov	r9d, 1
	cmp	qword [r12+rdx-8], 0
	cmove	r10d, r9d		; shiftWords now in r10d
	mov	[r14], rax		; TB[0] = 0
	mov	[rsp+112], r10		; save shiftWords for later
	mov	r9d, edx
	mov	[r14+rdx-8], rax	; TB[NB-1] = 0
	shr	r9d, 3			; NB
	sub	r9d, r10d		; - shiftWords
	xor	r8d, r8d
	shl	r10d, 3						; shiftWords in bytes
	add	r14, r10		; TB+shiftWords
calign
.setup1:
	mov	rax, [r12+r8*8]
	mov	[r14+r8*8], rax
	add	r8d, 1
	sub	r9d, 1
	jnz	.setup1
	sub	r14, r10		; restore original TB
	; load TB[NB-1]
	mov	rax, [r14+rdx-8]	; TB[NB-1]
	mov	r9d, 63
	bsr	rax, rax
	sub	r9d, eax		; - BitPrecision(TB[NB-1]) == shiftBits
	; now we need to do: ShiftWordsLeftByBits(TB, NB, shiftBits)

	mov	r8d, edx
	mov	[rsp+120], r9		; save shiftBits for later
	shr	r8d, 3			; NB (how many words we need to do)
	xor	edi, edi		; carry
	test	r9d, r9d
	jz	.setup1_noshl
	xor	esi, esi		; our index into the shift
calign
.setup1_shl:
	mov	ecx, r9d
	mov	rax, [r14+rsi*8]
	mov	rdx, rax
	shl	rax, cl
	or	rax, rdi
	mov	[r14+rsi*8], rax
	mov	ecx, 64
	add	rsi, 1
	sub	ecx, r9d
	shr	rdx, cl
	mov	rdi, rdx
	sub	r8d, 1
	jnz	.setup1_shl
	; we blasted rdi and rcx and rdx through there
calign
.setup1_noshl:

	mov	edx, ebx		; restore NB

	mov	ecx, [rsp+32]
	xor	eax, eax
	mov	r8d, ecx		; save for later use
	shl	ecx, 3			; NA in bytes
	; now do the same to TA
	mov	[r13], rax		; TA[0] = 0
	
	mov	[r13+rcx], rax	; TA[NA] = 0
	mov	[r13+rcx+8], rax	; TA[NA+1] = 0
	; now we need to do: CopyWords(TA+shiftWords, A, NA)
	; A is in r11
	; shiftWords is presently in bytes
	mov	rdi, r13
	add	rdi, r10
	mov	rsi, r11
	shr	ecx, 3			; NA
calign
.setup2:
	mov	rax, [rsi]
	mov	[rdi], rax
	add	rsi, 8
	add	rdi, 8
	sub	ecx, 1
	jnz	.setup2
	; now we need to do: ShiftWordsLeftByBits(TA, NA+2, shiftBits)
	add	r8d, 2			; NA+2, our loop count
	xor	esi, esi		; index into our TA
	xor	edi, edi		; carry
	test	r9d, r9d
	jz	.setup2_noshl
calign
.setup2_shl:
	mov	ecx, r9d
	mov	rax, [r13+rsi]
	mov	rdx, rax
	shl	rax, cl
	or	rax, rdi
	mov	[r13+rsi], rax
	mov	ecx, 64
	add	rsi, 8
	sub	ecx, r9d
	shr	rdx, cl
	mov	rdi, rdx
	sub	r8d, 1
	jnz	.setup2_shl
calign
.setup2_noshl:
	mov	edx, ebx		; restore our NB into edx for below (TODO, remove/change the references)
	
	xor	eax, eax
	mov	rsi, [rsp+8]		; Q
	; now we need:
	; if (TA[NA+1] == 0 && TA[NA] <= 1) {
	mov	ecx, [rsp+32]
	shl	ecx, 3			; NA in bytes
	cmp	[r13+rcx+8], rax
	jne	.setup4
	cmp	qword [r13+rcx], 1
	ja	.setup4
	; Q[NA-NB+1] = Q[NA-NB] = 0
	mov	edx, [rsp+40]
	mov	ebx, edx		; save copy of NB
	shl	edx, 3			; NB in bytes
	mov	r8d, ecx
	mov	rdi, [rsi+bigint_words_ofs]	; Q.bigint_words_ofs
	sub	r8d, edx		; NA-NB in bytes
	mov	[rdi+r8], rax		; Q[NA-NB] = 0
	mov	[rdi+r8+8], rax		; Q[NA-NB+1] = 0
	; now we need: while (TA[NA] || Compare(TA+NA-NB, TB, NB) >= 0) {
	;                TA[NA] -= Subtract(TA+NA-NB, TA+NA-NB, TB, NB);
	;		 ++Q[NA-NB]
	;               }
	; and then jump to setupr
calign
.setup3:
	cmp	qword [r13+rcx], 0	; TA[NA] ?
	jne	.setup3_doit
	mov	ecx, edx		; NB in bytes
	mov	r11d, ebx		; NB
	mov	r12, r13		; TA
	add	r12, r8			; TA+NA-NB
	sub	ecx, 8			; NB-1 in bytes
calign
.setup3_inner:
	mov	rax, [r12+rcx]
	cmp	rax, [r14+rcx]
	jb	.setupr			; if TB >, bailout
	ja	.setup3_doit		; if TB <, doit
	sub	rcx, 8
	sub	r11d, 1
	jnz	.setup3_inner
	; if we fell out of that loop, they are equal
calign
.setup3_doit:
	; TA[NA] -= Subtract(TA+NA-NB, TA+NA-NB, TB, NB)
	; %1 = NB
	; %2 = TA+NA-NB
	; %3 = TA+NA-NB
	; %4 = TB
	mov	ecx, ebx
	shl	ecx, 3			; NB in bytes
	mov	r12, r13		; TA
	add	r12, r8			; TA+NA-NB
	add	r12, rcx		; at the end of same
	add	r14, rcx		; also at the end of same
	mov	ecx, ebx		; NB
	neg	rcx
	jz	.setup3_done
	mov	rax, [r12+rcx*8]	
	sub	rax, [r14+rcx*8]
	mov	[r12+rcx*8], rax
calign
.setup3_doit_inner:
	mov	rax, [r12+rcx*8+8]
	sbb	rax, [r14+rcx*8+8]
	mov	[r12+rcx*8+8], rax
	lea	rcx, [rcx+2]
	jrcxz	.setup3_done
	mov	rax, [r12+rcx*8]
	sbb	rax, [r14+rcx*8]
	mov	[r12+rcx*8], rax
	jmp	.setup3_doit_inner
calign
.setup3_done:
	mov	rax, 0
	adc	rax, rax
	mov	ecx, ebx
	shl	ecx, 3
	sub	r14, rcx		; restore r14 to its previous value
	mov	ecx, [rsp+32]
	shl	ecx, 3			; NA in bytes
	sub	[r13+rcx], rax		; TA[NA] -= Subtract(TA+NA-NB, TA+NA-NB, TB, NB)
	; next up: ++Q[NA-NB]
	add	qword [rdi+r8], 1
	jmp	.setup3
calign
.setup4:
	shr	ecx, 3
	add	ecx, 2
	mov	[rsp+32], ecx		; NA += 2
	mov	edx, [rsp+40]
	mov	ebx, edx		; save copy of NB
	shl	edx, 3			; NB in bytes
calign
.setupr:
	; we need a space for two more words on rsp
	; and then: BT[0] = TB[NB-2] + 1
	; BT[1] = TB[NB-1] + (BT[0] == 0)
	xor	ecx, ecx
	mov	rax, [r14+rdx-16]
	mov	r11d, 1
	add	rax, 1
	cmovz	ecx, r11d
	mov	[rsp+96], rax
	add	rcx, [r14+rdx-8]
	mov	[rsp+104], rcx
	mov	r11d, [rsp+32]		; NA
	sub	r11d, 2

	; restore rdi
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+bigint_words_ofs]

calign
.rloop:
	cmp	r11d, ebx		; i >= NB?
	jb	.rloop_done

	;                Q       A     B
	; AtomicDivide(Q+i-NB, TA+i-2, BT);
	;    ->         DWord q = DivideFourWordsByTwo<word, DWord>(T, DWord(A[0], A[1]), DWord(A[2], A[3]), DWord(B[0], B[1]));

	; so at this point:
	; rdi == Q
	; r11d == i
	; ebx == NB
	; r13 == TA
	; r14 == TB
	; r15 == TP
	; [rsp] == R (bigint), will need its bigint_words_ofs
	; [rsp+96] == BT[0]
	; [rsp+104] == BT[1]
	; [rsp+112] == shiftWords
	; [rsp+120] == shiftBits
	; [rsp+128] == T[0]
	; [rsp+136] == T[1]
	; [rsp+144] == T[2]
	; [rsp+152] == T[3]
	; rax, rcx, rdx, rsi, r8, r9, r10, r12 are free, stack from 128 upward is free too
	mov	ecx, r11d
	sub	ecx, ebx
	; so we need pointers to Q+i-NB, TA+i-2, BT
	; [rdi+rcx*8] == Q+i-NB
	; [r13+r11*8-16] == TA+i-2
	; [rsp+96] == BT
	; if !BT[0] && !BT[1], set Q[0] == TA+i, set Q[1] == TA+i+1, proceed to CorrectQuotientEstimate
	; otherwise, proceed with divide

	cmp	qword [rsp+96], 0
	jne	.rloop_dodiv
	cmp	qword [rsp+104], 0
	jne	.rloop_dodiv
	; else, !B, so set Q
	mov	rax, [r13+r11*8]
	mov	rdx, [r13+r11*8+8]
	mov	[rdi+rcx*8], rax
	mov	[rdi+rcx*8+8], rdx
	jmp	.rloop_dodiv_fixquotient
calign
.rloop_dodiv:
	; B is nonzero, proceed with divide
	; twowords q = div4x2(T, twowords(TA+i-2, TA+i-1), twowords(TA+i), twowords(TA+i+1), twowords(BT[0], BT[1]))
	; setup T[0..3]
	mov	rax, [r13+r11*8-16]
	mov	rdx, [r13+r11*8-8]
	mov	rsi, [r13+r11*8]
	mov	r8, [r13+r11*8+8]
	mov	[rsp+128], rax		; T[0]
	mov	[rsp+136], rdx		; T[1]
	mov	[rsp+144], rsi		; T[2]
	mov	[rsp+152], r8		; T[3]

	; get our high word, which is ultimately destined for [rdi+rcx*8+8]
	; highword = div3x2(T+1, BT)
	; T[1] == [rsp+136]
	; BT[0] == [rsp+96]
	mov	r12, [rsp+152]	; T[3], A[2] -> Q
	mov	r8, [rsp+104]	; BT[1], B1
	mov	rax, r12	; copy of Q in rax
	add	r8, 1
	jz	.rloop_dodiv_subtract
	cmp	qword [rsp+104], 0
	je	.rloop_dodiv_lowwords
	; otherwise, we need: Q = T[3]A[2]:T[2]A[1] / B1+1
	mov	rdx, r12
	mov	rax, [rsp+144]	; T[2], A[1]
	div	r8
	mov	r12, rax	; Q
	jmp	.rloop_dodiv_subtract
calign
.rloop_dodiv_lowwords:
	; we need Q = T[2]A[1]:T[1]A[0] / B0
	mov	rdx, [rsp+144]	; T[2], A[1]
	mov	rax, [rsp+136]	; T[1], A[0]
	div	qword [rsp+96]	; BT[0], B0
	mov	r12, rax	; Q
calign
.rloop_dodiv_subtract:
	; now subtract Q*B from A
	; so Q is in r12 now, and also still sitting in rax
	mul	qword [rsp+96]	; Q * B0
	mov	r9, rax		; p.lowhalf
	mov	r10, rdx	; p.highhalf
	xor	r8d, r8d
	mov	rdx, [rsp+136]	; T[1], A[0]
	mov	[rsp+160], r8	; future u.lowhalf
	mov	[rsp+168], r8	; future u.highhalf
	sub	rdx, r9		;
	sbb	r8, 0		; u.highhalf
	; we need to sbb the carry if any into u.highhalf (0)
	mov	[rsp+136], rdx	; T[1], A[0] == u.lowhalf
	; now we need u = A[1], subtract p.highhalf (r10), subtract u.getHighHalfAsBorrow (which must be zero, no?), and finally subtract D::Mult(B1, Q)
	mov	rax, [rsp+144]	; T[2], A[1]
	sub	rax, r10
	sbb	qword [rsp+168], 0
	xor	r9d, r9d
	sub	r9, r8		; 0 - u.highhalf == gethighhalfasborrow
	sub	rax, r9
	sbb	qword [rsp+168], 0
	mov	qword [rsp+160], rax	; now we need the multiply(B1, Q) result
	mov	rax, [rsp+104]	; BT[1], B1
	mul	r12		; * Q
	; now we have to subtract rdx:rax with borrow into u at rsp+160..168
	sub	qword [rsp+160], rax
	sbb	qword [rsp+168], rdx
	; if there was a borrow after that, do we care? TODO: think about this some more
	mov	rax, [rsp+160]	; u.low
	mov	rdx, [rsp+168]	; u.high
	; T[2], A[1] = u.lowhalf
	mov	[rsp+144], rax	; T[2], A[1] = u.lowhalf
	; T[3], A[2] += u.highhalf
	add	[rsp+152], rdx	; T[3], A[2] += u.highhalf

	; now, if Q <= actual quotient, loop and fix it up
	; preemptively, set the actual Q spot so we can jump straight out
	mov	[rdi+rcx*8+8], r12	; high word result done
calign
.rloop_dodiv_inner:
	mov	rax, [rsp+136]		; T[1], A[0]
	mov	rdx, [rsp+144]		; T[2], A[1]

	cmp	qword [rsp+152], 0	; T[3], A[2] != 0?
	jne	.rloop_dodiv_inner_fixup
	cmp	rdx, [rsp+104]		; T[2], A[1] > BT[1], B1 ?
	ja	.rloop_dodiv_inner_fixup
	jne	.rloop_dodiv_lowq	; A[1] == B[1] &&
	cmp	rax, [rsp+96]
	jb	.rloop_dodiv_lowq
calign
.rloop_dodiv_inner_fixup:
	; all while conditions met, so now we need:
	; u = A[0] - B[0] (with borrow as before)
	xor	r8d, r8d
	sub	rax, [rsp+96]		; T[1], A[0] - BT[0], B0
	sbb	r8, 0			; u.highhalf
	mov	[rsp+136], rax		; T[1], A[0] = u.lowhalf
	; now we need: u = (D)A[1] - B1 - u.GetHighHalfAsBorrow
	xor	r9d, r9d
	sub	r9, r8			; 0 - u.highhalf == gethighhalfasborrow
	xor	r8d, r8d
	mov	rax, rdx		; T[2], A[1]
	sub	rax, [rsp+104]		; - BT[1], B1
	sbb	r8, 0
	sub	rax, r9			; - u.GetHighHalfAsBorrow
	sbb	r8, 0
	mov	[rsp+144], rax		; T[2], A[1] = u.lowhalf
	add	[rsp+152], r8		; T[3], A[2] += u.highhalf
	; now we increment Q
	add	qword [rdi+rcx*8+8], 1	; Q++
	jmp	.rloop_dodiv_inner
calign
.rloop_dodiv_lowq:
	; get our low word, which is ultimately destined for [rdi+rcx*8]
	; lowword = div3x2(T, BT)

	; T[0] == [rsp+128]
	; BT[0] == [rsp+96]
	mov	r12, [rsp+144]	; T[2], A[2] -> Q
	mov	r8, [rsp+104]	; BT[1], B1
	mov	rax, r12	; copy of Q in rax
	add	r8, 1
	jz	.rloop_dodiv_subtract2
	cmp	qword [rsp+104], 0
	je	.rloop_dodiv_lowwords2
	; otherwise, we need: Q = T[2]A[2]:T[1]A[1] / B1+1
	mov	rdx, r12
	mov	rax, [rsp+136]	; T[1], A[1]
	div	r8
	mov	r12, rax	; Q
	jmp	.rloop_dodiv_subtract2
calign
.rloop_dodiv_lowwords2:
	; we need Q = T[1]A[1]:T[0]A[0] / B0
	mov	rdx, [rsp+136]	; T[1], A[1]
	mov	rax, [rsp+128]	; T[0], A[0]
	div	qword [rsp+96]	; BT[0], B0
	mov	r12, rax	; Q
calign
.rloop_dodiv_subtract2:
	; now subtract Q*B from A
	; so Q is in r12 now, and also still sitting in rax
	mul	qword [rsp+96]	; Q * B0
	mov	r9, rax		; p.lowhalf
	mov	r10, rdx	; p.highhalf
	xor	r8d, r8d
	mov	rdx, [rsp+128]	; T[0], A[0]
	mov	[rsp+160], r8	; future u.lowhalf
	mov	[rsp+168], r8	; future u.highhalf
	sub	rdx, r9		;
	sbb	r8, 0		; u.highhalf			

	; we need to sbb the carry if any into u.highhalf (0)
	mov	[rsp+128], rdx	; T[0], A[0] == u.lowhalf
	; now we need u = A[1], subtract p.highhalf (r10), subtract u.getHighHalfAsBorrow (which must be zero, no?), and finally subtract D::Mult(B1, Q)
	mov	rax, [rsp+136]	; T[1], A[1]
	sub	rax, r10
	sbb	qword [rsp+168], 0
	xor	r9d, r9d
	sub	r9, r8		; 0 - u.highhalf == gethighhalfasborrow
	sub	rax, r9
	sbb	qword [rsp+168], 0
	mov	qword [rsp+160], rax	; now we need the multiply(B1, Q) result
	mov	rax, [rsp+104]	; BT[1], B1
	mul	r12		; * Q
	; now we have to subtract rdx:rax with borrow into u at rsp+160..168
	sub	qword [rsp+160], rax
	sbb	qword [rsp+168], rdx
	; if there was a borrow after that, do we care? TODO: think about this some more
	mov	rax, [rsp+160]	; u.low
	mov	rdx, [rsp+168]	; u.high
	; A[1] = u.lowhalf
	mov	[rsp+136], rax	; T[1], A[1] = u.lowhalf
	; A[2] += u.highhalf
	add	[rsp+144], rdx	; T[2], A[2] += u.highhalf
	
	; now, if Q <= actual quotient, loop and fix it up
	; preemptively, set the actual Q spot so we can jump straight out
	mov	[rdi+rcx*8], r12	; high word result done

calign
.rloop_dodiv_inner2:
	mov	rax, [rsp+128]		; T[0], A[0]
	mov	rdx, [rsp+136]		; T[1], A[1]

	cmp	qword [rsp+144], 0	; T[2], A[2] != 0?
	jne	.rloop_dodiv_inner_fixup2
	cmp	rdx, [rsp+104]		; T[1], A[1] > BT[1], B1 ?
	ja	.rloop_dodiv_inner_fixup2
	jne	.rloop_dodiv_fixquotient	; A[1] == B[1] &&
	cmp	rax, [rsp+96]
	jb	.rloop_dodiv_fixquotient
calign
.rloop_dodiv_inner_fixup2:
	; all while conditions met, so now we need:
	; u = A[0] - B[0] (with borrow as before)
	xor	r8d, r8d
	sub	rax, [rsp+96]		; T[0], A[0] - BT[0], B0
	sbb	r8, 0			; u.highhalf
	mov	[rsp+128], rax		; T[0], A[0] = u.lowhalf
	; now we need: u = (D)A[1] - B1 - u.GetHighHalfAsBorrow
	xor	r9d, r9d
	sub	r9, r8			; 0 - u.highhalf == gethighhalfasborrow
	xor	r8d, r8d
	mov	rax, rdx		; T[1], A[1]
	sub	rax, [rsp+104]		; - BT[1], B1
	sbb	r8, 0
	sub	rax, r9			; - u.GetHighHalfAsBorrow
	sbb	r8, 0
	mov	[rsp+136], rax		; T[1], A[1] = u.lowhalf
	add	[rsp+144], r8		; T[2], A[2] += u.highhalf
	; now we increment Q
	add	qword [rdi+rcx*8], 1	; Q++
	jmp	.rloop_dodiv_inner2

calign
.rloop_dodiv_fixquotient:
	; so the result of the goods is in [rdi+rdx*8] and [rdi+rdx*8+8]

	; so at this point:
	; rdi == Q
	; r11d == i
	; ebx == NB
	; r13 == TA
	; r14 == TB
	; r15 == TP
	; [rsp] == R (bigint), will need its bigint_words_ofs
	; [rsp+96] == BT[0]
	; [rsp+104] == BT[1]
	; [rsp+112] == shiftWords
	; [rsp+120] == shiftBits
	; [rsp+128] == T[0]
	; [rsp+136] == T[1]
	; [rsp+144] == T[2]
	; [rsp+152] == T[3]
	; rax, rcx, rdx, rsi, r8, r9, r10, r12 are free, stack from 128 upward is free too

	mov	ecx, r11d
	sub	ecx, ebx		; i-NB
	; we need pointers to: TA+i-NB, TP, Q+i-NB, TB
	; [r13+rcx*8] == TA+i-NB
	; r15 == TP
	; [rdi+rcx*8] == Q+i-NB
	; r14 == TB
	; ebx == NB
	; now we need to do:
	; CorrectQuotientEstimate(TA+i-NB, TP, Q+i-NB, TB, NB);
	;	   		     R     T    Q      B   N
	;                    rdi    rsi           rdx     ecx, r8, r9d
		; AsymmetricMultiply(r15, r15+r11*8+16, rdi+rcx*8, 2, r14, ebx)
		;		      R       T            A      NA   B   NB

	; due to the complexity of that routine, i think we'll be calling it externally rather than inlining it
	mov	r9d, ebx
	mov	r8, r14
	lea	rdx, [rdi+rcx*8]
	mov	ecx, 2
	lea	rsi, [r15+r11*8+16]
	mov	rdi, r15

	push	r11
	call	wd$asmult
	pop	r11
	
		; now: borrow = Subtract(R, R, T, N+2)
	; all of our non-callee-saves are destroyed now
	mov	ecx, r11d
	sub	ecx, ebx		; i-NB

	lea	rdi, [r13+rcx*8]	; TA+i-NB (R inside the CorrectQuotientEstimate context, C inside the Subtract context)
	mov	rsi, rdi		; "" (A inside the Subtract context)
	mov	rdx, r15		; TP (T inside the CorrectQuotientEstimate context, B inside the Subtract context)
	mov	ecx, ebx
	add	ecx, 2			; NB+2, N+2 inside the CorrectQuoitentEstimate, N inside the Subtract context

	shl	ecx, 3
	add	rdi, rcx		; all must be hanging off the end for the neg
	add	rsi, rcx
	add	rdx, rcx
	shr	ecx, 3

	; C (destination) is in rdi
	; A (leftside) is in rsi
	; B (rightside) is in rdx
	; N (count) is in ecx
	neg	rcx
	jz	.rloop_fixquot_sub1_done
	mov	rax, [rsi+rcx*8]
	sub	rax, [rdx+rcx*8]
	mov	[rdi+rcx*8], rax
calign
.rloop_fixquot_sub1:
	mov	rax, [rsi+rcx*8+8]
	sbb	rax, [rdx+rcx*8+8]
	mov	[rdi+rcx*8+8], rax
	lea	rcx, [rcx+2]
	jrcxz	.rloop_fixquot_sub1_done
	mov	rax, [rsi+rcx*8]
	sbb	rax, [rdx+rcx*8]
	mov	[rdi+rcx*8], rax
	jmp	.rloop_fixquot_sub1
calign
.rloop_fixquot_sub1_done:
	; mov	rax, 0
	; adc	rax, rax	; this is the "return" from Subtract, or in our case, word borrow =

	; so now we need R, B and N
	mov	ecx, r11d
	sub	ecx, ebx		; i-NB

	lea	rdi, [r13+rcx*8]	; TA+i-NB (R inside the CorrectQuotientEstimate context)
					; B == r14
					; N == ebx
calign
.rloop_fixquot_sub2:
	cmp	qword [rdi+rbx*8], 0	; while (R[N] ||
	jne	.rloop_fixquot_sub2_doit
	; Compare(R, B, N) >= 0
	mov	edx, ebx
	mov	r8d, ebx		; loop counter for compare
	shl	edx, 3
	sub	edx, 8			; N-1 in bytes
calign
.rloop_fixquot_sub2_compare:
	mov	rax, [rdi+rdx]
	cmp	rax, [r14+rdx]
	ja	.rloop_fixquot_sub2_doit
	jb	.rloop_next
	sub	edx, 8
	sub	r8d, 1
	jnz	.rloop_fixquot_sub2_compare
	; if we fell out of that loop, they are equal
calign
.rloop_fixquot_sub2_doit:
	; so now we need: R[N] -= Subtract(R, R, B, N);
	; rdi is still pointing at R	; C inside the Subtract context
	; B is in r14
	; N is in ebx
	mov	rsi, rdi		; "" (A inside the Subtract context)
	mov	rdx, r14		; B inside the Subtract context
	mov	ecx, ebx
	shl	ecx, 3			; count in bytes
	add	rdi, rcx
	add	rsi, rcx		; all msut be hanging off the end
	add	rdx, rcx
	shr	ecx, 3


	; C (destination) is in rdi
	; A (leftside) is in rsi
	; B (rightside) is in rdx
	; N (count) is in ecx
	clc
	neg	rcx
	jz	.rloop_fixquot_sub3_done
	mov	rax, [rsi+rcx*8]
	sub	rax, [rdx+rcx*8]
	mov	[rdi+rcx*8], rax
calign
.rloop_fixquot_sub3:
	mov	rax, [rsi+rcx*8+8]
	sbb	rax, [rdx+rcx*8+8]
	mov	[rdi+rcx*8+8], rax
	lea	rcx, [rcx+2]
	jrcxz	.rloop_fixquot_sub3_done
	mov	rax, [rsi+rcx*8]
	sbb	rax, [rdx+rcx*8]
	mov	[rdi+rcx*8], rax
	jmp	.rloop_fixquot_sub3
calign
.rloop_fixquot_sub3_done:
	mov	rsi, [rsp+8]		; Q
	mov	rax, 0
	adc	rax, rax	; this is the "return" from Subtract, or in our case, word borrow =

	mov	ecx, ebx
	shl	ecx, 3
	sub	rdi, rcx

	sub	[rdi+rbx*8], rax	; R[N] -= Subtract(R, R, B, N) from the CorrectQuotientEstimate function

	mov	rdi, [rsi+bigint_words_ofs]	; Q.bigint_words_ofs
	mov	ecx, r11d
	sub	ecx, ebx			; i-NB
	; and then: Q[1] += (++Q[0] == 0)

	add	qword [rdi+rcx*8], 1
	adc	qword [rdi+rcx*8+8], 0

	lea	rdi, [r13+rcx*8]		; restore for the next compare iteration
	jmp	.rloop_fixquot_sub2
calign
.rloop_next:
	; we blasted rdi above, restore it before we go back to the top
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+bigint_words_ofs]

	sub	r11d, 2
	jmp	.rloop
calign
.rloop_done:
	; ok well, HAHAH, that is a right-royal mess
	; so at this point:
	; rdi == Q
	; r11d == i
	; ebx == NB
	; r13 == TA
	; r14 == TB
	; r15 == TP
	; [rsp] == R (bigint), will need its bigint_words_ofs
	; [rsp+96] == BT[0]
	; [rsp+104] == BT[1]
	; [rsp+112] == shiftWords
	; [rsp+120] == shiftBits
	; [rsp+128] == T[0]
	; [rsp+136] == T[1]
	; [rsp+144] == T[2]
	; [rsp+152] == T[3]
	; rax, rcx, rdx, rsi, r8, r9, r10, r12 are free, stack from 128 upward is free too

	; CopyWords(R, TA+shiftWords, NB)
	mov	rsi, [rsp]
	mov	rdi, [rsi+bigint_words_ofs]	; R's words
	mov	r8, rdi				; save a copy of R's words
	mov	ecx, [rsp+112]
	shl	ecx, 3				; shiftWords in bytes
	add	r13, rcx			; TA+shiftWords
	mov	ecx, ebx			; NB
calign
.finalcopy:
	mov	rax, [r13]
	mov	[rdi], rax
	add	r13, 8
	add	rdi, 8
	sub	ecx, 1
	jnz	.finalcopy

	; now we have to do:
	; ShiftWordsRightByBits(R, NB, shiftBits)
	mov	rdi, r8				; R's words
	shl	ebx, 3				; NB in bytes
	add	rdi, rbx			
	sub	rdi, 8				; R[NB-1]
	; NB is still in ebx
	mov	r10d, [rsp+120]			; shiftBits
	mov	r9d, 64
	sub	r9d, r10d	; shift carry amount
	xor	edx, edx	; carry
	test	ebx, ebx
	jz	.noshift
	test	r10d, r10d
	jz	.noshift
calign
.finalshift:
	mov	ecx, r10d
	mov	rax, [rdi]
	mov	rsi, rax
	shr	rax, cl
	or	rax, rdx
	mov	[rdi], rax
	mov	ecx, r9d
	mov	rdx, rsi
	shl	rdx, cl
	sub	rdi, 8
	sub	ebx, 8
	jnz	.finalshift
	; carry leftover in rdx is discarded/ignored
calign
.noshift:
	; now we can free our scratchpad
	mov	rdi, [rsp+48]
	call	heap$free

	; and last but not least, deal with the sign of the results
	mov	rbx, [rsp]		; remainder bigint
	mov	r12, [rsp+8]		; quotient bigint
	mov	r13, [rsp+16]		; dividend bigint
	mov	r14, [rsp+24]		; divisor bigint

	cmp	dword [r13+bigint_negative_ofs], 0
	je	.final_dividend_positive

	; negate the quotient's sign
	mov	ecx, 1
	mov	eax, [r12+bigint_negative_ofs]
	sub	ecx, eax
	mov	[r12+bigint_negative_ofs], ecx
	; and, if the remainder is not zero
	mov	rdi, rbx
	call	bigint$is_zero
	test	eax, eax
	jnz	.final_dividend_positive
	mov	rdi, r12
	mov	rsi, bigint$one
	call	bigint$subtract
	; we need a temporary bigint to flip the remainder around
	mov	rdi, r14		; make a copy of the divisor
	call	bigint$new_copy
	mov	r15, rax
	mov	dword [rax+bigint_negative_ofs], 0	; absolute value only
	mov	rdi, rax
	mov	rsi, rbx
	call	bigint$subtract		; abs(divisor) - remainder
	mov	rdi, rbx
	mov	rsi, r15
	call	bigint$assign		; remainder=
	mov	rdi, r15
	call	bigint$destroy
calign
.final_dividend_positive:
	cmp	dword [r14+bigint_negative_ofs], 0
	je	.final_doreturn
	; else, negate the quotient's sign
	mov	ecx, 1
	mov	eax, [r12+bigint_negative_ofs]
	sub	ecx, eax
	mov	[r12+bigint_negative_ofs], ecx

calign
.final_doreturn:
	mov	rbx, [rsp+56]
	mov	r12, [rsp+64]
	mov	r13, [rsp+72]
	mov	r14, [rsp+80]
	mov	r15, [rsp+88]

	add	rsp, 192
	epilog
calign
.divisorbigger:
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi		; remainder bigint
	mov	r12, rsi		; quotient bigint
	mov	r13, rdx		; dividend bigint
	mov	r14, rcx		; divisor bigint
	mov	rsi, rdx
	call	bigint$assign
	mov	dword [rbx+bigint_negative_ofs], 0	; remainder's sign positive
	mov	rdi, r12
	call	bigint$clear				; quotient = 0

	; check the signs
	cmp	dword [r13+bigint_negative_ofs], 0
	je	.final_dividend_positive2
	; negate the quotient's sign
	mov	ecx, 1
	mov	eax, [r12+bigint_negative_ofs]
	sub	ecx, eax
	mov	[r12+bigint_negative_ofs], ecx
	; and, if the remainder is not zero
	mov	rdi, rbx
	call	bigint$is_zero
	test	eax, eax
	je	.final_dividend_positive2
	mov	rdi, r12
	mov	rsi, bigint$one
	call	bigint$subtract
	; we need a temporary bigint to flip the remainder around
	mov	rdi, r14		; make a copy of the divisor
	call	bigint$new_copy
	mov	r15, rax
	mov	dword [rax+bigint_negative_ofs], 0	; absolute value only
	mov	rdi, rax
	mov	rsi, rbx
	call	bigint$subtract		; abs(divisor) - remainder
	mov	rdi, rbx
	mov	rsi, r15
	call	bigint$assign		; remainder=
	mov	rdi, r15
	call	bigint$destroy
calign
.final_dividend_positive2:
	cmp	dword [r14+bigint_negative_ofs], 0
	je	.final_doreturn2
	; else, negate the quotient's sign
	mov	ecx, 1
	mov	eax, [r12+bigint_negative_ofs]
	sub	ecx, eax
	mov	[r12+bigint_negative_ofs], ecx
calign
.final_doreturn2:
	pop	r15 r14 r13 r12 rbx
	epilog

end if


if used bigint$divideword | defined include_everything
	; three arguments: rdi == bigint quotient, rsi == bigint dividend, rdx == word divisor
	; returns remainder in rax, puts quotient result into rdi
falign
bigint$divideword:
	prolog	bigint$divideword
	mov	r8, rdx
	mov	r9, rdx
	mov	rax, [rsi+bigint_words_ofs]
	mov	ecx, [rsi+bigint_size_ofs]
	sub	r8, 1
	test	rdx, r8
	jz	.pow2
	; otherwise, we need rsi's wordcount
	mov	edx, ecx
	push	rdi
	push	rsi
	shl	edx, 3
	add	rax, rdx
	push	r9
	push	rcx
	sub	rax, 8
calign
.wc:
	cmp	qword [rax], 0
	jne	.wcdone
	sub	ecx, 1
	jz	.wcdone
	sub	rax, 8
	jmp	.wc
calign
.wcdone:
	mov	esi, ecx
	call	bigint$newsize_clear
	pop	rcx r10 rsi rdi
	; so now r10 is our divisor, ecx is our wordcount
	test	ecx, ecx
	jz	.retzero

	mov	r8, [rdi+bigint_words_ofs]	; quotient
	mov	r9, [rsi+bigint_words_ofs]	; dividend
	xor	edx, edx
calign
.doit:
	mov	rax, [r9+rcx*8-8]
	div	r10
	mov	[r8+rcx*8-8], rax
	sub	ecx, 1
	jnz	.doit

	; so our remainder is in rdx
	mov	dword [rdi+bigint_negative_ofs], 0	; set
	mov	rax, rdx
	cmp	dword [rsi+bigint_negative_ofs], 0
	je	.outtahere
	mov	dword [rdi+bigint_negative_ofs], 1
	test	rdx, rdx
	jz	.outtahere
	mov	rax, r10
	sub	rax, rdx
	epilog
calign
.outtahere:
	epilog
calign
.retzero:
	xor	eax, eax
	epilog
calign
.pow2:
	push	rdi rsi rdx r8
	call	bigint$assign
	mov	rdi, [rsp+24]
	mov	rsi, [rsp+8]
	bsr	rsi, rsi
	call	bigint$shr
	mov	rdi, [rsp+16]
	mov	rcx, [rsp]
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rax, [rsi]
	and	rax, rcx
	add	rsp, 32
	epilog
end if




if used bigint$modword | defined include_everything
	; two arguments: rdi == bigint dividend, rsi == word divisor
	; returns remainder in rax, discards quotient
falign
bigint$modword:
	prolog	bigint$modword
	; otherwise, we need rdi's wordcount
	mov	r9, rsi
	mov	r10, [rdi+bigint_words_ofs]
	mov	r11d, [rdi+bigint_size_ofs]
	mov	edx, r11d
	shl	edx, 3
	add	r10, rdx
	sub	r10, 8
calign
.wc:
	cmp	qword [r10], 0
	jne	.wcdone
	sub	r11d, 1
	jz	.wcdone
	sub	r10, 8
	jmp	.wc
calign
.wcdone:
	; r11 is our wordcount
	test	r11d, r11d
	jz	.dividend_empty
	mov	r10, r9		; divisor
	mov	edx, r11d
	shl	edx, 3
	mov	r9, [rdi+bigint_words_ofs]
	add	r9, rdx
	sub	r9, 8
	xor	edx, edx
calign
.doit:
	mov	rax, [r9]
	div	r10
	sub	r9, 8
	sub	r11d, 1
	jnz	.doit
	; our remainder is in rdx
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.negdividend
	mov	rax, rdx
	epilog
calign
.negdividend:
	mov	rax, r10
	sub	rax, rdx
	epilog
calign
.dividend_empty:
	mov	rax, r10
	epilog
end if

if used bigint$inversemod | defined include_everything
	; three arguments: rdi == destination bigint, rsi == source bigint, rdx == bigint modulus
	; calculates the multiplicative inverse of rsi mod rdx into rdi
	; modulus mustn't be negative
falign
bigint$inversemod:
	prolog	bigint$inversemod
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	cmp	dword [rsi+bigint_negative_ofs], 1
	je	.sourceneg
	mov	rax, [rdx+bigint_words_ofs]
	test	qword [rax], 1
	jz	.evenmodulus
	; first up, set our destination's SIZE equal to our modulus' size
	mov	esi, [rdx+bigint_size_ofs]
	call	bigint$newsize_clear
	; one temprequired
	call	bigint$new
	mov	[rsp+24], rax
	; word-based partial inverse required
	; we need rdi to be destination's words, rsi to be temp1's words, rdx to be our source's words, rcx to be our source SIZE, r8 to be our modulus' words, and r9d to be our modulus' size
	mov	rdi, [rsp]
	mov	rsi, [rsp+24]
	mov	rdx, [rsp+8]
	mov	r8, [rsp+16]
	mov	ecx, [rdx+bigint_size_ofs]
	mov	r9d, [r8+bigint_size_ofs]
	mov	rdi, [rdi+bigint_words_ofs]
	mov	rsi, [rsi+bigint_words_ofs]
	mov	rdx, [rdx+bigint_words_ofs]
	mov	r8, [r8+bigint_words_ofs]
	call	wd$partinverse
	; now we need rdi to be destination's words, rsi to be destination's words, rdx == return from partinverse, rcx to be our modulus' words, r8d to be our modulus' size
	mov	rdi, [rsp]
	mov	rdx, rax
	mov	rcx, [rsp+16]
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rdi, rsi
	mov	r8d, [rcx+bigint_size_ofs]
	mov	rcx, [rcx+bigint_words_ofs]
	call	wd$divpow2mod
	; cleanup our temp and bailout
	mov	rdi, [rsp+24]
	call	bigint$destroy
	add	rsp, 40
	epilog
calign
.sourceneg:
	; rsi % rdx, result of which then gets inversemod into rdi
	; we need two temporaries
	call	bigint$new
	mov	[rsp+24], rax
	call	bigint$new
	mov	[rsp+32], rax
	mov	rdi, rax
	mov	rsi, [rsp+24]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	call	bigint$divide
	mov	rdi, [rsp]
	mov	rsi, [rsp+32]
	mov	rdx, [rsp+16]
	call	bigint$inversemod
	mov	rdi, [rsp+24]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	add	rsp, 40
	epilog
calign
.evenmodulus:
	mov	rax, [rsi+bigint_words_ofs]
	test	qword [rax], 1
	jz	.evenmodulus_zeroret
	mov	rdi, rdx
	call	bigint$is_zero
	test	eax, eax
	jnz	.evenmodulus_zeroret
	mov	rdi, [rsp+8]
	call	bigint$is_one
	test	eax, eax
	jnz	.evenmodulus_oneret
	call	bigint$new
	mov	[rsp+24], rax
	call	bigint$new
	mov	[rsp+32], rax
	mov	rdi, rax
	mov	rsi, [rsp+24]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+8]
	call	bigint$divide
	mov	rdi, [rsp+24]
	mov	rsi, [rsp+32]
	mov	rdx, [rsp+8]
	call	bigint$inversemod
	mov	rdi, [rsp+24]
	call	bigint$is_zero
	test	eax, eax
	jz	.evenmodulus_morecomplicated
	; otherwise, our original modulus % source's inversemod(source) returned zero, so we need to return zero as well
	mov	rdi, [rsp]
	mov	esi, 0
	call	bigint$set_unsigned
	mov	rdi, [rsp+24]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	add	rsp, 40
	epilog
calign
.evenmodulus_morecomplicated:
	; so the result of our original modulus % source's inversemod(source) is sitting in rsp+24
	; we need to calculate the original modulus * (source - rsp+24) + 1, divided by the original source (quotient this time)
	mov	rdi, [rsp+32]
	mov	rsi, [rsp+8]
	call	bigint$assign
	mov	rdi, [rsp+32]
	mov	rsi, [rsp+24]
	call	bigint$subtract
	mov	rdi, [rsp+24]
	mov	rsi, [rsp+16]
	mov	rdx, [rsp+32]
	call	bigint$multiply_into
	mov	rdi, [rsp+24]
	mov	rsi, bigint$one
	call	bigint$add
	mov	rdi, [rsp+32]
	mov	rsi, [rsp]
	mov	rdx, [rsp+24]
	mov	rcx, [rsp+8]
	call	bigint$divide
	; cleanup our temps and bailout
	mov	rdi, [rsp+24]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	add	rsp, 40
	epilog
calign
.evenmodulus_zeroret:
	mov	rdi, [rsp]
	mov	esi, 0
	call	bigint$set_unsigned
	add	rsp, 40
	epilog
calign
.evenmodulus_oneret:
	mov	rdi, [rsp]
	mov	esi, 1
	call	bigint$set_unsigned
	add	rsp, 40
	epilog

end if

if used bigint$inversemodword | defined include_everything
	; two arguments: rdi == source bigint, rsi == word mod
	; returns word in rax
falign
bigint$inversemodword:
	prolog	bigint$inversemodword
	push	rsi
	call	bigint$modword
	mov	r8, [rsp]	; g0 = mod
	mov	r9, rax		; g1 = source % mod
	xor	r10d, r10d	; v0 = 0
	mov	r11d, 1		; v1 = 1
calign
.loop:
	test	r9, r9
	jz	.zeroret
	cmp	r9, 1
	je	.return_case1
	xor	edx, edx
	mov	rax, r8
	div	r9
	mov	rcx, rax	; y = g0/g1
	mov	r8, rdx		; g0 = g0 % g1
	mov	rax, rcx
	mul	r11
	add	r10, rax
	test	r8, r8
	jz	.zeroret
	cmp	r8, 1
	je	.return_case2
	xor	edx, edx
	mov	rax, r9
	div	r8
	mov	rcx, rax	; y = g1/g0
	mov	r9, rdx		; g1 = g1 % g0
	mul	r10
	add	r11, rax
	jmp	.loop
calign
.return_case1:
	mov	rax, r11
	add	rsp, 8
	epilog
calign
.return_case2:
	pop	rax
	sub	rax, r10
	epilog
calign
.zeroret:
	xor	eax, eax
	add	rsp, 8
	epilog

end if

if used bigint$jacobi | defined include_everything
	; two arguments: rdi == bigint a, rsi == bigint b (prime)
	; returns eax == 0 if a%b == 0, 1 if a is quadratic residue mod b, -1 otherwise
	; NOTE: rather expensive in that we need 3 temporaries
falign
bigint$jacobi:
	prolog	bigint$jacobi
	push	rbx r12 r13 r14 r15
	mov	r12, rsi
	call	bigint$new_copy
	mov	rbx, rax		; a
	mov	rdi, r12
	call	bigint$new_copy
	mov	r12, rax		; b
	call	bigint$new
	mov	r13, rax		; temp
	mov	rdi, rbx
	mov	rsi, r12		; a = a % b
	call	bigint$modby
	mov	r14d, 1
calign
.looptest:
	; if a is negative, doit, if a is positive and is nonzero, doit
	xor	r15d, r15d
	cmp	dword [rbx+bigint_negative_ofs], 1
	je	.doit
	mov	rdi, rbx
	call	bigint$is_zero
	test	eax, eax
	jz	.doit
	; else, return
	mov	rdi, r12
	call	bigint$is_one
	xor	ecx, ecx
	test	eax, eax
	cmovz	r14d, ecx
	mov	rdi, r13
	call	bigint$destroy
	mov	rdi, r12
	call	bigint$destroy
	mov	rdi, rbx
	call	bigint$destroy
	mov	eax, r14d
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.doit:
	mov	rdi, rbx
	mov	esi, r15d
	call	bigint$bitget
	test	eax, eax
	jnz	.gotit
	add	r15d, 1
	jmp	.doit
calign
.gotit:
	mov	rdi, rbx
	mov	esi, r15d
	call	bigint$shr

	test	r15d, 1
	jz	.modfours
	mov	rdi, r12		; b
	mov	esi, 8
	call	bigint$modword
	cmp	rax, 3
	je	.negres1
	cmp	rax, 5
	je	.negres1
calign
.modfours:
	mov	rdi, rbx
	mov	esi, 4
	call	bigint$modword
	cmp	rax, 3
	jne	.swapandgo
	mov	rdi, r12
	mov	esi, 4
	call	bigint$modword
	cmp	rax, 3
	je	.negres2
calign
.swapandgo:
	mov	rdi, r13		; temp
	mov	rsi, rbx		; a
	call	bigint$assign
	mov	rdi, rbx
	mov	rsi, r12
	call	bigint$assign
	mov	rdi, r12
	mov	rsi, r13
	call	bigint$assign
	mov	rdi, rbx
	mov	rsi, r12
	call	bigint$modby
	jmp	.looptest
calign
.negres1:
	neg	r14d
	jmp	.modfours
calign
.negres2:
	neg	r14d
	jmp	.swapandgo

end if
	


if used bigint$gcd | defined include_everything
	; four arguments: rdi == destination/result bigint, rsi == scratch bigint, rdx == bigint, rcx == bigint
	; assumes rdx == some arbitrary number we are checking against rcx, and rcx is ODD (our prime)
falign
bigint$gcd:
	prolog	bigint$gcd
	sub	rsp, 64
	mov	[rsp], rdx
	mov	[rsp+8], rcx
	mov	[rsp+24], rdi
	mov	[rsp+16], rsi
	mov	rsi, rcx
	call	bigint$assign

	mov	rdi, [rsp+16]
	mov	rsi, [rsp]
	call	bigint$assign

	mov	rdi, [rsp+16]
	call	bigint$is_zero
	test	eax, eax
	jnz	.zeroret
	mov	rdi, [rsp+16]
	call	bigint$is_one
	test	eax, eax
	jnz	.oneret
	mov	rdi, [rsp+24]
	call	bigint$is_zero
	test	eax, eax
	jnz	.zeroret
	mov	rdi, [rsp+24]
	call	bigint$is_one
	xor	ecx, ecx
	test	eax, eax
	jnz	.oneret
	mov	rdi, [rsp+16]	;x
	mov	rsi, [rsp+24]	;y

	; figure out the initial minimum shift amount
	mov	r8, [rdi+bigint_words_ofs]
	xor	ecx, ecx
calign
.minlzx:
	mov	rax, [r8]
	add	r8, 8
	test	rax, rax
	jz	.minlzx_nextword
	; else, this word contains a nonzero value
	bsf	rdx, rax
	add	ecx, edx
	mov	r8, [rsi+bigint_words_ofs]
	xor	edx, edx
	jmp	.minlzy
calign
.minlzx_nextword:
	add	ecx, 64
	jmp	.minlzx
calign
.minlzy:
	mov	rax, [r8]
	add	r8, 8
	test	rax, rax
	jz	.minlzy_nextword
	; else, this word contains a nonzero value
	bsf	r9, rax
	add	edx, r9d
	jmp	.doinitialshift
calign
.minlzy_nextword:
	add	edx, 64
	jmp	.minlzy
calign
.doinitialshift:
	; x's wordcount is in ecx, y's in edx
	cmp	ecx, edx
	cmova	ecx, edx
	; store this value
	mov	[rsp+32], ecx		; shift amount
	mov	esi, ecx
	call	bigint$shr
	mov	rdi, [rsp+24]		; y
	mov	esi, [rsp+32]
	call	bigint$shr

	mov	rdi, [rsp+16]		; x
	mov	rsi, [rsp+24]		; y
calign
.mainloop:
	mov	rdi, [rsp+16]	;x
	call	bigint$is_zero
	mov	rdi, [rsp+16]	;x
	test	eax, eax
	jnz	.doreturn

	; otherwise, figure out x's new low zero bit count
	mov	r8, [rdi+bigint_words_ofs]
	xor	ecx, ecx
calign
.xdoit2:
	mov	rax, [r8]
	add	r8, 8
	test	rax, rax
	jz	.xnextword2
	; else, this word contains a nonzero value
	bsf	rdx, rax
	add	ecx, edx
	jmp	.doxshr
calign
.xnextword2:
	add	ecx, 64
	jmp	.xdoit2
calign
.doxshr:
	mov	esi, ecx
	call	bigint$shr
	mov	rdi, [rsp+24]	;y

	; and now, do the same for y's new low zero bit count
	mov	r9, [rdi+bigint_words_ofs]
	xor	ecx, ecx
calign
.ydoit2:
	mov	rax, [r9]
	add	r9, 8
	test	rax, rax
	jz	.ynextword2
	; else, this word contains a nonzero value
	bsf	rdx, rax
	add	ecx, edx
	jmp	.doyshr
calign
.ynextword2:
	add	ecx, 64
	jmp	.ydoit2
calign
.doyshr:
	mov	esi, ecx
	call	bigint$shr
	mov	rdi, [rsp+16]	;x
	mov	rsi, [rsp+24]	;y
	call	bigint$compare_unsigned
	cmp	eax, 0
	jge	.xge
	mov	rdi, [rsp+24]	;y
	mov	rsi, [rsp+16]	;x
	call	bigint$subtract_unsigned
	mov	rdi, [rsp+24]	;y
	mov	esi, 1
	call	bigint$shr
	jmp	.mainloop
calign
.xge:
	mov	rdi, [rsp+16]	;x
	mov	rsi, [rsp+24]	;y
	call	bigint$subtract_unsigned
	mov	rdi, [rsp+16]	;x
	mov	esi, 1
	call	bigint$shr
	jmp	.mainloop
calign
.doreturn:
	; return sitting in [rsp+24] (our original destination) is valid
	mov	rdi, [rsp+24]	; y
	mov	esi, [rsp+32]	; shift amount
	call	bigint$shl
	add	rsp, 64
	epilog
calign
.zeroret:
	mov	rdi, [rsp+24]
	call	bigint$clear
	add	rsp, 64
	epilog
calign
.oneret:
	mov	rdi, [rsp+24]
	mov	esi, 1
	call	bigint$set_unsigned
	add	rsp, 64
	epilog

end if


if used bigint$lcm | defined include_everything
	; four arguments: rdi == destination/result bigint, rsi == scratch bigint, rdx == bigint, rcx == bigint
	; assumes rdx == some arbitrary number we are checking against rcx, and rcx is ODD (our prime)
falign
bigint$lcm:
	prolog	bigint$lcm
	; calculate rdx/gcd(rdx,rcx)*rcx
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	; swap rdi/rsi so that the result of the gcd ends up in our scratch
	xchg	rdi, rsi
	call	bigint$gcd
	; so now, our scratch in rsp+8 has our gcd
	mov	rdi, [rsp]	; our destination
	mov	rsi, [rsp+16]	; original rdx
	call	bigint$assign
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]	; our gcd
	call	bigint$divby
	; so now just multiply it by the original rcx
	mov	rdi, [rsp]
	mov	rsi, [rsp+24]	
	call	bigint$multiply
	add	rsp, 32
	epilog

end if




if used bigint$divby | defined include_everything
	; two arguments: rdi == source/destination bigint, rsi == divisor
	; discards remainder, sticks bigint result into rdi
falign
bigint$divby:
	prolog	bigint$divby
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	bigint$new_copy
	mov	[rsp+16], rax
	call	bigint$new
	mov	[rsp+24], rax
	mov	rdi, rax	; remainder
	mov	rsi, [rsp]	; quotient
	mov	rdx, [rsp+16]	; dividend
	mov	rcx, [rsp+8]	; divisor
	call	bigint$divide
	; discard our copy and remainder
	mov	rdi, [rsp+16]
	call	bigint$destroy
	mov	rdi, [rsp+24]
	call	bigint$destroy
	add	rsp, 32
	epilog

end if

if used bigint$modby | defined include_everything
	; two arguments: rdi == source/destination bigint, rsi == divisor
	; discards result, sticks remainder into rdi
falign
bigint$modby:
	prolog	bigint$modby
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	bigint$new_copy
	mov	[rsp+16], rax
	call	bigint$new
	mov	[rsp+24], rax
	mov	rdi, [rsp]	; remainder
	mov	rsi, [rsp+24]	; quotient
	mov	rdx, [rsp+16]	; dividend
	mov	rcx, [rsp+8]	; divisor
	call	bigint$divide
	; discard our copy and quotient
	mov	rdi, [rsp+16]
	call	bigint$destroy
	mov	rdi, [rsp+24]
	call	bigint$destroy
	add	rsp, 32
	epilog

end if

if used bigint$divbyword | defined include_everything
	; two arguments: rdi == source/destination bigint, rsi == WORD divisor (not bigint object)
	; discards remainder, sticks result into rdi
falign
bigint$divbyword:
	prolog	bigint$divbyword
	push	rdi rsi
	call	bigint$new_copy
	mov	rdi, rax
	mov	rsi, [rsp+8]
	mov	rdx, [rsp]
	mov	[rsp], rax
	call	bigint$divideword
	mov	rdi, [rsp+8]
	mov	rsi, [rsp]
	call	bigint$assign
	mov	rdi, [rsp]
	call	bigint$destroy
	add	rsp, 16
	epilog
end if

if used bigint$modbyword | defined include_everything
	; two arguments: rdi == source/destination bigint, rsi == WORD divisor (not bigint object)
	; discards result, sticks remainder into rdi
falign
bigint$modbyword:
	prolog	bigint$modbyword
	push	rdi
	call	bigint$modword
	pop	rdi
	mov	rsi, rax
	call	bigint$set_unsigned
	epilog
end if


; NOTE Re: prime sieves... we have two versions that basically function identically
; the first of which, primesieve$ relies on the selection increment to be precisely 2
; which lets us do lots of shl instead of multiplies, resulting in overall better/cleaner goods
; the second of which, primesievemod$ relies on an arbitrary step, and is used for dsa
; parameter generation ... it uses way more grunt to do its deed due to the additional
; requirements of multiplication instead of shifts, as well as the lack of the fixed
; inverse mod table

primesieve_first_ofs = 0
primesieve_last_ofs = 8
primesieve_next_ofs = 16
primesieve_temp_ofs = 24
primesieve_size_ofs = 32
primesieve_state_ofs = 40

primesieve_size = primesieve_state_ofs + 131072



; analsievedebugging = 1




if used primesieve$new | defined include_everything
	; single arguments: rdi == first
	; returns a new primesieve object in rax
falign
primesieve$new:
	prolog	primesieve$new
	push	r12
	mov	r12, rdi
	mov	edi, primesieve_size
	call	heap$alloc_clear

	mov	rdi, r12		; rdi == first
	mov	r12, rax		; our final return
	call	bigint$new_copy
	mov	[r12+primesieve_first_ofs], rax
	mov	rdi, rax
	call	bigint$new_copy		; make a second copy of first
	mov	[r12+primesieve_last_ofs], rax
	call	bigint$new
	mov	[r12+primesieve_temp_ofs], rax

	mov	rdi, [r12+primesieve_first_ofs]
	call	bigint$lg2
	mov	edx, 32768
	mov	ecx, eax
	shr	ecx, 1
	add	ecx, 1
	cmp	ecx, edx
	cmova	ecx, edx
	mov	[r12+primesieve_size_ofs], ecx

	mov	rdi, [r12+primesieve_temp_ofs]
	mov	esi, eax
	call	bigint$set_unsigned

	mov	rdi, [r12+primesieve_last_ofs]
	mov	rsi, [r12+primesieve_temp_ofs]
	call	bigint$add_unsigned

if defined analsievedebugging
	; sieve debugging:
	; mov	rdi, .firststr
	; mov	rdx, [r12+primesieve_first_ofs]
	; mov	rsi, [rdx+bigint_words_ofs]
	; call	string$hexdecode
; 
	; mov	rdi, .laststr
	; mov	rdx, [r12+primesieve_last_ofs]
	; mov	rsi, [rdx+bigint_words_ofs]
	; call	string$hexdecode


	mov	rdi, .initstr
	call	string$to_stdoutln

	mov	rdi, [r12+primesieve_first_ofs]
	call	bigint$debug
	mov	rdi, [r12+primesieve_last_ofs]
	call	bigint$debug

	mov	rdi, .initstr2
	call	string$to_stdoutln
	
	breakpoint

	; end sieve debugging
end if


	mov	rdi, r12
	call	primesieve$restart
	mov	rax, r12
	pop	r12
	epilog

if defined analsievedebugging
cleartext .initstr, 'primesieve debug init:'
cleartext .initstr2, 'primesieve restart...'
cleartext .firststr, 'b1df36ef9c6daa9fef1e10c9af8477cbd6605781910563e1'
cleartext .laststr, '71e036ef9c6daa9fef1e10c9af8477cbd6605781910563e1'
end if


end if



if used primesieve$restart | defined include_everything
	; single argument in rdi: primesieve object
falign
primesieve$restart:
	prolog	primesieve$restart
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, [rdi+primesieve_first_ofs]
	mov	r13, bigint_primetable
	mov	r14, bigint_invmodtable
	mov	r15d, 3511
	mov	edx, [rdi+primesieve_size_ofs]
	shl	edx, 2
	lea	rdi, [rdi+primesieve_state_ofs]
	xor	esi, esi
	call	memset32
calign
.loop:
	cmp	word [r14], 0
	je	.skip
	mov	rdi, [rbx+primesieve_temp_ofs]
	mov	rsi, [rbx+primesieve_first_ofs]
	movzx	edx, word [r13]
	call	bigint$divideword
	movzx	ecx, word [r13]
	; result is now in rax/eax
	movzx	esi, word [r13]
	sub	esi, eax
	movzx	eax, word [r14]
	mul	rsi		; 64 bit result now in rax
	movzx	esi, word [r13]
	div	rsi
	lea	rdi, [rbx+primesieve_state_ofs]
calign
.innerloop:
	mov	dword [rdi+rdx*4], 1
	add	edx, esi
	cmp	edx, dword [rbx+primesieve_size_ofs]
	jb	.innerloop
	add	r13, 2
	add	r14, 2
	sub	r15d, 1
	jnz	.loop
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.skip:
	add	r13, 2
	add	r14, 2
	sub	r15d, 1
	jnz	.loop
	pop	r15 r14 r13 r12 rbx
	epilog
	

end if

if used primesieve$destroy | defined include_everything
	; single argument in rdi: primesieve object to destroy
falign
primesieve$destroy:
	prolog	primesieve$destroy
	push	rbx
	mov	rbx, rdi	; hold our object here
	mov	rdi, [rbx+primesieve_first_ofs]
	call	bigint$destroy

	mov	rdi, [rbx+primesieve_last_ofs]
	call	bigint$destroy

	mov	rdi, [rbx+primesieve_temp_ofs]
	call	bigint$destroy

	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog

end if

if used primesieve$next | defined include_everything
	; two arguments: rdi == primesieve object, rsi == destination bigint
	; returns bool whether we did or not if we need to be reset with new goods
falign
primesieve$next:
	prolog	primesieve$next
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	lea	rsi, [rdi+primesieve_state_ofs]
	mov	edx, [rdi+primesieve_next_ofs]
	cmp	edx, [rdi+primesieve_size_ofs]
	jae	.overrun
calign
.search:
	cmp	dword [rsi+rdx*4], 0
	je	.go
	add	edx, 1
	cmp	edx, [rdi+primesieve_size_ofs]
	jae	.overrun
	jmp	.search
calign
.go:
	; we need to set our destination to our first value + edx << 1
	mov	rdi, [rbx+primesieve_temp_ofs]
	mov	esi, edx
	shl	esi, 1
	add	edx, 1
	mov	[rbx+primesieve_next_ofs], edx
	call	bigint$set_unsigned
	mov	rdi, r12
	mov	rsi, [rbx+primesieve_first_ofs]
	call	bigint$assign
	mov	rdi, r12
	mov	rsi, [rbx+primesieve_temp_ofs]
	call	bigint$add_unsigned

if defined analsievedebugging
	mov	rdi, .candidate
	call	string$to_stdout
	mov	rdi, r12
	call	bigint$debug
	breakpoint

end if

	pop	r12 rbx
	mov	eax, 1
	epilog
if defined analsievedebugging
cleartext .candidate, 'candidate: '
end if
calign
.overrun:
	mov	rdi, [rbx+primesieve_temp_ofs]
	mov	esi, [rbx+primesieve_size_ofs]
	shl	esi, 1
	call	bigint$set_unsigned
	mov	rdi, [rbx+primesieve_first_ofs]
	mov	rsi, [rbx+primesieve_temp_ofs]
	call	bigint$add_unsigned
	mov	rdi, [rbx+primesieve_first_ofs]
	mov	rsi, [rbx+primesieve_last_ofs]
	call	bigint$compare_unsigned
	cmp	eax, 1
	je	.nodeal
	mov	dword [rbx+primesieve_next_ofs], 0
	mov	rdi, rbx
	call	primesieve$restart
	lea	rsi, [rbx+primesieve_state_ofs]
	mov	edx, [rbx+primesieve_next_ofs]
	jmp	.search
	epilog
calign
.nodeal:
	pop	r12 rbx
	xor	eax, eax
	epilog

end if


; ---- primesievemod goods, requires different step increment (than 2 for the normal one)
; also does WAY more calculations than the above (due to lack of fixed inverse mod table)

primesievemod_first_ofs = 0
primesievemod_last_ofs = 8
primesievemod_next_ofs = 16
primesievemod_temp_ofs = 24
primesievemod_size_ofs = 32
primesievemod_step_ofs = 40
primesievemod_state_ofs = 48

primesievemod_size = primesievemod_state_ofs + 131072


if used primesievemod$new | defined include_everything
	; two arguments: rdi == first, rsi == increment step
	; returns a new primesievemod object in rax
falign
primesievemod$new:
	prolog	primesievemod$new
	push	r12 r13
	mov	r12, rdi
	mov	r13, rsi
	mov	edi, primesievemod_size
	call	heap$alloc_clear

	mov	rdi, r12		; rdi == first
	mov	r12, rax		; our final return
	call	bigint$new_copy
	mov	[r12+primesievemod_first_ofs], rax
	mov	rdi, rax
	call	bigint$new_copy		; make a second copy of first
	mov	[r12+primesievemod_last_ofs], rax

	mov	rdi, r13
	call	bigint$new_copy		; step
	mov	[r12+primesievemod_step_ofs], rax

	call	bigint$new
	mov	[r12+primesievemod_temp_ofs], rax

	mov	rdi, [r12+primesievemod_first_ofs]
	call	bigint$lg2

	; so our "search interval" needs to be our lg2 of the first * mod
	mov	rdi, [r12+primesievemod_last_ofs]
	mov	esi, eax
	call	bigint$set_unsigned
	mov	rdi, [r12+primesievemod_last_ofs]
	mov	rsi, [r12+primesievemod_step_ofs]
	call	bigint$multiply
	mov	rdi, [r12+primesievemod_last_ofs]
	mov	rsi, [r12+primesievemod_first_ofs]
	call	bigint$add
	; so we need (last - first) / step + 1
	mov	rdi, [r12+primesievemod_temp_ofs]
	mov	rsi, [r12+primesievemod_last_ofs]
	call	bigint$assign
	mov	rdi, [r12+primesievemod_temp_ofs]
	mov	rsi, [r12+primesievemod_first_ofs]
	call	bigint$subtract
	mov	rdi, [r12+primesievemod_temp_ofs]
	mov	rsi, [r12+primesievemod_step_ofs]
	call	bigint$divby
	
	; and add one to it
	mov	rdi, [r12+primesievemod_temp_ofs]
	mov	rsi, bigint$one
	call	bigint$add
	; now get that value as a long into rax
	mov	rdi, [r12+primesievemod_temp_ofs]
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rax, [rsi]

	mov	edx, 32768
	cmp	rdx, rax
	cmova	rdx, rax

	mov	[r12+primesievemod_size_ofs], edx

	mov	rdi, r12
	call	primesievemod$restart
	mov	rax, r12

	pop	r13 r12
	epilog

end if



if used primesievemod$restart | defined include_everything
	; single argument in rdi: primesievemod object

falign
primesievemod$restart:
	prolog	primesievemod$restart
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, [rdi+primesievemod_first_ofs]
	mov	r13, bigint_primetable
	mov	r14, [rdi+primesievemod_step_ofs]
	mov	r15d, 3511
	mov	edx, [rdi+primesievemod_size_ofs]
	shl	edx, 2
	lea	rdi, [rdi+primesievemod_state_ofs]
	xor	esi, esi
	call	memset32
calign
.loop:
	mov	rdi, r14
	movzx	esi, word [r13]
	call	bigint$inversemodword
	test	rax, rax
	jz	.skip
	push	rax

	mov	rdi, [rbx+primesievemod_temp_ofs]
	mov	rsi, [rbx+primesievemod_first_ofs]
	movzx	edx, word [r13]
	call	bigint$divideword
	movzx	ecx, word [r13]
	; result is now in rax/eax
	movzx	esi, word [r13]
	sub	esi, eax
	pop	rax
	mul	rsi		; 64 bit result now in rax
	movzx	esi, word [r13]
	div	rsi
	lea	rdi, [rbx+primesievemod_state_ofs]
calign
.innerloop:
	mov	dword [rdi+rdx*4], 1
	add	edx, esi
	cmp	edx, dword [rbx+primesievemod_size_ofs]
	jb	.innerloop
	add	r13, 2
	sub	r15d, 1
	jnz	.loop
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.skip:
	add	r13, 2
	sub	r15d, 1
	jnz	.loop
	pop	r15 r14 r13 r12 rbx
	epilog

end if




if used primesievemod$destroy | defined include_everything
	; single argument in rdi: primesieve object to destroy
falign
primesievemod$destroy:
	prolog	primesievemod$destroy
	push	rbx
	mov	rbx, rdi	; hold our object here
	mov	rdi, [rbx+primesievemod_first_ofs]
	call	bigint$destroy

	mov	rdi, [rbx+primesievemod_last_ofs]
	call	bigint$destroy

	mov	rdi, [rbx+primesievemod_step_ofs]
	call	bigint$destroy

	mov	rdi, [rbx+primesievemod_temp_ofs]
	call	bigint$destroy

	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog

end if

if used primesievemod$next | defined include_everything
	; two arguments: rdi == primesieve object, rsi == destination bigint
	; returns bool whether we did or not if we need to be reset with new goods
falign
primesievemod$next:
	prolog	primesievemod$next
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	lea	rsi, [rdi+primesievemod_state_ofs]
	mov	edx, [rdi+primesievemod_next_ofs]
	cmp	edx, [rdi+primesievemod_size_ofs]
	jae	.overrun
calign
.search:
	cmp	dword [rsi+rdx*4], 0
	je	.go
	add	edx, 1
	cmp	edx, [rdi+primesievemod_size_ofs]
	jae	.overrun
	jmp	.search
calign
.go:
	; we need to set our destination to our first value + edx * step, and increment edx/next by one
	mov	rdi, [rbx+primesievemod_temp_ofs]
	mov	esi, edx
	add	edx, 1
	mov	[rbx+primesievemod_next_ofs], edx
	call	bigint$set_unsigned

	mov	rdi, [rbx+primesievemod_temp_ofs]
	mov	rsi, [rbx+primesievemod_step_ofs]
	call	bigint$multiply

	mov	rdi, r12
	mov	rsi, [rbx+primesievemod_first_ofs]
	call	bigint$assign
	mov	rdi, r12
	mov	rsi, [rbx+primesievemod_temp_ofs]
	call	bigint$add_unsigned

	pop	r12 rbx
	mov	eax, 1
	epilog
calign
.overrun:
	mov	rdi, [rbx+primesievemod_temp_ofs]
	mov	esi, [rbx+primesievemod_size_ofs]
	call	bigint$set_unsigned
	mov	rdi, [rbx+primesievemod_temp_ofs]
	mov	rsi, [rbx+primesievemod_step_ofs]
	call	bigint$multiply
	mov	rdi, [rbx+primesievemod_first_ofs]
	mov	rsi, [rbx+primesievemod_temp_ofs]
	call	bigint$add_unsigned
	mov	rdi, [rbx+primesievemod_first_ofs]
	mov	rsi, [rbx+primesievemod_last_ofs]
	call	bigint$compare_unsigned
	cmp	eax, 1
	je	.nodeal
	mov	dword [rbx+primesievemod_next_ofs], 0
	mov	rdi, rbx
	call	primesievemod$restart
	lea	rsi, [rbx+primesievemod_state_ofs]
	mov	edx, [rbx+primesievemod_next_ofs]
	jmp	.search
	epilog
calign
.nodeal:
	pop	r12 rbx
	xor	eax, eax
	epilog

end if


if used bigint$new_prime | defined include_everything
	; single argument in edi: how many bits the prime number should be
	; bits are rounded up to the nearest 16, and if that equals 16, just grabs a random one from the bigint_primetable
falign
bigint$new_prime:
	prolog	bigint$new_prime
	add	edi, 0xf
	and	edi, not 0xf
	cmp	edi, 16
	je	.smallone
	push	rbx r12 r13 r14 r15
	mov	r12d, edi
	mov	r13d, edi
	mov	edi, 2
	call	bigint$new_unsigned
	shr	r13d, 1
	mov	r15, rax
	call	bigint$new
	mov	rbx, rax
	mov	ecx, 6540
	cmp	r13d, ecx
	cmova	r13d, ecx
	mov	edx, r13d
	shl	edx, 1
	sub	rsp, rdx
calign
.outerloop:
	mov	rdi, rbx		; our return
	mov	esi, r12d		; bitcount
	call	bigint$set_random
	mov	rdi, rbx
	mov	rsi, [rdi+bigint_words_ofs]
	or	dword [rsi], 1
	mov	esi, r12d
	sub	esi, 1
	call	bigint$bitset
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 2
	call	bigint$bitset
	; so now we have a random number in rbx with lowest bit and top two bits set
	; rsp has lotsa room to figure out a decent way to weed them out
	xor	r14d, r14d
calign
.outersetup:
	; modword used to take rdi (dividend), and rsi == word divisor, and return the % result in rax
	; our divide requires a place to put the quotient though
	mov	rdi, rbx		; our random number of the right size
	movzx	esi, word [r14*2+bigint_primetable]
	call	bigint$modword
	mov	word [rsp+r14*2], ax
	add	r14d, 1
	cmp	r14d, r13d
	jne	.outersetup
	mov	rdi, r15
	mov	esi, 2
	call	bigint$set_unsigned
calign
.innerloop:
	mov	rdi, rbx
	mov	rsi, r15
	call	bigint$add		; our random number + 2
	; sanity check to make sure we haven't exceeded our desired bitcount
	mov	rdi, rbx
	call	bigint$bitcount
	cmp	rax, r12
	ja	.outerloop		; go back and do it again with more random goods
	mov	r14d, 1
	xor	r8d, r8d
	mov	r9d, r13d
	xor	r10d, r10d
calign
.innerupdate:
	xor	edx, edx
	movzx	ecx, word [r8*2+bigint_primetable]
	movzx	eax, word [rsp+r8*2]
	add	ax, 2
	div	cx
	mov	[rsp+r8*2], dx
	add	r8d, 1
	test	dx, dx
	cmovz	r14d, r10d
	sub	r9d, 1
	jnz	.innerupdate
	test	r14d, r14d
	jz	.innerloop
	mov	rdi, rbx
	call	bigint$isprime
	test	eax, eax
	jz	.innerloop
	; otherwise, all good
	mov	rdi, r15
	call	bigint$destroy
	mov	rax, rbx

	mov	edx, r13d
	shl	edx, 1
	add	rsp, rdx

	pop	r15 r14 r13 r12 rbx
	epilog
calign
.smallone:
	call	bigint$new
	push	rax
	xor	edi, edi
	mov	esi, 6540
	call	rng$int
	movzx	edx, word [rax*2+bigint_primetable]
	pop	rax
	mov	rdi, [rax+bigint_words_ofs]
	mov	[rdi], edx
	epilog

end if



if used bigint$random_prime | defined include_everything
	; two arguments: rdi == bigint to set, esi == how many bits the prime should be
	; bits are rounded up to the nearest 16, and if that equals 16, just grabs a random one from the bigint_primetable
falign
bigint$random_prime:
	prolog	bigint$random_prime
	add	esi, 0xf
	and	esi, not 0xf
	cmp	esi, 16
	je	.smallone
	push	rbx r12 r13 r14
	mov	r12d, esi
	mov	rbx, rdi
	call	bigint$set_random
	mov	rdi, [rbx+bigint_words_ofs]
	or	dword [rdi], 1

	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 1
	call	bigint$bitset
	
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 2
	call	bigint$bitset

	mov	rdi, rbx
	call	primesieve$new
	mov	r14, rax		; r14 == our primesieve object
calign
.toploop:
	mov	rdi, r14		; our primesieve object
	mov	rsi, rbx
	call	primesieve$next
	test	eax, eax		; if it failed, we need to re-randomize and start again
	jz	.tryagain
	mov	rdi, rbx
	call	bigint$isprime2
	test	eax, eax
	jz	.toploop		; get another one
	; otherwise, we are good
	mov	rdi, r14
	call	primesieve$destroy
	; mov	rax, rbx
	pop	r14 r13 r12 rbx
	epilog
calign
.tryagain:
	mov	rdi, rbx
	mov	esi, r12d
	call	bigint$set_random

	mov	rdi, [rbx+bigint_words_ofs]
	or	dword [rdi], 1
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 1
	call	bigint$bitset
	
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 2
	call	bigint$bitset


	mov	rdi, r14
	call	primesieve$destroy
	mov	rdi, rbx
	call	primesieve$new
	mov	r14, rax
	jmp	.toploop
calign
.smallone:
	push	rdi
	xor	edi, edi
	mov	esi, 6540
	call	rng$int
	movzx	esi, word [rax*2+bigint_primetable]
	pop	rdi
	call	bigint$set_unsigned
	epilog

end if



if used bigint$new_prime2 | defined include_everything
	; single argument in edi: how many bits the prime number should be
	; bits are rounded up to the nearest 16, and if that equals 16, just grabs a random one from the bigint_primetable
falign
bigint$new_prime2:
	prolog	bigint$new_prime2
	add	edi, 0xf
	and	edi, not 0xf
	cmp	edi, 16
	je	.smallone
	push	rbx r12 r13 r14
	mov	r12d, edi
	call	bigint$new_random
	mov	rbx, rax		; rbx == our final return

	mov	rdi, [rbx+bigint_words_ofs]
	or	dword [rdi], 1

	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 1
	call	bigint$bitset
	
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 2
	call	bigint$bitset

	mov	rdi, rbx
	call	primesieve$new
	mov	r14, rax		; r14 == our primesieve object
calign
.toploop:
	mov	rdi, r14		; our primesieve object
	mov	rsi, rbx
	call	primesieve$next
	test	eax, eax		; if it failed, we need to re-randomize and start again
	jz	.tryagain
	mov	rdi, rbx
	call	bigint$isprime2
	test	eax, eax
	jz	.toploop		; get another one
	; otherwise, we are good
	mov	rdi, r14
	call	primesieve$destroy
	mov	rax, rbx
	pop	r14 r13 r12 rbx
	epilog
calign
.tryagain:
	mov	rdi, rbx
	mov	esi, r12d
	call	bigint$set_random

	mov	rdi, [rbx+bigint_words_ofs]
	or	dword [rdi], 1
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 1
	call	bigint$bitset
	
	mov	rdi, rbx
	mov	esi, r12d
	sub	esi, 2
	call	bigint$bitset


	mov	rdi, r14
	call	primesieve$destroy
	mov	rdi, rbx
	call	primesieve$new
	mov	r14, rax
	jmp	.toploop
calign
.smallone:
	call	bigint$new
	push	rax
	xor	edi, edi
	mov	esi, 6540
	call	rng$int
	movzx	edx, word [rax*2+bigint_primetable]
	pop	rax
	mov	rdi, [rax+bigint_words_ofs]
	mov	[rdi], edx
	epilog

end if

if used bigint$verify_dsa_params | defined include_everything
	; three arguments: rdi == p, rsi == q, rdx == g
	; returns bool in eax as to whether or not they are valid
falign
bigint$verify_dsa_params:
	prolog	bigint$verify_dsa_params
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx

	; notes: and for public key validation, 0 < y < p, and for private key validation, 0 < x < q, g ** x mod p == y

	call	bigint$isprime2
	test	eax, eax
	jz	.badprimes
	mov	rdi, r12
	call	bigint$isprime2
	test	eax, eax
	jz	.badprimes
	
	; further, p-1 % q must be zero
	mov	rdi, rbx
	call	bigint$new_copy
	mov	r14, rax
	mov	rdi, rax
	mov	rsi, bigint$one
	call	bigint$subtract
	mov	rdi, r14
	mov	rsi, r12
	call	bigint$modby
	mov	rdi, r14
	call	bigint$is_zero
	push	rax
	mov	rdi, r14
	call	bigint$destroy
	pop	rax
	test	eax, eax
	jz	.badprimes

	; verify g**q mod p
	mov	rdi, r12	; exponent == q
	mov	rsi, rbx	; mod == p
	call	monty$new
	mov	r14, rax

	call	bigint$new
	push	rax

	mov 	rdi, r14
	mov	rsi, rax
	mov	rdx, r13
	call	monty$doit
	mov	rdi, r14
	call	monty$destroy
	
	mov	rdi, [rsp]
	mov	rsi, bigint$one
	call	bigint$compare

	mov	rdi, [rsp]
	mov	[rsp], rax
	call	bigint$destroy
	xor	eax, eax
	mov	ecx, 1
	pop	rdx
	test	edx, edx
	cmovz	eax, ecx

	pop	r14 r13 r12 rbx
	epilog
calign
.badprimes:
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog

end if



	; DSA parameters can of course be used for DH parameters, but then g (which is mod p) is quite large
	; for DHE and the like, small group sizes are better (only because of the xfer overhead of sending g
	; for every exchange)
	; for reference, modulus/subgroups for DHE that are not DSA overkill:
	; 1024/82 2048/113 3072/134 4096/152

if used bigint$dh_params | defined include_everything
	; three arguments: rdi == p, rsi == g, edx == size in bits of the safe prime p you want
	; note: both are write-only, size is determined by fixed params atop this file (dh_size)
	; g will be one of 2, 3 or 4

	; NOTE: we generate safe prime p, and generator g such that g is a quadratic residue mod p
	; FURTHER NOTE: we do an _insane_ number of Miller-Rabin tests on both p and its Sophie Germain
	; when we find them to verify them suitable for crypto use... this is not a lightweight operation, hahah.
falign
bigint$dh_params:
	prolog	bigint$dh_params
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r15d, edx
	; we need a temporary q
	call	bigint$new
	mov	r13, rax
calign
.outer:
	; generate a random p w/ 11/12 equiv/mod

	; we need: temp = min + (equiv-min)%mod
	; then we need a max of (max - temp) / 12
	; then we need this = randomrange(0, max)
	; then we need this mult by 12
	; then we need this += temp

	mov	esi, r15d
	mov	rdi, r13
	sub	esi, 1
	call	bigint$set_pow2

	mov	rdi, r12
	mov	esi, 11
	call	bigint$set_unsigned
	mov	rdi, r12
	mov	rsi, r13
	call	bigint$subtract
	; so now we have a giant negative number in r12
	mov	edi, 12
	call	bigint$new_unsigned
	push	rax
	call	bigint$new
	push	rax
	call	bigint$new
	push	rax

	; [rsp] == temp, [rsp+16] == divisor
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, r12
	mov	rcx, [rsp+16]
	call	bigint$divide

	; now the remainder of that is sitting in r12
	mov	rdi, r13
	mov	rsi, [rsp]
	call	bigint$add
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy

	; so now r13 has a clean minimum, now we need our upper bound
	mov	rdi, r12
	mov	esi, r15d
	call	bigint$set_pow2
	mov	rdi, r12
	mov	rsi, bigint$one
	call	bigint$subtract

	mov	rdi, r12
	mov	rsi, r13
	call	bigint$subtract

	mov	rdi, rbx
	mov	esi, 12
	call	bigint$set_unsigned

	mov	rdi, r12
	mov	rsi, rbx
	call	bigint$divby

	mov	rdi, rbx
	mov	rsi, bigint$zero
	mov	rdx, r12
	call	bigint$set_randomrange
	; now mul that by 12 and add r13 to it
	mov	rdi, r12
	mov	esi, 12
	call	bigint$set_unsigned
	mov	rdi, rbx
	mov	rsi, r12
	call	bigint$multiply
	mov	rdi, rbx
	mov	rsi, r13
	call	bigint$add

	; debug output of the sieve start
	; mov	rdi, rbx
	; call	bigint$debug
	; end debug

	; so now we have the seed for our primesieve sitting in rbx, r12 and r13 are done with
	; we need to add (dh_size - 1) * 12 to the sieve first
	mov	esi, r15d
	mov	edx, r15d
	sub	esi, 1
	sub	edx, 1
	mov	rdi, r13
	shl	esi, 3		; (dh size - 1) * 8
	shl	edx, 2		; (dh size - 1) * 4
	add	esi, edx
	call	bigint$set_unsigned
	mov	rdi, rbx
	mov	rsi, r13
	call	bigint$add

	mov	rdi, rbx
	call	bigint$tlz	; trim any leading zeroes off our previous calcs


	; create our primesievemod with step 12
	mov	rdi, rbx	; primesievemod first
	mov	rsi, r12	; still 12 from above
	call	primesievemod$new
	mov	r14, rax
calign
.inner:
	mov	rdi, r14
	mov	rsi, rbx
	call	primesievemod$next
	test	eax, eax	; if it failed, we need to re-randomize and start again
	jz	.tryagain

	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .space
	mov	edx, 1
	syscall

	; we need (p-1) / 2
	mov	rdi, r13
	mov	rsi, rbx
	call	bigint$assign
	mov	rdi, r13
	mov	esi, 1
	call	bigint$shr
	; if q is prime and p is prime, good to go for finding g, otherwise, get another sieve candidate
	mov	rdi, r13
	call	bigint$modsmallprimes
	test	eax, eax
	jnz	.inner

	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .dot
	mov	edx, 1
	syscall

	mov	rdi, r13
	call	bigint$isprime2
	test	eax, eax
	jz	.inner

	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .plus
	mov	edx, 1
	syscall

	mov	rdi, rbx
	call	bigint$isprime2
	test	eax, eax
	jz	.inner

	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .dollar
	mov	edx, 1
	syscall

	mov	rdi, r13
	call	bigint$verifyprime
	test	eax, eax
	jz	.inner
	mov	rdi, rbx
	call	bigint$verifyprime
	test	eax, eax
	jz	.inner

	; debug
	; mov	rdi, .debug1
	; call	string$to_stdoutln
	; mov	rdi, rbx
	; call	bigint$debug
	; mov	rdi, .debug2
	; call	string$to_stdoutln
	; mov	rdi, r13
	; call	bigint$debug
	; end debug

	; else, both are good, proceed with finding g, as Wei Dai states: "find g such that g is a quadratic residue mod p, then g has order q"
	mov	rdi, r12
	mov	esi, 2
	call	bigint$set_unsigned
	; we are done with our sieve
	mov	rdi, r14
	call	primesievemod$destroy
calign
.gloop:
	mov	rdi, r12
	mov	rsi, rbx
	call	bigint$jacobi
	cmp	eax, 1
	je	.dusted
	mov	rdi, r12
	mov	rsi, bigint$one
	call	bigint$add
	jmp	.gloop
calign
.dusted:
	; lots of debug output to verify g is the right value for p
	; mov	rdi, .mod8
	; call	string$to_stdoutln
	; mov	rdi, rbx
	; mov	esi, 8
	; call	bigint$modword
	; mov	rdi, rax
	; mov	esi, 10
	; call	string$from_unsigned
	; push	rax
	; mov	rdi, rax
	; call	string$to_stdoutln
	; pop	rdi
	; call	heap$free
	; mov	rdi, .mod7
	; call	string$to_stdoutln
	; mov	rdi, rbx
	; mov	esi, 7
	; call	bigint$modword
	; mov	rdi, rax
	; mov	esi, 10
	; call	string$from_unsigned
	; push	rax
	; mov	rdi, rax
	; call	string$to_stdoutln
	; pop	rdi
	; call	heap$free
	; mov	rdi, .mod12
	; call	string$to_stdoutln
	; mov	rdi, rbx
	; mov	esi, 12
	; call	bigint$modword
	; mov	rdi, rax
	; mov	esi, 10
	; call	string$from_unsigned
	; push	rax
	; mov	rdi, rax
	; call	string$to_stdoutln
	; pop	rdi
	; call	heap$free

	; destroy our temporary q
	mov	rdi, r13
	call	bigint$destroy
	pop	r15 r14 r13 r12 rbx
	epilog
; cleartext .debug1, 'p is:'
; cleartext .debug2, 'q is:'
; cleartext .mod8, 'p%8 is:'
; cleartext .mod7, 'p%7 is:'
; cleartext .mod12, 'p%12 is:'
align 4
.dot	db '.'
align 4
.space	db ' '
align 4
.plus	db '+'
align 4
.dollar	db '$'
calign
.tryagain:
	; blast our sieve and go back to the top
	mov	rdi, r14
	call	primesievemod$destroy
	jmp	.outer

end if



if used bigint$dsa_params | defined include_everything
	; three arguments: rdi == p, rsi == q, rdx == g
	; note: all three are write only, size is determined by fixed
	; params atop this file
falign
bigint$dsa_params:
	prolog	bigint$dsa_params
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
calign
.outer:
	mov	rdi, r12
	mov	esi, dsa_subgroup_size
	call	bigint$random_prime

	; so now we need a dsa_size prime such that it minus 1 is a multiple of q (r12)

	; first up, we need to set p to the correct sized random bits
	mov	rdi, rbx
	mov	esi, dsa_size
	call	bigint$set_random
	
	mov	rdi, [rbx+bigint_words_ofs]
	or	dword [rdi], 1
	mov	rdi, rbx
	mov	esi, dsa_size-1
	call	bigint$bitset

	mov	rdi, rbx
	mov	esi, dsa_size-2
	call	bigint$bitset

	; temporarily shl our q by 1
	mov	rdi, r12
	mov	esi, 1
	call	bigint$shl

	; so next step is to establish a temporary, and since we aren't using g yet, we can use it to do the deed
	mov	rdi, r13
	mov	esi, 1
	call	bigint$set_unsigned

	mov	rdi, r13
	mov	rsi, rbx
	call	bigint$subtract

	; now we need to mod by our q sitting in r12
	mov	rdi, r13
	mov	rsi, r12
	call	bigint$modby

	; now add that result back to our p
	mov	rdi, rbx
	mov	rsi, r13
	call	bigint$add

	; so now we have our q which is twice as big as it really needs to be
	; create our sieve with the modified parameter, and then re-adjust q back to its original

	mov	rdi, rbx
	mov	rsi, r12
	call	primesievemod$new
	mov	r14, rax		; r14 == our primesieve object

	; adjust q back to its original
	mov	rdi, r12
	mov	esi, 1
	call	bigint$shr

	; now, fire away with q
calign
.toploop:
	mov	rdi, r14		; our primesieve object
	mov	rsi, rbx
	call	primesievemod$next
	test	eax, eax		; if it failed, we need to re-randomize and start again
	jz	.tryagain

	mov	rdi, rbx
	call	bigint$isprime2
	test	eax, eax
	jz	.toploop		; get another one
	; otherwise, we are good
	mov	rdi, r14
	call	primesievemod$destroy

	; so now, we have p and q that suit our needs
	; next up, find a random g of order q, using our monty goods
	; we need a random h in the range of 2..p-2
	; and we need another temporary that is (p-1)/q
	
	; then we set g to the result of monty$doit
	; and then loop while g <= 1
calign
.random_h:
	mov	edi, dsa_size - 1
	call	bigint$new_random
	sub	rsp, 24
	mov	[rsp], rax
	mov	rdi, rbx
	call	bigint$new_copy
	mov	[rsp+8], rax
	mov	rdi, rax
	mov	rsi, bigint$one
	call	bigint$subtract
	mov	rdi, [rsp+8]
	mov	rsi, r12		; q
	call	bigint$divby

	; so now we are ready for our monty
	mov	rdi, [rsp+8]		; (p-1)/q == exponent
	mov	rsi, rbx		; p
	call	monty$new

	mov	[rsp+16], rax
	mov	rdi, rax
	mov	rsi, r13		; g =
	mov	rdx, [rsp]		; h
	call	monty$doit

	mov	rdi, [rsp+16]
	call	monty$destroy
	
	; so now, we can safely destroy our temps
	mov	rdi, [rsp]
	call	bigint$destroy
	
	mov	rdi, [rsp+8]
	call	bigint$destroy
	
	add	rsp, 24
	
	; g <= 1 ?
	mov	rdi, r13
	mov	rsi, bigint$one
	call	bigint$compare
	cmp	eax, 0
	jle	.random_h

	; otherwise, we are good, p, q, and g parameters all set

	pop	r14 r13 r12 rbx
	epilog
calign
.tryagain:
	mov	rdi, r14
	call	primesievemod$destroy
	jmp	.outer
end if



if used bigint_primetable | defined include_everything

dalign
bigint_primetable:
	dw	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607
	dw	613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381
	dw	1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221
	dw	2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083
	dw	3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001
	dw	4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943
	dw	4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861
	dw	5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841
	dw	6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841
	dw	7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837
	dw	8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817
	dw	9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973, 10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163, 10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333, 10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453, 10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531, 10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639, 10651, 10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729, 10733, 10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859, 10861
	dw	10867, 10883, 10889, 10891, 10903, 10909, 10937, 10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003, 11027, 11047, 11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117, 11119, 11131, 11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239, 11243, 11251, 11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317, 11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399, 11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491, 11497, 11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617, 11621, 11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731, 11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827, 11831, 11833, 11839, 11863, 11867, 11887, 11897, 11903, 11909, 11923, 11927, 11933, 11939
	dw	11941, 11953, 11959, 11969, 11971, 11981, 11987, 12007, 12011, 12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101, 12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163, 12197, 12203, 12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377, 12379, 12391, 12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473, 12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527, 12539, 12541, 12547, 12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613, 12619, 12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703, 12713, 12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823, 12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 12923, 12941
	dw	12953, 12959, 12967, 12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033, 13037, 13043, 13049, 13063, 13093, 13099, 13103, 13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177, 13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267, 13291, 13297, 13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381, 13397, 13399, 13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469, 13477, 13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597, 13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691, 13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759, 13763, 13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859, 13873, 13877, 13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933, 13963, 13967, 13997
	dw	13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071, 14081, 14083, 14087, 14107, 14143, 14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221, 14243, 14249, 14251, 14281, 14293, 14303, 14321, 14323, 14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407, 14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479, 14489, 14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563, 14591, 14593, 14621, 14627, 14629, 14633, 14639, 14653, 14657, 14669, 14683, 14699, 14713, 14717, 14723, 14731, 14737, 14741, 14747, 14753, 14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827, 14831, 14843, 14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923, 14929, 14939, 14947, 14951, 14957, 14969, 14983, 15013, 15017, 15031, 15053, 15061, 15073, 15077
	dw	15083, 15091, 15101, 15107, 15121, 15131, 15137, 15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217, 15227, 15233, 15241, 15259, 15263, 15269, 15271, 15277, 15287, 15289, 15299, 15307, 15313, 15319, 15329, 15331, 15349, 15359, 15361, 15373, 15377, 15383, 15391, 15401, 15413, 15427, 15439, 15443, 15451, 15461, 15467, 15473, 15493, 15497, 15511, 15527, 15541, 15551, 15559, 15569, 15581, 15583, 15601, 15607, 15619, 15629, 15641, 15643, 15647, 15649, 15661, 15667, 15671, 15679, 15683, 15727, 15731, 15733, 15737, 15739, 15749, 15761, 15767, 15773, 15787, 15791, 15797, 15803, 15809, 15817, 15823, 15859, 15877, 15881, 15887, 15889, 15901, 15907, 15913, 15919, 15923, 15937, 15959, 15971, 15973, 15991, 16001, 16007, 16033, 16057, 16061, 16063, 16067, 16069, 16073
	dw	16087, 16091, 16097, 16103, 16111, 16127, 16139, 16141, 16183, 16187, 16189, 16193, 16217, 16223, 16229, 16231, 16249, 16253, 16267, 16273, 16301, 16319, 16333, 16339, 16349, 16361, 16363, 16369, 16381, 16411, 16417, 16421, 16427, 16433, 16447, 16451, 16453, 16477, 16481, 16487, 16493, 16519, 16529, 16547, 16553, 16561, 16567, 16573, 16603, 16607, 16619, 16631, 16633, 16649, 16651, 16657, 16661, 16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747, 16759, 16763, 16787, 16811, 16823, 16829, 16831, 16843, 16871, 16879, 16883, 16889, 16901, 16903, 16921, 16927, 16931, 16937, 16943, 16963, 16979, 16981, 16987, 16993, 17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053, 17077, 17093, 17099, 17107, 17117, 17123, 17137, 17159, 17167, 17183, 17189, 17191, 17203
	dw	17207, 17209, 17231, 17239, 17257, 17291, 17293, 17299, 17317, 17321, 17327, 17333, 17341, 17351, 17359, 17377, 17383, 17387, 17389, 17393, 17401, 17417, 17419, 17431, 17443, 17449, 17467, 17471, 17477, 17483, 17489, 17491, 17497, 17509, 17519, 17539, 17551, 17569, 17573, 17579, 17581, 17597, 17599, 17609, 17623, 17627, 17657, 17659, 17669, 17681, 17683, 17707, 17713, 17729, 17737, 17747, 17749, 17761, 17783, 17789, 17791, 17807, 17827, 17837, 17839, 17851, 17863, 17881, 17891, 17903, 17909, 17911, 17921, 17923, 17929, 17939, 17957, 17959, 17971, 17977, 17981, 17987, 17989, 18013, 18041, 18043, 18047, 18049, 18059, 18061, 18077, 18089, 18097, 18119, 18121, 18127, 18131, 18133, 18143, 18149, 18169, 18181, 18191, 18199, 18211, 18217, 18223, 18229, 18233, 18251
	dw	18253, 18257, 18269, 18287, 18289, 18301, 18307, 18311, 18313, 18329, 18341, 18353, 18367, 18371, 18379, 18397, 18401, 18413, 18427, 18433, 18439, 18443, 18451, 18457, 18461, 18481, 18493, 18503, 18517, 18521, 18523, 18539, 18541, 18553, 18583, 18587, 18593, 18617, 18637, 18661, 18671, 18679, 18691, 18701, 18713, 18719, 18731, 18743, 18749, 18757, 18773, 18787, 18793, 18797, 18803, 18839, 18859, 18869, 18899, 18911, 18913, 18917, 18919, 18947, 18959, 18973, 18979, 19001, 19009, 19013, 19031, 19037, 19051, 19069, 19073, 19079, 19081, 19087, 19121, 19139, 19141, 19157, 19163, 19181, 19183, 19207, 19211, 19213, 19219, 19231, 19237, 19249, 19259, 19267, 19273, 19289, 19301, 19309, 19319, 19333, 19373, 19379, 19381, 19387, 19391, 19403, 19417, 19421, 19423, 19427
	dw	19429, 19433, 19441, 19447, 19457, 19463, 19469, 19471, 19477, 19483, 19489, 19501, 19507, 19531, 19541, 19543, 19553, 19559, 19571, 19577, 19583, 19597, 19603, 19609, 19661, 19681, 19687, 19697, 19699, 19709, 19717, 19727, 19739, 19751, 19753, 19759, 19763, 19777, 19793, 19801, 19813, 19819, 19841, 19843, 19853, 19861, 19867, 19889, 19891, 19913, 19919, 19927, 19937, 19949, 19961, 19963, 19973, 19979, 19991, 19993, 19997, 20011, 20021, 20023, 20029, 20047, 20051, 20063, 20071, 20089, 20101, 20107, 20113, 20117, 20123, 20129, 20143, 20147, 20149, 20161, 20173, 20177, 20183, 20201, 20219, 20231, 20233, 20249, 20261, 20269, 20287, 20297, 20323, 20327, 20333, 20341, 20347, 20353, 20357, 20359, 20369, 20389, 20393, 20399, 20407, 20411, 20431, 20441, 20443, 20477
	dw	20479, 20483, 20507, 20509, 20521, 20533, 20543, 20549, 20551, 20563, 20593, 20599, 20611, 20627, 20639, 20641, 20663, 20681, 20693, 20707, 20717, 20719, 20731, 20743, 20747, 20749, 20753, 20759, 20771, 20773, 20789, 20807, 20809, 20849, 20857, 20873, 20879, 20887, 20897, 20899, 20903, 20921, 20929, 20939, 20947, 20959, 20963, 20981, 20983, 21001, 21011, 21013, 21017, 21019, 21023, 21031, 21059, 21061, 21067, 21089, 21101, 21107, 21121, 21139, 21143, 21149, 21157, 21163, 21169, 21179, 21187, 21191, 21193, 21211, 21221, 21227, 21247, 21269, 21277, 21283, 21313, 21317, 21319, 21323, 21341, 21347, 21377, 21379, 21383, 21391, 21397, 21401, 21407, 21419, 21433, 21467, 21481, 21487, 21491, 21493, 21499, 21503, 21517, 21521, 21523, 21529, 21557, 21559, 21563, 21569
	dw	21577, 21587, 21589, 21599, 21601, 21611, 21613, 21617, 21647, 21649, 21661, 21673, 21683, 21701, 21713, 21727, 21737, 21739, 21751, 21757, 21767, 21773, 21787, 21799, 21803, 21817, 21821, 21839, 21841, 21851, 21859, 21863, 21871, 21881, 21893, 21911, 21929, 21937, 21943, 21961, 21977, 21991, 21997, 22003, 22013, 22027, 22031, 22037, 22039, 22051, 22063, 22067, 22073, 22079, 22091, 22093, 22109, 22111, 22123, 22129, 22133, 22147, 22153, 22157, 22159, 22171, 22189, 22193, 22229, 22247, 22259, 22271, 22273, 22277, 22279, 22283, 22291, 22303, 22307, 22343, 22349, 22367, 22369, 22381, 22391, 22397, 22409, 22433, 22441, 22447, 22453, 22469, 22481, 22483, 22501, 22511, 22531, 22541, 22543, 22549, 22567, 22571, 22573, 22613, 22619, 22621, 22637, 22639, 22643, 22651
	dw	22669, 22679, 22691, 22697, 22699, 22709, 22717, 22721, 22727, 22739, 22741, 22751, 22769, 22777, 22783, 22787, 22807, 22811, 22817, 22853, 22859, 22861, 22871, 22877, 22901, 22907, 22921, 22937, 22943, 22961, 22963, 22973, 22993, 23003, 23011, 23017, 23021, 23027, 23029, 23039, 23041, 23053, 23057, 23059, 23063, 23071, 23081, 23087, 23099, 23117, 23131, 23143, 23159, 23167, 23173, 23189, 23197, 23201, 23203, 23209, 23227, 23251, 23269, 23279, 23291, 23293, 23297, 23311, 23321, 23327, 23333, 23339, 23357, 23369, 23371, 23399, 23417, 23431, 23447, 23459, 23473, 23497, 23509, 23531, 23537, 23539, 23549, 23557, 23561, 23563, 23567, 23581, 23593, 23599, 23603, 23609, 23623, 23627, 23629, 23633, 23663, 23669, 23671, 23677, 23687, 23689, 23719, 23741, 23743, 23747
	dw	23753, 23761, 23767, 23773, 23789, 23801, 23813, 23819, 23827, 23831, 23833, 23857, 23869, 23873, 23879, 23887, 23893, 23899, 23909, 23911, 23917, 23929, 23957, 23971, 23977, 23981, 23993, 24001, 24007, 24019, 24023, 24029, 24043, 24049, 24061, 24071, 24077, 24083, 24091, 24097, 24103, 24107, 24109, 24113, 24121, 24133, 24137, 24151, 24169, 24179, 24181, 24197, 24203, 24223, 24229, 24239, 24247, 24251, 24281, 24317, 24329, 24337, 24359, 24371, 24373, 24379, 24391, 24407, 24413, 24419, 24421, 24439, 24443, 24469, 24473, 24481, 24499, 24509, 24517, 24527, 24533, 24547, 24551, 24571, 24593, 24611, 24623, 24631, 24659, 24671, 24677, 24683, 24691, 24697, 24709, 24733, 24749, 24763, 24767, 24781, 24793, 24799, 24809, 24821, 24841, 24847, 24851, 24859, 24877, 24889
	dw	24907, 24917, 24919, 24923, 24943, 24953, 24967, 24971, 24977, 24979, 24989, 25013, 25031, 25033, 25037, 25057, 25073, 25087, 25097, 25111, 25117, 25121, 25127, 25147, 25153, 25163, 25169, 25171, 25183, 25189, 25219, 25229, 25237, 25243, 25247, 25253, 25261, 25301, 25303, 25307, 25309, 25321, 25339, 25343, 25349, 25357, 25367, 25373, 25391, 25409, 25411, 25423, 25439, 25447, 25453, 25457, 25463, 25469, 25471, 25523, 25537, 25541, 25561, 25577, 25579, 25583, 25589, 25601, 25603, 25609, 25621, 25633, 25639, 25643, 25657, 25667, 25673, 25679, 25693, 25703, 25717, 25733, 25741, 25747, 25759, 25763, 25771, 25793, 25799, 25801, 25819, 25841, 25847, 25849, 25867, 25873, 25889, 25903, 25913, 25919, 25931, 25933, 25939, 25943, 25951, 25969, 25981, 25997, 25999, 26003
	dw	26017, 26021, 26029, 26041, 26053, 26083, 26099, 26107, 26111, 26113, 26119, 26141, 26153, 26161, 26171, 26177, 26183, 26189, 26203, 26209, 26227, 26237, 26249, 26251, 26261, 26263, 26267, 26293, 26297, 26309, 26317, 26321, 26339, 26347, 26357, 26371, 26387, 26393, 26399, 26407, 26417, 26423, 26431, 26437, 26449, 26459, 26479, 26489, 26497, 26501, 26513, 26539, 26557, 26561, 26573, 26591, 26597, 26627, 26633, 26641, 26647, 26669, 26681, 26683, 26687, 26693, 26699, 26701, 26711, 26713, 26717, 26723, 26729, 26731, 26737, 26759, 26777, 26783, 26801, 26813, 26821, 26833, 26839, 26849, 26861, 26863, 26879, 26881, 26891, 26893, 26903, 26921, 26927, 26947, 26951, 26953, 26959, 26981, 26987, 26993, 27011, 27017, 27031, 27043, 27059, 27061, 27067, 27073, 27077, 27091
	dw	27103, 27107, 27109, 27127, 27143, 27179, 27191, 27197, 27211, 27239, 27241, 27253, 27259, 27271, 27277, 27281, 27283, 27299, 27329, 27337, 27361, 27367, 27397, 27407, 27409, 27427, 27431, 27437, 27449, 27457, 27479, 27481, 27487, 27509, 27527, 27529, 27539, 27541, 27551, 27581, 27583, 27611, 27617, 27631, 27647, 27653, 27673, 27689, 27691, 27697, 27701, 27733, 27737, 27739, 27743, 27749, 27751, 27763, 27767, 27773, 27779, 27791, 27793, 27799, 27803, 27809, 27817, 27823, 27827, 27847, 27851, 27883, 27893, 27901, 27917, 27919, 27941, 27943, 27947, 27953, 27961, 27967, 27983, 27997, 28001, 28019, 28027, 28031, 28051, 28057, 28069, 28081, 28087, 28097, 28099, 28109, 28111, 28123, 28151, 28163, 28181, 28183, 28201, 28211, 28219, 28229, 28277, 28279, 28283, 28289
	dw	28297, 28307, 28309, 28319, 28349, 28351, 28387, 28393, 28403, 28409, 28411, 28429, 28433, 28439, 28447, 28463, 28477, 28493, 28499, 28513, 28517, 28537, 28541, 28547, 28549, 28559, 28571, 28573, 28579, 28591, 28597, 28603, 28607, 28619, 28621, 28627, 28631, 28643, 28649, 28657, 28661, 28663, 28669, 28687, 28697, 28703, 28711, 28723, 28729, 28751, 28753, 28759, 28771, 28789, 28793, 28807, 28813, 28817, 28837, 28843, 28859, 28867, 28871, 28879, 28901, 28909, 28921, 28927, 28933, 28949, 28961, 28979, 29009, 29017, 29021, 29023, 29027, 29033, 29059, 29063, 29077, 29101, 29123, 29129, 29131, 29137, 29147, 29153, 29167, 29173, 29179, 29191, 29201, 29207, 29209, 29221, 29231, 29243, 29251, 29269, 29287, 29297, 29303, 29311, 29327, 29333, 29339, 29347, 29363, 29383
	dw	29387, 29389, 29399, 29401, 29411, 29423, 29429, 29437, 29443, 29453, 29473, 29483, 29501, 29527, 29531, 29537, 29567, 29569, 29573, 29581, 29587, 29599, 29611, 29629, 29633, 29641, 29663, 29669, 29671, 29683, 29717, 29723, 29741, 29753, 29759, 29761, 29789, 29803, 29819, 29833, 29837, 29851, 29863, 29867, 29873, 29879, 29881, 29917, 29921, 29927, 29947, 29959, 29983, 29989, 30011, 30013, 30029, 30047, 30059, 30071, 30089, 30091, 30097, 30103, 30109, 30113, 30119, 30133, 30137, 30139, 30161, 30169, 30181, 30187, 30197, 30203, 30211, 30223, 30241, 30253, 30259, 30269, 30271, 30293, 30307, 30313, 30319, 30323, 30341, 30347, 30367, 30389, 30391, 30403, 30427, 30431, 30449, 30467, 30469, 30491, 30493, 30497, 30509, 30517, 30529, 30539, 30553, 30557, 30559, 30577
	dw	30593, 30631, 30637, 30643, 30649, 30661, 30671, 30677, 30689, 30697, 30703, 30707, 30713, 30727, 30757, 30763, 30773, 30781, 30803, 30809, 30817, 30829, 30839, 30841, 30851, 30853, 30859, 30869, 30871, 30881, 30893, 30911, 30931, 30937, 30941, 30949, 30971, 30977, 30983, 31013, 31019, 31033, 31039, 31051, 31063, 31069, 31079, 31081, 31091, 31121, 31123, 31139, 31147, 31151, 31153, 31159, 31177, 31181, 31183, 31189, 31193, 31219, 31223, 31231, 31237, 31247, 31249, 31253, 31259, 31267, 31271, 31277, 31307, 31319, 31321, 31327, 31333, 31337, 31357, 31379, 31387, 31391, 31393, 31397, 31469, 31477, 31481, 31489, 31511, 31513, 31517, 31531, 31541, 31543, 31547, 31567, 31573, 31583, 31601, 31607, 31627, 31643, 31649, 31657, 31663, 31667, 31687, 31699, 31721, 31723
	dw	31727, 31729, 31741, 31751, 31769, 31771, 31793, 31799, 31817, 31847, 31849, 31859, 31873, 31883, 31891, 31907, 31957, 31963, 31973, 31981, 31991, 32003, 32009, 32027, 32029, 32051, 32057, 32059, 32063, 32069, 32077, 32083, 32089, 32099, 32117, 32119, 32141, 32143, 32159, 32173, 32183, 32189, 32191, 32203, 32213, 32233, 32237, 32251, 32257, 32261, 32297, 32299, 32303, 32309, 32321, 32323, 32327, 32341, 32353, 32359, 32363, 32369, 32371, 32377, 32381, 32401, 32411, 32413, 32423, 32429, 32441, 32443, 32467, 32479, 32491, 32497, 32503, 32507, 32531, 32533, 32537, 32561, 32563, 32569, 32573, 32579, 32587, 32603, 32609, 32611, 32621, 32633, 32647, 32653, 32687, 32693, 32707, 32713, 32717, 32719, 32749, 32771, 32779, 32783, 32789, 32797, 32801, 32803, 32831, 32833
	dw	32839, 32843, 32869, 32887, 32909, 32911, 32917, 32933, 32939, 32941, 32957, 32969, 32971, 32983, 32987, 32993, 32999, 33013, 33023, 33029, 33037, 33049, 33053, 33071, 33073, 33083, 33091, 33107, 33113, 33119, 33149, 33151, 33161, 33179, 33181, 33191, 33199, 33203, 33211, 33223, 33247, 33287, 33289, 33301, 33311, 33317, 33329, 33331, 33343, 33347, 33349, 33353, 33359, 33377, 33391, 33403, 33409, 33413, 33427, 33457, 33461, 33469, 33479, 33487, 33493, 33503, 33521, 33529, 33533, 33547, 33563, 33569, 33577, 33581, 33587, 33589, 33599, 33601, 33613, 33617, 33619, 33623, 33629, 33637, 33641, 33647, 33679, 33703, 33713, 33721, 33739, 33749, 33751, 33757, 33767, 33769, 33773, 33791, 33797, 33809, 33811, 33827, 33829, 33851, 33857, 33863, 33871, 33889, 33893, 33911
	dw	33923, 33931, 33937, 33941, 33961, 33967, 33997, 34019, 34031, 34033, 34039, 34057, 34061, 34123, 34127, 34129, 34141, 34147, 34157, 34159, 34171, 34183, 34211, 34213, 34217, 34231, 34253, 34259, 34261, 34267, 34273, 34283, 34297, 34301, 34303, 34313, 34319, 34327, 34337, 34351, 34361, 34367, 34369, 34381, 34403, 34421, 34429, 34439, 34457, 34469, 34471, 34483, 34487, 34499, 34501, 34511, 34513, 34519, 34537, 34543, 34549, 34583, 34589, 34591, 34603, 34607, 34613, 34631, 34649, 34651, 34667, 34673, 34679, 34687, 34693, 34703, 34721, 34729, 34739, 34747, 34757, 34759, 34763, 34781, 34807, 34819, 34841, 34843, 34847, 34849, 34871, 34877, 34883, 34897, 34913, 34919, 34939, 34949, 34961, 34963, 34981, 35023, 35027, 35051, 35053, 35059, 35069, 35081, 35083, 35089
	dw	35099, 35107, 35111, 35117, 35129, 35141, 35149, 35153, 35159, 35171, 35201, 35221, 35227, 35251, 35257, 35267, 35279, 35281, 35291, 35311, 35317, 35323, 35327, 35339, 35353, 35363, 35381, 35393, 35401, 35407, 35419, 35423, 35437, 35447, 35449, 35461, 35491, 35507, 35509, 35521, 35527, 35531, 35533, 35537, 35543, 35569, 35573, 35591, 35593, 35597, 35603, 35617, 35671, 35677, 35729, 35731, 35747, 35753, 35759, 35771, 35797, 35801, 35803, 35809, 35831, 35837, 35839, 35851, 35863, 35869, 35879, 35897, 35899, 35911, 35923, 35933, 35951, 35963, 35969, 35977, 35983, 35993, 35999, 36007, 36011, 36013, 36017, 36037, 36061, 36067, 36073, 36083, 36097, 36107, 36109, 36131, 36137, 36151, 36161, 36187, 36191, 36209, 36217, 36229, 36241, 36251, 36263, 36269, 36277, 36293
	dw	36299, 36307, 36313, 36319, 36341, 36343, 36353, 36373, 36383, 36389, 36433, 36451, 36457, 36467, 36469, 36473, 36479, 36493, 36497, 36523, 36527, 36529, 36541, 36551, 36559, 36563, 36571, 36583, 36587, 36599, 36607, 36629, 36637, 36643, 36653, 36671, 36677, 36683, 36691, 36697, 36709, 36713, 36721, 36739, 36749, 36761, 36767, 36779, 36781, 36787, 36791, 36793, 36809, 36821, 36833, 36847, 36857, 36871, 36877, 36887, 36899, 36901, 36913, 36919, 36923, 36929, 36931, 36943, 36947, 36973, 36979, 36997, 37003, 37013, 37019, 37021, 37039, 37049, 37057, 37061, 37087, 37097, 37117, 37123, 37139, 37159, 37171, 37181, 37189, 37199, 37201, 37217, 37223, 37243, 37253, 37273, 37277, 37307, 37309, 37313, 37321, 37337, 37339, 37357, 37361, 37363, 37369, 37379, 37397, 37409
	dw	37423, 37441, 37447, 37463, 37483, 37489, 37493, 37501, 37507, 37511, 37517, 37529, 37537, 37547, 37549, 37561, 37567, 37571, 37573, 37579, 37589, 37591, 37607, 37619, 37633, 37643, 37649, 37657, 37663, 37691, 37693, 37699, 37717, 37747, 37781, 37783, 37799, 37811, 37813, 37831, 37847, 37853, 37861, 37871, 37879, 37889, 37897, 37907, 37951, 37957, 37963, 37967, 37987, 37991, 37993, 37997, 38011, 38039, 38047, 38053, 38069, 38083, 38113, 38119, 38149, 38153, 38167, 38177, 38183, 38189, 38197, 38201, 38219, 38231, 38237, 38239, 38261, 38273, 38281, 38287, 38299, 38303, 38317, 38321, 38327, 38329, 38333, 38351, 38371, 38377, 38393, 38431, 38447, 38449, 38453, 38459, 38461, 38501, 38543, 38557, 38561, 38567, 38569, 38593, 38603, 38609, 38611, 38629, 38639, 38651
	dw	38653, 38669, 38671, 38677, 38693, 38699, 38707, 38711, 38713, 38723, 38729, 38737, 38747, 38749, 38767, 38783, 38791, 38803, 38821, 38833, 38839, 38851, 38861, 38867, 38873, 38891, 38903, 38917, 38921, 38923, 38933, 38953, 38959, 38971, 38977, 38993, 39019, 39023, 39041, 39043, 39047, 39079, 39089, 39097, 39103, 39107, 39113, 39119, 39133, 39139, 39157, 39161, 39163, 39181, 39191, 39199, 39209, 39217, 39227, 39229, 39233, 39239, 39241, 39251, 39293, 39301, 39313, 39317, 39323, 39341, 39343, 39359, 39367, 39371, 39373, 39383, 39397, 39409, 39419, 39439, 39443, 39451, 39461, 39499, 39503, 39509, 39511, 39521, 39541, 39551, 39563, 39569, 39581, 39607, 39619, 39623, 39631, 39659, 39667, 39671, 39679, 39703, 39709, 39719, 39727, 39733, 39749, 39761, 39769, 39779
	dw	39791, 39799, 39821, 39827, 39829, 39839, 39841, 39847, 39857, 39863, 39869, 39877, 39883, 39887, 39901, 39929, 39937, 39953, 39971, 39979, 39983, 39989, 40009, 40013, 40031, 40037, 40039, 40063, 40087, 40093, 40099, 40111, 40123, 40127, 40129, 40151, 40153, 40163, 40169, 40177, 40189, 40193, 40213, 40231, 40237, 40241, 40253, 40277, 40283, 40289, 40343, 40351, 40357, 40361, 40387, 40423, 40427, 40429, 40433, 40459, 40471, 40483, 40487, 40493, 40499, 40507, 40519, 40529, 40531, 40543, 40559, 40577, 40583, 40591, 40597, 40609, 40627, 40637, 40639, 40693, 40697, 40699, 40709, 40739, 40751, 40759, 40763, 40771, 40787, 40801, 40813, 40819, 40823, 40829, 40841, 40847, 40849, 40853, 40867, 40879, 40883, 40897, 40903, 40927, 40933, 40939, 40949, 40961, 40973, 40993
	dw	41011, 41017, 41023, 41039, 41047, 41051, 41057, 41077, 41081, 41113, 41117, 41131, 41141, 41143, 41149, 41161, 41177, 41179, 41183, 41189, 41201, 41203, 41213, 41221, 41227, 41231, 41233, 41243, 41257, 41263, 41269, 41281, 41299, 41333, 41341, 41351, 41357, 41381, 41387, 41389, 41399, 41411, 41413, 41443, 41453, 41467, 41479, 41491, 41507, 41513, 41519, 41521, 41539, 41543, 41549, 41579, 41593, 41597, 41603, 41609, 41611, 41617, 41621, 41627, 41641, 41647, 41651, 41659, 41669, 41681, 41687, 41719, 41729, 41737, 41759, 41761, 41771, 41777, 41801, 41809, 41813, 41843, 41849, 41851, 41863, 41879, 41887, 41893, 41897, 41903, 41911, 41927, 41941, 41947, 41953, 41957, 41959, 41969, 41981, 41983, 41999, 42013, 42017, 42019, 42023, 42043, 42061, 42071, 42073, 42083
	dw	42089, 42101, 42131, 42139, 42157, 42169, 42179, 42181, 42187, 42193, 42197, 42209, 42221, 42223, 42227, 42239, 42257, 42281, 42283, 42293, 42299, 42307, 42323, 42331, 42337, 42349, 42359, 42373, 42379, 42391, 42397, 42403, 42407, 42409, 42433, 42437, 42443, 42451, 42457, 42461, 42463, 42467, 42473, 42487, 42491, 42499, 42509, 42533, 42557, 42569, 42571, 42577, 42589, 42611, 42641, 42643, 42649, 42667, 42677, 42683, 42689, 42697, 42701, 42703, 42709, 42719, 42727, 42737, 42743, 42751, 42767, 42773, 42787, 42793, 42797, 42821, 42829, 42839, 42841, 42853, 42859, 42863, 42899, 42901, 42923, 42929, 42937, 42943, 42953, 42961, 42967, 42979, 42989, 43003, 43013, 43019, 43037, 43049, 43051, 43063, 43067, 43093, 43103, 43117, 43133, 43151, 43159, 43177, 43189, 43201
	dw	43207, 43223, 43237, 43261, 43271, 43283, 43291, 43313, 43319, 43321, 43331, 43391, 43397, 43399, 43403, 43411, 43427, 43441, 43451, 43457, 43481, 43487, 43499, 43517, 43541, 43543, 43573, 43577, 43579, 43591, 43597, 43607, 43609, 43613, 43627, 43633, 43649, 43651, 43661, 43669, 43691, 43711, 43717, 43721, 43753, 43759, 43777, 43781, 43783, 43787, 43789, 43793, 43801, 43853, 43867, 43889, 43891, 43913, 43933, 43943, 43951, 43961, 43963, 43969, 43973, 43987, 43991, 43997, 44017, 44021, 44027, 44029, 44041, 44053, 44059, 44071, 44087, 44089, 44101, 44111, 44119, 44123, 44129, 44131, 44159, 44171, 44179, 44189, 44201, 44203, 44207, 44221, 44249, 44257, 44263, 44267, 44269, 44273, 44279, 44281, 44293, 44351, 44357, 44371, 44381, 44383, 44389, 44417, 44449, 44453
	dw	44483, 44491, 44497, 44501, 44507, 44519, 44531, 44533, 44537, 44543, 44549, 44563, 44579, 44587, 44617, 44621, 44623, 44633, 44641, 44647, 44651, 44657, 44683, 44687, 44699, 44701, 44711, 44729, 44741, 44753, 44771, 44773, 44777, 44789, 44797, 44809, 44819, 44839, 44843, 44851, 44867, 44879, 44887, 44893, 44909, 44917, 44927, 44939, 44953, 44959, 44963, 44971, 44983, 44987, 45007, 45013, 45053, 45061, 45077, 45083, 45119, 45121, 45127, 45131, 45137, 45139, 45161, 45179, 45181, 45191, 45197, 45233, 45247, 45259, 45263, 45281, 45289, 45293, 45307, 45317, 45319, 45329, 45337, 45341, 45343, 45361, 45377, 45389, 45403, 45413, 45427, 45433, 45439, 45481, 45491, 45497, 45503, 45523, 45533, 45541, 45553, 45557, 45569, 45587, 45589, 45599, 45613, 45631, 45641, 45659
	dw	45667, 45673, 45677, 45691, 45697, 45707, 45737, 45751, 45757, 45763, 45767, 45779, 45817, 45821, 45823, 45827, 45833, 45841, 45853, 45863, 45869, 45887, 45893, 45943, 45949, 45953, 45959, 45971, 45979, 45989, 46021, 46027, 46049, 46051, 46061, 46073, 46091, 46093, 46099, 46103, 46133, 46141, 46147, 46153, 46171, 46181, 46183, 46187, 46199, 46219, 46229, 46237, 46261, 46271, 46273, 46279, 46301, 46307, 46309, 46327, 46337, 46349, 46351, 46381, 46399, 46411, 46439, 46441, 46447, 46451, 46457, 46471, 46477, 46489, 46499, 46507, 46511, 46523, 46549, 46559, 46567, 46573, 46589, 46591, 46601, 46619, 46633, 46639, 46643, 46649, 46663, 46679, 46681, 46687, 46691, 46703, 46723, 46727, 46747, 46751, 46757, 46769, 46771, 46807, 46811, 46817, 46819, 46829, 46831, 46853
	dw	46861, 46867, 46877, 46889, 46901, 46919, 46933, 46957, 46993, 46997, 47017, 47041, 47051, 47057, 47059, 47087, 47093, 47111, 47119, 47123, 47129, 47137, 47143, 47147, 47149, 47161, 47189, 47207, 47221, 47237, 47251, 47269, 47279, 47287, 47293, 47297, 47303, 47309, 47317, 47339, 47351, 47353, 47363, 47381, 47387, 47389, 47407, 47417, 47419, 47431, 47441, 47459, 47491, 47497, 47501, 47507, 47513, 47521, 47527, 47533, 47543, 47563, 47569, 47581, 47591, 47599, 47609, 47623, 47629, 47639, 47653, 47657, 47659, 47681, 47699, 47701, 47711, 47713, 47717, 47737, 47741, 47743, 47777, 47779, 47791, 47797, 47807, 47809, 47819, 47837, 47843, 47857, 47869, 47881, 47903, 47911, 47917, 47933, 47939, 47947, 47951, 47963, 47969, 47977, 47981, 48017, 48023, 48029, 48049, 48073
	dw	48079, 48091, 48109, 48119, 48121, 48131, 48157, 48163, 48179, 48187, 48193, 48197, 48221, 48239, 48247, 48259, 48271, 48281, 48299, 48311, 48313, 48337, 48341, 48353, 48371, 48383, 48397, 48407, 48409, 48413, 48437, 48449, 48463, 48473, 48479, 48481, 48487, 48491, 48497, 48523, 48527, 48533, 48539, 48541, 48563, 48571, 48589, 48593, 48611, 48619, 48623, 48647, 48649, 48661, 48673, 48677, 48679, 48731, 48733, 48751, 48757, 48761, 48767, 48779, 48781, 48787, 48799, 48809, 48817, 48821, 48823, 48847, 48857, 48859, 48869, 48871, 48883, 48889, 48907, 48947, 48953, 48973, 48989, 48991, 49003, 49009, 49019, 49031, 49033, 49037, 49043, 49057, 49069, 49081, 49103, 49109, 49117, 49121, 49123, 49139, 49157, 49169, 49171, 49177, 49193, 49199, 49201, 49207, 49211, 49223
	dw	49253, 49261, 49277, 49279, 49297, 49307, 49331, 49333, 49339, 49363, 49367, 49369, 49391, 49393, 49409, 49411, 49417, 49429, 49433, 49451, 49459, 49463, 49477, 49481, 49499, 49523, 49529, 49531, 49537, 49547, 49549, 49559, 49597, 49603, 49613, 49627, 49633, 49639, 49663, 49667, 49669, 49681, 49697, 49711, 49727, 49739, 49741, 49747, 49757, 49783, 49787, 49789, 49801, 49807, 49811, 49823, 49831, 49843, 49853, 49871, 49877, 49891, 49919, 49921, 49927, 49937, 49939, 49943, 49957, 49991, 49993, 49999, 50021, 50023, 50033, 50047, 50051, 50053, 50069, 50077, 50087, 50093, 50101, 50111, 50119, 50123, 50129, 50131, 50147, 50153, 50159, 50177, 50207, 50221, 50227, 50231, 50261, 50263, 50273, 50287, 50291, 50311, 50321, 50329, 50333, 50341, 50359, 50363, 50377, 50383
	dw	50387, 50411, 50417, 50423, 50441, 50459, 50461, 50497, 50503, 50513, 50527, 50539, 50543, 50549, 50551, 50581, 50587, 50591, 50593, 50599, 50627, 50647, 50651, 50671, 50683, 50707, 50723, 50741, 50753, 50767, 50773, 50777, 50789, 50821, 50833, 50839, 50849, 50857, 50867, 50873, 50891, 50893, 50909, 50923, 50929, 50951, 50957, 50969, 50971, 50989, 50993, 51001, 51031, 51043, 51047, 51059, 51061, 51071, 51109, 51131, 51133, 51137, 51151, 51157, 51169, 51193, 51197, 51199, 51203, 51217, 51229, 51239, 51241, 51257, 51263, 51283, 51287, 51307, 51329, 51341, 51343, 51347, 51349, 51361, 51383, 51407, 51413, 51419, 51421, 51427, 51431, 51437, 51439, 51449, 51461, 51473, 51479, 51481, 51487, 51503, 51511, 51517, 51521, 51539, 51551, 51563, 51577, 51581, 51593, 51599
	dw	51607, 51613, 51631, 51637, 51647, 51659, 51673, 51679, 51683, 51691, 51713, 51719, 51721, 51749, 51767, 51769, 51787, 51797, 51803, 51817, 51827, 51829, 51839, 51853, 51859, 51869, 51871, 51893, 51899, 51907, 51913, 51929, 51941, 51949, 51971, 51973, 51977, 51991, 52009, 52021, 52027, 52051, 52057, 52067, 52069, 52081, 52103, 52121, 52127, 52147, 52153, 52163, 52177, 52181, 52183, 52189, 52201, 52223, 52237, 52249, 52253, 52259, 52267, 52289, 52291, 52301, 52313, 52321, 52361, 52363, 52369, 52379, 52387, 52391, 52433, 52453, 52457, 52489, 52501, 52511, 52517, 52529, 52541, 52543, 52553, 52561, 52567, 52571, 52579, 52583, 52609, 52627, 52631, 52639, 52667, 52673, 52691, 52697, 52709, 52711, 52721, 52727, 52733, 52747, 52757, 52769, 52783, 52807, 52813, 52817
	dw	52837, 52859, 52861, 52879, 52883, 52889, 52901, 52903, 52919, 52937, 52951, 52957, 52963, 52967, 52973, 52981, 52999, 53003, 53017, 53047, 53051, 53069, 53077, 53087, 53089, 53093, 53101, 53113, 53117, 53129, 53147, 53149, 53161, 53171, 53173, 53189, 53197, 53201, 53231, 53233, 53239, 53267, 53269, 53279, 53281, 53299, 53309, 53323, 53327, 53353, 53359, 53377, 53381, 53401, 53407, 53411, 53419, 53437, 53441, 53453, 53479, 53503, 53507, 53527, 53549, 53551, 53569, 53591, 53593, 53597, 53609, 53611, 53617, 53623, 53629, 53633, 53639, 53653, 53657, 53681, 53693, 53699, 53717, 53719, 53731, 53759, 53773, 53777, 53783, 53791, 53813, 53819, 53831, 53849, 53857, 53861, 53881, 53887, 53891, 53897, 53899, 53917, 53923, 53927, 53939, 53951, 53959, 53987, 53993, 54001
	dw	54011, 54013, 54037, 54049, 54059, 54083, 54091, 54101, 54121, 54133, 54139, 54151, 54163, 54167, 54181, 54193, 54217, 54251, 54269, 54277, 54287, 54293, 54311, 54319, 54323, 54331, 54347, 54361, 54367, 54371, 54377, 54401, 54403, 54409, 54413, 54419, 54421, 54437, 54443, 54449, 54469, 54493, 54497, 54499, 54503, 54517, 54521, 54539, 54541, 54547, 54559, 54563, 54577, 54581, 54583, 54601, 54617, 54623, 54629, 54631, 54647, 54667, 54673, 54679, 54709, 54713, 54721, 54727, 54751, 54767, 54773, 54779, 54787, 54799, 54829, 54833, 54851, 54869, 54877, 54881, 54907, 54917, 54919, 54941, 54949, 54959, 54973, 54979, 54983, 55001, 55009, 55021, 55049, 55051, 55057, 55061, 55073, 55079, 55103, 55109, 55117, 55127, 55147, 55163, 55171, 55201, 55207, 55213, 55217, 55219
	dw	55229, 55243, 55249, 55259, 55291, 55313, 55331, 55333, 55337, 55339, 55343, 55351, 55373, 55381, 55399, 55411, 55439, 55441, 55457, 55469, 55487, 55501, 55511, 55529, 55541, 55547, 55579, 55589, 55603, 55609, 55619, 55621, 55631, 55633, 55639, 55661, 55663, 55667, 55673, 55681, 55691, 55697, 55711, 55717, 55721, 55733, 55763, 55787, 55793, 55799, 55807, 55813, 55817, 55819, 55823, 55829, 55837, 55843, 55849, 55871, 55889, 55897, 55901, 55903, 55921, 55927, 55931, 55933, 55949, 55967, 55987, 55997, 56003, 56009, 56039, 56041, 56053, 56081, 56087, 56093, 56099, 56101, 56113, 56123, 56131, 56149, 56167, 56171, 56179, 56197, 56207, 56209, 56237, 56239, 56249, 56263, 56267, 56269, 56299, 56311, 56333, 56359, 56369, 56377, 56383, 56393, 56401, 56417, 56431, 56437
	dw	56443, 56453, 56467, 56473, 56477, 56479, 56489, 56501, 56503, 56509, 56519, 56527, 56531, 56533, 56543, 56569, 56591, 56597, 56599, 56611, 56629, 56633, 56659, 56663, 56671, 56681, 56687, 56701, 56711, 56713, 56731, 56737, 56747, 56767, 56773, 56779, 56783, 56807, 56809, 56813, 56821, 56827, 56843, 56857, 56873, 56891, 56893, 56897, 56909, 56911, 56921, 56923, 56929, 56941, 56951, 56957, 56963, 56983, 56989, 56993, 56999, 57037, 57041, 57047, 57059, 57073, 57077, 57089, 57097, 57107, 57119, 57131, 57139, 57143, 57149, 57163, 57173, 57179, 57191, 57193, 57203, 57221, 57223, 57241, 57251, 57259, 57269, 57271, 57283, 57287, 57301, 57329, 57331, 57347, 57349, 57367, 57373, 57383, 57389, 57397, 57413, 57427, 57457, 57467, 57487, 57493, 57503, 57527, 57529, 57557
	dw	57559, 57571, 57587, 57593, 57601, 57637, 57641, 57649, 57653, 57667, 57679, 57689, 57697, 57709, 57713, 57719, 57727, 57731, 57737, 57751, 57773, 57781, 57787, 57791, 57793, 57803, 57809, 57829, 57839, 57847, 57853, 57859, 57881, 57899, 57901, 57917, 57923, 57943, 57947, 57973, 57977, 57991, 58013, 58027, 58031, 58043, 58049, 58057, 58061, 58067, 58073, 58099, 58109, 58111, 58129, 58147, 58151, 58153, 58169, 58171, 58189, 58193, 58199, 58207, 58211, 58217, 58229, 58231, 58237, 58243, 58271, 58309, 58313, 58321, 58337, 58363, 58367, 58369, 58379, 58391, 58393, 58403, 58411, 58417, 58427, 58439, 58441, 58451, 58453, 58477, 58481, 58511, 58537, 58543, 58549, 58567, 58573, 58579, 58601, 58603, 58613, 58631, 58657, 58661, 58679, 58687, 58693, 58699, 58711, 58727
	dw	58733, 58741, 58757, 58763, 58771, 58787, 58789, 58831, 58889, 58897, 58901, 58907, 58909, 58913, 58921, 58937, 58943, 58963, 58967, 58979, 58991, 58997, 59009, 59011, 59021, 59023, 59029, 59051, 59053, 59063, 59069, 59077, 59083, 59093, 59107, 59113, 59119, 59123, 59141, 59149, 59159, 59167, 59183, 59197, 59207, 59209, 59219, 59221, 59233, 59239, 59243, 59263, 59273, 59281, 59333, 59341, 59351, 59357, 59359, 59369, 59377, 59387, 59393, 59399, 59407, 59417, 59419, 59441, 59443, 59447, 59453, 59467, 59471, 59473, 59497, 59509, 59513, 59539, 59557, 59561, 59567, 59581, 59611, 59617, 59621, 59627, 59629, 59651, 59659, 59663, 59669, 59671, 59693, 59699, 59707, 59723, 59729, 59743, 59747, 59753, 59771, 59779, 59791, 59797, 59809, 59833, 59863, 59879, 59887, 59921
	dw	59929, 59951, 59957, 59971, 59981, 59999, 60013, 60017, 60029, 60037, 60041, 60077, 60083, 60089, 60091, 60101, 60103, 60107, 60127, 60133, 60139, 60149, 60161, 60167, 60169, 60209, 60217, 60223, 60251, 60257, 60259, 60271, 60289, 60293, 60317, 60331, 60337, 60343, 60353, 60373, 60383, 60397, 60413, 60427, 60443, 60449, 60457, 60493, 60497, 60509, 60521, 60527, 60539, 60589, 60601, 60607, 60611, 60617, 60623, 60631, 60637, 60647, 60649, 60659, 60661, 60679, 60689, 60703, 60719, 60727, 60733, 60737, 60757, 60761, 60763, 60773, 60779, 60793, 60811, 60821, 60859, 60869, 60887, 60889, 60899, 60901, 60913, 60917, 60919, 60923, 60937, 60943, 60953, 60961, 61001, 61007, 61027, 61031, 61043, 61051, 61057, 61091, 61099, 61121, 61129, 61141, 61151, 61153, 61169, 61211
	dw	61223, 61231, 61253, 61261, 61283, 61291, 61297, 61331, 61333, 61339, 61343, 61357, 61363, 61379, 61381, 61403, 61409, 61417, 61441, 61463, 61469, 61471, 61483, 61487, 61493, 61507, 61511, 61519, 61543, 61547, 61553, 61559, 61561, 61583, 61603, 61609, 61613, 61627, 61631, 61637, 61643, 61651, 61657, 61667, 61673, 61681, 61687, 61703, 61717, 61723, 61729, 61751, 61757, 61781, 61813, 61819, 61837, 61843, 61861, 61871, 61879, 61909, 61927, 61933, 61949, 61961, 61967, 61979, 61981, 61987, 61991, 62003, 62011, 62017, 62039, 62047, 62053, 62057, 62071, 62081, 62099, 62119, 62129, 62131, 62137, 62141, 62143, 62171, 62189, 62191, 62201, 62207, 62213, 62219, 62233, 62273, 62297, 62299, 62303, 62311, 62323, 62327, 62347, 62351, 62383, 62401, 62417, 62423, 62459, 62467
	dw	62473, 62477, 62483, 62497, 62501, 62507, 62533, 62539, 62549, 62563, 62581, 62591, 62597, 62603, 62617, 62627, 62633, 62639, 62653, 62659, 62683, 62687, 62701, 62723, 62731, 62743, 62753, 62761, 62773, 62791, 62801, 62819, 62827, 62851, 62861, 62869, 62873, 62897, 62903, 62921, 62927, 62929, 62939, 62969, 62971, 62981, 62983, 62987, 62989, 63029, 63031, 63059, 63067, 63073, 63079, 63097, 63103, 63113, 63127, 63131, 63149, 63179, 63197, 63199, 63211, 63241, 63247, 63277, 63281, 63299, 63311, 63313, 63317, 63331, 63337, 63347, 63353, 63361, 63367, 63377, 63389, 63391, 63397, 63409, 63419, 63421, 63439, 63443, 63463, 63467, 63473, 63487, 63493, 63499, 63521, 63527, 63533, 63541, 63559, 63577, 63587, 63589, 63599, 63601, 63607, 63611, 63617, 63629, 63647, 63649
	dw	63659, 63667, 63671, 63689, 63691, 63697, 63703, 63709, 63719, 63727, 63737, 63743, 63761, 63773, 63781, 63793, 63799, 63803, 63809, 63823, 63839, 63841, 63853, 63857, 63863, 63901, 63907, 63913, 63929, 63949, 63977, 63997, 64007, 64013, 64019, 64033, 64037, 64063, 64067, 64081, 64091, 64109, 64123, 64151, 64153, 64157, 64171, 64187, 64189, 64217, 64223, 64231, 64237, 64271, 64279, 64283, 64301, 64303, 64319, 64327, 64333, 64373, 64381, 64399, 64403, 64433, 64439, 64451, 64453, 64483, 64489, 64499, 64513, 64553, 64567, 64577, 64579, 64591, 64601, 64609, 64613, 64621, 64627, 64633, 64661, 64663, 64667, 64679, 64693, 64709, 64717, 64747, 64763, 64781, 64783, 64793, 64811, 64817, 64849, 64853, 64871, 64877, 64879, 64891, 64901, 64919, 64921, 64927, 64937, 64951
	dw	64969, 64997, 65003, 65011, 65027, 65029, 65033, 65053, 65063, 65071, 65089, 65099, 65101, 65111, 65119, 65123, 65129, 65141, 65147, 65167, 65171, 65173, 65179, 65183, 65203, 65213, 65239, 65257, 65267, 65269, 65287, 65293, 65309, 65323, 65327, 65353, 65357, 65371, 65381, 65393, 65407, 65413, 65419, 65423, 65437, 65447, 65449, 65479, 65497, 65519, 65521
end if

if used bigint_invmodtable | defined include_everything

dalign
bigint_invmodtable:
	dw 0, 2, 3, 4, 6, 7, 9, 10, 12, 15, 16, 19, 21, 22, 24, 27, 30, 31, 34, 36, 37, 40, 42, 45, 49, 51, 52, 54, 55, 57, 64, 66, 69, 70, 75, 76, 79, 82, 84, 87, 90, 91, 96, 97, 99, 100, 106, 112, 114, 115, 117, 120, 121, 126, 129, 132, 135, 136, 139, 141, 142, 147, 154, 156, 157, 159, 166, 169, 174, 175, 177, 180, 184, 187, 190, 192, 195, 199, 201, 205, 210, 211, 216, 217, 220, 222, 225, 229, 231, 232, 234, 240, 244, 246, 250, 252, 255, 261, 262, 271, 274, 279, 282, 285, 286, 289, 294, 297, 300, 301, 304, 307, 309, 310, 316, 321, 322, 324, 327, 330, 331, 337, 339, 342, 346, 351, 355, 360, 364, 367, 370, 372, 376, 379, 381, 385, 387, 394, 399, 405, 406, 411, 412, 414, 415, 420, 427, 429, 430, 432, 439, 441, 442, 444, 454, 456, 460, 465, 469, 471, 474, 477, 484, 486, 489, 492, 496, 499, 505, 507, 510, 511, 516, 517, 520, 525, 526, 531, 532, 535, 544, 546, 547, 549, 552, 555, 559, 562, 565, 576, 577, 582, 586, 591, 594, 597, 601, 607, 609, 612, 615, 616, 619, 625, 630, 639, 640, 642, 645, 646, 649, 651, 652, 654, 660, 661, 664, 681, 684, 687, 691, 700, 705, 712, 714, 715, 717, 720, 724, 726, 727, 730, 736, 741, 742, 744, 745, 747, 750, 756, 762, 766, 772, 775, 777, 780, 784, 786, 790, 792, 799, 801, 804, 805, 807, 810, 811, 814, 819, 829, 832, 834, 835, 847, 849, 850, 855, 861, 862, 867, 871, 874, 877, 880, 889, 892, 894, 895, 901, 906, 912, 916, 924, 931, 934, 936, 937, 939, 940, 945, 951, 954, 957, 966, 967, 975, 976, 987, 990, 994, 997, 999, 1000, 1002, 1006, 1009, 1014, 1015, 1020, 1027, 1032, 1035, 1041, 1042, 1044, 1045, 1050, 1056, 1057, 1065, 1066, 1069, 1071, 1072, 1077, 1081, 1090, 1102, 1104, 1107, 1111, 1119, 1120, 1122, 1126, 1134, 1135, 1137, 1141, 1144, 1147, 1149, 1155, 1156, 1167, 1170, 1171, 1174, 1176, 1179, 1186, 1189, 1191, 1192, 1195, 1197, 1200, 1206, 1209, 1212, 1219, 1221, 1224, 1230, 1234, 1237, 1239, 1252, 1261, 1266, 1270, 1272, 1275, 1276, 1279, 1290, 1296, 1297, 1305, 1309, 1311, 1317, 1324, 1329, 1330, 1332, 1336, 1339, 1342, 1344, 1345, 1347, 1350, 1354, 1356, 1357, 1360, 1365, 1366, 1371, 1375, 1377, 1384, 1389, 1395, 1396, 1399, 1401, 1402, 1410, 1417, 1419, 1422, 1426, 1429, 1431, 1440, 1444, 1449, 1452, 1455, 1459, 1464, 1470, 1477, 1479, 1482, 1485, 1486, 1500, 1501, 1506, 1510, 1512, 1519, 1521, 1525, 1531, 1534, 1540, 1542, 1545, 1555, 1560, 1561, 1569, 1582, 1584, 1585, 1591, 1594, 1596, 1602, 1605, 1609, 1611, 1615, 1626, 1627, 1629, 1630, 1636, 1650, 1651, 1654, 1657, 1660, 1662, 1665, 1666, 1672, 1674, 1680, 1681, 1686, 1687, 1695, 1696, 1704, 1707, 1717, 1725, 1729, 1731, 1732, 1734, 1735, 1746, 1750, 1756, 1759, 1764, 1765, 1767, 1770, 1771, 1774, 1779, 1780, 1786, 1791, 1792, 1797, 1804, 1807, 1809, 1812, 1816, 1819, 1822, 1830, 1836, 1837, 1839, 1846, 1849, 1851, 1855, 1860, 1864, 1867, 1870, 1881, 1884, 1885, 1890, 1897, 1899, 1902, 1911, 1912, 1917, 1924, 1926, 1927, 1932, 1939, 1941, 1945, 1954, 1956, 1959, 1960, 1962, 1965, 1966, 1972, 1974, 1984, 1995, 2001, 2002, 2004, 2007, 2010, 2011, 2014, 2025, 2026, 2029, 2037, 2040, 2046, 2047, 2050, 2056, 2064, 2065, 2067, 2070, 2077, 2079, 2080, 2089, 2101, 2106, 2109, 2110, 2115, 2116, 2121, 2122, 2127, 2130, 2131, 2136, 2137, 2142, 2145, 2149, 2164, 2169, 2170, 2175, 2179, 2182, 2187, 2196, 2199, 2205, 2211, 2212, 2221, 2224, 2226, 2229, 2232, 2241, 2242, 2247, 2254, 2257, 2259, 2260, 2262, 2274, 2275, 2281, 2284, 2292, 2296, 2299, 2302, 2311, 2319, 2320, 2322, 2325, 2326, 2329, 2332, 2337, 2340, 2346, 2352, 2361, 2362, 2365, 2367, 2376, 2380, 2392, 2394, 2395, 2397, 2400, 2401, 2407, 2409, 2416, 2431, 2436, 2439, 2445, 2452, 2455, 2460, 2466, 2467, 2469, 2472, 2476, 2479, 2484, 2485, 2487, 2494, 2497, 2500, 2502, 2505, 2506, 2511, 2512, 2520, 2526, 2530, 2539, 2541, 2544, 2550, 2551, 2554, 2557, 2560, 2574, 2577, 2584, 2586, 2590, 2595, 2599, 2605, 2614, 2616, 2617, 2619, 2631, 2637, 2640, 2641, 2649, 2652, 2655, 2662, 2667, 2674, 2676, 2691, 2694, 2697, 2700, 2704, 2707, 2709, 2710, 2716, 2719, 2721, 2722, 2725, 2736, 2739, 2740, 2742, 2751, 2752, 2754, 2760, 2761, 2764, 2766, 2779, 2782, 2785, 2787, 2791, 2796, 2812, 2820, 2821, 2824, 2826, 2827, 2829, 2830, 2835, 2842, 2845, 2847, 2851, 2856, 2859, 2869, 2871, 2872, 2875, 2890, 2892, 2896, 2901, 2904, 2907, 2911, 2914, 2920, 2922, 2925, 2926, 2929, 2931, 2934, 2935, 2940, 2941, 2949, 2952, 2962, 2964, 2970, 2977, 2991, 2994, 3004, 3006, 3015, 3019, 3022, 3024, 3027, 3034, 3037, 3040, 3045, 3046, 3051, 3057, 3061, 3066, 3067, 3072, 3076, 3082, 3087, 3099, 3100, 3102, 3106, 3109, 3111, 3115, 3124, 3129, 3132, 3135, 3136, 3139, 3144, 3150, 3151, 3156, 3159, 3162, 3165, 3169, 3172, 3177, 3180, 3181, 3184, 3187, 3190, 3195, 3199, 3211, 3214, 3225, 3226, 3235, 3237, 3241, 3246, 3261, 3265, 3274, 3276, 3277, 3282, 3285, 3286, 3289, 3291, 3300, 3304, 3310, 3319, 3327, 3330, 3331, 3337, 3340, 3345, 3346, 3351, 3352, 3355, 3360, 3367, 3369, 3381, 3382, 3390, 3391, 3396, 3397, 3402, 3412, 3414, 3415, 3417, 3421, 3429, 3432, 3435, 3436, 3442, 3450, 3454, 3456, 3459, 3474, 3475, 3480, 3481, 3484, 3486, 3489, 3492, 3496, 3499, 3501, 3507, 3510, 3514, 3520, 3522, 3529, 3535, 3540, 3552, 3555, 3561, 3564, 3565, 3576, 3580, 3589, 3594, 3597, 3604, 3606, 3607, 3610, 3615, 3619, 3622, 3624, 3627, 3642, 3649, 3654, 3655, 3661, 3666, 3667, 3675, 3676, 3685, 3697, 3706, 3709, 3717, 3726, 3729, 3730, 3739, 3741, 3744, 3745, 3750, 3754, 3759, 3762, 3765, 3769, 3771, 3774, 3775, 3780, 3781, 3787, 3789, 3792, 3795, 3796, 3802, 3804, 3811, 3820, 3822, 3825, 3835, 3837, 3841, 3844, 3846, 3850, 3852, 3859, 3862, 3864, 3871, 3877, 3879, 3880, 3895, 3897, 3909, 3912, 3915, 3921, 3927, 3934, 3937, 3939, 3940, 3942, 3951, 3954, 3960, 3964, 3967, 3969, 3975, 3976, 3982, 3997, 4005, 4006, 4009, 4020, 4027, 4030, 4035, 4041, 4044, 4045, 4047, 4051, 4056, 4059, 4062, 4074, 4081, 4084, 4086, 4090, 4096, 4105, 4110, 4111, 4116, 4117, 4119, 4122, 4132, 4135, 4137, 4144, 4146, 4147, 4149, 4156, 4159, 4165, 4177, 4182, 4185, 4189, 4194, 4195, 4210, 4212, 4215, 4216, 4222, 4224, 4231, 4234, 4251, 4257, 4261, 4264, 4269, 4270, 4272, 4282, 4287, 4291, 4299, 4300, 4305, 4312, 4314, 4315, 4321, 4324, 4332, 4335, 4339, 4341, 4345, 4347, 4350, 4354, 4357, 4360, 4366, 4369, 4371, 4374, 4377, 4381, 4390, 4392, 4402, 4404, 4410, 4411, 4416, 4419, 4420, 4425, 4431, 4432, 4434, 4444, 4447, 4462, 4465, 4467, 4471, 4476, 4482, 4485, 4486, 4500, 4501, 4504, 4506, 4507, 4515, 4521, 4522, 4525, 4530, 4534, 4546, 4552, 4555, 4564, 4567, 4569, 4576, 4579, 4581, 4587, 4591, 4594, 4600, 4602, 4605, 4611, 4614, 4620, 4621, 4629, 4639, 4641, 4642, 4647, 4656, 4660, 4662, 4669, 4671, 4672, 4675, 4686, 4689, 4696, 4699, 4702, 4707, 4710, 4711, 4716, 4717, 4719, 4720, 4731, 4732, 4734, 4737, 4740, 4746, 4749, 4756, 4761, 4767, 4770, 4774, 4776, 4794, 4801, 4807, 4810, 4812, 4815, 4816, 4822, 4825, 4831, 4839, 4840, 4845, 4849, 4860, 4861, 4867, 4870, 4872, 4875, 4884, 4885, 4891, 4894, 4896, 4902, 4906, 4909, 4915, 4917, 4920, 4926, 4929, 4930, 4936, 4942, 4944, 4951, 4954, 4962, 4965, 4966, 4971, 4975, 4984, 4987, 5004, 5005, 5019, 5020, 5031, 5034, 5035, 5040, 5046, 5047, 5050, 5052, 5056, 5067, 5070, 5071, 5076, 5080, 5082, 5085, 5089, 5091, 5097, 5106, 5112, 5122, 5124, 5127, 5130, 5134, 5136, 5137, 5145, 5151, 5152, 5157, 5161, 5166, 5167, 5169, 5172, 5179, 5185, 5196, 5200, 5214, 5215, 5217, 5227, 5229, 5230, 5232, 5239, 5244, 5250, 5251, 5257, 5265, 5266, 5280, 5284, 5295, 5299, 5301, 5304, 5307, 5314, 5316, 5320, 5326, 5329, 5332, 5334, 5344, 5346, 5355, 5356, 5362, 5365, 5367, 5370, 5377, 5386, 5391, 5395, 5400, 5416, 5419, 5424, 5427, 5430, 5431, 5434, 5442, 5445, 5446, 5452, 5455, 5469, 5470, 5475, 5479, 5487, 5490, 5494, 5497, 5502, 5514, 5524, 5529, 5530, 5535, 5536, 5542, 5544, 5547, 5557, 5559, 5560, 5566, 5575, 5580, 5581, 5586, 5587, 5589, 5599, 5607, 5620, 5622, 5626, 5629, 5631, 5637, 5640, 5644, 5650, 5656, 5659, 5661, 5665, 5676, 5677, 5685, 5692, 5697, 5700, 5706, 5712, 5719, 5722, 5724, 5734, 5736, 5742, 5745, 5746, 5749, 5752, 5760, 5764, 5775, 5776, 5790, 5794, 5797, 5799, 5809, 5811, 5817, 5829, 5839, 5841, 5845, 5850, 5851, 5859, 5860, 5866, 5872, 5889, 5890, 5892, 5895, 5901, 5904, 5907, 5911, 5914, 5916, 5917, 5920, 5932, 5934, 5944, 5949, 5952, 5955, 5962, 5964, 5967, 5970, 5971, 5977, 5980, 5985, 5986, 5991, 5994, 6004, 6006, 6019, 6021, 6022, 6025, 6036, 6037, 6049, 6051, 6054, 6055, 6057, 6060, 6072, 6075, 6079, 6081, 6082, 6099, 6102, 6106, 6114, 6120, 6121, 6126, 6127, 6132, 6135, 6139, 6141, 6145, 6151, 6162, 6165, 6172, 6174, 6187, 6189, 6190, 6196, 6201, 6205, 6207, 6211, 6217, 6219, 6226, 6229, 6237, 6240, 6244, 6246, 6249, 6252, 6256, 6259, 6264, 6270, 6271, 6274, 6277, 6285, 6289, 6292, 6295, 6301, 6306, 6307, 6310, 6319, 6321, 6324, 6327, 6330, 6336, 6345, 6349, 6352, 6357, 6361, 6370, 6372, 6379, 6382, 6391, 6396, 6400, 6405, 6411, 6412, 6415, 6421, 6427, 6445, 6447, 6450, 6454, 6456, 6459, 6460, 6462, 6471, 6477, 6480, 6484, 6487, 6490, 6492, 6501, 6502, 6504, 6505, 6517, 6519, 6522, 6525, 6532, 6547, 6550, 6552, 6555, 6561, 6564, 6574, 6576, 6580, 6582, 6586, 6589, 6592, 6594, 6609, 6610, 6615, 6621, 6625, 6630, 6634, 6646, 6649, 6655, 6657, 6664, 6666, 6669, 6670, 6684, 6691, 6699, 6700, 6706, 6709, 6711, 6721, 6726, 6729, 6732, 6735, 6739, 6744, 6750, 6757, 6762, 6769, 6777, 6784, 6789, 6796, 6799, 6807, 6810, 6814, 6817, 6825, 6835, 6840, 6841, 6844, 6846, 6847, 6849, 6855, 6856, 6861, 6862, 6865, 6876, 6879, 6880, 6882, 6891, 6895, 6900, 6904, 6915, 6916, 6921, 6930, 6937, 6939, 6940, 6942, 6951, 6952, 6954, 6957, 6961, 6966, 6967, 6982, 6984, 6999, 7000, 7005, 7006, 7015, 7017, 7026, 7029, 7036, 7041, 7042, 7044, 7054, 7072, 7075, 7077, 7080, 7087, 7089, 7099, 7104, 7111, 7122, 7125, 7126, 7141, 7147, 7152, 7161, 7162, 7164, 7171, 7174, 7185, 7194, 7195, 7201, 7204, 7206, 7210, 7212, 7216, 7219, 7224, 7225, 7231, 7240, 7245, 7252, 7260, 7267, 7269, 7272, 7275, 7276, 7279, 7281, 7282, 7296, 7297, 7311, 7314, 7315, 7317, 7320, 7327, 7329, 7335, 7342, 7350, 7357, 7359, 7362, 7366, 7369, 7371, 7374, 7377, 7380, 7384, 7386, 7390, 7392, 7399, 7407, 7411, 7414, 7416, 7422, 7426, 7434, 7435, 7440, 7444, 7446, 7449, 7462, 7465, 7470, 7474, 7476, 7479, 7485, 7492, 7507, 7509, 7516, 7527, 7531, 7537, 7539, 7542, 7546, 7551, 7554, 7561, 7566, 7569, 7570, 7575, 7581, 7587, 7594, 7597, 7600, 7609, 7614, 7617, 7621, 7630, 7632, 7635, 7636, 7639, 7644, 7645, 7650, 7654, 7657, 7660, 7665, 7666, 7675, 7680, 7681, 7687, 7689, 7692, 7696, 7701, 7707, 7714, 7720, 7722, 7726, 7731, 7734, 7737, 7747, 7749, 7756, 7764, 7771, 7776, 7780, 7785, 7791, 7792, 7801, 7804, 7810, 7815, 7821, 7822, 7824, 7825, 7831, 7834, 7836, 7840, 7842, 7864, 7866, 7867, 7869, 7870, 7875, 7881, 7884, 7887, 7894, 7896, 7899, 7902, 7905, 7909, 7912, 7930, 7939, 7941, 7944, 7945, 7951, 7954, 7957, 7960, 7962, 7969, 7980, 7986, 7987, 7996, 8001, 8004, 8017, 8029, 8031, 8032, 8034, 8035, 8037, 8044, 8046, 8049, 8052, 8056, 8064, 8070, 8071, 8092, 8094, 8095, 8097, 8109, 8112, 8115, 8116, 8125, 8127, 8134, 8137, 8151, 8160, 8167, 8170, 8175, 8181, 8182, 8185, 8191, 8206, 8209, 8211, 8214, 8217, 8224, 8226, 8227, 8239, 8241, 8244, 8247, 8260, 8265, 8274, 8277, 8281, 8284, 8287, 8302, 8304, 8310, 8316, 8317, 8325, 8326, 8329, 8331, 8337, 8346, 8347, 8350, 8352, 8365, 8371, 8374, 8380, 8382, 8394, 8406, 8412, 8415, 8416, 8422, 8436, 8440, 8442, 8445, 8451, 8452, 8461, 8464, 8466, 8469, 8472, 8482, 8490, 8491, 8494, 8497, 8506, 8511, 8514, 8515, 8517, 8521, 8524, 8527, 8539, 8547, 8550, 8554, 8559, 8562, 8569, 8580, 8584, 8592, 8595, 8596, 8602, 8604, 8605, 8616, 8620, 8629, 8646, 8647, 8650, 8659, 8661, 8664, 8667, 8671, 8676, 8680, 8689, 8692, 8694, 8695, 8697, 8701, 8709, 8710, 8716, 8722, 8725, 8734, 8736, 8739, 8742, 8745, 8746, 8749, 8755, 8760, 8770, 8776, 8785, 8787, 8790, 8791, 8799, 8800, 8805, 8812, 8814, 8829, 8830, 8835, 8841, 8842, 8854, 8857, 8865, 8869, 8874, 8875, 8881, 8892, 8895, 8896, 8904, 8914, 8919, 8920, 8926, 8932, 8941, 8946, 8952, 8955, 8956, 8961, 8962, 8965, 8970, 8979, 8980, 8986, 8989, 8991, 8994, 8995, 9007, 9021, 9022, 9024, 9025, 9030, 9031, 9039, 9045, 9049, 9060, 9061, 9064, 9066, 9067, 9072, 9075, 9085, 9091, 9096, 9100, 9106, 9109, 9112, 9115, 9117, 9126, 9127, 9129, 9135, 9144, 9145, 9151, 9154, 9156, 9157, 9165, 9171, 9177, 9184, 9186, 9190, 9199, 9201, 9207, 9214, 9217, 9220, 9222, 9226, 9229, 9231, 9241, 9247, 9252, 9259, 9261, 9262, 9270, 9271, 9277, 9292, 9294, 9297, 9309, 9319, 9331, 9336, 9340, 9346, 9351, 9357, 9360, 9366, 9372, 9375, 9379, 9387, 9394, 9397, 9399, 9402, 9420, 9430, 9435, 9450, 9456, 9457, 9459, 9460, 9474, 9480, 9487, 9490, 9501, 9505, 9507, 9516, 9519, 9526, 9535, 9537, 9540, 9541, 9544, 9561, 9570, 9571, 9579, 9582, 9591, 9592, 9604, 9606, 9607, 9610, 9616, 9619, 9625, 9630, 9634, 9637, 9645, 9651, 9655, 9660, 9667, 9687, 9690, 9691, 9694, 9696, 9702, 9709, 9711, 9712, 9714, 9715, 9717, 9721, 9724, 9729, 9732, 9735, 9736, 9739, 9742, 9745, 9751, 9754, 9766, 9771, 9772, 9777, 9780, 9786, 9789, 9792, 9799, 9802, 9805, 9831, 9841, 9844, 9849, 9850, 9855, 9859, 9864, 9870, 9876, 9877, 9880, 9882, 9889, 9897, 9901, 9907, 9910, 9921, 9922, 9927, 9931, 9934, 9945, 9946, 9957, 9960, 9964, 9969, 9975, 9981, 9982, 9987, 9990, 9996, 9997, 9999, 10006, 10011, 10012, 10015, 10024, 10026, 10032, 10036, 10045, 10051, 10054, 10057, 10059, 10062, 10065, 10072, 10074, 10075, 10081, 10087, 10089, 10092, 10101, 10110, 10116, 10117, 10125, 10131, 10135, 10144, 10149, 10162, 10164, 10167, 10171, 10174, 10177, 10179, 10180, 10185, 10195, 10197, 10200, 10204, 10206, 10216, 10221, 10222, 10239, 10240, 10242, 10254, 10255, 10261, 10267, 10272, 10275, 10276, 10282, 10297, 10300, 10306, 10314, 10320, 10321, 10332, 10341, 10347, 10354, 10359, 10360, 10366, 10372, 10374, 10375, 10377, 10380, 10386, 10387, 10395, 10404, 10405, 10425, 10429, 10437, 10440, 10444, 10449, 10450, 10452, 10461, 10465, 10470, 10474, 10480, 10482, 10491, 10492, 10501, 10506, 10507, 10509, 10510, 10512, 10516, 10530, 10531, 10534, 10545, 10551, 10554, 10561, 10570, 10572, 10575, 10579, 10582, 10585, 10590, 10594, 10596, 10597, 10606, 10611, 10614, 10624, 10635, 10639, 10642, 10657, 10659, 10660, 10662, 10671, 10674, 10689, 10690, 10692, 10696, 10699, 10701, 10704, 10710, 10717, 10734, 10741, 10744, 10746, 10747, 10750, 10752, 10759, 10761, 10762, 10765, 10779, 10780, 10782, 10785, 10789, 10794, 10795, 10800, 10801, 10806, 10807, 10809, 10824, 10825, 10831, 10837, 10842, 10851, 10857, 10864, 10869, 10870, 10876, 10879, 10884, 10887, 10894, 10900, 10902, 10909, 10911, 10920, 10921, 10926, 10930, 10932, 10936, 10941, 10947, 10956, 10965, 10969, 10972, 10981, 10989, 10996, 10999, 11002, 11007, 11014, 11016, 11019, 11020, 11026, 11032, 11034, 11037, 11040, 11046, 11047, 11055, 11056, 11062, 11065, 11067, 11074, 11077, 11079, 11080, 11086, 11095, 11097, 11115, 11124, 11130, 11136, 11137, 11139, 11140, 11142, 11146, 11152, 11154, 11172, 11175, 11184, 11185, 11191, 11196, 11199, 11205, 11217, 11221, 11224, 11227, 11235, 11241, 11242, 11251, 11256, 11266, 11271, 11272, 11275, 11284, 11286, 11287, 11307, 11310, 11311, 11319, 11320, 11322, 11326, 11335, 11340, 11346, 11349, 11350, 11355, 11359, 11361, 11364, 11370, 11371, 11376, 11385, 11389, 11392, 11394, 11404, 11406, 11409, 11427, 11430, 11431, 11436, 11439, 11451, 11454, 11461, 11469, 11472, 11481, 11482, 11487, 11497, 11502, 11506, 11509, 11511, 11514, 11515, 11520, 11521, 11527, 11529, 11530, 11532, 11536, 11541, 11544, 11550, 11559, 11566, 11572, 11580, 11584, 11587, 11595, 11599, 11601, 11602, 11605, 11614, 11626, 11635, 11640, 11646, 11647, 11649, 11656, 11661, 11664, 11667, 11670, 11679, 11685, 11686, 11700, 11709, 11716, 11724, 11730, 11737, 11749, 11755, 11766, 11769, 11770, 11775, 11779, 11781, 11782, 11784, 11791, 11797, 11800, 11802, 11805, 11812, 11814, 11815, 11817, 11832, 11835, 11836, 11839, 11844, 11845, 11860, 11871, 11872, 11874, 11877, 11881, 11884, 11887, 11895, 11901, 11907, 11910, 11914, 11916, 11917, 11929, 11935, 11937, 11940, 11944, 11947, 11950, 11955, 11956, 11959, 11965, 11979, 11986, 11989, 11991, 11997, 12001, 12004, 12010, 12012, 12015, 12022, 12025, 12031, 12036, 12039, 12042, 12046, 12049, 12052, 12054, 12055, 12057, 12061, 12067, 12069, 12076, 12085, 12090, 12091, 12099, 12102, 12112, 12115, 12120, 12124, 12126, 12141, 12159, 12165, 12169, 12180, 12186, 12187, 12190, 12196, 12204, 12207, 12210, 12211, 12220, 12222, 12235, 12237, 12241, 12250, 12255, 12259, 12264, 12267, 12274, 12276, 12286, 12297, 12306, 12312, 12316, 12330, 12336, 12339, 12342, 12346, 12349, 12355, 12367, 12375, 12382, 12384, 12391, 12397, 12400, 12405, 12411, 12421, 12424, 12426, 12430, 12439, 12445, 12454, 12459, 12460, 12462, 12472, 12477, 12484, 12486, 12489, 12490, 12495, 12507, 12516, 12517, 12519, 12529, 12537, 12544, 12549, 12556, 12559, 12561, 12564, 12574, 12577, 12582, 12585, 12586, 12592, 12595, 12610, 12615, 12619, 12622, 12624, 12627, 12631, 12651, 12652, 12654, 12655, 12661, 12670, 12672, 12675, 12679, 12684, 12687, 12696, 12705, 12706, 12712, 12720, 12724, 12727, 12729, 12732, 12735, 12736, 12762, 12769, 12771, 12781, 12789, 12790, 12792, 12795, 12801, 12802, 12805, 12811, 12817, 12820, 12822, 12829, 12834, 12837, 12840, 12847, 12852, 12859, 12867, 12871, 12874, 12880, 12882, 12886, 12897, 12900, 12901, 12910, 12921, 12924, 12925, 12934, 12937, 12945, 12952, 12957, 12960, 12966, 12967, 12970, 12972, 12976, 12985, 12991, 12999, 13000, 13002, 13009, 13011, 13015, 13021, 13027, 13042, 13050, 13054, 13056, 13057, 13060, 13071, 13077, 13081, 13086, 13089, 13092, 13095, 13102, 13105, 13114, 13119, 13125, 13126, 13131, 13132, 13134, 13147, 13149, 13155, 13159, 13161, 13170, 13174, 13179, 13186, 13194, 13197, 13200, 13204, 13209, 13212, 13216, 13219, 13225, 13230, 13240, 13245, 13249, 13251, 13257, 13270, 13279, 13281, 13287, 13296, 13299, 13314, 13317, 13321, 13324, 13335, 13341, 13342, 13344, 13347, 13350, 13351, 13356, 13357, 13359, 13362, 13365, 13366, 13369, 13380, 13389, 13392, 13401, 13407, 13411, 13417, 13420, 13425, 13431, 13432, 13440, 13441, 13446, 13447, 13452, 13461, 13464, 13474, 13476, 13477, 13480, 13491, 13494, 13497, 13506, 13509, 13516, 13522, 13530, 13531, 13534, 13537, 13539, 13546, 13552, 13554, 13555, 13564, 13572, 13590, 13596, 13599, 13606, 13620, 13621, 13627, 13630, 13636, 13639, 13641, 13642, 13650, 13665, 13669, 13681, 13684, 13699, 13704, 13705, 13714, 13716, 13719, 13725, 13729, 13740, 13741, 13744, 13755, 13764, 13765, 13770, 13771, 13776, 13791, 13792, 13806, 13809, 13816, 13824, 13827, 13837, 13845, 13846, 13849, 13851, 13867, 13869, 13870, 13872, 13875, 13876, 13882, 13884, 13887, 13890, 13896, 13897, 13900, 13902, 13905, 13909, 13912, 13914, 13924, 13926, 13942, 13947, 13951, 13959, 13960, 13971, 13972, 13974, 13977, 13981, 13984, 13992, 13999, 14001, 14010, 14014, 14016, 14026, 14029, 14035, 14041, 14044, 14049, 14050, 14055, 14056, 14062, 14076, 14082, 14091, 14092, 14101, 14106, 14110, 14115, 14139, 14140, 14142, 14145, 14149, 14154, 14155, 14160, 14175, 14176, 14194, 14197, 14202, 14205, 14206, 14215, 14217, 14220, 14224, 14232, 14239, 14247, 14250, 14257, 14259, 14269, 14271, 14274, 14275, 14280, 14286, 14287, 14290, 14296, 14299, 14302, 14304, 14310, 14311, 14314, 14316, 14322, 14325, 14329, 14331, 14332, 14335, 14344, 14349, 14352, 14356, 14362, 14365, 14376, 14377, 14380, 14386, 14395, 14397, 14404, 14407, 14409, 14419, 14422, 14430, 14434, 14436, 14440, 14451, 14455, 14461, 14464, 14467, 14475, 14481, 14490, 14505, 14509, 14511, 14512, 14514, 14517, 14530, 14532, 14539, 14551, 14562, 14565, 14566, 14569, 14574, 14577, 14584, 14587, 14590, 14596, 14601, 14604, 14605, 14611, 14616, 14622, 14626, 14635, 14644, 14649, 14652, 14656, 14664, 14667, 14670, 14674, 14682, 14692, 14694, 14695, 14700, 14701, 14706, 14712, 14715, 14719, 14722, 14727, 14737, 14742, 14751, 14764, 14766, 14769, 14784, 14785, 14787, 14791, 14794, 14800, 14806, 14815, 14817, 14821, 14832, 14835, 14836, 14842, 14859, 14862, 14871, 14877, 14880, 14881, 14895, 14902, 14910, 14917, 14919, 14926, 14932, 14934, 14937, 14940, 14941, 14959, 14961, 14964, 14974, 14980, 14992, 14995, 15006, 15007, 15015, 15024, 15030, 15036, 15045, 15046, 15049, 15052, 15055, 15057, 15060, 15067, 15069, 15070, 15081, 15085, 15091, 15094, 15099, 15102, 15106, 15112, 15121, 15127, 15130, 15135, 15136, 15147, 15154, 15157, 15160, 15162, 15171, 15174, 15184, 15195, 15196, 15202, 15214, 15216, 15225, 15234, 15235, 15246, 15247, 15249, 15255, 15259, 15265, 15270, 15277, 15279, 15280, 15289, 15297, 15316, 15319, 15322, 15325, 15331, 15336, 15339, 15345, 15349, 15352, 15354, 15357, 15364, 15379, 15382, 15387, 15391, 15402, 15405, 15409, 15415, 15420, 15421, 15426, 15427, 15430, 15435, 15436, 15441, 15447, 15456, 15466, 15469, 15471, 15475, 15486, 15489, 15492, 15507, 15510, 15517, 15520, 15526, 15532, 15535, 15540, 15541, 15546, 15561, 15562, 15570, 15574, 15576, 15577, 15580, 15589, 15591, 15592, 15595, 15597, 15610, 15612, 15616, 15619, 15624, 15625, 15627, 15630, 15634, 15636, 15639, 15654, 15660, 15661, 15664, 15667, 15669, 15679, 15690, 15694, 15696, 15697, 15699, 15735, 15739, 15741, 15745, 15756, 15757, 15759, 15766, 15771, 15772, 15774, 15784, 15787, 15792, 15801, 15804, 15814, 15822, 15825, 15829, 15832, 15834, 15844, 15850, 15861, 15862, 15864, 15865, 15871, 15876, 15885, 15886, 15897, 15900, 15909, 15924, 15925, 15930, 15937, 15942, 15946, 15954, 15979, 15982, 15987, 15991, 15996, 16002, 16005, 16014, 16015, 16026, 16029, 16030, 16032, 16035, 16039, 16042, 16045, 16050, 16059, 16060, 16071, 16072, 16080, 16087, 16092, 16095, 16096, 16102, 16107, 16117, 16119, 16126, 16129, 16131, 16149, 16150, 16152, 16155, 16161, 16162, 16164, 16171, 16177, 16180, 16182, 16185, 16186, 16189, 16191, 16201, 16206, 16207, 16212, 16215, 16221, 16222, 16234, 16240, 16246, 16249, 16252, 16254, 16266, 16267, 16269, 16281, 16282, 16285, 16287, 16290, 16294, 16302, 16305, 16306, 16311, 16317, 16324, 16327, 16344, 16347, 16354, 16357, 16359, 16360, 16375, 16386, 16390, 16392, 16395, 16399, 16401, 16402, 16416, 16417, 16420, 16422, 16435, 16444, 16455, 16456, 16459, 16467, 16470, 16471, 16479, 16485, 16486, 16492, 16494, 16497, 16500, 16507, 16512, 16515, 16519, 16525, 16527, 16536, 16537, 16542, 16546, 16554, 16557, 16560, 16575, 16576, 16581, 16590, 16591, 16596, 16600, 16602, 16606, 16612, 16624, 16644, 16645, 16651, 16656, 16659, 16665, 16666, 16672, 16674, 16675, 16677, 16680, 16689, 16696, 16702, 16705, 16707, 16714, 16729, 16731, 16735, 16740, 16744, 16747, 16752, 16761, 16765, 16767, 16774, 16782, 16785, 16789, 16791, 16794, 16795, 16800, 16801, 16807, 16809, 16810, 16812, 16815, 16819, 16821, 16824, 16840, 16852, 16857, 16861, 16870, 16875, 16876, 16879, 16884, 16885, 16887, 16896, 16899, 16905, 16906, 16914, 16915, 16926, 16929, 16932, 16936, 16945, 16947, 16956, 16962, 16966, 16969, 16971, 16981, 16984, 16999, 17010, 17016, 17017, 17020, 17029, 17031, 17062, 17064, 17065, 17071, 17074, 17079, 17080, 17086, 17092, 17106, 17107, 17109, 17116, 17127, 17130, 17131, 17134, 17137, 17142, 17149, 17151, 17152, 17157, 17160, 17164, 17169, 17176, 17181, 17184, 17185, 17191, 17202, 17211, 17215, 17220, 17229, 17235, 17236, 17242, 17244, 17250, 17251, 17256, 17257, 17260, 17269, 17272, 17275, 17292, 17295, 17296, 17302, 17304, 17307, 17316, 17325, 17326, 17334, 17337, 17340, 17344, 17347, 17352, 17361, 17365, 17370, 17374, 17379, 17380, 17382, 17391, 17404, 17410, 17421, 17422, 17424, 17425, 17436, 17439, 17442, 17449, 17457, 17460, 17470, 17475, 17481, 17482, 17491, 17512, 17514, 17526, 17527, 17530, 17535, 17541, 17542, 17545, 17550, 17554, 17556, 17559, 17565, 17571, 17575, 17577, 17580, 17586, 17601, 17611, 17614, 17626, 17629, 17634, 17640, 17641, 17646, 17656, 17659, 17662, 17664, 17670, 17677, 17682, 17691, 17697, 17701, 17704, 17710, 17712, 17719, 17724, 17725, 17731, 17746, 17754, 17755, 17761, 17764, 17766, 17767, 17769, 17772, 17785, 17787, 17796, 17797, 17799, 17802, 17809, 17836, 17839, 17865, 17866, 17874, 17877, 17880, 17886, 17899, 17901, 17902, 17905, 17916, 17919, 17920, 17926, 17932, 17935, 17940, 17949, 17950, 17956, 17962, 17967, 17976, 17982, 17985, 17989, 17992, 17997, 18000, 18004, 18006, 18007, 18009, 18019, 18031, 18034, 18037, 18042, 18049, 18054, 18055, 18066, 18069, 18076, 18081, 18094, 18096, 18105, 18109, 18115, 18121, 18126, 18132, 18135, 18139, 18147, 18150, 18154, 18157, 18160, 18171, 18172, 18177, 18187, 18192, 18195, 18217, 18226, 18229, 18234, 18235, 18237, 18240, 18247, 18249, 18262, 18264, 18265, 18271, 18276, 18280, 18282, 18286, 18292, 18294, 18300, 18304, 18315, 18319, 18322, 18327, 18336, 18339, 18342, 18346, 18349, 18355, 18357, 18361, 18370, 18375, 18381, 18384, 18390, 18391, 18394, 18396, 18397, 18405, 18411, 18417, 18424, 18429, 18436, 18439, 18444, 18450, 18451, 18457, 18460, 18462, 18465, 18466, 18472, 18474, 18487, 18490, 18499, 18502, 18507, 18510, 18511, 18520, 18525, 18529, 18531, 18544, 18549, 18559, 18562, 18570, 18580, 18586, 18591, 18595, 18600, 18601, 18609, 18612, 18622, 18627, 18637, 18639, 18654, 18655, 18657, 18661, 18669, 18670, 18679, 18681, 18682, 18685, 18690, 18699, 18705, 18712, 18721, 18724, 18732, 18742, 18745, 18747, 18751, 18754, 18756, 18759, 18765, 18769, 18774, 18775, 18781, 18784, 18786, 18787, 18790, 18795, 18796, 18804, 18810, 18817, 18822, 18825, 18829, 18832, 18846, 18847, 18850, 18859, 18874, 18891, 18892, 18900, 18906, 18907, 18916, 18924, 18927, 18931, 18936, 18940, 18945, 18949, 18954, 18976, 18979, 18982, 18984, 18994, 18996, 18997, 18999, 19006, 19020, 19024, 19027, 19035, 19042, 19057, 19060, 19075, 19077, 19084, 19089, 19092, 19095, 19099, 19101, 19110, 19116, 19119, 19120, 19131, 19137, 19141, 19144, 19150, 19152, 19159, 19161, 19164, 19165, 19167, 19176, 19186, 19189, 19197, 19216, 19224, 19225, 19227, 19230, 19231, 19251, 19272, 19279, 19281, 19284, 19285, 19297, 19302, 19305, 19306, 19315, 19320, 19326, 19327, 19335, 19336, 19339, 19347, 19350, 19354, 19356, 19357, 19362, 19365, 19369, 19374, 19375, 19384, 19392, 19396, 19402, 19411, 19417, 19420, 19426, 19431, 19434, 19437, 19446, 19452, 19459, 19461, 19462, 19467, 19477, 19480, 19486, 19489, 19497, 19510, 19512, 19521, 19522, 19524, 19540, 19545, 19549, 19552, 19554, 19557, 19560, 19567, 19570, 19579, 19581, 19582, 19591, 19596, 19600, 19605, 19609, 19614, 19615, 19617, 19620, 19621, 19626, 19647, 19651, 19657, 19659, 19662, 19671, 19672, 19680, 19684, 19686, 19687, 19692, 19699, 19705, 19710, 19720, 19722, 19726, 19731, 19750, 19752, 19755, 19756, 19761, 19771, 19776, 19782, 19785, 19791, 19804, 19810, 19812, 19816, 19830, 19834, 19836, 19840, 19852, 19855, 19860, 19864, 19867, 19875, 19881, 19885, 19890, 19896, 19900, 19911, 19914, 19915, 19920, 19921, 19924, 19929, 19932, 19935, 19939, 19942, 19944, 19951, 19965, 19969, 19977, 19986, 19990, 19992, 19995, 20005, 20007, 20016, 20019, 20020, 20032, 20044, 20047, 20050, 20056, 20062, 20064, 20065, 20076, 20077, 20082, 20085, 20089, 20095, 20097, 20107, 20116, 20119, 20121, 20127, 20139, 20142, 20145, 20172, 20176, 20179, 20181, 20194, 20212, 20214, 20215, 20217, 20230, 20236, 20242, 20244, 20247, 20250, 20254, 20260, 20265, 20266, 20272, 20280, 20289, 20292, 20296, 20299, 20305, 20314, 20319, 20320, 20347, 20349, 20350, 20355, 20370, 20376, 20380, 20382, 20386, 20394, 20401, 20407, 20410, 20412, 20415, 20421, 20424, 20425, 20427, 20434, 20440, 20442, 20449, 20452, 20464, 20467, 20470, 20475, 20481, 20487, 20497, 20506, 20509, 20512, 20520, 20524, 20526, 20529, 20539, 20541, 20557, 20559, 20566, 20571, 20572, 20575, 20581, 20589, 20590, 20592, 20595, 20601, 20602, 20607, 20611, 20614, 20616, 20617, 20622, 20629, 20632, 20635, 20641, 20650, 20667, 20671, 20676, 20679, 20691, 20694, 20695, 20700, 20706, 20707, 20722, 20727, 20734, 20740, 20746, 20754, 20757, 20760, 20761, 20770, 20772, 20775, 20790, 20797, 20799, 20802, 20805, 20806, 20809, 20811, 20814, 20821, 20824, 20826, 20830, 20835, 20841, 20844, 20860, 20865, 20869, 20880, 20881, 20886, 20889, 20901, 20905, 20907, 20922, 20925, 20926, 20932, 20940, 20944, 20947, 20949, 20952, 20956, 20964, 20971, 20974, 20977, 20979, 20980, 20985, 20991, 20992, 21000, 21007, 21009, 21010, 21012, 21022, 21031, 21036, 21037, 21042, 21045, 21051, 21066, 21070, 21079, 21085, 21090, 21091, 21094, 21097, 21099, 21105, 21111, 21112, 21114, 21120, 21129, 21141, 21142, 21147, 21150, 21154, 21162, 21166, 21169, 21175, 21180, 21187, 21190, 21196, 21199, 21202, 21204, 21205, 21217, 21219, 21222, 21226, 21229, 21231, 21232, 21234, 21237, 21244, 21246, 21250, 21255, 21267, 21279, 21285, 21286, 21289, 21295, 21306, 21321, 21322, 21325, 21334, 21339, 21342, 21345, 21349, 21351, 21352, 21355, 21360, 21364, 21369, 21372, 21376, 21384, 21387, 21394, 21397, 21399, 21411, 21415, 21420, 21421, 21427, 21430, 21432, 21450, 21451, 21462, 21465, 21469, 21472, 21477, 21481, 21484, 21490, 21495, 21502, 21507, 21510, 21519, 21525, 21526, 21532, 21534, 21547, 21552, 21559, 21567, 21576, 21580, 21589, 21595, 21601, 21604, 21612, 21619, 21631, 21636, 21642, 21646, 21657, 21660, 21661, 21666, 21696, 21699, 21700, 21702, 21706, 21714, 21721, 21726, 21729, 21741, 21744, 21750, 21759, 21771, 21772, 21787, 21789, 21790, 21796, 21799, 21804, 21805, 21807, 21814, 21817, 21825, 21826, 21831, 21835, 21846, 21856, 21859, 21861, 21877, 21880, 21889, 21891, 21892, 21894, 21895, 21897, 21901, 21927, 21934, 21945, 21946, 21957, 21967, 21972, 21976, 21981, 21982, 21985, 21987, 21994, 21996, 21999, 22009, 22011, 22014, 22015, 22021, 22027, 22030, 22036, 22044, 22045, 22051, 22056, 22060, 22062, 22065, 22066, 22080, 22086, 22090, 22095, 22101, 22102, 22104, 22111, 22125, 22129, 22132, 22134, 22135, 22137, 22140, 22141, 22147, 22176, 22179, 22186, 22191, 22192, 22195, 22209, 22225, 22227, 22242, 22246, 22249, 22251, 22254, 22260, 22266, 22267, 22269, 22272, 22275, 22282, 22290, 22294, 22309, 22311, 22312, 22317, 22321, 22324, 22326, 22329, 22342, 22344, 22350, 22351, 22356, 22365, 22371, 22377, 22386, 22387, 22389, 22395, 22399, 22405, 22410, 22420, 22422, 22426, 22434, 22440, 22444, 22447, 22455, 22459, 22464, 22470, 22477, 22480, 22482, 22486, 22492, 22494, 22504, 22507, 22527, 22531, 22539, 22542, 22560, 22561, 22564, 22566, 22569, 22570, 22581, 22590, 22591, 22596, 22599, 22617, 22624, 22630, 22632, 22641, 22645, 22647, 22654, 22659, 22660, 22665, 22669, 22671, 22672, 22681, 22689, 22695, 22702, 22707, 22714, 22717, 22720, 22741, 22746, 22749, 22752, 22762, 22767, 22771, 22777, 22779, 22785, 22794, 22795, 22800, 22807, 22816, 22821, 22830, 22834, 22837, 22839, 22846, 22849, 22854, 22869, 22876, 22879, 22882, 22884, 22890, 22909, 22911, 22912, 22914, 22917, 22921, 22927, 22932, 22935, 22944, 22947, 22972, 22975, 22977, 22980, 22986, 22990, 22995, 23011, 23014, 23025, 23026, 23031, 23037, 23046, 23047, 23050, 23052, 23067, 23071, 23074, 23077, 23086, 23091, 23092, 23094, 23100, 23110, 23115, 23119, 23131, 23136, 23137, 23140, 23151, 23154, 23155, 23164, 23169, 23175, 23176, 23191, 23200, 23206, 23220, 23221, 23224, 23226, 23229, 23236, 23239, 23245, 23250, 23254, 23256, 23262, 23275, 23280, 23284, 23287, 23295, 23296, 23301, 23310, 23317, 23320, 23322, 23325, 23332, 23340, 23341, 23344, 23346, 23352, 23362, 23364, 23374, 23376, 23379, 23385, 23386, 23404, 23406, 23409, 23410, 23415, 23416, 23427, 23431, 23434, 23439, 23445, 23451, 23460, 23467, 23479, 23497, 23499, 23509, 23521, 23526, 23529, 23530, 23544, 23547, 23556, 23560, 23562, 23565, 23569, 23572, 23574, 23575, 23581, 23595, 23604, 23611, 23619, 23626, 23635, 23640, 23644, 23647, 23649, 23652, 23655, 23659, 23670, 23676, 23677, 23682, 23691, 23694, 23695, 23704, 23709, 23710, 23716, 23721, 23730, 23746, 23749, 23751, 23754, 23757, 23761, 23764, 23767, 23772, 23782, 23785, 23791, 23796, 23800, 23805, 23812, 23815, 23820, 23827, 23829, 23830, 23841, 23850, 23851, 23856, 23857, 23859, 23869, 23871, 23872, 23889, 23890, 23896, 23899, 23904, 23905, 23910, 23919, 23922, 23929, 23935, 23941, 23952, 23956, 23959, 23967, 23970, 23974, 23976, 23982, 23985, 23989, 23991, 24009, 24012, 24015, 24025, 24037, 24040, 24046, 24055, 24060, 24061, 24066, 24079, 24082, 24090, 24094, 24097, 24099, 24111, 24120, 24124, 24130, 24136, 24141, 24150, 24156, 24157, 24169, 24171, 24177, 24186, 24192, 24199, 24204, 24205, 24207, 24219, 24225, 24232, 24237, 24240, 24241, 24244, 24246, 24249, 24262, 24264, 24267, 24270, 24271, 24282, 24286, 24295, 24297, 24306, 24310, 24312, 24324, 24325, 24331, 24337, 24339, 24340, 24366, 24367, 24376, 24379, 24381, 24384, 24390, 24391, 24394, 24400, 24405, 24409, 24411, 24412, 24424, 24429, 24430, 24435, 24436, 24442, 24445, 24454, 24474, 24477, 24487, 24495, 24496, 24502, 24505, 24510, 24516, 24517, 24519, 24522, 24529, 24535, 24541, 24552, 24555, 24559, 24561, 24562, 24570, 24579, 24585, 24586, 24589, 24597, 24600, 24601, 24604, 24606, 24612, 24627, 24631, 24639, 24640, 24649, 24654, 24666, 24667, 24670, 24682, 24684, 24685, 24696, 24697, 24705, 24706, 24709, 24715, 24717, 24726, 24730, 24732, 24739, 24741, 24750, 24762, 24765, 24766, 24769, 24774, 24775, 24780, 24799, 24802, 24807, 24814, 24817, 24820, 24832, 24834, 24835, 24841, 24849, 24856, 24864, 24870, 24871, 24874, 24879, 24892, 24894, 24895, 24901, 24904, 24906, 24912, 24916, 24922, 24927, 24936, 24939, 24946, 24960, 24961, 24964, 24969, 24970, 24972, 24979, 24996, 24997, 25000, 25011, 25012, 25017, 25024, 25026, 25027, 25035, 25039, 25044, 25047, 25051, 25056, 25060, 25062, 25065, 25066, 25074, 25077, 25080, 25089, 25104, 25111, 25114, 25116, 25131, 25132, 25137, 25144, 25146, 25156, 25161, 25165, 25167, 25171, 25180, 25182, 25189, 25192, 25194, 25206, 25209, 25212, 25221, 25230, 25231, 25249, 25252, 25257, 25264, 25270, 25272, 25275, 25276, 25291, 25294, 25296, 25297, 25300, 25314, 25324, 25326, 25336, 25342, 25354, 25362, 25371, 25377, 25384, 25387, 25389, 25395, 25411, 25417, 25420, 25425, 25429, 25434, 25437, 25446, 25447, 25455, 25462, 25465, 25476, 25479, 25485, 25486, 25495, 25497, 25501, 25516, 25522, 25524, 25530, 25531, 25536, 25555, 25566, 25567, 25569, 25576, 25579, 25585, 25597, 25599, 25600, 25602, 25609, 25615, 25620, 25621, 25629, 25632, 25642, 25644, 25654, 25665, 25671, 25672, 25674, 25675, 25681, 25692, 25704, 25707, 25710, 25711, 25714, 25716, 25719, 25720, 25725, 25731, 25737, 25740, 25741, 25744, 25752, 25756, 25759, 25761, 25770, 25776, 25782, 25789, 25791, 25797, 25800, 25804, 25807, 25816, 25819, 25824, 25830, 25837, 25840, 25842, 25846, 25857, 25860, 25861, 25875, 25884, 25885, 25894, 25899, 25902, 25909, 25914, 25915, 25920, 25927, 25930, 25935, 25936, 25947, 25950, 25954, 25957, 25965, 25971, 25975, 25986, 25987, 25989, 25996, 26005, 26011, 26014, 26026, 26029, 26034, 26035, 26041, 26052, 26061, 26064, 26074, 26077, 26082, 26089, 26091, 26092, 26095, 26101, 26112, 26119, 26125, 26127, 26130, 26134, 26145, 26146, 26151, 26157, 26161, 26181, 26182, 26185, 26190, 26194, 26196, 26217, 26227, 26229, 26245, 26251, 26256, 26259, 26265, 26271, 26272, 26277, 26281, 26284, 26286, 26290, 26292, 26305, 26314, 26316, 26320, 26334, 26337, 26346, 26349, 26355, 26356, 26361, 26364, 26367, 26374, 26379, 26385, 26392, 26404, 26407, 26409, 26419, 26430, 26431, 26440, 26442, 26445, 26451, 26452, 26460, 26469, 26476, 26479, 26482, 26484, 26487, 26491, 26500, 26502, 26509, 26524, 26526, 26535, 26539, 26544, 26545, 26547, 26551, 26557, 26559, 26565, 26574, 26575, 26581, 26586, 26587, 26595, 26599, 26601, 26616, 26617, 26620, 26634, 26635, 26640, 26641, 26650, 26655, 26662, 26664, 26677, 26680, 26689, 26691, 26701, 26704, 26706, 26710, 26719, 26721, 26727, 26740, 26752, 26754, 26764, 26775, 26776, 26785, 26796, 26797, 26799, 26805, 26806, 26809, 26812, 26815, 26817, 26820, 26827, 26829, 26841, 26847, 26850, 26859, 26860, 26866, 26880, 26887, 26889, 26892, 26896, 26907, 26910, 26916, 26925, 26929, 26931, 26941, 26944, 26946, 26949, 26950, 26959, 26962, 26964, 26970, 26976, 26980, 26994, 26997, 27001, 27006, 27007, 27019, 27025, 27030, 27042, 27046, 27051, 27061, 27067, 27070, 27076, 27082, 27084, 27091, 27097, 27109, 27126, 27135, 27139, 27144, 27147, 27156, 27160, 27162, 27166, 27174, 27181, 27184, 27186, 27189, 27201, 27202, 27205, 27207, 27210, 27211, 27219, 27222, 27225, 27235, 27247, 27249, 27250, 27252, 27259, 27261, 27270, 27271, 27274, 27280, 27282, 27289, 27291, 27292, 27301, 27309, 27312, 27315, 27316, 27324, 27334, 27337, 27340, 27355, 27357, 27361, 27364, 27376, 27384, 27387, 27390, 27394, 27400, 27415, 27417, 27426, 27435, 27439, 27441, 27454, 27459, 27460, 27471, 27475, 27480, 27487, 27490, 27492, 27501, 27505, 27511, 27525, 27526, 27529, 27531, 27537, 27540, 27552, 27555, 27559, 27564, 27574, 27582, 27586, 27601, 27604, 27607, 27609, 27610, 27615, 27622, 27625, 27630, 27646, 27657, 27666, 27667, 27669, 27670, 27672, 27676, 27687, 27691, 27700, 27706, 27720, 27721, 27729, 27735, 27744, 27751, 27756, 27765, 27771, 27774, 27790, 27795, 27802, 27805, 27810, 27811, 27816, 27817, 27820, 27831, 27832, 27834, 27837, 27841, 27846, 27849, 27856, 27859, 27861, 27867, 27882, 27894, 27897, 27900, 27904, 27907, 27909, 27910, 27912, 27915, 27919, 27922, 27925, 27936, 27945, 27949, 27951, 27952, 27961, 27964, 27966, 27967, 27975, 27984, 27994, 27999, 28002, 28005, 28020, 28021, 28027, 28041, 28044, 28047, 28050, 28051, 28057, 28062, 28066, 28075, 28084, 28086, 28090, 28099, 28104, 28105, 28119, 28120, 28125, 28132, 28134, 28135, 28150, 28156, 28167, 28180, 28185, 28189, 28192, 28197, 28201, 28209, 28216, 28219, 28222, 28227, 28234, 28237, 28239, 28240, 28245, 28251, 28252, 28255, 28260, 28264, 28266, 28267, 28272, 28285, 28296, 28299, 28300, 28306, 28315, 28317, 28330, 28332, 28336, 28341, 28344, 28351, 28356, 28357, 28366, 28369, 28374, 28384, 28387, 28390, 28392, 28404, 28405, 28407, 28411, 28414, 28422, 28429, 28437, 28446, 28447, 28449, 28455, 28456, 28461, 28462, 28465, 28471, 28476, 28479, 28482, 28492, 28495, 28497, 28500, 28519, 28521, 28524, 28530, 28537, 28539, 28545, 28549, 28554, 28560, 28566, 28570, 28572, 28575, 28582, 28587, 28590, 28596, 28597, 28602, 28611, 28612, 28621, 28626, 28630, 28635, 28636, 28642, 28644, 28651, 28665, 28666, 28674, 28675, 28684, 28687, 28692, 28695, 28699, 28707, 28714, 28729, 28734, 28744, 28747, 28752, 28764, 28765, 28779, 28780, 28786, 28794, 28797, 28801, 28819, 28821, 28825, 28827, 28834, 28840, 28845, 28849, 28855, 28857, 28860, 28864, 28866, 28869, 28876, 28887, 28891, 28894, 28896, 28897, 28902, 28905, 28915, 28920, 28924, 28927, 28930, 28941, 28950, 28951, 28959, 28962, 28972, 28974, 28987, 28989, 28996, 29007, 29014, 29016, 29022, 29025, 29029, 29031, 29034, 29037, 29050, 29055, 29056, 29065, 29074, 29076, 29077, 29085, 29086, 29095, 29097, 29100, 29104, 29106, 29109, 29115, 29116, 29119, 29122, 29136, 29155, 29157, 29161, 29169, 29182, 29184, 29185, 29190, 29196, 29197, 29202, 29206, 29209, 29214, 29220, 29221, 29226, 29227, 29239, 29241, 29256, 29269, 29272, 29275, 29284, 29287, 29290, 29301, 29302, 29307, 29316, 29329, 29331, 29340, 29344, 29347, 29350, 29356, 29364, 29367, 29371, 29379, 29382, 29386, 29394, 29395, 29416, 29445, 29449, 29451, 29454, 29455, 29457, 29461, 29469, 29472, 29482, 29484, 29490, 29496, 29499, 29505, 29506, 29511, 29512, 29515, 29526, 29527, 29532, 29535, 29539, 29542, 29547, 29554, 29557, 29560, 29562, 29571, 29575, 29580, 29584, 29592, 29599, 29604, 29605, 29610, 29611, 29617, 29620, 29622, 29632, 29637, 29641, 29667, 29671, 29676, 29679, 29680, 29685, 29689, 29694, 29697, 29700, 29704, 29709, 29710, 29721, 29722, 29724, 29727, 29734, 29736, 29737, 29749, 29755, 29757, 29770, 29779, 29781, 29784, 29791, 29806, 29809, 29811, 29814, 29815, 29826, 29830, 29832, 29835, 29836, 29847, 29850, 29854, 29862, 29865, 29872, 29874, 29877, 29886, 29890, 29896, 29899, 29905, 29917, 29932, 29940, 29944, 29961, 29965, 29976, 29979, 29986, 29991, 30000, 30007, 30009, 30015, 30019, 30021, 30039, 30042, 30045, 30046, 30051, 30052, 30054, 30064, 30067, 30070, 30075, 30081, 30084, 30085, 30105, 30109, 30112, 30126, 30129, 30130, 30136, 30145, 30147, 30159, 30166, 30169, 30172, 30177, 30187, 30192, 30199, 30207, 30214, 30222, 30225, 30229, 30247, 30249, 30255, 30261, 30264, 30270, 30295, 30301, 30304, 30306, 30309, 30312, 30316, 30319, 30324, 30325, 30330, 30331, 30340, 30345, 30352, 30360, 30364, 30367, 30369, 30379, 30381, 30382, 30387, 30390, 30397, 30406, 30411, 30430, 30435, 30444, 30445, 30450, 30451, 30457, 30459, 30460, 30462, 30469, 30472, 30477, 30481, 30501, 30504, 30514, 30516, 30522, 30526, 30529, 30546, 30550, 30561, 30565, 30571, 30576, 30577, 30585, 30606, 30612, 30616, 30627, 30631, 30642, 30646, 30649, 30666, 30667, 30670, 30672, 30679, 30682, 30690, 30691, 30702, 30705, 30709, 30721, 30732, 30735, 30736, 30742, 30744, 30747, 30754, 30756, 30760, 30772, 30774, 30777, 30780, 30781, 30792, 30802, 30805, 30807, 30814, 30816, 30819, 30822, 30826, 30829, 30834, 30837, 30841, 30844, 30852, 30859, 30862, 30865, 30876, 30879, 30891, 30907, 30910, 30919, 30922, 30931, 30936, 30940, 30955, 30964, 30967, 30975, 30981, 30984, 30990, 30991, 30994, 30996, 31002, 31006, 31009, 31020, 31024, 31027, 31029, 31036, 31041, 31050, 31060, 31065, 31066, 31069, 31071, 31072, 31086, 31095, 31096, 31101, 31104, 31107, 31110, 31117, 31137, 31149, 31150, 31152, 31156, 31162, 31164, 31174, 31176, 31192, 31201, 31209, 31212, 31230, 31234, 31237, 31239, 31242, 31249, 31251, 31254, 31267, 31270, 31275, 31282, 31291, 31296, 31299, 31302, 31309, 31314, 31317, 31320, 31327, 31330, 31342, 31344, 31351, 31362, 31366, 31372, 31377, 31381, 31387, 31396, 31401, 31410, 31414, 31426, 31431, 31435, 31437, 31449, 31452, 31461, 31464, 31465, 31470, 31485, 31486, 31491, 31492, 31494, 31495, 31515, 31516, 31530, 31534, 31537, 31540, 31549, 31552, 31557, 31564, 31566, 31575, 31590, 31599, 31600, 31606, 31621, 31624, 31639, 31641, 31650, 31656, 31657, 31659, 31666, 31669, 31674, 31677, 31681, 31684, 31689, 31695, 31696, 31699, 31705, 31710, 31711, 31720, 31722, 31732, 31734, 31737, 31744, 31747, 31750, 31761, 31764, 31767, 31771, 31780, 31789, 31794, 31795, 31800, 31801, 31804, 31806, 31809, 31815, 31824, 31825, 31830, 31834, 31836, 31845, 31846, 31849, 31852, 31855, 31860, 31864, 31869, 31872, 31881, 31887, 31891, 31897, 31900, 31902, 31905, 31912, 31920, 31921, 31927, 31929, 31932, 31951, 31954, 31957, 31965, 31975, 31989, 31999, 32004, 32007, 32010, 32017, 32019, 32032, 32034, 32041, 32046, 32055, 32062, 32076, 32077, 32079, 32086, 32094, 32095, 32109, 32112, 32116, 32119, 32136, 32140, 32142, 32151, 32152, 32160, 32164, 32167, 32187, 32191, 32200, 32202, 32217, 32220, 32226, 32227, 32242, 32245, 32250, 32257, 32277, 32284, 32289, 32290, 32296, 32301, 32305, 32307, 32311, 32314, 32317, 32331, 32332, 32334, 32340, 32347, 32355, 32359, 32374, 32382, 32391, 32392, 32397, 32406, 32409, 32425, 32427, 32436, 32439, 32440, 32446, 32451, 32460, 32461, 32464, 32469, 32476, 32485, 32499, 32502, 32506, 32514, 32515, 32517, 32527, 32532, 32536, 32545, 32550, 32551, 32556, 32560, 32562, 32565, 32571, 32574, 32584, 32586, 32587, 32590, 32592, 32602, 32607, 32620, 32629, 32634, 32635, 32644, 32647, 32655, 32662, 32664, 32677, 32679, 32686, 32691, 32697, 32704, 32707, 32710, 32712, 32719, 32724, 32725, 32740, 32749, 32760


end if


if used bigint$isprime | defined include_everything

	; single arg in rdi == bigint, returns bool in eax
falign
bigint$isprime:
	prolog	bigint$isprime
	sub	rsp, 128
	mov	[rsp], rdi
	call	bigint$wordcount
	mov	rdi, [rsp]
	mov	[rsp+8], rax			; wordcount in our number
	test	eax, eax
	jz	.zeroret_noallocs
	cmp	eax, 1
	je	.singleword
calign
.effort:
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rax, [rsi]
	mov	ecx, 2			; b
	test	rax, 1
	jz	.zeroret_noallocs		; even number?
calign
.gcd2loop:
	; t := b
	mov	edx, ecx
	; b := a mod b
	mov	ecx, eax
	and	ecx, 1
	; a := t
	mov	eax, edx
	test	ecx, ecx
	jnz	.gcd2loop
	; return a
	cmp	eax, 1
	jne	.zeroret_noallocs
	mov	rax, [rsp+8]

	; proceed with the heavier goods
	shl	eax, 6
	mov	ecx, 192
	sub	eax, 2
	cmp	eax, ecx
	cmova	eax, ecx
	mov	edi, eax
	mov	[rsp+40], rax			; our random bit count
	call	bigint$new_random		; our random to check with
	mov	[rsp+16], rax
	mov	rdi, [rsp]
	call	bigint$new_copy
	mov	[rsp+32], rax			; our number - 1
	mov	rdi, rax
	mov	rsi, bigint$one
	call	bigint$subtract
	mov	rdi, [rsp+32]
	call	bigint$new_copy
	mov	[rsp+56], rax			; our number - 1 copy (which we'll shift right)
	; save rbx cuz we'll need it
	mov	[rsp+88], rbx
	mov	rdi, [rsp]
	mov	rax, [rsp+8]
	shl	eax, 6
	xor	edx, edx
	mov	ecx, 1
calign
.mriterationcount:
	cmp	eax, [rdx*4+.mrtable]
	ja	.mriterationcountdone
	add	ecx, 1
	add	edx, 1
	jmp	.mriterationcount
calign
.mriterationcountdone:
	mov	[rsp+48], rcx				; save iteration count for later
	; setup the goods to do the miller-rabin test
	; determine how many zero bits there are at the start of our number - 1
	xor	edx, edx
	mov	rdi, [rsp+56]
	mov	r8, [rsp+8]		; word count
	mov	rsi, [rdi+bigint_words_ofs]
calign
.findzerobits:
	mov	rax, [rsi]
	add	rsi, 8
	test	rax, rax
	jz	.findzero_wholeword
	bsf	rcx, rax
	add	rdx, rcx
	jmp	.doshiftright
calign
.findzero_wholeword:
	add	rdx, 64
	sub	r8d, 1
	jnz	.findzerobits
calign
.doshiftright:
	; now shiftright our [rsp+56] number-1 copy by that
	mov	[rsp+64], rdx		; save our zero bit count
	mov	rdi, [rsp+56]		; r
	mov	rsi, rdx
	call	bigint$shr
calign
.do_mr:
	mov	rsi, [rsp]
	mov	rdi, [rsi+bigint_monty_powmod_ofs]
	test	rdi, rdi
	jz	.new_mr
	mov	[rsp+72], rdi
	mov	rdx, rsi
	mov	rsi, [rsp+56]
	call	monty$reinit
	; our random goods are in [rsp+16]
	; test count is in [rsp+48]
	; our monty_powmod is in [rsp+72]

	mov	ebx, 1
calign
.miller_rabin_loop:
	mov	rdi, [rsp+72]
	mov	rsi, [rsp+56]
	mov	rdx, [rsp+16]
	call	monty$doit
	mov	rdi, [rsp+56]
	call	bigint$is_one
	; if monty_pow returned us with a 1, not a witness, go do our next iteration
	test	eax, eax
	jnz	.miller_rabin_next
	mov	rdi, [rsp+56]
	mov	rsi, [rsp+32]
	call	bigint$compare_unsigned
	test	eax, eax
	; if monty_pow returned us with our number-1, not a witness, go do our next iteration
	jz	.miller_rabin_next
calign
.miller_rabin_innerloop:
	cmp	ebx, [rsp+64]
	je	.miller_rabin_innerloop_done
	
	mov	rdi, [rsp+72]
	mov	rsi, [rsp+56]
	mov	rdx, [rsp+56]
	mov	rdi, [rdi+monty_w_ofs]
	call	bigint$multiply_into

	mov	r8, [rsp+72]
	mov	rdi, [r8+monty_z_ofs]		; remainder location
	mov	rsi, [r8+monty_r1_ofs]		; quotient location
	mov	rdx, [r8+monty_w_ofs]		; dividend
	mov	rcx, [rsp]			; divisor
	call	bigint$divide

	mov	rsi, [rsp+72]
	mov	rdi, [rsi+monty_z_ofs]
	call	bigint$is_one
	test	eax, eax
	jnz	.zeroret		; if the result == 1, death on a stick
	mov	rsi, [rsp+72]
	mov	rdi, [rsi+monty_z_ofs]
	mov	rsi, [rsp+32]
	call	bigint$compare_unsigned
	test	eax, eax
	jz	.miller_rabin_next	; maybe a prime, not a witness
	; otherwise, do our assignment and keep going
	mov	rdi, [rsp+72]
	mov	rsi, [rdi+monty_z_ofs]
	mov	rdi, [rsp+56]
	call	bigint$assign
	add	ebx, 1
	jmp	.miller_rabin_innerloop
calign
.miller_rabin_innerloop_done:
	; it cannot equal n_minus_1 here, so a quick zeroret is all we need
	jmp	.zeroret
calign
.miller_rabin_next:
	; otherwise, proceed to the next miller_rabin test iteration
	; we need to have more random material here
	mov	rdi, [rsp+16]
	mov	rsi, [rsp+40]
	call	bigint$set_random
	; so ecx has the iteration count that we need to do
	mov	ebx, 1		; reset our counter
	sub	dword [rsp+48], 1
	jnz	.miller_rabin_loop

	; otherwise, we made it through all iterations without bailing out, 1 it is
	jmp	.oneret
calign
.new_mr:
	mov	rdi, [rsp+56]
	call	monty$new
	mov	[rsp+72], rax
	mov	rdi, [rsp]
	mov	[rdi+bigint_monty_powmod_ofs], rax

	mov	ebx, 1
	jmp	.miller_rabin_loop
dalign
if millerrabinerrorrate = 64
.mrtable:
	; 2^-64 error probability
	dd	0x0758, 0x033b, 0x021d, 0x0195, 0x0146, 0x0113, 0x00ef, 0x00d5
	dd	0x00c0, 0x00b0, 0x00a3, 0x0098, 0x008f, 0x0088, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 80
.mrtable:
	; 2^-80 error probability
	dd	0x0a7e, 0x04b0, 0x0314, 0x024e, 0x01db, 0x018f, 0x015a, 0x0133
	dd	0x0115, 0x00fd, 0x00e9, 0x00d9, 0x00cc, 0x00c0, 0x00b6, 0x00ae
	dd	0x00a7, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 128
.mrtable:
	; 2^-128 error probability:
	dd	0x1713, 0x0a9e, 0x0701, 0x0540, 0x0437, 0x0389, 0x030d, 0x02b2
	dd	0x026b, 0x0232, 0x0204, 0x01de, 0x01be, 0x01a2, 0x018b, 0x0176
	dd	0x0164, 0x0154, 0x0146, 0x0139, 0x012d, 0x0122, 0x0118, 0x0110
	dd	0x0109, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 160
.mrtable:
	; 2^-160 error probability
	dd	0x220c, 0x0fda, 0x0a7b, 0x07db, 0x064d, 0x0547, 0x048d, 0x0403
	dd	0x0397, 0x0342, 0x02fc, 0x02c2, 0x0292, 0x0268, 0x0244, 0x0225
	dd	0x0209, 0x01f1, 0x01db, 0x01c7, 0x01b5, 0x01a5, 0x0197, 0x018b
	dd	0x017e, 0x0172, 0x0167, 0x015c, 0x0153, 0x014c, 0x0145, 0x013f
	dd	0x0139, 0x0133, 0x012d, 0x0127, 0x0121, 0x011a, 0x0114, 0x010e
	dd	0x0108, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 256
.mrtable:
	; 2^-256 error probability
	dd	0x4f43, 0x25aa, 0x18f9, 0x12b9, 0x0f02, 0x0c8c, 0x0acc, 0x097d
	dd	0x0879, 0x07aa, 0x0701, 0x0675, 0x05fe, 0x0599, 0x0541, 0x04f4
	dd	0x04b1, 0x0475, 0x043f, 0x040f, 0x03e3, 0x03bc, 0x0398, 0x0378
	dd	0x0359, 0x033c, 0x0322, 0x030b, 0x02f6, 0x02e2, 0x02cd, 0x02ba
	dd	0x02a8, 0x0298, 0x028a, 0x027d, 0x0271, 0x0265, 0x0259, 0x024d
	dd	0x0241, 0x0235, 0x0229, 0x021e, 0x0215, 0x020e, 0x0207, 0x0201
	dd	0x01fb, 0x01f5, 0x01ef, 0x01e9, 0x01e3, 0x01dd, 0x01d7, 0x01d1
	dd	0x01cb, 0x01c5, 0x01be, 0x01b8, 0x01b2, 0x01ac, 0x01a6, 0x01a0
	dd	0x019a, 0x0194, 0x018e, 0x0188, 0x0182, 0x017c, 0x0176, 0x0170
	dd	0x016a, 0x0163, 0x015d, 0x0157, 0x0151, 0x014b, 0x0145, 0x013f
	dd	0x0139, 0x0133, 0x012d, 0x0127, 0x0121, 0x011a, 0x0114, 0x010e
	dd	0x0108, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else
	display 'invalid Miller-Rabin error rate setting.',10
	err
end if
calign
.singleword:
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rdx, [rsi]
	cmp	rdx, 2
	je	.oneret_noallocs
	cmp	rdx, 1
	jbe	.zeroret_noallocs
	test	rdx, 1
	jz	.zeroret_noallocs
	cmp	rdx, 65521
	ja	.effort
	; else, table lookup
	xor	ecx, ecx
	mov	r8d, 6540
calign
.tableloop:
	mov	r9d, ecx
	cmp	ecx, r8d
	jge	.tabledone
	add	r9d, r8d
	shr	r9d, 1
	movzx	eax, word [r9*2+bigint_primetable]
	cmp	edx, eax
	je	.oneret_noallocs
	jb	.tableloop_case1
	mov	ecx, r9d
	add	ecx, 1
	jmp	.tableloop
calign
.tableloop_case1:
	mov	r8d, r9d
	sub	r8d, 1
	jmp	.tableloop
calign
.tabledone:
	mov	r9d, r8d
	add	r9d, 1
	cmp	r8d, 0
	cmovl	r8d, r9d
	movzx	eax, word [r8*2+bigint_primetable]
	cmp	eax, edx
	je	.oneret_noallocs
	cmovb	r8d, r9d
	movzx	eax, word [r8*2+bigint_primetable]
	cmp	eax, edx
	je	.oneret_noallocs
	jmp	.zeroret_noallocs
calign
.zeroret:
	mov	rdi, [rsp+16]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	mov	rdi, [rsp+56]
	call	bigint$destroy
	xor	eax, eax
	mov	rbx, [rsp+88]
	add	rsp, 128
	epilog
calign
.oneret:
	mov	rdi, [rsp+16]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	mov	rdi, [rsp+56]
	call	bigint$destroy
	mov	eax, 1
	mov	rbx, [rsp+88]
	add	rsp, 128
	epilog
calign
.zeroret_noallocs:
	xor	eax, eax
	add	rsp, 128
	epilog
calign
.oneret_noallocs:
	mov	eax, 1
	add	rsp, 128
	epilog

end if


if used bigint$modsmallprimes | defined include_everything
	; single arg in rdi == bigint (prime candidate)
	; returns bool in eax, false == no small primes were evenly divisible, true == we were able to divide a small prime evenly into rdi
falign
bigint$modsmallprimes:
	prolog	bigint$modsmallprimes
	push	rbx r14 r15
	mov	rbx, rdi
	mov	r14, bigint_primetable
	mov	r15d, 6540		; 6540 of them in our list
calign
.doit:
	mov	rdi, rbx
	movzx	esi, word [r14]
	add	r14, 2
	call	bigint$modword
	test	rax, rax
	jz	.oneret
	sub	r15d, 1
	jnz	.doit
	xor	eax, eax
	pop	r15 r14 rbx
	epilog
calign
.oneret:
	mov	eax, 1
	pop	r15 r14 rbx
	epilog

end if



if used bigint$isprime2 | defined include_everything
	; single arg in rdi == bigint, returns bool in eax
falign
bigint$isprime2:
	prolog	bigint$isprime2
	sub	rsp, 128
	mov	[rsp], rbx
	mov	[rsp+8], r12
	mov	[rsp+16], r13
	mov	[rsp+24], r14
	mov	[rsp+32], r15
	mov	rbx, rdi
	call	bigint$wordcount
	mov	r12d, eax
	mov	rsi, [rbx+bigint_words_ofs]
	mov	rdi, rbx
	test	eax, eax
	jz	.zeroret_noallocs
	cmp	eax, 1
	je	.singleword
	mov	rax, [rsi]
	mov	ecx, 2			; b
	test	eax, 1
	jz	.zeroret_noallocs	; even number?
calign
.effort:
if defined isprime_checkgcd
	call	bigint$new
	mov	r14, rax
	call	bigint$new
	mov	r15, rax
	mov	rdi, r14
	mov	rsi, r15
	mov	rdx, bigint$three
	mov	rcx, rbx
	call	bigint$gcd
	mov	rdi, r14
	call	bigint$is_one
	test	eax, eax
	; jz	.zeroret
	jnz	.gcddoit
	breakpoint
.gcddoit:
	mov	rdi, r14
	mov	rsi, rbx
	call	bigint$assign
	mov	rdi, r14
	mov	rsi, bigint$one			; our number - 1 into r14
	call	bigint$subtract_unsigned
	mov	rdi, r15
	mov	rsi, r14
	call	bigint$assign
else
	mov	rdi, rbx
	call	bigint$new_copy
	mov	r14, rax
	mov	rdi, r14
	mov	rsi, bigint$one
	call	bigint$subtract_unsigned	; our number - 1 into r14
	mov	rdi, r14
	call	bigint$new_copy
	mov	r15, rax		; mod/r

end if

	; determine the largest power of 2 that divides our number - 1
	xor	r8d, r8d		; multiword bitcount initial
	mov	rsi, [r15+bigint_words_ofs]
	; we KNOW there are nonzero bits here, hopefully in the first word
	mov	rcx, [rsi]
	test	rcx, rcx
	jz	.mod_multiword
	bsf	rsi, rcx
	mov	rdi, r15
	mov	[rsp+40], rsi
	mov	[rsp+48], rsi		; two copies for two loops
	mov	[rsp+56], rsi		; three copies
	call	bigint$shr
calign
.effort_modokay:
	; make sure we have a monty_powmod object for our number
	mov	r13, [rbx+bigint_monty_powmod_ofs]
	test	r13, r13
	jz	.new_powmod
	mov	rdi, r13
	mov	rsi, r15
	mov	rdx, rbx
	call	monty$reinit
calign
.check_exp3:
	mov	rdi, r13		; our monty_powmod
	mov	rsi, [r13+monty_x_ofs]	; our destination for the powmod operation
	mov	rdx, bigint$three	; 3 appears to be a stronger initial test than 2... is it?
	call	monty$doit
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, bigint$one
	call	bigint$compare_unsigned
	test	eax, eax		; if powmod returned us 1, keep going cuz it looks okay
	jz	.check_mr
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, r14
	call	bigint$compare_unsigned
	test	eax, eax
	jz	.check_mr		; if powmod returned us number - 1, keep going cuz it looks okay
	; otherwise, do our square/reduce loop
	cmp	dword [rsp+40], 1
	jbe	.zeroret		; no square/reduce loop required
calign
.check_exp3_loop:
	; monty_x_ofs squared into w
	mov	rdi, [r13+monty_w_ofs]
	mov	rsi, [r13+monty_x_ofs]
	call	bigint$square_into
	mov	rdi, [r13+monty_x_ofs]	; where we want our remainder to go
	mov	rsi, [r13+monty_z_ofs]		; where we want our quotient to go
	mov	rdx, [r13+monty_w_ofs]		; our dividend
	mov	rcx, rbx			; our divisor
	call	bigint$divide
	
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, r14
	call	bigint$compare_unsigned
	test	eax, eax
	jz	.check_mr
	mov	rdi, [r13+monty_x_ofs]
	call	bigint$is_one
	test	eax, eax
	jnz	.zeroret		; if it returned 1, outta here
	sub	dword [rsp+40], 1
	jnz	.check_exp3_loop
	; if we made it all the way through that loop, outta here
	jmp	.zeroret
calign
.check_mr:
	mov	eax, r12d
	shl	eax, 6
	xor	edx, edx
	mov	ecx, 1
calign
.mr_testcount:
	cmp	eax, [rdx*4+.mrtable]
	ja	.mr_initial_random
	add	ecx, 1
	add	edx, 1
	jmp	.mr_testcount
calign
.mr_initial_random:
	sub	ecx, 1			; because we already did one iteration with the #3
	jz	.oneret
	mov	[rsp+40], rcx		; save our test iteration count
	; we need to determine how many random bits we require
	mov	esi, r12d
	shl	esi, 6
	mov	ecx, 192
	sub	esi, 2
	cmp	esi, ecx
	cmova	esi, ecx
	mov	rdi, [r13+monty_z_ofs]	; our random bits
	call	bigint$set_random

	; [rsp+56] has our largest power of 2 that divides number - 1
	mov	rax, [rsp+56]
	mov	[rsp+64], rax			; make a copy of the count
calign
.mr_loop:
	mov	rdi, r13
	mov	rsi, [r13+monty_x_ofs]		; destination
	mov	rdx, [r13+monty_z_ofs]		; random bits
	call	monty$doit
	mov	rdi, [r13+monty_x_ofs]
	call	bigint$is_one
	test	eax, eax			; if pow_mod returned us with a 1, looking good, next iteration
	jnz	.mr_next_iteration
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, r14
	call	bigint$compare_unsigned
	test	eax, eax			; if pow_mod returend us with our number-1, next iteration
	jz	.mr_next_iteration
	; else, make sure our count in rsp+64 is >1
	cmp	dword [rsp+64], 1
	jbe	.zeroret			; no square/reduce loop required
calign
.mr_loop_inner:
	; monty_x_ofs squared into w
	mov	rdi, [r13+monty_w_ofs]
	mov	rsi, [r13+monty_x_ofs]
	call	bigint$square_into
	mov	rdi, [r13+monty_x_ofs]		; where we want our remainder to go
	mov	rsi, [r13+monty_z_ofs]		; where we want our quotient to go
	mov	rdx, [r13+monty_w_ofs]		; our dividend
	mov	rcx, rbx			; our divisor
	call	bigint$divide
	
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, r14
	call	bigint$compare_unsigned
	test	eax, eax
	jz	.mr_next_iteration	; if the result was number - 1, keep going cuz it looks okay
	mov	rdi, [r13+monty_x_ofs]
	call	bigint$is_one
	test	eax, eax
	jnz	.zeroret		; if it returned 1, outta here
	sub	dword [rsp+64], 1
	jnz	.mr_loop_inner
	; if we made it all the way through that loop, outta here
	jmp	.zeroret
calign
.mr_next_iteration:
	sub	dword [rsp+40], 1
	jz	.oneret			; made it all the way through, 1 it is.
	; re-randomize our goods
	mov	esi, r12d
	shl	esi, 6
	mov	ecx, 192
	sub	esi, 2
	cmp	esi, ecx
	cmova	esi, ecx
	mov	rdi, [r13+monty_z_ofs]	; our random bits
	call	bigint$set_random

	; [rsp+56] has our largest power of 2 that divides number - 1
	mov	rax, [rsp+56]
	mov	[rsp+64], rax			; make a copy of the count
	jmp	.mr_loop
calign
.new_powmod:
	mov	rdi, r15
	mov	rsi, rbx
	call	monty$new
	mov	[rbx+bigint_monty_powmod_ofs], rax
	mov	r13, rax
	jmp	.check_exp3
calign
.mod_multiword:
	; word we checked at rsi was zero, move to the next
	add	r8d, 64
	add	rsi, 8
	mov	rcx, [rsi]
	test	rcx, rcx
	jz	.mod_multiword
	bsf	rsi, rcx
	add	esi, r8d
	mov	rdi, rax
	mov	[rsp+40], rsi
	mov	[rsp+48], rsi
	mov	[rsp+56], rsi
	call	bigint$shr
	jmp	.effort_modokay
calign
.singleword:
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rdx, [rsi]
	cmp	rdx, 2
	je	.oneret_noallocs
	cmp	rdx, 1
	jbe	.zeroret_noallocs
	test	rdx, 1
	jz	.zeroret_noallocs
	cmp	rdx, 65521
	ja	.effort
	; else, table lookup
	xor	ecx, ecx
	mov	r8d, 6540
calign
.tableloop:
	mov	r9d, ecx
	cmp	ecx, r8d
	jge	.tabledone
	add	r9d, r8d
	shr	r9d, 1
	movzx	eax, word [r9*2+bigint_primetable]
	cmp	edx, eax
	je	.oneret_noallocs
	jb	.tableloop_case1
	mov	ecx, r9d
	add	ecx, 1
	jmp	.tableloop
calign
.tableloop_case1:
	mov	r8d, r9d
	sub	r8d, 1
	jmp	.tableloop
calign
.tabledone:
	mov	r9d, r8d
	add	r9d, 1
	cmp	r8d, 0
	cmovl	r8d, r9d
	movzx	eax, word [r8*2+bigint_primetable]
	cmp	eax, edx
	je	.oneret_noallocs
	cmovb	r8d, r9d
	movzx	eax, word [r8*2+bigint_primetable]
	cmp	eax, edx
	je	.oneret_noallocs
	jmp	.zeroret_noallocs
calign
.zeroret:
	mov	rdi, r14
	call	bigint$destroy
	mov	rdi, r15
	call	bigint$destroy
calign
.zeroret_noallocs:
	xor	eax, eax
	mov	rbx, [rsp]
	mov	r12, [rsp+8]
	mov	r13, [rsp+16]
	mov	r14, [rsp+24]
	mov	r15, [rsp+32]
	add	rsp, 128
	epilog
calign
.oneret:
	mov	rdi, r14
	call	bigint$destroy
	mov	rdi, r15
	call	bigint$destroy
calign
.oneret_noallocs:
	mov	eax, 1
	mov	rbx, [rsp]
	mov	r12, [rsp+8]
	mov	r13, [rsp+16]
	mov	r14, [rsp+24]
	mov	r15, [rsp+32]
	add	rsp, 128
	epilog
dalign
if millerrabinerrorrate = 64
.mrtable:
	; 2^-64 error probability
	dd	0x0758, 0x033b, 0x021d, 0x0195, 0x0146, 0x0113, 0x00ef, 0x00d5
	dd	0x00c0, 0x00b0, 0x00a3, 0x0098, 0x008f, 0x0088, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 80
.mrtable:
	; 2^-80 error probability
	dd	0x0a7e, 0x04b0, 0x0314, 0x024e, 0x01db, 0x018f, 0x015a, 0x0133
	dd	0x0115, 0x00fd, 0x00e9, 0x00d9, 0x00cc, 0x00c0, 0x00b6, 0x00ae
	dd	0x00a7, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 128
.mrtable:
	; 2^-128 error probability:
	dd	0x1713, 0x0a9e, 0x0701, 0x0540, 0x0437, 0x0389, 0x030d, 0x02b2
	dd	0x026b, 0x0232, 0x0204, 0x01de, 0x01be, 0x01a2, 0x018b, 0x0176
	dd	0x0164, 0x0154, 0x0146, 0x0139, 0x012d, 0x0122, 0x0118, 0x0110
	dd	0x0109, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 160
.mrtable:
	; 2^-160 error probability
	dd	0x220c, 0x0fda, 0x0a7b, 0x07db, 0x064d, 0x0547, 0x048d, 0x0403
	dd	0x0397, 0x0342, 0x02fc, 0x02c2, 0x0292, 0x0268, 0x0244, 0x0225
	dd	0x0209, 0x01f1, 0x01db, 0x01c7, 0x01b5, 0x01a5, 0x0197, 0x018b
	dd	0x017e, 0x0172, 0x0167, 0x015c, 0x0153, 0x014c, 0x0145, 0x013f
	dd	0x0139, 0x0133, 0x012d, 0x0127, 0x0121, 0x011a, 0x0114, 0x010e
	dd	0x0108, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 256
.mrtable:
	; 2^-256 error probability
	dd	0x4f43, 0x25aa, 0x18f9, 0x12b9, 0x0f02, 0x0c8c, 0x0acc, 0x097d
	dd	0x0879, 0x07aa, 0x0701, 0x0675, 0x05fe, 0x0599, 0x0541, 0x04f4
	dd	0x04b1, 0x0475, 0x043f, 0x040f, 0x03e3, 0x03bc, 0x0398, 0x0378
	dd	0x0359, 0x033c, 0x0322, 0x030b, 0x02f6, 0x02e2, 0x02cd, 0x02ba
	dd	0x02a8, 0x0298, 0x028a, 0x027d, 0x0271, 0x0265, 0x0259, 0x024d
	dd	0x0241, 0x0235, 0x0229, 0x021e, 0x0215, 0x020e, 0x0207, 0x0201
	dd	0x01fb, 0x01f5, 0x01ef, 0x01e9, 0x01e3, 0x01dd, 0x01d7, 0x01d1
	dd	0x01cb, 0x01c5, 0x01be, 0x01b8, 0x01b2, 0x01ac, 0x01a6, 0x01a0
	dd	0x019a, 0x0194, 0x018e, 0x0188, 0x0182, 0x017c, 0x0176, 0x0170
	dd	0x016a, 0x0163, 0x015d, 0x0157, 0x0151, 0x014b, 0x0145, 0x013f
	dd	0x0139, 0x0133, 0x012d, 0x0127, 0x0121, 0x011a, 0x0114, 0x010e
	dd	0x0108, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else
	display 'invalid Miller-Rabin error rate setting.',10
	err
end if

end if




if used bigint$verifyprime | defined include_everything
	; single arg in rdi == bigint, returns bool in eax (false == no deal, true == sweet)
	; unlike isprime, this does random iterations of the Miller-Rabin test.
	; whatever the library-configured miller-rabin error rate is, we calculate its normal
	; error rate, add 2 and multiply that count by 64 (which seems to put our error rate
	; in the mission impossible category, even when the library's error rate is set low)
falign
bigint$verifyprime:
	prolog	bigint$verifyprime
	sub	rsp, 128
	mov	[rsp], rbx
	mov	[rsp+8], r12
	mov	[rsp+16], r13
	mov	[rsp+24], r14
	mov	[rsp+32], r15
	mov	rbx, rdi

	call	bigint$modsmallprimes
	test	eax, eax
	jnz	.zeroret_noallocs
	mov	rdi, rbx
	call	bigint$wordcount
	mov	r12d, eax
	mov	rsi, [rbx+bigint_words_ofs]
	mov	rdi, rbx
	test	eax, eax
	jz	.zeroret_noallocs
	cmp	eax, 1
	je	.singleword
	mov	rax, [rsi]
	mov	ecx, 2			; b
	test	eax, 1
	jz	.zeroret_noallocs	; even number?
calign
.effort:
	; go ahead with fully random Miller-Rabin tests, with a crazy error rate
	mov	rdi, rbx
	call	bigint$new_copy
	mov	r14, rax
	mov	rdi, r14
	mov	rsi, bigint$one
	call	bigint$subtract_unsigned	; our number - 1 into r14
	mov	rdi, r14
	call	bigint$new_copy
	mov	r15, rax		; mod/r
	; determine the largest power of 2 that divides our number - 1
	mov	rsi, [rax+bigint_words_ofs]
	xor	r8d, r8d		; multiword bitcount initial
	; we KNOW there are nonzero bits here, hopefully in the first word
	mov	rcx, [rsi]
	test	rcx, rcx
	jz	.mod_multiword
	bsf	rsi, rcx
	mov	rdi, rax
	mov	[rsp+40], rsi
	mov	[rsp+48], rsi		; two copies for two loops
	mov	[rsp+56], rsi		; three copies
	call	bigint$shr
calign
.effort_modokay:
	; make sure we have a monty_powmod object for our number
	mov	r13, [rbx+bigint_monty_powmod_ofs]
	test	r13, r13
	jz	.new_powmod
	mov	rdi, r13
	mov	rsi, r15
	mov	rdx, rbx
	call	monty$reinit
calign
.check_mr:
	mov	eax, r12d
	shl	eax, 6
	xor	edx, edx
	mov	ecx, 1
calign
.mr_testcount:
	cmp	eax, [rdx*4+.mrtable]
	ja	.mr_initial_random
	add	ecx, 1
	add	edx, 1
	jmp	.mr_testcount
calign
.mr_initial_random:
	; whatever the defined miller rabin error rate is, go up by a LOT (+2 x 64)
	add	ecx, 2
	shl	ecx, 6
	mov	[rsp+40], rcx		; save our test iteration count
	; we need to determine how many random bits we require
	mov	esi, r12d
	shl	esi, 6
	mov	ecx, 192
	sub	esi, 2
	cmp	esi, ecx
	cmova	esi, ecx
	mov	rdi, [r13+monty_z_ofs]	; our random bits
	call	bigint$set_random

	; [rsp+56] has our largest power of 2 that divides number - 1
	mov	rax, [rsp+56]
	mov	[rsp+64], rax			; make a copy of the count
calign
.mr_loop:
	mov	rdi, r13
	mov	rsi, [r13+monty_x_ofs]		; destination
	mov	rdx, [r13+monty_z_ofs]		; random bits
	call	monty$doit
	mov	rdi, [r13+monty_x_ofs]
	call	bigint$is_one
	test	eax, eax			; if pow_mod returned us with a 1, looking good, next iteration
	jnz	.mr_next_iteration
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, r14
	call	bigint$compare_unsigned
	test	eax, eax			; if pow_mod returend us with our number-1, next iteration
	jz	.mr_next_iteration
	; else, make sure our count in rsp+64 is >1
	cmp	dword [rsp+64], 1
	jbe	.zeroret			; no square/reduce loop required
calign
.mr_loop_inner:
	; monty_x_ofs squared into w
	mov	rdi, [r13+monty_w_ofs]
	mov	rsi, [r13+monty_x_ofs]
	call	bigint$square_into
	mov	rdi, [r13+monty_x_ofs]		; where we want our remainder to go
	mov	rsi, [r13+monty_z_ofs]		; where we want our quotient to go
	mov	rdx, [r13+monty_w_ofs]		; our dividend
	mov	rcx, rbx			; our divisor
	call	bigint$divide
	
	mov	rdi, [r13+monty_x_ofs]
	mov	rsi, r14
	call	bigint$compare_unsigned
	test	eax, eax
	jz	.mr_next_iteration	; if the result was number - 1, keep going cuz it looks okay
	mov	rdi, [r13+monty_x_ofs]
	call	bigint$is_one
	test	eax, eax
	jnz	.zeroret		; if it returned 1, outta here
	sub	dword [rsp+64], 1
	jnz	.mr_loop_inner
	; if we made it all the way through that loop, outta here
	jmp	.zeroret
calign
.mr_next_iteration:
	sub	dword [rsp+40], 1
	jz	.oneret			; made it all the way through, 1 it is.
	; re-randomize our goods
	mov	esi, r12d
	shl	esi, 6
	mov	ecx, 192
	sub	esi, 2
	cmp	esi, ecx
	cmova	esi, ecx
	mov	rdi, [r13+monty_z_ofs]	; our random bits
	call	bigint$set_random

	; [rsp+56] has our largest power of 2 that divides number - 1
	mov	rax, [rsp+56]
	mov	[rsp+64], rax			; make a copy of the count
	jmp	.mr_loop
calign
.new_powmod:
	mov	rdi, r15
	mov	rsi, rbx
	call	monty$new
	mov	[rbx+bigint_monty_powmod_ofs], rax
	mov	r13, rax
	jmp	.check_mr
calign
.mod_multiword:
	; word we checked at rsi was zero, move to the next
	add	r8d, 64
	add	rsi, 8
	mov	rcx, [rsi]
	test	rcx, rcx
	jz	.mod_multiword
	bsf	rsi, rcx
	add	esi, r8d
	mov	rdi, rax
	mov	[rsp+40], rsi
	mov	[rsp+48], rsi
	mov	[rsp+56], rsi
	call	bigint$shr
	jmp	.effort_modokay
calign
.singleword:
	mov	rsi, [rdi+bigint_words_ofs]
	mov	rdx, [rsi]
	cmp	rdx, 2
	je	.oneret_noallocs
	cmp	rdx, 1
	jbe	.zeroret_noallocs
	test	rdx, 1
	jz	.zeroret_noallocs
	cmp	rdx, 65521
	ja	.effort
	; else, table lookup
	xor	ecx, ecx
	mov	r8d, 6540
calign
.tableloop:
	mov	r9d, ecx
	cmp	ecx, r8d
	jge	.tabledone
	add	r9d, r8d
	shr	r9d, 1
	movzx	eax, word [r9*2+bigint_primetable]
	cmp	edx, eax
	je	.oneret_noallocs
	jb	.tableloop_case1
	mov	ecx, r9d
	add	ecx, 1
	jmp	.tableloop
calign
.tableloop_case1:
	mov	r8d, r9d
	sub	r8d, 1
	jmp	.tableloop
calign
.tabledone:
	mov	r9d, r8d
	add	r9d, 1
	cmp	r8d, 0
	cmovl	r8d, r9d
	movzx	eax, word [r8*2+bigint_primetable]
	cmp	eax, edx
	je	.oneret_noallocs
	cmovb	r8d, r9d
	movzx	eax, word [r8*2+bigint_primetable]
	cmp	eax, edx
	je	.oneret_noallocs
	jmp	.zeroret_noallocs
calign
.zeroret:
	mov	rdi, r14
	call	bigint$destroy
	mov	rdi, r15
	call	bigint$destroy
calign
.zeroret_noallocs:
	xor	eax, eax
	mov	rbx, [rsp]
	mov	r12, [rsp+8]
	mov	r13, [rsp+16]
	mov	r14, [rsp+24]
	mov	r15, [rsp+32]
	add	rsp, 128
	epilog
calign
.oneret:
	mov	rdi, r14
	call	bigint$destroy
	mov	rdi, r15
	call	bigint$destroy
calign
.oneret_noallocs:
	mov	eax, 1
	mov	rbx, [rsp]
	mov	r12, [rsp+8]
	mov	r13, [rsp+16]
	mov	r14, [rsp+24]
	mov	r15, [rsp+32]
	add	rsp, 128
	epilog
dalign
if millerrabinerrorrate = 64
.mrtable:
	; 2^-64 error probability
	dd	0x0758, 0x033b, 0x021d, 0x0195, 0x0146, 0x0113, 0x00ef, 0x00d5
	dd	0x00c0, 0x00b0, 0x00a3, 0x0098, 0x008f, 0x0088, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 80
.mrtable:
	; 2^-80 error probability
	dd	0x0a7e, 0x04b0, 0x0314, 0x024e, 0x01db, 0x018f, 0x015a, 0x0133
	dd	0x0115, 0x00fd, 0x00e9, 0x00d9, 0x00cc, 0x00c0, 0x00b6, 0x00ae
	dd	0x00a7, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 128
.mrtable:
	; 2^-128 error probability:
	dd	0x1713, 0x0a9e, 0x0701, 0x0540, 0x0437, 0x0389, 0x030d, 0x02b2
	dd	0x026b, 0x0232, 0x0204, 0x01de, 0x01be, 0x01a2, 0x018b, 0x0176
	dd	0x0164, 0x0154, 0x0146, 0x0139, 0x012d, 0x0122, 0x0118, 0x0110
	dd	0x0109, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 160
.mrtable:
	; 2^-160 error probability
	dd	0x220c, 0x0fda, 0x0a7b, 0x07db, 0x064d, 0x0547, 0x048d, 0x0403
	dd	0x0397, 0x0342, 0x02fc, 0x02c2, 0x0292, 0x0268, 0x0244, 0x0225
	dd	0x0209, 0x01f1, 0x01db, 0x01c7, 0x01b5, 0x01a5, 0x0197, 0x018b
	dd	0x017e, 0x0172, 0x0167, 0x015c, 0x0153, 0x014c, 0x0145, 0x013f
	dd	0x0139, 0x0133, 0x012d, 0x0127, 0x0121, 0x011a, 0x0114, 0x010e
	dd	0x0108, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else if millerrabinerrorrate = 256
.mrtable:
	; 2^-256 error probability
	dd	0x4f43, 0x25aa, 0x18f9, 0x12b9, 0x0f02, 0x0c8c, 0x0acc, 0x097d
	dd	0x0879, 0x07aa, 0x0701, 0x0675, 0x05fe, 0x0599, 0x0541, 0x04f4
	dd	0x04b1, 0x0475, 0x043f, 0x040f, 0x03e3, 0x03bc, 0x0398, 0x0378
	dd	0x0359, 0x033c, 0x0322, 0x030b, 0x02f6, 0x02e2, 0x02cd, 0x02ba
	dd	0x02a8, 0x0298, 0x028a, 0x027d, 0x0271, 0x0265, 0x0259, 0x024d
	dd	0x0241, 0x0235, 0x0229, 0x021e, 0x0215, 0x020e, 0x0207, 0x0201
	dd	0x01fb, 0x01f5, 0x01ef, 0x01e9, 0x01e3, 0x01dd, 0x01d7, 0x01d1
	dd	0x01cb, 0x01c5, 0x01be, 0x01b8, 0x01b2, 0x01ac, 0x01a6, 0x01a0
	dd	0x019a, 0x0194, 0x018e, 0x0188, 0x0182, 0x017c, 0x0176, 0x0170
	dd	0x016a, 0x0163, 0x015d, 0x0157, 0x0151, 0x014b, 0x0145, 0x013f
	dd	0x0139, 0x0133, 0x012d, 0x0127, 0x0121, 0x011a, 0x0114, 0x010e
	dd	0x0108, 0x0102, 0x00fc, 0x00f6, 0x00f0, 0x00ea, 0x00e4, 0x00dd
	dd	0x00d7, 0x00d1, 0x00cb, 0x00c5, 0x00bf, 0x00b9, 0x00b2, 0x00ac
	dd	0x00a6, 0x00a0, 0x009a, 0x0094, 0x008d, 0x0087, 0x0081, 0x007b
	dd	0x0075, 0x006e, 0x0068, 0x0062, 0x005c, 0x0055, 0x004f, 0x0049
	dd	0x0042, 0x003c, 0x0035, 0x002f, 0x0028, 0x0021, 0x001b, 0x0000
	.mrtablesize = ($ - $$) shr 2
else
	display 'invalid Miller-Rabin error rate setting.',10
	err
end if

end if


if used bigint$rsaprivate
	; two arguments: rdi == rsaprivate X509 object, rsi == source/dest bigint
falign
bigint$rsaprivate:
	prolog	bigint$rsaprivate
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi

	; first up: y = source % q
	mov	rdi, [rdi+rsaprivate_y_ofs]	; remainder
	mov	rsi, [rbx+rsaprivate_z_ofs]	; quotient
	mov	rdx, r12			; dividend
	mov	rcx, [rbx+rsaprivate_q_ofs]	; divisor
	call	bigint$divide
	; next up: x = source % p
	mov	rdi, [rbx+rsaprivate_x_ofs]	; remainder
	mov	rsi, [rbx+rsaprivate_z_ofs]	; quotient
	mov	rdx, r12			; dividend
	mov	rcx, [rbx+rsaprivate_p_ofs]	; divisor
	call	bigint$divide

	; next up: expmod for both
	mov	rcx, [rbx+rsaprivate_q_ofs]
	mov	rsi, [rbx+rsaprivate_y_ofs]
	mov	rdx, [rbx+rsaprivate_y_ofs]
	mov	rdi, [rcx+bigint_monty_powmod_ofs]
	call	monty$doit
	mov	rcx, [rbx+rsaprivate_p_ofs]
	mov	rsi, [rbx+rsaprivate_x_ofs]
	mov	rdx, [rbx+rsaprivate_x_ofs]
	mov	rdi, [rcx+bigint_monty_powmod_ofs]
	call	monty$doit
	; CRT next
	; x -= y
	mov	rdi, [rbx+rsaprivate_x_ofs]
	mov	rsi, [rbx+rsaprivate_y_ofs]
	call	bigint$subtract
	mov	rdi, [rbx+rsaprivate_x_ofs]
	mov	rsi, [rbx+rsaprivate_p_ofs]
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.neg1
	; z = x * invqmodp
	mov	rdi, [rbx+rsaprivate_z_ofs]
	mov	rsi, [rbx+rsaprivate_x_ofs]
	mov	rdx, [rbx+rsaprivate_invqmodp_ofs]
	call	bigint$multiply_into
	; x = z % p
	mov	rdi, [rbx+rsaprivate_x_ofs]	; remainder
	mov	rsi, r12			; quotient
	mov	rdx, [rbx+rsaprivate_z_ofs]	; dividend
	mov	rcx, [rbx+rsaprivate_p_ofs]	; divisor
	call	bigint$divide
	mov	rdi, [rbx+rsaprivate_x_ofs]
	mov	rsi, [rbx+rsaprivate_p_ofs]
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.neg2
	mov	rdi, r12
	mov	rsi, [rbx+rsaprivate_x_ofs]
	mov	rdx, [rbx+rsaprivate_q_ofs]
	call	bigint$multiply_into
	; dest += y
	mov	rdi, r12
	mov	rsi, [rbx+rsaprivate_y_ofs]
	call	bigint$add
	pop	r12 rbx
	epilog
calign
.neg1:
	call	bigint$add
	; z = x * invqmodp
	mov	rdi, [rbx+rsaprivate_z_ofs]
	mov	rsi, [rbx+rsaprivate_x_ofs]
	mov	rdx, [rbx+rsaprivate_invqmodp_ofs]
	call	bigint$multiply_into
	; x = z % p
	mov	rdi, [rbx+rsaprivate_x_ofs]	; remainder
	mov	rsi, r12			; quotient
	mov	rdx, [rbx+rsaprivate_z_ofs]	; dividend
	mov	rcx, [rbx+rsaprivate_p_ofs]	; divisor
	call	bigint$divide
	mov	rdi, [rbx+rsaprivate_x_ofs]
	mov	rsi, [rbx+rsaprivate_p_ofs]
	cmp	dword [rdi+bigint_negative_ofs], 0
	jne	.neg2
	mov	rdi, r12
	mov	rsi, [rbx+rsaprivate_x_ofs]
	mov	rdx, [rbx+rsaprivate_q_ofs]
	call	bigint$multiply_into
	; dest += y
	mov	rdi, r12
	mov	rsi, [rbx+rsaprivate_y_ofs]
	call	bigint$add
	pop	r12 rbx
	epilog
calign
.neg2:
	call	bigint$add
	mov	rdi, r12
	mov	rsi, [rbx+rsaprivate_x_ofs]
	mov	rdx, [rbx+rsaprivate_q_ofs]
	call	bigint$multiply_into
	; dest += y
	mov	rdi, r12
	mov	rsi, [rbx+rsaprivate_y_ofs]
	call	bigint$add
	pop	r12 rbx
	epilog


end if


if used monty$inverse | defined include_everything
	; single arg in rdi: word to montgomery invert
	; returns inverted in rax
falign
monty$inverse:
	prolog	monty$inverse
	push	rbx r12 r13 r14
	mov	esi, 0
	mov	edx, 1
	cmp	rdi, 1
	cmove	edx, esi	; high
	xor	r10d, r10d	; quotient
	mov	esi, 64
	mov	rbx, [.allones]
	mov	r8, [.topmost]
calign
.dloop:
	mov	rax, rdx
	and	rax, r8
	shl	rdx, 1
	shl	r10, 1
	test	rax, rax
	jnz	.dloop_case1
	cmp	rdx, rdi
	jae	.dloop_case1
	sub	esi, 1
	jnz	.dloop
	jmp	.dloop_done
calign
.dloop_case1:
	sub	rdx, rdi
	or	r10, 1
	sub	esi, 1
	jnz	.dloop
calign
.dloop_done:
	mov	esi, 1
	xor	ecx, ecx
	xor	r13d, r13d
	xor	r8d, r8d
	mov	r9d, 1
	mov	rax, r10
	mul	rdi
	mov	r11, rbx
	sub	r11, rax
	add	r11, 1
	mov	r12, rsi
	sub	r13, r10
	mov	r14, rdi
	mov	rdi, r11
	mov	rsi, rcx
	mov	rcx, r12
	mov	r8, r9
	mov	r9, r13
calign
.iloop:
	test	rdi, rdi
	jz	.idone
	xor	edx, edx
	mov	rax, r14
	div	rdi
	mov	r10, rax
	mul	rdi
	mov	r11, r14
	sub	r11, rax
	xor	edx, edx
	mov	rax, r10
	mul	rcx
	mov	r12, rsi
	sub	r12, rax
	xor	edx, edx
	mov	rax, r10
	mul	r9
	mov	r13, r8
	sub	r13, rax

	mov	r14, rdi
	mov	rdi, r11
	mov	rsi, rcx
	mov	rcx, r12
	mov	r8, r9
	mov	r9, r13
	jmp	.iloop
calign
.idone:
	mov	rax, rbx
	sub	rax, r8
	add	rax, 1
	pop	r14 r13 r12 rbx
	epilog
dalign
.allones	dq	0xffffffffffffffff
.topmost	dq	0x8000000000000000
end if


monty_exp_ofs = 0
monty_modulus_ofs = 8
monty_r_ofs = 16
monty_r1_ofs = 24
monty_u_ofs = 32
monty_scratch_ofs = 40
monty_w_ofs = 48
monty_x_ofs = 56
monty_z_ofs = 64
monty_gcount_ofs = 72
monty_g_ofs = 80
	; g_ofs == 128 pointers, but these are not managed by new/reinit/destroy
	; and instead are created on the fly each time doit is called and then cleaned up prior to doit returning

monty_size = 80 + (128 shl 3)


if used monty$new | defined include_everything
	; two arguments: rdi == bigint exponent, rsi == bigint n (odd)
	; returns new heap$alloc'd monty object in rax
	; NOTE: this assumes sanity checks on the values were done beforehand
falign
monty$new:
	prolog	monty$new
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rbx
	mov	edi, monty_size
	call	heap$alloc
	mov	rbx, rax
	mov	rdi, [rsp]
	call	bigint$new_copy
	mov	[rbx+monty_exp_ofs], rax

	mov	rdi, [rsp+8]
	call	bigint$new_copy
	mov	[rbx+monty_modulus_ofs], rax

	call	bigint$new
	mov	[rbx+monty_r_ofs], rax

	call	bigint$new
	mov	[rbx+monty_w_ofs], rax
	call	bigint$new
	mov	[rbx+monty_x_ofs], rax
	call	bigint$new
	mov	[rbx+monty_z_ofs], rax
	call	bigint$new
	mov	[rbx+monty_r1_ofs], rax
	mov	rdi, rax
	mov	rsi, [rbx+monty_modulus_ofs]
	mov	edi, [rsi+bigint_size_ofs]
	call	bigint$new_size
	mov	[rbx+monty_u_ofs], rax
	; w is a heap allocated block, not a bigint
	mov	rsi, [rbx+monty_modulus_ofs]
	mov	edi, [rsi+bigint_size_ofs]
	lea	edi, [edi*4+edi]
	shl	edi, 3
	call	heap$alloc
	mov	[rbx+monty_scratch_ofs], rax
	; rdi == u's regs
	mov	rsi, rax
	; rdx == modulus' words
	; rcx == its size
	mov	r8, [rbx+monty_u_ofs]
	mov	r9, [rbx+monty_modulus_ofs]
	mov	rdi, [r8+bigint_words_ofs]
	mov	rdx, [r9+bigint_words_ofs]
	mov	ecx, [r9+bigint_size_ofs]
	call	wd$invmodpow2

if defined montydebug
	mov	rdi, .expstr
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_exp_ofs]
	call	bigint$debug
	mov	rdi, .modstr
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_modulus_ofs]
	call	bigint$debug
	mov	rdi, .invstr
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_u_ofs]
	call	bigint$debug
	; breakpoint
end if

	mov	rax, rbx
	mov	rbx, [rsp+16]
	add	rsp, 24
	epilog

if defined montydebug
cleartext .expstr, 'Exponent is:'
cleartext .modstr, 'Modulus is:'
cleartext .invstr, 'InverseModPower2 is:'
end if

end if




if used monty$reinit | defined include_everything
	; three arguments: rdi == monty object, rsi == bigint exponent, rdx == bigint n (odd)
	; it is assumed that the size of the modulus didn't change (as this is used from inside primechecking)
falign
monty$reinit:
	prolog	monty$reinit
	sub	rsp, 24
	mov	[rsp], rsi
	mov	[rsp+8], rdx
	mov	[rsp+16], rbx
	mov	rbx, rdi
	mov	rdi, [rdi+monty_exp_ofs]
	call	bigint$assign
	mov	rdi, [rbx+monty_modulus_ofs]
	mov	rsi, [rsp+8]
	call	bigint$assign
	mov	rdi, [rbx+monty_r_ofs]
	call	bigint$clear
	mov	rdi, [rbx+monty_r1_ofs]
	call	bigint$clear
	mov	rdi, [rbx+monty_z_ofs]
	call	bigint$clear
	mov	rdi, [rbx+monty_x_ofs]
	call	bigint$clear
	mov	rdi, [rbx+monty_w_ofs]
	call	bigint$clear
	mov	r8, [rbx+monty_u_ofs]
	mov	r9, [rbx+monty_modulus_ofs]
	mov	rdi, [r8+bigint_words_ofs]
	mov	rdx, [r9+bigint_words_ofs]
	mov	ecx, [r9+bigint_size_ofs]
	call	wd$invmodpow2

if defined montydebug
	mov	rdi, .expstr
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_exp_ofs]
	call	bigint$debug
	mov	rdi, .modstr
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_modulus_ofs]
	call	bigint$debug
	mov	rdi, .invstr
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_u_ofs]
	call	bigint$debug
	breakpoint
end if

	mov	rax, rbx	; not necessary for reinit
	mov	rbx, [rsp+16]
	add	rsp, 24
	epilog
if defined montydebug
cleartext .expstr, 'Re-init, Exponent is:'
cleartext .modstr, 'Modulus is:'
cleartext .invstr, 'InverseModPower2 is:'
end if

end if




if used monty$destroy | defined include_everything
	; single argument in rdi == our monty object
falign
monty$destroy:
	prolog	monty$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+monty_exp_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_modulus_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_r_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_r1_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_u_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_w_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_x_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_z_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+monty_scratch_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
end if

if used monty$destroy_clear | defined include_everything
	; single argument in rdi == our monty object
	; same as above, only we zero all memory
falign
monty$destroy_clear:
	prolog	monty$destroy_clear
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+monty_exp_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_modulus_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_r_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_r1_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_u_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_w_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_x_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_z_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+monty_scratch_ofs]
	call	heap$free_clear
	mov	rdi, rbx
	call	heap$free_clear
	pop	rbx
	epilog

end if


montyws_exp_ofs = 0
montyws_winmod_ofs = 8
montyws_winsize_ofs = 16
montyws_winstart_ofs = 24
montyws_expwin_ofs = 32
montyws_initial_ofs = 40
montyws_done_ofs = 48

montyws_size = 56

if used montyws$new | defined include_everything
	; single argument in rdi: bigint exponent
falign
montyws$new:
	prolog	montyws$new
	push	rdi
	mov	edi, montyws_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	bigint$new_copy
	mov	rdi, [rsp]
	mov	[rdi+montyws_exp_ofs], rax
	mov	[rsp], rbx
	mov	rbx, rdi
	mov	rdi, [rbx+montyws_exp_ofs]
	call	bigint$bitcount
	mov	edx, 2
	mov	r8d, 3
	mov	r9d, 4
	mov	r10d, 5
	mov	r11d, 6
	mov	ecx, 7
	mov	esi, 1
	cmp	eax, 17
	cmovae	esi, edx
	cmp	eax, 25
	cmovae	esi, r8d
	cmp	eax, 70
	cmovae	esi, r9d
	cmp	eax, 197
	cmovae	esi, r10d
	cmp	eax, 539
	cmovae	esi, r11d
	cmp	eax, 1434
	cmovae	esi, ecx
	mov	[rbx+montyws_winsize_ofs], rsi
	mov	edi, 1
	call	bigint$new_unsigned
	mov	[rbx+montyws_winmod_ofs], rax
	mov	rdi, rax
	mov	esi, [rbx+montyws_winsize_ofs]
	call	bigint$shl
	mov	qword [rbx+montyws_winstart_ofs], 0
	mov	qword [rbx+montyws_initial_ofs], 1
	mov	qword [rbx+montyws_done_ofs], 0
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used montyws$destroy | defined include_everything
	; single argument in rdi: our montyws object
falign
montyws$destroy:
	prolog	montyws$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+montyws_exp_ofs]
	call	bigint$destroy	
	mov	rdi, [rbx+montyws_winmod_ofs]
	call	bigint$destroy
	mov	rdi, rbx
	pop	rbx
	call	heap$free
	epilog

end if

if used montyws$next | defined include_everything
	; single argument in rdi: our montyws object
falign
montyws$next:
	prolog	montyws$next
	push	rbx r12 r13
	mov	rbx, rdi
	mov	rdi, [rdi+montyws_exp_ofs]
	call	bigint$wordcount
	shl	eax, 6
	xor	r12d, r12d
	mov	edx, [rbx+montyws_winsize_ofs]
	mov	r13d, eax
	cmp	dword [rbx+montyws_initial_ofs], 0
	cmove	r12d, edx
	mov	dword [rbx+montyws_initial_ofs], 0
	; skipC in r12d, expLen in r13d
calign
.loop:
	mov	rdi, [rbx+montyws_exp_ofs]
	mov	esi, r12d
	call	bigint$bitget
	test	eax, eax
	jnz	.doshr
	cmp	r12d, r13d
	jae	.alldone
	add	r12d, 1
	jmp	.loop
calign
.doshr:
	mov	rdi, [rbx+montyws_exp_ofs]
	mov	esi, r12d
	call	bigint$shr
	mov	ecx, dword [rbx+montyws_winsize_ofs]
	add	dword [rbx+montyws_winstart_ofs], r12d
	mov	esi, 1
	shl	esi, cl
	mov	rdi, [rbx+montyws_exp_ofs]
	call	bigint$modword
	mov	dword [rbx+montyws_expwin_ofs], eax
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	mov	dword [rbx+montyws_done_ofs], 1
	pop	r13 r12 rbx
	epilog

end if

if used monty$acc | defined include_everything
	; three arguments: rdi == monty object, rsi == source/dest, rdx == bigint to mult
	; rsi = reduce(rsi * rdx)
falign
monty$acc:
	prolog	monty$acc

if defined montydebug
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	
	mov	rdi, .ident
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	call	bigint$debug
	mov	rdi, [rsp+16]
	call	bigint$debug
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	add	rsp, 24
end if

	mov	eax, [rsi+bigint_size_ofs]
	cmp	eax, [rdx+bigint_size_ofs]
	je	.smult
	push	rdi rsi
	mov	rdi, rsi
	mov	rsi, rdx
	call	bigint$multiply
	pop	rsi rdi
	call	monty$reduce
	epilog
calign
.smult:
	; size of source/dest is the same as rdx's, use our faster multiply
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx

	; we need a copy of the source side, we can stick it into our w
	mov	rdi, [rdi+monty_w_ofs]
	call	bigint$assign
	mov	rdi, r12
	mov	esi, [r12+bigint_size_ofs]
	add	esi, [r13+bigint_size_ofs]
	call	bigint$resize
	mov	rdi, r12
	call	bigint$wordcount
	mov	r8, [rbx+monty_w_ofs]
	mov	rdi, [r12+bigint_words_ofs]
	mov	rsi, [r8+bigint_words_ofs]
	mov	rdx, [r13+bigint_words_ofs]
	mov	ecx, [r13+bigint_size_ofs]
	call	wd$smult
	mov	rdi, rbx
	mov	rsi, r12
	call	monty$reduce

if defined montydebug
	; spew our result as well
	mov	rdi, r12
	call	bigint$debug
end if

	pop	r13 r12 rbx
	epilog

if defined montydebug

cleartext .ident, 'monty$acc:'

end if
	
end if

if used monty$square | defined include_everything
	; two arguments: rdi == monty object, rsi == source/dest to square/reduce
falign
monty$square:
	prolog	monty$square

if defined montydebug
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	rdi, .ident
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	call	bigint$debug
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	add	rsp, 16
end if

	push	rdi rsi
	mov	rdi, [rdi+monty_z_ofs]
	call	bigint$square_into
	pop	rsi rdi
	call	monty$reduce_z_into

	epilog

if defined montydebug

cleartext .ident, 'monty$square:'

end if

end if


if used monty$add | defined include_everything
	; three arguments: rdi == monty object, rsi == leftside, rdx == rightside
	; multiplies rsi * rdx, reduces the result and tosses it into r1
falign
monty$add:
	prolog	monty$add

if defined montydebug
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	
	mov	rdi, .ident
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	call	bigint$debug
	mov	rdi, [rsp+16]
	call	bigint$debug
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	add	rsp, 24
end if


	mov	eax, [rsi+bigint_size_ofs]
	cmp	eax, [rdx+bigint_size_ofs]
	je	.smult
	push	rdi
	mov	rdi, [rdi+monty_r1_ofs]
	call	bigint$multiply_into
	pop	rdi
	mov	rsi, [rdi+monty_r1_ofs]
	call	monty$reduce
	epilog
calign
.smult:
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	add	eax, [rdx+bigint_size_ofs]
	mov	rdi, [rdi+monty_r1_ofs]
	mov	esi, eax
	call	bigint$resize
	mov	r8, [rbx+monty_r1_ofs]
	mov	rsi, [r12+bigint_words_ofs]
	mov	rdx, [r13+bigint_words_ofs]
	mov	ecx, [r13+bigint_size_ofs]
	mov	rdi, [r8+bigint_words_ofs]
	call	wd$smult
	mov	rdi, rbx
	mov	rsi, [rbx+monty_r1_ofs]
	call	monty$reduce
	pop	r13 r12 rbx
	epilog

if defined montydebug

cleartext .ident, 'monty$add:'

end if

end if

if used monty$reduce | defined include_everything
	; two arguments: rdi == monty object, rsi == bigint to reduce
falign
monty$reduce:
	prolog	monty$reduce
	push	rbx r12 r13 r14 r15

	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, [rdi+monty_modulus_ofs]
	
	mov	edx, [rsi+bigint_size_ofs]
	mov	rdi, [rdi+monty_scratch_ofs]
	mov	rsi, [rsi+bigint_words_ofs]
	mov	rcx, rdi
	shl	edx, 3
	add	rcx, rdx
	push	rcx
	call	memcpy
	pop	rdi

	mov	ecx, [r12+bigint_size_ofs]
	mov	edx, [r13+bigint_size_ofs]
	mov	r15d, edx
	xor	esi, esi
	shl	edx, 1
	mov	r14d, edx
	sub 	edx, ecx
	shl	edx, 3
	call	memset32
	; setup for our monty reduce

	mov	eax, [r13+bigint_size_ofs]

	mov	r11, [rbx+monty_u_ofs]
	mov	esi, r14d
	mov	rdi, [r12+bigint_words_ofs]	; Result words
	mov	[r12+bigint_size_ofs], eax	; set size of the result to match our modulus

	mov	rdx, [rbx+monty_scratch_ofs]	; T (scratch)
	shl	esi, 3
	mov	rcx, [r13+bigint_words_ofs]	; modulus words
	mov	r8, [r11+bigint_words_ofs]	; u words
	add	rsi, rdx			; T+2*N (scratch)

	; so at this point:
	; rdi == R
	; rsi == T
	; rdx == X
	; rcx == M
	; r8 == U
	; r15d == N

	mov	rbx, rdi	; R
	mov	r12, rsi	; T
	mov	r13, rdx	; X
	mov	r14, rcx	; M
	
	mov	rsi, rdx
	mov	rdx, r8
	mov	ecx, r15d
	call	wd$mullower

	mov	rdi, r12
	mov	rsi, r13
	mov	rdx, rbx
	mov	rcx, r14
	mov	r8d, r15d
	call	wd$mulupper

	mov	r8d, r15d
	mov	rsi, r13	; X+N
	shl	r8d, 3
	mov	ecx, r15d	; N
	mov	rdi, r12	; T
	add	rsi, r8
	mov	rdx, r12	; T
        shl     ecx, 3
        add     rdi, rcx
        add     rsi, rcx
        add     rdx, rcx
        neg     rcx
        jz      .nosub
        mov     rax, [rsi+rcx]
        sub     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
calign
.subloop:
        mov     rax, [rsi+rcx+8]
        sbb     rax, [rdx+rcx+8]
        mov     [rdi+rcx+8], rax
        lea     rcx, [rcx+16]
        jrcxz   .nosub
        mov     rax, [rsi+rcx]
        sbb     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
        jmp     .subloop
calign
.nosub:
	; save the result in r13
	mov	r13d, 0
	adc	r13, r13


	mov	r8d, r15d
	mov	rdi, r12	; T+n
	shl	r8d, 3
	mov	ecx, r15d	; N
	mov	rsi, r12
	mov	rdx, r14
	add	rdi, r8

        shl     ecx, 3
        add     rdi, rcx
        add     rsi, rcx
        add     rdx, rcx
        neg     rcx
        jz      .noadd
        mov     rax, [rsi+rcx]
        add     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
calign
.addloop:
        mov     rax, [rsi+rcx+8]
        adc     rax, [rdx+rcx+8]
        mov     [rdi+rcx+8], rax
        lea     rcx, [rcx+16]
        jrcxz   .noadd
        mov     rax, [rsi+rcx]
        adc     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
        jmp     .addloop
calign
.noadd:
	; last but not least, we need to copy the result
	xor	eax, eax
	mov	rdi, rbx
	sub	rax, r13
	mov	rsi, r12
	and	rax, r15
	mov	edx, r15d
	shl	rax, 3
	shl	edx, 3
	add	rsi, rax
	call	memcpy
	
	pop	r15 r14 r13 r12 rbx
	epilog

end if



if used monty$reduce_z_into | defined include_everything
	; two arguments: rdi == monty object, rsi == bigint destination of z reduction
falign
monty$reduce_z_into:
	prolog	monty$reduce_z_into



	push	rbx r12 r13
	mov	rax, [rdi+monty_z_ofs]
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, [rdi+monty_modulus_ofs]
	mov	edx, [rax+bigint_size_ofs]
	mov	rdi, [rdi+monty_scratch_ofs]
	mov	rsi, [rax+bigint_words_ofs]
	mov	rcx, rdi
	shl	edx, 3
	push	r14 r15
	add	rcx, rdx
	push	rcx
	call	memcpy
	mov	rax, [rbx+monty_z_ofs]
	pop	rdi

	mov	ecx, [rax+bigint_size_ofs]
	mov	edx, [r13+bigint_size_ofs]
	mov	r15d, edx
	xor	esi, esi
	shl	edx, 1
	mov	r14d, edx
	sub 	edx, ecx
	shl	edx, 3
	call	memset32
	; setup for our monty reduce

	mov	eax, [r13+bigint_size_ofs]

	mov	r11, [rbx+monty_u_ofs]
	mov	esi, r14d
	mov	rdi, [r12+bigint_words_ofs]	; Result words
	mov	[r12+bigint_size_ofs], eax	; set size of the result to match our modulus

	mov	rdx, [rbx+monty_scratch_ofs]	; T (scratch)
	shl	esi, 3
	mov	rcx, [r13+bigint_words_ofs]	; modulus words
	mov	r8, [r11+bigint_words_ofs]	; u words
	add	rsi, rdx			; T+2*N (scratch)

	; so at this point:
	; rdi == R
	; rsi == T
	; rdx == X
	; rcx == M
	; r8 == U
	; r15d == N

	mov	rbx, rdi	; R
	mov	r12, rsi	; T
	mov	r13, rdx	; X
	mov	r14, rcx	; M
	
	mov	rsi, rdx
	mov	rdx, r8
	mov	ecx, r15d
	call	wd$mullower

	mov	rdi, r12
	mov	rsi, r13
	mov	rdx, rbx
	mov	rcx, r14
	mov	r8d, r15d
	call	wd$mulupper

	mov	r8d, r15d
	mov	rsi, r13	; X+N
	shl	r8d, 3
	mov	ecx, r15d	; N
	mov	rdi, r12	; T
	add	rsi, r8
	mov	rdx, r12	; T

        shl     ecx, 3
        add     rdi, rcx
        add     rsi, rcx
        add     rdx, rcx
        neg     rcx
        jz      .nosub
        mov     rax, [rsi+rcx]
        sub     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
calign
.subloop:
        mov     rax, [rsi+rcx+8]
        sbb     rax, [rdx+rcx+8]
        mov     [rdi+rcx+8], rax
        lea     rcx, [rcx+16]
        jrcxz   .nosub
        mov     rax, [rsi+rcx]
        sbb     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
        jmp     .subloop
calign
.nosub:
	; save the result in r13
	mov	r13d, 0
	adc	r13, r13

	mov	r8d, r15d
	mov	rdi, r12	; T+n
	shl	r8d, 3
	mov	ecx, r15d	; N
	mov	rsi, r12
	mov	rdx, r14
	add	rdi, r8

        shl     ecx, 3
        add     rdi, rcx
        add     rsi, rcx
        add     rdx, rcx
        neg     rcx
        jz      .noadd
        mov     rax, [rsi+rcx]
        add     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
calign
.addloop:
        mov     rax, [rsi+rcx+8]
        adc     rax, [rdx+rcx+8]
        mov     [rdi+rcx+8], rax
        lea     rcx, [rcx+16]
        jrcxz   .noadd
        mov     rax, [rsi+rcx]
        adc     rax, [rdx+rcx]
        mov     [rdi+rcx], rax
        jmp     .addloop
calign
.noadd:
	; last but not least, we need to copy the result
	xor	eax, eax
	mov	rdi, rbx
	sub	rax, r13
	mov	rsi, r12
	and	rax, r15
	mov	edx, r15d
	shl	rax, 3
	shl	edx, 3
	add	rsi, rax
	call	memcpy
	
	pop	r15 r14 r13 r12 rbx
	epilog

end if



if used monty$doit | defined include_everything
	; three arguments: rdi == monty object, rsi == destination bigint argument, rdx == bigint source argument
falign
monty$doit:
	prolog	monty$doit

if defined montydebug
	; debug
	push	rdi rsi rdx
	mov	rdi, .d1
	call	string$to_stdoutln
	mov	rdi, [rsp]
	call	bigint$debug
	pop	rdx rsi rdi
	; end debug
end if

	; first up, we need to do an (rdx copy, shl (64 * modulus size) % modulus)
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdi, [rdi+monty_r_ofs]
	mov	rsi, rdx
	call	bigint$assign
	mov	rcx, [rbx+monty_modulus_ofs]
	mov	rdi, [rbx+monty_r_ofs]
	mov	esi, [rcx+bigint_size_ofs]
	shl	esi, 6
	call	bigint$shl
	mov	rsi, [rbx+monty_modulus_ofs]
	mov	rdi, [rbx+monty_r_ofs]
	call	bigint$modby
	; first we need a montyws, which requires a single argument of our exponent
	push	r14
	mov	rdi, [rbx+monty_exp_ofs]
	call	montyws$new
	push	r15
	mov	r14, rax
	mov	rdi, rax
	call	montyws$next
	; we need a fixed area for up to 1 << 7 integers, which is only 128
	mov	r15d, 1
	mov	ecx, [r14+montyws_winsize_ofs]
	sub	ecx, 1
	shl	r15d, cl
	mov	[rbx+monty_gcount_ofs], r15d

	; so here, we need to set all to pow2(64*modulus.size)%modulus
	; use monty_w_ofs for its base
	mov	rcx, [rbx+monty_modulus_ofs]
	mov	rdi, [rbx+monty_w_ofs]
	mov	esi, [rcx+bigint_size_ofs]
	shl	esi, 6
	call	bigint$set_pow2
	mov	rdi, [rbx+monty_w_ofs]
	mov	rsi, [rbx+monty_modulus_ofs]
	call	bigint$modby
calign
.ginit:
	mov	rdi, [rbx+monty_w_ofs]
	call	bigint$new_copy
	mov	[rbx+r15*8+monty_g_ofs-8], rax
	sub	r15d, 1
	jnz	.ginit

	; g = monty_r_ofs (which is already our temp that we did the conversion on from the actual argument passed to us)
	; we can use r15 for our exponent bit position
	; which conveniently is already zero
	cmp	dword [r14+montyws_done_ofs], 1
	je	.do_r
calign
.accloop:
	cmp	r15d, [r14+montyws_winstart_ofs]
	jne	.accnext
	; otherwise, we need to find g[r14.expwin/2]
	mov	ecx, [r14+montyws_expwin_ofs]
	shr	ecx, 1
	mov	rsi, [rbx+rcx*8+monty_g_ofs]
	mov	rdx, [rbx+monty_r_ofs]
	mov	rdi, rbx

	call	monty$acc

	mov	rdi, r14
	call	montyws$next
calign
.accnext:
	cmp	dword [r14+montyws_done_ofs], 1
	je	.do_r

	; square r13, reduce r13

if defined montydebug
	mov	rdi, .ident1
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_r_ofs]
	call	bigint$debug
end if

	mov	rdi, [rbx+monty_z_ofs]
	mov	rsi, [rbx+monty_r_ofs]
	call	bigint$square_into

if defined montydebug
	mov	rdi, .ident2
	call	string$to_stdoutln
	mov	rdi, [rbx+monty_z_ofs]
	call	bigint$debug
end if

	mov	rdi, rbx
	mov	rsi, [rbx+monty_r_ofs]
	call	monty$reduce_z_into
	add	r15d, 1

	jmp	.accloop
if defined montydebug

cleartext .ident1, 'monty$square (not really):'
cleartext .ident2, 'bigint$square_into result:'

end if

calign
.do_r:
	mov	ecx, [rbx+monty_gcount_ofs]
	sub	ecx, 1
	mov	rsi, [rbx+rcx*8+monty_g_ofs]
	mov	rdi, r12
	call	bigint$assign
	cmp	dword [rbx+monty_gcount_ofs], 1
	jbe	.cleanup
	mov	r15d, [rbx+monty_gcount_ofs]
	sub	r15d, 2
calign
.rloop:
	test	r15d, r15d
	jz	.rfinal
	mov	rsi, [rbx+r15*8+monty_g_ofs]
	mov	rdx, [rbx+r15*8+monty_g_ofs+8]
	mov	rdi, rbx
	call	monty$acc
	mov	rsi, r12
	mov	rdx, [rbx+r15*8+monty_g_ofs]
	mov	rdi, rbx
	call	monty$acc
	sub	r15d, 1
	jmp	.rloop
calign
.rfinal:
	mov	rsi, [rbx+monty_g_ofs]		; g[0]
	mov	rdx, [rbx+monty_g_ofs+8]	; g[1]
	mov	rdi, rbx
	call	monty$acc
	; square r12, reduce r12
	mov	rdi, [rbx+monty_z_ofs]
	mov	rsi, r12
	call	bigint$square_into
	mov	rdi, rbx
	mov	rsi, r12
	call	monty$reduce_z_into

	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, [rbx+monty_g_ofs]		; g[0]
	call	monty$add
	; now set the result of that, which is in monty_r1_ofs
	mov	rdi, r12
	mov	rsi, [rbx+monty_r1_ofs]
	call	bigint$assign
	; cleanup
calign
.cleanup:
	; so we have a montyws in r14
	mov	rdi, r14
	call	montyws$destroy
	; and we have our g temps
	mov	r15d, [rbx+monty_gcount_ofs]
calign
.gfree:
	mov	rdi, [rbx+r15*8+monty_g_ofs-8]
	call	bigint$destroy
	sub	r15d, 1
	jnz	.gfree
	; LAST but certainly not least, we have to do a proper Montgomery Reduction on the result sitting in r12
	mov	rdi, rbx
	mov	rsi, r12
	call	monty$reduce

if defined montydebug
	; debug
	mov	rdi, .d3
	call	string$to_stdoutln
	mov	rdi, r12
	call	bigint$debug
end if

	pop	r15 r14 r12 rbx
	epilog

if defined montydebug
cleartext .d1, 'monty$doit, source is:'
cleartext .d2, '              base is:'
cleartext .d3, 'monty$doit, END RESULT IS:'
cleartext .d4, 'monty$doit, identity is:'
end if

end if

