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
	; string_math.inc: double to/fro string conversion math helpers
	;

if used string$frexp | defined include_everything
	; two arguments: xmm0 and rdi == expptr, return in rax (smashes xmm0)
falign
string$frexp:
	prolog_silent	string$frexp
	; NOTE: frexp does not modify rdi, so we are not saving it
	call	frexp
	sub	dword [rdi], 53	; *expptr -= 53
	mulsd	xmm0, [_math_1shl53]	; m * (double)(1 << 53)
	cvtsd2si	rax, xmm0
	epilog
end if
	

if used string$qp2 | defined include_everything
	; rdi == exp, return in xmm0, smashes xmm1
falign
string$qp2:
	prolog_silent	string$qp2
	cmp	rdi, 64
	jge	.doublepow
	cmp	rdi, 0
	jle	.doublepow
	mov	ecx, edi
	mov	edi, 1
	shl	rdi, cl
	cvtsi2sd	xmm0, rdi
	epilog
calign
.doublepow:
	movq	xmm0, [_math_two]
	cvtsi2sd	xmm1, rdi
	call	pow
	epilog
end if


if used string$qp10 | defined include_everything
	; rdi == exp, return in xmm0, smashes xmm1
falign
string$qp10:
	prolog_silent	string$qp10
	cmp	rdi, 23
	jge	.doublepow
	cmp	rdi, 0
	jle	.doublepow
	shl	rdi, 3
	add	rdi, .kpowten
	movq	xmm0, [rdi]
	epilog
calign
.doublepow:
	movq	xmm0, [_math_ten]
	cvtsi2sd	xmm1, rdi
	call	pow
	epilog
dalign
.kpowten:
        dq      1.0f, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
end if


if used string$bqp10 | defined include_everything
	; rdi == exp, rsi == bint result
falign
string$bqp10:
	prolog_silent	string$bqp10
	push	rsi
	call	string$qp10
	pop	rdi
	call	stringbi$sfd
	epilog
end if


; next up: stringbi goods, intentionally 32bit word sizes here (TODO: someday when I am bored, replace all this)

stringbi_size = 64

if used stringbi$init | defined include_everything
	; single argument: rdi == buffer (which should be stringbi_size bytes in length)
	; note: do not use this one-liner, haha, reference only
falign
stringbi$init:	; init
	prolog_silent	stringbi$init
	mov	dword [rdi], 0
	epilog
end if


if used stringbi$sfi | defined include_everything
	; two arguments: rdi == buffer, esi == int to set it from
falign
stringbi$sfi:	; set from int
	prolog_silent	stringbi$sfi
	mov	dword [rdi], 1
	mov	dword [rdi+4], esi
	epilog
end if


if used stringbi$sfbi | defined include_everything
	; four arguments: rdi == buffer, rsi == o, edx == offset, ecx == amount
falign
stringbi$sfbi:	; set from other stringbi
	prolog_silent	stringbi$sfbi
	mov	dword [rdi], ecx
	add	rdi, 4
	test	ecx, ecx
	jz	.alldone
	shl	edx, 2
	add	rsi, rdx
calign
.top:
	mov	edx, dword [rsi]
	mov	dword [rdi], edx
	add	rsi, 4
	add	rdi, 4
	sub	ecx, 1
	jnz	.top
	epilog
calign
.alldone:
	epilog
end if


if used stringbi$cf | defined include_everything
	; two arguments: rdi == bfufer, rsi == source
	; dont call this, do the memcpy yourself
falign
stringbi$cf:		; copy
	prolog_silent	stringbi$cf
	mov	edx, stringbi_size
	call	memcpy
	epilog
end if


if used stringbi$sfd | defined include_everything
	; two arguments: rdi == buffer, xmm0 == value
falign
stringbi$sfd:		; set from double
	prolog_silent	stringbi$sfd
	push	r12
	sub	rsp, 8
	mov	r12, rdi
	mov	rdi, rsp	; for our string$frexp
	call	string$frexp
	mov	rdi, r12
	mov	esi, dword [rsp]
	; rax now has the result, xmm0 got smashed
	mov	dword [r12+4], eax
	shr	rax, 32
	mov	dword [r12+8], eax
	cmp	eax, 0
	jg	.twowords
	mov	dword [r12], 1
	cmp	esi, 0
	jl	.rshift
	add	rsp, 8
	pop	r12
	call	stringbi$lsb		; rdi == buffer, esi == shiftcount
	epilog
calign
.twowords:
	mov	dword [r12], 2
	cmp	esi, 0
	jl	.rshift
	add	rsp, 8
	pop	r12
	call	stringbi$lsb		; rdi == buffer, esi == shiftcount
	epilog
calign
.rshift:
	neg	esi
	add	rsp, 8
	pop	r12
	call	stringbi$rsb		; rdi == buffer, esi == shiftcount
	epilog
end if


if used stringbi$subtract | defined include_everything
	; three arguments: rdi == buffer, rsi == smaller, rdx == result
falign
stringbi$subtract:
	; c == rax
	; x == rcx
	; bigger = rdi
	; r8 == sbuf
	; r9 == bbuf
	; r10 == rbuf
	; r11 == borrow
	; r12 == idx
	prolog_silent	stringbi$subtract
	push	r12

	push	rdi rsi rdx
	call	stringbi$c
	pop	rdx rsi rdi
	cmp	eax, 0
	je	.zerores
	jg	.noswap
	mov	rcx, rsi
	mov	rsi, rdi
	mov	rdi, rcx	; bigger/smaller swapped
calign
.noswap:
	mov	ecx, dword [rdi]	; bigger.length
	add	ecx, 1
	; rdx.snw(ecx, 1)
	mov	r10d, dword [rdx]	; oldlength == rdx.length
	mov	dword [rdx], ecx	; newlength == total words
	cmp	r10d, ecx
	jge	.firstsnwclear
	sub	r10d, 1
	mov	eax, r10d
	shl	eax, 2
	add	rax, rdx
	add	rax, 4
calign
@@:
	mov	dword [rax], 0
	add	rax, 4
	add	r10d, 1
	cmp	r10d, ecx
	jb	@b
calign
.firstsnwclear:
	mov	r8, rsi
	add	r8, 4			; sbuf
	mov	r9, rdi
	add	r9, 4			; bbuf
	mov	r10, rdx
	add	r10, 4			; rbuf
	mov	eax, dword [rsi]	; smaller.length into c
	xor	r11d, r11d		; borrow = 0
	xor	r12d, r12d		; idx = 0
calign
.sloop:
	mov	ecx, dword [r9]
	mov	esi, dword [r8]
	sub	rcx, rsi
	sub	rcx, r11
	mov	r11, rcx
	shr	r11, 32
	and	r11, 1
	mov	dword [r10], ecx
	add	r9, 4
	add	r8, 4
	add	r10, 4
	add	r12, 1
	sub	eax, 1
	jnz	.sloop
	mov	eax, dword [rdi]	; bigger.length into c
	cmp	r12d, eax
	jge	.chopidx
	sub	rax, r12
calign
.bloop:
	mov	ecx, dword [r9]
	sub	rcx, r11
	mov	r11, rcx
	shr	r11, 32
	and	r11, 1
	mov	dword [r10], ecx
	add	r9, 4
	add	r10, 4
	add	r12, 1
	sub	eax, 1
	jnz	.bloop
calign
.chopidx:
	sub	r10, 4
	sub	r12, 1
	cmp	dword [r10], 0
	je	.chopidx
	add	r12, 1
	mov	dword [rdx], r12d	; result.snw(idx, 0)
	pop	r12
	epilog
calign
.zerores:
	mov	dword [rdx], 1
	mov	dword [rdx+4], 0
	pop	r12
	epilog
end if



if used stringbi$mbi | defined include_everything
	; two arguments: rdi == buffer, rsi == factor
falign
stringbi$mbi:	; multiply by integer
	prolog_silent	stringbi$mbi
	xor	edx, edx	; clear the add
	call	stringbi$maib
	epilog
end if


if used stringbi$mbd | defined include_everything
	; two args, rdi == buffer, xmm0 == factor
falign
stringbi$mbd:	; multiply by double
	prolog_silent	stringbi$mbd
	push	r12 r13
	mov	r13, rdi
	sub	rsp, stringbi_size
	mov	r12, rsp
	mov	rdi, rsp
	call	stringbi$sfd
	mov	rdi, r13
	mov	rsi, r12
	call	stringbi$mb
	add	rsp, stringbi_size
	pop	r13 r12
	epilog
end if


if used stringbi$dvo | defined include_everything
	; one arg: rdi == buffer, return in xmm0
falign
stringbi$dvo:	; double value of
	prolog_silent	stringbi$dvo
	mov	edx, dword [rdi]
	cmp	dword [rdi], 1
	je	.cvtreturn
	sub	edx, 1		; nextWord = numwords - 1
	push	r12 r13 r14 r15
	; no function callouts here... but we need rcx for shift ops
	mov	eax, 1		; bits = 1
	mov	ecx, dword [rdi+rdx*4+4]
calign
.bitsloop:
	cmp	ecx, 1
	jbe	.bitsset
	shr	ecx, 1
	add	eax, 1
	jmp	.bitsloop
calign
.bitsset:
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	r11d, r11d
	xor	r12d, r12d
	mov	r13d, 53
	xor	r14d, r14d
	mov	r15d, 1		; for our cmovs
calign
.posloop:
	cmp	r13d, 0
	jle	.checkpos
	mov	r12d, dword [rdi+rdx*4+4]
	mov	ecx, r14d	; wshift
	shr	r12, cl
	or	r11, r12
	; put w back:
	mov	r12d, dword [rdi+rdx*4+4]
	sub	edx, 1
	sub	r13d, eax	; pos -= bits
	cmp	r13d, 0
	jle	.checkpos
	cmp	edx, -1
	jle	.checkpos
	cmp	r13d, 31
	jg	.posloopbig
	mov	eax, r13d	; bits = pos
	mov	r14d, 32
	sub	r14d, eax	; wshift = 32 - bits
	mov	ecx, eax
	shl	r11, cl		; resultMantissa <<= bits
	jmp	.posloop
calign
.posloopbig:
	mov	eax, 32		; bits = 32
	xor	r14d, r14d	; wshift = 0
	shl	r11, 32		; resultMantissa <<= 32
	jmp	.posloop
calign
.checkpos:
	cmp	r13d, 0
	jg	.nearlythere	; pos > 0 don't do squat.
	test	r11, 1
	cmovnz	r8d, r15d	; bit53 = (resultmantissa & 1)
	cmp	eax, 32
	jne	.bitsnot32
	cmp	edx, -1
	jle	.nearlythere
	mov	r12d, dword [rdi+rdx*4+4]
	sub	edx, 1
	test	r12d, 2147483648	; 1 << 31
	cmovnz	r9d, r15d
	test	r12d, 2147483647	; (1 << 31) - 1
	cmovnz	r10d, r15d
	jmp	.nearlythere
calign
.bitsnot32:
	; use r15 temporarily
	mov	ecx, r14d
	sub	ecx, 1
	shl	r15, cl		; r15 == 1 << (wshift - 1)
	mov	ecx, 1
	test	r12, r15
	cmovnz	r9d, ecx	; bit54 = (w & (1<<(wshift-1)))
	cmp	r14d, 1
	jle	.bitsnot32_1
	sub	r15, 1
	test	r12, r15
	cmovnz	r10d, ecx	; rest =
calign
.bitsnot32_1:
	cmp	edx, -1
	jle	.nearlythere
	test	r10d, r10d
	jnz	.nearlythere
	cmp	dword [rdi+rdx*4+4], 0
	cmovne	r10d, ecx
calign
.nearlythere:
	test	r9d, r9d
	jz	.nearlythere_1
	or	r8d, r10d
	; or sets the zero flag for us so we don't need a subsequent test	r8d, r8d
	jz	.nearlythere_1
	add	r11, 1
calign
.nearlythere_1:
	mov	r12, r11
	; lg2 gets inlined: (rdi is still valid)
	mov	eax, dword [rdi]
	sub	eax, 1
	mov	edx, eax	; setup our index
	mov	ecx, 32
	mul	ecx

	mov	edx, dword [rdi]
	sub	edx, 1
	
	mov	ecx, dword [rdi+rdx*4+4]
calign
.bitsloop2:
	cmp	ecx, 1
	jbe	.bitsset2
	shr	ecx, 1
	add	eax, 1
	jmp	.bitsloop2
calign
.bitsset2:
	; eax == lg2
	sub	eax, 52		; + 1 - 53
	cmp	eax, 0
	jle	.alldone_cvt
	cmp	eax, 64
	jl	.useint
	mov	edi, 2
	mov	esi, eax
	cvtsi2sd	xmm0, edi
	cvtsi2sd	xmm1, eax
	call	pow
	cvtsi2sd	xmm1, r12
	mulsd	xmm0, xmm1
	pop	r15 r14 r13 r12
	epilog
calign
.useint:
	mov	ecx, eax
	mov	eax, 1
	shl	rax, cl
	cvtsi2sd	xmm1, rax
	cvtsi2sd	xmm0, r12
	mulsd	xmm0, xmm1
	pop	r15 r14 r13 r12
	epilog
calign
.alldone_cvt:
	cvtsi2sd	xmm0, r12
	pop	r15 r14 r13 r12
	epilog
calign
.alldone:
	pop	r15 r14 r13 r12
	epilog
calign
.cvtreturn:
	mov	eax, dword [rdi+4]
	cvtsi2sd	xmm0, eax
	epilog
end if


if used stringbi$m | defined include_everything
	; three arguments: rdi == buffer, rsi == smaller, rdx == result
falign
stringbi$m:	; multiply
	; c == rax
	; x == rcx
	; bigger == rdi
	; r8 == sbuf
	; r9 == bbuf
	; r10 == rbuf
	; r11 == f
	; r12 == p
	; r13 == olc
	; r14 == result
	; r15 == c
	prolog_silent	stringbi$m
	push	r12 r13 r14 r15
	mov	r14, rdx		; save our result
	mov	ecx, dword [rsi]	; smaller.length
	mov	r11d, dword [rdi]	; bigger.length
	cmp	ecx, r11d
	jl	.reallysmaller
	mov	r8, rsi
	mov	rsi, rdi
	mov	rdi, r8
calign
.reallysmaller:
	add	ecx, r11d		; maximum number of new words we'll have
	mov	dword [r14], ecx	; result.snw(x, 0)
	test	ecx, ecx
	jz	.noclear
	mov	r10, r14
	add	r10, 4			; rbuf
calign
.clearloop:
	mov	dword [r10], 0
	add	r10, 4
	sub	ecx, 1
	jnz	.clearloop
calign
.noclear:
	mov	r8, rsi
	add	r8, 4			; smaller.buffer into sbuf
	mov	r13d, dword [rsi]	; smaller.length into olc
	test	r13d, r13d
	jz	.alldone
	mov	r10, r14
	add	r10, 4			; result.buffer into rbuf
	; c == rax
	; x == rcx
	; bigger == rdi
	; r8 == sbuf
	; r9 == bbuf
	; r10 == rbuf
	; r11 == f
	; r12 == p
	; r13 == olc
	; r14 == result
	; r15 == c
calign
.outerloop:
	mov	r11d, dword [r8]	; f = [sbuf]
	test	r11d, r11d		; f?
	jz	.nofactor		; increments sbuf, increments rbuf, decrements olc, comes back
	xor	r15d, r15d		; c = 0
	push	r10			; save our position (rbuf+x)
	mov	r9, rdi
	add	r9, 4			; bigger.buffer into bbuf
	mov	ecx, dword [rdi]	; bigger.length into x
calign
.innerloop:
	mov	r12d, dword [r9]	; p = [bbuf]
	add	r9, 4			; move bbuf forward

	; mul r11, which multiplies rax * r11 and puts the result into rdx:rax
	mov	rax, r12		; get set for mul
	mul	r11			; rdx:rax = rax * r11

	mov	r12, rax		; p = p * f

	mov	esi, dword [r10]	; get [rbuf]
	add	r12, rsi		; p += [rbuf]
	add	r12, r15		; add p,c
	mov	r15, r12		; c = p
	shr	r15, 32			; c >>= 32
	mov	dword [r10], r12d	; [rbuf] = (p & 0xffffffff)
	add	r10, 4			; rbuf++
	sub	ecx, 1			; x--
	jnz	.innerloop		; more?
	mov	dword [r10], r15d	; [rbuf] = (c & 0xffffffff)
	pop	r10			; restore rbuf to pre-innerloop
	add	r10, 4			; rbuf++
	add	r8, 4			; sbuf++
	sub	r13d, 1			; olc--
	jnz	.outerloop		; more?
	; result.tlz(), then return
	mov	rdi, r14
	call	stringbi$tlz
	pop	r15 r14 r13 r12
	epilog
calign
.nofactor:
	add	r10, 4
	add	r8, 4
	sub	r13d, 1
	jnz	.outerloop
	; result.tlz(), then return
	mov	rdi, r14
	call	stringbi$tlz
	pop	r15 r14 r13 r12
	epilog
calign
.alldone:
	; result.tlz(), then return
	mov	rdi, r14
	call	stringbi$tlz
	pop	r15 r14 r13 r12
	epilog
end if


if used stringbi$a | defined include_everything
	; three arguments: rdi == buffer, rsi == smaller, rdx == result
falign
stringbi$a:	; add
	; c == rax
	; x == rcx
	; bigger = rdi
	; r8 == sbuf
	; r9 == bbuf
	; r10 == rbuf
	; r11 == borrow
	; r12 == idx
	prolog_silent	stringbi$a
	push	r12

	push	rdi rsi rdx
	call	stringbi$c
	pop	rdx rsi rdi
	cmp	eax, 0
	je	.zerores
	jg	.noswap
	mov	rcx, rsi
	mov	rsi, rdi
	mov	rdi, rcx	; bigger/smaller swapped
calign
.noswap:
	mov	ecx, dword [rdi]	; bigger.length
	add	ecx, 1
	; rdx.snw(ecx, 1)
	mov	r10d, dword [rdx]	; oldlength == rdx.length
	mov	dword [rdx], ecx	; newlength == total words
	cmp	r10d, ecx
	jge	.firstsnwclear
	sub	r10d, 1
	mov	eax, r10d
	shl	eax, 2
	add	rax, rdx
	add	rax, 4
calign
@@:
	mov	dword [rax], 0
	add	rax, 4
	add	r10d, 1
	cmp	r10d, ecx
	jb	@b
calign
.firstsnwclear:
	mov	r8, rsi
	add	r8, 4			; sbuf
	mov	r9, rdi
	add	r9, 4			; bbuf
	mov	r10, rdx
	add	r10, 4			; rbuf
	mov	eax, dword [rsi]	; smaller.length into c
	xor	r11d, r11d		; borrow = 0
	xor	r12d, r12d		; idx = 0
calign
.sloop:
	mov	ecx, dword [r9]
	mov	esi, dword [r8]
	add	rcx, rsi
	add	rcx, r11
	mov	r11, rcx
	shr	r11, 32
	and	r11, 1
	mov	dword [r10], ecx
	add	r9, 4
	add	r8, 4
	add	r10, 4
	add	r12, 1
	sub	eax, 1
	jnz	.sloop
	mov	eax, dword [rdi]	; bigger.length into c
	cmp	r12d, eax
	jge	.chopidx
	sub	rax, r12
calign
.bloop:
	mov	ecx, dword [r9]
	add	rcx, r11
	mov	r11, rcx
	shr	r11, 32
	and	r11, 1
	mov	dword [r10], ecx
	add	r9, 4
	add	r10, 4
	add	r12, 1
	sub	eax, 1
	jnz	.bloop
calign
.chopidx:
	test	r11, r11
	jz	.chopidxtwo
	mov	dword [r10], r11d
	add	r10, 4
	add	r12, 1
calign
.chopidxtwo:
	sub	r10, 4
	sub	r12, 1
	cmp	dword [r10], 0
	je	.chopidx
	add	r12, 1
	mov	dword [rdx], r12d	; result.snw(idx, 0)
	pop	r12
	epilog
calign
.zerores:
	; we compared the two and they are equal
	; check to see if it is one word only and said word is equal to zero for
	; quick[er] return from integer 0
	cmp	dword [rdi], 1
	jne	.noswap
	cmp	dword [rdi+4], 0
	jne	.noswap
	mov	dword [rdx], 1
	mov	dword [rdx+4], 0	; result.sfi(0)

	pop	r12
	epilog
end if
	

if used stringbi$co | defined include_everything
	; three arguments: rdi == buffer, rsi == other (buffer), rdx == offset (also a buffer)
falign
stringbi$co:	; compare offset
	prolog_silent	stringbi$co
	sub	rsp, stringbi_size
	mov	rcx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; temp.sfi(0)
	push	rsi
	mov	rsi, rdx
	mov	rdx, rcx
	call	stringbi$a
	pop	rsi
	mov	rdi, rsp
	call	stringbi$c
	add	rsp, stringbi_size
	epilog
end if


if used stringbi$mb | defined include_everything
	; two arguments: rdi == buffer, rsi == other (buffer)
falign
stringbi$mb:	; multiply by
	prolog_silent	stringbi$mb
	sub	rsp, stringbi_size
	mov	rdx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; temp.sfi(0)
	push	rdi
	call	stringbi$m
	pop	rdi
	mov	rsi, rsp
	mov	edx, stringbi_size
	call	memcpy
	add	rsp, stringbi_size
	epilog

end if


if used stringbi$decby | defined include_everything
	; two arguments: rdi == buffer, rsi == other
falign
stringbi$decby:	; decrement by
	prolog_silent	stringbi$decby
	sub	rsp, stringbi_size
	mov	rdx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; temp.sfi(0)
	push	rdi
	call	stringbi$subtract
	pop	rdi
	mov	rsi, rsp
	mov	rdx, stringbi_size
	call	memcpy
	add	rsp, stringbi_size
	epilog
end if


if used stringbi$lsb | defined include_everything
	; two arguments: rdi == buffer, esi == shift count
falign
stringbi$lsb:		; left shift by
	prolog_silent	stringbi$lsb
	push	r12 r13
	mov	r12, rdi
	sub	rsp, stringbi_size
	mov	r13, rsp
	mov	rdx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; temp.sfi(0)
	; rdi still valid
	; rsi is still valid
	; rdx valid from above
	call	stringbi$ls
	; copy our result:
	mov	rdi, r12
	mov	rsi, r13
	mov	edx, stringbi_size
	call	memcpy
	add	rsp, stringbi_size
	pop	r13 r12
	epilog
end if


if used stringbi$rsb | defined include_everything
	; two arguments: rdi == buffer, esi == shift count
falign
stringbi$rsb:		; right shift by
	prolog_silent	stringbi$rsb
	push	r12 r13
	mov	r12, rdi
	sub	rsp, stringbi_size
	mov	r13, rsp
	mov	rdx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; temp.sfi(0)
	; rdi still valid
	; rsi is still valid
	; rdx valid from above
	call	stringbi$rs
	; copy our result:
	mov	rdi, r12
	mov	rsi, r13
	mov	edx, stringbi_size
	call	memcpy
	add	rsp, stringbi_size
	pop	r13 r12
	epilog
end if


if used stringbi$db | defined include_everything

	; three arguments: rdi == buffer, rsi == divisor (buffer), rdx == result (buffer)
falign
stringbi$db:	; divide by
	prolog_silent	stringbi$db
	sub	rsp, stringbi_size
	mov	rcx, rdx
	mov	rdx, rsp
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; temp.sfi(0)
	; do we have to initialize our temporary? I don't think we do
	push	rdi
	call	stringbi$dm
	pop	rdi
	mov	rsi, rsp
	mov	edx, stringbi_size
	call	memcpy
	add	rsp, stringbi_size
	epilog
end if


if used stringbi$c | defined include_everything
	; two arguments: rdi == buffer, rsi == other (buffer), returns in eax
falign
stringbi$c:	; compare
	prolog_silent	stringbi$c
	mov	eax, dword [rsi]
	mov	ecx, dword [rdi]
	cmp	ecx, eax
	jg	.resone
	jl	.resnegone
	mov	edx, ecx
	sub	edx, 1
	shl	edx, 2
	push	rax		; save other's length
	add	rsi, rdx
	add	rsi, 4
	add	rdi, rdx
	add	rdi, 4
	pop	rdx		; restore others length
calign
.loop:
	mov	eax, dword [rdi]
	cmp	eax, dword [rsi]
	jb	.resnegone
	ja	.resone
	sub	rdi, 4
	sub	rsi, 4
	sub	edx, 1
	jnz	.loop
	xor	eax, eax
	epilog
calign
.resone:
	mov	eax, 1
	epilog
calign
.resnegone:
	mov	eax, -1
	epilog
end if
	

if used stringbi$maib | defined include_everything
	; three arguments: rdi == buffer, rsi == factor, edx == addition
falign
stringbi$maib:
	prolog_silent	stringbi$maib
	; eax == x
	; edx == carry
	mov	eax, dword [rdi]	; length
	test	eax, eax
	jz	.noloop
	mov	r8, rdi
	add	r8, 4			; ib
calign
.loop:
	mov	ecx, dword [r8]
	imul	rcx, rsi
	add	rcx, rdx
	mov	rdx, rcx
	shr	rdx, 32
	mov	dword [r8], ecx
	add	r8, 4
	sub	eax, 1
	jnz	.loop
	test	edx, edx
	jz	.nocarry
	mov	eax, dword [rdi]	; length
	add	eax, 1
	; rdi.snw(eax, 0)
	mov	dword [rdi], eax
	mov	dword [r8], edx
	epilog
calign
.noloop:
	test	edx, edx
	jz	.nocarry
	add	eax, 1
	; rdi.snw(eax, 0)
	mov	dword [rdi], eax
	mov	dword [rdi+1], edx
	epilog
calign
.nocarry:
	epilog
end if


if used stringbi$dm | defined include_everything
	; four arguments: rdi == buffer, rsi == divisor (buffer), rdx == residual (buffer), rcx == result (buffer)
falign
stringbi$dm:	; divmod
	prolog_silent	stringbi$dm
	; rdi (it) is only used initially, and we'll replace it with residual
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx
	call	stringbi$c
	cmp	eax, 0
	jl	.cnegone
	je	.cone
	mov	rdi, r14		; set residual to first arg
	mov	rsi, r12
	mov	edx, stringbi_size
	call	memcpy
	mov	r9d, dword [r13]	; divisor.length
	mov	r10d, dword [r15]	; oldlength == rdx.length
	mov	dword [r15], r9d	; newlength == total words
	cmp	r10d, r9d
	jge	.firstsnwclear
	sub	r10d, 1
	mov	eax, r10d
	shl	eax, 2
	add	rax, r15
	add	rax, 4
calign
@@:
	mov	dword [rax], 0
	add	rax, 4
	add	r10d, 1
	cmp	r10d, r9d
	jb	@b
calign
.firstsnwclear:
	mov	edx, dword [r14]	; residual.length
	sub	edx, 1
	shl	edx, 2
	mov	rax, r14
	add	rax, 4
	add	rdx, rax
	mov	eax, dword [rdx] 
	mov	r8, rdx
	sub	r8, 4
	mov	r9, rax			; save these two morsels for later
	mov	edx, dword [r13]	; divisor.length
	sub	edx, 1
	shl	edx, 2
	add	rdx, r13
	add	rdx, 4
	mov	ecx, dword [rdx]
	mov	r10, rcx		; save it
	xor	edx, edx		; clear rdx for div
	div	rcx
	; rax now has quotient
	mov	rbx, rax		; factor set
	test	rax, rax		
	jz	.refactor		; factor == 0
	cmp	rax, 10
	jge	.refactor		; factor >= 10
	jmp	.fcheckthree		; else, skip refactor bit
calign
.refactor:
	cmp	dword [r14], 1
	jle	.fcheckthree		; residual.length <= 1
	cmp	dword [r13], 1
	jle	.fcheckthree		; divisor.length <= 1
	mov	eax, dword [r8]
	shl	r9, 32
	or	rax, r9
	; rax == br
	xor	edx, edx
	div	r10
	mov	rbx, rax		; factor=
	cmp	rax, 9
	jle	.fcheckthree
	mov	rbx, 9
calign
.fcheckthree:
	; if (factor)
	test	rbx, rbx
	jz	.ccheck
	; we need a stack temporary for this section
	sub	rsp, stringbi_size
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; decr.sfi(0)
	mov	rdi, rsp
	mov	r12, rsp		; we can safely blast this and use it
	mov	rsi, r13
	mov	edx, stringbi_size
	call	memcpy			; decr.cf(divisor)
	mov	rdi, r12
	mov	rsi, rbx
	xor	edx, edx
	call	stringbi$maib		; decr.maib(factor, 0)
calign
.fcheckloop:
	mov	rdi, r12
	mov	rsi, r14
	call	stringbi$c		; decr.c(residual)
	cmp	eax, 1
	jne	.fcheckloopdone
	cmp	rbx, 0
	jle	.fcheckloopdone
	mov	rdi, r12
	mov	rsi, r13
	call	stringbi$decby		; decr.decby(devisor)
	sub	rbx, 1
	jmp	.fcheckloop
calign
.fcheckloopdone:
	mov	rdi, r14
	mov	rsi, r12
	call	stringbi$decby		; residual.decby(decr)
	add	rsp, stringbi_size	; done with our temporary, which also freed up r12 to use again
calign
.ccheck:
	mov	rdi, r14		; residual
	mov	rsi, r13		; divisor
	call	stringbi$c
	cmp	eax, 1
	jne	.cchecknotone
	mov	rdi, r14
	mov	rsi, r13
	call	stringbi$decby		; residual.decby(divisor)
	add	rbx, 1			; factor++
calign
.cchecknotone:
	; result->buffer[0] = (u32)factor
	mov	rdx, r15
	add	rdx, 4
	mov	dword [rdx], ebx
	
	; done
	mov	rdi, r15
	call	stringbi$tlz		; result.tlz()
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.fchecktwo:
	; if we made it here, factor >= 1
	cmp	rbx, 10
	jle	.fcheckthree		; no refactor necessary
	jmp	.refactor
calign
.cnegone:
	mov	rdi, r14
	mov	rsi, r12
	mov	edx, stringbi_size
	call	memcpy			; residual.cf(this)
	mov	dword [r15], 1
	mov 	dword [r15+4], 0	; result = 0
	; done
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.cone:
	mov	dword [r14], 1
	mov	dword [r15], 1
	mov	dword [r14+4], 0	; residual = 0
	mov	dword [r15+4], 1	; result = 1
	; done
	pop	r15 r14 r13 r12 rbx
	epilog
end if


if used stringbi$ls | defined include_everything
	; three arguemnts: rdi == buffer, esi == shift count, rdx == result buffer
falign
stringbi$ls:
	prolog_silent stringbi$ls
	mov	r8d, esi
	shr	r8d, 5		; number of new words
	mov	r9d, dword [rdi]
	add	r9d, r8d
	add	r9d, 1		; total words
	; rdx.snw(tw, 1)
	mov	r10d, dword [rdx]	; oldlength == rdx.length
	mov	dword [rdx], r9d	; newlength == total words
	cmp	r10d, r9d
	jge	.firstsnwclear
	sub	r10d, 1
	mov	eax, r10d
	shl	eax, 2
	add	rax, rdx
	add	rax, 4
calign
@@:
	mov	dword [rax], 0
	add	rax, 4
	add	r10d, 1
	cmp	r10d, r9d
	jb	@b
calign
.firstsnwclear:
	cmp	dword [rdi], 1
	jne	.notzero
	cmp	dword [rdi+4], 0
	jne	.notzero
	; result.sfi(0)
	mov	dword [rdx], 1
	mov	dword [rdx+4], 0
	epilog
calign
.notzero:
	mov	r10, rdx
	add	r10, 4
	test	r8d, r8d
	jz	.noclear
calign
.clearloop:
	mov	dword [r10], 0
	add	r10, 4
	sub	r8d, 1
	jnz	.clearloop
calign
.noclear:
	mov	r11d, dword [rdi]
	add	rdi, 4
	mov	ecx, esi
	and	ecx, 0x1f
	; now:
	; rdi == sbuf [ this (buffer) ]
	; rsi == ?
	; rdx == result (buffer)
	; r8d == x# (zero at this point)
	; r9d == tw
	; r10 == dbuf
	; r11d == l
	; ecx == shiftBy
	; rax == ?
	test	ecx, ecx
	jz	.nocarry
	; eax == sc
	; esi == c
	xor	esi, esi
	mov	eax, 32
	sub	eax, ecx
calign
.cloop:
	mov	r8d, dword [rdi]
	shl	r8d, cl
	or	r8d, esi
	mov	dword [r10], r8d
	add	r10, 4
	mov	esi, dword [rdi]
	xchg	eax, ecx		; swap them for the shr
	shr	esi, cl
	add	rdi, 4
	xchg	eax, ecx		; swap them back for the next loop iteration
	sub	r11d, 1
	jnz	.cloop
	mov	dword [r10], esi
	test	esi, esi
	jz	.noextraword
	add	r9d, 1
calign
.noextraword:
	sub	r9d, 1
	; rdx.snw(tw, 0)
	mov	dword [rdx], r9d
	epilog
calign
.nocarry:
	mov	r8d, dword [rdi]
	mov	dword [r10], r8d
	add	rdi, 4
	add	r10, 4
	sub	r11d, 1
	jnz	.nocarry
	sub	r9d, 1
	; rdx.snw(tw, 0)
	mov	dword [rdx], r9d
	epilog
end if


if used stringbi$rs | defined include_everything
	; three arguemnts: rdi == buffer, esi == shift count, rdx == result buffer
falign
stringbi$rs:
	prolog_silent stringbi$rs
	mov	r8d, esi
	shr	r8d, 5		; total fewer words
	mov	r9d, dword [rdi]
	sub	r9d, r8d	; new total words
	; rdx.snw(tw, 1)
	mov	r10d, dword [rdx]	; oldlength == rdx.length
	mov	dword [rdx], r9d	; newlength == total words
	cmp	r10d, r9d
	jge	.firstsnwclear
	sub	r10d, 1
	mov	eax, r10d
	shl	eax, 2
	add	rax, rdx
	add	rax, 4
calign
@@:
	mov	dword [rax], 0
	add	rax, 4
	add	r10d, 1
	cmp	r10d, r9d
	jb	@b
calign
.firstsnwclear:
	cmp	r8d, dword [rdi]
	jg	.zero
	mov	r8d, r9d
	sub	r8d, 1
	shl	r8d, 2
	mov	r10, rdx
	add	r10, 4
	add	r10, r8		; r10 == dbuf
	mov	r8d, dword [rdi]
	sub	r8d, 1
	shl	r8d, 2
	add	rdi, 4
	add	rdi, r8		; rdi == sbuf
	
	mov	ecx, esi
	and	ecx, 0x1f
	test	ecx, ecx
	jz	.nocarry
	mov	eax, 32
	sub	eax, ecx
	xor	esi, esi

	test	r9d, r9d
	jz	.nocloop
calign
.cloop:
	mov	r8d, dword [rdi]
	shr	r8d, cl
	or	r8d, esi
	mov	dword [r10], r8d
	sub	r10, 4
	mov	esi, dword [rdi]
	xchg	eax, ecx		; swap them for the shl
	shl	esi, cl
	xchg	eax, ecx		; swap them back for the next iteration
	sub	rdi, 4
	sub	r9d, 1
	jnz	.cloop
	mov	rdi, rdx
	call	stringbi$tlz
	epilog
calign
.nocarry:
	mov	r8d, dword [rdi]
	mov	dword [r10], r8d
	sub	rdi, 4
	sub	r10, 4
	sub	r9d, 1
	jnz	.nocarry
	mov	rdi, rdx
	call	stringbi$tlz
	epilog
calign
.zero:
	mov	dword [rdx], 1
	mov	dword [rdx+4], 0
	epilog
calign
.nocloop:
	mov	dword [rdx], 0
	mov	rdi, rdx
	call	stringbi$tlz
	epilog
end if


if used stringbi$tlz | defined include_everything
	; single argument: rdi (buffer)
falign
stringbi$tlz:		; trim leading zeroes
	prolog_silent	stringbi$tlz
	mov	eax, dword [rdi]
	sub	eax, 1
	shl	eax, 2
	mov	rsi, rdi
	add	rsi, 4
	add	rsi, rax
	mov	eax, dword [rdi]
	sub	eax, 1
calign
.loop:
	cmp	eax, 0
	jl	.loopdone
	cmp	dword [rsi], 0
	jne	.loopdone
	sub	eax, 1
	sub	rsi, 4
	jmp	.loop
calign
.loopdone:
	cmp	eax, -1
	je	.oneword
	add	eax, 1
	mov	dword [rdi], eax
	epilog
calign
.oneword:
	mov	dword [rdi], 1
	epilog
end if



virtual at rdi
	_dc_value	dq	?
	_dc_e		dd	?
	_dc_mantissa	dq	?
	_dc_mantprec	dd	?
	_dc_base10exp	dd	?
	_dc_finished	dd	?
	_dc_fastestok	dd	?
	_dc_minprec	dd	?
	_dc_lowok	dd	?
	_dc_highok	dd	?
	_dc_r		dq	?
	_dc_s		dq	?
	_dc_plus	dq	?
	_dc_minus	dq	?
	_dc_dr		dq	?
	_dc_ds		dq	?
	_dc_dplus	dq	?
	_dc_dminus	dq	?
	_dc_amode	dd	?
	_dc_bi		dq	?
	_dc_bi1		dq	?
end virtual	; 132 bytes
virtual at r12
	_dc12_value	dq	?
	_dc12_e		dd	?
	_dc12_mantissa	dq	?
	_dc12_mantprec	dd	?
	_dc12_base10exp	dd	?
	_dc12_finished	dd	?
	_dc12_fastestok	dd	?
	_dc12_minprec	dd	?
	_dc12_lowok	dd	?
	_dc12_highok	dd	?
	_dc12_r		dq	?
	_dc12_s		dq	?
	_dc12_plus	dq	?
	_dc12_minus	dq	?
	_dc12_dr	dq	?
	_dc12_ds	dq	?
	_dc12_dplus	dq	?
	_dc12_dminus	dq	?
	_dc12_amode	dd	?
	_dc12_bi	dq	?
	_dc12_bi1	dq	?
end virtual	; 132 bytes


stringdc_size = 132 + (stringbi_size * 6)




if used stringdc$new | defined include_everything
	; three arguments: xmm0 == value, edi == mode, esi == min digits
	; mode == 0 == normal, 1 == fixed, 2 == precision, 3 == exponential
	; returns new stringdc pointer (allocated via heap$alloc) in rax

	; TODO: get rid of mov	rdi, r12 and replace iwth dc12 goods
falign
stringdc$new:
	prolog_silent	stringdc$new
	; heap funcs do not screw with xmm0, so preserve our other two args
	push	r12	; preserve this one for the duration

	push	rdi rsi
	mov	edi, stringdc_size
	call	heap$alloc
	mov	rdi, rax
	mov	r12, rax
	pop	rdx rsi
	; so now, rdi is our pointer, esi == mode, edx == min digits
	mov	dword [_dc_amode], esi
	xor	ecx, ecx
	add	rax, 132		; header size
	mov	[_dc_r], rax
	add	rax, stringbi_size
	mov	[_dc_s], rax
	add	rax, stringbi_size
	mov	[_dc_plus], rax
	add	rax, stringbi_size
	mov	[_dc_minus], rax
	add	rax, stringbi_size
	mov	[_dc_bi], rax
	add	rax, stringbi_size
	mov	[_dc_bi1], rax
	movq	[_dc_value], xmm0	
	mov	dword [_dc_finished], ecx
	mov	dword [_dc_fastestok], ecx
	mov	dword [_dc_lowok], ecx
	mov	dword [_dc_highok], ecx
	mov	dword [_dc_minprec], edx
	mov	dword [_dc_mantprec], 53
	sub	rsp, 8
	mov	rdi, rsp
	call	string$frexp
	mov	ecx, dword [rsp]
	add	rsp, 8
	mov	rdi, r12
	mov	dword [_dc_e], ecx
	mov	[_dc_mantissa], rax
	cmp	dword [_dc_amode], 0
	jne	.notnormal
	test	eax, 1
	jnz	.lowhighset
	mov	dword [_dc_lowok], 1
	mov	dword [_dc_highok], 1
	jmp	.lowhighset
calign
.notnormal:
	mov	dword [_dc_lowok], 1
	mov	dword [_dc_highok], 1
calign
.lowhighset:
	mov	ecx, dword [_dc_mantprec]
	test	ecx, ecx
	jz	.doneleadingzeroes
	mov	rax, [_dc_mantissa]
	sub	ecx, 1
	mov	dword [_dc_mantprec], ecx
	shr	rax, cl
	test	rax, 1
	jz	.lowhighset

calign
.doneleadingzeroes:
	add	dword [_dc_mantprec], 1
	mov	eax, [_dc_e]
	cmp	eax, 0
	jg	.noneg
	neg	eax
calign
.noneg:
	add	eax, dword [_dc_mantprec]
	sub	eax, 1
	cmp	eax, 50
	jge	.nofastestimate
	mov	dword [_dc_fastestok], 1
	cmp	dword [_dc_e], 0
	jl	.fastnege
	mov	rax, 1
	shl	rax, 52
	cmp	rax, [_dc_mantissa]
	je	.fastposetwo
	mov	edi, dword [_dc_e]
	call	string$qp2
	mov	rdi, r12
	movq	[_dc_dplus], xmm0
	movq	[_dc_dminus], xmm0
	movq	xmm1, [_math_two]
	mulsd	xmm0, xmm1
	mov	rax, [_dc_mantissa]
	cvtsi2sd	xmm2, rax
	mulsd	xmm0, xmm2
	movq	[_dc_dr], xmm0
	movq	[_dc_ds], xmm1
	jmp	.fastposemodecheck
calign
.fastposetwo:
	mov	edi, dword [_dc_e]
	call	string$qp2
	mov	rdi, r12
	movq	[_dc_dminus], xmm0
	movq	xmm2, [_math_two]
	movsd	xmm1, xmm0
	mulsd	xmm1, xmm2
	movq	[_dc_dplus], xmm1
	mulsd	xmm1, xmm2
	addsd	xmm2, xmm2
	movq	[_dc_ds], xmm2
	mov	rax, [_dc_mantissa]
	cvtsi2sd	xmm2, rax
	mulsd	xmm1, xmm2
	movq	[_dc_dr], xmm1
	jmp	.fastposemodecheck
calign
.fastnege:
	movq	xmm0, [_math_two]
	movq	xmm1, [_math_fiftytwo]
	call	pow
	cvtsd2si	rax, xmm0
	cmp	rax, [_dc_mantissa]
	je	.fastnegepowequal
	mov	rax, [_dc_mantissa]
	cvtsi2sd	xmm0, rax
	movsd	xmm1, [_math_two]
	mulsd	xmm0, xmm1
	movq	[_dc_dr], xmm0
	mov	eax, 1
	sub	eax, dword [_dc_e]
	mov	rdi, rax
	call	string$qp2
	mov	rdi, r12
	movq	[_dc_ds], xmm0
	movq	xmm1, [_math_one]
	movq	[_dc_dplus], xmm1
	movq	[_dc_dminus], xmm1
	jmp	.fastposemodecheck
calign
.fastnegepowequal:
	mov	rax, [_dc_mantissa]
	cvtsi2sd	xmm0, rax
	movq	xmm1, [_math_two]
	movq	[_dc_dplus], xmm1
	addsd	xmm1, xmm1
	mulsd	xmm0, xmm1	; mantissa * 4.0
	movq	[_dc_dr], xmm0
	movq	xmm1, [_math_one]
	movq	[_dc_dminus], xmm1
	mov	eax, 2
	sub	eax, dword [_dc_e]
	mov	rdi, rax
	call	string$qp2
	mov	rdi, r12
	movq	[_dc_dr], xmm0
calign
.fastposemodecheck:
	cmp	dword [_dc_amode], 0
	je	.setbase10
	mov	edi, [_dc_minprec]	; mindigits
	call	string$qp10
	mov	rdi, r12
	movsd	xmm2, xmm0
	movq	xmm0, [_dc_ds]
	movq	xmm1, [_dc_dr]
	mulsd	xmm0, xmm2
	mulsd	xmm1, xmm2
	movq	[_dc_ds], xmm0
	movq	[_dc_dr], xmm1
	jmp	.setbase10
calign
.nofastestimate:
	cmp	dword [_dc12_e], 0
	jl	.slownege
	mov	rax, [_dc12_bi]
	mov	dword [rax], 1
	mov	dword [rax+4], 1	; bi.sfi(1)
	mov	rdi, rax
	mov	esi, dword [_dc12_e]
	call	stringbi$lsb
	mov	rax, 1
	shl	rax, 52
	cmp	rax, [_dc12_mantissa]
	je	.slowposetwo
	movq	xmm0, [_dc12_value]
	mov	rdi, [_dc12_r]
	call	stringbi$sfd		; r.sfd(avalue)
	mov	rdi, [_dc12_r]
	mov	esi, 1
	call	stringbi$lsb		; r.lsb(1)
	mov	rdi, [_dc12_s]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 2	; s.sfi(2)
	mov	rdi, [_dc12_plus]
	mov	rsi, [_dc12_bi]
	mov	edx, stringbi_size
	call	memcpy			; mplus.cf(bi)
	mov	rdi, [_dc12_minus]
	mov	rsi, [_dc12_bi]
	mov	edx, stringbi_size
	call	memcpy			; mminus.cf(bi)
	jmp	.slowmodecheck
calign
.slowposetwo:
	mov	rax, [_dc12_bi1]
	mov	dword [rax], 1
	mov	dword [rax+4], 0	; bi1.sfi(0)
	mov	rdi, [_dc12_bi]
	mov	esi, 1
	mov	rdx, rax
	call	stringbi$ls		; bi.ls(1, bi1)
	movq	xmm2, [_dc12_value]
	movq	xmm0, [_math_two]
	addsd	xmm0, xmm0
	mulsd	xmm0, xmm2
	mov	rdi, [_dc12_r]
	call	stringbi$sfd		; r.sfd(4*value)
	mov	rdi, [_dc12_s]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 4	; s.sfi(4)
	mov	rdi, [_dc12_plus]
	mov	rsi, [_dc12_bi1]
	mov	edx, stringbi_size
	call	memcpy			; plus.cf(bi1)
	mov	rsi, [_dc12_minus]
	mov	rsi, [_dc12_bi]
	mov	edx, stringbi_size
	call	memcpy			; minus.cf(bi)
	jmp	.slowmodecheck
calign
.slownege:
	mov	rax, 2
	shl	rax, 51

	; WHY are we calling pow with two fixed arguments?
	; rax            0x10000000000000	4503599627370496

	; movq	xmm0, [_math_two]
	; movq	xmm1, [_math_fiftytwo]
	; call	pow
	; cvtsd2si	rax, xmm0
	cmp	rax, [_dc12_mantissa]
	je	.slownegepowequal
	mov	rax, [_dc12_mantissa]
	shl	rax, 1
	cvtsi2sd	xmm0, rax

	; movq	xmm1, [_math_two]
	; mulsd	xmm0, xmm1		; shl above does this for us
	mov	rdi, [_dc12_r]
	call	stringbi$sfd		; r.sfd(xmm0)

	mov	rdi, [_dc12_s]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 2	; s.sfi(2)
	mov	esi, dword [_dc12_e]
	neg	esi
	call	stringbi$lsb		; s.lsb(x)

	mov	rdi, [_dc12_plus]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 1	; plus.sfi(1)
	mov	rdi, [_dc12_minus]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 1	; minus.sfi(1)
	jmp	.slowmodecheck
calign
.slownegepowequal:
	movq	xmm1, [_math_four]
	mov	rax, [_dc12_mantissa]
	cvtsi2sd	xmm0, rax
	mulsd	xmm0, xmm1		; xmm0 now equals mantissa * 4.0
	mov	rdi, [_dc12_r]
	call	stringbi$sfd		; r.sfd(mantissa*4.0)
	mov	rdi, [_dc12_s]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 2	; s.sfi(2)
	mov	esi, 1
	sub	esi, dword [_dc12_e]
	call	stringbi$lsb		; s.lsb(x)
	mov	rdi, [_dc12_plus]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 2	; plus.sfi(2)
	mov	rdi, [_dc12_minus]
	mov	dword [rdi], 1
	mov	dword [rdi+4], 1	; minus.sfi(1)
calign
.slowmodecheck:
	cmp	dword [_dc12_amode], 0
	je	.setbase10
	mov	rsi, [_dc12_bi]
	mov	dword [rsi], 1
	mov	dword [rsi+4], 0	; bi.sfi(0)
	mov	edi, dword [_dc12_minprec]
	call	string$bqp10
	mov	rdi, [_dc12_s]
	mov	rsi, [_dc12_bi]
	call	stringbi$mb
	mov	rdi, [_dc12_r]
	mov	rsi, [_dc12_bi]
	call	stringbi$mb
calign
.setbase10:
	mov	rdi, r12	; this
	call	stringdc$s
	mov	dword [_dc12_base10exp], eax
	mov	rax, r12
	pop	rdi
	epilog
end if



if used stringdc$s | defined include_everything
	; single argument: rdi (this)
	; return in eax
falign
stringdc$s:
	prolog_silent	stringdc$s
	push	r12 r13
	movq	xmm1, [.kl2_10]
	movq	xmm2, [.ch]
	mov	r12, rdi
	mov	eax, [_dc_e]
	mov	ecx, [_dc_mantprec]
	sub	ecx, 1
	add	eax, ecx	; b2exp
	cvtsi2sd	xmm0, eax
	mulsd	xmm0, xmm1
	subsd	xmm0, xmm2
	; ceil
	call	ceil
	; result is in xmm0
	cvtsd2si	r13d, xmm0
	cmp	dword [_dc12_fastestok], 0
	je	.slow
	cmp	r13d, 0
	jge	.fastpos
	; fastneg
	mov	edi, r13d
	neg	edi
	call	string$qp10
	movq	xmm1, [_dc12_dr]
	movq	xmm2, [_dc12_dplus]
	movq	xmm3, [_dc12_dminus]
	mulsd	xmm1, xmm0
	mulsd	xmm2, xmm0
	mulsd	xmm3, xmm0
	movq	[_dc12_dr], xmm1
	movq	[_dc12_dplus], xmm2
	movq	[_dc12_dminus], xmm3
	jmp	.fastfee
calign
.fastpos:
	mov	edi, r13d
	call	string$qp10
	movq	xmm1, [_dc12_ds]
	mulsd	xmm1, xmm0
	movq	[_dc12_s], xmm1
calign
.fastfee:
	; fastfee:
	movq	xmm0, [_dc12_dr]
	movq	xmm1, [_dc12_dplus]
	movq	xmm2, [_dc12_ds]
	movq	xmm3, [_dc12_dminus]
	movq	xmm4, [_math_ten]
	addsd	xmm0, xmm1
	cmp	dword [_dc12_highok], 0
	je	.fasthighnotok
	comisd	xmm0, xmm2
	jae	.fastplusonedone
	jmp	.fastmult10
calign
.fasthighnotok:
	comisd	xmm0, xmm2
	ja	.fastplusonedone
calign
.fastmult10:
	mulsd	xmm0, xmm4
	mulsd	xmm1, xmm4
	mulsd	xmm3, xmm4
	movq	[_dc12_dr], xmm0
	movq	[_dc12_dplus], xmm1
	movq	[_dc12_dminus], xmm3
	mov	eax, r13d
	pop	r13 r12
	epilog
calign
.fastplusonedone:
	mov	eax, r13d
	add	eax, 1	; corrected ee
	pop	r13 r12
	epilog
calign
.slow:
	sub	rsp, stringbi_size
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; scale.sfi(0)
	cmp	r13d, 0
	jge	.slowpos
	mov	edi, r13d
	neg	edi
	mov	rsi, rsp
	call	string$bqp10

	mov	rdi, [_dc12_r]
	mov	rsi, rsp
	call	stringbi$mb
	mov	rdi, [_dc12_plus]
	mov	rsi, rsp
	call	stringbi$mb
	mov	rdi, [_dc12_minus]
	mov	rsi, rsp
	call	stringbi$mb
	add	rsp, stringbi_size
	jmp	.slowfee
calign
.slowpos:
	mov	edi, r13d
	mov	rsi, rsp
	call	string$bqp10
	mov	rdi, [_dc12_s]
	mov	rsi, rsp
	call	stringbi$mb
	add	rsp, stringbi_size
calign
.slowfee:
	mov	rdi, [_dc12_r]
	mov	rsi, [_dc12_s]
	mov	rdx, [_dc12_plus]
	call	stringbi$co
	cmp	dword [_dc12_highok], 0
	je	.slowhighnotok
	cmp	eax, -1
	jne	.slowplusonedone
	jmp	.slowmult10
calign
.slowhighnotok:
	cmp	eax, 1
	je	.slowplusonedone
calign
.slowmult10:
	mov	rdi, [_dc12_r]
	mov	esi, 10
	call	stringbi$mbi
	mov	rdi, [_dc12_plus]
	mov	esi, 10
	call	stringbi$mbi
	mov	rdi, [_dc12_minus]
	mov	esi, 10
	call	stringbi$mbi
	mov	eax, r13d
	pop	r13 r12
	epilog
calign
.slowplusonedone:
	mov	eax, r13d
	add	eax, 1
	pop	r13 r12
	epilog
dalign
.kl2_10	dq	0.30102999566398119521373889472449f
dalign
.ch	dq	0.0000000001f

end if


if used stringdc$nd | defined include_everything

	; single argument in rdi, return in eax
falign
stringdc$nd:
	prolog_silent	stringdc$nd
	cmp	dword [_dc_finished], 0
	jne	.alreadyfinished
	push	r12 r13 r14
	mov	r12, rdi
	cmp	dword [_dc_fastestok], 0
	je	.slow

	movq	xmm0, [_dc_dr]
	movq	xmm1, [_dc_ds]
	movsd	xmm4, xmm0	; save
	movsd	xmm5, xmm1	; ""
	call	fmod		; xmm0 now has mod
	divsd	xmm4, xmm5	; quotient into xmm4
	cvtsd2si	r13, xmm4	; quotient as integer into r13

	xor	eax, eax		; within low end round range?
	xor	r14d, r14d		; within high end round range?
	mov	ecx, 1			; positive value for the cmov

	movq	[_dc12_dr], xmm0
	movsd	xmm4, xmm0		; save it again
	movq	xmm1, [_dc12_dplus]
	movq	xmm2, [_dc12_dminus]
	cmp	dword [_dc12_lowok], 0
	je	.fastlownotokay
	comisd	xmm0, xmm2		; r <= minus?
	cmovbe	eax, ecx		; set eax to 1 if r <= minus, otherwise leave it at zero
	jmp	.fastcheckhighend
calign
.fastlownotokay:
	comisd	xmm0, xmm2
	cmovb	eax, ecx		; r < minus? set to 1 if so
calign
.fastcheckhighend:
	addsd	xmm4, xmm1		; r + plus
	cmp	dword [_dc12_highok], 0
	je	.fasthighnotokay
	comisd	xmm4, xmm5		; >= s?
	cmovae	r14d, ecx		; set to 1 if so
	jmp	.fastcheckquotient
calign
.fasthighnotokay:
	comisd	xmm4, xmm5
	cmova	r14d, ecx		; > s ?
calign
.fastcheckquotient:
	cmp	r13, 0
	jl	.fastbadquotient
	cmp	r13, 9
	jg	.fastbadquotient
calign
.fastdoit:
	; eax is our bool for within low end orund range
	; r14d is our bool for within high end round range
	test	eax, eax
	jnz	.fastwithinlowend
	; else, !fast within low end range
	; so now we have to check highend:
	test	r14d, r14d
	jnz	.fastquoteplusdone
	; else, !fast within low end range and !fastwithinhighendrange
	; so, dr *= 10, dplus *= 10, dminus *= 10, then return quotient
	movq	xmm6, [_math_ten]
	mulsd	xmm0, xmm6		; r *= 10 
	mulsd	xmm1, xmm6		; plus *= 10 
	mulsd	xmm2, xmm6		; minus *= 10 
	movq	[_dc12_dr], xmm0
	movq	[_dc12_dplus], xmm1
	movq	[_dc12_dminus], xmm2
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign	
.fastwithinlowend:
	test	r14d, r14d
	jz	.fastnotwithinhighendouter
	; else, if (dr * 2 < ds) finished = true else quotient++ && finished = true; done
	addsd	xmm0, xmm0
	comisd	xmm0, xmm5	; dr * 2 < js?
	jae	.fastquoteplusdone
	mov	dword [_dc12_finished], 1
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign
.fastquoteplusdone:
	mov	dword [_dc12_finished], 1
	add	r13, 1
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign
.fastnotwithinhighendouter:
	mov	dword [_dc12_finished], 1
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign
.fastbadquotient:
	xor	r13d, r13d
	jmp	.fastdoit
calign
.slow:
	sub	rsp, stringbi_size
	mov	dword [rsp], 1
	mov	dword [rsp+4], 0	; sfi(0)

	mov	rdi, [_dc12_r]
	mov	rsi, [_dc12_s]
	mov	rdx, rsp
	call	stringbi$db

	mov	r13d, dword [rsp+4]	; quotient == bi.buffer[0]
	add	rsp, stringbi_size
	
	mov	rdi, [_dc12_r]
	mov	rsi, [_dc12_minus]
	call	stringbi$c
	mov	r14, rax		; save it temporarily

	mov	rdi, [_dc12_r]
	mov	rsi, [_dc12_s]
	mov	rdx, [_dc12_plus]
	call	stringbi$co
	; so at this point, r14 has the low end comparison result, and rax has the high end comparison result
	; put them somewhere else
	mov	r8, r14			; low end comparison result
	mov	r9, rax			; high end comparison result

	xor	eax, eax		; within low end round range?
	xor	r14d, r14d		; within high end round range?
	mov	ecx, 1			; positive value for the cmov

	cmp	dword [_dc12_lowok], 0
	je	.slowlownotokay
	cmp	r8, 1
	cmovne	eax, ecx		; set eax to 1 if low end comparison != 1
	jmp	.slowcheckhighend
calign
.slowlownotokay:
	cmp	r8d, -1
	cmove	eax, ecx		; set eax to 1 if low end comparison == -1
calign
.slowcheckhighend:
	cmp	dword [_dc12_highok], 0
	je	.slowhighnotokay
	cmp	r9d, -1
	cmovne	r14d, ecx		; set r14d to 1 if high end comparison != -1
	jmp	.slowcheckquotient
calign
.slowhighnotokay:
	cmp	r9, 1
	cmove	r14d, ecx		; set r14d to 1 if high end comparison == 1
calign
.slowcheckquotient:
	cmp	r13, 0
	jl	.slowbadquotient
	cmp	r13, 9
	jg	.slowbadquotient
calign
.slowdoit:
	; eax is our bool for within low end orund range
	; r14d is our bool for within high end round range
	test	eax, eax
	jnz	.slowwithinlowend
	; else, !slow within low end range
	; so now we have to check highend:
	test	r14d, r14d
	jnz	.slowquoteplusdone
	; else, !slow within low end range and !slowwithinhighendrange
	; so, r *= 10, plus *= 10, minus *= 10, then return quotient
	mov	rdi, [_dc12_r]
	mov	esi, 10
	call	stringbi$mbi
	mov	rdi, [_dc12_plus]
	mov	esi, 10
	call	stringbi$mbi
	mov	rdi, [_dc12_minus]
	mov	esi, 10
	call	stringbi$mbi
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign	
.slowwithinlowend:
	test	r14d, r14d
	jz	.slownotwithinhighendouter
	; else, if stringbi$co(r, s, r) == -1 finished = true else quotient++ && finished = true; done
	mov	rdi, [_dc12_r]
	mov	rsi, [_dc12_s]
	mov	rdx, rdi
	call	stringbi$co
	cmp	eax, -1
	jne	.slowquoteplusdone
	mov	dword [_dc12_finished], 1
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign
.slowquoteplusdone:
	mov	dword [_dc12_finished], 1
	add	r13, 1
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign
.slownotwithinhighendouter:
	mov	dword [_dc12_finished], 1
	mov	rax, r13
	pop	r14 r13 r12
	epilog
calign
.slowbadquotient:
	xor	r13d, r13d
	jmp	.slowdoit
calign
.alreadyfinished:
	xor	eax, eax
	epilog

end if
