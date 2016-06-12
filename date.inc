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
	; date.inc: timestamp convenience functions
	;   as well as some julian date goods
	;

	;
	; some notes about my choices here.. I have always preferred to keep stamps
	; in double JD format... second-precision is never enough, and converting
	; to milliseconds like javascript et al do I don't particularly care for
	; as much either.
	;
	; SO: we use [our own] truncated JD (those extra few digits help in accuracy)
	; it of course is slower to get timestamps this way because of the
	; extra calcs required compared to a pure gettimeofday call, but where
	; these extra clock cycles are critical, we just use gettimeofday directly
	; anyway.
	;

	;
	; Note re: Leap Seconds: we are intentionally leap-second unaware
	; because the values we get from gettimeofday are adjusted for us anyway
	; we aren't doing NASA missions, so there isn't much point in adding
	; the leap second table or all the associated goodies in here.
	;


if used gtod_double | defined include_everything
	; no args: calls gettimeofday, converts value to unadulterated double in xmm0
falign
gtod_double:
	prolog	gtod_double
	sub	rsp, 16
	mov	rdi, rsp
	xor	esi, esi
	call	gettimeofday
	pop	rdx
	cvtsi2sd	xmm0, rdx
	pop	rcx
	cvtsi2sd	xmm1, rcx
	mulsd	xmm1, [.millions]
	addsd	xmm0, xmm1
	epilog
dalign
.millions	dq	0.000001f
end if


if used timestamp | defined include_everything
	; no args: calls gettimeofday, converts value to truncated julian date
	; returns our truncated jd in xmm0
falign
timestamp:
	prolog	timestamp
	sub	rsp, 16
	mov	rdi, rsp
	xor	esi, esi
	call	gettimeofday
	; June 30 2013 UTC 00:00 == 1372550400 == JD 2456473.5
	pop	r8		; our time_t
	sub	r8, 1372550400	; less our arbitrary marker
	cvtsi2sd	xmm0, r8
	pop	r9		; our usecs
	cvtsi2sd	xmm1, r9
	; note here: we could do better precision/resolution-wise
	; but for my purposes, this works well enough and is faster than
	; the other multiple div/add methods, etc.
	mulsd	xmm1, [.usecs2day]	; usecs / 1000000 sitting in xmm1
	mulsd	xmm0, [.secs2day]	; secs / 86400 sitting in xmm0
	addsd	xmm0, xmm1
	epilog
dalign
.usecs2day	dq	0.000000000011574074074f
dalign
.secs2day	dq	0.000011574074074f
end if

if used ctime$to_jd | defined include_everything
	; two arguments: rdi == tv_secs, rsi == tv_usecs
	; returns our truncated jd in xmm0
falign
ctime$to_jd:
	prolog	ctime$to_jd
	sub	rdi, 1372550400	; less our arbitrary marker
	cvtsi2sd	xmm0, rdi
	cvtsi2sd	xmm1, rsi
	; note here: we could do better precision/resolution-wise
	; but for my purposes, this works well enough and is faster than
	; the other multiple div/add methods, etc.
	mulsd	xmm1, [.usecs2day]	; usecs / 1000000 sitting in xmm1
	mulsd	xmm0, [.secs2day]	; secs / 86400 sitting in xmm0
	addsd	xmm0, xmm1
	epilog
dalign
.usecs2day	dq	0.000000000011574074074f
dalign
.secs2day	dq	0.000011574074074f

end if


if used timestamp$to_jd | defined include_everything
	; single arg in xmm0: our truncated timestamp (as returned from timestamp above)
	; returns real JD (+2456473.5 is all we do to it)
falign
timestamp$to_jd:
	prolog	timestamp$to_jd
	addsd	xmm0, [.modifier]
	epilog
calign
.modifier	dq	2456473.5f
end if

; datetime "struct" requires 16 bytes e

_datetime_yearofs	= 0		; all these are shorts
_datetime_monthofs	= 2
_datetime_dayofs	= 4
_datetime_hourofs	= 6
_datetime_minofs	= 8
_datetime_secofs	= 10		; 
_datetime_usecofs	= 12		; except this one, 32bit

if used timestamp$to_datetime | defined include_everything
	; two arguments: our own truncated jd in xmm0, and a 16 byte buffer for the datetime "struct" in rdi
falign
timestamp$to_datetime:
	prolog	timestamp$to_datetime
	addsd	xmm0, [.modifier]
	call	timestamp$jd_to_datetime
	epilog
calign
.modifier	dq	2456473.5f
end if



if used timestamp$jd_to_datetime | defined include_everything
	; two arguments: real JD in xmm0, and a 16 byte buffer for the datetime "struct" in rdi
falign
timestamp$jd_to_datetime:
	prolog	timestamp$jd_to_datetime
	push	rbx
	mov	rbx, rdi
	movsd	xmm15, xmm0		; save arg
	call	floor			; xmm0 = floor(xmm0)
	movsd	xmm10, xmm0		; save floor(xmm0)
	cvtsd2si	eax, xmm0	; integer portion
	subsd	xmm15, xmm0		; saved arg -= floor(arg)	(fractional portion)
	addsd	xmm15, qword [.halfdaycorrection]	; += 0.500000058
	comisd	xmm15, qword [_math_one]
	jb	.nohalfdaycorrect
	subsd	xmm15, qword [_math_one]
	add	eax, 1
	cvtsi2sd	xmm10, eax
calign
.nohalfdaycorrect:
	; integer whole portion in both eax and xmm0, fraction portion sitting in xmm15
	cmp	eax, 2299161		; 10-15-1582g
	jb	.nogregcorrection
	; gregorian calendar correction required, integer portion still sitting in xmm0
	subsd	xmm0, qword [.bce0001]
	divsd	xmm0, qword [.correct400]
	call	floor
	movsd	xmm12, xmm0		; century
	mulsd	xmm0, qword [.quarter]
	call	floor
	movsd	xmm13, xmm0		; floor(century * 0.25)
	movsd	xmm0, xmm12
	mulsd	xmm0, qword [.mquarter]
	call	floor
	movsd	xmm14, xmm0		; floor(century * 0.025)

	movsd	xmm8, xmm10		; scratch 1 = integer portion
	subsd	xmm8, qword [_math_two]	; - 2.0
	addsd	xmm8, xmm12		; + century
	subsd	xmm8, xmm13		; - floor(century * 0.25)
	addsd	xmm8, xmm14		; + floor(century * 0.025)
	; scratch 1 + 10 for missing days in october 1582, centennial years not leap years >1500, less 4000 year intervals
calign
.doit:
	; fractional portion still sitting in xmm15
	; scratch 1 sitting in xmm8
	movsd	xmm9, xmm8
	addsd	xmm9, qword [.l1]	; scratch 2 = scratch 1 + 1524

	movsd	xmm0, xmm9
	subsd	xmm0, qword [.l2]
	divsd	xmm0, qword [.l3]
	addsd	xmm0, qword [.l4]
	call	floor
	movsd	xmm10, xmm0		; scratch 3 = floor (6680 + (scratch 2 - 2439992.1) / 365.25)

	; xmm0 still loaded with scratch 3
	mulsd	xmm0, qword [.l3]
	call	floor
	movsd	xmm11, xmm0		; scratch 4 = floor(scratch 3 * 365.25)

	movsd	xmm0, xmm9
	subsd	xmm0, xmm11
	divsd	xmm0, qword [.l5]
	call	floor
	movsd	xmm12, xmm0		; scratch 5 = floor( (scratch 2 - scratch 4) / 30.6001 )

	mulsd	xmm0, qword [.l5]
	call	floor
	movsd	xmm7, xmm0		; floor(scratch 5 * 30.6001)

	movsd	xmm0, xmm9
	subsd	xmm0, xmm11
	subsd	xmm0, xmm7
	call	floor
	cvtsd2si	eax, xmm0
	mov	word [rbx+_datetime_dayofs], ax	; day = floor(scratch 2 - scratch 4 - floor(scratch 5 * 30.6001))
	movsd	xmm0, xmm12
	subsd	xmm0, qword [_math_one]
	cvtsd2si	eax, xmm0
	cmp	eax, 12
	jbe	.monthokay
	sub	eax, 12
calign
.monthokay:
	push	rax
	movsd	xmm0, xmm10
	subsd	xmm0, qword [.l6]
	call	floor
	cvtsd2si	eax, xmm0	; year = floor(scratch 3 - 4715)
	pop	rcx		; month
	mov	word [rbx+_datetime_monthofs], cx	; month
	cmp	ecx, 2
	jbe	.monthokay2
	sub	eax, 1		; if (month > 2) year--;
calign
.monthokay2:
	cmp	eax, 0
	jg	.timecalc
	sub	eax, 1		; no year 0000
	; TODO: get rid of these very large nop fills if align_inner is enabled
calign
.timecalc:
	mov	word [rbx+_datetime_yearofs], ax	; year
	; our fractional portion is still sitting in xmm15
	mulsd	xmm15, qword [.l7]	; fractional *= 86400
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.l8]
	call	floor			; hour = floor(fractional / 3600)
	cvtsd2si	eax, xmm0
	mov	word [rbx+_datetime_hourofs], ax
	mulsd	xmm0, qword [.l8]
	subsd	xmm15, xmm0		; fraction -= (hour * 3600)

	movsd	xmm0, xmm15
	divsd	xmm0, qword [.l9]
	call	floor			; min = floor(fractional / 60)
	cvtsd2si	eax, xmm0
	mov	word [rbx+_datetime_minofs], ax
	mulsd	xmm0, qword [.l9]
	subsd	xmm15, xmm0		; fraction -= (min * 60)
	
	movsd	xmm0, xmm15
	call	floor			; sec = floor(fractional)
	cvtsd2si	eax, xmm0
	mov	word [rbx+_datetime_secofs], ax

	subsd	xmm15, xmm0		; fractional -= sec
	mulsd	xmm15, qword [.l10]	; usec = fractional * 1000000
	cvtsd2si	eax, xmm15
	mov	dword [rbx+_datetime_usecofs], eax

	pop	rbx
	epilog
dalign
.nogregcorrection:
	; whole day < 2299161
	movsd	xmm8, xmm0		; scratch 1 = integer portion
	jmp	.doit
dalign
.bce0001	dq	1721119.25f
.correct400	dq	36524.225f
.quarter	dq	0.25f
.mquarter	dq	0.025f
.halfdaycorrection	dq	0.500000058f
.l1		dq	1524.0f
.l2		dq	2439992.1f
.l3		dq	365.25f
.l4		dq	6680.0f
.l5		dq	30.6001f
.l6		dq	4715.0f
.l7		dq	86400.0f
.l8		dq	3600.0f
.l9		dq	60.0f
.l10		dq	1000000.0f
end if


if used datetime$rfc5322_to_timestamp | defined include_everything
	; single argument in rdi: string of the datetime we are parsing
	; returns xmm0 truncated jd timestamp, or 0 on error
falign
datetime$rfc5322_to_timestamp:
	prolog	datetime$rfc5322_to_timestamp
	; haha, TODO: someday when I am bored, make this more efficient instead of my lazyboy method
	xorpd	xmm0, xmm0
	cmp	qword [rdi], 29
	jne	.bailout
	xor	ecx, ecx
	push	rbx
	sub	rsp, 16
	mov	[rsp], rcx
	mov	[rsp+8], rcx
	mov	rbx, rdi
	mov	esi, 5
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 6
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+1], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 8
	call	string$charat
	mov	byte [rsp+2], al
	mov	rdi, rbx
	mov	esi, 9
	call	string$charat
	mov	byte [rsp+3], al
	mov	rdi, rbx
	mov	esi, 10
	call	string$charat
	mov	byte [rsp+4], al
	; year is next
	mov	rdi, rbx
	mov	esi, 12
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+6], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 13
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+7], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 14
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+8], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 15
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+9], al
	cmp	eax, 9
	ja	.error
	; time is next
	mov	rdi, rbx
	mov	esi, 17
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+10], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 18
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+11], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 20
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+12], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 21
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+13], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 23
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+14], al
	cmp	eax, 9
	ja	.error
	mov	rdi, rbx
	mov	esi, 24
	call	string$charat
	sub	eax, '0'
	mov	byte [rsp+15], al
	cmp	eax, 9
	ja	.error
	; so [rsp] == 2 byte day
	; [rsp+2] == 4 byte month
	; [rsp+6] == 4 byte year
	; [rsp+10] == 2 byte hour
	; [rsp+12] == 2 byte min
	; [rsp+14] == 2 byte sec
	mov	r8d, 10
	movzx	eax, byte [rsp]
	movzx	ecx, byte [rsp+1]
	mul	r8d
	add	eax, ecx
	mov	byte [rsp], al		; day
	movzx	eax, byte [rsp+10]
	movzx	ecx, byte [rsp+11]
	mul	r8d
	add	eax, ecx
	mov	byte [rsp+10], al	; hour
	movzx	eax, byte [rsp+12]
	movzx	ecx, byte [rsp+13]
	mul	r8d
	add	eax, ecx
	mov	byte [rsp+12], al	; min
	movzx	eax, byte [rsp+14]
	movzx	ecx, byte [rsp+15]
	mul	r8d
	add	eax, ecx
	mov	byte [rsp+14], al	; sec
	mov	r9d, 100
	mov	r10d, 1000
	movzx	eax, byte [rsp+6]
	mul	r10d
	mov	ecx, eax
	movzx	eax, byte [rsp+7]
	mul	r9d
	add	ecx, eax
	movzx	eax, byte [rsp+8]
	mul	r8d
	add	ecx, eax
	movzx	eax, byte [rsp+9]
	add	ecx, eax
	mov	word [rsp+6], cx	; year
	xor	eax, eax
	mov	ecx, 1
	mov	edx, 2
	mov	r8d, 3
	mov	r9d, 4
	mov	r10d, 5
	mov	r11d, 6
	cmp	dword [rsp+2], 'Feb'
	cmove	eax, ecx
	cmp	dword [rsp+2], 'Mar'
	cmove	eax, edx
	cmp	dword [rsp+2], 'Apr'
	cmove	eax, r8d
	cmp	dword [rsp+2], 'May'
	cmove	eax, r9d
	cmp	dword [rsp+2], 'Jun'
	cmove	eax, r10d
	cmp	dword [rsp+2], 'Jul'
	cmove	eax, r11d
	mov	ecx, 7
	mov	edx, 8
	mov	r8d, 9
	mov	r9d, 10
	mov	r10d, 11
	cmp	dword [rsp+2], 'Aug'
	cmove	eax, ecx
	cmp	dword [rsp+2], 'Sep'
	cmove	eax, edx
	cmp	dword [rsp+2], 'Oct'
	cmove	eax, r8d
	cmp	dword [rsp+2], 'Nov'
	cmove	eax, r9d
	cmp	dword [rsp+2], 'Dec'
	cmove	eax, r10d
	movzx	edi, word [rsp+6]
	mov	esi, eax
	movzx	edx, byte [rsp]
	movzx	ecx, byte [rsp+10]
	movzx	r8d, byte [rsp+12]
	movzx	r9d, byte [rsp+14]
	add	rsp, 16
	pop	rbx
	add	esi, 1
	call	datetime$to_timestamp
	epilog
calign
.error:
	add	rsp, 16
	pop	rbx
	epilog
calign
.bailout:
	epilog

end if




if used datetime$to_timestamp | defined include_everything
	; six arguments: edi = year, esi = month, edx = day, ecx = hour, r8d = min, r9d = sec
	; returns xmm0 timestamp
falign
datetime$to_timestamp:
	prolog	datetime$to_timestamp
	sub	rsp, 48
	virtual at rsp
		_dtt_year	dd	?
		_dtt_month	dd	?
		_dtt_day	dd	?
		_dtt_hour	dd	?
		_dtt_min	dd	?
		_dtt_sec	dd	?
		_dtt_syear	dd	?
		_dtt_smonth	dd	?
		_dtt_int	dd	?
	end virtual
	mov	[_dtt_year], edi
	mov	[_dtt_month], esi
	mov	[_dtt_day], edx
	mov	[_dtt_hour], ecx
	mov	[_dtt_min], r8d
	mov	[_dtt_sec], r9d
	cmp	esi, 2
	ja	.marchorbetter
	mov	r10d, edi
	sub	r10d, 1
	mov	[_dtt_syear], r10d
	mov	r11d, esi
	add	r11d, 13
	mov	[_dtt_smonth], r11d
calign
.doint:
	cvtsi2sd	xmm0, r10d	; syear
	mulsd	xmm0, qword [.l1]	; * 365.25
	call	floor
	movsd	xmm10, xmm0		; save result of floor(syear * 365.25)
	mov	r11d, [_dtt_smonth]
	cvtsi2sd	xmm0, r11d	; smonth
	mulsd	xmm0, qword [.l2]	; * 30.6001
	call	floor

	cvtsd2si	ecx, xmm0
	cvtsd2si	edx, xmm10
	mov	eax, dword [_dtt_day]
	add	eax, ecx
	add	eax, edx
	add	eax, 1720995
	mov	dword [_dtt_int], eax
	
	; need to determine day + 31 * (month + 12 * year)
	xor	edx, edx
	mov	eax, [_dtt_year]
	mov	ecx, 12
	mul	ecx
	; eax now has year * 12
	add	eax, dword [_dtt_month]
	; eax now has (month + 12 * year)
	mov	ecx, 31
	mul	ecx
	; eax now has 31 * (month + 12 * year)
	add	eax, dword [_dtt_day]
	cmp	eax, 588829
	jl	.halfdaycorrect
	mov	eax, dword [_dtt_syear]
	cvtsi2sd	xmm0, eax
	mulsd	xmm0, qword [.l3]
	call	floor
	movsd	xmm13, xmm0		; save floor(syear * 0.01)
	mulsd	xmm0, qword [.l4]
	call	floor
	movsd	xmm14, xmm0		; save floor(floor(syear * 0.01) * 0.25)
	movsd	xmm0, xmm13
	mulsd	xmm0, qword [.l5]
	call	floor
	mov	eax, dword [_dtt_int]
	add	eax, 2
	cvtsd2si ecx, xmm13
	sub	eax, ecx
	cvtsd2si ecx, xmm14
	add	eax, ecx
	cvtsd2si ecx, xmm0
	sub	eax, ecx
	mov	dword [_dtt_int], eax
calign
.halfdaycorrect:
	mov	eax, [_dtt_hour]
	cvtsi2sd	xmm0, eax
	divsd	xmm0, qword [.l6]
	subsd	xmm0, qword [.l7]
	comisd	xmm0, [_math_zero]
	jae	.dofractional
	addsd	xmm0, [_math_one]
	sub	dword [_dtt_int], 1
calign
.dofractional:
	; we need to compute: xmm0 + (min + sec/60) / 1440)
	mov	eax, [_dtt_sec]
	cvtsi2sd	xmm1, eax
	divsd	xmm1, qword [.l8]
	mov	eax, [_dtt_min]
	cvtsi2sd	xmm2, eax
	addsd	xmm1, xmm2
	divsd	xmm1, qword [.l9]
	addsd	xmm0, xmm1
	; done and sitting in xmm0

	; add the integer part to it, then mul by 10m
	mov	eax, [_dtt_int]
	cvtsi2sd	xmm1, eax
	addsd	xmm0, xmm1
	mulsd	xmm0, qword [.l10]
	; save this in upper regs so floor doesn't smash it
	movsd	xmm15, xmm0	; scratch 0
	call	floor
	; scratch now in xmm0
	subsd	xmm15, xmm0
	comisd	xmm15, qword [.l7]
	jbe	.doret
	addsd	xmm0, [_math_one]
	divsd	xmm0, qword [.l10]
	subsd	xmm0, qword [.modifier]
	add	rsp, 48
	epilog
calign
.doret:
	divsd	xmm0, qword [.l10]
	subsd	xmm0, qword [.modifier]
	add	rsp, 48
	epilog
calign
.marchorbetter:
	mov	r10d, edi
	mov	[_dtt_syear], edi
	mov	r11d, esi
	add	r11d, 1
	mov	[_dtt_smonth], r11d
	jmp	.doint
dalign
.l1	dq	365.25f
.l2	dq	30.6001f
.l3	dq	0.01f
.l4	dq	0.25f
.l5	dq	0.025f
.l6	dq	24.0f
.l7	dq	0.5f
.l8	dq	60.0f
.l9	dq	1440.0f
.l10	dq	10000000.0f
.modifier	dq	2456473.5f

end if



if used format$duration | defined include_everything
	; three arguments: duration in xmm0, mininum resolution in edi, esi == # digits to do fractional on lowest res (0 == none)
	; duration is in DAYS (to suit all my funky julian date math goodies)
	; min resolution is:
	; 5 == weeks
	; 4 == days
	; 3 == hours
	; 2 == minutes
	; 1 == seconds
	; 0 == milliseconds
	; if esi is nonzero, then _if_ the minres is >0, will get fractional result put behind it to esi decimal places
	; examples, with various esi flavours
	; duration of 1.1, minres of 5 == 0.2w	(0.15714 weeks rounded up)
	; duration of 1.1, minres of 4 == 1.1d
	; duration of 1.1, minres of 3 == 1d2.4h
	; duration of 1.1, minres of 2 == 1d2h24m
	; duration of 1.1, minres of 1 == 1d2h24m0s
	; duration of 1.1, minres of 0 == 1d2h24m0.000s
	; duration of 0.000062141203704, minres of 0 == 5.369s
	; duration of 0.000062141203704, minres of 1 == 5s
	; duration of 0.000062141203704, minres of 2 == 0m
	; you get the idea.
	; returns a new string in rax

	; TODO: make this a better jump-around-table based instead of the code bloated copy/paste i did
falign
format$duration:
	prolog	format$duration
	push	r12 r13 r14 r15		; our string accumulators and fractional digits
	mov	r13d, edi
	mov	r15d, esi
	movsd	xmm15, xmm0
	mov	rdi, .initialstr
	call	string$copy
	mov	r12, rax		; empty string in r12 (which will be our end return)
	cmp	r13d, 5
	ja	.msecs
	jmp	qword [.restable + r13*8]
	; shl	r13d, 3
	; add	r13, .restable
	; jmp	qword [r13]
dalign
.restable:
	dq	.msecs, .secs, .mins, .hours, .days, .weeks
cleartext .initialstr, ''
cleartext .wstr,'w'
cleartext .dstr,'d'
cleartext .hstr,'h'
cleartext .mstr,'m'
cleartext .sstr,'s'

calign
.msecs:
	comisd	xmm15, [.seven]
	jb	.msecs_days
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.seven]
	call	floor
	; so now, we have our floored / 7 result
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.seven]
	subsd	xmm15, xmm0
	; so now, sitting in edi is our integer #
	mov	esi, 10			; radix
	call	string$from_int		; this can blast xmm0..3, but highers are preserved... TODO: this is non-standard insofar as I am relying on
					; the underlying calls not to destroy xmm15... because it all lives here this is perfectly safe, but hmmm
	mov	r13, rax		; integer string
	mov	rdi, r12		; accumulated string so far
	mov	rsi, rax		; integer string
	call	string$concat		; add them together
	mov	r14, rax		; save it
	mov	rdi, r12		; free first bit
	call	heap$free
	mov	rdi, r13
	call	heap$free		; free second bit
	mov	rdi, r14		; our saved accumulated string
	mov	rsi, .wstr
	call	string$concat
	mov	r12, rax		; our new accumulated string
	mov	rdi, r14
	call	heap$free		; free our last bit
calign
.msecs_days:
	comisd	xmm15, [_math_one]
	jb	.msecs_hours
	movsd	xmm0, xmm15
	call	floor
	cvtsd2si edi, xmm0
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .dstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.msecs_hours:
	comisd	xmm15, qword [.interval_hour]
	jb	.msecs_mins
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_hour]
	call	floor
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.interval_hour]
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .hstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.msecs_mins:
	comisd	xmm15, qword [.interval_min]
	jb	.msecs_secs
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_min]
	call	floor
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.interval_min]
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .mstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.msecs_secs:
	; our lowest precision is msecs, which really means 0.000 for seconds, not finger-still res
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_sec]
	mov	edi, 1	; fixed mode
	mov	esi, 3	; precision
	call	string$from_double
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .sstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
	mov	rax, r12
	pop	r15 r14 r13 r12
	epilog
calign
.secs:
	comisd	xmm15, [.seven]
	jb	.secs_days
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.seven]
	call	floor
	; so now, we have our floored / 7 result
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.seven]
	subsd	xmm15, xmm0
	; so now, sitting in edi is our integer #
	mov	esi, 10			; radix
	call	string$from_int		; this can blast xmm0..3, but highers are preserved... TODO: this is non-standard insofar as I am relying on
					; the underlying calls not to destroy xmm15... because it all lives here this is perfectly safe, but hmmm
	mov	r13, rax		; integer string
	mov	rdi, r12		; accumulated string so far
	mov	rsi, rax		; integer string
	call	string$concat		; add them together
	mov	r14, rax		; save it
	mov	rdi, r12		; free first bit
	call	heap$free
	mov	rdi, r13
	call	heap$free		; free second bit
	mov	rdi, r14		; our saved accumulated string
	mov	rsi, .wstr
	call	string$concat
	mov	r12, rax		; our new accumulated string
	mov	rdi, r14
	call	heap$free		; free our last bit
calign
.secs_days:
	comisd	xmm15, [_math_one]
	jb	.secs_hours
	movsd	xmm0, xmm15
	call	floor
	cvtsd2si edi, xmm0
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .dstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.secs_hours:
	comisd	xmm15, qword [.interval_hour]
	jb	.secs_mins
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_hour]
	call	floor
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.interval_hour]
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .hstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.secs_mins:
	comisd	xmm15, qword [.interval_min]
	jb	.secs_secs
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_min]
	call	floor
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.interval_min]
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .mstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.secs_secs:
	; our lowest precision is msecs, which really means 0.000 for seconds, not finger-still res
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_sec]
	test	r15d, r15d
	jnz	.secs_secs_dofrac
	call	floor
	cvtsd2si edi, xmm0
	mov	esi, 10
	call	string$from_unsigned
	jmp	.secs_secs_ready
calign
.secs_secs_dofrac:
	mov	edi, 1		; fixed mode
	mov	esi, r15d	; precision
	call	string$from_double
calign
.secs_secs_ready:
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .sstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
	mov	rax, r12
	pop	r15 r14 r13 r12
	epilog
calign
.mins:
	comisd	xmm15, [.seven]
	jb	.mins_days
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.seven]
	call	floor
	; so now, we have our floored / 7 result
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.seven]
	subsd	xmm15, xmm0
	; so now, sitting in edi is our integer #
	mov	esi, 10			; radix
	call	string$from_int		; this can blast xmm0..3, but highers are preserved... TODO: this is non-standard insofar as I am relying on
					; the underlying calls not to destroy xmm15... because it all lives here this is perfectly safe, but hmmm
	mov	r13, rax		; integer string
	mov	rdi, r12		; accumulated string so far
	mov	rsi, rax		; integer string
	call	string$concat		; add them together
	mov	r14, rax		; save it
	mov	rdi, r12		; free first bit
	call	heap$free
	mov	rdi, r13
	call	heap$free		; free second bit
	mov	rdi, r14		; our saved accumulated string
	mov	rsi, .wstr
	call	string$concat
	mov	r12, rax		; our new accumulated string
	mov	rdi, r14
	call	heap$free		; free our last bit
calign
.mins_days:
	comisd	xmm15, [_math_one]
	jb	.mins_hours
	movsd	xmm0, xmm15
	call	floor
	cvtsd2si edi, xmm0
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .dstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.mins_hours:
	comisd	xmm15, qword [.interval_hour]
	jb	.mins_mins
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_hour]
	call	floor
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.interval_hour]
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .hstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.mins_mins:
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_min]
	test	r15d, r15d
	jnz	.mins_mins_dofrac
	call	floor
	cvtsd2si edi, xmm0
	mov	esi, 10
	call	string$from_unsigned
	jmp	.mins_mins_ready
calign
.mins_mins_dofrac:
	mov	edi, 1		; fixed mode
	mov	esi, r15d	; precision
	call	string$from_double
calign
.mins_mins_ready:
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .mstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
	mov	rax, r12
	pop	r15 r14 r13 r12
	epilog
calign
.hours:
	comisd	xmm15, [.seven]		; we doing less than 7 days?
	jb	.hours_days
	; otherwise, we doing weeks bit:
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.seven]
	call	floor
	; so now, we have our floored / 7 result
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.seven]
	subsd	xmm15, xmm0
	; so now, sitting in edi is our integer #
	mov	esi, 10			; radix
	call	string$from_int		; this can blast xmm0..3, but highers are preserved... TODO: this is non-standard insofar as I am relying on
					; the underlying calls not to destroy xmm15... because it all lives here this is perfectly safe, but hmmm
	mov	r13, rax		; integer string
	mov	rdi, r12		; accumulated string so far
	mov	rsi, rax		; integer string
	call	string$concat		; add them together
	mov	r14, rax		; save it
	mov	rdi, r12		; free first bit
	call	heap$free
	mov	rdi, r13
	call	heap$free		; free second bit
	mov	rdi, r14		; our saved accumulated string
	mov	rsi, .wstr
	call	string$concat
	mov	r12, rax		; our new accumulated string
	mov	rdi, r14
	call	heap$free		; free our last bit
calign
.hours_days:
	comisd	xmm15, [_math_one]	; we doing less than 1 day?
	jb	.hours_hours
	movsd	xmm0, xmm15
	call	floor
	cvtsd2si edi, xmm0
	subsd	xmm15, xmm0
	mov	esi, 10
	call	string$from_int
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .dstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
calign
.hours_hours:
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.interval_hour]
	test	r15d, r15d
	jnz	.hours_hours_dofrac
	call	floor
	cvtsd2si edi, xmm0
	mov	esi, 10
	call	string$from_unsigned
	jmp	.hours_hours_ready
calign
.hours_hours_dofrac:
	mov	edi, 1		; fixed mode
	mov	esi, r15d	; precision
	call	string$from_double
calign
.hours_hours_ready:
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .hstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
	mov	rax, r12
	pop	r15 r14 r13 r12
	epilog
calign
.days:
	comisd	xmm15, [.seven]
	jb	.days_days
	movsd	xmm0, xmm15
	divsd	xmm0, qword [.seven]
	call	floor
	; so now, we have our floored / 7 result
	cvtsd2si edi, xmm0
	mulsd	xmm0, qword [.seven]
	subsd	xmm15, xmm0
	; so now, sitting in edi is our integer #
	mov	esi, 10			; radix
	call	string$from_int		; this can blast xmm0..3, but highers are preserved... TODO: this is non-standard insofar as I am relying on
					; the underlying calls not to destroy xmm15... because it all lives here this is perfectly safe, but hmmm
	mov	r13, rax		; integer string
	mov	rdi, r12		; accumulated string so far
	mov	rsi, rax		; integer string
	call	string$concat		; add them together
	mov	r14, rax		; save it
	mov	rdi, r12		; free first bit
	call	heap$free
	mov	rdi, r13
	call	heap$free		; free second bit
	mov	rdi, r14		; our saved accumulated string
	mov	rsi, .wstr
	call	string$concat
	mov	r12, rax		; our new accumulated string
	mov	rdi, r14
	call	heap$free		; free our last bit
calign
.days_days:
	movsd	xmm0, xmm15
	test	r15d, r15d
	jnz	.days_days_dofrac
	call	floor
	cvtsd2si edi, xmm0
	mov	esi, 10
	call	string$from_unsigned
	jmp	.days_days_ready
calign
.days_days_dofrac:
	mov	edi, 1		; fixed mode
	mov	esi, r15d	; precision
	call	string$from_double
calign
.days_days_ready:
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .dstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
	mov	rax, r12
	pop	r15 r14 r13 r12
	epilog
calign
.weeks:

	movsd	xmm0, xmm15
	divsd	xmm0, qword [.seven]
	; so now, we have our / 7 result
	test	r15d, r15d
	jnz	.weeks_dofrac
	call	floor
	cvtsd2si edi, xmm0
	mov	esi, 10
	call	string$from_unsigned
	jmp	.weeks_ready
calign
.weeks_dofrac:
	mov	edi, 1		; fixed mode
	mov	esi, r15d	; precision
	call	string$from_double
calign
.weeks_ready:
	mov	r13, rax
	mov	rdi, r12
	mov	rsi, rax
	call	string$concat
	mov	r14, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	mov	rsi, .wstr
	call	string$concat
	mov	r12, rax
	mov	rdi, r14
	call	heap$free
	mov	rax, r12
	pop	r15 r14 r13 r12
	epilog
dalign
.seven	dq	7.0f
.interval_hour	dq	0.041666666666667f
.interval_min	dq	0.000694444444444f
.interval_sec	dq	0.000011574074074f


end if
