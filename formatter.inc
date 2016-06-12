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
	; formatter.inc: a convenience object to format output into buffers or strings
	;
	; this provides "printf-like" string formatting with dynamic arguments, in a "reuseable" way
	; maximum dynamic arguments is of course register-dependent (e.g. doubles == xmm0..15, normal
	; == rsi, rdx, rcx, r8, r9, r10, r11 (noting here we are happy to extend the 6 arg normal max)
	; and you can of course "nest" them by using add_string and a second/third/whatever formatter
	; chained together
	;
	; it is a programmer error to add more than 7 normal register items, or 16 normal double items
	; (because a call then to formatter$doit would crash)
	;

formatter_regargs_ofs = 0		; int of how many register arguments we are expecting
formatter_xmmargs_ofs = 8		; int of how many xmm arguments we are expecting
formatter_items_ofs = 16		; list of formatitems
formatter_rargs_ofs = 24		; an empty (always) list for argument handling in formatter$doit
formatter_xargs_ofs = 32		; an empty (always) list for argument handling in formatter$doit
formatter_options_ofs = 40		; bool as to whether to add space between items
formatter_size = 48

if used formatter$new | defined include_everything
	; single argument in edi: bool as to whether to add space between items
falign
formatter$new:
	prolog	formatter$new
	push	rdi
	call	list$new
	push	rax
	call	list$new
	push	rax
	call	list$new
	push	rax
	mov	edi, formatter_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	[rax+formatter_items_ofs], rsi
	mov	[rax+formatter_rargs_ofs], rdx
	mov	[rax+formatter_xargs_ofs], rcx
	mov	[rax+formatter_options_ofs], edi
	epilog

end if

formatitem_type_ofs = 0
formatitem_width_ofs = 8
formatitem_flags_ofs = 16
formatitem_prec_ofs = 24
formatitem_value_ofs = 32

formatitem_size = 40

; formatitem_type_ofs will be one of:
formatitem_static = 0
formatitem_string = 1
formatitem_boolean = 2
formatitem_integer = 3
formatitem_unsigned = 4
formatitem_double = 5
formatitem_buffer = 6
formatitem_bufferhex = 7
formatitem_date = 8
formatitem_time = 9
formatitem_datetime = 10
formatitem_duration = 11
formatitem_rfc3164datetime = 12
formatitem_rfc5322datetime = 13
formatitem_quotedstring = 14
formatitem_yyyymmdd = 15


if used formatter$destroy | defined include_everything
	; single argument in rdi: our formatter object
falign
formatter$destroy:
	prolog	formatter$destroy
	push	rdi
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, .itemdeath
	call	list$clear
	mov	rsi, [rsp]
	mov	rdi, [rsi+formatter_items_ofs]
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsi+formatter_rargs_ofs]
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsi+formatter_xargs_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	epilog
falign
.itemdeath:
	; this is called for each item in the list rdi == our formatitem
	cmp	qword [rdi+formatitem_value_ofs], 0
	jne	.itemdeath_withvalue
	call	heap$free
	ret
calign
.itemdeath_withvalue:
	push	rdi
	mov	rdi, [rdi+formatitem_value_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	ret

end if

if used formatter$add_static | defined include_everything
	; two arguments: rdi == formatter object, rsi == static string (we make a copy of it)
falign
formatter$add_static:
	prolog	formatter$add_static
	push	rdi
	mov	rdi, rsi
	call	string$copy
	push	rax
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_static
	mov	[rax+formatitem_value_ofs], rsi
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_string | defined include_everything
	; two arguments: rdi == our formatter object, esi == 0 == dynamic width, else fixed width
falign
formatter$add_string:
	prolog	formatter$add_string
	push	rdi rsi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_string
	mov	dword [rax+formatitem_width_ofs], esi
	add	dword [rdi+formatter_regargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_boolean | defined include_everything
	; two arguments: rdi == our formatter object, esi == 0 == dynamic width, else fixed width
falign
formatter$add_boolean:
	prolog	formatter$add_boolean
	push	rdi rsi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_boolean
	mov	dword [rax+formatitem_width_ofs], esi
	add	dword [rdi+formatter_regargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_integer | defined include_everything
	; three arguments: rdi == our formatter object, esi == 0 == decimal, 1 == decimal with thousands separator, 2 == hex output, 3 == hex output with 0x preface, edx == 0 == dynamic width, else fixed width
falign
formatter$add_integer:
	prolog	formatter$add_integer
	push	rdi rsi rdx
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdx rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_integer
	mov	dword [rax+formatitem_width_ofs], edx
	mov	dword [rax+formatitem_flags_ofs], esi
	add	dword [rdi+formatter_regargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_unsigned | defined include_everything
	; three arguments: rdi == our formatter object, esi == 0 == decimal, 1 == decimal with thousands separator, 2 == hex output, 3 == hex output with 0x preface, edx == 0 == dynamic width, else fixed width
falign
formatter$add_unsigned:
	prolog	formatter$add_unsigned
	push	rdi rsi rdx
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdx rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_unsigned
	mov	dword [rax+formatitem_width_ofs], edx
	mov	dword [rax+formatitem_flags_ofs], esi
	add	dword [rdi+formatter_regargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_double | defined include_everything
	; five arguments: rdi == our formatter object, esi == mode, edx == decimal digits precision, ecx == 0 == dynamic width, else fixed width, r8d == bool for thousands separator
	; mode should be one of: double_string_normal, double_string_fixed, double_string_precision, double_string_exponential (see string$from_double for further details)
falign
formatter$add_double:
	prolog	formatter$add_double
	shl	r8d, 8
	or	esi, r8d
	push	rdi rsi rdx rcx
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_double
	mov	dword [rax+formatitem_width_ofs], ecx
	mov	dword [rax+formatitem_flags_ofs], esi
	mov	dword [rax+formatitem_prec_ofs], edx
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_buffer | defined include_everything
	; single argument: rdi == our formatter object
	; this assumes the argument is a buffer that contains UTF8, so when formatter$doit comes along, it will convert the buffer from UTF8
falign
formatter$add_buffer:
	prolog	formatter$add_buffer
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_buffer
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_bufferhex | defined include_everything
	; single argument: rdi == our formatter object
	; this turns whatever is in the buffer into a string from bin to hex
falign
formatter$add_bufferhex:
	prolog	formatter$add_bufferhex
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_bufferhex
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_date | defined include_everything
	; single argument: rdi == our formatter object
	; this turns an xmm argument, which is a truncated JD timestamp, into ISO8601/RFC3339 "full-date" string, which is YYYY-MM-DD
	; see date.inc for truncated jd times, durations, etc.
falign
formatter$add_date:
	prolog	formatter$add_date
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_date
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_time | defined include_everything
	; single argument: rdi == our formatter object
	; this turns an xmm argument, which is a truncated JD timestamp, into ISO8601/RFC3339 "full-time" string, which is HH:MM:SS.ssssssZ
	; see date.inc for truncated jd times, durations, etc.
falign
formatter$add_time:
	prolog	formatter$add_time
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_time
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_datetime | defined include_everything
	; two arguments: rdi == our formatter object, esi == bool as to whether to enclose it in [] brackets
	; this turns an xmm argument, which is a truncated JD timestamp, into ISO8601/RFC3339 "date-time" string, which is full-date "T" full-time
	; see date.inc for truncated jd times, durations, etc.
falign
formatter$add_datetime:
	prolog	formatter$add_datetime
	push	rdi rsi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_datetime
	mov	dword [rax+formatitem_flags_ofs], esi
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_duration | defined include_everything
	; two arguments: rdi == our formatter object, esi == minimum resolution, edx == fractional digits (or 0 for none)
	; ms resolution == fractional digits ignored (0.000s is what you get on the end)
	; duration is in DAYS (and is an xmm arg), min res is: 5 == weeks, 4 == days, 3 == hours, 2 == mins, 1 == secs, 0 == ms
	; see date.inc for truncated jd times, durations, etc.
falign
formatter$add_duration:
	prolog	formatter$add_duration
	push	rdi rsi rdx
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdx rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_duration
	mov	dword [rax+formatitem_prec_ofs], esi
	mov	dword [rax+formatitem_flags_ofs], edx
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_rfc3164datetime | defined include_everything
	; single argument: rdi == our formatter object
	; this turns an xmm argument, which is a truncated JD timestamp, into RFC3164 "TIMESTAMP" string, which is Mmm dD HH:MM:SS
falign
formatter$add_rfc3164datetime:
	prolog	formatter$add_rfc3164datetime
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_rfc3164datetime
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_rfc5322datetime | defined include_everything
	; single argument: rdi == our formatter object
	; this turns an xmm argument, which is a truncated JD timestamp, into RFC5322 "IMF-fixdate" string, which is Sun, 06 Nov 1994 09:49:37 GMT
falign
formatter$add_rfc5322datetime:
	prolog	formatter$add_rfc5322datetime
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_rfc5322datetime
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_quotedstring | defined include_everything
	; two arguments: rdi == our formatter object, esi == 0 == dynamic width, else fixed width
falign
formatter$add_quotedstring:
	prolog	formatter$add_quotedstring
	push	rdi rsi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rsi rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_quotedstring
	mov	dword [rax+formatitem_width_ofs], esi
	add	dword [rdi+formatter_regargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if

if used formatter$add_yyyymmdd | defined include_everything
	; single argument: rdi == our formatter object
	; this turns an xmm argument, which is a truncated JD timestamp, into YYYYMMDD
	; see date.inc for truncated jd times, durations, etc.
falign
formatter$add_yyyymmdd:
	prolog	formatter$add_yyyymmdd
	push	rdi
	mov	edi, formatitem_size
	call	heap$alloc_clear
	pop	rdi
	mov	dword [rax+formatitem_type_ofs], formatitem_yyyymmdd
	add	dword [rdi+formatter_xmmargs_ofs], 1
	mov	rdi, [rdi+formatter_items_ofs]
	mov	rsi, rax
	call	list$push_back
	epilog

end if


if used formatter$doit | defined include_everything
	; variable # of arguments depending on how it was setup of course, but rdi == formatter object at the very least
	; returns a new string in rax of the result
falign
formatter$doit:
	prolog	formatter$doit
	; we "precompile" our arguments into two lists such that traversing our items list becomes a simple pop_front operation
	; this does a fair bit of work, but makes for the final compilation stage being nice and easy
	push	r13 r14 r15
	mov	r13, rdi
	mov	eax, [rdi+formatter_regargs_ofs]
	jmp	qword [rax*8+.regdispatch]
dalign
.regdispatch:
	dq	.reg0, .reg1, .reg2, .reg3, .reg4, .reg5, .reg6, .reg7
dalign
.xmmdispatch:
	dq	.ready, .xmm1, .xmm2, .xmm3, .xmm4, .xmm5, .xmm6, .xmm7, .xmm8, .xmm9, .xmm10, .xmm11, .xmm12, .xmm13, .xmm14, .xmm15
calign
.reg0:
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg1:
	; our argument is sitting in rsi that we need to add to regargs
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg2:
	; rsi, rdx are the two arguments we need to deal with
	push	rdx
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg3:
	; rsi, rdx, rcx are the three arguments we need to deal with
	push	rcx rdx
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg4:
	; rsi, rdx, rcx, r8
	push	r8 rcx rdx
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg5:
	; rsi, rdx, rcx, r8, r9
	push	r9 r8 rcx rdx
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg6:
	; rsi, rdx, rcx, r8, r9, r10
	push	r10 r9 r8 rcx rdx
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]
calign
.reg7:
	; rsi, rdx, rcx, r8, r9, r10, r11
	push	r11 r10 r9 r8 rcx rdx
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	pop	rsi
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$push_back
	mov	eax, [r13+formatter_xmmargs_ofs]
	jmp	qword [rax*8+.xmmdispatch]


	; some notes here: we know that heap$alloc and list$push_back do not mash xmm regs, so we don't have to preserve them all beforehand
calign
.xmm1:
	; xmm0
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm2:
	; xmm0, xmm1
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm3:
	; xmm0, xmm1, xmm2
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm4:
	; xmm0, xmm1, xmm2, xmm3
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm5:
	; xmm0, xmm1, xmm2, xmm3, xmm4
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm6:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm7:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm8:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm9:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm10:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm11:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm10
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm12:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm10
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm11
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm13:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm10
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm11
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm12
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm14:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm10
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm11
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm12
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm13
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm15:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm10
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm11
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm12
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm13
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm14
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	jmp	.ready
calign
.xmm16:
	; xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
	movq	rsi, xmm0
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm1
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm2
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm3
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm4
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm5
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm6
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm7
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm8
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm9
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm10
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm11
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm12
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm13
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm14
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	movq	rsi, xmm15
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$push_back
	; fallthrough to ready
calign
.ready:
	; rargs and xargs are both populated and we don't need to worry about registers/etc
	; so our formatter object is sitting in r13, r14 and r15 are unpopulated
	; we'll need one as a buffer
	call	buffer$new
	mov	r14, rax
	mov	rdi, [r13+formatter_items_ofs]
	mov	rsi, .peritem
	call	list$foreach
	; now turn the buffer into a string for our return
	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, [r14+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	mov	rdi, r14
	mov	r14, rax
	call	buffer$destroy
	mov	rax, r14
	pop	r15 r14 r13
	epilog
falign
.peritem:
	; called with a single argument in rdi that is our formatitem, r13 == our formatter, r14 == destination buffer
	mov	r15, rdi
	cmp	qword [r14+buffer_length_ofs], 0
	je	.firstitem
	cmp	dword [r13+formatter_options_ofs], 0
	je	.firstitem
	; otehrwise, buffer is non-empty, and we are to add a space between items
	mov	rdi, r14
	mov	esi, ' '
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
	mov	eax, [r15+formatitem_type_ofs]
	jmp	qword [rax*8+.peritemdispatch]
calign
.firstitem:
	mov	eax, [r15+formatitem_type_ofs]
	jmp	qword [rax*8+.peritemdispatch]
dalign
.peritemdispatch:
	dq	.item_static, .item_string, .item_boolean, .item_integer, .item_unsigned, .item_double, .item_buffer, .item_bufferhex, .item_date, .item_time, .item_datetime, .item_duration, .item_rfc3164datetime, .item_rfc5322datetime, .item_quotedstring, .item_yyyymmdd
calign
.item_static:
	; we can't use buffer$append_string, because that turns the string into utf8 first
	mov	rdi, r14
	mov	rsi, [r15+formatitem_value_ofs]
	mov	rdx, [rsi]			; its length in _characters_
	add	rsi, 8				; actual start of the buffer
if string_bits = 32
	shl	rdx, 2				; length in bytes
else
	shl	rdx, 1				; length in bytes
end if
	call	buffer$append
	ret
calign
.item_string:
	; pop our string argument from the rargs, check width
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	; if width == 0, just add it
	cmp	dword [r15+formatitem_width_ofs], 0
	je	.item_string_nopad
	; otherwise, we need to lpad our string, noting here we do _not_ do truncation
calign
.item_string_pad:
	mov	rdi, rax
	mov	esi, [r15+formatitem_width_ofs]
	mov	edx, ' '
	call	string$lpad
	push	rax
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free
	ret
calign
.item_string_nopad:
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	ret
calign
.item_boolean:
	; pop our bool argument from the rargs, check width
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	mov	rcx, rax
	mov	rax, .truestr
	mov	rdx, .falsestr
	test	rcx, rcx
	cmovz	rax, rdx
	; rax now has either true or false string, if width == 0, just add it
	cmp	dword [r15+formatitem_width_ofs], 0
	je	.item_string_nopad
	jmp	.item_string_pad
cleartext .truestr, 'true'
cleartext .falsestr, 'false'
cleartext .hexpreface, '0x'
cleartext .thousandseparator, ','
calign
.item_integer:
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	mov	rdi, rax
	mov	esi, 10
	mov	edx, 16
	cmp	dword [r15+formatitem_flags_ofs], 1
	cmova	esi, edx
	call	string$from_int
calign
.numeric_string_ready:
	push	rax
	cmp	dword [r15+formatitem_flags_ofs], 3
	jne	.numeric_string_nopreface
	; otherwise, add a 0x to the beginning of our string
	mov	rdi, .hexpreface
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
calign
.numeric_string_nopreface:
	cmp	dword [r15+formatitem_flags_ofs], 1
	jne	.numeric_string_checkwidth
	; we need to add thousands separators to our number
	mov	rdi, rax
	call	string$reverse
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	; so now, our string is reversed, e.g.: -12345 == 54321-
	xor	ecx, ecx
	push	rcx			; our starting offset
calign
.numeric_string_addthou:
	add	dword [rsp], 3
	mov	rax, [rsp+8]		; our string
	mov	ecx, [rsp]
	; deal with the special case for when our only remaining character is the sign
	mov	edx, [rax]
	sub	edx, ecx
	cmp	edx, 1
	jne	.numeric_string_notone
	; check to see if the remaining character is '-', if so, bailout
	mov	edx, [rax]
	sub	edx, 1
if string_bits = 32
	cmp	dword [rax+rdx*4+8], '-'
else
	cmp	word [rax+rdx*2+8], '-'
end if
	je	.numeric_string_thoudone
calign
.numeric_string_notone:
	cmp	ecx, [rax]
	jae	.numeric_string_thoudone
	mov	rdi, rax
	xor	esi, esi		; start offset
	mov	rdx, rcx		; end offset
	call	string$substring
	push	rax
	mov	rdi, rax
	mov	rsi, .thousandseparator
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	; so now we have up to our thou separator and a comma joined together, now we need to rejoin it with the rest of the string at [rsp+16]
	mov	rdi, [rsp+16]		; our original string
	mov	rsi, [rsp+8]		; our comma placement
	mov	rdx, -1			; length to the end
	call	string$substr
	push	rax
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp+24]		; our original string
	mov	[rsp+24], rax
	call	heap$free
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	add	dword [rsp], 1		; +1 char for our newly added comma
	jmp	.numeric_string_addthou
calign
.numeric_string_thoudone:
	pop	rcx			; we don't need our counter anymore
	mov	rdi, [rsp]
	call	string$reverse
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	; so now our string is back in the right order, width is next
calign
.numeric_string_checkwidth:
	cmp	dword [r15+formatitem_width_ofs], 0
	je	.numeric_string_nopad
	mov	rdi, rax
	mov	esi, [r15+formatitem_width_ofs]
	mov	edx, ' '
	call	string$lpad
	push	rax
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	ret
calign
.numeric_string_nopad:
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free		; get rid of our string
	ret
calign
.item_unsigned:
	; same as integer only without the sign
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	mov	rdi, rax
	mov	esi, 10
	mov	edx, 16
	cmp	dword [r15+formatitem_flags_ofs], 1
	cmova	esi, edx
	call	string$from_unsigned
	jmp	.numeric_string_ready
calign
.item_double:
	; so, [r15+formatitem_width_ofs] == 0 == dynamic width, 1 == fixed width
	; [r15+formatitem_flags_ofs] == low byte is mode, next byte is bool for thousands separator or not
	; [r15+formatitem_prec_ofs] == decimal digits precision
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	mov	edi, [r15+formatitem_flags_ofs]
	mov	esi, [r15+formatitem_prec_ofs]
	and	edi, 0xff
	call	string$from_double
	push	rax
	mov	ecx, [r15+formatitem_flags_ofs]
	test	ecx, 0xff00
	jz	.numeric_string_checkwidth
	; otherwise, we need to add thousands separators to this one, exactly like the numeric string version, only we need to
	; start at the decimal (if any) +1
	mov	rdi, rax
	call	string$reverse
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	; so now, our string is reversed, e.g.: -12345.01 == 10.54321-
	xor	ecx, ecx
	push	rcx			; our starting offset
	mov	rdi, [rsp+8]
	mov	esi, '.'
	call	string$indexof_charcode
	xor	ecx, ecx
	mov	rdx, rax
	add	rdx, 1
	cmp	rax, -1
	cmovne	ecx, edx
	mov	[rsp], ecx
	jmp	.numeric_string_addthou
calign
.item_buffer:
	; this assumes the buffer contents are UTF8, and converts it accordingly
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	mov	rdi, [rax+buffer_itself_ofs]
	mov	rsi, [rax+buffer_length_ofs]
	call	string$from_utf8
	push	rax
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free		; get rid of our string
	ret
calign
.item_bufferhex:
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	mov	rdi, [rax+buffer_itself_ofs]
	mov	rsi, [rax+buffer_length_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free		; get rid of our string
	ret

macro format_addstring {
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free		; get rid of our string
}

macro format_addchar {
	; char is assumed to already be sitting in esi
	mov	rdi, r14
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
}

calign
.item_date:
	; YYYY-MM-DD
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	sub	rsp, 16
	mov	rdi, rsp
	call	timestamp$to_datetime
	; so now our struct at [rsp] is valid, do our string
	movzx	edi, word [rsp+_datetime_yearofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	format_addstring
	mov	esi, '-'
	format_addchar
	movzx	edi, word [rsp+_datetime_monthofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, '-'
	format_addchar
	movzx	edi, word [rsp+_datetime_dayofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	; done
	add	rsp, 16
	ret
calign
.item_time:
	; HH:MM:SS.sssZ
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	sub	rsp, 16
	mov	rdi, rsp
	call	timestamp$to_datetime
	; so now our struct at [rsp] is valid, do our string
	movzx	edi, word [rsp+_datetime_hourofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	movzx	edi, word [rsp+_datetime_minofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	; now, our usecs is expressed as actual microseconds, not TIME-SECFRAC, so a usecs value on our side of 3 needs to be spewed out as 0.000003
	; so the simplest way to do that (albeit not the most efficient) is to convert secs and usecs both to doubles, and then use double format to do it
	; but ONLY if usecs is nonzero
	cmp	dword [rsp+_datetime_usecofs], 0
	jne	.item_time_fraction
	; otherwise, usecs is zero, so just output the sec and a trailing Z and be done with it
	movzx	edi, word [rsp+_datetime_secofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, 'Z'
	format_addchar
	; done
	add	rsp, 16
	ret
dalign
.onem	dq	1000000.0f
calign
.item_time_fraction:
	; because we are using double conversion here, we have to add a leading zero manually if the secs is not big enough
	movzx	ecx, word [rsp+_datetime_secofs]
	cmp	ecx, 10
	jae	.item_time_fraction_secsokay
	mov	esi, '0'
	format_addchar
	movzx	ecx, word [rsp+_datetime_secofs]
calign
.item_time_fraction_secsokay:
	mov	eax, [rsp+_datetime_usecofs]
	cvtsi2sd xmm0, ecx
	cvtsi2sd xmm1, eax
	divsd	xmm1, [.onem]
	addsd	xmm0, xmm1
	mov	edi, double_string_normal
	mov	esi, 6
	call	string$from_double
	push	rax
	format_addstring
	mov	esi, 'Z'
	format_addchar
	; done
	add	rsp, 16
	ret
calign
.item_datetime:
	; if formatter_datetime_fractional, then YYYY-MM-DDTHH:MM:SS.sssZ, else YYYY-MM-DDTHH:MM:SSZ
	cmp	dword [r15+formatitem_flags_ofs], 0
	je	.item_datetime_nobracket1
	mov	rdi, r14
	mov	esi, '['
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
calign
.item_datetime_nobracket1:
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	sub	rsp, 16
	mov	rdi, rsp
	call	timestamp$to_datetime
	; so now our struct at [rsp] is valid, do our string
	movzx	edi, word [rsp+_datetime_yearofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	format_addstring
	mov	esi, '-'
	format_addchar
	movzx	edi, word [rsp+_datetime_monthofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, '-'
	format_addchar
	movzx	edi, word [rsp+_datetime_dayofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, 'T'
	format_addchar
	movzx	edi, word [rsp+_datetime_hourofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	movzx	edi, word [rsp+_datetime_minofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar

if formatter_datetime_fractional
	mov	edi, [rsp+_datetime_usecofs]
	movzx	esi, word [rsp+_datetime_secofs]
	cmp	esi, 10
	jb	.item_datetime_lpad
	cvtsi2sd xmm1, edi
	cvtsi2sd xmm0, esi
	mulsd	xmm1, [.millions]
	addsd	xmm0, xmm1
	mov	edi, double_string_fixed
	mov	esi, 6
	call	string$from_double
	push	rax
	format_addstring
else
	movzx	edi, word [rsp+_datetime_secofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
end if
	mov	esi, 'Z'
	format_addchar
	cmp	dword [r15+formatitem_flags_ofs], 0
	je	.item_datetime_nobracket2
	mov	rdi, r14
	mov	esi, ']'
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
	; done
	add	rsp, 16
	ret
calign
.item_datetime_lpad:
	cvtsi2sd xmm1, edi
	cvtsi2sd xmm0, esi
	mulsd	xmm1, [.millions]
	addsd	xmm0, xmm1
	mov	edi, double_string_fixed
	mov	esi, 6
	call	string$from_double
	push	rax
	mov	rdi, rax
	mov	esi, 9
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, 'Z'
	format_addchar
	cmp	dword [r15+formatitem_flags_ofs], 0
	je	.item_datetime_nobracket2
	mov	rdi, r14
	mov	esi, ']'
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
	; done
	add	rsp, 16
	ret

calign
.item_datetime_nobracket2:
	; done
	add	rsp, 16
	ret
dalign
.millions	dq	0.000001f
calign
.item_duration:
	; depending on prec, outputs string duration, see format$duration in date.inc for more details
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	mov	edi, [r15+formatitem_prec_ofs]
	mov	esi, [r15+formatitem_flags_ofs]
	call	format$duration
	push	rax
	format_addstring
	ret
dalign
.abbrmonths:
if string_bits = 32
	dd	'J', 'a', 'n', ' '
	dd	'F', 'e', 'b', ' '
	dd	'M', 'a', 'r', ' '
	dd	'A', 'p', 'r', ' '
	dd	'M', 'a', 'y', ' '
	dd	'J', 'u', 'n', ' '
	dd	'J', 'u', 'l', ' '
	dd	'A', 'u', 'g', ' '
	dd	'S', 'e', 'p', ' '
	dd	'O', 'c', 't', ' '
	dd	'N', 'o', 'v', ' '
	dd	'D', 'e', 'c', ' '
else
	dw	'J', 'a', 'n', ' '
	dw	'F', 'e', 'b', ' '
	dw	'M', 'a', 'r', ' '
	dw	'A', 'p', 'r', ' '
	dw	'M', 'a', 'y', ' '
	dw	'J', 'u', 'n', ' '
	dw	'J', 'u', 'l', ' '
	dw	'A', 'u', 'g', ' '
	dw	'S', 'e', 'p', ' '
	dw	'O', 'c', 't', ' '
	dw	'N', 'o', 'v', ' '
	dw	'D', 'e', 'c', ' '
end if
calign
.item_rfc3164datetime:
	; "TIMESTAMP" says Mmm dD HH:MM:SS
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	sub	rsp, 16
	mov	rdi, rsp
	call	timestamp$to_datetime
	; Mmm is first up

	movzx	esi, word [rsp+_datetime_monthofs]
	sub	esi, 1
	mov	rdi, r14
if string_bits = 32
	mov	edx, 16
	shl	esi, 4
else
	mov	edx, 8
	shl	esi, 3
end if
	add	rsi, .abbrmonths
	call	buffer$append

	; next up is space-padded day
	movzx	edi, word [rsp+_datetime_dayofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, ' '
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	; we need a space
	mov	esi, ' '
	format_addchar
	; and our time
	movzx	edi, word [rsp+_datetime_hourofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	movzx	edi, word [rsp+_datetime_minofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	movzx	edi, word [rsp+_datetime_secofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	; done
	add	rsp, 16
	ret
dalign
.abbrdows:
if string_bits = 32
	; julian date to week:
	dd	'S', 'u', 'n', ','
	dd	'M', 'o', 'n', ','
	dd	'T', 'u', 'e', ','
	dd	'W', 'e', 'd', ','
	dd	'T', 'h', 'u', ','
	dd	'F', 'r', 'i', ','
	dd	'S', 'a', 't', ','
dalign
.gmt:
	dd	' ', 'G', 'M', 'T'
else
	; julian date to week:
	dw	'S', 'u', 'n', ','
	dw	'M', 'o', 'n', ','
	dw	'T', 'u', 'e', ','
	dw	'W', 'e', 'd', ','
	dw	'T', 'h', 'u', ','
	dw	'F', 'r', 'i', ','
	dw	'S', 'a', 't', ','
dalign
.gmt:
	dw	' ', 'G', 'M', 'T'
end if
calign
.item_rfc5322datetime:
	; "IMF-fixdate" says: Sun, 06 Nov 1994 08:49:37 GMT
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	; to get our DOW, we need that floored, converted to an integer, and % 7
	; TODO: verify this is right, haha
	push	rax
	movq	xmm0, rax
	call	floor
	cvtsd2si	rax, xmm0
	mov	ecx, 7
	xor	edx, edx
	div	ecx
	; remainder sitting in edx
	mov	esi, edx
	mov	rdi, r14
if string_bits = 32
	mov	edx, 16
	shl	esi, 4
else
	mov	edx, 8
	shl	esi, 3
end if
	add	rsi, .abbrdows
	call	buffer$append
	pop	rax
	movq	xmm0, rax
	sub	rsp, 16
	mov	rdi, rsp
	call	timestamp$to_datetime
	mov	esi, ' '
	format_addchar
	; next up is zero-padded day
	movzx	edi, word [rsp+_datetime_dayofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring	; pops it off the stack
	; we need a space
	mov	esi, ' '
	format_addchar
	; Mmm is first up
	movzx	esi, word [rsp+_datetime_monthofs]
	sub	esi, 1
	mov	rdi, r14
if string_bits = 32
	mov	edx, 16
	shl	esi, 4
else
	mov	edx, 8
	shl	esi, 3
end if
	add	rsi, .abbrmonths
	call	buffer$append
	; next up, full year
	movzx	edi, word [rsp+_datetime_yearofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	format_addstring
	; we need another space
	mov	esi, ' '
	format_addchar
	; and our time
	movzx	edi, word [rsp+_datetime_hourofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	movzx	edi, word [rsp+_datetime_minofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	esi, ':'
	format_addchar
	movzx	edi, word [rsp+_datetime_secofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	mov	rdi, r14
	mov	rsi, .gmt
if string_bits = 32
	mov	edx, 16
else	
	mov	edx, 8
end if
	call	buffer$append
	; done
	add	rsp, 16
	ret
calign
.item_quotedstring:
	; pop our string argument from the rargs, check width
	mov	rdi, r14
	mov	esi, '"'
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
	mov	rdi, [r13+formatter_rargs_ofs]
	call	list$pop_front
	; if width == 0, just add it
	cmp	dword [r15+formatitem_width_ofs], 0
	je	.item_quotedstring_nopad
	; otherwise, we need to lpad our string, noting here we do _not_ do truncation
calign
.item_quotedstring_pad:
	mov	rdi, rax
	mov	esi, [r15+formatitem_width_ofs]
	mov	edx, ' '
	call	string$lpad
	push	rax
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	pop	rdi
	call	heap$free
	mov	rdi, r14
	mov	esi, '"'
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
	ret
calign
.item_quotedstring_nopad:
	mov	rdi, r14
	mov	rsi, rax
	mov	rdx, [rax]
	add	rsi, 8
if string_bits = 32
	shl	rdx, 2
else
	shl	rdx, 1
end if
	call	buffer$append
	mov	rdi, r14
	mov	esi, '"'
if string_bits = 32
	call	buffer$append_dword
else
	call	buffer$append_word
end if
	ret
calign
.item_yyyymmdd:
	; YYYYMMDD
	mov	rdi, [r13+formatter_xargs_ofs]
	call	list$pop_front
	movq	xmm0, rax
	sub	rsp, 16
	mov	rdi, rsp
	call	timestamp$to_datetime
	; so now our struct at [rsp] is valid, do our string
	movzx	edi, word [rsp+_datetime_yearofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	format_addstring
	movzx	edi, word [rsp+_datetime_monthofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	movzx	edi, word [rsp+_datetime_dayofs]
	mov	esi, 10
	call	string$from_unsigned
	; this one needs lpadded
	push	rax
	mov	rdi, rax
	mov	esi, 2
	mov	edx, '0'
	call	string$lpad
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	format_addstring
	; done
	add	rsp, 16
	ret
	

end if
