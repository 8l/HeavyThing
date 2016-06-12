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
	; tui_matrix.inc: c'mon, what self-respecting text user interface library 
	; would it be without this?
	;
	; NOTE: hahah, with nearly all of my tests in various terminal software, this brings them
	; ALL to their knees (read: 100% cpu by the displaying terminal).
	;
	; Some of it has to do with the unicode/kana characters, but still, you'd think a TEXT
	; renderer would have a far more "high speed" symbol rate. The defaults that I have set
	; in here do not cause complete havoc, which means that this component IS useful as-is,
	; and does provide the desired effect. If you really want to see your terminal totally
	; FREAK OUT, set the max stream parameter here to 1000 or so, make your terminal window
	; a decent size, and prepare to have to forcibly terminate it. HAHAH
	;
	; Perhaps I should rename this to CPU Killer instead of tui_matrix, haha.
	;
	; as an aside, doing system call/library tracing with Terminal.app here suggests that
	; it, like other terminal programs, seems to recalculate the width of an entire line
	; when just one character in that line is updated. I suppose this makes sense for non
	; fixed-width terminals, but for fixed-width, you'd sure think they'd optimize it.
	; then again, I have not really encountered a situation until I built this text user
	; interface library whereby their methods were rendered totally insufficient. I'd love
	; to hear from the Apple Terminal.app developers on their opinion on this. Would be
	; fun to crank these symbol rates right up, ha!
	;

	; hahah, this is more of a joke than anything, and I suppose as a demonstration of
	; how flexible this text interface framework is, is an excellent example.
	; otherwise, until terminal emulators decide to handle the unicode/drawing better
	; is utterly useless, HA!



	; settings for how this all comes together:
	
	; our stream count, bahahaha, the windows original has this set to 1000, messy if you do that
	; per the above commentary
tui_matrix_maxstream = 100
tui_matrix_backtrace = 30	; original had 40 here
tui_matrix_leading = 10
tui_matrix_spacepad = 30

tui_matrix_r = 150
tui_matrix_g = 255
tui_matrix_b = 100

	; the wikipedia says half-width kana, which is 63 characters starting at 0xff61,
	; and latin alphanumerics.
	; if we actually do that, WHOAAOAOAO, hahah, CPU killer indeed (not THIS process, your terminal's)
	; so, if this setting is enabled, we go ahead and do the "wikipedia reference" version
	; and send half-width kana AND latin alphanumerics
	; if it is disabled, then we only send half-width kana (which is MUCH nicer to terminals)
	; also note, cpukiller = 1 doesn't display correctly for Terminal.app, maybe I screwed up the
	; math for the latin alphanumeric versus halfwidth kana, no idea, doesn't really matter anyway
	; this thing even with cpukiller disabled absolutely hammers all my terminals
tui_matrix_cpukiller = 0



tui_matrix_incr = tui_matrix_r / 6
tui_matrix_incg = tui_matrix_g / 6
tui_matrix_incb = tui_matrix_b / 6

tui_matrix_incr_s = tui_matrix_r / 3 / 6
tui_matrix_incg_s = tui_matrix_g / 3 / 6
tui_matrix_incb_s = tui_matrix_b / 3 / 6


if used tui_matrix$vtable | defined include_everything

dalign
tui_matrix$vtable:
        dq      tui_matrix$cleanup, tui_matrix$clone, tui_matrix$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_matrix$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

tui_matrix_intarr_size = tui_matrix_maxstream shl 2

tui_matrix_startx_ofs = tui_object_size + 0
tui_matrix_starty_ofs = tui_object_size + tui_matrix_intarr_size
tui_matrix_lastupdatey_ofs = tui_matrix_starty_ofs + tui_matrix_intarr_size
tui_matrix_streamspeed_ofs = tui_matrix_lastupdatey_ofs + tui_matrix_intarr_size
tui_matrix_origspeed_ofs = tui_matrix_streamspeed_ofs + tui_matrix_intarr_size
tui_matrix_streamstatus_ofs = tui_matrix_origspeed_ofs + tui_matrix_intarr_size
tui_matrix_streamcount_ofs = tui_matrix_streamstatus_ofs + tui_matrix_intarr_size
tui_matrix_timer_ofs = tui_matrix_streamcount_ofs + 8

tui_matrix_size = tui_matrix_timer_ofs + 4


if used tui_matrix$new | defined include_everything

	; note: because this is mainly just a bell/whistle useless component, I only bothered with
	; the default 100% width 100% height version. if you want it smaller/fixed size/different
	; there are two ways to do that:
	;	1) append this to a constrained parent, no real extra code required in here
	;	2) add your own $new_ii/$new_id/$new_di/$new_dd/etc to here
	;

	; no arguments, returns a heap$alloc'd tui_matrix object all setup and ready to go
	; NOTE: we _do_ fire our timer off here and get things underway, but since most will
	; be immediately followed with an appendchild, this really isn't a problem
	; cleanup takes care of killing our timer
	;
falign
tui_matrix$new:
	prolog	tui_matrix$new
	mov	edi, tui_matrix_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	mov	rsi, [rsp]	; timer_new wants object in rsi, time in edi
	mov	qword [rsi], tui_matrix$vtable
	mov	edi, 50		; 50ms == 20fps
	call	epoll$timer_new
	mov	rdi, [rsp]
	mov	[rdi+tui_matrix_timer_ofs], rax		; store the timer object so we can blast it later
	call	tui_matrix$initial_fill
	pop	rax
	epilog

end if



if used tui_matrix$cleanup | defined include_everything

; so, our timer is NEVER going to return a stop notice to the epoll layer, which means it will ALWAYS be valid
; throughout the lifetime of our object.
; what this means is that the only time our cleanup method is going to get called
; is when we, say, get removed from our parent... e.g. we will never be cleaned up from inside the timer handler
; itself inside the epoll object, so it is therefore SAFE to call epoll$timer_clear with our timer object
; without causing a circular nasty crash scenario (if our vcleanup were called from the timer handler itself,
; it too calls timer_clear, and heap$frees it, so this double could would be bad)... but we can be assured this
; doesn't happen simply by virtue of our timer not returning a "hey kill us please" return status.

falign
tui_matrix$cleanup:
	prolog	tui_matrix$cleanup
	; since we don't have any dynamically allocated extra objects, all we have to make sure
	; is that our timer object is already destroyed
	mov	rdi, [rdi+tui_matrix_timer_ofs]
	call	epoll$timer_clear
	; nothign else need be done since we didn't dynamically allocate anything extra
	epilog

end if

if used tui_matrix$initial_fill | defined include_everything

	; single argument in rdi: our tui_matrix object
falign
tui_matrix$initial_fill:
	prolog	tui_matrix$initial_fill
	mov	dword [rdi+tui_matrix_streamcount_ofs], 0
	mov	ecx, tui_matrix_maxstream
	xor	eax, eax
	lea	rdx, [rdi+tui_matrix_streamstatus_ofs]
calign
.clearloop:
	mov	dword [rdx], eax
	add	rdx, 4
	sub	ecx, 1
	jnz	.clearloop
	; do an initial fill of our entire space similar to what tui_background$fill does
	mov	eax, dword [rdi+tui_width_ofs]
	mov	ecx, dword [rdi+tui_height_ofs]
	test	eax, eax
	jz	.allgood
	test	ecx, ecx
	jz	.allgood
	mul	ecx
	mov	rdx, rdi
	shl	rax, 2
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rax
	mov	rdi, [rdx+tui_text_ofs]
	test	rdi, rdi
	jz	.bailout
	mov	esi, ' '
	mov	rdx, rax
	call	memset32
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_attr_ofs]
	ansi_colors esi, 'green', 'black'
	mov	rdx, [rsp+8]
	call	memset32
	add	rsp, 16
	epilog
calign
.bailout:
	add	rsp, 16
	epilog
calign
.allgood:
	epilog

end if



if used tui_matrix$clone | defined include_everything

	; single argument: rdi == source tui_matrix to clone/make a copy of
	; returns new tui_matrix copy in rax, NOTE: we don't ACTUALLY clone
	; we just return a brand new one, cloning since there is no useful
	; state information would be silly
falign
tui_matrix$clone:
	prolog	tui_matrix$clone
	call	tui_matrix$new
	epilog

end if



if used tui_matrix$draw | defined include_everything

	; single argument in rdi: our tui_matrix object
falign
tui_matrix$draw:
	prolog	tui_matrix$draw
	push	rdi
	call	tui_matrix$initial_fill
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	epilog

end if


if used tui_matrix$createdestroy | defined include_everything

	; single argument in rdi: our tui_matrix object
falign
tui_matrix$createdestroy:
	prolog	tui_matrix$createdestroy
	cmp	dword [rdi+tui_width_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_matrix_streamcount_ofs], tui_matrix_maxstream
	jae	.dostops
	lea	rdx, [rdi+tui_matrix_streamstatus_ofs]
	mov	ecx, tui_matrix_maxstream
	xor	eax, eax
calign
.searchloop:
	cmp	dword [rdx], 0
	jne	.searchnext
	; else, !streamstatus on this one
	add	dword [rdi+tui_matrix_streamcount_ofs], 1
	mov	dword [rdx], 1
	lea	rcx, [rdi+tui_matrix_lastupdatey_ofs]
	mov	dword [rcx+rax*4], -1
	lea	rcx, [rdi+tui_matrix_starty_ofs]
	mov	dword [rcx+rax*4], 0
	push	rdi rax
	mov	edi, [rdi+tui_width_ofs]
	call	rng$intmax
	mov	r8d, eax
	pop	rax rdi
	lea	rcx, [rdi+tui_matrix_startx_ofs]
	mov	dword [rcx+rax*4], r8d
	push	rdi rax
	mov	edi, 5
	call	rng$intmax
	mov	r8d, eax
	pop	rax rdi
	lea	rcx, [rdi+tui_matrix_origspeed_ofs]
	mov	dword [rcx+rax*4], r8d
	lea	rcx, [rdi+tui_matrix_streamspeed_ofs]
	mov	dword [rcx+rax*4], r8d
	jmp	.dostops
calign
.searchnext:
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.searchloop
calign
.dostops:
	lea	rdx, [rdi+tui_matrix_streamstatus_ofs]
	mov	ecx, tui_matrix_maxstream
	xor	eax, eax
calign
.stoploop:
	cmp	dword [rdx], 0
	je	.stopnext
	lea	r8, [rdi+tui_matrix_starty_ofs]
	mov	r9d, [r8+rax*4]
	mov	r10d, [rdi+tui_height_ofs]
	add	r10d, tui_matrix_backtrace
	cmp	r9d, r10d
	jbe	.stopnext
	mov	dword [rdx], 0
	sub	dword [rdi+tui_matrix_streamcount_ofs], 1
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.stoploop
	epilog
calign
.stopnext:
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.stoploop
	epilog

calign
.nothingtodo:
	epilog

end if

if used tui_matrix$update | defined include_everything

	; single argument in rdi: our tui_matrix object
falign
tui_matrix$update:
	prolog	tui_matrix$update
	lea	rdx, [rdi+tui_matrix_streamstatus_ofs]
	mov	ecx, tui_matrix_maxstream
	xor	eax, eax
calign
.updateloop:
	cmp	dword [rdx], 0
	je	.updatenext
	lea	r8, [rdi+tui_matrix_streamspeed_ofs]
	cmp	dword [r8+rax*4], 0
	je	.updateloop_caseone
	sub	dword [r8+rax*4], 1
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.updateloop
	epilog
calign
.updateloop_caseone:
	lea	r8, [rdi+tui_matrix_starty_ofs]
	add	dword [r8+rax*4], 1
	lea	r8, [rdi+tui_matrix_origspeed_ofs]
	mov	r9d, dword [r8+rax*4]
	lea	r8, [rdi+tui_matrix_streamspeed_ofs]
	mov	dword [r8+rax*4], r9d
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.updateloop
	epilog
calign
.updatenext:
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.updateloop
	epilog

end if


if used tui_matrix$display | defined include_everything

	; single argument in rdi: our tui_matrix object
falign
tui_matrix$display:
	prolog	tui_matrix$display
	lea	rdx, [rdi+tui_matrix_streamstatus_ofs]
	mov	ecx, tui_matrix_maxstream
	xor	eax, eax
calign
.streamloop:
	cmp	dword [rdx], 0
	je	.streamnext
	lea	r8, [rdi+tui_matrix_lastupdatey_ofs]
	lea	r9, [rdi+tui_matrix_starty_ofs]
	mov	r11d, dword [r9+rax*4]
	cmp	r11d, dword [r8+rax*4]
	je	.streamnext
	mov	dword [r8+rax*4], r11d
	lea	r8, [rdi+tui_matrix_startx_ofs]
	mov	r10d, dword [r8+rax*4]
	; x is in r10d, y is in r11d
	lea	r8, [rdi+tui_matrix_origspeed_ofs]
	mov	r9d, [r8+rax*4]
	; sos is in r9d
	; note, we precalculate all of our necessary vars here for the different cases depending on y
	sub	rsp, 120
	mov	[rsp], rdi			; preserve our object
	mov	[rsp+8], rdx			; outer loop
	mov	[rsp+16], rcx			; outer loop
	mov	[rsp+24], rax			; outer loop
	; calculate text/attr offsets for each of our three scenarios beforehand
	mov	ecx, [rdi+tui_height_ofs]
	mov	eax, [rdi+tui_width_ofs]
	mov	[rsp+32], rcx			; height
	xor	edx, edx
	mul	r11d				; eax now has y * width
	add	eax, r10d
	shl	eax, 2
	mov	[rsp+40], rax			; (y * width) + x in bytes
	mov	eax, [rdi+tui_width_ofs]
	xor	edx, edx
	mov	ecx, r11d
	sub	ecx, 1
	mul	ecx
	add	eax, r10d
	shl	eax, 2
	mov	[rsp+48], rax			; ((y-1) * width) + x in bytes
	mov	eax, [rdi+tui_width_ofs]
	xor	edx, edx
	mov	ecx, r11d
	sub	ecx, tui_matrix_backtrace
	mul	ecx
	add	eax, r10d
	shl	eax, 2
	mov	[rsp+56], rax			; ((y-backtrace) * width) + x
	; store our text/attr offsets so we don't have to reload rdi over and over again
	mov	rsi, [rdi+tui_text_ofs]
	mov	[rsp+64], rsi
	mov	rsi, [rdi+tui_attr_ofs]
	mov	[rsp+72], rsi

	; save our y (in r11) for the actual case checks
	mov	[rsp+80], r11

	; next up: calculate our two different colors
	xor	edx, edx
	mov	eax, tui_matrix_incr
	mul	r9d
	mov	r8d, tui_matrix_r
	sub	r8d, eax			; r - sos * incR
	xor	edx, edx
	mov	eax, tui_matrix_incg
	mul	r9d
	mov	r10d, tui_matrix_g
	sub	r10d, eax			; g - sos * incG
	xor	edx, edx
	mov	eax, tui_matrix_incb
	mul	r9d
	mov	r11d, tui_matrix_b
	sub	r11d, eax			; b - sos * incB
	; now, because we know this is the matrix and all, we aren't checking for r == g == b
	; so we can just divide all of these by 43 and put them back into a 256 color for us
	xor	edx, edx
	mov	eax, r8d
	mov	ecx, 43
	div	ecx
	mov	r8d, eax			; (r - sos * incR) / 43
	xor	edx, edx
	mov	eax, r10d
	mov	ecx, 43
	div	ecx
	xor	edx, edx
	mov	ecx, 6
	mul	ecx
	mov	r10d, eax			; ((g - sos * incG) / 43) * 6
	xor	edx, edx
	mov	eax, r11d
	mov	ecx, 43
	div	ecx
	xor	edx, edx
	mov	ecx, 36
	mul	ecx
	mov	r11d, eax			; ((b - sos * incG) / 43) * 36
	mov	eax, r8d
	add	eax, r10d
	add	eax, r11d
	add	eax, 16
	shl	eax, 8
	; update to make sure it is really black:
	or	eax, 0xe8
	mov	[rsp+88], rax			; initial color
	; now do the same thing but with r/3 - sos*incR, and with incr_s instead
	xor	edx, edx
	mov	eax, tui_matrix_incr_s
	mul	r9d
	mov	r8d, tui_matrix_r / 3
	sub	r8d, eax			; r - sos * incR
	xor	edx, edx
	mov	eax, tui_matrix_incg_s
	mul	r9d
	mov	r10d, tui_matrix_g / 3
	sub	r10d, eax			; g - sos * incG
	xor	edx, edx
	mov	eax, tui_matrix_incb_s
	mul	r9d
	mov	r11d, tui_matrix_b / 3
	sub	r11d, eax			; b - sos * incB
	; now, because we know this is the matrix and all, we aren't checking for r == g == b
	; so we can just divide all of these by 43 and put them back into a 256 color for us
	xor	edx, edx
	mov	eax, r8d
	mov	ecx, 43
	div	ecx
	mov	r8d, eax			; (r/3 - sos * incR) / 43
	xor	edx, edx
	mov	eax, r10d
	mov	ecx, 43
	div	ecx
	xor	edx, edx
	mov	ecx, 6
	mul	ecx
	mov	r10d, eax			; ((g/3 - sos * incG) / 43) * 6
	xor	edx, edx
	mov	eax, r11d
	mov	ecx, 43
	div	ecx
	xor	edx, edx
	mov	ecx, 36
	mul	ecx
	mov	r11d, eax			; ((b/3 - sos * incG) / 43) * 36
	mov	eax, r8d
	add	eax, r10d
	add	eax, r11d
	add	eax, 16
	shl	eax, 8
	; update to make sure it is really black:
	or	eax, 0xe8
	mov	[rsp+96], rax			; secondary color
	; next up, we need two random characters, though we may only use one of them
if tui_matrix_cpukiller
	; Terminal.app does _NOT_ like these, and doesn't render them correctly either...
	mov	edi, 366
	call	rng$intmax
	mov	rcx, rax
	mov	rdx, rax
	sub	rcx, 63
	add	rcx, 0x180			; latin alphanumerics
	add	rdx, 0xff61			; half-width kana
	cmp	rax, 63
	cmovb	rcx, rdx
	; code in ecx is our random character
	mov	[rsp+104], rcx
	; do it again
	mov	edi, 366
	call	rng$intmax
	mov	rcx, rax
	mov	rdx, rax
	sub	rcx, 63
	add	rcx, 0x180			; latin alphanumerics
	add	rcx, 0xff61			; half-width kana
	cmp	rax, 63
	cmovb	rcx, rdx
	; code in ecx is our random character
	mov	[rsp+112], rcx
else
	; It isn't particularly happy about these either, but way better than the cpukiller above
	mov	edi, 62
	call	rng$intmax
	add	rax, 0xff61			; half-width kana only
	mov	[rsp+104], rax
	; do it again
	mov	edi, 62
	call	rng$intmax
	add	rax, 0xff61
	mov	[rsp+112], rax
end if
	; so we have done all our unpleasant calculations, even if we don't use them all
	; so now we can check the y position, and draw the right goods
	mov	r11, [rsp+80]			; y
	mov	rcx, [rsp+32]			; height
	cmp	r11d, ecx
	jae	.checksecond
	; else, load up text/attr/offset and set to first randomchar and our first color
	mov	r8, [rsp+64]			; text
	mov	r9, [rsp+72]			; attr
	mov	r10, [rsp+40]			; (y * width) + x in bytes
	mov	eax, dword [rsp+104]		; character
	mov	edx, dword [rsp+88]		; initial color
	mov	dword [r8+r10], eax
	mov	dword [r9+r10], edx
calign
.checksecond:
	cmp	r11d, ecx
	ja	.checkthird
	test	r11d, r11d
	jz	.checkthird
	; else, load up text/attr/offset of y-1 and set to second randomchar and second color
	mov	r8, [rsp+64]			; text
	mov	r9, [rsp+72]			; attr
	mov	r10, [rsp+48]			; ((y-1)*width) + x in bytes
	mov	eax, dword [rsp+112]		; character
	mov	edx, dword [rsp+96]		; second color
	mov	dword [r8+r10], eax
	mov	dword [r9+r10], edx
calign
.checkthird:
	cmp	r11d, tui_matrix_backtrace
	jb	.nothird
	sub	r11d, tui_matrix_backtrace
	cmp	r11d, ecx
	jae	.nothird
	; else, load up text/attr/offset of y-backtrace and set char to ' ' and colors to 'green', 'black'
	mov	r8, [rsp+64]			; text
	mov	r9, [rsp+72]			; attr
	mov	r10, [rsp+56]			; ((y-backtrace)*width) + x in bytes
	ansi_colors edx, 'green', 'black'
	mov	dword [r8+r10], ' '
	mov	dword [r9+r10], edx
calign
.nothird:
	; restore our regs and stack and keep going
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	rax, [rsp+24]
	add	rsp, 120
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.streamloop
	epilog
calign
.streamnext:
	add	eax, 1
	add	rdx, 4
	sub	ecx, 1
	jnz	.streamloop
	epilog

end if



if used tui_matrix$timer | defined include_everything

	; single argument in rdi: our tui_matrix object
falign
tui_matrix$timer:
	prolog	tui_matrix$timer
	push	rdi
	call	tui_matrix$createdestroy
	mov	rdi, [rsp]
	call	tui_matrix$update
	mov	rdi, [rsp]
	call	tui_matrix$display
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rdi
	xor	eax, eax	; keep going
	epilog

end if
