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
	; tui_splash.inc: my 2 Ton Digital "signature" splash
	; meant to be the first child of any app/server, not too
	; over-the-top, haha, but distinguished :-)
	;
	; because of the embedded png, this adds about ~18k overhead
	;
	; keypress to cancel it, or when it finishes its deed, it will
	; add the appropriate first child in its place, and clone itself
	; accordingly
	;

if used tui_splash$vtable | defined include_everything


	; if this is set to 1, the logo png itself ends up in the lower 75% of the available height
	; zero, == 100% of height.
tui_splash_small_logo = 0


tui_splash_initcomplete_ofs = tui_background_size
tui_splash_onlychild_ofs = tui_background_size + 8
tui_splash_donecb_ofs = tui_background_size + 16
tui_splash_donecbarg_ofs = tui_background_size + 24

tui_splash_size = tui_background_size + 32

dalign
tui_splash$vtable:
	dq      tui_splash$cleanup, tui_splash$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_splash$sizechanged
	dq      tui_splash$alldonetimer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_splash$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

dalign
tui_splash$typist_vtable:
	dq      tui_typist$cleanup, tui_typist$clone, tui_typist$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_typist$sizechanged
	dq      tui_typist$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; we add one for our oncomplete:
	dq      tui_splash$typistcomplete

dalign
tui_splash$png_vtable:
	dq      tui_splash$logocleanup, tui_png$clone, tui_png$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_splash$logotimer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if


if used tui_splash$new | defined include_everything
	; single argument in rdi: the tui object to fire up on cancel or when our action completes
falign
tui_splash$new:
	prolog	tui_splash$new
	push	rdi
	mov	edi, tui_splash_size
	call	heap$alloc_clear
	push	rax					; [rsp] == our tui_splash object
	mov	qword [rax], tui_splash$vtable
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	esi, ' '
	mov	edx, 0xe8
	call	tui_background$init_dd
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rdi+tui_splash_onlychild_ofs], rsi
	mov	qword [rdi+tui_splash_initcomplete_ofs], 0
	; don't fire up the rest of our goods until we have valid bounds
	pop	rax rsi
	epilog

end if

if used tui_splash$sizechanged | defined include_everything
	; single argument in rdi: our tui_splash object
falign
tui_splash$sizechanged:
	prolog	tui_splash$sizechanged
	cmp	dword [rdi+tui_splash_initcomplete_ofs], 0
	jne	.normalsizechanged
	cmp	dword [rdi+tui_width_ofs], 0
	je	.normalsizechanged
	cmp	dword [rdi+tui_height_ofs], 0
	je	.normalsizechanged

	mov	dword [rdi+tui_splash_initcomplete_ofs], 1
	push	rax rdi
	; now we need a typist in the lower left corner
	; but padded, so we'll toss it into a box
	mov	edi, tui_object_size
	call	heap$alloc
	mov	[rsp+8], rax				; [rsp+8] == our typist container box
	mov	rdi, rax
	mov	esi, 46
	mov	edx, 3
	call	tui_object$init_ii
	mov	rax, [rsp+8]
	mov	qword [rax], tui_object$simple_vtable
	mov	dword [rax+tui_layout_ofs], tui_layout_horizontal
	mov	dword [rax+tui_vertalign_ofs], tui_align_bottom
	; now we can add our typist to it
	mov	edi, 46
	mov	esi, 1
	mov	rdx, .heavything
	ansi_colors ecx, 'lightgray', 'black'
	call	tui_typist$new_ii
	mov	qword [rax], tui_splash$typist_vtable
	mov	rdi, [rsp+8]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; now we can append the box to our background as a bastard child
	mov	rsi, [rsp+8]
	mov	rdi, [rsp]
	mov	dword [rsi+tui_horizalign_ofs], tui_align_left
	mov	dword [rsi+tui_vertalign_ofs], tui_align_bottom
	mov	dword [rsi+tui_bastardglue_ofs], 1
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendbastard]
	
	mov	rdi, [rsp]
	call	tui_object$sizechanged

	pop	rsi rax
	epilog
calign
.normalsizechanged:
	call	tui_object$sizechanged
	epilog
dalign
.heavything:
	dq      52
	dd      'I', 't', ' ', 'h', 'i', 't', ' ', 'm', 'e', ' ', 'l', 'i', 'k', 'e', ' ', 'a', '.', '.', '.', 0, 0, 0, 0, ' ', 'u', 'm', 'm', '.', '.', '.', 0, 0, 0, 0, ' ', '2', ' ', 't', 'o', 'n', ' ', 'h', 'e', 'a', 'v', 'y', ' ', 't', 'h', 'i', 'n', 'g'


end if

if used tui_splash$logo | defined include_everything


globals
{
tui_splash$logo	dq	0
}

falign
tui_splash$initlogo:
	prolog	tui_splash$initlogo
	mov	rdi, .logodata
	mov	rsi, .logosize
	call	png$new
	mov	[tui_splash$logo], rax
	epilog

dalign
.logodata:
	file	'2ton.png'

.logosize = $ - .logodata

end if

if used tui_splash$typistcomplete | defined include_everything
	; single arg in rdi: our typist object
falign
tui_splash$typistcomplete:
	prolog	tui_splash$typistcomplete
	; so our parent's parent is our outer tui_splash object
if tui_splash_small_logo
	; divvy it up into 25% 75% height, and toss a logo at the bottom using a vslidein effect
	push	rdi
	movq	xmm0, [.topspace]
	call	tui_vspacer$new_d
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, [tui_splash$logo]
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [.bottomspace]
	call	tui_png$new_dd
	mov	qword [rax], tui_splash$png_vtable
	mov	qword [rax+tui_png_user_ofs], 0
	pop	rdi
	mov	r8, rdi
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rsi, rax
	mov	edx, 1
	mov	rcx, tui_splash$logocomplete
	call	tui_effect$vslidein
	epilog
dalign
.topspace	dq	25.0f
.bottomspace	dq	75.0f

else
	push	rdi
	mov	rdi, [tui_splash$logo]
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_png$new_dd
	mov	qword [rax], tui_splash$png_vtable
	mov	qword [rax+tui_png_user_ofs], 0
	pop	rdi
	mov	r8, rdi
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rsi, rax
	mov	edx, 1
	mov	rcx, tui_splash$logocomplete
	call	tui_effect$vslidein
	epilog
end if

end if

if used tui_splash$logocomplete | defined include_everything

falign
tui_splash$logocomplete:
	prolog	tui_splash$logocomplete
	; get rid of our typist object first up
	mov	rsi, [rdi+tui_parent_ofs]	; container of the typist
	mov	rdi, [rsi+tui_parent_ofs]	; our tui_splash object
	push	rdi
	push	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovebastard]
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	pop	rdi
	call	heap$free
	pop	rdi

if tui_splash_small_logo
	; our tui_splash contains precisely two children, vspacer, and our logo tui_png
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rsi, [rdx+_list_valueofs]
else
	; our tui_splash contains precisely one child, our logo tui_png
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rsi, [rdx+_list_valueofs]
end if

	push	rsi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vhidecursor]
	pop	rsi

	mov	edi, 1750
	push	rsi
	call	epoll$timer_new
	mov	dword [rax+24], 2		; special destruct goods, we want the timer cleared, but the object left alone
	pop	rsi
	mov	[rsi+tui_png_user_ofs], rax	; save the timerptr in case we destruct in the midst of it all
	epilog

end if

if used tui_splash$logocleanup | defined include_everything
	; single arg in rdi: our tui_png object
falign
tui_splash$logocleanup:
	prolog	tui_splash$logocleanup
	push	qword [rdi+tui_png_user_ofs]
	call	tui_png$cleanup
	pop	rdi
	test	rdi, rdi
	jz	.notimer
	call	epoll$timer_clear
	epilog
calign
.notimer:
	epilog

end if

if used tui_splash$logotimer | defined include_everything
	; single argument in rdi == our png object
falign
tui_splash$logotimer:
	prolog	tui_splash$logotimer
	; fire a vaporize effect on it
	mov	qword [rdi+tui_png_user_ofs], 0
	mov	rsi, rdi
	mov	rdi, [rdi+tui_parent_ofs]
	mov	rdx, tui_splash$alldone
	mov	rcx, rdi
	call	tui_effect$vaporize
	mov	eax, 1				; destruct our timer
	epilog

end if

if used tui_splash$alldone | defined include_everything
	; single argument in rdi == our tui_splash object
falign
tui_splash$alldone:	
	prolog	tui_splash$alldone
	
	; ok, some commentary is required here... as this situation does arise from time to time
	;
	; because this gets called at the tail end of an effect completion timer, if we proceed
	; and destroy all children/bastards from the topmost object, then we ourselves, and all
	; of the nested state information also gets killed, which would most certainly cause us
	; to crashy-crashy, but only because of how this event came to be in the first place
	;
	; if instead, as we do here, we create a short-lived timer, whose single-task is to
	; actually go ahead and kill us off, then we avoid the catastrophy situation above, without
	; much penalty (the timer really is the only penalty, and you can force that to 0 anyway)
	mov	rsi, rdi
	mov	edi, 50
	call	epoll$timer_new
	mov	dword [rax+24], 1			; special timer handling, we want it to clean up after us
	xor	eax, eax
	epilog

end if

if used tui_splash$alldonetimer | defined include_everything
	; we get a single argument in rdi, our tui_splash object
falign
tui_splash$alldonetimer:
	prolog	tui_splash$alldonetimer

	; do a showcursor again first:
	push	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]
	pop	rdi

	mov	qword [rdi+tui_bounds_ofs], 0		; this shares the same spot as io_parent_ofs
	push	qword [rdi+tui_splash_donecb_ofs]
	push	qword [rdi+tui_splash_donecbarg_ofs]
	push	qword [rdi+tui_splash_onlychild_ofs]
	mov	qword [rdi+tui_splash_onlychild_ofs], 0
	mov	rsi, rdi
	mov	rdi, [rdi+tui_parent_ofs]
	push	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	pop	rdi rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	pop	rdi rsi
	test	rsi, rsi
	jnz	.withcallback
	mov	eax, 1
	epilog
calign
.withcallback:
	call	rsi
	mov	eax, 1
	epilog

end if

if used tui_splash$cleanup | defined include_everything
	; single argument in rdi: our tui splash object
falign
tui_splash$cleanup:
	prolog	tui_splash$cleanup
	; if we have an onlychild still, kill it properly since it won't be anyone else's child yet
	cmp	qword [rdi+tui_splash_onlychild_ofs], 0
	je	.nochild
	push	rdi
	mov	rdi, [rdi+tui_splash_onlychild_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_splash_onlychild_ofs]
	call	heap$free
	pop	rdi
	mov	qword [rdi+tui_splash_onlychild_ofs], 0
calign
.nochild:
	; let our tui_object$cleanup do the deed
	call	tui_object$cleanup
	epilog

end if

if used tui_splash$clone | defined include_everything
	; single argument in rdi: our tui splash object to clone
falign
tui_splash$clone:
	prolog	tui_splash$clone
	; we have to clone our onlychild as well as ourselves
	push	rdi
	mov	edi, tui_splash_size
	call	heap$alloc_clear
	push	rax
	mov	rdi, rax
	mov	rsi, [rsp+8]
	call	tui_background$init_copy
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+tui_splash_onlychild_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vclone]
	mov	r8, rax
	pop	rax rsi
	mov	qword [rax+tui_splash_initcomplete_ofs], 0
	mov	[rax+tui_splash_onlychild_ofs], r8
	; TODO: add donecb goods to this func as well
	epilog

end if

if used tui_splash$keyevent | defined include_everything
	; three arguments, rdi == our tui_splash object, esi == key, edx == esc_key
falign
tui_splash$keyevent:
	prolog	tui_splash$keyevent
	cmp	esi, 3
	je	.skipit
	; do a showcursor again first, in case the key came through while we were hidden
	push	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]
	pop	rdi

	push	qword [rdi+tui_splash_donecb_ofs]
	push	qword [rdi+tui_splash_donecbarg_ofs]

	; because effects get added as bastards to the _topmost_ object, and because
	; we know we are the one and only child of the topmost object, we can safely
	; remove everything from the topmost object, toss in our onlychild, and be done
	mov	rsi, [rdi+tui_splash_onlychild_ofs]
	mov	qword [rdi+tui_splash_onlychild_ofs], 0
	push	rsi
calign
.findtop:
	mov	rdi, [rdi+tui_parent_ofs]
	cmp	qword [rdi+tui_parent_ofs], 0
	jne	.findtop
	mov	rsi, [rdi]
	push	rdi rsi
	call	qword [rsi+tui_vremoveallbastards]
	mov	rsi, [rsp]
	mov	rdi, [rsp+8]
	call	qword [rsi+tui_vremoveallchildren]
	pop	rdx rdi
	pop	rsi
	call	qword [rdx+tui_vappendchild]
	pop	rdi rsi
	test	rsi, rsi
	jnz	.withcb
	mov	eax, 1
	epilog
calign
.skipit:
	xor	eax, eax
	epilog
calign
.withcb:
	call	rsi
	mov	eax, 1
	epilog

end if
