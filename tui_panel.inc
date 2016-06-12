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
	; tui_panel.inc: panel goodies... a panel is:
	; basically the same as a background, only with a box drawn around it
	; and a title atop, and automatic padding on the inside so that children
	; a) don't have to worry about the box, and b) can't write over top of it
	;
	; this is also a classic case of the reason why appendchild/etc are virtual methods
	; .. we hook them and toss them into a bounds-constrained child of our own
	; such that appendchild works the same as elsewhere, despite them being handled
	; differently here
	;

if used tui_panel$vtable | defined include_everything

dalign
tui_panel$vtable:
        dq      tui_panel$cleanup, tui_panel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
        dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

tui_panel_title_ofs = tui_background_size
tui_panel_titlecolors_ofs = tui_background_size + 8
tui_panel_titletext_ofs = tui_background_size + 16
tui_panel_guts_ofs = tui_background_size + 24
tui_panel_user_ofs = tui_background_size + 32		; not used in here

tui_panel_size = tui_background_size + 40



	; most panel instances i create aren't really descended from, but we are separating the $new and $init
	; such that it will be trivial to create either panels directly or descend from them either way

	; it is assumed that the pointer passed to the $init* functions already has (or will have) a valid vtable pointer

if used tui_panel$init_copy | defined include_everything
	; two arguments: rdi == tui_panel we are initialising, rsi == source tui_panel
	; this calls tui_background$init_copy and then sets up our own vars
falign
tui_panel$init_copy:
	prolog	tui_panel$init_copy
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	tui_background$init_copy
	; so that made a copy of all our children, and all our tui_object settings, and our tui_background settings
	; set our title colors
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+tui_panel_title_ofs]
	call	string$copy
	mov	rdi, [rsp]
	mov	[rdi+tui_panel_title_ofs], rax
	; copy the titlecolors
	mov	rsi, [rsp+8]
	mov	rdi, [rsp]
	mov	rdx, [rsi+tui_panel_titlecolors_ofs]
	mov	[rdi+tui_panel_titlecolors_ofs], rdx
	; next we need to make a copy of our titletext
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+tui_panel_titletext_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vclone]
	mov	rdi, [rsp]
	mov	[rdi+tui_panel_titletext_ofs], rax
	; last but not least, since all our children already got cloned, we need to set our guts pointer correctly
	mov	rdi, [rdi+tui_children_ofs]
	; this -cannot- be null, provided that a real panel was created in the first place
	mov	rdx, [_list_first]
	; move to its next
	mov	rdx, [rdx+_list_nextofs]
	; the child at rdx is our second child, so pull its object
	mov	rdi, [rdx+_list_valueofs]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdx, [_list_first]
	; move to its next
	mov	rdx, [rdx+_list_nextofs]
	mov	rdi, [rsp]
	; the child at rdx is our guts object
	mov	rsi, [rdx+_list_valueofs]
	mov	[rdi+tui_panel_guts_ofs], rsi
	add	rsp, 16
	epilog
end if

if used tui_panel$nvsetup | defined include_everything
	; three arguments: rdi == tui_panel, rsi == source titlestring (we'll copy it), edx = titlecolors
falign
tui_panel$nvsetup:
	prolog	tui_panel$nvsetup
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rdi+tui_panel_titlecolors_ofs], rdx
	mov	rdi, rsi
	call	string$copy
	mov	rdi, [rsp]
	mov	[rdi+tui_panel_title_ofs], rax
	mov	rcx, [rdi+tui_panel_titlecolors_ofs]
	; title text is next
	mov	rdx, rax		; filltext
	mov	rdi, [rax]		; string length
	add	rdi, 2			; + 2
	mov	esi, 1			; height
	mov	r8d, tui_textalign_center
	call	tui_label$new_ii
	mov	rdi, [rsp]
	mov	[rdi+tui_panel_titletext_ofs], rax


	; our "guts" container is next up...
	; what we want is an hbox atop of padding 1 height, same for bottom, left and right 1 x by 100%
	; and a guts fill in between the left/right ones that consumes 100%,100% of remaining space
	; then, with our overridden appendchild, children go into our guts container and not our
	; direct child list (this way, we preserve our border)

	; first up, we need to add to our _actual_ child list a horizontal spacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rsi, rax
	mov	rdi, [rsp]		; our tui_panel
	call	tui_object$appendchild	; NOT our overridden one!


	mov	edi, tui_object_size
	call	heap$alloc
	mov	[rsp+8], rax
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	mov	rdi, [rsp+8]
	; set its layout to horizontal:
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	; now we need a vertical spacer
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	tui_object$appendchild	; we don't use the vtable here because we know it is a tui_object

	; now we need another 100.0 x 100.0 for our guts itself
	mov	edi, tui_object_size
	call	heap$alloc
	mov	rcx, [rsp]		; our tui_panel object
	mov	[rcx+tui_panel_guts_ofs], rax	; save our guts object
	mov	rdi, rax
	mov	qword [rax], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	mov	rcx, [rsp]
	mov	rsi, [rcx+tui_panel_guts_ofs]
	mov	rdi, [rsp+8]
	call	tui_object$appendchild	; add it to our hbox
	
	; now we need one more vertical spacer added to it
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	tui_object$appendchild	; we don't use the vtable here because we know it is a tui_object

	; so now, we need to add the hbox itself to our real children list
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	call	tui_object$appendchild	; NOT our overridden one!

	; and last but not least, we need one more horizontal spacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rsi, rax
	mov	rdi, [rsp]
	call	tui_object$appendchild	; NOT our overridden one!

	add	rsp, 16
	epilog
end if


if used tui_panel$init_rect | defined include_everything
	; five arguments: rdi == tui_panel, rsi == pointer to a bounds rect, rdx == title string (we'll copy it), ecx = boxcolors, r8d = titlecolors
falign
tui_panel$init_rect:
	prolog	tui_panel$init_rect
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	[rsp+16], r8
	mov	edx, ' '		; fillchar for tui_background
					; ecx already set with our background colors
	call	tui_background$init_rect
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	call	tui_panel$nvsetup
	add	rsp, 24
	epilog
end if


if used tui_panel$init_id | defined include_everything
	; six arguments: rdi == tui_panel, esi = width, xmm0 == heightperc, rdx == title string (we'll copy it), ecx = boxcolors, r8d = titlecolors
falign
tui_panel$init_id:
	prolog	tui_panel$init_id
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	[rsp+16], r8
	mov	edx, ' '		; fillchar for tui_background
					; ecx already set with our background colors
	call	tui_background$init_id
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	call	tui_panel$nvsetup
	add	rsp, 24
	epilog
end if

if used tui_panel$init_di | defined include_everything
	; six arguments: rdi == tui_panel, xmm0 = widthperc, esi = height, rdx == title string (we'll copy it), ecx = boxcolors, r8d = titlecolors
falign
tui_panel$init_di:
	prolog	tui_panel$init_di
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	[rsp+16], r8
	mov	edx, ' '		; fillchar for tui_background
					; ecx already set with our background colors
	call	tui_background$init_di
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	call	tui_panel$nvsetup
	add	rsp, 24
	epilog
end if

if used tui_panel$init_dd | defined include_everything
	; six arguments: rdi == tui_panel, xmm0 = widthperc, xmm1 = heightperc, rsi == title string (we'll copy it), edx = boxcolors, ecx = titlecolors
falign
tui_panel$init_dd:
	prolog	tui_panel$init_dd
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rcx
	mov	esi, ' '		; fillchar for tui_background
					; edx already set with our background colors
	call	tui_background$init_dd
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	call	tui_panel$nvsetup
	add	rsp, 24
	epilog
end if

if used tui_panel$init_ii | defined include_everything
	; six arguments: rdi == tui_panel, esi = width, edx = height, rcx = title string (we'll copy it), r8d = boxcolors, r9d = titlecolors
falign
tui_panel$init_ii:
	prolog	tui_panel$init_ii
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rcx
	mov	[rsp+16], r9
	mov	ecx, ' '		; fillchar for tui_background
					; r8d already set with our background colors
	call	tui_background$init_ii
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	call	tui_panel$nvsetup
	add	rsp, 24
	epilog
end if

if used tui_panel$new_rect | defined include_everything
	; four arguments: rdi == pointer to a bounds rect, rsi = title string (we'll copy it), edx = boxcolors, ecx = titlecolors
	; returns new tui_panel in rax
falign
tui_panel$new_rect:
	prolog	tui_panel$new_rect
	push	rdi rsi rdx rcx
	mov	edi, tui_panel_size
	call	heap$alloc
	mov	qword [rax], tui_panel$vtable
	pop	r8 rcx rdx rsi
	mov	rdi, rax
	push	rax
	call	tui_panel$init_rect
	pop	rax
	epilog
end if


if used tui_panel$new_id | defined include_everything
	; five arguments: edi = width, xmm0 = heightperc, rsi = title string (we'll copy it), edx = boxcolors, ecx = titlecolors
	; returns new tui_panel in rax
falign
tui_panel$new_id:
	prolog	tui_panel$new_id
	sub	rsp, 48
	mov	[rsp], rdi
	movq	[rsp+8], xmm0
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	edi, tui_panel_size
	call	heap$alloc
	mov	qword [rax], tui_panel$vtable
	mov	[rsp+40], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	movq	xmm0, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	r8, [rsp+32]
	call	tui_panel$init_id
	mov	rax, [rsp+40]
	add	rsp, 48
	epilog
end if

if used tui_panel$new_di | defined include_everything
	; five arguments: xmm0 = widthperc, edi = height, rsi = title string (we'll copy it), edx = boxcolors, ecx = titlecolors
	; returns new tui_panel in rax
falign
tui_panel$new_di:
	prolog	tui_panel$new_di
	sub	rsp, 48
	movq	[rsp], xmm0
	mov	[rsp+8], rdi
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	edi, tui_panel_size
	call	heap$alloc
	mov	qword [rax], tui_panel$vtable
	mov	[rsp+40], rax
	mov	rdi, rax
	movq	xmm0, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	r8, [rsp+32]
	call	tui_panel$init_di
	mov	rax, [rsp+40]
	add	rsp, 48
	epilog
end if

if used tui_panel$new_dd | defined include_everything
	; five arguments: xmm0 = widthperc, xmm1 = heightperc, rdi = title string (we'll copy it), esi = boxcolors, edx = titlecolors
	; returns new tui_panel in rax
falign
tui_panel$new_dd:
	prolog	tui_panel$new_dd
	sub	rsp, 48
	movq	[rsp], xmm0
	movq	[rsp+8], xmm1
	mov	[rsp+16], rdi
	mov	[rsp+24], rsi
	mov	[rsp+32], rdx
	mov	edi, tui_panel_size
	call	heap$alloc
	mov	qword [rax], tui_panel$vtable
	mov	[rsp+40], rax
	mov	rdi, rax
	movq	xmm0, [rsp]
	movq	xmm1, [rsp+8]
	mov	rsi, [rsp+16]
	mov	rdx, [rsp+24]
	mov	rcx, [rsp+32]
	call	tui_panel$init_dd
	mov	rax, [rsp+40]
	add	rsp, 48
	epilog
end if

if used tui_panel$new_ii | defined include_everything
	; five arguments: edi = width, esi = height, rdx = title string (we'll copy it), ecx = boxcolors, r8d = titlecolors
	; returns new tui_panel in rax
falign
tui_panel$new_ii:
	prolog	tui_panel$new_ii
	sub	rsp, 48
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	edi, tui_panel_size
	call	heap$alloc
	mov	qword [rax], tui_panel$vtable
	mov	[rsp+40], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	call	tui_panel$init_ii
	mov	rax, [rsp+40]
	add	rsp, 48
	epilog
end if


if used tui_panel$cleanup | defined include_everything
	; single argument: rdi == tui_panel to cleanup
	; NOTE: we do not delete the object itself, only cleanup what we allocated
falign
tui_panel$cleanup:
	prolog	tui_panel$cleanup
	; our titletext is not an actual child in our list, so we have to free that, and our titlestring itself
	; the rest will get cleaned up for us by tui_object$cleanup (noting we are actually descended from tui_background, but it has no special cleanup)
	push	rdi
	mov	rdi, [rdi+tui_panel_title_ofs]
	call	heap$free		; the title string
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_panel_titletext_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vcleanup]	; call the title text's cleanup vmethod
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_panel_titletext_ofs]
	call	heap$free
	; to cleanup the rest of our goods, we need to call tui_object's cleanup
	mov	rdi, [rsp]
	call	tui_object$cleanup
	pop	rdi
	epilog
end if


if used tui_panel$clone | defined include_everything
	; single argument: rdi == source tui_panel to clone/make a copy of
	; returns new tui_panel copy in rax
falign
tui_panel$clone:
	prolog	tui_panel$clone
	push	rdi
	mov	edi, tui_panel_size
	call	heap$alloc
	mov	qword [rax], tui_panel$vtable
	mov	rsi, [rsp]
	mov	[rsp], rax
	mov	rdi, rax
	call	tui_panel$init_copy
	pop	rax
	epilog
end if

if used tui_panel$draw | defined include_everything
	; single argument: rdi == tui_panel
falign
tui_panel$draw:
	prolog	tui_panel$draw
	push	rdi
	call	tui_background$nvfill
	mov	rdi, [rsp]
	cmp	dword [rdi+tui_width_ofs], 0
	je	.diddlysquat
	cmp	dword [rdi+tui_height_ofs], 0
	je	.diddlysquat
	; first up, draw our box
	xor	esi, esi			; x
	xor	edx, edx			; y
	mov	ecx, [rdi+tui_width_ofs]
	mov	r8d, [rdi+tui_height_ofs]
	mov	r9d, [rdi+tui_bgcolors_ofs]
	call	tui_object$nvbox
	; so long as our title's length is nonzero, draw our title as well
	mov	rdi, [rsp]
	mov	rsi, [rdi+tui_panel_title_ofs]
	cmp	qword [rsi], 0
	je	.notitle
	mov	rdi, [rdi+tui_panel_titletext_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vdraw]		; call our titletext's draw method first
	mov	rdi, [rsp]
	mov	rsi, [rdi+tui_panel_titletext_ofs]
	; non-empty title, draw it with left/right TEEs
	mov	ecx, [rdi+tui_width_ofs]
	mov	r8d, [rsi+tui_width_ofs]
	sub	ecx, r8d
	cmp	ecx, 0
	jl	.notitle
	shl	ecx, 1				; space leftover / 2 << 2 (for byte offset)
	and	ecx, not 3
	mov	r8, [rdi+tui_text_ofs]
	mov	r9, [rdi+tui_attr_ofs]
	add	r8, rcx
	add	r9, rcx
	sub	r8, 4
	sub	r9, 4
	cmp	r8, [rdi+tui_text_ofs]
	jb	.noltee
	mov	dword [r8], 0x2524		; LTEE
calign
.noltee:
	add	r8, 4
	add	r9, 4
	mov	r10, [rsi+tui_text_ofs]
	mov	r11, [rsi+tui_attr_ofs]
	mov	edx, [rsi+tui_width_ofs]
	shl	edx, 2				; in bytes
	mov	rax, r8				; where we are at in the buffer currently
	sub	rax, [rdi+tui_text_ofs]		; less the start == how many bytes we have used so far
	mov	rcx, [rdi+tui_width_ofs]
	shl	rcx, 2
	sub	rcx, rax
	cmp	rdx, rcx
	cmova	rdx, rcx			; make sure we don't overrun the buffer
	push	r8 r9 r10 r11 rdx
	mov	rdi, r8
	mov	rsi, r10
	call	memcpy
	pop	rdx r11 r10 r9 r8
	push	r8 r9 r10 r11 rdx
	mov	rdi, r9
	mov	rsi, r11
	call	memcpy
	pop	rdx r11 r10 r9 r8
	add	r8, rdx
	add	r9, rdx
	mov	rdi, [rsp]
	mov	ecx, [rdi+tui_width_ofs]
	shl	ecx, 2
	mov	r10, [rdi+tui_text_ofs]
	add	r10, rcx
	cmp	r8, r10
	jae	.nortee
	mov	dword [r8], 0x251c
calign
.nortee:
	mov	rdi, [rsp]
calign
.notitle:
	mov	rdx, [rdi]		; load up our vtable
	call	qword [rdx+tui_vupdatedisplaylist]
	pop	rdi
	epilog
calign
.diddlysquat:
	pop	rdi
	epilog
end if

if used tui_panel$appendchild | defined include_everything
	; two arguments: rdi == our tui_panel, rsi == new object to add
falign
tui_panel$appendchild:
	prolog	tui_panel$appendchild
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rcx, [rdi]			; load up its vtable
	call	qword [rcx+tui_vappendchild]
	epilog
end if


if used tui_panel$prependchild | defined include_everything
	; two arguments: rdi == our tui_panel, rsi == new object to add
falign
tui_panel$prependchild:
	prolog	tui_panel$prependchild
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rcx, [rdi]			; load up its vtable
	call	qword [rcx+tui_vprependchild]
	epilog
end if


if used tui_panel$contains | defined include_everything
	; two arguments: rdi == our tui_panel, rsi == object to test for
	; returns zero in eax if rsi is not in our children list, or 1 in eax if it does
falign
tui_panel$contains:
	prolog	tui_panel$contains
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rcx, [rdi]			; load up its vtable
	call	qword [rcx+tui_vcontains]
	epilog
end if


if used tui_panel$getchildindex | defined include_everything
	; two arguments: rdi == our tui_panel, rsi == object to test for
	; returns unsigned index in eax, or -1 if it isn't found
falign
tui_panel$getchildindex:
	prolog	tui_panel$getchildindex
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rcx, [rdi]			; load up its vtable
	call	qword [rcx+tui_vgetchildindex]
	epilog
end if


if used tui_panel$removechild | defined include_everything
	; two arguments: rdi == our tui_panel, rsi == object to remove
	; NOTE: does _NOT_ delete/heap$free the child
	; if we do indeed remove it, we fire a layoutchanged vmethod call to redraw
	; returns zero in rax if we didn't find it, or returns the child pointer if we did
falign
tui_panel$removechild:
	prolog	tui_panel$removechild
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rcx, [rdi]			; load up its vtable
	call	qword [rcx+tui_vremovechild]
	epilog
end if
