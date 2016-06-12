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
	; tui_statusbar.inc: a single line statusbar with some builtins for things like:
	;   vertical line (|) spaced optional goods on the right, statusbar text on the left
	;   auto-updating uptime (time elapsed since we were created)
	;

if used tui_statusbar$vtable | defined include_everything

dalign
tui_statusbar$vtable:
	dq      tui_statusbar$cleanup, tui_statusbar$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_statusbar$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

tui_statusbar_colors_ofs = tui_object_size
tui_statusbar_douptime_ofs = tui_object_size + 4
tui_statusbar_initialtime_ofs = tui_object_size + 8
tui_statusbar_statuslabel_ofs = tui_object_size + 16
tui_statusbar_uptimelabel_ofs = tui_object_size + 24
tui_statusbar_timerptr_ofs = tui_object_size + 32

tui_statusbar_size = tui_object_size + 40

	; we make use of a global statusbar formatter, as there is no sense in making duplicates of it for uptime label
	; purposes, called from ht$init if tui_statusbar$vtable is used

globals
{
	tui_statusbar_formatter	dq	0
}

falign
tui_statusbar$globalinit:
	prolog	tui_statusbar$globalinit
	xor	edi, edi
	call	formatter$new
	mov	[tui_statusbar_formatter], rax
	mov	rdi, rax
	mov	rsi, .s1
	call	formatter$add_static
	mov	rdi, [tui_statusbar_formatter]
	mov	esi, 2			; minutes resolution
	xor	edx, edx		; no fractional component
	call	formatter$add_duration
	mov	rdi, [tui_statusbar_formatter]
	mov	rsi, .s2
	call	formatter$add_static
	epilog
dalign
.s1:
	dq	6
if string_bits = 32
	dd	' ', 0x2502, ' ', 'u', 'p', ' '
else
	dw	' ', 0x2502, ' ', 'u', 'p', ' '
end if
cleartext .s2, ' '

end if


	; we have three non-virtual functions as well:
	; nvsetcolors: changes the colors of our statusbar and issues a redraw (all children's colors)
	; nvsettext: sets the statusbar text
	; nvaddlabel: adds a vertical line-spaced label to our statusbar

if used tui_statusbar$new_i | defined include_everything
	; three arguments: edi == width, esi == colors, edx == bool for whether to include uptime or not
falign
tui_statusbar$new_i:
	prolog	tui_statusbar$new_i
	push	rdi rsi rdx
	mov	edi, tui_statusbar_size
	call	heap$alloc_clear
	pop	rdx rsi
	mov	rdi, [rsp]
	mov	[rsp], rax
	mov	qword [rax], tui_statusbar$vtable
	mov	[rax+tui_statusbar_colors_ofs], esi
	mov	[rax+tui_statusbar_douptime_ofs], edx
	mov	esi, edi
	mov	edx, 1
	mov	rdi, rax
	call	tui_object$init_ii
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	call	tui_statusbar$nvsetup
	pop	rax
	epilog

end if

if used tui_statusbar$new_d | defined include_everything
	; three arguments: xmm0 == widthperc, edi == colors, esi == bool for whether to include uptime or not
falign
tui_statusbar$new_d:
	prolog	tui_statusbar$new_d
	sub	rsp, 24
	movq	rax, xmm0
	mov	[rsp], rax
	mov	[rsp+8], rdi
	mov	[rsp+16], rsi
	mov	edi, tui_statusbar_size
	call	heap$alloc_clear
	mov	rdx, [rsp+16]
	mov	rsi, [rsp+8]
	mov	rcx, [rsp]
	mov	qword [rax], tui_statusbar$vtable
	mov	[rax+tui_statusbar_colors_ofs], esi
	mov	[rax+tui_statusbar_douptime_ofs], edx
	mov	[rsp], rax
	movq	xmm0, rcx
	mov	esi, 1
	mov	rdi, rax
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	call	tui_statusbar$nvsetup
	mov	rax, [rsp]
	add	rsp, 24
	epilog

end if

if used tui_statusbar$nvsetup | defined include_everything
	; single argument in rdi: our tui_statusbar object
falign
tui_statusbar$nvsetup:
	prolog	tui_statusbar$nvsetup
	; this is called for either of our "new" scenarios
	push	rbx
	mov	rbx, rdi
	call	timestamp
	movq	rax, xmm0
	mov	[rbx+tui_statusbar_initialtime_ofs], rax
	; fire up a 5 second timer
	mov	edi, 5000
	mov	rsi, rbx
	call	epoll$timer_new
	mov	[rbx+tui_statusbar_timerptr_ofs], rax
	; add an empty status label
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	mov	rsi, .emptystr
	mov	edx, [rbx+tui_statusbar_colors_ofs]
	mov	ecx, tui_textalign_left
	call	tui_label$new_di
	mov	[rbx+tui_statusbar_statuslabel_ofs], rax
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	cmp	dword [rbx+tui_statusbar_douptime_ofs], 0
	jne	.withuptime
	pop	rbx
	epilog
calign
.withuptime:
	mov	edi, 9
	mov	esi, 1
	mov	rdx, .s1
	mov	ecx, [rbx+tui_statusbar_colors_ofs]
	mov	r8d, tui_textalign_right
	call	tui_label$new_ii
	mov	[rbx+tui_statusbar_uptimelabel_ofs], rax
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	pop	rbx
	epilog
cleartext .emptystr, ''
dalign
.s1:
	dq	9
if string_bits = 32
	dd	' ', 0x2502, ' ', 'u', 'p', ' ', '0', 'm', ' '
else
	dw	' ', 0x2502, ' ', 'u', 'p', ' ', '0', 'm', ' '
end if

end if


if used tui_statusbar$cleanup | defined include_everything
	; single argument in rdi: our tui_statusbar object
falign
tui_statusbar$cleanup:
	prolog	tui_statusbar$cleanup
	; since all our children are normal tui_objects, tui_object$cleanup
	; will take care of all of them
	; cleanup our timer:
	push	rdi
	mov	rdi, [rdi+tui_statusbar_timerptr_ofs]
	call	epoll$timer_clear
	pop	rdi
	call	tui_object$cleanup
	epilog

end if

if used tui_statusbar$clone | defined include_everything
	; single argument in rdi: our tui_statusbar object
falign
tui_statusbar$clone:
	prolog	tui_statusbar$clone
	; let tui_object$init_copy copy all our children for us
	push	rdi
	mov	edi, tui_statusbar_size
	call	heap$alloc_clear
	mov	rsi, [rsp]
	push	rax
	call	tui_object$init_copy
	; then, first child is our statuslabel
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rax, [rsi+tui_statusbar_colors_ofs]	; includes douptime as well
	mov	rdx, [rdi+tui_children_ofs]
	mov	[rdi+tui_statusbar_colors_ofs], rax
	mov	rdx, [rdx+_list_first_ofs]
	mov	rdx, [rdx]
	mov	[rdi+tui_statusbar_statuslabel_ofs], rdx
	mov	edi, 5000
	mov	rsi, rdi
	call	epoll$timer_new
	mov	rdi, [rsp]
	mov	[rdi+tui_statusbar_timerptr_ofs], rax

	cmp	dword [rdi+tui_statusbar_douptime_ofs], 0
	jne	.withuptime
	mov	rax, rdi
	add	rsp, 16
	epilog
calign
.withuptime:
	; the -last- child is the uptimelabel
	mov	rdx, [rdi+tui_children_ofs]
	mov	rdx, [rdx+_list_last_ofs]
	mov	rdx, [rdx]
	mov	[rdi+tui_statusbar_uptimelabel_ofs], rdx
	; we need to reset the initialtime (since we don't want _program uptime_)
	; though I suppose that could be an option as well
	; commenting this section out would == program uptime for a tui_* server enviro
	call	timestamp
	mov	rdi, [rsp]
	movq	rax, xmm0
	mov	[rdi+tui_statusbar_initialtime_ofs], rax
	; last but not least, reset our uptimelabel text
	; NOTE: since the _original_ object (before clone) ALSO has a running timer
	; it means that our label, now cloned, has a size in excess of the 9 characters we really want
	; so we fire a sizechanged as well
	mov	rdi, [rdi+tui_statusbar_uptimelabel_ofs]
	mov	rsi, .s1
	call	tui_label$nvsettext
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_statusbar_uptimelabel_ofs]
	mov	dword [rdi+tui_width_ofs], 9
	mov	rsi, [rdi]
	call	qword [rsi+tui_vsizechanged]
	; one more to force the statusbar to lay itself out again
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	mov	rax, [rsp]
	add	rsp, 16
	epilog
dalign
.s1:
	dq	9
if string_bits = 32
	dd	' ', 0x2502, ' ', 'u', 'p', ' ', '0', 'm', ' '
else
	dw	' ', 0x2502, ' ', 'u', 'p', ' ', '0', 'm', ' '
end if

end if

if used tui_statusbar$timer | defined include_everything
	; single argument in rdi: our tui_statusbar object
falign
tui_statusbar$timer:
	prolog	tui_statusbar$timer
	cmp	dword [rdi+tui_statusbar_douptime_ofs], 0
	je	.nothingtodo
	push	rbx
	mov	rbx, rdi
	; this gets called for us every 5 seconds, so that we may update our uptimelabel
	; and even if !douptime, for code simplicity, we still fire up a timer
	; they are very lightweight and don't cause much penalty, and most all of my use-cases
	; actually use the uptime anyway so this is fine by me.
	; we can't use the epoll global timestamp value, because we need truncated jd timestamps
	call	timestamp
	subsd	xmm0, [rbx+tui_statusbar_initialtime_ofs]
	mov	rdi, [tui_statusbar_formatter]
	call	formatter$doit
	push	rax
	mov	rdi, [rbx+tui_statusbar_uptimelabel_ofs]
	mov	rsi, rax
	call	tui_label$nvsettext
	mov	rdi, [rsp]
	mov	rax, [rdi]		; length of the string
	mov	[rsp], rax
	call	heap$free
	; now, make sure that the width of our string == width of the label
	; and if not, resize the labelv to suit
	mov	rdi, [rbx+tui_statusbar_uptimelabel_ofs]
	pop	rax
	cmp	[rdi+tui_width_ofs], eax
	jne	.firesizechanged
	pop	rbx
	xor	eax, eax		; indefinitely keep firing our timer
	epilog
calign
.firesizechanged:
	mov	[rdi+tui_width_ofs], eax
	mov	rsi, [rdi]
	call	qword [rsi+tui_vsizechanged]
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vlayoutchanged]
	pop	rbx
	xor	eax, eax		; indefinitely keep firing our timer
	epilog
calign
.nothingtodo:
	epilog

end if


if used tui_statusbar$nvsetcolors | defined include_everything
	; two arguments: rdi == our tui_statusbar object, esi == new colors
	; NOTE: the reason this is here is because all our children are _labels_
	; so we static cast all our children to labels (CAVEAT EMPTOR if you add something that isn't a label)
	; and set each and every one of our children's lable colors to new colors, and let them redraw themselves
falign
tui_statusbar$nvsetcolors:
	prolog	tui_statusbar$nvsetcolors
	mov	rdi, [rdi+tui_children_ofs]
	mov	edx, esi
	mov	rsi, .childwalk
	call	list$foreach_arg
	epilog
falign
.childwalk:
	; rdi == our child (which must be a tui_label object), esi == colors
	mov	[rdi+tui_bgcolors_ofs], esi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	ret

end if

if used tui_statusbar$nvsettext | defined include_everything
	; two arguments: rdi == our tui_statusbar object, rsi == string to set the statuslabel
	; NOTE: we append the string in rsi to a fixed space, so that the caller doesn't always
	; have to prepend a space
falign
tui_statusbar$nvsettext:
	prolog	tui_statusbar$nvsettext
	push	rdi
	mov	rdi, .space
	call	string$concat
	mov	rdi, [rsp]
	push	rax
	mov	rdi, [rdi+tui_statusbar_statuslabel_ofs]
	mov	rsi, rax
	call	tui_label$nvsettext
	pop	rdi
	call	heap$free
	pop	rdi
	epilog
cleartext .space, ' '

end if

if used tui_statusbar$nvaddlabel | defined include_everything
	; two arguments: rdi == our tui_statusbar object, rsi == string of the label to add
	; we prepend the label with ' ', 0x2502, ' '
	; and then add it to the correct spot (right after the statuslabel)
	; NOTE: this means successive calls to addlabel == right to left display (reverse order of calls)
falign
tui_statusbar$nvaddlabel:
	prolog	tui_statusbar$nvaddlabel
	push	rdi
	mov	rdi, .s1
	call	string$concat
	mov	rdi, [rsp]
	push	rax
	mov	esi, 1
	mov	rdx, rax
	mov	ecx, [rdi+tui_statusbar_colors_ofs]
	mov	r8d, tui_textalign_left
	mov	edi, [rdx]
	call	tui_label$new_ii
	; we can't call the normal appendchild, because we need to insert it _after_ the statuslabel
	mov	rdi, [rsp+8]
	mov	rdx, rax
	mov	[rax+tui_parent_ofs], rdi
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	call	list$insert_after
	pop	rdi
	call	heap$free
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	epilog
dalign
.s1:
	dq	3
if string_bits = 32
	dd	' ', 0x2502, ' '
else
	dw	' ', 0x2502, ' '
end if


end if
