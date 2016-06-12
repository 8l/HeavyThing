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
	; tui_form.inc: a "convenience wrapper" to hold form-style goods
	; 
	; we deal with all the normal input components, and importantly
	; deal with tab order, etc.
	;
	;
	; NOTE: if you want custom focus changes from onenter/etc from tui_text or the like,
	; you'll need to hook it outside of here and call our tab/shifttab/whatever
	; same goes for submit style functionality, hook the onenters
	;
	; And for button presses, they fire the click event, so it is up to you how to deal
	; with those events

if used tui_form$vtable | defined include_everything

; our custom vtable is a copy of tui_background's, except for ontab, onshifttab
dalign
tui_form$vtable:
	dq      tui_form$cleanup, tui_form$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_form$firekeyevent, tui_form$ontab, tui_form$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

tui_form_tablist_ofs = tui_background_size
tui_form_insidebox_ofs = tui_background_size + 8
tui_form_labelcolumn_ofs = tui_background_size + 16
tui_form_inputcolumn_ofs = tui_background_size + 24
tui_form_inputrow_ofs = tui_background_size + 32
tui_form_buttonrow_ofs = tui_background_size + 40
tui_form_focus_ofs = tui_background_size + 48

tui_form_size = tui_background_size + 56

end if


	; our main tui_form object is a tui_background with the specified parms, and inside that, a fixed size, centered tui_object
	; that gets a label column on its left, and an input column on its right, and optionally a buttonrow below those that is not
	; constrained by the label/input columns (e.g. independent)

	; so, our fixed size tui_object needs a fixed size top tui_object, to hold the label and input columns
	; and optionally underneath that, a tui_object to hold the centered buttons
	

if used tui_form$new_rect | defined include_everything
	; three arguments: rdi == pointer to a bounds rect, esi == fillchar, edx == fill colors
falign
tui_form$new_rect:
	prolog	tui_form$new_rect
	push	rdi rsi rdx
	mov	edi, tui_form_size
	call	heap$alloc_clear
	mov	qword [rax], tui_form$vtable
	mov	rdi, rax
	pop	rcx rdx rsi
	push	rax
	call	tui_background$init_rect
	call	list$new
	mov	rdi, [rsp]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	mov	[rdi+tui_form_tablist_ofs], rax
	pop	rax
	epilog

end if

if used tui_form$new_id | defined include_everything
	; four arguments: edi == width, xmm0 == heightperc, esi == fillchar, edx == fill colors
falign
tui_form$new_id:
	prolog	tui_form$new_id
	movq	rax, xmm0
	push	rdi rax rsi rdx
	mov	edi, tui_form_size
	call	heap$alloc_clear
	mov	qword [rax], tui_form$vtable
	mov	rdi, rax
	pop	rcx rdx r8 rsi
	movq	xmm0, r8
	push	rax
	call	tui_background$init_id
	call	list$new
	mov	rdi, [rsp]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	mov	[rdi+tui_form_tablist_ofs], rax
	pop	rax
	epilog

end if

if used tui_form$new_di | defined include_everything
	; four arguments: xmm0 == widthperc, edi == height, esi == fillchar, edx == fill colors
falign
tui_form$new_di:
	prolog	tui_form$new_di
	movq	rax, xmm0
	push	rdi rax rsi rdx
	mov	edi, tui_form_size
	call	heap$alloc_clear
	mov	qword [rax], tui_form$vtable
	mov	rdi, rax
	pop	rcx rdx r8 rsi
	movq	xmm0, r8
	push	rax
	call	tui_background$init_di
	call	list$new
	mov	rdi, [rsp]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	mov	[rdi+tui_form_tablist_ofs], rax
	pop	rax
	epilog

end if

if used tui_form$new_dd | defined include_everything
	; four arguments: xmm0 == widthperc, xmm1 == heightperc, edi == fillchar, esi == fill colors
falign
tui_form$new_dd:
	prolog	tui_form$new_dd
	movq	rax, xmm0
	movq	rcx, xmm1
	push	rdi rsi rax rcx
	mov	edi, tui_form_size
	call	heap$alloc_clear
	mov	qword [rax], tui_form$vtable
	mov	rdi, rax
	pop	r9 r8 rdx rsi
	movq	xmm0, r8
	movq	xmm1, r9
	push	rax
	call	tui_background$init_dd
	call	list$new
	mov	rdi, [rsp]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	mov	[rdi+tui_form_tablist_ofs], rax
	pop	rax
	epilog

end if

if used tui_form$new_ii | defined include_everything
	; four arguments: edi == width, esi == height, edx == fillchar, ecx == fill colors
falign
tui_form$new_ii:
	prolog	tui_form$new_ii
	push	rdi rsi rdx rcx
	mov	edi, tui_form_size
	call	heap$alloc_clear
	mov	qword [rax], tui_form$vtable
	mov	rdi, rax
	pop	r8 rcx rdx rsi
	push	rax
	call	tui_background$init_ii
	call	list$new
	mov	rdi, [rsp]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	mov	[rdi+tui_form_tablist_ofs], rax
	pop	rax
	epilog

end if

if used tui_form$clone | defined include_everything
	; single argument in rdi: our tui_form to clone
falign
tui_form$clone:
	prolog	tui_form$clone
	; let tui_background's init_copy get us a copy of all our children, and then we walk
	; the list

	; NOTE: tab order may not be maintained through this, so if you have a custom form that tosses
	; buttons in beforehand, etc, this will need to be redone if you want taborder to work right

	push	rbx r12
	mov	r12, rdi
	mov	edi, tui_form_size
	call	heap$alloc_clear
	mov	rdi, rax
	mov	rsi, r12
	mov	rbx, rax
	call	tui_background$init_copy
	; so now, we have to extract all our state vars from walking our own child list
	call	list$new
	mov	[rbx+tui_form_tablist_ofs], rax
	; if the original doesn't have an inside box, we are done
	cmp	qword [r12+tui_form_insidebox_ofs], 0
	je	.alldone
	; otehrwise, we know we have one of each, or both
	; our inside box is our second child
	mov	rdi, [rbx+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	rsi, [rsi+_list_nextofs]
	mov	rdx, [rsi+_list_valueofs]
	mov	[rbx+tui_form_insidebox_ofs], rdx
	; if the original has no inputrow, then it must have buttons
	cmp	qword [r12+tui_form_inputrow_ofs], 0
	je	.buttonsonly

	; our input row is its first child
	mov	rdi, [rdx+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	rdx, [rsi+_list_valueofs]
	mov	[rbx+tui_form_inputrow_ofs], rdx
	; our buttonrow is its second child, which may or may not exist
	mov	rsi, [rsi+_list_nextofs]
	test	rsi, rsi
	jz	.columns
	mov	rdx, [rsi+_list_valueofs]
	mov	[rbx+tui_form_buttonrow_ofs], rdx
calign
.columns:
	; we need to do our labelcolumn and inputcolumn, first and second child
	; of the inputrow
	mov	rdi, [rbx+tui_form_inputrow_ofs]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rcx, [rdx+_list_valueofs]
	mov	[rbx+tui_form_labelcolumn_ofs], rcx
	mov	rdx, [rdx+_list_nextofs]
	mov	rcx, [rdx+_list_valueofs]
	mov	[rbx+tui_form_inputcolumn_ofs], rcx
	; now we need to set our tablist to all of the children in our inputcolumn
	mov	rdi, [rcx+tui_children_ofs]
	mov	rsi, .tabadd
	mov	rdx, [rbx+tui_form_tablist_ofs]
	call	list$foreach_arg
calign
.dobuttons:
	; now we need to do our buttonrow, which is slightly more tricky
	mov	rdi, [rbx+tui_form_buttonrow_ofs]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .tabadd_nospacers
	mov	rdx, [rbx+tui_form_tablist_ofs]
	call	list$foreach_arg

	; and last but not least, set input focus to the first tab item
	mov	rdi, [rbx+tui_form_tablist_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	test	rsi, rsi
	jz	.alldone
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, [rdi]
	mov	[rbx+tui_form_focus_ofs], rdi
	call	qword [rsi+tui_vgotfocus]
	jmp	.alldone
calign
.buttonsonly:
	; our buttonrow is the first child
	mov	rdi, [rdx+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	rdx, [rsi+_list_valueofs]
	mov	[rbx+tui_form_buttonrow_ofs], rdx
	jmp	.dobuttons

calign
.alldone:
	mov	rax, rbx
	pop	r12 rbx
	epilog
falign
.tabadd:
	; rdi == tui_object, rsi == list we need to add it to
	xchg	rdi, rsi
	call	list$push_back
	ret
falign
.tabadd_nospacers:
	; rdi == tui_object, rsi == list we need to add it to
	cmp	qword [rdi+tui_widthperc_ofs], 0
	jne	.nodeal
	xchg	rdi, rsi
	call	list$push_back
	ret
calign
.nodeal:
	ret

end if

if used tui_form$cleanup | defined include_everything
	; single argument in rdi: our tui_form to cleanup
falign
tui_form$cleanup:
	prolog	tui_form$cleanup
	; tui_background/object's cleanup will deal with our children's destruction
	; but we need to cleanup our tab order list
	push	rdi
	mov	rdi, [rdi+tui_form_tablist_ofs]
	xor	esi, esi
	push	rdi
	call	list$clear
	pop	rdi
	call	heap$free
	pop	rdi
	call	tui_object$cleanup
	epilog

end if


if used tui_form$nvadditem | defined include_everything
	; three arguments: rdi == our tui_form object, rsi == tui_label object, rdx == tui_* input object
falign
tui_form$nvadditem:
	prolog	tui_form$nvadditem
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	cmp	qword [rdi+tui_form_insidebox_ofs], 0
	jne	.notfirstone
	; no inputs have yet been added, so we need to add our fixed size goods
	; add a vspacer first
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	; now add our fixed side inner goods
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	r14, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	rdi, rbx
	mov	rsi, r14
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	mov	[rbx+tui_form_insidebox_ofs], r14
	; and one more vspacer
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
calign
.notfirstone:
	; make sure we have a labelcolumn
	cmp	qword [rbx+tui_form_labelcolumn_ofs], 0
	jne	.notfirstitem
	; no labelcolumn == we need to do our inputrow initial
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	r14, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	dword [r14+tui_layout_ofs], tui_layout_horizontal
	mov	rdi, [rbx+tui_form_insidebox_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	mov	[rbx+tui_form_inputrow_ofs], r14
	call	qword [rdx+tui_vappendchild]
	; and into that we need our two children, labelcolumn and inputcolumn
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	r14, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	rdi, [rbx+tui_form_inputrow_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	mov	[rbx+tui_form_labelcolumn_ofs], r14
	mov	dword [r14+tui_horizalign_ofs], tui_align_right
	call	qword [rdx+tui_vappendchild]
	; inputcol next
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	r14, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	rdi, [rbx+tui_form_inputrow_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	mov	[rbx+tui_form_inputcolumn_ofs], r14
	call	qword [rdx+tui_vappendchild]
calign
.notfirstitem:
	; add the label and input, then recalculate our dimensions
	mov	rdi, [rbx+tui_form_labelcolumn_ofs]
	mov	rsi, r12
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, [rbx+tui_form_inputcolumn_ofs]
	mov	rsi, r13
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, [rbx+tui_form_tablist_ofs]
	mov	rsi, r13
	call	list$push_back
	; list$push_back returns us the list _item_, if focus was not already set, set it
	cmp	qword [rbx+tui_form_focus_ofs], 0
	jne	.skipfocus
	mov	[rbx+tui_form_focus_ofs], rax
	mov	rdi, r13
	mov	rsi, [r13]
	call	qword [rsi+tui_vgotfocus]
calign
.skipfocus:
	mov	rdi, rbx
	call	tui_form$nvnewdims
	pop	r14 r13 r12 rbx
	epilog

end if

if used tui_form$nvaddbutton | defined include_everything
	; two arguments: rdi == our tui_form object, rsi == tui_button object
falign
tui_form$nvaddbutton:
	prolog	tui_form$nvaddbutton
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	cmp	qword [rdi+tui_form_insidebox_ofs], 0
	jne	.notfirstone
	; no inputs have yet been added, so we need to add our fixed size goods
	; add a vspacer first
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	; now add our fixed side inner goods
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	r14, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	rdi, rbx
	mov	rsi, r14
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	mov	[rbx+tui_form_insidebox_ofs], r14
	; and one more vspacer
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
calign
.notfirstone:
	; make sure we have a buttonrow
	cmp	qword [rbx+tui_form_buttonrow_ofs], 0
	jne	.notfirstbutton
	; add a buttonrow to our form
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	r14, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	dword [r14+tui_layout_ofs], tui_layout_horizontal
	mov	rdi, [rbx+tui_form_insidebox_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	mov	[rbx+tui_form_buttonrow_ofs], r14
	call	qword [rdx+tui_vappendchild]
	; and to that, add our first 100% wide hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rbx+tui_form_buttonrow_ofs]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.notfirstbutton:
	; add our button, and an hspacer, and then recalculate our dimensions
	mov	rdi, [rbx+tui_form_buttonrow_ofs]
	mov	rsi, r12
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rbx+tui_form_buttonrow_ofs]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add our button to the tablist
	mov	rdi, [rbx+tui_form_tablist_ofs]
	mov	rsi, r12
	call	list$push_back
	; list$push_back returns us the list _item_, if focus was not already set, set it
	cmp	qword [rbx+tui_form_focus_ofs], 0
	jne	.skipfocus
	mov	[rbx+tui_form_focus_ofs], rax
	mov	rdi, r12
	mov	rsi, [r12]
	call	qword [rsi+tui_vgotfocus]
calign
.skipfocus:
	mov	rdi, rbx
	call	tui_form$nvnewdims
	pop	r14 r13 r12 rbx
	epilog

end if


if used tui_form$nvnewdims | defined include_everything
	; single argument in rdi: our tui_form object
falign
tui_form$nvnewdims:
	prolog	tui_form$nvnewdims
	; Burning Purpose: something got added, so we need to recalculate all our dimensions
	; such that the form contents remain aligned and happy when new stuff gets added
	; we need to calculate the maximum width of all labels, all inputs
	; and the button widths and heights
	xor	eax, eax
	push	rbx rax rax rax rax rax rax
	mov	rbx, rdi
	cmp	qword [rdi+tui_form_labelcolumn_ofs], 0
	je	.noinputs
	mov	rdi, [rbx+tui_form_labelcolumn_ofs]
	mov	rsi, .dims
	mov	rdx, rsp
	mov	rdi, [rdi+tui_children_ofs]
	call	list$foreach_arg
	; do the same again for the inputs
	mov	rdi, [rbx+tui_form_inputcolumn_ofs]
	mov	rsi, .dims
	lea	rdx, [rsp+16]
	mov	rdi, [rdi+tui_children_ofs]
	call	list$foreach_arg
calign
.noinputs:
	; so [rsp] == max width of labels
	;  [rsp+4] == total width of labels (summed)
	;  [rsp+8] == max height of labels
	; [rsp+12] == total height of labels (summed)
	; [rsp+16] == max width of inputs
	; [rsp+20] == total width of inputs (summed)
	; [rsp+24] == max height of inputs
	; [rsp+28] == total height of inputs (summed)
	; now we need to do the same for buttons
	cmp	qword [rbx+tui_form_buttonrow_ofs], 0
	je	.nobuttons
	mov	rdi, [rbx+tui_form_buttonrow_ofs]
	mov	rsi, .dims
	lea	rdx, [rsp+32]
	mov	rdi, [rdi+tui_children_ofs]
	call	list$foreach_arg
calign
.nobuttons:
	; [rsp+32] == max width of each button
	; [rsp+36] == total width of buttons (summed)
	; [rsp+40] == max height of each button
	; [rsp+44] == total height of buttons (summed)

	; now we can set all our fixed-size container dimensions based on same
	; insidebox's total dimensions == max(max label width + max input width, total button width), max(total label height, total input height) + max button height
	mov	rdi, [rbx+tui_form_insidebox_ofs]
	mov	esi, [rsp]
	add	esi, [rsp+16]
	mov	edx, [rsp+12]
	mov	ecx, [rsp+36]
	cmp	esi, ecx
	cmovb	esi, ecx
	mov	ecx, [rsp+28]
	cmp	edx, ecx
	cmovb	edx, ecx
	add	edx, [rsp+40]
	mov	[rdi+tui_width_ofs], esi
	mov	[rdi+tui_height_ofs], edx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsizechanged]
	cmp	qword [rbx+tui_form_labelcolumn_ofs], 0
	je	.skipinputs
	; otherwise, set inputrow == insidebox's width, insidebox's height - max button height
	mov	r8, [rbx+tui_form_insidebox_ofs]
	mov	rdi, [rbx+tui_form_inputrow_ofs]
	mov	esi, [r8+tui_width_ofs]
	mov	edx, [r8+tui_height_ofs]
	sub	edx, [rsp+40]
	mov	[rdi+tui_width_ofs], esi
	mov	[rdi+tui_height_ofs], edx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsizechanged]
	; set labelcolumn dimensions to max label width, total label height
	mov	rdi, [rbx+tui_form_labelcolumn_ofs]
	mov	esi, [rsp]
	mov	edx, [rsp+12]
	mov	[rdi+tui_width_ofs], esi
	mov	[rdi+tui_height_ofs], edx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsizechanged]
	; do the same for input column	
	mov	rdi, [rbx+tui_form_inputcolumn_ofs]
	mov	esi, [rsp+16]
	mov	edx, [rsp+28]
	mov	[rdi+tui_width_ofs], esi
	mov	[rdi+tui_height_ofs], edx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsizechanged]
calign
.skipinputs:
	; if we have a buttonrow, set its width to our tui_form_insidebox_ofs's width, and its height to the max button height
	cmp	qword [rbx+tui_form_buttonrow_ofs], 0
	je	.skipbuttons
	mov	r8, [rbx+tui_form_insidebox_ofs]
	mov	rdi, [rbx+tui_form_buttonrow_ofs]
	mov	esi, [r8+tui_width_ofs]
	mov	edx, [rsp+40]
	mov	[rdi+tui_width_ofs], esi
	mov	[rdi+tui_height_ofs], edx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsizechanged]
calign
.skipbuttons:
	add	rsp, 48
	pop	rbx
	epilog
falign
.dims:
	; rdi == tui_object, rsi == pointer to 16 bytes worth of dimension goods that we need to update
	mov	edx, [rdi+tui_width_ofs]
	mov	ecx, [rdi+tui_height_ofs]
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	add	[rsi+8], edx
	add	[rsi+12], ecx
	cmp	edx, r8d
	cmova	r8d, edx
	cmp	ecx, r9d
	cmova	r9d, ecx
	mov	[rsi], r8d
	mov	[rsi+4], r9d
	ret

end if


if used tui_form$ontab | defined include_everything
	; single argument in rdi: our tui_form object
falign
tui_form$ontab:
	prolog	tui_form$ontab
	; make sure we have a focus object
	cmp	qword [rdi+tui_form_focus_ofs], 0
	je	.nothingtodo
	mov	rsi, [rdi+tui_form_focus_ofs]
	mov	rax, [rsi+_list_nextofs]
	or	rcx, [rsi+_list_prevofs]
	jz	.nothingtodo
	push	rdi rsi
	mov	rdi, [rsi+_list_valueofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rsi rdi
	mov	rsi, [rsi+_list_nextofs]
	test	rsi, rsi
	jnz	.nowrap
	mov	rdx, [rdi+tui_form_tablist_ofs]
	mov	rsi, [rdx+_list_first_ofs]
calign
.nowrap:
	mov	[rdi+tui_form_focus_ofs], rsi
	mov	rdi, [rsi+_list_valueofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_form$onshifttab | defined include_everything
	; single argument in rdi: our tui_form object
falign
tui_form$onshifttab:
	prolog	tui_form$onshifttab
	; make sure we have a focus object
	cmp	qword [rdi+tui_form_focus_ofs], 0
	je	.nothingtodo
	mov	rsi, [rdi+tui_form_focus_ofs]
	mov	rax, [rsi+_list_nextofs]
	or	rcx, [rsi+_list_prevofs]
	jz	.nothingtodo
	push	rdi rsi
	mov	rdi, [rsi+_list_valueofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rsi rdi
	mov	rsi, [rsi+_list_prevofs]
	test	rsi, rsi
	jnz	.nowrap
	mov	rdx, [rdi+tui_form_tablist_ofs]
	mov	rsi, [rdx+_list_last_ofs]
calign
.nowrap:
	mov	[rdi+tui_form_focus_ofs], rsi
	mov	rdi, [rsi+_list_valueofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nothingtodo:
	epilog

end if


if used tui_form$firekeyevent | defined include_everything
	; three arguments: rdi == our tui_form object, esi == key, edx == esc_key
falign
tui_form$firekeyevent:
	prolog	tui_form$firekeyevent
	; Burning Purpose: some tui input components do actually fire ontab/onshifttab/etc
	; but due to the way we are dealing with tab order, we hijack them here
	cmp	qword [rdi+tui_form_focus_ofs], 0
	je	.normal
	cmp	esi, 9
	je	.tab
	cmp	edx, 0x5a
	je	.shifttab
	; otherwise, let tui_object's firekeyevent handle it
calign
.normal:
	call	tui_object$firekeyevent
	epilog
calign
.tab:
	mov	rcx, [rdi]
	call	qword [rcx+tui_vontab]
	mov	eax, 1		; handled
	epilog
calign
.shifttab:
	mov	rcx, [rdi]
	call	qword [rcx+tui_vonshifttab]
	mov	eax, 1		; handled
	epilog
	
end if
