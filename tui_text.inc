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
	; tui_text.inc: a more feature-filled text display/editor
	;
	; NOTE: this is by no means the most efficient way to do things...
	; for some _huge_ text, this would have to do a TON of work, but for all of my purposes
	; this is more than sufficient, and a relatively clean way of doing things
	; the "TON of work" comes in from the fact that I did individual objects for each
	; line of text, so if we were doing a 512MB text file, and then our component was
	; resized, it would have to recompose [the view of] each and every line...
	; this is in opposition to the "right way", which for huge text would be a fileshadow
	; of modifications to the underlying/initial text, and then viewport of visible-only
	; but of course that requires a _LOT_ more work and calculations and is generally more
	; difficult.
	; 
	; the line-by-line composed view still WORKS for huge data, and really isn't even that
	; bad for fixed-size tui-level dimensions on the component itself, but you'd definitely
	; notice my design choice with multi-million-line text and width-resizing events.
	;
	; for right aligned text combined with !wrap, I am not sure I entirely like the way this
	; ended up... while it does work and do what it should, the way the horizontal scrolling
	; works for non-fully-recomposed views is a bit "hmm"... the cursor gutter is weird, etc.
	; YMMV.
	;
	; for right aligned text with wrap enabled, I am forcing a 1 char gutter, mainly because
	; I am lazy and don't feel like doing all the extra work necessary to only enforce it for
	; the logical end of line... TODO: someday when I am bored or need that particular feature
	; hehe, fix it up.
	;
	; Further, while my design here perfectly allows for centered and justified composition
	; none of my collection requires them, so they are breakpointed and marked with TODOs for
	; someday when I am bored and have nothing better to do.
	;

if used tui_text$vtable | defined include_everything

dalign
tui_text$vtable:
	dq      tui_text$cleanup, tui_text$clone, tui_text$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_text$gotfocus, tui_text$lostfocus
	dq      tui_text$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_text$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; we add one method to our vtable for onenter handling
	dq      tui_text$onenter

end if

tui_vonenter = tui_vclicked + 8

tui_text_initial_ofs = tui_object_size			; string copy of the initial text, needed in case we have to clone ourselves
tui_text_colors_ofs = tui_object_size + 8
tui_text_focuscolors_ofs = tui_object_size + 12
tui_text_multiline_ofs = tui_object_size + 16		; bool as to whether we are a multiline or singleline editor (defaults to false)
tui_text_dospinner_ofs = tui_object_size + 20		; we delay creation of our spinner until we have valid bounds, bool here as to whether we fire one up or not
tui_text_focussed_ofs = tui_object_size + 24		; bool as to whether we have focus or not
tui_text_pwdchar_ofs = tui_object_size + 28		; !0 == display all characters as this
tui_text_minlen_ofs = tui_object_size + 32		; !0 == minimum editable scroll position in the editorline... NOTE: initial text must be at least this long if this is used
tui_text_maxlen_ofs = tui_object_size + 36		; !0 == max chars we'll take
tui_text_align_ofs = tui_object_size + 40		; one of: tui_textalign_{left,right} (defaults to left)
tui_text_wrap_ofs = tui_object_size + 44		; 0 == horiz scroll, 1 == hardwrap, 2 == wordwrap (defaults to 0)
tui_text_heightlock_ofs = tui_object_size + 48		; !0 == height gets locked to text, this value == minimum value (such that adding more text will cause height++, then layoutchanged)
							; note: heightlock doesn't make sense if you initialized it with a heightperc instead.
tui_text_editable_ofs = tui_object_size + 52		; bool as to whether we allow edits or not, defaults to true
tui_text_docursor_ofs = tui_object_size + 56		; bool as to whether we bother with the cursor at all, defaults to true
tui_text_spinner_ofs = tui_object_size + 60		; pointer to a tui_spinner if we created one
tui_text_lines_ofs = tui_object_size + 68		; a list$new of our editor lines (actual text, in buffers)
tui_text_viewlines_ofs = tui_object_size + 76		; a list$new of our view lines (1:1 or 1:many from lines, in buffers)
tui_text_cursormap_ofs = tui_object_size + 84		; a list$new of our cursor map (1:1 or 1:many from lines, in buffers)
tui_text_topline_ofs = tui_object_size + 92		; a pointer to the viewlines list _item_ (so we can walk it directly) of the topmost visible line
tui_text_bottomline_ofs = tui_object_size + 100		; "" bottommost
tui_text_cursorline_ofs = tui_object_size + 108		; a pointer to the cursormap list _item_ that our cursor is sitting on
tui_text_cursor_ofs = tui_object_size + 116		; the point for our "real" cursor window position (0,0..width,height) bounded, not editor position
tui_text_prevwidth_ofs = tui_object_size + 124		; used to determine whether we need to "recompose" ourselves when a draw event comes through
tui_text_prevheight_ofs = tui_object_size + 128		; used to determine whether we grew or shrank, so we can modify topline/bottomline intelligently
tui_text_cursorx_ofs = tui_object_size + 132		; this is our x offset in BYTES into our cursorline object
							; noting here, when cursorline itself gets modified, this needs to be revalidated, along with the cursor position itself
tui_text_xscroll_ofs = tui_object_size + 136		; if we are !wrap, this is the horizontal scroll offset in bytes
tui_text_user_ofs = tui_object_size + 140		; not used in here, an extra 8 bytes for outer layers to keep if they want

tui_text_size = tui_object_size + 148


	; as mentioned in my commentary atop, this isn't the most efficient design, as each line of editor text requires 3 separate buffers
	; and the code to keep track of it all any other way would be way too complicated for my tastes...


	; we have some non-virtual functions as well, see nvgettext, nvsettext

	; also note: if you want to enable multiline (disabled by default in the new_* functions)
	; just set the tui_text_multiline_ofs dword to nonzero after your call to new_*
	; same same for the other options, just makes it nicer for argument handling in the new_ functions

	; NOTE NOTE : if you modify settings after your call to new_*, _and_ you have non-empty initial text
	; you will _have_ to call nvsettingsupdate

if used tui_text$new_ii | defined include_everything
	; six arguments: edi == width, esi == height, rdx == initialtext (string, or null), ecx == colors, r8d == focuscolors, r9d == bool as to whether we fire up a spinner or not
falign
tui_text$new_ii:
	prolog	tui_text$new_ii
	sub	rsp, 40
	mov	[rsp], edi
	mov	[rsp+4], esi
	mov	[rsp+8], rdx
	mov	[rsp+16], ecx
	mov	[rsp+20], r8d
	mov	[rsp+24], r9d
	test	rdx, rdx
	jz	.noinitialtext
	mov	rdi, rdx
	call	string$copy
	mov	[rsp+8], rax
calign
.noinitialtext:
	mov	edi, tui_text_size
	call	heap$alloc_clear
	mov	[rsp+32], rax
	mov	rdi, rax
	mov	esi, [rsp]
	mov	edx, [rsp+4]
	call	tui_object$init_ii
	mov	rdi, [rsp+32]
	mov	rsi, [rsp+8]
	mov	edx, [rsp+16]
	mov	ecx, [rsp+20]
	mov	r8d, [rsp+24]
	mov	qword [rdi], tui_text$vtable
	mov	[rdi+tui_text_initial_ofs], rsi
	mov	[rdi+tui_text_colors_ofs], edx
	mov	[rdi+tui_text_focuscolors_ofs], ecx
	mov	[rdi+tui_text_dospinner_ofs], r8d
	call	tui_text$nvsetup

	mov	rax, [rsp+32]
	add	rsp, 40
	epilog

end if

if used tui_text$new_dd | defined include_everything
	; six arguments: xmm0 == widthperc, xmm1 == heighperc, rdi == initialtext (string, or null), esi == colors, edx == focuscolors, ecx == bool dospinner
falign
tui_text$new_dd:
	prolog	tui_text$new_dd
	sub	rsp, 40
	movq	r8, xmm0
	movq	r9, xmm1
	mov	[rsp], rdi
	mov	[rsp+8], esi
	mov	[rsp+12], edx
	mov	[rsp+16], ecx
	mov	[rsp+20], r8
	mov	[rsp+28], r9
	test	rdi, rdi
	jz	.noinitialtext
	call	string$copy
	mov	[rsp], rax
calign
.noinitialtext:
	mov	edi, tui_text_size
	call	heap$alloc_clear
	movq	xmm0, [rsp+20]
	movq	xmm1, [rsp+28]
	mov	[rsp+20], rax
	mov	rdi, rax
	call	tui_object$init_dd
	mov	rdi, [rsp+20]
	mov	rsi, [rsp]
	mov	edx, [rsp+8]
	mov	ecx, [rsp+12]
	mov	r8d, [rsp+16]
	mov	qword [rdi], tui_text$vtable
	mov	[rdi+tui_text_initial_ofs], rsi
	mov	[rdi+tui_text_colors_ofs], edx
	mov	[rdi+tui_text_focuscolors_ofs], ecx
	mov	[rdi+tui_text_dospinner_ofs], r8d
	call	tui_text$nvsetup
	mov	rax, [rsp+20]
	add	rsp, 40
	epilog

end if

if used tui_text$new_id | defined include_everything
	; six arguments: edi == width, xmm0 == heighperc, rsi == initialtext (string, or null), edx == colors, ecx == focuscolors, r8d == bool dospinner
falign
tui_text$new_id:
	prolog	tui_text$new_id
	sub	rsp, 40
	movq	r9, xmm0
	mov	[rsp], edi
	mov	[rsp+4], r9
	mov	[rsp+12], rsi
	mov	[rsp+20], edx
	mov	[rsp+24], ecx
	mov	[rsp+28], r8d
	test	rsi, rsi
	jz	.noinitialtext
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+12], rax
calign
.noinitialtext:
	mov	edi, tui_text_size
	call	heap$alloc_clear
	movq	xmm0, [rsp+4]
	mov	[rsp+4], rax
	mov	rdi, rax
	mov	esi, [rsp]
	call	tui_object$init_id
	mov	rdi, [rsp+4]
	mov	rsi, [rsp+12]
	mov	edx, [rsp+20]
	mov	ecx, [rsp+24]
	mov	r8d, [rsp+28]
	mov	qword [rdi], tui_text$vtable
	mov	[rdi+tui_text_initial_ofs], rsi
	mov	[rdi+tui_text_colors_ofs], edx
	mov	[rdi+tui_text_focuscolors_ofs], ecx
	mov	[rdi+tui_text_dospinner_ofs], r8d
	call	tui_text$nvsetup
	mov	rax, [rsp+4]
	add	rsp, 40
	epilog

end if

if used tui_text$new_di | defined include_everything
	; six arugments: xmm0 == widthperc, edi == height, rsi == initialtext (string, or null), edx == colors, ecx == focuscolors, r8d == bool dospinner
falign
tui_text$new_di:
	prolog	tui_text$new_di
	sub	rsp, 40
	movq	r9, xmm0
	mov	[rsp], edi
	mov	[rsp+4], r9
	mov	[rsp+12], rsi
	mov	[rsp+20], edx
	mov	[rsp+24], ecx
	mov	[rsp+28], r8d
	test	rsi, rsi
	jz	.noinitialtext
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+12], rax
calign
.noinitialtext:
	mov	edi, tui_text_size
	call	heap$alloc_clear
	movq	xmm0, [rsp+4]
	mov	[rsp+4], rax
	mov	rdi, rax
	mov	esi, [rsp]
	call	tui_object$init_di
	mov	rdi, [rsp+4]
	mov	rsi, [rsp+12]
	mov	edx, [rsp+20]
	mov	ecx, [rsp+24]
	mov	r8d, [rsp+28]
	mov	qword [rdi], tui_text$vtable
	mov	[rdi+tui_text_initial_ofs], rsi
	mov	[rdi+tui_text_colors_ofs], edx
	mov	[rdi+tui_text_focuscolors_ofs], ecx
	mov	[rdi+tui_text_dospinner_ofs], r8d
	call	tui_text$nvsetup
	mov	rax, [rsp+4]
	add	rsp, 40
	epilog

end if

if used tui_text$new_rect | defined include_everything
	; five arguments: rdi == pointer to a bounds rect, rsi == initialtext (string, or null), edx == colors, ecx == focuscolors, r8d == bool dospinner
falign
tui_text$new_rect:
	prolog	tui_text$new_rect
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], edx
	mov	[rsp+20], ecx
	mov	[rsp+24], r8d
	test	rsi, rsi
	jz	.noinitialtext
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+8], rax
calign
.noinitialtext:
	mov	edi, tui_text_size
	call	heap$alloc_clear
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	[rsp], rax
	call	tui_object$init_rect
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	edx, [rsp+16]
	mov	ecx, [rsp+20]
	mov	r8d, [rsp+24]
	mov	qword [rdi], tui_text$vtable
	mov	[rdi+tui_text_initial_ofs], rsi
	mov	[rdi+tui_text_colors_ofs], edx
	mov	[rdi+tui_text_focuscolors_ofs], ecx
	mov	[rdi+tui_text_dospinner_ofs], r8d
	call	tui_text$nvsetup
	mov	rax, [rsp]
	add	rsp, 40
	epilog

end if

if used tui_text$nvsetup | defined include_everything
	; single argument in rdi: the tui_text object we are setting up
falign
tui_text$nvsetup:
	prolog	tui_text$nvsetup
	push	rdi
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_text_viewlines_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_text_cursormap_ofs], rax
	call	list$new
	pop	rdi
	mov	[rdi+tui_text_lines_ofs], rax
	mov	dword [rdi+tui_text_editable_ofs], 1
	mov	dword [rdi+tui_text_docursor_ofs], 1
	mov	rsi, [rdi+tui_text_initial_ofs]
	test	rsi, rsi
	jz	.noinitialtext
	call	tui_text$nvsettext
	epilog
calign
.noinitialtext:
	; so that we have a valid editor and pointers, we need to set an empty string
	mov	rsi, .emptystr
	call	tui_text$nvsettext
	epilog
cleartext .emptystr, ''

end if



if used tui_text$nvcheckspinner | defined include_everything
	; single arugment in rdi: the tui_text object we are setting up
	; NOTE: this is only ever called from our draw method, and its only purpose is to delay
	; the creation/fireup of our spinner, as there is no sense in having a spinner/timer/update running
	; if we don't have valid bounds and/or are not-yet visible
falign
tui_text$nvcheckspinner:
	prolog	tui_text$nvcheckspinner
	cmp	dword [rdi+tui_text_dospinner_ofs], 0
	je	.nothingtodo
	cmp	qword [rdi+tui_text_spinner_ofs], 0
	jne	.nothingtodo
	push	rdi
	mov	edi, [rdi+tui_text_focuscolors_ofs]
	mov	esi, 75					; spinner speed
	call	tui_spinner$new
	pop	rdi
	mov	rsi, rax
	mov	[rdi+tui_text_spinner_ofs], rax
	mov	rdx, [rdi]
	mov	ecx, [rdi+tui_text_cursor_ofs]		; x is the lower 32 bits
	mov	r8d, [rdi+tui_text_cursor_ofs+4]	; y is the upper
	mov	[rsi+tui_absolutex_ofs], ecx
	mov	[rsi+tui_absolutey_ofs], r8d
	mov	eax, 0
	mov	ecx, 1
	cmp	dword [rdi+tui_text_focussed_ofs], 0
	cmovne	eax, ecx
	mov	[rsi+tui_visible_ofs], eax
	call	qword [rdx+tui_vappendbastard]
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_text$setcursor | defined include_everything
	; three arguments: rdi == our tui_text object, esi == x, edx == y
	; NOTE: if we have no spinner, this just calls tui_object$setcursor
	; otherwise, we set our bastard's absolutex/y to our cursor, only if they are different to our cursor
falign
tui_text$setcursor:
	prolog	tui_text$setcursor
	cmp	qword [rdi+tui_text_spinner_ofs], 0
	je	.parentonly
	mov	eax, [rdi+tui_text_cursor_ofs]
	mov	ecx, [rdi+tui_text_cursor_ofs+4]
	mov	r8, [rdi+tui_text_spinner_ofs]
	cmp	eax, [r8+tui_absolutex_ofs]
	jne	.spinupdate
	cmp	ecx, [r8+tui_absolutey_ofs]
	je	.parentonly
calign
.spinupdate:
	push	rdi rsi rdx
	mov	[r8+tui_absolutex_ofs], eax
	mov	[r8+tui_absolutey_ofs], ecx
	; we need to call the spinner's calcbounds
	mov	rdi, r8
	mov	rcx, [r8]
	call	qword [rcx+tui_vcalcbounds]
	pop	rdx rsi rdi
calign
.parentonly:
	call	tui_object$setcursor
	epilog

end if

if used tui_text$cleanup | defined include_everything
	; single argument in rdi: our tui_text object
falign
tui_text$cleanup:
	prolog	tui_text$cleanup
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+tui_text_lines_ofs]
	mov	rsi, .linedestroy
	call	list$clear
	mov	rdi, [rbx+tui_text_lines_ofs]
	call	heap$free
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, buffer$destroy
	call	list$clear
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	call	heap$free
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, buffer$destroy
	call	list$clear
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	call	heap$free
	mov	rdi, rbx
	call	tui_object$cleanup
	pop	rbx
	epilog
falign
.linedestroy:
	; called with rdi == our editor line entry, which is a buffer, but since we have two lists attached to it
	; we need to clear them as well
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+buffer_user_ofs+8]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rbx+buffer_user_ofs+8]
	call	heap$free
	mov	rdi, [rbx+buffer_user_ofs]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rbx+buffer_user_ofs]
	call	heap$free
	mov	rdi, rbx
	call	buffer$destroy
	pop	rbx
	ret


end if

if used tui_text$clone | defined include_everything
	; single argument in rdi: the tui_text object to clone
falign
tui_text$clone:
	prolog	tui_text$clone
	push	rbx r12
	mov	r12, rdi
	mov	edi, tui_text_size
	call	heap$alloc_clear
	mov	rcx, [r12]
	mov	rbx, rax
	mov	[rax], rcx
	mov	rdi, rax
	mov	rsi, r12
	call	tui_object$init_copy
	mov	rdi, [r12+tui_text_initial_ofs]
	call	string$copy
	mov	[rbx+tui_text_initial_ofs], rax
	mov	edi, [r12+tui_text_multiline_ofs]
	mov	esi, [r12+tui_text_pwdchar_ofs]
	mov	edx, [r12+tui_text_maxlen_ofs]
	mov	ecx, [r12+tui_text_align_ofs]
	mov	r8d, [r12+tui_text_wrap_ofs]
	mov	r9d, [r12+tui_text_heightlock_ofs]
	mov	r10d, [r12+tui_text_editable_ofs]
	mov	r11d, [r12+tui_text_docursor_ofs]
	mov	[rbx+tui_text_multiline_ofs], edi
	mov	[rbx+tui_text_pwdchar_ofs], esi
	mov	[rbx+tui_text_maxlen_ofs], edx
	mov	[rbx+tui_text_align_ofs], ecx
	mov	[rbx+tui_text_wrap_ofs], r8d
	mov	[rbx+tui_text_heightlock_ofs], r9d
	mov	[rbx+tui_text_editable_ofs], r10d
	mov	[rbx+tui_text_docursor_ofs], r11d
	mov	edi, [r12+tui_text_focussed_ofs]
	mov	esi, [r12+tui_text_colors_ofs]
	mov	edx, [r12+tui_text_focuscolors_ofs]
	mov	ecx, [r12+tui_text_dospinner_ofs]
	mov	r8d, [r12+tui_text_minlen_ofs]
	mov	[rbx+tui_text_focussed_ofs], edi
	mov	[rbx+tui_text_colors_ofs], esi
	mov	[rbx+tui_text_focuscolors_ofs], edx
	mov	[rbx+tui_text_dospinner_ofs], ecx
	mov	[rbx+tui_text_minlen_ofs], r8d
	
	call	list$new
	mov	[rbx+tui_text_viewlines_ofs], rax
	call	list$new
	mov	[rbx+tui_text_cursormap_ofs], rax
	call	list$new
	mov	[rbx+tui_text_lines_ofs], rax
	
	mov	rdi, rbx
	mov	rsi, [rbx+tui_text_initial_ofs]
	call	tui_text$nvsettext

	mov	rax, rbx
	pop	r12 rbx
	epilog
	
end if

if used tui_text$nvdocursor | defined include_everything
	; single argument in rdi: the tui_text object
	; this is called from gotfocus/lostfocus to update our actual cursor position
falign
tui_text$nvdocursor:
	prolog	tui_text$nvdocursor
	cmp	dword [rdi+tui_text_focussed_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_text_docursor_ofs], 0
	je	.nothingtodo

	mov	r11d, [rdi+tui_text_cursor_ofs]
	mov	r8d, [rdi+tui_text_cursor_ofs+4]
	
	; if we are _scrolled_, bounds.a will be way out of whack

	mov	esi, [rdi+tui_bounds_ax_ofs]
	add	esi, r11d
	mov	edx, [rdi+tui_bounds_ay_ofs]
	add	edx, r8d
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsetcursor]
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_text$draw | defined include_everything
	; single argument in rdi: our tui_text object
falign
tui_text$draw:
	prolog	tui_text$draw
	mov	eax, [rdi+tui_text_prevwidth_ofs]
	cmp	dword [rdi+tui_width_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_height_ofs], 0
	je	.nothingtodo
	push	rbx
	mov	rbx, rdi

	; make sure our cursor is where it belongs:
	; NOTE: while this does cause a lot of extra calls to setcursor, tui_render doesn't duplicate them
	; over the wire...
	call	tui_text$nvdocursor
	mov	rdi, rbx

	; update: blasted this somewhere along the lines
	mov	eax, [rbx+tui_text_prevwidth_ofs]

	; if our current width != our prevwidth, we need to compose ourselves
	cmp	eax, [rdi+tui_width_ofs]
	je	.skipcompose
	mov	ecx, [rdi+tui_width_ofs]
	mov	[rdi+tui_text_prevwidth_ofs], ecx
	call	tui_text$nvcompose
	; nvcompose sets/adjusts our topline/bottomline/cursorline
	mov	eax, [rbx+tui_height_ofs]
	mov	[rbx+tui_text_prevheight_ofs], eax
	cmp	dword [rbx+tui_text_heightlock_ofs], 0
	je	.skipheightchange
	mov	rdi, rbx
	call	tui_text$nvheightchange
	jmp	.skipheightchange
calign
.skipcompose:
	; if our height != our prevheight, we need to adjust topline/bottomline
	mov	eax, [rbx+tui_height_ofs]
	cmp	eax, [rbx+tui_text_prevheight_ofs]
	je	.skipheightchange
	mov	[rbx+tui_text_prevheight_ofs], eax
	mov	rdi, rbx
	call	tui_text$nvheightchange
calign
.skipheightchange:
	; check our spinner, prefill our attr/text
	mov	rdi, rbx
	call	tui_text$nvcheckspinner
	mov	eax, [rbx+tui_width_ofs]
	mov	rdi, [rbx+tui_attr_ofs]
	mul	dword [rbx+tui_height_ofs]
	mov	esi, [rbx+tui_text_colors_ofs]
	mov	ecx, [rbx+tui_text_focuscolors_ofs]
	shl	eax, 2
	cmp	dword [rbx+tui_text_focussed_ofs], 0
	cmovne	esi, ecx
	mov	edx, eax
	push	rax
	call	memset32
	mov	rdi, [rbx+tui_text_ofs]
	mov	esi, ' '
	pop	rdx
	call	memset32

	; so, our viewlines must contain valid goods, so from our topline to our bottom line, copy
	; each composed viewline into our text

	; now, from our topline to our bottomline inclusive, dump each composed
	; line straight into our tui_text_ofs buffer
	mov	rdi, [rbx+tui_text_topline_ofs]
	push	r12 r13
	mov	r12, [rbx+tui_text_ofs]
	mov	r13, rdi			; topline/bottomline point to the list item, not value
calign
.lineloop:
	; so now, our viewline buffer is at [r13]
	; copy tui_width*4 worth of bytes from this value into r12, update r12, keep going
	mov	rdi, r12
	mov	rsi, [r13]
	mov	ecx, [rbx+tui_text_xscroll_ofs]	; xscroll in bytes
	mov	edx, [rbx+tui_width_ofs]
	mov	r8d, [rsi+buffer_length_ofs]
	mov	rsi, [rsi+buffer_itself_ofs]
	shl	edx, 2
	add	r12, rdx
	add	rsi, rcx
	sub	r8d, ecx
	cmp	edx, r8d
	cmova	edx, r8d
	call	memcpy
	cmp	r13, [rbx+tui_text_bottomline_ofs]
	je	.lineloop_done
	mov	r13, [r13+_list_nextofs]
	test	r13, r13
	jnz	.lineloop
calign
.lineloop_done:
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	r13 r12 rbx
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_text$gotfocus | defined include_everything
	; single argument in rdi: our tui_text object
falign
tui_text$gotfocus:
	prolog	tui_text$gotfocus
	mov	dword [rdi+tui_text_focussed_ofs], 1
	push	rdi
	cmp	dword [rdi+tui_text_docursor_ofs], 0
	je	.skipshowcursor
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]
	mov	rdi, [rsp]
calign
.skipshowcursor:
	cmp	qword [rdi+tui_text_spinner_ofs], 0
	jne	.withspinner
	call	tui_text$nvdocursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	epilog
calign
.withspinner:
	call	tui_text$nvdocursor
	pop	rdi
	mov	rcx, [rdi+tui_text_spinner_ofs]
	mov	dword [rcx+tui_visible_ofs], 1
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	epilog

end if

if used tui_text$lostfocus | defined include_everything
	; single argument in rdi: our tui_text object
falign
tui_text$lostfocus:
	prolog	tui_text$lostfocus
	mov	dword [rdi+tui_text_focussed_ofs], 0
	push	rdi
	cmp	dword [rdi+tui_text_docursor_ofs], 0
	je	.skiphidecursor
	mov	rsi, [rdi]
	call	qword [rsi+tui_vhidecursor]
	mov	rdi, [rsp]
calign
.skiphidecursor:
	cmp	qword [rdi+tui_text_spinner_ofs], 0
	jne	.withspinner
	call	tui_text$nvdocursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	epilog
calign
.withspinner:
	call	tui_text$nvdocursor
	pop	rdi
	mov	rcx, [rdi+tui_text_spinner_ofs]
	mov	dword [rcx+tui_visible_ofs], 0
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	epilog

end if

if used tui_text$nvfindcursor | defined include_everything
	; three arguments: rdi == our tui_text object, rsi == editorline we are looking for, edx == new offset into the current editorline
falign
tui_text$nvfindcursor:
	prolog	tui_text$nvfindcursor
	; burning purpose: because a single keyevent can completely redo our view lines
	; we need to scan from the topline to the bottomline in our view until we find our editorline
	; this gives us our initial cursory position
	; then we can iterate that editorline's cursormap list, to find the correct cursory position
	; as well as the correct cursor x position
	;
	; very unpleasant logic, but is required nonetheless
	;
	xor	r8d, r8d			; our y counter
	mov	rcx, [rdi+tui_text_topline_ofs]
	;
	; so, it is possible that the topmost visible line is a partial view of the editor line it represents
	; meaning, more than one viewline exists, and the topline != its first line
	; in which case, we need to know precisely what the real offset is, or our cursor pos will be jacked
	cmp	qword [rcx+_list_prevofs], 0
	je	.firstsearch			; no prev == we are at the topline
	mov	r9, [rcx]			; the buffer at this list item
	mov	r10, [r9+buffer_user_ofs]	; the editorline it refers to
calign
.negoffset:
	mov	r11, [rcx+_list_prevofs]
	mov	rax, [r11]			; the buffer at the previous line
	cmp	r10, [rax+buffer_user_ofs]
	jne	.firstsearch
	; otherwise, it is equal
	sub	r8d, 1
	mov	rcx, r11
	cmp	qword [r11+_list_prevofs], 0
	jne	.negoffset

calign
.firstsearch:
	mov	r9, [rcx]			; the buffer at this list item
	cmp	rsi, qword [r9+buffer_user_ofs]
	je	.firstfound
	add	r8d, 1
	mov	rcx, [rcx+_list_nextofs]
	jmp	.firstsearch
calign
.firstfound:
	; if this editorline has no prev, _and_ minlen is nonzero, we have to validate the offset we are looking for
	cmp	dword [rdi+tui_text_minlen_ofs], 0
	je	.firstfound_nomincheck
	mov	rcx, [rsi+buffer_user_ofs+16]	; the editorline's list item
	cmp	qword [rcx+_list_prevofs], 0
	jne	.firstfound_nomincheck
	mov	r9d, [rdi+tui_text_minlen_ofs]
	shl	r9d, 2
	cmp	r9d, edx
	cmova	edx, r9d
calign
.firstfound_nomincheck:
	; so now, we found the first visible line that contains the right editor line
	; search that editor line's cursormap list until we find the offset we are looking for
	; we safely assume that the offset we are looking for _definitely_ exists somewhere in the list
	; the cursormap's buffer length is correct for whatever mode we are in

	; r9 is sitting on the viewline buffer that contains the right editorline
	; even though we already have the editor line sitting in rsi, the first search
	; was needed to determine its real/visible offset into our viewing window
	; so now that we have the offset of our editorline sitting in r8d, now we can traverse
	; its cursormap list, looking for our new offset
	mov	rcx, [rsi+buffer_user_ofs+8]	; its cursormap list, which contains list item pointers from the real cursormap list
	mov	rcx, [rcx+_list_first_ofs]
calign
.secondsearch:
	mov	r9, [rcx]			; the list item
	mov	r9, [r9]			; the cursormap buffer object itself
	mov	eax, [r9+buffer_length_ofs]
	mov	r10, [r9+buffer_itself_ofs]
	xor	r11d, r11d			; our x offset counter
calign
.linesearch:
	cmp	edx, dword [r10]
	je	.foundit
	add	r10, 4
	add	r11d, 1
	sub	eax, 4
	jnz	.linesearch
	; if we made it to here, we didn't find our offset on that line
	add	r8d, 1
	mov	rcx, [rcx+_list_nextofs]
	jmp	.secondsearch
calign
.foundit:
	mov	r9, [rcx]			; the list item
	mov	[rdi+tui_text_cursorline_ofs], r9
	mov	eax, r11d
	shl	eax, 2
	mov	[rdi+tui_text_cursorx_ofs], eax
	; so our "effective x/y" is sitting in r11d/r8d, set the cursor accordingly, adjusting xscroll as necessary
	cmp	r11d, [rdi+tui_width_ofs]
	jae	.xscroll
	mov	dword [rdi+tui_text_xscroll_ofs], 0
	mov	dword [rdi+tui_text_cursor_ofs], r11d
	mov	dword [rdi+tui_text_cursor_ofs+4], r8d

	cmp	dword [rdi+tui_text_focussed_ofs], 0
	je	.nocursor
	cmp	dword [rdi+tui_text_docursor_ofs], 0
	je	.nocursor
	
	mov	esi, [rdi+tui_bounds_ax_ofs]
	add	esi, r11d
	mov	edx, [rdi+tui_bounds_ay_ofs]
	add	edx, r8d
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsetcursor]
	epilog
calign
.nocursor:
	epilog
calign
.xscroll:
	; we are in nowrap mode, and we ran past the end of our line
	; so, our cursor can't hang off the end of our visible area
	; so at the very least, xscroll is 1 now
	; + the difference between r11d and our width
	mov	r10d, r11d
	mov	r9d, [rdi+tui_width_ofs]
	sub	r10d, [rdi+tui_width_ofs]
	add	r10d, 1
	sub	r9d, 1
	shl	r10d, 2
	mov	[rdi+tui_text_xscroll_ofs], r10d
	mov	dword [rdi+tui_text_cursor_ofs], r9d
	mov	dword [rdi+tui_text_cursor_ofs+4], r8d

	cmp	dword [rdi+tui_text_focussed_ofs], 0
	je	.nocursor
	cmp	dword [rdi+tui_text_docursor_ofs], 0
	je	.nocursor
	
	mov	esi, [rdi+tui_bounds_ax_ofs]
	add	esi, r9d
	mov	edx, [rdi+tui_bounds_ay_ofs]
	add	edx, r8d
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsetcursor]
	epilog

end if


if used tui_text$nvexpandby | defined include_everything
	; two arguments: rdi == our tui_text object, rsi == editor buffer to _exclude_, edx == count of chars to expand
falign
tui_text$nvexpandby:
	prolog	tui_text$nvexpandby
	; this is only called for !wrap, where we grew our buffer length, said growth resulted
	; in the overall size (maxx) being increased, and since we try NOT to do full recomposing
	; after every keystroke, this is required so that all the other viewlines and cursormaps
	; can be expanded without a full recompose
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12d, edx
	mov	rdx, [rdi+tui_text_viewlines_ofs]
	mov	rcx, [rdi+tui_text_cursormap_ofs]
	mov	r15, rsi
	mov	r13, [rdx+_list_first_ofs]
	mov	r14, [rcx+_list_first_ofs]
calign
.top:
	push	r13 r14
calign
.doit:
	; the value at [r13] and [r14] is each buffer 
	mov	rdi, [r13]
	cmp	r15, [rdi+buffer_user_ofs]		; its link back to the editorbuffer
	je	.excluded
	cmp	dword [rbx+tui_text_align_ofs], tui_textalign_right
	je	.rightaligned
	mov	esi, ' '
	call	buffer$append_dword
	mov	rdi, [r14]
	mov	esi, 0xffffffff
	call	buffer$append_dword
	mov	r13, [r13+_list_nextofs]
	mov	r14, [r14+_list_nextofs]
	test	r13, r13
	jnz	.doit
	pop	r14 r13
	sub	r12d, 1
	jnz	.top
	pop	r15 r14 r13 r12
	epilog
calign
.rightaligned:
	sub	rsp, 8
	mov	qword [rsp], ' '
	xor	esi, esi
	mov	rdx, rsp
	mov	ecx, 4
	call	buffer$insert
	mov	dword [rsp], 0
	mov	rdi, [r14]
	xor	esi, esi
	mov	rdx, rsp
	mov	ecx, 4
	call	buffer$insert
	add	rsp, 8
	mov	r13, [r13+_list_nextofs]
	mov	r14, [r14+_list_nextofs]
	test	r13, r13
	jnz	.doit
	pop	r14 r13
	sub	r12d, 1
	jnz	.top
	pop	r15 r14 r13 r12
	epilog
calign
.excluded:
	mov	r13, [r13+_list_nextofs]
	mov	r14, [r14+_list_nextofs]
	test	r13, r13
	jnz	.doit

	pop	r14 r13
	sub	r12d, 1
	jnz	.top
	pop	r15 r14 r13 r12 rbx
	epilog

end if

if used tui_text$nvdeleteline | defined include_everything
	; two arguments: rdi == our tui_text object, rsi == the editor line buffer that we are deleting
	; this takes "special handling" for in-place deletion without fully recomposing our entire linelist
falign
tui_text$nvdeleteline:
	prolog	tui_text$nvdeleteline

	; this is a wee-bit messy, we have to destroy each viewline and cursormap entry that belongs to us
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, [rsi+buffer_user_ofs]		; the viewline list for this editorline
	mov	r13, [r13+_list_first_ofs]
	; sanity only, TODO: remove me for production
	test	r13, r13
	jz	.nolines
calign
.viewloop:
	; so our editor buffer's viewline list is a list of items from the real viewline list
	; free the buffer, then list$remove the item from the tui_text_viewlines_ofs list
	mov	rdi, [r13]				; the item from the editorbuffer list
	mov	rdi, [rdi]				; the buffer
	call	buffer$destroy
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, [r13]
	call	list$remove
	mov	r13, [r13+_list_nextofs]
	test	r13, r13
	jnz	.viewloop
	mov	r13, [r12+buffer_user_ofs+8]		; the cursormap list for this editorline
	mov	r13, [r13+_list_first_ofs]
	; sanity only, TODO: remove me for production
	test	r13, r13
	jz	.nolines
calign
.cursorloop:
	mov	rdi, [r13]				; the item from the editorbuffer list
	mov	rdi, [rdi]				; the buffer
	call	buffer$destroy
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, [r13]
	call	list$remove
	mov	r13, [r13+_list_nextofs]
	test	r13, r13
	jnz	.cursorloop
calign
.nolines:
	; now we have to empty and free both our editorbuffer lists
	mov	rdi, [r12+buffer_user_ofs]
	xor	esi, esi
	call	list$clear
	mov	rdi, [r12+buffer_user_ofs]
	call	heap$free
	mov	rdi, [r12+buffer_user_ofs+8]
	xor	esi, esi
	call	list$clear
	mov	rdi, [r12+buffer_user_ofs+8]
	call	heap$free

	; last but not least, we need to remove ourselves from the real tui_text_lines_ofs list
	mov	rdi, [rbx+tui_text_lines_ofs]
	mov	rsi, [r12+buffer_user_ofs+16]
	call	list$remove
	; now we can off our buffer and be done with it
	mov	rdi, r12
	call	buffer$destroy
	pop	r13 r12 rbx
	epilog

end if



if used tui_text$keyevent | defined include_everything
	; three arguments: rdi == our tui_text object, esi == key, edx == esc_key
falign
tui_text$keyevent:
	prolog	tui_text$keyevent
	cmp	dword [rdi+tui_text_focussed_ofs], 0
	je	.falseret
	cmp	dword [rdi+tui_text_editable_ofs], 0
	je	.scrollcheck
	; otherwise, we are editable
	cmp	edx, 0x41			; up arrow
	je	.uparrow
	cmp	edx, 0x42			; down arrow
	je	.downarrow
	cmp	edx, 0x43			; right arrow
	je	.rightarrow
	cmp	edx, 0x46			; end, well, shift-end
	je	.shiftend
	cmp	edx, 0x44			; left arrow
	je	.leftarrow
	cmp	edx, 0x48			; home, well, shift-home
	je	.shifthome
	cmp	esi, 0x7f			; backspace
	je	.backspace
	cmp	edx, 0x33			; delete
	je	.delete
	cmp	esi, 9				; tab
	je	.tab
	cmp	edx, 0x5a			; shift-tab
	je	.shifttab
	cmp	esi, 13				; enter
	je	.cr
	cmp	esi, 32
	jb	.falseret
	; otherwise, pass the key to our editorline
	; so our cursorline is a list item pointer into the cursormap
	; and our cursorx is the offset in bytes into the cursormap itself
	; and the value at that cursormap position is the offset into the editor line
	; that we are ultimately inserting into

	mov	rdx, [rdi+tui_text_cursorline_ofs]	; item pointer into the cursormap list
	mov	rcx, [rdx]				; the actual cursormap buffer object
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rcx+buffer_itself_ofs]
	mov	r9d, [rax+r8]

	cmp	dword [rdi+tui_text_maxlen_ofs], 0
	je	.skiplengthcheck
	mov	eax, [rdi+tui_text_maxlen_ofs]
	mov	r10, [rcx+buffer_user_ofs]
	shl	eax, 2
	mov	r11d, [r10+buffer_length_ofs]
	cmp	r11d, eax
	jae	.falseret
calign
.skiplengthcheck:
	; save rdi and r9 prior to our insert, because we'll need them to update the rest of our goods
	push	rdi r9
	; also save the editorline that we are referencing so we can recompose it
	push	qword [rcx+buffer_user_ofs]

	; first order of business is inserting the dword esi into the buffer at the specified offset
	push	rsi
	mov	rdi, [rcx+buffer_user_ofs]		; the editorline that the cursormap buffer object references
	mov	rsi, r9					; the offset that we are inserting at
	mov	rdx, rsp
	mov	ecx, 4
	call	buffer$insert
	add	rsp, 8

	; if we are doing wrap, it is possible that our actual height may change, in which case
	; we'll need to call nvheightchange so it can redo our view
	mov	rsi, [rsp]
	mov	rcx, [rsi+buffer_user_ofs]		; its viewline list
	mov	rdi, [rsp+16]
	push	qword [rcx+_list_size_ofs]

	; next order of business is recomposing the editorline
	call	tui_text$nvcomposeline

	pop	rax
	mov	rsi, [rsp]
	mov	rdi, [rsp+16]
	mov	rcx, [rsi+buffer_user_ofs]		; its viewline list
	cmp	rax, [rcx+_list_size_ofs]
	je	.noheightchange
	
	call	tui_text$nvheightchange

calign
.noheightchange:
	; if !wrap, _and_ our editorbuffer's length is the same length as its first viewline, then that means
	; that the line we are on was responsible for a single character growth in width, in which case
	; all other viewlines/cursormaps need expanded by 1 as well
	mov	rsi, [rsp]
	mov	rdi, [rsp+16]
	cmp	dword [rdi+tui_text_wrap_ofs], 0
	jne	.noexpand

	mov	rdx, [rsi+buffer_length_ofs]

	mov	rcx, [rsi+buffer_user_ofs]		; its viewline list
	mov	rcx, [rcx+_list_first_ofs]		; viewline list first item, which is itself an item
	mov	rcx, [rcx]				; the real item
	mov	rcx, [rcx]				; the buffer of hte first viewline

	cmp	rdx, [rcx+buffer_length_ofs]
	jne	.noexpand
	; otherwise, we are doing a full expansion of viewlines and cursormaps
	; since we know our buffer grew by precisely one, and we know that our viewlines and cursormaps are 1:1
	; thanks to wrap being zero
	; all we have to do is pass our editor buffer to the expansion, and they can all grow by one
	mov	edx, 1
	call	tui_text$nvexpandby
calign
.noexpand:
	; last order of business is our cursor positions (all of them)
	; and in this case, we need to search for our new editorline offset (which is the insert position+4)
	; in our cursormap, and if it isn't on the current cursormap line, walk forward to the next til we find it
	; updating our real cursor position as we go

	; no matter what, our cursorx position got increased by four bytes
	pop	rsi rdx
	mov	rdi, [rsp]				; the editorline we are looking for
	add	rdx, 4					; the new offset (of the editorline)
	; so rsi is the offset that we inserted into, which we now need to _refind_ in the cursormap (because it got fully blasted)
	call	tui_text$nvfindcursor

	; last but not least, we need to issue a draw
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
	
calign
.uparrow:
	cmp	dword [rdi+tui_text_multiline_ofs], 0
	je	.falseret
	; see if cursorline has a prev, if not, falseret
	mov	rsi, [rdi+tui_text_cursorline_ofs]
	cmp	qword [rsi+_list_prevofs], 0
	je	.falseret
	;
	; some commentary on up/down arrow functionality... hahah
	;
	; this is not necessarily simple, because we let the cursor walk _through_ multiple viewlines
	; which may actually be the same editorline, or may not be
	; if the previous line is the same editorline object, then our mission is simple
	; if it is not the same editorline object, we have to move up one anyway, but validate the
	; cursorx position against the actual editorline object's valid offsets
	;
	; now, whether that makes SENSE or not, hahah, most unpleasant really
	; if we hit the up arrow from the middle of our line, and the line above us only has one
	; word, we need to snap the cursorx to the end of the buffer
	; but, if the position directly above us is _valid_, then it makes sense to actually cursor
	; directly to that position, such that cursorx snapping only happens when there IS no text
	; at the actual position, but deciding which way to snap will be tricky...
	;
	; realistically, it means that we are past the end of the text... for right-aligned, does
	; that mean we want to place the cursor at the end of the line? I think it does
	; so
	; that simplifies it a bit, whether that is the "right" thing to do or not from a human-interface
	; perspective, i dunno.. might have to come back and change that thinking a bit.
	; for left, center, and justified though, snapping to the end of the bufferline makes the most
	; sense, and ensures we have a valid cursor position.
	;
	; worst case for right-aligned, is we change it to snap to the "nearest" by walking cursorx right
	; instead of snapping to the end of the buffer line (which is "odd" movement for a cursor-up/dn)

	; we need to determine whether the cursorline is at the top, or bottom
	; and the only way to do that is to figure out which viewline corresponds to the current cursorline
	; fortunately, we won't have too many to iterate, since we can walk just the editor line's list
	; of viewlines and cursorlines together and stop when we find the cursorline

	mov	rdx, [rsi]				; the cursormap buffer itself
	mov	rcx, [rdx+buffer_user_ofs]		; the editor line buffer it is referencing
	; so now, we need to walk both lists til we find our cursormap
	mov	r8, [rcx+buffer_user_ofs]
	mov	r9, [rcx+buffer_user_ofs+8]
	; set those each to the first
	mov	r8, [r8+_list_first_ofs]
	mov	r9, [r9+_list_first_ofs]
calign
.uparrow_viewscan:
	; the value at this editorline's list is actually another item, so we need the value AT [r9]
	cmp	rsi, [r9]
	je	.uparrow_viewscan_done
	mov	r8, [r8+_list_nextofs]
	mov	r9, [r9+_list_nextofs]
	jmp	.uparrow_viewscan
calign
.uparrow_viewscan_done:
	mov	r8, [r8]
	mov	r9, [r9]
	; so now, based on what is in [r8], we should be able to tell if the cursorline is at the top and/or bottom
	; probably could have added other state variables to eliminate that loop, but since it is single-editor-line
	; traversal of that to viewlines only, the penalty really isn't that bad.
	mov	rsi, [rsi+_list_prevofs]
	mov	[rdi+tui_text_cursorline_ofs], rsi
	cmp	r8, [rdi+tui_text_topline_ofs]
	jne	.uparrow_notop
	; we were at the topline, so scroll up both topline and bottomline
	mov	r8, [r8+_list_prevofs]
	mov	[rdi+tui_text_topline_ofs], r8
	mov	r9, [rdi+tui_text_bottomline_ofs]
	mov	r9, [r9+_list_prevofs]
	mov	[rdi+tui_text_bottomline_ofs], r9
calign
.uparrow_notop:
	; so now, all we have left to do is validate cursorx
	; so first, pull the value out of the new cursormap buffer, to see if it is a -1
	mov	rdx, [rsi]				; the cursormap buffer itself (of the new cursor line
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rdx+buffer_itself_ofs]
	mov	r9d, [rax+r8]
	; r9d now contains the value inside the cursormap, if it is a -1 then we need to findcursor for the
	; end of the buffer it references, else, we do a findcursor for the value we are sitting at
	; which will position our cursor, as well as our spinner if any for us
	cmp	r9d, 0xffffffff
	je	.uparrow_bufpos
	push	rdi
	mov	rsi, [rdx+buffer_user_ofs]		; the editorline
	mov	edx, r9d				; the offset we want
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
calign
.uparrow_bufpos:
	push	rdi
	mov	rsi, [rdx+buffer_user_ofs]		; the editorline
	mov	rdx, [rsi+buffer_length_ofs]
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.downarrow:
	cmp	dword [rdi+tui_text_multiline_ofs], 0
	je	.falseret
	; see if cursorline has a next, if not, falseret
	mov	rsi, [rdi+tui_text_cursorline_ofs]
	cmp	qword [rsi+_list_nextofs], 0
	je	.falseret

	; basically the same thing as above for uparrow
	mov	rdx, [rsi]				; the cursormap buffer object itself
	mov	rcx, [rdx+buffer_user_ofs]		; the editor line buffer it is referencing

	mov	r8, [rcx+buffer_user_ofs]		; the editor line's viewline list
	mov	r9, [rcx+buffer_user_ofs+8]		; the editor line's cursormap list
	; set those each to the first
	mov	r8, [r8+_list_first_ofs]
	mov	r9, [r9+_list_first_ofs]
calign
.downarrow_viewscan:
	; the value at this editorline's list is actually another item, so we need the value AT [r9]
	cmp	rsi, [r9]
	je	.downarrow_viewscan_done
	mov	r8, [r8+_list_nextofs]
	mov	r9, [r9+_list_nextofs]
	jmp	.downarrow_viewscan
calign
.downarrow_viewscan_done:
	mov	r8, [r8]
	mov	r9, [r9]

	; move the cursorline itself down one
	mov	rsi, [rsi+_list_nextofs]
	mov	[rdi+tui_text_cursorline_ofs], rsi
	cmp	r8, [rdi+tui_text_bottomline_ofs]
	jne	.downarrow_nobottom
	; we were at the bottomline, so scroll down both topline and bottomline
	mov	r8, [r8+_list_nextofs]
	mov	[rdi+tui_text_bottomline_ofs], r8
	mov	r9, [rdi+tui_text_topline_ofs]
	mov	r9, [r9+_list_nextofs]
	mov	[rdi+tui_text_topline_ofs], r9
calign
.downarrow_nobottom:
	; so now, all we have left to do is validate cursorx
	; so first, pull the value out of the new cursormap buffer, to see if it is a -1
	mov	rdx, [rsi]				; the cursormap buffer itself (of the new cursor line
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rdx+buffer_itself_ofs]
	mov	r9d, [rax+r8]
	; r9d now contains the value inside the cursormap, if it is a -1 then we need to findcursor for the
	; end of the buffer it references, else, we do a findcursor for the value we are sitting at
	; which will position our cursor, as well as our spinner if any for us
	cmp	r9d, 0xffffffff
	je	.downarrow_bufpos
	push	rdi
	mov	rsi, [rdx+buffer_user_ofs]		; the editorline
	mov	edx, r9d				; the offset we want
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
calign
.downarrow_bufpos:
	push	rdi
	mov	rsi, [rdx+buffer_user_ofs]		; the editorline
	mov	rdx, [rsi+buffer_length_ofs]		; the offset we want
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
	

calign
.rightarrow:
	; this should take us right one character in our editorline, which may also cause scroll
	mov	rsi, [rdi+tui_text_cursorline_ofs]
	mov	rdx, [rsi]				; the cursormap buffer object itself
	mov	rcx, [rdx+buffer_user_ofs]		; the editor line buffer it is referencing
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rdx+buffer_itself_ofs]
	mov	r9d, [rax+r8]
	mov	r10, [rcx+buffer_length_ofs]
	; if r9d is equal to the editor line's buffer length, falseret
	cmp	r9, r10
	je	.falseret
	; otherwise, we can increment it by 4 and call findcursor
	add	r9d, 4
	push	rdi
	mov	rsi, rcx
	mov	edx, r9d
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.shiftend:
	; this should take us to the end of the real editorline, even if it spans multiple viewlines
	; which also means, findcursor may have to scroll in order to get it in view
	mov	rsi, [rdi+tui_text_cursorline_ofs]
	mov	rdx, [rsi]				; the cursormap buffer object itself
	mov	rcx, [rdx+buffer_user_ofs]		; the editor line buffer it is referencing
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rdx+buffer_itself_ofs]
	mov	r9d, [rax+r8]
	mov	r10, [rcx+buffer_length_ofs]
	push	rdi
	mov	rsi, rcx
	mov	edx, r10d
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
calign
.leftarrow:
	; this should take us left one character in our editorline, which may also cause scroll
	; regardless of whether cursorx is zero or not, we need to determine the editorline's offset
	; that it is pointing to, and check that _that_ is nonzero, then decrement it
	mov	rsi, [rdi+tui_text_cursorline_ofs]
	mov	rdx, [rsi]				; the cursormap buffer object itself
	mov	rcx, [rdx+buffer_user_ofs]		; the editor line buffer it is referencing
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rdx+buffer_itself_ofs]
	mov	r9d, [rax+r8]
	; if r9d is zero here, falseret
	test	r9d, r9d
	jz	.falseret
	; otherwise, we can decrement it by 4, and call findcursor
	sub	r9d, 4
	push	rdi
	mov	rsi, rcx
	mov	edx, r9d
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.shifthome:
	; this should take us to the beginning of the real editorline, even if it spans multiple viewlines
	; which also means, findcursor may have to scroll in order to get it in view
	mov	rsi, [rdi+tui_text_cursorline_ofs]
	mov	rdx, [rsi]				; the cursormap buffer object itself
	mov	rcx, [rdx+buffer_user_ofs]
	push	rdi
	mov	rsi, rcx
	xor	edx, edx
	call	tui_text$nvfindcursor
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.backspace_startofline:
	; if there is no previous line to our current one, do _nothing_
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, [rcx+buffer_user_ofs]
	; we need r12's tui_text_lines_ofs ITEM entry to determine whether we have a prev or not
	mov	rsi, [r12+buffer_user_ofs+16]
	cmp	qword [rsi+_list_prevofs], 0
	je	.backspace_startofline_bailout
	; otherwise, there _is_ a previous line... 
	mov	rsi, [rsi+_list_prevofs]
	mov	r13, [rsi]				; the previous editorline's buffer
	; so, first thing to determine is whether our current line is empty or not
	cmp	qword [r12+buffer_length_ofs], 0
	je	.backspace_startofline_nomove

	; before we modify r13, we need to know what its first viewline length is
	mov	rcx, [r13+buffer_user_ofs]		; its viewline list
	mov	rcx, [rcx+_list_first_ofs]		; the viewline list first item, which is itself an item
	mov	rcx, [rcx]				; the real item
	mov	rcx, [rcx]				; the buffer of the first viewline
	mov	r14, [rcx+buffer_length_ofs]

	; we have to copy the contents of our entire buffer onto the end of our previous buffer
	; and if wrap is zero, we may also have to expand every other line
	mov	rdi, r13
	mov	rsi, [r12+buffer_itself_ofs]
	mov	rdx, [r12+buffer_length_ofs]
	call	buffer$append
	; now, we need to recompose our previous editorline
	mov	rdi, rbx
	mov	rsi, r13
	call	tui_text$nvcomposeline
	; if wrap is nonzero, we don't need to worry about expansion
	cmp	dword [rbx+tui_text_wrap_ofs], 0
	jne	.backspace_startofline_nomove

	; further, if the length of our previous buffer is not equal to its first viewline length
	; we don't need to worry about expansion
	mov	rdx, [r13+buffer_length_ofs]
	mov	rcx, [r13+buffer_user_ofs]		; its viewline list
	mov	rcx, [rcx+_list_first_ofs]		; viewline list first item, which is itself an item
	mov	rcx, [rcx]				; the real item
	mov	rcx, [rcx]				; the buffer of hte first viewline
	cmp	rdx, [rcx+buffer_length_ofs]
	jne	.backspace_startofline_nomove
	; otherwise, we need to expando-matic

	; the # of characters to expand by is the difference between what it _was_ and what it is now

	mov	rdi, rbx
	mov	rsi, r13				; our exclude
	sub	rdx, r14
	shr	rdx, 2
	call	tui_text$nvexpandby
calign
.backspace_startofline_nomove:
	; there is nothing in our current line's buffer, or we fellthrough from above
	; there are several factors to consider here to make sure that findcursor will
	; not die a thousand deaths, and that our cursorline/topline/bottomline themselves
	; don't get invalidated by our completely deleting this editorline and associated
	; viewline(s) and cursormap(s)
	
	; the simple case, where topline/bottomline/cursorline ALL do not reference the line we are on
	; in which case we can just delete the line and be done with it
	; so, loadup each of the three and check
	mov	rdi, [rbx+tui_text_topline_ofs]
	mov	rsi, [rbx+tui_text_bottomline_ofs]
	mov	rdx, [rbx+tui_text_cursorline_ofs]
	
	; each of those are list items, so we need to dereference them one more time
	mov	r8, [rdi]
	mov	r9, [rsi]
	mov	r10, [rdx]
	
	; now, any those buffer_user_ofs is equal to r12, more difficult case
	cmp	r12, [r8+buffer_user_ofs]
	je	.backspace_startofline_topline
	cmp	r12, [r9+buffer_user_ofs]
	je	.backspace_startofline_bottomline
	cmp	r12, [r10+buffer_user_ofs]
	je	.backspace_startofline_cursorline
	; so this is the simple case fallthrough, none of them reference our editorline
calign
.backspace_startofline_dodelete:
	mov	rdi, rbx
	mov	rsi, r12
	call	tui_text$nvdeleteline
	mov	rdi, rbx
	call	tui_text$nvheightchange
	; last but not least, find our cursor
	mov	rdi, rbx
	mov	rsi, r13
	mov	rdx, [r13+buffer_length_ofs]
	call	tui_text$nvfindcursor
	; call our draw method
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	pop	r14 r13 r12 rbx
	mov	eax, 1
	epilog
calign
.backspace_startofline_topline:
	; so, we need to set topline to its previous item (cuz we know we have a previous one)
	mov	rdi, [rdi+_list_prevofs]
	mov	[rbx+tui_text_topline_ofs], rdi
	cmp	r12, [r9+buffer_user_ofs]
	je	.backspace_startofline_bottomline
	cmp	r12, [r10+buffer_user_ofs]
	je	.backspace_startofline_cursorline
	jmp	.backspace_startofline_dodelete
calign
.backspace_startofline_bottomline:
	; we need to set bottomline to its previous item
	mov	rsi, [rsi+_list_prevofs]
	mov	[rbx+tui_text_bottomline_ofs], rsi
	; see if we are the cursorline
	cmp	r12, [r10+buffer_user_ofs]
	jne	.backspace_startofline_dodelete
calign
.backspace_startofline_cursorline:
	; move the cursorline to its prev
	mov	rdx, [rdx+_list_prevofs]
	mov	[rbx+tui_text_cursorline_ofs], rdx
	jmp	.backspace_startofline_dodelete
calign
.backspace_startofline_bailout:
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.backspace:
	; there are quite a few scenarios here that need dealing with
	; if we are at 0 offset in our buffer, and there is no previous line, do nothing
	
	; if we are at 0 offset in our buffer, and there is a previous line:
	;    new cursor position is the previous line's length before we modify it
	;    if we have anything in our buffer, concatenate it all to the previous line, and delete our line
	;       noting that our concatenation might result in a global expansion by more than 1 character if !wrap
	;    if we don't have anything in our buffer, just delete our line
	; if we are not at 0 offset in our buffer, remove the character _before_ our offset, backup one spot
	;    and recompose

	mov	rdx, [rdi+tui_text_cursorline_ofs]	; item pointer into the cursormap list
	mov	rcx, [rdx]				; the actual cursormap buffer object
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rcx+buffer_itself_ofs]
	mov	r9d, [rax+r8]

	; the editorline we are interested in is at [rcx+buffer_user_ofs]
	test	r9d, r9d
	jz	.backspace_startofline

	; in case minlen is being used, we also need to determine whether they are at the minlen or not
	mov	r10d, [rdi+tui_text_minlen_ofs]
	shl	r10d, 2					; in bytes
	test	r10d, r10d
	jz	.backspace_nomincheck
	; in addition, our cursorline must have no prev
	cmp	qword [rdx+_list_prevofs], 0
	jne	.backspace_nomincheck
	cmp	r9d, r10d
	jbe	.falseret
calign
.backspace_nomincheck:

	; otherwise, we are not at the leftmost of our editorbuffer, simple case
	; where we just have to remove the character _before_ ours, and back up our cursorofs
	; recompose our line and be done

	; save rdi and r9 prior to our remove, because we'll need them to update the rest of our goods
	push	rdi r9
	; also save the editorline that we are referencing so we can recompose it
	push	qword [rcx+buffer_user_ofs]

	; first order of business is inserting the dword esi into the buffer at the specified offset
	mov	rdi, [rcx+buffer_user_ofs]		; the editorline that the cursormap buffer object references
	mov	rsi, r9					; the offset that we are removing from
	mov	edx, 4
	sub	rsi, 4
	call	buffer$remove

	mov	rsi, [rsp]
	mov	rcx, [rsi+buffer_user_ofs]		; its viewline list
	mov	rdi, [rsp+16]
	push	qword [rcx+_list_size_ofs]

	; next order of business is recomposing the editorline
	call	tui_text$nvcomposeline

	pop	rax

	mov	rsi, [rsp]
	mov	rdi, [rsp+16]
	mov	rcx, [rsi+buffer_user_ofs]		; its viewline list
	cmp	rax, [rcx+_list_size_ofs]
	je	.bs_noheightchange

	; [rsp] == editorline
	; [rsp+8] == r9
	; [rsp+16] == original rdi
	; because nvheightchange _also_ calls nvfindcursor, we need to modify it beforehand
	mov	rdx, [rsp+8]
	sub	rdx, 4
	call	tui_text$nvfindcursor

	mov	rsi, [rsp]
	mov	rdi, [rsp+16]
	
	call	tui_text$nvheightchange

calign
.bs_noheightchange:

	mov	rsi, [rsp]
	mov	rdi, [rsp+16]

	mov	rcx, [rsi+buffer_user_ofs]		; its viewline list
	mov	rcx, [rcx+_list_first_ofs]		; viewline list first item, which is itself an item
	mov	rcx, [rcx]				; the real item
	mov	rcx, [rcx]				; the buffer of hte first viewline

	; last order of business is our cursor positions (all of them)
	; and in this case, we need to search for our new editorline offset (which is the insert position+4)
	; in our cursormap, and if it isn't on the current cursormap line, walk forward to the next til we find it
	; updating our real cursor position as we go

	; no matter what, our cursorx position got decreased by four bytes
	pop	rsi rdx
	mov	rdi, [rsp]				; the editorline we are looking for
	sub	rdx, 4					; the new offset (of the editorline)
	; so rsi is the offset that we inserted into, which we now need to _refind_ in the cursormap (because it got fully blasted)
	call	tui_text$nvfindcursor

	; last but not least, we need to issue a draw
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.delete_endofline:
	; if there is no next line to our current one, do _nothing_
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rax
	mov	rsi, [r12+buffer_user_ofs+16]
	cmp	qword [rsi+_list_nextofs], 0
	je	.delete_endofline_bailout
	; otherwise, there is a next line
	mov	rsi, [rsi+_list_nextofs]
	mov	r13, [rsi]				; the next editorline's buffer
	mov	r14d, r9d				; save the current buffer length
	; deal with the simple case first, where the nextline is empty
	; and the reason we care, is because deleting the line below us doesn't change our linelength, cursor position, or anything
	cmp	qword [r13+buffer_length_ofs], 0
	je	.delete_endofline_nextline_empty
	; otherwise, we have to concat the next line to our current line, save our offset so we can refind our cursor after we recompose

	mov	rdi, r12
	mov	rsi, [r13+buffer_itself_ofs]
	mov	rdx, [r13+buffer_length_ofs]
	call	buffer$append

	; we can now recompose our current line
	mov	rdi, rbx
	mov	rsi, r12
	call	tui_text$nvcomposeline

	; further, if the length of our previous buffer is not equal to its first viewline length
	; we don't need to worry about expansion
	mov	rdx, [r12+buffer_length_ofs]
	mov	rcx, [r12+buffer_user_ofs]		; its viewline list
	mov	rcx, [rcx+_list_first_ofs]		; viewline list first item, which is itself an item
	mov	rcx, [rcx]				; the real item
	mov	rcx, [rcx]				; the buffer of hte first viewline
	cmp	rdx, [rcx+buffer_length_ofs]
	jne	.delete_endofline_nomove
	; otherwise, we need to expando-matic

	; the # of characters to expand by is the difference between what it _was_ and what it is now

	mov	rdi, rbx
	mov	rsi, r12				; our exclude
	sub	rdx, r14
	shr	rdx, 2
	call	tui_text$nvexpandby
calign
.delete_endofline_nomove:

	; delete the next line
	mov	rdi, rbx
	mov	rsi, r13
	call	tui_text$nvdeleteline

	mov	rdi, rbx
	call	tui_text$nvheightchange
	
	mov	rdi, rbx
	mov	rsi, r12
	mov	edx, r14d
	call	tui_text$nvfindcursor
	
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	
	pop	r14 r13 r12 rbx
	mov	eax, 1
	epilog

calign
.delete_endofline_nextline_empty:
	; simpler case:
	mov	rdi, rbx
	mov	rsi, r13
	call	tui_text$nvdeleteline
	
	mov	rdi, rbx
	call	tui_text$nvheightchange

	mov	rdi, rbx
	mov	rsi, r12
	mov	edx, r14d
	call	tui_text$nvfindcursor
	
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]

	pop	r14 r13 r12 rbx
	mov	eax, 1
	epilog

calign
.delete_endofline_bailout:
	pop	r14 r13 r12 rbx
	xor	eax, eax
	epilog
calign
.delete:
	; similar to backspace, there are several scenarios here that need dealing with
	; if we are at the end of our buffer, and there is no next line, do nothing

	; if we are at the end of our buffer, and there is a next line:
	;   cursor position doesn't change
	;   we concatenate the next line to our current line, and delete the next line
	;
	; if we are not at the end of our buffer, remove the character _at_ our offset and recompose

	mov	rdx, [rdi+tui_text_cursorline_ofs]	; item pointer into the cursormap list
	mov	rcx, [rdx]				; the actual cursormap buffer object
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rcx+buffer_itself_ofs]
	mov	r9d, [rax+r8]				; the editorline offset
	
	; the editorline we are sitting on is at [rcx+buffer_user_ofs]
	mov	rax, [rcx+buffer_user_ofs]
	cmp	r9, [rax+buffer_length_ofs]
	je	.delete_endofline

	; otherwise, we are not at the end of our buffer, simple case where we just have to
	; remove the character at the r9 position, and leave everything else alone
	push	rdi r9 rax
	mov	rdi, rax
	mov	rsi, r9
	mov	edx, 4
	call	buffer$remove

	; recompose the editorline
	mov	rsi, [rsp]
	mov	rdi, [rsp+16]				; our tui_text object
	call	tui_text$nvcomposeline

	; our cursor position did not change, BUT, recomposition may have screwed us all up
	; so we still need to find our cursor position
	pop	rsi rdx
	mov	rdi, [rsp]
	call	tui_text$nvfindcursor

	; last but not least, we need to issue a draw
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.tab:
	mov	rsi, [rdi]
	call	qword [rsi+tui_vontab]
	mov	eax, 1
	epilog

calign
.shifttab:
	mov	rsi, [rdi]
	call	qword [rsi+tui_vonshifttab]
	mov	eax, 1
	epilog

calign
.cr:
	cmp	dword [rdi+tui_text_multiline_ofs], 0
	jne	.cr_multiline
	mov	rsi, [rdi]
	call	qword [rsi+tui_vonenter]
	mov	eax, 1
	epilog
calign
.cr_multiline:
	; so, enter was pressed, we need to determine our offset into the current buffer
	; and see whether there is more data _after_ our cursor
	; and if there is, move it to our newline that we have to create and truncate the current one

	mov	rdx, [rdi+tui_text_cursorline_ofs]	; item pointer into the cursormap list
	mov	rcx, [rdx]				; the actual cursormap buffer object
	mov	r8d, [rdi+tui_text_cursorx_ofs]
	mov	rax, [rcx+buffer_itself_ofs]
	mov	r9d, [rax+r8]				; offset into the editorline from the cursormap location
	; deal with the simple case first
	; the editorline buffer is at [rcx+buffer_user_ofs]
	mov	r10, [rcx+buffer_user_ofs]
	; now, if r9 == its length, then no move is required
	cmp	r9, [r10+buffer_length_ofs]
	je	.cr_multiline_nomove

	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, r10
	mov	r14d, r9d			; the offset we were sitting on
	call	buffer$new
	mov	r13, rax
	call	list$new
	mov	[r13+buffer_user_ofs], rax
	call	list$new
	mov	[r13+buffer_user_ofs+8], rax
	mov	rdi, [rbx+tui_text_lines_ofs]
	mov	rsi, [r12+buffer_user_ofs+16]
	mov	rdx, r13
	call	list$insert_after
	mov	[r13+buffer_user_ofs+16], rax
	; so now, append from r14-r12.length to our new buffer, then truncate r12
	mov	rdi, r13
	mov	rsi, [r12+buffer_itself_ofs]
	mov	rdx, [r12+buffer_length_ofs]
	add	rsi, r14
	sub	rdx, r14
	call	buffer$append

	; now we have to compose our new line
	mov	rdi, rbx
	mov	rsi, r13
	call	tui_text$nvcomposeline
	; now we have to truncate r12 by the length of our r13 buffer
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r13+buffer_length_ofs]
	mov	rdx, [r12+buffer_length_ofs]
	sub	rdx, rsi
	mov	[r12+buffer_length_ofs], rdx
	add	rdi, rdx
	mov	[r12+buffer_endptr_ofs], rdi
	; now we need to recompose r12
	mov	rdi, rbx
	mov	rsi, r12
	call	tui_text$nvcomposeline

	; our overall height obviously has changed, we need to revalidate our height
	mov	rdi, rbx
	call	tui_text$nvheightchange

	; so now, we should have a valid cursormap hanging off our new editorbuffer
	; we need to set cursorline to the first one in our list
	; and set cursorx and xscroll to 0
	mov	dword [rbx+tui_text_xscroll_ofs], 0
	mov	dword [rbx+tui_text_cursorx_ofs], 0
	mov	rdi, [r13+buffer_user_ofs+8]
	mov	rsi, [rdi+_list_first_ofs]
	; the value at rsi is the ITEM we want
	mov	rdx, [rsi]
	mov	[rbx+tui_text_cursorline_ofs], rdx
	; then call nvfindcursor
	mov	rdi, rbx
	mov	rsi, r13
	xor	edx, edx
	call	tui_text$nvfindcursor
	; then call draw
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]

	pop	r14 r13 r12 rbx
	mov	eax, 1
	epilog

calign
.cr_multiline_nomove:
	; cursor was at the end of the editorline, so we don't have to do any copying
	; so now, the pointer at [r10+buffer_user_ofs+16] is the list _item_ pointer in the editorline list
	; so we need to insert_after a new empty bufferline, and create our viewline and cursormap line
	; we can do that with a composeline of just the newline
	; save rdi and r10
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, r10
	call	buffer$new
	mov	r13, rax
	call	list$new
	mov	[r13+buffer_user_ofs], rax
	call	list$new
	mov	[r13+buffer_user_ofs+8], rax
	mov	rdi, [rbx+tui_text_lines_ofs]
	mov	rsi, [r12+buffer_user_ofs+16]
	mov	rdx, r13
	call	list$insert_after
	mov	[r13+buffer_user_ofs+16], rax
	; now we have to compose it
	mov	rdi, rbx
	mov	rsi, r13
	call	tui_text$nvcomposeline
	; our overall height obviously has changed, we need to revalidate our height
	mov	rdi, rbx
	call	tui_text$nvheightchange

	; so now, we should have a valid cursormap hanging off our new editorbuffer
	; we need to set cursorline to the first one in our list
	; and set cursorx and xscroll to 0
	mov	dword [rbx+tui_text_xscroll_ofs], 0
	mov	dword [rbx+tui_text_cursorx_ofs], 0
	mov	rdi, [r13+buffer_user_ofs+8]
	mov	rsi, [rdi+_list_first_ofs]
	; the value at rsi is the ITEM we want
	mov	rdx, [rsi]
	mov	[rbx+tui_text_cursorline_ofs], rdx
	; then call nvfindcursor
	mov	rdi, rbx
	mov	rsi, r13
	xor	edx, edx
	call	tui_text$nvfindcursor
	; then call draw
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]

	pop	r13 r12 rbx
	mov	eax, 1
	epilog

calign
.scrollcheck:
	; when we are not editable, if we have focus, we still may allow scrolling our text view
	breakpoint
calign
.trueret:
	mov	eax, 1
	epilog
calign
.falseret:
	xor	eax, eax
	epilog

end if


if used tui_text$onenter | defined include_everything
	; single argument in rdi: our tui_text object
	; default one here doesn't do anything
falign
tui_text$onenter:
	prolog	tui_text$onenter
	; donothing
	epilog

end if

if used tui_text$nvcomposeline | defined include_everything
	; two arguments: rdi == our tui_text object, rsi == editorline we are recomposing
	; this one is called from keyevent after we modify an editorline
	; so we have to figure out what kind of editor goods we are
	; and call the corresponding composer
falign
tui_text$nvcomposeline:
	prolog	tui_text$nvcomposeline
	mov	eax, [rdi+tui_text_align_ofs]
	xchg	rdi, rsi
	cmp	eax, tui_textalign_left
	je	.left
	cmp	eax, tui_textalign_center
	je	.center
	cmp	eax, tui_textalign_right
	je	.right
	call	tui_text$nvjustifiedcompose
	epilog
calign
.left:
	call	tui_text$nvleftcompose
	epilog
calign
.center:
	call	tui_text$nvcentercompose
	epilog
calign
.right:
	call	tui_text$nvrightcompose
	epilog

end if


if used tui_text$nvcompose | defined include_everything
	; single argument in rdi: our tui_text object
falign
tui_text$nvcompose:
	prolog	tui_text$nvcompose
	; burning purpose: our width changed, so we need to "recompose" all our viewlines
	; in addition to recomposing, we also need to take care to preserve (where possible) our topline/bottomline/cursorline offsets
	push	rbx r12 r13 r14
	mov	rbx, rdi
	xor	r12d, r12d			; if this is zero/null, we set everything up as initial
	cmp	qword [rdi+tui_text_topline_ofs], 0
	je	.nocursormap			; skip searching if we are doing the initial one

	; otherwise, we are doing a recompose of already visible goods, meaning, we have valid
	; viewlines and cursormaps, and valid cursorline

	; this obviously presents some complexities, due to the fact that the # of viewlines
	; may increase or decrease, and that all of them are getting blasted and redone
	
	; so, our burning requirement is: keep the cursor position glued to exactly where it is
	; in the editor lines, and "try our best" to keep the view looking similar to the way it
	; is before our resize.
	
	; we of course can't be accurate with that last bit, simply because our size may have
	; changed quite a bit, and there is no way to preserve exact scrolling/viewing lines/etc


	; first up: get the editor line buffer from the cursorline
	mov	rsi, [rdi+tui_text_cursorline_ofs]	; it is a list item
	mov	rdx, [rsi]				; and its value is a buffer
	mov	r12, [rdx+buffer_user_ofs]		; linkback to the editorline it references

	; next up: get the actual offset
	mov	r8d, [rdi+tui_text_cursorx_ofs]		; x position into the cursormap
	mov	rax, [rdx+buffer_itself_ofs]		; cursormap buffer
	mov	r13d, [rax+r8]				; the offset into the editorline
	
	; we need to know how many lines down from the top the cursormap was
	mov	rdx, [rdi+tui_text_topline_ofs]
	xor	r14d, r14d
	xor	eax, eax
calign
.topmost_findcursor:
	mov	r9, [rdx]
	cmp	r12, [r9+buffer_user_ofs]
	cmove	r14d, eax
	add	eax, 1
	cmp	rdx, [rdi+tui_text_bottomline_ofs]
	je	.nocursormap
	mov	rdx, [rdx+_list_nextofs]
	jmp	.topmost_findcursor

	; r12 == real editorline of the cursor
	; r13d == real editorline offset of the cursor
	; so now we have the # of lines down from the top that our cursor was at in r14d

calign
.nocursormap:
	; now we can blast both lists, recompose everything, and then re-establish
	; our bottom/cursor, as well as set our "real" cursor
	; in addition to blasting the viewlines and cursormap lists, we need to also
	; clear both of them hanging off each editor line
	mov	rdi, [rbx+tui_text_lines_ofs]
	mov	rsi, .lineclear
	call	list$foreach

	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, buffer$destroy
	call	list$clear
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, buffer$destroy
	call	list$clear
	mov	eax, [rbx+tui_text_align_ofs]
	mov	rsi, tui_text$nvleftcompose
	mov	rdx, rbx
	mov	r8, tui_text$nvcentercompose
	mov	r9, tui_text$nvrightcompose
	mov	r10, tui_text$nvjustifiedcompose
	cmp	eax, tui_textalign_center
	cmove	rsi, r8
	cmp	eax, tui_textalign_right
	cmove	rsi, r9
	cmp	eax, tui_textalign_justified
	cmove	rsi, r10
	mov	rdi, [rbx+tui_text_lines_ofs]
	call	list$foreach_arg

	; so now, we have fresh viewlines and cursormaps
	test	r12d, r12d
	jz	.initialvalues

	; first order of business: set topline and bottomline
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	[rbx+tui_text_topline_ofs], rsi
	mov	[rbx+tui_text_bottomline_ofs], rsi

	; save our topline item entry for later scanning:
	mov	r8, rsi
	mov	r9, rsi

	; next up: expand bottomline to accommodate our actual height, or end
	mov	ecx, [rbx+tui_height_ofs]
	sub	ecx, 1			; we already have one
	jz	.no_bottom_expansion	; special case for when we only have one line
calign
.bottom_expansion:
	cmp	qword [rsi+_list_nextofs], 0
	je	.no_bottom_expansion
	mov	rsi, [rsi+_list_nextofs]
	mov	[rbx+tui_text_bottomline_ofs], rsi
	sub	ecx, 1
	jnz	.bottom_expansion
calign
.no_bottom_expansion:
	; then, walk both forward until we have the right editorline in our visible area
	cmp	qword [rsi+_list_nextofs], 0
	je	.no_scrollforward	; skip walking if we can't walk forward anyway
	mov	r9, r8			; start at the top
	; otherwise, scan from top to bottom searching for the r12 editorbuffer, make sure we find it
calign
.cursor_search:
	mov	rcx, [r9]		; its value is a viewline buffer
	cmp	r12, [rcx+buffer_user_ofs]	; is this the cursor line?
	je	.no_scrollforward	; if we found it, let nvfindcursor do the deed for us
	cmp	r9, rsi
	je	.cursor_search_scroll
	mov	r9, [r9+_list_nextofs]
	jmp	.cursor_search
calign
.cursor_search_scroll:
	mov	r8, [r8+_list_nextofs]
	mov	rsi, [rsi+_list_nextofs]
	mov	[rbx+tui_text_topline_ofs], r8
	mov	[rbx+tui_text_bottomline_ofs], rsi
	jmp	.no_bottom_expansion
calign
.no_scrollforward:
	; then, call nvfindcursor to get the right spot
	mov	rdi, rbx
	mov	rsi, r12
	mov	edx, r13d
	call	tui_text$nvfindcursor

	; last but not least, the value in r14d was hte old # of visible lines down to the cursorline
	; leaving it here means the cursor will always be at/near the bottom in a resize event
	; which for my purposes is just fine... TODO: someday when I am bored, honour the linecount downward and adjust the scroll position

	pop	r14 r13 r12 rbx
	epilog


falign
.lineclear:
	; called with rdi == our editor line buffer object
	; all we need to do is clear both lists hanging off our object
	push	rdi
	mov	rdi, [rdi+buffer_user_ofs+8]
	xor	esi, esi
	call	list$clear
	pop	rdi
	xor	esi, esi
	mov	rdi, [rdi+buffer_user_ofs]
	call	list$clear
	ret
	


calign
.initialvalues:
	; no previous topline existed, so set our cursorline, cursoroffset, topline, bottomline, and our real cursor positions
	; all to their initial positions
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	[rbx+tui_text_bottomline_ofs], rsi
	mov	eax, [rbx+tui_height_ofs]
	mov	ecx, 1
	sub	eax, 1
	jz	.initialvalues_topgood
	cmp	qword [rsi+_list_prevofs], 0
	je	.initialvalues_topgood
calign
.initialvalues_topsearch:
	mov	rsi, [rsi+_list_prevofs]
	add	ecx, 1
	sub	eax, 1
	jz	.initialvalues_topgood
	cmp	qword [rsi+_list_prevofs], 0
	jne	.initialvalues_topsearch
calign
.initialvalues_topgood:
	mov	[rbx+tui_text_topline_ofs], rsi
	; ecx has how many viewlines we really have, which may or may not be our tui_height
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	[rbx+tui_text_cursorline_ofs], rsi
	; now we need to determine our real cursor x position (noting here that we may have to xscroll this)
	mov	r8, [rsi]			; the cursormap buffer
	mov	r9, [r8+buffer_itself_ofs]
	mov	r10, [r8+buffer_length_ofs]
	; we need to be able to compare the dword value with the length of the LINE buffer that it references
	; to determine the real x position
	mov	r11, [r8+buffer_user_ofs]	; the editor line buffer it references
	mov	r12, [r11+buffer_length_ofs]
	xor	edx, edx
calign
.initialvalues_xsearch:
	cmp	dword [r9+rdx*4], r12d
	je	.initialvalues_xfound
	add	edx, 1
	sub	r10d, 4
	jnz	.initialvalues_xsearch
calign
.initialvalues_xfound:
	; so now, edx == our "view based x modifier"
	; and ecx == how many lines we took up out of the height, aka our cursor y modifier
	; take one from ecx, since our scroll position is 0 based, not 1 based
	sub	ecx, 1

	; so, if edx >= width, we need to enable xscroll
	cmp	edx, [rbx+tui_width_ofs]
	jae	.initialvalues_xscroll

	mov	dword [rbx+tui_text_cursor_ofs], edx
	mov	dword [rbx+tui_text_cursor_ofs+4], ecx

	; we need to set our cursorx offset to edx in BYTES (this corresponds to the current cursorline pointer)
	mov	eax, edx
	shl	eax, 2
	mov	dword [rbx+tui_text_cursorx_ofs], eax

	cmp	dword [rbx+tui_text_focussed_ofs], 0
	je	.initialvalues_xsearch_nocursor
	cmp	dword [rbx+tui_text_docursor_ofs], 0
	je	.initialvalues_xsearch_nocursor
	
	mov	esi, [rbx+tui_bounds_ax_ofs]
	add	esi, edx
	mov	edx, [rbx+tui_bounds_ay_ofs]
	add	edx, ecx
	mov	rdi, rbx
	mov	rcx, [rbx]
	call	qword [rcx+tui_vsetcursor]
calign
.initialvalues_xsearch_nocursor:
	pop	r14 r13 r12 rbx
	epilog

calign
.initialvalues_xscroll:
	mov	r10d, edx
	mov	r9d, [rbx+tui_width_ofs]
	sub	r10d, [rbx+tui_width_ofs]
	add	r10d, 1
	sub	r9d, 1
	shl	r10d, 2

	mov	[rbx+tui_text_xscroll_ofs], r10d

	mov	dword [rbx+tui_text_cursor_ofs], r9d
	
	; copy of the above
	mov	dword [rbx+tui_text_cursor_ofs+4], ecx

	; we need to set our cursorx offset to edx in BYTES (this corresponds to the current cursorline pointer)
	mov	eax, edx
	shl	eax, 2
	mov	dword [rbx+tui_text_cursorx_ofs], eax

	cmp	dword [rbx+tui_text_focussed_ofs], 0
	je	.initialvalues_xsearch_nocursor
	cmp	dword [rbx+tui_text_docursor_ofs], 0
	je	.initialvalues_xsearch_nocursor
	
	mov	esi, [rbx+tui_bounds_ax_ofs]
	add	esi, edx
	mov	edx, [rbx+tui_bounds_ay_ofs]
	add	edx, ecx
	mov	rdi, rbx
	mov	rcx, [rbx]
	call	qword [rcx+tui_vsetcursor]

	pop	r14 r13 r12 rbx
	epilog




end if


	; some notes here on our various compose methods...
	;
	; since we support an editable dynamic layout, which is to say: non 1:1 underlying editor text to display text
	; we have to deal with several scenarios
	;
	; if our wrap is 0, aka horiz scroll, then our viewlines and cursormap contains a 1:1 ratio to the editor lines
	; and the width of each line is max(longest line length, tui_width)
	;
	; if our wrap is nonzero, either hardwrap or wordwrap, our viewlines and cursormap contains our tui_width's lines
	; however many are necessary to accommodate our editor line. Simple if hardwrap, highly variable otherwise.
	;
	; the cursor map is essential to maintain underlying editor sanity during wordwrap, justification, etc
	; whereby what ends up onscreen has nothign to do with the underlying editor (space/linefeed-wise)
	;
	; for example, if we are fully justifying text, and we add 6 spaces between words, a cursor position into any
	; of our 6 "contrived" spaces all point to the real editor line's single space offset, thus allowing sensible
	; editing and dynamic layout of on-the-fly text
	;
	; not really sure how the "bigboy" word processors do this same functionality, but I can't imagine there to be
	; very many different ways of skinning this particular cat.. haha
	;


if used tui_text$nvnewviewline | defined include_everything
	; three arguments: rdi == our tui_text object, rsi == editor line buffer object, rdx == previous viewline editor buffer object
	; NONSTANDARD RETURN: returns viewline buffer object in rax, cursormap buffer object in rdx, both reset/cleared

	; NOTE: this assumes that if rdx is nonzero, there _IS_ a previous entry (meaning: rdx really is already in the editor line's viewlist)
	;       the way this routine is called from the compose methods ensures this..
falign
tui_text$nvnewviewline:
	prolog	tui_text$nvnewviewline
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	; so the idea here is: if one of our compose methods got called "freshlike", then the two lists
	; hanging off our editor line buffer object will be empty, and we can just create two new buffers and return
	; if however, the compose method was called after an editor line modification, then we need to recompose
	; our viewlines/cursormap lines _in place_ (and in this way, after a keypress, the entirety of our linelist
	; doesn't need to be fully recomposed after every editor event)
	test	rdx, rdx
	jz	.noprev
	; otherwise, search through the editor lines entries, see above re: assumption, rdx _must_ exist in the list already
	; we need to walk forward in _both_ lists simultaneously, until we find rdx
	mov	rdi, [r12+buffer_user_ofs]
	mov	rsi, [r12+buffer_user_ofs+8]
	mov	rdi, [rdi+_list_first_ofs]
	mov	rsi, [rsi+_list_first_ofs]
calign
.searchloop:
	; the editor line entries contain list _item_ entries from the actual viewlist and cursormap lists in the tui_text object
	; which means: the value at [rdi] and [rsi] is actually itself another list ITEM
	mov	r8, [rdi]
	mov	r9, [rsi]
	; so now, the one we are looking for is at [r8]
	cmp	rdx, [r8]
	je	.foundit
	; otherwise, keep going
	; TODO: remove the following sanity check for production
	cmp	qword [rdi+_list_nextofs], 0
	je	.kakked
	mov	rdi, [rdi+_list_nextofs]
	mov	rsi, [rsi+_list_nextofs]
	jmp	.searchloop
calign
.kakked:
	breakpoint
calign
.foundit:
	; now, if there is no next, which is entirely possible, we create fresh ones and are done
	; if there is a next one, then we reset both buffers and return them

	; if we jump straight to .freshies, then our new line gets placed at the _end_ of the
	; tui_text's lists, but if we were editing a line in place, and our editing caused this
	; editor line to expand in linecount, then our newly created line would end up incorrectly
	; placed...

	cmp	qword [rdi+_list_nextofs], 0
	je	.freshies_insertorder


	; otherwise, move to the next spot for both lists
	mov	rdi, [rdi+_list_nextofs]
	mov	rsi, [rsi+_list_nextofs]
	mov	r8, [rdi]
	mov	r9, [rsi]
	; buffers are at [r8] and [r9]
	push	qword [r8]
	push	qword [r9]
	mov	rdi, [r8]
	call	buffer$reset
	mov	rdi, [rsp]
	call	buffer$reset
	pop	rdx rax r12 rbx
	epilog
calign
.noprev:
	; if our editor line's list is empty, create new ones and be done
	mov	rdx, [r12+buffer_user_ofs]
	mov	rcx, [r12+buffer_user_ofs+8]
	mov	r8, [rdx+_list_first_ofs]
	mov	r9, [rcx+_list_first_ofs]
	test	r8, r8
	jz	.freshies
	; otherwise, our return is the first from each list

	; so the values at [r8] and [r9] are the item from the tui_text list proper
	; and the values at those values again are the buffer objects
	mov	r8, [r8]
	mov	r9, [r9]				; the list items

	mov	rax, [r8]
	mov	rdx, [r9]				; the buffer objects

	push	rax rdx
	mov	rdi, rax
	call	buffer$reset
	mov	rdi, [rsp]
	call	buffer$reset

	pop	rdx rax
	epilog
calign
.freshies_insertorder:
	; if r8 has no next, go straight to normal freshies which adds us to the end
	cmp	qword [r8+_list_nextofs], 0
	je	.freshies
	; otherwise, our new entry has to occur for both lists in place, after r8 and r9 in the tui_text's
	; viewlines and cursormap list
	push	r13 r14
	mov	r13, r8
	mov	r14, r9
	call	buffer$new
	push	rax
	mov	[rax+buffer_user_ofs], r12			; backward link from the viewline buffer object to the editor line buffer
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, r13
	mov	rdx, rax
	call	list$insert_after
	mov	rsi, rax
	mov	rdi, [r12+buffer_user_ofs]
	call	list$push_back
	; do the same again for cursormap
	call	buffer$new
	push	rax
	mov	[rax+buffer_user_ofs], r12			; backward link from the viewline buffer object to the editor line buffer
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, r14
	mov	rdx, rax
	call	list$insert_after
	mov	rsi, rax
	mov	rdi, [r12+buffer_user_ofs+8]
	call	list$push_back
	pop	rdx rax r14 r13 r12 rbx
	epilog
calign
.freshies:

	;
	; two case scenarios here: 1) our editor buffer is the last of its kind
	; 2) our editor buffer is actually in the middle somewhere and has a next, in which case
	; we have to do insert_after instead of push_back to the tui_text_viewlines_ofs and tui_text_cursormap_ofs
	;
	mov	rax, [r12+buffer_user_ofs+16]			; its list item position
	cmp	qword [rax+_list_nextofs], 0
	jne	.freshies_insertbefore

calign
.freshies_doit:
	call	buffer$new
	push	rax		; save it for our return
	mov	[rax+buffer_user_ofs], r12			; backward link from the viewline buffer object to the editor line buffer
	; we add the actual buffer to the viewlines/cursormap list in our tui_text object, and then we add
	; the list _item_ itself to our editor line buffer's lists
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, rax
	call	list$push_back
	; list's last is what we need to insert into our editor line list
	mov	rsi, rax
	mov	rdi, [r12+buffer_user_ofs]
	call	list$push_back
	; do same again for the cursormap entry
	call	buffer$new
	push	rax		; save it for our return
	mov	[rax+buffer_user_ofs], r12			; backward link from the cursormap buffer object to the editor line buffer
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, rax
	call	list$push_back
	mov	rsi, rax
	mov	rdi, [r12+buffer_user_ofs+8]
	call	list$push_back

	pop	rdx rax r12 rbx
	epilog
calign
.freshies_insertbefore:
	; if our initial text contained multiple lines, it is possible that even though we had a
	; next editorbuffer, that it wasn't actually setup yet, so make sure it really does have one
	mov	rax, [rax+_list_nextofs]
	mov	rax, [rax]					; the editorbuffer line at the next spot
	mov	rcx, [rax+buffer_user_ofs]			; its viewline list
	cmp	qword [rcx+_list_first_ofs], 0
	je	.freshies_doit

	push	r13 r14
	; we need the first _item_ from the next editor buffer's viewlines list and cursormap list
	mov	rdx, [rax+buffer_user_ofs+8]			; its cursormap list
	mov	rcx, [rcx+_list_first_ofs]
	mov	rdx, [rdx+_list_first_ofs]
	mov	r13, [rcx]
	mov	r14, [rdx]

	call	buffer$new
	push	rax
	mov	[rax+buffer_user_ofs], r12			; backward link from the viewline buffer object to the editor line buffer
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, r13
	mov	rdx, rax
	call	list$insert_before
	mov	rsi, rax
	mov	rdi, [r12+buffer_user_ofs]
	call	list$push_back
	; do same again for the cursormap entry
	call	buffer$new
	push	rax
	mov	[rax+buffer_user_ofs], r12			; backward link from the cursormap buffer object to the editor line buffer
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, r14
	mov	rdx, rax
	call	list$insert_before
	mov	rsi, rax
	mov	rdi, [r12+buffer_user_ofs+8]
	call	list$push_back
	pop	rdx rax r14 r13 r12 rbx
	epilog

end if

if used tui_text$nvlastviewline | defined include_everything
	; three arguments: rdi == our tui_text object, rsi == editor line buffer object, rdx == previous viewline editor buffer object
	; this clears/truncates viewlines/cursormap entries (if any) that may exist _after_ rdx

	; similar to the newviewline, this assumes that rdx really is in the list
falign
tui_text$nvlastviewline:
	prolog	tui_text$nvlastviewline
	; and in line with the above, this makes sure that rdx is the _last_ line, and we'll remove viewlines/cursormap entries
	; that may have belonged to us before but no longer do now
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi

	; search through the editor lines entries, see above re: assumption, rdx _must_ exist in the list already
	; we need to walk forward in _both_ lists simultaneously, until we find rdx
	mov	rdi, [r12+buffer_user_ofs]
	mov	rsi, [r12+buffer_user_ofs+8]
	mov	rdi, [rdi+_list_first_ofs]
	mov	rsi, [rsi+_list_first_ofs]
calign
.searchloop:
	; the editor line entries contain list _item_ entries from the actual viewlist and cursormap lists in the tui_text object
	; which means: the value at [rdi] and [rsi] is actually itself another list ITEM
	mov	r8, [rdi]
	mov	r9, [rsi]
	; so now, the one we are looking for is at [r8]
	cmp	rdx, [r8]
	je	.foundit
	; otherwise, keep going
	; TODO: remove the following sanity check for production
	cmp	qword [rdi+_list_nextofs], 0
	je	.kakked
	mov	rdi, [rdi+_list_nextofs]
	mov	rsi, [rsi+_list_nextofs]
	jmp	.searchloop
calign
.kakked:
	breakpoint
calign
.foundit:
	; now, if there is no next, then we have nothing to do, as rdx already is the last one
	cmp	qword [rdi+_list_nextofs], 0
	je	.alldone

	; save rdi and rsi for our re-entry (they will remain valid after our list removals)
	push	rdi rsi
	
	; save the previous cursormap entry, in case we have to set cursorline to it
	mov	rax, rsi
	; otherwise, move to the next spot, we need to remove the next spot from BOTH lists for each viewline and cursormap
	mov	rdi, [rdi+_list_nextofs]
	mov	rsi, [rsi+_list_nextofs]

	; if the cursorline pointer for our tui_text object is pointing at rsi, set it to its previous value
	cmp	rsi, [rbx+tui_text_cursorline_ofs]
	jne	.notcursor
	mov	[rbx+tui_text_cursorline_ofs], rax
calign
.notcursor:
	; so [rdi] is now the list _item_ entry in the tui_text's viewline list
	; and [rsi] is the list _item_ entry in the tui_text's cursormap list
	mov	r8, [rdi]
	mov	r9, [rsi]
	; buffers are at [r8] and [r9]
	push	qword [r8]
	push	qword [r9]

	; so, not only do we need to destroy the buffers now on the stack, we have 4 list removes do do
	; rdi gets removed from [r12+buffer_user_ofs]
	; rsi gets removed from [r12+buffer_user_ofs+8]
	; r8 gets removed from [rbx+tui_text_viewlines_ofs]
	; r9 gets removed from [rbx+tui_text_cursormap_ofs]
	push	rdi rsi r8
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, r9
	call	list$remove
	pop	rsi
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	call	list$remove
	pop	rsi
	mov	rdi, [r12+buffer_user_ofs+8]
	call	list$remove
	pop	rsi
	mov	rdi, [r12+buffer_user_ofs]
	call	list$remove
	pop	rdi
	call	buffer$destroy
	pop	rdi
	call	buffer$destroy

	; restore rsi and rdi back to our "found rdx" position in the list, and go do it again
	pop	rsi rdi
	jmp	.foundit
calign
.alldone:
	pop	r12 rbx
	epilog

end if




if used tui_text$nvleftcompose | defined include_everything
	; two arguments: rdi == our editor line buffer object, rsi == tui_text object
falign
tui_text$nvleftcompose:
	prolog	tui_text$nvleftcompose


	; called with rdi == our editor line buffer, rsi == tui_text object
	push	rbp rbx r12 r13 r14 r15
	push	rsi					; one extra save of our tui_text object, since we blast rbx later
	mov	rbx, rsi
	mov	r12, rdi
	mov	rbp, [rdi+buffer_itself_ofs]
	mov	r13, [rdi+buffer_length_ofs]
	xor	r14d, r14d				; clear our previous viewline buffer object, needed for newviewline calls

	; for all methods of wrapping, we do not do "dangling valid cursor positions"
	; so if the last line is _full_ we create a new empty one with a single valid cursormap position
	
	cmp	dword [rsi+tui_text_wrap_ofs], 0
	je	.nowrap
	; else, hardwrap (1) or wordwrap (2), fixed viewlines to our tui width, minimum 1 line
calign
.wrap:
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvnewviewline
	mov	r14, rax
	mov	r15, rdx
	
	mov	rdi, rax
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$reserve
	mov	rdi, r14
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$append_nocopy
	mov	rdi, r15
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$append_nocopy
	mov	rdi, [r14+buffer_itself_ofs]
	mov	esi, ' '
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	call	memset32
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	call	memset32
	; r13d has our source text length in bytes
	mov	edx, [rbx+tui_width_ofs]
	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, rbp
	shl	edx, 2
	cmp	r13d, edx
	cmovb	edx, r13d
	; if there was less than a full line, we don't do wordwrap either
	jb	.wrap_nowordwrap

	; if there is still space left in the buffer _after_ edx bytes are consumed
	; and if wrap == 2, we need to attempt to wordwrap it to the next line
	; up to half our width we'll walk backward looking for a space
	cmp	dword [rbx+tui_text_wrap_ofs], 2
	jne	.wrap_nowordwrap
	mov	eax, r13d
	sub	eax, edx
	jz	.wrap_nowordwrap
	test	edx, edx
	jz	.wrap_nowordwrap		; sanity only
	; so, from a starting position of edx-4 backward for a maximum of half our width
	; we need to look for a space, if we make it backward for half our width
	; without finding a space, leave it alone and do hardwrap normally

	mov	r8d, [rbx+tui_width_ofs]
	shr	r8d, 1				; limit for our search
	mov	r9d, edx
	sub	r9d, 4				; search position relative to rsi
	test	r8d, r8d
	jz	.wrap_nowordwrap		; special case if we are ridiculously small
	test	r9d, r9d
	jz	.wrap_nowordwrap		; ""
calign
.wrap_wordwrap:
	cmp	dword [rsi+r9], 32		; split on space
	je	.wrap_wordwrap_chop
	cmp	dword [rsi+r9], '-'		; split on hyphens too
	sub	r9d, 4
	jz	.wrap_nowordwrap
	sub	r8d, 1
	jz	.wrap_nowordwrap
	jmp	.wrap_wordwrap
calign
.wrap_wordwrap_chop_pwdchar:
	mov	esi, [rbx+tui_text_pwdchar_ofs]
	call	memset32

	; populate the cursormap with our modified offset + the real offset
	mov	rax, rbp
	sub	rax, [r12+buffer_itself_ofs]

	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, [rsp]
	mov	rdx, [r15+buffer_length_ofs]
	add	esi, eax				; modified correct offset
	call	memset32

	pop	rdx
	mov	rdi, [r15+buffer_itself_ofs]
	jmp	.wrap_nowordwrap_doit
calign
.wrap_wordwrap_chop:
	; so we walked backward and found a space suitable for wordwrap
	; we can safely include the space on our line
	add	r9d, 4
	; r9d is now the correct length of our memcpy, but we also need to preserve it for afterthefact
	mov	edx, r9d
	push	r9

	cmp	dword [rbx+tui_text_pwdchar_ofs], 0
	jne	.wrap_wordwrap_chop_pwdchar
	call	memcpy
	
	; populate the cursormap with our modified offset + the real offset
	mov	rax, rbp
	sub	rax, [r12+buffer_itself_ofs]

	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, [rsp]
	mov	rdx, [r15+buffer_length_ofs]
	add	esi, eax				; modified correct offset
	call	memset32

	pop	rdx
	mov	rdi, [r15+buffer_itself_ofs]
	jmp	.wrap_nowordwrap_doit
.wrap_nowordwrap_pwdchar:
	mov	esi, [rbx+tui_text_pwdchar_ofs]
	call	memset32
	; populate our cursormap next, noting it is possible
	; we have a zero-length entry
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	cmp	r13d, edx
	cmovb	edx, r13d
	jmp	.wrap_nowordwrap_doit
calign
.wrap_nowordwrap:
	cmp	dword [rbx+tui_text_pwdchar_ofs], 0
	jne	.wrap_nowordwrap_pwdchar
	call	memcpy
	; populate our cursormap next, noting it is possible
	; we have a zero-length entry
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	cmp	r13d, edx
	cmovb	edx, r13d
calign
.wrap_nowordwrap_doit:
	; we need to determine our real offset into the source line, which is rbp - [r12+buffer_itself_ofs]
	mov	rax, rbp
	sub	rax, [r12+buffer_itself_ofs]
	xor	ecx, ecx
	; we can safely decrement r13d and increment rbp by edx at this stage
	sub	r13d, edx
	add	rbp, rdx
	test	edx, edx
	jz	.wrap_cursormap_done
calign
.wrap_cursormap:
	mov	[rdi+rcx], eax
	add	ecx, 4
	add	eax, 4
	sub	edx, 4
	jnz	.wrap_cursormap
calign
.wrap_cursormap_done:
	; if r13d is zero now, we have to add one more spot as a valid cursor position
	; _but_, r13d is zero and rcx == r15's buffer length, then we have a special case of adding an empty line
	test	r13d, r13d
	jnz	.wrap				; go back to the top and do it again if we still have more left
	; otherwise, we have exhaused our source line
	cmp	rcx, [r15+buffer_length_ofs]
	jne	.wrap_partial_last
	push	rax
	; otherwise, we need to add one more empty line
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvnewviewline
	mov	r14, rax
	mov	r15, rdx
	
	mov	rdi, rax
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$reserve
	mov	rdi, r14
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$append_nocopy
	mov	rdi, r15
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$append_nocopy
	mov	rdi, [r14+buffer_itself_ofs]
	mov	esi, ' '
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	call	memset32
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	call	memset32

	mov	rdi, [r15+buffer_itself_ofs]
	xor	ecx, ecx
	pop	rax
calign
.wrap_partial_last:
	mov	[rdi+rcx], eax				; last entry in the cursormap is a valid cursor position (dangling)
	; one last call to lastviewline
	pop	rdi
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvlastviewline
	; done, dusted
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.nowrap:
	; get our viewline buffer object and cursormap buffer object from newviewline
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvnewviewline
	mov	r14, rax
	mov	r15, rdx
	; cursormap has to be calculated, viewline needs ' ' fill + text copy
	mov	rdi, rbx
	call	tui_text$nvmaxx
	mov	ecx, [rbx+tui_width_ofs]
	cmp	eax, ecx
	cmovb	eax, ecx

	mov	r8d, [rbx+tui_text_pwdchar_ofs]
	push	r8
	
	; eax now contains the correct length of our viewline to add in characters
	mov	ebx, eax
	shl	ebx, 2
	mov	rdi, r14
	mov	esi, ebx
	call	buffer$reserve
	mov	rdi, r14
	mov	esi, ebx
	call	buffer$append_nocopy
	mov	rdi, [r14+buffer_itself_ofs]
	mov	esi, ' '
	mov	edx, ebx
	call	memset32
	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, [r12+buffer_itself_ofs]
	mov	edx, r13d
	pop	r8
	test	r8d, r8d
	jz	.nowrap_memcpy
	mov	esi, r8d
	call	memset32
	; viewline is done, cursormap is next
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$append_nocopy
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, ebx
	call	memset32
	push	r13					; save the length again for the finale
	; next up, loop to set our offset positions for our cursormap, noting that we take _byte_ offsets, not character offsets
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, r13d				; save the length of our source for the final placement
	xor	eax, eax
	test	r13d, r13d
	jz	.nowrap_cursormap_done
	jmp	.nowrap_cursormap
calign
.nowrap_memcpy:
	call	memcpy
	; viewline is done, cursormap is next
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$append_nocopy
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, ebx
	call	memset32
	push	r13					; save the length again for the finale
	; next up, loop to set our offset positions for our cursormap, noting that we take _byte_ offsets, not character offsets
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, r13d				; save the length of our source for the final placement
	xor	eax, eax
	test	r13d, r13d
	jz	.nowrap_cursormap_done
calign
.nowrap_cursormap:
	mov	[rdi+rax], eax
	add	eax, 4
	sub	r13d, 4
	jnz	.nowrap_cursormap
calign
.nowrap_cursormap_done:
	pop	r13
	; since we are not doing wrap, we set the last position off the end as a valid cursor position
	mov	rsi, [rsp]
	mov	[rdi+rax], edx				; last position off the end is a valid cursor position
	; one last call to lastviewline
	pop	rdi
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvlastviewline
	; done, dusted
	pop	r15 r14 r13 r12 rbx rbp
	epilog

end if




if used tui_text$nvrightcompose | defined include_everything
	; two arguments: rdi == our editor line buffer, rsi == tui_text object
falign
tui_text$nvrightcompose:
	prolog	tui_text$nvrightcompose
	push	rbp rbx r12 r13 r14 r15
	push	rsi					; one extra save of our tui_text object, since we blast rbx later
	mov	rbx, rsi
	mov	r12, rdi
	mov	rbp, [rdi+buffer_itself_ofs]
	mov	r13, [rdi+buffer_length_ofs]
	xor	r14d, r14d				; clear our previous viewline buffer object, needed for newviewline calls

	; for all methods of wrapping, we do not do "dangling valid cursor positions"
	; so if the last line is _full_ we create a new empty one with a single valid cursormap position
	
	cmp	dword [rsi+tui_text_wrap_ofs], 0
	je	.nowrap
	; else, hardwrap (1) or wordwrap (2), fixed viewlines to our tui width, minimum 1 line
calign
.wrap:
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvnewviewline
	mov	r14, rax
	mov	r15, rdx
	
	mov	rdi, rax
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$reserve
	mov	rdi, r14
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$append_nocopy
	mov	rdi, r15
	mov	esi, [rbx+tui_width_ofs]
	shl	esi, 2
	call	buffer$append_nocopy
	mov	rdi, [r14+buffer_itself_ofs]
	mov	esi, ' '
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	call	memset32
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, [rbx+tui_width_ofs]
	shl	edx, 2
	call	memset32
	; r13d has our source text length in bytes
	mov	edx, [rbx+tui_width_ofs]
	mov	rdi, [r14+buffer_itself_ofs]
	sub	edx, 1					; enforce our 1 char gutter for right-aligned
	mov	rsi, rbp
	shl	edx, 2
	cmp	r13d, edx
	cmovb	edx, r13d
	; if there was less than a full line, we don't do wordwrap either
	jb	.wrap_nowordwrap

	; if there is still space left in the buffer _after_ edx bytes are consumed
	; and if wrap == 2, we need to attempt to wordwrap it to the next line
	; up to half our width we'll walk backward looking for a space
	cmp	dword [rbx+tui_text_wrap_ofs], 2
	jne	.wrap_nowordwrap
	mov	eax, r13d
	sub	eax, edx
	jz	.wrap_nowordwrap
	test	edx, edx
	jz	.wrap_nowordwrap		; sanity only
	; so, from a starting position of edx-4 backward for a maximum of half our width
	; we need to look for a space, if we make it backward for half our width
	; without finding a space, leave it alone and do hardwrap normally

	mov	r8d, [rbx+tui_width_ofs]
	shr	r8d, 1				; limit for our search
	mov	r9d, edx
	sub	r9d, 4				; search position relative to rsi
	test	r8d, r8d
	jz	.wrap_nowordwrap		; special case if we are ridiculously small
	test	r9d, r9d
	jz	.wrap_nowordwrap		; ""
calign
.wrap_wordwrap:
	cmp	dword [rsi+r9], 32		; split on space
	je	.wrap_wordwrap_chop
	cmp	dword [rsi+r9], '-'		; split on hyphens too
	sub	r9d, 4
	jz	.wrap_nowordwrap
	sub	r8d, 1
	jz	.wrap_nowordwrap
	jmp	.wrap_wordwrap
calign
.wrap_wordwrap_chop_pwdchar:
	mov	esi, [rbx+tui_text_pwdchar_ofs]
	call	memset32
	
	; populate the cursormap with our modified offset + the real offset
	mov	rax, rbp
	sub	rax, [r12+buffer_itself_ofs]

	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, [rsp]
	mov	rdx, [r15+buffer_length_ofs]
	add	esi, eax				; modified correct offset
	call	memset32

	pop	rdx
	mov	rdi, [r15+buffer_itself_ofs]
	jmp	.wrap_nowordwrap_doit
calign
.wrap_wordwrap_chop:
	; so we walked backward and found a space suitable for wordwrap
	
	; we can safely include the space on our line
	; unlike left align, we don't add the space to _this_ line:  add	r9d, 4
	; r9d is now the correct length of our memcpy, but we also need to preserve it for afterthefact
	mov	edx, r9d

	; also unlike left align, we need to offset rdi
	mov	r10d, [r14+buffer_length_ofs]
	sub	r10d, edx
	sub	r10d, 4					; +1 for our forced gutter
	add	rdi, r10

	push	r9
	cmp	dword [rbx+tui_text_pwdchar_ofs], 0
	jne	.wrap_wordwrap_chop_pwdchar
	call	memcpy
	
	; populate the cursormap with our modified offset + the real offset
	mov	rax, rbp
	sub	rax, [r12+buffer_itself_ofs]

	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, [rsp]
	mov	rdx, [r15+buffer_length_ofs]
	add	esi, eax				; modified correct offset
	call	memset32

	pop	rdx
	mov	rdi, [r15+buffer_itself_ofs]
	jmp	.wrap_nowordwrap_doit
calign
.wrap_nowordwrap_pwdchar:
	mov	esi, [rbx+tui_text_pwdchar_ofs]
	call	memset32
	; populate our cursormap next, noting it is possible
	; we have a zero-length entry
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, [rbx+tui_width_ofs]
	sub	edx, 1
	shl	edx, 2
	cmp	r13d, edx
	cmovb	edx, r13d
	jmp	.wrap_nowordwrap_doit
calign
.wrap_nowordwrap:
	; also unlike left align, we need to offset rdi
	mov	r10d, [r14+buffer_length_ofs]
	sub	r10d, edx
	sub	r10d, 4					; +1 for our forced gutter
	add	rdi, r10

	cmp	dword [rbx+tui_text_pwdchar_ofs], 0
	jne	.wrap_nowordwrap_pwdchar

	call	memcpy
	; populate our cursormap next, noting it is possible
	; we have a zero-length entry
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, [rbx+tui_width_ofs]
	sub	edx, 1
	shl	edx, 2
	cmp	r13d, edx
	cmovb	edx, r13d
calign
.wrap_nowordwrap_doit:
	; we need to determine our real offset into the source line, which is rbp - [r12+buffer_itself_ofs]
	mov	rax, rbp
	sub	rax, [r12+buffer_itself_ofs]
	; for right aligned, we need to offset rcx by the difference in lengths

	mov	r11d, edx				; hangon to our actual bytes we did
	add	r11d, 4					; + 1 for our enforced gutter

	mov	ecx, [r15+buffer_length_ofs]
	sub	ecx, r11d

	; we can safely decrement r13d and increment rbp by edx at this stage
	sub	r13d, edx
	add	rbp, rdx
	test	edx, edx
	jz	.wrap_cursormap_done
calign
.wrap_cursormap:
	mov	[rdi+rcx], eax
	add	ecx, 4
	add	eax, 4
	sub	edx, 4
	jnz	.wrap_cursormap
calign
.wrap_cursormap_done:
	; if r13d is zero now, we have to add one more spot as a valid cursor position
	; _but_, r13d is zero and rcx == r15's buffer length, then we have a special case of adding an empty line
	test	r13d, r13d
	jnz	.wrap				; go back to the top and do it again if we still have more left
	; otherwise, we have exhaused our source line

	; because we have an enforced right gutter of 1 char, we don't need to add a separate line?
	jmp	.wrap_partial_last
calign
.wrap_partial_last:
	mov	[rdi+rcx], eax				; last entry in the cursormap is a valid cursor position (dangling)
	; one last call to lastviewline
	pop	rdi
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvlastviewline
	; done, dusted
	pop	r15 r14 r13 r12 rbx rbp
	epilog
calign
.nowrap_pwdchar:
	mov	esi, r8d
	call	memset32
	; viewline is done, cursormap is next
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$append_nocopy
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, ebx
	call	memset32
	push	r13					; save the length again for the finale
	; next up, loop to set our offset positions for our cursormap, noting that we take _byte_ offsets, not character offsets
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, r13d				; save the length of our source for the final placement

	mov	ecx, ebx
	sub	ecx, r13d

	xor	eax, eax
	test	r13d, r13d
	jz	.nowrap_cursormap_done
	jmp	.nowrap_cursormap
calign
.nowrap:
	; get our viewline buffer object and cursormap buffer object from newviewline
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvnewviewline
	mov	r14, rax
	mov	r15, rdx
	; cursormap has to be calculated, viewline needs ' ' fill + text copy
	mov	rdi, rbx
	call	tui_text$nvmaxx
	mov	ecx, [rbx+tui_width_ofs]
	cmp	eax, ecx
	cmovb	eax, ecx

	mov	r8d, [rbx+tui_text_pwdchar_ofs]
	push	r8
	
	; eax now contains the correct length of our viewline to add in characters
	mov	ebx, eax
	shl	ebx, 2
	mov	rdi, r14
	mov	esi, ebx
	call	buffer$reserve
	mov	rdi, r14
	mov	esi, ebx
	call	buffer$append_nocopy
	mov	rdi, [r14+buffer_itself_ofs]
	mov	esi, ' '
	mov	edx, ebx
	call	memset32
	mov	rdi, [r14+buffer_itself_ofs]
	mov	rsi, [r12+buffer_itself_ofs]
	mov	edx, r13d

	; right aligned == offset
	mov	r10d, ebx
	sub	r10d, edx
	add	rdi, r10

	pop	r8
	test	r8d, r8d
	jnz	.nowrap_pwdchar

	call	memcpy
	; viewline is done, cursormap is next
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$reserve
	mov	rdi, r15
	mov	esi, ebx
	add	esi, 4					; +1 for cursormap, so that we can find a dangling one, but only for .nowrap
	call	buffer$append_nocopy
	mov	rdi, [r15+buffer_itself_ofs]
	mov	esi, 0xffffffff
	mov	edx, ebx
	call	memset32
	push	r13					; save the length again for the finale
	; next up, loop to set our offset positions for our cursormap, noting that we take _byte_ offsets, not character offsets
	mov	rdi, [r15+buffer_itself_ofs]
	mov	edx, r13d				; save the length of our source for the final placement

	mov	ecx, ebx
	sub	ecx, r13d

	xor	eax, eax
	test	r13d, r13d
	jz	.nowrap_cursormap_done
calign
.nowrap_cursormap:
	mov	[rdi+rcx], eax
	add	ecx, 4
	add	eax, 4
	sub	r13d, 4
	jnz	.nowrap_cursormap
calign
.nowrap_cursormap_done:
	pop	r13
	; since we are not doing wrap, we set the last position off the end as a valid cursor position
	mov	rsi, [rsp]
	mov	[rdi+rcx], edx				; last position off the end is a valid cursor position
	; one last call to lastviewline
	pop	rdi
	mov	rsi, r12
	mov	rdx, r14
	call	tui_text$nvlastviewline
	; done, dusted
	pop	r15 r14 r13 r12 rbx rbp
	epilog

end if





if used tui_text$nvcentercompose | defined include_everything
	; two arguments: rdi == our editor line buffer, rsi == tui_text object
falign
tui_text$nvcentercompose:
	prolog	tui_text$nvcentercompose
	breakpoint
	; TODO: someday when I am bored, see commentary atop
	epilog

end if

if used tui_text$nvjustifiedcompose | defined include_everything
	; two arguments: rdi == our editor line buffer, rsi == tui_text object
falign
tui_text$nvjustifiedcompose:
	prolog	tui_text$nvjustifiedcompose
	breakpoint
	; TODO: someday when I am bored, see commentary atop
	epilog

end if


if used tui_text$nvmaxx | defined include_everything
	; single argument in rdi: our tui_text object
	; returns the maximum width in characters in our lines list
falign
tui_text$nvmaxx:
	prolog	tui_text$nvmaxx
	xor	eax, eax
	mov	rdi, [rdi+tui_text_lines_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	test	rsi, rsi
	jz	.ret
calign
.iter:
	mov	rdx, [rsi+_list_valueofs]
	mov	r8, [rdx+buffer_length_ofs]
	shr	r8, 2
	cmp	r8, rax
	cmova	rax, r8
	mov	rsi, [rsi+_list_nextofs]
	test	rsi, rsi
	jnz	.iter
	epilog
calign
.ret:
	epilog

end if

if used tui_text$nvheightchange | defined include_everything
	; single argument in rdi: our tui_text object
	; 
	; height changed, we have to adjust our topline and/or bottomline
	; this occurs when either the actual tui_height changes, or during the course
	; of editing, our height has changed
	; in other words: we are responsible for keeping topline/bottomline correct
falign
tui_text$nvheightchange:
	prolog	tui_text$nvheightchange
	; ok so... there are quite a few possible scenarios here
	; if we have more visible lines than our tui_height, then we need to shrink either the top or the bottom
	; depending on where the cursor is
	;
	; if we have less visible lines than our tui_height, we need to make sure all our lines are indeed visible
	; (e.g. we expanded during editing, and bottomline didn't get modified to reflect new lines, which is
	; our job here)
	;
	; so first up, or viewlines list _size_ has the actual total count of lines
	; we need to walk from topline to bottomline to determine how many we think are visible
	; and our tui_height of course is valid
	;	
	; we need to know which "half" our cursorline is sitting in too, depending on how our size is changing
	; will determine which side we truncate/add lines to
	;
	push	rbx
	mov	rbx, rdi

	mov	rdi, [rdi+tui_text_viewlines_ofs]
	mov	esi, [rdi+_list_size_ofs]

	; deal with the first very simple case: if heightlock is selected, we need to change our
	; actual tui_height to match our list size in esi
	cmp	dword [rbx+tui_text_heightlock_ofs], 0
	jne	.firstlast_heightlock

	; deal with the second simple case first, if our viewline count is <= tui_height
	cmp	esi, [rbx+tui_height_ofs]
	jbe	.firstlast

	; otherwise, we have more viewlines than we do display area
	; we need to find the cursorline's editorobject as we walk the viewlines
	mov	rdx, [rbx+tui_text_cursorline_ofs]	; cursorline is a list item
	mov	rcx, [rdx]				; and its value is a buffer
	mov	r8, [rcx+buffer_user_ofs]		; link back ot the editorline it references

	xor	ecx, ecx				; we'll use this as the cursorline entry
	xor	eax, eax
	mov	rdi, [rbx+tui_text_topline_ofs]
calign
.countvisible:
	; rdi is a list item, whose value is a buffer with a linkback
	mov	r9, [rdi]				
	cmp	r8, [r9+buffer_user_ofs]
	cmove	ecx, eax
	add	eax, 1
	cmp	rdi, [rbx+tui_text_bottomline_ofs]
	je	.countvisible_done
	mov	rdi, [rdi+_list_nextofs]
	jmp	.countvisible
calign
.countvisible_done:
	; ok so, eax is our viscount, esi is our actual linecount
	; ecx is the index in our viscount of where the cursor is at
	
	; so if our viscount is the same as our height, then we scroll both values together
	; and the direction we choose is dependent on which half the cursor is in
	mov	rdi, [rbx+tui_text_topline_ofs]
	mov	rsi, [rbx+tui_text_bottomline_ofs]

	mov	r8d, [rbx+tui_height_ofs]
	shr	r8d, 1					; half our height for cursor half comparisons

	cmp	eax, [rbx+tui_height_ofs]
	je	.heightvismatch
	jb	.growing
	; so, our viscount is more than our actual height, we need to shrink our topline/bottomline list
	; and which end we chop depends on where the cursor is
	; if the cursor is in the tophalf, shrink the bottom (bottom->prev til viscount and height the same)
	; if the cursor is in the bottomhalf, shrink the top (top->next til viscount and height the same)
	
	sub	eax, [rbx+tui_height_ofs]		; the difference

	cmp	ecx, r8d
	jb	.shrinking_tophalf
	; else, cursor is mid or bottomhalf
calign
.shrinking_bottomhalf:
	mov	rdi, [rdi+_list_nextofs]
	sub	eax, 1
	jnz	.shrinking_bottomhalf
	mov	[rbx+tui_text_topline_ofs], rdi
	pop	rbx
	epilog
calign
.shrinking_tophalf:
	mov	rsi, [rsi+_list_prevofs]
	sub	eax, 1
	jnz	.shrinking_tophalf
	mov	[rbx+tui_text_bottomline_ofs], rsi
	pop	rbx
	epilog

calign
.growing:
	; our viscount is less than our actual height, we need to grow our topline/bottomline list
	; and which end we grow depends on where the cursor is
	; if the cursor is in the tophalf, grow the bottom (bottom->next til viscount and height the same)
	; if the cursor is in the bottomhalf, grow the top (top->prev til viscount and height the same)

	mov	edx, [rbx+tui_height_ofs]
	sub	edx, eax				; the difference
	
	cmp	ecx, r8d
	jb	.growing_tophalf
	; cursor is mid or bottomhalf, grow the top
calign
.growing_bottomhalf:
	mov	rdi, [rdi+_list_prevofs]
	sub	edx, 1
	jnz	.growing_bottomhalf
	mov	[rbx+tui_text_topline_ofs], rdi
	pop	rbx
	epilog
calign
.growing_tophalf:
	; grow hte bottom
	mov	rsi, [rsi+_list_nextofs]
	sub	edx, 1
	jnz	.growing_tophalf
	mov	[rbx+tui_text_bottomline_ofs], rsi
	pop	rbx
	epilog

calign
.heightvismatch:
	; viscount is the same as our tui_height, and our viewlines is > than our height
	; if the cursor is in the tophalf, and there is no topline prev, direction = next
	; if the cursor is in the bottomhalf, and there is no bottomline next, direction = prev
	cmp	ecx, r8d
	jb	.heightvismatch_tophalf
	; else, cursor is mid or lower, so, scroll "up", meaning, both topline and bottomline
	; move to their next position, only if bottomline has a next, otherwise, prev it is
	cmp	qword [rsi+_list_nextofs], 0
	je	.heightvismatch_doprev
calign
.heightvismatch_donext:
	mov	rdi, [rdi+_list_nextofs]
	mov	rsi, [rsi+_list_nextofs]
	mov	[rbx+tui_text_topline_ofs], rdi
	mov	[rbx+tui_text_bottomline_ofs], rsi
	pop	rbx
	epilog
calign
.heightvismatch_tophalf:
	; cursor is upper, so scroll "down", meaning, both topline and bottomline move to
	; their prev position, only if topline has a prev, otherwise, next it is
	cmp	qword [rdi+_list_prevofs], 0
	je	.heightvismatch_donext
calign
.heightvismatch_doprev:
	mov	rdi, [rdi+_list_prevofs]
	mov	rsi, [rsi+_list_prevofs]
	mov	[rbx+tui_text_topline_ofs], rdi
	mov	[rbx+tui_text_bottomline_ofs], rsi
	pop	rbx
	epilog
calign
.firstlast:
	; our viewline count is less than or equal to our tui_height, just brute force
	; topline and bottomline to our viewline list's first and last
	mov	rdx, [rdi+_list_first_ofs]
	mov	rcx, [rdi+_list_last_ofs]
	mov	[rbx+tui_text_topline_ofs], rdx
	mov	[rbx+tui_text_bottomline_ofs], rcx
	pop	rbx
	epilog
calign
.firstlast_heightlock:
	; set topline/bottomline to our first and last, set our tui_height to esi
	; and do the necessary updating indicating our layout has changed

	; Hmmmmm, this needs more consideration as to what exactly we need to do here..

	mov	dword [rbx+tui_text_prevheight_ofs], esi		; make sure it doesn't get called twice
	mov	rdx, [rdi+_list_first_ofs]
	mov	rcx, [rdi+_list_last_ofs]
	mov	[rbx+tui_text_topline_ofs], rdx
	mov	[rbx+tui_text_bottomline_ofs], rcx
	mov	dword [rbx+tui_height_ofs], esi
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vsizechanged]
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vcalcbounds]
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vlayoutchanged]
	pop	rbx
	epilog


end if


if used tui_text$nvgettext | defined include_everything
	; single argument in rdi: our tui_text object
	; returns a _new_ heap$alloc'd string representation of what is in the editor lines
falign
tui_text$nvgettext:
	prolog	tui_text$nvgettext
	cmp	dword [rdi+tui_text_multiline_ofs], 0
	je	.singleline
	mov	rdi, [rdi+tui_text_lines_ofs]
	; there is _always_ at least one editor line
	push	rbx r12
	mov	rbx, rdi
	call	buffer$new
	mov	r12, rax
	mov	rdi, rbx
	mov	rsi, .addline
	mov	rdx, rax
	call	list$foreach_arg
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r12+buffer_length_ofs]
	call	string$from_utf32
	mov	rdi, r12
	mov	r12, rax
	call	buffer$destroy
	mov	rax, r12
	pop	r12 rbx
	epilog
calign
.addline:
	; passed in rdi == our editor line buffer, rsi == the buffer we are to append it to
	xchg	rdi, rsi
	mov	rdx, [rsi+buffer_length_ofs]
	mov	rsi, [rsi+buffer_itself_ofs]
	push	rdi
	call	buffer$append
	pop	rdi
	mov	esi, 10
	call	buffer$append_dword
	ret
calign
.singleline:
	; the first line only, no trailing LF
	mov	rdi, [rdi+tui_text_lines_ofs]
	mov	rdi, [_list_first]
	mov	rdi, [rdi]			; the line buffer itself
	mov	rsi, [rdi+buffer_length_ofs]
	mov	rdi, [rdi+buffer_itself_ofs]
	call	string$from_utf32
	epilog

end if

if used tui_text$nvsettext | defined include_everything
	; two arguments: rdi == our tui_text object, rsi == string (noting we do not assume ownership or anything)
falign
tui_text$nvsettext:
	prolog	tui_text$nvsettext
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdi, [rdi+tui_text_lines_ofs]
	mov	rsi, .linedestroy
	call	list$clear
	mov	rdi, [rbx+tui_text_viewlines_ofs]
	mov	rsi, buffer$destroy
	call	list$clear
	mov	rdi, [rbx+tui_text_cursormap_ofs]
	mov	rsi, buffer$destroy
	call	list$clear
	; split our text by linefeeds, then create new buffers per line
	mov	rdi, r12
	mov	esi, 10
	call	string$split
	mov	r13, rax
	cmp	qword [rax+_list_size_ofs], 0
	je	.empty
	mov	rdi, rax
	mov	rsi, .addline
	mov	rdx, [rbx+tui_text_lines_ofs]
	call	list$foreach_arg
	mov	rdi, r13
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r13
	call	heap$free
	; clear topline/bottomline/cursorline, cursor, prev*, xscroll
	xor	ecx, ecx
	mov	[rbx+tui_text_topline_ofs], rcx
	mov	[rbx+tui_text_bottomline_ofs], rcx
	mov	[rbx+tui_text_cursorline_ofs], rcx
	mov	[rbx+tui_text_cursor_ofs], rcx
	mov	[rbx+tui_text_prevwidth_ofs], rcx	; includes prevheight as well
	mov	[rbx+tui_text_xscroll_ofs], ecx
	; last but not least, call our draw method
	; the draw method takes care of composition, and initial cursor positioning as well
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	
	pop	r13 r12 rbx
	epilog
calign
.empty:
	mov	rdi, r12
	mov	rsi, [rbx+tui_text_lines_ofs]
	call	.addline
	mov	rdi, r13
	call	heap$free
	; clear topline/bottomline/cursorline, cursor, prev*, xscroll
	xor	ecx, ecx
	mov	[rbx+tui_text_topline_ofs], rcx
	mov	[rbx+tui_text_bottomline_ofs], rcx
	mov	[rbx+tui_text_cursorline_ofs], rcx
	mov	[rbx+tui_text_cursor_ofs], rcx
	mov	[rbx+tui_text_prevwidth_ofs], rcx	; includes prevheight as well
	mov	[rbx+tui_text_xscroll_ofs], ecx
	; last but not least, call our draw method
	; the draw method takes care of composition, and initial cursor positioning as well
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	
	pop	r13 r12 rbx
	epilog

falign
.addline:
	; called with rdi == string, rsi == tui_text_lines_ofs list


	; the spot at our buffer's buffer_user_ofs+16 needs to be set to the list item itself, so they can be backreferenced
	; during newline/deleteline operations (without scanning for the editorline, etc)

	; because we decoupled the editor lines from the actual cursormap/viewlines (as we must, due to the way it all works)
	; we have to be able to, from a cursormap + editor line buffer entry all by itself, be able to get into the actual
	; editorlines list (but only when we hit enter, or backspace/delete a line altogether)

	push	rdi rsi
	call	buffer$new
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	[rsp], rax
	call	list$push_back
	; push_back returns us the list item pointer itself, which we need to toss into our buffer at buffer_user_ofs+16
	; now we have to toss our string at [rsp+8] into our buffer at [rsp]
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]

	mov	[rdi+buffer_user_ofs+16], rax		; see above commentary about why we have to do this
if string_bits = 32
	mov	rsi, [rsi]
	shl	rsi, 2
	push	rsi
	call	buffer$reserve
	pop	rdx
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	add	rsi, 8
	call	buffer$append
else
	; otherwise, we need to determine how many utf32 codepoints there are, which may not be the utf16 length
	mov	rdi, rsi
	call	string$utf32_length
	shl	rax, 2
	mov	rdi, [rsp]
	mov	rsi, rax
	push	rax
	call	buffer$reserve
	pop	rsi
	mov	rdi, [rsp]
	call	buffer$append_nocopy
	mov	rdi, [rsp+8]
	mov	rsi, [rsp]
	mov	rsi, [rsi+buffer_itself_ofs]
	call	string$to_utf32
end if
	; create two lists hanging off our buffer at [rsp], so each editor line can maintain a list
	; of which viewlines and cursormap entries belong to it
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+buffer_user_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+buffer_user_ofs+8], rax
	add	rsp, 16
	ret
falign
.linedestroy:
	; called with rdi == our editor line entry, which is a buffer, but since we have two lists attached to it
	; we need to clear them as well
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+buffer_user_ofs+8]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rbx+buffer_user_ofs+8]
	call	heap$free
	mov	rdi, [rbx+buffer_user_ofs]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rbx+buffer_user_ofs]
	call	heap$free
	mov	rdi, rbx
	call	buffer$destroy
	pop	rbx
	ret


end if


if used tui_text$nvsettingsupdate | defined include_everything
	; single argument in rdi: our tui_text object

	; burning purpose: see commentary atop, but restated here:
	; if, after you called tui_text$new_*, and you modified the default settings
	; _and_ you have non-empty initialtext, _and_ you have non-dynamic dimensions (fixed width/height)
	; then draw gets called once at time of new, but not again, so if your settings modify alignment, 
	; etc, then what you see before the first keypress or redraw is _not_ reflecting your settings
	; so, if you experience that, hehe, calling this will remedy it
falign
tui_text$nvsettingsupdate:
	prolog	tui_text$nvsettingsupdate
	mov	dword [rdi+tui_text_prevwidth_ofs], 0		; this forces a recomposition
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	epilog

end if
