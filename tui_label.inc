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
	; tui_label.inc: text displaying goods
	; ... basically a background with layout-aware text goodies, string based
	; ... deals with multiline, but is not particularly smart about it, nor editable
	;
	; if you want heavier text layout/editing/etc, see tui_text.inc
	;
	; uses list and string of course in addition to tui_background, tui_object
	;

	; NOTE: this requires string32 not string16 (makes things simpler due to our dd buffer sizing)
	; TODO: someday when I am bored, redo this to support UTF16 strings instead of 32bit
	;

if used tui_label$vtable | defined include_everything

if string_bits = 16
	display 'ERROR: tui_label requires strings_bits = 32 in settings'
	err
end if

dalign
tui_label$vtable:
        dq      tui_label$cleanup, tui_label$clone, tui_label$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
end if

tui_textalign_left = 0
tui_textalign_center = 1
tui_textalign_right = 2
tui_textalign_justified = 3				; not supported in tui_label, see tui_text if you want fancier goods

tui_label_filltext_ofs = tui_background_size
tui_label_textalign_ofs = tui_background_size + 8		; dd
tui_label_lines_ofs = tui_background_size + 16		; list of string
tui_label_highlightchar_ofs = tui_background_size + 24	; dd
tui_label_highlightcolor_ofs = tui_background_size + 32	; dd

tui_label_size = tui_background_size + 40


	; since this is rarely if-ever descended, we provide $new constructors
	; instead of $init based ones like tui_object

	; use tui_label$clone if you want a copy


	; NOTE: we do not assume ownership of filltext strings passed to us at new
	; we make a copy of it...

if used tui_label$new_ii | defined include_everything
	; five arguments: edi == width, esi == height, rdx == filltext (string), ecx == colors, r8d == text alignment
falign
tui_label$new_ii:
	prolog	tui_label$new_ii
	sub	rsp, 56
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	rdi, rdx
	call	string$copy
	mov	[rsp+16], rax		; copy of our string
	call	list$new
	mov	[rsp+40], rax
	mov	edi, tui_label_size
	call	heap$alloc
	mov	qword [rax], tui_label$vtable
	mov	[rsp+48], rax
	mov	rdi, rax
	mov	rsi, [rsp]		; width
	mov	rdx, [rsp+8]		; height
	mov	ecx, ' '		; fillchar
	mov	r8, [rsp+24]		; fillcolors
	call	tui_background$init_ii
	mov	rdi, [rsp+48]
	mov	rsi, [rsp+16]		; our filltext string
	mov	[rdi+tui_label_filltext_ofs], rsi
	mov	rsi, [rsp+40]		; first list
	mov	[rdi+tui_label_lines_ofs], rsi
	mov	rsi, [rsp+32]
	mov	[rdi+tui_label_textalign_ofs], rsi
	mov	qword [rdi+tui_label_highlightchar_ofs], 0
	mov	qword [rdi+tui_label_highlightcolor_ofs], 0
	call	tui_label$nvlineate
	mov	rax, [rsp+48]
	add	rsp, 56
	epilog
end if


if used tui_label$new_str | defined include_everything
	; three arguments: rdi == filltext (string), esi == colors, edx == text alignment
	; NOTE: this calculates teh required dimensions for the string and then passes it to new_ii
falign
tui_label$new_str:
	prolog	tui_label$new_str
	push	rdi rsi rdx
	mov	esi, 10
	call	string$split
	sub	rsp, 16
	mov	[rsp], rax
	mov	qword [rsp+8], 0
	mov	rdi, rax
	mov	rsi, .linelength
	lea	rdx, [rsp+8]
	call	list$foreach_arg
	; dword [rsp+8] == max line length
	; dword [rsp+12] == line count
	mov	rdi, [rsp]
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [rsp]
	call	heap$free
	mov	edi, [rsp+8]
	mov	esi, [rsp+12]
	add	rsp, 16
	pop	r8 rcx rdx
	call	tui_label$new_ii
	epilog
falign
.linelength:
	; rdi == string of this line, rsi == pointer that we need to udpate
	mov	eax, [rdi]
	mov	edx, [rsi]
	add	dword [rsi+4], 1
	cmp	eax, edx
	cmova	edx, eax
	mov	[rsi], edx
	ret

end if


if used tui_label$new_dd | defined include_everything
	; five arguments: xmm0 == width percent, xmm1 == height percent, rdi == filltext (string), esi == colors, edx == text alignment
falign
tui_label$new_dd:
	prolog	tui_label$new_dd
	sub	rsp, 56
	movq	[rsp], xmm0
	movq	[rsp+8], xmm1
	mov	[rsp+16], rdi
	mov	[rsp+24], rsi
	mov	[rsp+32], rdx
	call	string$copy
	mov	[rsp+16], rax		; copy of our string
	call	list$new
	mov	[rsp+40], rax
	mov	edi, tui_label_size
	call	heap$alloc
	mov	qword [rax], tui_label$vtable
	mov	[rsp+48], rax
	mov	rdi, rax
	movq	xmm0, [rsp]		; width percent
	movq	xmm1, [rsp+8]		; height percent
	mov	esi, ' '		; fillchar
	mov	rdx, [rsp+24]		; fillcolors
	call	tui_background$init_dd
	mov	rdi, [rsp+48]
	mov	rsi, [rsp+16]		; our filltext string
	mov	[rdi+tui_label_filltext_ofs], rsi
	mov	rsi, [rsp+40]		; first list
	mov	[rdi+tui_label_lines_ofs], rsi
	mov	rsi, [rsp+32]
	mov	[rdi+tui_label_textalign_ofs], rsi
	mov	qword [rdi+tui_label_highlightchar_ofs], 0
	mov	qword [rdi+tui_label_highlightcolor_ofs], 0
	call	tui_label$nvlineate
	mov	rax, [rsp+48]
	add	rsp, 56
	epilog
end if

if used tui_label$new_id | defined include_everything
	; five arguments: edi == width, xmm0 == height percent, rsi == filltext (string), edx == colors, ecx == text alignment
falign
tui_label$new_id:
	prolog	tui_label$new_id
	sub	rsp, 56
	mov	[rsp], rdi
	movq	[rsp+8], xmm0
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+16], rax		; copy of our string
	call	list$new
	mov	[rsp+40], rax
	mov	edi, tui_label_size
	call	heap$alloc
	mov	qword [rax], tui_label$vtable
	mov	[rsp+48], rax
	mov	rdi, rax
	mov	rsi, [rsp]		; width
	movq	xmm0, [rsp+8]		; height percent
	mov	edx, ' '		; fillchar
	mov	rcx, [rsp+24]
	call	tui_background$init_id
	mov	rdi, [rsp+48]
	mov	rsi, [rsp+16]		; our filltext string
	mov	[rdi+tui_label_filltext_ofs], rsi
	mov	rsi, [rsp+40]		; first list
	mov	[rdi+tui_label_lines_ofs], rsi
	mov	rsi, [rsp+32]
	mov	[rdi+tui_label_textalign_ofs], rsi
	mov	qword [rdi+tui_label_highlightchar_ofs], 0
	mov	qword [rdi+tui_label_highlightcolor_ofs], 0
	call	tui_label$nvlineate
	mov	rax, [rsp+48]
	add	rsp, 56
	epilog
end if

if used tui_label$new_di | defined include_everything
	; five arguments: xmm0 == width percent, edi == height, rsi == filltext (string), edx == colors, ecx == text alignment
falign
tui_label$new_di:
	prolog	tui_label$new_di
	sub	rsp, 56
	movq	[rsp], xmm0
	mov	[rsp+8], rdi
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+16], rax		; copy of our string
	call	list$new
	mov	[rsp+40], rax
	mov	edi, tui_label_size
	call	heap$alloc
	mov	qword [rax], tui_label$vtable
	mov	[rsp+48], rax
	mov	rdi, rax
	movq	xmm0, [rsp]		; width percent
	mov	rsi, [rsp+8]		; height
	mov	edx, ' '		; fillchar
	mov	rcx, [rsp+24]
	call	tui_background$init_di
	mov	rdi, [rsp+48]
	mov	rsi, [rsp+16]		; our filltext string
	mov	[rdi+tui_label_filltext_ofs], rsi
	mov	rsi, [rsp+40]		; first list
	mov	[rdi+tui_label_lines_ofs], rsi
	mov	rsi, [rsp+32]
	mov	[rdi+tui_label_textalign_ofs], rsi
	mov	qword [rdi+tui_label_highlightchar_ofs], 0
	mov	qword [rdi+tui_label_highlightcolor_ofs], 0
	call	tui_label$nvlineate
	mov	rax, [rsp+48]
	add	rsp, 56
	epilog
end if

if used tui_label$new_rect | defined include_everything
	; four arguments: rdi == pointer to a bounds rect, rsi == filltext (string), edx == colors, ecx == text alignment
falign
tui_label$new_rect:
	prolog	tui_label$new_rect
	sub	rsp, 48
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+8], rax
	call	list$new
	mov	[rsp+32], rax
	mov	edi, tui_label_size
	call	heap$alloc
	mov	qword [rax], tui_label$vtable
	mov	[rsp+40], rax
	mov	rdi, rax
	mov	rsi, [rsp]		; rect
	mov	edx, ' '		; fillchar
	mov	rcx, [rsp+16]		; fillcolors
	call	tui_background$init_rect
	mov	rdi, [rsp+40]
	mov	rsi, [rsp+8]		; our filltext string
	mov	[rdi+tui_label_filltext_ofs], rsi
	mov	rsi, [rsp+32]		; first list
	mov	[rdi+tui_label_lines_ofs], rsi
	mov	rsi, [rsp+24]
	mov	[rdi+tui_label_textalign_ofs], rsi
	mov	qword [rdi+tui_label_highlightchar_ofs], 0
	mov	qword [rdi+tui_label_highlightcolor_ofs], 0
	call	tui_label$nvlineate
	mov	rax, [rsp+40]
	add	rsp, 48
	epilog
end if


if used tui_label$clone | defined include_everything
	; single argument: rdi == source tui_label to clone/make a copy of
	; returns new tui_label copy in rax
falign
tui_label$clone:
	prolog	tui_label$clone
	sub	rsp, 32
	mov	[rsp], rdi
	mov	rdi, [rdi+tui_label_filltext_ofs]	; source string
	call	string$copy
	mov	[rsp+8], rax
	call	list$new
	mov	[rsp+16], rax
	mov	edi, tui_label_size
	call	heap$alloc
	mov	qword [rax], tui_label$vtable
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	call	tui_background$init_copy
	mov	rdi, [rsp+24]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	[rdi+tui_label_filltext_ofs], rsi
	mov	[rdi+tui_label_lines_ofs], rdx
	mov	rsi, [rsp]
	mov	rdx, [rsi+tui_label_textalign_ofs]
	mov	[rdi+tui_label_textalign_ofs], rdx
	mov	r8, [rsi+tui_label_highlightchar_ofs]
	mov	r9, [rsi+tui_label_highlightcolor_ofs]
	mov	[rdi+tui_label_highlightchar_ofs], r8
	mov	[rdi+tui_label_highlightcolor_ofs], r9
	call	tui_label$nvlineate
	mov	rax, [rsp+24]
	add	rsp, 32
	epilog
end if

if used tui_label$nvlineate | defined include_everything
	; single argument: rdi == tui_label object, this is non-virtual (hence nv preface)
	; we split the filltext by linefeeds and populate our textlines list
falign
tui_label$nvlineate:
	prolog	tui_label$nvlineate
	push	rdi
	; first, make sure our textlines list is empty:
	mov	rdi, [rdi+tui_label_lines_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_label_lines_ofs]
	call	heap$free		; blast the old one entirely
	mov	rdx, [rsp]		; get our tui_label object back
	mov	rdi, [rdx+tui_label_filltext_ofs]
	mov	esi, 10			; LF
	call	string$split
	mov	rdi, [rsp]
	mov	rcx, [rax+_list_size_ofs]
	mov	[rdi+tui_label_lines_ofs], rax
	pop	rdi
	epilog
calign
.dumpit:
	call	string$to_stdoutln
	ret
end if

if used tui_label$cleanup | defined include_everything
	; single argument: rdi == tui_label we are destroying
	; NOTE: this does not free the pointer itself, but heap$free's everything that we allocated
	; and iterates/deletes its children/bastards just like tui_object does
falign
tui_label$cleanup:
	prolog	tui_label$cleanup
	push	rdi
	mov	rdi, [rdi+tui_label_lines_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_label_lines_ofs]
	call	heap$free
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_label_filltext_ofs]
	call	heap$free
	
	; background's cleanup doesn't free anything, so we can safely just let tui_object do the rest
	mov	rdi, [rsp]
	call	tui_object$cleanup

	pop	rdi
	epilog
end if


if used tui_label$nvsettext | defined include_everything
	; two arguments: rdi == tui_label, rsi == new string of text to set
	; note: we make a copy of rsi
falign
tui_label$nvsettext:
	prolog	tui_label$nvsettext
	push	rsi rdi
	; first up, get rid of our previous one
	mov	rdi, [rdi+tui_label_filltext_ofs]
	call	heap$free
	mov	rdi, [rsp+8]	; our string
	call	string$copy
	mov	rdi, [rsp]
	mov	[rdi+tui_label_filltext_ofs], rax	; store our new copy
	call	tui_label$nvlineate
	mov	rdi, [rsp]
	; this one is a virtual
	mov	rsi, [rdi]	; our vtable
	call	qword [rsi+tui_vdraw]
	pop	rdi rsi
	epilog
end if

if used tui_label$nvsetalign | defined include_everything
	; two arguments: rdi == tui_label, esi == new alignment type
falign
tui_label$nvsetalign:
	prolog	tui_label$nvsetalign
	mov	rdx, [rdi]	; our vtable
	mov	dword [rdi+tui_label_textalign_ofs], esi
	call	qword [rdx+tui_vdraw]
	epilog
end if

if used tui_label$nvsetcolors | defined include_everything
	; two arguments: rdi == tui_label, esi == new colors
falign
tui_label$nvsetcolors:
	prolog	tui_label$nvsetcolors
	mov	rdx, [rdi]	; our vtable
	mov	dword [rdi+tui_bgcolors_ofs], esi
	call	qword [rdx+tui_vdraw]
	epilog
end if

if used tui_label$nvaddline | defined include_everything
	; two arguments: rdi == tui_label, rsi == new string of line to add
	; NOTE: this is a "cheater" method, insofar as: we do not modify filltext itself
	; but instead just add an entry to the textlines list, which is all that is used for drawing anyway
	; STRING PASSED IN MUST NOT CONTAIN a linefeed
falign
tui_label$nvaddline:
	prolog	tui_label$nvaddline
	push	rdi
	mov	rdi, rsi
	call	string$copy
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_label_lines_ofs]
	mov	rsi, rax
	call	list$push_back
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	pop	rdi
	epilog
end if
	

if used tui_label$draw | defined include_everything
	; single argument: rdi == tui_label
	; renders/draws our text, then calls the virtual updatedisplaylist method
falign
tui_label$draw:
	prolog	tui_label$draw
	; we'll use all of our callee-saves
	sub	rsp, 72
	mov	[rsp], rdi
	mov	[rsp+8], rbx
	mov	[rsp+16], r12
	mov	[rsp+24], r13
	mov	[rsp+32], r14
	mov	[rsp+40], r15
	mov	[rsp+48], rbp
	mov	qword [rsp+56], 0
	mov	qword [rsp+64], 0

	; first up, blast our buffer by drawing our background
	call	tui_background$nvfill
	mov	rsi, [rsp]			; get our object back

	; calculate the offset of the last line of our text and attribute buffers into r14, r15
	mov	eax, [rsi+tui_width_ofs]
	mov	ecx, [rsi+tui_height_ofs]
	mul	ecx
	shl	eax, 2				; in bytes
	test	eax, eax	
	jz	.bailout			; width = 0 || height = 0

	mov	ecx, [rsi+tui_width_ofs]
	shl	ecx, 2
	sub	eax, ecx
	mov	r13d, ecx			; save our width
	mov	r14, [rsi+tui_text_ofs]
	add	r14, rax
	mov	r15, [rsi+tui_attr_ofs]
	add	r15, rax
	; ok so now, r14 and r15 point to the start of the last line of our text

	; we'll use [rsp+64] as our line counter
	mov	r12d, [rsi+tui_height_ofs]	; limit for our reverse_foreach

	; if our text line that we have to draw is _less_ than our actual height, we need to go backward for the difference
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	r8, [_list_size]

	mov	eax, r12d
	sub	eax, r8d
	mul	r13d				; eax = (height - linecount) * width in bytes
	mov	r9, r14
	mov	r10, r15
	sub	r9, rax
	sub	r10, rax
	
	cmp	r12d, r8d
	cmova	r14, r9
	cmova	r15, r10

	; store our highlightchar and highlightcolor
	mov	eax, dword [rsi+tui_label_highlightchar_ofs]
	mov	[rsp+56], eax
	mov	eax, dword [rsi+tui_label_highlightcolor_ofs]
	mov	[rsp+60], eax

	; TODO: would this be better with a jump table?
	mov	eax, dword [rsi+tui_label_textalign_ofs]

	; if we are doing highlighting, we need to use different line placement functions
	cmp	dword [rsi+tui_label_highlightchar_ofs], 0
	jne	.highlighter

	cmp	eax, tui_textalign_left
	je	.drawleft
	cmp	eax, tui_textalign_center
	je	.drawcenter
	; else, right it is
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	rbx, [_list_last]
	mov	rbp, .placeline_right

	; a note here on my strategy... 
	; because we are making use of all our callee-saves, and because list$reverse_foreach_limit
	; blasts callee-saves for its own uses during list traversal, this means we can't guarantee
	; that the values will remain in tact _inside_ the foreach destination function
	; to combat this:
	; we are doing a ridiculous amount of unconditional jumping around
	; this is messier to follow of course, but effectively does the same thing
	; as list$reverse_foreach_limit

	; there are a lot of stack-heavier ways to do this.. TODO: someday when I am bored, give this
	; some more consideration

macro tui_label_doit {
	test	rbx, rbx
	jz	.bailout
	jmp	rbp
}

	tui_label_doit

macro tui_label_list_next {
	add	dword [rsp+64], 1		; increment our line counter by one
	sub	r14, r13			; decrement r14 by one line
	sub	r15, r13			; decrement r15 by one line
	sub	r12d, 1
	jz	.bailout
	mov	rbx, [rbx+_list_prevofs]
	test	rbx, rbx
	jz	.bailout
	jmp	rbp
}

	; so on entry: rbx is pointing at our list _item_
	; 		r14 is pointing at our current text destination
	;		r15 is pointing at our current attr destination
	;
	; r12d is our line limit, which is handled by tui_label_list_next
	; r13 is our line length in bytes
	; rbp is our iterator function address, unchanging
calign
.placeline_left:
	mov	rdi, [rbx]			; the value in the list item (our line string)
	mov	rdx, [rdi]			; length of the string
	shl	rdx, 2				; in bytes
	cmp	rdx, r13
	cmova	rdx, r13			; length of our copy
	mov	rsi, rdi
	add	rsi, 8
	mov	rdi, r14
	call	memcpy
	tui_label_list_next
calign
.placeline_left_highlight:
	mov	rdi, [rbx]			; the value in the list item (our line string)
	mov	rdx, [rdi]			; length of the string
	shl	rdx, 2				; in bytes
	cmp	rdx, r13
	cmova	rdx, r13			; length of our copy
	mov	rsi, rdi
	add	rsi, 8
	mov	rdi, r14
	push	rdx
	call	memcpy
	pop	rdx
	shr	rdx, 2				; our copy length back in characters
	mov	rdi, r14
	mov	rsi, r15
	mov	r8d, dword [rsp+56]		; our highlight char
	mov	r9d, dword [rsp+60]		; our highlight color
calign
.dohighlight:
	mov	eax, dword [rdi]
	cmp	eax, r8d
	je	.highlightchar
	add	rdi, 4
	add	rsi, 4
	sub	rdx, 1
	jnz	.dohighlight
	
	tui_label_list_next
calign
.highlightchar:
	mov	dword [rsi], r9d
	add	rdi, 4
	add	rsi, 4
	sub	rdx, 1
	jnz	.dohighlight
	
	tui_label_list_next
calign
.placeline_center:
	mov	rdi, [rbx]			; the value in the list item (our line string)
	mov	rdx, [rdi]			; the length of the string
	shl	rdx, 2				; in bytes
	cmp	rdx, r13
	cmova	rdx, r13			; length of our copy
	mov	r11, r13
	sub	r11, rdx
	shr	r11, 1				; space leftover div 2 (in bytes)
	and	r11, not 3
	mov	rsi, rdi
	add	rsi, 8
	mov	rdi, r14
	add	rdi, r11
	call	memcpy
	tui_label_list_next

calign
.placeline_center_highlight:
	mov	rdi, [rbx]			; the value in the list item (our line string)
	mov	rdx, [rdi]			; the length of the string
	shl	rdx, 2				; in bytes
	cmp	rdx, r13
	cmova	rdx, r13			; length of our copy
	mov	r11, r13
	sub	r11, rdx
	shr	r11, 1				; space leftover div 2 (in bytes)
	and	r11, not 3
	mov	rsi, rdi
	add	rsi, 8
	mov	rdi, r14
	add	rdi, r11
	push	r11 rdx
	call	memcpy
	pop	rdx r11
	shr	rdx, 2				; our copy length back in characters
	mov	rdi, r14
	mov	rsi, r15
	add	rdi, r11
	add	rsi, r11
	mov	r8d, dword [rsp+56]		; our highlight char
	mov	r9d, dword [rsp+60]		; our highlight color
	jmp	.dohighlight

calign
.placeline_right:
	mov	rdi, [rbx]			; the value in the list item (our line string)
	mov	rdx, [rdi]			; the length of the string
	shl	rdx, 2				; in bytes
	cmp	rdx, r13
	cmova	rdx, r13			; length of our copy
	mov	r11, r13
	sub	r11, rdx			; space leftover
	mov	rsi, rdi
	add	rsi, 8
	mov	rdi, r14
	add	rdi, r11
	call	memcpy
	tui_label_list_next
calign
.placeline_right_highlight:
	mov	rdi, [rbx]			; the value in the list item (our line string)
	mov	rdx, [rdi]			; the length of the string
	shl	rdx, 2				; in bytes
	cmp	rdx, r13
	cmova	rdx, r13			; length of our copy
	mov	r11, r13
	sub	r11, rdx			; space leftover
	mov	rsi, rdi
	add	rsi, 8
	mov	rdi, r14
	add	rdi, r11
	push	r11 rdx
	call	memcpy
	pop	rdx r11
	shr	rdx, 2				; our copy length back in characters
	mov	rdi, r14
	mov	rsi, r15
	add	rdi, r11
	add	rsi, r11
	mov	r8d, dword [rsp+56]		; our highlight char
	mov	r9d, dword [rsp+60]		; our highlight color
	jmp	.dohighlight

calign
.drawleft:
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	rbx, [_list_last]
	mov	rbp, .placeline_left
	tui_label_doit
calign
.drawcenter:
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	rbx, [_list_last]
	mov	rbp, .placeline_center
	tui_label_doit
calign
.highlighter:
	cmp	eax, tui_textalign_left
	je	.drawleft_highlight
	cmp	eax, tui_textalign_center
	je	.drawcenter_highlight
	; else, right it is
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	rbx, [_list_last]
	mov	rbp, .placeline_right_highlight
	tui_label_doit
calign
.drawleft_highlight:
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	rbx, [_list_last]
	mov	rbp, .placeline_left_highlight
	tui_label_doit
calign
.drawcenter_highlight:
	mov	rdi, [rsi+tui_label_lines_ofs]
	mov	rbx, [_list_last]
	mov	rbp, .placeline_center_highlight
	tui_label_doit
calign
.bailout:
	mov	rdi, [rsp]		; get our object back
	mov	rsi, [rdi]		; get our vtable
	call	qword [rsi+tui_vupdatedisplaylist]

	mov	rbx, [rsp+8]
	mov	r12, [rsp+16]
	mov	r13, [rsp+24]
	mov	r14, [rsp+32]
	mov	r15, [rsp+40]
	mov	rbp, [rsp+48]
	add	rsp, 72
	epilog
end if
