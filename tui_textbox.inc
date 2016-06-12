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
	; tui_textbox.inc: a tui_panel wrapper that includes a title, message, and a single text editor
	; 
	; the idea behind this is, it is often useful to pop up a dialog box with some instruction text
	; that grabs a line of input, so rather than hand-code that each and every time we need it
	; this provides the basic functionality required.
	;

if used tui_textbox$vtable | defined include_everything

	; our vtable is the same, but we add one for our onenter handling (which is special)
dalign
tui_textbox$vtable:
	dq      tui_panel$cleanup, tui_panel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
	dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; and one for our onenter handling, descendents should override if they are interested
	dq	tui_textbox$onenter

	; further, we need a specialized vtable for our tui_text's onenter handler:
dalign
tui_textbox_editor$vtable:
	dq      tui_text$cleanup, tui_text$clone, tui_text$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_text$gotfocus, tui_text$lostfocus
	dq      tui_text$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_text$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; we add one method to our vtable for onenter handling
	dq      tui_textbox_editor$onenter


end if

if used tui_textbox$new | defined include_everything
	; tui_panel has a user variable that it doesn't itself use, we populate that with our tui_text editor for later reference

	; six arguments: rdi == string title, rsi == string message (multiline okay), rdx == optional initial text, ecx == panel/title colors, r8d == text colors, r9d == focus text colors
falign
tui_textbox$new:
	prolog	tui_textbox$new
	; this is largely copied from tui_alert for layout calcs, etc
	sub	rsp, 80
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	[rsp+40], r9
	; calculate the dimensions we need for our panel
	; even though it is inefficient, we split the message first so we can determine
	; the longest line (inefficient insofar as tui_label will split it again)
	mov	rdi, rsi
	mov	esi, 10
	call	string$split
	mov	[rsp+48], rax
	mov	qword [rsp+56], 0
	mov	rdi, rax
	mov	rsi, .linelength
	lea	rdx, [rsp+56]
	call	list$foreach_arg
	mov	rdi, [rsp]
	; start with min 32
	mov	r10d, 32
	; titlelen + 6 bigger?
	mov	r11, [rdi]
	add	r11d, 6
	cmp	r11d, r10d
	cmova	r10d, r11d
	; linelen(max) + 6 bigger?
	mov	r11d, [rsp+56]
	add	r11d, 6
	cmp	r11d, r10d
	cmova	r10d, r11d
	; width is complete
	mov	[rsp+64], r10d
	; height is next
	mov	rax, [rsp+48]
	mov	edx, [rax+_list_size_ofs]
	mov	ecx, edx
	; add	ecx, 1
	cmp	edx, 1
	cmova	edx, ecx
	add	edx, 6
	mov	[rsp+68], edx
	; get rid of our list
	mov	rdi, rax
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free
	; we can construct our panel now
	mov	edi, [rsp+64]		; width
	mov	esi, [rsp+68]		; height
	mov	rdx, [rsp]		; title
	mov	ecx, [rsp+24]		; boxcolors
	mov	r8d, [rsp+24]		; titlecolors
	call	tui_panel$new_ii
	; make sure we use our vtable for the panel
	mov	qword [rax], tui_textbox$vtable
	; also, we'd like a dropshadow under our panel
	mov	dword [rax+tui_dropshadow_ofs], 1
	mov	[rsp+56], rax		; our end return object
	; prepend our message with a linefeed so it ends up padded properly:
	mov	rdi, .lfstr
	mov	rsi, [rsp+8]
	call	string$concat
	mov	[rsp+64], rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	rdi, rax		; filltext
	mov	esi, [rsp+24]		; colors
	mov	edx, tui_textalign_center
	call	tui_label$new_dd
	; add that as a child to our panel
	mov	rdi, [rsp+56]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; free our filltext
	mov	rdi, [rsp+64]
	call	heap$free
	; next up, we need a 100% wide by 2 height vbox to hold our text editor
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	[rsp+64], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 2
	call	tui_object$init_di
	mov	rdi, [rsp+64]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	; add that to our panel
	mov	rsi, rdi
	mov	rdi, [rsp+56]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; finally, do up our editor
	; the width of our text == panel width - 4
	mov	r8, [rsp+56]
	mov	edi, [r8+tui_width_ofs]
	mov	esi, 1			; height
	sub	edi, 4			; width
	mov	rdx, [rsp+16]		; initial text
	mov	ecx, [rsp+32]		; colors
	mov	r8d, [rsp+40]		; focuscolors
	mov	r9d, 1			; spinners are nice, hahah
	call	tui_text$new_ii
	; set its vtable so that we get onenter hooks
	mov	qword [rax], tui_textbox_editor$vtable
	; add it to our box
	mov	rcx, [rsp+56]
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	push	rax
	mov	[rcx+tui_panel_user_ofs], rax
	mov	[rax+tui_text_user_ofs], rcx
	call	qword [rdx+tui_vappendchild]
	; make sure the textinput has focus:
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	
	mov	rax, [rsp+56]
	add	rsp, 80
	epilog
cleartext .lfstr, 10
falign
.linelength:
	; called for each string line in the message, rdi == string, rsi == pointer to update with our length
	mov	edx, [rdi]
	mov	ecx, [rsi]
	cmp	edx, ecx
	cmova	ecx, edx
	mov	[rsi], ecx
	ret


end if

if used tui_textbox$onenter | defined include_everything
	; single argument in rdi: our tui_textbox object
	; default here doesn't do anything
falign
tui_textbox$onenter:
	prolog	tui_textbox$onenter
	epilog

end if


if used tui_textbox_editor$onenter | defined include_everything
	; single argument in rdi: our tui_text editor object
falign
tui_textbox_editor$onenter:
	prolog	tui_textbox_editor$onenter
	mov	rdi, [rdi+tui_text_user_ofs]		; our tui_textbox parent object
	mov	rsi, [rdi]
	call	qword [rsi+tui_vonenter]
	epilog

end if
