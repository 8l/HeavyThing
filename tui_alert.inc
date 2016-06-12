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
	; tui_alert.inc: basic TUI alert box functionality
	; nothing terribly fancy, haha, but useful in situations where we have to do
	; "normal" alert-type goods
	;
	; to determine which button was pressed, the button itself will be passed inside
	; a click event, in which case you can examine it's button text
	;
	; This simplifies tui_alert, insofar as all we really do is provide a convenience
	; constructor that builds out the panel/message/buttons
	;

if used tui_alert$vtable | defined include_everything
	; we need to override the vtable only so we can deal with tab focus changes between buttons
dalign
tui_alert$vtable:
	dq      tui_panel$cleanup, tui_panel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
	dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_alert$ontab, tui_alert$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if



if used tui_alert$new | defined include_everything

	; button flags is an or combination of one or more of these:
tui_alert_ok = 1
tui_alert_cancel = 2
tui_alert_yes = 4
tui_alert_no = 8
tui_alert_continue = 16
tui_alert_quit = 32


	; six arguments: rdi == string title, rsi == string message (multiline okay), edx == button flags, ecx == panel/title colors, r8d == button colors, r9d == focus button colors
falign
tui_alert$new:
	prolog	tui_alert$new
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
	; combined width of buttons + 6 bigger?
	; textlen+7 is what tui_button allocates space-wise
	; ok == 9
	; cancel = 13
	; yes = 10
	; no = 9
	; continue = 15
	; quit = 11
	xor	eax, eax
	mov	r11d, 9
	test	dword [rsp+16], 1
	cmovnz	eax, r11d
	mov	ecx, eax
	add	ecx, 13
	test	dword [rsp+16], 2
	cmovnz	eax, ecx
	mov	ecx, eax
	add	ecx, 10
	test	dword [rsp+16], 4
	cmovnz	eax, ecx
	mov	ecx, eax
	add	ecx, 9
	test	dword [rsp+16], 8
	cmovnz	eax, ecx
	mov	ecx, eax
	add	ecx, 15
	test	dword [rsp+16], 16
	cmovnz	eax, ecx
	mov	ecx, eax
	add	ecx, 11
	test	dword [rsp+16], 32
	cmovnz	eax, ecx
	add	eax, 6
	cmp	eax, r10d
	cmova	r10d, eax
	; width is complete
	mov	[rsp+64], r10d
	; height is next
	mov	rax, [rsp+48]
	mov	edx, [rax+_list_size_ofs]
	mov	ecx, edx
	add	ecx, 1
	cmp	edx, 1
	cmova	edx, ecx
	add	edx, 8
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
	mov	qword [rax], tui_alert$vtable
	; also, we'd like a dropshadow under our panel:
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
	; next up, we need a 100% wide horizontal layout 4 height box to hold our buttons
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	[rsp+64], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 4
	call	tui_object$init_di
	mov	rdi, [rsp+64]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	; add that to our panel:
	mov	rsi, rdi
	mov	rdi, [rsp+56]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add an hspacer so that all our buttons end up equidistant
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; next up: create our buttons
	test	dword [rsp+16], 1
	jz	.skipok
	mov	rdi, .okstr
	mov	esi, [rsp+24]		; background colors
	mov	edx, [rsp+32]		; colors
	mov	ecx, [rsp+40]		; focuscolors
	call	tui_button$new
	; add that to our buttonbox
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add another hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.skipok:
	test	dword [rsp+16], 2
	jz	.skipcancel
	mov	rdi, .cancelstr
	mov	esi, [rsp+24]		; background colors
	mov	edx, [rsp+32]		; colors
	mov	ecx, [rsp+40]		; focuscolors
	call	tui_button$new
	; add that to our buttonbox
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add another hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.skipcancel:
	test	dword [rsp+16], 4
	jz	.skipyes
	mov	rdi, .yesstr
	mov	esi, [rsp+24]		; background colors
	mov	edx, [rsp+32]		; colors
	mov	ecx, [rsp+40]		; focuscolors
	call	tui_button$new
	; add that to our buttonbox
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add another hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.skipyes:
	test	dword [rsp+16], 8
	jz	.skipno
	mov	rdi, .nostr
	mov	esi, [rsp+24]		; background colors
	mov	edx, [rsp+32]		; colors
	mov	ecx, [rsp+40]		; focuscolors
	call	tui_button$new
	; add that to our buttonbox
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add another hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.skipno:
	test	dword [rsp+16], 16
	jz	.skipcontinue
	mov	rdi, .continuestr
	mov	esi, [rsp+24]		; background colors
	mov	edx, [rsp+32]		; colors
	mov	ecx, [rsp+40]		; focuscolors
	call	tui_button$new
	; add that to our buttonbox
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add another hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.skipcontinue:
	test	dword [rsp+16], 32
	jz	.skipquit
	mov	rdi, .quitstr
	mov	esi, [rsp+24]		; background colors
	mov	edx, [rsp+32]		; colors
	mov	ecx, [rsp+40]		; focuscolors
	call	tui_button$new
	; add that to our buttonbox
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add another hspacer
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
calign
.skipquit:
	; so now, we need to focus the SECOND child of our buttonbox
	mov	rdi, [rsp+64]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdi, [rdi+_list_first_ofs]
	cmp	qword [rdi+_list_nextofs], 0
	je	.skipfocus
	mov	rdi, [rdi+_list_nextofs]
	mov	rdi, [rdi]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
calign
.skipfocus:
	; do our final return
	mov	rax, [rsp+56]
	add	rsp, 80
	epilog
cleartext .lfstr, 10
cleartext .okstr, 'Ok'
cleartext .cancelstr, 'Cancel'
cleartext .yesstr, 'Yes'
cleartext .nostr, 'No'
cleartext .continuestr, 'Continue'
cleartext .quitstr, 'Quit'
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


if used tui_alert$addbutton | defined include_everything
	; two arguments: rdi == tui_alert (which is a tui_panel), rsi == tui_button to add
	; NOTE: we do not pay attention to sizing/resizing of the tui_alert panel itself, up to the caller to do that
falign
tui_alert$addbutton:
	prolog	tui_alert$addbutton
	; burning purpose: adhere to the tui_alert$new structure, and add this button
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdi, [rdi+_list_last_ofs]
	mov	rdi, [rdi]			; the buttonbox
	push	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; add an hspacer to it
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	pop	rdi
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	epilog
end if
	



;
; some notes here on the tab/shifttab goods:
; instead of creating an actual custom tui_panel object, and keeping our button list separately
; we _ASSUME_ that no other objects were added to us, and our contents are precisely what the above
; constructor tui_alert$new produced.
; This lets us grab our guts' last child, which is the button box, and navigate its children directly
;

if used tui_alert$ontab | defined include_everything
	; single argument in rdi: our tui_alert (which is a tui_panel)
falign
tui_alert$ontab:
	prolog	tui_alert$ontab
	push	rbx r12
	mov	rbx, [rdi+tui_panel_guts_ofs]
	mov	rbx, [rbx+tui_children_ofs]

	mov	rbx, [rbx+_list_last_ofs]	; last child of the panel == our buttonbox
	mov	rbx, [rbx]
	mov	rbx, [rbx+tui_children_ofs]

	cmp	qword [rbx+_list_size_ofs], 1
	je	.nothingtodo
	; first up, locate the button that _is_ focussed
	mov	r12, [rbx+_list_first_ofs]
calign
.locatefocus:
	; our buttonbox is: hspacer, button, hspacer [, button, hspacer]...
	mov	r12, [r12+_list_nextofs]
	mov	rdi, [r12]			; a button object
	cmp	dword [rdi+tui_button_focussed_ofs], 0
	jne	.focusfound
	; NOTE: this will crash of course if it isn't built exactly the way we expect
	mov	r12, [r12+_list_nextofs]
	jmp	.locatefocus
calign
.focusfound:
	; unfocus the one that has it
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlostfocus]
	mov	r12, [r12+_list_nextofs]
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jz	.resetfocus
	; otherwise, this one gets focus
	mov	rdi, [r12]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	; done, dusted.
	pop	r12 rbx
	epilog
calign
.resetfocus:
	; we ran off the end of our list
	mov	r12, [rbx+_list_first_ofs]
	mov	r12, [r12+_list_nextofs]
	mov	rdi, [r12]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	pop	r12 rbx
	epilog

end if


if used tui_alert$onshifttab | defined include_everything
	; single argument in rdi: our tui_alert (which is a tui_panel)
falign
tui_alert$onshifttab:
	prolog	tui_alert$onshifttab
	push	rbx r12
	mov	rbx, [rdi+tui_panel_guts_ofs]
	mov	rbx, [rbx+tui_children_ofs]

	mov	rbx, [rbx+_list_last_ofs]	; last child of the panel == our buttonbox
	mov	rbx, [rbx]
	mov	rbx, [rbx+tui_children_ofs]

	cmp	qword [rbx+_list_size_ofs], 1
	je	.nothingtodo
	; first up, locate the button that _is_ focussed
	mov	r12, [rbx+_list_first_ofs]
calign
.locatefocus:
	; our buttonbox is: hspacer, button, hspacer [, button, hspacer]...
	mov	r12, [r12+_list_nextofs]
	mov	rdi, [r12]			; a button object
	cmp	dword [rdi+tui_button_focussed_ofs], 0
	jne	.focusfound
	; NOTE: this will crash of course if it isn't built exactly the way we expect
	mov	r12, [r12+_list_nextofs]
	jmp	.locatefocus
calign
.focusfound:
	; unfocus the one that has it
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlostfocus]
	mov	r12, [r12+_list_prevofs]
	mov	r12, [r12+_list_prevofs]
	test	r12, r12
	jz	.resetfocus
	; otherwise, this one gets focus
	mov	rdi, [r12]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	; done, dusted.
	pop	r12 rbx
	epilog
calign
.resetfocus:
	; we ran off the end of our list
	mov	r12, [rbx+_list_last_ofs]
	mov	r12, [r12+_list_prevofs]
	mov	rdi, [r12]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	pop	r12 rbx
	epilog

end if
