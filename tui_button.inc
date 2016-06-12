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
	; tui_button.inc: simple button functionality
	;

if used tui_button$vtable | defined include_everything

dalign
tui_button$vtable:
	dq      tui_button$cleanup, tui_button$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_button$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_button$gotfocus, tui_button$lostfocus
	dq      tui_button$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if


if used tui_button$new | defined include_everything



tui_button_label_ofs = tui_background_size
tui_button_pressed_ofs = tui_background_size + 8
tui_button_focussed_ofs = tui_background_size + 16
tui_button_normalcolors_ofs = tui_background_size + 24
tui_button_focuscolors_ofs = tui_background_size + 32
tui_button_timerptr_ofs = tui_background_size + 40
tui_button_size = tui_background_size + 48

	; four arguments: rdi == string text, esi == background colors, edx == colors, ecx == focuscolors
falign
tui_button$new:
	prolog	tui_button$new
	push	rdi rsi rdx rcx
	mov	edi, tui_button_size
	call	heap$alloc
	mov	qword [rax], tui_button$vtable
	mov	rdi, rax
	mov	r9, [rsp+24]
	mov	esi, [r9]
	add	esi, 7
	mov	edx, 4
	mov	ecx, ' '
	mov	r8d, [rsp+16]
	mov	[rsp+16], rax
	call	tui_background$init_ii
	mov	rax, [rsp+16]
	mov	ecx, [rsp+8]
	mov	edx, [rsp]
	mov	dword [rax+tui_layout_ofs], tui_layout_absolute
	mov	qword [rax+tui_button_pressed_ofs], 0
	mov	qword [rax+tui_button_focussed_ofs], 0
	mov	qword [rax+tui_button_normalcolors_ofs], rcx
	mov	qword [rax+tui_button_focuscolors_ofs], rdx
	mov	qword [rax+tui_button_timerptr_ofs], 0
	; now we need to create our label

	; we need a string concatenation of our label with preceding and trailing LF
	mov	rdi, .lf
	mov	rsi, [rsp+24]
	call	string$concat
	mov	[rsp], rax
	mov	rdi, rax
	mov	rsi, .lf
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free

	mov	rsi, [rsp+24]
	mov	edx, [rsp+8]
	mov	ecx, tui_textalign_center
	mov	r8d, [rsi]
	add	r8d, 6

	mov	rsi, [rsp]

	sub	rsp, 16
	mov	rdi, rsp
	mov	qword [rdi], 0
	mov	dword [rdi+8], r8d
	mov	dword [rdi+12], 3
	call	tui_label$new_rect
	mov	dword [rax+tui_dropshadow_ofs], 1
	add	rsp, 16

	mov	rdi, [rsp+16]
	mov	rsi, rax
	mov	[rdi+tui_button_label_ofs], rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; done, finite, kaput, cleanup our concatenated string
	mov	rdi, [rsp]
	call	heap$free
	mov	rax, [rsp+16]
	add	rsp, 32
	epilog
dalign
.lf:
	dq	1
	dd	10


end if


if used tui_button$cleanup | defined include_everything
	; single argument in rdi: our tui_button
falign
tui_button$cleanup:
	prolog	tui_button$cleanup
	cmp	qword [rdi+tui_button_timerptr_ofs], 0
	je	.simple
	push	rdi
	mov	rdi, [rdi+tui_button_timerptr_ofs]
	call	epoll$timer_clear
	pop	rdi
	call	tui_object$cleanup
	epilog
calign
.simple:
	call	tui_object$cleanup
	epilog

end if


if used tui_button$clone | defined include_everything
	; single argument in rdi: our tui_button to clone
falign
tui_button$clone:
	prolog	tui_button$clone
	; so if we use the normal tui_background$clone, it will clone our children, and since our label is already a child
	; it will get copied also
	; then just copy the attributes, set our label to our first child, and we are done
	push	rdi
	mov	edi, tui_button_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	rsi, [rsp+8]
	call	tui_background$init_copy
	mov	rax, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsi+tui_button_normalcolors_ofs]
	mov	rcx, [rsi+tui_button_focuscolors_ofs]
	mov	r8d, [rsi+tui_button_focussed_ofs]
	mov	qword [rax+tui_button_pressed_ofs], 0
	mov	qword [rax+tui_button_focussed_ofs], r8
	mov	qword [rax+tui_button_normalcolors_ofs], rdx
	mov	qword [rax+tui_button_focuscolors_ofs], rcx
	mov	qword [rax+tui_button_timerptr_ofs], 0
	; last but not least, set our label to our first child
	mov	rdx, [rax+tui_children_ofs]
	mov	rdx, [rdx+_list_first_ofs]
	mov	rdx, [rdx+_list_valueofs]
	mov	qword [rax+tui_button_label_ofs], rdx
	mov	dword [rdx+tui_dropshadow_ofs], 1
	add	rsp, 16
	epilog

end if

if used tui_button$timer | defined include_everything
	; single argument in rdi: our tui_button object
falign
tui_button$timer:
	prolog	tui_button$timer
	mov	dword [rdi+tui_button_pressed_ofs], 0
	mov	qword [rdi+tui_button_timerptr_ofs], 0
	push	rdi
	mov	rdi, [rdi+tui_button_label_ofs]
	mov	dword [rdi+tui_dropshadow_ofs], 1
	mov	esi, -1
	mov	edx, -1
	mov	rcx, [rdi]
	call	qword [rcx+tui_vmove]
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vclick]	; this ultimately fires the vclicked method with this button object pointer in rsi
	mov	eax, 1			; destroy the timer object, but leave us alone otherwise
	epilog

end if

if used tui_button$gotfocus | defined include_everything
	; single argument in rdi: our tui_button object
falign
tui_button$gotfocus:
	prolog	tui_button$gotfocus
	mov	dword [rdi+tui_button_focussed_ofs], 1
	mov	esi, [rdi+tui_button_focuscolors_ofs]
	mov	rdi, [rdi+tui_button_label_ofs]
	call	tui_label$nvsetcolors
	epilog

end if

if used tui_button$lostfocus | defined include_everything
	; single argument in rdi: our tui_button object
falign
tui_button$lostfocus:
	prolog	tui_button$lostfocus
	mov	dword [rdi+tui_button_focussed_ofs], 0
	mov	esi, [rdi+tui_button_normalcolors_ofs]
	mov	rdi, [rdi+tui_button_label_ofs]
	call	tui_label$nvsetcolors
	epilog

end if

if used tui_button$keyevent | defined include_everything
	; three arguments: rdi == our tui_button object, esi == key, edx == esc_key
falign
tui_button$keyevent:
	prolog	tui_button$keyevent
	cmp	dword [rdi+tui_button_focussed_ofs], 0
	je	.nothingtodo
	cmp	esi, 9
	je	.tab
	cmp	edx, 0x5a
	je	.shifttab
	cmp	esi, 32
	jne	.nothingtodo
	; otherwise, space was pressed, make sure we aren't already pressed
	cmp	dword [rdi+tui_button_pressed_ofs], 1
	je	.nothingtodo
	mov	dword [rdi+tui_button_pressed_ofs], 1
	; we want a one-time delay so we can "animate" our button press, albeit a rather cheeseball effect
	; haha
	; this creates some complications of course if the resultant click action ends up in our destruction
	; but the click method shouldn't get called from here, not until the button comes back up
	mov	rsi, [rdi+tui_button_label_ofs]
	mov	dword [rsi+tui_dropshadow_ofs], 0
	push	rdi
	mov	rdi, rsi
	mov	esi, 1
	mov	edx, 1
	mov	rcx, [rdi]
	call	qword [rcx+tui_vmove]
	; fire up a timer
	mov	edi, 300
	mov	rsi, [rsp]
	call	epoll$timer_new
	pop	rdi
	mov	[rdi+tui_button_timerptr_ofs], rax
	mov	dword [rax+24], 2		; special timer handling, we don't want it to try and destroy/free our object
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	mov	eax, 1
	epilog
calign
.tab:
	mov	rdx, [rdi]
	call	qword [rdx+tui_vontab]
	mov	eax, 1
	epilog
calign
.shifttab:
	mov	rdx, [rdi]
	call	qword [rdx+tui_vonshifttab]
	mov	eax, 1
	epilog
calign
.nothingtodo:
	xor	eax, eax
	epilog

end if
