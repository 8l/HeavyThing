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
	; chatpanel.inc: a tui_panel descendent that deals with our semi-complicated
	; chat display...
	;
	; The idea here is to provide heightlocked tui_text areas, one for our own
	; user that always has a spinning cursor and right-aligned, and other
	; participants left-aligned.
	; 
	; we keep track of "in-progress" messages from other parties, and provide
	; specialised notifications.
	;
	; Further, we deal with the unpleasantness of vertical scrolling.
	;


; define for our history max:
chatpanel_history_max = 100
	; Some notes here on that:
	; due to the way I decided to do the scroll + valid tui_texts for the entire chatpanel
	; if we make that number huge, it has to redraw/iterate each and every one of the children
	; when redraw is called, this can be _very_ expensive, so we limit it at least enough so
	; that redrawing hundreds of children isn't quite so bad (if we _wanted_ a huge history,
	; then we'd just have to redo how we deal with the chatpanel_guts_ofs children and manage them
	; more appropriately)
	;


dalign
chatpanel$vtable:
	dq      chatpanel$cleanup, tui_panel$clone, chatpanel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, chatpanel$gotfocus, chatpanel$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
	dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, chatpanel$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

; every chatpanel needs a link to the chatroom it belongs to
chatpanel_room_ofs = tui_panel_size
; further, we hangon to the name of the room separately (the chatroom itself's name might be null)
chatpanel_name_ofs = tui_panel_size + 8
; for in-progress remote messages, we use a map of actives:
chatpanel_inprogress_ofs = tui_panel_size + 16
; and for our localtext, we keep a pointer as well
chatpanel_localtext_ofs = tui_panel_size + 24
; we also need a copy of our user pointer:
chatpanel_user_ofs = tui_panel_size + 32
; and a copy of the screen tui object
chatpanel_screen_ofs = tui_panel_size + 40
; and our local vertical scroll modifier
chatpanel_scroll_ofs = tui_panel_size + 48

chatpanel_size = tui_panel_size + 56

; single argument in rdi: the string name of the room (we copy it)
; NOTE: caller has to set the room pointer
falign
chatpanel$new:
	prolog	chatpanel$new
	push	rbx r12
	call	string$copy
	mov	r12, rax
	mov	edi, chatpanel_size
	call	heap$alloc_clear
	; tui_panel$init_dd requires a valid vtable to exist beforehand:
	mov	qword [rax], chatpanel$vtable
	mov	rbx, rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	rsi, r12
	ansi_colors edx, 'lightgray', 'black'
	ansi_colors ecx, 'lightgray', 'blue'
	call	tui_panel$init_dd
	mov	[rbx+chatpanel_name_ofs], r12
	xor	edi, edi
	call	unsignedmap$new
	mov	[rbx+chatpanel_inprogress_ofs], rax
	; for our "phantom scroll", we need a vspacer that is a fixed height
	; well in excess of however many rows are actually possible
	mov	edi, 100
	call	tui_vspacer$new_i
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	; our local text editor is next:
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	xor	esi, esi
	ansi_colors edx, 'lightgray', 'black'
	ansi_colors ecx, 'lightgray', 'blue'
	mov	r8d, 1
	call	tui_text$new_di
	mov	r12, rax
	mov	[rbx+chatpanel_localtext_ofs], rax

	; enable multiline, alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_docursor_ofs], 1
	mov	dword [rax+tui_text_heightlock_ofs], 1

	; hmm, not sure I like right aligned: mov	dword [rax+tui_text_align_ofs], tui_textalign_right
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	; make sure it gets focus:
	mov	rdi, r12
	mov	rsi, [r12]
	call	qword [rsi+tui_vgotfocus]

	mov	rax, rbx
	pop	r12 rbx
	epilog


; single argument in rdi: the chatpanel object to cleanup
falign
chatpanel$cleanup:
	prolog	chatpanel$cleanup
	push	rbx
	mov	rbx, rdi
	; leave whatever room we are in:
	mov	rdi, [rdi+chatpanel_room_ofs]
	mov	rsi, [rbx+chatpanel_user_ofs]
	mov	rdx, [rbx+chatpanel_screen_ofs]
	call	chatroom$leave
	; we have to clear our inprogress list
	; since it does not allocate anything for keys or values
	; we can just clear and free it
	mov	rdi, [rbx+chatpanel_inprogress_ofs]
	xor	esi, esi
	call	stringmap$clear
	mov	rdi, [rbx+chatpanel_inprogress_ofs]
	call	heap$free
	; get rid of our name string as well
	mov	rdi, [rbx+chatpanel_name_ofs]
	call	heap$free
	; let tui_panel$cleanup do the rest:
	mov	rdi, rbx
	call	tui_panel$cleanup
	pop	rbx
	epilog


; single argument in rdi: our chatpanel object
falign
chatpanel$titleupdate:
	prolog	chatpanel$titleupdate
	; burning purpose: if we are not in a proper room, _and_ our remote party
	; is not online, we need to change our colors up and add (offline) to the
	; title
	mov	rsi, [rdi+chatpanel_room_ofs]
	cmp	qword [rsi+chatroom_name_ofs], 0
	jne	.roomtitle
	; otherwise, our chatpanel_name_ofs is a buddy name, see if they are online
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+chatpanel_name_ofs]
	call	userdb$online
	test	eax, eax
	jnz	.nameonly
	; otherwise, add (offline) to the end
	mov	rdi, [rbx+chatpanel_name_ofs]
	mov	rsi, .offlinestr
	call	string$concat
	push	rax
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, rax
	call	tui_label$nvsettext
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rsp]
	mov	rax, [rsi]
	add	eax, 2
	mov	[rdi+tui_width_ofs], eax
	pop	rdi
	call	heap$free
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vsizechanged]

	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	pop	rbx
	epilog
cleartext .offlinestr, ' (offline)'
calign
.nameonly:
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rbx+chatpanel_name_ofs]
	call	tui_label$nvsettext
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rbx+chatpanel_name_ofs]
	mov	rax, [rsi]
	add	eax, 2
	mov	[rdi+tui_width_ofs], eax

	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vsizechanged]

	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	pop	rbx
	epilog
cleartext .roomstr, 'Room: '
calign
.roomtitle:
	push	rbx
	mov	rbx, rdi
	mov	rdi, .roomstr
	mov	rsi, [rsi+chatroom_name_ofs]
	call	string$concat
	push	rax
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, rax
	call	tui_label$nvsettext
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rsp]
	mov	rax, [rsi]
	add	eax, 2
	mov	[rdi+tui_width_ofs], eax
	pop	rdi
	call	heap$free
	mov	rdi, [rbx+tui_panel_titletext_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vsizechanged]

	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	pop	rbx
	epilog




; single argument in rdi: our chatpanel object
falign
chatpanel$draw:
	prolog	chatpanel$draw
	; burning purpose: manage our _guts_ scroll position
	; to do that, we need to iterate through the guts' children
	; and determine how much height is actually there
	cmp	dword [rdi+tui_height_ofs], 0
	je	.nothingtodo
	xor	ecx, ecx
	push	rbx
	mov	rbx, rdi
	push	rcx
	mov	rdi, [rdi+tui_panel_guts_ofs]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .heightcalc
	mov	rdx, rsp
	call	list$foreach_arg
	; so [rsp] now contains our calculated child height
	mov	rcx, [rbx+tui_panel_guts_ofs]
	mov	rdi, rbx
	mov	esi, [rsp]
	mov	edx, [rcx+tui_height_ofs]
	; we need to validate our scroll modifier
	mov	r8d, [rbx+chatpanel_scroll_ofs]
	; so, esi - edx == "bottom always visible"
	; our scroll modifier can never be positive
	; the minimum scroll amount is: -(esi-edx)
	sub	esi, edx
	neg	esi
	xor	ecx, ecx
	cmp	r8d, 0
	cmovg	r8d, ecx
	cmp	r8d, esi
	cmovl	r8d, esi
	mov	[rbx+chatpanel_scroll_ofs], r8d
	pop	rcx
	mov	rdi, [rbx+tui_panel_guts_ofs]
	; so now rcx contains the fixed actual height of the guts, which will always be greater than our height
	sub	ecx, [rdi+tui_height_ofs]
	add	ecx, r8d
	mov	dword [rdi+tui_scroll_ofs+4], ecx
	mov	rdi, rbx
	pop	rbx
	call	tui_panel$draw
	epilog
falign
.heightcalc:
	; rdi == tui_* child object, rsi == pointer to add to
	mov	edx, [rdi+tui_height_ofs]
	add	dword [rsi], edx
	ret
falign
.nothingtodo:
	epilog





; single argument in rdi: our chatpanel object
falign
chatpanel$gotfocus:
	prolog	chatpanel$gotfocus
	push	qword [rdi+chatpanel_localtext_ofs]
	ansi_colors ecx, 'lightgray', 'blue'
	mov	rdx, [rdi+tui_panel_titletext_ofs]
	mov	dword [rdx+tui_bgcolors_ofs], ecx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	epilog


; single argument in rdi: our chatpanel object
falign
chatpanel$lostfocus:
	prolog	chatpanel$lostfocus
	push	qword [rdi+chatpanel_localtext_ofs]
	ansi_colors ecx, 'lightgray', 'black'
	mov	rdx, [rdi+tui_panel_titletext_ofs]
	mov	dword [rdx+tui_bgcolors_ofs], ecx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	pop	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlostfocus]
	epilog




; two arguments: rdi == our chatpanel object, rsi == originating chatpanel
falign
chatpanel$remote_commit:
	prolog	chatpanel$remote_commit
	; all we have to do is clear the inprogress map entry for this user
	; when the next keystroke comes in, a new text editor for them will
	; get created
	push	rdi
	mov	rdi, [rdi+chatpanel_inprogress_ofs]
	mov	rsi, [rsi+chatpanel_user_ofs]
	call	unsignedmap$erase

	; possibly fire a bell if we haven't been around for a while
	mov	rdi, [rsp]
	call	chatpanel$bellcheck

	pop	rdi
	call	chatpanel$historylimit
	epilog


; two arguments: rdi == our chatpanel object, rsi == notification string
falign
chatpanel$notify:
	prolog	chatpanel$notify
	push	rbx
	mov	rbx, rdi
	; notification messages we want left justified tui_text, darker in color
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	ansi_colors edx, 'darkgray', 'black'
	ansi_colors ecx, 'darkgray', 'black'
	xor	r8d, r8d
	call	tui_text$new_di

	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 1
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2

	; and then append it to our guts, but prepended in place
	; before our localtext object
	mov	rdi, [rbx+tui_panel_guts_ofs]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdx, rax
	call	list$insert_before

	; force a redraw
	mov	rdi, [rbx+tui_panel_guts_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]

	pop	rbx
	epilog




; four arguments: rdi == our chatpanel object, esi == key, edx == esc key, rcx == originating chatpanel
falign
chatpanel$remote_keystroke:
	prolog	chatpanel$remote_keystroke
	; using our inprogress list, fire a keyevent to the right tui_text editor
	; the inprogress list is an unsigned map, key == user object pointer, value == tui_text pointer
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12d, esi
	mov	r13d, edx
	mov	r14, rcx
	mov	rdi, [rdi+chatpanel_inprogress_ofs]
	mov	rsi, [rcx+chatpanel_user_ofs]
	call	unsignedmap$find_value
	test	eax, eax
	jz	.newone
	; otherwise, simple case: fire the key event
	mov	r8d, [rdx+tui_height_ofs]
	mov	rdi, rdx
	mov	esi, r12d
	mov	edx, r13d
	mov	rcx, [rdi]
	push	rdi r8
	call	qword [rcx+tui_vkeyevent]
	pop	r8 rdi
	cmp	r8d, [rdi+tui_height_ofs]
	jne	.remote_heightchanged

	; possibly fire a bell if we haven't been around for a while
	mov	rdi, rbx
	call	chatpanel$bellcheck

	pop	r15 r14 r13 r12 rbx
	epilog
calign
.remote_heightchanged:
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcalcbounds]
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]

	; possibly fire a bell if we haven't been around for a while
	mov	rdi, rbx
	call	chatpanel$bellcheck

	pop	r15 r14 r13 r12 rbx
	epilog
cleartext .colonspace, ': '
calign
.newone:
	; no inprogress was found for this user object, create one
	; if we are in a multiperson room, we need to set the initialtext
	; to their username: 
	mov	rsi, [rbx+chatpanel_room_ofs]
	cmp	qword [rsi+chatroom_name_ofs], 0
	je	.newone_oneonone
	mov	rdx, [r14+chatpanel_user_ofs]	; the remote party
	mov	rdi, [rdx+user_username_ofs]
	mov	rsi, .colonspace
	call	string$concat
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	mov	r15, rax
	mov	rsi, rax
	ansi_colors edx, 'darkyellow', 'darkslategrey'
	ansi_colors ecx, 'darkyellow', 'darkslategrey'
	; hmm, not sure I like any of the colors really
	mov	dl, 0xeb
	mov	cl, 0xeb 
	xor	r8d, r8d
	call	tui_text$new_di
	mov	r8, [r15]

	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 1
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2
	; set its minlen so that the remote party can't edit their username
	mov	dword [rax+tui_text_minlen_ofs], r8d

	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	jmp	.newone_textready

calign
.newone_oneonone:
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	xor	esi, esi
	ansi_colors edx, 'darkyellow', 'darkslategrey'
	ansi_colors ecx, 'darkyellow', 'darkslategrey'
	; hmm, not sure I like any of the colors really
	mov	dl, 0xeb
	mov	cl, 0xeb 
	xor	r8d, r8d
	call	tui_text$new_di
	mov	r15, rax

	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 1
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2

calign
.newone_textready:
	; now, insert it into our inprogress list
	mov	rdi, [rbx+chatpanel_inprogress_ofs]
	mov	rsi, [r14+chatpanel_user_ofs]
	mov	rdx, r15
	call	unsignedmap$insert_unique

	; and then append it to our guts, but prepended in place
	; before our localtext object
	mov	rdi, [rbx+tui_panel_guts_ofs]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdx, r15
	call	list$insert_before

	; force a redraw
	mov	rdi, [rbx+tui_panel_guts_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]

	; and finally, send the keystroke off to it:
	mov	rdi, r15
	mov	esi, r12d
	mov	edx, r13d
	mov	rcx, [rdi]
	call	qword [rcx+tui_vkeyevent]

	; possibly fire a bell if we haven't been around for a while
	mov	rdi, rbx
	call	chatpanel$bellcheck

	pop	r15 r14 r13 r12 rbx
	epilog


; single argument in rdi: our chatpanel object
falign
chatpanel$historylimit:
	prolog	chatpanel$historylimit
	; just to prevent some insane amount of history accumulating and redraw penalties
	; we set our limit at chatpanel_history_max children
	mov	rsi, [rdi+tui_panel_guts_ofs]
	mov	rdx, [rsi+tui_children_ofs]
	cmp	qword [rdx+_list_size_ofs], chatpanel_history_max
	jbe	.nothingtodo
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rdx
calign
.limitloop:
	mov	rdi, r12
	call	list$pop_front
	mov	rdi, rax
	mov	rsi, [rax]
	push	rax
	call	qword [rsi+tui_vcleanup]
	pop	rdi
	call	heap$free
	cmp	qword [r12+_list_size_ofs], chatpanel_history_max
	ja	.limitloop
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vlayoutchanged]
	pop	r12 rbx
	epilog
calign
.nothingtodo:
	epilog


; single argument in rdi: our chatpanel object
falign
chatpanel$docr:
	prolog	chatpanel$docr
	push	rbx r12 r13
	mov	rbx, rdi

	mov	rdi, [rdi+chatpanel_localtext_ofs]
	; we must preserve focus:
	mov	r13d, [rdi+tui_text_focussed_ofs]
	mov	rdx, [rdi]
	mov	dword [rdi+tui_text_docursor_ofs], 0
	mov	dword [rdi+tui_text_editable_ofs], 0
	; destroy its spinner object, otherwise we'd have an invisible, running
	; spinner for each and every input line (which would still be okay, but
	; rather wasteful)
	mov	dword [rdi+tui_text_dospinner_ofs], 0
	mov	qword [rdi+tui_text_spinner_ofs], 0
	call	qword [rdx+tui_vremoveallbastards]
	; and kill its focus
	mov	rdi, [rbx+chatpanel_localtext_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlostfocus]

	; so now, create a spanking new one
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	xor	esi, esi
	ansi_colors edx, 'lightgray', 'black'
	ansi_colors ecx, 'lightgray', 'blue'
	mov	r8d, 1
	call	tui_text$new_di
	mov	r12, rax
	mov	[rbx+chatpanel_localtext_ofs], rax
	; enable multiline, right alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_docursor_ofs], 1
	mov	dword [rax+tui_text_heightlock_ofs], 1

	; hmm, not sure I like right aligned: mov	dword [rax+tui_text_align_ofs], tui_textalign_right
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	; make sure it gets focus:
	test	r13d, r13d
	jz	.skipfocus
	mov	rdi, r12
	mov	rsi, [r12]
	call	qword [rsi+tui_vgotfocus]

	mov	rdi, rbx
	call	chatpanel$historylimit

	pop	r13 r12 rbx
	epilog
calign
.skipfocus:
	pop	r13 r12 rbx
	epilog


; single argument in rdi: our chatpanel object
falign
chatpanel$bellcheck:
	prolog	chatpanel$bellcheck
	; if we haven't had a keystroke to our screne object in the last few minutes
	; do a bell
	mov	rsi, [rdi+chatpanel_screen_ofs]
	mov	rcx, [_epoll_tv_secs]
	sub	rcx, [rsi+screen_lastkey_ofs]
	cmp	ecx, 180
	jb	.nothingtodo
	; make sure we don't continually fire bell over and over again
	; set the current value to the current time - 120
	mov	rcx, [_epoll_tv_secs]
	sub	rcx, 120
	mov	qword [rsi+screen_lastkey_ofs], rcx
	mov	rdi, [rsi+screen_bell_ofs]
	mov	esi, 3
	call	tui_bell$nvdoit
	epilog
calign
.nothingtodo:
	epilog



; three arguments: rdi == our chatpanel object, esi == key, edx == esc key
falign
chatpanel$firekeyevent:
	prolog	chatpanel$firekeyevent
	; Burning purpose: the magic of keystroke sharing starts here, hahaha
	; basically, if esi/edx are valid tui_text keys, meaning, their
	; end-result == some modification of the editor, then we have to
	; share this with whomever else we are chatting with.
	; NOTE: while the tui_text editor will perfectly allow cursor movement
	; within it, because all participants aren't necessarily (or even likely)
	; to be same-sized, the remote cursormaps would never match if we allowed
	; cursor positioning in the editor to be replicated.
	; I don't really mind not having cursor abilities for sshtalk, a small
	; price to pay for the resultant effect.
	; Anyway, as a result of that, we specifically do _not_ fire cursor keys
	; Further, we do not pass enter keys to the tui_text editor either,
	; such that we can then let our text "go free" into the scrolling area
	;
	; we do support scrolling our own chatpanel up/down
	cmp	edx, 0x41			; up arrow
	je	.uparrow
	cmp	edx, 0x42			; down arrow
	je	.downarrow
	cmp	edx, 0x43			; right arrow
	je	.falseret			; bailout on left/right
	cmp	edx, 0x44			; left arrow
	je	.falseret
	cmp	esi, 0x7f			; backspace
	je	.doit
	; delete is an interesting kettle, really only useful if someone
	; shift-homes an active editor line, but it will still work so we'll
	; let it fly
	cmp	edx, 0x33			; delete
	je	.doit

	; for "effect", we can safely allow shift-end and shift-home:
	cmp	edx, 0x46			; shift-end
	je	.doit
	cmp	edx, 0x48			; shift-home
	je	.doit

	; we won't get tabs, they are ganked by the screen object
	cmp	esi, 13
	je	.cr
	cmp	esi, 32
	jb	.falseret
calign
.doit:
	; we need to replicate this keystroke to our remote parties
	; as well as let it go through to our own editor object
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12d, esi
	mov	r13d, edx
	mov	rdi, [rdi+chatpanel_localtext_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vkeyevent]

	; an interesting consequence of the way I designed the chatroom
	; goodies.... so, here's the situation:
	; for one on one chats only, when we first create the room
	; we add both users to the room users list, regardless of whether
	; said other party is online or not.
	; so, then we strike up a conversation, and then one party
	; closes the window, or drops offline, but the other party keeps
	; their window open, waits a while, then starts typign again
	; we then need to re-add the other party back to the room
	; in this scenario, otherwise, there is no way without adding
	; other crazy functionality to chatroom to keep both parties in
	; we still need to allow actual leaving of the room, such that
	; the chatrooms can in fact be torn down on close
	; So, haha, all that being said, verify participants if it is a
	; one on one
	mov	rdi, [rbx+chatpanel_room_ofs]
	cmp	qword [rdi+chatroom_name_ofs], 0
	jne	.doit_nomembercheck
	; so our chatpanel_name_ofs is the name of the other user that needs to
	; be in the room
	; we can do a insert_unique into the chatroom's user list with no penalty
	; but we have to find their user object first
	mov	rdi, [users]
	mov	rsi, [rbx+chatpanel_name_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.doit_nomembercheck		; sanity only
	mov	rdi, [rbx+chatpanel_room_ofs]
	mov	rdi, [rdi+chatroom_users_ofs]
	mov	rsi, rdx
	xor	edx, edx
	call	unsignedmap$insert_unique
	; it is fine if that fails
calign
.doit_nomembercheck:
	; replicate our keystroke to all remote parties
	mov	r14, [rbx+chatpanel_room_ofs]
	mov	r14, [r14+chatroom_users_ofs]
	; we know there is at least one user in here (ourself, haha)
	mov	r14, [r14+_avlofs_next]
calign
.doit_outer:
	; users is an unsigned map, full of user objects
	; so the [r14+_avlofs_key] is the user object itself
	; we need to iterate all tuilist entries for this user
	mov	r15, [r14+_avlofs_key]		; our user object itself
	cmp	r15, [rbx+chatpanel_user_ofs]
	je	.doit_outer_ourselves

	mov	r15, [r15+user_tuilist_ofs]	; its tuilist map
	mov	r15, [r15+_avlofs_next]		; its first node
	test	r15, r15
	jz	.doit_outer_next
calign
.doit_inner:
	; so the value at [r15+_avlofs_key] is the screen object
	mov	rdi, [r15+_avlofs_key]
	; otherwise, we have some work to do
	; we need to get a handle of the remote side's chatpanel
	; and in order to do that, we need to be calling it by
	; name, which will not necessarily be our own name unless
	; it is a chatroom...
	mov	rsi, [rbx+chatpanel_room_ofs]
	cmp	qword [rsi+chatroom_name_ofs], 0
	je	.doit_inner_ourname
	; otherwise, it is a chatroom
	mov	rsi, [rsi+chatroom_name_ofs]
	mov	edx, 1
	mov	ecx, 1
	call	screen$chatpanel_byname
	mov	rdi, rax
	mov	esi, r12d
	mov	edx, r13d
	mov	rcx, rbx
	call	chatpanel$remote_keystroke
	jmp	.doit_inner_next
calign
.doit_outer_ourselves:
        mov     r15, [r15+user_tuilist_ofs]     ; its tuilist map
        mov     r15, [r15+_avlofs_next]         ; its first node
        test    r15, r15
        jz      .doit_outer_next
calign
.doit_inner_ourselves:
        ; so the value at [r15+_avlofs_key] is the screen object
        mov     rdi, [r15+_avlofs_key]

        ; we don't replicate to our own screen object, because we already did it above
        cmp     rdi, [rbx+chatpanel_screen_ofs]
        je      .doit_inner_ourselves_next
        mov     rsi, [rbx+chatpanel_name_ofs]
        xor     edx, edx
        mov     ecx, 1
        mov     r8, [rbx+chatpanel_room_ofs]
        cmp     qword [r8+chatroom_name_ofs], 0
        cmovne  edx, ecx
        call    screen$chatpanel_byname
        mov     rdi, rax
        mov     esi, r12d
        mov     edx, r13d
        mov     rdi, [rdi+chatpanel_localtext_ofs]
	; NOTE: because we do "soft focus" (we don't force focus change when a new panel opens)
	; we have to _preserve_ whatever the previous value of focussed was, then set it back when we are done
	mov	eax, [rdi+tui_text_focussed_ofs]
	mov	dword [rdi+tui_text_focussed_ofs], 1
        mov     rcx, [rdi]
	push	rdi rax
        call    qword [rcx+tui_vkeyevent]
	pop	rax rdi
	; if eax == 0, we need to redraw it
	mov	[rdi+tui_text_focussed_ofs], eax
	test	eax, eax
	jnz	.doit_inner_ourselves_next
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
calign
.doit_inner_ourselves_next:
        mov     r15, [r15+_avlofs_next]
        test    r15, r15
        jnz     .doit_inner_ourselves
        jmp     .doit_outer_next
calign
.doit_inner_ourname:
	mov	rsi, [rbx+chatpanel_user_ofs]
	xor	edx, edx
	mov	ecx, 1
	mov	rsi, [rsi+user_username_ofs]
	call	screen$chatpanel_byname
	mov	rdi, rax
	mov	esi, r12d
	mov	edx, r13d
	mov	rcx, rbx
	call	chatpanel$remote_keystroke
	; fallthrough to doit_inner_next
calign
.doit_inner_next:
	mov	r15, [r15+_avlofs_next]
	test	r15, r15
	jnz	.doit_inner
calign
.doit_outer_next:
	mov	r14, [r14+_avlofs_next]
	test	r14, r14
	jnz	.doit_outer

	pop	r15 r14 r13 r12 rbx
	mov	eax, 1
	epilog

calign
.cr:
	; when enter is pressed, we need to let all remote parties know
	; in addition to creating a new localtext object for ourselves
	; we do _not_ pass this to our own editor
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi

	call	chatpanel$docr

	; and replicate this to all remote parties, such that they can clear their
	; in-progress list
	mov	r14, [rbx+chatpanel_room_ofs]
	mov	r14, [r14+chatroom_users_ofs]
	; we know there is at least one user in here (ourself, haha)
	mov	r14, [r14+_avlofs_next]
calign
.cr_outer:
	; users is an unsigned map, full of user objects
	; so the [r14+_avlofs_key] is the user object itself
	; we need to iterate all tuilist entries for this user
	mov	r15, [r14+_avlofs_key]		; our user object itself
	cmp	r15, [rbx+chatpanel_user_ofs]
	je	.cr_outer_ourselves

	mov	r15, [r15+user_tuilist_ofs]	; its tuilist map
	mov	r15, [r15+_avlofs_next]		; its first node
	test	r15, r15
	jz	.cr_outer_next
calign
.cr_inner:
	; so the value at [r15+_avlofs_key] is the screen object
	mov	rdi, [r15+_avlofs_key]
	; we don't replicate to our own screen object
	cmp	rdi, [rbx+chatpanel_screen_ofs]
	je	.cr_inner_next
	; otherwise, we have some work to do
	; we need to get a handle of the remote side's chatpanel
	; and in order to do that, we need to be calling it by
	; name, which will not necessarily be our own name unless
	; it is a chatroom...
	mov	rsi, [rbx+chatpanel_room_ofs]
	cmp	qword [rsi+chatroom_name_ofs], 0
	je	.cr_inner_ourname
	; otherwise, it is a chatroom
	mov	rsi, [rsi+chatroom_name_ofs]
	mov	edx, 1
	mov	ecx, 1
	call	screen$chatpanel_byname
	mov	rdi, rax
	mov	rsi, rbx
	call	chatpanel$remote_commit
	jmp	.cr_inner_next
calign
.cr_outer_ourselves:
	mov	r15, [r15+user_tuilist_ofs]	; its tuilist map
	mov	r15, [r15+_avlofs_next]		; its first node
	test	r15, r15
	jz	.cr_outer_next
calign
.cr_inner_ourselves:
	; [r15+_avlofs_key] is the screen object
	mov	rdi, [r15+_avlofs_key]
	; we don't replicate to our own screen object, because we already did it above
	cmp	rdi, [rbx+chatpanel_screen_ofs]
	je	.cr_inner_ourselves_next
	mov	rsi, [rbx+chatpanel_name_ofs]
	xor	edx, edx
	mov	ecx, 1
	mov	r8, [rbx+chatpanel_room_ofs]
	cmp	qword [r8+chatroom_name_ofs], 0
	cmovne	edx, ecx
	call	screen$chatpanel_byname
	mov	rdi, rax
	call	chatpanel$docr
calign
.cr_inner_ourselves_next:
	mov	r15, [r15+_avlofs_next]
	test	r15, r15
	jnz	.cr_inner_ourselves
	jmp	.cr_outer_next
calign
.cr_inner_ourname:
	mov	rsi, [rbx+chatpanel_user_ofs]
	xor	edx, edx
	mov	ecx, 1
	mov	rsi, [rsi+user_username_ofs]
	call	screen$chatpanel_byname
	mov	rdi, rax
	mov	rsi, rbx
	call	chatpanel$remote_commit
	; fallthrough to cr_inner_next
calign
.cr_inner_next:
	mov	r15, [r15+_avlofs_next]
	test	r15, r15
	jnz	.cr_inner
calign
.cr_outer_next:
	mov	r14, [r14+_avlofs_next]
	test	r14, r14
	jnz	.cr_outer

	pop	r15 r14 r13 r12 rbx
	mov	eax, 1
	epilog

calign
.uparrow:
	; modify our scroll property (if there is history in excess of our display)
	; no replication
	; our draw method does bounds checking on our scroll modifier, so all we need to do is subtract one
	sub	dword [rdi+chatpanel_scroll_ofs], 1
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog

calign
.downarrow:
	; modify our scroll property (if we are not already at the bottom)
	; no replication
	; our draw method does bounds checking on our scroll modifier, so all we need to do is add one
	add	dword [rdi+chatpanel_scroll_ofs], 1
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
calign
.falseret:
	xor	eax, eax
	epilog
