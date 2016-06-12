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
	; screen.inc: the sshtalk main screen tui object
	;
	; our screen is a simple tui_object, 100% x 100% so it can be resized
	; statusbar on the bottom, main chat area/useful area on the left
	; buddy list + help text on the right
	;

	; we "descend" the tui_object, so that we can set our state variables
	; correctly when we are cloned, and so that we can catch keystrokes to
	; change focus between elements, and deal with otherwise main-related
	; goodies
	;

dalign
screen$vtable:
	dq      screen$cleanup, screen$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      screen$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, screen$firekeyevent, screen$ontab, screen$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, screen$clicked

; offsets for our required variables
screen_main_ofs = tui_object_size
screen_statusbar_ofs = tui_object_size + 8
screen_buddylist_ofs = tui_object_size + 16
screen_helptext_ofs = tui_object_size + 24
screen_bell_ofs = tui_object_size + 32
screen_user_ofs = tui_object_size + 40
screen_focus_ofs = tui_object_size + 48
screen_modal_ofs = tui_object_size + 56
screen_modalalert_ofs = tui_object_size + 64
screen_start_ofs = tui_object_size + 72
screen_lastkey_ofs = tui_object_size + 80

screen_size = tui_object_size + 88


	; we also override the datagrid vtable for itemselected (aka open a chat panel)
dalign
buddylist$vtable:
	dq      tui_object$cleanup, tui_datagrid$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; our itemselected:
	dq	screen$buddyselected


	; for our main chat/screen area, we need to override tui_object$simple_vtable such that when we get resized, we can retile its children:
dalign
main$vtable:
	dq      tui_object$cleanup, tui_background$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, main$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked



	; to log connects w/ username/ip, we need a global formatter to reuse
	; to log connects w/ just username, we need another formatter
 	; to log disconnects w/ durations, we need a global formatter to reuse
globals
{
	connect_fmt	dq	0
	connect_noip_fmt	dq	0
	disco_fmt	dq	0
}

; no arguments, initialises the above
falign
screen$init_formatters:
	prolog	screen$init_formatters
	xor	edi, edi
	call	formatter$new
	mov	[connect_fmt], rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [connect_fmt]
	mov	rsi, .conn1
	call	formatter$add_static
	mov	rdi, [connect_fmt]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [connect_fmt]
	mov	rsi, .conn3
	call	formatter$add_static
	mov	rdi, [connect_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [connect_fmt]
	mov	rsi, .conn4
	call	formatter$add_static
	mov	rdi, [connect_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned

	xor	edi, edi
	call	formatter$new
	mov	[connect_noip_fmt], rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [connect_noip_fmt]
	mov	rsi, .conn2
	call	formatter$add_static
	mov	rdi, [connect_noip_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [connect_noip_fmt]
	mov	rsi, .conn4
	call	formatter$add_static
	mov	rdi, [connect_noip_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	


	xor	edi, edi
	call	formatter$new
	mov	[disco_fmt], rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [disco_fmt]
	mov	rsi, .disco1
	call	formatter$add_static
	mov	rdi, [disco_fmt]
	mov	esi, 1			; second resolution
	xor	edx, edx		; no fractional digits
	call	formatter$add_duration

	epilog
cleartext .conn1, ' connected from '
cleartext .conn2, ' connected at '
cleartext .conn3, ' at '
cleartext .conn4, 'x'
cleartext .disco1, ' disconnected, session time: '




; no arguments, returns a new screen object
falign
screen$new:
	prolog	screen$new

	; heheh, this function would be why markup was invented :-) someday when I am bored I should create a markup
	; parser for the tui_* objects, to make the process you see below much faster/easier, hahah

	push	rbx
	mov	edi, screen_size
	call	heap$alloc
	mov	rbx, rax
	mov	rdi, rax
	mov	qword [rax], screen$vtable
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	
	; its default layout is vertical, so add to that our "main" area, also 100% x 100%
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	; save the pointer to our main area for later reference
	; NOTE: we overwrite this pointer later when we create the "real" main
	mov	[rbx+screen_main_ofs], rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	
	; add that to our actual children list
	mov	rdi, rbx
	mov	rsi, [rbx+screen_main_ofs]

	; before we add it, set its layout to horizontal, because it will contain two more columns
	mov	dword [rsi+tui_layout_ofs], tui_layout_horizontal
	mov	rdx, [rdi]
	; NOTE: we know perfectly well that the main screen is a tui_object, so we really
	; don't need to call its "virtual" appendchild method, but for consistency throughout
	; all of the tui_* goods, practice makes perfect
	call	qword [rdx+tui_vappendchild]

	; next up, our full width statusbar on the bottom
	call	statusbar$new
	mov	[rbx+screen_statusbar_ofs], rax
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; set its statustext to our sshtalk goods:
	mov	rdi, [rbx+screen_statusbar_ofs]
	mov	rsi, .statustext
	call	tui_statusbar$nvsettext

	; so now, we have a dynamically sized main area and our statusbar
	; we need to divvy up the full-width main area into two separate ones
	; the right column being fixed width, the left being our dynamic area
	; that will be our main useful area

	; the main we created above we already set its layout to horizontal
	; so all it needs is three children:
	; another absolute layout 100% x 100% tui_background,
	; a vertical line, and our right column
	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	mov	rdi, rax
	; hangon to this pointer for our final move into the screen_main_ofs
	push	rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	esi, ' '		; background fill char
	ansi_colors edx, 'gray', 'black'
	call	tui_background$init_dd

	; add that to the previous main we created before
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, [rsp]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; vertical line is next, full height
	movq	xmm0, [_math_onehundred]
	ansi_colors edi, 'gray', 'black'
	call	tui_vline$new_d

	; add that to the previous main we created before
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; and now our fixed-width right column, that will contain our
	; buddy list, and help text
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	; hangon to this pointer for later so we can add to it
	push	rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 24
	call	tui_object$init_id

	; add that to the previous main we created before
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, [rsp]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; our right-hand column needs to contain a dynamic height
	; datagrid for our buddylist, and a heightlocked text area
	; below it
	mov	edi, 24
	movq	xmm0, [_math_onehundred]
	ansi_colors esi, 'black', 'lightgray'
	ansi_colors edx, 'lightgray', 'black'
	ansi_colors ecx, 'lightgray', 'blue'
	call	tui_datagrid$new_id
	; make sure to override its virtual method table so we get itemselected events
	mov	qword [rax], buddylist$vtable
	; set the user field for the datagrid to point back to us so that we don't have
	; to walk up the parent tree to find the real screen object during itemselect
	mov	[rax+tui_dguser_ofs], rbx

	; set our initial focus to the buddylist:
	mov	[rbx+screen_focus_ofs], rax

	; also, clear our modal pointer
	mov	qword [rbx+screen_modal_ofs], 0
	mov	qword [rbx+screen_modalalert_ofs], 0

	; save that so we can reference it directly later:
	mov	[rbx+screen_buddylist_ofs], rax

	; add that to our right hand column:
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; the DG needs headers:
	mov	rdi, [rbx+screen_buddylist_ofs]
	mov	rsi, .buddylabel
	movq	xmm0, [_math_onehundred]
	mov	edx, tui_textalign_left
	mov	rcx, .buddystr
	call	tui_datagrid$nvaddproperty_d

	mov	rdi, [rbx+screen_buddylist_ofs]
	mov	rsi, .onlinelabel
	mov	edx, 7
	mov	ecx, tui_textalign_right
	mov	r8, .onlinestr
	call	tui_datagrid$nvaddproperty_i

	; we need a tui_bell object
	mov	edi, 24
	mov	esi, 1
	ansi_colors edx, 'lightgray', 'black'
	call	tui_bell$new
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	; save that so we can mess with it later:
	mov	[rbx+screen_bell_ofs], rax
	call	qword [rdx+tui_vappendchild]

	; now we need our heightlocked help text area below that
	mov	edi, 24
	mov	esi, 7
	mov	rdx, .helptext
	ansi_colors ecx, 'lightgray', 'black'
	ansi_colors r8d, 'lightgray', 'black'
	xor	r9d, r9d
	call	tui_text$new_ii
	; disable editing, cursor
	mov	dword [rax+tui_text_editable_ofs], 0
	mov	dword [rax+tui_text_docursor_ofs], 0
	; enable multiline
	mov	dword [rax+tui_text_multiline_ofs], 1
	; enable heightlock in case we change the text later
	mov	dword [rax+tui_text_heightlock_ofs], 1
	; and enable wordwrap
	mov	dword [rax+tui_text_wrap_ofs], 2

	; save that so we can reference it directly later:
	mov	[rbx+screen_helptext_ofs], rax

	; now, add that to our right hand column
	pop	rdi
	mov	rsi, [rbx+screen_helptext_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	
	; so now that we are all done adding our children
	; swap the main with the "real" main
	pop	rdi
	mov	[rbx+screen_main_ofs], rdi
	; set its vtable to our custom one so we can retile on resize
	mov	qword [rdi], main$vtable

	; clear the user object:
	mov	qword [rbx+screen_user_ofs], 0

	call	timestamp
	movq	rax, xmm0
	mov	[rbx+screen_start_ofs], rax

	; last but not least, set our lastkey so that window opens
	; don't cause a bell
	; NOTE: the epoll layer always updates the globals _epoll_tv_secs/_epoll_tv_usecs
	; during each and every fire of epoll$iteration, so it is safe to use it without
	; actually calling a timestamp, since we know we were called from within an epoll
	; loop
	mov	rcx, [_epoll_tv_secs]
	mov	[rbx+screen_lastkey_ofs], rcx
	
	mov	rax, rbx
	pop	rbx
	epilog
cleartext .statustext, 'sshtalk v1.16 ',0xa9,' 2015, 2016 2 Ton Digital'
cleartext .buddylabel, 'Buddy'
cleartext .buddystr, 'buddy'
cleartext .onlinelabel, 'Status'
cleartext .onlinestr, 'status'
cleartext .helptext, ' C-a - Add Buddy',10,' C-r - Remove Buddy',10,' C-j - Join/Create Room',10,' C-w - Close Chat',10,' Up/Dn - Scroll Chat',10,' C-c - Exit',10,' Tab - Input Focus'



; NOTE NOTE NOTE: because sshtalk uses tui_simpleauth, we have a "special privilege" unlike the rest of the
; tui_objects... and that is: our username that was authenticated gets passed here to the clone in rsi, as well as
; the "real" tui_simpleauth parent object (which is a tui_ssh_renderer object in this case) in rdx

; three arguments: rdi == our screen object to clone, rsi == username that we are firing up, rdx == tui_ssh_renderer object we are about to belong to
falign
screen$clone:
	prolog	screen$clone
	; NOTE: since we don't have any dynamic content to clone necessarily, we just create a spanking new one
	; preserve our username
	push	rbx
	mov	rbx, rdx
	push	rsi
	call	screen$new

	; so now, we have to associate our screen object with the userdb user object
	mov	rdi, [users]
	mov	rsi, [rsp]
	mov	[rsp], rax
	call	stringmap$find_value
	; we know for certain that it exists, so no checking is necessary
	mov	rsi, [rsp]
	mov	[rsi+screen_user_ofs], rdx
	; so now, three things need to happen...
	; first up: add our newly created screen object to our user's tui map
	mov	rdi, [rdx+user_tuilist_ofs]
	call	unsignedmap$insert_unique
	; next up: update our own buddy list
	mov	rdi, [rsp]
	call	screen$updatebuddies
	; next up: we need to let everyone in our own notifies list that we are online
	mov	rdi, [rsp]
	mov	rsi, .notify
	mov	rdi, [rdi+screen_user_ofs]
	mov	rdi, [rdi+user_notifies_ofs]
	call	stringmap$foreach

	; hide our cursor:
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vhidecursor]

	; update the statusbar now that we have added ourselves to the tuilist
	mov	rdi, [rsp]
	mov	rdi, [rdi+screen_statusbar_ofs]
	call	statusbar$timer

	; the initial cursor should be hidden:
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vhidecursor]

	; the very topmost object that got passed to us in rdx, is a tui_ssh_renderer object
	; get the base from there
	mov	rdi, [rbx+tui_ssh_renderer_base_ofs]
	mov	edx, [rdi+tui_ssh_raddrlen_ofs]
	cmp	edx, sockaddr_in_size
	jne	.simplelog
	push	r12
	lea	rsi, [rdi+tui_ssh_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	mov	r12, rax
	mov	rcx, [rsp+8]

	mov	rdi, [connect_fmt]
	mov	rsi, [rcx+screen_user_ofs]
	mov	rdx, r12
	mov	rsi, [rsi+user_username_ofs]
	mov	ecx, [rbx+tui_width_ofs]
	mov	r8d, [rbx+tui_height_ofs]
	call	formatter$doit
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	edi, log_notice
	mov	rsi, r12
	call	syslog
	mov	rdi, r12
	call	heap$free

	pop	r12
	pop	rax rbx
	epilog
calign
.simplelog:
	mov	rcx, [rsp]
	mov	rdi, [connect_noip_fmt]
	mov	rsi, [rcx+screen_user_ofs]
	mov	rsi, [rsi+user_username_ofs]
	mov	edx, [rbx+tui_width_ofs]
	mov	ecx, [rbx+tui_height_ofs]
	call	formatter$doit
	mov	edi, log_notice
	mov	rsi, rax
	push	rax
	call	syslog
	pop	rdi
	call	heap$free

	pop	rax rbx
	epilog
falign
.notify:
	; two arguments: rdi == string username, rsi == user object
	; so, for every object in this user's tuilist, update their buddy list
	mov	rdi, [rsi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach
	ret



; single argument in rdi: our screen object to cleanup
falign
screen$cleanup:
	prolog	screen$cleanup
	; the reason we don't just use tui_object's cleanup is so that we can update
	; everyone in our notifies list of our absence
	; once we do that, we proceed with the normal tui_object$cleanup

	; due to the auto-leave functionality of the chatpanel object, we need
	; to make sure we destroy all our children _first_
	; and then deal with our user object and notifies
	push	rbx
	mov	rbx, rdi
	; log our disconnect
	call	timestamp
	mov	rdi, [disco_fmt]
	mov	rsi, [rbx+screen_user_ofs]
	subsd	xmm0, [rbx+screen_start_ofs]
	mov	rsi, [rsi+user_username_ofs]
	call	formatter$doit
	push	rax
	mov	edi, log_notice
	mov	rsi, rax
	call	syslog
	pop	rdi
	call	heap$free

	mov	rdi, rbx
	call	tui_object$cleanup
	mov	rsi, rbx
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_tuilist_ofs]
	call	unsignedmap$erase
	; next up: let everyone in our notifies list know that we are gone
	mov	rdi, [rbx+screen_user_ofs]
	mov	rsi, .notify
	mov	rdi, [rdi+user_notifies_ofs]
	call	stringmap$foreach
	pop	rbx
	epilog
falign
.notify:
	; two arguments: rdi == string username, rsi == user object
	; for every object in this user's tuilist, update their buddy list
	mov	rdi, [rsi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach
	ret



; single argument in rdi: our main container object
falign
main$sizechanged:
	prolog	main$sizechanged
	push	rdi
	call	tui_object$sizechanged
	pop	rdi
	call	tui_object$nvtile
	epilog




; single argument in rdi: our screen object
falign
screen$showhidecursor:
	prolog	screen$showhidecursor
	; burning purpose: depending on what has focus, show or hide the cursor
	cmp	qword [rdi+screen_modal_ofs], 0
	je	.nomodal
	; otherwise, we have a modal dialog open, see if it is alert or not
	cmp	dword [rdi+screen_modalalert_ofs], 1
	je	.hideit
	jmp	.showit
calign
.nomodal:
	mov	rsi, [rdi+screen_focus_ofs]
	cmp	rsi, [rdi+screen_buddylist_ofs]
	je	.hideit
	; otherwise, show it
calign
.showit:
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]
	epilog

calign
.hideit:
	mov	rsi, [rdi]
	call	qword [rsi+tui_vhidecursor]
	epilog





; single argument in rdi: our screen object
falign
screen$updatebuddies:
	prolog	screen$updatebuddies
	; burning purpose: tui_datagrid needs JSON data, walk through our buddylist
	; and create json objects for each one, then pass that to our buddylist DG
	; NOTE: we want our online buddies listed alphabetically, THEN our offline
	push	rbx r12
	mov	rbx, rdi
	; create an unnamed jsonarray to do our deed
	call	string$new
	mov	rdi, rax
	call	json$newarray_nocopy
	mov	rdi, [rbx+screen_user_ofs]
	mov	r12, rax
	mov	rdi, [rdi+user_buddylist_ofs]
	mov	rsi, .addjson_online
	mov	rdx, rax
	call	stringmap$foreach_arg
	mov	rdi, [rbx+screen_user_ofs]
	mov	rsi, .addjson_offline
	mov	rdi, [rdi+user_buddylist_ofs]
	mov	rdx, r12
	call	stringmap$foreach_arg

	; so now, we have a json array object sitting in r12
	; tui_datagrid$nvsetdata will assume ownership of the json array
	mov	rdi, [rbx+screen_buddylist_ofs]
	mov	rsi, r12
	call	tui_datagrid$nvsetdata

	; last but not least, go through our open chatpanels and titleupdate them
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, chatpanel$titleupdate
	mov	rdi, [rdi+tui_children_ofs]
	call	list$foreach

	pop	r12 rbx
	epilog
cleartext .buddystr, 'buddy'
cleartext .statusstr, 'status'
cleartext .onlinestr, 'online'
cleartext .offlinestr, 'offline'
falign
.addjson_online:
	; three arguments: rdi == string buddy name, rsi == user object, rdx == json array to add to
	; our avl tree stores its nodecount in _avlofs_right, make sure this user's tuilist is not empty
	mov	rcx, [rsi+user_tuilist_ofs]
	cmp	qword [rcx+_avlofs_right], 0
	je	.addjson_nothingtodo
	push	rdi rsi rdx
	; create an unnamed json object to hold our goods:
	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy
	; we need two values added to that object: buddy, status
	push	rax
	; [rsp] == our json object
	; [rsp+8] == json array
	; [rsp+16] == user object
	; [rsp+24] == string buddy name
	mov	rdi, .buddystr
	mov	rsi, [rsp+24]
	call	json$newvalue
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	mov	rdi, .statusstr
	mov	rsi, .onlinestr
	call	json$newvalue
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	; now add our json object to the json array
	pop	rsi rdi
	call	json$appendchild
	add	rsp, 16
	ret
falign
.addjson_offline:
	; same as above, only we make sure they are offline
	mov	rcx, [rsi+user_tuilist_ofs]
	cmp	qword [rcx+_avlofs_right], 0
	jne	.addjson_nothingtodo
	push	rdi rsi rdx
	; create an unnamed json object to hold our goods:
	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy
	; we need two values added to that object: buddy, status
	push	rax
	; [rsp] == our json object
	; [rsp+8] == json array
	; [rsp+16] == user object
	; [rsp+24] == string buddy name
	mov	rdi, .buddystr
	mov	rsi, [rsp+24]
	call	json$newvalue
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	mov	rdi, .statusstr
	mov	rsi, .offlinestr
	call	json$newvalue
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	; now add our json object to the json array
	pop	rsi rdi
	call	json$appendchild
	add	rsp, 16
	ret
calign
.addjson_nothingtodo:
	ret




; three arguments: rdi == screen object, rsi == string name of chatpanel, edx == bool as to whether it is a room or not
falign
screen$chatpanel_find:
	prolog	screen$chatpanel_find
	; our mission is to find and return the chatpanel, if it doesn't exist we return null
	; (unlike chatpanel_byname which will add/create one)
	mov	rcx, [rdi+screen_main_ofs]
	push	rbx r12 r13 r14
	mov	rax, [rcx+tui_children_ofs]
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	mov	r14, [rax+_list_first_ofs]
	test	r14, r14
	jz	.nullret
calign
.search:
	mov	rsi, [r14]			; the chatpanel object
	; we need to do a string compare of the names
	mov	rdi, r12
	mov	rsi, [rsi+chatpanel_name_ofs]
	call	string$equals
	test	eax, eax
	jnz	.found
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jnz	.search
calign
.nullret:
	xor	eax, eax
	pop	r14 r13 r12 rbx
	epilog
calign
.found:
	; the bool sitting in r13d has to be checked, in case someone
	; wants to join a room that has the same name as a buddy
	mov	rdi, [r14]
	mov	rsi, [rdi+chatpanel_room_ofs]
	mov	rdx, [rsi+chatroom_name_ofs]
	; if it is a room, rdx will be nonzero
	test	r13d, r13d
	jz	.found_checkbuddy
	; else, we need it to be a room
	test	rdx, rdx
	jz	.notfound
	mov	rax, rdi			; the chatpanel object
	pop	r14 r13 r12 rbx
	epilog
calign
.found_checkbuddy:
	; we need it to be a buddy chat
	test	rdx, rdx
	jnz	.notfound
	mov	rax, rdi
	pop	r14 r13 r12 rbx
	epilog
calign
.notfound:
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jz	.nullret
	jmp	.search





; three arguments: rdi == screen object, rsi == string name of chatpanel, edx == bool as to whether it is a room or not, ecx == bool for special focus
; NOTE on ecx: when buddyselected calls this, ecx == 0, so we don't do any special focussing, when it is called from remote_keystroke, ecx == 1
; in which case we try and "intelligently" mess with focus, primarily: if we didn't create a new window, we don't modify focus at all
; if we created a new one, and we were the first and only chat window, then we set the focus to the newly created window
falign
screen$chatpanel_byname:
	prolog	screen$chatpanel_byname
	; our mission is to find (and create if it doesn't exist) and return the chatpanel
	; all our chatpanels live in the main window, and are its exclusive children
	push	rbx r12 r13 r14 r15
	mov	r15d, ecx
	mov	rcx, [rdi+screen_main_ofs]
	mov	rax, [rcx+tui_children_ofs]
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, edx
	mov	r14, [rax+_list_first_ofs]
	test	r14, r14
	jz	.createone
calign
.search:
	mov	rsi, [r14]			; the chatpanel object
	; we need to do a string compare of the names
	mov	rdi, r12
	mov	rsi, [rsi+chatpanel_name_ofs]
	call	string$equals
	test	eax, eax
	jnz	.found
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jnz	.search
calign
.createone:
	; list was empty, or we didn't find it, so fire up a new one
	mov	rdi, r12
	call	chatpanel$new
	mov	rdi, [rbx+screen_user_ofs]
	mov	r14, rax
	mov	[r14+chatpanel_user_ofs], rdi
	mov	[r14+chatpanel_screen_ofs], rbx
	
	test	r13d, r13d
	jnz	.createone_room
	; else, 1:1 buddy chat, so do the necessary setup

	; if this user is already online, and already has a chatpanel open
	; then it is possible that there is already a chatroom in existence
	; for this chat

	; so the string name in r12 is actually the buddy's name, find it
	; in the users map, and see if that user already has one fired up
	mov	rdi, [users]
	mov	rsi, r12
	call	stringmap$find_value
	; all buddy names _do_ exist in the users map, no checking is required
	; now, we need to walk their tui list and see if we can find
	; a chatpanel with our username in it
	mov	r12, rdx
	mov	rdx, [rdx+user_tuilist_ofs]
	mov	r13, [rdx+_avlofs_next]		; first node in the tree
	test	r13, r13
	jz	.createone_buddy
calign
.createone_othersearch:
	; the key of the tuilist map is their screen object
	mov	rsi, [rbx+screen_user_ofs]
	mov	rdi, [r13+_avlofs_key]
	mov	rsi, [rsi+user_username_ofs]
	xor	edx, edx
	call	screen$chatpanel_find
	test	rax, rax
	jnz	.createone_buddy_found
	mov	r13, [r13+_avlofs_next]
	test	r13, r13
	jnz	.createone_othersearch
calign
.createone_buddy:
	xor	edi, edi
	xor	esi, esi
	call	chatroom$new
	mov	[r14+chatpanel_room_ofs], rax
	mov	rdi, rax
	mov	rsi, [rbx+screen_user_ofs]
	mov	rdx, rbx
	call	chatroom$join
	; now, the _remote_ party of the chat also needs to be added
	; we don't need to add a tui to it
	mov	rdi, [r14+chatpanel_room_ofs]
	mov	rsi, r12
	xor	edx, edx
	call	chatroom$join


	mov	rdi, r14
	call	chatpanel$titleupdate
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	test	r15d, r15d
	jz	.createone_buddy_skipfocus
	; make sure the panel we created does _not_ have focus (chatpanel$new defaults to focussed)
	mov	rdi, r14
	mov	rsi, [r14]
	call	qword [rsi+tui_vlostfocus]
	; see commentary atop for what we are up to here:
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, [rdi+tui_children_ofs]
	cmp	qword [rsi+_list_size_ofs], 1
	jne	.createone_buddy_skipfocus
	; otherwise, we were the one and only, set our focus to it
	mov	rdi, [rbx+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx

	mov	rdx, [rdi]
	call	qword [rdx+tui_vredraw]
	; our chatpanel is in r14 still, set our focus to it
	mov	[rbx+screen_focus_ofs], r14
	mov	rdi, r14
	mov	rsi, [r14]
	call	qword [rsi+tui_vgotfocus]
	; deal with our cursor:
	mov	rdi, rbx
	call	screen$showhidecursor

calign
.createone_buddy_skipfocus:
	; retile the display
	mov	rdi, [rbx+screen_main_ofs]
	mov	esi, 1				; horizontal tile preferred
	call	tui_object$nvtile
	mov	rax, r14
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.createone_buddy_found:
	; so, we found a chatpanel open somewhere else that is already pointed to us
	; and it is sitting in rax, so its chatpanel_room_ofs object
	; is the one that we need to hook to our own
	mov	rcx, [rax+chatpanel_room_ofs]
	mov	[r14+chatpanel_room_ofs], rcx
	mov	rdi, rcx
	mov	rsi, [rbx+screen_user_ofs]
	mov	rdx, rbx
	call	chatroom$join

	mov	rdi, r14
	call	chatpanel$titleupdate
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	test	r15d, r15d
	jz	.createone_buddy_skipfocus
	; make sure the panel we created does _not_ have focus (chatpanel$new defaults to focussed)
	mov	rdi, r14
	mov	rsi, [r14]
	call	qword [rsi+tui_vlostfocus]
	; see commentary atop for what we are up to here:
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, [rdi+tui_children_ofs]
	cmp	qword [rsi+_list_size_ofs], 1
	jne	.createone_buddy_skipfocus
	; otherwise, we were the one and only, set our focus to it
	mov	rdi, [rbx+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx

	mov	rdx, [rdi]
	call	qword [rdx+tui_vredraw]
	; our chatpanel is in r14 still, set our focus to it
	mov	[rbx+screen_focus_ofs], r14
	mov	rdi, r14
	mov	rsi, [r14]
	call	qword [rsi+tui_vgotfocus]
	; deal with our cursor:
	mov	rdi, rbx
	call	screen$showhidecursor

	; retile the display
	mov	rdi, [rbx+screen_main_ofs]
	mov	esi, 1				; horizontal tile preferred
	call	tui_object$nvtile
	mov	rax, r14
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.createone_room:
	; name sitting in r12 is a normal chatroom, see if it already exists:
	; we already have a chatpanel in r14
	mov	rdi, [chatrooms]
	mov	rsi, r12
	call	stringmap$find_value
	test	eax, eax
	jnz	.createone_room_found
	; otherwise, no such room exists, create one
	mov	rdi, r12
	xor	esi, esi
	call	chatroom$new
	mov	rdx, rax
	; fallthrough to finish the deed
calign
.createone_room_found:
	mov	[r14+chatpanel_room_ofs], rdx
	mov	rdi, rdx
	mov	rsi, [rbx+screen_user_ofs]
	mov	rdx, rbx
	call	chatroom$join
	; join calls unsignedmap$insert_unique, which returns us a bool in eax as to whether we succeeded or not
	push	rax
	
	mov	rdi, r14
	call	chatpanel$titleupdate
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, r14
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	test	r15d, r15d
	jz	.createone_room_skipfocus
	; make sure the panel we created does _not_ have focus (chatpanel$new defaults to focussed)
	mov	rdi, r14
	mov	rsi, [r14]
	call	qword [rsi+tui_vlostfocus]
	; see commentary atop for what we are up to here:
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, [rdi+tui_children_ofs]
	cmp	qword [rsi+_list_size_ofs], 1
	jne	.createone_room_skipfocus
	; otherwise, we were the one and only, set our focus to it
	mov	rdi, [rbx+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx

	mov	rdx, [rdi]
	call	qword [rdx+tui_vredraw]
	; our chatpanel is in r14 still, set our focus to it
	mov	[rbx+screen_focus_ofs], r14
	mov	rdi, r14
	mov	rsi, [r14]
	call	qword [rsi+tui_vgotfocus]
	; deal with our cursor:
	mov	rdi, rbx
	call	screen$showhidecursor
calign
.createone_room_skipfocus:
	; retile the display
	mov	rdi, [rbx+screen_main_ofs]
	mov	esi, 1				; horizontal tile preferred
	call	tui_object$nvtile

	; if we actually inserted ourselves uniquely into the chatroom userlist, do a notify
	pop	rax
	test	eax, eax
	jz	.createone_room_skipnotify

	; last but not least, we need to send notifies
	mov	rdi, [r14+chatpanel_room_ofs]
	mov	rsi, [rbx+screen_user_ofs]
	call	chatroom$join_notify

calign
.createone_room_skipnotify:

	mov	rax, r14
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.found:
	; the bool sitting in r13d has to be checked, in case someone
	; wants to join a room that has the same name as a buddy
	mov	rdi, [r14]
	mov	rsi, [rdi+chatpanel_room_ofs]
	mov	rdx, [rsi+chatroom_name_ofs]
	; if it is a room, rdx will be nonzero
	test	r13d, r13d
	jz	.found_checkbuddy
	; else, we need it to be a room
	test	rdx, rdx
	jz	.notfound
	mov	rax, rdi			; the chatpanel object
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.found_checkbuddy:
	; we need it to be a buddy chat
	test	rdx, rdx
	jnz	.notfound
	mov	rax, rdi
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.notfound:
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jz	.createone
	jmp	.search





; two arguments: rdi == the tui_datagrid object, rsi == the json object that was selected
falign
screen$buddyselected:
	prolog	screen$buddyselected
	; we get called when enter is pressed in our buddylist tui_datagrid
	; our tui_dguser_ofs contains the screen object that this datagrid belongs to

	; two scenarios here:
	; if no chatpanel exists for the buddy selected, fire up a new one, set focus to it
	; and be done.
	; if a chatpanel exists, focus it and be done
	; either way, our dg is losing focus
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi

	; since I didn't bother to deal with focus/unfocussed tui_datagrid goods, we have
	; to fake it... so change the selection color in the dg so there is a visual
	; indication it doesn't have focus
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx

	mov	rdx, [rdi]
	call	qword [rdx+tui_vredraw]

	; next up: extract the buddy name from the selected item json
	mov	rdi, r12
	mov	rsi, .buddystr
	call	json$getvaluebyname
	; it should have returned us with a jsonvalue object, whos json_value_ofs is the string we want
	mov	rdi, [rbx+tui_dguser_ofs]		; our screen object
	mov	rsi, [rax+json_value_ofs]
	xor	edx, edx
	xor	ecx, ecx
	call	screen$chatpanel_byname
	; that should have returned us the chatpanel we were after, set input focus to that
	mov	rdi, [rbx+tui_dguser_ofs]
	mov	[rdi+screen_focus_ofs], rax

	; and call its gotfocus method
	mov	rdi, rax
	mov	rsi, [rax]
	call	qword [rsi+tui_vgotfocus]

	mov	rdi, [rbx+tui_dguser_ofs]
	call	screen$showhidecursor

	pop	r12 rbx
	epilog
cleartext .buddystr, 'buddy'





; three arguments: rdi == our screen object, esi == key, edx == esc_key
falign
screen$keyevent:
	prolog	screen$keyevent
	xor	eax, eax
	epilog




; two arguments: rdi == our screen object, rsi == tui_object that got clicked
; NOTE: these really are only ever generated from modal tui_alert dialogs
; so we can take appropriate action thereof:
falign
screen$clicked:
	prolog	screen$clicked
	mov	qword [rdi+screen_modal_ofs], 0
	mov	rsi, [rdi]
	call	qword [rsi+tui_vremoveallbastards]
	epilog




; in order to capture onenter from tui_textbox during join/create room events
; we need to override its vtable:
dalign
screen_newroom$vtable:
	dq      tui_panel$cleanup, tui_panel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
	dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; and one for our onenter handling, descendents should override if they are interested
	dq      screen_newroom$onenter


; and the same again for our add buddy tui_textbox
dalign
screen_addbuddy$vtable:
	dq      tui_panel$cleanup, tui_panel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
	dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; and one for our onenter handling, descendents should override if they are interested
	dq      screen_addbuddy$onenter

; and the same once more for our remove buddy tui_textbox
dalign
screen_removebuddy$vtable:
	dq      tui_panel$cleanup, tui_panel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
	dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; and one for our onenter handling, descendents should override if they are interested
	dq      screen_removebuddy$onenter




; single argument in rdi == the tui_textbox panel object for our join/create room entry
falign
screen_newroom$onenter:
	prolog	screen_newroom$onenter
	; so our actual tui_text editor is sitting in [rdi+tui_panel_user_ofs]
	push	rbx r12 r13
	mov	rbx, [rdi+tui_parent_ofs]	; our screen object
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_text$nvgettext
	mov	r12, rax
	cmp	qword [rax], 0
	je	.closeit
	; otherwise, fire up a chatpanel for it or focus one we already have:
	mov	rdi, rbx
	mov	rsi, r12
	mov	edx, 1
	xor	ecx, ecx
	call	screen$chatpanel_byname
	; we have to specifically modify focus
	mov	r13, [rbx+screen_focus_ofs]
	mov	[rbx+screen_focus_ofs], rax

	; and call its gotfocus method
	mov	rdi, rax
	mov	rsi, [rax]
	call	qword [rsi+tui_vgotfocus]
	; lose focus to whatever used ot have it
	mov	rdi, r13
	mov	rsi, [r13]
	call	qword [rsi+tui_vlostfocus]

	; show/hide the cursor
	mov	rdi, rbx
	call	screen$showhidecursor

	; if r13 == the buddylist, fake our lostfocus:
	cmp	r13, [rbx+screen_buddylist_ofs]
	jne	.closeit
	mov	rdi, r13
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vredraw]
	; fallthrough to closeit
calign
.closeit:
	mov	rdi, r12
	call	heap$free
	mov	qword [rbx+screen_modal_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vremoveallbastards]
	pop	r13 r12 rbx
	epilog



; single argument in rdi == the tui_textbox panel object for our remove buddy dialog
falign
screen_removebuddy$onenter:
	prolog	screen_removebuddy$onenter
	; so our actual tui_text editor is sitting in [rdi+tui_panel_user_ofs]
	push	rbx r12
	mov	rbx, [rdi+tui_parent_ofs]	; our screen object
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_text$nvgettext
	mov	r12, rax
	cmp	qword [rax], 0
	je	.closeit
	; otherwise, pass it straight to removebuddy
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_username_ofs]
	mov	rsi, r12
	call	userdb$removebuddy
	test	rax, rax
	jnz	.errormsg
	; success, so we need to update ALL our tuis (if we are logged in multiple times,
	; this action needs to be replicated)
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach
	jmp	.closeit
calign
.errormsg:
	push	rax
	mov	rdi, r12
	call	heap$free
	pop	r12
	mov	qword [rbx+screen_modal_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vremoveallbastards]
	; add our error message dialog
	mov	rdi, .removebuddystr
	mov	rsi, r12
	mov	edx, tui_alert_ok
	; panel/title colors
	ansi_colors ecx, 'black', 'cyan'
	; button colors
	ansi_colors r8d, 'lightgray', 'black'
	; focus button colors
	ansi_colors r9d, 'yellow', 'blue'
	call	tui_alert$new
	; save the modal pointer for focus
	mov	rdi, rbx
	mov	[rbx+screen_modal_ofs], rax
	mov	dword [rbx+screen_modalalert_ofs], 1
	mov	rsi, rax
	mov	rdx, [rdi]
	; set its bastardglue so that it ends up centered
	mov	dword [rax+tui_bastardglue_ofs], 1
	mov	dword [rax+tui_horizalign_ofs], tui_align_center
	mov	dword [rax+tui_vertalign_ofs], tui_align_middle
	call	qword [rdx+tui_vappendbastard]
	; deal with our cursor:
	mov	rdi, rbx
	call	screen$showhidecursor
	pop	r12 rbx
	epilog
cleartext .removebuddystr, 'RemoveBuddy'
calign
.closeit:
	mov	rdi, r12
	call	heap$free
	mov	qword [rbx+screen_modal_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vremoveallbastards]
	pop	r12 rbx
	epilog





; single argument in rdi == the tui_textbox panel object for our add buddy dialog
falign
screen_addbuddy$onenter:
	prolog	screen_addbuddy$onenter
	; so our actual tui_text editor is sitting in [rdi+tui_panel_user_ofs]
	push	rbx r12
	mov	rbx, [rdi+tui_parent_ofs]	; our screen object
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_text$nvgettext
	mov	r12, rax
	cmp	qword [rax], 0
	je	.closeit
	; otherwise, pass it straight to addbuddy
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_username_ofs]
	mov	rsi, r12
	call	userdb$addbuddy
	test	rax, rax
	jnz	.errormsg
	; success, so we need to update ALL our tuis (if we are logged in multiple times,
	; this action needs to be replicated)
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach
	jmp	.closeit
calign
.errormsg:
	push	rax
	mov	rdi, r12
	call	heap$free
	pop	r12
	mov	qword [rbx+screen_modal_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vremoveallbastards]
	; add our error message dialog
	mov	rdi, .addbuddystr
	mov	rsi, r12
	mov	edx, tui_alert_ok
	; panel/title colors
	ansi_colors ecx, 'black', 'cyan'
	; button colors
	ansi_colors r8d, 'lightgray', 'black'
	; focus button colors
	ansi_colors r9d, 'yellow', 'blue'
	call	tui_alert$new
	; save the modal pointer for focus
	mov	rdi, rbx
	mov	[rbx+screen_modal_ofs], rax
	mov	dword [rbx+screen_modalalert_ofs], 1
	mov	rsi, rax
	mov	rdx, [rdi]
	; set its bastardglue so that it ends up centered
	mov	dword [rax+tui_bastardglue_ofs], 1
	mov	dword [rax+tui_horizalign_ofs], tui_align_center
	mov	dword [rax+tui_vertalign_ofs], tui_align_middle
	call	qword [rdx+tui_vappendbastard]
	; deal with our cursor:
	mov	rdi, rbx
	call	screen$showhidecursor
	pop	r12 rbx
	epilog
cleartext .addbuddystr, 'Add Buddy'
	
calign
.closeit:
	mov	rdi, r12
	call	heap$free
	mov	qword [rbx+screen_modal_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vremoveallbastards]
	pop	r12 rbx
	epilog






; three arguments: rdi == our screen object, esi == key, edx == esc_key
falign
screen$firekeyevent:
	prolog	screen$firekeyevent
	; the reason we override this is to mess with the input focus.
	; the tui_object default firekeyevent passes keys to ALL children
	; stopping when the first one handles it. If we allowed that to
	; happen, then only our first child would ever receive keystrokes.
	; deal with our commands first, before we pass it to our focusitem

	; before we do anything, make sure we update our lastkey time
	mov	rcx, [_epoll_tv_secs]
	mov	[rdi+screen_lastkey_ofs], rcx

	cmp	esi, 3			; let ctrl-c go, tui_ssh will grab it
	je	.falseret
	; further, since I didn't really do up tui_object's idea of what modal
	; is all about, we "fake" that too, by keeping track of it ourselves
	cmp	esi, 2			; ctrl-b
	je	.belltest
	cmp	qword [rdi+screen_modal_ofs], 0
	jne	.domodal
	cmp	esi, 1			; ctrl-a
	je	.addbuddy
	cmp	esi, 9
	je	.tab
	cmp	edx, 0x5a
	je	.shifttab
	cmp	esi, 10
	je	.ctrlj
	cmp	esi, 23
	je	.ctrlw
	cmp	esi, 18			; ctrl-r
	je	.removebuddy
	; otherwise, let her rip
	mov	rdi, [rdi+screen_focus_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vfirekeyevent]
	; let our return be its return
	epilog
calign
.belltest:
	mov	rdi, [rdi+screen_bell_ofs]
	mov	esi, 3
	call	tui_bell$nvdoit
	mov	eax, 1
	epilog
calign
.domodal:
	cmp	esi, 27
	je	.closemodal
	mov	rdi, [rdi+screen_modal_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vfirekeyevent]
	; let our return be its return
	epilog
calign
.closemodal:
	push	rdi
	mov	qword [rdi+screen_modal_ofs], 0
	mov	rsi, [rdi]
	call	qword [rsi+tui_vremoveallbastards]
	pop	rdi
	call	screen$showhidecursor
	mov	eax, 1
	epilog
cleartext .addbuddytitle, 'Add Buddy'
cleartext .addbuddymsg, 'Enter buddy name, or esc to cancel'
cleartext .removebuddytitle, 'Remove Buddy'
calign
.addbuddy:
	; several scenarios here:
	; if the focus is on the buddylist, we open an addbuddy dialog with no text
	; if the focus is on a chat window, and said chat is 1:1, and said buddy
	;   is not in our buddylist, we add it without dialog/confirmation
	; if the focus is on a chat window, and said chat is 1:1, and said buddy
	;   is already in our buddylist, we open addbuddy dialog with no text
	; if the focus is on a chat window, and said chat is a room, open our
	;   buddy dialog with no text
	mov	rsi, [rdi+screen_focus_ofs]
	cmp	rsi, [rdi+screen_buddylist_ofs]
	je	.addbuddy_emptytext
	; otherwise, our focus is not on our buddylist
	; so it must be a chatpanel, see if it is a room or not
	mov	rdx, [rsi+chatpanel_room_ofs]
	cmp	qword [rdx+chatroom_name_ofs], 0
	jne	.addbuddy_fromroom
	; otherwise, we are in a 1:1 chatpanel, see if this buddy is already in our list
	; if it is, then emptytext
	; if it is not, add it without question or interaction
	; chatpanel_name_ofs == the name of our remote party

	; TODO: change this to just call userdb$addbuddy

	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+screen_user_ofs]
	mov	rdi, [rdi+user_buddylist_ofs]
	mov	rsi, [rsi+chatpanel_name_ofs]
	; first do a quick lookup to determine if it is in our buddy list or not
	push	rsi
	call	stringmap$find_value
	pop	rsi
	test	eax, eax
	jnz	.addbuddy_fromchat_empty
	; otherwise, we need to do a lookup in the [users] map
	mov	rdi, [users]
	call	stringmap$find_value
	test	eax, eax
	jz	.addbuddy_fromchat_empty	; sanity only
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_buddylist_ofs]
	mov	rsi, [rdx+user_username_ofs]
	push	rdx
	call	stringmap$insert_unique
	pop	rcx
	; add the notifies entry
	mov	rdi, [rcx+user_notifies_ofs]
	mov	rdx, [rbx+screen_user_ofs]
	mov	rsi, [rdx+user_username_ofs]
	call	stringmap$insert_unique
	; now we need to update our buddylist, and then we are done
	; success, so we need to update ALL our tuis (if we are logged in multiple times,
	; this action needs to be replicated)
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach

	; last but not least, save our userdb
	call	userdb$save

	pop	rbx
	mov	eax, 1
	epilog
calign
.addbuddy_fromchat_empty:
	mov	rdi, rbx
	pop	rbx
	; fallthrough to empty
calign
.addbuddy_emptytext:
.addbuddy_fromroom:
	push	rdi
	mov	rdi, .addbuddytitle
	mov	rsi, .addbuddymsg
	mov	rdx, .emptystr
	; panel/title colors
	ansi_colors ecx, 'black', 'cyan'
	; button colors
	ansi_colors r8d, 'lightgray', 'black'
	; focus button colors
	ansi_colors r9d, 'yellow', 'blue'
	call	tui_textbox$new
	pop	rdi
	; set its vtable to our newroom vtable so we can capture onenter
	mov	qword [rax], screen_addbuddy$vtable
	; save the modal pointer for focus
	mov	[rdi+screen_modal_ofs], rax
	mov	dword [rdi+screen_modalalert_ofs], 0
	mov	rsi, rax
	mov	rdx, [rdi]
	; set its bastardglue so that it ends up centered
	mov	dword [rax+tui_bastardglue_ofs], 1
	mov	dword [rax+tui_horizalign_ofs], tui_align_center
	mov	dword [rax+tui_vertalign_ofs], tui_align_middle
	push	rdi
	call	qword [rdx+tui_vappendbastard]
	pop	rdi
	call	screen$showhidecursor
	mov	eax, 1
	epilog

cleartext .buddystr, 'buddy'
calign
.removebuddy:
	mov	rsi, [rdi+screen_buddylist_ofs]
	cmp	rsi, [rdi+screen_focus_ofs]
	je	.removebuddy_fromlist
	; not the buddylist, so must be a chatpanel then
	; determine if we are in a 1:1 chat or not
	mov	rsi, [rdi+screen_focus_ofs]
	mov	rdx, [rsi+chatpanel_room_ofs]
	cmp	qword [rdx+chatroom_name_ofs], 0
	jne	.removebuddy_fromroom
	; otherwise, we are in a 1:1 chatpanel, see if this buddy is in our list
	; if it _is_ in our list, then just remove it
	; otherwise, open a text input
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+screen_user_ofs]
	mov	rdi, [rdi+user_buddylist_ofs]
	mov	rsi, [rsi+chatpanel_name_ofs]
	call	stringmap$find_value
	test	eax, eax
	jz	.removebuddy_fromroom
	; yep, it is there, remove it
	mov	rdi, [rbx+screen_user_ofs]
	mov	rsi, [rdx+user_username_ofs]
	mov	rdi, [rdi+user_username_ofs]
	call	userdb$removebuddy
	; success, so we need to update ALL our tuis (if we are logged in multiple times,
	; this action needs to be replicated)
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach
	pop	rbx
	mov	eax, 1
	epilog
calign
.removebuddy_fromroom:
	; open a text input to get the buddy name
	push	rdi
	mov	rdi, .removebuddytitle
	mov	rsi, .addbuddymsg
	mov	rdx, .emptystr
	; panel/title colors
	ansi_colors ecx, 'black', 'cyan'
	; button colors
	ansi_colors r8d, 'lightgray', 'black'
	; focus button colors
	ansi_colors r9d, 'yellow', 'blue'
	call	tui_textbox$new
	pop	rdi
	; set its vtable to our newroom vtable so we can capture onenter
	mov	qword [rax], screen_removebuddy$vtable
	; save the modal pointer for focus
	mov	[rdi+screen_modal_ofs], rax
	mov	dword [rdi+screen_modalalert_ofs], 0
	mov	rsi, rax
	mov	rdx, [rdi]
	; set its bastardglue so that it ends up centered
	mov	dword [rax+tui_bastardglue_ofs], 1
	mov	dword [rax+tui_horizalign_ofs], tui_align_center
	mov	dword [rax+tui_vertalign_ofs], tui_align_middle
	push	rdi
	call	qword [rdx+tui_vappendbastard]
	pop	rdi
	call	screen$showhidecursor
	mov	eax, 1
	epilog
	
calign
.removebuddy_fromlist:
	push	rbx
	mov	rbx, rdi
	mov	rdi, rsi
	call	tui_datagrid$nvgetselected
	test	eax, eax
	jz	.removebuddy_fromlist_nodeal
	; otherwise, rax has our json object, extract the name we are after
	mov	rdi, rax
	mov	rsi, .buddystr
	call	json$getvaluebyname
	; it should have returned us with a jsonvalue object, whos json_value_ofs is the string we want
	mov	rdi, [rbx+screen_user_ofs]
	mov	rsi, [rax+json_value_ofs]
	mov	rdi, [rdi+user_username_ofs]
	call	userdb$removebuddy
	; success, so we need to update ALL our tuis (if we are logged in multiple times,
	; this action needs to be replicated)
	mov	rdi, [rbx+screen_user_ofs]
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, screen$updatebuddies
	call	unsignedmap$foreach
	pop	rbx
	mov	eax, 1
	epilog

calign
.removebuddy_fromlist_nodeal:
	pop	rbx
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

cleartext .newroomtitle, 'Join/Create Room'
cleartext .newroommsg, 'Enter room name, or esc to cancel'
cleartext .emptystr, ''

calign
.ctrlj:
	push	rdi
	mov	rdi, .newroomtitle
	mov	rsi, .newroommsg
	mov	rdx, .emptystr
	; panel/title colors
	ansi_colors ecx, 'black', 'cyan'
	; button colors
	ansi_colors r8d, 'lightgray', 'black'
	; focus button colors
	ansi_colors r9d, 'yellow', 'blue'
	call	tui_textbox$new
	pop	rdi
	; set its vtable to our newroom vtable so we can capture onenter
	mov	qword [rax], screen_newroom$vtable
	; save the modal pointer for focus
	mov	[rdi+screen_modal_ofs], rax
	mov	dword [rdi+screen_modalalert_ofs], 0
	mov	rsi, rax
	mov	rdx, [rdi]
	; set its bastardglue so that it ends up centered
	mov	dword [rax+tui_bastardglue_ofs], 1
	mov	dword [rax+tui_horizalign_ofs], tui_align_center
	mov	dword [rax+tui_vertalign_ofs], tui_align_middle
	push	rdi
	call	qword [rdx+tui_vappendbastard]
	pop	rdi
	call	screen$showhidecursor
	mov	eax, 1
	epilog
calign
.ctrlw:
	; if the focus is on the buddylist, do nothing
	mov	rdx, [rdi+screen_focus_ofs]
	cmp	rdx, [rdi+screen_buddylist_ofs]
	je	.falseret
	; otherwise, save the current focus, do an ontab first, then KO the window
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rdx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vontab]
	; remove the window from our main object
	mov	rdi, [rbx+screen_main_ofs]
	mov	rsi, r12
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	; removechild doesn't actually destroy the object, so do that next
	mov	rdi, r12
	mov	rsi, [r12]
	call	qword [rsi+tui_vcleanup]
	mov	rdi, r12
	call	heap$free
	; retile our main window
	mov	rdi, [rbx+screen_main_ofs]
	call	tui_object$nvtile
	pop	r12 rbx
	mov	eax, 1
	epilog
	
calign
.falseret:
	xor	eax, eax
	epilog



; single argument in rdi: our screen object
falign
screen$ontab:
	prolog	screen$ontab
	; burning purpose: change input focus in a sensible manner
	mov	rsi, [rdi+screen_focus_ofs]
	cmp	rsi, [rdi+screen_buddylist_ofs]
	je	.onbuddylist
	; otherwise, we are on a chatpanel, walk through the list and find it
	mov	rdx, [rdi+screen_main_ofs]
	mov	rcx, [rdx+tui_children_ofs]
	mov	rdx, [rcx+_list_first_ofs]
calign
.search:
	cmp	rsi, [rdx]
	je	.found
	; we -will- find it, so we don't need to do any checking
	mov	rdx, [rdx+_list_nextofs]
	jmp	.search
calign
.found:
	push	rdi rdx
	mov	rdi, rsi
	mov	rsi, [rsi]
	call	qword [rsi+tui_vlostfocus]
	pop	rdx rdi
	; so now, set rdx to its previous position, and if it is invalid, buddylist it is
	mov	rdx, [rdx+_list_prevofs]
	test	rdx, rdx
	jz	.focusbuddy
	; otherwise, focus to [rdx]
	push	rdi
	mov	rsi, [rdx]
	mov	[rdi+screen_focus_ofs], rsi
	mov	rdi, rsi
	mov	rsi, [rsi]
	call	qword [rsi+tui_vgotfocus]

	; show/hide the cursor
	pop	rdi
	call	screen$showhidecursor
	epilog
calign
.focusbuddy:
	; because we are faking tui_datagrid focuscolors, update them here too
	mov	rsi, [rdi+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'blue'
	mov	dword [rsi+tui_dgselcolors_ofs], ecx
	push	rdi
	mov	[rdi+screen_focus_ofs], rsi
	mov	rdi, rsi
	mov	rsi, [rsi]
	call	qword [rsi+tui_vredraw]
	pop	rdi
	call	screen$showhidecursor
	epilog
calign
.onbuddylist:
	mov	rdx, [rdi+screen_main_ofs]
	mov	rcx, [rdx+tui_children_ofs]
	mov	rdx, [rcx+_list_last_ofs]
	test	rdx, rdx
	jz	.nothingtodo
	mov	rsi, [rdx]
	mov	[rdi+screen_focus_ofs], rsi
	; unfocus the buddylist
	push	rdi
	mov	rdi, [rdi+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vredraw]
	mov	rdi, [rsp]
	mov	rdi, [rdi+screen_focus_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	pop	rdi
	call	screen$showhidecursor
	epilog
calign
.nothingtodo:
	epilog
	




; single argument in rdi: our screen object
falign
screen$onshifttab:
	prolog	screen$onshifttab
	; burning purpose: change input focus in a sensible manner
	mov	rsi, [rdi+screen_focus_ofs]
	cmp	rsi, [rdi+screen_buddylist_ofs]
	je	.onbuddylist
	; otherwise, we are on a chatpanel, walk through the list and find it
	mov	rdx, [rdi+screen_main_ofs]
	mov	rcx, [rdx+tui_children_ofs]
	mov	rdx, [rcx+_list_first_ofs]
calign
.search:
	cmp	rsi, [rdx]
	je	.found
	; we -will- find it, so we don't need to do any checking
	mov	rdx, [rdx+_list_nextofs]
	jmp	.search
calign
.found:
	push	rdi rdx
	mov	rdi, rsi
	mov	rsi, [rsi]
	call	qword [rsi+tui_vlostfocus]
	pop	rdx rdi
	; so now, set rdx to its next position, and if it is invalid, buddylist it is
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jz	.focusbuddy
	; otherwise, focus to [rdx]
	mov	rsi, [rdx]
	mov	[rdi+screen_focus_ofs], rsi
	push	rdi
	mov	rdi, rsi
	mov	rsi, [rsi]
	call	qword [rsi+tui_vgotfocus]
	pop	rdi
	call	screen$showhidecursor
	epilog
calign
.focusbuddy:
	; because we are faking tui_datagrid focuscolors, update them here too
	mov	rsi, [rdi+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'blue'
	mov	dword [rsi+tui_dgselcolors_ofs], ecx
	mov	[rdi+screen_focus_ofs], rsi
	push	rdi
	mov	rdi, rsi
	mov	rsi, [rsi]
	call	qword [rsi+tui_vredraw]
	pop	rdi
	call	screen$showhidecursor
	epilog
calign
.onbuddylist:
	mov	rdx, [rdi+screen_main_ofs]
	mov	rcx, [rdx+tui_children_ofs]
	mov	rdx, [rcx+_list_first_ofs]
	test	rdx, rdx
	jz	.nothingtodo
	mov	rsi, [rdx]
	mov	[rdi+screen_focus_ofs], rsi
	; unfocus the buddylist
	push	rdi
	mov	rdi, [rdi+screen_buddylist_ofs]
	ansi_colors ecx, 'lightgray', 'midnightblue'
	mov	dword [rdi+tui_dgselcolors_ofs], ecx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vredraw]
	mov	rdi, [rsp]
	mov	rdi, [rdi+screen_focus_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	pop	rdi
	call	screen$showhidecursor
	epilog
calign
.nothingtodo:
	epilog
