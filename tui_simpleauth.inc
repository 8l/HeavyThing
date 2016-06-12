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
	; tui_simpleauth.inc: simple auth screen
	;
	; we support user/pass, or single token based auth, and also provide a "new user"
	; form that has user/pass as well.
	;
	; we "descend" tui_object, but we add three virtual methods to deal with auth itself
	;
	; look and feel changes will require copying/modifying the new$/nvsetup goods
	;
	; NOTE: in a server environment, if you add objects to the top/bottom sections of the main
	; auth screen, you must _not_ alter the primary 3 children, or clone won't work properly
	; e.g. if you add to tui_simpleauth's first child (which is empty space above the authbox)
	; or you add to tui_simpleauth's last child, or alter the mid section's layout or add
	; to that, that is fine.
	; if you add any children anywhere to tui_simpleauth directly, clone will fail to find
	; the mid/panel out of its tui_object cloned version.
	;
	; ALSO NOTE: it does not make sense to clone this under anything but a "fresh" setup
	; e.g. if a clone occurs in any other state than "initial", results are undefined, haha
	; (this isn't a problem of course, because that is precisely the way it was designed to
	; work, but I figure it is worth noting)
	;


if used tui_simpleauth$vtable | defined include_everything

dalign
tui_simpleauth$vtable:
        dq      tui_simpleauth$cleanup, tui_simpleauth$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_simpleauth$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; our addon virtual methods that are tui_simpleauth-specific:
	dq	tui_simpleauth$allow_userpass, tui_simpleauth$allow_token, tui_simpleauth$create_newuser


tui_simpleauth_vuserpass = tui_vclicked + 8
tui_simpleauth_vtoken = tui_vclicked + 16
tui_simpleauth_vnewuser = tui_vclicked + 24

tui_simpleauth_authtype_ofs = tui_background_size
tui_simpleauth_onsuccess_ofs = tui_background_size + 8
tui_simpleauth_mid_ofs = tui_background_size + 16
tui_simpleauth_panel_ofs = tui_background_size + 24
tui_simpleauth_fail_ofs = tui_background_size + 32
tui_simpleauth_retrytime_ofs = tui_background_size + 40
tui_simpleauth_oldpanel_ofs = tui_background_size + 48
tui_simpleauth_timerptr_ofs = tui_background_size + 56

tui_simpleauth_size = tui_background_size + 64

end if


if used tui_simpleauth$new | defined include_everything
	; two arguments: edi == authtype, rsi == tui_object to fire up on success

	; authtype is one of:
tui_simpleauth_normal = 0
tui_simpleauth_newuser = 1
tui_simpleauth_token = 2

falign
tui_simpleauth$new:
	prolog	tui_simpleauth$new
	push	rbx rdi rsi
	mov	edi, tui_simpleauth_size
	call	heap$alloc
	mov	rbx, rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	esi, ' '
	ansi_colors edx, 'lightgray', 'black'
	call	tui_background$init_dd
	mov	qword [rbx], tui_simpleauth$vtable
	pop	rsi rdi
	xor	ecx, ecx
	mov	edx, 3
	mov	[rbx+tui_simpleauth_authtype_ofs], rdi
	mov	[rbx+tui_simpleauth_onsuccess_ofs], rsi
	mov	[rbx+tui_simpleauth_mid_ofs], rcx
	mov	[rbx+tui_simpleauth_panel_ofs], rcx
	mov	[rbx+tui_simpleauth_fail_ofs], rcx
	mov	[rbx+tui_simpleauth_retrytime_ofs], rdx
	mov	[rbx+tui_simpleauth_oldpanel_ofs], rcx
	mov	[rbx+tui_simpleauth_timerptr_ofs], rcx
	mov	rdi, rbx
	call	tui_simpleauth$nvsetup
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used tui_simpleauth$clone | defined include_everything
	; single argument in rdi: our tui_simpleauth object
falign
tui_simpleauth$clone:
	prolog	tui_simpleauth$clone
	push	rdi
	mov	edi, tui_simpleauth_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	rsi, [rsp+8]
	call	tui_background$init_copy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsi+tui_simpleauth_retrytime_ofs]
	mov	rcx, [rsi+tui_simpleauth_authtype_ofs]
	mov	r8, [rsi+tui_simpleauth_onsuccess_ofs]
	xor	r9d, r9d
	mov	[rdi+tui_simpleauth_authtype_ofs], rcx
	mov	[rdi+tui_simpleauth_onsuccess_ofs], r8
	mov	[rdi+tui_simpleauth_mid_ofs], r9
	mov	[rdi+tui_simpleauth_panel_ofs], r9
	mov	[rdi+tui_simpleauth_fail_ofs], r9
	mov	[rdi+tui_simpleauth_retrytime_ofs], rdx
	mov	[rdi+tui_simpleauth_oldpanel_ofs], r9
	mov	[rdi+tui_simpleauth_timerptr_ofs], r9

	; so now, we know that mid is the second child, and panel is its first child
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rcx, [rdx]			; mid
	mov	[rdi+tui_simpleauth_mid_ofs], rcx

	mov	rsi, [rcx+tui_children_ofs]

	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx]			; panel
	mov	[rdi+tui_simpleauth_panel_ofs], rdx

	; we need to set the panel's as varialbe so that it can link back to us:
	mov	[rdx+tui_authpanel_as_ofs], rdi

	mov	rax, rdi
	add	rsp, 16
	epilog

end if

if used tui_simpleauth$nvsetup | defined include_everything
	; single argument in rdi: our fresh tui_simpleauth object
falign
tui_simpleauth$nvsetup:
	prolog	tui_simpleauth$nvsetup
	; fill our screen
	push	rbx
	mov	rbx, rdi
	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [.half]
	call	tui_object$init_dd
	pop	rsi
	mov	qword [rsi], tui_object$simple_vtable
	mov	rdi, rbx
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]
	; our midsection depends on what kind of auth we are presenting
	cmp	dword [rbx+tui_simpleauth_authtype_ofs], tui_simpleauth_newuser
	je	.mid_newuser
	cmp	dword [rbx+tui_simpleauth_authtype_ofs], tui_simpleauth_token
	je	.mid_token
	; otherwise, normal it is
	mov	edi, tui_object_size
	call	heap$alloc
	mov	[rbx+tui_simpleauth_mid_ofs], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 6
	call	tui_object$init_di
	mov	rax, [rbx+tui_simpleauth_mid_ofs]
	mov	qword [rax], tui_object$simple_vtable
	mov	dword [rax+tui_horizalign_ofs], tui_align_center
	
	mov	edi, 38
	mov	esi, 6
	mov	rdx, rbx
	xor	ecx, ecx
	call	tui_authpanel$new
	mov	[rbx+tui_simpleauth_panel_ofs], rax
	mov	rdi, rax
	call	tui_authpanel$normalsetup
	jmp	.midready
dalign
.half	dq	50.0f
calign
.mid_newuser:
	mov	edi, tui_object_size
	call	heap$alloc
	mov	[rbx+tui_simpleauth_mid_ofs], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 10
	call	tui_object$init_di
	mov	rax, [rbx+tui_simpleauth_mid_ofs]
	mov	qword [rax], tui_object$simple_vtable
	mov	dword [rax+tui_horizalign_ofs], tui_align_center

	mov	edi, 38
	mov	esi, 10
	mov	rdx, rbx
	xor	ecx, ecx
	call	tui_authpanel$new
	mov	[rbx+tui_simpleauth_panel_ofs], rax
	mov	rdi, rax
	call	tui_authpanel$newusersetup
	jmp	.midready

calign
.mid_token:
	mov	edi, tui_object_size
	call	heap$alloc
	mov	[rbx+tui_simpleauth_mid_ofs], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 6
	call	tui_object$init_di
	mov	rax, [rbx+tui_simpleauth_mid_ofs]
	mov	qword [rax], tui_object$simple_vtable
	mov	dword [rax+tui_horizalign_ofs], tui_align_center

	mov	edi, 50
	mov	esi, 5
	mov	rdx, rbx
	xor	ecx, ecx
	call	tui_authpanel$new
	mov	[rbx+tui_simpleauth_panel_ofs], rax
	mov	rdi, rax
	call	tui_authpanel$tokensetup
	
calign
.midready:
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	
	mov	rdi, rbx
	mov	rsi, [rbx+tui_simpleauth_mid_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	; see the notes in tui_object.inc for why we do this one different
	; re: correcting rounding drops in height
	movq	xmm1, [.roundingerr]
	call	tui_object$init_dd

if defined tui_simpleauth_uglytesting
	; testing only
	mov	rsi, [rsp]
	mov	qword [rsi], tui_object$simple_vtable
	mov	dword [rsi+tui_layout_ofs], tui_layout_horizontal
	mov	dword [rsi+tui_vertalign_ofs], tui_align_bottom
	; create a newsticker to add to it
	movq	xmm0, [_math_onehundred]
	mov	rdi, .ticktext
	ansi_colors esi, 'lightgray', 'black'
	call	tui_newsticker$new_d
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; end testing
end if


	pop	rsi
	mov	qword [rsi], tui_object$simple_vtable
	mov	rdi, rbx
	mov	rdx, [rbx]
	call	qword [rdx+tui_vappendchild]

	pop	rbx
	epilog
if defined tui_simpleauth_uglytesting
cleartext .ticktext, 'Best viewed with a 6 pack of beer, ha! ... size: 135x35 min, Mac OS X: iTerm2 or Terminal.app, Winblows: SecureCRT (ANSI colors enabled, rows/cols adjust, lucida console), Linux: all linux terms seem happy...'
end if

dalign
.roundingerr	dq	51.0f

end if

if used tui_simpleauth$cleanup | defined include_everything
	; single argument in rdi: our tui_simpleauth object
falign
tui_simpleauth$cleanup:
	prolog	tui_simpleauth$cleanup
	; special handling is required for our "dangling" children
	push	rdi
	cmp	qword [rdi+tui_simpleauth_timerptr_ofs], 0
	je	.notimer
	mov	rdi, [rdi+tui_simpleauth_timerptr_ofs]
	call	epoll$timer_clear
	mov	rdi, [rsp]
	mov	qword [rdi+tui_simpleauth_timerptr_ofs], 0
calign
.notimer:
	call	tui_object$cleanup
	mov	rsi, [rsp]
	cmp	qword [rsi+tui_simpleauth_fail_ofs], 0
	je	.nofail
	mov	rdi, [rsi+tui_simpleauth_panel_ofs]
	push	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	pop	rdi
	call	heap$free
	mov	rsi, [rsp]
calign
.nofail:
	cmp	qword [rsi+tui_simpleauth_oldpanel_ofs], 0
	je	.noold
	mov	rdi, [rsi+tui_simpleauth_oldpanel_ofs]
	push	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	pop	rdi
	call	heap$free
calign
.noold:
	add	rsp, 8
	epilog

end if


if used tui_simpleauth$keyevent | defined include_everything
	; three arguments: rdi == our tui_simpleauth object, esi == key, edx == esc_key
falign
tui_simpleauth$keyevent:
	prolog	tui_simpleauth$keyevent
	; my original C++ was catching ctrl-C here, but since all the higher level renderers do that anyway, leaving this
	; as an unhandled return in case I change my mind
	xor	eax, eax
	epilog

end if

if used tui_simpleauth$allow_userpass | defined include_everything
	; three arguments: rdi == our tui_simpleauth object, rsi == string username, rdx == string password
falign
tui_simpleauth$allow_userpass:
	prolog	tui_simpleauth$allow_userpass
	; default here is to deny
	xor	eax, eax
	epilog

end if

if used tui_simpleauth$allow_token | defined include_everything
	; two arguments: rdi == our tui_simpleauth object, rsi == string token
falign
tui_simpleauth$allow_token:
	prolog	tui_simpleauth$allow_token
	; default here is to deny
	xor	eax, eax
	epilog

end if


tui_simpleauth_newuserform = 99

if used tui_simpleauth$create_newuser | defined include_everything
	; three arguments: rdi == our tui_simpleauth object, rsi == string username, rdx == string password
	; NOTE: a null return for this == success, a string pointer return == denied, and the string itself is the error message
	; also note: the return is meant to be static, e.g. the calling handler below will not attempt to free it
	; changing it to dynamic should the need ever arise just needs modifying here and below for when it is called
falign
tui_simpleauth$create_newuser:
	prolog	tui_simpleauth$create_newuser
	; default is to return an error string
	mov	rax, .denied
	epilog
cleartext .denied, 'Fail: Administratively Prohibited'

end if




if used tui_simpleauth$enterpressed | defined include_everything
	; single argument in rdi: our tui_simpleauth object
	; this is called for the "submit" action, either we have a user/pass, or we have a token
falign
tui_simpleauth$enterpressed:
	prolog	tui_simpleauth$enterpressed
	push	rbx r12 r13
	mov	rbx, rdi
	cmp	dword [rdi+tui_simpleauth_authtype_ofs], tui_simpleauth_newuserform
	je	.newuserform
	cmp	dword [rdi+tui_simpleauth_authtype_ofs], tui_simpleauth_token
	je	.token
	; otherwise, normal or newuser
	mov	rax, [rdi+tui_simpleauth_panel_ofs]
	mov	rdi, [rax+tui_authpanel_username_ofs]
	mov	r13, [rax+tui_authpanel_password_ofs]
	call	tui_text$nvgettext
	mov	r12, rax
	mov	rdi, r13
	call	tui_text$nvgettext
	mov	rdx, rax
	mov	rsi, r12
	mov	rdi, rbx
	mov	r13, rax
	mov	rcx, [rbx]
	call	qword [rcx+tui_simpleauth_vuserpass]
	push	rax
	mov	rdi, r13
	call	heap$free_clear
	pop	rax
	mov	rdx, .t1
	jmp	.authed
cleartext .t1, 'Incorrect username or password'
calign
.token:
	mov	rax, [rdi+tui_simpleauth_panel_ofs]
	mov	rdi, [rax+tui_authpanel_token_ofs]
	call	tui_text$nvgettext
	mov	r12, rax
	mov	rsi, rax
	mov	rdi, rbx
	mov	rdx, [rbx]
	call	qword [rdx+tui_simpleauth_vtoken]
	mov	rdx, .t2
	jmp	.authed
cleartext .t2, 'Invalid access token'
cleartext .t3, 'Passwords do not match'
calign
.newuserform:
	; quick sidestep to make sure both password fields match
	mov	rax, [rdi+tui_simpleauth_panel_ofs]
	mov	rdi, [rax+tui_authpanel_username_ofs]
	mov	r13, [rax+tui_authpanel_password_ofs]
	push	qword [rax+tui_authpanel_token_ofs]
	call	tui_text$nvgettext
	mov	r12, rax
	mov	rdi, r13
	call	tui_text$nvgettext
	mov	r13, rax
	pop	rdi
	call	tui_text$nvgettext
	; compare both passwords
	push	rax
	mov	rdi, rax
	mov	rsi, r13
	call	string$equals
	test	eax, eax
	jz	.passwords_mismatch
	; otherwise, we can free the passdup entry
	pop	rdi
	call	heap$free_clear

	; now we can proceed with our simpleauth
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, r13
	mov	rcx, [rbx]
	call	qword [rcx+tui_simpleauth_vnewuser]
	mov	rdi, r13
	mov	r13, rax
	call	heap$free_clear
	mov	rax, r13
	mov	rdx, .t1
	test	rax, rax
	jz	.success
	mov	rdi, rax
	mov	esi, [rbx+tui_simpleauth_retrytime_ofs]
	mov	rdx, rbx
if tui_simpleauth_newuserfail_exit
	mov	ecx, 1						; exit, not retry
else
	xor	ecx, ecx					; retry
end if
	call	tui_authfail$new
	mov	[rbx+tui_simpleauth_fail_ofs], rax
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_fail_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, rbx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vhidecursor]
	; new user attempts shouldn't necessarily increase the retrytime
	; shl	dword [rbx+tui_simpleauth_retrytime_ofs], 1
	mov	rdi, r12
	call	heap$free
	pop	r13 r12 rbx
	epilog
calign
.passwords_mismatch:
	; free the passdup entry
	pop	rdi
	call	heap$free_clear
	mov	rdi, r13
	call	heap$free_clear
	mov	rdi, r12
	call	heap$free
	; fire up an authfailed
	mov	rdi, .t3
	mov	esi, 3			; 3 seconds at most
	; mov	esi, [rbx+tui_simpleauth_retrytime_ofs]
	mov	rdx, rbx
	xor	ecx, ecx
	call	tui_authfail$new
	mov	[rbx+tui_simpleauth_fail_ofs], rax
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_fail_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, rbx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vhidecursor]
	; new user attempts shouldn't necessarily increase the retrytime
	; shl	dword [rbx+tui_simpleauth_retrytime_ofs], 1
	pop	r13 r12 rbx
	epilog
calign
.authed:
	test	eax, eax
	jnz	.success
	; otherwise, fire up an authfail dialog with a retry countdown
	mov	rdi, rdx
	mov	esi, [rbx+tui_simpleauth_retrytime_ofs]
	mov	rdx, rbx
	xor	ecx, ecx
	call	tui_authfail$new
	mov	[rbx+tui_simpleauth_fail_ofs], rax
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_fail_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, rbx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vhidecursor]
	shl	dword [rbx+tui_simpleauth_retrytime_ofs], 1
	mov	rdi, r12
	call	heap$free
	pop	r13 r12 rbx
	epilog
calign
.success:
	; this is a bit of evilness here... we need to commit suicide, and add a cloned version
	; of our onsuccess ... this is kinda bad form, but it is either a timer handler or
	; keyevent, both of which will stack unwind cleanly even if the tui_object chain gets
	; all jacked up...

	; set our cursor back to home position for good measure, let our onsuccess deal with it
	; from there
	mov	rdi, rbx
	xor	esi, esi
	xor	edx, edx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsetcursor]
	
	; remove ourselves, and add our cloned onsuccess
	mov	rdi, [rbx+tui_parent_ofs]
	mov	rsi, rbx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	mov	rdi, [rbx+tui_simpleauth_onsuccess_ofs]
	mov	rsi, r12					; NOTE: we pass the username/token as an argument to clone here
	mov	rdx, [rbx+tui_parent_ofs]			; as well as our actual parent (useful for finding the top of the chain inside clone)
	mov	rcx, [rdi]
	call	qword [rcx+tui_vclone]
	mov	rdi, [rbx+tui_parent_ofs]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; last but not least, *cough*, delete ourselves
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdi, rbx
	call	heap$free
	
	mov	rdi, r12
	call	heap$free

	pop	r13 r12 rbx
	epilog

end if


if used tui_simpleauth$canretry | defined include_everything
	; single argument in rdi: our tui_simpleauth object
	; this gets called after our countdown expires from tui_authfail
falign
tui_simpleauth$canretry:
	prolog	tui_simpleauth$canretry
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_fail_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	mov	rdi, [rbx+tui_simpleauth_fail_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdi, [rbx+tui_simpleauth_fail_ofs]
	call	heap$free
	mov	qword [rbx+tui_simpleauth_fail_ofs], 0
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]

	pop	rbx
	epilog

end if



if used tui_simpleauth$newuserclicked | defined include_everything
	; single argument in rdi: our tui_simpleauth object
falign
tui_simpleauth$newuserclicked:
	prolog	tui_simpleauth$newuserclicked
	push	rbx r12 r13
	mov	rbx, rdi

	; so really what we want to happen here is to replace the authpanel with a new authpanel, that has different
	; labels for the fields/button

	; and since it lives in mid, that would ordinarily be a simple swap out, BUT: things get interesting here
	; because the button action is fired when the button comes back up, and thus is a nested click event
	; from decently far down a stackchain, so we can't really just delete the authpanel and replace it quicksmart
	; which is why we have oldpanel :-)
	; this way, if we do swap them out, during our proper cleanup, oldpanel will _also_ get cleaned up if it
	; is set by this routine here
	; since we know that this can only happen once (there is no going back to the original panel after new user
	; is clicked)
	; we don't have to check much here

	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	[rbx+tui_simpleauth_oldpanel_ofs], rsi
	mov	rdx, [rdi]
	mov	r12, [rsi+tui_authpanel_username_ofs]
	mov	r13, [rsi+tui_authpanel_password_ofs]
	call	qword [rdx+tui_vremovechild]

	; now we need text representations of the username and password fields, in case they entered stuff there
	; before they hit new-user
	mov	rdi, r12
	call	tui_text$nvgettext
	mov	r12, rax
	mov	rdi, r13
	call	tui_text$nvgettext
	mov	r13, rax

	; now we can create our new authpanel
	mov	edi, 46
	mov	esi, 7
	mov	rdx, rbx
	mov	ecx, 1
	call	tui_authpanel$new
	mov	[rbx+tui_simpleauth_panel_ofs], rax
	mov	rdi, rax
	call	tui_authpanel$normalsetup
	; set their initial text
	mov	rdx, [rbx+tui_simpleauth_panel_ofs]
	mov	rsi, r12
	mov	rdi, [rdx+tui_authpanel_username_ofs]
	call	tui_text$nvsettext
	mov	rdx, [rbx+tui_simpleauth_panel_ofs]
	mov	rsi, r13
	mov	rdi, [rdx+tui_authpanel_password_ofs]
	call	tui_text$nvsettext
	; if any text was specified, it is possible that we need to auto-set the focus
	; to the first non-empty
	cmp	qword [r12], 0
	je	.skipfocus
	; otherwise, username was non-empty, so move focus
	mov	rdx, [rbx+tui_simpleauth_panel_ofs]
	mov	rdi, [rdx+tui_authpanel_username_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlostfocus]
	mov	rdx, [rbx+tui_simpleauth_panel_ofs]
	mov	rdi, [rdx+tui_authpanel_password_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
	cmp	qword [r13], 0
	je	.skipfocus
	; otherwise, password was also non-empty, move focus to passdup
	mov	rdx, [rbx+tui_simpleauth_panel_ofs]
	mov	rdi, [rdx+tui_authpanel_password_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlostfocus]
	mov	rdx, [rbx+tui_simpleauth_panel_ofs]
	mov	rdi, [rdx+tui_authpanel_token_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]
calign
.skipfocus:
	; clean those up
	mov	rdi, r13
	call	heap$free
	mov	rdi, r12
	call	heap$free

	; add that to our mid
	mov	rdi, [rbx+tui_simpleauth_mid_ofs]
	mov	rsi, [rbx+tui_simpleauth_panel_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; last but not least, set our authtype to newuserform
	mov	dword [rbx+tui_simpleauth_authtype_ofs], tui_simpleauth_newuserform

	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]
	
	pop	r13 r12 rbx
	epilog

end if




; ---------- the other goodies that the simpleauth screen needs:


if used tui_authfail$vtable | defined include_everything

dalign
tui_authfail$vtable:
        dq      tui_authfail$cleanup, tui_authfail$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_authfail$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
        dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

tui_authfail_as_ofs = tui_panel_size
tui_authfail_countdown_ofs = tui_panel_size + 8
tui_authfail_retrylabel_ofs = tui_panel_size + 16
tui_authfail_formatter_ofs = tui_panel_size + 24
tui_authfail_timerptr_ofs = tui_panel_size + 32
tui_authfail_exit_ofs = tui_panel_size + 40

tui_authfail_size = tui_panel_size + 48

end if

if used tui_authfail$new | defined include_everything
	; four arguments: rdi == string message to display, esi == retry time in seconds, rdx == tui_simpleauth object, ecx == bool as to whether we should exit after the countdown, or retry
falign
tui_authfail$new:
	prolog	tui_authfail$new
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+32], rcx
	mov	edi, tui_authfail_size
	call	heap$alloc
	mov	qword [rax], tui_authfail$vtable
	mov	rdi, rax
	mov	esi, 38
	mov	edx, 6
	mov	[rsp+24], rax
	mov	rcx, .t1
	mov	r10, .t5
	cmp	dword [rsp+32], 0
	cmovne	rcx, r10
	ansi_colors r8d, 'black', 'cyan'
	ansi_colors r9d, 'black', 'cyan'
	call	tui_panel$init_ii
	mov	rax, [rsp+24]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+32]
	mov	[rax+tui_authfail_as_ofs], rdx
	mov	[rax+tui_authfail_exit_ofs], rcx
	cvtsi2sd xmm0, esi
	movq	rsi, xmm0
	mov	[rax+tui_authfail_countdown_ofs], rsi
	mov	qword [rax+tui_authfail_timerptr_ofs], 0
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp+24]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rax, [rsp+24]
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	mov	rsi, [rsp]
	mov	edx, [rax+tui_panel_titlecolors_ofs]
	mov	ecx, tui_textalign_center
	call	tui_label$new_di
	mov	rdi, [rsp+24]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	xor	edi, edi
	call	formatter$new
	mov	rdi, rax
	mov	rax, [rsp+24]
	mov	[rax+tui_authfail_formatter_ofs], rdi
	mov	rsi, .t2
	mov	rdx, .t4
	cmp	dword [rsp+32], 0
	cmovne	rsi, rdx
	mov	[rsp+16], rdi
	call	formatter$add_static
	mov	rdi, [rsp+16]
	mov	esi, double_string_fixed
	mov	edx, 1
	xor	ecx, ecx
	call	formatter$add_double
	mov	rdi, [rsp+16]
	mov	rsi, .t3
	call	formatter$add_static
	mov	rax, [rsp+24]
	mov	rdi, [rsp+16]
	movq	xmm0, [rax+tui_authfail_countdown_ofs]
	call	formatter$doit
	mov	[rsp+8], rax
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	mov	rsi, rax
	ansi_colors edx, 'venetianred', 'cyan'
	mov	ecx, tui_textalign_center
	call	tui_label$new_di
	mov	rdi, [rsp+24]
	mov	[rdi+tui_authfail_retrylabel_ofs], rax
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rdi, [rsp+8]
	call	heap$free
	; last but not least, fire up our timer
	mov	edi, 100
	mov	rsi, [rsp+24]
	call	epoll$timer_new
	mov	dword [rax+24], 2		; we don't want the epoll layer to kill us off
	mov	rdi, [rsp+24]
	mov	[rdi+tui_authfail_timerptr_ofs], rax
	
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
cleartext .t1, 'Authentication Failed'
cleartext .t2, 'Retry in '
cleartext .t3, '...'
cleartext .t4, 'Exit in '
cleartext .t5, 'Failed'

end if

if used tui_authfail$clone | defined include_everything
	; this shouldn't be called, and is only here for sanity
falign
tui_authfail$clone:
	prolog	tui_authfail$clone
	breakpoint
	epilog

end if

if used tui_authfail$cleanup | defined include_everything
	; single argument in rdi: our tui_authfail object
falign
tui_authfail$cleanup:
	prolog	tui_authfail$cleanup
	push	rdi
	mov	rdi, [rdi+tui_authfail_formatter_ofs]
	call	formatter$destroy
	pop	rdi
	; if we have a timerptr, we have to timer_clear it, otherwise, normal tui_panel cleanup will work fine
	cmp	qword [rdi+tui_authfail_timerptr_ofs], 0
	je	.simple
	push	rdi
	mov	rdi, [rdi+tui_authfail_timerptr_ofs]
	mov	qword [rdi+tui_authfail_timerptr_ofs], 0
	call	epoll$timer_clear
	pop	rdi
	call	tui_panel$cleanup
	epilog
calign
.simple:
	call	tui_panel$cleanup
	epilog

end if

if used tui_authfail$timer | defined include_everything
	; single argument in rdi: our tui_authfail object
falign
tui_authfail$timer:
	prolog	tui_authfail$timer
	xorpd	xmm1, xmm1
	movq	xmm0, [rdi+tui_authfail_countdown_ofs]
	subsd	xmm0, [.dotone]
	movq	[rdi+tui_authfail_countdown_ofs], xmm0
	ucomisd xmm0, xmm1
	jbe	.ready
	push	rdi
	mov	rdi, [rdi+tui_authfail_formatter_ofs]
	call	formatter$doit
	mov	rdi, [rsp]
	push	rax
	mov	rdi, [rdi+tui_authfail_retrylabel_ofs]
	mov	rsi, rax
	call	tui_label$nvsettext
	pop	rdi
	call	heap$free
	pop	rdi
	xor	eax, eax		; don't kill the timer
	epilog
calign
.ready:
	mov	qword [rdi+tui_authfail_timerptr_ofs], 0
	cmp	dword [rdi+tui_authfail_exit_ofs], 0
	jne	.doexit
	mov	rdi, [rdi+tui_authfail_as_ofs]
	call	tui_simpleauth$canretry
	mov	eax, 1			; kill the timer
	epilog
dalign
.dotone	dq	0.1f
calign
.doexit:
	mov	esi, 1
	mov	rdx, [rdi]
	call	qword [rdx+tui_vexit]
	mov	eax, 1			; kill the timer
	epilog

end if


if used tui_autheditor$vtable | defined include_everything

dalign
tui_autheditor$vtable:
        dq      tui_text$cleanup, tui_text$clone, tui_text$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_text$gotfocus, tui_text$lostfocus
        dq      tui_text$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_text$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
        ; we add one method to our vtable for onenter handling
        dq      tui_autheditor$onenter

end if

if used tui_autheditor$new | defined include_everything
	; six arguments: edi == width, esi == height, rdx == initialtext, ecx == colors, r8d == focuscolors, r9 == authpanel
falign
tui_autheditor$new:
	prolog	tui_autheditor$new
	push	r9
	mov	r9d, 1
	call	tui_text$new_ii
	mov	qword [rax], tui_autheditor$vtable
	pop	r9
	mov	[rax+tui_text_user_ofs], r9
	epilog

end if

if used tui_autheditor$onenter | defined include_everything
	; single argument in rdi: our tui_autheditor object
falign
tui_autheditor$onenter:
	prolog	tui_autheditor$onenter
	mov	rsi, rdi
	mov	rdi, [rdi+tui_text_user_ofs]
	call	tui_authpanel$enterpressed
	epilog

end if

if used tui_authpanel$vtable | defined include_everything

dalign
tui_authpanel$vtable:
        dq      tui_panel$cleanup, tui_authpanel$clone, tui_panel$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_authpanel$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_panel$appendchild, tui_object$appendbastard, tui_panel$prependchild, tui_panel$contains, tui_panel$getchildindex
        dq      tui_panel$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_authpanel$ontab, tui_authpanel$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_authpanel$clicked

tui_authpanel_username_ofs = tui_panel_size
tui_authpanel_password_ofs = tui_panel_size + 8
tui_authpanel_token_ofs = tui_panel_size + 16			; also gets re-used as a duplicate pass entry for new user form
tui_authpanel_newuserbutton_ofs = tui_panel_size + 24
tui_authpanel_inputcolors_ofs = tui_panel_size + 32
tui_authpanel_focusinputcolors_ofs = tui_panel_size + 40
tui_authpanel_as_ofs = tui_panel_size + 48
tui_authpanel_newform_ofs = tui_panel_size + 56

tui_authpanel_size = tui_panel_size + 64

end if

if used tui_authpanel$new | defined include_everything
	; four arguments: edi == width, esi == height, rdx == pointer to the tui_simpleauth object, ecx == bool as to whether it is a new form or not
falign
tui_authpanel$new:
	prolog	tui_authpanel$new
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	edi, tui_authpanel_size
	call	heap$alloc
	mov	qword [rax], tui_authpanel$vtable
	mov	rdi, rax
	mov	esi, [rsp]
	mov	edx, [rsp+8]
	mov	[rsp], rax
	mov	rcx, .t1
	mov	r10, .t2
	ansi_colors r8d, 'black', 'cyan'
	ansi_colors r9d, 'black', 'cyan'
	cmp	dword [rsp+24], 0
	cmove	rcx, r10
	call	tui_panel$init_ii
	mov	rax, [rsp]
	mov	rdx, [rsp+16]
	mov	ecx, [rsp+24]
	xor	r8d, r8d
	ansi_colors r9d, 'lightgray', 'black'
	ansi_colors r10d, 'yellow', 'blue'
	mov	qword [rax], tui_authpanel$vtable
	mov	[rax+tui_authpanel_username_ofs], r8
	mov	[rax+tui_authpanel_password_ofs], r8
	mov	[rax+tui_authpanel_token_ofs], r8
	mov	[rax+tui_authpanel_newuserbutton_ofs], r8
	mov	[rax+tui_authpanel_inputcolors_ofs], r9
	mov	[rax+tui_authpanel_focusinputcolors_ofs], r10
	mov	[rax+tui_authpanel_as_ofs], rdx
	mov	[rax+tui_authpanel_newform_ofs], rcx
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	mov	rax, [rsp]
	add	rsp, 32
	epilog
cleartext .t1, 'New User Form'
cleartext .t2, 'Authentication Required'

end if

if used tui_authpanel$clone | defined include_everything
	; single argument in rdi: our authpanel to clone
falign
tui_authpanel$clone:
	prolog	tui_authpanel$clone
	push	rdi
	mov	edi, tui_authpanel_size
	call	heap$alloc
	mov	qword [rax], tui_authpanel$vtable
	mov	rsi, [rsp]
	push	rax
	mov	rdi, rax
	call	tui_panel$init_copy
	; so now, we need to set our authpanel-specific state variables
	; NOTE: we cannot set the tui_authpanel_as_ofs yet, because we haven't been
	; added to our real parent yet, it is up to the clone from tui_simpleauth
	; to set that.

	mov	rdi, [rsp]
	mov	rsi, [rsp+8]

	mov	rdx, [rsi+tui_authpanel_inputcolors_ofs]
	mov	rcx, [rsi+tui_authpanel_focusinputcolors_ofs]
	mov	r8, [rsi+tui_authpanel_newform_ofs]
	mov	[rdi+tui_authpanel_inputcolors_ofs], rdx
	mov	[rdi+tui_authpanel_focusinputcolors_ofs], rcx
	mov	[rdi+tui_authpanel_newform_ofs], r8
	xor	edx, edx
	mov	[rdi+tui_authpanel_username_ofs], rdx
	mov	[rdi+tui_authpanel_password_ofs], rdx
	mov	[rdi+tui_authpanel_token_ofs], rdx
	mov	[rdi+tui_authpanel_newuserbutton_ofs], rdx

	mov	rdx, [rdi+tui_panel_guts_ofs]		; our inner guts object, who's tui_children_ofs list has the goods we are after
	mov	rdx, [rdx+tui_children_ofs]
	; see the notes atop re: cloning requirements here
	; the original must be in its INITIAL state, or bad things might happen here
	; so, if the source authpanel has a newuserbutton, then we know to copy the three
	; if it has a token, then the token only
	; otherwise, user and pass

	; for the autheditors:
	; each child in the list is a 100% wide horizontal layout, with its first child as the label
	; and the second child as the autheditor that we are interested in finding
	; for the button, it is a 100% wide vertical layout, with its only child as the one we are interested in

	cmp	qword [rsi+tui_authpanel_newuserbutton_ofs], 0
	jne	.newuserbutton
	cmp	qword [rsi+tui_authpanel_token_ofs], 0
	jne	.token
	; otherwise, username and password are in our guts list
	mov	rsi, [rdx+_list_first_ofs]

	; the first child in the authpanel guts is an hspacer, added by the original new call
	mov	rsi, [rsi+_list_nextofs]

	mov	rdx, [rsi]				; the 100% wide horizontal layout
	mov	rcx, [rdx+tui_children_ofs]		; its child list
	mov	r8, [rcx+_list_first_ofs]
	mov	r8, [r8+_list_nextofs]
	mov	rax, [r8]				; the username
	mov	[rdi+tui_authpanel_username_ofs], rax
	; we also need to set its tui_text_user_ofs back to our authpanel:
	mov	[rax+tui_text_user_ofs], rdi

	mov	rsi, [rsi+_list_nextofs]
	mov	rdx, [rsi]				; the 100% wide horizontal layout
	mov	rcx, [rdx+tui_children_ofs]		; its child list
	mov	r8, [rcx+_list_first_ofs]
	mov	r8, [r8+_list_nextofs]
	mov	rax, [r8]				; the password
	mov	[rdi+tui_authpanel_password_ofs], rax
	; set its linkback:
	mov	[rax+tui_text_user_ofs], rdi
	
	mov	rax, rdi
	add	rsp, 16
	epilog
calign
.token:
	mov	rsi, [rdx+_list_first_ofs]

	; the first child in the authpanel guts is an hspacer, added by the original new call
	mov	rsi, [rsi+_list_nextofs]

	mov	rdx, [rsi]				; the 100% wide horizontal layout
	mov	rcx, [rdx+tui_children_ofs]		; its child list
	mov	r8, [rcx+_list_first_ofs]
	mov	r8, [r8+_list_nextofs]
	mov	rax, [r8]				; the token
	mov	[rdi+tui_authpanel_token_ofs], rax
	; set its linkback:
	mov	[rax+tui_text_user_ofs], rdi

	mov	rax, rdi
	add	rsp, 16
	epilog
calign
.newuserbutton:
	mov	rsi, [rdx+_list_first_ofs]

	; the first child in the authpanel guts is an hspacer, added by the original new call
	mov	rsi, [rsi+_list_nextofs]

	mov	rdx, [rsi]				; the 100% wide horizontal layout
	mov	rcx, [rdx+tui_children_ofs]		; its child list
	mov	r8, [rcx+_list_first_ofs]
	mov	r8, [r8+_list_nextofs]
	mov	rax, [r8]				; the username
	mov	[rdi+tui_authpanel_username_ofs], rax
	; set its linkback:
	mov	[rax+tui_text_user_ofs], rdi

	mov	rsi, [rsi+_list_nextofs]
	mov	rdx, [rsi]				; the 100% wide horizontal layout
	mov	rcx, [rdx+tui_children_ofs]		; its child list
	mov	r8, [rcx+_list_first_ofs]
	mov	r8, [r8+_list_nextofs]
	mov	rax, [r8]				; the password
	mov	[rdi+tui_authpanel_password_ofs], rax
	; set its linkback:
	mov	[rax+tui_text_user_ofs], rdi
	
	; it has a hspacer next, so skip that one
	mov	rsi, [rsi+_list_nextofs]

	mov	rsi, [rsi+_list_nextofs]
	mov	rdx, [rsi]				; the 100% wide centered vertical layout
	mov	rcx, [rdx+tui_children_ofs]		; its child list
	mov	r8, [rcx+_list_first_ofs]
	mov	rax, [r8]				; the newuserbutton
	mov	[rdi+tui_authpanel_newuserbutton_ofs], rax

	mov	rax, rdi
	add	rsp, 16
	epilog
	
end if

if used tui_authpanel$normalsetup | defined include_everything
	; single argument in rdi: our tui_authpanel object
falign
tui_authpanel$normalsetup:
	prolog	tui_authpanel$normalsetup
	push	rbx
	mov	rbx, rdi
	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	
	mov	edi, 19
	mov	esi, 1
	mov	rdx, .t1
	mov	ecx, dword [rbx+tui_panel_titlecolors_ofs]
	mov	r8d, tui_textalign_left
	mov	r9d, 11
	mov	r10, .t2
	cmp	dword [rbx+tui_authpanel_newform_ofs], 0
	cmove	rdx, r10
	cmove	edi, r9d
	call	tui_label$new_ii

	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, 24
	mov	esi, 1
	mov	rdx, .t5
	mov	ecx, [rbx+tui_authpanel_inputcolors_ofs]
	mov	r8d, [rbx+tui_authpanel_focusinputcolors_ofs]
	mov	r9, rbx
	call	tui_autheditor$new
	mov	[rbx+tui_authpanel_username_ofs], rax

	mov	dword [rax+tui_text_maxlen_ofs], 32
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; same again for the password
	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	
	mov	edi, 19
	mov	esi, 1
	mov	rdx, .t3
	mov	ecx, dword [rbx+tui_panel_titlecolors_ofs]
	mov	r8d, tui_textalign_left
	mov	r9d, 11
	mov	r10, .t4
	cmp	dword [rbx+tui_authpanel_newform_ofs], 0
	cmove	rdx, r10
	cmove	edi, r9d
	call	tui_label$new_ii

	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, 24
	mov	esi, 1
	mov	rdx, .t5
	mov	ecx, [rbx+tui_authpanel_inputcolors_ofs]
	mov	r8d, [rbx+tui_authpanel_focusinputcolors_ofs]
	mov	r9, rbx
	call	tui_autheditor$new
	mov	[rbx+tui_authpanel_password_ofs], rax

	mov	dword [rax+tui_text_maxlen_ofs], 32
	mov	dword [rax+tui_text_pwdchar_ofs], 'X'
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]


	; if we are a newform, add the password dup entry:
	cmp	dword [rbx+tui_authpanel_newform_ofs], 0
	je	.skip_passdup

	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	
	mov	edi, 19
	mov	esi, 1
	mov	rdx, .t6
	mov	ecx, dword [rbx+tui_panel_titlecolors_ofs]
	mov	r8d, tui_textalign_left
	call	tui_label$new_ii

	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, 24
	mov	esi, 1
	mov	rdx, .t5
	mov	ecx, [rbx+tui_authpanel_inputcolors_ofs]
	mov	r8d, [rbx+tui_authpanel_focusinputcolors_ofs]
	mov	r9, rbx
	call	tui_autheditor$new
	mov	[rbx+tui_authpanel_token_ofs], rax

	mov	dword [rax+tui_text_maxlen_ofs], 32
	mov	dword [rax+tui_text_pwdchar_ofs], 'X'
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]


calign
.skip_passdup:
	; set the focus for the username input field

	mov	rdi, [rbx+tui_authpanel_username_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]

	pop	rbx
	epilog
cleartext .t1, ' Desired Username: '
cleartext .t2, ' Username: '
cleartext .t3, ' Desired Password: '
cleartext .t4, ' Password: '
cleartext .t5, ''
cleartext .t6, ' Re-type Password: '

end if

if used tui_authpanel$newusersetup | defined include_everything
	; single argument in rdi: our tui_authpanel object
falign
tui_authpanel$newusersetup:
	prolog	tui_authpanel$newusersetup
	push	rbx
	mov	rbx, rdi
	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	
	mov	edi, 11
	mov	esi, 1
	mov	rdx, .t1
	mov	ecx, dword [rbx+tui_panel_titlecolors_ofs]
	mov	r8d, tui_textalign_left
	call	tui_label$new_ii

	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, 24
	mov	esi, 1
	mov	rdx, .t3
	mov	ecx, [rbx+tui_authpanel_inputcolors_ofs]
	mov	r8d, [rbx+tui_authpanel_focusinputcolors_ofs]
	mov	r9, rbx
	call	tui_autheditor$new
	mov	[rbx+tui_authpanel_username_ofs], rax

	mov	dword [rax+tui_text_maxlen_ofs], 32
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; same again for the password
	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	
	mov	edi, 11
	mov	esi, 1
	mov	rdx, .t2
	mov	ecx, dword [rbx+tui_panel_titlecolors_ofs]
	mov	r8d, tui_textalign_left
	call	tui_label$new_ii

	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, 24
	mov	esi, 1
	mov	rdx, .t3
	mov	ecx, [rbx+tui_authpanel_inputcolors_ofs]
	mov	r8d, [rbx+tui_authpanel_focusinputcolors_ofs]
	mov	r9, rbx
	call	tui_autheditor$new
	mov	[rbx+tui_authpanel_password_ofs], rax

	mov	dword [rax+tui_text_maxlen_ofs], 32
	mov	dword [rax+tui_text_pwdchar_ofs], 'X'
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; give the username field focus

	mov	rdi, [rbx+tui_authpanel_username_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]

	; add a new user button as well
	movq	xmm0, [_math_onehundred]
	call	tui_hspacer$new_d
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 4
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center

	; invert our inputcolors for the button
	mov	eax, [rbx+tui_authpanel_inputcolors_ofs]
	xchg	ah, al
	
	mov	rdi, .t4
	mov	esi, [rbx+tui_panel_titlecolors_ofs]
	mov	edx, eax
	mov	ecx, [rbx+tui_authpanel_focusinputcolors_ofs]
	call	tui_button$new

	mov	[rbx+tui_authpanel_newuserbutton_ofs], rax
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	
	pop	rbx
	epilog
cleartext .t1, ' Username: '
cleartext .t2, ' Password: '
cleartext .t3, ''
cleartext .t4, 'New User'

end if

if used tui_authpanel$tokensetup | defined include_everything
	; single argument in rdi: our tui_authpanel object
falign
tui_authpanel$tokensetup:
	prolog	tui_authpanel$tokensetup
	push	rbx
	mov	rbx, rdi
	mov	edi, tui_object_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	qword [rdi], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	
	mov	edi, 15
	mov	esi, 1
	mov	rdx, .t1
	mov	ecx, dword [rbx+tui_panel_titlecolors_ofs]
	mov	r8d, tui_textalign_left
	call	tui_label$new_ii

	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	edi, 32
	mov	esi, 1
	mov	rdx, .t2
	mov	ecx, [rbx+tui_authpanel_inputcolors_ofs]
	mov	r8d, [rbx+tui_authpanel_focusinputcolors_ofs]
	mov	r9, rbx
	call	tui_autheditor$new
	mov	[rbx+tui_authpanel_token_ofs], rax
	
	mov	dword [rax+tui_text_pwdchar_ofs], 'X'
	mov	dword [rax+tui_text_maxlen_ofs], 64
	mov	rdi, [rsp]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, rbx
	pop	rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, [rbx+tui_authpanel_token_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vgotfocus]

	pop	rbx
	epilog
cleartext .t1, ' Access Token: '
cleartext .t2, ''

end if

if used tui_authpanel$keyevent | defined include_everything
	; three arguments: rdi == our tui_authpanel object, esi == key, edx == esc_key
falign
tui_authpanel$keyevent:
	prolog	tui_authpanel$keyevent
	; ok, so we want a few different "overrides" here...
	; if the up or down arrows come through, treat them as tab/shifttab
	cmp	edx, 0x41	; up arrow
	je	.uparrow
	cmp	edx, 0x42	; down arrow
	je	.downarrow
	; if we receive an enter key, the only it will be unhandled by the autheditor
	; is if the newuser button has the focus when it is pressed, so _swallow_ it
	; and same with left/right arrows
	cmp	edx, 0x43	; right arrow
	je	.swallow
	cmp	edx, 0x44	; left arrow
	je	.swallow
	cmp	edx, 13
	je	.swallow
	xor	eax, eax	; unhandled
	epilog
calign
.swallow:
	mov	eax, 1
	epilog
calign
.uparrow:
	; hmmm, should we be using our vtable for these?
	call	tui_authpanel$onshifttab
	mov	eax, 1
	epilog
calign
.downarrow:
	call	tui_authpanel$ontab
	mov	eax, 1
	epilog

end if


if used tui_authpanel$ontab | defined include_everything
	; single argument in rdi: our tui_authpanel object
falign
tui_authpanel$ontab:
	prolog	tui_authpanel$ontab
	mov	rsi, [rdi+tui_authpanel_username_ofs]
	test	rsi, rsi
	jz	.nousername
	cmp	dword [rsi+tui_text_focussed_ofs], 0
	je	.nousername
	push	qword [rdi+tui_authpanel_password_ofs]
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nousername:
	mov	rsi, [rdi+tui_authpanel_password_ofs]
	test	rsi, rsi
	jz	.nopassword
	cmp	dword [rsi+tui_text_focussed_ofs], 0
	je	.nopassword
	push	rdi
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	cmp	qword [rdi+tui_authpanel_newuserbutton_ofs], 0
	jne	.newuserbutton
	cmp	dword [rdi+tui_authpanel_newform_ofs], 0
	jne	.newform
	mov	rdi, [rdi+tui_authpanel_username_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.newform:
	mov	rdi, [rdi+tui_authpanel_token_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.newuserbutton:
	push	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vhidecursor]
	pop	rdi
	mov	rdi, [rdi+tui_authpanel_newuserbutton_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nopassword:
	cmp	dword [rdi+tui_authpanel_newform_ofs], 0
	jne	.newform2
	mov	rsi, [rdi+tui_authpanel_newuserbutton_ofs]
	test	rsi, rsi
	jz	.nothingtodo
	cmp	dword [rsi+tui_button_focussed_ofs], 0
	je	.nothingtodo
	push	rdi
	push	qword [rdi+tui_authpanel_username_ofs]
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	pop	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vshowcursor]
	epilog
calign
.newform2:
	push	rdi
	mov	rdi, [rdi+tui_authpanel_token_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	mov	rdi, [rdi+tui_authpanel_username_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_authpanel$onshifttab | defined include_everything
	; single argument in rdi: our tui_authpanel object
falign
tui_authpanel$onshifttab:
	prolog	tui_authpanel$onshifttab
	mov	rsi, [rdi+tui_authpanel_username_ofs]
	test	rsi, rsi
	jz	.nousername
	cmp	dword [rsi+tui_text_focussed_ofs], 0
	je	.nousername
	push	rdi
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	cmp	dword [rdi+tui_authpanel_newform_ofs], 0
	jne	.username_token
	cmp	qword [rdi+tui_authpanel_newuserbutton_ofs], 0
	jne	.newuserbutton
	mov	rdi, [rdi+tui_authpanel_password_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.username_token:
	mov	rdi, [rdi+tui_authpanel_token_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.newuserbutton:
	push	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vhidecursor]
	pop	rdi
	mov	rdi, [rdi+tui_authpanel_newuserbutton_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nousername:
	mov	rsi, [rdi+tui_authpanel_password_ofs]
	test	rsi, rsi
	jz	.nopassword
	cmp	dword[ rsi+tui_text_focussed_ofs], 0
	je	.nopassword
	push	qword [rdi+tui_authpanel_username_ofs]
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nopassword:
	cmp	dword [rdi+tui_authpanel_newform_ofs], 0
	jne	.nopassword_token
	mov	rsi, [rdi+tui_authpanel_newuserbutton_ofs]
	test	rsi, rsi
	jz	.nothingtodo
	cmp	dword [rsi+tui_button_focussed_ofs], 0
	je	.nothingtodo
	push	rdi
	push	qword [rdi+tui_authpanel_password_ofs]
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	pop	rdi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vshowcursor]
	epilog
calign
.nopassword_token:
	mov	rsi, [rdi+tui_authpanel_token_ofs]
	test	rsi, rsi
	jz	.nothingtodo
	cmp	dword [rsi+tui_text_focussed_ofs], 0
	je	.nothingtodo
	; else, up to the password field
	push	rdi
	mov	rdi, rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vlostfocus]
	pop	rdi
	mov	rdi, [rdi+tui_authpanel_password_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vgotfocus]
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_authpanel$enterpressed | defined include_everything
	; two arguments: rdi == our tui_authpanel object, rsi == the tui_autheditor that has focus and sent us the event
falign
tui_authpanel$enterpressed:
	prolog	tui_authpanel$enterpressed
	; if they hit enter on the username, and the password is not-yet-filled, change focus to the password
	cmp	qword [rdi+tui_authpanel_username_ofs], 0
	je	.submit
	cmp	qword [rdi+tui_authpanel_password_ofs], 0
	je	.submit
	; the username must be non-empty as well
	push	rdi
	mov	rdi, [rdi+tui_authpanel_username_ofs]
	call	tui_text$nvgettext
	push	qword [rax]
	mov	rdi, rax
	call	heap$free
	pop	rcx rdi
	test	rcx, rcx
	jz	.dotab
	; if it is a newform, then we also need to check to make sure the retype password is also set
	cmp	dword [rdi+tui_authpanel_newform_ofs], 0
	jne	.newform
	push	rdi
	mov	rdi, [rdi+tui_authpanel_password_ofs]
	call	tui_text$nvgettext
	push	qword [rax]
	mov	rdi, rax
	call	heap$free
	pop	rcx rdi
	test	rcx, rcx
	jnz	.submit
calign
.dotab:
	mov	rdx, [rdi]
	call	qword [rdx+tui_vontab]
	epilog
calign
.newform:
	sub	rsp, 24
	mov	[rsp], rdi
	mov	rdi, [rdi+tui_authpanel_password_ofs]
	call	tui_text$nvgettext
	mov	[rsp+8], rax
	mov	rdi, [rsp]
	cmp	qword [rax], 0
	je	.newform_tab
	mov	rdi, rax
	call	heap$free
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_authpanel_token_ofs]
	call	tui_text$nvgettext
	mov	[rsp+8], rax
	mov	rdi, [rsp]
	cmp	qword [rax], 0
	je	.newform_tab
	mov	rdi, rax
	call	heap$free
	mov	rdi, [rsp]
	add	rsp, 24
	jmp	.submit
calign
.newform_tab:
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, [rsp]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vontab]
	add	rsp, 24
	epilog
calign
.submit:
	mov	rdi, [rdi+tui_authpanel_as_ofs]
	call	tui_simpleauth$enterpressed
	epilog

end if

if used tui_authpanel$clicked | defined include_everything
	; two arguments: rdi == our tui_authpanel object, rsi == tui_object that got clicked
falign
tui_authpanel$clicked:
	prolog	tui_authpanel$clicked
	; pass this backward to the simpleauth screen object, it can only mean the new user button was clicked
	; so we don't bother to check that rsi really is the newuserbutton
	mov	rdi, [rdi+tui_authpanel_as_ofs]
	call	tui_simpleauth$newuserclicked
	epilog

end if
