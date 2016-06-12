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
	; userdb.inc: the sshtalk user load/store
	;
	; Since this really isn't intended to be "huge" as such, we
	; just use flat files to store our info.
	;
	; Further, we include our tui_simpleauth virtual method table
	; such that we hook newuser and authentication directly
	;

	; user objects that are held globally and provide the necessary
	; functionality that we need (notification of online/offline, etc)
user_username_ofs = 0
user_password_ofs = 8
user_buddylist_ofs = 16
user_notifies_ofs = 24
user_tuilist_ofs = 32

user_size = 40


	; our userdb filename (we default to CWD, but full paths are fine too)
cleartext userdb_filename, 'sshtalk.userdb'


globals
{
	; a global stringmap for our users:
	users		dq	0
	; a global formatter for new user syslog messages:
	logfmt_new	dq	0
}

	; a copy of tui_simpleauth's vtable, with our own two methods that we need
dalign
userdb$vtable:
	dq      tui_simpleauth$cleanup, tui_simpleauth$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_simpleauth$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; and our userdb_auth specific methods:
	dq	userdb$authenticate, tui_simpleauth$allow_token, userdb$newuser



	; no arguments, called from sshtalk.asm to read our initial goods
falign
userdb$init:
	prolog	userdb$init
	push	rbx r12 r13
	; first up, our user map, in sort order
	xor	edi, edi
	call	stringmap$new
	mov	[users], rax
	; create our syslog formatters next:
	xor	edi, edi
	call	formatter$new
	mov	[logfmt_new], rax
	mov	rdi, [logfmt_new]
	mov	rsi, .logmsg_newuser
	call	formatter$add_static
	mov	rdi, [logfmt_new]
	xor	esi, esi
	call	formatter$add_string
	; load our userdb file next
	mov	rdi, userdb_filename
	call	file$to_buffer
	test	rax, rax
	jz	.nothingtodo
	mov	rbx, rax
calign
.doit:
	; make use of buffer's "line based convenience functions", haha
	mov	rdi, rbx
	mov	esi, 1		; consume leading empty lines
	call	buffer$has_more_lines
	test	eax, eax
	jz	.loadcomplete
	mov	rdi, rbx
	call	buffer$nextline
	mov	r12, rax
	; skip empty lines, lines that begin with space or #
	cmp	qword [rax], 0
	je	.skipline
	mov	rdi, rax
	mov	esi, 0
	call	string$charat
	cmp	eax, ' '
	je	.skipline
	cmp	eax, '#'
	je	.skipline
	; otherwise, split it by pipe delimiter
	mov	rdi, r12
	mov	esi, '|'
	call	string$split
	; get rid of the original string, swap r12 with our list
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	; list must contain at least 2 strings or we ignore the line and keep going
	cmp	qword [r12+_list_size_ofs], 2
	jb	.skiplist
	; it is possible that our user object already exists, in the case
	; of a previous buddylist reference
	mov	rdx, [r12+_list_first_ofs]
	mov	rdi, [users]
	mov	rsi, [rdx]
	call	stringmap$find_value
	; stringmap$find_value returns bool in eax, value in rdx
	mov	r13, rdx
	test	eax, eax
	jnz	.userobject_okay
	; otherwise, go ahead and create a user object
	mov	edi, user_size
	call	heap$alloc_clear
	mov	r13, rax
	mov	rdi, r12
	call	list$pop_front
	mov	[r13+user_username_ofs], rax
	mov	rdi, r12
	call	list$pop_front
	mov	[r13+user_password_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	[r13+user_buddylist_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	[r13+user_notifies_ofs], rax
	xor	edi, edi
	call	unsignedmap$new
	mov	[r13+user_tuilist_ofs], rax
	; last but not least, add to our users list
	mov	rdi, [users]
	mov	rsi, [r13+user_username_ofs]
	mov	rdx, r13
	call	stringmap$insert_unique
	jmp	.buddylist
cleartext .logmsg_newuser, 'New user added: '
cleartext .logmsg_auth, 'Authenticated: '
calign
.userobject_okay:
	; we haven't yet pulled anything from our token list
	; _if_ we already have a password, this is a duplicate
	; (and thus erroneous) user object, so we ignore this
	; entry entirely
	cmp	qword [r13+user_password_ofs], 0
	jne	.skiplist
	; otherwise, we can skip the username completely:
	mov	rdi, r12
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	; and now set the password:
	mov	rdi, r12
	call	list$pop_front
	mov	[r13+user_password_ofs], rax
	; the rest of the user object values should be okay
	; so fallthrough to .buddylist
calign
.buddylist:
	; so now, user/pass have been removed from the head
	; of our list, anything that remains are buddy names
	mov	rdi, r12
	mov	rsi, .handle_buddy
	mov	rdx, r13
	; list$clear/list$clear_arg effectively does a foreach, but also empties the list
	; exactly what we want
	call	list$clear_arg
	mov	rdi, r12
	call	heap$free
	jmp	.doit
falign
.handle_buddy:
	; since we don't really care/want profiling here
	; called with rdi == string buddy name, rsi == user object it belongs to
	push	rdi rsi
	; first up, find or create the buddy user object
	mov	rsi, rdi
	mov	rdi, [users]
	call	stringmap$find_value
	test	eax, eax
	jz	.newbuddy
calign
.handle_buddy_doit:
	; rdx is the buddy user object
	; so, to our user's buddylist, we add the buddy
	; and then to our buddy's notify list, we add our user
	mov	rdi, [rsp]
	push	rdx
	; [rsp+16] == string buddy name
	; [rsp+8] == original user object
	; [rsp] == buddy object
	mov	rsi, [rdx+user_username_ofs]
	mov	rdi, [rdi+user_buddylist_ofs]
	call	stringmap$insert_unique
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+8]
	mov	rdi, [rdi+user_notifies_ofs]
	mov	rsi, [rsi+user_username_ofs]
	call	stringmap$insert_unique
	; free the buddy name string that was passed to us:
	mov	rdi, [rsp+16]
	call	heap$free
	add	rsp, 24
	ret
calign
.newbuddy:
	; the buddy user object didn't exist, add a new one for it with a null password
	mov	edi, user_size
	call	heap$alloc_clear
	mov	rdi, [rsp+8]
	push	rax
	call	string$copy
	mov	rsi, [rsp]
	mov	[rsi+user_username_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	rsi, [rsp]
	mov	[rsi+user_buddylist_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	rsi, [rsp]
	mov	[rsi+user_notifies_ofs], rax
	xor	edi, edi
	call	unsignedmap$new
	mov	rsi, [rsp]
	mov	[rsi+user_tuilist_ofs], rax

	; now, add that to our users 
	mov	rdi, [users]
	mov	rdx, rsi
	mov	rsi, [rsi+user_username_ofs]
	call	stringmap$insert_unique
	pop	rdx
	jmp	.handle_buddy_doit
calign
.skiplist:
	; free the strings sitting in the list first up:
	mov	rdi, r12
	mov	rsi, heap$free
	call	list$clear
	; free the list itself:
	mov	rdi, r12
	call	heap$free
	jmp	.doit
calign
.skipline:
	mov	rdi, r12
	call	heap$free
	jmp	.doit
calign
.nothingtodo:
	pop	r13 r12 rbx
	epilog
calign
.loadcomplete:
	mov	rdi, rbx
	call	buffer$destroy
	pop	r13 r12 rbx
	epilog





	; no arguments: does the reverse of userdb$init, and writes it all back out
falign
userdb$save:
	prolog	userdb$save
	push	rbx
	call	buffer$new
	mov	rbx, rax
	mov	rdi, [users]
	mov	rsi, .douser
	mov	rdx, rax
	call	stringmap$foreach_arg
	mov	rdi, rbx
	mov	rsi, userdb_filename
	call	buffer$file_write
	mov	rdi, rbx
	call	buffer$destroy
	pop	rbx
	epilog
falign
.douser:
	; called with rdi == string of username, rsi == username object, rdx == our buffer
	cmp	qword [rsi+user_password_ofs], 0
	je	.reference_only
	; otherwise, append our pipe-delimited goods, followed by a final LF
	push	rbx r12
	mov	rbx, rsi
	mov	r12, rdx
	mov	rdi, rdx
	mov	rsi, [rsi+user_username_ofs]
	call	buffer$append_string
	mov	rdi, r12
	mov	esi, '|'
	call	buffer$append_byte
	mov	rdi, r12
	mov	rsi, [rbx+user_password_ofs]
	call	buffer$append_string
	mov	rdi, [rbx+user_buddylist_ofs]
	mov	rsi, .douserbuddies
	mov	rdx, r12
	call	stringmap$foreach_arg
	mov	rdi, r12
	mov	esi, 10
	call	buffer$append_byte
	pop	r12 rbx
	ret
calign
.reference_only:
	; user objects with null passwords == created from a buddylist reference only
	; which means we don't need to save it
	ret
falign
.douserbuddies:
	; called with rdi == string of buddy name, rsi == buddy object, rdx == our buffer
	push	rdi rdx
	mov	rdi, rdx
	mov	esi, '|'
	call	buffer$append_byte
	pop	rdi rsi
	call	buffer$append_string
	ret




	; three arguments: rdi == the tui_simpleauth object, rsi == string username, rdx == string password
	; we are expected to return a bool in eax as to whether we succeed or not
falign
userdb$authenticate:
	prolog	userdb$authenticate
	; first up: scrypt our password
	cmp	qword [rdx], 0
	je	.denied
	push	rbx r12 r13
	; make sure the user exists, or don't bother scrypting it
	mov	rbx, rsi
	mov	r12, rdx
	mov	rdi, [users]
	call	stringmap$find_value
	test	eax, eax
	jz	.nosuchuser
	cmp	qword [rdx+user_password_ofs], 0
	je	.nosuchuser
	push	rdx
	; convert the password to UTF8 first
	mov	rdi, r12
	call	string$utf8_length
	mov	rdi, r12
	mov	r12, rax
	mov	r13, rax
	add	r13, 15
	and	r13, not 15
	sub	rsp, r13
	mov	rsi, rsp
	call	string$to_utf8
	mov	rdx, rsp		; UTF8 password
	mov	ecx, r12d		; UTF8 password length
	; use the UTF8 password as the salt as well:
	mov	r8, rsp
	mov	r9d, r12d
	sub	rsp, 32			; -32 for our scrypt goods
	mov	rdi, rsp
	mov	esi, 32
	add	r13, 32
	call	scrypt
	; now turn that into a string
	mov	rdi, rsp
	mov	esi, 32
	call	string$from_bintohex
	add	rsp, r13
	mov	r12, rax
	pop	r13			; our user object
	mov	rdi, rax
	mov	rsi, [r13+user_password_ofs]
	call	string$equals
	; get rid of our password string
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	; done and dusted
	mov	rax, r12
	pop	r13 r12 rbx
	epilog
calign
.nosuchuser:
	pop	r13 r12 rbx
	xor	eax, eax
	epilog
calign
.denied:
	xor	eax, eax
	epilog



	; three arguments: rdi == the tui_simpleauth object, rsi == string username, rdx == string password
	; we are expected to return: null/zero in rax on success, or string error message to display
falign
userdb$newuser:
	prolog	userdb$newuser
	push	rbx r12 r13
	mov	rbx, rsi
	mov	r12, rdx
	; we only do simple sanity checks, rubbish is fine with me
	mov	rax, .tooshort
	cmp	qword [rsi], 2
	jb	.error
	mov	rax, .passtooshort
	cmp	qword [rdx], 4
	jb	.error
	mov	rdi, rsi
	mov	esi, '|'
	call	string$indexof_charcode
	cmp	rax, 0
	mov	rax, .nopipes
	jge	.error
	mov	rdi, [users]
	mov	rsi, rbx
	call	stringmap$find_value
	test	eax, eax
	jz	.proceed_new
	mov	rax, .userexists
	cmp	qword [rdx+user_password_ofs], 0
	jne	.error
	; else, this user object exists already, but had no password
	; which means someone already added us as a buddy, before we were a user
	mov	rbx, rdx
	jmp	.proceed_setpassword
	; our error strings:
cleartext .tooshort, 'Username too short.'
cleartext .passtooshort, 'Password too short.'
cleartext .userexists, 'Username already taken.'
cleartext .nopipes, 'Username cannot contain pipes.'
calign
.proceed_new:
	; no user object was located, and the lengths were okay
	mov	edi, user_size
	call	heap$alloc_clear
	mov	rdi, rbx
	mov	rbx, rax
	call	string$copy
	mov	[rbx+user_username_ofs], rax
	; create the rest of the objects we need, except the password
	xor	edi, edi
	call	stringmap$new
	mov	[rbx+user_buddylist_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	[rbx+user_notifies_ofs], rax
	xor	edi, edi
	call	unsignedmap$new
	mov	[rbx+user_tuilist_ofs], rax
	; add this user object to the users map
	mov	rdi, [users]
	mov	rsi, [rbx+user_username_ofs]
	mov	rdx, rbx
	call	stringmap$insert_unique
	; fallthrough to set the password
calign
.proceed_setpassword:
	; our password needs to be turned into UTF8, then scrypt'd just like the auth does
	mov	rdi, r12
	call	string$utf8_length
	mov	rdi, r12
	mov	r12, rax
	mov	r13, rax
	add	r13, 15
	and	r13, not 15
	sub	rsp, r13
	mov	rsi, rsp
	call	string$to_utf8
	mov	rdx, rsp		; UTF8 password
	mov	ecx, r12d		; UTF8 password length
	; use the UTF8 password as the salt as well:
	mov	r8, rsp
	mov	r9d, r12d
	sub	rsp, 32			; -32 for our scrypt goods
	mov	rdi, rsp
	mov	esi, 32
	add	r13, 32
	call	scrypt
	; now turn that into a string
	mov	rdi, rsp
	mov	esi, 32
	call	string$from_bintohex
	add	rsp, r13
	mov	[rbx+user_password_ofs], rax
	; syslog our new arrival:
	mov	rdi, [logfmt_new]
	mov	rsi, [rbx+user_username_ofs]
	call	formatter$doit
	push	rax
	mov	rsi, rax
	mov	edi, log_notice
	call	syslog
	pop	rdi
	call	heap$free
	; save the updated userdb:
	call	userdb$save
	; if we are running on the 2ton.com.au machine, or my local dev machine
	; auto-add @Sysop to their buddy list
        mov     rdi, [uname$nodename]
        mov     rsi, .hostname_slave
        call    string$starts_with
        push    rax
        mov     rdi, [uname$nodename]
        mov     rsi, .hostname_cdev
        call    string$equals
        pop     rcx
        or      eax, ecx
	test	eax, eax
	jnz	.2ton

	; done, dusted
	xor	eax, eax
	pop	r13 r12 rbx
	epilog
calign
.2ton:
	mov	rdi, [rbx+user_username_ofs]
	mov	rsi, .sysop
	call	userdb$addbuddy
	xor	eax, eax
	pop	r13 r12 rbx
	epilog
cleartext .hostname_slave, 'slave.'
cleartext .hostname_cdev, 'cdev'
cleartext .sysop, '@Sysop'
calign
.error:
	pop	r13 r12 rbx
	epilog




	; two arguments: rdi == string username, rsi == string buddy username
	; similar to new user, we are expected to return null on success, or a string error
falign
userdb$addbuddy:
	prolog	userdb$addbuddy
	push	rbx r12
	mov	r12, rsi
	mov	rsi, rdi
	mov	rdi, [users]
	call	stringmap$find_value
	test	eax, eax
	mov	rax, .internalerror
	jz	.error
	mov	rbx, rdx
	; make sure this buddy username is not already in their list
	mov	rdi, [rdx+user_buddylist_ofs]
	mov	rsi, r12
	call	stringmap$find_value
	test	eax, eax
	mov	rax, .alreadythere
	jnz	.error
	; make sure the buddy username is sane
	mov	rax, .tooshort
	cmp	qword [r12], 2
	jb	.error
	mov	rdi, r12
	mov	esi, '|'
	call	string$indexof_charcode
	cmp	rax, 0
	mov	rax, .nopipes
	jge	.error
	; now lookup the buddy object, or create a new one if it doesn't exist
	mov	rdi, [users]
	mov	rsi, r12
	call	stringmap$find_value
	test	eax, eax
	jz	.newuserobject
	; otherwise, the buddy object exists
	mov	r12, rdx
	jmp	.doit
calign
.newuserobject:
	; buddy name did not exist in our users, so create a new one
	mov	edi, user_size
	call	heap$alloc_clear
	mov	rdi, r12
	mov	r12, rax
	call	string$copy
	mov	[r12+user_username_ofs], rax
	; allocate the essential bits for the user object
	xor	edi, edi
	call	stringmap$new
	mov	[r12+user_buddylist_ofs], rax
	xor	edi, edi
	call	stringmap$new
	mov	[r12+user_notifies_ofs], rax
	xor	edi, edi
	call	unsignedmap$new
	mov	[r12+user_tuilist_ofs], rax
	; add this to the users map
	mov	rdi, [users]
	mov	rsi, [r12+user_username_ofs]
	mov	rdx, r12
	call	stringmap$insert_unique
calign
.doit:
	; so now, we have to add to buddy and notifies
	mov	rdi, [rbx+user_buddylist_ofs]
	mov	rsi, [r12+user_username_ofs]
	mov	rdx, r12
	call	stringmap$insert_unique
	; and for the buddy object itself, add the notifies back to us
	mov	rdi, [r12+user_notifies_ofs]
	mov	rsi, [rbx+user_username_ofs]
	mov	rdx, rbx
	call	stringmap$insert_unique
	; save the updated userdb:
	call	userdb$save
	xor	eax, eax
	pop	r12 rbx
	epilog
cleartext .alreadythere, 'Duplicate buddy name.'
cleartext .tooshort, 'Buddy name too short.'
cleartext .internalerror, 'WTF?! Reached an impossible codespot.'
cleartext .nopipes, 'Name cannot contain pipes.'
calign
.error:
	pop	r12 rbx
	epilog







	; two arguments: rdi == string username, rsi == string buddy username
	; similar to new user, we are expected to return null on success, or a string error
falign
userdb$removebuddy:
	prolog	userdb$removebuddy
	push	rbx r12
	mov	r12, rsi
	mov	rsi, rdi
	mov	rdi, [users]
	call	stringmap$find_value
	test	eax, eax
	mov	rax, .internalerror
	jz	.error
	mov	rbx, rdx
	; make sure this buddy username is not already in their list
	mov	rdi, [rdx+user_buddylist_ofs]
	mov	rsi, r12
	call	stringmap$find_value
	test	eax, eax
	mov	rax, .nosuchbuddy
	jz	.error
	mov	r12, rdx
	; so now, remove the buddy from rbx's buddylist
	; and remove the rbx's username from r12's notifies
	mov	rdi, [rbx+user_buddylist_ofs]
	mov	rsi, [r12+user_username_ofs]
	; now, since the key and the value for each of buddylist and notifies
	; is not duplicated (and actually points into the users map itself)
	; we don't have to worry about freeing them
	call	stringmap$erase
	; and do the same again for the notifies
	mov	rdi, [r12+user_notifies_ofs]
	mov	rsi, [rbx+user_username_ofs]
	call	stringmap$erase
	; update the userdb
	call	userdb$save
	; done, dusted.
	xor	eax, eax
	pop	r12 rbx
	epilog
cleartext .internalerror, 'WTF?! Reached an impossible codespot.'
cleartext .nosuchbuddy, 'No such buddy.'
calign
.error:
	pop	r12 rbx
	epilog






	; single argument in rdi: a username to check
	; returns bool in eax as to whether said username is online or not
falign
userdb$online:
	prolog	userdb$online
	mov	rsi, rdi
	mov	rdi, [users]
	call	stringmap$find_value
	test	eax, eax
	jz	.falseret
	mov	rdi, [rdx+user_tuilist_ofs]
	cmp	qword [rdi+_avlofs_right], 0		; its nodecount
	je	.falseret
	mov	eax, 1
	epilog
calign
.falseret:
	xor	eax, eax
	epilog

