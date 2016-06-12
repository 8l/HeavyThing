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
	; chatroom.inc: basic room management routines for sshtalk
	;
	; A chatroom contains an optional name, optional topic, and one more more
	; participants, which are user objects.
	;
	; Unnamed rooms are for 1:1 chatting, named rooms get placed into our
	; global [chatrooms] map, and get torn down when the last participant
	; bails out.
	;

chatroom_name_ofs = 0
chatroom_topic_ofs = 8
chatroom_users_ofs = 16
chatroom_size = 24

globals
{
	chatrooms	dq	0
}


; no arguments, called from sshtalk.asm to init our chatrooms global
falign
chatroom$init:
	prolog	chatroom$init
	xor	edi, edi
	call	stringmap$new
	mov	[chatrooms], rax
	epilog



; two arguments: rdi == optional name (null if not), rsi == optional topic (null if not)
; returns a new initialised chatroom object
falign
chatroom$new:
	prolog	chatroom$new
	push	rbx rdi rsi
	mov	edi, chatroom_size
	call	heap$alloc_clear
	mov	rbx, rax
	mov	edi, 1			; we want the chatroom_users_ofs map to be in _insert order_ not sort order
	call	unsignedmap$new
	mov	[rbx+chatroom_users_ofs], rax
	pop	rdi
	test	rdi, rdi
	jz	.notopic
	call	string$copy
	mov	[rbx+chatroom_topic_ofs], rax
calign
.notopic:
	pop	rdi
	test	rdi, rdi
	jz	.noname
	call	string$copy
	mov	[rbx+chatroom_name_ofs], rax
	mov	rdi, [chatrooms]
	mov	rsi, rax
	mov	rdx, rbx
	call	stringmap$insert_unique
calign
.noname:
	mov	rax, rbx
	pop	rbx
	epilog



; single argument in rdi: a chatroom object to destroy
falign
chatroom$destroy:
	prolog	chatroom$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+chatroom_name_ofs]
	test	rdi, rdi
	jz	.noname
	; we have to remove us from the chatrooms global
	mov	rsi, rdi
	mov	rdi, [chatrooms]
	call	stringmap$erase
	mov	rdi, [rbx+chatroom_name_ofs]
	call	heap$free
calign
.noname:
	mov	rdi, [rbx+chatroom_topic_ofs]
	test	rdi, rdi
	jz	.notopic
	call	heap$free
	mov	rdi, rbx
calign
.notopic:
	mov	rdi, [rbx+chatroom_users_ofs]
	xor	esi, esi
	call	unsignedmap$clear
	mov	rdi, [rbx+chatroom_users_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog


; three arguments: rdi == chatroom object, rsi == user object to add, rdx == tui object
falign
chatroom$join:
	prolog	chatroom$join
	; all we do is insert it
	mov	rdi, [rdi+chatroom_users_ofs]
	call	unsignedmap$insert_unique
	epilog




; three arguments: rdi == chatroom object, rsi == user object that joined
; NOTE: because of they way I did chatpanel construction/joining, this is intentionally separate
; from chatroom$join (and is done last)
falign
chatroom$join_notify:
	prolog	chatroom$join_notify
	; if we are a 1:1 chat, we don't do anything
	; if we are a room, we deal with notification messages as well
	cmp	qword [rdi+chatroom_name_ofs], 0
	je	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	; to our joining user, we send the list of everyone that is in here
	; to everyone else, we send username has arrived

	; if our user is here all by their lonesome, let them know and be done
	mov	rdi, [rbx+chatroom_users_ofs]

	; maps keep their count in _avlofs_right
	cmp	qword [rdi+_avlofs_right], 1
	je	.lonelyrider

	; so, first up, compile a list of everyone _except_ our joining user
	mov	rdi, .present
	call	string$copy
	mov	r13, rax
	mov	r14, [rbx+chatroom_users_ofs]
	mov	r14, [r14+_avlofs_next]		; first node
calign
.userlist:
	cmp	r12, [r14+_avlofs_key]
	je	.userlist_skip
	; otherwise, this user is not us, so add their name
	mov	rax, qword [.present]		; its length in characters
	cmp	rax, [r13]			; the current length of our string
	je	.userlist_nocomma
	mov	rdi, r13
	mov	rsi, .commastr
	call	string$concat
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
calign
.userlist_nocomma:
	mov	rdi, [r14+_avlofs_key]		; the user object
	mov	rsi, [rdi+user_username_ofs]
	mov	rdi, r13
	call	string$concat
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
calign
.userlist_skip:
	mov	r14, [r14+_avlofs_next]
	test	r14, r14
	jnz	.userlist
	; add a final period
	mov	rdi, r13
	mov	rsi, .periodstr
	call	string$concat
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	; so now, iterate through our user object's tui list and send r13 to them
	; since unsignedmap$foreach_arg will only pass one argument, use the stack to pass two:
	mov	rax, [rbx+chatroom_name_ofs]
	sub	rsp, 16
	mov	[rsp], r13
	mov	[rsp+8], rax
	mov	rdi, [r12+user_tuilist_ofs]
	mov	rsi, .msgnotify
	mov	rdx, rsp
	call	unsignedmap$foreach_arg
	; so now, let everyone else know we arrived
	mov	rdi, r13
	call	heap$free
	mov	rdi, [r12+user_username_ofs]
	mov	rsi, .arrivedstr
	call	string$concat
	mov	r13, rax
	mov	[rsp], rax
	; walk back through our chatroom users list
	mov	r14, [rbx+chatroom_users_ofs]
	mov	r14, [r14+_avlofs_next]		; first node
calign
.notifylist:
	cmp	r12, [r14+_avlofs_key]
	je	.notifylist_skip
	; otherwise, we need to iterate this user's tuilist, and send our notification
	mov	r15, [r14+_avlofs_key]		; the user object itself
	mov	rdi, [r15+user_tuilist_ofs]
	mov	rsi, .msgnotify
	mov	rdx, rsp
	call	unsignedmap$foreach_arg
calign
.notifylist_skip:
	mov	r14, [r14+_avlofs_next]
	test	r14, r14
	jnz	.notifylist
	; otherwise, we are good to go, free our string, restore our stack
	add	rsp, 16
	mov	rdi, r13
	call	heap$free

	pop	r15 r14 r13 r12 rbx
	epilog

cleartext .commastr, ', '
cleartext .periodstr, '.'
cleartext .present, 'Present: '
cleartext .arrivedstr, ' has arrived.'
calign
.lonelyrider:
	; iterate the tuilist of our user object in r12
	mov	rdi, [r12+user_tuilist_ofs]
	mov	rsi, .lonelyrider_notify
	mov	rdx, [rbx+chatroom_name_ofs]
	call	unsignedmap$foreach_arg
	
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.lonelyrider_notify:
	; called with: rdi == screen object, rsi == tuilist value, rdx == chatroom name string
	mov	rsi, rdx
	mov	edx, 1
	mov	ecx, 1
	call	screen$chatpanel_byname
	; that _will_ return us the goods
	mov	rdi, rax
	mov	rsi, .allalone
	call	chatpanel$notify
	ret
falign
.msgnotify:
	; called with rdi == screen object, rsi == unused, rdx == pointer to stack with [rsi] == msg, [rsi+8] == chatroom name
	mov	rsi, rdx
	push	rdx
	mov	rsi, [rsi+8]
	mov	edx, 1
	mov	ecx, 1
	call	screen$chatpanel_byname
	; that _will_ return us the goods
	pop	rsi
	mov	rdi, rax
	mov	rsi, [rsi]
	call	chatpanel$notify
	ret
cleartext .allalone, 'You are all alone.'
calign
.nothingtodo:
	epilog



; three arguments: rdi == chatroom object, rsi == user object to remove, rdx == tui object
; NOTE: we will automatically destroy the chatroom object if rdx is the last tui object attached
falign
chatroom$leave:
	prolog	chatroom$leave
	; the easiest way to determine whether we are the last one
	; is to literally count the # of tui objects that are in our room
	; and if that count is 1, teardown
	push	rbx r12 r13 r14
	xor	ecx, ecx
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	push	rcx
	mov	rdi, [rdi+chatroom_users_ofs]
	mov	rsi, .outercount
	mov	rdx, rsp
	call	unsignedmap$foreach_arg
	pop	rcx
	cmp	ecx, 1
	je	.teardown
	; if this user object has more than one tui object, do nothing
	mov	rdi, [r12+user_tuilist_ofs]
	; our avl trees store their node count in the _avlofs_right position:
	cmp	qword [rdi+_avlofs_right], 1
	ja	.donothing
	; otherwise go ahead and remove this user from our chatroom list
	; if we are a onetoone, jsut remove, else notify, then remove
	cmp	qword [rbx+chatroom_name_ofs], 0
	je	.oneonone
	; remove our user first
	mov	rdi, [rbx+chatroom_users_ofs]
	mov	rsi, r12
	call	unsignedmap$erase
	; now, if there is only one user left, tell them they are all by their lonesome
	mov	rdi, [rbx+chatroom_users_ofs]
	cmp	qword [rdi+_avlofs_right], 1
	je	.lonelyrider
	mov	rdi, [r12+user_username_ofs]
	mov	rsi, .leftstr
	call	string$concat
	mov	rcx, [rbx+chatroom_name_ofs]
	mov	r13, rax
	sub	rsp, 16
	mov	[rsp], rax
	mov	[rsp+8], rcx
	mov	r14, [rbx+chatroom_users_ofs]
	mov	r14, [r14+_avlofs_next]		; first node
calign
.notifylist:
	mov	rdi, [r14+_avlofs_key]
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, .msgnotify
	mov	rdx, rsp
	call	unsignedmap$foreach_arg
	mov	r14, [r14+_avlofs_next]
	test	r14, r14
	jnz	.notifylist
	add	rsp, 16
	mov	rdi, r13
	call	heap$free
	pop	r14 r13 r12 rbx
	epilog
cleartext .leftstr, ' has departed.'
calign
.lonelyrider:
	mov	rdi, [rdi+_avlofs_next]	; the first node
	mov	rdi, [rdi+_avlofs_key]	; the user object
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, .lonelyrider_notify
	mov	rdx, [rbx+chatroom_name_ofs]
	call	unsignedmap$foreach_arg
	pop	r14 r13 r12 rbx
	epilog
falign
.lonelyrider_notify:
	; called with: rdi == screen object, rsi == tuilist value, rdx == chatroom name string
	mov	rsi, rdx
	mov	edx, 1
	mov	ecx, 1
	call	screen$chatpanel_byname
	; that _will_ return us the goods
	mov	rdi, rax
	mov	rsi, .allalone
	call	chatpanel$notify
	ret
cleartext .allalone, 'You are now by yourself.'
falign
.msgnotify:
	; called with rdi == screen object, rsi == unused, rdx == pointer to stack with [rsi] == msg, [rsi+8] == chatroom name
	mov	rsi, rdx
	push	rdx
	mov	rsi, [rsi+8]
	mov	edx, 1
	mov	ecx, 1
	call	screen$chatpanel_byname
	; that _will_ return us the goods
	pop	rsi
	mov	rdi, rax
	mov	rsi, [rsi]
	call	chatpanel$notify
	ret

calign
.oneonone:
	mov	rdi, [rbx+chatroom_users_ofs]
	mov	rsi, r12
	call	unsignedmap$erase
	pop	r14 r13 r12 rbx
	epilog
calign
.donothing:
	pop	r14 r13 r12 rbx
	epilog
calign
.teardown:
	mov	rdi, rbx
	call	chatroom$destroy
	pop	r14 r13 r12 rbx
	epilog
falign
.outercount:
	; rdi == user object, rsi unimportant, rdx == address of counter var
	mov	rdi, [rdi+user_tuilist_ofs]
	mov	rsi, .innercount
	call	unsignedmap$foreach_arg
	ret
falign
.innercount:
	add	dword [rdx], 1
	ret
