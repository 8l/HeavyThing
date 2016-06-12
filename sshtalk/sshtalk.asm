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
include '../ht_defaults.inc'
include '../ht.inc'


;
; Burning Purpose:
; A nice showcase piece that makes use of lots of various bits of my library.
; I always used to like the talkd "feature" of being able to watch the other
; party type (mainly so I could give whomever I was chatting to a bad time
; about how crap they were at it).
; Taking from that, we provide a more, hmm, visually appealing slant to that
; theme.
;
; See https://2ton.com.au/sshtalk for the full commentary.
;

include 'userdb.inc'
include 'chatroom.inc'
include 'chatpanel.inc'
include 'screen.inc'
include 'statusbar.inc'


public _start
falign
_start:
	call	ht$init

	; load up/initialise our userdb:
	call	userdb$init

	; initialise our chatrooms
	call	chatroom$init

	; initialise our connect/disconnect syslog formatters
	call	screen$init_formatters

	; initialize our statusbar formatter:
	call	statusbar$init

	; our initial tui child for the ssh server needs to be setup like:
	; splash -> simpleauth -> sshtalk screen

	; create a base sshtalk screen
	call	screen$new

	; create our simpleauth next
	mov	edi, tui_simpleauth_newuser
	mov	rsi, rax
	call	tui_simpleauth$new
	; so that we can override our newuser/auth methods:
	mov	qword [rax], userdb$vtable
	; add our sshtalk text to the simpleauth
	mov	rbx, rax
	; its first child is the top "third" of the goods:
	mov	rdi, [rax+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	r12, [rsi]
	; its last child is the bottom "third" of the goods:
	mov	rsi, [rdi+_list_last_ofs]
	mov	r13, [rsi]
	; because we have to support ridiculously small terminal sizes (read: 80x25)
	; we can't really add too much text here, and if the terminal size is bigger
	; make sure our objects are centered in the space that remains
	mov	dword [r12+tui_horizalign_ofs], tui_align_center
	; add a vspacer for our variable height atop
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; our text is next
	movq	xmm0, [_math_onehundred]	; width percent
	mov	edi, 1				; height
	mov	rsi, .s1			; string
	ansi_colors edx, 'yellow', 'black'	; color
	mov	ecx, tui_textalign_center	; alignment
	call	tui_label$new_di
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; next one:
	mov	rdi, r12
	mov	rsi, .s2
	call	.addlabel
	
	; add a 1 high vspacer again
	mov	edi, 1
	call	tui_vspacer$new_i
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; the rest of our headers
	mov	rdi, r12
	mov	rsi, .s3
	call	.addlabel
	mov	rdi, r12
	mov	rsi, .s4
	call	.addlabel
	mov	rdi, r12
	mov	rsi, .s5
	call	.addlabel
	mov	rdi, r12
	mov	rsi, .s6
	call	.addlabel
	
	; add another spacer so that our text gets centered vertically
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; now do the setup for our lower third
	mov	edi, tui_object_size
	call	heap$alloc
	mov	r12, rax
	mov	rdi, rax
	mov	qword [rax], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	mov	rdi, r13
	mov	rsi, r12
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; in the event we have >25 rows, we want our text vertically centered in
	; the space below
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	
	mov	rdi, r12
	mov	rsi, .s7
	call	.addlabel
	; add a 1 high vspacer again
	mov	edi, 1
	call	tui_vspacer$new_i
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rdi, r12
	mov	rsi, .s8
	call	.addlabel
	mov	rdi, r12
	mov	rsi, .s9
	call	.addlabel

	; add a 1 high vspacer again
	mov	edi, 1
	call	tui_vspacer$new_i
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; now, if we are running on the 2ton.com.au machine, or my local dev machine
	; spit out 2ton-specific labels for the next two
	mov	rdi, [uname$nodename]
	mov	rsi, .hostname_slave
	call	string$starts_with
	push	rax
	mov	rdi, [uname$nodename]
	mov	rsi, .hostname_cdev
	call	string$equals
	pop	rcx
	or	eax, ecx

	mov	rdi, r12
	mov	rsi, .s10
	mov	rdx, .s10_2ton
	test	eax, eax
	cmovnz	rsi, rdx
	push	rax
	call	.addlabel
	pop	rax
	mov	rdi, r12
	mov	rsi, .s11_2ton
	test	eax, eax
	jz	.not_2ton_local
	call	.addlabel
calign
.not_2ton_local:
	; add our dynamic spacer to the end
	movq	xmm0, [_math_onehundred]
	call	tui_vspacer$new_d
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	
	; last but not least, add our news ticker to the bottom
	movq	xmm0, [_math_onehundred]
	mov	rdi, .tickertext
	ansi_colors esi, 'lightgray', 'black'
	call	tui_newsticker$new_d
	mov	rdi, r13
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; and our splash
	mov	rdi, rbx
	call	tui_splash$new

	; create a new tui_ssh object with that as its only child:
	mov	rdi, rax
	call	tui_ssh$new
	; hangon to that so we can link it with the ssh server object:
	mov	rbx, rax

	; create a new ssh server
	xor	edi, edi			; use /etc/ssh by default
	call	ssh$new_server
	test	rax, rax
	jz	.hostkeyerror
	; hangon to that so we can link it in the iochain
	mov	r12, rax

	; ssh is an epoll io chain, so link tui_ssh (also one) with the ssh layer
	mov	[rbx+io_child_ofs], rax		; app layer child = ssh layer
	mov	[rax+io_parent_ofs], rbx	; ssh layer parent = app layer

	; because our ssh chained epoll object doesn't do anything other than feed
	; its own iochain, we can use the default epoll$vtable:
	mov	rdi, epoll$default_vtable
	xor	esi, esi
	call	epoll$new
	; link that with our ssh server object
	mov	[r12+io_child_ofs], rax		; ssh layer child == epoll layer
	mov	[rax+io_parent_ofs], r12	; epoll layer parent == ssh layer

	; setup our tcp goods
	sub	rsp, sockaddr_in_size
	mov	rdi, rsp
	mov	esi, 4001
	call	inaddr_any
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, rbx			; top of the io chain is fine, epoll walks it
	call	epoll$inbound

if profiling
	call	tui_profiler$new
	mov	rdi, rax
	call	tui_terminal$new
end if

	; call epoll$run, noting that it doesn't return:
	call	epoll$run

	; not reached:
	mov	eax, syscall_exit
	xor	edi, edi
	syscall
calign
.hostkeyerror:
	mov	rdi, .errorstring
	call	string$to_stderrln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
falign
.addlabel:
	; object to add must be in rdi, string in rsi
	push	rdi
	movq	xmm0, [_math_onehundred]	; width percent
	mov	edi, 1				; height
	ansi_colors edx, 'lightgray', 'black'	; color
	mov	ecx, tui_textalign_center	; alignment
	call	tui_label$new_di
	pop	rdi
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	ret

cleartext .s1, 'sshtalk v1.16 ',0xa9,' 2015, 2016 2 Ton Digital'
cleartext .s2, 'proudly made in Cooroy, Australia'
cleartext .s3, 'A showcase piece for the HeavyThing library'
cleartext .s4, '100% wire-level secure ssh talk facility'
cleartext .s5, '100% handcrafted in x86_64 assembler'
cleartext .s6, 'Zero external dependencies'
cleartext .s7, 'Info/Source: https://2ton.com.au/sshtalk'
cleartext .s8, 'Connection: 4096 bit diffie-hellman-group-exchange-sha256,'
cleartext .s9, 'ssh-rsa,aes256-cbc,hmac-sha2-256,zlib[@openssh.com]'
cleartext .s10, 'Author: Jeff Marrison, jeff@2ton.com.au'
cleartext .s10_2ton, 'Author: Jeff Marrison, jeff@2ton.com.au, and via this sshtalk: @Sysop'
cleartext .s11_2ton, 'Online 6a-8a Mon-Fri AEST, may or may not respond, don',0x27,'t take it personally :)'
cleartext .hostname_slave, 'slave.'
cleartext .hostname_cdev, 'cdev'
cleartext .tickertext, 'Best viewed with a 6 pack of beer, ha! ... size: 135x35 min, Mac OS X: iTerm2 or Terminal.app, Winblows: SecureCRT (ANSI colors enabled, rows/cols adjust, lucida console), Linux: all linux terms seem happy...'
cleartext .errorstring, '/etc/ssh host keys and/or contents error.'

include '../ht_data.inc'
