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
	; master_ui.inc: webslap user interface goods
	;
	; Aside from my "signature" splash, all we do is provide the exact same
	; information that the text-only version does, but in realtime, and we
	; allow for test reruns, with auto-switching between result screens for
	; completed runs.
	;

globals
{
master_ui_text	dq	0
master_ui_timer	dq	0
master_ui_timerobj	dq	0
}

falign
master_ui:
	prolog	master_ui
	push	rbx r12 r13

	mov	edi, tui_object_size
	call	heap$alloc
	mov	rbx, rax
	mov	rdi, rax
	mov	qword [rax], tui_object$simple_vtable
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd

	; its default layout is vertical, so add to that our huge label
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	rdi, .waitstring
	ansi_colors esi, 'lightgray', 'black'
	mov	edx, tui_textalign_left
	call	tui_label$new_dd
	mov	rdi, rbx
	mov	[master_ui_text], rax
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; and our simple statusbar down the bottom
	movq	xmm0, [_math_onehundred]
	ansi_colors edi, 'black', 'gray'
	mov	esi, 1
	call	tui_statusbar$new_d

	push	rax
	mov	rdi, rax
	mov	rsi, .statustext
	call	tui_statusbar$nvsettext
	mov	rdi, [rsp]
	mov	rsi, .ctrlctext
	call	tui_statusbar$nvaddlabel
	pop	rsi
	mov	rdi, rbx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; and our splash -> that
	mov	rdi, rbx
	call	tui_splash$new
	mov	rbx, rax
	mov	qword [rax+tui_splash_donecb_ofs], master_ui_start

	mov	rdi, rbx
	call	tui_terminal$new

	call	io$new
	mov	[master_ui_timerobj], rax
	mov	qword [rax], master_ui_timer$vtable
	mov	edi, 100
	mov	rsi, rax
	call	epoll$timer_new
	mov	[master_ui_timer], rax

	pop	r13 r12 rbx

	epilog
cleartext .statustext, 'webslap v1.16 ',0xa9, ' 2015, 2016 2 Ton Digital'
cleartext .ctrlctext, 'C-c - Exit'
cleartext .waitstring, 'Waiting for results...'

dalign
master_ui_timer$vtable:
	dq	io$destroy, io$clone, io$connected, io$send, io$receive, io$error, master_ui_timer$update


falign
master_ui_start:
	prolog	master_ui_start
        call    timestamp
        movq    [begin], xmm0
        call    epoll$timestamp
        mov     [begin_msecs], rax
	mov     rdi, [workers]
	mov     rsi, .starting_gun
	call    list$foreach
	epilog
falign
.starting_gun:
	mov     ecx, 'DOIT'
	mov     edx, 8
	mov     rax, [rdi]
	push    rcx
	mov     rsi, rsp
	call    qword [rax+io_vsend]
	add     rsp, 8
	ret

falign
master_ui_complete:
	prolog	master_ui_complete
	cmp	qword [master_ui_timer], 0
	je	.nodeal
	mov	rdi, [master_ui_timer]
	mov	qword [master_ui_timer], 0
	call	epoll$timer_clear
	mov	rdi, [master_ui_timerobj]
	call	io$destroy

	mov	rdi, [master_ui_text]
	ansi_colors esi, 'lightgray', 'blue'
	mov	[rdi+tui_bgcolors_ofs], esi
	mov	edi, 1
	call	build_text
	mov	rdi, [master_ui_text]
	push	rax
	mov	rsi, rax
	call	tui_label$nvsettext
	pop	rdi
	call	heap$free
	epilog
calign
.nodeal:
	epilog

falign
master_ui_timer$update:
	prolog	master_ui_timer$update
	cmp	qword [completed], 0
	je	.waiting
	xor	edi, edi
	call	build_json
	xor	edi, edi
	call	build_text
	push	rax
	mov	rdi, [master_ui_text]
	mov	rsi, rax
	call	tui_label$nvsettext
	pop	rdi
	call	heap$free
	xor	eax, eax
	epilog
calign
.waiting:
	xor	eax, eax
	epilog

