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
	; statusbar.inc: the normal tui_statusbar doesn't do any special updating labels, so we
	; override the timer here to include C: #connected, U: #usersconnected/#totalusers as a label
	;

dalign
statusbar$vtable:
	dq      tui_statusbar$cleanup, tui_statusbar$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      statusbar$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

globals
{
	statusbar_fmt	dq	0
}

; no arguments, called once at startup
falign
statusbar$init:
	prolog	statusbar$init
	xor	edi, edi
	call	formatter$new
	mov	[statusbar_fmt], rax
	mov	rdi, rax
	mov	rsi, .s1
	call	formatter$add_static
	mov	rdi, [statusbar_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [statusbar_fmt]
	mov	rsi, .s2
	call	formatter$add_static
	mov	rdi, [statusbar_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [statusbar_fmt]
	mov	rsi, .s3
	call	formatter$add_static
	mov	rdi, [statusbar_fmt]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	epilog
cleartext .s1, 'C: '
cleartext .s2, ' U: '
cleartext .s3, '/'


; no arguments, returns # of users connected
falign
statusbar$usersonline:
	prolog	statusbar$usersonline
	xor	ecx, ecx
	mov	rdi, [users]
	mov	rsi, .usercount
	push	rcx
	mov	rdx, rsp
	call	unsignedmap$foreach_arg
	pop	rax
	epilog
falign
.usercount:
	; three arguments, rdi == username string, rsi == user object, rdx == our increment spot
	mov	rcx, [rsi+user_tuilist_ofs]
	xor	r8d, r8d
	mov	r9d, 1
	cmp	qword [rcx+_avlofs_right], 0
	cmovne	r8d, r9d
	add	[rdx], r8d
	ret


; no arguments, called when screen is created
falign
statusbar$new:
	prolog	statusbar$new
	movq	xmm0, [_math_onehundred]
	ansi_colors edi, 'black', 'gray'
	mov	esi, 1
	call	tui_statusbar$new_d
	; make sure we use our custom vtable for it:
	push	rbx
	mov	rbx, rax
	mov	qword [rax], statusbar$vtable
	call	statusbar$usersonline
	mov	rcx, [users]
	mov	rdi, [statusbar_fmt]
	mov	esi, [ssh_session_count]
	mov	edx, eax
	mov	ecx, [rcx+_avlofs_right]
	call	formatter$doit
	push	rax
	mov	rdi, rbx
	mov	rsi, rax
	call	tui_statusbar$nvaddlabel
	pop	rdi
	call	heap$free
	mov	rax, rbx
	pop	rbx
	epilog




falign
statusbar$timer:
	prolog	statusbar$timer
	push	rbx r12
	; our second-to-last child is the one we want
	mov	rbx, rdi
	call	statusbar$usersonline
	mov	rcx, [users]
	mov	rdi, [statusbar_fmt]
	mov	esi, [ssh_session_count]
	mov	edx, eax
	mov	ecx, [rcx+_avlofs_right]
	call	formatter$doit
	mov	rdi, .s1
	mov	rsi, rax
	mov	r12, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, [rbx+tui_children_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rsi, [rsi+_list_prevofs]
	; [rsi] == a tui_label object
	mov	rdi, [rsi]
	mov	rsi, r12
	mov	edx, [rdi+tui_width_ofs]
	mov	ecx, [r12]
	cmp	ecx, edx
	jne	.sizechanged
	call	tui_label$nvsettext
	mov	rdi, r12
	call	heap$free

	mov	rdi, rbx
	call	tui_statusbar$timer

	pop	r12 rbx
	epilog
dalign
.s1:
        dq      3
if string_bits = 32
        dd      ' ', 0x2502, ' '
else
        dw      ' ', 0x2502, ' '
end if
calign
.sizechanged:
	push	rdi
	mov	[rdi+tui_width_ofs], ecx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsizechanged]
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vlayoutchanged]
	pop	rdi
	mov	rsi, r12
	call	tui_label$nvsettext
	mov	rdi, r12
	call	heap$free

	mov	rdi, rbx
	call	tui_statusbar$timer
	
	pop	r12 rbx
	epilog
