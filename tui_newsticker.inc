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
	; tui_newsticker.inc: a "ticker tape" style component, nothing terribly fancy
	;

if used tui_newsticker$vtable | defined include_everything

dalign
tui_newsticker$vtable:
	dq      tui_newsticker$cleanup, tui_newsticker$clone, tui_newsticker$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_newsticker$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

tui_newsticker_filltext_ofs = tui_background_size
tui_newsticker_textpos_ofs = tui_background_size + 8
tui_newsticker_scrollpos_ofs = tui_background_size + 12
tui_newsticker_timerptr_ofs = tui_background_size + 16

tui_newsticker_size = tui_background_size + 24


; a define for the ms delay between updates
tui_newsticker_speed = 200

end if

if used tui_newsticker$new_i | defined include_everything
	; three arguments: edi == width, rsi == filltext string, edx == colors
falign
tui_newsticker$new_i:
	prolog	tui_newsticker$new_i
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+8], rax
	mov	edi, tui_newsticker_size
	call	heap$alloc_clear
	mov	rcx, [rsp+8]
	mov	qword [rax], tui_newsticker$vtable
	mov	[rax+tui_newsticker_filltext_ofs], rcx
	mov	rdi, rax
	mov	esi, [rsp]
	mov	edx, 1
	mov	ecx, ' '
	mov	r8d, [rsp+16]
	mov	[rsp], rdi
	call	tui_background$init_ii
	; fire up a timer
	mov	edi, tui_newsticker_speed
	mov	rsi, [rsp]
	call	epoll$timer_new
	mov	rcx, rax
	mov	rax, [rsp]
	mov	[rax+tui_newsticker_timerptr_ofs], rcx
	mov	dword [rax+tui_newsticker_scrollpos_ofs], -1
	add	rsp, 24
	epilog

end if

if used tui_newsticker$new_d | defined include_everything
	; three arguments: xmm0 == widthperc, rdi == filltext string, esi == colors
falign
tui_newsticker$new_d:
	prolog	tui_newsticker$new_d
	sub	rsp, 24
	movq	rax, xmm0
	mov	[rsp], rax
	mov	[rsp+8], rdi
	mov	[rsp+16], rsi
	call	string$copy
	mov	[rsp+8], rax
	mov	edi, tui_newsticker_size
	call	heap$alloc_clear
	mov	rdx, [rsp]
	mov	rcx, [rsp+8]
	mov	qword [rax], tui_newsticker$vtable
	mov	[rax+tui_newsticker_filltext_ofs], rcx
	mov	rdi, rax
	movq	xmm0, rdx
	mov	esi, 1
	mov	edx, ' '
	mov	ecx, [rsp+16]
	mov	[rsp], rdi
	call	tui_background$init_di
	; fire up a timer
	mov	edi, tui_newsticker_speed
	mov	rsi, [rsp]
	call	epoll$timer_new
	mov	rcx, rax
	mov	rax, [rsp]
	mov	[rax+tui_newsticker_timerptr_ofs], rcx
	mov	dword [rax+tui_newsticker_scrollpos_ofs], -1
	add	rsp, 24
	epilog

end if

if used tui_newsticker$clone | defined include_everything
	; single argument in rdi: our tui_newsticker object to clone
falign
tui_newsticker$clone:
	prolog	tui_newsticker$clone
	push	rdi
	mov	edi, tui_newsticker_size
	call	heap$alloc_clear
	mov	rdi, rax
	mov	rsi, [rsp]
	push	rax
	call	tui_background$init_copy
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+tui_newsticker_filltext_ofs]
	call	string$copy
	mov	rsi, [rsp]
	mov	[rsi+tui_newsticker_filltext_ofs], rax
	mov	edi, tui_newsticker_speed
	call	epoll$timer_new
	mov	rcx, rax
	pop	rax rdi
	mov	[rax+tui_newsticker_timerptr_ofs], rcx
	mov	dword [rax+tui_newsticker_scrollpos_ofs], -1
	epilog

end if

if used tui_newsticker$cleanup | defined include_everything
	; single argument in rdi: our tui_newsticker object
falign
tui_newsticker$cleanup:
	prolog	tui_newsticker$cleanup
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+tui_newsticker_filltext_ofs]
	call	heap$free
	mov	rdi, [rbx+tui_newsticker_timerptr_ofs]
	call	epoll$timer_clear
	mov	rdi, rbx
	call	tui_object$cleanup
	pop	rbx
	epilog

end if

if used tui_newsticker$draw | defined include_everything
	; single argument in rdi: our tui_newsticker object
falign
tui_newsticker$draw:
	prolog	tui_newsticker$draw
	cmp	dword [rdi+tui_width_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_height_ofs], 0
	je	.nothingtodo
	push	rbx
	mov	rbx, rdi
	call	tui_background$nvfill
	mov	rdi, [rbx+tui_newsticker_filltext_ofs]
	cmp	qword [rdi], 0
	je	.nofilltext
	mov	eax, [rbx+tui_newsticker_scrollpos_ofs]
	mov	ecx, [rbx+tui_width_ofs]
	sub	ecx, 1
	cmp	eax, -1
	cmove	eax, ecx
	mov	[rbx+tui_newsticker_scrollpos_ofs], eax
	add	ecx, 1
	mov	edx, [rbx+tui_newsticker_textpos_ofs]
	mov	rsi, [rbx+tui_text_ofs]
	mov	r8d, eax
	shl	r8d, 2
	add	rsi, r8
calign
.loop:
	cmp	eax, ecx
	jge	.loopdone
	cmp	edx, [rdi]
	jae	.loopnext_nocopy
if string_bits = 32
	mov	r8d, [rdi+rdx*4+8]
else
	movzx	r8d, word [rdi+rdx*2+8]
end if
	mov	[rsi], r8d
	add	eax, 1
	add	edx, 1
	add	rsi, 4
	jmp	.loop
calign
.loopnext_nocopy:
	add	eax, 1
	add	edx, 1
	add	rsi, 4
	jmp	.loop
calign
.loopdone:
	mov	edx, [rbx+tui_newsticker_textpos_ofs]
	cmp	edx, [rdi]
	jb	.nofilltext
	; reset it for next time around
	mov	dword [rbx+tui_newsticker_scrollpos_ofs], -1
	mov	dword [rbx+tui_newsticker_textpos_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rbx
	epilog
calign
.nofilltext:
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rbx
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_newsticker$timer | defined include_everything
	; single argument in rdi: our tui_newsticker object
falign
tui_newsticker$timer:
	prolog	tui_newsticker$timer
	cmp	dword [rdi+tui_newsticker_scrollpos_ofs], 0
	jg	.decscrollpos
	je	.inctextpos
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	xor	eax, eax		; keep going indefinitely
	epilog
calign
.decscrollpos:
	sub	dword [rdi+tui_newsticker_scrollpos_ofs], 1
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	xor	eax, eax		; keep going indefinitely
	epilog
calign
.inctextpos:
	add	dword [rdi+tui_newsticker_textpos_ofs], 1
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	xor	eax, eax		; keep going indefinitely
	epilog

end if

if used tui_newsticker$nvsettext | defined include_everything
	; two arguments: rdi == our tui_newsticker object, rsi == new string for filltext
falign
tui_newsticker$nvsettext:
	prolog	tui_newsticker$nvsettext
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+tui_newsticker_filltext_ofs]
	mov	[rbx+tui_newsticker_filltext_ofs], rsi
	call	heap$free
	mov	rdi, [rbx+tui_newsticker_filltext_ofs]
	call	string$copy
	mov	[rbx+tui_newsticker_filltext_ofs], rax
	mov	dword [rbx+tui_newsticker_scrollpos_ofs], -1
	mov	dword [rbx+tui_newsticker_textpos_ofs], 0
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	pop	rbx
	epilog

end if

if used tui_newsticker$nvappendtext | defined include_everything
	; two arguments: rdi == our tui_newsticker object, rsi == text to add to filltext
falign
tui_newsticker$nvappendtext:
	prolog	tui_newsticker$nvappendtext
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+tui_newsticker_filltext_ofs]
	call	string$concat
	mov	rdi, [rbx+tui_newsticker_filltext_ofs]
	mov	[rbx+tui_newsticker_filltext_ofs], rax
	call	heap$free
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vdraw]
	pop	rbx
	epilog

end if
