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
	; tui_bell.inc: a 1x1 tui component that will send via timer the 0x7 bell
	; but otherwise is a space (and thus must occupy a 1x1 spot on the render area)
	;
	; default action is a space of course (as it must be so that the renderer will
	; send the difference when we decide to write a bell)
	;

if used tui_bell$vtable | defined include_everything

tui_bell$vtable:
	dq      tui_bell$cleanup, tui_bell$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_bell$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

tui_bell_timerptr_ofs = tui_background_size
tui_bell_counter_ofs = tui_background_size + 8

tui_bell_size = tui_background_size + 16

end if

if used tui_bell$new | defined include_everything
	; three arguments: edi == width, esi == height, edx == colors
falign
tui_bell$new:
	prolog	tui_bell$new
	push	rdi rsi rdx
	mov	edi, tui_bell_size
	call	heap$alloc_clear
	pop	r8 rdx rsi
	mov	qword [rax], tui_bell$vtable
	mov	rdi, rax
	mov	ecx, ' '
	push	rax
	call	tui_background$init_ii
	pop	rax
	epilog

end if



if used tui_bell$clone | defined include_everything
	; single argument in rdi: our tui_bell to clone
falign
tui_bell$clone:
	prolog	tui_bell$clone
	push	rdi
	mov	edi, tui_bell_size
	call	heap$alloc_clear
	mov	qword [rax], tui_bell$vtable
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	[rsp], rax
	call	tui_background$init_copy
	pop	rax
	epilog

end if


if used tui_bell$cleanup | defined include_everything
	; single argument in rdi: our tui_bell object
falign
tui_bell$cleanup:
	prolog	tui_bell$cleanup
	cmp	qword [rdi+tui_bell_timerptr_ofs], 0
	je	.notimer
	push	rdi
	mov	rdi, [rdi+tui_bell_timerptr_ofs]
	call	epoll$timer_clear
	pop	rdi
	call	tui_object$cleanup
	epilog
calign
.notimer:
	call	tui_object$cleanup
	epilog

end if



if used tui_bell$timer | defined include_everything
	; single argument in rdi: our tui_bell object
falign
tui_bell$timer:
	prolog	tui_bell$timer
	cmp	dword [rdi+tui_bell_counter_ofs], 0
	je	.alldone
	mov	rsi, [rdi+tui_text_ofs]
	mov	edx, ' '
	mov	ecx, 0x7
	test	dword [rdi+tui_bell_counter_ofs], 1
	cmovz	edx, ecx
	mov	[rsi], edx
	sub	dword [rdi+tui_bell_counter_ofs], 1
	mov	rcx, [rdi]
	call	qword [rcx+tui_vupdatedisplaylist]
	xor	eax, eax	; don't kill our timer
	epilog
calign
.alldone:
	mov	qword [rdi+tui_bell_timerptr_ofs], 0
	mov	eax, 1		; stop our timer
	epilog

end if

if used tui_bell$nvdoit | defined include_everything
	; two arguments: rdi == our tui_bell object, esi == bellcount
falign
tui_bell$nvdoit:
	prolog	tui_bell$nvdoit
	test	esi, esi
	jz	.nothingtodo
	shl	esi, 1
	cmp	qword [rdi+tui_bell_timerptr_ofs], 0
	jne	.alreadygoing
	; otherwise, create a new timer
	mov	[rdi+tui_bell_counter_ofs], esi
	push	rdi
	mov	rsi, rdi
	mov	edi, 120
	call	epoll$timer_new
	pop	rdi
	mov	[rdi+tui_bell_timerptr_ofs], rax
	; specify that when the timer is complete, we don't want to be
	; destroyed, and instead, only want the timer to end
	mov	dword [rax+24], 2
	epilog
calign
.alreadygoing:
	add	dword [rdi+tui_bell_counter_ofs], esi
	epilog
calign
.nothingtodo:
	epilog

end if
