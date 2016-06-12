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
	; tui_spacers.inc: horizontal and vertical spacer objects
	; these are used to create dynamic layouts... they don't draw anything
	;
	; tui_hspacer and tui_vspacer contained herein
	;


	; to destroy, call its tui_vcleanup method then heap$free it
	; though that being said, removeAllChildren if it is added to a normal
	; object will clean itself up nicely anyway


if used tui_vspacer$new_i | defined include_everything
	; single argument in edi: height
	; returns a new vertical spacer in rax
falign
tui_vspacer$new_i:
	prolog	tui_vspacer$new_i
	push	rdi
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	esi, 1			; 1 character wide
	mov	rdx, [rsp]		; get back our height
	mov	[rsp], rax		; save our return
	call	tui_object$init_ii
	pop	rax
	epilog
end if

if used tui_hspacer$new_i | defined include_everything
	; single argument in edi: width
	; returns a new horizontal spacer in rax
falign
tui_hspacer$new_i:
	prolog	tui_hspacer$new_i
	push	rdi
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	rsi, [rsp]		; get back our width
	mov	edx, 1			; 1 character high
	mov	[rsp], rax		; save our return
	call	tui_object$init_ii
	pop	rax
	epilog
end if

if used tui_vspacer$new_d | defined include_everything
	; single argument in xmm0: height percentage (0..100)
	; returns a new vertical spacer in rax
falign
tui_vspacer$new_d:
	prolog	tui_vspacer$new_d
	mov	edi, tui_object_size
	sub	rsp, 8
	movq	[rsp], xmm0
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	esi, 1			; 1 character wide
	movq	xmm0, [rsp]		; get our percent back
	mov	[rsp], rax		; save our return
	call	tui_object$init_id
	pop	rax
	epilog
end if

if used tui_hspacer$new_d | defined include_everything
	; single argument in xmm0: width percentage (0..100)
	; returns a new horizontal spacer in rax
falign
tui_hspacer$new_d:
	prolog	tui_hspacer$new_d
	mov	edi, tui_object_size
	sub	rsp, 8
	movq	[rsp], xmm0
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	rdi, rax
	mov	esi, 1			; 1 character high
	movq	xmm0, [rsp]		; get our percent back
	mov	[rsp], rax		; save our return
	call	tui_object$init_di
	pop	rax
	epilog
end if
