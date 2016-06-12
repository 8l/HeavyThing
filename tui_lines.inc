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
	; tui_lines.inc: simple wrappers over the top of tui_background
	; to do horizontal/vertical lines
	;

if used tui_vline$new_i | defined include_everything
	; two arguments: edi == height, esi == colors
falign
tui_vline$new_i:
	prolog	tui_vline$new_i
	push	rdi rsi
	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	pop	r8		; colors
	mov	edx, [rsp]
	mov	[rsp], rax
	mov	rdi, rax
	mov	esi, 1
	mov	ecx, 0x2502	; VLINE
	call	tui_background$init_ii
	pop	rax
	epilog

end if

if used tui_vline$new_d | defined include_everything
	; two arguments: xmm0 == heightperc, edi == colors
falign
tui_vline$new_d:
	prolog	tui_vline$new_d
	movq	rax, xmm0
	push	rax rdi
	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	pop	rcx		; colors
	mov	rdi, [rsp]
	mov	[rsp], rax
	movq	xmm0, rdi
	mov	rdi, rax
	mov	esi, 1
	mov	edx, 0x2502	; VLINE
	call	tui_background$init_id
	pop	rax
	epilog

end if

if used tui_hline$new_i | defined include_everything
	; two arguments: edi == width, esi == colors
falign
tui_hline$new_i:
	prolog	tui_hline$new_i
	push	rdi rsi
	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	pop	r8		; colors
	mov	esi, [rsp]
	mov	[rsp], rax
	mov	rdi, rax
	mov	edx, 1
	mov	ecx, 0x2500	; HLINE
	call	tui_background$init_ii
	pop	rax
	epilog

end if

if used tui_hline$new_d | defined include_everything
	; two arguments: xmm0 == widthperc, edi == colors
falign
tui_hline$new_d:
	prolog	tui_hline$new_d
	movq	rax, xmm0
	push	rax rdi
	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	pop	rcx		; colors
	mov	rdi, [rsp]
	mov	[rsp], rax
	movq	xmm0, rdi
	mov	rdi, rax
	mov	esi, 1
	mov	edx, 0x2500	; HLINE
	call	tui_background$init_di
	pop	rax
	epilog

end if
