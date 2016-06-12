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
	; tui_lock.inc: epoll "locking" to prevent cascading calls to nvrender for any
	; of the top-level (tui_terminal, tui_ssh) tui renderers.
	;
	; The reason this is required is because at any given time, in response to input,
	; timers, etc, a single pass through epoll$iteration might cause considerably more
	; than one call to updatedisplaylist, which in turn then walks up the display list
	; and ultimately ends in a call to nvrender, which flattens every object from the
	; top down, and can be quite expensive.
	;
	; So, if tui_terminal or tui_ssh is used, then the epoll$run calls the funcs herein
	; contained herein. Lock then prevents either from actually calling nvrender, and
	; then release goes ahead and does it for those toplevel objects who _would_ have
	; While this adds a little bit of overhead to each pass of epoll$iteration, because
	; some of the tui components can be expensive to flatten/render/draw/etc, it is
	; well worth it.
	;
	; The effectiveness of this can be seen especially when using tui_text editing, where
	; each keyevent that comes in causes updatedisplaylist ot be called, and then a
	; cut-n-paste into it, hehe, can become quite heavy, and this entirely bypasses the
	; individual render for each keystroke if a buffer of input arrives
	;

if used tui_lock$hold | defined include_everything

globals
{
	_tui_lock	dd	0
	_tui_locklist	dq	0
}


	; no arguments, sets our global lock variable
falign
tui_lock$hold:
	prolog	tui_lock$hold
	mov	dword [_tui_lock], 1
	epilog

end if

if used tui_lock$init | defined include_everything
	; no arguments, called from epoll$init to initialize our locklist
falign
tui_lock$init:
	prolog	tui_lock$init
	mov	edi, 1		; insert order
	call	unsignedmap$new
	mov	[_tui_locklist], rax
	epilog

end if

if used tui_lock$updatedisplaylist | defined include_everything
	; single argument in rdi: the tui_ssh or tui_terminal object that would have rendered
falign
tui_lock$updatedisplaylist:
	prolog	tui_lock$updatedisplaylist
	mov	rsi, rdi
	mov	rdi, [_tui_locklist]
	; the value in our case is a dword in the upper half for show/hide cursor, lower dword split into two words, x/y (or -1 == none)
	mov	edx, -1				; no setcursor, no show/hidecursor
	call	unsignedmap$insert_unique
	epilog

end if


if used tui_lock$clear | defined include_everything
	; called if our object gets destroyed, makes sure we don't do any pendings
falign
tui_lock$clear:
	prolog	tui_lock$clear
	mov	rsi, rdi
	mov	rdi, [_tui_locklist]
	call	unsignedmap$erase
	epilog

end if



if used tui_lock$setcursor | defined include_everything
	; three arguments: rdi == tui_render object, esi == x, edx == y
falign
tui_lock$setcursor:
	prolog	tui_lock$setcursor
	shl	edx, 16
	or	esi, edx
	push	rdi rsi
	mov	rsi, rdi
	mov	rdi, [_tui_locklist]
	call	unsignedmap$find
	test	rax, rax
	jz	.newone
	; otherwise, rax is an avlnode, who's value we need to update
	; x == lower 16 bits, y == next 16 bits, upper dword needs to remain untouched
	pop	rsi rdi
	mov	rdx, [rax+_avlofs_value]
	and	rdx, [.clearmask]
	or	rdx, rsi
	mov	[rax+_avlofs_value], rdx
	epilog
calign
.newone:
	pop	rdx rsi
	mov	rdi, [_tui_locklist]
	call	unsignedmap$insert_unique
	epilog
dalign
.clearmask:
	dq	0x300000000

end if

if used tui_lock$showcursor | defined include_everything
	; single argument in rdi: tui_render object
falign
tui_lock$showcursor:
	prolog	tui_lock$showcursor
	push	rdi
	mov	rsi, rdi
	mov	rdi, [_tui_locklist]
	call	unsignedmap$find
	test	rax, rax
	jz	.newone
	; otherwise, rax is an avlnode, who's value we need to update
	pop	rdi
	mov	rdx, [rax+_avlofs_value]
	and	rdx, [.clearmask]
	or	rdx, [.setmask]
	mov	[rax+_avlofs_value], rdx
	epilog
calign
.newone:
	pop	rsi
	mov	rdx, [.setmask]
	call	unsignedmap$insert_unique
	epilog
dalign
.clearmask:
	dq	0xffffffff
.setmask:
	dq	0x100000000
	epilog

end if

if used tui_lock$hidecursor | defined include_everything
	; single argument in rdi: tui_render object
falign
tui_lock$hidecursor:
	prolog	tui_lock$hidecursor
	push	rdi
	mov	rsi, rdi
	mov	rdi, [_tui_locklist]
	call	unsignedmap$find
	test	rax, rax
	jz	.newone
	; otherwise, rax is an avlnode, who's value we need to update
	pop	rdi
	mov	rdx, [rax+_avlofs_value]
	and	rdx, [.clearmask]
	or	rdx, [.setmask]
	mov	[rax+_avlofs_value], rdx
	epilog
calign
.newone:
	pop	rsi
	mov	rdx, [.setmask]
	call	unsignedmap$insert_unique
	epilog
dalign
.clearmask:
	dq	0xffffffff
.setmask:
	dq	0x200000000
	epilog

end if


if used tui_lock$release | defined include_everything
	; no arguments, iterates through the locklist (if any) and does the deed
falign
tui_lock$release:
	prolog	tui_lock$release
	mov	dword [_tui_lock], 0
	mov	rdi, [_tui_locklist]
	mov	rsi, .doit
	call	unsignedmap$clear
	epilog
falign
.doit:
	; rdi == key, rsi == value
	mov	rdx, [rdi]
	test	rsi, rsi
	jz	.doit_updateonly
	push	rdi rsi
	; first up: updatedisplaylist
	call	qword [rdx+tui_vupdatedisplaylist]
	mov	rcx, [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rcx
	shr	rcx, 32
	mov	rdx, [rdi]
	test	ecx, ecx
	jz	.doit_cursoronly
	cmp	ecx, 1			; 1 == showcursor
	je	.doit_showcursor
	; else, must be hide cursor
	call	qword [rdx+tui_vhidecursor]
	mov	rsi, [rsp]
	mov	rdi, [rsp+8]
	jmp	.doit_cursoronly
calign
.doit_showcursor:
	call	qword [rdx+tui_vshowcursor]
	mov	rsi, [rsp]
	mov	rdi, [rsp+8]
calign
.doit_cursoronly:
	cmp	esi, -1
	je	.doit_ret
	mov	edx, esi
	shr	edx, 16
	and	esi, 0xffff
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsetcursor]
	pop	rsi rdi
	ret
calign
.doit_ret:
	pop	rsi rdi
	ret
falign
.doit_updateonly:
	call	qword [rdx+tui_vupdatedisplaylist]
	ret

end if
