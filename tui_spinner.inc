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
	; tui_spinner.inc: a very simple text spinner
	; we use - \ | / as our spinchars, but if you want unicode spinners or whatever
	; just modify spincharcount and the spinchars themselves (initial in $new, rest in $draw)
	; spincharcount is in the timer handler


if used tui_spinner$vtable | defined include_everything

dalign
tui_spinner$vtable:
        dq      tui_spinner$cleanup, tui_spinner$clone, tui_spinner$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_spinner$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
end if

tui_spinner_counter_ofs = tui_object_size
tui_spinner_colors_ofs = tui_object_size + 8
tui_spinner_speed_ofs = tui_object_size + 16
tui_spinner_timerptr_ofs = tui_object_size + 24
tui_spinner_size = tui_object_size + 32

if used tui_spinner$new | defined include_everything
	; two arguments: edi == colors, esi == ms "speed" (really, delay between updates)
	; esi == 50 == 20fps, etc.
falign
tui_spinner$new:
	prolog	tui_spinner$new
	push	rdi rsi
	mov	edi, tui_spinner_size
	call	heap$alloc
	pop	rsi rdi
	push	rax
	mov	qword [rax], tui_spinner$vtable
	mov	qword [rax+tui_spinner_counter_ofs], 0
	mov	qword [rax+tui_spinner_colors_ofs], rdi
	mov	qword [rax+tui_spinner_speed_ofs], rsi
	mov	rdi, rax
	mov	esi, 1
	mov	edx, 1
	call	tui_object$init_ii
	mov	rax, [rsp]
	mov	ecx, [rax+tui_spinner_colors_ofs]
	mov	rdi, [rax+tui_text_ofs]
	mov	rsi, [rax+tui_attr_ofs]
	mov	dword [rdi], '-'				; INITIAL SPINCHAR
	mov	dword [rsi], ecx
	mov	edi, [rax+tui_spinner_speed_ofs]
	mov	rsi, rax
	call	epoll$timer_new
	mov	rcx, rax
	pop	rax
	mov	[rax+tui_spinner_timerptr_ofs], rcx
	epilog

end if

if used tui_spinner$clone | defined include_everything
	; single argument in rdi: our spinner to clone
falign
tui_spinner$clone:
	prolog	tui_spinner$clone
	; since we aren't going to have any children/bastards/etc, clone is simple, we can just return a new one
	mov	esi, [rdi+tui_spinner_speed_ofs]
	mov	edi, [rdi+tui_spinner_colors_ofs]
	call	tui_spinner$new
	epilog

end if

if used tui_spinner$cleanup | defined include_everything
	; single argument in rdi: our spinner
falign
tui_spinner$cleanup:
	prolog	tui_spinner$cleanup
	; we have to cleanup our timer
	push	rdi
	mov	rdi, [rdi+tui_spinner_timerptr_ofs]
	call	epoll$timer_clear
	pop	rdi
	call	tui_object$cleanup
	epilog

end if

if used tui_spinner$draw | defined include_everything
	; single argument in rdi: our tui_spinner object
falign
tui_spinner$draw:
	prolog	tui_spinner$draw
	mov	rcx, [rdi]					; our vtable
	mov	edx, [rdi+tui_spinner_counter_ofs]
	mov	rsi, [rdi+tui_text_ofs]
	mov	eax, [rdx*4+.spinchars]
	mov	[rsi], eax
	call	qword [rcx+tui_vupdatedisplaylist]
	epilog
dalign
.spinchars:
	dd	'-', '\', '|', '/'				; SPINCHARS

end if

if used tui_spinner$timer | defined include_everything
	; single argument in rdi: our tui_spinner object
falign
tui_spinner$timer:
	prolog	tui_spinner$timer
	mov	rsi, [rdi]
	mov	edx, [rdi+tui_spinner_counter_ofs]
	xor	ecx, ecx
	add	edx, 1
	cmp	edx, 4						; SPINCHARCOUNT
	cmovae	edx, ecx
	mov	[rdi+tui_spinner_counter_ofs], edx
	call	qword [rsi+tui_vdraw];
	xor	eax, eax			; keep going
	epilog

end if
