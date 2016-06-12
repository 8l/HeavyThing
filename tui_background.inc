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
	; tui_background.inc: simple background-only component
	; descendents of this should call tui_background$draw in their own draw/init
	;

if used tui_background$vtable | defined include_everything

; unfortunately, we have to make 100% sure all of our referenced functions in our vtable get included...

dalign
tui_background$vtable:
        dq      tui_object$cleanup, tui_background$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
end if


tui_bgfillchar_ofs = tui_object_size
tui_bgcolors_ofs = tui_object_size + 8
tui_background_size = tui_object_size + 16


	; most of the time this is not a standalone component, only used by other components
	; so, if you WANT this as a standalone, allocate tui_background_size worth of space
	; set its vtable to tui_background$vtable, and call one of the init functions here


	; also note: our virtual draw method calls updatedisplaylist when it is done (which forces a redraw/refresh)
	; if you don't want this, use tui_background$nvfill
	

if used tui_background$init_copy | defined include_everything
	; two parameters: rdi == tui_background we are initialising, rsi == source tui_background
	; this calls tui_object$init_copy, and then copies our two vars
	; it is assumed that the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_background$init_copy:
	prolog	tui_background$init_copy
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	tui_object$init_copy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	eax, dword [rsi+tui_bgfillchar_ofs]
	mov	ecx, dword [rsi+tui_bgcolors_ofs]
	mov	dword [rdi+tui_bgfillchar_ofs], eax
	mov	dword [rdi+tui_bgcolors_ofs], ecx
	add	rsp, 16
	epilog
end if


if used tui_background$init_rect | defined include_everything
	; four parameters: rdi == tui_background we are initialising, rsi == pointer to a bounds rect, edx == fillchar, ecx == fill colors
	; this calls tui_object$init_rect, and then sets our two vars
	; it is assumed that the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_background$init_rect:
	prolog	tui_background$init_rect
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	[rsp+16], rcx
	call	tui_object$init_rect
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_bgfillchar_ofs], rdx
	mov	[rdi+tui_bgcolors_ofs], rcx
	add	rsp, 24
	epilog
end if

if used tui_background$init_id | defined include_everything
	; five arguments: rdi == tui_background, esi == width, xmm0 == heightperc, edx == fillchar, ecx == fill colors
	; this calls tui_object$init_id, and then sets our two vars
	; it is assumed that the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_background$init_id:
	prolog	tui_background$init_id
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	[rsp+16], rcx
	call	tui_object$init_id
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_bgfillchar_ofs], rdx
	mov	[rdi+tui_bgcolors_ofs], rcx
	add	rsp, 24
	epilog
end if


if used tui_background$init_di | defined include_everything
	; five arguments: rdi == tui_background, xmm0 == widthperc, esi == height, edx == fillchar, ecx == fill colors
	; this calls tui_object$init_di, and then sets our two vars
	; it is assumed that the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_background$init_di:
	prolog	tui_background$init_di
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	mov	[rsp+16], rcx
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_bgfillchar_ofs], rdx
	mov	[rdi+tui_bgcolors_ofs], rcx
	add	rsp, 24
	epilog
end if


if used tui_background$init_dd | defined include_everything
	; five arguments: rdi == tui_background, xmm0 == widthperc, xmm1 == heightperc, esi == fillchar, edx == fill colors
	; this calls tui_object$init_dd, and then sets our two vars
	; it is assumed that the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_background$init_dd:
	prolog	tui_background$init_dd
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	call	tui_object$init_dd
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_bgfillchar_ofs], rdx
	mov	[rdi+tui_bgcolors_ofs], rcx
	add	rsp, 24
	epilog
end if


if used tui_background$init_ii | defined include_everything
	; five arguments: rdi == tui_background, esi == width, edx == height, ecx == fillchar, r8d == fill colors
	; this calls tui_object$init_ii, and then sets our two vars
falign
tui_background$init_ii:
	prolog	tui_background$init_ii
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rcx
	mov	[rsp+16], r8
	call	tui_object$init_ii
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_bgfillchar_ofs], rdx
	mov	[rdi+tui_bgcolors_ofs], rcx
	add	rsp, 24
	epilog
end if


if used tui_background$clone | defined include_everything
	; single argument: rdi == source tui_background to clone/make a copy of
	; returns new tui_background copy in rax
falign
tui_background$clone:
	prolog	tui_background$clone
	push	rdi
	mov	edi, tui_background_size
	call	heap$alloc
	mov	rdx, tui_background$vtable
	mov	[rax], rdx			; store our vtable
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	tui_background$init_copy
	pop	rax
	epilog
end if


if used tui_background$draw | defined include_everything
	; single argument: tui_background in rdi
falign
tui_background$draw:
	prolog	tui_background$draw
	push	rdi
	call	tui_background$nvfill
	pop	rdi
	mov	rsi, [rdi]		; load the vtable
	call	qword [rsi+tui_vupdatedisplaylist]
	epilog
end if


if used tui_background$nvfill | defined include_everything
	; single argument: tui_background in rdi
falign
tui_background$nvfill:
	prolog	tui_background$nvfill
	mov	eax, dword [rdi+tui_width_ofs]
	mov	ecx, dword [rdi+tui_height_ofs]
	test	eax, eax
	jz	.nothingtodo
	test	ecx, ecx
	jz	.nothingtodo
	; else, we have both width and height (and yes, it is possible to have zero for either/both during dynamic sizing, hence the check)
	mul	ecx
	mov	rdx, rdi
	shl	rax, 2
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rax
	mov	rdi, [rdx+tui_text_ofs]
	test	rdi, rdi
	jz	.bailout
	mov	esi, [rdx+tui_bgfillchar_ofs]
	test	esi, esi
	jz	.attronly
	mov	rdx, rax
	call	memset32
calign
.attronly:
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_attr_ofs]
	mov	esi, [rcx+tui_bgcolors_ofs]
	mov	rdx, [rsp+8]
	call	memset32
	add	rsp, 16
	epilog
calign
.bailout:
	add	rsp, 16
	epilog
calign
.nothingtodo:
	epilog

end if
