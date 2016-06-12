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
	; tui_progressbar.inc: simple progressbar functionality
	;

tui_progressbar_min_ofs = tui_background_size
tui_progressbar_mind_ofs = tui_background_size + 8
tui_progressbar_cur_ofs = tui_background_size + 16
tui_progressbar_curd_ofs = tui_background_size + 24
tui_progressbar_max_ofs = tui_background_size + 32
tui_progressbar_maxd_ofs = tui_background_size + 40
tui_progressbar_int_ofs = tui_background_size + 48
tui_progressbar_dir_ofs = tui_background_size + 56		; 0 == horiz & vert, left to right & top to bottom, 1 == horiz & vert, other way 'round
tui_progressbar_fillcolors_ofs = tui_background_size + 64

tui_progressbar_size = tui_background_size + 72

if used tui_progressbar$vtable | defined include_everything

dalign
tui_progressbar$vtable:
	dq      tui_object$cleanup, tui_progressbar$clone, tui_progressbar$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if


if used tui_progressbar$new_id | defined include_everything
	; five arguments: edi == width, xmm0 == heightperc, esi == dir, edx == empty colors, ecx == fillcolors
falign
tui_progressbar$new_id:
	prolog	tui_progressbar$new_id
	movq	rax, xmm0
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rax
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	edi, tui_progressbar_size
	call	heap$alloc_clear
	mov	qword [rax], tui_progressbar$vtable
	mov	r8, [rsp+8]
	mov	rdi, rax
	mov	esi, [rsp]
	movq	xmm0, r8
	mov	edx, ' '
	mov	ecx, [rsp+24]
	mov	[rsp], rax
	call	tui_background$init_id
	mov	rax, [rsp]
	mov	esi, [rsp+16]
	mov	ecx, [rsp+32]
	mov	[rax+tui_progressbar_dir_ofs], esi
	mov	[rax+tui_progressbar_fillcolors_ofs], ecx
	mov	dword [rax+tui_progressbar_int_ofs], 1
	add	rsp, 40
	epilog

end if

if used tui_progressbar$new_di | defined include_everything
	; five arguments: xmm0 == widthperc, edi == height, esi == dir, edx == empty colors, ecx == fillcolors
falign
tui_progressbar$new_di:
	prolog	tui_progressbar$new_di
	movq	rax, xmm0
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rax
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	edi, tui_progressbar_size
	call	heap$alloc_clear
	mov	qword [rax], tui_progressbar$vtable
	mov	r8, [rsp+8]
	mov	rdi, rax
	mov	esi, [rsp]
	movq	xmm0, r8
	mov	edx, ' '
	mov	ecx, [rsp+24]
	mov	[rsp], rax
	call	tui_background$init_di
	mov	rax, [rsp]
	mov	esi, [rsp+16]
	mov	ecx, [rsp+32]
	mov	[rax+tui_progressbar_dir_ofs], esi
	mov	[rax+tui_progressbar_fillcolors_ofs], ecx
	mov	dword [rax+tui_progressbar_int_ofs], 1
	add	rsp, 40
	epilog

end if

if used tui_progressbar$new_dd | defined include_everything
	; five arguments: xmm0 == widthperc, xmm1 == heightperc, edi == dir, esi == empty colors, edx == fillcolors
falign
tui_progressbar$new_dd:
	prolog	tui_progressbar$new_dd
	movq	rax, xmm0
	movq	r8, xmm1
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rax
	mov	[rsp+16], rsi
	mov	[rsp+24], rdx
	mov	[rsp+32], r8
	mov	edi, tui_progressbar_size
	call	heap$alloc_clear
	mov	qword [rax], tui_progressbar$vtable
	mov	r8, [rsp+8]
	mov	r9, [rsp+32]
	mov	rdi, rax
	movq	xmm0, r8
	movq	xmm1, r9
	mov	esi, ' '
	mov	edx, [rsp+16]
	mov	[rsp+8], rax
	call	tui_background$init_dd
	mov	rax, [rsp+8]
	mov	esi, [rsp]
	mov	ecx, [rsp+24]
	mov	[rax+tui_progressbar_dir_ofs], esi
	mov	[rax+tui_progressbar_fillcolors_ofs], ecx
	mov	dword [rax+tui_progressbar_int_ofs], 1
	add	rsp, 40
	epilog

end if

if used tui_progressbar$new_ii | defined include_everything
	; five arguments: edi == width, esi == height, edx == dir, ecx == empty colors, r8d == fillcolors
falign
tui_progressbar$new_ii:
	prolog	tui_progressbar$new_ii
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	edi, tui_progressbar_size
	call	heap$alloc_clear
	mov	qword [rax], tui_progressbar$vtable
	mov	rdi, rax
	mov	esi, [rsp]
	mov	edx, [rsp+8]
	mov	ecx, ' '
	mov	r8d, [rsp+24]
	mov	[rsp], rax
	call	tui_background$init_ii
	mov	rax, [rsp]
	mov	esi, [rsp+16]
	mov	ecx, [rsp+32]
	mov	[rax+tui_progressbar_dir_ofs], esi
	mov	[rax+tui_progressbar_fillcolors_ofs], ecx
	mov	dword [rax+tui_progressbar_int_ofs], 1
	add	rsp, 40
	epilog

end if

if used tui_progressbar$new_rect | defined include_everything
	; four arguments: rdi == ptr to boundsrect, esi == dir, edx == empty colors, ecx == fillcolors
falign
tui_progressbar$new_rect:
	prolog	tui_progressbar$new_rect
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	edi, tui_progressbar_size
	call	heap$alloc_clear
	mov	qword [rax], tui_progressbar$vtable
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	edx, ' '
	mov	ecx, [rsp+16]
	mov	[rsp], rax
	call	tui_background$init_rect
	mov	rax, [rsp]
	mov	esi, [rsp+8]
	mov	ecx, [rsp+24]
	mov	[rax+tui_progressbar_dir_ofs], esi
	mov	[rax+tui_progressbar_fillcolors_ofs], ecx
	mov	dword [rax+tui_progressbar_int_ofs], 1
	add	rsp, 32
	epilog

end if

if used tui_progressbar$clone | defined include_everything
	; single argument in rdi: our tui_progressbar object to clone
falign
tui_progressbar$clone:
	prolog	tui_progressbar$clone
	push	rdi
	mov	edi, tui_progressbar_size
	call	heap$alloc_clear
	mov	rsi, [rsp]
	push	rax
	mov	rdi, rax
	mov	rcx, [rsi]
	mov	[rdi], rcx
	call	tui_background$init_copy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	lea	rdi, [rdi+tui_progressbar_min_ofs]
	lea	rsi, [rsi+tui_progressbar_min_ofs]
	mov	edx, 72
	call	memcpy
	pop	rax rsi
	epilog

end if

if used tui_progressbar$draw | defined include_everything
	; single argument in rdi: our tui_progressbar object
falign
tui_progressbar$draw:
	prolog	tui_progressbar$draw
	cmp	dword [rdi+tui_width_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_height_ofs], 0
	je	.nothingtodo
	push	rbx
	mov	rbx, rdi
	; let tui_background do its job first
	call	tui_background$nvfill
	; get our percentage
	mov	rdi, rbx
	call	tui_progressbar$nvgetperc
	; calc our total character area
	mov	eax, [rbx+tui_width_ofs]
	mov	ecx, [rbx+tui_height_ofs]
	mul	ecx
	cvtsi2sd xmm1, eax
	mulsd	xmm1, xmm0
	cvtsd2si edx, xmm1
	cmp	edx, 0
	jle	.outtahere
	shl	eax, 2		; in bytes
	shl	edx, 2		; in bytes
	sub	eax, edx
	mov	esi, [rbx+tui_progressbar_fillcolors_ofs]
	mov	rdi, [rbx+tui_attr_ofs]
	; if our direction is nonzero, we need to do the diff
	mov	rcx, [rbx+tui_attr_ofs]
	add	rcx, rax
	cmp	dword [rbx+tui_progressbar_dir_ofs], 0
	cmovne	rdi, rcx
	call	memset32
	; update our displaylist
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rbx
	epilog
calign
.outtahere:
	pop	rbx
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_progressbar$nvlimits | defined include_everything
	; three arguments: rdi == our tui_progressbar, rsi == min, rdx == max
falign
tui_progressbar$nvlimits:
	prolog	tui_progressbar$nvlimits
	mov	dword [rdi+tui_progressbar_int_ofs], 1
	mov	[rdi+tui_progressbar_min_ofs], rsi
	mov	[rdi+tui_progressbar_max_ofs], rdx
	mov	rcx, [rdi]
	call	qword [rcx+tui_vdraw]
	epilog

end if

if used tui_progressbar$nvlimitsd | defined include_everything
	; three arguments: rdi == our tui_progressbar, xmm0 == min, xmm1 == max
falign
tui_progressbar$nvlimitsd:
	prolog	tui_progressbar$nvlimitsd
	movq	rax, xmm0
	movq	rcx, xmm1
	mov	dword [rdi+tui_progressbar_int_ofs], 0
	mov	[rdi+tui_progressbar_mind_ofs], rax
	mov	[rdi+tui_progressbar_maxd_ofs], rcx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vdraw]
	epilog

end if

if used tui_progressbar$nvupdate | defined include_everything
	; two arguments: rdi == our tui_progressbar, rsi == cur
falign
tui_progressbar$nvupdate:
	prolog	tui_progressbar$nvupdate
	mov	[rdi+tui_progressbar_cur_ofs], rsi
	mov	rdx, [rdi]
	call	qword [rdx+tui_vdraw]
	epilog

end if

if used tui_progressbar$nvupdated | defined include_everything
	; two arguments: rdi == our tui_progressbar, xmm0 == cur
falign
tui_progressbar$nvupdated:
	prolog	tui_progressbar$nvupdated
	movq	rax, xmm0
	mov	[rdi+tui_progressbar_curd_ofs], rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vdraw]
	epilog

end if

if used tui_progressbar$nvgetperc | defined include_everything
	; single argument in rdi: our tui_progressbar
	; returns the current percentage in xmm0 (as a normal decimal, 50% == 0.5)
falign
tui_progressbar$nvgetperc:
	prolog	tui_progressbar$nvgetperc
	cmp	dword [rdi+tui_progressbar_int_ofs], 0
	je	.doubles
	mov	rax, [rdi+tui_progressbar_min_ofs]
	mov	rcx, [rdi+tui_progressbar_cur_ofs]
	mov	rdx, [rdi+tui_progressbar_max_ofs]
	cmp	rax, rdx
	je	.zeroret
	test	rdx, rdx
	jz	.zeroret
	sub	rcx, rax
	sub	rdx, rax
	cvtsi2sd xmm0, rcx
	cvtsi2sd xmm1, rdx
	divsd	xmm0, xmm1
	epilog
calign
.doubles:
	cmp	qword [rdi+tui_progressbar_max_ofs], 0
	je	.zeroret
	movq	xmm2, [rdi+tui_progressbar_mind_ofs]
	movq	xmm0, [rdi+tui_progressbar_curd_ofs]
	movq	xmm1, [rdi+tui_progressbar_maxd_ofs]
	ucomisd xmm1, xmm2
	je	.zeroret
	subsd	xmm0, xmm2
	subsd	xmm1, xmm2
	divsd	xmm0, xmm1
	epilog
calign
.zeroret:
	xorpd	xmm0, xmm0
	epilog

end if
