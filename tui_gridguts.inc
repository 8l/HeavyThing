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
	; tui_gridguts.inc: the "private" handlers that actually do the work for tui_datagrid
	; "private" meaning, while you CAN use this directly, it was intended to be used as
	; the one and only redheaded stepchild of tui_datagrid
	; as such, these are all prolog_silent so that their names don't end up in the symbol
	; table...
	;

if used tui_gridguts$vtable | defined include_everything

dalign
tui_gridguts$vtable:
        dq      tui_gridguts$cleanup, tui_gridguts$clone, tui_gridguts$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_gridguts$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

tui_ggdatagrid_ofs = tui_background_size
tui_ggdata_ofs = tui_background_size + 8
tui_ggselectedindex_ofs = tui_background_size + 16
tui_ggscroll_ofs = tui_background_size + 24
tui_ggcols_ofs = tui_background_size + 32
tui_ggsearchpanel_ofs = tui_background_size + 40
tui_ggsearchpanelvisible_ofs = tui_background_size + 48
tui_ggdataowner_ofs = tui_background_size + 56
tui_ggrowcount_ofs = tui_background_size + 64

tui_gridguts_size = tui_background_size + 72

if used tui_gridguts$new | defined include_everything
	; single argument in rdi: our tui_datagrid parent object
	; we descend tui_background, so we'll call its init, and setup our vars
	; returns a new tui_gridguts object in rax
falign
tui_gridguts$new:
	prolog_silent	tui_gridguts$new
	sub	rsp, 16
	mov	[rsp], rdi
	mov	edi, tui_gridguts_size
	call	heap$alloc
	mov	qword [rax], tui_gridguts$vtable
	mov	rcx, [rsp]
	mov	[rsp+8], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	esi, ' '
	mov	rdx, [rcx+tui_dgcolors_ofs]
	call	tui_background$init_dd
	call	list$new
	mov	rcx, rax
	mov	rax, [rsp+8]
	mov	rdi, [rsp]
	xor	edx, edx
	mov	[rax+tui_ggdatagrid_ofs], rdi
	mov	[rax+tui_ggdata_ofs], rdx
	mov	[rax+tui_ggselectedindex_ofs], rdx
	mov	[rax+tui_ggscroll_ofs], rdx
	mov	[rax+tui_ggcols_ofs], rcx
	mov	[rax+tui_ggsearchpanel_ofs], rdx
	mov	[rax+tui_ggsearchpanelvisible_ofs], rdx
	mov	[rax+tui_ggdataowner_ofs], rdx
	mov	[rax+tui_ggrowcount_ofs], rdx
	add	rsp, 16
	epilog
end if


	; grid columns get:
tui_gridcol_name_ofs = 0
tui_gridcol_width_ofs = 8
tui_gridcol_widthperc_ofs = 16
tui_gridcol_align_ofs = 24
tui_gridcol_propertyname_ofs = 32
tui_gridcol_actualwidth_ofs = 40

tui_gridcol_size = 48

if used tui_gridcol$new_copy | defined include_everything
	; single argument in rdi: grid column object to make a copy of
falign
tui_gridcol$new_copy:
	prolog_silent	tui_gridcol$new_copy
	sub	rsp, 32
	mov	[rsp], rdi
	mov	rdi, [rdi+tui_gridcol_name_ofs]
	call	string$copy
	mov	rdi, [rsp]
	mov	[rsp+8], rax
	mov	rdi, [rdi+tui_gridcol_propertyname_ofs]
	call	string$copy
	mov	[rsp+16], rax
	mov	edi, tui_gridcol_size
	call	heap$alloc
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	edx, tui_gridcol_size
	call	memcpy
	mov	rax, [rsp+24]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rax+tui_gridcol_name_ofs], rdx
	mov	[rax+tui_gridcol_propertyname_ofs], rcx
	add	rsp, 32
	epilog
end if

if used tui_gridguts$clone | defined include_everything
	; single argument in rdi: the tui_gridguts object to make a copy of
falign
tui_gridguts$clone:
	prolog_silent	tui_gridguts$clone
	sub	rsp, 16
	mov	[rsp], rdi
	mov	edi, tui_gridguts_size
	call	heap$alloc
	mov	qword [rax], tui_gridguts$vtable
	mov	rsi, [rsp]
	mov	[rsp+8], rax
	mov	rdi, rax
	call	tui_background$init_copy
	call	list$new
	mov	rdi, [rsp+8]
	mov	rsi, [rsp]
	; hmm, our parent ggdatagrid needs to be set, but it isn't available yet
	xor	edx, edx
	mov	[rdi+tui_ggdatagrid_ofs], rdx
	mov	[rdi+tui_ggdata_ofs], rdx
	mov	[rdi+tui_ggselectedindex_ofs], rdx
	mov	[rdi+tui_ggscroll_ofs], rdx
	mov	[rdi+tui_ggcols_ofs], rax
	mov	[rdi+tui_ggsearchpanel_ofs], rdx
	mov	[rdi+tui_ggsearchpanelvisible_ofs], rdx
	mov	[rdi+tui_ggdataowner_ofs], rdx
	mov	[rdi+tui_ggrowcount_ofs], rdx
	; copy the original's columns:
	mov	rdx, rax
	mov	rdi, [rsi+tui_ggcols_ofs]
	mov	rsi, .columncopy
	call	list$foreach_arg
	; if the original had data, we need to deepcopy it
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_ggdata_ofs]
	test	rdi, rdi
	jz	.allgood
	; further, see if the original OWNED the data...
	mov	rdx, [rsi+tui_ggdataowner_ofs]
	test	rdx, rdx
	jz	.copynotowner
	call	json$copy
	mov	rdi, [rsp+8]
	mov	[rdi+tui_ggdata_ofs], rax
	mov	qword [rdi+tui_ggdataowner_ofs], 1
	mov	rdx, [rax+json_contents_ofs]
	mov	rcx, [rdx]
	mov	[rdi+tui_ggrowcount_ofs], rcx	; set the rowcount
	add	rsp, 16
	mov	rax, rdi
	epilog
calign
.copynotowner:
	mov	rax, [rsp+8]
	mov	[rax+tui_ggdata_ofs], rdi
	mov	rdx, [rdi+json_contents_ofs]
	mov	rcx, [rdx]
	mov	[rax+tui_ggrowcount_ofs], rcx	; set the rowcount
	add	rsp, 16
	epilog
calign
.allgood:
	mov	rax, [rsp+8]
	add	rsp, 16
	epilog
calign
.columncopy:
	; this gets called with rdi as our column list object, and rsi as our destination list
	push	rsi
	call	tui_gridcol$new_copy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	list$push_back
	pop	rsi
	ret
end if
	

if used tui_gridguts$cleanup | defined include_everything
	; single argument in rdi: our tui_gridguts object to cleanup
falign
tui_gridguts$cleanup:
	prolog_silent	tui_gridguts$cleanup
	push	rdi
	call	tui_object$cleanup
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_ggcols_ofs]
	mov	rsi, .columncleanup
	call	list$clear
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_ggcols_ofs]
	call	heap$free
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_ggdata_ofs]
	test	rdi, rdi
	jz	.alldone
	cmp	qword [rcx+tui_ggdataowner_ofs], 0
	je	.alldone
	call	json$destroy
	pop	rdi
	epilog
calign
.alldone:
	pop	rdi
	epilog
calign
.columncleanup:
	; this gets called with our single gridcol in rdi
	push	rdi
	mov	rdi, [rdi+tui_gridcol_name_ofs]
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_gridcol_propertyname_ofs]
	call	heap$free
	mov	rdi, [rsp]
	call	heap$free
	pop	rdi
	ret
end if

if used tui_gridguts$draw | defined include_everything
	; single argument in rdi: our tui_gridguts object
falign
tui_gridguts$draw:
	prolog_silent	tui_gridguts$draw
	cmp	dword [rdi+tui_width_ofs], 0
	je	.invisible
	cmp	dword [rdi+tui_height_ofs], 0
	je	.invisible
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	call	tui_background$nvfill
	mov	rdi, rbx
	call	.calcwidths
	mov	eax, [rbx+tui_width_ofs]
	mov	r11d, eax
	shl	r11, 2				; width in bytes
	mov	ecx, [rbx+tui_height_ofs]
	mul	ecx
	shl	rax, 2				; width * height in bytes
	mov	r12, [rbx+tui_text_ofs]
	mov	r13, [rbx+tui_attr_ofs]
	mov	r14, r12
	add	r14, rax			; end of our text space

	; check to see if we are to draw our headers (headercolors >= 0)
	mov	rdx, [rbx+tui_ggdatagrid_ofs]
	mov	ecx, [rdx+tui_dgheadercolors_ofs]
	cmp	ecx, 0xffffffff
	je	.noheaders
	mov	r15d, 1				; relative x position
	mov	dword [r12], ' '
	mov	dword [r13], ecx
	mov	rdx, [rbx+tui_ggcols_ofs]
	mov	rdx, [rdx+_list_first_ofs]
	sub	rsp, 24
calign
.headerloop:
	test	rdx, rdx
	jz	.headers_done
	mov	rdi, [rdx+_list_valueofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	[rsp], rdx
	mov	[rsp+8], rcx
	mov	[rsp+16], r11

	mov	rsi, r12
	mov	rdx, r13

	mov	rax, r15
	shl	rax, 2
	add	rsi, rax
	add	rdx, rax
	; colors already in rcx
	mov	r8, [rdi+tui_gridcol_name_ofs]
	add	r15d, dword [rdi+tui_gridcol_actualwidth_ofs]
	call	.drawcolumn
	mov	rdx, [rsp]
	mov	rcx, [rsp+8]
	mov	r11, [rsp+16]
	
	mov	dword [r12+r15*4], ' '
	mov	dword [r13+r15*4], ecx
	add	r15, 1
	jmp	.headerloop
calign
.headers_done:
	add	r12, r11
	add	r13, r11
	add	rsp, 24
calign
.noheaders:
	mov	rdx, [rbx+tui_ggdata_ofs]
	test	rdx, rdx
	jz	.updateandreturn
	mov	rcx, [rdx+json_contents_ofs]
	mov	rax, [rcx]
	test	rax, rax		; rax has our contents array length
	jz	.updateandreturn

	mov	ecx, dword [rbx+tui_height_ofs]
	sub	ecx, 1
	cmp	dword [rbx+tui_ggscroll_ofs], 0
	je	.notopelipses
	call	.drawelipses
	mov	ecx, dword [rbx+tui_height_ofs]
	sub	ecx, 2
calign
.notopelipses:
	mov	r9, rax					; data contents size
	mov	r8d, dword [rbx+tui_ggscroll_ofs]	; dp
	sub	r9, r8
	cmp	rcx, r9
	jge	.nobottomelipses
	sub	rcx, 1
calign
.nobottomelipses:
	cmp	rcx, rax				; visual rows > data rows
	cmovle	r9, rcx
	cmovg	r9, rax					; minimum of visual rows and data rows
	add	r9, r8					; dpend
	cmp	r9, rax
	cmovg	r9, rax					; make sure it doesn't run past the end

	; so now we have the goods necessary to commence our loop
	sub	rsp, 48

	; load up the first list item in the contents array
	mov	r10, [rbx+tui_ggdata_ofs]
	mov	r10, [r10+json_contents_ofs]
	mov	r10, [r10+_list_first_ofs]
	; mov forward by scroll amount in our list
	test	r10, r10
	jz	.contentsloop				; sanity only
	test	r8, r8
	jz	.contentsloop
	mov	r15, r8
calign
.listwalk:
	mov	r10, [r10+_list_nextofs]
	test	r10, r10
	jz	.contentsloop
	sub	r15, 1
	jnz	.listwalk
calign
.contentsloop:
	cmp	r8, r9
	jge	.contentsdone
	cmp	r12, r14
	jge	.contentsdone
	test	r10, r10
	jz	.contentsdone
	mov	[rsp], r8
	mov	[rsp+8], r9
	mov	[rsp+16], r10
	mov	[rsp+24], r11
	mov	r15d, 1				; relative x position
	
	; get our colors from the parent DG
	mov	rdx, [rbx+tui_ggdatagrid_ofs]
	mov	ecx, dword [rdx+tui_dgcolors_ofs]
	mov	eax, dword [rdx+tui_dgselcolors_ofs]
	cmp	r8, [rbx+tui_ggselectedindex_ofs]
	cmove	ecx, eax
	; attribute now in ecx for this row
	mov	[rsp+32], rcx
	mov	dword [r12], ' '
	mov	dword [r13], ecx

	; we need to iterate the columns loop for the current contents object in [r10+_list_valueofs]
	mov	rdx, [rbx+tui_ggcols_ofs]
	mov	rdx, [rdx+_list_first_ofs]
calign
.contentscolumnloop:
	test	rdx, rdx
	jz	.contentscolumnsdone
	mov	[rsp+40], rdx
	; see if we actually have this property by name
	mov	rdi, [r10+_list_valueofs]
	mov	rsi, [rdx+_list_valueofs]
	mov	rsi, [rsi+tui_gridcol_propertyname_ofs]
	call	json$getvaluebyname
	test	rax, rax
	jz	.contentscolumnloop_novalue
	; otherwise, we have a json object in rax, make sure it is a string
	cmp	dword [rax+json_type_ofs], json_value
	jne	.contentscolumnloop_novalue	; was not a string value
	; otherwise, the string we want to draw is in [rax+json_value_ofs]

	mov	r8, [rax+json_value_ofs]

calign
.contentscolumnloop_drawcol:
	mov	rcx, [rsp+32]
	mov	rdx, [rsp+40]
	mov	rdi, [rdx+_list_valueofs]	; our grid column
	mov	rsi, r12
	mov	rdx, r13

	mov	rax, r15
	shl	rax, 2
	add	rsi, rax
	add	rdx, rax
	; colors already in rcx
	add	r15d, dword [rdi+tui_gridcol_actualwidth_ofs]
	call	.drawcolumn

	mov	r10, [rsp+16]
	mov	rcx, [rsp+32]
	mov	rdx, [rsp+40]

	mov	dword [r12+r15*4], ' '
	mov	dword [r13+r15*4], ecx
	add	r15d, 1

	mov	rdx, [rdx+_list_nextofs]
	jmp	.contentscolumnloop
cleartext .emptystr, ''
calign
.contentscolumnloop_novalue:
	mov	r8, .emptystr
	jmp	.contentscolumnloop_drawcol
calign
.contentscolumnsdone:
	mov	r8, [rsp]
	mov	r9, [rsp+8]
	mov	r10, [rsp+16]
	mov	r11, [rsp+24]
	
	mov	r10, [r10+_list_nextofs]
	add	r8, 1
	add	r12, r11
	add	r13, r11
	jmp	.contentsloop
calign
.contentsdone:
	add	rsp, 48

	; make sure we don't need a bottom elipses
	mov	rdx, [rbx+tui_ggdata_ofs]
	test	rdx, rdx
	jz	.updateandreturn
	mov	rcx, [rdx+json_contents_ofs]
	mov	rax, [rcx]
	test	rax, rax		; rax has our contents array length
	jz	.updateandreturn

	mov	ecx, dword [rbx+tui_height_ofs]
	sub	ecx, 1
	cmp	dword [rbx+tui_ggscroll_ofs], 0
	je	.notopelipses2
	mov	ecx, dword [rbx+tui_height_ofs]
	sub	ecx, 2
calign
.notopelipses2:
	; visual rows is in ecx, we need to subtract scroll from datarows
	sub	rax, qword [rbx+tui_ggscroll_ofs]
	cmp	rcx, rax
	jge	.updateandreturn
	call	.drawelipses
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.updateandreturn:
	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.drawelipses:
	cmp	r11, 12				; r11 is width in bytes, 12 == 3 characters worth
	jb	.notenoughroom
	mov	r8, [rbx+tui_ggdatagrid_ofs]
	mov	r9d, [r8+tui_dgcolors_ofs]
	mov	rcx, r11
calign
.drawelipses_loop:				; clear the entire line first
	sub	rcx, 4
	mov	dword [r12+rcx], ' '
	mov	dword [r13+rcx], r9d
	test	rcx, rcx
	jnz	.drawelipses_loop
	mov	rcx, r11			; width in bytes
	shr	rcx, 2				; width in characters
	sub	rcx, 3				; less 3
	shr	rcx, 1				; div 2 for our left edge
	mov	dword [r12+rcx*4], '.'
	mov	dword [r12+rcx*4+4], '.'
	mov	dword [r12+rcx*4+8], '.'
	add	r12, r11
	add	r13, r11
	ret
calign
.notenoughroom:
	add	r12, r11
	add	r13, r11
	ret
calign
.invisible:
	epilog
calign
.calcwidths:
	; we have to divide our column widths similar to how tui_object does it for calcchildbounds and horizontal layout...
	; the reason we are doing this here is to avoid having thousands of layout objects...
	; the way tui_object does it could get pretty ugly if there are bucketloads of children
	; rdi (and rbx) == our tui_gridguts object, and thats all we have, we are free to smash up all regs except rbx
	mov	r15d, dword [rdi+tui_width_ofs]
	sub	r15d, 1					; -1 here for the leftmost gutter of 1 char, then each col gets +1
	mov	rsi, [rdi+tui_ggcols_ofs]
	mov	rdx, [rsi+_list_size_ofs]		; our column count
	sub	r15, rdx
	cmp	r15, 0					; available width
	jle	.calcwidths_noroom
	xorpd	xmm0, xmm0				; total width percent
	mov	rdi, [rdi+tui_ggcols_ofs]
	mov	rsi, .calcwidths_sizescan
	call	list$foreach
	mov	rdi, [rbx+tui_ggcols_ofs]
	mov	rsi, .calcwidths_sizeset
	call	list$foreach
	ret
calign
.calcwidths_sizescan:
	; passed in rdi is our gridcol object
	cmp	qword [rdi+tui_gridcol_widthperc_ofs], 0
	jne	.calcwidths_sizescan_percbased
	sub	r15d, dword [rdi+tui_gridcol_width_ofs]
	ret
calign
.calcwidths_sizescan_percbased:
	movq	xmm1, [rdi+tui_gridcol_widthperc_ofs]
	addsd	xmm0, xmm1
	ret
calign
.calcwidths_sizeset:
	cmp	qword [rdi+tui_gridcol_widthperc_ofs], 0
	jne	.calcwidths_sizeset_percbased
	mov	eax, dword [rdi+tui_gridcol_width_ofs]
	mov	dword [rdi+tui_gridcol_actualwidth_ofs], eax
	ret
calign
.calcwidths_sizeset_percbased:
	cvtsi2sd	xmm2, r15d			; convert available width to a double
	movq	xmm1, [rdi+tui_gridcol_widthperc_ofs]
	divsd	xmm1, xmm0
	mulsd	xmm1, xmm2
	cvtsd2si	eax, xmm1
	mov	dword [rdi+tui_gridcol_actualwidth_ofs], eax
	ret
calign
.calcwidths_noroom:
	mov	rdi, rsi
	mov	rsi, .calcwidths_noroom_setter
	call	list$foreach
	ret
calign
.calcwidths_noroom_setter:
	xor	eax, eax
	sub	rax, 1					; hmm, do i need a full 64 bit negone?
	mov	[rdi+tui_gridcol_actualwidth_ofs], rax
	ret
calign
.drawcolumn:
	; this is called with rdi == grid column, rsi == text pointer, rdx == attribute pointer, ecx == colors, r8 == string to draw
	mov	r9, [rdi+tui_gridcol_actualwidth_ofs]
	cmp	r9, 1
	jle	.nothingtodo
	; first up, fill our area
	mov	r10, rsi	; save it
calign
.drawcolumn_clearloop:
	mov	dword [rsi], ' '
	mov	dword [rdx], ecx
	add	rsi, 4
	add	rdx, 4
	sub	r9, 1
	jnz	.drawcolumn_clearloop
	cmp	qword [r8], 0
	je	.nothingtodo
	mov	rsi, r10	; restore rsi back to the start
	mov	r9, [rdi+tui_gridcol_actualwidth_ofs]
	cmp	r9, qword [r8]
	jbe	.drawcolumn_doit
	; otherwise, the value's length is less than the actual width, so determine alignment
	mov	r10, r9
	sub	r10, qword [r8]	; remainder (in characters)
	mov	r9, qword [r8]
	cmp	dword [rdi+tui_gridcol_align_ofs], tui_textalign_left
	je	.drawcolumn_doit
	cmp	dword [rdi+tui_gridcol_align_ofs], tui_textalign_right
	je	.drawcolumn_right
	; else, it is centered
	shl	r10, 1
	add	rsi, r10
	jmp	.drawcolumn_doit
calign
.drawcolumn_right:
	shl	r10, 2
	add	rsi, r10
calign
.drawcolumn_doit:
	add	r8, 8		; skip its preface
if string_bits = 32
	mov	eax, dword [r8]
	add	r8, 4
else
	movzx	eax, word [r8]
	add	r8, 2
end if
	mov	dword [rsi], eax
	add	rsi, 4
	sub	r9, 1
	jnz	.drawcolumn_doit_loop
	ret
calign
.drawcolumn_doit_loop:
if string_bits = 32
	mov	eax, dword [r8]
	add	r8, 4
else
	movzx	eax, word [r8]
	add	r8, 2
end if
	mov	dword [rsi], eax
	add	rsi, 4
	sub	r9, 1
	jnz	.drawcolumn_doit_loop
	ret
calign
.nothingtodo:
	ret

end if


if used tui_gridguts$nvgetselected | defined include_everything

falign
tui_gridguts$nvgetselected:
	prolog_silent	tui_gridguts$nvgetselected
	mov	rcx, [rdi+tui_ggdata_ofs]
	test	rcx, rcx
	jz	.zeroret
	mov	rcx, [rcx+json_contents_ofs]
	mov	rax, [rcx]
	test	rax, rax		; rax has our contents array length
	jz	.zeroret
	; walk (*cough*) the contents array to get our correct item
	; the list itself is in rcx already, and the item count is in rax
	mov	r9, [rdi+tui_ggselectedindex_ofs]
	mov	rcx, [rcx+_list_first_ofs]
	test	r9, r9
	jz	.gotit
	test	rcx, rcx
	jz	.zeroret
calign
.enterloop:
	mov	rcx, [rcx+_list_nextofs]
	test	rcx, rcx
	jz	.zeroret
	sub	r9, 1
	jnz	.enterloop
calign
.gotit:
	test	rcx, rcx
	jz	.zeroret
	mov	rax, [rcx+_list_valueofs]	; our return
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog

end if




if used tui_gridguts$keyevent | defined include_everything
	; three arguments: rdi == tui_gridguts, esi == key, edx == esc_key
	; we return zero if we didn't handle it, 1 if we did
falign
tui_gridguts$keyevent:
	prolog_silent	tui_gridguts$keyevent
	; handle up and down arrows, enter key, and eventually searchpanel
	mov	rcx, [rdi+tui_ggdata_ofs]
	test	rcx, rcx
	jz	.zeroret
	mov	rcx, [rcx+json_contents_ofs]
	mov	rax, [rcx]
	test	rax, rax		; rax has our contents array length
	jz	.zeroret
	; otherwise, lets see what we got
	cmp	edx, 0x41		; esc key == 0x41 == up arrow
	je	.uparrow
	cmp	edx, 0x42		; esc key == 0x42 == down arrow
	je	.downarrow
	cmp	esi, 13
	je	.enter
	xor	eax, eax
	epilog
calign
.uparrow:
	mov	rax, [rdi+tui_ggselectedindex_ofs]
	test	rax, rax
	jz	.zeroret
	sub	rax, 1
	mov	[rdi+tui_ggselectedindex_ofs], rax
	mov	rcx, [rdi+tui_ggscroll_ofs]
	cmp	rax, rcx
	jge	.drawandoneret
	sub	rcx, 1
	mov	[rdi+tui_ggscroll_ofs], rcx
	jmp	.drawandoneret
calign
.downarrow:
	mov	rcx, [rdi+tui_ggselectedindex_ofs]
	add	rcx, 1
	cmp	rcx, rax
	jge	.zeroret
	mov	[rdi+tui_ggselectedindex_ofs], rcx

	mov	edx, dword [rdi+tui_height_ofs]
	sub	edx, 1				; rdx == visual row count
	mov	r8, [rdi+tui_ggscroll_ofs]	; r8 == top spot
	cmp	r8, 0
	je	.notopelipses
	sub	edx, 1
calign
.notopelipses:
	mov	r9, rax				; datarows
	sub	r9, r8				; - scroll
	cmp	rdx, r9				; visual rows < (datarows - scroll)
	jge	.nobottomelipses
	sub	edx, 1
calign
.nobottomelipses:
	mov	r10, r8
	add	r10, rdx		; r10 == bottom spot
	cmp	rcx, r10
	jl	.drawandoneret
	; else, selected index >= bottomspot, modify scroll
	test	r8, r8
	jz	.downarrow_noscrollyet
	add	r8, 1
	mov	[rdi+tui_ggscroll_ofs], r8
	jmp	.drawandoneret
calign
.downarrow_noscrollyet:
	add	r8, 1
	sub	rdx, 1
	mov	r9, rax				; datarows
	sub	r9, r8				; - scroll
	mov	r10, r8
	add	r10, 1
	cmp	rdx, r9
	cmovl	r8, r10
	mov	[rdi+tui_ggscroll_ofs], r8
	jmp	.drawandoneret
calign
.enter:
	; walk (*cough*) the contents array to get our correct item
	; the list itself is in rcx already, and the item count is in rax
	mov	r9, [rdi+tui_ggselectedindex_ofs]
	mov	rcx, [rcx+_list_first_ofs]
	test	r9, r9
	jz	.gotit
	test	rcx, rcx
	jz	.zeroret
calign
.enterloop:
	mov	rcx, [rcx+_list_nextofs]
	test	rcx, rcx
	jz	.zeroret
	sub	r9, 1
	jnz	.enterloop
calign
.gotit:
	test	rcx, rcx
	jz	.zeroret
	mov	rsi, [rcx+_list_valueofs]
	mov	rcx, [rdi+tui_ggdatagrid_ofs]	; our parent
	mov	rdx, [rcx]			; its vtable
	mov	rdi, rcx
	call	qword [rdx+tui_vitemselected]
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
calign
.drawandoneret:
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	mov	eax, 1
	epilog
end if


if used tui_gridguts$nvaddproperty_i | defined include_everything
	; five arguments: rdi == tui_gridguts object, rsi == string name, edx == integer width, ecx == text alignment, r8 == string propertyname
falign
tui_gridguts$nvaddproperty_i:
	prolog_silent	tui_gridguts$nvaddproperty_i
	sub	rsp, 48
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+8], rax
	mov	rdi, [rsp+32]
	call	string$copy
	mov	[rsp+32], rax
	mov	edi, tui_gridcol_size
	call	heap$alloc
	mov	[rsp+40], rax
	mov	rdi, rax
	xor	esi, esi
	mov	edx, tui_gridcol_size
	call	memset32
	mov	rax, [rsp+40]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	r8, [rsp+32]
	mov	[rax+tui_gridcol_name_ofs], rsi
	mov	[rax+tui_gridcol_width_ofs], rdx
	mov	[rax+tui_gridcol_align_ofs], rcx
	mov	[rax+tui_gridcol_propertyname_ofs], r8
	mov	r9, [rsp]
	mov	rdi, [r9+tui_ggcols_ofs]
	mov	rsi, rax
	call	list$push_back
	add	rsp, 48
	epilog
end if

if used tui_gridguts$nvaddproperty_d | defined include_everything
	; five arguments: rdi == tui_gridguts object, rsi == string name, xmm0 == double widthperc, edx == text alignment, rcx == string propertyname
falign
tui_gridguts$nvaddproperty_d:
	prolog_silent	tui_gridguts$nvaddproperty_d
	sub	rsp, 48
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	movq	r10, xmm0
	mov	[rsp+16], r10
	mov	[rsp+24], rdx
	mov	[rsp+32], rcx
	mov	rdi, rsi
	call	string$copy
	mov	[rsp+8], rax
	mov	rdi, [rsp+32]
	call	string$copy
	mov	[rsp+32], rax
	mov	edi, tui_gridcol_size
	call	heap$alloc
	mov	[rsp+40], rax
	mov	rdi, rax
	xor	esi, esi
	mov	edx, tui_gridcol_size
	call	memset32
	mov	rax, [rsp+40]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	r8, [rsp+32]
	mov	[rax+tui_gridcol_name_ofs], rsi
	mov	[rax+tui_gridcol_widthperc_ofs], rdx
	mov	[rax+tui_gridcol_align_ofs], rcx
	mov	[rax+tui_gridcol_propertyname_ofs], r8
	mov	r9, [rsp]
	mov	rdi, [r9+tui_ggcols_ofs]
	mov	rsi, rax
	call	list$push_back
	add	rsp, 48
	epilog
end if

if used tui_gridguts$nvcleardata_nodraw | defined include_everything
	; single argument: rdi == tui_gridguts object
	; if we own the data, destroy it, otherwise, just clear it
falign
tui_gridguts$nvcleardata_nodraw:
	prolog	tui_gridguts$nvcleardata_nodraw
	mov	rdx, [rdi+tui_ggdata_ofs]
	test	rdx, rdx
	jz	.nothingtodo
	xor	ecx, ecx
	mov	[rdi+tui_ggdata_ofs], rcx
	mov	r8, [rdi+tui_ggdataowner_ofs]
	mov	[rdi+tui_ggdataowner_ofs], rcx
	mov	[rdi+tui_ggrowcount_ofs], rcx	; clear the rowcount
	test	r8, r8
	jz	.nothingtodo
	mov	rdi, rdx
	call	json$destroy
	epilog
calign
.nothingtodo:
	epilog
end if

if used tui_gridguts$nvsetdata_notowner | defined include_everything
	; two arguments: rdi == tui_gridguts object, rsi == json array object (we do _NOT_ assume ownership of this set)
falign
tui_gridguts$nvsetdata_notowner:
	prolog	tui_gridguts$nvsetdata_notowner
	push	rdi rsi
	call	tui_gridguts$nvsetdata
	pop	rsi rdi
	mov	rdx, [rsi+json_contents_ofs]
	mov	rcx, [rdx]
	mov	qword [rdi+tui_ggdataowner_ofs], 0
	mov	qword [rdi+tui_ggrowcount_ofs], rcx
	epilog
end if

if used tui_gridguts$nvsetdata | defined include_everything
	; two arguments: rdi == tui_gridguts object, rsi == json array object (we assume ownership of this set, it _must_ be a json_array of json objects!)
falign
tui_gridguts$nvsetdata:
	prolog	tui_gridguts$nvsetdata
	mov	r8, [rdi+tui_ggrowcount_ofs]	; old row count
	push	rdi rsi r8
	call	tui_gridguts$nvcleardata_nodraw
	pop	r8 rsi rdi
calign
.no_old_rows:
	mov	[rdi+tui_ggdata_ofs], rsi
	mov	qword [rdi+tui_ggdataowner_ofs], 1
	; verify that selected index isn't past the end of our new data set
	mov	rcx, [rsi+json_contents_ofs]
	mov	r9, [rcx]			; data rows
	mov	[rdi+tui_ggrowcount_ofs], r9
	cmp	qword [rdi+tui_ggselectedindex_ofs], r9
	jb	.selectedindexokay
	mov	r10, r9
	sub	r10, 1
	test	r9, r9
	cmovnz	r9, r10
	mov	[rdi+tui_ggselectedindex_ofs], r9	; selected index = data rows - 1 (provided data rows > 0)
	mov	r9, [rcx]			; data rows back into r9
calign
.selectedindexokay:
	cmp	qword [rdi+tui_ggscroll_ofs], 0
	je	.noscrolladjust
	; cmp	r9, r8				; data rows >= old row count ?
	; jae	.noscrolladjust			; we dont have to manipulate scroll if we were already at the top or our rowcount grew
	; so if we made it here, then our rowcount _shrunk_ and we need to potentially modify our scroll area as well
	mov	ecx, dword [rdi+tui_height_ofs]
	cmp	ecx, 2				; visual rows == height - 1, less one for scroll >0
	jbe	.noheight
	; in order for us to have gotten here, scroll must be nonzero, which means we have a top elipses
	; and thus visual rows in ecx must be reduced again by one
	sub	ecx, 2				; visual rows.
	; if our visual rows is less than data rows - scroll position, and visual rows is still >0, subtract another one from it
	mov	edx, ecx
	sub	edx, 1
	mov	r8, [rdi+tui_ggscroll_ofs]	; top spot
	mov	r10, r9
	sub	r10, r8
	cmp	rcx, r10
	cmovb	rcx, rdx
	mov	r10, rcx
	add	r10, r8				; bottom spot
	sub	r10, 1

	cmp	r9, rcx				; data rows <= visual rows?
	jbe	.noheight			; if so, clear the scroll, draw and bailout

	; next up: figure out what our maximum scroll value can be, which is datarows - visualrows
	mov	r11, r9
	sub	r11, rcx			; r11 now has maxscroll
	cmp	r8, r11
	ja	.recalcwindow

calign
.windowokay:
	mov	r11, [rdi+tui_ggselectedindex_ofs]
	cmp	r11, r8
	jb	.selup
	cmp	r11, r10
	ja	.seldown
	; else, just draw and return
	mov	rsi, [rdi]			; our vtable
	call	qword [rsi+tui_vdraw]
	epilog
calign
.selup:
	mov	[rdi+tui_ggscroll_ofs], r11	; scroll set to selected index
	mov	rsi, [rdi]			; our vtable
	call	qword [rsi+tui_vdraw]
	epilog
calign
.seldown:
	; hmmm, this is still Not Quite Right. TODO: fix me properly
	sub	r11, r10			; selected index - bottom spot
	add	qword [rdi+tui_ggscroll_ofs], r11
	mov	rsi, [rdi]			; our vtable
	call	qword [rsi+tui_vdraw]
	epilog
calign
.noheight:
	; if height was zero, clear our scroll entirely
	mov	qword [rdi+tui_ggscroll_ofs], 0
	mov	rsi, [rdi]			; our vtable
	call	qword [rsi+tui_vdraw]		; this may still draw elipses... hmm
	epilog
calign
.noscrolladjust:
	mov	rsi, [rdi]			; our vtable
	call	qword [rsi+tui_vdraw]
	epilog
calign
.recalcwindow:
	mov	r8, r11
	mov	[rdi+tui_ggscroll_ofs], r8		; save it
	mov	r10, r9
	sub	r10, r8
	cmp	rcx, r10
	cmovb	rcx, rdx
	mov	r10, rcx
	add	r10, r8
	sub	r10, 1				; bottom spot
	jmp	.windowokay

	
end if
