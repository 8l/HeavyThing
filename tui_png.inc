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
	; tui_png.inc: hahah, displaying block-character png files
	; not particularly useful, but amusing anyway
	;

	;
	; NOTE: CAUTION: ETC: haha, the png object passed to the new
	; functions here does -not- make a copy of it, so the source
	; png object must survive for as long as this object does
	;

if used tui_png$vtable | defined include_everything

dalign
tui_png$vtable:
	dq      tui_png$cleanup, tui_png$clone, tui_png$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

tui_png_image_ofs = tui_object_size
tui_png_buffer_ofs = tui_object_size + 8
tui_png_width_ofs = tui_object_size + 16
tui_png_height_ofs = tui_object_size + 24
tui_png_bgcolor_ofs = tui_object_size + 32		; defaults to 0xe8 (black)
tui_png_user_ofs = tui_object_size + 40

tui_png_size = tui_object_size + 48

end if


if used tui_png$new_rect | defined include_everything
	; two arguments: rdi == pointer to bounds rect, rsi == pointer to png object
falign
tui_png$new_rect:
	prolog	tui_png$new_rect
	push	rdi rsi
	mov	edi, tui_png_size
	call	heap$alloc
	mov	rsi, [rsp+8]
	mov	[rsp+8], rax
	mov	rdi, rax
	call	tui_object$init_rect
	pop	rsi rax
	mov	qword [rax], tui_png$vtable
	mov	[rax+tui_png_image_ofs], rsi
	mov	qword [rax+tui_png_buffer_ofs], 0
	mov	qword [rax+tui_png_width_ofs], 0
	mov	qword [rax+tui_png_height_ofs], 0
	mov	qword [rax+tui_png_bgcolor_ofs], 0xe8
	epilog

end if

if used tui_png$new_dd | defined include_everything
	; three arguments: xmm0 == widthperc, xmm1 == heightperc, rdi == pointer to png object
falign
tui_png$new_dd:
	prolog	tui_png$new_dd
	; we cheat here: heap$alloc does not modify xmm0/xmm1
	push	rdi
	mov	edi, tui_png_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	call	tui_object$init_dd
	pop	rax rsi
	mov	qword [rax], tui_png$vtable
	mov	[rax+tui_png_image_ofs], rsi
	mov	qword [rax+tui_png_buffer_ofs], 0
	mov	qword [rax+tui_png_width_ofs], 0
	mov	qword [rax+tui_png_height_ofs], 0
	mov	qword [rax+tui_png_bgcolor_ofs], 0xe8
	epilog

end if

if used tui_png$new_id | defined include_everything
	; three arguments: edi == width, xmm0 == heightperc, rsi == pointer to png object
falign
tui_png$new_id:
	prolog	tui_png$new_id
	; we cheat here: heap$alloc does not modify xmm0/xmm1
	push	rdi rsi
	mov	edi, tui_png_size
	call	heap$alloc
	mov	esi, [rsp+8]
	mov	rdi, rax
	mov	[rsp+8], rax
	call	tui_object$init_id
	pop	rsi rax
	mov	qword [rax], tui_png$vtable
	mov	[rax+tui_png_image_ofs], rsi
	mov	qword [rax+tui_png_buffer_ofs], 0
	mov	qword [rax+tui_png_width_ofs], 0
	mov	qword [rax+tui_png_height_ofs], 0
	mov	qword [rax+tui_png_bgcolor_ofs], 0xe8
	epilog

end if

if used tui_png$new_di | defined include_everything
	; three arguments: xmm0 == widthperc, edi == height, rsi == pointer to png object
falign
tui_png$new_di:
	prolog	tui_png$new_di
	push	rdi rsi
	mov	edi, tui_png_size
	call	heap$alloc
	mov	esi, [rsp+8]
	mov	rdi, rax
	mov	[rsp+8], rax
	call	tui_object$init_di
	pop	rsi rax
	mov	qword [rax], tui_png$vtable
	mov	[rax+tui_png_image_ofs], rsi
	mov	qword [rax+tui_png_buffer_ofs], 0
	mov	qword [rax+tui_png_width_ofs], 0
	mov	qword [rax+tui_png_height_ofs], 0
	mov	qword [rax+tui_png_bgcolor_ofs], 0xe8
	epilog

end if

if used tui_png$new_ii | defined include_everything
	; three arguments: edi == width, esi == height, rdx == pointer to png object
falign
tui_png$new_ii:
	prolog	tui_png$new_ii
	push	rdi rsi rdx
	mov	edi, tui_png_size
	mov	esi, [rsp+16]
	mov	edx, [rsp+8]
	mov	rdi, rax
	mov	[rsp+8], rax
	call	tui_object$init_ii
	pop	rsi rax rdx
	mov	qword [rax], tui_png$vtable
	mov	[rax+tui_png_image_ofs], rsi
	mov	qword [rax+tui_png_buffer_ofs], 0
	mov	qword [rax+tui_png_width_ofs], 0
	mov	qword [rax+tui_png_height_ofs], 0
	mov	qword [rax+tui_png_bgcolor_ofs], 0xe8
	epilog

end if

if used tui_png$clone | defined include_everything
	; single argument in rdi: our tui_png object
falign
tui_png$clone:
	prolog	tui_png$clone
	push	rdi
	mov	edi, tui_png_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	mov	rsi, [rsp+8]
	call	tui_object$init_copy
	pop	rax rsi
	mov	rdx, [rsi+tui_png_image_ofs]
	mov	rcx, [rsi+tui_png_bgcolor_ofs]
	mov	[rax+tui_png_image_ofs], rsi
	mov	qword [rax+tui_png_buffer_ofs], 0
	mov	qword [rax+tui_png_width_ofs], 0
	mov	qword [rax+tui_png_height_ofs], 0
	mov	[rax+tui_png_bgcolor_ofs], rcx
	epilog

end if

if used tui_png$cleanup | defined include_everything
	; single argument in rdi: our tui_png object
falign
tui_png$cleanup:
	prolog	tui_png$cleanup
	push	rdi
	mov	rdi, [rdi+tui_png_buffer_ofs]
	test	rdi, rdi
	jz	.nobuffer
	call	heap$free
calign
.nobuffer:
	pop	rdi
	call	tui_object$cleanup
	epilog

end if

if used tui_png$draw | defined include_everything
	; single argument in rdi: our tui_png object
falign
tui_png$draw:
	prolog	tui_png$draw
	cmp	dword [rdi+tui_width_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_height_ofs], 0
	je	.nothingtodo
	mov	eax, [rdi+tui_png_width_ofs]
	mov	ecx, [rdi+tui_png_height_ofs]
	cmp	eax, [rdi+tui_width_ofs]
	jne	.newbuffer
	cmp	ecx, [rdi+tui_height_ofs]
	jne	.newbuffer
	cmp	qword [rdi+tui_png_buffer_ofs], 0
	je	.newbuffer
calign
.copyit:
	; otherwise, we have a buffer, its width is the same as ours before
	mul	ecx
	shl	eax, 2
	mov	edx, eax
	push	rdi
	mov	rdi, [rdi+tui_text_ofs]
	mov	esi, ' '
	push	rdx
	call	memset32
	pop	rdx rdi
	mov	rsi, [rdi+tui_png_buffer_ofs]
	mov	rdi, [rdi+tui_attr_ofs]
	call	memcpy
	epilog
calign
.newbuffer:
	; we horrifically downscale the source png to get the job done, maintaining aspect ratio
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	eax, [rdi+tui_width_ofs]
	mov	ecx, [rdi+tui_height_ofs]
	mov	[rdi+tui_png_width_ofs], eax
	mov	[rdi+tui_png_height_ofs], ecx
	mul	ecx
	shl	eax, 2
	mov	edi, eax
	call	heap$alloc_clear
	mov	[rbx+tui_png_buffer_ofs], rax

	; our attribute buffer gets memset32'd with our bgcolor
	mov	rdi, rax
	mov	esi, [rbx+tui_png_bgcolor_ofs]
	
	mov	eax, [rbx+tui_png_width_ofs]
	mov	ecx, [rbx+tui_png_height_ofs]
	mul	ecx
	shl	eax, 2
	mov	edx, eax
	call	memset32


	; next up: figure out our ratios
	mov	rdi, [rbx+tui_png_image_ofs]
	mov	eax, [rdi+png_width_ofs]
	mov	ecx, [rdi+png_height_ofs]
	mov	esi, [rbx+tui_png_width_ofs]
	mov	edx, [rbx+tui_png_height_ofs]
	cvtsi2sd xmm0, eax			; png width
	cvtsi2sd xmm1, ecx			; png height
	mulsd	xmm0, [_math_two]
	cvtsi2sd xmm2, esi			; our tui width in characters
	cvtsi2sd xmm3, edx			; our tui height in characters
	movsd	xmm4, xmm0
	divsd	xmm4, xmm1			; png aspect ratio, 1.0
	movsd	xmm5, xmm2
	divsd	xmm5, xmm3			; tui aspect ratio, 3.4262
	; set our new actual dimensions into xmm2 and xmm3
	ucomisd xmm5, xmm4
	ja	.rowfit
	; otherwise, colfit
	movsd	xmm3, xmm2
	divsd	xmm3, xmm4
	addsd	xmm3, [.half]
	jmp	.dimsready
dalign
.half	dq	0.5f
calign
.rowfit:
	movsd	xmm2, xmm3
	mulsd	xmm2, xmm4
	addsd	xmm2, [.half]
calign
.dimsready:
	; so now we have our aspect-ratio preserved new dimensions
	; convert those back into integer format temporarily so we can determine our off
	cvtsd2si r12d, xmm2			; our aspect-maintained new width (in characters)
	cvtsd2si r13d, xmm3			; our aspect-maintained new height (in characters)

	; in order for our image to remain centered, we need to calculate half of the difference between each and our actual tui object width
	sub	esi, r12d
	sub	edx, r13d
	shr	esi, 1
	shr	edx, 1
	mov	r14d, esi			; our x-modifier to center the goods
	mov	r15d, edx			; our y-modifier to center the goods

	shl	r14d, 2				; in bytes

	; next up, we need our actual ratio between the image and our text now that our new size is figured out
	movsd	xmm4, xmm0
	divsd	xmm4, xmm2			; our real width ratio, which should be considerably >0
	mulsd	xmm4, [.half]
	movsd	xmm5, xmm1
	divsd	xmm5, xmm3			; our real height ratio, which should be considerably >0

	; we need to know how many source pixels we need to gather in both directions for each output pixel
	cvtsd2si r10d, xmm4			; x gather
	cvtsd2si r11d, xmm5			; y gather

	; free up some registers
	sub	rsp, 48
	mov	[rsp], r12d			; new "real" width (not our tui width)
	mov	[rsp+4], r13d			; new "real" height (not our tui height)
	mov	[rsp+8], eax			; actual png width
	mov	[rsp+12], ecx			; actual png height
	mov	[rsp+16], r14d			; our x-modifier to center our real image in our tui buffer (in bytes)
	mov	[rsp+20], r15d			; our y-modifier to center our real image in our tui buffer in characters
	mov	[rsp+24], r10d			; source image x gather
	mov	[rsp+28], r11d			; source image y gather
	shl	eax, 2
	mov	[rsp+32], eax			; actual png width in bytes
	mov	eax, [rbx+tui_png_width_ofs]
	shl	eax, 2
	mov	[rsp+36], eax			; actual tui width in bytes

	; prepare the floating point color conversion
	mov	rax, 42.6666666666667f
	movq	xmm7, rax
	mov	rax, 36.0f
	movq	xmm8, rax
	mov	rax, 6.0f
	movq	xmm12, rax
	
	; ok so, now, we have to walk through each row in our tui image, gather up and average all of the rgb values in the source
	mov	rsi, [rdi+png_data_ofs]
	; we will use r15d as our "current line" for the rowloop
	xor	r14d, r14d			; our source row number
	xorpd	xmm1, xmm1			; our source row in floating point
	mov	[rsp+40], rsi			; save our source image data starting pointer
calign
.rowloop:
	xorpd	xmm0, xmm0			; our source column in floating point
	xor	r13d, r13d			; our source column number
	mov	rdi, [rbx+tui_png_buffer_ofs]
	mov	eax, r15d
	mul	dword [rsp+36]
	add	eax, dword [rsp+16]
	add	rdi, rax
	; rdi is now pointing at the "right" spot in the output
	mov	r12d, [rsp]
calign
.colloop:
	; gather x-gather * y-gather rgb values from the source, average them, recombine, put in the spot at rdi
	; first, calculate the spot in our image
	mov	rsi, [rsp+40]
	mov	eax, [rsp+8]
	mul	r14d				; source row number * actual png width
	add	eax, r13d			; add with source column number
	shl	eax, 2				; in bytes
	add	rsi, rax
	; now, for (..ygather), (..xgather), grab and average our values
	mov	ecx, [rsp+28]
	mov	eax, [rsp+12]			; actual png height
	sub	eax, r14d			; less the row we started on
	; if ecx is > this, chop it
	cmp	ecx, eax
	cmova	ecx, eax

	xor	r8d, r8d			; raccum
	xor	r9d, r9d			; gaccum
	xor	r10d, r10d			; baccum
	xor	r11d, r11d			; counter, though we could just multiply xgather and ygather
calign
.ygather:
	mov	edx, [rsp+24]			; xgather
	push	rsi				; save our source spot so we don't have to do the math again
calign
.xgather:
	movzx	eax, byte [rsi]
	add	r8d, eax
	movzx	eax, byte [rsi+1]
	add	r9d, eax
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, 1
	add	rsi, 4
	sub	edx, 1
	jnz	.xgather
	pop	rsi
	mov	eax, [rsp+32]
	add	rsi, rax
	sub	ecx, 1
	jnz	.ygather

	xor	edx, edx
	mov	eax, r8d
	div	r11d
	mov	r8d, eax
	xor	edx, edx
	mov	eax, r9d
	div	r11d
	mov	r9d, eax
	xor	edx, edx
	mov	eax, r10d
	div	r11d
	mov	r10d, eax

	; copy the lower 2 bits
	and	r8d, not 3
	and	r9d, not 3
	and	r10d, not 3
	; so now we have our gathered and averaged rgb values in r8d, r9d, r10d

	; In 256 color mode (ESC[38;5;<fgcode>m and ESC[48;5;<bgcode>m), the color-codes are the following:[citation needed]

 	; 0x00-0x07:  standard colors (as in ESC [ 30..37 m)
 	; 0x08-0x0F:  high intensity colors (as in ESC [ 90..97 m)
 	; 0x10-0xE7:  6*6*6=216 colors: 16 + 36*r + 6*g + b (0≤r,g,b≤5)
 	; 0xE8-0xFF:  grayscale from black to white in 24 steps
	; we need to determine whether they are the same or not, so that we can map them to black...gray 0..15
	cmp	r8d, r9d
	jne	.colored
	cmp	r9d, r10d
	jne	.colored

	; otherwise, we have the same values in all
	mov	eax, r8d
	mov	r9d, 11
	xor	edx, edx
	div	r9d
	add	eax, 0xe8
	and	eax, 0xff
	mov	[rdi], eax
	add	rdi, 4
	; keep going
	addsd	xmm0, xmm4
	cvtsd2si r13d, xmm0
	; add	r13d, [rsp+24]			; increment source column position by xgather
	sub	r12d, 1
	jnz	.colloop
	addsd	xmm1, xmm5
	cvtsd2si r14d, xmm1
	; add	r14d, [rsp+28]			; y gather
	add	r15d, 1
	sub	dword [rsp+4], 1
	jnz	.rowloop
	; all done
	add	rsp, 48
	mov	rdi, rbx
	pop	r15 r14 r13 r12 rbx
	mov	eax, [rdi+tui_png_width_ofs]
	mov	ecx, [rdi+tui_png_height_ofs]
	jmp	.copyit

calign
.colored:
	; we have to divide all of them by 43, r gets multiplied by 36, g gets multiplied by 6
 	; 0x10-0xE7:  6*6*6=216 colors: 16 + 36*r + 6*g + b (0≤r,g,b≤5)
	cvtsi2sd xmm9, r8d
	cvtsi2sd xmm10, r9d
	cvtsi2sd xmm11, r10d
	divsd	xmm9, xmm7
	divsd	xmm10, xmm7
	divsd	xmm11, xmm7
	cvtsd2si r8d, xmm9
	cvtsd2si r9d, xmm10
	cvtsd2si r10d, xmm11
	mov	ecx, 36
	mov	eax, 5
	cmp	r8d, 5
	cmova	r8d, eax
	cmp	r9d, 5
	cmova	r9d, eax
	cmp	r10d, 5
	cmova	r10d, eax
	mov	eax, r8d
	mul	ecx
	mov	r8d, eax
	mov	ecx, 6
	mov	eax, r9d
	mul	ecx
	mov	r9d, eax

	mov	eax, r8d
	add	eax, r9d
	add	eax, r10d
	add	eax, 16
	
	; and	eax, 0xff			; sanity only
	mov	[rdi], eax
	add	rdi, 4
	; keep going
	addsd	xmm0, xmm4
	cvtsd2si r13d, xmm0
	; add	r13d, [rsp+24]			; increment source column position by xgather
	sub	r12d, 1
	jnz	.colloop
	addsd	xmm1, xmm5
	cvtsd2si r14d, xmm1
	; add	r14d, [rsp+28]			; y gather
	add	r15d, 1
	sub	dword [rsp+4], 1
	jnz	.rowloop
	; all done
	add	rsp, 48
	mov	rdi, rbx
	pop	r15 r14 r13 r12 rbx
	mov	eax, [rdi+tui_png_width_ofs]
	mov	ecx, [rdi+tui_png_height_ofs]
	jmp	.copyit
calign
.nothingtodo:
	epilog

end if
