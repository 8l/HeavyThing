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
	; png.inc: a simple png decoder
	; minimalist insofar as I didn't bother with every tidbit
	; but does what I want :)
	; mainly, no PLTE/indexed color support, seems none of the pngs i have use them anyway
	; and I am feeling lazy today... we ignore everything but IDAT/IEND
	; we decompress/decode the image into a consecutive block of RGBA 32bit values
	;

if used png$new | defined include_everything

; we hang on to the IHDR fields here, even though all we really need post-parse
; is the width, height and data
png_width_ofs = 0
png_height_ofs = 4
png_bitdepth_ofs = 8
png_colortype_ofs = 12
png_linelength_ofs = 16
png_rowlength_ofs = 20
png_pixdepth_ofs = 24
png_channels_ofs = 28
png_data_ofs = 32

png_size = 40

	; two arguments: rdi == pointer to png encoded data, rsi == length of same
	; returns a new png object in rax, or null if we encountered some unrecognized/erroneous goods
falign
png$new:
	prolog	png$new
	; make sure its with a png header, and that the length is sane
	mov	rax, 0xa1a0a0d474e5089
	cmp	rsi, 41
	jb	.invalid
	cmp	[rdi], rax
	jne	.invalid
	; first chunk must be an IHDR, or die
	cmp	dword [rdi+12], 'IHDR'
	jne	.invalid
	push	rbx r12 r13 r14 r15
	mov	r13, rsi
	lea	r12, [rdi+8]
	sub	rsp, zlib_stream_size
	mov	rdi, rsp
	mov	esi, 1
	call	zlib$inflateInit
	call	buffer$new
	mov	[rsp+zlib_inbuf_ofs], rax
	call	buffer$new
	mov	[rsp+zlib_outbuf_ofs], rax
	mov	edi, png_size
	call	heap$alloc_clear
	mov	rbx, rax
	sub	r13, 16
if use_movbe
	movbe	ecx, [r12]		; length of the header chunk
else
	mov	ecx, [r12]		; length of the header chunk
	bswap	ecx
end if
	add	r12, 8
	cmp	rcx, r13
	jae	.bad
	cmp	ecx, 13
	jne	.bad
if use_movbe
	movbe	eax, dword [r12]
	movbe	ecx, dword [r12+4]
else
	mov	eax, dword [r12]
	mov	ecx, dword [r12+4]
	bswap	eax
	bswap	ecx
end if
	; make sure these are semi-sane before we proceed
	cmp	eax, 65536
	jae	.bad
	cmp	ecx, 65536
	jae	.bad
	test	eax, eax
	jz	.bad
	test	ecx, ecx
	jz	.bad
	mov	r9d, eax
	shl	r9d, 2				; scan line length in bytes
	mov	[rbx+png_linelength_ofs], r9
	; check the compression field
	cmp	byte [r12+10], 0
	jne	.bad
	movzx	edx, byte [r12+8]		; bit depth
	cmp	edx, 16
	ja	.bad
	cmp	edx, 8
	jb	.bad
	mov	dword [rbx+png_bitdepth_ofs], edx
	movzx	r8d, byte [r12+9]		; color type
	cmp	r8d, 6
	ja	.bad
	mov	dword [rbx+png_colortype_ofs], r8d
	mov	[rbx+png_width_ofs], eax
	mov	[rbx+png_height_ofs], ecx
	mul	ecx
	shl	eax, 2
	mov	edi, eax

	mov	eax, [rbx+png_bitdepth_ofs]
	lea	r9d, [eax+eax]
	lea	r10d, [eax*2+eax]
	lea	r11d, [eax*4]
	cmp	r8d, 2				; rgb == 3 channels
	cmove	eax, r10d
	cmp	r8d, 4				; gray alpha == 2 channels
	cmove	eax, r9d
	cmp	r8d, 6				; rgb alpha == 4 channels
	cmove	eax, r11d

	mov	[rbx+png_pixdepth_ofs], eax
	
	mov	ecx, eax
	add	ecx, 7
	cmp	eax, 8
	cmovb	eax, ecx
	mul	dword [rbx+png_width_ofs]
	shr	eax, 3
	mov	[rbx+png_rowlength_ofs], eax

	mov	eax, 1
	mov	r9d, 2
	mov	r10d, 3
	mov	r11d, 4
	cmp	r8d, 2
	cmove	eax, r10d
	cmp	r8d, 4
	cmove	eax, r9d
	cmp	r8d, 6
	cmove	eax, r11d
	mov	[rbx+png_channels_ofs], eax

	call	heap$alloc
	mov	[rbx+png_data_ofs], rax
	mov	r14, rax
	; 13 + 4 bytes for the crc to skip
	add	r12, 17
	sub	r13, 17
	; commence IDAT/IEND scanning
calign
.chunkscan:
	cmp	r13, 12
	jb	.bad
if use_movbe
	movbe	eax, dword [r12]
else
	mov	eax, dword [r12]
	bswap	eax
end if
	add	eax, 12
	cmp	rax, r13
	ja	.bad
	cmp	dword [r12+4], 'IDAT'
	je	.idat
	cmp	dword [r12+4], 'IEND'
	je	.iend
	cmp	dword [r12+4], 'PLTE'
	je	.bad
	; otherwise, skip and keep going
	add	r12, rax
	sub	r13, rax
	jz	.bad
	jmp	.chunkscan
calign
.idat:
	; save our length
	mov	r15, rax
	mov	rdi, [rsp+zlib_inbuf_ofs]
	call	buffer$reset
	mov	rdx, r15
	mov	rdi, [rsp+zlib_inbuf_ofs]
	lea	rsi, [r12+8]
	sub	rdx, 12
	test	rdx, rdx
	jz	.emptychunk
	call	buffer$append
	mov	rdi, rsp
	call	zlib$inflate
	;test	eax, eax
	;jz	.bad
	add	r12, r15
	sub	r13, r15
	jz	.bad
	jmp	.chunkscan
calign
.emptychunk:
	add	r12, r15
	sub	r13, r15
	jz	.bad
	jmp	.chunkscan
calign
.iend:
	; parse the outbuf, we are all done with r12, r13, r15
	; the length of the bytes sitting in outbuf should be: height * (rowlength + 1)
	mov	eax, [rbx+png_rowlength_ofs]
	add	eax, 1
	mov	r8d, eax
	mul	dword [rbx+png_height_ofs]
	mov	rdi, [rsp+zlib_outbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	r13, rsi			; save the start of the buffer
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, rax
	jne	.bad				; we gotta have the right amount of data
	; the first row _must_ be filter type none, or sub
	cmp	byte [rsi], 1
	ja	.bad
	; otherwise, we can commence row defiltering
	mov	rdi, rsi
	sub	rdi, r8				; keep a pointer precisely one row behind us
	sub	r8d, 1
	mov	r9d, [rbx+png_height_ofs]
calign
.defilter_rows:
	movzx	eax, byte [rsi]
	add	rsi, 1
	add	rdi, 1
	cmp	eax, 4
	ja	.bad
	jmp	qword [rax*8+.defilter_dispatch]
dalign
.defilter_dispatch:
	dq	.defilter_none, .defilter_sub, .defilter_up, .defilter_average, .defilter_paeth
calign
.defilter_none:
	; we are not modifying this row, skip it
	add	rdi, r8
	add	rsi, r8

	sub	r9d, 1
	jnz	.defilter_rows
	jmp	.defilter_complete
calign
.defilter_sub:
	mov	ecx, r8d
	mov	r15d, [rbx+png_pixdepth_ofs]
	; we don't look at our previous row, so increment it first up
	add	rdi, r8
	add	r15d, 7
	shr	r15d, 3			; bpp
	sub	ecx, r15d
	mov	r11, rsi
	add	r11, r15
calign
.defilter_subloop:
	movzx	eax, byte [rsi]
	add	byte [r11], al
	add	r11, 1
	add	rsi, 1
	sub	ecx, 1
	jnz	.defilter_subloop
	add	rsi, r15

	sub	r9d, 1
	jnz	.defilter_rows
	jmp	.defilter_complete
calign
.defilter_up:
	mov	ecx, r8d
calign
.defilter_uploop:
	movzx	eax, byte [rdi]
	add	byte [rsi], al
	add	rdi, 1
	add	rsi, 1
	sub	ecx, 1
	jnz	.defilter_uploop

	sub	r9d, 1
	jnz	.defilter_rows
	jmp	.defilter_complete
calign
.defilter_average:
	mov	ecx, r8d
	mov	r15d, [rbx+png_pixdepth_ofs]
	add	r15d, 7
	shr	r15d, 3			; bpp
	sub	ecx, r15d
	mov	r11d, r15d
calign
.defilter_average_firstbit:
	movzx	eax, byte [rsi]
	movzx	edx, byte [rdi]
	add	eax, edx
	shr	eax, 1
	mov	byte [rsi], al
	add	rsi, 1
	add	rdi, 1
	sub	r11d, 1
	jnz	.defilter_average_firstbit
	mov	r12, rsi
	sub	r12, r15
calign
.defilter_average_secondbit:
	movzx	eax, byte [rsi]
	movzx	edx, byte [rdi]
	movzx	r10d, byte [r12]
	add	edx, r10d
	shr	edx, 1
	add	eax, edx
	mov	byte [rsi], al
	add	rsi, 1
	add	rdi, 1
	add	r12, 1
	sub	ecx, 1
	jnz	.defilter_average_secondbit

	sub	r9d, 1
	jnz	.defilter_rows
	jmp	.defilter_complete
calign
.defilter_paeth_mb:
	; multiple byte version of paeth:
	movzx	r10d, byte [rsi]
	movzx	eax, byte [rdi]
	add	r10d, eax
	mov	byte [rsi], r10b
	add	rsi, 1
	add	rdi, 1
	sub	ecx, 1
	jnz	.defilter_paeth_mb
	mov	ecx, r8d
	sub	ecx, r15d
	push	rbx
	mov	ebx, r15d
	sub	rsp, 8
	neg	rbx
calign
.defilter_paeth_mbloop:
	movzx	r12d, byte [rdi+rbx]
	movzx	r10d, byte [rsi+rbx]
	movzx	r11d, byte [rdi]
	add	rdi, 1
	; r10d == A, r11d == B, r12d == C
	; edx == pa
	; r15d == pb
	; [rsp] == pc
	; [rsp+4] == p

	mov	eax, r11d
	sub	eax, r12d
	mov	[rsp+4], eax
	
	mov	edx, eax
	neg	edx
	cmovl	edx, eax

	mov	eax, r10d
	sub	eax, r12d
	mov	[rsp], eax

	mov	r15d, eax
	neg	r15d
	cmovl	r15d, eax

	add	eax, [rsp+4]
	push	rcx
	mov	ecx, eax
	neg	eax
	cmovl	eax, ecx
	pop	rcx
	mov	[rsp], eax

	movzx	eax, byte [rsi]

	cmp	r15d, edx
	cmovl	edx, r15d
	cmovl	r10d, r11d
	cmp	dword [rsp], edx
	cmovl	r10d, r12d

	add	r10d, eax
	mov	byte [rsi], r10b
	add	rsi, 1
	
	sub	ecx, 1
	jnz	.defilter_paeth_mbloop

	add	rsp, 8
	pop	rbx
	
	sub	r9d, 1
	jnz	.defilter_rows
	jmp	.defilter_complete
	
calign
.defilter_paeth:
	mov	r15d, [rbx+png_pixdepth_ofs]
	add	r15d, 7
	shr	r15d, 3
	mov	ecx, r15d
	cmp	r15d, 1
	jne	.defilter_paeth_mb
	mov	ecx, r8d
	movzx	r12d, byte [rdi]
	add	rdi, 1
	movzx	r10d, byte [rsi]
	add	r10d, r12d
	mov	byte [rsi], r10b
	add	rsi, 1
	sub	ecx, 1
	sub	rsp, 8
calign
.defilter_paeth_loop:
	and	r10d, 0xff
	movzx	r11d, byte [rdi]
	add	rdi, 1
	; r10d == A, r11d == B, r12d == C
	; edx == pa
	; r15d == pb
	; [rsp] == pc
	; [rsp+4] == p
	mov	eax, r11d
	sub	eax, r12d
	mov	[rsp+4], eax
	
	mov	edx, eax
	neg	edx
	cmovl	edx, eax

	mov	eax, r10d
	sub	eax, r12d
	mov	[rsp], eax

	mov	r15d, eax
	neg	r15d
	cmovl	r15d, eax

	add	eax, [rsp+4]
	push	rcx
	mov	ecx, eax
	neg	eax
	cmovl	eax, ecx
	pop	rcx
	mov	[rsp], eax

	movzx	eax, byte [rsi]

	cmp	r15d, edx
	cmovl	edx, r15d
	cmovl	r10d, r11d
	cmp	dword [rsp], edx
	cmovl	r10d, r12d

	mov	r12d, r11d
	add	r10d, eax
	mov	byte [rsi], r10b
	add	rsi, 1
	
	sub	ecx, 1
	jnz	.defilter_paeth_loop

	add	rsp, 8
	
	sub	r9d, 1
	jnz	.defilter_rows
	jmp	.defilter_complete
calign
.defilter_complete:
	; now that our defilter is done, we can actually parse the image data
	; restore rsi back to the beginning
	mov	rdi, [rsp+zlib_outbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	edx, [rbx+png_channels_ofs]
	mov	r8d, [rbx+png_rowlength_ofs]
	mov	r9d, [rbx+png_height_ofs]
	mov	r10d, [rbx+png_pixdepth_ofs]
	mov	r11d, 0xff000000
	jmp	qword [rdx*8+.channels_dispatch]
dalign
.channels_dispatch:
	dq	.bad, .onechannel, .twochannels, .threechannels, .fourchannels
calign
.onechannel:
	; bitdepth is either 8 or 16, x 1 in pixdepth
	cmp	r10d, 16
	je	.onechannel_16bit_rows
	; otherwise, grayscale, 8 bit, no alpha
calign
.onechannel_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.onechannel_cols:
	movzx	eax, byte [rsi]
	add	rsi, 1
	imul	eax, 0x010101
	or	eax, r11d		; alpha == 0xff == opaque, default
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 1
	jnz	.onechannel_cols
	sub	r9d, 1
	jnz	.onechannel_rows
	jmp	.allgood
calign
.onechannel_16bit_rows:
	; grayscale, 16 bit, no alpha
	add	rsi, 1
	mov	ecx, r8d
calign
.onechannel_16bit_cols:
	movzx	eax, byte [rsi]
	add	rsi, 2
	; broadcast the resultant value
	imul	eax, 0x010101
	or	eax, r11d		; alpha == 0xff == opaque, default
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 2
	jnz	.onechannel_16bit_cols
	sub	r9d, 1
	jnz	.onechannel_16bit_rows
	jmp	.allgood
calign
.twochannels:
	; gray with alpha channel
	; bitdepth is either 8 or 16, x 2 in pixdepth, so 16 or 32
	cmp	r10d, 32
	je	.twochannels_16bit_rows
calign
.twochannels_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.twochannels_cols:
	movzx	eax, byte [rsi]
	movzx	edx, byte [rsi+1]
	add	rsi, 2
	imul	eax, 0x010101
	shl	edx, 24
	or	eax, edx
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 2
	jnz	.twochannels_cols
	sub	r9d, 1
	jnz	.twochannels_rows
	jmp	.allgood
calign
.twochannels_16bit_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.twochannels_16bit_cols:
	movzx	eax, byte [rsi]
	movzx	edx, byte [rsi+2]
	add	rsi, 4
	imul	eax, 0x010101
	shl	edx, 24
	or	eax, edx
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 4
	jnz	.twochannels_16bit_cols
	sub	r9d, 1
	jnz	.twochannels_16bit_rows
	jmp	.allgood
calign
.threechannels:
	; rgb, no alpha channel
	; bitdepth is either 8 or 16, x 3 in pixdepth, so 24 or 48
	cmp	r10d, 48
	je	.threechannels_16bit_rows
calign
.threechannels_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.threechannels_cols:
	mov	eax, [rsi]
	and	eax, 0xffffff
	add	rsi, 3
	or	eax, r11d		; alpha == 0xff == opaque, default
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 3
	jnz	.threechannels_cols
	sub	r9d, 1
	jnz	.threechannels_rows
	jmp	.allgood
calign
.threechannels_16bit_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.threechannels_16bit_cols:
	movzx	eax, byte [rsi]
	movzx	edx, byte [rsi+2]
	movzx	r15d, byte [rsi+4]
	add	rsi, 6
	shl	edx, 8
	shl	r15d, 16
	or	eax, edx
	or	eax, r15d
	or	eax, r11d		; alpha == 0xff == opaque, default
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 6
	jnz	.threechannels_16bit_cols
	sub	r9d, 1
	jnz	.threechannels_16bit_rows
	jmp	.allgood
calign
.fourchannels:
	; rgba, our native
	; bitdepth is either 8 or 16, x 4 in pixdepth, so 32 or 64
	cmp	r10d, 64
	je	.fourchannels_16bit_rows
calign
.fourchannels_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.fourchannels_cols:
	mov	eax, [rsi]
	add	rsi, 4
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 4
	jnz	.fourchannels_cols
	sub	r9d, 1
	jnz	.fourchannels_rows
	jmp	.allgood
calign
.fourchannels_16bit_rows:
	add	rsi, 1
	mov	ecx, r8d
calign
.fourchannels_16bit_cols:
	; RGBA, but we have 2 bytes for each one all that need to be shrunk
	movzx	eax, byte [rsi]
	movzx	edx, byte [rsi+2]
	movzx	r15d, byte [rsi+4]
	shl	edx, 8
	shl	r15d, 16
	or	eax, edx
	or	eax, r15d
	movzx	edx, byte [rsi+6]
	shl	edx, 24
	or	eax, edx
	mov	[r14], eax
	add	r14, 4
	sub	ecx, 4
	jnz	.fourchannels_16bit_cols
	sub	r9d, 1
	jnz	.fourchannels_16bit_rows
	; fallthrough to allgood
calign
.allgood:
	mov	rdi, [rsp+zlib_inbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rsp+zlib_outbuf_ofs]
	call	buffer$destroy
	mov	rdi, rsp
	call	zlib$inflateEnd
	add	rsp, zlib_stream_size
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.bad:
	mov	rdi, [rsp+zlib_inbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rsp+zlib_outbuf_ofs]
	call	buffer$destroy
	mov	rdi, rsp
	call	zlib$inflateEnd
	add	rsp, zlib_stream_size

	mov	rdi, [rbx+png_data_ofs]
	test	rdi, rdi
	jz	.nodata
	call	heap$free
calign
.nodata:
	mov	rdi, rbx
	call	heap$free
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.invalid:
	xor	eax, eax
	epilog

end if


if used png$to_ppmbuffer | defined include_everything
	; single argument in rdi: our png object as created above by png$new
	; returns a new buffer with ppm-format compatible output (P6)
falign
png$to_ppmbuffer:
	prolog	png$to_ppmbuffer
	push	rbx r12 r13
	mov	rbx, rdi
	call	buffer$new
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, .p6
	mov	edx, 3
	call	buffer$append
	mov	edi, [rbx+png_width_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r12
	mov	esi, ' '
	call	buffer$append_byte
	mov	edi, [rbx+png_height_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_string
	pop	rdi
	call	heap$free
	mov	rdi, r12
	mov	esi, 10
	call	buffer$append_byte
	mov	rdi, r12
	mov	rsi, .colordepth
	mov	edx, 4
	call	buffer$append
	; next up, our png buffer is 32 bit RGBA, and we need 24bit RGB, so walk forward through our buffer
	mov	r13, [rbx+png_data_ofs]
	mov	eax, [rbx+png_width_ofs]
	mul	dword [rbx+png_height_ofs]
	sub	rsp, 8
	mov	ebx, eax
calign
.doit:
	mov	eax, [r13]
	mov	[rsp], eax
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, 3
	call	buffer$append
	add	r13, 4
	sub	ebx, 1
	jnz	.doit
	mov	rax, r12
	pop	r13 r12 rbx
	epilog
dalign
.p6:
	db	'P6',10
dalign
.colordepth:
	db	'255',10

end if
