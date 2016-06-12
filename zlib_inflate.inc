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
	; zlib_inflate.inc: inflate side of zlib port
	;	see zlib_deflate.inc for my amusing commentary re: same
	;	hahah
	;
	; This is quite literally a hand compilation (and thus interpretation/
	; modification) of the "reference zlib."
	; As such, the original zlib.h copyright appears below, although I am not
	; sure that is really necessary. Cheers to Jean-Loup Gailly and the legend
	; Mark Adler are definitely in order regardless of whether it is necessary
	; or not!
	;
	; zlib.h copyright notice appears below:
	;/* zlib.h -- interface of the 'zlib' general purpose compression library
	;  version 1.2.8, April 28th, 2013
	;
	;  Copyright (C) 1995-2013 Jean-loup Gailly and Mark Adler
	;
	;  This software is provided 'as-is', without any express or implied
	;  warranty.  In no event will the authors be held liable for any damages
	;  arising from the use of this software.
	;
	;  Permission is granted to anyone to use this software for any purpose,
	;  including commercial applications, and to alter it and redistribute it
	;  freely, subject to the following restrictions:
	;
	;  1. The origin of this software must not be misrepresented; you must not
	;     claim that you wrote the original software. If you use this software
	;     in a product, an acknowledgment in the product documentation would be
	;     appreciated but is not required.
	;  2. Altered source versions must be plainly marked as such, and must not be
	;     misrepresented as being the original software.
	;  3. This notice may not be removed or altered from any source distribution.
	;
	;  Jean-loup Gailly        Mark Adler
	;  jloup@gzip.org          madler@alumni.caltech.edu
	;
	;
	;  The data format used by the zlib library is described by RFCs (Request for
	;  Comments) 1950 to 1952 in the files http://tools.ietf.org/html/rfc1950
	;  (zlib format), rfc1951 (deflate format) and rfc1952 (gzip format).
	;*/


; zlib_stream_size/offsets/etc apply from zlib_deflate which is included before this one

zmode_head = 0
zmode_flags = 1
zmode_time = 2
zmode_os = 3
zmode_exlen = 4
zmode_extra = 5
zmode_name = 6
zmode_comment = 7
zmode_hcrc = 8
zmode_dictid = 9
zmode_dict = 10
zmode_type = 11
zmode_typedo = 12
zmode_stored = 13
zmode_copy_ = 14
zmode_copy = 15
zmode_table = 16
zmode_lenlens = 17
zmode_codelens = 18
zmode_len_ = 19
zmode_len = 20
zmode_lenext = 21
zmode_dist = 22
zmode_distext = 23
zmode_match = 24
zmode_lit = 25
zmode_check = 26
zmode_length = 27
zmode_done = 28
zmode_bad = 29
zmode_mem = 30
zmode_sync = 31

zlib_istate_mode_ofs = 0		; dd
zlib_istate_last_ofs = 8		; dd
zlib_istate_wrap_ofs = 16		; dd(b)
zlib_istate_havedict_ofs = 24		; dd(b)
zlib_istate_flags_ofs = 32		; dd
zlib_istate_dmax_ofs = 40		; dd
zlib_istate_check_ofs = 48		; dq
zlib_istate_total_ofs = 56		; dq
zlib_istate_head_ofs = 64		; dq->
zlib_istate_wbits_ofs = 72		; dd
zlib_istate_wsize_ofs = 80		; dd
zlib_istate_whave_ofs = 88		; dd
zlib_istate_wnext_ofs = 96		; dd
zlib_istate_window_ofs = 104		; dq->
zlib_istate_hold_ofs = 112		; dq
zlib_istate_bits_ofs = 120		; dd
zlib_istate_length_ofs = 128		; dd
zlib_istate_offset_ofs = 136		; dd
zlib_istate_extra_ofs = 144		; dd
zlib_istate_lencode_ofs = 152		; dq->
zlib_istate_distcode_ofs = 160		; dq->
zlib_istate_lenbits_ofs = 168		; dd
zlib_istate_distbits_ofs = 176		; dd
zlib_istate_ncode_ofs = 184		; dd
zlib_istate_nlen_ofs = 192		; dd
zlib_istate_ndist_ofs = 200		; dd
zlib_istate_have_ofs = 208		; dd
zlib_istate_next_ofs = 216		; dq->
zlib_istate_lens_ofs = 224		; array of short[320]
zlib_istate_work_ofs = 864		; array of short[288]
zlib_istate_codes_ofs = 1440		; array of code[1444] (ENOUGH), code is 4 bytes each
zlib_istate_sane_ofs = 7216		; dd
zlib_istate_back_ofs = 7224		; dd
zlib_istate_was_ofs = 7232		; dd
zlib_istate_flush_ofs = 7240		; dd (nonstandard, but we save it here on entry)
zlib_istate_streamp_ofs = 7248		; dq-> (back to the z_stream pointer)
zlib_istate_lenbitsmask_ofs = 7256	; dd (nonstandard, but no sense in constantly doing 1 shl lenbits - 1)
zlib_istate_distbitsmask_ofs = 7264	; dd (nonstandard, but no sense in constantly doing 1 shl distbits - 1)
zlib_istate_beg_ofs = 7272		; dq (nonstandard, used to store the max distance in output during inflate)
zlib_istate_orig_outlength_ofs = 7280	; dq (nonstandard, used to store the incoming outbuf length)
zlib_istate_fastlast_ofs = 7288		; dq (nonstandard, used for the inlined inflate fast)
zlib_istate_realwindow_ofs = 7296	; 32768 bytes, i loath doing multiple allocs, and in what seems to be every use case
					; that I have, a window does indeed get allocated, so may as well hang it off the end
					; here

zlib_istate_size = 7296 + 32768

zlib_inflate_window_bits = 15

if zlib_inflate_window_bits < 8 | zlib_inflate_window_bits > 15
	display 'bad inflate window bits',10
	err
end if

zlib_inftree_codes = 0
zlib_inftree_lens = 1
zlib_inftree_dists = 2

macro zlib_debug preface*, reg* {
        local ..continue, ..string
        push    rax rcx rdx rdi rsi r8 r9 r10 r11
        sub     rsp, 8
        mov     rdi, reg
        mov     esi, 10
        call    string$from_unsigned
        mov     [rsp], rax
        mov     rdi, ..string
        call    string$to_stdout
        mov     rdi, [rsp]
        call    string$to_stdoutln
        mov     rdi, [rsp]
        call    heap$free
        add     rsp, 8
        pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
        jmp     ..continue
cleartext ..string, preface
calign
..continue:
}

if used zlib$inflateEnd | defined include_everything
	; single argument in rdi: a zlib_stream pointer
	; all we do is heap$free the zlib_state_ofs that we allocated during init
	; we leave everything else well alone
falign
zlib$inflateEnd:
	prolog	zlib$inflateEnd
	mov	rdi, [rdi+zlib_state_ofs]
	call	heap$free
	epilog
end if


if used zlib$inflateInit | defined include_everything
	; two arguements: rdi == zlib_stream_size memory chunk for our state, esi == wrap
	; wrap == 1 == zheaders, wrap == 2 == gzheaders
	; we do not mess with inbuf or outbuf
falign
zlib$inflateInit:
	prolog	zlib$inflateInit
	xor	ecx, ecx
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+16], esi
	mov	[rdi+zlib_totalin_ofs], rcx
	mov	[rdi+zlib_totalout_ofs], rcx
	mov	edi, zlib_istate_size
	call	heap$alloc
	mov	rcx, [rsp]
	mov	[rsp+8], rax
	mov	[rcx+zlib_state_ofs], rax
	mov	rdi, rax
	xor	esi, esi
	mov	edx, zlib_istate_size - 32768					; we do not need to clear the window itself at the end
	call	memset
	mov	rsi, [rsp]
	mov	rdi, [rsp+8]
	mov	eax, [rsp+16]
	mov	[rdi+zlib_istate_streamp_ofs], rsi
	mov	dword [rdi+zlib_istate_wbits_ofs], zlib_inflate_window_bits
	mov	dword [rdi+zlib_istate_wrap_ofs], eax
	and	eax, 1
	; inflateResetKeep(strm) next
	lea	rcx, [rdi+zlib_istate_codes_ofs]
	mov	dword [rsi+zlib_adler_ofs], eax
	; zmode_head == 0 anyway, so this isn't necessary:
	;   mov	dword [rdi+zlib_istate_mode_ofs], zmode_head
	mov	dword [rdi+zlib_istate_dmax_ofs], 32768
	mov	[rdi+zlib_istate_lencode_ofs], rcx
	mov	[rdi+zlib_istate_distcode_ofs], rcx
	mov	[rdi+zlib_istate_next_ofs], rcx
	mov	dword [rdi+zlib_istate_sane_ofs], 1
	mov	dword [rdi+zlib_istate_back_ofs], -1
	lea	rsi, [rdi+zlib_istate_realwindow_ofs]
	mov	[rdi+zlib_istate_window_ofs], rsi
	mov	dword [rdi+zlib_istate_wsize_ofs], 32768
	; our memset atop cleared wnext/whave

	mov	rax, rsi
	add	rsp, 24
	epilog

end if

if used zlib$inflate | defined include_everything

	; two arguments: rdi == z_stream pointer, esi == flush_flags
	; we return a bool in eax (unlike the actual zlib), 1 == Z_OK, 0 == fail
	; and in our implementation, we really don't care WHY it failed, only that it did
falign
zlib$inflate:	
	prolog	zlib$inflate
	push	rbx r12 r13 r14 r15
	test	rdi, rdi
	jz	.error_return
	mov	rbx, [rdi+zlib_state_ofs]
	test	rbx, rbx
	jz	.error_return
	mov	dword [rbx+zlib_istate_flush_ofs], esi
	mov	r14, [rdi+zlib_inbuf_ofs]
	mov	r15, [rdi+zlib_outbuf_ofs]
	test	r14, r14
	jz	.error_return
	test	r15, r15
	jz	.error_return
	mov	ecx, [rbx+zlib_istate_mode_ofs]
	mov	eax, zmode_typedo
	cmp	ecx, zmode_type
	cmove	ecx, eax
	mov	[rbx+zlib_istate_mode_ofs], ecx
	; setup our user-space vars inside the inbuf so that we don't have to use the head of it
	; and consume (bad for large buffers)
	mov	rax, [r14+buffer_length_ofs]
	mov	rcx, [r14+buffer_itself_ofs]
	mov	[r14+buffer_user_ofs], rcx		; user_ofs == current pointer
	mov	[r14+buffer_user_ofs+8], rax		; user_ofs+8 == remaining bytes

	; left == strm->avail_out ... we don't need, we will always grow our output buffer
	; next = strm->next_in ... our input buffer, which we already have pointers for and we'll 'consume' from this
	; have == strm->avail_in == our input buffer also, we will consume from here too
	mov	r12, qword [rbx+zlib_istate_hold_ofs]	; hold
	mov	r13d, dword [rbx+zlib_istate_bits_ofs]	; bits

	mov	rax, [r15+buffer_length_ofs]
	mov	[rbx+zlib_istate_orig_outlength_ofs], rax	; save this so we know how much we really added

	; unlike the reference version, I really dislike pulling 8 bits at a time out of the input buffer
	; so we do 32 bits at a time or whatever is left

	; zlib_inflate_needbits:
	; we smash eax, ecx, edx
macro zlib_inflate_needbits n* {
	local	.getfour, .allgood
	cmp	r13d, n
	jae	.allgood
	mov	rax, [r14+buffer_user_ofs]
	cmp	qword [r14+buffer_user_ofs+8], 4
	jae	.getfour
	; less than 4 bytes remain, determine existing bits + (remaining bytes * 8) is >= n, else goto .inf_leave
	; it will be safe here to pull a dword even if it is past the end of input
	mov	r8d, [r14+buffer_user_ofs+8]
	mov	ecx, r13d
	mov	edx, dword [rax]
	; this needs to be and'd with the right mask corresponding to how much data we have left
	and	edx, [r8*4+.bytesleft]
	shl	rdx, cl
	add	r12, rdx
	mov	rcx, r8
	xor	edx, edx
	add	qword [r14+buffer_user_ofs], rcx	; move pointer forward
	shl	ecx, 3
	add	r13d, ecx	; number of bits we really added
	mov	qword [r14+buffer_user_ofs+8], rdx	; no more bytes left
	cmp	r13d, n
	jae	.allgood
	jmp	.inf_leave
calign
.getfour:
	mov	ecx, r13d
	mov	edx, dword [rax]
	shl	rdx, cl
	add	r12, rdx
	add	r13d, 32
	add	qword [r14+buffer_user_ofs], 4
	sub	qword [r14+buffer_user_ofs+8], 4
	; fallthrough to allgood
calign
.allgood:
}


macro zlib_inflate_fastcheck {
	local	.allgood
	cmp	r13d, 15
	jae	.allgood
	; add 16 more bits to the hold
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	movzx	edx, word [rax]
	shl	rdx, cl
	add	r12, rdx
	add	r13d, 16
	add	qword [r14+buffer_user_ofs], 2
	sub	qword [r14+buffer_user_ofs+8], 2
	; fallthrough to allgood
calign
.allgood:
}

macro zlib_inflate_fastcheck2 {
	; add 8 more bits to the hold
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	movzx	edx, byte [rax]
	shl	rdx, cl
	add	r12, rdx
	add	r13d, 8
	add	qword [r14+buffer_user_ofs], 1
	sub	qword [r14+buffer_user_ofs+8], 1
}

	; this one is different and only used inside inflate_fast
	; and the reason for the difference is because if there were 40 bytes in the accum
	; and the above macro were called with needing 48, it would overfill the accumulator
macro zlib_inflate_need6bytes {
	local	.allgood, .checkfour, .getwhateverisleft
	cmp	r13d, 48
	jae	.allgood
	cmp	r13d, 32
	jle	.checkfour		; it is okay to pull up to what we are after in dword size
	; otherwise, we know we can do at least 2 bytes at a time, because there is at least 16 bits left in the accum
	; and we know that we have more than 32 bits in our accum
	cmp	qword [r14+buffer_user_ofs+8], 2
	jb	.getwhateverisleft
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	movzx	edx, word [rax]
	shl	rdx, cl
	add	r12, rdx
	add	r13d, 16
	add	qword [r14+buffer_user_ofs], 2
	sub	qword [r14+buffer_user_ofs+8], 2
	jmp	.allgood
calign
.getwhateverisleft:
	; determine existing bits + (remaining bytes * 8) is >= n, else goto .inf_leave
	; it will be safe here to pull a dword even if it is past the end of input
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	mov	r8, [r14+buffer_user_ofs+8]
	mov	edx, dword [rax]
	and	edx, [r8*4+.bytesleft]
	shl	rdx, cl
	add	r12, rdx
	mov	rcx, r8
	xor	edx, edx
	add	qword [r14+buffer_user_ofs], rcx	; move pointer forward
	shl	ecx, 3
	add	r13d, ecx	; number of bits we really added
	mov	qword [r14+buffer_user_ofs+8], rdx	; no more bytes left
	cmp	r13d, 48
	jae	.allgood
	jmp	.inf_leave
calign
.checkfour:
	cmp	qword [r14+buffer_user_ofs+8], 4
	jb	.getwhateverisleft
	; else, safe to grab 4 bytes
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	mov	edx, dword [rax]
	shl	rdx, cl
	add	r12, rdx
	add	r13d, 32
	add	qword [r14+buffer_user_ofs], 4
	sub	qword [r14+buffer_user_ofs+8], 4
	; fallthrough to allgood
calign
.allgood:
}


	; zlib_inflate_needbits_reg:
	; we smash eax, ecx, edx, so n must be a register (32 bit) and not one of the ones we smash
	; NOTE: this is (for the moment) exactly the same code as zlib_inflate_needbits
macro zlib_inflate_needbits_reg n* {
	local	.getfour, .allgood
	cmp	r13d, n
	jae	.allgood
	cmp	qword [r14+buffer_user_ofs+8], 4
	jae	.getfour
	; less than 4 bytes remain, determine existing bits + (remaining bytes * 8) is >= n, else goto .inf_leave
	; it will be safe here to pull a dword even if it is past the end of input
	push	r8
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	mov	r8, [r14+buffer_user_ofs+8]
	mov	edx, dword [rax]
	and	edx, [r8*4+.bytesleft]
	shl	rdx, cl
	add	r12, rdx
	mov	rcx, r8
	xor	edx, edx
	pop	r8
	add	qword [r14+buffer_user_ofs], rcx	; move pointer forward
	shl	ecx, 3
	add	r13d, ecx	; number of bits we really added
	mov	qword [r14+buffer_user_ofs+8], rdx	; no more bytes left
	cmp	r13d, n
	jae	.allgood
	jmp	.inf_leave
calign
.getfour:
	mov	ecx, r13d
	mov	rax, [r14+buffer_user_ofs]
	mov	edx, dword [rax]
	shl	rdx, cl
	add	r12, rdx
	add	r13d, 32
	add	qword [r14+buffer_user_ofs], 4
	sub	qword [r14+buffer_user_ofs+8], 4
	; fallthrough to allgood
calign
.allgood:
}




	; zlib_inflate_unwindbits:
	; _requires_ bits to be byte aligned of course
	; but "puts them back"
macro zlib_inflate_unwindbits {
	shr	r13d, 3
	sub	qword [r14+buffer_user_ofs], r13	; move pointer backwards
	add	qword [r14+buffer_user_ofs+8], r13	; add bytes back into remaining
	xor	r13d, r13d
	xor	r12d, r12d
}

	; zlib_inflate_dropbits:
	; no smashes
macro zlib_inflate_dropbits n* {
	shr	r12, n
	sub	r13d, n
}

	; zlib_inflate_dropbits_reg:
	; smashes ecx (as it must), n must be a register not a literal (32 bits)
macro zlib_inflate_dropbits_reg n* {
	mov	ecx, n
	shr	r12, cl
	sub	r13d, n
}

	; zlib_inflate_bytebits:
	; we smash ecx
macro zlib_inflate_bytebits {
	mov	ecx, r13d
	and	ecx, 7
	shr	r12, cl
	sub	r13d, ecx
}


calign
.top:
	mov	eax, [rbx+zlib_istate_mode_ofs]
	shl	eax, 3
	add	rax, .modejumps
	jmp	qword [rax]
dalign
.bytesleft:
	dd	0x00000000, 0x000000ff, 0x0000ffff, 0x00ffffff
calign
.mode_head:
	xor	eax, eax
	mov	ecx, zmode_typedo
	cmp	dword [rbx+zlib_istate_wrap_ofs], 0
	cmove	eax, ecx
	mov	dword [rbx+zlib_istate_mode_ofs], eax
	je	.mode_typedo
	zlib_inflate_needbits 16
	mov	eax, r12d
	and	eax, 0xffff
	cmp	eax, 0x8b1f
	jne	.mode_head_nogzhead
	test	dword [rbx+zlib_istate_wrap_ofs], 2
	jz	.mode_head_nogzhead
	; CRC2(state->check, hold)
	xor	edi, edi				; crc32(0, null, 0) == 0
	sub	rsp, 8
	mov	dword [rsp], eax
	mov	rsi, rsp
	mov	edx, 2
	call	crc$32
	add	rsp, 8
	mov	qword [rbx+zlib_istate_check_ofs], rax
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_flags
	jmp	.mode_flags
calign
.mode_head_nogzhead:
	mov	dword [rbx+zlib_istate_flags_ofs], 0
	test	dword [rbx+zlib_istate_wrap_ofs], 1
	jz	.mode_bad
	; we don't do headers, none of my stream stuff needs it
	mov	eax, r12d
	mov	ecx, r12d
	and	eax, 0xff				; low byte from the accum
	and	ecx, 0xffff				
	shl	eax, 8					; << 8
	shr	ecx, 8					; high byte from the accum
	add	eax, ecx
	mov	ecx, 31
	xor	edx, edx
	div	ecx
	test	edx, edx
	jnz	.mode_bad
calign
.mode_head_noheadercheck:
	mov	eax, r12d
	and	eax, 0xf
	cmp	eax, 8					; BITS(4) != Z_DEFLATED
	jne	.mode_bad
	zlib_inflate_dropbits 4
	mov	eax, 1
	mov	ecx, r12d
	and	ecx, 0xf
	add	ecx, 8
	cmp	dword [rbx+zlib_istate_wbits_ofs], 0
	je	.mode_head_wbits_zero
	cmp	ecx, dword [rbx+zlib_istate_wbits_ofs]
	ja	.mode_bad
	shl	eax, cl
	mov	rdi, [rbx+zlib_istate_streamp_ofs]
	mov	qword [rbx+zlib_istate_check_ofs], 1	; adler32(0,null,0) == 1
	mov	qword [rdi+zlib_adler_ofs], 1
	mov	dword [rbx+zlib_istate_dmax_ofs], eax
	mov	eax, r12d
	zlib_inflate_dropbits 12
	mov	ecx, zmode_dictid
	mov	edx, zmode_type
	test	eax, 0x200
	cmovz	ecx, edx
	mov	[rbx+zlib_istate_mode_ofs], ecx
	jnz	.mode_dictid
	jmp	.mode_type
calign
.mode_head_wbits_zero:
	mov	dword [rbx+zlib_istate_wbits_ofs], ecx
	shl	eax, cl
	mov	rdi, [rbx+zlib_istate_streamp_ofs]
	mov	qword [rbx+zlib_istate_check_ofs], 1	; adler32(0,null,0) == 1
	mov	qword [rdi+zlib_adler_ofs], 1
	mov	dword [rbx+zlib_istate_dmax_ofs], eax
	mov	eax, r12d
	zlib_inflate_dropbits 12
	mov	ecx, zmode_dictid
	mov	edx, zmode_type
	test	eax, 0x200
	cmovz	ecx, edx
	mov	[rbx+zlib_istate_mode_ofs], ecx
	jnz	.mode_dictid
	jmp	.mode_type
calign
.mode_flags:
	zlib_inflate_needbits 16
	mov	eax, r12d
	and	eax, 0xffff
	mov	dword [rbx+zlib_istate_flags_ofs], eax
	mov	ecx, eax
	and	ecx, 0xff
	cmp	ecx, 8					; flags & 0xff != Z_DEFLATED
	jne	.mode_bad
	test	eax, 0xe000
	jnz	.mode_bad
	test	eax, 0x0200
	jnz	.mode_flags_docrc
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_time
	jmp	.mode_time
calign
.mode_flags_docrc:
	; CRC2(state->check, hold)
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	sub	rsp, 8
	mov	dword [rsp], r12d
	mov	rsi, rsp
	mov	edx, 2
	call	crc$32
	add	rsp, 8
	mov	qword [rbx+zlib_istate_check_ofs], rax
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_time
	; fallthrough to .mode_time
calign
.mode_time:
	zlib_inflate_needbits 32
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_time_docrc
	zlib_inflate_dropbits 32
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_os
	jmp	.mode_os
calign
.mode_time_docrc:
	; CRC4(state->check, hold)
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	sub	rsp, 8
	mov	dword [rsp], r12d
	mov	rsi, rsp
	mov	edx, 4
	call	crc$32
	add	rsp, 8
	mov	qword [rbx+zlib_istate_check_ofs], rax
	zlib_inflate_dropbits 32
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_os
	; fallthrough to .mode_os
calign
.mode_os:
	zlib_inflate_needbits 16
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_os_docrc
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_exlen
	jmp	.mode_exlen
calign
.mode_os_docrc:
	; CRC2(state->check, hold)
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	sub	rsp, 8
	mov	dword [rsp], r12d
	mov	rsi, rsp
	mov	edx, 2
	call	crc$32
	add	rsp, 8
	mov	qword [rbx+zlib_istate_check_ofs], rax
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_exlen
	; fallthrough to .mode_exlen
calign
.mode_exlen:
	test	dword [rbx+zlib_istate_flags_ofs], 0x0400
	jz	.mode_exlen_nolength
	zlib_inflate_needbits 16
	mov	eax, r12d
	and	eax, 0xffff
	mov	dword [rbx+zlib_istate_length_ofs], eax
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_exlen_docrc
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_extra
	jmp	.mode_extra
calign
.mode_exlen_docrc:
	; CRC2(state->check, hold)
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	sub	rsp, 8
	mov	dword [rsp], r12d
	mov	rsi, rsp
	mov	edx, 2
	call	crc$32
	add	rsp, 8
	mov	qword [rbx+zlib_istate_check_ofs], rax
	zlib_inflate_dropbits 16
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_extra
	jmp	.mode_extra
calign
.mode_exlen_nolength:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_extra
	; fallthrough to .mode_extra
calign
.mode_extra:
	test	dword [rbx+zlib_istate_flags_ofs], 0x0400
	jz	.mode_extra_nolength
	; ok so, here my pulling extra 32 bits at a time may not have exactly worked out so well
	; BUT, we can do an unwind of whatever is in our accumulator first
	; which solves the problem nicely
	zlib_inflate_unwindbits
	mov	edx, dword [rbx+zlib_istate_length_ofs]		; copy
	mov	rax, qword [r14+buffer_user_ofs+8]		; remaining bytes
	cmp	rdx, rax					; copy > have?
	cmova	rdx, rax					; if so, copy = have
	test	rdx, rdx
	jz	.mode_extra_nocopy
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_extra_docrc
	sub	qword [r14+buffer_user_ofs+8], rdx
	add	qword [r14+buffer_user_ofs], rdx
	sub	dword [rbx+zlib_istate_length_ofs], edx
	cmp	dword [rbx+zlib_istate_length_ofs], 0
	jne	.inf_leave
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_name
	jmp	.mode_name
calign
.mode_extra_docrc:
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	mov	rsi, [r14+buffer_user_ofs]
	push	rdx
	; rdx already set
	call	crc$32
	pop	rdx
	mov	qword [rbx+zlib_istate_check_ofs], rax
	sub	qword [r14+buffer_user_ofs+8], rdx
	add	qword [r14+buffer_user_ofs], rdx
	sub	dword [rbx+zlib_istate_length_ofs], edx
	cmp	dword [rbx+zlib_istate_length_ofs], 0
	jne	.inf_leave
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_name
	jmp	.mode_name
calign
.mode_extra_nocopy:
	cmp	dword [rbx+zlib_istate_length_ofs], 0
	jne	.inf_leave
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_name
	jmp	.mode_name
calign
.mode_extra_nolength:
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_name
	; fallthrough to .mode_name
calign
.mode_name:
	; the bit accumulator has to be empty at this stage
	test	dword [rbx+zlib_istate_flags_ofs], 0x0800
	jz	.mode_name_noname
	; yuck, a null terminated name?
	cmp	qword [r14+buffer_user_ofs+8], 0
	je	.inf_leave
	xor	edx, edx				; copy = 0
	mov	rax, [r14+buffer_user_ofs]
calign
.mode_name_findnull:
	movzx	ecx, byte [rax]
	add	rax, 1
	add	edx, 1
	test	ecx, ecx
	jz	.mode_name_nullfound
	cmp	rdx, qword [r14+buffer_user_ofs+8]
	jb	.mode_name_findnull
calign
.mode_name_nullfound:
	; could have fallen through due to running out of bytes
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_name_nullfound_docrc
	sub	qword [r14+buffer_user_ofs+8], rdx	; have -= copy
	add	qword [r14+buffer_user_ofs], rdx	; ptr += copy
	test	ecx, ecx
	jnz	.inf_leave
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_comment
	jmp	.mode_comment
calign
.mode_name_nullfound_docrc:
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	mov	rsi, [r14+buffer_user_ofs]
	; rdx already set, preserve it and rcx
	push	rcx rdx
	call	crc$32
	pop	rdx rcx
	mov	qword [rbx+zlib_istate_check_ofs], rax
	sub	qword [r14+buffer_user_ofs+8], rdx	; have -= copy
	add	qword [r14+buffer_user_ofs], rdx	; ptr += copy
	test	ecx, ecx
	jnz	.inf_leave
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_comment
	jmp	.mode_comment
calign
.mode_name_noname:
	mov	dword [rbx+zlib_istate_length_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_comment
	; fallthrough to .mode_comment
calign
.mode_comment:
	test	dword [rbx+zlib_istate_flags_ofs], 0x1000
	jz	.mode_comment_nocomment
	; yuck, a null terminated comment too?
	cmp	qword [r14+buffer_user_ofs+8], 0
	je	.inf_leave
	xor	edx, edx				; copy = 0
	mov	rax, [r14+buffer_user_ofs]
calign
.mode_comment_findnull:
	movzx	ecx, byte [rax]
	add	rax, 1
	add	edx, 1
	test	ecx, ecx
	jz	.mode_comment_nullfound
	cmp	rdx, qword [r14+buffer_user_ofs+8]
	jb	.mode_comment_findnull
calign
.mode_comment_nullfound:
	; could have fallen through due to running out of bytes
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_comment_nullfound_docrc
	sub	qword [r14+buffer_user_ofs+8], rdx	; have -= copy
	add	qword [r14+buffer_user_ofs], rdx	; ptr += copy
	test	ecx, ecx
	jnz	.inf_leave
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_hcrc
	jmp	.mode_hcrc
calign
.mode_comment_nullfound_docrc:
	mov	rdi, qword [rbx+zlib_istate_check_ofs]
	mov	rsi, [r14+buffer_user_ofs]
	; rdx already set, preserve it and rcx
	push	rcx rdx
	call	crc$32
	pop	rdx rcx
	mov	qword [rbx+zlib_istate_check_ofs], rax
	sub	qword [r14+buffer_user_ofs+8], rdx	; have -= copy
	add	qword [r14+buffer_user_ofs], rdx	; ptr += copy
	test	ecx, ecx
	jnz	.inf_leave
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_hcrc
	jmp	.mode_hcrc
calign
.mode_comment_nocomment:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_hcrc
	; fallthrough to .mode_hcrc
calign
.mode_hcrc:
	test	dword [rbx+zlib_istate_flags_ofs], 0x0200
	jnz	.mode_hcrc_checkit
	mov	rsi, [rbx+zlib_istate_streamp_ofs]
	mov	qword [rsi+zlib_adler_ofs], 0
	mov	qword [rbx+zlib_istate_check_ofs], 0	; crc32(0, null, 0) == 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_type
	jmp	.mode_type
calign
.mode_hcrc_checkit:
	zlib_inflate_needbits 16
	mov	eax, r12d
	and	eax, 0xffff
	mov	rcx, qword [rbx+zlib_istate_check_ofs]
	and	ecx, 0xffff
	cmp	eax, ecx
	jne	.mode_bad				; header crc mismatch
	zlib_inflate_dropbits 16
	mov	rsi, [rbx+zlib_istate_streamp_ofs]
	mov	qword [rsi+zlib_adler_ofs], 0
	mov	qword [rbx+zlib_istate_check_ofs], 0	; crc32(0, null, 0) == 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_type
	jmp	.mode_type
calign
.mode_dictid:
	zlib_inflate_needbits 32
	mov	rsi, [rbx+zlib_istate_streamp_ofs]
	mov	eax, r12d
	bswap	eax
	mov	qword [rsi+zlib_adler_ofs], rax
	mov	qword [rbx+zlib_istate_check_ofs], rax
	zlib_inflate_dropbits 32
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_dict
	; fallthrough to .mode_dict
calign
.mode_dict:
	; we don't support adding a custom user dictionary here... maybe someday when I am bored
	; we can come back and add it, for now, add a breakpoint
	cmp	dword [rbx+zlib_istate_havedict_ofs], 0
	je	.mode_dict_todo
	mov	rsi, [rbx+zlib_istate_streamp_ofs]
	mov	qword [rbx+zlib_istate_check_ofs], 1
	mov	qword [rsi+zlib_adler_ofs], 1		; adler32(0, null, 0) == 1
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_type
	jmp	.mode_type
calign
.mode_dict_todo:
	; in the reference version, this would be a Z_NEED_DICT return
	; which, none of my ssl/streaming/gzip goods use
	; TODO: someday when I am bored and have nothing better to do, add custom dictionary support to this
	; and NOTE: since zlib_istate_havedict_ofs is set to 0, this won't happen during normal runtime
	; unless you are playing with it :-)
	breakpoint
calign
.mode_type:
	cmp	dword [rbx+zlib_istate_flush_ofs], zlib_block
	je	.inf_leave
	cmp	dword [rbx+zlib_istate_flush_ofs], zlib_trees		; zlib_trees is defined with the other flush constants in deflate
	je	.inf_leave
	; fall through to .mode_typedo
calign
.mode_typedo:
	cmp	dword [rbx+zlib_istate_last_ofs], 0
	jne	.mode_typedo_last
	zlib_inflate_needbits 3
	mov	eax, r12d
	and	eax, 1
	mov	dword [rbx+zlib_istate_last_ofs], eax
	zlib_inflate_dropbits 1
	mov	eax, r12d
	and	eax, 3
	cmp	eax, 0
	je	.mode_typedo_stored
	cmp	eax, 1
	je	.mode_typedo_fixed
	cmp	eax, 2
	je	.mode_typedo_dynamic
	; invalid block type
	zlib_inflate_dropbits 2
	jmp	.mode_bad
calign
.mode_typedo_stored:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_stored
	zlib_inflate_dropbits 2
	jmp	.mode_stored
calign
.mode_typedo_fixed:
	; fixedtables(state)
	mov	qword [rbx+zlib_istate_lencode_ofs], .lenfix
	mov	dword [rbx+zlib_istate_lenbits_ofs], 9
	mov	dword [rbx+zlib_istate_lenbitsmask_ofs], 511	; 1 shl 9 - 1
	mov	qword [rbx+zlib_istate_distcode_ofs], .distfix
	mov	dword [rbx+zlib_istate_distbits_ofs], 5
	mov	dword [rbx+zlib_istate_distbitsmask_ofs], 31	; 1 shl 5 - 1
	; end of fixedtables
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_len_
	cmp	dword [rbx+zlib_istate_flush_ofs], zlib_trees
	je	.mode_typedo_fixed_treesflush
	zlib_inflate_dropbits 2
	jmp	.mode_len_
calign
.mode_typedo_fixed_treesflush:
	zlib_inflate_dropbits 2
	jmp	.inf_leave
calign
.mode_typedo_dynamic:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_table
	zlib_inflate_dropbits 2
	jmp	.mode_table
calign
.mode_typedo_last:
	zlib_inflate_bytebits
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_check
	jmp	.mode_check
calign
.mode_stored:
	zlib_inflate_bytebits
	zlib_inflate_needbits 32
	mov	eax, r12d
	mov	ecx, r12d
	shr	ecx, 16
	xor	ecx, 0xffff
	and	eax, 0xffff
	cmp	eax, ecx
	jne	.mode_bad		; invalid stored block lengths
	mov	dword [rbx+zlib_istate_length_ofs], eax
	zlib_inflate_dropbits 32
	zlib_inflate_unwindbits		; put back whatever remains
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_copy_
	cmp	dword [rbx+zlib_istate_flush_ofs], zlib_trees
	je	.inf_leave
	; fallthrough to .mode_copy_
calign
.mode_copy_:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_copy
	; fallthroguh to mode_copy
calign
.mode_copy:
	; do a buffer append
	cmp	dword [rbx+zlib_istate_length_ofs], 0
	je	.mode_copy_nolength
	mov	edx, [rbx+zlib_istate_length_ofs]
	mov	rcx, [r14+buffer_user_ofs+8]		; remaining bytes left
	cmp	rdx, rcx
	cmova	rdx, rcx
	test	rdx, rdx
	jz	.inf_leave
	; our next pointer is the buffer current pointer itself
	mov	rsi, [r14+buffer_user_ofs]
	mov	rdi, r15
	; before we call buffer$append, modify our remaining pointers and update length
	sub	dword [rbx+zlib_istate_length_ofs], edx
	sub	qword [r14+buffer_user_ofs+8], rdx
	add	qword [r14+buffer_user_ofs], rdx
	call	buffer$append
	cmp	dword [rbx+zlib_istate_length_ofs], 0
	je	.mode_copy_nolength
	; otherwise, for there still to be a length remaining, it means we _must_ have run out of input bytes
	jmp	.inf_leave
calign
.mode_copy_nolength:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_type
	jmp	.mode_type
calign
.mode_table:
	zlib_inflate_needbits 14
	mov	eax, r12d
	and	eax, 31
	add	eax, 257
	mov	dword [rbx+zlib_istate_nlen_ofs], eax
	cmp	eax, 286
	ja	.mode_bad		; too many length or distance symbols
	zlib_inflate_dropbits 5
	mov	eax, r12d
	and	eax, 31
	add	eax, 1
	mov	dword [rbx+zlib_istate_ndist_ofs], eax
	cmp	eax, 30
	ja	.mode_bad		; too many length or distance symbols
	zlib_inflate_dropbits 5
	mov	eax, r12d
	and	eax, 15
	add	eax, 4
	mov	dword [rbx+zlib_istate_ncode_ofs], eax
	zlib_inflate_dropbits 4
	mov	dword [rbx+zlib_istate_have_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_lenlens
	; fallthrough to .mode_lenlens
calign
.mode_lenlens:
	mov	ecx, [rbx+zlib_istate_have_ofs]
	cmp	ecx, dword [rbx+zlib_istate_ncode_ofs]
	jae	.mode_lenlens_ncodesdone
	zlib_inflate_needbits 3
	; lens is array of unsigned short, inline with state
	; order is array of dd
	lea	rdx, [rbx+zlib_istate_lens_ofs]
	mov	ecx, [rbx+zlib_istate_have_ofs]
	mov	r8d, dword [rcx*4+.order]
	add	ecx, 1
	mov	[rbx+zlib_istate_have_ofs], ecx
	mov	eax, r12d
	and	eax, 7				; BITS(3)
	mov	word [rdx+r8*2], ax
	zlib_inflate_dropbits 3
	jmp	.mode_lenlens
calign
.mode_lenlens_ncodesdone:
	cmp	dword [rbx+zlib_istate_have_ofs], 19
	jae	.mode_lenlens_ncodefilldone
	lea	rdx, [rbx+zlib_istate_lens_ofs]
	mov	ecx, [rbx+zlib_istate_have_ofs]
	mov	r8d, dword [rcx*4+.order]
	add	ecx, 1
	mov	[rbx+zlib_istate_have_ofs], ecx
	xor	eax, eax
	mov	word [rdx+r8*2], ax
	jmp	.mode_lenlens_ncodesdone
calign
.mode_lenlens_ncodefilldone:
	lea	rax, [rbx+zlib_istate_codes_ofs]
	mov	[rbx+zlib_istate_next_ofs], rax
	mov	[rbx+zlib_istate_lencode_ofs], rax
	mov	dword [rbx+zlib_istate_lenbits_ofs], 7
	mov	dword [rbx+zlib_istate_lenbitsmask_ofs], 127	; 1 shl 7 - 1
	mov	edi, zlib_inftree_codes
	lea	rsi, [rbx+zlib_istate_lens_ofs]
	mov	edx, 19
	lea	rcx, [rbx+zlib_istate_next_ofs]
	lea	r8, [rbx+zlib_istate_lenbits_ofs]
	lea	r9, [rbx+zlib_istate_work_ofs]
	call	.inflate_table

	; do the calculation of lenbitsmask once
	mov	edx, 1
	mov	ecx, [rbx+zlib_istate_lenbits_ofs]
	shl	edx, cl
	sub	edx, 1
	mov	[rbx+zlib_istate_lenbitsmask_ofs], edx

	test	eax, eax
	jz	.mode_bad				; invalid code lengths set
	mov	dword [rbx+zlib_istate_have_ofs], 0
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_codelens
	; fallthrough to .mode_codelens
calign
.mode_codelens:
	mov	eax, dword [rbx+zlib_istate_nlen_ofs]
	add	eax, dword [rbx+zlib_istate_ndist_ofs]
	cmp	dword [rbx+zlib_istate_have_ofs], eax
	jae	.mode_codelens_whiledone
calign
.mode_codelens_getbits:
	; accum in r12, bits in r13d
	mov	rsi, [rbx+zlib_istate_lencode_ofs]
	mov	edx, dword [rbx+zlib_istate_lenbitsmask_ofs]
	mov	ecx, r12d
	and	ecx, edx
	mov	eax, [rsi+rcx*4]			; here = state->lencode[BITS(state->lenbits)]
	movzx	ecx, ah					; here.bits
	cmp	ecx, r13d
	jbe	.mode_codelens_gotbits
	; else, we need MORE bits... but we don't want to necessarily assume that a dword would do the trick
	; hmmm... TODO: see how many times this thing actually gets called, and monitor the bit accumulator
	; ... the REASON we can't just say "hey gimme 32 bits" is because this code might not actually need that many
	; and we'd be falsely stating that we did and prematurely bailing out if in fact there were enough here
	; already ... hmmm
	mov	r8d, r13d
	add	r8d, 8
	zlib_inflate_needbits_reg r8d
	jmp	.mode_codelens_getbits
calign
.mode_codelens_gotbits:
	mov	edx, eax
	shr	edx, 16
	; eax contains here
	; ecx contains here.bits
	; edx == here.val
	cmp	edx, 16
	jb	.mode_codelens_lowval
	je	.mode_codelens_16
	cmp	edx, 17
	je	.mode_codelens_17
	; final else
	mov	r8d, ecx
	add	r8d, 7
	mov	r9d, ecx		; save here.bits
	zlib_inflate_needbits_reg r8d	; NEEDBITS(here.bits + 7)
	zlib_inflate_dropbits_reg r9d	; DROPBITS(here.bits)
	xor	r10d, r10d		; len = 0
	mov	r11d, r12d
	and	r11d, 127
	add	r11d, 11		; copy = 11 + BITS(7)
	zlib_inflate_dropbits 7
	jmp	.mode_codelens_lencopyset
calign
.mode_codelens_lowval:
	; state->lens[state->have++] = here.val
	mov	esi, dword [rbx+zlib_istate_have_ofs]
	lea	rdi, [rbx+zlib_istate_lens_ofs]
	mov	word [rdi+rsi*2], dx
	add	esi, 1
	mov	dword [rbx+zlib_istate_have_ofs], esi
	mov	r8d, ecx
	zlib_inflate_dropbits_reg r8d
	jmp	.mode_codelens	; back to the outermost while
calign
.mode_codelens_16:
	mov	r8d, ecx
	add	r8d, 2
	mov	r9d, ecx	; save here.bits
	zlib_inflate_needbits_reg r8d	; NEEDBITS(here.bits + 2)
	zlib_inflate_dropbits_reg r9d	; DROPBITS(here.bits)
	lea	rdi, [rbx+zlib_istate_lens_ofs]
	mov	esi, dword [rbx+zlib_istate_have_ofs]
	test	esi, esi
	jz	.mode_bad		; invalid bit length repeat
	sub	esi, 1
	movzx	r10d, word [rdi+rsi*2]	; len = state->lens[state->have - 1]
	mov	r11d, r12d
	and	r11d, 3
	add	r11d, 3			; copy = 3 + BITS(2)
	zlib_inflate_dropbits 2
	jmp	.mode_codelens_lencopyset
calign
.mode_codelens_17:
	mov	r8d, ecx
	add	r8d, 3
	mov	r9d, ecx	; save here.bits
	zlib_inflate_needbits_reg r8d	; NEEDBITS(here.bits + 3)
	zlib_inflate_dropbits_reg r9d	; DROPBITS(here.bits)
	xor	r10d, r10d		; len = 0
	mov	r11d, r12d
	and	r11d, 7
	add	r11d, 3			; copy = 3 + BITS(3)
	zlib_inflate_dropbits 3
	jmp	.mode_codelens_lencopyset
calign
.mode_codelens_lencopyset:
	mov	esi, dword [rbx+zlib_istate_have_ofs]
	lea	rdi, [rbx+zlib_istate_lens_ofs]
	mov	ecx, esi
	add	ecx, r11d
	mov	eax, dword [rbx+zlib_istate_nlen_ofs]
	add	eax, dword [rbx+zlib_istate_ndist_ofs]
	cmp	ecx, eax
	ja	.mode_bad		; invalid bit length repeat
	; otherwise, while (copy--) state->lens[state->have++] = (unsigned short)len
calign
.mode_codelens_lenloop:
	mov	word [rdi+rsi*2], r10w
	add	esi, 1
	sub	r11d, 1
	jnz	.mode_codelens_lenloop
	mov	dword [rbx+zlib_istate_have_ofs], esi
	jmp	.mode_codelens	; back to the outermost while
	
calign
.mode_codelens_whiledone:
	; check for end-of-block code
	lea	rdi, [rbx+zlib_istate_lens_ofs]
	cmp	word [rdi+512], 0
	je	.mode_bad		; invalid code -- missing end-of-block

	; build code tables
	lea	rax, [rbx+zlib_istate_codes_ofs]
	mov	[rbx+zlib_istate_next_ofs], rax
	mov	[rbx+zlib_istate_lencode_ofs], rax
	mov	dword [rbx+zlib_istate_lenbits_ofs], 9
	mov	dword [rbx+zlib_istate_lenbitsmask_ofs], 511	; 1 shl 9 - 1
	mov	edi, zlib_inftree_lens
	lea	rsi, [rbx+zlib_istate_lens_ofs]
	mov	edx, dword [rbx+zlib_istate_nlen_ofs]
	lea	rcx, [rbx+zlib_istate_next_ofs]
	lea	r8, [rbx+zlib_istate_lenbits_ofs]
	lea	r9, [rbx+zlib_istate_work_ofs]
	call	.inflate_table

	; do the calculation of lenbitsmask once
	mov	edx, 1
	mov	ecx, [rbx+zlib_istate_lenbits_ofs]
	shl	edx, cl
	sub	edx, 1
	mov	[rbx+zlib_istate_lenbitsmask_ofs], edx

	test	eax, eax
	jz	.mode_bad				; invalid literal/lengths set

	mov	rax, [rbx+zlib_istate_next_ofs]
	mov	[rbx+zlib_istate_distcode_ofs], rax
	mov	dword [rbx+zlib_istate_distbits_ofs], 6
	mov	dword [rbx+zlib_istate_distbitsmask_ofs], 63	; 1 shl 6 - 1
	mov	edi, zlib_inftree_dists
	lea	rsi, [rbx+zlib_istate_lens_ofs]
	mov	eax, dword [rbx+zlib_istate_nlen_ofs]
	shl	eax, 1
	add	rsi, rax				; state->lens + state->nlen
	mov	edx, dword [rbx+zlib_istate_ndist_ofs]
	lea	rcx, [rbx+zlib_istate_next_ofs]
	lea	r8, [rbx+zlib_istate_distbits_ofs]
	lea	r9, [rbx+zlib_istate_work_ofs]
	call	.inflate_table

	; do the calculation of distbitsmask
	mov	edx, 1
	mov	ecx, [rbx+zlib_istate_distbits_ofs]
	shl	edx, cl
	sub	edx, 1
	mov	[rbx+zlib_istate_distbitsmask_ofs], edx

	test	eax, eax
	jz	.mode_bad				; invalid distances set

	mov	dword [rbx+zlib_istate_mode_ofs], zmode_len_
	cmp	dword [rbx+zlib_istate_flush_ofs], zlib_trees
	je	.inf_leave
	; fallthrough to .mode_len_
calign
.mode_len_:
	; why do we do this?
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_len
	; fallthrough to .mode_len
calign
.mode_len:
	; uggh, HACKOLA, TODO: fix this properly, ughgh
	; ok so, inflate_fast and the have/bailout logic assumes that the bits in our hold is <8, so we effectively have to unwind them _the first_ time this happens
	
	mov	rax, [r14+buffer_user_ofs+8]
	mov	eax, r13d
	shr	eax, 3
	; subtract that from our user pointer/length
	sub	qword [r14+buffer_user_ofs], rax
	add	qword [r14+buffer_user_ofs+8], rax
	shl	eax, 3
	sub	r13d, eax
	mov	ecx, r13d
	mov	edx, 1
	shl	edx, cl
	sub	edx, 1
	and	r12, rdx


	cmp	qword [r14+buffer_user_ofs+8], 6
	; cmp	dword [rbx+zlib_istate_have_ofs], 6	hmmm, since we use the buffer user vars directly, this i think is incorrect
	jb	.mode_len_noinflate
	; else, we have >= 6, so inflate_fast(strm, out) inlined here, with mods to use the pre-existing accumulator
	
	mov	rax, [rbx+zlib_istate_orig_outlength_ofs]
	mov	[rbx+zlib_istate_beg_ofs], rax

	; set fastlast to whatever we actually have left - 5
	mov	rax, [r14+buffer_user_ofs]		; our current pointer
	add	rax, [r14+buffer_user_ofs+8]		; + how many bytes we have left
	sub	rax, 5
	mov	[rbx+zlib_istate_fastlast_ofs], rax

	; TODO: zlib_istate_beg_ofs and zlib_istate_orig_outlength_ofs do the same thing, but didn't when I first translated all this
	; so it will be safe to remove one of them
	
calign
.mode_len_inflate_fast_top:

	; hmmm, this is NQR: zlib_inflate_need6bytes
	zlib_inflate_fastcheck

	mov	rdi, r15
	mov	esi, 258
	call	buffer$reserve					; this is not an expensive call if there is room available

	mov	r8, [rbx+zlib_istate_lencode_ofs]
	mov	eax, r12d
	and	eax, dword [rbx+zlib_istate_lenbitsmask_ofs]	; hold & lmask
	mov	eax, dword [r8+rax*4]				; here = lcode[hold & lmask]
calign
.mode_len_inflate_fast_dolen:
	mov	r8d, eax
	shr	r8d, 8
	and	r8d, 0xff	; here.bits (op)
	zlib_inflate_dropbits_reg r8d				; this doesn't blast eax, but does blast ecx for the shr
	movzx	r8d, al		; here.op
	test	r8d, r8d
	jz	.mode_len_inflate_fast_literal
	test	r8d, 16
	jnz	.mode_len_inflate_fast_length_base
	test	r8d, 64
	jz	.mode_len_inflate_fast_2ndlevellength
	test	r8d, 32
	jz	.mode_bad					; invalid literal/length code
	; otherwise, end of block
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_type
	mov	dword [rbx+zlib_istate_back_ofs], -1
	jmp	.mode_type
calign
.mode_len_inflate_fast_literal:
	mov	rdi, r15
	mov	esi, eax
	shr	esi, 16						; here.val
	call	buffer$append_byte_noreserve
	jmp	.mode_len_inflate_fast_nextiteration		; check our while condition
calign
.mode_len_inflate_fast_length_base:
	mov	r10d, eax
	shr	r10d, 16					; len = here.val
	and	r8d, 15						; op &= 15 (extra bits)
	test	r8d, r8d
	jz	.mode_len_inflate_fast_length_base_noextra
	cmp	r13d, r8d
	jae	.mode_len_inflate_fast_noadd
	zlib_inflate_fastcheck2
calign
.mode_len_inflate_fast_noadd:
	; we need to do len += hold & ((1U << op) - 1)
	mov	edx, 1
	mov	ecx, r8d
	shl	edx, cl
	sub	edx, 1
	mov	ecx, r12d
	and	ecx, edx					; hold & ((1 << op) - 1)
	add	r10d, ecx					; len += ""
	zlib_inflate_dropbits_reg r8d				; hold >>= op, bits -= op
calign
.mode_len_inflate_fast_length_base_noextra:
	zlib_inflate_fastcheck
	; here = dcode[hold & dmask]
	mov	r8, [rbx+zlib_istate_distcode_ofs]
	mov	eax, r12d
	and	eax, dword [rbx+zlib_istate_distbitsmask_ofs]	; hold & dmask
	mov	eax, dword [r8+rax*4]				; here = dcode[hold & dmask]
calign
.mode_len_inflate_fast_dodist:
	mov	r8d, eax
	shr	r8d, 8
	and	r8d, 0xff	; here.bits (op)
	zlib_inflate_dropbits_reg r8d				; this doesn't blast eax, but does blast ecx for the shr
	movzx	r8d, al		; here.op
	test	r8d, 16
	jnz	.mode_len_inflate_fast_distbase
	test	r8d, 64
	jnz	.mode_bad					; invalid distance code
	; else, 2nd level distance code
	; so, here = dcode[here.val + (hold & ((1U << op) - 1))]
	mov	r9, [rbx+zlib_istate_distcode_ofs]
	; here.val == high word in eax
	; op is in r8b
	mov	edx, 1
	mov	ecx, r8d
	shl	edx, cl						; 1 << op
	sub	edx, 1						; - 1
	mov	ecx, r12d
	and	ecx, edx					; hold & ((1 << op) - 1)
	shr	eax, 16						; here.val
	add	eax, ecx
	mov	eax, dword [r9+rax*4]				; here = dcode[here.val + (hold & ((1U << op) - 1))]
	jmp	.mode_len_inflate_fast_dodist
calign
.mode_len_inflate_fast_distbase:
	mov	r11d, eax
	shr	r11d, 16					; dist = here.val
	and	r8d, 15						; op &= 15 (extra bits)
	cmp	r13d, r8d
	jae	.mode_len_inflate_fast_distbase_noadd
	zlib_inflate_fastcheck2
	cmp	r13d, r8d
	jae	.mode_len_inflate_fast_distbase_noadd
	zlib_inflate_fastcheck2
calign
.mode_len_inflate_fast_distbase_noadd:
	; we need to do dist += hold & ((1U << op) - 1)
	mov	edx, 1
	mov	ecx, r8d
	shl	edx, cl
	sub	edx, 1
	mov	ecx, r12d
	and	ecx, edx					; hold & ((1 << op) - 1)
	add	r11d, ecx					; dist += ""
	zlib_inflate_dropbits_reg r8d				; hold >>= op, bits -= op
	
	mov	r8, [r15+buffer_length_ofs]
	sub	r8, qword [rbx+zlib_istate_beg_ofs]		; max distance in output
	cmp	r11, r8						; see if copy from window
	ja	.mode_len_inflate_fast_fromwindow
	; else, copy direct from output
	; note: since we did a reserve atop for the output buffer, this should be okay since the buffer won't expand
	mov	rdi, r15
	mov	rsi, [r15+buffer_length_ofs]
	sub	rsi, r11
	add	rsi, [r15+buffer_itself_ofs]			; out - dist
	mov	edx, r10d					; length

	; _wow_ I am gobsmacked by this little gem...
	; SO, it happens that distance can be _less_ than length, which means that the reference zlib
	; _relies_ on byte for byte copies.... that was not my idea of fun figuring out.
	; so if distance is less than length, then we didn't go as far BACK in the output as the lenght of our new goods
	; and thus _replicate_ the byte(s) at the end, what a mess

	; so, everywhere we do out - dist, we have to determine whether this condition happens
	; and fallback to byte by byte copies like the reference version does
	cmp	r11, r10
	jb	.mode_len_inflate_fast_distbase_bytebybyte

	call	buffer$append
	jmp	.mode_len_inflate_fast_nextiteration		; check our while condition
calign
.mode_len_inflate_fast_distbase_bytebybyte:
	; see above commentary about why this is necessary
	mov	rdi, [r15+buffer_endptr_ofs]
	mov	rcx, rdx
calign
.mode_len_inflate_fast_distbase_byteloop:
	movzx	eax, byte [rsi]
	mov	byte [rdi], al
	add	rsi, 1
	add	rdi, 1
	sub	rcx, 1
	jnz	.mode_len_inflate_fast_distbase_byteloop
	; update endptr/length
	add	qword [r15+buffer_endptr_ofs], rdx
	add	qword [r15+buffer_length_ofs], rdx

	jmp	.mode_len_inflate_fast_nextiteration		; check our while condition

calign
.mode_len_inflate_fast_fromwindow:
	mov	eax, r11d					; dist
	sub	eax, r8d					; - op
	mov	r8d, eax					; op=
	cmp	eax, dword [rbx+zlib_istate_whave_ofs]
	ja	.mode_len_inflate_fast_fromwindow_case1
calign
.mode_len_inflate_fast_fromwindow_case2:
	mov	r9d, dword [rbx+zlib_istate_wnext_ofs]
	test	r9d, r9d
	jz	.mode_len_inflate_fast_fromwindow_case3
	cmp	r9d, r8d
	jb	.mode_len_inflate_fast_fromwindow_case4
	; else, contiguous in window
	mov	esi, r9d					; from = wnext
	sub	esi, r8d					; - op
	add	rsi, qword [rbx+zlib_istate_window_ofs]		; + window
	cmp	r8d, r10d					; op < len?
	jae	.mode_len_inflate_fast_restfromoutput
	; some from window
	sub	r10d, r8d					; len -= op
	mov	edx, r8d					; amount to copy from window
	mov	rdi, r15
	push	r10 r11						; save dist and len
	call	buffer$append
	pop	r11 r10
	mov	rsi, [r15+buffer_length_ofs]
	sub	rsi, r11
	add	rsi, [r15+buffer_itself_ofs]			; from = out - dist
	jmp	.mode_len_inflate_fast_restfromoutput
calign
.mode_len_inflate_fast_fromwindow_case4:
	; wrap around window
	mov	esi, dword [rbx+zlib_istate_wsize_ofs]		; from = wsize
	add	esi, dword [rbx+zlib_istate_wnext_ofs]		; + wnext
	sub	esi, r8d					; - op
	add	rsi, qword [rbx+zlib_istate_window_ofs]		; + window
	sub	r8d, dword [rbx+zlib_istate_wnext_ofs]		; op -= wnext
	cmp	r8d, r10d					; op < len?
	jae	.mode_len_inflate_fast_restfromoutput
	; else, some from end of window
	sub	r10d, r8d					; len -= op
	mov	edx, r8d					; amount to copy from window
	mov	rdi, r15
	push	r8 r10 r11					; save op, dist and len
	call	buffer$append
	pop	r11 r10 r8
	mov	rsi, qword [rbx+zlib_istate_window_ofs]
	cmp	dword [rbx+zlib_istate_wnext_ofs], r10d		; wnext < len?
	jae	.mode_len_inflate_fast_restfromoutput
	; some from start of the window
	mov	r8d, dword [rbx+zlib_istate_wnext_ofs]		; op = wnext
	sub	r10d, r8d					; len -= op
	mov	edx, r8d
	mov	rdi, r15
	push	r10 r11
	call	buffer$append
	pop	r11 r10
	mov	rsi, [r15+buffer_length_ofs]
	sub	rsi, r11
	add	rsi, [r15+buffer_itself_ofs]			; from = out - dist
	jmp	.mode_len_inflate_fast_restfromoutput
calign
.mode_len_inflate_fast_fromwindow_case3:
	; very common case
	mov	esi, dword [rbx+zlib_istate_wsize_ofs]		; from = wsize
	sub	esi, r8d					; - op
	add	rsi, qword [rbx+zlib_istate_window_ofs]		; + window
	cmp	r8d, r10d
	jae	.mode_len_inflate_fast_restfromoutput
	; some from window
	sub	r10d, r8d					; len =- op
	mov	edx, r8d					; amount to copy from window
	mov	rdi, r15
	push	r10 r11						; save dist and len
	call	buffer$append
	pop	r11 r10
	mov	rsi, [r15+buffer_length_ofs]
	sub	rsi, r11
	add	rsi, [r15+buffer_itself_ofs]			; from = out - dist
	jmp	.mode_len_inflate_fast_restfromoutput
calign
.mode_len_inflate_fast_fromwindow_case1:
	cmp	dword [rbx+zlib_istate_sane_ofs], 0
	je	.mode_len_inflate_fast_fromwindow_case2
	jmp	.mode_bad					; invalid distance too far back
calign
.mode_len_inflate_fast_restfromoutput:
	; from in rsi already setup, and len in r10d should be valid
	mov	rdi, r15
	mov	edx, r10d
	call	buffer$append
	jmp	.mode_len_inflate_fast_nextiteration		; check our while condition
calign
.mode_len_inflate_fast_2ndlevellength:
	; here = lcode[here.val + (hold & ((1U << op) - 1))]
	mov	r9, [rbx+zlib_istate_lencode_ofs]		; get lcode ready
	; here.val == high word in eax
	; op is in r8b
	mov	edx, 1
	mov	ecx, r8d
	shl	edx, cl
	sub	edx, 1
	mov	ecx, r12d
	and	ecx, edx					; hold & ((1 << op) - 1)
	shr	eax, 16						; here.val
	add	eax, ecx
	mov	eax, dword [r9+rax*4]				; here = lcode[here.val + (hold & ((1U << op) - 1))]
	jmp	.mode_len_inflate_fast_dolen

calign
.mode_len_inflate_fast_nextiteration:
	; he has a ...do while...
	; we set fastlast to the current buffer pointer - 5, so we can compare what is sitting in the user buffer now against it
	mov	rax, [r14+buffer_user_ofs]
	cmp	rax, [rbx+zlib_istate_fastlast_ofs]
	jb	.mode_len_inflate_fast_top
	; otherwise, fall back out to mode_len

	mov	eax, r13d
	shr	eax, 3

	; subtract that from our user pointer/length
	sub	qword [r14+buffer_user_ofs], rax
	add	qword [r14+buffer_user_ofs+8], rax
	shl	eax, 3
	sub	r13d, eax
	mov	ecx, r13d
	mov	edx, 1
	shl	edx, cl
	sub	edx, 1
	and	r12, rdx

	jmp	.mode_len

calign
.mode_len_noinflate:
	; so if have < 6 and mode == zmode_len, we end up here
	mov	dword [rbx+zlib_istate_back_ofs], 0

calign
.mode_len_getbits:
	; accum in r12, bits in r13d
	mov	rsi, [rbx+zlib_istate_lencode_ofs]
	mov	edx, dword [rbx+zlib_istate_lenbitsmask_ofs]
	mov	ecx, r12d
	and	ecx, edx
	mov	eax, [rsi+rcx*4]			; here = state->lencode[BITS(state->lenbits)]
	movzx	ecx, ah					; here.bits
	cmp	ecx, r13d
	jbe	.mode_len_gotbits
	; else, we need MORE bits... but we don't want to necessarily assume that a dword would do the trick
	; hmmm... TODO: see how many times this thing actually gets called, and monitor the bit accumulator
	; ... the REASON we can't just say "hey gimme 32 bits" is because this code might not actually need that many
	; and we'd be falsely stating that we did and prematurely bailing out if in fact there were enough here
	; already ... hmmm
	mov	r8d, r13d
	add	r8d, 8
	zlib_inflate_needbits_reg r8d
	jmp	.mode_len_getbits
calign
.mode_len_gotbits:
	; if (here.op && (here.op & 0xf0) == 0)
	test	al, al					; here.op ?
	jz	.mode_len_nolast
	test	al, 0xf0
	jnz	.mode_len_nolast
	; similar to the above getbits, but we need: here = state->lencode[last.val + (BITS(last.bits + last.op) >> last.bits)]
	; and the enough check to be last.bits + here.bits
	mov	r11d, eax
	shr	r11d, 16				; r11d == last.val
	movzx	ecx, al
	movzx	edx, ah
	mov	r9d, edx				; last.bits
	add	ecx, edx				
	mov	r10d, 1
	shl	r10d, cl
	sub	r10d, 1					; r10d == mask for BITS(last.bits + last.op)

calign
.mode_len_getlastbits:
	mov	rsi, [rbx+zlib_istate_lencode_ofs]
	mov	ecx, r9d
	mov	edx, r12d
	and	edx, r10d
	shr	edx, cl
	add	edx, r11d
	mov	eax, [rsi+rdx*4]			; here = state->lencode[last.val + (BITS(last.bits + last.op) >> last.bits)]
	movzx	ecx, ah					; here.bits
	add	ecx, r9d				; + last.bits
	cmp	ecx, r13d
	jbe	.mode_len_gotlastbits
	; else, we need MORE bits
	mov	r8d, r13d
	add	r8d, 8
	zlib_inflate_needbits_reg r8d
	jmp	.mode_len_getlastbits
calign
.mode_len_dolit:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_lit
	jmp	.mode_lit
calign
.mode_len_eob:
	mov	dword [rbx+zlib_istate_back_ofs], -1
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_type
	jmp	.mode_type
calign
.mode_len_gotlastbits:
	zlib_inflate_dropbits_reg r9d			; DROPBITS(last.bits)
	add	dword [rbx+zlib_istate_back_ofs], r9d
calign
.mode_len_nolast:
	movzx	edx, ah
	mov	r8d, edx				; here.bits
	zlib_inflate_dropbits_reg r8d			; DROPBITS(here.bits)
	add	dword [rbx+zlib_istate_back_ofs], r8d
	mov	r9d, eax
	shr	r9d, 16


	; wow, I was tired or something when I typed this: add	dword [rbx+zlib_istate_back_ofs], r9d	; state->length += here.val
	; should be:
	mov	dword [rbx+zlib_istate_length_ofs], r9d	; state->length = (unsigned)here.val


	test	al, al
	jz	.mode_len_dolit
	test	al, 32
	jnz	.mode_len_eob
	test	al, 64
	jnz	.mode_bad				; invalid literal/length code
	; otherwise, set extra to op & 15
	; then mode to lenext, and fallthrough
	movzx	r9d, al
	and	r9d, 15
	mov	dword [rbx+zlib_istate_extra_ofs], r9d
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_lenext
	; fallthrough to .mode_lenext
calign
.mode_lenext:
	mov	r8d, dword [rbx+zlib_istate_extra_ofs]
	test	r8d, r8d
	jnz	.mode_lenext_extrabits
	mov	r9d, dword [rbx+zlib_istate_length_ofs]
	mov	dword [rbx+zlib_istate_was_ofs], r9d	; state->was = state->length
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_dist
	jmp	.mode_dist
calign
.mode_lenext_extrabits:
	zlib_inflate_needbits_reg r8d			; NEEDBITS(state->extra)
	mov	edx, 1
	mov	ecx, r8d
	shl	edx, cl
	sub	edx, 1
	mov	eax, r12d
	and	eax, edx				; BITS(state->extra)
	add	dword [rbx+zlib_istate_length_ofs], eax
	zlib_inflate_dropbits_reg r8d			; DROPBITS(state->extra)
	add	dword [rbx+zlib_istate_back_ofs], r8d	; state->back += state->extra
	mov	r9d, dword [rbx+zlib_istate_length_ofs]
	mov	dword [rbx+zlib_istate_was_ofs], r9d
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_dist
	; fallthrough to .mode_dist
calign
.mode_dist:
	; accum in r12, bits in r13d
	mov	rsi, [rbx+zlib_istate_distcode_ofs]
	mov	edx, dword [rbx+zlib_istate_distbitsmask_ofs]
	mov	ecx, r12d
	and	ecx, edx
	mov	eax, [rsi+rcx*4]			; here = state->distcode[BITS(state->distbits)]
	movzx	ecx, ah					; here.bits
	cmp	ecx, r13d
	jbe	.mode_dist_gotbits
	; else, we need MORE bits... but we don't want to necessarily assume that a dword would do the trick
	; hmmm... TODO: see how many times this thing actually gets called, and monitor the bit accumulator
	; ... the REASON we can't just say "hey gimme 32 bits" is because this code might not actually need that many
	; and we'd be falsely stating that we did and prematurely bailing out if in fact there were enough here
	; already ... hmmm
	mov	r8d, r13d
	add	r8d, 8
	zlib_inflate_needbits_reg r8d
	jmp	.mode_dist
calign
.mode_dist_gotbits:
	; if (here.op && (here.op & 0xf0) == 0)
	test	al, 0xf0
	jnz	.mode_dist_nolast
	; similar to the above getbits, but we need: here = state->distcode[last.val + (BITS(last.bits + last.op) >> last.bits)]
	; and the enough check to be last.bits + here.bits
	mov	r11d, eax
	shr	r11d, 16				; r11d == last.val
	movzx	ecx, al
	movzx	edx, ah
	mov	r9d, edx				; last.bits
	add	ecx, edx				
	mov	r10d, 1
	shl	r10d, cl
	sub	r10d, 1					; r10d == mask for BITS(last.bits + last.op)

calign
.mode_dist_getlastbits:
	mov	rsi, [rbx+zlib_istate_distcode_ofs]
	mov	ecx, r9d
	mov	edx, r12d
	and	edx, r10d
	shr	edx, cl
	add	edx, r11d
	mov	eax, [rsi+rdx*4]			; here = state->distcode[last.val + (BITS(last.bits + last.op) >> last.bits)]
	movzx	ecx, ah					; here.bits
	add	ecx, r9d				; + last.bits
	cmp	ecx, r13d
	jbe	.mode_dist_gotlastbits
	; else, we need MORE bits
	mov	r8d, r13d
	add	r8d, 8
	zlib_inflate_needbits_reg r8d
	jmp	.mode_dist_getlastbits
calign
.mode_dist_gotlastbits:
	zlib_inflate_dropbits_reg r9d			; DROPBITS(last.bits)
	add	dword [rbx+zlib_istate_back_ofs], r9d	; state->back += last.bits
calign
.mode_dist_nolast:
	movzx	edx, ah
	mov	r8d, edx				; here.bits
	zlib_inflate_dropbits_reg r8d			; DROPBITS(here.bits)
	add	dword [rbx+zlib_istate_back_ofs], r8d	; state->back += here.bits
	test	al, 64
	jnz	.mode_bad				; invalid distance code
	mov	ecx, eax
	shr	ecx, 16
	mov	dword [rbx+zlib_istate_offset_ofs], ecx	; state->offset = here.val
	and	eax, 15
	mov	dword [rbx+zlib_istate_extra_ofs], eax
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_distext
	; fallthrough to .mode_distext
calign
.mode_distext:
	mov	r8d, dword [rbx+zlib_istate_extra_ofs]
	test	r8d, r8d
	jnz	.mode_distext_extrabits
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_match
	jmp	.mode_match
calign
.mode_distext_extrabits:
	zlib_inflate_needbits_reg r8d			; NEEDBITS(state->extra)
	mov	edx, 1
	mov	ecx, r8d
	shl	edx, cl
	sub	edx, 1
	mov	eax, r12d
	and	eax, edx				; BITS(state->extra)
	add	dword [rbx+zlib_istate_offset_ofs], eax	; state->offset += BITS(state->extra)
	zlib_inflate_dropbits_reg r8d			; DROPBITS(state->extra)
	add	dword [rbx+zlib_istate_back_ofs], r8d	; state->back += state->extra
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_match
	; fallthrough to .mode_match
calign
.mode_match:
	; make sure we reserve at least 258 bytes in our output buffer so that it doesn't relocate on us when we append
	mov	rdi, r15
	mov	esi, 258
	call	buffer$reserve
	; copy == number of bytes occupied in our output buffer
	mov	r10, [r15+buffer_length_ofs]		; copy == output buffer occupied
	mov	r11d, [rbx+zlib_istate_offset_ofs]
	cmp	r11, r10				; 64 bit compares here might be important (only if output buffer is _huge_)
	ja	.mode_match_fromwindow			; offset > copy, if so, from window it is
	; else, we copy from the output
	mov	rsi, [r15+buffer_itself_ofs]
	add	rsi, r10
	sub	rsi, r11				; from = "put" - offset
	mov	edx, dword [rbx+zlib_istate_length_ofs]
	jmp	.mode_match_docopy
calign
.mode_match_fromwindow:
	sub	r11, r10				; copy = offset - copy
	cmp	r11d, dword [rbx+zlib_istate_whave_ofs]
	jbe	.mode_match_fromwindow_okay
	cmp	dword [rbx+zlib_istate_sane_ofs], 0
	jne	.mode_bad				; invalid distance too far back
calign
.mode_match_fromwindow_okay:
	cmp	r11d, dword [rbx+zlib_istate_wnext_ofs]
	ja	.mode_match_fromwindow_copyadjust
	; else, from = state->window + (state->wnext - copy)
	mov	esi, dword [rbx+zlib_istate_wnext_ofs]
	sub	esi, r11d
	add	rsi, qword [rbx+zlib_istate_window_ofs]
	mov	edx, r11d
	mov	ecx, dword [rbx+zlib_istate_length_ofs]
	cmp	edx, ecx
	cmova	edx, ecx
	jmp	.mode_match_docopy
calign
.mode_match_fromwindow_copyadjust:
	sub	r11d, dword [rbx+zlib_istate_wnext_ofs]	; copy -= state->wnext
	
	mov	esi, dword [rbx+zlib_istate_wsize_ofs]
	sub	esi, r11d
	add	rsi, qword [rbx+zlib_istate_window_ofs]		; from = window + (wsize - copy)

	mov	edx, r11d
	mov	ecx, dword [rbx+zlib_istate_length_ofs]
	cmp	edx, ecx
	cmova	edx, ecx
	; fallthrough to .mode_match_docopy
calign
.mode_match_docopy:
	; copy is in edx, from is in rsi
	sub	dword [rbx+zlib_istate_length_ofs], edx	; state->length -= copy

	; well, isn't that pleasant... do in the reference, they do a byte by byte forward walk to copy it
	; turns out, this is quite important, if we do a normal buffer$append/memcpy/etc, we can walk off 
	; the end of the buffer

	; so, like the reference version, we too need to do a byte by byte walk
	; the old way here would have been considerably faster
	; old way: mov	rdi, r15
	; old way: call	buffer$append
	test	edx, edx
	jz	.mode_match_nocopy
	mov	rdi, [r15+buffer_endptr_ofs]
	add	qword [r15+buffer_length_ofs], rdx
	add	qword [r15+buffer_endptr_ofs], rdx
	xor	ecx, ecx
calign
.mode_match_copyloop:
	movzx	eax, byte [rsi+rcx]
	mov	[rdi+rcx], al
	add	ecx, 1
	sub	edx, 1
	jnz	.mode_match_copyloop
calign
.mode_match_nocopy:
	mov	edx, [rbx+zlib_istate_mode_ofs]
	mov	ecx, zmode_len
	cmp	dword [rbx+zlib_istate_length_ofs], 0
	cmove	edx, ecx
	mov	[rbx+zlib_istate_mode_ofs], edx
	je	.mode_len
	jmp	.mode_match
calign
.mode_lit:
	mov	esi, dword [rbx+zlib_istate_length_ofs]
	mov	rdi, r15
	call	buffer$append_byte_noreserve
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_len
	jmp	.mode_len
calign
.mode_check:
	cmp	dword [rbx+zlib_istate_wrap_ofs], 0
	je	.mode_check_nowrap
	zlib_inflate_needbits 32
	mov	rsi, [rbx+zlib_istate_streamp_ofs]
	mov	rdx, [r15+buffer_length_ofs]
	sub	rdx, qword [rbx+zlib_istate_orig_outlength_ofs]
	add	qword [rsi+zlib_totalout_ofs], rdx
	add	qword [rbx+zlib_istate_total_ofs], rdx
	mov	rdi, [rbx+zlib_istate_check_ofs]
	mov	rsi, [r15+buffer_itself_ofs]
	add	rsi, qword [rbx+zlib_istate_orig_outlength_ofs]
	cmp	dword [rbx+zlib_istate_flags_ofs], 0
	je	.mode_check_adler
	call	crc$32
	mov	[rbx+zlib_istate_check_ofs], rax	; store the result
	cmp	r12d, eax
	jne	.mode_bad			; incorrect data check
	jmp	.mode_check_updatedone
calign
.mode_check_adler:
	call	adler32
	mov	dword [rbx+zlib_istate_check_ofs], eax	; store the result
	mov	eax, r12d
	bswap	eax
	cmp	eax, dword [rbx+zlib_istate_check_ofs]
	jne	.mode_bad			; incorrect data check
	; fallthrough to mode_check_updatedone
calign
.mode_check_updatedone:
	zlib_inflate_dropbits 32
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_length
	jmp	.mode_length
calign
.mode_check_nowrap:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_length
	; fallthrough to .mode_length
calign
.mode_length:
	mov	dword [rbx+zlib_istate_mode_ofs], zmode_done
	cmp	dword [rbx+zlib_istate_wrap_ofs], 0
	je	.mode_done
	cmp	dword [rbx+zlib_istate_flags_ofs], 0
	je	.mode_done
	zlib_inflate_needbits 32
	mov	rcx, [rbx+zlib_istate_total_ofs]
	cmp	ecx, r12d
	jne	.mode_bad			; incorrect length check
	; fallthrough to .mode_done
calign
.mode_done:
	xor	r12d, r12d
	xor	r13d, r13d
	; we want to return a 1 in eax for successful return, but cleanup all our state information as well
	; the reference version jumps straight to inf_leave here... hmmm
	mov	[rbx+zlib_istate_hold_ofs], r12
	mov	[rbx+zlib_istate_bits_ofs], r13d
	mov	rdi, r14
	call	buffer$reset			; clear our input buffer, cuz presumably we exhausted it
	; all our goods are completed, so we really don't have to do much else
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.mode_bad:
.mode_mem:
.mode_sync:
	; it is presumed that we won't be called again with this (now invalid) state
	; so we don't have to do much cleanup
	; we want to return a 0 in eax for failed return
	mov	[rbx+zlib_istate_hold_ofs], r12
	mov	[rbx+zlib_istate_bits_ofs], r13d
	mov	rdi, r14
	call	buffer$reset			; clear our input buffer, cuz presumably we exhausted it
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.inf_leave:
	; this means we ran out of input
	mov	[rbx+zlib_istate_hold_ofs], r12
	mov	[rbx+zlib_istate_bits_ofs], r13d
	mov	rdi, r14
	call	buffer$reset			; clear our input buffer, cuz presumably we exhausted it
	; we know mode < bad, and can't be check

	; updatewindow inlined here:
	; note: at our init time, we go ahead and create a window and init wsize/wnext/whave
	mov	rdx, [r15+buffer_length_ofs]
	mov	rsi, [r15+buffer_itself_ofs]
	add	rsi, rdx
	sub	rdx, qword [rbx+zlib_istate_orig_outlength_ofs]
	; rdx == copy
	; rsi is the end of our output
	cmp	rdx, 32768
	jae	.inf_leave_wsize_or_better
	mov	r10d, 32768
	sub	r10d, dword [rbx+zlib_istate_wnext_ofs]	; dist = wsize - wnext
	cmp	r10d, edx
	cmova	r10d, edx
	mov	r11d, dword [rbx+zlib_istate_wnext_ofs]
	mov	rdi, [rbx+zlib_istate_window_ofs]
	add	rdi, r11
	sub	rsi, rdx				; end - copy
	push	rdx r10
	mov	edx, r10d				; dist is the amount
	call	memcpy
	pop	r10 rdx
	sub	rdx, r10				; copy -= dist
	test	rdx, rdx
	jnz	.inf_leave_window_copytwo
	add	dword [rbx+zlib_istate_wnext_ofs], r10d	; state->wnext += dist
	xor	ecx, ecx
	mov	edx, dword [rbx+zlib_istate_wnext_ofs]
	cmp	edx, 32768
	cmove	edx, ecx
	mov	dword [rbx+zlib_istate_wnext_ofs], edx
	mov	edx, dword [rbx+zlib_istate_whave_ofs]
	mov	ecx, edx
	add	ecx, r10d
	cmp	edx, 32768
	cmovb	edx, ecx
	mov	dword [rbx+zlib_istate_whave_ofs], edx
	jmp	.inf_leave_windowsweet
calign
.inf_leave_window_copytwo:
	mov	rsi, [r15+buffer_itself_ofs]
	add	rsi, qword [r15+buffer_length_ofs]
	sub	rsi, rdx				; end - copy == source
	; rdx == copy amount
	mov	rdi, [rbx+zlib_istate_window_ofs]
	push	rdx
	call	memcpy
	pop	rdx
	mov	dword [rbx+zlib_istate_wnext_ofs], edx	; wnext = copy
	mov	dword [rbx+zlib_istate_whave_ofs], 32768	; whave = wsize
	jmp	.inf_leave_windowsweet
calign
.inf_leave_wsize_or_better:
	sub	rsi, 32768
	mov	edx, 32768
	mov	rdi, [rbx+zlib_istate_window_ofs]
	call	memcpy
	mov	dword [rbx+zlib_istate_wnext_ofs], 0
	mov	dword [rbx+zlib_istate_whave_ofs], 32768
	; fallthrough to .inf_leave_windowsweet
calign
.inf_leave_windowsweet:
	; end of updatewindow, back to inf_leave goods

	mov	rsi, [rbx+zlib_istate_streamp_ofs]
	mov	rdx, [r15+buffer_length_ofs]
	sub	rdx, qword [rbx+zlib_istate_orig_outlength_ofs]
	add	qword [rsi+zlib_totalout_ofs], rdx
	add	qword [rbx+zlib_istate_total_ofs], rdx

	cmp	dword [rbx+zlib_istate_wrap_ofs], 0
	je	.inf_leave_nowrap
	mov	rdi, [rbx+zlib_istate_check_ofs]
	mov	rsi, [r15+buffer_itself_ofs]
	add	rsi, qword [rbx+zlib_istate_orig_outlength_ofs]
	cmp	dword [rbx+zlib_istate_flags_ofs], 0
	je	.inf_leave_adler
	call	crc$32
	mov	dword [rbx+zlib_istate_check_ofs], eax
	jmp	.inf_leave_nowrap
calign
.inf_leave_adler:
	call	adler32
	mov	[rbx+zlib_istate_check_ofs], eax
calign
.inf_leave_nowrap:
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog



dalign
.modejumps:
	dq	.mode_head, .mode_flags, .mode_time, .mode_os, .mode_exlen, .mode_extra, .mode_name, .mode_comment
	dq	.mode_hcrc, .mode_dictid, .mode_dict, .mode_type, .mode_typedo, .mode_stored, .mode_copy_, .mode_copy
	dq	.mode_table, .mode_lenlens, .mode_codelens, .mode_len_, .mode_len, .mode_lenext, .mode_dist
	dq	.mode_distext, .mode_match, .mode_lit, .mode_check, .mode_length, .mode_done, .mode_bad, .mode_mem
	dq	.mode_sync
calign
.error_return:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.inflate_table:
	; edi == type, rsi == lens (ushort *), edx == codes, rcx == *(code *)table, r8 = bits (uint *), r9 = work (ushort *)
	; unlike the reference version, we return eax == 1 on success, eax == 0 on fail
	push	rbp rbx r12 r13 r14 r15
	sub	rsp, 168
	xor	r10d, r10d
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	[rsp+40], r9
	; count at [rsp+48] for 32 bytes
	; offs at [rsp+80] for 32 bytes
	; 112+ unused
	mov	[rsp+48], r10
	mov	[rsp+56], r10
	mov	[rsp+64], r10
	mov	[rsp+72], r10
	mov	[rsp+80], r10		; preemptively set offs[1] = 0 (though we clear offs[0..3] of course)
calign
.inflate_table_acclens:
	movzx	eax, word [rsi+r10*2]
	add	r10d, 1
	add	word [rsp+rax*2+48], 1
	cmp	r10d, edx
	jb	.inflate_table_acclens
	; we'll keep root in ebp, max in ebx
	mov	ebp, dword [r8]
	mov	ebx, 15
calign
.inflate_table_boundcodelens:
	cmp	word [rsp+rbx*2+48], 0
	jne	.inflate_table_boundcodelens_maxdone
	sub	ebx, 1
	jnz	.inflate_table_boundcodelens
calign
.inflate_table_boundcodelens_maxdone:
	cmp	ebp, ebx
	cmova	ebp, ebx
	test	ebx, ebx
	jz	.inflate_table_nosymbols
	; we'll keep min in r12d
	mov	r12d, 1
calign
.inflate_table_boundcodelens_min:
	cmp	r12d, ebx
	jae	.inflate_table_boundcodelens_mindone
	cmp	word [rsp+r12*2+48], 0
	jne	.inflate_table_boundcodelens_mindone
	add	r12d, 1
	jmp	.inflate_table_boundcodelens_min
calign
.inflate_table_boundcodelens_mindone:
	cmp	ebp, r12d
	cmovb	ebp, r12d

	; check for an over-subscribed or incomplete set of lengths
	mov	r10d, 1		; len
	mov	r11d, 1		; left
calign
.inflate_table_checkoversub:
	cmp	r10d, 15
	ja	.inflate_table_checkoversubdone
	shl	r11d, 1
	movzx	eax, word [rsp+r10*2+48]
	sub	r11d, eax
	cmp	r11d, 0
	jl	.inflate_table_error	; over-subscribed
	add	r10d, 1
	jmp	.inflate_table_checkoversub
calign
.inflate_table_checkoversubdone:
	mov	r10d, 1			; get ready for next loop
	cmp	r11d, 0
	jle	.inflate_table_genoffs	; complete set
	; else, left > 0
	cmp	edi, zlib_inftree_codes	; type == CODES
	je	.inflate_table_error	; incomplete set
	cmp	ebx, 1			; max != 1
	jne	.inflate_table_error	; incomplete set
calign
.inflate_table_genoffs:
	; generate offsets into symbol table for each length for sorting
	xor	r11d, r11d		; we'll use this for sym for the loop
	cmp	r10d, 15
	jae	.inflate_table_symsort
	movzx	eax, word [rsp+r10*2+80]	; offs[len]
	add	ax, word [rsp+r10*2+48]		; + count[len]
	mov	word [rsp+r10*2+82], ax		; offs[len+1] =
	add	r10d, 1
	jmp	.inflate_table_genoffs
calign
.inflate_table_symsort:
	cmp	r11d, edx		; sym
	jae	.inflate_table_typecheck
	mov	r10d, r11d
	add	r10d, 1
	cmp	word [rsi+r11*2], 0
	cmove	r11d, r10d
	je	.inflate_table_symsort
	; otherwise, lens[sym] != 0, so we need to do:
	; work[offs[lens[sym]]++] = (ushort)sym;
	movzx	eax, word [rsi+r11*2]		; lens[sym]
	movzx	r10d, word [rsp+rax*2+80]	; offs[lens[sym]]
	add	word [rsp+rax*2+80], 1		; ++
	mov	word [r9+r10*2], r11w		; work[offs[lens[sym]]++] = sym
	add	r11d, 1
	jmp	.inflate_table_symsort
calign
.inflate_table_typecheck:
	mov	[rsp+112], rbp			; root
	mov	[rsp+120], rbx			; rbx
	mov	[rsp+128], rcx			; table
	cmp	edi, zlib_inftree_codes
	je	.inflate_table_codes
	cmp	edi, zlib_inftree_lens
	je	.inflate_table_lens
	; dists
	mov	r13d, ebp			; curr = root
	mov	r11, [rcx]			; next = *table
	mov	ecx, ebp
	mov	rbp, .inflate_table_dbase	; base
	mov	rbx, .inflate_table_dext	; extra
	mov	dword [rsp+136], -1		; end
	xor	edx, edx			; huff = 0
	xor	r8d, r8d			; sym = 0
	mov	r10d, r12d			; len = min
	xor	r14d, r14d			; drop = 0
	mov	r15d, -1			; low = -1
	mov	eax, 1
	shl	eax, cl
	cmp	eax, 592
	ja	.inflate_table_error		; type == DISTS && used > ENOUGH_DISTS (592) == insufficient space
	mov	dword [rsp+144], eax		; used = 1 << root
	sub	eax, 1
	mov	dword [rsp+152], eax		; mask = used - 1
	; next we need used limit
	mov	dword [rsp+160], 592		; used_limit = ENOUGH_DISTS = 592
	jmp	.inflate_table_mainloop
calign
.inflate_table_lens:
	mov	r13d, ebp			; curr = root
	mov	r11, [rcx]			; next = *table
	mov	ecx, ebp
	mov	rbp, .inflate_table_lbase	; base
	sub	rbp, 257 shl 1
	mov	rbx, .inflate_table_lext	; extra
	sub	rbx, 257 shl 1
	mov	dword [rsp+136], 256		; end
	xor	edx, edx			; huff = 0
	xor	r8d, r8d			; sym = 0
	mov	r10d, r12d			; len = min
	xor	r14d, r14d			; drop = 0
	mov	r15d, -1			; low = -1
	mov	eax, 1
	shl	eax, cl
	cmp	eax, 852
	ja	.inflate_table_error		; type == LENS && used > ENOUGH_LENS (852) == insufficient space
	mov	dword [rsp+144], eax		; used = 1 << root
	sub	eax, 1
	mov	dword [rsp+152], eax		; mask = used - 1
	; next we need used limit
	mov	dword [rsp+160], 852		; used_limit = ENOUGH_LENS = 852
	jmp	.inflate_table_mainloop
calign
.inflate_table_codes:
	mov	r13d, ebp			; curr = root
	mov	r11, [rcx]			; next = *table
	mov	ecx, ebp
	mov	rbp, r9				; base
	mov	rbx, r9				; extra
	mov	dword [rsp+136], 19		; end
	xor	edx, edx			; huff = 0
	xor	r8d, r8d			; sym = 0
	mov	r10d, r12d			; len = min
	xor	r14d, r14d			; drop = 0
	mov	r15d, -1			; low = -1
	mov	eax, 1
	shl	eax, cl
	mov	dword [rsp+144], eax		; used = 1 << root
	sub	eax, 1
	mov	dword [rsp+152], eax		; mask = used - 1
	; next we need used limit
	; because there really is no limit, lets just set it to 0xffff
	mov	dword [rsp+160], 0xffff		; used_limit is arbitrary large number
	; fallthrough to .inflate_table_mainloop

	; so at this point:
	; rbp		base
	; rbx		extra
	; edx		huff
	; r8d		sym
	; r9		work
	; r10d		len
	; r11		next
	; r12d		min
	; r13d		curr
	; r14d		drop
	; r15d		low
	; dword [rsp]	type
	; [rsp+8]	lens
	; [rsp+112]	root
	; [rsp+120]	max
	; [rsp+128]	table
	; [rsp+136]	end
	; [rsp+144]	used
	; [rsp+152]	mask
	; [rsp+160]	used_limit

	; edi/esi are more or less free
	; eax, ecx are free
calign
.inflate_table_mainloop:
	; op:8, bits:8, val:16
	movzx	ecx, word [r9+r8*2]	; work[sym]
	cmp	ecx, dword [rsp+136]
	jl	.inflate_table_mainloop_case1
	jg	.inflate_table_mainloop_case2
	; case3
	; low order byte == 96 (end of block), next byte: (len - drop), next word: 0
	mov	eax, r10d
	sub	eax, r14d
	shl	eax, 8
	or	eax, 0x60
	jmp	.inflate_table_mainloop_hereset
calign
.inflate_table_mainloop_case1:
	; low order byte == 0, next byte: (len - drop), next word: cx (work[sym])
	shl	ecx, 16
	mov	eax, r10d
	sub	eax, r14d
	shl	eax, 8
	or	eax, ecx
	jmp	.inflate_table_mainloop_hereset
calign
.inflate_table_mainloop_case2:
	; low order byte == extra[work[sym]] (extra[ecx]), next byte: (len - drop), next word: base[work[sym]] (base[ecx])
	movzx	eax, word [rbp+rcx*2]
	shl	eax, 16			; base[work[sym]]
	movzx	esi, word [rbx+rcx*2]	; extra[work[sym]]
	mov	ecx, r10d
	sub	ecx, r14d
	and	ecx, 0xff
	shl	ecx, 8
	or	eax, esi
	or	eax, ecx
	; fallthrough to .inflate_table_mainloop_hereset
calign
.inflate_table_mainloop_hereset:
	; here in eax is set

	; replicate for those indices with low len bits equal to huff


	mov	ecx, r10d
	sub	ecx, r14d	; len - drop

	; edi == incr, esi == fill
	mov	edi, 1
	mov	esi, 1
	shl	edi, cl		; incr = 1 shl (len - drop)
	mov	ecx, r13d	; curr
	shl	esi, cl		; fill = 1 shl (curr)

	mov	r12d, esi	; min = fill (save offset to next table)

	; we need an extra var for this loop
	push	r8
	mov	ecx, r14d	; save drop in ecx for our shr
calign
.inflate_table_reploop:
	sub	esi, edi
	mov	r8d, edx
	shr	r8d, cl		; huff >> drop
	add	r8d, esi	; + fill

	mov	dword [r11+r8*4], eax		; next[(huff >> drop)+fill] = here
	test	esi, esi
	jnz	.inflate_table_reploop
	pop	r8

	; next up: backwards increment the len-bit code huff
	
	mov	edi, 1
	mov	ecx, r10d
	sub	ecx, 1
	shl	edi, cl		; incr = 1 << (len - 1)

calign
.inflate_table_incrmod:
	test	edx, edi
	jz	.inflate_table_incrmod_done
	shr	edi, 1
	jmp	.inflate_table_incrmod
calign
.inflate_table_incrmod_done:
	; depending on whether incr != 0 or not, need to modify huff (edx)
	mov	esi, edi
	mov	ecx, edx	; ecx = huff
	sub	esi, 1
	and	ecx, esi	; ecx = huff & (incr - 1)
	add	ecx, edi	; ecx = (huff & (incr - 1)) + incr
	xor	esi, esi
	test	edi, edi
	cmovz	edx, esi	; if (!incr) huff = 0
	cmovnz	edx, ecx	; else huff = (huff & (incr - 1)) + incr

	add	r8d, 1		; sym++
	
	; count at [rsp+48] for 32 bytes
	; offs at [rsp+80] for 32 bytes
	sub	word [rsp+r10*2+48], 1	; --(count[len])
	jnz	.inflate_table_countdecnz
	cmp	r10d, dword [rsp+120]	; len == max?
	je	.inflate_table_mainloop_done
	
	mov	rsi, [rsp+8]		; get lens back
	movzx	ecx, word [r9+r8*2]	; work[sym]
	movzx	r10d, word [rsi+rcx*2]	; len = lens[work[sym]]
calign
.inflate_table_countdecnz:
	; create new sub-table if needed
	cmp	r10d, dword [rsp+112]
	jbe	.inflate_table_mainloop
	mov	eax, edx
	and	eax, dword [rsp+152]
	cmp	eax, r15d
	je	.inflate_table_mainloop
	test	r14d, r14d
	cmovz	r14d, dword [rsp+112]	; if (!drop) drop = root
	mov	eax, r12d
	shl	eax, 2
	add	r11, rax		; next += min (next is meant to be code*, so shl 2 for byte offset)
	mov	r13d, r10d
	mov	edi, 1
	sub	r13d, r14d		; curr = len - drop
	mov	ecx, r13d
	shl	edi, cl			; left = 1 << curr
calign
.inflate_table_nextlength:
	mov	eax, r13d		
	add	eax, r14d		; curr + drop
	cmp	eax, dword [rsp+120]
	jae	.inflate_table_nextlength_done
	movzx	ecx, word [rsp+rax*2+48]	; count[curr _ drop]
	sub	edi, ecx
	cmp	edi, 0
	jle	.inflate_table_nextlength_done
	add	r13d, 1				; curr++
	shl	edi, 1			; leff <<= 1
	jmp	.inflate_table_nextlength
calign
.inflate_table_nextlength_done:
	mov	esi, dword [rsp+144]	; used
	mov	ecx, r13d
	mov	eax, 1
	shl	eax, cl
	add	esi, eax
	mov	dword [rsp+144], esi
	cmp	esi, dword [rsp+160]	; used > used_limit ?
	ja	.inflate_table_error	; not enough space
	; point entry in root table to sub-table
	mov	r15d, edx
	and	r15d, dword [rsp+152]	; low = huff & mask
	
	mov	rdi, r11		; next
	mov	rcx, [rsp+128]		; get the table pointer back
	mov	rsi, [rcx]		; and the pointer it is pointing to
	sub	rdi, rsi
	; we want next - *table in offset not bytes, shl'd into the high word, which is shr 2 then shl 16
	shl	rdi, 14

	;  low order byte == op, next byte is bits, then val
	mov	eax, r13d		; curr
	mov	ecx, dword [rsp+112]	; root
	and	eax, 0xff
	and	ecx, 0xff
	shl	ecx, 8
	or	eax, ecx
	or	eax, edi
	; rsi is still pointing at our table, we need to offset it by r15d (low)
	mov	dword [rsi+r15*4], eax
	jmp	.inflate_table_mainloop
calign
.inflate_table_mainloop_done:
	; fill in remaining table entry if code is incomplete
	mov	rcx, [rsp+128]		; get the table pointer back
	mov	rsi, [rcx]		; and the pointer it is pointing to
	mov	edi, dword [rsp+144]	; used
	shl	edi, 2
	add	rsi, rdi
	mov	[rcx], rsi		; *table += used
	; next up we need to set *bits = root
	mov	rdi, [rsp+32]		; bits
	mov	ecx, [rsp+112]		; root
	mov	dword [rdi], ecx	; *bits = root

	test	edx, edx		; huff != 0 ?
	jz	.inflate_table_success
	
	; low order byte == 64 (invalid code marker), next byte: (len - drop), next word: 0
	mov	eax, r10d
	sub	eax, r14d
	shl	eax, 8
	or	eax, 0x40
	; next[huff] = eax
	mov	dword [r11+rdx*4], eax
	; success return
	add	rsp, 168
	pop	r15 r14 r13 r12 rbx rbp
	mov	eax, 1
	ret
calign
.inflate_table_success:
	add	rsp, 168
	pop	r15 r14 r13 r12 rbx rbp
	mov	eax, 1
	ret
calign
.inflate_table_nosymbols:
	mov	eax, 0x140
	mov	rdx, [rcx]		; get the pointer at table
	mov	dword [rdx], eax	; set that pointer to 0x140 (invalid code marker)
	add	rdx, 4
	mov	dword [rdx], eax	; set the next to 0x140 also
	add	rdx, 4
	mov	[rcx], rdx		; set the pointer at table again to our updated value
	mov	dword [r8], 1		; *bits = 1
	add	rsp, 168
	pop	r15 r14 r13 r12 rbx rbp
	xor	eax, eax
	ret
calign
.inflate_table_error:
	add	rsp, 168
	pop	r15 r14 r13 r12 rbx rbp
	xor	eax, eax
	ret
dalign
.inflate_table_lbase:
	dw	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
dalign
.inflate_table_lext:
	dw	16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 72, 78
dalign
.inflate_table_dbase:
	dw	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0
dalign
.inflate_table_dext:
	dw	16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 64, 64
dalign
.order:
	dd      16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
dalign
.lenfix:
	dd	0x760, 0x500800, 0x100800, 0x730814, 0x1f0712, 0x700800, 0x300800, 0xc00900
	dd	0xa0710, 0x600800, 0x200800, 0xa00900, 0x800, 0x800800, 0x400800, 0xe00900
	dd	0x60710, 0x580800, 0x180800, 0x900900, 0x3b0713, 0x780800, 0x380800, 0xd00900
	dd	0x110711, 0x680800, 0x280800, 0xb00900, 0x80800, 0x880800, 0x480800, 0xf00900
	dd	0x40710, 0x540800, 0x140800, 0xe30815, 0x2b0713, 0x740800, 0x340800, 0xc80900
	dd	0xd0711, 0x640800, 0x240800, 0xa80900, 0x40800, 0x840800, 0x440800, 0xe80900
	dd	0x80710, 0x5c0800, 0x1c0800, 0x980900, 0x530714, 0x7c0800, 0x3c0800, 0xd80900
	dd	0x170712, 0x6c0800, 0x2c0800, 0xb80900, 0xc0800, 0x8c0800, 0x4c0800, 0xf80900
	dd	0x30710, 0x520800, 0x120800, 0xa30815, 0x230713, 0x720800, 0x320800, 0xc40900
	dd	0xb0711, 0x620800, 0x220800, 0xa40900, 0x20800, 0x820800, 0x420800, 0xe40900
	dd	0x70710, 0x5a0800, 0x1a0800, 0x940900, 0x430714, 0x7a0800, 0x3a0800, 0xd40900
	dd	0x130712, 0x6a0800, 0x2a0800, 0xb40900, 0xa0800, 0x8a0800, 0x4a0800, 0xf40900
	dd	0x50710, 0x560800, 0x160800, 0x840, 0x330713, 0x760800, 0x360800, 0xcc0900
	dd	0xf0711, 0x660800, 0x260800, 0xac0900, 0x60800, 0x860800, 0x460800, 0xec0900
	dd	0x90710, 0x5e0800, 0x1e0800, 0x9c0900, 0x630714, 0x7e0800, 0x3e0800, 0xdc0900
	dd	0x1b0712, 0x6e0800, 0x2e0800, 0xbc0900, 0xe0800, 0x8e0800, 0x4e0800, 0xfc0900
	dd	0x760, 0x510800, 0x110800, 0x830815, 0x1f0712, 0x710800, 0x310800, 0xc20900
	dd	0xa0710, 0x610800, 0x210800, 0xa20900, 0x10800, 0x810800, 0x410800, 0xe20900
	dd	0x60710, 0x590800, 0x190800, 0x920900, 0x3b0713, 0x790800, 0x390800, 0xd20900
	dd	0x110711, 0x690800, 0x290800, 0xb20900, 0x90800, 0x890800, 0x490800, 0xf20900
	dd	0x40710, 0x550800, 0x150800, 0x1020810, 0x2b0713, 0x750800, 0x350800, 0xca0900
	dd	0xd0711, 0x650800, 0x250800, 0xaa0900, 0x50800, 0x850800, 0x450800, 0xea0900
	dd	0x80710, 0x5d0800, 0x1d0800, 0x9a0900, 0x530714, 0x7d0800, 0x3d0800, 0xda0900
	dd	0x170712, 0x6d0800, 0x2d0800, 0xba0900, 0xd0800, 0x8d0800, 0x4d0800, 0xfa0900
	dd	0x30710, 0x530800, 0x130800, 0xc30815, 0x230713, 0x730800, 0x330800, 0xc60900
	dd	0xb0711, 0x630800, 0x230800, 0xa60900, 0x30800, 0x830800, 0x430800, 0xe60900
	dd	0x70710, 0x5b0800, 0x1b0800, 0x960900, 0x430714, 0x7b0800, 0x3b0800, 0xd60900
	dd	0x130712, 0x6b0800, 0x2b0800, 0xb60900, 0xb0800, 0x8b0800, 0x4b0800, 0xf60900
	dd	0x50710, 0x570800, 0x170800, 0x840, 0x330713, 0x770800, 0x370800, 0xce0900
	dd	0xf0711, 0x670800, 0x270800, 0xae0900, 0x70800, 0x870800, 0x470800, 0xee0900
	dd	0x90710, 0x5f0800, 0x1f0800, 0x9e0900, 0x630714, 0x7f0800, 0x3f0800, 0xde0900
	dd	0x1b0712, 0x6f0800, 0x2f0800, 0xbe0900, 0xf0800, 0x8f0800, 0x4f0800, 0xfe0900
	dd	0x760, 0x500800, 0x100800, 0x730814, 0x1f0712, 0x700800, 0x300800, 0xc10900
	dd	0xa0710, 0x600800, 0x200800, 0xa10900, 0x800, 0x800800, 0x400800, 0xe10900
	dd	0x60710, 0x580800, 0x180800, 0x910900, 0x3b0713, 0x780800, 0x380800, 0xd10900
	dd	0x110711, 0x680800, 0x280800, 0xb10900, 0x80800, 0x880800, 0x480800, 0xf10900
	dd	0x40710, 0x540800, 0x140800, 0xe30815, 0x2b0713, 0x740800, 0x340800, 0xc90900
	dd	0xd0711, 0x640800, 0x240800, 0xa90900, 0x40800, 0x840800, 0x440800, 0xe90900
	dd	0x80710, 0x5c0800, 0x1c0800, 0x990900, 0x530714, 0x7c0800, 0x3c0800, 0xd90900
	dd	0x170712, 0x6c0800, 0x2c0800, 0xb90900, 0xc0800, 0x8c0800, 0x4c0800, 0xf90900
	dd	0x30710, 0x520800, 0x120800, 0xa30815, 0x230713, 0x720800, 0x320800, 0xc50900
	dd	0xb0711, 0x620800, 0x220800, 0xa50900, 0x20800, 0x820800, 0x420800, 0xe50900
	dd	0x70710, 0x5a0800, 0x1a0800, 0x950900, 0x430714, 0x7a0800, 0x3a0800, 0xd50900
	dd	0x130712, 0x6a0800, 0x2a0800, 0xb50900, 0xa0800, 0x8a0800, 0x4a0800, 0xf50900
	dd	0x50710, 0x560800, 0x160800, 0x840, 0x330713, 0x760800, 0x360800, 0xcd0900
	dd	0xf0711, 0x660800, 0x260800, 0xad0900, 0x60800, 0x860800, 0x460800, 0xed0900
	dd	0x90710, 0x5e0800, 0x1e0800, 0x9d0900, 0x630714, 0x7e0800, 0x3e0800, 0xdd0900
	dd	0x1b0712, 0x6e0800, 0x2e0800, 0xbd0900, 0xe0800, 0x8e0800, 0x4e0800, 0xfd0900
	dd	0x760, 0x510800, 0x110800, 0x830815, 0x1f0712, 0x710800, 0x310800, 0xc30900
	dd	0xa0710, 0x610800, 0x210800, 0xa30900, 0x10800, 0x810800, 0x410800, 0xe30900
	dd	0x60710, 0x590800, 0x190800, 0x930900, 0x3b0713, 0x790800, 0x390800, 0xd30900
	dd	0x110711, 0x690800, 0x290800, 0xb30900, 0x90800, 0x890800, 0x490800, 0xf30900
	dd	0x40710, 0x550800, 0x150800, 0x1020810, 0x2b0713, 0x750800, 0x350800, 0xcb0900
	dd	0xd0711, 0x650800, 0x250800, 0xab0900, 0x50800, 0x850800, 0x450800, 0xeb0900
	dd	0x80710, 0x5d0800, 0x1d0800, 0x9b0900, 0x530714, 0x7d0800, 0x3d0800, 0xdb0900
	dd	0x170712, 0x6d0800, 0x2d0800, 0xbb0900, 0xd0800, 0x8d0800, 0x4d0800, 0xfb0900
	dd	0x30710, 0x530800, 0x130800, 0xc30815, 0x230713, 0x730800, 0x330800, 0xc70900
	dd	0xb0711, 0x630800, 0x230800, 0xa70900, 0x30800, 0x830800, 0x430800, 0xe70900
	dd	0x70710, 0x5b0800, 0x1b0800, 0x970900, 0x430714, 0x7b0800, 0x3b0800, 0xd70900
	dd	0x130712, 0x6b0800, 0x2b0800, 0xb70900, 0xb0800, 0x8b0800, 0x4b0800, 0xf70900
	dd	0x50710, 0x570800, 0x170800, 0x840, 0x330713, 0x770800, 0x370800, 0xcf0900
	dd	0xf0711, 0x670800, 0x270800, 0xaf0900, 0x70800, 0x870800, 0x470800, 0xef0900
	dd	0x90710, 0x5f0800, 0x1f0800, 0x9f0900, 0x630714, 0x7f0800, 0x3f0800, 0xdf0900
	dd	0x1b0712, 0x6f0800, 0x2f0800, 0xbf0900, 0xf0800, 0x8f0800, 0x4f0800, 0xff0900
dalign
.distfix:
	dd	0x10510, 0x1010517, 0x110513, 0x1001051b, 0x50511, 0x4010519, 0x410515, 0x4001051d
	dd	0x30510, 0x2010518, 0x210514, 0x2001051c, 0x90512, 0x801051a, 0x810516, 0x540
	dd	0x20510, 0x1810517, 0x190513, 0x1801051b, 0x70511, 0x6010519, 0x610515, 0x6001051d
	dd	0x40510, 0x3010518, 0x310514, 0x3001051c, 0xd0512, 0xc01051a, 0xc10516, 0x540

end if
