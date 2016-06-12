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
	; zlib_deflate.inc: port of zlib, uses buffer goods
	;
	; This is quite literally a hand compilation (and thus interpretation/
	; modification) of the "reference zlib."
	; As such, the original zlib.h copyright appears below, although I am not
	; sure that is really necessary. Cheers to Jean-Loup Gailly and the legend
	; Mark Adler are definitely in order regardless of whether it is necessary
	; or not!
	;
	; NOTE: hahah, I really must be crazy...
	; Burning Purpose behind this entire kit of goodies though is to be
	; standalone, so either I go without, or I hand-compile it ;-)
	; HAHAH
	; 
	; Note to self: I wrote the maniacal HAHAH _before_ I did any of the work
	; how about "le Grunt" instead
	;
	; So, this deflate routine is mostly a "reference" version, its speed is faster than zlib-1.2.8
	; and the default gzip supplied with my primary linux distro
	;
	; NOTE: I didn't bother to do RLE and pure Huffman... none of my stuff uses it
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

	; TODO: cleanup dstate/remove unused items

	; various settings apply, see the default settings for further details.

	; profile the internal zlib function calls?
profile_zlib_internals = 0



zlib_inbuf_ofs = 0
zlib_outbuf_ofs = 8
zlib_totalin_ofs = 16
zlib_totalout_ofs = 24
zlib_state_ofs = 32
zlib_datatype_ofs = 40
zlib_adler_ofs = 48

zlib_stream_size = 56


zlib_tdesc_dyn_tree_ofs = 0
zlib_tdesc_max_code_ofs = 8
zlib_tdesc_stat_desc_ofs = 16

zlib_dstate_streamp_ofs = 0			; dq
zlib_dstate_status_ofs = 8			; dd
zlib_dstate_pending_buf_ofs = 16		; dq
zlib_dstate_wrap_ofs = 24			; dd (passed in at deflateInit)
zlib_dstate_gzhead_ofs = 32			; dq
zlib_dstate_gzindex_ofs = 40			; dd
zlib_dstate_last_flush_ofs = 48			; dd
zlib_dstate_w_size_ofs = 56			; dd-- notused (constant)
zlib_dstate_w_bits_ofs = 64			; dd-- notused (constant)
zlib_dstate_w_mask_ofs = 72			; dd-- notused (constant)
zlib_dstate_window_ofs = 80			; dq
zlib_dstate_window_size_ofs = 88		; dq-- notused (constant)
zlib_dstate_prev_ofs = 96			; dq
zlib_dstate_head_ofs = 104			; dq
zlib_dstate_ins_h_ofs = 112			; dd
zlib_dstate_hash_size_ofs = 120			; dd-- notused (constant)
zlib_dstate_hash_bits_ofs = 128			; dd-- notused
zlib_dstate_hash_mask_ofs = 136			; dd-- notused (constant)
zlib_dstate_hash_shift_ofs = 144		; dd-- notused (constant)
zlib_dstate_block_start_ofs = 152		; dq
zlib_dstate_match_length_ofs = 160		; dd
zlib_dstate_prev_match_ofs = 168		; dd
zlib_dstate_match_available_ofs = 176		; dd
zlib_dstate_strstart_ofs = 184			; dd
zlib_dstate_match_start_ofs = 192		; dd
zlib_dstate_lookahead_ofs = 200			; dd
zlib_dstate_prev_length_ofs = 208		; dd
zlib_dstate_max_chain_length_ofs = 216		; dd-- notused at all
zlib_dstate_max_lazy_match_ofs = 224		; dd-- notused (constant)
zlib_dstate_level_ofs = 232			; dd
zlib_dstate_strategy_ofs = 240			; dd
zlib_dstate_good_match_ofs = 248		; dd-- notused (constant)
zlib_dstate_nice_match_ofs = 256		; dd-- notused (constant)
zlib_dstate_dyn_ltree_ofs = 264			; array of struct ct_data_s
zlib_dstate_dyn_dtree_ofs = 2556		; array of struct ct_data_s
zlib_dstate_bl_tree_ofs = 2800			; array of struct ct_data_s
zlib_dstate_l_desc_ofs = 2956			; struct tree_desc_s
zlib_dstate_d_desc_ofs = 2980			; struct tree_desc_s
zlib_dstate_bl_desc_ofs = 3004			; struct tree_desc_s
zlib_dstate_bl_count_ofs = 3028			; array of dw
zlib_dstate_heap_ofs = 3060			; array of dd
zlib_dstate_heap_len_ofs = 5352			; dd
zlib_dstate_heap_max_ofs = 5360			; dd
zlib_dstate_depth_ofs = 5368			; array of db
zlib_dstate_l_buf_ofs = 5944			; dq
zlib_dstate_lit_bufsize_ofs = 5952		; dd-- notused (constant)
zlib_dstate_last_lit_ofs = 5960			; dd
zlib_dstate_d_buf_ofs = 5968			; dq
zlib_dstate_opt_len_ofs = 5976			; dq
zlib_dstate_static_len_ofs = 5984		; dq
zlib_dstate_matches_ofs = 5992			; dd
zlib_dstate_insert_ofs = 6000			; dd
zlib_dstate_bi_buf_ofs = 6008			; dw			... NOTE: changed to dq
zlib_dstate_bi_valid_ofs = 6016			; dd			... 
zlib_dstate_high_water_ofs = 6024		; dq
zlib_dstate_pending_out_ofs = 6032		; dq
zlib_dstate_pending_ofs = 6040			; dd

zlib_dstate_size = 6048


	; standard config goods here:
zlib_window_bits = 15
zlib_memlevel = 8


	; and calcs based on them:
zlib_wsize = 1 shl zlib_window_bits
zlib_wmask = zlib_wsize - 1

zlib_hashbits = zlib_memlevel + 7
zlib_hashsize = 1 shl zlib_hashbits
zlib_hashmask = zlib_hashsize - 1

zlib_min_match = 3

zlib_hashshift = (zlib_hashbits + zlib_min_match - 1) / zlib_min_match

zlib_litbufsize = 1 shl (zlib_memlevel + 6)

zlib_wsize_bytes = zlib_wsize shl 1
zlib_prev_bytes = zlib_wsize shl 1
zlib_head_bytes = zlib_hashsize shl 1
zlib_overlay_bytes = zlib_litbufsize shl 2

	; bi_buf/bi_valid sizing, in bits:
zlib_buf_size = 64

	; configuration based on zlib_deflate_level:
if zlib_deflate_level = 0
	zlib_good_length = 0
	zlib_max_lazy = 0
	zlib_nice_length = 0
	zlib_max_chain = 0
else if zlib_deflate_level = 1
	zlib_good_length = 4
	zlib_max_lazy = 4
	zlib_nice_length = 8
	zlib_max_chain = 4
else if zlib_deflate_level = 2
	zlib_good_length = 4
	zlib_max_lazy = 5
	zlib_nice_length = 16
	zlib_max_chain = 8
else if zlib_deflate_level = 3
	zlib_good_length = 4
	zlib_max_lazy = 6
	zlib_nice_length = 32
	zlib_max_chain = 32
else if zlib_deflate_level = 4
	zlib_good_length = 4
	zlib_max_lazy = 4
	zlib_nice_length = 16
	zlib_max_chain = 16
else if zlib_deflate_level = 5
	zlib_good_length = 8
	zlib_max_lazy = 16
	zlib_nice_length = 32
	zlib_max_chain = 32
else if zlib_deflate_level = 6
	zlib_good_length = 8
	zlib_max_lazy = 16
	zlib_nice_length = 128
	zlib_max_chain = 128
else if zlib_deflate_level = 7
	zlib_good_length = 8
	zlib_max_lazy = 32
	zlib_nice_length = 128
	zlib_max_chain = 256
else if zlib_deflate_level = 8
	zlib_good_length = 32
	zlib_max_lazy = 128
	zlib_nice_length = 258
	zlib_max_chain = 1024
else if zlib_deflate_level = 9
	zlib_good_length = 32
	zlib_max_lazy = 258
	zlib_nice_length = 258
	zlib_max_chain = 4096
else
	display 'invalid zlib_deflate_level',13,10
	err
end if


	; deflate states
zlib_dstate_init = 42
zlib_dstate_extra = 69
zlib_dstate_name = 73
zlib_dstate_comment = 91
zlib_dstate_hcrc = 103
zlib_dstate_busy = 113
zlib_dstate_finish = 666



macro zlib_debug preface*, reg* {
	local ..continue, ..string
	push	rax rcx rdx rdi rsi r8 r9 r10 r11
	sub	rsp, 8
	mov	rdi, reg
	mov	esi, 10
	call	string$from_unsigned
	mov	[rsp], rax
	mov	rdi, ..string
	call	string$to_stderr
	mov	rdi, [rsp]
	call	string$to_stderrln
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 8
	pop	r11 r10 r9 r8 rsi rdi rdx rcx rax
	jmp	..continue
cleartext ..string, preface
calign
..continue:
}

if used zlib$deflateEnd | defined include_everything

	; single argument in rdi: a zlib_stream pointer
	; all we do is free our state, otherwise, we leave things well enough alone
falign
zlib$deflateEnd:
	prolog	zlib$deflateEnd
	mov	rdi, [rdi+zlib_state_ofs]
	call	heap$free
	epilog

end if

if used zlib$deflateInit | defined include_everything
	; two arguments: rdi == a zlib_stream_size memory chunk for our state, esi == "wrap", see below
	; we do not mess with inbuf or outbuf
	; wrap == 0 == no headers whatsoever
	; wrap == 1 == zlib (suitable for all my streaming goods, SSH, etc)
	; wrap == 2 == gzip headers
falign
zlib$deflateInit:
	prolog	zlib$deflateInit
	xor	ecx, ecx
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+16], esi
	mov	[rdi+zlib_totalin_ofs], rcx
	mov	[rdi+zlib_totalout_ofs], rcx
	mov	qword [rdi+zlib_datatype_ofs], 2

	mov	qword [rdi+zlib_adler_ofs], 1

	mov	edi, zlib_dstate_size + zlib_wsize_bytes + zlib_prev_bytes + zlib_head_bytes + zlib_overlay_bytes + 64
	call	heap$alloc
	mov	[rsp+8], rax
	mov	rdi, rax
	xor	esi, esi
	mov	edx, zlib_dstate_size		; note: we are _not_ clearing the buffers, no sense in that.. TODO: do we even need to do it for the rest of them?
	call	memset32
	mov	rdi, [rsp+8]			; our zlib_dstate block, zeroed
	add	rdi, zlib_dstate_size + zlib_wsize_bytes + zlib_prev_bytes	; the head location
	xor	esi, esi
	mov	edx, zlib_head_bytes
	call	memset32			; we may consider just combining and zeroing the entire lot in one call, hmmm
	mov	rsi, [rsp+8]			; our zlib_dstate block, zeroed
	mov	rdi, [rsp]			; our original z_stream block
	mov	rdx, rsi
	mov	rcx, rsi
	mov	r8, rsi
	mov	r9, rsi

	add	rdx, zlib_dstate_size
	add	rcx, zlib_dstate_size
	add	r8, zlib_dstate_size
	add	r9, zlib_dstate_size
	add	rcx, zlib_wsize_bytes + 15
	add	r8, zlib_wsize_bytes + 15
	add	r9, zlib_wsize_bytes + 15
	and	rcx, not 15
	and	r8, not 15
	and	r9, not 15

	add	r8, zlib_prev_bytes + 15
	add	r9, zlib_prev_bytes + 15
	and	r8, not 15
	and	r9, not 15
	add	r9, zlib_head_bytes + 15
	and	r9, not 15

	mov	r10d, [rsp+16]
	mov	[rdi+zlib_state_ofs], rsi
	mov	[rsi+zlib_dstate_streamp_ofs], rdi
	mov	[rsi+zlib_dstate_wrap_ofs], r10d
	; mov	dword [rsi+zlib_dstate_w_bits_ofs], zlib_window_bits
	; mov	dword [rsi+zlib_dstate_w_size_ofs], zlib_wsize
	; mov	qword [rsi+zlib_dstate_window_size_ofs], zlib_wsize shl 1
	; mov	dword [rsi+zlib_dstate_w_mask_ofs], zlib_wmask
	; mov	dword [rsi+zlib_dstate_hash_bits_ofs], zlib_hashbits
	; mov	dword [rsi+zlib_dstate_hash_size_ofs], zlib_hashsize
	; mov	dword [rsi+zlib_dstate_hash_mask_ofs], zlib_hashmask
	; mov	dword [rsi+zlib_dstate_hash_shift_ofs], zlib_hashshift
	; mov	dword [rsi+zlib_dstate_lit_bufsize_ofs], zlib_litbufsize
	mov	[rsi+zlib_dstate_window_ofs], rdx
	mov	[rsi+zlib_dstate_prev_ofs], rcx
	mov	[rsi+zlib_dstate_head_ofs], r8			; fill_window requires these to be adjacent
	mov	[rsi+zlib_dstate_pending_buf_ofs], r9
	mov	[rsi+zlib_dstate_pending_out_ofs], r9
	xor	r8d, r8d
	; mov	qword [rsi+zlib_dstate_pending_buf_size_ofs], zlib_overlay_bytes
	mov	rdx, r9
	mov	rcx, r9
	add	rdx, zlib_overlay_bytes shr 2			; d_buf now at byte offset 16384 instead
	add	rcx, 3 * zlib_litbufsize
	mov	[rsi+zlib_dstate_d_buf_ofs], rdx
	mov	[rsi+zlib_dstate_l_buf_ofs], rcx
	mov	dword [rsi+zlib_dstate_level_ofs], zlib_deflate_level
	mov	[rsi+zlib_dstate_pending_ofs], r8
	mov	dword [rsi+zlib_dstate_status_ofs], zlib_dstate_init

	; _tr_init(rsi) is next
	xor	r9d, r9d
	mov	rdx, rsi
	mov	rcx, rsi
	mov	r8, rsi
	add	rdx, zlib_dstate_dyn_ltree_ofs
	add	rcx, zlib_dstate_dyn_dtree_ofs
	add	r8, zlib_dstate_bl_tree_ofs
	mov	[rsi+zlib_dstate_l_desc_ofs + zlib_tdesc_dyn_tree_ofs], rdx
	mov	qword [rsi+zlib_dstate_l_desc_ofs + zlib_tdesc_stat_desc_ofs], zlib_static_l_desc
	mov	[rsi+zlib_dstate_d_desc_ofs + zlib_tdesc_dyn_tree_ofs], rcx
	mov	qword [rsi+zlib_dstate_d_desc_ofs + zlib_tdesc_stat_desc_ofs], zlib_static_d_desc
	mov	[rsi+zlib_dstate_bl_desc_ofs + zlib_tdesc_dyn_tree_ofs], r8
	mov	qword [rsi+zlib_dstate_bl_desc_ofs + zlib_tdesc_stat_desc_ofs], zlib_static_bl_desc
	mov	[rsi+zlib_dstate_bi_buf_ofs], r9
	mov	[rsi+zlib_dstate_bi_valid_ofs], r9

	; our entire dstate is already memset to 0, so we don't need to do our Freq = 0 or any of the rest of the clearing inside init_block
	mov	word [rsi+zlib_dstate_dyn_ltree_ofs + 256*4], 1		; dyn_ltree[END_BLOCK].Freq = 1

	; lm_init sprinkled above, and here
	mov	dword [rsi+zlib_dstate_match_length_ofs], 2		; min_match - 1
	mov	dword [rsi+zlib_dstate_prev_length_ofs], 2		; ""
	; mov	dword [rsi+zlib_dstate_max_lazy_match_ofs], zlib_max_lazy
	; mov	dword [rsi+zlib_dstate_good_match_ofs], zlib_good_length
	; mov	dword [rsi+zlib_dstate_nice_match_ofs], zlib_nice_length
	; mov	dword [rsi+zlib_dstate_max_chain_length_ofs], zlib_max_chain

	; CLEAR_HASH(s) was taken care of by the memset above
	mov	rax, rdi
	add	rsp, 24
	epilog
dalign
zlib_static_l_desc:
	dq	zlib_static_ltree, extra_lbits, 257, 286, 15
dalign
zlib_static_d_desc:
	dq	zlib_static_dtree, zlib_extra_dbits, 0, 30, 15
dalign
zlib_static_bl_desc:
	dq	0, zlib_extra_blbits, 0, 19, 7
dalign
extra_lbits:
	dd	0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
dalign
zlib_extra_dbits:
	dd	0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
dalign
zlib_extra_blbits:
	dd	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,3,7
dalign
zlib_static_ltree:
	dw	 12,  8, 140,  8,  76,  8, 204,  8,  44,  8
	dw	172,  8, 108,  8, 236,  8,  28,  8, 156,  8
	dw	92,  8, 220,  8,  60,  8, 188,  8, 124,  8
	dw	252,  8,   2,  8, 130,  8,  66,  8, 194,  8
	dw	34,  8, 162,  8,  98,  8, 226,  8,  18,  8
	dw	146,  8,  82,  8, 210,  8,  50,  8, 178,  8
	dw	114,  8, 242,  8,  10,  8, 138,  8,  74,  8
	dw	202,  8,  42,  8, 170,  8, 106,  8, 234,  8
	dw	26,  8, 154,  8,  90,  8, 218,  8,  58,  8
	dw	186,  8, 122,  8, 250,  8,   6,  8, 134,  8
	dw	70,  8, 198,  8,  38,  8, 166,  8, 102,  8
	dw	230,  8,  22,  8, 150,  8,  86,  8, 214,  8
	dw	54,  8, 182,  8, 118,  8, 246,  8,  14,  8
	dw	142,  8,  78,  8, 206,  8,  46,  8, 174,  8
	dw	110,  8, 238,  8,  30,  8, 158,  8,  94,  8
	dw	222,  8,  62,  8, 190,  8, 126,  8, 254,  8
	dw	1,  8, 129,  8,  65,  8, 193,  8,  33,  8
	dw	161,  8,  97,  8, 225,  8,  17,  8, 145,  8
	dw	81,  8, 209,  8,  49,  8, 177,  8, 113,  8
	dw	241,  8,   9,  8, 137,  8,  73,  8, 201,  8
	dw	41,  8, 169,  8, 105,  8, 233,  8,  25,  8
	dw	153,  8,  89,  8, 217,  8,  57,  8, 185,  8
	dw	121,  8, 249,  8,   5,  8, 133,  8,  69,  8
	dw	197,  8,  37,  8, 165,  8, 101,  8, 229,  8
	dw	21,  8, 149,  8,  85,  8, 213,  8,  53,  8
	dw	181,  8, 117,  8, 245,  8,  13,  8, 141,  8
	dw	77,  8, 205,  8,  45,  8, 173,  8, 109,  8
	dw	237,  8,  29,  8, 157,  8,  93,  8, 221,  8
	dw	61,  8, 189,  8, 125,  8, 253,  8,  19,  9
	dw	275,  9, 147,  9, 403,  9,  83,  9, 339,  9
	dw	211,  9, 467,  9,  51,  9, 307,  9, 179,  9
	dw	435,  9, 115,  9, 371,  9, 243,  9, 499,  9
	dw	11,  9, 267,  9, 139,  9, 395,  9,  75,  9
	dw	331,  9, 203,  9, 459,  9,  43,  9, 299,  9
	dw	171,  9, 427,  9, 107,  9, 363,  9, 235,  9
	dw	491,  9,  27,  9, 283,  9, 155,  9, 411,  9
	dw	91,  9, 347,  9, 219,  9, 475,  9,  59,  9
	dw	315,  9, 187,  9, 443,  9, 123,  9, 379,  9
	dw	251,  9, 507,  9,   7,  9, 263,  9, 135,  9
	dw	391,  9,  71,  9, 327,  9, 199,  9, 455,  9
	dw	39,  9, 295,  9, 167,  9, 423,  9, 103,  9
	dw	359,  9, 231,  9, 487,  9,  23,  9, 279,  9
	dw	151,  9, 407,  9,  87,  9, 343,  9, 215,  9
	dw	471,  9,  55,  9, 311,  9, 183,  9, 439,  9
	dw	119,  9, 375,  9, 247,  9, 503,  9,  15,  9
	dw	271,  9, 143,  9, 399,  9,  79,  9, 335,  9
	dw	207,  9, 463,  9,  47,  9, 303,  9, 175,  9
	dw	431,  9, 111,  9, 367,  9, 239,  9, 495,  9
	dw	31,  9, 287,  9, 159,  9, 415,  9,  95,  9
	dw	351,  9, 223,  9, 479,  9,  63,  9, 319,  9
	dw	191,  9, 447,  9, 127,  9, 383,  9, 255,  9
	dw	511,  9,   0,  7,  64,  7,  32,  7,  96,  7
	dw	16,  7,  80,  7,  48,  7, 112,  7,   8,  7
	dw	72,  7,  40,  7, 104,  7,  24,  7,  88,  7
	dw	56,  7, 120,  7,   4,  7,  68,  7,  36,  7
	dw	100,  7,  20,  7,  84,  7,  52,  7, 116,  7
	dw	3,  8, 131,  8,  67,  8, 195,  8,  35,  8
	dw	163,  8,  99,  8, 227,  8
dalign
zlib_static_dtree:
	dw	 0, 5, 16, 5,  8, 5, 24, 5,  4, 5
	dw	20, 5, 12, 5, 28, 5,  2, 5, 18, 5
	dw	10, 5, 26, 5,  6, 5, 22, 5, 14, 5
	dw	30, 5,  1, 5, 17, 5,  9, 5, 25, 5
 	dw	5, 5, 21, 5, 13, 5, 29, 5,  3, 5
	dw	19, 5, 11, 5, 27, 5,  7, 5, 23, 5
dalign
zlib_dist_code:
 	db	0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,  8,  8,  8,  8
 	db	8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9, 10, 10, 10, 10, 10, 10, 10, 10
	db	10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11
	db	11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12
	db	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13
	db	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13
	db	13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14
	db	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14
	db	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14
	db	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15
	db	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15
	db	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15
	db	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,  0,  0, 16, 17
	db	18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22
	db	23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24
	db	24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25
	db	26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26
	db	26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27
	db	27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27
	db	27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28
	db	28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28
	db	28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28
	db	28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
	db	29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
	db	29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
	db	29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
dalign
zlib_length_code:
 	db	0,  1,  2,  3,  4,  5,  6,  7,  8,  8,  9,  9, 10, 10, 11, 11, 12, 12, 12, 12
	db	13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16
	db	17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19
	db	19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20
	db	21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22
	db	22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23
	db	23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24
	db	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24
	db	25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25
	db	25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26
	db	26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26
	db	26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27
	db	27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28
dalign
zlib_base_length:
	dd	0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56
	dd	64, 80, 96, 112, 128, 160, 192, 224, 0
dalign
zlib_base_dist:
    	dd	0,     1,     2,     3,     4,     6,     8,    12,    16,    24
   	dd	32,    48,    64,    96,   128,   192,   256,   384,   512,   768
 	dd	1024,  1536,  2048,  3072,  4096,  6144,  8192, 12288, 16384, 24576


end if

	; flush flags can be one of:
zlib_no_flush = 0
zlib_partial_flush = 1
zlib_sync_flush = 2
zlib_full_flush = 3
zlib_finish = 4
zlib_block = 5
	; zlib_trees is used for inflate side not this one:
zlib_trees = 6


if used zlib$deflate | defined include_everything

	; two arguments: rdi == z_stream pointer, esi == flush flags

	; we return a bool in eax (unlike the actual zlib), 1 == Z_OK equiv, 0 == fail
	; and in our implementation, we really don't care WHY it failed, only that it did.
	
		; NOTE: we use the input buffer's 16 user bytes for our own state information
		; TODO: maybe someday when I am bored I can just add these to the dstate information
		; and eliminate having to carry around r14/r15, hmm
falign
zlib$deflate:
	prolog	zlib$deflate
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, [rdi+zlib_state_ofs]
	mov	r13d, esi
	mov	r14, [rdi+zlib_inbuf_ofs]
	mov	r15, [rdi+zlib_outbuf_ofs]
	test	r12, r12
	jz	.error_return
	cmp	r13d, 0
	jl	.error_return
	cmp	r13d, zlib_block
	jg	.error_return
	test	r14, r14
	jz	.error_return
	test	r15, r15
	jz	.error_return

	mov	rdi, r15
	mov	esi, zlib_deflate_reserve
	call	buffer$reserve

	; setup our user-space vars inside the inbuf so that we don't have to use the head of it 
	; and consume (bad for large buffers of course)
	mov	rax, [r14+buffer_length_ofs]
	mov	rcx, [r14+buffer_itself_ofs]
	mov	[r14+buffer_user_ofs], rcx		; user_ofs == current pointer
	mov	[r14+buffer_user_ofs+8], rax		; user_ofs+8 == remaining bytes

	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	mov	ecx, [r12+zlib_dstate_wrap_ofs]
	; so now, z_stream is in rbx, dstate is in r12, r13d has our flush flags, r14 has our inbuf, r15 has our outbuf
	mov	eax, [r12+zlib_dstate_status_ofs]
	; this is one big fallthrough mess
	cmp	eax, zlib_dstate_init
	jne	.state_not_init
	jmp	qword [rcx*8+.header_wrap_table]
dalign
.header_wrap_table:
	dq	.noheader, .zheader, .gzheader
calign
.gzheader:
	cmp	qword [r12+zlib_dstate_gzhead_ofs], 0
	jne	.state_init_wrap2_withgzhead
	mov	qword [rbx+zlib_adler_ofs], 0	; crc32(0, null, 0) == 0
	mov	r10, [.state_init_wrap2_gzhead]
	; possible values for the 9th byte:
	xor	ecx, ecx			; we'll use this one
	mov	edx, [r12+zlib_dstate_level_ofs]
	mov	r8d, 2
	mov	r9d, 4
	cmp	edx, 9
	cmove	ecx, r8d
	cmp	edx, 2
	cmovl	ecx, r9d
	cmp	dword [r12+zlib_dstate_strategy_ofs], 2
	cmovae	ecx, r9d			; TODO: if we already set ecx to nonzero, we shouldn't do this, eh?
	mov	edx, 3				; OS_CODE == unix
	mov	qword [rdi+rsi], r10
	mov	byte [rdi+rsi+8], cl
	mov	byte [rdi+rsi+9], dl
	add	rsi, 10
	mov	[r12+zlib_dstate_pending_ofs], rsi
	mov	eax, zlib_dstate_busy
	mov	[r12+zlib_dstate_status_ofs], eax
	jmp	.state_not_init
dalign
.state_init_wrap2_gzhead:
	db	31, 139, 8, 0, 0, 0, 0, 0	; 8 bytes
calign
.state_init_wrap2_withgzhead:
	; we don't really use any of this functionality... TODO, someday when I am bored, fill this out.
	; since this would require the use of a user supplied buffer to dump the gzhead stuff into
	; this won't break during normal runtime operations
	breakpoint
calign
.state_init_wrapnot2:
.zheader:
.noheader:
	; wrap was not two
	; for us, strategy should always be zero on entry, TODO: redo these cmovs?
	mov	eax, zlib_window_bits
	mov	r10d, [r12+zlib_dstate_level_ofs]
	sub	eax, 8
	mov	ecx, 3
	shl	eax, 4
	mov	edx, 1
	mov	r8d, 2
	add	eax, 8
	xor	r9d, r9d
	shl	eax, 8

	cmp	dword [r12+zlib_dstate_strategy_ofs], 2	; Z_HUFFMAN_ONLY
	cmovae	ecx, r9d
	cmp	r10d, 6
	cmove	ecx, r8d
	cmovb	ecx, edx
	cmp	r10d, 2
	cmovb	ecx, r9d			; see above comment re: strategy always being zero for us/TODO
	; so ecx now has our level_flags, eax has our header
	shl	ecx, 6
	or	eax, ecx
	mov	edx, eax
	or	edx, 0x20			; PRESET_DICT
	cmp	dword [r12+zlib_dstate_strstart_ofs], 0
	cmovne	eax, edx
	; next up: header += 31 - (header % 31), wtf?
	; this is some funky goods here
	mov	ecx, eax
	mov	edx, 0x8421085
	mul	edx
	xor	eax, eax
	sub	ecx, edx
	shr	ecx, 1
	add	ecx, edx
	shr	ecx, 4
	mov	eax, ecx
	sal	eax, 5
	sub	eax, ecx
	add	eax, 31
	; so eax is our header ushort
	xchg	ah, al
	mov	word [rdi+rsi], ax
	add	rsi, 2
	mov	[r12+zlib_dstate_pending_ofs], rsi
	mov	eax, zlib_dstate_busy
	mov	dword [r12+zlib_dstate_status_ofs], eax
	mov	rcx, [rbx+zlib_adler_ofs]
	mov	qword [rbx+zlib_adler_ofs], 1	; adler32(0, null, 0) == 1
	cmp	dword [r12+zlib_dstate_strstart_ofs], 0
	je	.state_not_init
	; else, we have two more shorts to put in there, derived from rcx
	mov	edx, ecx		; save it
	shr	ecx, 16
	xchg	ch, cl
	xchg	dh, dl
	mov	word [rdi+rsi], cx
	mov	word [rdi+rsi+2], dx
	add	rsi, 4
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; fallthrough to state_not_init okay
calign
.state_not_init:
	; NOTE: we are skipping EXTRA_STATE, NAME_STATE, COMMENT_STATE, and HCRC_STATE
	; because none of my streaming goods need them... TODO: revisit when I am bored? haha

	; so here, he flushes the pending output... and I am not sure I see the reason behind emptying it, and then
	; he checks avail_out for zero, and returns OK, waiting for the caller to call here again...

	; in further consideration, especially considering the way I use these routines
	; pretty sure we can just ensure that avail_out will _never_ be zero (and thus just reserve the amount of space
	; we need)... I appreciate the motivation and reason behind his choices on that... and his way works a treat

	; so at this point, we need to determine whether or not we go ahead with the deflate_* or not, based on
	; whether we have actual data in our inbuf (which we _should_)
	mov	eax, [r12+zlib_dstate_strategy_ofs]

	; r14 is our inbuf
	cmp	qword [r14+buffer_length_ofs], 0			; this is still valid, since we haven't touched our user vars yet
	jne	.doblock
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 0		; will this ever be true the way we are using it?
	jne	.doblock
	; r13d is our flush flags
	test	r13d, r13d		; zlib_no_flush == 0
	jz	.block_done_or_no_block
	cmp	dword [r12+zlib_dstate_status_ofs], zlib_dstate_finish
	je	.block_done_or_no_block
calign
.doblock:
	; a note here: our strategy is fixed at zero, so during normal operations, these won't occur
	; (and only would if you are playing around with it)
	cmp	eax, 2			; Z_HUFFMAN_ONLY
	je	.deflate_huff
	cmp	eax, 3			; Z_RLE
	je	.deflate_rle
	; otherwise, depends on our configuration level
	if zlib_deflate_level = 0
		jmp	.deflate_stored
	else if zlib_deflate_level = 1 | zlib_deflate_level = 2 | zlib_deflate_level = 3
		jmp	.deflate_fast
	else
		jmp	.deflate_slow
	end if
calign
.bstate_done:
	; effectively the "return" of our previous jump to deflate_{huff,rle,stored,fast,slow}
	; and our return is in eax
zlib_bstate_need_more = 0
zlib_bstate_block_done = 1
zlib_bstate_finish_started = 2
zlib_bstate_finish_done = 3
	; restore/make sure rdi/rsi are valid and pointing to the pending buffer (so that all of the various places that jump back to here don't have to worryabout it)
	; one way or another, the above call to deflate_* exhausted the input buffer, so we reset it here (though I spose we don't really have to even touch it)
	; reset doesn't do much, and for my use-case scenarios, this works well
	mov	rdi, r14
	call	buffer$reset

	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	mov	edx, [r12+zlib_dstate_status_ofs]
	mov	ecx, zlib_dstate_finish
	cmp	eax, zlib_bstate_finish_done
	cmove	edx, ecx
	cmp	eax, zlib_bstate_finish_started
	cmove	edx, ecx
	mov	[r12+zlib_dstate_status_ofs], edx
	je	.success_return
	cmp	eax, zlib_bstate_need_more
	je	.success_return
	cmp	eax, zlib_bstate_block_done
	jne	.block_done_or_no_block
	; so bstate is block_done here.... check for Z_PARTIAL_FLUSH, and flush != Z_BLOCK, then move to the trailer check
	cmp	r13d, zlib_partial_flush
	je	.bstate_done_partial_flush
	cmp	r13d, zlib_block
	je	.block_done_or_no_block		; Z_BLOCK just goes straight to the trailer
	; else, FULL_FLUSH or SYNC_FLUSH
	cmp	r13d, zlib_full_flush
	je	.bstate_done_full_flush
	; else, SYNC_FLUSH, so just store an empty block, and go to the trailer
	; _tr_stored_block(s, (char *)0, 0L, 0);	args are: s, buf, stored_len, last
	; which does: send_bits(s, (STORED_BLOCK<<1)+last, 3);
	;   and then: copy_block(s, buf, (unsigned)stored_len, 1);
	;
	; STORED_BLOCK=0
	; send_bits(s, (STORED_BLOCK << 1) + last, 3);

macro send_bits_lit value*,length* {
	; length is meant to be a literal value, not a register/computed
	; rdi/rsi must be pointing to the correct pending buffer
	; value must be a reg
	; r12 must be our deflate state block
	; NOTE: no MSB conversion is done for putting these into the buffer
	; we blast ecx, edx, and r8d
	local	.overflow,.enoughroom,.exit,.binfname

	mov	ecx, dword [r12+zlib_dstate_bi_valid_ofs]
	cmp	ecx, zlib_buf_size - length
	jg	.overflow

	shl	value, cl
	or	qword [r12+zlib_dstate_bi_buf_ofs], value
	add	ecx, length
	mov	[r12+zlib_dstate_bi_valid_ofs], ecx
	; hmmm, something goes astray with shr r64, 64
	; and/or |= val << 64, wtf
	cmp	ecx, zlib_buf_size 
	jl	.exit
	; otherwise, clear it
	mov	rdx, [r12+zlib_dstate_bi_buf_ofs]
	mov	[rdi+rsi], rdx
	add	rsi, 8
	mov	dword [r12+zlib_dstate_bi_valid_ofs], 0
	mov	qword [r12+zlib_dstate_bi_buf_ofs], 0
	mov	qword [r12+zlib_dstate_pending_ofs], rsi
	jmp	.exit
calign
.overflow:
	; bi_buf |= value << bi_valid
	; save bi_buf for 8 bytes into output
	; bi_buf = value >> (zlib_buf_size - bi_valid)
	; bi_valid += length - zlib_buf_size (which will always be negative)
	mov	ecx, dword [r12+zlib_dstate_bi_valid_ofs]
	mov	rdx, value
	shl	value, cl		; value << bi_valid
	mov	r8d, zlib_buf_size
	sub	r8d, ecx		; buf_size - bi_valid
	mov	ecx, r8d
	shr	rdx, cl			; value >> (zlib_buf_size - bi_valid)
	mov	rcx, [r12+zlib_dstate_bi_buf_ofs]
	or	rcx, value				; value to send = old value | (value << bi_valid)
	mov	[r12+zlib_dstate_bi_buf_ofs], rdx	; bi_buf = value >> (zlib_buf_size - bi_valid)

	; put qword
	mov	qword [rdi+rsi], rcx
	add	rsi, 8
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; set new bi_valid
	mov	ecx, [r12+zlib_dstate_bi_valid_ofs]
	mov	edx, length
	sub	edx, zlib_buf_size
	add	ecx, edx
	mov	[r12+zlib_dstate_bi_valid_ofs], ecx
calign
.exit:
}
macro send_bits value*,length* {
	; length must be a register, not ecx, edx, or r8d, or r9d
	; rdi/rsi must be pointing to the correct pending buffer
	; value must be a reg also
	; r12 must be our deflate state block
	; NOTE: no MSB conversion is done for putting these into the buffer
	; we blast ecx, edx, r8d, and r9d
	local	.overflow,.enoughroom,.exit,.binfname

	mov	ecx, [r12+zlib_dstate_bi_valid_ofs]

	mov	r9d, zlib_buf_size
	sub	r9d, length
	cmp	ecx, r9d
	jg	.overflow

	shl	value, cl
	or	qword [r12+zlib_dstate_bi_buf_ofs], value
	add	ecx, length
	mov	[r12+zlib_dstate_bi_valid_ofs], ecx
	; hmmm, something goes astray with shr 64, 64
	; and/or |= val << 64, wtf
	cmp	ecx, zlib_buf_size
	jl	.exit
	; otherwise, clear it
	mov	rdx, [r12+zlib_dstate_bi_buf_ofs]
	mov	[rdi+rsi], rdx
	add	rsi, 8
	mov	qword [r12+zlib_dstate_bi_buf_ofs], 0
	mov	dword [r12+zlib_dstate_bi_valid_ofs], 0
	mov	qword [r12+zlib_dstate_pending_ofs], rsi
	jmp	.exit
calign
.overflow:
	; bi_buf |= value << bi_valid
	; save bi_buf for 8 bytes into output
	; bi_buf = value >> (zlib_buf_size - bi_valid)
	; bi_valid += length - zlib_buf_size (which will always be negative)
	mov	rdx, value
	mov	r9d, zlib_buf_size
	sub	r9d, ecx		; buf_size - bi_valid
	shl	value, cl		; value << bi_valid
	mov	ecx, r9d
	shr	rdx, cl			; value >> (zlib_buf_size - bi_valid)
	mov	rcx, [r12+zlib_dstate_bi_buf_ofs]
	or	rcx, value
	mov	qword [r12+zlib_dstate_bi_buf_ofs], rdx

	; put qword
	mov	qword [rdi+rsi], rcx
	add	rsi, 8
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; set new bi_valid
	mov	ecx, [r12+zlib_dstate_bi_valid_ofs]
	mov	edx, length
	sub	edx, zlib_buf_size
	add	ecx, edx
	mov	[r12+zlib_dstate_bi_valid_ofs], ecx
calign
.exit:
}
	
macro bi_windup {
	; this flushes whatever is in bi_buf, "aligned output on a byte boundary", heh
	; rdi/rsi must be pointing to the correct pending buffer
	; r12 must be our deflate state block
	; we blast ecx, edx, r8d, r9d (to avoid branching)
	mov	ecx, [r12+zlib_dstate_bi_valid_ofs]
	mov	rdx, [r12+zlib_dstate_bi_buf_ofs]
	add	ecx, 7
	and	ecx, not 7
	shr	ecx, 3
	mov	qword [rdi+rsi], rdx
	add	rsi, rcx
	mov	[r12+zlib_dstate_pending_ofs], rsi
	xor	edx, edx
	mov	[r12+zlib_dstate_bi_buf_ofs], rdx
	mov	[r12+zlib_dstate_bi_valid_ofs], edx
}
macro bi_flush {
	; if there is >= 8 bits in bi_buf, get rid of all but 7
	local ..exit

	; rdi/rsi must be pointing to the correct pending buffer
	; r12 must be our deflate state block
	; we blast eax, ecx, edx, r8d, r9d, r10d, r11d (to avoid branching)
	mov	ecx, [r12+zlib_dstate_bi_valid_ofs]
	mov	r8d, ecx
	mov	rdx, [r12+zlib_dstate_bi_buf_ofs]
	cmp	ecx, 8
	jb	..exit
	
	mov	[rdi+rsi], rdx			; regardless of how many, doesn't hurt
	shr	ecx, 3				; how many bytes we actually added
	add	rsi, rcx
	shl	ecx, 3				; back to bit count
	sub	r8d, ecx
	mov	[r12+zlib_dstate_bi_valid_ofs], r8d
	shr	rdx, cl
	mov	[r12+zlib_dstate_bi_buf_ofs], rdx

	mov	[r12+zlib_dstate_pending_ofs], rsi
calign
..exit:
}
	xor	eax, eax
	send_bits_lit rax, 3
	; next up: copy_block(0, 0, 1) where buf, stored_len are 0, and last = 1
	bi_windup
	; because buf and length are both zero, but header is required, we only adding the two shorts
	xor	eax, eax
	xor	ecx, ecx
	not	eax
	mov	word [rdi+rsi], cx
	mov	word [rdi+rsi+2], ax
	add	rsi, 4
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; _tr_stored_block is now complete.
	jmp	.block_done_or_no_block		; do the trailer bit next, which will flush_pending for all possible branches here
calign
.bstate_done_full_flush:
	; _tr_stored_block(s, (char*)0, 0L, 0);
	xor	eax, eax
	send_bits_lit rax, 3
	; next up: copy_block(0, 0, 1) where buf, stored_len are 0, and last = 1
	bi_windup
	; because buf and length are both zero, but header is required, we only adding the two shorts
	xor	eax, eax
	xor	ecx, ecx
	not	eax
	mov	word [rdi+rsi], cx
	mov	word [rdi+rsi+2], ax
	add	rsi, 4
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; _tr_stored_block is now complete.
	; unlike SYNC_FLUSH, we need to CLEAR_HASH(s), and also do:
	; if (s->lookahead == 0) {
	;   s->strstart = 0;
	;   s->block_start = 0;
	;   s->insert = 0;
	; }
	; CLEAR_HASH(s) == memset(s->head, 0, zlib_head_bytes)
	mov	rdi, [r12+zlib_dstate_head_ofs]
	xor	esi, esi
	mov	edx, zlib_head_bytes
	call	memset32
	; restore rdi/rsi back to our pending buffer
	xor	ecx, ecx
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	; if loadhead nonzero, jump straight to block_done_or_no_block
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 0
	jne	.block_done_or_no_block
	mov	dword [r12+zlib_dstate_strstart_ofs], ecx
	mov	[r12+zlib_dstate_block_start_ofs], rcx
	mov	dword [r12+zlib_dstate_insert_ofs], ecx
	jmp	.block_done_or_no_block
calign
.bstate_done_partial_flush:
	; _tr_align(s), then jmp to .block_done_or_no_block
	mov	eax, 2			; STATIC_TREES << 1
	send_bits_lit rax, 3
	; send_code(END_BLOCK, zlib_static_ltree) is next, END_BLOCK = 256, so we need to load up offset 256 * 4 from zlib_static_ltree
	mov	eax, dword [zlib_static_ltree + 1024]
	; the code, then length are encoded as shorts, code first, then length
	; so the low order word of eax is the code, and the high order is the length
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d
	; bi_flush
	; fallthrough toe block_done_or_no_block
calign
.block_done_or_no_block:
	; Assert(strm->avail_out > 0, "bug2");
	mov	eax, [r12+zlib_dstate_wrap_ofs]
	cmp	r13d, zlib_finish
	jne	.success_return
	jmp	qword [rax*8+.block_done_wrapjump]
dalign
.block_done_wrapjump:
	dq	.blockdone_nowrap, .blockdone_zwrap, .blockdone_gzwrap
calign
.blockdone_nowrap:
	; success return copy (NOTE: this is Z_STREAM_END return)
	; we flush all pending output here
	bi_flush
	mov	rdi, r15
	mov	rsi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rdx, [r12+zlib_dstate_pending_ofs]
	call	buffer$append
	xor	ecx, ecx
	mov	[r12+zlib_dstate_pending_ofs], rcx
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.blockdone_gzwrap:
	; two LSB uint32's get dumped into the buffer here
	mov	rcx, [rbx+zlib_adler_ofs]
	mov	rdx, [rbx+zlib_totalin_ofs]
	mov	dword [rdi+rsi], ecx
	mov	dword [rdi+rsi+4], edx
	add	rsi, 8
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; copy of .success_return
	; we flush all pending output here
	bi_flush
	mov	rdi, r15
	mov	rsi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rdx, [r12+zlib_dstate_pending_ofs]
	call	buffer$append
	xor	ecx, ecx
	mov	[r12+zlib_dstate_pending_ofs], rcx
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.blockdone_zwrap:
	; else, putShortMSB(strm->adler >> 16)
	; and   putShortMSB(strm->adler & 0xffff)
	; then set wrap = -wrap and be done
	mov	rcx, [rbx+zlib_adler_ofs]
	mov	edx, ecx		; save it
	shr	ecx, 16
	xchg	ch, cl
	xchg	dh, dl
	mov	word [rdi+rsi], cx
	mov	word [rdi+rsi+2], dx
	add	rsi, 4
	mov	[r12+zlib_dstate_pending_ofs], rsi
	; copy of .success_return fallthrough to avoid the extra jump
	; we flush all pending output here
	bi_flush
	mov	rdi, r15
	mov	rsi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rdx, [r12+zlib_dstate_pending_ofs]
	call	buffer$append
	xor	ecx, ecx
	mov	[r12+zlib_dstate_pending_ofs], rcx
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.success_return:
	; we flush all pending output here
	bi_flush
	mov	rdi, r15
	mov	rsi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rdx, [r12+zlib_dstate_pending_ofs]
	call	buffer$append
	xor	ecx, ecx
	mov	[r12+zlib_dstate_pending_ofs], rcx
	mov	eax, 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.error_return:
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog


	;
	; for all of the deflate_ methods, they are jumped to, not called
	; which means when they are done doing their business, they must put one of the zlib_bstate constants into eax
	; and then do a direct jump again to .bstate_done
	;
	; bstate constants:
	; zlib_bstate_need_more = 0
	; zlib_bstate_block_done = 1
	; zlib_bstate_finish_started = 2
	; zlib_bstate_finish_done = 3
	;
;--------------------------------------------------- deflate_stored -------------------------------------------------
calign
.deflate_stored:
	; on entry:
	; r12 == our dstate, r13d == flush, r14 == inbuf, r15 == outbuf, rbx == z_stream, rdi == pending buffer, rsi == pending offset
	; see commentary above re: return method
	;
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 1
	ja	.deflate_stored_windowokay
	call	.fill_window
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 0
	jne	.deflate_stored_windowokay
	mov	eax, zlib_bstate_need_more
	cmp	r13d, zlib_no_flush
	je	.bstate_done
	jmp	.deflate_stored_loopdone
calign
.deflate_stored_windowokay:
	mov	eax, [r12+zlib_dstate_lookahead_ofs]
	add	dword [r12+zlib_dstate_strstart_ofs], eax
	mov	dword [r12+zlib_dstate_lookahead_ofs], 0
	; figure out max_block_size
	mov	eax, 0xffff
	mov	ecx, zlib_overlay_bytes - 5
	cmp	eax, zlib_overlay_bytes - 5
	cmova	eax, ecx
	; max_block_size in rax
	mov	rcx, [r12+zlib_dstate_block_start_ofs]
	add	rcx, rax
	mov	edx, [r12+zlib_dstate_strstart_ofs]
	cmp	rdx, rcx
	jae	.deflate_stored_loop_case1
calign
.deflate_stored_loop_case1_continue:
	; strstart is still in edx
	sub	rdx, qword [r12+zlib_dstate_block_start_ofs]	; strstart - block_start
	cmp	edx, zlib_wsize - 262	
	jb	.deflate_stored		; go back around again
	; else, FLUSH_BLOCK(0)

	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block

	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	; FLUSH_BLOCK(0) done

	; then back around again
	jmp	.deflate_stored
calign
.deflate_stored_loop_case1:
	; lookaehead = (s->strstart - max_start)
	; strstart = max_start
	; flush_block(0)
	; then make sure strstart is still in edx, and jump to deflate_stored_loop_case1_continue
	; strstart is in edx, max_start is in rcx
	mov	r8, rdx
	sub	r8, rcx
	mov	dword [r12+zlib_dstate_lookahead_ofs], r8d	; lookahead = (strstart - max_start)
	mov	rdx, rcx
	mov	dword [r12+zlib_dstate_strstart_ofs], edx	; strstart = (max_start)
	; FLUSH_BLOCK(0)
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block

	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	; FLUSH_BLOCK(0) done
	mov	edx, [r12+zlib_dstate_strstart_ofs]
	jmp	.deflate_stored_loop_case1_continue

calign
.deflate_stored_loopdone:
	mov	dword [r12+zlib_dstate_insert_ofs], 0
	cmp	r13d, zlib_finish
	je	.deflate_stored_loopdone_finish
	mov	eax, zlib_bstate_block_done
	mov	edx, [r12+zlib_dstate_strstart_ofs]
	cmp	rdx, qword [r12+zlib_dstate_block_start_ofs]
	jle	.bstate_done
	; else, FLUSH_BLOCK(0)
	; FLUSH_BLOCK(0)
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block

	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	; FLUSH_BLOCK(0) done
	mov	eax, zlib_bstate_block_done
	jmp	.bstate_done
calign
.deflate_slow_finish:			; slow finish is the same, just calls flush_block(1) and returns .bstate_done
.deflate_fast_finish:			; fast finish is the same, just calls flush_block(1) and returns .bstate_done
.deflate_stored_loopdone_finish:
	; flush flags said finish, so FLUSH_BLOCK(1) and return zlib_bstate_finish_done
	; FLUSH_BLOCK(1)

	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	mov	edx, 1			; last
	call	.tr_flush_block

	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	; FLUSH_BLOCK(1) done
	mov	eax, zlib_bstate_finish_done
	jmp	.bstate_done


;--------------------------------------------------- deflate_fast ---------------------------------------------------
calign
.deflate_fast:
	; on entry:
	; r12 == our dstate, r13d == flush, r14 == inbuf, r15 == outbuf, rbx == z_stream, rdi == pending buffer, rsi == pending offset
	; see commentary above deflate_stored re: return method
	;
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 262
	jae	.deflate_fast_windowokay
	call	.fill_window
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 262
	jb	.deflate_fast_checkwindow
calign
.deflate_fast_windowokay:
	; UPDATE_HASH(s, h, c) = (h = (((h)<<s->hash_shift) ^ (c)) & s->hash_mask)
	;
	;
	; INSERT_STRING(s, str, match_head) = 
	; (UPDATE_HASH(s, s->ins_h, s->window[(str) + (MIN_MATCH-1)]), 
	; match_head = s->prev[(str) & s->w_mask] = s->head[s->ins_h],
	; s->head[s->ins_h] = (Pos)(str))
	mov	eax, [r12+zlib_dstate_strstart_ofs]		; load this up preemptively for noinitialinsert as well
	xor	r10d, r10d	; hash_head
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 3
	jb	.deflate_fast_noinitialinsert
	; INSERT_STRING(s, s->strstart, hash_head)
	; UPDATE_HASH(s, s->ins_h, s->window[(s->str_start) + (MIN_MATCH-1)])
	mov	rdx, [r12+zlib_dstate_window_ofs]
	; eax already strstart
	add	eax, 2					; MIN_MATCH - 1
	movzx	eax, byte [rdx+rax]			; c for UPDATE_HASH
	mov	edx, dword [r12+zlib_dstate_ins_h_ofs]	; h for UPDATE_HASH
	shl	edx, zlib_hashshift
	xor	edx, eax
	and	edx, zlib_hashmask			; h = (((h)<<s->hash_shift) ^ (c) & s->hash_mask)
	mov	dword [r12+zlib_dstate_ins_h_ofs], edx

	; next up: match_head (hash_head, r10d) = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h]
	mov	r8, [r12+zlib_dstate_head_ofs]
	mov	r9, [r12+zlib_dstate_prev_ofs]
	mov	ecx, dword [r12+zlib_dstate_strstart_ofs]
	movzx	r10d, word [r8+rdx*2]
	and	ecx, zlib_wmask
	mov	word [r9+rcx*2], r10w

	; next up: load back up strstart and set s->head[s->ins_h] to it
	mov	eax, [r12+zlib_dstate_strstart_ofs]
	mov	word [r8+rdx*2], ax
	; END INSERT_STRING(s, s->strstart, hash_head)
calign
.deflate_fast_noinitialinsert:
	test	r10d, r10d
	jz	.deflate_fast_check_match_length
	sub	eax, r10d
	cmp	eax, zlib_wsize - 262
	ja	.deflate_fast_check_match_length
	; else, s->match_length = longest_match(s, hash_head)
	; we'll go ahead and use rdi as our hash_head argument
	mov	edi, r10d
	push	r10
	call	.longest_match
	pop	r10
	mov	dword [r12+zlib_dstate_match_length_ofs], eax
calign
.deflate_fast_check_match_length:
	cmp	dword [r12+zlib_dstate_match_length_ofs], 3
	jb	.deflate_fast_literalonly
	push	r10
if defined zlib_debug_wedontdothis
	mov	edi, dword [r12+zlib_dstate_strstart_ofs]
	mov	esi, dword [r12+zlib_dstate_match_start_ofs]
	mov	edx, dword [r12+zlib_dstate_match_length_ofs]
	call	.check_match
end if
	; _tr_tally_dist(s, s->strstart - s->match_start, s->match_length - MIN_MATCH, bflush)

	mov	r8, [r12+zlib_dstate_l_buf_ofs]
	mov	r9, [r12+zlib_dstate_d_buf_ofs]
	mov	ecx, dword [r12+zlib_dstate_last_lit_ofs]

	; and it is a macro
	mov	edi, dword [r12+zlib_dstate_strstart_ofs]
	mov	esi, dword [r12+zlib_dstate_match_start_ofs]
	sub	edi, esi
	mov	esi, dword [r12+zlib_dstate_match_length_ofs]
	sub	esi, 3
	; edi == distance
	; esi == length
	; last_lit is a u32

	; we're using r10 as our hash_head, and bflush needs to be set by _tr_tally_dist macro
	; probably easiest way is to push it onto the stack along with hash_head and then end of loop check can pop them both
	; so we are free to blast eax, ecx, edx, r8d, r9d, and if we push r10 that too
	mov	word [r9+rcx*2], di			; s->d_buf[last_lit] = dist (word)
	mov	byte [r8+rcx], sil			; s->l_buf[last_lit] = len (byte)

	add	ecx, 1					; last_lit++
	sub	edi, 1					; distance--
	movzx	edx, byte [rsi+zlib_length_code]		; acquire length code[len]
	mov	dword [r12+zlib_dstate_last_lit_ofs], ecx	; put last_lit back
	lea	r8, [r12+zlib_dstate_dyn_ltree_ofs]
	add	edx, 257				; LITERALS + 1
	lea	r9, [r12+zlib_dstate_dyn_dtree_ofs]
	add	word [r8+rdx*4], 1			; s->dyn_ltree[_zlib_length_code[len]+LITERALS+1].Freq++
	; for the dyn_dtree, we need d_code(dist), and dist is in edi
	mov	r8d, edi
	shr	r8d, 7
	add	r8d, 256				; 256+(dist>>7)
	cmp	edi, 256
	cmovb	r8d, edi
	movzx	eax, byte [r8+zlib_dist_code]
	; so now eax == d_code(dist)
	add	word [r9+rax*4], 1			; s->dyn_dtree[d_code(dist)].Freq++
	; r10 was already pushed above, next is to determine whether to flush or not

	xor	edx, edx
	mov	eax, 1
	cmp	ecx, zlib_litbufsize - 1
	cmovne	eax, edx

	; eax == flush
	push	rax
	; end of _tr_tally_dist

	; next up: s->lookahead -= s->match_length
	mov	edx, dword [r12+zlib_dstate_match_length_ofs]
	sub	dword [r12+zlib_dstate_lookahead_ofs], edx

	; next up: if (s->match_length <= s->max_insert_length && s->lookahead >= MIN_MATCH) ...
	; max_insert_length == same as max_lazy_match
	cmp	edx, zlib_max_lazy
	ja	.deflate_fast_insert_nonew
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 3	; MIN_MATCH
	jb	.deflate_fast_insert_nonew
	; otherwise, insert new strings in hash table
	sub	dword [r12+zlib_dstate_match_length_ofs], 1	; s->match_length--
	; because we aren't calling check_match, this isn't necessary mov	r10, [rsp+8]					; get back hash_head (flush is at [rsp])
calign
.deflate_fast_insert_newstrings:
	mov	eax, dword [r12+zlib_dstate_strstart_ofs]
	add	eax, 1
	mov	dword [r12+zlib_dstate_strstart_ofs], eax	; s->strstart++
	
	; INSERT_STRING(s, s->strstart, hash_head)
	; UPDATE_HASH(s, s->ins_h, s->window[(s->str_start) + (MIN_MATCH-1)])
	mov	rdx, [r12+zlib_dstate_window_ofs]
	; eax already strstart
	add	eax, 2					; MIN_MATCH - 1
	movzx	eax, byte [rdx+rax]			; c for UPDATE_HASH
	mov	edx, dword [r12+zlib_dstate_ins_h_ofs]	; h for UPDATE_HASH
	shl	edx, zlib_hashshift
	xor	edx, eax
	and	edx, zlib_hashmask			; h = (((h)<<s->hash_shift) ^ (c) & s->hash_mask)
	mov	dword [r12+zlib_dstate_ins_h_ofs], edx

	; next up: match_head (hash_head, r10d) = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h]
	mov	r8, [r12+zlib_dstate_head_ofs]
	mov	r9, [r12+zlib_dstate_prev_ofs]
	mov	ecx, dword [r12+zlib_dstate_strstart_ofs]
	movzx	r10d, word [r8+rdx*2]
	and	ecx, zlib_wmask
	mov	word [r9+rcx*2], r10w

	; next up: load back up strstart and set s->head[s->ins_h] to it
	mov	eax, [r12+zlib_dstate_strstart_ofs]
	mov	word [r8+rdx*2], ax
	; END INSERT_STRING(s, s->strstart, hash_head)

	sub	dword [r12+zlib_dstate_match_length_ofs], 1
	jnz	.deflate_fast_insert_newstrings

	; r10 (hash_head) got updated, store it back in the stack as well
	mov	[rsp+8], r10

	add	eax, 1
	mov	dword [r12+zlib_dstate_strstart_ofs], eax	; s->strstart++
	; pop our flush and hash_head
	pop	rax						; flush
	pop	r10						; hash_head
	test	eax, eax
	jz	.deflate_fast
	; else, FLUSH_BLOCK(s, 0)
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	jmp	.deflate_fast
calign
.deflate_fast_insert_nonew:
	; match_length is already in edx
	; s->strstart += s->match_length
	mov	r8, [r12+zlib_dstate_window_ofs]
	xor	eax, eax
	add	dword [r12+zlib_dstate_strstart_ofs], edx
	; s->match_length = 0
	mov	dword [r12+zlib_dstate_match_length_ofs], eax
	; s->ins_h = s->window[s->strstart];
	mov	ecx, dword [r12+zlib_dstate_strstart_ofs]
	movzx	eax, byte [r8+rcx]
	mov	[r12+zlib_dstate_ins_h_ofs], eax		; ins_h = window[strstart]
	; next up: UPDATE_HASH(s, s->ins_h, s->window[s->strstart+1])
	; UPDATE_HASH(s, h, c) = (h = (((h)<<s->hash_shift) ^ (c)) & s->hash_mask)

	; eax == ins_h == h
	movzx	edx, byte [r8+rcx+1]				; s->window[s->strstart+1]
	; edx == c
	shl	eax, zlib_hashshift
	xor	eax, edx
	and	eax, zlib_hashmask
	mov	dword [r12+zlib_dstate_ins_h_ofs], eax
	; end of UPDATE_HASH(s, h, c)

	pop	rax						; flush
	pop	r10						; hash_head
	test	eax, eax
	jz	.deflate_fast
	; else, FLUSH_BLOCK(s, 0)
	
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	jmp	.deflate_fast
calign
.deflate_fast_literalonly:
	; _tr_tally_lit(s, s->window[s->strstart], bflush)
	mov	edi, dword [r12+zlib_dstate_strstart_ofs]
	mov	rdx, [r12+zlib_dstate_window_ofs]
	mov	ecx, dword [r12+zlib_dstate_last_lit_ofs]
	mov	r8, [r12+zlib_dstate_l_buf_ofs]
	mov	r9, [r12+zlib_dstate_d_buf_ofs]

	movzx	eax, byte [rdx+rdi]			; s->window[s->strstart]
	add	edi, 1					; strstart++, we'll put it back after we're done
	mov	word [r9+rcx*2], 0
	mov	byte [r8+rcx], al

	add	ecx, 1
	lea	r8, [r12+zlib_dstate_dyn_ltree_ofs]
	add	word [r8+rax*4], 1		; s->dyn_ltree[cc].Freq++
	mov	[r12+zlib_dstate_last_lit_ofs], ecx	; last_lit++

	; flush == (s->last_lit == s->lit_bufsize-1)
	xor	edx, edx
	mov	eax, 1
	cmp	ecx, zlib_litbufsize - 1
	cmovne	eax, edx
	; eax == flush

	mov	dword [r12+zlib_dstate_strstart_ofs], edi	; s->strstart++ (from above)
	sub	dword [r12+zlib_dstate_lookahead_ofs], 1	; s->lookahead--

	test	eax, eax
	jz	.deflate_fast

	; FLUSH_BLOCK(s, 0);
	
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	jmp	.deflate_fast
calign
.deflate_fast_checkwindow:
	; lookahead < MIN_LOOKAHEAD (262) ..
	mov	eax, zlib_bstate_need_more
	cmp	r13d, zlib_no_flush
	je	.bstate_done
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 0
	jne	.deflate_fast_windowokay

	; so we are all done with the for (;;)
	; next up is: s->insert = s->strstart < MIN_MATCH-1 ? s->strstart : MIN_MATCH-1
	mov	ecx, dword [r12+zlib_dstate_strstart_ofs]
	mov	edx, 2					; MIN_MATCH-1
	cmp	ecx, 2
	cmova	ecx, edx
	mov	dword [r12+zlib_dstate_insert_ofs], ecx
	cmp	r13d, zlib_finish
	je	.deflate_fast_finish			; stored_only finish does the same exact thing, so it is declared way above
	mov	eax, zlib_bstate_block_done
	cmp	dword [r12+zlib_dstate_last_lit_ofs], 0
	je	.bstate_done
	; FLUSH_BLOCK(s, 0)
	
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	mov	eax, zlib_bstate_block_done
	jmp	.bstate_done




;--------------------------------------------------- deflate_slow ---------------------------------------------------
calign
.deflate_slow:
	; on entry:
	; r12 == our dstate, r13d == flush, r14 == inbuf, r15 == outbuf, rbx == z_stream, rdi == pending buffer, rsi == pending offset
	; see commentary above deflate_stored re: return method
	;
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 262
	jae	.deflate_slow_windowokay
	call	.fill_window
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 262
	jb	.deflate_slow_checkwindow
calign
.deflate_slow_windowokay:
	; UPDATE_HASH(s, h, c) = (h = (((h)<<s->hash_shift) ^ (c)) & s->hash_mask)
	;
	;
	; INSERT_STRING(s, str, match_head) = 
	; (UPDATE_HASH(s, s->ins_h, s->window[(str) + (MIN_MATCH-1)]), 
	; match_head = s->prev[(str) & s->w_mask] = s->head[s->ins_h],
	; s->head[s->ins_h] = (Pos)(str))
	mov	eax, [r12+zlib_dstate_strstart_ofs]		; load this up preemptively for noinitialinsert as well
	xor	r10d, r10d	; hash_head
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 3
	jb	.deflate_slow_noinitialinsert
	; INSERT_STRING(s, s->strstart, hash_head)
	; UPDATE_HASH(s, s->ins_h, s->window[(s->str_start) + (MIN_MATCH-1)])
	mov	rdx, [r12+zlib_dstate_window_ofs]
	; eax already strstart
	add	eax, 2					; MIN_MATCH - 1
	movzx	eax, byte [rdx+rax]			; c for UPDATE_HASH
	mov	edx, dword [r12+zlib_dstate_ins_h_ofs]	; h for UPDATE_HASH
	shl	edx, zlib_hashshift
	xor	edx, eax
	and	edx, zlib_hashmask			; h = (((h)<<s->hash_shift) ^ (c) & s->hash_mask)
	mov	dword [r12+zlib_dstate_ins_h_ofs], edx

	; next up: match_head (hash_head, r10d) = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h]
	mov	r8, [r12+zlib_dstate_head_ofs]
	mov	r9, [r12+zlib_dstate_prev_ofs]
	mov	ecx, dword [r12+zlib_dstate_strstart_ofs]
	movzx	r10d, word [r8+rdx*2]
	and	ecx, zlib_wmask
	mov	word [r9+rcx*2], r10w

	; next up: load back up strstart and set s->head[s->ins_h] to it
	mov	eax, [r12+zlib_dstate_strstart_ofs]
	mov	word [r8+rdx*2], ax
	; END INSERT_STRING(s, s->strstart, hash_head)
calign
.deflate_slow_noinitialinsert:
	; different from deflate_fast:
	; s->prev_length = s->match_length, s->prev_match = s->match_start;
	; s->match_length = MIN_MATCH-1;
	mov	ecx, [r12+zlib_dstate_match_length_ofs]
	mov	edx, [r12+zlib_dstate_match_start_ofs]
	mov	r8d, 2

	mov	[r12+zlib_dstate_prev_length_ofs], ecx
	mov	[r12+zlib_dstate_prev_match_ofs], edx
	mov	[r12+zlib_dstate_match_length_ofs], r8d

	test	r10d, r10d
	jz	.deflate_slow_check_match_length		; !hash_head ?
	cmp	ecx, zlib_max_lazy
	jae	.deflate_slow_check_match_length		; prev_length >= max_lazy_match?

	sub	eax, r10d
	cmp	eax, zlib_wsize - 262
	ja	.deflate_slow_check_match_length

	; else, s->match_length = longest_match(s, hash_head)
	; we'll go ahead and use rdi as our hash_head argument
	mov	edi, r10d
	push	r10
	call	.longest_match
	pop	r10
	mov	dword [r12+zlib_dstate_match_length_ofs], eax

	; if match_length <= 5 and (strategy == filtered or (match_length == 3 && strstart - match_start > 4096))
	mov	ecx, [r12+zlib_dstate_match_length_ofs]
	cmp	ecx, 5
	ja	.deflate_slow_check_match_length
	cmp	dword [r12+zlib_dstate_strategy_ofs], 1		; Z_FILTERED
	je	.deflate_slow_force_match_length
	cmp	ecx, 3						; match_length == MIN_MATCH ?
	jne	.deflate_slow_check_match_length
	mov	eax, [r12+zlib_dstate_strstart_ofs]
	mov	edx, [r12+zlib_dstate_match_start_ofs]
	sub	eax, edx
	cmp	eax, 4096					; strstart - match_start > TOO_FAR?
	jle	.deflate_slow_check_match_length
calign
.deflate_slow_force_match_length:
	mov	dword [r12+zlib_dstate_match_length_ofs], 2	; MIN_MATCH-1
calign
.deflate_slow_check_match_length:
	mov	ecx, [r12+zlib_dstate_prev_length_ofs]
	mov	edx, [r12+zlib_dstate_match_length_ofs]
	mov	r8d, [r12+zlib_dstate_match_start_ofs]
	
	cmp	ecx, 3
	jb	.deflate_slow_check_match_available
	cmp	edx, ecx
	ja	.deflate_slow_check_match_available

	if profile_zlib_internals
		prolog_inner .deflate_slow_check_match_length
	end if

	push	r10
	; _tr_tally_dist(s, s->strstart - 1 - s->prev_match, s->prev_length - MIN_MATCH, bflush)
	mov	r8, [r12+zlib_dstate_l_buf_ofs]
	mov	r9, [r12+zlib_dstate_d_buf_ofs]
	mov	ecx, dword [r12+zlib_dstate_last_lit_ofs]

	; and it is a macro
	mov	edi, dword [r12+zlib_dstate_strstart_ofs]
	sub	edi, 1
	sub	edi, dword [r12+zlib_dstate_prev_match_ofs]
	mov	esi, dword [r12+zlib_dstate_prev_length_ofs]
	sub	esi, 3
	; edi == distance
	; esi == length
	; last_lit is a u32

	; we're using r10 as our hash_head, and bflush needs to be set by _tr_tally_dist macro
	; probably easiest way is to push it onto the stack along with hash_head and then end of loop check can pop them both
	; so we are free to blast eax, ecx, edx, r8d, r9d, and if we push r10 that too
	mov	word [r9+rcx*2], di			; s->d_buf[last_lit] = dist (word)
	mov	byte [r8+rcx], sil			; s->l_buf[last_lit] = len (byte)
	add	ecx, 1					; last_lit++
	sub	edi, 1					; distance--
	movzx	edx, byte [rsi+zlib_length_code]		; acquire length code[len]
	mov	dword [r12+zlib_dstate_last_lit_ofs], ecx	; put last_lit back
	lea	r8, [r12+zlib_dstate_dyn_ltree_ofs]
	add	edx, 257				; LITERALS + 1
	lea	r9, [r12+zlib_dstate_dyn_dtree_ofs]
	add	word [r8+rdx*4], 1			; s->dyn_ltree[_zlib_length_code[len]+LITERALS+1].Freq++

	; for the dyn_dtree, we need d_code(dist), and dist is in edi
	mov	r8d, edi
	shr	r8d, 7
	add	r8d, 256				; 256+(dist>>7)

	cmp	edi, 256
	cmovb	r8d, edi
	movzx	eax, byte [r8+zlib_dist_code]

	; so now eax == d_code(dist)
	add	word [r9+rax*4], 1			; s->dyn_dtree[d_code(dist)].Freq++

	; r10 was already pushed above, next is to determine whether to flush or not
	xor	edx, edx
	mov	eax, 1
	cmp	ecx, zlib_litbufsize - 1
	cmovne	eax, edx
	; eax == flush
	push	rax
	; end of _tr_tally_dist

	mov	r11d, dword [r12+zlib_dstate_lookahead_ofs]

	; next up: s->lookahead -= s->prev_length -1
	mov	edx, dword [r12+zlib_dstate_prev_length_ofs]
	sub	edx, 1
	sub	dword [r12+zlib_dstate_lookahead_ofs], edx
	; s->prev_length -= 2
	sub	edx, 1
	mov	dword [r12+zlib_dstate_prev_length_ofs], edx

	push	rbx

	; next up: do if (++strstart <= max_insert) INSERT_STRING(s, s->strstart, hash_head) while (--prev_length)
	; compute max_insert (pre the above mods) first

	mov	ebx, dword [r12+zlib_dstate_strstart_ofs]
	sub	r11d, 3
	add	r11d, ebx					; max_insert
calign
.deflate_slow_insert_newstrings:
	add	ebx, 1						; ++strstart
	cmp	ebx, r11d					; <= max_insert
	ja	.deflate_slow_insert_newstrings_next

	; INSERT_STRING(s, s->strstart, hash_head)
	; UPDATE_HASH(s, s->ins_h, s->window[(s->str_start) + (MIN_MATCH-1)])
	mov	rdx, [r12+zlib_dstate_window_ofs]
	movzx	eax, byte [rdx+rbx+2]			; c for UPDATE_HASH
	mov	edx, dword [r12+zlib_dstate_ins_h_ofs]	; h for UPDATE_HASH
	shl	edx, zlib_hashshift
	xor	edx, eax
	and	edx, zlib_hashmask			; h = (((h)<<s->hash_shift) ^ (c) & s->hash_mask)
	mov	dword [r12+zlib_dstate_ins_h_ofs], edx

	; next up: match_head (hash_head, r10d) = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h]
	mov	r8, [r12+zlib_dstate_head_ofs]
	mov	r9, [r12+zlib_dstate_prev_ofs]
	mov	ecx, ebx
	movzx	r10d, word [r8+rdx*2]
	and	ecx, zlib_wmask
	mov	word [r9+rcx*2], r10w

	; next up: load back up strstart and set s->head[s->ins_h] to it
	mov	word [r8+rdx*2], bx
	; END INSERT_STRING(s, s->strstart, hash_head)
calign
.deflate_slow_insert_newstrings_next:
	sub	dword [r12+zlib_dstate_prev_length_ofs], 1
	jnz	.deflate_slow_insert_newstrings
	xor	edx, edx

	add	ebx, 1
	mov	[r12+zlib_dstate_strstart_ofs], ebx
	pop	rbx

	; r10 (hash_head) got updated, store it back in the stack as well
	mov	[rsp+8], r10
	mov	[r12+zlib_dstate_match_available_ofs], edx	; match_available = 0
	mov	dword [r12+zlib_dstate_match_length_ofs], 2	; match_length = MIN_MATCH-1

	; pop our flush and hash_head
	pop	rax						; flush
	pop	r10						; hash_head

	if profile_zlib_internals
		epilog_inner
	end if

	test	eax, eax
	jz	.deflate_slow

	; else, FLUSH_BLOCK(s, 0)
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	jmp	.deflate_slow
calign
.deflate_slow_check_match_available:
	cmp	dword [r12+zlib_dstate_match_available_ofs], 0
	jne	.deflate_slow_match_available
	; otherwise, set match_available = 1, strstart++, lookahead-- and go back to the top
	mov	dword [r12+zlib_dstate_match_available_ofs], 1
	add	dword [r12+zlib_dstate_strstart_ofs], 1
	sub	dword [r12+zlib_dstate_lookahead_ofs], 1
	jmp	.deflate_slow
calign
.deflate_slow_match_available:
	if profile_zlib_internals
		prolog_inner .deflate_slow_match_available
	end if

	; _tr_tally_lit(s, s->window[s->strstart-1], bflush)
	mov	edi, dword [r12+zlib_dstate_strstart_ofs]
	mov	rdx, [r12+zlib_dstate_window_ofs]
	sub	edi, 1
	mov	ecx, dword [r12+zlib_dstate_last_lit_ofs]
	mov	r8, [r12+zlib_dstate_l_buf_ofs]
	mov	r9, [r12+zlib_dstate_d_buf_ofs]

	movzx	eax, byte [rdx+rdi]			; s->window[s->strstart-1]
	add	edi, 2					; strstart++, we'll put it back after we're done
	mov	word [r9+rcx*2], 0
	mov	byte [r8+rcx], al
	add	ecx, 1
	lea	r8, [r12+zlib_dstate_dyn_ltree_ofs]
	add	word [r8+rax*4], 1		; s->dyn_ltree[cc].Freq++
	mov	[r12+zlib_dstate_last_lit_ofs], ecx	; last_lit++

	; flush == (s->last_lit == s->lit_bufsize-1)
	xor	edx, edx
	mov	eax, 1
	cmp	ecx, zlib_litbufsize - 1
	cmovne	eax, edx
	; eax == flush

	mov	dword [r12+zlib_dstate_strstart_ofs], edi	; s->strstart++ (from above)
	sub	dword [r12+zlib_dstate_lookahead_ofs], 1	; s->lookahead--

	if profile_zlib_internals
		epilog_inner
	end if

	test	eax, eax
	jz	.deflate_slow

	; FLUSH_BLOCK_ONLY(s, 0);
	
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	jmp	.deflate_slow
calign
.deflate_slow_checkwindow:
	; lookahead < MIN_LOOKAHEAD (262) ..
	mov	eax, zlib_bstate_need_more
	cmp	r13d, zlib_no_flush
	je	.bstate_done
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 0
	jne	.deflate_slow_windowokay


	; so we are all done with the for (;;)
	cmp	dword [r12+zlib_dstate_match_available_ofs], 0
	je	.deflate_slow_alldone

	; _tr_tally_lit(s, s->window[s->strstart-1], bflush)
	mov	edi, dword [r12+zlib_dstate_strstart_ofs]
	mov	rdx, [r12+zlib_dstate_window_ofs]
	sub	edi, 1
	mov	ecx, dword [r12+zlib_dstate_last_lit_ofs]
	mov	r8, [r12+zlib_dstate_l_buf_ofs]
	mov	r9, [r12+zlib_dstate_d_buf_ofs]

	movzx	eax, byte [rdx+rdi]			; s->window[s->strstart]
	add	edi, 1					; strstart++, we'll put it back after we're done
	mov	word [r9+rcx*2], 0
	mov	byte [r8+rcx], al
	add	ecx, 1
	lea	r8, [r12+zlib_dstate_dyn_ltree_ofs]
	add	word [r8+rax*4], 1		; s->dyn_ltree[cc].Freq++
	mov	[r12+zlib_dstate_last_lit_ofs], ecx	; last_lit++

	; flush == (s->last_lit == s->lit_bufsize-1)
	xor	edx, edx
	mov	eax, 1
	cmp	ecx, zlib_litbufsize - 1
	cmovne	eax, edx
	; eax == flush

	mov	dword [r12+zlib_dstate_match_available_ofs], 0
	
calign
.deflate_slow_alldone:
	; next up is: s->insert = s->strstart < MIN_MATCH-1 ? s->strstart : MIN_MATCH-1
	mov	ecx, dword [r12+zlib_dstate_strstart_ofs]
	mov	edx, 2					; MIN_MATCH-1
	cmp	ecx, 2
	cmova	ecx, edx
	mov	dword [r12+zlib_dstate_insert_ofs], ecx
	cmp	r13d, zlib_finish
	je	.deflate_slow_finish			; stored_only finish does the same exact thing, so it is declared way above
	mov	eax, zlib_bstate_block_done
	cmp	dword [r12+zlib_dstate_last_lit_ofs], 0
	je	.bstate_done
	; FLUSH_BLOCK(s, 0)
	
	mov	r8, [r12+zlib_dstate_block_start_ofs]
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	xor	r9d, r9d
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, r8
	cmp	r8, 0
	cmovl	rdi, r9
	; stored_len is next
	mov	rsi, r10
	sub	rsi, r8
	xor	edx, edx		; last
	call	.tr_flush_block
	mov	r10d, [r12+zlib_dstate_strstart_ofs]
	mov	[r12+zlib_dstate_block_start_ofs], r10

	; flush_pending: (tr_flush_bits just calls bi_flush)

	; restore rdi/rsi as our pending buffer for bi_flush
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	bi_flush

	mov	rdx, [r12+zlib_dstate_pending_ofs]
	add	qword [rbx+zlib_totalout_ofs], rdx
	mov	rsi, [r12+zlib_dstate_pending_out_ofs]
	mov	rdi, r15
	call	buffer$append

	; we know that will always succeed, so we can leave pending_out_ofs alone
	; and we can just clear pending entirely
	mov	qword [r12+zlib_dstate_pending_ofs], 0
	mov	eax, zlib_bstate_block_done
	jmp	.bstate_done


;--------------------------------------------------- deflate_huff ---------------------------------------------------
calign
.deflate_huff:
	; on entry:
	; r12 == our dstate, r13d == flush, r14 == inbuf, r15 == outbuf, rbx == z_stream, rdi == pending buffer, rsi == pending offset
	;
	; do I really need to even write this? none of my stuff uses it
	;
	; a note here: our strategy is fixed at zero, so during normal operations, these won't occur
	; (and only would if you are playing around with it)
	breakpoint


;--------------------------------------------------- deflate_rle ----------------------------------------------------
calign
.deflate_rle:
	; on entry:
	; r12 == our dstate, r13d == flush, r14 == inbuf, r15 == outbuf, rbx == z_stream, rdi == pending buffer, rsi == pending offset
	;
	; do I really need to even write this? none of my stuff uses it
	;
	; a note here: our strategy is fixed at zero, so during normal operations, these won't occur
	; (and only would if you are playing around with it)
	breakpoint

;
; for deflate levels in the FAST area, longest_match is not where most time is spent
; for deflate level == 9, this is where the most time gets spent.
;
; this is basically identical to the above, only we avoid byte compares where possible and do the outer loop
; with words only, and the inner loop in 8 byte all-at-once sections
;

; TODO: rewrite me, optimize me, haha as this reference-method is a hideous mess
;

;--------------------------------------------------- longest_match --------------------------------------------------
falign
.longest_match:
	if profile_zlib_internals
		prolog	.longest_match
	end if
	; so on entry, rdi == cur_match (IPos), r12 == our dstate, r13d == flush, r14 == inbuf, r15 == outbuf, rbx == z_stream
	; we need to return match length
	push	rbx r13 r14 r15

	mov	rbx, [r12+zlib_dstate_window_ofs]
	mov	esi, dword [r12+zlib_dstate_strstart_ofs]
	mov	ecx, zlib_max_chain				; chain_length
	mov	r15, rbx					; window
	add	rbx, rsi					; scan


	mov	r14, rbx
	add	r14, 258					; s->window + s->strstart + MAX_MATCH == strend

	mov	edx, dword [r12+zlib_dstate_prev_length_ofs]	; best_len

	mov	rax, rbx
	mov	r8d, zlib_nice_length				; nice_match
	add	rax, rdx

	sub	rax, 1
	mov	r10d, esi
	
	xor	r11d, r11d
	sub	r10d, zlib_wsize - 262				; - (MAX_DIST(s))
	cmp	esi, zlib_wsize - 262
	cmova	r9d, r10d
	cmovbe	r9d, r11d					; limit

	movzx	r11d, word [rax]				; word in ebp == scan_end1 and scan_end

	mov	eax, ecx
	mov	r10, [r12+zlib_dstate_prev_ofs]			; prev
	shr	eax, 2

	cmp	edx, zlib_good_length
	cmovae	ecx, eax

	mov	eax, dword [r12+zlib_dstate_lookahead_ofs]

	cmp	r8d, eax
	cmova	r8d, eax
calign
.longest_match_outer_loop:
	mov	rax, r15
	mov	r13, r15
	add	rax, rdi
	add	r13, rdi					; match = s->window + cur_match
	add	rax, rdx
	sub	rax, 1

	; rbx == scan, r13 == match, rax == match[best_len-1]
	cmp	word [rax], r11w				; scan_end1 and scan_end
	jne	.longest_match_outer_next

	movzx	eax, word [r13]
	movzx	esi, word [rbx]
	cmp	ax, si
	jne	.longest_match_outer_next
	add	r13, 2
	add	rbx, 2
calign
.longest_match_inner_loop:
	add	r13, 1
	add	rbx, 1
	mov	rax, [r13]
	xor	rax, [rbx]
	jz	.longest_match_inner_nextq
	bsf	rax, rax
	shr	rax, 3			; the byte # that was different
	add	r13, rax
	add	rbx, rax
	jmp	.longest_match_inner_done
calign
.longest_match_inner_nextq:
	add	r13, 7
	add	rbx, 7
	cmp	rbx, r14					; scan < strend
	jb	.longest_match_inner_loop
	; special case here for when we actually DO run to the end, as there is no further byte checking to be done

	mov	rax, r14
	sub	rax, rbx
	mov	esi, 258
	sub	esi, eax					; len = (MAX_MATCH) - (int)(strend - scan)
	mov	rbx, r14
	sub	rbx, 258					; scan = strend - (MAX_MATCH)
	cmp	esi, edx					; len > best_len ?
	jbe	.longest_match_outer_next
	mov	dword [r12+zlib_dstate_match_start_ofs], edi	; s->match_start = cur_match
	mov	edx, esi					; best_len = len
	cmp	esi, r8d					; len >= nice_match
	jae	.longest_match_outer_done
	; else, scan_end1 = scan[best_len-1], scan_end = scan[best_len]
	movzx	r11d, word [rbx+rdx-1]
	jmp	.longest_match_outer_next
calign
.longest_match_inner_done:
	mov	rsi, rbx
	movzx	eax, byte [rbx]
	add	rsi, 1
	cmp	al, byte [r13]
	cmove	rbx, rsi
	mov	rax, r14
	sub	rax, rbx
	mov	esi, 258
	sub	esi, eax					; len = (MAX_MATCH) - (int)(strend - scan)
	mov	rbx, r14
	sub	rbx, 258					; scan = strend - (MAX_MATCH)
	cmp	esi, edx					; len > best_len ?
	jbe	.longest_match_outer_next

	mov	dword [r12+zlib_dstate_match_start_ofs], edi	; s->match_start = cur_match
	mov	edx, esi					; best_len = len
	cmp	esi, r8d					; len >= nice_match
	jae	.longest_match_outer_done
	; else, scan_end1 = scan[best_len-1], scan_end = scan[best_len]
	movzx	r11d, word [rbx+rdx-1]
calign
.longest_match_outer_next:
	and	edi, zlib_wmask					; cur_match & wmask
	movzx	edi, word [r10+rdi*2]				; prev[cur_match & wmask]
	cmp	edi, r9d					; > limit?
	jbe	.longest_match_outer_done
	sub	ecx, 1						; --chain_length != 0
	jnz	.longest_match_outer_loop
calign
.longest_match_outer_done:
	mov	ecx, dword [r12+zlib_dstate_lookahead_ofs]
	cmp	edx, ecx
	cmovbe	eax, edx
	cmova	eax, ecx
	pop	r15 r14 r13 rbx
if profile_zlib_internals
	epilog
else
	ret
end if




;--------------------------------------------------- fill_window ----------------------------------------------------
falign
.fill_window:
	if profile_zlib_internals
		prolog	.fill_window
	end if
	; all callee-saves are assumed to be valid, we blast pretty much everything else

	mov	edx, zlib_wsize shl 1
	mov	eax, [r12+zlib_dstate_strstart_ofs]
	sub	rdx, qword [r12+zlib_dstate_lookahead_ofs]
	sub	rdx, rax					; more == amount of space at the end of the window

	cmp	eax, zlib_wsize + (zlib_wsize - 262)
	; MAX_MATCH is 258
	; MIN_MATCH is 3
	; MIN_LOOKAHEAD = (MAX_MATCH + MIN_MATCH + 1)  == 258 + 3 == 261 + 1 == 262
	; MAX_DIST(s) = (w_size - MIN_LOOKAHEAD)
	jl	.fill_window_upperhalf_okay

	; else, move the upper half to the lower one to make room in the upper half
	mov	rdi, [r12+zlib_dstate_window_ofs]
	mov	edx, zlib_wsize
	mov	rsi, rdi
	add	rsi, zlib_wsize					; window + w_size
	call	memcpy

if defined zlib_fillwindow_reference

	mov	edx, zlib_hashsize				; n
	mov	rsi, [r12+zlib_dstate_head_ofs]			; the actual head buffer
	xor	ecx, ecx
	sub	dword [r12+zlib_dstate_match_start_ofs], zlib_wsize
	sub	dword [r12+zlib_dstate_strstart_ofs], zlib_wsize
	sub	qword [r12+zlib_dstate_block_start_ofs], zlib_wsize
	mov	r8d, zlib_wsize

	; slide the hash table
	; we need the address of the word at head[n]
	lea	rsi, [rsi+rdx*2]				; p
calign
.fill_window_slide_loop:
	sub	rsi, 2
	movzx	eax, word [rsi]					; m = *--p
	mov	r9d, eax
	sub	r9d, r8d					; m - w_size
	cmp	eax, r8d
	cmovae	eax, r9d
	cmovb	eax, ecx
	mov	word [rsi], ax
	sub	edx, 1
	jnz	.fill_window_slide_loop

	mov	rsi, [r12+zlib_dstate_prev_ofs]
	mov	edx, r8d					; n = w_size
	; now we have to do the same with prev
	lea	rsi, [rsi+rdx*2]
calign
.fill_window_slide_prev_loop:
	sub	rsi, 2
	movzx	eax, word [rsi]					; m = *--p
	mov	r9d, eax
	sub	r9d, r8d					; m - w_size
	cmp	eax, r8d
	cmovae	eax, r9d
	cmovb	eax, ecx
	mov	word [rsi], ax
	sub	edx, 1
	jnz	.fill_window_slide_prev_loop

else

	; this does the same thing as above, cleaner/faster though

	; NOTE, haha, i used psubusw before i actually saw intel's later patch to the C reference that does the same, hahah
	; good to know i picked the right way to do it

	sub	dword [r12+zlib_dstate_match_start_ofs], zlib_wsize
	sub	dword [r12+zlib_dstate_strstart_ofs], zlib_wsize
	sub	qword [r12+zlib_dstate_block_start_ofs], zlib_wsize

	mov	rdi, [r12+zlib_dstate_prev_ofs]			; prev & head are adjacent, so we can do all of them in one pass, 16 bytes at a time
	movdqa	xmm8, dqword [.wsizeby8]
	mov	ecx, 1024
calign
.fill_window_slide_loop:
	movdqa	xmm0, [rdi]
	movdqa	xmm1, [rdi+16]
	movdqa	xmm2, [rdi+32]
	movdqa	xmm3, [rdi+48]
	movdqa	xmm4, [rdi+64]
	movdqa	xmm5, [rdi+80]
	movdqa	xmm6, [rdi+96]
	movdqa	xmm7, [rdi+112]
	psubusw	xmm0, xmm8
	psubusw	xmm1, xmm8
	psubusw	xmm2, xmm8
	psubusw	xmm3, xmm8
	psubusw	xmm4, xmm8
	psubusw xmm5, xmm8
	psubusw xmm6, xmm8
	psubusw	xmm7, xmm8
	movdqa	[rdi], xmm0
	movdqa	[rdi+16], xmm1
	movdqa	[rdi+32], xmm2
	movdqa	[rdi+48], xmm3
	movdqa	[rdi+64], xmm4
	movdqa	[rdi+80], xmm5
	movdqa	[rdi+96], xmm6
	movdqa	[rdi+112], xmm7
	add	rdi, 128
	sub	ecx, 1
	jnz	.fill_window_slide_loop
end if

	; reset more cuz we made calls out and blasted it anyway
	mov	edx, zlib_wsize shl 1
	sub	rdx, qword [r12+zlib_dstate_lookahead_ofs]
	sub	rdx, qword [r12+zlib_dstate_strstart_ofs]	; more == amount of space at the end of the window

	; fallthrough to fill_window_upperhalf_okay
calign
.fill_window_upperhalf_okay:

	cmp	qword [r14+buffer_user_ofs+8], 0		; # of bytes remaining to be processed in inbuf
	je	.fill_window_nothingtoread

	; else, we need to call read_buf to fill our window
	mov	rdi, [r12+zlib_dstate_window_ofs]
	mov	rsi, rdx					; more
	add	rdi, qword [r12+zlib_dstate_strstart_ofs]
	add	rdi, qword [r12+zlib_dstate_lookahead_ofs]
	call	.read_buf

	; rax now contains now much we read
	add	qword [r12+zlib_dstate_lookahead_ofs], rax
	mov	ecx, [r12+zlib_dstate_lookahead_ofs]
	add	ecx, dword [r12+zlib_dstate_insert_ofs]

	cmp	ecx, 3						; MIN_MATCH
	jb	.fill_window_readcheck
	; else, initialize the hash value now that we have some input
	mov	rdi, [r12+zlib_dstate_window_ofs]
	mov	rsi, [r12+zlib_dstate_head_ofs]
	mov	r8, [r12+zlib_dstate_prev_ofs]
	mov	r9d, [r12+zlib_dstate_strstart_ofs]
	sub	r9d, dword [r12+zlib_dstate_insert_ofs]	; str
	movzx	r10d, byte [rdi+r9]			; ins_h
	
	; s->ins_h = ((s->ins_h << s->hash_shift) ^ s->window[str+1]) & s->hash_mask
	shl	r10d, zlib_hashshift
	xor	r10b, byte [rdi+r9+1]
	and	r10d, zlib_hashmask
	
	mov	dword [r12+zlib_dstate_ins_h_ofs], r10d	; s->ins_h =
calign
.fill_window_readloop_hashinitloop:
	cmp	dword [r12+zlib_dstate_insert_ofs], 0
	je	.fill_window_readcheck

	shl	r10d, zlib_hashshift
	xor	r10b, byte [rdi+r9+2]
	and	r10d, zlib_hashmask

	mov	dword [r12+zlib_dstate_ins_h_ofs], r10d	; s->ins_h =

	; next is s->prev[str & s->w_mask] = s->head[s->ins_h]
	movzx	eax, word [rsi+r10*2]				; eax = s->head[s->ins_h]
	mov	r11d, r9d
	and	r11d, zlib_wmask
	mov	word [r8+r11*2], ax
	; next is: s->head[s->ins_h] = (Pos)str
	mov	word [r8+r10*2], r9w
	add	r9d, 1
	sub	dword [r12+zlib_dstate_insert_ofs], 1
	mov	eax, [r12+zlib_dstate_lookahead_ofs]
	add	eax, dword [r12+zlib_dstate_insert_ofs]
	cmp	eax, 3
	jb	.fill_window_readcheck
	jmp	.fill_window_readloop_hashinitloop
align 16
.wsizeby8	dw	0x8000,0x8000,0x8000,0x8000,0x8000,0x8000,0x8000,0x8000
calign
.fill_window_readcheck:
	mov	rax, [r12+zlib_dstate_lookahead_ofs]

	; while (s->lookahead < MIN_LOOKAHEAD && s->strm->avail_in != 0), jmp up to to top again
	cmp	dword [r12+zlib_dstate_lookahead_ofs], 262	; MIN_LOOKAHEAD
	jae	.fill_window_nothingtoread

	cmp	qword [r14+buffer_user_ofs+8], 0		; # of bytes remaining to be processed in inbuf
	jne	.fill_window
	; else, fallthrough, top while loop bit is done now
calign
.fill_window_nothingtoread:
	; top half read while loop done...
	mov	rax, [r12+zlib_dstate_high_water_ofs]		; high_water
	mov	ecx, zlib_wsize shl 1				; window_size
	cmp	rax, rcx
if profile_zlib_internals
	jae	.profiled_retonly
else
	jae	.retonly
end if
	mov	edx, [r12+zlib_dstate_strstart_ofs]		; curr = strstart
	add	rdx, qword [r12+zlib_dstate_lookahead_ofs]	; + lookahead
	cmp	rax, rdx
	jae	.fill_window_highwater_checktwo

	; previous high water mark below current data -- zero WIN_INIT
	; bytes or up to the end of the window, whichever is less
	mov	r9, rdx
	sub	rcx, rdx
	mov	r8, 258						; MAX_MATCH (aka WIN_INIT)
	cmp	rcx, r8
	cmova	rcx, r8
	add	r9, rcx
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, rdx
	xor	esi, esi
	mov	rdx, rcx
	; high_water = curr + init
	mov	[r12+zlib_dstate_high_water_ofs], r9
	call	memset
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.fill_window_highwater_checktwo:
	; high_water still sitting in rax
	; curr still sitting in rdx
	add	rdx, 258					; MAX_MATCH (aka WIN_INIT)
	cmp	rax, rdx
if profile_zlib_internals
	jae	.profiled_retonly
else
	jae	.retonly
end if

	; else, high_water < curr + WIN_INIT
	sub	rdx, rax					; init = curr + WIN_INIT - high_water
	; window_size still in rcx, sub high_water from it and boundscheck
	sub	rcx, rax
	cmp	rdx, rcx
	cmova	rdx, rcx
	; we have to add init to high_water
	mov	rdi, [r12+zlib_dstate_window_ofs]
	add	rdi, rax
	xor	esi, esi
	add	qword [r12+zlib_dstate_high_water_ofs], rdx
	call	memset
if profile_zlib_internals
	epilog
else
	ret
end if

if profile_zlib_internals
calign
.profiled_retonly:
	epilog
end if




;--------------------------------------------------- read_buf -------------------------------------------------------
calign
.read_buf:
	if profile_zlib_internals
		prolog	.read_buf
	end if
	; arguments: rdi == destination buffer, rsi == size of spot to put it, all callee-saves are assumed to be valid
	; we'll consume from r14, return in rax/eax, r12 is still valid dstate
	xor	eax, eax
	mov	rdx, [r14+buffer_user_ofs+8]	; # of bytes remaining to be processed in inbuf
	cmp	rdx, rsi
	cmova	rdx, rsi
	test	rdx, rdx
if profile_zlib_internals
	jz	.profiled_retonly
else
	jz	.retonly
end if
	sub	rsp, 16
	mov	rsi, [r14+buffer_user_ofs]	; current pointer into the inbuf
	mov	[rsp], rdi
	mov	[rsp+8], rdx
	call	memcpy
	mov	eax, [r12+zlib_dstate_wrap_ofs]
	mov	rdi, [rbx+zlib_adler_ofs]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	jmp	qword [rax*8+.read_buf_wrapjump]
dalign
.read_buf_wrapjump:
	dq	.read_buf_nowrap, .read_buf_zwrap, .read_buf_gzwrap
calign
.read_buf_zwrap:
	call	adler32
	mov	[rbx+zlib_adler_ofs], rax
	mov	rax, [rsp+8]
	add	qword [r14+buffer_user_ofs], rax
	sub	qword [r14+buffer_user_ofs+8], rax
	add	qword [rbx+zlib_totalin_ofs], rax
	add	rsp, 16
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.read_buf_gzwrap:
	call	crc$32
	mov	[rbx+zlib_adler_ofs], rax
	mov	rax, [rsp+8]
	add	qword [r14+buffer_user_ofs], rax
	sub	qword [r14+buffer_user_ofs+8], rax
	add	qword [rbx+zlib_totalin_ofs], rax
	add	rsp, 16
if profile_zlib_internals
	epilog
else
	ret
end if
.read_buf_nowrap:
	; else, no wrap
	add	qword [rbx+zlib_totalin_ofs], rdx
	; rdx has the # of bytes we consumed
	add	qword [r14+buffer_user_ofs], rdx	; increment the current pointer by how many we read
	sub	qword [r14+buffer_user_ofs+8], rdx	; decrement the remaining bytes available by how many we read
	mov	rax, rdx
	add	rsp, 16
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.retonly:
	; common jump point for when we just want a ret and nothing else
	ret

;--------------------------------------------------- tr_flush_block -------------------------------------------------
falign
.tr_flush_block:
	; callee-saved are presumed good, args are: rdi == buf, rsi == stored_len, edx == last (bool)
	if profile_zlib_internals
		prolog	.tr_flush_block
	end if

	mov	r8, rsi		; opt_lenb
	mov	r9, rsi		; static_lenb
	xor	r10d, r10d	; max_blindex
	add	r8, 5
	add	r9, 5

	cmp	dword [r12+zlib_dstate_level_ofs], 0
	je	.tr_flush_block_notrees

	; save our args
	push	rdi rsi rdx
	; verify that our datatype has been set
	call	.maybe_set_data_type
	; build_tree(s, (tree_desc *)(&(s->l_desc)))
	lea	rdi, [r12+zlib_dstate_l_desc_ofs]
	call	.build_tree

	mov	r8, [r12+zlib_dstate_opt_len_ofs]
	mov	r9, [r12+zlib_dstate_static_len_ofs]

	; build_tree(s, (tree_desc *)(&(s->d_desc)))
	lea	rdi, [r12+zlib_dstate_d_desc_ofs]
	call	.build_tree

	mov	r8, [r12+zlib_dstate_opt_len_ofs]
	mov	r9, [r12+zlib_dstate_static_len_ofs]

	; max_blindex = build_bl_tree(s)
	call	.build_bl_tree
	mov	r10d, eax	; max_blindex

	; opt_lenb = (s->opt_len+3+7)>>3
	mov	r8, [r12+zlib_dstate_opt_len_ofs]
	add	r8, 10
	shr	r8, 3

	; static_lenb = (s->static_len+3+7)>>3
	mov	r9, [r12+zlib_dstate_static_len_ofs]
	add	r9, 10
	shr	r9, 3

	; if static_lenb <= opt_lenb then opt_lenb = static_lenb
	cmp	r9, r8
	cmovl	r8, r9

	pop	rdx rsi rdi
	; fallthrough to _tr_flush_block_notrees
calign
.tr_flush_block_notrees:

	mov	rax, rsi
	add	rax, 4
	cmp	rax, r8
	ja	.tr_flush_block_notrees_notstored
	test	rdi, rdi
	jz	.tr_flush_block_notrees_notstored

	push	rdi			; save the buffer, because send_bits_lit blasts r8, r9

	mov	r10, rsi		; save them temporarily, because send_bits_lit needs them to be pointing to our pending buffer goods
	mov	r11, rdx

	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	mov	eax, edx		; (STORED_BLOCK << 1) + last (STORED_BLOCK == 0)
	send_bits_lit rax, 3

	; copy_block(buf, stored_len, 1) is next
	bi_windup
	mov	eax, r10d
	mov	ecx, r10d
	not	eax
	mov	word [rdi+rsi], cx
	mov	word [rdi+rsi+2], ax
	add	rsi, 4
	; done below: mov	[r12+zlib_dstate_pending_ofs], rsi

	; preserve last across call to memcpy
	lea	rdi, [rdi+rsi]
	add	rsi, r10
	mov	[r12+zlib_dstate_pending_ofs], rsi
	mov	rdx, r10
	mov	rsi, [rsp]
	push	r11
	call	memcpy

	; init_block is next
	; L_CODES == 286
	; D_CODES == 30
	; BL_CODES == 19
	lea	rdi, [r12+zlib_dstate_dyn_ltree_ofs]
	lea	rsi, [r12+zlib_dstate_dyn_dtree_ofs]
	lea	rdx, [r12+zlib_dstate_bl_tree_ofs]
	mov	ecx, 19
calign
.initblock1:
	mov	word [rdi], 0
	mov	word [rsi], 0
	mov	word [rdx], 0
	add	rdi, 4
	add	rsi, 4
	add	rdx, 4
	sub	ecx, 1
	jnz	.initblock1
	mov	ecx, 11
calign
.initblock2:
	mov	word [rdi], 0
	mov	word [rsi], 0
	add	rdi, 4
	add	rsi, 4
	sub	ecx, 1
	jnz	.initblock2
	mov	ecx, 256
calign
.initblock3:
	mov	word [rdi], 0
	add	rdi, 4
	sub	ecx, 1
	jnz	.initblock3

	xor	eax, eax
	pop	r11
	add	rsp, 8			; undo the previous bfufer store, we aren't interested in it anymore
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	mov	word [r12+zlib_dstate_dyn_ltree_ofs + 256*4], 1	; dyn_ltree[END_BLOCK].Freq = 1
	mov	[r12+zlib_dstate_opt_len_ofs], rax
	mov	[r12+zlib_dstate_static_len_ofs], rax
	mov	[r12+zlib_dstate_last_lit_ofs], eax
	mov	[r12+zlib_dstate_matches_ofs], eax
	; if last then bi_windup
	test	r11d, r11d
if profile_zlib_internals
	jz	.profiled_retonly
else
	jz	.retonly
end if
	bi_windup
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.tr_flush_block_notrees_notstored:
	; if (strategy == Z_FIXED || static_lenb == opt_lenb)
	cmp	dword [r12+zlib_dstate_strategy_ofs], 4		; Z_FIXED
	je	.tr_flush_block_notrees_static
	cmp	r9, r8
	je	.tr_flush_block_notrees_static
	sub	rsp, 56
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], r13
	mov	[rsp+32], r14
	mov	[rsp+40], r10				; max_blindex
	mov	[rsp+48], r15

	lea	r13, [r12+zlib_dstate_l_desc_ofs]
	lea	r14, [r12+zlib_dstate_d_desc_ofs]

	; send_bits( (DYN_TREES << 1) + last, 3)	sends block type
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	mov	eax, 4
	add	eax, edx		; (DYN_TREES << 1) + last
	send_bits_lit rax, 3

	; send_all_trees(s->l_desc.max_code+1, s->d_desc.max_code+1, max_blindex+1) is next
	mov	eax, [r13+zlib_tdesc_max_code_ofs]	; hmmm
	sub	eax, 256
	send_bits_lit rax, 5				; send_bits(s, lcodes-257, 5) (-256 here cuz we skipped the +1 arg)
	mov	eax, [r14+zlib_tdesc_max_code_ofs]	; hmmm
	send_bits_lit rax, 5				; send_bits(s, dcodes-1, 5) (no minus here cuz we skipped the +1 arg)
	mov	rax, [rsp+40]				; max_blindex
	sub	eax, 3
	send_bits_lit rax, 4				; send_bits(s, blcodes-4, 4) (-3 here cuz we skipped the +1 arg)

	xor	r13d, r13d				; rank
	mov	r14, [rsp+40]				; max_blindex
	lea	r15, [r12+zlib_dstate_bl_tree_ofs]
calign
.tr_flush_block_notrees_notstored_loop1:
	mov	ecx, [r13*4+.bl_order]
	movzx	eax, word [r15+rcx*4+2]
	send_bits_lit rax, 3				; send_bits(s->bl_tree[bl_order[rank]].Len, 3)
	add	r13d, 1
	cmp	r13d, r14d
	jle	.tr_flush_block_notrees_notstored_loop1

	; we'll leave rdi and rsi pointing to our pending buffer
	lea	r13, [r12+zlib_dstate_l_desc_ofs]
	lea	r14, [r12+zlib_dstate_d_desc_ofs]
	
	; send_tree(s->dyn_ltree, lcodes-1) is next
	lea	rdx, [r12+zlib_dstate_dyn_ltree_ofs]
	mov	ecx, [r13+zlib_tdesc_max_code_ofs]
	; so now, rdi is pending buffer, rsi is pending offset, rdx is the dyn_tree, ecx is the count
	call	.send_tree

	lea	rdx, [r12+zlib_dstate_dyn_dtree_ofs]
	mov	ecx, [r14+zlib_tdesc_max_code_ofs]
	call	.send_tree

	; compress_block(s, (const ct_data *)s->dyn_ltree, (const ct_data *)s->dyn_dtree) is next
	; we'll leave rdi and rsi pointing to our pending buffer
	lea	rdx, [r12+zlib_dstate_dyn_ltree_ofs]
	lea	rcx, [r12+zlib_dstate_dyn_dtree_ofs]
	call	.compress_block

	; then:
	; init_block is next
	lea	rdi, [r12+zlib_dstate_dyn_ltree_ofs]
	lea	rsi, [r12+zlib_dstate_dyn_dtree_ofs]
	lea	rdx, [r12+zlib_dstate_bl_tree_ofs]
	mov	ecx, 19
calign
.initblock1a:
	mov	word [rdi], 0
	mov	word [rsi], 0
	mov	word [rdx], 0
	add	rdi, 4
	add	rsi, 4
	add	rdx, 4
	sub	ecx, 1
	jnz	.initblock1a
	mov	ecx, 11
calign
.initblock2a:
	mov	word [rdi], 0
	mov	word [rsi], 0
	add	rdi, 4
	add	rsi, 4
	sub	ecx, 1
	jnz	.initblock2a
	mov	ecx, 256
calign
.initblock3a:
	mov	word [rdi], 0
	add	rdi, 4
	sub	ecx, 1
	jnz	.initblock3a

	xor	eax, eax

	mov	r11, [rsp+16]
	mov	r13, [rsp+24]
	mov	r14, [rsp+32]
	mov	r15, [rsp+48]
	add	rsp, 56

	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	mov	word [r12+zlib_dstate_dyn_ltree_ofs + 256*4], 1	; dyn_ltree[END_BLOCK].Freq = 1
	mov	[r12+zlib_dstate_opt_len_ofs], rax
	mov	[r12+zlib_dstate_static_len_ofs], rax
	mov	[r12+zlib_dstate_last_lit_ofs], eax
	mov	[r12+zlib_dstate_matches_ofs], eax
	; if last then bi_windup
	test	r11d, r11d
if profile_zlib_internals
	jz	.profiled_retonly
else
	jz	.retonly
end if
	bi_windup
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.tr_flush_block_notrees_static:
	; send_bits( (STATIC_TREES << 1) + last, 3)	sends block type

	mov	r11, rdx

	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]

	mov	eax, 2
	add	eax, edx		; (STATIC_TREES << 1) + last
	send_bits_lit rax, 3

	push	r11

	; compress_block(s, (const ct_data *)zlib_static_ltree, (const ct_data *)zlib_static_dtree) is next
	; we'll leave rdi and rsi pointing to our pending buffer
	mov	rdx, zlib_static_ltree
	mov	rcx, zlib_static_dtree
	call	.compress_block

	; then:
	; init_block is next
	lea	rdi, [r12+zlib_dstate_dyn_ltree_ofs]
	lea	rsi, [r12+zlib_dstate_dyn_dtree_ofs]
	lea	rdx, [r12+zlib_dstate_bl_tree_ofs]
	mov	ecx, 19
calign
.initblock1b:
	mov	word [rdi], 0
	mov	word [rsi], 0
	mov	word [rdx], 0
	add	rdi, 4
	add	rsi, 4
	add	rdx, 4
	sub	ecx, 1
	jnz	.initblock1b
	mov	ecx, 11
calign
.initblock2b:
	mov	word [rdi], 0
	mov	word [rsi], 0
	add	rdi, 4
	add	rsi, 4
	sub	ecx, 1
	jnz	.initblock2b
	mov	ecx, 256
calign
.initblock3b:
	mov	word [rdi], 0
	add	rdi, 4
	sub	ecx, 1
	jnz	.initblock3b

	xor	eax, eax
	pop	r11
	mov	rdi, [r12+zlib_dstate_pending_buf_ofs]
	mov	rsi, [r12+zlib_dstate_pending_ofs]
	mov	word [r12+zlib_dstate_dyn_ltree_ofs + 256*4], 1	; dyn_ltree[END_BLOCK].Freq = 1
	mov	[r12+zlib_dstate_opt_len_ofs], rax
	mov	[r12+zlib_dstate_static_len_ofs], rax
	mov	[r12+zlib_dstate_last_lit_ofs], eax
	mov	[r12+zlib_dstate_matches_ofs], eax
	; if last then bi_windup
	test	r11d, r11d
if profile_zlib_internals
	jz	.profiled_retonly
else
	jz	.retonly
end if
	bi_windup
if profile_zlib_internals
	epilog
else
	ret
end if


	; send_code(s, c, tree) == send_bits(s, tree[c].Code, tree[c].Len)
;--------------------------------------------------- compress_block -------------------------------------------------
falign
.compress_block:
	if profile_zlib_internals
		prolog	.compress_block
	end if
	; rdi == pending buffer
	; rsi == pending offset
	; rdx == ltree
	; rcx == dtree

	; so... we can safely hang onto r10, r11 cuz send_bits doesn't chew it
	; but we'll need the rest of our callee-saves i think
	cmp	dword [r12+zlib_dstate_last_lit_ofs], 0
	je	.compress_block_endonly
	sub	rsp, 48
	mov	[rsp], rbx
	mov	[rsp+8], r13
	mov	[rsp+16], r14
	mov	[rsp+24], r15

	mov	r14, rdx		; ltree
	mov	r15, rcx		; dtree
	xor	ebx, ebx		; lx
calign
.compress_block_loop:
	; dbuf and lbuf are both pointers
	mov	rdx, [r12+zlib_dstate_d_buf_ofs]
	mov	rcx, [r12+zlib_dstate_l_buf_ofs]
	; r8d == dist == d_buf
	; eax == lc == l_buf
	movzx	r8d, word [rdx+rbx*2]
	movzx	eax, byte [rcx+rbx]

	add	ebx, 1
	test	r8d, r8d
	jz	.compress_block_literal
	; because we are register starved here, save dist and lc on the stack
	mov	dword [rsp+32], r8d		; dist
	mov	dword [rsp+40], eax		; lc
	; he say:
	; Here, lc is the match length - MIN_MATCH (3)
	movzx	r13d, byte [rax+zlib_length_code]	; code = zlib_length_code[lc]
	mov	edx, r13d
	add	edx, 257			; LITERALS + 1

	mov	eax, dword [r14+rdx*4]		; get the tree entry
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d			; send_code(code+LITERALS+1, ltree)
	
	mov	r10d, dword [r13*4+extra_lbits]
	test	r10d, r10d
	jz	.compress_block_loop_noextra
	mov	eax, dword [rsp+40]		; lc
	sub	eax, dword [r13*4+zlib_base_length]
	mov	dword [rsp+40], eax
	
	send_bits rax, r10d			; send_bits(lc, extra)
calign
.compress_block_loop_noextra:
	mov	r8d, dword [rsp+32]
	sub	r8d, 1
	mov	dword [rsp+32], r8d		; dist--

	; we need code = d_code(dist)
	; d_code(dist) == ((dist) < 256 ? _zlib_dist_code[dist] : _zlib_dist_code[256+((dist)>>7)]

	; dist is in r8d
	mov	r9d, r8d
	shr	r9d, 7
	add	r9d, 256
	; 256+(dist>>7)

	cmp	r8d, 256
	cmovb	r9d, r8d
	movzx	r13d, byte [r9d+zlib_dist_code]

	; so now r13d (code) is d_code(dist)
	; now we need to send_code(code, dtree) (dtree in r15)
	mov	eax, dword [r15+r13*4]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d

	; next up: extra = zlib_extra_dbits[code]
	mov	r10d, [r13*4+zlib_extra_dbits]
	test	r10d, r10d
	jz	.compress_block_donext
	
	; otherwise, extra != 0, so dist -= zlib_base_dist[code]
	; and then send_bits dist, extra
	mov	eax, dword [rsp+32]		; dist
	sub	eax, dword [r13*4+zlib_base_dist]	; -= zlib_base_dist[code]
	send_bits rax, r10d			; send_bits(dist, extra)

	; and donext (copy of to avoid nop fill)
	cmp	ebx, dword [r12+zlib_dstate_last_lit_ofs]
	jb	.compress_block_loop
	; else, send the END_BLOCK code and be done
	mov	eax, dword [r14+1024]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d

	mov	rbx, [rsp]
	mov	r13, [rsp+8]
	mov	r14, [rsp+16]
	mov	r15, [rsp+24]
	add	rsp, 48
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.compress_block_donext:
	cmp	ebx, dword [r12+zlib_dstate_last_lit_ofs]
	jb	.compress_block_loop
	; else, send the END_BLOCK code and be done
	mov	eax, dword [r14+1024]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d

	mov	rbx, [rsp]
	mov	r13, [rsp+8]
	mov	r14, [rsp+16]
	mov	r15, [rsp+24]
	add	rsp, 48
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.compress_block_literal:
	; send_code(s, lc, ltree)
	mov	eax, dword [r14+rax*4]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d
	cmp	ebx, dword [r12+zlib_dstate_last_lit_ofs]
	jb	.compress_block_loop
	; else, send the END_BLOCK code and be done
	mov	eax, dword [r14+1024]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d

	mov	rbx, [rsp]
	mov	r13, [rsp+8]
	mov	r14, [rsp+16]
	mov	r15, [rsp+24]
	add	rsp, 48
if profile_zlib_internals
	epilog
else
	ret
end if

calign
.compress_block_endonly:
	; not part of the loop, jumps here only if last_lit was zero on entry, hence no stack cleanup/mods
	mov	eax, dword [rdx+1024]			; tree[END_BLOCK] dword (END_BLOCK == 256)
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d
if profile_zlib_internals
	epilog
else
	ret
end if




	; send_code(s, c, tree) == send_bits(s, tree[c].Code, tree[c].Len)
;--------------------------------------------------- send_tree ------------------------------------------------------
falign
.send_tree:
	if profile_zlib_internals
		prolog	.send_tree
	end if
	; rdi == pending buffer
	; rsi == pending offset
	; rdx == tree
	; ecx == max_code

	movzx	eax, word [rdx+2]			; tree[0].Len

	sub	rsp, 72
	mov	[rsp], rbx
	mov	[rsp+8], r13
	mov	[rsp+16], r14
	mov	[rsp+24], r15
	mov	[rsp+32], rbp
	mov	dword [rsp+40], -1			; prevlen
	mov	dword [rsp+48], eax			; nextlen

	xor	ebp, ebp				; n
	mov	ebx, ecx				; max_code
	xor	r13d, r13d				; count
	mov	r14, rdx				; tree
	lea	r15, [r12+zlib_dstate_bl_tree_ofs]	; bl_tree
	
	; r11d == curlen, [rsp+40] == prevlen, [rsp+48] == nextlen, [rsp+56] == max_count, [rsp+64] == min_count
	mov	ecx, 7
	mov	r8d, 4
	mov	r9d, 138
	mov	r10d, 3
	test	eax, eax				; nextlen == 0?
	cmovz	ecx, r9d
	cmovz	r8d, r10d
	mov	dword [rsp+56], ecx			; max_count
	mov	dword [rsp+64], r8d			; min_count
calign
.send_tree_loop:
	cmp	ebp, ebx				; n > max_code?
	jg	.send_tree_loop_alldone
	add	ebp, 1					; n++
	movzx	eax, word [r14+rbp*4+2]			; tree[n].Len
	mov	r11d, dword [rsp+48]			; curlen = nextlen
	mov	dword [rsp+48], eax			; nextlen = tree[n].Len
	add	r13d, 1					; ++count
	cmp	r11d, eax				; curlen == nextlen?
	jne	.send_tree_loop_topcase1
	; otherwise, curlen == nextlen, so check if count < max_count
	cmp	r13d, dword [rsp+56]
	jl	.send_tree_loop				; yep, continue
calign
.send_tree_loop_topcase1:
	cmp	r13d, dword [rsp+64]			; count < min_count ?
	jl	.send_tree_loop_case1
	test	r11d, r11d				; curlen != 0 ?
	jnz	.send_tree_loop_case2
	cmp	r13d, 10				; count <= 10 ?
	jle	.send_tree_loop_case3	

	; last else, so:
	; send_code(REPZ_11_138, s->bl_tree);		REPZ_11_138 == 18, so we need to load the full code from r15+18*4(72)
	mov	eax, dword [r15+72]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d
	; send_bits(s, count-11, 7);
	mov	eax, r13d
	sub	eax, 11
	send_bits_lit rax, 7

	; resetcount:
	xor	r13d, r13d				; count = 0
	mov	dword [rsp+40], r11d			; prevlen = curlen
	cmp	dword [rsp+48], 0			; nextlen == 0?
	je	.send_tree_loop_case4
	cmp	r11d, dword [rsp+48]			; curlen == nextlen
	je	.send_tree_loop_case5
	; else, max_count = 7, min_count = 4
	mov	dword [rsp+56], 7
	mov	dword [rsp+64], 4
	jmp	.send_tree_loop
calign
.send_tree_loop_case1:
	; count < min_count
	; which says: do { send_code(curlen, s->bl_tree); } while (--count != 0);
	mov	eax, dword [r15+r11*4]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d
	sub	r13d, 1
	jnz	.send_tree_loop_case1

	; resetcount:
	xor	r13d, r13d				; count = 0
	mov	dword [rsp+40], r11d			; prevlen = curlen
	cmp	dword [rsp+48], 0			; nextlen == 0?
	je	.send_tree_loop_case4
	cmp	r11d, dword [rsp+48]			; curlen == nextlen
	je	.send_tree_loop_case5
	; else, max_count = 7, min_count = 4
	mov	dword [rsp+56], 7
	mov	dword [rsp+64], 4
	jmp	.send_tree_loop
calign
.send_tree_loop_case2:
	; curlen != 0
	; which says: if (curlen != prevlen) { send_code(curlen, s->bl_tree); count--; }
	;             send_code(REP_3_6, s->bl_tree); send_bits(count-3, 2);
	cmp	r11d, dword [rsp+40]				; curlen != prevlen?
	jne	.send_tree_loop_case2_sub
	mov	eax, dword [r15+64]			; REP_3_6 == 16 * 4 == 64
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d				; send_code(REP_3_6, bl_tree)
	mov	eax, r13d
	sub	eax, 3
	send_bits_lit rax, 2

	; resetcount:
	xor	r13d, r13d				; count = 0
	mov	dword [rsp+40], r11d			; prevlen = curlen
	cmp	dword [rsp+48], 0			; nextlen == 0?
	je	.send_tree_loop_case4
	cmp	r11d, dword [rsp+48]			; curlen == nextlen
	je	.send_tree_loop_case5
	; else, max_count = 7, min_count = 4
	mov	dword [rsp+56], 7
	mov	dword [rsp+64], 4
	jmp	.send_tree_loop
calign
.send_tree_loop_case2_sub:
	; same as above, only we do the extra step of sending curlen code first and decrementing count
	mov	eax, dword [r15+r11*4]
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d				; send_code(curlen, bl_tree)
	sub	r13d, 1					; count--

	; copy of above:
	mov	eax, dword [r15+64]			; REP_3_6 == 16 * 4 == 64
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d				; send_code(REP_3_6, bl_tree)
	mov	eax, r13d
	sub	eax, 3
	send_bits_lit rax, 2

	; resetcount:
	xor	r13d, r13d				; count = 0
	mov	dword [rsp+40], r11d			; prevlen = curlen
	cmp	dword [rsp+48], 0			; nextlen == 0?
	je	.send_tree_loop_case4
	cmp	r11d, dword [rsp+48]			; curlen == nextlen
	je	.send_tree_loop_case5
	; else, max_count = 7, min_count = 4
	mov	dword [rsp+56], 7
	mov	dword [rsp+64], 4
	jmp	.send_tree_loop
calign
.send_tree_loop_case3:
	; count <= 10
	; which says: send_code(REPZ_3_10, s->bl_tree); send_bits(count-3, 3);
	mov	eax, dword [r15+68]			; REPZ_3_10 == 17 * 4 == 68
	mov	r10d, eax
	and	eax, 0xffff
	shr	r10d, 16
	send_bits rax, r10d				; send_code(REPZ_3_10, bl_tree)
	mov	eax, r13d
	sub	eax, 3
	send_bits_lit rax, 3

	; resetcount:
	xor	r13d, r13d				; count = 0
	mov	dword [rsp+40], r11d			; prevlen = curlen
	cmp	dword [rsp+48], 0			; nextlen == 0?
	je	.send_tree_loop_case4
	cmp	r11d, dword [rsp+48]			; curlen == nextlen
	je	.send_tree_loop_case5
	; else, max_count = 7, min_count = 4
	mov	dword [rsp+56], 7
	mov	dword [rsp+64], 4
	jmp	.send_tree_loop
calign
.send_tree_loop_case4:
	; max_count = 138, min_count = 3
	mov	dword [rsp+56], 138
	mov	dword [rsp+64], 3
	jmp	.send_tree_loop
calign
.send_tree_loop_case5:
	; max_count = 6, min_count = 3
	mov	dword [rsp+56], 6
	mov	dword [rsp+64], 3
	jmp	.send_tree_loop
calign
.send_tree_loop_alldone:
	mov	rbx, [rsp]
	mov	r13, [rsp+8]
	mov	r14, [rsp+16]
	mov	r15, [rsp+24]
	mov	rbp, [rsp+32]
	add	rsp, 72
if profile_zlib_internals
	epilog
else
	ret
end if






;--------------------------------------------------- build_tree -----------------------------------------------------
falign
.build_tree:
	if profile_zlib_internals
		prolog	.build_tree
	end if
	push	rbx r13 r14 r15				; we need a few more temporaries here
	mov	rsi, [rdi+zlib_tdesc_dyn_tree_ofs]	; desc->dyn_tree
	mov	rdx, [rdi+zlib_tdesc_stat_desc_ofs]	; desc->stat_desc
	; stat_desc offsets:
	; static_tree = ofs 0
	; extra_bits = ofs 8
	; extra_base = ofs 16
	; elems = ofs 24
	; max_length = ofs 32
	mov	rcx, [rdx]				; static_tree
	mov	r8d, [rdx+24]				; elems
	xor	r9d, r9d				; n
	xor	r10d, r10d
	mov	edx, -1					; max_code
	; r10d == m, r11d == node

	; we'll use r10d as our heap_len, and r11 temporary as a pointer to the heap
	lea	r11, [r12+zlib_dstate_heap_ofs]
	
	mov	dword [r12+zlib_dstate_heap_len_ofs], r9d
	mov	dword [r12+zlib_dstate_heap_max_ofs], 573	; HEAP_MAX


calign
.build_tree_loop1:
	cmp	r9d, r8d				; n > elems?
	jae	.build_tree_loop2

	cmp	word [rsi+r9*4], 0
	jne	.build_tree_loop1_freq
	mov	word [rsi+r9*4+2], 0			; tree[n].Len = 0
	add	r9d, 1
	jmp	.build_tree_loop1
calign
.build_tree_loop1_freq:
	add	r10d, 1					; heap_len++
	movzx	eax, word [rsi+r9*4]
	mov	edx, r9d				; max_code = n
	mov	dword [r11+r10*4], r9d			; heap[heap_len] = n
	mov	byte [r12+r9+zlib_dstate_depth_ofs], 0	; s->depth[n] = 0
	add	r9d, 1					; n++
	jmp	.build_tree_loop1
calign
.build_tree_loop2:
	cmp	r10d, 2
	jae	.build_tree_loop2_done
	xor	eax, eax
	cmp	edx, 2
	jl	.build_tree_loop2_incmax
	add	r10d, 1
	mov	dword [r11+r10*4], 0
	mov	word [rsi], 1
	mov	byte [r12+zlib_dstate_depth_ofs], 0
	sub	qword [r12+zlib_dstate_opt_len_ofs], 1
	test	rcx, rcx
	jz	.build_tree_loop2
	mov	ax, word [rcx+2]
	sub	qword [r12+zlib_dstate_static_len_ofs], rax
	jmp	.build_tree_loop2
calign
.build_tree_loop2_incmax:
	add	edx, 1					; max_code
	add	r10d, 1
	mov	dword [r11+r10*4], edx
	mov	word [rsi+rdx*4], 1
	mov	byte [r12+rdx+zlib_dstate_depth_ofs], 0
	sub	qword [r12+zlib_dstate_opt_len_ofs], 1
	test	rcx, rcx
	jz	.build_tree_loop2
	mov	ax, word [rcx+rdx*4+2]
	sub	qword [r12+zlib_dstate_static_len_ofs], rax
	jmp	.build_tree_loop2
calign
.build_tree_loop2_done:
	mov	dword [r12+zlib_dstate_heap_len_ofs], r10d
	mov	dword [rdi+zlib_tdesc_max_code_ofs], edx

	mov	r9d, r10d
	shr	r9d, 1
calign
.build_tree_loop3:
	cmp	r9d, 1
	jl	.build_tree_final_loop
	; pqdownheap(s, tree, n)
	; r11 still pointing to our heap
	; rsi is our "tree"
	; r9d is n
macro pqdownheap {
	; edx is the k argument, rsi must be the tree, r11 must be pointing to the heap, r12 must be our dstate, r10d must be our heap_len
	; eax is our v
	; ebx is our j
	local	.loop,.notless,.keepgoing,.checkdepth,.done,.less_incj
	mov	eax, dword [r11+rdx*4]
	mov	ebx, edx
	shl	ebx, 1
calign
.loop:
	cmp	ebx, r10d
	jg	.done
	je	.notless
	; so, j < s->heap_len
	; if smaller(tree, s->heap[j+1], s->heap[j], s->depth)
	;   j++
	mov	r13d, dword [r11+rbx*4+4]		; heap[j+1]		n
	mov	r14d, dword [r11+rbx*4]			; heap[j]		m
	movzx	r15d, word [rsi+r13*4]			; tree[heap[j+1]].Freq	tree[n].Freq
	cmp	r15w, word [rsi+r14*4]			; cmp tree[heap[j+1]].Freq with tree[heap[j]].Freq	with tree[m].Freq
	jl	.less_incj
	jne	.notless
	; otherwise, freq was equal, check depth equality
	movzx	r15d, byte [r12+r13+zlib_dstate_depth_ofs]
	cmp	r15b, byte [r12+r14+zlib_dstate_depth_ofs]		; yuck.
	ja	.notless
calign
.less_incj:
	add	ebx, 1
calign
.notless:
	; if (smaller(tree, v, s->heap[j], s->depth)) break;
	mov	r13d, eax				; v
	mov	r14d, dword [r11+rbx*4]			; heap[j]
	movzx	r15d, word [rsi+r13*4]			; tree[v].Freq
	cmp	r15w, word [rsi+r14*4]
	; so, if tree[v].Freq < tree[heap[j]].Freq, break.
	; or, if tree[v].Freq == tree[heap[j]].Freq && depth[v] == depth[heap[j]], break.
	; otherwise, keep going.
	jl	.done
	je	.checkdepth
calign
.keepgoing:
	mov	r13d, dword [r11+rbx*4]		; r13d = heap[j]
	mov	dword [r11+rdx*4], r13d		; heap[k] = heap[j]
	mov	edx, ebx			; k = j
	shl	ebx, 1				; j <<= 1
	jmp	.loop
calign
.checkdepth:
	movzx	r15d, byte [r12+r13+zlib_dstate_depth_ofs]
	cmp	r15b, byte [r12+r14+zlib_dstate_depth_ofs]		; yuck.
	ja	.keepgoing
	; else, it was less than or equal, so break
calign
.done:
	mov	dword [r11+rdx*4], eax
}

	mov	edx, r9d
	pqdownheap
	sub	r9d, 1
	jmp	.build_tree_loop3			; TODO: redo this loop

macro pqremove {
	; rsi == tree argument
	; r9d == top argument
	mov	edx, 1
	mov	r9d, dword [r11+4]			; top = heap[SMALLEST]
	mov	eax, dword [r11+r10*4]			; heap[heap_len--]
	mov	dword [r11+4], eax			; heap[SMALLEST] = s->heap[s->heap_len--]
	sub	r10d, 1
	mov	dword [r12+zlib_dstate_heap_len_ofs], r10d
	pqdownheap
}

calign
.build_tree_final_loop:


	; so at this point:

	; rcx is our static tree (stree)
	; rdi is our tree desc (desc)
	; rsi is our tree
	; r8d is elems
	; r9d must be zero (n) at this point
	; r10d is still heap_len
	; r11 is still our heap
	; eax, ebx, edx, r13d, r14d, r15d are all free to use

	; we can use r8d for our node var since elems isn't referenced again
	; stree isn't referenced from this point forward, so we can blast rcx
	; pqremove is a #define, which modifies its top parameter, pqdownheap which it calls does not modify, and takes an argument

	; since pqdownheap uses edx as its arg, we can use r9d for our n argument, which is already zero
	pqremove

	; n (r9d) is now set, and we are free to blast all our temporaries now... r8d is still our node, r10d still our heap_len which got reduced
	mov	r13d, dword [r11+4]			; m = heap[SMALLEST]
	mov	r14d, dword [r12+zlib_dstate_heap_max_ofs]
	sub	r14d, 1
	mov	dword [r11+r14*4], r9d
	sub	r14d, 1
	mov	dword [r11+r14*4], r13d
	mov	dword [r12+zlib_dstate_heap_max_ofs], r14d
	; create a new node father of n and m
	movzx	eax, word [rsi+r9*4]			; tree[n].Freq
	movzx	ecx, word [rsi+r13*4]			; tree[m].Freq
	add	eax, ecx
	mov	word [rsi+r8*4], ax			; tree[node].Freq = tree[n].Freq + tree[m].Freq
	
	lea	rbx, [r12+zlib_dstate_depth_ofs]	; offset to the depth byte table
	movzx	eax, byte [rbx+r9]			; depth[n]
	movzx	ecx, byte [rbx+r13]			; depth[m]

	cmp	eax, ecx
	cmovb	eax, ecx
	add	eax, 1

	mov	byte [rbx+r8], al
	mov	word [rsi+r9*4+2], r8w			; tree[n].Dad = node
	mov	word [rsi+r13*4+2], r8w			; tree[m].Dad = node
	mov	dword [r11+4], r8d			; heap[SMALLEST] = node
	add	r8d, 1					; node++
	mov	edx, 1
	pqdownheap
	cmp	r10d, 2
	jae	.build_tree_final_loop

	mov	dword [r12+zlib_dstate_heap_len_ofs], r10d	; put heap_len back

	mov	eax, dword [r11+4]			; heap[SMALLEST]
	mov	r14d, dword [r12+zlib_dstate_heap_max_ofs]
	sub	r14d, 1
	mov	dword [r11+r14*4], eax			; heap[--heap_max] = heap[SMALLEST]
	mov	dword [r12+zlib_dstate_heap_max_ofs], r14d

	; gen_bitlen:

	; rdi is still our desc
	mov	rsi, [rdi+zlib_tdesc_dyn_tree_ofs]	; desc->dyn_tree	(tree)
	mov	rdx, [rdi+zlib_tdesc_stat_desc_ofs]	; desc->stat_desc
	mov	rcx, [rdx]				; static_tree		(stree)
	; extra_bits is at [rdx+8]
	; extra_base is at [rdx+16]
	; elems is at [rdx+24]
	; max_length is at [rdx+32]

	; stat_desc offsets:
	; static_tree = ofs 0
	; extra_bits = ofs 8
	; extra_base = ofs 16
	; elems = ofs 24
	; max_length = ofs 32
	xor	eax, eax
	mov	r8, [rdx+8]				; extra
	mov	r9d, dword [rdx+16]			; extra_base
	mov	r10d, dword [rdx+32]			; max_length
	lea	rdx, [r12+zlib_dstate_bl_count_ofs]	; rdx now pointing to our bl_count
	mov	[rdx], rax
	mov	[rdx+8], rax
	mov	[rdx+16], rax
	mov	[rdx+24], rax				; zero all of our bl_count entries (array of dw, 16 entries in all)

	; r11 is still our heap ... rdi (desc), rsi (tree), rdx (bl_count), rcx (stree), r8 (extra*), r9d (extra_bits), r10d (max_length), r11 (heap), r12(dstate), r14d (heap_max)
	; so we have clear eax, ebx, r13d, r14d, r15d
	; r14d still == heap_max
	mov	eax, [r11+r14*4]			; s->heap[s->heap_max]
	mov	word [rsi+rax*4+2], 0			; s->tree[s->heap[s->heap_max]].Len = 0
	add	r14d, 1					; heap_max + 1 (which we'll use as h)
	xor	ebx, ebx				; overflow = 0
calign
.gen_bitlen_loop1:
	cmp	r14d, 573				; h < HEAP_SIZE ?
	jae	.gen_bitlen_loop1_done
	lea	rdx, [r12+zlib_dstate_bl_count_ofs]	; rdx now pointing to our bl_count
	mov	eax, [r11+r14*4]			; n = s->heap[h]
	movzx	r15d, word [rsi+rax*4+2]		; tree[n].Dad
	movzx	r13d, word [rsi+r15*4+2]		; tree[tree[n].Dad].Len
	add	r13d, 1					; + 1 (bits)

	; 15 is clear, n = eax, h = r14d, overflow = ebx, bits = r13d
	mov	r15d, ebx
	add	r15d, 1
	cmp	r13d, r10d				; bits > max_length?
	cmova	r13d, r10d				; if so, bits = max_length
	cmova	ebx, r15d				; and overflow++

	mov	word [rsi+rax*4+2], r13w		; tree[n].Len = bits
	; if (n > max_code) continue;
	mov	r15d, r14d
	add	r15d, 1					; h++ temporary
	cmp	eax, dword [rdi+zlib_tdesc_max_code_ofs]
	cmova	r14d, r15d
	ja	.gen_bitlen_loop1			; continue

	add	word [rdx+r13*2], 1			; bl_count[bits]++

	xor	r15d, r15d				; xbits = 0
	mov	edx, eax
	sub	edx, r9d
	cmp	eax, r9d				; n >= base?
	jb	.gen_bitlen_loop1_noxbits
	; TODO: contemplate this cmov ... i intentionally set its address invalid if the condition isn't satisfied
	; but still get a segfault here even if the condition isn't met... :-(
	; cmovae	r15d, dword [r8+rdx*4]			; if so, xbits = extra[n-base]
	mov	r15d, dword [r8+rdx*4]
calign
.gen_bitlen_loop1_noxbits:
	; we are safe to blast r13d now, it will be set again next loop iteration
	add	r13d, r15d				; bits += xbits
	push	rax					; save n
	movzx	eax, word [rsi+rax*4]			; tree[n].Freq
	mul	r13
	add	qword [r12+zlib_dstate_opt_len_ofs], rax
	pop	rax
	add	r14d, 1
	test	rcx, rcx
	jz	.gen_bitlen_loop1
	; else, stree exists, so we need to do static_len += f * (stree[n].Len + xbits)
	movzx	r13d, word [rcx+rax*4+2]		; stree[n].Len into r13d
	add	r13d, r15d				; + xbits
	push	rax
	movzx	eax, word [rsi+rax*4]			; tree[n].Freq again (f)
	mul	r13
	add	qword [r12+zlib_dstate_static_len_ofs], rax
	pop	rax
	jmp	.gen_bitlen_loop1
calign
.gen_bitlen_loop1_done:
	test	ebx, ebx
	jz	.gen_bitlen_alldone
	lea	rdx, [r12+zlib_dstate_bl_count_ofs]	; rdx now pointing to our bl_count
calign
.gen_bitlen_loop2:
	mov	r13d, r10d				; bits = max_length
	sub	r13d, 1
	cmp	word [rdx+r13*2], 0
	jne	.gen_bitlen_loop2_continue
	sub	r13d, 1
calign
.gen_bitlen_loop2_bc:
	cmp	word [rdx+r13*2], 0
	jne	.gen_bitlen_loop2_continue
	sub	r13d, 1
	jmp	.gen_bitlen_loop2_bc
calign
.gen_bitlen_loop2_continue:
	sub	word [rdx+r13*2], 1
	add	word [rdx+r13*2+2], 2
	sub	word [rdx+r10*2], 1
	sub	ebx, 2
	cmp	ebx, 0
	jg	.gen_bitlen_loop2
	; he say:
	; now recompute all bit lengths, scanning in increasing frequency
	; rsi == tree, r11 == heap, rdx == bl_count, r14d = h (HEAP_SIZE at the moment)
	mov	r13d, r10d				; bits = max_length
calign
.gen_bitlen_loop3:
	test	r13d, r13d
	jz	.gen_bitlen_alldone
	movzx	ebx, word [rdx+r13*2]			; n = bl_count[bits]
calign
.gen_bitlen_loop3_inner:
	test	ebx, ebx
	jz	.gen_bitlen_loop3_inner_done
	sub	r14d, 1
	mov	r15d, dword [r11+r14*4]			; m = s->heap[--h]
	cmp	r15d, dword [rdi+zlib_tdesc_max_code_ofs]
	ja	.gen_bitlen_loop3_inner
	sub	ebx, 1					; n--
	movzx	ecx, word [rsi+r15*4+2]			; tree[m].Len
	cmp	r13d, ecx				; if (bits != tree[m].Len)
	je	.gen_bitlen_loop3_inner
	movzx	eax, word [rsi+r15*4]			; tree[m].Freq
	mov	edx, r13d
	sub	edx, ecx
	mul	rdx
	mov	word [rsi+r15*4+2], r13w		; tree[m].Len = bits
	add	qword [r12+zlib_dstate_opt_len_ofs], rax
	jmp	.gen_bitlen_loop3_inner
calign
.gen_bitlen_loop3_inner_done:
	sub	r13d, 1
	lea	rdx, [r12+zlib_dstate_bl_count_ofs]	; rdx now pointing to our bl_count
	jmp	.gen_bitlen_loop3

calign
.gen_bitlen_alldone:
	; esi must be max_code
	; rdx must point to s->bl_count
	mov	rbx, rsi				; (tree, which .gen_bitlen left alone)
	mov	esi, [rdi+zlib_tdesc_max_code_ofs]
	mov	rdi, rbx
	lea	rdx, [r12+zlib_dstate_bl_count_ofs]
	call	.gen_codes
	
	pop	r15 r14 r13 rbx
if profile_zlib_internals
	epilog
else
	ret
end if

;--------------------------------------------------- gen_codes ------------------------------------------------------
falign
.gen_codes:
	if profile_zlib_internals
		prolog	.gen_codes
	end if
	; on entry: rdi == tree, esi == max_code, rdx == pointer to bl_count array of dw
	sub	rsp, 48					; space for next_code
	xor	ecx, ecx				; code
	mov	r8d, 1					; bits
	xor	r9d, r9d				; n
calign
.gen_codes_ncloop:
	movzx	eax, word [rdx+r9*2]			; bl_count[bits-1]
	add	ecx, eax
	shl	ecx, 1
	mov	word [rsp+r8*2], cx
	add	r8d, 1
	add	r9d, 1
	cmp	r8d, 16
	jl	.gen_codes_ncloop
	xor	r9d, r9d
calign
.gen_codes_loop:
	cmp	r9d, esi
	ja	.gen_codes_bailout			; n > max_code == bailout
	mov	r8d, r9d
	add	r8d, 1
	movzx	eax, word [rdi+r9*4+2]			; tree[n].Len
	test	eax, eax
	cmovz	r9d, r8d
	jz	.gen_codes_loop
	; len nonzero, reverse the bits
	; tree[n].Code = bi_reverse(next_code[len]++, len)
	; then, n++ and continue
	movzx	ecx, word [rsp+rax*2]			; next_code[len]
	add	word [rsp+rax*2], 1			; next_code[len]++
	; ecx == code, we'll use r8d for our res
	xor	r8d, r8d
calign
.gen_codes_bi_reverse:
	mov	r10d, ecx
	and	r10d, 1
	or	r8d, r10d
	shr	ecx, 1
	shl	r8d, 1
	sub	eax, 1
	jnz	.gen_codes_bi_reverse
	shr	r8d, 1
	; r8d now contains the reverse, which we need to stick in tree[n].Code
	mov	word [rdi+r9*4], r8w
	add	r9d, 1
	jmp	.gen_codes_loop
calign
.gen_codes_bailout:
	add	rsp, 48
if profile_zlib_internals
	epilog
else
	ret
end if



;--------------------------------------------------- build_bl_tree --------------------------------------------------
falign
.build_bl_tree:
	if profile_zlib_internals
		prolog .build_bl_tree
	end if
	; use eax as our max_blindex (it is what we must return anyway)
	; no arguments, r12 == our dstate on entry
	lea	rdi, [r12+zlib_dstate_dyn_ltree_ofs]
	lea	rdx, [r12+zlib_dstate_l_desc_ofs]
	mov	rsi, [rdx+zlib_tdesc_max_code_ofs]	; hmmm
	call	.scan_tree
	lea	rdi, [r12+zlib_dstate_dyn_dtree_ofs]
	lea	rdx, [r12+zlib_dstate_d_desc_ofs]
	mov	rsi, [rdx+zlib_tdesc_max_code_ofs]	; hmmm
	call	.scan_tree

	lea	rdi, [r12+zlib_dstate_bl_desc_ofs]
	call	.build_tree

	mov	rax, [r12+zlib_dstate_opt_len_ofs]

	mov	eax, 18					; BL_CODES - 1
	lea	rdi, [r12+zlib_dstate_bl_tree_ofs]
calign
.build_bl_tree_loop1:
	cmp	eax, 3
	jl	.build_bl_tree_loop1_done
	; if (s->bl_tree[bl_order[max_blindex]].Len != 0) break
	mov	esi, [rax*4+.bl_order]
	cmp	word [rdi+rsi*4+2], 0
	jne	.build_bl_tree_loop1_done
	sub	eax, 1
	jmp	.build_bl_tree_loop1
dalign
.bl_order:
	dd	16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
calign
.build_bl_tree_loop1_done:
	mov	edx, 3
	mov	r8d, eax				; save our max_blndex
	add	eax, 1
	mul	rdx
	add	rax, 14
	add	qword [r12+zlib_dstate_opt_len_ofs], rax
	mov	eax, r8d				; restore our max_blindex
if profile_zlib_internals
	epilog
else
	ret
end if

;--------------------------------------------------- scan_tree ------------------------------------------------------
falign
.scan_tree:
	if profile_zlib_internals
		prolog	.scan_tree
	end if
	; rdi == tree, esi == max_code
	push	r13
	lea	rdx, [r12+zlib_dstate_bl_tree_ofs]
	; so we are free to blast eax, ecx, r8d, r9d, r10d, r11d
	
	; ecx == n
	; eax == prevlen
	; r8d == curlen
	; r9d == nextlen
	; r10d == count
	; r11d == max_count
	; r13d == min_count
	mov	eax, 138
	mov	ecx, 3
	movzx	r9d, word [rdi+2]	; tree[0].Len
	mov	word [rdi+rsi*4+6], 0xffff	; guard (tree[max_code+1].Len = 0xffff)
	xor	r10d, r10d
	mov	r11d, 7
	mov	r13d, 4
	test	r9d, r9d
	cmovz	r11d, eax
	cmovz	r13d, ecx		; if (nextlen == 0) max_count = 138, min_count = 3
	xor	ecx, ecx
	mov	eax, -1
calign
.scan_tree_loop:
	cmp	ecx, esi
	jg	.scan_tree_loop_done
	add	ecx, 1
	mov	r8d, r9d		; curlen = nextlen
	movzx	r9d, word [rdi+rcx*4+2]	; tree[n+1].Len
	add	r10d, 1			; ++count
	cmp	r8d, r9d
	jne	.scan_tree_loop_topcase1
	; otherwise, curlen == nextlen, so check if count < max_count
	cmp	r10d, r11d
	jl	.scan_tree_loop		; yep, continue
calign
.scan_tree_loop_topcase1:
	cmp	r10d, r13d		; count < min_count
	jl	.scan_tree_loop_case1	
	test	r8d, r8d		; curlen != 0
	jnz	.scan_tree_loop_case2
	cmp	r10d, 10		; count <= 10
	jle	.scan_tree_loop_case3
	; last else
	add	word [rdx+72], 1	; s->bl_tree[REPZ_11_138].Freq++ (REPZ_11_138 == 18 * 4 == 72)
	; resetcount:
	xor	r10d, r10d		; count = 0
	mov	eax, r8d		; prevlen = curlen
	test	r9d, r9d
	jz	.scan_tree_loop_case4
	cmp	r8d, r9d
	je	.scan_tree_loop_case5
	mov	r11d, 7
	mov	r13d, 4
	jmp	.scan_tree_loop
calign
.scan_tree_loop_case1:
	add	word [rdx+r8*4], r10w	; s->bl_tree[curlen].Freq += count
	; resetcount:
	xor	r10d, r10d		; count = 0
	mov	eax, r8d		; prevlen = curlen
	test	r9d, r9d
	jz	.scan_tree_loop_case4
	cmp	r8d, r9d
	je	.scan_tree_loop_case5
	mov	r11d, 7
	mov	r13d, 4
	jmp	.scan_tree_loop
calign
.scan_tree_loop_case2:
	add	word [rdx+64], 1	; s->bl_tree[REP_3_6].Freq++ (REP_3_6 == 16 * 4 == 64)
	cmp	r8d, eax		; curlen != prevlen
	je	.scan_tree_loop_rset
	add	word [rdx+r8*4], 1	; s->bl_tree[curlen].Freq++
	; resetcount:
	xor	r10d, r10d		; count = 0
	mov	eax, r8d		; prevlen = curlen
	test	r9d, r9d
	jz	.scan_tree_loop_case4
	cmp	r8d, r9d
	je	.scan_tree_loop_case5
	mov	r11d, 7
	mov	r13d, 4
	jmp	.scan_tree_loop
calign
.scan_tree_loop_case3:
	add	word [rdx+68], 1	; s->bl_tree[REPZ_3_10].Freq++ (REPZ_3_10 == 17 * 4 == 68)
	; resetcount:
	xor	r10d, r10d		; count = 0
	mov	eax, r8d		; prevlen = curlen
	test	r9d, r9d
	jz	.scan_tree_loop_case4
	cmp	r8d, r9d
	je	.scan_tree_loop_case5
	mov	r11d, 7
	mov	r13d, 4
	jmp	.scan_tree_loop
calign
.scan_tree_loop_rset:
	; resetcount:
	xor	r10d, r10d		; count = 0
	mov	eax, r8d		; prevlen = curlen
	test	r9d, r9d
	jz	.scan_tree_loop_case4
	cmp	r8d, r9d
	je	.scan_tree_loop_case5
	mov	r11d, 7
	mov	r13d, 4
	jmp	.scan_tree_loop
calign
.scan_tree_loop_case4:
	mov	r11d, 138
	mov	r13d, 3
	jmp	.scan_tree_loop
calign
.scan_tree_loop_case5:
	mov	r11d, 6
	mov	r13d, 3
	jmp	.scan_tree_loop
calign
.scan_tree_loop_done:
	pop	r13
if profile_zlib_internals
	epilog
else
	ret
end if




;--------------------------------------------------- mabe_set_data_type ---------------------------------------------
falign
.maybe_set_data_type:
	if profile_zlib_internals
		prolog	.maybe_set_data_type
	end if
	cmp	dword [rbx+zlib_datatype_ofs], 2	; Z_UNKNOWN
if profile_zlib_internals
	jne	.profiled_retonly
else
	jne	.retonly
end if
	; Z_BINARY = 0, Z_TEXT = 1
	; r12+zlib_dyn_ltree_ofs is what we need to load up
	lea	rsi, [r12+zlib_dstate_dyn_ltree_ofs]
	mov	edx, 0xf3ffc07f
	mov	ecx, 32
calign
.maybe_set_data_type_nontext_loop:
	test	rdx, 1
	jz	.maybe_set_data_type_nontext_next
	cmp	word [rsi], 0
	je	.maybe_set_data_type_nontext_next
	mov	dword [rbx+zlib_datatype_ofs], 0	; Z_BINARY
if profile_zlib_internals
	epilog
else
	ret
end if
calign
.maybe_set_data_type_nontext_next:
	add	rsi, 4
	shr	rdx, 1
	sub	ecx, 1
	jnz	.maybe_set_data_type_nontext_loop
	; else, check for textual white-listed bytes
	lea	rsi, [r12+zlib_dstate_dyn_ltree_ofs]
	; set it to Z_TEXT so we can just jump to retonly
	mov	dword [rbx+zlib_datatype_ofs], 1	; Z_TEXT
	cmp	word [rsi+36], 0
if profile_zlib_internals
	jne	.profiled_retonly
else
	jne	.retonly
end if
	cmp	word [rsi+40], 0
if profile_zlib_internals
	jne	.profiled_retonly
else
	jne	.retonly
end if
	cmp	word [rsi+52], 0
if profile_zlib_internals
	jne	.profiled_retonly
else
	jne	.retonly
end if
	add	rsi, 128				; [32]
	mov	ecx, 224				; LITERALS - 32
calign
.maybe_set_data_type_text_loop:
	cmp	word [rsi], 0
if profile_zlib_internals
	jne	.profiled_retonly
else
	jne	.retonly
end if
	add	rsi, 4
	sub	ecx, 1
	jnz	.maybe_set_data_type_text_loop
	; otherwise, no blacklisted or whitelisted bytes, stream is empty or graylisted only
	mov	dword [rbx+zlib_datatype_ofs], 0	; Z_BINARY
if profile_zlib_internals
	epilog
else
	ret
end if
	
end if




if used adler32 | defined include_everything
	; TODO: redo me with a bit more consideration
	; edi == adler32 accumulator, rsi == buffer, rdx == length
falign
adler32:
	prolog	adler32
	mov	r8d, edi
	mov	r9d, edi		
	and	r8d, 0xffff		; low order word
	shr	r9d, 16			; high order word
	cmp	rdx, 1
	je	.singlebyte
calign
.chunkloop:
	cmp	rdx, 5552
	jb	.chunkdone
	mov	ecx, 5552
	mov	r10d, r8d		; low order copy
	mov	r11d, r9d		; high order copy
calign
.chunkinner:
	cmp	ecx, 16
	jl	.chunkinnerdone
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+10]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+11]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+12]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+13]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+14]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+15]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 16
	sub	ecx, 16
	sub	rdx, 16
	jmp	.chunkinner
calign
.chunkinnerdone:
	; ecx < 16
	shl	ecx, 3
	add	rcx, .chunkjumptable
	jmp	qword [rcx]
dalign
.chunkjumptable:
	dq	.chunk0, .chunk1, .chunk2, .chunk3, .chunk4, .chunk5, .chunk6, .chunk7
	dq	.chunk8, .chunk9, .chunk10, .chunk11, .chunk12, .chunk13, .chunk14, .chunk15
calign
.chunk0:
	; r8d = r10d % 65521
	; r9d = r11d % 65521
	; save rdx cuz unsigned divide blasts it
	mov	rcx, rdx
	mov	eax, r10d
	mov	r10d, 65521
	xor	edx, edx
	div	r10d
	; remainder now in edx
	mov	r8d, edx
	xor	edx, edx
	mov	eax, r11d
	div	r10d
	mov	r9d, edx
	; restore rdx, then check for zero
	mov	rdx, rcx
	test	rdx, rdx
	jz	.chunkreallydone
	; otherwise, go back to the top
	jmp	.chunkloop
calign
.chunk1:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 1
	sub	rdx, 1
	jmp	.chunk0
calign
.chunk2:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 2
	sub	rdx, 2
	jmp	.chunk0
calign
.chunk3:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 3
	sub	rdx, 3
	jmp	.chunk0
calign
.chunk4:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 4
	sub	rdx, 4
	jmp	.chunk0
calign
.chunk5:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 5
	sub	rdx, 5
	jmp	.chunk0
calign
.chunk6:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 6
	sub	rdx, 6
	jmp	.chunk0
calign
.chunk7:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 7
	sub	rdx, 7
	jmp	.chunk0
calign
.chunk8:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 8
	sub	rdx, 8
	jmp	.chunk0
calign
.chunk9:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 9
	sub	rdx, 9
	jmp	.chunk0
calign
.chunk10:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 10
	sub	rdx, 10
	jmp	.chunk0
calign
.chunk11:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+10]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 11
	sub	rdx, 11
	jmp	.chunk0
calign
.chunk12:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+10]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+11]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 12
	sub	rdx, 12
	jmp	.chunk0
calign
.chunk13:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+10]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+11]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+12]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 13
	sub	rdx, 13
	jmp	.chunk0
calign
.chunk14:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+10]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+11]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+12]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+13]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 14
	sub	rdx, 14
	jmp	.chunk0
calign
.chunk15:
	movzx	eax, byte [rsi]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+1]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+2]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+3]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+4]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+5]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+6]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+7]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+8]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+9]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+10]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+11]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+12]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+13]
	add	r10d, eax
	add	r11d, r10d
	movzx	eax, byte [rsi+14]
	add	r10d, eax
	add	r11d, r10d
	add	rsi, 15
	sub	rdx, 15
	jmp	.chunk0
calign
.chunkdone:
	; if rdx < 5552, we end up here
	mov	ecx, edx		; however many are left, which we know is <5552
	mov	r10d, r8d		; low order copy
	mov	r11d, r9d		; high order copy
	; when this one finishes, it will call chunkreallydone
	jmp	.chunkinner
calign
.chunkreallydone:
	; rdx went to zero, which means we are all done and can recombine our r8d and r9d for our return
	shl	r9d, 16
	or	r8d, r9d
	mov	eax, r8d
	epilog
calign
.singlebyte:
	movzx	eax, byte [rsi]
	add	r8d, eax		; adler += buf[0]

	mov	ecx, r8d
	sub	ecx, 65521
	cmp	r8d, 65521
	cmovae	r8d, ecx		; if (adler >= BASE) adler -= BASE

	add	r9d, r8d		; sum2 += adler
	mov	ecx, r9d
	sub	ecx, 65521
	cmp	r9d, 65521
	cmovae	r9d, ecx		; if (sum2 >= BASE) sum2 -= BASE
	shl	r9d, 16
	or	r8d, r9d
	mov	eax, r8d
	epilog
	
	
end if
