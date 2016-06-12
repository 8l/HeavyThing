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
	; mappedheap.inc: file based heap management
	; a very simple freeblock-coalescing heap, backed by mapped (which may be anon)
	; bin-based for small allocations, tree based for large blocks
	;
	; this version utilises an in-memory unsignedmap that is not persisted to disk
	; (and is much faster/more tolerant as a result)
	;
	; we keep a "separate" linked list of large free blocks, smashed together in single
	; page groups instead of linking the blocks themselves
	;
	; the reason for this is: at startup/initialisation, when we need to build our
	; in-memory unsignedmap of the free blocks themselves, if they are block-linked and
	; the underlying mapped file is _huge_, then we potentially have to block-scan
	; (read: preload) the first page of every free block in the file. Because of the way the
	; underlying paging system works, this really means a 4k read penalty per large free
	; block.
	;
	; if instead, and the way we implemented it here, we keep 32 byte linked list blocks
	; _separate_, then we can read page_size / 32 worth of large free block records in a single
	; page read, and even if the linked list pages are disparate, this still only means block
	; based freelist loads, and thus no real startup penalty, even for very large maps with
	; a very high number of free large blocks
	;
	; CAVEAT EMPTOR: file based mapped goods do MAP_SHARED, which does indeed carry changes
	; to disk... but the timing/use of sync/syncpart should be carefully considered
	;
	; also note: our base pointer itself can and will move! (hence pointers are bad, haha)
	;
mappedheap_base_ofs = 0
mappedheap_size_ofs = 8
mappedheap_fd_ofs = 16
mappedheap_largefree_ofs = 24

mappedheap_size = 32


; inside the first 4k is our state information, it is unfortunate that we waste the remainder of the
; first 4k but we need a control structure and the rest is better left page-aligned
virtual at rsi
	_mh_bins	dq	?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
	_mh_freelist_first	dq	?
	_mh_freelist_last	dq	?
	_mh_unused_first	dq	?
	_mh_unused_last		dq	?
	_mh_super		dq	?
end virtual

mappedheap_freelist_next_ofs = 0
mappedheap_freelist_prev_ofs = 8
mappedheap_freelist_size_ofs = 16
mappedheap_freelist_ptr_ofs = 24


if used mappedheap$new | defined include_everything
	; single argument in rdi: string filename (NULL is okay, will be ANON if so)
falign
mappedheap$new:
	prolog	mappedheap$new
	test	rdi, rdi
	jz	.anon
	push	rdi
	mov	edi, mappedheap_size
	call	heap$alloc
	mov	rdx, [rsp]
	mov	[rsp], rax
	mov	rdi, rax
	mov	esi, page_size
	call	mapped$init
	mov	rdi, [rsp]
	cmp	qword [rdi+mappedheap_fd_ofs], 0
	jl	.failed
	call	unsignedmap$new
	mov	rdi, [rsp]
	mov	[rdi+mappedheap_largefree_ofs], rax
	; initialize the large block free list
	mov	rsi, [rdi+mappedheap_base_ofs]
	mov	rdx, [_mh_freelist_first]
	test	rdx, rdx
	jz	.alldone
	push	r12 r13 r14
	mov	r12, rdx
	mov	r13, [rdi+mappedheap_largefree_ofs]
	mov	r14, [rdi+mappedheap_base_ofs]
calign
.freelistloop:
	mov	rcx, r12
	add	rcx, r14	; rcx now a pointer to our freelist item
	mov	rdi, r13
	mov	rsi, [rcx+mappedheap_freelist_size_ofs]
	mov	rdx, r12	; offset not pointer
	call	unsignedmap$insert
	mov	rcx, r12
	add	rcx, r14
	mov	r12, [rcx+mappedheap_freelist_next_ofs]
	test	r12, r12
	jnz	.freelistloop
	pop	r14 r13 r12
	pop	rax		; get our return
	epilog
calign
.anon:
	mov	edi, mappedheap_size
	call	heap$alloc
	mov	rdi, rax
	mov	esi, page_size
	push	rax
	call	mapped$init_anon
	pop	rax
	epilog
calign
.failed:
	call	heap$free
	xor	eax, eax
	pop	rdi
	epilog
calign
.alldone:
	mov	rax, rdi
	pop	rdi
	epilog
end if


if used mappedheap$new_cstr | defined include_everything
	; single argument in rdi: null terminated cstr of the filename (NULL is okay, will be ANON if so)
	; returns new mappedheap in rax, or null on failure/error
falign
mappedheap$new_cstr:
	prolog	mappedheap$new_cstr
	test	rdi, rdi
	jz	.anon
	push	rdi
	mov	edi, mappedheap_size
	call	heap$alloc
	mov	rdx, [rsp]
	mov	[rsp], rax
	mov	rdi, rax
	mov	esi, page_size
	call	mapped$init_cstr
	mov	rdi, [rsp]
	cmp	qword [rdi+mappedheap_base_ofs], -1
	je	.failed
	call	unsignedmap$new
	mov	rdi, [rsp]
	mov	[rdi+mappedheap_largefree_ofs], rax
	; initialize the large block free list
	mov	rsi, [rdi+mappedheap_base_ofs]
	mov	rdx, [_mh_freelist_first]
	test	rdx, rdx
	jz	.alldone
	push	r12 r13 r14
	mov	r12, rdx
	mov	r13, [rdi+mappedheap_largefree_ofs]
	mov	r14, [rdi+mappedheap_base_ofs]
calign
.freelistloop:
	mov	rcx, r12
	add	rcx, r14	; rcx now a pointer to our freelist item
	mov	rdi, r13
	mov	rsi, [rcx+mappedheap_freelist_size_ofs]
	mov	rdx, r12	; offset not pointer
	call	unsignedmap$insert
	mov	rcx, r12
	add	rcx, r14
	mov	r12, [rcx+mappedheap_freelist_next_ofs]
	test	r12, r12
	jnz	.freelistloop
	pop	r14 r13 r12
	pop	rax		; get our return
	epilog
calign
.anon:
	mov	edi, mappedheap_size
	call	heap$alloc
	mov	rdi, rax
	mov	esi, page_size
	push	rax
	call	mapped$init_anon
	pop	rax
	epilog
calign
.failed:
	call	heap$free
	xor	eax, eax
	pop	rdi
	epilog
calign
.alldone:
	mov	rax, rdi
	pop	rdi
	epilog
end if


if used mappedheap$setsuper | defined include_everything
	; two arguments: rdi == mappedheap, rsi == arbitrary 64 bits to stick in the super spot
	; note here: a "super" is just a persistent spot... useful if you allocate something with
	; get, and need to retrieve its value during subsequent runs
falign
mappedheap$setsuper:
	prolog	mappedheap$setsuper
	mov	rdx, rsi
	mov	rsi, [rdi+mappedheap_base_ofs]
	mov	[_mh_super], rdx
	epilog
end if


if used mappedheap$getsuper | defined include_everything
	; single argument: rdi == mappedheap
	; returns whatever is/was set in the super spot in rax
falign
mappedheap$getsuper:
	prolog	mappedheap$getsuper
	mov	rsi, [rdi+mappedheap_base_ofs]
	mov	rax, [_mh_super]
	epilog
end if


if used mappedheap$put | defined include_everything
	; two arguments: rdi == mappedheap, rsi == offset/p to free up
falign
mappedheap$put:
	prolog	mappedheap$put
	sub	rsi, 8			; move back to our preface
	mov	rdx, [rdi+mappedheap_base_ofs]
	mov	rcx, [rdx+rsi]		; get our preface
	cmp	rcx, 32
	ja	.largeput
	; else, bin put
	mov	r8, [rdx+rcx*8]		; this bin's freelist head
	mov	[rdx+rsi+8], r8		; store it after this one's preface
	mov	[rdx+rcx*8], rsi	; store this one in the freelist head
	; done
	epilog
calign
.largeput:
	; we need rsi pointed to our heap base
	xchg	rdx, rsi
	; so now, rdx is our offset we are putting back, rsi is our actual base
	cmp	qword [_mh_unused_first], 0
	jne	.unused_okay
	; else, we need more unused entries
	push	rdi rdx rcx
	mov	rsi, (page_size shl 2) - 8	; bytes left
	call	mappedheap$get		; large get
	pop	rcx rdx rdi
	mov	rsi, [rdi+mappedheap_base_ofs]	; reset rsi in case our base moved during the get
	mov	r8, (page_size shl 2) - 8	; bytes left
	; rax contains the offset of our new page
calign
.moreunused_loop:
	cmp	r8, 32
	jl	.unused_okay
	mov	qword [rsi+rax+mappedheap_freelist_next_ofs], 0
	mov	r9, [_mh_unused_last]
	mov	qword [rsi+rax+mappedheap_freelist_prev_ofs], r9
	mov	qword [rsi+rax+mappedheap_freelist_size_ofs], 0
	mov	qword [rsi+rax+mappedheap_freelist_ptr_ofs], 0
	test	r9, r9
	jz	.moreunused_loop_setfirst
	mov	[rsi+r9+mappedheap_freelist_next_ofs], rax
	mov	[_mh_unused_last], rax
	add	rax, 32
	sub	r8, 32
	jmp	.moreunused_loop
calign
.moreunused_loop_setfirst:
	mov	[_mh_unused_first], rax
	mov	[_mh_unused_last], rax
	add	rax, 32
	sub	r8, 32
	jmp	.moreunused_loop
calign
.unused_okay:
	; so at this stage, rdi == our mappedheap, rsi == our base, rdx == offset we are putting back, rcx == its preface/size
	mov	r8, rdx
	add	r8, rcx				; offset to the next one
	mov	r9, [rdi+mappedheap_size_ofs]	; total size of the mappedheap
	mov	r10, r8
	add	r10, 32
	cmp	r10, r9
	ja	.nonext
	; else, there is a block after this one, see if it is in the largeblock freelist, and if it is, coalesce them
	mov	r10, [rsi+r8]			; preface of the next block
	sub	rsp, 48
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	[rsp+40], r10
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	mov	rsi, r10			; look for the size of the next block
	call	unsignedmap$find
	test	rax, rax
	mov	rsi, [rsp+8]
	mov	r8, [rsp+32]
	jz	.nextnotinfreelist
calign
.findnextloop:
	mov	r9, [rax+_avlofs_key]
	mov	r10, [rax+_avlofs_value]
	cmp	[rsi+r10+mappedheap_freelist_ptr_ofs], r8
	je	.foundnext
	mov	rax, [rax+_avlofs_trunk]
	test	rax, rax
	jnz	.findnextloop
	jmp	.nextnotinfreelist
calign
.foundnext:
	; next block is in the freelist, remove it from the largefree list, modify its pointers, reinsert coalesced block
	mov	r11, [rsp+40]			; size of the next block
	add	r11, [rsp+24]			; + the size of our block
	mov	rdx, [rsp+16]
	mov	[rsi+r10+mappedheap_freelist_ptr_ofs], rdx
	mov	[rsi+r10+mappedheap_freelist_size_ofs], r11
	; leave it in its spot in the freelist linkedlist
	mov	rdi, [rsp]
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	mov	rsi, r9
	mov	rdx, r10
	mov	[rsp+32], r10			; save our freelist spot
	mov	[rsp+40], r11			; save newsize
	call	unsignedmap$erase_specific
	; now, we need to reinsert it
	mov	rdi, [rsp]
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	mov	rdx, [rsp+32]
	mov	rsi, [rsp+40]
	call	unsignedmap$insert
	; and we are done and dusted.
	add	rsp, 48
	epilog
calign
.nextnotinfreelist:
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	r8, [rsp+32]
	mov	r10, [rsp+40]
	add	rsp, 48
calign
.nonext:
	; coalescing with next block was not possible, or there is no next block
	; so toss this block into the largeblock freelist
	mov	r8, [_mh_unused_first]
	mov	r9, [rsi+r8+mappedheap_freelist_next_ofs]
	mov	[_mh_unused_first], r9
	test	r9, r9
	jz	.nonext_setlast
	mov	qword [rsi+r9+mappedheap_freelist_prev_ofs], 0
	jmp	.nonext_doit
calign
.nonext_setlast:
	mov	[_mh_unused_last], r9
calign
.nonext_doit:
	mov	r9, [_mh_freelist_last]
	mov	qword [rsi+r8+mappedheap_freelist_next_ofs], 0
	mov	[rsi+r8+mappedheap_freelist_prev_ofs], r9
	mov	[rsi+r8+mappedheap_freelist_ptr_ofs], rdx
	mov	[rsi+r8+mappedheap_freelist_size_ofs], rcx
	test	r9, r9
	jz	.nonext_doit_setfirst
	mov	[rsi+r9+mappedheap_freelist_next_ofs], r8
	mov	[_mh_freelist_last], r8
	; do our insert
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	mov	rsi, rcx
	mov	rdx, r8
	call	unsignedmap$insert
	epilog
calign
.nonext_doit_setfirst:
	mov	[_mh_freelist_first], r8
	mov	[_mh_freelist_last], r8
	; do our insert
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	mov	rsi, rcx
	mov	rdx, r8
	call	unsignedmap$insert
	epilog

end if


if used mappedheap$get | defined include_everything
	; two arguments: rdi == mappedheap, rsi == size to allocate
	; similar to heap$alloc, only we return a useable OFFSET and not a pointer
	; to make a pointer out of it (remembering it may MOVE) just add pointer at [rdi] to it
falign
mappedheap$get:
	prolog	mappedheap$get
	add	rsi, 8			; add room for our preface
	cmp	rsi, 128
	jle	.get128
	cmp	rsi, 1024
	jle	.get1024
	cmp	rsi, 4096
	jle	.get4096
	cmp	rsi, 131072
	jle	.get131072
	add	rsi, 0x1ffff
	and	rsi, not 0x1ffff
	; largeget for rsi bytes
	push	rsi rdi
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	call	unsignedmap$lowerbound
	test	rax, rax
	jz	.largeget_expand
	; otherwise we got one from our freelist, stitch it up and see if we need to split it
	mov	r8, [rax+_avlofs_key]	; itemsize
	mov	r9, [rax+_avlofs_value]	; flcur
	push	r8 r9
	mov	rcx, [rsp]
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	mov	rsi, r8
	mov	rdx, r9
	call	unsignedmap$erase_specific
	pop	r9 r8
	mov	rsi, r8			; itemsize
	mov	rdi, [rsp]
	mov	rdx, [rdi+mappedheap_base_ofs]
	mov	rcx, [rsp+8]		; the original size we wanted
	sub	rsi, rcx		; - original size we wanted == leftover
	cmp	rsi, 131072
	ja	.largeget_split
	; and if not, remove this block from the freelist linked list, and add the freelist item spot
	mov	rsi, rdx		; our base pointer
	cmp	r9, [_mh_freelist_first]
	je	.largeget_isfirst
	cmp	r9, [_mh_freelist_last]
	je	.largeget_islastnotfirst
	; else, not first and not last
	mov	r10, [rdx+r9+mappedheap_freelist_next_ofs]
	mov	r11, [rdx+r9+mappedheap_freelist_prev_ofs]
	mov	[rdx+r11+mappedheap_freelist_next_ofs], r10
	mov	[rdx+r10+mappedheap_freelist_prev_ofs], r11
	jmp	.largeget_unusedinsert
calign
.largeget_isfirst:
	cmp	r9, [_mh_freelist_last]
	je	.largeget_isfirstandlast
	; else, is first but not last
	mov	r10, [rdx+r9+mappedheap_freelist_next_ofs]
	mov	[_mh_freelist_first], r10
	mov	qword [rdx+r10+mappedheap_freelist_prev_ofs], 0
	jmp	.largeget_unusedinsert
calign
.largeget_islastnotfirst:
	mov	r10, [rdx+r9+mappedheap_freelist_prev_ofs]
	mov	[_mh_freelist_last], r10
	mov	qword [rdx+r10+mappedheap_freelist_next_ofs], 0
	jmp	.largeget_unusedinsert
calign
.largeget_isfirstandlast:
	mov	qword [_mh_freelist_first], 0
	mov	qword [_mh_freelist_last], 0
calign
.largeget_unusedinsert:
	; back into the unused list
	mov	qword [rdx+r9+mappedheap_freelist_next_ofs], 0
	mov	r10, [_mh_unused_last]
	mov	[rdx+r9+mappedheap_freelist_prev_ofs], r10
	test	r10, r10
	jz	.largeget_unusedinsert_nonext
	mov	[rdx+r10+mappedheap_freelist_next_ofs], r9
	mov	[_mh_unused_last], r9
	mov	rax, [rdx+r9+mappedheap_freelist_ptr_ofs]
	pop	rdi rsi
	add	rax, 8
	epilog
calign
.largeget_unusedinsert_nonext:
	mov	[_mh_unused_first], r9
	mov	[_mh_unused_last], r9
	mov	rax, [rdx+r9+mappedheap_freelist_ptr_ofs]
	pop	rdi rsi
	add	rax, 8
	epilog
calign
.largeget_split:
	; we are splitting it cuz there is >128k leftover... we can re-use the flcur entry
	; since it is already linked into the list, so all we need to do is change its pointer and size
	; and leave the rest untouched (next/prev untouched that is)
	mov	r10, [rdx+r9+mappedheap_freelist_ptr_ofs]	; item offset
	mov	r11, r10
	mov	[rdx+r10], rcx		; set its preface
	add	r11, rcx		; remainder offset
	mov	[rdx+r11], rsi		; set the size of the one we are putting back
	mov	[rdx+r9+mappedheap_freelist_ptr_ofs], r11
	mov	[rdx+r9+mappedheap_freelist_size_ofs], rsi
	; insert it into back into our unsignedmap
	mov	rdi, [rdi+mappedheap_largefree_ofs]
	; rsi is already the leftover key
	mov	rdx, r9			; flcur value for the largefree map
	push	r10			; our return
	call	unsignedmap$insert
	pop	rax
	pop	rdi rsi
	add	rax, 8
	epilog
calign
.largeget_expand:
	mov	rax, [rdi+mappedheap_size_ofs]
	push	rax
	call	mapped$grow
	pop	rax
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, rax
	add	rdx, [rdi+mappedheap_base_ofs]
	mov	[rdx], rsi		; store our preface so when it gets put back we know where it goes
	pop	rdi rsi
	add	rax, 8
	epilog
calign
.get128:
	shr	rsi, 4
	jmp	.binget
calign
.get1024:
	add	rsi, 0x7f
	and	rsi, not 0x7f
	shr	rsi, 7
	add	rsi, 7
	jmp	.binget
calign
.get4096:
	add	rsi, 0x1ff
	and	rsi, not 0x1ff
	shr	rsi, 9
	add	rsi, 14
	jmp	.binget
calign
.get131072:
	add	rsi, 0x3fff
	and	rsi, not 0x3fff
	shr	rsi, 14
	add	rsi, 23
calign
.binget:
	mov	rcx, rsi		; our bin#
	mov	rsi, [rdi+mappedheap_base_ofs]
	mov	rax, [rsi+rcx*8]
	test	rax, rax
	jz	.newbin
	mov	rdx, [rax+8]		; the next item in the freelist for this bin
	mov	[rsi+rcx*8], rdx	; move to the bin list
	add	rax, 8			; our actual return
	epilog
calign
.newbin:
	push	rcx rdi
	shl	rcx, 3
	add	rcx, .binnewpages
	mov	rsi, [rcx]
	call	mappedheap$get
	sub	rax, 8			; we "take over" this spot, as it will never get put back
	mov	rdi, [rsp]
	mov	rcx, [rsp+8]
	mov	rsi, [rdi+mappedheap_base_ofs]
	mov	rdx, rcx
	shl	rdx, 3
	mov	r8, rdx
	add	rdx, .binsizes
	add	r8, .binnewpages
	mov	rdx, [rdx]
	mov	r8, [r8]
	; so now, rdx has our bin size, r8 has the size of the block we just allocated
calign
.newbininitloop:
	cmp	r8, rdx
	jl	.newbinreturn
	mov	[rax], rcx		; store the bin
	mov	r9, [rsi+rcx*8]	; get whatever is at the freelist first for this bin
	mov	[rax+8], r9		; store it
	mov	[rsi+rcx*8], rax	; store our new one
	add	rax, rdx		; move to the next one
	sub	r8, rdx			; decrement our new page size
	jmp	.newbininitloop
calign
.newbinreturn:
	pop	rdi rcx
	mov	rax, [rsi+rcx*8]
	mov	rdx, [rax+8]
	mov	[rsi+rcx*8], rdx
	add	rax, 8
	epilog
calign
.binsizes:
	dq	16,32,48,64,80,96,112,128,128,256,384,512,640,768,896,1024,1024,1536,2048,2560,3072,3584,4096,0,16384,32768,49152,65536,81920,98304,114688,131072
calign
.binnewpages:
	dq	4096,8192,12288,16384,20480,24576,28672,32768,32768,32768,49152,65536,81920,98304,114688,131072,65536,98304,131072,163840,196608,229376,262144,0,32768,65536,98304,131072,163840,196608,229376,262144

end if
