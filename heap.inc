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
	; heap.inc: memory management goodies
	;
	;
	; some notes here on the choice of memory management strategy
	;
	; this is a hotly debated matter of personal preference imo
	; ... HOWEVER, one-size-fits-all for every single programmer
	; isn't really that cool.
	;
	; that being said, most general purpose allocators work well
	; enough, and are generally fast enough for the average
	; coding requirement.
	;
	; Bin based allocation that is never returned to the kernel
	; is how this particular variety works. (Noting of course that
	; virtual memory isn't quite so simple.)
	;
	; several reasons for this: 1) hands down the fastest for
	; alloc/free obviously due to its simplistic design
	; 2) most every server-based system I have ever built
	; manages a good and decent number of inflight allocations
	; and during the course of running, frees and reallocates
	; similarly sized blocks depending on workload, etc.
	; consequently, we don't need some uber-conservative
	; tree-based freelist or coalescing strategies, we simply
	; place them in as waste-free-bin-sizes as practical
	; and call it good.
	;
	; This is not intended to run inside 64KB of memory, so:
	; cry me a river if you don't like it, or code up one that is
	; uber-conservative with its waste/overhead.
	;
	; now then...
	;
	; up to 2048 byte allocs, granularity for bins is 64 bytes (32 bins)
	; from 2048 to 16384, granularity for bins is 1024 bytes (14 bins)
	; and from 16384 to 131072, granularity is 4096 bytes (28 bins)
	; and from 131072 to 1048576, granularity is 64k (14 bins)
	; beyond this: straight unadulterated mmap calls for the lucky caller who wants >1MB alloc
	; (similar to how ptmalloc does it anyway for the bigger ones)
	;
	; TODO: compact our header size down from wasting 139272 bytes
	; for my purposes, wasting said is no dramas. (128GB ram on my dev
	; machine).

heapdebug = 0

	; 
	; we need two global variables that are writeable for our heap:

if used heap$init | defined include_everything

globals
{
	_heap_base	dq	0
	_heap_base_size	dq	0
}

initial_heap_shiftcount = 3

falign
heap$init:
	prolog_silent	heap$init
	mov	eax, syscall_mmap
	xor	edi, edi
	mov	rsi, 2147483648
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	shl	rsi, initial_heap_shiftcount
	syscall
	mov	[_heap_base], rax
	; update, the return from here we are interested in is NOT a -1
	; it is ENOMEM, which is -12
	cmp	rax, -12
	je	.trysmaller_2g
	cmp	rax, -1
	je	.trysmaller_2g
	mov	rdi, rax	; setup call to mremap
	mov	rsi, 2147483648	; old size
	mov	edx, 139272 + (heap_bincheck * 8)	; new size
	xor	r10d, r10d
	mov	eax, syscall_mremap
	shl	rsi, initial_heap_shiftcount
	syscall
	mov	[_heap_base], rax
	cmp	rax, -1
	je	.die
	mov	[_heap_base_size], 139272 + (heap_bincheck * 8)
	epilog
calign
.trysmaller_2g:
	mov	eax, syscall_mmap
	xor	edi, edi
	mov	rsi, 2147483648
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	mov	[_heap_base], rax
	cmp	rax, -12
	je	.trysmaller_1g
	cmp	rax, -1
	je	.trysmaller_1g
	mov	rdi, rax	; setup call to mremap
	mov	rsi, 2147483648	; old size
	mov	edx, 139272 + (heap_bincheck * 8)	; new size
	xor	r10d, r10d
	mov	eax, syscall_mremap
	syscall
	mov	[_heap_base], rax
	cmp	rax, -1
	je	.die
	mov	[_heap_base_size], 139272 + (heap_bincheck * 8)
	epilog
calign
.trysmaller_1g:
	mov	eax, syscall_mmap
	xor	edi, edi
	mov	rsi, 1073741824
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	mov	[_heap_base], rax
	cmp	rax, -12
	je	.trysmallerstill
	cmp	rax, -1
	je	.trysmallerstill
	mov	rdi, rax	; setup call to mremap
	mov	rsi, 1073741824 ; old size
	mov	edx, 139272 + (heap_bincheck * 8)	; new size
	xor	r10d, r10d
	mov	eax, syscall_mremap
	syscall
	mov	[_heap_base], rax
	cmp	rax, -1
	je	.die
	mov	[_heap_base_size], 139272 + (heap_bincheck * 8)
	epilog
calign
.trysmallerstill:
	mov	eax, syscall_mmap
	xor	edi, edi
	mov	rsi, 536870912
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	mov	[_heap_base], rax
	cmp	rax, -12
	je	.try256MB
	cmp	rax, -1
	je	.try256MB
	mov	rdi, rax	; setup call to mremap
	mov	rsi, 536870912	; old size
	mov	edx, 139272 + (heap_bincheck * 8)	; new size
	xor	r10d, r10d
	mov	eax, syscall_mremap
	syscall
	mov	[_heap_base], rax
	cmp	rax, -1
	je	.die
	mov	[_heap_base_size], 139272 + (heap_bincheck * 8)
	epilog
calign
.try256MB:
	mov	eax, syscall_mmap
	xor	edi, edi
	mov	rsi, 268435456
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	mov	[_heap_base], rax
	cmp	rax, -12
	je	.die
	cmp	rax, -1
	je	.die
	mov	rdi, rax	; setup call to mremap
	mov	rsi, 268435456	; old size
	mov	edx, 139272 + (heap_bincheck * 8)	; new size
	xor	r10d, r10d
	mov	eax, syscall_mremap
	syscall
	mov	[_heap_base], rax
	cmp	rax, -1
	je	.die
	mov	[_heap_base_size], 139272 + (heap_bincheck * 8)
	epilog
	

        ; syscall # into rax, args: rdi, rsi, rdx, r10, r8, r9
calign
.die:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .deathmsg
	mov	edx, .deathmsglen
	syscall
	mov	eax, syscall_exit
	mov	edi, 99
	syscall
	; update, adding friendly output here instead of 99 syscall death
dalign
.deathmsg:
	db	'Insufficient memory.',10
.deathmsglen = $ - .deathmsg
end if


if used heap$alloc_permanent | defined include_everything
	; single argument in rdi for count, returns in rax	
	; this is intended for permanent allocations (ones that aren't ever going to be heap$free'd)
	; all it does is call mmap for a new segment
falign
heap$alloc_permanent:
	prolog	heap$alloc_permanent
	add	rdi, 8
	push	rdi
	mov	eax, syscall_mmap
	mov	rsi, rdi
	xor	edi, edi
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	pop	rdi
	cmp	rax, -1
	je	.die
	mov	[rax], rdi
	add	rax, 8
	epilog
calign
.die:
	mov	eax, syscall_exit
	mov	edi, 99
	syscall
end if

if heapdebug

falign
debug_heap:
	; three args: rdi == db ptr, esi == length of same, rdx == number to display
	sub	rsp, 128
	mov	[rsp], rdx
	mov	eax, syscall_write
	mov	rdx, rsi
	mov	rsi, rdi
	mov	edi, 1
	syscall
	mov	eax, syscall_write
	lea	rsi, [rsp+8]
	mov	edx, 2
	mov	edi, 1
	mov	dword [rsi], '0x'
	syscall
	mov	rax, [rsp]
	mov	rsi, rsp
	mov	edi, 1
	mov	edx, 16
	bswap	rax
	
	xor	ecx, ecx
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf0
	shr	cl, 4
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	
	mov	cl, al
	and	cl, 0xf
	shr	rax, 8
	movzx	r8d, byte [rcx+.hexchars]
	mov	dword [rsi], r8d
	add	rsi, 1
	

	mov	rsi, rsp
	mov	eax, syscall_write
	syscall
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, 2
	mov	dword [rsi], 0x0a0d
	syscall
	add	rsp, 128
	ret
dalign
.hexchars:
	db	'0123456789abcdef'

end if

if heapdebug

falign
debug_nodebin:
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .debug1
	mov	edx, .debug1len
	syscall
	push	rbx
	mov	rbx, [_heap_base]
	mov	rbx, [rbx]
calign
.loop:
	test	rbx, rbx
	jz	.done
	mov	rdi, .debug2
	mov	esi, .debug2len
	mov	rdx, rbx
	call	debug_heap
	mov	rbx, [rbx]
	; jmp	.loop
calign
.done:
	pop	rbx
	ret
dalign
.debug1 db '                                                            node bin freelist:',10
.debug1len = $ - .debug1
.debug2 db '                                                                         node:'
.debug2len = $ - .debug2


end if


if heapdebug

falign
debug_firstbin:
	call	debug_nodebin
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .debug1
	mov	edx, .debug1len
	syscall
	push	rbx
	mov	rbx, [_heap_base]
	mov	rbx, [rbx+8]
calign
.loop:
	test	rbx, rbx
	jz	.done
	mov	rdi, .debug2
	mov	esi, .debug2len
	mov	rdx, rbx
	call	debug_heap
	mov	rbx, [rbx]
	; jmp	.loop
calign
.done:
	pop	rbx
	ret
dalign
.debug1 db '                                                            first bin freelist:',10
.debug1len = $ - .debug1
.debug2 db '                                                                           ptr:'
.debug2len = $ - .debug2


end if


if used heap$alloc | defined include_everything
	; single argument in rdi for count, returns in rax
falign
heap$alloc:
	prolog	heap$alloc
if heapdebug
	push	rdi
	mov	rdi, .debug3
	mov	esi, .debug3len
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+0x8]
	call	debug_heap

	mov	rdx, [rsp]
	mov	rdi, .debug1
	mov	esi, .debug1len
	call	debug_heap
	pop	rdi
end if
	cmp	rdi, avlnode_size	; we make a special allowance for map nodes
	je	.getnode
	cmp	rdi, 2048
	jle	.get64
	cmp	rdi, 16384
	jle	.get1024
	cmp	rdi, 131072
	jle	.get4096
	cmp	rdi, 1048576
	jle	.get65536
	; else, straight mmap return
	add	rdi, 8 + (heap_barriers * 8)
	push	rdi
	mov	eax, syscall_mmap
	mov	rsi, rdi
	xor	edi, edi
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	pop	rdi
	cmp	rax, -1
	je	.die
	mov	[rax], rdi
if heap_barriers
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8
end if
	epilog			; includes our ret for us
if heapdebug
dalign
.debug1	db 'heap$alloc for: '
.debug1len = $ - .debug1
.debug2 db '                              bin is: '
.debug2len = $ - .debug2
.debug3 db '-------- heap_base[8] is: '
.debug3len = $ - .debug3
.debug4 db 'NEW BIN NEW BIN NEW BIN NEW BIN NEW BIN: '
.debug4len = $ - .debug4
.debug5 db '         heap_base[8] now: '
.debug5len = $ - .debug5
end if
calign
.get64:
	add	rdi, 0x47	; size prefix + rounding
	mov	rdx, [_heap_base]
	mov	ecx, 6		; * 64 if we have to get a new bin
	and	rdi, not 0x3f
	mov	rsi, rdi
	shr	rsi, 3
	mov	r8, rsi
if heap_barriers
	add	rdi, 8
end if
if heapdebug
	push	rdi rdx rcx rsi r8
	mov	rdx, rsi
	mov	rdi, .debug2
	mov	esi, .debug2len
	call	debug_heap
	pop	r8 rsi rcx rdx rdi
end if
	add	rsi, rdx
	; rsi is now a valid pointer into our heap_base for our bin freelist start
	; so rdi >> 6 == / 64, which is the real bin #, but we actually want that # times 8
	; so shl'd again by 3, so the real shr is >> 3 hence above
	mov	rax, [rsi]
	test	rax, rax
	jz	.newbin
	; else, we have a valid offset for this bin
	mov	rcx, [rax]	; get its next into rcx
	mov	[rsi], rcx	; store the new next for this bin into the head of the freelist
	mov	[rax], r8	; to get the actual blocksize, this value << 3 == size of block itself, - 8
if heap_barriers
	cmp	qword [rax+8], 0x46004600
	jne	.barrierfail
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8
end if
if heapdebug
	push	rax
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+8]
	mov	rdi, .debug5
	mov	esi, .debug5len
	call	debug_heap

	call	debug_firstbin
	pop	rax
end if
	epilog			; all good
calign
.getnode:
	; special size allowance for map nodes
	mov	edi, 80 + (heap_barriers * 8)		; avlnode_size == 68, which has a partial dd hanging off the end, so 72 == align 8, + 8 for prefix
	mov	rdx, [_heap_base]
	mov	ecx, 9		; * 512 if we have to get a new bin
	; we'll use bin #0 for map nodes if !heap_bincheck, otherwise, the final spot in our header
if heap_bincheck
	mov	esi, 139272
else
	xor	esi, esi
end if
	mov	r8, rsi
	add	rsi, rdx
	mov	rax, [rsi]
	test	rax, rax
	jz	.newbin
	mov	rcx, [rax]
	mov	[rsi], rcx
	mov	[rax], r8
if heap_barriers
	cmp	qword [rax+8], 0x46004600
	jne	.barrierfail
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8
end if

if heapdebug
	push	rax
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+8]
	mov	rdi, .debug5
	mov	esi, .debug5len
	call	debug_heap

	call	debug_firstbin
	pop	rax
end if
	epilog
	
	; these are all variants of .get64, only diff is the alignment modifier
calign
.get1024:
	add	rdi, 0x407	; size prefix + rounding
	mov	rdx, [_heap_base]
	mov	ecx, 4		; * 16 if we have to get a new bin
	and	rdi, not 0x3ff
	mov	rsi, rdi
	shr	rsi, 3
	mov	r8, rsi
if heap_barriers
	add	rdi, 8
end if
	add	rsi, rdx
	mov	rax, [rsi]
	test	rax, rax
	jz	.newbin
	mov	rcx, [rax]	; get its next into rcx
	mov	[rsi], rcx	; store the new next for this bin into the head of the freelist
	mov	[rax], r8
if heap_barriers
	cmp	qword [rax+8], 0x46004600
	jne	.barrierfail
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8
end if
	epilog			; all good

calign
.get4096:
	add	rdi, 0x1007	; size prefix + rounding
	mov	rdx, [_heap_base]
	mov	ecx, 2		; * 4 if we have to get a new bin
	and	rdi, not 0xfff
	mov	rsi, rdi
	shr	rsi, 3
	mov	r8, rsi
if heap_barriers
	add	rdi, 8
end if
	add	rsi, rdx
	mov	rax, [rsi]
	test	rax, rax
	jz	.newbin
	mov	rcx, [rax]	; get its next into rcx
	mov	[rsi], rcx	; store the new next for this bin into the head of the freelist
	mov	[rax], r8
if heap_barriers
	cmp	qword [rax+8], 0x46004600
	jne	.barrierfail
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8
end if
	epilog			; all good

calign
.get65536:
	add	rdi, 0x10007	; size prefix + rounding
	mov	rdx, [_heap_base]
	mov	ecx, 1		; * 2 if we have to get a new bin
	and	rdi, not 0xffff
	mov	rsi, rdi
	shr	rsi, 3
	mov	r8, rsi
if heap_barriers
	add	rdi, 8
end if
	add	rsi, rdx
	mov	rax, [rsi]
	test	rax, rax
	jz	.newbin
	mov	rcx, [rax]	; get its next into rcx
	mov	[rsi], rcx	; store the new next for this bin into the head of the freelist
	mov	[rax], r8
if heap_barriers
	cmp	qword [rax+8], 0x46004600
	jne	.barrierfail
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8
end if
	epilog			; all good

	; rdi == count
	; rsi == x
	; rax == y
	; rcx == z
calign
.newbin:

if heapdebug
	push	rdi rsi rax rcx r8 rdx
	mov	rdi, .debug4
	mov	esi, .debug4len
	mov	rdx, rcx
	call	debug_heap
	pop	rdx r8 rcx rax rsi rdi
end if
	; rdi == our aligned upward to whatever boundary SIZE of our get
	; rsi == that >> 3 + heap_base
	; qword [rsi] == 0, hence no freelist for this bin.
	; no freelist for this bin exists, do a heap expand (mremap) for 64 items worth
	; then prelink them into the freelist, and copy the return code
	push	rcx		; save our bincount
	mov	rdx, rdi
	shl	rdi, cl		; * whatever was set above depending on how big the block is
	; count now contains the size of our heap expansion
	add	rdi, [_heap_base_size]
	; save rdi, rsi, rcx
	push	rdi
	push	rsi
	push	rdx
	mov	eax, syscall_mremap
	mov	rdx, rdi	; new size
	mov	rdi, [_heap_base]
	mov	rsi, [_heap_base_size]
	xor	r10d, r10d
	syscall
	cmp	rax, -1
	je	.die
	mov	[_heap_base], rax
	add	rax, [_heap_base_size]
	pop	rcx
	pop	rsi
	pop	rdi
	mov	[_heap_base_size], rdi
	mov	rdi, rcx
	; so at this point, rsi is still our freelist offset
	; rdi is still our alloc size
	; rax == end of the previous block (start of our newly acquired block)
	;
	; ok so rsi is still our freelist head offset
	; rax == pointer into heap_base + old heap base size (which is the offset to our new block)
	; rdi == actual item size, which is our individual increase size
	;
	pop	rcx
	mov	r8d, 1
	shl	r8d, cl
	sub	r8d, 1		; how many items - 1
calign
.newloop:
	mov	rcx, [rsi]		; get the pointer that _was_ at freelist head
	mov	[rax], rcx		; store that into the first 8 bytes of our new alloc seg
if heap_barriers
	mov	qword [rax+8], 0x46004600	; make sure our barrier is set to free
end if
	mov	[rsi], rax		; store our new alloc seg into the freelist head
	add	rax, rdi		; move forward by our alloc size
	sub	r8d, 1			; dec loop
	jnz	.newloop

	; now, rax is sitting on the LAST item, instead of linking it to the list, we will return it
	sub	rsi, [_heap_base]
	mov	[rax], rsi		; store the real offset to our freelist into the first 8 bytes of our alloc seg
if heap_barriers
	mov	qword [rax+8], 0x46464646
	add	rax, 16
else
	add	rax, 8			; add 8 to skip said prefix
end if
	epilog

if heap_barriers
.barrierfail:
	breakpoint
end if

calign
.die:
	mov	eax, syscall_exit
	mov	edi, 99
	syscall
end if

if used heap$alloc_clear | defined include_everything
	; single argument in rdi == size of pointer we are allocating
	; NOTE: we memset rounded up to nearest 8 of size before returning the pointer
falign
heap$alloc_clear:
	prolog	heap$alloc_clear
	push	rdi
	call	heap$alloc
	mov	rdi, rax
	mov	rdx, [rsp]
	mov	[rsp], rax
	xor	esi, esi
	add	rdx, 7
	and	rdx, not 7
	call	memset32		; avoids the imul
	pop	rax
	epilog

end if

if used heap$alloc_blockcopy | defined include_everything
	; two arguments: rdi == buffer to copy, rsi == length of same
falign
heap$alloc_blockcopy:
	prolog	heap$alloc_blockcopy
	push	rdi rsi
	mov	rdi, rsi
	call	heap$alloc
	pop	rdx rsi
	push	rax
	mov	rdi, rax
	call	memcpy
	pop	rax
	epilog

end if

if used heap$alloc_random | defined include_everything
	; single argument in rdi == size of pointer we are allocating
	; NOTE: we rng$block rounded up to nearest 8 of size before returning the pointer
falign
heap$alloc_random:
	prolog	heap$alloc_random
	push	rdi
	call	heap$alloc
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	[rsp], rax
	add	rsi, 7
	and	rsi, not 7
	call	rng$block
	pop	rax
	epilog
end if


if used heap$free | defined include_everything
	; single argument in rdi == pointer we are freeing
falign
heap$free:
	prolog	heap$free
if heap_barriers
	cmp	qword [rdi-8], 0x46464646
	jne	.barrierfail
	mov	rsi, [rdi-16]
else
	mov	rsi, [rdi-8]
end if

if heap_bincheck
	cmp	rsi, 8
	jb	.binfail
end if

if heapdebug
	push	rdi rsi
	mov	rdi, .debug3
	mov	esi, .debug3len
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+8]
	call	debug_heap

	mov	rdx, [rsp]
	test	rdx, rdx
	mov	rdi, .debug1
	mov	esi, .debug1len
	call	debug_heap
	pop	rsi rdi
end if
	mov	rdx, [_heap_base]
	cmp	rsi, 1048576
	jg	.largeput
if heap_bincheck
	cmp	rsi, 139272
	ja	.binfail
end if
if heap_barriers
	mov	qword [rdi-8], 0x46004600
	sub	rdi, 16
else
	sub	rdi, 8
end if
	mov	rax, [rdx+rsi]	; get whatever value is currently in our heap of the freelist head
	mov	[rsi+rdx], rdi	; put our pointer into the freelist head position
	mov	[rdi], rax	; put the old freelist head into our item

if heapdebug
	mov	rdi, .debug4
	mov	esi, .debug4len
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+8]
	call	debug_heap

	call	debug_firstbin
end if

	epilog
if heapdebug
dalign
.debug1 db 'HEAP$FREE FOR BIN: '
.debug1len = $ - .debug1
.debug3 db '-------- heap_base[8] is: '
.debug3len = $ - .debug3
.debug4 db '         heap_base[8] now: '
.debug4len = $ - .debug4
end if
calign
.largeput:
if heap_barriers
	sub	rdi, 16
else
	sub	rdi, 8
end if
	mov	eax, syscall_munmap
	; rdi is our pointer
	; rsi is already the size
	syscall
	epilog
if heap_barriers
.barrierfail:
	breakpoint
end if
if heap_bincheck
.binfail:
	breakpoint
end if



end if

if used heap$free_clear | defined include_everything
	; single argument in rdi == pointer we are freeing
	; NOTE: we memset 0 the space prior to calling the real free
falign
heap$free_clear:
	prolog	heap$free_clear
if heap_barriers
	cmp	qword [rdi-8], 0x46464646
	jne	.barrierfail
	mov	rsi, [rdi-16]
else
	mov	rsi, [rdi-8]
end if
if heap_bincheck
	cmp	rsi, 8
	jb	.binfail
end if
if heapdebug
	push	rdi rsi
	mov	rdi, .debug3
	mov	esi, .debug3len
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+8]
	call	debug_heap

	mov	rdx, [rsp]
	mov	rdi, .debug1
	mov	esi, .debug1len
	call	debug_heap
	pop	rsi rdi
end if

	mov	rdx, [_heap_base]
	cmp	rsi, 1048576
	jg	.largeput
if heap_bincheck
	cmp	rsi, 139272
	ja	.binfail
end if
	; we have to infer the size of our pointer so we can clear it before we put it back

if heap_bincheck
	mov	rdx, rsi
	shl	rdx, 3
	sub	rdx, 8
	mov	ecx, 72
	cmp	esi, 139272
	cmove	rdx, rcx
else
	mov	ecx, 72
	mov	rdx, rsi
	shl	rdx, 3
	sub	rdx, 8
	test	rsi, rsi
	cmovz	rdx, rcx
end if
	push	rdi rsi
	xor	esi, esi
	call	memset32
	pop	rsi rdi
	mov	rdx, [_heap_base]
if heap_barriers
	mov	qword [rdi-8], 0x46004600
	sub	rdi, 16
else
	sub	rdi, 8
end if
	mov	rax, [rdx+rsi]
	mov	[rsi+rdx], rdi
	mov	[rdi], rax
if heapdebug
	mov	rdi, .debug4
	mov	esi, .debug4len
	mov	rcx, [_heap_base]
	mov	rdx, [rcx+8]
	call	debug_heap

	call	debug_firstbin
end if

	epilog
if heapdebug
dalign
.debug1 db 'HEAP$FREE_CLEAR FOR BIN: '
.debug1len = $ - .debug1
.debug3 db '-------- heap_base[8] is: '
.debug3len = $ - .debug3
.debug4 db '         heap_base[8] now: '
.debug4len = $ - .debug4
end if
calign
.largeput:
if heap_barriers
	sub	rdi, 16
else
	sub	rdi, 8
end if
	push	rdi rsi
	mov	rdx, rsi
	xor	esi, esi
	call	memset32		; note: our size may not be exact, but mmap won't give us a partial word return
	pop	rsi rdi
	mov	eax, syscall_munmap
	syscall
	epilog
if heap_barriers
.barrierfail:
	breakpoint
end if
if heap_bincheck
.binfail:
	breakpoint
end if



end if


if used heap$free_random | defined include_everything
	; single argument in rdi == pointer we are freeing
	; NOTE: we put random bytes from rng$u64 into the space prior to calling the real free
	; this is _expensive_, hahaha, but useful in rare cases
falign
heap$free_random:
	prolog	heap$free_random
if heap_barriers
	cmp	qword [rdi-8], 0x46464646
	jne	.barrierfail
	mov	rsi, [rdi-16]
else
	mov	rsi, [rdi-8]
end if
if heap_bincheck
	cmp	rsi, 8
	jb	.binfail
end if
	mov	rdx, [_heap_base]
	cmp	rsi, 1048576
	jg	.largeput
if heap_bincheck
	cmp	rsi, 139272
	ja	.binfail
end if
	; we have to infer the size of our pointer so we can clear it before we put it back
if heap_bincheck
	mov	rdx, rsi
	shl	rdx, 3
	sub	rdx, 8
	mov	ecx, 72
	cmp	esi, 139272
	cmove	rdx, rcx
else
	mov	ecx, 72
	mov	rdx, rsi
	shl	rdx, 3
	sub	rdx, 8
	test	rsi, rsi
	cmovz	rdx, rcx
end if
	push	rdi rsi
	mov	rsi, rdx
	call	rng$block
	pop	rsi rdi
	mov	rdx, [_heap_base]
if heap_barriers
	mov	qword [rdi-8], 0x46004600
	sub	rdi, 16
else
	sub	rdi, 8
end if
	mov	rax, [rdx+rsi]
	mov	[rsi+rdx], rdi
	mov	[rdi], rax
	epilog
calign
.largeput:
if heap_barriers
	sub	rdi, 16
else
	sub	rdi, 8
end if
	push	rdi rsi
	call	rng$block
	pop	rsi rdi
	mov	eax, syscall_munmap
	syscall
	epilog
if heap_barriers
.barrierfail:
	breakpoint
end if
if heap_bincheck
.binfail:
	breakpoint
end if


end if
