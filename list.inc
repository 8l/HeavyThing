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
	; list.inc: basic list goodies
	; 
	; linked list only, no indexed array goods or associative keys or anything in here.
	; but we provide convenience functions for push_front/pop_front/etc in addition to the
	; normal boring stuff.
	;

	; we put the size first so external use doesn't have to call any functions here to determine it
virtual at rdi
	_list_size	dq	?
	_list_first	dq	?
	_list_last	dq	?
end virtual

_list_size_ofs = 0
_list_first_ofs = 8
_list_last_ofs = 16


; the list item itself (24 bytes of course), value listed first
_list_valueofs = 0
_list_nextofs = 8
_list_prevofs = 16

if used list$new | defined include_everything

	; no params, just allocates and initializes the basic list structure, return in rax
falign
list$new:
	prolog	list$new
	mov	edi, 24
	call	heap$alloc
	xor	esi, esi
	mov	[rax], rsi
	mov	[rax+8], rsi
	mov	[rax+16], rsi
	epilog
end if


if used list$destroy | defined include_everything
	; single arg: rdi == list pointer
	; NOTE: we do not iterate and destroy the list, all we do is call heap$free with it
	; to really get rid of your list, use list$clear first, then heap$free the list pointer
falign
list$destroy:
	prolog	list$destroy
	call	heap$free
	epilog
end if

if used list$front | defined include_everything
	; single arg: rdi == list, returns _list_first pointer (the item itself, not its value)
	; because this is just pulling [_list_first] from rdi, do not call this directly, just do it yourself
falign
list$front:
	prolog	list$front
	mov	rax, [_list_first]
	epilog
end if

if used list$back | defined include_everything
	; single arg: rdi == list, returns _list_last pointer (the item itself, not its value)
	; because this is just pulling [_list_last] from rdi, do not call this directly, just do it yourself
falign
list$back:
	prolog	list$back
	mov	rax, [_list_last]
	epilog
end if


if used list$size | defined include_everything
	; single arg: rdi == list, returns _list_size... because this is just returning qword [rdi], silly to call
	; provided like the above two functions as reference only:
falign
list$size:
	prolog	list$size
	mov	rax, [_list_size]
	epilog
end if


if used list$next | defined include_everything
	; single arg: rdi == list ITEM, returns its next, again as reference only
falign
list$next:
	prolog	list$next
	mov	rax, [rdi+_list_nextofs]
	epilog
end if

if used list$prev | defined include_everything
	; single arg: rdi == list ITEM, returns its prev, again as reference only
falign
list$prev:
	prolog	list$prev
	mov	rax, [rdi+_list_prevofs]
	epilog
end if


if used list$push_front | defined include_everything
	; two args: rdi == list, rsi == value to add, returns list item in rax
falign
list$push_front:
	prolog	list$push_front
	push	rdi rsi
	mov	edi, 24
	call	heap$alloc
	xor	edx, edx
	pop	rsi rdi
	mov	rcx, [_list_first]
	add	qword [_list_size], 1
	mov	[rax+_list_valueofs], rsi
	mov	[rax+_list_nextofs], rcx
	mov	[rax+_list_prevofs], rdx
	test	rcx, rcx
	jz	.emptylist
	mov	[rcx+_list_prevofs], rax
	mov	[_list_first], rax
	epilog
calign
.emptylist:
	mov	[_list_first], rax
	mov	[_list_last], rax
	epilog
end if


if used list$push_back | defined include_everything
	; two args: rdi == list, rsi == value to add, returns list item in rax
falign
list$push_back:
	prolog	list$push_back
	push	rdi rsi
	mov	edi, 24
	call	heap$alloc
	xor	edx, edx
	pop	rsi rdi
	mov	rcx, [_list_last]
	add	qword [_list_size], 1
	mov	[rax+_list_valueofs], rsi
	mov	[rax+_list_nextofs], rdx
	mov	[rax+_list_prevofs], rcx
	test	rcx, rcx
	jz	.emptylist
	mov	[rcx+_list_nextofs], rax
	mov	[_list_last], rax
	epilog
calign
.emptylist:
	mov	[_list_first], rax
	mov	[_list_last], rax
	epilog
end if


if used list$insert_before | defined include_everything
	; three args: rdi == list, rsi == reference list item, rdx == value to add, returns new list item in rax
falign
list$insert_before:
	prolog	list$insert_before
	push	rdi rsi rdx
	mov	edi, 24
	call	heap$alloc
	pop	rdx rsi rdi
	mov	rcx, [rsi+_list_prevofs]		; reference item's prev
	mov	r8, [_list_first]			; list first
	add	qword [_list_size], 1
	mov	[rax+_list_valueofs], rdx		; set value
	mov	[rax+_list_nextofs], rsi		; newone's next == reference item
	mov	[rax+_list_prevofs], rcx		; newone's prev == reference item's prev
	mov	[rsi+_list_prevofs], rax		; reference item's prev == new one
	cmp	rsi, r8
	je	.insert_first
	; else, rsi was not the first in the list, normal insert
	mov	[rcx+_list_nextofs], rax		; reference item's prev's next == newone
	epilog
calign
.insert_first:
	mov	[_list_first], rax
	epilog
end if


if used list$insert_after | defined include_everything
	; three args: rdi == list, rsi == reference list item, rdx == value to add, returns new list item in rax
falign
list$insert_after:
	prolog	list$insert_after
	push	rdi rsi rdx
	mov	edi, 24
	call	heap$alloc
	pop	rdx rsi rdi
	mov	rcx, [rsi+_list_nextofs]
	mov	r8, [_list_last]
	add	qword [_list_size], 1
	mov	[rax+_list_valueofs], rdx
	mov	[rax+_list_nextofs], rcx
	mov	[rax+_list_prevofs], rsi
	mov	[rsi+_list_nextofs], rax
	cmp	rsi, r8
	je	.insert_last
	mov	[rcx+_list_prevofs], rax
	epilog
calign
.insert_last:
	mov	[_list_last], rax
	epilog
end if


if used list$pop_front | defined include_everything
	; single arg: rdi == list
	; returns list VALUE, not item (we heap$free the item)
	; if the list is empty, result is undefined.
falign
list$pop_front:
	prolog	list$pop_front
	mov	rsi, [_list_first]
	test	rsi, rsi
	jz	.do_ret
	sub	qword [_list_size], 1
	mov	rax, [rsi+_list_valueofs]
	mov	rcx, [rsi+_list_nextofs]
	mov	[_list_first], rcx
	test	rcx, rcx
	jz	.nowempty
	mov	qword [rcx+_list_prevofs], 0
	; rsi is now unlinked, and our return is in rax, but we need to free rsi first
	push	rax
	mov	rdi, rsi
	call	heap$free
	pop	rax
	epilog
calign
.nowempty:
	mov	[_list_last], rcx
	; rsi is now unlinked, and our return is in rax, but we need to free rsi first
	push	rax
	mov	rdi, rsi
	call	heap$free
	pop	rax
	epilog
calign
.do_ret:
	epilog
end if


if used list$pop_back | defined include_everything
	; single arg: rdi == list
	; returns list VALUE, not item (we heap$free the item)
	; if the list is empty, result is undefined.
falign
list$pop_back:
	prolog	list$pop_back
	mov	rsi, [_list_last]
	test	rsi, rsi
	jz	.do_ret
	sub	qword [_list_size], 1
	mov	rax, [rsi+_list_valueofs]
	mov	rcx, [rsi+_list_prevofs]
	mov	[_list_last], rcx
	test	rcx, rcx
	jz	.nowempty
	mov	qword [rcx+_list_nextofs], 0
	; rsi is now unlinked, and our return is in rax, but we need to free rsi first
	push	rax
	mov	rdi, rsi
	call	heap$free
	pop	rax
	epilog
calign
.nowempty:
	mov	[_list_first], rcx
	; rsi is now unlinked, and our return is in rax, but we need to free rsi first
	push	rax
	mov	rdi, rsi
	call	heap$free
	pop	rax
	epilog
calign
.do_ret:
	epilog
end if


if used list$remove | defined include_everything
	; two args: rdi == list, rsi == ITEM to remove
	; no return... we will free the item block (we dont touch the value)
falign
list$remove:
	prolog	list$remove
	sub	qword [_list_size], 1
	cmp	rsi, [_list_first]
	je	.isfirst
	cmp	rsi, [_list_last]
	je	.lastnotfirst
	; else, not first and not last
	mov	rdx, [rsi+_list_nextofs]
	mov	rcx, [rsi+_list_prevofs]
	mov	[rcx+_list_nextofs], rdx
	mov	[rdx+_list_prevofs], rcx
	mov	rdi, rsi
	call	heap$free
	epilog
calign
.isfirst:
	cmp	rsi, [_list_last]
	je	.firstandlast
	; else, first but not last
	mov	rdx, [rsi+_list_nextofs]
	mov	qword [rdx+_list_prevofs], 0
	mov	[_list_first], rdx
	mov	rdi, rsi
	call	heap$free
	epilog
calign
.lastnotfirst:
	; last but not first
	mov	rcx, [rsi+_list_prevofs]
	mov	qword [rcx+_list_nextofs], 0
	mov	[_list_last], rcx
	mov	rdi, rsi
	call	heap$free
	epilog
calign
.firstandlast:
	; both first and last
	xor	eax, eax
	mov	[_list_first], rax
	mov	[_list_last], rax
	mov	rdi, rsi
	call	heap$free
	epilog
end if


if used list$to_array | defined include_everything
	; single arg: rdi == list
	; returns a single heap$alloc'd block of adjacent values from our list (iterates the list to place them)
	; if the list is empty, NULL is returned.
falign
list$to_array:
	prolog	list$to_array
	push	rdi
	mov	rdi, [_list_size]
	test	rdi, rdi
	jz	.nullret
	shl	rdi, 3
	call	heap$alloc
	pop	rdi
	; so our block is in rax
	mov	rsi, [_list_first]
	mov	rdi, rax
calign
.iter:
	mov	rdx, [rsi]	; get the value
	mov	[rdi], rdx
	add	rdi, 8
	mov	rsi, [rsi+_list_nextofs]
	test	rsi, rsi
	jnz	.iter
	epilog
calign
.nullret:
	xor	eax, eax
	epilog
end if


if used list$index | defined include_everything
	; two args: rdi == list, rsi == index to list item
	; returns VALUE at specified index or NULL if index runs off the end
	; NOTE: this, as it must, walks the list in order to find it, not more than half
	; (meaning: for large lists, heh, rethink your design if you are inclined to use
	; this function, haha, for small lists, this is a nice convenience function)
falign
list$index:
	prolog	list$index
	test	rsi, rsi
	jz	.firstone
	mov	rdx, [_list_size]
	mov	rcx, rdx
	shr	rdx, 1
	sub	rcx, 1
	cmp	rsi, rcx
	je	.lastone
	cmp	rsi, rdx
	jae	.walkbackward
	; otherwise, walk forward
	mov	rdx, [_list_first]
calign
.forward:
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jz	.nullret
	sub	rsi, 1
	jnz	.forward
	mov	rax, [rdx+_list_valueofs]
	epilog
calign
.walkbackward:
	mov	rdx, [_list_last]
	sub	rcx, rsi
calign
.backward:
	mov	rdx, [rdx+_list_prevofs]
	test	rdx, rdx
	jz	.nullret
	sub	rcx, 1
	jnz	.backward
	mov	rax, [rdx+_list_valueofs]
	epilog
calign
.nullret:
	xor	eax, eax
	epilog
calign
.firstone:
	mov	rdx, [_list_first]
	mov	rax, [rdx+_list_valueofs]
	epilog
calign
.lastone:
	mov	rdx, [_list_last]
	mov	rax, [rdx+_list_valueofs]
	epilog

end if

if used list$index_item | defined include_everything
	; two args: rdi == list, rsi == index to list item
	; returns ITEM at specified index or NULL if index runs off the end
	; NOTE: this, as it must, walks the list in order to find it, not more than half
	; (meaning: for large lists, heh, rethink your design if you are inclined to use
	; this function, haha, for small lists, this is a nice convenience function)
falign
list$index_item:
	prolog	list$index_item
	test	rsi, rsi
	jz	.firstone
	mov	rdx, [_list_size]
	mov	rcx, rdx
	shr	rdx, 1
	sub	rcx, 1
	cmp	rsi, rcx
	je	.lastone
	cmp	rsi, rdx
	jae	.walkbackward
	; otherwise, walk forward
	mov	rax, [_list_first]
calign
.forward:
	mov	rax, [rax+_list_nextofs]
	test	rax, rax
	jz	.nullret
	sub	rsi, 1
	jnz	.forward
	epilog
calign
.walkbackward:
	mov	rax, [_list_last]
	sub	rcx, rsi
calign
.backward:
	mov	rax, [rax+_list_prevofs]
	test	rax, rax
	jz	.nullret
	sub	rcx, 1
	jnz	.backward
	epilog
calign
.nullret:
	epilog
calign
.firstone:
	mov	rax, [_list_first]
	epilog
calign
.lastone:
	mov	rax, [_list_last]
	epilog

end if




if used list$foreach | defined include_everything
	; two args: rdi == list, rsi == function to call with single arg in rdi of the VALUE (not the list items themselves)
	; if the list is empty, nothing much happens
falign
list$foreach:
	prolog	list$foreach
	push	rbx r12
	mov	rbx, [_list_first]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
calign
.iter:
	mov	rdi, [rbx]
	call	r12
	mov	rbx, [rbx+_list_nextofs]
	test	rbx, rbx
	jnz	.iter
	pop	r12 rbx
	epilog
calign
.alldone:
	pop	r12 rbx
	epilog
end if

if used list$foreach_limit | defined include_everything
	; same as foreach, but takes a count/limit in rdx
	; passing 0 in rdx is silly and will result in the whole list being traversed
falign
list$foreach_limit:
	prolog	list$foreach_limit
	push	rbx r12 r13
	mov	rbx, [_list_first]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
	mov	r13, rdx
calign
.iter:
	mov	rdi, [rbx]
	call	r12
	mov	rbx, [rbx+_list_nextofs]
	sub	r13, 1
	jz	.alldone
	test	rbx, rbx
	jnz	.iter
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	pop	r13 r12 rbx
	epilog
end if


if used list$foreach_arg | defined include_everything
	; three args: rdi == list, rsi == function to call with single arg in rdi of the VALUE (not the list items themselves)
	; 			and rdx == arbitrary argument that will get passed in rsi to the function
	; if the list is empty, nothing much happens
falign
list$foreach_arg:
	prolog	list$foreach_arg
	push	rbx r12 r13
	mov	rbx, [_list_first]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
	mov	r13, rdx
calign
.iter:
	mov	rdi, [rbx]
	mov	rsi, r13
	mov	rbx, [rbx+_list_nextofs]
	call	r12
	test	rbx, rbx
	jnz	.iter
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	pop	r13 r12 rbx
	epilog
end if


if used list$foreach_items | defined include_everything
	; two args: rdi == list, rsi == function to call with single arg in rdi of the ITEM (not the value like above)
falign
list$foreach_items:
	prolog	list$foreach_items
	push	rbx r12
	mov	rbx, [_list_first]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
calign
.iter:
	mov	rdi, rbx
	call	r12
	mov	rbx, [rbx+_list_nextofs]
	test	rbx, rbx
	jnz	.iter
	pop	r12 rbx
	epilog
calign
.alldone:
	pop	r12 rbx
	epilog
end if


if used list$reverse_foreach | defined include_everything
	; same as foreach but goes backward through the list
falign
list$reverse_foreach:
	prolog	list$reverse_foreach
	push	rbx r12
	mov	rbx, [_list_last]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
calign
.iter:
	mov	rdi, [rbx]
	call	r12
	mov	rbx, [rbx+_list_prevofs]
	test	rbx, rbx
	jnz	.iter
	pop	r12 rbx
	epilog
calign
.alldone:
	pop	r12 rbx
	epilog
end if


if used list$reverse_foreach_arg | defined include_everything
	; same as foreach_arg but goes backward through the list
falign
list$reverse_foreach_arg:
	prolog	list$reverse_foreach_arg
	push	rbx r12 r13
	mov	rbx, [_list_last]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
	mov	r13, rdx
calign
.iter:
	mov	rdi, [rbx]
	mov	rsi, r13
	mov	rbx, [rbx+_list_prevofs]
	call	r12
	test	rbx, rbx
	jnz	.iter
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	pop	r13 r12 rbx
	epilog
end if


if used list$reverse_foreach_limit | defined include_everything
	; same as reverse_foreach, but takes a limit argument in rdx (will do at most this number, then stop)
	; passing 0 as a limit is silly and ignored (and will then iterate the entire list)
falign
list$reverse_foreach_limit:
	prolog	list$reverse_foreach_limit
	push	rbx r12 r13
	mov	rbx, [_list_last]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
	mov	r13, rdx
calign
.iter:
	mov	rdi, [rbx]
	call	r12
	mov	rbx, [rbx+_list_prevofs]
	sub	r13, 1
	jz	.alldone
	test	rbx, rbx
	jnz	.iter
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	pop	r13 r12 rbx
	epilog
end if
	

if used list$reverse_foreach_items | defined include_everything
	; same as foreach_items but goes backward through the list
falign
list$reverse_foreach_items:
	prolog	list$reverse_foreach_items
	push	rbx r12
	mov	rbx, [_list_last]
	test	rbx, rbx
	jz	.alldone
	mov	r12, rsi
calign
.iter:
	mov	rdi, rbx
	call	r12
	mov	rbx, [rbx+_list_prevofs]
	test	rbx, rbx
	jnz	.iter
	pop	r12 rbx
	epilog
calign
.alldone:
	pop	r12 rbx
	epilog
end if


if used list$clear | defined include_everything
	; two arguments: list in rdi, function to call for each item in rsi
	; EMPTIES the list, but calls the rprovided clear function for each item while its at it
	; useful for eliminating a list of allocated objects, etc.
	; cuz you can call this one with heap$free as its clearfunc
	; if you pass 0 in for the function to call for each item, we'll happily skip that bit and just remove all the list items
	; (which is useful if your list contents are not allocated)
falign
list$clear:
	prolog	list$clear
	cmp	qword [_list_first], 0
	je	.alldone
	test	rsi, rsi
	jz	.nofunc
	push	rbx r12
	mov	rbx, rdi	; save our list itself
	mov	r12, rsi	; save our clearfunc
calign
.iter:
	call	list$pop_front
	mov	rdi, rax	; its value
	call	r12
	mov	rdi, rbx
	cmp	qword [_list_first], 0
	jne	.iter
	pop	r12 rbx
	epilog
calign
.alldone:
	epilog
calign
.nofunc:
	push	rbx
	mov	rbx, rdi	; save our list itself
calign
.iter2:
	call	list$pop_front
	mov	rdi, rbx
	cmp	qword [_list_first], 0
	jne	.iter2
	pop	rbx
	epilog
end if

if used list$clear_arg | defined include_everything
	; three arguments: list in rdi, function to call for each item in rsi, arg to pass in rdx
	; same as list$clear, only that we pass an argument in rsi to the function
falign
list$clear_arg:
	prolog	list$clear_arg
	cmp	qword [_list_first], 0
	je	.alldone
	test	rsi, rsi
	jz	.nofunc
	push	rbx r12 r13
	mov	rbx, rdi	; save our list itself
	mov	r12, rsi	; save our clearfunc
	mov	r13, rdx	; save our argument
calign
.iter:
	call	list$pop_front
	mov	rdi, rax	; its value
	mov	rsi, r13
	call	r12
	mov	rdi, rbx
	cmp	qword [_list_first], 0
	jne	.iter
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	epilog
calign
.nofunc:
	push	rbx
	mov	rbx, rdi	; save our list itself
calign
.iter2:
	call	list$pop_front
	mov	rdi, rbx
	cmp	qword [_list_first], 0
	jne	.iter2
	pop	rbx
	epilog

end if

if used list$shuffle | defined include_everything
	; single argument in rdi: list to shuffle
	; this is by no means efficient, as we turn it into an array first, then scramble the array
	; and then put them back in-place
falign
list$shuffle:
	prolog	list$shuffle
	cmp	qword [_list_first], 0
	je	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, [_list_size]
	call	list$to_array
	mov	r13, rax
	mov	r14, rax
	xor	r15d, r15d
calign
.loop:
	xor	edi, edi
	mov	esi, r12d
	sub	esi, r15d
	sub	esi, 1
	call	rng$int			; rng$int uses 32bit values, so our list size can't be totally crazy

	add	eax, r15d
	mov	rcx, [r13+rax*8]
	mov	rdx, [r13+r15*8]
	mov	[r13+rax*8], rdx
	mov	[r13+r15*8], rcx
	add	r15d, 1
	cmp	r15d, r12d
	jb	.loop
	; put them back
	mov	r14, [rbx+_list_first_ofs]
	mov	r15, r13
calign
.place:
	mov	rax, [r15]
	mov	[r14+_list_valueofs], rax
	add	r15, 8
	mov	r14, [r14+_list_nextofs]
	sub	r12d, 1
	jnz	.place
	; cleanup our mess
	mov	rdi, r13
	call	heap$free
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.nothingtodo:
	epilog

end if
