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
	; maps.inc: avl tree for int,unsigned,double,string
	; no user-supplied comparator on purpose; the internals of this are messy
	;

	; for common-to-all-variants functions, we simply add the other symbols
	; due to the way we declare public symbols though, it doesn't actually
	; make a dirtier symbol table...
	
	; probably should make a cleaner/better way to do this


avlnode_size = 68

_avlofs_parent = 0
_avlofs_key = 8
_avlofs_left = 16
_avlofs_right = 24
_avlofs_trunk = 32
_avlofs_next = 40
_avlofs_prev = 48
_avlofs_value = 56
_avlofs_flags = 64		; dd


	profile_map_internals = 0


if used intmap$new | used unsignedmap$new | used doublemap$new | used stringmap$new | defined include_everything
	; single argument: bool in edi for insert_order (!edi == sort order)
	; NOTE: insert_order causes lower_bound/upper_bound/equal_range obviously to be jacked up
falign
mapcommon$new:
if used intmap$new | defined include_everything
intmap$new:
end if
if used unsignedmap$new | defined include_everything
unsignedmap$new:
end if
if used doublemap$new | defined include_everything
doublemap$new:
end if
if used stringmap$new | defined include_everything
stringmap$new:
end if
	prolog	mapcommon$new
	push	rdi
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdi
	xor	edx, edx
	mov	qword [rax+_avlofs_parent], rdx		; root node
	mov	qword [rax+_avlofs_left], rdx
	mov	qword [rax+_avlofs_right], rdx		; node count
	mov	qword [rax+_avlofs_next], rdx		; first
	mov	qword [rax+_avlofs_prev], rdx		; last
	mov	qword [rax+_avlofs_trunk], rdx
	mov	qword [rax+_avlofs_key], rdx
	mov	qword [rax+_avlofs_value], rdx
	mov	dword [rax+_avlofs_flags], edi
	epilog
end if

	; single argument: rdi == map
	; NOTE: we do not iterate and destroy the map, all we do is call heap$free wiht it
	; to really get rid of your map, use map$clear first, then heap$free the map pointer
if used intmap$destroy | used unsignedmap$destroy | used doublemap$destroy | used stringmap$destroy | defined include_everything

falign
mapcommon$destroy:
if used intmap$destroy | defined include_everything
intmap$destroy:
end if
if used unsignedmap$destroy | defined include_everything
unsignedmap$destroy:
end if
if used doublemap$destroy | defined include_everything
doublemap$destroy:
end if
if used stringmap$destroy | defined include_everything
stringmap$destroy:
end if
	prolog	mapcommon$destroy
	call	heap$free
	epilog

end if


if used intmap$clear | used unsignedmap$clear | used stringmap$clear | defined include_everything
	; two parameters: rdi == map, rsi == optional function to call (will pass key and value to it)
	; we do _not_ delete keys or values, only the nodes themselves
	; so if you need a cleaner to destroy keys/values, pass a function to do so in rsi
	; NOTE: doublemap is separate because its args to the optional function to call get passed in xmm0,rdi instead of rdi,rsi
falign
map$clear:
if used intmap$clear | defined include_everything
intmap$clear:
end if
if used unsignedmap$clear | defined include_everything
unsignedmap$clear:
end if
if used stringmap$clear | defined include_everything
stringmap$clear:
end if
	prolog	map$clear
	cmp	qword [rdi+_avlofs_next], 0
	je	.alldone
	test	rsi, rsi
	jz	.nofunc
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, [rbx+_avlofs_next]
calign
.iter:
	mov	rdi, [r13+_avlofs_key]
	mov	rsi, [r13+_avlofs_value]
	call	r12
	mov	rdi, r13
	mov	r13, [r13+_avlofs_next]
	call	heap$free
	test	r13, r13
	jnz	.iter
	; so at this point, we freed every node, clear the map structure itself
	xor	edx, edx
	mov	qword [rbx+_avlofs_parent], rdx		; root node
	mov	qword [rbx+_avlofs_right], rdx		; node count
	mov	qword [rbx+_avlofs_next], rdx		; first
	mov	qword [rbx+_avlofs_prev], rdx		; last
	mov	qword [rbx+_avlofs_trunk], rdx
	mov	qword [rbx+_avlofs_key], rdx
	mov	qword [rbx+_avlofs_value], rdx
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	epilog
calign
.nofunc:
	push	rbx r13
	mov	rbx, rdi
	mov	r13, [rbx+_avlofs_next]
calign
.iter2:
	mov	rdi, r13
	mov	r13, [r13+_avlofs_next]
	call	heap$free
	test	r13, r13
	jnz	.iter2
	; so at this point, we freed every node, clear the map structure itself
	xor	edx, edx
	mov	qword [rbx+_avlofs_parent], rdx		; root node
	mov	qword [rbx+_avlofs_right], rdx		; node count
	mov	qword [rbx+_avlofs_next], rdx		; first
	mov	qword [rbx+_avlofs_prev], rdx		; last
	mov	qword [rbx+_avlofs_trunk], rdx
	mov	qword [rbx+_avlofs_key], rdx
	mov	qword [rbx+_avlofs_value], rdx
	pop	r13 rbx
	epilog

end if
	
if used doublemap$clear | defined include_everything
falign
doublemap$clear:
	prolog	doublemap$clear
	cmp	qword [rdi+_avlofs_next], 0
	je	.alldone
	test	rsi, rsi
	jz	.nofunc
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, [rbx+_avlofs_next]
calign
.iter:
	movsd	xmm0, [r13+_avlofs_key]
	mov	rdi, [r13+_avlofs_value]
	call	r12
	mov	rdi, r13
	mov	r13, [r13+_avlofs_next]
	call	heap$free
	test	r13, r13
	jnz	.iter
	; so at this point, we freed every node, clear the map structure itself
	xor	edx, edx
	mov	qword [rbx+_avlofs_parent], rdx		; root node
	mov	qword [rbx+_avlofs_right], rdx		; node count
	mov	qword [rbx+_avlofs_next], rdx		; first
	mov	qword [rbx+_avlofs_prev], rdx		; last
	mov	qword [rbx+_avlofs_trunk], rdx
	mov	qword [rbx+_avlofs_key], rdx
	mov	qword [rbx+_avlofs_value], rdx
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	epilog
calign
.nofunc:
	push	rbx r13
	mov	rbx, rdi
	mov	r13, [rbx+_avlofs_next]
calign
.iter2:
	mov	rdi, r13
	mov	r13, [r13+_avlofs_next]
	call	heap$free
	test	r13, r13
	jnz	.iter2
	; so at this point, we freed every node, clear the map structure itself
	xor	edx, edx
	mov	qword [rbx+_avlofs_parent], rdx		; root node
	mov	qword [rbx+_avlofs_right], rdx		; node count
	mov	qword [rbx+_avlofs_next], rdx		; first
	mov	qword [rbx+_avlofs_prev], rdx		; last
	mov	qword [rbx+_avlofs_trunk], rdx
	mov	qword [rbx+_avlofs_key], rdx
	mov	qword [rbx+_avlofs_value], rdx
	pop	r13 rbx
	epilog
end if
	

if used intmap$find_value | defined include_everything
	; two args: rdi == map, rsi == key
	; returns bool in eax as to whether we found it or not, and value in rdx if so
falign
intmap$find_value:
	prolog	intmap$find_value
	call	_intmap_locate_node
	; normal return from _intmap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	eax, 1
	mov	rdx, [r8+_avlofs_value]
	epilog
end if


if used intmap$find | defined include_everything
	; two args: rdi == map, rsi == key
	; returns NODE in rax (zero if jacked up)
falign
intmap$find:
	prolog	intmap$find
	call	_intmap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	rax, r8
	epilog

end if

if used unsignedmap$find_value | defined include_everything
	; two args: rdi == map, rsi == key
	; returns bool in eax as to whether we found it or not, and value in rdx if so
falign
unsignedmap$find_value:
	prolog	unsignedmap$find_value
	call	_unsignedmap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	eax, 1
	mov	rdx, [r8+_avlofs_value]
	epilog
end if


if used unsignedmap$find | defined include_everything
	; two args: rdi == map, rsi == key
	; returns NODE in rax (zero if jacked up)


if defined unsignedmap_notinline

falign
unsignedmap$find:
	prolog	unsignedmap$find
	call	_unsignedmap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	rax, r8
	epilog

else

falign
unsignedmap$find:
	prolog	unsignedmap$find
	mov	rax, [rdi+_avlofs_parent]	; root node
	test	rax, rax
	jz	.locate_found
if align_inner
	mov	rdx, [rax+_avlofs_key]
	mov	r10, [rax+_avlofs_left]
	mov	r11, [rax+_avlofs_right]
	cmp	rsi, rdx
	je	.locate_found
	cmovb	rax, r10
	cmova	rax, r11
	test	rax, rax
	jnz	.locate_while
	; if we made it here, we didn't find it, and the value in rax is already clear
	epilog
end if
calign
.locate_while:
	mov	rdx, [rax+_avlofs_key]
	mov	r10, [rax+_avlofs_left]
	mov	r11, [rax+_avlofs_right]
	cmp	rsi, rdx
	je	.locate_found
	cmovb	rax, r10
	cmova	rax, r11
	test	rax, rax
	jnz	.locate_while
	; if we made it here, we didn't find it, and the value in rax is already clear
	epilog
calign
.locate_found:
	epilog

end if

end if



if used unsignedmap$lowerbound | defined include_everything
	; two args: rdi == map, rsi == key
	; returns NODE in rax (zero if jacked up)
falign
unsignedmap$lowerbound:
	prolog	unsignedmap$lowerbound
	mov	rdx, [rdi+_avlofs_parent]
	xor	eax, eax
calign
.while:
	test	rdx, rdx
	jz	.do_ret
	mov	rcx, [rdx+_avlofs_key]
	cmp	rcx, rsi
	ja	.leftside
	mov	rdx, [rdx+_avlofs_right]
	jmp	.while
calign
.leftside:
	mov	rax, rdx
	mov	rdx, [rdx+_avlofs_left]
	jmp	.while
calign
.do_ret:
	; whatever is in rax is sweet
	epilog

end if

if used stringmap$find_value | defined include_everything
	; two args: rdi == map, rsi == key
	; returns bool in eax as to whether we found it or not, and value in rdx if so
falign
stringmap$find_value:
	prolog	stringmap$find_value
	call	_stringmap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	eax, 1
	mov	rdx, [r8+_avlofs_value]
	epilog
end if

if used stringmap$find | defined include_everything
	; two args: rdi == map, rsi == key
	; returns NODE in rax (zero if jacked up)
falign
stringmap$find:
	prolog	stringmap$find
	call	_stringmap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	rax, r8
	epilog


end if

if used doublemap$find_value | defined include_everything
	; two args: rdi == map, xmm0 == key
	; returns bool in eax as to whether we found it or not, and value in xmm0 if so
falign
doublemap$find_value:
	prolog	doublemap$find_value
	call	_doublemap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	eax, 1
	movq	xmm0, [r8+_avlofs_value]
	epilog
end if

if used doublemap$find | defined include_everything
	; two args: rdi == map, xmm0 == key
	; returns NODE in rax (zero if jacked up)
falign
doublemap$find:
	prolog	doublemap$find
	call	_doublemap_locate_node
	test	r9d, avl_status_found
	jnz	.found
	xor	eax, eax
	epilog
calign
.found:
	mov	rax, r8
	epilog

end if



if used intmap$foreach | used unsignedmap$foreach | used stringmap$foreach | defined include_everything
	; two args: rdi == map, rsi == function to call with two args, rdi == key, rsi == value
	; if the map is empty, nothing much happens
	; note again, doublemap is separate, cuz of its use of xmm0 as the key argument
falign
map$foreach:
if used intmap$foreach | defined include_everything
intmap$foreach:
end if
if used unsignedmap$foreach | defined include_everything
unsignedmap$foreach:
end if
if used stringmap$foreach | defined include_everything
stringmap$foreach:
end if
	prolog	map$foreach
	cmp	qword [rdi+_avlofs_next], 0
	je	.alldone
	push	r12 r13
	mov	r12, rsi
	mov	r13, [rdi+_avlofs_next]
calign
.iter:
	mov	rdi, [r13+_avlofs_key]
	mov	rsi, [r13+_avlofs_value]
	call	r12
	mov	r13, [r13+_avlofs_next]
	test	r13, r13
	jnz	.iter
	pop	r13 r12
	epilog
calign
.alldone:
	epilog
end if


if used intmap$foreach_arg | used unsignedmap$foreach_arg | used stringmap$foreach_arg | defined include_everything
	; three args: rdi == map, rsi == function to call with THREE args, rdx is arbitary arg... called func gets: rdi == key, rsi == value, rdx == arbitrary arg
falign
map$foreach_arg:
if used intmap$foreach_arg | defined include_everything
intmap$foreach_arg:
end if
if used unsignedmap$foreach_arg | defined include_everything
unsignedmap$foreach_arg:
end if
if used stringmap$foreach_arg | defined include_everything
stringmap$foreach_arg:
end if
	prolog	map$foreach_arg
	cmp	qword [rdi+_avlofs_next], 0
	je	.alldone
	push	rbx r12 r13
	mov	rbx, rdx		; save our arbitrary argument
	mov	r12, rsi
	mov	r13, [rdi+_avlofs_next]
calign
.iter:
	mov	rdi, [r13+_avlofs_key]
	mov	rsi, [r13+_avlofs_value]
	mov	rdx, rbx
	call	r12
	mov	r13, [r13+_avlofs_next]
	test	r13, r13
	jnz	.iter
	pop	r13 r12 rbx
	epilog
calign
.alldone:
	epilog
end if

if used doublemap$foreach | defined include_everything
falign
doublemap$foreach:
	prolog	doublemap$foreach
	cmp	qword [rdi+_avlofs_next], 0
	je	.alldone
	push	r12 r13
	mov	r12, rsi
	mov	r13, [rdi+_avlofs_next]
calign
.iter:
	movsd	xmm0, [r13+_avlofs_key]
	mov	rdi, [r13+_avlofs_value]
	call	r12
	mov	r13, [r13+_avlofs_next]
	test	r13, r13
	jnz	.iter
	pop	r13 r12
	epilog
calign
.alldone:
	epilog
end if


if used intmap$reverse_foreach | used unsignedmap$reverse_foreach | used stringmap$reverse_foreach | defined include_everything
	; same as foreach, only we travel the list backward
falign
map$reverse_foreach:
if used intmap$reverse_foreach | defined include_everything
intmap$reverse_foreach:
end if
if used unsignedmap$reverse_foreach | defined include_everything
unsignedmap$reverse_foreach:
end if
if used stringmap$reverse_foreach | defined include_everything
stringmap$reverse_foreach:
end if
	prolog	map$reverse_foreach
	cmp	qword [rdi+_avlofs_prev], 0
	je	.alldone
	push	r12 r13
	mov	r12, rsi
	mov	r13, [rdi+_avlofs_prev]
calign
.iter:
	mov	rdi, [r13+_avlofs_key]
	mov	rsi, [r13+_avlofs_value]
	call	r12
	mov	r13, [r13+_avlofs_prev]
	test	r13, r13
	jnz	.iter
	pop	r13 r12
	epilog
calign
.alldone:
	epilog
end if


if used doublemap$reverse_foreach | defined include_everything
falign
doublemap$reverse_foreach:
	prolog	doublemap$reverse_foreach
	cmp	qword [rdi+_avlofs_prev], 0
	je	.alldone
	push	r12 r13
	mov	r12, rsi
	mov	r13, [rdi+_avlofs_prev]
calign
.iter:
	movsd	xmm0, [r13+_avlofs_key]
	mov	rdi, [r13+_avlofs_value]
	call	r12
	mov	r13, [r13+_avlofs_prev]
	test	r13, r13
	jnz	.iter
	pop	r13 r12
	epilog
calign
.alldone:
	epilog
end if



if used intmap$keys_to_array | used unsignedmap$keys_to_array | used doublemap$keys_to_array | used stringmap$keys_to_array | defined include_everything
	; single arg: rdi == map
	; returns a single heap$alloc'd block of adjacent keys from our map (iterates it to place them)
	; if the map is empty, NULL is returned.
	; (note: we are not type-specified here, just the 8 bytes stored in our key is placed)
	; up to the caller to distinguish what the key might actually be

	; note: this one is the same for all four variants
falign
map$keys_to_array:
if used intmap$keys_to_array | defined include_everything
intmap$keys_to_array:
end if
if used unsignedmap$keys_to_array | defined include_everything
unsignedmap$keys_to_array:
end if
if used doublemap$keys_to_array | defined include_everything
doublemap$keys_to_array:
end if
if used stringmap$keys_to_array | defined include_everything
stringmap$keys_to_array:
end if
	prolog	map$keys_to_array
	cmp	qword [rdi+_avlofs_right], 0	 ; node count
	je	.nullret
	push	rdi
	mov	rdi, qword [rdi+_avlofs_right]	; node count
	shl	rdi, 3				; x 8
	call	heap$alloc
	pop	rdi
	; return now sitting in rax
	mov	rdx, [rdi+_avlofs_next]		; first
	mov	rcx, rax			; our rolling buffer
calign
.iter:
	mov	r8, [rdx+_avlofs_key]
	mov	[rcx], r8
	add	rcx, 8
	mov	rdx, [rdx+_avlofs_next]
	test	rdx, rdx
	jnz	.iter
	epilog
calign
.nullret:
	xor	eax, eax
	epilog
end if


if used intmap$values_to_array | used unsignedmap$values_to_array | used doublemap$values_to_array | used stringmap$values_to_array | defined include_everything
	; single arg: rdi == map
	; returns a single heap$alloc'd block of adjacent values from our map (iterates it to place them)
	; if the map is empty, NULL is returned.
falign
map$values_to_array:
if used intmap$values_to_array | defined include_everything
intmap$values_to_array:
end if
if used unsignedmap$values_to_array | defined include_everything
unsignedmap$values_to_array:
end if
if used doublemap$values_to_array | defined include_everything
doublemap$values_to_array:
end if
if used stringmap$values_to_array | defined include_everything
stringmap$values_to_array:
end if
	prolog	map$values_to_array
	cmp	qword [rdi+_avlofs_right], 0	; node count
	je	.nullret
	push	rdi
	mov	rdi, qword [rdi+_avlofs_right]	; node count
	shl	rdi, 3				; x 8
	call	heap$alloc
	pop	rdi
	; return now sitting in rax
	mov	rdx, [rdi+_avlofs_next]		; first
	mov	rcx, rax			; our rolling buffer
calign
.iter:
	mov	r8, [rdx+_avlofs_value]
	mov	[rcx], r8
	add	rcx, 8
	mov	rdx, [rdx+_avlofs_next]
	test	rdx, rdx
	jnz	.iter
	epilog
calign
.nullret:
	xor	eax, eax
	epilog
end if


if used intmap$keys_to_list | used unsignedmap$keys_to_list | used unsignedmap$keys_to_list | used stringmap$keys_to_list | defined include_everything
	; single arg: rdi == map
	; returns a list$new list of keys from our map (iterates it to list$push_back)
	; if the map is empty, an empty list is returned (still list$new regardless)

	; this one is also the same for all four variants
falign
map$keys_to_list:
if used intmap$keys_to_list | defined include_everything
intmap$keys_to_list:
end if
if used unsignedmap$keys_to_list | defined include_everything
unsignedmap$keys_to_list:
end if
if used doublemap$keys_to_list | defined include_everything
doublemap$keys_to_list:
end if
if used stringmap$keys_to_list | defined include_everything
stringmap$keys_to_list:
end if
	prolog	map$keys_to_list
	push	rdi
	call	list$new
	pop	rdi
	cmp	qword [rdi+_avlofs_right], 0	; node count
	je	.alldone
	push	rbx r12
	mov	rbx, rax			; save our list
	mov	r12, [rdi+_avlofs_next]		; first
calign
.iter:
	mov	rdi, rbx
	mov	rsi, [r12+_avlofs_key]
	call	list$push_back
	mov	r12, [r12+_avlofs_next]
	test	r12, r12
	jnz	.iter
	mov	rax, rbx
	pop	r12 rbx
	epilog
calign
.alldone:
	; list$new is sitting in rax already, outta here
	epilog
end if


if used intmap$values_to_list | used unsignedmap$values_to_list | used doublemap$values_to_list | used stringmap$values_to_list | defined include_everything
	; single arg: rdi == map
	; returns a list$new list of values from our map (iterates it to list$push_back)
	; if the map is empty, an empty list is returned (still list$new regardless)
	; this one is also the same for all four variants
falign
map$values_to_list:
if used intmap$values_to_list | defined include_everything
intmap$values_to_list:
end if
if used unsignedmap$values_to_list | defined include_everything
unsignedmap$values_to_list:
end if
if used doublemap$values_to_list | defined include_everything
doublemap$values_to_list:
end if
if used stringmap$values_to_list | defined include_everything
stringmap$values_to_list:
end if
	prolog	map$values_to_list
	push	rdi
	call	list$new
	pop	rdi
	cmp	qword [rdi+_avlofs_right], 0	; node count
	je	.alldone
	push	rbx r12
	mov	rbx, rax			; save our list
	mov	r12, [rdi+_avlofs_next]		; first
calign
.iter:
	mov	rdi, rbx
	mov	rsi, [r12+_avlofs_value]
	call	list$push_back
	mov	r12, [r12+_avlofs_next]
	test	r12, r12
	jnz	.iter
	mov	rax, rbx
	pop	r12 rbx
	epilog
calign
.alldone:
	; list$new is sitting in rax already, outta here
	epilog

end if

avl_unbalanced = 0x1
avl_unb_left = 0x2
avl_unb_heavy = 0x4
avl_unb_mask = 0x7
avl_left_heavy = 0x7
avl_left_balanced = 0x3
avl_abs_balanced = 0
avl_right_balanced = 0x1
avl_right_heavy = 0x5
avl_trav_left = 0x8
avl_all = 0xf
avl_status_found = 0x4
avl_status_left = 0x8
avl_status_lcop = 0x10


if used _intmap_locate_node | defined include_everything
falign
_intmap_locate_node:
if profile_map_internals
	prolog _intmap_locate_node
else
	prolog_noprofile_silent _intmap_locate_node
end if
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	ecx, ecx
	mov	rax, [rdi+_avlofs_parent]	; start with our root node
calign
.while:
	test	rax, rax
	jz	.done
	mov	r8, rax
	mov	rdx, [rax+_avlofs_key]
	sub	rdx, rsi
	jz	.found
	jl	.follow_right
	bts	r10d, ecx
	add	ecx, 1
	or	r9d, avl_status_left
	mov	rax, [rax+_avlofs_left]
	jmp	.while
calign
.follow_right:
	and	r9d, 0xffff - avl_status_left
	add	ecx, 1
	mov	rax, [rax+_avlofs_right]
	jmp	.while
calign
.found:
	or	r9d, avl_status_found
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.done:
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if

end if

if used _unsignedmap_locate_node | defined include_everything

falign
_unsignedmap_locate_node:
if profile_map_internals
	prolog	_unsignedmap_locate_node
else
	prolog_noprofile_silent _unsignedmap_locate_node
end if

	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	ecx, ecx
	mov	rax, [rdi+_avlofs_parent]	; start with our root node
calign
.while:
	test	rax, rax
	jz	.done
	mov	r8, rax
	cmp	rsi, [rax+_avlofs_key]
	je	.found
	ja	.follow_right
	bts	r10d, ecx
	add	ecx, 1
	or	r9d, avl_status_left
	mov	rax, [rax+_avlofs_left]
	jmp	.while
calign
.follow_right:
	and	r9d, 0xffff - avl_status_left
	add	ecx, 1
	mov	rax, [rax+_avlofs_right]
	jmp	.while
calign
.found:
	or	r9d, avl_status_found
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.done:
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if

end if

if used _unsignedmap_locate_node_specific | defined include_everything
	; rdi == our map, rsi == key, rdx == _value_ (not node, but we'll convert it to the node before we return)
falign
_unsignedmap_locate_node_specific:
if profile_map_internals
	prolog	_unsignedmap_locate_node_specific
else
	prolog_noprofile_silent _unsignedmap_locate_node_specific
end if
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	ecx, ecx
	mov	rax, [rdi+_avlofs_parent]	; start with our root node
calign
.while:
	test	rax, rax
	jz	.done
	mov	r8, rax
	push	rdx
	mov	rdx, [rax+_avlofs_key]
	cmp	rdx, rsi
	je	.found
	jb	.follow_right
	pop	rdx
	bts	r10d, ecx
	add	ecx, 1
	or	r9d, avl_status_left
	mov	rax, [rax+_avlofs_left]
	jmp	.while
calign
.follow_right:
	pop	rdx
	and	r9d, 0xffff - avl_status_left
	add	ecx, 1
	mov	rax, [rax+_avlofs_right]
	jmp	.while
calign
.found:
	pop	rdx
	cmp	[r8+_avlofs_value], rdx
	je	.found_at_top
	cmp	qword [r8+_avlofs_trunk], 0
	je	.done
	; else, we need to loop with _rax_ and not r8 and find our value
calign
.searchtop:
	mov	rax, [rax+_avlofs_trunk]
	test	rax, rax
	jz	.done
	cmp	[rax+_avlofs_value], rdx
	jne	.searchtop
	mov	rdx, rax	; this is the specific node we are deleting
	or	r9d, avl_status_found
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.found_at_top:
	mov	rdx, r8		; this is the specific node we are deleting
	or	r9d, avl_status_found
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.done:
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if

end if

if used _doublemap_locate_node | defined include_everything
falign
_doublemap_locate_node:
if profile_map_internals
	prolog	_doublemap_locate_node
else
	prolog_noprofile_silent _doublemap_locate_node
end if
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	ecx, ecx
	mov	rax, [rdi+_avlofs_parent]	; start with our root node
calign
.while:
	test	rax, rax
	jz	.done
	mov	r8, rax
	movq	xmm1, [rax+_avlofs_key]
	comisd	xmm0, xmm1
	je	.found
	ja	.follow_right
	bts	r10d, ecx
	add	ecx, 1
	or	r9d, avl_status_left
	mov	rax, [rax+_avlofs_left]
	jmp	.while
calign
.follow_right:
	and	r9d, 0xffff - avl_status_left
	add	ecx, 1
	mov	rax, [rax+_avlofs_right]
	jmp	.while
calign
.found:
	or	r9d, avl_status_found
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.done:
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if

if used _stringmap_locate_node | defined include_everything
falign
_stringmap_locate_node:
if profile_map_internals
	prolog	_stringmap_locate_node
else
	prolog_noprofile_silent _stringmap_locate_node
end if
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	ecx, ecx
	mov	rax, [rdi+_avlofs_parent]	; start with our root node
calign
.while:
	test	rax, rax
	jz	.done
	mov	r8, rax
	; we have to preserve nearly all of our regs here... TODO: redo using stackvars?
	push	rdi rsi r8 r9 r10 rcx rax
	mov	rdi, [rax+_avlofs_key]
	call	string$compare
	mov	rdx, rax
	pop	rax rcx r10 r9 r8 rsi rdi
	cmp	rdx, 0
	je	.found
	jl	.follow_right
	bts	r10d, ecx
	add	ecx, 1
	or	r9d, avl_status_left
	mov	rax, [rax+_avlofs_left]
	jmp	.while
calign
.follow_right:
	and	r9d, 0xffff - avl_status_left
	add	ecx, 1
	mov	rax, [rax+_avlofs_right]
	jmp	.while
calign
.found:
	or	r9d, avl_status_found
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.done:
	mov	rax, r8
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if




	
if used _map_successor | defined include_everything
falign
_map_successor:
if profile_map_internals
	prolog	_map_successor
else
	prolog_noprofile_silent _map_successor
end if
	mov	r9, rsi
	mov	rax, [r9+_avlofs_right]
	test	rax, rax
	jz	.exit_ok
	mov	rsi, [rax+_avlofs_left]
	test	rsi, rsi
	jz	.exit_ok
	mov	rax, rsi
	jmp	.follow_left
calign
.follow_left:
	mov	rsi, [rax+_avlofs_left]
	test	rsi, rsi
	jz	.exit_ok
	mov	rax, rsi
	jmp	.follow_left
calign
.exit_ok:
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if


if used _map_left_lighter | defined include_everything
	; rdi: map, rsi: node
	; profiling intentionally disabled here cuz we jump around between them, and is thus encapsed in the calling funcs
falign
_map_left_lighter:
	mov	r11, rsi
	; left_lighter_iteration fallthrough copy to avoid 2 large nops
	mov	esi, [rsi+_avlofs_flags]
	test	esi, avl_unb_mask
	jz	_map_left_lighter_make_rb
	test	esi, avl_unb_left
	jz	_map_left_lighter_make_rh
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	cmp	qword [r11+_avlofs_parent], 0
	je	_map_left_lighter_exit_ok
	; left_lighter_subtree fallthrough copy to avoid nopfill
	mov	rax, r11
	mov	r11, [r11+_avlofs_parent]
	cmp	rax, [r11+_avlofs_left]
	je	_map_left_lighter_iteration
	jmp	_map_right_lighter_iteration
falign
_map_left_lighter_iteration:
	mov	esi, [r11+_avlofs_flags]
	test	esi, avl_unb_mask
	jz	_map_left_lighter_make_rb
	test	esi, avl_unb_left
	jz	_map_left_lighter_make_rh
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	cmp	qword [r11+_avlofs_parent], 0
	je	_map_left_lighter_exit_ok
	; left_lighter_subtree fallthrough copy to avoid nopfill
	mov	rax, r11
	mov	r11, [r11+_avlofs_parent]
	cmp	rax, [r11+_avlofs_left]
	je	_map_left_lighter_iteration
	jmp	_map_right_lighter_iteration
falign
_map_left_lighter_subtree:
	mov	rax, r11
	mov	r11, [r11+_avlofs_parent]
	cmp	rax, [r11+_avlofs_left]
	je	_map_left_lighter_iteration
	jmp	_map_right_lighter_iteration
falign
_map_left_lighter_make_rh:
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [r11+_avlofs_flags], avl_right_heavy
	mov	rax, r11
	push	r11
	mov	rsi, r11
	call	_map_rebalance
	pop	r11
	mov	r11, [r11+_avlofs_parent]
	cmp	r11, [rdi+_avlofs_parent]
	je	_map_left_lighter_exit_ok
	test	dword [r11+_avlofs_flags], avl_unbalanced
	jnz	_map_left_lighter_exit_ok
	jmp	_map_left_lighter_subtree
falign
_map_left_lighter_make_rb:
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [r11+_avlofs_flags], avl_right_balanced
	ret
falign
_map_left_lighter_exit_ok:
	ret
end if


if used _map_right_lighter | defined include_everything
falign
_map_right_lighter:
	mov	r11, rsi
	; map_right_lighter_iteration fallthrough copy to avoid two large nop fills
	mov	esi, [rsi+_avlofs_flags]
	test	esi, avl_unb_mask
	jz	_map_right_lighter_make_lb
	test	esi, avl_unb_left
	jnz	_map_right_lighter_make_lh
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	cmp	qword [r11+_avlofs_parent], 0
	je	_map_right_lighter_exit_ok
	; map_right_lighter_subtree fallthrough copy to avoid nop fills
	mov	rax, r11
	mov	r11, [r11+_avlofs_parent]
	cmp	rax, [r11+_avlofs_left]
	je	_map_left_lighter_iteration
	jmp	_map_right_lighter_iteration
calign
_map_right_lighter_iteration:
	mov	esi, [r11+_avlofs_flags]
	test	esi, avl_unb_mask
	jz	_map_right_lighter_make_lb
	test	esi, avl_unb_left
	jnz	_map_right_lighter_make_lh
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	cmp	qword [r11+_avlofs_parent], 0
	je	_map_right_lighter_exit_ok
	; map_right_lighter_subtree fallthrough copy to avoid nop fills
	mov	rax, r11
	mov	r11, [r11+_avlofs_parent]
	cmp	rax, [r11+_avlofs_left]
	je	_map_left_lighter_iteration
	jmp	_map_right_lighter_iteration
calign
_map_right_lighter_subtree:
	mov	rax, r11
	mov	r11, [r11+_avlofs_parent]
	cmp	rax, [r11+_avlofs_left]
	je	_map_left_lighter_iteration
	jmp	_map_right_lighter_iteration
calign
_map_right_lighter_make_lh:
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [r11+_avlofs_flags], avl_left_heavy
	mov	rax, r11
	push	r11
	mov	rsi, r11
	call	_map_rebalance
	pop	r11
	mov	r11, [r11+_avlofs_parent]
	cmp	r11, [rdi+_avlofs_parent]
	je	_map_right_lighter_exit_ok
	test	dword [r11+_avlofs_flags], avl_unbalanced
	jnz	_map_right_lighter_exit_ok
	jmp	_map_right_lighter_subtree
calign
_map_right_lighter_make_lb:
	and	dword [r11+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [r11+_avlofs_flags], avl_left_balanced
	ret
calign
_map_right_lighter_exit_ok:
	ret
end if


if used _map_rebalance | defined include_everything
	; rdi: map, rsi: node to rebalance, edx: [search]flags
falign
_map_rebalance:
if profile_map_internals
	prolog	_map_rebalance
else
	prolog_noprofile_silent _map_rebalance
end if
	mov	rcx, rsi
	mov	r11, [rsi+_avlofs_parent]
	mov	r8, [rsi+_avlofs_left]
	mov	r10, [rsi+_avlofs_right]
	test	r11, r11
	jz	.parent_ok
	and	edx, 0xffff - avl_status_lcop
	cmp	rcx, [r11+_avlofs_right]
	je	.parent_ok
	or	edx, avl_status_lcop
	; parent_ok fallthrough copy
	test	dword [rcx+_avlofs_flags], avl_unb_left
	jz	.right
	mov	eax, [r8+_avlofs_flags]
	mov	r9, r8
	; mov	r9, [rcx+_avlofs_left]
	test	eax, avl_unbalanced
	; test	dword [r9+_avlofs_flags], avl_unbalanced
	jz	.ll
	test	eax, avl_unb_left
	; test	dword [r9+_avlofs_flags], avl_unb_left
	jz	.lr
	jmp	.ll
calign
.parent_ok:
	test	dword [rcx+_avlofs_flags], avl_unb_left
	jz	.right
	mov	eax, [r8+_avlofs_flags]
	mov	r9, r8
	; mov	r9, [rcx+_avlofs_left]
	test	eax, avl_unbalanced
	; test	dword [r9+_avlofs_flags], avl_unbalanced
	jz	.ll
	test	eax, avl_unb_left
	; test	dword [r9+_avlofs_flags], avl_unb_left
	jz	.lr
	jmp	.ll
calign
.right:
	mov	eax, [r10+_avlofs_flags]
	mov	r9, r10
	; mov	r9, [rcx+_avlofs_right]
	test	eax, avl_unbalanced
	; test	dword [r9+_avlofs_flags], avl_unbalanced
	jz	.rr
	test	eax, avl_unb_left
	; test	dword [r9+_avlofs_flags], avl_unb_left
	jz	.rr
	jmp	.rl
calign
.ll:
	mov	r10, [r9+_avlofs_right]
	test	r11, r11
	jz	.ll_new_root
	test	edx, avl_status_lcop
	jz	.ll2
	mov	[r11+_avlofs_left], r9
	jmp	.ll3
calign
.ll2:
	mov	[r11+_avlofs_right], r9
if align_inner
	; ll3 fallthrough copy to avoid nop fill
	mov	[rcx+_avlofs_parent], r9
	mov	[rcx+_avlofs_left], r10
	mov	[r9+_avlofs_parent], r11
	mov	[r9+_avlofs_right], rcx
	test	r10, r10
	jz	.ll4
	mov	[r10+_avlofs_parent], rcx
	; ll4 fallthrough copy to avoid nop fill
	test	dword [r9+_avlofs_flags], avl_unb_mask
	jz	.ll5
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if
calign
.ll3:
	mov	[rcx+_avlofs_parent], r9
	mov	[rcx+_avlofs_left], r10
	mov	[r9+_avlofs_parent], r11
	mov	[r9+_avlofs_right], rcx
	test	r10, r10
	jz	.ll4
	mov	[r10+_avlofs_parent], rcx
if align_inner
	; ll4 fallthrough copy to avoid nop fill
	test	dword [r9+_avlofs_flags], avl_unb_mask
	jz	.ll5
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if
calign
.ll4:
	test	dword [r9+_avlofs_flags], avl_unb_mask
	jz	.ll5
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.ll5:
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [r9+_avlofs_flags], avl_right_balanced
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rcx+_avlofs_flags], avl_left_balanced
if profile_map_internals
	epilog
else
	epilog_noprofile
end if

calign
.lr:
	mov	r10, [r9+_avlofs_right]
	mov	r8, [r10+_avlofs_left]
	test	r11, r11
	jz	.lr_new_root
	test	edx, avl_status_lcop
	jz	.lr2
	mov	[r11+_avlofs_left], r10
	jmp	.lr3
calign
.lr2:
	mov	[r11+_avlofs_right], r10
if align_inner
	; lr3 fallthrough copy to avoid nop fill
	mov	[r10+_avlofs_parent], r11
	mov	r11, [r10+_avlofs_right]
	mov	[r10+_avlofs_left], r9
	mov	[r10+_avlofs_right], rcx
	mov	[rcx+_avlofs_parent], r10
	mov	[rcx+_avlofs_left], r11
	mov	[r9+_avlofs_parent], r10
	mov	[r9+_avlofs_right], r8
	test	r8, r8
	jz	.lr4
	mov	[r8+_avlofs_parent], r9
	; lr4 fallthrough copy to avoid nop fill
	test	r11, r11
	jz	.lr5
	mov	[r11+_avlofs_parent], rcx
	; lr5 fallthrough copy to avoid nop fill
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.lr7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jz	.lr6
	or	dword [rcx+_avlofs_flags], avl_right_balanced
	jmp	.lr7
end if
calign
.lr3:
	mov	[r10+_avlofs_parent], r11
	mov	r11, [r10+_avlofs_right]
	mov	[r10+_avlofs_left], r9
	mov	[r10+_avlofs_right], rcx
	mov	[rcx+_avlofs_parent], r10
	mov	[rcx+_avlofs_left], r11
	mov	[r9+_avlofs_parent], r10
	mov	[r9+_avlofs_right], r8
	test	r8, r8
	jz	.lr4
	mov	[r8+_avlofs_parent], r9
if align_inner
	; lr4 fallthrough copy to avoid nop fill
	test	r11, r11
	jz	.lr5
	mov	[r11+_avlofs_parent], rcx
	; lr5 fallthrough copy to avoid nop fill
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.lr7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jz	.lr6
	or	dword [rcx+_avlofs_flags], avl_right_balanced
	jmp	.lr7
end if
calign
.lr4:
	test	r11, r11
	jz	.lr5
	mov	[r11+_avlofs_parent], rcx
if align_inner
	; lr5 fallthrough copy to avoid nop fill
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.lr7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jz	.lr6
	or	dword [rcx+_avlofs_flags], avl_right_balanced
	jmp	.lr7
end if
calign
.lr5:
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.lr7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jz	.lr6
	or	dword [rcx+_avlofs_flags], avl_right_balanced
	jmp	.lr7
calign
.lr6:
	or	dword [r9+_avlofs_flags], avl_left_balanced
	and	dword [r10+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.lr7:
	and	dword [r10+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if

calign
.rl:
	mov	r10, [r9+_avlofs_left]
	mov	r8, [r10+_avlofs_right]
	test	r11, r11
	jz	.rl_new_root
	test	edx, avl_status_lcop
	jz	.rl2
	mov	[r11+_avlofs_left], r10
	jmp	.rl3
calign
.rl2:
	mov	[r11+_avlofs_right], r10
if align_inner
	; rl3 fallthrough copy to avoid nop fill
	mov	[r10+_avlofs_parent], r11
	mov	r11, [r10+_avlofs_left]
	mov	[r10+_avlofs_right], r9
	mov	[r10+_avlofs_left], rcx
	mov	[rcx+_avlofs_parent], r10
	mov	[rcx+_avlofs_right], r11
	mov	[r9+_avlofs_parent], r10
	mov	[r9+_avlofs_left], r8
	test	r8, r8
	jz	.rl4
	mov	[r8+_avlofs_parent], r9
	; rl4 fallthrough copy to avoid nop fill
	test	r11, r11
	jz	.rl5
	mov	[r11+_avlofs_parent], rcx
	; rl5 fallthrough copy to avoid nop fill
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.rl7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jnz	.rl6
	or	dword [rcx+_avlofs_flags], avl_left_balanced
	jmp	.rl7
end if
calign
.rl3:
	mov	[r10+_avlofs_parent], r11
	mov	r11, [r10+_avlofs_left]
	mov	[r10+_avlofs_right], r9
	mov	[r10+_avlofs_left], rcx
	mov	[rcx+_avlofs_parent], r10
	mov	[rcx+_avlofs_right], r11
	mov	[r9+_avlofs_parent], r10
	mov	[r9+_avlofs_left], r8
	test	r8, r8
	jz	.rl4
	mov	[r8+_avlofs_parent], r9
if align_inner
	; rl4 fallthrough copy to avoid nop fill
	test	r11, r11
	jz	.rl5
	mov	[r11+_avlofs_parent], rcx
	; rl5 fallthrough copy to avoid nop fill
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.rl7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jnz	.rl6
	or	dword [rcx+_avlofs_flags], avl_left_balanced
	jmp	.rl7
end if
calign
.rl4:
	test	r11, r11
	jz	.rl5
	mov	[r11+_avlofs_parent], rcx
if align_inner
	; rl5 fallthrough copy to avoid nop fill
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.rl7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jnz	.rl6
	or	dword [rcx+_avlofs_flags], avl_left_balanced
	jmp	.rl7
end if
calign
.rl5:
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	test	dword [r10+_avlofs_flags], avl_unbalanced
	jz	.rl7
	test	dword [r10+_avlofs_flags], avl_unb_left
	jnz	.rl6
	or	dword [rcx+_avlofs_flags], avl_left_balanced
	jmp	.rl7
calign
.rl6:
	or	dword [r9+_avlofs_flags], avl_right_balanced
if align_inner
	; rl7 fallthrough copy to avoid nop fill
	and	dword [r10+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if
calign
.rl7:
	and	dword [r10+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if

calign
.rr:
	mov	r10, [r9+_avlofs_left]
	test	r11, r11
	jz	.rr_new_root
	test	edx, avl_status_lcop
	jz	.rr2
	mov	[r11+_avlofs_left], r9
	jmp	.rr3
calign
.rr2:
	mov	[r11+_avlofs_right], r9
if align_inner
	; rr3 fallthrough copy to avoid nop fill
	mov	[rcx+_avlofs_parent], r9
	mov	[rcx+_avlofs_right], r10
	mov	[r9+_avlofs_parent], r11
	mov	[r9+_avlofs_left], rcx
	test	r10, r10
	jz	.rr4
	mov	[r10+_avlofs_parent], rcx
	; rr4 fallthrough copy to avoid nop fill
	test	dword [r9+_avlofs_flags], avl_unb_mask
	jz	.rr5
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if
calign
.rr3:
	mov	[rcx+_avlofs_parent], r9
	mov	[rcx+_avlofs_right], r10
	mov	[r9+_avlofs_parent], r11
	mov	[r9+_avlofs_left], rcx
	test	r10, r10
	jz	.rr4
	mov	[r10+_avlofs_parent], rcx
if align_inner
	; rr4 fallthrough copy to avoid nop fill
	test	dword [r9+_avlofs_flags], avl_unb_mask
	jz	.rr5
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
end if
calign
.rr4:
	test	dword [r9+_avlofs_flags], avl_unb_mask
	jz	.rr5
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.rr5:
	and	dword [r9+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [r9+_avlofs_flags], avl_left_balanced
	and	dword [rcx+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rcx+_avlofs_flags], avl_right_balanced
if profile_map_internals
	epilog
else
	epilog_noprofile
end if
calign
.ll_new_root:
	mov	[rdi+_avlofs_parent], r9
	jmp	.ll3
calign
.lr_new_root:
	mov	[rdi+_avlofs_parent], r10
	jmp	.lr3
calign
.rl_new_root:
	mov	[rdi+_avlofs_parent], r10
	jmp	.rl3
calign
.rr_new_root:
	mov	[rdi+_avlofs_parent], r9
	jmp	.rr3

end if


	; this causes a bit of code bloat using modified copies of each of these
	; for each variant... TODO: function pointers instead?

if used intmap$insert_unique | defined include_everything
	; rdi == map, rsi == key, rdx == value
	; rax == bool as to whether the insert succeeded or not (unique constraint violated)
falign
intmap$insert_unique:
	prolog	intmap$insert_unique
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	mov	[rax+_avlofs_key], rsi
	mov	[rax+_avlofs_value], rdx
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], 0
	add	qword [rdi+_avlofs_right], 1	; increment our list node count
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root
	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_intmap_locate_node
	; normal return from _intmap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	pop	rax

	test	r9d, avl_status_found
	jnz	.node_is_equal
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _intmap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	jmp	.check_heavy
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
calign
.check_heavy:
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	sub	qword [rdi+_avlofs_right], 1	; decrement our count again
	mov	rdi, rax
	call	heap$free
	xor	eax, eax	; 0 ret
	epilog
end if


if used unsignedmap$insert_unique | defined include_everything
	; rdi == map, rsi == key, rdx == value
	; rax == bool as to whether the insert succeeded or not (unique constraint violated)
falign
unsignedmap$insert_unique:
	prolog	unsignedmap$insert_unique


	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	mov	[rax+_avlofs_key], rsi
	mov	[rax+_avlofs_value], rdx
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], ecx
	add	qword [rdi+_avlofs_right], 1	; increment the map's nodecount
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root


	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_unsignedmap_locate_node
	pop	rax

	test	r9d, avl_status_found
	jnz	.node_is_equal

	; normal return from _unsignedmap_locate_node is in rax, but we know that r8 is the actual return
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _unsignedmap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax

	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order

	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	; check_heavy fallthrough copy
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
	; check_heavy fallthrough copy
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	sub	qword [rdi+_avlofs_right], 1	; decrement our count again
	mov	rdi, rax
	call	heap$free
	xor	eax, eax	; 0 ret
	epilog


end if


if used doublemap$insert_unique | defined include_everything
	; rdi == map, xmm0 == key, rsi == value
	; rax == bool as to whether the insert succeeded or not (unique constraint violated)
falign
doublemap$insert_unique:
	prolog	doublemap$insert_unique
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	movq	[rax+_avlofs_key], xmm0
	mov	[rax+_avlofs_value], rsi
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], 0
	add	qword [rdi+_avlofs_right], 1	; increment our list node count
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root
	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_doublemap_locate_node
	; normal return from _doublemap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	pop	rax
	test	r9d, avl_status_found
	jnz	.node_is_equal

	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _doublemap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	jmp	.check_heavy
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
calign
.check_heavy:
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	sub	qword [rdi+_avlofs_right], 1	; decrement our count again
	mov	rdi, rax
	call	heap$free
	xor	eax, eax	; 0 ret
	epilog
end if

if used stringmap$insert_unique | defined include_everything
	; rdi == map, rsi == key, rdx == value
	; rax == bool as to whether the insert succeeded or not (unique constraint violated)
	; with r8 being leftover as the node that was equal if it failed
falign
stringmap$insert_unique:
	prolog	stringmap$insert_unique
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	mov	[rax+_avlofs_key], rsi
	mov	[rax+_avlofs_value], rdx
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], ecx
	add	qword [rdi+_avlofs_right], 1	; increment the map's nodecount
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root

	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_stringmap_locate_node
	pop	rax

	test	r9d, avl_status_found
	jnz	.node_is_equal

	; normal return from _unsignedmap_locate_node is in rax, but we know that r8 is the actual return
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _unsignedmap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax

	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order

	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	; check_heavy fallthrough copy
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
	; check_heavy fallthrough copy
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	sub	qword [rdi+_avlofs_right], 1	; decrement our count again
	mov	rdi, rax
	call	heap$free
	xor	eax, eax	; 0 ret
	epilog

end if







; -------------- non-unique insert varieties ---------------
if used intmap$insert | defined include_everything
	; rdi == map, rsi == key, rdx == value
	; will accept duplicate keys (aka multimap)
falign
intmap$insert:
	prolog	intmap$insert
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	mov	[rax+_avlofs_key], rsi
	mov	[rax+_avlofs_value], rdx
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], 0
	add	qword [rdi+_avlofs_right], 1	; increment our list node count
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root
	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_intmap_locate_node
	; normal return from _intmap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	pop	rax
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _intmap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_found
	jnz	.node_is_equal
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	; special requirement here: we set our prev to r8, but it may be the top of a trunk
	; in which case, we need to link our prev not to the top of the trunk, but to its bottom-most
	push	r8
calign
.find_trunk_bottom_loop:
	cmp	qword [r8+_avlofs_trunk], 0
	je	.found_trunk_bottom
	mov	r8, [r8+_avlofs_trunk]
	jmp	.find_trunk_bottom_loop
calign
.found_trunk_bottom:
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	pop	r8
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	jmp	.check_heavy
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
calign
.check_heavy:
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	epilog
calign
.exit_ok:
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	epilog
calign
.node_is_equal:
	mov	[rax+_avlofs_parent], r8
	mov	rdx, [r8+_avlofs_trunk]
	mov	[rax+_avlofs_trunk], rdx
	mov	[r8+_avlofs_trunk], rax
	test	rdx, rdx
	jz	.noprevioustrunk
	mov	[rdx+_avlofs_parent], rax
	; list linkage next
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	epilog
calign
.trunklinkright_setlast:
	mov	[rdi+_avlofs_prev], rax
	epilog
calign
.noprevioustrunk:
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	epilog
calign
.trunklink_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.trunklinkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	epilog
calign
.trunklinkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	epilog
end if




if used unsignedmap$insert | defined include_everything
	; rdi == map, rsi == key, rdx == value
	; will accept duplicate keys (aka multimap)
falign
unsignedmap$insert:
	prolog	unsignedmap$insert
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	mov	[rax+_avlofs_key], rsi
	mov	[rax+_avlofs_value], rdx
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], 0
	add	qword [rdi+_avlofs_right], 1	; increment our list node count
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root
	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_unsignedmap_locate_node
	; normal return from _unsignedmap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	pop	rax
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _unsignedmap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_found
	jnz	.node_is_equal
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	; link us before r8
	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	; link us after r8...
	; special requirement here: we set our prev to r8, but it may be the top of a trunk
	; in which case, we need to link our prev not to the top of the trunk, but to its bottom-most
	push	r8
calign
.find_trunk_bottom_loop:
	cmp	qword [r8+_avlofs_trunk], 0
	je	.found_trunk_bottom
	mov	r8, [r8+_avlofs_trunk]
	jmp	.find_trunk_bottom_loop
calign
.found_trunk_bottom:
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	pop	r8
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	jmp	.check_heavy
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
calign
.check_heavy:
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	; rax == a
	; r8 == b
	mov	[rax+_avlofs_parent], r8
	mov	rdx, [r8+_avlofs_trunk]
	mov	[rax+_avlofs_trunk], rdx
	mov	[r8+_avlofs_trunk], rax
	test	rdx, rdx
	jz	.noprevioustrunk
	mov	[rdx+_avlofs_parent], rax
	; list linkage next
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	mov	eax, 1
	epilog
calign
.trunklinkright_setlast:
	mov	[rdi+_avlofs_prev], rax
	mov	eax, 1
	epilog
calign
.noprevioustrunk:
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	mov	eax, 1
	epilog
calign
.trunklink_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.trunklinkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	eax, 1
	epilog
calign
.trunklinkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	eax, 1
	epilog
end if


if used doublemap$insert | defined include_everything
	; rdi == map, xmm0 == key, rsi == value
	; will accept duplicate keys (aka multimap)
falign
doublemap$insert:
	prolog	doublemap$insert
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	movq	[rax+_avlofs_key], xmm0
	mov	[rax+_avlofs_value], rsi
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], 0
	add	qword [rdi+_avlofs_right], 1	; increment our list node count
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root
	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_doublemap_locate_node
	; normal return from _doublemap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	pop	rax
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _doublemap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_found
	jnz	.node_is_equal
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	; special requirement here: we set our prev to r8, but it may be the top of a trunk
	; in which case, we need to link our prev not to the top of the trunk, but to its bottom-most
	push	r8
calign
.find_trunk_bottom_loop:
	cmp	qword [r8+_avlofs_trunk], 0
	je	.found_trunk_bottom
	mov	r8, [r8+_avlofs_trunk]
	jmp	.find_trunk_bottom_loop
calign
.found_trunk_bottom:
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	pop	r8
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	jmp	.check_heavy
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
calign
.check_heavy:
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	mov	[rax+_avlofs_parent], r8
	mov	rdx, [r8+_avlofs_trunk]
	mov	[rax+_avlofs_trunk], rdx
	mov	[r8+_avlofs_trunk], rax
	test	rdx, rdx
	jz	.noprevioustrunk
	mov	[rdx+_avlofs_parent], rax
	; list linkage next
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	epilog
calign
.trunklinkright_setlast:
	mov	[rdi+_avlofs_prev], rax
	epilog
calign
.noprevioustrunk:
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	epilog
calign
.trunklink_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.trunklinkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	epilog
calign
.trunklinkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	epilog
end if

if used stringmap$insert | defined include_everything
	; rdi == map, rsi == key, rdx == value
	; will accept duplicate keys (aka multimap)
falign
stringmap$insert:
	prolog	stringmap$insert
	push	rdi rsi rdx
	mov	edi, avlnode_size
	call	heap$alloc
	pop	rdx rsi rdi
	xor	ecx, ecx
	mov	[rax+_avlofs_key], rsi
	mov	[rax+_avlofs_value], rdx
	mov	[rax+_avlofs_left], rcx
	mov	[rax+_avlofs_right], rcx
	mov	[rax+_avlofs_trunk], rcx
	mov	dword [rax+_avlofs_flags], 0
	add	qword [rdi+_avlofs_right], 1	; increment our list node count
	cmp	qword [rdi+_avlofs_parent], 0
	je	.no_root
	; so at this point, rdi still has our map, rsi still has our key, rdx has our value but we don't care about it anymore
	; and rax has our spanking new node
	push	rax
	call	_stringmap_locate_node
	; normal return from _stringmap_locate_node is in rax, but we know that r8 is the actual return, so go ahead and blast rax
	pop	rax
	; rdi still our map, rsi still our key, though we don't care about it anymore either, rax is our new node, r8 is our return
	; from _stringmap_locate_node, r9d is flags, r10d pathflags, ecx is pathcount
	mov	[rax+_avlofs_parent], r8	; link our parent with the return
	test	r9d, avl_status_found
	jnz	.node_is_equal
	test	r9d, avl_status_left
	jz	.node_b_right
	mov	[r8+_avlofs_left], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	mov	[rax+_avlofs_next], r8
	mov	rdx, [r8+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	mov	[r8+_avlofs_prev], rax
	test	rdx, rdx
	jz	.linkleft_setlast
	mov	[rdx+_avlofs_next], rax
	jmp	.check_balance
calign
.linkleft_setlast:
	mov	[rdi+_avlofs_next], rax
	jmp	.check_balance
calign
.link_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.linkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	jmp	.check_balance
calign
.node_b_right:
	mov	[r8+_avlofs_right], rax
	; link up our list
	test	dword [rdi+_avlofs_flags], 1
	jnz	.link_insert_order
	; special requirement here: we set our prev to r8, but it may be the top of a trunk
	; in which case, we need to link our prev not to the top of the trunk, but to its bottom-most
	push	r8
calign
.find_trunk_bottom_loop:
	cmp	qword [r8+_avlofs_trunk], 0
	je	.found_trunk_bottom
	mov	r8, [r8+_avlofs_trunk]
	jmp	.find_trunk_bottom_loop
calign
.found_trunk_bottom:
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	pop	r8
	test	rdx, rdx
	jz	.linkright_setlast
	mov	[rdx+_avlofs_prev], rax
	jmp	.check_balance
calign
.linkright_setlast:
	mov	[rdi+_avlofs_prev], rax
calign
.check_balance:
	sub	ecx, 1
	mov	rax, [rax+_avlofs_parent]
	mov	r8d, dword [rax+_avlofs_flags]
	and	r8d, avl_unb_mask
	bt	r10d, ecx	
	jnc	.trav_right
	; trav_left:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r8d, 1
	or	r8d, r11d
	mov	r9d, r8d
	shl	r8d, 1
	shl	r11d, 2
	add	r8d, r9d
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	test	r8d, avl_unb_left
	jz	.exit_ok
	jmp	.check_heavy
calign
.trav_right:
	mov	r11d, r8d
	and	r8d, 1
	shr	r11d, 1
	xor	r11d, 1
	and	r8d, r11d
	shl	r8d, 2
	add	r8d, r11d
	and	dword [rax+_avlofs_flags], 0xffff - avl_unb_mask
	or	dword [rax+_avlofs_flags], r8d
	mov	r9d, r8d
	and	r9d, avl_unb_left + avl_unbalanced
	xor	r9d, avl_unbalanced
	test	r9d, r9d
	jnz	.exit_ok
calign
.check_heavy:
	test	dword [rax+_avlofs_flags], avl_unb_heavy
	jnz	.node_is_heavy
	cmp	rax, [rdi+_avlofs_parent]
	je	.exit_ok
	jmp	.check_balance
calign
.node_is_heavy:
	mov	rsi, rax
	mov	edx, r9d
	call	_map_rebalance
	mov	eax, 1		; return true
	epilog
calign
.exit_ok:
	mov	eax, 1
	epilog
calign
.no_root:
	mov	[rdi+_avlofs_parent], rax
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	mov	qword [rax+_avlofs_parent], 0
	mov	qword [rax+_avlofs_next], 0
	mov	qword [rax+_avlofs_prev], 0
	mov	eax, 1
	epilog
calign
.node_is_equal:
	mov	[rax+_avlofs_parent], r8
	mov	rdx, [r8+_avlofs_trunk]
	mov	[rax+_avlofs_trunk], rdx
	mov	[r8+_avlofs_trunk], rax
	test	rdx, rdx
	jz	.noprevioustrunk
	mov	[rdx+_avlofs_parent], rax
	; list linkage next
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	epilog
calign
.trunklinkright_setlast:
	mov	[rdi+_avlofs_prev], rax
	epilog
calign
.noprevioustrunk:
	test	dword [rdi+_avlofs_flags], 1
	jnz	.trunklink_insert_order
	mov	[rax+_avlofs_prev], r8
	mov	rdx, [r8+_avlofs_next]
	mov	[rax+_avlofs_next], rdx
	mov	[r8+_avlofs_next], rax
	test	rdx, rdx
	jz	.trunklinkright_setlast
	mov	[rdx+_avlofs_prev], rax
	epilog
calign
.trunklink_insert_order:
	mov	qword [rax+_avlofs_next], 0
	mov	rdx, [rdi+_avlofs_prev]
	mov	[rax+_avlofs_prev], rdx
	test	rdx, rdx
	jz	.trunklinkleft_set_first
	mov	[rdx+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	epilog
calign
.trunklinkleft_set_first:
	mov	[rdi+_avlofs_next], rax
	mov	[rdi+_avlofs_prev], rax
	epilog
end if






if used intmap$erase | defined include_everything
falign
intmap$erase:
	prolog	intmap$erase
	call	_intmap_locate_node
	test	r9d, avl_status_found
	jz	.not_found
	mov	r11, [r8+_avlofs_parent]
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	test	rdx, rdx
	jz	.case_one
	mov	rax, [rdx+_avlofs_left]
	test	rax, rax
	jz	.case_two
	jmp	.case_three
calign
.case_one:
	test	r11, r11
	jz	.case_one_check_empty
	test	r9, r9
	jz	.case_one_no_c
	mov	[r9+_avlofs_parent], r11
calign
.case_one_no_c:
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_one_relink_right
	mov	[r11+_avlofs_left], r9
	mov	rsi, r11
	push	r8
	call	_map_left_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_relink_right:
	mov	[r11+_avlofs_right], r9
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_check_empty:
	test	r9, r9
	jnz	.case_one_new_root
	mov	qword [rdi+_avlofs_parent], 0
	jmp	.relinked
calign
.case_one_new_root:
	mov	qword [r9+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], r9
	jmp	.relinked
calign
.case_two:
	mov	[rdx+_avlofs_left], r9
	test	r9, r9
	jz	.case_two_no_c
	mov	[r9+_avlofs_parent], rdx
calign
.case_two_no_c:
	test	r11, r11
	jz	.case_two_new_root
	mov	[rdx+_avlofs_parent], r11
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_two_relink_right
	mov	[r11+_avlofs_left], rdx
	jmp	.case_two_rebalance
calign
.case_two_relink_right:
	mov	[r11+_avlofs_right], rdx
calign
.case_two_rebalance:
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rdx+_avlofs_flags], 0xffff - avl_all
	or	dword [rdx+_avlofs_flags], r9d
	pop	r9
	mov	r11, rdx
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_two_new_root:
	mov	qword [rdx+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rdx
	jmp	.case_two_rebalance
calign
.case_three:
	push	r8
	mov	rsi, r8
	call	_map_successor
	mov	r9, [rax+_avlofs_right]
	mov	r8, [rax+_avlofs_parent]
	mov	[r8+_avlofs_left], r9
	test	r9, r9
	jnz	.case_three_succ_has_right
calign
.case_three_succ_no_right:
	mov	rsi, r8
	push	rax
	call	_map_left_lighter
	pop	rax
	pop	r8
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	mov	[rax+_avlofs_left], r9
	mov	r11, [r8+_avlofs_parent]
	test	r9, r9
	jz	.case_three_succ_no_right_no_c
	mov	[r9+_avlofs_parent], rax
calign
.case_three_succ_no_right_no_c:
	mov	[rdx+_avlofs_parent], rax
	mov	[rax+_avlofs_right], rdx
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rax+_avlofs_flags], 0xffff - avl_all
	or	dword [rax+_avlofs_flags], r9d
	pop	r9
	mov	[rax+_avlofs_parent], r11
	test	r11, r11
	jz	.case_three_was_root
	cmp	r8, [r11+_avlofs_right]
	je	.case_three_relink_right
	mov	[r11+_avlofs_left], rax
	jmp	.relinked
calign
.case_three_relink_right:
	mov	[r11+_avlofs_right], rax
	jmp	.relinked
calign
.relinked:
	xor	eax, eax
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop:
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop_set_first:
	mov	[rdi+_avlofs_next], rdx
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_otherside:
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_set_last:
	mov	[rdi+_avlofs_prev], rdx
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.relinked_loop_dec:
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.case_three_succ_has_right:
	mov	[r9+_avlofs_parent], r8
	jmp	.case_three_succ_no_right
calign
.case_three_was_root:
	mov	qword [rax+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rax
	jmp	.relinked
calign
.not_found:
	xor	eax, eax	; no nodes deleted
	epilog

end if



if used unsignedmap$erase | defined include_everything
falign
unsignedmap$erase:
	prolog	unsignedmap$erase
	call	_unsignedmap_locate_node
	test	r9d, avl_status_found
	jz	.not_found
	mov	r11, [r8+_avlofs_parent]
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	test	rdx, rdx
	jz	.case_one
	mov	rax, [rdx+_avlofs_left]
	test	rax, rax
	jz	.case_two
	jmp	.case_three
calign
.case_one:
	test	r11, r11
	jz	.case_one_check_empty
	test	r9, r9
	jz	.case_one_no_c
	mov	[r9+_avlofs_parent], r11
calign
.case_one_no_c:
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_one_relink_right
	mov	[r11+_avlofs_left], r9
	mov	rsi, r11
	push	r8
	call	_map_left_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_relink_right:
	mov	[r11+_avlofs_right], r9
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_check_empty:
	test	r9, r9
	jnz	.case_one_new_root
	mov	qword [rdi+_avlofs_parent], 0
	jmp	.relinked
calign
.case_one_new_root:
	mov	qword [r9+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], r9
	jmp	.relinked
calign
.case_two:
	mov	[rdx+_avlofs_left], r9
	test	r9, r9
	jz	.case_two_no_c
	mov	[r9+_avlofs_parent], rdx
calign
.case_two_no_c:
	test	r11, r11
	jz	.case_two_new_root
	mov	[rdx+_avlofs_parent], r11
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_two_relink_right
	mov	[r11+_avlofs_left], rdx
	jmp	.case_two_rebalance
calign
.case_two_relink_right:
	mov	[r11+_avlofs_right], rdx
calign
.case_two_rebalance:
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rdx+_avlofs_flags], 0xffff - avl_all
	or	dword [rdx+_avlofs_flags], r9d
	pop	r9
	mov	r11, rdx
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_two_new_root:
	mov	qword [rdx+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rdx
	jmp	.case_two_rebalance
calign
.case_three:
	push	r8
	mov	rsi, r8
	call	_map_successor
	mov	r9, [rax+_avlofs_right]
	mov	r8, [rax+_avlofs_parent]
	mov	[r8+_avlofs_left], r9
	test	r9, r9
	jnz	.case_three_succ_has_right
calign
.case_three_succ_no_right:
	mov	rsi, r8
	push	rax
	call	_map_left_lighter
	pop	rax
	pop	r8
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	mov	[rax+_avlofs_left], r9
	mov	r11, [r8+_avlofs_parent]
	test	r9, r9
	jz	.case_three_succ_no_right_no_c
	mov	[r9+_avlofs_parent], rax
calign
.case_three_succ_no_right_no_c:
	mov	[rdx+_avlofs_parent], rax
	mov	[rax+_avlofs_right], rdx
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rax+_avlofs_flags], 0xffff - avl_all
	or	dword [rax+_avlofs_flags], r9d
	pop	r9
	mov	[rax+_avlofs_parent], r11
	test	r11, r11
	jz	.case_three_was_root
	cmp	r8, [r11+_avlofs_right]
	je	.case_three_relink_right
	mov	[r11+_avlofs_left], rax
	jmp	.relinked
calign
.case_three_relink_right:
	mov	[r11+_avlofs_right], rax
	jmp	.relinked
calign
.relinked:
	xor	eax, eax
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop:
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop_set_first:
	mov	[rdi+_avlofs_next], rdx
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_otherside:
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_set_last:
	mov	[rdi+_avlofs_prev], rdx
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.relinked_loop_dec:
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.case_three_succ_has_right:
	mov	[r9+_avlofs_parent], r8
	jmp	.case_three_succ_no_right
calign
.case_three_was_root:
	mov	qword [rax+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rax
	jmp	.relinked
calign
.not_found:
	xor	eax, eax	; no nodes deleted
	epilog




end if


if used unsignedmap$erase_specific | defined include_everything
	; different from the above in that we pay attention to its value object and leave the rest (if any)
	; of the trunk alone (will delete all matching values)
falign
unsignedmap$erase_specific:
	prolog	unsignedmap$erase_specific
	push	rdx rsi rdi
	call	_unsignedmap_locate_node_specific
	test	r9d, avl_status_found
	jz	.alldone
	call	unsignedmap$erase_specific_node
calign
.top:
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	call	_unsignedmap_locate_node_specific
	test	r9d, avl_status_found
	jz	.alldone
	call	unsignedmap$erase_specific_node
	jmp	.top
calign
.alldone:
	add	rsp, 24
	epilog
end if
	

if used unsignedmap$erase_specific_node | defined include_everything
	; not meant to be called publically, called from above public function
falign
unsignedmap$erase_specific_node:
	prolog	unsignedmap$erase_specific_node

	cmp	qword [r8+_avlofs_trunk], 0
	jne	.has_trunk

	mov	r11, [r8+_avlofs_parent]
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	test	rdx, rdx
	jz	.case_one
	mov	rax, [rdx+_avlofs_left]
	test	rax, rax
	jz	.case_two
	jmp	.case_three
calign
.case_one:
	test	r11, r11
	jz	.case_one_check_empty
	test	r9, r9
	jz	.case_one_no_c
	mov	[r9+_avlofs_parent], r11
calign
.case_one_no_c:
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_one_relink_right
	mov	[r11+_avlofs_left], r9
	mov	rsi, r11
	push	r8
	call	_map_left_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_relink_right:
	mov	[r11+_avlofs_right], r9
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_check_empty:
	test	r9, r9
	jnz	.case_one_new_root
	mov	qword [rdi+_avlofs_parent], 0
	jmp	.relinked
calign
.case_one_new_root:
	mov	qword [r9+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], r9
	jmp	.relinked
calign
.case_two:
	mov	[rdx+_avlofs_left], r9
	test	r9, r9
	jz	.case_two_no_c
	mov	[r9+_avlofs_parent], rdx
calign
.case_two_no_c:
	test	r11, r11
	jz	.case_two_new_root
	mov	[rdx+_avlofs_parent], r11
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_two_relink_right
	mov	[r11+_avlofs_left], rdx
	jmp	.case_two_rebalance
calign
.case_two_relink_right:
	mov	[r11+_avlofs_right], rdx
calign
.case_two_rebalance:
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rdx+_avlofs_flags], 0xffff - avl_all
	or	dword [rdx+_avlofs_flags], r9d
	pop	r9
	mov	r11, rdx
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_two_new_root:
	mov	qword [rdx+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rdx
	jmp	.case_two_rebalance
calign
.case_three:
	push	r8
	mov	rsi, r8
	call	_map_successor
	mov	r9, [rax+_avlofs_right]
	mov	r8, [rax+_avlofs_parent]
	mov	[r8+_avlofs_left], r9
	test	r9, r9
	jnz	.case_three_succ_has_right
calign
.case_three_succ_no_right:
	mov	rsi, r8
	push	rax
	call	_map_left_lighter
	pop	rax
	pop	r8
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	mov	[rax+_avlofs_left], r9
	mov	r11, [r8+_avlofs_parent]
	test	r9, r9
	jz	.case_three_succ_no_right_no_c
	mov	[r9+_avlofs_parent], rax
calign
.case_three_succ_no_right_no_c:
	mov	[rdx+_avlofs_parent], rax
	mov	[rax+_avlofs_right], rdx
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rax+_avlofs_flags], 0xffff - avl_all
	or	dword [rax+_avlofs_flags], r9d
	pop	r9
	mov	[rax+_avlofs_parent], r11
	test	r11, r11
	jz	.case_three_was_root
	cmp	r8, [r11+_avlofs_right]
	je	.case_three_relink_right
	mov	[r11+_avlofs_left], rax
	jmp	.relinked
calign
.case_three_relink_right:
	mov	[r11+_avlofs_right], rax
	jmp	.relinked
calign
.relinked:
	xor	eax, eax
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop:
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop_set_first:
	mov	[rdi+_avlofs_next], rdx
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_otherside:
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_set_last:
	mov	[rdi+_avlofs_prev], rdx
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.relinked_loop_dec:
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.case_three_succ_has_right:
	mov	[r9+_avlofs_parent], r8
	jmp	.case_three_succ_no_right
calign
.case_three_was_root:
	mov	qword [rax+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rax
	jmp	.relinked
calign
.not_found:
	xor	eax, eax	; no nodes deleted
	epilog


calign
.has_trunk:
	mov	rax, r8
	cmp	rdx, r8
	je	.has_trunk_foundit
calign
.again:
	mov	rax, [rax+_avlofs_trunk]
	test	rax, rax
	jz	.not_found
	cmp	rdx, rax
	jne	.again
calign
.has_trunk_foundit:
	mov	r11, [rax+_avlofs_prev]
	mov	rdx, [rax+_avlofs_next]
	test	r11, r11
	jz	.set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.otherside
calign
.set_first:
	mov	[rdi+_avlofs_next], rdx
calign
.otherside:
	test	rdx, rdx
	jz	.set_last
	mov	[rdx+_avlofs_prev], r11
	jmp	.has_trunk_keep_going
calign
.set_last:
	mov	[rdi+_avlofs_prev], r11
calign
.has_trunk_keep_going:
	sub	qword [rdi+_avlofs_right], 1
	cmp	rax, r8
	je	.top_of_trunk
	; else, we are not the top of the trunk, and we have a parent
	mov	r11, [rax+_avlofs_parent]
	mov	rdx, [rax+_avlofs_trunk]
	mov	[r11+_avlofs_trunk], rdx
	test	rdx, rdx
	jz	.not_top_no_new_parent
	mov	[rdx+_avlofs_parent], r11
calign
.not_top_no_new_parent:
	mov	rdi, rax
	call	heap$free
	mov	eax, 1
	epilog
calign
.top_of_trunk:
	mov	rdx, [rax+_avlofs_trunk]
	cmp	rax, [rdi+_avlofs_parent]
	jne	.top_of_trunk_not_root
	mov	[rdi+_avlofs_parent], rdx
calign
.top_of_trunk_not_root:
	mov	r11, [rax+_avlofs_parent]
	mov	[rdx+_avlofs_parent], r11
	test	r11, r11
	jz	.top_of_trunk_no_parent
	cmp	rax, [r11+_avlofs_left]
	jne	.top_of_trunk_parent_not_left
	mov	[r11+_avlofs_left], rdx
	jmp	.top_of_trunk_no_parent
calign
.top_of_trunk_parent_not_left:
	cmp	rax, [r11+_avlofs_right]
	jne	.top_of_trunk_no_parent
	mov	[r11+_avlofs_right], rdx
calign
.top_of_trunk_no_parent:
	mov	r9, [rax+_avlofs_left]
	mov	[rdx+_avlofs_left], r9
	test	r9, r9
	jz	.top_of_trunk_noleft
	mov	[r9+_avlofs_parent], rdx
calign
.top_of_trunk_noleft:
	mov	r9, [rax+_avlofs_right]
	mov	[rdx+_avlofs_right], r9
	test	r9, r9
	jz	.top_of_trunk_noright
	mov	[r9+_avlofs_parent], rdx
calign
.top_of_trunk_noright:
	mov	r9d, dword [rax+_avlofs_flags]
	mov	dword [rdx+_avlofs_flags], r9d
	mov	rdi, rax
	call	heap$free
	mov	eax, 1
	epilog


end if


if used doublemap$erase | defined include_everything
falign
doublemap$erase:
	prolog	doublemap$erase
	call	_doublemap_locate_node
	test	r9d, avl_status_found
	jz	.not_found
	mov	r11, [r8+_avlofs_parent]
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	test	rdx, rdx
	jz	.case_one
	mov	rax, [rdx+_avlofs_left]
	test	rax, rax
	jz	.case_two
	jmp	.case_three
calign
.case_one:
	test	r11, r11
	jz	.case_one_check_empty
	test	r9, r9
	jz	.case_one_no_c
	mov	[r9+_avlofs_parent], r11
calign
.case_one_no_c:
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_one_relink_right
	mov	[r11+_avlofs_left], r9
	mov	rsi, r11
	push	r8
	call	_map_left_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_relink_right:
	mov	[r11+_avlofs_right], r9
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_check_empty:
	test	r9, r9
	jnz	.case_one_new_root
	mov	qword [rdi+_avlofs_parent], 0
	jmp	.relinked
calign
.case_one_new_root:
	mov	qword [r9+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], r9
	jmp	.relinked
calign
.case_two:
	mov	[rdx+_avlofs_left], r9
	test	r9, r9
	jz	.case_two_no_c
	mov	[r9+_avlofs_parent], rdx
calign
.case_two_no_c:
	test	r11, r11
	jz	.case_two_new_root
	mov	[rdx+_avlofs_parent], r11
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_two_relink_right
	mov	[r11+_avlofs_left], rdx
	jmp	.case_two_rebalance
calign
.case_two_relink_right:
	mov	[r11+_avlofs_right], rdx
calign
.case_two_rebalance:
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rdx+_avlofs_flags], 0xffff - avl_all
	or	dword [rdx+_avlofs_flags], r9d
	pop	r9
	mov	r11, rdx
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_two_new_root:
	mov	qword [rdx+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rdx
	jmp	.case_two_rebalance
calign
.case_three:
	push	r8
	mov	rsi, r8
	call	_map_successor
	mov	r9, [rax+_avlofs_right]
	mov	r8, [rax+_avlofs_parent]
	mov	[r8+_avlofs_left], r9
	test	r9, r9
	jnz	.case_three_succ_has_right
calign
.case_three_succ_no_right:
	mov	rsi, r8
	push	rax
	call	_map_left_lighter
	pop	rax
	pop	r8
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	mov	[rax+_avlofs_left], r9
	mov	r11, [r8+_avlofs_parent]
	test	r9, r9
	jz	.case_three_succ_no_right_no_c
	mov	[r9+_avlofs_parent], rax
calign
.case_three_succ_no_right_no_c:
	mov	[rdx+_avlofs_parent], rax
	mov	[rax+_avlofs_right], rdx
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rax+_avlofs_flags], 0xffff - avl_all
	or	dword [rax+_avlofs_flags], r9d
	pop	r9
	mov	[rax+_avlofs_parent], r11
	test	r11, r11
	jz	.case_three_was_root
	cmp	r8, [r11+_avlofs_right]
	je	.case_three_relink_right
	mov	[r11+_avlofs_left], rax
	jmp	.relinked
calign
.case_three_relink_right:
	mov	[r11+_avlofs_right], rax
	jmp	.relinked
calign
.relinked:
	xor	eax, eax
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop:
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop_set_first:
	mov	[rdi+_avlofs_next], rdx
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_otherside:
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_set_last:
	mov	[rdi+_avlofs_prev], rdx
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.relinked_loop_dec:
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	epilog
calign
.case_three_succ_has_right:
	mov	[r9+_avlofs_parent], r8
	jmp	.case_three_succ_no_right
calign
.case_three_was_root:
	mov	qword [rax+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rax
	jmp	.relinked
calign
.not_found:
	xor	eax, eax	; no nodes deleted
	epilog

end if

if used stringmap$erase | defined include_everything
	; NOTE: caution is advised! special handling is required to deal with the fact that
	; we do not heap$free either the key or the value (that is up to the caller)
	; returns count of nodes removed (0 == not found) in eax, rdx == topmost node key, r8 == topmost node value
falign
stringmap$erase:
	prolog	stringmap$erase
	call	_stringmap_locate_node
	test	r9d, avl_status_found
	jz	.not_found
	push	qword [r8+_avlofs_key]
	push	qword [r8+_avlofs_value]
	mov	r11, [r8+_avlofs_parent]
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	test	rdx, rdx
	jz	.case_one
	mov	rax, [rdx+_avlofs_left]
	test	rax, rax
	jz	.case_two
	jmp	.case_three
calign
.case_one:
	test	r11, r11
	jz	.case_one_check_empty
	test	r9, r9
	jz	.case_one_no_c
	mov	[r9+_avlofs_parent], r11
calign
.case_one_no_c:
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_one_relink_right
	mov	[r11+_avlofs_left], r9
	mov	rsi, r11
	push	r8
	call	_map_left_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_relink_right:
	mov	[r11+_avlofs_right], r9
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_one_check_empty:
	test	r9, r9
	jnz	.case_one_new_root
	mov	qword [rdi+_avlofs_parent], 0
	jmp	.relinked
calign
.case_one_new_root:
	mov	qword [r9+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], r9
	jmp	.relinked
calign
.case_two:
	mov	[rdx+_avlofs_left], r9
	test	r9, r9
	jz	.case_two_no_c
	mov	[r9+_avlofs_parent], rdx
calign
.case_two_no_c:
	test	r11, r11
	jz	.case_two_new_root
	mov	[rdx+_avlofs_parent], r11
	sub	ecx, 1
	bt	r10d, ecx
	jnc	.case_two_relink_right
	mov	[r11+_avlofs_left], rdx
	jmp	.case_two_rebalance
calign
.case_two_relink_right:
	mov	[r11+_avlofs_right], rdx
calign
.case_two_rebalance:
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rdx+_avlofs_flags], 0xffff - avl_all
	or	dword [rdx+_avlofs_flags], r9d
	pop	r9
	mov	r11, rdx
	mov	rsi, r11
	push	r8
	call	_map_right_lighter
	pop	r8
	jmp	.relinked
calign
.case_two_new_root:
	mov	qword [rdx+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rdx
	jmp	.case_two_rebalance
calign
.case_three:
	push	r8
	mov	rsi, r8
	call	_map_successor
	mov	r9, [rax+_avlofs_right]
	mov	r8, [rax+_avlofs_parent]
	mov	[r8+_avlofs_left], r9
	test	r9, r9
	jnz	.case_three_succ_has_right
calign
.case_three_succ_no_right:
	mov	rsi, r8
	push	rax
	call	_map_left_lighter
	pop	rax
	pop	r8
	mov	r9, [r8+_avlofs_left]
	mov	rdx, [r8+_avlofs_right]
	mov	[rax+_avlofs_left], r9
	mov	r11, [r8+_avlofs_parent]
	test	r9, r9
	jz	.case_three_succ_no_right_no_c
	mov	[r9+_avlofs_parent], rax
calign
.case_three_succ_no_right_no_c:
	mov	[rdx+_avlofs_parent], rax
	mov	[rax+_avlofs_right], rdx
	push	r9
	mov	r9d, dword [r8+_avlofs_flags]
	and	r9d, avl_all
	and	dword [rax+_avlofs_flags], 0xffff - avl_all
	or	dword [rax+_avlofs_flags], r9d
	pop	r9
	mov	[rax+_avlofs_parent], r11
	test	r11, r11
	jz	.case_three_was_root
	cmp	r8, [r11+_avlofs_right]
	je	.case_three_relink_right
	mov	[r11+_avlofs_left], rax
	jmp	.relinked
calign
.case_three_relink_right:
	mov	[r11+_avlofs_right], rax
	jmp	.relinked
calign
.relinked:
	xor	eax, eax
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop:
	mov	r11, [r8+_avlofs_prev]
	mov	rdx, [r8+_avlofs_next]
	test	r11, r11
	jz	.relinked_loop_set_first
	mov	[r11+_avlofs_next], rdx
	jmp	.relinked_loop_otherside
calign
.relinked_loop_set_first:
	mov	[rdi+_avlofs_next], rdx
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_otherside:
	mov	r11, [r8+_avlofs_next]
	mov	rdx, [r8+_avlofs_prev]
	test	r11, r11
	jz	.relinked_loop_set_last
	mov	[r11+_avlofs_prev], rdx
	jmp	.relinked_loop_dec
calign
.relinked_loop_set_last:
	mov	[rdi+_avlofs_prev], rdx
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	pop	r8 rdx
	epilog
calign
.relinked_loop_dec:
	sub	qword [rdi+_avlofs_right], 1
	mov	r11, [r8+_avlofs_trunk]
	push	rdi rax r11
	mov	rdi, r8
	call	heap$free
	pop	r11 rax rdi
	add	eax, 1
	mov	r8, r11
	test	r8, r8
	jnz	.relinked_loop
	pop	r8 rdx
	epilog
calign
.case_three_succ_has_right:
	mov	[r9+_avlofs_parent], r8
	jmp	.case_three_succ_no_right
calign
.case_three_was_root:
	mov	qword [rax+_avlofs_parent], 0
	mov	[rdi+_avlofs_parent], rax
	jmp	.relinked
calign
.not_found:
	xor	eax, eax	; no nodes deleted
	epilog

end if
