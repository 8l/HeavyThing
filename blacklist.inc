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
	; blacklist.inc: a convenience object to deal with unsigned keys + time delay
	; NOTE: it is assumed that this is coupled with epoll, and as such it uses
	; the global time var in epoll to manage times

if used blacklist$new | defined include_everything

blacklist_item_key_ofs = 0
blacklist_item_timeout_ofs = 8
blacklist_item_next_ofs = 16
blacklist_item_prev_ofs = 24

blacklist_item_size = 32


blacklist_map_ofs = 0
blacklist_first_ofs = 8
blacklist_last_ofs = 16
blacklist_expiry_ofs = 24

blacklist_size = 32

	; single argument in rdi: the expiry time (in seconds) of how long a blacklist entry sticks for
	; returns a blacklist object in rax
falign
blacklist$new:
	prolog	blacklist$new
	push	rdi
	xor	edi, edi
	call	unsignedmap$new
	push	rax
	mov	edi, blacklist_size
	call	heap$alloc_clear
	pop	rcx rdi
	mov	[rax+blacklist_map_ofs], rcx
	mov	[rax+blacklist_expiry_ofs], rdi
	epilog

end if

if used blacklist$add | defined include_everything
	; two arguments: rdi == blacklist object, rsi == key
falign
blacklist$add:
	prolog	blacklist$add
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	call	blacklist$check
	test	eax, eax
	jnz	.alreadyhere
	mov	edi, blacklist_item_size
	call	heap$alloc
	mov	rdi, [_epoll_tv_secs]
	xor	esi, esi
	mov	rdx, [rbx+blacklist_last_ofs]
	add	rdi, [rbx+blacklist_expiry_ofs]
	mov	[rax+blacklist_item_key_ofs], r12
	mov	[rax+blacklist_item_timeout_ofs], rdi
	mov	[rax+blacklist_item_next_ofs], rsi
	mov	[rax+blacklist_item_prev_ofs], rdx
	mov	rdi, [rbx+blacklist_map_ofs]
	mov	rsi, r12
	mov	rdx, rax
	mov	r12, rax
	call	unsignedmap$insert_unique
	mov	rdi, [rbx+blacklist_last_ofs]
	test	rdi, rdi
	jz	.firstlast
	mov	[rdi+blacklist_item_next_ofs], r12
	mov	[rbx+blacklist_last_ofs], r12
	pop	r12 rbx
	epilog
calign
.firstlast:
	mov	[rbx+blacklist_first_ofs], r12
	mov	[rbx+blacklist_last_ofs], r12
	pop	r12 rbx
	epilog
calign
.alreadyhere:
	pop	r12 rbx
	epilog

end if

if used blacklist$remove | defined include_everything
	; two arguments: rdi == blacklist object, rsi == key
falign
blacklist$remove:
	prolog	blacklist$remove
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdi, [rdi+blacklist_map_ofs]
	call	unsignedmap$find_value
	test	eax, eax
	jz	.nobodyhome
	mov	rdi, [rbx+blacklist_map_ofs]
	mov	rsi, r12
	mov	r12, rdx
	call	unsignedmap$erase
	; unlink it from the list
	cmp	r12, [rbx+blacklist_first_ofs]
	je	.first
	cmp	r12, [rbx+blacklist_last_ofs]
	je	.lastnotfirst
	mov	rdi, [r12+blacklist_item_prev_ofs]
	mov	rsi, [r12+blacklist_item_next_ofs]
	mov	[rdi+blacklist_item_next_ofs], rsi
	mov	[rsi+blacklist_item_prev_ofs], rdi
	mov	rdi, r12
	call	heap$free
	pop	r12 rbx
	epilog
calign
.first:
	cmp	r12, [rbx+blacklist_last_ofs]
	je	.firstandlast
	mov	rdi, [r12+blacklist_item_next_ofs]
	xor	esi, esi
	mov	[rbx+blacklist_first_ofs], rdi
	mov	[rdi+blacklist_item_prev_ofs], rsi
	mov	rdi, r12
	call	heap$free
	pop	r12 rbx
	epilog
calign
.lastnotfirst:
	mov	rdi, [r12+blacklist_item_prev_ofs]
	xor	esi, esi
	mov	[rbx+blacklist_last_ofs], rdi
	mov	[rdi+blacklist_item_next_ofs], rsi
	mov	rdi, r12
	call	heap$free
	pop	r12 rbx
	epilog
calign
.firstandlast:
	xor	esi, esi
	mov	[rbx+blacklist_first_ofs], rsi
	mov	[rbx+blacklist_last_ofs], rsi
	mov	rdi, r12
	call	heap$free
	pop	r12 rbx
	epilog
calign
.nobodyhome:
	pop	r12 rbx
	epilog

end if

if used blacklist$check | defined include_everything
	; two arguments: rdi == blacklist object, rsi == key
	; returns a bool in eax as to whether or not it is in our map
	; NOTE: if the key is already in our map, its timeout is _reset_ freshly
	; the only way entries get removed is if they are _not_ checked for the blacklist time period
falign
blacklist$check:
	prolog	blacklist$check
	cmp	qword [rdi+blacklist_first_ofs], 0
	je	.nobodyhome
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, [_epoll_tv_secs]
calign
.weed:
	mov	rdi, [rbx+blacklist_first_ofs]
	cmp	[rdi+blacklist_item_timeout_ofs], r13
	ja	.weedcomplete
	mov	rsi, [rdi+blacklist_item_key_ofs]
	mov	rdi, rbx
	call	blacklist$remove
	cmp	qword [rbx+blacklist_first_ofs], 0
	jne	.weed
calign
.weedcomplete:
	mov	rdi, [rbx+blacklist_map_ofs]
	mov	rsi, r12
	call	unsignedmap$find_value
	test	eax, eax
	jz	.nothere
	add	r13, [rbx+blacklist_expiry_ofs]
	mov	r12, rdx
	mov	[rdx+blacklist_item_timeout_ofs], r13
	; unlink it from the list
	cmp	r12, [rbx+blacklist_first_ofs]
	je	.first
	cmp	r12, [rbx+blacklist_last_ofs]
	je	.lastnotfirst
	mov	rdi, [r12+blacklist_item_prev_ofs]
	mov	rsi, [r12+blacklist_item_next_ofs]
	mov	[rdi+blacklist_item_next_ofs], rsi
	mov	[rsi+blacklist_item_prev_ofs], rdi
	jmp	.relink
calign
.first:
	cmp	r12, [rbx+blacklist_last_ofs]
	je	.firstandlast
	mov	rdi, [r12+blacklist_item_next_ofs]
	xor	esi, esi
	mov	[rbx+blacklist_first_ofs], rdi
	mov	[rdi+blacklist_item_prev_ofs], rsi
	jmp	.relink
calign
.lastnotfirst:
	mov	rdi, [r12+blacklist_item_prev_ofs]
	xor	esi, esi
	mov	[rbx+blacklist_last_ofs], rdi
	mov	[rdi+blacklist_item_next_ofs], rsi
	jmp	.relink
calign
.firstandlast:
	xor	esi, esi
	mov	[rbx+blacklist_first_ofs], rsi
	mov	[rbx+blacklist_last_ofs], rsi
calign
.relink:
	; stick it back on the end
	mov	rdi, [rbx+blacklist_last_ofs]
	mov	qword [r12+blacklist_item_next_ofs], 0
	mov	[r12+blacklist_item_prev_ofs], rdi
	test	rdi, rdi
	jz	.firstlast
	mov	[rdi+blacklist_item_next_ofs], r12
	mov	[rbx+blacklist_last_ofs], r12
	mov	eax, 1
	pop	r13 r12 rbx
	epilog
calign
.firstlast:
	mov	[rbx+blacklist_first_ofs], r12
	mov	[rbx+blacklist_last_ofs], r12
	mov	eax, 1
	pop	r13 r12 rbx
	epilog
calign
.nothere:
	xor	eax, eax
	pop	r13 r12 rbx
	epilog
calign
.nobodyhome:
	xor	eax, eax
	epilog

end if


if used blacklist$destroy | defined include_everything
	; single argument in rdi: blacklist object to destroy
falign
blacklist$destroy:
	prolog	blacklist$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+blacklist_map_ofs]
	mov	rsi, .listkill
	call	unsignedmap$clear
	mov	rdi, [rbx+blacklist_map_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
falign
.listkill:
	; called with rdi == key, rsi == value
	mov	rdi, rsi
	call	heap$free
	ret

end if
