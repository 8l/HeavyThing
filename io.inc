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
	; io.inc: a do-nothing input/output "base object"
	; 
	; base virtual method functionality for chained/unchained io
	; 
	; destroy/clone/send calls populate FORWARD through the links
	; receive/connected/error/timeout calls populate BACKWARD
	;


io_vmethods_ofs = 0
io_parent_ofs = 8
io_child_ofs = 16

io_base_size = 24


	; the virtual methods we are interested in:
io_vdestroy = 0
io_vclone = 8
io_vconnected = 16
io_vsend = 24
io_vreceive = 32
io_verror = 40
io_vtimeout = 48


if used io$vtable | defined include_everything

dalign
io$vtable:
	dq	io$destroy, io$clone, io$connected, io$send, io$receive, io$error, io$timeout

end if


	; our implementations for each of the aforementioned, along with a
	; default constructor put here mainly for reference:

if used io$new | defined include_everything
	; no arguments, returns a new io object with its vtable pointed correctly
falign
io$new:
	prolog	io$new
	mov	edi, io_base_size
	call	heap$alloc_clear	; parent/child set to null for us
	mov	qword [rax], io$vtable
	epilog

end if

if used io$addchild | defined include_everything
	; two arguments: rdi == parent, rsi == child
falign
io$addchild:
	prolog	io$addchild
	mov	[rdi+io_child_ofs], rsi
	mov	[rsi+io_parent_ofs], rdi
	epilog
end if

if used io$destroy | defined include_everything
	; single argument in rdi: our io object

	; NOTE: descendents of this should call io$destroy directly, _LAST_ (which will then free the pointer)
falign
io$destroy:
	prolog	io$destroy
	; NOTE: we do not walk UP the tree, our job is only to destroy ourself and our child if any
	; for the real destroy calls, it is up to them to walk the tree beforehand such that this
	; happens correctly
	; 
	cmp	qword [rdi+io_child_ofs], 0
	je	.nochild
	; otherwise, we have a child
	push	rdi
	mov	rdi, [rdi+io_child_ofs]
	mov	rsi, [rdi]	; virtual method pointer location
	call	qword [rsi+io_vdestroy]
	pop	rdi
calign
.nochild:
	call	heap$free
	epilog

end if

if used io$clone | defined include_everything
	; single argument in rdi: io object to clone
	; returns new (copy), with new _copies_ of our child if any
	; NOTE: descendents of this need to do the same goods (child/parent clone/set)
falign
io$clone:
	prolog	io$clone
	cmp	qword [rdi+io_child_ofs], 0
	je	.nochild
	push	rdi
	mov	rdi, [rdi+io_child_ofs]
	mov	rsi, [rdi]	; virtual method pointer location
	call	qword [rsi+io_vclone]
	; so now we have rax == our child clone, rdi is our original
	push	rax
	mov	edi, io_base_size
	call	heap$alloc
	pop	rsi		; child
	pop	rdx		; our original
	mov	rcx, [rdx]	; our original's vmethod pointer
	mov	[rax], rcx
	mov	qword [rax+io_parent_ofs], 0	; parent = null
	mov	[rax+io_child_ofs], rsi		; our child
	mov	[rsi+io_parent_ofs], rax	; set our child's parent to us
	epilog
calign
.nochild:
	push	rdi
	mov	edi, io_base_size
	call	heap$alloc
	xor	esi, esi
	pop	rdx		; our original
	mov	rcx, [rdx]	; our original's vmethod pointer
	mov	[rax], rcx
	mov	[rax+io_parent_ofs], rsi	; parent = null
	mov	[rax+io_child_ofs], rsi		; child = null
	epilog

end if

if used io$connected | defined include_everything
	; single argument in rdi: io object
	; NOTE: for epoll inbounds, rsi/edx will also get populated with the remote address
falign
io$connected:
	prolog	io$connected
	mov	rdi, [rdi+io_parent_ofs]
	test	rdi, rdi
	jnz	.hasparent
	epilog
calign
.hasparent:
	mov	rcx, [rdi]	; virtual method pointer location
	call	qword [rcx+io_vconnected]
	epilog

end if

if used io$send | defined include_everything
	; three arguments: rdi == io object, rsi == ptr to data, rdx == length of same
falign
io$send:
	prolog	io$send
	; if we have a child, populate the call downward, if not, default io$send is a do nothing, so do precisely that
	mov	rdi, [rdi+io_child_ofs]
	test	rdi, rdi
	jnz	.haschild
	epilog
calign
.haschild:
	mov	rcx, [rdi]	; virtual method pointer location
	call	qword [rcx+io_vsend]
	epilog

end if


if used io$receive | defined include_everything
	; three arguments: rdi == io object, rsi == ptr to data, rdx == length of same
	; BOOL return says: if FALSE, don't destroy the objects, if true, destroys the objects (useful for fatal error conditions, etc)
falign
io$receive:
	prolog	io$receive
	; if we have a parent, populate the call upward, if not, default io$receive layer is a do nothing, so do precisely that
	; ensuring our return is false so that we don't get destroyed
	mov	rdi, [rdi+io_parent_ofs]
	test	rdi, rdi
	jnz	.hasparent
	xor	eax, eax
	epilog
calign
.hasparent:
	mov	rcx, [rdi]	; virtual method pointer location
	call	qword [rcx+io_vreceive]
	; let our return == parent's return
	epilog

end if

if used io$error | defined include_everything
	; single argument in rdi: io object
	; this is a notification only, we aren't responsible for destruction of the chain
	; our only mission is to populate the call upward
falign
io$error:
	prolog	io$error
	mov	rdi, [rdi+io_parent_ofs]
	test	rdi, rdi
	jnz	.hasparent
	epilog
calign
.hasparent:
	mov	rsi, [rdi]	; virtual method pointer location
	call	qword [rsi+io_verror]
	epilog

end if

if used io$timeout | defined include_everything
	; single argument in rdi: io object
	; NOTE: the default here is to return FALSE, but if descendents return true, signals death should occur
falign
io$timeout:
	prolog	io$timeout
	; we walk _up_ the tree, calling each one's timeout, if any return true, then we bailout, go to the topmost of the chain
	; and destroy everyone
	mov	rdi, [rdi+io_parent_ofs]
	test	rdi, rdi
	jnz	.hasparent
	xor	eax, eax
	epilog
calign
.hasparent:
	mov	rsi, [rdi]	; virtual method pointer location
	push	rdi
	call	qword [rsi+io_vtimeout]
	pop	rdi
	test	eax, eax
	jnz	.death
	epilog
calign
.death:
	cmp	qword [rdi+io_parent_ofs], 0
	je	.death_topmost
	mov	rdi, [rdi+io_parent_ofs]
	jmp	.death
calign
.death_topmost:
	mov	rsi, [rdi]	; virtual method pointer location
	call	qword [rsi+io_vdestroy]
	xor	eax, eax	; make sure our actual return is nondestructive
	epilog

end if

if used io$link | defined include_everything
	; two arguments: rdi == io object parent, rsi == io object child
	; all this does is link them together, convenience function for HLL use
falign
io$link:
	prolog	io$link
	mov	[rdi+io_child_ofs], rsi
	mov	[rsi+io_parent_ofs], rdi
	epilog

end if
