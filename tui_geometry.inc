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
	; tui_geometry.inc: various geometry helpers for our TUI goodies
	; 
	; this is mainly here for reference, though in some cases I do use the
	; functions directly, mostly the math is done directly inline
	;


; the required bytes to hold a point:
point_size = 8

if used point$new | defined include_everything
	; no arguments, returns a heap$alloc'd whopping 8 bytes of space
	; zero-filled (x & y are 0)
falign
point$new:
	prolog	point$new
	mov	edi, 8
	call	heap$alloc
	mov	qword [rax], 0
	epilog
end if

if used point$destroy | defined include_everything
	; reference only, if you want to destroy/delete it just heap$free it
falign
point$destroy:
	prolog	point$destroy
	call	heap$free
	epilog
end if

if used point$new_xy | defined include_everything
	; two arguments: x in edi, y in esi, returns heap$allocated
falign
point$new_xy:
	prolog	point$new_xy
	sub	rsp, 8
	mov	[rsp], edi
	mov	[rsp+4], esi
	mov	edi, 8
	call	heap$alloc
	mov	edi, [rsp]
	mov	[rax], edi
	mov	esi, [rsp+4]
	mov	[rax+4], esi
	add	rsp, 8
	epilog
end if

if used point$new_copy | defined include_everything
	; single argument: point buffer in rdi, returns heap$allocated copy of it
falign
point$new_copy:
	prolog	point$new_copy
	push	rdi
	mov	edi, 8
	call	heap$alloc
	pop	rdi
	mov	rsi, [rdi]
	mov	[rax], rsi
	epilog
end if


if used point$init_xy | defined include_everything
	; three arguments: point buffer in rdi, x in esi, y in edx
	; reference only, you should be doing this yourself, haha
falign
point$init_xy:
	prolog	point$init_xy
	mov	[rdi], esi
	mov	[rdi+4], edx
	epilog
end if


if used point$init_copy | defined include_everything
	; two arguments: point buffer in rdi (destination), point buffer in rsi (source)
	; reference only, you should be doing this yourself, haha
falign
point$init_copy:
	prolog	point$init_copy
	mov	rdx, [rsi]
	mov	[rdi], rdx
	epilog
end if

if used point$add | defined include_everything
	; two arguments: point buffer in rdi (destination), point buffer in rsi (source)
falign
point$add:
	prolog	point$add
	; due to 32bit overflow, have to do them separately
	mov	edx, [rsi]
	mov	ecx, [rsi+4]
	add	dword [rdi], edx
	add	dword [rdi+4], ecx
	epilog
end if


if used point$subtract | defined include_everything
	; two arguments: point buffer in rdi (destination), point buffer in rsi (source)
falign
point$subtract:
	prolog	point$subtract
	mov	edx, [rsi]
	mov	ecx, [rsi+4]
	sub	dword [rdi], edx
	sub	dword [rdi+4], ecx
	epilog
end if


if used point$equals | defined include_everything
	; two arguments: point buffer in rdi, point buffer in rsi
	; returns zero in eax if not, 1 in eax if so
falign
point$equals:
	prolog	point$equals
	mov	rdx, [rsi]
	cmp	[rdi], rdx
	je	.retone
	xor	eax, eax
	epilog
calign
.retone:
	mov	eax, 1
	epilog
end if

	; similar to point insofar as being mostly for reference

rect_size = point_size * 2

if used rect$new | defined include_everything
	; no arguments, returns a heap$alloc'd zeroed rect
falign
rect$new:
	prolog	rect$new
	mov	edi, rect_size
	call	heap$alloc
	mov	qword [rax], 0
	mov	qword [rax+8], 0
	epilog
end if


if used rect$new_coords | defined include_everything
	; edi, esi, edx, ecx == ax, ay, bx, by
	; returns heap$alloc'd new rect
falign
rect$new_coords:
	prolog	rect$new_coords
	sub	rsp, rect_size
	mov	[rsp], edi
	mov	edi, rect_size
	mov	[rsp+4], esi
	mov	[rsp+8], edx
	mov	[rsp+12], ecx
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rax], rdi
	mov	[rax+8], rsi
	add	rsp, rect_size
	epilog
end if


if used rect$new_rect | defined include_everything
	; single argument in rdi: rect (source)
	; returns heap$alloc'd new rect
falign
rect$new_rect:
	prolog	rect$new_rect
	push	rdi
	mov	edi, rect_size
	call	heap$alloc
	pop	rdi
	mov	rsi, [rdi]
	mov	rdx, [rdi+8]
	mov	[rax], rsi
	mov	[rax+8], rdx
	epilog
end if

if used rect$new_points | defined include_everything
	; two arguments: point in rdi, point in rsi
	; returns new heap$alloc'd rect
falign
rect$new_points:
	prolog	rect$new_points
	mov	rdx, [rdi]
	mov	rcx, [rsi]
	sub	rsp, rect_size
	mov	[rsp], rdx
	mov	[rsp+8], rcx
	mov	edi, rect_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rax], rdi
	mov	[rax+8], rsi
	add	rsp, rect_size
	epilog
end if


if used rect$init | defined include_everything
	; single argument: rect in rdi
	; just zeroes it
falign
rect$init:
	prolog	rect$init
	mov	qword [rdi], 0
	mov	qword [rdi+8], 0
	epilog
end if


if used rect$init_coords | defined include_everything
	; five arguments: rect buffer in rdi, then esi, edx, ecx, r8d == ax, ay, bx, by
falign
rect$init_coords:
	prolog	rect$init_coords
	mov	[rdi], esi
	mov	[rdi+4], edx
	mov	[rdi+8], ecx
	mov	[rdi+12], r8d
	epilog
end if


if used rect$init_rect | defined include_everything
	; two arguments: rect buffer in rdi (destination), rect buffer in rsi (source)
falign
rect$init_rect:
	prolog	rect$init_rect
	mov	rdx, [rsi]
	mov	rcx, [rsi+8]
	mov	[rdi], rdx
	mov	[rdi+8], rcx
	epilog
end if


if used rect$init_points | defined include_everything
	; three arguments: rect buffer in rdi, point in rsi, point in rdx
falign
rect$init_points:
	prolog	rect$init_points
	mov	rcx, [rsi]
	mov	r8, [rdx]
	mov	[rdi], rcx
	mov	[rdi+8], r8
	epilog
end if

if used rect$width | defined include_everything
	; single argument: rect in rdi
	; returns width in eax
falign
rect$width:
	prolog	rect$width
	mov	eax, [rdi+8]
	sub	eax, dword [rdi]
	epilog
end if


if used rect$height | defined include_everything
	; single argument: rect in rdi
	; returns height in eax
falign
rect$height:
	prolog	rect$height
	mov	eax, [rdi+12]
	sub	eax, dword [rdi+4]
	epilog
end if

if used rect$dims_into | defined include_everything
	; two arguments: rect buffer in rdi, point (destination) buffer in rdi
falign
rect$dims_into:
	prolog	rect$dims_into
	mov	eax, [rdi+8]
	sub	eax, dword [rdi]	; width
	mov	ecx, [rdi+12]
	sub	ecx, dword [rdi+4]	; height
	mov	[rdi], eax
	mov	[rdi+4], ecx
	epilog
end if

if used rect$move | defined include_everything
	; three arguments: rect buffer in rdi, delta x in esi, delta y in edx
falign
rect$move:
	prolog	rect$move
	add	dword [rdi], esi
	add	dword [rdi+4], edx
	add	dword [rdi+8], esi
	add	dword [rdi+12], edx
	epilog
end if

if used rect$grow | defined include_everything
	; three arguments: rect buffer in rdi, delta x in esi, delta y in edx
falign
rect$grow:
	prolog	rect$grow
	sub	dword [rdi], esi
	sub	dword [rdi+4], edx
	add	dword [rdi+8], esi
	add	dword [rdi+12], edx
	epilog
end if

if used rect$intersect | defined include_everything
	; two arguments: rect buffer in rdi (dest), rect buffer in rsi
falign
rect$intersect:
	prolog	rect$intersect
	mov	edx, [rdi]		; a.x
	mov	ecx, [rdi+8]		; b.x
	mov	r8d, [rsi]		; r.a.x
	mov	r9d, [rsi+8]		; r.b.x
	cmp	edx, r8d
	cmovl	edx, r8d		; a.x = max(a.x, r.a.x)
	cmp	ecx, r9d
	cmovg	ecx, r9d		; b.x = min(b.x, r.b.x)
	mov	[rdi], edx
	mov	[rdi+8], ecx

	mov	edx, [rdi+4]		; a.y
	mov	ecx, [rdi+12]		; b.y
	mov	r8d, [rsi+4]		; r.a.y
	mov	r9d, [rsi+12]		; r.b.y
	cmp	edx, r8d
	cmovl	edx, r8d		; a.y = max(a.y, r.a.y)
	cmp	ecx, r9d
	cmovg	ecx, r9d		; b.y = min(b.y, r.b.y)
	mov	[rdi+4], edx
	mov	[rdi+12], ecx
	epilog
end if

if used rect$union | defined include_everything
	; two arguments: rect buffer in rdi (dest), rect buffer in rsi
falign
rect$union:
	prolog	rect$union
	mov	edx, [rdi]		; a.x
	mov	ecx, [rdi+8]		; b.x
	mov	r8d, [rsi]		; r.a.x
	mov	r9d, [rsi+8]		; r.b.x
	cmp	edx, r8d
	cmovg	edx, r8d		; a.x = min(a.x, r.a.x)
	cmp	ecx, r9d
	cmovl	ecx, r9d		; b.x = max(b.x, r.b.x)
	mov	[rdi], edx
	mov	[rdi+8], ecx

	mov	edx, [rdi+4]		; a.y
	mov	ecx, [rdi+12]		; b.y
	mov	r8d, [rsi+4]		; r.a.y
	mov	r9d, [rsi+12]		; r.b.y
	cmp	edx, r8d
	cmovg	edx, r8d		; a.y = min(a.y, r.a.y)
	cmp	ecx, r9d
	cmovl	ecx, r9d		; b.y = max(b.y, r.b.y)
	mov	[rdi+4], edx
	mov	[rdi+12], ecx
	epilog
end if

if used rect$contains | defined include_everything
	; two arguments: rect buffer in rdi, point buffer in rsi
	; returns zero in eax if not, 1 in eax if so
falign
rect$contains:
	prolog	rect$contains
	mov	edx, [rsi]		; point.x
	mov	ecx, [rsi+4]		; point.y
	cmp	edx, dword [rdi]
	jl	.nope
	cmp	edx, dword [rdi+8]
	jge	.nope
	cmp	ecx, dword [rdi+4]
	jl	.nope
	cmp	ecx, dword [rdi+12]
	jge	.nope
	mov	eax, 1
	epilog
calign
.nope:
	xor	eax, eax
	epilog
end if

if used rect$contains_xy | defined include_everything
	; three arguments: rect buffer in rdi, x in esi, y in edx
	; returns zero in eax if not, 1 in eax if so
falign
rect$contains_xy:
	prolog	rect$contains_xy
	cmp	esi, dword [rdi]
	jl	.nope
	cmp	esi, dword [rdi+8]
	jge	.nope
	cmp	edx, dword [rdi+4]
	jl	.nope
	cmp	edx, dword [rdi+12]
	jge	.nope
	mov	eax, 1
	epilog
calign
.nope:
	xor	eax, eax
	epilog
end if

if used rect$equals | defined include_everything
	; two arguments: rect buffer in rdi, rect buffer in rsi
	; returns zero in eax if not, 1 in eax if so
falign
rect$equals:
	prolog	rect$equals
	mov	rdx, [rsi]
	mov	rcx, [rsi+8]
	cmp	rdx, qword [rdi]
	jne	.nope
	cmp	rcx, qword [rdi+8]
	jne	.nope
	mov	eax, 1
	epilog
calign
.nope:
	xor	eax, eax
	epilog
end if

if used rect$empty | defined include_everything
	; single argument: rect buffer in rdi
	; returns zero in eax if not, 1 in eax if so
falign
rect$empty:
	prolog	rect$empty
	mov	esi, dword [rdi]
	mov	edx, dword [rdi+4]
	cmp	esi, dword [rdi+8]
	jl	.nope
	cmp	edx, dword [rdi+12]
	jl	.nope
	mov	eax, 1
	epilog
calign
.nope:
	xor	eax, eax
	epilog
end if
