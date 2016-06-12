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
	; tui_datagrid.inc: take a json array as a data provider, offer settable display properties
	; allow selection, searching, etc.
	;	
	; requires json
	;

if used tui_datagrid$vtable | defined include_everything

dalign
tui_datagrid$vtable:
        dq      tui_object$cleanup, tui_datagrid$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; AND, we add one for itemselected
	dq	tui_datagrid$itemselected
end if

tui_dgheadercolors_ofs = tui_object_size
tui_dgcolors_ofs = tui_object_size + 8
tui_dgselcolors_ofs = tui_object_size + 16
tui_dgdata_ofs = tui_object_size + 24
tui_dgguts_ofs = tui_object_size + 32
tui_dguser_ofs = tui_object_size + 40			; unused in here

tui_datagrid_size = tui_object_size + 48

tui_vitemselected = tui_vclicked + 8


if used tui_datagrid$init_copy | defined include_everything
	; two parameters: rdi == tui_datagrid we are initialising, rsi == source tui_datagrid
	; this calls tui_object$init_copy, and then copies our own vars
	; it is assumed the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_datagrid$init_copy:
	prolog	tui_datagrid$init_copy
	push	rsi rdi
	call	tui_object$init_copy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rax, [rsi+tui_dgheadercolors_ofs]
	mov	rcx, [rsi+tui_dgcolors_ofs]
	mov	rdx, [rsi+tui_dgselcolors_ofs]
	mov	[rdi+tui_dgheadercolors_ofs], rax
	mov	[rdi+tui_dgcolors_ofs], rcx
	mov	[rdi+tui_dgselcolors_ofs], rdx
	mov	qword [rdi+tui_dgdata_ofs], 0
	mov	qword [rdi+tui_dgguts_ofs], 0
	call	tui_datagrid$nvsetup
	pop	rdi rsi
	epilog
end if

if used tui_datagrid$new_copy | defined include_everything
	; single argument in rdi == tui_datagrid we are making a copy of
	; returns new tui_datagrid copy in rax
falign
tui_datagrid$new_copy:
	prolog	tui_datagrid$new_copy
	push	rdi
	mov	edi, tui_datagrid_size
	call	heap$alloc
	mov	qword [rax], tui_datagrid$vtable
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	[rsp], rax
	call	tui_datagrid$init_copy
	mov	rax, [rsp]
	epilog
end if


if used tui_datagrid$init_rect | defined include_everything
	; five parameters: rdi == tui_datagrid we are initialising, rsi == pointer to a bounds rect, edx == headercolors, ecx == colors, r8d == selcolors
	; this calls tui_object$init_rect, and then sets our own vars
	; it is assumed the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_datagrid$init_rect:
	prolog	tui_datagrid$init_rect
	push	r8 rcx rdx rdi
	call	tui_object$init_rect
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	r8, [rsp+24]
	mov	[rdi+tui_dgheadercolors_ofs], rdx
	mov	[rdi+tui_dgcolors_ofs], rcx
	mov	[rdi+tui_dgselcolors_ofs], r8
	mov	qword [rdi+tui_dgdata_ofs], 0
	mov	qword [rdi+tui_dgguts_ofs], 0
	call	tui_datagrid$nvsetup
	add	rsp, 32
	epilog
end if


if used tui_datagrid$new_rect | defined include_everything
	; four parameters: rdi == pointer to a bounds rect, esi == headercolors, edx == colors, ecx == selcolors
	; returns a newly allocated tui_datagrid in rax
falign
tui_datagrid$new_rect:
	prolog	tui_datagrid$new_rect
	push	rdi rsi rdx rcx
	mov	edi, tui_datagrid_size
	call	heap$alloc
	mov	qword [rax], tui_datagrid$vtable
	pop	r8 rcx rdx rsi
	mov	rdi, rax
	push	rax
	call	tui_datagrid$init_rect
	pop	rax
	epilog
end if

if used tui_datagrid$init_id | defined include_everything
	; six parameters: rdi == tui_datagrid we are initialising, esi == width, xmm0 == heightperc, edx == headercolors, ecx == colors, r8d == selcolors
	; this calls tui_object$init_id, and then sets our own vars
	; it is assumed the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_datagrid$init_id:
	prolog	tui_datagrid$init_id
	push	r8 rcx rdx rdi
	call	tui_object$init_id
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	r8, [rsp+24]
	mov	[rdi+tui_dgheadercolors_ofs], rdx
	mov	[rdi+tui_dgcolors_ofs], rcx
	mov	[rdi+tui_dgselcolors_ofs], r8
	mov	qword [rdi+tui_dgdata_ofs], 0
	mov	qword [rdi+tui_dgguts_ofs], 0
	call	tui_datagrid$nvsetup
	add	rsp, 32
	epilog
end if

if used tui_datagrid$new_id | defined include_everything
	; five parameters: edi == width, xmm0 == heightperc, esi == headercolors, edx == colors, ecx == selcolors
	; returns a newly allocated tui_datagrid in rax
falign
tui_datagrid$new_id:
	prolog	tui_datagrid$new_id
	push	rdi rsi rdx rcx
	mov	edi, tui_datagrid_size
	call	heap$alloc
	mov	qword [rax], tui_datagrid$vtable
	pop	r8 rcx rdx rsi
	mov	rdi, rax
	push	rax
	call	tui_datagrid$init_id
	pop	rax
	epilog
end if


if used tui_datagrid$init_di | defined include_everything
	; six parameters: rdi == tui_datagrid we are initialising, xmm0 == widthperc, esi == height, edx == headercolors, ecx == colors, r8d == selcolors
	; this calls tui_object$init_di, and then sets our own vars
	; it is assumed the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_datagrid$init_di:
	prolog	tui_datagrid$init_di
	push	r8 rcx rdx rdi
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	r8, [rsp+24]
	mov	[rdi+tui_dgheadercolors_ofs], rdx
	mov	[rdi+tui_dgcolors_ofs], rcx
	mov	[rdi+tui_dgselcolors_ofs], r8
	mov	qword [rdi+tui_dgdata_ofs], 0
	mov	qword [rdi+tui_dgguts_ofs], 0
	call	tui_datagrid$nvsetup
	add	rsp, 32
	epilog
end if

if used tui_datagrid$new_di | defined include_everything
	; five parameters: xmm0 == widthperc, edi == height, esi == headercolors, edx == colors, ecx == selcolors
	; returns a newly allocated tui_datagrid in rax
falign
tui_datagrid$new_di:
	prolog	tui_datagrid$new_di
	push	rdi rsi rdx rcx
	mov	edi, tui_datagrid_size
	call	heap$alloc
	mov	qword [rax], tui_datagrid$vtable
	pop	r8 rcx rdx rsi
	mov	rdi, rax
	push	rax
	call	tui_datagrid$init_di
	pop	rax
	epilog
end if


if used tui_datagrid$init_dd | defined include_everything
	; six parameters: rdi == tui_datagrid we are initialising, xmm0 == widthperc, xmm1 == heightperc, esi == headercolors, edx == colors, ecx == selcolors
	; this calls tui_object$init_dd, and then sets our own vars
	; it is assumed the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_datagrid$init_dd:
	prolog	tui_datagrid$init_dd
	push	rcx rdx rsi rdi
	call	tui_object$init_dd
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	[rdi+tui_dgheadercolors_ofs], rsi
	mov	[rdi+tui_dgcolors_ofs], rdx
	mov	[rdi+tui_dgselcolors_ofs], rcx
	mov	qword [rdi+tui_dgdata_ofs], 0
	mov	qword [rdi+tui_dgguts_ofs], 0
	call	tui_datagrid$nvsetup
	add	rsp, 32
	epilog
end if


if used tui_datagrid$new_dd | defined include_everything
	; five parameters: xmm0 == widthperc, xmm1 == heightperc, edi == headercolors, esi == colors, edx == selcolors
	; returns a newly allocated tui_datagrid in rax
falign
tui_datagrid$new_dd:
	prolog	tui_datagrid$new_dd
	push	rdi rsi rdx
	mov	edi, tui_datagrid_size
	call	heap$alloc
	mov	qword [rax], tui_datagrid$vtable
	pop	rcx rdx rsi
	mov	rdi, rax
	push	rax
	call	tui_datagrid$init_dd
	pop	rax
	epilog
end if


if used tui_datagrid$init_ii | defined include_everything
	; six parameters: rdi == tui_datagrid we are initialising, esi == width, edx == height, ecx == headercolors, r8d == colors, r9d == selcolors
	; this calls tui_object$init_ii, and then sets our own vars
	; it is assumed the pointer passed here already has (or will have) a valid vtable pointer
falign
tui_datagrid$init_ii:
	prolog	tui_datagrid$init_ii
	push	r9 r8 rcx rdi
	call	tui_object$init_ii
	mov	rdi, [rsp]
	mov	rcx, [rsp+8]
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	[rdi+tui_dgheadercolors_ofs], rcx
	mov	[rdi+tui_dgcolors_ofs], r8
	mov	[rdi+tui_dgselcolors_ofs], r9
	mov	qword [rdi+tui_dgdata_ofs], 0
	mov	qword [rdi+tui_dgguts_ofs], 0
	call	tui_datagrid$nvsetup
	add	rsp, 32
	epilog
end if

if used tui_datagrid$new_ii | defined include_everything
	; five parameters: edi == width, esi == height, edx == headercolors, ecx == colors, r8d == selcolors
	; returns a newly allocated tui_datagrid in rax
falign
tui_datagrid$new_ii:
	prolog	tui_datagrid$new_ii
	push	rdi rsi rdx rcx r8
	mov	edi, tui_datagrid_size
	call	heap$alloc
	mov	qword [rax], tui_datagrid$vtable
	pop	r9 r8 rcx rdx rsi
	mov	rdi, rax
	push	rax
	call	tui_datagrid$init_ii
	pop	rax
	epilog
end if

	; include the "private" gridguts goods
if public_funcs & used tui_datagrid$vtable
public tui_gridguts
tui_gridguts:
end if
	include 'tui_gridguts.inc'

if used tui_datagrid$nvsetup | defined include_everything
	; single argument in rdi: the tui_datagrid object we are setting up
falign
tui_datagrid$nvsetup:
	prolog	tui_datagrid$nvsetup
	push	rdi
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	call	tui_gridguts$new
	pop	rdi
	mov	[rdi+tui_dgguts_ofs], rax	; save it in our datagrid object
	mov	rsi, rax		; the gridguts child
	mov	rdx, [rdi]		; our own vmethod table
	call	qword [rdx+tui_vappendchild]
	epilog
end if


if used tui_datagrid$clone | defined include_everything
	; single argument in rdi: the tui_datagrid to clone/make a copy of
	; returns new tui_datagrid copy in rax
falign
tui_datagrid$clone:
	prolog	tui_datagrid$clone
	call	tui_datagrid$new_copy
	epilog
end if

if used tui_datagrid$itemselected | defined include_everything
	; two arguments: rdi == tui_datagrid object, rsi == json object that was selected
	; this is the default implementation, which doesn't actually DO anything.
falign
tui_datagrid$itemselected:
	prolog	tui_datagrid$itemselected
	epilog
end if

if used tui_datagrid$nvgetselected | defined include_everything
	; single argument: rdi == tui_datagrid object
	; returns the _actual_ json for the currently selected index
	; you should probably not modify it :-)
	; returns null if none is selected
falign
tui_datagrid$nvgetselected:
	prolog	tui_datagrid$nvgetselected
	mov	rdi, [rdi+tui_dgguts_ofs]
	call	tui_gridguts$nvgetselected
	epilog

end if


if used tui_datagrid$nvaddproperty_i | defined include_everything
	; five arguments: rdi == tui_datagrid object, rsi == string name, edx == integer width, ecx == text alignment, r8 == string propertyname
falign
tui_datagrid$nvaddproperty_i:
	prolog	tui_datagrid$nvaddproperty_i
	mov	rdi, [rdi+tui_dgguts_ofs]
	call	tui_gridguts$nvaddproperty_i
	epilog
end if

if used tui_datagrid$nvaddproperty_d | defined include_everything
	; five arguments: rdi == tui_datagrid object, rsi == string name, xmm0 == double widthperc, edx == text alignment, rcx == string propertyname
falign
tui_datagrid$nvaddproperty_d:
	prolog	tui_datagrid$nvaddproperty_d
	mov	rdi, [rdi+tui_dgguts_ofs]
	call	tui_gridguts$nvaddproperty_d
	epilog
end if

if used tui_datagrid$nvsetdata | defined include_everything
	; two arguments: rdi == tui_datagrid object, rsi == json array object (we assume ownership of this set, it _must_ be a json_array of json objects!)
falign
tui_datagrid$nvsetdata:
	prolog	tui_datagrid$nvsetdata
	mov	rdi, [rdi+tui_dgguts_ofs]
	call	tui_gridguts$nvsetdata
	epilog
end if


if used tui_datagrid$nvsetdata_notowner | defined include_everything
	; two arguments: rdi == tui_datagrid object, rsi == json array object
	; same as normal, but a) we do NOT make a copy of it, and b) when we are destroyed, we do _not_ clean it up (thus, it must be owned/cleaned up by
	; the caller/someone else).. the first normal function assumes ownership and will clean it up when it dies
falign
tui_datagrid$nvsetdata_notowner:
	prolog	tui_datagrid$nvsetdata_notowner
	mov	rdi, [rdi+tui_dgguts_ofs]
	call	tui_gridguts$nvsetdata_notowner
	epilog

end if
