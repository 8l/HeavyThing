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
	; tui_object.inc: the base object for all things TUI.
	;
	; every kind of object that needs to display/draw things needs a base
	; set of functionality like draw buffers, positioning, size, children
	; events, etc.
	;
	; this is done in a "pseudo OOP" way, similar to how I did up the
	; epoll vmethod tables.
	;
	; I suppose that means it isn't really pseudo, insofar as I am still
	; doing inheritance and so on, hahah...
	;
	include 'tui_geometry.inc'

	; due to our reliance on epoll$timer goods, our vmethod table
	; must be similar (at least for the first few methods)
	; to epoll's such that we can "fake" being an epoll object even
	; when we are not one

	; this is an "interesting" translation from my perfectly working C++
	; versions, haha... maybe I am 3/4th the way to being properly
	; crazy, HA! (that being said, this assembler version is far and away better)

	; some notes here on layout goods:
	; if layout == vertical, then we pay attention to horizontal alignment (left, center, right)
	; if layout == horizontal, then we pay attention to vertical alignment (top, middle, bottom)

	; further notes/caution/advice on percentage based width/height calculations:
	; there are many ways to introduce rounding-based errors into the mix. we take care of the case
	; where rounding results in one too many, but for the other way, where we end up rounding away
	; one, care/screwing around must be taken to make sure that resizing through all of your
	; possibilities yields the right result. the tui_simpleauth is a good example of this, where
	; the top third of screenspace i declare as 50% high, then a fixed height midsection, and then
	; the bottom third as another 51%, which admittedly seems weird on its face, but this eliminates
	; the rounding issue for available space left (all depends on how you are slicing them up as to
	; whether this really matters or not)
	;

if used tui_object$vtable | used tui_object$default_vtable | defined include_everything

	; so our base tui_object default vtable is:
dalign
tui_object$default_vtable:
	dq	tui_object$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

if used tui_object$simple_vtable | defined include_everything

	; this one can be used directly, but only for nonfunctional tui_object direct descendents (see tui_spacers.inc for examples on why this is necessary)
dalign
tui_object$simple_vtable:
	dq	tui_object$cleanup, tui_object$simple_clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked


end if

	; descendents can swap in their own virtual methods just like the epoll layer.

	; every tui_object contains the following variables:
tui_vtable_ofs = 0		; pointer to a vtable
tui_bounds_ofs = 8		; rect itself, not a pointer
	tui_bounds_ax_ofs = 8
	tui_bounds_ay_ofs = 12
	tui_bounds_bx_ofs = 16
	tui_bounds_by_ofs = 20
tui_width_ofs = 24		; dd
tui_widthperc_ofs = 28		; dq (double)
tui_height_ofs = 36		; dd
tui_heightperc_ofs = 40		; dq (double)
tui_visible_ofs = 48		; dd
tui_includeinlayout_ofs = 52	; dd
tui_absolutex_ofs = 56		; dd
tui_absolutey_ofs = 60		; dd
tui_text_ofs = 64		; dq (pointer to buffer)
tui_attr_ofs = 72		; dq (pointer to buffer)
tui_focus_ofs = 80		; dq (pointer to a tui_object or descendent)
tui_parent_ofs = 88		; dq (pointer to a tui_object or descendent)
tui_layout_ofs = 96		; dd
tui_horizalign_ofs = 100	; dd
tui_vertalign_ofs = 104		; dd
tui_bastardglue_ofs = 108	; dd
tui_displayname_ofs = 112	; dq
tui_children_ofs = 120		; dq (list$)
tui_bastards_ofs = 128		; dq (list$)
tui_dropshadow_ofs = 136	; dd
tui_scroll_ofs = 140		; two dd's (a Point)

tui_object_size = 148

	; our layout constants
tui_layout_vertical = 0
tui_layout_horizontal = 1
tui_layout_absolute = 2
	; our horizontal alignment constants
tui_align_left = 0
tui_align_center = 1
tui_align_right = 2
	; our vertical alignment constants
tui_align_top = 0
tui_align_middle = 1
tui_align_bottom = 2

	; our virtual method table/function call offsets:
tui_vcleanup = 0
tui_vclone = 8
tui_vdraw = 16
tui_vredraw = 24
tui_vupdatedisplaylist = 32
tui_vsizechanged = 40
tui_vtimer = 48
tui_vlayoutchanged = 56
tui_vmove = 64
tui_vsetfocus = 72
tui_vgotfocus = 80
tui_vlostfocus = 88
tui_vkeyevent = 96
tui_vdomodal = 104
tui_vendmodal = 112
tui_vexit = 120
tui_vcalcbounds = 128
tui_vcalcchildbounds = 136
tui_vappendchild = 144
tui_vappendbastard = 152
tui_vprependchild = 160
tui_vcontains = 168
tui_vgetchildindex = 176
tui_vremovechild = 184
tui_vremovebastard = 192
tui_vremoveallchildren = 200
tui_vremoveallbastards = 208
tui_vgetobjectsunderpoint = 216
tui_vflatten = 224
tui_vfirekeyevent = 232
tui_vontab = 240
tui_vonshifttab = 248
tui_vsetcursor = 256
tui_vshowcursor = 264
tui_vhidecursor = 272
tui_vclick = 280
tui_vclicked = 288


	; some notes here on constructing a tui_object:
	; the base tui_object is not meant to be constructed by itself
	; and the reason of course for that is simply because
	; you would get zero functionality from the base layer (nothing to
	; draw, nothing to do, etc)
	; as a result, DESCENDENT objects get constructors, and then
	; call the tui_object's appropriate initialization methods
	; as such, there are not tui_object$new... functions, only
	; tui_object$init functions

	; ALL DESCENDENTS _MUST_ set their own vtable! (these init funcs don't do it for you)
	; it can be set _before_ or after calling the init functions herein
	; we do not overwrite/zero/clear the first 8 bytes of the object, thus leaving it
	; wholly uninitialised for the descendents to fill

if used tui_object$init_defaults | defined include_everything
	; single parameter in rdi: the tui_object
falign
tui_object$init_defaults:
	prolog	tui_object$init_defaults
	push	rdi
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_object_size - 8
	call	memset32
	mov	rdi, [rsp]
	mov	dword [rdi+tui_visible_ofs], 1
	mov	dword [rdi+tui_includeinlayout_ofs], 1
	mov	dword [rdi+tui_absolutex_ofs], -1
	mov	dword [rdi+tui_absolutey_ofs], -1
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_bastards_ofs], rax
	pop	rdi
	epilog
end if

if used tui_object$simple_clone | defined include_everything
	; single argument in rdi: tui object we are "cloning", noting here that this is ONLY useful for tui_object's acting as tui_objects, heh
	; see tui_spacers.inc for examples of why this is useful
falign
tui_object$simple_clone:
	prolog	tui_object$simple_clone
	push	rdi
	mov	edi, tui_object_size
	call	heap$alloc
	mov	rsi, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	call	tui_object$init_copy
	pop	rax
	epilog

end if

if used tui_object$init_copy | defined include_everything
	; two parameters: rdi == tui object we are initialising, rsi == source tui object
	; this copies all static settings, creates new buffers (if width && height nonzero)
	; copies the buffer contents, clones all children using the clone virtual method	
	; creates new dynamic contents... if displayname was non-null, creates a COPY of it
	; (translation: displayname is always a dynamically allocated string if it exists)
falign
tui_object$init_copy:
	prolog	tui_object$init_copy
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+24], r15
	mov	edx, tui_object_size
	call	memcpy
	xor	rcx, rcx
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rdi+tui_text_ofs], rcx
	mov	[rdi+tui_attr_ofs], rcx
	mov	rdx, [rsi+tui_displayname_ofs]
	mov	[rdi+tui_focus_ofs], rcx
	mov	[rdi+tui_parent_ofs], rcx
	mov	[rdi+tui_displayname_ofs], rcx
	test	rdx, rdx
	jz	.nodisplayname
	mov	rdi, rdx
	call	string$copy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rdi+tui_displayname_ofs], rax
calign
.nodisplayname:
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rdi+tui_bastards_ofs], rax

	mov	eax, [rsi+tui_width_ofs]
	mov	ecx, [rsi+tui_height_ofs]
	test	eax, eax
	jz	.nobuffers
	test	ecx, ecx
	jz	.nobuffers
	mul	ecx
	shl	eax, 2
	mov	dword [rsp+16], eax
	mov	edi, eax
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_text_ofs], rax
	mov	edi, dword [rsp+16]
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rdi+tui_attr_ofs], rax
	mov	edx, dword [rsp+16]
	mov	rdi, rax
	mov	rsi, [rsi+tui_attr_ofs]
	call	memcpy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	edx, dword [rsp+16]
	mov	rdi, [rdi+tui_text_ofs]
	mov	rsi, [rsi+tui_text_ofs]
	call	memcpy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
calign
.nobuffers:
	; we have to iterate the list at [rsi+tui_children_ofs]
	; and do vclones for every child there, add it to our own list
	; and set each child's parent to rdi
	; NOTE: we cheat here and use r15 across calls to list$foreach
	; because we know for certain that r15 will remain intact
	mov	r15, rdi
	mov	rdi, [rsi+tui_children_ofs]
	mov	rsi, .childrencopy
	call	list$foreach

	mov	r15, [rsp+24]
	add	rsp, 32
	epilog
calign
.childrencopy:
	; called with a single argument of the tui_object
	mov	rsi, [rdi]	; load its vtable pointer
	call	qword [rsi+tui_vclone]
	; so now we have an rax new cloned copy, we need to set its parent
	mov	[rax+tui_parent_ofs], r15	; see comment above re: cheating
	mov	rdi, [r15+tui_children_ofs]	; ""
	mov	rsi, rax
	call	list$push_back
	ret
	
end if


if used tui_object$init_rect | defined include_everything
	; two arguments, rdi == tui_object we are initialising, and rsi: pointer to a bounds rect
falign
tui_object$init_rect:
	prolog	tui_object$init_rect
	push	rsi rdi		; not really preserved
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_object_size - 8
	call	memset32
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rax, [rsi]
	mov	rcx, [rsi+8]
	mov	[rdi+tui_bounds_ofs], rax
	mov	[rdi+tui_bounds_ofs+8], rcx
	mov	dword [rdi+tui_visible_ofs], 1
	mov	dword [rdi+tui_includeinlayout_ofs], 1
	mov	dword [rdi+tui_absolutex_ofs], -1
	mov	dword [rdi+tui_absolutey_ofs], -1
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_bastards_ofs], rax
	mov	eax, [rdi+tui_bounds_bx_ofs]
	sub	eax, [rdi+tui_bounds_ax_ofs]
	mov	[rdi+tui_width_ofs], eax
	mov	ecx, [rdi+tui_bounds_by_ofs]
	sub	ecx, [rdi+tui_bounds_ay_ofs]
	mov	[rdi+tui_height_ofs], ecx
	test	eax, eax
	jz	.nobuffers
	test	ecx, ecx
	jz	.nobuffers
	mul	ecx
	shl	eax, 2
	mov	dword [rsp+8], eax
	mov	edi, eax
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_text_ofs], rax
	xor	esi, esi
	mov	edx, dword [rsp+8]
	mov	rdi, rax
	call	memset32
	mov	edi, dword [rsp+8]
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_attr_ofs], rax
	xor	esi, esi
	mov	edx, dword [rsp+8]
	mov	rdi, rax
	call	memset32
	add	rsp, 16
	epilog
calign
.nobuffers:
	add	rsp, 16
	epilog
end if


if used tui_object$init_id | defined include_everything
	; three arguments: rdi == tui_object we are initialising, esi == width, xmm0 == heightperc
falign
tui_object$init_id:		; id == integer width, double height
	prolog	tui_object$init_id
	movq	rdx, xmm0
	push	rdx rsi rdi
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_object_size - 8
	call	memset32
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_bastards_ofs], rax
	mov	dword [rdi+tui_visible_ofs], 1
	mov	dword [rdi+tui_includeinlayout_ofs], 1
	mov	dword [rdi+tui_absolutex_ofs], -1
	mov	dword [rdi+tui_absolutey_ofs], -1
	mov	rax, [rsp+8]
	mov	rcx, [rsp+16]
	mov	dword [rdi+tui_width_ofs], eax
	mov	[rdi+tui_heightperc_ofs], rcx
	add	rsp, 24
	epilog
end if

if used tui_object$init_di | defined include_everything
	; three arguments: rdi == tui_object we are initialising, xmm0 == widthperc, esi == height
falign
tui_object$init_di:		; id == double width, integer height
	prolog	tui_object$init_di
	movq	rdx, xmm0
	push	rdx rsi rdi
	; [rsp] == tui_object
	; [rsp+8] == height
	; [rsp+16] == widthperc
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_object_size - 8
	call	memset32
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_bastards_ofs], rax
	mov	dword [rdi+tui_visible_ofs], 1
	mov	dword [rdi+tui_includeinlayout_ofs], 1
	mov	dword [rdi+tui_absolutex_ofs], -1
	mov	dword [rdi+tui_absolutey_ofs], -1
	mov	rax, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_widthperc_ofs], rcx
	mov	dword [rdi+tui_height_ofs], eax
	add	rsp, 24
	epilog
end if

if used tui_object$init_dd | defined include_everything
	; three arguments: rdi == tui_object we are initialising, xmm0 == widthperc, xmm1 == heightperc
falign
tui_object$init_dd:
	prolog	tui_object$init_dd
	movq	rsi, xmm0
	movq	rdx, xmm1
	push	rdx rsi rdi
	; [rsp] == tui_object
	; [rsp+8] == widthperc
	; [rsp+16] == heightperc
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_object_size - 8
	call	memset32
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_bastards_ofs], rax
	mov	dword [rdi+tui_visible_ofs], 1
	mov	dword [rdi+tui_includeinlayout_ofs], 1
	mov	dword [rdi+tui_absolutex_ofs], -1
	mov	dword [rdi+tui_absolutey_ofs], -1
	mov	rax, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_widthperc_ofs], rax
	mov	[rdi+tui_heightperc_ofs], rcx
	add	rsp, 24
	epilog
end if

if used tui_object$init_ii | defined include_everything

	; three arguments: rdi == tui_object we are initialising, esi == width, edx == height
falign
tui_object$init_ii:		; ii == integer width, integer height
	prolog	tui_object$init_ii
	push	rdx rsi rdi
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_object_size - 8
	call	memset32
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_children_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_bastards_ofs], rax
	mov	dword [rdi+tui_visible_ofs], 1
	mov	dword [rdi+tui_includeinlayout_ofs], 1
	mov	dword [rdi+tui_absolutex_ofs], -1
	mov	dword [rdi+tui_absolutey_ofs], -1
	mov	rax, [rsp+8]
	mov	rcx, [rsp+16]
	mov	dword [rdi+tui_width_ofs], eax
	mov	dword [rdi+tui_height_ofs], ecx
	test	eax, eax
	jz	.nobuffers
	test	ecx, ecx
	jz	.nobuffers
	mul	ecx
	shl	eax, 2
	mov	dword [rsp+8], eax
	mov	edi, eax
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_text_ofs], rax
	xor	esi, esi
	mov	edx, dword [rsp+8]
	mov	rdi, rax
	call	memset32
	mov	edi, dword [rsp+8]
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_attr_ofs], rax
	xor	esi, esi
	mov	edx, dword [rsp+8]
	mov	rdi, rax
	call	memset32
	add	rsp, 24
	epilog
calign
.nobuffers:
	add	rsp, 24
	epilog
end if


if used tui_object$cleanup | defined include_everything
	; single argument: rdi == tui_object we are destroying
	; NOTE: this does not free the pointer itself, but heap$free's everything that we allocated
	; and iterates and does delete its children/bastards
falign
tui_object$cleanup:
	prolog	tui_object$cleanup
	push	rdi
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .childclear
	call	list$clear
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_children_ofs]
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_bastards_ofs]
	mov	rsi, .childclear
	call	list$clear
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_bastards_ofs]
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_text_ofs]
	test	rdi, rdi
	jz	.notextbuffer
	call	heap$free
	mov	rsi, [rsp]
	; copy of notextbuffer fallthrough (most common will be no branching in here)
	mov	rdi, [rsi+tui_attr_ofs]
	test	rdi, rdi
	jz	.noattrbuffer
	call	heap$free
	mov	rsi, [rsp]
	; copy of noattrbuffer fallthrough (most common will be no branching in here)
	mov	rdi, [rsi+tui_displayname_ofs]
	test	rdi, rdi
	jnz	.displayname
	pop	rdi
	epilog
calign
.notextbuffer:
	mov	rdi, [rsi+tui_attr_ofs]
	test	rdi, rdi
	jz	.noattrbuffer
	call	heap$free
	mov	rsi, [rsp]
calign
.noattrbuffer:
	mov	rdi, [rsi+tui_displayname_ofs]
	test	rdi, rdi
	jnz	.displayname
	pop	rdi
	epilog
calign
.displayname:
	call	heap$free
	pop	rdi
	epilog

calign
.childclear:
	; called for every child in children/bastards list
	; we DO delete the pointer when we are done
	push	rdi				; save it so we can delete it
	mov	rsi, [rdi]			; load its vmethod table
	call	qword [rsi+tui_vcleanup]	; call its virtual cleanup method
	pop	rdi
	call	heap$free
	ret
end if


if used tui_object$clone | defined include_everything
	; single argument in rdi: our tui_object to make a copy of
	; NOTE: ALL DESCENDENTS OF TUI_OBJECT MUST MAKE A VERSION OF THIS!
	; also note: you must return a NEW heap$alloc'd version of your descendent
	; initialized properly! (make sure to store your vtable!)
	; default one listed here just generates a breakpoint, as it is definitely
	; a programming error for the base one here to be called
falign
tui_object$clone:
	prolog	tui_object$clone
	breakpoint
	epilog
end if

if used tui_object$draw | defined include_everything
	; single argument in rdi: our tui_object
	; each descendent's draw method is responsible for updating its own text/attr buffers
	; but the ACTUAL render routine (which is to say: the terminal/etc responsible for
	; actually outputting the rendered version of the buffers) needs to be called in
	; forward Z order, so if an object updates itself, it needs to call updatedisplaylist
	; when it is done drawing its own buffers
	; consequently, the default implementation listed here only calls the updatedisplaylist
	; virtual method
falign
tui_object$draw:
	prolog	tui_object$draw
	mov	rsi, [rdi]	; load up our vtable
	call	qword [rsi+tui_vupdatedisplaylist]
	epilog
end if


if used tui_object$redraw | defined include_everything
	; single argument in rdi: our tui_object
	; this is called basically telling all objects to draw themselves, and is done
	; when layoutchanged happens, etc all initiated from our terminal/telnet/ssh/etc
	; default is to call our own draw, and then call all of our children's redraw vmethods
falign
tui_object$redraw:
	prolog	tui_object$redraw
	push	rdi
	mov	rsi, [rdi]		; load up our vtable
	call	qword [rsi+tui_vdraw]
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .childredraw
	call	list$foreach
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_bastards_ofs]
	mov	rsi, .childredraw
	call	list$foreach
	pop	rdi
	epilog
calign
.childredraw:
	; called with a single argument in rdi of the child, we need to call its own redraw vmethod
	mov	rsi, [rdi]		; load up its vtable
	call	qword [rsi+tui_vredraw]
	ret
end if

if used tui_object$updatedisplaylist | defined include_everything
	; single argument in rdi: our tui_object
	; this should not need to be overridden by anyone except top-most rendering layers
	; default is to walk up the tree, calling each one's virtual updateDisplayList
	; so that it can forward Z order walk back down and redraw/render everything
falign
tui_object$updatedisplaylist:
	prolog	tui_object$updatedisplaylist
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rsi, [rdi]		; load up the parent's vtable
	call	qword [rsi+tui_vupdatedisplaylist]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$setcursor | defined include_everything
	; three arguments: rdi == our tui_object, esi == x, edx == y
	; default is to walk up the tree finding someone who cares
falign
tui_object$setcursor:
	prolog	tui_object$setcursor
	; if we are scrolled, and a lower object set the cursor with its own bounds.a
	; we need to _adjust_ by our scroll amounts
	mov	eax, [rdi+tui_scroll_ofs]
	mov	ecx, [rdi+tui_scroll_ofs+4]
	sub	esi, eax
	sub	edx, ecx

	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rcx, [rdi]		; load up the parent's vtable
	call	qword [rcx+tui_vsetcursor]
	epilog
calign
.noparent:
	epilog
end if

if used tui_object$showcursor | defined include_everything
	; single argument in rdi: our tui_object
	; default is to walk up the tree finding someone who cares
falign
tui_object$showcursor:
	prolog	tui_object$showcursor
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rsi, [rdi]
	call	qword [rsi+tui_vshowcursor]
	epilog
calign
.noparent:
	epilog
end if

if used tui_object$hidecursor | defined include_everything
	; single argument in rdi: our tui_object
	; default is to walk up the tree finding someone who cares
falign
tui_object$hidecursor:
	prolog	tui_object$hidecursor
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rsi, [rdi]
	call	qword [rsi+tui_vhidecursor]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$timer | defined include_everything
	; single argument in rdi: our tui_object
	; this should be overridden only if you, the descendent, is interested in timer events
	; whatever resolution you asked for, your vmethod of same will get called
	; NOTE: if you return nonzero in eax from this, your object will be automatically
	; destroyed (useful for set and forget type situations)
falign
tui_object$timer:
	prolog	tui_object$timer
	xor	eax, eax		; keep the timer going is the default action
	epilog
end if

if used tui_object$sizechanged | defined include_everything
	; single argument in rdi: our tui_object
	; this is called if our layout goods actually modified our width/height,
	; in which case, we destroy our text/attr buffers if we have them
	; and reallocate them if our new size is nonzero
	; and if new size is nonzero, we also call our virtual draw method
falign
tui_object$sizechanged:
	prolog	tui_object$sizechanged
	sub	rsp, 8
	push	rdi
	mov	rdi, [rdi+tui_text_ofs]
	test	rdi, rdi
	jz	.notextbuffer
	call	heap$free
	mov	rdi, [rsp]
	mov	qword [rdi+tui_text_ofs], 0
	mov	rdi, [rdi+tui_attr_ofs]
	test	rdi, rdi
	jz	.noattrbuffer
	call	heap$free
	mov	rdi, [rsp]
	mov	qword [rdi+tui_attr_ofs], 0
calign
.checknew:
	mov	eax, [rdi+tui_width_ofs]
	mov	ecx, [rdi+tui_height_ofs]
	test	eax, eax
	jz	.nonewone
	test	ecx, ecx
	jz	.nonewone
	mul	ecx
	shl	eax, 2
	mov	dword [rsp+8], eax
	mov	edi, eax
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_text_ofs], rax
	mov	rdi, rax
	xor	esi, esi
	mov	edx, dword [rsp+8]
	call	memset32
	mov	edi, dword [rsp+8]
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rdi+tui_attr_ofs], rax
	mov	rdi, rax
	xor	esi, esi
	mov	edx, dword [rsp+8]
	call	memset32
	; so now our buffers have been allocated
	; we have to call our virtual draw method
	mov	rdi, [rsp]
	mov	rsi, [rdi]	; load up our vtable
	call	qword [rsi+tui_vdraw]
	pop	rdi
	add	rsp, 8
	epilog
calign
.notextbuffer:
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_attr_ofs]
	test	rdi, rdi
	jz	.noattrbuffer
	call	heap$free
	mov	rdi, [rsp]
	mov	qword [rdi+tui_attr_ofs], 0
	jmp	.checknew
calign
.noattrbuffer:
	mov	rdi, [rsp]
	jmp	.checknew
calign
.nonewone:
	pop	rdi
	add	rsp, 8
	epilog
end if


if used tui_object$layoutchanged | defined include_everything
	; single argument in rdi: our tui_object
	; this should not need to be overridden by anyone except topmost objects (terminal, renderers, etc)
	; default action is to walk up the tree calling each one's
falign
tui_object$layoutchanged:
	prolog	tui_object$layoutchanged
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rsi, [rdi]		; load up the parent's vtable
	call	qword [rsi+tui_vlayoutchanged]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$move | defined include_everything
	; three arguments: rdi == our tui_object, esi == delta x, edx == delta y
	; default action is:
	; for absolute-positioned elements, updates absolute_x and absolute_y
	; and updates the bounds rect for all
falign
tui_object$move:
	prolog	tui_object$move
	add	dword [rdi+tui_bounds_ax_ofs], esi
	add	dword [rdi+tui_bounds_ay_ofs], edx
	add	dword [rdi+tui_bounds_bx_ofs], esi
	add	dword [rdi+tui_bounds_by_ofs], edx
	cmp	dword [rdi+tui_absolutex_ofs], -1
	jne	.absolutetoo
	epilog
calign
.absolutetoo:
	add	dword [rdi+tui_absolutex_ofs], esi
	add	dword [rdi+tui_absolutey_ofs], edx
	epilog
end if

if used tui_object$setfocus | defined include_everything
	; two arguments: rdi == our tui_object, rsi == the object that got focus
	; default here is just to set the focus qword
falign
tui_object$setfocus:
	prolog	tui_object$setfocus
	mov	[rdi+tui_focus_ofs], rsi
	epilog
end if

if used tui_object$gotfocus | defined include_everything
	; single argument in rdi: our tui_object
falign
tui_object$gotfocus:
	prolog	tui_object$gotfocus
	epilog
end if


if used tui_object$lostfocus | defined include_everything
	; single argument in rdi: our tui_object
falign
tui_object$lostfocus:
	prolog	tui_object$lostfocus
	epilog
end if


if used tui_object$keyevent | defined include_everything
	; three arguments: rdi == our tui_object, esi == key, edx == esc_key
	; NOTE: return zero in eax if firekeyevent should keep walking up "bubbling"
	; and return nonzero in eax if firekeyevent should STOP
falign
tui_object$keyevent:
	prolog	tui_object$keyevent
	xor	eax, eax
	epilog
end if

if used tui_object$domodal | defined include_everything
	; two arguments: rdi == our tui_object, rsi == child object who wants modal
	; default action here is to walk up the chain until we find someone who cares
	; makes it easy for children who have no idea who their daddy is to get some
	; action, haha
falign
tui_object$domodal:
	prolog	tui_object$domodal
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rdx, [rdi]		; load up the parent's vtable
	; rsi child argument still intact
	call	qword [rdx+tui_vdomodal]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$endmodal | defined include_everything
	; single argument: rdi == our tui_object
	; default action here similar to domodal is just to walk up the chain until
	; we find someone who cares
falign
tui_object$endmodal:
	prolog	tui_object$endmodal
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rdx, [rdi]		; load up the parent's vtable
	call	qword [rdx+tui_vendmodal]
	epilog
calign
.noparent:
	epilog

end if

if used tui_object$exit | defined include_everything
	; two arguments: rdi == our tui_object, esi == exit code
	; default action here is to walk up the tree until we find someone who cares
	; and depending on who that real parent context is will determine what actually
	; happens, e.g. drop connection, syscall_exit, etc
falign
tui_object$exit:
	prolog	tui_object$exit
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rdx, [rdi]
	; esi argument still in tact
	call	qword [rdx+tui_vexit]
	epilog
calign
.noparent:
	epilog
end if

if used tui_object$calcbounds | defined include_everything
	; single argument in rdi: our tui_object
	; default action here should work for most descendent cases
falign
tui_object$calcbounds:
	prolog	tui_object$calcbounds
	push	rdi
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparentyet
	mov	rdx, [rdi]		; load up the parent's vtable
	call	qword [rdx+tui_vcalcchildbounds]
	; now do the same for all our children
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .childbounds
	call	list$foreach
	mov	rdi, [rsp]
	mov	rdi, [rdi+tui_bastards_ofs]
	mov	rsi, .childbounds
	call	list$foreach
	pop	rdi
	epilog
calign
.childbounds:
	; called for every child, we have to call its virtual calcbounds
	mov	rsi, [rdi]		; load up our vtable
	call	qword [rsi+tui_vcalcbounds]
	ret
calign
.noparentyet:
	; if we dont have a parent yet, we haven't been added to anyone WITH bounds yet
	; so we bailout
	pop	rdi
	epilog
end if


if used tui_object$calcchildbounds | defined include_everything
	; single argument in rdi: our tui_object
	; default action here should work for most descendent cases
	; this is responsible for all our fine layout calculations
falign
tui_object$calcchildbounds:
	prolog	tui_object$calcchildbounds
	push	rdi
	mov	rdx, rdi
	mov	rdi, [rdi+tui_bastards_ofs]
	mov	rsi, .bastardsfirst
	call	list$foreach_arg
	mov	rdi, [rsp]
	mov	eax, [rdi+tui_layout_ofs]
	cmp	eax, tui_layout_absolute
	je	.absolutelayout
	cmp	eax, tui_layout_vertical
	je	.verticallayout
	; else, we have a horizontal layout
	cmp	dword [rdi+tui_width_ofs], 0
	jle	.noroom
	; NOTE: we cheat here and use r14 and r15 across calls to list$foreach
	; because we know for certain that r14 and r15 will remain intact
	push	r14 r15
	mov	r14, rdi
	mov	r15d, dword [rdi+tui_width_ofs]		; available width
	xorpd	xmm0, xmm0				; total width percent
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .horizsizescan
	call	list$foreach
	mov	rdx, r14
	xor	r14d, r14d				; relative x
	mov	rdi, [rdx+tui_children_ofs]
	mov	rsi, .horizsizeset
	call	list$foreach_arg
	pop	r15 r14
	pop	rdi
	epilog
calign
.absolutelayout:
	mov	rdx, rdi
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .childabsolute
	call	list$foreach_arg
	pop	rdi
	epilog
calign
.noroom:
	pop	rdi
	epilog
calign
.verticallayout:
	; NOTE: we cheat here and use r14 and r15 across calls to list$foreach
	; because we know for certain that r14 and r15 will remain intact
	cmp	dword [rdi+tui_height_ofs], 0
	jle	.noroom
	push	r14 r15
	mov	r14, rdi
	mov	r15d, dword [rdi+tui_height_ofs]	; available height
	xorpd	xmm0, xmm0				; total height percent
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .vertsizescan
	call	list$foreach
	mov	rdx, r14
	xor	r14d, r14d				; relative y
	mov	rdi, [rdx+tui_children_ofs]
	mov	rsi, .vertsizeset
	call	list$foreach_arg
	pop	r15 r14
	pop	rdi
	epilog
calign
.vertsizeset:
	; so rdi is our child object, rsi is our parent object, r14d == relative_y, r15d == available_height, xmm0 == total_heightperc

	; the combination of visible/includeinlayout means that calcbounds will still apply to invisible children (useful for effects, etc)
	; cmp	dword [rdi+tui_visible_ofs], 0
	; je	.vertsizeset_nodeal
	cmp	dword [rdi+tui_includeinlayout_ofs], 0
	je	.vertsizeset_nodeal
	mov	r10d, [rdi+tui_width_ofs]		; old child width
	mov	r11d, [rdi+tui_height_ofs]		; old child height
	cmp	qword [rdi+tui_widthperc_ofs], 0
	je	.vertsizeset_checkheightperc
	; else, widthperc is nonzero, so this childs' width relative to its parent
	mov	eax, [rsi+tui_width_ofs]
	movq	xmm1, [rdi+tui_widthperc_ofs]
	movq	xmm3, [.math_hundredth]
	cvtsi2sd	xmm2, eax
	mulsd	xmm1, xmm3				; turn the widthperc back into a real percentage
	mulsd	xmm1, xmm2				; multiplied by parent width
	cvtsd2si	eax, xmm1
	mov	[rdi+tui_width_ofs], eax		; and back as an integer
calign
.vertsizeset_checkheightperc:
	cmp	qword [rdi+tui_heightperc_ofs], 0
	je	.vertsizeset_setbounds
	; else, heightperc is nonzero, so this calculate its relative goods
	cvtsi2sd	xmm2, r15d			; convert available_height to a double
	movq	xmm1, [rdi+tui_heightperc_ofs]
	divsd	xmm1, xmm0				; /= total height percent
	mulsd	xmm1, xmm2				; *= available height
	cvtsd2si	eax, xmm1
	; it is possible that there wasn't enough room, so if eax < 0, set to zero
	xor	r8d, r8d
	cmp	eax, 0
	cmovl	eax, r8d
	mov	[rdi+tui_height_ofs], eax		; and back as an integer
calign
.vertsizeset_setbounds:
	xor	edx, edx				; remainder
	mov	r8d, [rsi+tui_width_ofs]		; parent width
	mov	eax, [rdi+tui_width_ofs]		; child width
	sub	r8d, eax				; parent width - child width

	; in case parent width was less than child width, make sure we don't end up with negative numbers
	cmp	r8d, 0
	cmovl	r8d, edx

	mov	r9d, r8d
	shr	r9d, 1
	cmp	dword [rsi+tui_horizalign_ofs], tui_align_right
	cmove	edx, r8d
	cmp	dword [rsi+tui_horizalign_ofs], tui_align_center
	cmove	edx, r9d
	mov	eax, [rsi+tui_bounds_ax_ofs]		; parent bounds.a.x
	add	eax, edx				; + remainder
	mov	[rdi+tui_bounds_ax_ofs], eax		; child bounds.a.x =
	add	eax, dword [rdi+tui_width_ofs]		; + child width
	mov	[rdi+tui_bounds_bx_ofs], eax
	mov	eax, [rsi+tui_bounds_ay_ofs]		; parent bounds.a.y
	add	eax, r14d				; + relative_y
	mov	[rdi+tui_bounds_ay_ofs], eax		; child bounds.a.y =
	add	eax, dword [rdi+tui_height_ofs]		; + child height
	mov	[rdi+tui_bounds_by_ofs], eax		; child bounds.b.y =
	add	r14d, dword [rdi+tui_height_ofs]

	; it is possible that due to rounding errors, we went one too far, check to make sure we didn't overstep the bounds
	cmp	r14d, [rsi+tui_height_ofs]
	ja	.vertsizeset_overrun

calign
.vertsizeset_next:
	cmp	r10d, dword [rdi+tui_width_ofs]
	jne	.firesizechanged
	cmp	r11d, dword [rdi+tui_height_ofs]
	jne	.firesizechanged
	ret
calign
.vertsizeset_overrun:
	; only modify this if we actually did a height percentage:
	cmp	qword [rdi+tui_heightperc_ofs], 0
	je	.vertsizeset_next
	; only modify if already >0
	cmp	dword [rdi+tui_height_ofs], 0
	jle	.vertsizeset_next
	sub	dword [rdi+tui_height_ofs], 1
	sub	r14d, 1

	cmp	r10d, dword [rdi+tui_width_ofs]
	jne	.firesizechanged
	cmp	r11d, dword [rdi+tui_height_ofs]
	jne	.firesizechanged
	ret
calign
.math_hundredth	dq	0.01f
calign
.firesizechanged:
	mov	rsi, [rdi]				; load up the vtable
	sub	rsp, 8
	movq	[rsp], xmm0				; preserve total percentage
	call	qword [rsi+tui_vsizechanged]
	movq	xmm0, [rsp]
	add	rsp, 8
	ret
calign
.vertsizescan:
	; see note above re: cheating with r15, we know r15 and xmm0 stay in tact across list$foreach
	; cmp	dword [rdi+tui_visible_ofs], 0
	; je	.vertsizescan_nodeal
	cmp	dword [rdi+tui_includeinlayout_ofs], 0
	je	.vertsizescan_nodeal
	cmp	qword [rdi+tui_heightperc_ofs], 0
	jne	.vertsizescan_percbased
	sub	r15d, dword [rdi+tui_height_ofs]
	ret
calign
.vertsizescan_percbased:
	movq	xmm1, [rdi+tui_heightperc_ofs]
	addsd	xmm0, xmm1
	ret
calign
.vertsizescan_nodeal:
.vertsizeset_nodeal:
.horizsizescan_nodeal:
.horizsizeset_nodeal:
	ret
calign
.horizsizeset:
	; cmp	dword [rdi+tui_visible_ofs], 0
	; je	.horizsizeset_nodeal
	cmp	dword [rdi+tui_includeinlayout_ofs], 0
	je	.horizsizeset_nodeal
	mov	r10d, [rdi+tui_width_ofs]			; old child width
	mov	r11d, [rdi+tui_height_ofs]			; old child height
	cmp	qword [rdi+tui_widthperc_ofs], 0
	je	.horizsizeset_checkheightperc
	cvtsi2sd	xmm2, r15d				; convert available_width to a double
	movq	xmm1, [rdi+tui_widthperc_ofs]
	divsd	xmm1, xmm0					; /= total width percent
	mulsd	xmm1, xmm2					; *= available width
	cvtsd2si	eax, xmm1
	; it is possible that there wasn't enough room, so if eax < 0, set to zero
	xor	r8d, r8d
	cmp	eax, 0
	cmovl	eax, r8d
	mov	[rdi+tui_width_ofs], eax			; and back as an integer
calign
.horizsizeset_checkheightperc:
	cmp	qword [rdi+tui_heightperc_ofs], 0
	je	.horizsizeset_setbounds
	mov	eax, [rsi+tui_height_ofs]
	movq	xmm1, [rdi+tui_heightperc_ofs]
	movq	xmm3, [.math_hundredth]
	cvtsi2sd	xmm2, eax
	mulsd	xmm1, xmm3					; turn the heightperc back into a real percentage
	mulsd	xmm1, xmm2					; multiplied by parent height
	cvtsd2si	eax, xmm1
	mov	[rdi+tui_height_ofs], eax			; and back as an integer
calign
.horizsizeset_setbounds:
	xor	edx, edx					; remainder
	mov	r8d, [rsi+tui_height_ofs]			; parent height
	mov	eax, [rdi+tui_height_ofs]			; child height
	sub	r8d, eax					; parent height - child height
	; in case parent height was less than child height, make sure we don't end up with negative numbers
	cmp	r8d, 0
	cmovl	r8d, edx
	mov	r9d, r8d
	shr	r9d, 1
	cmp	dword [rsi+tui_vertalign_ofs], tui_align_bottom
	cmove	edx, r8d
	cmp	dword [rsi+tui_vertalign_ofs], tui_align_middle
	cmove	edx, r9d
	mov	eax, [rsi+tui_bounds_ax_ofs]			; parent bounds.a.x
	add	eax, r14d					; + relative_x
	mov	[rdi+tui_bounds_ax_ofs], eax			; child bounds.a.x =
	add	eax, [rdi+tui_width_ofs]			; + child width
	mov	[rdi+tui_bounds_bx_ofs], eax			; child bounds.b.x =
	mov	eax, [rsi+tui_bounds_ay_ofs]			; parent bounds.a.y
	add	eax, edx					; + remainder
	mov	[rdi+tui_bounds_ay_ofs], eax			; child bounds.a.y =
	add	eax, [rdi+tui_height_ofs]			; + child height
	mov	[rdi+tui_bounds_by_ofs], eax			; child bounds.b.y =
	add	r14d, dword [rdi+tui_width_ofs]			; relative_x += child width

	; it is possible that due to rounding errors, we went one too far, check to make sure we didn't overstep the bounds
	cmp	r14d, [rsi+tui_width_ofs]
	ja	.horizsizeset_overrun

calign
.horizsizeset_next:
	cmp	r10d, dword [rdi+tui_width_ofs]
	jne	.firesizechanged
	cmp	r11d, dword [rdi+tui_height_ofs]
	jne	.firesizechanged
	ret
calign
.horizsizeset_overrun:
	; only modify this if we actually did a width percentage:
	cmp	qword [rdi+tui_widthperc_ofs], 0
	je	.horizsizeset_next
	; only modify if already >0
	cmp	dword [rdi+tui_width_ofs], 0
	jle	.vertsizeset_next
	sub	dword [rdi+tui_width_ofs], 1
	sub	r14d, 1

	cmp	r10d, dword [rdi+tui_width_ofs]
	jne	.firesizechanged
	cmp	r11d, dword [rdi+tui_height_ofs]
	jne	.firesizechanged
	ret
calign
.horizsizescan:
	; see note above re: cheating with r15
	; cmp	dword [rdi+tui_visible_ofs], 0
	; je	.horizsizescan_nodeal
	cmp	dword [rdi+tui_includeinlayout_ofs], 0
	je	.horizsizescan_nodeal
	cmp	qword [rdi+tui_widthperc_ofs], 0
	jne	.horizsizescan_percbased
	sub	r15d, dword [rdi+tui_width_ofs]
	ret
calign
.horizsizescan_percbased:
	movq	xmm1, [rdi+tui_widthperc_ofs]
	addsd	xmm0, xmm1
	ret
calign
.bastardsfirst:
	; for our bastard children, we really only need to take into account whether
	; bastardglue is set or not and modify/adjust their position
	; so our argument in rdi is the bastard child, rsi is our parent
	cmp	dword [rdi+tui_bastardglue_ofs], 0
	je	.nobastardglue
	; otehrwise, bastardglue is set, so pay attention to its
	; vertical and horizontal alignment to set its x/y nothing that we do NOT
	; modify its SIZE.
	xor	edx, edx	; remainder
	mov	r8d, [rsi+tui_width_ofs]	; parent width
	mov	r9d, [rdi+tui_width_ofs]	; child width
	sub	r8d, r9d	; parent width - child width
	; make sure we didn't go negative
	cmp	r8d, 0
	cmovl	r8d, edx
	mov	r10d, r8d
	shr	r10d, 1
	cmp	dword [rdi+tui_horizalign_ofs], tui_align_right
	cmove	edx, r8d
	cmp	dword [rdi+tui_horizalign_ofs], tui_align_center
	cmove	edx, r10d
	mov	eax, [rsi+tui_bounds_ax_ofs]
	add	eax, edx
	mov	[rdi+tui_bounds_ax_ofs], eax
	add	eax, [rdi+tui_width_ofs]
	mov	[rdi+tui_bounds_bx_ofs], eax
	xor	edx, edx	; remainder
	mov	r8d, [rsi+tui_height_ofs]	; parent height
	mov	r9d, [rdi+tui_height_ofs]	; child height
	sub	r8d, r9d	; parent height - child height
	; make sure we didn't go negative
	cmp	r8d, 0
	cmovl	r8d, edx
	mov	r10d, r8d
	shr	r10d, 1
	cmp	dword [rdi+tui_vertalign_ofs], tui_align_bottom
	cmove	edx, r8d
	cmp	dword [rdi+tui_vertalign_ofs], tui_align_middle
	cmove	edx, r10d
	mov	eax, [rsi+tui_bounds_ay_ofs]
	add	eax, edx
	mov	[rdi+tui_bounds_ay_ofs], eax
	add	eax, [rdi+tui_height_ofs]
	mov	[rdi+tui_bounds_by_ofs], eax
	ret
calign
.nobastardglue:
.childabsolute:		; the code for unglued bastard absolute layouts is the same
	; its position is relative to ours, so we treat it as an absolute layout
	cmp	dword [rdi+tui_absolutex_ofs], -1
	je	.nobastardglue_first
	mov	eax, [rsi+tui_bounds_ax_ofs]	; parent.a.x
	add	eax, [rdi+tui_absolutex_ofs]	; + child.absolutex
	mov	ecx, [rsi+tui_bounds_ay_ofs]	; parent.a.y
	add	ecx, [rdi+tui_absolutey_ofs]	; + child.absolutey
	mov	[rdi+tui_bounds_ax_ofs], eax	; child.a.x = 
	mov	[rdi+tui_bounds_ay_ofs], ecx	; child.a.y =
	add	eax, [rdi+tui_width_ofs]	; + child width
	add	ecx, [rdi+tui_height_ofs]	; + child height
	mov	[rdi+tui_bounds_bx_ofs], eax
	mov	[rdi+tui_bounds_by_ofs], ecx
	ret
calign
.nobastardglue_first:
	; its position is still relative, but we haven't yet set absolute_x
	mov	eax, [rdi+tui_bounds_ax_ofs]
	mov	ecx, [rdi+tui_bounds_ay_ofs]
	mov	[rdi+tui_absolutex_ofs], eax
	mov	[rdi+tui_absolutey_ofs], ecx
	; now same as above:
	mov	eax, [rsi+tui_bounds_ax_ofs]
	add	eax, [rdi+tui_absolutex_ofs]
	mov	ecx, [rsi+tui_bounds_ay_ofs]
	add	ecx, [rdi+tui_absolutey_ofs]
	mov	[rdi+tui_bounds_ax_ofs], eax
	mov	[rdi+tui_bounds_ay_ofs], ecx
	add	eax, [rdi+tui_width_ofs]
	add	ecx, [rdi+tui_height_ofs]
	mov	[rdi+tui_bounds_bx_ofs], eax
	mov	[rdi+tui_bounds_by_ofs], ecx
	ret
end if



if used tui_object$appendchild | defined include_everything
	; two arguments: rdi == our tui_object, rsi == new object to add
	; we set the new object's parent to our rdi, add it to our children list, and then call our vmethod layoutchanged
falign
tui_object$appendchild:
	prolog	tui_object$appendchild
	push	rdi
	mov	[rsi+tui_parent_ofs], rdi
	mov	rdi, [rdi+tui_children_ofs]
	call	list$push_back
	mov	rdi, [rsp]
	mov	rsi, [rdi]		; load our vtable
	call	qword [rsi+tui_vlayoutchanged]	; force a redraw
	pop	rdi
	epilog
end if


if used tui_object$appendbastard | defined include_everything
	; two arguments: rdi == our tui_object, rsi == new object to add
	; we set the new object's parent to our rdi, add it to our bastards list, and then call our vmethod layoutchanged
falign
tui_object$appendbastard:
	prolog	tui_object$appendbastard
	push	rdi
	mov	[rsi+tui_parent_ofs], rdi
	mov	rdi, [rdi+tui_bastards_ofs]
	call	list$push_back
	mov	rdi, [rsp]
	mov	rsi, [rdi]		; load our vtable
	call	qword [rsi+tui_vlayoutchanged]	; force a redraw
	pop	rdi
	epilog
end if


if used tui_object$prependchild | defined include_everything
	; same as appendchild, but sticks it at the front of the list instead of the end
falign
tui_object$prependchild:
	prolog	tui_object$prependchild
	push	rdi
	mov	[rsi+tui_parent_ofs], rdi
	mov	rdi, [rdi+tui_children_ofs]
	call	list$push_front
	mov	rdi, [rsp]
	mov	rsi, [rdi]		; load our vtable
	call	qword [rsi+tui_vlayoutchanged]	; force a redraw
	pop	rdi
	epilog
end if


if used tui_object$contains | defined include_everything
	; two arguments: rdi == our tui_object, rsi == object to test for
	; returns zero in eax if rsi is not in rdi's children list, or 1 in eax if it does
falign
tui_object$contains:
	prolog	tui_object$contains
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdx, [_list_first]
	test	rdx, rdx
	jz	.zeroret
calign
.loop:
	cmp	rsi, [rdx+_list_valueofs]
	je	.oneret
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.loop
	xor	eax, eax
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
calign
.oneret:
	mov	eax, 1
	epilog
end if


if used tui_object$getchildindex | defined include_everything
	; two arguments: rdi == our tui_object, rsi == object to test for
	; returns unsigned index in eax, or -1 if it isn't found
falign
tui_object$getchildindex:
	prolog	tui_object$getchildindex
	xor	eax, eax
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdx, [_list_first]
	test	rdx, rdx
	jz	.negoneret
calign
.loop:
	cmp	rsi, [rdx+_list_valueofs]
	je	.oneret
	add	eax, 1
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.loop
	mov	eax, -1
	epilog
calign
.negoneret:
	mov	eax, -1
	epilog
calign
.oneret:
	epilog
end if

if used tui_object$removechild | defined include_everything
	; two arguments: rdi == our tui_object, rsi == object to remove
	; NOTE: does _NOT_ delete/cleanup/heap$free the child
	; if we do indeed remove it, we fire a layoutchanged vmethod call to redraw
	; returns zero in rax if we didn't find it, or returns the child if we did
falign
tui_object$removechild:
	prolog	tui_object$removechild
	push	rdi		; save our actual object
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdx, [_list_first]
	test	rdx, rdx
	jz	.zeroret
calign
.loop:
	cmp	rsi, [rdx+_list_valueofs]
	je	.foundit
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.loop
	xor	eax, eax
	pop	rdi
	epilog
calign
.zeroret:
	pop	rdi
	xor	eax, eax
	epilog
calign
.foundit:
	push	rsi	; save our return
	mov	rsi, rdx
	call	list$remove
	pop	rax
	pop	rdi	; get our object back
	mov	rsi, [rdi]	; load the vtable
	push	rax	; preserve our return
	call	qword [rsi+tui_vlayoutchanged]
	pop	rax
	epilog
end if
	

if used tui_object$removebastard | defined include_everything
	; two arguments: rdi == our tui_object, rsi == object to remove
	; same as removechild, only does so with the bastards list instead
falign
tui_object$removebastard:
	prolog	tui_object$removebastard
	push	rdi		; save our actual object
	mov	rdi, [rdi+tui_bastards_ofs]
	mov	rdx, [_list_first]
	test	rdx, rdx
	jz	.zeroret
calign
.loop:
	cmp	rsi, [rdx+_list_valueofs]
	je	.foundit
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.loop
	xor	eax, eax
	pop	rdi
	epilog
calign
.zeroret:
	pop	rdi
	xor	eax, eax
	epilog
calign
.foundit:
	push	rsi	; save our return
	mov	rsi, rdx
	call	list$remove
	pop	rax
	pop	rdi	; get our object back
	mov	rsi, [rdi]	; load the vtable
	push	rax	; preserve our return
	call	qword [rsi+tui_vlayoutchanged]
	pop	rax
	epilog
end if
	

if used tui_object$removeallchildren | defined include_everything
	; single argument: rdi == our tui_object
	; removes ALL children, and if we actually deleted any, fires a new layoutchanged vmethod call
	; note: this actually DOES delete them (after calling vcleanup first, then it heap$frees them)
falign
tui_object$removeallchildren:
	prolog	tui_object$removeallchildren
	push	rdi
	mov	rdi, [rdi+tui_children_ofs]
	cmp	[_list_first], 0
	je	.nothingtodo
	mov	rsi, .childkill
	call	list$clear
	mov	rdi, [rsp]
	mov	rsi, [rdi]		; load the vtable
	call	qword [rsi+tui_vlayoutchanged]
	pop	rdi
	epilog
calign
.childkill:
	; single argument in rdi == the child we are killing
	push	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	pop	rdi
	call	heap$free
	ret
calign
.nothingtodo:
	pop	rdi
	epilog
end if

if used tui_object$removeallbastards | defined include_everything
	; single argument: rdi == our tui_object
	; removes ALL bastards, and if we actually deleted any, fires a new layoutchanged vmethod call
	; note: this actually DOES delete them (after calling vcleanup first, then it heap$frees them)
falign
tui_object$removeallbastards:
	prolog	tui_object$removeallbastards
	push	rdi
	mov	rdi, [rdi+tui_bastards_ofs]
	cmp	[_list_first], 0
	je	.nothingtodo
	mov	rsi, .childkill
	call	list$clear
	mov	rdi, [rsp]
	mov	rsi, [rdi]		; load the vtable
	call	qword [rsi+tui_vlayoutchanged]
	pop	rdi
	epilog
calign
.childkill:
	; single argument in rdi == the child we are killing
	push	rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	pop	rdi
	call	heap$free
	ret
calign
.nothingtodo:
	pop	rdi
	epilog
end if

if used tui_object$getobjectsunderpoint | defined include_everything
	; three arguments: rdi == our tui_object, rsi == a POINTER to a point, rdx == list to append objects to
falign
tui_object$getobjectsunderpoint:
	prolog	tui_object$getobjectsunderpoint
	push	rax rdx rsi rdi
	
	mov	rdi, [rdi+tui_children_ofs]
	mov	rdx, [_list_first]
	test	rdx, rdx
	jz	.checkbastards
calign
.loop:
	mov	r8, [rdx+_list_valueofs]	; get the child itself
	; determine if this child's bounds contains the point pointed to by rsi
	mov	eax, [rsi]			; point.x
	mov	ecx, [rsi+4]			; point.y
	cmp	eax, dword [r8+tui_bounds_ofs]
	jl	.nope
	cmp	eax, dword [r8+tui_bounds_ofs+8]
	jge	.nope
	cmp	ecx, dword [r8+tui_bounds_ofs+4]
	jl	.nope
	cmp	ecx, dword [r8+tui_bounds_ofs+12]
	jge	.nope
	; else, the point is in bounds, so we need to add it to our list
	mov	[rsp+24], rdx			; save our list pointer so we can keep going
	mov	rdi, [rsp+16]			; the destination list
	mov	rsi, r8				; the child to add
	call	list$push_back
	; next, we need to call this child's vgetobjectsunderpoint
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+_list_valueofs]	; the object
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rdi]			; its vtable
	call	qword [rcx+tui_vgetobjectsunderpoint]

	mov	rdx, [rsp+24]
	mov	rsi, [rsp+8]
	
calign
.nope:
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.loop
	; else, restore our rdi
	mov	rdi, [rsp]
calign
.checkbastards:
	mov	rdi, [rdi+tui_bastards_ofs]
	mov	rdx, [_list_first]
	test	rdx, rdx
	jz	.alldone
calign
.bloop:
	mov	r8, [rdx+_list_valueofs]	; get the child itself
	; determine if this child's bounds contains the point pointed to by rsi
	mov	eax, [rsi]			; point.x
	mov	ecx, [rsi+4]			; point.y
	cmp	eax, dword [r8+tui_bounds_ofs]
	jl	.bnope
	cmp	eax, dword [r8+tui_bounds_ofs+8]
	jge	.bnope
	cmp	ecx, dword [r8+tui_bounds_ofs+4]
	jl	.bnope
	cmp	ecx, dword [r8+tui_bounds_ofs+12]
	jge	.bnope
	; else, the point is in bounds, so we need to add it to our list
	mov	[rsp+24], rdx			; save our list pointer so we can keep going
	mov	rdi, [rsp+16]			; the destination list
	mov	rsi, r8				; the child to add
	call	list$push_back
	; next, we need to call this child's vgetobjectsunderpoint
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+_list_valueofs]	; the object
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rdi]			; its vtable
	call	qword [rcx+tui_vgetobjectsunderpoint]

	mov	rdx, [rsp+24]
	mov	rsi, [rsp+8]
calign
.bnope:
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.bloop
	; else, we are all done
	add	rsp, 32
	epilog
calign
.alldone:
	add	rsp, 32
	epilog
end if


if used tui_object$nvflattenchild | defined include_everything
	; four arguments: rdi == our tui_object, rsi == fresh text buffer, rdx == fresh attr buffer, rcx == child to flatten into it
	; NOTE: it is called nvflattenchild because this one is _not_ a member of the virtual method table
falign
tui_object$nvflattenchild:
	prolog	tui_object$nvflattenchild
	mov	rax, [rdi+tui_bounds_ofs]
	mov	r8, [rdi+tui_bounds_ofs+8]

	mov	r10d, [rcx+tui_bounds_ofs]	; child bounds.a.x
	mov	r11d, [rcx+tui_bounds_ofs+8]	; child bounds.b.x

	; first up, make a clipping rect
	sub	rsp, 136
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx

	mov	[rsp+32], rax			; our bounds.a
	mov	[rsp+40], r8			; our bounds.b
	; intersect this temporary bounds object with the child's bounds
	; rdi == rsp+32
	; rsi == [rcx+tui_bounds_ofs]

	mov	r8d, [rsp+32]			; our bounds.a.x
	mov	r9d, [rsp+40]			; our bounds.b.x

	; scroll mod:
	add	r8d, [rdi+tui_scroll_ofs]
	add	r9d, [rdi+tui_scroll_ofs]
	; end scroll mod

	cmp	r8d, r10d
	cmovl	r8d, r10d
	cmp	r9d, r11d
	cmovg	r9d, r11d
	mov	[rsp+32], r8d			; intersected with child's a.x
	mov	[rsp+40], r9d			; intersected with child's b.x

	mov	r8d, [rsp+36]			; our bounds.a.y
	mov	r9d, [rsp+44]			; our bounds.b.y

	; scroll mod:
	add	r8d, [rdi+tui_scroll_ofs+4]
	add	r9d, [rdi+tui_scroll_ofs+4]
	; end scroll mod

	mov	r10d, [rcx+tui_bounds_ofs+4]
	mov	r11d, [rcx+tui_bounds_ofs+12]
	cmp	r8d, r10d
	cmovl	r8d, r10d
	cmp	r9d, r11d
	cmovg	r9d, r11d
	mov	[rsp+36], r8d
	mov	[rsp+44], r9d

	; check to see if our intersection is empty
	mov	r8d, [rsp+32]
	mov	r9d, [rsp+36]

	cmp	r8d, [rsp+40]
	jge	.bailout
	cmp	r9d, [rsp+44]
	jge	.bailout

	; otherwise, it is non-empty, proceed:
	mov	qword [rsp+128], 0
	; if scroll is nonzero, and we clipped the child, we need to scroll the child cliprect too
	cmp	qword [rdi+tui_scroll_ofs], 0
	je	.notempty_noscroll
	cmp	dword [rdi+tui_scroll_ofs], 0
	je	.notempty_noxscroll
	; otherwise, xscroll is nonzero, see if we got all of our child's bounds
	mov	r10d, [rcx+tui_bounds_ofs]
	mov	r11d, [rcx+tui_bounds_ofs+8]
	sub	r11d, r10d
	; that now has our child width, check that against our clipped width
	mov	r9d, [rsp+40]
	mov	r8d, [rsp+32]
	sub	r9d, r8d
	cmp	r11d, r9d
	je	.notempty_noxscroll
	; otherwise, the difference (r11d - r9d) must be the cliprect scroll x
	sub	r11d, r9d

	; if cliprect.a.x == child's bounds.a.x, no scroll
	cmp	r10d, [rsp+32]
	je	.notempty_noxscroll
	mov	[rsp+128], r11d
calign
.notempty_noxscroll:
	; do the same for y
	cmp	dword [rdi+tui_scroll_ofs+4], 0
	je	.notempty_noscroll
	; otherwise, yscroll is nonzero, see if we got all of our child's bounds
	mov	r10d, [rcx+tui_bounds_ofs+4]
	mov	r11d, [rcx+tui_bounds_ofs+12]
	sub	r11d, r10d
	; that now has our child height, check that against our clipped height
	mov	r9d, [rsp+44]
	mov	r8d, [rsp+36]
	sub	r9d, r8d
	cmp	r11d, r9d
	je	.notempty_noscroll
	; otherwise, the difference (r11d - r9d) must be the cliprect scroll y
	sub	r11d, r9d

	; if cliprect.a.y == child's bounds.a.y, no scroll
	cmp	r10d, [rsp+36]
	je	.notempty_noscroll

	mov	[rsp+132], r11d
calign
.notempty_noscroll:
	; next up: call our child's flatten vmethod
	mov	rdi, rcx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vflatten]
	; if it returned us null, bail out
	test	rax, rax
	jz	.bailout
	; otherwise, we can start our loop
	; rax == c_text, rdx == c_attr
	mov	[rsp+48], rax		; save c_text
	mov	[rsp+56], rdx		; save c_attr

	; we need a ton of temporaries here
	mov	[rsp+64], rbp
	mov	[rsp+72], rbx
	mov	[rsp+80], r12
	mov	[rsp+88], r13
	mov	[rsp+96], r14
	mov	[rsp+104], r15
	; we'll put those back when we are done

	mov	rdi, [rsp]		; get our object back, though only temporarily
	mov	rcx, [rsp+24]		; and the child we are flattening, though only temporarily

	; we need to calculate and preserve for our loop:
	; clipping rect a.y - our object's bounds.a.y
	; clipping rect a.x - our object's bounds.a.x

	mov	r12d, [rsp+36]		; cliprect.a.y
	sub	r12d, [rdi+tui_bounds_ay_ofs]	; - our object's bounds.a.y

	; scroll mod
	sub	r12d, [rdi+tui_scroll_ofs+4]	; - our object's scroll.y
	; end scroll mod

	mov	r13d, [rsp+32]		; cliprect.a.x
	sub	r13d, [rdi+tui_bounds_ax_ofs]	; - our object's bounds.a.x

	; scroll mod
	sub	r13d, [rdi+tui_scroll_ofs]	; - our object's scroll.x
	; end scroll mod

	; we also need to save the child's width and our object's width
	mov	r14d, [rdi+tui_width_ofs]	; our object's width
	mov	r15d, [rcx+tui_width_ofs]	; our child's width

	mov	r11d, [rsp+44]		; cliprect.b.y
	sub	r11d, [rsp+36]		; - cliprect.a.y
	sub	r11d, 1			; - 1 (we walk this down to zero inclusive and then stop our loop to save a register)

	mov	r9d, [rsp+40]		; cliprect.b.x
	sub	r9d, [rsp+32]		; - cliprect.a.x == copy length

	mov	r8d, [rsp+32]		; cliprect.a.x
	sub	r8d, [rcx+tui_bounds_ax_ofs]	; - child's bounds.a.x

	; scroll mod
	add	r8d, [rsp+128]
	; end scroll mod

	mov	rdi, [rsp+8]		; get our flat_text buffer
	mov	rsi, [rsp+16]		; get our flat_attr buffer

	; as a precautionary/sanitarium check, make sure line is >= 0
	cmp	r11d, 0
	jl	.loopdone
calign
.lineloop:
	; first up: calculate our destination offset
	mov	eax, r11d		; line
	add	eax, r12d		; + (cliprect.a.y - our object's bounds.a.y)
	mul	r14d			; * our object's width
	add	eax, r13d		; + (cliprect.a.x - our object's bounds.a.x)
	shl	rax, 2			; in byte offset, not characters
	mov	rcx, rax		; save the offset

	; next up: calculate our source offset
	mov	eax, r11d		; line
	; scroll mod
	add	eax, [rsp+132]
	; end scroll mod
	mul	r15d			; * our child's width
	add	eax, r8d		; + (cliprect.a.x - child bounds.a.x)
	shl	rax, 2			; in byte offset, not characters

	; so now we have:
	; ecx == destination offset
	; eax == source offset
	; r9d == copy length

	mov	edx, ecx
	add	rcx, rdi		; flat_text + destination offset
	add	rdx, rsi		; flat_attr + destination offset

	; so now we need source text and source attr pointers (rbp and rbx + source offset)
	mov	rbp, [rsp+48]		; c_text
	mov	rbx, [rsp+56]		; c_attr
	add	rbp, rax
	add	rbx, rax

	; r10d is free, so is rax
	xor	r10d, r10d		; inner loop/copy offset
calign
.innerloop:
	; a note here on why we don't just do a blind memcpy:
	; we support "transparent" objects ... which is to say: if the text buffer is null/0
	; then we do _not_ flatten said 0, which lets objects be transparent if they want
	; this is slower, and surely there is an SSE2 way of makign this go a bit faster
	; TODO: someday when I am bored, spend some quality time in this routine
	mov	eax, dword [rbp+r10*4]
	test	eax, eax
	jz	.nocopy
	mov	dword [rcx+r10*4], eax
	mov	eax, dword [rbx+r10*4]
	mov	dword [rdx+r10*4], eax
	add	r10d, 1
	cmp	r10d, r9d
	jb	.innerloop
	sub	r11d, 1
	cmp	r11d, 0
	jge	.lineloop
	jmp	.loopdone
calign
.bailout:
	; it is indeed empty, we are outta here.
	add	rsp, 136
	epilog
calign
.nocopy:
	; dword in source text was 0, so we are not copying this spot
	add	r10d, 1
	cmp	r10d, r9d
	jb	.innerloop
	sub	r11d, 1
	cmp	r11d, 0
	jge	.lineloop
calign
.loopdone:
	; our copy is complete, free our c_text and c_attr
	mov	rdi, [rsp+48]		; c_text
	call	heap$free
	mov	rdi, [rsp+56]		; c_attr
	call	heap$free
	; so at this point, our next horrendous mess to deal with is if our child
	; wants a drop-shadow.
	; _we_ have to implement this, because the child itself doesn't have access
	; to modify (nor should it) its parent buffer
	mov	rcx, [rsp+24]		; our child
	cmp	dword [rcx+tui_dropshadow_ofs], 0
	je	.cleanupandreturn
	; so the actual dropshadow spot is the child bounds moved +1,+1
	; so we need a temporary copy of the child bounds, move it +1,+1
	; and then intersect it as we did with the original flatten
	; and if there is indeed room in the intersected bounds
	mov	rax, [rcx+tui_bounds_ofs]
	mov	rdx, [rcx+tui_bounds_ofs+8]
	mov	[rsp+112], rax
	mov	[rsp+120], rdx
	; now +1,+1 it
	add	dword [rsp+112], 1
	add	dword [rsp+116], 1
	add	dword [rsp+120], 1
	add	dword [rsp+124], 1	; childoverdown at rsp+112

	; now do an intersection with our object's bounds
	mov	rdi, [rsp]		; get our object back into rdi
	
	mov	rax, [rdi+tui_bounds_ofs]
	mov	r8, [rdi+tui_bounds_ofs+8]
	mov	[rsp+32], rax
	mov	[rsp+40], r8		; shadowclip at rsp+32
	; intersect this temporary bounds object with the child's bounds +1,+1
	; rdi == rsp+32
	; rsi == [rcx+tui_bounds_ofs]

	mov	r8d, [rsp+32]
	mov	r9d, [rsp+40]
	mov	r10d, [rsp+112]
	mov	r11d, [rsp+120]
	cmp	r8d, r10d
	cmovl	r8d, r10d
	cmp	r9d, r11d
	cmovg	r9d, r11d
	mov	[rsp+32], r8d
	mov	[rsp+40], r9d

	mov	r8d, [rsp+36]
	mov	r9d, [rsp+44]
	mov	r10d, [rsp+116]
	mov	r11d, [rsp+124]
	cmp	r8d, r10d
	cmovl	r8d, r10d
	cmp	r9d, r11d
	cmovg	r9d, r11d
	mov	[rsp+36], r8d
	mov	[rsp+44], r9d

	; if there was room for our drop shadow, then our shadow cliprect at rsp+32 will contain childoverdown.b
	; so....
	; we have to see if our intersected bounds.b.x is equal to our moved +1,+1 bounds
	; as well as making sure intersected bounds.b.y is equal to our moved +1,+1 bounds

	mov	rax, [rsp+120]		; b.x and b.y together from the childoverdown rect
	cmp	rax, [rsp+40]		; compared to our intersected b.x and b.y together
	jne	.cleanupandreturn	; intersection is kakked


	; at this point: we have our shadowclip sitting in rsp+32
	; we have our child in rcx, our object in rdi, everything else is free

	mov	r12d, [rsp+44]		; shadowclip.b.y
	sub	r12d, [rsp+36]		; - shadowclip.a.y
	sub	r12d, 1
	mov	[rsp+112], r12d		; our iteration count for our vertical loop
	cmp	r12d, 0
	jle	.shadow_vertdone

	mov	r12d, [rsp+40]		; shadowclip.b.x
	sub	r12d, [rsp+32]		; - shadowclip.a.x
	sub	r12d, 1
	shl	r12d, 2			; our column modifier in bytes, first bit
	mov	[rsp+116], r12d
	
	mov	r12d, [rsp+32]		; shadowclip.a.x
	sub	r12d, [rdi+tui_bounds_ax_ofs]	; - our bounds.a.x
	shl	r12d, 2
	add	dword [rsp+116], r12d	; our column modifier in bytes

	; next up, figure out our line modifier and width in bytes
	mov	r12d, [rsp+36]		; shadowclip.a.y
	sub	r12d, [rdi+tui_bounds_ay_ofs]	; - our bounds.a.y
	; leave that sitting in r12d

	mov	r14d, [rdi+tui_width_ofs]
	shl	r14d, 2			; our actual width in bytes

	; we are ready for our vertical loop
	xor	r13d, r13d		; our line
	mov	rdi, [rsp+8]		; get our flat_text buffer
	mov	rsi, [rsp+16]		; get our flat_attr buffer
calign
.shadow_vertloop:
	mov	eax, r13d		; line
	add	eax, r12d
	mul	r14d
	add	eax, dword [rsp+116]	; + our total column modifier

	mov	r10d, eax
	add	r10, rsi		; flat_attr + destination offset

	mov	eax, dword [r10]
	test	eax, eax
	jz	.shadow_vertloop_next
	; else, darken the colors
	push	r12			; darkenindices mashes heaps of regs
	call	.darkenindices
	pop	r12
	mov	dword [r10], eax
calign
.shadow_vertloop_next:
	add	r13d, 1
	sub	dword [rsp+112], 1
	jnz	.shadow_vertloop
calign
.shadow_vertdone:
	; next up: do the same for our horizontal side:
	mov	rdi, [rsp]		; get our object back into rdi
	mov	rcx, [rsp+24]		; our child

	; get our iteration count for our horizontal loop
	mov	r12d, [rsp+40]		; shadowclip.b.x
	sub	r12d, [rsp+32]		; - shadowclip.a.x
	mov	[rsp+112], r12d		; our iteration count for our horizontal loop
	cmp	r12d, 0
	jle	.cleanupandreturn

	; figure out our basis line modifier
	mov	r12d, [rsp+44]		; shadowclip.b.y
	sub	r12d, [rsp+36]		; - shadowclip.a.y
	sub	r12d, 1
	cmp	r12d, 0
	jle	.cleanupandreturn
	; and add to that:
	mov	r13d, [rsp+36]		; shadowclip.a.y
	sub	r13d, [rdi+tui_bounds_ay_ofs]
	add	r12d, r13d
	; multiply that by our width in bytes, which is still sitting in r14d
	mov	eax, r12d
	mul	r14d

	; we also need to account for our shadowclip.a.x - our a.x
	mov	r12d, [rsp+32]		; shadowclip.a.x
	sub	r12d, [rdi+tui_bounds_ax_ofs]	; - our bounds.a.x
	shl	r12d, 2
	add	eax, r12d


	mov	[rsp+116], eax		; our line modifier

	; we are ready for our horizontal loop
	xor	r13d, r13d		; our column
	mov	rdi, [rsp+8]		; get our flat_text buffer
	mov	rsi, [rsp+16]		; get our flat_attr buffer
calign
.shadow_horizloop:
	mov	eax, r13d		; column
	shl	eax, 2			; in bytes
	add	eax, [rsp+116]		; + line modifier

	mov	r10d, eax
	add	r10, rsi		; flat_attr + destination offset

	mov	eax, dword [r10]
	test	eax, eax
	jz	.shadow_horizloop_next
	; else, darken the colors
	call	.darkenindices
	mov	dword [r10], eax
calign
.shadow_horizloop_next:
	add	r13d, 1
	sub	dword [rsp+112], 1
	jnz	.shadow_horizloop

calign
.cleanupandreturn:
	; restore our callee-saves:
	mov	rbp, [rsp+64]
	mov	rbx, [rsp+72]
	mov	r12, [rsp+80]
	mov	r13, [rsp+88]
	mov	r14, [rsp+96]
	mov	r15, [rsp+104]
	add	rsp, 136
	epilog
falign
.darkenindices:
	; al/ah need modified
	mov	r8d, eax
	shr	r8d, 8
	and	eax, 0xff
	call	.darkeneax
	mov	r9d, eax
	mov	eax, r8d
	call	.darkeneax
	; put them back together
	shl	eax, 8
	or	eax, r9d
	ret
falign
.darkeneax:
	cmp	eax, 0xe8
	jae	.darken_gray
	cmp	eax, 16
	jb	.darken_sys
calign
.darken_doit:
	; else, we do it the hard way, TODO: someday when I am bored, come up with a better way than these divs
	mov	ecx, 6
	sub	eax, 16
	mov	r11d, eax		; our index
	xor	edx, edx
	div	ecx			; div 6
	mov	r12d, edx		; blue == remainder
	mov	r11d, eax
	xor	edx, edx
	div	ecx
	mov	r15d, edx		; green == remainder
	mov	r11d, eax
	xor	edx, edx
	div	ecx
	; red now sitting in edx
	mov	eax, edx
	sub	eax, 1
	cmp	edx, 0
	cmova	edx, eax

	mov	eax, r15d
	sub	eax, 1
	cmp	r15d, 0
	cmova	r15d, eax

	mov	eax, r12d
	sub	eax, 1
	cmp	r12d, 0
	cmova	r12d, eax

	mov	ecx, 36
	; our return is r12d + (r15d * 6) + (edx * 36) + 16
	mov	eax, edx
	mul	ecx

	add	r12d, eax
	mov	ecx, 6
	add	r12d, 16

	mov	eax, r15d
	mul	ecx
	add	r12d, eax

	xchg	eax, r12d

	ret
calign
.darken_gray:
	sub	eax, 0xe8
	shr	eax, 1
	add	eax, 0xe8
	ret
calign
.darken_sys:
	jmp	qword [rax*8+.darken_dispatch]
dalign
.darken_dispatch:
	dq	.d0, .d1, .d2, .d3, .d4, .d5, .d6, .d7, .d8, .d9, .d10, .d11, .d12, .d13, .d14, .d15
calign
.d0:
	; eax is already zero, return 0
	ret
calign
.d1:
	ansi_rgbi eax, 194, 54, 33
	jmp	.darken_doit
calign
.d2:
	ansi_rgbi eax, 37, 188, 36
	jmp	.darken_doit
calign
.d3:
	ansi_rgbi eax, 173, 173, 39
	jmp	.darken_doit
calign
.d4:
	ansi_rgbi eax, 73, 46, 225
	jmp	.darken_doit
calign
.d5:
	ansi_rgbi eax, 211, 56, 211
	jmp	.darken_doit
calign
.d6:
	ansi_rgbi eax, 51, 187, 200
	jmp	.darken_doit
calign
.d7:
	ansi_rgbi eax, 203, 204, 205
	jmp	.darken_doit
calign
.d8:
	ansi_rgbi eax, 129, 131, 131
	jmp	.darken_doit
calign
.d9:
	ansi_rgbi eax, 252, 57, 31
	jmp	.darken_doit
calign
.d10:
	ansi_rgbi eax, 49, 231, 34
	jmp	.darken_doit
calign
.d11:
	ansi_rgbi eax, 234, 236, 35
	jmp	.darken_doit
calign
.d12:
	ansi_rgbi eax, 88, 51, 255
	jmp	.darken_doit
calign
.d13:
	ansi_rgbi eax, 249, 53, 248
	jmp	.darken_doit
calign
.d14:
	ansi_rgbi eax, 20, 240, 240
	jmp	.darken_doit
calign
.d15:
	mov	eax, 0xe8 + 12
	ret

end if


if used tui_object$flatten | defined include_everything
	; single argument: rdi == our tui_object
	; returns newly allocated flat_text buffer in rax, flat_attr buffer in rdx
	; NOTE: due to second return in rdx, not sure how a C/C++ wrapper for this would work
	; but it would be trivial to create a second version that accepts pointers to buffers
	; like the old version does
falign
tui_object$flatten:
	prolog	tui_object$flatten
	cmp	qword [rdi+tui_text_ofs], 0
	je	.nullret
	mov	eax, [rdi+tui_width_ofs]
	mov	ecx, [rdi+tui_height_ofs]

	mul	ecx
	shl	eax, 2
	test	eax, eax
	jz	.nullret

	sub	rsp, 32
	mov	[rsp], rdi
	mov	dword [rsp+24], eax
	mov	edi, eax
	call	heap$alloc
	mov	[rsp+8], rax
	mov	edi, dword [rsp+24]
	call	heap$alloc
	mov	[rsp+16], rax

	; copy our text into our new flat_text, and our attr into our new flat_attr

	mov	rcx, [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, [rcx+tui_text_ofs]
	mov	edx, dword [rsp+24]
	call	memcpy

	mov	rcx, [rsp]
	mov	rdi, [rsp+16]
	mov	rsi, [rcx+tui_attr_ofs]
	mov	edx, dword [rsp+24]
	call	memcpy

	; so now we have a copy of our own buffer, now it is time to iterate over our children
	; and if they are visible and have valid bounds, stick their flattened goods into our
	; new buffers at the right spot
	
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_children_ofs]
	mov	r8, [_list_first]
	test	r8, r8
	jz	.flattenbastards
calign
.loop:
	mov	rcx, [r8+_list_valueofs]	; the actual child object
	cmp	dword [rcx+tui_visible_ofs], 0
	je	.next
	cmp	qword [rcx+tui_text_ofs], 0
	je	.next
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	[rsp+24], r8			; save our pointer so we can keep going
	call	tui_object$nvflattenchild
	mov	r8, [rsp+24]
calign
.next:
	mov	r8, [r8+_list_nextofs]
	test	r8, r8
	jnz	.loop
calign
.flattenbastards:
	mov	rcx, [rsp]
	mov	rdi, [rcx+tui_bastards_ofs]
	mov	r8, [_list_first]
	test	r8, r8
	jz	.alldone
calign
.bloop:
	mov	rcx, [r8+_list_valueofs]	; the actual child object
	cmp	dword [rcx+tui_visible_ofs], 0
	je	.bnext
	cmp	qword [rcx+tui_text_ofs], 0
	je	.bnext
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	[rsp+24], r8			; save our pointer so we can keep going
	call	tui_object$nvflattenchild
	mov	r8, [rsp+24]
calign
.bnext:
	mov	r8, [r8+_list_nextofs]
	test	r8, r8
	jnz	.bloop
calign
.alldone:
	mov	rax, [rsp+8]
	mov	rdx, [rsp+16]
	add	rsp, 32
	epilog
calign
.nullret:
	xor	eax, eax
	xor	edx, edx
	epilog
end if


if used tui_object$firekeyevent | defined include_everything
	; three arguments: rdi == our tui_object, esi == key, edx == esc_key
	; this fires off the key events to all children (visible or not)
	; stops when one of them says so via its return
	; returns zero in eax if no one did, or 1 if so
falign
tui_object$firekeyevent:
	prolog	tui_object$firekeyevent
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	cmp	qword [rdi+tui_focus_ofs], 0
	jne	.usefocus
	; hmmm, do we pass it to our children before we check ourselves?
	; TODO: come back and think more about this
	mov	rdi, [rdi+tui_children_ofs]
	mov	rcx, [_list_first]
	test	rcx, rcx
	jz	.nokids
calign
.loop:
	mov	[rsp+24], rcx
	mov	rdi, [rcx+_list_valueofs]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vfirekeyevent]
	test	eax, eax
	jnz	.kidsdone
	mov	rcx, [rsp+24]
	mov	rcx, [rcx+_list_nextofs]
	test	rcx, rcx 
	jnz	.loop
calign
.nokids:
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rdi]		; get our vtable
	call	qword [rcx+tui_vkeyevent]
	add	rsp, 32
	epilog
calign
.usefocus:
	mov	rdi, [rdi+tui_focus_ofs]
	mov	rcx, [rdi]		; get its vtable
	call	qword [rcx+tui_vfirekeyevent]
	test	eax, eax
	jnz	.usefocusdone
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rdi]		; get our vtable
	call	qword [rcx+tui_vkeyevent]
	add	rsp, 32
	epilog
calign
.usefocusdone:
.kidsdone:
	add	rsp, 32
	epilog
end if


if used tui_object$ontab | defined include_everything
	; single argument: our tui object in rdi
	; default propagates the call up the tree
falign
tui_object$ontab:
	prolog	tui_object$ontab
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rsi, [rdi]		; load up the parent's vtable
	call	qword [rsi+tui_vontab]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$onshifttab | defined include_everything
	; single argument: our tui object in rdi
	; default propagates the call up the tree
falign
tui_object$onshifttab:
	prolog	tui_object$onshifttab
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rsi, [rdi]		; load up the parent's vtable
	call	qword [rsi+tui_vonshifttab]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$click | defined include_everything
	; single argument: our tui object in rdi
	; default calls parent's clicked vmethod with our rdi as its argument
falign
tui_object$click:
	prolog	tui_object$click
	mov	rsi, rdi
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rdx, [rdi]		; load up the parent's vtable
	call	qword [rdx+tui_vclicked]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$clicked | defined include_everything
	; two arguments: rdi == our tui_object, rsi == displayobject that fired the click
	; default just walks up the tree
falign
tui_object$clicked:
	prolog	tui_object$clicked
	mov	rdi, [rdi+tui_parent_ofs]
	test	rdi, rdi
	jz	.noparent
	mov	rdx, [rdi]		; load up the parent's vtable
	call	qword [rdx+tui_vclicked]
	epilog
calign
.noparent:
	epilog
end if


if used tui_object$nvbox | defined include_everything
	; six arguments: tui_object (or descendent) in rdi, x in esi, y in edx, width in ecx, height in r8d, colors in r9d
	; this is a convenience function to draw a box, since lots of descendent components do such things
falign
tui_object$nvbox:
	prolog	tui_object$nvbox
	mov	eax, [rdi+tui_width_ofs]		; actual object width
	mov	r10, [rdi+tui_text_ofs]
	mov	r11, [rdi+tui_attr_ofs]
	test	eax, eax
	jz	.bailout
	test	r10, r10
	jz	.bailout
	cmp	esi, dword [rdi+tui_width_ofs]
	jae	.bailout				; sanity check
	cmp	edx, dword [rdi+tui_height_ofs]
	jae	.bailout				; sanity check
	sub	eax, esi				; actual object width - x == max width
	cmp	ecx, eax
	cmova	ecx, eax
	mov	eax, [rdi+tui_height_ofs]
	sub	eax, edx				; actual object height - y == max height
	cmp	r8d, eax
	cmova	r8d, eax
	cmp	ecx, 0
	jle	.bailout
	cmp	r8d, 0
	jle	.bailout
	; values sanitized, we need to make use of a few more temporaries
	push	rbx r12 r13 r14 r15
	; being a bit lazy here, hahah
	mov	eax, [rdi+tui_width_ofs]
	mul	edx					; y * actual object width
	shl	eax, 2					; in bytes

	mov	ebx, esi				; x
	shl	ebx, 2					; in bytes

	mov	r12d, [rdi+tui_width_ofs]		; actual object width
	shl	r12d, 2					; in bytes
	
	; update both r10 and r11 by our starting location
	add	r10, rax
	add	r11, rax

	; do the first line
	mov	r14, r10
	mov	r15, r11
	add	r14, rbx
	add	r15, rbx
	mov	r13d, ecx				; our width in characters
	sub	r13d, 2					; less corners
	mov	dword [r14], 0x250c			; ULCORNER
	mov	dword [r15], r9d			; attr
	add	r14, 4
	add	r15, 4
	cmp	r13d, 0
	jle	.firstlinenomiddle
calign
.firstlineloop:
	mov	dword [r14], 0x2500			; HLINE
	mov	dword [r15], r9d			; attr
	add	r14, 4
	add	r15, 4
	sub	r13d, 1
	jnz	.firstlineloop
calign
.firstlinenomiddle:
	mov	dword [r14], 0x2510			; URCORNER
	mov	dword [r15], r9d			; attr
	add	r14, 4
	add	r15, 4
	
	; now we can increment r10 and r11 by a whole line
	add	r10, r12
	add	r11, r12
	; now r10 and r11 are sitting on the second line left edge of actual object (not x-modified)
	mov	r13d, r8d				; height
	sub	r13d, 2					; -2 cuz we are doing top/bottom separately
	cmp	r13d, 0
	jle	.nomiddle
	mov	edx, ecx				; our box width
	shl	edx, 2					; in bytes
	sub	edx, 4					; offset to last position
calign
.midloop:
	mov	r14, r10
	mov	r15, r11
	add	r14, rbx
	add	r15, rbx
	mov	dword [r14], 0x2502			; VLINE
	mov	dword [r15], r9d			; attr

	add	r14, rdx
	add	r15, rdx
	mov	dword [r14], 0x2502			; VLINE
	mov	dword [r15], r9d			; attr
	
	add	r10, r12
	add	r11, r12
	sub	r13d, 1
	jnz	.midloop
calign
.nomiddle:
	mov	r14, r10
	mov	r15, r11
	add	r14, rbx
	add	r15, rbx
	mov	r13d, ecx
	sub	r13d, 2
	mov	dword [r14], 0x2514			; LLCORNER
	mov	dword [r15], r9d
	add	r14, 4
	add	r15, 4
	cmp	r13d, 0
	jle	.lastlinenomiddle
calign
.lastlineloop:
	mov	dword [r14], 0x2500			; HLINE
	mov	dword [r15], r9d
	add	r14, 4
	add	r15, 4
	sub	r13d, 1
	jnz	.lastlineloop
calign
.lastlinenomiddle:
	mov	dword [r14], 0x2518			; LRCORNER
	mov	dword [r15], r9d

	pop	r15 r14 r13 r12 rbx
	epilog
calign
.bailout:
	epilog
end if


if used tui_object$nvtile | defined include_everything
	; two arguments: rdi == a tui_object or descendent, esi == bool for horizontal or not
	; CAUTION: this forces the layout to absolute for the object in rdi (as it must)
	; further: if we don't have valid bounds, this doesn't do much
falign
tui_object$nvtile:
	prolog	tui_object$nvtile
	mov	rdx, [rdi+tui_children_ofs]
	mov	rcx, [rdx+_list_size_ofs]
	test	ecx, ecx
	jz	.nothingtodo
	mov	dword [rdi+tui_layout_ofs], tui_layout_absolute
	; figure out the most-equal divisors for our child count in ecx
	; we'll need the integer square root of ecx first up
	mov	edx, ecx
	xor	r8d, r8d
	mov	r9d, 1 shl 30

	; make soure our bounds is not empty
	mov	r10d, [rdi+tui_bounds_ax_ofs]
	mov	r11d, [rdi+tui_bounds_ay_ofs]
	cmp	r10d, [rdi+tui_bounds_bx_ofs]
	jl	.isqr1
	cmp	r11d, [rdi+tui_bounds_by_ofs]
	jae	.nothingtodo
calign
.isqr1:
	cmp	r9d, edx
	jbe	.isqr2
	shr	r9d, 2
	jmp	.isqr1
calign
.isqr2:
	mov	eax, r8d
	test	r9d, r9d
	jz	.isqr2_done
	add	eax, r9d
	cmp	edx, eax
	jae	.isqr2_mod
	shr	r8d, 1
	shr	r9d, 2
	jmp	.isqr2
calign
.isqr2_mod:
	mov	r10d, r9d
	sub	edx, eax
	shl	r10d, 1
	add	r8d, r10d
	shr	r8d, 1
	shr	r9d, 2
	jmp	.isqr2
calign
.isqr2_done:
	; result is sitting in r8d
	xor	edx, edx
	mov	eax, ecx
	div	r8d
	test	edx, edx
	jz	.med_check2
	mov	r10d, r8d
	xor	edx, edx
	add	r10d, 1
	mov	eax, ecx
	div	r10d
	test	edx, edx
	cmovz	r8d, r10d
calign
.med_check2:
	xor	edx, edx
	mov	eax, ecx
	div	r8d
	cmp	r8d, eax
	cmovb	r8d, eax

	xor	edx, edx
	mov	eax, ecx
	div	r8d

	; x == eax
	; y == r8d
	; childcount still sitting in ecx

	test	esi, esi
	cmovnz	r10d, eax
	cmovnz	r11d, r8d
	cmovz	r10d, r8d
	cmovz	r11d, eax

	; number of columns now sitting in r10d
	; number of rows now sitting in r11d

	; make sure our bounds rect will allow our cols/rows to fit
	mov	eax, [rdi+tui_bounds_bx_ofs]
	xor	edx, edx
	sub	eax, [rdi+tui_bounds_ax_ofs]
	div	r10d
	test	eax, eax
	jz	.nothingtodo		; tiling error if width / number of columns == 0
	mov	eax, [rdi+tui_bounds_by_ofs]
	xor	edx, edx
	sub	eax, [rdi+tui_bounds_ay_ofs]
	div	r11d
	test	eax, eax
	jz	.nothingtodo		; tiling error if height / number of rows == 0

	; otherwise, we need some more regs
	push	rbx r12 r13 r14 r15
	; figure out how many are leftover
	mov	eax, ecx
	xor	edx, edx
	div	r10d
	mov	r14d, ecx
	mov	r15d, edx		; leftover count in r15d
	sub	r14d, 1			; starting tile number in r14d

	; next up, walk through our children list one by one
	mov	r13, [rdi+tui_children_ofs]
	mov	r13, [r13+_list_first_ofs]
calign
.childloop:
	mov	r12, [r13]		; the actual tui_object child at this list position
	; save a copy of the child's width/height before we do anything, to see if we need
	; to call its sizechanged method or not
	mov	eax, [r12+tui_width_ofs]
	mov	edx, [r12+tui_height_ofs]
	push	rax rdx

	; next up, we need to calculate the tile rect for this child
	
	; x in r8d
	; y in r9d
	; d in ecx

	mov	eax, r10d		; number of columns
	sub	eax, r15d		; less how many are leftover
	mul	r11d			; * number of rows
	mov	ecx, eax

	cmp	r14d, ecx
	jae	.childloop_tilerect_case2
	; else, childloop_tilerect_case1
	; set x = tile number / number of rows
	xor	edx, edx
	mov	eax, r14d
	div	r11d
	mov	r8d, eax
	; set y = tile number % number of rows
	mov	r9d, edx

	; now calculate the actual child bounds, we are done with ecx
	; child bounds:
	;	a.x = (((parent.b.x - parent.a.x) * x) / numcols) + parent.a.x
	mov	ecx, r8d
	mov	eax, [rdi+tui_bounds_bx_ofs]
	sub	eax, [rdi+tui_bounds_ax_ofs]
	mul	r8d
	div	r10d
	add	eax, [rdi+tui_bounds_ax_ofs]
	mov	[r12+tui_bounds_ax_ofs], eax
	add	ecx, 1
	;	b.x = (((parent.b.x - parent.a.x) * (x+1) / numcols) + parent.a.x
	mov	eax, [rdi+tui_bounds_bx_ofs]
	sub	eax, [rdi+tui_bounds_ax_ofs]
	mul	ecx
	div	r10d
	add	eax, [rdi+tui_bounds_ax_ofs]
	mov	[r12+tui_bounds_bx_ofs], eax
	;	a.y = (((parent.b.y - parent.a.y) * y) / numrows) + parent.a.y
	mov	ecx, r9d
	mov	eax, [rdi+tui_bounds_by_ofs]
	sub	eax, [rdi+tui_bounds_ay_ofs]
	mul	r9d
	div	r11d
	add	eax, [rdi+tui_bounds_ay_ofs]
	mov	[r12+tui_bounds_ay_ofs], eax
	add	ecx, 1
	;	b.y = (((parent.b.y - parent.a.y) * (y+1) / numrows) + parent.a.y
	mov	eax, [rdi+tui_bounds_by_ofs]
	sub	eax, [rdi+tui_bounds_ay_ofs]
	mul	ecx
	div	r11d
	add	eax, [rdi+tui_bounds_ay_ofs]
	mov	[r12+tui_bounds_by_ofs], eax

	jmp	.childloop_tilerect_done

calign
.childloop_tilerect_case2:
	mov	eax, r14d
	mov	r9d, r11d
	sub	eax, ecx
	add	r9d, 1
	xor	edx, edx
	div	r9d
	; set y = tilenumber - d % (number of rows + 1)
	mov	r9d, edx
	; set x = tilenumber - d / (number of rows + 1) + (number of columns - leftover count)
	mov	r8d, r10d
	sub	r8d, r15d
	add	eax, r8d
	xchg	eax, r8d

	; now calculate the actual child bounds, we are done with ecx
	; child bounds:
	;	a.x = (((parent.b.x - parent.a.x) * x) / numcols) + parent.a.x
	mov	ecx, r8d
	mov	eax, [rdi+tui_bounds_bx_ofs]
	sub	eax, [rdi+tui_bounds_ax_ofs]
	mul	r8d
	div	r10d
	add	eax, [rdi+tui_bounds_ax_ofs]
	mov	[r12+tui_bounds_ax_ofs], eax
	add	ecx, 1
	;	b.x = (((parent.b.x - parent.a.x) * (x+1) / numcols) + parent.a.x
	mov	eax, [rdi+tui_bounds_bx_ofs]
	sub	eax, [rdi+tui_bounds_ax_ofs]
	mul	ecx
	div	r10d
	add	eax, [rdi+tui_bounds_ax_ofs]
	mov	[r12+tui_bounds_bx_ofs], eax
	; temporarily increase number of rows by 1
	add	r11d, 1
	;	a.y = (((parent.b.y - parent.a.y) * y) / (numrows+1)) + parent.a.y
	mov	ecx, r9d
	mov	eax, [rdi+tui_bounds_by_ofs]
	sub	eax, [rdi+tui_bounds_ay_ofs]
	mul	r9d
	div	r11d
	add	eax, [rdi+tui_bounds_ay_ofs]
	mov	[r12+tui_bounds_ay_ofs], eax
	add	ecx, 1
	;	b.y = (((parent.b.y - parent.a.y) * (y+1) / (numrows+1)) + parent.a.y
	mov	eax, [rdi+tui_bounds_by_ofs]
	sub	eax, [rdi+tui_bounds_ay_ofs]
	mul	ecx
	div	r11d
	add	eax, [rdi+tui_bounds_ay_ofs]
	mov	[r12+tui_bounds_by_ofs], eax

	; restore our number of rows
	sub	r11d, 1

calign
.childloop_tilerect_done:

	; set its width, height, absolutex and absolutey
	mov	eax, [r12+tui_bounds_bx_ofs]
	mov	ecx, [r12+tui_bounds_by_ofs]
	sub	eax, [r12+tui_bounds_ax_ofs]
	sub	ecx, [r12+tui_bounds_ay_ofs]
	mov	[r12+tui_width_ofs], eax
	mov	[r12+tui_height_ofs], ecx
	
	mov	eax, [r12+tui_bounds_ax_ofs]
	mov	ecx, [r12+tui_bounds_ay_ofs]
	sub	eax, [rdi+tui_bounds_ax_ofs]
	sub	ecx, [rdi+tui_bounds_ay_ofs]
	mov	[r12+tui_absolutex_ofs], eax
	mov	[r12+tui_absolutey_ofs], ecx

	pop	rdx rax
	cmp	eax, [r12+tui_width_ofs]
	jne	.childloop_sizechanged
	cmp	edx, [r12+tui_height_ofs]
	jne	.childloop_sizechanged

	sub	r14d, 1
	mov	r13, [r13+_list_nextofs]
	test	r13, r13
	jnz	.childloop

	pop	r15 r14 r13 r12 rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	epilog
calign
.childloop_sizechanged:
	; we need to save r10d, r11d, rdi
	push	rdi r10 r11
	mov	rdi, r12
	mov	rsi, [r12]
	call	qword [rsi+tui_vsizechanged]
	pop	r11 r10 rdi
	
	sub	r14d, 1
	mov	r13, [r13+_list_nextofs]
	test	r13, r13
	jnz	.childloop
	
	pop	r15 r14 r13 r12 rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_object$nvcascade | defined include_everything
	; single argument in rdi: our tui_object
	; CAUTION: this forces the layout to absolute for the object in rdi (as it must)
	;
	; since we don't do preferred dimensions on objects, if you tile and then cascade
	; the windows won't get their original dims back of course...
falign
tui_object$nvcascade:
	prolog	tui_object$nvcascade
	mov	rdx, [rdi+tui_children_ofs]
	mov	rcx, [rdx+_list_size_ofs]
	test	ecx, ecx
	jz	.nothingtodo
	mov	dword [rdi+tui_layout_ofs], tui_layout_absolute
	mov	rcx, [rdx+_list_first_ofs]
	xor	eax, eax
calign
.childloop:
	mov	rdx, [rcx]			; the actual child object
	mov	[rdx+tui_absolutex_ofs], eax
	mov	[rdx+tui_absolutey_ofs], eax
	add	eax, 1
	mov	rcx, [rcx+_list_nextofs]
	test	rcx, rcx
	jnz	.childloop

	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	epilog
calign
.nothingtodo:
	epilog

end if
