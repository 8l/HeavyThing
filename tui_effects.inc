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
	; tui_effects.inc: various tui_effect transitions
	;
	; See the examples as to how to make these work correctly.
	;

if used tui_effect$hslidein | defined include_everything

	; four arguments: rdi == object to append child to, rsi == new child, edx == 0 == right to left, edx == 1 == left to right, rcx == 0 or function to call when effect completes, r8 == arg of oncomplete (if rcx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$hslidein:
	prolog	tui_effect$hslidein
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsi+tui_parent_ofs], rdi
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$vtable
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_appendchild
	mov	rdx, [rsp+8]
	mov	ecx, 50
	call	tui_effect$init
	; now, we need the dimension of either the effect, or the child to determine initial positions
	cmp	dword [rsp+16], 0
	je	.fromright
	; else, from left, which means we need the child size
	mov	rsi, [rsp+8]
	mov	eax, dword [rsi+tui_width_ofs]
	cvtsi2sd xmm15, eax
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .movefromleft
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.fromright:
	; need the effect size:
	mov	rsi, [rsp+24]
	mov	eax, dword [rsi+tui_width_ofs]
	cvtsi2sd xmm15, eax
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .movefromright
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.movefromleft:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_xvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [_math_zeropointone]
	; from the left means we want negative initial positions
	subsd	xmm0, xmm15
	subsd	xmm0, xmm6
	movsd	xmm2, xmm6			; xvel = 1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_x_ofs], xmm0
	movq	[rdi+tui_particle_minx_ofs], xmm0
	movq	[rdi+tui_particle_xvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_hgravity_ofs], xmm7	; hgravity = +0.1
	ret
calign
.movefromright:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_xvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [.hgrav]
	; from the right means we want positive initial positions
	addsd	xmm0, xmm15
	addsd	xmm0, xmm6
	movsd	xmm2, xmm5			; xvel = -1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_x_ofs], xmm0
	movq	[rdi+tui_particle_maxx_ofs], xmm0
	movq	[rdi+tui_particle_xvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_hgravity_ofs], xmm7
	ret
dalign
.hgrav	dq	-0.1f

end if



if used tui_effect$vslidein | defined include_everything

	; four arguments: rdi == object to append child to, rsi == new child, edx == 0 == bottom to top, edx == 1 == top to bottom, rcx == 0 or function to call when effect completes, r8 == arg of oncomplete (if rcx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$vslidein:
	prolog	tui_effect$vslidein
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsi+tui_parent_ofs], rdi
	mov	[rsp+24], rcx
	mov	[rsp+32], r8

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$vtable
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_appendchild
	mov	rdx, [rsp+8]
	mov	ecx, 50
	call	tui_effect$init
	; now, we need the dimension of either the effect, or the child to determine initial positions
	cmp	dword [rsp+16], 0
	je	.frombottom
	; else, from top, which means we need the child size
	mov	rsi, [rsp+8]
	mov	eax, dword [rsi+tui_height_ofs]
	cvtsi2sd xmm15, eax
	mov	rdx, [rsp+24]
	mov	ecx, [rdx+tui_height_ofs]
	cvtsi2sd xmm14, ecx
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .movefromtop
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.frombottom:
	; need the effect size:
	mov	rsi, [rsp+24]
	mov	eax, dword [rsi+tui_height_ofs]
	cvtsi2sd xmm15, eax
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .movefrombottom
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.movefromtop:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_yvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [_math_zeropointone]
	; from the top means we want negative initial positions
	subsd	xmm1, xmm14
	subsd	xmm1, xmm6
	movsd	xmm2, xmm6			; yvel = 1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_y_ofs], xmm1
	movq	[rdi+tui_particle_miny_ofs], xmm1
	movq	[rdi+tui_particle_yvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_gravity_ofs], xmm7	; gravity = +0.1
	ret
calign
.movefrombottom:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_yvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [.grav]
	; from the bottom means we want positive initial positions
	addsd	xmm1, xmm15
	addsd	xmm1, xmm6
	movsd	xmm2, xmm5			; yvel = -1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_y_ofs], xmm1
	movq	[rdi+tui_particle_maxy_ofs], xmm1
	movq	[rdi+tui_particle_yvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_gravity_ofs], xmm7
	ret
dalign
.grav	dq	-0.1f

end if

if used tui_effect$hslideout | defined include_everything

	; four arguments: rdi == object to remove child from, rsi == child, edx == 0 == out the left, edx == 1 == out the right, rcx == 0 or function to call when effect completes, r8 == arg of oncomplete (if rcx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$hslideout:
	prolog	tui_effect$hslideout
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$vtable
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_removechild
	mov	rdx, [rsp+8]
	mov	ecx, 50
	call	tui_effect$init
	; since we are sliding out, final positions for all particles can be width or -1 depending on our direction
	cmp	dword [rsp+16], 0
	je	.goleft
	; else, we goin right, so we need the width of our effect
	mov	rsi, [rsp+24]
	mov	eax, dword [rsi+tui_width_ofs]
	cvtsi2sd xmm15, eax
	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .moveright
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.goleft:
	movq	xmm15, [_math_negone]
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .moveleft
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.moveright:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_xvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [_math_zeropointone]
	; targetx and maxx both need set to xmm15
	movq	[rdi+tui_particle_targetx_ofs], xmm15
	movq	[rdi+tui_particle_maxx_ofs], xmm15
	movsd	xmm2, xmm6			; xvel = 1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_xvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_hgravity_ofs], xmm7	; gravity = +0.1
	ret
calign
.moveleft:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_xvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [.grav]
	; targetx and minx both need set to xmm15
	movq	[rdi+tui_particle_targetx_ofs], xmm15
	movq	[rdi+tui_particle_minx_ofs], xmm15
	movsd	xmm2, xmm5			; xvel = -1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_xvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_hgravity_ofs], xmm7
	ret
dalign
.grav	dq	-0.1f

end if


if used tui_effect$vslideout | defined include_everything

	; four arguments: rdi == object to append remove child from, rsi == child, edx == 0 == out the top, edx == 1 == out the bottom, rcx == 0 or function to call when effect completes, r8 == arg of oncomplete (if rcx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$vslideout:
	prolog	tui_effect$vslideout
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$vtable
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_removechild
	mov	rdx, [rsp+8]
	mov	ecx, 50
	call	tui_effect$init
	; since we are sliding out, final positions for all particles can be height or -1 depending on our direction
	cmp	dword [rsp+16], 0
	je	.goup
	; else, we goin down, so we need the height of our effect
	mov	rsi, [rsp+24]
	mov	eax, dword [rsi+tui_height_ofs]
	cvtsi2sd xmm15, eax
	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .movedown
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.goup:
	movq	xmm15, [_math_negone]
	mov	rdx, [rsp+24]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .moveup
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.movedown:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_yvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [_math_zeropointone]
	; targety and maxy both need set to xmm15
	movq	[rdi+tui_particle_targety_ofs], xmm15
	movq	[rdi+tui_particle_maxy_ofs], xmm15
	movsd	xmm2, xmm6			; yvel = 1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_yvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_gravity_ofs], xmm7	; gravity = +0.1
	ret
calign
.moveup:
	; single arg in rdi == tui_particle, we need to adjust its default settings
	movq	xmm0, [rdi+tui_particle_x_ofs]
	movq	xmm1, [rdi+tui_particle_y_ofs]
	movq	xmm2, [rdi+tui_particle_yvel_ofs]
	movq	xmm3, [rdi+tui_particle_drag_ofs]
	movq	xmm5, [_math_negone]
	movq	xmm6, [_math_one]
	movq	xmm7, [.grav]
	; targety and miny both need set to xmm15
	movq	[rdi+tui_particle_targety_ofs], xmm15
	movq	[rdi+tui_particle_miny_ofs], xmm15
	movsd	xmm2, xmm5			; yvel = -1.0
	movsd	xmm3, xmm6			; drag = 1.0
	movq	[rdi+tui_particle_yvel_ofs], xmm2
	movq	[rdi+tui_particle_drag_ofs], xmm3
	movq	[rdi+tui_particle_gravity_ofs], xmm7
	ret
dalign
.grav	dq	-0.1f

end if

if used tui_effect$visi_vtable | defined include_everything

; for effects that need to hide/show or vice versa their particles after the delay elapses
; (used by materialize/vaporize)

dalign
tui_effect$visi_vtable:
        dq      tui_effect$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_effect$visi_timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

if used tui_effect$visi_timer | defined include_everything

falign
tui_effect$visi_timer:
	prolog	tui_effect$visi_timer
	; burning purpose: let tui_effect$timer do its thing, but override its notion of whether we are done or not
	; if we iterate through our list, and we didn't flip char/origchar, and all delays are 0, consider us done
	; otherwise, consider us not done
	push	rdi
	call	tui_effect$timer
	pop	rdi
	test	eax, eax
	jnz	.timerdone
	push	rdi r15
	mov	r15d, 1
	mov	rdx, rdi
	mov	rsi, .particlecheck
	mov	rdi, [rdi+tui_effect_particles_ofs]
	call	list$foreach_arg
	mov	ecx, r15d
	pop	r15 rdi
	xor	eax, eax	; make sure we return zero for this one so the next iteration does proper cleanup
	test	ecx, ecx
	jz	.timerdone
	; otherwise, set alldone
	mov	dword [rdi+tui_effect_alldone_ofs], 1
	; eax already clear
	epilog
calign
.timerdone:
	epilog
falign
.particlecheck:
	; so the normal timer already ran, and may have set us to zero
	; our argument in rsi is actually the tui_effect object
	; and depending on whether or not it was a hide effect (tui_effect_user_ofs == 1) or a show effect (tui_effect_user_ofs == 0)
	; determines whether we are setting or clearing
	cmp	dword [rsi+tui_effect_user_ofs], 0
	jne	.hideeffect
	; else, it is a show effect
	cmp	dword [rdi+tui_particle_delay_ofs], 0
	jne	.retonly
	; else, delay is zero, so compare orig char
	mov	eax, dword [rdi+tui_particle_orig_char_ofs]
	cmp	eax, dword [rdi+tui_particle_char_ofs]
	je	.retonly
	; otherwise, we have to SHOW it, and make sure r15d (done flag) gets cleared
	mov	dword [rdi+tui_particle_char_ofs], eax
	xor	r15d, r15d
	ret
calign
.hideeffect:
	cmp	dword [rdi+tui_particle_delay_ofs], 0
	jne	.retonly
	; else, see if the char is zero or not
	cmp	dword [rdi+tui_particle_char_ofs], 0
	je	.retonly
	; otehrwise, we have to HIDE it, and make sure r15d (done flag) gets cleared
	mov	dword [rdi+tui_particle_char_ofs], 0
	xor	r15d, r15d
	ret
calign
.retonly:
	ret

end if

if used tui_effect$bottomline_vtable | defined include_everything

; for effects that need to stop when all particles reach the bottom edge, we need a custom timer implementation

dalign
tui_effect$bottomline_vtable:
        dq      tui_effect$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_effect$bottomline_timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

if used tui_effect$bottomline_timer | defined include_everything

falign
tui_effect$bottomline_timer:
	prolog	tui_effect$bottomline_timer
	; burning purpose: iterate through our particles, and if all of them are at targety, set alldone flag
	push	rdi r15
        mov     r15d, 1
	mov	rdx, rdi
        mov     rsi, .particlecheck
        mov     rdi, [rdi+tui_effect_particles_ofs]
        call    list$foreach_arg
	mov	eax, r15d
	pop	r15 rdi
	mov	dword [rdi+tui_effect_alldone_ofs], eax
	; then call the normal tui_effect$timer
	call	tui_effect$timer
	epilog
falign
.particlecheck:
	movq	xmm0, [rdi+tui_particle_y_ofs]
	movq	xmm1, [rdi+tui_particle_targety_ofs]
	ucomisd	xmm0, xmm1
	je	.isequal
	; else, they are NOT equal, so clear r15d and return
	xor	r15d, r15d
	ret
calign
.isequal:
	; leave r15d alone, return
	ret

end if

if used tui_effect$crumble | defined include_everything
	; a remove effect that looks like the target crumbles/falls away
	; this adds a random particle delay to each one, and then lets gravity take over

	; three arguments: rdi == object to remove child from, rsi == child, rdx == 0 or function to call when effect completes, rcx == arg of oncomplete (if rdx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$crumble:
	prolog	tui_effect$crumble
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$bottomline_vtable	; make sure this one uses bottomline for bailout
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_removechild
	mov	rdx, [rsp+8]
	mov	ecx, 25
	call	tui_effect$init
	mov	rsi, [rsp+24]
	; load up the height of our effect
	mov	eax, dword [rsi+tui_height_ofs]
	cvtsi2sd xmm15, eax
	; set our initial particle properties
	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .adjust
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 32
	epilog
falign
.adjust:
	; height of the effect itself is sitting in xmm15, set targety and maxy to that
	; set particle delay to a random number
	; and set gravity to a fixed number
	movq	[rdi+tui_particle_maxy_ofs], xmm15
	movq	[rdi+tui_particle_targety_ofs], xmm15
	push	rdi
	call	rng$u32
	pop	rdi
	movq	xmm0, [.grav]
	and	eax, 0x7f		; random number between 0..127 inclusive
	mov	dword [rdi+tui_particle_delay_ofs], eax
	movq	[rdi+tui_particle_gravity_ofs], xmm0
	movq	xmm1, [_math_one]
	movq	[rdi+tui_particle_drag_ofs], xmm1
	ret
dalign
.grav	dq	0.025f

end if

if used tui_effect$vaporize | defined include_everything
	; a remove effect that at random intervals removes each particle
	; this adds a random particle delay to each one

	; three arguments: rdi == object to remove child from, rsi == child, rdx == 0 or function to call when effect completes, rcx == arg to oncomplete (if rdx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$vaporize:
	prolog	tui_effect$vaporize
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$visi_vtable		; make sure this one uses the visibility based timer
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_removechild
	mov	rdx, [rsp+8]
	mov	ecx, 15						; timer delay in ms
	call	tui_effect$init
	mov	rsi, [rsp+24]
	mov	dword [rsi+tui_effect_user_ofs], 1		; hide effect
	; so, vaporize doesn't actually MOVE any particles, just sets them to 0 when the delay expires
	; and assigns random delays for each of them
	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .adjust
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 32
	epilog
falign
.adjust:
	push	rdi
	call	rng$u32
	pop	rdi
	and	eax, 0x3f		; random number between 0..63 inclusive

	; add	eax, 25

	mov	dword [rdi+tui_particle_delay_ofs], eax
	; make targetx +1, and since these don't move, this will never be reached
	; and this way, leaves it up to visi_timer to establish whether we are done or not
	movq	xmm0, [rdi+tui_particle_targetx_ofs]
	addsd	xmm0, [_math_one]
	movq	[rdi+tui_particle_targetx_ofs], xmm0
	ret

end if


if used tui_effect$materialize | defined include_everything
	; append effect that at random intervals shows each particle
	; this adds a random particle delay to each one, and then lets gravity take over

	; three arguments: rdi == object to append child to, rsi == new child, rdx == 0 or function to call when effect completes, rcx == arg to oncomplete (if rdx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$materialize:
	prolog	tui_effect$materialize
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsi+tui_parent_ofs], rdi

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$visi_vtable		; make sure this one uses the visibility based timer
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_appendchild
	mov	rdx, [rsp+8]
	mov	ecx, 15						; timer delay in ms
	call	tui_effect$init
	mov	rsi, [rsp+24]
	mov	dword [rsi+tui_effect_user_ofs], 0		; show effect
	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .adjust
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 32
	epilog
falign
.adjust:
	push	rdi
	call	rng$u32
	pop	rdi
	and	eax, 0x3f		; random number between 0..63 inclusive
	mov	dword [rdi+tui_particle_char_ofs], 0
	mov	dword [rdi+tui_particle_delay_ofs], eax
	; make targetx +1, and since these don't move, this will never be reached
	; and this way, leaves it up to visi_timer to establish whether we are done or not
	movq	xmm0, [rdi+tui_particle_targetx_ofs]
	addsd	xmm0, [_math_one]
	movq	[rdi+tui_particle_targetx_ofs], xmm0
	ret

end if


if used tui_effect$fountain | defined include_everything
	; append effect that "spews" particles up from the bottom center, particles are randomized
	; three arguments: rdi == object to append child to, rsi == new child, rdx == 0 or function to call when effect completes, rcx == arg to oncomplete (if rdx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$fountain:
	prolog	tui_effect$fountain
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsi+tui_parent_ofs], rdi

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$vtable		; normal vtable for this one
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_appendchild
	mov	rdx, [rsp+8]
	mov	ecx, 50
	call	tui_effect$init
	mov	rsi, [rsp+24]

	; we need to know the center x position, and the height of our object
	; we can preload them in xmm14, xmm15 for use in our adjuster
	mov	eax, [rsi+tui_width_ofs]
	mov	ecx, [rsi+tui_height_ofs]
	cvtsi2sd xmm13, eax				; width
	shr	eax, 1
	cvtsi2sd xmm14, eax				; width/2
	add	ecx, 1
	cvtsi2sd xmm15, ecx				; height+1
	; NOTE: xmm13/xmm14/xmm15 are preserved across calls to rng$ so it is save to do this once beforehand

	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .adjust
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 32
	epilog
falign
.adjust:
	push	rdi
	call	rng$u32
	pop	rdi
	and	eax, 0x7f		; random number between 0..127 inclusive
	mov	dword [rdi+tui_particle_delay_ofs], eax
	xorpd	xmm12, xmm12
	; we want the initial starting position to be width/2 height+1
	movq	[rdi+tui_particle_x_ofs], xmm14
	movq	[rdi+tui_particle_y_ofs], xmm15
	movq	[rdi+tui_particle_minx_ofs], xmm12
	movq	[rdi+tui_particle_maxx_ofs], xmm13
	movq	[rdi+tui_particle_miny_ofs], xmm12
	movq	[rdi+tui_particle_maxy_ofs], xmm15
	; so now, positions are all set, and targetx/targety are still valid from our initial call
	; next up, we need to set our initial xvel/yvel
	push	rdi
	call	rng$double
	pop	rdi

	movq	xmm1, [.half]
	subsd	xmm1, xmm0

	movq	[rdi+tui_particle_xvel_ofs], xmm1	; xvel == -0.5..0.5
	movq	xmm0, [.speed]
	movq	[rdi+tui_particle_yvel_ofs], xmm0	; yvel == speed
	movq	xmm0, [.grav]
	movq	[rdi+tui_particle_gravity_ofs], xmm0
	movq	xmm0, [.drag]
	movq	[rdi+tui_particle_drag_ofs], xmm0
	; now, in order to get this particle to actually snap to where it belongs, we need to create a force specific to this particle
	; that has an attraction to its target position

	; unfortunately, we need to set the particle's min/max x and y relative to the center position of our particle
	; and the reason for this is, velocity does not just stop on a dime when our target is reached (and this is partly because
	; the target is never really reached)
	; so we can prevent this, and make our particles LAND where they go by making sure that the minx/miny is set accordingly
	push	rdi
	mov	edi, tui_force_size
	call	heap$alloc
	pop	rdi
	movq	xmm0, [rdi+tui_particle_targetx_ofs]
	movq	xmm1, [rdi+tui_particle_targety_ofs]
	; set miny == targety ...
	; NOTE: this is not really ideal, because this prevents particles from flying up, arcing back down to where they land
	; TODO: come back and make this a bit more fancy, haha
	movq	[rdi+tui_particle_miny_ofs], xmm1
	movq	xmm2, [.strength]
	xorpd	xmm3, xmm3
	xor	ecx, ecx
	movq	[rax+tui_force_x_ofs], xmm0
	movq	[rax+tui_force_y_ofs], xmm1
	movq	[rax+tui_force_strength_ofs], xmm2
	mov	dword [rax+tui_force_active_ofs], 1
	movq	[rax+tui_force_radius_ofs], xmm3
	mov	[rax+tui_force_bounds_ofs], rcx
	mov	[rax+tui_force_bounds_bx_ofs], rcx
	mov	[rax+tui_force_update_ofs], rcx
	; now, we need to determine whether we need to set minx or maxx, depending on whether this pixel is going to go left or right
	movq	xmm4, [rdi+tui_particle_x_ofs]	; its initial starting position
	ucomisd xmm4, xmm0
	jae	.goingleft
	; else, our starting position is less than our target final position, so our particle is going right
	; set maxx to our targetx
	movq	[rdi+tui_particle_maxx_ofs], xmm0

	mov	rdi, [rdi+tui_particle_forces_ofs]
	mov	rsi, rax
	call	list$push_back
	ret
calign
.goingleft:
	; our starting position is >= our target final position, so our particle is going left
	movq	[rdi+tui_particle_minx_ofs], xmm0
	
	mov	rdi, [rdi+tui_particle_forces_ofs]
	mov	rsi, rax
	call	list$push_back
	ret

; settings for the effect... hahah
dalign
.half	dq	0.5f
.speed	dq	-1.5f
.grav	dq	0.05f
.drag	dq	1.0f
.strength	dq	-0.2f

end if



if used tui_effect$sprinkle | defined include_everything
	; an append effect that looks like the target sprinkles in from above
	; this adds a random particle delay to each one, and then lets gravity take over

	; three arguments: rdi == object to append child to, rsi == new child, rdx == 0 or function to call when effect completes, rcx == arg to oncomplete (if rdx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$sprinkle:
	prolog	tui_effect$sprinkle
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsi+tui_parent_ofs], rdi

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$vtable
	mov	r8, [rsp+16]
	mov	r9, [rsp+24]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_appendchild
	mov	rdx, [rsp+8]
	mov	ecx, 25
	call	tui_effect$init
	mov	rsi, [rsp+24]

	; we need to set all the initial particle's y and miny position to -1, and add a random delay
	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .adjust
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 32
	epilog
falign
.adjust:
	; set miny and y to negone
	; set particle delay to a random number
	; and set gravity to a fixed number
	movq	xmm2, [_math_negone]
	movq	[rdi+tui_particle_miny_ofs], xmm2
	movq	[rdi+tui_particle_y_ofs], xmm2
	push	rdi
	call	rng$u32
	pop	rdi
	movq	xmm0, [.grav]
	and	eax, 0x7f		; random number between 0..127 inclusive
	mov	dword [rdi+tui_particle_delay_ofs], eax
	movq	[rdi+tui_particle_gravity_ofs], xmm0
	movq	xmm1, [_math_one]
	movq	[rdi+tui_particle_drag_ofs], xmm1
	ret
dalign
.grav	dq	0.025f

end if



if used tui_effect$gunshotout | defined include_everything

	; four arguments: rdi == object to remove child from, rsi == child, edx == strength, rcx == 0 or function to call when effect completes, r8 == arg to oncomplete (if rcx)
	; object in rdi must exist and have nonzero dimensions already (e.g. must have already done a layout)
	; NOTE: this one can take a while for all particles to finally reach their target destination
	; returns the tui_effect object in rax (in case you need to modify any of its settings)
falign
tui_effect$gunshotout:
	prolog	tui_effect$gunshotout
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8

	mov	edi, tui_effect_size
	call	heap$alloc
	mov	qword [rax], tui_effect$bottomline_vtable	; make sure this one uses the bottomline for bailout
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, tui_effect_type_removechild
	mov	rdx, [rsp+8]
	mov	ecx, 50
	call	tui_effect$init
	; so now, we need to center a repelling force in the middle of the target bounds
	; note here, we cannot be precisely on an x/y coord for the 'middle'
	; and this is because the character located there if it were would be stuck
	
	mov	edi, tui_force_size
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdx, [rsp+24]
	mov	rsi, rax
	mov	rdi, [rdx+tui_effect_forces_ofs]
	call	list$push_back

	movq	xmm1, [.half]
	; so now, we need target width and height div 2, added to target's bounds.a.x and bounds.a.y
	; + 0.5 each for our force destination
	mov	rdi, [rsp+32]		; force
	mov	rsi, [rsp+8]		; target
	mov	eax, dword [rsi+tui_width_ofs]
	sub	eax, 1
	shr	eax, 1
	add	eax, dword [rsi+tui_bounds_ax_ofs]
	cvtsi2sd xmm0, eax
	addsd	xmm0, xmm1
	movq	[rdi+tui_force_x_ofs], xmm0

	mov	eax, dword [rsi+tui_height_ofs]
	sub	eax, 1
	shr	eax, 1
	add	eax, dword [rsi+tui_bounds_ay_ofs]
	cvtsi2sd xmm0, eax
	addsd	xmm0, xmm1
	movq	[rdi+tui_force_y_ofs], xmm0

	; setup our negative strength
	mov	eax, dword [rsp+16]
	cvtsi2sd xmm15, eax
	movq	[rdi+tui_force_strength_ofs], xmm15
	
	mov	qword [rdi+tui_force_active_ofs], 1
	mov	qword [rdi+tui_force_radius_ofs], 0
	mov	qword [rdi+tui_force_bounds_ofs], 0
	mov	qword [rdi+tui_force_bounds_bx_ofs], 0
	mov	qword [rdi+tui_force_update_ofs], 0
	; now our force is setup

	
	; next we have to iterate all particles and adjust their targety, and min/max
	mov	rsi, [rsp+24]
	; load up the height of our effect
	mov	eax, dword [rsi+tui_height_ofs]
	cvtsi2sd xmm15, eax
	mov	eax, dword [rsi+tui_width_ofs]
	cvtsi2sd xmm14, eax
	xorpd	xmm13, xmm13

	mov	rdi, [rsi+tui_effect_particles_ofs]
	mov	rsi, .adjust
	call	list$foreach
	mov	rax, [rsp+24]
	add	rsp, 40
	epilog
calign
.adjust:
	movq	xmm5, [.drag]
	movq	xmm6, [_math_one]
	movq	xmm7, [.grav]
	xorpd	xmm8, xmm8
	subsd	xmm8, xmm14
	movapd	xmm9, xmm14
	addsd	xmm9, xmm14
	movq	[rdi+tui_particle_minx_ofs], xmm8	; minx = -width of effect
	movq	[rdi+tui_particle_maxx_ofs], xmm9	; maxx = 2xwidth of effect
	xorpd	xmm8, xmm8
	subsd	xmm8, xmm15
	movapd	xmm9, xmm15
	addsd	xmm9, xmm15
	movq	[rdi+tui_particle_miny_ofs], xmm8	; miny = -height of effect
	movq	[rdi+tui_particle_maxy_ofs], xmm15	; maxy = height of effect
	movq	[rdi+tui_particle_targety_ofs], xmm15	; targety = height of effect
	movq	[rdi+tui_particle_drag_ofs], xmm5
	movq	[rdi+tui_particle_gravity_ofs], xmm7
	ret
dalign
.drag	dq	0.8f
.half	dq	0.5f
.grav	dq	0.4f
	
end if
