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
	; tui_effect.inc: the base effect tui_object descendent for all our effects
	;
	; we support various kinds of effects: appendchild, appendbastard, removechild, removebastard, move, distort
	;
	; this base tui_effect layer doesn't do any actual effect, up to descendents of this to actually implement
	; the draw method
	;
	; what we do however is the initial setup that is common to all effects
	; and that is: turn the target into a particle list with no velocity/gravity/drag/etc
	; all with their current positions set to their real position
	;
	; we also provide the basic particle update/draw mechanism, also common to all
	;
	; so the slide effect for example, calls this layer's init, and then does a list$foreach over the particles
	; to set all their initial positions offscreen, and all their initial one-axis velocities to a positive #
	; and thats the entirety of the slide effects functionality, this layer takes care of the rest.
	;
	; each particle carries a target_x and target_y, and the effect will be considered done when all
	; particles reach their target _and_ minframes is reached (this way they can start and end at their target position if we want)
	;


if used tui_effect$vtable | defined include_everything

	; we are pretty much a standard tui_object, but we add a custom timer handler that calls draw
	; repeatedly, and takes care of the final end result depending on our constructor type
dalign
tui_effect$vtable:
	dq      tui_effect$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq      tui_effect$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

end if

tui_effect_parent_ofs = tui_object_size + 0		; the topmost tui_object parent of the target (just so we don't have to traverse each time to find it)
tui_effect_target_ofs = tui_object_size + 8		; the target of our effect itself
tui_effect_particles_ofs = tui_object_size + 16		; a list$new of tui_particle objects
tui_effect_forces_ofs = tui_object_size + 24		; a list$new of tui_force objects
tui_effect_time_ofs = tui_object_size + 32		; time in milliseconds of our timer fire (e.g. for 10fps, this is 100)
tui_effect_frames_ofs = tui_object_size + 40		; how many times the timer has fired
tui_effect_minframes_ofs = tui_object_size + 48		; the minimum number of frames before we contemplate being done, defaults to 0
tui_effect_type_ofs = tui_object_size + 56		; the type of effect we are, one of:
	tui_effect_type_appendchild = 0
	tui_effect_type_appendbastard = 1
	tui_effect_type_removechild = 2
	tui_effect_type_removebastard = 3
	tui_effect_type_move = 4
	tui_effect_type_distort = 5
tui_effect_movex_ofs = tui_object_size + 64		; if type == tui_effect_type_move, this is an int of where to move the target when we are done
tui_effect_movey_ofs = tui_object_size + 72		; "" for y
tui_effect_oncomplete_ofs = tui_object_size + 80	; if this is nonzero when our effect is complete, call this function
tui_effect_oncompletearg_ofs = tui_object_size + 88	; "", this will be rdi
							;      additional note: rsi will be set to the effect itself
tui_effect_injector_ofs = tui_object_size + 96		; convenience list for having a separate list of particles (default tui_effect doesn't make use of this
							; but does clean it up/create it)
tui_effect_alldone_ofs = tui_object_size + 104		; this gets set to 0 on init, but if you set it externally, the next timer cycle that runs will exit and clean itself up
tui_effect_timerptr_ofs = tui_object_size + 112		; this gets set to the epoll timer object upon init, and when cleanup happens, if this is nonzero, we call timer_clear
							; noting that for a "normal" finish (e.g. effect is complete, we clear it when we return 1 from the timer itself)
tui_effect_user_ofs = tui_object_size + 120
tui_effect_size = tui_object_size + 128




	; FORCES:
	; forces have an x/y position, a strength, active bool, an optional maximum distance (radius), an optional bounding box, and 32 bytes of userspace
	; to create "special" forces, hahah... the standard just kinda works like attract/repel with how much being inversely proportional to the distance
	; the target is away
	; 
	; note that this method makes a _point_ force, if you want flatline gravity in on or more directions, use the gravity fields of the particles instead
	; 
tui_force_x_ofs = 0		; double
tui_force_y_ofs = 8		; double
tui_force_strength_ofs = 16	; double
tui_force_active_ofs = 24	; bool
tui_force_radius_ofs = 32	; double
tui_force_bounds_ofs = 48	; bounds
	tui_force_bounds_ax_ofs = 48
	tui_force_bounds_ay_ofs = 52
	tui_force_bounds_bx_ofs = 56
	tui_force_bounds_by_ofs = 60
tui_force_update_ofs = 64	; pointer to the update function itself, useful if you want to create nonstandard forces, can be 0 for default, which doesn't change
tui_force_user_ofs = 72

tui_force_size = 104

	; we aren't creating any tui_force$new functions, up to user to initialize/heap$alloc them

if used tui_force$update | defined include_everything

	; argument in rdi: our tui_force object, argument in rsi: the tui_effect object we are attached to
	; if the update field contains a nonzero function pointer, we call it
	; otherwise, we don't do anything
	; NOTE: if the force is not active, update will still get called, this allows a force to, for example, turn itself
	; on and off over time, haha
	; if however, it is not active, when the particle update occurs, inactive forces are not applied to their values
falign
tui_force$update:
	prolog	tui_force$update
	cmp	qword [rdi+tui_force_update_ofs], 0
	je	.nothingtodo
	call	qword [rdi+tui_force_update_ofs]
	epilog
calign
.nothingtodo:
	epilog

end if


if used tui_force$apply | defined include_everything

	; argument in rdi: our tui_force object
	; NOTE: this relies on the particle's x being in xmm5, y being in xmm6, xvel being in xmm7, and yvel being in xmm8
	; if our force is applied, we only mess with xvel/yvel
falign
tui_force$apply:
	prolog	tui_force$apply
	pxor	xmm10, xmm10
	cmp	dword [rdi+tui_force_active_ofs], 0
	je	.nothingtodo
	; check to see if we have a bounding box first up
	cmp	qword [rdi+tui_force_bounds_bx_ofs], 0
	je	.checkradius
	; TODO: we probably need these values floored
	; else, we do have a nonzero bounding box, so convert this particle's x/y back into integers and check them
	cvtsd2si eax, xmm5				; TODO: change this to use r14/r15 across calls or something so this doesn't need to happen
	cvtsd2si ecx, xmm6
	cmp	eax, dword [rdi+tui_force_bounds_ax_ofs]
	jl	.nothingtodo
	cmp	ecx, dword [rdi+tui_force_bounds_ay_ofs]
	jl	.nothingtodo
	cmp	eax, dword [rdi+tui_force_bounds_bx_ofs]
	jge	.nothingtodo
	cmp	ecx, dword [rdi+tui_force_bounds_by_ofs]
	jge	.nothingtodo
calign
.doit:
	; else, it is inside the bounding box, so strength/distance applies
	; compute our distance first up
	movq	xmm0, [rdi+tui_force_x_ofs]
	movq	xmm1, [rdi+tui_force_y_ofs]
	subsd	xmm0, xmm5
	subsd	xmm1, xmm6
	mulsd	xmm0, xmm0
	mulsd	xmm1, xmm1
	addsd	xmm0, xmm1
	sqrtsd	xmm0, xmm0			; distance
calign
.doit_distancedone:
	; if our distance is zero, do nothing
	ucomisd	xmm0, xmm10
	je	.nothingtodo
	; get our strength
	movq	xmm1, [rdi+tui_force_x_ofs]
	movq	xmm2, [rdi+tui_force_y_ofs]
	movq	xmm3, [rdi+tui_force_strength_ofs]
	; deal with our x velocity modifications first, noting here we amplify the effect for x distance
	; because most all of my terminals are 3:1 width/height wise, and if we don't adjust them differently
	; the effect will be weird
	; testing is the only way to get these adjustments right


	; so, it is acting weird, because i am treating the xdistance and ydistance quite separately
	; the overall effect has to be based on the real distance

	; or, do we try it with ONLY the real distance... hmm the reason I separated it to begin with was
	; due to 3:1 browser... hmm

	; dx = x distance
	; dy = y distance

	; figure out strength / distance first
	divsd	xmm3, xmm0			; strength / distance
	; multiply that by dx to get our x modifier
	subsd	xmm1, xmm5			; x distance
	mulsd	xmm1, xmm3

	subsd	xmm7, xmm1
	; multiply that by dy to get our y modifier
	subsd	xmm2, xmm6			; y distance
	mulsd	xmm2, xmm3

	subsd	xmm8, xmm2
	epilog
calign
.checkradius:
	; if the radius is zero, then go ahead and do it, otherwise we need to check distance against radius
	movq	xmm9, [rdi+tui_force_radius_ofs]
	ucomisd	xmm9, xmm10
	je	.doit
	; otherwise, compute the distance, then check against xmm9
	movq	xmm0, [rdi+tui_force_x_ofs]
	movq	xmm1, [rdi+tui_force_y_ofs]
	subsd	xmm0, xmm5
	subsd	xmm1, xmm6
	mulsd	xmm0, xmm0
	mulsd	xmm1, xmm1
	addsd	xmm0, xmm1
	sqrtsd	xmm0, xmm0			; distance
	ucomisd	xmm0, xmm9
	jbe	.doit_distancedone
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_effect$cleanup | defined include_everything

	; single argument in rdi: our tui_effect object
falign
tui_effect$cleanup:
	prolog	tui_effect$cleanup
	push	rdi
	cmp	qword [rdi+tui_effect_timerptr_ofs], 0
	je	.notimerclear
	mov	rdi, [rdi+tui_effect_timerptr_ofs]
	call	epoll$timer_clear
	mov	rdi, [rsp]
	mov	qword [rdi+tui_effect_timerptr_ofs], 0
calign
.notimerclear:
	; we have to remove ourselves from our parent's bastard child list, free particles list and forces list
	; noting that for each particle, there may be more lists
	mov	rsi, rdi
	mov	rdi, [rsi+tui_effect_parent_ofs]
	call	tui_object$removebastard
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	mov	rsi, .particlefree
	call	list$clear
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_particles_ofs]
	call	heap$free
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_injector_ofs]
	mov	rsi, .particlefree
	call	list$clear
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_injector_ofs]
	call	heap$free
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_forces_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_forces_ofs]
	call	heap$free

	; deal with our tui_object cleanup as well:
	mov	rdi, [rsp]
	call	tui_object$cleanup

	pop	rdi
	epilog
falign
.particlefree:
	push	rdi
	mov	rdi, [rdi+tui_particle_forces_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_particle_forces_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	ret

end if


if used tui_effect$init | defined include_everything

	; rdi == tui_effect object (descendent), esi == tui_effect_type, rdx == target, ecx == timer delay (ms), [ r8d == movex, r9d == movey, but only for type == tui_effect_type_move ]
	; if type != movex, r8 == oncomplete call, and if you want oncomplete functionality with type == move, set the oncomplete var yourself after init
	;     further, if type != movex, r9 == oncomplete call argument, again, set manually if you want it with type == move
	; this calls tui_object$init_defaults for our own effect object, then appends us as a bastard to the topmost parent of target
	; and then depending on what type of effect we are, if appending, sets visible = 0 for the target, and goes ahead and adds it
	; (which calculates its layout but doesn't actually draw it)
	; and if a remove/move/distort, doesn't do anything to target
	; and then turns target into a list of particles, and finally creates our epoll timer
	; no return
	; NOTE: we do not set our vtable (up to the caller), AND!! vtable must be set for us BEFORE ENTRY TO HERE.

	; ALSO NOTE NOTE NOTE: if we are an append effect, the target's parent must be set to the desired object that we are ultimately appending it to
	; but it must not yet be actually appended. the rest of the use cases assume that parent is valid/already set and that the child is already sweet/happy
falign
tui_effect$init:
	prolog	tui_effect$init
	mov	[rdi+tui_effect_target_ofs], rdx
	mov	[rdi+tui_effect_time_ofs], rcx
	mov	qword [rdi+tui_effect_frames_ofs], 0
	mov	qword [rdi+tui_effect_minframes_ofs], 0
	mov	[rdi+tui_effect_type_ofs], rsi
	mov	r10, r8
	xor	r11d, r11d
	cmp	esi, tui_effect_type_move
	cmove	r10, r11
	mov	[rdi+tui_effect_movex_ofs], r8		; if type isn't move, it is okay for these to be junk
	mov	[rdi+tui_effect_movey_ofs], r9
	mov	[rdi+tui_effect_oncomplete_ofs], r10
	; r9 may have been an oncompletearg, and if type == move, then this will be junk, but thats okay
	mov	[rdi+tui_effect_oncompletearg_ofs], r9
	push	rdi
	call	tui_object$init_defaults
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_effect_particles_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_effect_forces_ofs], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+tui_effect_injector_ofs], rax
	mov	qword [rdi+tui_effect_alldone_ofs], 0
	; now we need to establish the topmost parent of the target object, results are undefined if there is none, hahah, caller beware
	mov	rsi, [rdi+tui_effect_target_ofs]
	xor	rdx, rdx
calign
.findparent:
	mov	rdx, rsi
	mov	rsi, [rsi+tui_parent_ofs]
	test	rsi, rsi
	jnz	.findparent
	; rdx now has our topmost parent
	mov	[rdi+tui_effect_parent_ofs], rdx
	test	rdx, rdx
	jz	.kakked					; sanity only

	; next we need to set our preferred bounds...
	mov	eax, [rdx+tui_width_ofs]		; topmost parent's width
	mov	ecx, [rdx+tui_height_ofs]		; topmost parent's height
	mov	[rdi+tui_width_ofs], eax
	mov	[rdi+tui_height_ofs], ecx		; our width/height to same as topmost parents
	xor	eax, eax
	mov	[rdi+tui_absolutex_ofs], eax
	mov	[rdi+tui_absolutey_ofs], eax		; set our absolute x/y position to 0,0, relative to topmost parent (which is probably at actual 0,0 anyway)
	
	; append us as a bastard to the topmost parent, BEFORE we do anything
	mov	rsi, rdi
	mov	rdi, rdx
	call	tui_object$appendbastard		; hmmm, should we be using its vtable to call this?

	; bastards bounds setting does not fire a sizechanged event, so we'll do that to establish our initial buffers
	mov	rdi, [rsp]
	mov	rsi, [rdi]				; our vtable
	call	qword [rsi+tui_vsizechanged]

	; now we have proper buffers, and our draw method was called once
	mov	rdi, [rsp]
	cmp	dword [rdi+tui_effect_type_ofs], 2
	jae	.notappending
	; otherwise, we are appending the target to its parent, which was set before entry to the desired object we are appending it to
	mov	rsi, [rdi+tui_effect_target_ofs]
	mov	rdx, [rsi+tui_parent_ofs]
	mov	dword [rsi+tui_visible_ofs], 0		; make sure to set its visible property to 0 before we call the real appendchild
	mov	rcx, [rdx]				; the parent's vtable
	; what this does is, because tui_includeinlayout_ofs is still set to 1, will actually cause proper bounds to be calculated
	; for the target as if it were already appended (and it is)
	mov	rdi, rdx
	call	qword [rcx+tui_vappendchild]		; so now, our child has bounds (or better), but it is set to invisible, its draw was called
calign
.notappending:
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_effect_target_ofs]
	; so now, we need to flatten our target in order to turn it into particles
	mov	rsi, [rdi]	
	call	qword [rsi+tui_vflatten]
	test	rax, rax
	jz	.noparticles				; this better not happen, won't be much of an effect now will it? hahah
	; so we'll need to keep track of our current x, y, target's width, height, flat_text, flat_attr pointers, and our target list itself
	mov	rsi, [rsp]				; get back our object
	sub	rsp, 96
	mov	[rsp+8], rbx
	mov	[rsp+16], r12
	mov	[rsp+24], r13
	mov	[rsp+32], r14
	mov	[rsp+40], r15
	mov	[rsp+48], rax				; flat_text
	mov	[rsp+56], rdx				; flat_attr
	mov	rcx, [rsi+tui_effect_target_ofs]	; our target so we can get its width/height
	mov	r8d, [rcx+tui_width_ofs]
	mov	r9d, [rcx+tui_height_ofs]
	mov	r10d, [rcx+tui_bounds_ax_ofs]
	mov	r11d, [rcx+tui_bounds_ay_ofs]
	mov	[rsp+64], r8
	mov	[rsp+72], r9
	mov	[rsp+80], r10
	mov	[rsp+88], r11
	
	mov	rbx, [rsi+tui_effect_particles_ofs]	; our destination list
	mov	r12, rax
	mov	r13, rdx
	xor	r15d, r15d				; y
calign
.yloop:
	xor	r14d, r14d				; x
calign
.xloop:
	; tui_particle$new needs: char, attr, x, y
	mov	edi, dword [r12]
	mov	esi, dword [r13]
	add	r12, 4
	add	r13, 4
	mov	edx, r14d				; our current x/y in the target's context
	add	edx, dword [rsp+80]			; the real x/y in the screen's context
	mov	ecx, r15d
	add	ecx, dword [rsp+88]
	call	tui_particle$new
	mov	rdi, rbx
	mov	rsi, rax
	call	list$push_back
	add	r14d, 1
	cmp	r14d, dword [rsp+64]
	jb	.xloop
	
	add	r15d, 1
	cmp	r15d, dword [rsp+72]
	jb	.yloop

	; so now, all particles have been created, we can free our flat_text and flat_attr
	mov	rdi, [rsp+48]
	call	heap$free
	mov	rdi, [rsp+56]
	call	heap$free
	; and restore our callee-saves and stack
	mov	rbx, [rsp+8]
	mov	r12, [rsp+16]
	mov	r13, [rsp+24]
	mov	r14, [rsp+32]
	mov	r15, [rsp+40]
	add	rsp, 96
calign
.noparticles:
	mov	rsi, [rsp]				; our tui_effect object back
	mov	edi, dword [rsi+tui_effect_time_ofs]
	call	epoll$timer_new
	; specify that we want death and dismemberment to the epoll timer layer:
	mov	dword [rax+24], 1
	
	; in the event that we get torn down while our timer is still running, we need to be able to
	; clear the timer object
	pop	rdi
	mov	[rdi+tui_effect_timerptr_ofs], rax
	epilog
calign
.kakked:
	; programmer error
	breakpoint

end if

if used tui_effect$delay | defined include_everything
	; two arguments: rdi == our tui_effect object, esi == delay to set on all particles
falign
tui_effect$delay:
	prolog	tui_effect$delay
	mov	rdi, [rdi+tui_effect_particles_ofs]
	mov	edx, esi
	mov	rsi, .particledelay
	call	list$foreach_arg
	epilog
falign
.particledelay:
	add	dword [rdi+tui_particle_delay_ofs], esi
	ret

end if


if used tui_particle$new | defined include_everything

tui_particle_char_ofs = 0
tui_particle_attr_ofs = 8
tui_particle_orig_char_ofs = 16
tui_particle_orig_attr_ofs = 24
tui_particle_x_ofs = 32			; double
tui_particle_y_ofs = 40			; double
tui_particle_xvel_ofs = 48		; double
tui_particle_yvel_ofs = 56		; double
tui_particle_drag_ofs = 64		; double
tui_particle_gravity_ofs = 72		; double
tui_particle_hgravity_ofs = 80		; double
tui_particle_forces_ofs = 88		; list
tui_particle_targetx_ofs = 96		; double
tui_particle_targety_ofs = 104		; double
tui_particle_minx_ofs = 112		; double
tui_particle_maxx_ofs = 120		; double
tui_particle_miny_ofs = 128		; double
tui_particle_maxy_ofs = 136		; double
tui_particle_delay_ofs = 144		; int

tui_particle_size = 152

	; NOTE: that is a ridiculous number of fields per particle... but depending on the type of effect
	; that we are after, each and every one of them can and does come into play
	; min/max x and y for example, if the effect desired is only gravity, and particles accelerate
	; then without these, there is no way to "hit the target" without a ridiculously huge and nasty
	; bit of code to detect it, the default init makes the particles immovable by setting them all
	; to the initial x/y value.



	; four arguments: edi == char, esi == attr, edx == x, ecx == y
falign
tui_particle$new:
	prolog	tui_particle$new
	push	rdi rsi rdx rcx
	mov	edi, tui_particle_size
	call	heap$alloc
	push	rax
	call	list$new
	pop	r8
	mov	[r8+tui_particle_forces_ofs], rax
	pop	rcx rdx rsi rdi
	cvtsi2sd	xmm0, edx
	cvtsi2sd	xmm1, ecx
	mov	[r8+tui_particle_char_ofs], rdi
	mov	[r8+tui_particle_attr_ofs], rsi
	mov	[r8+tui_particle_orig_char_ofs], rdi
	mov	[r8+tui_particle_orig_attr_ofs], rsi
	movq	[r8+tui_particle_x_ofs], xmm0
	movq	[r8+tui_particle_y_ofs], xmm1
	movq	[r8+tui_particle_targetx_ofs], xmm0
	movq	[r8+tui_particle_targety_ofs], xmm1
	movq	[r8+tui_particle_minx_ofs], xmm0
	movq	[r8+tui_particle_maxx_ofs], xmm0
	movq	[r8+tui_particle_miny_ofs], xmm1
	movq	[r8+tui_particle_maxy_ofs], xmm1
	xor	ecx, ecx
	mov	edx, 1
	cvtsi2sd	xmm2, edx
	mov	[r8+tui_particle_xvel_ofs], rcx
	mov	[r8+tui_particle_yvel_ofs], rcx
	movq	[r8+tui_particle_drag_ofs], xmm2
	mov	[r8+tui_particle_gravity_ofs], rcx
	mov	[r8+tui_particle_hgravity_ofs], rcx
	; our "delay" counter ... if nonzero, particle updater will decrement and do nothing
	mov	[r8+tui_particle_delay_ofs], rcx
	mov	rax, r8
	epilog

end if

if used tui_particle$update | defined include_everything

	; two arguments: rdi == tui_particle object, rsi == tui_effect object that we belong to
	; NOTE NOTE NOTE: we use a "known-preserved across list$foreach_arg" r15 variable to indicate whether we are
	; NOT done... this gets used in the tui_effect timer loop to determine whether all particles have reached their
	; destination and in fact are done and we check against the tui_effect object's minimum frame count
	; in addition to our target destination to determine hwether we are really done or not.
falign
tui_particle$update:
	prolog	tui_particle$update
	push	rsi rdi
	cmp	dword [rdi+tui_particle_delay_ofs], 0
	jne	.delayset
	; [rsp] == our tui_particle, [rsp+8] == tui_effect object
	; first up, we have to update our own forces that are specific to this particle, in case they change/move/etc
	mov	rdx, rsi	; the tui_effect object
	mov	rsi, tui_force$update
	mov	rdi, [rdi+tui_particle_forces_ofs]
	call	list$foreach_arg

	; because list$foreach_arg doesn't mess with xmm regs, and we aren't going to be calling any memfuncs in between
	; these calls, we can safely load up this particles values ONCE, then call foreach on all forces
	; which can load their own values into OTHER xmms, and do the math that way
	; so, load up all our important values first, which are:
	mov	rdi, [rsp]
	movq	xmm5, [rdi+tui_particle_x_ofs]
	movq	xmm6, [rdi+tui_particle_y_ofs]		; forces need these to calculate distance
	movq	xmm7, [rdi+tui_particle_xvel_ofs]	; if a force acts upon us, it is going to mess with our x or y velocity
	movq	xmm8, [rdi+tui_particle_yvel_ofs]
	movq	xmm14, [rdi+tui_particle_targetx_ofs]
	movq	xmm15, [rdi+tui_particle_targety_ofs]

	; so now, we have to APPLY all forces, both our local ones, and the tui_effect globals, but these will per above
	; only mess with xmm7, xmm8
	; apply local forces (our own first)
	mov	rdi, [rdi+tui_particle_forces_ofs]
	mov	rsi, tui_force$apply
	call	list$foreach				; no arg necessary here
	; globals next
	mov	rcx, [rsp+8]
	mov	rdi, [rcx+tui_effect_forces_ofs]
	mov	rsi, tui_force$apply
	call	list$foreach
	; so now, if any of the forces messed with our xvel/yvel, we can now apply and then store our values back in
	; we have to apply our own movement math (velocities, gravities, drag)
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	; load up the remaining values we need
	movq	xmm2, [rdi+tui_particle_drag_ofs]
	movq	xmm3, [rdi+tui_particle_gravity_ofs]
	movq	xmm4, [rdi+tui_particle_hgravity_ofs]

	mov	r8d, [rsi+tui_width_ofs]
	mov	r9d, [rsi+tui_height_ofs]

	; ok so, if our velocities are cruising along, but we are approaching our target
	; we need to make sure we don't skip past it... problem here is manifold, in that
	; we might be any direction away from our target
	; ... further, our actual velocity might be HUGE, and our distance might still be
	; well outside... there is no good way to do this
	;
	; so, the solution, though ugly, is to use four vars to each particle: min/max x and y

	movq	xmm10, [rdi+tui_particle_minx_ofs]
	movq	xmm11, [rdi+tui_particle_maxx_ofs]
	movq	xmm12, [rdi+tui_particle_miny_ofs]
	addsd	xmm5, xmm7		; x += xvel
	addsd	xmm6, xmm8		; y += yvel		hmm, should these be AFTER our velocity mods?
	movq	xmm13, [rdi+tui_particle_maxy_ofs]

	ucomisd	xmm5, xmm10		; is x < minx?
	jae	.minxokay
	movapd	xmm5, xmm10		; if so, x = minx
	jmp	.checky
calign
.minxokay:
	ucomisd xmm5, xmm11		; is x > maxx
	jbe	.checky
	movapd	xmm5, xmm11		; if so, x = maxx
	; copy of checky fallthrough
	ucomisd xmm6, xmm12		; is y < miny
	jae	.minyokay
	movapd	xmm6, xmm12		; if so, y = miny
	jmp	.checktarget
calign
.checky:
	ucomisd xmm6, xmm12		; is y < miny
	jae	.minyokay
	movapd	xmm6, xmm12		; if so, y = miny
	jmp	.checktarget
calign
.minyokay:
	ucomisd xmm6, xmm13		; is y > maxy
	jbe	.checktarget
	movapd	xmm6, xmm13		; if so, y = maxy
	; copy of checktarget fallthrough
	ucomisd	xmm5, xmm14
	jne	.notattarget
	ucomisd xmm6, xmm15
	je	.targetreached
	jmp	.notattarget
calign
.checktarget:
	ucomisd	xmm5, xmm14
	jne	.notattarget
	ucomisd xmm6, xmm15
	je	.targetreached

calign
.notattarget:
	mulsd	xmm7, xmm2		; xvel *= drag
	mulsd	xmm8, xmm2		; yvel *= drag

	addsd	xmm7, xmm4		; xvel += hgravity
	addsd	xmm8, xmm3		; yvel += gravity

	; put all our values back
	movq	[rdi+tui_particle_x_ofs], xmm5
	movq	[rdi+tui_particle_y_ofs], xmm6
	movq	[rdi+tui_particle_xvel_ofs], xmm7
	movq	[rdi+tui_particle_yvel_ofs], xmm8

	; hmm, rounding creates interesting problems here
	; we know that floor doesn't smash xmm5 or xmm6, so we can safely preserve them (CAVEAT EMPTOR)

	movapd	xmm0, xmm5		; x
	call	floor
	movapd	xmm5, xmm0
	movapd	xmm0, xmm6		; y
	call	floor
	movapd	xmm6, xmm0
	mov	rsi, [rsp+8]
	mov	rdi, [rsp]
	mov	r8d, [rsi+tui_width_ofs]
	cvtsd2si	ecx, xmm5	; x
	cvtsd2si	eax, xmm6	; y
	mov	r9d, [rsi+tui_height_ofs]
	
	; last but not least, we have to convert our x and y doubles into integers, and see if they are within bounds
	cmp	ecx, 0
	jl	.alldone
	cmp	eax, 0
	jl	.alldone
	cmp	ecx, r8d
	jge	.alldone
	cmp	eax, r9d
	jge	.alldone
	; otherwise, we appear to be inbounds

	xor	edx, edx
	mul	r8d			; y * width
	add	eax, ecx		; + x
	shl	eax, 2			; in bytes
	; eax now has our offset in bytes for our character

	; load up our character
	mov	ecx, [rdi+tui_particle_char_ofs]
	mov	edx, [rdi+tui_particle_attr_ofs]
	; buffers
	mov	r10, [rsi+tui_text_ofs]
	mov	r11, [rsi+tui_attr_ofs]
	mov	dword [r10+rax], ecx
	mov	dword [r11+rax], edx
	xor	r15d, r15d		; we didn't reach our target
	add	rsp, 16
	epilog
calign
.alldone:
	xor	r15d, r15d		; we didn't reach our target
	add	rsp, 16
	epilog

calign
.targetreached:
	; store back our modified goods, and stop all velocities, etc
	xorpd	xmm0, xmm0
	movq	[rdi+tui_particle_gravity_ofs], xmm0
	movq	[rdi+tui_particle_hgravity_ofs], xmm0
	movq	[rdi+tui_particle_xvel_ofs], xmm0
	movq	[rdi+tui_particle_yvel_ofs], xmm0
	movq	[rdi+tui_particle_x_ofs], xmm5
	movq	[rdi+tui_particle_y_ofs], xmm6
	; we still have to draw our target if it is inside a visible area, and due to the delayset goods, we make a copy of the draw code here
	movapd	xmm0, xmm5		; x
	call	floor
	movapd	xmm5, xmm0
	movapd	xmm0, xmm6		; y
	call	floor
	movapd	xmm6, xmm0
	
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	r8d, [rsi+tui_width_ofs]
	mov	r9d, [rsi+tui_height_ofs]
	
	; last but not least, we have to convert our x and y doubles into integers, and see if they are within bounds
	cvtsd2si	ecx, xmm5	; x
	cvtsd2si	eax, xmm6	; y
	cmp	ecx, 0
	jl	.targetreached_oob
	cmp	eax, 0
	jl	.targetreached_oob
	cmp	ecx, r8d
	jge	.targetreached_oob
	cmp	eax, r9d
	jge	.targetreached_oob
	; otherwise, we appear to be inbounds

	xor	edx, edx
	mul	r8d			; y * width
	add	eax, ecx		; + x
	shl	eax, 2			; in bytes
	; eax now has our offset in bytes for our character

	; load up our character
	mov	ecx, [rdi+tui_particle_char_ofs]
	mov	edx, [rdi+tui_particle_attr_ofs]
	; buffers
	mov	r10, [rsi+tui_text_ofs]
	mov	r11, [rsi+tui_attr_ofs]
	mov	dword [r10+rax], ecx
	mov	dword [r11+rax], edx

	add	rsp, 16
	epilog
calign
.targetreached_oob:
	; out of bounds, but our target was reached
	add	rsp, 16
	epilog

calign
.delayset:
	sub	dword [rdi+tui_particle_delay_ofs], 1

	; we still have to DRAW our particle, even if we didn't DO anything to it
	movq	xmm5, [rdi+tui_particle_x_ofs]
	movq	xmm6, [rdi+tui_particle_y_ofs]		; forces need these to calculate distance

	movapd	xmm0, xmm5		; x
	call	floor
	movapd	xmm5, xmm0
	movapd	xmm0, xmm6		; y
	call	floor
	movapd	xmm6, xmm0
	
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	r8d, [rsi+tui_width_ofs]
	mov	r9d, [rsi+tui_height_ofs]
	
	; last but not least, we have to convert our x and y doubles into integers, and see if they are within bounds
	cvtsd2si	ecx, xmm5	; x
	cvtsd2si	eax, xmm6	; y
	cmp	ecx, 0
	jl	.alldone
	cmp	eax, 0
	jl	.alldone
	cmp	ecx, r8d
	jge	.alldone
	cmp	eax, r9d
	jge	.alldone
	; otherwise, we appear to be inbounds

	xor	edx, edx
	mul	r8d			; y * width
	add	eax, ecx		; + x
	shl	eax, 2			; in bytes
	; eax now has our offset in bytes for our character

	; load up our character
	mov	ecx, [rdi+tui_particle_char_ofs]
	mov	edx, [rdi+tui_particle_attr_ofs]
	; buffers
	mov	r10, [rsi+tui_text_ofs]
	mov	r11, [rsi+tui_attr_ofs]
	mov	dword [r10+rax], ecx
	mov	dword [r11+rax], edx
	xor	r15d, r15d		; we didn't reach our target
	add	rsp, 16
	epilog

end if



if used tui_effect$timer | defined include_everything
	; single argument in rdi: our tui_effect object
falign
tui_effect$timer:
	prolog	tui_effect$timer
	; Burning Purpose: go through our forces list, and call each one's update first
	; then, clear our text and attribute buffer (hmm, do we need to clear the attribute buffer?)
	; then go through each particle and call its update with us as an argument
	cmp	dword [rdi+tui_effect_alldone_ofs], 0
	jne	.finalize		; does our final action and returns 1 which destroys us
	cmp	dword [rdi+tui_effect_frames_ofs], 0
	je	.firstframe
calign
.top:
	cmp	qword [rdi+tui_text_ofs], 0
	je	.nothingtodo
	; first, clear our buffers
	mov	eax, [rdi+tui_width_ofs]
	mov	ecx, [rdi+tui_height_ofs]
	test	eax, eax
	jz	.nothingtodo
	test	ecx, ecx
	jz	.nothingtodo	; these are sanityonly
	mul	ecx
	shl	eax, 2
	mov	edx, eax
	xor	esi, esi
	push	rdi rdx
	mov	rdi, [rdi+tui_text_ofs]
	call	memset32
	mov	rcx, [rsp+8]
	pop	rdx
	xor	esi, esi
	mov	rdi, [rcx+tui_attr_ofs]
	call	memset32
	; next up: run our forces update
	mov	rdx, [rsp]
	mov	rsi, tui_force$update
	mov	rdi, [rdx+tui_effect_forces_ofs]
	call	list$foreach_arg
	mov	rdx, [rsp]
	push	r15
	mov	r15d, 1
	mov	rsi, tui_particle$update
	mov	rdi, [rdx+tui_effect_particles_ofs]
	call	list$foreach_arg
	; we need to also call our updatedisplaylist so that our updates get flattened/rendered
	mov	rdi, [rsp+8]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	mov	eax, r15d
	pop	r15
	pop	rdi
	add	dword [rdi+tui_effect_frames_ofs], 1		; increase our frame count
	test	eax, eax
	jnz	.finalize
	epilog
calign
.nothingtodo:
	mov	qword [rdi+tui_effect_timerptr_ofs], 0		; our timer gets cleared for us by the 1 ret
	mov	qword [rdi+tui_bounds_ofs], 0			; this shares the same spot as io_parent_ofs
	mov	eax, 1		; if we didn't have anything to do, we may as well stop our timer?
	epilog
calign
.finalize:
	; particle$update made it all the way through and left alldone set to 1 (or alldone was nonzero), which means we need to finish the process
	; if we are a remove effect type, now is the time to remove the target from its parent
	mov	qword [rdi+tui_effect_timerptr_ofs], 0		; our timer gets cleared for us by the 1 ret
	mov	qword [rdi+tui_bounds_ofs], 0			; this shares the same spot as io_parent_ofs
	cmp	dword [rdi+tui_effect_type_ofs], tui_effect_type_removechild
	je	.finalize_removechild
	cmp	dword [rdi+tui_effect_type_ofs], tui_effect_type_removebastard
	je	.finalize_removebastard
	; and return 1 so we get destroyed
	cmp	qword [rdi+tui_effect_oncomplete_ofs], 0
	je	.finalize_nocompletefunc
	push	rdi
	mov	rsi, [rdi+tui_effect_target_ofs]
	mov	dword [rsi+tui_visible_ofs], 1
	mov	rdx, [rsi]
	call	qword [rdx+tui_vupdatedisplaylist]		; make sure it redraws itself
	pop	rsi
	mov	rdi, [rsi+tui_effect_oncompletearg_ofs]
	call	qword [rsi+tui_effect_oncomplete_ofs]
	mov	eax, 1
	epilog
calign
.finalize_removechild:
	push	rdi
	mov	rsi, [rdi+tui_effect_target_ofs]
	mov	rdi, [rsi+tui_parent_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovechild]
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_target_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_target_ofs]
	call	heap$free
	; target is now destroyed
	pop	rdi
	cmp	qword [rdi+tui_effect_oncomplete_ofs], 0
	je	.finalize_deadchild_nocompletefunc
	mov	rsi, rdi
	mov	rdi, [rdi+tui_effect_oncompletearg_ofs]
	call	qword [rsi+tui_effect_oncomplete_ofs]
	mov	eax, 1
	epilog
calign
.finalize_deadchild_nocompletefunc:
	mov	eax, 1
	epilog
calign
.finalize_removebastard:
	push	rdi
	mov	rsi, [rdi+tui_effect_target_ofs]
	mov	rdi, [rsi+tui_parent_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vremovebastard]
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_target_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_effect_target_ofs]
	call	heap$free
	; target is now destroyed
	pop	rdi
	cmp	qword [rdi+tui_effect_oncomplete_ofs], 0
	je	.finalize_deadchild_nocompletefunc
	mov	rsi, rdi
	mov	rdi, [rdi+tui_effect_oncompletearg_ofs]
	call	qword [rsi+tui_effect_oncomplete_ofs]
	mov	eax, 1
	epilog
calign
.finalize_nocompletefunc:
	; depending on what type of event we are determines what we need to do
	mov	rsi, [rdi+tui_effect_target_ofs]
	mov	dword [rsi+tui_visible_ofs], 1
	mov	rdx, [rsi]
	call	qword [rdx+tui_vupdatedisplaylist]		; make sure it redraws itself
	mov	eax, 1
	epilog
calign
.firstframe:
	cmp	dword [rdi+tui_effect_type_ofs], 2
	jb	.top
	; if we are removing, moving, distorting, then
	; we need to set the target's visible property to 0, but only here at the first frame of our effect
	mov	rsi, [rdi+tui_effect_target_ofs]
	mov	dword [rsi+tui_visible_ofs], 0
	jmp	.top

end if
