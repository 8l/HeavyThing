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
	;       tuieffects.asm: a simple TUI effects demonstration
	;
	; first things first, include the library defaults, and the
	; library main include:
include '../../ht_defaults.inc'
include '../../ht.inc'

	; for the purposes of our demonstration, limit the number of iterations:
demo_iterations = 10

	
	; Our HeavyThing's TUI effects can't be run with no valid size, so we can't
	; initialise any effects until we get our first proper resize event. As a result
	; we need a descendent virtual method table from our base tui_background to
	; work from, and the only override we are grabbing here is for the sizechanged
	; event so that we can get things underway.
	; so, we literally copy tui_background.inc's vtable, and then change its
	; sizechanged handler to our own:
dalign
demo_vtable:
	dq      tui_object$cleanup, tui_background$clone, tui_background$draw, tui_object$redraw, tui_object$updatedisplaylist, demo_sizechanged
	dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked

	; for our descended tui_background object, we need to hangon to some state
	; variables:

demo_panel_ofs = tui_background_size
demo_iterations_ofs = tui_background_size + 8

demo_size = tui_background_size + 16


	; and then define our sizechanged handler:
	; called with a single argument in rdi, the tui_background object
falign
demo_sizechanged:
	prolog	demo_sizechanged
	; set our object's iteration count to the beginning:
	mov	qword [rdi+demo_iterations_ofs], demo_iterations
	; make sure we let tui_background's (which was tui_object's) sizechange run
	; noting this is not a virtual method call (or we'd be calling ourself)
	push	rdi
	call	tui_object$sizechanged
; we need to reuse the effect launcher, so we set another global entry point:
calign
demo_reentry:
	; create our tui_panel object (which is the "target" tui_object that we'll apply effects to)
	mov	edi, 35
	mov	esi, 8
	mov	rdx, .title
	ansi_colors ecx, 'lightgray', 'blue'
	ansi_colors r8d, 'yellow', 'blue'
	call	tui_panel$new_ii
	; save our tui_panel pointer in our base demo object:
	mov	rdi, [rsp]
	mov	[rdi+demo_panel_ofs], rax
	; pick one of our random addition effects
	call	rng$u32
	mov	ecx, 5
	xor	edx, edx
	mov	r10d, eax
	div	ecx
	mov	eax, edx
	shr	r10d, 8
	and	r10d, 1				; r10d == possibly used direction
	pop	rdi
	mov	rsi, [rdi+demo_panel_ofs]
	jmp	qword [rax*8+.dispatch]
dalign
.dispatch:
	dq	.hslider, .vslider, .sprinkler, .materialise, .fountain
calign
.hslider:
	; horizontal slide in effect
	mov	edx, r10d
	mov	rcx, ineffect_complete
	mov	r8, rdi
	call	tui_effect$hslidein
	epilog
calign
.vslider:
	; vertical slide in effect
	mov	edx, r10d
	mov	rcx, ineffect_complete
	mov	r8, rdi
	call	tui_effect$vslidein
	epilog
calign
.sprinkler:
	; "sprinkle" in effect
	mov	rdx, ineffect_complete
	mov	rcx, rdi
	call	tui_effect$sprinkle
	epilog
calign
.materialise:
	; materialise effect
	mov	rdx, ineffect_complete
	mov	rcx, rdi
	call	tui_effect$materialize		; haha to my consistency re: AU/UK/USA spellings, hahah
	epilog
calign
.fountain:
	; fountain effect, quite interesting this one with a large enough terminal, haha
	mov	rdx, ineffect_complete
	mov	rcx, rdi
	call	tui_effect$fountain
	epilog
cleartext .title, '2 Ton Digital'


	; this function gets called when the aforementioned "in" effect is completed
	; so now we have to do the "out" effect
	; single argument in rdi == our original demo toplevel object
falign
ineffect_complete:
	prolog	ineffect_complete
	push	rdi
	call	rng$u32
	pop	rdi
	mov	ecx, 5
	xor	edx, edx
	mov	r10d, eax
	div	ecx
	mov	eax, edx
	shr	r10d, 8
	and	r10d, 1				; r10d == possibly used direction
	mov	rsi, [rdi+demo_panel_ofs]
	jmp	qword [rax*8+.dispatch]
dalign
.dispatch:
	dq	.hslider, .vslider, .vaporise, .gunshot, .crumble
calign
.hslider:
	; horizontal slide out effect
	mov	edx, r10d
	mov	rcx, outeffect_complete
	mov	r8, rdi
	call	tui_effect$hslideout
	epilog
calign
.vslider:
	; vertical slide out effect
	mov	edx, r10d
	mov	rcx, outeffect_complete
	mov	r8, rdi
	call	tui_effect$vslideout
	epilog
calign
.gunshot:
	; very interesting (especially with large terminal size) gunshot out effect
	mov	edx, 1
	mov	rcx, outeffect_complete
	mov	r8, rdi
	call	tui_effect$gunshotout
	epilog
calign
.crumble:
	; "crumble" out effect
	mov	rdx, outeffect_complete
	mov	rcx, rdi
	call	tui_effect$crumble
	epilog
calign
.vaporise:
	; vaporise effect
	mov	rdx, outeffect_complete
	mov	rcx, rdi
	call	tui_effect$vaporize		; haha to my consistency re: AU/UK/USA spellings, hahah
	epilog


	; this function gets called when the aforementioned "out" effect is completed
	; single argument in rdi == our original demo toplevel object
falign
outeffect_complete:
	prolog	outeffect_complete
	; rdi is our demo background object, its panel object is now destroyed
	sub	dword [rdi+demo_iterations_ofs], 1
	jz	.alldone
	; otherwise, fire up a new in transition effect, reusing the first one we did
	push	rdi
	jmp	demo_reentry
calign
.alldone:
	; all we want to do is drop back out cleanly:
	mov	rdx, [rdi]
	xor	esi, esi
	call	qword [rdx+tui_vexit]
	epilog					; not reached



public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	; the terminal object needs a tui_object descendent as its main/only child
	; so, we create our demo object to be a background descendent. Since tui_background
	; is normally always descended, it does not have its own "new" functions, so
	; we'll create it and initialise it manually here:
	mov	edi, demo_size
	call	heap$alloc
	mov	rbx, rax			; hangon to our pointer
	mov	qword [rax], demo_vtable	; set its virtual method table pointer
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]	; 100% wide
	movq	xmm1, [_math_onehundred]	; 100% high
	mov	esi, '.'			; fill character
	mov	edx, 0x00ef			; attributes (though we could use the ansi_colors macro as well)
	call	tui_background$init_dd

	; create our tui_terminal object with our created tui_background
	; noting that tui_terminal automatically adds itself to the epoll layer
	mov	rdi, rbx
	call	tui_terminal$new

	; all thats left is to turn control over to the epoll layer
	call	epoll$run
	; epoll$run does not come back.

	; include the global data segment:
include '../../ht_data.inc'

