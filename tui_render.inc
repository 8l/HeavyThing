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
	; tui_render.inc: one layer removed from tui_object, this is meant to be
	; the "base" layer (e.g. terminal, ssh server, etc descend from this, not
	; displayobject itself)
	;
	; this is responsible for generating the actual ansi output
	;

if used tui_render$default_vtable | used tui_render$vtable | defined include_everything

	; NOTE: we add render-only virtual methods to our tui_object ones
dalign
tui_render$default_vtable:
        dq      tui_render$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_render$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_render$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_render$setcursor, tui_render$showcursor, tui_render$hidecursor, tui_object$click, tui_object$clicked
	; our render-specific additions:
	dq	tui_render$ansioutput, tui_render$newlayoutonresize, tui_render$newwindowsize

end if

tui_vansioutput = tui_vclicked + 8
tui_vnewlayoutonresize = tui_vclicked + 16
tui_vnewwindowsize = tui_vclicked + 24

	; we also add a few render specific variables

tui_noupdate_ofs = tui_object_size		; dd
tui_noupdatecount_ofs = tui_object_size + 8
tui_outputbytes_ofs = tui_object_size + 16
tui_lastrender_text_ofs = tui_object_size + 24
tui_lastrender_attr_ofs = tui_object_size + 32
tui_cursor_ofs = tui_object_size + 40
tui_cursorvisible_ofs = tui_object_size + 48	; dd
tui_outputbuffer_ofs = tui_object_size + 56

tui_render_size = tui_object_size + 64


	; similar to tui_object itself, this is not meant to be constructed by itself
	; because this doesn't actually DO anything with its output
	; one more layer on top of this is required (terminal, telnet, ssh, etc)

	; ALL DESCENDENTS _MUST_ set their own vtable! (like tui_object, we skip it)

if used tui_render$init_defaults | defined include_everything
	; single parameter in rdi: the tui_render object
falign
tui_render$init_defaults:
	prolog	tui_render$init_defaults
	push	rdi
	add	rdi, 8		; skip the vtable pointer
	xor	esi, esi
	mov	edx, tui_render_size - 8
	call	memset32
	mov	rdi, [rsp]
	; copy of the tui_object defaults so we don't have to call it
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
	mov	dword [rdi+tui_cursorvisible_ofs], 1
	call	buffer$new
	mov	rdi, [rsp]
	mov	[rdi+tui_outputbuffer_ofs], rax
	pop	rdi
	epilog
end if


if used tui_render$init_copy | defined include_everything
	; two parameters: rdi == tui render we are initialising, rsi == source tui render
	; similar again to tui_object's, we copy all static settings, create new
	; buffers if width and height nonzero, create new lists, outputbuffer
	; and clear other sensibles
falign
tui_render$init_copy:
	prolog	tui_render$init_copy
	push	rsi rdi
	add	rdi, tui_object_size
	add	rsi, tui_object_size
	mov	edx, tui_render_size - tui_object_size
	call	memcpy
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	call	tui_object$init_copy
	call	buffer$new
	xor	ecx, ecx
	mov	rdi, [rsp]
	mov	[rdi+tui_noupdate_ofs], rcx
	mov	[rdi+tui_outputbytes_ofs], rcx
	mov	[rdi+tui_lastrender_text_ofs], rcx
	mov	[rdi+tui_lastrender_attr_ofs], rcx
	mov	[rdi+tui_outputbuffer_ofs], rax
	pop	rdi rsi
	epilog
end if


if used tui_render$cleanup | defined include_everything
	; single parameter in rdi: tui render object to cleanup after:
	; NOTE: this does not free the pointer itself, but heap$free's everything that we allocated
falign
tui_render$cleanup:
	prolog	tui_render$cleanup
	push	rdi
	call	tui_object$cleanup
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_lastrender_text_ofs]
	test	rdi, rdi
	jz	.notextbuffer
	call	heap$free
	mov	rsi, [rsp]
calign
.notextbuffer:
	mov	rdi, [rsi+tui_lastrender_attr_ofs]
	test	rdi, rdi
	jz	.noattrbuffer
	call	heap$free
	mov	rsi, [rsp]
calign
.noattrbuffer:
	mov	rdi, [rsi+tui_outputbuffer_ofs]
	call	buffer$destroy
	pop	rdi
	call	tui_lock$clear
	epilog
end if


if used tui_render$updatedisplaylist | defined include_everything
	; single argument in rdi: our tui_render object
falign
tui_render$updatedisplaylist:
	prolog	tui_render$updatedisplaylist
	cmp	dword [rdi+tui_noupdate_ofs], 1
	je	.noupdates
	cmp	dword [_tui_lock], 0
	jne	.locked
	push	rdi
	mov	rsi, [rdi]		; load our vtable
	call	qword [rsi+tui_vflatten]	; call our flatten method
	test	rax, rax
	jz	.gotbupkiss
	mov	rdi, [rsp]		; get our object back
	mov	rsi, rax		; text returned from flatten
	; rdx already contains our attr returned from flatten
	call	tui_render$nvrender
	pop	rdi
	epilog
calign
.gotbupkiss:
	; flatten gave us a null return, not much else to do
	pop	rdi
	epilog
calign
.noupdates:
	; noupdate is set, so all we have to do is increase our updatecount and continue
	add	qword [rdi+tui_noupdatecount_ofs], 1
	epilog
calign
.locked:
	call	tui_lock$updatedisplaylist
	epilog
end if


if used tui_render$layoutchanged | defined include_everything
	; single argument in rdi: our tui_render object
	; we override this one because we are the parent/base and our size is known
falign
tui_render$layoutchanged:
	prolog	tui_render$layoutchanged
	push	rdi
	mov	rdi, [rdi+tui_children_ofs]	; load up our child list
	mov	rsi, .childbounds
	call	list$foreach
	xor	ecx, ecx
	mov	rdi, [rsp]
	mov	[rdi+tui_noupdatecount_ofs], rcx
	mov	dword [rdi+tui_noupdate_ofs], 1	; disable actual updates during our redraw
						; if we DON'T do this, then redraw would do a LOT of extra work for no reason
	mov	rsi, [rdi]			; load our vtable
	call	qword [rsi+tui_vredraw]		; call our redraw virtual method
	mov	rdi, [rsp]
	mov	dword [rdi+tui_noupdate_ofs], 0	; enable updates again
	cmp	qword [rdi+tui_noupdatecount_ofs], 0
	je	.nothingtodo
	; otherwise, call our updatedisplaylist virtual method, because we did have some goodies
	mov	rsi, [rdi]			; load our vtable
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rdi
	epilog
calign
.nothingtodo:
	pop	rdi
	epilog
calign
.childbounds:
	mov	rsi, [rdi]			; get the child's vtable loaded up
	call	qword [rsi+tui_vcalcbounds]
	ret
end if

if used tui_render$newlayoutonresize | defined include_everything
	; single argument in rdi: our tui_render object
	; this is the same as the above layoutchanged, only we blast lastrender_*
falign
tui_render$newlayoutonresize:
	prolog	tui_render$newlayoutonresize
	push	rdi
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .childbounds
	call	list$foreach
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_lastrender_text_ofs]
	test	rdi, rdi
	jz	.notextbuffer
	mov	qword [rsi+tui_lastrender_text_ofs], 0
	call	heap$free
	mov	rsi, [rsp]
calign
.notextbuffer:
	mov	rdi, [rsi+tui_lastrender_attr_ofs]
	test	rdi, rdi
	jz	.noattrbuffer
	mov	qword [rsi+tui_lastrender_attr_ofs], 0
	call	heap$free
calign
.noattrbuffer:
	xor	ecx, ecx
	mov	rdi, [rsp]
	mov	[rdi+tui_noupdatecount_ofs], rcx
	mov	dword [rdi+tui_noupdate_ofs], 1
	mov	rsi, [rdi]
	call	qword [rsi+tui_vredraw]
	mov	rdi, [rsp]
	mov	dword [rdi+tui_noupdate_ofs], 0
	cmp	qword [rdi+tui_noupdatecount_ofs], 0
	je	.nothingtodo
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]
	pop	rdi
	epilog
calign
.nothingtodo:
	pop	rdi
	epilog
calign
.childbounds:
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcalcbounds]
	ret
end if


if used tui_render$ansioutput | defined include_everything
	; three arguments: rdi == our tui_render object, rsi == pointer to UTF8 bytes to send out, rdx == count
	; NOTE HERE: this is our base tui_render, and as such we have no idea what transport layer we are using
	; or anything like that, so we don't do anything except die a thousand deaths... aka PEBCAK
falign
tui_render$ansioutput:
	prolog	tui_render$ansioutput
	breakpoint
	epilog
end if


if used tui_render$showcursor | defined include_everything
	; single argument in rdi: our tui_render object
falign
tui_render$showcursor:
	prolog	tui_render$showcursor
	cmp	dword [_tui_lock], 0
	jne	.doit_locked
	cmp	dword [rdi+tui_cursorvisible_ofs], 1
	je	.alreadyvisible
	mov	dword [rdi+tui_cursorvisible_ofs], 1
	mov	rsi, .showit
	mov	edx, 6
	mov	rcx, [rdi]			; load our vtable
	call	qword [rcx+tui_vansioutput]	; send it out
	epilog
calign
.alreadyvisible:
	epilog
calign
.showit:
	db	27,'[?25h'
calign
.doit_locked:
	call	tui_lock$showcursor
	epilog
end if

if used tui_render$hidecursor | defined include_everything
	; single argument in rdi: our tui_render object
falign
tui_render$hidecursor:
	prolog	tui_render$hidecursor
	cmp	dword [_tui_lock], 0
	jne	.doit_locked
	cmp	dword [rdi+tui_cursorvisible_ofs], 0
	je	.alreadyhidden
	mov	dword [rdi+tui_cursorvisible_ofs], 0
	mov	rsi, .hideit
	mov	edx, 6
	mov	rcx, [rdi]			; load our vtable
	call	qword [rcx+tui_vansioutput]	; send it out
	epilog
calign
.alreadyhidden:
	epilog
calign
.hideit:
	db	27,'[?25l'
calign
.doit_locked:
	call	tui_lock$hidecursor
	epilog
end if

if used tui_render$setcursor | defined include_everything
	; three arguments: rdi == our tui_render object, esi == x, edx == y
	; NOTE: unlike ANSI, our cursor positions are 0 offset, so we +1 both of them here
	; prior to output
falign
tui_render$setcursor:
	prolog	tui_render$setcursor
	; if esi and edx are already the same as our cursor, we don't do anything
	cmp	esi, [rdi+tui_cursor_ofs]
	jne	.doit
	cmp	edx, [rdi+tui_cursor_ofs+4]
	jne	.doit
	epilog
calign
.doit:
	mov	[rdi+tui_cursor_ofs], esi
	mov	[rdi+tui_cursor_ofs+4], edx	; set the cursor position in our object so render knows where it goes
	cmp	dword [_tui_lock], 0
	jne	.doit_locked
	add	esi, 1
	add	edx, 1				; correct 1-offset ANSI coords
	sub	rsp, 128
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	byte [rsp+48], 27
	mov	byte [rsp+49], '['
	mov	edi, edx			; y is first
	mov	esi, 10
	call	string$from_int
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	rsi, rsp
	add	rsi, 50
	call	string$to_utf8
	mov	rdi, [rsp+24]
	mov	rax, [rdi]
	mov	[rsp+24], rax			; its length (and since we know it is all digits, utf8 length is samesame)
	call	heap$free
	mov	rdi, [rsp+8]			; x is next
	mov	esi, 10
	call	string$from_int
	mov	[rsp+32], rax
	mov	rcx, [rsp+24]			; length of the y string
	mov	rdi, rax
	mov	rsi, rsp
	add	rsi, 50
	add	rsi, rcx
	mov	byte [rsi], ';'
	add	rsi, 1
	call	string$to_utf8
	mov	rdi, [rsp+32]
	mov	rax, [rdi]
	mov	[rsp+32], rax			; its length
	call	heap$free
	mov	rax, [rsp+24]
	mov	rcx, [rsp+32]
	mov	rdi, [rsp]			; our object
	mov	rsi, rsp
	add	rsi, 48
	mov	rdx, rsi
	add	rdx, 3
	add	rdx, rax
	add	rdx, rcx
	mov	byte [rdx], 'H'
	add	rdx, 1
	sub	rdx, rsi
	mov	rcx, [rdi]			; our object's vtable
	call	qword [rcx+tui_vansioutput]
	add	rsp, 128
	epilog
calign
.doit_locked:
	call	tui_lock$setcursor
	epilog
end if

if used tui_render$newwindowsize | defined include_everything
	; three arguments: rdi == our tui_render object, esi == xsize, edx == ysize
falign
tui_render$newwindowsize:
	prolog	tui_render$newwindowsize
	xor	ecx, ecx
	push	rdi
	mov	qword [rdi+tui_bounds_ofs], rcx	; a.x and a.y == 0
	mov	dword [rdi+tui_bounds_bx_ofs], esi
	mov	dword [rdi+tui_bounds_by_ofs], edx
	mov	dword [rdi+tui_width_ofs], esi
	mov	dword [rdi+tui_height_ofs], edx
	mov	dword [rdi+tui_noupdate_ofs], 1
	mov	qword [rdi+tui_noupdatecount_ofs], rcx

	; it is possible that some child of ours might instantiate a new layout
	; and if that happens, we _must_ clear lasttext/lastattr _before_ we go anywhere
	push	qword [rdi+tui_lastrender_text_ofs]
	push	qword [rdi+tui_lastrender_attr_ofs]
	mov	qword [rdi+tui_lastrender_text_ofs], 0
	mov	qword [rdi+tui_lastrender_attr_ofs], 0

	mov	rsi, [rdi]			; our object's vtable
	call	qword [rsi+tui_vsizechanged]	; because this calls updateDisplayList otherwise by calling all of its children's draw methods

	pop	rdi
	test	rdi, rdi
	jz	.nofree
	call	heap$free
calign
.nofree:
	pop	rdi
	test	rdi, rdi
	jz	.nofree2
	call	heap$free
calign
.nofree2:
	mov	rdi, [rsp]
	mov	dword [rdi+tui_noupdate_ofs], 0
	mov	rsi, [rdi]			; our object's vtable
	call	qword [rsi+tui_vnewlayoutonresize]
	pop	rdi
	epilog

end if




if used tui_render$nvrender | defined include_everything
	; three arguments: rdi == our tui_render object, rsi == render text, rdx == render attr
falign
tui_render$nvrender:
	prolog	tui_render$nvrender
	sub	rsp, 160
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	; we are going to make use of all of our callee-saves
	mov	[rsp+24], rbx
	mov	[rsp+32], r12
	mov	[rsp+40], r13
	mov	[rsp+48], r14
	mov	[rsp+56], r15
	mov	[rsp+64], rbp
	mov	dword [rsp+72], 0xffffffff		; last_attr

	mov	rbp, [rdi+tui_outputbuffer_ofs]		; save the output buffer in rbp
	mov	r12, rsi				; render text
	mov	r13, rdx				; render attr
	xor	r14d, r14d				; x = 0
	mov	r15d, [rdi+tui_width_ofs]		; save our actual width so we can maintain cursor position

	mov	eax, r15d
	mov	ecx, dword [rdi+tui_height_ofs]
	mul	ecx
	mov	ebx, eax				; # of loop iterations

	mov	rdi, rbp
	call	buffer$reset

	mov	rdi, rbp
	mov	esi, ebx
	shl	esi, 2
	add	esi, 2048
	call	buffer$reserve

	mov	rdi, [rsp]
	mov	r10, [rdi+tui_lastrender_text_ofs]
	mov	r11, [rdi+tui_lastrender_attr_ofs]

	xor	ecx, ecx
	mov	dword [rsp+80], ecx			; y
	mov	dword [rsp+88], -1			; cursor_x
	mov	dword [rsp+96], -1			; cursor_y
	mov	dword [rsp+104], ecx			; inaltcharset

	test	r10, r10
	jnz	.render_loop

	; no previous render buffer exists, so send out the initial cls/setup as well
	mov	dword [rsp+88], ecx			; cursor_x = 0, since CLS puts it there for us
	mov	dword [rsp+96], ecx			; cursor_y



	mov	rdi, [rsp]
	mov	rax, .initial_cls
	mov	rcx, .initial_cls_hidecursor
	mov	r8d, .initial_cls_length
	mov	r9d, .initial_cls_hidecursor_length
	cmp	dword [rdi+tui_cursorvisible_ofs], 0
	cmove	rsi, rcx
	cmovne	rsi, rax
	cmove	edx, r9d
	cmovne	edx, r8d
	mov	rdi, rbp
	call	buffer$append

	mov	rdi, [rsp]
	mov	r10, [rdi+tui_lastrender_text_ofs]
	mov	r11, [rdi+tui_lastrender_attr_ofs]

	; so at this point:
	; ebx is our iteration number
	; rbp is our output buffer
	; r12 is our render text
	; r13 is our render attr
	; r14d is x
	; r15d is our width
	; last_attr is at [rsp+72]
	; y is at [rsp+80]
	; cursor_x is at [rsp+88]
	; cursor_y is at [rsp+96]
	; inaltcharset is at [rsp+104]
calign
.render_loop:
	test	r10, r10
	jz	.render_loop_noprior
	; otherwise, we do have a previous
	mov	eax, dword [r11]			; our old attribute
	cmp	eax, dword [r13]			; our new attribute
	jne	.render_loop_noprior
	mov	eax, dword [r10]			; our old text
	cmp	eax, dword [r12]			; our new text
	jne	.render_loop_noprior
	; otherwise, both the text and attribute are the same as they were before
	; add	r10, 4  <-- render_loop_next increments this one for us
	add	r11, 4
	; add	r12, 4	<-- render_loop_next increments this one for us
	add	r13, 4
	; in addition, render_loop_next takes care of moving x forward
	jmp	.render_loop_next
calign
.render_loop_noprior:
	mov	eax, dword [r13]			; get our attribute
	cmp	eax, dword [rsp+72]
	je	.render_loop_sameattr
	; else, this attribute was different to our last, send out the goods
	shr	eax, 8
	mov	ecx, dword [rsp+72]
	shr	ecx, 8
	and	eax, 0xff
	and	ecx, 0xff
	cmp	eax, ecx
	je	.render_loop_fgsame
	; else, fg in eax is different, we need a string version of it
	mov	[rsp+112], rax
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	mov	rdi, rbp
	mov	rsi, .fgcolor_preface
	mov	edx, 7
	call	buffer$append

	mov	rax, [rsp+112]
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'm'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
calign
.render_loop_fgsame:
	mov	eax, dword [r13]			; get our attribute again
	mov	ecx, dword [rsp+72]
	and	eax, 0xff
	and	ecx, 0xff
	cmp	eax, ecx
	je	.render_loop_bgsame
	; else, bg in eax is different, we need a string version of it
	mov	[rsp+112], rax
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	mov	rdi, rbp
	mov	rsi, .bgcolor_preface
	mov	edx, 7
	call	buffer$append
	mov	rax, [rsp+112]
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'm'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
calign
.render_loop_bgsame:
	mov	eax, dword [r13]
	mov	dword [rsp+72], eax			; last_attr = current attr
calign
.render_loop_sameattr:
	mov	r8d, [rsp+80]				; load up y
	mov	rdx, [rbp+buffer_endptr_ofs]
	add	r13, 4					; next attribute position
	add	r11, 4					; old attribute pos, we don't test it for nonzero so it is okay if we increment it regardless
	mov	eax, dword [r12]			; get our text

	; hmmm, I had these next two lines commented out from before, but I don't remember why...
	test	eax, eax				; we dont send nulls
	jz	.render_loop_next

if acs_linechars
	cmp	dword [rsp+104], 0			; inaltcharset?
	je	.render_loop_notinacs
	; else, we are in the ACS
	cmp	eax, 0x2500
	jb	.render_loop_clearacs
	cmp	eax, 0x257f
	ja	.render_loop_clearacs
end if
	; r14d is x
	; r15d is our width
	; last_attr is at [rsp+72]
	; y is at [rsp+80]
	; cursor_x is at [rsp+88]
	; cursor_y is at [rsp+96]
	; inaltcharset is at [rsp+104]
calign
.render_loop_cursorpos:
	; if (cursor_x != x || cursor_y != y)
	cmp	r14d, [rsp+88]
	jne	.render_loop_xdiff
	cmp	r8d, [rsp+96]
	jne	.render_loop_xsameydiff
calign
.render_loop_cursorokay:
	; else, x == cursor_x and y == cursor_y
	cmp	eax, 0x80
	jb	.render_loop_ascii
	cmp	eax, 0x800
	jb	.render_loop_twobyte
if acs_linechars
	cmp	eax, 0x2500
	jb	.render_loop_threebyte
	cmp	eax, 0x250c
	je	.render_loop_lc1
	cmp	eax, 0x2514
	je	.render_loop_lc2
	cmp	eax, 0x2510
	je	.render_loop_lc3
	cmp	eax, 0x2518
	je	.render_loop_lc4
	cmp	eax, 0x2500
	je	.render_loop_lc5
	cmp	eax, 0x2502
	je	.render_loop_lc6
	cmp	eax, 0x253c
	je	.render_loop_lc7
	cmp	eax, 0x251c
	je	.render_loop_lc8
	cmp	eax, 0x2524
	je	.render_loop_lc9
	cmp	eax, 0x252c
	je	.render_loop_lc10
	cmp	eax, 0x2534
	je	.render_loop_lc11
	cmp	eax, 0x2592
	je	.render_loop_lc12
end if
	cmp	eax, 0x10000
	jb	.render_loop_threebyte
	cmp	eax, 0x200000
	jb	.render_loop_fourbyte
	cmp	eax, 0x4000000
	jb	.render_loop_fivebyte
	; anything else is really invalid, but we'll go ahead and stick it in as a 6 byte sequence UCS4 style
	mov	ecx, eax
	shr	ecx, 30
	and	ecx, 1
	or	ecx, 0xfc
	mov	byte [rdx], cl
	mov	ecx, eax
	shr	ecx, 24
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+1], cl
	mov	ecx, eax
	shr	ecx, 18
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+2], cl
	mov	ecx, eax
	shr	ecx, 12
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+3], cl
	mov	ecx, eax
	shr	ecx, 6
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+4], cl
	mov	ecx, eax
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+5], cl
	add	rdx, 6
	add	qword [rbp+buffer_endptr_ofs], 6
	add	qword [rbp+buffer_length_ofs], 6
	jmp	.render_loop_next_cursornext
calign
.render_loop_fivebyte:
	mov	ecx, eax
	shr	ecx, 24
	and	ecx, 0x03
	or	ecx, 0xf8
	mov	byte [rdx], cl
	mov	ecx, eax
	shr	ecx, 18
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+1], cl
	mov	ecx, eax
	shr	ecx, 12
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+2], cl
	mov	ecx, eax
	shr	ecx, 6
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+3], cl
	mov	ecx, eax
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+4], cl
	add	rdx, 5
	add	qword [rbp+buffer_endptr_ofs], 5
	add	qword [rbp+buffer_length_ofs], 5
	jmp	.render_loop_next_cursornext
calign
.render_loop_fourbyte:
	mov	ecx, eax
	shr	ecx, 18
	and	ecx, 0x07
	or	ecx, 0xf0
	mov	byte [rdx], cl
	mov	ecx, eax
	shr	ecx, 12
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+1], cl
	mov	ecx, eax
	shr	ecx, 6
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+2], cl
	mov	ecx, eax
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+3], cl
	add	rdx, 4
	add	qword [rbp+buffer_endptr_ofs], 4
	add	qword [rbp+buffer_length_ofs], 4
	jmp	.render_loop_next_cursornext
calign
.render_loop_threebyte:
	mov	ecx, eax
	shr	ecx, 12
	and	ecx, 0x0f
	or	ecx, 0xe0
	mov	byte [rdx], cl
	mov	ecx, eax
	shr	ecx, 6
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+1], cl
	mov	ecx, eax
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+2], cl
	add	rdx, 3
	add	qword [rbp+buffer_endptr_ofs], 3
	add	qword [rbp+buffer_length_ofs], 3
	jmp	.render_loop_next_cursornext
calign
.render_loop_twobyte:
	mov	ecx, eax
	shr	ecx, 6
	and	ecx, 0x1f
	or	ecx, 0xc0
	mov	byte [rdx], cl
	mov	ecx, eax
	and	ecx, 0x3f
	or	ecx, 0x80
	mov	byte [rdx+1], cl
	add	rdx, 2
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2
	jmp	.render_loop_next_cursornext
calign
.render_loop_ascii:
	mov	byte [rdx], al
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	jmp	.render_loop_next_cursornext
if acs_linechars
calign
.render_loop_lc1:
	mov	eax, 0x6c
	jmp	.render_loop_ascii
calign
.render_loop_lc2:
	mov	eax, 0x6d
	jmp	.render_loop_ascii
calign
.render_loop_lc3:
	mov	eax, 0x6b
	jmp	.render_loop_ascii
calign
.render_loop_lc4:
	mov	eax, 0x6a
	jmp	.render_loop_ascii
calign
.render_loop_lc5:
	mov	eax, 0x71
	jmp	.render_loop_ascii
calign
.render_loop_lc6:
	mov	eax, 0x78
	jmp	.render_loop_ascii
calign
.render_loop_lc7:
	mov	eax, 0x6e
	jmp	.render_loop_ascii
calign
.render_loop_lc8:
	mov	eax, 0x74
	jmp	.render_loop_ascii
calign
.render_loop_lc9:
	mov	eax, 0x75
	jmp	.render_loop_ascii
calign
.render_loop_lc10:
	mov	eax, 0x77
	jmp	.render_loop_ascii
calign
.render_loop_lc11:
	mov	eax, 0x76
	jmp	.render_loop_ascii
calign
.render_loop_lc12:
	mov	eax, 0x61
	jmp	.render_loop_ascii
calign
.render_loop_clearacs:
	mov	dword [rsp+104], 0			; inaltcharset = false
	mov	byte [rdx], 27
	mov	byte [rdx+1], '('
	mov	byte [rdx+2], 'B'			; TODO: change these to dword moves
	add	rdx, 3
	add	qword [rbp+buffer_endptr_ofs], 3
	add	qword [rbp+buffer_length_ofs], 3
	jmp	.render_loop_cursorpos
calign
.render_loop_notinacs:
	cmp	eax, 0x2500
	jb	.render_loop_cursorpos
	cmp	eax, 0x257f
	ja	.render_loop_cursorpos
	mov	dword [rsp+104], 1			; inaltcharset = true
	mov	byte [rdx], 27
	mov	byte [rdx+1], '('
	mov	byte [rdx+2], '0'			; TODO: change these to dword moves
	add	rdx, 3
	add	qword [rbp+buffer_endptr_ofs], 3
	add	qword [rbp+buffer_length_ofs], 3
	jmp	.render_loop_cursorpos
end if
calign
.render_loop_next_cursornext:
	; increment cursor_x, and check line wrap for cursor_y
	add	dword [rsp+88], 1			; cursor_x++
	cmp	dword [rsp+88], r15d			; cursor_x == width?
	jb	.render_loop_next
	mov	dword [rsp+88], 0			; cursor_x = 0
	add	dword [rsp+96], 1			; cursor_y++
calign
.render_loop_next:
	mov	rdx, r10
	add	rdx, 4
	test	r10, r10
	cmovnz	r10, rdx				; increment old text position only if r10 was already nonzero
	add	r12, 4					; next text position
	add	r14d, 1					; x++
	cmp	r14d, r15d				; x == width?
	je	.render_loop_next_newline
	sub	ebx, 1
	jnz	.render_loop
	jmp	.render_loop_done
calign
.render_loop_next_morebuffer:
	mov	rdi, rbp
	mov	esi, 16384
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	call	buffer$reserve
	mov	rax, [rbp+buffer_size_ofs]		; ??
	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
	sub	ebx, 1
	jnz	.render_loop
	jmp	.render_loop_done
calign
.render_loop_xsameydiff:
	; just y is different
	cmp	r8d, [rsp+96]
	ja	.render_loop_ydiffdown
	; else, do a cursor up for cursor_y - y
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2

	mov	eax, dword [rsp+96]
	sub	eax, dword [rsp+80]
	cmp	eax, 256
	jae	.render_loop_xsameydiff_stringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_xsameydiff_valsent
calign
.render_loop_xsameydiff_stringbased:
	mov	edi, eax
	mov	esi, 10
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
calign
.render_loop_xsameydiff_valsent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'A'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	mov	r8d, [rsp+80]
	mov	[rsp+96], r8d
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	eax, dword [r12]			; restore the character for cursorokay
	jmp	.render_loop_cursorokay
calign
.render_loop_ydiffdown:
	; do a cursor down for y - cursor_y
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2

	mov	eax, dword [rsp+80]
	sub	eax, dword [rsp+96]
	cmp	eax, 256
	jae	.render_loop_ydiffdown_stringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_ydiffdown_valsent
calign
.render_loop_ydiffdown_stringbased:
	mov	edi, eax
	mov	esi, 10
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
calign
.render_loop_ydiffdown_valsent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'B'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	mov	r8d, [rsp+80]
	mov	[rsp+96], r8d
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	eax, dword [r12]			; restore the character for cursorokay
	jmp	.render_loop_cursorokay
calign
.render_loop_xdiff:

	; NOTE NOTE NOTE: relative x cursor positioning with the way linewrap works isn't exactly right
	; and the reason for this is: if we wrote an entire line, while we update cursor_x to 0 and assume the
	; wrap has occurred, if we don't actually write another character, linewrap doesn't actually occur
	; and then forward cursor does nothing, and thus our screen ends up all jacked
	; the docs say: If the cursor is already at the edge of the screen, relative positioning has no effect
	; 
	; So, for now, if cursor_x is zero, we do a full cursor position
	;
	; someday I should give this some more thought... but this seems to work okay:

	cmp	dword [rsp+88], 0
	je	.render_loop_xdiffydiff

	cmp	r8d, [rsp+96]
	jne	.render_loop_xdiffydiff
	; else, only x is different
	cmp	r14d, [rsp+88]
	ja	.render_loop_xdiffright
	; else, do a cursor left for cursor_x - x
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2

	mov	eax, dword [rsp+88]
	sub	eax, r14d
	cmp	eax, 256
	jae	.render_loop_xdiff_stringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_xdiff_valsent
calign
.render_loop_xdiff_stringbased:
	mov	edi, eax
	mov	esi, 10
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
calign
.render_loop_xdiff_valsent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'D'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	mov	[rsp+88], r14d
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	eax, dword [r12]			; restore the character for cursorokay
	jmp	.render_loop_cursorokay
calign
.render_loop_xdiffright:
	; do a cursor right for x - cursor_x
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2

	mov	eax, r14d
	sub	eax, dword [rsp+88]
	cmp	eax, 256
	jae	.render_loop_xdiffright_stringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_xdiffright_valsent
calign
.render_loop_xdiffright_stringbased:
	mov	edi, eax
	mov	esi, 10
	mov	[rsp+120], r10
	mov	[rsp+128], r11
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
calign
.render_loop_xdiffright_valsent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'C'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	mov	[rsp+88], r14d
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	eax, dword [r12]			; restore the character for cursorokay
	jmp	.render_loop_cursorokay
	; y is at [rsp+80]
	; cursor_x is at [rsp+88]
	; cursor_y is at [rsp+96]
calign
.render_loop_xdiffydiff:
	; both are different
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2

	mov	[rsp+120], r10
	mov	[rsp+128], r11				; save these just in case we do end up doing string based sends

	mov	eax, [rsp+80]				; y
	add	eax, 1					; correct to ANSI 1 offset
	cmp	eax, 256
	jae	.render_loop_xdiffydiff_ystringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_xdiffydiff_ysent
calign
.render_loop_xdiffydiff_ystringbased:
	mov	edi, eax
	mov	esi, 10
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
calign
.render_loop_xdiffydiff_ysent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], ';'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1

	mov	eax, r14d				; x
	add	eax, 1					; correct to ANSI 1 offset
	cmp	eax, 256
	jae	.render_loop_xdiffydiff_xstringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_xdiffydiff_xsent
calign
.render_loop_xdiffydiff_xstringbased:
	mov	edi, eax
	mov	esi, 10
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
calign
.render_loop_xdiffydiff_xsent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'H'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	mov	[rsp+88], r14d				; cursor_x = x
	mov	eax, [rsp+80]
	mov	[rsp+96], eax				; cursor_y = y
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	r10, [rsp+120]
	mov	r11, [rsp+128]
	mov	eax, dword [r12]			; restore the character for cursorokay
	jmp	.render_loop_cursorokay
calign
.render_loop_next_newline:
	xor	r14d, r14d				; x = 0
	add	dword [rsp+80], 1			; y++

	mov	rdx, [rbp+buffer_size_ofs]		; end of every line, make sure we have a bunch of room
	mov	rcx, [rbp+buffer_length_ofs]
	sub	rdx, rcx
	cmp	rdx, 16384
	jbe	.render_loop_next_morebuffer
	sub	ebx, 1
	jnz	.render_loop
calign
.render_loop_done:
	test	r10, r10
	jz	.render_loop_done_nofree

	; free last render text and attr buffers
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_lastrender_text_ofs]
	call	heap$free

	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_lastrender_attr_ofs]
	call	heap$free
calign
.render_loop_done_nofree:
	; if (inaltcharset)...
	; noColor
	; cursor
	; cursor_visible
	; send
	; save last_render_text/last_render_attr
	mov	rdi, [rsp]				; get our tui_render object back
	mov	rdx, [rbp+buffer_endptr_ofs]
if acs_linechars
	cmp	dword [rsp+104], 0
	je	.render_done_noacs
	; else, we have to kick us out of ACS
	mov	byte [rdx], 27
	mov	byte [rdx+1], '('
	mov	byte [rdx+2], 'B'			; TODO: change these to dword moves
	add	rdx, 3
	add	qword [rbp+buffer_endptr_ofs], 3
	add	qword [rbp+buffer_length_ofs], 3
calign
.render_done_noacs:
end if
	; next up: nocolor setting
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	mov	byte [rdx+2], '0'
	mov	byte [rdx+3], 'm'			; TODO: change these to dword moves
	add	rdx, 4
	add	qword [rbp+buffer_endptr_ofs], 4
	add	qword [rbp+buffer_length_ofs], 4

	; next up: place our actual render object cursor where it goes
	mov	r14d, [rdi+tui_cursor_ofs]		; cursor.x
	mov	r15d, [rdi+tui_cursor_ofs+4]		; cursor.y

	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	add	qword [rbp+buffer_endptr_ofs], 2
	add	qword [rbp+buffer_length_ofs], 2

	mov	eax, r15d				; y
	add	eax, 1					; correct to ANSI 1 offset
	cmp	eax, 256
	jae	.render_loop_done_ystringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_done_ysent
calign
.render_loop_done_ystringbased:
	mov	edi, eax
	mov	esi, 10
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
calign
.render_loop_done_ysent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], ';'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1

	mov	eax, r14d				; x
	add	eax, 1					; correct to ANSI 1 offset
	cmp	eax, 256
	jae	.render_loop_done_xstringbased
	shl	rax, 3
	add	rax, .uchars

	mov	rdi, [rbp+buffer_endptr_ofs]
	mov	edx, dword [rax]
	mov	esi, dword [rax+4]
	mov	dword [rdi], esi
	add	qword [rbp+buffer_endptr_ofs], rdx
	add	qword [rbp+buffer_length_ofs], rdx

	jmp	.render_loop_done_xsent
calign
.render_loop_done_xstringbased:
	mov	edi, eax
	mov	esi, 10
	call	string$from_int
	mov	[rsp+112], rax
	mov	rdi, rbp
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, [rsp+112]
	call	heap$free
calign
.render_loop_done_xsent:
	mov	rdx, [rbp+buffer_endptr_ofs]
	mov	byte [rdx], 'H'
	add	rdx, 1
	add	qword [rbp+buffer_endptr_ofs], 1
	add	qword [rbp+buffer_length_ofs], 1
	mov	rdx, [rbp+buffer_endptr_ofs]

	; if the cursorvisible flag is enabled, add that too
	mov	rdi, [rsp]				; get our object back
	cmp	dword [rdi+tui_cursorvisible_ofs], 0
	je	.render_done_cursorhidden
	
	mov	byte [rdx], 27
	mov	byte [rdx+1], '['
	mov	byte [rdx+2], '?'
	mov	byte [rdx+3], '2'			; TODO: change these to dword moves
	mov	byte [rdx+4], '5'
	mov	byte [rdx+5], 'h'			; show cursor
	add	rdx, 6
	add	qword [rbp+buffer_endptr_ofs], 6
	add	qword [rbp+buffer_length_ofs], 6
calign
.render_done_cursorhidden:
	; send the buffer sitting in rbp out the door
	mov	rbx, rbp
	mov	rbp, [rsp+64]				; restore rbp


	mov	rdi, [rsp]
	mov	rsi, [rbx+buffer_itself_ofs]
	mov	rdx, [rbx+buffer_length_ofs]
	mov	rcx, [rdi]				; get the object's vtable
	call	qword [rcx+tui_vansioutput]

	mov	rdi, [rsp]				; get our object back
	mov	rcx, [rbx+buffer_length_ofs]
	add	qword [rdi+tui_outputbytes_ofs], rcx	; update how many bytes we have sent out
	; and last but not least, set last_rendertext and last_renderattr

	if defined force_full_redraws

	xor	ecx, ecx
	mov	[rdi+tui_lastrender_text_ofs], rcx
	mov	[rdi+tui_lastrender_attr_ofs], rcx

	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, [rsp+16]
	call	heap$free

	else

	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	[rdi+tui_lastrender_text_ofs], rdx
	mov	[rdi+tui_lastrender_attr_ofs], rcx

	end if

	; restore our callee-saves
	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]
	mov	r14, [rsp+48]
	mov	r15, [rsp+56]
	add	rsp, 160
	; voila.
	epilog
dalign
.initial_cls:
	db	27,'[38;5;0m',27,'[48;5;0m',27,'[H',27,'[J',27,'[1;1H',27,'[0m'
	.initial_cls_length = $ - .initial_cls
dalign
.initial_cls_hidecursor:
	db	27,'[38;5;0m',27,'[48;5;0m',27,'[H',27,'[J',27,'[1;1H',27,'[0m',27,'[?25l'
	.initial_cls_hidecursor_length = $ - .initial_cls_hidecursor
dalign
.fgcolor_preface:		; 7 bytes
	db	27,'[38;5;'
dalign
.bgcolor_preface:		; 7 bytes
	db	27,'[48;5;'

	; because a) our fgcol/bgcol is 256 limited, and because
	; most of our cursor positioning is also likely to be 256 or less
	; we create this big bloated table of predone UTF8 with dd length prefix
	; so each one take 8 bytes, x 256 == extra 2048 bytes of code here, but
	; worth it due to not having to call string$from_int repeatedly
macro ualign {
	local a
	virtual
		align 4
		a = $ - $$
	end virtual
	if a = 3
		db 0x0, 0x0, 0x0
	else if a = 2
		db 0x0, 0x0
	else if a = 1
		db 0x0
	end if
}
dalign
.uchars:
macro uchar val* {
	local TOP,AA
	ualign
	TOP:
		dd AA
		db val
	AA = ($ - TOP - 4)
}
uchar '0'
uchar '1'
uchar '2'
uchar '3'
uchar '4'
uchar '5'
uchar '6'
uchar '7'
uchar '8'
uchar '9'
uchar '10'
uchar '11'
uchar '12'
uchar '13'
uchar '14'
uchar '15'
uchar '16'
uchar '17'
uchar '18'
uchar '19'
uchar '20'
uchar '21'
uchar '22'
uchar '23'
uchar '24'
uchar '25'
uchar '26'
uchar '27'
uchar '28'
uchar '29'
uchar '30'
uchar '31'
uchar '32'
uchar '33'
uchar '34'
uchar '35'
uchar '36'
uchar '37'
uchar '38'
uchar '39'
uchar '40'
uchar '41'
uchar '42'
uchar '43'
uchar '44'
uchar '45'
uchar '46'
uchar '47'
uchar '48'
uchar '49'
uchar '50'
uchar '51'
uchar '52'
uchar '53'
uchar '54'
uchar '55'
uchar '56'
uchar '57'
uchar '58'
uchar '59'
uchar '60'
uchar '61'
uchar '62'
uchar '63'
uchar '64'
uchar '65'
uchar '66'
uchar '67'
uchar '68'
uchar '69'
uchar '70'
uchar '71'
uchar '72'
uchar '73'
uchar '74'
uchar '75'
uchar '76'
uchar '77'
uchar '78'
uchar '79'
uchar '80'
uchar '81'
uchar '82'
uchar '83'
uchar '84'
uchar '85'
uchar '86'
uchar '87'
uchar '88'
uchar '89'
uchar '90'
uchar '91'
uchar '92'
uchar '93'
uchar '94'
uchar '95'
uchar '96'
uchar '97'
uchar '98'
uchar '99'
uchar '100'
uchar '101'
uchar '102'
uchar '103'
uchar '104'
uchar '105'
uchar '106'
uchar '107'
uchar '108'
uchar '109'
uchar '110'
uchar '111'
uchar '112'
uchar '113'
uchar '114'
uchar '115'
uchar '116'
uchar '117'
uchar '118'
uchar '119'
uchar '120'
uchar '121'
uchar '122'
uchar '123'
uchar '124'
uchar '125'
uchar '126'
uchar '127'
uchar '128'
uchar '129'
uchar '130'
uchar '131'
uchar '132'
uchar '133'
uchar '134'
uchar '135'
uchar '136'
uchar '137'
uchar '138'
uchar '139'
uchar '140'
uchar '141'
uchar '142'
uchar '143'
uchar '144'
uchar '145'
uchar '146'
uchar '147'
uchar '148'
uchar '149'
uchar '150'
uchar '151'
uchar '152'
uchar '153'
uchar '154'
uchar '155'
uchar '156'
uchar '157'
uchar '158'
uchar '159'
uchar '160'
uchar '161'
uchar '162'
uchar '163'
uchar '164'
uchar '165'
uchar '166'
uchar '167'
uchar '168'
uchar '169'
uchar '170'
uchar '171'
uchar '172'
uchar '173'
uchar '174'
uchar '175'
uchar '176'
uchar '177'
uchar '178'
uchar '179'
uchar '180'
uchar '181'
uchar '182'
uchar '183'
uchar '184'
uchar '185'
uchar '186'
uchar '187'
uchar '188'
uchar '189'
uchar '190'
uchar '191'
uchar '192'
uchar '193'
uchar '194'
uchar '195'
uchar '196'
uchar '197'
uchar '198'
uchar '199'
uchar '200'
uchar '201'
uchar '202'
uchar '203'
uchar '204'
uchar '205'
uchar '206'
uchar '207'
uchar '208'
uchar '209'
uchar '210'
uchar '211'
uchar '212'
uchar '213'
uchar '214'
uchar '215'
uchar '216'
uchar '217'
uchar '218'
uchar '219'
uchar '220'
uchar '221'
uchar '222'
uchar '223'
uchar '224'
uchar '225'
uchar '226'
uchar '227'
uchar '228'
uchar '229'
uchar '230'
uchar '231'
uchar '232'
uchar '233'
uchar '234'
uchar '235'
uchar '236'
uchar '237'
uchar '238'
uchar '239'
uchar '240'
uchar '241'
uchar '242'
uchar '243'
uchar '244'
uchar '245'
uchar '246'
uchar '247'
uchar '248'
uchar '249'
uchar '250'
uchar '251'
uchar '252'
uchar '253'
uchar '254'
uchar '255'

end if
