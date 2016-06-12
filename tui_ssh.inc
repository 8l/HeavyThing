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
	; tui_ssh.inc: terminal support for ssh, meant for use in the context of an ssh server
	;
	;	this has to do a number of ssh-specialized things, mainly dynamic window resizing
	;	and specialized clone operations
	;
	; this is an io descendent for io chaining, but _requires_ that its next in line be
	; an ssh object (because of our specialized callback handling for the ssh protocol itself)
	; (this is a semi-loose requirement, insofar as an intermediary or muxer could be put in
	; between the two if enough care is taken)
	;
	; tui_ssh$new is really the only one required, passed to it the tui_object descended onlychild
	; and this will take care of the rest provided the caller to tui_ssh$new establishes the io
	; chain correctly
	;

if used tui_ssh$vtable | defined include_everything
	; our io descendent vtable for the tui_ssh action
dalign
tui_ssh$vtable:
	dq	tui_ssh$destroy, tui_ssh$clone, tui_ssh$connected, io$send, tui_ssh$receive, io$error, io$timeout

end if


if used tui_ssh$new | defined include_everything

tui_ssh_renderer_ofs = io_base_size			; when vconnected gets called
tui_ssh_onlychild_ofs = io_base_size + 8		; this is appendchild'd to the renderer
tui_ssh_raddr_ofs = io_base_size + 16
tui_ssh_raddrlen_ofs = io_base_size + 126
tui_ssh_size = io_base_size + 134

	; single argument in rdi: the display tui_object to get created/cloned as the first child when connect happens
	; NOTE: argument in rdi cannot be NULL, and it doesn't make sense to use this without a TUI object in the first place
	; returns a new tui_ssh object suitable for io chaining, but does not create a parent/child for the io layer
falign
tui_ssh$new:
	prolog	tui_ssh$new
	push	rdi
	mov	edi, tui_ssh_size
	call	heap$alloc_clear
	mov	rsi, [rsp]
	mov	qword [rax], tui_ssh$vtable
	mov	[rax+tui_ssh_onlychild_ofs], rsi
	mov	[rsp], rax
	; create our renderer layer
	mov	rdi, rax
	call	tui_ssh_renderer$new
	mov	rdi, rax
	pop	rax
	mov	[rax+tui_ssh_renderer_ofs], rdi
	epilog

end if

if used tui_ssh_renderer$new | defined include_everything

; we store precisely one pointer in the renderer object
tui_ssh_renderer_base_ofs = tui_render_size		; pointer to the tui_ssh object
tui_ssh_renderer_size = tui_render_size + 8


; this is the default tui_render vtable, except for ansioutput and exit
dalign
tui_ssh_renderer$vtable:
        dq      tui_render$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_render$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_render$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_ssh_renderer$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_render$setcursor, tui_render$showcursor, tui_render$hidecursor, tui_object$click, tui_object$clicked
        ; our render-specific additions:
        dq      tui_ssh_renderer$ansioutput, tui_render$newlayoutonresize, tui_render$newwindowsize

	; single argument in rdi: our ssh base pointer, returns a new initialized tui_ssh_renderer object in rax
falign
tui_ssh_renderer$new:
	prolog	tui_ssh_renderer$new
	push	rdi
	mov	edi, tui_ssh_renderer_size
	call	heap$alloc_clear
	mov	rdx, [rsp]
	mov	rdi, rax
	mov	[rsp], rax
	mov	[rax+tui_ssh_renderer_base_ofs], rdx
	mov	qword [rax], tui_ssh_renderer$vtable
	call	tui_render$init_defaults
	pop	rax
	epilog

end if


if used tui_ssh_renderer$ansioutput | defined include_everything
	; three arguments: rdi == our tui_ssh_renderer object, rsi == pointer to utf8 bytes to send out, rdx == count
falign
tui_ssh_renderer$ansioutput:
	prolog	tui_ssh_renderer$ansioutput
	mov	rdi, [rdi+tui_ssh_renderer_base_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	epilog

end if

if used tui_ssh_renderer$exit | defined include_everything
	; two arguments: rdi == our tui_ssh_renderer object, esi == exit code
falign
tui_ssh_renderer$exit:
	prolog	tui_ssh_renderer$exit
	; we don't really care about the exit code, but we do need our base object
	push	r12 r13 r14
	mov	r12, [rdi+tui_ssh_renderer_base_ofs]
	mov	edi, [rdi+tui_width_ofs]	; its height
	mov	esi, 10
	call	string$from_unsigned
	mov	r13, rax
	sub	rsp, 128
	mov	rdi, rsp
	mov	rsi, .seeyalater
	mov	edx, .seeyalater_size
	call	memcpy
	mov	rdi, r13
	lea	rsi, [rsp+.seeyalater_size]
	call	string$to_utf8
	mov	r14d, eax			; how many bytes it wrote
	lea	rdi, [rsp+rax+.seeyalater_size]
	mov	rsi, .reallyseeya
	mov	edx, .reallyseeya_size
	call	memcpy
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, r14d
	add	edx, .seeyalater_size + .reallyseeya_size
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	mov	rdi, r13
	call	heap$free
	add	rsp, 128

	; so now, hopefully that went down the wire, ideally we need to let the ssh object know that it wants a cleanexit, and well-behaved clients
	; will exit as soon as we send the goods
	mov	rdi, [r12+io_child_ofs]		; better be our ssh object
	call	ssh$cleanexit
	pop	r14 r13 r12
	epilog
if tui_ssh_alternatescreen

dalign
.seeyalater:
        db      27,'[r',27,'[?25h',27,'['
        .seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
        db      ';1H',27,'[?1049l!!Exit!!',13,10
        .reallyseeya_size = $ - .reallyseeya

else

dalign
.seeyalater:
        db      27,'[r',27,'[?25h',27,'['
        .seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
        db      ';1H!!Exit!!',13,10
        .reallyseeya_size = $ - .reallyseeya

end if


end if



if used tui_ssh$destroy | defined include_everything
	; single argument in rdi: our tui_ssh object
	; similar to io$destroy, only that we cleanup our renderer as well
falign
tui_ssh$destroy:
	prolog	tui_ssh$destroy
	push	rdi
	mov	rdi, [rdi+tui_ssh_renderer_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_ssh_renderer_ofs]
	call	heap$free
	; if we still have an onlychild pointer, it needs to be taken care of as well
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_ssh_onlychild_ofs]
	test	rdi, rdi
	jz	.nochild
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_ssh_onlychild_ofs]
	call	heap$free
calign
.nochild:
	; now that our renderer has been taken care of, we can pass the rest
	; of our effort onto io$destroy
	pop	rdi
	call	io$destroy
	epilog

end if

if used tui_ssh$clone | defined include_everything
	; single argument in rdi: our tui_ssh object to clone
	; returns new (copy), with new _copies_ of our onlychild (and any other io children)
falign
tui_ssh$clone:
	prolog	tui_ssh$clone
	sub	rsp, 16
	mov	[rsp], rdi
	; we are free to create a virgin/non-cloned renderer, but we need to clone our onlychild, as well as our io children
	mov	rdi, [rdi+tui_ssh_onlychild_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vclone]
	mov	[rsp+8], rax
	mov	edi, tui_ssh_size
	call	heap$alloc_clear
	mov	rsi, [rsp+8]
	mov	qword [rax], tui_ssh$vtable
	mov	[rax+tui_ssh_onlychild_ofs], rsi
	mov	[rsp+8], rax
	; create our renderer layer
	mov	rdi, rax
	call	tui_ssh_renderer$new
	mov	rdi, rax
	mov	rax, [rsp+8]
	mov	[rax+tui_ssh_renderer_ofs], rdi

	; so now, we need to determine whether we have children or not (which we probably do)
	mov	rdi, [rsp]
	cmp	qword [rdi+io_child_ofs], 0
	je	.nochild
	mov	rdi, [rdi+io_child_ofs]
	mov	rsi, [rdi]	; virtual method pointer location for the child
	call	qword [rsi+io_vclone]
	mov	rsi, rax	; new child
	mov	rdx, [rsp]	; our original object
	mov	rcx, [rdx]	; our original's vmethod pointer
	mov	rax, [rsp+8]	; our new object
	mov	[rax], rcx	; set our new object's vmethod pointer
	mov	qword [rax+io_parent_ofs], 0	; parent = null
	mov	[rax+io_child_ofs], rsi		; our child
	mov	[rsi+io_parent_ofs], rax	; set our child's parent to us
	add	rsp, 16
	epilog
calign
.nochild:
	; rax is already setup, and we have a clean version already done, return
	add	rsp, 16
	epilog
end if

if used tui_ssh$wsize | defined include_everything
	; three arguments: rdi == our tui_ssh object, esi == width, edx == height
falign
tui_ssh$wsize:
	prolog	tui_ssh$wsize
	mov	rdi, [rdi+tui_ssh_renderer_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vnewwindowsize]
	epilog

end if

if used tui_ssh$connected | defined include_everything
	; single argument in rdi: our tui_ssh object
	; this is overridden because now is the time that we actually do our appendchild to the rendering layer
falign
tui_ssh$connected:
	prolog	tui_ssh$connected
	; copy our remote address
	push	rdi
	mov	[rdi+tui_ssh_raddrlen_ofs], edx
	lea	rdi, [rdi+tui_ssh_raddr_ofs]
	call	memcpy
	pop	rdi

	; if alternatescreen is enabled, before we do _anything_, we need to send out the altscreen goods
	push	rdi
	mov	rsi, .altscr
	mov	edx, .altscrsize
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	pop	rdi
	; now, and only now, do we set our wsizecb for the ssh layer, and this is because: at tui_ssh$new, we don't necessarily have a child ssh object yet
	; and further, before now we aren't interested anyway
	mov	rsi, [rdi+io_child_ofs]		; our underlying ssh object, which better exist, otherwise how did we get called in the first place?
	mov	qword [rsi+ssh_wsizecb_ofs], tui_ssh$wsize
	mov	[rsi+ssh_wsizecbarg_ofs], rdi
	; so now that we did that, we also need to pick out its width/height
	mov	edx, [rsi+ssh_height_ofs]
	mov	esi, [rsi+ssh_width_ofs]
	push	rdi
	mov	rdi, [rdi+tui_ssh_renderer_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vnewwindowsize]

	pop	rdi
	; and finally, we need to append our only child
	mov	rsi, [rdi+tui_ssh_onlychild_ofs]
	mov	qword [rdi+tui_ssh_onlychild_ofs], 0
	mov	rdi, [rdi+tui_ssh_renderer_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	epilog
if tui_ssh_alternatescreen
dalign
.altscr db 27,'[?1049h',27,'[12h'
.altscrsize = $ - .altscr
else
dalign
.altscr db 27,'[12h'
.altscrsize = $ - .altscr

end if

end if



if used tui_ssh$receive | defined include_everything
	; three arguments: rdi == our tui_ssh object, rsi == ptr to data, rdx == length of same
	; we return false for not destroying the objects
	; we get incoming data from the ssh layer here, that we parse for ANSI escapes, etc and pass onward
	; to the rendering layer as normal keyevents
falign
tui_ssh$receive:
	prolog	tui_ssh$receive
	push	r12 r13 r14
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	add	r14, rsi
calign
.loop:
	cmp	r13, r14
	jae	.alldone
	movzx	eax, byte [r13]
	mov	ecx, eax			; save the full char in ecx
	shr	eax, 4
	cmp	eax, 12
	jae	.unichar
	; else, it isn't a unicode character, check it for escapes
calign
.notunicode:
	; our unmolested byte is sitting in ecx
	cmp	ecx, 27
	jne	.normalchar
	mov	rdx, r14			; the end of our buffer
	sub	rdx, r13			; where we are now
	cmp	rdx, 3
	jl	.normalchar
	movzx	edx, byte [r13+1]		; next char has to be [ or O
	cmp	edx, '['
	je	.escbracket
	cmp	edx, 'O'
	je	.escoh
	; else, send it out as a normal key
calign
.normalchar:
	cmp	ecx, 3				; we treat Ctrl-C as "special" and bailout
	je	.ctrlc
	mov	rdi, [r12+tui_ssh_renderer_ofs]	; our tui object
	mov	esi, ecx			; our key
	xor	edx, edx			; our esc_key
	mov	rcx, [rdi]			; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	add	r13, 1
	jmp	.loop
calign
.fireescaped:
	; fire the escape key in ecx
	mov	rdi, [r12+tui_ssh_renderer_ofs]	; our tui object
	xor	esi, esi			; our key
	mov	edx, ecx			; our esc_key
	mov	rcx, [rdi]			; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	add	r13, 1
	jmp	.loop
calign
.escbracket:
	; ESC [ received
	add	r13, 2				; skip ESC [
	movzx	ecx, byte [r13]
	cmp	ecx, 'A'
	je	.fireescaped
	cmp	ecx, 'B'
	je	.fireescaped
	cmp	ecx, 'C'
	je	.fireescaped
	cmp	edx, 'D'
	je	.fireescaped
	; otherwise, go forward til we run out of room, or til we hit a ~, shl by 8 each one we get
	xor	eax, eax
calign
.escloop:
	cmp	r13, r14
	jae	.escloopdone
	movzx	ecx, byte [r13]
	cmp	ecx, '~'
	je	.escloopdone
	shl	eax, 8
	or	eax, ecx
	add	r13, 1
	jmp	.escloop
calign
.escloopdone:
	mov	ecx, eax
	jmp	.fireescaped			; this could make r13 go one past the end, quite alright
calign
.escoh:
	; ESC O received
	shl	ecx, 8				; 'O' << 8
	movzx	eax, byte [r13+1]
	or	ecx, eax			; | next byte
	add	r13, 2
	jmp	.fireescaped
calign
.unichar:
	cmp	eax, 12
	je	.unichar_2
	cmp	eax, 13
	je	.unichar_2
	cmp	eax, 14
	je	.unichar_3
	cmp	eax, 15
	je	.unichar_4
	; anything else is invalid unicode, no?
	; so we can let the "normal" non-unicode parser see what it makes of it
	jmp	.notunicode
calign
.unichar_2:
	mov	rdx, r14			; the end of our buffer
	sub	rdx, r13			; where we are now
	cmp	rdx, 2
	jl	.alldone			; kakked if we ran to the end (shouldn't happen in normal circumstances)
	movzx	edx, byte [r13+1]		; get the next char
	mov	r8d, edx			; save it
	and	edx, 0xc0
	cmp	edx, 0x80
	jne	.notunicode
	mov	eax, ecx		; first byte
	shl	eax, 6
	and	r8d, 0x3f
	and	eax, 0x7c0
	or	eax, r8d
	cmp	eax, 0x80
	jb	.notunicode
	; otherwise, unicode point in eax is valid, fire it
	mov	rdi, [r12+tui_ssh_renderer_ofs]	; our tui object
	mov	esi, eax		; our key
	xor	edx, edx		; our esc_key
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	; swallow two characters and keep going
	add	r13, 2
	jmp	.loop
calign
.unichar_3:
	mov	rdx, r14		; the end of our buffer
	sub	rdx, r13		; where we are now
	cmp	rdx, 3
	jl	.alldone		; kakked if we ran to the end (shouldn't happen in normal circumstances)
	movzx	edx, byte [r13+1]	; get the next char
	movzx	r9d, byte [r13+2]	; and the next char
	mov	r10d, edx		; save
	mov	r11d, r9d		; save
	and	edx, 0xc0
	cmp	edx, 0x80
	jne	.notunicode
	and	r9d, 0xc0
	cmp	r9d, 0x80
	jne	.notunicode
	mov	r8d, ecx
	shl	r8d, 12
	and	r8d, 0xf000
	shl	r10d, 6
	and	r10d, 0xfc0
	or	r8d, r10d
	and	r11d, 0x3f
	or	r8d, r11d
	cmp	r8d, 0x800
	jb	.notunicode
	; otherwise, unicode point in r8d is valid, fire it
	mov	rdi, [r12+tui_ssh_renderer_ofs]	; our tui object
	mov	esi, r8d		; our key
	xor	edx, edx		; our esc_key
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	; swallow three characters and keep going
	add	r13, 3
	jmp	.loop
calign
.unichar_4:
	mov	rdx, r14		; the end of our buffer
	sub	rdx, r13		; where we are now
	cmp	rdx, 4
	jl	.alldone		; kakked if we ran to the end (shouldn't happen in normal circumstances)
	; ecx is our unmolested first byte
	movzx	eax, byte [r13+1]	; second byte
	movzx	edx, byte [r13+2]	; third byte
	movzx	r8d, byte [r13+3]	; fourth byte
	mov	r9d, eax
	and	r9d, 0xc0
	cmp	r9d, 0x80
	jne	.notunicode
	mov	r9d, edx
	and	r9d, 0xc0
	cmp	r9d, 0x80
	jne	.notunicode
	mov	r9d, r8d
	and	r9d, 0xc0
	cmp	r9d, 0x80
	jne	.notunicode
	mov	r9d, ecx
	shl	r9d, 18
	and	r9d, 0x1c0000
	shl	eax, 12
	and	eax, 0x3f000
	or	r9d, eax
	shl	edx, 6
	and	edx, 0xfc0
	or	r9d, edx
	and	r8d, 0x3f
	or	r9d, r8d
	cmp	r9d, 0x10000
	jb	.notunicode
	; otherwise, unicode point in r9d is valid, fire it
	mov	rdi, [r12+tui_ssh_renderer_ofs]	; our tui object
	mov	esi, r9d		; our key
	xor	edx, edx		; our esc_key
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	; swallow four characters and keep going
	add	r13, 4
	jmp	.loop
calign
.alldone:
	pop	r14 r13 r12
	xor	eax, eax		; don't kill us off
	epilog
calign
.ctrlc:
	; send out ansi to do screen restore before we off ourselves
	mov	rdi, [r12+tui_ssh_renderer_ofs]	; our tui object
	mov	edi, [rdi+tui_width_ofs]	; its height
	mov	esi, 10
	call	string$from_unsigned
	mov	r13, rax
	sub	rsp, 128
	mov	rdi, rsp
	mov	rsi, .seeyalater
	mov	edx, .seeyalater_size
	call	memcpy
	mov	rdi, r13
	lea	rsi, [rsp+.seeyalater_size]
	call	string$to_utf8
	mov	r14d, eax			; how many bytes it wrote
	lea	rdi, [rsp+rax+.seeyalater_size]
	mov	rsi, .reallyseeya
	mov	edx, .reallyseeya_size
	call	memcpy
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, r14d
	add	edx, .seeyalater_size + .reallyseeya_size
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	mov	rdi, r13
	call	heap$free
	add	rsp, 128

	; so now, hopefully that went down the wire, ideally we need to let the ssh object know that it wants a cleanexit, and well-behaved clients
	; will exit as soon as we send the goods
	mov	rdi, [r12+io_child_ofs]		; better be our ssh object
	call	ssh$cleanexit

	pop	r14 r13 r12
	mov	eax, 1			; suicide
	epilog
if tui_ssh_alternatescreen

dalign
.seeyalater:
        db      27,'[r',27,'[?25h',27,'['
        .seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
        db      ';1H',27,'[?1049l!!Ctrl-C!!',13,10
        .reallyseeya_size = $ - .reallyseeya

else

dalign
.seeyalater:
        db      27,'[r',27,'[?25h',27,'['
        .seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
        db      ';1H!!Ctrl-C!!',13,10
        .reallyseeya_size = $ - .reallyseeya

end if

end if


