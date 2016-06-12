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
	; tui_typist.js: an error prone typing simulator, haha
	;   mainly just for fun, but an interesting effect nevertheless
	; 
	; some notes on the input text: on new/init, we require
	; a normal string for the text to type, but we support
	; three "special" characters that we won't actually output
	; to the text buffer:
	; 0 == delay for an otherwise keypress length of time
	; 8 == backspace
	; 10 == crlf
	; these can be constructed in a number of ways
	;
	; this certainly didn't get a lot of attention put into it
	; haha, it has potential though :-) think of it more like
	; an old mechanical typewriter than a real typist, only we
	; have accuracy and error correction, hahah
	;
	; it is a bit too rhythmic, someday when I am bored I need
	; to make it more erratic so it looks more like a person
	; typing
	;
	; TODO: we are too "rhythmic", make it look more like real typing

	; also note: resize events restart us from the beginning

if used tui_typist$vtable | defined include_everything

dalign
tui_typist$vtable:
        dq      tui_typist$cleanup, tui_typist$clone, tui_typist$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_typist$sizechanged
        dq      tui_typist$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; we add one for our oncomplete:
	dq	tui_typist$oncomplete

tui_typist_voncomplete = tui_vclicked + 8

tui_typist_delay_ofs = tui_background_size
tui_typist_accuracy_ofs = tui_background_size + 8
tui_typist_cursor_ofs = tui_background_size + 16
tui_typist_text_ofs = tui_background_size + 24
tui_typist_index_ofs = tui_background_size + 32
tui_typist_timerptr_ofs = tui_background_size + 40
tui_typist_lastptr_ofs = tui_background_size + 48
tui_typist_alldone_ofs = tui_background_size + 56
tui_typist_usecursor_ofs = tui_background_size + 64
tui_typist_errmod_ofs = tui_background_size + 68

tui_typist_size = tui_background_size + 72

end if


tui_typist_mindelay = 50
tui_typist_maxdelay = 100




if used tui_typist$new_rect | defined include_everything
	; three arguments: rdi == pointer to bounds rect, rsi == text to type, edx == colors
falign
tui_typist$new_rect:
	prolog	tui_typist$new_rect
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12d, edx
	mov	rdi, rsi
	call	string$copy
	mov	r13, rax
	mov	edi, tui_typist_size
	call	heap$alloc
	mov	rdi, rax
	mov	rsi, rbx
	mov	edx, ' '
	mov	ecx, r12d
	mov	rbx, rax
	call	tui_background$init_rect
	mov	qword [rbx], tui_typist$vtable
	mov	[rbx+tui_typist_text_ofs], r13
	mov	rdi, rbx
	pop	r13 r12
	call	tui_typist$nvsetup
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used tui_typist$new_dd | defined include_everything
	; four arguments: xmm0 == widthperc, xmm1 == heightperc, rdi == text to type, esi == colors
falign
tui_typist$new_dd:
	prolog	tui_typist$new_dd
	push	rbx r12 r13 r14
	movq	rbx, xmm0
	movq	r12, xmm1
	mov	r13d, esi
	call	string$copy
	mov	r14, rax
	mov	edi, tui_typist_size
	call	heap$alloc
	movq	xmm0, rbx
	movq	xmm1, r12
	mov	rdi, rax
	mov	esi, ' '
	mov	edx, r13d
	mov	rbx, rax
	call	tui_background$init_dd
	mov	qword [rbx], tui_typist$vtable
	mov	[rbx+tui_typist_text_ofs], r14
	mov	rdi, rbx
	pop	r14 r13 r12
	call	tui_typist$nvsetup
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used tui_typist$new_id | defined include_everything
	; four arguments: edi == width, xmm0 == heightperc, rsi == text to type, edx == colors
falign
tui_typist$new_id:
	prolog	tui_typist$new_id
	push	rbx r12 r13 r14
	mov	ebx, edi
	movq	r12, xmm0
	mov	r13d, edx
	mov	rdi, rsi
	call	string$copy
	mov	r14, rax
	mov	edi, tui_typist_size
	call	heap$alloc
	mov	rdi, rax
	mov	esi, ebx
	movq	xmm0, r12
	mov	edx, ' '
	mov	ecx, r13d
	mov	rbx, rax
	call	tui_background$init_id
	mov	qword [rbx], tui_typist$vtable
	mov	[rbx+tui_typist_text_ofs], r14
	mov	rdi, rbx
	pop	r14 r13 r12
	call	tui_typist$nvsetup
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used tui_typist$new_di | defined include_everything
	; four arguments: xmm0 == widthperc, edi == height, rsi == text to type, edx == colors
falign
tui_typist$new_di:
	prolog	tui_typist$new_di
	push	rbx r12 r13 r14
	movq	rbx, xmm0
	mov	r12d, edi
	mov	r13d, edx
	mov	rdi, rsi
	call	string$copy
	mov	r14, rax
	mov	edi, tui_typist_size
	call	heap$alloc
	mov	rdi, rax
	movq	xmm0, rbx
	mov	esi, r12d
	mov	edx, ' '
	mov	ecx, r13d
	mov	rbx, rax
	call	tui_background$init_di
	mov	qword [rbx], tui_typist$vtable
	mov	[rbx+tui_typist_text_ofs], r14
	mov	rdi, rbx
	pop	r14 r13 r12
	call	tui_typist$nvsetup
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used tui_typist$new_ii | defined include_everything
	; four arguments: edi == width, esi == height, rdx == text to type, ecx == colors
falign
tui_typist$new_ii:
	prolog	tui_typist$new_ii
	push	rbx r12 r13 r14
	mov	ebx, edi
	mov	r12d, esi
	mov	r13d, ecx
	mov	rdi, rdx
	call	string$copy
	mov	r14, rax
	mov	edi, tui_typist_size
	call	heap$alloc
	mov	rdi, rax
	mov	esi, ebx
	mov	edx, r12d
	mov	ecx, ' '
	mov	r8d, r13d
	mov	rbx, rax
	call	tui_background$init_ii
	mov	qword [rbx], tui_typist$vtable
	mov	[rbx+tui_typist_text_ofs], r14
	mov	rdi, rbx
	pop	r14 r13 r12
	call	tui_typist$nvsetup
	mov	rax, rbx
	pop	rbx
	epilog

end if

if used tui_typist$clone | defined include_everything
	; single argument: rdi == tui_typist object to clone
falign
tui_typist$clone:
	prolog	tui_typist$clone
	push	rbx r12
	mov	rbx, rdi
	mov	edi, tui_typist_size
	call	heap$alloc
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, rbx
	call	tui_background$init_copy
	mov	rdi, [rbx+tui_typist_text_ofs]
	call	string$copy
	mov	[r12+tui_typist_text_ofs], rax
	mov	rdi, r12
	call	tui_typist$nvsetup
	mov	rax, r12
	pop	r12 rbx
	epilog

end if

if used tui_typist$nvsetup | defined include_everything
	; single argument in rdi: our tui_typist object we are initializing...
	; the only var we require to be populated is the text itself
falign
tui_typist$nvsetup:
	prolog	tui_typist$nvsetup
	push	rbx
	mov	rbx, rdi
	mov	qword [rdi+tui_typist_cursor_ofs], 0
	mov	qword [rdi+tui_typist_index_ofs], 0
	mov	qword [rdi+tui_typist_timerptr_ofs], 0
	mov	qword [rdi+tui_typist_lastptr_ofs], 0
	mov	qword [rdi+tui_typist_alldone_ofs], 0
	mov	qword [rdi+tui_typist_usecursor_ofs], 1		; default to gank the cursor
								; also sets errmod to 0
	; calculate our typing delay
	mov	edi, tui_typist_mindelay
	mov	esi, tui_typist_maxdelay
	call	rng$int
	mov	qword [rbx+tui_typist_delay_ofs], rax
	; calculate our accuracy
	call	rng$double
	mulsd	xmm0, [.dot1]
	addsd	xmm0, [.accbase]
	movq	[rbx+tui_typist_accuracy_ofs], xmm0
	pop	rbx
	epilog
dalign
.dot1		dq	0.1f
.accbase	dq	0.80f

end if


if used tui_typist$cleanup | defined include_everything
	; single argument: rdi == tui_typist object to cleanup
falign
tui_typist$cleanup:
	prolog	tui_typist$cleanup
	push	rdi
	mov	rdi, [rdi+tui_typist_text_ofs]
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_typist_timerptr_ofs]
	test	rdi, rdi
	jz	.notimer
	call	epoll$timer_clear
	pop	rdi
	call	tui_object$cleanup
	epilog
calign
.notimer:
	pop	rdi
	call	tui_object$cleanup
	epilog

end if

if used tui_typist$draw | defined include_everything
	; single argument: rdi == tui_typist object to draw
falign
tui_typist$draw:
	prolog	tui_typist$draw
	; we are "special" insofar as we do not maintain a separate buffer for our typing activities
	; when we are first placed and/or added and flattened, our draw method gets called with valid bounds
	; at which point, all we have to do is a one-time background$nvfill, and fire up our timerptr
	; if the timer is already running, it means our draw got called again, but since we are writing
	; directly into our own buffers, this is fine and dandy
	cmp	dword [rdi+tui_typist_alldone_ofs], 0
	jne	.nothingtodo
	cmp	qword [rdi+tui_typist_timerptr_ofs], 0
	jne	.nothingtodo
	cmp	dword [rdi+tui_width_ofs], 0
	je	.nothingtodo
	cmp	dword [rdi+tui_height_ofs], 0
	je	.nothingtodo
	; otherwise, we need our background fill, and then we need to fire up our timer
	push	rdi
	call	tui_background$nvfill
	mov	rsi, [rsp]
	mov	edi, [rsi+tui_typist_delay_ofs]
	call	epoll$timer_new
	pop	rdi
	mov	[rdi+tui_typist_timerptr_ofs], rax
	; specify that when we specify timer complete that we don't want to be destroyed
	; and instead, only want the timer to end.
	mov     dword [rax+24], 2
	epilog
calign
.nothingtodo:
	epilog

end if

if used tui_typist$sizechanged | defined include_everything
	; single argument in rdi: our tui_typist object
falign
tui_typist$sizechanged:
	prolog	tui_typist$sizechanged
	; burning purpose: reset everything
	push	rdi
	mov	rdi, [rdi+tui_typist_timerptr_ofs]
	test	rdi, rdi
	jz	.notimer
	call	epoll$timer_clear
	mov	rdi, [rsp]
	mov	qword [rdi+tui_typist_timerptr_ofs], 0
	call	tui_typist$nvsetup
	pop	rdi
	call	tui_object$sizechanged		; this will also fire off our draw method all over again
	epilog
calign
.notimer:
	mov	rdi, [rsp]
	call	tui_typist$nvsetup
	pop	rdi
	call	tui_object$sizechanged		; this will also fire off our draw method all over again
	epilog

end if

if used tui_typist$nvsetcursor | defined include_everything
	; single argument in rdi: our tui_typist object
falign
tui_typist$nvsetcursor:
	prolog	tui_typist$nvsetcursor
	mov	esi, [rdi+tui_bounds_ax_ofs]
	mov	edx, [rdi+tui_bounds_ay_ofs]
	add	esi, [rdi+tui_typist_cursor_ofs]
	add	edx, [rdi+tui_typist_cursor_ofs+4]
	add	esi, [rdi+tui_typist_errmod_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vsetcursor]
	epilog

end if


if used tui_typist$timer | defined include_everything
	; single argument in rdi: our tui_typist object
falign
tui_typist$timer:
	prolog	tui_typist$timer
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	rsi, [rdi+tui_typist_text_ofs]
	mov	rdx, [rsi]
	cmp	qword [rdi+tui_typist_index_ofs], rdx
	jae	.typingcompleted
	cmp	qword [rdi+tui_typist_lastptr_ofs], 0
	jne	.correction
	mov	eax, [rdi+tui_width_ofs]
	mul	dword [rdi+tui_typist_cursor_ofs+4]
	add	eax, [rdi+tui_typist_cursor_ofs]
	shl	eax, 2
	mov	r8d, eax			; our current offset in bytes into our buffer
	mov	eax, [rdi+tui_width_ofs]
	mul	dword [rdi+tui_height_ofs]
	shl	eax, 2
	mov	r9d, eax			; our actual maximum in bytes
	cmp	r8d, r9d
	jae	.bailout
	mov	r12, r8
	add	r12, [rbx+tui_text_ofs]
	; get the actual character we are going to attempt to type from our text
	mov	rdi, [rbx+tui_typist_text_ofs]
	mov	esi, [rbx+tui_typist_index_ofs]
	call	string$charat
	mov	r13d, eax
	; 
	; we don't make errors on backspace, delay, or crlf
	cmp	eax, 8
	je	.backspace
	cmp	eax, 0
	je	.typingdelay
	cmp	eax, 10
	je	.crlf
	cmp	eax, 32
	je	.noerror
	; determine whether we are going to screw up or not
	call	rng$double
	movq	xmm1, [rbx+tui_typist_accuracy_ofs]
	ucomisd	xmm0, xmm1
	jae	.typingerror
calign
.noerror:
	; otherwise, we are sticking the real character in
	add	dword [rbx+tui_typist_index_ofs], 1
	mov	dword [r12], r13d
	mov	eax, [rbx+tui_width_ofs]
	add	dword [rbx+tui_typist_cursor_ofs], 1
	cmp	dword [rbx+tui_typist_cursor_ofs], eax
	jb	.delay
	; otherwise, nextline
	add	dword [rbx+tui_typist_cursor_ofs+4], 1
	mov	dword [rbx+tui_typist_cursor_ofs], 0
	jmp	.delay
calign
.typingcompleted:
	; our index moved off the end of our text
	; call our oncomplete method, and then tell the epoll layer to let us go
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_typist_voncomplete]
	mov	qword [rbx+tui_typist_timerptr_ofs], 0	; in case we get restarted
	mov	qword [rbx+tui_typist_alldone_ofs], 1
	pop	r14 r13 r12 rbx
	mov	eax, 1
	epilog
calign
.typingdelay:
	add	dword [rbx+tui_typist_index_ofs], 1
	jmp	.delay
calign
.typingerror:
	; stick a legitimate-looking, haha, (QWERTY area based) typing error at [r12]
	mov	dword [rbx+tui_typist_errmod_ofs], 1
	mov	[rbx+tui_typist_lastptr_ofs], r12
	mov	rdi, .nearest
	mov	rsi, .nearest + .nearest_size
calign
.findit:
	movzx	eax, byte [rdi]
	cmp	r13d, eax
	je	.typingerror_match
	add	rdi, 9
	cmp	rdi, rsi
	jb	.findit
	; no match, so stick +1 of r13 at r12
	add	r13d, 1
	mov	dword [r12], r13d
	jmp	.delay
calign
.typingerror_match:
	; so, we need to save our pointer at rdi
	push	r14
	mov	r14, rdi
calign
.typingerror_match_loop:
	mov	edi, 1
	mov	esi, 8
	call	rng$int
	cmp	byte [r14+rax], 0
	je	.typingerror_match_loop
	movzx	r13d, byte [r14+rax]
	pop	r14
	mov	dword [r12], r13d
	jmp	.delay
dalign
.nearest:
	; 37 groups of 9 bytes each, could be way more complex if I were motivated and felt like translating more of my C++ goods
	db	'1', '2', 'w', 'q', 0, 0, 0, 0, 0
	db	'2', '1', '3', 'q', 'w', 'e', 0, 0, 0
	db	'3', '2', '4', 'w', 'e', 'r', 0, 0, 0
	db	'4', '3', '5', 'e', 'r', 't', 0, 0, 0
	db	'5', '4', '6', 'r', 't' ,'y', 0, 0, 0
	db	'6', '5', '7', 't', 'y', 'u', 0, 0, 0
	db	'7', '6', '8', 'y', 'u', 'i', 0, 0, 0
	db	'8', '7', '9', 'u', 'i', 'o', 0, 0, 0
	db	'9', '7', '0', 'i', 'o', 'p', 0, 0, 0
	db	'0', '9', '-', 'o', 'p', '[', 0, 0, 0
	db	'-', '0', '=', 'p', '[', ']', 0, 0, 0
	db	'q', '1', '2', 'w', 's', 'a', 0, 0, 0
	db	'w', '1', '2', '3', 'q', 'e', 'a', 's', 'd'
	db	'e', '2', '3', '4', 'w', 'r', 's', 'd', 'f'
	db	'r', '3', '4', '5', 'e', 't', 'd', 'f', 'g'
	db	't', '4', '5', '6', 'r', 'y', 'f', 'g', 'h'
	db	'y', '5', '6', '7', 't', 'u', 'g', 'h', 'j'
	db	'u', '6', '7', '8', 'y', 'i', 'h', 'j', 'k'
	db	'i', '7', '8', '9', 'u', 'o', 'j', 'k', 'l'
	db	'o', '8', '9', '0', 'i', 'p', 'k', 'l', ';'
	db	'p', '9', '0', '-', 'o', '[', 'l', ';', 39
	db	'a', 'q', 'w', 's', 'z', 'x', 0, 0, 0
	db	's', 'q', 'w', 'e', 'a', 'd', 'z', 'x', 'c'
	db	'd', 'w', 'e', 'r', 's', 'f', 'x', 'c', 'v'
	db	'f', 'e', 'r', 't', 'd', 'g', 'c', 'v', 'b'
	db	'g', 'r', 't', 'y', 'f', 'h', 'v', 'b', 'n'
	db	'h', 't', 'y', 'u', 'g', 'j', 'b', 'n', 'm'
	db	'j', 'y', 'u', 'i', 'h', 'k', 'n', 'm', ','
	db	'k', 'u', 'i', 'o', 'j', 'l', 'm', ',', '.'
	db	'l', 'i', 'o', 'p', 'k', ';', ',', '.', '/'
	db	'z', 'a', 's', 'x', 0, 0, 0, 0, 0
	db	'x', 'a', 's', 'd', 'z', 'c', 0, 0, 0
	db	'c', 's', 'd', 'f', 'x', 'v', 0, 0, 0
	db	'v', 'd', 'f', 'g', 'c', 'b', 0, 0, 0
	db	'b', 'f', 'g', 'h', 'v', 'n', 0, 0, 0
	db	'n', 'g', 'h', 'j', 'b', 'm', 0, 0, 0
	db	'm', 'h', 'j', 'k', 'n', ',', 0, 0, 0
.nearest_size = $ - .nearest

calign
.crlf:
	add	dword [rbx+tui_typist_index_ofs], 1	; so we don't do the backspace again
	mov	dword [rbx+tui_typist_cursor_ofs], 0
	add	dword [rbx+tui_typist_cursor_ofs+1], 1
	jmp	.delay
calign
.backspace:
	add	dword [rbx+tui_typist_index_ofs], 1	; so we don't do the backspace again
	cmp	dword [rbx+tui_typist_cursor_ofs], 0
	je	.bailout
	sub	dword [rbx+tui_typist_cursor_ofs], 1	; so our next character ends up back one
	sub	r12, 4
	mov	dword [r12], ' '
	jmp	.delay
calign
.bailout:
	pop	r14 r13 r12 rbx
	epilog
calign
.correction:
	; lastptr was set, which means we stuck a typing error in
	mov	dword [rdi+tui_typist_errmod_ofs], 0
	mov	rsi, [rdi+tui_typist_lastptr_ofs]
	mov	dword [rsi], ' '
	mov	qword [rdi+tui_typist_lastptr_ofs], 0
calign
.delay:

	cmp	dword [rbx+tui_typist_usecursor_ofs], 0
	je	.skipcursor
	mov	rdi, rbx
	call	tui_typist$nvsetcursor

calign
.skipcursor:
	; come up with a new random delay
	xor	edi, edi
	mov	esi, 3
	call	rng$int
	mov	ecx, 20
	mul	ecx
	add	eax, [rbx+tui_typist_delay_ofs]

	; if the next character is equal to this character, halve the time
	mov	edx, eax
	shr	edx, 1
	cmp	r13d, r14d
	cmove	eax, edx

	mov	rsi, [rbx+tui_typist_timerptr_ofs]
	mov	[rsi], rax

	mov	rdi, rbx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vupdatedisplaylist]

	pop	r14 r13 r12 rbx
	xor	eax, eax		; don't kill the timer
	epilog

end if

if used tui_typist$oncomplete | defined include_everything
	; single argument in rdi: our tui_typist object
falign
tui_typist$oncomplete:
	prolog	tui_typist$oncomplete
	; default do-nothing
	epilog

end if
