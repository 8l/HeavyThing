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
	; tui_terminal.inc: terminal support for the tui layer...
	;	this hooks stdin/stdout via epoll, sets up the necessary
	;	signal handling for WINCH, does necessary termios-type goods
	;

if used tui_terminal$vtable | defined include_everything

dalign
tui_terminal$vtable:
        dq      tui_terminal$cleanup, tui_object$clone, tui_object$draw, tui_object$redraw, tui_render$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_render$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_terminal$keyevent, tui_object$domodal, tui_object$endmodal, tui_terminal$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_render$setcursor, tui_render$showcursor, tui_render$hidecursor, tui_object$click, tui_object$clicked
        dq      tui_terminal$ansioutput, tui_render$newlayoutonresize, tui_render$newwindowsize
end if


	; Terminal is meant to be a singleton for obvious reasons
	; you should create precisely one, passing its first child
	; and then fire up the epoll layer
if used tui_terminal$new | defined include_everything

globals
{
	_tui_terminal_singleton	dq	0
}

end if


; we add some vars to our "inherited" render properties
tui_stdin_ofs = tui_render_size
tui_stdout_ofs = tui_render_size + 8
tui_termios_stdin_save = tui_render_size + 16
tui_termios_stdout_save = tui_render_size + 76
tui_terminal_initsent = tui_render_size + 136

tui_terminal_size = tui_render_size + 144


if used stdio_datareceived | defined include_everything
	; stdio epoll functions:

	; this one just gets a single argument with our epoll object in rdi (well, it also gets buffer start/length but we don't care)
falign
stdio_datareceived:
	prolog_silent	stdio_datareceived
	; Burning Purpose: get our terminal pointer into rdi, get our input buffer into rsi
	; and hand it off to the terminal side's nvstdin
	mov	rsi, [rdi+epoll_inbuf_ofs]
	mov	rdi, [rdi+epoll_base_size]	; our terminal pointer
	call	tui_terminal$nvstdin
	xor	eax, eax			; don't close the connection
	epilog
end if

if used stdio_error | defined include_everything
falign
stdio_error:
	prolog_silent	stdio_error
	; Burning Purpose: send ourselves as an argument to our terminal advising them
	; that we have been destroyed (epoll layer will have deleted us good and proper)
	mov	rsi, rdi		; us as an argument
	mov	rdi, [rdi+epoll_base_size]	; our terminal
	call	tui_terminal$nvonesidedied
	epilog
end if


if used stdio_winch | defined include_everything
	; signal handling goods...
	; CAVEAT EMPTOR: the whole reason that terminal must be a singleton (and its a good thing
	; since it makes SENSE) is because when one of these signals arrives, we need to be able
	; to FIND our terminal instance (hence our fine and dandy looking _tui_terminal_singleton
	; global variable)
falign
stdio_winch:
	prolog_silent	stdio_sigwinch
	; get our terminal size and fire a newwindowsize virtual method call
	sub	rsp, 16
	xor	edi, edi			; fd
	mov	esi, 0x5413			; TIOCGWINSZ
	mov	rdx, rsp
	mov	eax, syscall_ioctl
	syscall
	movzx	edx, word [rsp]			; ws_row
	movzx	esi, word [rsp+2]		; ws_col
	add	rsp, 16
	mov	rdi, [_tui_terminal_singleton]
	mov	rcx, [rdi]
	call	qword [rcx+tui_vnewwindowsize]	; 
	epilog
end if


if used stdio_term | defined include_everything
falign
stdio_term:
	prolog_silent	stdio_term
	mov	rdi, [_tui_terminal_singleton]
	call	tui_terminal$nvterminated
	epilog
end if

if used stdio_vtable | defined include_everything

	; need our stdio-specific epoll goodies
calign
stdio_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, stdio_datareceived, stdio_error, io$timeout

end if

if used tui_terminal$cleanup | defined include_everything
	; single argument in rdi: our tui_terminal object
	; NOTE: we do not free rdi, only cleanup everything we made
falign
tui_terminal$cleanup:
	prolog	tui_terminal$cleanup
	push	rdi
	call	tui_render$cleanup
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_stdin_ofs]
	test	rdi, rdi
	jz	.nostdin
	call	epoll$fatality
calign
.nostdin:
	mov	rsi, [rsp]
	mov	rdi, [rsi+tui_stdout_ofs]
	test	rdi, rdi
	jz	.nostdout
	mov	qword [rdi+epoll_fd_ofs], -1	; do _not_ let the epoll layer close the fd
	call	epoll$fatality
calign
.nostdout:
	; we don't really care if they actually did error out before
	; these will silently error and we don't mind one bit
	; we also need to restore the terminal attributes
	mov	rcx, [rsp]
	xor	edi, edi			; fd
	mov	esi, 0x5404			; TCSETSF
	lea	rdx, [rcx+tui_termios_stdin_save]
	mov	eax, syscall_ioctl
	syscall
	mov	rcx, [rsp]
	mov	edi, 1				; fd
	mov	esi, 0x5404			; TCSETSF
	lea	rdx, [rcx+tui_termios_stdout_save]
	mov	eax, syscall_ioctl
	syscall
	; remove O_NONBLOCK from our stdout
	mov	eax, syscall_fcntl
	mov	edi, 1				; stdout
	mov	esi, 3				; F_GETFL
	syscall
	and	eax, 0xfffff7ff			; &= ~O_NONBLOCK
	mov	edi, 1				; stdout
	mov	esi, 4				; F_SETFL
	mov	edx, eax			; flags
	mov	eax, syscall_fcntl
	syscall
	pop	rdi
	epilog
end if


if used tui_terminal$new | defined include_everything
	; single argument in rdi: first child
falign
tui_terminal$new:
	prolog	tui_terminal$new
	cmp	qword [_tui_terminal_singleton], 0
	jne	.kakked
	sub	rsp, 16
	mov	[rsp+8], rdi
	mov	edi, tui_terminal_size
	call	heap$alloc
	mov	[rsp], rax
	mov	rdi, rax
	mov	rsi, [rsp+8]
	mov	qword [rdi], tui_terminal$vtable	; set our vtable
	add	rdi, 8
	xor	esi, esi
	mov	edx, tui_terminal_size - 8
	call	memset32
	mov	rdi, [rsp]
	; copy of tui_render's init_defaults routine
        mov     dword [rdi+tui_visible_ofs], 1
        mov     dword [rdi+tui_includeinlayout_ofs], 1
        mov     dword [rdi+tui_absolutex_ofs], -1
        mov     dword [rdi+tui_absolutey_ofs], -1
        call    list$new
        mov     rdi, [rsp]
        mov     [rdi+tui_children_ofs], rax
        call    list$new
        mov     rdi, [rsp]
        mov     [rdi+tui_bastards_ofs], rax
        mov     dword [rdi+tui_cursorvisible_ofs], 1
        call    buffer$new
        mov     rdi, [rsp]
        mov     [rdi+tui_outputbuffer_ofs], rax

	; now we need to setup our terminal-specific vars
	; for our stdin/stdout, we need two epoll objects
	; each one needs an extra pointer to hold our terminal pointer
	mov	rdi, stdio_vtable
	mov	esi, 8
	call	epoll$new
	mov	rsi, [rsp]
	mov	[rsi+tui_stdin_ofs], rax	; set stdin
	mov	[rax+epoll_base_size], rsi	; save our terminal instance in the epoll object
	mov	rdi, stdio_vtable
	mov	esi, 8
	call	epoll$new
	mov	rsi, [rsp]
	mov	[rsi+tui_stdout_ofs], rax	; set stdout
	mov	[rax+epoll_base_size], rsi	; save our terminal instance in the epoll object
	; now we call established on both of them

	; NOTE: because my epoll layer automatically does an EPOLLIN, and because stdin/stdout are dup2'd
	; we are leaving this one out... we still get data inbound on fd 1

	;xor	edi, edi			; fd
	;mov	rsi, [rsi+tui_stdin_ofs]	; epoll object for stdin
	;call	epoll$established
	mov	rdx, [rsp]
	mov	edi, 1				; fd
	mov	rsi, [rdx+tui_stdout_ofs]	; epoll object for stdout
	call	epoll$established
	; next up, we need to hook SIGWINCH
	sub	rsp, 152
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, 152
	call	memset32
	mov	qword [rsp], stdio_winch
	mov	qword [rsp+8], 0x14000000	; SA_RESTORER|SA_RESTART
	mov	qword [rsp+16], .rt_sigreturn
	mov	qword [rsp+24], 1 shl 27	; 1 shl (SIGWINCH - 1)
	mov	eax, syscall_rt_sigaction
	mov	edi, 28				; SIGWINCH
	mov	rsi, rsp
	xor	edx, edx
	mov	r10d, 8				; sizeof(sigset_t)
	syscall
	; next up, we need to hook SIGTERM
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, 152
	call	memset32
	mov	qword [rsp], stdio_term
	mov	qword [rsp+8], 0x14000000	; SA_RESTORER|SA_RESTART
	mov	qword [rsp+16], .rt_sigreturn
	mov	qword [rsp+24], 1 shl 14	; 1 shl (SIGTERM - 1)
	mov	eax, syscall_rt_sigaction
	mov	edi, 15				; SIGTERM
	mov	rsi, rsp
	xor	edx, edx
	mov	r10d, 8				; sizeof(sigset_t)
	syscall
	add	rsp, 152
	; next up, we have to do our nonportable ioctls to get our termios goods
	mov	rcx, [rsp]			; get our object back
	xor	edi, edi			; fd
	mov	esi, 0x5401			; TCGETS
	lea	rdx, [rcx+tui_termios_stdin_save]
	mov	eax, syscall_ioctl
	syscall
	mov	rcx, [rsp]			; get our object back
	mov	edi, 1				; fd
	mov	esi, 0x5401			; TCGETS
	lea	rdx, [rcx+tui_termios_stdout_save]
	mov	eax, syscall_ioctl
	syscall
	; next up, copy and modify them
	mov	rcx, [rsp]
	lea	rsi, [rcx+tui_termios_stdin_save]
	sub	rsp, 64				; sizeof(struct termios) is 60
	mov	rdi, rsp
	mov	edx, 60
	call	memcpy
	; offset of c_lflag is 0xC
	and	dword [rsp+0xC], 0xffff7ff4	; c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG)
	; offset of c_iflag is 0
	and	dword [rsp], 0xfffffedd		; c_iflag &= ~(BRKINT | ICRNL | ISTRIP)
	; offset of c_cflag is 8
	and	dword [rsp+8], 0xfffffecf	; c_cflag &= ~(CSIZE | PARENB)
	or	dword [rsp+8], 0x30		; c_cflag |= CS8
	; offset of c_oflag is 4
	and	dword [rsp+4], 0xfffffffe	; c_oflag &= ~(OPOST)
	mov	word [rsp+0x16], 0		; c_cc[VMIN] = 0, c_cc[VTIME] = 0
	; last but not least, tcsetattr it
	xor	edi, edi			; fd
	mov	esi, 0x5404			; TCSETSF
	mov	rdx, rsp
	mov	eax, syscall_ioctl
	syscall
	; now, do the same thing for stdout, though i don't think we really have to, one is enough, haha
	; TODO: someday when I am bored, figure out whether this is really even necessary
	; since we made room for our buffer, it means our object pointer is now at +64
	mov	rcx, [rsp+64]
	lea	rsi, [rcx+tui_termios_stdout_save]
	mov	rdi, rsp
	mov	edx, 60
	call	memcpy
	; copy of the above modifications and syscall with the fd changed:
	; offset of c_lflag is 0xC
	and	dword [rsp+0xC], 0xffff7ff4	; c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG)
	; offset of c_iflag is 0
	and	dword [rsp], 0xfffffedd		; c_iflag &= ~(BRKINT | ICRNL | ISTRIP)
	; offset of c_cflag is 8
	and	dword [rsp+8], 0xfffffecf	; c_cflag &= ~(CSIZE | PARENB)
	or	dword [rsp+8], 0x30		; c_cflag |= CS8
	; offset of c_oflag is 4
	and	dword [rsp+4], 0xfffffffe	; c_oflag &= ~(OPOST)
	mov	word [rsp+0x16], 0		; c_cc[VMIN] = 0, c_cc[VTIME] = 0
	; last but not least, tcsetattr it
	mov	edi, 1				; fd
	mov	esi, 0x5404			; TCSETSF
	mov	rdx, rsp
	mov	eax, syscall_ioctl
	syscall
	; we are not quite done with our temporary buffer
	xor	edi, edi			; fd
	mov	esi, 0x5413			; TIOCGWINSZ
	mov	rdx, rsp
	mov	eax, syscall_ioctl
	syscall
	movzx	edx, word [rsp]			; ws_row
	movzx	esi, word [rsp+2]		; ws_col
	add	rsp, 64
	mov	rdi, [rsp]			; get our object pointer
	mov	rcx, [rdi]			; get its vtable
	call	qword [rcx+tui_vnewwindowsize]	; 
	; we need to set our global singleton (so that we can access it from the signal handlers)
	mov	rdi, [rsp]
	mov	[_tui_terminal_singleton], rdi
	; we also need to add our first child:
	mov	rsi, [rsp+8]
	mov	rdx, [rdi]			; load our vtable
	call	qword [rdx+tui_vappendchild]
	mov	rax, [rsp]			; setup our return
	add	rsp, 16
	epilog
calign
.kakked:
	; terminal$new was called more than once
	breakpoint

calign
.rt_sigreturn:
	mov	eax, syscall_rt_sigreturn
	syscall
	ret	; ??
end if


if used tui_terminal$keyevent | defined include_everything
	; three arguments: tui_terminal object in rdi, esi == key, edx == esc_key
	; NOTE: the reason we hook this is solely to capture ctrl-c, haha
falign
tui_terminal$keyevent:
	prolog	tui_terminal$keyevent
	xor	eax, eax
	cmp	esi, 3
	jne	.outtahere
	; otherwise, ctrl-c was hit
	sub	rsp, 128
	mov	[rsp], rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]	; call the virtual cleanup method first, this restores all the goods
	; since we are about to call sysexit, all we really need is our height, which still should be intact
	mov	rdi, [rsp]
	mov	esi, [rdi+tui_height_ofs]
	mov	[rsp+8], rsi			; save our height
	call	heap$free			; free our actual object, though again, since we are calling sysexit
						; that really isn't necessary, haha
if used epoll_child | defined include_everything
	call	epoll_child_killall
end if
	mov	qword [_tui_terminal_singleton], 0	; neither is that
	; now, we need to send out some "GTFO" ANSI, because I loath having my cursor jacked up
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .seeyalater
	mov	edx, .seeyalater_size
	syscall	; send out our preface
	mov	rdi, [rsp+8]			; get our height back
	mov	esi, 10				; radix
	call	string$from_int
	mov	[rsp], rax			; save our string
	mov	rdi, rax
	mov	rsi, rsp
	add	rsi, 16
	call	string$to_utf8
	mov	rcx, [rsp]			; get our string back
	mov	rdx, [rcx]			; get its size
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	add	rsi, 16
	syscall
	mov	rdi, [rsp]
	call	heap$free			; free our height string
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .reallyseeya
	mov	edx, .reallyseeya_size
	syscall
	mov	eax, syscall_exit
	mov	edi, 127
	syscall
	; not reached:
	epilog
if terminal_alternatescreen

dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H',27,'[?1049l!!Ctrl-C!!',10
	.reallyseeya_size = $ - .reallyseeya

else

dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H!!Ctrl-C!!',10
	.reallyseeya_size = $ - .reallyseeya

end if
calign
.outtahere:
	epilog
end if


if used tui_terminal$nvclose | defined include_everything
	; two arguments: tui_terminal object in rdi, message (string) in rsi to display on stdout
	; NOTE: this "shuts down cleanly" our tui_terminal object, spits out the message, but does
	; not do anything else (useful if you want a tui, but then want to background/daemonize/etc)
falign
tui_terminal$nvclose:
	prolog	tui_terminal$nvclose
	sub	rsp, 128
	mov	[rsp], rdi
	mov	[rsp+120], rsi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]	; call the virtual cleanup method first, this restores all the goods
	; since we are about to call sysexit, all we really need is our height, which still should be intact
	mov	rdi, [rsp]
	mov	esi, [rdi+tui_height_ofs]
	mov	[rsp+8], rsi			; save our height
	call	heap$free
	mov	qword [_tui_terminal_singleton], 0
	; now, we need to send out some "GTFO" ANSI, because I loath having my cursor jacked up
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .seeyalater
	mov	edx, .seeyalater_size
	syscall	; send out our preface
	mov	rdi, [rsp+8]			; get our height back
	mov	esi, 10				; radix
	call	string$from_int
	mov	[rsp], rax			; save our string
	mov	rdi, rax
	mov	rsi, rsp
	add	rsi, 16
	call	string$to_utf8
	mov	rcx, [rsp]			; get our string back
	mov	rdx, [rcx]			; get its size
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	add	rsi, 16
	syscall
	mov	rdi, [rsp]
	call	heap$free			; free our height string
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .reallyseeya
	mov	edx, .reallyseeya_size
	syscall
	; send our message
	mov	rdi, [rsp+120]
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 127
	syscall
	; not reached:
	epilog
if terminal_alternatescreen

dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H',27,'[?1049l'
	.reallyseeya_size = $ - .reallyseeya

else

dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H'
	.reallyseeya_size = $ - .reallyseeya

end if
calign
.outtahere:
	epilog

end if


if used tui_terminal$exit | defined include_everything
	; two arguments, tui_terminal object in rdi, exit code in esi
	; we actually just do a brute force exit exactly like keyevent for ctrl-C
falign
tui_terminal$exit:
	prolog	tui_terminal$exit
	sub	rsp, 128
	mov	[rsp], rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]	; call the virtual cleanup method first, this restores all the goods
	; since we are about to call sysexit, all we really need is our height, which still should be intact
	mov	rdi, [rsp]
	mov	esi, [rdi+tui_height_ofs]
	mov	[rsp+8], rsi			; save our height
	call	heap$free			; free our actual object, though again, since we are calling sysexit
						; that really isn't necessary, haha
if used epoll_child | defined include_everything
	call	epoll_child_killall
end if
	mov	qword [_tui_terminal_singleton], 0	; neither is that
	; now, we need to send out some "GTFO" ANSI, because I loath having my cursor jacked up
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .seeyalater
	mov	edx, .seeyalater_size
	syscall	; send out our preface
	mov	rdi, [rsp+8]			; get our height back
	mov	esi, 10				; radix
	call	string$from_int
	mov	[rsp], rax			; save our string
	mov	rdi, rax
	mov	rsi, rsp
	add	rsi, 16
	call	string$to_utf8
	mov	rcx, [rsp]			; get our string back
	mov	rdx, [rcx]			; get its size
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	add	rsi, 16
	syscall
	mov	rdi, [rsp]
	call	heap$free			; free our height string
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .reallyseeya
	mov	edx, .reallyseeya_size
	syscall
	mov	eax, syscall_exit
	mov	edi, 127
	syscall
	; not reached:
	epilog
if terminal_alternatescreen
dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H',27,'[?1049l!!Clean Exit!!',10
	.reallyseeya_size = $ - .reallyseeya
else
dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H!!Clean Exit!!',10
	.reallyseeya_size = $ - .reallyseeya
end if

end if


if used tui_terminal$nvterminated | defined include_everything
	; single argument in rdi: our tui_terminal object
	; this gets called from SIGTERM
falign
tui_terminal$nvterminated:
	prolog	tui_terminal$nvterminated
	sub	rsp, 128
	mov	[rsp], rdi
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]	; call the virtual cleanup method first, this restores all the goods
	; since we are about to call sysexit, all we really need is our height, which still should be intact
	mov	rdi, [rsp]
	mov	esi, [rdi+tui_height_ofs]
	mov	[rsp+8], rsi			; save our height
	call	heap$free			; free our actual object, though again, since we are calling sysexit
						; that really isn't necessary, haha
if used epoll_child | defined include_everything
	call	epoll_child_killall
end if
	mov	qword [_tui_terminal_singleton], 0	; neither is that
	; now, we need to send out some "GTFO" ANSI, because I loath having my cursor jacked up
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .seeyalater
	mov	edx, .seeyalater_size
	syscall	; send out our preface
	mov	rdi, [rsp+8]			; get our height back
	mov	esi, 10				; radix
	call	string$from_int
	mov	[rsp], rax			; save our string
	mov	rdi, rax
	mov	rsi, rsp
	add	rsi, 16
	call	string$to_utf8
	mov	rcx, [rsp]			; get our string back
	mov	rdx, [rcx]			; get its size
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	add	rsi, 16
	syscall
	mov	rdi, [rsp]
	call	heap$free			; free our height string
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .reallyseeya
	mov	edx, .reallyseeya_size
	syscall
	mov	eax, syscall_exit
	mov	edi, 127
	syscall
	; not reached:
	epilog
if terminal_alternatescreen
dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H',27,'[?1049l!!Terminated!!',10
	.reallyseeya_size = $ - .reallyseeya
else
dalign
.seeyalater:
	db	27,'[r',27,'[?25h',27,'['
	.seeyalater_size = $ - .seeyalater
dalign
.reallyseeya:
	db	';1H!!Terminated!!',10
	.reallyseeya_size = $ - .reallyseeya
end if

end if


if used tui_terminal$ansioutput | defined include_everything
	; three arguments: tui_terminal object in rdi, utf8 buffer in rsi, length in rdx
falign
tui_terminal$ansioutput:
	prolog	tui_terminal$ansioutput
	; all we need to do is grab our stdout epoll object and send it
	if terminal_alternatescreen
		cmp	dword [rdi+tui_terminal_initsent], 0
		je	.initfirst
	end if
	mov	rdi, [rdi+tui_stdout_ofs]
	test	rdi, rdi
	jz	.nothingtodo
if defined terminal_ansidebug
	push	rdi rsi rdx

        mov     eax, syscall_open
        mov     rdi, .debug_fname
        mov     esi, 0x442
        mov     edx, 0x180
        syscall
	push	rax
        mov     rdi, rax                ; fd
	mov	rsi, [rsp+16]
	mov	rdx, [rsp+8]
	mov	eax, syscall_write
	syscall
	pop	rdi
	mov	eax, syscall_close
	syscall
	pop	rdx rsi rdi
end if
	mov	rcx, [rdi]		; load up its vtable
	call	qword [rcx+epoll_vsend]
	epilog
calign
.nothingtodo:
	; means our stdout side got closed or errored
	epilog
if terminal_alternatescreen
calign
.initfirst:
	mov	dword [rdi+tui_terminal_initsent], 1
	mov	rdi, [rdi+tui_stdout_ofs]
	test	rdi, rdi
	jz	.nothingtodo
	push	rdi rsi rdx
	mov	rsi, .altscr
	mov	edx, .altscrsize
	mov	rcx, [rdi]		; load up its vtable
	call	qword [rcx+epoll_vsend]
	pop	rdx rsi rdi
	mov	rcx, [rdi]
	call	qword [rcx+epoll_vsend]
	epilog
dalign
.altscr	db 27,'[?1049h'
.altscrsize = $ - .altscr
end if
if defined terminal_ansidebug
dalign
.debug_fname:
	db 'terminal.ansi',0
end if

end if

if used tui_terminal$nvonesidedied | defined include_everything
	; two arguments: tui_terminal object in rdi, epoll object (either stdin or stdout) in rsi
falign
tui_terminal$nvonesidedied:
	prolog	tui_terminal$nvonesidedied
	xor	edx, edx
	cmp	rsi, [rdi+tui_stdin_ofs]
	jne	.notstdin
	mov	[rdi+tui_stdin_ofs], rdx	; clear it
	epilog
calign
.notstdin:
	cmp	rsi, [rdi+tui_stdout_ofs]
	jne	.notstdout
	mov	[rdi+tui_stdout_ofs], rdx	; clear it
	epilog
calign
.notstdout:
	; this should not ever happen... sanity check, we'll breakpoint it
	breakpoint
	epilog
end if

if used tui_terminal$nvstdin | defined include_everything
	; two arguments: tui_terminal object in rdi, input buffer (accumulating) in rsi
falign
tui_terminal$nvstdin:
	prolog	tui_terminal$nvstdin
	; Burning Purpose: we have to parse for UTF8 sequences, escape sequences, and other "normal" characters
	; firing tui_object style keyboard events as we go
	push	r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, [rsi+buffer_itself_ofs]
	mov	r14, [rsi+buffer_endptr_ofs]
	mov	r15, rsi
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
	mov	rdx, r14		; the end of our buffer
	sub	rdx, r13		; where we are now
	cmp	rdx, 3
	jl	.normalchar		; wait for more data if there isn't enough sitting here for us
	movzx	edx, byte [r13+1]	; next char has to be [ or O
	cmp	edx, '['
	je	.escbracket
	cmp	edx, 'O'
	je	.escoh
	; else, send it out as a normal key
calign
.normalchar:
	; fire the key in ecx
	mov	rdi, r12		; our tui_terminal object
	mov	esi, ecx		; our key
	xor	edx, edx		; our esc_key
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	; swallow three characters and keep going
	add	r13, 1
	jmp	.loop
calign
.fireescaped:
	; fire the escape key in ecx
	mov	rdi, r12		; our tui_terminal object
	xor	esi, esi		; our key
	mov	edx, ecx		; our esc_key
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	; swallow one char and keep going
	add	r13, 1
	jmp	.loop
calign
.escbracket:
	; ESC [ received
	add	r13, 2			; skip ESC [
	movzx	ecx, byte [r13]
	cmp	ecx, 'A'
	je	.fireescaped
	cmp	ecx, 'B'
	je	.fireescaped
	cmp	ecx, 'C'
	je	.fireescaped
	cmp	ecx, 'D'
	je	.fireescaped
	; otherwise, go forward til we run out of room or til we hit a ~, shl by 8 each one we get
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
	jmp	.fireescaped		; this could make r13 go one past the end, quite alright
calign
.escoh:
	; ESC O received
	shl	ecx, 8			; 'O' << 8
	movzx	eax, byte [r13+1]
	or	ecx, eax		; | next byte
	add	r13, 2
	jmp	.fireescaped
calign
.unichar:
	; upper 4 bits of the byte in al were >= 12
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
	mov	rdx, r14		; the end of our buffer
	sub	rdx, r13		; where we are now
	cmp	rdx, 2
	jl	.alldone		; wait for more data if there isn't enough sitting here for us
	movzx	edx, byte [r13+1]	; get the next char
	mov	r8d, edx		; save it
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
	mov	rdi, r12		; our tui_terminal object
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
	jl	.alldone		; wait for more data if there isn't enough sitting here for us
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
	mov	rdi, r12		; our tui_terminal object
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
	jl	.alldone		; wait for more data if there isn't enough sitting here for us
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
	mov	rdi, r12		; our tui_terminal object
	mov	esi, r9d		; our key
	xor	edx, edx		; our esc_key
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+tui_vfirekeyevent]
	; swallow four characters and keep going
	add	r13, 4
	jmp	.loop
calign
.alldone:
	mov	rsi, r13
	sub	rsi, qword [r15+buffer_itself_ofs]
	cmp	rsi, 0
	jle	.nodata
	mov	rdi, r15
	call	buffer$consume
calign
.nodata:
	pop	r15 r14 r13 r12
	epilog
end if
