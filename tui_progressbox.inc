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
	; tui_progressbox.inc: a tui_panel wrapper that includes a title, message, and a progressbar
	; 
	; similar to tui_progressbox (and largely a cut-paste), simple goods to provide a dialog box with a progressbar
	;

if used tui_progressbox$new | defined include_everything
	; tui_panel has a user variable that it doesn't itself use, we populate that with our tui_progressbar for later reference

	; five arguments: rdi == string title, rsi == string message (multiline okay), edx == panel/title colors, ecx == progress colors, r8d == progress fill colors
falign
tui_progressbox$new:
	prolog	tui_progressbox$new
	; this is largely copied from tui_alert for layout calcs, etc
	sub	rsp, 80
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx
	mov	[rsp+32], r8
	; calculate the dimensions we need for our panel
	; even though it is inefficient, we split the message first so we can determine
	; the longest line (inefficient insofar as tui_label will split it again)
	mov	rdi, rsi
	mov	esi, 10
	call	string$split
	mov	[rsp+48], rax
	mov	qword [rsp+56], 0
	mov	rdi, rax
	mov	rsi, .linelength
	lea	rdx, [rsp+56]
	call	list$foreach_arg
	mov	rdi, [rsp]
	; start with min 32
	mov	r10d, 32
	; titlelen + 6 bigger?
	mov	r11, [rdi]
	add	r11d, 6
	cmp	r11d, r10d
	cmova	r10d, r11d
	; linelen(max) + 6 bigger?
	mov	r11d, [rsp+56]
	add	r11d, 6
	cmp	r11d, r10d
	cmova	r10d, r11d
	; width is complete
	mov	[rsp+64], r10d
	; height is next
	mov	rax, [rsp+48]
	mov	edx, [rax+_list_size_ofs]
	mov	ecx, edx
	; add	ecx, 1
	cmp	edx, 1
	cmova	edx, ecx
	add	edx, 6
	mov	[rsp+68], edx
	; get rid of our list
	mov	rdi, rax
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free
	; we can construct our panel now
	mov	edi, [rsp+64]		; width
	mov	esi, [rsp+68]		; height
	mov	rdx, [rsp]		; title
	mov	ecx, [rsp+16]		; boxcolors
	mov	r8d, [rsp+16]		; titlecolors
	call	tui_panel$new_ii
	; also, we'd like a dropshadow under our panel
	mov	dword [rax+tui_dropshadow_ofs], 1
	mov	[rsp+56], rax		; our end return object
	; prepend our message with a linefeed so it ends up padded properly:
	mov	rdi, .lfstr
	mov	rsi, [rsp+8]
	call	string$concat
	mov	[rsp+64], rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	mov	rdi, rax		; filltext
	mov	esi, [rsp+16]		; colors
	mov	edx, tui_textalign_center
	call	tui_label$new_dd
	; add that as a child to our panel
	mov	rdi, [rsp+56]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; free our filltext
	mov	rdi, [rsp+64]
	call	heap$free
	; next up, we need a 100% wide by 2 height vbox to hold our progressbar
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$simple_vtable
	mov	[rsp+64], rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 2
	call	tui_object$init_di
	mov	rdi, [rsp+64]
	mov	dword [rdi+tui_horizalign_ofs], tui_align_center
	; add that to our panel
	mov	rsi, rdi
	mov	rdi, [rsp+56]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; finally, do up our progressbar
	; the width of our text == panel width - 4
	mov	r8, [rsp+56]
	mov	edi, [r8+tui_width_ofs]
	mov	esi, 1			; height
	sub	edi, 4			; width
	mov	edx, 0			; direction
	mov	ecx, [rsp+24]		; empty colors
	mov	r8d, [rsp+32]		; fillcolors
	call	tui_progressbar$new_ii
	; add it to our box
	mov	rcx, [rsp+56]
	mov	rdi, [rsp+64]
	mov	rsi, rax
	mov	rdx, [rdi]
	mov	[rcx+tui_panel_user_ofs], rax
	call	qword [rdx+tui_vappendchild]
	mov	rax, [rsp+56]
	add	rsp, 80
	epilog
cleartext .lfstr, 10
falign
.linelength:
	; called for each string line in the message, rdi == string, rsi == pointer to update with our length
	mov	edx, [rdi]
	mov	ecx, [rsi]
	cmp	edx, ecx
	cmova	ecx, edx
	mov	[rsi], ecx
	ret

end if


if used tui_progressbox$nvlimits | defined include_everything
	; three arguments: rdi == our tui_progressbox, rsi == min, rdx == max
falign
tui_progressbox$nvlimits:
	prolog	tui_progressbox$nvlimits
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_progressbar$nvlimits
	epilog

end if

if used tui_progressbox$nvlimitsd | defined include_everything
	; three arguments: rdi == our tui_progressbox, xmm0 == min, xmm1 == max
falign
tui_progressbox$nvlimitsd:
	prolog	tui_progressbox$nvlimitsd
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_progressbar$nvlimitsd
	epilog

end if

if used tui_progressbox$nvupdate | defined include_everything
	; two arguments: rdi == our tui_progressbox, rsi == cur
falign
tui_progressbox$nvupdate:
	prolog	tui_progressbox$nvupdate
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_progressbar$nvupdate
	epilog

end if

if used tui_progressbox$nvupdated | defined include_everything
	; two arguments: rdi == our tui_progressbox, xmm0 == cur
falign
tui_progressbox$nvupdated:
	prolog	tui_progressbox$nvupdated
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_progressbar$nvupdated
	epilog

end if

if used tui_progressbox$nvgetperc | defined include_everything
	; single argument rdi: our tui_progressbox
	; returns the current percentage in xmm0 (as a normal decimal, 50% == 0.5)
falign
tui_progressbox$nvgetperc:
	prolog	tui_progressbox$nvgetperc
	mov	rdi, [rdi+tui_panel_user_ofs]
	call	tui_progressbar$nvgetperc
	epilog

end if
