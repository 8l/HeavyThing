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
	;       tuimatrix.asm: TUI Matrix Demo
	;
	; As noted on our https://2ton.com.au/HeavyThing/ page, as well as in
	; the comments of tui_matrix.inc itself, this is _not_ nice to terminal
	; programs.
	;
	; The wikipedia article says half-width kana AND latin alphanumerics, but
	; if we do that, Mac OS X Terminal.app doesn't display it correctly at all
	; and everyone else grinds to a near halt. We only use half-width kana,
	; which is 63 characters starting at 0xff61, but it is still very nasty.
	; gnome-terminal seems to cope with this okay though, YMMV.
	;
	; CAUTION IS THEREFORE ADVISED: you may have to kill your own terminal
	; program, hahah.
	;
	; See the full commentary in tui_matrix.inc anyway.
	;
	; first things first, include the library defaults, and the
	; library main include:
include '../../ht_defaults.inc'
include '../../ht.inc'

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	; the HeavyThing's tui_matrix object is a 100% x 100% tui_object and
	; doesn't require any arguments:
	call	tui_matrix$new

	; tui_terminal just needs an only child to include, so pass that
	; straight to it, noting that tui_terminal$new automatically adds itself
	; to the epoll layer
	mov	rdi, rax
	call	tui_terminal$new

	; all thats left is to pass control on to the epoll layer
	call	epoll$run
	; epoll$run does not return.

	; include the global data segment:
include '../../ht_data.inc'

