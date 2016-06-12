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
	; hnwatch.asm: HackerNews realtime API terminal-based watcher/reader
	;

include '../ht_defaults.inc'
include '../ht.inc'

include 'hnmodel.inc'
include 'ui.inc'

	; a global to set the limit on how many main page items we'll retrieve/watch
globals
{
	main_item_limit	dq	150
}


falign
statusupdate:
	prolog	statusupdate
	mov	rdi, rsi
	call	string$to_stdoutln
	epilog

public _start
falign
_start:
	call	ht$init

	; fireup our hnmodel to commence data retrieval
	; default to topstories
	mov	rdi, .topstories
	mov	qword [navstring], .topstories
	call	hnmodel$init

	; fire up our ui:
	call	ui$init
	
	; release control to epoll (indefinitely)
	call	epoll$run
cleartext .topstories, 'topstories'

include '../ht_data.inc'
