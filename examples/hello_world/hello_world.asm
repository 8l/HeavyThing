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
	; first things first, include the library defaults, and the
	; library main include:
include '../../ht_defaults.inc'
include '../../ht.inc'

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	mov	rdi, .helloworld
	call	string$to_stdoutln
	mov	eax, syscall_exit
	xor	edi, edi
	syscall

cleartext .helloworld, 'Hello World'

	; include the global data segment:
include '../../ht_data.inc'

