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
	; call.inc: a macro to wrap call such that we can optionally align returns
	;

macro call target* {
if align_callreturns
	local ..c, ..r, a
	virtual
		align 16
		a = $ - $$
	end virtual
	a = a - (..r - ..c)
	; a can be negative as well as positive
	if a = 15 | a = -1
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
		db 0x66, 0xf, 0x1f, 0x44, 0x00, 0x00
	else if a = 14 | a = -2
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
		db 0xf, 0x1f, 0x44, 0x00, 0x00
	else if a = 13 | a = -3
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
		db 0xf, 0x1f, 0x40, 0x00
	else if a = 12 | a = -4
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
		db 0xf, 0x1f, 0x00
	else if a = 11 | a = -5
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
		db 0x66, 0x90
	else if a = 10 | a = -6
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
		db 0x90
	else if a = 9 | a = -7
		db 0x66, 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
	else if a = 8 | a = -8
		db 0xf, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
	else if a = 7 | a = -9
		db 0xf, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00
	else if a = 6 | a = -10
		db 0x66, 0xf, 0x1f, 0x44, 0x00, 0x00
	else if a = 5 | a = -11
		db 0xf, 0x1f, 0x44, 0x00, 0x00
	else if a = 4 | a = -12
		db 0xf, 0x1f, 0x40, 0x00
	else if a = 3 | a = -13
		db 0xf, 0x1f, 0x00
	else if a = 2 | a = -15
		db 0x66, 0x90
	else if a = 1
		db 0x90
	end if
..c:	call	target
..r:
else if align_returns
	local	..c
	push	..c
	jmp	target
	calign
	..c:
else
	call	target
end if
}
