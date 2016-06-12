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
	; cleartext.inc: static string encoding macros
	;

	; ok, for UTF32, this is messy, because fasm won't let me make a string of latin1 as 32bits, only db and du
	;
	; thanks to revolution & l_inc @board.flatassembler.net for helping me pull my head out with this
	; sometimes the simple solutions are the most elusive.


macro cleartext name*, [val*] {
common
if string_bits = 32
	local .DAT,CC,I,Si,J
	dalign
	name:
	dq	CC
	.DAT:
	db	val
	CC = ($ - .DAT)
	; create filler for the diff
	db ((CC shl 2) - CC) dup 0
	; next up: walk backward through the string and promote it to 32bits
	I = CC - 1
	J = I shl 2
	repeat CC
		load Si byte from .DAT+I
		store dword Si at .DAT+J
		I = I - 1
		J = J - 4
	end repeat
else
        local AA,BB
        dalign
        name:
        dq      AA
        du      val
        BB = ($ - name - 8)
        AA = BB shr 1
end if
}
