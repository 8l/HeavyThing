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
	; dh_groups.inc: g values for the various dh_pool goods
	; see dh_pool.inc for commentary
	;

if used dhg2 | defined include_everything

dalign
dhg2:
	dq	2, .data, 0, 0
align 16
.data:	dq	0x2, 0x0

end if

if used dhg3 | defined include_everything

dalign
dhg3:
	dq	2, .data, 0, 0
align 16
.data:	dq	0x3, 0x0

end if
