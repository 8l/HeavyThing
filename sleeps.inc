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
	; sleeps.inc: convenience macros to wrap the nanosleep syscall
	;
macro sleep tt {
	sub	rsp, 16
	mov	qword [rsp], tt
	mov	qword [rsp+8], 0
	mov	rdi, rsp
	xor	esi, esi
	mov	eax, syscall_nanosleep
	syscall
	add	rsp, 16
}

macro usleep tt {
	sub	rsp, 16
	mov	qword [rsp], 0
	mov	qword [rsp+8], tt * 1000
	mov	rdi, rsp
	xor	esi, esi
	mov	eax, syscall_nanosleep
	syscall
	add	rsp, 16
}

macro nanosleep tt {
	sub	rsp, 16
	mov	qword [rsp], 0
	mov	qword [rsp+8], tt
	mov	rdi, rsp
	xor	esi, esi
	mov	eax, syscall_nanosleep
	syscall
	add	rsp, 16
}
