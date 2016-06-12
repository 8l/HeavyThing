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
	; sysinfo.inc: /proc/* parsing, *blech*
	;
	; glibc appears to do its own fine /proc/* parsing as well
	; this is certainly NOT cheap, lame that there isn't
	; syscalls to get more info about our environment
	;

if used sysinfo$cpucount | defined include_everything
	; no arguments, parses /proc/cpuinfo
	; returns the # of instances of vendor_id that exist in it, works on all of my various gear, YMMV
falign
sysinfo$cpucount:
	prolog	sysinfo$cpucount
	push	rbx r12 r13
	mov	rdi, .fname
	call	file$proc_cstr
	mov	rbx, rax
	xor	r12d, r12d
	xor	r13d, r13d
calign
.loop:
	mov	rdi, rbx
	mov	rsi, .searchstr
	mov	edx, r12d
	call	string$indexof_ofs
	cmp	rax, -1
	je	.return
	add	r13d, 1
	mov	r12, rax
	add	r12, qword [.searchstr]
	jmp	.loop
calign
.return:
	mov	rdi, rbx
	call	heap$free
	mov	eax, r13d
	pop	r13 r12 rbx
	epilog
dalign
.fname db '/proc/cpuinfo',0
cleartext .searchstr, 'vendor_id'
end if
