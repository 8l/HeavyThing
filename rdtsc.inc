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
	; rdtsc.inc: rdtsc macro (not function on purpose)
	;
	; This file is a slightly modified version of rdtsc64.asm by Agner Fog from
	; his excellent randoma/asmlib libraries.
        ;
        ; Cheers for this Agner; All Hail Agner!
        ;
	; Agner's rdtsc64.asm copyright appears below:
	;*************************  rdtsc64.asm  *********************************
	; Author:           Agner Fog
	; Date created:     
	; Last modified:    2008-12-03
	; Source URL:       www.agner.org/optimize
	; Project:          asmlib.zip
	; Description:
	; This function returns the value of the time stamp counter, which counts 
	; clock cycles. To count how many clock cycles a piece of code takes, call
	; Rdtsc before and after the code to measure and calculate the difference.
	;
	; Copyright (c) 2003-2008 GNU General Public License www.gnu.org/licenses
	;******************************************************************************



	; dumps rdtsc into rax
	; NOTE: subtract 731 (Core2 time for this func itself)
	; hmm, this macro only takes ~310 or so on my core i7
	; smashes rax, rdx
	;
macro readtsc {
	push	rbx rcx			; ebx/ecx smashed by cpuid
	xor	eax, eax
        cpuid                          ; serialize
        rdtsc                          ; read time stamp counter into edx:eax
        shl     rdx, 32
        or      rax, rdx               ; combine into 64 bit register
        push    rax
	xor	eax, eax
        cpuid                          ; serialize
	pop	rax rcx rbx
}
