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
	;       sha256.asm: Simple SHA256 example
	;
	; first things first, include the library defaults, and the
	; library main include:
include '../../ht_defaults.inc'
include '../../ht.inc'

public _start
_start:
	; every HeavyThing program needs to start with a call to initialise it
	call	ht$init

	; first things first, get our filename to process
	cmp	dword [argc], 1
	jbe	.usage

	mov	rdi, [argv]
	call	list$pop_back
	; despite us "leaking" the filename, we are a single-pass only so we don't mind:
	; pass that straight to our privmapped object
	mov	rdi, rax
	xor	esi, esi
	call	privmapped$new
	test	rax, rax
	jz	.badinputfile
	; otherwise, we now have a private mmap of our input
	mov	rbx, rax

	; fire up a new sha256 context
	call	sha256$new
	mov	r12, rax

	; update it with our entire file
	mov	rdi, rax
	mov	rsi, [rbx+privmapped_base_ofs]
	mov	rdx, [rbx+privmapped_size_ofs]
	call	sha256$update

	; make room for our final hash
	sub	rsp, 32
	; get the final hash
	mov	rdi, r12
	mov	rsi, rsp
	; sha256$final will optionally destroy the context for us:
	mov	edx, 1
	call	sha256$final

	; turn our final hash into a string
	mov	rdi, rsp
	mov	esi, 32
	call	string$from_bintohex
	; dump that to stdout
	mov	rdi, rax
	call	string$to_stdoutln

	; done, dusted.
	mov	eax, syscall_exit
	xor	edi, edi
	syscall
calign
.usage:
	mov	rdi, .argrequired
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .argrequired, 'input filename required.'
calign
.badinputfile:
	mov	rdi, .badinput
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .badinput, 'unable to open input file'

	; include the global data segment:
include '../../ht_data.inc'
