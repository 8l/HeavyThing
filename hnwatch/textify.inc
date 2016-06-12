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
	; textify.inc: since the "text" field of HackerNews' API returns us with HTML
	; and I haven't yet bothered to transcode my XML/XHTML parsers into the
	; HeavyThing library, the function contained herein is just my "brute force,
	; beat it with a hammer" HTML stripper so that the comment viewing page
	; looks a little more sane than otherwise. Only the most common cases are
	; dealt with in here, and it is suitable for my viewing tastes, haha, YMMV.
	;

	; single argument in rdi: a "text" string value as returned by the API
	; returns a new string stripped of the most common HTML goods.
	; NOTE: this is _not_ an efficient way to do this, but since it isn't
	; getting called a zillion times per second, lazy works ok here.
falign
textify:
	prolog	textify
	push	rbx r12 r13 r14
	; step one: turn <p> into \n
	mov	rsi, .p
	mov	rdx, .lf
	call	string$replace
	mov	rbx, rax
	
	; step two: remove &#xXX; entities
calign
.entities:
	mov	rdi, rbx
	mov	rsi, .xent
	call	string$indexof
	cmp	rax, -1
	je	.stepthree
	mov	r12d, eax
	mov	rdi, rbx
	lea	esi, [eax+3]
	mov	edx, 2
	call	string$substr
	mov	r13, rax
	mov	rdi, r13
	call	string$to_lower_inplace
	mov	rdi, r13
	sub	rsp, 8
	mov	rsi, rsp
	call	string$hexdecode
	; byte at rsi is the one we are after
	mov	rdi, r13
	call	heap$free
	mov	rdi, rsp
	mov	esi, 1
	call	string$from_utf8
	add	rsp, 8
	mov	r13, rax
	; now we can construct the whole subsequence
	mov	rdi, rbx
	mov	esi, r12d
	mov	edx, 6
	call	string$substr
	mov	r14, rax
	mov	rdi, rbx
	mov	rsi, rax
	mov	rdx, r13
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	call	heap$free
	jmp	.entities

.stepthree:
	; remove <code><pre>, <pre><code> and </code></pre>
	mov	rdi, rbx
	mov	rsi, .codepre
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free

	mov	rdi, rbx
	mov	rsi, .precode
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
	
	mov	rdi, rbx
	mov	rsi, .endcodepre
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
	
	; step four, remove common lt/gt/amp/quot
	mov	rdi, rbx
	mov	rsi, .lt
	mov	rdx, .lessthan
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free

	mov	rdi, rbx
	mov	rsi, .gt
	mov	rdx, .greaterthan
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free

	mov	rdi, rbx
	mov	rsi, .amp
	mov	rdx, .ampersand
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free

	mov	rdi, rbx
	mov	rsi, .quot
	mov	rdx, .quotmark
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free

	; step 5: deal with <a href... as best as we can so that cmd-click in my Terminal.app
	; lets me click them
calign
.ahrefs:
	mov	rdi, rbx
	mov	rsi, .ahref
	call	string$indexof
	cmp	rax, -1
	je	.nohrefs
	mov	r12d, eax
	mov	rdi, rbx
	mov	rsi, .quotmark
	lea	edx, [r12d+10]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.nohrefs	; bailout if it is jacked up (e.g. leave this and all that follow alone)
	mov	rdi, rbx
	lea	esi, [r12d+9]
	mov	edx, eax
	call	string$substring
	mov	r14, rax	; the url itself, now we need to strip the entire <a href... </a>
	mov	rdi, rbx
	mov	rsi, .ahrefclose
	lea	edx, [r12d+10]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.nohrefs_free	; bailout
	mov	rdi, rbx
	mov	esi, r12d
	lea	edx, [eax+4]
	call	string$substring
	mov	r13, rax
	
	mov	rdi, rbx
	mov	rsi, r13
	mov	rdx, r14
	call	string$replace
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free

	mov	rdi, r13
	call	heap$free
	mov	rdi, r14
	call	heap$free
	jmp	.ahrefs
	
.nohrefs_free:
	mov	rdi, r14
	call	heap$free
.nohrefs:

	mov	rax, rbx
	pop	r14 r13 r12 rbx
	epilog
cleartext .p, '<p>'
cleartext .lf, 10
cleartext .xent, '&#x'
cleartext .emptystr, ''
cleartext .codepre, '<code><pre>'
cleartext .precode, '<pre><code>'
cleartext .endcodepre, '</code></pre>'
cleartext .lt, '&lt;'
cleartext .gt, '&gt;'
cleartext .amp, '&amp;'
cleartext .quot, '&quot;'
cleartext .lessthan, '<'
cleartext .greaterthan, '>'
cleartext .ampersand, '&'
cleartext .quotmark, '"'
cleartext .ahref, '<a href="'
cleartext .ahrefclose, '</a>'
