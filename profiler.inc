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
	; profiler.inc: automatic callgraph/profiling goods
	;
	; SOME NOTES HERE:
	;
	; This isn't 100% accurate of course... but does provide excellent per-cycle
	; function timings and of course the actual callgraph itself.
	;
	; In other words, if this profiler says something takes X clock cycles
	; some of those clocks are still buried in the unpleasantness in profiler itself
	; and while measures were taken to reduce the exponential nesting results of this
	; profiling a single line function does not equal <10 clock cycles... a quick
	; look at how the profiling function enter/leave macros looks is sufficient to
	; understand why this is, hahaha
	;
	; that being said: for optimization efforts, this does precisely what I wanted it
	; to, and provides clock timing quite suitable for optimization efforts.
	;
	; finer-grained-than-this requires a bit more custom efforts.
	;
	; ALSO NOTE: profiler$init does some precomputing for delta timing, and tries
	; to wakeup the power management goods PRIOR to doing so.
	; this of course comes at a penalty that you'll see in the profiler output of ht$init
	; 
	; if you are on some crazy-fast machine, or if this annoys you, play with the values
	; in profile$init to adjust its delta timing and how much effort is spent doing so
	;
	; TODO: with profiling enabled, it would also be trivial to use the profiler
	; state tables to generate named-function stack traces at any given time.
	; might be useful to toss in.
	; 
	;


macro prolog name {
	local .function_name,.function_start,.function_namelen
	if public_funcs
		public name
	end if
        if framepointers
                push rbp
                mov rbp, rsp
        end if
        if profiling
                jmp     .function_start
                cleartext .function_name, `name
		calign
                .function_start:
                ; important for obvious reasons that we preserve _all_ registers
                push    rax rcx rdx rdi rsi r8 r9 r10 r11
                mov     rdi, .function_name
                call    profiler$enter                  ; single arg rdi == function name
                pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
	else if calltracing
                jmp     .function_start
		.function_name:
		db	'calltrace: '
		db	`name
		db	10
		.function_namelen = $ - .function_name
		calign
                .function_start:
                ; important for obvious reasons that we preserve _all_ registers
                push    rax rcx rdx rdi rsi r8 r9 r10 r11
		mov	eax, syscall_write
		mov	edi, 1
		mov	rsi, .function_name
		mov	edx, .function_namelen
		syscall
                pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
        end if
}

macro prolog_noprofile name {
	if public_funcs
		public name
	end if
	if framepointers
		push	rbp
		mov	rbp, rsp
	end if
}

macro prolog_noprofile_silent name {
	if framepointers
		push	rbp
		mov	rbp, rsp
	end if
}

macro prolog_silent name {
	local .function_name,.function_start
        if framepointers
                push rbp
                mov rbp, rsp
        end if
        if profiling
                jmp     .function_start
                cleartext .function_name, `name
		calign
                .function_start:
                ; important for obvious reasons that we preserve _all_ registers
                push    rax rcx rdx rdi rsi r8 r9 r10 r11
                mov     rdi, .function_name
                call    profiler$enter                  ; single arg rdi == function name rc4 offset into code
                pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
        end if
}

macro epilog {
        if profiling
                ; important for obvious reasons that we preserve _all_ registers
                push    rax rcx rdx rdi rsi r8 r9 r10 r11
                call    profiler$leave
                pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
        end if
        if framepointers
                leave
        end if
        ret
}

; these two inner-ones are useful for profiling individual codesections inside a function
; such that new framepointers and return are not necessary, but that entries aka calls
; can be tracked as well as cycle counts
; CARE MUST BE TAKEN to make sure these stay 1:1 (or the callgraph and everything gets all jacked up)
macro prolog_inner name {
	local .function_name,.function_start
        if profiling
                jmp     .function_start
                cleartext .function_name, `name
		calign
                .function_start:
                ; important for obvious reasons that we preserve _all_ registers
                push    rax rcx rdx rdi rsi r8 r9 r10 r11
                mov     rdi, .function_name
                call    profiler$enter                  ; single arg rdi == function name rc4 offset into code
                pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
        end if
}

macro epilog_inner {
        if profiling
                ; important for obvious reasons that we preserve _all_ registers
                push    rax rcx rdx rdi rsi r8 r9 r10 r11
                call    profiler$leave
                pop     r11 r10 r9 r8 rsi rdi rdx rcx rax
        end if
}

macro epilog_noprofile {
	if framepointers
		leave
	end if
	ret
}

if profiling

globals
{
	_profiler_tscaccum	dq	0
	_profiler_deltamod	dq	0
	_profiler_last_tsc	dq	0
	_profiler_current	dq	0
	_profiler_block_free	dq	0
	_profiler_block		dq	0
}

falign
public profiler$init
profiler$init:
	; burning purpose: compute our _profiler_deltamod


	; NOTE: we need to sit and spin for 20us or so to kick the cpu power management up before we start our timing

	; ALSO: without this pmloop init here, what can happen is that power management upscales our process, and thus
	; what we start out as for timing information turns out to be incorrect, and we can get negative CPC results
	; in the profiler output.

	xor	eax, eax
	mov	ecx, 320000000
calign
.pmloop:
	xor	eax, ecx
	add	eax, ecx
	sub	ecx, 1
	jnz	.pmloop

	readtsc
	mov	[_profiler_last_tsc], rax
	mov	ecx, 1000000
calign
.loop:
	readtsc
	sub	ecx, 1
	jnz	.loop
	; rax has our most recent result
	sub	rax, qword [_profiler_last_tsc]
	; rax now has how long it took to do a bunch of readtscs....
	mov	ecx, 1000000
	xor	edx, edx
	div	rcx
	mov	[_profiler_deltamod], rax
	ret


; if attempting to clear the profiler from inside a child process, this causes the slate to be wiped clean
; (noting that we toss (leak) the previous profiler mmap segment)
falign
public profiler$reset
profiler$reset:
	mov	qword [_profiler_current], 0
	ret



	; single argument, rdi == function name
falign
public profiler$enter
profiler$enter:
	mov	rcx, [_profiler_current]
	test	rcx, rcx
	jz	.virgin
	readtsc
	mov	rdx, [_profiler_deltamod]
	mov	r9, [_profiler_tscaccum]
	add	r9, rdx
	mov	[_profiler_tscaccum], r9
	sub	rax, r9
	mov	r8, rax
	sub	rax, qword [_profiler_last_tsc]
	mov	[_profiler_last_tsc], r8
	; rax has the delta, we need to add this to our current item before we make a new current
	add	qword [_profiler_rcx_cycles], rax
	cmp	qword [_profiler_rcx_children], 0
	jz	.newchild
	mov	r10, rcx	; save for linking back to parent
	mov	rcx, [_profiler_rcx_children]
calign
.searchloop:
	mov	r9, [_profiler_rcx_name]
	cmp	[_profiler_rcx_name], rdi
	je	.foundit
	mov	r9, rcx				; save our prev pointer
	mov	rcx, [_profiler_rcx_next]	; move to next one
	test	rcx, rcx
	jnz	.searchloop
	; addchild:
	mov	r8, [_profiler_block_free]
	sub	r8, profiler_record_size
	cmp	r8, [_profiler_block]
	jbe	.kakked
	mov	[_profiler_block_free], r8
	mov	rcx, r9				; our prev
	; r8 is our spanking new pointer, link to rcx's next
	mov	[_profiler_rcx_next], r8
	mov	rcx, r8
	; set our goods
	mov	qword [_profiler_rcx_name], rdi
	mov	qword [_profiler_rcx_calls], 1
	mov	qword [_profiler_rcx_cycles], 0
	mov	qword [_profiler_rcx_children], 0
	mov	qword [_profiler_rcx_parent], r10
	mov	qword [_profiler_rcx_next], 0
	mov	[_profiler_current], rcx
	readtsc
	mov	rdx, [_profiler_deltamod]
	mov	r9, [_profiler_tscaccum]
	add	r9, rdx
	mov	[_profiler_tscaccum], r9
	sub	rax, r9
	mov	[_profiler_last_tsc], rax
	ret
calign
.foundit:
	; rcx matches our function name
	; set current to it, add calls
	add	qword [_profiler_rcx_calls], 1
	mov	[_profiler_current], rcx
	ret
calign
.kakked:
	mov	eax, syscall_exit
	mov	edi, 98
	syscall
calign
.newchild:
	; rcx is still loaded with the node we need to add to/set
	mov	r8, [_profiler_block_free]
	sub	r8, profiler_record_size
	cmp	r8, [_profiler_block]
	jbe	.kakked
	mov	[_profiler_block_free], r8
	; r8 is our spanking new pointer, link to rcx's children list
	mov	[_profiler_rcx_children], r8
	mov	r9, rcx				; save our parent pointer
	mov	rcx, r8
	; set our goods
	mov	qword [_profiler_rcx_name], rdi
	mov	qword [_profiler_rcx_calls], 1
	mov	qword [_profiler_rcx_cycles], 0
	mov	qword [_profiler_rcx_children], 0
	mov	qword [_profiler_rcx_parent], r9
	mov	qword [_profiler_rcx_next], 0
	mov	[_profiler_current], rcx
	readtsc
	mov	rdx, [_profiler_deltamod]
	mov	r9, [_profiler_tscaccum]
	add	r9, rdx
	mov	[_profiler_tscaccum], r9
	sub	rax, r9
	mov	[_profiler_last_tsc], rax
	ret
calign
.virgin:
	; no profiler current exists (which means by default it is our very first call, so do some setup)
	push	rdi				; save our one and only argument
	mov	eax, syscall_mmap
	xor	edi, edi
	mov	esi, profiler_record_size * profiler_recordcount
	mov	edx, 0x3
	mov	r10d, 0x22
	mov	r8, -1
	xor	r9d, r9d
	syscall
	cmp	rax, -1
	je	.kakked
	mov	[_profiler_block], rax
	add	rax, profiler_record_size * (profiler_recordcount - 1)
	mov	rcx, rax
	mov	[_profiler_current], rax	; this is our "global" record
	mov	[_profiler_block_free], rax	; this is the starting point for our next free one
	pop	rdi
	readtsc
	mov	rdx, [_profiler_deltamod]
	add	qword [_profiler_tscaccum], rdx
	sub	rax, qword [_profiler_tscaccum]
	mov	[_profiler_last_tsc], rax
	; zero our record in its entirety
	mov	qword [_profiler_rcx_name], 0
	mov	qword [_profiler_rcx_calls], 0
	mov	qword [_profiler_rcx_cycles], 0
	mov	qword [_profiler_rcx_children], 0
	mov	qword [_profiler_rcx_parent], 0
	mov	qword [_profiler_rcx_next], 0
	jmp	profiler$enter			; it will have better luck this time

	; no arguments
falign
public profiler$leave
profiler$leave:
	mov	rcx, [_profiler_current]
	readtsc
	mov	rdx, [_profiler_deltamod]
	mov	r9, [_profiler_tscaccum]
	add	r9, rdx
	mov	[_profiler_tscaccum], r9
	sub	rax, r9
	mov	r8, rax
	sub	rax, qword [_profiler_last_tsc]
	mov	qword [_profiler_last_tsc], r8
	add	qword [_profiler_rcx_cycles], rax
	mov	rcx, [_profiler_rcx_parent]
	mov	[_profiler_current], rcx
	ret

profiler_record_size = 48

virtual at rcx
	_profiler_rcx_name dq ?
	_profiler_rcx_calls dq ?
	_profiler_rcx_cycles dq ?
	_profiler_rcx_children dq ?
	_profiler_rcx_parent dq ?
	_profiler_rcx_next dq ?
end virtual


if used profiler$to_json | defined include_everything
	; no arguments
	; returns current profiler data as a new json OBJECT... with two children:
	; profiler, a json ARRAY (array of object, suitable for dumping into a tui_datagrid)
	; callgraph, a json ARRAY, same
falign
profiler$to_json:
	prolog	profiler$to_json	; yes, we profile ourself
	; save all our callee-save goods
	push	rbx r12 r13 r14 r15

	; we need a copy of the information table (so that it doesn't change in flight while we are doing our thing)
	mov	rdi, [_profiler_block]
	add	rdi, profiler_record_size * profiler_recordcount
	sub	rdi, qword [_profiler_block_free]
	; this call to heap$alloc will likely use another spot in our profiler table
	add	rdi, profiler_record_size * 2
	call	heap$alloc
	mov	r11, [_profiler_block]
	add	r11, profiler_record_size * profiler_recordcount	; the end
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, [_profiler_block_free]
calign
.copyloop:
	mov	rcx, [rsi]
	add	rsi, 8
	mov	[rdi], rcx
	add	rdi, 8
	cmp	rsi, r11
	jb	.copyloop

	; so now we have a copy of the relevant goods in rbx
	; in order to get our per function based totals, we need to iterate the blocks in rbx
	; stop when name == 0, add function name itself to a unique unsignedmap
	; and then iterate that list to generate our per cycle list
	; (cuz there will likely be duplicate same-func names in the list and we are not generating a callgraph yet)
	xor	edi, edi	; sort order
	call	unsignedmap$new
	mov	r12, rax

	mov	rcx, rbx
calign
.functionload:
	mov	rdi, r12
	mov	rsi, [_profiler_rcx_name]
	push	rcx
	call	unsignedmap$insert_unique
	pop	rcx
	add	rcx, 48
	cmp	[_profiler_rcx_name], 0
	jne	.functionload
	; ok so now our unsignedmap in r12 is full of our unique function names
	; now we want to iterate through those, and create a second map with cycle counts
	xor	edi, edi	; sort order
	call	unsignedmap$new
	mov	r13, rax
	mov	rax, [r12+_avlofs_next]
	; we know that there is valid functions, so we don't have to check the first one for null
calign
.cycleload:
	mov	rdi, [rax+_avlofs_key]
	call	.gettotals_for_function
	; so at this point, rax still has our node, rdi has our function index, rdx has our total cycle count
	mov	rsi, rdx	; cycle count is our key
	mov	rdx, rdi	; value is our function index
	mov	rdi, r13
	push	rax
	call	unsignedmap$insert	; duplicates fine by me
	pop	rax
	mov	rax, [rax+_avlofs_next]
	test	rax, rax
	jnz	.cycleload

	; we can safely destroy our map in r12, and reuse the spot for our json array
	mov	rdi, r12
	xor	esi, esi	; no clear function
	call	unsignedmap$clear
	mov	rdi, r12
	call	heap$free
	; now, create a new json array called profiler
	
	mov	rdi, .profilerstr
	call	json$newarray
	mov	r12, rax

	; so now our unsignedmap in r13 has our by-cycle count, go through it backwards
	; we need to tally up the total cycles for all of our program
	xor	r9d, r9d	; accum them here
	mov	rax, [r13+_avlofs_prev]
calign
.gettotalcycles:
	add	r9, [rax+_avlofs_key]
	mov	rax, [rax+_avlofs_prev]
	test	rax, rax
	jnz	.gettotalcycles

	mov	rax, [r13+_avlofs_prev]
calign
.populatecycles:
	mov	rdi, [rax+_avlofs_value]	; function index
	call	.gettotals_for_function		; even though we have cycles, we still need call count
	mov	rsi, rdx
	mov	rdx, r8				; so now, rdi == function, rsi == cycles, rdx == calls, r9 == total cycles
	call	.add_profiler_function
	mov	rax, [rax+_avlofs_prev]
	test	rax, rax
	jnz	.populatecycles

	; we are no longer interested in our map in r13
	mov	rdi, r13
	xor	esi, esi	; no clear function
	call	unsignedmap$clear
	mov	rdi, r13
	call	heap$free

	; we need a new callgraph json array
	mov	rdi, .callgraphstr
	call	json$newarray
	mov	r13, rax


	; ok so, if we use our COPY in rbx, due to all of our own functions calls, it is no longer valid
	; so, we have to make use of the "live" one (cough)
	mov	rcx, [_profiler_block]
	add	rcx, profiler_record_size * (profiler_recordcount-1)	; the "list node" (master root), of which its children list has the goods

	mov	rcx, [_profiler_rcx_children]
	; now, all we have to do is iterate through this list
calign
.graphloop:
	push	rcx
	mov	rdi, rcx	; first arg: the profiler block
	xor	esi, esi	; second arg: the nest level
	call	.add_individual_callgraph
	pop	rcx
	mov	rcx, [_profiler_rcx_next]
	test	rcx, rcx
	jnz	.graphloop

	mov	rdi, rbx
	call	heap$free

	; construct our unnamed object return
	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy

	mov	r14, rax
	mov	rdi, rax
	mov	rsi, r12
	call	json$appendchild
	mov	rdi, r14
	mov	rsi, r13
	call	json$appendchild
	mov	rax, r14
	
	pop	r15 r14 r13 r12 rbx
	epilog
cleartext .profilerstr, 'profiler'
cleartext .callgraphstr, 'callgraph'
cleartext .functionstr, 'function'
cleartext .callsstr, 'calls'
cleartext .cyclesstr, 'cycles'
cleartext .cpcstr, 'cpc'
cleartext .totcyclesstr, 'totcycles'
cleartext .percstr, '%'
calign
.add_individual_callgraph:
	; rdi == pointer to our profiler block, rsi == nestlevel
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rsi

	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy
	mov	r14, rax

	mov	rdi, .functionstr
	call	string$copy
	mov	r15, rax
	
	mov	rcx, [rsp]

	mov	rdi, [_profiler_rcx_name]
	mov	rsi, [rsp+8]
	add	rsi, qword [rdi]		; width + leading spaces for padding
	mov	edx, ' '			; padchar
	call	string$lpad
	mov	rdi, r15
	mov	rsi, rax			; the value
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "function":"name" child.

	mov	rsi, [rsp+8]
	add	rsi, 1				; for the next level down
	mov	[rsp+8], rsi

	mov	rdi, .callsstr
	call	string$copy
	mov	r15, rax
	
	mov	rcx, [rsp]

	mov	rdi, [_profiler_rcx_calls]
	mov	esi, 10		; radix
	call	string$from_int
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "calls":"12345" child.
	
	mov	rdi, .cyclesstr
	call	string$copy
	mov	r15, rax
	
	mov	rcx, [rsp]
	
	mov	rdi, [_profiler_rcx_cycles]
	mov	esi, 10		; radix
	call	string$from_int
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "cycles":"12345" child.

	mov	rdi, .cpcstr
	call	string$copy
	mov	r15, rax

	mov	rcx, [rsp]
	
if cpc_integers
	mov	rax, [_profiler_rcx_cycles]
	mov	rcx, [_profiler_rcx_calls]
	div	rcx
	mov	rdi, rax
	mov	esi, 10
	call	string$from_int
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild
else
	mov	rsi, [_profiler_rcx_cycles]
	mov	rdx, [_profiler_rcx_calls]

	cvtsi2sd	xmm0, rsi
	cvtsi2sd	xmm1, rdx
	divsd	xmm0, xmm1			; cycles / calls
	mov	edi, double_string_fixed
	mov	esi, 1				; precision of 1 decimal digit should be plenty
	call	string$from_double
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "cpc":"123.456" child.
end if

	mov	rdi, .totcyclesstr
	call	string$copy
	mov	r15, rax

	mov	rdi, [rsp]
	xor	rax, rax
	call	.get_total_cycles

	mov	rdi, rax
	mov	esi, 10		; radix
	call	string$from_int
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "totcycles":"12345" child.

	; now our object in r14 is complete, add it to r13
	mov	rdi, r13
	mov	rsi, r14
	call	json$appendchild

	; now we need to "nest"
	mov	rcx, [rsp]

	mov	rcx, [_profiler_rcx_children]
	test	rcx, rcx
	jz	.individual_done
calign
.individual_loop:
	mov	[rsp], rcx
	mov	rdi, rcx
	mov	rsi, [rsp+8]
	call	.add_individual_callgraph
	mov	rcx, [rsp]
	mov	rcx, [_profiler_rcx_next]
	test	rcx, rcx
	jnz	.individual_loop
calign
.individual_done:
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	add	rsp, 16
	ret
calign
.get_total_cycles:
	; parm in rdi == our record, we need to tally up our cycle count and all our children's
	mov	rcx, rdi
	add	rax, [_profiler_rcx_cycles]
	mov	rcx, [_profiler_rcx_children]
	test	rcx, rcx
	jz	.get_total_cycles_done
calign
.get_total_cycles_loop:
	push	rcx rsi
	mov	rdi, rcx
	call	.get_total_cycles
	pop	rsi rcx
	mov	rcx, [_profiler_rcx_next]
	test	rcx, rcx
	jnz	.get_total_cycles_loop
calign
.get_total_cycles_done:
	ret
	
calign
.add_profiler_function:
	; rdi == function, rsi == cycles, rdx == calls, r9 == total cycles
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], r9
	mov	[rsp+32], rax		; we are not allowed to mash rax or r9
	
	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy
	mov	r14, rax

	mov	rdi, .functionstr
	call	string$copy
	mov	r15, rax
	mov	rdi, [rsp]
	call	string$copy
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild	; object now has a "function":"name" child

	mov	rdi, .callsstr
	call	string$copy
	mov	r15, rax
	mov	rdi, [rsp+16]
	mov	esi, 10
	call	string$from_int
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild	; object now has a "calls":"12345" child

	mov	rdi, .cyclesstr
	call	string$copy
	mov	r15, rax
	mov	rdi, [rsp+8]
	mov	esi, 10
	call	string$from_int
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild	; object nowe has a "cycles":"12345" child

	mov	rdi, .cpcstr
	call	string$copy
	mov	r15, rax

if cpc_integers
	mov	rax, [rsp+8]
	mov	rcx, [rsp+16]
	div	rcx
	mov	rdi, rax
	mov	esi, 10
	call	string$from_int
else

	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]

	cvtsi2sd	xmm0, rsi
	cvtsi2sd	xmm1, rdx
	divsd	xmm0, xmm1			; cycles / calls
	mov	edi, double_string_fixed
	mov	esi, 1				; precision of 1 decimal digit should be plenty
	call	string$from_double
end if
	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "cpc":"123.456" child.

	mov	rdi, .totcyclesstr
	call	string$copy
	mov	r15, rax

	; for the total cycles field here, we want to add a percentage of total time spent
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+24]
	cvtsi2sd	xmm0, rsi
	cvtsi2sd	xmm1, rdx
	divsd	xmm0, xmm1
	movq	xmm1, [_math_onehundred]
	mulsd	xmm0, xmm1

	mov	edi, double_string_fixed
	mov	esi, 3				; 2 decimal digits for our percentage string
	call	string$from_double

	push	rax
	mov	rdi, rax
	mov	rsi, .percstr
	call	string$concat

	mov	rdi, r15
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild		; object now has a "totcycles":"99.99%" child.

	pop	rdi
	call	heap$free			; free the first bit of our string

	; our object is complete, now we need to add our unnamed object to the array in r12
	mov	rdi, r12
	mov	rsi, r14
	call	json$appendchild
	
	; restore our vars
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	r9, [rsp+24]
	mov	rax, [rsp+32]
	add	rsp, 40
	ret

calign
.gettotals_for_function:
	; without mashing rax, populate rdx with the total number of cycles, r8 with the total number of calls
	mov	rcx, rbx
	xor	edx, edx
	xor	r8d, r8d
calign
.gffloop:
	cmp	qword [_profiler_rcx_name], rdi
	jne	.gffnext
	add	rdx, qword [_profiler_rcx_cycles]
	add	r8, qword [_profiler_rcx_calls]
	add	rcx, profiler_record_size
	cmp	qword [_profiler_rcx_name], 0
	jne	.gffloop
	ret
calign
.gffnext:
	add	rcx, profiler_record_size
	cmp	qword [_profiler_rcx_name], 0
	jne	.gffloop
	ret
end if
	
	
	
if used profiler$to_string | defined include_everything
	; no arguments
	; returns current profiler data as a string suitable for dumping to stdout/stderr
falign
profiler$to_string:
	prolog	profiler$to_string	; yes, we profile ourself

	sub	rsp, 16
	call	buffer$new

	mov	[rsp], rax
	mov	rdi, rax
	mov	rsi, .profilerheader
	call	buffer$append_string
	mov	rdi, [rsp]
	mov	esi, 10
	call	buffer$append_byte

	call	profiler$to_json
	mov	[rsp+8], rax
	
	mov	rdi, rax
	mov	rsi, .profilerstr
	call	json$getvaluebyname
	mov	rdi, [rax+json_contents_ofs]
	mov	rsi, .eachcallgraph
	mov	rdx, [rsp]
	call	list$foreach_arg

	mov	rdi, [rsp]
	mov	rsi, .callgraphheader
	call	buffer$append_string
	mov	rdi, [rsp]
	mov	esi, 10
	call	buffer$append_byte
	
	mov	rdi, [rsp+8]
	mov	rsi, .callgraphstr
	call	json$getvaluebyname
	mov	rdi, [rax+json_contents_ofs]
	mov	rsi, .eachcallgraph
	mov	rdx, [rsp]
	call	list$foreach_arg

	mov	rdi, [rsp+8]
	call	json$destroy

	mov	rcx, [rsp]
	mov	rdi, [rcx+buffer_itself_ofs]
	mov	rsi, [rcx+buffer_length_ofs]
	call	string$from_utf8
	mov	[rsp+8], rax
	mov	rdi, [rsp]
	call	buffer$destroy
	mov	rax, [rsp+8]
	add	rsp, 16
	epilog
cleartext .profilerstr, 'profiler'
cleartext .callgraphstr, 'callgraph'
cleartext .profilerheader, 'Function calls listed by total time spent descending:'
cleartext .callgraphheader, 'Actual Call Graph, Listed in Call Order and Dependency Order'
cleartext .functionstr, 'function'
cleartext .callsstr, 'calls'
cleartext .cyclesstr, 'cycles'
cleartext .cpcstr, 'cpc'
cleartext .totcyclesstr, 'totcycles'
cleartext .ind1, ': calls: '
cleartext .ind2, ', cycles: '
cleartext .ind3, ', cpc: '
cleartext .ind4, ', tot_cycles: '
calign
.eachcallgraph:
	; rdi == our entry json object, rsi == destination buffer
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	rdi, rsi
	mov	esi, 1024
	call	buffer$reserve
	mov	rdi, [rsp]
	mov	rsi, .functionstr
	call	json$getvaluebyname
	mov	rsi, [rax+json_value_ofs]
	mov	rdi, [rsp+8]
	call	buffer$append_string
	
	mov	rdi, [rsp+8]
	mov	rsi, .ind1
	call	buffer$append_string

	mov	rdi, [rsp]
	mov	rsi, .callsstr
	call	json$getvaluebyname
	mov	rsi, [rax+json_value_ofs]
	mov	rdi, [rsp+8]
	call	buffer$append_string
	
	mov	rdi, [rsp+8]
	mov	rsi, .ind2
	call	buffer$append_string

	mov	rdi, [rsp]
	mov	rsi, .cyclesstr
	call	json$getvaluebyname
	mov	rsi, [rax+json_value_ofs]
	mov	rdi, [rsp+8]
	call	buffer$append_string

	mov	rdi, [rsp+8]
	mov	rsi, .ind3
	call	buffer$append_string

	mov	rdi, [rsp]
	mov	rsi, .cpcstr
	call	json$getvaluebyname
	mov	rsi, [rax+json_value_ofs]
	mov	rdi, [rsp+8]
	call	buffer$append_string

	mov	rdi, [rsp]
	mov	rsi, .totcyclesstr
	call	json$getvaluebyname
	test	rax, rax
	jz	.nototal
	mov	[rsp+16], rax

	mov	rdi, [rsp+8]
	mov	rsi, .ind4
	call	buffer$append_string
	
	mov	rax, [rsp+16]
	mov	rsi, [rax+json_value_ofs]
	mov	rdi, [rsp+8]
	call	buffer$append_string
.nototal:
	mov	rdi, [rsp+8]
	mov	esi, 10
	call	buffer$append_byte
	add	rsp, 24
	ret
end if



if used tui_profiler$vtable | defined include_everything
	; in order to create a component, we are going to wrap our goods inside a custom tui_object
	; and keep track of our header label, and allow flipping/refreshing of the profiler data.
	; so this means we need a custom vtable so we can catch keyevents and do a custom clone/cleanup
dalign
tui_profiler$vtable:
        dq      tui_profiler$cleanup, tui_profiler$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
        dq      tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
        dq      tui_profiler$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
        dq      tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
        dq      tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
        dq      tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
        dq      tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
end if

tui_profiler_dg_ofs = tui_object_size
tui_profiler_json_ofs = tui_object_size + 8
tui_profiler_state_ofs = tui_object_size + 16
tui_profiler_text_ofs = tui_object_size + 24

tui_profiler_size = tui_object_size + 32

if used tui_profiler$new | defined include_everything
	; no arguments, returns a new tui_profiler component in rax (100% width/height)
	; returns a new profiler tui component in rax suitable for adding to an existing tui object,
	; or as an argument to terminal$new, etc.
	; NOTE: this sets the initial datagrid goods with the current profiler data
falign
tui_profiler$new:
	prolog	tui_profiler$new
	mov	edi, tui_profiler_size
	call	heap$alloc
	push	rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	mov	rax, [rsp]
	mov	qword [rax], tui_profiler$vtable
	call	profiler$to_json
	mov	rdi, [rsp]
	mov	[rdi+tui_profiler_json_ofs], rax	; store the json object itself

	; next up, we need our header line
	; which is an hbox, 100%x1 dims, and in it
	; two labels, one of which we need to be able to modify
	; and the other of which will remain static for the life of our component
	mov	edi, tui_object_size
	call	heap$alloc
	mov	qword [rax], tui_object$default_vtable
	push	rax
	mov	rdi, rax
	movq	xmm0, [_math_onehundred]
	mov	esi, 1
	call	tui_object$init_di
	mov	rdi, [rsp]
	mov	dword [rdi+tui_layout_ofs], tui_layout_horizontal
	; now we need to create/add a label to it
	movq	xmm0, [_math_onehundred]
	mov	edi, 1
	mov	rsi, .profilerlabel
	ansi_colors edx, 'lightgray', 'black'
	mov	ecx, tui_textalign_left
	call	tui_label$new_di
	; [rsp+8] is our tui_profiler object, we need to set its text label to this one
	mov	rsi, [rsp+8]
	mov	[rsi+tui_profiler_text_ofs], rax
	mov	rsi, rax
	mov	rdi, [rsp]	; the header hbox
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; now we need our static right hand side text
	mov	edi, 48
	mov	esi, 1
	mov	rdx, .controlslabel
	ansi_colors ecx, 'lightgray', 'black'
	mov	r8d, tui_textalign_right
	call	tui_label$new_ii
	mov	rdi, [rsp]	; the header hbox
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; so now, we have to add the header hbox to our tui_profiler object
	pop	rsi
	mov	rdi, [rsp]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	

	; next up, we need a datagrid
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	ansi_colors edi, 'black', 'lightgray'
	ansi_colors esi, 'lightgray', 'black'
	ansi_colors edx, 'lightgray', 'blue'
	call	tui_datagrid$new_dd
	mov	rdi, [rsp]
	mov	[rdi+tui_profiler_dg_ofs], rax
	; set its initial data to the profiler json array object contained in our goods
	mov	rsi, .profilerstr
	mov	rdi, [rdi+tui_profiler_json_ofs]
	call	json$getvaluebyname
	; this should be a json array object sitting in rax
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	mov	rsi, rax
	call	tui_datagrid$nvsetdata_notowner

	; so now we have a datagrid with profiler data, the DG needs its headers
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	mov	rsi, .functionlabel
	movq	xmm0, [_math_onehundred]
	mov	edx, tui_textalign_left
	mov	rcx, .functionstr
	call	tui_datagrid$nvaddproperty_d

	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	mov	rsi, .callslabel
	mov	edx, 14
	mov	ecx, tui_textalign_right
	mov	r8, .callsstr
	call	tui_datagrid$nvaddproperty_i

	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	mov	rsi, .cycleslabel
	mov	edx, 14
	mov	ecx, tui_textalign_right
	mov	r8, .cyclesstr
	call	tui_datagrid$nvaddproperty_i

	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	mov	rsi, .cpclabel
	mov	edx, 14
	mov	ecx, tui_textalign_right
	mov	r8, .cpcstr
	call	tui_datagrid$nvaddproperty_i

	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	mov	rsi, .totlabel
	mov	edx, 14
	mov	ecx, tui_textalign_right
	mov	r8, .totcyclesstr
	call	tui_datagrid$nvaddproperty_i

	mov	rdi, [rsp]
	mov	rsi, [rdi+tui_profiler_dg_ofs]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	
	; so now, we have added/set everything we need, except our state variable
	mov	rax, [rsp]
	mov	qword [rax+tui_profiler_state_ofs], 0
	add	rsp, 8
	
	epilog
cleartext .profilerstr, 'profiler'
cleartext .functionlabel, 'Function Name'
cleartext .functionstr, 'function'
cleartext .callslabel, 'Calls'
cleartext .callsstr, 'calls'
cleartext .cycleslabel, 'Cycles'
cleartext .cyclesstr, 'cycles'
cleartext .cpclabel, 'CPC'
cleartext .cpcstr, 'cpc'
cleartext .totlabel, 'Total Cycles'
cleartext .totcyclesstr, 'totcycles'
cleartext .profilerlabel, ' Functions by time spent descending'
cleartext .controlslabel, 'Space-Profiler/CallGraph Up/Dn-Peruse R-Refresh '

end if

if used tui_profiler$cleanup | defined include_everything
	; single argument in rdi: the tui_profiler object we are cleaning up
	; we call tui_object's cleanup to let it deal with everything but our json, which is the only one we hold onto
	; that isn't handeld by tui_object's method
falign
tui_profiler$cleanup:
	prolog	tui_profiler$cleanup
	push	rdi
	call	tui_object$cleanup
	pop	rsi
	mov	rdi, [rsi+tui_profiler_json_ofs]
	call	json$destroy
	epilog
end if

if used tui_profiler$clone | defined include_everything
	; single argument in rdi: the tui_profiler object we are making a copy of
falign
tui_profiler$clone:
	prolog	tui_profiler$clone
	; because we dont actually care, we just return a spanking new one
	call	tui_profiler$new
	epilog
end if

if used tui_profiler$keyevent | defined include_everything
	; three arguments: rdi == tui_profiler object, esi == key, edx == esc_key
	; returns 1 in eax if we handled it, 0 if not
falign
tui_profiler$keyevent:
	prolog	tui_profiler$keyevent
	xor	eax, eax
	cmp	esi, 32
	je	.gotspace
	cmp	esi, 'r'
	je	.gotr
	cmp	esi, 'R'
	je	.gotr
	epilog

calign
.gotr:
	push	rdi
	mov	rdi, [rdi+tui_profiler_json_ofs]
	call	json$destroy
	call	profiler$to_json
	mov	rdi, [rsp]		; jumping to toprofiler assumes rdi was pushed, so we are not popping it here
	mov	[rdi+tui_profiler_json_ofs], rax
	jmp	.toprofiler
calign
.gotspace:
	; flip between profiler and callgraph data
	push	rdi
	cmp	qword [rdi+tui_profiler_state_ofs], 0
	je	.tocallgraph
calign
.toprofiler:
	; else, toprofiler data.
	mov	rdi, [rdi+tui_profiler_json_ofs]
	mov	rsi, .profilerstr
	call	json$getvaluebyname

	mov	rsi, rax
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	call	tui_datagrid$nvsetdata_notowner
	mov	rdi, [rsp]

	cmp	qword [rdi+tui_profiler_state_ofs], 0
	je	.notextreset
	mov	qword [rdi+tui_profiler_state_ofs], 0
	mov	rdi, [rdi+tui_profiler_text_ofs]
	mov	rsi, .profilerlabel
	call	tui_label$nvsettext
calign
.notextreset:
	pop	rdi
	mov	eax, 1
	epilog
calign
.tocallgraph:
	mov	rdi, [rdi+tui_profiler_json_ofs]
	mov	rsi, .callgraphstr
	call	json$getvaluebyname
	mov	rsi, rax
	mov	rdx, [rsp]
	mov	rdi, [rdx+tui_profiler_dg_ofs]
	call	tui_datagrid$nvsetdata_notowner
	mov	rdi, [rsp]
	mov	qword [rdi+tui_profiler_state_ofs], 1
	mov	rdi, [rdi+tui_profiler_text_ofs]
	mov	rsi, .callgraphlabel
	call	tui_label$nvsettext
	pop	rdi
	mov	eax, 1
	epilog
cleartext .profilerstr, 'profiler'
cleartext .callgraphstr, 'callgraph'
cleartext .profilerlabel, ' Functions by time spent descending'
cleartext .callgraphlabel, ' Actual Call Graph'
end if


end if
