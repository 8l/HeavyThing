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
	; epoll.inc: epoll/socket/fd layer
	;
	; some notes here on our "epoll object" methods
	; we "descend" the io.inc object model, using virtual methods to do our deed
	; this has the pleasant side-effect in that we can chain together any number
	; of arbitrary io-descendents, and have the epoll layer be one of them
	;

	;
	; some notes on the way I decided to design the io chaining goods (mainly for
	; my own benefit so I can keep my head around it, haha):
	; when any of the epoll$inbound, epoll$outbound, epoll$outbound_hostname, epoll$established
	; are called, their input is _not_ necessarily an actual epoll object, and instead
	; is assumed to be an io object descendent, whose LAST link in the chain _is_ the
	; epoll object.
	; In other words, those functions walk down a chain to find the actual epoll object, and
	; in this way, it is possible to create an application layer io$ object, attach an
	; epoll object as its child for sending/receiving, and call epoll$outbound directly on the
	; application layer io object, without care/regard for the underlying implementation.
	; This lets us do more creative things with TLS, etc. without having to modify much at the
	; application layer itself.
	; 
	;
	; some further notes on the way I decided to do the timer handling, again mainly for my
	; own reference because it can be quite messy... haha
	; ok so: for "normal" epoll objects, meaning: ones that are actually epoll objects, and
	; not tui_* objects, when a timer decides it no longer wishes to be alive, it can return
	; 1 for a self-destruct. This all works perfectly, and the epoll$iteration correctly deals
	; with it by calling epoll$fatality (which in turn calls io_vdestroy, and thus frees the
	; pointer and calls the destructor).
	; NOW, haha, the messy bit: for tui_object descendents, which _pretend_ to be epoll objects
	; (insofar as their vmethod table is in the same spot, and they have their timer handler
	; also in the same spot, and their _cleanup_ method in the same spot as epoll$destroy's)
	; if a tui_* descendent's timer decides it wants to off itself, it has to specifically
	; let this epoll layer know that io_vdestroy/fatality is not enough, and that it _also_
	; needs to free the pointer... otherwise, we end up with the tui_* cleanup method being
	; called thanks to epoll$fatality, but then the pointer to the tui_* object itself remains
	; dangling forever (aka leak.)
	; There are several instances where the tui layer does not want to adhere to the io_vdestroy
	; principle of freeing itself when it is called, so to deal with this:
	; timer_new returns a timer object that is 32 bytes in size. if you set the dword at +24
	; to 1, this special handling of timer expiry takes effect and _after_ epoll$fatality
	; is called, an additional call to heap$free will also occur for the epoll object attached
	; if you set the dword at +24 to 2, then no cleanup/destroy/free will occur, but the timer
	; will itself be cleared.
	;
	;

	;
	; Special attention is required for the way we deal with input buffering here...
	; the io$receive model specifies that the receive functions receive a flat pointer
	; and a length, and does NOT specify that it is actually a proper buffer$ object.
	; In a great many use cases, it is beneficial to be able to accumulate data
	; after thorough inspection of same (e.g. partial packet/fragment received, etc)
	; as a result, when we actually do physical reads and append to the end of the buffer
	; epoll$receive (the default base one that does nothing), resets the actual input
	; buffer when it is done populating it back up the io$ chain.
	; descendents of epoll$ _must_ do the same, because the input buffer is not
	; reset or consumed/etc from inside here and is only ever appended to.
	;

	;
	; Notes re: output buffering/exhaustion...
	; Under normal operating conditions, we do not constantly poll for EPOLLOUT, and only
	; activate that when we _should_. That is to say: when we attempt to send data, and
	; a partial send is accepted or we get a flat EWOULDBLOCK/EGAIN. The application layers
	; above this epoll layer can continue to send, and we'll buffer it ad nauseum, but
	; if you wanted to send say a 500GB file, obviously you can't sit there and a) read the
	; entire file first, then b) buffer it to memory, and then finally c) let this epoll
	; layer slowly exhaust (aack, that would be very bad, haha) the buffer.
	; SO, the solution is to (without unnecessarily adding calls for normal operating) make
	; a single call on the epoll object you are working with that enables a callback.
	; The callback will get called under precisely two conditions:
	; 1) during/inside a call to epoll$send, if we ended up buffering some/all of it, then
	;    the callback is called with rdi == your callback arg, esi == 0, indicating that
	;    callback #2 will be called when the buffer is emptied.
	; 2) when the epoll layer buffering has been emptied, the callback will be called with
	;    rdi == your callback arg, esi == 1, indicating that it is safe to send more data.
	; Cloned/listening sockets do not inherit these, and are meant to be used on a single
	; epoll object where/when it makes sense at the applayer to do so.
	;

	;
	; Notes re: epoll_wait and service destruction
	; There are quite a few case scenarios whereby an event happens on one fd that causes
	; the teardown of another unrelated fd. Of course, if _both_ had pending epoll events,
	; thus both fds were returned in our call to epoll wait, when we iterate through the
	; results, we wouldn't necessarily be aware that the second fd was no longer serviceable
	; without some decent bookkeeping. In order to solve that particular condition, we keep
	; a global unsigned map that is _cleared and set_ during epoll_wait calls, then
	; epoll$destroy does a remove call against it. Because the maximum size of this map
	; is the maximum # of events returned in a single call to epoll_wait, this overhead isn't
	; really that bad, and is well worth the effort. (The alternative is to keep a fixed
	; array of fds that map to epoll objects, which seems overkill to me, especially since
	; the # of operations per second on small maps is quite high).

	; SETTING:
	; profile the epoll iteration itself? (NOTE: if you are using the tui profiler, or doing other epoll related goods,
	; then enabling this and refresing the profiler results can have undesired effects, mainly that the # of
	; clock cycles spent inside epoll$iteration including its wait times end up in the profiler output, which is
	; probably NOT what you want)
	; also includes epoll$run, as they are both synonymous for profiling purposes
	profile_epoll_iteration = 0

epoll_debug = 0

epoll_inbuf_ofs = io_base_size
epoll_outbuf_ofs = io_base_size + 8
epoll_fd_ofs = io_base_size + 16
epoll_readtimeout_ofs = io_base_size + 24
epoll_timerobject_ofs = io_base_size + 32
epoll_listener_ofs = io_base_size + 40
epoll_other_ofs = io_base_size + 48
epoll_sendcb_ofs = io_base_size + 56		; see commentary above re: these two
epoll_sendcbarg_ofs = io_base_size + 64
epoll_partialsend_ofs = io_base_size + 72
epoll_udpserver_ofs = io_base_size + 76

epoll_base_size = io_base_size + 80

	; our virtual method offsets are the same as the base io virtual method offsets
	; for clarity, we copy them:
epoll_vdestroy = io_vdestroy
epoll_vclone = io_vclone
epoll_vconnected = io_vconnected
epoll_vsend = io_vsend
epoll_vreceive = io_vreceive
epoll_verror = io_verror
epoll_vtimeout = io_vtimeout

	; each and every one of those MUST be valid (though it is fine to use the defaults)

	; NOTE OF CAUTION: with cleanup, as in c++ destructors, it is imperative that your own
	; implementation still makes a call to the default one here (so that we can cleanup
	; all of our epoll specific internal goodies)

if used epoll$new | defined include_everything
	; two arguments: virtual method table pointer in rdi, extra space required in rsi
	; (virtual method table same as for io, 7 functions in total)
	; NOTE: sets parent/child both to null (io's parent/child)
falign
epoll$new:
	prolog	epoll$new
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	buffer$new
	mov	[rsp+16], rax
	call	buffer$new
	mov	[rsp+24], rax
	mov	rdi, [rsp+8]
	add	rdi, epoll_base_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	[rax], rdi			; io_vmethods_ofs
	mov	qword [rax+io_parent_ofs], 0
	mov	qword [rax+io_child_ofs], 0
	mov	[rax+epoll_inbuf_ofs], rdx
	mov	[rax+epoll_outbuf_ofs], rcx
	mov	qword [rax+epoll_fd_ofs], -1
	mov	qword [rax+epoll_readtimeout_ofs], 0
	mov	qword [rax+epoll_timerobject_ofs], 0
	mov	qword [rax+epoll_listener_ofs], 0
	mov	qword [rax+epoll_sendcb_ofs], 0
	mov	qword [rax+epoll_sendcbarg_ofs], 0
	mov	qword [rax+epoll_partialsend_ofs], 0	; covers udpserver_ofs as well
	add	rsp, 32
	epilog

end if

if used epoll$timer_new | defined include_everything
	; two arguments: time (in milliseconds) in rdi, epoll object in rsi
	; returns a pointer to the new timer object
	;
	; NOTE: see commentary atop about the special use of the timer offset at +24
	; if you set it to nonzero (after this function returns you the timer pointer)
	; then we will heap$free the epoll object upon timer destruct (meaning, your
	; timer returned 1 from its timer handler)
falign
epoll$timer_new:
	prolog  epoll$timer_new
	push    rsi rdi
	mov     edi, 32
	call    heap$alloc
	mov	qword [rax+24], 0
	mov     rdi, [rsp]
	mov     rsi, [rsp+8]
	mov     [rax], rdi
	mov     [rax+8], rsi
	mov     [rsp], rax
	call    epoll$timestamp
	mov     rsi, rax
	mov     rdx, [rsp]
	mov     rcx, [rdx]      ; the time in ms of the timer itself
	add     rsi, rcx        ; added to the actual timestamp
	mov     [rdx+16], rsi   ; its key into the timemap
	mov     rdi, [_epoll_timemap]
	call    unsignedmap$insert
	mov     rax, [rsp]
	add     rsp, 16
	epilog
end if

if used epoll$timer_reset | defined include_everything
	; single argument: timer object in rdi
	; starts the timer countdown again to its original value
falign
epoll$timer_reset:
	prolog  epoll$timer_reset
	push    rdi
	mov     rdx, rdi        ; value object
	mov     rsi, [rdi+16]   ; its key
	mov     rdi, [_epoll_timemap]
	call    unsignedmap$erase_specific
	call    epoll$timestamp
	mov     rsi, rax
	mov     rdx, [rsp]
	mov     rcx, [rdx]      ; the time in ms of the timer itself
	add     rsi, rcx        ; added to the actual timestamp
	mov     [rdx+16], rsi   ; its new key into the timemap
	mov     rdi, [_epoll_timemap]
	call    unsignedmap$insert
	pop     rax
	epilog
end if

if used epoll$timer_clear | defined include_everything
	; single argument: timer object in rdi
	; removes the timer from the timemap and heap$frees the timer object
falign
epoll$timer_clear:
	prolog  epoll$timer_clear
	push    rdi
	mov     rdx, rdi
	mov     rsi, [rdi+16]
	mov     rdi, [_epoll_timemap]
	call    unsignedmap$erase_specific
	pop     rdi
	call    heap$free
	epilog

end if


if used epoll$destroy | defined include_everything
	; single argument in rdi: our epoll object
	; NOTE: descendents of this need to do their own cleanup, then call this, which in turn will call io$destroy which does the final heap$free
falign
epoll$destroy:
	prolog	epoll$destroy
if epoll_debug
	push	rdi
	mov	rdi, .destroystr
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, [rsp]
	mov	rdi, [rdi+epoll_fd_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdi
end if
	push	rbx
	mov	rbx, rdi
	push	qword [rdi+epoll_timerobject_ofs]
	push	qword [rdi+epoll_inbuf_ofs]
	push	qword [rdi+epoll_fd_ofs]
	; make sure we mark ourselves as no longer serviceable, see commentary atop as to why we do this
	mov	rdi, [_epoll_serviceable]
	mov	rsi, rbx
	call	unsignedmap$erase
if epoll_unixconnect_forgiving & used epoll$outbound
	; we also need to confirm that this object is not sitting in the _epoll_unixconnect_map
	mov	rdi, [_epoll_unixconnect_map]
	mov	rsi, rbx
	call	unsignedmap$find
	test	rax, rax
	jz	.notinqueue
	; free the value first, then erase it
	mov	rdi, [rax+_avlofs_value]	; the copy of the destination address
	call	heap$free
	mov	rdi, [_epoll_unixconnect_map]
	mov	rsi, rbx
	call	unsignedmap$erase
calign
.notinqueue:
end if
	mov	rdi, [rbx+epoll_outbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rsp+8]
	call	buffer$destroy
if epoll_del_before_close
	cmp	qword [rsp], 0
	jl	.noclose

	mov	rdi, rbx
	mov	esi, 2
	mov	rdx, [rsp]
	mov	r10, rsp
	sub	r10, 16
	mov	dword [r10], 1		; EPOLLIN
	mov	qword [r10+4], rdi	; our object
	mov	eax, syscall_epoll_ctl
	mov	rdi, [_epoll_fd]
	syscall
	mov	rdi, [rsp]
	mov	eax, syscall_close
	syscall
else

	mov	rdi, [rsp]
	cmp	rdi, 0
	jl	.noclose
	mov	rdi, [rsp]
	mov	eax, syscall_close
	syscall
end if
calign
.noclose:
	mov	rdi, [rsp+16]
	test	rdi, rdi
	jz	.justret
	call	epoll$timer_clear
	add	rsp, 24
	mov	rdi, rbx
	pop	rbx
	; note: not our virtual destroy on purpose
	call	io$destroy
	epilog
if epoll_debug
cleartext .destroystr, 'epoll$destroy: '
end if
calign
.justret:
	add	rsp, 24
	mov	rdi, rbx
	pop	rbx
	; note: not our virtual destroy on purpose
	call	io$destroy

	epilog

end if

if used epoll$clone | defined include_everything
	; single argument in rdi: our epoll object
	; for a listening/inbound socket, when we accept a new one, this is called.
	; we must return a new "clone" of ourselves (which basically means: epoll$new but with
	; our own virtual method table)
	; this default only calls epoll$new with the correct virtual method table pointer, 
	; and also clones children if any
falign
epoll$clone:
	prolog	epoll$clone
	push	rdi
	mov	rdi, [rdi]	; the virtual method table
	xor	esi, esi	; no extra space required
	call	epoll$new
	mov	rdi, [rsp]
	mov	rsi, [rdi+epoll_readtimeout_ofs]
	mov	[rax+epoll_readtimeout_ofs], rsi	; copy our original's readtimeout setting
	cmp	qword [rdi+io_child_ofs], 0
	jne	.withchild
	pop	rdi
	epilog
calign
.withchild:
	mov	[rsp], rax	; save our return
	mov	rdi, [rdi+io_child_ofs]
	mov	rsi, [rdi]	; its vmethod table
	call	qword [rsi+io_vclone]
	pop	rdi
	mov	[rdi+io_child_ofs], rax
	mov	[rax+io_parent_ofs], rdi
	xchg	rdi, rax
	epilog

end if


if used epoll$pause | defined include_everything
	; single argument in rdi: our epoll object (descendent is okay, we walk the chain to
	; the bottom-most to find the epoll object)
	;
	; This assumes that the socket is not presently in a blocking send state (waiting for 
	; its send buffer to be exhausted), and instead implies it is in a normal read state
	;
	; This effectively does nothing other than an EPOLL_CTL_MOD for the object, which
	; results (ultimately) in the underlying tcp stacks buffering mechanisms to stop.
	;
	; Where this is useful is: Imagine a case scenario where you have a forwarding agent
	; setup such that host A sends to host B, which then onsends to host C. In this case
	; we would be the relay at host B. Further, imagine the bandwidth between A and B
	; to be very high, and imagine the bandwidth between B and C to be crap.
	; So host A crams as much data as possible down the line, host B receives it at top
	; speed, but its send buffers can't cope with the inbound data rate due to the crap
	; bandwidth between B and C. Host B then calls this function on its receive side
	; from host A, which effectively jams the sending line (and that way, host B doesn't
	; have to accumulate potentially vast amounts of data waiting for the pipe to C to
	; slowly drain). Once B is sitting on sufficiently low data (or more specifically, 
	; once B's output buffer gets exhausted to C), then it calls epoll$resume on its
	; link to A, which then does successive read calls to exhaust the kernel supplied
	; buffers, and then re-enables EPOLLIN on it. Rinse, repeat.
	;
falign
epoll$pause:
	prolog	epoll$pause
calign
.chainwalk:
	cmp	qword [rdi+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdi, [rdi+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
        ; enable EPOLLOUT
        mov     esi, 3                          ; EPOLL_CTL_MOD
	mov	rdx, [rdi+epoll_fd_ofs]		; load up our fd
        sub     rsp, 16
        mov     r10, rsp
        mov     dword [r10], 0x18               ; EPOLLHUP|EPOLLERR
        mov     qword [r10+4], rdi              ; our object
        mov     eax, syscall_epoll_ctl
        mov     rdi, [_epoll_fd]
        syscall
	add	rsp, 16
	epilog

end if

if used epoll$resume | defined include_everything
	; single argument in rdi: our epoll object (descendent is okay, we walk the chain to
	; the bottom-most to find the epoll object)
	; CAUTION: this can result in your object's destruction, so care must be taken that it is
	; the last thing you do before a return
	;
	; see notes above for epoll$pause as to how this is meant to work
falign
epoll$resume:
	prolog	epoll$resume
	; read until we get a wouldblock, then re-enable EPOLLIN
calign
.chainwalk:
	cmp	qword [rdi+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdi, [rdi+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	sub	rsp, 160
	mov	[rsp], rdi		; save our object
	mov	rcx, [rdi+epoll_fd_ofs]	; save our fd
	mov	rdx, [rdi+epoll_inbuf_ofs]
	mov	[rsp+16], rcx
	mov	[rsp+8], rdx
calign
.readloop:
	mov	rdi, [rsp+8]
	mov	esi, epoll_readsize
	call	buffer$reserve
	; read needs: fd in rdi, buffer in rsi, size in rdx
	mov	eax, syscall_read
	mov	rsi, [rsp+8]
	mov	rsi, [rsi]		; endptr
	mov	rdi, [rsp+16]
	mov	edx, epoll_readsize
	syscall
	; rax < 0 == error, but could be EAGAIN
	cmp	rax, 0
	jle	.readerror
	cmp	rax, epoll_readsize
	jl	.appendthendone
	mov	rdi, [rsp+8]		; our input buffer
	mov	rsi, rax		; our # of bytes read
	call	buffer$append_nocopy
	jmp	.readloop
calign
.appendthendone:
	mov	rdi, [rsp+8]		; our input buffer
	mov	rsi, rax		; our # of bytes read
	call	buffer$append_nocopy
	jmp	.read_return
calign
.readerror:
	cmp	rax, -11		; EAGAIN aka EWOULDBLOCK
	je	.read_return
	; else, an actual error occurred, call the object's socketerror and die die die
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_verror]
	jmp	.read_cleanup_and_return
calign
.read_return:
	mov	rcx, [rsp+8]
	cmp	qword [rcx+8], 0	; buffer length
	jne	.read_doreceived
	jmp	.read_quietreturn
calign
.read_doreceived:
	mov	rdi, [rsp]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+epoll_vreceive]
	mov	rdi, [rsp+8]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	qword [rdi+buffer_length_ofs], 0
	mov	[rdi+buffer_endptr_ofs], rsi
	; vreceive will return true if we are sposed to KO it
	test	eax, eax
	jz	.read_quietreturn
	; else, death on a stick, and because _they_ asked for it, no other calls than cleanup to be done
calign
.read_cleanup_and_return:
	mov	rdi, [rsp]
	call	epoll$fatality		; will walk to the top and call topmost's vdestroy
	add	rsp, 160
	epilog
calign
.read_quietreturn:
	; enable EPOLLIN again
	mov	rdi, [rsp]
	mov	esi, 3			; EPOLL_CTL_MOD
	mov	rdx, [rdi+epoll_fd_ofs]
	mov	r10, rsp
	add	r10, 8
	mov	dword [r10], 1		; EPOLLIN
	mov	qword [r10+4], rdi
	mov	eax, syscall_epoll_ctl
	mov	rdi, [_epoll_fd]
	syscall
	add	rsp, 160
	epilog

end if


if used epoll$send | defined include_everything
	; three arguments: rdi == our epoll object, rsi == ptr to data, rdx == length of same
	; attempts a direct write on the underlying fd, anything that remains ends up in our
	; output buffer and EPOLLOUT is enabled on it.
	; if a subsequent send comes through and there is already accumulated data in the 
	; output buffer, we simply append it and bailout (will wait for the EPOLLOUT signal
	; before it attempts to purge the buffer). See commentary atop for sendcb/sendcbarg
	; for the callbacks that can optionally be generated inside here.
	;
	; NOTE RE: actual write error (<0, not EAGAIN, proper error)
	; we silently discard the buffer when this happens, but we do not destruct our object
	; inside this routine. this is so a calling implementation needn't worry about whether
	; it is valid or not during their "send this/send that"
	;
	; the next epoll$iteration call will return an EPOLLHUP|EPOLLERR on it at which point
	; error will get called and it will get torn down properly
falign
epoll$send:
	prolog	epoll$send
	mov	rcx, [rdi+epoll_outbuf_ofs]
	mov	eax, syscall_write
	mov	r8, [rdi+epoll_fd_ofs]
	cmp	qword [rcx+buffer_length_ofs], 0
	jne	.buffer_append
        ; we want [rsp] == rdi, [rsp+8] == rsi, [rsp+16] == rdx, [rsp+24] == rcx
	push	r8 rdx rsi rdi
	mov	rdi, r8
	syscall
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	cmp	rax, 0
	jle	.sendfailed
	sub	rdx, rax
	jnz	.sentpartial
	; write took all of the data, nothing more to do
	add	rsp, 32
	epilog
calign
.sentpartial:
	; write took some of the data
	mov	rdi, [rdi+epoll_outbuf_ofs]
	add	rsi, rax
	call	buffer$append
	; enable EPOLLOUT
	mov	rcx, [rsp]			; our object
	mov	esi, 3				; EPOLL_CTL_MOD
	mov	rdx, [rsp+24]			; our fd
	sub	rsp, 16
	mov	eax, syscall_epoll_ctl
	mov	dword [rcx+epoll_partialsend_ofs], 1	; set the flag so that when EPOLLOUT occurs we know why
	mov	r10, rsp
	mov	rdi, [_epoll_fd]
	mov	dword [r10], 5			; EPOLLIN|EPOLLOUT
	mov	qword [r10+4], rcx		; our object
	syscall
	mov	rdi, [rsp+16]
	add	rsp, 16
	cmp	qword [rdi+epoll_sendcb_ofs], 0
	jne	.sentpartial_callback
	add	rsp, 32
	epilog
calign
.sentpartial_callback:
	mov	rdx, rdi
	mov	rdi, [rdi+epoll_sendcbarg_ofs]
	xor	esi, esi
	call	qword [rdx+epoll_sendcb_ofs]
	add	rsp, 32
	epilog
calign
.sendfailed:
	; write returned <= 0
	mov	rdi, [rdi+epoll_outbuf_ofs]
	cmp	rax, -11			; the only acceptable return
	je	.sendfailed_buffer
	; else, an actual error occurred
	; see above re: why we ignore this
	add	rsp, 32
	epilog
calign
.sendfailed_buffer:
	call	buffer$append
	; enable EPOLLOUT
	mov	rcx, [rsp]			; our object
	mov	esi, 3				; EPOLL_CTL_MOD
	mov	rdx, [rsp+24]			; our fd
	sub	rsp, 16
	mov	eax, syscall_epoll_ctl
	mov	dword [rcx+epoll_partialsend_ofs], 1	; set the flag so that when EPOLLOUT occurs we know why
	mov	r10, rsp
	mov	rdi, [_epoll_fd]
	mov	dword [r10], 5			; EPOLLIN|EPOLLOUT
	mov	qword [r10+4], rcx		; our object
	syscall
	mov	rdi, [rsp+16]
	add	rsp, 16
	cmp	qword [rdi+epoll_sendcb_ofs], 0
	jne	.sentpartial_callback
	add	rsp, 32
	epilog
calign
.buffer_append:
        ; there was already data sitting in the outbuf, add this and be done
if epoll_debug
	push	rcx
end if

        mov     rdi, rcx
        call    buffer$append
if epoll_debug
	mov	rdi, .s1
	call	string$to_stdout
	pop	rcx
	mov	rdi, [rcx+buffer_length_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	epilog
if epoll_debug
cleartext .s1, 'epoll$send, buffer length is: '
end if

end if


if used epoll$receive | defined include_everything
	; three arguments: rdi == epoll object, rsi == ptr to data, rdx == length of same
	; NOTE: see paragraph or so atop as to what/how/why
	; In short however: we get passed (per the io spec) rsi == inbuf's start, rdx == length of same
	; these do however come from the input buffer at [rdi+epoll_inbuf_ofs]
	; and because the physical read portion never clears it, our default implementation here
	; (that all descendents need to supply/deal with), clears the input buffer when we are done with it
	; for chained/cooked scenarios, the way the returns are handled is likely to have to be custom-done
	; not terribly messy, but the simple value return in eax is too simple for what is required
	; to accumulate data...
	;
	; basically: if your descendent of this doesn't buffer$reset or buffer$consume the [rdi+epoll_inbuf_ofs]
	; then it will accumulate endlessly.
	;
falign
epoll$receive:
	prolog	epoll$receive
	; we _almost_ copy identically the io$receive default, with the exception that before we return
	; we reset the epoll_inbuf_ofs buffer
	push	rdi
	mov	rdi, [rdi+io_parent_ofs]
	test	rdi, rdi
	jnz	.hasparent
	pop	rsi
	mov	rdi, [rsi+epoll_inbuf_ofs]
	call	buffer$reset
	xor	eax, eax	; don't destroy us
	epilog
calign
.hasparent:
	mov	rcx, [rdi]	; its virtual method pointer
	call	qword [rcx+io_vreceive]
	; let our return == parent's return
	mov	rsi, [rsp]
	mov	[rsp], rax	; save our return
	mov	rdi, [rsi+epoll_inbuf_ofs]
	call	buffer$reset
	pop	rax
	epilog

end if


if used epoll$default_vtable | defined include_everything

dalign
if public_funcs
public epoll$default_vtable
end if
epoll$default_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, epoll$receive, io$error, io$timeout

end if

	include 'epoll_dns.inc'

if used epoll$set_readtimeout | defined include_everything
	; two arguments: epoll object (base or descendent) in rdi, read timeout in milliseconds in rsi
	; provided as a reference only.
	; if on an inbound object this is set, then the read timeout applies to all accepted/cloned
	; sockets without having to explicitly set it inside your own clone version
falign
epoll$set_readtimeout:
	prolog	epoll$set_readtimeout
	mov	[rdi+epoll_readtimeout_ofs], rsi
	epilog
end if


if used epoll$timestamp | defined include_everything
	; no arguments, calls gettimeofday and manipulates the results into our pseudo-millisecond format
falign
epoll$timestamp:
	mov	rdi, _epoll_tv_secs
	xor	esi, esi
	call	gettimeofday
	mov	rax, [_epoll_tv_usecs]
	mov	ecx, 1000
	xor	edx, edx
	div	rcx
	; rax now has remainder in milliseconds
	mov	r8, rax
	xor	edx, edx
	mov	rax, qword [_epoll_tv_secs]
	sub	rax, qword [_epoll_inittime]
	mul	rcx
	; rax now has tv_secs * 1000 in it
	add	rax, r8
if used _epoll_tv_msecs
	mov	[_epoll_tv_msecs], rax
end if
	; now we have time since inittime in milliseconds sitting in rax, done
	ret
end if
	


	; address helpers:

sockaddr_in_size = 16
sockaddr_un_size = 110

if used unix_addr | defined include_everything
	; two args: destination buffer in rdi, string in rsi
falign
unix_addr:
	prolog	unix_addr
	push	rdi rsi
	xor	esi, esi
	mov	edx, sockaddr_un_size
	call	memset
	pop	rdi rsi		; swapped on purpose
	mov	word [rsi], 1		; AF_UNIX/PF_LOCAL
	add	rsi, 2
	call	string$to_utf8	; because we cleared it before hand, it is ok that utf8 didn't null terminate it
	epilog
end if

if used inaddr_any | defined include_everything
	; two args: destination buffer in rdi, port in esi
falign
inaddr_any:
	prolog	inaddr_any
	xor	edx, edx
	mov	[rdi], rdx
	mov	[rdi+8], rdx
	mov	eax, esi
	mov	word [rdi], 2		; AF_INET/PF_INET
	mov	byte [rdi+2], ah
	mov	byte [rdi+3], al	; htons(port)
	mov	dword [rdi+4], 0	; INADDR_ANY
	epilog
end if


if used inet_addr | defined include_everything
	; three args: destination buffer in rdi, string in rsi (e.g. 127.0.0.1), port in edx
	; returns 1 in eax on success, 0 on error
	; certainly a lazy-man's implementation, hahah, TODO: redo this so it takes less effort or just write a freakin macro to do it
	; isn't really a performance hit as such though since it really only gets run during initial fireup
	; requires string
falign
inet_addr:
	prolog	inet_addr
	xor	ecx, ecx
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rdi], rcx
	mov	[rdi+8], rcx
	mov	rdi, [rsp+8]
	mov	esi, '.'
	call	string$split
	mov	[rsp+24], rax
	cmp	qword [rax], 4
	jne	.address_error

	mov	rdi, rax
	call	list$pop_front
	mov	[rsp+32], rax
	mov	rdi, rax
	call	string$to_int
	mov	rdi, [rsp]
	mov	byte [rdi+4], al
	mov	rdi, [rsp+32]
	call	heap$free

	mov	rdi, [rsp+24]
	call	list$pop_front
	mov	[rsp+32], rax
	mov	rdi, rax
	call	string$to_int
	mov	rdi, [rsp]
	mov	byte [rdi+5], al
	mov	rdi, [rsp+32]
	call	heap$free
	
	mov	rdi, [rsp+24]
	call	list$pop_front
	mov	[rsp+32], rax
	mov	rdi, rax
	call	string$to_int
	mov	rdi, [rsp]
	mov	byte [rdi+6], al
	mov	rdi, [rsp+32]
	call	heap$free
	
	mov	rdi, [rsp+24]
	call	list$pop_front
	mov	[rsp+32], rax
	mov	rdi, rax
	call	string$to_int
	mov	rdi, [rsp]
	mov	byte [rdi+7], al
	mov	rdi, [rsp+32]
	call	heap$free

	mov	rdi, [rsp+24]
	call	heap$free

	mov	rdi, [rsp]
	mov	rdx, [rsp+16]
	mov	word [rdi], 2		; AF_INET/PF_INET
	mov	byte [rdi+2], dh
	mov	byte [rdi+3], dl	; htons(port)
	mov	eax, 1
	add	rsp, 40
	epilog
	; short for family
	; short for port
	; address
calign
.address_error:
	mov	rdi, [rsp+24]
	cmp	qword [rdi], 0
	je	.address_error_return
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	jmp	.address_error
calign
.address_error_return:
	mov	rdi, [rsp+24]
	call	heap$free
	add	rsp, 40
	xor	eax, eax
	epilog
end if



if used inet_ntoa | defined include_everything
	; single argument in edi: 32 bit ip address
	; returns a new string of same
falign
inet_ntoa:
	prolog	inet_ntoa
	push	r12 r13
	mov	r12d, edi
        movzx   edi, r12b
        shr     r12d, 8
        mov     esi, 10
        call    string$from_unsigned
        mov     r13, rax
        mov     rdi, rax
        mov     rsi, .dot
        call    string$concat
        mov     rdi, r13
        mov     r13, rax
        call    heap$free


        movzx   edi, r12b
        shr     r12d, 8
        mov     esi, 10
        call    string$from_unsigned
        push    rax
        mov     rdi, r13
        mov     rsi, rax
        call    string$concat
        mov     rdi, r13
        mov     r13, rax
        call    heap$free
        pop     rdi
        call    heap$free
        mov     rdi, r13
        mov     rsi, .dot
        call    string$concat
        mov     rdi, r13
        mov     r13, rax
        call    heap$free

        movzx   edi, r12b
        shr     r12d, 8
        mov     esi, 10
        call    string$from_unsigned
        push    rax
        mov     rdi, r13
        mov     rsi, rax
        call    string$concat
        mov     rdi, r13
        mov     r13, rax
        call    heap$free
        pop     rdi
        call    heap$free
        mov     rdi, r13
        mov     rsi, .dot
        call    string$concat
        mov     rdi, r13
        mov     r13, rax
        call    heap$free

        movzx   edi, r12b
        shr     r12d, 8
        mov     esi, 10
        call    string$from_unsigned
        push    rax
        mov     rdi, r13
        mov     rsi, rax
        call    string$concat
        mov     rdi, r13
        mov     r13, rax
        call    heap$free
        pop     rdi
        call    heap$free

	mov	rax, r13
	pop	r13 r12
	epilog
cleartext .dot, '.'

end if

	

if used socket$tcp | defined include_everything
	; helper routines
falign
socket$tcp:
	prolog	socket$tcp
	mov	eax, syscall_socket
	mov	edi, 2		; AF_INET
	mov	esi, 1		; SOCK_STREAM
	xor	edx, edx	; protocol
	syscall
	epilog
end if


if used socket$udp | defined include_everything

falign
socket$udp:
	prolog	socket$udp
	mov	eax, syscall_socket
	mov	edi, 2		; AF_INET
	mov	esi, 2		; SOCK_DGRAM
	xor	edx, edx	; protocol
	syscall
	epilog
end if

if used socket$unix | defined include_everything
falign
socket$unix:
	prolog	socket$unix
	mov	eax, syscall_socket
	mov	edi, 1		; AF_UNIX
	mov	esi, 1		; SOCK_STREAM
	xor	edx, edx	; protocol
	syscall
	epilog
end if

if used socket$unixudp | defined include_everything
falign
socket$unixudp:
	prolog	socket$unixudp
	mov	eax, syscall_socket
	mov	edi, 1		; AF_UNIX
	mov	esi, 2		; SOCK_DGRAM
	xor	edx, edx	; protocol
	syscall
	epilog
end if

if used socket$nonblocking | defined include_everything
	; single arg in rdi: socket
	; returns 1 on success, 0 on error
falign
socket$nonblocking:
	prolog	socket$nonblocking
if epoll_fionbio
	sub	rsp, 8
	mov	eax, syscall_ioctl
	mov	esi, 0x5421	; FIONBIO
	mov	qword [rsp], 1
	mov	rdx, rsp
	syscall
	add	rsp, 8
	mov	ecx, 0
	mov	edx, 1
	cmp	eax, 0
	cmove	eax, edx
	cmovne	eax, ecx
	epilog
else
	push	r12
	mov	r12, rdi
	mov	eax, syscall_fcntl
	mov	esi, 3		; F_GETFL
	syscall
	cmp	eax, 0
	jl	.kakked
	or	eax, 0x800	; O_NONBLOCK
	mov	rdi, r12	; socket
	mov	esi, 4		; F_SETFL
	mov	edx, eax	; flags
	mov	eax, syscall_fcntl
	syscall
	cmp	eax, 0
	jl	.kakked
	mov	eax, 1
	pop	r12
	epilog
calign
.kakked:
	xor	eax, eax
	pop	r12
	epilog

end if

end if



if used epoll$init | defined include_everything
globals
{
	_epoll_fds	dq	0
	_epoll_fd	dq	0
	_epoll_timemap	dq	0
	_epoll_inittime	dq	0
	_epoll_bailout	dq	0
	; these two below are useful globals for not having to call gettimeofday if you are inside an epoll handler (since epoll dispatch loop calls it anyway)
	_epoll_tv_secs	dq	0
	_epoll_tv_usecs	dq	0
	; this one is to prevent a nasty condition for epoll_wait returns, see commentary atop
	_epoll_serviceable	dq	0
	; this one is useful if you want to do something _after_ a full processing of epoll_wait returns
	_epoll_postprocessing_hook	dq	0
if used _epoll_tv_msecs
	_epoll_tv_msecs dq	0
end if
; if (epoll_unixconnect_forgiving & used epoll$outbound) | defined include_everything
if epoll_unixconnect_forgiving & used epoll$outbound
	; see the commentary in the settings for what this is all about
	_epoll_unixconnect_map	dq	0
	_epoll_unixconnect_msecs	dq	0
else if defined include_everything
	; see the commentary in the settings for what this is all about
	_epoll_unixconnect_map	dq	0
	_epoll_unixconnect_msecs	dq	0
end if
if used epoll$inbound_delayed | defined include_everything
	_epoll_inbound_delayed_first	dq	0
	_epoll_inbound_delayed	dq	0
end if
}
end if



if used epoll$init | defined include_everything
	; this is called by ht$init... we determine our max fd #, and allocate room for it
falign
epoll$init:
	prolog	epoll$init
	; SIGPIPE has to be ignored
	sub	rsp, 152		; struct sigaction: 152 bytes
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, 152
	call	memset32
	; kernel_sigaction.h says: handler, unsigned long flags, restorer, then the sa_mask
	mov	qword [rsp], 1		; SIG_IGN
	mov	qword [rsp+8], 0x14000000	; SA_RESTORER | SA_RESTART
	mov	qword [rsp+16], .rt_sigreturn
	mov	qword [rsp+24], 1 shl 12	; 1 shl (SIGPIPE - 1)
	mov	eax, syscall_rt_sigaction
	mov	edi, 13		; SIGPIPE
	mov	rsi, rsp
	xor	edx, edx
	mov	r10d, 8	; sizeof(sigset_t)
	syscall
	mov	eax, syscall_getrlimit
	mov	edi, 7		; RLIMIT_NOFILE
	mov	rsi, rsp
	syscall
	mov	rcx, epoll_minfds
	mov	rax, qword [rsp+8]
	cmp	rax, rcx
	cmovl	rax, rcx
	mov	qword [rsp], rax
	mov	rax, qword [rsp+8]
	cmp	rax, rcx
	cmovl	rax, rcx
	mov	qword [rsp+8], rax
	mov	eax, syscall_setrlimit
	mov	edi, 7
	mov	rsi, rsp
	syscall
	mov	eax, syscall_getrlimit
	mov	edi, 7
	mov	rsi, rsp
	syscall
	cmp	qword [rsp], epoll_minfds
	jl	.error_minfds
	mov	rdi, qword [rsp]	; rlim_cur
	mov	[_epoll_fds], rdi
	mov	rdi, [_epoll_fds]
	sub	rdi, 1
	mov	eax, syscall_epoll_create
	syscall
	cmp	eax, -1
	je	.error_epoll_create
	mov	[_epoll_fd], rax
	mov	rdi, rax
	mov	eax, syscall_fcntl
	mov	esi, 2		; F_SETFD
	mov	edx, 1		; CLOEXEC
	syscall
	test	eax, eax
	jnz	.error_fcntl
	mov	rdi, _epoll_tv_secs
	xor	esi, esi
	call	gettimeofday
	mov	rax, [_epoll_tv_secs]
	mov	[_epoll_inittime], rax
	xor	edi, edi	; sort order required.
	call	unsignedmap$new
	mov	[_epoll_timemap], rax
	add	rsp, 152
if used epoll$outbound_hostname | used dns$lookup_ipv4 | defined include_everything
	call	dns$init
end if
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$init
end if
	mov	edi, 1
	call	unsignedmap$new
	mov	[_epoll_serviceable], rax
if epoll_unixconnect_forgiving & used epoll$outbound
	mov	edi, 1		; insert order very important here
	call	unsignedmap$new
	mov	[_epoll_unixconnect_map], rax
end if
if used epoll$inbound_delayed | defined include_everything
	cmp	qword [_epoll_inbound_delayed_first], 0
	je	.freshy
	; otherwise, we are re-initializing (presumably after a fork)
	; so, we go through our delayed list and add them now
	mov	rdi, [_epoll_inbound_delayed]
	mov	rsi, .delayed_epoll_add
	call	list$clear
end if
	epilog
if used epoll$inbound_delayed | defined include_everything
calign
.freshy:
	call	list$new
	mov	[_epoll_inbound_delayed], rax
	mov	dword [_epoll_inbound_delayed_first], 1
	epilog
falign
.delayed_epoll_add:
	; rdi == the epoll object (with its associated fd) that we need to do our epoll add to
	sub	rsp, 40
	mov	rax, rdi
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rax+epoll_fd_ofs]
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	ret
end if
calign
.rt_sigreturn:
	mov	rax, syscall_rt_sigreturn
	syscall
	ret	; ??

calign
.error_minfds:
	mov	rdi, .minfds_str
	call	string$to_stdoutln
        mov     eax, syscall_exit
        mov     edi, 97
        syscall
calign
.error_epoll_create:
	mov	rdi, .epoll_str
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 96
	syscall
calign
.error_fcntl:
	mov	rdi, .fcntl_str
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 95
	syscall
cleartext .minfds_str,'Minimum file descriptors insufficient'
cleartext .epoll_str,'epoll_create failed'
cleartext .fcntl_str,'fcntl(epoll fd, F_SETFD, 1) failed'

end if



if used epoll$udpserver | defined include_everything
	; three arguments: address buffer in rdi, length of same in esi, epoll vmethod object in rdx
	; returns 1 on success, 0 on error (we'll kill the epoll object in rdx on error)

	; NOTE ON the epoll object in rdx: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings.
falign
epoll$udpserver:
	prolog	epoll$udpserver
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	; find the bottom-most io object in the chain of rdx
calign
.chainwalk:
	cmp	qword [rdx+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdx, [rdx+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rsp+16], rdx
	mov	dword [rdx+epoll_udpserver_ofs], 1
	call	socket$udp
	cmp	eax, 0
	jl	.error
	mov	rdi, [rsp+16]	; our object
	mov	[rdi+epoll_fd_ofs], rax	; save our fd
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 2		; SO_REUSEADDR
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	mov	dword [r10], 1
	mov	dword [r10+4], epoll_linger_time
	mov	eax, syscall_setsockopt
	syscall
	mov	eax, syscall_bind
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	test	eax, eax
	jnz	.close_error
	mov	eax, syscall_listen
	mov	rdi, [rsp+24]
	mov	esi, 512
	syscall
	test	eax, eax
	jnz	.close_error
	mov	rdi, [rsp+24]
	call	socket$nonblocking
	test	eax, eax
	jz	.close_error
	; fire off our epoll_ctl
	mov	rax, [rsp+16]		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.close_error:
	mov	rdi, [rsp+24]
	mov	eax, syscall_close
	syscall
	add	rsp, 40
	xor	eax, eax
	epilog
calign
.error:
	add	rsp, 40
	xor	eax, eax
	epilog

end if


if used epoll$inbound | defined include_everything
	; three arguments: address buffer in rdi, length of same in esi, epoll vmethod object in rdx (its clone method will get called)
	; returns 1 on success, 0 on error.

	; NOTE ON the epoll object in rdx: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings, clone walks back to the top such that the entire chain can be reproduced
falign
epoll$inbound:
	prolog	epoll$inbound
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	; find the bottom-most io object in the chain of rdx
calign
.chainwalk:
	cmp	qword [rdx+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdx, [rdx+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rdx+epoll_listener_ofs], rsi
	mov	[rsp+16], rdx
	cmp	word [rdi], 1
	je	.unix
	; socket, SO_REUSEADDR, bind, listen, sockopts, nonblocking
	call	socket$tcp
	cmp	eax, 0
	jl	.error
	mov	rdi, [rsp+16]	; our object
	mov	[rdi+epoll_fd_ofs], rax	; save our fd
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 2		; SO_REUSEADDR
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	mov	dword [r10], 1
	mov	dword [r10+4], epoll_linger_time
	mov	eax, syscall_setsockopt
	syscall
	mov	eax, syscall_bind
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	test	eax, eax
	jnz	.close_error
	mov	eax, syscall_listen
	mov	rdi, [rsp+24]
	mov	esi, 512
	syscall
	test	eax, eax
	jnz	.close_error
if epoll_keepalive
	mov	eax, syscall_setsockopt
	mov	rdi, [rsp+24]
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 9		; SO_KEEPALIVE
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	syscall
end if
if epoll_linger
	mov	eax, syscall_setsockopt
	mov	rdi, [rsp+24]
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 0xd	; SO_LINGER
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 8
	syscall
end if
if epoll_nodelay
	mov	eax, syscall_setsockopt
	mov	rdi, [rsp+24]
	mov	esi, 6		; IPPROTO_TCP
	mov	edx, 1		; TCP_NODELAY
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	syscall
end if
	mov	rdi, [rsp+24]
	call	socket$nonblocking
	test	eax, eax
	jz	.close_error
	; fire off our epoll_ctl
	mov	rax, [rsp+16]		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.unix:
	call	socket$unix
	cmp	eax, 0
	jl	.error
	mov	rdi, [rsp+16]	; our object
	mov	[rdi+epoll_fd_ofs], rax	; save our fd
	mov	[rsp+24], rax
	mov	rdi, [rsp]
	add	rdi, 2
	mov	eax, syscall_unlink
	syscall
	mov	eax, syscall_bind
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	test	eax, eax
	jnz	.close_error
	mov	rdi, [rsp]
	add	rdi, 2
	mov	esi, 0x1ff		; 0777 chmod
	mov	eax, syscall_chmod
	syscall
	mov	eax, syscall_listen
	mov	rdi, [rsp+24]
	mov	esi, 512
	syscall
	test	eax, eax
	jnz	.close_error
	mov	rdi, [rsp+24]
	call	socket$nonblocking
	test	eax, eax
	jz	.close_error
	; fire off our epoll_ctl
	mov	rax, [rsp+16]		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.close_error:
	mov	rdi, [rsp+24]
	mov	eax, syscall_close
	syscall
	add	rsp, 40
	xor	eax, eax
	epilog
calign
.error:
	add	rsp, 40
	xor	eax, eax
	epilog
end if

if used epoll$shutdown | defined include_everything
	; single argument in rdi: an epoll iochain (we'll walk to the bottom)
falign
epoll$shutdown:
	prolog	epoll$shutdown
calign
.chainwalk:
	cmp	qword [rdi+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdi, [rdi+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	eax, syscall_shutdown
	xor	esi, esi
	mov	rdi, [rdi+epoll_fd_ofs]
	syscall
	epilog

end if



if used epoll$inbound_delayed | defined include_everything
	; three arguments: address buffer in rdi, length of same in esi, epoll vmethod object in rdx (its clone method will get called)
	; returns 1 on success, 0 on error.

	; this is the exact same as epoll$inbound above, only we do _not_ do epoll_add, and instead add them to a list
	; such that the next call to epoll$init _then_ adds them last (useful for listen/accept then fork then reinit of epoll)

	; NOTE ON the epoll object in rdx: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings, clone walks back to the top such that the entire chain can be reproduced
falign
epoll$inbound_delayed:
	prolog	epoll$inbound_delayed
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	; find the bottom-most io object in the chain of rdx
calign
.chainwalk:
	cmp	qword [rdx+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdx, [rdx+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rdx+epoll_listener_ofs], rsi
	mov	[rsp+16], rdx
	cmp	word [rdi], 1
	je	.unix
	; socket, SO_REUSEADDR, bind, listen, sockopts, nonblocking
	call	socket$tcp
	cmp	eax, 0
	jl	.error
	mov	rdi, [rsp+16]	; our object
	mov	[rdi+epoll_fd_ofs], rax	; save our fd
	mov	[rsp+24], rax
	mov	rdi, rax
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 2		; SO_REUSEADDR
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	mov	dword [r10], 1
	mov	dword [r10+4], epoll_linger_time
	mov	eax, syscall_setsockopt
	syscall
	mov	eax, syscall_bind
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	test	eax, eax
	jnz	.close_error
	mov	eax, syscall_listen
	mov	rdi, [rsp+24]
	mov	esi, 512
	syscall
	test	eax, eax
	jnz	.close_error
if epoll_keepalive
	mov	eax, syscall_setsockopt
	mov	rdi, [rsp+24]
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 9		; SO_KEEPALIVE
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	syscall
end if
if epoll_linger
	mov	eax, syscall_setsockopt
	mov	rdi, [rsp+24]
	mov	esi, 1		; SOL_SOCKET
	mov	edx, 0xd	; SO_LINGER
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 8
	syscall
end if
if epoll_nodelay
	mov	eax, syscall_setsockopt
	mov	rdi, [rsp+24]
	mov	esi, 6		; IPPROTO_TCP
	mov	edx, 1		; TCP_NODELAY
	mov	r10, rsp
	add	r10, 32
	mov	r8d, 4
	syscall
end if
	mov	rdi, [rsp+24]
	call	socket$nonblocking
	test	eax, eax
	jz	.close_error

	; unlike the normal epoll$inbound, we just add this to the delayed list
	mov	rdi, [_epoll_inbound_delayed]
	mov	rsi, [rsp+16]		; our object
	call	list$push_back

	add	rsp, 40
	mov	eax, 1
	epilog
calign
.unix:
	call	socket$unix
	cmp	eax, 0
	jl	.error
	mov	rdi, [rsp+16]	; our object
	mov	[rdi+epoll_fd_ofs], rax	; save our fd
	mov	[rsp+24], rax
	mov	rdi, [rsp]
	add	rdi, 2
	mov	eax, syscall_unlink
	syscall
	mov	eax, syscall_bind
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	test	eax, eax
	jnz	.close_error
	mov	rdi, [rsp]
	add	rdi, 2
	mov	esi, 0x1ff		; 0777 chmod
	mov	eax, syscall_chmod
	syscall
	mov	eax, syscall_listen
	mov	rdi, [rsp+24]
	mov	esi, 512
	syscall
	test	eax, eax
	jnz	.close_error
	mov	rdi, [rsp+24]
	call	socket$nonblocking
	test	eax, eax
	jz	.close_error

	; unlike the normal epoll$inbound, we just add this to the delayed list
	mov	rdi, [_epoll_inbound_delayed]
	mov	rsi, [rsp+16]		; our object
	call	list$push_back

	add	rsp, 40
	mov	eax, 1
	epilog
calign
.close_error:
	mov	rdi, [rsp+24]
	mov	eax, syscall_close
	syscall
	add	rsp, 40
	xor	eax, eax
	epilog
calign
.error:
	add	rsp, 40
	xor	eax, eax
	epilog
end if



if used epoll$fatality | defined include_everything
	; single argument in rdi: epoll object
	; NOTE: due to io chaining, if we signal that an object needs to get properly destroyed
	; we walk back up to the top here and call THAT object's destroy, which will in turn get
	; back to this object
falign
epoll$fatality:
	prolog	epoll$fatality

if epoll_debug
	push	rdi
	mov	rdi, .fatalstr
	call	string$to_stdoutln
	pop	rdi
end if
	cmp	qword [rdi+io_parent_ofs], 0
	jne	.moveup
	mov	rsi, [rdi]	; load its vmethod table
	call	qword [rsi+epoll_vdestroy]
	epilog
if epoll_debug
cleartext .fatalstr, 'epoll$fatality'
end if
calign
.hasparent:
	cmp	qword [rdi+io_parent_ofs], 0
	jne	.moveup
	mov	rsi, [rdi]	; load its vmethod table
	call	qword [rsi+epoll_vdestroy]
	epilog
calign
.moveup:
	mov	rdi, [rdi+io_parent_ofs]
	jmp	.hasparent

end if




if used epoll$outbound | defined include_everything
	; three arguments: address buffer in rdi, length of same in esi, epoll vmethod object in rdx
	; returns 1 on success, 0 on failure, if failure occurs, epoll vmethod object is cleaned up, error called, and destroyed

	; NOTE ON the epoll object in rdx: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings, clone walks back to the top such that the entire chain can be reproduced
falign
epoll$outbound:
	prolog	epoll$outbound
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	; find the bottom-most io object in the chain of rdx
calign
.chainwalk:
	cmp	qword [rdx+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdx, [rdx+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rsp+16], rdx
	cmp	word [rdi], 1
	je	.unix
	call	socket$tcp
	cmp	eax, 0
	jl	.error
	mov	[rsp+24], rax
	mov	rdx, [rsp+16]
	mov	[rdx+epoll_fd_ofs], rax	; save our fd
	mov	rdi, rax
	call	socket$nonblocking
	test	eax, eax
	jz	.error
if epoll_outbound_cloexec
	mov	rdi, [rsp+24]
	mov	eax, syscall_fcntl
	mov	esi, 2		; F_SETFD
	mov	edx, 1		; CLOEXEC
	syscall
end if
	mov	eax, syscall_connect
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	cmp	eax, -115		; EINPROGRESS
	jne	.error
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
calign
.allgood:
	; fire off our epoll_ctl
	mov	rax, [rsp+16]		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 4		; EPOLLOUT
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.unix:
	call	socket$unix
	cmp	eax, 0
	jl	.error
	mov	[rsp+24], rax
	mov	rdx, [rsp+16]
	mov	[rdx+epoll_fd_ofs], rax	; save our fd
	mov	rdi, rax
	call	socket$nonblocking
	test	eax, eax
	jz	.error
if epoll_outbound_cloexec
	mov	rdi, [rsp+24]
	mov	eax, syscall_fcntl
	mov	esi, 2		; F_SETFD
	mov	edx, 1		; CLOEXEC
	syscall
end if
	mov	eax, syscall_connect
	mov	rdi, [rsp+24]		; fd
	mov	rsi, [rsp]		; address
	mov	rdx, [rsp+8]		; addrlength
	syscall
	; unix connects can happen atomically
	test	rax, rax
	jz	.unix_connected
if epoll_unixconnect_forgiving
	cmp	eax, -11		; EAGAIN
	je	.unix_forgiving
end if
	cmp	eax, -115		; EINPROGRESS
	jne	.error
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
	; fire off our epoll_ctl
	mov	rax, rdi		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 4		; EPOLLOUT
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
if epoll_unixconnect_forgiving
calign
.unix_forgiving:
	; So, per our lengthy commentary re: this setting, we'll do exactly what the
	; error message suggests, try again later :-)
	; first up, we need a copy of the address
	mov	edi, sockaddr_un_size
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	edx, sockaddr_un_size
	call	memcpy
	; now, insert it into our forgiving map
	mov	rdi, [_epoll_unixconnect_map]
	mov	rsi, [rsp+16]		; our object
	mov	rdx, [rsp+32]		; our copy of the address
	mov	qword [rsi+epoll_fd_ofs], -1
	call	unsignedmap$insert_unique
	mov	rdi, [rsp+24]	; our fd
	mov	eax, syscall_close
	syscall
	; now, we return 1 indicating it is underway
	add	rsp, 40
	mov	eax, 1
	epilog
end if
calign
.unix_connected:
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.unix_connected_allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
calign
.unix_connected_allgood:
	; fire off our epoll_ctl
	mov	rax, rdi		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	; call our vconnected
	mov	rdi, [rsp+16]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_vconnected]
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.error:
	mov	rdi, [rsp+16]	; get our epoll object pointer
	call	epoll$fatality	; will walk to the top, and then call vdestroy for the topmost object
	xor	eax, eax
	add	rsp, 40
	epilog
end if



if used epoll$outbound_witherror | defined include_everything
	; three arguments: address buffer in rdi, length of same in esi, epoll vmethod object in rdx
	; returns 1 on success, 0 on failure, if failure occurs, epoll vmethod object is cleaned up, error called, and destroyed
	
	; this is exactly the same as above, only we call verror if something goes wrong out of the gate

	; NOTE ON the epoll object in rdx: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings, clone walks back to the top such that the entire chain can be reproduced
falign
epoll$outbound_witherror:
	prolog	epoll$outbound_witherror
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	; find the bottom-most io object in the chain of rdx
calign
.chainwalk:
	cmp	qword [rdx+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdx, [rdx+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rsp+16], rdx
	cmp	word [rdi], 1
	je	.unix
	call	socket$tcp
	cmp	eax, 0
	jl	.error
	mov	[rsp+24], rax
	mov	rdx, [rsp+16]
	mov	[rdx+epoll_fd_ofs], rax	; save our fd
	mov	rdi, rax
	call	socket$nonblocking
	test	eax, eax
	jz	.error
if epoll_outbound_cloexec
	mov	rdi, [rsp+24]
	mov	eax, syscall_fcntl
	mov	esi, 2		; F_SETFD
	mov	edx, 1		; CLOEXEC
	syscall
end if
	mov	eax, syscall_connect
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	syscall
	cmp	eax, -115		; EINPROGRESS
	jne	.error
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
calign
.allgood:
	; fire off our epoll_ctl
	mov	rax, [rsp+16]		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 4		; EPOLLOUT
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.unix:
	call	socket$unix
	cmp	eax, 0
	jl	.error
	mov	[rsp+24], rax
	mov	rdx, [rsp+16]
	mov	[rdx+epoll_fd_ofs], rax	; save our fd
	mov	rdi, rax
	call	socket$nonblocking
	test	eax, eax
	jz	.error
if epoll_outbound_cloexec
	mov	rdi, [rsp+24]
	mov	eax, syscall_fcntl
	mov	esi, 2		; F_SETFD
	mov	edx, 1		; CLOEXEC
	syscall
end if
	mov	eax, syscall_connect
	mov	rdi, [rsp+24]		; fd
	mov	rsi, [rsp]		; address
	mov	rdx, [rsp+8]		; addrlength
	syscall
	; unix connects can happen atomically
	test	rax, rax
	jz	.unix_connected
if epoll_unixconnect_forgiving
	cmp	eax, -11		; EAGAIN
	je	.unix_forgiving
end if
	cmp	eax, -115		; EINPROGRESS
	jne	.error
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
	; fire off our epoll_ctl
	mov	rax, rdi		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 4		; EPOLLOUT
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
if epoll_unixconnect_forgiving
calign
.unix_forgiving:
	; So, per our lengthy commentary re: this setting, we'll do exactly what the
	; error message suggests, try again later :-)
	; first up, we need a copy of the address
	mov	edi, sockaddr_un_size
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	edx, sockaddr_un_size
	call	memcpy
	; now, insert it into our forgiving map
	mov	rdi, [_epoll_unixconnect_map]
	mov	rsi, [rsp+16]		; our object
	mov	rdx, [rsp+32]		; our copy of the address
	mov	qword [rsi+epoll_fd_ofs], -1
	call	unsignedmap$insert_unique
	mov	rdi, [rsp+24]	; our fd
	mov	eax, syscall_close
	syscall
	; now, we return 1 indicating it is underway
	add	rsp, 40
	mov	eax, 1
	epilog
end if
calign
.unix_connected:
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.unix_connected_allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
calign
.unix_connected_allgood:
	; fire off our epoll_ctl
	mov	rax, rdi		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	; call our vconnected
	mov	rdi, [rsp+16]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_vconnected]
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.error:
	; UNLIKE the normal epoll$outbound, we _must_ call verror first
	mov	rdi, [rsp+16]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_verror]
	;
	mov	rdi, [rsp+16]	; get our epoll object pointer
	call	epoll$fatality	; will walk to the top, and then call vdestroy for the topmost object
	xor	eax, eax
	add	rsp, 40
	epilog
end if

if used epoll$unix_reconnect | defined include_everything
	; two arguments: rdi == address buffer (sockaddr_un_size), rsi == epoll object (real, not io chained)
	; this is basically the same as above, only we'll call verror if an error occurs prior to destroying the object
	; TODO: merge this with the above outbound_witherror function as it does the same thing
falign
epoll$unix_reconnect:
	prolog	epoll$unix_reconnect
	sub	rsp, 40
	mov	[rsp], rdi
	mov	[rsp+16], rsi
	call	socket$unix
	cmp	eax, 0
	jl	.error
	mov	[rsp+24], rax
	mov	rdx, [rsp+16]
	mov	[rdx+epoll_fd_ofs], rax	; save our fd
	mov	rdi, rax
	call	socket$nonblocking
	test	eax, eax
	jz	.error
if epoll_outbound_cloexec
	mov	rdi, [rsp+24]
	mov	eax, syscall_fcntl
	mov	esi, 2		; F_SETFD
	mov	edx, 1		; CLOEXEC
	syscall
end if
	mov	eax, syscall_connect
	mov	rdi, [rsp+24]		; fd
	mov	rsi, [rsp]		; address
	mov	edx, sockaddr_un_size
	syscall
	; unix connects can happen atomically
	test	rax, rax
	jz	.unix_connected
if epoll_unixconnect_forgiving
	cmp	eax, -11		; EAGAIN
	je	.unix_forgiving
end if
	cmp	eax, -115		; EINPROGRESS
	jne	.error
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
	; fire off our epoll_ctl
	mov	rax, rdi		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 4		; EPOLLOUT
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.allgood:
	; fire off our epoll_ctl
	mov	rax, [rsp+16]		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 4		; EPOLLOUT
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 40
	mov	eax, 1
	epilog
if epoll_unixconnect_forgiving
calign
.unix_forgiving:
	; So, per our lengthy commentary re: this setting, we'll do exactly what the
	; error message suggests, try again later :-)
	; first up, we need a copy of the address
	mov	edi, sockaddr_un_size
	call	heap$alloc
	mov	[rsp+32], rax
	mov	rdi, rax
	mov	rsi, [rsp]
	mov	edx, sockaddr_un_size
	call	memcpy
	; now, insert it into our forgiving map
	mov	rdi, [_epoll_unixconnect_map]
	mov	rsi, [rsp+16]		; our object
	mov	rdx, [rsp+32]		; our copy of the address
	mov	qword [rsi+epoll_fd_ofs], -1
	call	unsignedmap$insert_unique
	mov	rdi, [rsp+24]	; our fd
	mov	eax, syscall_close
	syscall
	; now, we return 1 indicating it is underway
	add	rsp, 40
	mov	eax, 1
	epilog
end if
calign
.unix_connected:
	; do readtimeout
	mov	rdi, [rsp+16]
	cmp	qword [rdi+epoll_readtimeout_ofs], 0
	je	.unix_connected_allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rsi, rdi		; our object as arg
	mov	rdi, [rdi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+16]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
calign
.unix_connected_allgood:
	; fire off our epoll_ctl
	mov	rax, rdi		; our object
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp+24]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	; call our vconnected
	mov	rdi, [rsp+16]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_vconnected]
	add	rsp, 40
	mov	eax, 1
	epilog
calign
.error:
	; UNLIKE the normal epoll$outbound, we _must_ call verror first
	mov	rdi, [rsp+16]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_verror]
	; now we can proceed with destruction
	mov	rdi, [rsp+16]	; get our epoll object pointer
	call	epoll$fatality	; will walk to the top, and then call vdestroy for the topmost object
	xor	eax, eax
	add	rsp, 40
	epilog

end if


if used epoll$do_unix_forgiving | defined include_everything
	; no arguments, called from epoll$iteration _right before_ the call to epoll wait
falign
epoll$do_unix_forgiving:
	prolog	epoll$do_unix_forgiving
	mov	rdi, [_epoll_unixconnect_map]
	mov	rax, [_epoll_tv_msecs]
	mov	rcx, [_epoll_unixconnect_msecs]
	mov	rdx, rax
	cmp	qword [rdi+_avlofs_parent], 0
	jne	.doit
	epilog
calign
.doit:
	sub	rax, rcx
	cmp	rax, 10
	jb	.maybenot
	mov	[_epoll_unixconnect_msecs], rdx
	
	push	rbx
	mov	rbx, rdi		; the map we need to service

if defined unix_forgiving_queuesize_debug
	mov	rdi, [rdi+_avlofs_right]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	; make a new map to replace the old one with
	mov	edi, 1			; insert order
	call	unsignedmap$new
	mov	[_epoll_unixconnect_map], rax
	mov	rdi, rbx
	mov	rsi, .reconnect
	call	unsignedmap$clear
	mov	rdi, rbx
	call	heap$free
	pop	rbx

	epilog
calign
.maybenot:
	epilog

falign
.reconnect:
	mov	rax, [_epoll_unixconnect_map]
	cmp	qword [rax+_avlofs_right], 0
	jne	.reconnect_alreadystuffed
	; rdi == epoll object, rsi == address buffer
	push	rsi
	xchg	rdi, rsi
	call	epoll$unix_reconnect
	; regardless of what happened, free our address buffer
	pop	rdi
	call	heap$free
	ret
calign
.reconnect_alreadystuffed:
	; just put them straight back in
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, rax
	call	unsignedmap$insert_unique
	ret

end if




if used epoll$outbound_hostname | defined include_everything

	; three arguments: hostname string in rdi, port in esi, epoll vmethod object in rdx
	; this will do a DNS query lookup of the hostname, and if that fails, will call the error
	; and if that succeeds, a normal connect commences with the result of the lookup

	; NOTE ON the epoll object in rdx: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings, clone walks back to the top such that the entire chain can be reproduced
falign
epoll$outbound_hostname:
	prolog	epoll$outbound_hostname
	; find the bottom-most io object in the chain of rdx
calign
.chainwalk:
	cmp	qword [rdx+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdx, [rdx+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rdx+epoll_other_ofs], rsi		; save the port for later use
	mov	rcx, rdx				; setup our arbitrary argument to the dns layer
	mov	rsi, .success
	mov	rdx, .failure
	call	dns$lookup_ipv4
	epilog
calign
.success:
	; despite these being local labels, they are called as normal functions by the dns layer
	; rdi == our original hostname, rsi == our epoll vmethod object, and edx == our network byte order host
	sub	rsp, 16 + sockaddr_in_size
	mov	[rsp], rsi
	mov	[rsp+8], rdx
	lea	rdi, [rsp+16]
	xor	esi, esi
	mov	edx, sockaddr_in_size
	call	memset32
	lea	rdi, [rsp+16]		; our sockaddr_in address
	mov	rdx, [rsp]		; our epoll vmethod object
	mov	rax, [rdx+epoll_other_ofs]	; our port
	mov	rcx, [rsp+8]		; our network byte order host
	xchg	ah,al
	mov	word [rdi], 2		; AF_INET/PF_INET
	mov	word [rdi+2], ax	; htons(port)
	mov	dword [rdi+4], ecx
	mov	esi, sockaddr_in_size
	call	epoll$outbound
	add	rsp, 16 + sockaddr_in_size
	ret
calign
.failure:
	; lookup failed, call the error vmethod, then call the vcleanup, then free it
	push	rsi			; our object
	mov	rdi, rsi
	mov	rsi, [rdi]		; its vmethod table
	call	qword [rsi+epoll_verror]
	mov	rdi, [rsp]
	call	epoll$fatality		; will walk to the top and call topmost's vdestroy
	add	rsp, 8
	ret

end if


if used epoll$send_string | defined include_everything
	; convenience function to send out a string (as utf8)
	; two arguments: epoll object in rdi, string in rsi
falign
epoll$send_string:
	prolog	epoll$send_string
	push	r12 r13 r14
	mov	r12, rdi
	mov	rdi, rsi
	mov	r13, rsi
	call	string$utf8_length
	mov	r14, rax
	cmp	rax, 16384
	jge	.heapbased
	sub	rsp, rax
	mov	rsi, rsp
	mov	rdi, r13
	call	string$to_utf8
	mov	rdi, r12
	mov	rsi, rsp
	mov	rdx, r14
	mov	rcx, [rdi]		; our epoll object's vmethod table
	call	qword [rcx+epoll_vsend]
	add	rsp, r14
	pop	r14 r13 r12
	epilog
calign
.heapbased:
	mov	rdi, rax
	call	heap$alloc
	push	rax
	mov	rsi, rax
	mov	rdi, r13
	call	string$to_utf8
	mov	rdi, r12
	mov	rsi, [rsp]
	mov	rdx, r14
	mov	rcx, [rdi]		; our epoll object's vmethod table
	call	qword [rcx+epoll_vsend]
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 8
	pop	r14 r13 r12
	epilog
end if

if used epoll$send_string_crlf | defined include_everything
	; same but tosses 13,10 on the end
falign
epoll$send_string_crlf:
	prolog	epoll$send_string_crlf
	push	r12 r13 r14
	mov	r12, rdi
	mov	rdi, rsi
	mov	r13, rsi
	call	string$utf8_length
	mov	r14, rax
	cmp	rax, 16384
	jge	.heapbased
	sub	rsp, rax
	sub	rsp, 2
	mov	rsi, rsp
	mov	rdi, r13
	call	string$to_utf8
	mov	rdi, r12
	mov	rsi, rsp
	mov	rdx, r14
	mov	byte [rsi+rdx], 13
	mov	byte [rsi+rdx+1], 10
	add	rdx, 2
	mov	rcx, [rdi]		; our epoll object's vmethod table
	call	qword [rcx+epoll_vsend]
	add	rsp, r14
	add	rsp, 2
	pop	r14 r13 r12
	epilog
calign
.heapbased:
	mov	rdi, rax
	add	rdi, 2
	call	heap$alloc
	push	rax
	mov	rsi, rax
	mov	rdi, r13
	call	string$to_utf8
	mov	rdi, r12
	mov	rsi, [rsp]
	mov	rdx, r14
	mov	byte [rsi+rdx], 13
	mov	byte [rsi+rdx+1], 10
	add	rdx, 2
	mov	rcx, [rdi]		; our epoll object's vmethod table
	call	qword [rcx+epoll_vsend]
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 8
	pop	r14 r13 r12
	epilog
end if


if used epoll$established | defined include_everything
	; two arguments: socket/fd in rdi, epoll vmethod object in rsi
	; it is assumed that fd is already nonblocking and all set to go

	; NOTE ON the epoll object in rsi: actually, it is an io object descendent (of which epoll is one) whereby the LAST object in the chain
	; (which may be the first/only), MUST be an epoll object. This lets us chain io objects together nice and neatlike.
	; we walk down to the bottom here to do the epoll bindings, clone walks back to the top such that the entire chain can be reproduced
falign
epoll$established:
	prolog	epoll$established
	; find the bottom-most io object in the chain of rsi
calign
.chainwalk:
	cmp	qword [rsi+io_child_ofs], 0
	je	.chainwalk_done
	mov	rsi, [rsi+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rsi+epoll_fd_ofs], rdi
	sub	rsp, 24
	mov	[rsp+16], rdi		; fd
	mov	[rsp], rdi		; fd again
	mov	[rsp+8], rsi		; our object
	cmp	qword [rsi+epoll_readtimeout_ofs], 0
	je	.allgood
	; otherwise, a readtimeout has been specified in milliseconds, we need to add this value
	mov	rdi, [rsi+epoll_readtimeout_ofs]
	call	epoll$timer_new
	mov	rdi, [rsp+8]		; our object
	mov	[rdi+epoll_timerobject_ofs], rax
	mov	rax, rdi
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rsp]		; fd
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 24
	epilog
calign
.allgood:
	; fire off our epoll_ctl
	mov	rax, rsi		; our object
	mov	rdx, rdi		; our fd
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	sub	rsp, 24
	mov	r10, rsp
	mov	dword [rsp], 1		; EPOLLIN
	mov	qword [rsp+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	add	rsp, 48
	epilog
end if


if used epoll$sendcb | defined include_everything
	; three arguments: epoll vmethod object in rdi, callback function in rsi, callback argument in rdx
	; when this is called, the object in rdi can be any valid io chain, we epoll must be the LAST object in the chain
	; (which can also be the one and only), and we walk down the chain to find the actual epoll object, and then
	; set epoll_sendcb_ofs and epoll_sendcbarg_ofs.
	;
	; this is just a convenience function to save the applayer from having to walk the chain itself to set these
falign
epoll$sendcb:
	prolog	epoll$sendcb
calign
.chainwalk:
	cmp	qword [rdi+io_child_ofs], 0
	je	.chainwalk_done
	mov	rdi, [rdi+io_child_ofs]
	jmp	.chainwalk
calign
.chainwalk_done:
	mov	[rdi+epoll_sendcb_ofs], rsi
	mov	[rdi+epoll_sendcbarg_ofs], rdx
	epilog

end if



if used epoll$iteration | defined include_everything
	; does one pass only then returns
falign
epoll$iteration:
	if profile_epoll_iteration
		prolog	epoll$iteration
	else if public_funcs
		public epoll$iteration
	end if
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$hold
end if
	push	rbx r12 r13
	mov	r12, [_epoll_timemap]
	call	epoll$timestamp
	mov	rbx, rax
calign
.timeout_loop:
	mov	r12, [r12+_avlofs_next]
	test	r12, r12
	jz	.epoll_wait_indefinitely
	cmp	rbx, qword [r12+_avlofs_key]
	jb	.epoll_wait_mintime		; qword [r12+_avlofs_key] - rbx == time in ms to epoll_wait
	; else, key time is >= our timestamp, which means we are timing it out
	mov	rdi, qword [r12+_avlofs_value]
	mov	rdi, [rdi+8]			; get the epoll object out of the timer object
	mov	rsi, [rdi]			; load up the virtual method table into rsi
	call	qword [rsi+epoll_vtimeout]; 
	; that will return zero in eax if we are sposed to ignore (and thus reset it)
	; or a nonzero == full destruction of the entire deal
	test	eax, eax
	jnz	.timeout_loop_destruct
	mov	rdi, [r12+_avlofs_value]
	call	epoll$timer_reset_private
	mov	r12, [_epoll_timemap]		; r12 = first
	jmp	.timeout_loop
calign
.timeout_loop_destruct:
	; two possibilities here, one is that the timer object we are clearing
	; is the same as the one inside the epoll object (most common case)
	; the other is that they are independent, and the epoll object has a -different- timer object
	; in which case, we need to do an additional timer_clear of the timer object at [r12+_avlofs_value]
	mov	rsi, [r12+_avlofs_value]	; the timer object

	; for non-epoll pretenders (tui_* type goods), we have to check the special cases _before_ we check for epoll object goods
	cmp	dword [rsi+24], 1
	je	.timeout_loop_destruct_case3
	cmp	dword [rsi+24], 2
	je	.timeout_loop_destruct_case4
	mov	rdi, [rsi+8]			; get the epoll object out of the timer object
	cmp	rsi, [rdi+epoll_timerobject_ofs]
	jne	.timeout_loop_destruct_case2

if epoll_debug
	push	rdi rsi
	mov	rdi, .timeout_case1str
	call	string$to_stdoutln
	pop	rsi rdi
end if
	; otherwise, the timer object inside the epoll object is the same as the one we are clearing
	; make sure no special handling is taken care of for this object as well
	; and its own vdestroy will clear the timer
	call	epoll$fatality			; will walk to the top and call topmost's vdestroy
	mov	r12, [_epoll_timemap]		; r12 = first so we can keep going
	jmp	.timeout_loop
if epoll_debug
cleartext .timeout_case1str, 'epoll timeout_loop_destruct_case1'
cleartext .timeout_case2str, 'epoll timeout_loop_destruct_case2'
cleartext .timeout_case3str, 'epoll timeout_loop_destruct_case3'
cleartext .timeout_case4str, 'epoll timeout_loop_destruct_case4'
end if
calign
.timeout_loop_destruct_case2:
if epoll_debug
	push	rdi rsi
	mov	rdi, .timeout_case2str
	call	string$to_stdoutln
	pop	rsi rdi
end if
	; so, there are two different timers, the one that caused the timeout, and a different timer object in
	; the epoll object itself, which means we have to ALSO clear this timer because the epoll$destroy
	; won't have done it for us
	; timer object is sitting in rsi, we need to check its +24 offset to see if we need "special" handling
	call	epoll$fatality
	mov	rdi, [r12+_avlofs_value]
	call	epoll$timer_clear
	mov	r12, [_epoll_timemap]		; r12 = first
	jmp	.timeout_loop
calign
.timeout_loop_destruct_case4:
if epoll_debug
	push	rdi rsi
	mov	rdi, .timeout_case4str
	call	string$to_stdoutln
	pop	rsi rdi
end if
	; see the commentary atop as to why this is necessary... similar to case3, for tui_* pretenders
	; it is useful in certain circumstances to want the timer to _end_, but for no cleanup/destruct
	; to actually occur, so all we do in case4's instance is clear the timer
	mov	rdi, [r12+_avlofs_value]
	call	epoll$timer_clear
	mov	r12, [_epoll_timemap]
	jmp	.timeout_loop
calign
.timeout_loop_destruct_case3:
if epoll_debug
	push	rdi rsi
	mov	rdi, .timeout_case3str
	call	string$to_stdoutln
	pop	rsi rdi
end if
	; see the commentary atop as to why this is necessary... basically, for tui_* pretenders,
	; we also have to support actually heap$free'ing the epoll object in addition to calling its io_vdestroy
	; because tui_* objects don't actually heap$free themselves during cleanup
	mov	rdi, [rsi+8]			; get the epoll object out of the timer object
	push	rdi
	call	epoll$fatality
	pop	rdi
	call	heap$free
	mov	rdi, [r12+_avlofs_value]
	call	epoll$timer_clear
	mov	r12, [_epoll_timemap]
	jmp	.timeout_loop
calign
.epoll_wait_indefinitely:
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$release
end if
if epoll_unixconnect_forgiving & used epoll$outbound
	; per commentary in settings, deal with "forgiving unix stream socket connects"
	call	epoll$do_unix_forgiving
end if
	; setup call to epoll wait
	sub	rsp, epoll_stacksize * 12
	mov	eax, syscall_epoll_wait
	mov	rdi, [_epoll_fd]
	mov	rsi, rsp
	mov	edx, epoll_stacksize
	mov	r10d, -1			; block indefinitely
	syscall
	jmp	.process_epoll_wait
calign
.epoll_wait_mintime:
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$release
end if
if epoll_unixconnect_forgiving & used epoll$outbound
	; per commentary in settings, deal with "forgiving unix stream socket connects"
	call	epoll$do_unix_forgiving
end if
	; setup call to epoll wait
	sub	rsp, epoll_stacksize * 12
	mov	eax, syscall_epoll_wait
	mov	rdi, [_epoll_fd]
	mov	rsi, rsp
	mov	edx, epoll_stacksize
	mov	r10, qword [r12+_avlofs_key]
	sub	r10, rbx
	syscall
calign
.process_epoll_wait:
	; return result is in eax
	cmp	eax, 0
	jle	.nothingtodo
	mov	r12, rsp
	mov	r13d, eax
	call	epoll$timestamp
	mov	rbx, rax
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$hold
end if
	; see the commentary atop about what _epoll_serviceable is all about, but basically
	; we need to preprocess such that we don't inadvertently service an object that has been
	; destroyed _during_ the .process_epoll_loop
	; so first up, clear whatever may be sitting in our serviceable map
	mov	rdi, [_epoll_serviceable]
	xor	esi, esi		; no clear function
	call	unsignedmap$clear
	; now we have to prescan the list and insert them into our map
	push	r12 r13
calign
.prescan_epoll_loop:
	mov	rdi, [_epoll_serviceable]
	mov	rsi, [r12+4]
	call	unsignedmap$insert_unique
	add	r12, 12
	sub	r13d, 1
	jnz	.prescan_epoll_loop
	pop	r13 r12
calign
.process_epoll_loop:
	; make sure this object is still serviceable
	mov	rdi, [_epoll_serviceable]
	mov	rsi, [r12+4]
	call	unsignedmap$find
	test	eax, eax
	jz	.process_epoll_loop_deceased
	mov	edi, dword [r12]
	mov	rsi, qword [r12+4]
	call	epoll$activity
	add	r12, 12
	sub	r13d, 1
	jnz	.process_epoll_loop

	cmp	qword [_epoll_postprocessing_hook], 0
	jne	.process_epoll_loop_posthook

	add	rsp, epoll_stacksize * 12
	pop	r13 r12 rbx
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$release
end if
	if profile_epoll_iteration
		epilog
	else
		ret
	end if
calign
.process_epoll_loop_posthook:
	call	qword [_epoll_postprocessing_hook]

	add	rsp, epoll_stacksize * 12
	pop	r13 r12 rbx
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$release
end if
	if profile_epoll_iteration
		epilog
	else
		ret
	end if
calign
.process_epoll_loop_deceased:
	add	r12, 12
	sub	r13d, 1
	jnz	.process_epoll_loop

	cmp	qword [_epoll_postprocessing_hook], 0
	jne	.process_epoll_loop_posthook

	add	rsp, epoll_stacksize * 12
	pop	r13 r12 rbx
if used tui_render$updatedisplaylist | used tui_render$layoutchanged | used tui_render$nvrender | defined include_everything
	call	tui_lock$release
end if
	if profile_epoll_iteration
		epilog
	else
		ret
	end if
calign
.nothingtodo:
	add	rsp, epoll_stacksize * 12
	pop	r13 r12 rbx
	if profile_epoll_iteration
		epilog
	else
		ret
	end if
	ret
end if


if used epoll$timer_reset_private | defined include_everything
	; not meant to be called publically: (current timestamp is in rbx)
falign
epoll$timer_reset_private:
	push	rdi
	mov	rdx, rdi	; value object
	mov	rsi, [rdi+16]	; its key
	mov	rdi, [_epoll_timemap]
	call	unsignedmap$erase_specific
	mov	rsi, rbx
	mov	rdx, [rsp]
	mov	rcx, [rdx]	; the time in ms of the timer itself
	add	rsi, rcx	; added to the actual timestamp
	mov	[rdx+16], rsi	; its new key into the timemap
	mov	rdi, [_epoll_timemap]
	call	unsignedmap$insert
	pop	rdi
	ret
end if


if used epoll$activity | defined include_everything
	; not meant to be called publically: (current timestamp is in rbx)
falign
epoll$activity:
if epoll_debug
	push	rdi rsi
	mov	rdi, .epoll_event
	call	string$to_stdout
	mov	rdi, [rsp+8]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .epoll_event_fd
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	rdi, [rdi+epoll_fd_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rsi rdi
end if
	; edi == our epoll_event.events (EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLERR|etc)
	; rsi == our epoll object
	test	edi, 0x18		; EPOLLHUP == 0x10, EPOLLERR = 0x08
	jnz	.epoll_error
	test	edi, 4			; EPOLLOUT
	jnz	.epoll_write
	test	edi, 1			; EPOLLIN
	jnz	.epoll_read
if epoll_debug
	push	rdi
	mov	rdi, .epoll_unknownstr
	call	string$to_stdout
	pop	rdi
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	ret
if epoll_debug
cleartext .epoll_event, 'epoll_event: '
cleartext .epoll_event_fd, ' fd: '
cleartext .epoll_unknownstr, 'epoll_event UNKNOWN: '
cleartext .epoll_errorstr, 'epoll$activity epoll_error'
end if
calign
.epoll_error:
if epoll_debug
	push	rdi rsi
	mov	rdi, .epoll_errorstr
	call	string$to_stdoutln
	pop	rsi rdi
end if
	; Interesting rare condition here that we might have also received EPOLLIN at the same time:
	test	edi, 1
	jnz	.epoll_error_withread
	; HUP or ERR occurred, blast our epoll object accordingly
	sub	rsp, 32
	mov	[rsp], rsi
	mov	rdi, rsi
	mov	rsi, [rdi]		; load our virtual method table
	call	qword [rsi+epoll_verror]
	mov	rdi, [rsp]
	call	epoll$fatality		; will walk to the top and call topmost's vdestroy
	add	rsp, 32
	ret
calign
.epoll_error_withread_death:
	add	rsp, 160
	pop	rsi rdi
	; HUP or ERR occurred, blast our epoll object accordingly
	sub	rsp, 32
	mov	[rsp], rsi
	mov	rdi, rsi
	mov	rsi, [rdi]		; load our virtual method table
	call	qword [rsi+epoll_verror]
	mov	rdi, [rsp]
	call	epoll$fatality		; will walk to the top and call topmost's vdestroy
	add	rsp, 32
	ret
calign
.epoll_error_withread:
	push	rdi rsi
	; simplified version of what happens with epoll_read:
	sub	rsp, 160
	mov	[rsp], rsi		; save our object
	mov	rdi, rsi
	mov	rdx, [rsi+epoll_listener_ofs]
	mov	rcx, [rsi+epoll_fd_ofs]
	mov	[rsp+8], rdx
	mov	[rsp+16], rcx		; save our fd
	test	rdx, rdx
	jnz	.epoll_error_withread_death	; accept + EPOLLIN == revert to original error state
	mov	rdx, [rdi+epoll_inbuf_ofs]
	mov	[rsp+8], rdx		; our input buffer
	; read loop until we get anything other than EAGAIN/EWOULDBLOCK
calign
.epoll_error_readloop:
	mov	rdi, [rsp+8]
	mov	esi, epoll_readsize
	call	buffer$reserve
	; read needs: fd in rdi, buffer in rsi, size in rdx
	mov	rsi, [rsp+8]
	mov	rdi, [rsp+16]
	mov	eax, syscall_read
	mov	edx, epoll_readsize
	mov	rsi, [rsi]		; the endptr conveniently at the first spot
	syscall
	; rax < 0 == error, but could be EAGAIN
	; in our epoll_error_withread condition, doesn't matter
	cmp	rax, 0
	jle	.epoll_error_readdone
	cmp	rax, epoll_readsize
	jl	.epoll_error_appenddone
	mov	rdi, [rsp+8]		; input buffer
	mov	rsi, rax		; our # of bytes read
	call	buffer$append_nocopy
	jmp	.epoll_error_readloop
calign
.epoll_error_appenddone:
	mov	rdi, [rsp+8]		; input buffer
	mov	rsi, rax		; our # of bytes read
	call	buffer$append_nocopy
calign
.epoll_error_readdone:
	; so here, if there is a nonzero amount of data in the buffer, call the vreceive function
	; and check its return status to see whether we should be destroying ourselves
	; and here is where we deviate from the normal epoll_read condition:
	; since we already know there is ALSO an error condition, don't bother with verror
	; and fatality _if_ vreceive already said to teardown
	mov	rcx, [rsp+8]
	cmp	qword [rcx+8], 0	; buffer_length_ofs
	jne	.epoll_error_readcall
	; otherwise, zero bytes sitting in the buffer, proceed with normal error:
calign
.epoll_error_readkill:
	add	rsp, 160
	pop	rsi rdi
	; HUP or ERR occurred, blast our epoll object accordingly
	sub	rsp, 32
	mov	[rsp], rsi
	mov	rdi, rsi
	mov	rsi, [rdi]		; load our virtual method table
	call	qword [rsi+epoll_verror]
	mov	rdi, [rsp]
	call	epoll$fatality		; will walk to the top and call topmost's vdestroy
	add	rsp, 32
	ret
calign
.epoll_error_readcall:
	; call vreceive with our input buffer
	mov	rdi, [rsp]		; the epoll object
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]		; vmethod table
	call	qword [rcx+epoll_vreceive]
	; since we are tearing down no matter what, we don't need to deal with epoll_inbuf_accumulate
	; so, one of two things here, the ONLY difference being: if vreceive returned true, we do NOT
	; call verror, and instead quietly do our teardown
	test	eax, eax
	jz	.epoll_error_readkill	; this will call verror and teardown
	; otherwise, we do not call verror, and quietly teardown
	add	rsp, 160
	pop	rsi rdi
	; HUP or ERR occurred, blast our epoll object accordingly
	; rsi is our epoll object:
	mov	rdi, rsi
	call	epoll$fatality
	ret

calign
.epoll_write:
	; connection attempt or previously-enabled EPOLLOUT (due to write buffer ending up full) are the only ways this gets triggered
	sub	rsp, 24
	mov	[rsp], rsi
	mov	edx, [rsi+epoll_partialsend_ofs]
	test	rdx, rdx
	jz	.epoll_outbound_connected
	; otherwise, epoll_partialsend_ofs was nonzero, which means we set it when we saturated the output buffers.
	; if we still have data to go, send it, otherwise, EPOLL_CTL_MOD it back to EPOLLIN only and return
	mov	rcx, [rsi+epoll_outbuf_ofs]
	cmp	qword [rcx+buffer_length_ofs], 0
	je	.epoll_write_clear
	; else, there is still data left to go in the out buffer
	mov	[rsp+8], rcx			; our output buffer
	mov	rdx, [rsi+epoll_fd_ofs]
	mov	[rsp+16], rdx			; our fd
	; burning purpose: attempt to write the entirety of our output buffer
	mov	rdi, rdx			; our fd
	mov	rsi, [rcx+buffer_itself_ofs]	; the output buffer
	mov	rdx, [rcx+buffer_length_ofs]
	mov	eax, syscall_write
	syscall
	cmp	rax, 0
	jle	.epoll_write_error
	mov	rsi, rax			; the number of bytes we wrote
	mov	rdi, [rsp+8]			; our output buffer
	call	buffer$consume
	; now, if we have no more data to send, EPOLL_CTL_MOd back to EPOLLIN only and return
	; otherwise, we have more data to send, so leave everything as is and return
	mov	rcx, [rsp+8]			; our output buffer
	cmp	qword [rcx+buffer_length_ofs], 0
	je	.epoll_write_clear
	add	rsp, 24
	ret
calign
.epoll_write_clear:
	mov	rdi, [rsp]			; our object
	mov	dword [rdi+epoll_partialsend_ofs], 0	; clear the flag set previously... TODO: is this necessary?
	mov	esi, 3				; EPOLL_CTL_MOD
	mov	rdx, [rdi+epoll_fd_ofs]		; load up our fd
	mov	r10, rsp
	add	r10, 8
	mov	dword [r10], 1			; EPOLLIN
	mov	qword [r10+4], rdi		; our object
	mov	eax, syscall_epoll_ctl
	mov	rdi, [_epoll_fd]
	syscall
	mov	rdi, [rsp]
	cmp	qword [rdi+epoll_sendcb_ofs], 0
	jne	.epoll_write_clear_callback
	add	rsp, 24
	ret
calign
.epoll_write_clear_callback:
	mov	rdx, rdi
	mov	rdi, [rdi+epoll_sendcbarg_ofs]
	mov	esi, 1
	call	qword [rdx+epoll_sendcb_ofs]
	add	rsp, 24
	ret
if epoll_debug
cleartext .epoll_write_errorstr, 'epoll$activity epoll_write_error'
end if
calign
.epoll_write_error:
	cmp	rax, -11
	je	.epoll_write_quickret		; we should NOT receive these here... TODO: remove me perhaps.
	; otherwise, we need to do a proper teardown
if epoll_debug
	push	rdi rsi rdx
	mov	rdi, .epoll_write_errorstr
	call	string$to_stdoutln
	pop	rdx rsi rdi
end if
	mov	rdi, [rsp]
	mov	rdx, [rdi+epoll_fd_ofs]
	mov	[rsp+16], rdx			; save our fd
	mov	rsi, [rdi]
	call	qword [rsi+epoll_verror]
	mov	rdi, [rsp]
	call	epoll$fatality			; will walk to the top and call topmost's vdestroy
	add	rsp, 24
	ret
calign
.epoll_outbound_connected:
	mov	rdi, [rsp]	; our object
	mov	rsi, [rdi]	; our virtual method table
	call	qword [rsi+epoll_vconnected]
	jmp	.epoll_write_clear
calign
.epoll_write_quickret:
	add	rsp, 24
	ret
calign
.epoll_recvfrom:
	; the most we'll ever get from a udp fragmented bundle of joy is 64kb
	mov	rdi, [rsp+8]
	mov	esi, 65536
	call	buffer$reserve
	mov	rsi, [rsp+8]	; epoll_inbuf_ofs
	mov	rdi, [rsp+16]	; fd
	mov	edx, 65536	; length
	xor	r10d, r10d	; flags
	lea	r8, [rsi+buffer_user_ofs]
	lea	r9, [rsp+64]
	mov	rsi, [rsi+buffer_itself_ofs]
	mov	eax, syscall_recvfrom
	mov	qword [r9], 24	; 24 bytes max for our buffer_user_ofs
	syscall
	cmp	rax, 0
	jle	.read_return	; anything for a UDP listener that is <= 0 == bailout, no?
	mov	rdi, [rsp+8]	; epoll_inbuf_ofs
	mov	rsi, rax
	call	buffer$append_nocopy
	; call our receive function, then reset and continue
	mov	rcx, [rsp+8]	; epoll_inbuf_ofs
	mov	rdi, [rsp]	; the epoll object
	mov	rsi, [rcx+buffer_itself_ofs]	; pointer to data waiting
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]	; vmethod table
	call	qword [rcx+epoll_vreceive]
	; reset the buffer
	mov	rdi, [rsp+8]
	call	buffer$reset
	jmp	.epoll_recvfrom
calign
.epoll_read:
	; check to see if this is a listener, and if it is, do an accept loop here until it returns EAGAIN/EWOULDBLOCK
	sub	rsp, 160
	mov	[rsp], rsi	; save our object
	mov	rdi, rsi
	mov	rdx, [rsi+epoll_listener_ofs]
	mov	rcx, [rsi+epoll_fd_ofs]
	mov	[rsp+8], rdx	; save our address size for convenience for accept loop later (if !accepting, thsi is overwritten/ignored)
	mov	[rsp+16], rcx	; save our fd
	test	rdx, rdx
	jnz	.acceptloop
	; else, this is not a listener socket, repeatedly do normal reads on its fd, pumping nonzero reads
	mov	rdx, [rdi+epoll_inbuf_ofs]
	mov	[rsp+8], rdx	; our input buffer
	cmp	dword [rdi+epoll_udpserver_ofs], 0
	jne	.epoll_recvfrom
calign
.readloop:
	mov	rdi, [rsp+8]
	mov	esi, epoll_readsize
	call	buffer$reserve
	; read needs: fd in rdi, buffer in rsi, size in rdx
	mov	rsi, [rsp+8]
	mov	rdi, [rsp+16]
	mov	eax, syscall_read
	mov	edx, epoll_readsize
	mov	rsi, [rsi]	; the endptr conveniently at the first spot
	syscall
	; rax < 0 == error, but could be EAGAIN
	cmp	rax, 0
	jle	.readerror
	cmp	rax, epoll_readsize
	jl	.appendthendone
	mov	rdi, [rsp+8]	; our input buffer
	mov	rsi, rax	; our # of bytes read
	call	buffer$append_nocopy
	jmp	.readloop
calign
.appendthendone:
	mov	rdi, [rsp+8]	; our input buffer
	mov	rsi, rax	; our # of bytes read
	call	buffer$append_nocopy
	jmp	.read_return
if epoll_debug
cleartext .readerrorstr, 'epoll$activty readerror'
end if
calign
.readerror:
	cmp	rax, -11	; EAGAIN aka EWOULDBLOCK
	je	.read_return
if epoll_debug
	push	rdi
	mov	rdi, .readerrorstr
	call	string$to_stdoutln
	pop	rdi
end if
	; else, an actual error occurred, call the object's socketerror handler and die die die
	mov	rdi, [rsp]
	mov	rsi, [rdi]
	call	qword [rsi+epoll_verror]
	jmp	.read_cleanup_and_return
calign
.read_return:
	; if there is a nonzero amount of data in the input buffer, call the vreceive function
	; and check its return status to see whether we should be destroying ourselves
	mov	rcx, [rsp+8]
	cmp	qword [rcx+8], 0	; buffer_length_ofs
	jne	.read_doreceived
	add	rsp, 160
	ret
calign
.read_doreceived:
	mov	rdi, [rsp]	; the epoll object
	mov	rsi, [rcx+buffer_itself_ofs]	; pointer to data waiting
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]	; vmethod table
	call	qword [rcx+epoll_vreceive]
	; so the way I _used_ to have this, was to allow data to accumulate endlessly in the input buffer
	; and allow the data received function to selectively consume data from the head of the buffer
	; this time around, we need to clear it each and every time
	; if the application layer is interested in accumulating, it will need to do a separate buffer

if defined epoll_inbuf_accumulate
	; buffer$reset inline here:
	mov	rdi, [rsp+8]		; our input buffer
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	qword [rdi+buffer_length_ofs], 0
	mov	[rdi+buffer_endptr_ofs], rsi
	; end buffer$reset
end if

	; vreceive will return true if we are sposed to KO it
	test	eax, eax
	jz	.read_quietreturn
	; else, death on a stick, and because _they_ asked for it, no other calls than cleanup to be done
calign
.read_cleanup_and_return:
	mov	rdi, [rsp]
	call	epoll$fatality		; will walk to the top and call topmost's vdestroy
	add	rsp, 160
	ret
calign
.read_quietreturn:
	; if they have an existing timer object, it needs to be reset
	mov	rdi, [rsp]
	cmp	qword [rdi+epoll_timerobject_ofs], 0
	je	.read_quietreturn_notimer
	mov	rdi, [rdi+epoll_timerobject_ofs]
	call	epoll$timer_reset_private
	add	rsp, 160
	ret
calign
.read_quietreturn_notimer:
	add	rsp, 160
	ret
calign
.acceptloop:
	; rdi == our object, rcx == our fd, we need to make
	; [rsp] == our object
	; [rsp+16] == our fd (for the accept4 loop itself)
	; [rdi+epoll_listener_ofs] == the size of the address buffer we need
	mov	eax, syscall_accept4
	mov 	rdi, [rsp+16]			; the fd
	mov	rsi, rsp
	add	rsi, 32				; the address space
	mov	rdx, rsp
	add	rdx, 24
	mov	qword [rdx], 110
	mov	r10d, 0x80800			; SOCK_NONBLOCK | SOCK_CLOEXEC (SOCK_NONBLOCK is the lower 0x800)
	syscall
	cmp	eax, 0
	jl	.accepterror
	; actual addrlen is at [rsp+24], address is at [rsp+32]
	; else, we got back a valid fd already set to nonblocking...
	mov	[rsp+8], rax			; save our spanking new fd


	; we need to find the topmost io object in the listener chain, call THAT one's clone, and then walk back down it
	; to locate the newly created/cloned epoll object at the end
	mov	rdi, [rsp]
	cmp	qword [rdi+io_parent_ofs], 0
	je	.topmost_found
calign
.find_top:
	mov	rdi, [rdi+io_parent_ofs]
	cmp	qword [rdi+io_parent_ofs], 0
	jne	.find_top
calign
.topmost_found:
	mov	rsi, [rdi]
	call	qword [rsi+epoll_vclone]	; call clone first up
	; now, we need to find rax's bottom-most object, which MUST be an epoll object
	cmp	qword [rax+io_child_ofs], 0
	je	.bottommost_found
calign
.find_bottom:
	mov	rax, [rax+io_child_ofs]
	cmp	qword [rax+io_child_ofs], 0
	jne	.find_bottom
calign
.bottommost_found:
	mov	rdx, [rsp+8]			; retrieve its fd
	mov	[rax+epoll_fd_ofs], rdx		; set its fd
	mov	[rsp+8], rax			; overwrite its fd spot with our new object
	; if we have a nonzero readtimeout, we need to add it to the timemap
	cmp	qword [rax+epoll_readtimeout_ofs], 0
	jne	.acceptwithtimeout
	; add it to EPOLL:
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rax+epoll_fd_ofs]	; the fd
	mov	r10, rsp
	add	r10, 142
	mov	dword [r10], 1		; EPOLLIN
	mov	qword [r10+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	mov	rdi, [rsp+8]			; its object
	lea	rsi, [rsp+32]
	mov	edx, [rsp+24]
	mov	rcx, [rdi]			; its vmethod table
	call	qword [rcx+epoll_vconnected]	; call its connected method
if epoll_multiple_accepts
	; and we are done
	jmp	.acceptloop
else
	add	rsp, 160
	ret
end if
calign
.acceptwithtimeout:
	mov	rdi, [rax+epoll_readtimeout_ofs]
	mov	rsi, rax
	call	epoll$timer_new
	mov	rdx, [rsp+8]
	mov	[rdx+epoll_timerobject_ofs], rax
	mov	rax, [rsp+8]		; get our object back into rax
	; add it to EPOLL:
	mov	rdi, [_epoll_fd]
	mov	esi, 1			; EPOLL_CTL_ADD
	mov	rdx, [rax+epoll_fd_ofs]	; the fd
	mov	r10, rsp
	add	r10, 142
	mov	dword [r10], 1		; EPOLLIN
	mov	qword [r10+4], rax	; our object
	mov	eax, syscall_epoll_ctl
	syscall
	mov	rdi, [rsp+8]			; its object
	lea	rsi, [rsp+32]
	mov	edx, [rsp+24]
	mov	rcx, [rdi]			; its vmethod table
	call	qword [rcx+epoll_vconnected]	; call its connected method
if epoll_multiple_accepts
	; and we are done
	jmp	.acceptloop
else
	add	rsp, 160
	ret
end if
calign
.accepterror:
	add	rsp, 160
	ret
end if



if used epoll$run | defined include_everything
	; repeatedly calls epoll$iteration, doesn't come back unless qword at [_epoll_bailout] is nonzero
falign
epoll$run:
	if profile_epoll_iteration
		prolog	epoll$run
	else if public_funcs
		public epoll$run
	end if
calign
.iter:
	call	epoll$iteration
	cmp	qword [_epoll_bailout], 0
	je	.iter
	if profile_epoll_iteration
		epilog
	else
		ret
	end if
end if

