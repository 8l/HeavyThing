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
	; epoll_dns.inc: simple DNS routines using our epoll layer
	;

	;
	; CAVEAT EMPTOR: i wrote all of this quite hungover, bwahahah
	;

	;
	; still left to do someday when I am bored: implement a cache of results for each query type
	;

if used dns$init | defined include_everything
globals
{
	; the last modification time of the file
	_dns_resolve_mtime	dq	0
	; the last time (epoll$timestamp, in ms) we checked the mtime
	_dns_resolve_checktime	dq	0
	; our most-recent call to epoll$timestamp
	_dns_timestamp		dq	0
	; the list of our actual nameservers (fd followed by addrinfo followed by querymap for simplicity)
	_dns_servers		dq	0
	; the current (roundrobin) dns server
	_dns_server_cur		dq	0
	; the query id list
	_dns_query_ids		dq	0
	; the index into it:
	_dns_query_idx		dq	0
}
end if

if used dns$clear_nameservers | defined include_everything
	; no arguments, frees/clears our nameserver list
falign
dns$clear_nameservers:
	prolog	dns$clear_nameservers
	mov	rdi, [_dns_servers]
	mov	rsi, .clearfunc
	call	list$clear
	mov	qword [_dns_server_cur], 0
	epilog
calign
.clearfunc:
	push	rdi
	call	epoll$destroy
	mov	rdi, [rsp]
	mov	rdi, [rdi+_dns_server_map_ofs]
	mov	rsi, .queryclearfunc
	call	unsignedmap$clear
	mov	rdi, [rsp]
	mov	rdi, [rdi+_dns_server_map_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	ret
calign
.queryclearfunc:
	; key in rdi, val in rsi
	push	rsi		; our object

	mov	rdi, [rsi+epoll_base_size+48]
	call	epoll$timer_clear

	mov	rdx, [rsp]
	mov	rcx, [rdx+epoll_base_size+16]
	mov	rdi, [rdx+epoll_base_size]
	call	rcx		; the failure callback
	
	mov	rdi, [rsp]
	call	epoll$fatality	; walk up to the top and destroy

	add	rsp, 8
	ret
end if


if used dns$next_server | defined include_everything
	; no arguments, just advances the _dns_server_cur pointer
falign
dns$next_server:
	prolog	dns$next_server
	cmp	qword [_dns_server_cur], 0
	je	.setfirst
	mov	rdi, [_dns_server_cur]
	mov	rdi, [rdi+_list_nextofs]
	test	rdi, rdi
	jz	.setfirst
	mov	[_dns_server_cur], rdi
	epilog
calign
.setfirst:
	mov	rdi, [_dns_servers]
	mov	rsi, [_list_first]
	mov	[_dns_server_cur], rsi
	epilog
end if


_dns_server_fd_ofs = epoll_base_size
_dns_server_addr_ofs = epoll_base_size + 8
_dns_server_map_ofs = epoll_base_size + 8 + sockaddr_in_size 
_dns_epoll_extra_space = 16 + sockaddr_in_size

if used dns$epoll_vtable | defined include_everything

dalign
dns$epoll_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, dns$server_read, io$error, io$timeout
end if


if used dns$nameserver | defined include_everything
	; single argument in rdi: ip address of a nameserver
falign
dns$nameserver:
	prolog	dns$nameserver
	sub	rsp, 16
	mov	[rsp], rdi
	mov	rdi, dns$epoll_vtable
	mov	rsi, _dns_epoll_extra_space
	call	epoll$new
	mov	[rsp+8], rax
	mov	rdi, rax
	add	rdi, _dns_server_addr_ofs
	mov	rsi, [rsp]
	mov	edx, 53
	call	inet_addr
	test	eax, eax
	jz	.badaddress
	; we need an unsignedmap for it:
	call	unsignedmap$new
	mov	rdi, [rsp+8]
	mov	[rdi+_dns_server_map_ofs], rax
	call	socket$udp
	mov	rdi, [rsp+8]
	mov	[rdi+_dns_server_fd_ofs], rax
	mov	rdi, rax
	call	socket$nonblocking
	mov	r8, [rsp+8]
	mov	rdi, [r8+_dns_server_fd_ofs]
	mov	rsi, r8
	add	rsi, _dns_server_addr_ofs
	mov	edx, sockaddr_in_size
	mov	eax, syscall_connect
	syscall
	; next up: we can just call established on it
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+_dns_server_fd_ofs]
	call	epoll$established
	; done and dusted, add to our linked list
	mov	rdi, [_dns_servers]
	mov	rsi, [rsp+8]
	call	list$push_back
	add	rsp, 16
	epilog
calign
.badaddress:
	mov	rdi, [rsp+8]
	call	epoll$fatality
	add	rsp, 16
	epilog
end if


if used dns$read_config | defined include_everything
	; called every time we perform a NS check, but only does anything if the /etc/resolv.conf file
	; has changed since we last checked
falign
dns$read_config:
	prolog	dns$read_config
	call	epoll$timestamp
	mov	[_dns_timestamp], rax
	sub	rax, qword [_dns_resolve_checktime]
	cmp	rax, 60000
	jb	.nothingtodo
	mov	[_dns_resolve_checktime], rax
	mov	rdi, .resolvfile
	call	file$mtime_cstr
	cmp	rax, [_dns_resolve_mtime]
	je	.nothingtodo
	mov	[_dns_resolve_mtime], rax
	mov	rdi, .resolvfile
	call	file$to_string_cstr
	push	r12			; our offset
	push	rax			; [rsp] == our new string
	xor	r12d, r12d
calign
.confsearch:
	mov	rdi, [rsp]
	mov	rsi, .nstr
	mov	rdx, r12
	call	string$indexof_ofs
	cmp	rax, 0
	jl	.confdone
	add	rax, 10			; length(nameserver)
	mov	r12, rax		; save the index
	mov	rdi, [rsp]
	mov	rsi, rax
	movzx	ecx, word [rdi+rax*2+8]
	call	string$skip_whitespace
	mov	r12, rax		; save the index
	mov	rsi, rax
	; rdi still intact from skip_whitespace (DANGER)
	call	string$next_whitespace
	mov	rdx, rax		; end of the substring
	mov	rsi, r12		; start of the substring
	; rdi still intact from next_whitespace (DANGER)
	cmp	rax, r12
	je	.confdone
	call	string$substring
	push	rax
	mov	rdi, rax
	call	dns$nameserver
	pop	rdi
	call	heap$free		; free the substring
	jmp	.confsearch
calign
.confdone:
	mov	rdi, [rsp]
	call	heap$free
	pop	rcx r12
	epilog
calign
.nothingtodo:
	epilog
calign
.resolvfile:
	db	'/etc/resolv.conf',0
cleartext	.nstr, 'nameserver'
end if


if used dns$scramble_queryids | defined include_everything
	; no arguments, does a random shuffle of the unsigned shorts in query_ids
falign
dns$scramble_queryids:
	prolog	dns$scramble_queryids
	push	r12 r13
	mov	r12, [_dns_query_ids]
	xor	r13d, r13d		; i
calign
.loop:
	xor	edi, edi
	mov	esi, 65536
	sub	esi, r13d
	call	rng$int
	add	eax, r13d		; j = i + rng$int(0, 65536 - i)
	movzx	ecx, word [r12+rax*2]	; temp = ids[j]
	movzx	edx, word [r12+r13*2]	; ids[i]
	mov	word [r12+rax*2], dx	; ids[j] = ids[i]
	mov	word [r12+r13*2], cx	; ids[i] = temp
	add	r13d, 1
	cmp	r13d, 65536
	jb	.loop
	pop	r13 r12
	epilog
end if

if used dns$init | defined include_everything
	; this is called from epoll$init, and does the initial parse
	; of /etc/resolv.conf, as well as randomizes the query ids
falign
dns$init:
	prolog	dns$init
	call	list$new
	mov	[_dns_servers], rax
	mov	edi, 65536 * 2	; space for unsigned short * all possible values
	call	heap$alloc
	mov	[_dns_query_ids], rax
	mov	rdi, rax
	push	rbx
	mov	ebx, 65536
calign
.initloop:
	sub	ebx, 1
	mov	word [rdi], bx
	add	rdi, 2
	test	ebx, ebx
	jnz	.initloop
	call	dns$scramble_queryids
	pop	rbx
	mov	qword [_dns_query_idx], 0
	mov	qword [_dns_resolve_checktime], 54321	; the unsigned subtract/compare will force it to read once
	call	dns$read_config
	epilog
end if


macro nameunpack {
	local	.doit, .compressed, .namecopy, .namecopy2, .namecopy3, .namecopy4, .namecopy5, .nodot, .namedone, .namereallydone, .compressed_2deep, .compressed_3deep
	mov	r8, rsp		; dptr
	mov	qword [rsp+272], 0
	mov	qword [rsp+304], 0
	mov	qword [rsp+312], 0
calign
.doit:
	cmp	rdi, r11
	jae	.loop_done	; need more data.
	movzx	eax, byte [rdi]
	add	rdi, 1
	test	eax, eax
	jz	.namedone
	mov	r10d, eax
	and	r10d, 0xc0
	cmp	r10d, 0xc0
	je	.compressed
	test	r10d, r10d
	jnz	.invalid_data
	mov	r10d, eax
	; uncompressed name
	mov	r9, rdi
	add	r9, r10
	cmp	r9, r11
	jae	.loop_done		; need more data
	cmp	r8, rsp
	je	.nodot
	mov	byte [r8], '.'
	add	r8, 1
calign
.nodot:
	; else, we have enough room
	cmp	r10d, 16
	jb	.namecopy2
calign
.namecopy:
	mov	rax, [rdi]
	mov	r9, [rdi+8]
	mov	[r8], rax
	mov	[r8+8], r9
	add	rdi, 16
	add	r8, 16
	sub	r10d, 16
	cmp	r10d, 16
	jae	.namecopy
calign
.namecopy2:
	cmp	r10d, 8
	jb	.namecopy3
	mov	rax, [rdi]
	mov	[r8], rax
	add	rdi, 8
	add	r8, 8
	sub	r10d, 8
calign
.namecopy3:
	cmp	r10d, 4
	jb	.namecopy4
	mov	eax, [rdi]
	mov	[r8], eax
	add	rdi, 4
	add	r8, 4
	sub	r10d, 4
	jz	.doit
calign
.namecopy4:
	cmp	r10d, 2
	jb	.namecopy5
	movzx	eax, word [rdi]
	mov	word [r8], ax
	add	rdi, 2
	add	r8, 2
	sub	r10d, 2
	jz	.doit
calign
.namecopy5:
	test	r10d, r10d
	jz	.doit
	movzx	eax, byte [rdi]
	mov	byte [r8], al
	add	rdi, 1
	add	r8, 1
	sub	r10d, 1
	jmp	.doit
calign
.compressed:
	; compressed name
	cmp	qword [rsp+312], 0
	jne	.invalid_data
	movzx	r10d, byte [rdi]
	add	rdi, 1
	cmp	qword [rsp+304], 0
	jne	.compressed_3deep
	cmp	qword [rsp+272], 0
	jne	.compressed_2deep
	mov	qword [rsp+272], rdi	; to restore after we jump around
	and	eax, 0x3f
	shl	eax, 8
	add	eax, r10d
	mov	rdi, rsi
	add	rdi, rax
	jmp	.doit
calign
.compressed_2deep:
	mov	qword [rsp+304], rdi	; to restoure after we jump around
	and	eax, 0x3f
	shl	eax, 8
	add	eax, r10d
	mov	rdi, rsi
	add	rdi, rax
	jmp	.doit
calign
.compressed_3deep:
	mov	qword [rsp+312], rdi	; to restore after we jump around
	and	eax, 0x3f
	shl	eax, 8
	add	eax, r10d
	mov	rdi, rsi
	add	rdi, rax
	jmp	.doit
calign
.namedone:
	cmp	qword [rsp+272], 0
	je	.namereallydone
	mov	rdi, qword [rsp+272]
calign
.namereallydone:
	; store a null terminating byte at the end in case name extraction is required later
	mov	byte [r8], 0
}

macro nameunpack_nowrite {
	local	.doit, .compressed, .namecopy, .namecopy2, .namecopy3, .namecopy4, .namecopy5, .nodot, .namedone, .namereallydone, .compressed_2deep, .compressed_3deep
	mov	r8, rsp		; dptr
	mov	qword [rsp+272], 0
	mov	qword [rsp+304], 0
	mov	qword [rsp+312], 0
calign
.doit:
	cmp	rdi, r11
	jae	.loop_done	; need more data.
	movzx	eax, byte [rdi]
	add	rdi, 1
	test	eax, eax
	jz	.namedone
	mov	r10d, eax
	and	r10d, 0xc0
	cmp	r10d, 0xc0
	je	.compressed
	test	r10d, r10d
	jnz	.invalid_data
	mov	r10d, eax
	; uncompressed name
	mov	r9, rdi
	add	r9, r10
	cmp	r9, r11
	jae	.loop_done		; need more data
	cmp	r8, rsp
	je	.nodot
	; mov	byte [r8], '.'
	add	r8, 1
calign
.nodot:
	; else, we have enough room
	cmp	r10d, 16
	jb	.namecopy2
calign
.namecopy:
	mov	rax, [rdi]
	mov	r9, [rdi+8]
	; mov	[r8], rax
	; mov	[r8+8], r9
	add	rdi, 16
	add	r8, 16
	sub	r10d, 16
	cmp	r10d, 16
	jae	.namecopy
calign
.namecopy2:
	cmp	r10d, 8
	jb	.namecopy3
	mov	rax, [rdi]
	; mov	[r8], rax
	add	rdi, 8
	add	r8, 8
	sub	r10d, 8
calign
.namecopy3:
	cmp	r10d, 4
	jb	.namecopy4
	mov	eax, [rdi]
	; mov	[r8], eax
	add	rdi, 4
	add	r8, 4
	sub	r10d, 4
	jz	.doit
calign
.namecopy4:
	cmp	r10d, 2
	jb	.namecopy5
	movzx	eax, word [rdi]
	; mov	word [r8], ax
	add	rdi, 2
	add	r8, 2
	sub	r10d, 2
	jz	.doit
calign
.namecopy5:
	test	r10d, r10d
	jz	.doit
	movzx	eax, byte [rdi]
	; mov	byte [r8], al
	add	rdi, 1
	add	r8, 1
	sub	r10d, 1
	jmp	.doit
calign
.compressed:
	; compressed name
	cmp	qword [rsp+312], 0
	jne	.invalid_data
	movzx	r10d, byte [rdi]
	add	rdi, 1
	cmp	qword [rsp+304], 0
	jne	.compressed_3deep
	cmp	qword [rsp+272], 0
	jne	.compressed_2deep
	mov	qword [rsp+272], rdi	; to restore after we jump around
	and	eax, 0x3f
	shl	eax, 8
	add	eax, r10d
	mov	rdi, rsi
	add	rdi, rax
	jmp	.doit
calign
.compressed_2deep:
	mov	qword [rsp+304], rdi	; to restoure after we jump around
	and	eax, 0x3f
	shl	eax, 8
	add	eax, r10d
	mov	rdi, rsi
	add	rdi, rax
	jmp	.doit
calign
.compressed_3deep:
	mov	qword [rsp+312], rdi	; to restore after we jump around
	and	eax, 0x3f
	shl	eax, 8
	add	eax, r10d
	mov	rdi, rsi
	add	rdi, rax
	jmp	.doit
calign
.namedone:
	cmp	qword [rsp+272], 0
	je	.namereallydone
	mov	rdi, qword [rsp+272]
calign
.namereallydone:
	; store a null terminating byte at the end in case name extraction is required later
	; mov	byte [r8], 0
}




if used dns$server_read | defined include_everything
	; this gets called when data arrives from a nameserver
	; NOTE: rsi/rdx are pre-populated with the inbuf start/length, but we interact with the input buffer directly
	; see commentary atop epoll.inc for further explanatory
falign
dns$server_read:
	prolog	dns$server_read
	sub	rsp, 320
	mov	[rsp+256], rdi
calign
.loop_top:
	mov	rdi, [rsp+256]				; get our epoll object
	mov	rdx, [rdi+epoll_inbuf_ofs]		; its input buffer
	cmp	qword [rdx+buffer_length_ofs], 12	; 12 bytes for our header at a minimum
	jb	.loop_done				; go wait for more data if we dont have enough for at least our header

	mov	rsi, [rdx+buffer_itself_ofs]		; its actual buffer
	mov	r11, [rdx+buffer_length_ofs]

	; locate our original query in the inflight list so we know what to extract from the answer
	movzx	esi, word [rsi]				; the id, in network byte order (but we left it that way)
	mov	rdi, [rdi+_dns_server_map_ofs]		; our inflight map
	call	unsignedmap$find_value
	test	eax, eax
	jz	.notinflight
	; else, we found it in the inflight list... 
	; save the value to our stack, erase it from the inflight map (may as well now)
	; our key should still be in rsi, as is our map (because we know that unsignedmap$find_value doesn't blast them)
	mov	[rsp+280], rdx				; the actual query/timeout epoll object
	call	unsignedmap$erase

	; so now, we can clear the timer for it:
	; [rdi+epoll_base_size+48]	= timer object
	mov	rdx, [rsp+280]				; get our query/timeout epoll object back
	mov	rdi, [rdx+epoll_base_size+48]		; the timer object
	call	epoll$timer_clear

	; so our timer is now defunct, and we have removed the query from the inflight list
	; now determine the relevant information we need during the answer parse
	mov	rdx, [rsp+280]
	mov	rax, [rdx+epoll_base_size+32]		; the query type
	mov	[rsp+288], rax				; save it for examination later
	; [rdi+epoll_base_size+32]	= query type
	mov	qword [rsp+296], 0			; the answer space
	; proceed with our parsing action
	jmp	.loop_start
calign
.notinflight:
	; no inflight query exists for this record
	xor	ecx, ecx
	mov	[rsp+280], rcx
	mov	[rsp+288], rcx
	mov	[rsp+296], rcx
calign
.loop_start:
	mov	qword [rsp], 0				; clear the name unpack space
	mov	rdi, [rsp+256]				; get our epoll object again
	mov	rdx, [rdi+epoll_inbuf_ofs]
	mov	rsi, [rdx+buffer_itself_ofs]
	mov	r11, [rdx+buffer_length_ofs]

	mov	rdi, rsi				
	add	r11, rdi				; r11 now pointing to the end of our buffer
	add	rdi, 12					; rdi pointing to the beginning after the header

	movzx	ecx, word [rsi+4]
	xchg	ch, cl					; qdcount
	xor	edx, edx
calign
.qdloop:
	cmp	edx, ecx
	jae	.qdloopdone
	nameunpack_nowrite
	; ntohs(type), ntohs(cls) is here
	add	rdi, 4		
	cmp	rdi, r11
	ja	.loop_done				; need more data
	je	.server_error				; if it is equal, NXDOMAIN
	add	edx, 1
	jmp	.qdloop
calign
.qdloopdone:
	movzx	ecx, word [rsi+6]
	xchg	ch, cl
	xor	edx, edx
calign
.anloop:
	cmp	edx, ecx
	jae	.anloopdone

	nameunpack_nowrite

	mov	rax, rdi
	add	rax, 10
	cmp	rax, r11
	jae	.loop_done				; need more data
	; otherwise, we have: short type, short cls, u32 ttl, short namelen
	movzx	r8d, word [rdi]
	movzx	eax, word [rdi+8]
	xchg	al,ah
	add	rdi, 10
	; so now eax has namelength, and r8d has the type (in network byte order)
	add	rax, rdi
	mov	[rsp+264], rax		; save our new rdi for post-parse
	cmp	r8d, 0x500		; T_CNAME
	jne	.an_notcname
	nameunpack
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.anloop
calign
.an_notcname:
	cmp	r8d, 0x100		; T_A
	jne	.an_nota
	; compare our query type
	cmp	qword [rsp+288], 1
	jne	.an_notmx		; go to the next one if the query_type wasn't T_A to begin with
	cmp	qword [rsp+296], 0
	jne	.an_notmx		; go to the next one if we already set the answer
	; address sitting in dword [rdi]
	mov	eax, dword [rdi]
	mov	qword [rsp+296], rax	; set the answer
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.anloop
calign
.an_nota:
	cmp	r8d, 0xC00		; T_PTR
	jne	.an_notptr
	nameunpack
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.anloop
calign
.an_notptr:
	cmp	r8d, 0xF00		; T_MX
	jne	.an_notmx
	; preference is the first two bytes
	add	rdi, 2
	nameunpack
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.anloop
calign
.an_notmx:
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.anloop
calign
.anloopdone:
	movzx	ecx, word [rsi+8]	; nscount
	xchg	ch, cl
	xor	edx, edx
calign
.nsloop:
	cmp	edx, ecx
	jae	.nsloopdone
	nameunpack_nowrite
	mov	rax, rdi
	add	rax, 10
	cmp	rax, r11
	jae	.loop_done				; need more data
	; otherwise, we have: short type, short cls, u32 ttl, short namelen
	movzx	r8d, word [rdi]
	movzx	eax, word [rdi+8]
	xchg	al,ah
	add	rdi, 10
	; so now eax has namelength, and r8d has the type (in network byte order)
	add	rax, rdi
	mov	[rsp+264], rax		; save our new rdi for post-parse
	cmp	r8d, 0x200		; T_NS
	jne	.ns_notns
	nameunpack_nowrite
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.nsloop
calign
.ns_notns:
	cmp	r8d, 0x600		; T_SOA
	jne	.ns_notsoa
	nameunpack_nowrite
	; SOA now in [rsp]
	nameunpack_nowrite
	; MB
	; now we have u32: serial, u32: refresh, u32: retry, u32: exp, u32: minttl
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.nsloop
calign
.ns_notsoa:
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.nsloop
calign
.nsloopdone:
	movzx	ecx, word [rsi+10]	; arcount
	xchg	ch, cl
	xor	edx, edx
calign
.arloop:
	cmp	edx, ecx
	jae	.arloopdone
	nameunpack_nowrite
	mov	rax, rdi
	add	rax, 10
	cmp	rax, r11
	jae	.loop_done
	movzx	r8d, word [rdi]
	movzx	eax, word [rdi+8]
	xchg	al,ah
	add	rdi, 10
	; so now eax has namelength, and r8d has the type (in network byte order)
	add	rax, rdi
	mov	[rsp+264], rax
	cmp	r8d, 0x100 		; T_A
	jne	.ar_nota
	; otherwise, address is sitting at dword [rdi]
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.arloop
calign
.ar_nota:
	mov	rdi, [rsp+264]
	add	edx, 1
	jmp	.arloop
calign
.arloopdone:
	; so if we made it to here, the # of bytes we consumed is rdi - start of the real buffer
	; which is still in rsi
	sub	rdi, rsi
	; determine whether this was an error condition or not:
	movzx	eax, byte [rsi+3]			; rz
	and	eax, 0xf
	jnz	.server_error
	; otherwise, do our callback w/ the result [if any] and keep going
	; make sure we have a nonzero answer
	cmp	qword [rsp+296], 0
	je	.check_cname
	; otherwise, we can go ahead and consume this answer, then issue our callback
	; and then cleanup/destroy the query object

	mov	rsi, rdi		; # of bytes to consume
	mov	rdi, [rsp+256]				; get our epoll object
	mov	rdi, [rdi+epoll_inbuf_ofs]		; its input buffer
	call	buffer$consume

	; [rdi+epoll_base_size+8]	= success callback
	
	mov	rdx, [rsp+280]				; get our query/timeout epoll object back
	test	rdx, rdx
	jz	.loop_top

	mov	rcx, [rdx+epoll_base_size+8]
	mov	rdi, [rdx+epoll_base_size]		; the original query string
	mov	rsi, [rdx+epoll_base_size+24]		; arbitrary parameter
	mov	rdx, [rsp+296]				; the answer
	call	rcx					; call the success callback
	
	; so now, we have to issue the cleanup
	mov	rdi, [rsp+280]
	call	epoll$fatality
	jmp	.loop_top
calign
.check_cname:
	; so, while this is an unsual way to go about this, if we were presented with a CNAME, but no IP
	; then we need to take special measures and re-issue the query for the cname itself
	cmp	byte [rsp], 0				; if we wrote nothing to the nameunpack space, outta here
	je	.server_error
	; otherwise, we wrote a name ... care must be taken that we don't end up in an infinite loop
	mov	rdx, [rsp+280]
	test	rdx, rdx
	jz	.server_error
	cmp	qword [rdx+epoll_base_size+64], 0
	jne	.server_error
	
	; otherwise, re-issue a new query with our name in [rsp]
	; consume our 
	mov	rsi, rdi		; # of bytes to consume
	mov	rdi, [rsp+256]				; get our epoll object
	mov	rdi, [rdi+epoll_inbuf_ofs]		; its input buffer
	call	buffer$consume

	mov	r11, [rsp+280]
	mov	rdi, rsp
	mov	rsi, [r11+epoll_base_size+8]		; success callback
	mov	rdx, [r11+epoll_base_size+16]		; fail callback
	mov	rcx, [r11+epoll_base_size+24]		; arbitrary parameter
	mov	r8, [r11+epoll_base_size+32]		; original query type
	mov	r9d, 1					; bool for requery
	mov	r10, [r11+epoll_base_size]		; the original string (which we need to carry)
	call	dns$query_cstring_requery
	
	; now, a _new_ "fake" epoll object is inflight, and we already removed the one we're working on
	; so blast it
	mov	rdi, [rsp+280]
	call	epoll$fatality
	jmp	.loop_top
calign
.server_error:
	; server puked back some sorta error
	; check to see if we have a callback to issue

	; and then keep going
	mov	rsi, rdi		; # of bytes to consume
	mov	rdi, [rsp+256]				; get our epoll object
	mov	rdi, [rdi+epoll_inbuf_ofs]		; its input buffer
	call	buffer$consume

	mov	rdx, [rsp+280]
	test	rdx, rdx
	jz	.loop_top
	
	mov	rcx, [rdx+epoll_base_size+16]		; failure callback
	mov	rdi, [rdx+epoll_base_size]		; the original query string
	mov	rsi, [rdx+epoll_base_size+24]		; arbitrary parameter
	call	rcx

	; cleanup/destroy
	mov	rdi, [rsp+280]
	call	epoll$fatality
	jmp	.loop_top
calign
.invalid_data:
	; server puked back something we could not parse, reset the inbuf (swallowing what we have)
	mov	rdx, [rsp+256]
	mov	rdi, [rdx+epoll_inbuf_ofs]
	call	buffer$reset
	add	rsp, 320
	xor	eax, eax		; don't close the socket
	epilog
calign
.loop_done:
	xor	eax, eax		; dont close the socket
	add	rsp, 320
	epilog
end if


if used dns$timed_out | defined include_everything
	;
	;	TODO: we probably should add a second query second if there are other nameservers available
	;	all of my nameservers are local, and this isn't an issue for me...
	;
falign
dns$timed_out:
	prolog	dns$timed_out

	; rdi is our epoll object, so our
	; [rdi+epoll_base_size]		= string hostname
	; [rdi+epoll_base_size+8]	= success callback
	; [rdi+epoll_base_size+16]	= failure callback
	; [rdi+epoll_base_size+24]	= arbitrary parameter
	; [rdi+epoll_base_size+32]	= query type
	; [rdi+epoll_base_size+40]	= query id
	; [rdi+epoll_base_size+48]	= timer object
	; [rdi+epoll_base_size+56]	= query map for the server we used
	
	; first things first, remove us from the inflight map
	push	rdi
	mov	rdx, rdi			; ourselves
	mov	rsi, [rdi+epoll_base_size+40]	; the query id
	mov	rdi, [rdi+epoll_base_size+56]	; the unsigned map
	call	unsignedmap$erase_specific
	; next up: call the failure callback
	mov	rdx, [rsp]
	mov	rdi, [rdx+epoll_base_size]	; string
	mov	rsi, [rdx+epoll_base_size+24]	; arbitrary parameter
	mov	rcx, [rdx+epoll_base_size+16]	; failure callback
	call	rcx
	; now, all we have to do is return nonzero and we'll get all cleaned up and free'd
	mov	eax, 1
	add	rsp, 8
	epilog
end if



if used dns$query_cstring_requery | defined include_everything
	; cstring (null terminated) in rdi, success callback in rsi, failure callback in rdx, arbitrary parameter in rcx, query type in r8d, requery bool in r9d, original string in r10

	; this is only called from server_read in the event we got answers that needed further querying to resolve
	; someday I should rewrite all this, hahah
falign
dns$query_cstring_requery:
	prolog_silent	dns$query_cstring_requery
	sub	rsp, 576
	mov	[rsp+512], rdi	; save our parameters
	mov	[rsp+520], rsi
	mov	[rsp+528], rdx
	mov	[rsp+536], rcx
	mov	[rsp+544], r8
	mov	[rsp+560], r9
	mov	[rsp+568], r10
	call	strlen_latin1
	; hangon to our length
	mov	[rsp+552], rax
	xor	r8d, r8d
	mov	[rsp], r8
	mov	[rsp+8], r8	; zero out the first 16 bytes
	lea	rdi, [rsp+13]
	mov	rsi, [rsp+512]
	mov	rdx, rax
	call	memcpy
	mov	rax, [rsp+552]
	mov	r10, [_dns_query_ids]
	mov	r11, [_dns_query_idx]
	movzx	r9d, word [r10+r11*2]
	add	r11d, 1
	mov	[_dns_query_idx], r11
	cmp	r11d, 65536
	jb	.noreset
	mov	qword [_dns_query_idx], 0
calign
.noreset:
	; so now, r9w has our query id, we don't really care what the order is, only that it is unique
	mov	[rsp+552], r9		; save our query id so we can add it to the inflight list
	mov	word [rsp], r9w		; header.id = next query id
	mov	byte [rsp+2], 1		; recursion desired
	mov	word [rsp+5], 1		; qdcount
	; we already wrote our string in plaintext, now we need to encode the bytes for namepack
	mov	ecx, 1			; bufpos
	; r8d == namepos
	xor	r9d, r9d		; savespot
	xor	r10d, r10d		; namelen
	mov	r11d, eax		; hostlen
	xor	edx, edx		; namepos
	mov	rsi, rsp
	add	rsi, 13
calign
.namepack:
	cmp	edx, r11d
	jae	.namepackdone
	movzx	eax, byte [rsi+rdx]
	cmp	eax, '.'
	jne	.notdot
	mov	byte [rsp+r9+12], r10b
	mov	r9d, ecx
	add	ecx, 1
	xor	r10d, r10d
	add	edx, 1
	jmp	.namepack
calign
.notdot:
	add	r10d, 1
	add	ecx, 1
	add	edx, 1
	jmp	.namepack
calign
.namepackdone:
	mov	byte [rsp+r9+12], r10b
	mov	byte [rsp+rcx+12], 0
	add	ecx, 1
	mov	rax, [rsp+544]		; query type
	mov	byte [rsp+rcx+12], ah
	mov	byte [rsp+rcx+13], al
	mov	word [rsp+rcx+14], 0x100
	add	ecx, 4
	; query length is rcx + 12
	mov	rdi, [_dns_server_cur]	; list item
	mov	rdi, [rdi]		; its value
	mov	rsi, rsp
	mov	edx, ecx
	add	edx, 12
	; we really don't need to do this via the vtable, but for consistency, we do anyway:
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+epoll_vsend]	; this will buffer it nicely for us if the interface is jammed

	; we are going to cheat a bit here
	mov	rdi, .inflight_vtable
	mov	esi, 72
	call	epoll$new

	mov	rdi, [rsp+568]		; string hostname
	mov	rsi, [rsp+520]		; success callback
	mov	rdx, [rsp+528]		; fail callback
	mov	rcx, [rsp+536]		; arbitrary parameter
	mov	r8, [rsp+544]		; query type
	mov	r9, [rsp+552]		; query id
	mov	r10, [rsp+560]		; requery bool


	mov	[rax+epoll_base_size], rdi
	mov	[rax+epoll_base_size+8], rsi
	mov	[rax+epoll_base_size+16], rdx
	mov	[rax+epoll_base_size+24], rcx
	mov	[rax+epoll_base_size+32], r8
	mov	[rax+epoll_base_size+40], r9
	mov	[rax+epoll_base_size+64], r10
	; so now, we need to establish a timer for it, and record the timer id
	mov	[rsp], rax		; save our object
	mov	edi, dns_timeout_msecs	; our timeout in milliseconds
	mov	rsi, rax		; our epoll object, who's timeout func will get called (the rest are untouched)
	call	epoll$timer_new
	mov	rdx, [rsp]
	mov	[rdx+epoll_base_size+48], rax	; save our timer object

	; so now, we have a running timer, and have saved all our goods in our new "not really an epoll" object
	; next up: we need to put our object, keyed by its query id, into the _dns_server_cur's map
	mov	rdi, [_dns_server_cur]
	mov	rdi, [rdi]		; its value, since _dns_server_cur is a list item and not the actual value
	mov	rdi, [rdi+_dns_server_map_ofs]
	mov	[rdx+epoll_base_size+56], rdi	; save our usnignedmap for use later
	mov	rsi, [rdx+epoll_base_size+40]	; the query id
	; rdx is still loaded up with the value side
	call	unsignedmap$insert

	add	rsp, 576
	epilog
dalign
.inflight_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, epoll$receive, io$error, dns$timed_out
end if


; header:
; unsigned short id, char qr, char rz, shorts qdcount, ancount, nscount, arcount
; followed by character data[498] max


if used dns$query | defined include_everything
	; string in rdi, success callback in rsi, failure callback in rdx, arbitrary parameter in rcx, query type in r8d
falign
dns$query:
	prolog_silent	dns$query
	xor	r9d, r9d
	sub	rsp, 560
	mov	[rsp+512], rdi	; save our parameters
	mov	[rsp+520], rsi
	mov	[rsp+528], rdx
	mov	[rsp+536], rcx
	mov	[rsp+544], r8
	mov	[rsp], r9
	mov	[rsp+8], r9	; zero out the first 16 bytes
	lea	rsi, [rsp+13]
	call	string$to_utf8
	mov	r10, [_dns_query_ids]
	mov	r11, [_dns_query_idx]
	movzx	r9d, word [r10+r11*2]
	add	r11d, 1
	mov	[_dns_query_idx], r11
	cmp	r11d, 65536
	jb	.noreset
	mov	qword [_dns_query_idx], 0
calign
.noreset:
	; so now, r9w has our query id, we don't really care what the order is, only that it is unique
	mov	[rsp+552], r9		; save our query id so we can add it to the inflight list
	mov	word [rsp], r9w		; header.id = next query id
	mov	byte [rsp+2], 1		; recursion desired
	mov	word [rsp+5], 1		; qdcount
	; we already wrote our string in plaintext, now we need to encode the bytes for namepack
	mov	ecx, 1			; bufpos
	; r8d == namepos
	xor	r9d, r9d		; savespot
	xor	r10d, r10d		; namelen
	mov	r11d, eax		; hostlen
	xor	edx, edx		; namepos
	lea	rsi, [rsp+13]
calign
.namepack:
	cmp	edx, r11d
	jae	.namepackdone
	movzx	eax, byte [rsi+rdx]
	cmp	eax, '.'
	jne	.notdot
	mov	byte [rsp+r9+12], r10b
	mov	r9d, ecx
	add	ecx, 1
	xor	r10d, r10d
	add	edx, 1
	jmp	.namepack
calign
.notdot:
	add	r10d, 1
	add	ecx, 1
	add	edx, 1
	jmp	.namepack
calign
.namepackdone:
	mov	byte [rsp+r9+12], r10b
	mov	byte [rsp+rcx+12], 0
	add	ecx, 1
	mov	rax, [rsp+544]		; query type
	mov	rdi, [_dns_server_cur]	; list item
	mov	byte [rsp+rcx+12], ah
	mov	byte [rsp+rcx+13], al
	mov	word [rsp+rcx+14], 0x100
	add	ecx, 4
	; query length is rcx + 12
	mov	rdi, [rdi]		; its value
	mov	rsi, rsp
	lea	edx, [ecx+12]
	; we really don't need to do this via the vtable, but for consistency, we do anyway:
	mov	rcx, [rdi]		; its vtable
	call	qword [rcx+epoll_vsend]	; this will buffer it nicely for us if the interface is jammed

	; we are going to cheat a bit here
	mov	rdi, .inflight_vtable
	mov	esi, 72
	call	epoll$new

	mov	rdi, [rsp+512]		; string hostname
	mov	rsi, [rsp+520]		; success callback
	mov	rdx, [rsp+528]		; fail callback
	mov	rcx, [rsp+536]		; arbitrary parameter
	mov	r8, [rsp+544]		; query type
	mov	r9, [rsp+552]		; query id


	mov	[rax+epoll_base_size], rdi
	mov	[rax+epoll_base_size+8], rsi
	mov	[rax+epoll_base_size+16], rdx
	mov	[rax+epoll_base_size+24], rcx
	mov	[rax+epoll_base_size+32], r8
	mov	[rax+epoll_base_size+40], r9
	mov	qword [rax+epoll_base_size+64], 0
	; so now, we need to establish a timer for it, and record the timer id
	mov	[rsp], rax		; save our object
	mov	edi, dns_timeout_msecs	; our timeout in milliseconds
	mov	rsi, rax		; our epoll object, who's timeout func will get called (the rest are untouched)
	call	epoll$timer_new
	mov	rdx, [rsp]
	mov	[rdx+epoll_base_size+48], rax	; save our timer object

	; so now, we have a running timer, and have saved all our goods in our new "not really an epoll" object
	; next up: we need to put our object, keyed by its query id, into the _dns_server_cur's map
	mov	rdi, [_dns_server_cur]
	mov	rdi, [rdi]		; its value, since _dns_server_cur is a list item and not the actual value
	mov	rdi, [rdi+_dns_server_map_ofs]
	mov	[rdx+epoll_base_size+56], rdi	; save our usnignedmap for use later
	mov	rsi, [rdx+epoll_base_size+40]	; the query id
	; rdx is still loaded up with the value side
	call	unsignedmap$insert

	add	rsp, 560
	epilog
dalign
.inflight_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, epoll$receive, io$error, dns$timed_out
end if






if used dns$lookup_ipv4 | defined include_everything
	; arguments: hostname in rdi (string), success callback in rsi, failure callback in rdx, rcx: arbitrary argument that will get passed to callbacks
	; note on callback params: rdi will be the string passed here, rsi will be the arbitrary parameter, and for success callback, rdx will contain the result
falign
dns$lookup_ipv4:
	prolog	dns$lookup_ipv4
	sub	rsp, 32
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+24], rcx

if epoll_debug
	call	string$to_stdoutln
end if

	call	dns$read_config
	call	dns$next_server

	cmp	qword [_dns_server_cur], 0
	je	.silly
	mov	rdi, [rsp]
	call	string$utf8_length
	cmp	rax, 255
	jae	.silly
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
	mov	rcx, [rsp+24]
	mov	r8d, 1			; T_A
	call	dns$query

	add	rsp, 32
	epilog
calign
.silly:
	mov	rdi, [rsp]		; hostname string
	mov	rsi, [rsp+24]		; arbitrary parameter
	call	qword [rsp+16]		; call the failure function straight up
	add	rsp, 32
	epilog
end if
