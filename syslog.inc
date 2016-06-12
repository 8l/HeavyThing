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
	; syslog.inc: convenience for writing to the local syslog
	; similar/functionally equivalent to the libc goods
	;
	; we use /dev/log via AF_UNIX/SOCK_DGRAM, and open a socket
	; to it upon init
	; 
	; NOTE RE: RFC5424...
	; /dev/log on all my gear doesn't speak it, so by default we
	; don't have it enabled... so we speak RFC3164 if it is disabled


if used syslog$init | defined include_everything


; speak RFC5424?
rfc5424 = 0



; priority constants (0..7)
log_emerg = 0
log_alert = 1
log_crit = 2
log_err = 3
log_warning = 4
log_notice = 5
log_info = 6
log_debug = 7


globals
{
	; we keep a formatter handy for the actual syslog messages
	syslog_formatter	dq	0
	; in addition, we make a _copy_ of the argv[0] for our progname
	; changing this string pointer will result in different ident
	syslog_ident		dq	0
	; we also call getpid and store its value here:
	syslog_pid		dq	0
	; the socket itself
	syslog_fd		dq	0
	; so that we don't have to deal with dynamic stack allocation, we keep a single buffer
	; for composing messages
	syslog_buffer		dq	0
}


falign
syslog$init:
	prolog	syslog$init
	mov	eax, syscall_getpid
	syscall
	mov	[syslog_pid], rax
	xor	edi, edi
	call	formatter$new
	mov	[syslog_formatter], rax
	mov	rdi, rax
	mov	rsi, .s1
	call	formatter$add_static
	mov	rdi, [syslog_formatter]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned		; priority+facility is first arg
	mov	rdi, [syslog_formatter]
	mov	rsi, .s2
	call	formatter$add_static
	mov	rdi, [syslog_formatter]
if rfc5424
	call	formatter$add_datetime		; current truncated JD is second arg
else
	call	formatter$add_rfc3164datetime	; current truncated JD is second arg
end if
	mov	rdi, [syslog_formatter]
	mov	rsi, .s3
	call	formatter$add_static
if rfc5424
	mov	rdi, [syslog_formatter]
	xor	esi, esi
	call	formatter$add_string		; we use the uname$nodename value for this, third arg
	mov	rdi, [syslog_formatter]
	mov	rsi, .s3
	call	formatter$add_static
end if
	mov	rdi, [syslog_formatter]
	xor	esi, esi
	call	formatter$add_string		; ident for this, fourth arg
	mov	rdi, [syslog_formatter]
if rfc5424
	mov	rsi, .s3
else
	mov	rsi, .s5
end if
	call	formatter$add_static
	mov	rdi, [syslog_formatter]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned		; syslog_pid for this, fifth arg
	mov	rdi, [syslog_formatter]
	mov	rsi, .s4
	call	formatter$add_static
	; our formatter ends there, the actual syslog routine deals with the rest

	mov	qword [syslog_ident], .default_ident
	cmp	qword [argc], 0
	je	.noident

	; next up: set our ident, which we take last_indexof / forward from the argv[0]
	mov	rdi, [argv]
	mov	rax, [_list_first]
	mov	rdi, [rax+_list_valueofs]	; argv[0] (which should always exist)
	mov	rsi, .lazyslash			; TODO: haha, lazy boy I am
	call	string$last_indexof
	cmp	rax, -1
	je	.wholeident
	mov	rsi, rax
	mov	rdi, [argv]
	mov	rax, [_list_first]
	mov	rdi, [rax+_list_valueofs]
	mov	rdx, 256
	add	rsi, 1
	call	string$substr
	jmp	.identgood
cleartext .lazyslash, '/'
cleartext .default_ident, 'noname'
calign
.wholeident:
	mov	rdi, [argv]
	mov	rax, [_list_first]
	mov	rdi, [rax+_list_valueofs]
	call	string$copy
calign
.identgood:
	mov	[syslog_ident], rax		; we make a copy of it in case app-layer blasts the argv list
.noident:
	; setup our fd
	call	socket$unixudp
	mov	[syslog_fd], rax
	; connect us to /dev/log
	sub	rsp, 128
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, 128
	call	memset32
	mov	word [rsp], 1			; AF_UNIX/PF_LOCAL
	mov	rax, qword [.devlog]		; conveniently 8 bytes
	mov	[rsp+2], rax
	; so [rsp] for sockaddr_un_size (110) is all set to go
	mov	eax, syscall_connect
	mov	rdi, [syslog_fd]
	mov	rsi, rsp
	mov	edx, sockaddr_un_size		; 110
	syscall
	add	rsp, 128
	; if that fails, we have much larger problems to deal with, no error checking quite intentionally
	; last but not least, create a buffer
	call	buffer$new
	mov	[syslog_buffer], rax
	epilog

cleartext .s1, '<'
if rfc5424
cleartext .s2, '>1 '
cleartext .s3, ' '
cleartext .s4, ' - - '
else
cleartext .s2, '>'
cleartext .s3, ' '
cleartext .s4, ']: '
cleartext .s5, '['
end if

dalign
.devlog	db '/dev/log'


end if


if used syslog | defined include_everything
	; two arguments: edi == priority (0..7), rsi == _string_
falign
syslog:
	prolog	syslog
	add	edi, syslog_facility
	push	rsi rdi
	call	timestamp			; its return is sitting in xmm0, second arg to our formatter
	mov	rdi, [syslog_formatter]
	pop	rsi				; first arg to our formatter == priority + facility
if rfc5424
	mov	rdx, [uname$nodename]		; our hostname
	mov	rcx, [syslog_ident]		; our progname
	mov	r8, [syslog_pid]		; our PID
else
	mov	rdx, [syslog_ident]		; our progname
	mov	rcx, [syslog_pid]
end if
	call	formatter$doit
	push	rax

	mov	rdi, [syslog_buffer]
	call	buffer$reset
	mov	rdi, [rsp]
	call	string$utf8_length
	; save that length as well
	push	rax
	; we also need our utf8 length of the arg string, which is at [rsp+16]
	mov	rdi, [rsp+16]
	call	string$utf8_length
	pop	rcx
	add	rax, 16				; an extra bit for our BOM, overkill but doesn't hurt
	add	rax, rcx
	mov	rdi, [syslog_buffer]
	mov	rsi, rax			; our utf8 lengths
	call	buffer$reserve
	mov	rcx, [syslog_buffer]
	; so now, we can convert both strings
	mov	rdi, [rsp]
	mov	rsi, [rcx+buffer_itself_ofs]
	call	string$to_utf8
	mov	rcx, [syslog_buffer]
	add	qword [rcx+buffer_endptr_ofs], rax
	add	qword [rcx+buffer_length_ofs], rax
if rfc5424
	; next we have to write our BOM
	mov	rdi, rcx
	mov	rsi, .bom
	mov	edx, 3
	call	buffer$append
end if
	pop	rdi
	call	heap$free
	mov	rcx, [syslog_buffer]
	; so now we have to convert our arg string to utf8 and append that too, we know there is room
	pop	rdi
	mov	rsi, [rcx+buffer_endptr_ofs]
	call	string$to_utf8
	mov	rcx, [syslog_buffer]
	add	qword [rcx+buffer_endptr_ofs], rax
	add	qword [rcx+buffer_length_ofs], rax
	; so now, we just have to send it over the wire and we are done
	mov	eax, syscall_write
	mov	rdi, [syslog_fd]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	syscall
if syslog_stderr
	; add a trailing lf to the buffer
	mov	rdi, [syslog_buffer]
	mov	esi, 10
	call	buffer$append_byte_noreserve
	mov	rcx, [syslog_buffer]
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]

	; unlike glibc, i prefer to have time information on stderr as well so I can scroll back and determine timing information
	; so, the only part we skip of the message is the <PRI>
calign
.search:
	cmp	byte [rsi], '>'
	je	.searchdone
	add	rsi, 1
	sub	rdx, 1
	jmp	.search
calign
.searchdone:
	add	rsi, 1
	sub	rdx, 1
	syscall
end if
	epilog
if rfc5424
dalign
.bom	db	0xef, 0xbb, 0xbf
end if

end if

