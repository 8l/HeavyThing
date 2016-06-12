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
	; webslap.asm: modern day apachebench-style utility that is highly useful
	; for infrastructure testing/load testing, deployment quality assurance, etc.
	;
	; Adam Twiss' ApacheBench utility is still in widespread use, and works a
	; treat for barebones testing of a single URL. What it does _not_ do well
	; (at all) is TLS, or any real-world HTTP/1.1 features that for most normal
	; web environments are critical performance features. I am not cutting
	; Adam's work in _any_ way, and in fact, I ran Zeus webservers for many
	; years back in the day. Quite the opposite in fact, this is my best effort
	; at giving homage to his long-standing, and well-before-its-time work. He
	; was well-ahead of everyone else, and I am sure if he was still in the game
	; as it were, there'd be no reason for me to have written webslap :-)
	;
	; Anyway, on with the show. This is a "quick and dirty" bit of code, haha
	; but it does the required goods :-)
	;
	; CAUTION!! If you use this thing in a "maniac" sorta way, whereby we actually
	; run out of local available ports, the results are undefined (e.g. it will
	; most likely crash :-) Fortunately, for normal real-world testing, this
	; doesn't really cause any problems.
	;
	; See https://2ton.com.au/webslap for the full commentary/docs.
	;

include '../ht_defaults.inc'
include '../ht.inc'

include 'globals.inc'
include 'worker.inc'
include 'master.inc'

globals
{
prednslist	dq	0
}

public _start
falign
_start:
	call	ht$init

	call	list$new
	mov	[urls], rax

	mov	rbx, [argv]
	; sanity only, make sure we have argv[0]
	cmp	qword [rbx+_list_first_ofs], 0
	je	.usage
	; argv's first (aka ARGV[0]) is our progname, blast it first
	mov	rdi, rbx
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.usage
	xor	r12d, r12d
	; create a list to hold hostnames that we get during argument parsing:
	call	list$new
	mov	r15, rax
	mov	[prednslist], rax
calign
.argparse:
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, rax
	xor	esi, esi
	call	string$charat
	cmp	eax, '-'
	je	.argopt
	mov	rdi, r13
	mov	rsi, .postcolon
	call	string$starts_with
	test	eax, eax
	jnz	.posturl
	; make sure we can parse this as a fully qualified url, or bailout
	xor	edi, edi
	mov	rsi, r13
	call	url$new
	test	rax, rax
	jz	.badurl
	push	rax
	mov	rdi, [rax+url_host_ofs]
	call	string$copy
	mov	rdi, rax
	call	.predns_add
	pop	rdi
	call	url$destroy
	mov	rdi, [urls]
	mov	rsi, r13
	call	list$push_back
	add	r12d, 1
	cmp	qword [rbx+_list_first_ofs], 0
	jne	.argparse
calign
.doit:
	test	r12d, r12d
	jz	.nourls
	; truncate concurrency if it is >requests
	mov	rax, [concurrency]
	mov	rcx, [requests]
	cmp	rax, rcx
	cmova	rax, rcx
	mov	[concurrency], rax
	; if cpucount > concurrency, truncate cpucount
	mov	rcx, [cpucount]
	cmp	rcx, rax
	cmova	rcx, rax
	mov	[cpucount], rcx
	
	; OK so if we made it to here, we have reasonably sane parameters for launch.
	; so that none of our child processes have to do their own (and thus duplicate)
	; DNS queries, we'll preparse all URL hosts that we saw.
	mov	rdi, r15
	mov	rsi, .predns
	call	list$foreach

	mov	rdi, .greeting
	call	string$to_stdoutln

	; if there is no first, we don't mind leaving an empty list laying around
	; so jump straight to the master setup
	cmp	qword [r15+_list_first_ofs], 0
	je	master

	mov	rdi, .msg_predns
	call	string$to_stdoutln
	; now we have to hang around until those complete
calign
.predns_wait:
	call	epoll$iteration
	cmp	qword [r15+_list_first_ofs], 0
	jne	.predns_wait

	mov	rdi, r15
	call	heap$free
	
	jmp	master

cleartext .greeting, 'This is WebSlap v1.16 ',0xa9,' 2015, 2016 2 Ton Digital. Author: Jeff Marrison',10,'A showcase piece for the HeavyThing library. Commercial support available',10,'Proudly made in Cooroy, Australia. More info: https://2ton.com.au/webslap',10
cleartext .msg_predns, 'Preemptive DNS queries in progress...'
falign
.predns_add:
	; called with a single argument in rdi: the hostname (but it might be an IP address too)
	push	rbx
	mov	rbx, rdi
	sub	rsp, sockaddr_in_size
	mov	rdi, rsp
	mov	rsi, rbx
	call	inet_addr
	test	eax, eax
	jz	.predns_add_dns
	; make sure it didn't return us with 0.0.0.0 or 255.255.255.255
	lea	rdi, [rsp+4]
	cmp	dword [rdi], 0
	je	.predns_add_dns
	cmp	dword [rdi], 0xffffffff
	je	.predns_add_dns
	add	rsp, sockaddr_in_size
	; otherwise, ip address, don't add to predns list
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	ret
calign
.predns_add_dns:
	add	rsp, sockaddr_in_size
	mov	rdi, [prednslist]
	mov	rsi, rbx
	call	list$push_back
	pop	rbx
	ret
falign
.predns:
	; called with a single argument in rdi: the hostname to lookup (not an IP address)
	mov	rsi, .predns_success
	mov	rdx, .predns_failure
	mov	rcx, rdi
if webclient_global_dnscache
	call	wcdns$lookup_ipv4
else
	display 'HeavyThing library setting webclient_global_dnscache is required for webslap',10
	err
end if
	ret
falign
.predns_success:
	mov	rdi, [prednslist]
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	ret
falign
.predns_failure:
	push	rdi
	mov	rdi, .err_dnsfail
	call	string$to_stdout
	pop	rdi
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_dnsfail, 'DNS lookup failed for host: '
calign
.posturl:
	mov	rdi, r13
	mov	esi, ':'
	mov	edx, 5
	call	string$indexof_charcode_ofs
	cmp	rax, 0
	jl	.badurl
	mov	rdi, r13
	mov	esi, 5
	mov	rdx, rax
	call	string$substring
	mov	r14, rax
	mov	rdi, rax
	call	file$to_buffer
	test	rax, rax
	jz	.badpostfile
	mov	rdi, rax
	call	buffer$destroy
	mov	rdi, r13
	mov	esi, ':'
	mov	edx, 6
	add	rdx, [r14]
	call	string$indexof_charcode_ofs
	cmp	rax, 0
	jl	.badurl
	mov	rdi, r13
	mov	rsi, rax
	add	rsi, 1
	mov	rdx, -1
	call	string$substr
	mov	rdi, r14
	mov	r14, rax
	call	heap$free
	xor	edi, edi
	mov	rsi, r14
	call	url$new
	test	rax, rax
	cmovz	r13, r14
	jz	.badurl
	push	rax
	mov	rdi, [rax+url_host_ofs]
	call	string$copy
	mov	rdi, rax
	call	.predns_add
	pop	rdi
	call	url$destroy
	mov	rdi, r14
	call	heap$free
	mov	rdi, [urls]
	mov	rsi, r13
	call	list$push_back
	add	r12d, 1
	cmp	qword [rbx+_list_first_ofs], 0
	jne	.argparse
	jmp	.doit
cleartext .postcolon, 'POST:'
calign
.badurl:
	; offending url is in r13
	mov	rdi, .err_badurl
	call	string$to_stdout
	mov	rdi, r13
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_badurl, 'Bad URL: '
calign
.badpostfile:
	; offending filename is in r14
	mov	rdi, .err_badpostfile
	call	string$to_stdout
	mov	rdi, r14
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_badpostfile, 'Bad POST file: '
calign
.nourls:
	mov	rdi, .err_nourls
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_nourls, 'No URLs specified.'
calign
.argopt:
	; this is a lame way to deal with argument parsing, haha
	; someday I should really reconsider how I did the argv list
macro argcheck s*, j* {
	local	.start, .text
	jmp	.start
	cleartext .text, s
	.start:
	mov	rdi, r13
	mov	rsi, .text
	call	string$equals
	test	eax, eax
	jnz	j
}
macro argbool s*, v* {
	local	.start, .text
	jmp	.start
	cleartext .text, s
	.start:
	mov	rdi, r13
	mov	rsi, .text
	call	string$equals
	mov	ecx, [v]
	xor	edx, edx
	test	eax, eax
	cmovnz	ecx, edx
	mov	[v], ecx
	jnz	.arg_next_free
}
	argcheck '-n', .argn
	argcheck '-c', .argc
	argcheck '-cpu', .argcpu
	argcheck '-first', .argfirst
	argcheck '-g', .argg
	argcheck '-json', .argjson
	argbool '-nokeepalive', do_keepalive
	argbool '-nogz', do_gzip
	argbool '-nocookies', do_cookies
	argbool '-notlsresume', do_tlsresume
	argbool '-noetag', do_etag
	argbool '-nolastmodified', do_lastmod
	argbool '-ordered', do_random
	argbool '-noui', do_ui
	; unrecognized arg
	mov	rdi, .err_badargopt
	call	string$to_stdout
	mov	rdi, r13
	call	string$to_stdoutln
	jmp	.usage
cleartext .err_badargopt, 'Unrecognized option: '

calign
.argn:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, rax
	call	string$to_unsigned
	test	rax, rax
	jz	.nonsensearg
	mov	[requests], rax
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argc:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, rax
	call	string$to_unsigned
	test	rax, rax
	jz	.nonsensearg
	mov	[concurrency], rax
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argcpu:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, rax
	call	string$to_unsigned
	test	rax, rax
	jz	.nonsensearg
	mov	[cpucount], rax
	call	sysinfo$cpucount
	shl	rax, 1
	cmp	rax, [cpucount]
	jb	.crazycpucount
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argfirst:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	xor	edi, edi
	mov	rsi, rax
	call	url$new
	test	rax, rax
	jz	.badurl
	push	rax
	mov	rdi, [rax+url_host_ofs]
	call	string$copy
	mov	rdi, rax
	call	.predns_add
	pop	rdi
	call	url$destroy
	mov	rdi, [firsturl]
	mov	[firsturl], r13
	test	rdi, rdi
	jz	.arg_next
	call	heap$free
	jmp	.arg_next
calign
.argg:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, rbx
	call	list$pop_front
	mov	rdi, [tsvout]
	mov	[tsvout], rax
	test	rdi, rdi
	jz	.arg_next
	call	heap$free
calign
.arg_next:
	cmp	qword [rbx+_list_first_ofs], 0
	jne	.argparse
	jmp	.doit
calign
.argjson:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, rbx
	call	list$pop_front
	mov	rdi, [jsonout]
	mov	[jsonout], rax
	test	rdi, rdi
	jz	.arg_next
	call	heap$free
	jmp	.arg_next
calign
.arg_next_free:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	jne	.argparse
	jmp	.doit
calign
.nonsensearg:
	mov	rdi, .err_nonsense
	call	string$to_stdout
	mov	rdi, r13
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_nonsense, 'Nonsense argument: '
calign
.crazycpucount:
	mov	rdi, .err_crazycpucount
	call	string$to_stdout
	mov	rdi, r13
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_crazycpucount, 'Insane CPU count: '
calign
.endofargs:
	mov	rdi, .err_endofargs
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_endofargs, 'Unexpected end of arguments encountered.'
calign
.usage:
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, .msg_usage
	mov	edx, .msg_usagelen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.msg_usage:
db	'Usage: webslap [options] [POST:filename:contenttype:]http[s]://hostname[:port]/path[?query][#ref] [...]',10,\
	'Options are:',10,\
	'    -n requests       Number of requests to perform',10,\
	'    -c concurrency    Number of simultaneous channels',10,\
	'    -cpu count        Number of processes to use',10,\
	'    -first URL        Visit URL before commencing tests',10,\
	'    -g filename       Output TSV per-request data',10,\
	'    -json filename    Output JSON results',10,\
	'    -nokeepalive      Disable keep-alive',10,\
        '    -nogz             Disable ungzip/Accept-Encoding: gzip headers',10,\
	'    -nocookies        Disable session cookies',10,\
	'    -notlsresume      Disable TLS session resumption',10,\
	'    -noetag           Disable ETag/If-None-Match',10,\
	'    -nolastmodified   Disable Last-Modified/If-Modified-Since',10,\
	'    -ordered          Visit URL arglist in order instead of randomly',10,\
	'    -noui             Do not fire up a user interface',10
.msg_usagelen = $ - .msg_usage

include '../ht_data.inc'
