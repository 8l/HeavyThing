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
	; arguments.inc: rwasa's argument parsing (messy but effective)
	; and our globals for configuration goodies
	;

globals
{
	cpucount	dq	1
	runas		dq	0
	runasuid	dq	0
	runasgid	dq	0
	funcmatch	dq	0
	background	dq	1
	configs		dq	0
	pemfile		dq	0
}


	; no arguments, parses our startup arguments and sets up our global variables
falign
arguments:
	prolog	arguments
	mov	rdi, .default_runas
	call	string$copy
	mov	[runas], rax
	mov	rdi, .default_funcmatch
	call	string$copy
	mov	[funcmatch], rax
	call	list$new
	mov	[configs], rax
	; add our default webservercfg object 
	call	webservercfg$new
	mov	rdi, [configs]
	mov	rsi, rax
	call	list$push_back
	push	rbx r12 r13 r14
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
	xor	r12d, r12d		; bool as to whether we've seen any options
	xor	r14d, r14d		; bool as to whether we've seen bind options
calign
.argparse:
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, rax
	xor	esi, esi
	call	string$charat
	cmp	eax, '-'
	jne	.usage
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
	mov	ecx, dword [v]
	xor	edx, edx
	test	eax, eax
	cmovnz	ecx, edx
	mov	dword [v], ecx
	jnz	.arg_next_free
}
	argcheck '-cpu', .argcpu
	argcheck '-runas', .argrunas
	argbool '-foreground', background
	argcheck '-new', .argnew
	argcheck '-bind', .argbind
	argcheck '-tls', .argtls
	argcheck '-cachecontrol', .argcachecontrol
	argcheck '-filestattime', .argfilestattime
	argcheck '-logpath', .arglogpath
	argcheck '-errlog', .argerrlog
	argcheck '-errsyslog', .argerrsyslog
	argcheck '-fastcgi', .argfastcgi
	argcheck '-backpath', .argbackpath
	argcheck '-vhost', .argvhost
	argcheck '-sandbox', .argsandbox
	argcheck '-hostsandbox', .arghostsandbox
	argcheck '-indexfiles', .argindexfiles
	argcheck '-redirect', .argredirect
	argcheck '-funcmatch', .argfuncmatch
	; unrecognized argument
	mov	rdi, .err_badargopt
	call	string$to_stdout
	mov	rdi, r13
	call	string$to_stdoutln
	jmp	.usage
cleartext .default_runas, 'nobody'
cleartext .default_funcmatch, '.asmcall'
cleartext .err_badargopt, 'Unrecognized option: '

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
.argcachecontrol:
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
	jz	.argcachecontrol_nocache
	mov	rdi, rax
	call	webservercfg$make_cachecontrol
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	[rdi+webservercfg_cachecontrol_ofs], rax
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argcachecontrol_nocache:
	mov	rdi, r13
	call	heap$free
	mov	rdi, .nocachestring
	call	string$copy
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	[rdi+webservercfg_cachecontrol_ofs], rax
	jmp	.arg_next
cleartext .nocachestring, 'no-cache'
calign
.argfilestattime:
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
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	[rdi+webservercfg_filestattime_ofs], rax
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argrunas:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	mov	rdi, [runas]
	call	heap$free
	mov	rdi, rbx
	call	list$pop_front
	mov	[runas], rax
	jmp	.arg_next
calign
.argnew:
	mov	rdi, r13
	call	heap$free
	; so, if we haven't seen ANY options yet, don't do anything
	test	r12d, r12d
	jz	.arg_next
	; if we haven't seen any bind options, puke an error
	test	r14d, r14d
	jz	.argnew_nopriorbind
	; otherwise, create a new webservercfg object, and reset our flags
	call	webservercfg$new
	mov	rdi, [configs]
	mov	rsi, rax
	call	list$push_back
	; reset our bools
	xor	r12d, r12d
	xor	r14d, r14d
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs	; it makes no sense for a -new option on the end
	jmp	.arg_next
calign
.argnew_nopriorbind:
	mov	rdi, .err_nopriorbind
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_nopriorbind, 'Error: -new option specified, but no prior bind options for the previous config were present.'
calign
.argbind:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r14d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	; see if it contains a :, if not, treat it as a port
	mov	rdi, rax
	mov	esi, ':'
	call	string$indexof_charcode
	cmp	rax, 0
	jl	.argbind_portonly
	; otherwise, split them and sort out address goods first
	mov	rdi, r13
	mov	esi, ':'
	call	string$split
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	; we need space for our sockaddr_in_size + a spot to hangon to our string + a spot for our port
	sub	rsp, sockaddr_in_size + 16
	mov	rdi, r13
	call	list$pop_back
	mov	[rsp+sockaddr_in_size], rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp+sockaddr_in_size]
	mov	[rsp+sockaddr_in_size], rax
	call	heap$free
	mov	rdi, r13
	call	list$pop_front
	mov	[rsp+sockaddr_in_size+8], rax
	mov	rdi, rsp
	mov	rsi, rax
	mov	rdx, [rsp+sockaddr_in_size]
	call	inet_addr
	; save that result
	mov	rdi, [rsp+sockaddr_in_size+8]
	mov	[rsp+sockaddr_in_size+8], rax
	call	heap$free
	mov	rdi, r13
	call	heap$free
	cmp	dword [rsp+sockaddr_in_size+8], 0
	je	.argbind_badaddress
	; see if our port looked okay for sanity's sake
	cmp	qword [rsp+sockaddr_in_size], 0
	je	.argbind_badport
	cmp	qword [rsp+sockaddr_in_size], 65536
	jae	.argbind_badport
	; address/port looks okay, and r13 is free to use
	jmp	.argbind_doit
calign
.argbind_portonly:
	mov	rdi, r13
	call	string$to_unsigned
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	sub	rsp, sockaddr_in_size + 16
	mov	rdi, rsp
	mov	rsi, r13
	call	inaddr_any
	test	r13, r13
	jz	.argbind_badport
	cmp	r13, 65536
	jae	.argbind_badport
calign
.argbind_doit:
	; r13 is free to use, sockaddr_in at rsp is valid
	; so create our normal webserver object, using the last webservercfg object
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	call	webserver$new
	mov	r13, rax

	; if a previous pemfile option was set, create a tls layer
	mov	rdi, [pemfile]
	test	rdi, rdi
	jz	.argbind_doit_notls
	; set the istls flag for the webservercfg object so it can properly reconstruct preface URLs
	mov	rcx, [rax+webserver_config_ofs]
	mov	dword [rcx+webservercfg_istls_ofs], 1
	call	tls$new_server
	test	rax, rax
	jz	.argbind_pemerror
	; clear the pemfile for the next bind
	mov	qword [pemfile], 0
	mov	[r13+io_child_ofs], rax
	mov	[rax+io_parent_ofs], r13
	mov	[rsp+sockaddr_in_size], rax
	mov	rdi, epoll$default_vtable
	xor	esi, esi
	call	epoll$new
	mov	rdx, [rsp+sockaddr_in_size]
	mov	[rdx+io_child_ofs], rax
	mov	[rax+io_parent_ofs], rdx
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, r13
	call	epoll$inbound_delayed
	add	rsp, sockaddr_in_size + 16
	test	eax, eax
	jnz	.arg_next
	; otherwise, bind failed
	mov	rdi, .err_bindfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
calign
.argbind_doit_notls:
	mov	rdi, epoll$default_vtable
	xor	esi, esi
	call	epoll$new
	mov	[r13+io_child_ofs], rax
	mov	[rax+io_parent_ofs], r13
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, r13
	call	epoll$inbound_delayed
	add	rsp, sockaddr_in_size + 16
	test	eax, eax
	jnz	.arg_next
	; otherwise, bind failed
	mov	rdi, .err_bindfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_bindfail, 'Error: bind failed.'
calign
.argbind_pemerror:
	mov	rdi, .err_pemfailed
	call	string$to_stdout
	mov	rdi, [pemfile]
	call	string$to_stdoutln
	add	rsp, sockaddr_in_size + 16
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_pemfailed, 'PEM file contents or read error: '
calign
.argbind_badaddress:
	add	rsp, sockaddr_in_size + 16
	mov	rdi, .err_badbindaddress
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_badbindaddress, 'Error: Invalid bind address'
calign
.argbind_badport:
	add	rsp, sockaddr_in_size + 16
	mov	rdi, .err_badbindport
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_badbindport, 'Error: Invalid bind port'
calign
.argtls:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	; if there is already a pemfile set, free it
	mov	rdi, [pemfile]
	test	rdi, rdi
	jz	.argtls_noprior
	call	heap$free
calign
.argtls_noprior:
	mov	rdi, rbx
	call	list$pop_front
	mov	[pemfile], rax
	jmp	.arg_next
calign
.arglogpath:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$logs_path
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argerrlog:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$errorlog_path
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argerrsyslog:
	mov	rdi, r13
	call	heap$free
	add	r12d, 1
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	call	webservercfg$errorlog_syslog
	jmp	.arg_next
calign
.argfastcgi:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_size_ofs], 2
	jb	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	push	rax			; endswith
	mov	rdi, rbx
	call	list$pop_front
	push	rax			; address
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, [rsp+8]
	mov	rdx, rax
	call	webservercfg$fastcgi_map
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	jmp	.arg_next
calign
.argbackpath:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_size_ofs], 1
	jb	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	push	rax			; address
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$backpath
	pop	rdi
	call	heap$free
	jmp	.arg_next
calign
.argvhost:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$set_vhost
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argsandbox:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$global_sandbox
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.arghostsandbox:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_size_ofs], 2
	jb	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	push	rax			; hostname
	mov	rdi, rbx
	call	list$pop_front
	push	rax			; directory
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, [rsp+8]
	mov	rdx, rax
	call	webservercfg$host_sandbox
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	jmp	.arg_next
calign
.argindexfiles:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$index_files
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argredirect:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [configs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	call	webservercfg$set_redirect
	mov	rdi, r13
	call	heap$free
	jmp	.arg_next
calign
.argfuncmatch:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	je	.endofargs
	add	r12d, 1
	mov	rdi, rbx
	call	list$pop_front
	mov	r13, rax
	mov	rdi, [funcmatch]
	mov	[funcmatch], r13
	test	rdi, rdi
	jz	.arg_next
	call	heap$free
	jmp	.arg_next
calign
.argdone:
	test	r14d, r14d
	jz	.missingbind

	; before we bailout, make sure our runas user exists, and get its uid from /etc/passwd
	mov	rdi, .etcpasswd
	call	file$to_buffer
	test	rax, rax
	jz	.badetcpasswd
	mov	rbx, rax
calign
.passwdloop:
	mov	rdi, rbx
	mov	esi, 1
	call	buffer$has_more_lines
	test	eax, eax
	jz	.passwdfail
	mov	rdi, rbx
	call	buffer$nextline
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, [runas]
	call	string$starts_with
	test	eax, eax
	jnz	.passwdfound
	mov	rdi, r12
	call	heap$free
	jmp	.passwdloop
calign
.passwdfound:
	mov	rdi, rbx
	call	buffer$destroy
	mov	rdi, r12
	mov	esi, ':'
	call	string$split
	mov	rbx, rax
	mov	rdi, r12
	call	heap$free
	cmp	qword [rbx+_list_size_ofs], 4
	jb	.badetcpasswd
	mov	rdi, rbx
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	mov	rdi, rbx
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	mov	rdi, rbx
	call	list$pop_front
	mov	r12, rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	[runasuid], rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, rbx
	call	list$pop_front
	mov	r12, rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	[runasgid], rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, rbx
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, rbx
	call	heap$free
	pop	r14 r13 r12 rbx
	epilog
cleartext .etcpasswd, '/etc/passwd'
calign
.missingbind:
	mov	rdi, .err_missingbind
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_missingbind, 'Bind required for webserver configuration.'
calign
.badetcpasswd:
	mov	rdi, .err_badetcpasswd
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_badetcpasswd, 'Unable to read /etc/passwd to extract our runas uid.'
calign
.passwdfail:
	mov	rdi, .err_passwdfail
	call	string$to_stdoutln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .err_passwdfail, 'Unable to locate the runas user in /etc/passwd.'
calign
.arg_next_free:
	mov	rdi, r13
	call	heap$free
	cmp	qword [rbx+_list_first_ofs], 0
	jne	.argparse
	jmp	.argdone
calign
.arg_next:
	cmp	qword [rbx+_list_first_ofs], 0
	jne	.argparse
	jmp	.argdone
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
falign
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
db	'Usage: rwasa [options...]',10,\
	'Options are:',10,\
	'    -cpu count                  How many processes to start, defaults to 1',10,\
	'    -runas username             Run as username (defaults to nobody, parses /etc/passwd)',10,\
	'    -foreground                 Run in foreground (defaults to background)',10,\
	'    -new                        Start a new webserver configuration object',10,\
	'    -tls pemfile                Specify TLS PEM for next bind option',10,\
	'    -bind [addr:]port           Add a listener on [addr:]port',10,\
	'    -cachecontrol secs          Set static file cache control (default: 300)',10,\
	'    -filestattime secs          Set static file stat time (default: 120)',10,\
	'    -logpath directory          Specify full pathname where to put logs',10,\
	'    -errlog filename            Specify full filename for error logs',10,\
	'    -errsyslog                  Send errors to syslog',10,\
	'    -fastcgi endswith address   Add fastcgi handler (addr:host or /unixpath)',10,\
	'    -backpath address           Add backpath/upstream (addr:host or /unixpath)',10,\
	'    -vhost directory            Add virtual hosting directory (full path)',10,\
	'    -sandbox directory          Add global sandbox directory (full path)',10,\
	'    -hostsandbox host directory Add hostname sandbox directory (full path)',10,\
	'    -indexfiles list            Index files list (comma separated)',10,\
	'    -redirect url               Redirect all requests to url',10,\
	'    -funcmatch endswith         Function map ends with match (default: .asmcall)',10
.msg_usagelen = $ - .msg_usage
