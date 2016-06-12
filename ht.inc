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
	; ht.inc: main include file that includes everything else
	; 
	; YOU MUST INCLUDE a version of (copied/modified/renamed probably)
	;   of ht_defaults.inc, settings in here are required
	; 
	; first include MUST be above.
	;
	; it is assumed we are the second include (we define a data section, and then leave a dangling
	; code section) (so that include 'ht.inc' gets you all squared away with nothing else to type)
	;
	; NOTE: you must include (as a finale sorta thing) ht_data.inc
	;
	; initialization can come in many varieties, ht$init will initialise all of it depending on
	; which functions are actually used
	;

	; NOTE re: premature exit, this will exit with a code of 99 if heap mmap/mremap fails
	; and will exit with a code of 98 if profiler stack overrun
	; and will exit with a code of 97 if epoll minfds is not met (by setrlimit)
	; and will exit with a code of 96 if epoll_create fails

	;
	;	NOTE NOTE NOTE on '.data'/writeable/global variables
	;		so that hte linker doesn't have to combine sections
	;		just use the [crazy] macro method:
	;		globals
	;		{
	;			someglobal dq 0
	;		}
	;

	; include our data segment macros
	include 'dataseg_macros.inc'

	; now start our code segment:
	section '.text' executable align 16
ht$codeseg = $

	; include our multibyte nop alignment macros
	include 'align_macros.inc'

	; include our call macro
	include 'call.inc'
	
	; include our static string making macro
	include 'cleartext.inc'

	; include our ReadTSC macro
	include 'rdtsc.inc'

	; include our breakpoint macro (very small, but for organisation, nicer to have it separate)
	include 'breakpoint.inc'

	; include our nanosleep wrapper macros
	include 'sleeps.inc'

	; include our system call number convenience file
	include 'syscall.inc'

	; include our ansi colors macro (tui object inside the profiler needs it declared first)
	include 'tui_ansi.inc'

	; include our profiler (which includes prolog/epilog macros and the profiler itself)
	; note here re: settings, all of our functions still use the prolog/epilog macros,
	; so whether profiling is actually turned ON or not, the macros still need to be here
	include 'profiler.inc'

	; include our heap
	include 'heap.inc'

	include 'memfuncs.inc'

	; include our vdso parser
	include 'vdso.inc'

	include 'crc.inc'

	; include our math functions
	include 'math.inc'

	; include our rng
	include 'rng.inc'

	; basic list/queue goods
	include 'list.inc'

	; include our string handling goods
	include 'unicodecase.inc'

	if string_bits = 32
		include 'string32.inc'
	else
		include 'string16.inc'
	end if
	include 'dir.inc'

	include 'json.inc'

	include 'date.inc'

	include 'maps.inc'

	include 'blacklist.inc'

	include 'base64_latin1.inc'

	include 'buffer.inc'

	include 'formatter.inc'

	include 'syslog.inc'

	include 'zlib_inflate.inc'
	include 'zlib_deflate.inc'

	include 'mimelike.inc'

	include 'png.inc'

	include 'sha3.inc'
	include 'sha2.inc'
	include 'sha1.inc'
	include 'md5.inc'
	include 'hmac.inc'
	include 'hmac_drbg.inc'
	include 'pbkdf2.inc'
	include 'scrypt.inc'

	include 'aes.inc'
	include 'htcrypt.inc'
	include 'htxts.inc'

	include 'file.inc'

	include 'sysinfo.inc'

	include 'io.inc'

	include 'epoll.inc'
	include 'epoll_child.inc'

	include 'bigint.inc'
	include 'dh_pool.inc'
	include 'X509.inc'

	include 'curve25519.inc'
	include 'ed25519.inc'
	include 'poly1305.inc'
	include 'sodium_compat.inc'
	include 'tls.inc'
	include 'ssh.inc'

	include 'privmapped.inc'
	include 'mapped.inc'
	include 'mappedheap.inc'

	include 'tui_object.inc'
	include 'tui_render.inc'
	include 'tui_lock.inc'
	include 'tui_terminal.inc'
	include 'tui_background.inc'
	include 'tui_bell.inc'
	include 'tui_lines.inc'
	include 'tui_spinner.inc'
	include 'tui_spacers.inc'
	include 'tui_label.inc'
	include 'tui_progressbar.inc'
	include 'tui_text.inc'
	include 'tui_button.inc'
	include 'tui_panel.inc'
	include 'tui_alert.inc'
	include 'tui_textbox.inc'
	include 'tui_progressbox.inc'
	include 'tui_datagrid.inc'
	include 'tui_effect.inc'
	include 'tui_effects.inc'
	include 'tui_matrix.inc'
	include 'tui_ssh.inc'
	include 'tui_typist.inc'
	include 'tui_png.inc'
	include 'tui_splash.inc'
	include 'tui_simpleauth.inc'
	include 'tui_form.inc'
	include 'tui_statusbar.inc'
	include 'tui_newsticker.inc'

	include 'url.inc'
	include 'httpheaders.inc'
	include 'fcgiclient.inc'
	include 'webserver.inc'
	include 'cookiejar.inc'
	include 'webclient.inc'

if used argc | defined include_everything

; this is an ordinary integer

globals
{
argc	dq	0
}

end if

if used argv | used env | defined include_everything

; this is created with a list$new, such that arg parsing can be done with list$foreach
; nice and simple like

globals
{
argv	dq	0
}

end if

if used env | defined include_everything

; this is created with a stringmap$new, such that environments can be gotten with stringmap$find/findvalue

globals
{
env	dq	0
}

end if


; cpu-specific feature globals, if these are referenced, then ht$init will issue the necessary cpuid calls to work
; these out

if used is_Intel | used has_SSE3 | used has_SSSE3 | used has_SSE41 | used has_SSE42 | used has_POPCNT | used has_AVX | used has_AESNI | used cpu_L1_size | defined include_everything

globals
{
	is_Intel	dd	0
	has_SSE3	dd	0
	has_SSSE3	dd	0
	has_SSE41	dd	0
	has_SSE42	dd	0
	has_POPCNT	dd	0
	has_AVX		dd	0
	has_AESNI	dd	0
	cpu_L1_size	dd	0
}

end if


; convenience strings for uname goodies, only populated if they are used, note that these are actually strings
; we allocate them in the heap during init if they are referenced

if used uname$sysname | defined include_everything

globals
{
	uname$sysname	dq	0 
}

end if

if used uname$nodename | defined include_everything

globals
{
	uname$nodename	dq	0
}

end if

if used uname$release | defined include_everything

globals
{
	uname$release	dq	0
}

end if

if used uname$version | defined include_everything

globals
{
	uname$version	dq	0
}

end if

if used uname$machine | defined include_everything

globals
{
	uname$machine	dq	0
}

end if

	; two arguments: edi == argc, rsi == pointer to argv (null is okay, we'll ignore it if so but then argc/argv/env obviously won't work)
falign
ht$init_args:
	prolog	ht$init_args
	push	r12 r13
	mov	r12d, edi
	mov	r13, rsi

	if code_preload
		mov	rdi, ht$codeseg
		mov	rsi, ht$dataseg
calign
.preloadloop:
		movapd	xmm0, [rdi]
		add	rdi, 16
		cmp	rdi, rsi
		jb	.preloadloop
	end if
	if profiling
		call	profiler$init
	end if
	if used heap$alloc | used heap$free | defined include_everything
		call	heap$init
	end if
	if used is_Intel | used has_SSE3 | used has_SSSE3 | used has_SSE41 | used has_SSE42 | used has_POPCNT | used has_AVX | used has_AESNI | used cpu_L1_size | defined include_everything
		push	rbx
		xor	eax, eax
		cpuid
		xor	r8d, r8d
		mov	r9d, 1
		cmp	ecx, 'ntel'
		cmove	r8d, r9d
		mov	[is_Intel], r8d
		mov	eax, 1
		cpuid
		xor	r8d, r8d
		mov	r9d, 1
		test	ecx, 1
		cmovnz	r8d, r9d
		mov	[has_SSE3], r8d
		jz	.cachesize
		xor	r8d, r8d
		bt	ecx, 9
		cmovc	r8d, r9d
		mov	[has_SSSE3], r8d
		jnc	.cachesize
		xor	r8d, r8d
		bt	ecx, 19
		cmovc	r8d, r9d
		mov	[has_SSE41], r8d
		jnc	.cachesize
		xor	r8d, r8d
		bt	ecx, 23
		cmovc	r8d, r9d
		mov	[has_POPCNT], r8d
		jnc	.cachesize
		xor	r8d, r8d
		bt	ecx, 20
		cmovc	r8d, r9d
		mov	[has_SSE42], r8d
		jnc	.cachesize
		xor	r8d, r8d
		bt	ecx, 25
		cmovc	r8d, r9d
		mov	[has_AESNI], r8d

		xor	r8d, r8d
		bt	ecx, 28
		cmovc	r8d, r9d
		mov	[has_AVX], r8d
calign
.cachesize:
		; determine the size of our L1 cache
		cmp	dword [is_Intel], 0
		jne	.cachesize_intel
		mov	eax, 0x80000005
		cpuid
		movzx	eax, cl
		mov	[cpu_L1_size], eax
		jmp	.cachesize_done
calign
.cachesize_intel:
		movzx	eax, bh
		shl	eax, 3
		mov	[cpu_L1_size], eax
calign
.cachesize_done:
		; in the event of some freak of nature where we didn't get
		; a valid cache line size, make sure it is a sensible
		; default to avoid catastrophic infinite loops where
		; this value is used as a loop counter:
		mov	r8d, 64
		test	eax, eax
		cmovz	eax, r8d
		mov	[cpu_L1_size], eax
		pop	rbx
	end if
	if used argc | used argv | used env | defined include_everything
		if used argv | used env | defined include_everything
			call	list$new
			mov	[argv], rax
		end if
		if used env | defined include_everything
			call	stringmap$new
			mov	[env], rax
		end if
		mov	[argc], r12
		test	r13, r13
		jz	.skip_argvenv
		if used argv | used env | defined include_everything
			; parse our arguments, convert them to strings and insert into the argv list
			calign
			.argloop:
				mov	rdi, [r13]
				call	strlen_latin1
				mov	rdi, [r13]
				mov	rsi, rax
				call	string$from_utf8
				mov	rdi, [argv]
				mov	rsi, rax
				call	list$push_back
				add	r13, 8
				cmp	qword [r13], 0
				jne	.argloop
				add	r13, 8		; skip the null
		end if
		if used env | defined include_everything
			; parse our environment, convert them to stringmap and insert into the env
			calign
			.envloop:
				mov	rdi, [r13]
				call	strlen_latin1
				mov	rdi, [r13]
				mov	rsi, rax
				call	string$from_utf8
				push	rax
				mov	rdi, rax
				mov	esi, '='
				call	string$indexof_charcode
				cmp	rax, -1
				je	.envbad
				push	rax
				mov	rdi, [rsp+8]
				mov	esi, 0
				mov	rdx, rax
				call	string$substr
				push	rax
				mov	rdi, [rsp+16]
				mov	rsi, [rsp+8]
				add	rsi, 1
				mov	rdx, -1
				call	string$substr
				mov	rdi, [env]
				mov	rsi, [rsp]
				mov	rdx, rax
				call	stringmap$insert
				mov	rdi, [rsp+16]
				call	heap$free
				add	rsp, 24
				add	r13, 8
				cmp	qword [r13], 0
				jne	.envloop
				jmp	.envdone
			calign
			.envbad:
				pop	rdi
				call	heap$free
				add	r13, 8
				cmp	qword [r13], 0
				jne	.envloop
			calign
			.envdone:
		end if
		calign
		.skip_argvenv:
	end if
	if used uname$sysname | used uname$nodename | used uname$release | used uname$version | used uname$machine | defined include_everything
		sub	rsp, 512	; plenty of room for the struct utsname
		mov	eax, syscall_uname
		mov	rdi, rsp
		syscall
		test	eax, eax
		jnz	.baduname
		if used uname$sysname | defined include_everything
			mov	rdi, rsp
			call	strlen_latin1
			mov	rdi, rsp
			mov	rsi, rax
			call	string$from_utf8
			mov	[uname$sysname], rax
		end if
		if used uname$nodename | defined include_everything
			lea	rdi, [rsp+65]
			call	strlen_latin1
			lea	rdi, [rsp+65]
			mov	rsi, rax
			call	string$from_utf8
			mov	[uname$nodename], rax
		end if
		if used uname$release | defined include_everything
			lea	rdi, [rsp+65*2]
			call	strlen_latin1
			lea	rdi, [rsp+65*2]
			mov	rsi, rax
			call	string$from_utf8
			mov	[uname$release], rax
		end if
		if used uname$version | defined include_everything
			lea	rdi, [rsp+65*3]
			call	strlen_latin1
			lea	rdi, [rsp+65*3]
			mov	rsi, rax
			call	string$from_utf8
			mov	[uname$version], rax
		end if
		if used uname$machine | defined include_everything
			lea	rdi, [rsp+65*4]
			call	strlen_latin1
			lea	rdi, [rsp+65*4]
			mov	rsi, rax
			call	string$from_utf8
			mov	[uname$machine], rax
		end if
	calign
	.baduname:
		add	rsp, 512
	end if
	call	vdso$init
	if used syslog | defined include_everything
		call	syslog$init
	end if
	if used rng$int | used rng$intmax | used rng$u64 | used rng$u32 | used rng$double | defined include_everything
		call	rng$init
	end if
	if used epoll$iteration | used epoll$run | defined include_everything
		call	epoll$init
	end if
	if used tls$pemlookup | used tls$pemrevalidate | defined include_everything
		call	tls$peminit
	end if
	; if (tls_server_sessioncache & used tls$new_server) | (tls_client_sessioncache & used tls$new_client) | defined include_everything
	if (tls_server_sessioncache & used tls$new_server)
		call	tls$sessioncacheinit
	else if (tls_client_sessioncache & used tls$new_client)
		call	tls$sessioncacheinit
	else if defined include_everything
		call	tls$sessioncacheinit
	end if
	; if (used ssh$new_server & ssh_blacklist) | defined include_everything
	if (used ssh$new_server & ssh_blacklist)
		mov	edi, ssh_blacklist
		call	blacklist$new
		mov	[ssh$blacklist], rax
	else if defined include_everything
		mov	edi, ssh_blacklist
		call	blacklist$new
		mov	[ssh$blacklist], rax
	end if
	if used tui_splash$logo | defined include_everything
		; does the one-time png parse
		call	tui_splash$initlogo
	end if
	if used tui_statusbar$vtable | defined include_everything
		; sets up the text formatter for the uptime duration
		call	tui_statusbar$globalinit
	end if
	if used url$new | defined include_everything
		; sets up the scheme-port default map
		call	url$init
	end if
	if used webserver$sendresponse | used webserver$logs_path | defined include_everything
		; sets up the formatters that the webserver needs
		call	webserver$init
	end if
	if used webservercfg$hotlist | used webservercfg$direxists | defined include_everything
		; separated from webserver$init, as the functions are useful for other applications than just webserver
		call	webservercfg$init
	else if used webservercfg$fastcgi_map & webserver_fastcgi_postprocess
		call	webservercfg$init
	end if
	if used fcgiclient$new | defined include_everything
		; initializes the fastcgi initial client buffer statics
		call	fcgiclient$init
	end if
	if (webclient_global_dnscache & used wchost$new) | used wcdns$lookup_ipv4
		; initializes the global dns cache object for webclient
		call	wcdns$init
	end if
	pop	r13 r12
	epilog


; ht$init: initialise everything in our basket of goodies, depending on what was in settings.
falign
ht$init:
	prolog	ht$init
	; extract argc/argv depending on config/usage and pass back to ht$init_args
	if used argc | used argv | used env | defined include_everything
		; ht$init is called from a pure fasm enviro, so we can safely compute where
		; our _start entrypoint stackframe is
		if framepointers
			lea	rdx, [rsp+16]
		else
			lea	rdx, [rsp+8]
		end if
		mov	rdi, [rdx]		; argc is here
		lea	rsi, [rdx+8]		; argv pointer here
		call	ht$init_args
	else
		xor	edi, edi
		xor	esi, esi
		call	ht$init_args
	end if
	epilog



if used ht$syscall | defined include_everything
	; varargs, a NON-EFFICIENT wrapper for HLL -> syscall
	; particularly useful if you want to use HeavyThing w/ -nostdlib and still want
	; access to all the normal syscall goods
	; unfortunately due to the fact that we can't know in advance whether we have
	; no args, or all 6 args, we have to do some shuffling
	; edi == syscall number, rsi, rdx, rcx, r8, r9, r10 == arguments
falign
ht$syscall:
	prolog	ht$syscall
	mov	eax, edi
	mov	rdi, rsi
	mov	rsi, rdx
	mov	rdx, rcx
	mov	rcx, r10
	mov	r10, r8
	mov	r8, r9
	mov	r9, rcx
	syscall
	epilog

end if
