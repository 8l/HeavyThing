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
	; webserver.inc: HTTP/1.1 server io layer, and webserver configuration object goodies.
	;
	; Rather than configure an iochain layer with all of the configuration possibilities,
	; we keep configuration details in a separate object (webservercfg). The reason for this
	; is so that @clone time, it only copies a single pointer, and no construction/copying
	; is required.
	;
	; What this means is: if you create a webservercfg object, and then you create a listener
	; iochain/epoll object, the webservercfg object must persist for the life of the listener
	; and all its active connections. This being said, it is perfectly possible to change it
	; "on the fly".
	; 
	; IMPORTANT CAUTION/NOTE re: this design:
	; For file-based serving (ala sandbox/vhost/etc), I open mmaps for the underlying file
	; and recheck their mtime every 2 minutes to see if the mtime has changed, and if it did
	; I redo the mmap. This means that I am not doing stats every single request, far from
	; it, and it also means we don't maintain an actual byte cache of each file that we are
	; serving (and leave that to the OS via mmap). These are good things. :-)
	; Note that this does not apply to fastcgi/function mappings obviously, as we do not
	; do any mmap/file/disk io other than document root checking for those.
	; A _SERIOUS_ side effect of this design is: say you are serving up index.html, and
	; doing active development on the same file. When the first request arrives, we mmap it
	; and get our file size and base mapping pointer. So then, you _update_ index.html, and
	; you changed the _size_ of index.html. (Noting here, on all my linux systems, changing
	; it without changing the size, your changes do get reflected). The issue is our caching
	; of the size itself. Anyway, say you reduced the size of index.html, and then re-issue
	; a request inside the timeframe that we check for mtime changes. Well, what happens is
	; we do not get a SIGBUS or anything nasty, but when we go to send it out, we zero-pad
	; the size up to what it _was_, which is _not_ a good thing. (well, _we_ don't zero pad
	; it, the kernel does that for us).
	; REMEDY (and a penalty of my design that I am personally happy to pay) is:
	; if you change index.html, delete it first and make a new one. This way, our previous
	; mmap cache of index.html will remain _valid_ (and thus not zero padded or truncated),
	; until we come back around and check the mtime, which will be different, and then you'll
	; get your updated copy. HINT: vim script will do this for you ;-)
	; Since in all of my real-world webserver environments, production machines are _not_
	; in a constant state of change, this really isn't a penalty at all, and for my
	; dev environment to production environment deployments, I simply delete the previous
	; contents prior to placing the new ones, and nothing breaks thanks to the cacheing
	; strategy I have chosen here. There are trade-offs with any design really, and if
	; you strace most of the "common" approaches, hahah, _wow_ is about all I have to say
	; to that. Running straces on this one, after it has done its initial cacheing
	; (which is most of normal runtime) is quite a different ballgame.
	; If this strategy doesn't suit your needs, but you still want to use the rest of it
	; see webservercfg$hotlist and modify the way it does its cacheing and/or file i/o.
	;
	; CACHE SETTINGS: again for file-based serving (e.g. if we are serving real files from
	; a sandbox/vhost webservercfg setup), we make use of the library-wide setting for
	; webserver_filecache_time (whcih is in seconds). If you are messing around with an
	; active development web environment, then you'll obviously want to zero that (and if
	; it is at zero, we'll only send Cache-Control: no-cache and be done with it).
	; if it is >0 (the default is 300 seconds, and we x3 that for s-maxage), then we send
	; Cache-Control: no-transform,public,max-age=X,s-maxage=X*3 and an ETag and a
	; Last-Modified header.
	; For fastcgi maps and local function mapped requests/responses, of course we don't
	; set _any_ of those headers.
	;
	; RANGE REQUESTS: again for file-base serving, we don't bother to support multiple
	; ranges, but are happy to deal with single range requests. If a multiple range is
	; sent to us, we just puke out the full response (most clients I have seen in the 
	; wild only send a single range, so this suits me fine)
	;
	; HTTP Strict Transport Security: see the library setting for webserver_hsts
	; as to how it works, default is enabled.
	;
	; Amusing notes re: ApacheBench, which everyone that cares seems stuck on:
	; ApacheBench's TLS support has some very broken bits. Specifically, under TLS, as
	; specified by ab -f TLS1 (which of course is required for this TLS/HTTPS goods),
	; if the object you are messing with is not very small, it just doesn't work.
	; It does _not_ like the fact that we combine and send the headers + content out
	; all in one go, as opposed to a separate tls$send for the header, and then repeated
	; tls$sends with the data. Quite strange behaviour really, the method we have here
	; is compliant, and I am not about to change it.
	; Strangely, the _same_ behavior via non-TLS and ab works fine, go figure. Amusingly
	; in any case, ab is too slow TLS-wise to be of much use anyway.
	;


webserverdebug = 0

; separate one for timer debugging (can add lots of extra output)
webservertimerdebug = 0



if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything

	; NOTE HERE: for normal webserver logs and error logs, we automatically do timer-based
	; buffered logfile writing, but this functionality is only enabled if either are set
	; and to do so, we use an epoll$timer, which requires an epoll/io vtable for our timer
	; handler

webservercfg_vhost_ofs = io_base_size + 0			; string (directory name)
webservercfg_sandboxes_ofs = io_base_size + 8			; stringmap
webservercfg_indexfiles_ofs = io_base_size + 16			; list of string
webservercfg_logpath_ofs = io_base_size + 24			; string (directory name)
webservercfg_syslog_ofs = io_base_size + 32			; bool (errors only)
webservercfg_errorfile_ofs = io_base_size + 40			; string (file name)
webservercfg_errordocs_ofs = io_base_size + 48			; string (directory name)
webservercfg_fastcgi_ofs = io_base_size + 56			; stringmap (of heap$alloc'd socket addresses)
webservercfg_funcmap_ofs = io_base_size + 64			; stringmap
webservercfg_stats_ofs = io_base_size + 72			; string
webservercfg_istls_ofs = io_base_size + 80			; bool (used for constructing proper URLs from requests)
webservercfg_redirect_ofs = io_base_size + 88			; string, if set, overrides all other settings and forces a 302 redirect to here
webservercfg_logbuffer_ofs = io_base_size + 96
webservercfg_errorlogbuffer_ofs = io_base_size + 104
webservercfg_timerptr_ofs = io_base_size + 112
webservercfg_backpath_ofs = io_base_size + 120			; heap$alloc'd socket address if set, null if not
webservercfg_cachecontrol_ofs = io_base_size + 128		; override for the webserver_filecache_time config setting
webservercfg_filestattime_ofs = io_base_size + 136		; override for the webserver_hotlist_statfreq config setting
webservercfg_cachecontrolstr_ofs = io_base_size + 144		; override for string version of the Cache-Control header itself

webservercfg_size = io_base_size + 144

	; note: none of the io methods except for the timeout spot are used by the webservercfg object
	; which is why they are all set to the io defaults
dalign
webservercfg$vtable:
	dq	io$destroy, io$clone, io$connected, io$send, io$receive, io$error, webservercfg$timer


else

webservercfg_vhost_ofs = 0			; string (directory name)
webservercfg_sandboxes_ofs = 8			; stringmap
webservercfg_indexfiles_ofs = 16		; list of string
webservercfg_logpath_ofs = 24			; string (directory name)
webservercfg_syslog_ofs = 32			; bool (errors only)
webservercfg_errorfile_ofs = 40			; string (file name)
webservercfg_errordocs_ofs = 48			; string (directory name)
webservercfg_fastcgi_ofs = 56			; stringmap (of heap$alloc'd socket addresses)
webservercfg_funcmap_ofs = 64			; stringmap
webservercfg_stats_ofs = 72			; string
webservercfg_istls_ofs = 80			; bool (used for constructing proper URLs from requests)
webservercfg_redirect_ofs = 88			; string, if set, overrides all other settings and forces a 302 redirect to here
webservercfg_cachecontrol_ofs = 96		; override for the webserver_filecache_time config setting
webservercfg_filestattime_ofs = 104		; override for the webserver_hotlist_statfreq config setting
webservercfg_backpath_ofs = 112			; heap$alloc'd socket address if set, null if not

webservercfg_size = 120

end if






if used webservercfg$new_vhost | defined include_everything
	; single argument in rdi: the absolute base directory of the vhost area
	; /path/to/vhost sorta thing, to which the lower cased Host: header gets
	; added to for auto sandboxing
	; note: we add a trailing slash to the path if it doesn't end with one, so that during request
	; processing, we only have to do a single concatenation
	; returns new webservercfg object in rax
falign
webservercfg$new_vhost:
	prolog	webservercfg$new_vhost
	push	rbx
	mov	rbx, rdi
	cmp	qword [rdi], 0
	je	.slashonly
	mov	rsi, [rdi]
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	je	.asis
	mov	rdi, rbx
	mov	rsi, .slash
	call	string$concat
	mov	rbx, rax
	call	webservercfg$new
	mov	[rax+webservercfg_vhost_ofs], rbx
	pop	rbx
	epilog
calign
.slashonly:
	mov	rdi, .slash
	call	string$copy
	mov	rbx, rax
	call	webservercfg$new
	mov	[rax+webservercfg_vhost_ofs], rbx
	pop	rbx
	epilog
calign
.asis:
	mov	rdi, rbx
	call	string$copy
	mov	rbx, rax
	call	webservercfg$new
	mov	[rax+webservercfg_vhost_ofs], rbx
	pop	rbx
	epilog
cleartext .slash, '/'

end if
	

if used webservercfg$new_sandbox | defined include_everything
	; single argument in rdi: the absolute path of the docroot sandbox
	; returns new webservercfg object in rax
	; note: if the path ends in a /, we remove it, so that during request processing
	; we can do a single concatenation of the url's munged path to this directory
	; this ignores Host: headers entirely, and serves up whatever it gets from the sandbox dir.
falign
webservercfg$new_sandbox:
	prolog	webservercfg$new_sandbox
	push	rbx r12
	mov	r12, rdi
	mov	rdi, .nohost
	call	string$copy
	mov	rbx, rax
	cmp	qword [r12], 0
	je	.asis
	mov	rdi, r12
	mov	rsi, [r12]
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	jne	.asis
	mov	rdi, r12
	xor	esi, esi
	mov	rdx, [r12]
	sub	rdx, 1
	call	string$substr
	mov	r12, rax
	jmp	.doit
calign
.asis:
	mov	rdi, r12
	call	string$copy
	mov	r12, rax
calign
.doit:
	call	webservercfg$new
	mov	rdi, [rax+webservercfg_sandboxes_ofs]
	mov	rsi, rbx
	mov	rdx, r12
	mov	rbx, rax
	call	stringmap$insert_unique
	mov	rax, rbx
	pop	r12 rbx
	epilog
cleartext .nohost, '..nohost..'

end if


if used webservercfg$new | defined include_everything
	; no arguments, returns a clean slate webservercfg (good for making custom webapps)
falign
webservercfg$new:
	prolog	webservercfg$new
	xor	edi, edi
	call	stringmap$new
	push	rax
	call	list$new
	push	rax
	xor	edi, edi
	call	stringmap$new
	push	rax
	xor	edi, edi
	call	stringmap$new
	push	rax
	mov	edi, webservercfg_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	[rax+webservercfg_sandboxes_ofs], rdi
	mov	[rax+webservercfg_indexfiles_ofs], rsi
	mov	[rax+webservercfg_fastcgi_ofs], rdx
	mov	[rax+webservercfg_funcmap_ofs], rcx
	mov	qword [rax+webservercfg_filestattime_ofs], webserver_hotlist_statfreq
	push	rax
	mov	rdi, .indexhtml
	call	string$copy
	mov	rdi, [rsp]
	mov	rdi, [rdi+webservercfg_indexfiles_ofs]
	mov	rsi, rax
	call	list$push_back
	pop	rax

if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything
	push	rbx
	mov	rbx, rax
	mov	qword [rax], webservercfg$vtable
	call	buffer$new
	mov	[rbx+webservercfg_logbuffer_ofs], rax
	call	buffer$new
	mov	[rbx+webservercfg_errorlogbuffer_ofs], rax
	mov	edi, 1500		; every 1.5 seconds, dump our log buffers (any more and tail -f is lame, any less is overkill imo)
	mov	rsi, rbx
	call	epoll$timer_new
	; we don't need to set any special timer goods, because the timer itself will never ask for death
	; but we do need to keep it in the event we are destroyed
	mov	[rbx+webservercfg_timerptr_ofs], rax
	mov	rax, rbx
	pop	rbx
end if

if webserver_filecache_time
	push	rax
	mov	rdi, [webservercfg$cachecontrol]
	call	string$copy
	mov	rdx, rax
	pop	rax
	mov	[rax+webservercfg_cachecontrol_ofs], rdx
else
	push	rax
	mov	rdi, mimelike$noncache
	call	string$copy
	mov	rdx, rax
	pop	rax
	mov	[rax+webservercfg_cachecontrol_ofs], rdx
end if

	epilog
cleartext .indexhtml, 'index.html'

end if


if used webservercfg$new_copy | defined include_everything
	; single argument in rdi: webservercfg object to make a copy of
falign
webservercfg$new_copy:
	prolog	webservercfg$new_copy
	push	rbx r12
	mov	r12, rdi
	call	webservercfg$new
	mov	rbx, rax
	mov	rdi, [r12+webservercfg_vhost_ofs]
	call	.stringcopy
	mov	[rbx+webservercfg_vhost_ofs], rax
	mov	rdi, [r12+webservercfg_sandboxes_ofs]
	mov	rsi, .stringstringcopy
	mov	rdx, [rbx+webservercfg_sandboxes_ofs]
	call	stringmap$foreach_arg
	mov	rdi, [rbx+webservercfg_indexfiles_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [r12+webservercfg_indexfiles_ofs]
	mov	rsi, .listcopy
	mov	rdx, [rbx+webservercfg_indexfiles_ofs]
	call	list$foreach_arg
	mov	rdi, [r12+webservercfg_logpath_ofs]
	call	.stringcopy
	mov	[rbx+webservercfg_logpath_ofs], rax
	mov	rdx, [r12+webservercfg_syslog_ofs]
	mov	[rbx+webservercfg_syslog_ofs], rdx
	mov	rdi, [r12+webservercfg_errorfile_ofs]
	call	.stringcopy
	mov	[rbx+webservercfg_errorfile_ofs], rax
	mov	rdi, [r12+webservercfg_errordocs_ofs]
	call	.stringcopy
	mov	[rbx+webservercfg_errordocs_ofs], rax
	mov	rdi, [r12+webservercfg_fastcgi_ofs]
	mov	rsi, .stringheapcopy
	mov	rdx, [rbx+webservercfg_fastcgi_ofs]
	call	stringmap$foreach_arg
	mov	rdi, [r12+webservercfg_funcmap_ofs]
	mov	rsi, .stringintcopy
	mov	rdx, [rbx+webservercfg_funcmap_ofs]
	call	stringmap$foreach_arg
	mov	rdi, [r12+webservercfg_stats_ofs]
	call	.stringcopy
	mov	[rbx+webservercfg_stats_ofs], rax
	mov	rdi, [r12+webservercfg_backpath_ofs]
	call	.heapcopy
	mov	[rbx+webservercfg_backpath_ofs], rax
	mov	rax, rbx
	pop	r12 rbx
	epilog
falign
.stringcopy:
	mov	rax, rdi
	test	rdi, rdi
	jz	.stringcopy_nodeal
	call	string$copy
.stringcopy_nodeal:
	ret
falign
.stringstringcopy:
	push	rbx r12 r13
	mov	r12, rsi
	mov	r13, rdx
	call	string$copy
	mov	rbx, rax
	mov	rdi, r12
	call	string$copy
	mov	rdi, r13
	mov	rsi, rbx
	mov	rdx, rax
	call	stringmap$insert_unique
	pop	r13 r12 rbx
	ret
falign
.stringheapcopy:
	; used for the fastcgimap
	push	rbx r12 r13
	mov	r12, rsi
	mov	r13, rdx
	call	string$copy
	mov	rbx, rax
	mov	rdi, [r12]
	add	rdi, 8
	call	heap$alloc
	mov	rdi, rax
	mov	rsi, r12
	mov	rdx, [r12]
	add	rdx, 8
	mov	r12, rax
	call	memcpy
	mov	rdi, r13
	mov	rsi, rbx
	mov	rdx, r12
	call	stringmap$insert_unique
	pop	r13 r12 rbx
	ret
falign
.heapcopy:
	mov	rax, rdi
	test	rdi, rdi
	jz	.stringcopy_nodeal
	push	r12
	mov	r12, rdi
	mov	rdi, [rdi]
	add	rdi, 8
	call	heap$alloc
	mov	rdi, rax
	mov	rsi, r12
	mov	rdx, [r12]
	add	rdx, 8
	mov	r12, rax
	call	memcpy
	mov	rax, r12
	pop	r12
	ret
	
falign
.stringintcopy:
	push	r12 r13
	mov	r12, rsi
	mov	r13, rdx
	call	string$copy
	mov	rdi, r13
	mov	rsi, rax
	mov	rdx, r12
	call	stringmap$insert_unique
	pop	r13 r12
	ret
falign
.listcopy:
	push	rsi
	call	string$copy
	pop	rdi
	mov	rsi, rax
	call	list$push_back
	ret
end if


if used webservercfg$destroy | defined include_everything
	; single argument in rdi: webservercfg object to destroy
falign
webservercfg$destroy:
	prolog	webservercfg$destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+webservercfg_vhost_ofs]
	call	.maybefree
	mov	rdi, [rbx+webservercfg_redirect_ofs]
	call	.maybefree
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	mov	rsi, .stringstringfree
	call	stringmap$clear
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	call	heap$free
	mov	rdi, [rbx+webservercfg_indexfiles_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [rbx+webservercfg_indexfiles_ofs]
	call	heap$free
	mov	rdi, [rbx+webservercfg_logpath_ofs]
	call	.maybefree
	mov	rdi, [rbx+webservercfg_errorfile_ofs]
	call	.maybefree
	mov	rdi, [rbx+webservercfg_errordocs_ofs]
	call	.maybefree
	mov	rdi, [rbx+webservercfg_fastcgi_ofs]
	mov	rsi, .stringstringfree		; note: stringstringfree does heap$free for both sides, which is fine for the fastcgi map as well
	call	stringmap$clear
	mov	rdi, [rbx+webservercfg_backpath_ofs]
	call	.maybefree
	mov	rdi, [rbx+webservercfg_fastcgi_ofs]
	call	heap$free
	mov	rdi, [rbx+webservercfg_funcmap_ofs]
	mov	rsi, heap$free
	call	stringmap$clear
	mov	rdi, [rbx+webservercfg_funcmap_ofs]
	call	heap$free
	mov	rdi, [rbx+webservercfg_stats_ofs]
	call	.maybefree

if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything
	mov	rdi, [rbx+webservercfg_timerptr_ofs]
	call	epoll$timer_clear
	mov	rdi, [rbx+webservercfg_logbuffer_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+webservercfg_errorlogbuffer_ofs]
	call	buffer$destroy
end if
	mov	rdi, [rbx+webservercfg_cachecontrol_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
falign
.maybefree:
	test	rdi, rdi
	jz	.maybefree_nodeal
	call	heap$free
.maybefree_nodeal:
	ret
falign
.stringstringfree:
	push	rsi
	call	heap$free
	pop	rdi
	call	heap$free
	ret

end if



if used webservercfg$index_files | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == comma delimited list of index filenames
falign
webservercfg$index_files:
	prolog	webservercfg$index_files
	push	rdi rsi
	mov	rdi, [rdi+webservercfg_indexfiles_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rsi, [rsp+8]
	mov	rdi, [rsi+webservercfg_indexfiles_ofs]
	call	heap$free
	pop	rdi
	mov	esi, ','
	call	string$split
	pop	rdi
	mov	[rdi+webservercfg_indexfiles_ofs], rax
	epilog

end if


if used webservercfg$global_sandbox | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == global sandbox to set
falign
webservercfg$global_sandbox:
	prolog	webservercfg$global_sandbox
	push	rbx r12
	mov	rbx, rdi
	mov	rdi, rsi
	call	string$copy
	mov	r12, rax
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	mov	rsi, .nohost
	call	stringmap$find
	test	rax, rax
	jz	.newone
	mov	rdi, [rax+_avlofs_value]
	mov	[rax+_avlofs_value], r12
	call	heap$free
	epilog
calign
.newone:
	mov	rdi, .nohost
	call	string$copy
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	mov	rsi, rax
	mov	rdx, r12
	call	stringmap$insert_unique
	pop	r12 rbx
	epilog
cleartext .nohost, '..nohost..'

end if


if used webservercfg$host_sandbox | defined include_everything
	; three arguments: rdi == webservercfg object, rsi == hostname, rdx == absolute path to sandbox
	; if the sandbox path ends in /, we remove it so that we only have to concat strings once during request processing
falign
webservercfg$host_sandbox:
	prolog	webservercfg$host_sandbox
	; copy both strings, add to sandboxes map
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r13, rdx
	mov	rdi, rsi
	call	string$to_lower
	mov	r12, rax
	cmp	qword [r13], 0
	je	.asis
	mov	rdi, r13
	mov	rsi, [r13]
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	jne	.asis
	mov	rdi, r13
	xor	esi, esi
	mov	rdx, [r13]
	sub	rdx, 1
	call	string$substr
	mov	r13, rax
	jmp	.doit
calign
.asis:
	mov	rdi, r13
	call	string$copy
	mov	r13, rax
calign
.doit:
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	mov	rsi, r12
	mov	rdx, r13
	call	stringmap$insert_unique
	pop	r13 r12 rbx
	epilog

end if

if used webservercfg$set_vhost | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == vhost directory path
	; note: we add a trailing slash to the path if it doesn't end with one
falign
webservercfg$set_vhost:
	prolog	webservercfg$set_vhost
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	cmp	qword [rdi+webservercfg_vhost_ofs], 0
	je	.noprior
	mov	rdi, [rdi+webservercfg_vhost_ofs]
	call	heap$free
calign
.noprior:
	mov	rdi, r12
	call	string$copy
	mov	[rbx+webservercfg_vhost_ofs], rax
	mov	rsi, [rax]
	mov	rdi, rax
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	jne	.addslash
	pop	r12 rbx
	epilog
calign
.addslash:
	mov	rdi, [rbx+webservercfg_vhost_ofs]
	mov	rsi, .slash
	call	string$concat
	mov	rdi, [rbx+webservercfg_vhost_ofs]
	mov	[rbx+webservercfg_vhost_ofs], rax
	call	heap$free
	pop	r12 rbx
	epilog
cleartext .slash, '/'

end if

if used webservercfg$set_redirect | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == string redirect url
falign
webservercfg$set_redirect:
	prolog	webservercfg$set_redirect
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	cmp	qword [rdi+webservercfg_redirect_ofs], 0
	je	.noprior
	mov	rdi, [rdi+webservercfg_redirect_ofs]
	call	heap$free
calign
.noprior:
	mov	rdi, r12
	call	string$copy
	mov	[rbx+webservercfg_redirect_ofs], rax
	pop	r12 rbx
	epilog

end if


if used webservercfg$logs_path | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == absolute path to write logs to
	; if the path here does not end in a /, we add one so that our logwriter only has to do a single concat
	; further, we add access.log., such that the log writer only has to add the YYYYMMDD to the end of the filename
falign
webservercfg$logs_path:
	prolog	webservercfg$logs_path
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	cmp	qword [rdi+webservercfg_logpath_ofs], 0
	je	.noprior
	mov	rdi, [rdi+webservercfg_logpath_ofs]
	call	heap$free
calign
.noprior:
	cmp	qword [r12], 0
	je	.slashonly
	mov	rdi, r12
	mov	rsi, [r12]
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	je	.asis
	mov	rdi, r12
	mov	rsi, .slashaccesslogdot
	call	string$concat
	mov	[rbx+webservercfg_logpath_ofs], rax
	pop	r12 rbx
	epilog
calign
.slashonly:
	; probably not what you want, hahah
	mov	rdi, .slashaccesslogdot
	call	string$copy
	mov	[rbx+webservercfg_logpath_ofs], rax
	pop	r12 rbx
	epilog
calign
.asis:
	mov	rdi, r12
	mov	rsi, .accesslogdot
	call	string$concat
	mov	[rbx+webservercfg_logpath_ofs], rax
	pop	r12 rbx
	epilog
cleartext .slashaccesslogdot, '/access.log.'
cleartext .accesslogdot, 'access.log.'

end if


if used webservercfg$errorlog_syslog | defined include_everything
	; single argument in rdi: our webservercfg object
	; calling this will send errors to the syslog (though you could just do the one-liner yourself)
	; NOTE: the code that actually does send it to the syslog does: if used webservercfg$errorlog_syslog
	; so while it may be tempting to just set the dword externally, hehe, call this.
falign
webservercfg$errorlog_syslog:
	prolog	webservercfg$errorlog_syslog
	mov	dword [rdi+webservercfg_syslog_ofs], 1
	epilog

end if


if used webservercfg$errorlog_path | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == filename of logfile to write errors to
falign
webservercfg$errorlog_path:
	prolog	webservercfg$errorlog_path
	cmp	qword [rdi+webservercfg_errorfile_ofs], 0
	je	.noprior
	push	rdi rsi
	mov	rdi, [rdi+webservercfg_errorfile_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+webservercfg_errorfile_ofs], rax
	epilog
calign
.noprior:
	push	rdi
	mov	rdi, rsi
	call	string$copy
	pop	rdi
	mov	[rdi+webservercfg_errorfile_ofs], rax
	epilog

end if


if used webservercfg$errordocs_path | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == absolute path to error html files (a directory path that is)
	; if the directory path doesn't end in /, we add one (so that error document lookup is made easier)
	; files should be named 404.html, etc.
falign
webservercfg$errordocs_path:
	prolog	webservercfg$errordocs_path
	cmp	qword [rdi+webservercfg_errordocs_ofs], 0
	je	.noprior
	push	rdi rsi
	mov	rdi, [rdi+webservercfg_errordocs_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	mov	rdi, [rsp]
	mov	[rdi+webservercfg_errordocs_ofs], rax
	jmp	.checktrailingslash
calign
.noprior:
	push	rdi
	mov	rdi, rsi
	call	string$copy
	mov	rdi, [rsp]
	mov	[rdi+webservercfg_errordocs_ofs], rax
calign
.checktrailingslash:
	cmp	qword [rax], 0
	je	.done
	mov	rsi, [rax]
	mov	rdi, rax
	sub	rsi, 1
	call	string$charat
	cmp	eax, '/'
	je	.done
	mov	rdi, [rsp]
	mov	rdi, [rdi+webservercfg_errordocs_ofs]
	mov	rsi, .slash
	call	string$concat
	mov	rsi, [rsp]
	mov	rdi, [rsi+webservercfg_errordocs_ofs]
	mov	[rsi+webservercfg_errordocs_ofs], rax
	call	heap$free
	pop	rdi
	epilog
calign
.done:
	pop	rdi
	epilog
cleartext .slash, '/'

end if


if used webservercfg$fastcgi_map | defined include_everything
	; three arguments: rdi == webservercfg object, rsi == file ends with match string, rdx == string fastcgi address
	; rsi == something like '.php', such that if the request is https://example.com/subdir/example.php?testing
	; then the request will automatically be sent via fastcgi...
	; fastcgi address can contain either an absolute pathname (unix fd), or if it doesn't begin with /, then
	; it is assumed to be an IPv4 address:port
	; further commentary on matching: this can be '.php', but can also be '/somedir/test.php', or even fully qualified
	; system paths, because the matching is done as an ends_with against the document root + the munged url path (after ../.. removal, etc)
falign
webservercfg$fastcgi_map:
	prolog	webservercfg$fastcgi_map
	; our webservercfg_fastcgi_ofs is a stringmap for matching, and a heap$alloc'd block for the destination address
	; and we compute the destination address here, so that during runtime, no such calcs are required
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	rdi, rsi
	mov	r13, rdx
	call	string$copy
	mov	r12, rax
	mov	rdi, r13
	mov	esi, 0
	call	string$charat
	cmp	eax, '/'
	je	.unixaddr
	; otherwise, make sure it has a :
	mov	rdi, r13
	mov	esi, ':'
	call	string$indexof_charcode
	cmp	rax, 0
	jl	.unixaddr
	mov	r15d, eax
	mov	edi, sockaddr_in_size + 8
	call	heap$alloc_clear
	mov	r14, rax
	mov	qword [rax], sockaddr_in_size
	mov	rdi, r13
	xor	esi, esi
	mov	edx, r15d
	call	string$substr
	mov	rdi, r13
	mov	esi, r15d
	add	esi, 1
	mov	rdx, -1
	mov	r15, rax
	call	string$substr
	push	rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	pop	rdx
	lea	rdi, [r14+8]
	mov	rsi, r15
	call	inet_addr
	mov	rdi, r15
	call	heap$free
	mov	rdi, [rbx+webservercfg_fastcgi_ofs]
	mov	rsi, r12
	mov	rdx, r14
	call	stringmap$insert_unique
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.unixaddr:
	mov	edi, sockaddr_un_size + 8
	call	heap$alloc_clear
	mov	r14, rax
	mov	qword [rax], sockaddr_un_size
	lea	rdi, [rax+8]
	mov	rsi, r13
	call	unix_addr
	mov	rdi, [rbx+webservercfg_fastcgi_ofs]
	mov	rsi, r12
	mov	rdx, r14
	call	stringmap$insert_unique
	pop	r15 r14 r13 r12 rbx
	epilog
	
end if


if used webservercfg$backpath | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == string backpath address
	; address can contain either an absolute pathname (unix fd), or if it doesn't begin with / then
	; it is assumed to be an IPv4 address:port
falign
webservercfg$backpath:
	prolog	webservercfg$backpath
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r13, rsi
	mov	rdi, rsi
	mov	esi, 0
	call	string$charat
	cmp	eax, '/'
	je	.unixaddr
	; otherwise, make sure it has a :
	mov	rdi, r13
	mov	esi, ':'
	call	string$indexof_charcode
	cmp	rax, 0
	jl	.unixaddr
	mov	r15d, eax
	mov	edi, sockaddr_in_size + 8
	call	heap$alloc_clear
	mov	r14, rax
	mov	qword [rax], sockaddr_in_size
	mov	rdi, r13
	xor	esi, esi
	mov	edx, r15d
	call	string$substr
	mov	rdi, r13
	mov	esi, r15d
	add	esi, 1
	mov	rdx, -1
	mov	r15, rax
	call	string$substr
	push	rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	pop	rdx
	lea	rdi, [r14+8]
	mov	rsi, r15
	call	inet_addr
	mov	rdi, r15
	call	heap$free
	mov	[rbx+webservercfg_backpath_ofs], r14
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.unixaddr:
	mov	edi, sockaddr_un_size + 8
	call	heap$alloc_clear
	mov	r14, rax
	mov	qword [rax], sockaddr_un_size
	lea	rdi, [rax+8]
	mov	rsi, r13
	call	unix_addr
	mov	[rbx+webservercfg_backpath_ofs], r14
	pop	r15 r14 r13 r12 rbx
	epilog

end if


if used webservercfg$function_map | defined include_everything
	; three arguments: rdi == webservercfg object, rsi == file ends with match string, rdx == function pointer to call
	; rsi == something like '.asm', similar to fastcgi_map (is directory/host independent, any url that ends
	; with the match string will get passed to your function).
	; the function will get called with: rdi == webserver object, rsi == request url, rdx == mimelike object of request
	; it should return similarly to how the custom vmethod approach works (null ret == auto 404, -1 == do nothing,
	; else mimelike response object to send out)
	; further commentary on matching: this can be '.asm', but can also be '/somedir/test.asm', or even fully qualified
	; system paths, because the matching is done as an ends_with against the document root + the munged url path (after ../.. removal, etc)
falign
webservercfg$function_map:
	prolog	webservercfg$function_map
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rdx
	mov	rdi, rsi
	call	string$copy
	mov	rdi, [rbx+webservercfg_funcmap_ofs]
	mov	rsi, rax
	mov	rdx, r12
	call	stringmap$insert_unique
	pop	r12 rbx
	epilog

end if



if used webservercfg$stats_exact | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == exact file to match
	; if url.file == rsi, then we return our webserver statistics goods
	; NOTE: if this function is not called, no stats are kept in the first place
falign
webservercfg$stats_exact:
	prolog	webservercfg$stats_exact
	cmp	qword [rdi+webservercfg_stats_ofs], 0
	je	.noprior
	push	rdi rsi
	mov	rdi, [rdi+webservercfg_stats_ofs]
	call	heap$free
	pop	rdi
	call	string$copy
	pop	rdi
	mov	[rdi+webservercfg_stats_ofs], rax
	epilog
calign
.noprior:
	push	rdi
	mov	rdi, rsi
	call	string$copy
	pop	rdi
	mov	[rdi+webservercfg_stats_ofs], rax
	epilog

end if

if used webservercfg$direxists | used webservercfg$hotlist | used webservercfg$mimetype | defined include_everything

globals
{
	webservercfg$dirmap	dq	0

	webservercfg$hotmap	dq	0
	webservercfg$hotfirst	dq	0
	webservercfg$hotlast	dq	0

	webservercfg$mimemap	dq	0

if webserver_filecache_time
	webservercfg$cachecontrol	dq	0
end if

	webservercfg$rangeformat	dq	0
}

end if

globals
{
if used webservercfg$fastcgi_map & webserver_fastcgi_postprocess
	webservercfg$fastcgiqueue	dq	0
else if defined include_everything
	webservercfg$fastcgiqueue	dq	0
end if
}

if used webservercfg$make_cachecontrol | defined include_everything
	; single argument in rdi: the time in seconds of the cachecontrol header
	; returns a new string appropriate for the value side of the header itself
falign
webservercfg$make_cachecontrol:
	prolog	webservercfg$make_cachecontrol
	; we want: no-transform,public,max-age=X
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, .cachecontrolpreface
	mov	rsi, rax
	push	rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	pop	rax
	epilog
cleartext .cachecontrolpreface, 'no-transform,public,max-age='

end if



if used webservercfg$init | defined include_everything
	; no arguments, initializes the necessary cache lists/maps
falign
webservercfg$init:
	prolog	webservercfg$init
	xor	edi, edi
	call	stringmap$new
	mov	[webservercfg$dirmap], rax
	xor	edi, edi
	call	stringmap$new
	mov	[webservercfg$hotmap], rax

if used webservercfg$fastcgi_map & webserver_fastcgi_postprocess
	call	list$new
	mov	[webservercfg$fastcgiqueue], rax
else if defined include_everything
	call	list$new
	mov	[webservercfg$fastcgiqueue], rax
end if

if webserver_filecache_time
	mov	edi, webserver_filecache_time
	call	webservercfg$make_cachecontrol
	mov	[webservercfg$cachecontrol], rax
end if
	xor	edi, edi
	call	formatter$new
	mov	[webservercfg$rangeformat], rax
	mov	rdi, rax
	mov	rsi, .rangeformatpreface
	call	formatter$add_static
	mov	rdi, [webservercfg$rangeformat]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [webservercfg$rangeformat]
	mov	rsi, .rangedash
	call	formatter$add_static
	mov	rdi, [webservercfg$rangeformat]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [webservercfg$rangeformat]
	mov	rsi, .rangeslash
	call	formatter$add_static
	mov	rdi, [webservercfg$rangeformat]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned

	; our mimemap config is next
	xor	edi, edi
	call	unsignedmap$new
	mov	[webservercfg$mimemap], rax

macro mimemap_addone k*, v* {
	mov	rdi, [webservercfg$mimemap]
	mov	esi, k
	mov	rdx, v
	call	unsignedmap$insert_unique
}
	; hmm, does anyone really use upper case filenames anymore? probably not.. TODO: removeme
	mimemap_addone 'html', .texthtml
	mimemap_addone 'HTML', .texthtml
	mimemap_addone 'htm', .texthtml
	mimemap_addone 'HTM', .texthtml
	mimemap_addone 'shtm', .texthtml
	mimemap_addone 'SHTM', .texthtml
	mimemap_addone 'txt', .textplain
	mimemap_addone 'TXT', .textplain
	mimemap_addone 'css', .textcss
	mimemap_addone 'CSS', .textcss
	mimemap_addone 'xml', .textxml
	mimemap_addone 'XML', .textxml
	mimemap_addone 'csv', .textcsv
	mimemap_addone 'CSV', .textcsv
	mimemap_addone 'gif', .imagegif
	mimemap_addone 'GIF', .imagegif
	mimemap_addone 'jpg', .imagejpeg
	mimemap_addone 'JPG', .imagejpeg
	mimemap_addone 'jpeg', .imagejpeg
	mimemap_addone 'JPEG', .imagejpeg
	mimemap_addone 'png', .imagepng
	mimemap_addone 'PNG', .imagepng
	mimemap_addone 'tif', .imagetiff
	mimemap_addone 'TIF', .imagetiff
	mimemap_addone 'tiff', .imagetiff
	mimemap_addone 'TIFF', .imagetiff
	mimemap_addone 'ico', .imageicon
	mimemap_addone 'ICO', .imageicon
	mimemap_addone 'jng', .imagejng
	mimemap_addone 'JNG', .imagejng
	mimemap_addone 'bmp', .imagebmp
	mimemap_addone 'BMP', .imagebmp
	mimemap_addone 'wbmp', .imagewbmp
	mimemap_addone 'WBMP', .imagewbmp
	mimemap_addone 'svg', .imagesvg
	mimemap_addone 'svgz', .imagesvg
	mimemap_addone 'SVG', .imagesvg
	mimemap_addone 'SVGZ', .imagesvg
	mimemap_addone 'js', .appjs
	mimemap_addone 'JS', .appjs
	mimemap_addone 'json', .appjson
	mimemap_addone 'JSON', .appjson
	mimemap_addone 'atom', .appatom
	mimemap_addone 'ATOM', .appatom
	mimemap_addone 'rss', .apprss
	mimemap_addone 'RSS', .apprss
	mimemap_addone 'jar', .appjar
	mimemap_addone 'JAR', .appjar
	mimemap_addone 'war', .appjar
	mimemap_addone 'WAR', .appjar
	mimemap_addone 'ear', .appjar
	mimemap_addone 'EAR', .appjar
	mimemap_addone 'pdf', .apppdf
	mimemap_addone 'PDF', .apppdf
	mimemap_addone 'ps', .appps
	mimemap_addone 'PS', .appps
	mimemap_addone 'eps', .appps
	mimemap_addone 'EPS', .appps
	mimemap_addone 'ai', .appai
	mimemap_addone 'AI', .appai
	mimemap_addone 'rtf', .apprtf
	mimemap_addone 'RTF', .apprtf
	mimemap_addone 'xhtm', .appxhtml
	mimemap_addone 'XHTM', .appxhtml
	mimemap_addone 'rar', .apprar
	mimemap_addone 'RAR', .apprar
	mimemap_addone 'rpm', .apprpm
	mimemap_addone 'RPM', .apprpm
	mimemap_addone 'swf', .appswf
	mimemap_addone 'SWF', .appswf
	mimemap_addone 'der', .appx509
	mimemap_addone 'DER', .appx509
	mimemap_addone 'pem', .appx509
	mimemap_addone 'PEM', .appx509
	mimemap_addone 'crt', .appx509
	mimemap_addone 'CRT', .appx509
	mimemap_addone 'zip', .appzip
	mimemap_addone 'ZIP', .appzip
	mimemap_addone 'aif', .audioaiff
	mimemap_addone 'AIF', .audioaiff
	mimemap_addone 'aifc', .audioaiff
	mimemap_addone 'AIFC', .audioaiff
	mimemap_addone 'aiff', .audioaiff
	mimemap_addone 'AIFF', .audioaiff
	mimemap_addone 'mp3', .audiomp3
	mimemap_addone 'MP3', .audiomp3
	mimemap_addone 'mid', .audiomidi
	mimemap_addone 'MID', .audiomidi
	mimemap_addone 'midi', .audiomidi
	mimemap_addone 'MIDI', .audiomidi
	mimemap_addone 'kar', .audiomidi
	mimemap_addone 'KAR', .audiomidi
	mimemap_addone '3gp', .video3gpp
	mimemap_addone '3GP', .video3gpp
	mimemap_addone '3gpp', .video3gpp
	mimemap_addone '3GPP', .video3gpp
	mimemap_addone 'mpg', .videompeg
	mimemap_addone 'MPG', .videompeg
	mimemap_addone 'mpeg', .videompeg
	mimemap_addone 'MPEG', .videompeg
	mimemap_addone 'mov', .videoquicktime
	mimemap_addone 'MOV', .videoquicktime
	mimemap_addone 'flv', .videoflv
	mimemap_addone 'FLV', .videoflv
	mimemap_addone 'mng', .videomng
	mimemap_addone 'MNG', .videomng
	mimemap_addone 'asx', .videoasf
	mimemap_addone 'ASX', .videoasf
	mimemap_addone 'asf', .videoasf
	mimemap_addone 'ASF', .videoasf
	mimemap_addone 'wmv', .videowmv
	mimemap_addone 'WMV', .videowmv
	mimemap_addone 'avi', .videoavi
	mimemap_addone 'AVI', .videoavi
	mimemap_addone 'mp4', .videomp4
	mimemap_addone 'MP4', .videomp4
	mimemap_addone 'm4v', .videom4v
	mimemap_addone 'M4V', .videom4v
	mimemap_addone 'htc', .textxcomp
	mimemap_addone 'HTC', .textxcomp
	mimemap_addone 'wml', .textwml
	mimemap_addone 'WML', .textwml
	mimemap_addone 'jad', .textappdesc
	mimemap_addone 'JAD', .textappdesc
	mimemap_addone 'mml', .textmathml
	mimemap_addone 'MML', .textmathml

	epilog
cleartext .texthtml, 'text/html'
cleartext .textplain, 'text/plain'
cleartext .textcss, 'text/css'
cleartext .textcsv, 'text/comma-separated-values'
cleartext .textxml, 'text/xml'
cleartext .textxcomp, 'text/x-component'
cleartext .textwml, 'text/vnd.wap.wml'
cleartext .textappdesc, 'text/vnd.sun.j2me.app-descriptor'
cleartext .textmathml, 'text/mathml'
cleartext .imagegif, 'image/gif'
cleartext .imagejpeg, 'image/jpeg'
cleartext .imagepng, 'image/png'
cleartext .imagetiff, 'image/tiff'
cleartext .imageicon, 'image/x-icon'
cleartext .imagejng, 'image/x-jng'
cleartext .imagebmp, 'image/x-ms-bmp'
cleartext .imagewbmp, 'image/vnd.wap.wbmp'
cleartext .imagesvg, 'image/svg+xml'
cleartext .appjs, 'application/javascript'
cleartext .appjson, 'application/json'
cleartext .appatom, 'application/atom+xml'
cleartext .apprss, 'application/rss+xml'
cleartext .appjar, 'application/java-archive'
cleartext .apppdf, 'application/pdf'
cleartext .appps, 'application/postscript'
cleartext .appai, 'application/illustrator'
cleartext .apprtf, 'application/rtf'
cleartext .appxhtml, 'application/vnd.wap.xhtml+xml'
cleartext .apprar, 'application-x-rar-compressed'
cleartext .apprpm, 'application-x-redhat-package-manager'
cleartext .appswf, 'application/x-shockwave-flash'
cleartext .appx509, 'application/x-x509-ca-cert'
cleartext .appzip, 'application/zip'
cleartext .audioaiff, 'audio/aiff'
cleartext .audiomp3, 'audio/mpeg'
cleartext .audiomidi, 'audio/midi'
cleartext .video3gpp, 'video/3gpp'
cleartext .videompeg, 'video/mpeg'
cleartext .videoquicktime, 'video/quicktime'
cleartext .videoflv, 'video/x-flv'
cleartext .videomng, 'video/x-mng'
cleartext .videoasf, 'video/x-ms-asf'
cleartext .videowmv, 'video/x-ms-wmv'
cleartext .videoavi, 'video/x-msvideo'
cleartext .videomp4, 'video/mp4'
cleartext .videom4v, 'video/x-m4v'
cleartext .rangeformatpreface, 'bytes '
cleartext .rangedash, '-'
cleartext .rangeslash, '/'


end if


if used webservercfg$direxists | defined include_everything
	; single argument in rdi: a directory name
	; returns a bool, but caches its stat results so that stat doesn't have to be run every single request
falign
webservercfg$direxists:
	prolog	webservercfg$direxists
	push	rbx r12 r13
	mov	rbx, rdi
	mov	rsi, rdi
	mov	rdi, [webservercfg$dirmap]
	call	stringmap$find
	mov	edx, dword [_epoll_tv_secs]
	test	rax, rax
	jz	.statnew
	; so the lower 32 bits of the value is the time we entered it
	; if that is > 60 seconds old, delete the entry entirely and do a new one
	; if it is less than 60 seconds old, return the upper 32 bits of the value and be done
	sub	edx, [rax+_avlofs_value]	; lower 32 bits
	cmp	edx, 60
	jae	.statredo
	; otherwise, return the upper 32 bits and be done
	mov	eax, [rax+_avlofs_value+4]
	pop	r13 r12 rbx
	epilog
calign
.statredo:
	; we have to free the string key
	mov	r12, [rax+_avlofs_key]
	mov	rdi, [webservercfg$dirmap]
	mov	rsi, rbx
	call	stringmap$erase
	mov	rdi, r12
	call	heap$free
	; fallthrough to statnew
calign
.statnew:
	; we need a copy of the directory name string
	mov	rdi, rbx
	call	string$copy
	mov	rbx, rax
	mov	rdi, rax
	call	string$utf8_length
	mov	r12, rax
	add	rax, 0x17
	and	rax, not 0xf
	sub	rsp, rax
	mov	r13, rsp
	mov	rdi, rbx
	mov	rsi, rsp
	call	string$to_utf8
	mov	byte [rsp+r12], 0
	mov	rdi, rsp
	sub	rsp, 0x90
	mov	eax, syscall_stat
	mov	rsi, rsp
	syscall
	xor	ecx, ecx			; result
	mov	edx, 1
	test	eax, eax
	jnz	.statnew_notdir
	test	dword [rsp+0x18], 0x4000	; st_mode & S_IFDIR?
	cmovnz	ecx, edx
calign
.statnew_notdir:
	add	rsp, 0x90
	mov	rax, r12
	add	rax, 0x17
	and	rax, not 0xf
	add	rsp, rax
	; ecx is the bool as to whether the directory exists or not
	mov	r12d, ecx
	mov	edx, dword [_epoll_tv_secs]
	shl	rcx, 32
	or	rdx, rcx
	mov	rdi, [webservercfg$dirmap]
	mov	rsi, rbx
	call	stringmap$insert_unique
	mov	eax, r12d
	pop	r13 r12 rbx
	epilog

end if



if used webservercfg$hotlist | defined include_everything

; webserver file cache object

wsfc_checktime_ofs = 0
wsfc_stattime_ofs = 8
wsfc_filename_ofs = 16
wsfc_privmapped_ofs = 24
wsfc_next_ofs = 32
wsfc_prev_ofs = 40

wsfc_size = 48


falign
wsfc$destroy:
	prolog	wsfc$destroy
	push	rbx
	mov	rbx, rdi
	cmp	qword [rdi+wsfc_privmapped_ofs], 0
	je	.nopm
	mov	rdi, [rdi+wsfc_filename_ofs]
	call	heap$free
	mov	rdi, [rbx+wsfc_privmapped_ofs]
	mov	rdi, [rdi+privmapped_user_ofs]
	call	heap$free
	mov	rdi, [rbx+wsfc_privmapped_ofs]
	call	privmapped$destroy
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog
calign
.nopm:
	mov	rdi, [rdi+wsfc_filename_ofs]
	call	heap$free
	mov	rdi, rbx
	call	heap$free
	pop	rbx
	epilog


falign
wsfc$link:
	prolog	wsfc$link
	mov	rsi, [webservercfg$hotlast]
	mov	qword [rdi+wsfc_next_ofs], 0
	mov	[rdi+wsfc_prev_ofs], rsi
	test	rsi, rsi
	jz	.first
	mov	[rsi+wsfc_next_ofs], rdi
	mov	[webservercfg$hotlast], rdi
	epilog
calign
.first:
	mov	[webservercfg$hotfirst], rdi
	mov	[webservercfg$hotlast], rdi
	epilog


falign
wsfc$unlink:
	prolog	wsfc$unlink
	mov	rsi, [webservercfg$hotfirst]
	mov	rdx, [webservercfg$hotlast]
	mov	rcx, [rdi+wsfc_next_ofs]
	mov	r8, [rdi+wsfc_prev_ofs]
	xor	r9d, r9d
	cmp	rdi, rsi
	je	.first
	cmp	rdi, rdx
	je	.lastnotfirst
	mov	[rcx+wsfc_prev_ofs], r8
	mov	[r8+wsfc_next_ofs], rcx
	epilog
calign
.first:
	cmp	rdi, rdx
	je	.firstandlast
	mov	[webservercfg$hotfirst], rcx
	mov	[rcx+wsfc_prev_ofs], r9
	epilog
calign
.firstandlast:
	mov	[webservercfg$hotfirst], r9
	mov	[webservercfg$hotlast], r9
	epilog
calign
.lastnotfirst:
	mov	[webservercfg$hotlast], r8
	mov	[r8+wsfc_next_ofs], r9
	epilog

end if



if used webservercfg$hotlist_unpin | defined include_everything
	; this is called with rdi == privmapped object, and is a function because of the inflightcb necessity
falign
webservercfg$hotlist_unpin:
	prolog	webservercfg$hotlist_unpin
	sub	dword [rdi+privmapped_pincount_ofs], 1
	epilog

end if


if used webservercfg$hotlist_weed | defined include_everything
	; no arguments, gets rid of old/stale privmapped objects
falign
webservercfg$hotlist_weed:
	prolog	webservercfg$hotlist_weed
	cmp	qword [webservercfg$hotfirst], 0
	je	.nothingtodo
calign
.doit:
	mov	rdi, [webservercfg$hotfirst]
	mov	rcx, [_epoll_tv_secs]
	mov	r11, rcx
	sub	rcx, [rdi+wsfc_checktime_ofs]
	mov	rsi, [rdi+wsfc_privmapped_ofs]
	cmp	rcx, webserver_hotlist_time
	jb	.nothingtodo
	test	rsi, rsi
	jnz	.doit_checkpincount
	push	rdi
	call	wsfc$unlink
	mov	rdx, [rsp]
	mov	rdi, [webservercfg$hotmap]
	mov	rsi, [rdx+wsfc_filename_ofs]
	call	stringmap$erase
	pop	rdi
	call	wsfc$destroy
	cmp	qword [webservercfg$hotfirst], 0
	jne	.doit
	epilog
calign
.doit_checkpincount:
	cmp	dword [rsi+privmapped_pincount_ofs], 0
	jne	.relink
	push	rdi
	call	wsfc$unlink
	mov	rdx, [rsp]
	mov	rdi, [webservercfg$hotmap]
	mov	rsi, [rdx+wsfc_filename_ofs]
	call	stringmap$erase
	pop	rdi
	call	wsfc$destroy
	cmp	qword [webservercfg$hotfirst], 0
	jne	.doit
	epilog
calign
.relink:
	push	rdi
	mov	[rdi+wsfc_checktime_ofs], r11
	call	wsfc$unlink
	pop	rdi
	call	wsfc$link
	jmp	.doit
calign
.nothingtodo:
	epilog

end if


if used webservercfg$hotlist | defined include_everything
	; two arguments: rdi == a full filename, esi == webserver_hotlist_statfreq (or override from config)
	; returns a privmapped object in rax, or null if it doesn't exist, caches result either way so open doesn't have to run every single time
falign
webservercfg$hotlist:
	prolog	webservercfg$hotlist
	push	rbx r12 r13
	mov	r13d, esi
	mov	rbx, rdi
	mov	rsi, rdi
	mov	rdi, [webservercfg$hotmap]
	call	stringmap$find
	mov	rcx, [_epoll_tv_secs]
	test	rax, rax
	jz	.newone
	mov	r11, rcx
	mov	r12, [rax+_avlofs_value]	; the wsfc object
	sub	rcx, [r12+wsfc_stattime_ofs]
	mov	rdx, [r12+wsfc_privmapped_ofs]
	cmp	rcx, r13
	jb	.oldone_relink_return
	test	rdx, rdx
	jz	.oldone_redo
	; if our item is pinned, keep our object in tact
	cmp	dword [rdx+privmapped_pincount_ofs], 0
	jne	.oldone_relink_return
	; this one is valid, we need to redo our stat for it and make sure the mtime is the same
	sub	rsp, 0x90
	mov	rsi, rsp
	mov	rdi, [rdx+privmapped_fname_ofs]
	mov	eax, syscall_stat
	syscall
	test	eax, eax
	jnz	.oldone_disappeared
	mov	rax, [r12+wsfc_privmapped_ofs]
	mov	rdx, [_epoll_tv_secs]
	mov	rcx, [rsp+0x58]			; st_mtime
	add	rsp, 0x90
	cmp	rcx, [rax+privmapped_mtime_ofs]
	jne	.oldone_redo
	; otherwise, it is same-same, update our times
	mov	[r12+wsfc_checktime_ofs], rdx
	mov	[r12+wsfc_stattime_ofs], rdx
	mov	rdi, r12
	call	wsfc$unlink
	mov	rdi, r12
	call	wsfc$link
if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything
	; if either of those are used, the hotlist weed gets run from the timer, otherwise, we do it from here
else
	call	webservercfg$hotlist_weed
end if
	mov	rax, [r12+wsfc_privmapped_ofs]
	pop	r13 r12 rbx
	epilog
calign
.oldone_disappeared:
	add	rsp, 0x90
.oldone_redo:
	; so, we have a valid map entry, but the file itself disappeared
	; unlink it, destroy the entry, and then let newone take over
	mov	rdi, r12
	call	wsfc$unlink
	; since the stringmap is keyed with the privmapped_filename_ofs, we don't
	; need to separately free its key, as it will be free'd when privmapped$destroy is called
	mov	rdi, [webservercfg$hotmap]
	mov	rsi, rbx
	call	stringmap$erase
	mov	rdi, r12
	call	wsfc$destroy
	jmp	.newone
calign
.oldone_relink_return:
	mov	[r12+wsfc_checktime_ofs], r11
	mov	rdi, r12
	call	wsfc$unlink
	mov	rdi, r12
	call	wsfc$link
	mov	r12, [r12+wsfc_privmapped_ofs]
if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything
	; if either of those are used, the hotlist weed gets run from the timer, otherwise, we do it from here
else
	call	webservercfg$hotlist_weed
end if
	mov	rax, r12
	pop	r13 r12 rbx
	epilog
calign
.newone:
	mov	rdi, rbx
	mov	esi, 1			; we want etags
	call	privmapped$new
	mov	rdx, [_epoll_tv_secs]
	mov	r12, rax
	mov	edi, wsfc_size
	call	heap$alloc
	mov	rdx, [_epoll_tv_secs]
	mov	[rax+wsfc_checktime_ofs], rdx
	mov	[rax+wsfc_stattime_ofs], rdx
	mov	[rax+wsfc_privmapped_ofs], r12
	mov	r12, rax
	mov	rdi, rbx
	call	string$copy
	mov	[r12+wsfc_filename_ofs], rax
	mov	rdi, r12
	call	wsfc$link
	; add it to our map
	mov	rdi, [webservercfg$hotmap]
	mov	rsi, [r12+wsfc_filename_ofs]
	mov	rdx, r12
	call	stringmap$insert_unique

	; create a mimetype string in privmapped_user_ofs, but only if privmapped exists
	cmp	qword [r12+wsfc_privmapped_ofs], 0
	je	.noctype
	mov	rdi, rbx
	call	webservercfg$mimetype
	mov	rdx, rax
	mov	rax, [r12+wsfc_privmapped_ofs]
	mov	[rax+privmapped_user_ofs], rdx

if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything
	; if either of those are used, the hotlist weed gets run from the timer, otherwise, we do it from here
else
	call	webservercfg$hotlist_weed
end if
	mov	rax, [r12+wsfc_privmapped_ofs]
	pop	r13 r12 rbx
	epilog
calign
.noctype:
if used webservercfg$errorlog_path | used webservercfg$logs_path | defined include_everything
	; if either of those are used, the hotlist weed gets run from the timer, otherwise, we do it from here
else
	call	webservercfg$hotlist_weed
end if
	mov	rax, [r12+wsfc_privmapped_ofs]
	pop	r13 r12 rbx
	epilog


end if


if used webservercfg$mimetype | defined include_everything
	; single argument in rdi: string full filename
	; returns a new string in rax of the content type
	; NOTE: our default content type if we dont' find one from an extension is application/octet-stream
falign
webservercfg$mimetype:
	prolog	webservercfg$mimetype
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	mov	rsi, .dot
	call	string$last_indexof
	cmp	rax, 0
	jl	.default
	xor	ecx, ecx
	mov	rdi, rbx
	mov	rsi, rax
	mov	edx, 4
	add	rsi, 1
	push	rcx
	call	string$substr
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, rsp
	call	string$to_utf8
	mov	rdi, rbx
	call	heap$free
	pop	rsi
	mov	rdi, [webservercfg$mimemap]
	call	unsignedmap$find_value
	test	eax, eax
	jz	.default
	mov	rdi, rdx		; rdx is the value from our mimemap
	call	string$copy
	pop	r12 rbx
	epilog
calign
.default:
	pop	r12 rbx
	mov	rdi, .def
	call	string$copy
	epilog
cleartext .dot, '.'
cleartext .def, 'application/octet-stream'

end if


if used webservercfg$handler | defined include_everything
	; four arguments: rdi == webservercfg object, rsi == webserver object, rdx == request url, rcx == mimelike request object
falign
webservercfg$handler:
	prolog	webservercfg$handler
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	mov	r14, rcx

	; if a redirect string is present, deal with that alone
	cmp	qword [rbx+webservercfg_redirect_ofs], 0
	jne	.outer_doredirect

	; first order of business: determine our document root
if used webservercfg$new_vhost | used webservercfg$set_vhost | defined include_everything
	; in order, if we have a vhost directory, try it first, url makes sure the hostname is lowercased, so all we need is a simple concat
	cmp	qword [rbx+webservercfg_vhost_ofs], 0
	je	.novhost
	mov	rdi, [rbx+webservercfg_vhost_ofs]
	mov	rsi, [r13+url_host_ofs]
	call	string$concat
	mov	r15, rax
	mov	rdi, rax
	call	webservercfg$direxists
	test	eax, eax
	jnz	.gotdocumentroot

	; otherwise, clear the string in r15
	mov	rdi, r15
	call	heap$free
calign
.novhost:
end if
if used webservercfg$new_sandbox | used webservercfg$host_sandbox | defined include_everything
	; next up: determine whether the host exists in sandboxes
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	mov	rsi, [r13+url_host_ofs]
	mov	rdx, [rdi+_avlofs_parent]
	test	rdx, rdx
	jz	.checknohost
	cmp	dword [rdi+_avlofs_right], 1
	jne	.find_sandbox_withmap
	; otherwise, since there is only one node, just do a string$equals
	push	qword [rdx+_avlofs_value]
	mov	rdi, [rdx+_avlofs_key]
	call	string$equals
	pop	rdi
	test	eax, eax
	jz	.checknohost
	call	string$copy
	mov	r15, rax
	jmp	.gotdocumentroot
calign
.find_sandbox_withmap:
	call	stringmap$find_value
	test	eax, eax
	jz	.checknohost
	; otherwise, we need to copy the string
	mov	rdi, rdx
	call	string$copy
	mov	r15, rax
	jmp	.gotdocumentroot
cleartext .docrootstr, 'DOCUMENT_ROOT'
cleartext .nohoststr, '..nohost..'
calign
.checknohost:
	mov	rdi, [rbx+webservercfg_sandboxes_ofs]
	mov	rsi, .nohoststr
	call	stringmap$find_value
	test	eax, eax
if used webservercfg$backpath
	jz	.nodocumentroot_checkbackpath
else
	jz	.nullret
end if
	mov	rdi, rdx
	call	string$copy
	mov	r15, rax
end if
if used webservercfg$new_vhost | used webservercfg$new_sandbox | used webservercfg$host_sandbox | used webservercfg$set_vhost | defined include_everything
calign
.gotdocumentroot:
	; set a DOCUMENT_ROOT header in the request so we can reference it later:
	mov	rdi, r14
	mov	rsi, .docrootstr
	mov	rdx, r15
	call	mimelike$setheader

	; next up: concatenate the url path to our document root
	mov	rdi, r15
	mov	rsi, [r13+url_path_ofs]
	call	string$concat
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; first up, see if the path ends with a /
	mov	rdi, r15
	mov	rsi, [r15]
	test	rsi, rsi
	jz	.impossible		; sanity only
	sub	rsi, 1
if string_bits = 32
	cmp	dword [rdi+rsi*4+8], '/'
else
	cmp	word [rdi+rsi*2+8], '/'
end if
	je	.indexfile
	; otherwise, proceed with normal request handling
	call	.request
	; let that be our return, free r15 and be done
	mov	r13, rax		; save our return
	mov	rdi, r15
	call	heap$free
	mov	rax, r13
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.indexfile:
	; we have to iterate through our index files, testing each one until we get a non-null response from request
	; so that we can walk the list without calling list$foreach, we smash rbp (which will of course render the
	; gdb stackframe/framepointers rubbish if anything dies inside this handling loop)
	mov	rdi, [rbx+webservercfg_indexfiles_ofs]
	cmp	qword [rdi+_list_first_ofs], 0
	je	.impossible		; this should NOT happen
	push	rbp
	mov	rbp, [rdi+_list_first_ofs]
calign
.indexfile_walk:
	; we need to make a concatenation of the r15 and the index list value, set r15 to that, call .request
	mov	rdi, r15
	mov	rsi, [rbp+_list_valueofs]
	call	string$concat
	push	r15
	mov	r15, rax

	; concat our indexfile to our url's path, saving the url path
	push	qword [r13+url_path_ofs]
	mov	rdi, [r13+url_path_ofs]
	mov	rsi, [rbp+_list_valueofs]
	mov	[r13+url_user_ofs], rdi		; in the event we hand it off via fastcgi, it will use this to construct the "right" REQUEST_URI
	call	string$concat
	mov	[r13+url_path_ofs], rax
	call	.request
	test	rax, rax
	jnz	.indexfile_complete
	pop	rsi
	mov	rdi, [r13+url_path_ofs]
	mov	[r13+url_path_ofs], rsi
	call	heap$free

	mov	rdi, r15
	call	heap$free
	pop	r15
	mov	rbp, [rbp+_list_nextofs]
	test	rbp, rbp
	jnz	.indexfile_walk
	; if we made it to here, we tried all index files, nothing happened, so return null
	pop	rbp
	mov	rdi, r15
	call	heap$free
if used webservercfg$backpath
	; if backpath is used, we need to check it irrespective of docroot
	jmp	.nodocumentroot_checkbackpath
else
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
end if
calign
.indexfile_complete:
	mov	r13, rax		; save our return

	pop	rdi
	call	heap$free
	
	; so there we were, walking our index file list, and we got a nonzero result
	; let that be our return, cleanup everything else and bailout
	mov	rdi, r15
	call	heap$free
	pop	r15
	mov	rdi, r15
	call	heap$free
	pop	rbp
	mov	rax, r13
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.impossible:
	mov	rdi, r15
	call	heap$free
calign
.nullret:
	xor	eax, eax			; null ret == proceed with 404
						; -1 ret == sit on the connection, don't do anything
						; anything else is a response object
	pop	r15 r14 r13 r12 rbx
	epilog
else
	; no sandbox was configured, and no vhost was configured, so we really don't HAVE a document root
	; so, we set our r15 (which should be our full path) to the URL's path, and call .request
	; noting here we don't have to (obviously) free it when we're done
	mov	r15, [r13+url_path_ofs]
	call	.request
	pop	r15 r14 r13 r12 rbx
	epilog

end if

if used webservercfg$backpath

calign
.nodocumentroot_checkbackpath:
	; if backpath for our config object is null, bailout normally
	cmp	qword [rbx+webservercfg_backpath_ofs], 0
	jnz	.request_with_backpath
	xor	eax, eax
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.request_with_backpath:
	; similar to the above, set our r15 to our URL's path and let request deal with it
	mov	r15, [r13+url_path_ofs]
	call	.request
	pop	r15 r14 r13 r12 rbx
	epilog
end if

calign
.outer_doredirect:
	call	.request
	pop	r15 r14 r13 r12 rbx
	epilog
falign
.request:
	; rbx == webservercfg object, r12 == webserver object, r13 == request url, r14 == mimelike request object, r15 == full pathname
	; so, two schools of thought here re: fastcgi handlers
	; 1) regardless of whether the underlying file actually exists, pass it straight off to any mapped handlers
	; 2) underlying file must exist to pass it off
	; since a fastcgi handler can be "pure" (and thus not really file based), I vote for option #1, let the fastcgi handler work out
	; whether it is valid or not
	; so, our first order of business is to determine whether there _is_ a handler for it

	; if a redirect string is present, deal with that alone
	cmp	qword [rbx+webservercfg_redirect_ofs], 0
	jne	.doredirect

	; instead of using stringmap$foreach_arg, we walk the trees directly here so we can preserve our callee-saves without having to constantly
	; smash them onto the stack and back
if used webservercfg$function_map | defined include_everything
	; we give "funcmap" precedence over any fastcgi mappings
	; rbx == [r12+webserver_config_ofs], so we can safely blast/restore it
	mov	rbx, [rbx+webservercfg_funcmap_ofs]
	cmp	qword [rbx+_avlofs_next], 0
	je	.dofastcgi
	mov	rbx, [rbx+_avlofs_next]
calign
.funcwalk:
	mov	rdi, r15
	mov	rsi, [rbx+_avlofs_key]
	call	string$ends_with
	test	eax, eax
	jnz	.functioncall_doit
	mov	rbx, [rbx+_avlofs_next]
	test	rbx, rbx
	jnz	.funcwalk
calign
.dofastcgi:
end if
if used webservercfg$fastcgi_map | defined include_everything
	mov	rdi, [r12+webserver_config_ofs]
	mov	rbx, [rdi+webservercfg_fastcgi_ofs]
	cmp	qword [rbx+_avlofs_next], 0
	je	.dofilesystem
	mov	rbx, [rbx+_avlofs_next]
calign
.fastcgiwalk:
	mov	rdi, r15
	mov	rsi, [rbx+_avlofs_key]
	call	string$ends_with
	test	eax, eax
	jnz	.fastcgi_doit
	mov	rbx, [rbx+_avlofs_next]
	test	rbx, rbx
	jnz	.fastcgiwalk
calign
.dofilesystem:
end if
if used webservercfg$new_vhost | used webservercfg$new_sandbox | used webservercfg$host_sandbox | used webservercfg$set_vhost | defined include_everything


	; let the hotlist deal with our mmap cache
	mov	rcx, [r12+webserver_config_ofs]
	mov	rdi, r15
	mov	esi, [rcx+webservercfg_filestattime_ofs]
	call	webservercfg$hotlist
	test	rax, rax
	jz	.filesystem_nodeal
	; if the method is POST, return 405 method not allowed
	cmp	dword [r14+mimelike_user_ofs], 2		; POST
	je	.dofilesystem_notallowed

	push	rax
	push	qword [rax+privmapped_user_ofs]

	; so we have a valid privmapped object, it is not expensive to create mimelike objects
	; (only to compose them), so we proceed with creation, and after we have our Last-Modified
	; header, _then_ we check for If-Modified-Since, and same with our ETag and If-None-Match

	; first step: construct a mimelike return for our object, paying attention to Range requests
	call	mimelike$new
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, .r200
	call	mimelike$setpreface
	; content type is next
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	pop	rdx
	call	mimelike$addheader
	; we don't need to set the content length here, mimelike$compose will do that for us

	mov	rax, [rsp]
	mov	rdi, rbx
	mov	rsi, [rax+privmapped_base_ofs]
	mov	rdx, [rax+privmapped_size_ofs]

	test	dword [r12+webserver_flags_ofs], 2
	jz	.nogziptest
	; if there is _already_ a zbuf for our privmapped object, then we know that it should be gzipped anyway, in which case
	; we can just revert straight to it with no further checking, since we know the client supports it
	mov	r8, [rax+privmapped_zbuf_ofs]
	test	r8, r8
	jz	.checkshouldgzip
	; otherwise, nonzero, so set them
calign
.doit_gzipped:
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	push	rsi rdx
	mov	rsi, mimelike$contentencoding
	mov	rdx, mimelike$gzip
	call	mimelike$addheader
	mov	rdi, rbx
	pop	rdx rsi
	mov	rax, [rsp]
	jmp	.nogziptest
calign
.checkshouldgzip:
	call	mimelike$shouldgzip
	test	eax, eax
	jz	.nodeal_gzip
	; if it is already gzipped, no deal
	mov	rax, [rsp]
	mov	rdi, rbx
	mov	rsi, [rax+privmapped_base_ofs]
	mov	rdx, [rax+privmapped_size_ofs]
	mov	ecx, [rsi]
	mov	r8d, [rsi]
	and	ecx, 0xffffff
	shr	r8d, 24
	cmp	ecx, 0x88b1f
	jne	.gzipgoahead
	test	r8d, 0xe0
	jz	.nogziptest
calign
.gzipgoahead:
	cmp	rdx, mimelike_mingzip
	jb	.nogziptest
	; otherwise, we _should_ gzip it
	mov	rdi, rax
	push	rax
	call	privmapped$deflate
	pop	rax
	mov	rdi, rbx
	mov	r8, [rax+privmapped_zbuf_ofs]
	jmp	.doit_gzipped
calign
.nodeal_gzip:
	mov	rax, [rsp]
	mov	rdi, rbx
	mov	rsi, [rax+privmapped_base_ofs]
	mov	rdx, [rax+privmapped_size_ofs]
	; fallthrough to .nogziptest
calign
.nogziptest:
	; if we know that this is going to end up being segment-sent, increase the pincount for the privmapped object:
	cmp	rdx, webserver_bigfile
	jbe	.notpinned
	add	dword [rax+privmapped_pincount_ofs], 1
	; set our inflightcb/cbarg
	mov	qword [r12+webserver_inflightcb_ofs], webservercfg$hotlist_unpin
	mov	[r12+webserver_inflightcbarg_ofs], rax
calign
.notpinned:
	call	mimelike$setbody_external

if webserver_filecache_time
	mov	rcx, [r12+webserver_config_ofs]

	; add Cache-Control, ETag and Last-Modified headers
	mov	rdi, rbx
	mov	rsi, mimelike$cachecontrol
	mov	rdx, [rcx+webservercfg_cachecontrol_ofs]
	call	mimelike$addheader
	; generate our ETag and Last-Modified headers
	mov	rax, [rsp]
	mov	rdi, rbx
	mov	rsi, mimelike$lastmodified
	mov	rdx, [rax+privmapped_mtimestr_ofs]
	call	mimelike$addheader

	; since our privmapped object already has its static_etag, all we have to do is set it
	mov	rax, [rsp]
	mov	rdi, rbx
	mov	rsi, mimelike$etag
	mov	rdx, [rax+privmapped_etag_ofs]
	call	mimelike$addheader


	; some notes here on "weirdness, IMO."
	; So, in the wild, we receive requests with one or both of Pragma: no-cache and Cache-Control: no-cache
	; BUT, in those same requests, we _still also_ receive If-None-Match and/or If-Modified-Since
	; now, if we return (which I reckon is _correct_) 304 samesame for those, well, everything breaks.
	; this doesn't really seem intuitive to me. If you (the web browser/client) really don't WANT
	; me to send a 304, don't include the If-None-Match, or If-Modified-Since, because then I really
	; don't have a choice but to send you back the full response...
	; alas, that isn't the way the implementations seem to work browser-wise.
	; _weird_.
	; Anyway, so if we receive Pragma: no-cache, or Cache-Control: no-cache, we'll send back the full
	; response, and ignore whether there is ifmodifiedsince or lastmodified headers. (which seems to make
	; the "offending" browsers happy)
	; the HTTP spec re: caching is a mess upon mess of things, too much room for interpretation, haha

	; check for Pragma: no-cache
	mov	rdi, r14
	mov	rsi, mimelike$pragma
	call	mimelike$getheader
	test	rax, rax
	jz	.dofilesystem_nopragma
	mov	rdi, rax
	mov	rsi, mimelike$nocache
	call	string$equals
	test	eax, eax
	jnz	.dofilesystem_noifnonematch
calign
.dofilesystem_nopragma:
	; check for Cache-Control: no-cache
	mov	rdi, r14
	mov	rsi, mimelike$cachecontrol
	call	mimelike$getheader
	test	rax, rax
	jz	.dofilesystem_doifmodifiedsince
	mov	rdi, rax
	mov	rsi, mimelike$nocache
	call	string$indexof
	cmp	rax, 0
	jge	.dofilesystem_noifnonematch
calign
.dofilesystem_doifmodifiedsince:
	; check for ifmodifiedsince
	mov	rdi, r14
	mov	rsi, mimelike$ifmodifiedsince
	call	mimelike$getheader
	test	rax, rax
	jz	.dofilesystem_noifmodifiedsince
	push	rax
	mov	rdi, rbx
	mov	rsi, mimelike$lastmodified
	call	mimelike$getheader
	pop	rsi
	mov	rdi, rax
	call	string$equals
	test	eax, eax
	jnz	.dofilesystem_304
calign
.dofilesystem_noifmodifiedsince:
	; check to see if the request contains an If-None-Match
	mov	rdi, r14
	mov	rsi, mimelike$ifnonematch
	call	mimelike$getheader
	test	rax, rax
	jz	.dofilesystem_noifnonematch
	push	rax
	mov	rdi, rbx
	mov	rsi, mimelike$etag
	call	mimelike$getheader
	pop	rsi
	mov	rdi, rax
	call	string$equals
	test	eax, eax
	jnz	.dofilesystem_304
calign
.dofilesystem_noifnonematch:

else
	; add Cache-Control: no-cache
	mov	rdi, rbx
	mov	rsi, mimelike$cachecontrol
	mov	rdx, mimelike$nocache
	call	mimelike$addheader
end if
	; update: this just adds unnecessary overhead per request for smaller ones
	mov	rax, [rsp]
	cmp	qword [rax+privmapped_size_ofs], 524288
	jbe	.skipacceptranges
	
	; add an Accept-Ranges: bytes header
	mov	rdi, rbx
	mov	rsi, mimelike$acceptranges
	mov	rdx, mimelike$bytes
	call	mimelike$addheader
calign
.skipacceptranges:

	; so, we are ready to reply with a 200, here is the time to check for Range requests

	cmp	dword [r14+mimelike_user_ofs], 0		; GET request only for Range requests
	jne	.dofilesystem_norange
	mov	rdi, r14
	mov	rsi, mimelike$range
	call	mimelike$getheader
	test	rax, rax
	jz	.dofilesystem_norange
	; there is a Range header, so split its value by - and see what we've got
	sub	rsp, 24
	mov	[rsp], rax
	mov	rdi, rax
	mov	rsi, .bytesequal
	call	string$starts_with
	test	eax, eax
	jz	.dofilesystem_badrange_syntax
	; otherwise, we need a substring from 6 onward
	mov	rdi, [rsp]
	mov	esi, 6
	mov	rdx, -1
	call	string$substr
	mov	[rsp], rax
	mov	rdi, [rsp]
	mov	esi, '-'
	call	string$split
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	cmp	qword [rax+_list_size_ofs], 2
	ja	.dofilesystem_badrange
	; otherwise, convert both sides ot unsigneds
	mov	rdi, rax
	call	list$pop_front
	mov	[rsp+8], rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp+8]
	mov	[rsp+8], rax
	call	heap$free
	mov	rdi, [rsp]
	mov	qword [rsp+16], 0
	cmp	qword [rdi+_list_first_ofs], 0
	je	.dofilesystem_range_nosecond
	mov	rdi, [rsp]
	call	list$pop_front
	mov	[rsp+16], rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
calign
.dofilesystem_range_nosecond:
	mov	rdi, [rsp]
	call	heap$free
	; now, if the start offset is >= our length, spew the full object
	mov	rcx, [rsp+8]
	mov	rdx, [rsp+16]
	add	rsp, 24
	mov	rax, [rsp]					; our privmapped object
	cmp	rcx, [rax+privmapped_size_ofs]
	jae	.dofilesystem_norange
	
	; and, if our ending offset >= our length, set it to our length-1
	mov	r8, [rax+privmapped_size_ofs]
	sub	r8, 1
	cmp	rdx, r8
	cmova	rdx, r8
	; and if our ending offset was zero, set it to our length-1
	test	rdx, rdx
	cmovz	rdx, r8
	mov	r8, rdx
	add	r8, 1
	sub	r8, rcx
	jz	.dofilesystem_norange				; 0 bytes was the result
	
	; otherwise, modify our goods for the specified range

	mov	r9, [rax+privmapped_base_ofs]
	add	r9, rcx
	push	r9 r8

	; set the preface to 206 Partial Content, add Content-Range header
	mov	rdi, [webservercfg$rangeformat]
	mov	rsi, rcx
	; rdx already set
	mov	rcx, [rax+privmapped_size_ofs]
	call	formatter$doit
	pop	rdx rsi
	push	rax
	mov	rdi, rbx
	call	mimelike$setbody_external

	pop	rdx
	mov	rdi, rbx
	mov	rsi, mimelike$contentrange
	call	mimelike$addheader_novaluecopy
	mov	rdi, rbx
	mov	rsi, .r206
	call	mimelike$setpreface

	jmp	.dofilesystem_norange

calign
.dofilesystem_badrange_syntax:
	add	rsp, 24
	jmp	.dofilesystem_norange
cleartext .bytesequal, 'bytes='
calign
.dofilesystem_badrange:
	mov	rdi, [rsp]
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 24
	; fallthrough and return the complete response
calign
.dofilesystem_norange:
	add	rsp, 8

	mov	rax, rbx
	; restore rbx before we bailout
	mov	rbx, [r12+webserver_config_ofs]
	ret

calign
.doredirect:
	push	qword [rbx+webservercfg_redirect_ofs]
	call	mimelike$new
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, .r302
	call	mimelike$setpreface
	mov	rdi, rbx
	mov	rsi, mimelike$cachecontrol
	mov	rdx, .privatestr
	call	mimelike$addheader
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$texthtmlutf8
	call	mimelike$addheader
	mov	rdi, rbx
	mov	rsi, mimelike$location
	pop	rdx
	call	mimelike$addheader
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	mov	rdx, .fivestr
	call	mimelike$addheader
	mov	rdi, rbx
	mov	rsi, .r302body
	mov	edx, 5
	call	mimelike$setbody
	mov	rax, rbx
	mov	rbx, [r12+webserver_config_ofs]
	ret
cleartext .r302, 'HTTP/1.1 302 Look over here mate'
cleartext .privatestr, 'private'
cleartext .fivestr, '5'
.r302body:
	db	'Moved'
	

if webserver_filecache_time
calign
.dofilesystem_304:
	; resource was not modified on our end since the last time we coughed it up
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	call	mimelike$removeheader
	mov	rdi, rbx
	mov	rsi, mimelike$cachecontrol
	call	mimelike$removeheader
	mov	rdi, rbx
	mov	rsi, .r304
	call	mimelike$setpreface
	mov	rdi, rbx
	mov	rsi, mimelike$transferencoding
	call	mimelike$removeheader
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	call	mimelike$removeheader
	mov	rdi, rbx
	mov	rsi, mimelike$contentencoding
	call	mimelike$removeheader
	mov	rdi, rbx
	mov	qword [rdi+mimelike_bodyext_ofs], 0
	mov	qword [rdi+mimelike_bodyextlen_ofs], 0
	mov	qword [rdi+mimelike_bodyextend_ofs], 0

	add	rsp, 8
	mov	rax, rbx
	; restore rbx before we bailout
	mov	rbx, [r12+webserver_config_ofs]
	ret

cleartext .r304, 'HTTP/1.1 304 Same same mate'
end if
cleartext .r200, 'HTTP/1.1 200 She',0x27,'ll be apples'
cleartext .r206, 'HTTP/1.1 206 Just a slice of the whole pie'
calign
.dofilesystem_notallowed:
	mov	rdi, [r12+webserver_config_ofs]
	mov	esi, 405
	call	webservercfg$error
	; restore rbx before we bailout
	mov	rbx, [r12+webserver_config_ofs]
	ret

calign
.filesystem_nodeal:
end if
	; if r15 does not end in a slash, _and_ it is a directory, redirect to the same with a trailing / appended
	mov	rdi, r15
	mov	rsi, [rdi]
	test	rsi, rsi
	jz	.really_nodeal
	sub	esi, 1
if string_bits = 32
	cmp	dword [rdi+rsi*4+8], '/'
else
	cmp	word [rdi+rsi*2+8], '/'
end if
	je	.really_nodeal
	mov	rdi, r15
	call	webservercfg$direxists
	test	eax, eax
	jz	.really_nodeal
	; otherwise, do a redirect to one with a / added
	call	mimelike$new
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, .r301
	call	mimelike$setpreface
	mov	rdi, rbx
	mov	rsi, mimelike$cachecontrol
	mov	rdx, .privatestr
	call	mimelike$addheader
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$texthtmlutf8
	call	mimelike$addheader
	mov	rdi, [r13+url_path_ofs]
	mov	rsi, .slash
	call	string$concat
	mov	rdi, rbx
	mov	rsi, mimelike$location
	mov	rdx, rax
	call	mimelike$addheader_novaluecopy
	mov	rdi, rbx
	mov	rsi, mimelike$contentlength
	mov	rdx, .fivestr
	call	mimelike$addheader
	mov	rdi, rbx
	mov	rsi, .r302body
	mov	edx, 5
	call	mimelike$setbody
	mov	rax, rbx
	mov	rbx, [r12+webserver_config_ofs]
	ret
cleartext .r301, 'HTTP/1.1 301 She nicked off'
cleartext .slash, '/'
calign
.really_nodeal:

if used webservercfg$backpath
	; if we would have returned null, and there is a backpath set, shoot it
	cmp	qword [r12+webserver_backpath_ofs], 0
	jne	.do_backpath
end if
	; null ret in rax will work fine
	mov	rbx, [r12+webserver_config_ofs]
	ret
if used webservercfg$backpath
cleartext .xforwardedfor, 'X-Forwarded-For'
cleartext .xforwardedport, 'X-Forwarded-Port'
cleartext .xforwardedhost, 'X-Forwarded-Host'
cleartext .xforwardedproto, 'X-Forwarded-Proto'
cleartext .xforwardedprotohttp, 'http'
cleartext .xforwardedprotohttps, 'https'
cleartext .host, 'Host'
calign
.do_backpath:
	; modify the headers in our request

	; X-Forwarded-For
	; X-Forwarded-Host
	; X-Forwarded-Port
	; X-Forwarded-Proto
	mov	rbx, [r12+webserver_config_ofs]

	lea	rsi, [r12+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	mov	rdi, r14
	mov	rsi, .xforwardedfor
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy

	lea	rdx, [r12+webserver_raddr_ofs]
	movzx	eax, word [rdx+2]
	xchg	ah, al
	mov	edi, eax
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, r14
	mov	rsi, .xforwardedport
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy

	mov	rdi, r14
	mov	rsi, .host
	call	mimelike$getheader
	mov	rdi, r14
	mov	rsi, .xforwardedhost
	mov	rdx, rax
	call	mimelike$setheader

	mov	rdi, r14
	mov	rsi, .xforwardedproto
	mov	rdx, .xforwardedprotohttp
	mov	rcx, .xforwardedprotohttps
	cmp	dword [rbx+webservercfg_istls_ofs], 0
	cmovne	rdx, rcx
	call	mimelike$setheader

	; NOTE: we do not modify the Host: header itself
	mov	rdi, [r12+webserver_backpath_ofs]
	mov	rsi, r14
	call	wsbp$sendrequest

	; we have to return -1 here
	mov	rax, -1
	ret


end if

	

if used webservercfg$function_map | defined include_everything
calign
.functioncall_doit:
        ; we pass it three arguments: rdi == our webserver object, rsi == request url, rdx == mimelike object of the request
	mov	rdi, r12
	mov	rsi, r13
	mov	rdx, r14
	call	qword [rbx+_avlofs_value]
	; restore rbx before we bailout
	mov	rbx, [r12+webserver_config_ofs]
	; let the function's return be our return
	ret
end if
if used webservercfg$fastcgi_map | defined include_everything
calign
.fastcgi_doit:
	; [rbx+_avlofs_value] is our outbound fastcgi destination
	; all we have to do is create an fcgiclient and call epoll$outbound on it, store the pointer in case we die
	; from here, we must return -1 so that nothing happens til the fastcgi call completes

	; we add fake headers to the request object for REMOTE_ADDR and REMOTE_PORT here so that the fastcgi handler has ready access
	; to them. Note here that it is not possible for a remote party to fake/override these, as any write we do here elimintes the
	; remote-sides version to begin with (same story with DOCUMENT_ROOT)
	lea	rsi, [r12+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	mov	rdi, r14
	mov	rsi, .remoteaddr
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy

	lea	rdx, [r12+webserver_raddr_ofs]
	movzx	eax, word [rdx+2]
	xchg	ah, al
	mov	edi, eax
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, r14
	mov	rsi, .remoteport
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy

	mov	rcx, r12		; webserver object as its callback argument
	mov	rdi, r13		; url as its first arg
	mov	rsi, r14
	mov	rdx, webservercfg$fastcgi_result
	call	fcgiclient$new

if webserver_fastcgi_postprocess
	mov	rcx, [rbx+_avlofs_value]
	; this is wasteful in that we overwrite this pointer each time, but not expensive
	mov	qword [_epoll_postprocessing_hook], webservercfg$fastcgi_postprocess
	mov	rdi, [webservercfg$fastcgiqueue]
	mov	rsi, rax
	mov	qword [rax+fcgiclient_user_ofs], rcx
	call	list$push_back
	; return -1 so that the webserver layer does _nothing_ with our request
	mov	rax, -1
	mov	rbx, [r12+webserver_config_ofs]
	ret
else
	; we need to hook that to our webserver object so that if our webserver client goes away
	; we can blast the fastcgi connection with it
	mov	[r12+webserver_fcgihooked_ofs], rax
	; we need to pass that straight to epoll outbound
	mov	rdi, [rbx+_avlofs_value]
	mov	rsi, [rdi]
	add	rdi, 8
	mov	rdx, rax
	call	epoll$outbound
	; if epoll$outbound _failed_ to connect, we get a zero in eax
	test	eax, eax
	jz	.fastcgi_error
	; we return -1 here so that the webserver layer does _nothing_ with our request
	mov	rax, -1
	; restore rbx before we bailout
	mov	rbx, [r12+webserver_config_ofs]
	ret
calign
.fastcgi_error:
	mov	rbx, [r12+webserver_config_ofs]
	; first up: clear our hook
	mov	qword [r12+webserver_fcgihooked_ofs], 0
	; next up: get a 502 error
	mov	rdi, rbx
	mov	esi, 502
	call	webservercfg$error
	; let that return be our return
	ret
end if
cleartext .remoteaddr, 'REMOTE_ADDR'
cleartext .remoteport, 'REMOTE_PORT'

end if


end if

if used webservercfg$fastcgi_map & webserver_fastcgi_postprocess

falign
webservercfg$fastcgi_postprocess:
	prolog	webservercfg$fastcgi_postprocess
	mov	rdi, [webservercfg$fastcgiqueue]
	mov	rsi, .doit
	call	list$clear
	epilog
falign
.doit:
	; rdi == the fcgiclient object we are dealing with
	; its fcgiclient_callbackarg_ofs is the webserver object we did it for
	mov	rcx, [rdi+fcgiclient_callbackarg_ofs]	; webserver object
	mov	rdx, rdi
	mov	[rcx+webserver_fcgihooked_ofs], rdi
	mov	rdi, [rdi+fcgiclient_user_ofs]
	mov	rsi, [rdi]
	add	rdi, 8
	call	epoll$outbound_witherror
	ret

else if defined include_everything

falign
webservercfg$fastcgi_postprocess:
	prolog	webservercfg$fastcgi_postprocess
	mov	rdi, [webservercfg$fastcgiqueue]
	mov	rsi, .doit
	call	list$clear
	epilog
falign
.doit:
	; rdi == the fcgiclient object we are dealing with
	; its fcgiclient_callbackarg_ofs is the webserver object we did it for
	mov	rcx, [rdi+fcgiclient_callbackarg_ofs]	; webserver object
	mov	rdx, rdi
	mov	[rcx+webserver_fcgihooked_ofs], rdi
	mov	rdi, [rdi+fcgiclient_user_ofs]
	mov	rsi, [rdi]
	add	rdi, 8
	call	epoll$outbound_witherror
	ret

end if



if used webservercfg$fastcgi_result | defined include_everything
	; three arguments we get: rdi == webserver object, rsi == stdout buffer, rdx == stderr buffer
	; _or_ we get nulls in rsi/rdx if some catastrophic error occurred
falign
webservercfg$fastcgi_result:
	prolog	webservercfg$fastcgi_result
	push	rbx r12 r13

	; first things first: clear our hooked goods so that we don't double-destroy anything
	mov	qword [rdi+webserver_fcgihooked_ofs], 0
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx

	; if an actual error occurred, do a 502
	test	rsi, rsi
	jz	.do502
	; first up, whatever errors came through, send to errorlog
if used webservercfg$errorlog_path | used webservercfg$errorlog_syslog | defined include_everything
	mov	rdi, [rdx+buffer_itself_ofs]
	mov	rsi, [rdx+buffer_length_ofs]
	test	rsi, rsi
	jz	.noerrorlog
	call	string$from_utf8
	push	rax
	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, rax
	call	webservercfg$logerror
	pop	rdi
	call	heap$free
calign
.noerrorlog:
end if
	; next up, make sure we can parse the mimelike result
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r12+buffer_length_ofs]
	xor	edx, edx
	xor	ecx, ecx
	test	rsi, rsi
	jz	.do502
	call	mimelike$new_parse
	test	rax, rax
	jz	.do502

	; otherwise, extract the status, and set a preface from it
	mov	r13, rax
	mov	rdi, rax
	mov	rsi, .statusstr
	call	mimelike$getheader
	test	rax, rax
	jz	.do_checkcontenttype
	; extract the status, and return a normal webserver error based on it
	push	rax
	mov	rdi, rax
	mov	esi, ' '
	call	string$indexof_charcode
	pop	rdi
	cmp	rax, 0
	jl	.do502
	xor	esi, esi
	mov	edx, eax
	call	string$substr
	push	rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	cmp	dword [rsp], 302
	je	.check302
	cmp	dword [rsp], 301
	je	.check301
	cmp	dword [rsp], 304
	je	.do304
	cmp	dword [rsp], 206
	je	.do206
	mov	rdi, [rbx+webserver_config_ofs]
	pop	rsi
	call	webservercfg$error
	mov	rdi, r13
	mov	r13, rax
	call	mimelike$destroy
	mov	rax, [rbx+webserver_request_ofs]
	; and finally, send it out
	mov	rdi, rbx
	mov	rsi, r13
	mov	edx, [rax+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog
calign
.sentresponse_suicidal:
	mov	rdi, rbx
	call	epoll$fatality
	pop	r13 r12 rbx
	epilog
calign
.return_newtimer:
	mov	rdi, rbx
	call	webserver$newtimer
	pop	r13 r12 rbx
	epilog
calign
.do_checkcontenttype:
	; now, as much as I love nonstandard use cases, heh
	; php sends Content-type instead of Content-Type like everyone else
	; so, first up, check for that rubbish
	mov	rdi, r13
	mov	rsi, .php_lame_ctype
	call	mimelike$getheader
	test	rax, rax
	jnz	.phplame
	; see if there is a proper Content-Type
	mov	rdi, r13
	mov	rsi, mimelike$contenttype
	call	mimelike$getheader
	test	rax, rax
	jnz	.do200
	; see if there is a Location, otherwise, bailout with a 502
calign
.check302:
	mov	rdi, r13
	mov	rsi, .locstr
	call	mimelike$getheader
	test	rax, rax
	jz	.do502
	; do a 302
	mov	rdi, r13
	mov	rsi, .r302
	call	mimelike$setpreface
	mov	rdi, r13
	mov	rsi, .statusstr
	call	mimelike$removeheader
	mov	rdi, r13
	mov	rsi, mimelike$contentlength
	mov	rdx, .fivestr
	call	mimelike$setheader
	mov	rdi, r13
	mov	rsi, .r302body
	mov	edx, 5
	call	mimelike$setbody
	mov	rax, [rbx+webserver_request_ofs]
	mov	rdi, rbx
	mov	rsi, r13
	mov	edx, [rax+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog
calign
.check301:
	mov	rdi, r13
	mov	rsi, .locstr
	call	mimelike$getheader
	test	rax, rax
	jz	.do502
	; do a 302
	mov	rdi, r13
	mov	rsi, .r301
	call	mimelike$setpreface
	mov	rdi, r13
	mov	rsi, .statusstr
	call	mimelike$removeheader
	mov	rdi, r13
	mov	rsi, mimelike$contentlength
	mov	rdx, .fivestr
	call	mimelike$setheader
	mov	rdi, r13
	mov	rsi, .r302body
	mov	edx, 5
	call	mimelike$setbody
	mov	rax, [rbx+webserver_request_ofs]
	mov	rdi, rbx
	mov	rsi, r13
	mov	edx, [rax+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog
calign
.do304:
	mov	rdi, r13
	mov	rsi, .r304
	call	mimelike$setpreface
	mov	rdi, r13
	mov	rsi, .statusstr
	call	mimelike$removeheader
	mov	rax, [rbx+webserver_request_ofs]
	mov	rdi, rbx
	mov	rsi, r13
	mov	edx, [rax+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog
calign
.do206:
	mov	rdi, r13
	mov	rsi, .r206
	call	mimelike$setpreface
	mov	rdi, r13
	mov	rsi, .statusstr
	call	mimelike$removeheader
	mov	rax, [rbx+webserver_request_ofs]
	mov	rdi, rbx
	mov	rsi, r13
	mov	edx, [rax+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog

cleartext .fivestr, '5'
calign
.phplame:
	mov	rdi, r13
	mov	rsi, mimelike$contenttype
	mov	rdx, rax
	call	mimelike$setheader
	mov	rdi, r13
	mov	rsi, .php_lame_ctype
	call	mimelike$removeheader
	; fallthrough to do200
calign
.do200:
	mov	rdi, r13
	mov	rsi, .r200
	call	mimelike$setpreface
	mov	rax, [rbx+webserver_request_ofs]
	mov	rdi, rbx
	mov	rsi, r13
	mov	edx, [rax+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog
calign
.do502:
	mov	rdi, [rbx+webserver_config_ofs]
	mov	esi, 502
	call	webservercfg$error
	mov	rcx, [rbx+webserver_request_ofs]
	mov	rdi, rbx
	mov	rsi, rax
	mov	edx, [rcx+mimelike_user_ofs]
	; clear sentpartial
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	je	.return_newtimer
	pop	r13 r12 rbx
	epilog
cleartext .statusstr, 'Status'
cleartext .httponedotone, 'HTTP/1.1 '
cleartext .r200, 'HTTP/1.1 200 She',0x27,'ll be apples'
cleartext .r206, 'HTTP/1.1 206 Just a slice of the whole pie'
cleartext .r301, 'HTTP/1.1 301 She nicked off'
cleartext .r302, 'HTTP/1.1 302 Look here mate'
cleartext .r304, 'HTTP/1.1 304 Same same mate'
cleartext .php_lame_ctype, 'Content-type'
cleartext .locstr, 'Location'
.r302body:
	db	'Moved'

end if





if used webservercfg$timer | defined include_everything
	; single argument in rdi: our webservercfg object
	; our goal is to empty our logbuffer and/or errorlogbuffer of whatever they have accumulated since our last tick
falign
webservercfg$timer:
	prolog	webservercfg$timer
	push	rbx
	mov	rbx, rdi

if used webservercfg$errorlog_path | defined include_everything
	cmp	qword [rbx+webservercfg_errorfile_ofs], 0
	je	.noerrorwrite
	mov	rdi, [rbx+webservercfg_errorlogbuffer_ofs]
	mov	rsi, [rbx+webservercfg_errorfile_ofs]
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.noerrorwrite
	call	buffer$file_append
calign
.noerrorwrite:
	; we free the accumulated buffer regardless of whether we wrote it or not (so that it doesn't bloat indefinitely)
	mov	rdi, [rbx+webservercfg_errorlogbuffer_ofs]
	call	buffer$reset

end if

if used webservercfg$logs_path | defined include_everything
	; our logpath string must be non-null for us to proceed
	mov	rdi, [rbx+webservercfg_logbuffer_ofs]
	cmp	qword [rbx+webservercfg_logpath_ofs], 0
	je	.nologwrite
	cmp	qword [rdi+buffer_length_ofs], 0
	je	.nologwrite
	
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd
	mov	rdi, [webservercfg$lognameformat]
	mov	rsi, [rbx+webservercfg_logpath_ofs]
	call	formatter$doit
	push	rax
	mov	rdi, [rbx+webservercfg_logbuffer_ofs]
	mov	rsi, rax
	call	buffer$file_append
	pop	rdi
	call	heap$free
calign
.nologwrite:
	mov	rdi, [rbx+webservercfg_logbuffer_ofs]
	call	buffer$reset

end if

if used webservercfg$hotlist | defined include_everything
	call	webservercfg$hotlist_weed
end if

	xor	eax, eax		; keep the timer going indefinitely (well, until webservercfg$destroy is called on us)
	pop	rbx
	epilog

end if


if used webservercfg$log | used webservercfg$logerror | defined include_everything

globals
{
	; if this is set, normal webservercfg logging will not occur, and instead
	; this will get called with rdi == webservercfg object, rsi == preformatted string, edx == 0 == normal log, 1 == errorlog
	webservercfg$log_hook	dq	0
}

end if


if used webservercfg$log | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == preformatted string to dump into the logs
falign
webservercfg$log:
	prolog	webservercfg$log
if used webservercfg$logs_path | defined include_everything
	cmp	qword [webservercfg$log_hook], 0
	jne	.hooked
	mov	rdi, [rdi+webservercfg_logbuffer_ofs]
	push	rdi
	call	buffer$append_string
	pop	rdi
	mov	esi, 0xa
	call	buffer$append_byte
end if
	epilog
if used webservercfg$logs_path | defined include_everything
calign
.hooked:
	xor	edx, edx			; normal log
	call	qword [webservercfg$log_hook]
	epilog
end if

end if


if used webservercfg$logerror | defined include_everything
	; two arguments: rdi == webservercfg object, rsi == preformatted string to dump into the error logs
falign
webservercfg$logerror:
	prolog	webservercfg$logerror
if used webservercfg$errorlog_syslog | used webservercfg$errorlog_path | defined include_everything
	cmp	qword [webservercfg$log_hook], 0
	jne	.hooked
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
if used webservercfg$errorlog_syslog | defined include_everything
	cmp	dword [rdi+webservercfg_syslog_ofs], 0
	je	.skip_syslog
	; we double up the datetime here, cuz of course syslog does that for us, so we substring out our own timestamp
	mov	rdi, r12
	xor	esi, esi
	call	string$next_whitespace
	mov	rdi, r12
	mov	rsi, rax
	add	rsi, 1
	mov	rdx, -1
	call	string$substr
	push	r12
	mov	r12, rax
	mov	edi, log_notice
	mov	rsi, rax
	call	syslog
	mov	rdi, r12
	call	heap$free
	pop	r12
calign
.skip_syslog:
end if

if used webservercfg$errorlog_path | defined include_everything
	cmp	qword [rbx+webservercfg_errorfile_ofs], 0
	je	.skip_errorlog
	; all we have to do is add it to our errorlogbuffer
	mov	rdi, [rbx+webservercfg_errorlogbuffer_ofs]
	mov	rsi, r12
	push	rdi
	call	buffer$append_string
	pop	rdi
	mov	esi, 0xa
	call	buffer$append_byte
calign
.skip_errorlog:
end if
	pop	r12 rbx
	epilog
calign
.hooked:
	mov	edx, 1		; error log
	call	qword [webservercfg$log_hook]
	epilog

else
	epilog
end if


end if



if used webservercfg$error | defined include_everything
	; two arguments: rdi == webservercfg object, esi == error code
	; we create a mimelike response object with the minimum goods
falign
webservercfg$error:
	prolog	webservercfg$error
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12d, esi
	call	mimelike$new
	mov	r13, rax
	; since we don't have many of these, no sense in a map or table based
	mov	rdi, .e506
	mov	rsi, .e400
	mov	rdx, .e403
	mov	rcx, .e404
	mov	r8, .e500
	mov	r9, .e501
	mov	r10, .e502
	mov	r11, .e503
	cmp	r12d, 400
	cmove	rdi, rsi
	je	.gotit
	cmp	r12d, 403
	cmove	rdi, rdx
	je	.gotit
	cmp	r12d, 404
	cmove	rdi, rcx
	je	.gotit
	cmp	r12d, 500
	cmove	rdi, r8
	je	.gotit
	cmp	r12d, 501
	cmove	rdi, r9
	je	.gotit
	cmp	r12d, 502
	cmove	rdi, r10
	je	.gotit
	cmp	r12d, 503
	cmove	rdi, r11
	je	.gotit
	mov	r11, .e405
	cmp	r12d, 405
	cmove	rdi, r11
	je	.gotit
	mov	rsi, .e504
	mov	rdx, .e505
	cmp	r12d, 504
	cmove	rdi, rsi
	cmp	r12d, 505
	cmove	rdi, rdx
calign
.gotit:
	mov	rsi, rdi
	mov	rdi, r13
	call	mimelike$setpreface
	; now check to see whether we are doing it stringbased or not
	cmp	qword [rbx+webservercfg_errordocs_ofs], 0
	je	.stringbased
	mov	edi, r12d
	mov	esi, 10
	call	string$from_unsigned
	mov	r12, rax
	mov	rdi, [rbx+webservercfg_errordocs_ofs]
	mov	rsi, rax
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .dothtml
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	esi, [rbx+webservercfg_filestattime_ofs]
	call	webservercfg$hotlist
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	test	r12, r12
	jz	.stringbased
	; otherwise, we have our privmapped sitting in r12
	mov	rdi, r13
	mov	rsi, [r12+privmapped_base_ofs]
	mov	rdx, [r12+privmapped_size_ofs]
	call	mimelike$setbody_external
	; set the content type to text/html; charset=UTF-8
	mov	rdi, r13
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$texthtmlutf8
	call	mimelike$addheader
	; we are done
	mov	rax, r13
	pop	r13 r12 rbx
	epilog
cleartext .dothtml, '.html'
calign
.stringbased:
	; so our preface already got set, set our content type to text/plain
	mov	rdi, r13
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$textplain
	call	mimelike$addheader
	; our actual body for non-file-based errors is simply the substr of our preface that excludes the HTTP/1.1 preface
	; in UTF-8 of course
	; we cheat here and deal with our mimelike body directly
	mov	rdi, [r13+mimelike_preface_ofs]
	mov	esi, 9
	mov	rdx, -1
	call	string$substr
	mov	r12, rax
	mov	rdi, rax
	call	string$utf8_length
	mov	rdi, [r13+mimelike_body_ofs]
	mov	rsi, rax
	call	buffer$reserve
	mov	rsi, [r13+mimelike_body_ofs]
	mov	rdi, r12
	mov	rsi, [rsi+buffer_itself_ofs]
	call	string$to_utf8
	mov	rdi, [r13+mimelike_body_ofs]
	mov	rsi, rax
	call	buffer$append_nocopy
	mov	rdi, [r13+mimelike_body_ofs]
	mov	esi, 0xa0d
	call	buffer$append_word
	mov	rdi, r12
	call	heap$free
	mov	rax, r13
	pop	r13 r12 rbx
	epilog
if defined boring_http_replies
cleartext .e400, 'HTTP/1.1 400 Bad Request'
cleartext .e403, 'HTTP/1.1 403 Forbidden'
cleartext .e404, 'HTTP/1.1 404 Not Found'
cleartext .e405, 'HTTP/1.1 405 Not Allowed'
cleartext .e500, 'HTTP/1.1 500 Internal Server Error'
cleartext .e501, 'HTTP/1.1 501 Not Implemented'
cleartext .e502, 'HTTP/1.1 502 Bad Gateway'
cleartext .e503, 'HTTP/1.1 503 Service Unavailable'
cleartext .e504, 'HTTP/1.1 504 Gateway Timeout'
cleartext .e505, 'HTTP/1.1 505 HTTP Version Not Supported'
cleartext .e506, 'HTTP/1.1 506 Unimplemented Error Code'
else
cleartext .e400, 'HTTP/1.1 400 Up a gumtree'
cleartext .e403, 'HTTP/1.1 403 I wouldn',0x27,'t be doin that'
cleartext .e404, 'HTTP/1.1 404 Gone Walkabout'
cleartext .e405, 'HTTP/1.1 405 Wrong idea mate'
cleartext .e500, 'HTTP/1.1 500 It',0x27,'s Cactus'
cleartext .e501, 'HTTP/1.1 501 Not Implemented'
cleartext .e502, 'HTTP/1.1 502 Had a blue with the old fella'
cleartext .e503, 'HTTP/1.1 503 You got nits in your network'
cleartext .e504, 'HTTP/1.1 504 Gateway Tuckered Out'
cleartext .e505, 'HTTP/1.1 505 You gone bongers mate?'
cleartext .e506, 'HTTP/1.1 506 Unimplemented Error Code'
end if

end if




if used webservercfg$backpath

	; our io/epoll vtable for backpath (aka upstream)
dalign
wsbp$vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, wsbp$receive, wsbp$error, io$timeout



	; two arguments: rdi == our wsbp epoll object, rsi == webserver_request_ofs (already modified to suit the backpath)
falign
wsbp$sendrequest:
	prolog	wsbp$sendrequest
	; in most deployment/use cases for backpath, the actual backpath is local, so we don't bother to break up the requests
	; and instead send it all in one go and let the epoll layer deal with output buffering (if it is necessary)
	push	rdi rsi
	mov	rdi, rsi
	call	mimelike$compose
	pop	rcx rdi
	mov	r8, [rcx+mimelike_xmitbody_ofs]
	mov	r9, [rdi]
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	call	qword [r9+io_vsend]
	epilog


	; we get three arguments, rdi == our wsbp epoll object, rsi == ptr to data, rdx == length of same
falign
wsbp$receive:
	prolog	wsbp$receive
	; if we were _not_ intercepting and possibly auto-gzipping the response, we could just cross-connect these and send it
	; straight out to the client, instead however we need to perform similar actions as the webserver$receive, and actually
	; parse/acquire the complete reply, then use the normal webserver$sendresponse method to fire it back out, which will
	; deal with all of the normal autogzipping/etc for us
	mov	r8, [rdi+epoll_base_size]	; webserver object

	push	rbx
	mov	rbx, rdi
	mov	r9, [r8+webserver_request_ofs]

	; we can make use of our epoll_inbuf_ofs directly here
	mov	rdi, [rdi+epoll_inbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	mov	r11d, [r9+mimelike_user_ofs]	; GET, HEAD, POST (0, 1, 2)
	; we assume that backpaths are trusted hosts, so we don't do all of the length restrictions here
	cmp	rdx, 16
	jb	.needmore
	mov	rcx, rsi
	mov	r10, rdx
calign
.headerscan:
	cmp	edx, 4
	jb	.headerscan_lessthanfourleft
	cmp	dword [rsi], 0xa0d0a0d
	je	.headerfound
	cmp	edx, 2
	jb	.needmore
	cmp	word [rsi], 0xa0a
	je	.headerfound
	add	rsi, 1
	sub	edx, 1
	jnz	.headerscan
calign
.headerscan_lessthanfourleft:
	cmp	word [rsi], 0xa0a
	je	.headerfound
	add	rsi, 1
	sub	edx, 1
	jz	.needmore
	cmp	word [rsi], 0xa0a
	je	.headerfound
calign
.needmore:
	xor	eax, eax		; don't kill us off
	pop	rbx
	epilog
calign
.headerfound:
	; if this response is in reply to a HEAD request, then we need to take special care
	cmp	r11d, 1
	je	.headresponse
	; otherwise, if the backpath is local (which hopefully it is), we can let mimelike$new_parse_ext deal with it
	push	r11
	mov	rdi, rcx
	mov	rsi, r10
	xor	edx, edx	; full response required
	mov	ecx, 1		; preface exists
	call	mimelike$new_parse_ext
	pop	rdx
	test	rax, rax
	jz	.needmore
	; otherwise, we got a complete response
	mov	rdi, [rbx+epoll_base_size]
	mov	rsi, rax
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	mov	rdi, [rbx+epoll_inbuf_ofs]
	call	buffer$reset
	xor	eax, eax
	pop	rbx
	epilog
calign
.sentresponse_suicidal:
	; we need to epoll$fatality our webserver object, _and_ ourselves
	mov	rdi, [rbx+epoll_base_size]
	; make sure that we clear our backpath pointer for the webserver object here and now
	mov	qword [rdi+webserver_backpath_ofs], 0
	call	epoll$fatality
	mov	eax, 1
	pop	rbx
	epilog
calign
.headresponse:
	; we need to mimelike parse the goods, header only for the epoll_inbuf_ofs, then sendresponse
	; then clear the epoll_inbuf_ofs
	; then return 0
	mov	rdi, rcx
	mov	rsi, r10
	mov	edx, 1		; headers only please
	mov	ecx, 1		; preface exists
	call	mimelike$new_parse
	test	rax, rax
	jz	.do502
	mov	rdi, [rbx+epoll_base_size]
	mov	rsi, rax
	mov	edx, 1		; HEAD
	call	webserver$sendresponse
	test	eax, eax
	jnz	.sentresponse_suicidal
	mov	rdi, [rbx+epoll_inbuf_ofs]
	call	buffer$reset
	xor	eax, eax
	pop	rbx
	epilog
calign
.do502:
	; we know that wsbp$error will fire off our 502 for us
	mov	rdi, rbx
	call	wsbp$error
	; clear our inbuf also, cuz we were unable to parse it
	mov	rdi, [rbx+epoll_inbuf_ofs]
	call	buffer$reset
	xor	eax, eax
	pop	rbx
	epilog



falign
wsbp$error:
	prolog	wsbp$error
	; if there is a current request in progress, we need to fire off a 502, otherwise, we just set the backpath ptr to 0
	; and bailout quietly
	mov	rsi, [rdi+epoll_base_size]
	cmp	qword [rsi+webserver_request_ofs], 0
	jne	.do502
	mov	qword [rsi+webserver_backpath_ofs], 0
	epilog
calign
.do502:
	push	rsi
	mov	rdi, [rdi+epoll_base_size+8]
	mov	esi, 502
	call	webservercfg$error
	pop	rdi
	mov	rsi, rax
	mov	rcx, [rdi+webserver_request_ofs]
	mov	edx, [rcx+mimelike_user_ofs]
	mov	qword [rdi+webserver_backpath_ofs], 0
	call	webserver$sendresponse
	epilog

end if



webserver_config_ofs = io_base_size
webserver_flags_ofs = io_base_size + 8
webserver_accum_ofs = io_base_size + 16
webserver_timer_ofs = io_base_size + 24
webserver_timedout_ofs = io_base_size + 32
webserver_request_ofs = io_base_size + 40
webserver_respcode_ofs = io_base_size + 48
webserver_sentpartial_ofs = io_base_size + 56
webserver_inflight_ofs = io_base_size + 64
webserver_inflightlen_ofs = io_base_size + 72
webserver_inflightcb_ofs = io_base_size + 80
webserver_inflightcbarg_ofs = io_base_size + 88
webserver_inflightsent_ofs = io_base_size + 96
webserver_fcgihooked_ofs = io_base_size + 104
webserver_requestlen_ofs = io_base_size + 112
webserver_needmore_ofs = io_base_size + 120
webserver_backpath_ofs = io_base_size + 128
webserver_raddr_ofs = io_base_size + 136
webserver_raddrlen_ofs = webserver_raddr_ofs + 110

webserver_size = webserver_raddrlen_ofs + 8


if used webserver$vtable | defined include_everything

	; our io/epoll vtable, and we include one extra method for our webrequest

dalign
webserver$vtable:
	dq	webserver$destroy, webserver$clone, webserver$connected, io$send, webserver$receive, io$error, webserver$timeout
	; our added custom method:
	dq	webserver$request

end if

webserver_vrequest = io_vtimeout + 8

if used webserver$new | defined include_everything
	; single argument in rdi: a webservercfg object
falign
webserver$new:
	prolog	webserver$new
	push	rdi
	call	buffer$new
	push	rax
	mov	edi, webserver_size
	call	heap$alloc_clear
	pop	rsi rdi
	mov	qword [rax], webserver$vtable
	mov	[rax+webserver_config_ofs], rdi
	mov	[rax+webserver_accum_ofs], rsi
	epilog

end if

if used webserver$clone | defined include_everything
	; single argument in rdi: webserver object to clone
falign
webserver$clone:
	prolog	webserver$clone
	; since the config object is the only var we clone, just pass it to new
	push	rdi
	mov	rdi, [rdi+webserver_config_ofs]
	call	webserver$new
	pop	rsi
	; make sure we clone the vtable in case it is different
	mov	rcx, [rsi]
	mov	[rax], rcx
	;
	cmp	qword [rsi+io_child_ofs], 0
	jne	.withchild
	epilog
calign
.withchild:
	push	rax
	mov	rdi, [rsi+io_child_ofs]
	mov	rsi, [rdi]
	call	qword [rsi+io_vclone]
	mov	rsi, rax
	pop	rax
	mov	[rax+io_child_ofs], rsi
	mov	[rsi+io_parent_ofs], rax
	; in order to accommodate partial send buffering, we need to issue our epoll sendcb
	mov	rdx, rax
	mov	rdi, rsi
	mov	rsi, webserver$sendcb
	call	epoll$sendcb
	epilog

end if

if used webserver$destroy | defined include_everything
	; single argument in rdi: our webserver object
falign
webserver$destroy:
	prolog	webserver$destroy
	push	rbx
	mov	rbx, rdi
	; cleanup after ourselves, and then let io$destroy do the free of our pointer and deal with our children
	mov	rdi, [rdi+webserver_accum_ofs]
	call	buffer$destroy
	; if there is a request object sitting here still, destroy it too
	mov	rdi, [rbx+webserver_request_ofs]
	test	rdi, rdi
	jz	.norequest
	call	mimelike$destroy
calign
.norequest:
	; if !timedout, and timer is non-null, then we need to clean up our timer object
	; if timedout, then the epoll layer is doing it for us
if webservertimerdebug
	cmp	dword [rbx+webserver_timedout_ofs], 0
	jne	.debug_timedout
	cmp	qword [rbx+webserver_timer_ofs], 0
	je	.skiptimer
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, rbx
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debug2
	call	string$to_stdout
	mov	rdi, [rbx+webserver_timer_ofs]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, [rbx+webserver_timer_ofs]
	call	epoll$timer_clear
	jmp	.skiptimer
cleartext .debug1, 'webserver$destroy, we are: '
cleartext .debug2, ' clearing timer at: '
cleartext .debug3, ' timedout was set, not clearing timer at: '
calign
.debug_timedout:
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, rbx
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debug3
	call	string$to_stdout
	mov	rdi, [rbx+webserver_timer_ofs]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, [rbx+webserver_timer_ofs]
	call	epoll$timer_clear
	; fallthrough from here
else

	cmp	dword [rbx+webserver_timedout_ofs], 0
	jne	.skiptimer
	mov	rdi, [rbx+webserver_timer_ofs]
	test	rdi, rdi
	jz	.skiptimer
	call	epoll$timer_clear
end if

calign
.skiptimer:
	; if we have a nonzero inflightcb, call it
	cmp	qword [rbx+webserver_inflightcb_ofs], 0
	je	.skipinflightcb
	mov	rdi, [rbx+webserver_inflightcbarg_ofs]
	call	qword [rbx+webserver_inflightcb_ofs]
calign
.skipinflightcb:
	cmp	qword [rbx+webserver_fcgihooked_ofs], 0
	je	.skipfcgi
	mov	rdi, [rbx+webserver_fcgihooked_ofs]
	call	epoll$fatality
calign
.skipfcgi:
if used webservercfg$backpath
	; if we have a nonzero backpath, destroy it
	cmp	qword [rbx+webserver_backpath_ofs], 0
	je	.skipbackpath
	mov	rdi, [rbx+webserver_backpath_ofs]
	call	epoll$fatality
calign
.skipbackpath:
end if
	mov	rdi, rbx
	pop	rbx
	call	io$destroy
	epilog

end if


if used webserver$connected | defined include_everything
	; io defined rdi == our webserver object, and epoll gives us remote address/len for server mode in rsi/edx
falign
webserver$connected:
	prolog	webserver$connected
	push	rbx
	mov	rbx, rdi
	; we could use the actual epoll object's timers, but we'll have easier/tighter control if we fire our own
	; from here, primary reason being: we don't want a general-purpose long-standing read timeout in effect,
	; because once we get an initial request, said timeout has to cease (while we then perhaps slowly service it)
	mov	[rdi+webserver_raddrlen_ofs], edx
	lea	rdi, [rdi+webserver_raddr_ofs]
	call	memcpy
	; create a 30 second timeout to wait for a request to arrive:
	mov	rdi, rbx
	call	webserver$newtimer
	; clear our sentpartial (in case sendcb was triggered by lower io layers)
	mov	dword [rbx+webserver_sentpartial_ofs], 0
if used webservercfg$backpath
	; if our config object has a backpath set, now is the time to fire it up
	mov	rsi, [rbx+webserver_config_ofs]
	cmp	qword [rsi+webservercfg_backpath_ofs], 0
	jne	.backpath
end if
	pop	rbx
	epilog
if used webservercfg$backpath
calign
.backpath:
	; so, we do 1:1 as connections arrive, rather than dealing with them per-request
	; we need to create our wsbp epoll object first up
	mov	rdi, wsbp$vtable
	mov	esi, 16
	call	epoll$new
	mov	[rbx+webserver_backpath_ofs], rax
	mov	rcx, [rbx+webserver_config_ofs]
	mov	r8, [rcx+webservercfg_backpath_ofs]
	lea	rdi, [r8+8]
	mov	esi, [r8]
	mov	rdx, rax
	; hangon to our pointers so that the wsbp functions know who they are dealing with
	mov	[rax+epoll_base_size], rbx			; webserver object
	mov	[rax+epoll_base_size+8], rcx			; webservercfg object
	call	epoll$outbound
	; if that _failed_ we need to clear our backpath and let it ride
	test	eax, eax
	jz	.backpath_failed
	pop	rbx
	epilog
calign
.backpath_failed:
	mov	qword [rbx+webserver_backpath_ofs], 0
	pop	rbx
	epilog

end if

end if



if used webserver$sendcb | defined include_everything
	; two arguments: rdi == our webserver object, esi == 0 == partial send occurred, 1 == send buffer exhausted
falign
webserver$sendcb:
	prolog	webserver$sendcb
	test	esi, esi
	jz	.setpartial
	; if inflight is nonzero, special handling is required
	cmp	qword [rdi+webserver_inflight_ofs], 0
	jne	.inflight
calign
.normal_finish:
	; otherwise, our send buffer was exhausted... if we were meant to close the connection, now is the time
	test	dword [rdi+webserver_flags_ofs], 1
	jz	.closeit

	; if we have a request object, destroy it
	cmp	qword [rdi+webserver_request_ofs], 0
	je	.normal_finish_norequest
	push	rdi
	mov	rdi, [rdi+webserver_request_ofs]
	call	mimelike$destroy
	pop	rdi
	mov	qword [rdi+webserver_request_ofs], 0
calign
.normal_finish_norequest:
	push	rdi
	; otherwise, we need a new timer
	call	webserver$newtimer
	pop	rdi
	mov	rsi, [rdi+webserver_accum_ofs]
	cmp	qword [rsi+buffer_length_ofs], 0
	jne	.normal_finish_recurse
if webserverdebug
	mov	rdi, .debug1
	call	string$to_stdoutln
end if
	epilog
calign
.normal_finish_recurse:
	push	rbx
	mov	rbx, rdi
calign
.normal_finish_recursion:
	mov	dword [rbx+webserver_needmore_ofs], 0
	mov	rdi, rbx
	call	webserver$check_accum
	cmp	dword [rbx+webserver_needmore_ofs], 0
	jne	.normal_finish_return
	test	eax, eax
	jnz	.normal_finish_deathonastick
	cmp	qword [rbx+webserver_request_ofs], 0
	jne	.normal_finish_return
	; make sure we still have accum data to deal with
	mov	rsi, [rbx+webserver_accum_ofs]
	cmp	qword [rsi+buffer_length_ofs], 16
	ja	.normal_finish_recursion
	; otherwise, we are done
	pop	rbx
	epilog
calign
.normal_finish_deathonastick:
	mov	rdi, rbx
	pop	rbx
	jmp	.closeit
calign
.normal_finish_return:
	; it is servicing a request, so let it be
	pop	rbx
	epilog

calign
.setpartial:
	mov	dword [rdi+webserver_sentpartial_ofs], 1
if webserverdebug
	mov	rdi, .debug2
	call	string$to_stdoutln
end if
	epilog
calign
.closeit:
	push	rdi
	call	tls$closenotify
	pop	rdi
	call	epoll$fatality
if webserverdebug
	mov	rdi, .debug3
	call	string$to_stdoutln
end if
	epilog
if webserverdebug
cleartext .debug1, 'send buffer exhausted, ready for next request'
cleartext .debug2, 'webserver$sendcb, set sentpartial=1'
cleartext .debug3, 'send buffer exhausted, closed connection'
end if
calign
.inflight:
	mov	dword [rdi+webserver_sentpartial_ofs], 0
	cmp	qword [rdi+webserver_inflightlen_ofs], 0
	je	.inflight_complete
	mov	rax, [rdi+webserver_inflightlen_ofs]
	mov	rcx, [rdi]
	mov	edx, webserver_subsequentsend
	mov	rsi, [rdi+webserver_inflight_ofs]
	cmp	rdx, rax
	cmova	rdx, rax
	add	[rdi+webserver_inflightsent_ofs], rdx
	add	[rdi+webserver_inflight_ofs], rdx
	sub	[rdi+webserver_inflightlen_ofs], rdx
	push	rdi
	call	qword [rcx+io_vsend]
	pop	rdi
	cmp	dword [rdi+webserver_sentpartial_ofs], 0
	je	.inflight
	epilog
calign
.inflight_complete:
	push	rdi
	mov	rsi, [rdi+webserver_inflightsent_ofs]
	call	webserver$log
	pop	rdi
	mov	qword [rdi+webserver_inflight_ofs], 0
	cmp	qword [rdi+webserver_inflightcb_ofs], 0
	je	.normal_finish
	; otherwise, we have a callback + argument
	push	rdi
	mov	rcx, rdi
	mov	rdi, [rdi+webserver_inflightcbarg_ofs]
	call	qword [rcx+webserver_inflightcb_ofs]
	pop	rdi
	mov	qword [rdi+webserver_inflightcb_ofs], 0
	jmp	.normal_finish

end if


if used webserver$log | defined include_everything
	; two arguments: rdi == webserver object, rsi == size of the object returned
	; NOTE: this signifies the end of a request handling
falign
webserver$log:
	prolog	webserver$log
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdx, [rdi+webserver_config_ofs]
	mov	r13, [rdi+webserver_request_ofs]
	test	r13, r13
	jz	.norequest
	; if our config object does not have a logpath, we don't bother
	cmp	qword [rdx+webservercfg_logpath_ofs], 0
	je	.dontbother

	; otherwise, prepare our logformat
	sub	rsp, 64
	mov	rdi, r13
	mov	rsi, .hoststr
	call	mimelike$getheader
	mov	rcx, .dashstr
	test	rax, rax
	cmovz	rax, rcx
	mov	[rsp], rax
	lea	rsi, [rbx+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	mov	[rsp+8], rax
	mov	rdi, [r13+mimelike_preface_ofs]
	mov	rax, .emptystr
	test	rdi, rdi
	cmovz	rdi, rax
	mov	[rsp+16], rdi
	mov	edi, [rbx+webserver_respcode_ofs]
	mov	[rsp+24], rdi
	mov	[rsp+32], r12
	mov	rdi, r13
	mov	rsi, .refererstr
	call	mimelike$getheader
	mov	rcx, .emptystr
	test	rax, rax
	cmovz	rax, rcx
	mov	[rsp+40], rax
	mov	rdi, r13
	mov	rsi, .useragentstr
	call	mimelike$getheader
	mov	rcx, .emptystr
	test	rax, rax
	cmovz	rax, rcx
	mov	[rsp+48], rax
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd

	mov	rdi, [webserver$logformat]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	mov	rcx, [rsp+16]
	mov	r8, [rsp+24]
	mov	r9, [rsp+32]
	mov	r10, [rsp+40]
	mov	r11, [rsp+48]
	call	formatter$doit
	mov	[rsp], rax
	mov	rdi, [rsp+8]
	call	heap$free

	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, [rsp]
	call	webservercfg$log
	
	mov	rdi, [rsp]
	call	heap$free

	add	rsp, 64
	pop	r13 r12 rbx
	epilog
calign
.dontbother:
	pop	r13 r12 rbx
	epilog

cleartext .hoststr, 'Host'
cleartext .dashstr, '-'
cleartext .emptystr, ''
cleartext .refererstr, 'Referer'
cleartext .useragentstr, 'User-Agent'
calign
.norequest:
	; if respcode == 400, errorlog a bad request
	; if respcode == 501, errorlog a not implemented, extract the first bytes from the accumulator til we hit a space (or end)
	; otherwise, generate a string containing the response code
	cmp	dword [rbx+webserver_respcode_ofs], 400
	je	.badrequest
	cmp	dword [rbx+webserver_respcode_ofs], 501
	je	.notimplemented
	
	lea	rsi, [rbx+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	push	rax

	mov	rdi, [rbx+webserver_respcode_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
if webserverdebug
	mov	rdi, .debugrequest_str
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
end if
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd
	mov	rdi, [webserver$errorformat]
	mov	rsi, [rsp+8]
	mov	rdx, [rsp]
	call	formatter$doit
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, [rsp]
	call	webservercfg$logerror
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 16

	pop	r13 r12 rbx
	epilog
calign
.notimplemented:
	mov	rdi, [rbx+webserver_accum_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	test	rdx, rdx
	jz	.notimplemented_plain
calign
.notimplemented_scan:
	cmp	byte [rsi], ' '
	je	.notimplemented_doit
	cmp	byte [rsi], 13
	je	.notimplemented_doit
	cmp	byte [rsi], 10
	je	.notimplemented_doit
	add	rsi, 1
	sub	rdx, 1
	jnz	.notimplemented_scan
calign
.notimplemented_doit:
	mov	rdi, [rdi+buffer_itself_ofs]
	sub	rsi, rdi
	jz	.notimplemented_plain
	call	string$from_utf8
	push	rax
	mov	rdi, .notimplemented_preface
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, .notimplemented_postface
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free

	lea	rsi, [rbx+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	push	rax
	
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd
	mov	rdi, [webserver$errorformat]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	call	formatter$doit
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp+8]
	call	heap$free
	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, [rsp]
	call	webservercfg$logerror
	mov	rdi, [rsp]
	call	heap$free
	add	rsp, 16

	pop	r13 r12 rbx
	epilog
calign
.notimplemented_plain:
	lea	rsi, [rbx+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	push	rax
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd
	mov	rdi, [webserver$errorformat]
	mov	rsi, [rsp]
	mov	rdx, .notimplemented_plainstr
	call	formatter$doit
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, [rsp]
	call	webservercfg$logerror
	pop	rdi
	call	heap$free

	pop	r13 r12 rbx
	epilog
calign
.badrequest:
	lea	rsi, [rbx+webserver_raddr_ofs]
	mov	edi, [rsi+4]
	call	inet_ntoa
	push	rax
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd
	mov	rdi, [webserver$errorformat]
	mov	rsi, [rsp]
	mov	rdx, .badrequest_str
	call	formatter$doit
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, [rsp]
	call	webservercfg$logerror
	pop	rdi
	call	heap$free

	pop	r13 r12 rbx
	epilog

	
cleartext .notimplemented_preface, 'Request method ['
cleartext .notimplemented_postface, '] not implemented'
cleartext .notimplemented_plainstr, 'Request method not implemented'
cleartext .badrequest_str, 'Bad request'
if webserverdebug
cleartext .debugrequest_str, 'Responded with: '
end if

end if





if used webserver$sendresponse | used webserver$logs_path | defined include_everything


globals
{
	webserver$dateformat	dq	0
	webserver$logformat	dq	0
	webserver$errorformat	dq	0
	webservercfg$lognameformat	dq	0
}


end if



if used webserver$sendresponse | defined include_everything

	; three arguments: rdi == webserver object, rsi == mimelike response object, edx == GET, HEAD, POST (0,1,2)
	; we return a bool in eax as to whether or not we should close the connection then and there
	; further, we assume ownership of the response object (and destroy it ourselves, or deal with buffering of same)

	; NOTE/CAUTION: if the size of the response body is >webserver_bigfile, said body/bodyext needs to remain valid
	; for the lifetime of this request/response transmit (which could be a while).
	; if, prior to calling this, webserver_inflightcb_ofs and webserver_inflightcbarg_ofs are set, when we finish sending
	; the entirety, inflightcb will be called (so that you could, say, unpin the resource)
	; NOTE: inflightcb is really only useful if the response itself is not buffered inside mimelike_body_ofs (a buffer object)
	; if it is an external resource, inflightcb is mighty useful
	; if it is in the body buffer, we actually set inflightcb to buffer$destroy with its arg set to the buffer itself so that it automatically gets cleaned up
	; when we complete the sending

	; NOTE 2/CAUTION 2: It is expected that this routine will always be responsible for servicing the current request
	; and as such, this routine also clears the webserver_request_ofs object, as well as _recalling_ webserver$check_accum (so that we can do pipelining)
	; because this may result in our own webserver object death/destruction, it is imperative that this routine be the _last_ in your calling context/frame
	; 
falign
webserver$sendresponse:
	prolog	webserver$sendresponse
	push	rbx r13 r14
	mov	rbx, rdi
	mov	r13, rsi
	mov	r14d, edx

if webserver_breach_mitigation & webserver_autogzip
	test	dword [rbx+webserver_flags_ofs], 2
	jz	.skipbreach
	mov	rcx, [rbx+webserver_config_ofs]
	cmp	dword [rcx+webservercfg_istls_ofs], 0
	je	.skipbreach
	; note: just because auto-gzip is enabled, doesn't mean we actually ARE going to gzip it
	; but we'll still add X-NB here regardless as it certainly can't hurt anything.
if webserver_breach_mitigation > 1024
	display 'webserver_breach_mitigation has an insane value (>1024), fail.',10
	err
end if
	sub	rsp, 1032
	mov	edi, 1
	mov	esi, webserver_breach_mitigation
	call	rng$int
	mov	[rsp+1024], eax
	mov	esi, eax
	mov	rdi, rsp
	call	rng$block
	mov	rdi, rsp
	mov	esi, [rsp+1024]
	xor	edx, edx
	call	string$from_bintohex
	mov	rdi, r13
	mov	rsi, .xnb
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
	add	rsp, 1032
calign
.skipbreach:
end if
	mov	rdx, .closestr
	mov	rcx, .keepalivestr
	test	dword [rbx+webserver_flags_ofs], 1
	cmovnz	rdx, rcx
	mov	rdi, r13
	mov	rsi, mimelike$connection
	call	mimelike$setheader
	mov	rdi, r13
	mov	rsi, .serverstr
	mov	rdx, .ident
	call	mimelike$setheader
	mov	rdi, [_epoll_tv_secs]
	mov	rsi, [_epoll_tv_usecs]
	call	ctime$to_jd
	mov	rdi, [webserver$dateformat]
	call	formatter$doit
	mov	rdi, r13
	mov	rsi, .datestr
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy

if webserver_autogzip
	test	dword [rbx+webserver_flags_ofs], 2
	jz	.nogzip
	mov	rcx, [r13+mimelike_body_ofs]
	mov	rax, [r13+mimelike_bodyextlen_ofs]
	or	rax, [rcx+buffer_length_ofs]
	jz	.nogzip
	cmp	rax, webserver_bigfile
	ja	.nogzip
	mov	rdi, r13
	mov	rsi, mimelike$contentencoding
	mov	rdx, mimelike$gzip
	call	mimelike$setheader
calign
.nogzip:
end if
	test	dword [rbx+webserver_flags_ofs], 4
	jz	.nochunked
	mov	rcx, [r13+mimelike_body_ofs]
	mov	rax, [r13+mimelike_bodyextlen_ofs]
	or	rax, [rcx+buffer_length_ofs]
	cmp	rax, webserver_bigfile
	ja	.nochunked
	test	rax, rax
	jz	.nochunked

	; apple core media does _not_ like chunked transfer encoding for partial ranges
	; so, see if we have a Content-Range header, and if we do, skip adding the chunked header
	mov	rdi, r13
	mov	rsi, mimelike$contentrange
	call	mimelike$getheader
	test	rax, rax
	jnz	.nochunked

	mov	rdi, r13
	mov	rsi, mimelike$transferencoding
	mov	rdx, mimelike$chunked
	call	mimelike$setheader
calign
.nochunked:
if webserver_hsts
	mov	rcx, [rbx+webserver_config_ofs]
	cmp	dword [rcx+webservercfg_istls_ofs], 0
	je	.nohsts
	mov	rdi, r13
	mov	rsi, .hsts
	mov	rdx, .hstsvalue
	call	mimelike$setheader
calign
.nohsts:
end if
	; extra our response code from position 9,3 of our preface
	mov	rdi, [r13+mimelike_preface_ofs]
	; a reply with no preface is not allowed, so we don't bother checking for it
	mov	esi, 9
	mov	edx, 3
	call	string$substr
	push	rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	[rbx+webserver_respcode_ofs], rax
	pop	rdi
	call	heap$free

	; now, for transmit bodies that are > webserver_bigfile, we do _not_ compose them
	; and instead deal with things quite differently (to avoid buffering the entirety
	; _twice_, meaning: compose builds its xmitbody, and then the call to epoll$send
	; then buffers the entire thing, then the xmitbody gets torn down, while the epoll
	; layer consumes its own sendbuffer)

	; obviously, for huge files that is not a good thing to be doing, hahah
	mov	rcx, [r13+mimelike_body_ofs]
	mov	rax, [r13+mimelike_bodyextlen_ofs]
	or	rax, [rcx+buffer_length_ofs]
	cmp	rax, webserver_bigfile
	ja	.sendinsegments

	; so now, the response object is ready for composition
	mov	rdi, r13
	call	mimelike$compose
	mov	rcx, [r13+mimelike_xmitbody_ofs]

	; clear our sentpartial flag in case we set it before
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	mov	qword [rbx+webserver_inflightsent_ofs], 0

if webserverdebug
	mov	rcx, [r13+mimelike_xmitbody_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [r13+mimelike_hdrlen_ofs]
	syscall
end if

	; now, if we are responding to a HEAD request, we only send hdrlen worth
	mov	rcx, [r13+mimelike_xmitbody_ofs]
	mov	r8, [r13+mimelike_hdrlen_ofs]
	mov	rdi, rbx
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]
	cmp	r14d, 1
	cmove	rdx, r8

	; only log the object size itself, not the entire size
	mov	r9, rdx
	sub	r9, r8

	; ok so, we are ready to send everything out... but there are two case scenarios here
	; to be dealt with:
	; 1) simple case: rdx <= webserver_initialsend, in which case, send it all in one whack
	;    and be done with it
	; 2) > webserver_initialsend, setup inflight/inflightcb and repeat until we get a sentpartial
	;     or we send everything out without getting one in which case we continue as normal


	cmp	rdx, webserver_initialsend
	ja	.senduntilpartial


	push	r9
	call	qword [rcx+io_vsend]
	pop	rsi

	mov	rdi, rbx
	call	webserver$log

	; we can cleanup our response object now that we are done with it
	mov	rdi, r13
	call	mimelike$destroy

	; so now, if sentpartial, we return 0 from here no matter what
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.zeroret_complete
	; if the connection should be closed (flag & 1 == 0), we return 1
	test	dword [rbx+webserver_flags_ofs], 1
	jnz	.zeroret_complete

	; cleanup the outstanding request object
	cmp	qword [rbx+webserver_request_ofs], 0
	je	.oneret_norequest
	mov	rdi, [rbx+webserver_request_ofs]
	mov	qword [rbx+webserver_request_ofs], 0
	call	mimelike$destroy

	mov	eax, 1
	pop	r14 r13 rbx
	epilog
calign
.oneret_norequest:
	mov	eax, 1
	pop	r14 r13 rbx
	epilog
calign
.zeroret_complete:
	; cleanup the outstanding request object
	cmp	qword [rbx+webserver_request_ofs], 0
	je	.zeroret_complete_norequest
	mov	rdi, [rbx+webserver_request_ofs]
	mov	qword [rbx+webserver_request_ofs], 0
	call	mimelike$destroy

	xor	eax, eax
	pop	r14 r13 rbx
	epilog
calign
.zeroret_complete_norequest:
	xor	eax, eax
	pop	r14 r13 rbx
	epilog
if webserver_breach_mitigation
cleartext .xnb, 'X-NB'
end if
if webserver_hsts
cleartext .hsts, 'Strict-Transport-Security'
cleartext .hstsvalue, 'max-age=31536000; includeSubDomains'
end if
calign
.senduntilpartial:
	; so we know that r13+xmitbody is the buffer we are actually sending
	mov	rax, [r13+mimelike_xmitbody_ofs]
	mov	qword [rbx+webserver_inflightcb_ofs], buffer$destroy
	mov	[rbx+webserver_inflightcbarg_ofs], rax
	; so now, set inflight and inflightlen to rsi, rdx
	mov	[rbx+webserver_inflight_ofs], rsi
	mov	[rbx+webserver_inflightlen_ofs], rdx
	; the dword at r9 is our actual object length, not our send length
	; but r8 is the one we need to set inflightsent to _negative_
	sub	[rbx+webserver_inflightsent_ofs], r8
	; modify our inflight/len pointers by webserver_initialsend
	add	qword [rbx+webserver_inflight_ofs], webserver_initialsend
	sub	qword [rbx+webserver_inflightlen_ofs], webserver_initialsend
	add	qword [rbx+webserver_inflightsent_ofs], webserver_initialsend
	push	rdi rsi rcx
	; create a new buffer for mimelike
	call	buffer$new
	mov	[r13+mimelike_xmitbody_ofs], rax
	; now we can destroy the response
	mov	rdi, r13
	call	mimelike$destroy
	pop	rcx rsi rdi
	mov	edx, webserver_initialsend
	; go ahead and send out the first bit
	call	qword [rcx+io_vsend]
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.zeroret
calign
.senduntilpartial_loop:
	; otherwise, keep going
	mov	eax, webserver_subsequentsend
	mov	rdi, rbx
	mov	rcx, [rbx]
	mov	rsi, [rbx+webserver_inflight_ofs]
	mov	rdx, [rbx+webserver_inflightlen_ofs]
	cmp	rdx, rax
	cmova	rdx, rax
	add	[rbx+webserver_inflight_ofs], rdx
	sub	[rbx+webserver_inflightlen_ofs], rdx
	add	[rbx+webserver_inflightsent_ofs], rdx
	call	qword [rcx+io_vsend]
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.zeroret
	cmp	qword [rbx+webserver_inflightlen_ofs], 0
	jne	.senduntilpartial_loop
	; so if we made it to here, we sent everything out without a partial send
	; (which _is_ possible depending on the underlying transport and our settings)
	; first up, clear all inflight goods
	mov	qword [rbx+webserver_inflight_ofs], 0
	mov	qword [rbx+webserver_inflightcb_ofs], 0
	mov	rdi, [rbx+webserver_inflightcbarg_ofs]
	mov	qword [rbx+webserver_inflightcbarg_ofs], 0
	call	buffer$destroy
	; now our logging exercise:
	mov	rdi, rbx
	mov	rsi, [rbx+webserver_inflightsent_ofs]
	call	webserver$log
	; if the connection should be closed (flag & 1 == 0), we return 1
	test	dword [rbx+webserver_flags_ofs], 1
	jnz	.zeroret_complete

	; cleanup the outstanding request object
	cmp	qword [rbx+webserver_request_ofs], 0
	je	.oneret_norequest
	mov	rdi, [rbx+webserver_request_ofs]
	mov	qword [rbx+webserver_request_ofs], 0
	call	mimelike$destroy

	mov	eax, 1
	pop	r14 r13 rbx
	epilog
calign
.sendinsegments:
	; > webserver_bigfile, so we handle these a bit differently to avoid
	; double buffering the file itself
	; we need to know which body is in use, bodyext or the body buffer
	mov	rcx, [r13+mimelike_body_ofs]
	mov	rdx, [r13+mimelike_bodyext_ofs]
	mov	rax, [r13+mimelike_bodyextlen_ofs]
	mov	r8, [rcx+buffer_itself_ofs]
	mov	r9, [rcx+buffer_length_ofs]
	test	r9, r9
	jnz	.sendinsegments_bodybuffer
	; otherwise, it is bodyext we are sending (and if we were done from the file based handler,
	; then inflightcb and inflightcbarg are already set
	mov	[rbx+webserver_inflight_ofs], rdx
	mov	[rbx+webserver_inflightlen_ofs], rax
	; clear the bodyext pointers in the response buffer itself
	mov	qword [r13+mimelike_bodyext_ofs], 0
	mov	qword [r13+mimelike_bodyextlen_ofs], 0

	jmp	.sendinsegments_ready
calign
.sendinsegments_bodybuffer:
	; see notes above, but we set/use inflightcb to do our cleanup of the real
	; transmit body, unlike external above which is caller-specified
	mov	[rbx+webserver_inflight_ofs], r8
	mov	[rbx+webserver_inflightlen_ofs], r9
	mov	qword [rbx+webserver_inflightcb_ofs], buffer$destroy
	mov	[rbx+webserver_inflightcbarg_ofs], rcx
	; so now, we need to "unhook" the buffer that is actually the mimelike body
	; with a brand new empty one (so that its destroy still works properly)
	call	buffer$new
	mov	[r13+mimelike_body_ofs], rax
calign
.sendinsegments_ready:
	; first things first, we have to set the content length header, because
	; mimelike$compose, with no body, leaves the headers untouched/as-is
	mov	qword [rbx+webserver_inflightsent_ofs], 0
	mov	rdi, [rbx+webserver_inflightlen_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, r13
	mov	rsi, mimelike$contentlength
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy
	; clear the sentpartial flag just ins
	mov	dword [rbx+webserver_sentpartial_ofs], 0
	; our response object body should be clear, which means compose will only compose the headers and preface
	mov	rdi, r13
	call	mimelike$compose
	; so now, we have to do two separate sends, one for the response object's xmitbody
	; and one for our first "inflight chunk"

if webserverdebug
	mov	rcx, [r13+mimelike_xmitbody_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [r13+mimelike_hdrlen_ofs]
	syscall
end if

	mov	rcx, [r13+mimelike_xmitbody_ofs]
	mov	rdx, [r13+mimelike_hdrlen_ofs]
	mov	rdi, rbx
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	; so now we are done with our response object
	mov	rdi, r13
	call	mimelike$destroy

	; so now, we have our inflight goods all ready to roll, send until we get a partial (or we send it all out)
	; (which, depending on transport layer and our settings, is certainly possible)
	; send our first inflight chunk (we don't need to check for length)
	if webserver_initialsend >= webserver_bigfile
		display 'webserver_initialsend must be < webserver_bigfile',10
		err
	end if

	mov	rdi, rbx
	mov	edx, webserver_initialsend
	mov	rsi, [rbx+webserver_inflight_ofs]
	mov	rcx, [rdi]
	sub	[rbx+webserver_inflightlen_ofs], rdx
	add	[rbx+webserver_inflight_ofs], rdx
	add	[rbx+webserver_inflightsent_ofs], rdx
	call	qword [rcx+io_vsend]
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.zeroret
calign
.sendinsegments_loop:
	; otherwise, keep going until we get a partial send, or until we run out of data
	mov	eax, webserver_subsequentsend
	mov	rdi, rbx
	mov	rcx, [rbx]
	mov	rsi, [rbx+webserver_inflight_ofs]
	mov	rdx, [rbx+webserver_inflightlen_ofs]
	cmp	rdx, rax
	cmova	rdx, rax
	add	[rbx+webserver_inflight_ofs], rdx
	sub	[rbx+webserver_inflightlen_ofs], rdx
	add	[rbx+webserver_inflightsent_ofs], rdx
	call	qword [rcx+io_vsend]
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.zeroret
	cmp	qword [rbx+webserver_inflightlen_ofs], 0
	jne	.sendinsegments_loop
	; if we made it to here without ever hitting a partial send
	; then it is time to finish up our actions
	mov	rdi, rbx
	mov	rsi, [rbx+webserver_inflightsent_ofs]
	call	webserver$log
	; clear our inflight buffer ptr
	mov	qword [rbx+webserver_inflight_ofs], 0
	; deal with our inflightcb if one exists:
	cmp	qword [rbx+webserver_inflightcb_ofs], 0
	je	.sendinsegments_finish_nocb
	mov	rdi, [rbx+webserver_inflightcbarg_ofs]
	call	qword [rbx+webserver_inflightcb_ofs]
	; clear them
	mov	qword [rbx+webserver_inflightcb_ofs], 0
	mov	qword [rbx+webserver_inflightcbarg_ofs], 0
calign
.sendinsegments_finish_nocb:
	; if the connection should be closed (flags & 1 == 0), we return 1
	test	dword [rbx+webserver_flags_ofs], 1
	jnz	.zeroret_complete

	; cleanup the outstanding request object
	cmp	qword [rbx+webserver_request_ofs], 0
	je	.oneret_norequest
	mov	rdi, [rbx+webserver_request_ofs]
	mov	qword [rbx+webserver_request_ofs], 0
	call	mimelike$destroy

	mov	eax, 1
	pop	r14 r13 rbx
	epilog
calign
.zeroret:
	xor	eax, eax
	pop	r14 r13 rbx
	epilog
cleartext .closestr, 'close'
cleartext .keepalivestr, 'keep-alive'
cleartext .serverstr, 'Server'
cleartext .ident, 'HeavyThing'
cleartext .datestr, 'Date'

end if


if used webserver$init | defined include_everything
	; no arguments, called from ht$init to initialize our webserver dateformat, log and errorlog formatter objects
falign
webserver$init:
	prolog	webserver$init
	xor	edi, edi
	call	formatter$new
	mov	[webserver$dateformat], rax
	mov	rdi, rax
	call	formatter$add_rfc5322datetime
	mov	edi, 1
	call	formatter$new
	mov	[webserver$logformat], rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [webserver$logformat]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [webserver$logformat]
	mov	rsi, .nouserident
	call	formatter$add_static
	mov	rdi, [webserver$logformat]
	mov	esi, 1
	call	formatter$add_datetime
	mov	rdi, [webserver$logformat]
	xor	esi, esi
	call	formatter$add_quotedstring
	mov	rdi, [webserver$logformat]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [webserver$logformat]
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [webserver$logformat]
	xor	esi, esi
	call	formatter$add_quotedstring
	mov	rdi, [webserver$logformat]
	xor	esi, esi
	call	formatter$add_quotedstring
	mov	edi, 1
	call	formatter$new
	mov	[webserver$errorformat], rax
	mov	rdi, rax
	mov	esi, 1
	call	formatter$add_datetime
	mov	rdi, [webserver$errorformat]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [webserver$errorformat]
	xor	esi, esi
	call	formatter$add_quotedstring

	xor	edi, edi
	call	formatter$new
	mov	[webservercfg$lognameformat], rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [webservercfg$lognameformat]
	call	formatter$add_yyyymmdd

	; so, our normal log format is:
	; string Host
	; string IP
	; double current time
	; string request preface
	; unsigned response code
	; unsigned object length
	; string referer
	; string user agent

	; and our error log format is:
	; double current time
	; string IP
	; string error message
	epilog
cleartext .nouserident, '- -'

end if


if used webserver$newtimer | defined include_everything
	; single argument in rdi: our webserver object
	; if one of your handlers returns -1 (and thus the webserver handler just sits there)
	; then whenever you are done and have responded, you _should_ call this to make sure
	; that the connection ends up being terminated after 30 seconds of no request arrival
falign
webserver$newtimer:
	prolog	webserver$newtimer
	cmp	qword [rdi+webserver_timer_ofs], 0
	jne	.doreset
	push	rdi
	mov	rsi, rdi
	mov	edi, 30000
	call	epoll$timer_new
	pop	rdi
	mov	[rdi+webserver_timer_ofs], rax
if webservertimerdebug
	push	rdi
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debugnew
	call	string$to_stdout
	mov	rdx, [rsp]
	mov	esi, 16
	mov	rdi, [rdx+webserver_timer_ofs]
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdi
end if
	epilog
calign
.doreset:
if webservertimerdebug
	push	rdi
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debugreset
	call	string$to_stdout
	mov	rdx, [rsp]
	mov	esi, 16
	mov	rdi, [rdx+webserver_timer_ofs]
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdi
end if
	mov	rdi, [rdi+webserver_timer_ofs]
	call	epoll$timer_reset
	epilog
if webservertimerdebug
cleartext .debug1, 'webserver$newtimer, we are: '
cleartext .debugnew, ' new timer at: '
cleartext .debugreset, ' resetting timer at: '
end if

end if


if used webserver$cleartimer | defined include_everything
	; single argument in rdi: our webserver object
	; if there is a timer object, we blast it
falign
webserver$cleartimer:
	prolog	webserver$cleartimer
	cmp	qword [rdi+webserver_timer_ofs], 0
	je	.nothingtodo
if webservertimerdebug
	push	rdi
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debugclear
	call	string$to_stdout
	mov	rdx, [rsp]
	mov	esi, 16
	mov	rdi, [rdx+webserver_timer_ofs]
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdi
end if
	mov	rsi, rdi
	mov	rdi, [rdi+webserver_timer_ofs]
	mov	qword [rsi+webserver_timer_ofs], 0
	call	epoll$timer_clear
	epilog
calign
.nothingtodo:
if webservertimerdebug
	push	rdi
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debugnada
	call	string$to_stdoutln
	pop	rdi
end if
	epilog

if webservertimerdebug
cleartext .debug1, 'webserver$cleartimer, we are: '
cleartext .debugclear, ' clearing timer at: '
cleartext .debugnada, ' no timer object to clear.'
end if

end if



if used webserver$receive | defined include_everything
	; three arguments: rdi == our webserver object, rsi == ptr to data, rdx == length of same
falign
webserver$receive:
	prolog	webserver$receive
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+webserver_accum_ofs]
	call	buffer$append
	mov	dword [rbx+webserver_needmore_ofs], 0
	mov	rdi, rbx
	call	webserver$check_accum
	cmp	dword [rbx+webserver_needmore_ofs], 0
	jne	.loopdone
	test	eax, eax
	jz	.loop
	; NOTE: check_accum's return will be our return
	pop	rbx
	epilog
calign
.loop:
	cmp	qword [rbx+webserver_request_ofs], 0
	jne	.loopdone
	; if there is < 16 bytes in the accum, also return
	mov	rsi, [rbx+webserver_accum_ofs]
	cmp	qword [rsi+buffer_length_ofs], 16
	jb	.loopdone
	; otherwise, recall check_accum again
	mov	dword [rbx+webserver_needmore_ofs], 0
	mov	rdi, rbx
	call	webserver$check_accum
	cmp	dword [rbx+webserver_needmore_ofs], 0
	jne	.loopdone
	test	eax, eax
	jz	.loop
	pop	rbx
	epilog
calign
.loopdone:
	pop	rbx
	epilog

end if



	
if used webserver$check_accum | defined include_everything
	; single argument in rdi: our webserver object
	; NOTE: this is called from sendresponse, as well as the above receive so that we can do pipelining safely
	; we return in accordance with the epoll$receive goods, 0 == stay happy, 1 == death on a stick
falign
webserver$check_accum:
	prolog	webserver$check_accum
	; if we are already servicing a request, don't do anything
	cmp	qword [rdi+webserver_request_ofs], 0
	jne	.busy
	push	rbx
	mov	rbx, rdi
	; rather than perpetually call mimelike$new_parse to determine whether we have a complete
	; request, the most common case is a normal request, so quickly scan our buffer for a header
	; before we bother with parsing and error discovery
	mov	rdi, [rdi+webserver_accum_ofs]
	mov	ecx, webserver_maxheader		; the maximum size we'll allow for a request header
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	mov	r8, rsi
	cmp	rdx, rcx
	cmova	rdx, rcx
	cmp	rdx, 16
	jb	.needmore
calign
.headerscan:
	cmp	edx, 4
	jb	.headerscan_lessthanfourleft
	cmp	dword [rsi], 0xa0d0a0d
	je	.headerfound
	cmp	edx, 2
	jb	.headerscan_nodeal
	cmp	word [rsi], 0xa0a
	je	.headerfound
	add	rsi, 1
	sub	edx, 1
	jnz	.headerscan
calign
.headerscan_nodeal:
	; if we made it to here, check the length overall
	cmp	[rdi+buffer_length_ofs], rcx
	jae	.bloatedheader
	jmp	.needmore
calign
.headerscan_lessthanfourleft:
	cmp	word [rsi], 0xa0a
	je	.headerfound
	add	rsi, 1
	sub	edx, 1
	jz	.headerscan_nodeal
	cmp	word [rsi] ,0xa0a
	je	.headerfound
	jmp	.headerscan_nodeal
cleartext .hoststr, 'Host'
calign
.headerfound:
	; temporarily set our requestlen to however far we made it
	mov	r9, rsi
	sub	r9, r8
	mov	r10, r9
	add	r10, 4
	add	r9, 2
	cmp	word [rsi], 0xa0d
	cmove	r9, r10
	mov	[rbx+webserver_requestlen_ofs], r9

	; sanity only: remove me
	cmp	qword [rbx+webserver_fcgihooked_ofs], 0
	jne	.badclient
	cmp	qword [rbx+webserver_inflight_ofs], 0
	jne	.badclient
	; end sanity only
	; the beginning of our request must of course be one of: 
	; GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
	; we are only interested in the first three however
	cmp	dword [r8], 'GET '
	je	.headerproceed
	cmp	dword [r8], 'HEAD'
	je	.headerproceed
	cmp	dword [r8], 'POST'
	je	.headerproceed_post
	; otherwise, puke a 501 Not Implemented
	mov	edi, 501
	jmp	.do_error_nostack
calign
.badclient:
	mov	edi, 400
	jmp	.do_error_nostack
if webserverdebug
cleartext .debugbusy, 'webserver$check_accum, busy!'
end if
calign
.busy:
	; we are already servicing a request, so jsut return 0 and be done
if webserverdebug
	mov	rdi, .debugbusy
	call	string$to_stdoutln
end if
	xor	eax, eax
	epilog
calign
.headerproceed:
	; go ahead and use our entire buffer length for mimelike$new_parse

if webserverdebug
	push	rdi r8
	mov	eax, syscall_write
	mov	rsi, r8
	mov	rdx, [rdi+buffer_length_ofs]
	mov	edi, 1
	syscall
	pop	r8 rdi
end if

	mov	rsi, [rdi+buffer_length_ofs]
	mov	rdi, r8
	mov	edx, 1			; headers only please
	mov	ecx, 1			; preface aka start line exists
	call	mimelike$new_parse
	; this _must_ succeed, unlike POST where we'll hang out until it does
	mov	edi, 400
	test	rax, rax
	jz	.do_error_nostack
calign
.handlerequest:
	mov	rcx, [rax+mimelike_parselen_ofs]
	; there can be no previous request object, so all we have to do is set it
	mov	[rbx+webserver_request_ofs], rax
	cmp	qword [rax+mimelike_preface_ofs], 0
	je	.rejectrequest
	mov	[rbx+webserver_requestlen_ofs], rcx
	; first things first, use the mimelike_user_ofs to store the request method
	mov	rdi, [rbx+webserver_accum_ofs]
	xor	ecx, ecx
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	edx, 1
	mov	r8d, 2
	mov	r9d, 4
	mov	r10d, 5
	cmp	dword [rsi], 'HEAD'
	cmove	ecx, edx
	cmove	r9d, r10d
	cmp	dword [rsi], 'POST'
	cmove	ecx, r8d
	cmove	r9d, r10d
	mov	[rax+mimelike_user_ofs], ecx
	; next up: we need to parse the preface to construct our fully formed URL and

	; so [rsi+r9] == start of the url request, we need to walk forward from there until we find a space (or worse, CR/LF)
	lea	rdi, [rsi+r9]
	xor	esi, esi
	mov	edx, 1
calign
.handlerequest_parsepreface:
	movzx	ecx, byte [rdi+rsi]
	cmp	ecx, 32
	je	.handlerequest_parsepreface_done
	cmp	ecx, 13
	je	.fail_preface
	cmp	ecx, 10
	je	.fail_preface
	add	esi, 1
	add	edx, 1
	jmp	.handlerequest_parsepreface
calign
.handlerequest_parsepreface_done:
	test	esi, esi
	jz	.fail_preface
	; so, rdi + esi are all setup for a string$from_utf8 to construct our url portion
	mov	ecx, [rdi+rdx+4]
	cmp	dword [rdi+rdx], 'HTTP'
	jne	.fail_httpversion
	mov	r8d, ecx
	and	ecx, 0x00ffffff
	cmp	ecx, '/1.'
	jne	.fail_httpversion
	shr	r8d, 24
	cmp	r8d, '0'
	jb	.fail_httpversion
	cmp	r8d, '1'
	ja	.fail_httpversion
	sub	r8d, '0'
	; rax is still pointing to our request object
	mov	dword [rax+mimelike_user_ofs+4], r8d
	; so now we can construct our url path portion
	call	string$from_utf8
	push	rax
	; we need to check to see whether it is a fully formed URL or not
	xor	edi, edi
	mov	rsi, rax
	call	url$new
	test	rax, rax
	jnz	.fullyqualifiedrequest
	; failing that, if the request string doesn't start with a /, puke a 400
	mov	rdi, [rsp]
	cmp	qword [rdi], 0
	je	.badrequeststring
if string_bits = 32
	cmp	dword [rdi+8], '/'
else
	cmp	word [rdi+8], '/'
end if
	jne	.badrequeststring
	; otherwise, looking good so far, now its time to construct our request URL
	; the request _must_ contain a Host header so we can construct our url
	mov	rdi, [rbx+webserver_request_ofs]
	mov	rsi, .hoststr
	call	mimelike$getheader
	test	rax, rax
	jz	.badrequeststring
	; ultimately it needs to be lowercased
	mov	rdi, rax
	call	string$to_lower
	push	rax
	; so now, depending on whether webserver_istls_ofs is set or not, depends on how we construct our fully qualified URL
	mov	rcx, [rbx+webserver_config_ofs]
	mov	rdi, .httpcolonslashslash
	mov	rsi, .httpscolonslashslash
	cmp	dword [rcx+webservercfg_istls_ofs], 0
	cmovne	rdi, rsi
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	; so now we have http://hostname
	; hmmm, TODO: should we add a :port to the authority section if it is nonstandard?
	; we really aren't making use of the full URL comparison, other than to make it easier later
	; to parse/deal with path munging, etc... hmmm, scratch myself some more about this later
	; next up is to concat our request string to that
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	call	string$concat
	mov	rdi, [rsp+8]
	mov	[rsp+8], rax
	call	heap$free
	pop	rdi
	call	heap$free
	; so now, we have a full request url string in [rsp], and our mimelike object at [rbx+webserver_request_ofs]
	xor	edi, edi
	mov	rsi, [rsp]
	call	url$new
	test	rax, rax
	jz	.badrequeststring
	mov	rdi, [rsp]
	mov	[rsp], rax		; the url object
	call	heap$free

	; so now, [rsp] == url object, [rbx+webserver_request_ofs] == mimelike request object
	; fallthrough to processrequest
calign
.processrequest:
	; [rsp] == url object, [rbx+webserver_request_ofs] == mimelike request object
	; proceed with normal handling...

	; first up, clear our waiting for a request timer:
	mov	rdi, rbx
	call	webserver$cleartimer

	; determine our response parameters before we proceed
	; flags:
	; 0x1 == our reply will be Connection: keep-alive, or if bit 1 not set, close
	; 0x2 == whether to gzip our output
	; 0x4 == whether to chunk our output
	
	mov	dword [rbx+webserver_flags_ofs], 1		; default to keep-alive
	mov	rdi, [rbx+webserver_request_ofs]
	mov	rsi, .connectionstr
	call	mimelike$getheader
	test	rax, rax
	jz	.noconnectionheader
	mov	rdi, rax
	mov	rsi, .closestr
	call	string$starts_with
	xor	ecx, ecx
	mov	edx, 1
	test	eax, eax
	cmovnz	edx, ecx
	mov	dword [rbx+webserver_flags_ofs], edx		; if Connection: close, no deal
	jmp	.processrequest_checkgzip
cleartext .connectionstr, 'Connection'
cleartext .closestr, 'close'
cleartext .gzipstr, 'gzip'
cleartext .acceptencoding, 'Accept-Encoding'
calign
.noconnectionheader:
	mov	rdi, [rbx+webserver_request_ofs]
	xor	ecx, ecx
	mov	edx, 1
	cmp	dword [rdi+mimelike_user_ofs+4], 0
	cmovne	ecx, edx
	mov	dword [rbx+webserver_flags_ofs], ecx		; if HTTP/1.0, default to close it
calign
.processrequest_checkgzip:
	mov	rdi, [rbx+webserver_request_ofs]
	mov	rsi, .acceptencoding
	call	mimelike$getheader
	test	rax, rax
	jz	.processrequest_doit
	mov	rdi, rax
	mov	rsi, .gzipstr
	call	string$indexof
	cmp	rax, 0
	jl	.processrequest_doit
	or	dword [rbx+webserver_flags_ofs], 2		; enable gzip on output
calign
.processrequest_doit:
	; one more flag to set, and that is whether to consider chunked encoding
	xor	ecx, ecx
	mov	edx, 4
	mov	rdi, [rbx+webserver_request_ofs]
	cmp	dword [rdi+mimelike_user_ofs+4], 0
	cmovne	ecx, edx
	or	dword [rbx+webserver_flags_ofs], ecx		; go ahead and set chunked headers on reply

	; first, pass these off to our vrequest method, as this allows for "request URL rewriting" prior to
	; the normal webservercfg handlers dealing with it
	mov	rdi, rbx
	mov	rsi, [rsp]
	mov	rdx, [rbx+webserver_request_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+webserver_vrequest]
	; if we got a -1, consume all of our accum buffer, and silently bailout without doing anything else
	cmp	rax, -1
	je	.request_donothing
	; if we got a null, proceed to webservercfg handling
	; anything else == it must be a mimelike response object, so send it down the line and reset our accum
	test	rax, rax
	jnz	.request_doresponse
	; let the webservercfg object come up with a return for us
	mov	rdi, [rbx+webserver_config_ofs]
	mov	rsi, rbx
	mov	rdx, [rsp]
	mov	rcx, [rbx+webserver_request_ofs]
	call	webservercfg$handler
	; similar story here, if we got a -1, consume all of our accum buffer and bailout
	cmp	rax, -1
	je	.request_donothing
	; if we got a null, fire back a 404
	test	rax, rax
	jnz	.request_doresponse
	; otherwise, fire off a 404 properly
	mov	esi, 404
	mov	rdi, [rbx+webserver_config_ofs]
	call	webservercfg$error
	; fallthrough to request_doresponse
calign
.request_doresponse:
	; rax == mimelike response object, [rsp] == url object, [rbx+webserver_request_ofs] == mimelike request object
	mov	r8, [rbx+webserver_request_ofs]
	; sendresponse will destroy the response object, but not the URL

	mov	rdi, rbx
	mov	rsi, rax			; the response object
	mov	edx, [r8+mimelike_user_ofs]	; GET, HEAD, POST (0, 1, 2) (so it knows whether to include the body or not)
	call	webserver$sendresponse

	mov	rdi, [rsp]
	mov	[rsp], rax			; the return from sendresponse
	call	url$destroy
	; we do not destroy the mimelike request object so that the logging mechanism can extract data from it

	mov	rdi, [rbx+webserver_accum_ofs]
	mov	rsi, [rbx+webserver_requestlen_ofs]
	test	rsi, rsi
	jz	.request_doresponse_fullreset
	call	buffer$consume

	; start up a new request timer, but only if sentpartial is 0
	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.request_doresponse_nonewtimer

	mov	rdi, rbx
	call	webserver$newtimer
calign
.request_doresponse_nonewtimer:
	; let its return be our return (0 == no death, 1 == death)
	pop	rax
	pop	rbx
	epilog
calign
.request_doresponse_fullreset:
	call	buffer$reset

	cmp	dword [rbx+webserver_sentpartial_ofs], 0
	jne	.request_doresponse_nonewtimer
	mov	rdi, rbx
	call	webserver$newtimer
	jmp	.request_doresponse_nonewtimer
calign
.do_error_nostack:
	; edi == error code, stack is clear
	mov	esi, edi
	mov	rdi, [rbx+webserver_config_ofs]
	call	webservercfg$error

	mov	rdi, rbx
	mov	rsi, rax			; the response object
	xor	edx, edx			; GET/HEAD/POST error reply we don't care much
	call	webserver$sendresponse
	push	rax

	; consume from our accumulator
	mov	rdi, [rbx+webserver_accum_ofs]
	mov	rsi, [rbx+webserver_requestlen_ofs]
	test	rsi, rsi
	jz	.do_error_nostack_fullreset
	call	buffer$consume

	; start up a new request timer
	mov	rdi, rbx
	call	webserver$newtimer

	pop	rax
	pop	rbx
	epilog
calign
.do_error_nostack_fullreset:
	call	buffer$reset
	
	; start up a new request timer
	mov	rdi, rbx
	call	webserver$newtimer

	pop	rax
	pop	rbx
	epilog
calign
.request_donothing:
	mov	rdi, [rbx+webserver_accum_ofs]
	mov	rsi, [rbx+webserver_requestlen_ofs]
	test	rsi, rsi
	jz	.request_donothing_fullreset
	call	buffer$consume

	; NOTE: we do _not_ startup a new timer here, up to the implementation that decided to return -1
	; to deal with that.

	; free our url
	pop	rdi
	call	url$destroy
	xor	eax, eax		; don't kill us off
	pop	rbx
	epilog
calign
.request_donothing_fullreset:
	call	buffer$reset
	; free our url
	pop	rdi
	call	url$destroy
	xor	eax, eax		; don't kill us off
	pop	rbx
	epilog
calign
.fullyqualifiedrequest:
	mov	rdi, [rsp]
	mov	[rsp], rax		; the url object
	call	heap$free
	; so now, [rsp] == url object, [rbx+webserver_request_ofs] == mimelike object
	jmp	.processrequest
cleartext .httpslashonedot, 'HTTP/1.'
cleartext .host, 'Host'
cleartext .httpcolonslashslash, 'http://'
cleartext .httpscolonslashslash, 'https://'
calign
.badrequeststring:
	; [rsp] == request string
	; and then fire off a 400 bad request
	pop	rdi
	call	heap$free
	mov	edi, 400
	jmp	.do_error_nostack
calign
.fail_httpversion:
	mov	edi, 505
	jmp	.do_error_nostack
calign
.fail_preface:
	mov	edi, 400
	jmp	.do_error_nostack
calign
.rejectrequest:
	; 400 bad request
	mov	edi, 400
	jmp	.do_error_nostack
calign
.headerproceed_post:
	mov	rsi, [rdi+buffer_length_ofs]
	mov	rdi, r8
	xor	edx, edx		; complete request required
	mov	ecx, 1			; preface aka start line exists
	call	mimelike$new_parse
	; if that didn't succeed, we most likely need more data
	test	rax, rax
	jz	.needmore_maxrequestcheck
	jmp	.handlerequest
calign
.bloatedheader:
	; as opposed to returning an error here, drop the connection
	; the spec of course says we should return a properly formed error, but
	; since we didn't even find the end of the header inside our limit
	; it is likely malformed/garbage anyway, so silent death here on purpose
	mov	eax, 1				; silent suicide please
	pop	rbx
	epilog
calign
.needmore_maxrequestcheck:
	; make sure we haven't accumulated more than our max, or die
	; (this prevents memory starvation attacks)
	; webserver_maxrequest
	mov	rdi, [rbx+webserver_accum_ofs]
	cmp	qword [rdi+buffer_length_ofs], webserver_maxrequest
	ja	.bloatedheader			; will drop us just the same
calign
.needmore:
	mov	dword [rbx+webserver_needmore_ofs], 1
	xor	eax, eax			; don't kill us off
	pop	rbx
	epilog

end if


if used webserver$timeout | defined include_everything
	; single argument in rdi == our webserver object
falign
webserver$timeout:
	prolog	webserver$timeout
	; when our destruct comes in, we need to know the origin of the destruction
	; came from here (because the epoll layer will cleanup our timer for us, but
	; otherwise, we'll need to manage cleaning it up ourselves)
	push	rdi
if webservertimerdebug
	mov	rdi, .debug1
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .debug2
	call	string$to_stdout
	mov	rdx, [rsp]
	mov	esi, 16
	mov	rdi, [rdx+webserver_timer_ofs]
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, [rsp]
end if

	call	tls$closenotify
	pop	rdi
	mov	dword [rdi+webserver_timedout_ofs], 1
	mov	eax, 1			; suicide please
	epilog
if webservertimerdebug
cleartext .debug1, 'webserver$timeout, we are at: '
cleartext .debug2, ' timer is at: '
end if

end if


if used webserver$request | defined include_everything
	; three arguments: rdi == our webserver object, rsi == request url, rdx == mimelike object of the request
	; NOTE: default implementation here doesn't do anything (which will let the webservercfg layer handle it)
falign
webserver$request:
	prolog	webserver$request
	xor	eax, eax
	epilog

end if
