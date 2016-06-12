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
	; ht_defaults.inc: global settings that determine how the library gets built.
	;
	; we are the first include, set our fasm format
	;
	format ELF64
	;
	; SETTINGS, which directly affect which bits of our basket get actually assembled
	; some are dependent on others of course...
	;

	; some things, such as mapped, need to know what our system page size is
	page_size = 4096

	; align functions?
	align_functions = 1

	; align returns? (translates call into push aligned after call and jmp)
	align_returns = 0

	; align call returns? (does multibyte NOP fill _before_ the call to pad the return address out to 16 byte alignment)
	align_callreturns = 0

	; align inner jump targets?
	align_inner = 1

	; align tables/static text/jump tables? 
	align_data = 1

	; the actual alignment for either
	function_alignment = 16
	inner_alignment = 16
	data_alignment = 16

	; generate framepointers? (we like gdb)
	framepointers = 1

	; should we make public symbols for our functions?
	public_funcs = 1

	; enable automatic profiling in clocks/calls/callgraph?
	profiling = 0

	; preload (barbarically) the code? (does a once-over read of all of it)
	code_preload = 1

	if profiling
		; the CPC field for the profiler output can be floating point
		; or integer based... floating point requires string_math goodies
		; which in turn create a very large number of nested function calls
		; for most purposes, integer based is fine and dandy
		cpc_integers = 1

		; how large the profiler record size has to be, depending on your call graph, depends on how large this needs to be
		profiler_recordcount = 16384
	end if

	; if profiling = 0, and this is enabled, every function that begins with a prolog statement will dump its function name to stdout when called
	calltracing = 0

	; enable bin checking during free? (adds overhead, but useful for picking up errant memory corruption)
	heap_bincheck = 0

	; enable heap barrier/validity checking? setting this to 1 causes an extra 8 byte preface that is checked for validity and breakpoints if not
	; during alloc/free of non-mmap blocks
	heap_barriers = 0

	; if this is defined (whether set to 1 or not), then instead of only
	; functions being included that are used, EVERYTHING ends up in the resultant
	; binary...
	; include_everything = 1

	; rng uses simple 32bit rdtsc seed if 0, or uses HMAC_DRBG to do up its initial state
	rng_heavy_init = 1

	; by default, the initial seed is in part pulled from /dev/urandom. If this setting is enabled,
	; we pull 32 bytes from /dev/random instead (which may stall). Default is 0
	rng_paranoid = 0


	; native string in UTF16 or UTF32?
	; NOTE: some tui components require UTF32
	string_bits = 32

	; extended utf16 case modifies? (see commentary in unicodecase.inc)
	extendedcase = 0

	; utf strict adherence? (relaxed, aka 0 is probably what you want)
	; that being said, it is nice to also be able to validate utf.. your choice
	strict_utf = 0

	; if you use string$from_bintobase64, these settings affect its encoding (as well as base64$encode_latin1)
	base64_linebreaks = 1
	base64_maxline = 76

	; for library functions, if this is enabled, uses movbe rather than bswap + separate mov
	; Haswell or better CPU and this is a good thing.
	use_movbe = 0

	; epoll specific settings:

	; NOTE: it is _highly_ recommended that you lower the linux default of 15 to 8 for this kernel setting:
	; echo 8 >/proc/sys/net/ipv4/tcp_retries2
	; the default of 15 means that if a connection "vanishes" (think: lappy going to sleep), then
	; we hold/maintain/accumulate output for that connection for a full 13 minutes, and that is insane!
	; 8 == ~3 minutes or so, which seems to be a good value "in the middle"... spose in the end it depends
	; on your application/what you are trying to achieve

	; on init, we do a getrlimit/setrlimit, the minfds here lists the minimum # required to proceed, or we error and die
	epoll_minfds = 4096

	; do we call accept4 repeatedly, or do we let the level-triggered action deal with that
	epoll_multiple_accepts = 1

	; default socket options:
	epoll_keepalive = 1
	epoll_linger = 0
	epoll_nodelay = 1

	; docs say "new programs should use fcntl to set nonblocking", but that requires two separate syscalls
	; so, for busy systems, by default we use the old-school method of ioctl(fd, FIONBIO, 1)
	epoll_fionbio = 1

	; if epoll_linger is on, this is the linger timeout:
	epoll_linger_time = 30

	; the "maxevents" count that we stack-allocate on our calls to epoll_wait (* 12 for bytes)
	; default: epoll_stacksize = 4096
	epoll_stacksize = 16384

	; the default read block size (each connection reserves this much, then calls read,
	; so if you have many many connections, this size factors into overall memory usage)
	; default: epoll_readsize = 32768
	epoll_readsize = 4096

	; issue a EPOLL_CTL_DEL before closing the fd on cleanup?
	; epoll does interesting things across/before/after forks to say the least...
	; specifically, if a parent process fires up the epoll layer, does some outbound connections
	; that end up pending, then forks, even though we set CLOEXEC for the outbound sockets
	; the fds don't get properly terminated from the epoll fd in the parent process, weird imo.
	; by leaving this here, forces the epoll_ctl deletion prior to doing the close(fd) call.
	epoll_del_before_close = 0

	; set CLOEXEC flag for epoll$outbound sockets?
	epoll_outbound_cloexec = 0

	; unix connect "evil trickery":
	; Ok so, some commentary here re: the basic idea/issue/premise... For outbound socket connects to a
	; unix stream socket, it is quite possible to receive an EAGAIN from the connect syscall, indicating
	; that the other end's listen backlog is exhausted and that we should "try again later". Linux defaults
	; the kernel upper limit of this setting to 128, which is fine in most cases, but there are lots of
	; scenarios where this is less than ideal, and it seems silly to force the condition back on the user
	; of this library, rather than allow the library to deal with it.
	; So, _if_ this setting is enabled, and epoll$outbound is used, and connect returns EAGAIN, then
	; we insert the epoll object and a memcpy of the destination address into an insert-order map.
	; We do _not_ do this timer-based, so it is assumed that when this condition arises, that the epoll
	; layer is quite busy anyway, so we don't need to postpone/delay, and calls to unix stream socket
	; connects are quite fast. Of course, there are ways to break this method entirely, but for my use
	; cases, this works well. Specifically, we service the "try unix connect again" queue _before_ we
	; process the next round of epoll_wait/epoll$iteration, and what this means is that the connects
	; will ultimately be serviced in the order they arrived to begin with, and subsequent connects don't
	; get to run _before_ we do the ones already in the queue (e.g. new ones that arrive get put at the
	; back of the queue, where they should be). Some common sense obviously applies as to whether this
	; strategy really does make sense or not, but it means that application layer uses for this epoll
	; layer don't have to worry about it, it _will_ let it through when the far endpoint's queue comes
	; good. Our default here is to apply this queueing strategy. CAUTION: It is _very_ important that
	; you don't end up deleting an epoll object (unrelated epoll object that is) during a connected
	; handler, because then it is possible that a queued unix outbound connection may still be in the
	; "list of ones to process" after it was destroyed (this isn't a problem for normal use).
	epoll_unixconnect_forgiving = 1
	


	; default timeout in milliseconds for DNS queries
	dns_timeout_msecs = 10000

	; mimelike specific settings:
	; during transmit body composition, if Content-Encoding is set to gzip, and the actual body
	; length is less than this setting, composition removes the Content-Encoding header and does
	; NOT gzip it. The default here works well in the wild.
	mimelike_mingzip = 1024
	; during transmit body composition, if Transfer-Encoding is set to chunked, and this setting is
	; nonzero, and the body length is less than this setting, composition removes the Transfer-Encoding
	; header and adds a Content-Length header instead. (known content lengths defeats the purpose of
	; chunked transfer encoding anyway, but this is a useful feature to have around, different browsers
	; treat chunked transfer encodings quite interestingly).
	mimelike_minchunked = 0
	; and if we do end up doing chunked encoding, what should our chunksize be?
	mimelike_chunksize = 65535
	; during mimelike$compose, do we "split" Set-Cookie headers? Basically, new browsers have no
	; issue with my mimelike overall design choice of single unique headers, concatenated with
	; ', ' ... but, older browsers, specifically when used from the webserver object, don't like
	; dealing with multiple ', ' separated cookies in a single header... so if this setting is
	; enabled, then during composition, it checks each header for string$equals to 'Set-Cookie',
	; and if it _is_, then Compose itself splits them out into individual lines
	mimelike_setcookie_split = 1
	


	; tui_* specific settings:

	; should we send an initial 1049h and close with 1049l ? (think: vim restore screen when done)
	terminal_alternatescreen = 1

	; same for tui_ssh sessions
	tui_ssh_alternatescreen = 1


	; translate unicode line characters to the alternate character set line drawing chars?
	acs_linechars = 1
	; some notes here re: that one... with my Terminal.app, the unicode line characters draw just fine
	; but leaves horrific gaps in the vertical linespacing... this is presumably due to my font
	; having increased linespacing as well... interestingly however, they made special allowances
	; for the VT100 ACS linedrawing characters, which draw perfectly.
	; SO, since instead of writing invalid unicode characters into the tui_object buffers,
	; if the above setting is enabled, then the renderer translates them on the fly and modeswitches
	; between normal and ACS mode automatically... descendents of tui_object needn't be aware
	; and can just write standard unicode line drawing...

	; for tui_simpleauth, should a new user failure cause an exit?
	tui_simpleauth_newuserfail_exit = 0


	; syslog options:
	syslog_facility = 1 * 8		; user-level messages (*8 for priority value calculation)
					; 0 == kernel, 1 == user, 2 == mail, 3 == system daemons, 4 == security/auth, 6 == lpd, 7 == news, 8 == uucp, 9 == clockd, 10 == security/auth, 11 == ftp, etc.
					; see RFC5424 for further details
	syslog_stderr = 0		; send to stderr in addition to the syslog?


	; formatter settings
	; ISO8601 date format, from formatter$add_datetime. If this setting is true, we set the seconds in fractional
	; otherwise we stop at whole seconds
	formatter_datetime_fractional = 0


	; bigint settings:
	; to reduce the number of times we re-allocate/check for permissible sizes, etc
	; we have a static hard limit defined on the number of words a bigint can hold
	; CAUTION: we do _not_ check for overruns, so expect a crashy-crashy if this
	; setting isn't right for the intended application (or the app layer doesn't
	; boundscheck the math beforehand). SSH/TLS included herein do basic checks
	; to ensure overruns don't occur in the wild wild internet.
	bigint_maxwords = 512
	
	; maximum wordcount for unrolled squaring/mults
	; (This setting adds a TON of code if unrollsize > 16)
	; must be one of 16, 32, 64, 96, 128
	; NOTE: 16 is probably what you want unless you are doing a very specialized bit of mahem
	bigint_unrollsize = 16

	; for Miller-Rabin primality checking, this setting affects how many iterations end up being
	; done. Error rate is in 2^-VALUE, where value is below:
	millerrabinerrorrate = 64	; can be one of 64, 80, 128, 160, 256

	; sizes for DSA generated goods (one of 1024, 2048, 3072)
	dsa_size = 3072
	; dsa subgroup size (one of 160, 224, 256 per above size)
	dsa_subgroup_size = 256

	; Diffie-Hellman parameter settings
	; dh_bits = 4096		; this was our library default, many people said this was too much
	dh_bits = 2048
	; how many bits to use for our side's private "key" (aka DH private exponent)
	; While any value in the range 2..q-2 is perfectly fine, the modexp required to do a full
	; q's worth is considerably heavier than is required. NIST says 224 bits for a 2048 key, etc. etc.
	; so our default of 512 bits covers that and a bit more for good measure.
	; NOTE: OpenSSL (and probably others) always sets this to a random value in 2..q-2, and they
	; do so because they have no assurances about the DH p in use. Since we painstakingly
	; created our dh_pool to consist entirely of safe primes and their sophie germain counterparts,
	; we can safely use smaller private exponents to achieve the desired level of symmetric key
	; strength equivalence. It is somewhat surprising that none of the popular TLS server software
	; seems to have an option for specifying this.
	; dh_privatekey_size = 512	; this setting was used with dh_bits == 4096
	dh_privatekey_size = 256



	; TLS settings:
	; when we walk the cipher suite list, do we walk our own first, or the clients?
	; (server cipher order preferred or not)
	tls_server_cipher_order = 1

	; for server side PEM/X509 handling, this setting is the # of seconds
	; that we wait to check to see if the underlying PEM file got modified
	tls_pem_refresh_interval = 3600

	; Unfortunately, a good chunk of the wild interwebs doesn't support DHE (still, ughgh).
	; so, by default, we toss in the mandatory non-PFS ciphersuites.
	tls_perfect_forward_secrecy_only = 0

	; Much to my surprise, RSA blinding operations are not performed by default in OpenSSL
	; or any other library that I can find. Enabling this option prevents leaking any
	; information about the private exponent, at the expense of a tremendous amount of 
	; extra calculations.
	tls_server_rsa_blinding = 0

	; As many have pointed out, a lot of large-scale production environments do not care
	; so much about security as I do, this setting disables all but RSA/AES-128/CBC for
	; the ciphersuite list (to provide maximum throughout, despite it being with no DHE)
	tls_minimalist = 0

	; for DHE, in _client_ mode, should we verify that the supplied modulus is prime?
	tls_clientside_dh_p_verify = 0

	; in _server_ mode, if we encounter a bad_record_mac condition, should we blacklist
	; the IP? if this is nonzero, it specifies the time in seconds that the blacklist
	; should last for
	tls_blacklist = 86400

	; in _server_ mode, do we honour/enable sessionid reuse? This of course involves us
	; keeping copies of TLS states around for a while, so this setting, if nonzero
	; determines how long we keep them around for. The default here is 1 hour, and this
	; is probably overkill, since most are single-session based anyway (from the browser
	; side that is).
	tls_server_sessioncache = 3600

	; in _server_ mode, do we include OCSP Stapling? (this is generally a good thing)
	; NOTE: I can't find a single browser that supports RFC6961 yet, so multi-stapling
	; is not going to work for you just yet. Simple solution: Get your certificate from
	; a top-tier CA so that you don't have intermediates to contend with and you'll be
	; sweet. If we do have more than one certificate (and thus OCSPResponse for each),
	; at the moment, we'll only present status_request (not v2/multi), with the first
	; one we have (and this is better than none I spose).
	tls_server_ocsp_stapling = 1

	; OCSP specs say that everyone shall do sha1, so by default we leave the following
	; turned off (surely they will move to SHA256 at some point in the near future)
	X509_ocsp_sha256 = 0

	; on successful OCSP responses (regardless of what the validity period returned by
	; the OCSP responder), how often should we update our OCSP responses? NOTE: since
	; the response carries its age onto the end clients, even though the response may
	; be valid for a week or more, I have seen several clients reject them if they are
	; too stale (and then they go and fetch their own fresh copies, defeating the
	; entire purpose of OCSP stapling to begin with)
	; so, this is set by default to a 2 hourly timer (time is in milliseconds)
	X509_ocsp_refresh = 7200000

	; and similarly, if an error occurs, or we are unable to get them, etc, how often
	; should we retry? 5 min is the default
	X509_ocsp_retry = 300000

	; so that you can get an idea of what is really going on, and because we don't provide
	; any way to verify what is happening, we default to doing syslog messages for OCSP
	; Stapling activity
	X509_ocsp_syslog = 1

	; a companion to the above setting, if it is nonzero and enabled, should we encrypt
	; the actual session data itself? While really just an obfuscation technique, what
	; this does, if enabled, is randomly generate an AES256 key, and then use said
	; persistent AES256 enc/dec states such that actual session master key/cipherindex
	; are not kept in the cleartext in memory. It means a coredump of a running tls server
	; doesn't just "give up the goods" without someone having to spend some effort, haha
	tls_server_encryptcache = 1

	; similarly, in client mode, do we store sessionids and their associated master keys?
	; see above commentary for the server-side similar functionality
	; NOTE/CAUTION: because these share the same tls$sessionid map, both of these can't be
	; enabled at the same time _IF_ (and only if) you are trying to establish connections
	; directly to yourself inside the same executing session (haha, not a very common thing
	; but figure it is worth the warning)
	tls_client_sessioncache = 3600
	tls_client_encryptcache = 1

	; SCRYPT settings:
	; of course the "real" scrypt uses hmac-sha256, this option lets us use sha512 with it instead
	scrypt_sha512 = 1
	scrypt_N = 1024
	scrypt_r = 1
	scrypt_p = 1


	; SSH settings:
	; compile-time option that determines whether we use dh_pool.inc with a random index
	; for our DH public p/g, or whether we generate them on-the-fly. The dh_bits setting
	; above determines how large our safe prime is. CAUTION IS ADVISED! haha, generating
	; safe primes is not without its computational penalties. 2kbit DH params generate
	; fast enough to use on the fly, but anything larger will come with some heavy time
	; delays for our server-side goods. This is mainly intended for fun/playing around,
	; haha, if you really wanted to generate on-the-fly DH parameters, a modification
	; to the multiprocess make_dh_static to then send new parameters as they are generated
	; would be much more prudent. haha
	ssh_dh_dynamic = 0

	; compile-time option whether we use/try to use compression for SSH client/server.
	ssh_do_compression = 1

	; compile-time option to whether we _FORCE_ compression (requires the above set to 1 obviously)
	; NOTE: this prevents us from sending the "none" option in the kex, and really does force it
	; NOTE 2: for tui_ssh related goods, which is mostly what I use this for, our default of forced
	; is a GOOD thing.
	ssh_force_compression = 1

	; in _server_ mode, if we encounter a bad hmac, we randomize the expected length of the
	; incoming packet, such that we don't reveal any information to an attacker and sit there
	; waiting for more. Per my sentiments on the same for TLS though, by default we will blacklist
	; the remote IP by the below setting. Set to 0 to disable.
	ssh_blacklist = 86400


	; zlib settings:
	zlib_deflate_level = 6		; 0 == Z_NO_COMPRESSION, 1 == Z_BEST_SPEED, 9 == Z_BEST_COMPRESSION, 6 == normal zlib default

	; how many bytes do we automatically reserve in the outbuf when deflate is called?
	zlib_deflate_reserve = 16384

	; privmapped setting:
	; NOTE: if you are not running as user nobody, this noatime is a nicety, but otherwise you'll likely
	; get EPERM issues if the user/file doesn't belong to you (which seems weird)... at least confirmed on
	; oldish kernels, hmm, TODO: investigate this oddity a bit more, as O_NOATIME would be nice across the
	; board
	privmapped_noatime = 0


	; WEBSERVER settings:
	; for file-based (sandbox/vhost) serving, we automatically add Cache-Control, Last-Modified and ETag
	; headers, this setting defines how the max-age setting (and we set s-maxage to it * 3)
	; if this is zero, we only send Cache-Control: no-cache. This can also be overridden in the webserver
	; object.
	webserver_filecache_time = 300

	; when we receive data and are expecting a request header, this defines how large the upper limit
	; is before we decide to bailout and call it bad input:
	webserver_maxheader = 32768

	; similarly, and to prevent memory starvation attacks, this defines the maximum upper limit
	; of a POST request (and depending on your environment determines what this value should really be)
	; the default here reflects my normal operating environments, YMMV.
	webserver_maxrequest = 64 * 1048576
	
	; for file handling, if the file size is <= this setting, we may or may not do autogzip/chunking
	; and we use mimelike$xmitbody to do our full composition beforehand. Otherwise, no gzip/chunking
	; and we send it out in pieces as-is (the body of the file that is).
	; imagine: serving an 8GB file, without this threshold, we'd read it all into buffers and slowly
	; let the epoll layer consume it as it goes out, yikes.
	webserver_bigfile = 32 * 1048576

	; on the fly gzip our output (below the bigfile threshold only)
	webserver_autogzip = 1

	; we do our best to pay close attention to actual socket-level buffers, and because epoll$send
	; actually does buffer$consumes on whatever it has pending, we must be careful not to go too
	; crazy filling epoll's send buffers. (This is because for remote TCP where the send window is
	; small, buffer$consume effectively does a memmove of its entire sendbuffer by the amount that
	; is gradually accepted by the socket itself, obviously a bad thing if said buffer were gigantic).
	; so, this setting and the next one determine how aggressive we are filling the epoll layer's
	; sendbuffer and subsequent refills:
	webserver_initialsend = 262144
	webserver_subsequentsend = 262144

	; for filesystem serving, we do not constantly stat our cached privmapped objects, and only
	; do them periodically... this setting (seconds) detemrines how frequently we'll check them for
	; modifications (for production systems that don't change a lot, higher is better)
	; NOTE: this value _must_ be less than the hotlist time setting below
	webserver_hotlist_statfreq = 120

	; for filesystem serving, we keep cached privmapped objects for the underlying files, such that
	; we don't have to constantly stat/open/mmap (or any of the other various methods).
	; this setting determines how long old ones should hang around for (in seconds)
	webserver_hotlist_time = 900

	; ssllabs.com Best Practices says that all sites should employ HSTS, and further, that such
	; headers are ignored by HTTP clients (and ones that don't support it to begin with).
	; if the webservercfg object is set with the istls flag, we go ahead and add it (and include
	; subdomains) if this setting is in effect.
	webserver_hsts = 1

	; the BREACH attack is annoying, specifically because we _like_ webserver_autogzip, what a
	; spectacular difference it makes for normal webserver operations, especially nice when the
	; application layers (be them fastcgi, function calls, whatever) needn't concern themselves
	; with gzip awareness.
	; If this setting is nonzero, we add this random number of bytes (and then hex encode it) 
	; and add it as a random-length header in our responses (called X-NB). We only do so for TLS
	; _and_ auto-gzipped content. Note that because we add these random number of bytes in the
	; response header, and that the attacker only gets to see the resultant encrypted traffic
	; to measure the response sizes, compression does not apply here and these would make the
	; attacker's job much more difficult.
	; This also directly applies to the TIME attack, and any that rely on measuring compressed
	; response bodies (down to the byte level). Paranoid users may wish to increase this number.
	webserver_breach_mitigation = 48

	; if this is set, fastcgi maps are not hooked _on the spot_ and instead are hooked via
	; epoll's postprocessing hook
	webserver_fastcgi_postprocess = 0

	
	; webclient settings:
	; this setting defines the upper limit on how many simultaneous connections we'll do for
	; a single hostname (default only, can be modified directly in webclient)
	webclient_maxconns = 6

	; for any webclient request, how long will we sit around without _receiving_ any data?
	; (each time we get more data down the line, we reset this timer, so it really is a
	; read idle timeout). NOTE: if you are using webclient to upload some huge amount of
	; data that will take a while, this timeout needs upped considerably, haha
	; default here is 2 minutes (ms resolution as passed to epoll$timer_new)
	webclient_readtimeout = 120000

	; if the webclient receives a 301 or 302, should it follow them or return them?
	webclient_follow_redirects = 1

	; should we use a global object for dns cacheing? (this is only useful if you are using
	; more than one webclient object at the same time)
	webclient_global_dnscache = 1
