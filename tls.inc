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
	; tls.inc: TLS 1.2 minimalist implementation
	; 
	; Some notes here on my design/implementation choices...
	; This is not designed to be a user-friendly TLS package when it comes to
	; handling certificates. Specifically, I maintain a Garbage-In/Garbage-Out
	; policy. In short, if you feed this bogus/lame/invalid/expired/kak certs,
	; I am not going out of my way to tell you about it. Mind you, it won't be
	; long before your other, more retentive clients complain about the same
	; thing. That and given the plethora of user-friendly tools for dealing with
	; those types of things, I don't see much point in going all that extra
	; distance in what is only meant to be a high performance server-side library.
	; This isn't to say I have taken any shortcuts or security compromises, just
	; that I am not doing certificate chain validation, etc. We simply don't
	; care about that in a high-traffic server environment.
	;
	; Re: remote timing attacks to recover private keys, we perform blinding as a
	; countermeasure, but even that I didn't feel was sufficient. As a result, I
	; included a tls_blacklist setting, such that the moment we encounter a
	; crypto-related error (in server mode), said remote IP gets immediately
	; blacklisted. For cryptanalysis of this library, you may want to disable that
	; little unpleasantry. Basically, I see no reason to give would-be attackers
	; the luxury of us playing along, and during play-nice interactions, crypto
	; errors do not occur. UPDATE: see notes in ht_defaults.inc as to the setting
	; to enable RSA blinding operations in server mode for pure RSA key exchange.
	;
	; CipherSuite choices are limited to AES variants, because let's all stand
	; and share in a moment of silence about the fine AES hardware implementation
	; that all the newer gear performs. I suppose in a non-highspeed crypto
	; environment, one might want all the other variants, but here thanks to the
	; absolutely insane speeds we get out of the AES implementation, there really
	; is no reason to include the others.
	; (if I decide to add other ciphers, I have added MULTICIPHER comments on
	; where those would be required)
	;
	; MAC choices are limited to CBC for the moment, and the primary reason for
	; that is simply that latest browser support for CCM is nonexistent, and
	; the latest version of Firefox (29.0.something at the moment) will only
	; negotiate two ECDHE GCM combinations. 
	;
	; For Ephemeral Diffie-Hellman key exchanges, we make use of the bitsize
	; and random idx for our fixed public p and g values (dh_pool.inc). DH 
	; private key size is determined by the dh_privatekey_size setting.
	;
	; So, on with the show Re: how this works and is meant to be used...
	;
	; we do not descend the epoll object directly, though we _could_ of course.
	; the reason for this is simply because if it is tied 1:1 with an epoll
	; object, then we cannot do muxed remote TLS slave operations, and this
	; functionality is required. (Think dynamically scalable TLS cpu-only slave
	; farms).
	;
	; As a result, we are simply an io object descendent. It is expected that
	; our parent/previous io chain will feed us data to encrypt, and will accept
	; our decrypted data. Further, it is expected that our child/next io chain
	; will handle sending our TLS protocol goods, and feed us the same.
	;
	;
	; Further notes re: how we deal with server-side PEM pathnames for X509...
	; We do not want multiple copies of our server-side X509 goods, mainly because
	; they contain our private key, and having multiple copies of that seems like a
	; bad idea.
	;
	; to deal with that, without compromising security by making the heap "readily"
	; searchable for same, we keep a separate stringmap of pathnames to X509 certs.
	; when a new tls server side connection is created, the configured pathname for
	; the server certificate is passed into here, at which point we do a lookup
	; into our statically maintained list of pre-loaded X509 certs.
	; 
	; we will periodically check to see if the underlying certificate has been updated
	; (configurable), and if it has, will reload a NEW X509 cert. CAUTION CAUTION:
	; if you replace an underlying PEM with us running along happily, it _MUST_ be
	; valid (we will likely crash if it is not)... MUY IMPORTANTE! haha, there is no
	; graceful way to error on a new server connect if we loaded an invalid updated
	; X509 certificate... We do of course check validity when creating the _initial_
	; one... it is only for on-the-fly replacement of same that disaster might strike.
	; Typically, the only time I replace them is when my certificates are near expiry and
	; require updating. I loath having to shut everything down when I update certs,
	; so our strategy here, which _greatly_ simplifies dealing with that very scenario
	; is that we simply reload the newly updated X509 cert, but we intentionally
	; NEVER free the old one. This is an intentional memory leak, that for me would
	; happen at most once every year or two. Is it bad form to leave an expired cert
	; laying around in the heap? Hmm, perhaps... but if the private keys get updated
	; as they should during certificate updates, well, the old one is useless anyway.
	; What this SAVES us is that we don't have to quiesce active connections when
	; a certificate gets updated (meaning: any inflight connections are not affected
	; and would live out their time using the old certificate). Any new connections
	; after the update will of course from that point forward use the replacement.
	; This works well in my server environments, and IMO does not represent any
	; significant security implications. see "INTENTIONAL MEMORY LEAK" below for
	; more clarity...
	;


tlsdebug = 0



if used tls$ciphersuites | defined include_everything

	; our CipherSuite preferences (comment out ones you don't want us to advertise)
	; if this list is re-ordered, so too must the ciphersuiteparams list (they MUST be 1:1)
dalign
tls$ciphersuites:
	; db	0x00, 0xa3	; TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
	; db	0x00, 0x9f	; TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	; db	0x00, 0xa2	; TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
	; db	0x00, 0x9e	; TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	; db	0x00, 0x9d	; TLS_RSA_WITH_AES_256_GCM_SHA384
	; db	0x00, 0x9c	; TLS_RSA_WITH_AES_128_GCM_SHA256

if tls_minimalist = 0
	db	0x00, 0x6a	; TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
	db	0x00, 0x6b	; TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	db	0x00, 0x32	; TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
	db	0x00, 0x67	; TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	db	0x00, 0x38	; TLS_DHE_DSS_WITH_AES_256_CBC_SHA
	db	0x00, 0x39	; TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	db	0x00, 0x32	; TLS_DHE_DSS_WITH_AES_128_CBC_SHA
	db	0x00, 0x33	; TLS_DHE_RSA_WITH_AES_128_CBC_SHA
if tls_perfect_forward_secrecy_only = 0
	db	0x00, 0x3d	; TLS_RSA_WITH_AES_256_CBC_SHA256
	db	0x00, 0x3c	; TLS_RSA_WITH_AES_128_CBC_SHA256
	db	0x00, 0x35	; TLS_RSA_WITH_AES_256_CBC_SHA		; spec says this one isn't mandatory, but may as well
	db	0x00, 0x2f	; TLS_RSA_WITH_AES_128_CBC_SHA		; spec says we MUST support this one.
end if

else
	; for tls_minimalist, we support only the bare minimum non-DHE
	db	0x00, 0x2f	; TLS_RSA_WITH_AES_128_CBC_SHA		; spec says we MUST support this one.
end if

tls_ciphersuite_size = $ - tls$ciphersuites


; possible kex constants... depending on the negotiated ciphersuite, we really only support three methods:
tls_kex_dhe_dss = 1
tls_kex_dhe_rsa = 2
tls_kex_rsa = 3

	; 1:1 match _index-wise_ to the above, parameters for same
	; params are: key exchange algo, cipher algorithm, keylen, blocklen, ivlen, macalgo (init func ptr), maclen, mackeylen
dalign
tls$cipherspecs:

if tls_minimalist = 0
	dq	tls_kex_dhe_dss, aes$tls, 32, 16, 16, hmac$init_sha256, 32, 32		; TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
	dq	tls_kex_dhe_rsa, aes$tls, 32, 16, 16, hmac$init_sha256, 32, 32		; TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	dq	tls_kex_dhe_dss, aes$tls, 16, 16, 16, hmac$init_sha256, 32, 32		; TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
	dq	tls_kex_dhe_rsa, aes$tls, 16, 16, 16, hmac$init_sha256, 32, 32		; TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	dq	tls_kex_dhe_dss, aes$tls, 32, 16, 16, hmac$init_sha1, 20, 20		; TLS_DHE_DSS_WITH_AES_256_CBC_SHA
	dq	tls_kex_dhe_rsa, aes$tls, 32, 16, 16, hmac$init_sha1, 20, 20		; TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	dq	tls_kex_dhe_dss, aes$tls, 16, 16, 16, hmac$init_sha1, 20, 20		; TLS_DHE_DSS_WITH_AES_128_CBC_SHA
	dq	tls_kex_dhe_rsa, aes$tls, 16, 16, 16, hmac$init_sha1, 20, 20		; TLS_DHE_RSA_WITH_AES_128_CBC_SHA
if tls_perfect_forward_secrecy_only = 0
	dq	tls_kex_rsa, aes$tls, 32, 16, 16, hmac$init_sha256, 32, 32		; TLS_RSA_WITH_AES_256_CBC_SHA256
	dq	tls_kex_rsa, aes$tls, 16, 16, 16, hmac$init_sha256, 32, 32		; TLS_RSA_WITH_AES_128_CBC_SHA256
	dq	tls_kex_rsa, aes$tls, 32, 16, 16, hmac$init_sha1, 20, 20		; TLS_RSA_WITH_AES_256_CBC_SHA
	dq	tls_kex_rsa, aes$tls, 16, 16, 16, hmac$init_sha1, 20, 20		; TLS_RSA_WITH_AES_128_CBC_SHA
end if

else
	; for tls_minimalist, we support only the bare minimum non-DHE
	dq	tls_kex_rsa, aes$tls, 16, 16, 16, hmac$init_sha1, 20, 20		; TLS_RSA_WITH_AES_128_CBC_SHA

end if
	

	; MUY IMPORTANTE! (keylen + ivlen + mackeylen) * 2 _CANNOT_ exceed this limit:
tls_maxkeymaterial = 256

tls_cipherspec_kexalgo_ofs = 0
tls_cipherspec_cipheralgo_ofs = 8
tls_cipherspec_keylen_ofs = 16
tls_cipherspec_blocklen_ofs = 24
tls_cipherspec_ivlen_ofs = 32
tls_cipherspec_macalgo_ofs = 40
tls_cipherspec_maclen_ofs = 48
tls_cipherspec_mackeylen_ofs = 56

tls_cipherspec_size = 64
	; 64 == shl 6 == easy lookup with no mul


; the size in bytes of each connection state, noting that for server-side
; Ephemeral Diffie-Hellman, we hang onto our private key/exponent
; and use the bytes starting at tls_cstate_localmackey to do so
; such that dh_privatekey_size shr 3 must be able to fit
; default lets dh_privatekey_size be 3072 (which is insane)
; so we'll generate a warning and bailout if this setting needs adjusting

tls_cstate_size = 504

tls_clientmode_ofs = io_base_size			; bool as to whether we started life in client mode or not
tls_localcert_ofs = io_base_size + 8			; possibly null, otherwise a pointer to an X509 cert (which we do not own aka is not a copy)
tls_sessionidlen_ofs = io_base_size + 16		; the actual byte length of the sessionid
tls_sessionid_ofs = io_base_size + 24			; NOTE here: this is some evil trickery so that we can use "string" based maps with arbitrary uninterpreted bytes
							; the string "length" (preface 8 bytes for normal strings) is fixed at whatever amounts to 32 bytes, and the remainder (if any)
							; are zeroed such that string comparisons work properly even though they aren't really strings in a UTF sorta way, haha
tls_peercert_ofs = tls_sessionid_ofs + 40		; a pointer to the remote side's X509 goods
tls_version_ofs = tls_peercert_ofs + 8			; negotiated version
tls_ocspsupport_ofs = tls_version_ofs + 8		; client supported ocsp?
tls_expectmin_ofs = tls_ocspsupport_ofs + 8
tls_expectmax_ofs = tls_expectmin_ofs + 8		; maximum handshake type to expect
tls_open_ofs = tls_expectmax_ofs + 8			; open? (if we receive application data prior to this being set to 1, die.)
tls_secreneg_ofs = tls_open_ofs + 8
tls_renegdata_ofs = tls_secreneg_ofs + 8
tls_dhindex_ofs = tls_renegdata_ofs + 24
tls_readseq_ofs = tls_dhindex_ofs + 8			; current read sequence number
tls_writeseq_ofs = tls_readseq_ofs + 8			; current write sequence number
tls_recordbuf_ofs = tls_writeseq_ofs + 8		; to build our records from [possibly] fragments
tls_accbuf_ofs = tls_recordbuf_ofs + 8			; everything we receive gets appended to here, records are reassembled/compiled from here, then this is consumed/reset
tls_hacc_ofs = tls_accbuf_ofs + 8			; our handshake message accumulator (needed for the Finished hashing)
tls_dheint_ofs = tls_hacc_ofs + 8			; may or may not be set, if DHE, and we are a server, this is our temporary random, if client, this is our Yc
tls_cr_hmac_ofs = tls_dheint_ofs + 8			; current read hmac (so that we don't constantly have to initialize them freshlike on the stack)
tls_cw_hmac_ofs = tls_cr_hmac_ofs + hmac_size		; current write hmac ""
tls_cr_cipher_ofs = tls_cw_hmac_ofs + hmac_size		; current read cipher (aes_size, decrypt init)
tls_cw_cipher_ofs = tls_cr_cipher_ofs + aes_size	; current write cipher (aes_size, encrypt init)
tls_cr_ofs = tls_cw_cipher_ofs + aes_size		; current read state offset
tls_cw_ofs = tls_cr_ofs + tls_cstate_size		; current write state offset
tls_pr_ofs = tls_cw_ofs + tls_cstate_size		; pending state offset
tls_raddr_ofs = tls_pr_ofs + tls_cstate_size		; if in server mode, this gets set to the remote address
tls_raddrlen_ofs = tls_raddr_ofs + 110

tls_size = tls_raddrlen_ofs + 8


; individual connection state offsets:
tls_cstate_ciphervalid = 0
tls_cstate_cipherindex = 4
tls_cstate_mastersecret = 8
tls_cstate_localrandom = 56
tls_cstate_remoterandom = 88
tls_cstate_localmackey = 120
tls_cstate_remotemackey = 184
tls_cstate_localenckey = 248
tls_cstate_remoteenckey = 312
tls_cstate_localiv_ofs = 376
tls_cstate_remoteiv_ofs = 440

if (tls_cstate_size - tls_cstate_localmackey) < dh_privatekey_size shr 3
	display 'tls_cstate_size needs adjusting upward due to large dh_privatekey_size.',10
	err
end if

end if


if used tls$vtable | defined include_everything

dalign
tls$vtable:
	dq	tls$destroy, tls$clone, tls$connected, tls$send, tls$receive, io$error, io$timeout

end if


if used tls$new_client | defined include_everything
	; two arguments: rdi == ptr to sessionid (may be null), esi == length of same (may be zero, must not exceed 32)
	; returns a new parent/childless tls object ready for client mode
falign
tls$new_client:
	prolog	tls$new_client
	push	rdi rsi
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	mov	edi, tls_size
	call	heap$alloc_clear
	pop	r8 rcx rdx rsi rdi
	mov	qword [rax], tls$vtable				; setup our own vtable
	mov	dword [rax+tls_clientmode_ofs], 1
	mov	dword [rax+tls_sessionidlen_ofs], esi
	mov	dword [rax+tls_expectmin_ofs], 2		; we expect a server hello
	mov	dword [rax+tls_expectmax_ofs], 2		; ""
	mov	[rax+tls_recordbuf_ofs], rdx
	mov	[rax+tls_accbuf_ofs], rcx
	mov	[rax+tls_hacc_ofs], r8
	mov	qword [rdx+buffer_user_ofs], 0			; recordbuf.user == 0 (we use this for fragment type consistency checking and length)
	if string_bits = 32
		mov	dword [rax+tls_sessionid_ofs], 8
	else
		mov	dword [rax+tls_sessionid_ofs], 16
	end if
	test	rdi, rdi
	jnz	.withsessionid
	epilog
calign
.withsessionid:
	test	esi, esi
	jz	.retonly
	push	rax
	mov	edx, esi
	mov	rsi, rdi
	lea	rdi, [rax+tls_sessionid_ofs+8]
	call	memcpy
if tls_client_sessioncache
	; we have to make sure this session id is really in our cache
	push	rbx
	mov	rbx, [rsp+8]
	sub	rsp, 64
	mov	rsi, rsp
	lea	rdi, [rbx+tls_sessionid_ofs+8]
	call	tls$sessioncache_get
	add	rsp, 64
	test	rax, rax
	jz	.sessioncache_clear

	pop	rbx rax
	epilog
calign
.sessioncache_clear:
	mov	dword [rbx+tls_sessionidlen_ofs], 0
	pop	rbx rax
	epilog
else
	pop	rax
	epilog
end if
calign
.retonly:
	epilog

end if



if used tls$destroy | defined include_everything
	; single argument in rdi: our tls object
falign
tls$destroy:
	prolog	tls$destroy
	; cleanup all our goods, we don't have to destroy our own pointer though, io$destroy will do that for us so call it last
	; recordbuf, accbuf, hacc must be destroyed
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+tls_recordbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+tls_accbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+tls_hacc_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+tls_peercert_ofs]
	test	rdi, rdi
	jz	.nopeercert
	call	X509$destroy
.nopeercert:
	mov	rdi, [rbx+tls_dheint_ofs]
	test	rdi, rdi
	jz	.nodheint
	call	bigint$destroy_clear
.nodheint:
	; clear our state so we don't leave anything laying around in the heap
	lea	rdi, [rbx+tls_clientmode_ofs]
	xor	esi, esi
	mov	edx, tls_size - io_base_size
	call	memset
	mov	rdi, rbx
	pop	rbx
	call	io$destroy
	epilog

end if

if used tls$pemlookup | used tls$pemrevalidate | defined include_everything

globals
{
	tls$pem_bypath	dq	0
	tls$pem_byptr	dq	0
}

end if

globals
{
if used tls$peminit & tls_blacklist
	tls$blacklist	dq	0
else if defined include_everything
	tls$blacklist	dq	0
end if
}


if (tls_server_sessioncache & used tls$new_server) | (tls_client_sessioncache & used tls$new_client)

globals
{
	tls$sessioncache	dq	0
	tls$sessioncache_hook	dq	0
	tls$sessioncache_first	dq	0
	tls$sessioncache_last	dq	0
}

if tls_server_encryptcache | tls_client_encryptcache

globals
{
	tls$sessionenc	dq	0
	tls$sessiondec	dq	0
}

end if

end if

if used tls$peminit | defined include_everything
	; no arguments, called from ht$init, required to setup our global maps for server-side X509 handling
falign
tls$peminit:
	prolog	tls$peminit
	; make sure the epoll global timestamp is setup first (so that we can use the global timestamp instead of
	; calling gettimeofday)
	call	epoll$timestamp
	xor	edi, edi
	call	stringmap$new
	mov	[tls$pem_bypath], rax
	xor	edi, edi
	call	unsignedmap$new
	mov	[tls$pem_byptr], rax
if tls_blacklist
	; this is as good a time as any, since tls_blacklist is server mode only, and server mode requires pemlookups
	mov	edi, tls_blacklist
	call	blacklist$new
	mov	[tls$blacklist], rax
end if
	epilog

end if

if (tls_server_sessioncache & used tls$new_server) | (tls_client_sessioncache & used tls$new_client)


falign
tls$sessioncacheinit:
	prolog	tls$sessioncacheinit
	mov	edi, 8192
	call	heap$alloc_clear
	mov	[tls$sessioncache], rax
	; randomly generate our aes states if encryptcache is enabled
if tls_server_encryptcache | tls_client_encryptcache
	mov	edi, aes_size
	call	heap$alloc
	mov	[tls$sessionenc], rax
	mov	edi, aes_size
	call	heap$alloc
	mov	[tls$sessiondec], rax
	sub	rsp, 32
	mov	rdi, rsp
	mov	esi, 32
	call	rng$block
	mov	rdi, [tls$sessionenc]
	mov	rsi, rsp
	mov	edx, 32
	call	aes$init_encrypt
	mov	rdi, [tls$sessiondec]
	mov	rsi, rsp
	mov	edx, 32
	call	aes$init_decrypt
	mov	rdi, rsp
	mov	esi, 32
	call	rng$block
	add	rsp, 32
end if
	epilog


	; rdi == pointer to 32 bytes of sessionid, rsi == tls state (unencrypted)
falign
tls$sessioncache_set:
	prolog	tls$sessioncache_set
	; the bucket number is 0..1023 << 3, so our mask is 0x1ff8
	; each entry is: 32 byte key, 8 byte time, 8 byte next ptr, 8 byte tnext, 64 bytes of data == 120 bytes.
	push	rdi rsi

if tlsdebug
	mov	rdi, .debugstr
	call	string$to_stdout
	mov	rdi, [rsp+8]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rsi, [rsp]
	mov	rdi, [rsp+8]

end if

	cmp	qword [tls$sessioncache_hook], 0
	je	.skiphook
	call	qword [tls$sessioncache_hook]
.skiphook:
	mov	edi, 120
	call	heap$alloc
	pop	rsi rdi
	mov	rcx, [rdi]
	mov	rdx, [tls$sessioncache]
	mov	r9, [rdi+8]
	mov	r8, rcx
	and	ecx, 0x1ff8
	mov	r10, [rdi+16]
	mov	r11, [rdi+24]
	add	rdx, rcx
	; so our new entry's next is [rdx]
	mov	[rax], r8
	mov	[rax+8], r9
	mov	[rax+16], r10
	mov	r8, [_epoll_tv_secs]
	mov	r9, [rdx]
	mov	[rax+24], r11
	mov	[rax+32], r8
	mov	[rax+40], r9
	mov	qword [rax+48], 0
	; and now [rdx] gets set to us:
	mov	[rdx], rax
	; copy our 64 bytes of state information
	lea	rdi, [rax+56]
	mov	edx, 64
	push	rbx
	mov	rbx, rax
	call	memcpy
	; if we are encrypting it, now is the time
if (tls_server_sessioncache & tls_server_encryptcache) | (tls_client_sessioncache & tls_client_encryptcache)
	mov	rdi, [tls$sessionenc]
	lea	rsi, [rbx+56]
	call	aes$encrypt
	mov	rdi, [tls$sessionenc]
	lea	rsi, [rbx+56+16]
	call	aes$encrypt
	mov	rdi, [tls$sessionenc]
	lea	rsi, [rbx+56+32]
	call	aes$encrypt
	mov	rdi, [tls$sessionenc]
	lea	rsi, [rbx+56+48]
	call	aes$encrypt
end if
	; link us to the timemap
	mov	rax, [tls$sessioncache_last]
	test	rax, rax
	jnz	.notfirst
	mov	[tls$sessioncache_first], rbx
	mov	[tls$sessioncache_last], rbx
	jmp	.weed
if tlsdebug
cleartext .debugstr, '              tls$sessioncache_set: '
end if
calign
.notfirst:
	mov	[rax+48], rbx
	mov	[tls$sessioncache_last], rbx
calign
.weed:
	mov	rbx, [tls$sessioncache_first]
	mov	rcx, [_epoll_tv_secs]
	sub	rcx, [rbx+32]
if (tls_server_sessioncache & used tls$new_server)
	cmp	ecx, tls_server_sessioncache
else
	cmp	ecx, tls_client_sessioncache
end if
	ja	.remove
	pop	rbx
	epilog
calign
.remove:
	; remove it from the timeout list first
	mov	rax, [rbx+48]
	mov	rcx, [rbx]
	mov	rdx, [tls$sessioncache]
	mov	[tls$sessioncache_first], rax
	test	rax, rax
	jnz	.remove_skiplast
	mov	qword [tls$sessioncache_last], 0
.remove_skiplast:
	xor	eax, eax
	and	ecx, 0x1ff8
	add	rdx, rcx
	mov	rcx, [rdx]
calign
.remove_search:
	cmp	rbx, rcx
	je	.remove_found
	mov	rax, rcx
	mov	rcx, [rcx+40]
	; we know it has to be here, so no test for running off the end is necessary
	jmp	.remove_search
calign
.remove_found:
	mov	rcx, [rbx+40]
	test	rax, rax
	jz	.remove_found_top
	; otherwise, it was not at the top, so rax's bucket next is our bucket next
	mov	[rax+40], rcx
	; done, free it
	mov	rdi, rbx
	call	heap$free
	; go back for more
	jmp	.weed
calign
.remove_found_top:
	; set our new bucket top to our next
	mov	[rdx], rcx
	; done, free it
	mov	rdi, rbx
	call	heap$free
	; go back for more
	jmp	.weed




	; rdi == pointer to 32 bytes of sessionid, rsi == destination
	; returns either rsi or null
falign
tls$sessioncache_get:
	prolog	tls$sessioncache_get
	; the bucket number is 0..1023 << 3, so our mask is 0x1ff8
	; each entry is: 32 byte key, 8 byte time, 8 byte next ptr, 8 byte tnext, 64 bytes of data == 120 bytes.
if tlsdebug
	push	rdi rsi
	mov	rdi, .debugstr
	call	string$to_stdout
	mov	rdi, [rsp+8]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rsi rdi
end if

	xor	eax, eax
	mov	rcx, [rdi]
	mov	rdx, [tls$sessioncache]
	mov	r9, [rdi+8]
	mov	r8, rcx
	and	ecx, 0x1ff8
	mov	r10, [rdi+16]
	mov	r11, [rdi+24]
	add	rdx, rcx
	mov	rcx, [rdx]
	test	rcx, rcx
	jnz	.search
	epilog
if tlsdebug
cleartext .debugstr, '          tls$sessioncache_get: '
end if
calign
.search:
	cmp	r8, [rcx]
	jne	.searchnext
	cmp	r9, [rcx+8]
	jne	.searchnext
	cmp	r10, [rcx+16]
	jne	.searchnext
	cmp	r11, [rcx+24]
	je	.found
calign
.searchnext:
	; save our last node in rax so we can unlink/relink
	mov	rax, rcx
	mov	rcx, [rcx+40]	; its next ptr
	test	rcx, rcx
	jnz	.search
	; if we made it here, it isn't in the list, bailout
	xor	eax, eax
	epilog
calign
.found:
	; first things first, relink
	test	rax, rax
	jz	.found_norelink
	; otherwise, [rax+40] == us, [rcx+40] is what it needs to be
	mov	r8, [rcx+40]
	; our next needs to be set to whatever the bucket top is
	mov	r9, [rdx]
	mov	[rax+40], r8
	mov	[rcx+40], r9
	mov	[rdx], rcx
calign
.found_norelink:
	; so rcx is at the topmost of the bucket, rsi is our destination where the session data needs copied to
	push	rsi
	sub	rsp, 64
	mov	rdi, rsp
	lea	rsi, [rcx+56]
	mov	edx, 64
	call	memcpy
if (tls_server_sessioncache & tls_server_encryptcache) | (tls_client_sessioncache & tls_client_encryptcache)
	mov	rdi, [tls$sessiondec]
	mov	rsi, rsp
	call	aes$decrypt
	mov	rdi, [tls$sessiondec]
	lea	rsi, [rsp+16]
	call	aes$decrypt
	mov	rdi, [tls$sessiondec]
	lea	rsi, [rsp+32]
	call	aes$decrypt
	mov	rdi, [tls$sessiondec]
	lea	rsi, [rsp+48]
	call	aes$decrypt
end if
	mov	rsi, rsp
	mov	rdi, [rsp+64]
	mov	edx, 56
	call	memcpy
	add	rsp, 64
	pop	rax
	epilog

end if


if used tls$pemlookup | defined include_everything
	; single argument in rdi: _string_ pathname of PEM file
	; NOTE: see comments atop re: how we deal with PEM files and their associated copyless X509 certs
	; returns either pointer to X509 object, or null if we were unable to read it, or null if
	; it didn't pass basic checks (private cert, certs, etc) keeping in mind we maintain a GIGO policy
	; when it comes to handling certs
falign
tls$pemlookup:
	prolog	tls$pemlookup
	; first up, see if we already have this pathname in our global X509 map
	push	rdi
	mov	rsi, rdi
	mov	rdi, [tls$pem_bypath]
	call	stringmap$find_value
	test	eax, eax
	jz	.newone
	; otherwise, stringmap$find_value stuck our value into rdx
	; so, we now must revalidate it
	mov	rdi, rdx
	call	tls$pemrevalidate
	pop	rdi
	epilog
calign
.newone:
	; create a new X509 cert from the pem pathname
	mov	rdi, [rsp]
	call	X509$new_pem
	test	rax, rax
	jz	.newone_kakked
	; make sure it contains a private key _and_ one or more certificates
	mov	rdx, [rax+X509_certificates_ofs]
	test	rdx, rdx
	jz	.newone_kakked_delete
	cmp	qword [rdx], 0			; count in the certificates list
	je	.newone_kakked_delete
	mov	r8, [rax+X509_privatekey_ofs]
	or	r8, [rax+X509_dsaprivatekey_ofs]
	test	r8, r8
	jz	.newone_kakked_delete
	; otherwise, basic checks passed, add us to our maps
	mov	rdi, [tls$pem_bypath]
	mov	rsi, [rsp]
	mov	rdx, rax
	push	rax				; save our object
	call	stringmap$insert_unique
	mov	rdi, [tls$pem_byptr]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	call	unsignedmap$insert_unique	; by pointer

if tls_server_ocsp_stapling
	mov	rdi, [rsp]
	call	X509$ocsp
end if

	pop	rax rdi
	epilog
calign
.newone_kakked:
	pop	rdi
	epilog
calign
.newone_kakked_delete:
	mov	rdi, rax
	call	X509$destroy
	pop	rdi
	xor	eax, eax
	epilog

end if


if used tls$pemrevalidate | defined include_everything
	; single argument in rdi: pointer to X509 cert
	; based on the configuration option of how frequently to check for updates to the underlying file
	; we may or may not load a new one, returns either same pointer, or a new one if we updated it
falign
tls$pemrevalidate:
	prolog	tls$pemrevalidate
	mov	rcx, [_epoll_tv_secs]
	sub	rcx, [rdi+X509_checktime_ofs]
	cmp	rcx, tls_pem_refresh_interval
	jb	.nocheck
	; otherwise, its been a while since we've checked to see if the underlying file has been modified
	push	rdi
	mov	rsi, rdi
	mov	rdi, [tls$pem_byptr]
	call	unsignedmap$find_value
	test	eax, eax
	jz	.catastrophy
	; otherwise, our pathname string is in rdx
	push	rdx
	mov	rdi, rdx
	call	file$mtime
	mov	rcx, rax
	mov	rax, [rsp+8]
	cmp	rcx, [rax+X509_mtime_ofs]
	je	.notmodified
	; otherwise, file mtime is different to the one in the cert that was handed to us to check
	; this is an INTENTIONAL MEMORY LEAK, see the commentary atop re: why this is
	
	; delete both entries from the maps, and reinsert them
	mov	rdi, rax
	call	X509$destroy

	mov	rdi, [tls$pem_bypath]
	mov	rsi, [rsp]
	call	stringmap$erase

	mov	rdi, [tls$pem_byptr]
	mov	rsi, [rsp+8]
	call	unsignedmap$erase

	; get a shiny new X509 object
	mov	rdi, [rsp]
	call	X509$new_pem

	mov	[rsp+8], rax
	mov	rdi, [tls$pem_byptr]
	mov	rsi, rax
	mov	rdx, [rsp]
	call	unsignedmap$insert_unique

	mov	rdi, [tls$pem_bypath]
	mov	rsi, [rsp]
	mov	rdx, [rsp+8]
	call	stringmap$insert_unique

if tls_server_ocsp_stapling
	mov	rdi, [rsp+8]
	call	X509$ocsp
end if

	mov	rax, [rsp+8]
	add	rsp, 16
	epilog
calign
.notmodified:
	mov	rcx, [_epoll_tv_secs]
	pop	rdx rax
	mov	[rax+X509_checktime_ofs], rcx
	epilog
calign
.catastrophy:
	; if we didn't find our pointer in the list, we won't die a thousand deaths
	; as the name implies, heh, but this is not a good condition to have arise
	; (the only way is if the localcert itself wasn't put in place by the tls$pem routines in the first place)
	pop	rax
	epilog
calign
.nocheck:
	mov	rax, rdi
	epilog

end if





if used tls$new_server | defined include_everything
	; single argument in rdi: _string_ pathname of PEM file that has our goods (private, cert, chain)
	; NOTE: see comments atop re: how we deal with PEM files and their associated copyless X509 certs
	; returns either pointer to new tls object in rax, or null if we encountered an error with the PEM
falign
tls$new_server:
	prolog	tls$new_server
	call	tls$pemlookup
	test	rax, rax
	jz	.pemkakked
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	mov	edi, tls_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	qword [rax], tls$vtable				; setup our own vtable
	mov	dword [rax+tls_expectmin_ofs], 1		; we expect a client hello
	mov	dword [rax+tls_expectmax_ofs], 1		; ""
	mov	[rax+tls_recordbuf_ofs], rcx
	mov	[rax+tls_accbuf_ofs], rdx
	mov	[rax+tls_hacc_ofs], rsi
	mov	qword [rcx+buffer_user_ofs], 0			; recordbuf.user == 0 (we use this for fragment type consistency checking and length)
	if string_bits = 32
		mov	dword [rax+tls_sessionid_ofs], 8
	else
		mov	dword [rax+tls_sessionid_ofs], 16
	end if
	mov	[rax+tls_localcert_ofs], rdi
	epilog
calign
.pemkakked:
	epilog

end if


if used tls$clone | defined include_everything
	; single argument in rdi: our tls object to clone
falign
tls$clone:
	prolog	tls$clone
	push	rdi
	mov	rdi, [rdi+tls_localcert_ofs]
	call	tls$pemrevalidate
	mov	rdi, [rsp]
	mov	[rdi+tls_localcert_ofs], rax			; store whatever the revalidate gave us back
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	mov	edi, tls_size
	call	heap$alloc_clear
	pop	rcx rdx rsi rdi
	mov	r8, [rdi+tls_localcert_ofs]
	mov	r9, [rdi]					; get our original's vtable
	mov	r10, [rdi+io_child_ofs]				; determine whether our original had a child or not
	mov	dword [rax+tls_expectmin_ofs], 1		; we expect a client hello
	mov	dword [rax+tls_expectmax_ofs], 1		; ""
	mov	qword [rax], r9					; setup our own vtable
	mov	[rax+tls_recordbuf_ofs], rcx
	mov	[rax+tls_accbuf_ofs], rdx
	mov	[rax+tls_hacc_ofs], rsi
	mov	qword [rcx+buffer_user_ofs], 0			; recordbuf.user == 0 (we use this for fragment type consistency checking and length)
	if string_bits = 32
		mov	dword [rax+tls_sessionid_ofs], 8
	else
		mov	dword [rax+tls_sessionid_ofs], 16
	end if
	mov	[rax+tls_localcert_ofs], r8
	test	r10, r10
	jnz	.withchild
	epilog
calign
.withchild:
	push	rax						; save our return object
	mov	rdi, r10					; argument for child clone
	mov	rsi, [r10]					; get our child's vtable
	call	qword [rsi+io_vclone]
	mov	rsi, rax
	pop	rax
	mov	[rax+io_child_ofs], rsi
	mov	[rsi+io_parent_ofs], rax
	epilog

end if

if used tls$send_initialclienthello | defined include_everything
	; single argument in rdi: our tls object
	; assumption: [rdi+tls_clientmode_ofs] == 1
falign
tls$send_initialclienthello:
	prolog	tls$send_initialclienthello

	; clienthello initial 3 bytes == 0x030316 (protocol = 3,3, 0x16 == 22 == handshake)
	; byte #4 is the high order of our length
	; byte #5 is the low order of our length
	; bytes 6..length == our Handshake

	; our Handshake looks like:
	; byte #0 == 1 == client_hello
	; byte #1 == high order of 24 bit length
	; byte #2 == middle order
	; byte #3 == low order

	; then a ClientHello, which looks like:
	; first two bytes == protocol version == 3,3
	; next four bytes == 32 bit BIG ENDIAN ctime
	; next 28 bytes == random bytes
	; length-encoded up-to-32 byte session id is next (variable)
	; length encoded _LIST_ of supported CipherSuites (each of which is 2 bytes) (length is up to 2^16-2, so we need two byte length encoding)
	; length encoded list of compression methods, which are single byte, length is 2^8-1, so we need single byte length encoding
	; end of record if no extensions are supported
	; otherwise, a length encoded Extension list, length is 2 bytes.

	; the initialclienthello goes out plaintext like, so we avoid having to deal with encrypting it
	; so we can precompute our length as:
	;   5 for the initial ContentType, Protocol Version, and 2 byte Length
	; + 4 for the Handshake preface, (handshake type + 3 byte length)
	; +34 for the protocol version, ctime, and 28 bytes of random in the ClientHello
	; + 1 for the session id length encoding
	; +?? for the sessionid length itself if nonzero
	; + 2 byte length encoding for our supported CipherSuites
	; +?? for the list of supported CipherSuites
	; + 1 byte length for list of compression length, which will always be 1
	; + 1 byte 0 for the null compression method
	; --- stop there if no extension list
	;  48 without our unknowns

	; + tls_ciphersuite_size (which is in bytes)
	; + our sessionid length (which might be zero)
	mov	edx, dword [_epoll_tv_secs]	; low order 32 bits of this is fine
	mov	ecx, [rdi+tls_sessionidlen_ofs]
	push	rbx r12
	mov	rbx, rdi
	mov	r12d, 48 + tls_ciphersuite_size
	add	r12d, ecx
	sub	rsp, 512
	; sub	rsp, r12
	; total length of the outer fragment is r12d - 5
	mov	eax, r12d
	sub	eax, 5
	mov	dword [rsp], 0x010316		; protocol version, plus 0x16 (22) handshake (RFC says 3, 1 or 3,0 for record-layer clienthello)
	; RFC says some old servers are busted and will reject the initial client hello if the record layer version is too high, hmm
	; TODO: multibyte these..
	mov	byte [rsp+3], ah
	mov	byte [rsp+4], al
	mov	byte [rsp+5], 1			; client_hello
	; total length of our ClientHello is another 4 less
	sub	eax, 4
	mov	byte [rsp+6], 0			; upper byte of our length
	mov	byte [rsp+7], ah
	mov	byte [rsp+8], al
	mov	word [rsp+9], 0x0303		; protocol version of the client hello
if use_movbe
	movbe	dword [rsp+11], edx
else
	bswap	edx				; make sure our gmt is in big endian format
	mov	dword [rsp+11], edx
end if
	lea	rdi, [rsp+15]
	mov	esi, 28
	call	rng$block

	; 32 bytes at [rsp+11] is our Random structure, which we need a copy of in our tls object
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rsi, [rsp+11]
	mov	edx, 32
	call	memcpy

	mov	ecx, [rbx+tls_sessionidlen_ofs]

	mov	byte [rsp+43], cl		; sessionidlen
	lea	rdi, [rsp+44]			; our pointer from here
	test	ecx, ecx
	jz	.nosessionid
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, [rbx+tls_sessionidlen_ofs]
	call	memcpy
	; reset rdi to the right spot
	mov	ecx, [rbx+tls_sessionidlen_ofs]
	lea	rdi, [rsp+44]
	add	rdi, rcx
calign
.nosessionid:
	mov	eax, tls_ciphersuite_size
	mov	byte [rdi], ah
	mov	byte [rdi+1], al
	add	rdi, 2
	mov	rsi, tls$ciphersuites
	mov	edx, tls_ciphersuite_size
	call	memcpy
	; now we need to get our pointer back
	mov	ecx, [rbx+tls_sessionidlen_ofs]
	lea	rdi, [rsp+44]
	add	rdi, rcx
	add	rdi, tls_ciphersuite_size + 2
	mov	word [rdi], 1			; compression list length + 0 byte
	; so now, we can send off our goods ...
	; noting here, it isn't our OWN send routine that we need to call, it is our _child's_ (and if we don't have one, something is very wrong)

	; we need to add just the handshake message component itself to the hacc so we can hash it properly at Finished time
	mov	rdi, [rbx+tls_hacc_ofs]
	mov	rsi, rsp
	mov	edx, r12d
	add	rsi, 5
	sub	edx, 5
	call	buffer$append

if tlsdebug
	;debug
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	edi, r12d
	sub	edi, 5
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	;end debug

	mov	rdi, rsp
	mov	esi, r12d
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	mov	rdi, [rbx+io_child_ofs]
if tlsdebug
	; sanity check only
	test	rdi, rdi
	jz	.breakpoint
	; end sanity check
end if
	mov	rsi, rsp
	mov	edx, r12d
	mov	rcx, [rdi]	; its vtable
	call	qword [rcx+io_vsend]
	add	rsp, 512
	; add	rsp, r12

	mov	dword [rbx+tls_writeseq_ofs], 1		; since we know we are initial, dword move is fine here
	pop	r12 rbx
	epilog
if tlsdebug
calign
.breakpoint:
	breakpoint
end if

if tlsdebug
cleartext .debugstr, 'tls$send_initialclienthello appending to handshake accumulator:'
end if

end if

if used tls$send_alert | defined include_everything

; our alert constants:
tls_alert_warning = 1
tls_alert_fatal = 2

tls_alert_close_notify = 0
tls_alert_unexpected_message = 10
tls_alert_bad_record_mac = 20
tls_alert_record_overflow = 22
tls_alert_handshake_failure = 40
tls_alert_bad_certificate = 42
tls_alert_unsupported_certificate = 43
tls_alert_certificate_revoked = 44
tls_alert_certificate_expired = 45
tls_alert_certificate_unknown = 46
tls_alert_illegal_parameter = 47
tls_alert_unknown_ca = 48
tls_alert_access_denied = 49
tls_alert_decode_error = 50
tls_alert_decrypt_error = 51
tls_alert_protocol_version = 70
tls_alert_insufficient_security = 71
tls_alert_internal_error = 80
tls_alert_user_cancelled = 90
tls_alert_no_renegotiation = 100
tls_alert_unsupported_extension = 110
	
	; three arguments: rdi == our tls object, esi == alert level, edx == alert description
falign
tls$send_alert:
	prolog	tls$send_alert
	cmp	dword [rdi+tls_cw_ofs+tls_cstate_ciphervalid], 1
	je	.doenc
	sub	rsp, 8
	mov	eax, [rdi+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x15			; protocol record layer + 0x15 == 21 == alert
	mov	dword [rsp], eax
	; upper order byte of our length is 0, so next is our length byte which is 2, followed by alert level, followed by alert description
	; total send length is 7
	shl	esi, 8
	shl	edx, 16
	mov	ecx, 2
	or	ecx, esi
	or	ecx, edx
	mov	dword [rsp+4], ecx
	mov	rdi, [rdi+io_child_ofs]		; our next in line
if tlsdebug
	; sanity check only
	test	rdi, rdi
	jz	.breakpoint
	; end sanity check
end if
	mov	rsi, rsp
	mov	edx, 7
	mov	rcx, [rdi]	; our vtable
	call	qword [rcx+io_vsend]
	add	rsp, 8
	epilog
calign
.doenc:
	sub	rsp, 8
	shl	edx, 8
	or	esi, edx
	mov	dword [rsp], esi
	mov	esi, 0x15		; 0x15 == 21 == alert
	mov	rdx, rsp
	mov	ecx, 2
	call	tls$encrypt
	add	rsp, 8
	epilog
if tlsdebug
calign
.breakpoint:
	breakpoint
end if

end if


if used tls$closenotify | defined include_everything
	; single argument in rdi: an epoll io chain object (most likely the topmost in the chain)
	; NOTE: TLS says we MUST send one, but for io chain independence, it is important that we don't
	; make the upper layer io layers _necessarily_ aware that they are operating over TLS in the first place
	; so all we do is walk down the io chain, if we see a vtable that matches our own tls$vtable, then we
	; send a tls alert with close_notify (see webserver.inc for why this is necessary)
falign
tls$closenotify:
	prolog	tls$closenotify
calign
.chainwalk:
	cmp	qword [rdi], tls$vtable
	je	.foundit
	cmp	qword [rdi+io_child_ofs], 0
	je	.outtahere
	mov	rdi, [rdi+io_child_ofs]
	jmp	.chainwalk
calign
.foundit:
	mov	esi, tls_alert_warning
	mov	edx, tls_alert_close_notify
	call	tls$send_alert
	epilog
calign
.outtahere:
	epilog

end if


if used tls$connected | defined include_everything
	; single argument in rdi: our tls object (we do get passed the remote address/len from the epoll layer too in server mode)
falign
tls$connected:
	prolog	tls$connected
	cmp	dword [rdi+tls_clientmode_ofs], 1
	je	.clientmode
if tls_blacklist
	push	rdi
	mov	[rdi+tls_raddrlen_ofs], edx
	lea	rdi, [rdi+tls_raddr_ofs]
	call	memcpy
	mov	rdx, [rsp]
	mov	rdi, [tls$blacklist]
	mov	esi, [rdx+tls_raddr_ofs+4]
	call	blacklist$check
	test	eax, eax
	jnz	.blacklisted
	pop	rdi
else
	mov	[rdi+tls_raddrlen_ofs], edx
	lea	rdi, [rdi+tls_raddr_ofs]
	call	memcpy
end if

if tlsdebug
	mov	rdi, .serverconnected
	call	string$to_stdoutln
end if
	epilog
if tls_blacklist
calign
.blacklisted:
	; send an access denied alert, and set our tls object so that no negotiation can occur
	mov	rdi, [rsp]
	; we need to set the version number before we proceed (cuz nothign else has happened yet)
	mov	dword [rdi+tls_version_ofs], 0x303
	mov	esi, tls_alert_fatal
	mov	edx, tls_alert_access_denied
	call	tls$send_alert
	pop	rdi
	mov	dword [rdi+tls_expectmin_ofs], 0xffff		; we expect a client hello
	mov	dword [rdi+tls_expectmax_ofs], 0xffff		; ""

if tlsdebug
	mov	rdi, .serverconnected_bl
	call	string$to_stdoutln
end if
	epilog

end if
calign
.clientmode:
if tlsdebug
	push	rdi
	mov	rdi, .clientconnected
	call	string$to_stdoutln
	pop	rdi
end if
	call	tls$send_initialclienthello
	epilog

if tlsdebug

cleartext .serverconnected, 'tls$connected, server, waiting for ClientHello'
cleartext .serverconnected_bl, 'tls$connected, server, BLACKLISTED!'
cleartext .clientconnected, 'tls$connected, client, sending ClientHello'

end if

end if

if used tls$send | defined include_everything
	; three arguments: rdi == our tls object, rsi == ptr to data, rdx == length of same
	; this gets called with application-level data to send, which we of course need to cook
	; and forward on to our next in line
falign
tls$send:
	prolog	tls$send
	; NOTE TO SELF: _we_ have to break up fragments here at this level with repeated calls to tls$encrypt, tls$encrypt will not do it for us
	; and our segment size cannot exceed 2**14
	test	rdx, rdx
	jz	.nothingtodo
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
calign
.loop:
	mov	ecx, 16384
	cmp	r13, 16384
	cmovb	ecx, r13d
	mov	rdi, rbx
	mov	esi, 0x17	; application_data
	mov	rdx, r12
	; update r12/r13 for our next pass
	add	r12, rcx
	sub	r13, rcx
	call	tls$encrypt
	test	r13, r13
	jnz	.loop
	pop	r13 r12 rbx
	epilog
calign
.nothingtodo:
	epilog

end if


if used tls$encrypt | defined include_everything
	; four arguments: rdi == our tls object, esi == record layer type we are sending, rdx == buffer to encrypt/send, ecx == length of same (must not exceed 2**14)
falign
tls$encrypt:
	prolog	tls$encrypt
	mov	eax, [rdi+tls_cw_ofs+tls_cstate_cipherindex]
	cmp	dword [rdi+tls_cw_ofs+tls_cstate_ciphervalid], 0
	je	.plaintext
	shl	eax, 6
	mov	r9d, ecx
	cmp	dword [rdi+tls_open_ofs], 0
	je	.plaintext
	cmp	dword [rax+tls$cipherspecs+tls_cipherspec_blocklen_ofs], 0
	je	.aead
	add	r9d, 48 + 2047
if epoll_nodelay
	xor	r8d, r8d
	mov	r10d, 0x16
	mov	r11d, 1
	cmp	esi, 0x36
	cmove	esi, r10d
	cmove	r8d, r11d
end if
	
	; otherwise, we are a block cipher (only because we don't support any stream ciphers)
	; ultimately, we need a buffer that is large enough to do all of our dirty work, so we'll round ecx + 40 up to the nearest 2k boundary and use
	; that space for our goods locally here on the stack.

	; also note: due to the 5 byte preface and all the unaligned ops that result if the buffer starts there, we align the start of the encryption ops
	; and then only the final send is unaligned
	sub	rsp, 80
	mov	[rsp], rdi
if epoll_nodelay
	mov	[rsp+8], esi
	mov	[rsp+12], r8d
else
	mov	[rsp+8], rsi
end if
	mov	[rsp+16], rdx
	mov	r10, [rdi+tls_writeseq_ofs]
	mov	r11d, ecx
	mov	[rsp+24], rcx
	mov	[rsp+32], rbx
	mov	[rsp+40], r12
	and	r9d, not 2047
	mov	rbx, rdi
	bswap	r10
	mov	[rsp+48], r13
	mov	[rsp+56], r14
	mov	[rsp+64], r15
	mov	r12d, r9d
	bswap	r11d
	; rbx will persist as the tls object
	; so r12d will persist as our total stack modification size
	sub	rsp, r9
	; so now, our record layer header is going to start at rsp+3 for 5 bytes, our TLSCipherText will start at rsp+8 per the aforementioned
	; alignment issues

	; we can use our space temporarily though to do our initial mac update:
	; update our hmac with big endian versions of: 64 bit sequence number, type, version (negotiated), and the length of our actual message (ecx)
	mov	r13d, [rbx+tls_version_ofs]

	shr	r11d, 16
	mov	[rsp], r10
	mov	byte [rsp+8], sil
	mov	word [rsp+9], r13w
	mov	word [rsp+11], r11w

	lea	rdi, [rbx+tls_cw_hmac_ofs]
	mov	rsi, rsp
	mov	edx, 13
	call	qword [rdi+hmac_macupdate_ofs]	; update the mac with 13 bytes

	; update our hmac with the message itself
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	mov	rsi, [rsp+r12+16]
	mov	edx, [rsp+r12+24]
	call	qword [rdi+hmac_macupdate_ofs]	; update the mac with our message itself

	; so now, we can begin constructing the actual goods
	mov	eax, [rsp+r12+8]		; the message type
	shl	r13d, 8
	mov	ecx, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	or	r13d, eax
	shl	ecx, 6
	mov	[rsp+3], r13d
	; first 3 bytes of the header written

	; now we need our blocklen, ivlen, maclen from our cipherspecs
	mov	r9d, [rcx+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	mov	r10d, [rcx+tls$cipherspecs+tls_cipherspec_maclen_ofs]
	xor	r11d, r11d
	mov	eax, 1
	mov	r8d, [rcx+tls$cipherspecs+tls_cipherspec_blocklen_ofs]
	; if TLS version is 1.0 (0x103 in our version dword), we are not adding an explicit IV to the message
	cmp	dword [rbx+tls_version_ofs], 0x103
	cmove	r9d, r11d
	add	eax, r10d
	add	eax, r9d
	; now we need to round all that up to the nearest blocksize
	mov	edx, r8d
	sub	edx, 1
	add	eax, dword [rsp+r12+24]		; message length itself
	; so eax now contains ivlen (only if TLS1.1 or better) + msg length + mac length + 1
	; store this value temporarily before we round it upward
	mov	r15d, eax
	; round up to the nearest block length
	add	eax, edx
	not	edx
	and	eax, edx
	; so now eax is our rounded up to the nearest blocksize in length
	; we can add this to rsp+6
	mov	byte [rsp+6], ah
	mov	byte [rsp+7], al
	; establish our starting pointer:
	lea	r13, [rsp+8]
	; save our total length
	mov	r14d, eax
	mov	[rsp+r12+72], rax
	; compute our padding length:
	sub	eax, r15d
	mov	r15d, eax		; r15b is our padding value
	; if ivlen (sitting in r9d still) is nonzero, we need an explicit IV prepended to our output
	test	r9d, r9d
	jz	.cbc_noexplicit_iv
if defined tls_notjustaes
	mov	rdi, r13
	mov	esi, r9d
	add	r13, r9			; update our output pointer
	call	rng$block
else
	call	rng$u64
	mov	[r13], rax
	call	rng$u64
	mov	[r13+8], rax
	add	r13, 16
end if
calign
.cbc_noexplicit_iv:
	; add our message to the block
	mov	rdi, r13
	mov	rsi, [rsp+r12+16]	; original message buffer
	mov	edx, [rsp+r12+24]	; original message length
	; update r13 for adding the mac
	add	r13, rdx
	call	memcpy
	; next we need our mac on the end
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	mov	rsi, r13
	mov	edx, [rdi+hmac_macsize_ofs]	; the length of the mac itself
	; update r13 for adding our padding value
	add	r13, rdx
	call	hmac$final
	; add our padding bytes
	mov	rdi, r13
	mov	esi, r15d		; our padding value
	mov	edx, r15d
	add	edx, 1
	; we won't be adding anything past this point, so we don't need to worry about updating r13 again
	call	memset

if tlsdebug
	; debug
	mov	rdi, .preencstr
	call	string$to_stdoutln
	lea	rdi, [rsp+3]
	mov	esi, r14d
	add	esi, 5
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	; so now, rsp+8 is the start of the goods we need to CBC
	; our total buf size is sitting in r14d, we need to get the block length out again and store it somewhere convenient
if defined tls_notjustaes
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	r13d, [rax+tls$cipherspecs+tls_cipherspec_blocklen_ofs]
	
	; MULTICIPHER MOD REQUIRED:
	; xor the first block with our localiv
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localiv_ofs]
	lea	rdi, [rsp+8]
	mov	edx, r13d
	call	memxor
else
	; since we know AES is 16 byte blocks, no sense in calling memxor
	mov	rcx, [rbx+tls_cw_ofs+tls_cstate_localiv_ofs]
	mov	rdx, [rbx+tls_cw_ofs+tls_cstate_localiv_ofs+8]
	xor	[rsp+8], rcx
	xor	[rsp+16], rdx
end if

	; encrypt the first block
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	lea	rsi, [rsp+8]
	; MULTICIPHER MOD REQUIRED:
	call	aes$encrypt

	; use r15 for our block pointer
	lea	r15, [rsp+8]		; pointed at first block again for our loop commencement
if defined tls_notjustaes
	sub	r14d, r13d		; reduce our total length by the block we just did
else
	sub	r14d, 16
end if
	jz	.cbc_alldone
calign
.cbc_loop:

if defined tls_notjustaes
	; MULTICIPHER MOD REQUIRED
	lea	rdi, [r15+r13]		; "this" block
	mov	rsi, r15		; "previous" block
	mov	edx, r13d
	; move r15 up to the "this" block
	add	r15, r13
	call	memxor
else
	; since we know AES is 16 byte blocks, no sense in calling memxor
	mov	rcx, [r15]
	mov	rdx, [r15+8]
	xor	[r15+16], rcx
	xor	[r15+16+8], rdx
	; move r15 up to the "this" block
	add	r15, 16
end if
	; encrypt block at r15
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	mov	rsi, r15
	; MULTICIPHER MOD REQUIRED:
	call	aes$encrypt
if defined tls_notjustaes
	sub	r14d, r13d
else
	sub	r14d, 16
end if
	jnz	.cbc_loop
calign
.cbc_alldone:
	; set our localiv to the last block
if defined tls_notjustaes
	lea	rdi, [rbx+tls_cw_ofs+tls_cstate_localiv_ofs]
	mov	rsi, r15
	mov	edx, r13d
	call	memcpy
else
	lea	rdi, [rbx+tls_cw_ofs+tls_cstate_localiv_ofs]
	mov	rax, [r15]
	mov	rcx, [r15+8]
	mov	[rdi], rax
	mov	[rdi+8], rcx
end if

if tlsdebug
	; debug
	mov	rdi, .encsend
	call	string$to_stdoutln
	lea	rdi, [rsp+3]
	mov	esi, [rsp+r12+72]
	add	esi, 5
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	; last but not least, send our goods down the wire
	mov	rdi, [rbx+io_child_ofs]
if tlsdebug
	; sanity check only
	test	rdi, rdi
	jz	.breakpoint
	; end sanity check
end if

	lea	rsi, [rsp+3]
	mov	edx, [rsp+r12+72]		; our saved buffer length (not including header)
	add	edx, 5				; + the header
	mov	rcx, [rdi]			; its vtable
if epoll_nodelay
	cmp	dword [rsp+r12+12], 1
	je	.withccs
end if
	call	qword [rcx+io_vsend]


	; increment our write sequence
	add	qword [rbx+tls_writeseq_ofs], 1

	; restore our stackframe and cleanup
	add	rsp, r12

	mov	rbx, [rsp+32]
	mov	r12, [rsp+40]
	mov	r13, [rsp+48]
	mov	r14, [rsp+56]
	mov	r15, [rsp+64]
	add	rsp, 80
	epilog
if epoll_nodelay
calign
.withccs:
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x14
	sub	rsp, 8
	mov	dword [rsp+5], eax
	mov	word [rsp+9], 0x0101
	sub	rsi, 6
	add	edx, 6
	call	qword [rcx+io_vsend]
	add	rsp, 8
	
	; increment our write sequence
	add	qword [rbx+tls_writeseq_ofs], 1

	; restore our stackframe and cleanup
	add	rsp, r12

	mov	rbx, [rsp+32]
	mov	r12, [rsp+40]
	mov	r13, [rsp+48]
	mov	r14, [rsp+56]
	mov	r15, [rsp+64]
	add	rsp, 80
	epilog
end if
if tlsdebug
cleartext .encsend, 'tls$encrypt, sending:'
cleartext .preencstr, 'tls$encrypt, pre-encryption, block looks like:'
end if
calign
.aead:
	; AEAD Ciphers (GCM in our case)

calign
.plaintext:
	; the only time this can happen is if the initial handshake resulted in kakked encryption keys, at which point
	; we send an alert with a death notification, which is most likely decrypt_failed
	mov	r8d, ecx
	mov	r9d, ecx
	mov	r13d, ecx
	and	r8d, 0xff00
	add	r9d, 2047
	add	r13d, 5
	and	ecx, 0xff
	shl	r8d, 16
	and	r9d, not 2047
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12d, r9d
	sub	rsp, r9
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, esi
	or	eax, r8d
	mov	dword [rsp], eax
	mov	byte [rsp+4], cl
	lea	rdi, [rsp+5]
	mov	rsi, rdx
	mov	edx, r13d
	sub	edx, 5
	call	memcpy
	; so now, rsp for r13d bytes is what needs to go out
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	edx, r13d
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	add	rsp, r12
	pop	r13 r12 rbx
	epilog
if tlsdebug
calign
.breakpoint:
	breakpoint
	; sanity only here
end if

end if

if used tls$decrypt | defined include_everything
	; four arguments: rdi == our tls object, rsi == ptr to tls record layer, edx == length of same
	; depending on the current read state, decrypt accordingly, append result to the recordbuf
	; returns 0 in eax if no fatality occurred, 1 if we raised a fatal error
falign
tls$decrypt:
	prolog	tls$decrypt
	; first up: see if we are dealign with a fragment from a previous read, and typecheck that they are both the same
	mov	r8, [rdi+tls_recordbuf_ofs]
	movzx	r9d, byte [rsi]
	movzx	r10d, word [rsi+1]
	movzx	eax, word [rsi+3]
	xchg	ah, al
	cmp	dword [r8+buffer_user_ofs], 0
	jne	.checkfragment
calign
.proceed:
	mov	[r8+buffer_user_ofs], r9d	; save its type for when we are done
	; so here, either we are a fresh record, or we are a continuation fragment with the same type
	; if type is < 0x17 and the record layer length is zero, puke
	cmp	r9d, 0x17
	je	.nolengthcheck
	test	eax, eax
	jz	.error
calign
.nolengthcheck:
	; if there is no cipher set for our current read state, we are done.
	cmp	dword [rdi+tls_cr_ofs+tls_cstate_ciphervalid], 0
	je	.plaintext
	; otherwise, we have work to do
	; if our length is not a multiple of the block length, die.
	mov	r10d, [rdi+tls_cr_ofs+tls_cstate_cipherindex]
	shl	r10d, 6
	mov	r11d, [r10+tls$cipherspecs+tls_cipherspec_blocklen_ofs]
	test	r11d, r11d
	jz	.aead
	sub	r11d, 1
	test	eax, r11d
	jnz	.error
	add	r11d, 1

	push	rbp rbx r12 r13 r14 r15
	; we'll use rbp as our "last cipher text pointer" (because we need to swap them around)
	mov	rbx, rdi
	mov	r12d, eax		; save our total length
	mov	r13d, r11d		; our block length
	mov	r14d, eax		; save our total length
	lea	r15, [rsi+5]		; skip the record layer header
	shl	r11d, 1

	push	rsi

	; we also need room for two blocks worth on our stack
	sub	rsp, r11
	lea	rbp, [rsp+r13]		; set rbp to second block spot

	; copy the first crypted block into our first block spot
	mov	rdi, rsp
	mov	rsi, r15
	mov	edx, r13d
	call	memcpy

	; decrypt the first block
	lea	rdi, [rbx+tls_cr_cipher_ofs]
	mov	rsi, r15
	; MULTICIPHER MOD REQUIRED:
	call	aes$decrypt

if defined tls_notjustaes
	; MULTICIPHER MOD REQUIRED:
	; now xor it with our remoteiv
	mov	rdi, r15
	lea	rsi, [rbx+tls_cr_ofs+tls_cstate_remoteiv_ofs]
	mov	edx, r13d
	call	memxor
else
	; since we know AES is 16 bytes, no sense in calling memxor
	mov	rcx, [rbx+tls_cr_ofs+tls_cstate_remoteiv_ofs]
	mov	rdx, [rbx+tls_cr_ofs+tls_cstate_remoteiv_ofs+8]
	xor	[r15], rcx
	xor	[r15+8], rdx
end if

	sub	r14d, r13d		; reduce our total length by the block we just did
	jz	.cbc_alldone
	add	r15, r13
calign
.cbc_loop:
	; copy the crypted block into rbp
	mov	rdi, rbp
	mov	rsi, r15
	mov	edx, r13d
	call	memcpy

	; decrypt block at r15
	lea	rdi, [rbx+tls_cr_cipher_ofs]
	mov	rsi, r15
	; MULTICIPHER MOD REQUIRED:
	call	aes$decrypt

	; swap rbp
	mov	rax, rsp
	lea	rcx, [rsp+r13]
	cmp	rbp, rsp
	cmove	rbp, rcx
	cmovne	rbp, rax

if defined tls_notjustaes
	; xor it with our previous crypted block, which is in rbp
	mov	rdi, r15
	mov	rsi, rbp
	mov	edx, r13d
	call	memxor
else
	; since we know AES is 16 bytes, no sense in calling memxor
	mov	rcx, [rbp]
	mov	rdx, [rbp+8]
	xor	[r15], rcx
	xor	[r15+8], rdx
end if

	add	r15, r13
	sub	r14d, r13d
	jnz	.cbc_loop
calign
.cbc_alldone:
	; swap rbp once more to get the real last crypted block
	mov	rax, rsp
	lea	rcx, [rsp+r13]
	cmp	rbp, rsp
	cmove	rbp, rcx
	cmovne	rbp, rax
	
	; set our localiv to the last block
	lea	rdi, [rbx+tls_cr_ofs+tls_cstate_remoteiv_ofs]
	mov	rsi, rbp
	mov	edx, r13d
	call	memcpy
	mov	eax, r13d
	shl	eax, 1

	add	rsp, rax
	pop	rsi
	lea	r15, [rsi+5]		; skip the record layer header

if tlsdebug
	; debug
	push	rsi
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	rdi, r15
	mov	esi, r12d
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rsi
	lea	r15, [rsi+5]
	; end debug
end if

	; next up: check padding

	; so at this stage, rsi is still valid, rbx == our tls object, r12d has our total length, r13d has our block length, r15 is pointed at start of content
	; the only way we can tell if the decryption was valid or not is to check the padding value(s) at the end
	; and if it/they are bad, puke a bad_record_mac alert and die.
	mov	ecx, r12d
	sub	ecx, 1
	movzx	eax, byte [r15+rcx]
	cmp	eax, r12d			; padding length value in eax
	jae	.bad_record_mac
	
	mov	edx, r12d
	sub	edx, eax
	sub	edx, 1				; start of where the padding bytes need to be
	mov	ecx, eax
	test	eax, eax
	jz	.zeropadding
calign
.padcheck:
	cmp	byte [r15+rdx], al
	jne	.bad_record_mac
	add	edx, 1
	sub	ecx, 1
	jnz	.padcheck
calign
.zeropadding:
	; next up: check hmac
	add	eax, 1
	; get back our cipherspecs so we can compute our lengths
	mov	r10d, [rbx+tls_cr_ofs+tls_cstate_cipherindex]
	shl	r10d, 6
	mov	r8d, [r10+tls$cipherspecs+tls_cipherspec_maclen_ofs]
	mov	r9d, [r10+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	xor	r11d, r11d
	; if TLS version is 1.0 (0x103 in our version dword), we are not adding an explicit IV to the message
	cmp	dword [rbx+tls_version_ofs], 0x103
	cmove	r9d, r11d

	mov	ecx, r8d
	add	ecx, eax
	add	ecx, r9d
	cmp	r12d, ecx
	jb	.bad_record_mac			; don't die with a specific error, just puke back the same bad_record_mac

	; we need to hang onto our value in ecx so we can compute the plaintext length
	push	rcx

	mov	edi, [rsi]			; first byte == our record type, next two == record version

	; we need our computed length of the goodies, which is r12d - ecx
	; save our pad size
	mov	r14d, eax
	; save our explicit iv length
	mov	ebp, r9d
	mov	eax, r12d
	sub	eax, ecx
	
	; shore up some space for our hmac goodies
if use_movbe
	movbe	rdx, [rbx+tls_readseq_ofs]
	sub	rsp, 64
else
	mov	rdx, [rbx+tls_readseq_ofs]
	sub	rsp, 64
	bswap	rdx
end if
	mov	[rsp], rdx
	mov	[rsp+8], edi			; copies one more that we really didn't want
	xchg	ah, al
	mov	word [rsp+11], ax

if tlsdebug
	; debug
	mov	rdi, .macstr
	call	string$to_stdoutln
	mov	rdi, rsp
	mov	esi, 13
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, rsp
	mov	edx, 13
	call	qword [rdi+hmac_macupdate_ofs]	; update the mac with 13 bytes

	; update our hmac with the message itself
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [r15+rbp]
	mov	edx, r12d			; total record length
	sub	edx, dword [rsp+64]		; our earlier saved computed goods
	call	qword [rdi+hmac_macupdate_ofs]	; update the mac with our message itself
	; so now we can do the final into rsp
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, rsp
	call	hmac$final

	; get our mac length back out
	mov	r10d, [rbx+tls_cr_ofs+tls_cstate_cipherindex]
	shl	r10d, 6
	mov	r8d, [r10+tls$cipherspecs+tls_cipherspec_maclen_ofs]
	add	r8d, r14d

	lea	r9, [rbx+tls_cr_hmac_ofs]
	mov	ecx, r12d
	sub	ecx, r8d
	lea	rdi, [r15+rcx]
	mov	rsi, rsp
	mov	edx, [r9+hmac_macsize_ofs]
	call	memcmp
	cmp	eax, 0
	jne	.bad_record_mac_stackmod

	; otherwise, recompute our plaintext length
	mov	edx, r12d			; total record length
	sub	edx, dword [rsp+64]		; our earlier saved computed goods
	; now add it to our record buf
	lea	rsi, [r15+rbp]
	mov	rdi, [rbx+tls_recordbuf_ofs]
	; store the length that we computed
	add	dword [rdi+buffer_user_ofs+4], edx
	call	buffer$append

	add	qword [rbx+tls_readseq_ofs], 1

	add	rsp, 72

	pop	r15 r14 r13 r12 rbx rbp
	xor	eax, eax
	epilog
if tlsdebug
cleartext .macstr, 'tls$decrypt, 13 bytes of mac ghost is:'
end if
calign
.bad_record_mac:
if tls_blacklist
	; these don't happen under normal "play nice" operating conditions, so, if we are in server mode
	; and tls blacklisting is enabled, add them
	cmp	dword [rbx+tls_clientmode_ofs], 0
	jne	.bad_record_mac_skipblacklist
	mov	rdi, [tls$blacklist]
	mov	esi, [rbx+tls_raddr_ofs+4]
	call	blacklist$add
calign
.bad_record_mac_skipblacklist:
end if
	; send a fatal alert with bad_record_mac and bailout
	mov	rdi, rbx
	mov	esi, tls_alert_fatal
	mov	edx, tls_alert_bad_record_mac
	call	tls$send_alert

	pop	r15 r14 r13 r12 rbx rbp
	mov	eax, 1		; fatality
	epilog
calign
.bad_record_mac_stackmod:
if tls_blacklist
	; these don't happen under normal "play nice" operating conditions, so, if we are in server mode
	; and tls blacklisting is enabled, add them
	cmp	dword [rbx+tls_clientmode_ofs], 0
	jne	.bad_record_mac_skipblacklist2
	mov	rdi, [tls$blacklist]
	mov	esi, [rbx+tls_raddr_ofs+4]
	call	blacklist$add
calign
.bad_record_mac_skipblacklist2:
end if
	; send a fatal alert with bad_record_mac and bailout
	mov	rdi, rbx
	mov	esi, tls_alert_fatal
	mov	edx, tls_alert_bad_record_mac
	call	tls$send_alert

	add	rsp, 72

	pop	r15 r14 r13 r12 rbx rbp
	mov	eax, 1		; fatality
	epilog
calign
.plaintext:
	; store the length that we computed
	add	dword [r8+buffer_user_ofs+4], eax	; append the record layer length
	; append the fragment only to the record buffer, our specified length is in eax
	mov	rdi, r8		; recordbuf
	add	rsi, 5		; skip the content type, protocol version, and length header
	mov	edx, eax	; the length
	call	buffer$append
	xor	eax, eax
	epilog
if tlsdebug
cleartext .debugstr, 'tls$decrypt, AES decryption result:'
end if
calign
.aead:
	; all our ciphers are CBC at the moment.. so this won't happen during normal runtime
	breakpoint
calign
.checkfragment:
	cmp	r9d, [r8+buffer_user_ofs]
	je	.proceed
	mov	eax, 1		; fatality
	epilog
calign
.error:
	mov	eax, 1		; fatality
	epilog

end if

if used tls$process_alert | defined include_everything
	; three arguments: rdi == our tls object, esi == level, edx == description
	; we return nonzero in eax if we want to immediately die
falign
tls$process_alert:
	prolog	tls$process_alert
	xor	eax, eax		; don't kill us
	mov	ecx, 1
	cmp	esi, tls_alert_warning
	cmovne	eax, ecx
	epilog

end if

if used tls$process_handshake | defined include_everything
	; four arguments: rdi == our tls object, rsi == handshake message buffer, edx == handshake type, ecx == length of handshake message
	; we return nonzero in eax if we want to immediately die
falign
tls$process_handshake:
	prolog	tls$process_handshake
	; we require a good deal of state based sanity checking here for order of receipt, etc.
	test	edx, edx
	jz	.hello_request		; special case for HelloRequest, bypassing the expectmin/expectmax
	cmp	edx, 20
	ja	.invalid
	; make sure this handshake type is within our expected ranges
	cmp	edx, [rdi+tls_expectmin_ofs]
	jb	.invalid
	cmp	edx, [rdi+tls_expectmax_ofs]
	ja	.invalid

	; before we fly off, we need to add this message to our hacc
	push	rdi rsi rdx rcx
	mov	rdi, [rdi+tls_hacc_ofs]
	sub	rsi, 4
	mov	edx, ecx
	add	edx, 4
	call	buffer$append

if tlsdebug
	;debug
	mov	rdi, .debugtype
	call	string$to_stdout
	mov	edi, [rsp+8]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, .debugstr
	call	string$to_stdoutln
	mov	edi, [rsp]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	;end debug
end if

	pop	rcx rdx rsi rdi

	jmp	qword [rdx*8+.typedispatch]

if tlsdebug
cleartext .debugtype, 'tls$processhandshake for type: '
cleartext .debugstr, 'tls$processhandshake initial, appending to handshake accumulator:'
end if

calign
.return_noerror:
	xor	eax, eax		; don't kill us off
	epilog
calign
.hello_request:
	; if we are not a client, this is an error, die (even though the RFC says it is not intended to establish which side is client/server)
	cmp	dword [rdi+tls_clientmode_ofs], 1
	jne	.invalid
	; we are a client ... so, if we are already in the middle of a handshake
	; the RFC says to ignore this message
	cmp	dword [rdi+tls_expectmax_ofs], 0
	jne	.return_noerror
	; otherwise, we are to send a new ClientHello, set our new expectmin/expectmax, and continue

if tlsdebug
	; TODO
	breakpoint
else
	jmp	.return_noerror
end if

calign
.client_hello:
	; .failed sends an alert, .invalid dies a thousand deaths
	; contrary to some other implementations, we are intentionally not very descriptive to the far
	; end when we encounter any errors
	cmp	dword [rdi+tls_clientmode_ofs], 0
	jne	.invalid
	; we won't allow client initiated renegotiation, but we'll reply nicely with a warning
	cmp	dword [rdi+tls_open_ofs], 0
	jne	.warn_no_renegotiation
	; if we are not in a handshake/expecting a handshake, and we receive this, die a thousand deaths
	cmp	dword [rdi+tls_expectmax_ofs], 0
	je	.invalid

	; compute our minimum client_hello length, and very ecx is at least this much, or die
	; first two bytes == protocol version offered by the client
	; next 32 bytes are big endian ctime and 28 bytes of entropy
	; length encoded up-to-32 byte session id is next (variable)
	; length encoded list of supported CipherSuites (each of which is 2 bytes) (length is up to 2^16-2, so 2 byte length encoding)
	; length encoded list of compression methods, single byte, length is 2^8-1, single byte length encoding
	; end of record if no extensions are supported, otherwise a length encoded Extension list, length is 2 bytes
	; ---
	cmp	ecx, 40		; absolute minimum # of bytes
	jb	.invalid
	movzx	eax, word [rsi]
	cmp	al, 3
	jne	.failed		; major version must be 3 or we do send back a proper handshake failed alert
	; ceiling our version number minor to 3
	cmp	ah, 3
	jbe	.client_hello_minor_okay
	mov	ah, 3
calign
.client_hello_minor_okay:
	test	ah, ah
	jz	.client_hello_sslv3
	mov	[rdi+tls_version_ofs], eax
	mov	r8, [rsi+2]
	mov	r9, [rsi+10]
	mov	r10, [rsi+18]
	mov	r11, [rsi+26]
	; pending read state's remoterandom
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom], r8
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom+8], r9
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom+16], r10
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom+24], r11
	movzx	eax, byte [rsi+34]
	cmp	eax, 32
	ja	.invalid

if tls_server_sessioncache

	; if the client provided no session id, don't bother at all and just skip it
	test	eax, eax
	jz	.client_hello_nosessionid
	
	; so our sessioncache is an insert-order stringmap, but its keys aren't _real_ strings
	; since we know how string$compare works, actual byte data sitting in a string isn't
	; a bad thing, so we can use it for fixed-length keys
	
	; now, we know all our session ids we generate are precisely 32 bytes, so if it isn't 32
	; proceed with a new one
	cmp	eax, 32
	jne	.client_hello_nosessionid

	mov	r8, [rsi+35]
	mov	r9, [rsi+43]
	mov	r10, [rsi+51]
	mov	r11, [rsi+59]

	mov	dword [rdi+tls_sessionidlen_ofs], 32
	mov	[rdi+tls_sessionid_ofs+8], r8
	mov	[rdi+tls_sessionid_ofs+16], r9
	mov	[rdi+tls_sessionid_ofs+24], r10
	mov	[rdi+tls_sessionid_ofs+32], r11

	push	rdi rsi rcx
	
	lea	rsi, [rdi+tls_pr_ofs]
	lea	rdi, [rdi+tls_sessionid_ofs+8]
	call	tls$sessioncache_get
	pop	rcx rsi rdi
	test	rax, rax
	jnz	.client_hello_fromsessioncache
	; otherwise, undo our stack and proceed
	mov	eax, 32
calign
.client_hello_nosessionid:

end if
	; session id is at rsi+35 for eax bytes, skip it and decrement ecx
	lea	rsi, [rsi+rax+35]
	sub	ecx, 35
	cmp	ecx, eax
	jb	.invalid
	sub	ecx, eax
	; so now, rsi is pointing to _after_ the session id
	; ecx has the number of bytes that remain after it, make sure there is at least 5 bytes left
	cmp	ecx, 5
	jb	.invalid
	; we are sitting on the length encoded list of supported CipherSuites
	; we need to verify that we have enough data for the entire list (each is 2 bytes)
	; then walk and pick one from our own (we pick the first one we support that the client offers)
	movzx	eax, word [rsi]
	xchg	ah, al
	; this is our # of _bytes_ not elements that we have in our CipherSuites list, make sure it is
	; nonzero and that we have enough room left for it
	sub	ecx, 2
	jz	.invalid
	test	eax, eax
	jz	.invalid
	cmp	ecx, eax
	jb	.invalid
	; otherwise, we have a nonzero list of CipherSuites, walk them
	add	rsi, 2

	; scan for the 0x00, 0xff SCSV
	push	rsi rax rcx
calign
.client_hello_scsvsearch:
	cmp	word [rsi], 0xff00
	je	.client_hello_foundscsv
	add	rsi, 2
	sub	ecx, 2
	jz	.invalid
	sub	eax, 2
	jnz	.client_hello_scsvsearch
	pop	rcx rax rsi

calign
.client_hello_cipherselection:
	; depending on whether we were brought up with DSA or RSA cert, depends on which ones we need to pay attention to
if tls_server_cipher_order
	xor	r8d, r8d		; our index
	mov	r9d, tls_ciphersuite_size shr 1 ; max index
	push	rsi rax rcx
end if

	mov	r10, [rdi+tls_localcert_ofs]
	cmp	qword [r10+X509_privatekey_ofs], 0
	je	.client_hello_choosecipher_dsa

if tls_server_cipher_order
	; RSA only, go through our list first
calign
.client_hello_choosecipher:
	mov	r11d, r8d
	shl	r11d, 6
	cmp	dword [r11+tls$cipherspecs+tls_cipherspec_kexalgo_ofs], tls_kex_dhe_dss
	je	.client_hello_choosecipher_skip
	movzx	edx, word [r8*2+tls$ciphersuites]	; the one we're looking for
	mov	rcx, [rsp]
	mov	rax, [rsp+8]
	mov	rsi, [rsp+16]
calign
.client_hello_choosecipher_walk:
	cmp	dx, [rsi]
	je	.client_hello_cipherfound
	add	rsi, 2
	sub	ecx, 2
	jz	.invalid		; sanity only, remove me for production (TODO)
	sub	eax, 2
	jnz	.client_hello_choosecipher_walk
	; move to our next one
calign
.client_hello_choosecipher_skip:
	add	r8d, 1
	cmp	r8d, r9d
	jne	.client_hello_choosecipher
	; if we made it all the way to here, no deal
	add	rsp, 24
	jmp	.failed

else

	; otherwise, we are looking for RSA only ones
calign
.client_hello_choosecipher:
	movzx	edx, word [rsi]
	add	rsi, 2
	sub	ecx, 2
	jz	.invalid		; sanity only, remove me for production (TODO)
	; walk our own ciphersuite list and see if we can find it
	xor	r8d, r8d		; our index
	mov	r9d, tls_ciphersuite_size shr 1	; max index
calign
.client_hello_choosecipher_walk:
	mov	r11d, r8d
	shl	r11d, 6
	cmp	dword [r11+tls$cipherspecs+tls_cipherspec_kexalgo_ofs], tls_kex_dhe_dss
	je	.client_hello_choosecipher_skip
	cmp	dx, word [r8*2+tls$ciphersuites]
	je	.client_hello_cipherfound
calign
.client_hello_choosecipher_skip:
	add	r8d, 1
	cmp	r8d, r9d
	jne	.client_hello_choosecipher_walk
	; if we made it through our list and didn't find it, go to the next offered cipher
	sub	eax, 2
	jnz	.client_hello_choosecipher
	jmp	.failed			; we walked our list and didn't find one that we support

end if

calign
.client_hello_foundscsv:
	add	dword [rdi+tls_secreneg_ofs], 1
	pop	rcx rax rsi

	; if we already have an open encryption context, bailout because this is invalid
	cmp	dword [rdi+tls_open_ofs], 0
	jne	.failed			; this will send a handshake failed error

	jmp	.client_hello_cipherselection

if tls_server_sessioncache

if tlsdebug
cleartext .sessdebugstr, 'Client passed Session ID: '
end if

calign
.client_hello_fromsessioncache:
	; so at this point, our tls_pr_ofs has already been filled
	mov	r8, [_epoll_tv_secs]
	push	rbx r12 r13 r14 r15
	sub	rsp, 16384

	mov	rbx, rdi
	mov	r12, rsp

	; now we can compose our ServerHelloDone
	mov	r14d, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	; get our ciphersuite bytes from there
	movzx	r13d, word [r14*2+tls$ciphersuites]

	mov	ecx, dword [_epoll_tv_secs]	; low order 32 bits of this is fine
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localrandom+4]
if use_movbe
	mov	esi, 28
	movbe	dword [rbx+tls_pr_ofs+tls_cstate_localrandom], ecx
else
	bswap	ecx
	mov	esi, 28
	mov	dword [rbx+tls_pr_ofs+tls_cstate_localrandom], ecx
end if
	call	rng$block

	; compose our serverhello
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	; our length is:
	; 4 for the handshake preface, 2 for proto version, 32 for our random, 33 for sessionid, 2 for ciphersuite, 1 for compression length
	; 74 bytes in total
	mov	dword [r12], eax
	add	r12, 4
	mov	byte [r12], 74
	add	r12, 1
	; so now, our handshake preface, which is first byte == 2 == server_hello, then 3 big endian bytes for the handshake length itself
	; which is 70 bytes
	mov	eax, 70
	shl	eax, 24
	or	eax, 2
	mov	dword [r12], eax
	add	r12, 4
	; next up is our proto version
	mov	eax, [rbx+tls_version_ofs]
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r12
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; byte for the sessionid length of 32
	mov	byte [r12], 32
	add	r12, 1
	mov	rdi, r12
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; next up, our 2 bytes for ciphersuite
	mov	dword [r12], r13d
	; now, since the low order bytes of that were our cipherindex, and the upper word is zero, we can just increment r12 by 3
	add	r12, 3
	; that completes our server_hello message, append just the handshake mesasge component to the hacc so we can hash it
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	mov	edx, 74
	call	buffer$append


	; so now, we need to fire off our ChangeCipherSpec, and our Finished message at the same time

	; we need to add the ChangeCipherSpec 6 bytes at the end
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x14			; protocol record layer and 0x14 == 20 == ChangeCipherSpec
	mov	dword [r12], eax
	mov	word [r12+4], 0x0101		; low order length = 1, change cipher spec byte = 1
	add	r12, 6

	; and now we can send the whole lot out
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	rdx, r12
	sub	rdx, rsp
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]


	xor	esi, esi
	xor	edx, edx
	call	.keycalc

	; copy the pending read state to the current write state (so that our setting the current write state isn't affected by
	; the incoming Finished encrypted message, mac keys, IVs, etc)
	lea	rdi, [rbx+tls_cw_ofs]
	lea	rsi, [rbx+tls_pr_ofs]
	mov	edx, tls_cstate_size
	call	memcpy

	; get our cipherindex
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; we need to initialize our current write hmac before we proceed:
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	call	qword [rax+tls$cipherspecs+tls_cipherspec_macalgo_ofs]
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; and we need to set its key, which is a flat call
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localmackey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	call	hmac$key

	; and we need to initialize our current write cipher with our key
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localenckey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; MULTICIPHER MOD REQUIRED:
	call	aes$init_encrypt

	; set our open flag indicating that we are write-ready
	mov	dword [rbx+tls_open_ofs], 1
	mov	qword [rbx+tls_writeseq_ofs], 0

	; set our expectmin/expectmax to be Finished
	mov	dword [rbx+tls_expectmin_ofs], 20
	mov	dword [rbx+tls_expectmax_ofs], 20

	; compose our finished message on the stack
	mov	dword [rsp], 0x0c000014		; low order byte == handshake msg_type == 20 == Finished, next byte is high order length, mid, 0x0c == 12 bytes length
	lea	rdx, [rbx+tls_cw_ofs+tls_cstate_mastersecret]
	mov	rcx, .sfin
	mov	rsi, rsp
	add	rsi, 4
	call	.verify_data

	; set our renegdata
	lea	rdi, [rbx+tls_renegdata_ofs+12]
	lea	rsi, [rsp+4]
	mov	edx, 12
	call	memcpy

	; add that straight into the hacc as well
	mov	rdi, [rbx+tls_hacc_ofs]
	mov	rsi, rsp
	mov	edx, 16
	call	buffer$append

	; fire that off encrypted
	mov	rdi, rbx
	mov	esi, 0x16			; record layer type == handshake
	mov	rdx, rsp
	mov	ecx, 16				; record layer length to encode
	call	tls$encrypt

	; channel not open yet, and we can't reset the hacc buf yet because we are waiting for the client changecipherspec and finished message now

	; restore our stackframe
	add	rsp, 16384
	pop	r15 r14 r13 r12 rbx

	xor	eax, eax			; don't kill us off
	epilog

end if

if tls_server_cipher_order
	; DSA only, go through our list
calign
.client_hello_choosecipher_dsa:
	mov	r11d, r8d
	shl	r11d, 6
	cmp	dword [r11+tls$cipherspecs+tls_cipherspec_kexalgo_ofs], tls_kex_dhe_rsa
	je	.client_hello_choosecipher_dsa_skip
	cmp	dword [r11+tls$cipherspecs+tls_cipherspec_kexalgo_ofs], tls_kex_rsa
	je	.client_hello_choosecipher_dsa_skip
	movzx	edx, word [r8*2+tls$ciphersuites]	; the one we're looking for
	mov	rcx, [rsp]
	mov	rax, [rsp+8]
	mov	rsi, [rsp+16]
calign
.client_hello_choosecipher_dsa_walk:
	cmp	dx, [rsi]
	je	.client_hello_cipherfound
	add	rsi, 2
	sub	ecx, 2
	jz	.invalid		; sanity only, remove me for production (TODO)
	sub	eax, 2
	jnz	.client_hello_choosecipher_dsa_walk
	; move to our next one
calign
.client_hello_choosecipher_dsa_skip:
	add	r8d, 1
	cmp	r8d, r9d
	jne	.client_hello_choosecipher_dsa
	; if we made it all the way to here, no deal
	add	rsp, 24
	jmp	.failed

else

calign
.client_hello_choosecipher_dsa:
	movzx	edx, word [rsi]
	add	rsi, 2
	sub	ecx, 2
	jz	.invalid		; sanity only, remove me for production (TODO)
	; walk our own ciphersuite list and see if we can find it
	xor	r8d, r8d
	mov	r9d, tls_ciphersuite_size shr 1	; max index
calign
.client_hello_choosecipher_dsa_walk:
	; make sure this is a dsa cipher on our end
	mov	r11d, r8d
	shl	r11d, 6
	cmp	dword [r11+tls$cipherspecs+tls_cipherspec_kexalgo_ofs], tls_kex_dhe_rsa
	je	.client_hello_choosecipher_dsa_skip
	cmp	dword [r11+tls$cipherspecs+tls_cipherspec_kexalgo_ofs], tls_kex_rsa
	je	.client_hello_choosecipher_dsa_skip
	cmp	dx, word [r8*2+tls$ciphersuites]
	je	.client_hello_cipherfound
calign
.client_hello_choosecipher_dsa_skip:
	add	r8d, 1
	cmp	r8d, r9d
	jne	.client_hello_choosecipher_dsa_walk
	; if we made it through our list and didn't find it, go to the next offered cipher
	sub	eax, 2
	jnz	.client_hello_choosecipher_dsa
	jmp	.failed			; we walked our list and didn't find one that we support


end if


calign
.client_hello_cipherfound:
if tls_server_cipher_order
	add	rsi, 2
	sub	ecx, 2
	add	rsp, 24
end if
	sub	eax, 2			; skip the one we did find in their list
	add	rsi, rax
	sub	ecx, eax
	jz	.invalid
	; so we have a cipher index sitting in r8d that matches
	mov	dword [rdi+tls_pr_ofs+tls_cstate_ciphervalid], 1
	mov	dword [rdi+tls_pr_ofs+tls_cstate_cipherindex], r8d

	; what is left is: compression methods list, and extensions list
	mov	qword [rdi+tls_ocspsupport_ofs], 0

	; if we have nonzero ocspresponses for our certificate(s), then
	; skip the compression list (if any), and see if the client sent us certificate status request

	; so the byte at rsi is the compression list length (if any)
	
	; followed by the extension list length (in bigendian word)
	movzx	eax, byte [rsi]
	add	rsi, 1
	sub	ecx, 1
	jz	.client_hello_skipextensions
	cmp	eax, ecx
	ja	.invalid
	add	rsi, rax
	sub	ecx, eax
	jz	.client_hello_skipextensions
	cmp	ecx, 2
	jb	.invalid
	; so ecx is nonzero, we need to preserve r8d, edx, rdi
	movzx	eax, word [rsi]
	xchg	ah, al
	add	rsi, 2
	sub	ecx, 2

	jz	.client_hello_skipextensions
	test	eax, eax
	jz	.client_hello_skipextensions
	cmp	eax, ecx
	ja	.invalid

	; otherwise, eax is the length in bytes of our extension list
	; we need to scan it looking for OCSP Stapling support
	xor	r10d, r10d
calign
.client_hello_extensionscan:
	movzx	r9d, word [rsi] ; extension type
	add	rsi, 2
	sub	eax, 2
	jz	.invalid
	cmp	eax, 2
	jb	.invalid
	movzx	ecx, word [rsi]	; length of the extension
	add	rsi, 2
	sub	eax, 2
	xchg	ch, cl
	cmp	ecx, eax
	ja	.invalid
	add	rsi, rcx
	sub	eax, ecx
	mov	r11d, r10d
	add	r11d, 1
	cmp	r9d, 0x500	; status_request
	cmove	r10d, r11d
	cmp	r9d, 0x1100	; status_request_v2
	cmove	r10d, r11d
	cmp	r9d, 0x1ff	; renegotation_info extension
	jne	.client_hello_notrenegotiation_info
	; we don't allow clients to renegotiate with us, so we don't have to check if we're open already and for the longer extension length
	; the length of the field must be precisely 1 and its length of the renegotiation_info must be zero
	cmp	ecx, 1
	jne	.failed
	cmp	byte [rsi-1], 0
	jne	.failed
	; otherwise, all good, add 1 to our segreneg
	add	dword [rdi+tls_secreneg_ofs], 1
	; fallthrough
calign
.client_hello_notrenegotiation_info:
	test	eax, eax
	jnz	.client_hello_extensionscan
	; if we made it to here, we successfully scanned through all presented extensions
	; so, r10d == 1 == status_request support, r10d == 2 == multi status support
	mov	[rdi+tls_ocspsupport_ofs], r10d
calign
.client_hello_skipextensions:

	; so if we got here, we don't really mind if the client did or did not specify RFC5746, since we don't allow
	; clients to renegotiate full-stop, if the MiTM scenario of spliced TLS connections did happen, we'd blow the whole
	; thing by responding with the no_renegotiation warning anyway

	; fire off our ServerHello, Certificate, and if OCSP, CertificateStatusList, and if DHE, ServerKeyExchange, and our ServerHelloDone

	; at the _very_ most, we'll need 32k worth of space to compose all three, if dh_bits == 16384 (cough)
	; then the dh params will require ~2k by themselves, and our certificates in binary form
	; and if the certificates we are using are also some insane size (16384 bit), and we have many certificates
	; all with OCSPResponse objects sitting in them, then we can still safely fit everything we need in 32kb
	;
	; TODO: make this stack size configurable for the server-send part of the equation, since
	; all production environments will have fixed parameter sizes that are known in advance
	;

	; we'll need our callee-saves since we have some work to do to compose our goods
	push	rbx r12 r13 r14 r15
	sub	rsp, 32768
	mov	rbx, rdi
	mov	r12, rsp
	mov	r13d, edx
	mov	r14d, r8d
	
	; rbx == our tls object
	; r12 == current pointer into our stack, total size to send == r12 - rsp
	; r13d == our ciphersuite bytes
	; r14d == our cipherindex
	; first up, we need to generate our local random 32 bytes
	; spec says the first four are ctime
	mov	ecx, dword [_epoll_tv_secs]	; low order 32 bits of this is fine
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localrandom+4]
if use_movbe
	mov	esi, 28
	movbe	dword [rbx+tls_pr_ofs+tls_cstate_localrandom], ecx
else
	bswap	ecx
	mov	esi, 28
	mov	dword [rbx+tls_pr_ofs+tls_cstate_localrandom], ecx
end if
	call	rng$block

	; generate a random [unique] sessionid... I am not sure how other implementations do this
	; we have two choices as I see it: actually random generated, or SHA256 of the client hello
	; providing the clienthello indeed contained a legit clientrandom, then since SHA256 won't
	; suffer collisions, we could do that...
	; TODO: make this a configuration choice, rng versus sha256 sessionid generation, for now since
	; sha256 is so much heavier than RNG, we'll shoot RNG based.. the odds of us generating
	; the same exact 32 byte rng sequence _inside_ the sessionid validity period is close enough
	; to zero for my liking
	mov	dword [rbx+tls_sessionidlen_ofs], 32
	; the sessionid_ofs preface 8 bytes of evil trickery is already set for us
	lea	rdi, [rbx+tls_sessionid_ofs+8]
	mov	esi, 32
	call	rng$block

	; compose our serverhello
	
	; load back up the version we saved before into eax
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16

	mov	dword [r12], eax
	add	r12, 4				; high order byte of our length is 0

	; so, options are:
	; 1) no OCSP and no secure renegotiation extension
	; 2) no OCSP and secure renegotiation extension
	; 3) OCSP and no secure renegotiation extension
	; 4) OCSP and secure renegotiation extension
	xor	eax, eax
	mov	r8d, 1
	cmp	dword [rbx+tls_secreneg_ofs], 0
	cmovne	eax, r8d
if tls_server_ocsp_stapling
	cmp	dword [rbx+tls_ocspsupport_ofs], 0
	je	.client_hello_serverhello_jump
	
	mov	dword [rbx+tls_ocspsupport_ofs], 0
	mov	rdi, [rbx+tls_localcert_ofs]
	mov	rsi, [rdi+X509_certificates_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	xor	r8d, r8d
	mov	r9d, 1
calign
.client_hello_ocspresponse_scan:
	mov	rcx, [rdx]	; the X509cert object
	cmp	qword [rcx+X509cert_ocspresponse_ofs], 0
	cmovne	r8d, r9d
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.client_hello_ocspresponse_scan
	test	r8d, r8d
	jz	.client_hello_serverhello_jump
	or	eax, 2
end if

calign
.client_hello_serverhello_jump:
	jmp	qword [rax*8+.client_hello_serverhello_jumptable]


dalign
.client_hello_serverhello_jumptable:
	dq	.client_hello_serverhello_noocsp_nosecreneg, .client_hello_serverhello_noocsp_secreneg
if tls_server_ocsp_stapling
	dq	.client_hello_serverhello_ocsp_nosecreneg, .client_hello_serverhello_ocsp_secreneg
end if


	; our length is:
	; 4 for the handshake preface, 2 for proto version, 32 for our random, 33 for sessionid, 2 for ciphersuite, 1 for compression length, 2 bytes for extension length,
	; 5 bytes for our secure renegotiation extension data if its initial, or 28 if secure renegotiating serverhello
	; 81 bytes in total, but only if we are initial not doing OCSP, 74 + 2 + 28 == 104 bytes if reneg

	; if we are doing OCSP, and the client supports it, _and_ we have valid OCSP responses, then we have to add 4 more bytes for the OCSP status request goods:
	; 2 byte for status_request{_v2} (5{17}), 2 byte empty length

if tls_server_ocsp_stapling


calign
.client_hello_serverhello_ocsp_nosecreneg:
	; otherwise, we have one or more ocspresponse buffers sitting in our certificate list
	; 80 bytes in total
	mov	byte [r12], 80
	add	r12, 1
	; and our handshake preface, which is first byte == 2 == server_hello, then 3 big endian bytes for the handshake length itself
	; which is 76 bytes
	mov	eax, 76
	shl	eax, 24
	or	eax, 2
	mov	dword [r12], eax
	add	r12, 4
	mov	dword [rbx+tls_ocspsupport_ofs], 1

	; next up is our proto version
	mov	eax, [rbx+tls_version_ofs]
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r12
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; byte for the sessionid length of 32
	mov	byte [r12], 32
	add	r12, 1
	mov	rdi, r12
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; next up, our 2 bytes for ciphersuite, we need our index back
	mov	dword [r12], r13d
	; now, since the low order bytes of that were our cipherindex, and the upper word is zero
	; we can just increment r12d by 3
	add	r12, 3

	; next up is the length of our extension list in bytes
	mov	word [r12], 0x400
	add	r12, 2

	; status_request_v2 == 17, status_request = 5
	mov	word [r12], 0x500
	mov	word [r12+2], 0
	add	r12, 4
	
	; that completes our server_hello message, append just the handshake message component to the hacc so we can hash it properly at Finished time
	; (the clienthello already was)
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	mov	edx, 80
	call	buffer$append
	jmp	.client_hello_serverhello_done

calign
.client_hello_serverhello_ocsp_secreneg:
	; otherwise, we have one or more ocspresponse buffers sitting in our certificate list
	; 80 bytes in total
	mov	byte [r12], 85
	add	r12, 1
	; and our handshake preface, which is first byte == 2 == server_hello, then 3 big endian bytes for the handshake length itself
	mov	eax, 81
	shl	eax, 24
	or	eax, 2
	mov	dword [r12], eax
	add	r12, 4
	mov	dword [rbx+tls_ocspsupport_ofs], 1

	; next up is our proto version
	mov	eax, [rbx+tls_version_ofs]
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r12
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; byte for the sessionid length of 32
	mov	byte [r12], 32
	add	r12, 1
	mov	rdi, r12
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; next up, our 2 bytes for ciphersuite, we need our index back
	mov	dword [r12], r13d
	; now, since the low order bytes of that were our cipherindex, and the upper word is zero
	; we can just increment r12d by 3
	add	r12, 3

	; next up is the length of our extension list in bytes
	mov	word [r12], 0x900
	add	r12, 2

	; status_request_v2 == 17, status_request = 5
	mov	word [r12], 0x500
	mov	word [r12+2], 0
	add	r12, 4

	; and our renegotiation_info, ff 01 00 01 00
	mov	dword [r12], 0x10001ff
	mov	byte [r12+4], 0x00
	add	r12, 5
	
	; that completes our server_hello message, append just the handshake message component to the hacc so we can hash it properly at Finished time
	; (the clienthello already was)
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	mov	edx, 85
	call	buffer$append
	jmp	.client_hello_serverhello_done

end if

calign
.client_hello_serverhello_noocsp_secreneg:

	; we need to add 7 bytes to our total length, 2 for the extension list, and +5 for our renegotiation_info
	mov	byte [r12], 81
	add	r12, 1
	; so now, our handshake preface, which is first byte == 2 == server_hello, then 3 big endian bytes for the handshake length itself
	; plus our extra 7
	mov	eax, 77
	shl	eax, 24
	or	eax, 2
	mov	dword [r12], eax
	add	r12, 4

	; next up is our proto version
	mov	eax, [rbx+tls_version_ofs]
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r12
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; byte for the sessionid length of 32
	mov	byte [r12], 32
	add	r12, 1
	mov	rdi, r12
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; next up, our 2 bytes for ciphersuite, we need our index back
	mov	dword [r12], r13d
	; now, since the low order bytes of that were our cipherindex, and the upper word is zero
	; we can just increment r12d by 3
	add	r12, 3
	
	; next up is the length of our extension list in bytes
	mov	word [r12], 0x500
	add	r12, 2

	; and our renegotiation_info, ff 01 00 01 00
	mov	dword [r12], 0x10001ff
	mov	byte [r12+4], 0x00
	add	r12, 5
	
	; that completes our server_hello message, append just the handshake message component to the hacc so we can hash it properly at Finished time
	; (the clienthello already was)
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	mov	edx, 81
	call	buffer$append
	jmp	.client_hello_serverhello_done
calign
.client_hello_serverhello_noocsp_nosecreneg:
	mov	byte [r12], 74
	add	r12, 1
	; so now, our handshake preface, which is first byte == 2 == server_hello, then 3 big endian bytes for the handshake length itself
	; which is 70 bytes
	mov	eax, 70
	shl	eax, 24
	or	eax, 2
	mov	dword [r12], eax
	add	r12, 4

	; next up is our proto version
	mov	eax, [rbx+tls_version_ofs]
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r12
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; byte for the sessionid length of 32
	mov	byte [r12], 32
	add	r12, 1
	mov	rdi, r12
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, 32
	add	r12, 32
	call	memcpy
	; next up, our 2 bytes for ciphersuite, we need our index back
	mov	dword [r12], r13d
	; now, since the low order bytes of that were our cipherindex, and the upper word is zero
	; we can just increment r12d by 3
	add	r12, 3
	
	; that completes our server_hello message, append just the handshake message component to the hacc so we can hash it properly at Finished time
	; (the clienthello already was)
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	mov	edx, 74
	call	buffer$append



calign
.client_hello_serverhello_done:
	; compose our Certificate message regardless of whether we are doing DHE or not (certificate == handshaketype 11)
	; so the certificate handshake message itself is a 3 byte length prefixed list of certificates, starting with our own
	; and each certificate is also prefaced with a 3 byte length prefix
	; so we can precompute our length ahead of time to compose the record layer length and the handshake preface

	; NOTE: when the new_server was setup, the validity of localcert/X509_certificates_ofs/etc was checked
	; so we do not do error checking here because they must already exist

	mov	rdi, [rbx+tls_localcert_ofs]
	; we need to iterate its certificates list, and walk forward with X509cert_derlen_ofs being added + 3 bytes each to
	; our total accumulated length
	mov	rsi, [rdi+X509_certificates_ofs]
	mov	r15d, 3			; 3 bytes length prefix total
	; load up the list item first position
	mov	rdx, [rsi+_list_first_ofs]
calign
.client_hello_certlength:
	; so our X509 cert is the qword at [rdx]
	mov	rcx, [rdx]
	add	r15d, 3
	add	r15d, dword [rcx+X509cert_derlen_ofs]
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jnz	.client_hello_certlength
	; so now, we have the total length of the certificate_list
	; so our outer layer length is r15d+4, handshake layer length is r15d
	; construct our recordlayer goods first
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	; go ahead and copy those 3 bytes into our buffer
	mov	dword [r12], eax
	add	r12, 3
	; outer layer length is r15d+4
	mov	eax, r15d
	add	eax, 4
	; we know this won't exceed 2^16-1, so we don't have to worry about fragmenting this
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	; so we have our 5 byte record layer header
	; next is our 4 byte handshake preface

	; save this pointer so we can add it to the hacc
	mov	r13, r12
	mov	eax, r15d
	bswap	eax
	or	eax, 11			; 11 == certificate handshaketype
	mov	dword [r12], eax
	add	r12, 4
	; next up is the vector length itself, 3 bytes, but it is _not_ including the original 3
	sub	r15d, 3
	mov	eax, r15d
	bswap	eax
	shr	eax, 8
	mov	dword [r12], eax
	add	r12, 3
	; so now, go through each certificate and add it
	mov	r15, [rsi+_list_first_ofs]
calign
.client_hello_addcert:
	; X509 cert is in the qword at [r15]
	mov	rcx, [r15]
	; we need to add this one's 3 byte length prefix
	mov	eax, dword [rcx+X509cert_derlen_ofs]
	mov	edx, eax
	bswap	eax
	shr	eax, 8
	mov	dword [r12], eax
	add	r12, 3
	mov	rsi, [rcx+X509cert_der_ofs]
	mov	rdi, r12
	add	r12, rdx
	call	memcpy
	mov	r15, [r15+_list_nextofs]
	test	r15, r15
	jnz	.client_hello_addcert

	; server certificate done

	; we have to add just the handshake part of that to our goods
	mov	rdi, [rbx+tls_hacc_ofs]
	mov	rsi, r13
	mov	rdx, r12
	sub	rdx, r13
	call	buffer$append

if tls_server_ocsp_stapling
	cmp	dword [rbx+tls_ocspsupport_ofs], 0
	je	.client_hello_nocertificatestatus
	; otherwise, we need to construct our CertificateStatus handshake message

	; NOTE: when browsers start supporting OCSP Multiple goods, we'll have to check the value sitting in tls_ocspsupport_ofs
	; for now, since not one browser I can find actually does it yet, we'll compose precisely _one_

	; send a certificate_status (22) handshake message, with the CertificateStatusType set to ocsp, and 3 byte length prefixed OCSPResponse
	; total length is first ocspresponse length + 3 byte length preface + 1 byte status_type
	
	mov	rdi, [rbx+tls_localcert_ofs]
	; we need to iterate its certificates list, and walk forward with X509cert_derlen_ofs being added + 3 bytes each to
	; our total accumulated length
	mov	rsi, [rdi+X509_certificates_ofs]
	mov	rdx, [rsi+_list_first_ofs]
calign
.client_hello_certstatus_findocsp:
	mov	rcx, [rdx]
	cmp	qword [rcx+X509cert_ocspresponse_ofs], 0
	jne	.client_hello_certstatus_foundocsp
	mov	rdx, [rdx+_list_nextofs]
	; we know that one exists, so we don't need sanity checking while traversing this list
	jmp	.client_hello_certstatus_findocsp;
calign
.client_hello_certstatus_foundocsp:
	; so our handshake layer length is the ocspresponse length + 4
	mov	rdx, [rcx+X509cert_ocspresponse_ofs]
	mov	r15, [rdx+buffer_length_ofs]
	add	r15d, 4
	; our record layer length is r15d+4
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	; copy those 3 bytes into our buffer
	mov	dword [r12], eax
	add	r12, 3
	; outer layer length is r15d+4
	mov	eax, r15d
	add	eax, 4
	; we know this won't exceed 2^16-1, so we don't have to worry about fragmenting this
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	; so we have our 5 byte record layer header
	; next is our 4 byte handshake preface
	; save this pointer so we can add it to the hacc
	mov	r13, r12
	mov	eax, r15d
	bswap	eax
	or	eax, 22		; certificate status handshake message
	mov	dword [r12], eax
	add	r12, 4
	; so now, we need the length - 4
	sub	r15d, 4
	mov	eax, r15d
	bswap	eax
	or	eax, 1		; CertificateStatusType == 1 == ocsp
	mov	dword [r12], eax
	add	r12, 4
	; and finally, add the OCSPResponse itself
	mov	rdi, r12
	mov	rsi, [rdx+buffer_itself_ofs]
	mov	rdx, r15
	add	r12, r15
	call	memcpy

	; so now our certificatestatus message is complete, next up, add that to our hacc
	mov	rdi, [rbx+tls_hacc_ofs]
	mov	rsi, r13
	mov	rdx, r12
	sub	rdx, r13
	call	buffer$append

if tlsdebug
	mov	rdi, .ocspdebug
	call	string$to_stdoutln
end if

calign
.client_hello_nocertificatestatus:
end if

	; now, depending on whether we are DHE or not determines whether we send a ServerKeyExchange or not
	shl	r14d, 6			; get our offset into the cipherspecs
	mov	eax, [r14+tls$cipherspecs+tls_cipherspec_kexalgo_ofs]
	cmp	eax, 1
	je	.client_hello_kex_dhe_dss
	cmp	eax, 2
	je	.client_hello_kex_dhe_rsa
	cmp	eax, 3
	je	.client_hello_kex_rsa


	; restore our stackframe
	mov	rdi, rbx
	add	rsp, 32768
	pop	r15 r14 r13 r12 rbx

	jmp	.failed
if tlsdebug
cleartext .ocspdebug, 'TLS, we added an OCSPResponse to our handshake'
end if
dalign
.sighashfuncs:
	; cheater function reference for signature creation when we construct our ServerKeyExchange
	dq	sha160$init, sha160$update, sha160$final, 20		; 0 is an invalid index
	dq	sha160$init, sha160$update, sha160$final, 20
	dq	sha256$init, sha256$update, sha256$final, 32
	dq	sha384$init, sha384$update, sha384$final, 48
	dq	sha512$init, sha512$update, sha512$final, 64
dalign
.sighashalgo:
	dw	0x0102, 0x0102, 0x0104, 0x0105, 0x0106
dalign
.sighashids:
	db	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	db	17 dup 0	; fill to align for 32 bytes per entry
	db	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	db	17 dup 0	; fill to align for 32 bytes per entry
	db	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
	db	13 dup 0	; fill to align for 32 bytes per entry
	db	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
	db	13 dup 0	; fill to align for 32 bytes per entry
	db	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
	db	13 dup 0	; fill to align for 32 bytes per entry
dalign
.sighashidlens:
	dd	15
	db	28 dup 0	; fill to align for 32 bytes per entry
	dd	15
	db	28 dup 0	; fill to align for 32 bytes per entry
	dd	19
	db	28 dup 0	; fill to align for 32 bytes per entry
	dd	19
	db	28 dup 0	; fill to align for 32 bytes per entry
	dd	19
	db	28 dup 0	; fill to align for 32 bytes per entry
	; TODO: that is an awful lot of unnecessary zero-fills, redo that so it is a little more efficient size-wise
if tlsdebug
cleartext .debugrsam, 'RSA Signature, pre-private-operation, m is:'
cleartext .debugrsasig, 'RSA Signature, post-private-operation, sig is:'
end if
calign
.client_hello_kex_dhe_dss:
	; compose our ServerKeyExchange message, first up: ServerDHParams, p, g, Ys
	; we need to hang onto our private exponent until we get the ClientKeyExchange message
	; we store our private exponent at tls_cr_ofs+tls_cstate_localmackey temporarily
	call	bigint$new
	mov	r15, rax
calign
.client_hello_kex_dhe_dss_again:
	mov	rdi, r15
	mov	esi, dh_privatekey_size
	call	bigint$set_random
	; save this value in our pending read state for later retrieval
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localmackey]
	mov	edx, [r15+bigint_size_ofs]
	mov	rsi, [r15+bigint_words_ofs]
	mov	[rdi], edx
	add	rdi, 4
	shl	edx, 3
	call	memcpy
	; randomly select from our dh$pool
	xor	edi, edi
	mov	esi, dh$pool_p_size - 1
	call	rng$int
	mov	[rbx+tls_dhindex_ofs], eax
	; compute Ys == dh$pool_g**r15 mod dh$pool_p
	mov	rdi, r15
	mov	rsi, [rax*8+dh$pool_p]
	call	monty$new
	mov	ecx, [rbx+tls_dhindex_ofs]
	mov	[r15+bigint_monty_powmod_ofs], rax
	mov	rdi, rax
	mov	rsi, r15		; destination for our monty
	mov	rdx, [rcx*8+dh$pool_g]	; source for our monty
	call	monty$doit
	mov	rdi, [r15+bigint_monty_powmod_ofs]
	call	monty$destroy_clear
	mov	qword [r15+bigint_monty_powmod_ofs], 0
	; so now, Ys is sitting in r15
	; make sure it is >1
	mov	rdi, r15
	mov	rsi, bigint$one
	call	bigint$compare
	cmp	eax, 0
	jle	.client_hello_kex_dhe_dss_again

	; r13, r14 are free to use
	; construct our ServerKeyExchange message
	mov	ecx, [rbx+tls_dhindex_ofs]
	
	; so that we can come back _after the fact_ and set our length
	push	r12
	add	r12, 9			; skip the type, version, and record layer length so that we can construct our handshake message, and skip our handshake preface length of 4 bytes
	; now we need dh$pool_p's bytecount as a 2 byte big endian string
	mov	rdi, [rcx*8+dh$pool_p]
	call	bigint$bytecount
	mov	edx, [rbx+tls_dhindex_ofs]
	mov	ecx, eax
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, [rdx*8+dh$pool_p]
	mov	rsi, r12
	add	r12, rcx
	call	bigint$encode
	mov	ecx, [rbx+tls_dhindex_ofs]
	mov	rdi, [rcx*8+dh$pool_g]
	call	bigint$bytecount
	mov	edx, [rbx+tls_dhindex_ofs]
	mov	ecx, eax
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, [rdx*8+dh$pool_g]
	mov	rsi, r12
	add	r12, rcx
	call	bigint$encode
	mov	rdi, r15
	call	bigint$bytecount
	mov	ecx, eax
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r15
	mov	rsi, r12
	add	r12, rcx
	call	bigint$encode
	; so now we have our ServerDHParams, p, g, Ys all encoded and ready to roll, now we need our signature
	; despite the actual certificate being signed with different params, I think we need to use SHA1 here
	; so, do up our sha1 of the ServerDHParams
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	call	sha160$init
	; now, we need to update it with our remoterandom first
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	mov	edx, 32
	call	sha160$update
	; udpate it with our localrandom next
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	call	sha160$update
	; now we need to update it with our ServerDHParams
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, [rsp]
	add	rsi, 9
	mov	rdx, r12
	sub	rdx, rsi
	call	sha160$update
	; so now we need to turn the hash itself into a bigint, and then perform our DSA signing operation on it
	; to produce the signature
	; we know there is ample space at r12 to do our deed, and we know the length of our hash
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, r12
	xor	edx, edx				; don't attempt to free the state
	call	sha160$final
	mov	rdi, r15
	mov	rsi, r12
	mov	edx, 20
	call	bigint$set_encoded
	mov	rdi, r15
	call	bigint$tlz
	; so now we have our m
	; load up our dsaprivate, which we know for certain exists
	mov	rdi, [rbx+tls_localcert_ofs]
	mov	r13, [rdi+X509_dsaprivatekey_ofs]
	; so we need a random k < q
	call	bigint$new
	mov	r14, rax
calign
.client_hello_kex_dhe_dss_randomk:
	mov	rdi, [r13+dsaprivate_q_ofs]
	call	bigint$bitcount
	mov	rdi, r14
	mov	esi, eax
	call	bigint$set_random
	mov	rdi, r14
	mov	rsi, [r13+dsaprivate_q_ofs]
	call	bigint$compare
	cmp	eax, 0
	jge	.client_hello_kex_dhe_dss_randomk
	; r = (g**k mod p) mod q
	mov	rdi, r14			; k == exponent
	mov	rsi, [r13+dsaprivate_p_ofs]	; p == modulus
	call	monty$new
	mov	[r15+bigint_monty_powmod_ofs], rax
	; so r15 == H(m)
	; r14 == k
	; we need a couple of temporaries here to do the deed
	call	bigint$new
	push	rax

	; do our inversemod k, q firstup
	mov	rdi, rax
	mov	rsi, r14
	mov	rdx, [r13+dsaprivate_q_ofs]
	call	bigint$inversemod
	; source and dest can't be the same for inversemod, so
	; assign that result back into r14
	mov	rdi, r14
	mov	rsi, [rsp]
	call	bigint$assign
	; r14 == inversemod of k and q
	; next up: do our r monty
	mov	rdi, [r15+bigint_monty_powmod_ofs]
	mov	rsi, [rsp]
	mov	rdx, [r13+dsaprivate_g_ofs]
	call	monty$doit
	; so now the bigint at [rsp] == g**k mod p
	; now we need to mod that by q
	mov	rdi, [rsp]
	mov	rsi, [r13+dsaprivate_q_ofs]
	call	bigint$modby
	; r in [rsp] is complete, and r14 == the first part of s, r15 == H(m)
	
	; so now we need (x * r) + r15
	; and then we need to monty$acc s (r14) with the result of that to get s
	mov	rdi, [rsp]
	call	bigint$new_copy
	push	rax
	mov	rdi, rax
	mov	rsi, [r13+dsaprivate_x_ofs]
	call	bigint$multiply
	mov	rdi, r15
	mov	rsi, [rsp]
	call	bigint$add
	; so now r15 == (x * r) + r15
	; we are done with that last temp
	pop	rdi
	call	bigint$destroy_clear
	; next we need r14 (inversemod k) * r15 mod q
	mov	rdi, r15
	mov	rsi, r14
	call	bigint$multiply
	mov	rdi, r15
	mov	rsi, [r13+dsaprivate_q_ofs]
	call	bigint$modby
	; so now r15 == s, set r14 to r
	mov	rdi, r14
	mov	rsi, [rsp]
	call	bigint$assign
	pop	rdi
	call	bigint$destroy_clear
	; r14 == r, r15 == s
	; if either are zero, start again
	mov	rdi, r14
	call	bigint$is_zero
	test	eax, eax
	jnz	.client_hello_kex_dhe_dss_randomk
	mov	rdi, r15
	call	bigint$is_zero
	test	eax, eax
	jnz	.client_hello_kex_dhe_dss_randomk

	; if the tls version is >= 1.2, we need to add the sigalgo/hash preface
	cmp	dword [rbx+tls_version_ofs], 0x0303
	jb	.client_hello_kex_dhe_dss_nosighashalgo

	; encode our SignatureAndHashAlgorithm 2 byte preface
	; sha1 == 2, sha256 == 4, sha384 == 5, sha512 == 6
	; followed by a 1 for rsa
	mov	word [r12], 0x202
	add	r12, 2

calign
.client_hello_kex_dhe_dss_nosighashalgo:

	; if we made it to here, r14 == r, r15 == s
	; we need to do opaque vector encode, 2 byte length prefix of: DER encoded sequence with 2 integers
	; both their lengths should be the same as dsaprivate_q's length (modulus for both)
	
	; sequence is 0x10, followed by encoded length... per dsa specs, q is going to be <= 256 bits, so 32 bytes at most plus encoding lengths of same
	; which will, no matter what, fit inside a single byte length encoding for the ASN1 tags
	; Soooo, that means we can precompute our lengths beforehand
	; we can re-use r13 now as we are done with our dsaprivate object

	; sequence guts == r.bytecount + 2, s.bytecount + 2
	; opaque vector guts == sequence guts + 2

	mov	rdi, r14
	call	bigint$bytecount
	mov	byte [r12+5], al		; length of r
	mov	r13d, eax
	mov	rdi, r15
	call	bigint$bytecount
	add	r13d, eax
	; 0x2 == integer, plus a length byte, for a total of 4 bytes for the guts of our sequence
	add	r13d, 4				; sequence length
	; so now, we know the length of our sequence
	mov	byte [r12+2], 0x30		; SEQUENCE, constructed, definite-length method
	mov	byte [r12+3], r13b		; length, which is assured to be less than 0x7f, so one byte is fine
	mov	byte [r12+4], 0x2		; definite-length integer

	; length at r12+5 was set above
	mov	rdi, r14
	lea	rsi, [r12+6]
	call	bigint$encode
	mov	edx, r13d
	movzx	eax, byte [r12+5]		; length of r in bytes
	mov	byte [r12+rax+6], 0x2		; definite-length integer
	sub	edx, eax			; length of s in bytes
	sub	edx, 4				; (less the sequence length)
	mov	byte [r12+rax+7], dl
	mov	rdi, r15
	lea	rsi, [r12+rax+8]
	call	bigint$encode
	; ok so both r and s have been DER encoded, and we have a grand total of 6 bytes extra on top of r13
	; as our actual opaque length
	add	r13d, 2
	; but we _know_ that r13d < 127, so the byte at r12 is zero
	; followed by r13b
	mov	byte [r12], 0
	mov	byte [r12+1], r13b
	; TODO: multibyte those, haha, lazy boy
	; so now, r13+2 is our total append length
	add	r12, r13
	add	r12, 2

	; hopefully that is it
	; next up, we have to compose the 9 byte preface, which is sitting at the pointer at [rsp]
	mov	r8, r12
	mov	r9, [rsp]
	sub	r8, r9
	; r8 now is the _total_ length, including the 9 byte preface
	mov	r10d, r8d		; save total length
	sub	r8d, 5
	; r8d now has our recordlayer length, of which we only want the uppermost byte
	and	r8d, 0xff00
	shl	r8d, 16
	
	; load back up the version we saved before into eax
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	or	eax, r8d
	mov	[r9], eax		; first four of the record layer header

	; next byte at r9+4 is the low order byte of our record layer length
	mov	edx, r10d
	sub	edx, 5
	and	edx, 0xff
	mov	byte [r9+4], dl
	; now we need our handshake preface of 4 bytes, to stick at r9+5
	; it is ServerKeyExchange type (12), followed by big endian length of our handshake part only
	mov	edx, r10d
	sub	edx, 9
	bswap	edx
	or	edx, 12
	mov	dword [r9+5], edx


	; so now, we have to add the handshake component only to the hacc
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [r9+5]
	mov	edx, r10d
	sub	edx, 5
	call	buffer$append

	; so now, our ServerHelloDone (type 14) handshake message in the chain needs to be added, zero length handshake
	; r12 is still valid and pointing to the end of our action
	mov	r13, r12		; save that
	
	; load back up the version we saved before into eax
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	; our length is: 4 for the handshake preface
	mov	dword [r12], eax
	add	r12, 4				; high order byte of our length is 0
	mov	byte [r12], 4
	add	r12, 1
	; our handshake message itself's low order byte is 14, and thats all we need
	mov	dword [r12], 14
	add	r12, 4

	; add that also to our handshake accumulator
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [r13+5]
	mov	edx, 4
	call	buffer$append

	add	rsp, 8			; remove our saved spot from the stack

	; and now, we can send the whole lot out in one fell swoop
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	rdx, r12
	sub	rdx, rsp
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	; set our new expectmin and expectmax to be precisely ClientKeyExchange
	mov	dword [rbx+tls_expectmin_ofs], 16
	mov	dword [rbx+tls_expectmax_ofs], 16

	; so now, we have to cleanup after ourselves...
	mov	rdi, r14
	call	bigint$destroy_clear
	mov	rdi, r15
	call	bigint$destroy_clear

	; restore our stackframe
	add	rsp, 32768
	pop	r15 r14 r13 r12 rbx

	xor	eax, eax				; don't kill us off
	epilog

calign
.client_hello_kex_dhe_rsa:
	; compose our ServerKeyExchange message, first up: ServerDHParams, p, g, Ys
	; we need to hang onto our private exponent until we get the ClientKeyExchange message
	; we store our private exponent at tls_cr_ofs+tls_cstate_localmackey temporarily
	call	bigint$new
	mov	r15, rax
calign
.client_hello_kex_dhe_rsa_again:
	mov	rdi, r15
	mov	esi, dh_privatekey_size
	call	bigint$set_random
	; save this value in our pending read state for later retrieval
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localmackey]
	mov	edx, [r15+bigint_size_ofs]
	mov	rsi, [r15+bigint_words_ofs]
	mov	[rdi], edx
	add	rdi, 4
	shl	edx, 3
	call	memcpy
	; randomly select from our dh$pool
	xor	edi, edi
	mov	esi, dh$pool_p_size - 1
	call	rng$int
	mov	[rbx+tls_dhindex_ofs], eax
	; compute Ys == dh$pool_g**r15 mod dh$pool_p
	mov	rdi, r15
	mov	rsi, [rax*8+dh$pool_p]
	call	monty$new
	mov	ecx, [rbx+tls_dhindex_ofs]
	mov	[r15+bigint_monty_powmod_ofs], rax
	mov	rdi, rax
	mov	rsi, r15		; destination for our monty
	mov	rdx, [rcx*8+dh$pool_g]	; source for our monty
	call	monty$doit
	mov	rdi, [r15+bigint_monty_powmod_ofs]
	call	monty$destroy_clear
	mov	qword [r15+bigint_monty_powmod_ofs], 0
	; make sure it is >1
	mov	rdi, r15
	mov	rsi, bigint$one
	call	bigint$compare
	cmp	eax, 0
	jle	.client_hello_kex_dhe_rsa_again

	; so now, Ys is sitting in r15
	; r13, r14 are free to use
	; construct our ServerKeyExchange message
	mov	ecx, [rbx+tls_dhindex_ofs]
	
	; so that we can come back _after the fact_ and set our length
	push	r12
	add	r12, 9			; skip the type, version, and record layer length so that we can construct our handshake message, and skip our handshake preface length of 4 bytes
	; now we need dh$pool_p's bytecount as a 2 byte big endian string
	mov	rdi, [rcx*8+dh$pool_p]
	call	bigint$bytecount
	mov	edx, [rbx+tls_dhindex_ofs]
	mov	ecx, eax
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, [rdx*8+dh$pool_p]
	mov	rsi, r12
	add	r12, rcx
	call	bigint$encode
	mov	ecx, [rbx+tls_dhindex_ofs]
	mov	rdi, [rcx*8+dh$pool_g]
	call	bigint$bytecount
	mov	edx, [rbx+tls_dhindex_ofs]
	mov	ecx, eax
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, [rdx*8+dh$pool_g]
	mov	rsi, r12
	add	r12, rcx
	call	bigint$encode
	mov	rdi, r15
	call	bigint$bytecount
	mov	ecx, eax
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2
	mov	rdi, r15
	mov	rsi, r12
	add	r12, rcx
	call	bigint$encode
	; so now we have our ServerDHParams, p, g, Ys all encoded and ready to roll, now we need our signature
	; if TLS <1.2, we need an MD5/SHA1, otherwise, we'll use whatever our key is done with
	; get our public certificate first up
	mov	rdi, [rbx+tls_localcert_ofs]
	mov	rsi, [rdi+X509_certificates_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	r14, [rdx]
	cmp	dword [rbx+tls_version_ofs], 0x0303
	jb	.client_hello_kex_dhe_rsa_oldtls
	; for TLS1.2, since we are not doing SigAlg extensions, we'll just use whatever our key is done with
	; we support precisely 4 different RSA sigalgs, which will be in the _first_ certificate in our localcert's certificate list X509cert_signature_ofs
	; 1: RSA/SHA-160
	; 2: RSA/SHA-256
	; 3: RSA/SHA-384
	; 4: RSA/SHA-512
	; we can blast/use our own TLS hash state spot to do this since we haven't yet initialised any of that yet
	; ok so, our first certificate (which better be our own anyway)
	; is sitting in r14, our .sighashfuncs is groups of 4 dq pointers to the individual hash functions
	; based on the index sitting in X509cert_signature_ofs
	mov	r13d, [r14+X509cert_signature_ofs]
	; TODO: spread that dependency chain out a bit, that is nasty
	; TODO: validate the X509cert_signature_ofs at pemlookup time, this will die a thousand deaths if the signature index is >4
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	; so we can use either HMAC, since neither of them are setup yet
	shl	r13d, 5		; sigalgo x 32 == offset into our .sighashfuncs
	call	qword [r13+.sighashfuncs]	; the init function
	; now, we need to update it with our remoterandom first
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	mov	edx, 32
	call	qword [r13+.sighashfuncs+8]	; the update function
	; udpate it with our localrandom next
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	call	qword [r13+.sighashfuncs+8]	; the update function
	; now we need to update it with our ServerDHParams
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, [rsp]
	add	rsi, 9
	mov	rdx, r12
	sub	rdx, rsi
	call	qword [r13+.sighashfuncs+8]	; the update function

	; since we don't want to recopy/move our hash final result, precompute the length we need
	mov	rdi, [r14+X509cert_public_n_ofs]
	call	bigint$bitcount
	sub	eax, 1
	shr	eax, 3
	; eax now == emLen
	; our padding length == emLen - our hash length - our hash id length - 2
	push	rax

	; dword [r13+.sighashidlens] == hash id length
	; bytes at [r13+.sighashids] == hash id itself
	mov	edx, eax
	mov	byte [r12], 0x01			; EM leading byte sans the 0x00 since we are turning this into an integer anyway
	sub	edx, dword [r13+.sighashfuncs+24]	; our hash length
	sub	edx, dword [r13+.sighashidlens]
	sub	edx, 2
	mov	byte [r12+rdx+1], 0x00
	; we need to memset the spot at r12+1 for rdx bytes of 0xff
	lea	rdi, [r12+1]
	mov	esi, 0xff
	call	memset
	; [rsp] is a saved emLen, recompute our padding length so we can memcpy our hashid into it
	mov	rdx, [rsp]
	sub	edx, dword [r13+.sighashfuncs+24]	; our hash length
	sub	edx, dword [r13+.sighashidlens]
	; so edx is our padding length + 2, we need r12+that
	lea	rdi, [r12+rdx]
	lea	rsi, [r13+.sighashids]
	mov	edx, [r13+.sighashidlens]
	call	memcpy
	mov	rax, [rsp]				; emLen
	mov	edx, [r13+.sighashfuncs+24]		; the actual hash size
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, r12
	add	rsi, rax
	sub	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	qword [r13+.sighashfuncs+16]		; the final function
	; so now we have our EMSA-PKCS1-v1_5 version of our hash sitting in r12 for emLen ([rsp]) bytes
	jmp	.client_hello_kex_dhe_rsa_hashdone

calign
.client_hello_kex_dhe_rsa_oldtls:
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	call	md5$init
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	call	sha160$init
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	mov	edx, 32
	call	md5$update
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	mov	edx, 32
	call	sha160$update
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	call	md5$update
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	mov	edx, 32
	call	sha160$update
	; ServerDHParams are next
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, [rsp]
	add	rsi, 9
	mov	rdx, r12
	sub	rdx, rsi
	call	md5$update
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	mov	rsi, [rsp]
	add	rsi, 9
	mov	rdx, r12
	sub	rdx, rsi
	call	sha160$update

	; same as above, we don't want to recopy/move our hash final result, precompute the length we need
	mov	rdi, [r14+X509cert_public_n_ofs]
	call	bigint$bitcount
	sub	eax, 1
	shr	eax, 3
	; eax now == emLen
	; our padding length == emLen - 38 (36 + 2 for pkcs identifiers)
	push	rax
	mov	edx, eax
	mov	byte [r12], 0x01
	sub	edx, 38
	mov	byte [r12+rdx+1], 0x00
	; we need to memset the spot at r12+1 for rdx bytes of 0xff
	lea	rdi, [r12+1]
	mov	esi, 0xff
	call	memset
	; [rsp] is a saved emLen, recompute our padding length
	mov	rax, [rsp]		; emLen
	sub	eax, 36
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	mov	rsi, r12
	add	rsi, rax
	xor	edx, edx		; don't attempt to free the state
	call	md5$final
	mov	rax, [rsp]		; emLen
	sub	eax, 20
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	mov	rsi, r12
	add	rsi, rax
	xor	edx, edx		; don't attempt to free the state
	call	sha160$final
	; so now we have our EMSA-PKCS1-v1_5 version of our hashes sitting in r12 for emLen ([rsp]) bytes

calign
.client_hello_kex_dhe_rsa_hashdone:
	; now we get to do our RSA private operations on that as a bigint
	mov	rdi, r15
	mov	rsi, r12
	pop	rdx
	call	bigint$set_encoded
	mov	rdi, r15
	call	bigint$tlz

if tlsdebug
	; debug
	mov	rdi, .debugrsam
	call	string$to_stdoutln
	mov	rdi, r15
	call	bigint$debug
end if

	; so now r15 is our RSA m to encrypt with our rsaprivate goods

	; NOTE RE: RSA Blinding: because we know the inputs are good and that _we_ generated them
	; we aren't exposing ourselves to any timing channel by not doing blinding here

	push	r12
	mov	rcx, [rbx+tls_localcert_ofs]
	mov	r12, [rcx+X509_privatekey_ofs]
	mov	rsi, r15
	mov	rdi, r12
	call	bigint$rsaprivate
	mov	rdi, [r12+rsaprivate_n_ofs]
	call	bigint$bytecount
	mov	r12, [rsp]
	mov	[rsp], rax			; keep this number!

	; so now r15 contains m**d mod n
if tlsdebug
	; debug
	mov	rdi, .debugrsasig
	call	string$to_stdoutln
	mov	rdi, r15
	call	bigint$debug
end if
	cmp	dword [rbx+tls_version_ofs], 0x0303
	jb	.client_hello_kex_dhe_rsa_nosighashalgo

	; encode our SignatureAndHashAlgorithm 2 byte preface
	; sha1 == 2, sha256 == 4, sha384 == 5, sha512 == 6
	; followed by a 1 for rsa
	shr	r13d, 4
	movzx	eax, word [r13+.sighashalgo]
	mov	word [r12], ax
	add	r12, 2

calign
.client_hello_kex_dhe_rsa_nosighashalgo:
	; NOTE: openssl (and I am not sure why exactly) requires the length of our sig to be
	; matching, even though it is still a perfectly good number
	; occasionally, (~0.5%) of the time, we end up with a signature that has the high order
	; byte being zero, which of course makes our bytecount _not_ match, and thus OpenSSL
	; pukes a wrong signature length... I don't recall seeing in the specs anywhere that says
	; the signature length _must_ equal the modulus length, but we need to do it anyway:

	; so, if we retrieve our rsaprivate_n_ofs bytecount, it is the one we care about
	mov	rax, [rsp]

if defined actual_rsa_signature_length
	; bytecount length prefix of 2 bytes is next
	mov	rdi, r15
	call	bigint$bytecount

	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2

	; next up: the result itself... 
	mov	rdi, r15
	mov	rsi, r12
	call	bigint$encode
	; r15's bytecount is how many bytes we actually wrote
	mov	rdi, r15
	call	bigint$bytecount
	add	r12, rax
	; so now, we have our complete message
else
	xchg	ah, al
	mov	word [r12], ax
	add	r12, 2

	; next up: the result itself, but we need to make sure we put it in the right spot
	mov	qword [r12], 0
	mov	rdi, r15
	call	bigint$bytecount
	mov	rcx, [rsp]
	sub	rcx, rax
	; ecx now has the # of bytes that were "leftover"

	mov	rdi, r15
	lea	rsi, [r12+rcx]
	call	bigint$encode

	; rsa modulus n is the correct number of bytes
	mov	rax, [rsp]
	add	r12, rax

end if
	pop	rax

	; next up, we have to compose the 9 byte preface, which is sitting at the pointer at [rsp]
	mov	r8, r12
	mov	r9, [rsp]
	sub	r8, r9
	; r8 now is the _total_ length, including the 9 byte preface
	mov	r10d, r8d		; save total length
	sub	r8d, 5
	; r8d now has our recordlayer length, of which we only want the uppermost byte
	and	r8d, 0xff00
	shl	r8d, 16
	
	; load back up the version we saved before into eax
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	or	eax, r8d
	mov	[r9], eax		; first four of the record layer header

	; next byte at r9+4 is the low order byte of our record layer length
	mov	edx, r10d
	sub	edx, 5
	and	edx, 0xff
	mov	byte [r9+4], dl
	; now we need our handshake preface of 4 bytes, to stick at r9+5
	; it is ServerKeyExchange type (12), followed by big endian length of our handshake part only
	mov	edx, r10d
	sub	edx, 9
	bswap	edx
	or	edx, 12
	mov	dword [r9+5], edx


	; so now, we have to add the handshake component only to the hacc
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [r9+5]
	mov	edx, r10d
	sub	edx, 5
	call	buffer$append

	; so now, our ServerHelloDone (type 14) handshake message in the chain needs to be added, zero length handshake
	; r12 is still valid and pointing to the end of our action
	mov	r13, r12		; save that
	
	; load back up the version we saved before into eax
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	; our length is: 4 for the handshake preface
	mov	dword [r12], eax
	add	r12, 4				; high order byte of our length is 0
	mov	byte [r12], 4
	add	r12, 1
	; our handshake message itself's low order byte is 14, and thats all we need
	mov	dword [r12], 14
	add	r12, 4

	; add that also to our handshake accumulator
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [r13+5]
	mov	edx, 4
	call	buffer$append

	add	rsp, 8			; remove our saved spot from the stack

	; and now, we can send the whole lot out in one fell swoop
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	rdx, r12
	sub	rdx, rsp
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	; set our new expectmin and expectmax to be precisely ClientKeyExchange
	mov	dword [rbx+tls_expectmin_ofs], 16
	mov	dword [rbx+tls_expectmax_ofs], 16

	; so now, we have to cleanup after ourselves...
	; r15 contains the original monty object used to do our DHE, so we'll clear it
	mov	rdi, r15
	call	bigint$destroy_clear

	; restore our stackframe
	add	rsp, 32768
	pop	r15 r14 r13 r12 rbx

	xor	eax, eax				; don't kill us off
	epilog
calign
.client_hello_kex_rsa:
	; all we have to do is add our ServerHelloDone and we are outta here
	mov	r13, r12
	
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x16
	mov	dword [r12], eax
	add	r12, 4					; high order byte of our length is 0
	mov	byte [r12], 4				; low order of our length is 4
	add	r12, 1
	; our handshake message itself's low order byte is 14, and thats all we need
	mov	dword [r12], 14
	add	r12, 4

	; add that to our handshake accumulator
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [r13+5]
	mov	edx, 4
	call	buffer$append

	; and now, we can send the whole lot out in one fell swoop
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	rdx, r12
	sub	rdx, rsp
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	; set our new expectmin and expectmax to be precisely ClientKeyExchange
	mov	dword [rbx+tls_expectmin_ofs], 16
	mov	dword [rbx+tls_expectmax_ofs], 16

	; restore our stackframe
	add	rsp, 32768
	pop	r15 r14 r13 r12 rbx

	xor	eax, eax				; don't kill us off
	epilog
calign
.server_hello:
	; the variable component of our length is the session id, and since we aren't presently sending 
	; any TLS Extensions, that part must also be fixed length.
	; verify our length and decode the message, puke a fatal handshake failure alert if we can't
	; make sure we are in client mode
	cmp	dword [rdi+tls_clientmode_ofs], 1
	jne	.failed
	
	; 2 bytes for server_version, 32 bytes for random, ?? bytes for session_id (min 1), 2 bytes for cipher_suite, 1 byte for compression method, no extensions
	cmp	ecx, 38
	jb	.failed
	movzx	eax, word [rsi]
	cmp	al, 3
	jne	.failed
	mov	[rdi+tls_version_ofs], eax
	mov	r8, [rsi+2]
	mov	r9, [rsi+10]
	mov	r10, [rsi+18]
	mov	r11, [rsi+26]
	; pending read state's remoterandom
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom], r8
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom+8], r9
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom+16], r10
	mov	[rdi+tls_pr_ofs+tls_cstate_remoterandom+24], r11
	movzx	r8d, byte [rsi+34]
	cmp	r8d, 32
	ja	.failed		; make sure it has a valid upper bound
if tls_client_sessioncache
	; see if this is the same sessionid that we sent
	cmp	r8d, [rdi+tls_sessionidlen_ofs]
	jne	.server_hello_newsession
	test	r8d, r8d
	jz	.server_hello_newsession
	; otherwise, we need to memcmp them, so save all our state vars first
	push	rdi rsi rcx r8
	lea	rdi, [rdi+tls_sessionid_ofs+8]
	lea	rsi, [rsi+35]
	mov	edx, r8d
	call	memcmp
	pop	r8 rcx rsi rdi
	test	eax, eax
	jnz	.server_hello_newsession

	; grab it from the cache and wait for the finished message
	push	rdi rsi rcx r8
	lea	rsi, [rdi+tls_pr_ofs]
	lea	rdi, [rdi+tls_sessionid_ofs+8]
	call	tls$sessioncache_get
	pop	r8 rcx rsi rdi
	; very bad things will happen if it isn't there
	test	rax, rax
	jz	.server_hello_newsession	; ultimately this would fail

	push	rbx r12
	mov	rbx, rdi
	xor	esi, esi
	xor	edx, edx
	call	.keycalc

	; set our expectmin/max to 20 (finished)
	mov	dword [rbx+tls_expectmin_ofs], 20
	mov	dword [rbx+tls_expectmax_ofs], 20

	; set clientmode = 2 so that when we receive the finished message
	; we'll know we need to deal with it differently
	mov	dword [rbx+tls_clientmode_ofs], 2
	
	pop	r12 rbx
	xor	eax, eax		; don't kill us off
	epilog

calign
.server_hello_newsession:
end if
	mov	[rdi+tls_sessionidlen_ofs], r8d
	cmp	r8d, 32
	ja	.failed		; make sure it has a valid upper bound
	; temporarily store the pointer to where it is in our input buffer
	lea	r9, [rsi+35]
	mov	[rdi+tls_sessionid_ofs+8], r9

	; 35 + r8 == 2 byte ciphersuite
	; 37 + r8 == compression method, but we know that will be zero, just verify that it is
	add	r8d, 38
	cmp	ecx, r8d
	jne	.failed
	; rsi+r8-3 == 2 byte ciphersuite
	; rsi+r8-1 == compression method, verify it is 0
	cmp	byte [rsi+r8-1], 0
	jne	.failed
	; find our ciphersuite
	movzx	eax, word [rsi+r8-3]
	; verify that the word in ax is indeed in our advertised ciphersuite list first up
	xor	r9d, r9d
	mov	rsi, tls$ciphersuites
	mov	edx, tls_ciphersuite_size
calign
.verifyloop:
	cmp	ax, word [rsi]
	je	.ciphersuitefound
	add	rsi, 2
	add	r9d, 1
	sub	edx, 2
	jnz	.verifyloop
	jmp	.failed
calign
.ciphersuitefound:
	; ok so we found the cipher suite in our list, we need to set all our parameters from index r9d
	mov	dword [rdi+tls_pr_ofs+tls_cstate_ciphervalid], 1
	mov	dword [rdi+tls_pr_ofs+tls_cstate_cipherindex], r9d
	
	; setup our success state for handling this record:
	; set our new expectation as to the types we will receive next
	mov	dword [rdi+tls_expectmin_ofs], 11	; certificate
	mov	dword [rdi+tls_expectmax_ofs], 14	; server_hello_done

	; so now, if we have a sessionid length, copy it properly
	mov	rsi, [rdi+tls_sessionid_ofs+8]		; get our temporary pointer back as our source
	mov	edx, [rdi+tls_sessionidlen_ofs]		; and its length
	lea	rdi, [rdi+tls_sessionid_ofs+8]
	test	edx, edx
	jz	.nosessionid
	call	memcpy
	xor	eax, eax				; don't kill us off
	epilog
calign
.nosessionid:
	xor	eax, eax
	epilog
calign
.certificate:
	; if we are not a client, die.
	cmp	dword [rdi+tls_clientmode_ofs], 1
	jne	.failed
	; otehrwise, parse our Certificate message
	; record layer length == total length.. list length is in BYTES, and each list item also has a byte preface
	; so at the very very minimum, we have to have 3 bytes for the list entire length (which should equal handshake message length - 3)
	; and be a minimum of 4, because we need 3 bytes for the length of the first certificate, and the spec says its length cannot be zero
	; note here we do not support our peer sending an empty certificate list
	cmp	ecx, 7
	jb	.failed
	; pull the length of our list first:
if use_movbe
	movbe	r9d, [rsi]
else
	mov	r9d, [rsi]
	bswap	r9d
end if
	shr	r9d, 8
	sub	ecx, 3
	cmp	r9d, ecx
	jne	.failed
	add	rsi, 3
	; we need to preserve rdi, rsi, and ecx
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, ecx
	call	X509$new
	mov	[rbx+tls_peercert_ofs], rax
calign
.certificateloop:
	; while our remaining bytecount is nonzero, keep going
	cmp	r13d, 0
	jl	.certificateloop_failed			; sanity only in case we screwed the pooch elsewhere
	je	.certificateloop_done
	cmp	r13d, 4			; make sure we have at least our length preface and 1 byte more
	jb	.certificateloop_failed
	; parse the length of this certificate
if use_movbe
	movbe	edx, [r12]
else
	mov	edx, [r12]
	bswap	edx
end if
	shr	edx, 8
	; skip our length
	add	r12, 3
	; decrement our bytes remaining
	sub	r13d, 3

	; make sure that this length is <= bytes remaining
	cmp	edx, r13d
	ja	.certificateloop_failed
	
	; prepare r13d for the next iteration of our loop
	sub	r13d, edx

	; add this certificate to our list
	mov	rdi, [rbx+tls_peercert_ofs]
	mov	rsi, r12
	; prepare our buffer for the next iteration of our loop
	add	r12, rdx
	call	X509$add_certificate

if defined tls_client_strictcertchecking
	test	eax, eax
	jnz	.certificateloop	; all good, keep going
	; otherwise, it failed to add it, die.
	mov	rdi, rbx
	pop	r13 r12 rbx
	jmp	.failed
else
	jmp	.certificateloop	; keep going
end if
calign
.certificateloop_failed:
	mov	rdi, rbx
	pop	r13 r12 rbx
	jmp	.failed
calign
.certificateloop_done:
	; so if we made it here, then our certificates were added successfully
	; make sure we have at least one certificate in the X509 object
	mov	rdi, rbx
	pop	r13 r12 rbx
	mov	rsi, [rbx+tls_peercert_ofs]
	mov	rdx, [rsi+X509_certificates_ofs]
	test	rdx, rdx
	jz	.failed
	cmp	qword [rdx], 0
	je	.failed
	; otehrwise, looks okay, let it fly.... we have to set our expectmin to +1
	add	dword [rdi+tls_expectmin_ofs], 1
	xor	eax, eax		; don't kill us off
	epilog

calign
.server_key_exchange:
	; we only get these for DHE_DSS and DHE_RSA
	; if we are not a client, die.
	cmp	dword [rdi+tls_clientmode_ofs], 1
	jne	.failed
	; make sure we got a certificate beforehand, we don't do anon
	; check our kex method that was set in the serverhello to make sure we are on the right track, die if not
	cmp	dword [rdi+tls_pr_ofs+tls_cstate_ciphervalid], 1
	jne	.failed
	; otherwise, check what kind of kex we decided on
	mov	eax, [rdi+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, dword [rax+tls$cipherspecs+tls_cipherspec_kexalgo_ofs]
	cmp	edx, 2
	ja	.failed
	; so it is either a 1 or a 2, go ahead and parse our message... we don't need to hang on to these values, all we need to do
	; is compute Yc at this time and hold out for the hello_done, at which point we'll send that back
	; we have precisely three values, dh_p, dh_g, dh_Ys, each of which is prefaced by a 2 byte length, followed by their bigint encoded form
	cmp	ecx, 9
	jb	.failed
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, ecx

	call	bigint$new
	push	rax
	call	bigint$new
	push	rax
	call	bigint$new
	push	rax
	call	bigint$new
	push	rax

	movzx	edx, word [r12]
	xchg	dh, dl
	add	r12, 2
	sub	r13d, 2
	cmp	r13d, edx
	jb	.server_kex_failed
	; otherwise, we can set_encoded
	mov	rdi, [rsp]
	mov	rsi, r12
	; update r12/r13 for when we are done
	add	r12, rdx
	sub	r13d, edx
	call	bigint$set_encoded
	mov	rdi, [rsp]
	call	bigint$tlz
	; [rsp] == dh_p
if tls_clientside_dh_p_verify
	mov	rdi, [rsp]
	call	bigint$isprime2
	test	eax, eax
	jz	.server_kex_failed
end if
	cmp	r13d, 3
	jb	.server_kex_failed
	movzx	edx, word [r12]
	xchg	dh, dl
	add	r12, 2
	sub	r13d, 2
	cmp	r13d, edx
	jb	.server_kex_failed
	mov	rdi, [rsp+8]
	mov	rsi, r12
	; update r12/r13 for when we are done
	add	r12, rdx
	sub	r13d, edx
	call	bigint$set_encoded
	mov	rdi, [rsp+8]
	call	bigint$tlz
	; [rsp+8] == dh_g
	cmp	r13d, 3
	jb	.server_kex_failed
	movzx	edx, word [r12]
	xchg	dh, dl
	add	r12, 2
	sub	r13d, 2
	cmp	r13d, edx
	jb	.server_kex_failed
	mov	rdi, [rsp+16]
	mov	rsi, r12
	; update r12/r13 for when we are done
	add	r12, rdx
	sub	r13d, edx
	call	bigint$set_encoded
	mov	rdi, [rsp+16]
	call	bigint$tlz
	; [rsp+16] == dh_Ys

	; TODO: if we ever decide to add support for signature verification here is where we'd need to do it



	; so now, we can compute our premaster secret, as well as our Yc to send off

if tlsdebug
	; debug
	mov	rdi, .server_dh_p
	call	string$to_stdoutln
	mov	rdi, [rsp]
	call	bigint$debug
	mov	rdi, .server_dh_g
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	call	bigint$debug
	mov	rdi, .server_dh_Ys
	call	string$to_stdoutln
	mov	rdi, [rsp+16]
	call	bigint$debug
	; end debug
end if

	; make sure all three are nonzero (at the very least)... if we wanted to be anal about it, we could check/verify these values
	; in client mode though and for the purposes of this library, that is overkill/unnecessary.
	mov	rdi, [rsp]
	call	bigint$is_zero
	test	eax, eax
	jnz	.server_kex_failed
	mov	rdi, [rsp+8]
	call	bigint$is_zero
	test	eax, eax
	jnz	.server_kex_failed
	mov	rdi, [rsp+16]
	call	bigint$is_zero
	test	eax, eax
	jnz	.server_kex_failed

calign
.server_key_exchange_newdh:
	; our DH private key size determines how large our side's private exponent is..
	mov	rdi, [rsp+24]
	mov	esi, dh_privatekey_size
	call	bigint$set_random
	; [rsp+24] == b  == our DH private key/exponent
	mov	rdi, [rsp+24]
	mov	rsi, [rsp]
	call	monty$new
	; compute our premaster secret one-off first as Ys**b mod p
	mov	rcx, [rsp]		; modulus
	mov	rdi, rax
	mov	rsi, [rsp+24]		; destination for premaster secret
	mov	rdx, [rsp+16]		; Ys
	; hang the monty object off the modulus so it gets cleaned up nice and neatlike (cleanly I might add)
	mov	[rcx+bigint_monty_powmod_ofs], rax
	call	monty$doit

	; so now we have our premaster secret sitting in [rsp+24]
	; compute its length in bytes into r14d, hopefully it is a power of 2 or our stack will be all misaligned
	mov	rdi, [rsp+24]
	call	bigint$bytecount
	mov	r14d, eax
	mov	rdi, [rsp+24]
	sub	rsp, rax
	mov	rsi, rsp
	call	bigint$encode
	; so now, [rsp] for r14d bytes is our premaster secret
	mov	rsi, rsp
	mov	edx, r14d
	call	.keycalc
	add	rsp, r14
	; now, we can blast our premaster secret and calculate Yc as g**b mod p
	mov	rcx, [rsp]		; modulus
	mov	rsi, [rsp+24]
	mov	rdx, [rsp+8]		; g
	mov	rdi, [rcx+bigint_monty_powmod_ofs]
	call	monty$doit
	; cleanup our monty object, and then make sure our Yc did not inadvertently end up <=1
	mov	rcx, [rsp]
	mov	rdi, [rcx+bigint_monty_powmod_ofs]
	mov	qword [rcx+bigint_monty_powmod_ofs], 0
	call	monty$destroy_clear
	mov	rdi, [rsp+24]
	mov	rsi, bigint$one
	call	bigint$compare
	cmp	eax, 0
	jle	.server_key_exchange_newdh

	; so now we have our Yc in bigint format sitting in [rsp+24]
	; we need to store its length and itself for when our ServerHelloDone comes in
	cmp	qword [rbx+tls_dheint_ofs], 0
	jne	.server_kex_dhe_assign
	mov	rdi, [rsp+24]
	call	bigint$new_copy
	mov	[rbx+tls_dheint_ofs], rax	; it would be nice if we could just fire the ClientKeyExchange off now and be done with it
	
	pop	rdi
	call	bigint$destroy_clear	; it is the one with our monty object hanging off it
	pop	rdi
	call	bigint$destroy		; the rest are public so we don't really care
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy

	pop	r14 r13 r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
calign
.server_kex_dhe_assign:
	mov	rdi, [rbx+tls_dheint_ofs]
	mov	rsi, [rsp+24]
	call	bigint$assign
	
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy

	pop	r14 r13 r12 rbx
	xor	eax, eax		; don't kill us off
	epilog

if tlsdebug
cleartext .server_dh_p, 'Server dh_p is:'
cleartext .server_dh_g, 'Server dh_g is:'
cleartext .server_dh_Ys, 'Server dh_Ys is:'
end if
calign
.server_kex_failed:
	; cleanup our 4 bigints, cleanup the stack, and jmp to failed
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy
	pop	rdi
	call	bigint$destroy

	pop	r14 r13 r12 rbx
	jmp	.failed
calign
.certificate_request:
	; we should _not_ get these for normal net traffic
	jmp	.failed

calign
.server_hello_done:
	; our turn to fire off our ClientKeyExchange, ChangeCipherSpec, and Finished messages
	; if we are not in client mode, die
	cmp	dword [rdi+tls_clientmode_ofs], 1
	jne	.failed
	; if we don't have a ciphervalid in our pending read state, die
	cmp	dword [rdi+tls_pr_ofs+tls_cstate_ciphervalid], 1
	jne	.failed
	; otherwise, see what kind of kex we decided on
	mov	eax, [rdi+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	ecx, dword [rax+tls$cipherspecs+tls_cipherspec_kexalgo_ofs]
	jmp	qword [rcx*8+.server_hello_done_kextype]
dalign
.server_hello_done_kextype:
	dq	0, .server_hello_done_dhe, .server_hello_done_dhe, .server_hello_done_rsa
calign
.server_hello_done_dhe:
	; already verified that we are in the right mode, but we haven't verified we have a valid dheint yet
	mov	r8, [rdi+tls_dheint_ofs]
	test	r8, r8
	jz	.failed
	; otherwise, it appears that we have one, we need to compose our ClientKeyExchange and ChangeCipherSpec
	; so that we can jump to sendfinished when we are done, we need to preserve : r14 r13 r12 rbx
	push	rbx r12 r13 r14
	; all we need to do is send our dh_Yc with a 2 byte length prefix in a ClientKeyExchange message, and include a ChangeCipherSpec after it
	mov	rbx, rdi
	mov	rdi, r8
	call	bigint$bytecount
	mov	r12d, eax		; save the real bytecount
	; in addition to the actual bigint bytecount, we need:
	; 5 bytes for record layer header
	; 4 bytes for handshake header
	; 2 bytes for our length prefix
	; 5 bytes for the record layer header for ChangeCipherSpec
	; 1 byte for the ChangeCipherSpec 1 byte
	; -- 17 extra bytes
	add	eax, 0xf + 17
	and	eax, not 0xf
	mov	r13d, eax
	sub	rsp, rax
	; ok so now, we can compose our message, encode our bigint, add to the hacc buffer, send it unencrypted
	mov	ecx, r12d
	mov	edx, r12d

	mov	r8d, [rbx+tls_version_ofs]
	shl	r8d, 8
	or	r8d, 0x16			; (protocol record layer, 0x16 == 22 == handshake)
	mov	dword [rsp], r8d		; (protocol record layer = 3,1, 0x16 == 22 == handshake
	; the record layer size is bigint bytecount + 2 + 4
	add	ecx, 6
	add	edx, 2
	xchg	ch, cl
	mov	word [rsp+3], cx		; outer layer set
	; next is our handshake type + length, which is 4 less
	bswap	edx
	or	edx, 16				; client_key_exchange as its first byte
	mov	dword [rsp+5], edx
	; now we need our 2 byte vector length prefix:
	mov	eax, r12d
	xchg	ah, al
	mov	word [rsp+9], ax
	; and last but not least, we need our bigint encoded
	mov	rdi, [rbx+tls_dheint_ofs]
	lea	rsi, [rsp+11]
	call	bigint$encode
	; we need to add the ChangeCipherSpec 6 bytes at the end
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x14			; protocol record layer and 0x14 == 20 == ChangeCipherSpec
	mov	dword [rsp+r12+11], eax
	mov	word [rsp+r12+15], 0x0101	; low order length = 1, change cipher spec byte = 1
	; so now, the bundle of joy is ready to roll out
	mov	rdi, [rbx+io_child_ofs]		; our next in line
if tlsdebug
	; sanity check only: TODO: remove me for production
	test	rdi, rdi
	jz	.breakpoint
	; end sanity check
end if

if tlsdebug
	; debug
	mov	rdi, rsp
	mov	esi, r12d
	add	esi, 17
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, [rbx+io_child_ofs]
	; end debug
end if

	; we need to add just the contents of our outbound message to our handshake accumulator
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	mov	edx, r12d
	add	edx, 6				; 4 bytes for the handshake message preface, 2 bytes for our bigint length preface
	call	buffer$append

if tlsdebug
	;debug
	mov	rdi, .debugstr2
	call	string$to_stdoutln
	mov	edi, r12d
	add	edi, 6
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	;end debug
end if

	; change cipher spec message is not included in the hacc buf because it is not a handshake message
	mov	rdi, [rbx+io_child_ofs]

	mov	rsi, rsp
	mov	rcx, [rdi]			; its vtable
	mov	edx, r12d
	add	edx, 17
	call	qword [rcx+io_vsend]
	add	rsp, r13

	jmp	.server_hello_done_sendfinished

calign
.server_hello_done_rsa:
	; we need to make sure we have a valid peercert, and that it contains what appears to be valid RSA goodies
	mov	rsi, [rdi+tls_peercert_ofs]
	test	rsi, rsi
	jz	.failed
	mov	rdx, [rsi+X509_certificates_ofs]
	test	rdx, rdx
	jz	.failed
	cmp	qword [rdx], 0
	je	.failed
	; otherwise, there is a certificate at the head of the list, pull the list_first
	mov	rcx, [rdx+_list_first_ofs]
	mov	rdx, [rcx+_list_valueofs]
	; so rdx now is sitting on an X509 certificate, make sure it has apparently valid RSA goods in it
	; save our tls object and the X509 cert

	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rdx
	mov	rdi, [rdx+X509cert_public_n_ofs]
	call	bigint$is_zero
	test	eax, eax
	jnz	.server_hello_done_rsa_kakked
	mov	rdi, [r12+X509cert_public_e_ofs]
	call	bigint$is_zero
	test	eax, eax
	jnz	.server_hello_done_rsa_kakked
	; otherwise, we have a public n and a public e from the server, so next we need a premaster secret of 48 disposable bytes

	; we need to generate a PKCS1v15 padded version of our random 48 disposable bytes that is the same length as the public n's bytecount
	; first byte is two, remaining bytes are random, last bytes are our random
	; which means we can effectively random block the whole thing and set three of its bytes, stipulation that they are nonzero
	mov	rdi, [r12+X509cert_public_n_ofs]
	call	bigint$bytecount

	; hmmm, I am not sure why this is required... but, this appears to make everyone happy:
	sub	eax, 1
	; make sure it is at least 64 bytes long
	mov	ecx, 64
	cmp	eax, ecx
	cmovb	eax, ecx
	mov	r14d, eax		; our required length
	; so now, we can setup our PKCS1v15 padded premaster secret
	sub	rsp, 4096
	; sub	rsp, r14
	mov	rdi, rsp
	mov	esi, r14d
	call	rng$block_nzb		; nzb == no zero bytes
	mov	byte [rsp], 2
	mov	eax, r14d
	sub	eax, 49
	mov	byte [rsp+rax], 0	; separator
	; now we need our version
	mov	word [rsp+rax+1], 0x0303	; version from our client hello
	
	; so now we need to calculate our master secret
	lea	rsi, [rsp+rax+1]
	mov	edx, 48
	call	.keycalc

if tlsdebug
	; debug master secret
	mov	rdi, .msecstr
	call	string$to_stdoutln
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	esi, 48
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	; end debug
end if

	; and now we need a bigint encoded from the entire rsp
	mov	rdi, rsp
	mov	esi, r14d
	call	bigint$new_encoded
	mov	r13, rax
	; clear our premaster secret off the stack for good measure:

if tlsdebug
	; debug
	mov	rdi, rsp
	mov	esi, r14d
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	mov	rdi, rsp
	xor	esi, esi
	mov	edx, r14d
	call	memset

	add	rsp, 4096
	; add	rsp, r14

	; so now, we need to calculate: r13 ** public_e mod public_n
	; we only need to do this once, so we can use r13 to hang onto the goods
	mov	rdi, [r12+X509cert_public_e_ofs]
	mov	rsi, [r12+X509cert_public_n_ofs]
	call	monty$new
	mov	[r13+bigint_monty_powmod_ofs], rax
	; since monty$doit makes an immediate copy of the source argument, we can use the same for source and destination:
	mov	rdi, rax
	mov	rsi, r13
	mov	rdx, r13
	call	monty$doit
	; so now, the bigint sitting in r13 is the result of our calculation

if tlsdebug
	mov	rdi, .server_hello_done_rsadebug
	call	string$to_stdoutln
	mov	rdi, r13
	call	bigint$debug
end if

	; length prefix goes out with our EncryptedPreMasterSecret
	; get our byte count required for our encrypted premaster secret
	mov	rdi, r13
	call	bigint$bytecount
	sub	rsp, rax			; TODO: alignment issues? their modulus is hopefully a decent size, hmmm
	mov	ecx, eax
	mov	edx, eax
	; in addition to the actual bigint bytecount, we need:
	; 5 bytes for record layer header
	; 4 bytes for handshake header
	; 2 bytes for our length prefix
	; 5 bytes for the record layer header for ChangeCipherSpec
	; 1 byte for the ChangeCipherSpec 1 byte

	mov	r8d, [rbx+tls_version_ofs]
	sub	rsp, 24
	shl	r8d, 8
	or	r8d, 0x16			; (protocol record layer, 0x16 == 22 == handshake)
	mov	dword [rsp], r8d		; (protocol record layer = 3,1, 0x16 == 22 == handshake
	; the record layer size is bigint bytecount + 2 + 4
	add	ecx, 6
	add	edx, 2
	xchg	ch, cl
	mov	word [rsp+3], cx		; outer layer set
	; next is our handshake type + length, which is 4 less
	bswap	edx
	or	edx, 16				; client_key_exchange as its first byte
	mov	dword [rsp+5], edx
	; save our byte length, cuz we need it for the send length calculation
	mov	r8d, eax
	; now we need our 2 byte vector length prefix:
	xchg	ah, al
	mov	word [rsp+9], ax
	; and last but not least, we need our bigint encoded
	mov	rdi, r13
	lea	rsi, [rsp+11]
	push	r8
	call	bigint$encode
	pop	rdx
	; we need to add the ChangeCipherSpec 6 bytes at the end
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x14			; protocol record layer and 0x14 == 20 == ChangeCipherSpec
	mov	dword [rsp+rdx+11], eax
	mov	word [rsp+rdx+15], 0x0101	; low order length = 1, change cipher spec byte = 1
	; so now, the bundle of joy is ready to roll out
	mov	rdi, [rbx+io_child_ofs]		; our next in line
if tlsdebug
	; sanity check only: TODO: remove me for production
	test	rdi, rdi
	jz	.breakpoint
	; end sanity check
end if

if tlsdebug
	; debug
	mov	rdi, rsp
	push	rdx
	mov	esi, edx
	add	esi, 17
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	pop	rdx
	mov	rdi, [rbx+io_child_ofs]
	; end debug
end if

	; we need to add just the contents of our outbound message to our handshake accumulator
	mov	rdi, [rbx+tls_hacc_ofs]
	lea	rsi, [rsp+5]
	push	rdx
	add	edx, 6				; 4 bytes for the handshake message preface, 2 bytes for our bigint length preface
	call	buffer$append


if tlsdebug
	;debug
	mov	rdi, .debugstr2
	call	string$to_stdoutln
	mov	edi, [rsp]
	add	edi, 6
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	;end debug
end if

	; change cipher spec message is not included in the hacc buf because it is not a handshake message
	pop	rdx
	mov	rdi, [rbx+io_child_ofs]

	mov	rsi, rsp
	mov	rcx, [rdi]			; its vtable
	push	rdx
	add	edx, 17
	call	qword [rcx+io_vsend]
	pop	rdx
	add	rsp, 24
	add	rsp, rdx

	; cleanly destroy r13
	mov	rdi, r13
	call	bigint$destroy_clear

calign
.server_hello_done_sendfinished:
	; unfortunately, we need PRFs again, and we couldn't do them prior to here
	; fortunately, they are not terribly expensive to setup/do, so we'll do them now (and we'll have to do them again when we get the other side's finished message)

	; we need to construct an unencrypted payload of a handshake message that is: type: finished, length: 12 bytes (for a total of 4 bytes handshake header), + the 12
	; for a total of 16 bytes, and then pass that to the encrypt with the appropriate outer record layer type
	sub	rsp, 16
	mov	dword [rsp], 0x0c000014		; low order byte == handshake msg_type == 20 == Finished, next byte is high order length == 0, middle order length == 0, 0x0c == 12 bytes length
	mov	rsi, rsp
	add	rsi, 4
	lea	rdx, [rbx+tls_pr_ofs+tls_cstate_mastersecret]	; make sure we give it the pointer to the master secret to use
	mov	rcx, .cfin
	call	.verify_data

	; set our renegdata
	lea	rdi, [rbx+tls_renegdata_ofs]
	lea	rsi, [rsp+4]
	mov	edx, 12
	call	memcpy

if tls_client_sessioncache

	cmp	dword [rbx+tls_sessionidlen_ofs], 0
	je	.server_hello_done_nosessioncache
	; otherwise, we need to add this baby to our session cache
	lea	rsi, [rbx+tls_pr_ofs]
	lea	rdi, [rbx+tls_sessionid_ofs+8]
	call	tls$sessioncache_set
calign
.server_hello_done_nosessioncache:

end if

	; copy our current pending read state to our current write state (cuz it has all our keys)
	; (we don't copy the current pending read state to the current read state until we get the server's ChangeCipherSpec message)
	lea	rdi, [rbx+tls_cw_ofs]
	lea	rsi, [rbx+tls_pr_ofs]
	mov	edx, tls_cstate_size
	call	memcpy
	; clear our pending read state? hmm, no, we'll save that til we get the server's ChangeCipherSpec ...

	; get our cipherindex
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; we need to initialize our current write hmac before we proceed:
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	call	qword [rax+tls$cipherspecs+tls_cipherspec_macalgo_ofs]
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; and we need to set its key, which is a flat call
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localmackey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	call	hmac$key

	; and we need to initialize our current write cipher with our key
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localenckey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; MULTICIPHER MOD REQUIRED:
	call	aes$init_encrypt


	; we need to add our finished message to the handshake accumulator as well so that when the server's arrives
	; we can compute it correctly
	mov	rdi, [rbx+tls_hacc_ofs]
	mov	rsi, rsp
	mov	edx, 16
	call	buffer$append

if tlsdebug
	;debug
	mov	rdi, .debugstr3
	call	string$to_stdoutln
	mov	edi, 16
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	;end debug
end if

	; set our open flag indicating we are write-ready
	mov	dword [rbx+tls_open_ofs], 1
	mov	qword [rbx+tls_writeseq_ofs], 0

	; update our expectmin and expectmax to include ONLY finished messages
	mov	dword [rbx+tls_expectmin_ofs], 20
	mov	dword [rbx+tls_expectmax_ofs], 20

	; and finally, fire off our Finished message
	mov	rdi, rbx			; our tls object
	mov	esi, 0x16			; record layer type == handshake
	mov	rdx, rsp			; buffer location
	mov	ecx, 16				; record layer length to encode
	call	tls$encrypt

	; and before we close the show, call our parent's connected method to let them know the
	; channel is open
	; NOTE: in client mode, it makes no sense to send our raddr, as it is not set to begin with
	; so for tls client mode connections only, we send our sessionid
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, [rbx+tls_sessionidlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]

	add	rsp, 16				; cleanup the space we made for the verifydata

	pop	r14 r13 r12 rbx
	xor	eax, eax			; don't kill us off
	epilog

if tlsdebug
cleartext .msecstr, 'master secret is:'
cleartext .clientdebug1, 'Adding this session id to our tls$sessioncache:'
end if
	
if tlsdebug
calign
.breakpoint:
	breakpoint
end if


if tlsdebug
cleartext .server_hello_done_rsadebug, 'PreMasterSecret:'
cleartext .debugstr2, 'tls$process_handshake, ClientKeyExchange message append to hacc:'
cleartext .debugstr3, 'tls$process_handshake, Finished message append to hacc:'
end if

calign
.server_hello_done_rsa_kakked:
	pop	r13 r12 rbx
	jmp	.failed
calign
.certificate_verify:
	; we should _not_ get these for normal net traffic
	jmp	.failed

calign
.client_key_exchange:
	cmp	ecx, 3
	jbe	.failed
	cmp	dword [rdi+tls_clientmode_ofs], 1
	je	.failed
	; make sure we have already got our cipherindex
	cmp	dword [rdi+tls_pr_ofs+tls_cstate_ciphervalid], 1
	jne	.failed
	; otherwise, check what kind of kex we decided on
	mov	eax, [rdi+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, dword [rax+tls$cipherspecs+tls_cipherspec_kexalgo_ofs]
	cmp	edx, 3
	jb	.client_key_exchange_DH
	; otherwise, we received an RSA encrypted premaster secret
	; length prefix of 2 bytes
	movzx	eax, word [rsi]
	sub	ecx, 2
	xchg	ah, al
	add	rsi, 2
	; make sure we have precisely the right amount of data for it
	cmp	ecx, eax
	jne	.failed
	; otherwise, we have a nice simple encoded RSA encrypted premaster secret, PKCS1v15 padded
	push	rbx r12 r13
	mov	rbx, rdi
	mov	rdi, rsi
	mov	esi, ecx
	call	bigint$new_encoded
	mov	r12, rax
	
if tlsdebug
	mov	rdi, .client_kex_rsam
	call	string$to_stdoutln
	mov	rdi, r12
	call	bigint$debug
end if

	; so now, perform the RSA operation to extract our PKCS1v15 padded premaster secret
	push	r14 r15
	mov	rdx, [rbx+tls_localcert_ofs]
	mov	rcx, [rdx+X509_privatekey_ofs]
	push	rcx

if tls_server_rsa_blinding

	; NOTE: per spec, we have to blind this operation to prevent leaking information about
	; our RSA private exponent

	mov	rdi, [rcx+rsaprivate_n_ofs]
	call	bigint$bitcount
	mov	r14d, eax
	call	bigint$new
	mov	r13, rax
calign
.client_key_exchange_rsa_blinding:
	mov	rdi, r13
	mov	esi, r14d
	call	bigint$set_random
	; make sure it is nonzero and less than n
	mov	rdi, r13
	call	bigint$is_zero
	test	eax, eax
	jnz	.client_key_exchange_rsa_blinding
	mov	rdx, [rsp]
	mov	rdi, r13
	mov	rsi, [rdx+rsaprivate_n_ofs]
	call	bigint$compare
	cmp	eax, 0
	jge	.client_key_exchange_rsa_blinding
	; next up, we need the multiplicative inverse mod n of our random
	call	bigint$new
	mov	rcx, [rsp]
	mov	r14, rax
	mov	rdi, rax
	mov	rsi, r13
	mov	rdx, [rcx+rsaprivate_n_ofs]
	call	bigint$inversemod
	; next up, we need to set r13 = r13**e mod n
	mov	rdx, [rsp]
	mov	rdi, [rdx+rsaprivate_e_ofs]
	mov	rsi, [rdx+rsaprivate_n_ofs]
	call	monty$new
	; hang that off r13 so it gets destroyed properly when we are done
	mov	[r13+bigint_monty_powmod_ofs], rax
	; source and dest can be the same for monty$doit
	mov	rdi, rax
	mov	rsi, r13
	mov	rdx, r13
	call	monty$doit
	; multiply that by our input ciphertext bigint, mod n to finish our blinding
	mov	rdi, r13
	mov	rsi, r12
	call	bigint$multiply
	mov	rdx, [rsp]
	mov	rdi, r13
	mov	rsi, [rdx+rsaprivate_n_ofs]
	call	bigint$modby

else
	mov	r13, r12

end if

	mov	rdi, [rsp]
	mov	rsi, r13
	call	bigint$rsaprivate

if tls_server_rsa_blinding

	; result of that sitting in r13, now we need to undo our blinding
	; so, r13 = r13 * r14 % n
	mov	rdi, r13
	mov	rsi, r14
	call	bigint$multiply
	mov	rdx, [rsp]
	mov	rdi, r13
	mov	rsi, [rdx+rsaprivate_n_ofs]
	call	bigint$modby
	call	bigint$new
	mov	r15, rax
	; we can reuse the first monty object to check our results
	mov	rdi, [r13+bigint_monty_powmod_ofs]
	mov	rsi, r15				; destination for monty
	mov	rdx, r13				; source
	call	monty$doit
	; that must equal r12 or something went horribly wrong
	mov	rdi, r15
	mov	rsi, r12
	call	bigint$compare
	mov	[rsp], rax
	; so the result is sitting in r13, copy it to r12, cleanup everything else
	mov	rdi, r12
	mov	rsi, r13
	call	bigint$assign
	mov	rdi, r13
	call	bigint$destroy_clear
	mov	rdi, r14
	call	bigint$destroy_clear
	mov	rdi, r15
	call	bigint$destroy_clear

	pop	rax
	pop	r15 r14

	; so now, if eax is nonzero, we are kakked
	test	eax, eax
	jnz	.client_key_exchange_badrsa

else
	pop	rax
	pop	r15 r14
end if


	; so now we have our decrypted value sitting in r12
if tlsdebug
	mov	rdi, .client_kex_rsapm
	call	string$to_stdoutln
	mov	rdi, r12
	call	bigint$debug

	; BLACKLIST CHECK: test to invalidate it on purpose
	; mov	rdi, r12
	; mov	rsi, bigint$one
	; call	bigint$subtract

end if

	; heh, so, the _last_ 48 bytes, in reverse endian order, is our premaster secret
	mov	rdi, r12
	call	bigint$bytecount
	; Thanks to Thomas Ptacek for coercing me to document what I did here better:
	; Page 58 of the spec re: Bleichenbacher and Klima et al says:
	; if the padding is not correct, _or_ the length of the message is not exactly 48 bytes
	; then we have some issues to avoid.
	;
	; In my tests, I am unable to get a <= 48 byte result from the RSA private operation
	; (and of course that RSA private _includes_ the PKCS padding.)
	; So I check for "absurd overflow" (4096 bytes == a 32kbit rsa private result)
	; and I check for "sorry, no deal underflow", and in both cases I do terminate the
	; connection then and there with a failed handshake message.
	; With incorrect padding, this falls through despite incorrect padding/lengths, and
	; randomizes the version number if the one we got wasn't correct per the following
	; pages 59 and 60 of the spec. The end result of randomizing the version number is
	; a decryption error which results in random length expectation and subsequent drop
	; (and the subsequent drop is randomized thanks to the length expectation random).
	;
	; Shorter version: Since we do not send distinct messages for padding errors, and
	; only drop the connection if there is <= 48 bytes as a result of our RSA private
	; or absurdly too many, otherwise we keep going (and eventually run into a decrypt
	; fail which means random delays to the attackers). (the encrypted Finished message
	; results in a decrypt fail which is where the delays arise from).
	;
	; if the bytecount of that is not >48, something went horribly wrong
	cmp	rax, 48
	jbe	.client_key_exchange_badrsa
	cmp	rax, 4096
	jae	.client_key_exchange_badrsa
	mov	r13, rax
	sub	rsp, 4096
	; sub	rsp, rax
	mov	rdi, r12
	mov	rsi, rsp
	call	bigint$encode

	mov	rdx, r13
	sub	rdx, 48
	lea	rsi, [rsp+rdx]
	mov	edx, 48
	; page 59/60 of the RFC says we MUST check the version number, and if it doesn't match, to randomize it
	movzx	eax, word [rsi]
	cmp	dword [rbx+tls_version_ofs], eax
	je	.client_key_exchange_versionokay
	; otherwise, randomize it
	mov	rdi, rsi
	mov	esi, edx
	call	rng$block
	
	mov	rdx, r13
	sub	rdx, 48
	lea	rsi, [rsp+rdx]
	mov	edx, 48
calign
.client_key_exchange_versionokay:
	call	.keycalc
	; clear our stack for good measure
	mov	rdi, rsp
	xor	esi, esi
	mov	rdx, r13
	call	memset
	add	rsp, 4096
	; add	rsp, r13

	; cleanup our r12 cleanly (as it contains are decrypted premaster secret)
	mov	rdi, r12
	call	bigint$destroy_clear

	; set our expectmin/expectmax to be Finished
	mov	dword [rbx+tls_expectmin_ofs], 20
	mov	dword [rbx+tls_expectmax_ofs], 20

	; copy the pending read state to the current write state (so that our setting the current write state isn't affected by
	; the incoming Finished encrypted message, mac keys, IVs, etc)
	lea	rdi, [rbx+tls_cw_ofs]
	lea	rsi, [rbx+tls_pr_ofs]
	mov	edx, tls_cstate_size
	call	memcpy

	; get our cipherindex
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; we need to initialize our current write hmac before we proceed:
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	call	qword [rax+tls$cipherspecs+tls_cipherspec_macalgo_ofs]
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; and we need to set its key, which is a flat call
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localmackey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	call	hmac$key

	; and we need to initialize our current write cipher with our key
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localenckey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; MULTICIPHER MOD REQUIRED:
	call	aes$init_encrypt
	; restore our stackframe
	pop	r13 r12 rbx
	xor	eax, eax			; don't kill us off
	epilog
calign
.client_key_exchange_badrsa:
	; cleanup our r12 cleanly
	mov	rdi, r12
	call	bigint$destroy_clear
	pop	r13 r12 rbx
	jmp	.failed

if tlsdebug
cleartext .client_kex_rsam, 'client_key_exchange, RSA encrypted premaster secret is:'
cleartext .client_kex_rsapm, 'client_key_exchange, RSA decrypted premaster secret is:'
end if

calign
.client_key_exchange_DH:
	; we received the client's public DH value
	; length prefix of 2 bytes
	movzx	eax, word [rsi]
	sub	ecx, 2
	xchg	ah, al
	add	rsi, 2
	; make sure we have precisely the right amount of data for it
	cmp	ecx, eax
	jne	.failed
	; otherwise, we have a nice simple encoded public DH value
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	rdi, rsi
	mov	esi, ecx
	call	bigint$new_encoded
	mov	r12, rax
	; now we need our previousely saved secret reconstructed, which is sitting in tls_pr_ofs+tls_cstate_localmackey
	call	bigint$new
	mov	r13, rax
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_localmackey]
	mov	edx, [rsi]		; size in words from our save
	add	rsi, 4
	mov	rdi, [r13+bigint_words_ofs]
	mov	[r13+bigint_size_ofs], edx
	shl	edx, 3
	call	memcpy
	; so now our bigint at r13 is our DH private key, r12 is the client's DH public
	; we need to compute r12**r13 mod dh$pool_p, result of which is our premaster secret
	mov	ecx, [rbx+tls_dhindex_ofs]
	mov	rdi, r13
	mov	rsi, [rcx*8+dh$pool_p]
	call	monty$new
	mov	[r13+bigint_monty_powmod_ofs], rax
	mov	rdi, rax
	mov	rsi, r12
	mov	rdx, r12
	call	monty$doit
	; r12 now contains our premaster secret as an integer
if tlsdebug
	mov	rdi, .server_hello_done_rsadebug
	call	string$to_stdoutln
	mov	rdi, r12
	call	bigint$debug
end if

	; compute its length in bytes into r14d, hopefully it is a power of 2 or our stack will be all misaligned
	mov	rdi, r12
	call	bigint$bytecount
	mov	r14d, eax
	mov	rdi, r12
	sub	rsp, 4096
	; sub	rsp, rax
	mov	rsi, rsp
	call	bigint$encode
	; so, [rsp] for r14d bytes is our premaster secret, go ahead and calculate all our keys
	mov	rsi, rsp
	mov	edx, r14d
	call	.keycalc
	add	rsp, 4096
	; add	rsp, r14
	; now, we can cleanup both our values
	mov	rdi, r13
	call	bigint$destroy_clear
	mov	rdi, r12
	call	bigint$destroy_clear	; original value was public, but now contains our premaster secret, so clear it is
	
	; set our expectmin/expectmax to be Finished
	mov	dword [rbx+tls_expectmin_ofs], 20
	mov	dword [rbx+tls_expectmax_ofs], 20

	; copy the pending read state to the current write state (so that our setting the current write state isn't affected by
	; the incoming Finished encrypted message, mac keys, IVs, etc)
	lea	rdi, [rbx+tls_cw_ofs]
	lea	rsi, [rbx+tls_pr_ofs]
	mov	edx, tls_cstate_size
	call	memcpy

	; get our cipherindex
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; we need to initialize our current write hmac before we proceed:
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	call	qword [rax+tls$cipherspecs+tls_cipherspec_macalgo_ofs]
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; and we need to set its key, which is a flat call
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localmackey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	call	hmac$key

	; and we need to initialize our current write cipher with our key
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localenckey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; MULTICIPHER MOD REQUIRED:
	call	aes$init_encrypt

	; cleanup our stack
	pop	r14 r13 r12 rbx
	xor	eax, eax		; don't kill us off
	epilog

calign
.finished:
	; actual length of our handshake message (part, not including handshake header) must be precisely 12
	cmp	ecx, 12
	jne	.failed

	; depending on which mode we are in determines how we deal with this
	cmp	dword [rdi+tls_clientmode_ofs], 0
	jne	.finished_fromserver
	; finished from the client, rollback this finished message from our handshake accumulator _temporarily_
	; (because we'll need to include it again when we compose our own Finished message)
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi

	mov	r8, [rdi+tls_hacc_ofs]
	sub	qword [r8+buffer_length_ofs], 16
	sub	qword [r8+buffer_endptr_ofs], 16

	lea	rdx, [rdi+tls_cr_ofs+tls_cstate_mastersecret]
	mov	rcx, .cfin
	sub	rsp, 16
	mov	rsi, rsp
	call	.verify_data
	; put our length back
	mov	r8, [rbx+tls_hacc_ofs]
	add	qword [r8+buffer_length_ofs], 16
	add	qword [r8+buffer_endptr_ofs], 16
	
	; verify that they match
	mov	rdi, rsp
	mov	rsi, r12
	mov	edx, 12
	call	memcmp
	test	eax, eax
	jnz	.finished_mismatch

	; set our renegdata
	lea	rdi, [rbx+tls_renegdata_ofs]
	mov	rsi, r12
	mov	edx, 12
	call	memcpy

	; if we are already open, do our final upper layer connected notification
	cmp	dword [rbx+tls_open_ofs], 1
	je	.finished_resumption

	; match! fire off our ChangeCipherSpec and Finished message of our own, along with firing off the upper layer connected notification

if epoll_nodelay = 0
	; unfortunately, since our ChangeCipherSpec has to go out unencrypted, we can't do a single-shot
	; we need to add the ChangeCipherSpec 6 bytes at the end
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x14			; protocol record layer and 0x14 == 20 == ChangeCipherSpec
	mov	dword [rsp], eax
	mov	word [rsp+4], 0x0101		; low order length = 1, change cipher spec byte = 1
	; send the 6 bytes off

	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	edx, 6
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

end if
	
	; set our open flag indicating we are write-ready
	mov	dword [rbx+tls_open_ofs], 1
	mov	qword [rbx+tls_writeseq_ofs], 0

	; reset our expectmin and expectmax
	mov	dword [rbx+tls_expectmin_ofs], 0
	mov	dword [rbx+tls_expectmax_ofs], 0

	; compose our finished message on the stack
	mov	dword [rsp], 0x0c000014		; low order byte == handshake msg_type == 20 == Finished, next byte is high order length == 0, middle order length == 0, 0x0c == 12 bytes length
	lea	rdx, [rbx+tls_cr_ofs+tls_cstate_mastersecret]
	mov	rcx, .sfin
	mov	rsi, rsp
	add	rsi, 4
	call	.verify_data

	; set our renegdata
	lea	rdi, [rbx+tls_renegdata_ofs+12]
	lea	rsi, [rsp+4]
	mov	edx, 12
	call	memcpy

	; and finally, fire off our Finished message
	mov	rdi, rbx			; our tls object
if epoll_nodelay
	mov	esi, 0x36			; special record layer type tells tls$encrypt to send ChangeCipherSpec out with its result
else
	mov	esi, 0x16			; record layer type == handshake
end if
	mov	rdx, rsp			; buffer location
	mov	ecx, 16				; record layer length to encode
	call	tls$encrypt

	; and before we close the show, call our parent's connected method to let them know the
	; channel is open
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+tls_raddr_ofs]
	mov	edx, [rbx+tls_raddrlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]

	; reset our hacc buf as well
	mov	rdi, [rbx+tls_hacc_ofs]
	call	buffer$reset

	add	rsp, 16
	pop	r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
calign
.finished_resumption:
	; reset our expectmin and expectmax
	mov	dword [rbx+tls_expectmin_ofs], 0
	mov	dword [rbx+tls_expectmax_ofs], 0

	; and before we close the show, call our parent's connected method to let them know the
	; channel is open
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+tls_raddr_ofs]
	mov	edx, [rbx+tls_raddrlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]

	; reset our hacc buf as well
	mov	rdi, [rbx+tls_hacc_ofs]
	call	buffer$reset

	add	rsp, 16
	pop	r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
calign
.finished_fromserver:
	; otherwise, we need to get our verify data like before, only this time, we need to chop the last 16 bytes from the hacc
	; because this finished message already got added to it (we can safely just chop 16 bytes off its length) (and then put it back when we are done)
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi

	mov	r8, [rdi+tls_hacc_ofs]
	sub	qword [r8+buffer_length_ofs], 16
	sub	qword [r8+buffer_endptr_ofs], 16
	
	lea	rdx, [rdi+tls_cr_ofs+tls_cstate_mastersecret]
	mov	rcx, .sfin
	sub	rsp, 16
	mov	rsi, rsp
	call	.verify_data

	; we don't really need to put the length back, if they match we can reset the buffer anyway
	; verify that they match
	mov	rdi, rsp
	mov	rsi, r12
	mov	edx, 12
	call	memcmp
	test	eax, eax
	jnz	.finished_mismatch

	; set our renegdata
	lea	rdi, [rbx+tls_renegdata_ofs+12]
	mov	rsi, r12
	mov	edx, 12
	call	memcpy

if tls_client_sessioncache
	cmp	dword [rbx+tls_clientmode_ofs], 2
	je	.finished_fromserver_resumption
end if

	; otherwise, we are sweet, reset the handshake accumulator
	mov	rdi, [rbx+tls_hacc_ofs]
	call	buffer$reset

	add	rsp, 16
	pop	r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
if tls_client_sessioncache
calign
.finished_fromserver_resumption:
	; send our ChangeCipherSpec and Finished message, set everything to open
	mov	dword [rbx+tls_clientmode_ofs], 1	; restore it back to the normal value

	mov	r8, [rbx+tls_hacc_ofs]
	add	qword [r8+buffer_length_ofs], 16
	add	qword [r8+buffer_endptr_ofs], 16

	; unfortunately, since our ChangeCipherSpec has to go out unencrypted, we can't do a single-shot

	; we need to add the ChangeCipherSpec 6 bytes at the end
	mov	eax, [rbx+tls_version_ofs]
	shl	eax, 8
	or	eax, 0x14			; protocol record layer and 0x14 == 20 == ChangeCipherSpec
	mov	dword [rsp], eax
	mov	word [rsp+4], 0x0101		; low order length = 1, change cipher spec byte = 1
	; send the 6 bytes off

	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, rsp
	mov	edx, 6
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	; copy our current pending read state to our current write state (cuz it has all our keys)
	; (we don't copy the current pending read state to the current read state until we get the server's ChangeCipherSpec message)
	lea	rdi, [rbx+tls_cw_ofs]
	lea	rsi, [rbx+tls_pr_ofs]
	mov	edx, tls_cstate_size
	call	memcpy

	; clear our pending read state
	lea	rdi, [rbx+tls_pr_ofs]
	xor	esi, esi
	mov	edx, tls_cstate_size
	call	memset

	; get our cipherindex
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; we need to initialize our current write hmac before we proceed:
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	call	qword [rax+tls$cipherspecs+tls_cipherspec_macalgo_ofs]
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; and we need to set its key, which is a flat call
	lea	rdi, [rbx+tls_cw_hmac_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localmackey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	call	hmac$key

	; and we need to initialize our current write cipher with our key
	mov	eax, [rbx+tls_cw_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	lea	rdi, [rbx+tls_cw_cipher_ofs]
	lea	rsi, [rbx+tls_cw_ofs+tls_cstate_localenckey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; MULTICIPHER MOD REQUIRED:
	call	aes$init_encrypt

	
	; set our open flag indicating we are write-ready
	mov	dword [rbx+tls_open_ofs], 1
	mov	qword [rbx+tls_writeseq_ofs], 0

	; reset our expectmin and expectmax
	mov	dword [rbx+tls_expectmin_ofs], 0
	mov	dword [rbx+tls_expectmax_ofs], 0

	; compose our finished message on the stack
	mov	dword [rsp], 0x0c000014		; low order byte == handshake msg_type == 20 == Finished, next byte is high order length == 0, middle order length == 0, 0x0c == 12 bytes length
	lea	rdx, [rbx+tls_cr_ofs+tls_cstate_mastersecret]
	mov	rcx, .cfin
	mov	rsi, rsp
	add	rsi, 4
	call	.verify_data

	; set our renegdata
	lea	rdi, [rbx+tls_renegdata_ofs]
	lea	rsi, [rsp+4]
	mov	edx, 12
	call	memcpy

	; and finally, fire off our Finished message
	mov	rdi, rbx			; our tls object
	mov	esi, 0x16			; record layer type == handshake
	mov	rdx, rsp			; buffer location
	mov	ecx, 16				; record layer length to encode
	call	tls$encrypt

	; and before we close the show, call our parent's connected method to let them know the
	; channel is open
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+tls_sessionid_ofs+8]
	mov	edx, [rbx+tls_sessionidlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]

	; reset our hacc buf as well
	mov	rdi, [rbx+tls_hacc_ofs]
	call	buffer$reset

	add	rsp, 16
	pop	r12 rbx
	xor	eax, eax		; don't kill us off
	epilog

end if
calign
.finished_mismatch:
	mov	rdi, rbx
	mov	esi, tls_alert_fatal
	mov	edx, tls_alert_decrypt_error
	call	tls$send_alert
	add	rsp, 16
	pop	r12 rbx
	mov	eax, 1
	epilog
calign
.failed:
	; send a handshake_failed alert first, and die a thousand deaths
	; rdi must still be valid and pointing to our tls object when we get here
	mov	esi, tls_alert_fatal
	mov	edx, tls_alert_handshake_failure
	call	tls$send_alert
	mov	eax, 1
	epilog
calign
.warn_no_renegotiation:
	mov	esi, tls_alert_warning
	mov	edx, tls_alert_no_renegotiation
	call	tls$send_alert
	mov	eax, 1
	epilog
calign
.client_hello_sslv3:
	mov	esi, tls_alert_fatal
	mov	edx, tls_alert_protocol_version
	call	tls$send_alert
	mov	eax, 1
	epilog
dalign
.typedispatch:
	dq	.hello_request, .client_hello, .server_hello, .invalid, .invalid, .invalid, .invalid, .invalid, .invalid, .invalid, .invalid
	dq	.certificate, .server_key_exchange, .certificate_request, .server_hello_done, .certificate_verify, .client_key_exchange
	dq	.invalid, .invalid, .invalid, .finished
calign
.invalid:
	mov	eax, 1			; die a thousand deaths
	epilog
calign
.verify_data:
	; NOTE: nonstandard/private routine that is _called_, no prolog/epilog here qutie on purpose
	; rsi == spot to place our 12 bytes of verify_data, rbx == our tls object, rdx == pointer to the master secret to use, rcx == pointer to either client or server message
	push	r12 r13 r14 r15
	mov	r12, rsi		; save our destination
	mov	r14, rdx		; save our master secret temporarily
	mov	r15, rcx		; save the pointer to the 'client finished' or 'server finished' message
	cmp	dword [rbx+tls_version_ofs], 0x0303	; might be 0x0103, or 0x0203 if TLS1.0 or TLS1.1
	jb	.verify_data_oldtls

	; use the new style PRF (sha256, depending on cipher-specified goods)
	sub	rsp, hmac_size
	mov	r13, rsp

	; we need 80 bytes on the stack to do our deed
	sub	rsp, 80
	mov	rax, [r15]
	mov	rcx, [r15+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	; now we need a plain hash of the haccbuf contents
	mov	rdi, r13
	call	sha256$init
	mov	rcx, [rbx+tls_hacc_ofs]
	mov	rdi, r13
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	sha256$update
	mov	rdi, r13
	lea	rsi, [rsp+15]
	xor	edx, edx		; don't free us, haha
	call	sha256$final
	; so now, we can reinitialize the sha256 space as an hmac (since an hmac starts with one we can reuse it)
	mov	rdi, r13
	call	hmac$init_sha256
	mov	rdi, r13
	mov	rsi, r14
	mov	edx, 48
	call	hmac$key
	; so our phash size needs to be 15 + hmac_macsize_ofs
	mov	rdi, r13
	mov	rsi, r12
	mov	edx, 12
	mov	rcx, rsp
	mov	r8d, [r13+hmac_macsize_ofs]
	add	r8d, 15
	call	hmac$phash
	; output done, dusted

if tlsdebug
	; debug
	mov	rdi, .vstr
	call	string$to_stdoutln
	mov	rdi, r12
	mov	esi, 12
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	add	rsp, 80 + hmac_size

	pop	r15 r14 r13 r12
	ret
calign
.verify_data_oldtls:
	; old style PRF (md5, sha1)
	sub	rsp, hmac_size
	mov	r13, rsp

	; we need 80 bytes on the stack to do our deed, but we also need room for a second hmac
	sub	rsp, hmac_size + 80
	mov	rax, [r15]
	mov	rcx, [r15+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	lea	r15, [rsp+80]	; our second hmac location
	; so now we need to concatenate an md5 sum of the haccbuf _and_ a sha1 sum
	mov	rdi, r13
	call	md5$init
	mov	rcx, [rbx+tls_hacc_ofs]
	mov	rdi, r13
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	md5$update
	mov	rdi, r13
	lea	rsi, [rsp+15]
	xor	edx, edx	; don't free us, hahah
	call	md5$final
	; now we can reinitialize that one as a sha160
	mov	rdi, r13
	call	sha160$init
	mov	rcx, [rbx+tls_hacc_ofs]
	mov	rdi, r13
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	sha160$update
	mov	rdi, r13
	lea	rsi, [rsp+15+16]	; md5 == 16 byte length
	xor	edx, edx	; don't free us, hahah
	call	sha160$final
	; so now we have 15 byte label + 16 byte md5 + 20 byte sha160 (51 bytes)
	; now we need to initialize our actual hmac
	mov	rdi, r13
	call	hmac$init_md5
	mov	rdi, r13
	mov	rsi, r14
	mov	edx, 24
	call	hmac$key
	mov	rdi, r15
	call	hmac$init_sha1
	mov	rdi, r15
	lea	rsi, [r14+24]
	mov	edx, 24
	call	hmac$key
	; phash the md5 one, phash_xor the sha1 one, and we are done
	mov	rdi, r13
	mov	rsi, r12
	mov	edx, 12
	mov	rcx, rsp
	mov	r8d, 51
	call	hmac$phash
	mov	rdi, r15
	mov	rsi, r12
	mov	edx, 12
	mov	rcx, rsp
	mov	r8d, 51
	call	hmac$phash_xor

if tlsdebug
	; debug
	mov	rdi, .vstr
	call	string$to_stdoutln
	mov	rdi, r12
	mov	esi, 12
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if

	; done
	add	rsp, hmac_size * 2 + 80
	
	pop	r15 r14 r13 r12
	ret
if tlsdebug
cleartext .vstr, 'Verify Data 12 bytes is:'
end if
calign
.keycalc:
	; NOTE: nonstandard/private routine that is _called_, no prolog/epilog here quite on purpose
	; rsi == unencrypted real premaster secret, rbx == our tls object, preserve any callee-saves that we need, edx == length of our premaster secret (may not be 48 bytes)
	; if rsi is _null_ on entry, it is assumed that the master secret is already set, in whcih case we just do the key expansion bit

	; our goal: generate our master secret, and then generate our key expansion to come up with our keys
	; master secret is: PRF(pre_master_secret, "master secret", localrandom, remoterandom)[0..47]
	; key_block is: PRF(master_secret, "key expansion", server_random, client_random)[...however many are necessary...]

	; TODO: fair bit of copy/paste/same-same code in here, this needs a rework/cleanup, lazy boy.
	push	r12 r13 r14
	mov	r12, rsi		; our 48 byte premaster secret
	cmp	dword [rbx+tls_version_ofs], 0x0303	; might be 0x0103, or 0x0203 if TLS1.0 or TLS1.1
	jb	.keycalc_oldtls
	; use the new style PRF (sha256, depending on cipher-specified goods)
	mov	r14d, edx		; save our premaster length
	sub	rsp, hmac_size
	mov	r13, rsp
	mov	rdi, rsp
	call	hmac$init_sha256
	test	r12, r12
	jnz	.keycalc_newprf_normal
	; key is our master secret
	mov	rdi, r13
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 48
	call	hmac$key
	sub	rsp, 80 + tls_maxkeymaterial
	jmp	.keycalc_newprf_keyexpansion
calign
.keycalc_newprf_normal:
	; the key to our hmac is the premaster secret
	mov	rdi, r13
	mov	rsi, r12
	mov	edx, r14d
	call	hmac$key
	; so now we need to smash together our 77 byte long seed
	sub	rsp, 80 + tls_maxkeymaterial
	mov	rax, qword [.msec]
	mov	rcx, qword [.msec+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	lea	rdi, [rsp+13]		; unfortunate destination for our memcpy
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rax
	cmovne	rsi, rcx
	mov	edx, 32
	call	memcpy
	lea	rdi, [rsp+13+32]
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, rax
	mov	edx, 32
	call	memcpy
	; so now, we are finally ready to generate our master secret
	mov	rdi, r13
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 48
	mov	rcx, rsp
	mov	r8d, 77
	call	hmac$phash
	; master secret complete.
	; so next up is our key expansion, which needs the hmac initialized to the master secret as its key
	mov	rdi, r13
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 48
	call	hmac$replace_key
calign
.keycalc_newprf_keyexpansion:
	; and then 77 bytes again for key expansion + server random + client_random
	mov	rax, qword [.ksec]
	mov	rcx, qword [.ksec+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	lea	rdi, [rsp+13]		; unfortunate destination for our memcpy
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, rax
	mov	edx, 32
	call	memcpy
	lea	rdi, [rsp+13+32]
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rax
	cmovne	rsi, rcx
	mov	edx, 32
	call	memcpy
	; so our 77 byte seed for key expansion is all setup, now we need to determine how many bytes we need
	; to generate... we could just generate 128 bytes and call it good, but these functions are expensive
	; so we need to stick to the bare minimum
	; we are done with r12, so we can use that for our stack modifications
	; mac key length * 2, enc key length * 2, iv length * 2
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	r12d, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	add	r12d, dword [rax+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	add	r12d, dword [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	shl	r12d, 1
	mov	rdi, r13
	lea	rsi, [rsp+80]	; space for tls_maxkeymaterial bytes _after_ our 77 byte seed
	mov	edx, r12d
	mov	rcx, rsp
	mov	r8d, 77
	call	hmac$phash
	; ok so now we have our key material, and depending on which one of us is a client, depends on where we put it
	; use r12 to walk through the key material
	lea	r12, [rsp+80]
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	test	edx, edx
	jz	.keycalc_nomackeys
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localmackey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, r8
	call	memcpy
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_remotemackey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, r8
	cmovne	rsi, rcx
	; update r12 to skip over our mac keys
	lea	r12, [r12+rdx*2]
	call	memcpy
calign
.keycalc_nomackeys:
	; enc keys are next
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; ALL ciphers have keys, so we don't need to zerotest this one
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localenckey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, r8
	call	memcpy
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_remoteenckey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, r8
	cmovne	rsi, rcx
	; update r12 to skip over our enc keys
	lea	r12, [r12+rdx*2]
	call	memcpy
	; last but not least, ivs, which we may or may not have
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	test	edx, edx
	jz	.keycalc_noivs
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localiv_ofs]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, r8
	call	memcpy
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_remoteiv_ofs]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, r8
	cmovne	rsi, rcx
	call	memcpy
calign
.keycalc_noivs:
	; ok well, we extracted our key material
	; so now all we have left to do is blast all our sensitive data
	; which starts at rsp and moves up to 80+tls_maxkeymaterial+
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, hmac_size + tls_maxkeymaterial + 80
	call	memset32
	add	rsp, hmac_size + tls_maxkeymaterial + 80
	pop	r14 r13 r12
	ret
calign
.keycalc_oldtls:
	; use the old style PRF (md5 + sha1)
	push	rdx			; we have to save the length of our premaster secret

if tlsdebug
	; debug
	mov	rdi, .clientstr
	call	string$to_stdoutln
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rdi, rax
	cmovne	rdi, rcx
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	mov	rdi, .serverstr
	call	string$to_stdoutln
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rdi, rcx
	cmovne	rdi, rax
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; end debug
end if
	sub	rsp, hmac_size
	mov	r13, rsp
	sub	rsp, hmac_size
	mov	r14, rsp
	mov	rdi, r13
	call	hmac$init_md5
	mov	rdi, r14
	call	hmac$init_sha1
	test	r12, r12
	jnz	.keycalc_oldtls_normal
	; otherwise, no premaster secret, which means we already have a master secret:
	; so key expansion, which needs the hmac's initialized to the master secret as its key
	mov	rdi, r13
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 24
	call	hmac$key
	mov	rdi, r14
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret+24]
	mov	edx, 24
	call	hmac$key
	sub	rsp, 80 + tls_maxkeymaterial
	jmp	.keycalc_oldtls_keyexpansion
calign
.keycalc_oldtls_normal:
	; our premaster secret may not be evenly divisible by 2
	mov	edx, [rsp+hmac_size*2]
	; md5 gets the first half, sha1 gets the other half
	mov	rdi, r13
	add	edx, 1
	mov	rsi, r12
	shr	edx, 1
	call	hmac$key
	mov	ecx, [rsp+hmac_size*2]
	mov	rdi, r14
	mov	edx, ecx
	add	ecx, 1
	mov	rsi, r12
	shr	ecx, 1
	sub	edx, ecx
	add	rsi, rdx	;
	xchg	edx, ecx
	call	hmac$key
	; so now we need to smash together our 77 byte long seed
	sub	rsp, 80 + tls_maxkeymaterial
	mov	rax, qword [.msec]
	mov	rcx, qword [.msec+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	lea	rdi, [rsp+13]		; unfortunate destination for our memcpy
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rax
	cmovne	rsi, rcx
	mov	edx, 32
	call	memcpy
	lea	rdi, [rsp+13+32]
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, rax
	mov	edx, 32
	call	memcpy

	; so now, we are finally ready to generate our master secret
	mov	rdi, r13
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 48
	mov	rcx, rsp
	mov	r8d, 77
	call	hmac$phash

	; and do the same again for our sha1
	mov	rdi, r14
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 48
	mov	rcx, rsp
	mov	r8d, 77
	call	hmac$phash_xor


	; master secret complete.
	; so next up is our key expansion, which needs the hmac's initialized to the master secret as its key
	mov	rdi, r13
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret]
	mov	edx, 24
	call	hmac$replace_key
	mov	rdi, r14
	lea	rsi, [rbx+tls_pr_ofs+tls_cstate_mastersecret+24]
	mov	edx, 24
	call	hmac$replace_key
calign
.keycalc_oldtls_keyexpansion:
	; and then 77 bytes again for key expansion + server random + client_random
	mov	rax, qword [.ksec]
	mov	rcx, qword [.ksec+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	lea	rdi, [rsp+13]		; unfortunate destination for our memcpy
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, rax
	mov	edx, 32
	call	memcpy
	lea	rdi, [rsp+13+32]
	lea	rax, [rbx+tls_pr_ofs+tls_cstate_localrandom]
	lea	rcx, [rbx+tls_pr_ofs+tls_cstate_remoterandom]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rax
	cmovne	rsi, rcx
	mov	edx, 32
	call	memcpy
	; so our 77 byte seed for key expansion is all setup, now we need to determine how many bytes we need
	; to generate... we could just generate 128 bytes and call it good, but these functions are expensive
	; so we need to stick to the bare minimum
	; we are done with r12, so we can use that for our stack modifications
	; mac key length * 2, enc key length * 2, iv length * 2
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	r12d, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	add	r12d, dword [rax+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	add	r12d, dword [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	shl	r12d, 1
	mov	rdi, r13
	lea	rsi, [rsp+80]	; space for tls_maxkeymaterial bytes _after_ our 77 byte seed
	mov	edx, r12d
	mov	rcx, rsp
	mov	r8d, 77
	call	hmac$phash
	mov	rdi, r14
	lea	rsi, [rsp+80]	; space for tls_maxkeymaterial bytes _after_ our 77 byte seed
	mov	edx, r12d
	mov	rcx, rsp
	mov	r8d, 77
	call	hmac$phash_xor

	; ok so now we have our key material, and depending on which one of us is a client, depends on where we put it
	; use r12 to walk through the key material
	lea	r12, [rsp+80]
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	test	edx, edx
	jz	.keycalc_oldtls_nomackeys
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localmackey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, r8
	call	memcpy
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_remotemackey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, r8
	cmovne	rsi, rcx
	; update r12 to skip over our mac keys
	lea	r12, [r12+rdx*2]
	call	memcpy
calign
.keycalc_oldtls_nomackeys:
	; enc keys are next
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; ALL ciphers have keys, so we don't need to zerotest this one
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localenckey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, r8
	call	memcpy
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_remoteenckey]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, r8
	cmovne	rsi, rcx
	; update r12 to skip over our enc keys
	lea	r12, [r12+rdx*2]
	call	memcpy
	; last but not least, ivs, which we may or may not have
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	test	edx, edx
	jz	.keycalc_oldtls_noivs
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_localiv_ofs]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, rcx
	cmovne	rsi, r8
	call	memcpy
	mov	eax, [rbx+tls_pr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_ivlen_ofs]
	lea	rdi, [rbx+tls_pr_ofs+tls_cstate_remoteiv_ofs]
	mov	rcx, r12
	lea	r8, [r12+rdx]
	cmp	dword [rbx+tls_clientmode_ofs], 1
	cmove	rsi, r8
	cmovne	rsi, rcx
	call	memcpy
calign
.keycalc_oldtls_noivs:
	; ok well, we extracted our key material
	; so now all we have left to do is blast all our sensitive data
	; which starts at rsp and moves up to 80+tls_maxkeymaterial+
	mov	rdi, rsp
	xor	esi, esi
	mov	edx, hmac_size * 2 + tls_maxkeymaterial + 80 + 8
	call	memset32
	add	rsp, hmac_size * 2 + tls_maxkeymaterial + 80 + 8
	pop	r14 r13 r12
	ret
if tlsdebug
cleartext .clientstr, 'client random is:'
cleartext .serverstr, 'server random is:'
end if
dalign
.msec:
	db	'master secret'
dalign
.ksec:
	db	'key expansion'
dalign
.cfin:
	db	'client finished'
dalign
.sfin:
	db	'server finished'

end if



if used tls$receive | defined include_everything
	; three arguments: rdi == our tls object, rsi == ptr to data, rdx == length of same
	;
	; NOTES HERE: it is not immediately clear from the RFC whether interleaving _and_ fragments occur simultaneously.
	; In sniffing around other implementations in the wild, it would appear great pains have been taken to allow for this.
	; I don't really see any valid reason why we would get a _partial_ fragment of one type, followed by anything other
	; than the rest of it back-to-back. So, while I am happy to deal with interleaved ContentTypes, our partial
	; fragment handling demands that the content type of the NEXT fragment (assuming it was indeed partial and waiting
	; for the rest of its fragment to arrive) is the same type, and if it isn't, we'll produce an error alert.
	;
falign
tls$receive:
	prolog	tls$receive
	push	rbx r12 r13
	mov	rbx, rdi		; save our tls object, we'll need it
	mov	rdi, [rdi+tls_accbuf_ofs]
	call	buffer$append
	mov	r12, [rbx+tls_accbuf_ofs]
	mov	r13, [r12+buffer_length_ofs]
	mov	r12, [r12+buffer_itself_ofs]
calign
.parseloop:
	cmp	r13, 5
	jb	.needmore
	; record layer says first byte must be one of: 
	; 0x14 (change_cipher_spec)
	; 0x15 (alert)
	; 0x16 (handshake)
	; 0x17 (application_data)
	; if it is _not_, then we need to signal an error
	movzx	eax, byte [r12]
	movzx	ecx, word [r12+1]
	cmp	eax, 0x14
	jb	.error
	cmp	eax, 0x17
	ja	.error
	; major version must be 3
	cmp	cl, 3
	jne	.error
	; length check next
	movzx	edx, word [r12+3]
	xchg	dh, dl
	add	edx, 5
	; so now, edx contains the full boat of how many bytes we need sitting here to constitute a full block
	cmp	r13, rdx
	jb	.needmore
	; then length of which is sitting in edx
	mov	rdi, rbx
	mov	rsi, r12
	; before we process the record, update r12 and r13
	add	r12, rdx
	sub	r13, rdx
	call	tls$decrypt		; this will append its result to recordbuf, and return nonzero in eax if it encountered a fatal error
	test	eax, eax
	jnz	.error
	; so now, recordbuf contains our decrypted goods
	; its dword at buffer_user_ofs is its record layer content type, and +4 dword is the record layer specified length (accumulated)
	; zero length fragments were already checked
	mov	rdi, [rbx+tls_recordbuf_ofs]
	mov	eax, [rdi+buffer_user_ofs]	; its type
	mov	ecx, [rdi+buffer_user_ofs+4]	; its length
	sub	eax, 0x14
	jmp	qword [rax*8+.typedispatch]
calign
.change_cipher_spec:
	; if the length isn't 1, die.
	cmp	ecx, 1
	jne	.error
	; otherwise, we copy the pending read state to the current read state, and zero the pending read state
	; if the ciphertype result is 0, die
	cmp	dword [rbx+tls_pr_ofs+tls_cstate_ciphervalid], 0
	je	.error
	; if our handshake state is not expecting Finished next, die.
	cmp	dword [rbx+tls_expectmin_ofs], 20
	jne	.error
	cmp	dword [rbx+tls_expectmax_ofs], 20
	jne	.error

	; reset our recordbuf before we proceed, since it is already sitting in rdi
	mov	rdi, [rbx+tls_recordbuf_ofs]
	mov	qword [rdi+buffer_user_ofs], 0
	call	buffer$reset
	; copy the pending read state to the current read state
	lea	rdi, [rbx+tls_cr_ofs]
	lea	rsi, [rbx+tls_pr_ofs]
	mov	edx, tls_cstate_size
	call	memcpy

	; if we are in client mode, _and_ we are resuming a previous session, don't clear our read state just yet
	cmp	dword [rbx+tls_clientmode_ofs], 2
	je	.change_cipherspec_noclear

	; clear the pending read state
	lea	rdi, [rbx+tls_pr_ofs]
	xor	esi, esi
	mov	edx, tls_cstate_size
	call	memset32

calign
.change_cipherspec_noclear:

	; initialize the read hmac
	; get our cipherindex
	mov	eax, [rbx+tls_cr_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; we need to initialize our current write hmac before we proceed:
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	call	qword [rax+tls$cipherspecs+tls_cipherspec_macalgo_ofs]
	mov	eax, [rbx+tls_cr_ofs+tls_cstate_cipherindex]
	shl	eax, 6

	; and we need to set its key, which is a flat call
	lea	rdi, [rbx+tls_cr_hmac_ofs]
	lea	rsi, [rbx+tls_cr_ofs+tls_cstate_remotemackey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_mackeylen_ofs]
	call	hmac$key

	; and we need to initialize our current read cipher with our key
	mov	eax, [rbx+tls_cr_ofs+tls_cstate_cipherindex]
	shl	eax, 6
	lea	rdi, [rbx+tls_cr_cipher_ofs]
	lea	rsi, [rbx+tls_cr_ofs+tls_cstate_remoteenckey]
	mov	edx, [rax+tls$cipherspecs+tls_cipherspec_keylen_ofs]
	; MULTICIPHER MOD REQUIRED:
	call	aes$init_decrypt

	; if we are in client mode, skip the checks for the server session cache goods
	cmp	dword [rbx+tls_clientmode_ofs], 0
	jne	.parseloop

if tls_server_sessioncache
	; if we are already open, special handling because we resumed a session
	cmp	dword [rbx+tls_open_ofs], 1
	je	.change_cipher_spec_alreadyopen

	lea	rsi, [rbx+tls_cr_ofs]
	lea	rdi, [rbx+tls_sessionid_ofs+8]
	call	tls$sessioncache_set

calign
.change_cipher_spec_alreadyopen:
end if
	; keep going
	jmp	.parseloop
calign
.alert:
	; if the length is > 2, die.
	cmp	ecx, 2
	ja	.error
	; if the length is < 2, alert was fragmented
	jb	.parseloop
	; otherwise, our record buf contains precisely 2 bytes
	mov	rsi, [rdi+buffer_itself_ofs]
	movzx	edx, byte [rsi+1]
	movzx	esi, byte [rsi]
	mov	rdi, rbx
	call	tls$process_alert
	; if process_alert returned nonzero, die.
	test	eax, eax
	jnz	.error
	; reset the record buffer
	mov	rdi, [rbx+tls_recordbuf_ofs]
	mov	qword [rdi+buffer_user_ofs], 0
	call	buffer$reset
	; keep going

	jmp	.parseloop
calign
.handshake:
	; if the length is < 4, fragmented, need more
	cmp	ecx, 4
	jb	.parseloop
	mov	r8d, ecx
	; otherwise, extract our handshake type, and bytes in the message
	mov	rsi, [rdi+buffer_itself_ofs]
	movzx	edx, byte [rsi]		; handshake type
	mov	ecx, [rsi]		; the first 4 bytes
	and	ecx, not 0xff		; strip the handshake type out
	bswap	ecx			; the length
	; so now, our length sitting in the recordbuf must be ecx+4, if it is greater than that, die.
	; if it is less than that, fragmented, need more
	add	ecx, 4
	cmp	r8d, ecx
	ja	.error
	jb	.parseloop
	; otherwise, valid handshake message
	add	rsi, 4			; skip the length and type
	sub	ecx, 4			; restore the actual length
	mov	rdi, rbx		; tls object
	; rsi == pointer into the recordbuffer where the handshake message begins
	; edx == the handshake TYPE
	; ecx == the length of the handshake message
	call	tls$process_handshake
	; if it returns nonzero, a fatal error has occurred
	test	eax, eax
	jnz	.error
	; reset the record buffer
	mov	rdi, [rbx+tls_recordbuf_ofs]
	mov	qword [rdi+buffer_user_ofs], 0
	call	buffer$reset
	; keep going
	jmp	.parseloop
calign
.application_data:
	; make sure we are open for business
	cmp	dword [rbx+tls_open_ofs], 1
	jne	.error
	; we are already decrypted, pass the contents of recordbuf up the chain
	test	ecx, ecx
	jz	.parseloop		; it is valid for length 0 application data to get passed to us, ignore

	; pass the recordbuffer up the io chain, checking to see if they want us to close
	mov	rcx, [rbx+tls_recordbuf_ofs]
	mov	rdi, [rbx+io_parent_ofs]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	r8, [rdi]		; its vtable
	call	qword [r8+io_vreceive]
	test	eax, eax
	jnz	.application_data_suicide
	; reset the record buffer
	mov	rdi, [rbx+tls_recordbuf_ofs]
	mov	qword [rdi+buffer_user_ofs], 0
	call	buffer$reset
	; keep going
	jmp	.parseloop
calign
.application_data_suicide:
	mov	rdi, rbx
	mov	esi, tls_alert_warning
	mov	edx, tls_alert_close_notify
	call	tls$send_alert
	; we don't jump to error because we don't need to raise the error call if the parent layer requested death anyway
	; reset the accbuf
	mov	rdi, [rbx+tls_accbuf_ofs]
	call	buffer$reset
	pop	r13 r12 rbx
	mov	eax, 1			; kill us off
	epilog
dalign
.typedispatch:
	dq	.change_cipher_spec, .alert, .handshake, .application_data
calign
.needmore:
	; if r12 has moved forward in the accbuf, we need to consume however many bytes it did
	mov	rdi, [rbx+tls_accbuf_ofs]
	mov	rsi, r12
	sub	rsi, [rdi+buffer_itself_ofs]
	test	rsi, rsi
	jz	.needmore_returnonly
	call	buffer$consume
	pop	r13 r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
calign
.needmore_returnonly:
	pop	r13 r12 rbx
	xor	eax, eax		; don't kill us off
	epilog
calign
.error:
	; reset the accbuf
	mov	rdi, [rbx+tls_accbuf_ofs]
	call	buffer$reset

	; notify our parent layer that we raised an error, but only if the channel is open
	cmp	dword [rbx+tls_open_ofs], 1
	jne	.error_skipnotify

	mov	rdi, [rbx+io_parent_ofs]
	mov	rsi, [rdi]		; its vtable
	call	qword [rsi+io_verror]
calign
.error_skipnotify:
	pop	r13 r12 rbx
	mov	eax, 1			; kill us off
	epilog
calign
.receive_plaintext:
	; no ciphertype is set for this connection, which means we are in the initialization stage
	xor	eax, eax	; don't kill us off
	epilog

end if

