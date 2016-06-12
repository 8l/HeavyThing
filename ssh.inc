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
	; ssh.inc: io descendent to deal with client/server SSH v2.0 goodies
	;
	; NOTE: we are not RFC-compliant here, mainly due to my lack of inclusion
	; of "REQUIRED" cipher suites/KEX/etc. My narrow-minded selection is
	; based on my own preferences. Notes on my choices follow. Despite not
	; having done all the "REQUIRED" bits like 3DES, interoperability is fine
	; and dandy. All of the SSH clients/servers I have dealt with support my
	; choices herein.
	;
	; diffie-hellman-group-exchange-sha256: I dislike the idea of using public
	;   DH params, and much prefer using our own safe primes. While this does
	;   increase the key exchange byte overhead by having to send the DH p
	;   I feel this is well worth it, as the authors of RFC4419 agree.
	;   Whether we use dh_pool.inc (and the associated safe prime size)
	;   or whether we do them on-the-fly is configurable. See the notes I put
	;   along with the configuration option on caution advice with non-static
	;   DH params.
	; ssh-rsa/ssh-dsa PK goods: For signing/host key/PK ops, we support both
	;   since they are similar and in widespread use. The choice as to which
	;   server-side decides to use is configurable at compile time.
	; aes256-cbc: On AESNI hardware, aes256 is insanely fast, and the bottleneck
	;   is of course the HMAC speed. When I bother to implement GCM for TLS I'll
	;   toss it and CTR or something else in here as well. For all my SSH needs
	;   the actual full-rate aes256-cbc is ridiculously more than enough.
	;   NOTE: to mitigate the CBC "leaking 14 bits of plaintext" issue, we
	;   treat bad lengths special and keep going for a random length of time
	;   such that bad length and bad HMAC cannot be distinguished. ( see:
	;   http://www.isg.rhul.ac.uk/~kp/SandPfinal.pdf ). Further to this, and to
	;   completely thwart the attack in the aforementioned paper, we employ
	;   special handling for HMAC failures, in that during normal operation,
	;   no HMAC errors ever arise. Thus, if we do encounter an hmac error, we
	;   intentionally randomize our length requirement at that moment in time
	;   such that no information is leaked. (although, the lack of a reply at
	;   all from our side is in itself somewhat of an indication that it has
	;   failed). Further to this, in client mode, we send an SSH_MSG_IGNORE
	;   with a random amount of actual data prior to sending our password anyway
	;   this appears to fully deal with the issue
	; hmac-sha2-256: While SHA512 is faster, the extra protocol overhead to carry
	;   it doesn't seem to have any benefit. SHA256 it is.
	; 
	;
	; NOTE 2: The SSH protocol is quite flexible, and supports a great many
	; modes of operation/channels/etc. For all of my uses, I only require a single
	; channel open, normally a session. To support sftp and the like, the kind
	; of channel request we send is determined by the dword in ssh_clientmode_ofs
	; being 2 instead of 1. If it is a 1, we'll start a shell, 2 and we'll start
	; subsystem sftp. For server-mode, we'll accept either.
	;
	; NOTE 3: due to the way I did io chaining, I treat stderr as 2>&1 style
	; meaning all extended data/stderr that comes through gets added
	; for all of my use cases, this suits me fine
	;
	; NOTE 4: in client mode, after ssh$new_client is called, you have to set
	; the terminal width/height beforehand, and then if you want to change it
	; you have to call ssh$client_windowsize (if the connection is interactive
	; and open already, sends it over the wire as well). Defaults to 80x25
	;
	; NOTE 5: in client mode, we do verify the host signature for both RSA and
	; DSA, but we are not presently checking the hostkey against any database
	; see the calls to .keycalc herein, as when they are called r12/r13 are
	; pointers to the hostkey blob itself, and that'd be a fine time to
	; generate a hash into the ssh_hostkey_ofs buffer if one was interested
	;


	; This is an io.inc "descendent", meant to be chained the same way that I 
	; did the TLS layer.
	;

sshdebug = 0

	; various settings apply, see the default settings for further details

if used ssh_ident | defined include_everything
	; our ident, not in string form intentionally:
dalign
ssh_ident:
	db	'SSH-2.0-HeavyThing',13,10
ssh_ident_len = $ - ssh_ident

end if

if used ssh_ident_blacklisted | defined include_everything
	; our ident that gets sent out if the other end was blacklisted for bad hmac/twiddling with us
dalign
ssh_ident_blacklisted:
	db	'SSH-2.0-HeavyThing ::You are blacklisted, find something else to do::',13,10
ssh_ident_blacklisted_len = $ - ssh_ident_blacklisted

end if

if used ssh_service | defined include_everything
	; our service name we send for client mode connections
dalign
ssh_service:
	db	0, 0, 0, 14, 'ssh-connection'
ssh_service_len = $ - ssh_service

end if


if used ssh_kexinit | defined include_everything
	; our kexinit "bundle of name-list joy"
	; split into two parts, with the first being the optional pubkey algs we advertise as a server (client uses both)

dalign
ssh_kexinit_both:
	; kex_algorithms
	db 0, 0, 0, 36, 'diffie-hellman-group-exchange-sha256'
	; server_host_key_algorithms
	db 0, 0, 0, 15, 'ssh-rsa,ssh-dss'
ssh_kexinit_both_len = $ - ssh_kexinit_both

dalign
ssh_kexinit_rsa:
	; kex_algorithms
	db 0, 0, 0, 36, 'diffie-hellman-group-exchange-sha256'
	; server_host_key_algorithms
	db 0, 0, 0, 7, 'ssh-rsa'
ssh_kexinit_rsa_len = $ - ssh_kexinit_rsa
	
dalign
ssh_kexinit_dsa:
	; kex_algorithms
	db 0, 0, 0, 36, 'diffie-hellman-group-exchange-sha256'
	; server_host_key_algorithms
	db 0, 0, 0, 7, 'ssh-dss'
ssh_kexinit_dsa_len = $ - ssh_kexinit_dsa
	

	; the remainder
dalign
ssh_kexinit:
	; encryption_algorithms_client_to_server
	db 0, 0, 0, 10, 'aes256-cbc'
	; encryption_algorithms_server_to_client
	db 0, 0, 0, 10, 'aes256-cbc'
	; mac_algorithms_client_to_server
	db 0, 0, 0, 13, 'hmac-sha2-256'
	; mac_algorithms_server_to_client
	db 0, 0, 0, 13, 'hmac-sha2-256'
if ssh_do_compression

if ssh_force_compression
	; compression_algorithms_client_to_server
	db 0, 0, 0, 21, 'zlib@openssh.com,zlib'
	; compression_algorithms_server_to_client
	db 0, 0, 0, 21, 'zlib@openssh.com,zlib'
else
	; compression_algorithms_client_to_server
	db 0, 0, 0, 26, 'zlib@openssh.com,zlib,none'
	; compression_algorithms_server_to_client
	db 0, 0, 0, 26, 'zlib@openssh.com,zlib,none'
end if

else
	db 0, 0, 0, 4, 'none'
	db 0, 0, 0, 4, 'none'
end if
	; languages_client_to_server
	db 0, 0, 0, 0
	; languages_server_to_client
	db 0, 0, 0, 0
	; bool first_kex_packet_follows
	db 0
	; uint32 0 reserved for future extensions
	db 0, 0, 0, 0

ssh_kexinit_len = $ - ssh_kexinit

end if

	; stage constants
ssh_stage_idents = 0
ssh_stage_wantkexinit = 1
ssh_stage_wantkexgexreq = 2
ssh_stage_wantkexgexgroup = 3
ssh_stage_wantkexgexinit = 4
ssh_stage_wantkexgexreply = 5
ssh_stage_wantnewkeys = 6
ssh_stage_wantservice = 7
ssh_stage_wantuserauth = 8
ssh_stage_wantchannel = 9
ssh_stage_channel = 10
ssh_stage_interactive = 11
ssh_stage_torndown = 12
if ssh_blacklist
ssh_stage_goaway = 13
end if


	; ssh object offsets and size
ssh_clientmode_ofs = io_base_size				; 0 == server, 1 == session client, 2 == sftp client
ssh_open_ofs = io_base_size + 8					; bool, true if we made it all the way through the first kex/keys/etc
ssh_compstate_ofs = io_base_size + 16				; compression state: 0 == inactive, 1 == pending SSH_MSG_USERAUTH_SUCCESS, 2 == active
ssh_stage_ofs = io_base_size + 24				; dd, one of our constants above
ssh_sessionid_ofs = io_base_size + 32				; our 32 byte session id, aka H (initial one only)
ssh_hash_ofs = ssh_sessionid_ofs + 32				; our hash H (initial one same as above)
ssh_localcert_ofs = ssh_hash_ofs + 32 				; if we are in server mode, pointer to the X509 object
ssh_dh_p_ofs = ssh_localcert_ofs + 8				; if we are client mode, or server mode with dynamic on the fly DH params, these are the ones
ssh_dh_g_ofs = ssh_dh_p_ofs + 8					; ""
ssh_dh_private_ofs = ssh_dh_g_ofs + 8				; our dh private value
ssh_dh_e_ofs = ssh_dh_private_ofs + 8				; public e
ssh_dh_f_ofs = ssh_dh_e_ofs + 8					; public f
ssh_dh_shared_ofs = ssh_dh_f_ofs + 8				; this value doesn't stick around for long, but is used for subsequent key calcs
ssh_dh_min_ofs = ssh_dh_shared_ofs + 8				; really a uint32, client min bits
ssh_dh_n_ofs = ssh_dh_min_ofs + 8				; "", client n
ssh_dh_max_ofs = ssh_dh_n_ofs + 8				; "", client max bits
ssh_pending_localiv_ofs = ssh_dh_max_ofs + 8			; pending localiv, awaiting NEWKEYS, note: the real ones are used on-the-fly and change with each block
ssh_pending_remoteiv_ofs = ssh_pending_localiv_ofs + 32 	; pending remoteiv, awaiting NEWKEYS (which is why we have pending and active ones)
ssh_localiv_ofs = ssh_pending_remoteiv_ofs + 32			; current localiv
ssh_remoteiv_ofs = ssh_localiv_ofs + 32 			; current remoteiv
ssh_localkey_ofs = ssh_remoteiv_ofs + 32			; pending local AES256 key (these get zeroed once they go into effect)
ssh_remotekey_ofs = ssh_localkey_ofs + 32			; pending remote AES256 key
ssh_localint_ofs = ssh_remotekey_ofs + 32			; pending local integrity key
ssh_remoteint_ofs = ssh_localint_ofs + 32			; pending remote integrity key
ssh_localkexinit_ofs = ssh_remoteint_ofs + 32			; a buffer that holds our local kexinit
ssh_remotekexinit_ofs = ssh_localkexinit_ofs + 8		; a buffer that holds the remote kexinit
ssh_remoteident_ofs = ssh_remotekexinit_ofs + 8			; a buffer that holds the remote ident sans the CRLF
ssh_hostkey_ofs = ssh_remoteident_ofs + 8			; a buffer that holds the host key
ssh_accbuf_ofs = ssh_hostkey_ofs + 8				; a buffer to accumulate data received
ssh_packetbuf_ofs = ssh_accbuf_ofs + 8				; a buffer to hold decompressed packets
ssh_peeklen_ofs = ssh_packetbuf_ofs + 8				; decrypted length to wait for
ssh_readseq_ofs = ssh_peeklen_ofs + 8				; our 32 bit read sequence
ssh_writeseq_ofs = ssh_readseq_ofs + 8				; our 32 bit write sequence
ssh_channelid_ofs = ssh_writeseq_ofs + 8			; the channel id in use
ssh_localwindow_ofs = ssh_channelid_ofs + 8			; our 32 bit window size
ssh_remotewindow_ofs = ssh_localwindow_ofs + 8			; remote 32 bit window size
ssh_width_ofs = ssh_remotewindow_ofs + 8			; our terminal columns
ssh_height_ofs = ssh_width_ofs + 8				; our terminal rows
ssh_readcipher_ofs = ssh_height_ofs + 8				; aes_size bytes for our current read cipher
ssh_writecipher_ofs = ssh_readcipher_ofs + aes_size		; aes_size bytes for our current write cipher
ssh_readhmac_ofs = ssh_writecipher_ofs + aes_size		; hmac_size bytes for our current read hmac
ssh_writehmac_ofs = ssh_readhmac_ofs + hmac_size		; hmac_size bytes for our current write hmac
ssh_inflate_ofs = ssh_writehmac_ofs + hmac_size			; if we are doing compression, our inflate state
ssh_deflate_ofs = ssh_inflate_ofs + zlib_stream_size		; if we are doing compression, our deflate state
ssh_wsizecb_ofs = ssh_deflate_ofs + zlib_stream_size		; an optional callback for when the window size changes
ssh_wsizecbarg_ofs = ssh_wsizecb_ofs + 8			; if the callback is set, this == rdi when it is called, if 0, then the ssh object itself
ssh_authcb_ofs = ssh_wsizecbarg_ofs + 8				; an optional callback for server-mode user/pass verification
ssh_authcbarg_ofs = ssh_authcb_ofs + 8				; if the callback is set, this == rdi when it is called (rsi == string username, rdx == string password), 0 == ssh object itself
ssh_eofcb_ofs = ssh_authcbarg_ofs + 8				; an optional callback for when we receive an EOF (valid for both client/server mode)
ssh_eofcbarg_ofs = ssh_eofcb_ofs + 8				; if the callback is set, this == rdi when it is called, if 0, then the ssh object itself
									; NOTE HERE: if you return nonzero in eax, we'll get silently torn down (e.g. no call to verror)
ssh_username_ofs = ssh_eofcbarg_ofs + 8				; if in client mode, the username that was passed to new_client, if in server mode, the username of the remote party
ssh_password_ofs = ssh_username_ofs + 8				; optional password
ssh_exec_ofs = ssh_password_ofs + 8				; if in server mode, and we get an exec connection, this is its contents + args
								; if in client mode, and this is nonzero (pointer to string), we'll issue an exec instead of a shell/pty
ssh_localenc_ofs = ssh_exec_ofs + 8				; bool as to whether we are doing outbound encryption or not
ssh_remoteenc_ofs = ssh_localenc_ofs + 8 			; bool as to whether we are doing inbound encryption or not
ssh_dead_ofs = ssh_remoteenc_ofs + 8				; bool as to whether we encountered a fatal error, but are sitting in wait for more data
ssh_raddr_ofs = ssh_dead_ofs + 8				; if in server mode, this is the remote address
ssh_raddrlen_ofs = ssh_raddr_ofs + 110			

ssh_size = ssh_raddrlen_ofs + 8

	; TODO: hmm, thats a whole lotta buffers for a single ssh object, we should probably reduce that number
	; really, that is a whole lotta state variables for an ssh connection, haha, ughghh

if used ssh$vtable | defined include_everything

dalign
ssh$vtable:
	dq	ssh$destroy, ssh$clone, ssh$connected, ssh$send, ssh$receive, io$error, io$timeout


	; we also keep a global count of how many ssh sessions there are
	; NOTE: we do not increase this count with new_server, but decrease it with destroy, so if you
	; destroy your listener, you'll have to increase this count by one
globals
{
	ssh_session_count	dd	0
}



end if


globals
{
if used ssh$new_server & ssh_blacklist
	ssh$blacklist	dq	0
else if defined include_everything
	ssh$blacklist	dq	0
end if
}


if used ssh$new_client | defined include_everything
	; two arguments: rdi == username to send, or 0 for default 'taketwo', rsi == password to send, or 0 for no password (userauth method == 'none' in this case)
	; returns a new parent/childless ssh object ready for client mode
	; NOTE: we do _not_ make copies of the username/password passed, and do not attempt to heap$free them either
falign
ssh$new_client:
	prolog	ssh$new_client
	add	dword [ssh_session_count], 1
	push	rdi rsi
	test	rdi, rdi
	jz	.nousercopy		; if there was no username, there won't be a password either
	call	string$copy
	mov	[rsp+8], rax
	mov	rdi, [rsp]
	test	rdi, rdi
	jz	.nousercopy
	call	string$copy
	mov	[rsp], rax
calign
.nousercopy:
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	call	buffer$new
	push	rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	edi, ssh_size
	call	heap$alloc_clear
	pop	r11 r10 r9 r8 rcx rdx rsi rdi
	mov	qword [rax], ssh$vtable
	mov	dword [rax+ssh_clientmode_ofs], 1		; change this to a 2 after this function call if you want us to send subsystem sftp
	mov	[rax+ssh_deflate_ofs+zlib_inbuf_ofs], r11
	mov	[rax+ssh_deflate_ofs+zlib_outbuf_ofs], r10
	mov	[rax+ssh_accbuf_ofs], r8
	mov	[rax+ssh_packetbuf_ofs], r9
	; some trickery here for the inflate goods:
	mov	[rax+ssh_inflate_ofs+zlib_inbuf_ofs], r11	; use the same inbuf for the temporary storage on receive of compressed goods
	mov	[rax+ssh_inflate_ofs+zlib_outbuf_ofs], r9	; use the packetbuf as the output area for inflate
	mov	[rax+ssh_localkexinit_ofs], rcx
	mov	[rax+ssh_remotekexinit_ofs], rdx
	mov	[rax+ssh_remoteident_ofs], rsi
	mov	[rax+ssh_hostkey_ofs], rdi
	mov	dword [rax+ssh_width_ofs], 80
	mov	dword [rax+ssh_height_ofs], 25
	pop	rsi rdi
	mov	[rax+ssh_username_ofs], rdi
	mov	[rax+ssh_password_ofs], rsi
	epilog
end if

if used ssh$destroy | defined include_everything
	; single argument in rdi: our ssh object
falign
ssh$destroy:
	prolog	ssh$destroy
	sub	dword [ssh_session_count], 1
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+ssh_localkexinit_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+ssh_remotekexinit_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+ssh_remoteident_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+ssh_hostkey_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+ssh_accbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$destroy
	; we init deflate's inbuf and outbuf regardless of whether comp was enabled
	mov	rdi, [rbx+ssh_deflate_ofs+zlib_inbuf_ofs]
	call	buffer$destroy
	mov	rdi, [rbx+ssh_deflate_ofs+zlib_outbuf_ofs]
	call	buffer$destroy
if ssh_do_compression
	cmp	qword [rbx+ssh_inflate_ofs+zlib_state_ofs], 0
	je	.noinf
	lea	rdi, [rbx+ssh_inflate_ofs]
	call	zlib$inflateEnd
.noinf:
	cmp	qword [rbx+ssh_deflate_ofs+zlib_state_ofs], 0
	je	.nodef
	lea	rdi, [rbx+ssh_deflate_ofs]
	call	zlib$deflateEnd
.nodef:
end if
	cmp	qword [rbx+ssh_dh_p_ofs], 0
	je	.nodhp
	mov	rdi, [rbx+ssh_dh_p_ofs]
	call	bigint$destroy
.nodhp:
	cmp	qword [rbx+ssh_dh_g_ofs], 0
	je	.nodhg
	mov	rdi, [rbx+ssh_dh_g_ofs]
	call	bigint$destroy
.nodhg:
	cmp	qword [rbx+ssh_dh_private_ofs], 0
	je	.nodhprivate
	mov	rdi, [rbx+ssh_dh_private_ofs]
	call	bigint$destroy_clear
.nodhprivate:
	cmp	qword [rbx+ssh_dh_e_ofs], 0
	je	.nodhe
	mov	rdi, [rbx+ssh_dh_e_ofs]
	call	bigint$destroy_clear
.nodhe:
	cmp	qword [rbx+ssh_dh_f_ofs], 0
	je	.nodhf
	mov	rdi, [rbx+ssh_dh_f_ofs]
	call	bigint$destroy_clear
.nodhf:
	cmp	qword [rbx+ssh_dh_shared_ofs], 0
	je	.nodhshared
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	call	bigint$destroy_clear
.nodhshared:
	cmp	qword [rbx+ssh_username_ofs], 0
	je	.nousername
	mov	rdi, [rbx+ssh_username_ofs]
	call	heap$free
.nousername:
	cmp	qword [rbx+ssh_password_ofs], 0
	je	.nopassword
	mov	rdi, [rbx+ssh_password_ofs]
	call	heap$free_clear
.nopassword:
	cmp	qword [rbx+ssh_exec_ofs], 0
	je	.noexec
	mov	rdi, [rbx+ssh_exec_ofs]
	call	heap$free
.noexec:
	lea	rdi, [rbx+ssh_clientmode_ofs]
	xor	esi, esi
	mov	edx, ssh_size - io_base_size
	call	memset
	mov	rdi, rbx
	pop	rbx
	call	io$destroy
	epilog
end if

if used ssh$new_server | defined include_everything
	; single argument in rdi: _string_ directory of where to find ssh_host_{dsa,rsa}_key{.pub} files, or 0/null if we are to default to /etc/ssh
	; returns either pointer to new ssh object in rax, or null if we encountered an error reading our ssh files
falign
ssh$new_server:
	prolog	ssh$new_server
	call	X509$new_ssh
	test	rax, rax
	jz	.nohostkeys
	push	r12
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	call	buffer$new
	push	rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	edi, ssh_size
	call	heap$alloc_clear
	pop	r12 r11 r10 r9 rcx rdx rsi rdi r8
	mov	qword [rax], ssh$vtable
	mov	[rax+ssh_deflate_ofs+zlib_inbuf_ofs], r11
	mov	[rax+ssh_deflate_ofs+zlib_outbuf_ofs], r12
	mov	[rax+ssh_accbuf_ofs], r9
	mov	[rax+ssh_packetbuf_ofs], r10
	; some trickery here for the inflate goods:
	mov	[rax+ssh_inflate_ofs+zlib_inbuf_ofs], r11	; use the same inbuf for the temporary storage on receive of compressed goods
	mov	[rax+ssh_inflate_ofs+zlib_outbuf_ofs], r10	; use the packetbuf as the output area for inflate
	mov	[rax+ssh_localkexinit_ofs], rcx
	mov	[rax+ssh_remotekexinit_ofs], rdx
	mov	[rax+ssh_remoteident_ofs], rsi
	mov	[rax+ssh_hostkey_ofs], rdi
	mov	[rax+ssh_localcert_ofs], r8
	mov	dword [rax+ssh_width_ofs], 80
	mov	dword [rax+ssh_height_ofs], 25
	pop	r12
	epilog
calign
.nohostkeys:
	epilog

end if

if used ssh$clone | defined include_everything
	; single argument in rdi: our ssh object to clone
falign
ssh$clone:
	prolog	ssh$clone
	add	dword [ssh_session_count], 1
	push	rdi
	; normal alloc first up
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	call	buffer$new
	push	rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	call	buffer$new
	push	rax
	mov	rdi, rax
	mov	esi, 65536
	call	buffer$reserve
	mov	edi, ssh_size
	call	heap$alloc_clear
	pop	r11 r10 r9 r8 rcx rdx rsi rdi
	mov	[rax+ssh_deflate_ofs+zlib_inbuf_ofs], r10
	mov	[rax+ssh_deflate_ofs+zlib_outbuf_ofs], r11
	mov	[rax+ssh_accbuf_ofs], r8
	mov	[rax+ssh_packetbuf_ofs], r9
	; some trickery here for the inflate goods:
	mov	[rax+ssh_inflate_ofs+zlib_inbuf_ofs], r10	; use the same inbuf for the temporary storage on receive of compressed goods
	mov	[rax+ssh_inflate_ofs+zlib_outbuf_ofs], r9	; use the packetbuf as the output area for inflate
	mov	[rax+ssh_localkexinit_ofs], rcx
	mov	[rax+ssh_remotekexinit_ofs], rdx
	mov	[rax+ssh_remoteident_ofs], rsi
	mov	[rax+ssh_hostkey_ofs], rdi
	pop	rsi	; our original object
	mov	ecx, [rsi+ssh_clientmode_ofs]
	mov	rdx, [rsi+ssh_localcert_ofs]
	mov	r9, [rsi]				; get our original's vtable
	mov	r10, [rsi+io_child_ofs]			; determine whether our original had a child or not
	mov	[rax], r9				; setup our own vtable
	mov	r8, [rsi+ssh_authcb_ofs]
	mov	r11, [rsi+ssh_authcbarg_ofs]
	mov	[rax+ssh_clientmode_ofs], ecx
	mov	[rax+ssh_localcert_ofs], rdx
	mov	[rax+ssh_authcb_ofs], r8
	mov	[rax+ssh_authcbarg_ofs], r11
	mov	r8, [rsi+ssh_wsizecb_ofs]
	mov	r11, [rsi+ssh_wsizecbarg_ofs]
	mov	[rax+ssh_wsizecb_ofs], r8
	mov	[rax+ssh_wsizecbarg_ofs], r11
	mov	r8, [rsi+ssh_eofcb_ofs]
	mov	r11, [rsi+ssh_eofcbarg_ofs]
	mov	[rax+ssh_eofcb_ofs], r8
	mov	[rax+ssh_eofcbarg_ofs], r11
	mov	dword [rax+ssh_width_ofs], 80
	mov	dword [rax+ssh_height_ofs], 25
	test	r10, r10
	jnz	.withchild
	epilog
calign
.withchild:
	push	rax					; save our return object
	mov	rdi, r10				; argument for child clone
	mov	rsi, [r10]
	call	qword [rsi+io_vclone]
	mov	rsi, rax
	pop	rax
	mov	[rax+io_child_ofs], rsi
	mov	[rsi+io_parent_ofs], rax
	epilog

end if



if used ssh$set_authcb | defined include_everything
	; three arguments: rdi == our ssh object, rsi == function to call on auth, rdx == optional arg (or null)
	; if rdx == 0, then the ssh object itself will get passed as the first argument to the auth callback
	; otherwise, first arg is the specified argument.
	; rsi == string username, rdx == string password
	; if your function returns true, auth success, false == SSH auth failure.
falign
ssh$set_authcb:
	prolog	ssh$set_authcb
	mov	[rdi+ssh_authcb_ofs], rsi
	mov	[rdi+ssh_authcbarg_ofs], rdx
	epilog

end if



if used ssh$connected | defined include_everything
	; single argument in rdi: our ssh object
falign
ssh$connected:
	prolog	ssh$connected
	; if we are in server mode, send our ident only and be done
	; if we are in client mode, wait for the server's ident to arrive before we send ours
	cmp	dword [rdi+ssh_clientmode_ofs], 0
	jne	.clientmode
	; server mode, ident only, swallow our remote address as well
	push	rdi
	mov	[rdi+ssh_raddrlen_ofs], edx
	lea	rdi, [rdi+ssh_raddr_ofs]
	call	memcpy
if ssh_blacklist
	mov	rdx, [rsp]
	mov	rdi, [ssh$blacklist]
	mov	esi, [rdx+ssh_raddr_ofs+4]
	call	blacklist$check
	test	eax, eax
	jnz	.blacklisted
end if
	pop	rdi
	
	; server mode, send ident only
	mov	rdi, [rdi+io_child_ofs]
	mov	rsi, ssh_ident
	mov	edx, ssh_ident_len
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	epilog
if ssh_blacklist
calign
.blacklisted:
	pop	rdi
	mov	dword [rdi+ssh_stage_ofs], ssh_stage_goaway

	; server mode, blacklisted ident
	mov	rdi, [rdi+io_child_ofs]
	mov	rsi, ssh_ident_blacklisted
	mov	edx, ssh_ident_blacklisted_len
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	epilog
end if
calign
.clientmode:
	epilog

end if

if used ssh$encrypt | defined include_everything
	; four arguments: rdi == ssh object, esi == ssh type, rdx == ptr to payload, ecx == length of same, length must be <= 32768
	; if the connection is still in plaintext, this will still compose and send the goods despite its encrypt name
falign
ssh$encrypt:
	prolog	ssh$encrypt
	cmp	dword [rdi+ssh_stage_ofs], ssh_stage_torndown
	je	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12d, esi
	mov	r13, rdx
	mov	r14d, ecx

if sshdebug
	zlib_debug 'ssh$encrypt sending packet type: ', rsi
end if

if ssh_do_compression
	cmp	dword [rdi+ssh_compstate_ofs], 2
	jne	.nocomp
	; compose our goods into the ssh_deflate_ofs+zlib_inbuf_ofs, call deflate, then recompose back into inbuf
	mov	r15, [rdi+ssh_deflate_ofs+zlib_inbuf_ofs]
	mov	rdi, [rdi+ssh_deflate_ofs+zlib_inbuf_ofs]
	call	buffer$reset
	mov	rdi, [rbx+ssh_deflate_ofs+zlib_outbuf_ofs]
	call	buffer$reset
	mov	rdi, [r15+buffer_itself_ofs]
	mov	byte [rdi], r12b	; type
	add	qword [r15+buffer_endptr_ofs], 1
	add	qword [r15+buffer_length_ofs], 1
	; append the contents to the inbuf
	mov	rdi, r15
	mov	rsi, r13
	mov	edx, r14d
	call	buffer$append
	lea	rdi, [rbx+ssh_deflate_ofs]
	mov	esi, zlib_partial_flush
	call	zlib$deflate
	; that returns a bool for 1 == Z_OK, 0 == fail... we should check for failure
if sshdebug
	test	eax, eax
	jz	.kakked
end if
	; so now, we need to recompose it into the inbuf
	mov	rdi, r15
	call	buffer$reset
	mov	rsi, [rbx+ssh_deflate_ofs+zlib_outbuf_ofs]
	mov	rcx, [rsi+buffer_length_ofs]
	add	ecx, 5			; +1 for the padlen itself, +4 temporarily for our packet length so we get the padding right
	mov	edx, 16
	mov	r8d, ecx
	and	r8d, 0xf
	sub	edx, r8d		; padlen
	mov	r9d, edx
	add	r9d, 16
	cmp	edx, 4
	cmovb	edx, r9d
	sub	ecx, 4			; take our temporary length back off
	add	ecx, edx		; + our ppadlen
	mov	rdi, [r15+buffer_itself_ofs]
if use_movbe
	movbe	dword [rdi], ecx
else
	bswap	ecx
	mov	dword [rdi], ecx
end if
	mov	byte [rdi+4], dl
	add	qword [r15+buffer_endptr_ofs], 5
	add	qword [r15+buffer_length_ofs], 5
	; append the contents of the compressed buffer, but save our padlen
	mov	rdi, r15
	mov	r12d, edx		; save our padlen
	mov	rdx, [rsi+buffer_length_ofs]
	mov	rsi, [rsi+buffer_itself_ofs]
	call	buffer$append
	; add our random bytes to the end
	mov	rdi, r15
	mov	esi, r12d
	call	buffer$reserve
	mov	rdi, [r15+buffer_endptr_ofs]
	mov	esi, r12d		; padlen # of random bytes
	add	qword [r15+buffer_endptr_ofs], r12
	add	qword [r15+buffer_length_ofs], r12
	call	rng$block
	; output is ready and sitting in ssh_deflate_ofs+zlib_inbuf_ofs
	jmp	.bufferready
if sshdebug
calign
.kakked:
	breakpoint
end if
calign
.nocomp:
end if
	; compose our goods directly into the ssh_deflate_ofs+zlib_inbuf_ofs
	mov	r15, [rdi+ssh_deflate_ofs+zlib_inbuf_ofs]
	mov	rdi, [rdi+ssh_deflate_ofs+zlib_inbuf_ofs]
	call	buffer$reset
	mov	ecx, r14d
	add	ecx, 6			; +1 for the padlen itself, +1 for the type of the message, +4 temporarily for our packet length so we get the padding right
	mov	edx, 16
	mov	r8d, ecx
	and	r8d, 0xf
	sub	edx, r8d		; padlen
	mov	r9d, edx
	add	r9d, 16
	cmp	edx, 4
	cmovb	edx, r9d
	sub	ecx, 4			; take our temporary length back off
	add	ecx, edx		; + our padlen
	mov	rdi, [r15+buffer_itself_ofs]
if use_movbe
	movbe	dword [rdi], ecx
else
	bswap	ecx
	mov	dword [rdi], ecx
end if
	mov	byte [rdi+4], dl
	mov	byte [rdi+5], r12b
	add	qword [r15+buffer_endptr_ofs], 6
	add	qword [r15+buffer_length_ofs], 6
	; append the contents, but save our pad length
	mov	rdi, r15
	mov	rsi, r13
	mov	r12d, edx		; save our padlen
	mov	edx, r14d
	call	buffer$append
	; add our random bytes to the end
	mov	rdi, r15
	mov	esi, r12d
	call	buffer$reserve
	mov	rdi, [r15+buffer_endptr_ofs]
	mov	esi, r12d		; padlen # of random bytes
	add	qword [r15+buffer_endptr_ofs], r12
	add	qword [r15+buffer_length_ofs], r12
	call	rng$block
	; so now, ssh_deflate_ofs+zlib_inbuf_ofs is the composed/ready to roll buffer with the correct length
calign
.bufferready:
	; next up: if we are an open channel, proceed with aes256 and hmac
	cmp	dword [rbx+ssh_open_ofs], 0
	je	.plaintext

	; calculate our hmac first
	sub	rsp, 8
	mov	eax, [rbx+ssh_writeseq_ofs]
if use_movbe
	movbe	[rsp], eax
else
	bswap	eax
	mov	[rsp], eax
end if

	lea	rdi, [rbx+ssh_writehmac_ofs]
	mov	rsi, rsp
	mov	edx, 4
	call	qword [rdi+hmac_macupdate_ofs]
	add	rsp, 8

	; our entire packet next
	lea	rdi, [rbx+ssh_writehmac_ofs]
	mov	rsi, [r15+buffer_itself_ofs]
	mov	rdx, [r15+buffer_length_ofs]
	call	qword [rdi+hmac_macupdate_ofs]

if sshdebug & defined sshanaldebug
	; this debug here is a bit heavy:
	mov	rdi, .hmacmsg
	call	string$to_stdoutln
	mov	rdi, [r15+buffer_itself_ofs]
	mov	rsi, [r15+buffer_length_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

end if
	
	; xor the first block with our localiv
	mov	rdi, [r15+buffer_itself_ofs]
	lea	rsi, [rbx+ssh_localiv_ofs]
	mov	edx, 16
	call	memxor

	; encrypt the first block
	lea	rdi, [rbx+ssh_writecipher_ofs]
	mov	rsi, [r15+buffer_itself_ofs]
	call	aes$encrypt

	; use r14 for our block pointer, r13 for our total length, which we know is small
	mov	r14, [r15+buffer_itself_ofs]
	mov	r13, [r15+buffer_length_ofs]
	
	sub	r13d, 16
	jz	.cbc_alldone
calign
.cbc_loop:
	lea	rdi, [r14+16]		; "this" block
	mov	rsi, r14		; "previous" block
	mov	edx, 16
	add	r14, 16
	call	memxor
	lea	rdi, [rbx+ssh_writecipher_ofs]
	mov	rsi, r14
	call	aes$encrypt
	sub	r13d, 16
	jnz	.cbc_loop
calign
.cbc_alldone:
	; set our localiv to the last block
	lea	rdi, [rbx+ssh_localiv_ofs]
	mov	rsi, r14
	mov	edx, 16
	call	memcpy

	; so now, we can reserve 32 extra bytes for the hmac on the end
	mov	rdi, r15
	mov	esi, 32
	call	buffer$reserve
	lea	rdi, [rbx+ssh_writehmac_ofs]
	mov	rsi, [r15+buffer_endptr_ofs]
	call	hmac$final
	add	qword [r15+buffer_endptr_ofs], 32
	add	qword [r15+buffer_length_ofs], 32
	; fallthrough to the plaintext which will send it out
calign
.plaintext:
	; just send out ssh_deflate_ofs+zlib_inbuf_ofs over the wire
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, [r15+buffer_itself_ofs]
	mov	rdx, [r15+buffer_length_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	; increment our write sequence number
	add	dword [rbx+ssh_writeseq_ofs], 1
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.nothingtodo:
	epilog

if sshdebug
cleartext .hmacmsg, 'HMAC Packet Contents:'
end if

end if

if used ssh$send | defined include_everything
	; three arguments: rdi == our ssh object, rsi == ptr to data, rdx == length of same
	; this gets called with application-level data to send, which of course need to cook
	; and forward on to our next in line
falign
ssh$send:
	prolog	ssh$send
if sshdebug
	push	rdi rsi rdx
	mov	rdi, .sendmsg
	call	string$to_stdoutln
	pop	rdx rsi rdi
end if
	test	rdx, rdx
	jz	.nosend
	cmp	dword [rdi+ssh_stage_ofs], ssh_stage_interactive
	jne	.nosend

	; up to 32760 chunks at a time, less the 8 bytes we need of preface
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	sub	rsp, 32768
calign
.loop:
	; NOTE: despite the SSH docs stating that all implementations must accept 32768 byte blocks
	; openssh demands (and complains loudly if we exceed) smaller ones

	; mov	ecx, 32760
	; cmp	r13, 32760
	mov	ecx, 16384
	cmp	r13, 16384
	cmovb	ecx, r13d
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	edx, ecx
if use_movbe
	mov	[rsp], eax
	movbe	[rsp+4], ecx
else
	bswap	ecx
	mov	[rsp], eax
	mov	[rsp+4], ecx
end if
	lea	rdi, [rsp+8]
	mov	rsi, r12
	; update r12/r13 for our next pass
	add	r12, rdx
	sub	r13, rdx
	; reduce the remote side's window
	sub	dword [rbx+ssh_remotewindow_ofs], edx
	call	memcpy
	mov	ecx, [rsp+4]
	mov	rdi, rbx
	mov	esi, 94			; SSH_MSG_CHANNEL_DATA
	mov	rdx, rsp
	bswap	ecx
	add	ecx, 8
	call	ssh$encrypt
	test	r13, r13
	jnz	.loop
	
	add	rsp, 32768
	pop	r13 r12 rbx
	epilog
calign
.nosend:
	epilog
if sshdebug
cleartext .sendmsg, 'ssh$send called'
end if

end if

if used ssh$client_windowsize | defined include_everything
	; three arguments: rdi == our ssh object, esi == width, edx == height
falign
ssh$client_windowsize:
	prolog	ssh$client_windowsize
	mov	dword [rdi+ssh_width_ofs], esi
	mov	dword [rdi+ssh_height_ofs], edx
	cmp	dword [rdi+ssh_stage_ofs], ssh_stage_interactive
	jne	.nosend
	push	rbx
	mov	rbx, rdi
	sub	rsp, 256
	mov	eax, [rdi+ssh_channelid_ofs]
	mov	[rsp], eax
	lea	rdi, [rsp+4]
	mov	rsi, .wch
	mov	edx, .wchlen
	call	memcpy
	lea	rdi, [rsp+4+.wchlen]
	mov	eax, [rbx+ssh_width_ofs]
	mov	ecx, [rbx+ssh_height_ofs]
if use_movbe
	movbe	dword [rdi], eax
	movbe	dword [rdi+4], ecx
else
	bswap	eax
	bswap	ecx
	mov	dword [rdi], eax
	mov	dword [rdi+4], ecx
end if
	mov	dword [rdi+8], 0
	mov	dword [rdi+12], 0
	mov	rdi, rbx
	mov	esi, 98			; SSH_MSG_CHANNEL_REQUEST
	mov	rdx, rsp
	mov	ecx, 4 + .wchlen + 16
	call	ssh$encrypt
	add	rsp, 256
	pop	rbx
	epilog
dalign
.wch:
	db	0, 0, 0, 13, 'window-change', 0
.wchlen = $ - .wch
calign
.nosend:
	epilog

end if

if used ssh$cleanexit | defined include_everything
	; single argument: rdi == our ssh object
	; this sends our two window messages to tear us down, well-behaved clients will respond
	; with a disco message
falign
ssh$cleanexit:
	prolog	ssh$cleanexit
	push	rbx
	mov	rbx, rdi
	mov	eax, [rdi+ssh_channelid_ofs]
	sub	rsp, 8
	mov	rdi, rbx
	mov	esi, 96			; SSH_MSG_CHANNEL_EOF
	mov	rdx, rsp
	mov	[rsp], eax
	mov	ecx, 4
	call	ssh$encrypt
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	rdi, rbx
	mov	esi, 97			; SSH_MSG_CHANNEL_CLOSE
	mov	rdx, rsp
	mov	[rsp], eax
	mov	ecx, 4
	call	ssh$encrypt
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_torndown	; prevent any further data from being sent out
	add	rsp, 8
	pop	rbx
	epilog

end if


if used ssh$receive | defined include_everything
	; three arguments: rdi == our ssh object, rsi == ptr to data, rdx == length of same
falign
ssh$receive:
	prolog	ssh$receive
	push	rbx
	mov	rbx, rdi
	; special case handling for when we are in ssh_stage_idents:
	cmp	dword [rdi+ssh_stage_ofs], 0
	je	.ident
if ssh_blacklist
	cmp	dword [rdi+ssh_stage_ofs], ssh_stage_goaway
	je	.goaway
end if
	; append whatever we got to the accbuf first up:
	mov	rdi, [rdi+ssh_accbuf_ofs]
	call	buffer$append
calign
.loop:
	mov	rsi, [rbx+ssh_accbuf_ofs]
	cmp	qword [rsi+buffer_length_ofs], 16
	jb	.needmore

	cmp	dword [rbx+ssh_remoteenc_ofs], 0
	je	.processclearpacket
	; cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantservice
	; jb	.processclearpacket
	mov	edx, [rbx+ssh_peeklen_ofs]
	test	edx, edx
	jz	.setpeeklen
calign
.loop_peeklenset:
	; we know peeklen is valid and sitting in edx, rsi == accbuf itself
	cmp	qword [rsi+buffer_length_ofs], rdx
	jb	.needmore
	; otherwise, we know we have enough data sitting here to decrypt everything _after_ the first block, sans the last 2 (which is our hmac)
	; and further, that are hmac is sitting here as well (cuz it got added to the peeklen)

	; so, proceed with decrypting rdx-48 worth of blocks, using a double block buffer on the stack for our iv updates
	push	r12 r13 r14
	sub	rsp, 32
	lea	r12, [rsp+16]			; set r12 flipper to second block spot
	mov	r13d, edx			; our peeklen
	mov	r14, [rsi+buffer_itself_ofs]
	sub	r13d, 48			; 32 bytes at the end are the hmac, 16 bytes at the head is the first block we already decrypted
	jz	.loop_peeklenset_checkhmac
	add	r14, 16				; skip the first block that we already did

	; copy the first crypted block into our first block spot
	mov	rdi, rsp
	mov	rsi, r14
	mov	edx, 16
	call	memcpy

	; decrypt the first block
	lea	rdi, [rbx+ssh_readcipher_ofs]
	mov	rsi, r14
	call	aes$decrypt

	; xor it with our remoteiv
	mov	rdi, r14
	lea	rsi, [rbx+ssh_remoteiv_ofs]
	mov	edx, 16
	call	memxor

	sub	r13d, 16
	jz	.cbc_alldone
	add	r14, 16
calign
.cbc_loop:
	; copy the crypted block into r12
	mov	rdi, r12
	mov	rsi, r14
	mov	edx, 16
	call	memcpy
	
	; decrypt block at r14
	lea	rdi, [rbx+ssh_readcipher_ofs]
	mov	rsi, r14
	call	aes$decrypt

	; swap r12
	mov	rax, rsp
	lea	rcx, [rsp+16]
	cmp	r12, rsp
	cmove	r12, rcx
	cmovne	r12, rax

	; xor it with our previous crypted block in r12
	mov	rdi, r14
	mov	rsi, r12
	mov	edx, 16
	call	memxor

	add	r14, 16
	sub	r13d, 16
	jnz	.cbc_loop
calign
.cbc_alldone:
	; swap r12 once more to get the real last crypted block
	mov	rax, rsp
	lea	rcx, [rsp+16]
	cmp	r12, rsp
	cmove	r12, rcx
	cmovne	r12, rax

	; set our remoteiv to the last block
	lea	rdi, [rbx+ssh_remoteiv_ofs]
	mov	rsi, r12
	mov	edx, 16
	call	memcpy

calign
.loop_peeklenset_checkhmac:
	; we are done with our double block buffer at rsp, but we still need room
	; to deal with our hmac ghost value
	
	; compute the hmac...
	mov	eax, [rbx+ssh_readseq_ofs]
if use_movbe
	movbe	[rsp], eax
else
	bswap	eax
	mov	[rsp], eax
end if
	
	lea	rdi, [rbx+ssh_readhmac_ofs]
	mov	rsi, rsp
	mov	edx, 4
	call	qword [rdi+hmac_macupdate_ofs]

	; the entire packet next, we can use peeklen again - 32
	mov	rsi, [rbx+ssh_accbuf_ofs]
	mov	edx, [rbx+ssh_peeklen_ofs]
	lea	rdi, [rbx+ssh_readhmac_ofs]
	mov	rsi, [rsi+buffer_itself_ofs]
	sub	edx, 32
	call	qword [rdi+hmac_macupdate_ofs]

	lea	rdi, [rbx+ssh_readhmac_ofs]
	mov	rsi, rsp
	call	hmac$final

	; compare that with the trailing 32 bytes of the hacc
	mov	rdi, [rbx+ssh_accbuf_ofs]
	mov	ecx, [rbx+ssh_peeklen_ofs]
	mov	edx, 32
	mov	rsi, rsp
	mov	rdi, [rdi+buffer_itself_ofs]
	add	rdi, rcx
	sub	rdi, 32
	call	memcmp
	test	eax, eax
	jnz	.badhmac
		; see notes atop as to what happens when bad length and/or hmac comes through

	; hmac verification success, possible inflate must happen next
if ssh_do_compression
	cmp	dword [rbx+ssh_compstate_ofs], 2
	jne	.loop_peeklenset_noinflate

	; we need to inflate the goods first
	; we need to add its actual len - padlen - 1 to the inflate inbuf
	mov	rdi, [rbx+ssh_inflate_ofs+zlib_inbuf_ofs]
	call	buffer$reset
	mov	rsi, [rbx+ssh_accbuf_ofs]
	mov	rcx, [rsi+buffer_itself_ofs]
if use_movbe
	movbe	edx, [rcx]
else
	mov	edx, [rcx]
	bswap	edx					; len
end if
	movzx	r8d, byte [rcx+4]			; padlen
	sub	edx, r8d
	sub	edx, 1
	mov	rdi, [rbx+ssh_inflate_ofs+zlib_inbuf_ofs]
	lea	rsi, [rcx+5]
	call	buffer$append

if sshdebug
	mov	rdi, .compressedmsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_inflate_ofs+zlib_inbuf_ofs]
	mov	rsi, [rdi+buffer_length_ofs]
	mov	rdi, [rdi+buffer_itself_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	lea	rdi, [rbx+ssh_inflate_ofs]
	mov	esi, zlib_partial_flush
	call	zlib$inflate

if sshdebug
	mov	rdi, .infsuccessmsg
	mov	rsi, .inffailedmsg
	test	eax, eax
	cmovz	rdi, rsi
	call	string$to_stdoutln

	mov	rdi, .decompressedmsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_length_ofs]
	mov	rdi, [rdi+buffer_itself_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	; so now, packetbuf contains the output from inflate
	; consume peeklen worth of data from the accbuf, and reset the type
	mov	rdi, [rbx+ssh_accbuf_ofs]
	mov	esi, [rbx+ssh_peeklen_ofs]
	call	buffer$consume
	
	; unfortunately, the zlib inflate included the type, get it and consume just 1 byte (sucks due to the potentially large memmove)
	; but it is either that or we do a double-buffer, which still would incur a memcpy again, so I suppose it is much of a muchness
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	
	movzx	r8d, byte [rsi]				; the packet type
	mov	esi, 1
	push	r8
	call	buffer$consume
	pop	r8

	add	rsp, 32
	pop	r14 r13 r12
	jmp	.processclearpacket_ready
if sshdebug & ssh_do_compression
cleartext .compressedmsg, 'ssh$receive, compressed data is:'
cleartext .decompressedmsg, 'decompressed result is:'
cleartext .infsuccessmsg, 'inflate succeeded'
cleartext .inffailedmsg, 'inflate failed'
end if
calign
.loop_peeklenset_noinflate:
end if
	mov	rsi, [rbx+ssh_accbuf_ofs]
	mov	rcx, [rsi+buffer_itself_ofs]
if use_movbe
	movbe	edx, [rcx]
else
	mov	edx, dword [rcx]
	bswap	edx				; packet_length
end if
	movzx	r8d, byte [rcx+4]		; padding_length
	sub	edx, 2
	sub	edx, r8d
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	lea	rsi, [rcx+6]
	call	buffer$append
	; consume peeklen worth of data from the accbuf, and reset the type
	mov	rdi, [rbx+ssh_accbuf_ofs]
	mov	rcx, [rdi+buffer_itself_ofs]
	mov	esi, [rbx+ssh_peeklen_ofs]
	movzx	eax, byte [rcx+5]		; type, we skipped the padding length
	push	rax
	call	buffer$consume
	pop	r8

	add	rsp, 32
	pop	r14 r13 r12
	jmp	.processclearpacket_ready
calign
.badhmac:
	; see notes atop as to what happens when bad length and/or hmac comes through

	; so, if we were not being mindful of leaking information about the kind of error we got
	; then we'd call our error method and drop the connection here and now

if ssh_blacklist
	; these don't happen under normal "play nice" operating conditions, so, if we are in server mode
	; and ssh blacklisting is enabled, add them
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badhmac_skipblacklist
	mov	rdi, [ssh$blacklist]
	mov	esi, [rbx+ssh_raddr_ofs+4]
	call	blacklist$add
calign
.badhmac_skipblacklist:
end if
	
	; if we _already_ did this, then what we really get are two bad hmacs, and on the second one
	; we really will die
	cmp	dword [rbx+ssh_dead_ofs], 0
	jne	.badhmac_die

	; as it is, we want a random integer between 2k and 18k
	mov	dword [rbx+ssh_dead_ofs], 1
	xor	edi, edi
	mov	esi, 16384
	call	rng$int
	add	eax, 2048
	add	[rbx+ssh_peeklen_ofs], eax

	add	rsp, 32
	pop	r14 r13 r12
	jmp	.loop
calign
.badhmac_die:
	add	rsp, 32
	; call our error method, since when we return 1 for suicide, epoll won't call it for us
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	jne	.badhmac_die_skipnotify
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+io_verror]
calign
.badhmac_die_skipnotify:
	pop	r14 r13 r12 rbx
	mov	eax, 1				; die a thousand deaths
	epilog
calign
.needmore:
	pop	rbx
	xor	eax, eax			; don't kill us off
	epilog
if ssh_blacklist
calign
.goaway:
	pop	rbx
	mov	eax, 1				; death on a stick
	epilog
end if
calign
.setpeeklen:
	; decrypt the first block only, set peeklen, check for a sane value, then proceed
	mov	rcx, [rsi+buffer_itself_ofs]

	; copy this encrypted block to the stack, decrypt it, xor it with the remoteiv, set remoteiv to the encrypted block
	sub	rsp, 16
	mov	rdi, rsp
	mov	rsi, rcx
	mov	edx, 16
	call	memcpy
	mov	rsi, [rbx+ssh_accbuf_ofs]
	lea	rdi, [rbx+ssh_readcipher_ofs]
	mov	rsi, [rsi+buffer_itself_ofs]
	call	aes$decrypt
	; xor it with the remoteiv
	mov	rdi, [rbx+ssh_accbuf_ofs]
	lea	rsi, [rbx+ssh_remoteiv_ofs]
	mov	rdi, [rdi+buffer_itself_ofs]
	mov	edx, 16
	call	memxor
	; set remoteiv to the original encrypted block
	lea	rdi, [rbx+ssh_remoteiv_ofs]
	mov	rsi, rsp
	mov	edx, 16
	call	memcpy
	; restore our stackframe
	add	rsp, 16
	; now, first block is decrypted, and our remoteiv is updated
	mov	rsi, [rbx+ssh_accbuf_ofs]
	mov	rcx, [rsi+buffer_itself_ofs]

if use_movbe
	movbe	edx, [rcx]
else
	mov	edx, dword [rcx]
	bswap	edx
end if
	add	edx, 36				; +4 for the length field itself, +32 for the mac length

	; special handling here to mitigate http://www.isg.rhul.ac.uk/~kp/SandPfinal.pdf

	; so, if we were _not_ dealing with the aforementioned, then we'd do:
	; test	edx, 0xf
	; jnz	.badlength			; must be a multiple of our blocksize
	; cmp	edx, 5
	; jb	.badlength
	; cmp	edx, 262144
	; ja	.badlength
	; mov	dword [rbx+ssh_peeklen_ofs], edx

	; instead however, if any of our checks fail, set peeklen to a random value between 2k and 32k
	; and let it ride such that length errors (and thus the first block) don't get distinguished
	; to the remote party (of course the hmac will fail when we receive peeklen worth of data)
	
	test	edx, 0xf
	jnz	.random_peeklen			; must be a multiple of our blocksize
	cmp	edx, 5
	jb	.random_peeklen
	cmp	edx, 262144
	ja	.random_peeklen
	mov	dword [rbx+ssh_peeklen_ofs], edx

	jmp	.loop_peeklenset
calign
.random_peeklen:
	xor	edi, edi
	mov	esi, 16384
	call	rng$int
	add	eax, 2048
	mov	rsi, [rbx+ssh_accbuf_ofs]
	mov	dword [rbx+ssh_peeklen_ofs], eax
	mov	edx, eax
	; now, if we receive a bad hmac along the way, it too will add and wait for data
	; but, since we already did that, we set our dead flag here so that when enough data
	; arrives, whether it is a bad hmac or length, it dies then and there
	mov	dword [rbx+ssh_dead_ofs], 1
	jmp	.loop_peeklenset
calign
.processclearpacket:
	; read/consume whole clear packets from our buffer, set peeklen = 0 and jump back to the top
	; regardless of whether peeklen was set or not, we need to determine our length again (possible
	; that peeklen was not involved as in the case of the initial plaintext handshake)
	mov	rcx, [rsi+buffer_itself_ofs]
if use_movbe
	movbe	edx, [rcx]
else
	mov	edx, dword [rcx]
	bswap	edx				; packet_length
end if
	movzx	r8d, byte [rcx+4]		; padding_length
	cmp	edx, 5
	jb	.badlength
	cmp	edx, 262144
	ja	.badlength
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantservice
	jb	.processclearpacket_nomac
	; check the mac length here, and possibly decompress what we have
calign
.processclearpacket_nomac:
	; make sure we have enough data here, rdx + 4
	add	edx, 4
	cmp	qword [rsi+buffer_length_ofs], rdx
	jb	.needmore
	; copy the contents that we need, which is packet_length - padding_length - 2 into the packetbuf
	lea	rsi, [rcx+6]
	sub	edx, 6
	sub	edx, r8d
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$append
	; we need to consume len + 4 from our accbuf, and reset the type
	mov	rdi, [rbx+ssh_accbuf_ofs]
	mov	rcx, [rdi+buffer_itself_ofs]
if use_movbe
	movbe	esi, [rcx]
	movzx	eax, byte [rcx+5]		; type, we skipped the padding length
else
	mov	esi, [rcx]
	movzx	eax, byte [rcx+5]		; type, we skipped the padding length
	bswap	esi
end if
	add	esi, 4
	push	rax
	call	buffer$consume
	pop	r8
calign
.processclearpacket_ready:
	; update our readseq first and foremost:
	add	dword [rbx+ssh_readseq_ofs], 1
if sshdebug
	zlib_debug 'ssh_receive, processing packet type: ', r8
end if
	; so r8d == the type of our packet, and [rbx+ssh_packetbuf_ofs] is the buffer that contains our actual data
	; process our packet type, and then reset peeklen and keep going
	cmp	r8d, 94			; SSH_MSG_CHANNEL_DATA
	je	.got_channel_data
	cmp	r8d, 95			; SSH_MSG_CHANNEL_EXTENDED_DATA
	je	.got_channel_extended_data
	cmp	r8d, 93			; SSH_MSG_CHANNEL_WINDOW_ADJUST
	je	.got_channelwindow_adjust
	cmp	r8d, 96			; SSH_MSG_CHANNEL_EOF
	je	.got_channel_eof
	cmp	r8d, 97			; SSH_MSG_CHANNEL_CLOSE
	je	.got_channel_close
	cmp	r8d, 1			; SSH_MSG_DISCONNECT
	je	.got_disco
	cmp	r8d, 80			; SSH_MSG_GLOBAL_REQUEST
	je	.got_globalrequest
	cmp	r8d, 20			; SSH_MSG_KEXINIT
	je	.got_kexinit
	cmp	r8d, 30			; SSH_MSG_KEX_DH_GEX_REQUEST_OLD
	je	.got_kexgexreq_old
	cmp	r8d, 31			; SSH_MSG_KEX_DH_GEX_GROUP
	je	.got_kexgexgroup
	cmp	r8d, 32			; SSH_MSG_KEX_DH_GEX_INIT
	je	.got_kexgexinit
	cmp	r8d, 33			; SSH_MSG_KEX_DH_GEX_REPLY
	je	.got_kexgexreply
	cmp	r8d, 34			; SSH_MSG_KEX_DH_GEX_REQUEST
	je	.got_kexgexreq
	cmp	r8d, 21			; SSH_MSG_NEWKEYS
	je	.got_newkeys
	cmp	r8d, 2			; SSH_MSG_IGNORE
	je	.got_ignore
	cmp	r8d, 5			; SSH_MSG_SERVICE_REQUEST
	je	.got_servicerequest
	cmp	r8d, 6			; SSH_MSG_SERVICE_ACCEPT
	je	.got_serviceaccept
	cmp	r8d, 50			; SSH_MSG_USERAUTH_REQUEST
	je	.got_userauth_request
	cmp	r8d, 51			; SSH_MSG_USERAUTH_FAILURE
	je	.got_userauth_failure
	cmp	r8d, 53			; SSH_MSG_USERAUTH_BANNER
	je	.got_ignore
	cmp	r8d, 4			; SSH_MSG_DEBUG
	je	.got_ignore
	cmp	r8d, 52			; SSH_MSG_USERAUTH_SUCCESS
	je	.got_userauth_success
	cmp	r8d, 60			; SSH_MSG_USERAUTH_INFO_REQUEST
	je	.got_userauth_info_request
	cmp	r8d, 90			; SSH_MSG_CHANNEL_OPEN
	je	.got_channelopen
	cmp	r8d, 91			; SSH_MSG_CHANNEL_OPEN_CONFIRMATION
	je	.got_channelopen_confirmation
	cmp	r8d, 92			; SSH_MSG_CHANNEL_OPEN_FAILURE
	je	.got_channelopen_failure
	cmp	r8d, 98			; SSH_MSG_CHANNEL_REQUEST
	je	.got_channel_request
	cmp	r8d, 99			; SSH_MSG_CHANNEL_SUCCESS
	je	.got_channel_success
	cmp	r8d, 100		; SSH_MSG_CHANNEL_FAILURE
	je	.got_channel_failure

if sshdebug
	breakpoint
end if

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
if sshdebug
cleartext .dhpmsg, 'Diffie-Hellman public p:'
cleartext .dhgmsg, 'Diffie-Hellman public g:'
cleartext .dhprivatemsg, 'Diffie-Hellman private:'
cleartext .dhemsg, 'Diffie-Hellman public e:'
cleartext .dhfmsg, 'Diffie-Hellman public f:'
cleartext .dhsharedmsg, 'Diffie-Hellman shared secret:'
end if
calign
.got_disco:
	; hmmm, if we jump to badlength, we raise our verror
	; and really, if we receive a SSH_MSG_DISCONNECT, we should close
	; without raising an error
	jmp	.silent_suicide
	; jmp	.badlength		; die with error
calign
.got_channel_data:
	; make sure we are in interactive mode:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	jne	.badlength		; die die die
	; otherwise, first four bytes are the channel
	; next four bytes is length, and bytes after that is the goods
	; so make sure we have at least 8 bytes
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 8
	jb	.badlength		; die die die
if use_movbe
	movbe	eax, [rsi+4]
else
	mov	eax, [rsi+4]
	bswap	eax
end if
	sub	rdx, 8
	cmp	eax, edx
	ja	.badlength		; die die die
	; reduce our window by eax
	sub	dword [rbx+ssh_localwindow_ofs], eax
	add	rsi, 8
	mov	edx, eax
	; notify our next layer up
	mov	rdi, [rbx+io_parent_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vreceive]
	; if our next layer up requested death, we need to do so as well
	test	eax, eax
	jnz	.appsuicide
	; make sure our localwindow is still big enough, or send a windowadjust
	cmp	dword [rbx+ssh_localwindow_ofs], 1048576
	jb	.got_channel_data_sendwindowadjust
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_data_sendwindowadjust:
	sub	rsp, 8
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	ecx, 512 * 1048576
	add	dword [rbx+ssh_localwindow_ofs], ecx
if use_movbe
	mov	[rsp], eax
	movbe	[rsp+4], ecx
else
	bswap	ecx
	mov	[rsp], eax
	mov	[rsp+4], ecx
end if
	mov	rdi, rbx
	mov	esi, 93			; SSH_MSG_CHANNEL_WINDOW_ADJUST
	mov	rdx, rsp
	mov	ecx, 8
	call	ssh$encrypt
	add	rsp, 8
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_eof:
	cmp	qword [rbx+ssh_eofcb_ofs], 0
	je	.got_channel_close	; won't do anything
	mov	rdi, rbx
	mov	rcx, [rbx+ssh_eofcbarg_ofs]
	cmp	qword [rbx+ssh_eofcbarg_ofs], 0
	cmovne	rdi, rcx
	call	qword [rbx+ssh_eofcb_ofs]
	test	eax, eax
	jnz	.got_channel_eof_suicide
	; fallthrough to got_channel_close which will just keep going
calign
.got_channel_close:
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_eof_suicide:
	; send a EOF message first
	mov	eax, [rbx+ssh_channelid_ofs]
	sub	rsp, 8
	mov	rdi, rbx
	mov	esi, 96			; SSH_MSG_CHANNEL_EOF
	mov	rdx, rsp
	mov	[rsp], eax
	mov	ecx, 4
	call	ssh$encrypt
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	rdi, rbx
	mov	esi, 97			; SSH_MSG_CHANNEL_CLOSE
	mov	rdx, rsp
	mov	[rsp], eax
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8

	; now, if we jump straight ot silent_suicide, and _we_ teardown the connection
	; then we get a "Connection closed by remote host" output from normal ssh clients
	; so instead, since we closed our channel, wait for their side to shut it down:
	; reset our packetbuf
	; jmp	.silent_suicide

	; note: we could also send an exit-status channel request here as stated in rfc4254, but none of my stuff
	; seems to care about it

	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
dalign
.disco:
	db 0, 0, 0, 11, 0, 0, 0, 4, 'Bye!', 0, 0, 0, 0
.discolen = $ - .disco
calign
.got_channel_extended_data:
	; make sure we are in interactive mode:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	jne	.badlength		; die die die
	; otherwise, first four bytes are the channel
	; next four bytes is the data type code, which must be 1
	; next four bytes is length, and bytes after that is the goods
	; so make sure we have at least 12 bytes
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 12
	jb	.badlength		; die die die
	; make sure the second 32bit int is 1
	cmp	dword [rsi+4], 0x01000000
	jne	.badlength		; die die die
if use_movbe
	movbe	eax, [rsi+8]
else
	mov	eax, [rsi+8]
	bswap	eax
end if
	sub	rdx, 12
	cmp	eax, edx
	ja	.badlength		; die die die
	; reduce our window by eax
	sub	dword [rbx+ssh_localwindow_ofs], eax
	add	rsi, 12
	mov	edx, eax
	; notify our next layer up
	mov	rdi, [rbx+io_parent_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vreceive]
	; if our next layer up requested death, we need to do so as well
	test	eax, eax
	jnz	.appsuicide
	; make sure our localwindow is still big enough, or send a windowadjust
	cmp	dword [rbx+ssh_localwindow_ofs], 1048576
	jb	.got_channel_data_sendwindowadjust
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_success:
	; this doesn't have any useful information, so just make sure we were in a wantchannel mode
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.badlength		; die die die
	; otherwise, set our mode to interactive
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	; notify the applayer of our connected status:
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+ssh_raddr_ofs]
	mov	edx, [rbx+ssh_raddrlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_request:
	; make sure we are in server mode, we check stage for wantchannel for each different type
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badlength
	; otherwise, we are sitting on the uint32 channelid, followed by a cstring rtype
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	cmp	qword [rdi+buffer_length_ofs], 11
	jb	.badlength
	push	r12
	mov	r12, [rdi+buffer_itself_ofs]
	add	r12, 4

if sshdebug
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [r12+4]
if use_movbe
	movbe	edx, [r12]
else
	mov	edx, [r12]
	bswap	edx
end if
	syscall
end if
	; remote ssh commands come in as "exec", which for our purposes here we don't want a bar of, though we will go ahead and accept it
	mov	rdi, r12
	mov	rsi, .rpty
	mov	edx, .rptylen
	call	memcmp
	test	eax, eax
	jz	.got_channel_request_pty
	mov	rdi, r12
	mov	rsi, .rshell
	mov	edx, .rshelllen
	call	memcmp
	test	eax, eax
	jz	.got_channel_request_shell
	mov	rdi, r12
	mov	rsi, .renv
	mov	edx, .renvlen
	call	memcmp
	test	eax, eax
	jz	.got_channel_request_env
	mov	rdi, r12
	mov	rsi, .rexec
	mov	edx, .rexeclen
	call	memcmp
	test	eax, eax
	jz	.got_channel_request_exec
	mov	rdi, r12
	mov	rsi, .rwinchg
	mov	edx, .rwinchglen
	call	memcmp
	test	eax, eax
	jz	.got_channel_request_winchg

	lea	rsi, [r12+4]
if use_movbe
	movbe	edx, [r12]
else
	mov	edx, [r12]
	bswap	edx
end if
	add	rsi, rdx

	pop	r12
	; otherwise, puke back a failure, but only do so if they asked for a reply
	cmp	byte [rsi], 0
	je	.got_channel_request_unknown_noreply

	mov	rdi, rbx
	mov	esi, 100			; SSH_MSG_CHANNEL_FAILURE
	lea	rdx, [rbx+ssh_channelid_ofs]
	mov	ecx, 4
	call	ssh$encrypt
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_request_unknown_noreply:
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop

dalign
.rpty:
	db	0, 0, 0, 7, 'pty-req'
.rptylen = $ - .rpty
dalign
.rshell:
	db	0, 0, 0, 5, 'shell'
.rshelllen = $ - .rshell
dalign
.renv:
	db	0, 0, 0, 3, 'env'
.renvlen = $ - .renv
dalign
.rexec:
	db	0, 0, 0, 4, 'exec'
.rexeclen = $ - .rexec
dalign
.rwinchg:
	db	0, 0, 0, 13, 'window-change'
.rwinchglen = $ - .rwinchg
calign
.got_channel_request_kakked:
	pop	r13 r12
	jmp	.badlength		; die die die
calign
.got_channel_request_pty:
	push	r13
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.got_channel_request_kakked
	add	r12, .rptylen
	mov	r13, [rdi+buffer_length_ofs]
	sub	r13d, .rptylen + 4
	jz	.got_channel_request_kakked
	cmp	r13d, 25
	jb	.got_channel_request_kakked
	movzx	r9d, byte [r12]
	add	r12, 1
	sub	r13d, 1			; want reply
	; we are sitting on:
	; bool wantReply
	; C string term
	; width
	; height
	; pixwidth
	; pixheight
	; C string modes
if use_movbe
	movbe	eax, [r12]
	add	r12, 4
	sub	r13d, 4
else
	mov	eax, [r12]
	add	r12, 4
	sub	r13d, 4
	bswap	eax
end if
	cmp	eax, r13d
	jae	.got_channel_request_kakked
	add	r12, rax
	sub	r13d, eax
	cmp	r13d, 20
	jb	.got_channel_request_kakked
	; width/height are next
	mov	eax, [r12]
	mov	ecx, [r12+4]
if use_movbe
	movbe	[rbx+ssh_width_ofs], eax
	movbe	[rbx+ssh_height_ofs], ecx
else
	bswap	eax
	bswap	ecx
	mov	[rbx+ssh_width_ofs], eax
	mov	[rbx+ssh_height_ofs], ecx
end if
	cmp	qword [rbx+ssh_wsizecb_ofs], 0
	je	.got_channel_request_nowsize
	push	r9
	mov	rdi, rbx
	mov	r9, [rbx+ssh_wsizecbarg_ofs]
	cmp	qword [rbx+ssh_wsizecbarg_ofs], 0
	cmovne	rdi, r9
	mov	esi, eax
	mov	edx, ecx
	call	qword [rbx+ssh_wsizecb_ofs]
	pop	r9
calign
.got_channel_request_nowsize:
	test	r9d, r9d
	jz	.got_channel_request_pty_noreply
	sub	rsp, 8
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	[rsp], eax
	mov	rdi, rbx
	mov	esi, 99			; SSH_MSG_CHANNEL_SUCCESS
	mov	rdx, rsp
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8
calign
.got_channel_request_pty_noreply:
	pop	r13 r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_request_shell:
	push	r13
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.got_channel_request_kakked
	add	r12, .rshelllen
	mov	r13, [rdi+buffer_length_ofs]
	sub	r13d, .rshelllen + 4
	; set our stage to interactive
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	; fire off our vconnected, notify the applayer of our connected status:
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+ssh_raddr_ofs]
	mov	edx, [rbx+ssh_raddrlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]
	; see if they want a reply
	cmp	byte [r12], 0
	je	.got_channel_request_shell_noreply
	sub	rsp, 8
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	[rsp], eax
	mov	rdi, rbx
	mov	esi, 99			; SSH_MSG_CHANNEL_SUCCESS
	mov	rdx, rsp
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8
calign
.got_channel_request_shell_noreply:
	pop	r13 r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_request_env:
	push	r13
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.got_channel_request_kakked
	add	r12, .renvlen
	mov	r13, [rdi+buffer_length_ofs]
	sub	r13d, .renvlen + 4
	; we aren't really interested in keeping them, but if the client wants a reply, we are obliged to send one
	cmp	byte [r12], 0
	je	.got_channel_request_env_noreply
	sub	rsp, 8
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	[rsp], eax
	mov	rdi, rbx
	mov	esi, 99			; SSH_MSG_CHANNEL_SUCCESS
	mov	rdx, rsp
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8
calign
.got_channel_request_env_noreply:
	pop	r13 r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_request_exec:
	push	r13
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.got_channel_request_kakked
	add	r12, .rexeclen
	mov	r13, [rdi+buffer_length_ofs]
	sub	r13d, .rexeclen + 4		; +4 for the preface channelid
	; set our stage to interactive
	; so the byte at [r12] is our wantreply
	; parse command string, which has to be immediately after the byte for wantreply
if use_movbe
	movbe	eax, [r12+1]
else
	mov	eax, [r12+1]
	bswap	eax
end if
	add	eax, 1
	cmp	eax, r13d
	ja	.got_channel_request_kakked
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	sub	eax, 1
	lea	rdi, [r12+5]
	mov	esi, eax
	call	string$from_utf8
	mov	[rbx+ssh_exec_ofs], rax

	; fire off our vconnected, notify the applayer of our connected status:
	mov	rdi, [rbx+io_parent_ofs]
	lea	rsi, [rbx+ssh_raddr_ofs]
	mov	edx, [rbx+ssh_raddrlen_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vconnected]
	; see if they want a reply
	cmp	byte [r12], 0
	je	.got_channel_request_exec_noreply
	sub	rsp, 8
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	[rsp], eax
	mov	rdi, rbx
	mov	esi, 99			; SSH_MSG_CHANNEL_SUCCESS
	mov	rdx, rsp
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8
calign
.got_channel_request_exec_noreply:
	pop	r13 r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_request_winchg:
	push	r13
	add	r12, .rwinchglen
	mov	r13, [rdi+buffer_length_ofs]
	sub	r13d, .rwinchglen
	; we are sitting on a bool for wantreply, followed by 4 unsigneds, we are only interested in the first 2
	cmp	r13d, 9
	jb	.got_channel_request_kakked
if use_movbe
	movbe	eax, [r12+1]
	movbe	ecx, [r12+5]
else
	mov	eax, [r12+1]
	mov	ecx, [r12+5]
	bswap	eax
	bswap	ecx
end if

	; make sure these values are semi-sane (mainly to prevent malicious remote agents
	; setting these to some HUGE value)
	mov	edx, 384
	cmp	eax, edx
	cmova	eax, edx
	shr	edx, 1
	cmp	ecx, edx
	cmova	ecx, edx

	mov	[rbx+ssh_width_ofs], eax
	mov	[rbx+ssh_height_ofs], ecx
	cmp	qword [rbx+ssh_wsizecb_ofs], 0
	je	.got_channel_request_winchg_nocb
	mov	rdi, rbx
	mov	r8, [rbx+ssh_wsizecbarg_ofs]
	cmp	qword [rbx+ssh_wsizecbarg_ofs], 0
	cmovne	rdi, r8
	mov	esi, eax
	mov	edx, ecx
	call	qword [rbx+ssh_wsizecb_ofs]
calign
.got_channel_request_winchg_nocb:
	cmp	byte [r12], 0
	je	.got_channel_request_winchg_noreply
	sub	rsp, 8
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	[rsp], eax
	mov	rdi, rbx
	mov	esi, 99			; SSH_MSG_CHANNEL_SUCCESS
	mov	rdx, rsp
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8
calign
.got_channel_request_winchg_noreply:
	pop	r13 r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channel_failure:
	; if we got one of these, this is a fatal condition
	jmp	.badlength		; die die die
calign
.got_globalrequest:
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 8
	jb	.badlength
if use_movbe
	movbe	eax, dword [rsi]
else
	mov	eax, dword [rsi]
	bswap	eax
end if
	add	rsi, 4
	sub	rdx, 4
	cmp	rax, rdx
	jae	.badlength
	add	rsi, rax
	cmp	byte [rsi], 0
	jne	.got_globalrequest_doreply
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_globalrequest_doreply:
	mov	rdi, rbx
	mov	esi, 82			; SSH_MSG_REQUEST_FAILURE
	mov	rdx, rsp
	xor	ecx, ecx
	call	ssh$encrypt
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channelwindow_adjust:
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 8
	jb	.badlength
if use_movbe
	movbe	eax, dword [rsi+4]
else
	mov	eax, dword [rsi+4]
	bswap	eax
end if
	add	[rbx+ssh_remotewindow_ofs], eax
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channelopen:
	; make sure we are expecting a channel message, and are in servermode
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badlength			; die die die
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.badlength
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 16
	jb	.badlength
	; otherwise, we are sitting on a string type, followed by uint32 channel, uint32 window_size, uint32 maxpacket
if use_movbe
	movbe	eax, dword [rsi]
else
	mov	eax, dword [rsi]
	bswap	eax
end if
	add	rsi, 4
	sub	rdx, 4
	cmp	rax, rdx
	ja	.badlength
	; it must be equal to session
	cmp	eax, 7
	jne	.got_channelopen_fail
	cmp	dword [rsi], 'sess'
	jne	.got_channelopen_fail
	mov	ecx, [rsi+4]
	and	ecx, 0xffffff
	cmp	ecx, 'ion'
	jne	.badlength
	add	rsi, 7
	sub	rdx, 7
	cmp	rdx, 12
	jne	.badlength
	mov	eax, [rsi]
if use_movbe
	movbe	ecx, [rsi+4]
	movbe	edx, [rsi+8]
else
	mov	ecx, [rsi+4]
	mov	edx, [rsi+8]
	; don't swap the channelid, we'll just use it as-is: bswap	eax
	bswap	ecx
	bswap	edx
end if
	mov	[rbx+ssh_channelid_ofs], eax
	mov	[rbx+ssh_remotewindow_ofs], ecx
	mov	r8d, 0x7fffffff
	mov	[rbx+ssh_localwindow_ofs], r8d
	mov	r9d, 32768
	; send back our open confirmation
	sub	rsp, 16
	mov	[rsp], eax
	mov	[rsp+4], eax
if use_movbe
	movbe	[rsp+8], r8d
	movbe	[rsp+12], r9d
else
	bswap	r8d
	bswap	r9d
	mov	[rsp+8], r8d
	mov	[rsp+12], r9d
end if
	mov	rdi, rbx
	mov	esi, 91				; SSH_MSG_CHANNEL_OPEN_CONFIRMATION
	mov	rdx, rsp
	mov	ecx, 16
	call	ssh$encrypt
	add	rsp, 16
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channelopen_fail:
	; send back administratively prohibited
	add	rsi, rax
	sub	rdx, rax
	mov	eax, [rsi]			; the channelid they sent
	sub	rsp, 32
	mov	dword [rsp], eax
	mov	dword [rsp+4], 0x01000000	; ADMINISTRATIVELY PROHIBITED
	mov	dword [rsp+8], 0x04000000
	mov	dword [rsp+12], '-No-'
	mov	dword [rsp+16], 0x02000000
	mov	dword [rsp+20], 'en'
	mov	rdi, rbx
	mov	esi, 92				; SSH_MSG_CHANNEL_OPEN_FAILURE
	mov	rdx, rsp
	mov	ecx, 22
	call	ssh$encrypt
	add	rsp, 32
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channelopen_confirmation:
	; make sure we are expecting a channel message, and are in clientmode
	; then send our channel request to either open a shell or fire up sftp subsystem
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	je	.badlength			; die die die
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel
	jne	.badlength
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 16
	jb	.badlength
	
	; we are sitting on our channel, followed by their channelid, which we'll copy
	mov	eax, [rsi+4]
	; we don't need to bswap it, we'll just handle it as-is
	mov	[rbx+ssh_channelid_ofs], eax
	; the remote window size is next
if use_movbe
	movbe	edx, [rsi+8]
else
	mov	edx, [rsi+8]
	bswap	edx
end if
	mov	[rbx+ssh_remotewindow_ofs], edx

	; their maxpacket is next, which we really don't care about

	; otherwise, depending on what kind of clientmode we are, ask for either a shell or system sftp
	cmp	dword [rbx+ssh_clientmode_ofs], 2
	je	.got_channelopen_confirmation_sftp

	; if we are not sftp, see if we are an exec
	cmp	qword [rbx+ssh_exec_ofs], 0
	jne	.got_channelopen_confirmation_exec

	; otherwise, send a pty-req with no confirmation, then a shell request with confiramation
	sub	rsp, 2048
	mov	[rsp], eax
	lea	rdi, [rsp+4]
	mov	rsi, .ptyreq
	mov	edx, .ptyreqlen
	call	memcpy
	; that takes care of up to the wantreply bool, and our fixed TERM environment variable (suited for my TUI goods)
	; as xterm-256color (so we could, for example, put an ssh session into one of my tui windows)
	lea	rdi, [rsp+4+.ptyreqlen]
	mov	eax, [rbx+ssh_width_ofs]
	mov	ecx, [rbx+ssh_height_ofs]
if use_movbe
	movbe	[rdi], eax
	movbe	[rdi+4], ecx
else
	bswap	eax
	bswap	ecx
	mov	[rdi], eax
	mov	[rdi+4], ecx
end if
	mov	dword [rdi+8], 0
	mov	dword [rdi+12], 0
	mov	dword [rdi+16], 0
	; extra 20 bytes
	
	mov	rdi, rbx
	mov	esi, 98			; SSH_MSG_CHANNEL_REQUEST
	mov	rdx, rsp
	mov	ecx, .ptyreqlen + 4 + 20
	call	ssh$encrypt
	mov	eax, [rbx+ssh_channelid_ofs]

	; else, send a shell request
	sub	rsp, 2048
	mov	[rsp], eax
	lea	rdi, [rsp+4]
	mov	rsi, .sessreq
	mov	edx, .sessreqlen
	call	memcpy
	mov	rdi, rbx
	mov	esi, 98			; SSH_MSG_CHANNEL_REQUEST
	mov	rdx, rsp
	mov	ecx, .sessreqlen + 4
	call	ssh$encrypt
	add	rsp, 2048

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channelopen_confirmation_exec:
	sub	rsp, 16384
	mov	[rsp], eax		; our channel
	lea	rdi, [rsp+4]
	mov	rsi, .execreq
	mov	edx, .execreqlen
	call	memcpy
	mov	rdi, [rbx+ssh_exec_ofs]
	call	string$utf8_length
	lea	rsi, [rsp+4+.execreqlen]
	push	rax
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	add	rsi, 4
	mov	rdi, [rbx+ssh_exec_ofs]
	call	string$to_utf8
	pop	rcx
	add	ecx, 4+.execreqlen
	mov	rdi, rbx
	mov	esi, 98			; SSH_MSG_CHANNEL_REQUEST
	mov	rdx, rsp
	call	ssh$encrypt
	add	rsp, 16384

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_channelopen_confirmation_sftp:
	sub	rsp, 2048
	mov	[rsp], eax
	lea	rdi, [rsp+4]
	mov	rsi, .sftpreq
	mov	edx, .sftpreqlen
	call	memcpy
	mov	rdi, rbx
	mov	esi, 98			; SSH_MSG_CHANNEL_REQUEST
	mov	rdx, rsp
	mov	ecx, .sftpreqlen + 4
	call	ssh$encrypt
	add	rsp, 2048

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
dalign
.ptyreq:
	db	0, 0, 0, 7, 'pty-req', 0, 0, 0, 0, 14, 'xterm-256color'
.ptyreqlen = $ - .ptyreq
dalign
.sessreq:
	db	0, 0, 0, 5, 'shell', 1
.sessreqlen = $ - .sessreq
dalign
.sftpreq:
	db	0, 0, 0, 9, 'subsystem', 1, 0, 0, 0, 4, 'sftp'
.sftpreqlen = $ - .sftpreq
dalign
.execreq:
	db	0, 0, 0, 4, 'exec', 1
.execreqlen = $ - .execreq
calign
.got_channelopen_failure:
	; ultimately, this is an error no matter how it originated
	; so, we will go ahead of off ourselves, with an applayer notify of same
	jmp	.badlength			; die die die
calign
.got_userauth_info_request:
	; make sure we are expecting wantuserauth
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantuserauth
	jne	.badlength			; die die die
	; otherwise, compose our SSH_MSG_USERAUTH_INFO_RESPONSE
	; this usually comes through twice, one with a prompt and one without
	; so we have to actually parse our buffer
	mov	rsi, [rbx+ssh_packetbuf_ofs]
	; swallow 3 strings, making sure we don't run off the end of our packetbuf
	mov	rdx, [rsi+buffer_length_ofs]
	mov	rsi, [rsi+buffer_itself_ofs]
	cmp	rdx, 16
	jb	.badlength
	
if use_movbe
	movbe	eax, dword [rsi]
else
	mov	eax, dword [rsi]
	bswap	eax
end if
	add	rsi, 4
	sub	edx, 4
	cmp	eax, edx
	jae	.badlength
	sub	edx, eax
	
if use_movbe
	movbe	eax, dword [rsi]
else
	mov	eax, dword [rsi]
	bswap	eax
end if
	add	rsi, 4
	sub	edx, 4
	cmp	eax, edx
	jae	.badlength
	sub	edx, eax
	
if use_movbe
	movbe	eax, dword [rsi]
else
	mov	eax, dword [rsi]
	bswap	eax
end if
	add	rsi, 4
	sub	edx, 4
	cmp	eax, edx
	jae	.badlength
	sub	edx, eax
	
	; next is our num prompts integer
if use_movbe
	movbe	eax, dword [rsi]
else
	mov	eax, dword [rsi]
	bswap	eax
end if

	cmp	eax, 1
	ja	.badlength		; if more than one prompt, bailout
	jb	.got_userauth_info_request_noreply
	
	cmp	qword [rbx+ssh_password_ofs], 0
	je	.badlength			; die die die
	; otherwise, an integer # responses, and our password
	mov	rdi, [rbx+ssh_password_ofs]
	call	string$utf8_length
	mov	edx, eax
	sub	rsp, 2048
	mov	dword [rsp], 0x01000000
if use_movbe
	movbe	dword [rsp+4], eax
else
	bswap	eax
	mov	dword [rsp+4], eax
end if
	lea	rsi, [rsp+8]
	mov	rdi, [rbx+ssh_password_ofs]
	push	rdx
	call	string$to_utf8
	pop	rcx
	add	rcx, 8
	mov	rdi, rbx
	mov	esi, 61			; SSH_MSG_USERAUTH_INFO_RESPONSE
	mov	rdx, rsp
	call	ssh$encrypt
	add	rsp, 2048

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_userauth_info_request_noreply:
	; we got 0 prompts, so return a response with a 0
	sub	rsp, 4
	mov	dword [rsp], 0
	mov	rdi, rbx
	mov	esi, 61			; SSH_MSG_USERAUTH_INFO_RESPONSE
	mov	rdx, rsp
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 4
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_userauth_request:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantuserauth
	jne	.badlength			; die die die
	; make sure we are in server mode
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badlength			; die die die
	; otherwise, we have string username, string servicename, string method, string language, string submethods
	; so, depending on whether we have callbacks enabled or not determines how we proceed from here
	cmp	qword [rbx+ssh_authcb_ofs], 0
	je	.got_userauth_request_immediatesuccess
	; otherwise, there is an auth callback setup for us, so we need to extract our 4 strings
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 20
	jb	.badlength
	push	r12 r13
	mov	r12, rsi
	mov	r13, rdx
if use_movbe
	movbe	eax, dword [r12]
else
	mov	eax, dword [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	ja	.got_userauth_request_fail1
	; otherwise, we have a utf8 username here
	mov	rdi, r12
	mov	esi, eax
	add	r12, rax
	sub	r13, rax
	jz	.got_userauth_request_fail1
	cmp	r13, 12
	jb	.got_userauth_request_fail1
	call	string$from_utf8
	mov	[rbx+ssh_username_ofs], rax
if use_movbe
	movbe	eax, dword [r12]
else
	mov	eax, dword [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	ja	.got_userauth_request_fail1
	; otherwise, we have a utf8 servicename, which _should_ be ssh-connection
	; if we cared about the contents of the servicename, we would create a string here
	; since we don't, just skip over it
	add	r12, rax
	sub	r13, rax
	jz	.got_userauth_request_fail1
	cmp	r13, 8
	jb	.got_userauth_request_fail1
	; next up: string method
if use_movbe
	movbe	eax, dword [r12]
else
	mov	eax, dword [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	ja	.got_userauth_request_fail1
	; otherwise, we have a utf8 methodname here
	cmp	eax, 8
	jne	.got_userauth_request_fail2
	cmp	dword [r12], 'pass'
	jne	.got_userauth_request_fail2
	cmp	dword [r12+4], 'word'
	jne	.got_userauth_request_fail2
	; skip the method name, and the leading boolean to our password
	add	r12, rax
	sub	r13, rax
	jz	.got_userauth_request_fail1
	cmp	r13, 5
	jb	.got_userauth_request_fail1
	add	r12, 1
	sub	r13, 1
if use_movbe
	movbe	eax, dword [r12]
else
	mov	eax, dword [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	ja	.got_userauth_request_fail1
	mov	rdi, r12
	mov	esi, eax
	add	r12, rax
	sub	r13, rax
	call	string$from_utf8
	mov	[rbx+ssh_password_ofs], rax
	; now, do our authcb to determine the outcome
	mov	rdi, rbx
	mov	r8, [rbx+ssh_authcbarg_ofs]
	cmp	qword [rbx+ssh_authcbarg_ofs], 0
	cmovne	rdi, r8
	mov	rsi, [rbx+ssh_username_ofs]
	mov	rdx, [rbx+ssh_password_ofs]
	call	qword [rbx+ssh_authcb_ofs]
	test	eax, eax
	jz	.got_userauth_request_fail2
	; otherwise, success, blast the password field
	mov	rdi, [rbx+ssh_password_ofs]
	mov	qword [rbx+ssh_password_ofs], 0
	call	heap$free_clear

	mov	rdi, rbx
	mov	esi, 52				; SSH_MSG_USERAUTH_SUCCESS
	mov	rdx, rsp
	xor	ecx, ecx
	call	ssh$encrypt
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel

	; if compression is pending, enable it
	mov	edx, 2
	mov	ecx, [rbx+ssh_compstate_ofs]
	cmp	ecx, 1
	cmove	ecx, edx
	mov	[rbx+ssh_compstate_ofs], ecx


	pop	r13 r12

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_userauth_request_fail1:
	; just die
	pop	r13 r12
	jmp	.badlength	; die die die
calign
.got_userauth_request_fail2:
	; no actual death, just fire off an authfail
	pop	r13 r12
	mov	rdi, rbx
	mov	esi, 51				; SSH_MSG_USERAUTH_FAILURE
	mov	rdx, .authfail
	mov	ecx, .authfaillen
	call	ssh$encrypt

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
dalign
.authfail:
	db	0, 0, 0, 8, 'password', 1
.authfaillen = $ - .authfail
calign
.got_userauth_request_immediatesuccess:
	; no authcb was set, so we just accept it
	mov	rdi, rbx
	mov	esi, 52				; SSH_MSG_USERAUTH_SUCCESS
	mov	rdx, rsp
	xor	ecx, ecx
	call	ssh$encrypt
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel

	; if compression is pending, enable it
	mov	edx, 2
	mov	ecx, [rbx+ssh_compstate_ofs]
	cmp	ecx, 1
	cmove	ecx, edx
	mov	[rbx+ssh_compstate_ofs], ecx


	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_userauth_failure:
	; ultimately, we aren't interested in other possible methods if our attempt failed, we can safely terminate our connection
	; which will in turn notify our applayer of our death
	jmp	.badlength			; die die die
calign
.got_userauth_success:
	; the rfc says we should ignore auth messages silently if our auth has already completed
	; but I say, if we weren't expecting it, die
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantuserauth
	jne	.badlength			; die die die
	; otherwise, we are sweet, which means we need to open a channel next
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantchannel

	; if compression is pending, enable it
	mov	edx, 2
	mov	ecx, [rbx+ssh_compstate_ofs]
	cmp	ecx, 1
	cmove	ecx, edx
	mov	[rbx+ssh_compstate_ofs], ecx

	; make our channel id random:
	call	rng$u32
	; the remote side doesn't care about our channelid, and since we are "single-channel" minded, when we 
	; receive the confirmation, we'll just set our channelid to whatever the remote side sent us and call
	; it good
	mov	dword [rbx+ssh_channelid_ofs], eax

	; send out our channel open request
	mov	ecx, 0x7fffffff
	mov	dword [rbx+ssh_localwindow_ofs], ecx

	sub	rsp, 2048
	mov	rdi, rsp
	mov	rsi, .sessionstr
	mov	edx, .sessionstrlen
	call	memcpy
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	ecx, [rbx+ssh_localwindow_ofs]
	mov	edx, 32768
	lea	rdi, [rsp+.sessionstrlen]
	mov	dword [rdi], eax
if use_movbe
	movbe	dword [rdi+4], ecx
	movbe	dword [rdi+8], edx
else
	bswap	ecx
	bswap	edx
	mov	dword [rdi+4], ecx
	mov	dword [rdi+8], edx
end if
	
	mov	rdi, rbx
	mov	esi, 90				; SSH_MSG_CHANNEL_OPEN
	mov	rdx, rsp
	mov	ecx, .sessionstrlen + 12
	call	ssh$encrypt
	
	add	rsp, 2048
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
dalign
.sessionstr:
	db	0, 0, 0, 7, 'session'
.sessionstrlen = $ - .sessionstr
calign
.got_servicerequest:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantservice
	jne	.badlength
	; there should be precisely one string, and it should match precisely ssh-userauth
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	edx, .client_servicename_len
	jne	.badlength			; die die die
	; otherwise, its length is the same, make sure it is equal
	mov	rdi, [rdi+buffer_itself_ofs]
	mov	rsi, .client_servicename
	call	memcmp
	test	eax, eax
	jnz	.badlength			; if service name != ssh-userauth, die
	; otherwise, we are clear to send back a service accept
	mov	rdi, rbx
	mov	esi, 6				; SSH_MSG_SERVICE_ACCEPT
	mov	rdx, .client_servicename
	mov	ecx, .client_servicename_len
	call	ssh$encrypt
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantuserauth
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_serviceaccept:
	; we get these in client mode after we send our service request
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantservice
	jne	.badlength			; die die die
	push	r12

	sub	rsp, 2048
	mov	r12, rsp
	; otherwise, we need to kickoff our userauth

	; update our stage
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantuserauth

	; we aren't really interested in the string, as it should equal the one we sent anyway
	; 50 == userauth request
	; service == "ssh-connection"
	; username is whatever got passed to us at client init
	; if a password was set, then we do method == password, otherwise method == none
	cmp	qword [rbx+ssh_username_ofs], 0
	je	.got_serviceaccept_nousername
	cmp	qword [rbx+ssh_password_ofs], 0
	je	.got_serviceaccept_nopassword

	; otherwise, we have both, so fire off a keyboard-interactive (though of course we aren't really
	; doing that) session
	mov	rdi, [rbx+ssh_username_ofs]
	call	string$utf8_length
	mov	edx, eax
if use_movbe
	movbe	[r12], eax
else
	bswap	eax
	mov	[r12], eax
end if
	add	r12, 4
	mov	rdi, [rbx+ssh_username_ofs]
	mov	rsi, r12
	add	r12, rdx
	call	string$to_utf8
	; service name is next
	mov	rdi, r12
	mov	rsi, ssh_service
	mov	edx, ssh_service_len
	add	r12, ssh_service_len
	call	memcpy
	; method name is 'keyboard-interactive', followed by language tag and submethods
	mov	rdi, r12
	mov	rsi, .keyboardinteractive
	mov	edx, .keyboardinteractive_len
	add	r12, .keyboardinteractive_len
	call	memcpy
	; send it off
	mov	rdi, rbx
	mov	esi, 50				; SSH_MSG_USERAUTH_REQUEST
	mov	rdx, rsp
	mov	rcx, r12
	sub	rcx, rsp
	call	ssh$encrypt

	add	rsp, 2048
	pop	r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_serviceaccept_nousername:
	; no username was given to us, so send method = 'none', username = 'taketwo'
	mov	rdi, rbx
	mov	esi, 50				; SSH_MSG_USERAUTH_REQUEST
	mov	rdx, .default_auth
	mov	ecx, .default_auth_len
	call	ssh$encrypt
	add	rsp, 2048
	pop	r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_serviceaccept_nopassword:
	; we have a username, but no password
	mov	rdi, [rbx+ssh_username_ofs]
	call	string$utf8_length
	mov	edx, eax
if use_movbe
	movbe	[r12], eax
else
	bswap	eax
	mov	[r12], eax
end if
	add	r12, 4
	mov	rdi, [rbx+ssh_username_ofs]
	mov	rsi, r12
	add	r12, rdx
	call	string$to_utf8
	; service name is next
	mov	rdi, r12
	mov	rsi, ssh_service
	mov	edx, ssh_service_len
	add	r12, ssh_service_len
	call	memcpy
	mov	rdi, r12
	mov	rsi, .no_method
	mov	edx, .no_method_len
	add	r12, .no_method_len
	call	memcpy
	; send it off

	mov	rdi, rbx
	mov	esi, 50				; SSH_MSG_USERAUTH_REQUEST
	mov	rdx, rsp
	mov	rcx, r12
	sub	rcx, rsp
	call	ssh$encrypt

	add	rsp, 2048
	pop	r12
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
dalign
.password_method:
	db	0, 0, 0, 8, 'password', 0
.password_method_len = $ - .password_method
dalign
.keyboardinteractive:
	db	0, 0, 0, 20, 'keyboard-interactive', 0, 0, 0, 5, 'en-US', 0, 0, 0, 0
.keyboardinteractive_len = $ - .keyboardinteractive

dalign
.default_auth:
	db	0, 0, 0, 7, 'taketwo', 0, 0, 0, 14, 'ssh-connection', 0, 0, 0, 4, 'none'
.default_auth_len = $ - .default_auth
dalign
.no_method:
	db	0, 0, 0, 4, 'none'
.no_method_len = $ - .no_method
calign
.got_ignore:
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_newkeys:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantnewkeys
	jne	.badlength			; die die die
	; there is no data that accompanies this, all we need to do is initialize our read state
	lea	rdi, [rbx+ssh_remoteiv_ofs]
	lea	rsi, [rbx+ssh_pending_remoteiv_ofs]
	mov	edx, 16
	call	memcpy
	lea	rdi, [rbx+ssh_readcipher_ofs]
	lea	rsi, [rbx+ssh_remotekey_ofs]

	mov	edx, 32
	call	aes$init_decrypt
	lea	rdi, [rbx+ssh_readhmac_ofs]
	call	hmac$init_sha256
	lea	rdi, [rbx+ssh_readhmac_ofs]
	lea	rsi, [rbx+ssh_remoteint_ofs]
	mov	edx, 32

	; INTENTIONAL KAKKING OF REMOTE KEYS:
	; mov	dword [rsi], 0x4646
	; end intentional kakking

	call	hmac$key

	; now that they are keyed, we can clear them
	lea	rdi, [rbx+ssh_pending_remoteiv_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_remotekey_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_remoteint_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32

if ssh_do_compression
	; also initialize our inflate state
	cmp	qword [rbx+ssh_inflate_ofs+zlib_state_ofs], 2
	jne	.skipinfend
	lea	rdi, [rbx+ssh_inflate_ofs]
	call	zlib$inflateEnd
calign
.skipinfend:
	lea	rdi, [rbx+ssh_inflate_ofs]
	mov	esi, 1
	call	zlib$inflateInit
end if
	; if inbound decryption was _already_ enabled, we need to set our expectation differently:
	cmp	dword [rbx+ssh_remoteenc_ofs], 1
	je	.got_newkeys_notfirst

	; enable inbound decryption
	mov	dword [rbx+ssh_remoteenc_ofs], 1
	; update our stage to wantservice
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantservice

	; if the compression state == 3, turn it all to active now
	mov	eax, [rbx+ssh_compstate_ofs]
	mov	ecx, 2
	cmp	eax, 3
	cmove	eax, ecx
	mov	[rbx+ssh_compstate_ofs], eax

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_newkeys_notfirst:
	; rekey! set our stage to open again
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_interactive

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
dalign
.rsapref:
	db	0, 0, 0, 7, 'ssh-rsa'
.rsapreflen = $ - .rsapref
dalign
.dsapref:
	db	0, 0, 0, 7, 'ssh-dss'
.dsapreflen = $ - .dsapref
dalign
.sighash:
        db      0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
.sighashlen = $ - .sighash
calign
.got_kexgexinit:
	; we should be in server mode, and specifically be expecting this message
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badlength		; die die die
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexinit
	jne	.badlength		; die die die
	; otherwise, we should be camped out on precisely one public e mpint
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, (dh_bits shr 3)	; this should always match our own
	jb	.badlength
	; otherwise, construct our dh_e
	lea	rdi, [rsi+4]
if use_movbe
	movbe	esi, [rsi]
else
	mov	esi, [rsi]
	bswap	esi
end if
	; sanity to make sure we have enough room to do our monty powmods, though the static dh_bits should cover it
	cmp	esi, bigint_maxwords shl 2
	ja	.badlength
	call	bigint$new_encoded
	; we might have had a previous value as well:
	mov	rdi, [rbx+ssh_dh_e_ofs]
	mov	[rbx+ssh_dh_e_ofs], rax
	test	rdi, rdi
	jz	.got_kexgexinit_noclear
	call	bigint$destroy
	; if there was an e already there, so too must there be an f
	mov	rdi, [rbx+ssh_dh_f_ofs]
	call	bigint$destroy_clear	; clear because of the monty object hanging off it
	; and same with dh_private
	mov	rdi, [rbx+ssh_dh_private_ofs]
	call	bigint$destroy_clear
	; and same with dh_shared
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	call	bigint$destroy_clear
	mov	rax, [rbx+ssh_dh_e_ofs]
calign
.got_kexgexinit_noclear:
	; create a new bigint for our dh_f
	call	bigint$new
	mov	[rbx+ssh_dh_f_ofs], rax
	; next up, our dh_private
	mov	edi, dh_privatekey_size	; dh_privatekey_size determines how much private key (aka DH private exponent) we use
	call	bigint$new_random
	mov	[rbx+ssh_dh_private_ofs], rax
	; next up, generate our dh_f by doing dh_g**dh_private mod dh_p
	mov	rdi, rax		; exponent for monty
	mov	rsi, [rbx+ssh_dh_p_ofs]	; modulus
	call	monty$new
	mov	rdi, [rbx+ssh_dh_f_ofs]	; we'll stick our monty object here
	mov	[rdi+bigint_monty_powmod_ofs], rax
	mov	rdi, rax
	mov	rsi, [rbx+ssh_dh_f_ofs]	; destination for the powmod
	mov	rdx, [rbx+ssh_dh_g_ofs]	; source for the powmod
	call	monty$doit
	; create our shared secret with the same monty object using the client's public e
	call	bigint$new
	mov	[rbx+ssh_dh_shared_ofs], rax
	mov	rdi, [rbx+ssh_dh_f_ofs]
	mov	rsi, [rbx+ssh_dh_shared_ofs]	; destination for the powmod
	mov	rdx, [rbx+ssh_dh_e_ofs]	; source for the powmod
	mov	rdi, [rdi+bigint_monty_powmod_ofs]
	call	monty$doit
	; so our Diffie-Hellman math bit is done, next up is organising our host key/certs

	mov	rdi, [rbx+ssh_localcert_ofs]
	; either our X509_pubkey_ofs or X509_dsapubkey_ofs needs to be sent off/included for our host key
	push	r12 r13 r14 r15
	mov	rsi, [rdi+X509_pubkey_ofs]
	mov	rdx, [rdi+X509_dsapubkey_ofs]
	; we know we have at one if not both
	test	rsi, rsi
	cmovz	rsi, rdx
	mov	r12, [rsi+buffer_itself_ofs]
	mov	r13, [rsi+buffer_length_ofs]
	call	.keycalc
	; so now we have our hash H and all our derived keys

	; go ahead and get our signature SHA160 prepared

	sub	rsp, 16384

	; get a sha160 happening of our H
	mov	rdi, rsp
	call	sha160$init
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_hash_ofs]
	mov	edx, 32
	call	sha160$update


	; next up, we need to sign it depending on which one we sent off
	mov	rdi, [rbx+ssh_localcert_ofs]
	cmp	qword [rdi+X509_pubkey_ofs], 0
	je	.got_kexgexinit_sign_dsa
	mov	rsi, [rdi+X509_privatekey_ofs]

	; we need a "straight" sha160 for the RSA signing operation, hash of the hash itself (32 bytes)
	
	; else, we are RSA signing H
	; which means we need a EMSA-PKCS1-v1_5 version of SHA160(H)
	lea	r12, [rsp+sha160_state_size]
	mov	rdi, [rsi+rsaprivate_n_ofs]		; public n
	call	bigint$bitcount
	sub	eax, 1
	shr	eax, 3					; emLen
	mov	r13d, eax				; hang onto emLen

	mov	edx, r13d
	mov	byte [r12], 0x01			; EM leading byte sans the 0x00 since we turn this into an integer anyway which would drop it
	sub	edx, 20 + .sighashlen + 2		; 20 for the hash, + the hashid preface, + 2 more for our pkcs identifiers
	mov	byte [r12+rdx+1], 0x00
	; we need to memset the spot at r12+1 for rdx bytes of 0xff
	lea	rdi, [r12+1]
	mov	esi, 0xff
	call	memset
	mov	edx, r13d
	sub	edx, 20 + .sighashlen
	lea	rdi, [r12+rdx]
	mov	rsi, .sighash
	mov	edx, .sighashlen
	call	memcpy
	mov	edx, r13d
	sub	edx, 20
	lea	rsi, [r12+rdx]
	mov	rdi, rsp
	xor	edx, edx				; don't attempt to free the state
	call	sha160$final

	; so now we have emLen worth of bytes sitting at rsp nicely pkcs padded/encoded
	; we need an integer of that:
	mov	rdi, r12
	mov	esi, r13d
	call	bigint$new_encoded
	mov	r14, rax				; hangon to our temporary bigint

	; NOTE RE: RSA Blinding: because we know the inputs are good and that _we_ generated them
	; we aren't exposing ourselves to any timing channel by not doing blinding here
	push	r12 r13 r15
	mov	r13, r14
	mov	rcx, [rbx+ssh_localcert_ofs]
	mov	r12, [rcx+X509_privatekey_ofs]
	; so we need (r13 mod q)**dmodq mod q
	mov	rdi, r13
	call	bigint$new_copy
	mov	r15, rax
	mov	rdi, rax
	mov	rsi, [r12+rsaprivate_q_ofs]
	call	bigint$modby
	mov	rdi, [r12+rsaprivate_dmodq_ofs]		; exponent
	mov	rsi, [r12+rsaprivate_q_ofs]		; modulus
	call	monty$new
	mov	[r15+bigint_monty_powmod_ofs], rax
	mov	rdi, rax
	mov	rsi, r15
	mov	rdx, r15
	call	monty$doit
	; and then: (r13 mod p)**dmodp mod p
	mov	rdi, r13
	mov	rsi, [r12+rsaprivate_p_ofs]
	call	bigint$modby
	; reinitialize our monty object in r15
	mov	rdi, [r15+bigint_monty_powmod_ofs]
	mov	rsi, [r12+rsaprivate_dmodp_ofs]		; exponent
	mov	rdx, [r12+rsaprivate_p_ofs]		; modulus
	call	monty$reinit
	mov	rdi, [r15+bigint_monty_powmod_ofs]
	mov	rsi, r13
	mov	rdx, r13
	call	monty$doit
	; CRT goods
	mov	rdi, r13
	mov	rsi, r15
	call	bigint$subtract
	mov	rdi, r13
	mov	rsi, [r12+rsaprivate_invqmodp_ofs]
	call	bigint$multiply
	mov	rdi, r13
	mov	rsi, [r12+rsaprivate_p_ofs]
	call	bigint$modby
	mov	rdi, r13
	mov	rsi, [r12+rsaprivate_q_ofs]
	call	bigint$multiply
	mov	rdi, r13
	mov	rsi, r15
	call	bigint$add
	; r13 has the result, cleanup r15
	mov	rdi, r15
	call	bigint$destroy_clear
	
	mov	r14, r13
	pop	r15 r13 r12

	; so now we can compose our return SSH_MSG_KEX_DH_GEX_REPLY
	; X509_pubkey_ofs == a buffer, whose length we eneed to prefix
	mov	rcx, [rbx+ssh_localcert_ofs]
	mov	rsi, [rcx+X509_pubkey_ofs]
	mov	rdx, [rsi+buffer_length_ofs]
	mov	r15d, edx				; hangon to our length
	mov	eax, edx
if use_movbe
	movbe	[rsp], eax
else
	bswap	eax
	mov	[rsp], eax				; length prefix
end if
	lea	rdi, [rsp+4]
	mov	rsi, [rsi+buffer_itself_ofs]
	call	memcpy

	; next is our f
	mov	rdi, [rbx+ssh_dh_f_ofs]
	lea	rsi, [rsp+r15+8]			; +4 for the original length prefix, +4 more for this one's length prefix
	call	bigint$ssh_encode

if use_movbe
	lea	rdi, [rsp+r15+4]
	movbe	[rdi], eax
else
	mov	edx, eax
	bswap	edx
	lea	rdi, [rsp+r15+4]
	mov	[rdi], edx				; its length prefix
end if
	; update r15 to be pointing to the right spot in our buffer
	add	r15d, 8
	add	r15d, eax

	; resulting signature needs ot be prefaced with ssh-rsa
	lea	rdi, [rsp+r15+4]
	mov	rsi, .rsapref
	mov	edx, .rsapreflen
	call	memcpy

	; so next up is the result of our rsaprivate, which also needs length prefixed
	mov	rdi, r14
	lea	rsi, [rsp+r15+8+.rsapreflen]
	call	bigint$encode
	mov	rdi, r14
	call	bigint$bytecount
if use_movbe
	lea	rdi, [rsp+r15+4+.rsapreflen]
	movbe	[rdi], eax
else
	mov	edx, eax
	bswap	edx
	lea	rdi, [rsp+r15+4+.rsapreflen]
	mov	[rdi], edx
end if
	; we need to set the overall signature length
	mov	edx, eax
	add	edx, 4
	add	edx, .rsapreflen
	lea	rdi, [rsp+r15]
if use_movbe
	movbe	[rdi], ecx
else
	bswap	edx
	mov	[rdi], edx
end if

	; we are ready to send it down the wire
	mov	rdi, rbx
	mov	esi, 33			; SSH_MSG_KEX_DH_GEX_REPLY
	mov	rdx, rsp
	mov	ecx, r15d
	add	ecx, 8+.rsapreflen
	add	ecx, eax
	call	ssh$encrypt

	; cleanup r14
	mov	rdi, r14
	call	bigint$destroy		; it got sent in the clear over the wire, no _clear necessary

	; we also need to send our newkeys message, and initialise our side of the goods:
	mov	rdi, rbx
	mov	esi, 21				; SSH_MSG_NEWKEYS
	mov	rdx, rsp
	xor	ecx, ecx			; no bytes go with this one
	call	ssh$encrypt

	; copy our pending local side keys to the current keys, initialise our aes write key, set open = 1, and send off our service request
	lea	rdi, [rbx+ssh_localiv_ofs]
	lea	rsi, [rbx+ssh_pending_localiv_ofs]
	mov	edx, 16
	call	memcpy
	lea	rdi, [rbx+ssh_writecipher_ofs]
	lea	rsi, [rbx+ssh_localkey_ofs]
	mov	edx, 32
	call	aes$init_encrypt
	lea	rdi, [rbx+ssh_writehmac_ofs]
	call	hmac$init_sha256
	lea	rdi, [rbx+ssh_writehmac_ofs]
	lea	rsi, [rbx+ssh_localint_ofs]
	mov	edx, 32
	call	hmac$key

	; now that they are keyed, we can clear them
	lea	rdi, [rbx+ssh_pending_localiv_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_localkey_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_localint_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32

if ssh_do_compression
	; also initialize our deflate state
	cmp	qword [rbx+ssh_deflate_ofs+zlib_state_ofs], 2
	jne	.skipdefend
	lea	rdi, [rbx+ssh_deflate_ofs]
	call	zlib$deflateEnd
calign
.skipdefend:
	lea	rdi, [rbx+ssh_deflate_ofs]
	mov	esi, 1
	call	zlib$deflateInit
end if

	mov	dword [rbx+ssh_localenc_ofs], 1
	mov	dword [rbx+ssh_open_ofs], 1		; this will turn on encryption for writes if it wasn't already
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantnewkeys

	add	rsp, 16384
	pop	r15 r14 r13 r12

	; we are done with our dh values
	call	.dhclear

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop

calign
.got_kexgexinit_sign_dsa:
	; DSA signature of H, which is to say: do our hmac final, turn that into an integer
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx				; don't attempt to free the state
	call	sha160$final
	lea	rdi, [rsp+sha160_state_size]
	mov	esi, 20
	call	bigint$new_encoded
	mov	r12, rax				; m
	mov	rdi, [rbx+ssh_localcert_ofs]
	mov	r13, [rdi+X509_dsaprivatekey_ofs]
	; so we need a random k < q
	call	bigint$new
	mov	r14, rax
calign
.got_kexgexinit_sign_dsa_randomk:
	mov	rdi, [r13+dsaprivate_q_ofs]
	call	bigint$bitcount
	mov	rdi, r14
	mov	esi, eax
	call	bigint$set_random
	mov	rdi, r14
	mov	rsi, [r13+dsaprivate_q_ofs]
	call	bigint$compare
	cmp	eax, 0
	jge	.got_kexgexinit_sign_dsa_randomk
	; r = (g**k mod p)
	mov	rdi, r14				; k == exponent
	mov	rsi, [r13+dsaprivate_p_ofs]		; p == modulus
	call	monty$new
	mov	[r12+bigint_monty_powmod_ofs], rax	; r12 == our H(m)
	; we need a couple of temporaries here to do the deed
	call	bigint$new
	push	rax
	; inversemod k, q
	mov	rdi, rax
	mov	rsi, r14
	mov	rdx, [r13+dsaprivate_q_ofs]
	call	bigint$inversemod
	mov	rdi, r14
	mov	rsi, [rsp]
	call	bigint$assign
	; r14 == inversemod of k and q
	mov	rdi, [r12+bigint_monty_powmod_ofs]
	mov	rsi, [rsp]				; destination for our powmod
	mov	rdx, [r13+dsaprivate_g_ofs]		; source
	call	monty$doit
	; so now [rsp] == g**k mod p
	; now we need to mod that by q
	mov	rdi, [rsp]
	mov	rsi, [r13+dsaprivate_q_ofs]
	call	bigint$modby
	; r in [rsp] is complete, and r14 == the first part of s, r12 == H(m)
	; now we need (x * r) + r12
	mov	rdi, [rsp]
	call	bigint$new_copy
	push	rax
	mov	rdi, rax
	mov	rsi, [r13+dsaprivate_x_ofs]
	call	bigint$multiply
	mov	rdi, r12
	mov	rsi, [rsp]
	call	bigint$add
	; so now r12 == (x * r) + r12
	pop	rdi
	call	bigint$destroy_clear
	; next we need r14 (inversemod k) * r12 mod q
	mov	rdi, r12
	mov	rsi, r14
	call	bigint$multiply
	mov	rdi, r12
	mov	rsi, [r13+dsaprivate_q_ofs]
	call	bigint$modby
	; so now r12 == s, set r14 to r
	mov	rdi, r14
	mov	rsi, [rsp]
	call	bigint$assign
	pop	rdi
	call	bigint$destroy_clear

	; r14 == r, r12 == s
	; if either are zero (possible but remote)
	; start over
	mov	rdi, r14
	call	bigint$is_zero
	test	eax, eax
	jnz	.got_kexgexinit_sign_dsa_randomk
	mov	rdi, r12
	call	bigint$is_zero
	test	eax, eax
	jnz	.got_kexgexinit_sign_dsa_randomk

	; now, the RFC says that a dss signature is a string containing r and s, 160 bit integers, without lengths or padding, unsigned, in network byte order
	
	; go ahead and compile our reply

	; so now we can compose our return SSH_MSG_KEX_DH_GEX_REPLY
	; X509_dsapubkey_ofs == a buffer, whose length we eneed to prefix
	mov	rcx, [rbx+ssh_localcert_ofs]
	mov	rsi, [rcx+X509_dsapubkey_ofs]
	mov	rdx, [rsi+buffer_length_ofs]
	mov	r15d, edx				; hangon to our length
	mov	eax, edx
if use_movbe
	movbe	[rsp], eax
else
	bswap	eax
	mov	[rsp], eax				; length prefix
end if
	lea	rdi, [rsp+4]
	mov	rsi, [rsi+buffer_itself_ofs]
	call	memcpy

	; next is our f
	mov	rdi, [rbx+ssh_dh_f_ofs]
	lea	rsi, [rsp+r15+8]			; +4 for the original length prefix, +4 more for this one's length prefix
	call	bigint$ssh_encode
if use_movbe
	lea	rdi, [rsp+r15+4]
	movbe	[rdi], eax
else
	mov	edx, eax
	bswap	edx
	lea	rdi, [rsp+r15+4]
	mov	[rdi], edx				; its length prefix
end if
	; update r15 to be pointing to the right spot in our buffer
	add	r15d, 8
	add	r15d, eax

	lea	rdi, [rsp+r15]
	; our total length is .dsapreflen + 4 + 40
	mov	eax, .dsapreflen + 4 + 40
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if

	; resulting signature needs ot be prefaced with ssh-dss
	lea	rdi, [rsp+r15+4]
	mov	rsi, .dsapref
	mov	edx, .dsapreflen
	add	r15, .dsapreflen + 4
	call	memcpy

	; next is our length prefix, which is 40
	mov	eax, 40
	lea	rdi, [rsp+r15]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	r15, 4
	; next is r
	mov	rdi, r14
	lea	rsi, [rsp+r15]
	add	r15, 20
	call	bigint$encode
	; next is s
	mov	rdi, r12
	lea	rsi, [rsp+r15]
	add	r15, 20
	call	bigint$encode

	; we can go ahead and send it off
	mov	rdi, rbx
	mov	esi, 33			; SSH_MSG_KEX_DH_GEX_REPLY
	mov	rdx, rsp
	mov	ecx, r15d
	call	ssh$encrypt

	; cleanup r14
	mov	rdi, r14
	call	bigint$destroy_clear
	; cleanup r12
	mov	rdi, r12
	call	bigint$destroy_clear

	; we also need to send our newkeys message, and initialise our side of the goods:
	mov	rdi, rbx
	mov	esi, 21				; SSH_MSG_NEWKEYS
	mov	rdx, rsp
	xor	ecx, ecx			; no bytes go with this one
	call	ssh$encrypt


	; copy our pending local side keys to the current keys, initialise our aes write key, set open = 1, and send off our service request
	lea	rdi, [rbx+ssh_localiv_ofs]
	lea	rsi, [rbx+ssh_pending_localiv_ofs]
	mov	edx, 16
	call	memcpy
	lea	rdi, [rbx+ssh_writecipher_ofs]
	lea	rsi, [rbx+ssh_localkey_ofs]
	mov	edx, 32
	call	aes$init_encrypt
	lea	rdi, [rbx+ssh_writehmac_ofs]
	call	hmac$init_sha256
	lea	rdi, [rbx+ssh_writehmac_ofs]
	lea	rsi, [rbx+ssh_localint_ofs]
	mov	edx, 32
	call	hmac$key

	; now that they are keyed, we can clear them
	lea	rdi, [rbx+ssh_pending_localiv_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_localkey_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_localint_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32

if ssh_do_compression
	; also initialize our deflate state
	cmp	qword [rbx+ssh_deflate_ofs+zlib_state_ofs], 0
	je	.skipdefend2
	lea	rdi, [rbx+ssh_deflate_ofs]
	call	zlib$deflateEnd
calign
.skipdefend2:
	lea	rdi, [rbx+ssh_deflate_ofs]
	mov	esi, 1
	call	zlib$deflateInit
end if
	mov	dword [rbx+ssh_localenc_ofs], 1
	mov	dword [rbx+ssh_open_ofs], 1		; this will turn on encryption for writes if it wasn't already
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantnewkeys

	add	rsp, 16384
	pop	r15 r14 r13 r12

	; we are done with our dh values
	call	.dhclear

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_kexgexreq_old:
	; we should be in server mode, and specifically be expecting this message
	; we should be sitting on precisely 4 bytes, n
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badlength		; die die die
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexreq
	jne	.badlength		; die die die
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 4
	jne	.badlength
	mov	dword [rbx+ssh_dh_min_ofs], -1
if use_movbe
	movbe	eax, [rsi]
else
	mov	eax, [rsi]
	bswap	eax
end if
	mov	dword [rbx+ssh_dh_n_ofs], eax
	mov	dword [rbx+ssh_dh_max_ofs], -1
	jmp	.got_kexgexreq_ready
calign
.got_kexgexreq:
	; we should be in server mode, and specifically be expecting this message
	; we should be sitting on precisely 12 bytes, min, n, max
	; we need to respond with our SSH_MSG_DH_GEX_GROUP, with p and g
	; we _could_ parse the max, and check it against our dh_bits, if dh_bits > their max, abort the connection
	; but since all of my clients are happy with even big ones, hehe, we'll just send it along
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.badlength		; die die die
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexreq
	jne	.badlength		; die die die

	mov	rdi, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	rdx, [rdi+buffer_length_ofs]
	cmp	rdx, 12
	jne	.badlength
	; else, parse min, n, max so we can save them for our hash
	mov	eax, [rsi]
	mov	ecx, [rsi+4]
	mov	edx, [rsi+8]
if use_movbe
	movbe	[rbx+ssh_dh_min_ofs], eax
	movbe	[rbx+ssh_dh_n_ofs], ecx
	movbe	[rbx+ssh_dh_max_ofs], edx
else
	bswap	eax
	bswap	ecx
	bswap	edx
	mov	[rbx+ssh_dh_min_ofs], eax
	mov	[rbx+ssh_dh_n_ofs], ecx
	mov	[rbx+ssh_dh_max_ofs], edx
end if
calign
.got_kexgexreq_ready:

	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexinit

	; if we are in the middle of a rekey, we need to clear out the previous values
	cmp	qword [rbx+ssh_dh_p_ofs], 0
	je	.got_kexgexreq_noclear
	mov	rdi, [rbx+ssh_dh_p_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+ssh_dh_g_ofs]
	call	bigint$destroy
calign
.got_kexgexreq_noclear:
	; if dynamic dh params are enabled, here is where they get generated
if ssh_dh_dynamic
	call	bigint$new
	mov	[rbx+ssh_dh_p_ofs], rax
	call	bigint$new
	mov	[rbx+ssh_dh_g_ofs], rax
	
	mov	rdi, [rbx+ssh_dh_p_ofs]
	mov	rsi, rax
	mov	edx, dh_bits
	call	bigint$dh_params
else
	; randomly select from our dh$pool
	xor	edi, edi
	mov	esi, dh$pool_p_size - 1
	call	rng$int
	mov	rdi, [rax*8+dh$pool_p]
	push	rax
	call	bigint$new_copy
	mov	[rbx+ssh_dh_p_ofs], rax
	pop	rax
	mov	rdi, [rax*8+dh$pool_g]
	call	bigint$new_copy
	mov	[rbx+ssh_dh_g_ofs], rax
end if
	sub	rsp, 4096
	mov	rdi, [rbx+ssh_dh_p_ofs]
	lea	rsi, [rsp+4]
	call	bigint$ssh_encode
	mov	edx, eax
if use_movbe
	movbe	[rsp], eax
else
	bswap	eax
	mov	[rsp], eax
end if
	lea	rsi, [rsp+rdx+8]
	mov	rdi, [rbx+ssh_dh_g_ofs]
	push	rdx
	call	bigint$ssh_encode
	pop	rdx
	mov	ecx, eax
if use_movbe
	lea	rsi, [rsp+rdx+4]
	movbe	[rsi], eax
else
	bswap	eax
	lea	rsi, [rsp+rdx+4]
	mov	[rsi], eax
end if
	mov	rdi, rbx
	mov	esi, 31			; SSH_MSG_KEX_DH_GEX_GROUP
	add	ecx, 8
	add	ecx, edx
	mov	rdx, rsp
	call	ssh$encrypt
	add	rsp, 4096

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_kexgexreply:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexreply
	jne	.badlength			; die die die
	; packetbuf contains our SSH_MSG_KEX_DH_GEX_REPLY, which has a 4 byte big endian "string" of the server public host key and certificates
	; along with a 4 byte big endian length prefixed server DH public f, and a 4 byte big endian "string" of the signature of H
	mov	rdx, [rbx+ssh_packetbuf_ofs]
	mov	rcx, [rdx+buffer_length_ofs]
	cmp	rcx, 278
	jb	.badlength			; our absolute minimum message size (really, it is much much larger than this, sanity only)
	mov	rdi, [rdx+buffer_itself_ofs]
if use_movbe
	movbe	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
else
	mov	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
	bswap	esi
end if
	cmp	esi, ecx
	jae	.badlength			; make sure the length prefix is sane
	; otherwise, we are sitting on the public key

	; we need to do some stack saving here so we can circle back to the public key
	push	r12 r13 r14
	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rcx

	; which is: string "ssh-{r,d}sa" followed by mpint e,n for rsa, or p, q, g, dsaprivate(k) for dsa
	
	; if we set aside the public key, load up the public f, then calculate our shared secret and H
	; we can then circle back around, and verify the signature based on which type of public key it is

	; skip the public key for the moment
	add	rdi, rsi
	sub	rcx, rsi
	jz	.got_kexgexreply_badlength	; invalid if we don't have enough length
	cmp	rcx, 64
	jb	.got_kexgexreply_badlength	; sanity only really
if use_movbe
	movbe	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
else
	mov	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
	bswap	esi
end if
	cmp	esi, ecx
	jae	.got_kexgexreply_badlength	; make sure the length prefix is sane

	; sanity to make sure the length isn't too insane:
	cmp	esi, bigint_maxwords shl 2
	ja	.got_kexgexreply_badlength

	; we are now sitting on our server's public f, length is sitting in esi
	push	rdi
	add	[rsp], rsi
	sub	rcx, rsi
	push	rcx
	call	bigint$new_encoded
	mov	[rbx+ssh_dh_f_ofs], rax		; our public f value

	mov	rdi, rax
	mov	rsi, bigint$one
	call	bigint$compare
	cmp	eax, 0
	jle	.got_kexgexreply_bad_dh
	mov	rdi, [rbx+ssh_dh_f_ofs]
	mov	rsi, [rbx+ssh_dh_p_ofs]
	call	bigint$compare
	cmp	eax, 0
	jge	.got_kexgexreply_bad_dh

if sshdebug
	mov	rdi, .dhfmsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_dh_f_ofs]
	call	bigint$debug
end if
	; so now, we can compute the shared secret with public f in r15
	call	bigint$new
	mov	[rbx+ssh_dh_shared_ofs], rax

	; public_f**ssh_dh_private_ofs mod dh_p is what we need
	; we still have a monty object hanging off our public e object, reuse it, since its exponents are the same
	mov	rax, [rbx+ssh_dh_e_ofs]		; our public e value
	mov	rdi, [rax+bigint_monty_powmod_ofs]
	mov	rsi, [rbx+ssh_dh_shared_ofs]	; destination for our powmod
	mov	rdx, [rbx+ssh_dh_f_ofs]		; source for our powmod
	call	monty$doit
if sshdebug
	mov	rdi, .dhsharedmsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	call	bigint$debug
end if

	; now that we have all our values from the key exchange, we can let the keycalc commence
	call	.keycalc


	; so our keys are set, now we need to send out the SSH_NEWKEYS message
	mov	rdi, rbx
	mov	esi, 21				; SSH_MSG_NEWKEYS
	mov	rdx, rsp
	xor	ecx, ecx			; no bytes go with this one
	call	ssh$encrypt


	; copy our pending local side keys to the current keys, initialise our aes write key, set open = 1, and send off our service request
	lea	rdi, [rbx+ssh_localiv_ofs]
	lea	rsi, [rbx+ssh_pending_localiv_ofs]
	mov	edx, 16
	call	memcpy
	lea	rdi, [rbx+ssh_writecipher_ofs]
	lea	rsi, [rbx+ssh_localkey_ofs]
	mov	edx, 32
	call	aes$init_encrypt
	lea	rdi, [rbx+ssh_writehmac_ofs]
	call	hmac$init_sha256
	lea	rdi, [rbx+ssh_writehmac_ofs]
	lea	rsi, [rbx+ssh_localint_ofs]
	mov	edx, 32
	call	hmac$key

	; now that they are keyed, we can clear them
	lea	rdi, [rbx+ssh_pending_localiv_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_localkey_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32
	lea	rdi, [rbx+ssh_localint_ofs]
	xor	esi, esi
	mov	edx, 32
	call	memset32

if ssh_do_compression
	; also initialize our deflate state
	cmp	qword [rbx+ssh_deflate_ofs+zlib_state_ofs], 0
	je	.skipdefend3
	lea	rdi, [rbx+ssh_deflate_ofs]
	call	zlib$deflateEnd
calign
.skipdefend3:
	lea	rdi, [rbx+ssh_deflate_ofs]
	mov	esi, 1
	call	zlib$deflateInit
end if
	mov	dword [rbx+ssh_localenc_ofs], 1
	mov	dword [rbx+ssh_open_ofs], 1		; this will turn on encryption for writes if it wasn't already

	; [rsp] == rcx (length of signature blob)
	; [rsp+8] == rdi (pointer to signature blob)

	; first dword of the sigblob is its overall length, next dword is the preface length
	; which _must_ match the preface length starting at r12
	mov	rdi, [rsp+8]
	mov	rsi, r12
	mov	edx, 11					; 4 for the uint32 preface length, 7 for the preface itself
	add	rdi, 4
	call	memcmp
	test	eax, eax
	jnz	.got_kexgexreply_keysigmismatch
	; otherwise, figure out which kind of signature it is, rsa or dss
	mov	rdi, [rsp+8]
	add	rdi, 11					; +4 for the uint32 preface, +4 for the preface length, +3 into that
	cmp	dword [rdi], '-dss'
	je	.got_kexgexreply_dss_sig
	; make sure it is -rsa
	cmp	dword [rdi], '-rsa'
	jne	.got_kexgexreply_keysigmismatch
	; r13 must be at least 11 + 6 + 12 bytes long
	cmp	r13, 29
	jbe	.got_kexgexreply_keysigmismatch
	
	; rsa signature, rsa public key, so our key after the preface contains e, n
	; and our signature after the preface contains s, an int without padding/etc
	; so we need to do: sig**e mod n, generate our own hash and compare the results
	
	; e begins at [r12+11]
	add	r12, 11
	sub	r13, 11
if use_movbe
	movbe	eax, [r12]
else
	mov	eax, [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	jae	.got_kexgexreply_keysigmismatch
	; otherwise, we can compose bigint e
	mov	rdi, r12
	mov	esi, eax
	; skip over this one before we move on
	add	r12, rax
	sub	r13, rax
	jz	.got_kexgexreply_keysigmismatch
	cmp	r13, 4
	jb	.got_kexgexreply_keysigmismatch
	; before we proceed, verify the length of n
if use_movbe
	movbe	ecx, [r12]
else
	mov	ecx, [r12]
	bswap	ecx
end if
	cmp	rcx, r13
	jae	.got_kexgexreply_keysigmismatch

	; sanity to make sure our length isn't too insane
if use_movbe
	movbe	r8d, [r12]
	cmp	esi, bigint_maxwords shl 2
	ja	.got_kexgexreply_keysigmismatch
else
	mov	r8d, [r12]
	cmp	esi, bigint_maxwords shl 2
	ja	.got_kexgexreply_keysigmismatch
	bswap	r8d
end if
	cmp	r8d, bigint_maxwords shl 2
	ja	.got_kexgexreply_keysigmismatch

	call	bigint$new_encoded
	mov	r14, rax
if use_movbe
	movbe	esi, [r12]
	add	r12, 4
else
	mov	esi, [r12]
	add	r12, 4
	bswap	esi
end if
	mov	rdi, r12
	call	bigint$new_encoded
	mov	r13, rax

if sshdebug
	mov	rdi, .rsasige
	call	string$to_stdoutln
	mov	rdi, r14
	call	bigint$debug
	mov	rdi, .rsasign
	call	string$to_stdoutln
	mov	rdi, r13
	call	bigint$debug
end if

	; so now we have r13 == n, r14 == e, we need a monty object to do the deed
	mov	rdi, r14
	mov	rsi, r13
	call	monty$new
	mov	[r13+bigint_monty_powmod_ofs], rax
	; we can re-use r14 for our signature
	
	mov	rdi, [rsp+8]
	mov	rcx, [rsp]			; length of the signature blob
	add	rdi, 15				; skip over the preface
if use_movbe
	movbe	esi, [rdi]
else
	mov	esi, [rdi]
	bswap	esi
end if
	sub	rcx, 15
	cmp	rsi, rcx
	ja	.got_kexgexreply_rsasigkakked
	add	rdi, 4

	cmp	esi, bigint_maxwords shl 2
	ja	.got_kexgexreply_rsasigkakked
	
	mov	rdx, rsi
	mov	rsi, rdi
	mov	rdi, r14
	call	bigint$set_encoded
if sshdebug
	mov	rdi, .rsasig
	call	string$to_stdoutln
	mov	rdi, r14
	call	bigint$debug
end if
	
	mov	rdi, [r13+bigint_monty_powmod_ofs]
	mov	rsi, r13
	mov	rdx, r14
	call	monty$doit

if sshdebug
	mov	rdi, .rsasigmsg
	call	string$to_stdoutln
	mov	rdi, r13
	call	bigint$debug
end if

	; ok so, at this point, we should have our PKCS padded result sitting in r13
	; next up, we need to calculate our own signature, then compare to the beginning of our bigint_words_ofs
	; get a sha160 happening of our H
	sub	rsp, sha160_state_size + 32
	mov	rdi, rsp
	call	sha160$init
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_hash_ofs]
	mov	edx, 32
	call	sha160$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx				; don't attempt to free the state
	call	sha160$final

if sshdebug
	mov	rdi, .rsaourhash
	call	string$to_stdoutln
	lea	rdi, [rsp+sha160_state_size]
	mov	esi, 20
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	; so, our bigint result is in little endian format, and our sha160 final is in "big endian"
	; so either we encode the result of the r13 signature verify, or we reverse our sha160 hash
	; reversing seems like a better plan
	lea	rdi, [rsp+sha160_state_size]
	mov	esi, 20
	call	memreverse

	; so now, we can compare the result
	mov	rdi, [r13+bigint_words_ofs]
	lea	rsi, [rsp+sha160_state_size]
	mov	edx, 20					; sha1 hash size
	call	memcmp
	add	rsp, sha160_state_size + 32
	
	test	eax, eax
	jnz	.got_kexgexreply_rsasigkakked		; mismatch, bailout
	
	; otherwise, signature verified, proceed
	mov	rdi, r13
	call	bigint$destroy
	mov	rdi, r14
	call	bigint$destroy

	pop	rcx
	pop	rdi

if sshdebug
	mov	rdi, .sigok
	call	string$to_stdoutln
end if
	jmp	.got_kexgexreply_doservicerequest

if sshdebug
cleartext .rsasige, 'RSA public exponent:'
cleartext .rsasign, 'RSA public modulus:'
cleartext .rsasig, 'RSA Signature s:'
cleartext .rsasigmsg, 'RSA Signature Verification (little endian):'
cleartext .rsaourhash, 'Our SHA160 of the hash H (big endian):' 
cleartext .sigok, 'Signature Verified'
cleartext .dsasigr, 'DSA Signature r:'
cleartext .dsasigs, 'DSA Signature s:'
cleartext .dsapubp, 'DSA Public p:'
cleartext .dsapubq, 'DSA Public q:'
cleartext .dsapubg, 'DSA Public g:'
cleartext .dsapuby, 'DSA Public y:'
cleartext .dsaw, 'DSA verification w:'
cleartext .dsau1, 'DSA verification u1:'
cleartext .dsau2, 'DSA verification u2:'
cleartext .dsav, 'DSA verification v:'
end if
calign
.got_kexgexreply_dss_sig:

	mov	rdi, [rsp+8]
if use_movbe
	movbe	eax, [rdi]
else
	mov	eax, [rdi]
	bswap	eax			; sigblob overall length
end if

	cmp	eax, 55					; 4 for blob length prefix, 4 for string type preface, 7 for string type, 20 for r, 20 for s
	jne	.got_kexgexreply_keysigmismatch

	mov	eax, [rsp]
	cmp	eax, 59					; +4 more on top of 55 for the # of bytes that were left in our buffer
	jne	.got_kexgexreply_keysigmismatch		; no trailing bytes are permitted

	; so, r12 is our dss public key (preface), r13 is our dss public key length
	; the pubkey begins at r12+11
	; parse r and s and place into [rsp] and [rsp+8] respectively
	mov	rdi, [rsp+8]
	add	rdi, 19
	mov	esi, 20
	call	bigint$new_encoded
	mov	[rsp], rax
	mov	rdi, [rsp+8]
	add	rdi, 39
	mov	esi, 20
	call	bigint$new_encoded
	mov	[rsp+8], rax
	; r == [rsp]
	; s == [rsp+8]

if sshdebug
	mov	rdi, .dsasigr
	call	string$to_stdoutln
	mov	rdi, [rsp]
	call	bigint$debug
	mov	rdi, .dsasigs
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	call	bigint$debug
end if
	; next up, we need to parse out our dsa public key goods, we'll need one extra bigint + the four provided in the dsakey
	sub	rsp, 48
	; so now, [rsp+48] == r
	;         [rsp+56] == s
	call	bigint$new
	mov	[rsp], rax
	call	bigint$new
	mov	[rsp+8], rax
	call	bigint$new
	mov	[rsp+16], rax
	call	bigint$new
	mov	[rsp+24], rax
	call	bigint$new
	mov	[rsp+32], rax
	mov	edi, 65537
	call	bigint$new_unsigned
	mov	[rsp+40], rax
	; that way cleanup doesn't need ot check every one

	; r13 must be at the very least 100 bytes or so (though really, much longer, and we should reject them entirely if they are too small)
	cmp	r13, 100
	jb	.got_kexgexreply_dsasigbad
	; p begins at [r12+11]
	add	r12, 11
	sub	r13, 11
if use_movbe
	movbe	eax, [r12]
else
	mov	eax, [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	jae	.got_kexgexreply_dsasigbad
	; otehrwise, we can compose bigint p
	mov	rdi, [rsp]
	mov	rsi, r12
	mov	edx, eax
	
	; sanity to make sure the length isn't insane
	cmp	eax, bigint_maxwords shl 2
	ja	.got_kexgexreply_dsasigbad

	; skop over this one before we move on
	add	r12, rax
	sub	r13, rax
	call	bigint$set_encoded
	; trim any leading zeroes
	mov	rdi, [rsp]
	call	bigint$tlz
	cmp	r13, 4
	jb	.got_kexgexreply_dsasigbad
if use_movbe
	movbe	eax, [r12]
else
	mov	eax, [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	jae	.got_kexgexreply_dsasigbad
	; otherwise, we can compose bigint q
	mov	rdi, [rsp+8]
	mov	rsi, r12
	mov	edx, eax

	; sanity to make sure the length isn't insane
	cmp	eax, bigint_maxwords shl 2
	ja	.got_kexgexreply_dsasigbad

	; skip over this one before we move on
	add	r12, rax
	sub	r13, rax
	call	bigint$set_encoded
	; trim any leading zeroes
	mov	rdi, [rsp+8]
	call	bigint$tlz
	cmp	r13, 4
	jb	.got_kexgexreply_dsasigbad
if use_movbe
	movbe	eax, [r12]
else
	mov	eax, [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	jae	.got_kexgexreply_dsasigbad
	; otherwise, we can compose bigint g
	mov	rdi, [rsp+16]
	mov	rsi, r12
	mov	edx, eax
	
	; sanity to make sure the length isn't insane
	cmp	eax, bigint_maxwords shl 2
	ja	.got_kexgexreply_dsasigbad

	; skip over this one before we move on
	add	r12, rax
	sub	r13, rax
	call	bigint$set_encoded
	; trim any leading zeroes
	mov	rdi, [rsp+16]
	call	bigint$tlz
	cmp	r13, 4
	jb	.got_kexgexreply_dsasigbad
if use_movbe
	movbe	eax, [r12]
else
	mov	eax, [r12]
	bswap	eax
end if
	add	r12, 4
	sub	r13, 4
	cmp	rax, r13
	ja	.got_kexgexreply_dsasigbad
	; otherwise, we can compose bigint y
	mov	rdi, [rsp+24]
	mov	rsi, r12
	mov	edx, eax

	; sanity to make sure the length isn't insane
	cmp	eax, bigint_maxwords shl 2
	ja	.got_kexgexreply_dsasigbad

	call	bigint$set_encoded
	; trim any leading zeroes
	mov	rdi, [rsp+24]
	call	bigint$tlz

if sshdebug
	mov	rdi, .dsapubp
	call	string$to_stdoutln
	mov	rdi, [rsp]
	call	bigint$debug
	mov	rdi, .dsapubq
	call	string$to_stdoutln
	mov	rdi, [rsp+8]
	call	bigint$debug
	mov	rdi, .dsapubg
	call	string$to_stdoutln
	mov	rdi, [rsp+16]
	call	bigint$debug
	mov	rdi, .dsapuby
	call	string$to_stdoutln
	mov	rdi, [rsp+24]
	call	bigint$debug
end if

	; next up, reject the signature if r is zero, s is zero, or r >= q, or s >= q
	mov	rdi, [rsp+48]
	call	bigint$is_zero
	test	eax, eax
	jnz	.got_kexgexreply_dsasigbad
	mov	rdi, [rsp+56]
	call	bigint$is_zero
	test	eax, eax
	jnz	.got_kexgexreply_dsasigbad
	mov	rdi, [rsp+48]
	mov	rsi, [rsp+8]
	call	bigint$compare
	cmp	eax, 0
	jge	.got_kexgexreply_dsasigbad
	mov	rdi, [rsp+56]
	mov	rsi, [rsp+8]
	call	bigint$compare
	cmp	eax, 0
	jge	.got_kexgexreply_dsasigbad
	
	; next up: w = inversemod s, q, inversemod needs a separate destination, place into rsp+32
	mov	rdi, [rsp+32]
	mov	rsi, [rsp+56]			; s
	mov	rdx, [rsp+8]			; q
	call	bigint$inversemod

if sshdebug
	mov	rdi, .dsaw
	call	string$to_stdoutln
	mov	rdi, [rsp+32]
	call	bigint$debug
end if

	; u1 = (H(m) * w) mod q

	; calculate our hash next
	; get a sha160 happening of our H
	sub	rsp, sha160_state_size + 32
	mov	rdi, rsp
	call	sha160$init
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_hash_ofs]
	mov	edx, 32
	call	sha160$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx			; don't attempt to free the state
	call	sha160$final

	; we no longer need s, which is now at [rsp+56+32]
	mov	rdi, [rsp+56+32+sha160_state_size]
	lea	rsi, [rsp+sha160_state_size]
	mov	edx, 20
	call	bigint$set_encoded
	add	rsp, sha160_state_size + 32

	; so now, [rsp+56] == H(m), multiply that by w, which is in [rsp+32]
	mov	rdi, [rsp+56]
	mov	rsi, [rsp+32]
	call	bigint$multiply
	; now mod the result by q
	mov	rdi, [rsp+56]			; u1
	mov	rsi, [rsp+8]			; q
	call	bigint$modby

if sshdebug
	mov	rdi, .dsau1
	call	string$to_stdoutln
	mov	rdi, [rsp+56]
	call	bigint$debug
end if
	; so at this stage:
	; [rsp] == p
	; [rsp+8] == q
	; [rsp+16] == g
	; [rsp+24] == y
	; [rsp+32] == w
	; [rsp+40] == unused
	; [rsp+48] == r
	; [rsp+56] == u1

	; u2 = (r * w) mod q
	mov	rdi, [rsp+40]			; u2
	mov	rsi, [rsp+48]			; r
	mov	rdx, [rsp+32]			; w
	call	bigint$multiply_into
	mov	rdi, [rsp+40]
	mov	rsi, [rsp+8]
	call	bigint$modby

if sshdebug
	mov	rdi, .dsau2
	call	string$to_stdoutln
	mov	rdi, [rsp+40]
	call	bigint$debug
end if

	; [rsp+56] == u1
	; [rsp+40] == u2
	mov	rdi, [rsp+56]			; u1 == exponent for monty powmod
	mov	rsi, [rsp]			; modulus == p for monty powmod
	call	monty$new
	mov	rdi, [rsp]
	mov	[rdi+bigint_monty_powmod_ofs], rax	; save the monty powmod object so it'll get cleaned up later
	mov	rdi, rax
	mov	rsi, [rsp+56]			; u1 == destination for monty powmod
	mov	rdx, [rsp+16]			; g == source for monty powmod
	call	monty$doit

	; do the same for y**u2 mod p
	mov	rdi, [rsp]
	mov	rdi, [rdi+bigint_monty_powmod_ofs]
	mov	rsi, [rsp+40]			; u2 == exponent for monty powmod
	mov	rdx, [rsp]			; modulus == p for monty powmod
	call	monty$reinit
	mov	rdi, [rsp]
	mov	rdi, [rdi+bigint_monty_powmod_ofs]
	mov	rsi, [rsp+40]			; u2 == destination for monty powmod
	mov	rdx, [rsp+24]			; y == source for monty powmod
	call	monty$doit

	; now we need to multiply both those together, then mod by p
	mov	rdi, [rsp+40]			; u2 == source/dest for multiply
	mov	rsi, [rsp+56]			; u1 == mutliplier
	call	bigint$multiply
	mov	rdi, [rsp+40]
	mov	rsi, [rsp]			; mod by p
	call	bigint$modby

	; and finally, mod that by q
	mov	rdi, [rsp+40]
	mov	rsi, [rsp+8]
	call	bigint$modby

if sshdebug
	mov	rdi, .dsav
	call	string$to_stdoutln
	mov	rdi, [rsp+40]
	call	bigint$debug
end if

	; so now, if [rsp+40] != [rsp+48], sigs don't match, die a thousand deaths
	mov	rdi, [rsp+40]
	mov	rsi, [rsp+48]
	call	bigint$compare
	test	eax, eax
	jnz	.got_kexgexreply_dsasigbad

	; otherwise, cleanup our goods, and proceed
	mov	rdi, [rsp]
	call	bigint$destroy
	mov	rdi, [rsp+8]
	call	bigint$destroy
	mov	rdi, [rsp+16]
	call	bigint$destroy
	mov	rdi, [rsp+24]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	mov	rdi, [rsp+40]
	call	bigint$destroy
	mov	rdi, [rsp+48]
	call	bigint$destroy
	mov	rdi, [rsp+56]
	call	bigint$destroy
	add	rsp, 64

if sshdebug
	mov	rdi, .sigok
	call	string$to_stdoutln
end if
	jmp	.got_kexgexreply_doservicerequest

calign
.got_kexgexreply_dsasigbad:
	; we have 64 bytes on the stack that are all bigints, kill em
	mov	rdi, [rsp]
	call	bigint$destroy
	mov	rdi, [rsp+8]
	call	bigint$destroy
	mov	rdi, [rsp+16]
	call	bigint$destroy
	mov	rdi, [rsp+24]
	call	bigint$destroy
	mov	rdi, [rsp+32]
	call	bigint$destroy
	mov	rdi, [rsp+40]
	call	bigint$destroy
	mov	rdi, [rsp+48]
	call	bigint$destroy
	mov	rdi, [rsp+56]
	call	bigint$destroy
	add	rsp, 64
	pop	r14 r13 r12
	jmp	.badlength			; die a thousand deaths
calign
.got_kexgexreply_rsasigkakked:
	mov	rdi, r13
	call	bigint$destroy
	mov	rdi, r14
	call	bigint$destroy
	jmp	.got_kexgexreply_keysigmismatch
calign
.got_kexgexreply_doservicerequest:
	; so now, since we are in client mode, we need to request a service
	mov	rdi, rbx
	mov	esi, 5				; SSH_MSG_SERVICE_REQUEST
	mov	rdx, .client_servicename
	mov	ecx, .client_servicename_len
	call	ssh$encrypt

	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantnewkeys		; we need the other side's newkeys next

	pop	r14 r13 r12

	; we are done with our dh values
	call	.dhclear
	
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_kexgexreply_keysigmismatch:
	pop	rcx rdi
	pop	r14 r13 r12
	jmp	.badlength			; die die die
dalign
.client_servicename:
	db	0, 0, 0, 0xc
	db	'ssh-userauth'
.client_servicename_len = $ - .client_servicename
calign
.got_kexgexreply_badlength:
	pop	r14 r13 r12
	jmp	.badlength
calign
.got_kexgexreply_bad_dh:
	add	rsp, 16
	pop	r14 r13 r12
	jmp	.badlength
calign
.got_kexgexgroup:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexgroup
	jne	.badlength			; die die die
	; packetbuf contains our SSH_MSG_KEX_DH_GEX_GROUP message, which has our DH p and g
	; each are 4 byte length prefixed, big endian encoded like always
	mov	rdx, [rbx+ssh_packetbuf_ofs]
	mov	rcx, [rdx+buffer_length_ofs]
	cmp	rcx, 265
	jb	.badlength			; our absolute minimum message size
	mov	rdi, [rdx+buffer_itself_ofs]
if use_movbe
	movbe	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
else
	mov	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
	bswap	esi
end if
	; sanity to make sure the length isn't insane
	cmp	esi, bigint_maxwords shl 2
	ja	.badlength			; die die die
	cmp	esi, ecx
	jae	.badlength
	push	rdi
	add	[rsp], rsi
	push	rcx
	call	bigint$new_encoded
	mov	[rbx+ssh_dh_p_ofs], rax
	pop	rcx
	pop	rdi
if use_movbe
	movbe	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
else
	mov	esi, dword [rdi]
	add	rdi, 4
	sub	rcx, 4
	bswap	esi
end if
	; g should be very small, _but_, it is permissible to use DSA parameters for DH as well
	; so instead of forcing g to be small, we will allow same-size g size checking
	cmp	esi, bigint_maxwords shl 2
	ja	.badlength
	test	esi, esi
	jz	.badlength
	cmp	esi, ecx
	ja	.badlength
	call	bigint$new_encoded
	mov	[rbx+ssh_dh_g_ofs], rax
	; openssh 6.2 is sending leading zeroes ... this causes unnecessary sizing bloats, but the bigint$new_encoded
	; trims them for us by default

if sshdebug
	mov	rdi, .dhpmsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_dh_p_ofs]
	call	bigint$debug
	mov	rdi, .dhgmsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_dh_g_ofs]
	call	bigint$debug
end if
	; we need to compose/send off our public dh e
	; so, we need to generate our dh private, then compose e and send it off

	push	r12
	call	bigint$new
	mov	[rbx+ssh_dh_private_ofs], rax
	call	bigint$new
	mov	r12, rax
calign
.got_kexgexgroup_dh_random:
	mov	rdi, [rbx+ssh_dh_private_ofs]
	mov	esi, dh_privatekey_size	; dh_privatekey_size determines how big or DH private "key" is
	call	bigint$set_random
					; we only need ot hangon to dh_private until we receive the gexreply

if sshdebug
	mov	rdi, .dhprivatemsg
	call	string$to_stdoutln
	mov	rdi, [rbx+ssh_dh_private_ofs]
	call	bigint$debug
end if

	; now we need g**private mod p, in a temporary bigint
	mov	rdi, [rbx+ssh_dh_private_ofs]	; exponent
	mov	rsi, [rbx+ssh_dh_p_ofs]		; modulus
	call	monty$new
	mov	[r12+bigint_monty_powmod_ofs], rax
	mov	rdi, rax
	mov	rsi, r12			; destination for powmod
	mov	rdx, [rbx+ssh_dh_g_ofs]		; source for powmod
	call	monty$doit
	; destroy the monty object in case we need to go back around
	mov	rdi, [r12+bigint_monty_powmod_ofs]
	mov	qword [r12+bigint_monty_powmod_ofs], 0
	call	monty$destroy_clear
	; make sure we didn't inadvertently end up with a 1 or 0
	mov	rdi, r12
	mov	rsi, bigint$one
	call	bigint$compare
	cmp	eax, 0
	jle	.got_kexgexgroup_dh_random

if sshdebug
	mov	rdi, .dhemsg
	call	string$to_stdoutln
	mov	rdi, r12
	call	bigint$debug
end if

	; so now r12 contains the result of g**private mod p
	; save it in our dh_e_ofs so we can use it to calculate our H later
	mov	[rbx+ssh_dh_e_ofs], r12
	sub	rsp, 4096			; plenty of space for our outgoing
	mov	rdi, r12
	lea	rsi, [rsp+4]
	call	bigint$ssh_encode
	mov	ecx, eax
if use_movbe
	movbe	dword [rsp], eax
else
	bswap	eax
	mov	dword [rsp], eax
end if
	add	ecx, 4

	; our SSH_MSG_KEX_DH_INIT is ready to roll
	mov	rdi, rbx
	mov	esi, 32				; SSH_MSG_KEX_DH_GEX_INIT
	mov	rdx, rsp
	; ecx is still valid from above for # of bytes we are sending
	call	ssh$encrypt
	
	add	rsp, 4096

	; we do not cleanup our public e value here yet, because we need it for the next H calc
	pop	r12
	
	; so now, update our stage indicating that we want a gexreply... there *shouldn't* be any more
	; data waiting for us, but we'll reset and go back to the top anyway
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexgexreply
	
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_kexinit_interactive:
	; so we already have a session running, our peer wants to rekey
	; we need to clear our 
	mov	rdi, [rbx+ssh_remotekexinit_ofs]
	call	buffer$reset
	mov	rdi, [rbx+ssh_localkexinit_ofs]
	call	buffer$reset
	jmp	.got_kexinit_doit
calign
.got_kexinit:
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	je	.got_kexinit_interactive
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexinit
	jne	.badlength			; die die die
calign
.got_kexinit_doit:
	; we need ot include the 0x14 (20) SSH_KEX_INIT byte
	mov	rdi, [rbx+ssh_remotekexinit_ofs]
	mov	esi, 0x14
	call	buffer$append_byte
	; we need to copy the contents of the packetbuf into the remotekexinit buffer
	mov	rcx, [rbx+ssh_packetbuf_ofs]
	mov	rdi, [rbx+ssh_remotekexinit_ofs]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	buffer$append
	; so, if we supported multiple algorithms/etc, then we'd of course be forced to actually parse this
	; as it stands, since we support precisely one, whether we are the client _or_ server
	; we can safely assume that they were agreed upon, because the RFC says specifically that both sides
	; must disconnect if agreement can't be reached, and if a malicious client/server wants to play
	; silly-buggers with us, well, subsequent packets will fail miserably anyway
	; the one exception to this of course is the compression method selection, which depending on our peer
	; might be none, zlib@openssh.com, or zlib
	; we check this only if ssh_do_compression is enabled (cuz otherwise it will be disabled indefinitely anyway)
if ssh_do_compression
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	je	.got_kexinit_nocomp			; don't modify the compression setting if it is already enabled
	mov	rcx, [rbx+ssh_packetbuf_ofs]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	cmp	rdx, 32			; sanity only
	jb	.got_kexinit_nocomp
	sub	rdx, 4
if ssh_force_compression
calign
.got_kexinit_compsearch:
	cmp	dword [rsi], 'zlib'
	je	.got_kexinit_compfound
	add	rsi, 1
	sub	rdx, 1
	jnz	.got_kexinit_compsearch
	jmp	.got_kexinit_nocomp
else
calign
.got_kexinit_compsearch:
	cmp	dword [rsi], 'ne,z'			; if we find none,zli first, don't enable compression
	je	.got_kexinit_nocomp
	cmp	dword [rsi], 'zlib'
	je	.got_kexinit_compfound
	add	rsi, 1
	sub	rdx, 1
	jnz	.got_kexinit_compsearch
	jmp	.got_kexinit_nocomp
end if
calign
.got_kexinit_compfound:
	mov	eax, 3
	mov	ecx, 1
	cmp	dword [rsi+4], '@ope'
	cmove	eax, ecx
	mov	dword [rbx+ssh_compstate_ofs], eax
calign
.got_kexinit_nocomp:

end if
	; update our stage
	mov	ecx, ssh_stage_wantkexgexreq
	mov	edx, ssh_stage_wantkexgexgroup
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmovne	ecx, edx
	mov	[rbx+ssh_stage_ofs], ecx
	; if we are a client, we need to send off the gexreq
	; if we are a server, we expect to receive a gexreq next
	je	.got_kexinit_server
	; compose our SSH_MSG_KEY_DH_GEX_REQUEST and send it off
	sub	rsp, 16
	mov	eax, 2048
	mov	ecx, 4096
	mov	edx, 16384
	mov	[rbx+ssh_dh_min_ofs], eax
	mov	[rbx+ssh_dh_n_ofs], ecx
	mov	[rbx+ssh_dh_max_ofs], edx
if use_movbe
	movbe	dword [rsp], eax
	movbe	dword [rsp+4], ecx
	movbe	dword [rsp+8], edx
else
	bswap	eax
	bswap	ecx
	bswap	edx
	mov	dword [rsp], eax
	mov	dword [rsp+4], ecx
	mov	dword [rsp+8], edx
end if
	mov	rdi, rbx
	mov	esi, 34						; SSH_MSG_KEX_DH_GEX_REQUEST
	mov	rdx, rsp
	mov	ecx, 12
	call	ssh$encrypt					; send off our gex request
	add	rsp, 16

	; if we are a client, bailout
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.got_kexinit_server:
	; we need to send back our kexinit
	; next up, compose our kexinit, noting here we have to hangon to this message
	; determine the length of the kexinit message, which will be one of two possibilities (three real, but two are same length)
	mov	rdi, [rbx+ssh_localcert_ofs]

	xor	eax, eax
	xor	ecx, ecx
	mov	edx, 1
	cmp	qword [rdi+X509_privatekey_ofs], 0
	cmovne	eax, edx
	cmp	qword [rdi+X509_dsaprivatekey_ofs], 0
	cmovne	ecx, edx
	and	eax, ecx
	mov	esi, ssh_kexinit_both_len + ssh_kexinit_len + 17
	mov	edx, ssh_kexinit_rsa_len + ssh_kexinit_len + 17
	mov	ecx, ssh_kexinit_both_len
	mov	r8d, ssh_kexinit_rsa_len
	mov	r9, ssh_kexinit_both
	mov	r10, ssh_kexinit_rsa
	mov	r11, ssh_kexinit_dsa
	test	eax, eax
	cmovz	esi, edx
	cmovz	ecx, r8d
	mov	rdi, [rbx+ssh_localkexinit_ofs]
	mov	dword [rdi+buffer_user_ofs], esi		; total length
	mov	dword [rdi+buffer_user_ofs+4], ecx		; just the first length
	mov	qword [rdi+buffer_user_ofs+8], r9		; first pointer
	jnz	.got_kexinit_server_bothset
	mov	rsi, [rbx+ssh_localcert_ofs]
	cmp	qword [rsi+X509_privatekey_ofs], 0
	cmove	r10, r11
	mov	qword [rdi+buffer_user_ofs+8], r10
calign
.got_kexinit_server_bothset:

	mov	esi, [rdi+buffer_user_ofs]
	call	buffer$reserve
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	mov	rdi, [rcx+buffer_itself_ofs]
	mov	esi, 24
	call	rng$block					; stick 24 bytes of random in the head of the buffer
	mov	rax, [rbx+ssh_localkexinit_ofs]
	mov	ecx, [rax+buffer_user_ofs]
	mov	edx, [rax+buffer_user_ofs+4]
	mov	rsi, [rax+buffer_user_ofs+8]
	mov	rdi, [rax+buffer_itself_ofs]
	mov	byte [rdi], 20					; SSH_MSG_KEXINIT
	add	qword [rax+buffer_endptr_ofs], rcx
	add	qword [rax+buffer_length_ofs], rcx
	add	rdi, 17
	call	memcpy
	; next for the common bit
	mov	rax, [rbx+ssh_localkexinit_ofs]
	mov	ecx, [rax+buffer_user_ofs+4]
	mov	rdi, [rax+buffer_itself_ofs]
	mov	rsi, ssh_kexinit
	add	ecx, 17
	mov	edx, ssh_kexinit_len
	add	rdi, rcx
	call	memcpy

	mov	rax, [rbx+ssh_localkexinit_ofs]
	mov	rdi, rbx
	mov	esi, 20						; SSH_MSG_KEXINIT
	mov	rdx, [rax+buffer_itself_ofs]
	mov	ecx, [rax+buffer_user_ofs]
	sub	ecx, 1
	add	rdx, 1
	call	ssh$encrypt					; send off the kexinit

	; we are expecting a kexgexreq next, our stage already reflects this
	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.badlength:
	; call our error method, since when we return 1 for suicide, epoll won't call it for us
	cmp	dword [rbx+ssh_stage_ofs], ssh_stage_interactive
	jne	.badlength_skipnotify
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+io_verror]
calign
.badlength_skipnotify:
	pop	rbx
	mov	eax, 1				; die die die
	epilog
calign
.appsuicide:
	; same as above, only we don't call verror, and we send out the "clean ssh shutdown messages along with it"
	mov	eax, [rbx+ssh_channelid_ofs]
	sub	rsp, 8
	mov	rdi, rbx
	mov	esi, 96			; SSH_MSG_CHANNEL_EOF
	mov	rdx, rsp
	mov	[rsp], eax
	mov	ecx, 4
	call	ssh$encrypt
	mov	eax, [rbx+ssh_channelid_ofs]
	mov	rdi, rbx
	mov	esi, 97			; SSH_MSG_CHANNEL_CLOSE
	mov	rdx, rsp
	mov	[rsp], eax
	mov	ecx, 4
	call	ssh$encrypt
	add	rsp, 8

	; now, if we immediately close the connection, then we get weird ssh termination messages, so lets try letting the client do it
	; this behaviour indeed seems to make all my ssh clients play nice... but I think we get a subsequent error when it closes down
	; hmmm TODO: think about this some more

	; reset our packetbuf
	mov	rdi, [rbx+ssh_packetbuf_ofs]
	call	buffer$reset
	; reset peeklen to 0 and go back to the top
	mov	dword [rbx+ssh_peeklen_ofs], 0
	jmp	.loop
calign
.silent_suicide:
	; same as above, only we don't call verror
	pop	rbx
	mov	eax, 1				; die die die
	epilog
calign
.ident:
	; read/consume the remote ident, and depending on whether we are a client/server, get our kex underway
	; save the remote ident for use later
	; we don't actually care what the ident is, though it _must_ start with a SSH-2
	cmp	dword [rsi], 'SSH-'
	jne	.badident
	cmp	byte [rsi+4], '2'
	jne	.badident
	; otherwise, we'll add and consume up to the CRLF
	mov	ecx, 4
	mov	r8d, edx
	sub	r8d, 4
	jz	.badident
calign
.ident_findcrlf:
	add	ecx, 1
	sub	r8d, 1
	jz	.badident
	cmp	byte [rsi+rcx], 13
	jne	.ident_findcrlf
	cmp	byte [rsi+rcx+1], 10
	jne	.ident_findcrlf
	
	lea	r9, [rsi+rcx+2]
	mov	r10d, edx
	sub	r10d, ecx
	sub	r10d, 2
	push	r9 r10
	mov	rdi, [rbx+ssh_remoteident_ofs]
	mov	edx, ecx
	call	buffer$append
	; ok so, we saved remoteident, now restore rsi/rdx with our updated goods
	pop	rdx rsi
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.ident_client
	; we are in server mode, we expect to receive the client's kexinit first up
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexinit
	; append whatever we got to the accbuf first up:
	mov	rdi, [rbx+ssh_accbuf_ofs]
	call	buffer$append
	; cruise back to the loop to see if we already got it
	jmp	.loop
calign
.ident_client:
	; client mode, send our ident and our initial kex, and our SSH_MSG_KEY_DH_GEX_REQUEST
	; we received the ident, but there should be no more data waiting (none of my ssh servers in the wild send ident+kexinit straight out of the gate)
	; send our ident first up:
	mov	rdi, [rbx+io_child_ofs]
	mov	rsi, ssh_ident
	mov	edx, ssh_ident_len
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]
	; next up, compose our kexinit, noting here we have to hangon to this message
	mov	rdi, [rbx+ssh_localkexinit_ofs]
	mov	esi, ssh_kexinit_both_len + ssh_kexinit_len + 17
	call	buffer$reserve
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	mov	rdi, [rcx+buffer_itself_ofs]
	mov	esi, 24
	call	rng$block					; stick 24 bytes of random in the head of the buffer
	mov	rax, [rbx+ssh_localkexinit_ofs]
	mov	rdi, [rax+buffer_itself_ofs]
	mov	byte [rdi], 20					; SSH_MSG_KEXINIT
	add	qword [rax+buffer_endptr_ofs], ssh_kexinit_both_len + ssh_kexinit_len + 17
	add	qword [rax+buffer_length_ofs], ssh_kexinit_both_len + ssh_kexinit_len + 17
	add	rdi, 17
	mov	rsi, ssh_kexinit_both
	mov	edx, ssh_kexinit_both_len
	call	memcpy
	; common bit next
	mov	rax, [rbx+ssh_localkexinit_ofs]
	mov	rdi, [rax+buffer_itself_ofs]
	add	rdi, 17 + ssh_kexinit_both_len
	mov	rsi, ssh_kexinit
	mov	edx, ssh_kexinit_len
	call	memcpy
	mov	rax, [rbx+ssh_localkexinit_ofs]
	mov	rdi, rbx
	mov	esi, 20						; SSH_MSG_KEXINIT
	mov	rdx, [rax+buffer_itself_ofs]
	mov	ecx, ssh_kexinit_both_len + ssh_kexinit_len + 16
	add	rdx, 1
	call	ssh$encrypt					; send off the kexinit

	; update our stage since we are expecting a kexinit back
	mov	dword [rbx+ssh_stage_ofs], ssh_stage_wantkexinit
	pop	rbx
	xor	eax, eax			; don't kill us off
	epilog
calign
.badident:
	; we could be nice and send a protocol error back
	; call our error method, since when we return 1 for suicide, epoll won't call it for us
	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+io_verror]
	pop	rbx
	mov	eax, 1				; die die die
	epilog
calign
.dhclear:
	; nonstandard call, rbx == our ssh object, we are done with all our dh values
	mov	rdi, [rbx+ssh_dh_p_ofs]
	mov	qword [rbx+ssh_dh_p_ofs], 0
	call	bigint$destroy
	mov	rdi, [rbx+ssh_dh_g_ofs]
	mov	qword [rbx+ssh_dh_g_ofs], 0
	call	bigint$destroy
	mov	rdi, [rbx+ssh_dh_private_ofs]
	mov	qword [rbx+ssh_dh_private_ofs], 0
	call	bigint$destroy_clear
	mov	rdi, [rbx+ssh_dh_e_ofs]
	mov	qword [rbx+ssh_dh_e_ofs], 0
	call	bigint$destroy
	mov	rdi, [rbx+ssh_dh_f_ofs]
	mov	qword [rbx+ssh_dh_f_ofs], 0
	call	bigint$destroy
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	mov	qword [rbx+ssh_dh_shared_ofs], 0
	call	bigint$destroy_clear
	ret
calign
.keycalc:
	; nonstandard call, rbx == our ssh object all dh exchange is complete
	; further, r12 _must_ be pointing at our host key blob, r13 its length
	; and all our values are ready to calculate H and derive our pending keys
	; 
	; we'll use a 16kb stackframe to do the calculation
	sub	rsp, 16384
	mov	rdi, rsp
	call	sha256$init
	; depending on whether we are in client or server mode, depends on which order we do them
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	jne	.keycalc_client
	; else, we are a server
	; remote ident
	mov	rcx, [rbx+ssh_remoteident_ofs]
	mov	eax, [rcx+buffer_length_ofs]
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, [rcx+buffer_itself_ofs]
	call	memcpy
	mov	rcx, [rbx+ssh_remoteident_ofs]
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rcx+buffer_length_ofs]
	add	edx, 4
	call	sha256$update
	; ssh_ident / ssh_ident_len, encoded
	lea	rdi, [rsp+sha256_state_size]
	mov	eax, ssh_ident_len - 2
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, ssh_ident
	mov	edx, ssh_ident_len - 2
	call	memcpy
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, ssh_ident_len + 2
	call	sha256$update
	; remote length-prefixed encoded kexinit payload
	mov	rcx, [rbx+ssh_remotekexinit_ofs]
	mov	eax, [rcx+buffer_length_ofs]
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, [rcx+buffer_itself_ofs]
	call	memcpy
	mov	rcx, [rbx+ssh_remotekexinit_ofs]
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rcx+buffer_length_ofs]
	add	edx, 4
	call	sha256$update
	; our length-prefixed encoded kexinit payload
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	mov	eax, [rcx+buffer_length_ofs]
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, [rcx+buffer_itself_ofs]
	call	memcpy
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rcx+buffer_length_ofs]
	add	edx, 4
	call	sha256$update
	; next up: length prefixed host key blob, length is in r13, buffer in r12
	lea	rdi, [rsp+sha256_state_size]
	mov	eax, r13d
	mov	edx, r13d
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, r12
	call	memcpy
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, r13d
	add	edx, 4
	call	sha256$update
	; uint32 min, n, max
	lea	rdi, [rsp+sha256_state_size]
	cmp	dword [rbx+ssh_dh_min_ofs], -1
	je	.keycalc_oldgex
	mov	eax, [rbx+ssh_dh_min_ofs]
	mov	ecx, [rbx+ssh_dh_n_ofs]
	mov	edx, [rbx+ssh_dh_max_ofs]
if use_movbe
	movbe	[rdi], eax
	movbe	[rdi+4], ecx
	movbe	[rdi+8], edx
else
	bswap	eax
	bswap	ecx
	bswap	edx
	mov	[rdi], eax
	mov	[rdi+4], ecx
	mov	[rdi+8], edx
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 12
	call	sha256$update
	jmp	.keycalc_gexskip
calign
.keycalc_oldgex:
	mov	eax, [rbx+ssh_dh_n_ofs]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 4
	call	sha256$update
calign
.keycalc_gexskip:
	; encoded dh_p
	mov	rdi, [rbx+ssh_dh_p_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_g
	mov	rdi, [rbx+ssh_dh_g_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_e
	mov	rdi, [rbx+ssh_dh_e_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_f
	mov	rdi, [rbx+ssh_dh_f_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_shared
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_hash_ofs]
	xor	edx, edx			; don't attempt to free the state
	call	sha256$final
	jmp	.keycalc_hashdone
calign
.keycalc_client:
	; first up, ssh_ident / ssh_ident_len, encoded
	lea	rdi, [rsp+sha256_state_size]
	mov	eax, ssh_ident_len - 2
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, ssh_ident
	mov	edx, ssh_ident_len - 2
	call	memcpy

if sshdebug
	mov	rdi, .hashinputmsg
	call	string$to_stdoutln
	lea	rdi, [rsp+sha256_state_size]
	mov	esi, ssh_ident_len + 2
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, ssh_ident_len + 2
	call	sha256$update
	; next up, remote ident
	mov	rcx, [rbx+ssh_remoteident_ofs]
	mov	eax, [rcx+buffer_length_ofs]
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, [rcx+buffer_itself_ofs]
	call	memcpy
if sshdebug
	mov	rcx, [rbx+ssh_remoteident_ofs]
	lea	rdi, [rsp+sha256_state_size]
	mov	esi, [rcx+buffer_length_ofs]
	add	esi, 4
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	mov	rcx, [rbx+ssh_remoteident_ofs]
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rcx+buffer_length_ofs]
	add	edx, 4
	call	sha256$update
	; our length-prefixed encoded kexinit payload
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	mov	eax, [rcx+buffer_length_ofs]
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, [rcx+buffer_itself_ofs]
	call	memcpy
if sshdebug
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	lea	rdi, [rsp+sha256_state_size]
	mov	esi, [rcx+buffer_length_ofs]
	add	esi, 4
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	mov	rcx, [rbx+ssh_localkexinit_ofs]
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rcx+buffer_length_ofs]
	add	edx, 4
	call	sha256$update
	; remote length-prefixed encoded kexinit payload
	mov	rcx, [rbx+ssh_remotekexinit_ofs]
	mov	eax, [rcx+buffer_length_ofs]
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, [rcx+buffer_itself_ofs]
	call	memcpy
if sshdebug
	mov	rcx, [rbx+ssh_remotekexinit_ofs]
	lea	rdi, [rsp+sha256_state_size]
	mov	esi, [rcx+buffer_length_ofs]
	add	esi, 4
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	mov	rcx, [rbx+ssh_remotekexinit_ofs]
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rcx+buffer_length_ofs]
	add	edx, 4
	call	sha256$update
	; next up: length prefixed host key blob, length is in r13, buffer in r12
	lea	rdi, [rsp+sha256_state_size]
	mov	eax, r13d
	mov	edx, r13d
if use_movbe
	movbe	[rdi], eax
else
	bswap	eax
	mov	[rdi], eax
end if
	add	rdi, 4
	mov	rsi, r12
	call	memcpy
if sshdebug
	lea	rdi, [rsp+sha256_state_size]
	mov	esi, r13d
	add	esi, 4
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, r13d
	add	edx, 4
	call	sha256$update
	; uint32 min, n, max
	lea	rdi, [rsp+sha256_state_size]
	mov	eax, [rbx+ssh_dh_min_ofs]
	mov	ecx, [rbx+ssh_dh_n_ofs]
	mov	edx, [rbx+ssh_dh_max_ofs]
if use_movbe
	movbe	[rdi], eax
	movbe	[rdi+4], ecx
	movbe	[rdi+8], edx
else
	bswap	eax
	bswap	ecx
	bswap	edx
	mov	[rdi], eax
	mov	[rdi+4], ecx
	mov	[rdi+8], edx
end if
if sshdebug
	lea	rdi, [rsp+sha256_state_size]
	mov	esi, 12
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 12
	call	sha256$update
	; encoded dh_p
	mov	rdi, [rbx+ssh_dh_p_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_g
	mov	rdi, [rbx+ssh_dh_g_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_e
	mov	rdi, [rbx+ssh_dh_e_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_f
	mov	rdi, [rbx+ssh_dh_f_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	; encoded dh_shared
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	lea	rsi, [rsp+sha256_state_size+4]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rsi, [rsp+sha256_state_size]
if use_movbe
	movbe	[rsi], eax
else
	bswap	eax
	mov	[rsi], eax
end if
	mov	rdi, rsp
	add	edx, 4
	call	sha256$update
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_hash_ofs]
	xor	edx, edx			; don't try and destroy the state
	call	sha256$final
calign
.keycalc_hashdone:
	; so the hash is sitting in [rbx+ssh_hash_ofs] for 32 bytes
	cmp	qword [rbx+ssh_sessionid_ofs], 0
	jne	.keycalc_notfirst
	cmp	qword [rbx+ssh_sessionid_ofs+8], 0
	jne	.keycalc_notfirst
	cmp	qword [rbx+ssh_sessionid_ofs+16], 0
	jne	.keycalc_notfirst
	cmp	qword [rbx+ssh_sessionid_ofs+24], 0
	jne	.keycalc_notfirst
	lea	rdi, [rbx+ssh_sessionid_ofs]
	lea	rsi, [rbx+ssh_hash_ofs]
	mov	edx, 32
	call	memcpy

if sshdebug
	mov	rdi, .sessidmsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_sessionid_ofs]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

calign
.keycalc_notfirst:
	; key derivation goods next, our sha256 state got re-initialized for reuse on our call to final above
if sshdebug
	mov	rdi, .hashmsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_hash_ofs]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	; so, dh_shared == K, sessionid is set, hash is set
	; initial iv client to server == sha256(K || H || 'A' || sessionid)
	; initial iv server to client == sha256(K || H || 'B' || sessionid)
	; encryptkey client to server == .... 'C'
	;            server to client == .... 'D'
	; integrity  client to server == .... 'E'
	;            server to client == .... 'F'
	; encode our plaintext length of shared secret K into [rsp+sha256_state_size]
	; encode our bswapped length of shared secret K into [rsp+sha256_state_size+4]
	; encode our shared secret K into [rsp+sha256_state_size+8]
	; copy our 32 byte hash after that
	mov	rdi, [rbx+ssh_dh_shared_ofs]
	lea	rsi, [rsp+sha256_state_size+8]
	call	bigint$ssh_encode
	mov	edx, eax
	lea	rdi, [rsp+sha256_state_size]
	mov	[rdi], eax
if use_movbe
	movbe	[rdi+4], eax
else
	bswap	eax
	mov	[rdi+4], eax
end if
	; next up, our 32 byte hash after that
	add	rdi, rdx
	add	rdi, 8
	lea	rsi, [rbx+ssh_hash_ofs]
	mov	edx, 32
	call	memcpy
	; get our host order length of K back
	lea	rdi, [rsp+sha256_state_size]
	mov	ecx, [rdi]
	add	rdi, 8 + 32
	add	rdi, rcx
	mov	byte [rdi], 'A'
	add	rdi, 1
	lea	rsi, [rbx+ssh_sessionid_ofs]
	mov	edx, 32
	call	memcpy
	; hash is ready to compute
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rsi]
	add	rsi, 4
	add	edx, 4 + 32 + 1 + 32
	call	sha256$update
	; now, depending on whether we are client mode or server mode, depends on where the final goes
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_pending_localiv_ofs]
	lea	rdx, [rbx+ssh_pending_remoteiv_ofs]
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmove	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	sha256$final
	; change our character
	lea	rdi, [rsp+sha256_state_size]
	mov	ecx, [rdi]
	add	rdi, 8 + 32
	add	rdi, rcx
	mov	byte [rdi], 'B'
	; do the update again
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rsi]
	add	rsi, 4
	add	edx, 4 + 32 + 1 + 32
	call	sha256$update
	; final for next one
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_pending_remoteiv_ofs]
	lea	rdx, [rbx+ssh_pending_localiv_ofs]
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmove	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	sha256$final
	; change our character
	lea	rdi, [rsp+sha256_state_size]
	mov	ecx, [rdi]
	add	rdi, 8 + 32
	add	rdi, rcx
	mov	byte [rdi], 'C'
	; do the update again
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rsi]
	add	rsi, 4
	add	edx, 4 + 32 + 1 + 32
	call	sha256$update
	; final for next one
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_localkey_ofs]
	lea	rdx, [rbx+ssh_remotekey_ofs]
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmove	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	sha256$final
	; change our character
	lea	rdi, [rsp+sha256_state_size]
	mov	ecx, [rdi]
	add	rdi, 8 + 32
	add	rdi, rcx
	mov 	byte [rdi], 'D'
	; do the update again
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rsi]
	add	rsi, 4
	add	edx, 4 + 32 + 1 + 32
	call	sha256$update
	; final for next one
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_remotekey_ofs]
	lea	rdx, [rbx+ssh_localkey_ofs]
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmove	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	sha256$final
	; change our character
	lea	rdi, [rsp+sha256_state_size]
	mov	ecx, [rdi]
	add	rdi, 8 + 32
	add	rdi, rcx
	mov 	byte [rdi], 'E'
	; do the update again
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rsi]
	add	rsi, 4
	add	edx, 4 + 32 + 1 + 32
	call	sha256$update
	; final for next one
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_localint_ofs]
	lea	rdx, [rbx+ssh_remoteint_ofs]
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmove	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	sha256$final
	; change our character
	lea	rdi, [rsp+sha256_state_size]
	mov	ecx, [rdi]
	add	rdi, 8 + 32
	add	rdi, rcx
	mov 	byte [rdi], 'F'
	; do the update again
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, [rsi]
	add	rsi, 4
	add	edx, 4 + 32 + 1 + 32
	call	sha256$update
	; final for next one
	mov	rdi, rsp
	lea	rsi, [rbx+ssh_remoteint_ofs]
	lea	rdx, [rbx+ssh_localint_ofs]
	cmp	dword [rbx+ssh_clientmode_ofs], 0
	cmove	rsi, rdx
	xor	edx, edx				; don't attempt to free the state
	call	sha256$final

	; ok so, all our pending keys are set
if sshdebug
	mov	rdi, .localivmsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_pending_localiv_ofs]
	mov	esi, 16
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .remoteivmsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_pending_remoteiv_ofs]
	mov	esi, 16
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .localkeymsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_localkey_ofs]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .remotekeymsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_remotekey_ofs]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .localintmsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_localint_ofs]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .remoteintmsg
	call	string$to_stdoutln
	lea	rdi, [rbx+ssh_remoteint_ofs]
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	add	rsp, 16384
	ret
	
if sshdebug
cleartext .sessidmsg, 'Session ID:'
cleartext .hashmsg, 'Exchange hash H:'
cleartext .localivmsg, 'Local IV:'
cleartext .remoteivmsg, 'Remote IV:'
cleartext .localkeymsg, 'Local Key:'
cleartext .remotekeymsg, 'Remote Key:'
cleartext .localintmsg, 'Local Integrity Key:'
cleartext .remoteintmsg, 'Remote Integrity Key:'
cleartext .hashinputmsg, 'Exchange Hash Input Bytes:'
end if

end if


