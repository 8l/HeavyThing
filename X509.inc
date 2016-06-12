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
	; X509.inc: just enough X509 goods to deal with the TLS/SSH that I require
	;
	; some notes here:
	;
	; all of my certificate environments contain a private key, and
	; optionally certificates, and optionally public keys.
	;
	; as a result, we provide two ways to load 'em up as it were:
	; X509$new_pem: this reads a PEM file, which is expected to contain
	; ALL the goods (and is how I deploy them in my webserver enviros)
	; e.g. private key along with certificate/intermediates.
	;
	; X509$new_ssh: this will read what is normally /etc/ssh/ssh_host_rsa_key
	; and you can specify alternate locations if you want
	; 
	; What this lets me do is access the guts of it decoded
	; without having to continually base64 decode/search/extract the bits
	; we are after
	;
	; probably not the nicest way to go about it, but serves my lightweight
	; purposes here nicely
	;

X509debug = 0


X509_privatekey_ofs = 0			; for rsa private keys
X509_dsaprivatekey_ofs = 8		; for dsa private keys
X509_pubkey_ofs = 16			; for ssh style rsa public keys (will be a buffer with the binary goods)
X509_dsapubkey_ofs = 24			; for ssh style dsa public keys ("")
X509_certificates_ofs = 32		; list$new or null (signed/certchain/etc)
X509_mtime_ofs = 40			; if we were loaded as a PEM, this is its mtime
X509_checktime_ofs = 48			; ""

X509_size = 56

if used X509$new | defined include_everything
	; no arguments, returns a heap$alloc'd X509 object that is all empty/null
	; don't call this directly, just do the two lines yourself, haha
falign
X509$new:
	prolog	X509$new
	mov	edi, X509_size
	call	heap$alloc_clear
	epilog

end if

if used X509$destroy | defined include_everything
	; single argument in rdi: X509 object to fully destroy
	; cleans up all allocated objects/lists, and heap$free's the X509 object itself
falign
X509$destroy:
	prolog	X509$destroy
	push	rdi
	cmp	qword [rdi+X509_privatekey_ofs], 0
	je	.noprivatekey
	mov	rdi, [rdi+X509_privatekey_ofs]
	call	X509$rsaprivate_destroy
calign
.noprivatekey:
	mov	rdi, [rsp]
	cmp	qword [rdi+X509_dsaprivatekey_ofs], 0
	je	.nodsaprivatekey
	mov	rdi, [rdi+X509_dsaprivatekey_ofs]
	call	X509$dsaprivate_destroy
calign
.nodsaprivatekey:
	mov	rdi, [rsp]
	cmp	qword [rdi+X509_certificates_ofs], 0
	je	.nocertificates
	mov	rdi, [rdi+X509_certificates_ofs]
	mov	rsi, .certclear
	call	list$clear
	mov	rdi, [rsp]
	mov	rdi, [rdi+X509_certificates_ofs]
	call	heap$free
calign
.nocertificates:
	mov	rdi, [rsp]
	cmp	qword [rdi+X509_pubkey_ofs], 0
	je	.nopubkey
	mov	rdi, [rdi+X509_pubkey_ofs]
	call	buffer$destroy
calign
.nopubkey:
	mov	rdi, [rsp]
	cmp	qword [rdi+X509_dsapubkey_ofs], 0
	je	.nodsapubkey
	mov	rdi, [rdi+X509_dsapubkey_ofs]
	call	buffer$destroy
calign
.nodsapubkey:
	pop	rdi
	call	heap$free_clear		; clear probably not necessary here, but for good measure
	epilog
falign
.certclear:
	; called with rdi == our certificate
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rdi+X509cert_der_ofs]
	call	heap$free
	mov	rdi, [rbx+X509cert_serial_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_signature_r_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_signature_s_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_issuercn_ofs]
	call	heap$free
	mov	rdi, [rbx+X509cert_validafter_ofs]
	call	heap$free
	mov	rdi, [rbx+X509cert_validuntil_ofs]
	call	heap$free
	mov	rdi, [rbx+X509cert_subjectcn_ofs]
	call	heap$free
	mov	rdi, [rbx+X509cert_public_n_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_public_e_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_public_p_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_public_q_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_public_g_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_public_dsa_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+X509cert_altnames_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [rbx+X509cert_altnames_ofs]
	call	heap$free
	mov	rdi, [rbx+X509cert_ocspuri_ofs]
	test	rdi, rdi
	jz	.noocspuri
	call	heap$free
.noocspuri:
if used X509$ocsp | defined include_everything
	mov	rdi, [rbx+X509cert_ocspresponse_ofs]
	test	rdi, rdi
	jz	.noocsp
	call	buffer$destroy
.noocsp:
	mov	rdi, [rbx+X509cert_ocsprequest_ofs]
	test	rdi, rdi
	jz	.noocsprequest
	call	buffer$destroy
.noocsprequest:
	mov	rdi, [rbx+X509cert_ocsphost_ofs]
	test	rdi, rdi
	jz	.noocsphost
	call	heap$free
.noocsphost:
	mov	rdi, [rbx+X509cert_ocsptimer_ofs]
	test	rdi, rdi
	jz	.noocsptimer
	call	epoll$timer_clear
.noocsptimer:
end if
	mov	rdi, [rbx+X509cert_caissuers_ofs]
	test	rdi, rdi
	jz	.noissuers
	call	heap$free
.noissuers:
	mov	rdi, rbx
	pop	rbx
	call	heap$free
	ret

end if




if used X509$ocsp | defined include_everything


globals
{
	; if this is set, then every time we receive a valid response, we'll call this
	X509$ocsp_hook	dq	0
}

	; single argument in rdi: an X509 object (with certificates)
	; we will propagate (per certificate) an oscpresponse buffer periodically, for use with OCSP Stapling (RFC2560)
falign
X509$ocsp:
	prolog	X509$ocsp
	mov	rdx, rdi
	mov	rdi, [rdi+X509_certificates_ofs]
	mov	rsi, .doit
	call	list$foreach_arg
	epilog
falign
.doit:
	; rdi == X509cert_* object, rsi == parent X509 object
	cmp	qword [rdi+X509cert_ocspuri_ofs], 0
	je	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r15, rsi

	; create our OCSP request for this certificate, this takes a bit of grunt, but we only have to do it once
	call	buffer$new
	mov	[rbx+X509cert_ocsprequest_ofs], rax
	mov	r12, rax

if X509_ocsp_sha256
	; we use SHA256, which is 32 bytes in length, so our total length is: 10 + seriallength + (32 + 2) * 2 + 9 + 6
	; 93 bytes + seriallength
	mov	r13d, [rbx+X509cert_seriallength_ofs]
	add	r13d, 93
else
	; we use SHA160, which is 20 bytes in length, so our total length is: 10 + seriallength + (20 + 2) * 2 + 5 + 6
	; 65 bytes + seriallength
	mov	r13d, [rbx+X509cert_seriallength_ofs]
	add	r13d, 65
end if

macro ocspseqpreface n* {
	mov	rdi, r12
	mov	esi, 0x30
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, r13d
	sub	esi, n
	call	buffer$append_byte
}
	ocspseqpreface 2
	ocspseqpreface 4
	ocspseqpreface 6
	ocspseqpreface 8
	ocspseqpreface 10

if X509_ocsp_sha256
	; next up, our AlgorithmIdentifier, which is 0x30 + 0x0d + 0x06 + 0x09 + 9 byte OID + 0x05 + 0x00
	mov	rdi, r12
	mov	esi, 0x30
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x0d
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x06
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x09
	call	buffer$append_byte
	mov	rdi, r12
	mov	rsi, .algoid
	mov	edx, 9
	call	buffer$append
	mov	rdi, r12
	mov	esi, 0x05
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x00
	call	buffer$append_byte
	
	; next up is 0x04 + 0x20
	mov	rdi, r12
	mov	esi, 0x04
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x20
	call	buffer$append_byte

	; and the hash of hte issuerdn is next, and we have that in this cert
	sub	rsp, sha256_state_size + 32
	mov	rdi, rsp
	call	sha256$init
	mov	eax, [rbx+X509cert_issuerdnstart_ofs]
	mov	edx, [rbx+X509cert_issuerdnlength_ofs]
	mov	rsi, [rbx+X509cert_der_ofs]
	mov	rdi, rsp
	add	rsi, rax
	call	sha256$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	xor	edx, edx
	call	sha256$final
	mov	rdi, r12
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 32
	call	buffer$append

	; next up is 0x04 + 0x20
	mov	rdi, r12
	mov	esi, 0x04
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x20
	call	buffer$append_byte

else
	; next up, our AlgorithmIdentifier, which is 0x30 + 0x09 + 0x06 + 0x05 + 5 byte OID + 0x05 + 0x00
	mov	rdi, r12
	mov	esi, 0x30
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x09
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x06
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x05
	call	buffer$append_byte
	mov	rdi, r12
	mov	rsi, .algoid
	mov	edx, 5
	call	buffer$append
	mov	rdi, r12
	mov	esi, 0x05
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x00
	call	buffer$append_byte
	
	; next up is 0x04 + 0x14
	mov	rdi, r12
	mov	esi, 0x04
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x14
	call	buffer$append_byte

	; and the hash of hte issuerdn is next, and we have that in this cert
	sub	rsp, sha160_state_size + 32
	mov	rdi, rsp
	call	sha160$init
	mov	eax, [rbx+X509cert_issuerdnstart_ofs]
	mov	edx, [rbx+X509cert_issuerdnlength_ofs]
	mov	rsi, [rbx+X509cert_der_ofs]
	mov	rdi, rsp
	add	rsi, rax
	call	sha160$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx
	call	sha160$final
	mov	rdi, r12
	lea	rsi, [rsp+sha160_state_size]
	mov	edx, 20
	call	buffer$append

	; next up is 0x04 + 0x14
	mov	rdi, r12
	mov	esi, 0x04
	call	buffer$append_byte
	mov	rdi, r12
	mov	esi, 0x14
	call	buffer$append_byte


end if

	; next up is our hash of the issuerpublickey, which is considerably more complicated

	; so the first option is: this issuer exists as another certificate in our certificates list itself
	; [rbx+X509cert_issuercn_ofs] string is what we are looking for in the X509cert_subjectcn_ofs of the certificates list
	mov	rdi, [r15+X509_certificates_ofs]
	mov	r13, [rdi+_list_first_ofs]
	; we know there is at least one certificate here
calign
.issuersearch:
	mov	rdx, [r13+_list_valueofs]
	mov	rdi, [rbx+X509cert_issuercn_ofs]
	mov	rsi, [rdx+X509cert_subjectcn_ofs]
	call	string$equals
	test	eax, eax
	jnz	.issuersearch_found
	mov	r13, [r13+_list_nextofs]
	test	r13, r13
	jnz	.issuersearch
	; if we made it to here, we were unable to locate the issuer in our own certificate list
	; so, we need a string replacement with ' ' -> '_', and then add '.pem' to the end of the name we are after
	; and see if it exists in /etc/ssl/certs
	mov	rdi, [rbx+X509cert_issuercn_ofs]
	mov	rsi, .spacestr
	mov	rdx, .underscorestr
	call	string$replace
	mov	r13, rax
	mov	rdi, rax
	mov	rsi, .pemfilestr
	call	string$concat
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	mov	rdi, .etcsslcerts
	mov	rsi, r13
	call	string$concat
	mov	rdi, r13
	mov	r13, rax
	call	heap$free

if X509debug
	mov	rdi, r13
	call	string$to_stdoutln
end if

	mov	rdi, r13
	call	X509$new_pem
	test	rax, rax
	jz	.issuer_pemfile_error
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	; so, we have an X509 object sitting in r13, make sure it has a certificates list, and that said list is non-empty, then search for our original
	; issuercn
	mov	rdi, [r13+X509_certificates_ofs]
	test	rdi, rdi
	jz	.issuer_x509_error
	mov	r14, [rdi+_list_first_ofs]
calign
.issuersearch2:
	mov	rdx, [r14+_list_valueofs]
	mov	rdi, [rbx+X509cert_issuercn_ofs]
	mov	rsi, [rdx+X509cert_subjectcn_ofs]
	call	string$equals
	test	eax, eax
	jnz	.issuersearch_found2
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jnz	.issuersearch2
calign
.issuer_x509_error:
	; if we made it to here, no deal
	mov	rdi, r13
	call	X509$destroy
	; destroy our buffer in r12 and clear rbx's ocsprequest
	mov	rdi, r12
	call	buffer$destroy
	mov	qword [rbx+X509cert_ocsprequest_ofs], 0
if X509_ocsp_sha256
	add	rsp, sha256_state_size + 32
else
	add	rsp, sha160_state_size + 32
end if
	pop	r15 r14 r13 r12 rbx
	ret
calign
.issuer_pemfile_error:
	mov	rdi, r13
	call	heap$free
	; destroy our buffer in r12 and clear rbx's ocsprequest
	mov	rdi, r12
	call	buffer$destroy
	mov	qword [rbx+X509cert_ocsprequest_ofs], 0
if X509_ocsp_sha256
	add	rsp, sha256_state_size + 32
else
	add	rsp, sha160_state_size + 32
end if
	pop	r15 r14 r13 r12 rbx
	ret
calign
.issuersearch_found:
	; X509cert object at [r13+_list_valueofs] contains the public key we were looking for
	mov	rcx, [r13+_list_valueofs]

	mov	eax, [rcx+X509cert_publickeystart_ofs]
	mov	edx, [rcx+X509cert_publickeylength_ofs]
	mov	rsi, [rcx+X509cert_der_ofs]
	mov	rdi, rsp
	add	rsi, rax
if X509_ocsp_sha256
	call	sha256$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	xor	edx, edx
	call	sha256$final
	mov	rdi, r12
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 32
	call	buffer$append

	add	rsp, sha256_state_size + 32
else
	call	sha160$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx
	call	sha160$final
	mov	rdi, r12
	lea	rsi, [rsp+sha160_state_size]
	mov	edx, 20
	call	buffer$append
	
	add	rsp, sha160_state_size + 32
end if
	jmp	.doserial

calign
.issuersearch_found2:
	; X509cert object at [r14+_list_valueofs] contains the public key we were looking for
	mov	rcx, [r14+_list_valueofs]
	
	mov	eax, [rcx+X509cert_publickeystart_ofs]
	mov	edx, [rcx+X509cert_publickeylength_ofs]
	mov	rsi, [rcx+X509cert_der_ofs]
	mov	rdi, rsp
	add	rsi, rax
if X509_ocsp_sha256
	call	sha256$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha256_state_size]
	xor	edx, edx
	call	sha256$final
	mov	rdi, r12
	lea	rsi, [rsp+sha256_state_size]
	mov	edx, 32
	call	buffer$append

	add	rsp, sha256_state_size + 32
else
	call	sha160$update
	mov	rdi, rsp
	lea	rsi, [rsp+sha160_state_size]
	xor	edx, edx
	call	sha160$final
	mov	rdi, r12
	lea	rsi, [rsp+sha160_state_size]
	mov	edx, 20
	call	buffer$append

	add	rsp, sha160_state_size + 32
end if

	mov	rdi, r13
	call	X509$destroy
	; fallthrough to doserial
calign
.doserial:
	; last but not least, we need the serial from rbx
	mov	eax, [rbx+X509cert_serialstart_ofs]
	mov	edx, [rbx+X509cert_seriallength_ofs]
	mov	rsi, [rbx+X509cert_der_ofs]
	add	rsi, rax
	mov	rdi, r12
	call	buffer$append

if X509debug
	mov	rdi, .ocspreqmsg
	call	string$to_stdoutln
	mov	rdi, [r12+buffer_itself_ofs]
	mov	rsi, [r12+buffer_length_ofs]
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if

	; so now, we have a DER encoded OCSP request sitting in r12/[rbx+X509cert_ocsprequest_ofs]
	; next thing we have to do is actually fire up the initial OCSP request
	
	; so, we could use our existing webclient layer to do it for us, but that is _way_ overkill
	; for what we need, so to keep it as lightweight as possible, we'll do the DNS/epoll action
	; ourselves directly from in here
	xor	edi, edi
	mov	rsi, [rbx+X509cert_ocspuri_ofs]
	call	url$new
	test	rax, rax
	jz	.ocspuri_error
	mov	r13, rax
	mov	rdi, [rax+url_host_ofs]
	call	string$copy
	mov	[rbx+X509cert_ocsphost_ofs], rax
	mov	rdi, r13
	call	url$destroy
if X509_ocsp_syslog
	mov	rdi, .initialsyslogpreface
	mov	rsi, [rbx+X509cert_ocspuri_ofs]
	call	string$concat
	mov	r13, rax
	mov	edi, log_notice
	mov	rsi, rax
	call	syslog
	mov	rdi, r13
	call	heap$free
end if
	; dns is next
	mov	rdi, [rbx+X509cert_ocsphost_ofs]
	mov	rsi, .dns_success
	mov	rdx, .dns_failure
	mov	rcx, rbx
	call	dns$lookup_ipv4
	pop	r15 r14 r13 r12 rbx
	ret
if X509_ocsp_syslog
cleartext .initialsyslogpreface, 'OCSP request to '
end if
calign
.ocspuri_error:
	mov	rdi, r12
	call	buffer$destroy
	mov	qword [rbx+X509cert_ocsprequest_ofs], 0
	pop	r15 r14 r13 r12 rbx
	ret
	
calign
.nothingtodo:
	ret
cleartext .spacestr, ' '
cleartext .underscorestr, '_'
cleartext .pemfilestr, '.pem'
cleartext .etcsslcerts, '/etc/ssl/certs/'
if X509debug
cleartext .ocspreqmsg, 'OCSP Request DER Buffer:'
end if
dalign
.algoid:
if X509_ocsp_sha256
	db	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
else
	db	0x2b, 0x0e, 0x03, 0x02, 0x1a
end if

	; sha160: 0x2b, 0x0e, 0x03, 0x02, 0x1a
	; sha224: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
	; sha256: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
	; sha384: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
	; sha512: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03


dalign
.ocsp_outbound_vtable:
	dq	epoll$destroy, epoll$clone, .ocsp_outbound_connected, epoll$send, .ocsp_outbound_receive, .ocsp_outbound_error, io$timeout
falign
.dns_success:
	; despite being declared inline here, this is a standalone function
	; rdi == host string that we passed to dns, rsi == our X509 object, rdx == result
	; we need to issue our connect
	push	rsi rdx

if X509debug
	call	string$to_stdoutln
	mov	rdi, [rsp]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .ocspdnssuccess
	call	string$to_stdoutln
end if
	mov	rdi, .ocsp_outbound_vtable
	mov	esi, 8
	call	epoll$new
	pop	rdx rsi
	mov	[rax+epoll_base_size], rsi
	; setup our remote address
	sub	rsp, sockaddr_in_size + 8
	mov	[rsp+sockaddr_in_size], rsi
	mov	ecx, 80
	mov	word [rsp], 2		; AF_INET/PF_INET
	xchg	ch, cl
	mov	word [rsp+2], cx	; htons(port)
	mov	dword [rsp+4], edx
	mov	qword [rsp+8], 0
	mov	rdi, rsp
	mov	esi, sockaddr_in_size
	mov	rdx, rax
	call	epoll$outbound
	; in the event that _failed miserably, we need to do a retry all over again
	test	eax, eax
	jz	.dns_success_connectfailed
	add	rsp, sockaddr_in_size + 8
	ret
calign
.dns_success_connectfailed:
if X509debug
	mov	rdi, .ocspconnectfail
	call	string$to_stdoutln
end if
	mov	edi, io_base_size + 8
	call	heap$alloc_clear
	mov	rdx, [rsp+sockaddr_in_size]
	mov	qword [rax], .retry_vtable
	mov	[rax+io_base_size], rdx
	mov	edi, X509_ocsp_retry
	mov	rsi, rax
	call	epoll$timer_new
	add	rsp, sockaddr_in_size + 8
	ret
if X509debug
cleartext .ocspdnssuccess, 'OCSP DNS lookup succeeded'
cleartext .ocspconnectfail, 'OCSP outbound connection failed.'
cleartext .ocspdnsfailure, 'OCSP DNS lookup failed: '
end if
dalign
.retry_vtable:
	dq	io$destroy, io$clone, io$connected, io$send, io$receive, io$error, .dns_retry
falign
.dns_failure:
if X509debug
	push	rsi rdi
	mov	rdi, .ocspdnsfailure
	call	string$to_stdout
	pop	rdi
	call	string$to_stdoutln
	pop	rsi
end if
	; despite being declared inline here, this is a standalone function
	; we need to retry again every 5 minutes, or until we are destroyed
	push	rsi
	mov	edi, io_base_size + 8
	call	heap$alloc_clear
	pop	rdx
	mov	qword [rax], .retry_vtable
	mov	[rax+io_base_size], rdx
	mov	edi, X509_ocsp_retry
	mov	rsi, rax
	push	rdx
	call	epoll$timer_new
	pop	rdx
	mov	[rdx+X509cert_ocsptimer_ofs], rax
	ret
falign
.dns_retry:
if X509debug
	push	rdi
	mov	rdi, .dnsretry1
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	r8, [rdi+io_base_size]
	mov	rdi, [r8+X509cert_ocsphost_ofs]
	call	string$to_stdoutln
	mov	rdi, [rsp]
end if
	; object in rdi == our simple io object, at which io_base_size is our X509 pointer
	mov	r9, rdi
	mov	r8, [rdi+io_base_size]
	mov	rdi, [r8+X509cert_ocsphost_ofs]
	mov	rsi, .dns_success
	mov	rdx, .dns_failure
	mov	rcx, r8
	mov	qword [r8+X509cert_ocsptimer_ofs], 0
	call	dns$lookup_ipv4
if X509debug
	mov	rdi, .dnsretry2
	call	string$to_stdout
	mov	rdi, [rsp]
	mov	r8, [rdi+io_base_size]
	mov	rdi, [r8+X509cert_ocsphost_ofs]
	call	string$to_stdoutln
	mov	rdi, [rsp]

	pop	rdi
end if
	mov	eax, 1		; kill off our io object
	ret
if X509debug
cleartext .dnsretry1, '--------- .dns_retry for host: '
cleartext .dnsretry2, '********* after dns$lookup_ipv4, host is: '
end if
falign
.ocsp_outbound_error:
	; again, despite this being declared inline, this is a standalone function also
	; create a new retry timer
	push	qword [rdi+epoll_base_size]	; our X509cert object

if X509_ocsp_syslog
	mov	rdx, [rdi+epoll_base_size]
	mov	rdi, .errorsyslogpreface
	mov	rsi, [rdx+X509cert_ocspuri_ofs]
	call	string$concat
	push	rax
	mov	edi, log_notice
	mov	rsi, rax
	call	syslog
	pop	rdi
	call	heap$free
end if
	mov	edi, io_base_size + 8
	call	heap$alloc_clear
	pop	rdx
	mov	qword [rax], .retry_vtable
	mov	[rax+io_base_size], rdx
	mov	edi, X509_ocsp_retry
	mov	rsi, rax
	push	rdx
	call	epoll$timer_new
	pop	rdx
	mov	[rdx+X509cert_ocsptimer_ofs], rax
	ret
if X509_ocsp_syslog
cleartext .errorsyslogpreface, 'OCSP fetch ERROR from '
cleartext .connectsyslogpreface1, 'OCSP fd: '
cleartext .connectsyslogpreface2, ' fetching from '
end if
falign
.ocsp_outbound_connected:
	; again despite this being declared inline, this is a standalone function also
	; rdi == our epoll object, [rdi+epoll_base_size] is our X509cert object
	push	rbx r12 r13 r14
	; we need to construct a mimelike object for our OCSP request
	mov	rbx, rdi
	mov	r12, [rdi+epoll_base_size]
	call	mimelike$new
	mov	r13, rax

	mov	rdi, rax
	mov	rsi, mimelike$connection
	mov	rdx, .close
	call	mimelike$setheader

	mov	rdi, r13
	mov	rsi, .host
	mov	rdx, [r12+X509cert_ocsphost_ofs]
	call	mimelike$setheader

	mov	rsi, [r12+X509cert_ocspuri_ofs]
	xor	edi, edi
	call	url$new
	mov	r14, rax

if X509_ocsp_syslog
	mov	edi, [rbx+epoll_fd_ofs]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, .connectsyslogpreface1
	mov	rsi, rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, .connectsyslogpreface2
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, [r12+X509cert_ocspuri_ofs]
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	edi, log_notice
	mov	rsi, [rsp]
	call	syslog
	pop	rdi
	call	heap$free
end if

	mov	rdi, r14
	call	url$topreface
	mov	rdi, r14
	mov	r14, rax
	call	url$destroy
	
	; turn it into a valid HTTP POST preface
	mov	rdi, .postpreface
	mov	rsi, r14
	call	string$concat
	mov	rdi, r14
	mov	r14, rax
	call	heap$free

	mov	rdi, r14
	mov	rsi, .prefaceend
	call	string$concat
	mov	rdi, r14
	mov	r14, rax
	call	heap$free

	mov	rdi, r13
	mov	rsi, r14
	call	mimelike$setpreface_nocopy

	mov	rdi, r13
	mov	rsi, mimelike$contenttype
	mov	rdx, .ctype
	call	mimelike$setheader

if defined X509_add_content_transfer_encoding
	mov	rdi, r13
	mov	rsi, mimelike$contenttransferencoding
	mov	rdx, mimelike$binary
	call	mimelike$setheader
end if

	mov	rcx, [r12+X509cert_ocsprequest_ofs]
	mov	rdi, [rcx+buffer_length_ofs]
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, r13
	mov	rsi, mimelike$contentlength
	mov	rdx, rax
	call	mimelike$setheader_novaluecopy

	; set the body
	mov	rcx, [r12+X509cert_ocsprequest_ofs]
	mov	rdi, r13
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	mimelike$setbody

	mov	rdi, r13
	xor	esi, esi
	call	mimelike$compose

if X509debug
	mov	rdi, .ocspsend
	call	string$to_stdoutln
	mov	rcx, [r13+mimelike_xmitbody_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	; mov	rdx, [rcx+buffer_length_ofs]
	mov	rdx, [r13+mimelike_hdrlen_ofs]
	syscall
end if
	mov	rcx, [r13+mimelike_xmitbody_ofs]
	mov	rdi, rbx
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	mov	rcx, [rdi]
	call	qword [rcx+io_vsend]

	mov	rdi, r13
	call	mimelike$destroy

if X509debug
	mov	rdi, .ocspsend2
	call	string$to_stdout
	mov	rdi, [r12+X509cert_ocsphost_ofs]
	call	string$to_stdoutln
end if

	pop	r14 r13 r12 rbx
	ret
cleartext .close, 'close'
cleartext .host, 'Host'
cleartext .postpreface, 'POST '
cleartext .prefaceend, ' HTTP/1.1'
cleartext .ctype, 'application/ocsp-request'
if X509debug
cleartext .ocspsend, 'SENDING OCSP HTTP REQUEST:'
cleartext .ocspsend2, '  AFTER REQUEST SEND, ocsphost is: '
cleartext .ocspreceive, 'RECEIVED OCSP RESPONSE:'
cleartext .ocspreceive2, '.ocsp_outbound_receive, ocsphost is: '
cleartext .ocspreceive3, '  after complete receive, ocsphost is: '
end if


falign
.ocsp_outbound_receive:
	; same with this one, standalone, called for our ocsp_outbound connection
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, [rdi+epoll_base_size]	; our X509cert object

if X509debug
	mov	rdi, .ocspreceive2
	call	string$to_stdout
	mov	rdi, [r12+X509cert_ocsphost_ofs]
	call	string$to_stdoutln
end if

	; so we got back a reply, which may have been a partial reply and that we need to wait
	; for more data to arrive
	mov	r8, [rbx+epoll_inbuf_ofs]
	xor	edx, edx
	mov	ecx, 1
	mov	rdi, [r8+buffer_itself_ofs]
	mov	rsi, [r8+buffer_length_ofs]
	xor	r8d, r8d
	call	mimelike$new_parse
	test	rax, rax
	jz	.ocsp_outbound_receive_needmore
	; otherwise the parse was successful, so now we need to copy the body from this to our ocspresponse X509cert buffer
	mov	r13, rax
	cmp	qword [r12+X509cert_ocspresponse_ofs], 0
	jne	.ocsp_outbound_receive_nonewbuffer
	call	buffer$new
	mov	[r12+X509cert_ocspresponse_ofs], rax
calign
.ocsp_outbound_receive_nonewbuffer:

if X509debug
	mov	rdi, .ocspreceive
	call	string$to_stdoutln
	mov	rcx, [rbx+epoll_inbuf_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	; mov	rdx, [rcx+buffer_length_ofs]
	mov	rdx, [r13+mimelike_hdrlen_ofs]
	syscall
end if

	mov	rdi, [r12+X509cert_ocspresponse_ofs]
	call	buffer$reset
	mov	rcx, [r13+mimelike_body_ofs]
	mov	rdi, [r12+X509cert_ocspresponse_ofs]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	buffer$append

	cmp	qword [X509$ocsp_hook], 0
	je	.ocsp_outbound_receive_skiphook
	mov	rdi, r12
	call	qword [X509$ocsp_hook]
calign
.ocsp_outbound_receive_skiphook:

	; destroy the mimelike object
	mov	rdi, r13
	call	mimelike$destroy

	; we need to schedule a new timer so that our OCSP goods get updated periodically

	; create a new refresh timer
	mov	edi, io_base_size + 8
	call	heap$alloc_clear
	mov	rdx, r12
	mov	qword [rax], .retry_vtable
	mov	[rax+io_base_size], rdx
	mov	edi, X509_ocsp_refresh
	mov	rsi, rax
if X509debug
	mov	r13, rax
end if
	call	epoll$timer_new
	mov	[r12+X509cert_ocsptimer_ofs], rax

if X509debug
	mov	rdi, .refreshtimerdebug
	call	string$to_stdout
	mov	rdi, [r12+X509cert_ocsptimer_ofs]
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdout
	pop	rdi
	call	heap$free
	mov	rdi, .refreshtimerdebug2
	call	string$to_stdout
	mov	rdi, r13
	mov	esi, 16
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
end if
	
if X509debug
	mov	rdi, .ocspreceive3
	call	string$to_stdout
	mov	rdi, [r12+X509cert_ocsphost_ofs]
	call	string$to_stdoutln
end if


	mov	eax, 1		; go ahead and kill us off
	pop	r13 r12 rbx
	ret
if X509debug
cleartext .refreshtimerdebug, 'Created new refresh timer object at: '
cleartext .refreshtimerdebug2, ' with our io object at: '
end if
calign
.ocsp_outbound_receive_needmore:
	pop	r13 r12 rbx
	xor	eax, eax	; don't kill our connection just yet
	ret



end if





dsaprivate_p_ofs = 0			; bigint
dsaprivate_q_ofs = 8			; bigint
dsaprivate_g_ofs = 16			; bigint
dsaprivate_y_ofs = 24			; bigint (dsa public)
dsaprivate_x_ofs = 32			; bigint (dsa private)

dsaprivate_size = 40


if used X509$dsaprivate_destroy | defined include_everything
	; single argument in rdi: our dsaprivate object
falign
X509$dsaprivate_destroy:
	prolog	X509$dsaprivate_destroy
	push	rbx
	mov	rbx, rdi
	mov	rdi, [rbx+dsaprivate_p_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+dsaprivate_q_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+dsaprivate_g_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+dsaprivate_y_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+dsaprivate_x_ofs]
	call	bigint$destroy_clear
	mov	rdi, rbx
	call	heap$free_clear
	pop	rbx
	epilog
end if


macro asn1_tag {
	; assumed that r12 == buffer, r13 == _remaining bytes_ left in r12 (which we'll decrement as we consume them)
	; this will populate the tag itself in eax, raw tag in ecx, length in r8d, and update r13/r12 as we go
	; if we were all jacked up, or an error occurred, etc, eax will be -1
	; we mash r8, r9, r10, set eax, ecx
	local	.length,.kakked,.done
	cmp	r13, 2
	jle	.kakked
	movzx	eax, byte [r12]
	mov	ecx, eax
	and	eax, 0x1f
	add	r12, 1
	sub	r13, 1
	; decode the length as well
	movzx	r8d, byte [r12]
	add	r12, 1
	sub	r13, 1
	test	r8d, 0x80
	; length in r8d is fine
	jz	.done
	and	r8d, 0x7f	; length bytes
	test	r8d, r8d
	jz	.done
	mov	r9d, r8d
	xor	r8d, r8d
calign
.length:
	test	r13, r13
	jz	.kakked
	movzx	r10d, byte [r12]
	add	r12, 1
	sub	r13, 1
	shl	r8, 8
	or	r8, r10
	sub	r9d, 1
	jnz	.length
	jmp	.done
calign
.kakked:
	mov	eax, -1
calign
.done:
}



if used X509$add_dsaprivatekey | defined include_everything
	; three arguments: rdi == X509 object to add to, rsi == DER encoded buffer, rdx == length of same
	; returns bool in eax as to whether we succeeded or not
falign
X509$add_dsaprivatekey:
	prolog	X509$add_dsaprivatekey
	sub	rsp, 64
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	; we need some of our callee-saves
	mov	[rsp+24], rbx
	mov	[rsp+32], r12
	mov	[rsp+40], r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	call	list$new
	mov	[rsp+48], rax		; our "undo" list in case we have to unwind all this, makes it much cleaner
	mov	edi, dsaprivate_size
	call	heap$alloc_clear
	mov	[rsp+56], rax		; our dsaprivate object

	; first things first, we expect a sequence
	call	.gettag
	cmp	eax, 0x10		; we need it to start iwth a sequence, or die.
	jne	.kakked
	; version is first up
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	; openssl seems to produce version == 0
	cmp	r8d, 1
	jne	.kakked
	test	r13, r13
	jz	.kakked			; no more data left?
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; we aren't presently checking the actual value of our single byte version here... though everything i have it is zero
	; cmp	eax, 0
	; ja	.kakked

	; p is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	; otherwise, we should have a [large-ish] integer sitting here
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	[rdi+dsaprivate_p_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	rdi, [rdi+dsaprivate_p_ofs]
	call	bigint$debug
end if

	; q is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	[rdi+dsaprivate_q_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	rdi, [rdi+dsaprivate_q_ofs]
	call	bigint$debug
end if

	; g is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked	
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	[rdi+dsaprivate_g_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	rdi, [rdi+dsaprivate_g_ofs]
	call	bigint$debug
end if

	; y is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked	
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	[rdi+dsaprivate_y_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	rdi, [rdi+dsaprivate_y_ofs]
	call	bigint$debug
end if

	; last but not least, x
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked	
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	[rdi+dsaprivate_x_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our dsaprivate object
	mov	rdi, [rdi+dsaprivate_x_ofs]
	call	bigint$debug
end if

	mov	rdi, [rsp+48]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free_clear
	
	; last but not least, we need to add our rsaprivate object to our X509 object
	mov	rdi, [rsp]
	mov	rsi, [rsp+56]
	mov	[rdi+X509_dsaprivatekey_ofs], rsi

	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]
	add	rsp, 64
	mov	eax, 1			; success.
	epilog
calign
.kakked:
	mov	rdi, [rsp+48]
	mov	rsi, bigint$destroy_clear
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free_clear
	mov	rdi, [rsp+56]
	call	heap$free_clear

	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]
	add	rsp, 64
	xor	eax, eax		; fail.
	epilog
falign
.gettag:
	asn1_tag
	ret


end if




rsaprivate_n_ofs = 0			; bigint
rsaprivate_e_ofs = 8			; bigint
rsaprivate_d_ofs = 16			; bigint
rsaprivate_p_ofs = 24			; bigint
rsaprivate_q_ofs = 32			; bigint
rsaprivate_dmodp_ofs = 40		; bigint
rsaprivate_dmodq_ofs = 48		; bigint
rsaprivate_invqmodp_ofs = 56		; bigint
rsaprivate_x_ofs = 64			; bigint
rsaprivate_y_ofs = 72
rsaprivate_z_ofs = 80
rsaprivate_other_ofs = 88		; list

rsaprivate_size = 96

rsaprivate_ri_ofs = 0			; bigint
rsaprivate_di_ofs = 8			; bigint
rsaprivate_ti_ofs = 16			; bigint

rsaprivate_other_size = 24

if used X509$rsaprivate_destroy | defined include_everything

	; single argument in rdi: our rsaprivate object
falign
X509$rsaprivate_destroy:
	prolog	X509$rsaprivate_destroy
	push	rbx
	mov	rbx, rdi
	; all must be valid by nature except for other, which is optional
	mov	rdi, [rbx+rsaprivate_n_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+rsaprivate_e_ofs]
	call	bigint$destroy
	mov	rdi, [rbx+rsaprivate_d_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+rsaprivate_p_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+rsaprivate_q_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+rsaprivate_dmodp_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+rsaprivate_dmodq_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+rsaprivate_invqmodp_ofs]
	call	bigint$destroy_clear
	mov	rdi, [rbx+rsaprivate_x_ofs]
	call	bigint$destroy
	mov	rsi, [rbx+rsaprivate_y_ofs]
	call	bigint$destroy
	mov	rsi, [rbx+rsaprivate_z_ofs]
	call	bigint$destroy
	cmp	qword [rbx+rsaprivate_other_ofs], 0
	je	.no_other
	mov	rdi, [rbx+rsaprivate_other_ofs]
	mov	rsi, .otherclear
	call	list$clear
	mov	rdi, [rbx+rsaprivate_other_ofs]
	call	heap$free_clear			; clear not necessary here but for good measure
calign
.no_other:
	mov	rdi, rbx
	call	heap$free_clear			; clear not necessary here but for good measure
	pop	rbx
	epilog
calign
.otherclear:
	; rdi is our other item
	push	r15
	mov	r15, rdi
	mov	rdi, [r15+rsaprivate_ri_ofs]
	call	bigint$destroy_clear
	mov	rdi, [r15+rsaprivate_di_ofs]
	call	bigint$destroy_clear
	mov	rdi, [r15+rsaprivate_ti_ofs]
	call	bigint$destroy_clear
	pop	rdi
	call	heap$free_clear			; clear not necessary here but for good measure
	ret
end if




if used X509$add_privatekey | defined include_everything
	; three arguments: rdi == X509 object to add to, rsi == DER encoded buffer, rdx == length of same
	; returns bool in eax as to whether we succeeded or not
falign
X509$add_privatekey:
	prolog	X509$add_privatekey
	sub	rsp, 64
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	; we need some of our callee-saves
	mov	[rsp+24], rbx
	mov	[rsp+32], r12
	mov	[rsp+40], r13
	mov	r12, rsi
	mov	r13, rdx
	call	list$new
	mov	[rsp+48], rax		; our "undo" list in case we have to unwind all this, makes it much cleaner
	mov	edi, rsaprivate_size
	call	heap$alloc_clear
	mov	rbx, rax

	; from RFC 3447

	; first things first, we expect a sequence
	call	.gettag
	cmp	eax, 0x10		; we need it to start iwth a sequence, or die.
	jne	.kakked
	; version is first up
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	; now, its length... hmmm I say:
	; because the RFC says 0 or 1 only, the lenght MUST be one byte
	cmp	r8d, 1
	jne	.kakked
	test	r13, r13
	jz	.kakked			; no more data left?
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	cmp	eax, 1
	ja	.kakked
	; n (modulus) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	; otherwise, we should have a [large-ish] integer sitting here
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_n_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rbx+rsaprivate_n_ofs]
	call	bigint$debug
end if

	; e (publicExponent) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_e_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rbx+rsaprivate_e_ofs]
	call	bigint$debug
end if

	; d (privateExponent) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked	
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_d_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rbx+rsaprivate_d_ofs]
	call	bigint$debug
end if
	; p (prime1) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_p_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
if X509debug
	mov	rdi, [rbx+rsaprivate_p_ofs]
	call	bigint$debug
end if

	; q (prime2) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_q_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
if X509debug
	mov	rdi, [rbx+rsaprivate_q_ofs]
	call	bigint$debug
end if

	; dmodp (exponent1) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_dmodp_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
if X509debug
	mov	rdi, [rbx+rsaprivate_dmodp_ofs]
	call	bigint$debug
end if

	; dmodq (exponent2) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_dmodq_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
if X509debug
	mov	rdi, [rbx+rsaprivate_dmodq_ofs]
	call	bigint$debug
end if

	; invqmodp (coefficient) is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	[rbx+rsaprivate_invqmodp_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
if X509debug
	mov	rdi, [rbx+rsaprivate_invqmodp_ofs]
	call	bigint$debug
end if

	; create two monty objects for our rsaprivate goods
	mov	rdi, [rbx+rsaprivate_dmodq_ofs]
	mov	rsi, [rbx+rsaprivate_q_ofs]
	call	monty$new
	mov	rdi, [rbx+rsaprivate_q_ofs]
	mov	[rdi+bigint_monty_powmod_ofs], rax

	mov	rdi, [rbx+rsaprivate_dmodp_ofs]
	mov	rsi, [rbx+rsaprivate_p_ofs]
	call	monty$new
	mov	rdi, [rbx+rsaprivate_p_ofs]
	mov	[rdi+bigint_monty_powmod_ofs], rax

	; so, RFC says there might be more goods after here, but none of my RSA private keys contain anything
	; ... call this a todo for now
	mov	rdi, [rsp+48]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free

	; create our x, y, and z working integers
	call	bigint$new
	mov	[rbx+rsaprivate_x_ofs], rax
	call	bigint$new
	mov	[rbx+rsaprivate_y_ofs], rax
	call	bigint$new
	mov	[rbx+rsaprivate_z_ofs], rax
	
	; last but not least, we need to add our rsaprivate object to our X509 object
	mov	rdi, [rsp]
	mov	[rdi+X509_privatekey_ofs], rbx

	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]
	add	rsp, 64
	mov	eax, 1			; success.
	epilog
calign
.kakked:
	mov	rdi, [rsp+48]
	mov	rsi, bigint$destroy_clear
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free
	mov	rdi, [rsp+56]
	call	heap$free_clear

	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]
	add	rsp, 64
	xor	eax, eax		; fail.
	epilog
falign
.gettag:
	asn1_tag
	ret

end if

; we are by no means attempting to be a full fledged X509/OpenSSL replacement here
; all we are interested in are the fields required to do the deed, haha

; all of my certificates are rsaEncryption certificates... so this provides for same

X509cert_der_ofs = 0			; allocated buffer that holds a _copy_ of what is signed
X509cert_derlen_ofs = 8			; length of that section as a normal integer
X509cert_serial_ofs = 16		; bigint
X509cert_signature_ofs = 24		; this will be an int from one of the constants (the TYPE of signature)
X509cert_signature_r_ofs = 32		; if the signature is a DSA, we get r and s bigints
X509cert_signature_s_ofs = 40		; ""
X509cert_issuercn_ofs = 48		; string (we only care about the CN of the Name items)
X509cert_validafter_ofs = 56		; string (in YYMMDDHH24MISS with a trailing Z on it)
X509cert_validuntil_ofs = 64		; ""
X509cert_subjectcn_ofs = 72		; string (we only care about the CN of the Name items)
X509cert_public_n_ofs = 80		; bigint (rsa)
X509cert_public_e_ofs = 88		; bigint (rsa)
X509cert_public_p_ofs = 96		; bigint (dsa)
X509cert_public_q_ofs = 104		; bigint (dsa)
X509cert_public_g_ofs = 112		; bigint (dsa)
X509cert_public_dsa_ofs = 120		; bigint (dsa)
X509cert_altnames_ofs = 128		; list (of string)
X509cert_ocspuri_ofs = 136		; string
X509cert_caissuers_ofs = 144		; string

if used X509$ocsp | defined include_everything

X509cert_ocspresponse_ofs = 152		; buffer (or null)
X509cert_serialstart_ofs = 160		; dword offset to start of serialNumber (including tag/length)
X509cert_seriallength_ofs = 164		; dword length of serialNumber (so that we don't have to reencode it)
X509cert_issuerdnstart_ofs = 168	; dword offset to start of issuerDN (including tag/length)
X509cert_issuerdnlength_ofs = 172	; dword length of issuerDN
X509cert_publickeystart_ofs = 176	; dword offset to start of public key (excluding tag and length)
X509cert_publickeylength_ofs = 180	; dword length of public key (excluding tag and length)
X509cert_ocsprequest_ofs = 184		; buffer
X509cert_ocsphost_ofs = 192		; string hostname of ocspuri
X509cert_ocsptimer_ofs = 200		; pointer to an epoll timer object, or null if none is current
X509cert_signaturevalue_ofs = 208	; bytes, length determined by the signature type/algo

X509cert_size = 208 + 512		; we stick the signature straight into the X509cert object

else

X509cert_signaturevalue_ofs = 152	; bytes, length determined by the signature type/algo

X509cert_size = 152 + 512		; we stick the signature straight into the X509cert object

end if


if used X509$add_certificate | defined include_everything
	; three arguments: rdi == X509 object to add to, rsi == DER encoded buffer, rdx == length of same
	; returns bool in eax as to whether we succeeded or not
falign
X509$add_certificate:
	prolog	X509$add_certificate
	sub	rsp, 96
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	; we need some of our callee-saves
	mov	[rsp+24], rbx
	mov	[rsp+32], r12
	mov	[rsp+40], r13
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	cmp	qword [rdi+X509_certificates_ofs], 0
	jne	.listokay
	call	list$new
	mov	[rbx+X509_certificates_ofs], rax
calign
.listokay:
	call	list$new
	mov	[rsp+48], rax		; our "bigint undo" list in case we have to unwind all this, makes it much cleaner
	mov	edi, X509cert_size
	call	heap$alloc_clear
	mov	[rsp+56], rax		; our X509cert object

	call	list$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_altnames_ofs], rax

	call	list$new
	mov	[rsp+64], rax		; our "string undo" list in case we have to unwind all this, makes it much cleaner

	; make a full copy of our goods
	mov	rdi, r12
	mov	rsi, r13
	call	heap$alloc_blockcopy
	mov	rdx, [rsp+56]		; our X509cert object
	mov	[rdx+X509cert_der_ofs], rax
	mov	[rdx+X509cert_derlen_ofs], r13
	mov	rdi, [rsp+64]
	mov	rsi, rax
	call	list$push_back		; our "string undo" just calls heap$free_clear for everything in it, which is fine for this

	; from RFC 2459

	; first things first, we expect a sequence
	call	.gettag
	cmp	eax, 0x10		; we need it to start iwth a sequence, or die.
	jne	.kakked
	; next is our certificate sequence
	push	r12			; save the offset to the start of our sequence, because we'll need a copy of it
	call	.gettag
	pop	rdi			; start of our sequence in the buffer
	cmp	eax, 0x10		; this too must be a sequence, or die.
	jne	.kakked

	; mov	rdx, [rsp+56]		; our X509cert object
	; mov	[rdx+X509cert_derlen_ofs], r8
	; so at this point, we have the length of our der component saved
	; mov	rsi, r8
	; call	heap$alloc_blockcopy
	; mov	rdi, [rsp+56]		; our X509cert object
	; mov	[rdi+X509cert_der_ofs], rax
	; mov	rdi, [rsp+64]
	; mov	rsi, rax
	; call	list$push_back		; our "string undo" just calls heap$free_clear for everything in it, which is fine for this

	; version is first up
	call	.gettag
	cmp	ecx, 0xa0		; constructed | context_specific, type 0
	jne	.checkserial
	; otherwise, if we call gettag again, we should get an integer with length one
	call	.gettag
	cmp	eax, 0x2		; integer or die
	jne	.kakked
	cmp	r8d, 1			; length 1 or die
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; version must be less than or equal to 2
	cmp	eax, 2
	ja	.kakked
	; version is okay
	; serialNumber is next, it most likely fits in a 64 bit integer, but will be encoded as a variable length bigendian integer
if used X509$ocsp | defined include_everything
	; calculate the offset to our serial number
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rdi+X509cert_serialstart_ofs], eax
end if
	call	.gettag
calign
.checkserial:
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_serial_ofs], rax
if used X509$ocsp | defined include_everything
	; calculate the length, including the tag, of our serial number
	mov	rcx, r12
	sub	rcx, [rsp+8]
	sub	ecx, [rdi+X509cert_serialstart_ofs]
	mov	[rdi+X509cert_seriallength_ofs], ecx
end if
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our X509cert object
	mov	rdi, [rdi+X509cert_serial_ofs]
	call	bigint$debug
end if

	; next up is the signature, which is another sequence that contains an object identifier, then parameters
	call	.gettag
	cmp	eax, 0x10		; make sure it is a sequence, or die
	jne	.kakked

	call	.gettag
	cmp	eax, 0x6		; make sure it is an OID, or die.
	jne	.kakked
	cmp	r13, r8
	jb	.kakked			; make sure we have enough room left

	; if, and only if we are camped out on DSA-SHA1, we'll have a length of 7 bytes instead of 9
	cmp	r8d, 7
	je	.dsasigalg_sha1

	cmp	r8d, 9			; make sure its length is 9 bytes or die (noting here DSA-SHA1 handled above)
	jne	.kakked
	
	; determine whether it is an RSA or DSA signature algorithm
	mov	rax, [r12]
	cmp	rax, [.sigalgpreface+8]
	je	.dsasigalg
	cmp	rax, [.sigalgpreface]
	jne	.kakked			; not RSA or DSA, something weird and not in the wild for SSL, die
	
	; otherwise, we are camped out on an RSA signature algorithm, swallow the first 8 bytes that we already compared, and check the last byte
	mov	rdi, [rsp+56]		; our X509cert object
	add	r12, 8
	sub	r13, 8
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; we support precisely 4 RSA sigalgs
	xor	ecx, ecx		; use this as our spot
	mov	edx, 0x01		; RSA/SHA-160
	mov	r8d, 0x02		; RSA/SHA-256
	mov	r9d, 0x03		; RSA/SHA-384
	mov	r10d, 0x04		; RSA/SHA-512
	cmp	eax, 0x05
	cmove	ecx, edx
	cmp	eax, 0x0b
	cmove	ecx, r8d
	cmp	eax, 0x0c
	cmove	ecx, r9d
	cmp	eax, 0x0d
	cmove	ecx, r10d

	test	ecx, ecx
	jz	.kakked			; not one of the 4 we support
	; otherwise, we can use our constant in ecx as our sigalg
	mov	[rdi+X509cert_signature_ofs], rcx

	; now, we need precisely one NULL, no optional sigalgo parameters are present
	call	.gettag
	cmp	eax, 0x05		; NULL
	jne	.kakked
	test	r8d, r8d
	jnz	.kakked			; length must be zero for NULL

	; create two empty bigints for r & s even though they won't be used
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_signature_r_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_signature_s_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	jmp	.sigalgokay
calign
.dsasigalg_sha1:
	mov	rdi, [rsp+56]		; our X509cert object
	add	r12, 6
	sub	r13, 6
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; make sure it is a 3, or die
	cmp	eax, 3
	jne	.kakked			; not sitting on DSA-SHA1
	mov	qword [rdi+X509cert_signature_ofs], 0x05	; DSA/SHA-160
	jmp	.dsasigalg_okay
calign
.dsasigalg:
	mov	rdi, [rsp+56]		; our X509cert object
	add	r12, 8
	sub	r13, 8
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; we support precisely 2 DSA sigalgs (of the longer form anyway)
	xor	ecx, ecx		; use this as our spot
	mov	edx, 0x06		; DSA/SHA-224
	mov	r8d, 0x07		; DSA/SHA-256
	cmp	eax, 0x01
	cmove	ecx, edx
	cmp	eax, 0x02
	cmove	ecx, r8d
	test	ecx, ecx
	jz	.kakked			; not one of the 2 we support
	; otherwise, we can use our constant in ecx as our sigalg
	mov	[rdi+X509cert_signature_ofs], rcx
calign
.dsasigalg_okay:
	; RFC2459 section 7.2.2 says parameters are specifically omitted
	; create our r and s beforehand
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_signature_r_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_signature_s_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

calign
.sigalgokay:
	; issuer is next

if used X509$ocsp | defined include_everything
	; in the event we have to hash the issuer name, we need to store the start and end offsets
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rdi+X509cert_issuerdnstart_ofs], eax
end if

	call	.gettag
	cmp	eax, 0x10		; sequence or die
	jne	.kakked

	mov	rdi, r8			; length of the name sequence
	call	.getCN
	test	rax, rax
	jnz	.sigalgokay_CNokay
	; google returns us a certificate with no CN present... :-(
	call	string$new
calign
.sigalgokay_CNokay:
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_issuercn_ofs], rax
	mov	rdi, [rsp+64]		; our string undo list
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_issuercn_ofs]
	call	string$to_stdoutln
end if

if used X509$ocsp | defined include_everything
	; figure out the length of the complete issuerDN
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	sub	eax, [rdi+X509cert_issuerdnstart_ofs]
	mov	[rdi+X509cert_issuerdnlength_ofs], eax
end if
	
	; next up: validity sequence
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	jne	.kakked

	call	.gettag
	cmp	eax, 0x17		; UTC TIME OR DIE, we should _not_ get GENERALIZED TIME here...
	jne	.kakked
	cmp	r13, r8
	jb	.kakked			; not enough data to continue
	; else, create a string out of our current value
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	string$from_utf8
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_validafter_ofs], rax
	mov	rdi, [rsp+64]
	mov	rsi, rax
	call	list$push_back
	
if X509debug
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_validafter_ofs]
	call	string$to_stdoutln
end if

	; and one more for the valid until
	call	.gettag
	cmp	eax, 0x17		; UTC TIME OR DIE, we should _not_ get GENERALIZED TIME here...
	jne	.kakked
	cmp	r13, r8
	jb	.kakked			; not enough data to continue
	; else, create a string out of our current value
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	string$from_utf8
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_validuntil_ofs], rax
	mov	rdi, [rsp+64]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_validuntil_ofs]
	call	string$to_stdoutln
end if

	; next up: subject
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	jne	.kakked

	mov	rdi, r8
	call	.getCN
	test	rax, rax
	jz	.kakked
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_subjectcn_ofs], rax
	mov	rdi, [rsp+64]		; our string undo list
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_subjectcn_ofs]
	call	string$to_stdoutln
end if
	
	; next up: subjectPublicKeyInfo
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	jne	.kakked

	; subjectPublicKeyInfo AlgorithmIdentifier is next, which is also a sequence
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	jne	.kakked

	; OID is next
	; we support precisely 3 public key types here (well, 2, but one is an alternate)
	; 1.2.840.113549.1.1.1 -- RSA
	; 2.5.8.1.1 - RSA
	; 1.2.840.10040.4.1 -- DSA
	call	.gettag
	cmp	eax, 0x6		; OID or die
	jne	.kakked
	cmp	r13, r8
	jb	.kakked			; not enough data to proceed
	cmp	r8d, 9
	ja	.kakked
	je	.rsa9
	cmp	r8d, 4
	jb	.kakked
	je	.rsa4
	cmp	r8d, 7
	jne	.kakked
	; dsa7
	mov	rax, [r12]
	shl	rax, 8			; we are only interseted in 7 bytes, topmost on littleendian load is last, so we discard it
	cmp	rax, [.dsapublic]
	jne	.kakked
	; otherwise, we are indeed sitting on a dsa public key
	add	r12, r8
	sub	r13, r8

if used X509$ocsp | defined include_everything
	; record the start offset of the public key info excluding tag and length
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rdi+X509cert_publickeystart_ofs], eax
end if

	; so, if params are present, our following tag should be a sequence, and if it is a bitstring, then the CA's parameters apply and not this one
	call	.gettag
	cmp	eax, 0x03		; bit_string? the dsa public key is encoded as an integer inside the bit string
	je	.dsanoparams
	cmp	eax, 0x10		; sequence or die
	jne	.kakked
	; otherwise, we have 3 parameters for the DSA goods

	; p is first
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_public_p_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our X509cert object
	mov	rdi, [rdi+X509cert_public_p_ofs]
	call	bigint$debug
end if

	; q is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_public_q_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our X509cert object
	mov	rdi, [rdi+X509cert_public_q_ofs]
	call	bigint$debug
end if

	; last but not least, g
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_public_g_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our X509cert object
	mov	rdi, [rdi+X509cert_public_g_ofs]
	call	bigint$debug
end if

	; we also need to zero-populate the rsa side n and e
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_n_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_e_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	jmp	.dsapublickeytag
calign
.dsanoparams:
	; no params were specified for the dsa public key, but we need clear bigints in all five
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_p_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_q_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_g_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_n_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_e_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	mov	eax, 0x3
	jmp	.dsadopublickey		; tag already acquired here
calign
.rsa9:
	; length of the OID was 9, so check to make sure it matches .rsapublic
	mov	rax, [r12]
	cmp	rax, [.rsapublic]
	jne	.kakked
	add	r12, 8
	sub	r13, 8
	movzx	eax, byte [r12]
	cmp	eax, 1
	jne	.kakked
	add	r12, 1
	sub	r13, 1
	; else, it matches, there should be a NULL after this (cuz we are still in AlgorithmIdentifier)
	call	.gettag
	cmp	eax, 0x5
	jne	.kakked
	jmp	.rsapublickeytag
calign
.rsa4:
	mov	eax, [r12]
	cmp	eax, [.rsapublicalt]
	jne	.kakked
	add	r12, 4
	sub	r13, 4
	; fallthrough to rsapublickeytag
calign
.rsapublickeytag:
	; it appears that our public key is nestled inside a BIT STRING
	call	.gettag
	cmp	eax, 0x3		; BIT STRING or die
	jne	.kakked
	cmp	r13, r8
	jb	.kakked			; not enough data to proceed

	add	r12, 1
	sub	r13, 1

if used X509$ocsp | defined include_everything
	; record the start offset of the public key info excluding tag and length
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rdi+X509cert_publickeystart_ofs], eax
end if

	call	.gettag
	cmp	eax, 0x10		; sequence or die

	; we should have n and e integers
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_public_n_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our X509cert object
	mov	rdi, [rdi+X509cert_public_n_ofs]
	call	bigint$debug
end if

	; e is next
	call	.gettag
	cmp	eax, 0x2		; integer
	jne	.kakked
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked			; enough data left?
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_public_e_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]		; our X509cert object
	mov	rdi, [rdi+X509cert_public_e_ofs]
	call	bigint$debug
end if

	; populate the dsa ones with zero-but-valid bigints
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_p_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_q_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_g_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back
	
	call	bigint$new
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_public_dsa_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

	jmp	.publickeydone

calign
.dsapublickeytag:
	; TODO: redo this, we really need the length carried forward from dsanoparams, or at the very least, another check above for length minimums
	call	.gettag
.dsadopublickey:
	cmp	eax, 0x3		; bit_string or die
	jne	.kakked
	add	r12, 1
	sub	r13, 1			; skip the bit_string preface octet

if used X509$ocsp | defined include_everything
	; record the start offset of the public key info excluding tag and length
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	mov	[rdi+X509cert_publickeystart_ofs], eax
end if

	call	.gettag
	cmp	eax, 0x2		; integer or die
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jz	.kakked
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	rdi, [rsp+56]		; our X509cert object
	mov	[rdi+X509cert_public_dsa_ofs], rax
	mov	rdi, [rsp+48]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]
	mov	rdi, [rdi+X509cert_public_dsa_ofs]
	call	bigint$debug
end if

	; fallthrough to .publickeydone
calign
.publickeydone:

if used X509$ocsp | defined include_everything
	; record the length of our publickeyinfo goods
	mov	rdi, [rsp+56]
	mov	rax, r12
	sub	rax, [rsp+8]
	sub	eax, [rdi+X509cert_publickeystart_ofs]
	mov	[rdi+X509cert_publickeylength_ofs], eax
end if

	call	.gettag
	; so, for our optional issueruniqueid and optional subject uniqueid
	; if the class is only context_specific and our type is 1
	; or if the class is context_specific and our type is 2
	; then we can skip over them
	; then, if class is constructed | context_specific and type is 3, then extensions is a bit string,
	; and otherwise, we are done and need to bailout to the signature algorithm
	cmp	r13, r8
	jb	.kakked

	; so easy check first, fi this is an object id, jump straight to the sigalgo
	cmp	eax, 0x10
	je	.sigalgo_seqtagpresent
	
	mov	edx, ecx
	and	edx, 0xa0
	cmp	edx, 0xa0
	je	.extensionsonly
	; otherwise, we must have one of the other optionals, skip them as we aren't interested
	add	r12, r8
	sub	r13, r8
	jmp	.publickeydone
calign
.extensionsonly:
	cmp	eax, 3
	jne	.kakked

	; why isn't this one prefaced by a leading octet like the others? ahh, maybe that is only for primitives or something
	; nfi

	; and now we expect a sequence of all our extensions... 
	call	.gettag
	cmp	eax, 0x10
	jne	.kakked

	; otherwise, we need to save our length so we know when to bailout, because
	; immediately following this extension list, is the signature algorithm
	; which is also a sequence folloewd by an OID
	mov	rdx, r13
	sub	rdx, r8
	mov	[rsp+72], rdx

	cmp	r13, r8
	jb	.kakked
calign
.extensionloop:
	cmp	r13, [rsp+72]
	jbe	.sigalgo

	; each extension is a SEQUENCE
	call	.gettag
	cmp	eax, 0x10
	jne	.kakked

	call	.gettag
	cmp	eax, 0x6
	jne	.kakked
	cmp	r13, r8
	jb	.kakked

	; Sooooooooooooooooooooo, our extensions we recognize are:
	; oid length 3:
	; 2.5.29.14	X509v3 SubjectKeyIdentifier				0x0e1d5500
	; 2.5.29.15	X509v3 KeyUsage						0x0f1d5500
	; 2.5.29.17	X509v3 SubjectAlternativeName				0x111d5500
	; 2.5.29.18	X509v3 IssuerAlternativeName				0x121d5500
	; 2.5.29.19	X509v3 BasicConstraints					0x131d5500
	; 2.5.29.20	X509v3 CRLNumber					0x141d5500
	; 2.5.20.21	X509v3 ReasonCode					0x151d5500
	; 2.5.20.23	X509v3 HoldInstructionCode				0x171d5500
	; 2.5.20.24	X509v3 InvalidityDate					0x181d5500
	; 2.5.20.31	X509v3 CRLDistributionPoints				0x1f1d5500
	; 2.5.20.32	X509v3 CertificatePolicies				0x201d5500
	; 2.5.20.35	X509v3 AuthorityKeyIdentifier				0x231d5500
	; 2.5.20.36	X509v3 PolicyConstraints				0x241d5500
	; 2.5.20.37	X509v3 ExtendedKeyUsage					0x251d5500
	; oid length 4:
	; 2.5.29.32.0	X509v3 AnyPolicy					0x00201d55
	; oid length 8:
	; 1.3.6.1.5.5.7.1.1	PKIX	AuthorityInformationAccess		0x010107050501062b
	; all of these are not extensions as such but part of the authorityinformationaccess
	; 1.3.6.1.5.5.7.3.1	PKIX	ServerAuth				0x010307050501062b
	; 1.3.6.1.5.5.7.3.2	PKIX	ClientAuth				0x020307050501062b
	; 1.3.6.1.5.5.7.3.3	PKIX	CodeSigning				0x030307050501062b
	; 1.3.6.1.5.5.7.3.4	PKIX	EmailProtection				0x040307050501062b
	; 1.3.6.1.5.5.7.3.5	PKIX	IPsecEndSystem				0x050307050501062b
	; 1.3.6.1.5.5.7.3.6	PKIX	IPsecTunnel				0x060307050501062b
	; 1.3.6.1.5.5.7.3.7	PKIX	IPsecUser				0x070307050501062b
	; 1.3.6.1.5.5.7.3.8	PKIX	TimeStamping				0x080307050501062b
	; 1.3.6.1.5.5.7.3.9	PKIX	OCSPSigning				0x090307050501062b
	; 1.3.6.1.5.5.7.48.1	PKIX	OCSP					0x013007050501062b
	; 1.3.6.1.5.5.7.48.2	PKIX	CAIssuers				0x023007050501062b
	; 1.3.6.1.5.5.7.8.5	PKIX	XMPPAddr				0x050807050501062b
	; oid length 9:
	; 1.3.6.1.5.5.7.48.1.1	PKIX	OCSP BasicResponse			same as OSCP but with a trailing 0x01 byte after it

	cmp	r8d, 3
	je	.extension3
	cmp	r8d, 4
	je	.extension4
	cmp	r8d, 8
	je	.extension8
	cmp	r8d, 9
	je	.extension9
calign
.extension_skip:
	; otherwise, we need to SKIP it (because it isn't necessarily an error to receive ones we don't recognize, UNLESS the critical
	; flag is specified)
	add	r12, r8
	sub	r13, r8
	; next one better be a bool
	call	.gettag
	cmp	eax, 0x1		; bool?
	jne	.extension_skip_nocrit
	cmp	r8d, 1
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	cmp	byte [r12], 0
	jne	.kakked			; critical set for an extension that we don't understand == outta here
	add	r12, 1
	sub	r13, 1
	call	.gettag
calign
.extension_skip_nocrit:
	cmp	eax, 0x4
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	add	r12, r8
	sub	r13, r8
	jmp	.extensionloop
calign
.extension_skip_ignorecrit:
	; used for ones we recognized but don't really care about [yet]
	add	r12, r8
	sub	r13, r8
	; next one is either a bool _or_ the value
	call	.gettag
	cmp	eax, 0x1
	jne	.extension_skip_ignorecrit_nobool
	cmp	r8d, 1
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	; this section we are ignoring whether it is crit
	; cmp	byte [r12], 0
	; jne	.kakked			; critical set for an extension that we don't understand == outta here
	add	r12, 1
	sub	r13, 1
	call	.gettag
calign
.extension_skip_ignorecrit_nobool:
	cmp	eax, 0x4
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	add	r12, r8
	sub	r13, r8
	jmp	.extensionloop
calign
.extension3:
	; 3 byte OID length, so we'll grab a dword and shl it by 8
	mov	eax, [r12]
	shl	eax, 8
	cmp	eax, 0x0e1d5500		; SubjectKeyIdentifier
	je	.extension_skip_ignorecrit
	cmp	eax, 0x0f1d5500		; KeyUsage
	je	.extension_skip_ignorecrit
	cmp	eax, 0x111d5500		; SubjectAlternativeName
	je	.extSubjectAlternativeName
	cmp	eax, 0x121d5500		; IssuerAlternativeName
	je	.extension_skip_ignorecrit
	cmp	eax, 0x131d5500		; BasicConstraints
	je	.extension_skip_ignorecrit
	cmp	eax, 0x141d5500		; CRLNumber
	je	.extension_skip_ignorecrit
	cmp	eax, 0x151d5500		; ReasonCode
	je	.extension_skip_ignorecrit
	cmp	eax, 0x171d5500		; HoldInstructionCode
	je	.extension_skip_ignorecrit
	cmp	eax, 0x181d5500		; InvalidityDate
	je	.extension_skip_ignorecrit
	cmp	eax, 0x1f1d5500		; CRLDistributionPoints
	je	.extension_skip_ignorecrit
	cmp	eax, 0x201d5500		; CertificatePolicies
	je	.extension_skip_ignorecrit
	cmp	eax, 0x231d5500		; AuthorityKeyIdentifier
	je	.extension_skip_ignorecrit
	cmp	eax, 0x241d5500		; PolicyConstraints
	je	.extension_skip_ignorecrit
	cmp	eax, 0x251d5500		; ExtendedKeyUsage
	je	.extension_skip_ignorecrit
	jmp	.extension_skip
calign
.extension4:
	mov	eax, [r12]
	cmp	eax, 0x00201d55		; AnyPolicy
	je	.extension_skip_ignorecrit
	jmp	.extension_skip
dalign
.AuthorityInformationAccess:	dq	0x010107050501062b
.ServerAuth:			dq	0x010307050501062b
.ClientAuth:			dq	0x020307050501062b
.CodeSigning:			dq	0x030307050501062b
.EmailProtection:		dq	0x040307050501062b
.IPsecEndSystem:		dq	0x050307050501062b
.IPsecTunnel:			dq	0x060307050501062b
.IPsecUser:			dq	0x070307050501062b
.TimeStamping:			dq	0x080307050501062b
.OCSPSigning:			dq	0x090307050501062b
.OCSP:				dq	0x013007050501062b
.CAIssuers:			dq	0x023007050501062b
.XMPPAddr:			dq	0x050807050501062b
calign
.extension8:
	mov	rax, [r12]
	cmp	rax, [.AuthorityInformationAccess]
	je	.extAuthorityInformationAccess
if defined authinfoaccessbits
	cmp	rax, [.ServerAuth]
	je	.extension_skip_ignorecrit
	cmp	rax, [.ClientAuth]
	je	.extension_skip_ignorecrit
	cmp	rax, [.CodeSigning]
	je	.extension_skip_ignorecrit
	cmp	rax, [.EmailProtection]
	je	.extension_skip_ignorecrit
	cmp	rax, [.IPsecEndSystem]
	je	.extension_skip_ignorecrit
	cmp	rax, [.IPsecTunnel]
	je	.extension_skip_ignorecrit
	cmp	rax, [.IPsecUser]
	je	.extension_skip_ignorecrit
	cmp	rax, [.TimeStamping]
	je	.extension_skip_ignorecrit
	cmp	rax, [.OCSPSigning]
	je	.extension_skip_ignorecrit
	cmp	rax, [.OCSP]
	je	.extension_skip_ignorecrit
	cmp	rax, [.XMPPAddr]
	je	.extension_skip_ignorecrit
end if
	jmp	.extension_skip
calign
.extension9:
	mov	rax, [r12]
	cmp	rax, [.OCSP]
	jne	.extension_skip
	movzx	eax, byte [r12+8]
	cmp	eax, 1
	jne	.extension_skip
	jmp	.extension_skip_ignorecrit

; and, the extensions we care about:
calign
.extSubjectAlternativeName:
	; skip our OID first
	add	r12, r8
	sub	r13, r8
	; next tag is the critical bool
	call	.gettag
	cmp	eax, 0x1
	jne	.extSubjectAlternativeName_nocrit
	cmp	r8d, 1
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	add	r12, 1
	sub	r13, 1
	; next tag is the octet string:
	call	.gettag
calign
.extSubjectAlternativeName_nocrit:
	cmp	eax, 0x4
	jne	.kakked			; OCTET STRING or die
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	; we need to store the length of this sequence so that we know when to bailout as well
	cmp	r13, r8
	jb	.kakked
	mov	rdx, r13
	sub	rdx, r8
	mov	[rsp+80], rdx
	; so now, we have to iterate over this sequence and extract all string variants
calign
.extSubjectAlternativeName_loop:
	cmp	r13, [rsp+80]
	jbe	.extensionloop
	call	.gettag
	test	eax, eax
	jz	.extSubjectAlternativeName_skip
	cmp	eax, 3
	je	.extSubjectAlternativeName_skip
	cmp	eax, 4
	je	.extSubjectAlternativeName_skip
	cmp	eax, 5
	je	.extSubjectAlternativeName_skip
	cmp	eax, 7
	je	.extSubjectAlternativeName_skip
	cmp	eax, 8
	jae	.extSubjectAlternativeName_skip
	; else, we have an extractable normal sorta string, grab it
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	string$from_utf8
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_altnames_ofs]
	mov	rsi, rax
	call	list$push_back
	jmp	.extSubjectAlternativeName_loop
calign
.extSubjectAlternativeName_skip:
	add	r12, r8
	sub	r13, r8
	jmp	.extSubjectAlternativeName_loop
calign
.extAuthorityInformationAccess:
	; skip our OID first
	add	r12, r8
	sub	r13, r8
	; next tag is the critical bool
	call	.gettag
	cmp	eax, 0x1
	jne	.extAuthorityInformationAccess_nocrit
	cmp	r8d, 1
	jne	.kakked
	cmp	r13, r8
	jb	.kakked
	add	r12, 1
	sub	r13, 1
	; next tag is the octet string:
	call	.gettag
calign
.extAuthorityInformationAccess_nocrit:
	cmp	eax, 0x4
	jne	.kakked			; OCTET STRING or die
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	; we need to store the length of this sequence so that we know when to bailout as well
	cmp	r13, r8
	jb	.kakked
	mov	rdx, r13
	sub	rdx, r8
	mov	[rsp+80], rdx
	; so now, we have to iterate over this sequence and extract all string variants
calign
.extAuthorityInformationAccess_loop:
	cmp	r13, [rsp+80]
	jbe	.extensionloop
	call	.gettag
	cmp	eax, 0x10		; sequence or die
	jne	.kakked
	call	.gettag
	cmp	eax, 0x6		; OID or die
	jne	.kakked
	mov	rax, [r12]
	cmp	rax, [.OCSP]
	je	.extAuthorityInformationAccess_OSCP
	cmp	rax, [.CAIssuers]
	je	.extAuthorityInformationAccess_CAIssuers
	; otherwise, skip this one entirely
	add	r12, r8
	sub	r13, r8
	; next one is a GeneralName
	call	.gettag
	add	r12, r8
	sub	r13, r8
	jmp	.extAuthorityInformationAccess_loop
calign
.extAuthorityInformationAccess_OSCP:
	add	r12, r8
	sub	r13, r8
	; next one is a GeneralName
	call	.gettag
	test	eax, eax
	jz	.extAuthorityInformationAccess_skip
	cmp	eax, 3
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 4
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 5
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 7
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 8
	jae	.extAuthorityInformationAccess_skip
	; otherwise, we have an OSCP string
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	string$from_utf8
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_ocspuri_ofs], rax
	mov	rdi, [rsp+64]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, .debugocspuri
	call	string$to_stdout
	mov	rdi, [rsp+56]
	mov	rdi, [rdi+X509cert_ocspuri_ofs]
	call	string$to_stdoutln
	jmp	.extAuthorityInformationAccess_loop
cleartext .debugocspuri, 'OCSP URI: '
else
	jmp	.extAuthorityInformationAccess_loop
end if
calign
.extAuthorityInformationAccess_skip:
	add	r12, r8
	sub	r13, r8
	jmp	.extAuthorityInformationAccess_loop
calign
.extAuthorityInformationAccess_CAIssuers:
	add	r12, r8
	sub	r13, r8
	; next one is a GeneralName
	call	.gettag
	test	eax, eax
	jz	.extAuthorityInformationAccess_skip
	cmp	eax, 3
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 4
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 5
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 7
	je	.extAuthorityInformationAccess_skip
	cmp	eax, 8
	jae	.extAuthorityInformationAccess_skip
	; otherwise, we have an OSCP string
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	string$from_utf8
	mov	rdi, [rsp+56]
	mov	[rdi+X509cert_caissuers_ofs], rax
	mov	rdi, [rsp+64]
	mov	rsi, rax
	call	list$push_back

if X509debug
	mov	rdi, [rsp+56]
	mov	rdi, [rdi+X509cert_caissuers_ofs]
	call	string$to_stdoutln
end if
	
	jmp	.extAuthorityInformationAccess_loop
calign
.sigalgo:
	; so if we made it to here, everything parsed okay for tbsCertificate
	; next in line is the signatureAlgorithm
	call	.gettag
	cmp	eax, 0x10		; make sure it is a sequence, or die
	jne	.kakked

.sigalgo_seqtagpresent:
	call	.gettag
	cmp	eax, 0x6		; make sure it is an OID, or die.
	jne	.kakked

	cmp	r13, r8
	jb	.kakked			; make sure we have enough room left

	cmp	r8d, 7
	je	.sigalgo_dsa7

	cmp	r8d, 9			; make sure its length is 9 bytes or die (noting here we are tossing DSA-SHA1 out on purpose)
	jne	.kakked
	
	; determine whether it is an RSA or DSA signature algorithm
	mov	rax, [r12]
	cmp	rax, [.sigalgpreface+8]
	je	.sigalgo_dsa
	cmp	rax, [.sigalgpreface]
	jne	.kakked			; not RSA or DSA, something weird and not in the wild for SSL, die
	
	; otherwise, we are camped out on an RSA signature algorithm, swallow the first 8 bytes that we already compared, and check the last byte
	mov	rdi, [rsp+56]		; our X509cert object
	add	r12, 8
	sub	r13, 8
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; we support precisely 4 RSA sigalgs
	xor	ecx, ecx		; use this as our spot
	mov	edx, 0x01		; RSA/SHA-160
	mov	r8d, 0x02		; RSA/SHA-256
	mov	r9d, 0x03		; RSA/SHA-384
	mov	r10d, 0x04		; RSA/SHA-512
	cmp	eax, 0x05
	cmove	ecx, edx
	cmp	eax, 0x0b
	cmove	ecx, r8d
	cmp	eax, 0x0c
	cmove	ecx, r9d
	cmp	eax, 0x0d
	cmove	ecx, r10d
	test	ecx, ecx
	jz	.kakked			; not one of the 4 we support
	; otherwise, we can use our constant in ecx as our sigalg
	cmp	ecx, dword [rdi+X509cert_signature_ofs]
	jne	.kakked			; must be the same one we had before

	; now, we need precisely one NULL
	call	.gettag
	cmp	eax, 0x05		; NULL
	jne	.kakked
	test	r8d, r8d
	jnz	.kakked			; length must be zero for NULL

	jmp	.signature
calign
.sigalgo_dsa7:
	mov	rdi, [rsp+56]		; our X509cert object
	add	r12, 6
	sub	r13, 6
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	cmp	eax, 3			; DSA/SHA-160
	jne	.kakked
	cmp	dword [rdi+X509cert_signature_ofs], 0x05
	jne	.kakked			; must be the same one we had before
	jmp	.sigalgo_dsa_okay

calign
.sigalgo_dsa:
	mov	rdi, [rsp+56]		; our X509cert object
	add	r12, 8
	sub	r13, 8
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; we support precisely 2 DSA sigalgs
	xor	ecx, ecx		; use this as our spot
	mov	edx, 0x06		; DSA/SHA-224
	mov	r8d, 0x07		; DSA/SHA-256
	cmp	eax, 0x01
	cmove	ecx, edx
	cmp	eax, 0x02
	cmove	ecx, r8d
	test	ecx, ecx
	jz	.kakked			; not one of the 2 we support
	; otherwise, we can use our constant in ecx as our sigalg
	cmp	ecx, dword [rdi+X509cert_signature_ofs]
	jne	.kakked			; must be the same one we had before
calign
.sigalgo_dsa_okay:
	; heh, ok so... the signature is encoded as a bit string, but is actually
	; an ASN1 sequence containing r and s inside it
	; for now, jump straight to the signature bit... TODO: breakout r and s
	jmp	.signature


	; read in r and s
	call	.gettag
	cmp	eax, 0x10
	jne	.kakked
	cmp	r13, r8
	jb	.kakked

	; r is first
	call	.gettag
	mov	rdi, [rsp+56]		; our X509cert object
	cmp	eax, 0x2		; integer
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, [rdi+X509cert_signature_r_ofs]
	mov	rsi, r12
	mov	rdx, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$set_encoded

if X509debug
	mov	rdi, [rsp+56]
	mov	rdi, [rdi+X509cert_signature_r_ofs]
	call	bigint$debug
end if

	; then s
	call	.gettag
	mov	rdi, [rsp+56]		; our X509cert object
	cmp	eax, 0x2		; integer
	test	r8d, r8d
	jz	.kakked
	cmp	r13, r8
	jb	.kakked
	mov	rdi, [rdi+X509cert_signature_s_ofs]
	mov	rsi, r12
	mov	rdx, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$set_encoded

if X509debug
	mov	rdi, [rsp+56]
	mov	rdi, [rdi+X509cert_signature_s_ofs]
	call	bigint$debug
end if

calign
.signature:
	call	.gettag
	cmp	eax, 0x3		; bit string or die
	cmp	r13, r8
	jb	.kakked			; not enough data for it
	cmp	r8, 513
	ja	.kakked
	add	r12, 1			; skip the bit string preface byte
	sub	r13, 1			;
	sub	r8, 1

	mov	rcx, [rsp+56]
	lea	rdi, [rcx+X509cert_signaturevalue_ofs]
	mov	rsi, r12
	mov	rdx, r8
	call	memcpy

	; if there are trailing bytes, do we care? I don't think we do
	
	; cleanup our undo lists
	mov	rdi, [rsp+48]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free_clear

	mov	rdi, [rsp+64]
	xor	esi, esi
	call	list$clear
	mov	rdi, [rsp+64]
	call	heap$free_clear

	; last but not least, we need to add our rsaprivate object to our X509 object
	mov	rdi, [rbx+X509_certificates_ofs]
	mov	rsi, [rsp+56]
	call	list$push_back

	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]

	add	rsp, 96
	mov	eax, 1			; success.
	epilog
calign
.kakked:
	mov	rdi, [rsp+48]
	mov	rsi, bigint$destroy_clear
	call	list$clear
	mov	rdi, [rsp+48]
	call	heap$free_clear
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_altnames_ofs]
	mov	rsi, heap$free
	call	list$clear
	mov	rsi, [rsp+56]
	mov	rdi, [rsi+X509cert_altnames_ofs]
	call	heap$free

	mov	rdi, [rsp+56]
	call	heap$free_clear

	mov	rdi, [rsp+64]
	mov	rsi, heap$free_clear
	call	list$clear
	mov	rdi, [rsp+64]
	call	heap$free_clear

	mov	rbx, [rsp+24]
	mov	r12, [rsp+32]
	mov	r13, [rsp+40]
	add	rsp, 96
	xor	eax, eax		; fail.
	epilog
falign
.gettag:
	asn1_tag
	ret
falign
.getCN:
	; passed in rdi is the overall total length of the Name sequence itself, which is then comprised
	; of a SET OF AttributeTypeAndValue
	sub	rsp, 16
	cmp	r13, rdi
	jb	.getCN_failed		; not enough for our total sequence
	mov	rax, r13
	sub	rax, rdi
	mov	[rsp], rax		; our cutoff to stop our sequence searching
	mov	qword [rsp+8], 0	; our return string
calign
.getCN_loop:
	cmp	r13, [rsp]
	jbe	.getCN_return		; we got to the end of the name sequence

	call	.gettag
	cmp	eax, 0x11		; SET OF or die
	jne	.getCN_failed

	; SET OF AttributeTypeAndValue, AttributeTypeAndValue == SEQUENCE { OID, Value }
	; so, we need a SEQUENCE next
	call	.gettag
	cmp	eax, 0x10		; SEQUENCE or die
	jne	.getCN_failed

	; next up is our object id
	call	.gettag
	cmp	eax, 0x6		; OID or die
	jne	.getCN_failed

	cmp	r8d, 0x3		; length == 3 or its not an X520 object id
	jne	.getCN_loop_checkPKCS9
	cmp	r13, r8
	jb	.getCN_failed		; not enough data
	; first word at r12 must be 0x0455
	movzx	eax, word [r12]
	add	r12, 2
	sub	r13, 2
	cmp	eax, 0x455
	jne	.getCN_failed		; not an X520 object id
	movzx	eax, byte [r12]
	add	r12, 1
	sub	r13, 1
	; eax one of:
	; 03 == CommonName (the one we are after)
	; 04 == Surname
	; 05 == SerialNumber
	; 06 == Country
	; 07 == Locality
	; 08 == State
	; 0a == Organization
	; 0b == OrganizationalUnit
	; 0c == Title
	; 2a == GivenName
	; 2b == Initials
	; 2c == GenerationalQualifier
	; 2e == DNQualifier
	; 41 == Pseudonym
	cmp	eax, 0x03
	jb	.getCN_failed
	je	.getCN_extract
	cmp	eax, 0x09
	je	.getCN_failed
	jb	.getCN_skip
	cmp	eax, 0x0d
	jb	.getCN_skip
	cmp	eax, 0x2a
	je	.getCN_skip
	cmp	eax, 0x2b
	je	.getCN_skip
	cmp	eax, 0x2c
	je	.getCN_skip
	cmp	eax, 0x2e
	je	.getCN_skip
	cmp	eax, 0x41
	je	.getCN_skip

	; NOTE TO SELF: google gives me back a bunch of other X520 goods like postalAddress, (2.5.4.16, etc)
	; instead of puking here with a failure, we will default to just skip over ones we don't necessarily
	; recognize
	; jmp	.getCN_skip
	; jmp	.getCN_failed
	; fallthrough to skip
calign
.getCN_skip:
	; so, we got a recognized X520 OID, next is the value of same
	call	.gettag
	cmp	r13, r8
	jb	.getCN_failed
	add	r12, r8
	sub	r13, r8
	jmp	.getCN_loop
dalign
.PKCS9preface:
	db	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09
calign
.getCN_loop_checkPKCS9:
	cmp	r8d, 0x9	; length == 9 or its not a PKCS9 object id
	jne	.getCN_failed
	; so we have 9 bytes at r12, match the first 8
	mov	rax, qword [.PKCS9preface]
	cmp	qword [r12], rax
	jne	.getCN_failed
	; otherwise, advance r12
	add	r12, 9
	sub	r13, 9
	jmp	.getCN_skip
calign
.getCN_extract:
	; we got the CN we are interested in, extract it and keep going
	call	.gettag
	; string type better be here
	cmp	r13, r8
	jb	.getCN_failed	; not enough data remains

	; for BMPString, they are 2-octet characters, for UniversalString, they are 4-octet characters, big-endian encoded
	cmp	eax, 0x13	; PRINTABLE STRING
	je	.getCN_extract_normal
	cmp	eax, 0x0c	; UTF8 STRING
	je	.getCN_extract_normal
	cmp	eax, 0x12	; NUMERIC STRING
	je	.getCN_extract_normal
	cmp	eax, 0x14	; T61 STRING
	je	.getCN_extract_normal
	cmp	eax, 0x15	; VIDEOTEX STRING
	je	.getCN_extract_normal
	cmp	eax, 0x16	; IA5 STRING
	je	.getCN_extract_normal
	cmp	eax, 0x19	; GRAPHIC STRING
	je	.getCN_extract_normal
	cmp	eax, 0x1a	; VISIBLE STRING
	je	.getCN_extract_normal
	cmp	eax, 0x1b	; GENERAL STRING
	je	.getCN_extract_normal
	cmp	eax, 0x1e	; BMP STRING
	je	.getCN_extract_ucs2
	cmp	eax, 0x1c	; UNIVERSAL STRING
	je	.getCN_extract_ucs4
	jmp	.getCN_failed
calign
.getCN_extract_normal:
	; just construct a normal string from whatever is here (which may not necessarily be right, but hey, it is safe to do it)
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	string$from_utf8
	mov	[rsp+8], rax
	jmp	.getCN_loop
calign
.getCN_extract_ucs2:
	; we need to byte flip however many words we have
	test	r8, 1
	jnz	.getCN_failed		; not divisible by 2
	; we can use below our current stackframe to do this
	mov	rdi, rsp
	sub	rdi, r8
	sub	rdi, r8			; x2 because our call to string will consume some stack as well
	mov	rsi, r8
	mov	rdx, rdi
calign
.getCN_extract_ucs2_loop:
	movzx	eax, word [r12]
	add	r12, 2
	sub	r13, 2
	xchg	ah, al
	mov	word [rdx], ax
	add	rdx, 2
	sub	r8, 2
	jnz	.getCN_extract_ucs2_loop
	call	string$from_utf16
	mov	[rsp+8], rax
	jmp	.getCN_loop
calign
.getCN_extract_ucs4:
	; we need to byte flip however many words we have
	test	r8, 3
	jnz	.getCN_failed		; not divisible by 4
	; we can use below our current stackframe to do this
	mov	rdi, rsp
	sub	rdi, r8
	sub	rdi, r8			; x2 because our call to string will consume some stack as well
	mov	rsi, r8
	mov	rdx, rdi
calign
.getCN_extract_ucs4_loop:
if use_movbe
	movbe	eax, [r12]
	add	r12, 4
	sub	r13, 4
else
	mov	eax, [r12]
	add	r12, 4
	sub	r13, 4
	bswap	eax
end if
	mov	[rdx], eax
	add	rdx, 4
	sub	r8, 4
	jnz	.getCN_extract_ucs4_loop
	call	string$from_utf32
	mov	[rsp+8], rax
	jmp	.getCN_loop
calign
.getCN_return:
	mov	rax, [rsp+8]		; if we indeed found a CN, then we set our return to it
	add	rsp, 16
	ret
calign
.getCN_failed:
	xor	eax, eax
	add	rsp, 16
	ret

dalign
.sigalgpreface:
	dq	0x01010df78648862a	; RSA, OID starts with: 1.2.840.113549.1.1.
	dq	0x0304036501488660	; DSA, OID starts with: 2.16.840.1.101.3.4.3.
.dsapublic:
	dq	0x010438ce48862a00	; DSA public key OID
.rsapublic:
	dq	0x01010df78648862a	; RSA public key OID (first 8 bytes), followed by a 0x01
.rsapublicalt:
	dd	0x01010855		; RSA alternate public key OID
	

end if

if used X509$new_ssh | defined include_everything
	; single argument: rdi == 0 == search /etc/ssh, else == string of directory name to search
	; returns bool in eax as to whether we found _everything_ we were looking for or not
falign
X509$new_ssh:
	prolog	X509$new_ssh
	mov	rsi, .defaultdir
	test	rdi, rdi
	cmovz	rdi, rsi
	sub	rsp, 48
	mov	[rsp], rdi		; save the source directory for re-use
	mov	edi, X509_size
	call	heap$alloc_clear
	mov	[rsp+8], rax		; our X509 return object if all goes well
	; we need a working buffer
	call	buffer$new
	mov	[rsp+24], rax
	; load up our private keys first
	mov	rdi, [rsp]
	mov	rsi, .rsakey
	call	string$concat
	mov	[rsp+16], rax
	mov	rdi, rax
	call	file$mtime
	test	eax, eax
	jz	.dsaload
	; otherwise, we got a mtime, so load up the file so we can parse it
	mov	rdi, [rsp+16]
	call	file$to_string
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free		; get rid of our concatenated filename
	; so now we have the base64 version of our DER goodies (hopefully) sitting in [rsp+16]
	; parse it for the goods we are looking for
	xor	edx, edx
	mov	[rsp+32], rdx		; search position
calign
.psearch:
	mov	rdi, [rsp+16]
	mov	rsi, .rsaprivatekey
	mov	rdx, [rsp+32]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.dsaload
	; rax contains the index of the start we are after
	mov	[rsp+40], rax
	mov	rdi, [rsp+16]
	mov	rsi, .rsaprivateend
	mov	rdx, rax
	call	string$indexof_ofs
	cmp	rax, -1
	je	.dsaload
	mov	[rsp+32], rax		; save the next search start location
	mov	rdi, [rsp+16]
	mov	rsi, [rsp+40]
	add	rsi, qword [.rsaprivatekey]
	mov	rdx, rax
	call	string$substring
	; so now we have a string representation of just the base64 encoded bit
	mov	[rsp+40], rax
	; it is assumed our working buffer is already clear/reset
	mov	rdi, [rsp+24]
	mov	rsi, rax
	xor	edx, edx
	call	buffer$append_base64decode
	mov	rcx, [rsp+24]		; working buffer
	mov	rdi, [rsp+8]		; X509 return object
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	X509$add_privatekey
	mov	rdi, [rsp+24]
	call	buffer$reset
	mov	rdi, [rsp+40]
	call	heap$free		; free our substring
	jmp	.psearch
calign
.dsaload:
	mov	rdi, [rsp+16]
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, .dsakey
	call	string$concat
	mov	[rsp+16], rax
	mov	rdi, rax
	call	file$mtime
	test	eax, eax
	jz	.csearch
	; otherwise, we got a mtime, so load up the file so we can parse it
	mov	rdi, [rsp+16]
	call	file$to_string
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free		; get rid of our concatenated filename
	; so now we have the base64 version of our DER goodies (hopefully) sitting in [rsp+16]
	; parse it for the goods we are looking for
	xor	edx, edx
	mov	[rsp+32], rdx
calign
.dsearch:
	; dsa private keys next
	mov	rdi, [rsp+16]
	mov	rsi, .dsaprivatekey
	mov	rdx, [rsp+32]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.csearch
	; rax contains the index of the start we are after
	mov	[rsp+40], rax
	mov	rdi, [rsp+16]
	mov	rsi, .dsaprivateend
	mov	rdx, rax
	call	string$indexof_ofs
	cmp	rax, -1
	je	.csearch
	mov	[rsp+32], rax		; save the next search start location
	mov	rdi, [rsp+16]
	mov	rsi, [rsp+40]
	add	rsi, qword [.dsaprivatekey]
	mov	rdx, rax
	call	string$substring
	; so now we have a string representation of just the base64 encoded bit
	mov	[rsp+40], rax
	; it is assumed our working buffer is already clear/reset
	mov	rdi, [rsp+24]
	mov	rsi, rax
	xor	edx, edx
	call	buffer$append_base64decode
	mov	rcx, [rsp+24]		; working buffer
	mov	rdi, [rsp+8]		; X509 return object
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	X509$add_dsaprivatekey
	mov	rdi, [rsp+24]
	call	buffer$reset
	mov	rdi, [rsp+40]
	call	heap$free		; free our substring
	jmp	.dsearch
calign
.csearch:
	mov	rdi, [rsp+16]
	call	heap$free
	mov	rdi, [rsp+8]
	mov	rsi, [rdi+X509_privatekey_ofs]
	or	rsi, [rdi+X509_dsaprivatekey_ofs]
	jz	.failed
	; otherwise, we need to load and parse the "special" ssh pub key format (why didn't they just use X509v3 like everything else?)

	mov	rdi, [rsp]
	mov	rsi, .rsapub
	call	string$concat
	mov	[rsp+16], rax
	mov	rdi, rax
	call	file$mtime
	test	eax, eax
	jz	.dpsearch
	call	buffer$new
	mov	rdi, [rsp+8]
	mov	[rdi+X509_pubkey_ofs], rax	; our buffer object to hold the goods
	mov	rdi, [rsp+16]
	call	file$to_string
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
	; so now we know that our base64 data is the second "column" (ssh-rsa AAAA... user@host)
	; and further, that the ssh-rsa is static, so get a substring of our goods starting at offset 8, up to the next space
	mov	rdi, [rsp+16]
	mov	esi, ' '
	mov	edx, 8
	call	string$indexof_charcode_ofs
	cmp	rax, 0
	jl	.dpsearch			; something went wrong
	mov	rdi, [rsp+16]
	mov	esi, 8
	mov	rdx, rax
	call	string$substring
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
if X509debug
	mov	rdi, .rsapubmsg
	call	string$to_stdout
	mov	rdi, [rsp+16]
	call	string$to_stdout
	mov	rdi, .rsapubmsg2
	call	string$to_stdoutln
end if
	; now we need our base64 decoded goods into our buffer
	mov	rdi, [rsp+8]
	mov	rdi, [rdi+X509_pubkey_ofs]
	mov	rsi, [rsp+16]
	xor	edx, edx
	call	buffer$append_base64decode
	; all good
calign
.dpsearch:
	mov	rdi, [rsp+16]
	call	heap$free
	mov	rdi, [rsp]
	mov	rsi, .dsapub
	call	string$concat
	mov	[rsp+16], rax
	mov	rdi, rax
	call	file$mtime
	test	eax, eax
	jz	.finalcheck
	call	buffer$new
	mov	rdi, [rsp+8]
	mov	[rdi+X509_dsapubkey_ofs], rax	; our buffer object to hold the goods
	mov	rdi, [rsp+16]
	call	file$to_string
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
	;
	mov	rdi, [rsp+16]
	mov	esi, ' '
	mov	edx, 8
	call	string$indexof_charcode_ofs
	cmp	rax, 0
	jl	.finalcheck
	mov	rdi, [rsp+16]
	mov	esi, 8
	mov	rdx, rax
	call	string$substring
	mov	rdi, [rsp+16]
	mov	[rsp+16], rax
	call	heap$free
	;
	mov	rdi, [rsp+8]
	mov	rdi, [rdi+X509_dsapubkey_ofs]
	mov	rsi, [rsp+16]
	xor	edx, edx
	call	buffer$append_base64decode
	; all good, fall through to the final check
calign
.finalcheck:
	; do simple sanity checking on the results (e.g. rsaprivate but no rsapub, dsaprivate but no dsapub)
	mov	rdi, [rsp+16]
	call	heap$free

	mov	rdi, [rsp+8]
	mov	rsi, [rdi+X509_privatekey_ofs]
	mov	rdx, [rdi+X509_dsaprivatekey_ofs]
	mov	rcx, [rdi+X509_pubkey_ofs]
	mov	r8, [rdi+X509_dsapubkey_ofs]
	
	test	rsi, rsi
	jz	.finalcheck_norsaprivate
	test	rcx, rcx
	jz	.failed				; got an rsaprivate, but no rsapub
calign
.finalcheck_norsaprivate:
	test	rdx, rdx
	jz	.finalcheck_nodsaprivate
	test	r8, r8
	jz	.failed				; got a dsaprivate but no dsapub
calign
.finalcheck_nodsaprivate:
	; otherwise, go ahead and let it ride
	mov	rdi, [rsp+24]
	call	buffer$destroy			; free our working buffer
	mov	rax, [rsp+8]			; our return
	add	rsp, 48
	epilog
calign
.failed:
	mov	rdi, [rsp+8]
	call	X509$destroy
	mov	rdi, [rsp+24]
	call	buffer$destroy
	xor	eax, eax
	add	rsp, 48
	epilog
if X509debug
cleartext .rsapubmsg, 'ssh_host_rsa_key.pub ['
cleartext .rsapubmsg2, ']'
end if
cleartext .defaultdir, '/etc/ssh'
cleartext .rsakey, '/ssh_host_rsa_key'
cleartext .rsapub, '/ssh_host_rsa_key.pub'
cleartext .dsakey, '/ssh_host_dsa_key'
cleartext .dsapub, '/ssh_host_dsa_key.pub'
cleartext .rsaprivatekey, '-----BEGIN RSA PRIVATE KEY-----'
cleartext .rsaprivateend, '-----END RSA PRIVATE KEY-----'
cleartext .dsaprivatekey, '-----BEGIN DSA PRIVATE KEY-----'
cleartext .dsaprivateend, '-----END DSA PRIVATE KEY-----'

end if


if used X509$new_pem | defined include_everything
	; single argument in rdi: filename of the PEM file
	; returns a new X509 object in rax, that may or may not be valid/complete
	; returns null in rax if PEM file empty/file error, or of nothing was found whatsoever
	; of interest in the given filename
falign
X509$new_pem:
	prolog	X509$new_pem
	sub	rsp, 48
	mov	[rsp], rdi
	call	file$mtime
	mov	[rsp+16], rax
	mov	rdi, [rsp]

	call	file$to_string
	mov	[rsp+8], rax

	mov	edi, X509_size
	call	heap$alloc_clear
	mov	[rsp], rax

	mov	rcx, [rsp+16]
	mov	rdx, [_epoll_tv_secs]
	mov	[rax+X509_mtime_ofs], rcx
	mov	[rax+X509_checktime_ofs], rdx

	; we need a working buffer
	call	buffer$new
	mov	[rsp+40], rax

	; private keys first
	xor	edx, edx
	mov	[rsp+16], rdx
calign
.psearch:
	mov	rdi, [rsp+8]
	mov	rsi, .rsaprivatekey
	mov	rdx, [rsp+16]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.dsearch
	; rax contains the index of the start we are after
	mov	[rsp+24], rax
	mov	rdi, [rsp+8]
	mov	rsi, .rsaprivateend
	mov	rdx, rax
	call	string$indexof_ofs
	cmp	rax, -1
	je	.dsearch
	mov	[rsp+16], rax		; save the next search start location
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+24]
	add	rsi, qword [.rsaprivatekey]
	mov	rdx, rax
	call	string$substring
	; so now we have a string representation of just the base64 encoded bit
	mov	[rsp+24], rax
	; it is assumed our working buffer is already clear/reset
	mov	rdi, [rsp+40]
	mov	rsi, rax
	xor	edx, edx
	call	buffer$append_base64decode
	mov	rcx, [rsp+40]		; working buffer
	mov	rdi, [rsp]		; X509 return object
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	X509$add_privatekey
	mov	rdi, [rsp+40]
	call	buffer$reset
	mov	rdi, [rsp+24]
	call	heap$free		; free our substring
	jmp	.psearch
calign
.dsearch:
	; dsa private keys next
	mov	rdi, [rsp+8]
	mov	rsi, .dsaprivatekey
	mov	rdx, [rsp+16]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.csearch
	; rax contains the index of the start we are after
	mov	[rsp+24], rax
	mov	rdi, [rsp+8]
	mov	rsi, .dsaprivateend
	mov	rdx, rax
	call	string$indexof_ofs
	cmp	rax, -1
	je	.csearch
	mov	[rsp+16], rax		; save the next search start location
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+24]
	add	rsi, qword [.dsaprivatekey]
	mov	rdx, rax
	call	string$substring
	; so now we have a string representation of just the base64 encoded bit
	mov	[rsp+24], rax
	; it is assumed our working buffer is already clear/reset
	mov	rdi, [rsp+40]
	mov	rsi, rax
	xor	edx, edx
	call	buffer$append_base64decode
	mov	rcx, [rsp+40]		; working buffer
	mov	rdi, [rsp]		; X509 return object
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	X509$add_dsaprivatekey
	mov	rdi, [rsp+40]
	call	buffer$reset
	mov	rdi, [rsp+24]
	call	heap$free		; free our substring
	jmp	.dsearch
calign
.csearch:
	; certificates next
	mov	rdi, [rsp+8]
	mov	rsi, .certificate
	mov	rdx, [rsp+16]
	call	string$indexof_ofs
	cmp	rax, -1
	je	.alldone
	; rax contains the index of the start we are after
	mov	[rsp+24], rax
	mov	rdi, [rsp+8]
	mov	rsi, .certificateend
	mov	rdx, rax
	call	string$indexof_ofs
	cmp	rax, -1
	je	.alldone
	mov	[rsp+16], rax		; save the next search start location
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+24]
	add	rsi, qword [.certificate]
	mov	rdx, rax
	call	string$substring
	; so now we have a string representation of just the base64 encoded bit
	mov	[rsp+24], rax
	; it is assumed our working buffer is already clear/reset
	mov	rdi, [rsp+40]
	mov	rsi, rax
	xor	edx, edx
	call	buffer$append_base64decode
	mov	rcx, [rsp+40]		; working buffer
	mov	rdi, [rsp]		; X509 return object
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	call	X509$add_certificate
	mov	rdi, [rsp+40]
	call	buffer$reset
	mov	rdi, [rsp+24]
	call	heap$free		; free our substring
	jmp	.csearch
calign
.alldone:
	mov	rdi, [rsp+40]
	call	buffer$destroy

	mov	rdi, [rsp+8]
	call	heap$free

	mov	rax, [rsp]
	add	rsp, 48
	epilog
cleartext .rsaprivatekey, '-----BEGIN RSA PRIVATE KEY-----'
cleartext .rsaprivateend, '-----END RSA PRIVATE KEY-----'
cleartext .dsaprivatekey, '-----BEGIN DSA PRIVATE KEY-----'
cleartext .dsaprivateend, '-----END DSA PRIVATE KEY-----'
cleartext .certificate, '-----BEGIN CERTIFICATE-----'
cleartext .certificateend, '-----END CERTIFICATE-----'


end if





if used X509$append_der | defined include_everything
	; three arguments: rdi == json X509 object to append to, rsi == DER bytes, rdx == length of same
falign
X509$append_der:
	prolog	X509$append_der
	sub	rsp, 48
	xor	ecx, ecx
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	mov	[rsp+32], rcx
	mov	[rsp+40], rcx
	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy
	mov	[rsp+24], rax		; our working object, with no name as yet
	mov	rsi, [rsp+8]
	mov	rdx, [rsp+16]
calign
.outerloop:
	cmp	rdx, 2
	jle	.eoc
	movzx	eax, byte [rsi]
	mov	ecx, eax
	and	eax, 0x1f
	add	rsi, 1
	sub	rdx, 1
	; decode the length as well
	movzx	r8d, byte [rsi]
	add	rsi, 1
	sub	rdx, 1
	test	r8d, 0x80
	; length in r8d is fine
	jz	.outerjump
	and	r8d, 0x7f	; length bytes
	test	r8d, r8d
	jz	.outerjump
	mov	r9d, r8d
	xor	r8d, r8d
.outerloop_length:
	test	rdx, rdx
	jz	.eoc
	movzx	r10d, byte [rsi]
	add	rsi, 1
	sub	rdx, 1
	shl	r8, 8
	or	r8, r10
	sub	r9d, 1
	jnz	.outerloop_length
	jmp	qword [rax*8+.asn1table]
calign
.outerjump:
	jmp	qword [rax*8+.asn1table]
calign
.boolean:

calign
.integer:

calign
.bitstring:

calign
.octetstring:

calign
.null:

calign
.objectid:

calign
.objectdesc:

calign
.external:

calign
.real:

calign
.enumerated:

calign
.utf8string:
	; outta here.
	add	rsp, 48
	epilog

calign
.sequence:
	mov	[rsp+24], r8		; store our length (even if it is indefinite)
	mov	dword [rsp+32], 1
	jmp	.outerloop

calign
.set:

calign
.numericstring:

calign
.printablestring:

calign
.t61string:

calign
.videotexstring:

calign
.ia5string:

calign
.utctime:

calign
.generalizedtime:

calign
.graphicstring:

calign
.visiblestring:

calign
.generalstring:

calign
.universalstring:

calign
.characterstring:

calign
.bmpstring:


calign
.eoc:
	; outta here.
	add	rsp, 48
	epilog
dalign
.asn1table:
	dq	.eoc, .boolean, .integer, .bitstring, .octetstring, .null, .objectid, .objectdesc, .external, .real, .enumerated, .eoc
	dq	.utf8string, .eoc, .eoc, .eoc, .sequence, .set, .numericstring, .printablestring, .t61string, .videotexstring, .ia5string
	dq	.utctime, .generalizedtime, .graphicstring, .visiblestring, .generalstring, .universalstring, .characterstring, .bmpstring
	dq	.eoc

end if






























