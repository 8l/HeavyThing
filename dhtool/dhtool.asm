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
	; dhtool.asm: Diffie-Hellman parameter tool, used to verify existing
	; parameters or generate new safe prime and generator (using multiple CPU).
	;
	; If verifying: We accept a filename input for either a standard dhparam
	; PEM file, or /etc/ssh/moduli (or similar file), and we then perform our
	; "hardcore" verification. If it is an SSH moduli file, this will verify
	; each and every one of the parameters in it.
	;
	; If creating new: Similar to the "openssl dhparam ..." command, this will
	; send to STDERR a compatible PEM file (see dh_pem2ssh to convert it to
	; /etc/ssh/moduli format). The reason we send to stderr is because stdout
	; is filled with spaces, periods, plusses and $ for visual indication it
	; is not actually stuck. (And so for automated job running, stdout can
	; safely be redirected to /dev/null without affecting operation).
	; 
	; Because much of the huge prime sieve operations are what I like to think of as "luck
	; of the draw", if no CPU count argument is specified, we fire up as many 
	; execution threads as there are cores available. For every sieve candidate,
	; we write a ' ', for every q that passes trial division, we write a '.', for
	; every q that is probably prime we, we write a '+', and for every p that is
	; probably prime, we write a '$', at which point hardcore verification begins.
	; (Hardcore verification being ~192 Miller-Rabin iterations for both primes).
	;
	; command line argument is size in bits you want of the DH safe prime, and optional
	; -CPUCOUNT setting to control the number of processes we fire up.
	; 
	; when we have found and verified one, we output a PKCS#3 DH Parameter file to
	; stderr in PEM format.
	; (The stderr output versus stdout is mainly because the HeavyThing library
	; spews its character progress outputs to stdout, so instead of modifying that,
	; we just chose stderr for the final output stage here to assist in scripting/
	; automation)
	;
	;
	; SOME FURTHER NOTES ABOUT HOW/WHY/WHERE/WHAT:
	;
	; This produces safe primes, and is verified with 192 Miller-Rabin rounds for >=2048
	; bit safe primes. Both the safe prime and its Sophie-Germain counterpart are
	; verified the same.
	;
	; A note here on generator selection: Unlike OpenSSL and OpenSSH, we generate
	; g such that g is a quadratic residue mod p, and is always of order q.
	; OpenSSL/OpenSSH make sure g is always of order 2q, and there are conflicting
	; ideas about which is the "correct" way to go about this. Specifically, see
	; https://groups.google.com/forum/#!topic/sci.crypt/fcfusEoJ8M4
	; and http://crypto.stackexchange.com/questions/12961/diffie-hellman-parameter-check-when-g-2-must-p-mod-24-11
	; and Wei Dai's page: http://www.cryptopp.com/wiki/Diffie-Hellman#Validating_Parameters
	;
	; IMO: The stackexchange commentary from poncho hit it in one, do we leak a bit
	; from private exponents, or do we halve the solution space of the shared secret...
	; Private exponents are usually always smaller than the modulus/prime, so I say
	; Wei Dai's preference (and as is also required by DDH/ElGamal) to ensure g is a
	; quadratic residue mod p is better. Modifications to this code to make it work like
	; OpenSSL/OpenSSH would be trivial in any case if you don't like Wei Dai, poncho, or
	; my decision re: same :-)
	;
	; THAT BEING SAID: If you use openssl dhparam -check to verify the outputs of this
	; program, you'll notice it doesn't like our generators.
	; 


	include 'dhtool_settings.inc'
	include '../ht.inc'

insane_primesize = 131072


	; single epoll object in rdi
calign
parent_receive:
	prolog	parent_receive
	mov	eax, syscall_write
	mov	edi, 2
	syscall

	mov	rdi, [childlist]
	mov	rsi, .killkids
	call	list$clear

	mov	eax, syscall_exit
	xor	edi, edi
	syscall

	epilog

falign
.killkids:
	; single arg in rdi, our child
	mov	eax, syscall_kill
	mov	esi, 0xf		; SIGTERM
	syscall
	ret

dalign
parent_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, parent_receive, io$error, io$timeout

globals
{
	childlist	dq	0
}


public _start
falign
_start:
	call	ht$init

	cmp	qword [argc], 1
	jbe	.usage

	call	list$new
	mov	[childlist], rax

	mov	rdi, [argv]
	call	list$pop_back
	mov	rbx, rax
	mov	rdi, rax
	call	string$isnumber
	test	eax, eax
	jz	.maybeverify
	mov	rdi, rbx
	call	string$to_unsigned
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
	test	rbx, rbx
	jz	.usage
	cmp	rbx, insane_primesize
	ja	.yourenuts
	cmp	rbx, 1536
	jb	.toosmall

	; see if a cpucount argument was passed (-XX)
	mov	rdi, [argv]
	call	list$pop_back
	test	rax, rax
	jz	.nocpuarg
	mov	r12, rax
	mov	rdi, rax
	mov	esi, '-'
	call	string$indexof_charcode
	cmp	rax, 0
	jne	.nocpuarg
	mov	rdi, r12
	mov	esi, 1
	mov	rdx, -1
	call	string$substr
	mov	r13, rax
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	string$isnumber
	test	eax, eax
	jz	.usage
	mov	rdi, r13
	call	string$to_unsigned
	mov	r12, rax
	test	rax, rax
	jz	.usage
	call	sysinfo$cpucount
	cmp	r12, rax
	ja	.cputoomany
	jmp	.doit
calign
.nocpuarg:
	; basic sanity checks passed, determine how many cores we have available
	call	sysinfo$cpucount
	; at minimum 1 (in case for some jacked reason /proc/cpuinfo gave us bupkiss)
	mov	ecx, 1
	mov	edx, 16384		; hahah, funny, though it will do it, my big machines are only 64 cores... :-/
	cmp	eax, ecx
	cmovl	eax, ecx
	cmp	eax, edx
	cmova	eax, edx

	mov	r12d, eax
calign
.doit:
	mov	rdi, .banner
	call	string$to_stdout
	; the easiest/most straightforward/lockfree way to shoot it is of course socketpair/fork
	sub	rsp, 8			; for our socketpair
calign
.children:
	mov	eax, syscall_socketpair
	mov	edi, 1			; AF_UNIX
	mov	esi, 0x801		; SOCK_STREAM | SOCK_NONBLOCK
	xor	edx, edx
	mov	r10, rsp
	syscall
	cmp	rax, 0
	jl	.socketpairdeath
	; fork callee-saves are jacked:
	push	rbx r12
	mov	eax, syscall_fork
	syscall
	cmp	rax, 0
	jl	.forkdeath
	je	.inchild
	pop	r12 rbx

	mov	rdi, [childlist]
	mov	rsi, rax		; push our child's pid into our childlist
	call	list$push_back

	; else, we are the parent, make our established goods
	; we'll use the second socketpair fd for the parent side
	; so close the first one
	mov	eax, syscall_close
	mov	edi, [rsp]
	syscall
	mov	rdi, parent_vtable
	xor	esi, esi
	call	epoll$new
	mov	edi, [rsp+4]
	mov	rsi, rax
	call	epoll$established

	sub	r12d, 1
	jnz	.children

	call	epoll$run		; won't come back

falign
.inchild:
	pop	r12 rbx
	; post-fork child entrypoint
	; close the other half of our socketpair
	mov	eax, syscall_close
	mov	edi, [rsp+4]
	syscall

	; our side is blocking on the socketpair, not epoll$run based
	mov	r13d, [rsp]		; our side of the socketpair

	call	bigint$new
	mov	r14, rax
	call	bigint$new
	mov	r15, rax

	; we need to reinit our rng otherwise all children have the same seed:
	call	rng$init

	; no looping required, dh params will return us with one when it finds one
	mov	rdi, r14
	mov	rsi, r15
	mov	edx, ebx		; our desired safe prime bits
	call	bigint$dh_params

	; now, all we need to do is construct a return and send it back to the parent
	sub	rsp, 65536

	; we need to compute our safe prime bytecount so we can encode the PKCS#3 sequence (and subsequent integer) lengths
	; smash ebp for the task
	mov	rdi, r14
	call	bigint$bytecount
	lea	ebp, [eax+1]		; our encoded bytecount for dh_p
	
	mov	word [rsp], 0x8230	; 0x30 == sequence, 0x82 == length bytecount, 2
	lea	edx, [ebp+7]		; our sequence length is encoded bytecount + 7
	xchg	dh, dl
	mov	word [rsp+2], dx	; sequence length 2 bytes, big endian
	mov	word [rsp+4], 0x8202	; 0x02 == integer, 0x82 == length bytecount, 2
	mov	ecx, ebp
	xchg	ch, cl
	mov	word [rsp+6], cx	; integer length 2 bytes, big endian
	; now we can ssh_encode (which adds the leading zero byte)
	mov	rdi, r14
	lea	rsi, [rsp+8]
	call	bigint$ssh_encode
	; that returns the number of bytes it wrote in eax, which should == ebp
	lea	rdi, [rsp+rbp+8]
	mov	word [rdi], 0x0102	; 0x02 == integer, 0x01 == length bytecount, 1
	; we need to get the dh_g integer value from the bottommost word
	mov	rsi, [r15+bigint_words_ofs]
	mov	rax, [rsi]		; bottommost word is the byte we are after
	mov	byte [rdi+2], al	; we know it will be small
	; so now our total length is rsp+rbp+11
	; we need a base64 encoded version of that
	mov	rdi, rsp
	lea	rsi, [rbp+11]
	xor	edx, edx
	call	string$from_bintobase64
	; we no longer need ebp
	mov	rbp, rax

	; OUTPUT GOODS:
	mov	rdi, rsp
	mov	rsi, .pem_preface
	mov	edx, .pem_prefacelen
	call	memcpy
	lea	r12, [rsp+.pem_prefacelen]	; use this as our running pointer
	; next up, utf8 output our string in rbp
	mov	rdi, rbp
	mov	rsi, r12
	call	string$to_utf8
	; that returns the number of bytes it wrote, so add that to r12
	add	r12, rax
	mov	rdi, r12
	mov	rsi, .pem_postface
	mov	rdx, .pem_postfacelen
	call	memcpy
	; get rid of our base64 string
	mov	rdi, rbp
	call	heap$free
	; add postfacelen to r12
	add	r12, .pem_postfacelen

	; so now, r12-rsp is the length of what we just built
	; send it out to r13d
	mov	eax, syscall_write
	mov	edi, r13d
	mov	rsi, rsp
	mov	rdx, r12
	sub	rdx, rsp
	syscall

	sleep 1

	mov	eax, syscall_exit
	mov	edi, 1
	syscall

dalign
.pem_preface db '-----BEGIN DH PARAMETERS-----',10
.pem_prefacelen = $ - .pem_preface
dalign
.pem_postface db '-----END DH PARAMETERS-----',10
.pem_postfacelen = $ - .pem_postface
cleartext .banner, 'This is dhtool v1.16 ',0xa9,' 2015, 2016 2 Ton Digital. Author: Jeff Marrison',10,'A showcase piece for the HeavyThing library. Commercial support available',10,'Proudly made in Cooroy, Australia. More info: https://2ton.com.au/dhtool',10


falign
.forkdeath:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .forkmsg
	mov	edx, .forkmsglen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.forkmsg db 'fork syscall failed?!',10
.forkmsglen = $ - .forkmsg

falign
.socketpairdeath:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .socketpairmsg
	mov	edx, .socketpairmsglen
	syscall	
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.socketpairmsg db 'socketpair syscall failed?!',10
.socketpairmsglen = $ - .socketpairmsg

falign
.usage:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .usagestr
	mov	edx, .usagestrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.usagestr db 'Usage:',10
	db 'To create a new DH parameter file (similar to openssl dhparam):',10
	db './dhtool [-XX] SIZE',10,'Where SIZE is size in bits of the safe prime you want, XX specifies how many cores to use',10,10
	db 'To verify an existing dhparam file, -or- an OpenSSH moduli file:',10
	db './dhtool filename',10,10
	db 'To convert an existing dhparam file to an OpenSSH moduli compatible line:',10
	db './dhtool -convert filename',10
.usagestrlen = $ - .usagestr
falign
.cputoomany:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .cpustr
	mov	edx, .cpustrlen
	syscall	
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.cpustr db 'You requested more CPUs than we have available. If you REALLY want that, edit make_dh_pem.asm and remove the check.',10
.cpustrlen = $ - .cpustr

falign
.yourenuts:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .nutsstr
	mov	edx, .nutsstrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.nutsstr db 'You have requested an insane safe prime size. If you REALLY want that, edit make_dh_pem.asm and up the limit.',10
.nutsstrlen = $ - .nutsstr

falign
.toosmall:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .smallstr
	mov	edx, .smallstrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.smallstr db 'You have requested a safe prime size that is insecure/too small. If you REALLY want that, edit make_dh_pem.asm and lower the limit.',10
.smallstrlen = $ - .smallstr

calign
.noinput:
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .noinputstr
	mov	edx, .noinputstrlen
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
dalign
.noinputstr db 'Unable to read input file.',10
.noinputstrlen = $ - .noinputstr

calign
.error:
	call	string$to_stderrln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall

cleartext .nofilename, 'Filename from openssl dhparam output required.'
cleartext .dhparameters, '-----BEGIN DH PARAMETERS-----'
cleartext .dhparametersend, '-----END DH PARAMETERS-----'
cleartext .nodhparam, 'Missing BEGIN DH PARAMETERS in input file.'
cleartext .nodhparamend, 'Missing END DH PARAMETERS in input file.'
cleartext .derbad, 'Invalid DER encoding.'

calign
.maybesshmoduli:
	mov	rdi, .banner
	call	string$to_stdout
	mov	rdi, r15
	call	heap$free
	mov	rdi, r12
	call	buffer$destroy
	mov	rdi, rbx
	call	file$to_buffer
	; loop through lines looking for ssh moduli
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
calign
.outer:
	mov	rdi, rbx
	mov	esi, 1
	call	buffer$has_more_lines
	test	eax, eax
	jz	.alldone
	mov	rdi, rbx
	call	buffer$nextline
	mov	r12, rax
	mov	rdi, rax
	mov	esi, ' '
	call	string$split
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	; first one is time or #comment, but make sure we have the right count
	cmp	qword [r12+_list_size_ofs], 7
	jne	.outer_skip
	mov	rdi, r12
	call	list$pop_front
	mov	rdi, rax
	cmp	qword [rax], 1
	je	.outer_skip_free
	mov	r13, rax
	mov	rdi, rax
	call	string$isnumber
	mov	rdi, r13
	test	eax, eax
	jz	.outer_skip_free
	; so far so good, skip this
	call	heap$free
	; next is type, which in mine are always 2
	mov	rdi, r12
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	; next is tests, which in mine are always 6
	mov	rdi, r12
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	; next is tries, which in mine are always 100 (Miller-Rabin count?)
	mov	rdi, r12
	call	list$pop_front
	mov	rdi, rax
	call	heap$free
	; next is size, which we need to hangon to
	mov	rdi, r12
	call	list$pop_front
	mov	r13, rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, r13
	mov	r13, rax
	call	heap$free
	; next is generator, 2, 3, or 5
	mov	rdi, r12
	call	list$pop_front
	mov	r14, rax
	mov	rdi, rax
	call	string$to_unsigned
	mov	rdi, r14
	mov	r14, rax
	call	heap$free
	; next is the bigint itself
	mov	rdi, r12
	call	list$pop_front
	mov	r15, rax
	; tolower it first
	mov	rdi, r15
	call	string$to_lower_inplace
	; create space on our stack for the hex decoded number
	sub	rsp, 16384
	mov	rdi, r15
	mov	rsi, rsp
	call	string$hexdecode
	; that returned the number of bytes we wrote
	mov	rdi, r15
	mov	r15, rax
	call	heap$free
	; next up, bigint from that
	mov	rdi, rsp
	mov	rsi, r15
	call	bigint$new_encoded
	mov	r15, rax
	; we are done with our temporary stack
	add	rsp, 16384
	; output the size that the file said it is + 1
	mov	rdi, .filesize
	call	string$to_stdout
	mov	rdi, r13
	add	rdi, 1
	mov	esi, 10
	call	string$from_unsigned
	mov	rdi, rax
	push	rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free
	; see if they match
	mov	rdi, .filesizematch
	call	string$to_stdout
	mov	rdi, r15
	call	bigint$bitcount
	mov	rdi, .yes
	mov	rsi, .no
	mov	rdx, r13
	add	rdx, 1
	cmp	rdx, rax
	cmovne	rdi, rsi
	call	string$to_stdoutln
	mov	rdi, r14
	call	bigint$new_unsigned
	mov	r14, rax
	; verify those
	mov	rdi, r15
	mov	rsi, r14
	call	.dh_verify
	mov	rdi, r14
	call	bigint$destroy
	mov	rdi, r15
	call	bigint$destroy
	jmp	.outer_skip
cleartext .filesize, 'Prime Size: '
cleartext .filesizematch, 'Size Match: '
calign
.outer_skip_free:
	call	heap$free
.outer_skip:
	mov	rdi, r12
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, r12
	call	heap$free
	jmp	.outer
calign
.alldone:
	mov	rdi, rbx
	call	buffer$destroy
	mov	eax, syscall_exit
	xor	edi, edi
	syscall

calign
.maybeverify:
	; rbx is our filename argument that string$isnumber did not return happily
	; it is either a PEM file or an /etc/ssh/moduli file
	mov	rdi, rbx
	call	file$mtime
	test	rax, rax
	jz	.noinput
	mov	rdi, rbx
	call	file$to_string
	mov	r15, rax
	call	buffer$new
	mov	r12, rax
	; see if it is a DH PARAMETER file:
	mov	rdi, r15
	mov	rsi, .dhparameters
	xor	edx, edx
	call	string$indexof_ofs
	cmp	rax, -1
	je	.maybesshmoduli
	mov	r14, rax
	mov	rdi, r15
	mov	rsi, .dhparametersend
	mov	rdx, rax
	call	string$indexof_ofs
	mov	rdi, .nodhparamend
	cmp	rax, -1
	je	.error
	mov	r13, rax
	mov	rdi, r15
	mov	rsi, r14
	add	rsi, qword [.dhparameters]
	mov	rdx, rax
	call	string$substring
	mov	rdi, rbx
	mov	rbx, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, rbx
	xor	edx, edx
	call	buffer$append_base64decode
	mov	rdi, rbx
	call	heap$free
	; so now our buffer in r12 contains the base64 decoded DER
	push	r12
	mov	r13, [r12+buffer_length_ofs]
	mov	r12, [r12+buffer_itself_ofs]

	call	.gettag
	mov	rdi, .derbad
	cmp	eax, 0x10		; SEQUENCE or puke
	jne	.error
	; p is first, integer:
	call	.gettag
	mov	rdi, .derbad
	cmp	eax, 0x2		; INTEGER or puke
	jne	.error
	test	r8d, r8d		; nonzero length or puke
	jz	.error
	cmp	r13, r8			; not enough data left == puke
	jb	.error
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	r14, rax		; DH p
	
	; g is next
	call	.gettag
	mov	rdi, .derbad
	cmp	eax, 0x2		; INTEGER or puke
	jne	.error
	test	r8d, r8d		; nonzero length or puke
	jz	.error
	cmp	r13, r8			; not enough data left == puke
	jb	.error
	mov	rdi, r12
	mov	rsi, r8
	add	r12, r8
	sub	r13, r8
	call	bigint$new_encoded
	mov	r15, rax

	mov	rdi, [argv]
	call	list$pop_back
	push	rax
	mov	rdi, rax
	mov	rsi, .dashconvert
	call	string$equals
	pop	rdi
	push	rax
	call	heap$free
	pop	rax
	test	rax, rax
	jnz	.convert

	mov	rdi, .banner
	call	string$to_stdout
	
	; verify both
	mov	rdi, r14
	mov	rsi, r15
	call	.dh_verify
.cleanup_exit:

	; cleanup and exit
	mov	rdi, r14
	call	bigint$destroy
	mov	rdi, r15
	call	bigint$destroy
	pop	rdi
	call	buffer$destroy
	
	mov	eax, syscall_exit
	xor	edi, edi
	syscall
falign
.gettag:
	asn1_tag
	ret
cleartext .dashconvert, '-convert'
calign
.convert:
	mov	rdi, .banner
	call	string$to_stderr
	; DH p == r14, DH g == r15
	mov	edi, 1			; space between items please
	call	formatter$new
	mov	r12, rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_datetime
	mov	rdi, r12
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned	; type
	mov	rdi, r12
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned	; tests
	mov	rdi, r12
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned	; tries
	mov	rdi, r12
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned	; size
	mov	rdi, r12
	xor	esi, esi
	xor	edx, edx
	call	formatter$add_unsigned	; generator
	mov	rdi, r12
	xor	esi, esi
	call	formatter$add_string	; bigint hex
	; turn our r14 into the necessary goods
	sub	rsp, 16384
	mov	rdi, r14
	mov	rsi, rsp
	call	bigint$encode
	mov	rdi, rsp
	mov	rsi, rax
	call	string$from_bintohex
	add	rsp, 16384
	mov	r13, rax
	mov	rdi, rax
	call	string$to_upper_inplace
	; get the current datetime
	mov	rdi, r14
	call	bigint$bitcount
	push	rax
	call	timestamp
	mov	r9, [r15+bigint_words_ofs]
	mov	rdi, r12
	mov	esi, 2			; type
	mov	edx, 6			; tests
	mov	ecx, 192		; tries
	pop	r8
	sub	r8, 1			; size
	mov	r9, [r9]		; generator
	mov	r10, r13		; bigint string
	call	formatter$doit
	mov	rdi, r12
	mov	r12, rax
	call	formatter$destroy
	; our formatter puts YYYY-MM-DDTHH:MI:SSZ
	; so we need to strip all that.
	mov	rdi, r12
	mov	rsi, .dash
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .t
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .colon
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	mov	rsi, .z
	mov	rdx, .emptystr
	call	string$replace
	mov	rdi, r12
	mov	r12, rax
	call	heap$free

	mov	rdi, r12
	call	string$to_stdoutln
	mov	rdi, r12
	call	heap$free
	mov	rdi, r13
	call	heap$free

	jmp	.cleanup_exit
cleartext .dash, '-'
cleartext .t, 'T'
cleartext .colon, ':'
cleartext .z, 'Z'
cleartext .emptystr, ''

	; rdi == DH p, rsi == DH g
falign
.dh_verify:
	push	rbx r12 r13 r14 r15
	mov	r14, rdi
	mov	r15, rsi
	
	mov	rdi, .dhp
	call	string$to_stdout
	mov	rdi, r14
	call	bigint$debug
	mov	rdi, .dhg
	call	string$to_stdout
	mov	rdi, r15
	call	bigint$debug

	mov	rdi, .verifyp
	call	string$to_stdout

	mov	rdi, r14
	call	bigint$verifyprime
	mov	rdi, .goodp
	mov	rsi, .badp
	test	eax, eax
	cmovz	rdi, rsi
	call	string$to_stdoutln

	mov	rdi, .verifysafe
	call	string$to_stdout

	mov	rdi, r14
	call	bigint$new_copy
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, bigint$one
	call	bigint$subtract
	mov	rdi, rbx
	mov	esi, 1
	call	bigint$shr
	
	mov	rdi, rbx
	call	bigint$verifyprime
	mov	rdi, .goodp
	mov	rsi, .badp
	test	eax, eax
	cmovz	rdi, rsi
	call	string$to_stdoutln

	; verify the order of the subgroup
	mov	rdi, .verifysubgroup
	call	string$to_stdout

	mov	rdi, rbx		; exponent == q
	mov	rsi, r14		; modulus == p
	call	monty$new
	mov	[r14+bigint_monty_powmod_ofs], rax

	; reuse rbx for our destination
	mov	rdi, rax
	mov	rsi, rbx		; destination for monty exponentation
	mov	rdx, r15		; source == DH g
	call	monty$doit

	mov	rdi, rbx
	call	bigint$is_one
	mov	rdi, .goodp
	mov	rsi, .badp
	test	eax, eax
	cmovz	rdi, rsi
	call	string$to_stdoutln

	mov	rdi, .verifysubgroup2
	call	string$to_stdout

	; see if it is order of 2q instead of q like above
	mov	rdi, rbx		; set it to (p-1) >> 1 again
	mov	rsi, r14
	call	bigint$assign
	mov	rdi, rbx
	mov	rsi, bigint$one
	call	bigint$subtract
	mov	rdi, rbx
	mov	esi, 1
	call	bigint$shr

	; verify the order of the subgroup 2q instead of q
	mov	rdi, rbx
	mov	esi, 1
	call	bigint$shl

	mov	rdi, rbx		; exponent == 2q
	mov	rsi, r14		; modulus == p
	call	monty$new
	mov	[rbx+bigint_monty_powmod_ofs], rax

	; reuse rbx again for destination
	mov	rdi, rax
	mov	rsi, rbx
	mov	rdx, r15		; rbx = g**2q mod p
	call	monty$doit

	mov	rdi, rbx
	call	bigint$is_one
	mov	rdi, .goodp
	mov	rsi, .badp
	test	eax, eax
	cmovz	rdi, rsi
	call	string$to_stdoutln

	mov	rdi, rbx
	call	bigint$destroy

	mov	rdi, .verifyg
	call	string$to_stdout

	mov	rdi, r15
	mov	rsi, r14
	call	bigint$jacobi
	mov	rdi, .yes
	mov	rsi, .no
	cmp	eax, 1
	cmovne	rdi, rsi
	push	rax
	call	string$to_stdoutln
	pop	rax
	
	cmp	eax, 1
	je	.skip_newg

	; g is not a quadratic residue mod p, so figure out
	; which one is the goods and output that for information/headsup purposes
	mov	rdi, r15
	mov	rsi, bigint$two
	call	bigint$assign

	; walk g upward til we find one that is a quadratic residue mod p
calign
.gloop:
	mov	rdi, r15
	mov	rsi, r14
	call	bigint$jacobi
	cmp	eax, 1
	je	.gfound
	mov	rdi, r15
	mov	rsi, bigint$one
	call	bigint$add
	jmp	.gloop
calign
.gfound:
	mov	rdi, .newg
	call	string$to_stdout
	mov	rdi, r15
	call	bigint$debug
	
calign
.skip_newg:
	mov	rdi, .mod8
	call	string$to_stdout
	mov	rdi, r14
	mov	esi, 8
	call	bigint$modword
	mov	rdi, rax
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .mod7
	call	string$to_stdout
	mov	rdi, r14
	mov	esi, 7
	call	bigint$modword
	mov	rdi, rax
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .mod12
	call	string$to_stdout
	mov	rdi, r14
	mov	esi, 12
	call	bigint$modword
	mov	rdi, rax
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	mov	rdi, .mod24
	call	string$to_stdout
	mov	rdi, r14
	mov	esi, 24
	call	bigint$modword
	mov	rdi, rax
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stdoutln
	pop	rdi
	call	heap$free

	; done, dusted

	pop	r15 r14 r13 r12 rbx
	ret
cleartext .dhp, 'DH p (LE): '
cleartext .dhg, 'DH g (LE): '
cleartext .verifyp, 'Ridiculous p verification (MR=192)...'
cleartext .verifysafe, 'Ridiculous Sophie Germain counterpart verification (MR=192)...'
cleartext .verifysubgroup, 'Verifying the order of the subgroup (g has order q)...'
cleartext .verifysubgroup2, 'Verifying the order of the subgroup (g has order 2q)...'
cleartext .verifyg, 10,'Wei Dai states "find g such that g is a quadratic residue mod p, then g has order q"', 10, 'A quick Google for "DH_NOT_SUITABLE_GENERATOR" and "DH_check()" provides some useful',10,'information about how OpenSSL chooses these, but Wei Dai chooses g differently.',10,10,'So, is g a quadratic residue mod p? '
cleartext .newg, 'Appropriate g such that g is a quadratic residue mod p: '

cleartext .goodp, 'Good.'
cleartext .badp, 'Bad.'
cleartext .yes, 'Yes.'
cleartext .no, 'No.'

cleartext .mod8, ' p%8 is: '
cleartext .mod7, ' p%7 is: '
cleartext .mod12, 'p%12 is: '
cleartext .mod24, 'p%24 is: '


	include '../ht_data.inc'
