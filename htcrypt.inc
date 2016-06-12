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
	; htcrypt.inc: my Heavy Thing password-based crypt/decrypt
	;
	; After having built all of the rest of the Heavy Thing crypto goods to support
	; TLS/SSH, I rather like the idea of cascading AES256, so what this
	; does is:
	; 1) start with a user-supplied passphrase (or 8kb worth of key material, and skip step 2)
	; 2) using our hmac-sha512 modified scrypt, expand that out to 8kb worth of preliminary key material
	; 3) break the 8kb key material into 256 AES256 contexts (32 byte keys x 256 == 8kb), initialised sequentially
	; 4) make a temporary copy of the first 64 bytes of key material
	; 5) repeat 1024 times:
	;    using the byte indexes from the last 64 bytes of key material, AES256 the entire key block
	;    repeatedly in sequence to finally arrive at 8kb of key material that took a bit more
	;    grunt to arrive at. See commentary below for the reason why I decided to do this.
	; 6) using our newly crunched 8kb worth of key material, re-initialize all 256 AES256 encryption contexts
	; 7) using the same 8kb worth of key material, initialize 256 AES256 _decryption_ contexts as well
	;
	; to encrypt an AES-sized block (16 bytes)
	; using the byte indexes from step 4, encrypt the block successively 64 times
	; 
	; to decrypt an AES-sized block (16 bytes)
	; using the reversed byte indexes from step 4, decrypt the block successively 64 times
	;
	;
	; This is _not_ meant to be crazy-fast, and is certainly not meant to be memory efficient.
	; 
	; So, the "cascading" means: using the 64 byte index, we walk forward for encryption through
	; each and every 64 byte index, and use that AES256 context to re-encrypt what is there.
	; 
	; We provide a useless key material generator, such that many of these contexts can be created
	; without doing any expensive work (such that a coredump/inspection renders a lot of objects all
	; that look/appear valid, but won't necessarily be).
	;
	; Further to this, we provide additional functions to encrypt/decrypt all our encrypt/decrypt states
	; such that what sits in memory isn't required to be valid at any given time.
	;
	; While the two aforementioned efforts do nothing other than obfuscate and/or make difficult the
	; process of memory analysis, still a nice thing to have in the event there are concerns about
	; coredumps of your running/valid process.
	;
	; In Summary: we initialise 256 different AES256 encrypt and decrypt states, all of which are valid
	; we then maintain a 64 byte sequence index inside a randomized block that is our "real" sequencer
	; such that when we want to encrypt something, we walk through AES encrypt contents at each of the
	; byte indexes contained in the 64 byte sequence, which may contain duplicates, etc.
	; For decryption, we reverse the 64 byte sequence and walk backward through them.
	;
	; NOTE re: cascaded AES256: There is ongoing debate about whether or not cascaded AES256 (using
	; unique keys for each) actually provides a security benefit over a single AES256. The point here
	; is to mandate the use of 8192 bytes of key material, and the cascaded AES256 is a desirable
	; side effect. Whether this really increases security beyond a single key AES256 or not isn't
	; really important to the code contained herein.
	;
	; NOTE re: new_keymaterial doing its one-way AES256 "grinding": The only reason we do this is
	; to make brute-force password recoveries ridiculously difficult. We could have done that
	; exclusively with other key derivation functions, but it is assumed that they were used
	; (as is done with new_passphrase) already, so all we are really doing is "scrambling" the
	; key material further, using AES256 as a CSPRNG as it were. The method chosen requires a fair
	; bit of time/effort.
	;

if used htcrypt$new_passphrase | used htcrypt$new_keymaterial | used htcrypt$new_raw_keymaterial | defined include_everything


htcrypt_user_ofs = 0		; not used in here, 16 bytes
htcrypt_x_ofs = 16		; this gets set to the first unused AES256 context that is not in the sequence
htcrypt_enc_ofs = 24
htcrypt_dec_ofs = 2072
htcrypt_seq_ofs = 4120
htcrypt_r_ofs = 4128

htcrypt_size = htcrypt_r_ofs + 4080


aes_alloc_size = 312


; if this is set, new_keymaterial will dump its sequence and key material to stderr
htcrypt_debug_keymaterial = 0


end if


if used htcrypt$new_passphrase | defined include_everything

	; two arguments: rdi == pointer to passphrase, esi == length of same
falign
htcrypt$new_passphrase:
	prolog	htcrypt$new_passphrase
	sub	rsp, 8192
	mov	rdx, rdi
	mov	ecx, esi
	mov	r8, rdi
	mov	r9d, esi
	mov	rdi, rsp
	mov	esi, 8192
	call	scrypt
	mov	rdi, rsp
	call	htcrypt$new_keymaterial
	add	rsp, 8192
	epilog

end if



if used htcrypt$new_keymaterial | defined include_everything
	; single argument: rdi == pointer to 8kb block of key material
falign
htcrypt$new_keymaterial:
	prolog	htcrypt$new_keymaterial
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rdi
	mov	edi, htcrypt_size
	call	heap$alloc_random
	mov	rbx, rax
	; first up: determine a random location in our htcrypt_r_ofs space
	; to store our first 64 bytes of sequencing material
	xor	edi, edi
	mov	esi, 4016
	call	rng$int
	; make sure it falls on an 8 byte boundary so that it at least looks like
	; every other pointer we have
	and	rax, not 7
	lea	rdi, [rbx+rax+htcrypt_r_ofs]
	mov	rsi, r12
	mov	edx, 64
	mov	[rbx+htcrypt_seq_ofs], rdi
	call	memcpy
	; find the index of the first unused in the sequence
	xor	edx, edx
calign
.findx_outer:
	; see if edx exists in the sequence
	mov	rsi, [rbx+htcrypt_seq_ofs]
	mov	ecx, 64
calign
.findx_inner:
	cmp	byte [rsi], dl
	je	.findx_next	; this one exists in the sequence
	add	rsi, 1
	sub	ecx, 1
	jnz	.findx_inner
	; if we made it to here, edx is not in the sequence
	mov	[rbx+htcrypt_x_ofs], rdx
	jmp	.foundx
calign
.findx_next:
	add	edx, 1
	jmp	.findx_outer
calign
.foundx:
if htcrypt_debug_keymaterial
	mov	rdi, .debug3
	call	string$to_stderr
	mov	rdi, [rbx+htcrypt_seq_ofs]
	mov	esi, 64
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stderrln
	pop	rdi
	call	heap$free
end if

	; next up: do our preliminary 256 aes256 contexts
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_enc_ofs]
calign
.prelim:
	mov	edi, aes_alloc_size
	call	heap$alloc_random
	mov	[r15], rax
	mov	rdi, rax
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_encrypt
	sub	r14d, 1
	jnz	.prelim
	; next up: using the last 64 bytes of key material as our sequence
	; encrypt the key material 64 times
	sub	r13, 64
	; we can store our 64 byte sequence temporarily in our dec area
	; because it will be overwritten as soon as we are done with this step
	mov	eax, 1024
	lea	rdi, [rbx+htcrypt_dec_ofs]
	mov	rsi, r13
	mov	edx, 64
	mov	r15, rdi
	push	rax
	call	memcpy
	push	r12
	mov	r12d, 64
calign
.keyscramble_outer:
	; for each sequence, encrypt the entire 8192 byte space
	mov	r13, [rsp]
	mov	r14d, 512
calign
.keyscramble_inner:
	; get our aes position:
	movzx	eax, byte [r15]
	mov	rdi, [rbx+rax*8+htcrypt_enc_ofs]
	mov	rsi, r13
	add	r13, 16
	call	aes$encrypt
	sub	r14d, 1
	jnz	.keyscramble_inner
	; move to our next index
	add	r15, 1
	sub	r12d, 1
	jnz	.keyscramble_outer

	; setup for our repeat
	lea	rdi, [rbx+htcrypt_dec_ofs]
	mov	rsi, [rsp]
	mov	edx, 64
	mov	r15, rdi
	add	rsi, 8192 - 64
	call	memcpy
	mov	r12d, 64
	sub	dword [rsp+8], 1
	jnz	.keyscramble_outer

	pop	r12 rax
	; so now, we have done a LOT of work on the key material
	; next up, reinit all our aes256 encryption contexts
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_enc_ofs]
	mov	r13, r12
calign
.final_enc:
if htcrypt_debug_keymaterial
	mov	rdi, .debug1
	call	string$to_stderr
	mov	edi, 256
	sub	edi, r14d
	push	rdi
	mov	rdi, rsp
	mov	esi, 1
	call	string$from_bintohex
	mov	[rsp], rax
	mov	rdi, rax
	call	string$to_stderr
	pop	rdi
	call	heap$free
	mov	rdi, .debug2
	call	string$to_stderr
	mov	rdi, r13
	mov	esi, 32
	call	string$from_bintohex
	push	rax
	mov	rdi, rax
	call	string$to_stderrln
	pop	rdi
	call	heap$free
end if

	mov	rdi, [r15]
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_encrypt
	sub	r14d, 1
	jnz	.final_enc
	; next up, same for our decryption goods as well
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_dec_ofs]
	mov	r13, r12
calign
.final_dec:
	mov	edi, aes_alloc_size
	call	heap$alloc_random
	mov	[r15], rax
	mov	rdi, rax
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_decrypt
	sub	r14d, 1
	jnz	.final_dec
	; last but not least, randomize the block we used
	mov	rdi, r12
	mov	esi, 8192
	call	rng$block
	; done, dusted
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	epilog

if htcrypt_debug_keymaterial
cleartext .debug1, 'Key #'
cleartext .debug2, ': '
cleartext .debug3, 'Sequence: '
end if

end if


if used htcrypt$new_raw_keymaterial | defined include_everything
	; single argument: rdi == pointer to 8kb block of key material
	; unlike the above, this is meant for cryptographically secure key material passed straight in
	; and as a result, we do _not_ grind on it
falign
htcrypt$new_raw_keymaterial:
	prolog	htcrypt$new_raw_keymaterial
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r13, rdi
	mov	edi, htcrypt_size
	call	heap$alloc_random
	mov	rbx, rax
	; first up: determine a random location in our htcrypt_r_ofs space
	; to store our first 64 bytes of sequencing material
	xor	edi, edi
	mov	esi, 4016
	call	rng$int
	; make sure it falls on an 8 byte boundary so that it at least looks like
	; every other pointer we have
	and	rax, not 7
	lea	rdi, [rbx+rax+htcrypt_r_ofs]
	mov	rsi, r12
	mov	edx, 64
	mov	[rbx+htcrypt_seq_ofs], rdi
	call	memcpy
	; find the index of the first unused in the sequence
	xor	edx, edx
calign
.findx_outer:
	; see if edx exists in the sequence
	mov	rsi, [rbx+htcrypt_seq_ofs]
	mov	ecx, 64
calign
.findx_inner:
	cmp	byte [rsi], dl
	je	.findx_next	; this one exists in the sequence
	add	rsi, 1
	sub	ecx, 1
	jnz	.findx_inner
	; if we made it to here, edx is not in the sequence
	mov	[rbx+htcrypt_x_ofs], rdx
	jmp	.foundx
calign
.findx_next:
	add	edx, 1
	jmp	.findx_outer
calign
.foundx:
	; next up: do our preliminary 256 aes256 contexts
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_enc_ofs]
calign
.prelim:
	mov	edi, aes_alloc_size
	call	heap$alloc_random
	mov	[r15], rax
	mov	rdi, rax
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_encrypt
	sub	r14d, 1
	jnz	.prelim
	; next up, same for our decryption goods as well
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_dec_ofs]
	mov	r13, r12
calign
.final_dec:
	mov	edi, aes_alloc_size
	call	heap$alloc_random
	mov	[r15], rax
	mov	rdi, rax
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_decrypt
	sub	r14d, 1
	jnz	.final_dec
	; done, dusted
	mov	rax, rbx
	pop	r15 r14 r13 r12 rbx
	epilog

end if

if used htcrypt$new_useless | defined include_everything
	; no arguments, returns a relatively-work-free useless context that looks and smells like the real deal
falign
htcrypt$new_useless:
	prolog	htcrypt$new_useless
	push	rbx r12 r13 r14 r15
	sub	rsp, 8192
	mov	rdi, rsp
	mov	esi, 8192
	mov	r12, rsp
	mov	r13, rsp
	call	rng$block
	mov	edi, htcrypt_size
	call	heap$alloc_random
	mov	rbx, rax
	; first up: determine a random location in our htcrypt_r_ofs space
	; to store our first 64 bytes of sequencing material
	xor	edi, edi
	mov	esi, 4016
	call	rng$int
	; make sure it falls on an 8 byte boundary so that it at least looks like
	; every other pointer we have
	and	rax, not 7
	lea	rdi, [rbx+rax+htcrypt_r_ofs]
	mov	rsi, r12
	mov	edx, 64
	mov	[rbx+htcrypt_seq_ofs], rdi
	call	memcpy
	; find the index of the first unused in the sequence
	xor	edx, edx
calign
.findx_outer:
	; see if edx exists in the sequence
	mov	rsi, [rbx+htcrypt_seq_ofs]
	mov	ecx, 64
calign
.findx_inner:
	cmp	byte [rsi], dl
	je	.findx_next	; this one exists in the sequence
	add	rsi, 1
	sub	ecx, 1
	jnz	.findx_inner
	; if we made it to here, edx is not in the sequence
	mov	[rbx+htcrypt_x_ofs], rdx
	jmp	.foundx
calign
.findx_next:
	add	edx, 1
	jmp	.findx_outer
calign
.foundx:
	; next up: do our preliminary 256 aes256 contexts
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_enc_ofs]
calign
.prelim:
	mov	edi, aes_alloc_size
	call	heap$alloc_random
	mov	[r15], rax
	mov	rdi, rax
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_encrypt
	sub	r14d, 1
	jnz	.prelim

	; next up, same for our decryption goods as well
	mov	r14d, 256
	lea	r15, [rbx+htcrypt_dec_ofs]
	mov	r13, r12
calign
.final_dec:
	mov	edi, aes_alloc_size
	call	heap$alloc_random
	mov	[r15], rax
	mov	rdi, rax
	add	r15, 8
	mov	rsi, r13
	mov	edx, 32
	add	r13, 32
	call	aes$init_decrypt
	sub	r14d, 1
	jnz	.final_dec
	; last but not least, randomize the block we used
	mov	rdi, r12
	mov	esi, 8192
	call	rng$block
	; done, dusted
	mov	rax, rbx
	add	rsp, 8192
	pop	r15 r14 r13 r12 rbx
	epilog

end if


if used htcrypt$destroy | defined include_everything
	; single argument in rdi: the htcrypt object
	; NOTE: this does RNG over every single object before heap$free
falign
htcrypt$destroy:
	prolog	htcrypt$destroy
	push	rbx r12 r13
	mov	rbx, rdi
	lea	r12, [rdi+htcrypt_enc_ofs]
	mov	r13d, 512
calign
.destruct:
	mov	rdi, [r12]
	mov	esi, aes_alloc_size
	call	rng$block
	mov	rdi, [r12]
	call	heap$free
	add	r12, 8
	sub	r13d, 1
	jnz	.destruct
	; next up, randomize our entire block again
	mov	rdi, rbx
	mov	esi, htcrypt_size
	call	rng$block
	; finally, free our pointer
	mov	rdi, rbx
	call	heap$free
	pop	r13 r12 rbx
	epilog

end if

if used htcrypt$hide | defined include_everything
	; two arguments: rdi == htcrypt object, rsi == aes encryption context
	; see commentary atop as to why this is here, all we do is encrypt our
	; important bits such that they don't sit in memory in the clear
falign
htcrypt$hide:
	prolog	htcrypt$hide
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	; first up, our sequence
	mov	rsi, [rdi+htcrypt_seq_ofs]
	mov	rdi, r12
	call	aes$encrypt
	mov	rdi, r12
	mov	rsi, [rbx+htcrypt_seq_ofs]
	add	rsi, 16
	call	aes$encrypt
	mov	rdi, r12
	mov	rsi, [rbx+htcrypt_seq_ofs]
	add	rsi, 32
	call	aes$encrypt
	mov	rdi, r12
	mov	rsi, [rbx+htcrypt_seq_ofs]
	add	rsi, 48
	call	aes$encrypt
	; next up, all our enc and dec contexts
	lea	r13, [rbx+htcrypt_enc_ofs]
	lea	r14, [rbx+htcrypt_dec_ofs]
	mov	r15d, 256
calign
.doit:
	; we want the aes context to look/smell like every other normal one
	; so we don't want to encrypt the entirety of the block, only the roundkeys
	mov	rsi, [r13]
	add	rsi, 16
	mov	rbx, rsi
	repeat 15
		mov	rdi, r12
		mov	rsi, rbx
		add	rbx, 16
		call	aes$encrypt
	end repeat
	mov	rsi, [r14]
	add	rsi, 16
	mov	rbx, rsi
	repeat 15
		mov	rdi, r12
		mov	rsi, rbx
		add	rbx, 16
		call	aes$encrypt
	end repeat
	add	r13, 8
	add	r14, 8
	sub	r15d, 1
	jnz	.doit
	pop	r15 r14 r13 r12 rbx
	epilog

end if



if used htcrypt$show | defined include_everything
	; two arguments: rdi == htcrypt object, rsi == aes decryption context
	; reverses the hide function above
falign
htcrypt$show:
	prolog	htcrypt$show
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	; first up, our sequence
	mov	rsi, [rdi+htcrypt_seq_ofs]
	mov	rdi, r12
	call	aes$decrypt
	mov	rdi, r12
	mov	rsi, [rbx+htcrypt_seq_ofs]
	add	rsi, 16
	call	aes$decrypt
	mov	rdi, r12
	mov	rsi, [rbx+htcrypt_seq_ofs]
	add	rsi, 32
	call	aes$decrypt
	mov	rdi, r12
	mov	rsi, [rbx+htcrypt_seq_ofs]
	add	rsi, 48
	call	aes$decrypt
	; next up, all our enc and dec contexts
	lea	r13, [rbx+htcrypt_enc_ofs]
	lea	r14, [rbx+htcrypt_dec_ofs]
	mov	r15d, 256
calign
.doit:
	; we want the aes context to look/smell like every other normal one
	; so we don't want to encrypt the entirety of the block, only the roundkeys
	mov	rsi, [r13]
	add	rsi, 16
	mov	rbx, rsi
	repeat 15
		mov	rdi, r12
		mov	rsi, rbx
		add	rbx, 16
		call	aes$decrypt
	end repeat
	mov	rsi, [r14]
	add	rsi, 16
	mov	rbx, rsi
	repeat 15
		mov	rdi, r12
		mov	rsi, rbx
		add	rbx, 16
		call	aes$decrypt
	end repeat
	add	r13, 8
	add	r14, 8
	sub	r15d, 1
	jnz	.doit
	pop	r15 r14 r13 r12 rbx
	epilog

end if



if used htcrypt$encrypt | defined include_everything
	; two arguments: rdi == htcrypt object, rsi == ptr to block to encrypt in place
falign
htcrypt$encrypt:
	prolog	htcrypt$encrypt
	cmp	dword [rdi+htcrypt_x_ofs], 255
	je	.singleaes
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, 64
	mov	r14, [rbx+htcrypt_seq_ofs]
calign
.doit:
	movzx	eax, byte [r14]
	add	r14, 1
	mov	rdi, [rbx+rax*8+htcrypt_enc_ofs]
	mov	rsi, r12
	call	aes$encrypt
	sub	r13d, 1
	jnz	.doit
	pop	r14 r13 r12 rbx
	epilog
calign
.singleaes:
	mov	rdi, [rdi+2040+htcrypt_enc_ofs]	; 8 * 255 is the context we want
	call	aes$encrypt
	epilog

end if

if used htcrypt$decrypt | defined include_everything
	; two arguments: rdi == htcrypt object, rsi == ptr to block to decrypt in place
falign
htcrypt$decrypt:
	prolog	htcrypt$decrypt
	cmp	dword [rdi+htcrypt_x_ofs], 255
	je	.singleaes
	push	rbx r12 r13 r14
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13d, 64
	mov	r14, [rbx+htcrypt_seq_ofs]
	add	r14, 64
calign
.doit:
	sub	r14, 1
	movzx	eax, byte [r14]
	mov	rdi, [rbx+rax*8+htcrypt_dec_ofs]
	mov	rsi, r12
	call	aes$decrypt
	sub	r13d, 1
	jnz	.doit
	pop	r14 r13 r12 rbx
	epilog
calign
.singleaes:
	mov	rdi, [rdi+2040+htcrypt_dec_ofs]	; 8 * 255 is the context we want
	call	aes$decrypt
	epilog


end if
