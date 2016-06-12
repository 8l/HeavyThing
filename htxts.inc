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
	; htxts.inc: XTS encryption/decryption, using htcrypt (which is cascaded AES256)
	; 
	; this is by the AESXTS standard, but instead of flat aes$encrypt/decrypt, we use htcrypt
	;
	; NOTE: we use htcrypt's x index for the tweak's AES context, if x == 255, then we use 254
	;   (this allows the cascaded AES feature of htcrypt to effectively be disabled)
	;

if used htxts$encrypt | used htxts$decrypt | defined include_everything


; NOTE: this _must_ be a power of 2 >= 16
htxts_blocksize = 2048

; 1 << this needs to equal the above
htxts_blocksize_bits = 11

htxts_blocks = htxts_blocksize shr 4


end if


if used htxts$encrypt | defined include_everything
	; three arguments: rdi == htcrypt context, rsi == ptr to htxts_blocksize worth of plaintext, rdx == ptr to encryption tweak (e.g. blocknum) (must be 16 bytes in length)
falign
htxts$encrypt:
	prolog	htxts$encrypt
	push	rbx r12 r13 r14 r15
	mov	eax, [rdi+htcrypt_x_ofs]
	mov	ecx, 254
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	cmp	eax, 255
	cmove	eax, ecx
	; first order of business: encrypt the tweak using the enc[htcrypt.x] from our htcrypt context
	mov	rdi, [rdi+rax*8+htcrypt_enc_ofs]
	mov	rsi, rdx
	call	aes$encrypt
	; now, for htxts_blocks, do our tweaked encrypt
	mov	r14d, htxts_blocks
calign
.tweaked:
	; xor our block with the tweak
	mov	rax, [r13]
	mov	rcx, [r13+8]
	xor	[r12], rax
	xor	[r12+8], rcx
	; htcrypt the block
	mov	rdi, rbx
	mov	rsi, r12
	call	htcrypt$encrypt
	; xor with the tweak again
	mov	rax, [r13]
	mov	rcx, [r13+8]
	xor	[r12], rax
	xor	[r12+8], rcx
	; LSFR the tweak
	shl	rcx, 1
	jc	.lsfr_carry
	shl	rax, 1
	adc	rcx, 0
	mov	[r13], rax
	mov	[r13+8], rcx

	; proceed to next block or done
	add	r12, 16
	sub	r14d, 1
	jnz	.tweaked
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.lsfr_carry:
	shl	rax, 1
	adc	rcx, 0
	xor	rax, 0x87
	mov	[r13], rax
	mov	[r13+8], rcx
	
	; proceed to next block or done
	add	r12, 16
	sub	r14d, 1
	jnz	.tweaked
	pop	r15 r14 r13 r12 rbx
	epilog


end if


if used htxts$decrypt | defined include_everything
	; three arguments: rdi == htcrypt context, rsi == ptr to htxts_blocksize worth of ciphertext, rdx == ptr to encryption tweak (e.g. blocknum)
falign
htxts$decrypt:
	prolog	htxts$decrypt
	push	rbx r12 r13 r14 r15
	mov	eax, [rdi+htcrypt_x_ofs]
	mov	ecx, 254
	mov	rbx, rdi
	mov	r12, rsi
	mov	r13, rdx
	cmp	eax, 255
	cmove	eax, ecx
	; first order of business: encrypt the tweak using the enc[htcrypt.x] from our htcrypt context
	mov	rdi, [rdi+rax*8+htcrypt_enc_ofs]
	mov	rsi, rdx
	call	aes$encrypt
	; now, for htxts_blocks, do our tweaked encrypt
	mov	r14d, htxts_blocks
calign
.tweaked:
	; xor our block with the tweak
	mov	rax, [r13]
	mov	rcx, [r13+8]
	xor	[r12], rax
	xor	[r12+8], rcx
	; htcrypt the block
	mov	rdi, rbx
	mov	rsi, r12
	call	htcrypt$decrypt
	; xor with the tweak again
	mov	rax, [r13]
	mov	rcx, [r13+8]
	xor	[r12], rax
	xor	[r12+8], rcx
	; LSFR the tweak
	shl	rcx, 1
	jc	.lsfr_carry
	shl	rax, 1
	adc	rcx, 0
	mov	[r13], rax
	mov	[r13+8], rcx

	; proceed to next block or done
	add	r12, 16
	sub	r14d, 1
	jnz	.tweaked
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.lsfr_carry:
	shl	rax, 1
	adc	rcx, 0
	xor	rax, 0x87
	mov	[r13], rax
	mov	[r13+8], rcx
	
	; proceed to next block or done
	add	r12, 16
	sub	r14d, 1
	jnz	.tweaked

	pop	r15 r14 r13 r12 rbx
	epilog

end if
