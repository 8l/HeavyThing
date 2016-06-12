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
	; math.inc: math functions (baseline for my library's required goods)
	;

_math_zero	dq	0.0f
_math_one	dq	1.0f
_math_two	dq	2.0f
_math_four	dq	4.0f
_math_fiftytwo	dq	52.0f
_math_ten	dq	10.0f
_math_negone	dq	-1.0f
_math_onehundred	dq	100.0f
_math_zeropointone	dq	0.1f
_math_pi                dw      0x2d18,0x5444,0x21fb,0x4009
_math_1shl53	dq	9007199254740992f
_math_negzero           dw      0x0000,0x0000,0x0000,0x8000
_math_neginf		dw	0x0000,0x0000,0x0000,0xfff0
_math_posinf		dw	0x0000,0x0000,0x0000,0x7ff0
_math_nan		dw	0x0000,0x0000,0xffff,0x7fff


_vcast_vi_i_one	dd	1,1,0,0
_mm_set_pd_negz_negz	dq	-0.0f,-0.0f


if used pow | defined include_everything
; credit where credit is due for this function: transcoded from Naoki Shibata's fantastic work
; a thing of beauty really... hats off

	; two arguments, x & y in xmm0, xmm1, returns in xmm0
falign
pow:
	prolog	pow
	push	rbp
	sub	rsp, 16 * 16
	mov	rbp, rsp
	add	rbp, 32
	and	rbp, not 0xf

	movapd xmm15,xmm0
	cvtpd2dq xmm2,xmm1
	cvtdq2pd xmm0,xmm2
	cmpneqpd xmm0,xmm1
	movapd xmm7,[.p4970]			; XMMWORD PTR [rip+0xb146]        # 414970 <_IO_stdin_used+0x480>
	movapd xmm3,[.p5090]			; XMMWORD PTR [rip+0xb85e]        # 415090 <_IO_stdin_used+0xba0>
	movapd xmm8,[.p4b70]			; XMMWORD PTR [rip+0xb335]        # 414b70 <_IO_stdin_used+0x680>
	movapd xmm4,xmm7
	movdqa dqword [rbp+16],xmm0
	movdqa xmm0,[.p49d0]			; XMMWORD PTR [rip+0xb183]        # 4149d0 <_IO_stdin_used+0x4e0>
	andnpd xmm4,xmm15
	mulpd  xmm3,xmm4
	movapd dqword [rbp+64],xmm4
	movapd xmm14,xmm8
	pand   xmm0,xmm2
	movdqa xmm2,dqword [rbp+16]
	pcmpeqd xmm0,[.p49d0]			; XMMWORD PTR [rip+0xb15d]        # 4149d0 <_IO_stdin_used+0x4e0>
	movdqa xmm4,[.p4960]			; XMMWORD PTR [rip+0xb0e5]        # 414960 <_IO_stdin_used+0x470>
	movapd xmm11,xmm8
	shufps xmm0,xmm0,0x50
	pandn  xmm2,xmm0
	movapd xmm0,[.p4990]			; XMMWORD PTR [rip+0xb100]        # 414990 <_IO_stdin_used+0x4a0>
	movdqa dqword [rbp+48],xmm2
	movapd xmm2,xmm3
	cmpltpd xmm2,[.p4980]			; XMMWORD PTR [rip+0xb0dd]        # 414980 <_IO_stdin_used+0x490>
	mulpd  xmm0,xmm3
	movdqa xmm6,xmm2
	movdqa xmm9,xmm2
	pandn  xmm6,xmm3
	pand   xmm0,xmm2
	por    xmm0,xmm6
	pand   xmm0,[.p49a0]			; XMMWORD PTR [rip+0xb0dc]        # 4149a0 <_IO_stdin_used+0x4b0>
	psrld  xmm0,0x14
	movdqa xmm3,xmm0
	psubd  xmm0,[.p49c0]			; XMMWORD PTR [rip+0xb0eb]        # 4149c0 <_IO_stdin_used+0x4d0>
	psubd  xmm3,[.p49b0]			; XMMWORD PTR [rip+0xb0d3]        # 4149b0 <_IO_stdin_used+0x4c0>
	pand   xmm0,xmm2
	pandn  xmm9,xmm3
	pxor   xmm3,xmm3
	por    xmm0,xmm9
	shufps xmm0,xmm0,0xd
	psubd  xmm3,xmm0
	movdqa dqword [rbp],xmm0
	movdqa xmm2,xmm3
	movapd xmm9,xmm8
	psrad  xmm2,0x1f
	movdqa xmm0,xmm2
	paddd  xmm0,xmm3
	psrad  xmm0,0x9
	psubd  xmm0,xmm2
	pslld  xmm0,0x7
	movdqa xmm2,xmm0
	paddd  xmm0,[.p4950]			; XMMWORD PTR [rip+0xb023]        # 414950 <_IO_stdin_used+0x460>
	pslld  xmm2,0x2
	psubd  xmm3,xmm2
	pxor   xmm2,xmm2
	pcmpgtd xmm2,xmm0
	paddd  xmm3,[.p4950]			; XMMWORD PTR [rip+0xb00a]        # 414950 <_IO_stdin_used+0x460>
	pandn  xmm2,xmm0
	movdqa xmm0,xmm2
	pcmpgtd xmm2,[.p4960]			; XMMWORD PTR [rip+0xb00a]        # 414960 <_IO_stdin_used+0x470>
	shufps xmm3,xmm3,0x73
	pslld  xmm3,0x14
	pand   xmm4,xmm2
	pandn  xmm2,xmm0
	movapd xmm0,dqword [rbp+64]
	por    xmm2,xmm4
	shufps xmm2,xmm2,0x73
	pslld  xmm2,0x14
	mulpd  xmm0,xmm2
	movapd xmm4,[.p4f00]			; XMMWORD PTR [rip+0xb57a]        # 414f00 <_IO_stdin_used+0xa10>
	movapd xmm5,xmm4
	mulpd  xmm0,xmm2
	mulpd  xmm0,xmm2
	mulpd  xmm0,xmm2
	mulpd  xmm0,xmm3
	addpd  xmm14,xmm0
	movapd xmm3,xmm0
	addpd  xmm5,xmm0
	divpd  xmm9,xmm14
	movapd xmm2,xmm14
	movapd xmm10,xmm14
	subpd  xmm2,xmm8
	movapd xmm12,xmm5
	subpd  xmm10,xmm2
	subpd  xmm3,xmm2
	subpd  xmm11,xmm10
	movapd xmm2,xmm11
	movdqa xmm11,xmm5
	addpd  xmm2,xmm3
	movapd xmm3,xmm5
	subpd  xmm3,xmm4
	subpd  xmm12,xmm3
	subpd  xmm0,xmm3
	movdqa xmm3,[.p4af0]			; XMMWORD PTR [rip+0xb0fb]        # 414af0 <_IO_stdin_used+0x600>
	subpd  xmm4,xmm12
	movapd xmm12,xmm5
	pand   xmm11,xmm3
	subpd  xmm12,xmm11
	addpd  xmm4,xmm0
	movdqa xmm0,xmm14
	pand   xmm0,xmm3
	subpd  xmm14,xmm0
	movapd xmm13,xmm14
	mulpd  xmm5,xmm9
	movdqa xmm6,xmm9
	movapd xmm10,xmm9
	pand   xmm6,xmm3
	subpd  xmm10,xmm6
	mulpd  xmm14,xmm6
	mulpd  xmm13,xmm10
	mulpd  xmm2,xmm5
	movapd dqword [rbp+80],xmm13
	movapd xmm13,xmm0
	mulpd  xmm13,xmm10
	subpd  xmm4,xmm2
	mulpd  xmm0,xmm6
	mulpd  xmm4,xmm9
	movapd dqword [rbp+32],xmm13
	movapd xmm13,xmm8
	subpd  xmm13,xmm0
	movapd xmm0,xmm13
	movapd xmm13,xmm12
	mulpd  xmm12,xmm6
	subpd  xmm0,dqword [rbp+32]
	mulpd  xmm6,xmm11
	mulpd  xmm13,xmm10
	mulpd  xmm10,xmm11
	subpd  xmm0,xmm14
	movapd xmm11,xmm5
	mulpd  xmm11,xmm5
	subpd  xmm6,xmm5
	subpd  xmm0,dqword [rbp+80]
	addpd  xmm6,xmm10
	movapd xmm14,xmm11
	mulpd  xmm0,xmm5
	addpd  xmm6,xmm12
	movapd xmm12,xmm7
	xorpd  xmm12,xmm11
	addpd  xmm6,xmm13
	movapd xmm13,xmm5
	addpd  xmm6,xmm0
	movdqa xmm0,xmm5
	pand   xmm0,xmm3
	movapd xmm9,xmm0
	subpd  xmm13,xmm0
	addpd  xmm9,xmm0
	addpd  xmm4,xmm6
	movapd xmm6,xmm0
	mulpd  xmm6,xmm0
	movapd xmm10,xmm13
	mulpd  xmm9,xmm13
	mulpd  xmm10,xmm13
	movapd xmm2,xmm4
	addpd  xmm2,xmm4
	addpd  xmm6,xmm12
	mulpd  xmm2,xmm5
	addpd  xmm6,xmm9
	movapd xmm9,xmm11
	mulpd  xmm9,xmm5
	addpd  xmm6,xmm10
	movdqa xmm10,xmm11
	pand   xmm10,xmm3
	subpd  xmm14,xmm10
	addpd  xmm6,xmm2
	movapd xmm2,[.p5200]			; XMMWORD PTR [rip+0xb6b1]        # 415200 <_IO_stdin_used+0xd10>
	movapd xmm12,xmm14
	mulpd  xmm2,xmm11
	mulpd  xmm14,xmm0
	mulpd  xmm0,xmm10
	mulpd  xmm12,xmm13
	mulpd  xmm13,xmm10
	movdqa xmm10,xmm9
	addpd  xmm2,[.p5210]			; XMMWORD PTR [rip+0xb696]        # 415210 <_IO_stdin_used+0xd20>
	mulpd  xmm6,xmm5
	pand   xmm10,xmm3
	mulpd  xmm2,xmm11
	addpd  xmm2,[.p5220]			; XMMWORD PTR [rip+0xb690]        # 415220 <_IO_stdin_used+0xd30>
	mulpd  xmm2,xmm11
	addpd  xmm2,[.p5230]			; XMMWORD PTR [rip+0xb693]        # 415230 <_IO_stdin_used+0xd40>
	mulpd  xmm2,xmm11
	addpd  xmm2,[.p5240]			; XMMWORD PTR [rip+0xb696]        # 415240 <_IO_stdin_used+0xd50>
	mulpd  xmm2,xmm11
	addpd  xmm2,[.p5250]			; XMMWORD PTR [rip+0xb699]        # 415250 <_IO_stdin_used+0xd60>
	mulpd  xmm2,xmm11
	addpd  xmm2,[.p5260]			; XMMWORD PTR [rip+0xb69c]        # 415260 <_IO_stdin_used+0xd70>
	mulpd  xmm2,xmm11
	mulpd  xmm11,xmm4
	addpd  xmm2,[.p5270]			; XMMWORD PTR [rip+0xb69a]        # 415270 <_IO_stdin_used+0xd80>
	movapd dqword [rbp+80],xmm11
	movapd xmm11,xmm7
	xorpd  xmm11,xmm9
	addpd  xmm0,xmm11
	movapd xmm11,xmm9
	subpd  xmm11,xmm10
	mulpd  xmm9,xmm2
	addpd  xmm0,xmm14
	addpd  xmm0,xmm13
	movapd xmm13,xmm7
	xorpd  xmm13,xmm9
	addpd  xmm0,xmm12
	movapd xmm12,xmm2
	addpd  xmm0,dqword [rbp+80]
	addpd  xmm0,xmm6
	movdqa xmm6,xmm2
	pand   xmm6,xmm3
	subpd  xmm12,xmm6
	mulpd  xmm0,xmm2
	movapd xmm2,xmm11
	mulpd  xmm11,xmm6
	mulpd  xmm6,xmm10
	mulpd  xmm2,xmm12
	mulpd  xmm12,xmm10
	addpd  xmm6,xmm13
	movapd xmm13,xmm7
	addpd  xmm6,xmm11
	addpd  xmm6,xmm12
	addpd  xmm6,xmm2
	addpd  xmm6,xmm0
	movapd xmm0,[.p5110]			; XMMWORD PTR [rip+0xb49f]        # 415110 <_IO_stdin_used+0xc20>
	mulpd  xmm5,xmm0
	mulpd  xmm4,xmm0
	movapd xmm2,xmm5
	addpd  xmm2,xmm9
	addpd  xmm4,xmm6
	movdqa xmm6,[.p5120]			; XMMWORD PTR [rip+0xb492]        # 415120 <_IO_stdin_used+0xc30>
	movapd xmm0,xmm2
	movapd xmm12,xmm2
	pand   xmm6,xmm3
	subpd  xmm0,xmm5
	subpd  xmm12,xmm0
	subpd  xmm9,xmm0
	movapd xmm0,[.p5120]			; XMMWORD PTR [rip+0xb46f]        # 415120 <_IO_stdin_used+0xc30>
	subpd  xmm5,xmm12
	movapd xmm12,xmm0
	subpd  xmm12,xmm6
	addpd  xmm5,xmm9
	; HMmmmm: cvtdq2pd xmm9,QWORD PTR [rsp-0x18]
	cvtdq2pd xmm9, qword [rbp]
	movapd xmm11,xmm9
	mulpd  xmm0,xmm9
	movapd xmm10,xmm12
	addpd  xmm5,xmm4
	movdqa xmm4,xmm9
	mulpd  xmm9,[.p5280]			; XMMWORD PTR [rip+0xb593]        # 415280 <_IO_stdin_used+0xd90>
	pand   xmm4,xmm3
	subpd  xmm11,xmm4
	mulpd  xmm12,xmm4
	mulpd  xmm4,xmm6
	xorpd  xmm13,xmm0
	mulpd  xmm10,xmm11
	mulpd  xmm11,xmm6
	addpd  xmm4,xmm13
	addpd  xmm4,xmm12
	addpd  xmm4,xmm11
	movapd xmm11,xmm0
	addpd  xmm11,xmm2
	addpd  xmm4,xmm10
	movapd xmm6,xmm11
	movapd xmm13,xmm11
	movdqa xmm12,xmm11
	subpd  xmm6,xmm0
	pand   xmm12,xmm3
	addpd  xmm4,xmm9
	movapd xmm9,xmm11
	subpd  xmm9,xmm12
	subpd  xmm13,xmm6
	subpd  xmm2,xmm6
	movapd xmm6,xmm1
	addpd  xmm4,xmm5
	movapd xmm5,xmm9
	subpd  xmm0,xmm13
	addpd  xmm0,xmm2
	movdqa xmm2,xmm1
	pand   xmm2,xmm3
	subpd  xmm6,xmm2
	mulpd  xmm9,xmm2
	mulpd  xmm2,xmm12
	addpd  xmm0,xmm4
	movapd xmm4,xmm11
	movapd xmm11,xmm7
	mulpd  xmm4,xmm1
	mulpd  xmm5,xmm6
	mulpd  xmm6,xmm12
	mulpd  xmm0,xmm1
	xorpd  xmm11,xmm4
	addpd  xmm2,xmm11
	movapd xmm11,[.p5140]			; XMMWORD PTR [rip+0xb386]        # 415140 <_IO_stdin_used+0xc50>
	addpd  xmm2,xmm9
	addpd  xmm2,xmm6
	movapd xmm6,xmm4
	addpd  xmm2,xmm5
	addpd  xmm2,xmm0
	movapd xmm0,xmm4
	addpd  xmm6,xmm2
	mulpd  xmm6,[.p5130]			; XMMWORD PTR [rip+0xb351]        # 415130 <_IO_stdin_used+0xc40>
	cvtpd2dq xmm6,xmm6
	cvtdq2pd xmm5,xmm6
	mulpd  xmm11,xmm5
	mulpd  xmm5,[.p5150]			; XMMWORD PTR [rip+0xb35c]        # 415150 <_IO_stdin_used+0xc60>
	addpd  xmm0,xmm11
	movapd xmm9,xmm0
	movapd xmm12,xmm0
	subpd  xmm9,xmm4
	subpd  xmm12,xmm9
	subpd  xmm11,xmm9
	movapd xmm9,xmm0
	addpd  xmm9,xmm5
	subpd  xmm4,xmm12
	movapd xmm13,xmm9
	addpd  xmm4,xmm11
	addpd  xmm4,xmm2
	movapd xmm2,xmm9
	subpd  xmm2,xmm0
	subpd  xmm13,xmm2
	subpd  xmm5,xmm2
	movapd xmm2,xmm9
	subpd  xmm0,xmm13
	addpd  xmm0,xmm5
	movapd xmm5,xmm9
	addpd  xmm0,xmm4
	addpd  xmm2,xmm0
	subpd  xmm5,xmm2
	movdqa xmm4,xmm2
	movapd xmm14,xmm2
	pand   xmm4,xmm3
	movapd xmm9,xmm2
	movapd xmm12,xmm4
	subpd  xmm14,xmm4
	mulpd  xmm9,xmm2
	addpd  xmm5,xmm0
	movapd xmm0,[.p5290]			; XMMWORD PTR [rip+0xb403]        # 415290 <_IO_stdin_used+0xda0>
	addpd  xmm12,xmm4
	mulpd  xmm4,xmm4
	mulpd  xmm0,xmm2
	movapd xmm13,xmm14
	mulpd  xmm13,xmm14
	movapd xmm11,xmm5
	mulpd  xmm12,xmm14
	addpd  xmm11,xmm5
	movapd xmm14,xmm7
	xorpd  xmm14,xmm9
	addpd  xmm4,xmm14
	movapd xmm14,xmm7
	addpd  xmm0,[.p52a0]			; XMMWORD PTR [rip+0xb3d1]        # 4152a0 <_IO_stdin_used+0xdb0>
	mulpd  xmm11,xmm2
	addpd  xmm4,xmm12
	movapd xmm12,xmm9
	mulpd  xmm0,xmm2
	addpd  xmm4,xmm13
	addpd  xmm0,[.p52b0]			; XMMWORD PTR [rip+0xb3c1]        # 4152b0 <_IO_stdin_used+0xdc0>
	addpd  xmm4,xmm11
	movdqa xmm11,xmm9
	pand   xmm11,xmm3
	subpd  xmm12,xmm11
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p52c0]			; XMMWORD PTR [rip+0xb3b1]        # 4152c0 <_IO_stdin_used+0xdd0>
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p52d0]			; XMMWORD PTR [rip+0xb3b5]        # 4152d0 <_IO_stdin_used+0xde0>
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p52e0]			; XMMWORD PTR [rip+0xb3b9]        # 4152e0 <_IO_stdin_used+0xdf0>
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p52f0]			; XMMWORD PTR [rip+0xb3bd]        # 4152f0 <_IO_stdin_used+0xe00>
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p5300]			; XMMWORD PTR [rip+0xb3c1]        # 415300 <_IO_stdin_used+0xe10>
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p5310]			; XMMWORD PTR [rip+0xb3c5]        # 415310 <_IO_stdin_used+0xe20>
	mulpd  xmm0,xmm2
	addpd  xmm0,[.p5320]			; XMMWORD PTR [rip+0xb3c9]        # 415320 <_IO_stdin_used+0xe30>
	mulpd  xmm9,xmm0
	movapd xmm13,xmm0
	pand   xmm3,xmm0
	mulpd  xmm4,xmm0
	subpd  xmm13,xmm3
	movapd xmm0,xmm12
	mulpd  xmm12,xmm3
	mulpd  xmm3,xmm11
	mulpd  xmm0,xmm13
	xorpd  xmm14,xmm9
	mulpd  xmm13,xmm11
	movdqa xmm11,[.p4970]			; XMMWORD PTR [rip+0xa9db]        # 414970 <_IO_stdin_used+0x480>
	addpd  xmm3,xmm14
	addpd  xmm3,xmm12
	movdqa xmm12,[.p49f0]			; XMMWORD PTR [rip+0xaa48]        # 4149f0 <_IO_stdin_used+0x500>
	addpd  xmm3,xmm13
	addpd  xmm3,xmm0
	movapd xmm0,xmm2
	addpd  xmm0,xmm9
	addpd  xmm3,xmm4
	movapd xmm4,xmm8
	subpd  xmm2,xmm0
	addpd  xmm4,xmm0
	addpd  xmm2,xmm9
	addpd  xmm2,xmm5
	addpd  xmm2,xmm3
	movapd xmm3,xmm8
	subpd  xmm3,xmm4
	addpd  xmm3,xmm0
	addpd  xmm3,xmm2
	movdqa xmm2,xmm6
	psrad  xmm2,0x1f
	movdqa xmm0,xmm2
	paddd  xmm0,xmm6
	addpd  xmm3,xmm4
	movdqa xmm4,[.p4960]			; XMMWORD PTR [rip+0xa95a]        # 414960 <_IO_stdin_used+0x470>
	psrad  xmm0,0x9
	psubd  xmm0,xmm2
	pslld  xmm0,0x7
	movdqa xmm2,xmm0
	paddd  xmm0,[.p4950]			; XMMWORD PTR [rip+0xa930]        # 414950 <_IO_stdin_used+0x460>
	pslld  xmm2,0x2
	psubd  xmm6,xmm2
	pxor   xmm2,xmm2
	pcmpgtd xmm2,xmm0
	paddd  xmm6,[.p4950]			; XMMWORD PTR [rip+0xa917]        # 414950 <_IO_stdin_used+0x460>
	pandn  xmm2,xmm0
	movdqa xmm0,xmm2
	shufps xmm6,xmm6,0x73
	pcmpgtd xmm0,[.p4960]			; XMMWORD PTR [rip+0xa913]        # 414960 <_IO_stdin_used+0x470>
	pslld  xmm6,0x14
	pand   xmm4,xmm0
	pandn  xmm0,xmm2
	por    xmm0,xmm4
	shufps xmm0,xmm0,0x73
	pslld  xmm0,0x14
	xorpd  xmm4,xmm4
	mulpd  xmm3,xmm0
	movapd xmm5,xmm4
	movdqa xmm2,dqword [rbp+48]
	cmpltpd xmm5,xmm15
	pand   xmm2,[.p4f00]			; XMMWORD PTR [rip+0xae79]        # 414f00 <_IO_stdin_used+0xa10>
	movdqa xmm9,xmm5
	mulpd  xmm3,xmm0
	mulpd  xmm3,xmm0
	mulpd  xmm3,xmm0
	movdqa xmm0,[.p4b70]			; XMMWORD PTR [rip+0xaad0]        # 414b70 <_IO_stdin_used+0x680>
	mulpd  xmm3,xmm6
	movdqa xmm6,dqword [rbp+48]
	pandn  xmm6,xmm0
	por    xmm2,xmm6
	por    xmm2,dqword [rbp+16]
	pandn  xmm9,xmm2
	movdqa xmm2,xmm5
	movdqa xmm5,xmm1
	pand   xmm2,xmm0
	por    xmm2,xmm9
	pand   xmm5,xmm11
	mulpd  xmm3,xmm2
	movapd xmm2,dqword [rbp+64]
	subpd  xmm2,xmm8
	cmpeqpd xmm8,xmm15
	pxor   xmm5,xmm2
	movapd xmm2,xmm5
	cmpltpd xmm5,xmm4
	cmpeqpd xmm2,xmm4
	movdqa xmm9,xmm2
	pand   xmm2,xmm0
	pandn  xmm9,xmm12
	por    xmm2,xmm9
	pandn  xmm5,xmm2
	movapd xmm9,[.p49f0]			; XMMWORD PTR [rip+0xa8d6]        # 4149f0 <_IO_stdin_used+0x500>
	movapd xmm2,xmm7
	xorpd  xmm7,xmm1
	andnpd xmm2,xmm1
	cmpeqpd xmm2,xmm9
	cmpeqpd xmm9,dqword [rbp+64]
	movdqa xmm13,xmm2
	pand   xmm5,xmm2
	pandn  xmm13,xmm3
	movapd xmm3,xmm15
	por    xmm5,xmm13
	cmpeqpd xmm3,xmm4
	movdqa xmm2,xmm3
	pand   xmm7,xmm3
	por    xmm3,xmm9
	pandn  xmm2,xmm1
	por    xmm7,xmm2
	cmpltpd xmm7,xmm4
	movdqa xmm2,xmm15
	pand   xmm2,xmm11
	por    xmm2,xmm0
	pand   xmm2,dqword [rbp+48]
	pandn  xmm7,xmm12
	por    xmm2,xmm6
	mulpd  xmm2,xmm7
	movdqa xmm6,xmm3
	pandn  xmm6,xmm5
	movapd xmm5,xmm15
	cmpneqpd xmm5,xmm15
	pand   xmm2,xmm3
	movapd xmm3,xmm1
	por    xmm2,xmm6
	cmpneqpd xmm3,xmm1
	cmpeqpd xmm1,xmm4
	por    xmm3,xmm5
	por    xmm3,xmm2
	por    xmm1,xmm8
	movdqa xmm2,xmm1
	pand   xmm0,xmm1
	pandn  xmm2,xmm3
	por    xmm0,xmm2
	add	rsp, 16*16
	pop	rbp
	epilog
dalign
.p4950:
	db	0xff,0x03,0,0,0xff,0x03,0,0,0,0,0,0,0,0,0,0
dalign
.p4960:
	db	0xff,0x07,0,0,0xff,0x07,0,0,0,0,0,0,0,0,0,0
dalign
.p4970:
	db	0,0,0,0,0,0,0,0x80,0,0,0,0,0,0,0,0x80
dalign
.p4980:
	db	0,0,0,0,0,0,0x30,0x2d,0,0,0,0,0,0,0x30,0x2d
dalign
.p4990:
	db	0,0,0,0,0,0,0xb0,0x52,0,0,0,0,0,0,0xb0,0x52
dalign
.p49a0:
	db	0,0,0,0,0,0,0xf0,0xff,0,0,0,0,0,0,0xf0,0xff
dalign
.p49b0:
	db	0,0,0,0,0xfe,0x03,0,0,0,0,0,0,0xfe,0x03,0,0
dalign
.p49c0:
	db	0,0,0,0,0x2a,0x05,0,0,0,0,0,0,0x2a,0x05,0,0
dalign
.p49d0:
	db	0x01,0,0,0,0x01,0,0,0,0,0,0,0,0,0,0,0
dalign
.p49f0:
	db	0,0,0,0,0,0,0xf0,0x7f,0,0,0,0,0,0,0xf0,0x7f
dalign
.p4af0:
	db	0,0,0,0xf8,0xff,0xff,0xff,0xff,0,0,0,0xf8,0xff,0xff,0xff,0xff
dalign
.p4b70:
	db	0,0,0,0,0,0,0xf0,0x3f,0,0,0,0,0,0,0xf0,0x3f
dalign
.p4f00:
	db	0,0,0,0,0,0,0xf0,0xbf,0,0,0,0,0,0,0xf0,0xbf
dalign
.p5090:
	db	0x1b,0x0d,0xe0,0x2d,0x90,0xa0,0xe6,0x3f,0x1b,0x0d,0xe0,0x2d,0x90,0xa0,0xe6,0x3f
dalign
.p5110:
	db	0,0,0,0,0,0,0,0x40,0,0,0,0,0,0,0,0x40
dalign
.p5120:
	db	0xef,0x39,0xfa,0xfe,0x42,0x2e,0xe6,0x3f,0xef,0x39,0xfa,0xfe,0x42,0x2e,0xe6,0x3f
dalign
.p5130:
	db	0xfe,0x82,0x2b,0x65,0x47,0x15,0xf7,0x3f,0xfe,0x82,0x2b,0x65,0x47,0x15,0xf7,0x3f
dalign
.p5140:
	db	0,0x30,0xfa,0xfe,0x42,0x2e,0xe6,0xbf,0,0x30,0xfa,0xfe,0x42,0x2e,0xe6,0xbf
dalign
.p5150:
	db	0xe6,0xec,0x78,0xf2,0x6a,0xde,0x53,0xbd,0xe6,0xec,0x78,0xf2,0x6a,0xde,0x53,0xbd
dalign
.p5200:
	db	0xe2,0xb2,0x25,0x4f,0xa3,0x3a,0xc1,0x3f,0xe2,0xb2,0x25,0x4f,0xa3,0x3a,0xc1,0x3f
dalign
.p5210:
	db	0x30,0x61,0x9e,0xe6,0x84,0xed,0xc0,0x3f,0x30,0x61,0x9e,0xe6,0x84,0xed,0xc0,0x3f
dalign
.p5220:
	db	0xa6,0x90,0x6f,0x02,0x74,0xb2,0xc3,0x3f,0xa6,0x90,0x6f,0x02,0x74,0xb2,0xc3,0x3f
dalign
.p5230:
	db	0x0e,0xce,0xa2,0x20,0xcb,0x45,0xc7,0x3f,0x0e,0xce,0xa2,0x20,0xcb,0x45,0xc7,0x3f
dalign
.p5240:
	db	0x4e,0xbc,0xfe,0x2f,0xc7,0x71,0xcc,0x3f,0x4e,0xbc,0xfe,0x2f,0xc7,0x71,0xcc,0x3f
dalign
.p5250:
	db	0xa1,0xd1,0x37,0x92,0x24,0x49,0xd2,0x3f,0xa1,0xd1,0x37,0x92,0x24,0x49,0xd2,0x3f
dalign
.p5260:
	db	0x41,0xa9,0x99,0x99,0x99,0x99,0xd9,0x3f,0x41,0xa9,0x99,0x99,0x99,0x99,0xd9,0x3f
dalign
.p5270:
	db	0x53,0x55,0x55,0x55,0x55,0x55,0xe5,0x3f,0x53,0x55,0x55,0x55,0x55,0x55,0xe5,0x3f
dalign
.p5280:
	db	0x3f,0x80,0x39,0x3b,0x9e,0xbc,0x7a,0x3c,0x3f,0x80,0x39,0x3b,0x9e,0xbc,0x7a,0x3c
dalign
.p5290:
	db	0xb9,0x56,0x14,0xd5,0x59,0xf5,0x5a,0x3e,0xb9,0x56,0x14,0xd5,0x59,0xf5,0x5a,0x3e
dalign
.p52a0:
	db	0xad,0xb5,0x6d,0x69,0x8f,0x8a,0x92,0x3e,0xad,0xb5,0x6d,0x69,0x8f,0x8a,0x92,0x3e
dalign
.p52b0:
	db	0x5e,0x26,0x7d,0xd2,0xdf,0x1d,0xc7,0x3e,0x5e,0x26,0x7d,0xd2,0xdf,0x1d,0xc7,0x3e
dalign
.p52c0:
	db	0x1b,0x49,0x6c,0xec,0x99,0x01,0xfa,0x3e,0x1b,0x49,0x6c,0xec,0x99,0x01,0xfa,0x3e
dalign
.p52d0:
	db	0x3d,0xc3,0xe0,0x1a,0xa0,0x01,0x2a,0x3f,0x3d,0xc3,0xe0,0x1a,0xa0,0x01,0x2a,0x3f
dalign
.p52e0:
	db	0x7b,0xec,0x28,0x18,0x6c,0xc1,0x56,0x3f,0x7b,0xec,0x28,0x18,0x6c,0xc1,0x56,0x3f
dalign
.p52f0:
	db	0x68,0xfb,0x10,0x11,0x11,0x11,0x81,0x3f,0x68,0xfb,0x10,0x11,0x11,0x11,0x81,0x3f
dalign
.p5300:
	db	0x90,0x0e,0x55,0x55,0x55,0x55,0xa5,0x3f,0x90,0x0e,0x55,0x55,0x55,0x55,0xa5,0x3f
dalign
.p5310:
	db	0x58,0x55,0x55,0x55,0x55,0x55,0xc5,0x3f,0x58,0x55,0x55,0x55,0x55,0x55,0xc5,0x3f
dalign
.p5320:
	db	0x09,0x00,0x00,0x00,0x00,0x00,0xe0,0x3f,0x09,0x00,0x00,0x00,0x00,0x00,0xe0,0x3f
end if


cephes_frexp = 0

if cephes_frexp

if used frexp | defined include_everything
	; two arguments: (double)xmm0 and rdi == expptr, returns in xmm0
falign
frexp:
	prolog frexp
	sub	rsp, 8
	movq	[rsp], xmm0
	movzx	eax, word [rsp+6]
	mov	ecx, eax
	shr	ecx, 4
	and	ecx, 0x7ff
	test	ecx, ecx
	jnz	.ieeedon
	comisd	xmm0, [_math_zero]
	je	.zero
	movq	xmm1, [_math_two]
calign
.again:
	mulsd	xmm0, xmm1		; *= 2.0
	sub	ecx, 1			; i--
	movq	[rsp], xmm0		; put it back for our union (TODO: pull me differently)
	movzx	eax, word [rsp+6]	; get back q
	shr	eax, 4			; >> 4
	and	eax, 0x7ff		; & 0x7ff
	test	eax, eax		; k =
	jz	.again			; while (k == 0)
	add	ecx, eax		; i += k
	; ieeedon fallthrough copy
	sub	ecx, 0x3fe		; i -= 0x3fe
	mov	dword [rdi], ecx	; expptr = i
	movzx	eax, word [rsp+6]
	and	eax, 0x800f		; q &= 0x800f
	or	eax, 0x3fe0		; q |= 0x3fe0
	mov	word [rsp+6], ax
	movq	xmm0, [rsp]
	add	rsp, 8
	epilog
calign
.ieeedon:
	sub	ecx, 0x3fe		; i -= 0x3fe
	mov	dword [rdi], ecx	; expptr = i
	movzx	eax, word [rsp+6]
	and	eax, 0x800f		; q &= 0x800f
	or	eax, 0x3fe0		; q |= 0x3fe0
	mov	word [rsp+6], ax
	movq	xmm0, [rsp]
	add	rsp, 8
	epilog
calign
.zero:
	movq	xmm0, [_math_zero]
	mov	dword [rdi], 0
	add	rsp, 8
	epilog
end if


else

if used frexp | defined include_everything
	; two arguments: (double)xmm0 and rdi == expptr, returns in xmm0
falign
frexp:
	prolog frexp
	sub	rsp, 8
	movq	[rsp], xmm0
	mov	ecx, dword [rsp]		; lx
	mov	edx, dword [rsp+4]		; hx
	mov	eax, edx			; ix = hx
	and	eax, 0x7fffffff			; & 0x7fffffff
	mov	dword [rdi], 0			; *expptr = 0
	cmp	eax, 0x7ff00000
	jae	.puke				; xmm unmodified, return
	mov	r8d, eax
	or	r8d, ecx			; lx|ix
	test	r8d, r8d
	jz	.puke
	cmp	eax, 0x00100000
	jb	.sub
	shr	eax, 20
	sub	eax, 1022
	mov	dword [rdi], eax
	and	edx, 0x800fffff
	or	edx, 0x3fe00000
	mov	dword [rsp+4], edx
	movq	xmm0, [rsp]
	add	rsp, 8
	epilog
calign
.puke:
	epilog
calign
.t54	dq	1.80143985094819840000e+16
calign
.sub:
	movq	xmm1, [.t54]
	mulsd	xmm0, xmm1
	movq	[rsp], xmm0
	mov	edx, dword [rsp+4]
	mov	r8d, edx
	and	r8d, 0x7fffffff;
	mov	eax, r8d
	mov	dword [rdi], -54
	shr	eax, 20
	sub	eax, 1022
	add	dword [rdi], eax
	and	edx, 0x800fffff
	or	edx, 0x3fe00000
	mov	dword [rsp+4], edx
	movq	xmm0, [rsp]
	add	rsp, 8
	epilog

end if

end if


if used isnan | defined include_everything
	; single argument in xmm0, return in eax
falign
isnan:
	prolog	isnan
	sub	rsp, 8
	movq	[rsp], xmm0
	mov	eax, [rsp+4]
	mov	ecx, [rsp]
	mov	edx, ecx
	and	eax, 0x7fffffff
	neg	edx
	mov	r8d, 0x7ff00000
	or	ecx, edx
	shr	ecx, 31
	or	eax, ecx
	sub	r8d, eax
	shr	r8d, 31
	mov	eax, r8d
	add	rsp, 8
	epilog
end if


if used isinfinite | defined include_everything
	; single argument in xmm0, return in eax
falign
isinfinite:
	prolog	isinfinite
	sub	rsp, 8
	movq	[rsp], xmm0
	mov	eax, [rsp+4]
	mov	ecx, [rsp]
	mov	edx, eax
	and	eax, 0x7fffffff
	xor	eax, 0x7ff00000
	or	ecx, eax
	mov	eax, ecx
	neg	eax
	or	ecx, eax
	shr	ecx, 31
	shr	edx, 30
	not	ecx
	and	ecx, edx
	mov	eax, ecx
	add	rsp, 8
	epilog

end if

if used isfinite | defined include_everything
	; single argument in xmm0, return in eax
falign
isfinite:
	prolog	isfinite
	call	isinfinite
	mov	ecx, eax
	xor	edx, edx
	mov	eax, 1
	test	ecx, ecx
	cmovnz	eax, edx
	epilog

end if

if used floor | defined include_everything
	; single argument in xmm0, return in xmm0
falign
floor:
	prolog	floor
	movq	rax, xmm0
	xorpd	xmm1, xmm1
	push	rax
	call	isnan
	test	eax, eax
	jnz	.do_ret
	call	isinfinite
	test	eax, eax
	jnz	.do_ret
	comisd	xmm0, xmm1
	je	.do_ret
	movzx	ecx, word [rsp+6]
	shr	ecx, 4
	and	ecx, 0x7ff
	mov	rax, rsp
	sub	ecx, 0x3ff
	cmp	ecx, 0
	jge	.enotlessthanzero
	comisd	xmm0, xmm1
	jae	.retzero
	movq	xmm0, [_math_negone]
	add	rsp, 8
	epilog
calign
.retzero:
	xorpd	xmm0, xmm0
	add	rsp, 8
	epilog
calign
.enotlessthanzero:
	mov	edx, 52
	sub	edx, ecx
	mov	ecx, edx
calign
.cleanoutloop:
	cmp	ecx, 16
	jb	.doneclearing
	mov	word [rax], 0
	add	rax, 2
	sub	ecx, 16
	jmp	.cleanoutloop
calign
.doneclearing:
	cmp	ecx, 0
	jle	.nomask
	movzx	edx, word [rax]
	mov	r9, .bmask
	add	r9, rcx
	add	r9, rcx
	and	dx, word [r9]
	mov	word [rax], dx
calign
.nomask:
	comisd	xmm0, xmm1
	jae	.retrsp
	comisd	xmm0, [rsp]
	je	.retrsp
	movq	xmm0, [rsp]
	subsd	xmm0, [_math_one]
	add	rsp, 8
	epilog
calign
.retrsp:
	movq	xmm0, [rsp]
	add	rsp, 8
	epilog
calign
.do_ret:
	; xmm0 must be good
	add	rsp, 8
	epilog
dalign
.bmask  dw      0xffff, 0xfffe, 0xfffc, 0xfff8, 0xfff0, 0xffe0, 0xffc0, 0xff80, 0xff00, 0xfe00, 0xfc00, 0xf800, 0xf000, 0xe000, 0xc000, 0x8000, 0x0000
end if


if used fmod | defined include_everything
	; two arguments, xmm0 and xmm1
	; CAUTION: NO ERROR CHECKING!
falign
fmod:
	prolog	fmod
	; q <- integer(roundtowardnearestinteger(xmm0 / xmm1))
	; xmm0 <- xmm0 - (xmm1 * q)
	movq	xmm2, xmm0
	divsd	xmm2, xmm1
	cvtsd2si	rax, xmm2
	cvtsi2sd	xmm2, rax
	mulsd	xmm2, xmm1
	subsd	xmm0, xmm2
	epilog

end if


if used ceil | defined include_everything
	; single argument in xmm0, return in xmm0
falign
ceil:
	prolog	ceil
	call	isnan
	test	eax, eax
	jnz	.do_ret
	call	isfinite
	test	eax, eax
	jz	.do_ret
	movsd	xmm2, xmm0	; save x
	call	floor
	comisd	xmm0, xmm2
	jae	.noaddone
	addsd	xmm0, [_math_one]
calign
.noaddone:
	comisd	xmm0, [_math_zero]
	jne	.do_ret
	comisd	xmm2, [_math_zero]
	jae	.do_ret
	movq	xmm0, qword [_math_negzero]
	epilog
calign
.do_ret:
	; xmm0 must be good
	epilog
end if
