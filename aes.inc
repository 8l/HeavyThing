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
	; aes.inc: aes128/aes192/aes256 goodies, based on public domain implementation from Wei Dai
	;
	; NOTE: in keeping with my overall library requirement of SSE2-only operation, if AESNI is available
	; we happily make use of it, but otherwise, falls back to plain-old x86_64 version.
	;
	; Some notes here on timing attacks and the like for the non-AESNI version only:
	; I have implemented the Wei Dai timing countermeasures, there really isn't a performance hit.
	; and it appears to directly address the issues raised by Joseph Bonneau and Ilya Mironov back in 2006.
	; (32M block samples required.)
	; 
	; Considering that Wei Dai's own library which has been externally validated is _not_ using
	; the countermeasure (thanks to gcc optimizing it out wholly), I very much doubt this matters a great deal,
	; and it certainly doesn't matter for the way I use these tidbits.
	;
	; YMMV. hahah
	;

aes_rounds_ofs = 0
aes_loopidx_ofs = 8		; either (0, 1, or 2) << 3 depending on whether we are AES128, AES192, or AES256 (unrolls the round loop accordingly)
aes_roundkeys_ofs = 16		; round keys themselves, room for 15 x 16 bytes worth
aes_size = 264			; we actually only need 256, but all of the aesni goods require our object to be aligned 16, so on entry, we force-align rdi


if used aes$tls | defined include_everything
	; aes$tls is just a function wrapper for the 4 functions that we provide such that it can do function call hooks to here
dalign
aes$tls:
	dq	aes$init_encrypt, aes$encrypt, aes$init_decrypt, aes$decrypt

end if



if public_funcs & (used aes$Se | used aes$Sd | used aes$Td | used aes$Te)

dalign
public aes$data
aes$data:
end if

if used aes$Se | defined include_everything

dalign
aes$Se:
	db	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d
	db	0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
	db	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2
	db	0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
	db	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb
	db	0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
	db	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d
	db	0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
	db	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d
	db	0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
	db	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9
	db	0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
	db	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

end if

if used aes$Sd | defined include_everything

dalign
aes$Sd:
	db	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82
	db	0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d
	db	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49
	db	0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
	db	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00
	db	0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02
	db	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce
	db	0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
	db	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b
	db	0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31
	db	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f
	db	0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
	db	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d


end if


if used aes$Te | defined include_everything

dalign
aes$Te:
	dd	0xc6636300, 0xc66363a5, 0xf87c7c00, 0xf87c7c84, 0xee777700, 0xee777799, 0xf67b7b00, 0xf67b7b8d
	dd	0xfff2f200, 0xfff2f20d, 0xd66b6b00, 0xd66b6bbd, 0xde6f6f00, 0xde6f6fb1, 0x91c5c500, 0x91c5c554
	dd	0x60303000, 0x60303050, 0x02010100, 0x02010103, 0xce676700, 0xce6767a9, 0x562b2b00, 0x562b2b7d
	dd	0xe7fefe00, 0xe7fefe19, 0xb5d7d700, 0xb5d7d762, 0x4dabab00, 0x4dababe6, 0xec767600, 0xec76769a
	dd	0x8fcaca00, 0x8fcaca45, 0x1f828200, 0x1f82829d, 0x89c9c900, 0x89c9c940, 0xfa7d7d00, 0xfa7d7d87
	dd	0xeffafa00, 0xeffafa15, 0xb2595900, 0xb25959eb, 0x8e474700, 0x8e4747c9, 0xfbf0f000, 0xfbf0f00b
	dd	0x41adad00, 0x41adadec, 0xb3d4d400, 0xb3d4d467, 0x5fa2a200, 0x5fa2a2fd, 0x45afaf00, 0x45afafea
	dd	0x239c9c00, 0x239c9cbf, 0x53a4a400, 0x53a4a4f7, 0xe4727200, 0xe4727296, 0x9bc0c000, 0x9bc0c05b
	dd	0x75b7b700, 0x75b7b7c2, 0xe1fdfd00, 0xe1fdfd1c, 0x3d939300, 0x3d9393ae, 0x4c262600, 0x4c26266a
	dd	0x6c363600, 0x6c36365a, 0x7e3f3f00, 0x7e3f3f41, 0xf5f7f700, 0xf5f7f702, 0x83cccc00, 0x83cccc4f
	dd	0x68343400, 0x6834345c, 0x51a5a500, 0x51a5a5f4, 0xd1e5e500, 0xd1e5e534, 0xf9f1f100, 0xf9f1f108
	dd	0xe2717100, 0xe2717193, 0xabd8d800, 0xabd8d873, 0x62313100, 0x62313153, 0x2a151500, 0x2a15153f
	dd	0x08040400, 0x0804040c, 0x95c7c700, 0x95c7c752, 0x46232300, 0x46232365, 0x9dc3c300, 0x9dc3c35e
	dd	0x30181800, 0x30181828, 0x37969600, 0x379696a1, 0x0a050500, 0x0a05050f, 0x2f9a9a00, 0x2f9a9ab5
	dd	0x0e070700, 0x0e070709, 0x24121200, 0x24121236, 0x1b808000, 0x1b80809b, 0xdfe2e200, 0xdfe2e23d
	dd	0xcdebeb00, 0xcdebeb26, 0x4e272700, 0x4e272769, 0x7fb2b200, 0x7fb2b2cd, 0xea757500, 0xea75759f
	dd	0x12090900, 0x1209091b, 0x1d838300, 0x1d83839e, 0x582c2c00, 0x582c2c74, 0x341a1a00, 0x341a1a2e
	dd	0x361b1b00, 0x361b1b2d, 0xdc6e6e00, 0xdc6e6eb2, 0xb45a5a00, 0xb45a5aee, 0x5ba0a000, 0x5ba0a0fb
	dd	0xa4525200, 0xa45252f6, 0x763b3b00, 0x763b3b4d, 0xb7d6d600, 0xb7d6d661, 0x7db3b300, 0x7db3b3ce
	dd	0x52292900, 0x5229297b, 0xdde3e300, 0xdde3e33e, 0x5e2f2f00, 0x5e2f2f71, 0x13848400, 0x13848497
	dd	0xa6535300, 0xa65353f5, 0xb9d1d100, 0xb9d1d168, 0x00000000, 0x00000000, 0xc1eded00, 0xc1eded2c
	dd	0x40202000, 0x40202060, 0xe3fcfc00, 0xe3fcfc1f, 0x79b1b100, 0x79b1b1c8, 0xb65b5b00, 0xb65b5bed
	dd	0xd46a6a00, 0xd46a6abe, 0x8dcbcb00, 0x8dcbcb46, 0x67bebe00, 0x67bebed9, 0x72393900, 0x7239394b
	dd	0x944a4a00, 0x944a4ade, 0x984c4c00, 0x984c4cd4, 0xb0585800, 0xb05858e8, 0x85cfcf00, 0x85cfcf4a
	dd	0xbbd0d000, 0xbbd0d06b, 0xc5efef00, 0xc5efef2a, 0x4faaaa00, 0x4faaaae5, 0xedfbfb00, 0xedfbfb16
	dd	0x86434300, 0x864343c5, 0x9a4d4d00, 0x9a4d4dd7, 0x66333300, 0x66333355, 0x11858500, 0x11858594
	dd	0x8a454500, 0x8a4545cf, 0xe9f9f900, 0xe9f9f910, 0x04020200, 0x04020206, 0xfe7f7f00, 0xfe7f7f81
	dd	0xa0505000, 0xa05050f0, 0x783c3c00, 0x783c3c44, 0x259f9f00, 0x259f9fba, 0x4ba8a800, 0x4ba8a8e3
	dd	0xa2515100, 0xa25151f3, 0x5da3a300, 0x5da3a3fe, 0x80404000, 0x804040c0, 0x058f8f00, 0x058f8f8a
	dd	0x3f929200, 0x3f9292ad, 0x219d9d00, 0x219d9dbc, 0x70383800, 0x70383848, 0xf1f5f500, 0xf1f5f504
	dd	0x63bcbc00, 0x63bcbcdf, 0x77b6b600, 0x77b6b6c1, 0xafdada00, 0xafdada75, 0x42212100, 0x42212163
	dd	0x20101000, 0x20101030, 0xe5ffff00, 0xe5ffff1a, 0xfdf3f300, 0xfdf3f30e, 0xbfd2d200, 0xbfd2d26d
	dd	0x81cdcd00, 0x81cdcd4c, 0x180c0c00, 0x180c0c14, 0x26131300, 0x26131335, 0xc3ecec00, 0xc3ecec2f
	dd	0xbe5f5f00, 0xbe5f5fe1, 0x35979700, 0x359797a2, 0x88444400, 0x884444cc, 0x2e171700, 0x2e171739
	dd	0x93c4c400, 0x93c4c457, 0x55a7a700, 0x55a7a7f2, 0xfc7e7e00, 0xfc7e7e82, 0x7a3d3d00, 0x7a3d3d47
	dd	0xc8646400, 0xc86464ac, 0xba5d5d00, 0xba5d5de7, 0x32191900, 0x3219192b, 0xe6737300, 0xe6737395
	dd	0xc0606000, 0xc06060a0, 0x19818100, 0x19818198, 0x9e4f4f00, 0x9e4f4fd1, 0xa3dcdc00, 0xa3dcdc7f
	dd	0x44222200, 0x44222266, 0x542a2a00, 0x542a2a7e, 0x3b909000, 0x3b9090ab, 0x0b888800, 0x0b888883
	dd	0x8c464600, 0x8c4646ca, 0xc7eeee00, 0xc7eeee29, 0x6bb8b800, 0x6bb8b8d3, 0x28141400, 0x2814143c
	dd	0xa7dede00, 0xa7dede79, 0xbc5e5e00, 0xbc5e5ee2, 0x160b0b00, 0x160b0b1d, 0xaddbdb00, 0xaddbdb76
	dd	0xdbe0e000, 0xdbe0e03b, 0x64323200, 0x64323256, 0x743a3a00, 0x743a3a4e, 0x140a0a00, 0x140a0a1e
	dd	0x92494900, 0x924949db, 0x0c060600, 0x0c06060a, 0x48242400, 0x4824246c, 0xb85c5c00, 0xb85c5ce4
	dd	0x9fc2c200, 0x9fc2c25d, 0xbdd3d300, 0xbdd3d36e, 0x43acac00, 0x43acacef, 0xc4626200, 0xc46262a6
	dd	0x39919100, 0x399191a8, 0x31959500, 0x319595a4, 0xd3e4e400, 0xd3e4e437, 0xf2797900, 0xf279798b
	dd	0xd5e7e700, 0xd5e7e732, 0x8bc8c800, 0x8bc8c843, 0x6e373700, 0x6e373759, 0xda6d6d00, 0xda6d6db7
	dd	0x018d8d00, 0x018d8d8c, 0xb1d5d500, 0xb1d5d564, 0x9c4e4e00, 0x9c4e4ed2, 0x49a9a900, 0x49a9a9e0
	dd	0xd86c6c00, 0xd86c6cb4, 0xac565600, 0xac5656fa, 0xf3f4f400, 0xf3f4f407, 0xcfeaea00, 0xcfeaea25
	dd	0xca656500, 0xca6565af, 0xf47a7a00, 0xf47a7a8e, 0x47aeae00, 0x47aeaee9, 0x10080800, 0x10080818
	dd	0x6fbaba00, 0x6fbabad5, 0xf0787800, 0xf0787888, 0x4a252500, 0x4a25256f, 0x5c2e2e00, 0x5c2e2e72
	dd	0x381c1c00, 0x381c1c24, 0x57a6a600, 0x57a6a6f1, 0x73b4b400, 0x73b4b4c7, 0x97c6c600, 0x97c6c651
	dd	0xcbe8e800, 0xcbe8e823, 0xa1dddd00, 0xa1dddd7c, 0xe8747400, 0xe874749c, 0x3e1f1f00, 0x3e1f1f21
	dd	0x964b4b00, 0x964b4bdd, 0x61bdbd00, 0x61bdbddc, 0x0d8b8b00, 0x0d8b8b86, 0x0f8a8a00, 0x0f8a8a85
	dd	0xe0707000, 0xe0707090, 0x7c3e3e00, 0x7c3e3e42, 0x71b5b500, 0x71b5b5c4, 0xcc666600, 0xcc6666aa
	dd	0x90484800, 0x904848d8, 0x06030300, 0x06030305, 0xf7f6f600, 0xf7f6f601, 0x1c0e0e00, 0x1c0e0e12
	dd	0xc2616100, 0xc26161a3, 0x6a353500, 0x6a35355f, 0xae575700, 0xae5757f9, 0x69b9b900, 0x69b9b9d0
	dd	0x17868600, 0x17868691, 0x99c1c100, 0x99c1c158, 0x3a1d1d00, 0x3a1d1d27, 0x279e9e00, 0x279e9eb9
	dd	0xd9e1e100, 0xd9e1e138, 0xebf8f800, 0xebf8f813, 0x2b989800, 0x2b9898b3, 0x22111100, 0x22111133
	dd	0xd2696900, 0xd26969bb, 0xa9d9d900, 0xa9d9d970, 0x078e8e00, 0x078e8e89, 0x33949400, 0x339494a7
	dd	0x2d9b9b00, 0x2d9b9bb6, 0x3c1e1e00, 0x3c1e1e22, 0x15878700, 0x15878792, 0xc9e9e900, 0xc9e9e920
	dd	0x87cece00, 0x87cece49, 0xaa555500, 0xaa5555ff, 0x50282800, 0x50282878, 0xa5dfdf00, 0xa5dfdf7a
	dd	0x038c8c00, 0x038c8c8f, 0x59a1a100, 0x59a1a1f8, 0x09898900, 0x09898980, 0x1a0d0d00, 0x1a0d0d17
	dd	0x65bfbf00, 0x65bfbfda, 0xd7e6e600, 0xd7e6e631, 0x84424200, 0x844242c6, 0xd0686800, 0xd06868b8
	dd	0x82414100, 0x824141c3, 0x29999900, 0x299999b0, 0x5a2d2d00, 0x5a2d2d77, 0x1e0f0f00, 0x1e0f0f11
	dd	0x7bb0b000, 0x7bb0b0cb, 0xa8545400, 0xa85454fc, 0x6dbbbb00, 0x6dbbbbd6, 0x2c161600, 0x2c16163a

end if

if used aes$Td | defined include_everything

dalign
aes$Td:
	dd	0x51f4a752, 0x51f4a750, 0x7e416509, 0x7e416553, 0x1a17a46a, 0x1a17a4c3, 0x3a275ed5, 0x3a275e96
	dd	0x3bab6b30, 0x3bab6bcb, 0x1f9d4536, 0x1f9d45f1, 0xacfa58a5, 0xacfa58ab, 0x4be30338, 0x4be30393
	dd	0x2030fabf, 0x2030fa55, 0xad766d40, 0xad766df6, 0x88cc76a3, 0x88cc7691, 0xf5024c9e, 0xf5024c25
	dd	0x4fe5d781, 0x4fe5d7fc, 0xc52acbf3, 0xc52acbd7, 0x263544d7, 0x26354480, 0xb562a3fb, 0xb562a38f
	dd	0xdeb15a7c, 0xdeb15a49, 0x25ba1be3, 0x25ba1b67, 0x45ea0e39, 0x45ea0e98, 0x5dfec082, 0x5dfec0e1
	dd	0xc32f759b, 0xc32f7502, 0x814cf02f, 0x814cf012, 0x8d4697ff, 0x8d4697a3, 0x6bd3f987, 0x6bd3f9c6
	dd	0x038f5f34, 0x038f5fe7, 0x15929c8e, 0x15929c95, 0xbf6d7a43, 0xbf6d7aeb, 0x95525944, 0x955259da
	dd	0xd4be83c4, 0xd4be832d, 0x587421de, 0x587421d3, 0x49e069e9, 0x49e06929, 0x8ec9c8cb, 0x8ec9c844
	dd	0x75c28954, 0x75c2896a, 0xf48e797b, 0xf48e7978, 0x99583e94, 0x99583e6b, 0x27b97132, 0x27b971dd
	dd	0xbee14fa6, 0xbee14fb6, 0xf088adc2, 0xf088ad17, 0xc920ac23, 0xc920ac66, 0x7dce3a3d, 0x7dce3ab4
	dd	0x63df4aee, 0x63df4a18, 0xe51a314c, 0xe51a3182, 0x97513395, 0x97513360, 0x62537f0b, 0x62537f45
	dd	0xb1647742, 0xb16477e0, 0xbb6baefa, 0xbb6bae84, 0xfe81a0c3, 0xfe81a01c, 0xf9082b4e, 0xf9082b94
	dd	0x70486808, 0x70486858, 0x8f45fd2e, 0x8f45fd19, 0x94de6ca1, 0x94de6c87, 0x527bf866, 0x527bf8b7
	dd	0xab73d328, 0xab73d323, 0x724b02d9, 0x724b02e2, 0xe31f8f24, 0xe31f8f57, 0x6655abb2, 0x6655ab2a
	dd	0xb2eb2876, 0xb2eb2807, 0x2fb5c25b, 0x2fb5c203, 0x86c57ba2, 0x86c57b9a, 0xd3370849, 0xd33708a5
	dd	0x3028876d, 0x302887f2, 0x23bfa58b, 0x23bfa5b2, 0x02036ad1, 0x02036aba, 0xed168225, 0xed16825c
	dd	0x8acf1c72, 0x8acf1c2b, 0xa779b4f8, 0xa779b492, 0xf307f2f6, 0xf307f2f0, 0x4e69e264, 0x4e69e2a1
	dd	0x65daf486, 0x65daf4cd, 0x0605be68, 0x0605bed5, 0xd1346298, 0xd134621f, 0xc4a6fe16, 0xc4a6fe8a
	dd	0x342e53d4, 0x342e539d, 0xa2f355a4, 0xa2f355a0, 0x058ae15c, 0x058ae132, 0xa4f6ebcc, 0xa4f6eb75
	dd	0x0b83ec5d, 0x0b83ec39, 0x4060ef65, 0x4060efaa, 0x5e719fb6, 0x5e719f06, 0xbd6e1092, 0xbd6e1051
	dd	0x3e218a6c, 0x3e218af9, 0x96dd0670, 0x96dd063d, 0xdd3e0548, 0xdd3e05ae, 0x4de6bd50, 0x4de6bd46
	dd	0x91548dfd, 0x91548db5, 0x71c45ded, 0x71c45d05, 0x0406d4b9, 0x0406d46f, 0x605015da, 0x605015ff
	dd	0x1998fb5e, 0x1998fb24, 0xd6bde915, 0xd6bde997, 0x89404346, 0x894043cc, 0x67d99e57, 0x67d99e77
	dd	0xb0e842a7, 0xb0e842bd, 0x07898b8d, 0x07898b88, 0xe7195b9d, 0xe7195b38, 0x79c8ee84, 0x79c8eedb
	dd	0xa17c0a90, 0xa17c0a47, 0x7c420fd8, 0x7c420fe9, 0xf8841eab, 0xf8841ec9, 0x00000000, 0x00000000
	dd	0x0980868c, 0x09808683, 0x322bedbc, 0x322bed48, 0x1e1170d3, 0x1e1170ac, 0x6c5a720a, 0x6c5a724e
	dd	0xfd0efff7, 0xfd0efffb, 0x0f8538e4, 0x0f853856, 0x3daed558, 0x3daed51e, 0x362d3905, 0x362d3927
	dd	0x0a0fd9b8, 0x0a0fd964, 0x685ca6b3, 0x685ca621, 0x9b5b5445, 0x9b5b54d1, 0x24362e06, 0x24362e3a
	dd	0x0c0a67d0, 0x0c0a67b1, 0x9357e72c, 0x9357e70f, 0xb4ee961e, 0xb4ee96d2, 0x1b9b918f, 0x1b9b919e
	dd	0x80c0c5ca, 0x80c0c54f, 0x61dc203f, 0x61dc20a2, 0x5a774b0f, 0x5a774b69, 0x1c121a02, 0x1c121a16
	dd	0xe293bac1, 0xe293ba0a, 0xc0a02aaf, 0xc0a02ae5, 0x3c22e0bd, 0x3c22e043, 0x121b1703, 0x121b171d
	dd	0x0e090d01, 0x0e090d0b, 0xf28bc713, 0xf28bc7ad, 0x2db6a88a, 0x2db6a8b9, 0x141ea96b, 0x141ea9c8
	dd	0x57f1193a, 0x57f11985, 0xaf750791, 0xaf75074c, 0xee99dd11, 0xee99ddbb, 0xa37f6041, 0xa37f60fd
	dd	0xf701264f, 0xf701269f, 0x5c72f567, 0x5c72f5bc, 0x44663bdc, 0x44663bc5, 0x5bfb7eea, 0x5bfb7e34
	dd	0x8b432997, 0x8b432976, 0xcb23c6f2, 0xcb23c6dc, 0xb6edfccf, 0xb6edfc68, 0xb8e4f1ce, 0xb8e4f163
	dd	0xd731dcf0, 0xd731dcca, 0x426385b4, 0x42638510, 0x139722e6, 0x13972240, 0x84c61173, 0x84c61120
	dd	0x854a2496, 0x854a247d, 0xd2bb3dac, 0xd2bb3df8, 0xaef93274, 0xaef93211, 0xc729a122, 0xc729a16d
	dd	0x1d9e2fe7, 0x1d9e2f4b, 0xdcb230ad, 0xdcb230f3, 0x0d865235, 0x0d8652ec, 0x77c1e385, 0x77c1e3d0
	dd	0x2bb316e2, 0x2bb3166c, 0xa970b9f9, 0xa970b999, 0x11944837, 0x119448fa, 0x47e964e8, 0x47e96422
	dd	0xa8fc8c1c, 0xa8fc8cc4, 0xa0f03f75, 0xa0f03f1a, 0x567d2cdf, 0x567d2cd8, 0x2233906e, 0x223390ef
	dd	0x87494e47, 0x87494ec7, 0xd938d1f1, 0xd938d1c1, 0x8ccaa21a, 0x8ccaa2fe, 0x98d40b71, 0x98d40b36
	dd	0xa6f5811d, 0xa6f581cf, 0xa57ade29, 0xa57ade28, 0xdab78ec5, 0xdab78e26, 0x3fadbf89, 0x3fadbfa4
	dd	0x2c3a9d6f, 0x2c3a9de4, 0x507892b7, 0x5078920d, 0x6a5fcc62, 0x6a5fcc9b, 0x547e460e, 0x547e4662
	dd	0xf68d13aa, 0xf68d13c2, 0x90d8b818, 0x90d8b8e8, 0x2e39f7be, 0x2e39f75e, 0x82c3af1b, 0x82c3aff5
	dd	0x9f5d80fc, 0x9f5d80be, 0x69d09356, 0x69d0937c, 0x6fd52d3e, 0x6fd52da9, 0xcf25124b, 0xcf2512b3
	dd	0xc8ac99c6, 0xc8ac993b, 0x10187dd2, 0x10187da7, 0xe89c6379, 0xe89c636e, 0xdb3bbb20, 0xdb3bbb7b
	dd	0xcd26789a, 0xcd267809, 0x6e5918db, 0x6e5918f4, 0xec9ab7c0, 0xec9ab701, 0x834f9afe, 0x834f9aa8
	dd	0xe6956e78, 0xe6956e65, 0xaaffe6cd, 0xaaffe67e, 0x21bccf5a, 0x21bccf08, 0xef15e8f4, 0xef15e8e6
	dd	0xbae79b1f, 0xbae79bd9, 0x4a6f36dd, 0x4a6f36ce, 0xea9f09a8, 0xea9f09d4, 0x29b07c33, 0x29b07cd6
	dd	0x31a4b288, 0x31a4b2af, 0x2a3f2307, 0x2a3f2331, 0xc6a594c7, 0xc6a59430, 0x35a26631, 0x35a266c0
	dd	0x744ebcb1, 0x744ebc37, 0xfc82ca12, 0xfc82caa6, 0xe090d010, 0xe090d0b0, 0x33a7d859, 0x33a7d815
	dd	0xf1049827, 0xf104984a, 0x41ecda80, 0x41ecdaf7, 0x7fcd50ec, 0x7fcd500e, 0x1791f65f, 0x1791f62f
	dd	0x764dd660, 0x764dd68d, 0x43efb051, 0x43efb04d, 0xccaa4d7f, 0xccaa4d54, 0xe49604a9, 0xe49604df
	dd	0x9ed1b519, 0x9ed1b5e3, 0x4c6a88b5, 0x4c6a881b, 0xc12c1f4a, 0xc12c1fb8, 0x4665510d, 0x4665517f
	dd	0x9d5eea2d, 0x9d5eea04, 0x018c35e5, 0x018c355d, 0xfa87747a, 0xfa877473, 0xfb0b419f, 0xfb0b412e
	dd	0xb3671d93, 0xb3671d5a, 0x92dbd2c9, 0x92dbd252, 0xe910569c, 0xe9105633, 0x6dd647ef, 0x6dd64713
	dd	0x9ad761a0, 0x9ad7618c, 0x37a10ce0, 0x37a10c7a, 0x59f8143b, 0x59f8148e, 0xeb133c4d, 0xeb133c89
	dd	0xcea927ae, 0xcea927ee, 0xb761c92a, 0xb761c935, 0xe11ce5f5, 0xe11ce5ed, 0x7a47b1b0, 0x7a47b13c
	dd	0x9cd2dfc8, 0x9cd2df59, 0x55f273eb, 0x55f2733f, 0x1814cebb, 0x1814ce79, 0x73c7373c, 0x73c737bf
	dd	0x53f7cd83, 0x53f7cdea, 0x5ffdaa53, 0x5ffdaa5b, 0xdf3d6f99, 0xdf3d6f14, 0x7844db61, 0x7844db86
	dd	0xcaaff317, 0xcaaff381, 0xb968c42b, 0xb968c43e, 0x38243404, 0x3824342c, 0xc2a3407e, 0xc2a3405f
	dd	0x161dc3ba, 0x161dc372, 0xbce22577, 0xbce2250c, 0x283c49d6, 0x283c498b, 0xff0d9526, 0xff0d9541
	dd	0x39a801e1, 0x39a80171, 0x080cb369, 0x080cb3de, 0xd8b4e414, 0xd8b4e49c, 0x6456c163, 0x6456c190
	dd	0x7bcb8455, 0x7bcb8461, 0xd532b621, 0xd532b670, 0x486c5c0c, 0x486c5c74, 0xd0b8577d, 0xd0b85742

end if

if used aes$init_common | defined include_everything
	; (shared init code between encrypt/decrypt inits)
	; three arguments: rdi == aes object (MUST BE ALIGNED 16), rsi == ptr to key, edx == length of same (16, 24, or 32)
	; NOTE: we preserve rdi through here, the individual inits rely on this fact
falign
aes$init_common:
	prolog	aes$init_common
	mov	eax, edx
	shr	edx, 3		; edx now 2, 3, or 4
	shr	eax, 2		; eax now 4, 6, or 8
	sub	edx, 2		; edx now 0, 1, or 2
	add	eax, 6		; eax now 10, 12, or 14
	mov	r8d, edx
	mov	[rdi+aes_rounds_ofs], eax
	add	r8d, 3
	cmp	dword [has_AESNI], 1
	cmove	edx, r8d
	shl	edx, 3		; edx now 0, 8, 16, 24, 32, 40
	mov	[rdi+aes_loopidx_ofs], rdx
	jmp	qword [rdx+.dispatch]
dalign
.dispatch:
	dq	.aes128, .aes192, .aes256, .aesni128, .aesni192, .aesni256

macro aes_keygen kl*, ofs*, rcon* {
	local rk
	rk = ofs
	mov	eax, [rdi+rk*4+(kl-1)*4+aes_roundkeys_ofs]
	mov	ecx, eax
	mov	edx, eax
	mov	r8d, eax

	and	eax, 0xff0000
	and	ecx, 0xff00
	and	edx, 0xff
	and	r8d, 0xff000000
	shr	eax, 16
	shr	ecx, 8
	shr	r8d, 24
	movzx	r9d, byte [rax+aes$Se]		; 2
	movzx	r10d, byte [rcx+aes$Se]		; 1
	movzx	r11d, byte [rdx+aes$Se]		; 0
	shl	r9d, 24
	shl	r10d, 16
	shl	r11d, 8
	movzx	eax, byte [r8+aes$Se]		; 3
	xor	r9d, r10d			; why are these xors instead of ors? they'll never get xor'd as such
	xor	r9d, r11d
	xor	r9d, eax			; x
	mov	ecx, [rdi+rk*4+aes_roundkeys_ofs]	; rk[0]
	mov	edx, [rdi+rk*4+4+aes_roundkeys_ofs]	; rk[1]
	mov	r8d, [rdi+rk*4+8+aes_roundkeys_ofs]	; rk[2]
	xor	ecx, r9d
	xor	ecx, rcon
	mov	r9d, [rdi+rk*4+12+aes_roundkeys_ofs]	; rk[3]
	mov	[rdi+rk*4+kl*4+aes_roundkeys_ofs], ecx
	xor	edx, ecx
	mov	[rdi+rk*4+kl*4+4+aes_roundkeys_ofs], edx
	xor	r8d, edx
	mov	[rdi+rk*4+kl*4+8+aes_roundkeys_ofs], r8d
	xor	r9d, r8d
	mov	[rdi+rk*4+kl*4+12+aes_roundkeys_ofs], r9d
	if kl = 6 & ofs < 42
		mov	eax, [rdi+rk*4+16+aes_roundkeys_ofs]
		mov	ecx, [rdi+rk*4+20+aes_roundkeys_ofs]
		xor	eax, [rdi+rk*4+36+aes_roundkeys_ofs]
		xor	ecx, [rdi+rk*4+40+aes_roundkeys_ofs]
		mov	[rdi+rk*4+40+aes_roundkeys_ofs], eax
		mov	[rdi+rk*4+44+aes_roundkeys_ofs], ecx
	else if kl = 8 & ofs < 48
		mov	eax, [rdi+rk*4+44+aes_roundkeys_ofs]		; temp
		mov	ecx, eax
		mov	edx, eax
		mov	r8d, eax
		and	eax, 0xff000000
		and	ecx, 0xff0000
		and	edx, 0xff00
		and	r8d, 0xff
		shr	eax, 24
		shr	ecx, 16
		shr	edx, 8
		movzx	r9d, byte [rax+aes$Se]		; 3
		movzx	r10d, byte [rcx+aes$Se]		; 2
		movzx	r11d, byte [rdx+aes$Se]		; 1
		shl	r9d, 24
		shl	r10d, 16
		mov	ecx, [rdi+rk*4+16+aes_roundkeys_ofs]		; rk[4]
		mov	edx, [rdi+rk*4+20+aes_roundkeys_ofs]		; rk[5]
		shl	r11d, 8
		movzx	eax, byte [r8+aes$Se]		; 0
		xor	r9d, r10d
		xor	r9d, r11d
		xor	r9d, eax
		
		xor	ecx, r9d
	
		xor	edx, ecx			; 5 ^ 12
		
		mov	r8d, [rdi+rk*4+24+aes_roundkeys_ofs]		; rk[6]
		mov	r9d, [rdi+rk*4+28+aes_roundkeys_ofs]		; rk[7]
	
		xor	r8d, edx			; 6 ^ 13
		xor	r9d, r8d			; 7 ^ 14
		mov	[rdi+rk*4+48+aes_roundkeys_ofs], ecx		; 4 =
		mov	[rdi+rk*4+52+aes_roundkeys_ofs], edx		; 5 =
		mov	[rdi+rk*4+56+aes_roundkeys_ofs], r8d		; 6 =
		mov	[rdi+rk*4+60+aes_roundkeys_ofs], r9d		; 7 =

	end if
}

calign
.aes128:
	; 4 32 bit words in our key
if use_movbe
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	movbe	[rdi+aes_roundkeys_ofs], r8d
	movbe	[rdi+aes_roundkeys_ofs+4], r9d
	movbe	[rdi+aes_roundkeys_ofs+8], r10d
	mov	r8d, [rsi+12]
	movbe	[rdi+aes_roundkeys_ofs+12], r8d
else
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	bswap	r8d
	bswap	r9d
	bswap	r10d
	mov	[rdi+aes_roundkeys_ofs], r8d
	mov	[rdi+aes_roundkeys_ofs+4], r9d
	mov	[rdi+aes_roundkeys_ofs+8], r10d
	mov	r8d, [rsi+12]
	bswap	r8d
	mov	[rdi+aes_roundkeys_ofs+12], r8d
end if

	; rk pointed at start, 32 bit key count is 44
	; keylen/4 == 4
	aes_keygen 4, 0, 0x01000000
	aes_keygen 4, 4, 0x02000000
	aes_keygen 4, 8, 0x04000000
	aes_keygen 4, 12, 0x08000000
	aes_keygen 4, 16, 0x10000000
	aes_keygen 4, 20, 0x20000000
	aes_keygen 4, 24, 0x40000000
	aes_keygen 4, 28, 0x80000000
	aes_keygen 4, 32, 0x1B000000
	aes_keygen 4, 36, 0x36000000

	epilog
calign
.aes192:
	; 6 32 bit words in our key
if use_movbe
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	movbe	[rdi+aes_roundkeys_ofs], r8d
	movbe	[rdi+aes_roundkeys_ofs+4], r9d
	movbe	[rdi+aes_roundkeys_ofs+8], r10d
	mov	r8d, [rsi+12]
	mov	r9d, [rsi+16]
	mov	r10d, [rsi+20]
	movbe	[rdi+aes_roundkeys_ofs+12], r8d
	movbe	[rdi+aes_roundkeys_ofs+16], r9d
	movbe	[rdi+aes_roundkeys_ofs+20], r10d
else
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	bswap	r8d
	bswap	r9d
	bswap	r10d
	mov	[rdi+aes_roundkeys_ofs], r8d
	mov	[rdi+aes_roundkeys_ofs+4], r9d
	mov	[rdi+aes_roundkeys_ofs+8], r10d
	mov	r8d, [rsi+12]
	mov	r9d, [rsi+16]
	mov	r10d, [rsi+20]
	bswap	r8d
	bswap	r9d
	bswap	r10d
	mov	[rdi+aes_roundkeys_ofs+12], r8d
	mov	[rdi+aes_roundkeys_ofs+16], r9d
	mov	[rdi+aes_roundkeys_ofs+20], r10d
end if

	; rk pointed at start, 32 bit key count is 52
	; keylen/4 == 6
        aes_keygen 6, 0, 0x01000000
        aes_keygen 6, 6, 0x02000000
        aes_keygen 6, 12, 0x04000000
        aes_keygen 6, 18, 0x08000000
        aes_keygen 6, 24, 0x10000000
        aes_keygen 6, 30, 0x20000000
        aes_keygen 6, 36, 0x40000000
        aes_keygen 6, 42, 0x80000000		; ofs + keylen/4 + 4 == 52 == end, finite
	epilog
calign
.aes256:
	; 8 32 bit words in our key
if use_movbe
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	movbe	[rdi+aes_roundkeys_ofs], r8d
	movbe	[rdi+aes_roundkeys_ofs+4], r9d
	movbe	[rdi+aes_roundkeys_ofs+8], r10d
	mov	r8d, [rsi+12]
	mov	r9d, [rsi+16]
	mov	r10d, [rsi+20]
	movbe	[rdi+aes_roundkeys_ofs+12], r8d
	movbe	[rdi+aes_roundkeys_ofs+16], r9d
	movbe	[rdi+aes_roundkeys_ofs+20], r10d
	mov	r8d, [rsi+24]
	mov	r9d, [rsi+28]
	movbe	[rdi+aes_roundkeys_ofs+24], r8d
	movbe	[rdi+aes_roundkeys_ofs+28], r9d
else
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	bswap	r8d
	bswap	r9d
	bswap	r10d
	mov	[rdi+aes_roundkeys_ofs], r8d
	mov	[rdi+aes_roundkeys_ofs+4], r9d
	mov	[rdi+aes_roundkeys_ofs+8], r10d
	mov	r8d, [rsi+12]
	mov	r9d, [rsi+16]
	mov	r10d, [rsi+20]
	bswap	r8d
	bswap	r9d
	bswap	r10d
	mov	[rdi+aes_roundkeys_ofs+12], r8d
	mov	[rdi+aes_roundkeys_ofs+16], r9d
	mov	[rdi+aes_roundkeys_ofs+20], r10d
	mov	r8d, [rsi+24]
	mov	r9d, [rsi+28]
	bswap	r8d
	bswap	r9d
	mov	[rdi+aes_roundkeys_ofs+24], r8d
	mov	[rdi+aes_roundkeys_ofs+28], r9d
end if

	; rk pointed at start, 32 bit key count is 60
	; keylen/4 == 8
        aes_keygen 8, 0, 0x01000000
        aes_keygen 8, 8, 0x02000000
        aes_keygen 8, 16, 0x04000000
        aes_keygen 8, 24, 0x08000000
        aes_keygen 8, 32, 0x10000000
        aes_keygen 8, 40, 0x20000000
        aes_keygen 8, 48, 0x40000000            ; ofs + keylen/4 + 4 == 60 == end, finite
	epilog

macro aesni_keygen kl*, ofs*, rcon* {
	local rk
	rk = ofs

	mov	eax, [rdi+rk*4+aes_roundkeys_ofs]
	mov	ecx, [rdi+rk*4+aes_roundkeys_ofs+4]
	mov	r8d, [rdi+rk*4+aes_roundkeys_ofs+8]
	aeskeygenassist	xmm1, xmm0, 0
	pextrd	edx, xmm1, 3
	xor	eax, edx
	mov	r9d, [rdi+rk*4+aes_roundkeys_ofs+12]
	if kl = 6 & ofs < 42
		mov	r10d, [rdi+rk*4+aes_roundkeys_ofs+16]
		mov	r11d, [rdi+rk*4+aes_roundkeys_ofs+20]
	else if kl = 8 & ofs < 48
		; mov	r10d, [rdi+rk*4+aes_roundkeys_ofs+44]
	end if
	xor	eax, rcon
	mov	[rdi+rk*4+kl*4+aes_roundkeys_ofs], eax
	xor	ecx, eax
	mov	[rdi+rk*4+kl*4+aes_roundkeys_ofs+4], ecx
	xor	r8d, ecx
	mov	[rdi+rk*4+kl*4+aes_roundkeys_ofs+8], r8d
	xor	r9d, r8d
	mov	[rdi+rk*4+kl*4+aes_roundkeys_ofs+12], r9d
	if kl = 4 & ofs < 36
		pinsrd	xmm0, r9d, 3
	else if kl = 6 & ofs < 42
		; xor	r10d, [rdi+rk*4+aes_roundkeys_ofs+36]
		xor	r10d, r9d
		mov	[rdi+rk*4+aes_roundkeys_ofs+40], r10d
		xor	r11d, r10d
		mov	[rdi+rk*4+aes_roundkeys_ofs+44], r11d
		pinsrd	xmm0, r11d, 3
	else if kl = 8 & ofs < 48
		; pinsrd	xmm0, r10d, 3
		pinsrd	xmm0, r9d, 3
		mov	eax, [rdi+rk*4+aes_roundkeys_ofs+16]
		mov	ecx, [rdi+rk*4+aes_roundkeys_ofs+20]
		mov	r8d, [rdi+rk*4+aes_roundkeys_ofs+24]
		aeskeygenassist	xmm1, xmm0, 0
		pextrd	edx, xmm1, 2
		mov	r9d, [rdi+rk*4+aes_roundkeys_ofs+28]
		xor	eax, edx
		mov	[rdi+rk*4+aes_roundkeys_ofs+48], eax
		xor	ecx, eax
		mov	[rdi+rk*4+aes_roundkeys_ofs+52], ecx
		xor	r8d, ecx
		mov	[rdi+rk*4+aes_roundkeys_ofs+56], r8d
		xor	r9d, r8d
		mov	[rdi+rk*4+aes_roundkeys_ofs+60], r9d
		pinsrd	xmm0, r9d, 3
	end if
}

calign
.aesni128:
	movdqu	xmm0, [rsi]
	movdqu	[rdi+aes_roundkeys_ofs], xmm0

	aesni_keygen 4, 0, 0x01
	aesni_keygen 4, 4, 0x02
	aesni_keygen 4, 8, 0x04
	aesni_keygen 4, 12, 0x08
	aesni_keygen 4, 16, 0x10
	aesni_keygen 4, 20, 0x20
	aesni_keygen 4, 24, 0x40
	aesni_keygen 4, 28, 0x80
	aesni_keygen 4, 32, 0x1B
	aesni_keygen 4, 36, 0x36
	epilog

calign
.aesni192:
	mov	rax, [rsi]
	movdqu	xmm0, [rsi+8]
	mov	[rdi+aes_roundkeys_ofs], rax
	movdqu	[rdi+aes_roundkeys_ofs+8], xmm0

        aesni_keygen 6, 0, 0x01
        aesni_keygen 6, 6, 0x02
        aesni_keygen 6, 12, 0x04
        aesni_keygen 6, 18, 0x08
        aesni_keygen 6, 24, 0x10
        aesni_keygen 6, 30, 0x20
        aesni_keygen 6, 36, 0x40
        aesni_keygen 6, 42, 0x80
	epilog
calign
.aesni256:
	movdqu	xmm1, [rsi]
	movdqu	xmm0, [rsi+16]
	movdqu	[rdi+aes_roundkeys_ofs], xmm1
	movdqu	[rdi+aes_roundkeys_ofs+16], xmm0

        aesni_keygen 8, 0, 0x01
        aesni_keygen 8, 8, 0x02
        aesni_keygen 8, 16, 0x04
        aesni_keygen 8, 24, 0x08
        aesni_keygen 8, 32, 0x10
        aesni_keygen 8, 40, 0x20
        aesni_keygen 8, 48, 0x40
	epilog

end if


if used aes$init_encrypt | defined include_everything
	; three arguments: rdi == aes object, rsi == ptr to key, edx == length of same (16, 24, or 32)
	; no actual bounds checking on key length validity is done, up to the caller
falign
aes$init_encrypt:
	prolog	aes$init_encrypt
	; force align rdi to 16
	add	rdi, 0xf
	and	rdi, not 0xf
	call	aes$init_common			; rdi stays intact across this call
	cmp	dword [has_AESNI], 1
	jne	.noaesni
	; else, AESNI present, all done
	epilog
calign
.noaesni:
	; byteswap the first and last round key (4 words each)
	mov	eax, [rdi+aes_rounds_ofs]	; number of rounds
	mov	ecx, [rdi+aes_roundkeys_ofs]
	mov	edx, [rdi+aes_roundkeys_ofs+4]
	shl	eax, 4				; rounds * 16
if use_movbe
	movbe	[rdi+aes_roundkeys_ofs], ecx
	movbe	[rdi+aes_roundkeys_ofs+4], edx
	mov	ecx, [rdi+aes_roundkeys_ofs+8]
	mov	edx, [rdi+aes_roundkeys_ofs+12]
	mov	r8d, [rdi+rax+aes_roundkeys_ofs]
	movbe	[rdi+aes_roundkeys_ofs+8], ecx
	movbe	[rdi+aes_roundkeys_ofs+12], edx
	movbe	[rdi+rax+aes_roundkeys_ofs], r8d
	mov	ecx, [rdi+rax+aes_roundkeys_ofs+4]
	mov	edx, [rdi+rax+aes_roundkeys_ofs+8]
	mov	r8d, [rdi+rax+aes_roundkeys_ofs+12]
	movbe	[rdi+rax+aes_roundkeys_ofs+4], ecx
	movbe	[rdi+rax+aes_roundkeys_ofs+8], edx
	movbe	[rdi+rax+aes_roundkeys_ofs+12], r8d
else
	bswap	ecx
	bswap	edx
	mov	[rdi+aes_roundkeys_ofs], ecx
	mov	[rdi+aes_roundkeys_ofs+4], edx
	mov	ecx, [rdi+aes_roundkeys_ofs+8]
	mov	edx, [rdi+aes_roundkeys_ofs+12]
	mov	r8d, [rdi+rax+aes_roundkeys_ofs]
	bswap	ecx
	bswap	edx
	bswap	r8d
	mov	[rdi+aes_roundkeys_ofs+8], ecx
	mov	[rdi+aes_roundkeys_ofs+12], edx
	mov	[rdi+rax+aes_roundkeys_ofs], r8d
	mov	ecx, [rdi+rax+aes_roundkeys_ofs+4]
	mov	edx, [rdi+rax+aes_roundkeys_ofs+8]
	mov	r8d, [rdi+rax+aes_roundkeys_ofs+12]
	bswap	ecx
	bswap	edx
	bswap	r8d
	mov	[rdi+rax+aes_roundkeys_ofs+4], ecx
	mov	[rdi+rax+aes_roundkeys_ofs+8], edx
	mov	[rdi+rax+aes_roundkeys_ofs+12], r8d
end if
	epilog

end if

if used aes$init_decrypt | defined include_everything
	; three arguments: rdi == aes object, rsi == ptr to key, edx == length of same (16, 24, or 32)
	; no actual bounds checking on key length validity is done, up to the caller

	; NOTE: unrolling these certainly causes a fair bit of bloat, but there are no conditional branches in here
falign
aes$init_decrypt:
	prolog	aes$init_decrypt
	; force align rdi to 16
	add	rdi, 0xf
	and	rdi, not 0xf
	call	aes$init_common
	mov	eax, [rdi+aes_loopidx_ofs]
	jmp	qword [rax+.dispatch]
dalign
.dispatch:
	dq	.aes128, .aes192, .aes256, .aesni128, .aesni192, .aesni256

macro inverseinner i*, j* {
	mov	eax, [rdi+i*4+aes_roundkeys_ofs]
	mov	ecx, eax
	mov	edx, eax
	mov	r8d, eax
	and	eax, 0xff000000
	and	ecx, 0xff0000
	and	edx, 0xff00
	and	r8d, 0xff
	shr	eax, 24
	shr	ecx, 16
	shr	edx, 8
	movzx	r9d, byte [rax+aes$Se]		; 3
	movzx	r10d, byte [rcx+aes$Se]		; 2
	movzx	r11d, byte [rdx+aes$Se]		; 1
	movzx	eax, byte [r8+aes$Se]		; 0
	mov	esi, dword [r9*8+aes$Td + (3 mod 4) + 1]
	xor	esi, dword [r10*8+aes$Td + (4 mod 4) + 1]
	xor	esi, dword [r11*8+aes$Td + (5 mod 4) + 1]
	xor	esi, dword [rax*8+aes$Td + (6 mod 4) + 1]
	; esi now has the i side, do the j side next
	mov	eax, [rdi+j*4+aes_roundkeys_ofs]
	mov	ecx, eax
	mov	edx, eax
	mov	r8d, eax
	and	eax, 0xff000000
	and	ecx, 0xff0000
	and	edx, 0xff00
	and	r8d, 0xff
	shr	eax, 24
	shr	ecx, 16
	shr	edx, 8
	movzx	r9d, byte [rax+aes$Se]		; 3
	movzx	r10d, byte [rcx+aes$Se]		; 2
	movzx	r11d, byte [rdx+aes$Se]		; 1
	movzx	eax, byte [r8+aes$Se]		; 0
	mov	ecx, dword [r9*8+aes$Td + (3 mod 4) + 1]
	xor	ecx, dword [r10*8+aes$Td + (4 mod 4) + 1]
	xor	ecx, dword [r11*8+aes$Td + (5 mod 4) + 1]
	xor	ecx, dword [rax*8+aes$Td + (6 mod 4) + 1]
	; now ecx has the j side, put them back
	mov	[rdi+j*4+aes_roundkeys_ofs], esi
	mov	[rdi+i*4+aes_roundkeys_ofs], ecx
}

macro inverseouter i* {
	mov	eax, [rdi+i*4+aes_roundkeys_ofs]
	mov	ecx, eax
	mov	edx, eax
	mov	r8d, eax
	and	eax, 0xff000000
	and	ecx, 0xff0000
	and	edx, 0xff00
	and	r8d, 0xff
	shr	eax, 24
	shr	ecx, 16
	shr	edx, 8
	movzx	r9d, byte [rax+aes$Se]		; 3
	movzx	r10d, byte [rcx+aes$Se]		; 2
	movzx	r11d, byte [rdx+aes$Se]		; 1
	movzx	eax, byte [r8+aes$Se]		; 0
	mov	ecx, dword [r9*8+aes$Td + (3 mod 4) + 1]
	xor	ecx, dword [r10*8+aes$Td + (4 mod 4) + 1]
	xor	ecx, dword [r11*8+aes$Td + (5 mod 4) + 1]
	xor	ecx, dword [rax*8+aes$Td + (6 mod 4) + 1]
	mov	[rdi+i*4+aes_roundkeys_ofs], ecx
}

macro doswap l* {
if use_movbe
	mov	eax, [rdi+aes_roundkeys_ofs]
	mov	ecx, [rdi+aes_roundkeys_ofs+4]
	mov	edx, [rdi+l*4+aes_roundkeys_ofs]
	movbe	[rdi+l*4+aes_roundkeys_ofs], eax
	movbe	[rdi+l*4+aes_roundkeys_ofs+4], ecx
	movbe	[rdi+aes_roundkeys_ofs], edx
	mov	r8d, [rdi+l*4+aes_roundkeys_ofs+4]
	mov	eax, [rdi+aes_roundkeys_ofs+8]
	mov	ecx, [rdi+aes_roundkeys_ofs+12]
	movbe	[rdi+aes_roundkeys_ofs+4], r8d
	movbe	[rdi+l*4+aes_roundkeys_ofs+8], eax
	movbe	[rdi+l*4+aes_roundkeys_ofs+12], ecx
	mov	edx, [rdi+l*4+aes_roundkeys_ofs+8]
	mov	r8d, [rdi+l*4+aes_roundkeys_ofs+12]
	movbe	[rdi+aes_roundkeys_ofs+8], edx
	movbe	[rdi+aes_roundkeys_ofs+12], r8d
else
	mov	eax, [rdi+aes_roundkeys_ofs]
	mov	ecx, [rdi+aes_roundkeys_ofs+4]
	bswap	eax
	bswap	ecx
	mov	edx, [rdi+l*4+aes_roundkeys_ofs]
	mov	r8d, [rdi+l*4+aes_roundkeys_ofs+4]
	bswap	edx
	bswap	r8d
	mov	[rdi+l*4+aes_roundkeys_ofs], eax
	mov	[rdi+l*4+aes_roundkeys_ofs+4], ecx
	mov	eax, [rdi+aes_roundkeys_ofs+8]
	mov	ecx, [rdi+aes_roundkeys_ofs+12]
	bswap	eax
	bswap	ecx
	mov	[rdi+aes_roundkeys_ofs], edx
	mov	[rdi+aes_roundkeys_ofs+4], r8d
	mov	edx, [rdi+l*4+aes_roundkeys_ofs+8]
	mov	r8d, [rdi+l*4+aes_roundkeys_ofs+12]
	bswap	edx
	bswap	r8d
	mov	[rdi+l*4+aes_roundkeys_ofs+8], eax
	mov	[rdi+l*4+aes_roundkeys_ofs+12], ecx
	mov	[rdi+aes_roundkeys_ofs+8], edx
	mov	[rdi+aes_roundkeys_ofs+12], r8d
end if
}

calign
.aes128:
	inverseinner 4, 36
	inverseinner 5, 37
	inverseinner 6, 38
	inverseinner 7, 39
	
	inverseinner 8, 32
	inverseinner 9, 33
	inverseinner 10, 34
	inverseinner 11, 35

	inverseinner 12, 28
	inverseinner 13, 29
	inverseinner 14, 30
	inverseinner 15, 31

	inverseinner 16, 24
	inverseinner 17, 25
	inverseinner 18, 26
	inverseinner 19, 27

	inverseouter 20
	inverseouter 21
	inverseouter 22
	inverseouter 23

	doswap 40

	epilog
calign
.aes192:
	inverseinner 4, 44
	inverseinner 5, 45
	inverseinner 6, 46
	inverseinner 7, 47
	
	inverseinner 8, 40
	inverseinner 9, 41
	inverseinner 10, 42
	inverseinner 11, 43

	inverseinner 12, 36
	inverseinner 13, 37
	inverseinner 14, 38
	inverseinner 15, 39

	inverseinner 16, 32
	inverseinner 17, 33
	inverseinner 18, 34
	inverseinner 19, 35

	inverseinner 20, 28
	inverseinner 21, 29
	inverseinner 22, 30
	inverseinner 23, 31

	inverseouter 24
	inverseouter 25
	inverseouter 26
	inverseouter 27

	doswap 48

	epilog

calign
.aes256:
	inverseinner 4, 52
	inverseinner 5, 53
	inverseinner 6, 54
	inverseinner 7, 55
	
	inverseinner 8, 48
	inverseinner 9, 49
	inverseinner 10, 50
	inverseinner 11, 51
	
	inverseinner 12, 44
	inverseinner 13, 45
	inverseinner 14, 46
	inverseinner 15, 47
	
	inverseinner 16, 40
	inverseinner 17, 41
	inverseinner 18, 42
	inverseinner 19, 43

	inverseinner 20, 36
	inverseinner 21, 37
	inverseinner 22, 38
	inverseinner 23, 39

	inverseinner 24, 32
	inverseinner 25, 33
	inverseinner 26, 34
	inverseinner 27, 35

	inverseouter 28
	inverseouter 29
	inverseouter 30
	inverseouter 31

	doswap 56
	
	epilog

macro aesni_inverseinner i*, j* {
	aesimc	xmm0, [rdi+i*4+aes_roundkeys_ofs]
	aesimc	xmm1, [rdi+j*4+aes_roundkeys_ofs]
	movdqu	[rdi+i*4+aes_roundkeys_ofs], xmm1
	movdqu	[rdi+j*4+aes_roundkeys_ofs], xmm0
}

macro aesni_inversemiddle i* {
	aesimc	xmm0, [rdi+i*4+aes_roundkeys_ofs]
	movdqu	[rdi+i*4+aes_roundkeys_ofs], xmm0
}

calign
.aesni128:
	; inversemix required, but considerably simpler than the above methods
	; swap the first and last key
	movdqu	xmm0, [rdi+aes_roundkeys_ofs]
	movdqu	xmm1, [rdi+aes_roundkeys_ofs+160]
	movdqu	[rdi+aes_roundkeys_ofs+160], xmm0
	movdqu	[rdi+aes_roundkeys_ofs], xmm1
	aesni_inverseinner 4, 36
	aesni_inverseinner 8, 32
	aesni_inverseinner 12, 28
	aesni_inverseinner 16, 24
	aesni_inversemiddle 20
	epilog

calign
.aesni192:
	; swap the first and last key
	movdqu	xmm0, [rdi+aes_roundkeys_ofs]
	movdqu	xmm1, [rdi+aes_roundkeys_ofs+192]
	movdqu	[rdi+aes_roundkeys_ofs+192], xmm0
	movdqu	[rdi+aes_roundkeys_ofs], xmm1
	aesni_inverseinner 4, 44
	aesni_inverseinner 8, 40
	aesni_inverseinner 12, 36
	aesni_inverseinner 16, 32
	aesni_inverseinner 20, 28
	aesni_inversemiddle 24
	epilog

calign
.aesni256:
	; swap the first and last key
	movdqu	xmm0, [rdi+aes_roundkeys_ofs]
	movdqu	xmm1, [rdi+aes_roundkeys_ofs+224]
	movdqu	[rdi+aes_roundkeys_ofs+224], xmm0
	movdqu	[rdi+aes_roundkeys_ofs], xmm1
	aesni_inverseinner 4, 52
	aesni_inverseinner 8, 48
	aesni_inverseinner 12, 44
	aesni_inverseinner 16, 40
	aesni_inverseinner 20, 36
	aesni_inverseinner 24, 32
	aesni_inversemiddle 28
	epilog

end if

if used aes$encrypt | defined include_everything
	; two arguments: rdi == aes object, rsi == ptr to block to encrypt in place
falign
aes$encrypt:
	prolog	aes$encrypt
	; force align rdi to 16
	add	rdi, 0xf
	and	rdi, not 0xf
	cmp	dword [has_AESNI], 1
	je	.aesni
	push	r12 r13 r14 r15
	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	xor	eax, eax
	xor	r12d, r12d
	mov	rdx, aes$Te
	mov	ecx, [cpu_L1_size]
	mov	r11d, [rsi+12]
	; preload the Te table into the L1 cache per the exhaustive commentary on cache timing
	; though per my notes atop, my use cases for this library don't seem to be vulnerable
calign
.timingcountermeasure:
	and	eax, dword [rdx+r12]
	add	r12d, ecx
	cmp	r12d, 2048
	jb	.timingcountermeasure
	and	rax, qword [rdx+2040]

	xor	r8d, [rdi+aes_roundkeys_ofs]
	xor	r9d, [rdi+aes_roundkeys_ofs+4]
	xor	r10d, [rdi+aes_roundkeys_ofs+8]
	xor	r11d, [rdi+aes_roundkeys_ofs+12]
	mov	r12d, [rdi+aes_roundkeys_ofs+16]
	mov	r13d, [rdi+aes_roundkeys_ofs+20]
	mov	r14d, [rdi+aes_roundkeys_ofs+24]
	mov	r15d, [rdi+aes_roundkeys_ofs+28]

macro quarter_round_fe t*, tb*, d*, c*, b*, a* {
	movzx	eax, tb
	shr	t, 8
	xor	a, [aes$Te+rax*8+ ((6-3) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	b, [aes$Te+rax*8+ ((6-2) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	c, [aes$Te+rax*8+ ((6-1) mod 4) + 1]
	xor	d, [aes$Te+t*8+ ((6-0) mod 4) + 1]
}

macro quarter_round_e t*, tb*, a*, b*, c*, d* {
	movzx	eax, tb
	shr	t, 8
	xor	a, [aes$Te+rax*8+ ((3+3) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	b, [aes$Te+rax*8+ ((2+3) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	c, [aes$Te+rax*8+ ((1+3) mod 4) + 1]
	xor	d, [aes$Te+t*8+ ((0+3) mod 4) + 1]
}

macro quarter_round_le t*, tb*, a*, b*, c*, d* {
	movzx	eax, tb
	shr	t, 8
	movzx	ecx, byte [aes$Te+rax*8+1]
	movzx	eax, tb
	shr	t, 8
	movzx	edx, byte [aes$Te+rax*8+1]
	movzx	eax, tb
	shr	t, 8
	mov	byte [rsi+a], cl
	mov	byte [rsi+b], dl
	movzx	ecx, byte [aes$Te+rax*8+1]
	movzx	edx, byte [aes$Te+t*8+1]
	mov	byte [rsi+c], cl
	mov	byte [rsi+d], dl
}

macro aesenc_round r* {
	mov	r8d, [rdi+r*4+aes_roundkeys_ofs]
	mov	r9d, [rdi+r*4+aes_roundkeys_ofs+4]
	mov	r10d, [rdi+r*4+aes_roundkeys_ofs+8]
	mov	r11d, [rdi+r*4+aes_roundkeys_ofs+12]
	
	quarter_round_e r15d, r15b, r8d, r9d, r10d, r11d
	quarter_round_e r14d, r14b, r11d, r8d, r9d, r10d
	quarter_round_e r13d, r13b, r10d, r11d, r8d, r9d
	quarter_round_e r12d, r12b, r9d, r10d, r11d, r8d

	mov	r12d, [rdi+r*4+aes_roundkeys_ofs+16]
	mov	r13d, [rdi+r*4+aes_roundkeys_ofs+20]
	mov	r14d, [rdi+r*4+aes_roundkeys_ofs+24]
	mov	r15d, [rdi+r*4+aes_roundkeys_ofs+28]

	quarter_round_e r11d, r11b, r12d, r13d, r14d, r15d
	quarter_round_e r10d, r10b, r15d, r12d, r13d, r14d
	quarter_round_e r9d, r9b, r14d, r15d, r12d, r13d
	quarter_round_e r8d, r8b, r13d, r14d, r15d, r12d
}

macro aesenc_xor_roundkeys r* {
	; we have to xor [rsi] with round keys (16 bytes only)
	mov	eax, [rdi+r*4+aes_roundkeys_ofs]
	mov	ecx, [rdi+r*4+aes_roundkeys_ofs+4]
	mov	edx, [rdi+r*4+aes_roundkeys_ofs+8]
	mov	r8d, [rdi+r*4+aes_roundkeys_ofs+12]
	xor	[rsi], eax
	xor	[rsi+4], ecx
	xor	[rsi+8], edx
	xor	[rsi+12], r8d
}

	quarter_round_fe r11d, r11b, r12d, r13d, r14d, r15d
	quarter_round_fe r10d, r10b, r15d, r12d, r13d, r14d
	quarter_round_fe r9d, r9b, r14d, r15d, r12d, r13d
	quarter_round_fe r8d, r8b, r13d, r14d, r15d, r12d
calign
.aesni:	; jumps here if AESNI to skip all the non AESNI goodies
	mov	eax, [rdi+aes_loopidx_ofs]
	jmp	qword [rax+.dispatch]
dalign
.dispatch:
	dq	.aes128, .aes192, .aes256, .aesni128, .aesni192, .aesni256

calign
.aes128:
	; 4 unrolls
	aesenc_round 8
	aesenc_round 16
	aesenc_round 24
	aesenc_round 32
	
	quarter_round_le r14d, r14b, 15, 2, 5, 8
	quarter_round_le r13d, r13b, 11, 14, 1, 4
	quarter_round_le r12d, r12b, 7, 10, 13, 0
	quarter_round_le r15d, r15b, 3, 6, 9, 12

	aesenc_xor_roundkeys 40

	pop	r15 r14 r13 r12
	epilog
calign
.aes192:
	; 5 unrolls
	aesenc_round 8
	aesenc_round 16
	aesenc_round 24
	aesenc_round 32
	aesenc_round 40

	quarter_round_le r14d, r14b,  15, 2, 5, 8
	quarter_round_le r13d, r13b, 11, 14, 1, 4
	quarter_round_le r12d, r12b, 7, 10, 13, 0
	quarter_round_le r15d, r15b, 3, 6, 9, 12
	
	aesenc_xor_roundkeys 48

	pop	r15 r14 r13 r12
	epilog
calign
.aes256:
	; 6 unrolls
	aesenc_round 8
	aesenc_round 16
	aesenc_round 24
	aesenc_round 32
	aesenc_round 40
	aesenc_round 48

	quarter_round_le r14d, r14b, 15, 2, 5, 8
	quarter_round_le r13d, r13b, 11, 14, 1, 4
	quarter_round_le r12d, r12b, 7, 10, 13, 0
	quarter_round_le r15d, r15b, 3, 6, 9, 12
	
	aesenc_xor_roundkeys 56

	pop	r15 r14 r13 r12
	epilog

macro aesni_enc i* {
	aesenc	xmm0, [rdi+i*16+aes_roundkeys_ofs]
}

macro aesni_enclast i* {
	aesenclast xmm0, [rdi+i*16+aes_roundkeys_ofs]
}

calign
.aesni128:
	movdqu	xmm0, [rsi]	; load up our block
	pxor	xmm0, [rdi+aes_roundkeys_ofs]
	repeat 9
		aesni_enc %
	end repeat
	aesni_enclast 10
	movdqu	[rsi], xmm0	; store the goods
	epilog

calign
.aesni192:
	movdqu	xmm0, [rsi]	; load up our block
	pxor	xmm0, [rdi+aes_roundkeys_ofs]
	repeat 11
		aesni_enc %
	end repeat
	aesni_enclast 12
	movdqu	[rsi], xmm0	; store the goods
	epilog

calign
.aesni256:
	movdqu	xmm0, [rsi]	; load up our block
	pxor	xmm0, [rdi+aes_roundkeys_ofs]
	repeat 13
		aesni_enc %
	end repeat
	aesni_enclast 14
	movdqu	[rsi], xmm0	; store the goods
	epilog

end if

if used aes$decrypt | defined include_everything
	; two arguments: rdi == aes object, rsi == ptr to block to decrypt in place
falign
aes$decrypt:
	prolog	aes$decrypt
	; force align rdi to 16
	add	rdi, 0xf
	and	rdi, not 0xf
	cmp	dword [has_AESNI], 1
	je	.aesni
	push	r12 r13 r14 r15

	mov	r8d, [rsi]
	mov	r9d, [rsi+4]
	mov	r10d, [rsi+8]
	xor	eax, eax
	xor	r12d, r12d
	mov	rdx, aes$Td
	mov	ecx, [cpu_L1_size]
	mov	r11d, [rsi+12]
	; preload the Td table into the L1 cache per the exhaustive commentary on cache timing
	; though per my notes atop, my use cases for this library don't seem to be vulnerable
calign
.timingcountermeasure:
	and	eax, dword [rdx+r12]
	add	r12d, ecx
	cmp	r12d, 2048
	jb	.timingcountermeasure
	and	rax, qword [rdx+2040]

	xor	r8d, [rdi+aes_roundkeys_ofs]
	xor	r9d, [rdi+aes_roundkeys_ofs+4]
	xor	r10d, [rdi+aes_roundkeys_ofs+8]
	xor	r11d, [rdi+aes_roundkeys_ofs+12]
	mov	r12d, [rdi+aes_roundkeys_ofs+16]
	mov	r13d, [rdi+aes_roundkeys_ofs+20]
	mov	r14d, [rdi+aes_roundkeys_ofs+24]
	mov	r15d, [rdi+aes_roundkeys_ofs+28]

macro quarter_round_fd t*, tb*, d*, c*, b*, a* {
	movzx	eax, tb
	shr	t, 8
	xor	a, [aes$Td+rax*8+ ((6-3) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	b, [aes$Td+rax*8+ ((6-2) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	c, [aes$Td+rax*8+ ((6-1) mod 4) + 1]
	xor	d, [aes$Td+t*8+ ((6-0) mod 4) + 1]
}

macro quarter_round_d t*, tb*, a*, b*, c*, d* {
	movzx	eax, tb
	shr	t, 8
	xor	a, [aes$Td+rax*8+ ((3+3) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	b, [aes$Td+rax*8+ ((2+3) mod 4) + 1]
	movzx	eax, tb
	shr	t, 8
	xor	c, [aes$Td+rax*8+ ((1+3) mod 4) + 1]
	xor	d, [aes$Td+t*8+ ((0+3) mod 4) + 1]
}

macro quarter_round_ld t*, tb*, a*, b*, c*, d* {
	movzx	eax, tb
	shr	t, 8
	movzx	ecx, byte [aes$Td+rax*8]
	movzx	eax, tb
	shr	t, 8
	movzx	edx, byte [aes$Td+rax*8]
	movzx	eax, tb
	shr	t, 8
	mov	byte [rsi+a], cl
	mov	byte [rsi+b], dl
	movzx	ecx, byte [aes$Td+rax*8]
	movzx	edx, byte [aes$Td+t*8]
	mov	byte [rsi+c], cl
	mov	byte [rsi+d], dl
}

macro aesdec_round r* {
	mov	r8d, [rdi+r*4+aes_roundkeys_ofs]
	mov	r9d, [rdi+r*4+aes_roundkeys_ofs+4]
	mov	r10d, [rdi+r*4+aes_roundkeys_ofs+8]
	mov	r11d, [rdi+r*4+aes_roundkeys_ofs+12]

	quarter_round_d r15d, r15b, r10d, r9d, r8d, r11d
	quarter_round_d r14d, r14b, r9d, r8d, r11d, r10d
	quarter_round_d r13d, r13b, r8d, r11d, r10d, r9d
	quarter_round_d r12d, r12b, r11d, r10d, r9d, r8d

	mov	r12d, [rdi+r*4+aes_roundkeys_ofs+16]
	mov	r13d, [rdi+r*4+aes_roundkeys_ofs+20]
	mov	r14d, [rdi+r*4+aes_roundkeys_ofs+24]
	mov	r15d, [rdi+r*4+aes_roundkeys_ofs+28]

	quarter_round_d r11d, r11b, r14d, r13d, r12d, r15d
	quarter_round_d r10d, r10b, r13d, r12d, r15d, r14d
	quarter_round_d r9d, r9b, r12d, r15d, r14d, r13d
	quarter_round_d r8d, r8b, r15d, r14d, r13d, r12d
}

macro aesdec_xor_roundkeys r* {
	; we have to xor [rsi] with round keys (16 bytes only)
	mov	eax, [rdi+r*4+aes_roundkeys_ofs]
	mov	ecx, [rdi+r*4+aes_roundkeys_ofs+4]
	mov	edx, [rdi+r*4+aes_roundkeys_ofs+8]
	mov	r8d, [rdi+r*4+aes_roundkeys_ofs+12]
	xor	[rsi], eax
	xor	[rsi+4], ecx
	xor	[rsi+8], edx
	xor	[rsi+12], r8d
}

	quarter_round_fd r11d, r11b, r14d, r13d, r12d, r15d
	quarter_round_fd r10d, r10b, r13d, r12d, r15d, r14d
	quarter_round_fd r9d, r9b, r12d, r15d, r14d, r13d
	quarter_round_fd r8d, r8b, r15d, r14d, r13d, r12d
calign
.aesni: ; jumps here and skips all the unnecessary nonAESNI goods if has_AESNI
	mov	eax, [rdi+aes_loopidx_ofs]
	jmp	qword [rax+.dispatch]
dalign
.dispatch:
	dq	.aes128, .aes192, .aes256, .aesni128, .aesni192, .aesni256

calign
.aes128:
	; 4 unrolls
	aesdec_round 8
	aesdec_round 16
	aesdec_round 24
	aesdec_round 32
	
	quarter_round_ld r14d, r14b, 7, 2, 13, 8
	quarter_round_ld r13d, r13b, 3, 14, 9, 4
	quarter_round_ld r12d, r12b, 15, 10, 5, 0
	quarter_round_ld r15d, r15b, 11, 6, 1, 12
	
	aesdec_xor_roundkeys 40

	pop	r15 r14 r13 r12
	epilog
calign
.aes192:
	; 5 unrolls
	aesdec_round 8
	aesdec_round 16
	aesdec_round 24
	aesdec_round 32
	aesdec_round 40

	quarter_round_ld r14d, r14b, 7, 2, 13, 8
	quarter_round_ld r13d, r13b, 3, 14, 9, 4
	quarter_round_ld r12d, r12b, 15, 10, 5, 0
	quarter_round_ld r15d, r15b, 11, 6, 1, 12
	
	aesdec_xor_roundkeys 48

	pop	r15 r14 r13 r12
	epilog
calign
.aes256:
	; 6 unrolls
	aesdec_round 8
	aesdec_round 16
	aesdec_round 24
	aesdec_round 32
	aesdec_round 40
	aesdec_round 48

	quarter_round_ld r14d, r14b, 7, 2, 13, 8
	quarter_round_ld r13d, r13b, 3, 14, 9, 4
	quarter_round_ld r12d, r12b, 15, 10, 5, 0
	quarter_round_ld r15d, r15b, 11, 6, 1, 12
	
	aesdec_xor_roundkeys 56

	pop	r15 r14 r13 r12
	epilog

macro aesni_dec i* {
	aesdec	xmm0, [rdi+i*16+aes_roundkeys_ofs]
}

macro aesni_declast i* {
	aesdeclast xmm0, [rdi+i*16+aes_roundkeys_ofs]
}

calign
.aesni128:
	movdqu	xmm0, [rsi]	; load up our block
	pxor	xmm0, [rdi+aes_roundkeys_ofs]
	repeat 9
		aesni_dec %
	end repeat
	aesni_declast 10
	movdqu	[rsi], xmm0	; store the goods
	epilog

calign
.aesni192:
	movdqu	xmm0, [rsi]	; load up our block
	pxor	xmm0, [rdi+aes_roundkeys_ofs]
	repeat 11
		aesni_dec %
	end repeat
	aesni_declast 12
	movdqu	[rsi], xmm0	; store the goods
	epilog

calign
.aesni256:
	movdqu	xmm0, [rsi]	; load up our block
	pxor	xmm0, [rdi+aes_roundkeys_ofs]
	repeat 13
		aesni_dec %
	end repeat
	aesni_declast 14
	movdqu	[rsi], xmm0	; store the goods
	epilog

end if
