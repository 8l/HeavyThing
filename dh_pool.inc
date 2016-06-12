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
	; dh_pool.inc: Static Diffie-Hellman parameters
	;
	; The dh_bits setting determines the bit size of the safe prime p.
	;
	; Depending on which bitsize is selected, determines which static
	; pool to load up. dh$pool_p and dh$pool_g are arrays of dq pointers
	; to p and g, of dh$pool_p_size count. This way, they can be randomly
	; chosen for both TLS/SSH group exchanges.
	;
	; If you want to generate your own, see utils/make_dh_static.asm that will
	; generate a single-use format, and basically what is contained herein.
	;
	; NOTE: 1024 BITS IS TOO SMALL FOR THEE.
	;
	; Anyone who is familiar with safe primes and their partner Sophie Germain primes
	; will appreciate how much CPU effort went into the making of these pool files,
	; particularly the bigger ones, haha. While the ones I have include here are not
	; proven primes, both the Safe Prime and the Sophie Germain counterpart underwent
	; ~200 extra Miller-Rabin rounds to verify them. This effectively makes the error
	; probability so ridiculously small thatit is more than sufficient for DHE purposes
	; (IMO). If you are interested in even lower error probabilities, see
	; bigint$verifyprime and adjust the iteration count accordingly. (bigint$dh_params
	; makes calls to bigint$verifyprime after it finds ones that already pass within the
	; configured millerrabinerrorrate). Someday when I am bored I will run these through
	; provable tests as well.
	; Also a note here on the extra 200 Miller-Rabin tests: of course I am being silly
	; by doing this many. HAC says specifically that all I am really doing is increasing
	; the running time required in the final stage, haha, still, silly seems like it
	; can't hurt for static DH parameters. More so considering that I am not bothering
	; with running proof tests on the results. HAC also says "Since the error probability
	; of probable primes can be efficiently brought down to acceptably low levels (see
	; Note 4.49 but note the dependence on t), there appears to be no reason for
	; mandating the use of provable primes over probable primes."
	; Well, t=~200 or so is "acceptably low level" to me, hahah.
	;

include 'dh_groups.inc'

if dh_bits = 2048
	include 'dh_pool_2k.inc'
else if dh_bits = 3072
	include 'dh_pool_3k.inc'
else if dh_bits = 4096
	include 'dh_pool_4k.inc'
else if dh_bits = 6144
	include 'dh_pool_6k.inc'
else if dh_bits = 8192
	include 'dh_pool_8k.inc'
else if dh_bits = 16384
	include 'dh_pool_16k.inc'
else
	display 'invalid dh_bits setting, valid values are 2048,3072,4096,6144,8192,16384.',10
	err
end if
