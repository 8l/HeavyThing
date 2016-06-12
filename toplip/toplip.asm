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
	; toplip.asm: Command line file encryption/decryption utility that includes
	;   plausible deniability, PNG/JPG embedding, very strong anti-brute-forcing,
	;   very strong encryption.
	;
	; Full commentary below.
	;
	; usage: ./toplip [-b] [-d] [-r] [-m mediafile] [[-nomix|-drbg][-1][-c COUNT][-i ITER ]-alt inputfile] [-nomix|-drbg][-1][-c COUNT][-i ITER ]inputfile
	; -b == input/output in base64 (see below notes)
	; -d == decrypt the inputfile
	; -r == generate (and display of course) one time 48 byte each pass phrases as base64
	; -m mediafile == for encrypting only, merge the output into the specified mediafile.
	;      Valid media types: PNG, JPG (plain JFIF or EXIF).
	;      (Note that decrypting will auto-detect and attempt to extract if the inputfile for 
	;      decryption is given a media file).
	; -1 == for each input file (-alt or main), this option disables the use of cascaded
	;      AES256, and instead uses a single AES256 context (two for the XTS-AES stage).
	; -c COUNT == for each input file (-alt or main), this option overrides the default count
	;      of one (1) passphrase. Specifying a higher count here will ask for this many actual
	;      passphrases, and generate this number of separate key material and crypto contexts
	;      that are then used over-top of each other.
	; -i ITER == for each input file (-alt or main), specify an alternate iteration count
	;      for scrypt's internal use of PBKDF2-SHA512 (default is 1). For the initial 8192
	;      bytes of key material, and before one-way AES key grinding of same, we use scrypt
	;      and this option overrides how many iterations of PBKDF2-SHA512 it will perform
	;      for each passphrase. (NOTE: this can _dramatically_ increase the calc times).
	;      Hex values or decimal values permitted (e.g. 10, 0xfff, etc).
	; -drbg == for each input file, by default the 8192 bytes of key material is xor'd with
	;      TLSv1.2 PRF(SHA256) of the supplied passphrase(s). This option will mix the key
	;      material with HMAC_DRBG(SHA256) instead.
	; -nomix == for each input file (see -drbg), this option specifies no additional mixing
	;      of the scrypt generated 8192 byte key material.
	; -alt inputfile == generate one or more "Plausible Deniability" file (encrypting only)
	;      This will ask for another set of passphrases, which MUST NOT be the same.
	;      Without this option, three alternate contents are randomly generated such that it is
	;      impossible to tell by examining the encrypted output whether there is or is not
	;      anything other than pure random. See the -noalt option for what happens without
	;      this option. This option can be specified up to 3 times (for a max of 4 files).
	; -noalt == Do not generate additional random data. By default, extra random data is
	;      inserted into the encrypted output such that forensic analysis (with a valid set
	;      of passphrases) on a given encrypted output does not cover all of the ciphertext
	;      present. See further commentary below about why the default setting is a good thing.
	;      Specifying this option means that no extra random data is inserted into the output
	;      (and this might be useful if you do not need plausible deniability, or you are
	;      dealing with very large files).
	; if -b is specified for encrypt, base64 of the encrypted goods is output to stdout
	; if -b is specified for decrypt, it is assumed the input is base64, and plaintext is output to stdout
	;
	; NOTE: for base64 and media merging, all crypto input/output must be _BUFFERED IN MEMORY_.
	; NOTE 2: for plausible-deniability automatic extras, they will be IN MEMORY also, so for very large
	;      inputs, make sure you have enough VM.
	;
	; passphrase acquisition is done via stdin with stderr prompts if -r not specified
	;
	;
	; The reason this code exists is because there is a distinct lack of command-line crypto
	; that has the following features (top-level overview, keep reading for a more technical explanation):
	;    1) Plausible deniability: The ability to embed multiple payloads with different
	;       passphrase materials inside the same crypto block in a way that makes it impossible
	;       to conclusively identify the number of payloads that exist (if any). While this
	;       of course does not cover actual "Rubber-hose cryptanalysis", what it does provide
	;       are ways to plausibly open a crypted bundle with controlled exposure risk, and no
	;       way outside the rubber-hose method for an attacker to know positively whether MORE
	;       payloads exist or not.
	;    2) Multiple passphrase protection: The ability to, at encryption time, specify the number
	;       and complexity (iterations, mixing) of passphrases for a given payload. Used properly, this
	;       dramatically increases the difficulty level for password-based brute force recovery.
	;    3) No easily identified output markers or alignment: No "file header", and no fixed
	;       alignment for output means that it is impossible to determine by quick examination
	;       whether a file with otherwise-random data was produced by this code or not.
	;    4) The ability to embed and extract crypted materials in common image types (PNG/JPG):
	;       Unless you are working on crypto, it is unlikely that you have a reason to have a
	;       slew of files that look like random data in your posession. Placing important or
	;       otherwise private encrypted materials inside images means that a casual observer will
	;       not discover there is any extraneous data inside the image to begin with (and the same
	;       images can be opened/viewed without revealing they are carrying payloads).
	;    5) Simplified protection against brute force recovery: OpenSSL's enc/dec command line
	;       certainly works, but as has been documented repeatedly over the years, its key
	;       derivation function appears to still use MD5, and it still appears that we can't set
	;       even the iteration count it uses. We employ scrypt-SHA512 for the base key derivation
	;       and depending on command-line options, mix in either TLSv1.2 PRF or HMAC-DRBG with it,
	;       and allow command-line options to specify the PBKDF2 iteration count (that scrypt
	;       itself uses). In addition to this, we use the resultant 8192 bytes of key material
	;       as one-way sets of AES256 keys, and then use AES256 as a CSPRNG to further grind
	;       on the 8192 bytes of key material. Combined with the option to specify an arbitrary
	;       number of multiple passphrases per encrypted input file, this effectively renders
	;       password-based brute force recovery a very difficult exercise.
	;
	; Cryptographic design motivations:
	; 1) Passphrase-based key derivation
	;    Computationally expensive key derivation, combined with optional cascading of multiple keys
	;    was the primary objective. This was specifically to render high-speed passphrase brute forcing
	;    difficult, and in a user-specified way (with command line options that obviously need to be
	;    remembered along with passphrases themselves).
	; 
	;    Thanks to cryptocurrency proliferation, there are now a great many hash accelerators. Things
	;    like hashcat.net (hats off to that) and others mean that "simple" or straightforward hash based
	;    KDF don't provide the same level of protection for passphrases. By modifying scrypt to make use
	;    of HMAC-SHA512 in its initial and final stages of PBKDF2, and further by allowing arbitrary
	;    iterations counts for same, we can effectively render "purist" hash brute forcers ineffective.
	;    Further, that we obviously do not store any part of the "computed hash" (key material) in the
	;    output, means that all brute force attempts will require a minimum number of calculations,
	;    much in the same way that traditional disk encryption uses. By combining the output from
	;    scrypt-SHA512 with other PRFs and performing one-way AES256 key "grinding", the task for
	;    brute forcing is considerably more expensive than any single PBKDF method.
	;
	; 2) Plausible deniability payload discovery
	;    The ability to optionally embed multiple payloads inside the same contiguous output without
	;    disclosing the existence of same, each with their own separate passphrases/key materials.
	;
	; 3) Payload confidentiality
	;    Making use of XTS-AES in combination with our cascaded AES256, as well as cascaded XTS-AES
	;    itself.
	;
	; Technical design commentary:
	; 1) Underlying crypto methods
	;    No "new" or "homebrew" crypto has been used here. AES256, HMAC-SHA512, scrypt (and thus
	;    PBKDF2), TLSv1.2 PRF(SHA256), HMAC-DRBG(SHA256), and XTS-AES (via htxts) have been put together
	;    in carefully considered ways to achieve the aforementioned design goals.
	;
	;    As explained briefly above, each passphrase supplied is passed to scrypt-sha512 to derive 8192
	;    bytes of key material. Command line options allow for specifying a >1 PBKDF2 iteration count
	;    that the underlying scrypt function uses. Note that the SALT used for scrypt (and other mixing
	;    functions) is 32 bytes of PRNG output.
	;
	;    Depending on command line options, this 8192 bytes is then further manipulated (listed per opt):
	;      -nomix: Nothing further is done.
	;      -drbg: HMAC_DRBG(SHA256) is used, seeded with SALT || SHA512(passphrase), to generate an 
	;             additional 8192 bytes of key material, which is then xor'd with the scrypt output.
	;      default: TLSv1.2 PRF(SHA256) is used, secret = passphase, label = 'key derivation', seed =
	;               SALT to generate an additional 8192 bytes of key material, which is then xor'd with
	;               the scrypt output.
	;
	;    Note that our use of scrypt, TLSv1.2 PRF, and HMAC_DRBG for key derivation are not NIST/FIPS
	;    approved methods of key derivation.
	;
	;    Once the above has derived 8192 bytes of key material, that is passed to the "htcrypt" set of
	;    functions, which is an encapsulation of 256 separate AES256 encryption and decryption contexts.
	;    As explained in the htcrypt.inc commentary, htcrypt's init then takes the first 64 bytes of
	;    the scrypt-generated key material, and uses it as its "main sequencer." It then initializes
	;    256 AES256 encryption contexts using 32 bytes each of the original 8192 bytes (32x256 == 8192).
	;    Then, using the last 64 bytes of the original 8192 bytes of key material as a "temporary
	;    sequencer", it encrypts the full 8192 bytes of key material 64 times, using the temporary
	;    sequencer bytes as indexes to the AES256 encryption contexts initialized before. It performs
	;    this "reencrypting the 8192 bytes of key material 64 times" a full 1024 times. This is
	;    effectively using AES256 as a CSPRNG to further arrive at a computationally difficult final
	;    set of 8192 bytes key material.
	;
	;    Once the final 8192 bytes of key material is arrived at, htcrypt then initializes all 256
	;    separate AES256 encryption and decryption contexts using 32 bytes each in succession. Unless
	;    the -1 option is specified, for later-done encrypt operations, each call to htcrypt$encrypt 
	;    actually results in 64 separate AES256 block encryptions, and the contexts used are determined 
	;    by the initial "main sequencer" noted earlier in forward order. For decrypt operations, the 
	;    "main sequencer" bytes are used in reverse for the underlying AES256 decrypt calls. If the -1
	;    option is set, only one AES256 context is used (at the end of the 8192 bytes of generated
	;    key material), and thus does not use cascaded AES256 like the default.
	;
	;    For the 128 bytes of HEADER_OR_IV described below, htcrypt encrypt/decrypt is then used in
	;    a CBC manner. The 16 byte IV is randomly generated, and then for each set of htcrypt
	;    contexts (one per passphrase set), the HEADER = HEADER xor IV, htcrypt$encrypt HEADER, 
	;    IV = IV xor HEADER, htcrypt$encrypt IV. (see below for more detail)
	;
	;    For the actual payload encryption, we make use of the "htxts" set of functions, which is
	;    identical to AES-XTS except for the use of htcrypt$encrypt and htcrypt$decrypt instead of
	;    a single AES256 encrypt/decrypt. The initial XTS 16 byte tweak value is the unencrypted
	;    first 16 byte IV (randomly generated). The first block of htxts plaintext is prepended with
	;    64 bytes of additional random IV.
	;
	;    For integrity verification, an HMAC-SHA512 is appended to the output, along with a partial
	;    randomly sized garbage block (to prevent all outputs from being 16-byte aligned).
	;
	; 2) Effective Security
	;    Reiterated:
	;    No "new" or "homebrew" crypto has been used here. AES256, HMAC-SHA512, scrypt (and thus
	;    PBKDF2), TLSv1.2 PRF(SHA256), HMAC-DRBG(SHA256), and XTS-AES (via htxts) have been put together
	;    in carefully considered ways to achieve the aforementioned design goals.
	;
	;    The point of cascading AES256 was not necessarily to increase the security of AES256 in and
	;    of itself, but to mandate the use and generation of a full 8192 bytes of key material. At best
	;    this dramatically increases its security, and at worst it falls back to a single-key AES256.
	;    If -1 is specified, thereby disabling cascaded AES256, then all of the encrypt/decrypt ops
	;    are "by the book" and the key material used for the single (and double for XTS) AES256 is
	;    taken from the end of the 8192 bytes of key material, still enforcing the use of 8192 bytes.
	;    If -1 is not specified (the default), then the effective security at the block level for the
	;    HEADER_OR_IV portion is somewhere above a single 32 byte AES256 key, and for the XTS portion
	;    somewhere above two 32 byte keys, and for our requirements this is more than sufficient.
	;    Noting here that there is ongoing debate about what the actual effective security gains are
	;    from performing cascaded AES256, but for the purposes herein, regardless of how that debate
	;    turns out, the design goals are satisfied.
	;
	;    At the time of this writing:
	;    Since related key attacks do not apply to this design, at the worst our HEADER_OR_IV (see below)
	;    security sits at 2**254, and if cascaded AES256 is enabled possibly much higher still. For the
	;    XTS payload encryption, since it uses two full sets of AES256 keys, and at worst we are at a
	;    "non-key-halved" full security of XTS-AES. If indeed cascaded AES256 lends to a security
	;    increase, it could further be argued that the use of the 64 bytes of sequencing material
	;    also contribute to the overall security. Either way, our baseline effective security is more
	;    than sufficient for the design goals herein.
	;
	;    The command line options for constructing key material complexity provide for a much higher than
	;    "typical" level of passphrase-based security, and at the end of the day, the effective security
	;    is most likely tied to the passphrase(s) as it should be. (Noting of course you could provide
	;    extremely high entropy passphrases and shift it the other way.)
	;
	; 3) Encryption output format
	;    Each output starts with a 32 byte SALT, followed by eight 16 byte blocks, each of which can be
	;    used as an IV or a HEADER block. These eight blocks are randomly ordered and selected at encrypt
	;    time, and a HEADER consists of the start and end offsets in the overall crypto stream. Which 2
	;    blocks get used by a given stream is chosen at random. If plausible deniability is enabled (and
	;    thus more than one encryption stream exists), each one chooses its own 2 random blocks. For
	;    unused blocks, they are simply PRNG initialized.
	;
	;    The order of input files is randomized before encryption begins (which may include "bogus"
	;    files, and/or alternates).
	;
	;    Following the aforementioned 32+128 bytes, up to four separate htxts encrypted payloads follow.
	;    Each plaintext payload is prepended with 64 bytes of PRNG, appended with a block sized
	;    padding, followed by an HMAC_SHA512 of the plaintext, followed by a random length (1..15) of
	;    garbage data.
	;
	;    Note that the 64 byte PRNG "preamble" does not increase security in any way, because we are not
	;    making use of block chaining (XTS-AES method is used). We do however include it in the HMAC
	;    calculation, as well as use the trailing 4 bits as our padding indicator.
	;
	;    Thus:
	;          [0..31] == SALT
	;          [32..47] == HEADER_OR_IV[0]
	;          [48..63] == HEADER_OR_IV[1]
	;          [64..79] == HEADER_OR_IV[2]
	;          [80..95] == HEADER_OR_IV[3]
	;          [96..111] == HEADER_OR_IV[4]
	;          [112..127] == HEADER_OR_IV[5]
	;          [128..143] == HEADER_OR_IV[6]
	;          [144..159] == HEADER_OR_IV[7]
	;          [160...] == crypted materials and PRNG mix (one or more)
	;          crypted material HTXTS(
	;            [0..63] == PRNG output
	;            [64..X] == plaintext
	;            [X..block-size-padded] == PRNG
	;            HMAC-SHA512(plaintext)
	;            garbage (random length 1..15)
	;
	;    HEADER and IV indexes are randomly selected (the list of 8 is scrambled initially)
	;
	;    All of the HEADER_OR_IV entries are initialized with PRNG output, and then for each input file
	;    specified (depending on -alt, -noalt, etc), an IV and HEADER block is selected.
	;
	;    If -alt is specified once or more (thus plausible deniability, aka multiple sets of valid keys/files),
	;    for each file specified an additional HEADER and IV is chosen. The list of input files is also 
	;    randomized. Four minus the number of input files "bogus" files are added and are PRNG-only output.
	;
	;    If -alt is not specified, and -noalt is also not specified (thus, one set of keys and one file),
	;    then three additional PRNG "bogus" files are added to the list and is PRNG-only output.
	;
	;    If -noalt is specified, then the a single header/IV is chosen, but the actual encrypted contents
	;    begin at offset 160 and no extra random data (other than the garbage/padding above) is added.
	;
	; 4) Decryption discovery/HEADER validity checking pseudocode
	;    For x in 0..7
	;      For y in 0..7
	;        if y <> x
	;          copy HEADER_OR_IV[x] to tempbuf[0]
	;          copy HEADER_OR_IV[y] to tempbuf[1]
	;          foreach key in reverse-order keys (keys == passphrase-derived htcrypt contexts)
	;            key.decrypt(tempbuf[0])
	;            xor tempbuf[0] with tempbuf[1]
	;            key.decrypt(tempbuf[1])
	;            xor tempbuf[1] with tempbuf[0]
	;          if (both qwords of tempbuf[1] are within bounds of filesize, and low qword < high qword)
	;            initial XTS tweak = tempbuf[0]
	;            start_ofs = low qword of tempbuf[1]
	;            end_ofs = high qword of tempbuf[1]
	;            goto success
	;          end if
	;        end if
	;    if we made it through the loop and arrived here, fail.
	;    success:
	;    previous_key = null
	;    foreach key in forward-order keys (keys == passphrase-derived htcrypt contexts)
	;      key.tweak = initial XTS tweak (from above discovery loop result)
	;      if previous_key <> null
	;        previous_key.encrypt(key.tweak)
	;      end if
	;      previous_key = key
	;
	; 5) Hacking and brute force recovery notes
	;   5.1) Password/passphrase based
	;     Key derivation is intentionally expensive, and with command line options to increase its
	;     complexity manifold. At a minimum, for each set of derived key material, the discovery process
	;     outlined in section #4 above would need to be completed in order to validate a given set
	;     of passphrase inputs. (Of course, you could skip the discovery process and attempt the
	;     XTS-AES sections instead, but then you would be forced to guess the location and extents of
	;     the actual payload, versus the HEADER/IV discovery process in section #4 which would yield
	;     those values anyway and is simpler compared to the XTS-AES process itself.)
	;
	;     The defaults contained herein, like many other key derivation settings, are a compromise
	;     between acceptable user-experience delays and the associated computational difficulty of
	;     brute forcing. At these levels on a local development machine, approximately 1.7 attempts per
	;     second per CPU core are possible.
	;
	;     For non-default settings, especially where multiple passphrases and high iteration counts
	;     are specified, things quickly become intractable (at least on consumer-grade hardware). By
	;     increasing the iteration count to 100,000 on the same local development machine the time
	;     per attempt goes up to 23 seconds per CPU core per passphrase.
	;
	;   5.2) Encryption and XTS description
	;     The SALT is only used for key material generation, and is not used at all for any subsequent
	;     encryption operations. Inside htcrypt.inc, if you enable htcrypt_debug_keymaterial, it will
	;     output the sequence and 256 AES256 keys that it uses to stderr.
	;
	;     Per the discovery method outlined in #4 above, the IV and HEADER are "CBC-style" encrypted,
	;     and the PRNG-generated plaintext IV is used as the initial XTS tweak block for actual payload
	;     recovery. Further to this, 64 bytes of random data is prepended to the first XTS block's
	;     plaintext (though as mentioned above, these 64 bytes do not affect security).
	;
	;     What this effectively means is that the XTS enc/decrypt operations are linked to the CBC-style
	;     IV and HEADER portion due to the use of the decrypted IV as the initial XTS tweak value.
	;
	;     At the time of encryption, the plaintext IV (which is then used as the initial XTS tweak) is
	;     PRNG output. The "CBC-style" means that the IV + HEADER are encrypted in the following way
	;     (per key in forward order):
	;         xor HEADER with IV (which is initial random plaintext IV, or last ciphertext IV)
	;         encrypt HEADER (set last ciphertext to result)
	;         xor IV with HEADER (which is last ciphertext)
	;         encrypt IV (set last ciphertext to result)
	;     then if there are more keys in use, the IV is still the "last ciphertext", per normal CBC-mode
	;     operation, despite reiterating over the same two blocks. (See section #4 for more details.)
	;
	;     For an attacker who has nothing but output from this code to work with, and is attempting to
	;     extract plaintext payload(s), there is no way to discern which of the 8 initial 16 byte blocks
	;     are IV or HEADER, so the same discovery process outlined in #4 would have to apply to any
	;     attempts on the HEADER_OR_IV blocks themselves.
	;
	;     In order to recover any plaintext payload(s), all sets of key material (and their respective
	;     AES256 contexts along with their sequencing), the decrypted IV, and the decrypted file offsets
	;     (start/end) are required.
	;
	;     If -1 was specified for a given inputfile, then the "htxts" operations here do not use
	;     cascaded AES256, and instead do "normal" single AES256 encryption. The tweak encryption key
	;     and the data encryption key in this mode are chosen from the end of the final 8192 bytes of
	;     key material. If -1 was not specified, thus cascaded AES256 is enabled, then the "htxts"
	;     methods used here are still done per the XTS-AES standard, but instead of using a single
	;     AES256, we use our cascaded AES256 htcrypt operations described above, and the tweak key
	;     is the first unused (in the main sequence) AES256 context, thus providing at most 65 full
	;     AES256 contexts for a normal htxts operation. "At most" being that the htcrypt sequencing
	;     may actually contain duplicate indexes.
	;
	;     Note that if multiple passphrases (and thus key material) were specified for a given inputfile,
	;     that even if -1 is specified, these do end up in a cascaded manner for both the HEADER_OR_IV
	;     and the XTS portion as outlined above.
	;
	;     Unlike traditional disk-based XTS-AES, we use the initial 16 byte plaintext (PRNG-generated)
	;     IV for the initial tweak value. This has the pleasant side effect that two plaintexts encrypted
	;     with the same set of key materials will not result in identical outputs.
	;
	;     htxts encrypt does (per block, which is 2048 bytes each):
	;       AES256 encrypt tweak with htcrypt.aeskeys[tweak key index] (not cascaded)
	;       for i in 0..127
	;         xor subblock[i] with tweak
	;         htcrypt.encrypt(subblock[i])
	;         xor subblock[i] with tweak
	;         LSFRshift(tweak)
	;     so to encrypt a block, the above is run in forward order for each set of keys, modifying the
	;     tweak (per key, each key has its own unique tweak) in-place through all blocks.
	;
	;   5.3) scrypt key derivation implementation and mixing strategies
	;     The HeavyThing scrypt implementation is a reference one, with N=1024, r=1, p=1 except for the
	;     fact that instead of using SHA256 as scrypt-proper does, we use SHA512 to initialize the state,
	;     and then for the final output stage, again we use SHA512. Note that the PBKDF2 iteration counts
	;     that scrypt uses for its init and final output stages we allow to override the default of 1.
	;
	;     The reason that mixing strategies of the final scrypt key material are employed is twofold:
	;     First, that there may be some issue with the scrypt output itself, and secondly that it forces
	;     any attacker to implement multiple key generation techniques as we have done here.
	;
	;   5.4) PRNG implementation
	;     The underlying HeavyThing library uses a modified version of Agner Fog's SFMT and Mother-of-all
	;     generators. He specifically states that they are safe to use _provided_ that only the combined
	;     output is accessible to an attacker, and that a complete subsequence of the output (in our case
	;     1408 bytes) is never revealed. Care is taken to satisfy these requirements.
	;
	;   5.5) HMAC-SHA512 integrity verification
	;     The primary purpose for appending HMAC-SHA512 is to verify the integrity of the encrypted
	;     payload to ensure that no tampering or other bit errors occur. Since the payload encryption is
	;     done with XTS-AES, single bit errors do not corrupt the entirety that follows, and as such may
	;     not necessarily be self-evident without employing integrity verification.
	;

include '../ht_defaults.inc'
include '../ht.inc'

passphrase_default_count = 1
passphrase_default_iter = 1



globals
{
	do_enc		dd	1
	do_b64		dd	0
	do_pwd		dd	0	; bool as to whether we generate one-offs for passphrases
	do_cascaded	dd	1	; bool as to whether we use cascaded AES256 in htcrypt or not, default true.
	pcount		dd	passphrase_default_count	; how many passphrases we'll get
	piter		dd	passphrase_default_iter		; how many PBKDF2-SHA512 iterations we do for scrypt
	pmix		dd	2	; default key material mixer
	noalt		dd	0	; set if -noalt is passed
	next_is_inputfile	dd	0	; bool for argscan using list$foreach
	next_is_mediafile	dd	0	; bool for argscan using list$foreach
	next_is_count	dd	0	; bool for argscan
	next_is_iter	dd	0	; bool for argscan
	outbuf		dq	0	; buffer if we are outputting anything other than straight to stdout
	outmedia	dq	0	; if -m mediafile was specified, this is the source media to merge output with (privmapped)
	termios		dq	0	; heap allocated spot to save our initial termios (so we can +/-ECHO)
	inputfiles dq	0		; list of inputfiles to deal with
	rofs		dq	128
	headerblocks	dq	0	; list of 0..7, shuffled for encryption block selection
	salt		dq	0	; buffer to hold the 32 byte SALT
	headerbuf	dq	0	; buffer to hold the 128 byte HEADER_OR_IV section
	firstkey	dd	1	; flag as to whether we are getting the first key or not
}

	; this is called setup for a syscall_write
falign
output:
	cmp	qword [outmedia], 0
	jne	.output_buffer
	cmp	dword [do_b64], 0
	jne	.output_buffer
	; otherwise, syscall it is
	syscall
	ret
.output_buffer:
	; rsi + rdx is our desired output
	mov	rdi, [outbuf]
	call	buffer$append
	ret

calign
output_flush:
	cmp	qword [outmedia], 0
	jne	.tomedia
	cmp	dword [do_b64], 0
	jne	.tobase64
	ret
.tomedia:
	call	outmedia$merge
	ret
.tobase64:
	; convert outbuf to base64 and send to stdout
	call	buffer$new
	mov	r8, [outbuf]
	push	rax
	mov	rdi, rax
	mov	rsi, [r8+buffer_itself_ofs]
	mov	rdx, [r8+buffer_length_ofs]
	xor	ecx, ecx
	call	buffer$append_bintobase64_latin1
	mov	rcx, [rsp]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	rdx, [rcx+buffer_length_ofs]
	syscall
	pop	rdi
	call	buffer$destroy
	ret


inputfile_name_ofs = 0
inputfile_privmapped_ofs = 8
inputfile_buffer_ofs = 16
inputfile_bogus_ofs = 24
inputfile_size_ofs = 32
inputfile_garbage_ofs = 40
inputfile_padlen_ofs = 44
inputfile_start_ofs = 48
inputfile_end_ofs = 56
inputfile_keys_ofs = 64
inputfile_mac_ofs = 72
inputfile_srcptr_ofs = 80
inputfile_totalsize_ofs = 88
inputfile_macbuf_ofs = 96
inputfile_pcount_ofs = 104
inputfile_piter_ofs = 112
inputfile_mix_ofs = 120
inputfile_cascaded_ofs = 128

inputfile_size = 136



	; single argument in rdi: 
falign
public inputfile$new
inputfile$new:
	push	rdi					; save a copy of hte name
	xor	esi, esi
	call	privmapped$new
	test	rax, rax
	jz	.nodeal
	push	rax					; save privmapped
	mov	edi, inputfile_size
	call	heap$alloc_clear
	pop	rdi rsi
	mov	[rax+inputfile_name_ofs], rsi
	mov	[rax+inputfile_privmapped_ofs], rdi
	mov	rcx, [rdi+privmapped_size_ofs]
	mov	[rax+inputfile_size_ofs], rcx
	add	rcx, 0xf
	and	rcx, not 0xf
	sub	rcx, [rax+inputfile_size_ofs]
	mov	[rax+inputfile_padlen_ofs], ecx
	; set pcount and piter to whatever is currently in the global context
	mov	r8d, [pcount]
	mov	r9d, [piter]
	mov	r10d, [pmix]
	mov	r11d, [do_cascaded]
	mov	[rax+inputfile_pcount_ofs], r8d
	mov	[rax+inputfile_piter_ofs], r9d
	mov	[rax+inputfile_mix_ofs], r10d
	mov	[rax+inputfile_cascaded_ofs], r11d
	; reset pcount and piter to their defaults
	mov	[pcount], passphrase_default_count
	mov	[piter], passphrase_default_iter
	mov	[pmix], 2
	mov	[do_cascaded], 1
	;
	push	rax
	mov	edi, 1
	mov	esi, 15
	call	rng$int
	mov	rcx, rax
	pop	rax
	mov	[rax+inputfile_garbage_ofs], ecx
	add	ecx, [rax+inputfile_padlen_ofs]
	add	ecx, 128
	add	rcx, [rax+inputfile_size_ofs]
	mov	[rax+inputfile_totalsize_ofs], rcx
	ret
calign
.nodeal:
	pop	rdi
	ret


falign
public inputfile$destroy
inputfile$destroy:
	push	rbx
	mov	rbx, rdi
	cmp	dword [rdi+inputfile_bogus_ofs], 0
	jne	.bogus
	mov	rdi, [rdi+inputfile_mac_ofs]
	call	hmac$destroy
	mov	rdi, [rbx+inputfile_macbuf_ofs]
	test	rdi, rdi
	jz	.nomacbuf
	call	heap$free_clear
.nomacbuf:
	mov	rdi, [rbx+inputfile_privmapped_ofs]
	call	privmapped$destroy
	mov	rdi, [rbx+inputfile_buffer_ofs]
	test	rdi, rdi
	jz	.nobuffer
	call	buffer$destroy
.nobuffer:
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, htcrypt$destroy
	call	list$clear
	mov	rdi, [rbx+inputfile_keys_ofs]
	call	heap$free
	lea	rdi, [rbx+inputfile_start_ofs]
	mov	esi, 16
	call	rng$block
	; leave the rest
	pop	rbx
	ret
calign
.bogus:
	; even though our bogus file is already PRNG, scramble it again
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rsi, [rdi+buffer_length_ofs]
	mov	rdi, [rdi+buffer_itself_ofs]
	call	rng$block
	mov	rdi, [rbx+inputfile_buffer_ofs]
	call	buffer$destroy
	; leave the rest
	pop	rbx
	ret


	; single argument in rdi: the size of the other actual input file, which we'll randomly pick our bogus size from
falign
public inputfile$new_bogus
inputfile$new_bogus:
	; so the actual size of a normal encryption is:
	; size rounded up to nearest 16 == padlen
	; + 64 IV
	; + 64 HMAC
	; + RNG(1..15 bytes)
	; so if we get a random value of our input file size
	; between 1 and our input file size, then calc the extra required space:
	mov	rsi, rdi
	mov	edi, 1
	call	rng$int
	mov	rcx, rax
	add	rcx, 0xf
	and	rcx, not 0xf
	; rcx now has our file size rounded up to the nearest blocklen
	add	rcx, 128
	push	rcx
	mov	edi, 1
	mov	esi, 15
	call	rng$int
	pop	rcx
	add	rax, rcx
	; now we have an accurate randomized bogus size
	push	rbx
	mov	rbx, rax
	mov	edi, inputfile_size
	call	heap$alloc_clear
	mov	rsi, rbx
	mov	rbx, rax
	mov	dword [rax+inputfile_bogus_ofs], 1
	mov	[rax+inputfile_size_ofs], rsi
	mov	[rax+inputfile_totalsize_ofs], rsi
	; next we need srcptr, and a random buffer
	call	buffer$new
	mov	[rbx+inputfile_buffer_ofs], rax
	mov	rdi, rax
	mov	rsi, [rbx+inputfile_size_ofs]
	call	buffer$reserve
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rsi, [rbx+inputfile_size_ofs]
	call	buffer$append_nocopy
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rsi, [rbx+inputfile_size_ofs]
	mov	rdi, [rdi+buffer_itself_ofs]
	mov	[rbx+inputfile_srcptr_ofs], rdi
	call	rng$block
	mov	rax, rbx
	pop	rbx
	ret



falign
public inputfile$load
inputfile$load:
	mov	rsi, [rdi+inputfile_privmapped_ofs]
	mov	rdx, [rsi+privmapped_base_ofs]
	mov	[rdi+inputfile_srcptr_ofs], rdx
	; if do_enc == 0 && do_b64 is 1, we need to base64 decode our input
	cmp	dword [do_enc], 0
	jne	.nothingtodo
	cmp	dword [do_b64], 1
	jne	.mediacheck
	; otherwise, base64 decode our goods
	push	rbx
	mov	rbx, rdi
	call	buffer$new
	mov	[rbx+inputfile_buffer_ofs], rax
	mov	rdi, rax
	mov	rsi, [rbx+inputfile_srcptr_ofs]
	mov	rdx, [rbx+inputfile_size_ofs]
	xor	ecx, ecx
	call	buffer$append_base64tobin_latin1
	; that returned us the number of bytes it wrote
	mov	[rbx+inputfile_size_ofs], rax
	; set our new srcptr to the buffer
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	[rbx+inputfile_srcptr_ofs], rsi
	add	rax, 0xf
	and	rax, not 0xf
	sub	rax, [rbx+inputfile_size_ofs]
	mov	[rbx+inputfile_padlen_ofs], eax
	add	eax, [rbx+inputfile_garbage_ofs]
	add	eax, 128
	add	rax, [rbx+inputfile_size_ofs]
	mov	[rbx+inputfile_totalsize_ofs], rax

	; populate the SALT with the first 32 bytes
	mov	rcx, [salt]
	mov	rdi, [rcx+buffer_itself_ofs]
	; rsi is still set to the srcptr
	mov	edx, 32
	mov	qword [rcx+buffer_length_ofs], 32
	lea	r8, [rdi+32]
	mov	[rcx+buffer_endptr_ofs], r8
	call	memcpy

	pop	rbx
.nothingtodo:
	ret
calign
.mediacheck:
	; not base64, so check and see if it is a recognized media type, and if so, see if we can
	; parse out our goods, otherwise leave it alone
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12, rdx		; privmapped_base_ofs
	mov	r13, [rsi+privmapped_size_ofs]
	mov	rax, 0xa1a0a0d474e5089
	cmp	r13, 41
	jb	.media_asis
	; see if it starts with a PNG header
	cmp	[r12], rax
	je	.maybe_png
	cmp	dword [r12], 0xe0ffd8ff
	je	.maybe_jfif
	cmp	dword [r12], 0xe1ffd8ff
	je	.maybe_exif
calign
.media_asis:
	; we still need to load up the salt:
	mov	rcx, [salt]
	mov	rdi, [rcx+buffer_itself_ofs]
	mov	rsi, r12
	mov	edx, 32
	mov	qword [rcx+buffer_length_ofs], 32
	lea	r8, [rdi+32]
	mov	[rcx+buffer_endptr_ofs], r8
	call	memcpy
	pop	r13 r12 rbx
	ret
calign
.maybe_exif:
	cmp	dword [r12+6], 'EXIF'
	je	.exif
	cmp	dword [r12+6], 'Exif'
	jne	.media_asis
.exif:
	; we do basically the same thing as for a normal JFIF
	call	buffer$new
	mov	[rbx+inputfile_buffer_ofs], rax
	; skip the app1
	movzx	eax, word [r12+4]
	xchg	ah, al
	add	eax, 4			; +2 for length, +2 for SOI
	add	r12, rax
	sub	r13, rax
calign
.exif_scan:
	cmp	word [r12], 0xecff
	je	.exif_app12
	; see if this is our app2 or SOS
	cmp	word [r12], 0xe2ff
	je	.jfif_done
	cmp	word [r12], 0xdaff
	je	.jfif_done
.exif_skip:
	; otherwise, skip this one, making sure we don't run past the end
	movzx	eax, word [r12+2]
	xchg	ah, al
	add	eax, 2
	cmp	rax, r13
	ja	.undo_jfif
	add	r12, rax
	sub	r13, rax
	jmp	.exif_scan
calign
.exif_app12:
	; make sure the byte at [r12+11] is 0
	cmp	byte [r12+11], 0
	jne	.exif_skip
	mov	rdi, [rbx+inputfile_buffer_ofs]
	lea	rsi, [r12+12]
	movzx	edx, word [r12+2]
	xchg	dh, dl
	sub	edx, 10
	call	buffer$append
	jmp	.exif_skip

calign
.maybe_jfif:
	cmp	dword [r12+6], 'JFIF'
	jne	.media_asis
	; it is a JFIF, create an input buffer, and scan the image
	call	buffer$new
	mov	[rbx+inputfile_buffer_ofs], rax
	; skip the app0
	movzx	eax, word [r12+4]
	xchg	ah, al
	add	eax, 4			; +2 for length, +2 for SOI
	add	r12, rax
	sub	r13, rax
calign
.jfif_scan:
	cmp	word [r12], 0xecff
	je	.jfif_app12
	; see if this is our SOS
	cmp	word [r12], 0xdaff
	je	.jfif_done
.jfif_skip:
	; otherwise, skip this one, making sure we don't run past the end
	movzx	eax, word [r12+2]
	xchg	ah, al
	add	eax, 2
	cmp	rax, r13
	ja	.undo_jfif
	add	r12, rax
	sub	r13, rax
	jmp	.jfif_scan
dalign
.ducky:
	db	'Ducky',0
dalign
.pictureinfo:
	db	'PictureInfo',0
calign
.jfif_app12:
	; if the identifier (at [r12+4]) == 'Ducky'0 or 'PictureInfo'0, skip
	lea	rdi, [r12+4]
	mov	rsi, .ducky
	mov	edx, 6
	call	memcmp
	test	eax, eax
	jz	.jfif_skip
	lea	rdi, [r12+4]
	mov	rsi, .pictureinfo
	mov	edx, 12
	call	memcmp
	test	eax, eax
	jz	.jfif_skip
	; make sure the byte at [r12+11] is 0
	cmp	byte [r12+11], 0
	jne	.jfif_skip
	mov	rdi, [rbx+inputfile_buffer_ofs]
	lea	rsi, [r12+12]
	movzx	edx, word [r12+2]
	xchg	dh, dl
	sub	edx, 10
	call	buffer$append
	jmp	.jfif_skip
calign
.undo_jfif:
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	qword [rbx+inputfile_buffer_ofs], 0
	call	buffer$destroy
	pop	r13 r12 rbx
	ret
calign
.jfif_done:
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rax, [rdi+buffer_length_ofs]
	mov	[rbx+inputfile_size_ofs], rax
	; set our new srcptr to the buffer
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	[rbx+inputfile_srcptr_ofs], rsi
	add	rax, 0xf
	and	rax, not 0xf
	sub	rax, [rbx+inputfile_size_ofs]
	mov	[rbx+inputfile_padlen_ofs], eax
	add	eax, [rbx+inputfile_garbage_ofs]
	add	eax, 128
	add	rax, [rbx+inputfile_size_ofs]
	mov	[rbx+inputfile_totalsize_ofs], rax

	; populate the SALT with the first 32 bytes
	mov	rcx, [salt]
	mov	rdi, [rcx+buffer_itself_ofs]
	; rsi is still set to the srcptr
	mov	edx, 32
	mov	qword [rcx+buffer_length_ofs], 32
	lea	r8, [rdi+32]
	mov	[rcx+buffer_endptr_ofs], r8
	call	memcpy

	pop	r13 r12 rbx
	ret

calign
.maybe_png:
	cmp	dword [r12+12], 'IHDR'
	jne	.media_asis
	; otherwise, we have a PNG file... create an inputfile buffer to store the goods
	; and then walk forward until we find a private chunk that matches our chunk naming
	; convention
	call	buffer$new
	mov	[rbx+inputfile_buffer_ofs], rax
	add	r12, 8
	sub	r13, 16
	mov	ecx, [r12]		; length of the IHDR chunk
	bswap	ecx
	add	r12, 8
	cmp	rcx, r13
	jae	.png_bad
	cmp	ecx, 13
	jne	.png_bad
	; otherwise, 13+4 bytes for the crc to skip the IHDR
	add	r12, 17
	sub	r13, 17
	; commence scanning for our crypto'd chunk
calign
.png_scan:
	cmp	r13, 12
	jb	.png_bad
	mov	eax, dword [r12]
	bswap	eax
	mov	r10d, eax
	add	eax, 12
	cmp	rax, r13
	ja	.png_bad
	movzx	ecx, byte [r12+4]
	movzx	edx, byte [r12+5]
	movzx	r8d, byte [r12+6]
	movzx	r9d, byte [r12+7]
	cmp	ecx, 'a'
	jb	.png_next
	cmp	ecx, 'z'
	ja	.png_next
	cmp	edx, 'a'
	jb	.png_next
	cmp	edx, 'z'
	ja	.png_next
	cmp	r8d, 'Z'
	ja	.png_next
	cmp	r8d, 'A'
	jb	.png_next
	cmp	r9d, 'a'
	jb	.png_next
	cmp	r9d, 'z'
	ja	.png_next
	; otherwise, we have a private chunk that fits the bill
	; its data is at r12+8, its length is sitting in r10
	mov	rdi, [rbx+inputfile_buffer_ofs]
	lea	rsi, [r12+8]
	mov	edx, r10d
	push	r10
	call	buffer$append
	pop	rax
	mov	[rbx+inputfile_size_ofs], rax
	; set our new srcptr to the buffer
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	rsi, [rdi+buffer_itself_ofs]
	mov	[rbx+inputfile_srcptr_ofs], rsi
	add	rax, 0xf
	and	rax, not 0xf
	sub	rax, [rbx+inputfile_size_ofs]
	mov	[rbx+inputfile_padlen_ofs], eax
	add	eax, [rbx+inputfile_garbage_ofs]
	add	eax, 128
	add	rax, [rbx+inputfile_size_ofs]
	mov	[rbx+inputfile_totalsize_ofs], rax

	; populate the SALT with the first 32 bytes
	mov	rcx, [salt]
	mov	rdi, [rcx+buffer_itself_ofs]
	; rsi is still set to the srcptr
	mov	edx, 32
	mov	qword [rcx+buffer_length_ofs], 32
	lea	r8, [rdi+32]
	mov	[rcx+buffer_endptr_ofs], r8
	call	memcpy

	pop	r13 r12 rbx
	ret
calign
.png_next:
	add	r12, rax
	sub	r13, rax
	jz	.undo_png
	jmp	.png_scan
calign
.undo_png:
	; in the _extremely_ unlikely case that we matched a PNG header, but it was
	; really crypto output (haha), just undo our buffering and let the decode
	; proceed with the input as-is
	mov	rdi, [rbx+inputfile_buffer_ofs]
	mov	qword [rbx+inputfile_buffer_ofs], 0
	call	buffer$destroy
	pop	r13 r12 rbx
	ret
calign
.png_bad:
	mov	rdi, .pngcorrupted
	call	string$to_stderrln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .pngcorrupted, 'PNG image format parse of inputfile failed.'
	


	; single argument in rdi, the inputfile we are hanging the keys on
falign
public inputfile$keygen
inputfile$keygen:
	cmp	dword [rdi+inputfile_bogus_ofs], 0
	jne	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12d, [rdi+inputfile_pcount_ofs]	; how many passphrases we are getting/generating
	mov	r13d, 1					; the current # for display purposes

	; create our keys list
	call	list$new
	mov	[rbx+inputfile_keys_ofs], rax

	; make room for a full block on our stack
	sub	rsp, htxts_blocksize

	cmp	dword [do_pwd], 0
	je	.pwd_acquire
calign
.generateloop:
	cmp	dword [firstkey], 1
	je	.skiplf1
	mov	eax, syscall_write
	mov	edi, 2
	mov	dword [rsp], 10
	mov	rsi, rsp
	mov	edx, 1
	syscall
.skiplf1:
	mov	dword [firstkey], 0

	mov	rdi, [rbx+inputfile_name_ofs]
	call	string$to_stderr

	mov	rdi, .passphrase_preface
	call	string$to_stderr

	; generate our current passphrase # and display that
	mov	edi, r13d
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stderr
	pop	rdi
	call	heap$free

	mov	rdi, .passphrase_postface
	call	string$to_stderr

	; generate 48 bytes of RNG for each and display them
	lea	rdi, [rsp+(htxts_blocksize-96)]
	mov	esi, 96
	call	rng$block
	; encode the first as our passphrase
	lea	rdi, [rsp+(htxts_blocksize-96)]
	mov	esi, 48
	mov	rdx, rsp
	xor	ecx, ecx
	call	base64$encode_latin1
	; base64_linebreaks is set by default for the HeavyThing library
	; which means it added a CRLF to the end, we need to change it to a single LF
	sub	rax, 1
	mov	byte [rsp+rax-1], 10
	; dump that to stderr
	mov	rdx, rax
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, rsp
	push	rdx
	sub	rdx, 1		; skip the LF
	syscall
	pop	rax

	mov	r11, [salt]
	mov	rdx, rsp	; passphrase
	mov	ecx, eax	; length of same
	mov	r8, [r11+buffer_itself_ofs] ; salt
	mov	r9d, 32		; length of same
	mov	r10d, [rbx+inputfile_piter_ofs]
	; save the location of the original passphrase for mixing
	mov	r14, rsp
	mov	r15d, eax
	sub	rsp, 8192
	mov	rdi, rsp
	mov	esi, 8192
	call	scrypt_iter
	; deal with mixing
	mov	rdi, rsp
	mov	eax, [rbx+inputfile_mix_ofs]
	shl	eax, 3
	mov	rsi, [rax+.mixdispatch]
	call	rsi
	mov	rdi, rsp
	call	htcrypt$new_keymaterial
	; if cascaded AES256 is disabled, set the htcrypt's x var to 255
	mov	ecx, [rax+htcrypt_x_ofs]
	mov	edx, 255
	cmp	dword [rbx+inputfile_cascaded_ofs], 0
	cmove	ecx, edx
	mov	[rax+htcrypt_x_ofs], ecx
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, rax
	call	list$push_back
	; clear our stack key material
	mov	rdi, rsp
	mov	esi, 8192
	call	rng$block
	add	rsp, 8192

	; randomize our block/stackframe (which also discards htxts_blocksize worth of RNG state/sequence)
	mov	rdi, rsp
	mov	esi, htxts_blocksize
	call	rng$block

	; update counters, proceed
	add	r13d, 1
	sub	r12d, 1
	jnz	.generateloop

	add	rsp, htxts_blocksize
	pop	r15 r14 r13 r12 rbx
	ret
cleartext .passphrase_preface, '   Passphrase #'
cleartext .passphrase_postface, ': '
cleartext .badpass, 10,'unable to acquire passphrase'
cleartext .keygen, 'generating keys...'
cleartext .donemsg, 'Done'
dalign
.mixdispatch:
	dq	.nomix, .drbgmix, .tlsprfmix
falign
.nomix:
	ret
falign
.drbgmix:
	; rdi == pointer to 8192 bytes of key material output from scrypt
	; r14 == pointer to original passphrase
	; r15d == length of same

	; we want to seed an HMAC_DRBG(SHA256) with a SHA512 of our passphrase
	; and then generate a _separate_ 8192 bytes of key material with that
	; and then xor mix it in with the scrypt output
	push	r12 r13
	sub	rsp, 8192
	mov	r12, rdi		; save our original scrypt output pointer
	
	; copy the salt to the first 32 bytes of the stack
	mov	rcx, [salt]
	mov	rdi, rsp
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	edx, 32
	call	memcpy

	call	sha512$new
	mov	r13, rax
	mov	rdi, rax
	mov	rsi, r14
	mov	edx, r15d
	call	sha512$update
	mov	rdi, r13
	lea	rsi, [rsp+32]
	mov	edx, 1			; cleanup the sha512 state
	call	sha512$final

	; next up, init an HMAC_DRBG and seed it with the 64 byte sha512 final
	mov	rdi, hmac$init_sha256
	mov	rsi, rsp
	mov	edx, 96
	call	hmac_drbg$new
	mov	r13, rax
	; next up, generate 8192 bytes with that
	mov	rdi, rax
	mov	rsi, rsp
	mov	edx, 8192
	call	hmac_drbg$generate
	; cleanup our drbg
	mov	rdi, r13
	call	hmac_drbg$destroy
	; mix (xor) the results
	mov	rdi, r12
	mov	rsi, rsp
	mov	edx, 8192
	call	memxor
	; scramble our stackframe
	mov	rdi, rsp
	mov	esi, 8192
	call	rng$block
	; done, dusted.
	add	rsp, 8192
	pop	r13 r12
	ret
dalign
.tlsprflabel:
	db	'key derivation'	; 14 bytes
falign
.tlsprfmix:
	; rdi == pointer to 8192 bytes of key material output from scrypt
	; r14 == pointer to original passphrase
	; r15d == length of same

	; we want to mix our scrypt output with the TLSv1.2 PRF(SHA256)
	; secret = user supplied passphrase
	; label = 'key derivation'
	; seed = SALT
	push	r12 r13
	sub	rsp, 80
	; our concatenated data starts with our label for 14 bytes
	mov	rax, qword [.tlsprflabel]
	mov	rcx, qword [.tlsprflabel+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	mov	r12, rdi		; save our original scrypt output pointer

	; copy our SALT to [rsp+14]
	mov	rcx, [salt]
	lea	rdi, [rsp+14]
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	edx, 32
	call	memcpy
	
	; next up, create an HMAC_SHA256 (so we can use the phash function of it, which is TLSv1.2 PRF)
	call	hmac$new_sha256
	mov	r13, rax
	; the hmac key gets set to our user supplied passphrase
	mov	rdi, rax
	mov	rsi, r14
	mov	edx, r15d
	call	hmac$key
	; now we can call phash_xor directly
	mov	rdi, r13
	mov	rsi, r12		; the scrypt original
	mov	edx, 8192
	mov	rcx, rsp
	mov	r8d, 46			; 14 bytes for label, 32 bytes for SALT
	call	hmac$phash_xor
	; cleanup our hmac state
	mov	rdi, r13
	call	hmac$destroy
	; randomize our stack
	mov	rdi, rsp
	mov	esi, 80
	call	rng$block
	; done, dusted.
	add	rsp, 80
	pop	r13 r12
	ret

calign
.badpassphrase:
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, htcrypt$destroy
	call	list$clear
	mov	rdi, rsp
	mov	esi, htxts_blocksize
	call	rng$block
	mov	rdi, .badpass
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
calign
.pwd_acquire:
	; acquire passphrase
	cmp	dword [firstkey], 1
	je	.skiplf2
	mov	eax, syscall_write
	mov	edi, 2
	mov	dword [rsp], 10
	mov	rsi, rsp
	mov	edx, 1
	syscall
.skiplf2:
	mov	dword [firstkey], 0

	mov	rdi, [rbx+inputfile_name_ofs]
	call	string$to_stderr

	mov	rdi, .passphrase_preface
	call	string$to_stderr

	; generate our current passphrase # and display that
	mov	edi, r13d
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, rax
	call	string$to_stderr
	pop	rdi
	call	heap$free

	mov	rdi, .passphrase_postface
	call	string$to_stderr

	mov	eax, syscall_read
	mov	edi, 0
	mov	rsi, rsp
	mov	edx, htxts_blocksize
	syscall
	cmp	rax, 0
	jle	.badpassphrase
	push	rax
	mov	rdi, .keygen
	call	string$to_stderr
	pop	rax

	mov	r11, [salt]
	mov	rdx, rsp	; passphrase
	mov	ecx, eax	; length of same
	mov	r8, [r11+buffer_itself_ofs] ; salt
	mov	r9d, 32		; length of same
	mov	r10d, [rbx+inputfile_piter_ofs]
	; save the location of the original passphrase for mixing
	mov	r14, rsp
	mov	r15d, eax
	sub	rsp, 8192
	mov	rdi, rsp
	mov	esi, 8192
	call	scrypt_iter
	; deal with mixing
	mov	rdi, rsp
	mov	eax, [rbx+inputfile_mix_ofs]
	shl	eax, 3
	mov	rsi, [rax+.mixdispatch]
	call	rsi
	mov	rdi, rsp
	call	htcrypt$new_keymaterial
	; if cascaded AES256 is disabled, set the htcrypt's x var to 255
	mov	ecx, [rax+htcrypt_x_ofs]
	mov	edx, 255
	cmp	dword [rbx+inputfile_cascaded_ofs], 0
	cmove	ecx, edx
	mov	[rax+htcrypt_x_ofs], ecx
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, rax
	call	list$push_back
	; clear our stack key material
	mov	rdi, rsp
	mov	esi, 8192
	call	rng$block
	add	rsp, 8192

	mov	rdi, .donemsg
	call	string$to_stderr

	; randomize our block/stackframe (which also discards htxts_blocksize worth of RNG state/sequence)
	mov	rdi, rsp
	mov	esi, htxts_blocksize
	call	rng$block

	; update our counters/proceed
	add	r13d, 1
	sub	r12d, 1
	jnz	.pwd_acquire

	add	rsp, htxts_blocksize
	pop	r15 r14 r13 r12 rbx
	ret
calign
.nothingtodo:
	ret




	; single argument in rdi: inputfile
falign
public inputfile$extents
inputfile$extents:
	mov	rax, [rofs]
	mov	rcx, [rdi+inputfile_totalsize_ofs]
	mov	[rdi+inputfile_start_ofs], rax
	add	rax, rcx
	mov	[rdi+inputfile_end_ofs], rax
	mov	[rofs], rax
	ret




	; single argument in rdi: inputfile
falign
public inputfile$headeriv
inputfile$headeriv:
	; so, everything has been setup, headerblocks is shuffled, and headerbuf contains
	; the 128 byte RNG that we are ultimately messing with
	cmp	dword [rdi+inputfile_bogus_ofs], 0
	jne	.nothingtodo		; bogus files == we don't touch any HEADER_OR_IV blocks, and leave them as PRNG
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	; get our IV location
	mov	rdi, [headerblocks]
	call	list$pop_front

	mov	rdi, [headerbuf]
	shl	eax, 4			; index * 16 is the offset
	mov	rsi, [rdi+buffer_itself_ofs]
	lea	r12, [rsi+rax]		; pointer offset into the 128 byte HEADER_OR_IV blocks for our IV
	; do the same again for our HEADER spot
	mov	rdi, [headerblocks]
	call	list$pop_front

	mov	rdi, [headerbuf]
	shl	eax, 4
	mov	rsi, [rdi+buffer_itself_ofs]
	lea	r13, [rsi+rax]		; pointer offset into the 128 byte HEADER_OR_IV blocks for our HEADER

	; grab our tweak xor value as the unmolested initial 16 byte PRNG output
	mov	rax, [r12]
	mov	rcx, [r12+8]
	; set our HEADER qwords to our start and end offsets
	mov	r8, [rbx+inputfile_start_ofs]
	mov	r9, [rbx+inputfile_end_ofs]
	; store them in the right spot (r13)
	mov	[r13], r8
	mov	[r13+8], r9

	; for each set of keys, initial tweaks and do our xor + encrypt, which goes (foreach key):
	; (populate and/or encrypt the initial tweak)
	; xor HEADER with IV
	; encrypt HEADER with current key
	; xor IV with resultant HEADER
	; encrypt IV with current key
	; (move to next key or done)

	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	r14, [rdi+_list_first_ofs]
	xor	r15d, r15d
	; note: we do not use list$foreach here because we need to pass multiple args
	; (r12 and r13)
	; store rax/rcx on the stack so we can propagate it per-key
	push	rcx rax
calign
.foreach_key:
	; first up, populate and possibly encrypt this key's initial tweak
	mov	rdi, [r14+_list_valueofs]
	mov	rax, [rsp]
	mov	rcx, [rsp+8]
	mov	[rdi+htcrypt_user_ofs], rax
	mov	[rdi+htcrypt_user_ofs+8], rcx
	; if r15 is set, then there is a previous set of keys, use those to encrypt it
	; such that every htcrypt context gets a different initial tweak
	test	r15, r15
	jz	.foreach_key_skiptweakencrypt
	lea	rsi, [rdi+htcrypt_user_ofs]
	mov	rdi, [r15+_list_valueofs]
	call	htcrypt$encrypt
.foreach_key_skiptweakencrypt:

	; IV is at [r12], HEADER is at [r13]
	; xor the HEADER with the IV
	mov	rax, [r12]
	mov	rcx, [r12+8]
	xor	[r13], rax
	xor	[r13+8], rcx
	; encrypt the header with this key
	mov	rdi, [r14+_list_valueofs]
	mov	rsi, r13
	call	htcrypt$encrypt
	; xor IV with the resultant HEADER
	mov	rax, [r13]
	mov	rcx, [r13+8]
	xor	[r12], rax
	xor	[r12+8], rcx
	; encrypt IV with this key
	mov	rdi, [r14+_list_valueofs]
	mov	rsi, r12
	call	htcrypt$encrypt
	; next, or done
	mov	r15, r14
	mov	r14, [r14+_list_nextofs]
	test	r14, r14
	jnz	.foreach_key
	pop	rax rcx

	; allocate our hmac
	sub	rsp, 32
	call	hmac$new_sha512
	mov	[rbx+inputfile_mac_ofs], rax

	; get our first set of keys out so we can read back the unencrypted initial tweak
	mov	rdi, [rbx+inputfile_keys_ofs]
	xor	esi, esi
	call	list$index
	mov	r11, rax

	; copy our HEADER and our initial tweak and use that as our HMAC key, noting here
	; that the HMAC we are using is only for integrity checking and not for authenticity

	mov	r8, [rbx+inputfile_start_ofs]
	mov	r9, [rbx+inputfile_end_ofs]
	mov	r10, [r11+htcrypt_user_ofs]
	mov	r11, [r11+htcrypt_user_ofs+8]
	mov	[rsp], r8
	mov	[rsp+8], r10
	mov	[rsp+16], r11
	mov	[rsp+24], r9
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	edx, 32
	xor	r10d, r10d
	xor	r11d, r11d
	call	hmac$key
	mov	rdi, rsp
	mov	esi, 32
	call	rng$block
	add	rsp, 32

	; go ahead and compute our HMAC
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, [rbx+inputfile_srcptr_ofs]
	mov	rdx, [rbx+inputfile_size_ofs]
	call	hmac$data

	; done, dusted.
	pop	r15 r14 r13 r12 rbx
	ret
calign
.nothingtodo:
	ret




	; single argument in rdi: our inputfile
falign
public inputfile$encrypt
inputfile$encrypt:
	cmp	dword [rdi+inputfile_bogus_ofs], 0
	jne	.bogus
	push	rbp rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	rbp, [rdi+inputfile_srcptr_ofs]
	mov	r15, [rdi+inputfile_size_ofs]

	sub	rsp, htxts_blocksize

	; first up, do our 64 byte IV at the start, and then a partial htxts block
	mov	rdi, rsp
	mov	esi, 64
	call	rng$block

	; we need to store our padding byte value at [63] so that when decrypt occurs
	; it can reverse-determine the correct output length, but rather than clear
	; the upper bits, we'll just set the lower 4 bits of byte 63

	mov	eax, [rbx+inputfile_padlen_ofs]
	movzx	ecx, byte [rsp+63]
	and	ecx, 0xf0
	or	ecx, eax
	mov	byte [rsp+63], cl

	; add the 64 bytes preamble to the _end_ of the HMAC
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	; allocate and compute our mac final
	mov	edi, 64
	call	heap$alloc
	mov	[rbx+inputfile_macbuf_ofs], rax
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rax
	call	hmac$final

	; now we can fill the remainder of the block with our input
	mov	rcx, htxts_blocksize - 64
	lea	rdi, [rsp+64]
	mov	rsi, rbp
	mov	rdx, r15
	cmp	r15, rcx
	cmova	rdx, rcx
	lea	r14, [rdx+64]	; save the total length of the first block
	cmp	r15, rdx
	je	.encrypt_lastblock
	; otherwise, not the last block, so encrypt this one
	call	memcpy

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output to stdout
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	rdx, r14
	call	output
	; our r15/rbp needs updating by the r14-64 result
	sub	r14, 64
	add	rbp, r14
	sub	r15, r14
	; now we can proceed with the rest of the blocks, we know that r15 is nonzero
calign
.encrypt_loop:
	mov	ecx, htxts_blocksize
	mov	rdi, rsp
	mov	rsi, rbp
	mov	rdx, r15
	cmp	r15, rcx
	cmova	rdx, rcx
	mov	r14, rdx	; save the length of this block
	cmp	r15, rdx
	je	.encrypt_lastblock
	; otherwise, not the last block, so encrypt this one
	call	memcpy

	; encrypt the block with all the keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output to stdout
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	rdx, r14
	call	output
	; update r15/rbp
	add	rbp, r14
	sub	r15, r14
	; we know it is nonzero
	jmp	.encrypt_loop
calign
.encrypt_lastblock:
	; memcpy has not occurred yet, but we can go ahead and let it:
	call	memcpy
	; just in case we are splitting a block, allocate 64 bytes
	mov	edi, 64
	call	heap$alloc
	mov	r15, rax
	; so r14 has the length that we populated
	; several case scenarios:
	; 1) we are sitting neatly on an end of htxts_blocksize
	; 2) we don't have enough room to add our HMAC + garbage
	; 3) we have enough room
	mov	eax, htxts_blocksize
	sub	eax, r14d
	jz	.encrypt_fullblock	; this can only happen if padding length == 0
	; otherwise, we need padding length + 64 + garbage block worth of room left
	; eax is how much space is left in our block
	cmp	eax, [rbx+inputfile_padlen_ofs]
	je	.encrypt_fullblock	; padding length neatly hit the end of a block
	mov	ecx, [rbx+inputfile_padlen_ofs]
	; we need room for paddinglength + 64 + 16
	add	ecx, 80
	cmp	ecx, eax
	ja	.encrypt_splitblock
	; otherwise, there is room left for all our goods, we need to place our hmac
	; at rsp+r14+paddinglength for 64 bytes
	; place our hmac final
	mov	ecx, [rbx+inputfile_padlen_ofs]
	lea	rdi, [rsp+r14]
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, 64
	add	rdi, rcx
	call	memcpy

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; now determine our final write length, which is r14+paddinglength+64+garbagelength
	mov	r8d, [rbx+inputfile_padlen_ofs]
	mov	ecx, [rbx+inputfile_garbage_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp

	mov	rdx, r14
	add	rdx, r8
	add	rdx, 64
	add	rdx, rcx
	call	output

	; done, dusted.
	jmp	.done
calign
.encrypt_fullblock:
	; padding length was zero, _or_ padding lenght neatly put us at the end of a full block

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output the full block to stdout
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, htxts_blocksize
	call	output

	; now our hmac goes at the start of our new block
	mov	rdi, rsp
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, 64
	call	memcpy
	; encrypt this as an entire new block, noting here that we are re-encrypting the remaining
	; contents of the previous encrypted block (which will remain in our garbage padding area)

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output 64 + our garbage length
	mov	ecx, [rbx+inputfile_garbage_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	rdx, 64
	add	rdx, rcx
	call	output
	; we are all done.
	jmp	.done
calign
.encrypt_splitblock:
	; there is not enough room left in the current block to hold 80 more bytes after padding
	sub	eax, [rbx+inputfile_padlen_ofs]
	; we need to add same to r14 so we know how much is used
	add	r14d, [rbx+inputfile_padlen_ofs]
	; we know that eax is nonzero, or fullblock would have been the result
	; so the next step is to put our hmac output in a temporary, and then copy bits and pieces
	cmp	eax, 64
	jb	.encrypt_reallysplit
	; otherwise, there is room for our entire hmac, but _not_ enough room for the garbage afterwards
	lea	rdi, [rsp+r14]
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, 64
	call	memcpy
	; encrypt this full block

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output the full block to stdout
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, htxts_blocksize
	call	output
	; now encrypt the full block once more, noting we are only producing garbage

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output only the garbage length
	mov	edx, [rbx+inputfile_garbage_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	call	output
	; we are all done.
	jmp	.done
calign
.encrypt_reallysplit:
	lea	rdi, [rsp+r14]
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, eax		; how many bytes are actually left
	mov	r15d, 64
	sub	r15d, eax
	lea	rbp, [rsi+rax]
	call	memcpy
	; encrypt and send the full block

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output the full block to stdout
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, htxts_blocksize
	call	output

	; put what is left of our hmac
	mov	rdi, rsp
	mov	rsi, rbp
	mov	edx, r15d
	call	memcpy
	; encrypt this entire block

	; encrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .encrypt_block
	mov	rdx, rsp
	call	list$foreach_arg

	; output the remainder + garbage length
	mov	edx, [rbx+inputfile_garbage_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	add	rdx, r15
	call	output
	; we are all done, fallthrough:
calign
.done:
	; whatever is sitting on the stack is already public
	; so we don't need to worry about randomizing it again
	add	rsp, htxts_blocksize
	pop	r15 r14 r13 r12 rbx rbp
	ret

	; despite being inline here, called as external function from list$foreach_arg
falign
.encrypt_block:
	; rdi == our htcrypt context, rsi == pointer to block we are encrypting
	lea	rdx, [rdi+htcrypt_user_ofs]
	call	htxts$encrypt
	ret


calign
.bogus:
	; all we have to do is output our buffer
	mov	rcx, [rdi+inputfile_buffer_ofs]
	mov	rdx, [rdi+inputfile_totalsize_ofs]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	call	output
	ret






	; single argument in rdi: our inputfile
falign
public inputfile$decrypt
inputfile$decrypt:
	cmp	qword [rdi+inputfile_size_ofs], 290	; our abso-minimum size == salt + header + 130 bytes
	jb	.notenough
	push	rbp rbx r12 r13 r14 r15
	sub	rsp, htxts_blocksize
	mov	rbx, rdi
	mov	rbp, [rdi+inputfile_srcptr_ofs]
	mov	r15, [rdi+inputfile_size_ofs]

	; skip over the SALT 32 bytes:
	add	rbp, 32
	sub	r15, 32

	; our first order of business is doing our discovery/HEADER validity checking
	; read: brute force attempts have to do this bit.
	xor	r12d, r12d			; our IV offset
	xor	r13d, r13d			; our HEADER offset

	mov	rdi, .decrypting
	call	string$to_stderr
calign
.disco_loop:
	cmp	r13d, r12d			; if IV == HEADER, no sense in checking this one
	je	.disco_inner_next
	; copy the 16 bytes at IV
	mov	rax, [rbp+r12]
	mov	rcx, [rbp+r12+8]
	; copy the 16 bytes at HEADER
	mov	rdx, [rbp+r13]
	mov	r8, [rbp+r13+8]
	mov	[rsp], rax
	mov	[rsp+8], rcx
	mov	[rsp+16], rdx
	mov	[rsp+24], r8
	; IV temporary copy is at [rsp]
	; HEADER temporary copy is at [rsp+16]

	; so now, for each set of keys in REVERSE, do our decrypt + xor which goes (foreach key):
	; decrypt IV with current key
	; xor IV with HEADER
	; decrypt HEADER with current key
	; xor HEADER with IV
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .decrypt_iv_header
	mov	rdx, rsp
	call	list$reverse_foreach_arg

	; so at this point, if everything went perfect, our initial tweak is sitting in
	; IV, and our HEADER will contain valid start/end offsets
	mov	rdx, [rsp+16]
	mov	r8, [rsp+24]
	cmp	rdx, r8
	jae	.disco_inner_next		; if the start >= end, no deal
	cmp	rdx, [rbx+inputfile_size_ofs]
	jae	.disco_inner_next		; if the start >= filesize, no deal
	cmp	r8, [rbx+inputfile_size_ofs]
	ja	.disco_inner_next		; if the end > filesize, no deal
	mov	r9, r8
	sub	r9, rdx
	cmp	r9, 130
	jae	.decrypt			; if the end - start is >= 130, looks like we're sweet
	; otherwise, no deal, fallthrough to .disco_inner_next
calign
.disco_inner_next:
	add	r13d, 16
	cmp	r13d, 128
	jb	.disco_loop
	xor	r13d, r13d
	add	r12d, 16
	cmp	r12d, 128
	jb	.disco_loop
	; if we made it to here, no deal

	mov	rdi, .sorry
	call	string$to_stderrln

	; destroy our htcrypt contexts before we die
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, htcrypt$destroy
	call	list$clear
	call	termreset

	mov	eax, syscall_exit
	mov	edi, 1
	syscall

	; despite being declared inline here, called as a function from list$reverse_foreach_arg
	; to decrypt the IV + header
falign
.decrypt_iv_header:
	; rdi == our htcrypt context, rsi == 32 bytes, [0] == IV, [16] == HEADER
	push	r12 r13
	mov	r12, rdi
	mov	r13, rsi
	; decrypt IV with current key
	call	htcrypt$decrypt
	; xor IV with HEADER
	mov	rax, [r13+16]
	mov	rcx, [r13+24]
	xor	[r13], rax
	xor	[r13+8], rcx
	; decrypt HEADER with current key
	mov	rdi, r12
	lea	rsi, [r13+16]
	call	htcrypt$decrypt
	; xor HEADER with IV
	mov	rax, [r13]
	mov	rcx, [r13+8]
	xor	[r13+16], rax
	xor	[r13+24], rcx
	pop	r13 r12
	ret
cleartext .sorry, 'Invalid keys and/or input'
cleartext .decrypting, 10,'Decrypting...'
calign
.decrypt:
	; so our IV is sitting in [rsp] for 16 bytes
	; and our HEADER is sitting in rdx/r8
	mov	[rbx+inputfile_start_ofs], rdx
	mov	[rbx+inputfile_end_ofs], r8

	; we need to populate and initialize all of the tweaks for our keys
	; in FORWARD ORDER (just like the encrypt does)
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	r12, [rdi+_list_first_ofs]
	xor	r13d, r13d
calign
.tweakpopulate:
	mov	rdi, [r12+_list_valueofs]
	mov	rax, [rsp]
	mov	rcx, [rsp+8]
	mov	[rdi+htcrypt_user_ofs], rax
	mov	[rdi+htcrypt_user_ofs+8], rcx
	; if there was a previous one, use it to encrypt this one, otherwise we leave it
	test	r13, r13
	jz	.tweakpopulate_skipencrypt
	lea	rsi, [rdi+htcrypt_user_ofs]
	mov	rdi, [r13+_list_valueofs]
	call	htcrypt$encrypt
.tweakpopulate_skipencrypt:
	mov	r13, r12
	mov	r12, [r12+_list_nextofs]
	test	r12, r12
	jnz	.tweakpopulate
	
	; get our IV back and HEADER back:
	mov	rax, [rsp]
	mov	rcx, [rsp+8]
	mov	rdx, [rsp+16]
	mov	r8, [rsp+24]

	; compute our hmac key, reordering the goods
	mov	[rsp], rdx
	mov	[rsp+8], rax
	mov	[rsp+16], rcx
	mov	[rsp+24], r8

	call	hmac$new_sha512
	mov	[rbx+inputfile_mac_ofs], rax
	mov	rdi, rax
	mov	rsi, rsp
	mov	edx, 32
	call	hmac$key
	mov	rdi, rsp
	mov	esi, 32
	call	rng$block

	; allocate a 64 byte buffer to hold the first block's 64 byte preamble
	mov	edi, 64
	call	heap$alloc
	mov	[rbx+inputfile_macbuf_ofs], rax
	
	; adjust our rbp/r15 markers
	mov	r15, [rbx+inputfile_end_ofs]
	add	rbp, [rbx+inputfile_start_ofs]
	sub	r15, [rbx+inputfile_start_ofs]
	; save our "new" srcptr and overwrite the original
	mov	[rbx+inputfile_srcptr_ofs], rbp
	; save our "new" size and overwrite the original
	mov	[rbx+inputfile_size_ofs], r15
calign
.decrypt_loop:
	; so, r15 == total number of bytes we have to deal with
	; rbp == pointer to source
	; copy up to a full block into rsp, decrypt it, then figure out
	; what we are dealing with
	mov	ecx, htxts_blocksize
	mov	rdi, rsp
	mov	rsi, rbp
	mov	rdx, r15
	cmp	r15, rcx
	cmova	rdx, rcx
	mov	r14d, edx
	call	memcpy

	; decrypt this full block, even if we didn't populate all of it
	; decrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .decrypt_block
	mov	rdx, rsp
	call	list$reverse_foreach_arg

	; now, several possibilities that we have to deal with
	cmp	r14, r15
	je	.decrypt_lastblock
	; if we are not the last block, see if we are the first block
	cmp	rbp, [rbx+inputfile_srcptr_ofs]
	je	.decrypt_first_not_last
	; we are not the first and not the last, make sure we are not a split block
	mov	rcx, r15		; how much total is left including this block
	mov	rax, [rbx+inputfile_size_ofs]
	and	eax, 0xf		; our garbage amount
	sub	rcx, r14		; - this block == how much is left for the _next_
	cmp	eax, ecx		; is all thats left garbage?
	je	.decrypt_lastblock_evenly	; if so, treat this as the last block and be happy
	; see if there is at least garbage length + 64 in the _next_ block
	add	eax, 64
	cmp	rcx, rax
	jb	.decrypt_last_split
	; otherwise, there is at least 64 + garbage length in the next block
	; we are _not_ the first block, and we are _not_ the last block
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	rdx, r14
	call	hmac$data
	; output what we have to stdout
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, r14d
	call	output
	; udpate our pointers and keep going
	add	rbp, r14
	sub	r15, r14
	jmp	.decrypt_loop
calign
.decrypt_lastblock_evenly:
	; all that remains _after_ this block is garbage
	cmp	rbp, [rbx+inputfile_srcptr_ofs]
	je	.decrypt_first_and_last
	; otherwise, last block, but _not_ the first block, and our hmac is _exactly_ at the end
	; of this block
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	edx, htxts_blocksize - 64
	sub	edx, [rbx+inputfile_padlen_ofs]
	call	hmac$data
	; add the 64 byte preamble
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, 64
	call	hmac$data
	; output the goods
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, htxts_blocksize - 64
	sub	edx, [rbx+inputfile_padlen_ofs]
	call	output
	; we can blast our data now with our hmac final
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	call	hmac$final
	mov	rdi, rsp
	lea	rsi, [rsp+(htxts_blocksize - 64)]
	mov	edx, 64
	call	memcmp
	test	eax, eax
	jnz	.decrypt_done_badhmac
	jmp	.done
calign
.decrypt_lastblock:
	cmp	rbp, [rbx+inputfile_srcptr_ofs]
	je	.decrypt_first_and_last
	; otherwise, last block, but _not_ the first block, and we are _not_ a split last block
	; so, determine how much actual data we have, update our mac, then compare against the
	; we already have our padding length sitting in pincount
	mov	rcx, [rbx+inputfile_size_ofs]
	mov	eax, r14d		; how much data we put into this block
	sub	eax, [rbx+inputfile_padlen_ofs]	; less the padding length
	sub	eax, 64			; less our HMAC length
	and	ecx, 0xf
	sub	eax, ecx
	; eax is now our data length
	mov	r8d, [rbx+inputfile_padlen_ofs]
	lea	rbp, [rsp+rax]		; the end of the data
	add	rbp, r8			; + padding == start of HMAC decrypted
	; so now we can update the actual hmac
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	rdx, rax
	mov	r15, rax		; save the length of the data so we can output it
	call	hmac$data
	; add the preamble 64 bytes
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, 64
	call	hmac$data
	; output to stdout the data
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	rdx, r15
	call	output
	; now, we need to hmac_final and compare the result
	sub	rsp, 64
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	call	hmac$final
	mov	rdi, rsp
	mov	rsi, rbp
	mov	edx, 64
	call	memcmp
	add	rsp, 64
	test	eax, eax
	jnz	.decrypt_done_badhmac
	; otherwise, all good
	jmp	.done
calign
.decrypt_first_and_last:
	; extract our padding length
	movzx	ecx, byte [rsp+63]
	and	ecx, 0xf
	mov	[rbx+inputfile_padlen_ofs], ecx
	; verify that our filesize is legit
	mov	r11, [rbx+inputfile_size_ofs]
	mov	r10, r11
	and	r10d, 0xf
	; r10d == garbage amount, ecx == padding amount
	sub	r11, rcx
	sub	r11, r10
	sub	r11, 128
	; so r11 is now our computed length according to garbage + padlen as indicated in [rsp+63]
	; lets recompute the total length and verify that it matches
	mov	r9, r11
	add	r9, 0xf
	and	r9, not 0xf
	add	r9, r10
	add	r9, 128
	; r9 should match our actual size
	cmp	r9, [rbx+inputfile_size_ofs]
	jne	.decrypt_failed
	; update our hmac with the real data
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64]
	mov	edx, r14d		; total length we put into the block
	sub	edx, 128		; less 64 RNG, 64 HMAC
	sub	edx, ecx		; less padding
	; and finally less our garbage amount
	mov	r8d, r14d
	and	r8d, 0xf
	sub	edx, r8d
	; save our length
	mov	r15d, edx
	; get the position of our HMAC
	lea	rbp, [rsi+rdx]
	; add the padding length to that
	add	rbp, rcx
	call	hmac$data
	; append the preamble to the end
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	; output our result to stdout
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [rsp+64]
	mov	edx, r15d
	call	output
	; do our final hmac and compare the result
	sub	rsp, 64
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	call	hmac$final
	mov	rdi, rsp
	mov	rsi, rbp
	mov	edx, 64
	call	memcmp
	add	rsp, 64
	test	eax, eax
	jnz	.decrypt_done_badhmac
	; otherwise, all good
	jmp	.done
calign
.decrypt_first_not_last:
	mov	rcx, r15		; how much total is left including this block
	mov	rax, [rbx+inputfile_size_ofs]
	and	eax, 0xf		; our garbage amount
	sub	rcx, r14		; - this block == how much is left for the _next_
	cmp	eax, ecx		; is all thats left garbage?
	je	.decrypt_first_and_last
	; see if there is at least garbage length + 64 in the _next_ block
	add	eax, 64
	cmp	rcx, rax
	jb	.decrypt_first_and_last_split
	; otherwise, there is at least 64 + garbage length in the next block
	; if there is _exactly_ 64 + garbage length in the next block, then this block contains
	; our padding
	je	.decrypt_first_evenly
	; extract our padding length first up
	movzx	ecx, byte [rsp+63]
	and	ecx, 0xf
	mov	[rbx+inputfile_padlen_ofs], ecx
	; verify that our filesize is legit
	mov	r11, [rbx+inputfile_size_ofs]
	mov	r10, r11
	and	r10d, 0xf
	; r10d == garbage amount, ecx == padding amount
	sub	r11, rcx
	sub	r11, r10
	sub	r11, 128
	; so r11 is now our computed length according to garbage + padlen as indicated in [rsp+63]
	; lets recompute the total length and verify that it matches
	mov	r9, r11
	add	r9, 0xf
	and	r9, not 0xf
	add	r9, r10
	add	r9, 128
	; r9 should match our actual size
	cmp	r9, [rbx+inputfile_size_ofs]
	jne	.decrypt_failed

	; update our hmac with all of the rest of the data
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64]
	mov	edx, htxts_blocksize - 64
	call	hmac$data

	; set our macbuf to the preamble so we can add it at the end
	mov	rdi, [rbx+inputfile_macbuf_ofs]
	mov	rsi, rsp
	mov	edx, 64
	call	memcpy
	; output all of this block to stdout
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [rsp+64]
	mov	edx, htxts_blocksize - 64
	call	output
	; udpate our pointers and keep going
	add	rbp, r14
	sub	r15, r14
	jmp	.decrypt_loop
calign
.decrypt_first_evenly:
	; this block _contains_ our padding, and is the end, and the next block's start is our HMAC
	; extract our padding length first up
	movzx	ecx, byte [rsp+63]
	and	ecx, 0xf
	mov	[rbx+inputfile_padlen_ofs], ecx
	; verify that our filesize is legit
	mov	r11, [rbx+inputfile_size_ofs]
	mov	r10, r11
	and	r10d, 0xf
	; r10d == garbage amount, ecx == padding amount
	sub	r11, rcx
	sub	r11, r10
	sub	r11, 128
	; so r11 is now our computed length according to garbage + padlen as indicated in [rsp+63]
	; lets recompute the total length and verify that it matches
	mov	r9, r11
	add	r9, 0xf
	and	r9, not 0xf
	add	r9, r10
	add	r9, 128
	; r9 should match our actual size
	cmp	r9, [rbx+inputfile_size_ofs]
	jne	.decrypt_failed
	; update our hmac with all of the data sans padding
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64]
	mov	edx, htxts_blocksize - 64
	sub	edx, ecx
	call	hmac$data
	; update our hmac with the preamble
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	edx, 64
	call	hmac$data
	; output that to stdout
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [rsp+64]
	mov	edx, htxts_blocksize - 64
	sub	edx, [rbx+inputfile_padlen_ofs]
	call	output
	; in order to verify the hmac, we first need to decrypt the next block
	add	rbp, r14
	sub	r15, r14
	mov	rdi, rsp
	mov	rsi, rbp
	mov	edx, r15d
	call	memcpy

	; decrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .decrypt_block
	mov	rdx, rsp
	call	list$reverse_foreach_arg

	sub	rsp, 64
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	call	hmac$final
	mov	rdi, rsp
	lea	rsi, [rsp+64]
	mov	edx, 64
	call	memcmp
	add	rsp, 64
	test	eax, eax
	jnz	.decrypt_done_badhmac
	; otherwise, done and dusted
	jmp	.done
calign
.decrypt_first_and_last_notsplit:
	; this block contains all of the hmac, but only some/part/maybenotany of the garbage
	; garbage amount is in edx
	; eax is what is left in the next block
	; ecx is our padding bytecount
	; edx is our garbage count
	; so, ALL data that remains - garbage count - 64 == HMAC start
	; and ALL data that remains - garbage count - 64 - padding count == end of data
	mov	r8d, r15d	; all the data that remains
	sub	r8d, edx	; less garbage count
	sub	r8d, 64		; less HMAC count
	; so our hmac is at rsp+r8
	mov	r9d, r8d
	sub	r9d, ecx
	; our data end is at r9
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64]	; start of data
	push	r8 r9
	mov	edx, r9d
	sub	edx, 64
	mov	[rsp], rdx	; length of our data
	call	hmac$data
	; update the hmac with our preamble
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+16]
	mov	edx, 64
	call	hmac$data
	; output our data
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [rsp+64+16]	; start of data
	mov	rdx, [rsp]
	call	output
	; last but not least, compare hmacs
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+16]
	call	hmac$final
	pop	r9 r8
	mov	rdi, rsp
	lea	rsi, [rsp+r8]
	mov	edx, 64
	call	memcmp
	test	eax, eax
	jnz	.decrypt_done_badhmac
	; otherwise, done
	jmp	.done
calign
.decrypt_first_and_last_split:
	; so this block contains our padding, _and_ part of the hmac
	; extract our padding length first up
	movzx	ecx, byte [rsp+63]
	and	ecx, 0xf
	mov	[rbx+inputfile_padlen_ofs], ecx
	; verify that our filesize is legit
	mov	r11, [rbx+inputfile_size_ofs]
	mov	r10, r11
	and	r10d, 0xf
	; r10d == garbage amount, ecx == padding amount
	sub	r11, rcx
	sub	r11, r10
	sub	r11, 128
	; so r11 is now our computed length according to garbage + padlen as indicated in [rsp+63]
	; lets recompute the total length and verify that it matches
	mov	r9, r11
	add	r9, 0xf
	and	r9, not 0xf
	add	r9, r10
	add	r9, 128
	; r9 should match our actual size
	cmp	r9, [rbx+inputfile_size_ofs]
	jne	.decrypt_failed
	; we need to update our hmac and output the data we have gotten so far
	mov	rax, r15
	sub	rax, r14
	; rax now has what is left in the next block, we know this one was a full one
	mov	rdx, [rbx+inputfile_size_ofs]
	and	edx, 0xf
	; edx == garbage length
	cmp	edx, eax		; if the next block is only garbage
	jae	.decrypt_first_and_last_notsplit	; there may be some garbage in this block too
	; otherwise, the next block contains _some_ of the hmac
	sub	eax, edx		; == how many bytes in the next block remain less the garbage, which is how many of our hmac is there
	mov	r8d, 64
	sub	r8d, eax		; how many bytes of the hmac are in _this_ block
	; so now we can update our running hmac, and output the data
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64]
	mov	edx, htxts_blocksize - 64
	sub	edx, r8d
	sub	edx, ecx
	lea	r9, [rsi+rdx]
	add	r9, rcx			; start of hmac, after data+padding
	push	rax r8 rdx r9
	call	hmac$data
	; update hmac with the preamble
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+32]
	mov	edx, 64
	call	hmac$data
	; rax was # of bytes remaining in next block less the garbge
	; r8 was how many bytes of HMAC are in _this_ block
	; r9 == address of HMAC start in this block
	; rdx == length of the data we updated
	
	; first up, output the data
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [rsp+64+32]
	mov	rdx, [rsp+8]
	call	output
	; now we need a temporary spot to hold our decrypted hmac
	mov	rsi, [rsp]		; address of start of hmac
	mov	rdx, [rsp+16]		; length of hmac in this block
	sub	rsp, 64
	mov	rdi, rsp
	call	memcpy
	; now we need to copy the next block and decrypt it so we can get the rest of the encrypted HMAC
	lea	rdi, [rsp+64+32]
	lea	rsi, [rbp+r14]
	mov	rdx, [rsp+64+24]
	call	memcpy
	; now decrypt that full block at rsp+64+32

	; decrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .decrypt_block
	lea	rdx, [rsp+64+32]
	call	list$reverse_foreach_arg

	; now we have to copy whats left and append it to our hmac
	mov	rax, [rsp+64+16]	; how many bytes we _got_
	lea	rdi, [rsp+rax]
	lea	rsi, [rsp+64+32]
	mov	rdx, [rsp+64+24]
	call	memcpy
	; now we can hmac$final into rsp+64+32 and then compare them both
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64+32]
	call	hmac$final
	mov	rdi, rsp
	lea	rsi, [rsp+64+32]
	mov	edx, 64
	call	memcmp
	add	rsp, 64+32
	test	eax, eax
	jnz	.decrypt_done_badhmac
	; otherwise, we are sweet
	jmp	.done
calign
.decrypt_last_split:
	; so the next block contains < (64 + garbage) bytes, which means this block contains _some_ of the hmac
	; and the next block contains the rest of it
	; we need to update our hmac and output the data we have gotten so far
	mov	ecx, [rbx+inputfile_padlen_ofs]
	mov	rax, r15
	sub	rax, r14
	; rax now has what is left in the next block, we know this one was a full one
	mov	rdx, [rbx+inputfile_size_ofs]
	and	edx, 0xf
	; edx == garbage length
	; the next block contains _some_ of the hmac
	sub	eax, edx		; == how many bytes in the next block remain less the garbage, which is how many of our hmac is there
	mov	r8d, 64
	sub	r8d, eax		; how many bytes of the hmac are in _this_ block
	; so now we can update our running hmac, and output the data
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, rsp
	mov	edx, htxts_blocksize
	sub	edx, r8d
	sub	edx, ecx
	lea	r9, [rsi+rdx]
	add	r9, rcx			; start of hmac, after data+padding
	push	rax r8 rdx r9
	call	hmac$data
	; add our preamble 64 bytes
	mov	rdi, [rbx+inputfile_mac_ofs]
	mov	rsi, [rbx+inputfile_macbuf_ofs]
	mov	edx, 64
	call	hmac$data

	; rax was # of bytes remaining in next block less the garbge
	; r8 was how many bytes of HMAC are in _this_ block
	; r9 == address of HMAC start in this block
	; rdx == length of the data we updated
	
	; first up, output the data
	mov	eax, syscall_write
	mov	edi, 1
	lea	rsi, [rsp+32]
	mov	rdx, [rsp+8]
	call	output
	; now we need a temporary spot to hold our decrypted hmac
	mov	rsi, [rsp]		; address of start of hmac
	mov	rdx, [rsp+16]		; length of hmac in this block
	sub	rsp, 64
	mov	rdi, rsp
	call	memcpy
	; now we need to copy the next block and decrypt it so we can get the rest of the encrypted HMAC
	lea	rdi, [rsp+64+32]
	lea	rsi, [rbp+r14]
	mov	rdx, [rsp+64+24]
	call	memcpy
	; now decrypt that full block at rsp+64+32

	; decrypt the block with all keys/tweaks
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, .decrypt_block
	lea	rdx, [rsp+64+32]
	call	list$reverse_foreach_arg

	; now we have to copy whats left and append it to our hmac
	mov	rax, [rsp+64+16]	; how many bytes we _got_
	lea	rdi, [rsp+rax]
	lea	rsi, [rsp+64+32]
	mov	rdx, [rsp+64+24]
	call	memcpy
	; now we can hmac$final into rsp+64+32 and then compare them both
	mov	rdi, [rbx+inputfile_mac_ofs]
	lea	rsi, [rsp+64+32]
	call	hmac$final
	mov	rdi, rsp
	lea	rsi, [rsp+64+32]
	mov	edx, 64
	call	memcmp
	add	rsp, 64+32
	test	eax, eax
	jnz	.decrypt_done_badhmac
	; otherwise, we are sweet
	; fallthrough to done.
calign
.done:
	; remove any cleartext remaining on the stack:
	mov	rdi, rsp
	mov	esi, htxts_blocksize
	call	rng$block
	; normal/okay return from here will result in cleanup of keys/etc

	add	rsp, htxts_blocksize
	pop	r15 r14 r13 r12 rbx rbp
	ret

	; despite being inline here, called as external function from list$reverse_foreach_arg
falign
.decrypt_block:
	; rdi == our htcrypt context, rsi == pointer to block we are decrypting
	lea	rdx, [rdi+htcrypt_user_ofs]
	call	htxts$decrypt
	ret

calign
.decrypt_done_badhmac:
	; remove any cleartext remaining on the stack (even though the HMAC failed and it is
	; likely garbage anyway)
	mov	rdi, rsp
	mov	esi, htxts_blocksize
	call	rng$block
	; get rid of our keys
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, htcrypt$destroy
	call	list$clear
	lea	rdi, [rbx+inputfile_start_ofs]
	mov	esi, 16
	call	rng$block
	mov	rdi, .donebadhmacmsg
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
calign
.decrypt_failed:
	; remove any cleartext remaining on the stack (even though the HMAC failed and it is
	; likely garbage anyway)
	mov	rdi, rsp
	mov	esi, htxts_blocksize
	call	rng$block
	; get rid of our keys
	mov	rdi, [rbx+inputfile_keys_ofs]
	mov	rsi, htcrypt$destroy
	call	list$clear
	lea	rdi, [rbx+inputfile_start_ofs]
	mov	esi, 16
	call	rng$block
	mov	rdi, .sorry
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall

cleartext .donebadhmacmsg, 'Done, HMAC FAIL'
cleartext .notenoughdata, 10,'insufficient input length'
calign
.notenough:
	mov	rdi, .notenoughdata
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall






falign
argscan:
	cmp	dword [next_is_inputfile], 0
	jne	.do_inputfile
	cmp	dword [next_is_mediafile], 0
	jne	.do_mediafile
	cmp	dword [next_is_count], 0
	jne	.do_count
	cmp	dword [next_is_iter], 0
	jne	.do_iter
	push	rdi
	mov	rsi, .dashd
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashd
	push	rdi
	mov	rsi, .dashb
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashb
	push	rdi
	mov	rsi, .dashr
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashr
	push	rdi
	mov	rsi, .dash1
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dash1
	push	rdi
	mov	rsi, .dashalt
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashalt
	push	rdi
	mov	rsi, .dashm
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashm
	push	rdi
	mov	rsi, .dashnoalt
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashnoalt
	push	rdi
	mov	rsi, .dashc
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashc
	push	rdi
	mov	rsi, .dashi
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_dashi
	push	rdi
	mov	rsi, .dashdrbg
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_drbg
	push	rdi
	mov	rsi, .dashnomix
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.do_nomix
	; otherwise, unrecognized option
	push	rdi
	mov	rdi, .invalidarg
	call	string$to_stderr
	pop	rdi
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
	; not reached
cleartext .invalidarg, 'invalid argument: '
calign
.do_inputfile:
	push	rdi
	mov	dword [next_is_inputfile], 0
	call	inputfile$new
	pop	rdi
	test	rax, rax
	jz	.bad_inputfile
	mov	rdi, [inputfiles]
	mov	rsi, rax
	call	list$push_back
	ret
calign
.do_mediafile:
	push	rdi
	mov	dword [next_is_mediafile], 0
	call	privmapped$new
	pop	rdi
	test	rax, rax
	jz	.bad_mediafile
	mov	[outmedia], rax
	call	outmedia$identify
	; that won't come back if it failed
	ret
calign
.do_count:
	push	rdi
	mov	dword [next_is_count], 0
	call	string$to_unsigned
	pop	rdi
	cmp	rax, 0
	jle	.bad_count
	mov	dword [pcount], eax
	call	heap$free
	ret
calign
.do_iter:
	push	rdi
	mov	dword [next_is_iter], 0
	call	string$to_unsigned
	pop	rdi
	cmp	rax, 0
	jle	.bad_iter
	mov	dword [piter], eax
	call	heap$free
	ret
calign
.bad_inputfile:
	push	rdi
	mov	rdi, .badfile
	call	string$to_stderr
	pop	rdi
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .badfile, 'input file error: '
calign
.bad_mediafile:
	push	rdi
	mov	rdi, .badmedia
	call	string$to_stderr
	pop	rdi
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .badmedia, 'media file error: '
calign
.bad_count:
	push	rdi
	mov	rdi, .badcount
	call	string$to_stderr
	pop	rdi
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .badcount, 'invalid -c COUNT specified: '
calign
.bad_iter:
	push	rdi
	mov	rdi, .baditer
	call	string$to_stderr
	pop	rdi
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .baditer, 'invalid -i ITER specified: '
calign
.do_dashd:
	mov	ecx, 1
	sub	ecx, eax
	mov	[do_enc], ecx
	ret
calign
.do_dashb:
	mov	[do_b64], eax
	ret
calign
.do_dashr:
	mov	[do_pwd], eax
	ret
calign
.do_dashalt:
	mov	dword [next_is_inputfile], 1
	ret
calign
.do_dashm:
	mov	dword [next_is_mediafile], 1
	ret
calign
.do_dashnoalt:
	mov	dword [noalt], 1
	ret
calign
.do_dashc:
	mov	dword [next_is_count], 1
	ret
calign
.do_dashi:
	mov	dword [next_is_iter], 1
	ret
calign
.do_drbg:
	mov	[pmix], 1
	ret
calign
.do_dash1:
	mov	[do_cascaded], 0
	ret
calign
.do_nomix:
	mov	[pmix], 0
	ret
cleartext .dashd, '-d'
cleartext .dashb, '-b'
cleartext .dashr, '-r'
cleartext .dash1, '-1'
cleartext .dashm, '-m'
cleartext .dashalt, '-alt'
cleartext .dashnoalt, '-noalt'
cleartext .dashc, '-c'
cleartext .dashi, '-i'
cleartext .dashdrbg, '-drbg'
cleartext .dashnomix, '-nomix'


	; because of the [silly] way I decided to do the arguments, special handling
	; is required for the -c COUNT and/or -i ITER for the main input file
	; along with -drbg and -nomix
	; (versus the argscan above which works fine for -alt inputfiles)
falign
mainargopts:
	; so, the idea here is to parse out -i and -c in reverse order until we hit
	; a -alt or run out of options, and apply them to the main inputfile
	; which was already list$pop_back'd from [argv]
	push	rbx r12
	mov	rdi, [argv]
	mov	rbx, [_list_last]
	test	rbx, rbx
	jz	.alldone
	xor	r12d, r12d
calign
.iter:
	mov	rdi, [rbx]
	mov	rsi, .dashi
	call	string$equals
	test	eax, eax
	jnz	.do_dashi
	mov	rdi, [rbx]
	mov	rsi, .dashc
	call	string$equals
	test	eax, eax
	jnz	.do_dashc
	mov	rdi, [rbx]
	mov	rsi, .dashdrbg
	call	string$equals
	test	eax, eax
	jnz	.do_drbg
	mov	rdi, [rbx]
	mov	rsi, .dash1
	call	string$equals
	test	eax, eax
	jnz	.do_dash1
	mov	rdi, [rbx]
	mov	rsi, .dashnomix
	call	string$equals
	test	eax, eax
	jnz	.do_nomix
	mov	rdi, [rbx]
	mov	rsi, .dashalt
	call	string$equals
	test	eax, eax
	jnz	.alldone
	; otherwise, set r12 to rbx and keep going
calign
.next:
	mov	r12, rbx
	mov	rbx, [rbx+_list_prevofs]
	test	rbx, rbx
	jnz	.iter
	pop	r12 rbx
	ret
cleartext .dashc, '-c'
cleartext .dashi, '-i'
cleartext .dash1, '-1'
cleartext .dashalt, '-alt'
cleartext .dashdrbg, '-drbg'
cleartext .dashnomix, '-nomix'
cleartext .missingdashi, 'missing argument to -i'
cleartext .missingdashc, 'missing argument to -c'
cleartext .baddashi, 'invalid argument to -i'
cleartext .baddashc, 'invalid argument to -c'
calign
.alldone:
	pop	r12 rbx
	ret
calign
.error:
	call	string$to_stderrln
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
calign
.do_dashi:
	mov	rdi, .missingdashi
	test	r12, r12
	jz	.error
	mov	rdi, [r12]
	call	string$to_unsigned
	mov	rdi, .baddashi
	cmp	rax, 0
	jle	.error
	mov	rdi, [inputfiles]
	mov	rdi, [_list_first]
	mov	rdi, [rdi]
	mov	[rdi+inputfile_piter_ofs], eax
	jmp	.next
calign
.do_dashc:
	mov	rdi, .missingdashc
	test	r12, r12
	jz	.error
	mov	rdi, [r12]
	call	string$to_unsigned
	mov	rdi, .baddashc
	cmp	rax, 0
	jle	.error
	mov	rdi, [inputfiles]
	mov	rdi, [_list_first]
	mov	rdi, [rdi]
	mov	[rdi+inputfile_pcount_ofs], eax
	jmp	.next
calign
.do_drbg:
	mov	rdi, [inputfiles]
	mov	rdi, [_list_first]
	mov	rdi, [rdi]
	mov	qword [rdi+inputfile_mix_ofs], 1
	jmp	.next
calign
.do_nomix:
	mov	rdi, [inputfiles]
	mov	rdi, [_list_first]
	mov	rdi, [rdi]
	mov	qword [rdi+inputfile_mix_ofs], 0
	jmp	.next
calign
.do_dash1:
	mov	rdi, [inputfiles]
	mov	rdi, [_list_first]
	mov	rdi, [rdi]
	mov	qword [rdi+inputfile_cascaded_ofs], 0
	jmp	.next



falign
termreset:
	xor	edi, edi
	mov	esi, 0x5404		; TCSETSF
	mov	rdx, [termios]
	mov	eax, syscall_ioctl
	syscall
	ret



outmedia_png = 0
outmedia_jfif = 1
outmedia_exif = 2


falign
public outmedia$identify
outmedia$identify:
	; [outmedia] is a valid privmapped object, see if we can identify what it is
	; and if we can't, bailout with an error
	push	rbx r12 r13 r14
	mov	rbx, [outmedia]
	mov	r12, [rbx+privmapped_base_ofs]
	mov	r13, [rbx+privmapped_size_ofs]
	cmp	r13, 41				; min size required for a PNG parse
	jb	.err_unrecognized
	mov	rax, 0xa1a0a0d474e5089
	cmp	[r12], rax
	je	.maybe_png
	cmp	dword [r12], 0xe0ffd8ff
	je	.maybe_jfif
	cmp	dword [r12], 0xe1ffd8ff
	je	.maybe_exif
calign
.err_unrecognized:
	mov	rdi, .unrecognized
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .unrecognized, 'Unrecognized or unsupported mediafile type.'
calign
.maybe_exif:
	cmp	dword [r12+6], 'EXIF'
	je	.exif
	cmp	dword [r12+6], 'Exif'
	jne	.err_unrecognized
.exif:
	; EXIF it is, we'll let the merge function deal with the rest
	mov	qword [rbx+privmapped_user_ofs], outmedia_exif
	pop	r14 r13 r12 rbx
	ret
calign
.maybe_jfif:
	cmp	dword [r12+6], 'JFIF'
	jne	.err_unrecognized
	; JFIF it is, we'll let the merge function deal with the rest
	mov	qword [rbx+privmapped_user_ofs], outmedia_jfif
	pop	r14 r13 r12 rbx
	ret
calign
.maybe_png:
	; make sure the first chunk is an IHDR
	cmp	dword [r12+12], 'IHDR'
	jne	.err_unrecognized
	; otherwise, it is a PNG
	mov	qword [rbx+privmapped_user_ofs], outmedia_png
	; count the number of chunks that exist after the IHDR, and validate it as we go
	add	r12, 8
	sub	r13, 16
	xor	r14d, r14d
	mov	ecx, [r12]			; length of the header chunk
	bswap	ecx
	add	r12, 8
	cmp	rcx, r13
	jae	.err_unrecognized
	cmp	ecx, 13				; IHDR is 13 bytes
	jne	.err_unrecognized
	; 13 + 4 bytes for the CRC to skip:
	add	r12, 17
	sub	r13, 17
	; commence chunk counting, and store the location of the first chunk after the header in outbuf
	mov	rsi, [outbuf]
	mov	[rsi+buffer_user_ofs], r12
calign
.png_chunkscan:
	cmp	r13, 12
	jb	.err_unrecognized
	mov	eax, [r12]
	bswap	eax
	add	eax, 12
	cmp	rax, r13
	ja	.err_unrecognized
	; dword at [r12+4] is our chunk type, if it is IEND, bailout, otherwise, increment r14d and keep going
.png_chunkscan_normal:
	cmp	dword [r12+4], 'IEND'
	je	.png_done
	add	r14d, 1
	cmp	dword [r12+4], 'IDAT'
	je	.png_idat
	add	r12, rax
	sub	r13, rax
	jz	.err_unrecognized
	jmp	.png_chunkscan
calign
.png_idat:
	; spec says multiple IDAT chunks must be consecutive, so we can't treat them as separate and inject our goods
	add	r12, rax
	sub	r13, rax
	jz	.err_unrecognized
	; otherwise, fall into continuous IDAT scanning
calign
.png_idatscan:
	cmp	r13, 12
	jb	.err_unrecognized
	mov	eax, [r12]
	bswap	eax
	add	eax, 12
	cmp	rax, r13
	ja	.err_unrecognized
	cmp	dword [r12+4], 'IDAT'
	jne	.png_chunkscan_normal
	add	r12, rax
	sub	r13, rax
	jz	.err_unrecognized
	jmp	.png_idatscan
calign
.png_done:
	; r14d has our # of chunks that exist _after_ IHDR
	; if it is _zero_, something went horribly wrong
	test	r14d, r14d
	jz	.err_unrecognized
	mov	dword [rbx+privmapped_user_ofs+4], r14d
	pop	r14 r13 r12 rbx
	ret





falign
public outmedia$merge
outmedia$merge:
	; called when all output is sitting in the outbuf ready to go
	mov	rdi, [outmedia]
	mov	eax, [rdi+privmapped_user_ofs]
	jmp	qword [rax*8+.dispatch]
dalign
.dispatch:
	dq	.png, .jfif, .exif
calign
.png:
	; outmedia is a PNG file, the dword in [rdi+privmapped_user_ofs+4] is our total PNG chunk count
	; outbuf's buffer_user_ofs is a pointer to the start of the first chunk after the header
	; we want our encrypted goods to be placed in a _randomly_ located chunk somewhere after IHDR
	; and before IEND, in a per-specification randomized chunk identifier
	push	rbx r12 r13 r14 r15
	sub	rsp, 8
	mov	rbx, [outbuf]
	mov	r12, [rdi+privmapped_base_ofs]
	mov	r13, [rbx+buffer_user_ofs]		; start of first chunk after IHDR
	mov	r14, [rdi+privmapped_size_ofs]
	add	r14, r12				; pointer to the end of the PNG
	mov	eax, [rbx+buffer_length_ofs]		; note: >4GB not gonna fly here, hahah, but that seems unreasonable anyway, fine by me
	bswap	eax
	mov	[rsp], eax				; store our byteswapped length

	mov	esi, [rdi+privmapped_user_ofs+4]	; # of chunks between IHDR and IEND
	xor	edi, edi
	call	rng$int
	; so now we have a random skip count, we know our mediafile is good, so skip forward this many
	test	eax, eax
	jz	.png_skipdone
calign
.png_skip:
	mov	ecx, [r13]
	bswap	ecx
	add	ecx, 12
.png_skip_normal:
	cmp	dword [r13+4], 'IDAT'
	je	.png_skip_idats
	add	r13, rcx
	sub	eax, 1
	jnz	.png_skip
	; fallthrough to png_skipdone:
calign
.png_skipdone:
	; so now, we can safely output between r13 and r12 to stdout:
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, r12
	mov	rdx, r13
	sub	rdx, r12
	syscall
	; now we can generate our random chunk type, and that must be:
	; first and second letters must be random lowercase, third spec says must be upper case
	; fourth must be lowercase
	xor	edi, edi
	mov	esi, 25
	call	rng$int
	and	eax, 0xff
	add	eax, 'a'
	mov	[rsp+4], al
	xor	edi, edi
	mov	esi, 25
	call	rng$int
	and	eax, 0xff
	add	eax, 'a'
	mov	[rsp+5], al
	xor	edi, edi
	mov	esi, 25
	call	rng$int
	and	eax, 0xff
	add	eax, 'A'
	mov	[rsp+6], al
	xor	edi, edi
	mov	esi, 25
	call	rng$int
	and	eax, 0xff
	add	eax, 'a'
	mov	[rsp+7], al
	; now our preface 8 bytes is complete, next we need to calculate our CRC to append to the outbuf before we send it
	; CRC is calculated with the chunk type and the data, but not the length
	xor	edi, edi
	lea	rsi, [rsp+4]
	mov	edx, 4
	call	crc$32
	mov	edi, eax
	mov	rsi, [rbx+buffer_itself_ofs]
	mov	edx, [rbx+buffer_length_ofs]
	call	crc$32
	; spec says network byte order:
	bswap	eax
	mov	rdi, rbx
	mov	esi, eax
	call	buffer$append_dword
	; so now we can output our 8 byte chunk preface + outbuf
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, 8
	syscall
	add	rsp, 8
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rbx+buffer_itself_ofs]
	mov	edx, [rbx+buffer_length_ofs]
	syscall
	; and finally, r13 for r14-r13 bytes of the remaining PNG
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, r13
	mov	rdx, r14
	sub	rdx, r13
	syscall
	pop	r15 r14 r13 r12 rbx
	ret
calign
.png_skip_idats:
	; spec says multiple IDAT must be consecutive so we have to treat these all as one if more than one exists
	; skip over the first IDAT and decrement our chunk counter
	add	r13, rcx
	sub	eax, 1
calign
.png_skip_idatscan:
	mov	ecx, [r13]
	bswap	ecx
	add	ecx, 12
	cmp	dword [r13+4], 'IDAT'
	jne	.png_skip_idatdone
	add	r13, rcx
	jmp	.png_skip_idatscan
calign
.png_skip_idatdone:
	test	eax, eax
	jz	.png_skipdone
	jmp	.png_skip_normal

calign
.exif:
	push	rbx r12 r13 r14 r15
	mov	rbx, [outbuf]				; our encrypted materials to embed
	mov	r12, [rdi+privmapped_base_ofs]		; sourceptr of our outmedia
	mov	r13, [rdi+privmapped_size_ofs]		; size of our outmedia
	add	r13, r12				; ptr to end of our outmedia
	mov	r14, [rbx+buffer_itself_ofs]		; crypto start
	mov	r15, [rbx+buffer_length_ofs]		; crypto length
	; for EXIF, we skip the APP1 initial segment, and inject our APP12 straight after it
	movzx	eax, word [r12+4]			; Length
	xchg	ah, al
	add	eax, 4					; +2 for length, +2 for SOI
	add	r12, rax
	; so at this point, we can output up to r12
	mov	eax, syscall_write
	mov	rsi, [rdi+privmapped_base_ofs]
	mov	edi, 1
	mov	rdx, r12
	sub	rdx, rsi
	syscall
	sub	rsp, 16
	; the remainder will be same-same as we do for JFIF
	jmp	.jfif_outloop
calign
.jfif:
	push	rbx r12 r13 r14 r15
	mov	rbx, [outbuf]				; our encrypted materials to embed
	mov	r12, [rdi+privmapped_base_ofs]		; sourceptr of our outmedia
	mov	r13, [rdi+privmapped_size_ofs]		; size of our outmedia
	add	r13, r12				; ptr to end of our outmedia
	mov	r14, [rbx+buffer_itself_ofs]		; crypto start
	mov	r15, [rbx+buffer_length_ofs]		; crypto length
	; we can safely skip the JFIF APP0 segment, and see if the next one is a JFXX
	; and skip that one too if it is
	movzx	eax, word [r12+4]			; Length
	xchg	ah, al
	add	eax, 4					; +2 for length, +2 for SOI
	add	r12, rax
	; so if the next two bytes are also ff, e0, and dword at [4] == JFXX, skip that too
	cmp	word [r12], 0xe0ff
	jne	.jfif_nojfxx
	cmp	dword [r12+4], 0x5858464a
	jne	.jfif_nojfxx
	; otherwise, JFXX is sitting here, and it is sposed to be adjacent to the JFIF APP0
	; so skip this one too
	movzx	eax, word [r12+2]			; Length
	xchg	ah, al
	add	eax, 2
	add	r12, rax
calign
.jfif_nojfxx:
	; we'll output APP12 (0xecff) segments, with our identifier being a random 7 byte & 0x7f characters,
	; null terminated. In the wild, the only APP12 markers I have in my fairly large stash are Ducky
	; or PictureInfo, so during the parse we skip those and treat the rest as though we created them
	
	; so at this point, we can output up to r12
	mov	eax, syscall_write
	mov	rsi, [rdi+privmapped_base_ofs]
	mov	edi, 1
	mov	rdx, r12
	sub	rdx, rsi
	syscall

	; now we can commence our segment creation, we'll need 12 bytes for our APP12 + length + string
	; and each actual crypto segment can be at most 65535 - 2(length) - 8 (identifier), 65525
	sub	rsp, 16
calign
.jfif_outloop:
	; get a 64 bit RNG for our identifier
	call	rng$u64
	mov	word [rsp], 0xecff		; APP12
	mov	rcx, r15
	mov	edx, 65525
	cmp	rcx, rdx
	cmova	rcx, rdx
	; save this length so we can mess with r14/r15
	mov	r8d, ecx
	mov	r9, qword [.jfif_idmask]
	; add 8 for our identifier and 2 for our length
	add	ecx, 10
	; byteswap and put into our length
	xchg	ch, cl
	mov	word [rsp+2], cx
	; construct our identifier
	and	rax, r9
	; add our identifier
	mov	[rsp+4], rax
	; output our 12 bytes, but save our length modifier
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, rsp
	mov	edx, 12
	push	r8
	syscall
	pop	rdx
	; output our rdx worth of bytes from r14
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, r14
	; update r14/r15
	add	r14, rdx
	sub	r15, rdx
	syscall
	; if we have data remaining, repeat
	test	r15, r15
	jnz	.jfif_outloop
	; otherwise, we are all done adding our segments
	; now we can output the remainder of the media
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, r12
	mov	rdx, r13
	sub	rdx, r12
	syscall

	; done, dusted.
	add	rsp, 16
	pop	r15 r14 r13 r12 rbx
	ret
dalign
.jfif_idmask:
	dq	0x007f7f7f7f7f7f7f



cleartext banner, 'This is toplip v1.16 ',0xa9,' 2015, 2016 2 Ton Digital. Author: Jeff Marrison',10,'A showcase piece for the HeavyThing library. Commercial support available',10,'Proudly made in Cooroy, Australia. More info: https://2ton.com.au/toplip',10

falign
public _start
_start:
	; every HeavyThing program needs to start wiht a call to initialise it:
	call	ht$init
	
	cmp	dword [argc], 1
	je	.needinputfile

	; get our termios goods happening
	mov	edi, 64
	call	heap$alloc_clear
	mov	[termios], rax
	xor	edi, edi
	mov	esi, 0x5401		; TCGETS
	mov	rdx, rax
	mov	eax, syscall_ioctl
	syscall
	; copy that to the stack
	sub	rsp, 64
	mov	rdi, rsp
	mov	rsi, [termios]
	mov	edx, 60			; sizeof(struct termios) == 60
	call	memcpy
	; clear the ECHO
	and     dword [rsp+0xC], 0xfffffff7	; c_lflag &= ~(ECHO)
	; TCSETSF next
	xor	edi, edi
	mov	esi, 0x5404		; TCSETSF
	mov	rdx, rsp
	mov	eax, syscall_ioctl
	syscall
	; done with the stack
	add	rsp, 64

	; create our inputfiles list
	call	list$new
	mov	[inputfiles], rax

	; remove our program name (argv[0]) from the args
	mov	rdi, [argv]
	call	list$pop_front
	mov	rdi, rax
	call	heap$free

	; regardless of whether we are encrypting or decrypting, last arg must be inputfile
	mov	rdi, [argv]
	call	list$pop_back

	; fake out the argscanner and call that an input file
	mov	dword [next_is_inputfile], 1
	mov	rdi, rax
	call	argscan
	; that will have bailed out if it failed

	; due to the [silly] way that I decided to do arg handling, deal with -i and -c to main inputfile first
	call	mainargopts

	; create an output buffer
	call	buffer$new
	mov	[outbuf], rax

	; create a salt buffer
	call	buffer$new
	mov	[salt], rax

	; create a header buffer
	call	buffer$new
	mov	[headerbuf], rax

	; argscan to get our flags and other input files
	mov	rdi, [argv]
	mov	rsi, argscan
	call	list$foreach

	; do some sanity checking of our args
	mov	rdi, .toomanyinputfiles
	mov	rsi, [inputfiles]
	cmp	qword [rsi+_list_size_ofs], 4
	ja	.error
	mov	rdi, .inputfile
	cmp	qword [rsi+_list_size_ofs], 0
	je	.error

	; if we are decrypting, and input files > 0, puke
	cmp	[do_enc], 0
	jne	.skip_decfilecheck
	mov	rdi, .toomanyinputfiles
	cmp	qword [rsi+_list_size_ofs], 1
	jne	.error
.skip_decfilecheck:
	; now, load/parse/do whatever to our inputfiles before we go any further
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$load
	call	list$foreach

	; now we go our separate ways depending on whether we are encrypting or decrypting

	; dump our banner to stderr
	mov	rdi, banner
	call	string$to_stderr

	cmp	[do_enc], 0
	je	.decrypt

	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; encrypt
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------

	; if -noalt was not specified, _and_ if inputfiles count is 1, we need to add a bogus
	; inputfile to the mix
	cmp	dword [noalt], 0
	jne	.skip_bogus

	; otherwise, fill our inputfiles up to 4 with bogus material, random size based on main input file
.bogus_fill:
	mov	rdi, [inputfiles]
	cmp	qword [rdi+_list_size_ofs], 4
	je	.skip_bogus
	mov	rsi, [rdi+_list_first_ofs]
	mov	rdx, [rsi+_list_valueofs]
	mov	rdi, [rdx+inputfile_size_ofs]
	call	inputfile$new_bogus
	mov	rdi, [inputfiles]
	mov	rsi, rax
	call	list$push_back
	jmp	.bogus_fill

.skip_bogus:

	; generate our 32 byte SALT, we know that the default buffer size is 256, more than we need
	mov	rdi, [salt]
	add	qword [rdi+buffer_length_ofs], 32
	add	qword [rdi+buffer_endptr_ofs], 32
	mov	rdi, [rdi+buffer_itself_ofs]
	mov	esi, 32
	call	rng$block

	; each inputfile's totalsize is already set, garbage is already set, padlen is already set
	; first thing we have to do is acquire (or generate) the keys for each input file
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$keygen
	call	list$foreach

	mov	rdi, .encrypting
	call	string$to_stderr

	; next step is randomizing the inputfile list (this determines what order they appear in the output)
	mov	rdi, [inputfiles]
	call	list$shuffle

	; determine our offsets into our output (which is required before we can generate HEADER blocks)
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$extents
	call	list$foreach

	; generate our 128 byte HEADER_OR_IV block, we know that the default buffer
	; size is 256, more than we need so we can write directly to it
	mov	rdi, [headerbuf]
	add	qword [rdi+buffer_length_ofs], 128
	add	qword [rdi+buffer_endptr_ofs], 128
	mov	rdi, [rdi+buffer_itself_ofs]
	mov	esi, 128
	call	rng$block
	
	; generate a list of 8 header entries
	call	list$new
	mov	[headerblocks], rax
	repeat 8
		mov	rdi, [headerblocks]
		mov	esi, % - 1
		call	list$push_back
	end repeat
	mov	rdi, [headerblocks]
	call	list$shuffle

	; now we can let each input file calculate its HEADER and IV
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$headeriv
	call	list$foreach

	; output the 32 byte SALT to stdout
	mov	rcx, [salt]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	edx, 32
	call	output

	; output the 128 byte headerbuf to stdout
	mov	rcx, [headerbuf]
	mov	eax, syscall_write
	mov	edi, 1
	mov	rsi, [rcx+buffer_itself_ofs]
	mov	edx, 128
	call	output

	; encrypt each output file
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$encrypt
	call	list$foreach

	; flush the output buffer
	call	output_flush

	; cleanup after ourselves
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$destroy
	call	list$clear

	; done, dusted.
	mov	rdi, .donemsg
	call	string$to_stderrln

	call	termreset
	mov	eax, syscall_exit
	xor	edi, edi
	syscall
cleartext .donemsg, 'Done'
cleartext .encrypting, 10,'Encrypting...'
calign
.decrypt:
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; decrypt
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; -----------------------------------------------------------------------------------------
	; if do_b64 was set, clear it either way because we have already converted the input
	; and we don't want our plaintext output to be base64
	mov	[do_b64], 0

	; the 32 byte SALT was set by the inputfile$load function call earlier

	; first thing we have to do is acquire the keys for the input file
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$keygen
	call	list$foreach

	; now just call decrypt, which will scan/find/do the deed
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$decrypt
	call	list$foreach

	; flush the output buffer
	call	output_flush
	
	; cleanup after ourselves
	mov	rdi, [inputfiles]
	mov	rsi, inputfile$destroy
	call	list$clear

	; done, dusted
	mov	rdi, .donemsg
	call	string$to_stderrln

	call	termreset
	mov	eax, syscall_exit
	xor	edi, edi
	syscall

.needinputfile:
	mov	rdi, banner
	call	string$to_stderr
	mov	eax, syscall_write
	mov	edi, 2
	mov	rsi, .msg_usage
	mov	edx, .msg_usage_len
	syscall
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
calign
.error:
	call	string$to_stderrln
	call	termreset
	mov	eax, syscall_exit
	mov	edi, 1
	syscall
cleartext .inputfile, 'input file required'
cleartext .toomanyinputfiles, 'too many input files'
dalign
.msg_usage:
db	'Usage: toplip [-b] [-d] [-r] [-m mediafile] [[-nomix|-drbg][-1][-c COUNT][-i ITER ]-alt inputfile] [-nomix|-drbg][-1][-c COUNT][-i ITER ]inputfile',10,\
	'  -b == input/output in base64 (see below notes)',10,\
	'  -d == decrypt the inputfile',10,\
	'  -r == generate (and display of course) one time 48 byte each pass phrases as base64',10,\
	'  -m mediafile == for encrypting only, merge the output into the specified mediafile.',10,\
	'       Valid media types: PNG, JPG (plain JFIF or EXIF).',10,\
	'       (Note that decrypting will auto-detect and attempt to extract if the inputfile for',10,\
	'       decryption is given a media file).',10,\
	'  -1 == for each input file (-alt or main), this option disables the use of cascaded',10,\
	'       AES256, and instead uses a single AES256 context (two for the XTS-AES stage).',10,\
	'  -c COUNT == for each input file (-alt or main), this option overrides the default count',10,\
	'       of one (1) passphrase. Specifying a higher count here will ask for this many actual',10,\
	'       passphrases, and generate this number of separate key material and crypto contexts',10,\
	'       that are then used over-top of each other (cascaded).',10,\
	'  -i ITER == for each input file (-alt or main), specify an alternate iteration count',10,\
	'       for scrypt',0x27,'s internal use of PBKDF2-SHA512 (default is 1). For the initial 8192',10,\
	'       bytes of key material, and before one-way AES key grinding of same, we use scrypt',10,\
	'       and this option overrides how many iterations of PBKDF2-SHA512 it will perform',10,\
	'       for each passphrase. (NOTE: this can _dramatically_ increase the calc times).',10,\
	'       Hex values or decimal values permitted (e.g. 10, 0xfff, etc).',10,\
	'  -drbg == for each input file, by default the 8192 bytes of key material is xor',0x27,'d with',10,\
	'       TLSv1.2 PRF(SHA256) of the supplied passphrase(s). This option will mix the key',10,\
	'       material with HMAC_DRBG(SHA256) instead.',10,\
	'  -nomix == for each input file (see -drbg), this option specifies no additional mixing',10,\
	'       of the scrypt generated 8192 byte key material.',10,\
	'  -alt inputfile == generate one or more "Plausible Deniability" file (encrypting only)',10,\
	'       This will ask for another set of passphrases, which MUST NOT be the same.',10,\
	'       Without this option, three alternate contents are randomly generated such that it is',10,\
	'       impossible to tell by examining the encrypted output whether there is or is not',10,\
	'       anything other than pure random. See the -noalt option for what happens without',10,\
	'       this option. This option can be specified up to 3 times (for a max of 4 files).',10,\
	'  -noalt == Do not generate additional random data. By default, extra random data is',10,\
	'       inserted into the encrypted output such that forensic analysis (with a valid set',10,\
	'       of passphrases) on a given encrypted output does not cover all of the ciphertext',10,\
	'       present. See further commentary below about why the default setting is a good thing.',10,\
	'       Specifying this option means that no extra random data is inserted into the output',10,\
	'       (and this might be useful if you do not need plausible deniability, or you are',10,\
	'       dealing with very large files).',10,\
	'  if -b is specified for encrypt, base64 of the encrypted goods is output to stdout',10,\
	'  if -b is specified for decrypt, it is assumed the input is base64, and plaintext is output to stdout',10
.msg_usage_len = $ - .msg_usage



include '../ht_data.inc'
