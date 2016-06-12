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
	; rwasa.asm: Rapid Web Application Server in Assembler :-) haha
	;
	; Burning Purpose: Using the webserver architecture of the HeavyThing
	; library, provide normal HTTP[s] web serving w/ optional fastcgi,
	; and provide a simple example application that allows very easy
	; custom application handling from within this assembler environment.
	;
	; While the example application's assembly language hook doesn't DO
	; anything, copying this, modifying the webhook and recompiling is
	; basically all you'd have to do. (This demo piece just returns an
	; unexciting web response for .asmcall hooks, see inline comments
	; below for further details, as well as the -funcmatch startup option
	; that overrides the .asmcall matching)
	;
	; Further, in its standalone "showcase piece" form, it nicely provides
	; full normal webserver support.
	;
	; NOTE Re: our argument parsing/config building goods, while we do
	; catch some operational issues with the arguments we are passed, it
	; is more a matter of "garbage in or nonsensible order, etc" == undefined
	; results.... haha, used as intended, it is fine, YMMV :-)
	;
	; See https://2ton.com.au/rwasa for the full commentary/docs.
	;

include '../ht_defaults.inc'
include '../ht.inc'

include 'arguments.inc'
include 'worker.inc'
include 'master.inc'


	; this is our main function call hook, as defined by _start.hookthemall
	; it is called by the webserver layer with:
	; rdi == webserver object, rsi == request url, rdx == mimelike request object
	; per the webserver layer requirements, we must return one of:
	; null: webserver will respond with a 404 automatically.
	; -1 == webserver will sit there and do absolutely nothing
	; or anything else is a properly formed mimelike response object (including
	; preface line)
	;
	; for our demonstration purposes, we'll construct a simple text/plain return
falign
asmcall:
	prolog	asmcall
	push	rbx r12
	; build a dynamic text reply first up
	mov	rbx, rsi
	call	buffer$new
	mov	rdi, rax
	mov	rsi, .stringpreface
	mov	r12, rax
	call	buffer$append_string
	mov	rdi, rbx
	call	url$tostring
	mov	rbx, rax
	mov	rdi, r12
	mov	rsi, rax
	call	buffer$append_string
	mov	rdi, rbx
	call	heap$free
	mov	rdi, r12
	mov	rsi, .stringreply
	call	buffer$append_string

	; construct our return object
	call	mimelike$new
	; set the http preface
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, .httppreface
	call	mimelike$setpreface
	; set our content type
	mov	rdi, rbx
	mov	rsi, mimelike$contenttype
	mov	rdx, mimelike$textplain
	call	mimelike$setheader
	; set our body to the UTF8 of our string
	mov	rdi, rbx
	mov	rsi, [r12+buffer_itself_ofs]
	mov	rdx, [r12+buffer_length_ofs]
	call	mimelike$setbody
	; free our working buffer
	mov	rdi, r12
	call	buffer$destroy
	; return our mimelike response
	mov	rax, rbx
	pop	r12 rbx
	epilog
cleartext .stringpreface, 'Welcome to rwasa!',13,10,'URL: '
cleartext .stringreply, 13,10,'This is a native assembler function call hook.',13,10,13,10,'See https://2ton.com.au/rwasa for more information/documentation.',13,10
cleartext .httppreface, 'HTTP/1.1 200 rwasa reporting for duty'


public _start
falign
_start:
	call	ht$init

	; Let the boring stuff handle argument parsing (which determines
	; all of the initial configuration/etc and provides basic usage)
	
	call	arguments

	; now, there is a list of webservercfg objects sitting in the
	; global variable [configs], minimum count of 1 (the arguments
	; function doesn't allow startup with zero configurations).
	
	; So, our default demo action is to hook every webrequest for
	; every single configuration that ends in .asmcall, such that
	; any URL request to our webserver enviro whose path ends in
	; same will call our do-nothin (note: .asmcall can be changed
	; with the startup option -funcmatch)
	mov	rdi, [configs]
	mov	rsi, .hookthemall
	call	list$foreach
	
	; start everything up
	jmp	masterthread
falign
.hookthemall:
	; this is called by list$foreach with rdi == webservercfg object
	; all we are doing is adding a function call hook attached
	; to .asmcall (or whatever was specified with -funcmatch)
	mov	rsi, [funcmatch]
	mov	rdx, asmcall
	call	webservercfg$function_map
	ret

include '../ht_data.inc'
