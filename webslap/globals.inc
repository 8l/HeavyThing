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
	; globals.inc: webslap global variables, defaults where applicable
	;
globals
{
	; command line config goods 1:1
	requests	dq	1
	concurrency	dq	1
	cpucount	dq	2
	firsturl	dq	0
	tsvout		dq	0
	jsonout		dq	0
	urls		dq	0
	do_keepalive	dd	1
	do_gzip		dd	1
	do_cookies	dd	1
	do_tlsresume	dd	1
	do_etag		dd	1
	do_lastmod	dd	1
	do_random	dd	1
	do_ui		dd	1
}
