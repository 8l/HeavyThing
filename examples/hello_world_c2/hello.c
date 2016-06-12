/*
	; ------------------------------------------------------------------------
	; HeavyThing x86_64 assembly language library and showcase programs
	; Copyright © 2015 2 Ton Digital 
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

        see https://2ton.com.au/rants_and_musings/gcc_integration.html for
        information and commentary re: how/why/what/where/when

*/
/* declarations for HeavyThing functions that we need: */
void ht$init_args(int, char **);
void *string$from_cstr(const void *);
void string$to_stdoutln(const void *);
void heap$free(const void *);
int ht$syscall(int num);

int main(int argc, char *argv[]) {
	/* First order of business: initialize HeavyThing */
	/* Since we aren't interested in arguments/env, 0/NULL work fine here */
	ht$init_args(0, 0);
	/* Next, since we can't use the HeavyThing cleartext macro to create
	   a static string, we'll create one from a normal const char * */
	void *s = string$from_cstr("Heya");
	/* Write it */
	string$to_stdoutln(s);
	/* Free it */
	heap$free(s);
	/* since we compile with -nostdlib, make a call to exit (60) */
	ht$syscall(60);
}
