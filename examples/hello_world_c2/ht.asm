include 'settings.inc'
include '../../ht.inc'

	; Unlike our first example, this time we don't want the ENTIRE
	; library being included in our example program
	; So, we create a dummy wrapper so that fasm only includes the
	; functions that we want:
_include:
	call	ht$init_args
	call	string$from_cstr
	call	string$to_stdoutln
	call	heap$free
	call	ht$syscall
	
include '../../ht_data.inc'
