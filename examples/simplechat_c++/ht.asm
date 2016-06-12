include '../../ht_defaults.inc'
include '../../ht.inc'

	; dummy wrapper so that our fasm compiler will include
	; the parts of the HeavyThing library that we want (instead of
	; everything which is bigger than it needs to be).
	; NOTE: unlike our previous examples, this time we just define
	; them all as data pointers which still forces fasm to include
	; it all.
_include:
	dq	ht$init_args
	dq	string$from_cstr
	dq	string$to_stdoutln
	dq	heap$alloc
	dq	heap$free
	dq	epoll$new
	dq	inaddr_any
	dq	epoll$inbound
	dq	epoll$destroy
	dq	epoll$clone
	dq	epoll$receive
	dq	epoll$send
	dq	io$error
	dq	io$timeout
	dq	epoll$run
	dq	inet_ntoa
	dq	string$from_unsigned
	dq	string$to_utf8

include '../../ht_data.inc'
