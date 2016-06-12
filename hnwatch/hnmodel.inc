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
	; hnmodel.inc: everything required to retrieve and keep sane our HN data
	; makes use of eventstream.inc for EventSource SSE/streaming
	; and makes use of the HeavyThing webclient for retrieving items
	;
	; Note for future reference and/or anyone who cares:
	; Since this makes use of the EventSource/SSE streaming, we receive a
	; "stream" of HN ids to retrieve, and we issue the requests for each
	; ID (whether updated or initial) then and there, on the spot. This
	; for the most part works a treat, but occasionally we receive a 401
	; Permission Denied for item requests. After some quality head scratching,
	; it turns out that if we wait 30 seconds or so after receiving the
	; 401 and try our request again, it works much better. I won't bother to
	; speculate as to WHY this is happening, but several delays were
	; attempted, and 30 seconds appears to be the sweet spot such that errors
	; don't occur nearly as often (they still seem to but much more rare).
	;
	; If you see a nonzero E: (errorcount) in the UI, then uncomment
	; the following definition and it will dump (albeit not very pretty)
	; error reports to errors.log in the current working directory.
	;
	; Uncomment this if you want to know what is causing nonzero E:
	; error_logging = 1

globals
{
	webclient	dq	0
	updatestream	dq	0		; an eventstream for updates
	mainstream	dq	0		; an eventstream for 'topstories', 'newstories', etc.

	mainorder	dq	0		; a normal list w/ string keys for the current main

	statuscb	dq	0		; if nonzero, called for status updates
	statuscbarg	dq	0		; if "", this gets passed in rdi to it

	items		dq	0		; stringmap that holds onto our items and state information

	updatedcb	dq	0		; if set, function to call after the items or order gets updated

	items_blacklist	dq	0		; a blacklist object repurposed for our expiry needs
	items_scratch	dq	0		; a scratch list for the weed operation

	item_retries	dq	0		; stringmap of items with unsigned retry counts, because
						; we occasionally get 401 Unauthorized responses when we get
						; retrieve items (not sure why).

	; counters
	requestcount	dq	0		; total # of items requested
	bytecount	dq	0		; total # of bytes received for items
	errorcount	dq	0		; total # of retrieval errors
}

include 'eventstream.inc'


	; single argument in rdi: string for which main we are after:
	; 'topstories', 'newstories', 'askstories', 'showstories', 'jobstories'
	; called from _start (aka main) to get things underway
falign
hnmodel$init:
	prolog	hnmodel$init
	push	rdi
	; first up, create our webclient
	xor	edi, edi
	call	webclient$new
	mov	[webclient], rax
	; next, eventstream for our main index
	pop	rdi
	mov	rsi, hnmodel$mainstream
	mov	rdx, hnmodel$statusupdate
	call	eventstream$new
	mov	[mainstream], rax
	; next, eventstream for our updates
	mov	rdi, .updates
	mov	rsi, hnmodel$updatestream
	mov	rdx, hnmodel$statusupdate
	call	eventstream$new
	mov	[updatestream], rax
	; create an empty list for our order
	call	list$new
	mov	[mainorder], rax
	; create a insert-order stringmap for our items
	mov	edi, 1
	call	stringmap$new
	mov	[items], rax
	mov	edi, 1
	call	stringmap$new
	mov	[item_retries], rax
	; create a blacklist object, as it will serve our needs for an object expiry
	mov	edi, 10800			; 3 hour expiry if we haven't poked/prodded one in that timeframe
	call	blacklist$new
	mov	[items_blacklist], rax
	; create an eternal timer to deal with our repurposed blacklist to get rid of old items
	mov	rdi, items_weed_vtable
	xor	esi, esi
	call	epoll$new
	mov	edi, 3600000			; once an hour is good
	mov	rsi, rax
	call	epoll$timer_new
	; create our items_scratch list
	call	list$new
	mov	[items_scratch], rax
	epilog
cleartext .updates, 'updates'
cleartext .main, 'main'


	; single argument in rdi: a string for our new main eventstream
	; we clear the mainorder list, and destroy the current eventstream
	; and replace it with our newly selected one
falign
hnmodel$newmain:
	prolog	hnmodel$newmain
	push	rdi
	mov	rdi, [mainstream]
	call	eventstream$destroy
	pop	rdi
	mov	rsi, hnmodel$mainstream
	mov	rdx, hnmodel$statusupdate
	call	eventstream$new
	mov	[mainstream], rax
	; clear the mainorder list
	mov	rdi, [mainorder]
	mov	rsi, heap$free
	call	list$clear
	epilog


	; called with no arguments, we destroy the contents of mainorder and the items cache
falign
hnmodel$reset:
	prolog	hnmodel$reset
	; mainorder, items stringmap, items_blacklist all need wiped out, everything else stays in tact
	mov	rdi, [mainorder]
	mov	rsi, heap$free
	call	list$clear
	mov	rdi, [items]
	mov	rsi, .eachitem
	call	stringmap$clear
	mov	rdi, [items_blacklist]
	call	blacklist$destroy
	mov	edi, 10800			; 3 hour expiry if we haven't poked/prodded one in that timeframe
	call	blacklist$new
	mov	[items_blacklist], rax
	epilog
falign
.eachitem:
	; rdi == string key, rsi == possible json object or null if it hasn't been populated yet
	push	rsi
	call	heap$free
	pop	rdi
	test	rdi, rdi
	jz	.nodestroy
	call	json$destroy
.nodestroy:
	ret



	; single argument in rdi: a json object with our main stream data
	; eventstream deals with cleaning up the json passed to us here
falign
hnmodel$mainstream:
	prolog	hnmodel$mainstream
	; Burning Purpose: dispose of our contents in mainorder, replace with
	; copies of the stringvalues of the passed jsonarray in data, and while
	; we are at it, verify that fetches have occurred for each of the items
	; or at least are underway
	push	rbx
	mov	rbx, rdi
	mov	rsi, .data
	call	json$getvaluebyname
	test	rax, rax
	jz	.alldone
	cmp	dword [rax+json_type_ofs], json_array
	jne	.alldone
	mov	rbx, rax
	mov	rdi, rax
	call	json$arraylength
	test	rax, rax
	jz	.alldone
	; otherwise, we are in business, clear our mainorder list first up
	mov	rdi, [mainorder]
	mov	rsi, heap$free
	call	list$clear
	; next up, iterate through our json array
	mov	rdi, rbx
	mov	rsi, .eachitem
	call	json$foreach
	; mainorder has been updated, call the updatedcb
	cmp	qword [updatedcb], 0
	je	.alldone
	call	qword [updatedcb]
.alldone:
	pop	rbx
	epilog
cleartext .data, 'data'
falign
.eachitem:
	; this gets called with rsi == a json object (which better be a string)
	cmp	dword [rdi+json_type_ofs], json_value
	jne	.borked
	; LIMITER
	mov	eax, dword [main_item_limit]
	mov	rsi, [mainorder]
	cmp	dword [rsi+_list_size_ofs], eax
	jae	.borked
	; END LIMITER
	; otherwise, make a string copy of its stringvalue
	mov	rdi, [rdi+json_value_ofs]
	call	string$copy
	push	rax
	mov	rdi, [mainorder]
	mov	rsi, rax
	call	list$push_back
	; make sure this item is either already here or queued up, and if not, queue up one ourselves
	pop	rdi
	xor	esi, esi		; not an update
	call	hnmodel$retrieve
.borked:
	ret


	; single argument in rdi: a json object with our update stream data
falign
hnmodel$updatestream:
	prolog	hnmodel$updatestream
	push	rbx
	mov	rbx, rdi
	mov	rsi, .data
	call	json$getvaluebyname
	test	rax, rax
	jz	.alldone
	cmp	dword [rax+json_type_ofs], json_object
	jne	.alldone
	; updates come in with an items array and a profiles array
	mov	rbx, rax
	mov	rdi, rax
	mov	rsi, .items
	call	json$getvaluebyname
	test	rax, rax
	jz	.alldone
	cmp	dword [rax+json_type_ofs], json_array
	jne	.alldone
	mov	rbx, rax
	mov	rdi, rax
	call	json$arraylength
	test	rax, rax
	jz	.alldone
	; iterate through these, and let retrieve deal with it
	mov	rdi, rbx
	mov	rsi, .eachitem
	call	json$foreach
.alldone:
	pop	rbx
	epilog
cleartext .data, 'data'
cleartext .items, 'items'
falign
.eachitem:
	; this gets called with rsi == a json object (which better be a string)
	cmp	dword [rdi+json_type_ofs], json_value
	jne	.borked
	mov	rdi, [rdi+json_value_ofs]
	; make sure this item is either already here or queued up, and if not, queue up one ourselves
	mov	esi, 1			; this IS an update
	call	hnmodel$retrieve
.borked:
	ret


	; single argument in rdi: a string for a status update
falign
hnmodel$statusupdate:
	prolog	hnmodel$statusupdate
	mov	rsi, rdi
	mov	rdi, [statuscbarg]
	cmp	qword [statuscb], 0
	je	.skipit
	call	qword [statuscb]
.skipit:
	epilog


	; two arguments: rdi == string item id, esi == bool as to whether it is an update or not
falign
hnmodel$retrieve:
	prolog	hnmodel$retrieve
	push	rbx r12 r13
	mov	rbx, rdi
	mov	r12d, esi
	; convert our item id into an unsigned so we can mess with our blacklist
	call	string$to_unsigned
	mov	r13, rax
	; first up, see if we already know about this item
	mov	rsi, rbx
	mov	rdi, [items]
	call	stringmap$find
	test	rax, rax
	jz	.freshmeat
	push	rax
	; update our blacklist timing
	mov	rdi, [items_blacklist]
	mov	rsi, r13
	call	blacklist$check
	pop	rax
	; if this is NOT an update, we are done
	test	r12d, r12d
	jz	.alldone
	; set rbx to the string KEY (because it will survive past this call, and we
	; need it for our webclient get)
	mov	rbx, [rax+_avlofs_key]
	jmp	.freshmeat_skipinsert
.freshmeat:
	; insert a stringmap entry with a null value to indicate it is underway
	; but only if our previous find actually did return 0
	mov	rdi, rbx
	call	string$copy
	mov	rbx, rax
	mov	rdi, [items]
	mov	rsi, rax
	xor	edx, edx
	call	stringmap$insert_unique
	; we also want to include our id in our blacklist
	mov	rdi, [items_blacklist]
	mov	rsi, r13
	call	blacklist$add
.freshmeat_skipinsert:
	; issue a new web get for this one
	mov	rdi, .itemurlpreface
	mov	rsi, rbx
	call	string$concat
	mov	r12, rax
	mov	rdi, rax
	mov	rsi, .itemurlpostface
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, [webclient]
	mov	rsi, r12
	mov	rdx, hnmodel$webitem
	mov	rcx, rbx
	add	qword [requestcount], 1
	call	webclient$get
	; status line for it too
	mov	rdi, .status_preface
	mov	rsi, r12
	call	string$concat
	mov	rdi, r12
	mov	r12, rax
	call	heap$free
	mov	rdi, r12
	call	hnmodel$statusupdate
	mov	rdi, r12
	call	heap$free
.alldone:
	pop	r13 r12 rbx
	epilog
cleartext .itemurlpreface, 'https://hacker-news.firebaseio.com/v0/item/'
cleartext .itemurlpostface, '.json'
cleartext .status_preface, 'Get: '


falign
hnmodel$webitem:
	prolog	hnmodel$webitem
	; rdi == our string key into our items map
	; rsi == mimelike result object with our item
	; rdx == url object
	; rcx == # milliseconds it took to get it
	push    rbx r12 r13 r14
	mov     rbx, rdi
	mov     r12, rsi
	cmp     rsi, webclient_fail_dns
	je      .dnsfail
	cmp     rsi, webclient_fail_preconnect
	je      .preconnect
	cmp     rsi, webclient_fail_closed
	je      .closed
	cmp     rsi, webclient_fail_timeout
	je      .timeout
	; let the statuscb know that we got what we wanted
	mov	rsi, rdi
	mov	rdi, .status_preface
	call	string$concat
	push	rax
	mov	rdi, rax
	call	hnmodel$statusupdate
	pop	rdi
	call	heap$free
	; construct a native string from the utf8 response
	mov     rdi, [r12+mimelike_body_ofs]
	mov     rsi, [rdi+buffer_length_ofs]
	mov     rdi, [rdi+buffer_itself_ofs]
	add	qword [bytecount], rsi
	call    string$from_utf8
	mov     r13, rax
	; verify that our preface contains ' 200 '
	mov	rdi, [r12+mimelike_preface_ofs]
	mov	rsi, .p200
	call	string$indexof
	cmp	rax, -1
	je	.not200
	mov     rdi, r13
	xor     esi, esi
	call    json$parse_object
	mov     rdi, r13
	mov     r13, rax
	call    heap$free
	test    r13, r13
	jz      .jsonfail
	; otherwise, r13 is our valid json object for the item
	; our key is sitting in rbx, so next up is finding it in our item map
	mov	rdi, [items]
	mov	rsi, rbx
	call	stringmap$find
	test	rax, rax		; sanity only, should be here
	jz	.borked
	mov	rdi, [rax+_avlofs_value]
	mov	[rax+_avlofs_value], r13
	test	rdi, rdi
	jz	.skip_json_destroy
	call	json$destroy
.skip_json_destroy:
	; done, dusted.
	cmp	qword [updatedcb], 0
	je	.alldone
	mov	rdi, rbx		; the key that caused the updatedcb
	call	qword [updatedcb]
.alldone:

if defined debug_output
	; debug output only:
	; turn that into a string for now
	mov     rdi, r13
	call    json$tostring
	mov     r14, rax
	mov     rdi, rax
	call    string$to_stdoutln
	mov     rdi, r14
	call    heap$free
	; end debug output
end if

	pop     r14 r13 r12 rbx
	epilog
cleartext .status_preface, 'Received: '
cleartext .p200, ' 200 '
.not200:
	; see if this key exists in the item_retries map
	mov	rdi, [item_retries]
	mov	rsi, rbx
	call	stringmap$find_value
	test	eax, eax
	jz	.not200_retry

if defined error_logging
	; error logging/debugging
	mov	rdi, [r12+mimelike_preface_ofs]
	mov	rsi, .errorlog
	call	string$file_append
	mov	rdi, r13
	mov	rsi, .errorlog
	call	string$file_append
	; end logging/debugging
end if

	; r13 is still a string, clear it
	mov	rdi, r13
	call	heap$free
	mov	rdi, .err_not200
	jmp	.error_noretry
.not200_retry:
	; insert this key into the item_retries map to prevent loops
	mov	rdi, [item_retries]
	mov	rsi, rbx
	xor	edx, edx
	call	stringmap$insert_unique
	; r13 is still a string, clear it
	mov	rdi, r13
	call	heap$free

if defined nodelay_retries
	; we need to retry this one
	mov	rdi, rbx
	mov	esi, 1		; update
	call	hnmodel$retrieve
else
	; See the commentary atop as to what/why this is

	; dummy epoll object to deal with our timer
	mov	rdi, .retry_vtable
	mov	esi, 8		; room to hold our string
	call	epoll$new
	mov	[rax+epoll_base_size], rbx
	mov	edi, 30000	; wait 30 seconds and try again
	mov	rsi, rax
	call	epoll$timer_new

end if
	pop	r14 r13 r12 rbx
	epilog
if defined nodelay_retries
else
falign
.retry_timeout:
	; while declared here, this is called wholly external
	mov	rdi, [rdi+epoll_base_size]	; the original string key from the item map
	mov	esi, 1		; update
	call	hnmodel$retrieve
	mov	eax, 1		; destroy the timer and the dummy epoll object
	ret
dalign
.retry_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, epoll$receive, io$error, .retry_timeout
end if
.borked:
	mov	rdi, r13
	call	json$destroy
	mov	rdi, .err_borked
	jmp	.error
.jsonfail:
	mov     rdi, .err_jsonfail
	jmp     .error
.dnsfail:
        mov     rdi, .err_dnsfail
        jmp     .error
.preconnect:
        mov     rdi, .err_preconnect
        jmp     .error
.closed:
        mov     rdi, .err_close
        jmp     .error
.timeout:
        mov     rdi, .err_timeout
.error:
	add	qword [errorcount], 1
	mov	rsi, rbx
	call	string$concat
	mov	r13, rax
	
if defined error_logging
	; error logging/debugging
	mov	rdi, rax
	mov	rsi, .errorlog
	call	string$file_append
	; end logging/debugging
end if

	mov	rdi, r13
	call	hnmodel$statusupdate
	mov	rdi, r13
	call	heap$free
	; we need to retry this one
	mov	rdi, rbx
	mov	esi, 1		; update
	call	hnmodel$retrieve
	pop	r14 r13 r12 rbx
	epilog
.error_noretry:
	add	qword [errorcount], 1
	mov	rsi, rbx
	call	string$concat
	mov	r13, rax

if defined error_logging
	; error logging/debugging
	mov	rdi, rax
	mov	rsi, .errorlog
	call	string$file_append
	; end logging/debugging
end if

	mov	rdi, r13
	call	hnmodel$statusupdate
	mov	rdi, r13
	call	heap$free
	pop	r14 r13 r12 rbx
	epilog
cleartext .err_not200, '!200 Response: '
cleartext .err_borked, 'BORKED: '
cleartext .err_jsonfail, 'JSON parse fail: '
cleartext .err_dnsfail, 'DNS lookup fail: '
cleartext .err_preconnect, 'Preconnect fail: '
cleartext .err_close, 'Connection closed: '
cleartext .err_timeout, 'Timed out: '
if defined error_logging
cleartext .errorlog, 'errors.log'
end if


	; a copy of epoll$default_vtable with our own timer hook
dalign
items_weed_vtable:
	dq	epoll$destroy, epoll$clone, io$connected, epoll$send, epoll$receive, io$error, hnmodel$weed

falign
hnmodel$weed:
	prolog	hnmodel$weed
	; first up, clear our temporary scratch list
	mov	rdi, [items_scratch]
	xor	esi, esi
	call	list$clear
	; for every item in our items map, make sure it exists in our repurposed blacklist object, and if not
	; delete it (but do so AFTER we traverse the list)
	mov	rdi, [items]
	mov	rsi, .eachitem
	call	stringmap$foreach
	; now, for every item in the scratch, delete them
	mov	rdi, [items_scratch]
	mov	rsi, .deleteitem
	call	list$foreach
	; if our itemscratch is not empty, call our updatedcb
	mov	rdi, [items_scratch]
	cmp	qword [_list_size], 0
	je	.skipupdated
	cmp	qword [updatedcb], 0
	je	.skipupdated
	call	qword [updatedcb]
.skipupdated:
	; clear our list for good measure
	mov	rdi, [items_scratch]
	xor	esi, esi
	call	list$clear
	; done, dusted
	xor	eax, eax		; keep our timer going
	epilog
falign
.eachitem:
	; rdi == key, rsi == value from the items list itself, we are at this stage only interested in the key
	push	rbx
	call	string$to_unsigned
	mov	rsi, [items_blacklist]
	mov	rbx, rax
	; so now we have an unsigned key, see if it exists in our blacklists' map
	mov	rdi, [rsi+blacklist_map_ofs]
	mov	rsi, rax
	call	unsignedmap$find_value
	test	eax, eax
	jz	.eachitem_deletequeue
	; otherwise, it was there, so we are happy, return
	pop	rbx
	ret
.eachitem_deletequeue:
	mov	rdi, [items_scratch]
	mov	rsi, rbx
	call	list$push_back
	pop	rbx
	ret

falign
.deleteitem:
	; rdi == unsigned key, we need to KO it from the items map
	; turn rdi back into a string so we can find it
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, [items]
	mov	rsi, rax
	call	stringmap$find
	test	rax, rax
	jz	.deleteitem_borked
	mov	rdi, [items]
	mov	rsi, [rax+_avlofs_key]
	push	qword [rax+_avlofs_key]
	push	qword [rax+_avlofs_value]
	call	stringmap$erase
	pop	rdi
	test	rdi, rdi
	jz	.nojsondestroy
	call	json$destroy
.nojsondestroy:
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	ret
.deleteitem_borked:
	pop	rdi
	call	heap$free
	ret

