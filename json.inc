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
	; json.inc: json "object" support...
	;	a "general purpose" string-based json object container of sorts
	;	that supports the required JSON type vars
	;
	; this is intentionally messy, but gives decent versatility elsewhere in use-case scenarios
	;

json_value = 0
json_array = 1
json_object = 2

json_name_ofs = 0
json_type_ofs = 8		; dd, one of the above contains (json_value, json_array, json_object)
json_value_ofs = 16		; these two share space in the object, but differ in use, so two separate names for them
json_contents_ofs = 16 

json_size = 24


if used json$newvalue | defined include_everything
	; two arguments: rdi == string name, rsi == string value
	; returns new json object in rax, does not assume ownership of either argument
falign
json$newvalue:
	prolog	json$newvalue
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	call	string$copy
	mov	[rsp], rax
	mov	rdi, [rsp+8]
	call	string$copy
	mov	[rsp+8], rax
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_value
	mov	[rax+json_value_ofs], rsi
	add	rsp, 16
	epilog
end if


if used json$newvalue_nocopy | defined include_everything
	; two arguments: rdi == string name, rsi == string value
	; returns new json object in rax, ASSUMES OWNERSHIP OF BOTH name and value arguments
falign
json$newvalue_nocopy:
	prolog	json$newvalue_nocopy
	sub	rsp, 16
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	rsi, [rsp+8]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_value
	mov	[rax+json_value_ofs], rsi
	add	rsp, 16
	epilog
end if

if used json$newarray | defined include_everything
	; single argument: rdi == string name
	; returns new json object in rax, does not assume ownership of the name (copies it)
falign
json$newarray:
	prolog	json$newarray
	push	rdi
	call	string$copy
	mov	[rsp], rax
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_array
	mov	[rsp], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+json_contents_ofs], rax
	pop	rax
	epilog
end if

if used json$newarray_nocopy | defined include_everything
	; single argument: rdi == string name
	; returns new json object in rax, ASSUMES OWNERSHIP of the name
falign
json$newarray_nocopy:
	prolog	json$newarray_nocopy
	push	rdi
	mov	edi, json_size
	call	heap$alloc
	mov	rdx, [rsp]
	mov	[rax+json_name_ofs], rdx
	mov	qword [rax+json_type_ofs], json_array
	mov	[rsp], rax
	call	list$new
	mov	rdi, [rsp]
	mov	[rdi+json_contents_ofs], rax
	pop	rax
	epilog
end if


if used json$newobject | defined include_everything
	; single argument: rdi == string name
	; returns new json object in rax, does not assume ownership of the name (copies it)
falign
json$newobject:
	prolog	json$newobject
	push	rdi
	call	string$copy
	mov	[rsp], rax
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_object
	mov	[rsp], rax
	mov	edi, 1
	call	stringmap$new
	mov	rdi, [rsp]
	mov	[rdi+json_contents_ofs], rax
	pop	rax
	epilog
end if


if used json$newobject_nocopy | defined include_everything
	; single argument: rdi == string name
	; returns new json object in rax, ASSUMES OWNERSHIP of the name
falign
json$newobject_nocopy:
	prolog	json$newobject_nocopy
	push	rdi
	mov	edi, json_size
	call	heap$alloc
	mov	rdx, [rsp]
	mov	[rax+json_name_ofs], rdx
	mov	qword [rax+json_type_ofs], json_object
	mov	[rsp], rax
	mov	edi, 1
	call	stringmap$new
	mov	rdi, [rsp]
	mov	[rdi+json_contents_ofs], rax
	pop	rax
	epilog
end if
	

if used json$copy | defined include_everything
	; single argument: rdi == json object
	; returns a newly copied one in rax (deep copies everything if any)
falign
json$copy:
	prolog	json$copy
	sub	rsp, 24
	mov	[rsp], rdi
	mov	rdi, [rdi+json_name_ofs]
	call	string$copy
	mov	rdi, [rsp]
	mov	[rsp+8], rax
	cmp	dword [rdi+json_type_ofs], json_object
	je	.isobject
	cmp	dword [rdi+json_type_ofs], json_array
	je	.isarray
	; else, it is a value
	mov	rdi, [rdi+json_value_ofs]
	call	string$copy
	mov	[rsp+16], rax
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+16]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_value
	mov	[rax+json_value_ofs], rsi
	add	rsp, 24
	epilog
calign
.isobject:
	call	stringmap$new
	mov	rcx, [rsp]		; get back the original object we are copying
	mov	[rsp+16], rax
	mov	rdx, rax		; our argument for foreach_arg
	mov	rdi, [rcx+json_contents_ofs]
	mov	rsi, .objectcopy
	call	stringmap$foreach_arg
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+16]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_object
	mov	[rax+json_contents_ofs], rsi
	add	rsp, 24
	epilog
	; this is called for every key/value in the contents stringmap, along with rdx as the destination map
calign
.objectcopy:
	sub	rsp, 24
	mov	[rsp], rdi
	mov	[rsp+8], rsi
	mov	[rsp+16], rdx
	call	string$copy
	mov	[rsp], rax
	mov	rdi, [rsp+8]
	call	json$copy
	mov	rdi, [rsp+16]
	mov	rsi, [rsp]		; key
	mov	rdx, rax		; value
	call	stringmap$insert
	add	rsp, 24
	ret
calign
.isarray:
	call	list$new
	mov	rcx, [rsp]		; get back the original object we are copying
	mov	[rsp+16], rax
	mov	rdx, rax		; our argument for foreach_arg
	mov	rdi, [rcx+json_contents_ofs]
	mov	rsi, .arraycopy
	call	list$foreach_arg
	mov	edi, json_size
	call	heap$alloc
	mov	rdi, [rsp+8]
	mov	rsi, [rsp+16]
	mov	[rax+json_name_ofs], rdi
	mov	qword [rax+json_type_ofs], json_array
	mov	[rax+json_contents_ofs], rsi
	add	rsp, 24
	epilog
	; this is called for every item in the contents list/array, along with rsi as the destination new list
calign
.arraycopy:
	push	rsi
	call	json$copy
	pop	rdi
	mov	rsi, rax
	call	list$push_back
	ret
end if
	
json_name_ofs = 0
json_type_ofs = 8		; dd, one of the above contains (json_value, json_array, json_object)
json_value_ofs = 16		; these two share space in the object, but differ in use, so two separate names for them
json_contents_ofs = 16 

if used json$destroy | defined include_everything
	; single argument: rdi == json object
	; this cleans everything up depending on type, and heap$free's rdi
falign
json$destroy:
	prolog	json$destroy
	push	rdi
	mov	rdi, [rdi+json_name_ofs]
	call	heap$free
	mov	rdi, [rsp]
	mov	edx, dword [rdi+json_type_ofs]
	mov	ecx, json_object
	mov	eax, json_array
	cmp	edx, ecx
	je	.isobject
	cmp	edx, eax
	je	.isarray
	; else, it is a value
	mov	rdi, [rdi+json_value_ofs]
	call	heap$free
	pop	rdi
	call	heap$free
	epilog
calign
.isobject:
	mov	rdi, [rdi+json_contents_ofs]
	push	rdi
	mov	rsi, .objectcleaner
	call	stringmap$clear
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	epilog
	; this gets called for every key/value in the object's contents map, free the string, and json$destroy the value
calign
.objectcleaner:
	push	rdi
	mov	rdi, rsi
	call	json$destroy
	pop	rdi
	call	heap$free
	ret
calign
.isarray:
	mov	rdi, [rdi+json_contents_ofs]
	push	rdi
	mov	rsi, json$destroy
	call	list$clear
	pop	rdi
	call	heap$free
	pop	rdi
	call	heap$free
	epilog
end if


if used json$appendchild | defined include_everything
	; two arguments: rdi == json object, rsi == child object to add to this one
	; NOTE: this only makes sense (obviously) for json_array and json_object types, and will _do nothing_ if type is json_value
	; ALSO NOTE: this does not make a _new copy_ of the child passed in rsi, tosses it straight in (and thus assumes ownership)
falign
json$appendchild:
	prolog	json$appendchild
	cmp	dword [rdi+json_type_ofs], json_value
	je	.pebcak
	cmp	dword [rdi+json_type_ofs], json_object
	je	.isobject
	; else, it is an array
	mov	rdi, [rdi+json_contents_ofs]	; load up the contents list
	call	list$push_back
	epilog
calign
.isobject:
	; we need a copy of the child object's name to use as a key for our stringmap
	push	rdi rsi
	mov	rdi, [rsi+json_name_ofs]
	call	string$copy
	pop	rsi rdi
	mov	rdi, [rdi+json_contents_ofs]	; load up the contents stringmap
	mov	rdx, rsi			; value
	mov	rsi, rax			; key
	call	stringmap$insert
	epilog
calign
.pebcak:
	epilog
end if


if used json$tostring | defined include_everything
	; single argument: rdi == json object
	; returns new string representation in JSON form/encoding in rax
json$tostring:
	prolog	json$tostring
	sub	rsp, 16
	mov	[rsp], rdi
	call	buffer$new
	mov	[rsp+8], rax
	mov	rdi, [rsp]
	mov	rsi, rax
	call	.appendtobuffer
	; so now, this object and all its descendents (if any) were converted to UTF32 in our buffer
	; now we need to construct a string from it
	mov	rdx, [rsp+8]	; our buffer
	mov	rdi, [rdx+buffer_itself_ofs]
	mov	rsi, [rdx+buffer_length_ofs]
	call	string$from_utf32
	mov	[rsp], rax
	mov	rdi, [rsp+8]
	call	buffer$destroy
	mov	rax, [rsp]
	add	rsp, 16
	epilog
	; so this is re-entrantly called for every object... rdi == json object, rsi == destination buffer
calign
.appendtobuffer:
	; TODO: none of my stuff uses extended UTF16 as name characters, this won't encode properly if the UTF16 is enabled, and hte name itself contains >0x10000 codes
	push	rsi rdi
	mov	rdx, [rdi+json_name_ofs]
	cmp	qword [rdx], 0
	je	.noname
	mov	rdi, rsi		; destination buffer
	mov	rsi, [rdx]		; string length in characters
	add	rsi, 3			; space for leading/trailing quotes and a colon
	shl	rsi, 2			; in utf32
	call	buffer$reserve
	
	mov	rdi, [rsp]		; our object
	mov	rsi, [rsp+8]		; destination buffer
	mov	rdx, [rsi+buffer_endptr_ofs]	; endptr to the buffer
	mov	rcx, [rdi+json_name_ofs]
	mov	dword [rdx], '"'
if string_bits = 32
	mov	rdi, rdx
	add	rdi, 4			;
	mov	rsi, rcx
	add	rsi, 8
	mov	rdx, [rcx]
	shl	rdx, 2
	call	memcpy
else
	mov	rsi, rdx
	add	rsi, 4
	mov	rdi, rcx
	call	string$to_utf32
end if
	; add our close quote and colon
	mov	rdi, [rsp]		; our object
	mov	rsi, [rsp+8]		; destination buffer
	mov	rdx, [rsi+buffer_endptr_ofs]	; endptr to the buffer
	mov	rcx, [rdi+json_name_ofs]
	add	rdx, 4
	mov	r8, [rcx]
	shl	r8, 2
	add	rdx, r8
	add	r8, 12
	mov	dword [rdx], '"'
	mov	dword [rdx+4], ':'
	; bytes to add is in r8 nice and neatlike
	add	[rsi+buffer_endptr_ofs], r8
	add	[rsi+buffer_length_ofs], r8
calign
.noname:
	; either there was no name, or we already added it quoted with a trailing colon
	cmp	dword [rdi+json_type_ofs], json_object
	je	.isobject
	cmp	dword [rdi+json_type_ofs], json_array
	je	.isarray
	; else, it is a value
	; because we don't actually do separate types for json values (null, boolean, etc)
	; we do a bit of cheating here as well for wellknown types... NOTE: depending on the JS enviro
	; it is possible to get a normal javascript environment to also incorrectly do these... and it has never caused me any problems
	; since all of mine still end up the same regardless of their "origin/base" type...
	; IN OTHER WORDS: null, true, false get placed in here unquoted, similar to numeric-only ones
	mov	rsi, [rdi+json_value_ofs]
	mov	rdi, .str_null
	call	string$equals
	test	eax, eax
	jnz	.value_unquoted
	mov	rdx, [rsp]		; our object
	mov	rsi, [rdx+json_value_ofs]
	mov	rdi, .str_true
	call	string$equals
	test	eax, eax
	jnz	.value_unquoted
	mov	rdx, [rsp]		; our object
	mov	rsi, [rdx+json_value_ofs]
	mov	rdi, .str_false
	call	string$equals
	test	eax, eax
	jnz	.value_unquoted
	; next up, see if it is a number
	mov	rdx, [rsp]
	mov	rdi, [rdx+json_value_ofs]
	call	string$isnumber
	test	eax, eax
	jnz	.value_unquoted
	; otherwise, quote and encode the value
	mov	rdx, [rsp]		; our object
	mov	rdi, [rsp+8]		; our destination buffer
	mov	rcx, [rdx+json_value_ofs]
	mov	rsi, [rcx]
	shl	rsi, 4			; *16 to be absolutely certain there is enough room in our buffer (x4 for chars, x4 again for UTF32)
	add	rsi, 16			; for quotes on either end + 2 reserve chars
	call	buffer$reserve
	mov	rdi, [rsp]		; our object
	mov	rsi, [rsp+8]		; our destination buffer
	mov	rdx, [rsi+buffer_endptr_ofs]
	mov	rcx, [rdi+json_value_ofs]
	mov	r8, [rcx]		; length of the string in characters
	add	rcx, 8			; rcx now pointing to the start of the actual string contents
	mov	dword [rdx], '"'
	mov	r9d, 1			; how many characters we have written
	add	rdx, 4
calign
.quotedloop:
	test	r8, r8
	jz	.endquotedloop
if string_bits = 32
	mov	eax, dword [rcx]
	add	rcx, 4
	sub	r8, 1
else
	movzx	eax, word [rcx]
	add	rcx, 2
	sub	r8, 1
end if
	cmp	eax, 9
	je	.quotedtab
	cmp	eax, 13
	je	.quotedcr
	cmp	eax, 10
	je	.quotedlf
	cmp	eax, '"'
	je	.quotedquote
	cmp	eax, '\'
	je	.quotedbackslash
	cmp	eax, 32
	jb	.quotedhexval
	mov	dword [rdx], eax
	add	r9, 1
	add	rdx, 4
	jmp	.quotedloop
cleartext .str_null, 'null'
cleartext .str_true, 'true'
cleartext .str_false, 'false'
calign
.value_unquoted:
	mov	rdx, [rsp]		; our object
	mov	rdi, [rsp+8]		; our destination buffer
	mov	rcx, [rdx+json_value_ofs]
	mov	rsi, [rcx]
	shl	rsi, 2			; in bytes
	add	rsi, 8			; make sure there is always room for +2 chars
	call	buffer$reserve
	mov	rdi, [rsp]		; our object
	mov	rsi, [rsp+8]		; our destination buffer
	mov	rdx, [rsi+buffer_endptr_ofs]
	mov	rcx, [rdi+json_value_ofs]
	mov	r8, [rcx]		; length of the string in characters
	add	rcx, 8			; rcx now pointing to the start of the actual string contents
	xor	r9d, r9d
calign
.unquotedloop:
	test	r8, r8
	jz	.endunquotedloop
if string_bits = 32
	mov	eax, dword [rcx]
	add	rcx, 4
	sub	r8, 1
else
	movzx	eax, word [rcx]
	add	rcx, 2
	sub	r8, 1
end if
	mov	dword [rdx], eax
	add	r9, 1
	add	rdx, 4
	jmp	.unquotedloop
calign
.endunquotedloop:
	shl	r9, 2
	add	[rsi+buffer_endptr_ofs], r9
	add	[rsi+buffer_length_ofs], r9	; append_nocopy
	pop	rdi rsi
	ret
calign
.quotedtab:
	mov	dword [rdx], '\'
	mov	dword [rdx+4], 't'
	add	rdx, 8
	add	r9, 2
	jmp	.quotedloop
calign
.quotedcr:
	mov	dword [rdx], '\'
	mov	dword [rdx+4], 'r'
	add	rdx, 8
	add	r9, 2
	jmp	.quotedloop
calign
.quotedlf:
	mov	dword [rdx], '\'
	mov	dword [rdx+4], 'n'
	add	rdx, 8
	add	r9, 2
	jmp	.quotedloop
calign
.quotedquote:
	mov	dword [rdx], '\'
	mov	dword [rdx+4], '"'
	add	rdx, 8
	add	r9, 2
	jmp	.quotedloop
calign
.quotedbackslash:
	mov	dword [rdx], '\'
	mov	dword [rdx+4], '\'
	add	rdx, 8
	add	r9, 2
	jmp	.quotedloop
calign
.quotedhexval:
	; eax < 32, so we need to encode this as a \uXXXX
	mov	dword [rdx], '\'
	mov	dword [rdx+4], 'u'
	mov	dword [rdx+8], '0'
	mov	dword [rdx+12], '0'
	push	r12
	mov	r10d, eax
	shr	r10d, 4
	mov	r11d, '0'
	mov	r12d, '1'
	test	r10d, r10d
	cmovz	r10d, r11d
	cmovnz	r10d, r12d
	mov	dword [rdx+16], r10d
	mov	r10d, eax
	and	r10d, 0xf
	mov	r11d, r10d
	mov	r12d, r10d
	add	r11d, '0'
	add	r12d, 'a'
	cmp	r10d, 10
	cmovb	r10d, r11d
	cmovae	r10d, r12d
	mov	dword [rdx+20], r10d
	pop	r12
	add	rdx, 24
	add	r9, 6
	jmp	.quotedloop
calign
.endquotedloop:
	mov	dword [rdx], '"'
	add	r9, 1
	shl	r9, 2
	add	rdx, 4
	add	[rsi+buffer_endptr_ofs], r9
	add	[rsi+buffer_length_ofs], r9	; append_nocopy
	pop	rdi rsi
	ret
calign
.isobject:
	mov	rdx, [rdi+json_contents_ofs]
	mov	rcx, [rdx+_avlofs_right]	; node count in the contents map
	mov	rdi, rsi			; our destination buffer
	mov	rsi, rcx
	add	rsi, 2
	shl	rsi, 2
	call	buffer$reserve
	
	mov	r8, [rsp+8]			; our destination buffer
	mov	r9, [r8+buffer_endptr_ofs]
	mov	dword [r9], '{'
	add	qword [r8+buffer_endptr_ofs], 4
	add	qword [r8+buffer_length_ofs], 4

	mov	rcx, [rsp]			; our object
	mov	rdi, [rcx+json_contents_ofs]	; our contents stringmap
	mov	rsi, .objectappend
	mov	rdx, [rsp+8]			; our destination buffer
	call	stringmap$foreach_arg

	mov	rdi, [rsp]			; our object
	mov	rsi, [rdi+json_contents_ofs]
	mov	rcx, [rsi+_avlofs_right]	; node count in the contents map
	test	rcx, rcx
	jz	.objectnochildren
	mov	r8, [rsp+8]
	mov	r9, [r8+buffer_endptr_ofs]
	sub	r9, 4
	mov	dword [r9], '}'
	pop	rdi rsi
	ret
calign
.objectnochildren:
	mov	r8, [rsp+8]			; our destination buffer
	mov	r9, [r8+buffer_endptr_ofs]
	mov	dword [r9], '}'
	add	qword [r8+buffer_endptr_ofs], 4
	add	qword [r8+buffer_length_ofs], 4
	pop	rdi rsi
	ret
calign
.isarray:
	mov	rdx, [rdi+json_contents_ofs]	; our contents list
	mov	rcx, [rdx]			; the list size (in items)
	mov	rdi, rsi			; our destination buffer
	mov	rsi, rcx			; how many characters we need
	add	rsi, 2
	shl	rsi, 2
	call	buffer$reserve
	mov	r8, [rsp+8]			; our destination buffer
	mov	r9, [r8+buffer_endptr_ofs]
	mov	dword [r9], '['
	add	qword [r8+buffer_endptr_ofs], 4
	add	qword [r8+buffer_length_ofs], 4

	mov	rcx, [rsp]		; our object
	mov	rdi, [rcx+json_contents_ofs]	; our contents list
	mov	rsi, .arrayappend
	mov	rdx, [rsp+8]
	call	list$foreach_arg

	mov	rdi, [rsp]			; our object
	mov	rsi, [rdi+json_contents_ofs]
	mov	rcx, [rsi]			; the list size itself
	test	rcx, rcx
	jz	.nochildren
	mov	r8, [rsp+8]			; our destination buffer
	mov	r9, [r8+buffer_endptr_ofs]
	sub	r9, 4
	mov	dword [r9], ']'
	pop	rdi rsi
	ret
calign
.nochildren:
	mov	r8, [rsp+8]			; our destination buffer
	mov	r9, [r8+buffer_endptr_ofs]
	mov	dword [r9], ']'
	add	qword [r8+buffer_endptr_ofs], 4
	add	qword [r8+buffer_length_ofs], 4
	pop	rdi rsi
	ret
calign
.arrayappend:
	push	rsi
	call	.appendtobuffer
	pop	rsi
	mov	r8, [rsi+buffer_endptr_ofs]
	mov	dword [r8], ','
	add	qword [rsi+buffer_endptr_ofs], 4
	add	qword [rsi+buffer_length_ofs], 4
	ret
	; this one gets called with the string key in rdi, our json object in rsi, and our destination buffer in rdx
calign
.objectappend:
	mov	rdi, rsi
	mov	rsi, rdx
	push	rdx
	call	.appendtobuffer
	pop	rdx
	mov	r8, [rdx+buffer_endptr_ofs]
	mov	dword [r8], ','
	add	qword [rdx+buffer_endptr_ofs], 4
	add	qword [rdx+buffer_length_ofs], 4
	ret
end if


if used json$stringvalue | defined include_everything
	; single argument in rdi: json object
	; returns the string value in rax (if and only if the type of the object is json_value)
	; returns zero in rax if it wasn't a json_value
falign
json$stringvalue:
	prolog	json$stringvalue
	cmp	dword [rdi+json_type_ofs], json_value
	jne	.zeroret
	mov	rax, [rdi+json_value_ofs]
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if

if used json$name | defined include_everything
	; single argument in rdi: json object
	; returns the name in rax
	; NOTE: this is just here for reference, since you can get the name out by [rdi] anyway
falign
json$name:
	prolog	json$name
	mov	rax, [rdi+json_name_ofs]
	epilog
end if

if used json$arraylength | defined include_everything
	; single argument in rdi: json object (which must be a json_array)
	; returns the length of the array in rax
falign
json$arraylength:
	prolog	json$arraylength
	cmp	dword [rdi+json_type_ofs], json_array
	jne	.zeroret
	mov	rsi, [rdi+json_contents_ofs]
	mov	rax, [rsi]		; list_size offset is 0
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if

if used json$valueat | defined include_everything
	; two arguments: json object (which must be a json_array) in rdi, index in rsi
	; returns the json_object at the specified index (NOTE: this has to _walk_ the list, you sure you want to be using this?)
	; (will return null if not a json_array, or index invalid)
falign
json$valueat:
	prolog	json$valueat
	cmp	dword [rdi+json_type_ofs], json_array
	jne	.zeroret
	mov	rsi, [rdi+json_contents_ofs]
	mov	rdx, [rsi+8]		; list_first offset is 8
	test	rdx, rdx
	jz	.zeroret
	test	rsi, rsi
	jnz	.walk
	mov	rax, [rdx+_list_valueofs]
	epilog
calign
.walk:
	mov	rdx, [rdx+_list_nextofs]
	test	rdx, rdx
	jz	.zeroret
	sub	rsi, 1
	jnz	.walk
	mov	rax, [rdx+_list_valueofs]
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if


if used json$foreach | defined include_everything
	; two arguments: json object (which can either be json_array or json_object), function to call in rsi
	; NOTE: json_array foreach passes only the json object in rdi
	;       json_object foreach passes the name in rdi, and the object in rsi
falign
json$foreach:
	prolog	json$foreach
	cmp	dword [rdi+json_type_ofs], json_value
	je	.bork
	cmp	dword [rdi+json_type_ofs], json_array
	je	.isarray
	; else, it is an object
	mov	rdi, [rdi+json_contents_ofs]
	call	stringmap$foreach
	epilog
calign
.isarray:
	mov	rdi, [rdi+json_contents_ofs]
	call	list$foreach
	epilog
calign
.bork:
	epilog
end if

if used json$foreach_arg | defined include_everything
	; three arguments: json object (which can either be json_array or json_object), function to call in rsi, arbitrary arg passed in rdx
	; NOTE: json_array foreach_arg passes the json object in rdi and the arbitrary arg in rsi
	;       json_object foreach_arg passes the name in rdi, object in rsi, and the arbitrary arg in rdx
falign
json$foreach_arg:
	prolog	json$foreach_arg
	cmp	dword [rdi+json_type_ofs], json_value
	je	.bork
	cmp	dword [rdi+json_type_ofs], json_array
	je	.isarray
	; else, it is an object
	mov	rdi, [rdi+json_contents_ofs]
	call	stringmap$foreach_arg
	epilog
calign
.isarray:
	mov	rdi, [rdi+json_contents_ofs]
	call	list$foreach_arg
	epilog
calign
.bork:
	epilog
end if

if used json$hasvaluebyname | defined include_everything
	; two arguments: json object (which must be a json_object) in rdi, string name in rsi to check for
	; returns bool in eax
falign
json$hasvaluebyname:
	prolog	json$hasvaluebyname
	cmp	dword [rdi+json_type_ofs], json_object
	jne	.zeroret
	mov	rdi, [rdi+json_contents_ofs]
	call	stringmap$find
	test	rax, rax
	jz	.zeroret
	mov	eax, 1
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if


if used json$getvaluebyname | defined include_everything
	; two arguments: json object (which must be a json_object) in rdi, string name in rsi to get
	; returns json object in rax or null if kakked
falign
json$getvaluebyname:
	prolog	json$getvaluebyname
	cmp	dword [rdi+json_type_ofs], json_object
	jne	.zeroret
	mov	rdi, [rdi+json_contents_ofs]
	call	stringmap$find
	test	rax, rax
	jz	.zeroret
	mov	rax, [rax+_avlofs_value]
	epilog
calign
.zeroret:
	xor	eax, eax
	epilog
end if




if used json$parse_object | defined include_everything
	; two arguments: string to parse in rdi, bool in esi as to whether or not to expect a leading function name
	; returns json object in rax, or null on parse error
falign
json$parse_object:
	prolog	json$parse_object
	push	rbx r12 r13 r14 r15
	mov	r12, rdi
	mov	r15, rsi
	call	buffer$new
	mov	rbx, rax
	mov	rdi, r12
	xor	esi, esi
	cmp	qword [rdi], 0
	je	.nullret
	call	string$skip_whitespace	; preserves rdi, ret in rax
	cmp	rax, [rdi]
	jae	.nullret

	mov	r12, rdi		; save our string
	mov	r13, [rdi]		; its length in characters
	mov	r14, rax		; our starting position

	test	r15d, r15d
	jz	.noleadingfunctionname
	call	.parse_string		; this modifies r14
	mov	r15, rax		; object name saved/stored
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.nullret_clearobjectname
	mov	r14, rax
	; check the character at our new pos to see if it is a colon, and if so, skip it and any whitespace that follows
if string_bits = 32
	cmp	dword [r12+r14*4+8], ':'
else
	cmp	word [r12+r14*2+8], ':'
end if
	jne	.noleadingfunctionname
	add	r14, 1
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.nullret_clearobjectname
	mov	r14, rax
calign
.noleadingfunctionname:
	; so we may or may not have an object name in r15, next task is to parse the object
	call	.parse_object
	test	rax, rax
	jnz	.retokay_checkname
	test	r15, r15
	jz	.nullret
calign
.nullret_clearobjectname:
	mov	rdi, r15
	call	heap$free
	mov	rdi, rbx
	call	buffer$destroy
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	epilog
calign
.nullret:
	mov	rdi, rbx
	call	buffer$destroy
	pop	r15 r14 r13 r12 rbx
	xor	eax, eax
	epilog
calign
.retokay_checkname:
	test	r15, r15
	jz	.retokay
	; else, save our object return
	mov	r12, rax
	mov	rdi, [rax+json_name_ofs]
	call	heap$free
	mov	rax, r12
	mov	[rax+json_name_ofs], r15
calign
.retokay:
	mov	r14, rax
	mov	rdi, rbx
	call	buffer$destroy
	mov	rax, r14
	pop	r15 r14 r13 r12 rbx
	epilog
calign
.parse_string:
	; we'll return a string in rax, can be quoted or unquoted
	; there is a buffer sitting in wait in rbx for our parse operation, reset it first
	mov	rdi, rbx
	call	buffer$reset
	; pos is in r14, length of string in r13, string itself in r12
	; it is assumed on entry that r14 < r13
if string_bits = 32
	cmp	dword [r12+r14*4+8], '"'
else
	cmp	word [r12+r14*2+8], '"'
end if
	jne	.parse_string_unquoted
	; else, we have a quoted string
	add	r14, 1
calign
.parse_string_quotedloop:
	; make sure we have enough buffer room:
	mov	rcx, [rbx+buffer_size_ofs]
	sub	rcx, qword [rbx+buffer_length_ofs]
	cmp	rcx, 32
	jae	.parse_string_quoted_nogrow
	mov	rdi, rbx
	mov	esi, 4096
	call	buffer$reserve
calign
.parse_string_quoted_nogrow:
	cmp	r14, r13
	jae	.parse_string_doreturn
if string_bits = 32
	mov	eax, [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, '"'
	je	.parse_string_quoted_close
	mov	rsi, .parse_string_quotedloop	; save our loop entry
	cmp	eax, '\'
	je	.parse_string_escaped
	; else, add it to our buffer
	mov	rdx, [rbx+buffer_endptr_ofs]
if string_bits = 32
	mov	dword [rdx], eax
	add	qword [rbx+buffer_endptr_ofs], 4
	add	qword [rbx+buffer_length_ofs], 4
else
	mov	word [rdx], ax
	add	qword [rbx+buffer_endptr_ofs], 2
	add	qword [rbx+buffer_length_ofs], 2
end if
	add	r14, 1
	jmp	.parse_string_quotedloop
calign
.parse_string_escaped:
	add	r14, 1				; skip the \
	cmp	r14, r13
	jae	.parse_string_doreturn
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, '"'
	je	.parse_string_escaped_addchar
	cmp	eax, '\'
	je	.parse_string_escaped_addchar
	cmp	eax, '/'
	je	.parse_string_escaped_addchar
	cmp	eax, 'b'
	je	.parse_string_escaped_backspace
	mov	ecx, 13
	cmp	eax, 'f'
	cmove	eax, ecx
	je	.parse_string_escaped_addchar
	cmp	eax, 'r'
	cmove	eax, ecx
	je	.parse_string_escaped_addchar
	mov	ecx, 10
	cmp	eax, 'n'
	cmove	eax, ecx
	je	.parse_string_escaped_addchar
	mov	ecx, 9
	cmp	eax, 't'
	cmove	eax, ecx
	je	.parse_string_escaped_addchar
	cmp	eax, 'u'
	je	.parse_string_escaped_hexcode
	; otherwise, we have nfi what this is
	add	r14, 1
	jmp	rsi
calign
.parse_string_escaped_addchar:
	mov	rdx, [rbx+buffer_endptr_ofs]
if string_bits = 32
	mov	dword [rdx], eax
	add	qword [rbx+buffer_endptr_ofs], 4
	add	qword [rbx+buffer_length_ofs], 4
else
	mov	word [rdx], ax
	add	qword [rbx+buffer_endptr_ofs], 2
	add	qword [rbx+buffer_length_ofs], 2
end if
	add	r14, 1
	jmp	rsi
calign
.parse_string_escaped_hexcode:
	; we got a \u, which means we have 4 hex digits of a utf16 code?
	add	r14, 1
	mov	rcx, r13
	sub	rcx, r14
	cmp	rcx, 4
	jb	.parse_string_doreturn
	; we need to construct a string with a proper lenght prefix, we can use our buffer for that, even though it won't be aligned
	mov	rdi, [rbx+buffer_endptr_ofs]
	mov	qword [rdi], 4
	push	rsi
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
	mov	ecx, dword [r12+r14*4+12]
	mov	edx, dword [r12+r14*4+16]
	mov	r8d, dword [r12+r14*4+20]
	mov	dword [rdi+8], eax
	mov	dword [rdi+12], ecx
	mov	dword [rdi+16], edx
	mov	dword [rdi+24], edx
	mov	esi, 16
	call	string$to_int_radix
else
	movzx	eax, word [r12+r14*2+8]
	movzx	ecx, word [r12+r14*2+10]
	movzx	edx, word [r12+r14*2+12]
	movzx	r8d, word [r12+r14*2+14]
	mov	word [rdi+8], ax
	mov	word [rdi+10], cx
	mov	word [rdi+12], dx
	mov	word [rdi+14], r8w
	mov	esi, 16
	call	string$to_int_radix
end if
	add	r14, 3				; 3 here because addchar adds one as well
	; so now we have an integer value (hopefully in eax)
	pop	rsi
	jmp	.parse_string_escaped_addchar
calign
.parse_string_escaped_backspace:
	add	r14, 1
	cmp	qword [rbx+buffer_length_ofs], 0
	je	.parse_string_escaped_backspace_next
if string_bits = 32
	sub	qword [rbx+buffer_endptr_ofs], 4
	sub	qword [rbx+buffer_length_ofs], 4
else
	sub	qword [rbx+buffer_endptr_ofs], 2
	sub	qword [rbx+buffer_length_ofs], 2
end if
calign
.parse_string_escaped_backspace_next:
	jmp	rsi
calign
.parse_string_unquoted:
	mov	rcx, [rbx+buffer_size_ofs]
	sub	rcx, qword [rbx+buffer_length_ofs]
	cmp	rcx, 32
	jae	.parse_string_unquoted_nogrow
	mov	rdi, rbx
	mov	esi, 4096
	call	buffer$reserve
calign
.parse_string_unquoted_nogrow:
	cmp	r14, r13
	jae	.parse_string_doreturn
if string_bits = 32
	mov	eax, [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	; determine if eax is a space, and if so, skip it and return
	cmp	eax, 32
	ja	.parse_string_unquoted_notspace
	mov	ecx, eax
	sub	ecx, 1
	mov	r8d, 1
	shl	r8d, cl
	test	r8d, 2147488512
	jz	.parse_string_unquoted_notspace
	; else, we hit a space
	add	r14, 1
	jmp	.parse_string_doreturn
calign
.parse_string_unquoted_notspace:
	mov	rsi, .parse_string_unquoted
	cmp	eax, '\'
	je	.parse_string_escaped
	; else, add it to our buffer
	mov	rdx, [rbx+buffer_endptr_ofs]
if string_bits = 32
	mov	dword [rdx], eax
	add	qword [rbx+buffer_endptr_ofs], 4
	add	qword [rbx+buffer_length_ofs], 4
else
	mov	word [rdx], ax
	add	qword [rbx+buffer_endptr_ofs], 2
	add	qword [rbx+buffer_length_ofs], 2
end if
	add	r14, 1
	jmp	.parse_string_unquoted

calign
.parse_string_quoted_close:
	add	r14, 1				; skip the close quote
	; convert the buffer contents in rbx to a string and return
	mov	rdi, [rbx+buffer_itself_ofs]
	mov	rsi, [rbx+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	ret
calign
.parse_string_doreturn:
	; convert the buffer contents in rbx to a string and return
	mov	rdi, [rbx+buffer_itself_ofs]
	mov	rsi, [rbx+buffer_length_ofs]
if string_bits = 32
	call	string$from_utf32
else
	call	string$from_utf16
end if
	ret

calign
.parse_object:
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_object_nullret
	mov	r14, rax
	; make sure the character we are sitting on is an openbrace, nullret if not
if string_bits = 32
	cmp	dword [r12+r14*4+8], '{'
else
	cmp	word [r12+r14*2+8], '{'
end if
	jne	.parse_object_nullret
	; otherwise, we need a new object
	call	string$new
	mov	rdi, rax
	call	json$newobject_nocopy
	sub	rsp, 16
	mov	[rsp], rax		; our [rsp] == our newly created json object (with a 0 length name)
	add	r14, 1
calign
.parse_object_loop:
	cmp	r14, r13
	jae	.parse_object_nullret_cleanit
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_object_nullret_cleanit
	mov	r14, rax
	; check to see if we are an empty object (char at r14 openbrace?)
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, '}'
	je	.parse_object_emptyobject
	cmp	eax, '"'
	jne	.parse_object_nullret_cleanit
	; else, we have a variable name, quoted
	call	.parse_string
	; we now have a string in rax that is our vname
	mov	[rsp+8], rax
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_object_nullret_cleanwithname
	mov	r14, rax
	; make sure the next character we are sitting on is a :
if string_bits = 32
	cmp	dword [r12+r14*4+8], ':'
else
	cmp	word [r12+r14*2+8], ':'
end if
	jne	.parse_object_nullret_cleanwithname
	add	r14, 1
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_object_nullret_cleanwithname
	mov	r14, rax
	; now we can need to parse the actual value, which needs our arguments:
	mov	rdi, [rsp]		; the json object
	mov	rsi, [rsp+8]		; the value name
					; .parse_value swallows the vname (assumes ownership of it)
					; so afterwards, all we are concerned with is the object in [rsp]
	call	.parse_value		; returns bool in eax as to whether it succeeded or not
	test	eax, eax
	jz	.parse_object_nullret_cleanit
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_object_nullret_cleanit
	mov	r14, rax
	; character here can be either a close brace or a comma, anything else == death on a stick
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, '}'
	je	.parse_object_emptyobject	; not really empty, but does the same thing we need
	cmp	eax, ','
	jne	.parse_object_nullret_cleanit
	add	r14, 1
	jmp	.parse_object_loop
calign
.parse_object_emptyobject:
	add	r14, 1
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	mov	r14, rax
	mov	rax, [rsp]
	add	rsp, 16
	ret
calign
.parse_object_nullret_cleanit:
	mov	rdi, [rsp]
	add	rsp, 16
	call	json$destroy
	xor	eax, eax
	ret
calign
.parse_object_nullret_cleanwithname:
	mov	rdi, [rsp]
	call	json$destroy
	mov	rdi, [rsp+8]
	call	heap$free
	add	rsp, 16
	xor	eax, eax
	ret
calign
.parse_object_nullret:
	xor	eax, eax
	ret



	; this one gets two "proper" args: rdi == the json object, rsi == the string of our value name
	; string goods in r12..r14 are valid
	; we assume ownership of the string in rsi (meaning no matter what, we must clean it up or place/use it)
	; we return bool in eax as to whether we succeeded or not
calign
.parse_value:
	push	rsi rdi
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, '"'		; quoted string
	je	.parse_value_quoted
	cmp	eax, '.'		; this is (from what I gather) not from spec, but i have seen in the wild: "varname":.5
	je	.parse_value_number
	cmp	eax, '-'
	je	.parse_value_number
	cmp	eax, '0'
	jb	.parse_value_notnumber
	cmp	eax, '9'
	jbe	.parse_value_number
calign
.parse_value_notnumber:
	cmp	eax, '{'
	je	.parse_value_object
	cmp	eax, '['
	je	.parse_value_array
	cmp	eax, 't'		; true
	je	.parse_value_true
	cmp	eax, 'f'		; false
	je	.parse_value_false
	cmp	eax, 'n'		; null
	je	.parse_value_null
	cmp	eax, 'E'		; again, not spec, but i have confirmed (broken-assed) behaviour in the wild of: "varname":E
	je	.parse_value_weirde
calign
.parse_value_kakkedret:
	mov	rdi, [rsp+8]
	call	heap$free		; free our string
	xor	eax, eax		; false return
	pop	rdi rsi
	ret
calign
.parse_value_object:
	call	.parse_object
	test	rax, rax
	jz	.parse_value_kakkedret	; will free the string
	mov	rdi, [rax+json_name_ofs]
	mov	rsi, [rsp+8]		; the vname
	mov	[rax+json_name_ofs], rsi
	mov	[rsp+8], rax		; save the object temporarily
	call	heap$free		; free the previous name
	mov	rdi, [rsp]		; the parent object
	mov	rsi, [rsp+8]
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret
calign
.parse_value_array:
	add	r14, 1
	cmp	r14, r13
	jae	.parse_value_kakkedret
	; create a new json array object, give it the vname
	mov	rdi, [rsp+8]
	call	json$newarray_nocopy
	mov	[rsp+8], rax		; save our array object
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild	; add it to the parent object
	; check for the special case if an empty array
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, ']'
	je	.parse_value_array_empty
	; loop through the array contents
calign
.parse_value_array_loop:
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_value_array_kakked
	; we need a new empty string for the arg to .parse_value
	call	string$new
	; reentrantly call .parse_value, with the parent arg set to the array
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	.parse_value
	test	eax, eax
	jz	.parse_value_array_kakked
	mov	rdi, r12
	mov	rsi, r14
	call	string$skip_whitespace
	cmp	rax, r13
	jae	.parse_value_array_kakked
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, ','
	je	.parse_value_array_nextitem
	cmp	eax, ']'
	jne	.parse_value_array_kakked
	add	r14, 1
	pop	rdi rsi
	mov	eax, 1
	ret
calign
.parse_value_array_nextitem:
	add	r14, 1
	jmp	.parse_value_array_loop
calign
.parse_value_array_empty:
	add	r14, 1
	pop	rdi rsi
	mov	eax, 1
	ret
calign
.parse_value_array_kakked:
	; now, because we already consumed vname, and we already added our array to the parent object
	; we don't need to do anything other than just return false
	pop	rdi rsi
	xor	eax, eax
	ret
calign
.parse_value_quoted:
	call	.parse_string
	; string is now in rax of its actual value, vname is in [rsp+8], and the object is in [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret
calign
.parse_value_number:
	mov	rdi, r12		; setup the string parm for our substr call
	mov	rsi, r14		; save the starting position
	add	r14, 1
	; now walk forward while we have what looks like numeric goods
calign
.parse_value_number_loop:
	cmp	r14, r13
	jae	.parse_value_number_done
if string_bits = 32
	mov	eax, dword [r12+r14*4+8]
else
	movzx	eax, word [r12+r14*2+8]
end if
	cmp	eax, '-'
	je	.parse_value_number_next
	cmp	eax, '.'
	je	.parse_value_number_next
	cmp	eax, 'e'
	je	.parse_value_number_next
	cmp	eax, 'E'
	je	.parse_value_number_next
	cmp	eax, '+'
	je	.parse_value_number_next
	cmp	eax, '0'
	jb	.parse_value_number_done
	cmp	eax, '9'
	ja	.parse_value_number_done
calign
.parse_value_number_next:
	add	r14, 1
	jmp	.parse_value_number_loop
calign
.parse_value_number_done:
	mov	rdx, r14
	sub	rdx, rsi
	call	string$substr
	; string is now in rax of the substr value, vname is in [rsp+8], and the object is in [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret
calign
.parse_value_weirde:
	; per the brief comment above, there is at least one broken browser that sends
	; "varname":E
	; if the _string_ value is indeed an E by itself
	; Sooo... to accommodate this broken-assed behaviour, if the next character after the E is a comma or a }, we will
	; go ahead and accept it, otherwise, we return false due to invalid json encoding
	mov	rcx, r14
	add	rcx, 1
	cmp	rcx, r13
	jae	.parse_value_kakkedret
if string_bits = 32
	mov	eax, dword [r12+rcx*4+8]
else
	movzx	eax, word [r12+rcx*2+8]
end if
	cmp	eax, ','
	je	.parse_value_weirde_ok
	cmp	eax, '}'
	jne	.parse_value_kakkedret
calign
.parse_value_weirde_ok:
	mov	rdi, r12
	mov	rsi, r14
	mov	edx, 1
	call	string$substr
	; string is now in rax of the substr value, vname is in [rsp+8], and the object is in [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret
cleartext .truestr, 'true'
calign
.parse_value_true:
	add	r14, 4
	mov	rdi, .truestr
	call	string$copy
	; string is now in rax of the value, vname is in [rsp+8], and the object is in [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret
cleartext .falsestr, 'false'
calign
.parse_value_false:
	add	r14, 5
	mov	rdi, .falsestr
	call	string$copy
	; string is now in rax of the value, vname is in [rsp+8], and the object is in [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret
cleartext .nullstr, 'null'
calign
.parse_value_null:
	add	r14, 4
	mov	rdi, .nullstr
	call	string$copy
	; string is now in rax of the value, vname is in [rsp+8], and the object is in [rsp]
	mov	rdi, [rsp+8]
	mov	rsi, rax
	call	json$newvalue_nocopy
	mov	rdi, [rsp]
	mov	rsi, rax
	call	json$appendchild
	pop	rdi rsi
	mov	eax, 1
	ret

end if
