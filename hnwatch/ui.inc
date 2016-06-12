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
	; ui.inc: tui goods to display the globals from hnmodel.inc
	;

globals
{
	main_screen	dq	0		; topmost UI object that holds everything else
	main_datagrid	dq	0		; we keep a global reference to it for updates
	status_format	dq	0		; formatter object for statusbar updates

	item_screen	dq	0		; if an item was selected, this is its container
	item_format1	dq	0		; formatter objects for itemselected display
	item_format2	dq	0		; ""
	item_format3	dq	0		; ""
	item_format4	dq	0		; ""
	item_kids	dq	0		; a stringmap of item-specific child items
	; when an item is selected for display this gets set to its ID (string)
	displayitem	dq	0

	; global string object that contains our current main nav (topstories, newstories, etc)
	; set initially by _start (aka main)
	navstring	dq	0
}

include 'textify.inc'

falign
ui$init:
	prolog	ui$init
	push	rbx r12 r13
	mov	edi, 1
	call	unsignedmap$new
	mov	[item_kids], rax

	; we need a base tui_object to hold "everything"
	mov	edi, tui_object_size
	call	heap$alloc
	mov	rbx, rax
	mov	rdi, rax
	mov	[main_screen], rax
	; use our custom vtable so we can grab the main nav keys
	mov	qword [rax], .custom_vtable
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	; so now we have a 100% x 100% dynamic-sized outer tui object
	
	; the default layout for tui_objects is vertical, and our main
	; HN index needs to be a datagrid object, so we'll add that next
	; 100% x 100% so it will autofill all available space:
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	ansi_colors edi, 'black', 'lightgray'
	ansi_colors esi, 'lightgray', 'black'
	ansi_colors edx, 'lightgray', 'blue'
	call	tui_datagrid$new_dd
	mov	r12, rax
	; override its virtual method table with our own so we can hook itemselected
	mov	qword [rax], .datagrid_vtable
	; add our datagrid header information
	; first column we want width 4 for our rank
	mov	rdi, rax
	mov	rsi, .label_rank
	mov	edx, 4
	mov	ecx, tui_textalign_left
	mov	r8, .prop_rank
	call	tui_datagrid$nvaddproperty_i
	; next column is dynamic width title
	mov	rdi, r12
	mov	rsi, .label_title
	movq	xmm0, [_math_onehundred]
	mov	edx, tui_textalign_left
	mov	rcx, .prop_title
	call	tui_datagrid$nvaddproperty_d
	; next column is width 4 score/points
	mov	rdi, r12
	mov	rsi, .label_score
	mov	edx, 4
	mov	ecx, tui_textalign_right
	mov	r8, .prop_score
	call	tui_datagrid$nvaddproperty_i
	; next column is width 7 age
	mov	rdi, r12
	mov	rsi, .label_age
	mov	edx, 7
	mov	ecx, tui_textalign_right
	mov	r8, .prop_age
	call	tui_datagrid$nvaddproperty_i
	; next column is width 16 username
	mov	rdi, r12
	mov	rsi, .label_by
	mov	edx, 16
	mov	ecx, tui_textalign_left
	mov	r8, .prop_by
	call	tui_datagrid$nvaddproperty_i
	; last column is width 4 comment count
	mov	rdi, r12
	mov	rsi, .label_descendants
	mov	edx, 4
	mov	ecx, tui_textalign_right
	mov	r8, .prop_descendants
	call	tui_datagrid$nvaddproperty_i
	; so now that we are done with column definitions, next up
	; is to add it to our outer tui_object
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; now we can set our global var so that updates can set the data
	mov	[main_datagrid], r12

	; last but not least, add a statusbar to the bottom of our main tui_object
	movq	xmm0, [_math_onehundred]
	ansi_colors edi, 'black', 'gray'
	mov	esi, 1
	call	tui_statusbar$new_d
	mov	r13, rax
	
	; set its initial text
	mov	rdi, rax
	mov	rsi, .copyright
	call	tui_statusbar$nvsettext

	; we are not using tui_statusbar$nvaddlabel because we want highlightchars in
	; the tui_label object (otherwise, this is a straight copy from nvaddlabel)
macro add_statusbar_label s*, c* {
	mov	rdi, .s1
	mov	rsi, s
	call	string$concat
	push	rax
	mov	esi, 1
	mov	rdx, rax
	mov	ecx, [r13+tui_statusbar_colors_ofs]
	mov	r8d, tui_textalign_left
	mov	edi, [rdx]
	call	tui_label$new_ii
	; set the highlightchar and highlightcolors
	ansi_colors r8d, 'venetianred', 'gray'
	mov	dword [rax+tui_label_highlightchar_ofs], c
	mov	dword [rax+tui_label_highlightcolor_ofs], r8d
	mov	rdi, r13
	mov	rdx, rax
	mov	[rax+tui_parent_ofs], rdi
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	call	list$insert_after
	; done with our string
	pop	rdi
	call	heap$free
	mov	rsi, [r13]
	mov	rdi, r13
	call	qword [rsi+tui_vlayoutchanged]
}

	; add our labels
	; add_statusbar_label .stat_reset, 'R'
	add_statusbar_label .stat_job, 'J'
	add_statusbar_label .stat_show, 'S'
	add_statusbar_label .stat_ask, 'A'
	add_statusbar_label .stat_new, 'N'
	add_statusbar_label .stat_top, 'T'

	; add it to our main tui_object
	mov	rdi, rbx
	mov	rsi, r13
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]


	; create our status formatter object
	xor	edi, edi
	call	formatter$new
	mov	[status_format], rax
	mov	rdi, rax
	mov	rsi, .copyright
	call	formatter$add_static
	mov	rdi, [status_format]
	mov	rsi, .s1
	call	formatter$add_static

	mov	rdi, [status_format]
	mov	rsi, .s2
	call	formatter$add_static
	mov	rdi, [status_format]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned

	mov	rdi, [status_format]
	mov	rsi, .s3
	call	formatter$add_static
	mov	rdi, [status_format]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned

	mov	rdi, [status_format]
	mov	rsi, .s4
	call	formatter$add_static
	mov	rdi, [status_format]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned

	mov	rdi, [status_format]
	mov	rsi, .s5
	call	formatter$add_static
	mov	rdi, [status_format]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned

	; three formatters for itemselected display
	; text for Rank. Title
	xor	edi, edi
	call	formatter$new
	mov	[item_format1], rax
	mov	rdi, rax
	mov	rsi, .item_format_space
	call	formatter$add_static
	mov	rdi, [item_format1]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [item_format1]
	mov	rsi, .item_format1_dotspace
	call	formatter$add_static
	mov	rdi, [item_format1]
	xor	esi, esi
	call	formatter$add_string
	; text for X points by username T ago
	xor	edi, edi
	call	formatter$new
	mov	[item_format2], rax
	mov	rdi, rax
	mov	rsi, .item_format_quadspace
	call	formatter$add_static
	mov	rdi, [item_format2]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [item_format2]
	mov	rsi, .item_format2_pointsby
	call	formatter$add_static
	mov	rdi, [item_format2]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [item_format2]
	mov	rsi, .item_format_space
	call	formatter$add_static
	mov	rdi, [item_format2]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [item_format2]
	mov	rsi, .item_format2_ago
	call	formatter$add_static
	; text for X points by username | Y comments
	xor	edi, edi
	call	formatter$new
	mov	[item_format3], rax
	mov	rdi, rax
	mov	rsi, .item_format_quadspace
	call	formatter$add_static
	mov	rdi, [item_format3]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [item_format3]
	mov	rsi, .item_format2_pointsby
	call	formatter$add_static
	mov	rdi, [item_format3]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [item_format3]
	mov	rsi, .item_format_space
	call	formatter$add_static
	mov	rdi, [item_format3]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [item_format3]
	mov	rsi, .item_format3_pipe
	call	formatter$add_static
	mov	rdi, [item_format3]
	mov	esi, 1
	xor	edx, edx
	call	formatter$add_unsigned
	mov	rdi, [item_format3]
	mov	rsi, .item_format3_comments
	call	formatter$add_static
	; text for BY TIME ago
	mov	edi, 1
	call	formatter$new
	mov	[item_format4], rax
	mov	rdi, rax
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [item_format4]
	xor	esi, esi
	call	formatter$add_string
	mov	rdi, [item_format4]
	mov	rsi, .item_format4_ago
	call	formatter$add_static

	; set the hnmodel's statuscb and its arg
	mov	qword [statuscb], ui$statusbar_update
	mov	[statuscbarg], r13

	; so now we are done constructing our main view, fire up our signature
	; splash page intro
	mov	rdi, rbx
	call	tui_splash$new

	; set the hnmodels' updatedcb to our composer
	mov	qword [updatedcb], ui$compose
	
	; and last but not least, hook all that into a tui_terminal object
	mov	rdi, rax
	call	tui_terminal$new

	pop	r13 r12 rbx
	epilog
cleartext .label_rank, 'Pos'
cleartext .prop_rank, 'rank'
cleartext .label_title, 'Title'
cleartext .prop_title, 'title'
cleartext .label_score, 'Pts'
cleartext .prop_score, 'score'
cleartext .label_age, 'Age'
cleartext .prop_age, 'age'
cleartext .label_by, 'By'
cleartext .prop_by, 'by'
cleartext .label_descendants, 'Cmt'
cleartext .prop_descendants, 'descendants'

cleartext .stat_top, 'Top'
cleartext .stat_new, 'New'
cleartext .stat_ask, 'Ask'
cleartext .stat_show, 'Show'
cleartext .stat_job, 'Job'
cleartext .stat_reset, 'Reset'

cleartext .copyright, 'hnwatch v1.16 ',0xa9,' 2015, 2016 2 Ton Digital'

cleartext .item_format_space, ' '
cleartext .item_format_quadspace, '    '
cleartext .item_format1_dotspace, '. '
cleartext .item_format2_pointsby, ' points by '
cleartext .item_format2_ago, ' ago'
cleartext .item_format3_pipe, ' ago | '
cleartext .item_format3_comments, ' comments'
cleartext .item_format4_ago, 'ago'
dalign
.s1:
        dq      3
if string_bits = 32
        dd      ' ', 0x2502, ' '
else
        dw      ' ', 0x2502, ' '
end if
cleartext .s2, 'I: '
cleartext .s3, ' R: '
cleartext .s4, ' B: '
cleartext .s5, ' E: '
	; this is a copy of tui_object$simple_vtable, with an override for our key handler
dalign
.custom_vtable:
	dq	tui_object$cleanup, tui_object$simple_clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	ui$main_keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
dalign
.datagrid_vtable:
; direct copy of datagrid's vtable, but with our own itemselected
	dq	tui_object$cleanup, tui_datagrid$clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
	; our itemselected:
	dq	ui$itemselected



	; three arguments: rdi == our main tui_object, esi == key, edx == esc_key
falign
ui$main_keyevent:
	prolog	ui$main_keyevent
	mov	rdi, .topstories
	cmp	esi, 't'
	je	.gotit
	cmp	esi, 'T'
	je	.gotit
	mov	rdi, .newstories
	cmp	esi, 'n'
	je	.gotit
	cmp	esi, 'N'
	je	.gotit
	mov	rdi, .askstories
	cmp	esi, 'a'
	je	.gotit
	cmp	esi, 'A'
	je	.gotit
	mov	rdi, .showstories
	cmp	esi, 's'
	je	.gotit
	cmp	esi, 'S'
	je	.gotit
	mov	rdi, .jobstories
	cmp	esi, 'j'
	je	.gotit
	cmp	esi, 'J'
	je	.gotit
if defined use_reset_goods
	; special handling required for reset
	cmp	esi, 'r'
	je	.reset
	cmp	esi, 'R'
	je	.reset
end if
	; otherwise, not handled
	xor	eax, eax
	epilog
cleartext .topstories, 'topstories'
cleartext .newstories, 'newstories'
cleartext .askstories, 'askstories'
cleartext .showstories, 'showstories'
cleartext .jobstories, 'jobstories'
.gotit:
	; rdi == the string that we want, compare it to our navstring
	push	rdi
	mov	rsi, [navstring]
	call	string$equals
	pop	rdi
	test	eax, eax
	jnz	.nothingtodo
	; otherwise, we have a new main nav to goto
	mov	[navstring], rdi
	call	hnmodel$newmain
	; call our compose in the interim so that the user
	; gets an indication their key was accepted (there is lag
	; while the new eventstream gets underway)
	xor	edi, edi			; no key triggered the updatecb
	call	ui$compose
.nothingtodo:
	mov	eax, 1				; key handled
	epilog
.reset:
	; let hnmodel do a full reset
	call	hnmodel$reset
	; update our UI so the user knows something happened
	xor	edi, edi
	call	ui$compose
	mov	eax, 1
	epilog


	; single argument in rdi: an item's json object
	; returns a new string of its age (e.g. 3h25m)
	; or null if no time is present in the json
falign
ui$jsonage:
	prolog	ui$jsonage
	mov	rsi, .prop_time
	call	json$getvaluebyname
	test	rax, rax
	jz	.nullret
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.nullret
	; convert that to an unsigned
	mov	rdi, rax
	call	string$to_unsigned
	; convert that to our julian date
	mov	rdi, rax
	xor	esi, esi
	call	ctime$to_jd
	; hangon to that value
	movaps	xmm15, xmm0
	; get the current julian date
	call	timestamp
	; less the jsons
	subsd	xmm0, xmm15
	; format that as a string
	mov	edi, 2		; minute == minimum resolution
	xor	esi, esi	; no fractions
	call	format$duration
	epilog
.nullret:
	mov	rdi, .null
	call	string$copy
	epilog
cleartext .prop_time, 'time'
cleartext .null, '(null)'



	; helper function to update a heightlocked row
	; rdi == unsigned item number
	; rsi == item json
	; edx == nesting level
	; rcx == the row we are modifying
falign
ui$itemupdaterow:
	prolog	ui$itemupdaterow
	push	rbx r12 r13 r14 r15
	mov	rbx, rcx
	mov	r12, rdi
	mov	r13, rsi
	mov	r14d, edx
	; set our row's ID
	mov	qword [rcx+tui_object_size], rdi
	; set our first child's width to our nesting level
	mov	rdi, [rcx+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	rdi, [rsi+_list_valueofs]
	shl	edx, 1
	mov	dword [rdi+tui_width_ofs], edx
	mov	rsi, [rdi]
	call	qword [rsi+tui_vsizechanged]
	; our last child is the inner vertical, we need to reset both tui_text's contents
	mov	rdi, [rbx+tui_children_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	r15, [rsi+_list_valueofs]
	; r15 == our heightlocked vertical layout row
	; its first child is the BY TIME ago
	; its last child is the text itself
	mov	rdi, r13
	call	ui$jsonage
	mov	r14, rax
	mov	rdi, r13
	mov	rsi, .prop_by
	call	json$getvaluebyname
	test	rax, rax
	jz	.no_username
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.no_username
.username_ready:
	mov	rdi, [item_format4]
	mov	rsi, rax
	mov	rdx, r14
	call	formatter$doit
	mov	rdi, r14
	mov	r14, rax
	call	heap$free
	mov	rdi, [r15+tui_children_ofs]
	mov	rsi, [rdi+_list_first_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, r14
	call	tui_text$nvsettext
	mov	rdi, r14
	call	heap$free
	; do the same for the text
	; get our text from the json in r13
	mov	rdi, r13
	mov	rsi, .prop_text
	call	json$getvaluebyname
	test	rax, rax
	jz	.no_text
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.no_text
.text_ready:
	mov	rdi, rax
	call	textify
	mov	rdi, [r15+tui_children_ofs]
	mov	rsi, [rdi+_list_last_ofs]
	mov	rdi, [rsi+_list_valueofs]
	mov	rsi, rax
	push	rax
	call	tui_text$nvsettext
	pop	rdi
	call	heap$free

	mov	rdi, rbx
	mov	rsi, [rbx]
	call	qword [rsi+tui_vlayoutchanged]

	pop	r15 r14 r13 r12 rbx
	epilog
.no_username:
	mov	rax, .null
	jmp	.username_ready
.no_text:
	mov	rax, .null
	jmp	.text_ready
cleartext .prop_text, 'text'
cleartext .prop_by, 'by'
cleartext .null, '(null)'



	; helper function to create a heightlocked row
	; rdi == unsigned item number (so we can track updates)
	; rsi == item json
	; edx == nesting level
falign
ui$itemnewrow:
	prolog	ui$itemnewrow
	push	rbx r12 r13 r14
	; heightlocked row ==
	; indent | light coloured by TIME ago
	;        | text
	mov	r12, rdi
	mov	r13, rsi
	mov	r14d, edx
	mov	edi, tui_object_size + 8	; +8 so we can store an id at tui_object_size of this row
	call	heap$alloc
	mov	rdi, rax
	push	rax
	mov	qword [rax], .custom_vtable_outer
	movq	xmm0, [_math_onehundred]
	mov	esi, 2
	call	tui_object$init_di
	pop	rbx
	; set our item number for future easy reference
	mov	qword [rbx+tui_object_size], r12
	; set its layout to horizontal
	mov	dword [rbx+tui_layout_ofs], tui_layout_horizontal
	; add to that our spacer

	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	mov	rdi, rax
	mov	esi, r14d
	mov	edx, 2
	mov	ecx, ' '
	shl	esi, 1
	ansi_colors r8d, 'lightgray', 'black'
	push	rax
	call	tui_background$init_ii
	pop	rsi
	mov	rdi, rbx
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; now we need a 100% wide by variable height vertical layout
	mov	edi, tui_object_size
	call	heap$alloc
	mov	r12, rax
	mov	rdi, rax
	mov	qword [rax], .custom_vtable_inner
	movq	xmm0, [_math_onehundred]
	mov	esi, 2
	call	tui_object$init_di
	; add that to our horizontal outer box
	mov	rdi, rbx
	mov	rsi, r12
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; to our inner heightlocked one, we need a 100% wide x 1 for by + timeago
	; first, get our text for it
	mov	rdi, r13
	call	ui$jsonage
	mov	r14, rax
	mov	rdi, r13
	mov	rsi, .prop_by
	call	json$getvaluebyname
	test	rax, rax
	jz	.no_username
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.no_username
.username_ready:
	mov	rdi, [item_format4]
	mov	rsi, rax
	mov	rdx, r14
	call	formatter$doit
	mov	rdi, r14
	mov	r14, rax
	call	heap$free
	; now we can create our tui_text 100% wide by 1
	movq	xmm0, [_math_onehundred]		; width
	mov	edi, 1					; height
	mov	rsi, r14				; initial text
	ansi_colors edx, 'darkslategray', 'black'
	mov	ecx, edx				; colors and focuscolors
	xor	r8d, r8d				; no spinner
	call	tui_text$new_di
	mov	dword [rax+tui_text_focussed_ofs], 0
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_editable_ofs], 0
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	; add that to our RHS in r12
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	; free our initialtext string
	mov	rdi, r14
	call	heap$free
	; get our text from the json
	mov	rdi, r13
	mov	rsi, .prop_text
	call	json$getvaluebyname
	test	rax, rax
	jz	.no_text
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.no_text
.text_ready:
	mov	rdi, rax
	call	textify
	; and last but not least, a heightlocked multiline
	movq	xmm0, [_math_onehundred]		; width
	mov	edi, 1					; height
	mov	rsi, rax				; initial text
	ansi_colors edx, 'lightgray', 'black'
	mov	ecx, edx				; colors and focuscolors
	xor	r8d, r8d				; no spinner
	push	rax
	call	tui_text$new_di
	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 0
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_editable_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2
	; add that to our RHS in r12
	mov	rdi, r12
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]
	pop	rdi
	call	heap$free
	; done, dusted
	mov	rax, rbx
	pop	r14 r13 r12 rbx
	epilog
.no_username:
	mov	rax, .null
	jmp	.username_ready
.no_text:
	mov	rax, .null
	jmp	.text_ready
cleartext .prop_text, 'text'
cleartext .prop_by, 'by'
cleartext .null, '(null)'
	
falign
.outer_layoutchanged:
	; called with rdi == our row object, we need to set our row's height to our second child's height
	; then call our own sizechanged, followed by tui_object's layoutchanged
	push	rdi
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_last_ofs]
	mov	rdx, [rdx+_list_valueofs]
	mov	ecx, [rdx+tui_height_ofs]
	mov	r8, [rdi]
	mov	[rdi+tui_height_ofs], ecx
	push	rcx
	call	qword [r8+tui_vsizechanged]
	pop	rcx
	; set our first child's height = second child's height also
	mov	rdi, [rsp]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdi, [rdx+_list_valueofs]
	mov	r8, [rdi]
	mov	[rdi+tui_height_ofs], ecx
	call	qword [r8+tui_vsizechanged]
	pop	rdi
	call	tui_object$layoutchanged
	ret
falign
.inner_layoutchanged:
	; same as above, but we set it to our last child's height+1
	push	rdi
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_last_ofs]
	mov	rdx, [rdx+_list_valueofs]
	mov	ecx, [rdx+tui_height_ofs]
	mov	r8, [rdi]
	add	ecx, 1
	mov	[rdi+tui_height_ofs], ecx
	call	qword [r8+tui_vsizechanged]
	pop	rdi
	call	tui_object$layoutchanged
	ret


	; this is a copy of tui_object$simple_vtable, with an override for our layoutchanged
dalign
.custom_vtable_outer:
	dq	tui_object$cleanup, tui_object$simple_clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, .outer_layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked
dalign
.custom_vtable_inner:
	dq	tui_object$cleanup, tui_object$simple_clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, .inner_layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	tui_object$keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked




	; three arguments: rdi == our main tui_object, esi == key, edx == esc_key
falign
ui$item_keyevent:
	prolog	ui$item_keyevent
	cmp	esi, 27			; ESC key
	je	.bailout
	cmp	esi, 't'
	je	.bailout
	cmp	esi, 'T'
	je	.bailout
	cmp	esi, 'n'
	je	.bailout
	cmp	esi, 'N'
	je	.bailout
	cmp	esi, 'a'
	je	.bailout
	cmp	esi, 'A'
	je	.bailout
	cmp	esi, 's'
	je	.bailout
	cmp	esi, 'S'
	je	.bailout
	cmp	esi, 'j'
	je	.bailout
	cmp	esi, 'J'
	je	.bailout
if defined use_reset_goods
	cmp	esi, 'r'
	je	.bailout
	cmp	esi, 'R'
	je	.bailout
end if
	cmp	edx, 0x41		; up arrow
	je	.uparrow
	cmp	edx, 0x42		; down arrow
	je	.downarrow
	cmp	edx, 0x44		; left arrow
	je	.bailout
	xor	eax, eax
	epilog
.bailout:
	push	rsi rdx
	mov	rax, [main_datagrid]
	; swap the item_screen with the data_grid
	; (we are cheating a bit and directly manipulating its child list)
	mov	rsi, [main_screen]
	mov	rdi, [rsi+tui_children_ofs]
	mov	rdx, [_list_first]
	mov	[rdx+_list_valueofs], rax
	; call the main screen's layoutchanged
	mov	rdi, [main_screen]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	; clear our displayitem
	mov	qword [displayitem], 0
	; clear our item_kids map
	mov	rdi, [item_kids]
	xor	esi, esi
	call	unsignedmap$clear
	; destroy our item_screen itself
	mov	rdi, [item_screen]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vcleanup]
	mov	rdi, [item_screen]
	call	heap$free
	mov	qword [item_screen], 0
	pop	rsi rdx
	cmp	esi, 27
	jne	.pass_keyevent
	mov	eax, 1
	epilog
.pass_keyevent:
	mov	rdi, [main_datagrid]
	call	ui$main_keyevent
	epilog
.uparrow:
	; if our scroll pos at +4 is already 0, do nothing
	cmp	dword [rdi+tui_scroll_ofs+4], 0
	je	.uparrow_nothingtodo
	; otherwise, decrement it and be done
	sub	dword [rdi+tui_scroll_ofs+4], 1
	; call draw
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
	; done, dusted
.uparrow_nothingtodo:
	mov	eax, 1
	epilog
.downarrow:
	mov	rsi, [rdi+tui_parent_ofs]
	mov	ecx, [rsi+tui_height_ofs]	; height of our actual parent object
	xor	r8d, r8d
	push	rdi rcx
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, .heightcalc
	push	r8
	mov	rdx, rsp
	call	list$foreach_arg
	pop	r8 rcx rdi
	sub	r8d, 99				; the height of our "filler" less the statusbar height
	cmp	r8, rcx
	jbe	.downarrow_nothingtodo
	sub	r8, rcx
	cmp	dword [rdi+tui_scroll_ofs+4], r8d
	jae	.downarrow_nothingtodo
	add	dword [rdi+tui_scroll_ofs+4], 1
	; call draw
	mov	rsi, [rdi]
	call	qword [rsi+tui_vdraw]
.downarrow_nothingtodo:
	mov	eax, 1
	epilog
falign
.heightcalc:
	; rdi == tui object of our item screen, rsi == pointer to stackspace for counter
	mov	eax, [rdi+tui_height_ofs]
	add	dword [rsi], eax
	ret
	


	; no arguments, called when an item is selected, and when new items come in (compose)
falign
ui$itemupdate:
	prolog	ui$itemupdate
	; sanity check to make sure we have a displayitem
	cmp	qword [displayitem], 0
	je	.nothingtodo
	; otherwise, find the item in the item map
	mov	rdi, [displayitem]
	mov	esi, 10
	call	string$from_unsigned
	push	rax
	mov	rdi, [items]
	mov	rsi, rax
	call	stringmap$find_value
	pop	rdi
	push	rax rdx
	call	heap$free
	pop	rdx rax
	test	eax, eax
	jz	.nothingtodo			; sanity only, it better be here
	test	rdx, rdx
	jz	.nothingtodo
	push	rbx r12 r13 r14 r15
	mov	rbx, rdx			; the item's json object
	; otherwise, set/update first line of text, which is rank and title
	mov	rdi, rdx
	mov	rsi, .prop_rank
	call	json$getvaluebyname
	test	rax, rax
	jz	.kakked
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.kakked
	; turn that into an unsigned
	mov	rdi, rax
	call	string$to_unsigned
	mov	r12, rax
	; get the title
	mov	rdi, rbx
	mov	rsi, .prop_title
	call	json$getvaluebyname
	test	rax, rax
	jz	.kakked
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.kakked
	; format those two for our first display line
	mov	rdi, [item_format1]
	mov	rsi, r12
	mov	rdx, rax
	call	formatter$doit
	mov	r12, rax
	; get the first child from the item screen, which we know is tui_text
	mov	rdi, [item_screen]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdi, [rdx+_list_valueofs]
	mov	rsi, rax
	call	tui_text$nvsettext
	; free the format string
	mov	rdi, r12
	call	heap$free
	; next up, second line
	mov	rdi, rbx
	mov	rsi, .prop_score
	call	json$getvaluebyname
	test	rax, rax
	jz	.check_ago

	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.check_ago
	; turn that into an unsigned
	mov	rdi, rax
	call	string$to_unsigned
	mov	r12, rax
	; get the username
	mov	rdi, rbx
	mov	rsi, .prop_by
	call	json$getvaluebyname
	test	rax, rax
	jz	.check_ago
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.check_ago
	mov	r13, rax
	; age next
	mov	rdi, rbx
	mov	rsi, .prop_age
	call	json$getvaluebyname
	test	rax, rax
	jz	.kakked
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.kakked
	mov	r14, rax
	; comment count last but not least
	mov	rdi, rbx
	mov	rsi, .prop_descendants
	call	json$getvaluebyname
	test	rax, rax
	jz	.check_ago
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.check_ago
	; turn that into an unsigned
	mov	rdi, rax
	call	string$to_unsigned
	mov	r15, rax
	; second line formatter
	mov	rdi, [item_format2]
	mov	rsi, r12
	mov	rdx, r13
	mov	rcx, r14
	mov	r8, r15
	mov	r9, [item_format3]
	test	r15, r15
	cmovnz	rdi, r9
	call	formatter$doit
	mov	r12, rax
	; get the second child from the item screen, which we know is tui_text
	mov	rdi, [item_screen]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rdi, [rdx+_list_valueofs]
	mov	rsi, rax
	call	tui_text$nvsettext
	; free the format string
	mov	rdi, r12
	call	heap$free
	jmp	.url_or_text
cleartext .ago_cat, ' ago'
.check_ago:
	; for job listings, there is no score, only a time
	mov	rdi, rbx
	call	ui$jsonage
	mov	rdi, rax
	mov	rsi, .ago_cat
	push	rax
	call	string$concat
	mov	rdi, [rsp]
	mov	[rsp], rax
	call	heap$free
	mov	rax, [rsp]
	mov	rdi, [item_screen]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rdi, [rdx+_list_valueofs]
	mov	rsi, rax
	call	tui_text$nvsettext
	pop	rdi
	call	heap$free

.url_or_text:
	; url or text is next
	xor	r14d, r14d
	xor	r15d, r15d
	mov	rdi, rbx
	mov	rsi, .prop_url
	call	json$getvaluebyname
	xor	r12d, r12d
	test	rax, rax
	jz	.skip_url
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.skip_url
	mov	r12, rax
	mov	r14, [rax]		; its length
.skip_url:
	mov	rdi, rbx
	mov	rsi, .prop_text
	call	json$getvaluebyname
	xor	r13d, r13d
	test	rax, rax
	jz	.skip_text
	mov	rdi, rax
	call	json$stringvalue
	mov	r13, rax
	mov	r15, [rax]		; its length
.skip_text:
	mov	rdi, r12
	or	rdi, rsi
	jz	.skip_line3
	; depending on which one's length is set determines which one we'll use
	test	r14d, r14d
	cmovz	r12, r13
	; textify it (good for asks, etc as they can also be HTML)
	mov	rdi, r12
	call	textify
	; get the third child from the item screen, which we know is tui_text
	mov	rdi, [item_screen]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rdi, [rdx+_list_valueofs]
	mov	rsi, rax
	push	rax
	call	tui_text$nvsettext
	pop	rdi
	call	heap$free

.skip_line3:

	; next up: iterate/descend its kids, and their kids, etc.
	; first, recursively retrieve our items
	mov	rdi, [item_kids]
	mov	rsi, [displayitem]
	xor	edx, edx
	call	unsignedmap$insert_unique
	; get its kids list
	mov	rdi, rbx
	mov	rsi, .prop_kids
	call	json$getvaluebyname
	; if there is no kids, we are done
	test	rax, rax
	jz	.kakked
	; otherwise, foreach item there, do the deed
	mov	rdi, rax
	mov	rsi, .retriever
	call	json$foreach
	; so now, as items come in, this will repeatedly get called
	; and new kids of kids, etc will get updated correctly

	; so now we have to walk forward and update all of our item_screen's
	; rows starting at line 4, providing there _is_ a next
	mov	rdi, [item_screen]
	mov	rsi, [rdi+tui_children_ofs]
	mov	rdx, [rsi+_list_first_ofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	rdx, [rdx+_list_nextofs]
	mov	ecx, 1
	mov	rdx, [rdx+_list_nextofs]
	; make a spot on our stack to hold that value and our nesting level
	push	rcx rdx
	; recurse again through the kids, updating as we go
	mov	rdi, rbx
	mov	rsi, .prop_kids
	call	json$getvaluebyname
	mov	rdi, rax
	mov	rsi, .rowupdate
	mov	rdx, rsp
	call	json$foreach_arg
	add	rsp, 16

	; call layout changed on our item_screen
	mov	rdi, [item_screen]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]
	
.kakked:
	pop	r15 r14 r13 r12 rbx
.nothingtodo:
	epilog
falign
.rowupdate:
	; rdi == json value object of the kids id, rsi == pointer to our item_screen's child list ITEM and nesting level
	cmp	dword [rdi+json_type_ofs], json_value
	jne	.rowupdate_nothingtodo
	push	rbx r12 r13 r14
	mov	r12, rsi
	mov	rdi, [rdi+json_value_ofs]
	push	rdi
	call	string$to_unsigned
	mov	r13, rax			; unsigned numeric form of our id
	pop	rsi
	mov	rdi, [items]
	call	stringmap$find_value
	test	eax, eax
	jz	.rowupdate_notfound
	test	rdx, rdx
	jz	.rowupdate_notfound
	mov	rbx, rdx
	; so now, rbx == json object of the item we are updating
	; make sure it does not contain "deleted":true
	mov	rdi, rdx
	mov	rsi, .prop_deleted
	call	json$getvaluebyname
	test	rax, rax
	jz	.rowupdate_keepgoing
	mov	rdi, rax
	call	json$stringvalue
	test	rax, rax
	jz	.rowupdate_keepgoing
	mov	rdi, rax
	mov	rsi, .true
	call	string$equals
	test	eax, eax
	jnz	.rowupdate_notfound

.rowupdate_keepgoing:
	; and r12 is a pointer to our item_screen's child list ITEM
	; r13 == numeric unsigned of our id
	; three case scenarios:
	; 1) this item has not yet been added, thus list item has no next
	; 2) this item got updated, this row's id matches our own
	; 3) this item got reordered, this row's id != match our own
	; for both case 2 and 3, we can safely just update the row
	mov	rsi, [r12]			; list item pointer
	cmp	qword [rsi+_list_nextofs], 0
	je	.rowupdate_caseone

	; update this row with our goods
	mov	rcx, [rsi+_list_valueofs]
	mov	rdi, r13
	mov	rsi, rbx
	mov	rdx, [r12+8]
	call	ui$itemupdaterow
	; move our list pointer to the next spot before we keep going

	mov	rsi, [r12]
	mov	rdx, [rsi+_list_nextofs]
	mov	[r12], rdx

.rowupdate_godeeper:
	mov	rdi, rbx
	mov	rsi, .prop_kids
	call	json$getvaluebyname
	; if there are no kids, we are done
	test	rax, rax
	jz	.rowupdate_notfound
	mov	rdi, rax
	mov	rsi, .rowupdate
	; make new stackspace for our goods
	mov	rcx, [r12+8]
	mov	r8, [r12]
	add	rcx, 1
	push	rcx r8
	mov	rdx, rsp
	call	json$foreach_arg
	mov	rcx, [rsp]
	mov	[r12], rcx
	add	rsp, 16
.rowupdate_notfound:
	pop	r14 r13 r12 rbx
.rowupdate_nothingtodo:
	ret
cleartext .prop_deleted, 'deleted'
cleartext .true, 'true'

.rowupdate_caseone:
	; create a new row to hold our text with the appropriate nesting level
	mov	rdi, r13
	mov	rsi, rbx			; item json
	mov	rdx, [r12+8]			; nesting level
	call	ui$itemnewrow
	; insert that row into our children before the list item at [r12]
	mov	rdi, [item_screen]
	mov	rcx, rdi
	mov	rdi, [rdi+tui_children_ofs]
	mov	rsi, [r12]			; our current list location
	mov	rdx, rax
	mov	[rax+tui_parent_ofs], rcx	; set our new row's parent
	call	list$insert_before

	; done with this row, go deeper
	jmp	.rowupdate_godeeper

falign
.retriever:
	; this is called with rdi == json value object of the kids id
	cmp	dword [rdi+json_type_ofs], json_value
	jne	.retriever_nothingtodo
	mov	rdi, [rdi+json_value_ofs]
	mov	esi, 10
	push	rdi
	call	string$to_unsigned
	mov	rdi, [item_kids]
	mov	rsi, rax
	xor	edx, edx
	call	unsignedmap$insert_unique

	; next up, make sure the hnmodel either has or has queued this item already:
	mov	rdi, [rsp]
	xor	esi, esi		; not an update
	call	hnmodel$retrieve
	; and last but not least, if this item has already been retrieved, recursively walk its kids
	mov	rdi, [items]
	pop	rsi
	call	stringmap$find_value
	test	eax, eax
	jz	.retriever_nothingtodo
	test	rdx, rdx
	jz	.retriever_nothingtodo
	mov	rdi, rdx
	mov	rsi, .prop_kids
	call	json$getvaluebyname
	; if there is no kids, we are doen
	test	rax, rax
	jz	.retriever_nothingtodo
	; otherwise, foreach item there, do the deed
	mov	rdi, rax
	mov	rsi, .retriever
	call	json$foreach
.retriever_nothingtodo:
	ret
cleartext .prop_rank, 'rank'
cleartext .prop_kids, 'kids'
cleartext .prop_title, 'title'
cleartext .prop_score, 'score'
cleartext .prop_by, 'by'
cleartext .prop_age, 'age'
cleartext .prop_descendants, 'descendants'
cleartext .prop_url, 'url'
cleartext .prop_text, 'text'
	



	; this gets called from our datagrid with rdi == datagrid, rsi == json of the item selected
falign
ui$itemselected:
	prolog	ui$itemselected
	push	rbx
	mov	rbx, rsi
	; create our item_screen, remove the datagrid from the mainscreen, replace it with item_screen
	mov	edi, tui_object_size
	call	heap$alloc
	mov	rdi, rax
	mov	[item_screen], rax
	; use our custom vtable so we can grab the main nav keys
	mov	qword [rax], .custom_vtable
	movq	xmm0, [_math_onehundred]
	movq	xmm1, [_math_onehundred]
	call	tui_object$init_dd
	; so now we have a 100% x 100% dynamic-sized outer tui object
	; add 3 empty tui_text lines, heightlocked for our item-specific goods
	movq	xmm0, [_math_onehundred]		; width
	mov	edi, 1					; height
	xor	esi, esi				; initial text
	ansi_rgbi edx, 40, 40, 40
	ansi_rgbi ecx, 247, 247, 247
	shl	edx, 8
	or	edx, ecx
	mov	ecx, edx				; colors and focuscolors
	xor	r8d, r8d				; no spinner
	call	tui_text$new_di
	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 0
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_editable_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2

	; append that to our item_screen
	mov	rdi, [item_screen]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; again for the next line
	movq	xmm0, [_math_onehundred]		; width
	mov	edi, 1					; height
	xor	esi, esi				; initial text
	ansi_rgbi edx, 130, 130, 130
	ansi_rgbi ecx, 247, 247, 247
	shl	edx, 8
	or	edx, ecx
	mov	ecx, edx				; colors and focuscolors
	xor	r8d, r8d				; no spinner
	call	tui_text$new_di
	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 0
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_editable_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2

	; append that to our item_screen
	mov	rdi, [item_screen]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; and one more for the url or text itself
	movq	xmm0, [_math_onehundred]		; width
	mov	edi, 1					; height
	xor	esi, esi				; initial text
	ansi_colors edx, 'lightgray', 'black'
	mov	ecx, edx				; colors and focuscolors
	xor	r8d, r8d				; no spinner
	call	tui_text$new_di
	; enable multiline, left alignment, wordwrap, and heightlock
	mov	dword [rax+tui_text_multiline_ofs], 1
	mov	dword [rax+tui_text_focussed_ofs], 0
	mov	dword [rax+tui_text_docursor_ofs], 0
	mov	dword [rax+tui_text_editable_ofs], 0
	mov	dword [rax+tui_text_heightlock_ofs], 1
	mov	dword [rax+tui_text_align_ofs], tui_textalign_left
	mov	dword [rax+tui_text_wrap_ofs], 2

	; append that to our item_screen
	mov	rdi, [item_screen]
	mov	rsi, rax
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	; to "fill" the gap in our scrollable vertical layout window
	; we need a 100% wide by 100 row high background object (so that it clears empty space)
	mov	edi, tui_background_size
	call	heap$alloc
	mov	qword [rax], tui_background$vtable
	movq	xmm0, [_math_onehundred]
	mov	esi, 100
	mov	rdi, rax
	mov	edx, ' '
	ansi_colors ecx, 'lightgray', 'black'
	push	rax
	call	tui_background$init_di
	pop	rsi
	; append that to our item_screen
	mov	rdi, [item_screen]
	mov	rdx, [rdi]
	call	qword [rdx+tui_vappendchild]

	mov	rax, [item_screen]
	; replace the datagrid with our itemscreen
	; (we are cheating a bit and directly manipulating its child list)
	mov	rsi, [main_screen]
	mov	rdi, [rsi+tui_children_ofs]
	mov	rdx, [_list_first]
	mov	[rdx+_list_valueofs], rax
	; set our item screen's parent = main_screen
	mov	[rax+tui_parent_ofs], rsi
	; call the main screen's layoutchanged
	mov	rdi, [main_screen]
	mov	rsi, [rdi]
	call	qword [rsi+tui_vlayoutchanged]

	; get the ID string value from the itemselected json
	mov	rdi, rbx
	mov	rsi, .id
	call	json$getvaluebyname
	mov	rdi, rax
	call	json$stringvalue
	; sanity only
	test	rax, rax
	jz	.alldone
	mov	rdi, rax
	mov	esi, 10
	call	string$to_unsigned
	; set our global displayitem to it
	mov	[displayitem], rax
	call	ui$itemupdate
.alldone:
	
	pop	rbx
	epilog
cleartext .id, 'id'

	; this is a copy of tui_object$simple_vtable, with an override for our key handler
dalign
.custom_vtable:
	dq	tui_object$cleanup, tui_object$simple_clone, tui_object$draw, tui_object$redraw, tui_object$updatedisplaylist, tui_object$sizechanged
	dq	tui_object$timer, tui_object$layoutchanged, tui_object$move, tui_object$setfocus, tui_object$gotfocus, tui_object$lostfocus
	dq	ui$item_keyevent, tui_object$domodal, tui_object$endmodal, tui_object$exit, tui_object$calcbounds, tui_object$calcchildbounds
	dq	tui_object$appendchild, tui_object$appendbastard, tui_object$prependchild, tui_object$contains, tui_object$getchildindex
	dq	tui_object$removechild, tui_object$removebastard, tui_object$removeallchildren, tui_object$removeallbastards
	dq	tui_object$getobjectsunderpoint, tui_object$flatten, tui_object$firekeyevent, tui_object$ontab, tui_object$onshifttab
	dq	tui_object$setcursor, tui_object$showcursor, tui_object$hidecursor, tui_object$click, tui_object$clicked


	; this gets called with rdi == our statusbar object, rsi == string for our status
falign
ui$statusbar_update:
	prolog	ui$statusbar_update
	mov	r8, [items]
	push	rbx r12
	mov	rbx, rdi
	mov	r12, rsi
	mov	rdi, [status_format]
	mov	rsi, [r8+_avlofs_right]		; items.count
	mov	rdx, [requestcount]
	mov	rcx, [bytecount]
	mov	r8, [errorcount]
	call	formatter$doit
	push	rax
	mov	rdi, rbx
	mov	rsi, rax
	call	tui_statusbar$nvsettext
	pop	rdi
	call	heap$free
	pop	r12 rbx
	epilog



	; this gets called with a single arg from hnmodel after the items map has been updated
	; rdi == string item that caused it or null if we did it from in here
falign
ui$compose:
	prolog	ui$compose
	; Burning Purpose: create a new json array for our main datagrid from mainorder + item map
	; this is not very efficient thanks to this thing wholly recomposing EVERYTHING for each
	; and every item that gets updated, but it is fast enough not to warrant more complexity
	; for keeping them together instead... if we were dealing with a huge amount of inflight
	; items, this choice would obviously not be acceptable. hahah, YMMV.
	push	rbx r12
	mov	r12, rdi
	mov	rdi, .noname
	call	json$newarray
	mov	rbx, rax

	mov	rdi, [mainorder]
	mov	rsi, .eachmainorder
	mov	rdx, rax
	call	list$foreach_arg

	; now we can update the main_datagrid
	mov	rdi, [main_datagrid]
	mov	rsi, rbx
	call	tui_datagrid$nvsetdata

	test	r12, r12
	jz	.skip_itemcheck
	mov	rdi, r12
	mov	esi, 10
	call	string$to_unsigned
	mov	rdi, [item_kids]
	mov	rsi, rax
	call	unsignedmap$find_value
	test	eax, eax
	jz	.skip_itemcheck

	; otherwise, it exists in the items list, so call itemupdate
	call	ui$itemupdate
.skip_itemcheck:
	pop	r12 rbx
	epilog
falign
.eachmainorder:
	; rdi == string key from list, rsi == json array destination
	push	rbx r12 r13 r14 r15
	mov	rbx, rdi
	mov	r12, rsi
	; find this item in our items map
	mov	rdi, [items]
	mov	rsi, rbx
	call	stringmap$find_value
	test	eax, eax
	jz	.nodeal
	test	rdx, rdx
	jz	.nodeal
	; otherwise, rdx == the item json, deep copy it
	mov	r14, rdx
	mov	rdi, rdx
	call	json$copy
	mov	r13, rax
	; set its rank = r12's arraylength+1
	mov	rdi, .rank
	call	string$copy
	push	rax
	mov	rdi, r12
	call	json$arraylength
	lea	rdi, [rax+1]
	mov	esi, 10
	call	string$from_unsigned
	pop	rdi
	mov	rsi, rax
	mov	r15, rax
	call	json$newvalue_nocopy
	; append that to our json copy in r13
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	; add or replace the item map's json as well:
	mov	rdi, r14
	mov	rsi, .rank
	call	json$getvaluebyname
	test	rax, rax
	jnz	.set_map_rank
	; otherwise, add a new one to it
	mov	rdi, .rank
	mov	rsi, r15
	call	json$newvalue
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild
	jmp	.map_rank_done
.set_map_rank:
	; rax is the rank in the map's json, replace its value
	; with a copy of the string in r15
	push	rax
	mov	rdi, r15
	call	string$copy
	pop	rsi
	mov	rdi, [rsi+json_value_ofs]
	mov	[rsi+json_value_ofs], rax
	call	heap$free
.map_rank_done:
	; calculate the age of this item
	mov	rdi, .age
	call	string$copy
	push	rax
	mov	rdi, r13
	call	ui$jsonage
	pop	rdi
	mov	rsi, rax
	mov	r15, rax
	call	json$newvalue_nocopy
	; append that to our json copy in r13
	mov	rdi, r13
	mov	rsi, rax
	call	json$appendchild
	; set the original map's age as well
	mov	rdi, r14
	mov	rsi, .age
	call	json$getvaluebyname
	test	rax, rax
	jnz	.set_map_age
	; otherwise, add a new one
	mov	rdi, .age
	mov	rsi, r15
	call	json$newvalue
	mov	rdi, r14
	mov	rsi, rax
	call	json$appendchild
	jmp	.skipage
.set_map_age:
	; rax is the rank in the map's json, replace its value
	; with a copy of the string in r15
	push	rax
	mov	rdi, r15
	call	string$copy
	pop	rsi
	mov	rdi, [rsi+json_value_ofs]
	mov	[rsi+json_value_ofs], rax
	call	heap$free
	jmp	.skipage
.skipage_free:
	pop	rdi
	call	heap$free
.skipage:
	; last but not least, append our new json object in r13 to our r12 array
	mov	rdi, r12
	mov	rsi, r13
	call	json$appendchild
.nodeal:
	pop	r15 r14 r13 r12 rbx
	ret
cleartext .noname, 'noname'
cleartext .rank, 'rank'
cleartext .time, 'time'
cleartext .age, 'age'
