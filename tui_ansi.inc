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
	; tui_ansi.inc: ansi colors/codes helper goodies
	;

macro ansi_wci_rgbi {
	; hmm, these should relaly use floating point math... we may have to adjust the results here
	; TODO: either manually adjust/slide to compensate or figure out a way to get floating point math here
	if ansi_wcr = ansi_wcg & ansi_wcg = ansi_wcb
		if ansi_wcr = 0
			ansi_wci_val = 0xe8
		else if ansi_wcr = 255
			ansi_wci_val = 255		; was 15, but different terminals render it differently
		else
			; grayscale
			ansi_wci_val = (ansi_wcr / 11) + 232
		end if
	else
		ansi_wcr = ansi_wcr / 43
		ansi_wcg = ansi_wcg / 43
		ansi_wcb = ansi_wcb / 43
		ansi_wci_val = ansi_wcb + (ansi_wcg * 6) + (ansi_wcr * 36) + 16
	end if
}

macro ansi_wci wc* {
	;
	; hahah, if you are going to have a named color list, it may as well be ridiculously comprehensive right?
	; this was originally pulled from some "web color" list ages ago...
	;
	if wc eq 'black'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 0
	else if wc eq 'white'
		ansi_wcr = 255
		ansi_wcg = 255
		ansi_wcb = 255
	else if wc eq 'red'
		ansi_wcr = 255
		ansi_wcg = 0
		ansi_wcb = 0
	else if wc eq 'green'
		ansi_wcr = 0
		ansi_wcg = 255
		ansi_wcb = 0
	else if wc eq 'blue'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 255
	else if wc eq 'cyan'
		ansi_wcr = 0
		ansi_wcg = 255
		ansi_wcb = 255
	else if wc eq 'magenta'
		ansi_wcr = 255
		ansi_wcg = 0
		ansi_wcb = 255
	else if wc eq 'yellow'
		ansi_wcr = 255
		ansi_wcg = 255
		ansi_wcb = 0
	else if wc eq 'darkyellow'
		ansi_wcr = 192
		ansi_wcg = 192
		ansi_wcb = 0
	else if wc eq 'orange'
		ansi_wcr = 255
		ansi_wcg = 128
		ansi_wcb = 0
	else if wc eq 'greenyellow'
		ansi_wcr = 173
		ansi_wcg = 255
		ansi_wcb = 47
	else if wc eq 'springgreen'
		ansi_wcr = 0
		ansi_wcg = 255
		ansi_wcb = 127
	else if wc eq 'skyblue'
		ansi_wcr = 135
		ansi_wcg = 206
		ansi_wcb = 235
	else if wc eq 'violet'
		ansi_wcr = 143
		ansi_wcg = 94
		ansi_wcb = 153
	else if wc eq 'violetred'
		ansi_wcr = 208
		ansi_wcg = 32
		ansi_wcb = 144
	else if wc eq 'dimgray'
		ansi_wcr = 105
		ansi_wcg = 105
		ansi_wcb = 105
	else if wc eq 'gray'
		ansi_wcr = 128
		ansi_wcg = 128
		ansi_wcb = 128
	else if wc eq 'grey'
		ansi_wcr = 192
		ansi_wcg = 192
		ansi_wcb = 192
	else if wc eq 'lightgrey'
		ansi_wcr = 211
		ansi_wcg = 211
		ansi_wcb = 211
	else if wc eq 'lightgray'
		ansi_wcr = 211
		ansi_wcg = 211
		ansi_wcb = 211
	else if wc eq 'dimgrey'
		ansi_wcr = 105
		ansi_wcg = 105
		ansi_wcb = 105
	else if wc eq 'mediumvioletred'
		ansi_wcr = 199
		ansi_wcg = 21
		ansi_wcb = 133
	else if wc eq 'blueviolet'
		ansi_wcr = 138
		ansi_wcg = 43
		ansi_wcb = 226
	else if wc eq 'orchid'
		ansi_wcr = 218
		ansi_wcg = 112
		ansi_wcb = 214
	else if wc eq 'mediumorchid'
		ansi_wcr = 172
		ansi_wcg = 77
		ansi_wcb = 166
	else if wc eq 'darkorchid'
		ansi_wcr = 106
		ansi_wcg = 37
		ansi_wcb = 102
	else if wc eq 'maroon'
		ansi_wcr = 128
		ansi_wcg = 0
		ansi_wcb = 0
	else if wc eq 'plum'
		ansi_wcr = 221
		ansi_wcg = 160
		ansi_wcb = 221
	else if wc eq 'thistle'
		ansi_wcr = 216
		ansi_wcg = 191
		ansi_wcb = 216
	else if wc eq 'lightblue'
		ansi_wcr = 171
		ansi_wcg = 197
		ansi_wcb = 255
	else if wc eq 'mediumblue'
		ansi_wcr = 61
		ansi_wcg = 98
		ansi_wcb = 208
	else if wc eq 'cornflowerblue'
		ansi_wcr = 100
		ansi_wcg = 149
		ansi_wcb = 237
	else if wc eq 'navyblue'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 142
	else if wc eq 'navy'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 128
	else if wc eq 'midnightblue'
		ansi_wcr = 25
		ansi_wcg = 25
		ansi_wcb = 112
	else if wc eq 'turquoise'
		ansi_wcr = 64
		ansi_wcg = 224
		ansi_wcb = 208
	else if wc eq 'mediumturquoise'
		ansi_wcr = 62
		ansi_wcg = 172
		ansi_wcb = 181
	else if wc eq 'darkturquoise'
		ansi_wcr = 29
		ansi_wcg = 111
		ansi_wcb = 117
	else if wc eq 'lightsteelblue'
		ansi_wcr = 52
		ansi_wcg = 152
		ansi_wcb = 202
	else if wc eq 'steelblue'
		ansi_wcr = 70
		ansi_wcg = 130
		ansi_wcb = 180
	else if wc eq 'cadetblue'
		ansi_wcr = 126
		ansi_wcb = 125
		ansi_wcb = 160
	else if wc eq 'slateblue'
		ansi_wcr = 106
		ansi_wcb = 90
		ansi_wcg = 205
	else if wc eq 'mediumslateblue'
		ansi_wcr = 95
		ansi_wcg = 109
		ansi_wcb = 154
	else if wc eq 'darkslateblue'
		ansi_wcr = 51
		ansi_wcg = 62
		ansi_wcb = 99
	else if wc eq 'darkslategrey'
		ansi_wcr = 60
		ansi_wcg = 64
		ansi_wcb = 74
	else if wc eq 'darkslategray'
		ansi_wcr = 60
		ansi_wcg = 64
		ansi_wcb = 74
	else if wc eq 'darkgreen'
		ansi_wcr = 0
		ansi_wcg = 83
		ansi_wcb = 0
	else if wc eq 'darkolivegreen'	
		ansi_wcr = 79
		ansi_wcg = 79
		ansi_wcb = 47
	else if wc eq 'forestgreen'
		ansi_wcr = 34
		ansi_wcg = 139
		ansi_wcb = 34
	else if wc eq 'mediumforestgreen'
		ansi_wcr = 107
		ansi_wcg = 142
		ansi_wcb = 35
	else if wc eq 'limegreen'
		ansi_wcr = 50
		ansi_wcg = 205
		ansi_wcb = 50
	else if wc eq 'mediumspringgreen'
		ansi_wcr = 60
		ansi_wcg = 141
		ansi_wcb = 35
	else if wc eq 'palegreen'
		ansi_wcr = 152
		ansi_wcg = 255
		ansi_wcb = 152
	else if wc eq 'seagreen'
		ansi_wcr = 46
		ansi_wcg = 139
		ansi_wcb = 87
	else if wc eq 'mediumseagreen'
		ansi_wcr = 27
		ansi_wcg = 134
		ansi_wcb = 86
	else if wc eq 'aquamarine'
		ansi_wcr = 127
		ansi_wcg = 255
		ansi_wcb = 212
	else if wc eq 'mediumaquamarine'
		ansi_wcr = 21
		ansi_wcg = 135
		ansi_wcb = 118
	else if wc eq 'yellowgreen'
		ansi_wcr = 154
		ansi_wcg = 205
		ansi_wcb = 50
	else if wc eq 'gold'
		ansi_wcr = 255
		ansi_wcg = 215
		ansi_wcb = 0
	else if wc eq 'mediumgoldenrod'
		ansi_wcr = 184
		ansi_wcg = 134
		ansi_wcb = 11
	else if wc eq 'goldenrod'
		ansi_wcr = 218
		ansi_wcg = 165
		ansi_wcb = 32
	else if wc eq 'wheat'
		ansi_wcr = 245
		ansi_wcg = 222
		ansi_wcb = 179
	else if wc eq 'khaki'
		ansi_wcr = 240
		ansi_wcg = 230
		ansi_wcb = 140
	else if wc eq 'tan'
		ansi_wcr = 210
		ansi_wcg = 180
		ansi_wcb = 140
	else if wc eq 'sandybrown'
		ansi_wcr = 244
		ansi_wcg = 164
		ansi_wcb = 96
	else if wc eq 'sienna'
		ansi_wcr = 160
		ansi_wcg = 82
		ansi_wcb = 45
	else if wc eq 'brown'
		ansi_wcr = 128
		ansi_wcg = 42
		ansi_wcb = 42
	else if wc eq 'indianred'
		ansi_wcr = 176
		ansi_wcg = 23
		ansi_wcb = 31
	else if wc eq 'pink'
		ansi_wcr = 255
		ansi_wcg = 192
		ansi_wcb = 203
	else if wc eq 'coral'
		ansi_wcr = 255
		ansi_wcg = 127
		ansi_wcb = 80
	else if wc eq 'salmon'
		ansi_wcr = 250
		ansi_wcg = 128
		ansi_wcb = 114
	else if wc eq 'orangered'
		ansi_wcr = 255
		ansi_wcg = 69
		ansi_wcb = 0
	else if wc eq 'firebrick'
		ansi_wcr = 178
		ansi_wcg = 34
		ansi_wcb = 34
	else if wc eq 'antiquewhite'
		ansi_wcr = 250
		ansi_wcg = 235
		ansi_wcb = 215
	else if wc eq 'azure'
		ansi_wcr = 240
		ansi_wcg = 255
		ansi_wcb = 255
	else if wc eq 'bisque'
		ansi_wcr = 255
		ansi_wcg = 228
		ansi_wcb = 196
	else if wc eq 'blanchedalmond'
		ansi_wcr = 255
		ansi_wcg = 235
		ansi_wcb = 205
	else if wc eq 'cornsilk'
		ansi_wcr = 255
		ansi_wcg = 248
		ansi_wcb = 220
	else if wc eq 'eggshell'
		ansi_wcr = 252
		ansi_wcg = 230
		ansi_wcb = 201
	else if wc eq 'floralwhite'
		ansi_wcr = 255
		ansi_wcg = 250
		ansi_wcb = 240
	else if wc eq 'gainsboro'
		ansi_wcr = 220
		ansi_wcg = 220
		ansi_wcb = 220
	else if wc eq 'ghostwhite'
		ansi_wcr = 248
		ansi_wcg = 248
		ansi_wcb = 255
	else if wc eq 'honeydew'
		ansi_wcr = 240
		ansi_wcg = 255
		ansi_wcb = 240
	else if wc eq 'ivory'
		ansi_wcr = 255
		ansi_wcg = 255
		ansi_wcb = 240
	else if wc eq 'lavender'
		ansi_wcr = 230
		ansi_wcg = 230
		ansi_wcb = 250
	else if wc eq 'lavenderblush'
		ansi_wcr = 255
		ansi_wcg = 240
		ansi_wcb = 245
	else if wc eq 'lemonchiffon'
		ansi_wcr = 255
		ansi_wcg = 250
		ansi_wcb = 205
	else if wc eq 'linen'
		ansi_wcr = 250
		ansi_wcg = 240
		ansi_wcb = 230
	else if wc eq 'mintcream'
		ansi_wcr = 245
		ansi_wcg = 255
		ansi_wcb = 250
	else if wc eq 'mistyrose'
		ansi_wcr = 255
		ansi_wcg = 228
		ansi_wcb = 225
	else if wc eq 'moccasin'
		ansi_wcr = 255
		ansi_wcg = 228
		ansi_wcb = 181
	else if wc eq 'navajowhite'
		ansi_wcr = 255
		ansi_wcg = 222
		ansi_wcb = 173
	else if wc eq 'oldlace'
		ansi_wcr = 253
		ansi_wcg = 245
		ansi_wcb = 230
	else if wc eq 'papayawhip'
		ansi_wcr = 255
		ansi_wcg = 239
		ansi_wcb = 213
	else if wc eq 'peachpuff'
		ansi_wcr = 255
		ansi_wcg = 218
		ansi_wcb = 185
	else if wc eq 'seashell'
		ansi_wcr = 255
		ansi_wcg = 245
		ansi_wcb = 238
	else if wc eq 'snow'
		ansi_wcr = 255
		ansi_wcg = 250
		ansi_wcb = 250
	else if wc eq 'titaniumwhite'
		ansi_wcr = 252
		ansi_wcg = 255
		ansi_wcb = 240
	else if wc eq 'whitesmoke'
		ansi_wcr = 245
		ansi_wcg = 245
		ansi_wcb = 245
	else if wc eq 'zincwhite'
		ansi_wcr = 253
		ansi_wcg = 248
		ansi_wcb = 255
	else if wc eq 'coldgrey'
		ansi_wcr = 128
		ansi_wcg = 138
		ansi_wcb = 135
	else if wc eq 'slategrey'
		ansi_wcr = 112
		ansi_wcg = 128
		ansi_wcb = 144
	else if wc eq 'slategreydark'
		ansi_wcr = 47
		ansi_wcg = 79
		ansi_wcb = 79
	else if wc eq 'slategreylight'
		ansi_wcr = 119
		ansi_wcg = 136
		ansi_wcb = 153
	else if wc eq 'warmgrey'
		ansi_wcr = 128
		ansi_wcg = 128
		ansi_wcb = 105
	else if wc eq 'ivoryblack'
		ansi_wcr = 41
		ansi_wcg = 36
		ansi_wcb = 33
	else if wc eq 'lampblack'
		ansi_wcr = 46
		ansi_wcg = 71
		ansi_wcb = 59
	else if wc eq 'alizarincrimson'
		ansi_wcr = 227
		ansi_wcg = 38
		ansi_wcb = 54
	else if wc eq 'brick'
		ansi_wcr = 156
		ansi_wcg = 102
		ansi_wcb = 31
	else if wc eq 'cadmiumreddeep'
		ansi_wcr = 227
		ansi_wcg = 23
		ansi_wcb = 13
	else if wc eq 'corallight'
		ansi_wcr = 240
		ansi_wcg = 128
		ansi_wcb = 128
	else if wc eq 'deeppink'
		ansi_wcr = 255
		ansi_wcg = 20
		ansi_wcb = 147
	else if wc eq 'englishred'
		ansi_wcr = 212
		ansi_wcg = 61
		ansi_wcb = 26
	else if wc eq 'geraniumlake'
		ansi_wcr = 227
		ansi_wcg = 18
		ansi_wcb = 48
	else if wc eq 'hotpink'
		ansi_wcr = 255
		ansi_wcg = 105
		ansi_wcb = 180
	else if wc eq 'lightsalmon'
		ansi_wcr = 255
		ansi_wcg = 160
		ansi_wcb = 122
	else if wc eq 'madderlakedeep'
		ansi_wcr = 227
		ansi_wcg = 46
		ansi_wcb = 48
	else if wc eq 'pinklight'
		ansi_wcr = 255
		ansi_wcg = 182
		ansi_wcb = 193
	else if wc eq 'raspberry'
		ansi_wcr = 135
		ansi_wcg = 38
		ansi_wcb = 87
	else if wc eq 'rosemadder'
		ansi_wcr = 227
		ansi_wcg = 54
		ansi_wcb = 56
	else if wc eq 'tomato'
		ansi_wcr = 255
		ansi_wcg = 99
		ansi_wcb = 71
	else if wc eq 'venetianred'
		ansi_wcr = 212
		ansi_wcg = 26
		ansi_wcb = 31
	else if wc eq 'beige'
		ansi_wcr = 163
		ansi_wcg = 148
		ansi_wcb = 128
	else if wc eq 'brownmadder'
		ansi_wcr = 219
		ansi_wcg = 41
		ansi_wcb = 41
	else if wc eq 'brownochre'
		ansi_wcr = 135
		ansi_wcg = 66
		ansi_wcb = 31
	else if wc eq 'burlywood'
		ansi_wcr = 222
		ansi_wcg = 184
		ansi_wcb = 135
	else if wc eq 'burntsienna'
		ansi_wcr = 138
		ansi_wcg = 54
		ansi_wcb = 15
	else if wc eq 'burntumber'
		ansi_wcr = 138
		ansi_wcg = 51
		ansi_wcb = 36
	else if wc eq 'chocolate'
		ansi_wcr = 210
		ansi_wcg = 105
		ansi_wcb = 30
	else if wc eq 'deepochre'
		ansi_wcr = 115
		ansi_wcg = 61
		ansi_wcb = 26
	else if wc eq 'flesh'
		ansi_wcr = 255
		ansi_wcg = 125
		ansi_wcb = 64
	else if wc eq 'fleshochre'
		ansi_wcr = 255
		ansi_wcg = 87
		ansi_wcb = 33
	else if wc eq 'goldochre'
		ansi_wcr = 199
		ansi_wcg = 120
		ansi_wcb = 38
	else if wc eq 'greenishumber'
		ansi_wcr = 255
		ansi_wcg = 61
		ansi_wcb = 13
	else if wc eq 'khakidark'
		ansi_wcr = 189
		ansi_wcg = 183
		ansi_wcb = 107
	else if wc eq 'lightbeige'
		ansi_wcr = 245
		ansi_wcg = 245
		ansi_wcb = 220
	else if wc eq 'peru'
		ansi_wcr = 205
		ansi_wcg = 133
		ansi_wcb = 63
	else if wc eq 'rosybrown'
		ansi_wcr = 188
		ansi_wcg = 143
		ansi_wcb = 143
	else if wc eq 'rawsienna'
		ansi_wcr = 199
		ansi_wcg = 97
		ansi_wcb = 20
	else if wc eq 'rawumber'
		ansi_wcr = 115
		ansi_wcg = 74
		ansi_wcb = 18
	else if wc eq 'sepia'
		ansi_wcr = 94
		ansi_wcg = 38
		ansi_wcb = 18
	else if wc eq 'saddlebrown'
		ansi_wcr = 139
		ansi_wcg = 69
		ansi_wcb = 19
	else if wc eq 'vandykebrown'
		ansi_wcr = 94
		ansi_wcg = 38
		ansi_wcb = 5
	else if wc eq 'cadmiumorange'
		ansi_wcr = 255
		ansi_wcg = 97
		ansi_wcr = 3
	else if wc eq 'cadmiumredlight'
		ansi_wcr = 255
		ansi_wcg = 3
		ansi_wcb = 13
	else if wc eq 'carrot'
		ansi_wcr = 237
		ansi_wcg = 145
		ansi_wcb = 33
	else if wc eq 'darkorange'
		ansi_wcr = 255
		ansi_wcg = 140
		ansi_wcb = 0
	else if wc eq 'marsorange'
		ansi_wcr = 150
		ansi_wcg = 69
		ansi_wcb = 20
	else if wc eq 'marsyellow'
		ansi_wcr = 227
		ansi_wcg = 112
		ansi_wcb = 26
	else if wc eq 'yellowochre'
		ansi_wcr = 227
		ansi_wcg = 130
		ansi_wcb = 23
	else if wc eq 'aureolineyellow'
		ansi_wcr = 255
		ansi_wcg = 168
		ansi_wcb = 36
	else if wc eq 'banana'
		ansi_wcr = 227
		ansi_wcg = 207
		ansi_wcb = 87
	else if wc eq 'cadmiumlemon'
		ansi_wcr = 255
		ansi_wcg = 227
		ansi_wcb = 3
	else if wc eq 'cadmiumyellow'
		ansi_wcr = 255
		ansi_wcg = 153
		ansi_wcb = 18
	else if wc eq 'cadmiumyellowlight'
		ansi_wcr = 255
		ansi_wcg = 176
		ansi_wcb = 15
	else if wc eq 'goldenroddark'
		ansi_wcr = 184
		ansi_wcg = 134
		ansi_wcb = 11
	else if wc eq 'goldenrodlight'
		ansi_wcr = 250
		ansi_wcg = 250
		ansi_wcb = 210
	else if wc eq 'goldenrodpale'
		ansi_wcr = 238
		ansi_wcg = 232
		ansi_wcb = 170
	else if wc eq 'lightgoldenrod'
		ansi_wcr = 238
		ansi_wcg = 221
		ansi_wcb = 130
	else if wc eq 'melon'
		ansi_wcr = 227
		ansi_wcg = 168
		ansi_wcb = 105
	else if wc eq 'naplesyellowdeep'
		ansi_wcr = 255
		ansi_wcg = 168
		ansi_wcb = 18
	else if wc eq 'yellowlight'
		ansi_wcr = 255
		ansi_wcg = 255
		ansi_wcb = 224
	else if wc eq 'chartreuse'
		ansi_wcr = 127
		ansi_wcg = 255
		ansi_wcb = 0
	else if wc eq 'chromeoxidegreen'
		ansi_wcr = 102
		ansi_wcg = 128
		ansi_wcb = 20
	else if wc eq 'cinnabargreen'
		ansi_wcr = 97
		ansi_wcg = 179
		ansi_wcb = 41
	else if wc eq 'cobaltgreen'
		ansi_wcr = 61
		ansi_wcg = 145
		ansi_wcb = 64
	else if wc eq 'emeraldgreen'
		ansi_wcr = 0
		ansi_wcg = 201
		ansi_wcb = 87
	else if wc eq 'greendark'
		ansi_wcr = 0
		ansi_wcg = 100
		ansi_wcb = 0
	else if wc eq 'greenpale'
		ansi_wcr = 152
		ansi_wcg = 251
		ansi_wcb = 152
	else if wc eq 'lawngreen'
		ansi_wcr = 124
		ansi_wcg = 252
		ansi_wcb = 0
	else if wc eq 'mint'
		ansi_wcr = 189
		ansi_wcg = 252
		ansi_wcb = 201
	else if wc eq 'olive'
		ansi_wcr = 128
		ansi_wcg = 128
		ansi_wcb = 0
	else if wc eq 'olivedrab'
		ansi_wcr = 107
		ansi_wcg = 142
		ansi_wcb = 35
	else if wc eq 'olivegreendark'
		ansi_wcr = 85
		ansi_wcg = 107
		ansi_wcb = 47
	else if wc eq 'permanentgreen'
		ansi_wcr = 10
		ansi_wcg = 201
		ansi_wcb = 43
	else if wc eq 'sapgreen'
		ansi_wcr = 48
		ansi_wcg = 128
		ansi_wcb = 20
	else if wc eq 'seagreendark'
		ansi_wcr = 143
		ansi_wcg = 188
		ansi_wcb = 143
	else if wc eq 'seagreenmedium'
		ansi_wcr = 60
		ansi_wcg = 179
		ansi_wcb = 113
	else if wc eq 'seagreenlight'
		ansi_wcr = 32
		ansi_wcg = 178
		ansi_wcb = 170
	else if wc eq 'springgreenmedium'
		ansi_wcr = 0
		ansi_wcg = 250
		ansi_wcb = 154
	else if wc eq 'terreverte'
		ansi_wcr = 56
		ansi_wcg = 94
		ansi_wcb = 15
	else if wc eq 'viridianlight'
		ansi_wcr = 110
		ansi_wcg = 255
		ansi_wcb = 112
	else if wc eq 'aquamarinemedium'
		ansi_wcr = 102
		ansi_wcg = 205
		ansi_wcb = 170
	else if wc eq 'cyanwhite'
		ansi_wcr = 224
		ansi_wcg = 255
		ansi_wcb = 255
	else if wc eq 'turquoisedark'
		ansi_wcr = 0
		ansi_wcg = 206
		ansi_wcb = 209
	else if wc eq 'turquoisemedium'
		ansi_wcr = 72
		ansi_wcg = 209
		ansi_wcb = 204
	else if wc eq 'turquoisepale'
		ansi_wcr = 175
		ansi_wcg = 238
		ansi_wcb = 238
	else if wc eq 'aliceblue'
		ansi_wcr = 240
		ansi_wcg = 248
		ansi_wcb = 255
	else if wc eq 'bluelight'
		ansi_wcr = 173
		ansi_wcg = 216
		ansi_wcb = 230
	else if wc eq 'bluemedium'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 205
	else if wc eq 'cadet'
		ansi_wcr = 95
		ansi_wcg = 158
		ansi_wcb = 160
	else if wc eq 'cobalt'
		ansi_wcr = 61
		ansi_wcg = 89
		ansi_wcb = 171
	else if wc eq 'cornflower'
		ansi_wcr = 100
		ansi_wcg = 149
		ansi_wcb = 237
	else if wc eq 'cerulean'
		ansi_wcr = 5
		ansi_wcg = 184
		ansi_wcb = 204
	else if wc eq 'dodgerblue'
		ansi_wcr = 30
		ansi_wcg = 144
		ansi_wcb = 255
	else if wc eq 'indigo'
		ansi_wcr = 46
		ansi_wcg = 8
		ansi_wcb = 84
	else if wc eq 'manganeseblue'
		ansi_wcr = 3
		ansi_wcg = 168
		ansi_wcb = 158
	else if wc eq 'peacock'
		ansi_wcr = 51
		ansi_wcg = 161
		ansi_wcb = 201
	else if wc eq 'powderblue'
		ansi_wcr = 176
		ansi_wcg = 224
		ansi_wcb = 230
	else if wc eq 'royalblue'
		ansi_wcr = 65
		ansi_wcg = 105
		ansi_wcb = 225
	else if wc eq 'slatebluedark'
		ansi_wcr = 72
		ansi_wcg = 61
		ansi_wcb = 139
	else if wc eq 'slatebluelight'
		ansi_wcr = 132
		ansi_wcg = 112
		ansi_wcb = 255
	else if wc eq 'slatebluemedium'
		ansi_wcr = 123
		ansi_wcg = 104
		ansi_wcb = 238
	else if wc eq 'skybluedeep'
		ansi_wcr = 0
		ansi_wcg = 191
		ansi_wcb = 255
	else if wc eq 'skybluelight'
		ansi_wcr = 135
		ansi_wcg = 206
		ansi_wcb = 250
	else if wc eq 'steelbluelight'
		ansi_wcr = 176
		ansi_wcg = 196
		ansi_wcb = 222
	else if wc eq 'turquoiseblue'
		ansi_wcr = 0
		ansi_wcg = 199
		ansi_wcb = 140
	else if wc eq 'ultramarine'
		ansi_wcr = 18
		ansi_wcg = 10
		ansi_wcb = 143
	else if wc eq 'cobaltvioletdeep'
		ansi_wcr = 145
		ansi_wcg = 33
		ansi_wcb = 158
	else if wc eq 'orchiddark'
		ansi_wcr = 153
		ansi_wcg = 50
		ansi_wcb = 204
	else if wc eq 'orchidmedium'
		ansi_wcr = 186
		ansi_wcg = 85
		ansi_wcb = 211
	else if wc eq 'permanentredviolet'
		ansi_wcr = 219
		ansi_wcg = 38
		ansi_wcb = 69
	else if wc eq 'purple'
		ansi_wcr = 128
		ansi_wcg = 0
		ansi_wcb = 128
	else if wc eq 'purplemedium'
		ansi_wcr = 147
		ansi_wcg = 112
		ansi_wcb = 219
	else if wc eq 'ultramarineviolet'
		ansi_wcr = 92
		ansi_wcg = 36
		ansi_wcb = 110
	else if wc eq 'violetdark'
		ansi_wcr = 148
		ansi_wcg = 0
		ansi_wcb = 211
	else if wc eq 'violetredmedium'
		ansi_wcr = 199
		ansi_wcg = 21
		ansi_wcb = 133
	else if wc eq 'violetredpale'
		ansi_wcr = 219
		ansi_wcg = 112
		ansi_wcb = 147
	else if wc eq 'silver'
		ansi_wcr = 192
		ansi_wcg = 192
		ansi_wcb = 192
	else if wc eq 'fuchsia'
		ansi_wcr = 255
		ansi_wcg = 0
		ansi_wcb = 255
	else if wc eq 'lime'
		ansi_wcr = 0
		ansi_wcg = 255
		ansi_wcb = 0
	else if wc eq 'teal'
		ansi_wcr = 0
		ansi_wcg = 128
		ansi_wcb = 128
	else if wc eq 'aqua'
		ansi_wcr = 0
		ansi_wcg = 255
		ansi_wcb = 255
	else if wc eq 'slategray'
		ansi_wcr = 112
		ansi_wcg = 128
		ansi_wcb = 144
	else if wc eq 'lightslategray'
		ansi_wcr = 119
		ansi_wcg = 136
		ansi_wcb = 153
	else if wc eq 'lightslategrey'
		ansi_wcr = 119
		ansi_wcg = 136
		ansi_wcb = 153
	else if wc eq 'lightslateblue'
		ansi_wcr = 132
		ansi_wcg = 112
		ansi_wcb = 255
	else if wc eq 'deepskyblue'
		ansi_wcr = 0
		ansi_wcg = 191
		ansi_wcb = 255
	else if wc eq 'lightskyblue'
		ansi_wcr = 135
		ansi_wcg = 206
		ansi_wcb = 250
	else if wc eq 'paleturquoise'
		ansi_wcr = 175
		ansi_wcg = 238
		ansi_wcb = 238
	else if wc eq 'lightcyan'
		ansi_wcr = 224
		ansi_wcg = 255
		ansi_wcb = 255
	else if wc eq 'darkseagreen'
		ansi_wcr = 143
		ansi_wcg = 188
		ansi_wcb = 143
	else if wc eq 'lightseagreen'
		ansi_wcr = 32
		ansi_wcg = 178
		ansi_wcb = 170
	else if wc eq 'darkkhaki'
		ansi_wcr = 189
		ansi_wcg = 183
		ansi_wcb = 107
	else if wc eq 'palegoldenrod'
		ansi_wcr = 238
		ansi_wcg = 232
		ansi_wcb = 170
	else if wc eq 'lightgoldenrodyellow'
		ansi_wcr = 250
		ansi_wcg = 250
		ansi_wcb = 210
	else if wc eq 'lightyellow'
		ansi_wcr = 255
		ansi_wcg = 255
		ansi_wcb = 224
	else if wc eq 'darksalmon'
		ansi_wcr = 233
		ansi_wcg = 150
		ansi_wcb = 122
	else if wc eq 'lightcoral'
		ansi_wcr = 240
		ansi_wcg = 128
		ansi_wcb = 128
	else if wc eq 'lightpink'
		ansi_wcr = 255
		ansi_wcg = 182
		ansi_wcb = 193
	else if wc eq 'palevioletred'
		ansi_wcr = 219
		ansi_wcg = 112
		ansi_wcb = 147
	else if wc eq 'darkviolet'
		ansi_wcr = 148
		ansi_wcg = 0
		ansi_wcb = 211
	else if wc eq 'mediumpurple'
		ansi_wcr = 147
		ansi_wcg = 112
		ansi_wcb = 219
	else if wc eq 'snow1'
		ansi_wcr = 255
		ansi_wcg = 250
		ansi_wcb = 250
	else if wc eq 'snow2'
		ansi_wcr = 238
		ansi_wcg = 233
		ansi_wcb = 233
	else if wc eq 'snow3'
		ansi_wcr = 205
		ansi_wcg = 201
		ansi_wcb = 201
	else if wc eq 'snow4'
		ansi_wcr = 139
		ansi_wcg = 137
		ansi_wcb = 137
	else if wc eq 'seashell1'
		ansi_wcr = 255
		ansi_wcg = 245
		ansi_wcb = 238
	else if wc eq 'seashell2'
		ansi_wcr = 238
		ansi_wcg = 229
		ansi_wcb = 222
	else if wc eq 'seashell3'
		ansi_wcr = 205
		ansi_wcg = 197
		ansi_wcb = 191
	else if wc eq 'seashell4'
		ansi_wcr = 139
		ansi_wcg = 134
		ansi_wcb = 130
	else if wc eq 'antiquewhite1'
		ansi_wcr = 255
		ansi_wcg = 239
		ansi_wcb = 219
	else if wc eq 'antiquewhite2'
		ansi_wcr = 238
		ansi_wcg = 223
		ansi_wcb = 204
	else if wc eq 'antiquewhite3'
		ansi_wcr = 205
		ansi_wcg = 192
		ansi_wcb = 176
	else if wc eq 'antiquewhite4'
		ansi_wcr = 139
		ansi_wcg = 131
		ansi_wcb = 120
	else if wc eq 'bisque1'
		ansi_wcr = 255
		ansi_wcg = 228
		ansi_wcb = 196
	else if wc eq 'darkgrey'
		ansi_wcr = 169
		ansi_wcg = 169
		ansi_wcb = 169
	else if wc eq 'darkgray'
		ansi_wcr = 169
		ansi_wcg = 169
		ansi_wcb = 169
	else if wc eq 'darkblue'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 139
	else if wc eq 'darkcyan'
		ansi_wcr = 0
		ansi_wcg = 139
		ansi_wcb = 139
	else if wc eq 'darkmargenta'
		ansi_wcr = 139
		ansi_wcg = 0
		ansi_wcb = 139
	else if wc eq 'darkred'
		ansi_wcr = 139
		ansi_wcg = 0
		ansi_wcb = 0
	else if wc eq 'lightgreen'
		ansi_wcr = 144
		ansi_wcg = 238
		ansi_wcb = 144
	else if wc eq 'ochre'
		ansi_wcr = 204
		ansi_wcg = 119
		ansi_wcb = 34

		; hmm the original list has duplicates... TODO: remove/clean these up
	else if wc eq 'black'
		ansi_wcr = 0
		ansi_wcg = 0
		ansi_wcb = 0
	else if wc eq 'red'
		ansi_wcr = 194
		ansi_wcg = 54
		ansi_wcb = 33
	else if wc eq 'green'
		ansi_wcr = 37
		ansi_wcg = 188
		ansi_wcb = 36
	else if wc eq 'brown'
		ansi_wcr = 173
		ansi_wcg = 173
		ansi_wcb = 39
	else if wc eq 'blue'
		ansi_wcr = 73
		ansi_wcg = 46
		ansi_wcb = 225
	else if wc eq 'magenta'
		ansi_wcr = 211
		ansi_wcg = 56
		ansi_wcb = 211
	else if wc eq 'cyan'
		ansi_wcr = 51
		ansi_wcg = 187
		ansi_wcb = 200
	else if wc eq 'gray'
		ansi_wcr = 203
		ansi_wcg = 204
		ansi_wcb = 205
	else if wc eq 'darkgray'
		ansi_wcr = 131
		ansi_wcg = 131
		ansi_wcb = 131
	else if wc eq 'brightred'
		ansi_wcr = 252
		ansi_wcg = 57
		ansi_wcb = 31
	else if wc eq 'lightred'
		ansi_wcr = 252
		ansi_wcg = 57
		ansi_wcb = 31
	else if wc eq 'brightgreen'
		ansi_wcr = 49
		ansi_wcg = 231
		ansi_wcb = 34
	else if wc eq 'lightgreen'
		ansi_wcr = 49
		ansi_wcg = 231
		ansi_wcb = 34
	else if wc eq 'yellow'
		ansi_wcr = 234
		ansi_wcg = 236
		ansi_wcb = 35
	else if wc eq 'brightblue'
		ansi_wcr = 88
		ansi_wcg = 51	
		ansi_wcb = 255
	else if wc eq 'lightblue'
		ansi_wcr = 88
		ansi_wcg = 51
		ansi_wcb = 255
	else if wc eq 'brightmagenta'
		ansi_wcr = 249
		ansi_wcg = 53
		ansi_wcb = 248
	else if wc eq 'lightmagenta'
		ansi_wcr = 249
		ansi_wcg = 53
		ansi_wcb = 248
	else if wc eq 'brightcyan'
		ansi_wcr = 20
		ansi_wcg = 240
		ansi_wcb = 240
	else if wc eq 'lightcyan'
		ansi_wcr = 20
		ansi_wcg = 240
		ansi_wcb = 240
	else if wc eq 'white'
		ansi_wcr = 235
		ansi_wcg = 235
		ansi_wcb = 235
	else
		display 'ERROR ENCOUNTERED: ' # `wc # ' is surprisingly not in our ridiculous webcolor list.',13,10
		err
	end if
	ansi_wci_rgbi
}

macro ansi_rgbi reg*,red*,green*,blue* {
	ansi_wcr = red
	ansi_wcg = green
	ansi_wcb = blue
	ansi_wci_rgbi
	mov	reg, ansi_wci_val
}

macro ansi_colors reg*,fg*,bg* {
	ansi_wci fg
	ansi_colors_fg = ansi_wci_val
	ansi_wci bg
	mov	reg, (ansi_colors_fg shl 8) or ansi_wci_val
}
