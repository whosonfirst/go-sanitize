package sanitize

// https://github.com/exflickr/flamework/blob/master/www/include/lib_sanitize.php

import (
	"regexp"
)

func SanitizeString(input string) (string, error) {

	var output string
	var err error

	var pattern string

	output = input

	/*

		#
		# filter out evil codepoints
		#
		# U+0000..U+0008	00000000..00001000				\x00..\x08				[\x00-\x08]
		# U+000E..U+001F	00001110..00011111				\x0E..\x1F				[\x0E-\x1F]
		# U+007F..U+0084	01111111..10000100				\x7F,\xC2\x80..\xC2\x84			\x7F|\xC2[\x80-\x84\x86-\x9F]
		# U+0086..U+009F	10000110..10011111				\xC2\x86..\xC2\x9F			^see above^
		# U+FEFF		1111111011111111				\xEF\xBB\xBF				\xEF\xBB\xBF
		# U+206A..U+206F	10000001101010..10000001101111			\xE2\x81\xAA..\xE2\x81\xAF		\xE2\x81[\xAA-\xAF]
		# U+FFF9..U+FFFA	1111111111111001..1111111111111010		\xEF\xBF\xB9..\xEF\xBF\xBA		\xEF\xBF[\xB9-\xBA]
		# U+E0000..U+E007F	11100000000000000000..11100000000001111111	\xF3\xA0\x80\x80..\xF3\xA0\x81\xBF	\xF3\xA0[\x80-\x81][\x80-\xBF]
		# U+D800..U+DFFF	1101100000000000..1101111111111111		\xED\xA0\x80..\xED\xBF\xBF		\xED[\xA0-\xBF][\x80-\xBF]
		# U+110000..U+13FFFF	100010000000000000000..100111111111111111111	\xf4\x90\x80\x80..\xf4\xbf\xbf\xbf	\xf4[\x90-\xbf][\x80-\xbf][\x80-\xbf]
		#

	*/

	pattern = "[\x00-\x08]|[\x0E-\x1F]|\x7F|\xC2[\x80-\x84\x86-\x9F]|\xEF\xBB\xBF|\xE2\x81[\xAA-\xAF]|\xEF\xBF[\xB9-\xBA]|\xF3\xA0[\x80-\x81][\x80-\xBF]|\xED[\xA0-\xBF][\x80-\xBF]|\xf4[\x90-\xbf][\x80-\xbf][\x80-\xbf]"

	output, err = scrub(pattern, input)

	if err != nil {
		return "", err
	}

	sanitize_strip_reserved := false // make me an input thingy...
	allow_newlines := false          // sudo make me an input thingy

	if sanitize_strip_reserved {

		pattern = "\\p{Cn}" // FIX ME
		output, err = scrub(pattern, input)

	} else {

		pattern = "((\xF4\x8F|\xEF|\xF0\x9F|\xF0\xAF|\xF0\xBF|((\xF1|\xF2|\xF3)(\x8F|\x9F|\xAF|\xBF)))\xBF(\xBE|\xBF))|\xEF\xB7[\x90-\xAF]"
		output, err = scrub(pattern, input)
	}

	if err != nil {
		return "", err
	}

	lf := " "
	ff := " "

	if allow_newlines {
		lf = "\n"
		ff = "\n\n"
	}

	lookup := map[string]string{
		"\xE2\x80\xA8": lf, // U+2028
		"\xE2\x80\xA9": ff, // U+2029
		"\xC2\x85":     lf, // EBCDIC Next Line / NEL
		"\x09":         " ",
		"\x0B":         ff,
		"\x0C":         ff,
		"\r\n":         lf,
		"\r":           lf,
		"\n":           lf,
		"\xEF\xBF\xBC": "?", // U+FFFC
		"\xEF\xBF\xBD": "?", // U+FFFD
	}

	_, ok := lookup["bueller"]

	if ok {

	}

	// PLEASE MAKE ME WORK (where $map == lookup)
	// $input = str_replace(array_keys($map), $map, $input);

	return output, nil
}

func SanitizeStripOverlong(input string) (string, error) {

	/*

		#
		# invalid bytes: C0-C1, F5-FF
		# overlong 3 bytes: E0[80-9F][80-BF]
		# overlong 4 bytes: F0[80-8F][80-BF][80-BF]
		#

	*/

	pattern := "[\xC0-\xC1\xF5-\xFF]|\xE0[\x80-\x9F][\x80-\xbf]|\xF0[\x80-\x8F][\x80-\xBF][\x80-\xBF]"
	return scrub(input, pattern)
}

func SanitizeCleanUTF8(input string) (string, error) {

	var pattern string

	pattern = ""
	pattern += "([\xC0-\xC1\xF5-\xFF])"                             // invalid bytes
	pattern += "|([\xC0-\xDF](?=[^\x80-\xBF]|$))"                   // 1-leader without a trailer
	pattern += "|([\xE0-\xEF](?=[\x80-\xBF]{0,1}([^\x80-\xBF]|$)))" // 2-leader without 2 trailers
	pattern += "|([\xF0-\xF7](?=[\x80-\xBF]{0,2}([^\x80-\xBF]|$)))" // 3-leader without 3 trailers
	pattern += "|((?<=[\x00-\x7F]|^)[\x80-\xBF]+)"                  // trailer following a non-leader
	pattern += "|((?<=[\xC0-\xDF][\x80-\xBF]{1})[\x80-\xBF]+)"      // 1 leader with too many trailers
	pattern += "|((?<=[\xE0-\xEF][\x80-\xBF]{2})[\x80-\xBF]+)"      // 2 leader with too many trailers
	pattern += "|((?<=[\xF0-\xF7][\x80-\xBF]{3})[\x80-\xBF]+)"      // 3 leader with too many trailers
	pattern += "|(\xE0[\x80-\x9F])"                                 // overlong 3-byte
	pattern += "|(\xF0[\x80-\x8F])"                                 // overlong 4-byte

	tmp, err := scrub(input, pattern)

	if err != nil {
		return "", err
	}

	/*

		#
		# one of the reasons this is even slower than it needs to be is that
		# we have to apply it twice. seems to be related to overlapping
		# assertions, but that shouldn't be the case. argh!
		#

	*/

	return scrub(tmp, pattern)
}

func scrub(input string, pattern string) (string, error) {

	re := regexp.MustCompile(pattern)

	output := re.ReplaceAllString(input, "")
	return output, nil
}
