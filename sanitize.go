package sanitize

// https://github.com/exflickr/flamework/blob/master/www/include/lib_sanitize.php
// https://blog.golang.org/strings
// https://golang.org/pkg/regexp/syntax/

import (
	"errors"
	_ "log"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Options struct {
	StripReserved     bool
	AllowNewlines     bool
	replacementString string
}

func DefaultOptions() *Options {

	o := Options{
		StripReserved:     false,
		AllowNewlines:     false,
		replacementString: "",
	}

	return &o
}

func DebugOptions() *Options {

	o := Options{
		StripReserved:     false,
		AllowNewlines:     false,
		replacementString: " { SANITIZED } ",
	}

	return &o
}

func SanitizeString(input string, options *Options) (string, error) {

	if !utf8.ValidString(input) {
		return "", errors.New("Invalid UTF8 string")
	}

	var output string
	var err error

	var pattern string

	output = input

	/*

		lib_sanitize says:
		filter out evil codepoints

		U+0000..U+0008		00000000..00001000				\x00..\x08				[\x00-\x08]
		U+000E..U+001F		00001110..00011111				\x0E..\x1F				[\x0E-\x1F]
		U+007F..U+0084		01111111..10000100				\x7F,\xC2\x80..\xC2\x84			\x7F|\xC2[\x80-\x84\x86-\x9F]
		U+0086..U+009F		10000110..10011111				\xC2\x86..\xC2\x9F			^see above^
		U+FEFF			1111111011111111				\xEF\xBB\xBF				\xEF\xBB\xBF
		U+206A..U+206F		10000001101010..10000001101111			\xE2\x81\xAA..\xE2\x81\xAF		\xE2\x81[\xAA-\xAF]
		U+FFF9..U+FFFA		1111111111111001..1111111111111010		\xEF\xBF\xB9..\xEF\xBF\xBA		\xEF\xBF[\xB9-\xBA]
		U+E0000..U+E007F	11100000000000000000..11100000000001111111	\xF3\xA0\x80\x80..\xF3\xA0\x81\xBF	\xF3\xA0[\x80-\x81][\x80-\xBF]
		U+D800..U+DFFF		1101100000000000..1101111111111111		\xED\xA0\x80..\xED\xBF\xBF		\xED[\xA0-\xBF][\x80-\xBF]
		U+110000..U+13FFFF	100010000000000000000..100111111111111111111	\xf4\x90\x80\x80..\xf4\xbf\xbf\xbf	\xf4[\x90-\xbf][\x80-\xbf][\x80-\xbf]

	*/

	evil_codepoints := []string{
		"[\\x00-\\x08]",
		"[\\x0E-\\x1F]",
		"\\x7F",
		"\\xC2[\\x80-\\x84\\x86-\\x9F]",
		"\\xEF\\xBB\\xBF",
		"\\xE2\\x81[\\xAA-\\xAF]",
		"\\xEF\\xBF[\\xB9-\\xBA]",
		"\\xF3\\xA0[\\x80-\\x81][\\x80-\\xBF]",
		"\\xED[\\xA0-\\xBF][\\x80-\\xBF]",
		"\\xF4[\\x90-\\xbf][\\x80-\\xbf][\\x80-\\xbf]",
	}

	pattern = strings.Join(evil_codepoints, "|")

	output, err = scrub(output, pattern, options.replacementString)

	if err != nil {
		return "", err
	}

	if options.StripReserved {

		pattern = "\\p{Cn}"
		output, err = scrub(output, pattern, options.replacementString)

	} else {

		pattern = "((\\xF4\\x8F|\\xEF|\\xF0\\x9F|\\xF0\\xAF|\\xF0\\xBF|((\\xF1|\\xF2|\\xF3)(\\x8F|\\x9F|\\xAF|\\xBF)))\\xBF(\\xBE|\\xBF))|\\xEF\\xB7[\\x90-\\xAF]"
		output, err = scrub(output, pattern, options.replacementString)
	}

	if err != nil {
		return "", err
	}

	lf := options.replacementString
	ff := options.replacementString

	if options.AllowNewlines {
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

	lookup_keys := make([]string, 0)

	for k, _ := range lookup {
		lookup_keys = append(lookup_keys, k)
	}

	pattern = strings.Join(lookup_keys, "|")

	repl := func(s string) string {
		return lookup[s]
	}

	re := regexp.MustCompile(pattern)
	output = re.ReplaceAllStringFunc(output, repl)

	return output, nil
}

func SanitizeInt32(input string) (int32, error) {

	output, err := strconv.ParseInt(input, 10, 32)

	if err != nil {
		return 0, err
	}

	return int32(output), nil
}

func SanitizeInt64(input string) (int64, error) {

	return strconv.ParseInt(input, 10, 64)
}

func SanitizeFloat64(input string) (float64, error) {

	return strconv.ParseFloat(input, 64)
}

/*
	To-do: When the dust settles compile all the regular expressions during init
	and remove this function (20160909/thisisaaronland)
*/

func scrub(input string, pattern string, repl string) (string, error) {

	re := regexp.MustCompile(pattern)
	output := re.ReplaceAllString(input, repl)
	return output, nil
}
