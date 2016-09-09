package sanitize

// https://github.com/exflickr/flamework/blob/master/www/include/lib_sanitize.php
// https://blog.golang.org/strings
// https://golang.org/pkg/regexp/syntax/
// http://www.fileformat.info/info/unicode/char/search.htm
// http://www.regular-expressions.info/unicode.html

import (
	"errors"
	_ "log"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var re_evil *regexp.Regexp
var re_reserved *regexp.Regexp
var re_invalid *regexp.Regexp

func init() {

	/*

			evil codepoints, lib_sanitize says:

				U+0000..U+0008		00000000..00001000				\x00..\x08				[\x00-\x08]
				U+000E..U+001F		00001110..00011111				\x0E..\x1F				[\x0E-\x1F]
				U+007F..U+0084		01111111..10000100				\x7F,\xC2\x80..\xC2\x84			\x7F|\xC2[\x80-\x84\x86-\x9F]
				U+0086..U+009F		10000110..10011111				\xC2\x86..\xC2\x9F			^see above^

				go-sanitize says we are actually doing this for "U+0086..U+009F" (20160909/thisisaaronland)

		                "\\x7F",
		                "(?:\\x7F|\\xC2)?[\\x80-\\x84\\x86-\\x9F]",

				lib_sanitize goes on to say:

				U+FEFF			1111111011111111				\xEF\xBB\xBF				\xEF\xBB\xBF
				U+206A..U+206F		10000001101010..10000001101111			\xE2\x81\xAA..\xE2\x81\xAF		\xE2\x81[\xAA-\xAF]
				U+FFF9..U+FFFA		1111111111111001..1111111111111010		\xEF\xBF\xB9..\xEF\xBF\xBA		\xEF\xBF[\xB9-\xBA]

				go-sanitize says we aren't able to match '1111111111111001 U+FFF9 '\ufff9'  ef  bf  b9' because... I have no
				idea (20160909/thisisaaronland)

				lib_sanitize goes on to say:

				U+E0000..U+E007F	11100000000000000000..11100000000001111111	\xF3\xA0\x80\x80..\xF3\xA0\x81\xBF	\xF3\xA0[\x80-\x81][\x80-\xBF]

				go-sanitize says we aren't able to match '11100000000000000000 U+E0000 '\U000e0000'  f3  a0  80  80'
				through '11100000000001111110 U+E007E '\U000e007e'  f3  a0  81  be' because... again, I am not really
				sure (20160909/thisisaaronland)

				lib_sanitize goes on to say:

				U+D800..U+DFFF		1101100000000000..1101111111111111		\xED\xA0\x80..\xED\xBF\xBF		\xED[\xA0-\xBF][\x80-\xBF]
				U+110000..U+13FFFF	100010000000000000000..100111111111111111111	\xf4\x90\x80\x80..\xf4\xbf\xbf\xbf	\xf4[\x90-\xbf][\x80-\xbf][\x80-\xbf]

	*/

	evil_codepoints := []string{
		"[\\x00-\\x08]",
		"[\\x0E-\\x1F]",
		"\\x7F", // deviates from lib_sanitize
		"(?:\\x7F|\\xC2)?[\\x80-\\x84\\x86-\\x9F]", // deviates from lib_sanitize
		"\\xEF\\xBB\\xBF",
		"\\xE2\\x81[\\xAA-\\xAF]",
		"\\xEF\\xBF[\\xB9-\\xBA]",              // does not always work (see above)
		"\\xF3\\xA0[\\x80-\\x81][\\x80-\\xBF]", // does not always work (see above)
		"\\xED[\\xA0-\\xBF][\\x80-\\xBF]",
		"\\xF4[\\x90-\\xbf][\\x80-\\xbf][\\x80-\\xbf]",
	}

	re_evil = regexp.MustCompile(strings.Join(evil_codepoints, "|"))

	/*

		reserved characters

		lib_sanitize says \p{Cn} as in \p{Unassigned} however Go recognized neither of those as
		valid character class ranges so we have to settle for the entirety of the \p{Other}
		range which is inclusive of things like control character (trapped above) and private
		use characters and so on... computers, right? (20160909/thisisaaronland)

	*/

	re_reserved = regexp.MustCompile(`\p{C}`)

	/*

		invalid characters, as in:

			s := "\xF0\xBF"
			r,_ := utf8.DecodeRuneInString(s)
			fmt.Printf("%+q\n", r)
			fmt.Printf("%.8b\n", r)

			1111111111111101	\ufffd		F4 8F (and so on...)

	*/

	re_invalid = regexp.MustCompile("((\\xF4\\x8F|\\xEF|\\xF0\\x9F|\\xF0\\xAF|\\xF0\\xBF|((\\xF1|\\xF2|\\xF3)(\\x8F|\\x9F|\\xAF|\\xBF)))\\xBF(\\xBE|\\xBF))|\\xEF\\xB7[\\x90-\\xAF]")

	/*

		linefeed character regular expressions are defined at runtime below

	*/
}

type Options struct {
	StripReserved      bool
	AllowNewlines      bool
	replacementString  string
	replacementTab     string
	replacementLF      string
	replacementFF      string
	replacementUnknown string
}

func DefaultOptions() *Options {

	o := Options{
		StripReserved:      false,
		AllowNewlines:      false,
		replacementString:  "",
		replacementLF:      " ",
		replacementFF:      " ",
		replacementTab:     " ",
		replacementUnknown: "?",
	}

	return &o
}

func DebugOptions() *Options {

	o := Options{
		StripReserved:      false,
		AllowNewlines:      false,
		replacementString:  " { SANITIZED } ",
		replacementLF:      " { SANITIZED } ",
		replacementFF:      " { SANITIZED } ",
		replacementTab:     " { SANITIZED } ",
		replacementUnknown: " { SANITIZED } ",
	}

	return &o
}

func SanitizeString(input string, options *Options) (string, error) {

	if !utf8.ValidString(input) {
		return "", errors.New("Invalid UTF8 string")
	}

	output := input

	output = re_evil.ReplaceAllString(output, options.replacementString)

	if options.StripReserved {

		output = re_reserved.ReplaceAllString(output, options.replacementString)

	} else {

		output = re_invalid.ReplaceAllString(output, options.replacementString)
	}

	lf := options.replacementLF
	ff := options.replacementLF

	if options.AllowNewlines {
		lf = "\n"
		ff = "\n\n"
	}

	lookup := map[string]string{
		"\xE2\x80\xA8": lf, // U+2028
		"\xE2\x80\xA9": ff, // U+2029
		"\xC2\x85":     lf, // EBCDIC Next Line / NEL
		"\x09":         options.replacementTab,
		"\x0B":         ff,
		"\x0C":         ff,
		"\r\n":         lf,
		"\r":           lf,
		"\n":           lf,
		"\xEF\xBF\xBC": options.replacementUnknown, // U+FFFC
		"\xEF\xBF\xBD": options.replacementUnknown, // U+FFFD
	}

	lookup_keys := make([]string, 0)

	for k, _ := range lookup {
		lookup_keys = append(lookup_keys, k)
	}

	re_linefeeds := regexp.MustCompile(strings.Join(lookup_keys, "|"))

	cb_linefeeds := func(s string) string {
		return lookup[s]
	}

	output = re_linefeeds.ReplaceAllStringFunc(output, cb_linefeeds)

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
