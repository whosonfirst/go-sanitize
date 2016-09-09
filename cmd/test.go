package main

// This file will be deleted when the dust settles (20160909/thisisaaronland)

import (
	"fmt"
	"os"
	"sanitize"
	_ "unicode"
	"strconv"
)

func main() {

	opts := sanitize.DebugOptions()

	codepoints := [][]string{
	       { "00000000", "00001000" },
	       { "00001110", "00011111" },
	       { "01111111", "10000100" },
	       { "10000110", "10011111" },
	       { "1111111011111111", "1111111011111111" },
	       { "1111111111111001", "1111111111111010" },
	       { "11100000000000000000", "11100000000001111111" },
	       { "1101100000000000", "1101111111111111" },
	       { "100010000000000000000", "100111111111111111111" },
	}

	for _, pair := range codepoints {
	
	lo, _ := strconv.ParseUint(pair[0], 2, 32)
	hi, _ := strconv.ParseUint(pair[1], 2, 32)	

	// fmt.Println("#", lo, hi)
	
	for i := lo; i < hi; i++ {
	
		r := rune(i)
		c, _ := sanitize.SanitizeString(string(r), opts)

		if c != " { SANITIZED } " {
		   fmt.Printf("%b %U '%s'\n", r, r, c)
		}
	}
	}
	os.Exit(0)
	
	input := "foo bar\nbaz ok: '\u2318' BAD:'\u0007' BAD:'\uFEFF' BAD:'\u2029' BAD:'\u0007' BAD:'\u007F' BAD:'\x0B' woop wwoop"

	for index, runeValue := range input {

		s, _ := sanitize.SanitizeString(string(runeValue), opts)
		fmt.Printf("%#U starts at byte position %d becomes '%s'\n", runeValue, index, s)
	}

	output, _ := sanitize.SanitizeString(input, opts)
	fmt.Println(output)
}
