package render_test

type texts struct {
	name   string
	values []string
}

// hostile is text chosen to upset text/tabwriter or a terminal.
func hostile() []texts {
	chosen := []string{
		"", " ", "plain", "two words", "trailing ", " leading", `"`, `\`, `"quoted"`,
		"\xff", "\xff\xff", "a\xffb", "a\xffb\xff", "\xffa\tb\nc\xff", "\xff\t\xff\n",
		"\t", "a\tb", "\n", "a\nb", "a\r\nb", "\v", "\f", "\r", "\x00", "\x1b[2J", "\x7f",
		"<b>&amp;</b>", "\u0085", "\u009b", "\u202e", "\u2028", "é", "証拠", "e\u0301",
	}
	var alone, inside []string
	for b := byte(0); ; b++ {
		alone = append(alone, string([]byte{b}))
		inside = append(inside, string([]byte{'a', b, 'z'}))
		if b == 0xff {
			break
		}
	}
	// Every sequence of one to three of the bytes that tabwriter, a terminal or UTF-8 treat specially.
	const special = "\xff\t\n\v\f\r\x1b \"\\a\xc3\xa9\x80"
	sequences := []string{""}
	for begin := 0; len(sequences[begin]) < 3; begin++ {
		for i := range len(special) {
			sequences = append(sequences, sequences[begin]+special[i:i+1])
		}
	}
	return []texts{
		{"chosen", chosen},
		{"every byte alone", alone},
		{"every byte inside text", inside},
		{"sequences of special bytes", sequences[1:]},
	}
}
