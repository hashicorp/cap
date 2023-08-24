// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"testing"
)

var testcases = map[string]string{
	"#test":                      "\\#test",
	"test,hello":                 "test\\,hello",
	"test,hel+lo":                "test\\,hel\\+lo",
	"test\\hello":                "test\\\\hello",
	"  test  ":                   "\\  test \\ ",
	"":                           "",
	`\`:                          `\\`,
	"trailing\000":               `trailing\00`,
	"mid\000dle":                 `mid\00dle`,
	"\000":                       `\00`,
	"multiple\000\000":           `multiple\00\00`,
	"backlash-before-null\\\000": `backlash-before-null\\\00`,
	"trailing\\":                 `trailing\\`,
	"double-escaping\\>":         `double-escaping\\\>`,
}

func Test_EscapeValue(t *testing.T) {
	for test, answer := range testcases {
		res := escapeValue(test)
		if res != answer {
			t.Errorf("Failed to escape %q: %q != %q\n", test, res, answer)
		}
	}
}

// Fuzz_EscapeValue is only focused on finding panics
func Fuzz_EscapeValue(f *testing.F) {
	for tc, _ := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = escapeValue(s)
	})
}
