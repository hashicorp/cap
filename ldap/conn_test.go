// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import "testing"

func Test_EscapeValue(t *testing.T) {
	testcases := map[string]string{
		"#test":       "\\#test",
		"test,hello":  "test\\,hello",
		"test,hel+lo": "test\\,hel\\+lo",
		"test\\hello": "test\\\\hello",
		"  test  ":    "\\  test \\ ",
		"":            "",
		`\`:           `\`,
		"golang\000":  `golang\00`,
		"go\000lang":  `go\00lang`,
		"\000":        `\00`,
	}

	for test, answer := range testcases {
		res := EscapeValue(test)
		if res != answer {
			t.Errorf("Failed to escape %q: %q != %q\n", test, res, answer)
		}
	}
}
