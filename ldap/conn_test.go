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
	}

	for test, answer := range testcases {
		res := EscapeValue(test)
		if res != answer {
			t.Errorf("Failed to escape %s: %s != %s\n", test, res, answer)
		}
	}
}
