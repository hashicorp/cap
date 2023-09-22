package saml

import "reflect"

// isNil reports if a is nil
func isNil(a any) bool {
	if a == nil {
		return true
	}
	switch reflect.TypeOf(a).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Chan, reflect.Slice, reflect.Func:
		return reflect.ValueOf(a).IsNil()
	}
	return false
}
