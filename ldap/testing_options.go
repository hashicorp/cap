package ldap

// TestOption defines a common functional options type which can be used in a
// variadic parameter pattern.
type TestOption func(interface{})

// getTestOpts gets the test defaults and applies the opt
// overrides passed in
func getTestOpts(t TestingT, opt ...TestOption) testOptions {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	opts := testDefaults(t)
	testApplyOpts(&opts, opt...)
	return opts
}

// testApplyOpts takes a pointer to the options struct as a set of default options
// and applies the slice of opts as overrides.
func testApplyOpts(opts interface{}, opt ...TestOption) {
	for _, o := range opt {
		if o == nil { // ignore any nil Options
			continue
		}
		o(opts)
	}
}

// testOptions are the set of available options for test functions
type testOptions struct {
	withTokenGroupSIDs [][]byte
	withMembersOf      []string
	withDefaults       *TestDefaults
}

func testDefaults(t TestingT) testOptions {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return testOptions{
		withDefaults: &TestDefaults{
			UserAttr:  DefaultUserAttr,
			GroupAttr: DefaultGroupAttr,
			UserDN:    TestDefaultUserDN,
			GroupDN:   TestDefaultGroupDN,
		},
	}
}

// TestDefaults define a type for composing all the defaults for tests
type TestDefaults struct {
	UserAttr string

	GroupAttr string
	// UserDN is the base distinguished name to use when searching for users
	// which is "ou=people,dc=example,dc=org" by default
	UserDN string

	// GroupDN is the base distinguished name to use when searching for groups
	// which is "ou=groups,dc=example,dc=org" by default
	GroupDN string

	// UPNDomain is the userPrincipalName domain, which enables a
	// userPrincipalDomain login with [username]@UPNDomain (optional)
	UPNDomain string
}

// WithTestDefaults provides an option to provide a set of defaults with
// overrides for tests.
func WithTestDefaults(t TestingT, defaults *TestDefaults) TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testOptions); ok {
			if defaults != nil {
				if defaults.UserAttr != "" {
					o.withDefaults.UserAttr = defaults.UserAttr
				}
				if defaults.GroupAttr != "" {
					o.withDefaults.GroupAttr = defaults.GroupAttr
				}
				if defaults.UserDN != "" {
					o.withDefaults.UserDN = defaults.UserDN
				}
				if defaults.GroupDN != "" {
					o.withDefaults.GroupDN = defaults.GroupDN
				}
				if defaults.UPNDomain != "" {
					o.withDefaults.UPNDomain = defaults.UPNDomain
				}
			}
		}
	}
}

// WithTestMembersOf specifies optional test memberOf attributes for user
// entries
func WithTestMembersOf(t TestingT, membersOf ...string) TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testOptions); ok {
			o.withMembersOf = membersOf
		}
	}
}

// WithTestTokenGroups specifies optional test tokenGroups SID attributes for user
// entries
func WithTestTokenGroups(t TestingT, tokenGroupSID ...[]byte) TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testOptions); ok {
			o.withTokenGroupSIDs = tokenGroupSID
		}
	}
}
