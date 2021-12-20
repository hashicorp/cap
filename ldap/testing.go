package ldap

import (
	"fmt"
	"sort"
)

// TestEntry represents a test entry
type TestEntry struct {
	// DN is the distinguished name of the entry
	DN string
	// Attributes are the returned attributes for the entry
	Attributes []*TestEntryAttribute
}

// TestEntryAttribute holds a single attribute
type TestEntryAttribute struct {
	// Name is the name of the attribute
	Name string
	// Values contain the string values of the attribute
	Values []string
	// ByteValues contain the raw values of the attribute
	ByteValues [][]byte
}

// getAttributeValues returns the values for the named attribute, or an empty list
func (e *TestEntry) getAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.Values
		}
	}
	return []string{}
}

// NewTestEntry returns an Entry object with the specified distinguished name and attribute key-value pairs.
// The map of attributes is accessed in alphabetical order of the keys in order to ensure that, for the
// same input map of attributes, the output entry will contain the same order of attributes
func NewTestEntry(dn string, attributes map[string][]string) *TestEntry {
	var attributeNames []string
	for attributeName := range attributes {
		attributeNames = append(attributeNames, attributeName)
	}
	sort.Strings(attributeNames)

	var encodedAttributes []*TestEntryAttribute
	for _, attributeName := range attributeNames {
		encodedAttributes = append(encodedAttributes, newTestEntryAttribute(attributeName, attributes[attributeName]))
	}
	return &TestEntry{
		DN:         dn,
		Attributes: encodedAttributes,
	}
}

// newTestEntryAttribute returns a new EntryAttribute with the desired key-value pair
func newTestEntryAttribute(name string, values []string) *TestEntryAttribute {
	var bytes [][]byte
	for _, value := range values {
		bytes = append(bytes, []byte(value))
	}
	return &TestEntryAttribute{
		Name:       name,
		Values:     values,
		ByteValues: bytes,
	}
}

// TestMemberOf creates test memberOf attributes which can be assigned to user
// entries.  Supported Options: WithTestDefaults
func TestMemberOf(t TestingT, groupNames []string, opt ...TestOption) []string {
	opts := getTestOpts(t, opt...)
	DNs := make([]string, 0, len(groupNames))
	for _, n := range groupNames {
		DNs = append(DNs, fmt.Sprintf("%s=%s,%s", opts.withDefaults.GroupAttr, n, opts.withDefaults.GroupDN))
	}
	return DNs
}

// TestUsers creates tests user entries.  Options supported: WithTestDefaults, WithTestMembersOf
func TestUsers(t TestingT, userNames []string, opt ...TestOption) []*TestEntry {
	opts := getTestOpts(t, opt...)

	entries := make([]*TestEntry, 0, len(userNames))
	for _, n := range userNames {
		entryAttrs := map[string][]string{
			"name":     {n},
			"email":    {fmt.Sprintf("%s@example.com", n)},
			"password": {"password"},
		}
		if len(opts.withMembersOf) > 0 {
			entryAttrs["memberOf"] = opts.withMembersOf
		}
		if len(opts.withTokenGroupSIDs) > 0 {
			groups := make([]string, 0, len(opts.withTokenGroupSIDs))
			for _, s := range opts.withTokenGroupSIDs {
				groups = append(groups, string(s))
			}
			entryAttrs["tokenGroups"] = groups
		}
		var DN string
		switch {
		case opts.withDefaults.UPNDomain != "":
			DN = fmt.Sprintf("userPrincipalName=%s@%s,%s", n, opts.withDefaults.UPNDomain, opts.withDefaults.UserDN)
		default:
			DN = fmt.Sprintf("%s=%s,%s", opts.withDefaults.UserAttr, n, opts.withDefaults.UserDN)
		}
		entries = append(entries,
			NewTestEntry(
				DN,
				entryAttrs,
			),
		)
	}
	return entries
}

// TestGroup creates a test group entry.  Options supported: WithTestDefaults
func TestGroup(t TestingT, groupName string, memberNames []string, opt ...TestOption) *TestEntry {
	opts := getTestOpts(t, opt...)

	members := make([]string, 0, len(memberNames))
	for _, n := range memberNames {
		var DN string
		switch {
		case opts.withDefaults.UPNDomain != "":
			DN = fmt.Sprintf("userPrincipalName=%s@%s,%s", n, opts.withDefaults.UPNDomain, opts.withDefaults.UserDN)
		default:
			DN = fmt.Sprintf("%s=%s,%s", opts.withDefaults.UserAttr, n, opts.withDefaults.UserDN)
		}
		members = append(members, DN)
	}
	return NewTestEntry(
		fmt.Sprintf("%s=%s,%s", opts.withDefaults.GroupAttr, groupName, opts.withDefaults.GroupDN),
		map[string][]string{
			"member": members,
		})
}
