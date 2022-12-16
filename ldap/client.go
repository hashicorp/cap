package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"html/template"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
)

const (
	schemeLDAP    = "ldap"
	schemeLDAPTLS = "ldaps"
)

// Client provides a client for making requests to a directory service.
type Client struct {
	conf *ClientConfig
	conn *ldap.Conn
}

// Warning is a warning message
type Warning string

func fmtWarning(format string, a ...interface{}) Warning {
	return Warning(fmt.Sprintf(format, a...))
}

// NewClient will create a new client from the configuration.  The following
// defaults will be used if no config value is provided for them:
//   - URLs:			see constant DefaultURL
//   - UserAttr: 		see constant DefaultUserAttr
//   - GroupAttr: 		see constant DefaultGroupAttr
//   - GroupFilter: 		see constant DefaultGroupFilter
//   - TLSMinVersion: 	see constant DefaultTLSMinVersion
//   - TLSMaxVersion: 	see constant DefaultTLSMaxVersion
func NewClient(ctx context.Context, conf *ClientConfig) (*Client, error) {
	const op = "ldap.NewClient"
	if conf == nil {
		return nil, fmt.Errorf("%s: missing config: %w", op, ErrInvalidParameter)
	}
	clientConf, err := conf.clone()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if len(clientConf.URLs) == 0 {
		clientConf.URLs = []string{DefaultURL}
	}
	if clientConf.GroupAttr == "" {
		clientConf.GroupAttr = DefaultGroupAttr
	}
	if clientConf.GroupFilter == "" {
		clientConf.GroupFilter = DefaultGroupFilter
	}
	if clientConf.TLSMinVersion == "" {
		clientConf.TLSMinVersion = DefaultTLSMinVersion
	}
	if clientConf.TLSMaxVersion == "" {
		clientConf.TLSMaxVersion = DefaultTLSMaxVersion
	}
	if clientConf.UserAttr == "" {
		clientConf.UserAttr = DefaultUserAttr
	}
	if err := clientConf.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Client{
		conf: clientConf,
	}, nil
}

// connect will connect to a directory server using the URLs from the config or
// the WithURLs option.  It will attempt   Supports options: WithDialer, WithURLs
func (c *Client) connect(ctx context.Context, opt ...Option) error {
	const op = "ldap.(Client).connect"
	if c.conf == nil {
		return fmt.Errorf("%s: missing configuration: %w", op, ErrInternal)
	}
	opts := getConfigOpts(opt...)
	if len(c.conf.URLs) == 0 && len(opts.withURLs) == 0 {
		return fmt.Errorf("%s: missing both configuration and optional LDAP URLs: %w", op, ErrInvalidParameter)
	}
	if len(opts.withURLs) == 0 {
		opts.withURLs = c.conf.URLs
	}
	var retErr *multierror.Error
	var conn *ldap.Conn
	for _, uut := range opts.withURLs {
		u, err := url.Parse(uut)
		if err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("%s: error parsing url %q: %w", op, uut, err))
			continue
		}
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			host = u.Host
		}
		var tlsConfig *tls.Config
		switch u.Scheme {
		case schemeLDAP:
			conn, err = ldap.DialURL(uut)
			if err != nil {
				break
			}
			if conn == nil {
				err = fmt.Errorf("%s: empty connection after dialing: %w", op, ErrUnknown)
				break
			}
			if c.conf.StartTLS {
				tlsConfig, err = getTLSConfig(
					host,
					withInsecureTLS(c.conf.InsecureTLS),
					withTLSMinVersion(c.conf.TLSMinVersion),
					withTLSMaxVersion(c.conf.TLSMaxVersion),
					withCertificate(c.conf.Certificate),
					withClientTLSCert(c.conf.ClientTLSCert),
					withClientTLSKey(c.conf.ClientTLSKey),
				)
				if err != nil {
					break
				}
				err = conn.StartTLS(tlsConfig)
			}
		case schemeLDAPTLS:
			tlsConfig, err = getTLSConfig(
				host,
				withInsecureTLS(c.conf.InsecureTLS),
				withTLSMinVersion(c.conf.TLSMinVersion),
				withTLSMaxVersion(c.conf.TLSMaxVersion),
				withCertificate(c.conf.Certificate),
				withClientTLSCert(c.conf.ClientTLSCert),
				withClientTLSKey(c.conf.ClientTLSKey),
			)
			if err != nil {
				break
			}
			conn, err = ldap.DialURL(uut, ldap.DialWithTLSConfig(tlsConfig))
		default:
			retErr = multierror.Append(retErr, fmt.Errorf("%s: invalid LDAP scheme in url %q: %w", op, uut, ErrInvalidParameter))
			continue
		}
		if err == nil {
			retErr = nil
			break
		}
		retErr = multierror.Append(retErr, fmt.Errorf("%s: error connecting to host %q: %w", op, uut, err))
	}
	if retErr != nil {
		return retErr
	}
	if timeout := c.conf.RequestTimeout; timeout > 0 {
		conn.SetTimeout(time.Duration(timeout) * time.Second)
	}
	c.conn = conn
	return nil
}

// AuthResult is the result from a user authentication request via Client.Authenticate(...)
type AuthResult struct {
	// Success represents whether or not the attempt was successful
	Success bool

	// Groups are the groups that were associated with the authenticated
	// user (optional, see WithGroups() option)
	Groups []string

	// UserAttributes that are associated with the authenticated user (optional,
	// see WithUserAttributes() option)
	UserAttributes []Attribute

	// Warnings are warnings that happen during either authentication or when
	// attempting to find the groups associated with the authenticated user (see
	// the WithGroups option)
	Warnings []Warning
}

type Attribute struct {
	// Name is the name of the LDAP attribute
	Name string
	// Vals are the LDAP attribute values
	Vals []string
}

// Authenticate the user using the client's configured directory service.  If
// the WithGroups option is specified, it will also return the user's groups
// from the directory.
//
// Supported options: WithUserAttributes, WithGroups, WithDialer, WithURLs
func (c *Client) Authenticate(ctx context.Context, username, password string, opt ...Option) (*AuthResult, error) {
	const op = "ldap.(Client).Authenticate"
	if username == "" {
		return nil, fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	if !c.conf.AllowEmptyPasswordBinds && password == "" {
		return nil, fmt.Errorf("%s: password cannot be of zero length if allow_empty_passwd_bind is not enabled: %w", op, ErrInvalidParameter)
	}

	if err := c.connect(ctx, opt...); err != nil {
		return nil, fmt.Errorf("%s: failed to connect: %w", op, err)
	}

	userBindDN, err := c.getUserBindDN(username)
	if err != nil {
		return nil, fmt.Errorf("%s: discovery of user bind DN failed: %w", op, err)
	}

	// Try to bind as the login user. This is where the actual authentication takes place.
	if len(password) > 0 {
		err = c.conn.Bind(userBindDN, password)
	} else {
		err = c.conn.UnauthenticatedBind(userBindDN)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: unable to bind user: %w", op, err)
	}
	opts := getConfigOpts(opt...)
	if !opts.withGroups && !opts.withUserAttributes {
		return &AuthResult{
			Success: true,
		}, nil
	}

	// We re-bind to the BindDN if it's defined because we assume the BindDN
	// should be the one to search, not the user authenticating.
	if c.conf.BindDN != "" && c.conf.BindPassword != "" {
		if err := c.conn.Bind(c.conf.BindDN, c.conf.BindPassword); err != nil {
			// unless the binddn was changed during this inflight authentication
			// flow, it should be very difficult to encounter this error
			return nil, fmt.Errorf("%s: unable to re-bind with the configuration BindDN user: %w", op, err)
		}
	}

	userDN, err := c.getUserDN(userBindDN, username)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get the DN for the authenticated user: %w", op, err)
	}

	var userAttrs []Attribute
	if opts.withUserAttributes {
		userAttrs, err = c.getUserAttributes(userDN)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to get user attributes: %w", op, err)
		}
	}
	if !opts.withGroups {
		return &AuthResult{
			Success:        true,
			UserAttributes: userAttrs,
		}, nil
	}

	if c.conf.AnonymousGroupSearch {
		if err := c.conn.UnauthenticatedBind(userDN); err != nil {
			return nil, fmt.Errorf("%s: group search anonymous bind failed: %w", op, err)
		}
	}

	ldapGroups, warnings, err := c.getGroups(userDN, username)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get user groups: %w", op, err)
	}

	return &AuthResult{
		Success:        true,
		UserAttributes: userAttrs,
		Groups:         ldapGroups,
		Warnings:       warnings,
	}, nil
}

// Close will close the client's connection to the directory service.
func (c *Client) Close(ctx context.Context) {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) getUserAttributes(userDN string) ([]Attribute, error) {
	const op = "ldap.(Client).getUserAttributes"
	switch {
	case userDN == "":
		return nil, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}

	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN: userDN,
		Scope:  ldap.ScopeBaseObject,
		Filter: "(objectClass=*)",
	})
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: LDAP search for user attributes failed: %w", op, err)
	case len(result.Entries) != 1:
		return nil, fmt.Errorf("%s: LDAP search for user attributes was 0 or not unique", op)
	}
	userEntry := result.Entries[0]
	attributes := make([]Attribute, 0, len(userEntry.Attributes))
	for _, a := range userEntry.Attributes {
		attributes = append(attributes, Attribute{
			Name: a.Name,
			Vals: a.Values,
		})
	}
	return attributes, nil
}

// getGroups queries LDAP and returns a slice describing the set of groups the
// authenticated user is a member of.
//
// If c.conf.UseTokenGroups is true then the search is performed directly on the
// userDN. The values of those attributes are converted to string SIDs, and then
// looked up to get Entry objects. Otherwise, the search query is constructed
// according to c.conf..GroupFilter, and run in context of c.conf.GroupDN.
// Groups will be resolved from the query results by following the attribute
// defined in c.conf.GroupAttr.
//
// c.conf.GroupFilter is a go template and is compiled with the following context: [UserDN, Username]
//
//	UserDN - The DN of the authenticated user
//	Username - The Username of the authenticated user
//
// Example:
//
//	 c.conf.GroupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
//	 c.conf.GroupDN     = "OU=Groups,DC=myorg,DC=com"
//	 c.conf.GroupAttr   = "cn"
//
//	NOTE - If the config GroupFilter is empty, no query is performed and an
//	empty result slice is returned.
func (c *Client) getGroups(userDN string, username string) ([]string, []Warning, error) {
	const op = "ldap.(Client).getLDAPGroups"
	var warnings []Warning
	if userDN == "" {
		return nil, warnings, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}
	if username == "" {
		return nil, warnings, fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	var entries []*ldap.Entry
	var err error
	if c.conf.UseTokenGroups {
		entries, warnings, err = c.tokenGroupsSearch(userDN)
	} else {
		entries, warnings, err = c.filterGroupsSearch(userDN, username)
	}
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: %w", op, err)
	}

	// retrieve the groups in a string/bool map as a structure to avoid duplicates
	ldapMap := make(map[string]bool)

	for _, e := range entries {
		dn, err := ldap.ParseDN(e.DN)
		if err != nil || len(dn.RDNs) == 0 {
			continue
		}

		// Enumerate attributes of each result, parse out CN and add as group
		values := e.GetAttributeValues(c.conf.GroupAttr)
		if len(values) > 0 {
			for _, val := range values {
				groupCN := c.getCN(val)
				ldapMap[groupCN] = true
			}
		} else {
			// If groupattr didn't resolve, use self (enumerating group objects)
			groupCN := c.getCN(e.DN)
			ldapMap[groupCN] = true
		}
	}

	ldapGroups := make([]string, 0, len(ldapMap))
	for key := range ldapMap {
		ldapGroups = append(ldapGroups, key)
	}

	return ldapGroups, warnings, nil
}

func (c *Client) tokenGroupsSearch(userDN string) ([]*ldap.Entry, []Warning, error) {
	const op = "ldap.(Client).tokenGroupsSearch"
	var warnings []Warning
	if userDN == "" {
		return nil, warnings, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}
	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN: userDN,
		Scope:  ldap.ScopeBaseObject,
		Filter: "(objectClass=*)",
		Attributes: []string{
			"tokenGroups",
		},
		SizeLimit: 1,
	})
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: search failed: %w", op, err)
	}
	if len(result.Entries) == 0 {
		warnings = append(warnings, fmtWarning("%s: unable to read object for group attributes: userdn %s and groupattr %s", op, userDN, c.conf.GroupAttr))
		return make([]*ldap.Entry, 0), warnings, nil
	}

	userEntry := result.Entries[0]
	groupAttrValues := userEntry.GetRawAttributeValues("tokenGroups")

	groupEntries := make([]*ldap.Entry, 0, len(groupAttrValues))
	for _, sidBytes := range groupAttrValues {
		sidString, err := sidBytesToString(sidBytes)
		if err != nil {
			warnings = append(warnings, fmtWarning("%s: unable to read sid: %s", op, err.Error()))
			continue
		}

		groupResult, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN: fmt.Sprintf("<SID=%s>", sidString),
			Scope:  ldap.ScopeBaseObject,
			Filter: "(objectClass=*)",
			Attributes: []string{
				"1.1", // RFC no attributes
			},
			SizeLimit: 1,
		})
		if err != nil {
			warnings = append(warnings, fmtWarning("%s: unable to read the group sid: %s", op, sidString))
			continue
		}
		if len(groupResult.Entries) == 0 {
			warnings = append(warnings, fmtWarning("%s: unable to find the group sid: %s", op, sidString))
			continue
		}

		groupEntries = append(groupEntries, groupResult.Entries[0])
	}

	return groupEntries, warnings, nil
}

func (c *Client) filterGroupsSearch(userDN string, username string) ([]*ldap.Entry, []Warning, error) {
	const op = "ldap.(Client).filterGroupsSearch"
	var warnings []Warning
	if userDN == "" {
		return nil, warnings, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}
	if username == "" {
		return nil, warnings, fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	if c.conf.GroupFilter == "" {
		return make([]*ldap.Entry, 0), warnings, nil
	}
	if c.conf.GroupDN == "" {
		return make([]*ldap.Entry, 0), warnings, nil
	}
	// Parse the configuration as a template.
	// Example template "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
	t, err := template.New("queryTemplate").Parse(c.conf.GroupFilter)
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: LDAP search failed due to template compilation error: %w", op, err)
	}

	// Build context to pass to template - we will be exposing UserDn and Username.
	context := struct {
		UserDN   string
		Username string
	}{
		ldap.EscapeFilter(userDN),
		ldap.EscapeFilter(username),
	}

	var renderedQuery bytes.Buffer
	if err := t.Execute(&renderedQuery, context); err != nil {
		return nil, warnings, fmt.Errorf("%s: LDAP search failed due to template parsing error: %w", op, err)
	}

	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN: c.conf.GroupDN,
		Scope:  ldap.ScopeWholeSubtree,
		Filter: renderedQuery.String(),
		Attributes: []string{
			c.conf.GroupAttr,
		},
		SizeLimit: math.MaxInt32,
	})
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: LDAP search failed: %w", op, err)
	}

	return result.Entries, warnings, nil
}

func sidBytesToString(b []byte) (string, error) {
	const op = "ldap.sidBytesToString"
	if b == nil {
		return "", fmt.Errorf("%s: missing bytes: %w", op, ErrInvalidParameter)
	}
	reader := bytes.NewReader(b)

	var revision, subAuthorityCount uint8
	var identifierAuthorityParts [3]uint16

	if err := binary.Read(reader, binary.LittleEndian, &revision); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading Revision: %w", op, b, err)
	}

	if err := binary.Read(reader, binary.LittleEndian, &subAuthorityCount); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading SubAuthorityCount: %w", op, b, err)
	}

	if err := binary.Read(reader, binary.BigEndian, &identifierAuthorityParts); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading IdentifierAuthority: %w", op, b, err)
	}
	identifierAuthority := (uint64(identifierAuthorityParts[0]) << 32) + (uint64(identifierAuthorityParts[1]) << 16) + uint64(identifierAuthorityParts[2])

	subAuthority := make([]uint32, subAuthorityCount)
	if err := binary.Read(reader, binary.LittleEndian, &subAuthority); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading SubAuthority: %w", op, b, err)
	}

	result := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)
	for _, subAuthorityPart := range subAuthority {
		result += fmt.Sprintf("-%d", subAuthorityPart)
	}

	return result, nil
}

// SIDBytes creates a SID from the provided revision and identifierAuthority
func SIDBytes(revision uint8, identifierAuthority uint16) ([]byte, error) {
	const op = "ldap.SidBytes"
	var identifierAuthorityParts [3]uint16
	identifierAuthorityParts[2] = identifierAuthority

	subAuthorityCount := uint8(0)
	var writer bytes.Buffer
	if err := binary.Write(&writer, binary.LittleEndian, uint8(revision)); err != nil {
		return nil, fmt.Errorf("%s: unable to write revision: %w", op, err)
	}
	if err := binary.Write(&writer, binary.LittleEndian, subAuthorityCount); err != nil {
		return nil, fmt.Errorf("%s: unable to write subauthority count: %w", op, err)
	}
	if err := binary.Write(&writer, binary.BigEndian, identifierAuthorityParts); err != nil {
		return nil, fmt.Errorf("%s: unable to write authority parts: %w", op, err)
	}
	return writer.Bytes(), nil
}

func (c *Client) getUserBindDN(username string) (string, error) {
	const op = "ldap.(Client).getUserBindDN"
	if username == "" {
		return "", fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	// this validation check and the logic right below it are dependent, so if
	// you update one of them, be sure to update the other one as well.
	if !c.conf.DiscoverDN && (c.conf.BindDN == "" || c.conf.BindPassword == "") && c.conf.UPNDomain == "" && c.conf.UserDN == "" {
		return "", fmt.Errorf("%s: cannot derive UserBindDN based on config (see combination of: discoverdn, binddn, bindpass, upndomain, userdn): %w", op, ErrInvalidParameter)
	}
	var bindDN string
	if c.conf.DiscoverDN || (c.conf.BindDN != "" && c.conf.BindPassword != "") {
		var err error
		if c.conf.BindPassword != "" {
			err = c.conn.Bind(c.conf.BindDN, c.conf.BindPassword)
		} else {
			err = c.conn.UnauthenticatedBind(c.conf.BindDN)
		}
		if err != nil {
			return "", fmt.Errorf("%s: bind (service) failed: %w", op, err)
		}

		filter, err := c.renderUserSearchFilter(username)
		if err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}

		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN:    c.conf.UserDN,
			Scope:     ldap.ScopeWholeSubtree,
			Filter:    filter,
			SizeLimit: math.MaxInt32,
		})
		if err != nil {
			return "", fmt.Errorf("%s: LDAP search for binddn failed: %w", op, err)
		}
		if len(result.Entries) != 1 {
			return "", fmt.Errorf("LDAP search for binddn 0 or not unique")
		}
		bindDN = result.Entries[0].DN
	} else {
		if c.conf.UPNDomain != "" {
			bindDN = fmt.Sprintf("%s@%s", EscapeValue(username), c.conf.UPNDomain)
		} else {
			bindDN = fmt.Sprintf("%s=%s,%s", c.conf.UserAttr, EscapeValue(username), c.conf.UserDN)
		}
	}
	return bindDN, nil
}

/*
 * Returns the DN of the object representing the authenticated user.
 */
func (c *Client) getUserDN(bindDN, username string) (string, error) {
	const op = "ldap.(Client).getUserDN"
	if bindDN == "" {
		return "", fmt.Errorf("%s: missing bind dn: %w", op, ErrInvalidParameter)
	}
	if username == "" {
		return "", fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	var userDN string
	if c.conf.UPNDomain != "" {
		// Find the distinguished name for the user if userPrincipalName used for login
		filter := fmt.Sprintf("(userPrincipalName=%s@%s)", EscapeValue(username), c.conf.UPNDomain)
		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN:    c.conf.UserDN,
			Scope:     ldap.ScopeWholeSubtree,
			Filter:    filter,
			SizeLimit: math.MaxInt32,
		})
		if err != nil {
			return userDN, fmt.Errorf("%s: LDAP search failed for detecting user: %w", op, err)
		}
		for _, e := range result.Entries {
			userDN = e.DN
		}
	} else {
		userDN = bindDN
	}
	return userDN, nil
}

/*
 * Parses a distinguished name and returns the CN portion.
 * Given a non-conforming string (such as an already-extracted CN),
 * it will be returned as-is.
 */
func (c *Client) getCN(dn string) string {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil || len(parsedDN.RDNs) == 0 {
		// It was already a CN, return as-is
		return dn
	}

	for _, rdn := range parsedDN.RDNs {
		for _, rdnAttr := range rdn.Attributes {
			if c.conf.DeprecatedVaultPre111GroupCNBehavior == nil || *c.conf.DeprecatedVaultPre111GroupCNBehavior {
				if rdnAttr.Type == "CN" {
					return rdnAttr.Value
				}
			} else {
				if strings.EqualFold(rdnAttr.Type, "CN") {
					return rdnAttr.Value
				}
			}
		}
	}
	// Default, return self
	return dn
}

func (c *Client) renderUserSearchFilter(username string) (string, error) {
	const (
		op = "ldap.(Client).renderUserSearchFilter"

		emptyUserFilter   = ""
		defaultUserFilter = "({{.UserAttr}}={{.Username}})"
		queryTemplate     = "queryTemplate"
	)
	if username == "" {
		return "", fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}

	var userFilter string
	// The UserFilter can be blank if not set, or running this version of the code
	// on an existing ldap configuration
	switch {
	case c.conf.UserFilter != emptyUserFilter:
		userFilter = c.conf.UserFilter
	default:
		userFilter = defaultUserFilter
	}

	// Parse the configuration as a template.
	// Example template "({{.UserAttr}}={{.Username}})"
	t, err := template.New(queryTemplate).Parse(userFilter)
	if err != nil {
		return "", fmt.Errorf("%s: search failed due to template compilation error: %w", op, err)
	}

	// Build context to pass to template - we will be exposing UserDn and Username.
	context := struct {
		UserAttr string
		Username string
	}{
		EscapeFilter(c.conf.UserAttr),
		EscapeFilter(username),
	}
	if c.conf.UPNDomain != "" {
		context.UserAttr = "userPrincipalName"
		context.Username = fmt.Sprintf("%s@%s", EscapeValue(username), c.conf.UPNDomain)
	}

	var renderedFilter bytes.Buffer
	if err := t.Execute(&renderedFilter, context); err != nil {
		return "", fmt.Errorf("%s: search failed due to template parsing error: %w", op, err)
	}

	return renderedFilter.String(), nil
}

func getTLSConfig(host string, opt ...Option) (*tls.Config, error) {
	const op = "ldap.getTLSConfig"
	if host == "" {
		return nil, fmt.Errorf("%s: missing host: %w", op, ErrInvalidParameter)
	}
	opts := getConfigOpts(opt...)
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	if opts.withTLSMinVersion != "" {
		tlsMinVersion, ok := tlsutil.TLSLookup[opts.withTLSMinVersion]
		if !ok {
			return nil, fmt.Errorf("%s: invalid 'tls_min_version' in config: %w", op, ErrInvalidParameter)
		}
		tlsConfig.MinVersion = tlsMinVersion
	}

	if opts.withTLSMaxVersion != "" {
		tlsMaxVersion, ok := tlsutil.TLSLookup[opts.withTLSMaxVersion]
		if !ok {
			return nil, fmt.Errorf("%s: invalid 'tls_max_version' in config: %w", op, ErrInvalidParameter)
		}
		tlsConfig.MaxVersion = tlsMaxVersion
	}

	if opts.withInsecureTLS {
		tlsConfig.InsecureSkipVerify = true
	}
	if opts.withCertificate != "" {
		caPool := x509.NewCertPool()
		ok := caPool.AppendCertsFromPEM([]byte(opts.withCertificate))
		if !ok {
			return nil, fmt.Errorf("%s: could not append CA certificate: %w", op, ErrUnknown)
		}
		tlsConfig.RootCAs = caPool
	}
	if opts.withClientTLSCert != "" && opts.withClientTLSKey != "" {
		certificate, err := tls.X509KeyPair([]byte(opts.withClientTLSCert), []byte(opts.withClientTLSKey))
		if err != nil {
			return nil, fmt.Errorf("%s: failed to parse client X509 key pair: %w", op, err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	} else if opts.withClientTLSCert != "" || opts.withClientTLSKey != "" {
		return nil, fmt.Errorf("%s: both client_tls_cert and client_tls_key must be set in configuration: %w", op, ErrInvalidParameter)
	}
	return tlsConfig, nil
}

// EscapeValue will properly escape the input string as an ldap value
func EscapeValue(input string) string {
	if input == "" {
		return ""
	}

	// RFC4514 forbids un-escaped:
	// - leading space or hash
	// - trailing space
	// - special characters '"', '+', ',', ';', '<', '>', '\\'
	// - null
	for i := 0; i < len(input); i++ {
		escaped := false
		if input[i] == '\\' {
			i++
			escaped = true
		}
		switch input[i] {
		case '"', '+', ',', ';', '<', '>', '\\':
			if !escaped {
				input = input[0:i] + "\\" + input[i:]
				i++
			}
			continue
		}
		if escaped {
			input = input[0:i] + "\\" + input[i:]
			i++
		}
	}
	if input[0] == ' ' || input[0] == '#' {
		input = "\\" + input
	}
	if input[len(input)-1] == ' ' {
		input = input[0:len(input)-1] + "\\ "
	}
	return input
}

func EscapeFilter(filter string) string {
	return ldap.EscapeFilter(filter)
}
