package ldap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/lor00x/goldap/message"
	"github.com/vjeantet/ldapserver"

	"github.com/stretchr/testify/require"
)

const (
	// TestDefaultUserDN defines a default base distinguished name to use when
	// searching for users for the TestDirectory
	TestDefaultUserDN = "ou=people,dc=example,dc=org"

	// TestDefaultGroupDN defines a default base distinguished name to use when
	// searching for groups for the TestDirectory
	TestDefaultGroupDN = "ou=groups,dc=example,dc=org"
)

func init() {
	// unfortunately, there's really not a better way to turn off logging from
	// github.com/vjeantet/ldapserver  TODO: an upstream PR to possible fix
	// this.
	ldapserver.Logger = ldapserver.DiscardingLogger
}

// TestDirectory is a local ldap directory that supports test ldap capabilities
// which makes writing tests much easier.
//
// It's important to remember that the TestDirectory is stateful (see any of its
// receiver functions that begin with Set*)
//
// Once you started a TestDirectory with StartTestDirectory(...), the following
// test ldap operations are supported:
//
//  * Bind
//  * Search
//  * StartTLS
//
// Making requests to the TestDirectory is facilitated by:
//  * TestDirectory.Cert() 		returns the pem-encoded CA certificate used by the directory.
//  * TestDirectory.Port() 		returns the port the directory is listening on.
//  * TestDirectory.ClientCert() 	returns a client cert for mtls
//  * TestDirectory.ClientKey() 	returns a client private key for mtls
//
type TestDirectory struct {
	t       TestingT
	s       *ldapserver.Server
	logger  hclog.Logger
	port    int
	useTLS  bool
	useMTLS bool
	client  *tls.Config
	server  *tls.Config

	mu                 sync.Mutex
	users              []*TestEntry
	groups             []*TestEntry
	tokenGroups        map[string][]*TestEntry // string == SID
	allowAnonymousBind bool

	// userDN is the base distinguished name to use when searching for users
	userDN string
	// groupDN is the base distinguished name to use when searching for groups
	groupDN string
}

// StartTestDirectory creates and starts a running TestDirectory ldap server.
// Support options: WithPort, WithTestMTLS, WithTestNoTLS, WithTestDefaults,
// WithTestLogging.
//
// The TestDirectory will be shutdown when the test and all its
// subtests are compted via a registered function with t.Cleanup(...)
func StartTestDirectory(t TestingT, opt ...TestOption) *TestDirectory {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	opts := getTestDirectoryOpts(t, opt...)
	if opts.withPort == 0 {
		opts.withPort = testFreePort(t)
	}

	d := &TestDirectory{
		t:                  t,
		logger:             opts.withLogger,
		users:              opts.withDefaults.Users,
		groups:             opts.withDefaults.Groups,
		port:               opts.withPort,
		userDN:             opts.withDefaults.UserDN,
		groupDN:            opts.withDefaults.GroupDN,
		allowAnonymousBind: opts.withDefaults.AllowAnonymousBind,
	}

	d.s = ldapserver.NewServer()
	routes := ldapserver.NewRouteMux()
	routes.NotFound(d.handleNotFound(t))
	routes.Bind(d.handleBind(t))
	routes.Extended(d.handleStartTLS(t)).RequestName(ldapserver.NoticeOfStartTLS).Label("StartTLS")
	routes.Search(d.handleSearchUsers(t)).BaseDn(d.userDN).Label("Search - Users")
	routes.Search(d.handleSearchGroups(t)).BaseDn(d.groupDN).Label("Search - Groups")
	routes.Search(d.handleSearchGeneric(t)).Label("Search - Generic")

	d.s.Handle(routes)

	serverTLSConfig, clientTLSConfig := testGetTLSconfig(t, opt...)
	d.client = clientTLSConfig
	d.server = serverTLSConfig

	var connOpts []func(s *ldapserver.Server)
	if !opts.withNoTLS {
		d.useTLS = true
		connOpts = append(connOpts, func(s *ldapserver.Server) {
			s.Listener = tls.NewListener(s.Listener, d.server)
		})

	}
	go func() {
		err := d.s.ListenAndServe(fmt.Sprintf(":%d", opts.withPort), connOpts...)
		require.NoError(err)
	}()

	if v, ok := interface{}(t).(CleanupT); ok {
		v.Cleanup(func() { d.s.Stop() })
	}
	// need a bit of a pause to get the service up and running, otherwise we'll
	// get a connection error because the service isn't listening yet.
	time.Sleep(10 * time.Millisecond)
	return d
}

// Stop will stop the TestDirectory if it wasn't started with a *testing.T
// if it was started with *testing.T then Stop() is ignored.
func (d *TestDirectory) Stop() {
	if _, ok := interface{}(d.t).(CleanupT); !ok {
		d.s.Stop()
	}
}

func (d *TestDirectory) handleNotFound(t TestingT) func(w ldapserver.ResponseWriter, r *ldapserver.Message) {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w ldapserver.ResponseWriter, r *ldapserver.Message) {
		switch r.ProtocolOpType() {
		case ldapserver.ApplicationBindRequest:
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
			res.SetDiagnosticMessage("Default binding behavior set to return Success")
			w.Write(res)

		default:
			res := ldapserver.NewResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage("Operation not implemented by server")
			w.Write(res)
		}
	}
}

func (d *TestDirectory) handleStartTLS(t TestingT) func(ldapserver.ResponseWriter, *ldapserver.Message) {
	const op = "ldap.(TestDirectory).handleStartTLS"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		tlsConn := tls.Server(m.Client.GetConn(), d.server)
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess)
		res.SetResponseName(ldapserver.NoticeOfStartTLS)
		w.Write(res)

		if err := tlsConn.Handshake(); err != nil {
			d.infof("StartTLS Handshake error", "op", op, "err", err)
			res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
			res.SetResultCode(ldapserver.LDAPResultOperationsError)
			w.Write(res)
			return
		}

		m.Client.SetConn(tlsConn)
		d.infof("StartTLS OK", "op", op)
	}
}

func (d *TestDirectory) handleSearchGeneric(t TestingT) func(ldapserver.ResponseWriter, *ldapserver.Message) {
	const op = "ldap.(TestDirectory).handleSearchGeneric"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetSearchRequest()
		d.infof("request", "op", op, "BaseDN", r.BaseObject())
		d.infof("request", "op", op, "Filter", r.Filter())
		d.infof("request", "op", op, "Attributes", r.Attributes())
		d.infof("request", "op", op, "BaseObject", r.BaseObject())
		d.infof("request", "op", op, "TimeLimit", r.TimeLimit())

		// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
		select {
		case <-m.Done:
			d.infof("Leaving handleSearch...", "op", op)
			return
		default:
		}

		filter := r.FilterString()

		// if our search base is the base userDN, we're searching for a single
		// user, so adjust the filter to match user's entries
		if strings.Contains(string(r.BaseObject()), d.userDN) {
			filter = fmt.Sprintf("(%s)", r.BaseObject())
			d.infof("new filter", "op", op, "value", filter)
			for _, a := range r.Attributes() {
				d.infof("attr", "op", op, "value", a)
				if a == "tokenGroups" {
					d.infof("asking for groups", "op", op)
				}
			}
		}

		// if our search base is a SID, then we're searching for tokenGroups
		if len(d.tokenGroups) > 0 && strings.HasPrefix(string(r.BaseObject()), "<SID=") {
			sid := string(r.BaseObject())
			sid = strings.TrimPrefix(sid, "<SID=")
			sid = strings.TrimSuffix(sid, ">")
			for _, g := range d.tokenGroups[sid] {
				d.infof("found tokenGroup", "op", op, "group DN", g.DN)
				result := ldapserver.NewSearchResultEntry(g.DN)
				for _, attr := range g.Attributes {
					values := make([]message.AttributeValue, 0, len(attr.Values))
					for _, v := range attr.Values {
						values = append(values, message.AttributeValue(v))
					}
					result.AddAttribute(message.AttributeDescription(attr.Name), values...)
				}
				w.Write(result)
			}
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
			w.Write(res)
			return
		}

		d.infof("filter", "op", op, "value", filter)
		for _, e := range d.users {
			if ok, _ := match(filter, e.DN); !ok {
				continue
			}
			result := ldapserver.NewSearchResultEntry(e.DN)
			for _, attr := range e.Attributes {
				values := make([]message.AttributeValue, 0, len(attr.Values))
				for _, v := range attr.Values {
					values = append(values, message.AttributeValue(v))
				}
				result.AddAttribute(message.AttributeDescription(attr.Name), values...)
			}
			w.Write(result)
		}
		for _, e := range d.groups {
			if ok, _ := match(filter, e.DN); !ok {
				continue
			}
			result := ldapserver.NewSearchResultEntry(e.DN)
			for _, attr := range e.Attributes {
				values := make([]message.AttributeValue, 0, len(attr.Values))
				for _, v := range attr.Values {
					values = append(values, message.AttributeValue(v))
				}
				result.AddAttribute(message.AttributeDescription(attr.Name), values...)
			}
			w.Write(result)
		}
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
	}
}

func (d *TestDirectory) handleSearchGroups(t TestingT) func(ldapserver.ResponseWriter, *ldapserver.Message) {
	const op = "ldap.(TestDirectory).handleSearchGroups"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetSearchRequest()
		d.infof("request", "op", op, "BaseDN", r.BaseObject())
		d.infof("request", "op", op, "Filter", r.Filter())
		d.infof("request", "op", op, "Attributes", r.Attributes())
		d.infof("request", "op", op, "BaseObject", r.BaseObject())
		d.infof("request", "op", op, "TimeLimit", r.TimeLimit())

		// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
		select {
		case <-m.Done:
			d.infof("Leaving handleSearch...", "op", op)
			return
		default:
		}

		_, entries := d.findMembers(r.FilterString())
		for _, e := range entries {
			result := ldapserver.NewSearchResultEntry(e.DN)
			for _, attr := range e.Attributes {
				values := make([]message.AttributeValue, 0, len(attr.Values))
				for _, v := range attr.Values {
					values = append(values, message.AttributeValue(v))
				}
				result.AddAttribute(message.AttributeDescription(attr.Name), values...)
			}
			w.Write(result)
		}
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
	}
}

func (d *TestDirectory) handleSearchUsers(t TestingT) func(ldapserver.ResponseWriter, *ldapserver.Message) {
	const op = "ldap.(TestDirectory).handleSearchUsers"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetSearchRequest()
		d.infof("request", "op", op, "BaseDN", r.BaseObject())
		d.infof("request", "op", op, "Filter", r.Filter())
		d.infof("request", "op", op, "Attributes", r.Attributes())
		d.infof("request", "op", op, "BaseObject", r.BaseObject())
		d.infof("request", "op", op, "TimeLimit", r.TimeLimit())

		// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
		select {
		case <-m.Done:
			d.infof("Leaving handleSearch...", "op", op)
			return
		default:
		}

		_, entries := find(d.t, r.FilterString(), d.users)
		for _, e := range entries {
			result := ldapserver.NewSearchResultEntry(e.DN)
			for _, attr := range e.Attributes {
				values := make([]message.AttributeValue, 0, len(attr.Values))
				for _, v := range attr.Values {
					values = append(values, message.AttributeValue(v))
				}
				result.AddAttribute(message.AttributeDescription(attr.Name), values...)
			}
			w.Write(result)
		}
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
	}
}

func (d *TestDirectory) infof(msg string, args ...interface{}) {
	if d.logger != nil {
		d.logger.Info(msg, args...)
	}
}

func (d *TestDirectory) findMembers(filter string, opt ...TestOption) (bool, []*TestEntry) {
	opts := getTestDirectoryOpts(d.t, opt...)
	var matches []*TestEntry
	for _, e := range d.groups {
		members := e.getAttributeValues("member")
		for _, m := range members {
			if ok, _ := match(filter, "member="+m); ok {
				matches = append(matches, e)
				if opts.withFirst {
					return true, matches
				}
			}
		}
	}
	if len(matches) > 0 {
		return true, matches
	}
	return false, nil
}

func find(t TestingT, filter string, entries []*TestEntry, opt ...TestOption) (bool, []*TestEntry) {
	opts := getTestDirectoryOpts(t, opt...)
	var matches []*TestEntry
	for _, e := range entries {
		if ok, _ := match(filter, e.DN); ok {
			matches = append(matches, e)
			if opts.withFirst {
				return true, matches
			}
		}
	}
	if len(matches) > 0 {
		return true, matches
	}
	return false, nil
}

func match(filter string, attr string) (bool, error) {
	// TODO: make this actually do something more reasonable with the search
	// request filter
	re := regexp.MustCompile(`\((.*?)\)`)
	submatchall := re.FindAllString(filter, -1)
	for _, element := range submatchall {
		element = strings.ReplaceAll(element, "*", "")
		element = strings.Trim(element, "|(")
		element = strings.Trim(element, "(")
		element = strings.Trim(element, ")")
		element = strings.TrimSpace(element)
		if strings.Contains(attr, element) {
			return true, nil
		}
	}
	return false, nil
}

// handleBind is ONLY supporting simple authentication (no SASL here!)
func (d *TestDirectory) handleBind(t TestingT) func(ldapserver.ResponseWriter, *ldapserver.Message) {
	const op = "ldap.(TestDirectory).handleBind"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetBindRequest()
		d.infof("request", "op", op, "Name", r.Name())

		res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)

		// first, we'll deal with anon binds with an empty password
		if d.allowAnonymousBind && r.AuthenticationSimple() == "" {
			w.Write(res)
			return
		}

		for _, u := range d.users {
			if u.DN == string(r.Name()) {
				d.infof("found bind user", "op", op, "DN", u.DN)
				values := u.getAttributeValues("password")
				if len(values) > 0 && (string(r.AuthenticationSimple()) == values[0]) {
					w.Write(res)
					return
				}
			}
		}

		d.infof("Bind failed", "op", op, "user", string(r.Name()))
		res.SetResultCode(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
		w.Write(res)
	}
}

// Cert returns the pem-encoded certificate used by the TestDirectory.
func (d *TestDirectory) Cert() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	require.NotNil(d.server)
	require.Len(d.server.Certificates, 1)
	cert := d.server.Certificates[0]
	require.NotNil(cert)
	require.Len(cert.Certificate, 1)
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NoError(err)
	return buf.String()
}

// Port returns the port the directory is listening on
func (d *TestDirectory) Port() int {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	return d.port
}

// ClientCert returns the pem-encoded certificate which can be used by a client
// for mTLS.
func (d *TestDirectory) ClientCert() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	require.NotNil(d.client)
	require.Len(d.client.Certificates, 1)
	cert := d.client.Certificates[0]
	require.NotNil(cert)
	require.Len(cert.Certificate, 1)
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NoError(err)
	return buf.String()
}

// ClientKey returns the pem-encoded private key which can be used by a client
// for mTLS.
func (d *TestDirectory) ClientKey() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	require.NotNil(d.client)
	require.Len(d.client.Certificates, 1)
	privBytes, err := x509.MarshalPKCS8PrivateKey(d.client.Certificates[0].PrivateKey)
	require.NoError(err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	require.NotNil(pemKey)
	return string(pemKey)
}

// Users returns all the current user entries in the TestDirectory
func (d *TestDirectory) Users() []*TestEntry {
	return d.users
}

// SetUsers sets the user entries.
func (d *TestDirectory) SetUsers(users ...*TestEntry) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users = users
}

// Groups returns all the current group entries in the TestDirectory
func (d *TestDirectory) Groups() []*TestEntry {
	return d.groups
}

// SetGroups sets the group entries.
func (d *TestDirectory) SetGroups(groups ...*TestEntry) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.groups = groups
}

// SetTokenGroups will set the tokenGroup entries.
func (d *TestDirectory) SetTokenGroups(tokenGroups map[string][]*TestEntry) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokenGroups = tokenGroups
}

// TokenGroups will return the tokenGroup entries
func (d *TestDirectory) TokenGroups() map[string][]*TestEntry {
	return d.tokenGroups
}

// AllowAnonymousBind returns the allow anon bind setting
func (d *TestDirectory) AllowAnonymousBind() bool {
	return d.allowAnonymousBind
}

// SetAllowAnonymousBind enables/disables anon binds
func (d *TestDirectory) SetAllowAnonymousBind(enabled bool) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allowAnonymousBind = enabled
}

// getTestDirectoryOpts gets the test directory defaults and applies the opt
// overrides passed in
func getTestDirectoryOpts(t TestingT, opt ...TestOption) testDirectoryOptions {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	opts := testDirectoryDefaults(t)
	testApplyOpts(&opts, opt...)
	return opts
}

// testDirectoryOptions is the set of available options for TestDirectory
// functions
type testDirectoryOptions struct {
	withPort     int
	withLogger   hclog.Logger
	withNoTLS    bool
	withMTLS     bool
	withDefaults *TestDirectoryDefaults

	withFirst bool
}

func testDirectoryDefaults(t TestingT) testDirectoryOptions {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return testDirectoryOptions{
		withDefaults: &TestDirectoryDefaults{
			UserDN:  TestDefaultUserDN,
			GroupDN: TestDefaultGroupDN,
		},
	}
}

// TestDirectoryDefaults define a type for composing all the defaults for
// StartTestDirectory(...)
type TestDirectoryDefaults struct {
	// Users configures the user entries which are empty by default
	Users []*TestEntry

	// Groups configures the group entries which are empty by default
	Groups []*TestEntry

	// TokenGroups configures the tokenGroup entries which are empty be default
	TokenGroups map[string][]*TestEntry

	// UserDN is the base distinguished name to use when searching for users
	// which is "ou=people,dc=example,dc=org" by default
	UserDN string

	// GroupDN is the base distinguished name to use when searching for groups
	// which is "ou=groups,dc=example,dc=org" by default
	GroupDN string

	// AllowAnonymousBind determines if anon binds are allowed
	AllowAnonymousBind bool
}

// WithTestDirectoryDefaults provides an option to provide a set of defaults to
// StartTestDirectory(...) which make it much more composable.
//
// Valid for: StartTestDirectory
func WithTestDirectoryDefaults(defaults *TestDirectoryDefaults) TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testDirectoryOptions); ok {
			if defaults != nil {
				if defaults.AllowAnonymousBind {
					o.withDefaults.AllowAnonymousBind = true
				}
				if defaults.Users != nil {
					o.withDefaults.Users = defaults.Users
				}
				if defaults.Groups != nil {
					o.withDefaults.Groups = defaults.Groups
				}
				if defaults.UserDN != "" {
					o.withDefaults.UserDN = defaults.UserDN
				}
				if defaults.GroupDN != "" {
					o.withDefaults.GroupDN = defaults.GroupDN
				}
				if len(defaults.TokenGroups) > 0 {
					o.withDefaults.TokenGroups = defaults.TokenGroups
				}
			}
		}
	}
}

// WithTestNoTLS provides the option to not use TLS for the test directory.
//
// Valid for: StartDirectory(...)
func WithTestNoTLS() TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testDirectoryOptions); ok {
			o.withNoTLS = true
		}
	}
}

// WithTestMTLS provides the option to use mTLS for the test directory.
//
// Valid for: StartDirectory(...)
func WithTestMTLS() TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testDirectoryOptions); ok {
			o.withMTLS = true
		}
	}
}

// WithTestLogger provides the optional logger for the test diretory.
//
// Valid for: StartDirectory(...)
func WithTestLogger(l hclog.Logger) TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testDirectoryOptions); ok {
			o.withLogger = l
		}
	}
}

// WithTestPort provides an optional port for the test directory. 0 causes a
// started server with a random port. Any other value returns a started server
// on that port.
//
// Valid for: StartTestDirectory
func WithTestPort(port int) TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testDirectoryOptions); ok {
			o.withPort = port
		}
	}
}

// withTestFirst provides the option to only find the first match.
func withTestFirst() TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testDirectoryOptions); ok {
			o.withFirst = true
		}
	}
}

// TestFreePort just returns an available free localhost port
func testFreePort(t TestingT) int {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// supports WithTestMTLS
func testGetTLSconfig(t TestingT, opt ...TestOption) (s *tls.Config, c *tls.Config) {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)

	certSubject := pkix.Name{
		Organization:  []string{"Acme, INC."},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"New York"},
		StreetAddress: []string{"Empire State Building"},
		PostalCode:    []string{"10118"},
	}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          genSerialNumber(t),
		Subject:               certSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPriv.PublicKey, caPriv)
	require.NoError(err)

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	privBytes, err := x509.MarshalPKCS8PrivateKey(caPriv)
	require.NoError(err)
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	cert := &x509.Certificate{
		SerialNumber:          genSerialNumber(t),
		Subject:               certSubject,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	serverCert := genCert(t, ca, caPriv, cert)

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	clientTLSConf := &tls.Config{
		RootCAs: certpool,
	}

	opts := getTestDirectoryOpts(t, opt...)
	if opts.withMTLS {
		// setup mTLS for certs from the ca
		serverTLSConf.ClientCAs = certpool
		serverTLSConf.ClientAuth = tls.RequireAndVerifyClientCert

		cert := &x509.Certificate{
			SerialNumber:          big.NewInt(2019),
			Subject:               certSubject,
			EmailAddresses:        []string{"mtls.client@example.com"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			SubjectKeyId:          []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		clientCert := genCert(t, ca, caPriv, cert)
		clientTLSConf.Certificates = []tls.Certificate{clientCert}
	}
	// TODO: I think, this has been deprecated, so remove it it works without it
	// serverTLSConf.BuildNameToCertificate()

	return serverTLSConf, clientTLSConf
}

func genCert(t TestingT, ca *x509.Certificate, caPriv interface{}, certTemplate *x509.Certificate) tls.Certificate {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(err)

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, &certPrivKey.PublicKey, caPriv)
	require.NoError(err)

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	require.NoError(err)

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	newCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	require.NoError(err)
	return newCert
}

func genSerialNumber(t TestingT) *big.Int {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)
	return serialNumber
}
