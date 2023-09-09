package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/hashicorp/cap/oidc"
	"github.com/jonboulle/clockwork"

	"github.com/hashicorp/cap/saml/models/core"
)

const (
	postBindingScriptSha256 = "T8Q9GZiIVtYoNIdF6UW5hDNgJudFDijQM/usO+xUkes="
)

type authnRequestOptions struct {
	clock                       clockwork.Clock
	allowCreate                 bool
	nameIDFormat                core.NameIDFormat
	forceAuthn                  bool
	protocolBinding             core.ServiceBinding
	authnContextClassRefs       []string
	indent                      int
	assertionConsumerServiceURL string
}

func authnRequestOptionsDefault() authnRequestOptions {
	return authnRequestOptions{
		allowCreate:     false,
		clock:           clockwork.NewRealClock(),
		nameIDFormat:    core.NameIDFormat(""),
		forceAuthn:      false,
		protocolBinding: core.ServiceBindingHTTPPost,
	}
}

func getAuthnRequestOptions(opt ...Option) authnRequestOptions {
	opts := authnRequestOptionsDefault()
	ApplyOpts(&opts, opt...)
	return opts
}

// AllowCreate is a Boolean value used to indicate whether the identity provider is allowed, in the course
// of fulfilling the request, to create a new identifier to represent the principal.
func AllowCreate() Option {
	return func(o interface{}) {
		if o, ok := o.(*authnRequestOptions); ok {
			o.allowCreate = true
		}
	}
}

// WithNameIDFormat will set an NameIDPolicy object with the
// given NameIDFormat. It implies AllowCreate=true.
func WithNameIDFormat(f core.NameIDFormat) Option {
	return func(o interface{}) {
		if o, ok := o.(*authnRequestOptions); ok {
			o.nameIDFormat = f
			o.allowCreate = true
		}
	}
}

// ForceAuthentication is a boolean value that tells the identity provider it MUST authenticate the presenter
// directly rather than rely on a previous security context.
func ForceAuthn() Option {
	return func(o interface{}) {
		if o, ok := o.(*authnRequestOptions); ok {
			o.forceAuthn = true
		}
	}
}

// WithProtocolBinding defines the ProtocolBinding to be used. It defaults to HTTP-Post.
// The ProtocolBinding is a URI reference that identifies a SAML protocol binding to be used
// when returning the <Response> message.
func WithProtocolBinding(binding core.ServiceBinding) Option {
	return func(o interface{}) {
		if o, ok := o.(*authnRequestOptions); ok {
			o.protocolBinding = binding
		}
	}
}

// WithAuthContextClassRefs defines AuthnContextClassRefs.
// An AuthContextClassRef Specifies the requirements, if any, that the requester places on the
// authentication context that applies to the responding provider's authentication of the presenter.
func WithAuthContextClassRefs(cfs []string) Option {
	return func(o interface{}) {
		if o, ok := o.(*authnRequestOptions); ok {
			o.authnContextClassRefs = cfs
		}
	}
}

// WithIndent indent the XML document when marshalling it.
func WithIndent(indent int) Option {
	return func(o interface{}) {
		if o, ok := o.(*authnRequestOptions); ok {
			o.indent = indent
		}
	}
}

// WithClock changes the clock used when generating requests.
func WithClock(clock clockwork.Clock) Option {
	return func(o interface{}) {
		switch opts := o.(type) {
		case *authnRequestOptions:
			opts.clock = clock
		case *parseResponseOptions:
			opts.clock = clock
		}
	}
}

// WithAssertionConsumerServiceURL changes the Assertion Consumer Service URL
// to use in the Auth Request or during the response validation
func WithAssertionConsumerServiceURL(url string) Option {
	return func(o interface{}) {
		switch opts := o.(type) {
		case *authnRequestOptions:
			opts.assertionConsumerServiceURL = url
		case *parseResponseOptions:
			opts.assertionConsumerServiceURL = url
		}
	}
}

// CreateAuthnRequest creates an Authentication Request object.
// The defaults follow the deployment profile for federation interoperability.
// See: 3.1.1 https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_service_provider_requirements [INT_SAML]
//
// Options:
// - WithClock
// - ForceAuthn
// - AllowCreate
// - WithIDFormat
// - WithProtocolBinding
// - WithAuthContextClassRefs
// - WithAssertionConsumerServiceURL
func (sp *ServiceProvider) CreateAuthnRequest(
	id string,
	binding core.ServiceBinding,
	opt ...Option,
) (*core.AuthnRequest, error) {
	const op = "saml.ServiceProvider.CreateAuthnRequest"

	if id == "" {
		return nil, fmt.Errorf("%s: no ID provided: %w", op, oidc.ErrInvalidParameter)
	}

	if binding == "" {
		return nil, fmt.Errorf("%s: no binding provided: %w", op, oidc.ErrInvalidParameter)
	}

	opts := getAuthnRequestOptions(opt...)

	destination, err := sp.destination(binding)
	if err != nil {
		return nil, fmt.Errorf(
			"%s: failed to get destination for given service binding (%s): %w",
			op,
			binding,
			err,
		)
	}

	ar := &core.AuthnRequest{}

	ar.ID = id
	ar.Version = core.SAMLVersion2
	ar.ProtocolBinding = opts.protocolBinding

	// [INT_SAML][SDP-SP05][SDP-SP06]
	// "The message SHOULD contain an AssertionConsumerServiceURL attribute and MUST NOT contain an
	// AssertionConsumerServiceIndex attribute (i.e., the desired endpoint MUST be the default,
	// or identified via the AssertionConsumerServiceURL attribute)."
	ar.AssertionConsumerServiceURL = sp.cfg.AssertionConsumerServiceURL
	if opts.assertionConsumerServiceURL != "" {
		ar.AssertionConsumerServiceURL = opts.assertionConsumerServiceURL
	}

	ar.IssueInstant = opts.clock.Now().UTC()
	ar.Destination = destination

	ar.Issuer = &core.Issuer{}
	ar.Issuer.Value = sp.cfg.EntityID

	// [INT_SAML][SDP-SP04]
	// "The <samlp:AuthnRequest> message MUST either omit the <samlp:NameIDPolicy> element (RECOMMENDED),
	// or the element MUST contain an AllowCreate attribute of "true" and MUST NOT contain a Format attribute."
	if opts.allowCreate || opts.nameIDFormat != "" {
		ar.NameIDPolicy = &core.NameIDPolicy{
			AllowCreate: opts.allowCreate,
		}

		// This will only be set if the option WithNameIDFormat is set.
		if opts.nameIDFormat != "" {
			ar.NameIDPolicy.Format = opts.nameIDFormat
		}
	}

	// [INT_SAML][SDP-SP07]
	// "An SP that does not require a specific <saml:AuthnContextClassRef> value MUST NOT include a
	// <samlp:RequestedAuthnContext> element in its requests.
	// An SP that requires specific <saml:AuthnContextClassRef> values MUST specify the allowable values
	// in a <samlp:RequestedAuthnContext> element in its requests, with the Comparison attribute set to exact."
	if len(opts.authnContextClassRefs) > 0 {
		ar.RequestedAuthContext = &core.RequestedAuthnContext{
			AuthnContextClassRef: opts.authnContextClassRefs,
			Comparison:           core.ComparisonExact,
		}
	}

	ar.ForceAuthn = opts.forceAuthn

	return ar, nil
}

// AuthnRequestPost creates an AuthRequest with HTTP-Post binding.
func (sp *ServiceProvider) AuthnRequestPost(
	relayState string, opt ...Option,
) ([]byte, *core.AuthnRequest, error) {
	requestID, err := sp.cfg.GenerateAuthRequestID()
	if err != nil {
		return nil, nil, err
	}

	authN, err := sp.CreateAuthnRequest(requestID, core.ServiceBindingHTTPPost)
	if err != nil {
		return nil, nil, err
	}

	opts := getAuthnRequestOptions(opt...)
	payload, err := authN.CreateXMLDocument(opts.indent)
	if err != nil {
		return nil, nil, err
	}

	b64Payload := base64.StdEncoding.EncodeToString(payload)

	tmpl := template.Must(
		template.New("post-binding").Parse(postBindingTempl),
	)

	buf := bytes.Buffer{}

	if err := tmpl.Execute(&buf, map[string]string{
		"Destination": authN.Destination,
		"SAMLRequest": b64Payload,
		"RelayState":  relayState,
	}); err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), authN, nil
}

func WritePostBindingRequestHeader(w http.ResponseWriter) {
	w.Header().
		Add("Content-Security-Policy", fmt.Sprintf("script-src '%s'", postBindingScriptSha256))
	w.Header().Add("Content-type", "text/html")
}

func (sp *ServiceProvider) AuthnRequestRedirect(
	relayState string, opts ...Option,
) (*url.URL, *core.AuthnRequest, error) {
	const op = "saml.ServiceProvider.AuthnRequestRedirect"

	requestID, err := sp.cfg.GenerateAuthRequestID()
	if err != nil {
		return nil, nil, err
	}

	authN, err := sp.CreateAuthnRequest(requestID, core.ServiceBindingHTTPRedirect, opts...)
	if err != nil {
		return nil, nil, err
	}

	payload, err := Deflate(authN, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to deflate/compress request: %w", op, err)
	}

	b64Payload := base64.StdEncoding.EncodeToString(payload)

	redirect, err := url.Parse(authN.Destination)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to parse destination URL: %w", op, err)
	}

	// if sp.SignRequest {
	// 	ctx := sp.SigningContext()
	// 	qs.Add("SigAlg", ctx.GetSignatureMethodIdentifier())
	// 	var rawSignature []byte
	// 	if rawSignature, err = ctx.SignString(signatureInputString(qs.Get("SAMLRequest"), qs.Get("RelayState"), qs.Get("SigAlg"))); err != nil {
	// 		return "", fmt.Errorf("unable to sign query string of redirect URL: %v", err)
	// 	}

	// 	// Now add base64 encoded Signature
	// 	qs.Add("Signature", base64.StdEncoding.EncodeToString(rawSignature))
	// }

	vals := redirect.Query()
	vals.Set("SAMLRequest", b64Payload)

	if relayState != "" {
		vals.Set("RelayState", relayState)
	}

	redirect.RawQuery = vals.Encode()

	return redirect, authN, nil
}

// Deflate returns an AuthnRequest in the Deflate file format, applying default
// compression.
func Deflate(authn *core.AuthnRequest, opt ...Option) ([]byte, error) {
	buf := bytes.Buffer{}
	opts := getAuthnRequestOptions(opt...)

	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	defer fw.Close()

	encoder := xml.NewEncoder(fw)
	encoder.Indent("", strings.Repeat(" ", opts.indent))
	err = encoder.Encode(authn)
	if err != nil {
		return nil, err
	}

	if err := fw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
