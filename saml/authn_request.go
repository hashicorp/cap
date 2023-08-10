package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/hashicorp/cap/oidc"

	"github.com/hashicorp/cap/saml/models/core"
)

const (
	postBindingScriptSha256 = "T8Q9GZiIVtYoNIdF6UW5hDNgJudFDijQM/usO+xUkes="
)

type authnRequestOptions struct {
	allowCreate           bool
	nameIDFormat          core.NameIDFormat
	forceAuthn            bool
	protocolBinding       core.ServiceBinding
	authnContextClassRefs []string
}

func authnRequestOptionsDefault() authnRequestOptions {
	return authnRequestOptions{
		allowCreate:     false,
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

// CreateAuthNRequest creates an Authentication Request object.
// The defaults follow the deployment profile for federation interoperability.
// See: 3.1.1 https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_service_provider_requirements [INT_SAML]
//
// Options:
// - ForceAuthn
// - AllowCreate
// - WithIDFormat
// - WithProtocolBinding
// - WithAuthContextClassRefs
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
	ar.AssertionConsumerServiceURL = sp.cfg.AssertionConsumerServiceURL.String()
	ar.IssueInstant = time.Now().UTC()
	ar.Destination = destination

	ar.Issuer = &core.Issuer{}
	ar.Issuer.Value = sp.cfg.EntityID.String()

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
			AuthnConextClassRef: opts.authnContextClassRefs,
			Comparison:          core.ComparisonExact,
		}
	}

	ar.ForceAuthn = opts.forceAuthn

	return ar, nil
}

// AuthnRequestPost creates an AuthRequest with HTTP-Post binding.
func (sp *ServiceProvider) AuthnRequestPost(relayState string) ([]byte, *core.AuthnRequest, error) {
	requestID, err := sp.cfg.GenerateAuthRequestID()
	if err != nil {
		return nil, nil, err
	}

	authN, err := sp.CreateAuthnRequest(requestID, core.ServiceBindingHTTPPost)
	if err != nil {
		return nil, nil, err
	}

	payload, err := authN.CreateXMLDocument()
	if err != nil {
		return nil, nil, err
	}

	b64Payload := base64.StdEncoding.EncodeToString(payload)

	tmpl := template.Must(
		template.New("post-binding").Parse(PostBindingTempl),
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
	requestID, err := sp.cfg.GenerateAuthRequestID()
	if err != nil {
		return nil, nil, err
	}

	authN, err := sp.CreateAuthnRequest(requestID, core.ServiceBindingHTTPRedirect, opts...)
	if err != nil {
		return nil, nil, err
	}

	output, err := xml.Marshal(authN)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println(string(output))

	payload, err := b64Deflate(authN)
	if err != nil {
		return nil, nil, err
	}

	b64Payload := base64.StdEncoding.EncodeToString(payload)

	redirect, err := url.Parse(authN.Destination)
	if err != nil {
		return nil, nil, err
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

func b64Deflate(authn *core.AuthnRequest) ([]byte, error) {
	buf := bytes.Buffer{}

	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	defer fw.Close()

	err = xml.NewEncoder(fw).Encode(authn)
	if err != nil {
		return nil, err
	}

	if err := fw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
