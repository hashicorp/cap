// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"

	"github.com/jonboulle/clockwork"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

type parseResponseOptions struct {
	clock                            clockwork.Clock
	skipRequestIDValidation          bool
	skipAssertionConditionValidation bool
	skipSignatureValidation          bool
	assertionConsumerServiceURL      string
	validateResponseSignature        bool
	validateAssertionSignature       bool
}

func parseResponseOptionsDefault() parseResponseOptions {
	return parseResponseOptions{
		clock:                            clockwork.NewRealClock(),
		skipRequestIDValidation:          false,
		skipAssertionConditionValidation: false,
		skipSignatureValidation:          false,
		validateResponseSignature:        false,
		validateAssertionSignature:       false,
	}
}

func getParseResponseOptions(opt ...Option) parseResponseOptions {
	opts := parseResponseOptionsDefault()
	ApplyOpts(&opts, opt...)
	return opts
}

// InsecureSkipRequestIDValidation disables/skips if the given requestID matches
// the InResponseTo parameter in the SAML response. This options should only
// be used for testing purposes.
func InsecureSkipRequestIDValidation() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.skipRequestIDValidation = true
		}
	}
}

// InsecureSkipAssertionConditionValidation disables/skips validation of the assertion
// conditions within the SAML response. This options should only be used for
// testing purposes.
func InsecureSkipAssertionConditionValidation() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.skipAssertionConditionValidation = true
		}
	}
}

// InsecureSkipSignatureValidation disables/skips validation of the SAML Response and its assertions.
// This options should only be used for testing purposes.
func InsecureSkipSignatureValidation() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.skipSignatureValidation = true
		}
	}
}

// ValidateResponseSignature enables signature validation to ensure the response is at least signed
func ValidateResponseSignature() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.validateResponseSignature = true
		}
	}
}

// ValidateAssertionSignature enables signature validation to ensure the assertion is at least signed
func ValidateAssertionSignature() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.validateAssertionSignature = true
		}
	}
}

// ParseResponse parses and validates a SAML Reponse.
//
// Options:
// - InsecureSkipRequestIDValidation
// - InsecureSkipAssertionConditionValidation
// - InsecureSkipSignatureValidation
// - WithAssertionConsumerServiceURL
// - WithClock
func (sp *ServiceProvider) ParseResponse(
	samlResp string,
	requestID string,
	opt ...Option,
) (*core.Response, error) {
	const op = "saml.(ServiceProvider).ParseResponse"
	opts := getParseResponseOptions(opt...)

	switch {
	case sp == nil:
		return nil, fmt.Errorf("%s: missing service provider %w", op, ErrInternal)
	case samlResp == "":
		return nil, fmt.Errorf("%s: missing saml response: %w", op, ErrInvalidParameter)
	case requestID == "":
		return nil, fmt.Errorf("%s: missing request ID: %w", op, ErrInvalidParameter)
	case opts.skipSignatureValidation && (opts.validateResponseSignature || opts.validateAssertionSignature):
		return nil, fmt.Errorf("%s: option `skip signature validation` cannot be true with any validate signature option : %w", op, ErrInvalidParameter)
	}

	// We use github.com/russellhaering/gosaml2 for SAMLResponse signature and condition validation.
	ip, err := sp.internalParser(
		opts.skipSignatureValidation,
		opts.assertionConsumerServiceURL,
		opts.clock,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: error initializing parser: %w", op, err)
	}

	// This will validate the response and all assertions.
	response, err := ip.ValidateEncodedResponse(samlResp)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: unable to validate encoded response: %w", op, err)
	case len(response.Assertions) == 0:
		// note: this is currently unreachable since the call to
		// ip.ValidateEncodedResponse(...) above will return an err if there are
		// no assertions, but we've left this here since it's a required for our
		// implementation as well.
		return nil, fmt.Errorf("%s: %w", op, ErrMissingAssertions)
	case !opts.skipRequestIDValidation && response.InResponseTo != requestID:
		return nil, fmt.Errorf(
			"InResponseTo (%s) doesn't match the expected requestID (%s)",
			response.InResponseTo,
			requestID,
		)
	case !opts.skipAssertionConditionValidation:
		// Verify conditions for all assertions
		for _, assert := range response.Assertions {
			warnings, err := ip.VerifyAssertionConditions(&assert)
			switch {
			case err != nil:
				return nil, fmt.Errorf("%s: %w", op, err)
			case warnings.InvalidTime:
				// note: this is currently unreachable since the call to
				// ip.ValidateEncodedResponse(...) above will return an err if
				// the time is invalid, but we've left this here since it's a
				// required for our implementation as well.
				return nil, fmt.Errorf("%s: %w", op, ErrInvalidTime)
			case warnings.NotInAudience:
				return nil, fmt.Errorf("%s: %w", op, ErrInvalidAudience)
			case assert.Subject == nil || assert.Subject.NameID == nil:
				// note: this is currently unreachable since the call to
				// ip.ValidateEncodedResponse(...) above will return an err if
				// there isn't a subject, but we've left this here since it's a
				// required for our implementation as well.
				return nil, fmt.Errorf("%s: %w", op, ErrMissingSubject)
			case assert.AttributeStatement == nil:
				return nil, fmt.Errorf("%s: %w", op, ErrMissingAttributeStmt)
			}
		}
	}

	samlResponse := core.Response{Response: *response}
	if opts.validateResponseSignature || opts.validateAssertionSignature {
		// func ip.ValidateEncodedResponse(...) above only requires either `response or all its `assertions` are signed,
		// but does not require both. The validateSignature function will validate either response or assertion
		// or both is surely signed depending on the parse response options given.
		if err := validateSignature(&samlResponse, op, opts); err != nil {
			return nil, err
		}
	}

	return &samlResponse, nil
}

func (sp *ServiceProvider) internalParser(
	skipSignatureValidation bool,
	assertionConsumerServiceURL string,
	clock clockwork.Clock,
) (*saml2.SAMLServiceProvider, error) {
	const op = "saml.(ServiceProvider).internalParser"
	switch {
	case isNil(clock):
		return nil, fmt.Errorf("%s: missing clock: %w", op, ErrInvalidParameter)
	}
	idpMetadata, err := sp.IDPMetadata()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: %w", op, err)
	case len(idpMetadata.IDPSSODescriptor) != 1:
		return nil, fmt.Errorf("%s: expected one IdP descriptor and got %d: %w", op, len(idpMetadata.IDPSSODescriptor), ErrInternal)
	}

	var certStore dsig.MemoryX509CertificateStore
	for _, kd := range idpMetadata.IDPSSODescriptor[0].KeyDescriptor {
		switch kd.Use {
		case "", metadata.KeyTypeSigning:
			for _, xcert := range kd.KeyInfo.X509Data.X509Certificates {
				parsed, err := parseX509Certificate(xcert.Data)
				if err != nil {
					return nil, fmt.Errorf("%s: unable to parse cert: %w", op, err)
				}
				certStore.Roots = append(certStore.Roots, parsed) // append works just fine with a nil slice
			}
		}
	}

	if assertionConsumerServiceURL == "" {
		assertionConsumerServiceURL = sp.cfg.AssertionConsumerServiceURL
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      idpMetadata.EntityID,
		IDPCertificateStore:         &certStore,
		ServiceProviderIssuer:       sp.cfg.EntityID,
		AudienceURI:                 sp.cfg.EntityID,
		AssertionConsumerServiceURL: assertionConsumerServiceURL,
		SkipSignatureValidation:     skipSignatureValidation,
		Clock:                       dsig.NewFakeClock(clock),
	}, nil
}

// parseX509Certificate parses the contents of a <ds:X509Certificate> which is a
// base64-encoded ASN.1 DER certificate. It does not parse PEM-encoded certificates.
func parseX509Certificate(cert string) (*x509.Certificate, error) {
	const op = "saml.parseCert"
	switch {
	case cert == "":
		return nil, fmt.Errorf("%s: missing certificate: %w", op, ErrInvalidParameter)
	default:
		regex := regexp.MustCompile(`\s+`)
		cert = regex.ReplaceAllString(cert, "")
		if cert == "" {
			return nil, fmt.Errorf("%s: certificate was only whitespace: %w", op, ErrInvalidParameter)
		}
	}
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("cannot decode certificate: %s", err)
	}
	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %s", err)
	}

	return parsedCert, nil
}

func parsePEMCertificate(cert []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(cert)
	if block == nil {
		return nil, fmt.Errorf("no certificate found")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("extra data found after certificate: %s", rest)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("wrong block type found: %q", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

func validateSignature(response *core.Response, op string, opts parseResponseOptions) error {
	// validate child object assertions
	for _, assert := range response.Assertions() {
		// note: at one time func ip.ValidateEncodedResponse(...) above allows all signed or all unsigned
		// assertions, and will give error if there is a mix of both. We are still looping on all assertions
		// instead of retrieving signature for one assertion, so we do not depend on dependency implementation.
		if !assert.SignatureValidated && opts.validateAssertionSignature {
			return fmt.Errorf("%s: %w", op, ErrInvalidSignature)
		}
	}

	// validate root object response
	if !response.SignatureValidated && opts.validateResponseSignature {
		return fmt.Errorf("%s: %w", op, ErrInvalidSignature)
	}

	return nil
}
