package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/hashicorp/cap/saml/models/core"
)

type parseResponseOptions struct {
	skipRequestIDValidation          bool
	skipAssertionConditionValidation bool
	skipSignatureValidation          bool
}

func parseResponseOptionsDefault() parseResponseOptions {
	return parseResponseOptions{
		skipRequestIDValidation:          false,
		skipAssertionConditionValidation: false,
		skipSignatureValidation:          false,
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

// ParseResponse parses and validates a SAML Reponse.
//
// Options:
// - InsecureSkipRequestIDValidation
// - InsecureSkipAssertionConditionValidation
// - InsecureSkipSignatureValidation
func (sp *ServiceProvider) ParseResponse(
	samlResp string,
	requestID string,
	opt ...Option,
) (*core.Response, error) {
	opts := getParseResponseOptions(opt...)

	// We use github.com/russellhaering/gosaml2 for SAMLResponse signature and condition validation.
	ip, err := sp.internalParser(opts.skipSignatureValidation)
	if err != nil {
		return nil, err
	}

	// This will validate the response and all assertions.
	response, err := ip.ValidateEncodedResponse(samlResp)
	if err != nil {
		return nil, err
	}

	if !opts.skipRequestIDValidation {
		if response.InResponseTo != requestID {
			return nil, fmt.Errorf(
				"InResponseTo (%s) doesn't match the expected requestID (%s)",
				response.InResponseTo,
				requestID,
			)
		}
	}

	if len(response.Assertions) == 0 {
		return nil, errors.New("missing assertions")
	}

	// Verify conditions for all assertions
	if !opts.skipAssertionConditionValidation {
		for _, assert := range response.Assertions {
			warnings, err := ip.VerifyAssertionConditions(&assert)
			if err != nil {
				return nil, err
			}

			if warnings.InvalidTime {
				return nil, errors.New("invalid time")
			}

			if warnings.NotInAudience {
				return nil, errors.New("invalid audience")
			}

			if assert.Subject == nil || assert.Subject.NameID == nil {
				return nil, errors.New("subject missing")
			}

			if assert.AttributeStatement == nil {
				return nil, errors.New("attribute statement missing")
			}
		}
	}

	// TODO: transform gosaml2 response to core.Response
	var result core.Response
	xml.Unmarshal([]byte(samlResp), &result)

	return &result, nil
}

func (sp *ServiceProvider) internalParser(skipSignatureValidation bool) (*saml2.SAMLServiceProvider, error) {
	idpMetadata, err := sp.IDPMetadata()
	if err != nil {
		return nil, err
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range idpMetadata.IDPSSODescriptor[0].KeyDescriptor {
		switch kd.Use {
		case "", "signing":
			for _, xcert := range kd.KeyInfo.X509Data.X509Certificates {
				parsed, err := parseX509Certificate(xcert.Data)
				if err != nil {
					return nil, err
				}

				certStore.Roots = append(certStore.Roots, parsed)
			}
		}
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      idpMetadata.EntityID,
		IDPCertificateStore:         &certStore,
		ServiceProviderIssuer:       sp.cfg.EntityID,
		AudienceURI:                 sp.cfg.EntityID,
		AssertionConsumerServiceURL: sp.cfg.AssertionConsumerServiceURL,
		SkipSignatureValidation:     skipSignatureValidation,
	}, nil
}

// parseX509Certificate parses the contents of a <ds:X509Certificate> which is a
// base64-encoded ASN.1 DER certificate. It does not parse PEM-encoded certificates.
func parseX509Certificate(cert string) (*x509.Certificate, error) {
	regex := regexp.MustCompile(`\s+`)
	cert = regex.ReplaceAllString(cert, "")
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %s", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
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
