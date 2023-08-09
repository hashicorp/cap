package saml

import (
	"crypto/x509"
	"encoding/base64"
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

func parseReponseOptionsDefault() parseResponseOptions {
	return parseResponseOptions{
		skipRequestIDValidation:          false,
		skipAssertionConditionValidation: false,
		skipSignatureValidation:          false,
	}
}

func getParseResponseOptions(opt ...Option) parseResponseOptions {
	opts := parseReponseOptionsDefault()
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

	// We use github.com/russellhaering/gosaml2 for SAMLResponse signiture and condition validation.
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

func (sp *ServiceProvider) internalParser(
	skipSignatureValidation bool,
) (*saml2.SAMLServiceProvider, error) {
	meta, err := sp.FetchMetadata()
	if err != nil {
		return nil, err
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range meta.IDPSSODescriptor[0].KeyDescriptor {
		switch kd.Use {
		case "", "signing":
			for _, xcert := range kd.KeyInfo.X509Data.X509Certificates {
				parsed, err := parseCert(xcert.Data)
				if err != nil {
					return nil, err
				}

				certStore.Roots = append(certStore.Roots, parsed)
			}
		}
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      meta.EntityID,
		ServiceProviderIssuer:       sp.cfg.Issuer.String(),
		AssertionConsumerServiceURL: sp.cfg.AssertionConsumerServiceURL.String(),
		AudienceURI:                 sp.cfg.EntityID.String(),
		IDPCertificateStore:         &certStore,
		SkipSignatureValidation:     skipSignatureValidation,
	}, nil
}

func parseCert(cert string) (*x509.Certificate, error) {
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
