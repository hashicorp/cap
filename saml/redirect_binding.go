package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"net/url"

	"github.com/hashicorp/go-uuid"

	"github.com/hashicorp/cap/saml/models/core"
)

func (sp *ServiceProvider) AuthNRequestRedirect(
	relayState string,
) (*url.URL, *core.AuthnRequest, error) {
	requestID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, err
	}

	authN, err := sp.CreateAuthnRequest(requestID, core.ServiceBindingHTTPRedirect)
	if err != nil {
		return nil, nil, err
	}

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
