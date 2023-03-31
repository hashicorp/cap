package core_test

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/core/fictures"
)

func Test_ParseResponse_ResponseContainer(t *testing.T) {
	r := require.New(t)

	res := responseXML(t)

	r.Equal(res.Destination, "http://localhost:8000/saml/acs")
	r.Equal(res.ID, "saml-response-id")
	r.Equal(res.InResponseTo, "saml-request-id")
	r.Equal(res.IssueInstant.String(), "2023-03-31 06:55:44.494 +0000 UTC")
	r.Equal(res.Version, "2.0")
}

func Test_ParseResponse_Issuer(t *testing.T) {
	r := require.New(t)

	iss := responseXML(t).Issuer

	r.Equal(iss.Value, "https://samltest.id/saml/idp")
}

func Test_ParseResponse_Status(t *testing.T) {
	r := require.New(t)

	status := responseXML(t).Status

	r.Equal(status.StatusCode.Value, core.StatusCodeSuccess)
}

func responseXML(t *testing.T) core.Response {
	t.Helper()

	r := require.New(t)

	res := core.Response{}

	err := xml.Unmarshal([]byte(fictures.ResponseXML), &res)
	r.NoError(err)

	return res
}
