// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// azureGroups is the structured response from the Microsoft Graph API when fetching group IDs for a user.
// The Value field contains a slice of group IDs.
type azureGroups struct {
	Value []string `json:"value"`
}

const (

	// Deprecated: The Azure AD (AAD) Graph API hosts.
	azureADGraphHost   = "graph.windows.net"
	azureADGraphUSHost = "graph.microsoftazure.us"
	azureADGraphCNHost = "graph.chinacloudapi.cn"

	// The Microsoft Graph API hosts.
	microsoftGraphHost      = "graph.microsoft.com"
	microsoftGraphUSHost    = "graph.microsoft.us"
	microsoftGraphUSDodHost = "dod-graph.microsoft.us"
	microsoftGraphCNHost    = "microsoftgraph.chinacloudapi.cn"

	// getMemberObjectsPath is the path to the Microsoft Graph API endpoint for
	// retrieving the groups a user is a member of.
	getMemberObjectsPath = "/v1.0/me/getMemberObjects"

	// claimNameField and claimsSourceField are the Azure distributed claims fields.
	claimNameField   = "_claim_names"
	claimSourceField = "_claim_sources"

	// claimGroupsField is the Azure defined key within _claim_names that indicates
	// the groups claim has been distributed due to token size constraints.
	claimGroupsField = "groups"

	// claimEndpointField is the Azure defined key within _claim_sources that indicates
	// the endpoint to call to retrieve the distributed groups claim.
	claimEndpointField = "endpoint"
)

// supportedGraphHosts maps each supported Graph API host to its actively
// supported Microsoft Graph API equivalent, including deprecated Azure AD
// Graph API hosts.
var supportedGraphHosts = map[string]string{
	azureADGraphHost:        microsoftGraphHost,
	azureADGraphUSHost:      microsoftGraphUSHost,
	azureADGraphCNHost:      microsoftGraphCNHost,
	microsoftGraphHost:      microsoftGraphHost,
	microsoftGraphUSHost:    microsoftGraphUSHost,
	microsoftGraphUSDodHost: microsoftGraphUSDodHost,
	microsoftGraphCNHost:    microsoftGraphCNHost,
}

// ResolveGroupClaims will detect an Azure groups overage indicator in the
// provided claims and fetch the full list of group IDs from the Microsoft
// Graph API using the provided OAuth2 token. When no overage indicator is
// present, it returns an empty map. On success, the returned map contains
// a "groups" key populated with the user's group IDs.
func ResolveGroupClaims(ctx context.Context, client *http.Client, token *oauth2.Token, claims map[string]any) (map[string]any, error) {
	const op = "azure.ResolveGroupClaims"
	switch {
	case client == nil:
		return nil, fmt.Errorf("%s: nil http client: %w", op, ErrNilParameter)
	case token == nil:
		return nil, fmt.Errorf("%s: nil oauth2 token: %w", op, ErrNilParameter)
	case claims == nil:
		return nil, fmt.Errorf("%s: nil claims map: %w", op, ErrNilParameter)
	case len(claims) == 0:
		// If there are no claims, there are certainly no distributed claims to resolve.
		return map[string]any{}, nil
	}

	host, ok := fetchGroupsOverageHost(claims)
	if !ok {
		// If there is no overage claim, there is nothing to resolve.
		return map[string]any{}, nil
	}

	endpoint, err := graphGroupsEndpoint(host)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to resolve graph groups endpoint: %w", op, err)
	}

	groupIDs, err := fetchGroupIDs(ctx, client, token, endpoint)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to fetch group IDs from graph API: %w", op, err)
	}

	return map[string]any{
		claimGroupsField: groupIDs,
	}, nil
}

// knownGraphHost reports whether host is within the known set of Microsoft
// Graph API hosts, including deprecated Azure AD Graph API hosts that Azure
// may still emit.
func knownGraphHost(host string) bool {
	_, ok := supportedGraphHosts[host]
	return ok
}

// fetchGroupsOverageHost fetches the Azure Graph API host from the provided
// overage claims if they are present and match against a known set of
// Microsoft supported endpoints. Example overage claim structure:
//
//	{
//	    "_claim_names": {
//	        "groups": "src1"
//	    },
//	    "_claim_sources": {
//	        "src1": {
//	            "endpoint": "https://graph.microsoft.com/v1.0/users/{userID}/getMemberObjects"
//	        }
//	    }
//	}
func fetchGroupsOverageHost(claims map[string]any) (string, bool) {
	if len(claims) == 0 {
		return "", false
	}
	// Check for the presence of the _claim_names field and ensure it's a map.
	claimNames, ok := claims[claimNameField].(map[string]any)
	if !ok || claimNames == nil {
		return "", false
	}
	// Fetch the source key for the groups claim from _claim_names.
	sourceKey, ok := claimNames[claimGroupsField].(string)
	if !ok || sourceKey == "" {
		return "", false
	}
	// Check for the presence of the _claim_sources field and ensure it's a map.
	sources, ok := claims[claimSourceField].(map[string]any)
	if !ok || sources == nil {
		return "", false
	}

	// Fetch the source for the groups claim from _claim_sources retrieved using the sourceKey from _claim_names.
	source, ok := sources[sourceKey].(map[string]any)
	if !ok || source == nil {
		return "", false
	}

	// Fetch the endpoint for the groups claim within _claim_sources.
	endpoint, ok := source[claimEndpointField].(string)
	if !ok || endpoint == "" {
		return "", false
	}

	// Parse the endpoint URL to extract the host and validate it against known Graph API hosts.
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", false
	}

	if !knownGraphHost(u.Host) {
		return "", false
	}

	return u.Host, true
}

// graphGroupsEndpoint returns the Microsoft Graph API endpoint for retrieving a user's
// groups, based on the provided Graph host.
func graphGroupsEndpoint(host string) (*url.URL, error) {
	const op = "azure.graphGroupsEndpoint"
	if host == "" {
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidParameter)
	}

	h, ok := supportedGraphHosts[host]
	if !ok {
		return nil, fmt.Errorf("%s: unknown graph host %s: %w", op, host, ErrInvalidParameter)
	}

	url, err := url.Parse(fmt.Sprintf("https://%s%s", h, getMemberObjectsPath))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse graph endpoint URL: %w", op, err)
	}

	return url, nil
}

// fetchGroupIDs calls the Microsoft Graph API at the given endpoint and returns
// a slice of group IDs the authenticated user belongs to.
func fetchGroupIDs(ctx context.Context, client *http.Client, token *oauth2.Token, endpoint *url.URL) ([]string, error) {
	const op = "azure.fetchGroupIDs"
	switch {
	case client == nil:
		return nil, fmt.Errorf("%s: nil http client: %w", op, ErrNilParameter)
	case token == nil:
		return nil, fmt.Errorf("%s: nil oauth2 token: %w", op, ErrNilParameter)
	case endpoint == nil:
		return nil, fmt.Errorf("%s: missing endpoint: %w", op, ErrInvalidParameter)
	}

	payload := strings.NewReader("{\"securityEnabledOnly\": false}")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), payload)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", op, err)
	}

	req.Header.Add("content-type", "application/json")
	token.SetAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: graph API request failed: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: graph API request failed with status %d", op, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read the graph API response body: %w", op, err)
	}

	var groups azureGroups
	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, fmt.Errorf("%s: failed to unmarshal the graph API response body: %w", op, err)
	}

	return groups.Value, nil
}
