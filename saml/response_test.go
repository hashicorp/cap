// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package saml_test

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
	testprovider "github.com/hashicorp/cap/saml/test"
)

var testExpiredResp = `PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpSZXNwb25zZSBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo4MDAwL3NhbWwvYWNzIiBJRD0iXzg4NDljMmVlNTMyZmNkYjc4MWYyYTE3NzZlYWMzNzQxIiBJblJlc3BvbnNlVG89ImJjNWE1YmFhLTk0ZTAtNThhOC04NzJjLWU1MTQ5MWQyYjNlZSIgSXNzdWVJbnN0YW50PSIyMDIzLTA4LTI1VDE0OjMyOjUzLjY4MFoiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnhzZD0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc2FtbHRlc3QuaWQvc2FtbC9pZHA8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNfODg0OWMyZWU1MzJmY2RiNzgxZjJhMTc3NmVhYzM3NDEiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjxlYzpJbmNsdXNpdmVOYW1lc3BhY2VzIFByZWZpeExpc3Q9InhzZCIgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3JtPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPlJWNDg1dUtHSlptTkExbzU2Z3h4aytWWmt2eE1xdGxIWkEyaUhIOFpVMVE9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmQzTHBjNmhjU0I3YndDek1yTzN3ZlpyTmlHazVnWjhyS1JLT1FFTkRQMnErcDMrTGtEbVNCdDZ6enl4bjMzTUNTSnQrZFBIcEYxNFlNQUsvTjNQbld3U1NVcDBqNWt6T2M5S2E1TmRpYW5FME5nWW5VMHFqaEZKYlRoQVF6N2hSb3dTNEo0OWhTLzZNdVNRMFo3bkJCQ2VEZ2VENlBZUkFwS012bE90a0JHUEphTFQybVJ5L2duUStDQzZ1ZFVkSnl2U2diOW40M2x2eGRhYVpXckRLM1dnYTk4WWxrY1JITHJtUEFBTThLeFlXbmtvcGlvNllJTlU0RDVtWmpzRXNuVWtINDFXZ2N3Z21TMnh6UDNJQ25OYzNXSDlOSHJWS3A5YXQyREJ3cllESXNlczZGWGdZcStpVVdLMjE5MWpXcElDM3FWQUIwY09pbG1SWHd0RUg3Zz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlERWpDQ0FmcWdBd0lCQWdJVkFNRUNRMXRqZ2hhZm01T3hXRGg5aHdaZnh0aFdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1CWXhGREFTCkJnTlZCQU1NQzNOaGJXeDBaWE4wTG1sa01CNFhEVEU0TURneU5ESXhNVFF3T1ZvWERUTTRNRGd5TkRJeE1UUXdPVm93RmpFVU1CSUcKQTFVRUF3d0xjMkZ0YkhSbGMzUXVhV1F3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzBaNFFYMU5GSwpzNzF1ZmJRd29Rb1c3cWtOQUpSSUFOR0E0aU0wVGhZZ2h1bDNwQytGd3JHdjM3YVR4V1hmQTFVRzluaktiYkRyZWlEQVpLbmdDZ3lqCnhqMHVKNGxBcmdrcjRBT0VqajV6WEE4MXVHSEFSZlVCY3R2UWNzWnBCSXhET3ZVVUltQWwrM05xTGdNR0YyZmt0eE1HN2tYM0dFVk4KYzFrbGJOM2RmWXNhdzVkVXJ3MjVEaGVMOW5wN0cvKzI4R3dIUHZMYjRhcHRPaU9OYkNhVnZoOVVNSEVBOUY3YzB6ZkYvY0w1Zk9wZApWYTU0d1RJMHUxMkNzRkt0NzhoNmxFR0c1alVzL3FYOWNsWm5jSk03RUZrTjNpbVBQeSswSEM4bnNwWGlIL01aVzhvMmNxV1JrcnczCk16QlpXM09qazVuUWo0MFY2TlViamI3a2ZlanpBZ01CQUFHalZ6QlZNQjBHQTFVZERnUVdCQlFUNlk5SjNUdy9oT0djOFBOVjdKRUUKNGsyWk5UQTBCZ05WSFJFRUxUQXJnZ3R6WVcxc2RHVnpkQzVwWklZY2FIUjBjSE02THk5ellXMXNkR1Z6ZEM1cFpDOXpZVzFzTDJsawpjREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBU2szZ3VLZlRrVmhFYUlWdnhFUE5SMnczdld0M2Z3bXdKQ2NjVzk4WFhMV2dOYnUzCllhTWIyUlNuN1RoNHAzaCttZnlrMmRvbjZhdTdVeXpjMUpkMzlSTnY4MFRHNWlRb3hmQ2dwaHkxRlltbWRhU2ZPOHd2RHRIVFROaUwKQXJBeE9ZdHpmWWJ6YjVRck5OSC9nUUVOOFJKYUVmL2cvMUdUdzl4LzEwM2RTTUswUlh0bCtmUnMybmJsRDFKSktTUTNBZGh4Sy93ZQpQM2FVUHRMeFZWSjl3TU9RT2ZjeTAybCtoSE1iNnVBanNQT3BPVktxaTNNOFhtY1VaT3B4NHN3dGdHZGVvU3BlUnlydE12UndkY2NpCk5CcDlVWm9tZTQ0cVpBWUgxaXFycG1tanNmSTlwSkl0c2dXdTNrWFBqaFNmajFBSkdSMWw5Skd2SnJIa2kxaUhUQT09PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpTdGF0dXM+PHNhbWwycDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWwycDpTdGF0dXM+PHNhbWwyOkFzc2VydGlvbiBJRD0iXzM1ZWE5MGI3MTFkNmYzODUzNDVmMGRiZGQ3ZDBlZDViIiBJc3N1ZUluc3RhbnQ9IjIwMjMtMDgtMjVUMTQ6MzI6NTMuNjgwWiIgVmVyc2lvbj0iMi4wIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWwyOklzc3Vlcj5odHRwczovL3NhbWx0ZXN0LmlkL3NhbWwvaWRwPC9zYW1sMjpJc3N1ZXI+PHNhbWwyOlN1YmplY3Q+PHNhbWwyOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyIgTmFtZVF1YWxpZmllcj0iaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcCIgU1BOYW1lUXVhbGlmaWVyPSJodHRwOi8vc2FtbC5qdWx6L2V4YW1wbGUiIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5tc21pdGhAc2FtbHRlc3QuaWQ8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBBZGRyZXNzPSIxMDQuMjguMzkuMzQiIEluUmVzcG9uc2VUbz0iYmM1YTViYWEtOTRlMC01OGE4LTg3MmMtZTUxNDkxZDJiM2VlIiBOb3RPbk9yQWZ0ZXI9IjIwMjMtMDgtMjVUMTQ6Mzc6NTMuNjkzWiIgUmVjaXBpZW50PSJodHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbC9hY3MiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyMy0wOC0yNVQxNDozMjo1My42ODBaIiBOb3RPbk9yQWZ0ZXI9IjIwMjMtMDgtMjVUMTQ6Mzc6NTMuNjgwWiI+PHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWwyOkF1ZGllbmNlPmh0dHA6Ly9zYW1sLmp1bHovZXhhbXBsZTwvc2FtbDI6QXVkaWVuY2U+PC9zYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDI6Q29uZGl0aW9ucz48c2FtbDI6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIzLTA4LTI1VDE0OjMxOjU2LjA2NFoiIFNlc3Npb25JbmRleD0iX2Y3MmE2M2VlMzc4MmI0N2M4OWY2MGU4MWFkZGUwYWIwIj48c2FtbDI6U3ViamVjdExvY2FsaXR5IEFkZHJlc3M9IjEwNC4yOC4zOS4zNCIvPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50PjxzYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWwyOkF0dHJpYnV0ZSBGcmllbmRseU5hbWU9ImVkdVBlcnNvbkVudGl0bGVtZW50IiBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuNyIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZT5BbWJhc3NhZG9yPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48c2FtbDI6QXR0cmlidXRlVmFsdWU+Tm9uZTwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PC9zYW1sMjpBdHRyaWJ1dGU+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDphdHRyaWJ1dGU6c3ViamVjdC1pZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHNkOnN0cmluZyI+bXNtaXRoQHNhbWx0ZXN0LmlkPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIEZyaWVuZGx5TmFtZT0idWlkIiBOYW1lPSJ1cm46b2lkOjAuOS4yMzQyLjE5MjAwMzAwLjEwMC4xLjEiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDI6QXR0cmlidXRlVmFsdWU+bW9ydHk8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJ0ZWxlcGhvbmVOdW1iZXIiIE5hbWU9InVybjpvaWQ6Mi41LjQuMjAiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDI6QXR0cmlidXRlVmFsdWU+KzEtNTU1LTU1NS01NTA1PC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIEZyaWVuZGx5TmFtZT0icm9sZSIgTmFtZT0iaHR0cHM6Ly9zYW1sdGVzdC5pZC9hdHRyaWJ1dGVzL3JvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzZDpzdHJpbmciPmphbml0b3JAc2FtbHRlc3QuaWQ8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJtYWlsIiBOYW1lPSJ1cm46b2lkOjAuOS4yMzQyLjE5MjAwMzAwLjEwMC4xLjMiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDI6QXR0cmlidXRlVmFsdWU+bXNtaXRoQHNhbWx0ZXN0LmlkPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIEZyaWVuZGx5TmFtZT0ic24iIE5hbWU9InVybjpvaWQ6Mi41LjQuNCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZT5TbWl0aDwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PC9zYW1sMjpBdHRyaWJ1dGU+PHNhbWwyOkF0dHJpYnV0ZSBGcmllbmRseU5hbWU9ImRpc3BsYXlOYW1lIiBOYW1lPSJ1cm46b2lkOjIuMTYuODQwLjEuMTEzNzMwLjMuMS4yNDEiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDI6QXR0cmlidXRlVmFsdWU+TW9ydHkgU21pdGg8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgRnJpZW5kbHlOYW1lPSJnaXZlbk5hbWUiIE5hbWU9InVybjpvaWQ6Mi41LjQuNDIiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDI6QXR0cmlidXRlVmFsdWU+TW9ydGltZXI8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjwvc2FtbDI6QXR0cmlidXRlU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg==`

func TestServiceProvider_ParseResponse(t *testing.T) {
	t.Parallel()
	const (
		testRequestId = "test-request-id"
		testEntityID  = "http://hashicorp-cap.test"
		testAcs       = "http://hashicorp-cap.test/saml/acs"
	)

	tp := testprovider.StartTestProvider(t)
	defer tp.Close()

	metadataURL := fmt.Sprintf("%s/saml/metadata", tp.ServerURL())

	testCfg, err := saml.NewConfig(testEntityID, testAcs, metadataURL)
	require.NoError(t, err)
	testSp, err := saml.NewServiceProvider(testCfg)
	require.NoError(t, err)

	fakeTime, err := time.Parse("2006-01-02 15:04:05", "2023-08-25 14:33:53")
	require.NoError(t, err)

	testCfgWithBadMetadata, err := saml.NewConfig(testEntityID, testAcs, fmt.Sprintf("%s/saml/invalid", tp.ServerURL()))
	require.NoError(t, err)
	testSpWithInvalidMetadataURL, err := saml.NewServiceProvider(testCfgWithBadMetadata)
	require.NoError(t, err)

	tests := []struct {
		name            string
		sp              *saml.ServiceProvider
		samlResp        string
		requestID       string
		opts            []saml.Option
		want            *core.Response
		wantErrContains string
		wantErrIs       error
		wantErrAs       error
	}{
		{
			name:      "success - with both response and assertion signed",
			sp:        testSp,
			samlResp:  base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithResponseAndAssertionSigned()))),
			opts:      []saml.Option{},
			requestID: testRequestId,
		},
		{
			name:      "success - with just response signed",
			sp:        testSp,
			samlResp:  base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustResponseSigned()))),
			opts:      []saml.Option{},
			requestID: testRequestId,
		},
		{
			name:      "success - with just assertion signed",
			sp:        testSp,
			samlResp:  base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustAssertionSigned()))),
			opts:      []saml.Option{},
			requestID: testRequestId,
		},
		{
			name:      "success - with both options enabled of validating both signatures & with both response and assertion signed",
			sp:        testSp,
			samlResp:  base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithResponseAndAssertionSigned()))),
			opts:      []saml.Option{saml.ValidateResponseSignature(), saml.ValidateAssertionSignature()},
			requestID: testRequestId,
		},
		{
			name:      "success - with option of validate response signature & with only response signed",
			sp:        testSp,
			samlResp:  base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustResponseSigned()))),
			opts:      []saml.Option{saml.ValidateResponseSignature()},
			requestID: testRequestId,
		},
		{
			name:      "success - with option of validate assertion signature & with only assertion signed",
			sp:        testSp,
			samlResp:  base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustAssertionSigned()))),
			opts:      []saml.Option{saml.ValidateAssertionSignature()},
			requestID: testRequestId,
		},
		{
			name:            "missing signature",
			sp:              testSp,
			samlResp:        base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t))),
			opts:            []saml.Option{},
			requestID:       testRequestId,
			wantErrContains: "response and/or assertions must be signed",
		},
		{
			name:            "error-invalid-signature - with both options enabled of validating both signatures & with only response signed",
			sp:              testSp,
			samlResp:        base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustResponseSigned()))),
			opts:            []saml.Option{saml.ValidateResponseSignature(), saml.ValidateAssertionSignature()},
			requestID:       testRequestId,
			wantErrContains: "invalid signature",
		},
		{
			name:            "error-invalid-signature - with both options enabled of validating both signatures & with only assertion signed",
			sp:              testSp,
			samlResp:        base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustAssertionSigned()))),
			opts:            []saml.Option{saml.ValidateResponseSignature(), saml.ValidateAssertionSignature()},
			requestID:       testRequestId,
			wantErrContains: "invalid signature",
		},
		{
			name:            "error-invalid-signature - with option of validate response signature & with only assertion signed",
			sp:              testSp,
			samlResp:        base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustAssertionSigned()))),
			opts:            []saml.Option{saml.ValidateResponseSignature()},
			requestID:       testRequestId,
			wantErrContains: "invalid signature",
		},
		{
			name:            "error-invalid-signature - with option of validate assertion signature & with just response signed",
			sp:              testSp,
			samlResp:        base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithJustResponseSigned()))),
			opts:            []saml.Option{saml.ValidateAssertionSignature()},
			requestID:       testRequestId,
			wantErrContains: "invalid signature",
		},
		{
			name:     "err-assertion-missing-attribute-stmt",
			sp:       testSp,
			samlResp: base64.StdEncoding.EncodeToString([]byte(testRespInvalidAssertionMissingAttributeStmt)),
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
			},
			requestID:       testRequestId,
			wantErrContains: "attribute statement missing",
		},
		{
			name:     "err-assertion-missing-subject",
			sp:       testSp,
			samlResp: base64.StdEncoding.EncodeToString([]byte(testRespInvalidAssertionMissingSubject)),
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
			},
			requestID:       testRequestId,
			wantErrContains: "unable to validate encoded response: missing Subject element",
		},
		{
			name:     "err-assertion-missing-not-before",
			sp:       testSp,
			samlResp: base64.StdEncoding.EncodeToString([]byte(testRespInvalidAssertionMissingNotBefore)),
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
			},
			requestID:       testRequestId,
			wantErrContains: "missing NotBefore attribute on Conditions element",
		},
		{
			name:     "err-assertion-invalid-audience",
			sp:       testSp,
			samlResp: base64.StdEncoding.EncodeToString([]byte(testRespInvalidAssertionAudience)),
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
			},
			requestID:       testRequestId,
			wantErrContains: "invalid audience",
		},
		{
			name:     "err-no-assertions",
			sp:       testSp,
			samlResp: base64.StdEncoding.EncodeToString([]byte(testRespNoAssertions)),
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
			},
			requestID:       testRequestId,
			wantErrContains: "unable to validate encoded response: missing Assertion element",
		},
		{
			name:     "err-bad-metatdata-url",
			sp:       testSpWithInvalidMetadataURL,
			samlResp: testExpiredResp,
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
			},
			requestID:       "invalid-request-id",
			wantErrContains: "error initializing parser: saml.(ServiceProvider).internalParser: saml.ServiceProvider.FetchIDPMetadata: failed to parse identity provider XML metadata",
		},
		{
			name:     "err-unable-to-parse-resp",
			sp:       testSp,
			samlResp: "unable-to-parse-resp",
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
			},
			requestID:       testRequestId,
			wantErrContains: "unable to validate encoded response: illegal base64 data",
		},
		{
			name:            "err-in-response-to",
			sp:              testSp,
			samlResp:        base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t, testprovider.WithResponseAndAssertionSigned()))),
			requestID:       "invalid-request-id",
			wantErrContains: "doesn't match the expected requestID (invalid-request-id)",
		},
		{
			name: "expired",
			sp:   testSp,
			samlResp: base64.StdEncoding.EncodeToString([]byte(tp.SamlResponse(t,
				testprovider.WithResponseAndAssertionSigned(),
				testprovider.WithResponseExpired(),
			))),
			requestID:       "request-id",
			wantErrAs:       &saml2.ErrInvalidValue{},
			wantErrContains: "unable to validate encoded response: Expired NotOnOrAfter value",
		},
		{
			name:            "nil-sp",
			wantErrIs:       saml.ErrInternal,
			wantErrContains: "missing service provider",
		},
		{
			name:            "missing-saml-response",
			sp:              testSp,
			wantErrIs:       saml.ErrInvalidParameter,
			wantErrContains: "missing saml response",
		},
		{
			name:            "missing-request-id",
			sp:              testSp,
			samlResp:        testExpiredResp,
			wantErrIs:       saml.ErrInvalidParameter,
			wantErrContains: "missing request ID",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.sp.ParseResponse(tc.samlResp, tc.requestID, tc.opts...)
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Empty(got)
				assert.ErrorContains(err, tc.wantErrContains)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrAs != nil {
					assert.ErrorAs(err, tc.wantErrAs)
				}
				return
			}
			require.NoError(err, tc.name)
			assert.Equal(testRequestId, got.InResponseTo)
			assert.Equal("http://hashicorp-cap.test/saml/acs", got.Destination)
			assert.Equal("urn:oasis:names:tc:SAML:2.0:status:Success", got.Status.StatusCode.Value)
			assert.Equal("http://test.idp", got.Issuer())
			assert.Equal("name-id", got.Assertions()[0].Subject.NameID.Value)
			assert.Equal("assertion-id", got.Assertions()[0].ID)
		})
	}
}

func TestServiceProvider_ParseResponseCustomACS(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	fakeTime, err := time.Parse("2006-01-02", "2015-07-15")
	r.NoError(err)

	tp := testprovider.StartTestProvider(t)
	defer tp.Close()

	cfg, err := saml.NewConfig(
		"http://hashicorp-cap.test",
		"http://test.me/saml/acs",
		fmt.Sprintf("%s/saml/metadata", tp.ServerURL()),
	)
	r.NoError(err)

	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	encodedResponse := base64.StdEncoding.EncodeToString([]byte(responseUnsigned))

	type testCase struct {
		name string
		opts []saml.Option
		err  string
	}

	for _, c := range []testCase{
		{
			name: "default url",
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
			},
		},
		{
			name: "valid acs url",
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
				saml.WithAssertionConsumerServiceURL("http://test.me/saml/acs"),
			},
		},
		{
			name: "invalid acs url",
			opts: []saml.Option{
				saml.WithClock(clockwork.NewFakeClockAt(fakeTime)),
				saml.InsecureSkipSignatureValidation(),
				saml.WithAssertionConsumerServiceURL("http://badurl.me"),
			},
			err: "Unrecognized Destination value, Expected: http://badurl.me, Actual: http://test.me/saml/acs",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err = sp.ParseResponse(
				encodedResponse,
				"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685",
				c.opts...,
			)
			if c.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, c.err)
		})
	}
}

// From https://www.samltool.com/generic_sso_res.php
const responseUnsigned = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://test.me/saml/acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://test.idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://test.idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://test.me/saml/acs" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://test.me/saml/acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://hashicorp-cap.test</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

const testRespNoAssertions = `
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="http://hashicorp-cap.test/saml/acs" ID="_8849c2ee532fcdb781f2a1776eac3741" InResponseTo="bc5a5baa-94e0-58a8-872c-e51491d2b3ee" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
	xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<saml2:Issuer
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://test.idp</saml2:Issuer>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="#_8849c2ee532fcdb781f2a1776eac3741">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
						<ec:InclusiveNamespaces PrefixList="xsd"
							xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
						</ds:Transform>
					</ds:Transforms>
					<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<ds:DigestValue>RV485uKGJZmNA1o56gxxk+VZkvxMqtlHZA2iHH8ZU1Q=</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
			<ds:SignatureValue>d3Lpc6hcSB7bwCzMrO3wfZrNiGk5gZ8rKRKOQENDP2q+p3+LkDmSBt6zzyxn33MCSJt+dPHpF14YMAK/N3PnWwSSUp0j5kzOc9Ka5NdianE0NgYnU0qjhFJbThAQz7hRowS4J49hS/6MuSQ0Z7nBBCeDgeD6PYRApKMvlOtkBGPJaLT2mRy/gnQ+CC6udUdJyvSgb9n43lvxdaaZWrDK3Wga98YlkcRHLrmPAAM8KxYWnkopio6YINU4D5mZjsEsnUkH41WgcwgmS2xzP3ICnNc3WH9NHrVKp9at2DBwrYDIses6FXgYq+iUWK2191jWpIC3qVAB0cOilmRXwtEH7g==</ds:SignatureValue>
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEBCwUAMBYxFDAS
BgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4MDgyNDIxMTQwOVowFjEUMBIG
A1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFK
s71ufbQwoQoW7qkNAJRIANGA4iM0ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyj
xj0uJ4lArgkr4AOEjj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVN
c1klbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF/cL5fOpd
Va54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8nspXiH/MZW8o2cqWRkrw3
MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0GA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE
4k2ZNTA0BgNVHREELTArggtzYW1sdGVzdC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lk
cDANBgkqhkiG9w0BAQsFAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3
YaMb2RSn7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHTTNiL
ArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nblD1JJKSQ3AdhxK/we
P3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcUZOpx4swtgGdeoSpeRyrtMvRwdcci
NBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</ds:Signature>
		<saml2p:Status>
			<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</saml2p:Status>
	</saml2p:Response>
`

const testRespInvalidAssertionAudience = `
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="http://hashicorp-cap.test/saml/acs" ID="_8849c2ee532fcdb781f2a1776eac3741" InResponseTo="test-request-id" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
	xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<saml2:Issuer
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://test.idp</saml2:Issuer>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="#_8849c2ee532fcdb781f2a1776eac3741">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
						<ec:InclusiveNamespaces PrefixList="xsd"
							xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
						</ds:Transform>
					</ds:Transforms>
					<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<ds:DigestValue>RV485uKGJZmNA1o56gxxk+VZkvxMqtlHZA2iHH8ZU1Q=</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
			<ds:SignatureValue>d3Lpc6hcSB7bwCzMrO3wfZrNiGk5gZ8rKRKOQENDP2q+p3+LkDmSBt6zzyxn33MCSJt+dPHpF14YMAK/N3PnWwSSUp0j5kzOc9Ka5NdianE0NgYnU0qjhFJbThAQz7hRowS4J49hS/6MuSQ0Z7nBBCeDgeD6PYRApKMvlOtkBGPJaLT2mRy/gnQ+CC6udUdJyvSgb9n43lvxdaaZWrDK3Wga98YlkcRHLrmPAAM8KxYWnkopio6YINU4D5mZjsEsnUkH41WgcwgmS2xzP3ICnNc3WH9NHrVKp9at2DBwrYDIses6FXgYq+iUWK2191jWpIC3qVAB0cOilmRXwtEH7g==</ds:SignatureValue>
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEBCwUAMBYxFDAS
BgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4MDgyNDIxMTQwOVowFjEUMBIG
A1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFK
s71ufbQwoQoW7qkNAJRIANGA4iM0ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyj
xj0uJ4lArgkr4AOEjj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVN
c1klbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF/cL5fOpd
Va54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8nspXiH/MZW8o2cqWRkrw3
MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0GA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE
4k2ZNTA0BgNVHREELTArggtzYW1sdGVzdC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lk
cDANBgkqhkiG9w0BAQsFAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3
YaMb2RSn7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHTTNiL
ArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nblD1JJKSQ3AdhxK/we
P3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcUZOpx4swtgGdeoSpeRyrtMvRwdcci
NBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</ds:Signature>
		<saml2p:Status>
			<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</saml2p:Status>
		<saml2:Assertion ID="_35ea90b711d6f385345f0dbdd7d0ed5b" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Issuer>http://test.idp</saml2:Issuer>
			<saml2:Subject>
				<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" NameQualifier="https://samltest.id/saml/idp" SPNameQualifier="http://saml.julz/example"
					xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">msmith@samltest.id
				</saml2:NameID>
				<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
					<saml2:SubjectConfirmationData Address="104.28.39.34" InResponseTo="test-request-id" NotOnOrAfter="2023-08-25T14:37:53.693Z" Recipient="http://hashicorp-cap.test/saml/acs"/>
				</saml2:SubjectConfirmation>
			</saml2:Subject>
			<saml2:Conditions NotBefore="2023-08-25T14:32:53.680Z" NotOnOrAfter="2023-08-25T14:37:53.680Z">
				<saml2:AudienceRestriction>
					<! -- audience is intentionally invalid -->. 
					<saml2:Audience>http://saml.julz/invalid-audience</saml2:Audience>
				</saml2:AudienceRestriction>
			</saml2:Conditions>
			<saml2:AuthnStatement AuthnInstant="2023-08-25T14:31:56.064Z" SessionIndex="_f72a63ee3782b47c89f60e81adde0ab0">
				<saml2:SubjectLocality Address="104.28.39.34"/>
				<saml2:AuthnContext>
					<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
				</saml2:AuthnContext>
			</saml2:AuthnStatement>
			<saml2:AttributeStatement>
				<saml2:Attribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Ambassador</saml2:AttributeValue>
					<saml2:AttributeValue>None</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">msmith@samltest.id
					</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>morty</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="telephoneNumber" Name="urn:oid:2.5.4.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>+1-555-555-5505</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="role" Name="https://samltest.id/attributes/role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">janitor@samltest.id
					</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>msmith@samltest.id</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Smith</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Morty Smith</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Mortimer</saml2:AttributeValue>
				</saml2:Attribute>
			</saml2:AttributeStatement>
		</saml2:Assertion>
	</saml2p:Response>`

const testRespInvalidAssertionMissingNotBefore = `
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="http://hashicorp-cap.test/saml/acs" ID="_8849c2ee532fcdb781f2a1776eac3741" InResponseTo="test-request-id" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
	xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<saml2:Issuer
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://test.idp</saml2:Issuer>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="#_8849c2ee532fcdb781f2a1776eac3741">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
						<ec:InclusiveNamespaces PrefixList="xsd"
							xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
						</ds:Transform>
					</ds:Transforms>
					<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<ds:DigestValue>RV485uKGJZmNA1o56gxxk+VZkvxMqtlHZA2iHH8ZU1Q=</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
			<ds:SignatureValue>d3Lpc6hcSB7bwCzMrO3wfZrNiGk5gZ8rKRKOQENDP2q+p3+LkDmSBt6zzyxn33MCSJt+dPHpF14YMAK/N3PnWwSSUp0j5kzOc9Ka5NdianE0NgYnU0qjhFJbThAQz7hRowS4J49hS/6MuSQ0Z7nBBCeDgeD6PYRApKMvlOtkBGPJaLT2mRy/gnQ+CC6udUdJyvSgb9n43lvxdaaZWrDK3Wga98YlkcRHLrmPAAM8KxYWnkopio6YINU4D5mZjsEsnUkH41WgcwgmS2xzP3ICnNc3WH9NHrVKp9at2DBwrYDIses6FXgYq+iUWK2191jWpIC3qVAB0cOilmRXwtEH7g==</ds:SignatureValue>
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEBCwUAMBYxFDAS
BgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4MDgyNDIxMTQwOVowFjEUMBIG
A1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFK
s71ufbQwoQoW7qkNAJRIANGA4iM0ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyj
xj0uJ4lArgkr4AOEjj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVN
c1klbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF/cL5fOpd
Va54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8nspXiH/MZW8o2cqWRkrw3
MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0GA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE
4k2ZNTA0BgNVHREELTArggtzYW1sdGVzdC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lk
cDANBgkqhkiG9w0BAQsFAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3
YaMb2RSn7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHTTNiL
ArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nblD1JJKSQ3AdhxK/we
P3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcUZOpx4swtgGdeoSpeRyrtMvRwdcci
NBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</ds:Signature>
		<saml2p:Status>
			<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</saml2p:Status>
		<saml2:Assertion ID="_35ea90b711d6f385345f0dbdd7d0ed5b" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Issuer>http://test.idp</saml2:Issuer>
			<saml2:Subject>
				<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" NameQualifier="https://samltest.id/saml/idp" SPNameQualifier="http://saml.julz/example"
					xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">msmith@samltest.id
				</saml2:NameID>
				<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
					<saml2:SubjectConfirmationData Address="104.28.39.34" InResponseTo="test-request-id" NotOnOrAfter="2023-08-25T14:37:53.693Z" Recipient="http://hashicorp-cap.test/saml/acs"/>
				</saml2:SubjectConfirmation>
			</saml2:Subject>
			<!-- intentionally missing NotBefore -->
			<saml2:Conditions NotOnOrAfter="2023-08-25T14:37:53.680Z">
				<saml2:AudienceRestriction>
           <saml2:Audience>http://hashicorp-cap.test</saml2:Audience>
				</saml2:AudienceRestriction>
			</saml2:Conditions>
			<saml2:AuthnStatement AuthnInstant="2023-08-25T14:31:56.064Z" SessionIndex="_f72a63ee3782b47c89f60e81adde0ab0">
				<saml2:SubjectLocality Address="104.28.39.34"/>
				<saml2:AuthnContext>
					<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
				</saml2:AuthnContext>
			</saml2:AuthnStatement>
			<saml2:AttributeStatement>
				<saml2:Attribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Ambassador</saml2:AttributeValue>
					<saml2:AttributeValue>None</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">msmith@samltest.id
					</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>morty</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="telephoneNumber" Name="urn:oid:2.5.4.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>+1-555-555-5505</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="role" Name="https://samltest.id/attributes/role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">janitor@samltest.id
					</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>msmith@samltest.id</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Smith</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Morty Smith</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Mortimer</saml2:AttributeValue>
				</saml2:Attribute>
			</saml2:AttributeStatement>
		</saml2:Assertion>
</saml2p:Response>
`

const testRespInvalidAssertionMissingSubject = `
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="http://hashicorp-cap.test/saml/acs" ID="_8849c2ee532fcdb781f2a1776eac3741" InResponseTo="test-request-id" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
	xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<saml2:Issuer
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://test.idp</saml2:Issuer>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="#_8849c2ee532fcdb781f2a1776eac3741">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
						<ec:InclusiveNamespaces PrefixList="xsd"
							xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
						</ds:Transform>
					</ds:Transforms>
					<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<ds:DigestValue>RV485uKGJZmNA1o56gxxk+VZkvxMqtlHZA2iHH8ZU1Q=</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
			<ds:SignatureValue>d3Lpc6hcSB7bwCzMrO3wfZrNiGk5gZ8rKRKOQENDP2q+p3+LkDmSBt6zzyxn33MCSJt+dPHpF14YMAK/N3PnWwSSUp0j5kzOc9Ka5NdianE0NgYnU0qjhFJbThAQz7hRowS4J49hS/6MuSQ0Z7nBBCeDgeD6PYRApKMvlOtkBGPJaLT2mRy/gnQ+CC6udUdJyvSgb9n43lvxdaaZWrDK3Wga98YlkcRHLrmPAAM8KxYWnkopio6YINU4D5mZjsEsnUkH41WgcwgmS2xzP3ICnNc3WH9NHrVKp9at2DBwrYDIses6FXgYq+iUWK2191jWpIC3qVAB0cOilmRXwtEH7g==</ds:SignatureValue>
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEBCwUAMBYxFDAS
BgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4MDgyNDIxMTQwOVowFjEUMBIG
A1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFK
s71ufbQwoQoW7qkNAJRIANGA4iM0ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyj
xj0uJ4lArgkr4AOEjj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVN
c1klbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF/cL5fOpd
Va54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8nspXiH/MZW8o2cqWRkrw3
MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0GA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE
4k2ZNTA0BgNVHREELTArggtzYW1sdGVzdC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lk
cDANBgkqhkiG9w0BAQsFAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3
YaMb2RSn7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHTTNiL
ArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nblD1JJKSQ3AdhxK/we
P3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcUZOpx4swtgGdeoSpeRyrtMvRwdcci
NBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</ds:Signature>
		<saml2p:Status>
			<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</saml2p:Status>
		<saml2:Assertion ID="_35ea90b711d6f385345f0dbdd7d0ed5b" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Issuer>http://test.idp</saml2:Issuer>
			<!-- intentionally missing subject -->
			<saml2:Conditions NotBefore="2023-08-25T14:32:53.680Z" NotOnOrAfter="2023-08-25T14:37:53.680Z">
				<saml2:AudienceRestriction>
            <saml2:Audience>http://hashicorp-cap.test</saml2:Audience>
				</saml2:AudienceRestriction>
			</saml2:Conditions>
			<saml2:AuthnStatement AuthnInstant="2023-08-25T14:31:56.064Z" SessionIndex="_f72a63ee3782b47c89f60e81adde0ab0">
				<saml2:SubjectLocality Address="104.28.39.34"/>
				<saml2:AuthnContext>
					<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
				</saml2:AuthnContext>
			</saml2:AuthnStatement>
			<saml2:AttributeStatement>
				<saml2:Attribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Ambassador</saml2:AttributeValue>
					<saml2:AttributeValue>None</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">msmith@samltest.id
					</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>morty</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="telephoneNumber" Name="urn:oid:2.5.4.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>+1-555-555-5505</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="role" Name="https://samltest.id/attributes/role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">janitor@samltest.id
					</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>msmith@samltest.id</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Smith</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Morty Smith</saml2:AttributeValue>
				</saml2:Attribute>
				<saml2:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
					<saml2:AttributeValue>Mortimer</saml2:AttributeValue>
				</saml2:Attribute>
			</saml2:AttributeStatement>
		</saml2:Assertion>
</saml2p:Response>
`

const testRespInvalidAssertionMissingAttributeStmt = `
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="http://hashicorp-cap.test/saml/acs" ID="_8849c2ee532fcdb781f2a1776eac3741" InResponseTo="test-request-id" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
	xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<saml2:Issuer
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://test.idp</saml2:Issuer>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="#_8849c2ee532fcdb781f2a1776eac3741">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
						<ec:InclusiveNamespaces PrefixList="xsd"
							xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
						</ds:Transform>
					</ds:Transforms>
					<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<ds:DigestValue>RV485uKGJZmNA1o56gxxk+VZkvxMqtlHZA2iHH8ZU1Q=</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
			<ds:SignatureValue>d3Lpc6hcSB7bwCzMrO3wfZrNiGk5gZ8rKRKOQENDP2q+p3+LkDmSBt6zzyxn33MCSJt+dPHpF14YMAK/N3PnWwSSUp0j5kzOc9Ka5NdianE0NgYnU0qjhFJbThAQz7hRowS4J49hS/6MuSQ0Z7nBBCeDgeD6PYRApKMvlOtkBGPJaLT2mRy/gnQ+CC6udUdJyvSgb9n43lvxdaaZWrDK3Wga98YlkcRHLrmPAAM8KxYWnkopio6YINU4D5mZjsEsnUkH41WgcwgmS2xzP3ICnNc3WH9NHrVKp9at2DBwrYDIses6FXgYq+iUWK2191jWpIC3qVAB0cOilmRXwtEH7g==</ds:SignatureValue>
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEBCwUAMBYxFDAS
BgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4MDgyNDIxMTQwOVowFjEUMBIG
A1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFK
s71ufbQwoQoW7qkNAJRIANGA4iM0ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyj
xj0uJ4lArgkr4AOEjj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVN
c1klbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF/cL5fOpd
Va54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8nspXiH/MZW8o2cqWRkrw3
MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0GA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE
4k2ZNTA0BgNVHREELTArggtzYW1sdGVzdC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lk
cDANBgkqhkiG9w0BAQsFAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3
YaMb2RSn7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHTTNiL
ArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nblD1JJKSQ3AdhxK/we
P3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcUZOpx4swtgGdeoSpeRyrtMvRwdcci
NBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</ds:Signature>
		<saml2p:Status>
			<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</saml2p:Status>
		<saml2:Assertion ID="_35ea90b711d6f385345f0dbdd7d0ed5b" IssueInstant="2023-08-25T14:32:53.680Z" Version="2.0"
			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
			<saml2:Issuer>http://test.idp</saml2:Issuer>
			<saml2:Subject>
  <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" NameQualifier="http://test.idp" SPNameQualifier="http://saml.julz/example"
					xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">msmith@samltest.id
				</saml2:NameID>
				<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
					<saml2:SubjectConfirmationData Address="104.28.39.34" InResponseTo="test-request-id" NotOnOrAfter="2023-08-25T14:37:53.693Z" Recipient="http://hashicorp-cap.test/saml/acs"/>
				</saml2:SubjectConfirmation>
			</saml2:Subject>
			<saml2:Conditions NotBefore="2023-08-25T14:32:53.680Z" NotOnOrAfter="2023-08-25T14:37:53.680Z">
				<saml2:AudienceRestriction>
					<saml2:Audience>http://hashicorp-cap.test</saml2:Audience>
				</saml2:AudienceRestriction>
			</saml2:Conditions>
			<saml2:AuthnStatement AuthnInstant="2023-08-25T14:31:56.064Z" SessionIndex="_f72a63ee3782b47c89f60e81adde0ab0">
				<saml2:SubjectLocality Address="104.28.39.34"/>
				<saml2:AuthnContext>
					<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
				</saml2:AuthnContext>
			</saml2:AuthnStatement>
			<!-- intentionally missing attribute stmt -->
			</saml2:Assertion>
	</saml2p:Response>`
