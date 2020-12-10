package oidc

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = RedactedClientSecret
		secret := ClientSecret("bob's phone number")
		assert.Equalf(want, secret.String(), "ClientSecret.String() = %v, want %v", secret.String(), want)
	})
}

func TestClientSecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, RedactedClientSecret)
		secret := ClientSecret("bob's phone number")
		got, err := secret.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "ClientSecret.MarshalJSON() = %s, want %s", got, want)
	})
}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	_, testCaPem := TestGenerateCA(t, []string{"localhost"})
	testNow := func() time.Time {
		return time.Now().Add(-1 * time.Minute)
	}

	type args struct {
		issuer       string
		clientID     string
		clientSecret ClientSecret
		supported    []Alg
		redirectURL  string
		opt          []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *Config
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-with-all-valid-opts",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
				opt: []Option{
					WithAudiences("YOUR_AUD1", "YOUR_AUD2"),
					WithScopes("email", "profile"),
					WithProviderCA(testCaPem),
					WithNow(testNow),
				},
			},
			want: &Config{
				Issuer:               "http://YOUR_ISSUER/",
				ClientID:             "YOUR_CLIENT_ID",
				ClientSecret:         "YOUR_CLIENT_SECRET",
				SupportedSigningAlgs: []Alg{RS512},
				RedirectURL:          "http://YOUR_REDIRECT_URL",
				Audiences:            []string{"YOUR_AUD1", "YOUR_AUD2"},
				Scopes:               []string{oidc.ScopeOpenID, "email", "profile"},
				ProviderCA:           testCaPem,
				NowFunc:              testNow,
			},
		},
		{
			name: "empty-issuer",
			args: args{
				issuer:       "",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "bad-issuer-scheme",
			args: args{
				issuer:       "ldap://bad-scheme",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "bad-issuer-url",
			args: args{
				issuer:       "http://bad-url\\",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "empty-client-id",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-client-secret",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-algs",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    nil,
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-redirect",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "invalid-providerCA",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectURL:  "http://YOUR_REDIRECT_URL",
				opt: []Option{
					WithProviderCA("bad certificate"),
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidCACert,
		},
		{
			name: "invalid-alg",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientID:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{"bad alg"},
				redirectURL:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewConfig(tt.args.issuer, tt.args.clientID, tt.args.clientSecret, tt.args.supported, tt.args.redirectURL, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			assert.Equalf(tt.want.ClientID, got.ClientID, "NewConfig() = %v, want %v", got.ClientID, tt.want.ClientID)
			assert.Equalf(tt.want.ClientSecret, got.ClientSecret, "NewConfig() = %v, want %v", got.ClientSecret, tt.want.ClientSecret)
			assert.Equalf(tt.want.Scopes, got.Scopes, "NewConfig() = %v, want %v", got.Scopes, tt.want.Scopes)
			assert.Equalf(tt.want.Issuer, got.Issuer, "NewConfig() = %v, want %v", got.Issuer, tt.want.Issuer)
			assert.Equalf(tt.want.SupportedSigningAlgs, got.SupportedSigningAlgs, "NewConfig() = %v, want %v", got.SupportedSigningAlgs, tt.want.SupportedSigningAlgs)
			assert.Equalf(tt.want.RedirectURL, got.RedirectURL, "NewConfig() = %v, want %v", got.RedirectURL, tt.want.RedirectURL)
			assert.Equalf(tt.want.Audiences, got.Audiences, "NewConfig() = %v, want %v", got.Audiences, tt.want.Audiences)
			assert.Equalf(tt.want.ProviderCA, got.ProviderCA, "NewConfig() = %v, want %v", got.ProviderCA, tt.want.ProviderCA)
			testAssertEqualFunc(t, tt.want.NowFunc, got.NowFunc, "now = %p,want %p", tt.want.NowFunc, got.NowFunc)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	// Validate testing is covered by TestNewConfig() but we do have just more
	// more test to add here.
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		var c *Config
		err := c.Validate()
		assert.Truef(errors.Is(err, ErrNilParameter), "Config.Validate() = %v, want %v", err, ErrNilParameter)
	})
}

func Test_WithScopes(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithScopes("alice", "bob"))
	testOpts := configDefaults()
	testOpts.withScopes = []string{oidc.ScopeOpenID, "alice", "bob"}
	assert.Equal(opts, testOpts)
}

func Test_WithAudiences(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithAudiences("alice", "bob"))
	testOpts := configDefaults()
	testOpts.withAudiences = []string{"alice", "bob"}
	assert.Equal(opts, testOpts)
}

func Test_WithProviderCA(t *testing.T) {
	t.Parallel()
	_, testCaPem := TestGenerateCA(t, []string{"localhost"})
	assert := assert.New(t)
	opts := getConfigOpts(WithProviderCA(testCaPem))
	testOpts := configDefaults()
	testOpts.withProviderCA = testCaPem
	assert.Equal(opts, testOpts)
}

func TestConfig_Now(t *testing.T) {
	tests := []struct {
		name    string
		nowFunc func() time.Time
		want    func() time.Time
		skew    time.Duration
	}{
		{
			name:    "default-time",
			nowFunc: nil,
			want:    time.Now,
			skew:    1 * time.Millisecond,
		},
		{
			name:    "time-travel-backward",
			nowFunc: func() time.Time { return time.Now().Add(-10 * time.Millisecond) },
			want:    func() time.Time { return time.Now().Add(-10 * time.Millisecond) },
			skew:    1 * time.Millisecond,
		},
		{
			name:    "time-travel-forward",
			nowFunc: func() time.Time { return time.Now().Add(10 * time.Millisecond) },
			want:    func() time.Time { return time.Now().Add(10 * time.Millisecond) },
			skew:    1 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			c := &Config{NowFunc: tt.nowFunc}
			assert.True(c.Now().Before(tt.want()))
			assert.True(c.Now().Add(tt.skew).After(tt.want()))
		})
	}
}

func TestEncodeCertificates(t *testing.T) {
	testCert, testPem := TestGenerateCA(t, []string{"localhost"})

	tests := []struct {
		name      string
		certs     []*x509.Certificate
		want      string
		wantErr   bool
		wantIsErr error
	}{
		{
			name:  "valid",
			certs: []*x509.Certificate{testCert, testCert},
			want:  testPem + testPem,
		},
		{
			name:      "no-certs",
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name:      "nil-cert",
			certs:     []*x509.Certificate{testCert, nil},
			wantErr:   true,
			wantIsErr: ErrNilParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := EncodeCertificates(tt.certs...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			if got != tt.want {
				t.Errorf("EncodeCertificates() = %v, want %v", got, tt.want)
			}
		})
	}
}
