package oidc

type Client interface {
	Start(ctx, statePayload interface{}, opts ...Option) (stateId string, providerURL string)
	Authenticate(ctx, providerAuthURL string, opts ...Option) error
}

type DefaultClient struct {
}

func NewDefaultClient(opts ...Option) (Client, error) {
	panic("todo")
}
