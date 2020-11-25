package oidc

import "time"

const expirySkew = 10 * time.Second

type Token struct {
	RefreshToken string
	AccessToken  string
	Expiry       time.Time
	IdToken      string
}

func (t *Token) Expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Before(time.Now().Add(expirySkew))
}

func (t *Token) Valid() bool {
	if t == nil {
		return false
	}
	if t.AccessToken == "" {
		return false
	}
	return !t.Expired()
}
