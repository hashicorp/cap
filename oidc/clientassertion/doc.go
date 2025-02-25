package clientassertion

// clientassertion signs JWTs with a Private Key or Client Secret for use
// in OIDC client_assertion requests, A.K.A. private_key_jwt. reference:
// https://oauth.net/private-key-jwt/
//
// Example usage:
//
// cass, err := clientassertion.New("client-id", []string{"audience"},
// 	clientassertion.WithRSAKey(rsaPrivateKey, "RS256"),
// 	clientassertion.WithKeyID("jwks-key-id-or-x5t-etc"),
// )
// jwtString, err := cass.SignedToken()
