// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func ExampleJWT() {
	cid := "client-id"
	aud := []string{"audience"}

	// With an HMAC client secret
	secret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 bytes for HS256
	j, err := NewJWTWithHMAC(cid, aud, HS256, secret)
	if err != nil {
		log.Fatal(err)
	}
	signed, err := j.Serialize()
	if err != nil {
		log.Fatal(err)
	}

	{
		// decode and inspect the JWT -- this is the IDP's job,
		// but it illustrates the example.
		token, err := jwt.ParseSigned(signed, []jose.SignatureAlgorithm{"HS256"})
		if err != nil {
			log.Fatal(err)
		}
		headers := token.Headers[0]
		fmt.Printf("ClientSecret\n  Headers - Algorithm: %s; typ: %s\n",
			headers.Algorithm, headers.ExtraHeaders["typ"])
		var claim jwt.Claims
		err = token.Claims([]byte(secret), &claim)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  Claims  - Issuer: %s; Subject: %s; Audience: %v\n",
			claim.Issuer, claim.Subject, claim.Audience)
	}

	// With an RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	pubKey, ok := privKey.Public().(*rsa.PublicKey)
	if !ok {
		log.Fatal("couldn't get rsa.PublicKey from PrivateKey")
	}
	j, err = NewJWTWithRSAKey(cid, aud, RS256, privKey,
		// note: for some providers, they key ID may be an x5t derivation
		// of a cert generated from the private key.
		// if your key has an associated JWKS endpoint, it will be the "kid"
		// for the public key at /.well-known/jwks.json
		WithKeyID("some-key-id"),
		// extra headers, like x5t, are optional
		WithHeaders(map[string]string{
			"x5t": "should-be-derived-from-a-cert",
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	signed, err = j.Serialize()
	if err != nil {
		log.Fatal(err)
	}

	{ // decode and inspect the JWT -- this is the IDP's job
		token, err := jwt.ParseSigned(signed, []jose.SignatureAlgorithm{"RS256"})
		if err != nil {
			log.Fatal(err)
		}
		h := token.Headers[0]
		fmt.Printf("PrivateKey\n  Headers - KeyID: %s; Algorithm: %s; typ: %s; x5t: %s\n",
			h.KeyID, h.Algorithm, h.ExtraHeaders["typ"], h.ExtraHeaders["x5t"])
		var claim jwt.Claims
		err = token.Claims(pubKey, &claim)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  Claims  - Issuer: %s; Subject: %s; Audience: %v\n",
			claim.Issuer, claim.Subject, claim.Audience)
	}

	// Output:
	// ClientSecret
	//   Headers - Algorithm: HS256; typ: JWT
	//   Claims  - Issuer: client-id; Subject: client-id; Audience: [audience]
	// PrivateKey
	//   Headers - KeyID: some-key-id; Algorithm: RS256; typ: JWT; x5t: should-be-derived-from-a-cert
	//   Claims  - Issuer: client-id; Subject: client-id; Audience: [audience]
}
