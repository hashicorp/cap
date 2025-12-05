// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package jwt_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/hashicorp/cap/jwt"
)

func ExampleValidator_Validate() {
	ctx := context.Background()

	keySet, err := jwt.NewJSONWebKeySet(ctx, "your_jwks_url", "your_jwks_ca_pem")
	if err != nil {
		log.Fatal(err)
	}

	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		log.Fatal(err)
	}

	expected := jwt.Expected{
		Issuer:            "your_expected_issuer",
		Subject:           "your_expected_subject",
		ID:                "your_expected_jwt_id",
		Audiences:         []string{"your_expected_audiences"},
		SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleHBfaXNzIiwiZXhwIjoxNTI2MjM5MDIyfQ.XG1xYJcuPMfgu8xkMzVjkYK2WIUyl4-A1Zq1j4Dfr99-PJUN36ZAgi8Fj08modiexXETrg05MqSxkJAE5Czns1IhqEEypx6xfYHSINp0SLKxBFHPA4BCi0IW83T-e225JjjVEGFR_Wo8QM6Rc-qQVJ9bqwKD4kcbQeMACkgGFcgNurtNkOM9vtOEs0Pe9tb4nHYw4ef1stCytTi9GFZwGoHQf0pjpWCpjlxaFIR4vmHQ4YB3w29o_tKN6zqyA2FITnvkzGnaLvdPecJNskRSCPUTRfYcVVNXCOnCvTdpvwK-c4nCs5yGnw3eeFoT6mhQSp39KYti1MpHNQTYwZrLTA"
	claims, err := validator.Validate(ctx, token, expected)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(claims)
}

func ExampleNewJSONWebKeySet() {
	ctx := context.Background()

	keySet, err := jwt.NewJSONWebKeySet(ctx, "your_jwks_url", "your_jwks_ca_pem")
	if err != nil {
		log.Fatal(err)
	}

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleHBfaXNzIiwiZXhwIjoxNTI2MjM5MDIyfQ.XG1xYJcuPMfgu8xkMzVjkYK2WIUyl4-A1Zq1j4Dfr99-PJUN36ZAgi8Fj08modiexXETrg05MqSxkJAE5Czns1IhqEEypx6xfYHSINp0SLKxBFHPA4BCi0IW83T-e225JjjVEGFR_Wo8QM6Rc-qQVJ9bqwKD4kcbQeMACkgGFcgNurtNkOM9vtOEs0Pe9tb4nHYw4ef1stCytTi9GFZwGoHQf0pjpWCpjlxaFIR4vmHQ4YB3w29o_tKN6zqyA2FITnvkzGnaLvdPecJNskRSCPUTRfYcVVNXCOnCvTdpvwK-c4nCs5yGnw3eeFoT6mhQSp39KYti1MpHNQTYwZrLTA"
	claims, err := keySet.VerifySignature(ctx, token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(claims)
}

func ExampleNewOIDCDiscoveryKeySet() {
	ctx := context.Background()

	keySet, err := jwt.NewOIDCDiscoveryKeySet(ctx, "your_issuer_url", "your_issuer_ca_pem")
	if err != nil {
		log.Fatal(err)
	}

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleHBfaXNzIiwiZXhwIjoxNTI2MjM5MDIyfQ.XG1xYJcuPMfgu8xkMzVjkYK2WIUyl4-A1Zq1j4Dfr99-PJUN36ZAgi8Fj08modiexXETrg05MqSxkJAE5Czns1IhqEEypx6xfYHSINp0SLKxBFHPA4BCi0IW83T-e225JjjVEGFR_Wo8QM6Rc-qQVJ9bqwKD4kcbQeMACkgGFcgNurtNkOM9vtOEs0Pe9tb4nHYw4ef1stCytTi9GFZwGoHQf0pjpWCpjlxaFIR4vmHQ4YB3w29o_tKN6zqyA2FITnvkzGnaLvdPecJNskRSCPUTRfYcVVNXCOnCvTdpvwK-c4nCs5yGnw3eeFoT6mhQSp39KYti1MpHNQTYwZrLTA"
	claims, err := keySet.VerifySignature(ctx, token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(claims)
}

func ExampleNewStaticKeySet() {
	ctx := context.Background()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	keys := []crypto.PublicKey{
		rsaKey.Public(),
	}

	keySet, err := jwt.NewStaticKeySet(keys)
	if err != nil {
		log.Fatal(err)
	}

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleHBfaXNzIiwiZXhwIjoxNTI2MjM5MDIyfQ.XG1xYJcuPMfgu8xkMzVjkYK2WIUyl4-A1Zq1j4Dfr99-PJUN36ZAgi8Fj08modiexXETrg05MqSxkJAE5Czns1IhqEEypx6xfYHSINp0SLKxBFHPA4BCi0IW83T-e225JjjVEGFR_Wo8QM6Rc-qQVJ9bqwKD4kcbQeMACkgGFcgNurtNkOM9vtOEs0Pe9tb4nHYw4ef1stCytTi9GFZwGoHQf0pjpWCpjlxaFIR4vmHQ4YB3w29o_tKN6zqyA2FITnvkzGnaLvdPecJNskRSCPUTRfYcVVNXCOnCvTdpvwK-c4nCs5yGnw3eeFoT6mhQSp39KYti1MpHNQTYwZrLTA"
	claims, err := keySet.VerifySignature(ctx, token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(claims)
}
