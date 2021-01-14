package jwt_test

import (
	"context"
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
		SigningAlgorithms: []string{"your_expected_signing_algs"},
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

	keySet, err := jwt.NewOIDCDiscoveryKeySet(ctx, "your_oidc_discovery_url", "your_oidc_discovery_ca_pem")
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

	pubKeys := []string{
		`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----`,
	}

	keySet, err := jwt.NewStaticKeySet(pubKeys)
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
