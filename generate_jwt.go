package main

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateJWT(keyID, issuerID, privateKeyStr string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuerID,
		"exp": time.Now().Add(time.Minute * 20).Unix(),
		"aud": "appstoreconnect-v1",
	})
	token.Header["kid"] = keyID

	return token.SignedString(key)
}
