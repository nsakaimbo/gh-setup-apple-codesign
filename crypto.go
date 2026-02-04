package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/youmark/pkcs8"
)

// generateRSAKey generates a new RSA private key with the specified bit size
func generateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// createCSR creates a Certificate Signing Request from a private key and subject information
func createCSR(privKey *rsa.PrivateKey, commonName, organization, country string) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			Country:      []string{country},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, privKey)
}

// saveEncryptedPrivateKey saves a private key encrypted with a password using PKCS#8
func saveEncryptedPrivateKey(privKey *rsa.PrivateKey, outputPath, password string) error {
	var pemBlock *pem.Block
	var err error

	if password != "" {
		// Encrypt the key using PKCS#8 with AES-256-CBC (OpenSSL-compatible)
		encryptedDER, err := pkcs8.ConvertPrivateKeyToPKCS8(privKey, []byte(password))
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}

		pemBlock = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: encryptedDER,
		}
	} else {
		// Save unencrypted key in PKCS#1 format
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		}
	}

	// Write to file
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

// convertCertToPEM converts DER-encoded certificate bytes to PEM format
func convertCertToPEM(derBytes []byte, outputPath string) error {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create PEM file: %w", err)
	}
	defer file.Close()

	return pem.Encode(file, pemBlock)
}

// generateStubCertificate creates a self-signed certificate for testing purposes
func generateStubCertificate(privKey *rsa.PrivateKey, commonName, organization, country string) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			Country:      []string{country},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return certBytes, nil
}
