package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

// createP12 creates a PKCS12 file from the private key and certificate
// Uses modern encryption compatible with macOS Keychain
func createP12(keyPath, certPath, outputPath, password string) error {
	// Read the private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key (handle both encrypted and unencrypted keys)
	var privKey *rsa.PrivateKey
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from key file")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		// Decrypt PKCS#8 encrypted key
		if password == "" {
			return fmt.Errorf("password required to decrypt private key")
		}
		keyInterface, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %w", err)
		}
		var ok bool
		privKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not an RSA key")
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		// Unencrypted PKCS#1 key
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported key type: %s", block.Type)
	}

	// Read the certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse the certificate
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("failed to decode PEM block from certificate file")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create PKCS12 bundle with legacy RC2 encryption for macOS Keychain compatibility
	// Use password-based encryption
	var pfxData []byte
	if password == "" {
		// Use empty password for unencrypted bundles
		pfxData, err = pkcs12.Legacy.Encode(privKey, cert, nil, "")
	} else {
		// Use password for encrypted bundles
		pfxData, err = pkcs12.Legacy.Encode(privKey, cert, nil, password)
	}
	if err != nil {
		return fmt.Errorf("failed to encode PKCS12: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, pfxData, 0600); err != nil {
		return fmt.Errorf("failed to write PKCS12 file: %w", err)
	}

	return nil
}

// createCombinedPEM converts a P12 file to a combined PEM containing both private key and certificate
// Uses native Go to read PKCS12 and write PEM
func createCombinedPEM(p12Path, outputPath, password string) error {
	// Read PKCS12 file
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		return fmt.Errorf("failed to read PKCS12 file: %w", err)
	}

	// Decode PKCS12 with legacy support
	var privKey interface{}
	var cert *x509.Certificate
	var caCerts []*x509.Certificate

	if password == "" {
		privKey, cert, caCerts, err = pkcs12.DecodeChain(pfxData, "")
	} else {
		privKey, cert, caCerts, err = pkcs12.DecodeChain(pfxData, password)
	}
	if err != nil {
		return fmt.Errorf("failed to decode PKCS12: %w", err)
	}

	// Open output file
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create PEM file: %w", err)
	}
	defer file.Close()

	// Write private key
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an RSA key")
	}

	var keyBlock *pem.Block
	if password != "" {
		// Encrypt the private key
		encryptedDER, err := pkcs8.ConvertPrivateKeyToPKCS8(rsaKey, []byte(password))
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		keyBlock = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: encryptedDER,
		}
	} else {
		// Unencrypted key
		keyBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}
	}

	if err := pem.Encode(file, keyBlock); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Write certificate
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	if err := pem.Encode(file, certBlock); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	// Write CA certificates if present
	for _, caCert := range caCerts {
		caBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		}
		if err := pem.Encode(file, caBlock); err != nil {
			return fmt.Errorf("failed to encode CA certificate: %w", err)
		}
	}

	return nil
}
