package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

// Test fixtures - real PEM-formatted key and certificate (revoked, safe for testing)
const testPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz3+Ec5mT8oNT8AAT7v2RJEh2VYdxs4FDizU4KpXMbRwntdqM
JOh5mXoeA6cwV6Jf6+mkQ0zQ5SbU/0SmV//Rwd3xezBmo7ocJv/Sa6OOvTkOlwKo
UG9ORfB7uu28amT52yDKLuGpYpU/39bcrVT78IH588vC6KdUy9UErS9jVea5oGx3
Qw8x5xhAdqnPgirklieUQwAarb7puFLKycT6247KiFtWmLTuhirR12LFO8R3f5ls
cuoeJGkoqKw89vBxWr5AQmxObub8tqkZ1PxI3LNQsqaJk5to9GXUx+fAdvg5cGHH
puLPafTI2U597X3ld/PAOpsDPa1XVb8ybJS1YwIDAQABAoIBABwoBJQfKelFktVF
XW8Xr2NKBeyzNWWTS9QPA7EbpKLFqEnP/yZe+WkvHfWG8VNi8Ds1+Bk9yjbeHxcI
fL4CM7dn44XA2pyq+3j7S9VZW1wn6ufo72gCwo9RA6ko62FQlGr8txLHglGjSQiZ
wlYu6wUGziEb7DXfxuzl2f2aKZOVPYdufU/gqZ9doRSiVvqbAIGToRUxGnzkxfuj
uIj2KdQylYbKlPR/oxDz0Uh+H8RgZh2sqCPbQ7IOOXpdNfUsNWdBHsT8WddaL9HE
gplv9mLSp7o7MLbKDHCQQNCf495bWECNBN9LhMmMY3PZEODpENs+FCOSO3143uwV
biU+r9ECgYEA/3im7ExbHmQTedLyFHeKJqGKW2dXDrYM79Pqv9bvh35D4D57xzl5
ADKIqZh1N3z6TCl1aQCDI8f2+vBFMGvQdvJVZtDTBQhSXQeCfSb9JfDAiQ1dBqIN
dNPilh9NIHouzKDGc9Ddim+1j0FLV8iDCXs8G4sUnIiahjRIFmCVJmsCgYEAz+1z
BM6iEfTc3V+YpvMyMqs7pSFC3Pzeip6qMIY69WIsqxdKvXxoIYzOoDhEORG4KdZk
VAjqi8hBI7biw9E3OKGfV4bA5vVytUaH0GkuJnCYogZUVj0KP3kRwbpYWAN869mA
ZlY5qKn0sjtj/ssyIu/+2b/k2Tqw343dpCGBuukCgYEA3VPf+dRlFL1LCj4xMH4o
GDPXtDyhdcNPDfAg7rb9qftAPuSjRASMyhj9wUCuPLZv+s/oQmIJO1SgquLCbqLZ
ZlOonXzJdRCymppI+LhwlRAxHguPzpFS6yYupjTUExEHvoyDog8QAEGroELHTXQP
4oT7nDkwUDUg+qgM1CY00aUCgYBaSBew9qeYdGGSHXgCxYX+SitTv+VwXruiJNJw
z1e6RC5w+2QQcnwkVSdCmivFO9RjFhvqARUWLJVcFITR0X3QsRymvHP11I1B+KXv
8DuBpVIgx+7GoypX9RGotGi3jownPAFsbfQLMAB3gyIf98qFMP/PPGr5h2pVJxwd
sA7MQQKBgQCD2bsoZ+10FgLvLiqYwVVeFfEViV1BeTXlu0QEGQFh9QHfyyqMy0x1
aOFGe96P9atoyF4+8V851om+lbK4rWE5YjwOiNRqWgvobBHC4gD3fo7LSH3cEdXT
2rOlsU1vc8aCgdG48izpfOQEwkSJqIWg6SMzzOoh+QgetH8QQrtYFw==
-----END RSA PRIVATE KEY-----`

const testCertificatePEM = `-----BEGIN CERTIFICATE-----
MIIFzjCCBLagAwIBAgIQKWoHF/eaTXL6dSmQ4BNN0TANBgkqhkiG9w0BAQsFADB1
MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFw
cGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTI2MDIwMzE4MjY0M1oXDTI3MDIwMzE4
MjY0MlowgZQxGjAYBgoJkiaJk/IsZAEBDApOWVQ0MlRQSjhVMTgwNgYDVQQDDC9B
cHBsZSBEZXZlbG9wbWVudDogQ3JlYXRlZCB2aWEgQVBJIChOWVQ0MlRQSjhVKTET
MBEGA1UECwwKOExOQlM4UldIVzEaMBgGA1UECgwRTmljaG9sYXMgU2FrYWltYm8x
CzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3+E
c5mT8oNT8AAT7v2RJEh2VYdxs4FDizU4KpXMbRwntdqMJOh5mXoeA6cwV6Jf6+mk
Q0zQ5SbU/0SmV//Rwd3xezBmo7ocJv/Sa6OOvTkOlwKoUG9ORfB7uu28amT52yDK
LuGpYpU/39bcrVT78IH588vC6KdUy9UErS9jVea5oGx3Qw8x5xhAdqnPgirklieU
QwAarb7puFLKycT6247KiFtWmLTuhirR12LFO8R3f5lscuoeJGkoqKw89vBxWr5A
QmxObub8tqkZ1PxI3LNQsqaJk5to9GXUx+fAdvg5cGHHpuLPafTI2U597X3ld/PA
OpsDPa1XVb8ybJS1YwIDAQABo4ICODCCAjQwDAYDVR0TAQH/BAIwADAfBgNVHSME
GDAWgBQJ/sAVkPmvZAqSErkmKGMMl+ynsjBwBggrBgEFBQcBAQRkMGIwLQYIKwYB
BQUHMAKGIWh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vd3dkcmczLmRlcjAxBggrBgEF
BQcwAYYlaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy13d2RyZzMwNDCCAR4G
A1UdIASCARUwggERMIIBDQYJKoZIhvdjZAUBMIH/MIHDBggrBgEFBQcCAjCBtgyB
s1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3Vt
ZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRl
cm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFu
ZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDcGCCsGAQUFBwIB
FitodHRwczovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvMBYG
A1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTqSEl+F+0FXjVTL0dzg2Ir
bowAJDAOBgNVHQ8BAf8EBAMCB4AwEwYKKoZIhvdjZAYBAgEB/wQCBQAwEwYKKoZI
hvdjZAYBDAEB/wQCBQAwDQYJKoZIhvcNAQELBQADggEBABN2soHMnjOPNzlDB02U
5IRDpBHyZY5CpXzb4ydTjt0NkiM4Q1a8plEtJ8L1YxSFli9N01PXQFGwmZJjRTTp
yoicJY7Oc8/MkrT56N+r9E/Qbs9fZS18mj5kuafURl0VvfcVxqqs7z45KjWeTkIR
XCmENYMsR9IzAhzy5rX4nAtZhNgiI1K5vpoHftlwD84/wSxvexp5PLH+EQ2e1Y9o
niNKaCs8nKDPQhvOpsBSmPZaSzLEzwqFj6EWuYXgoGRleJTHDUtFLw16G4XCw6as
FOCMQ1peSNjsrbxS1UTI7PBMz4Z+j/U5M5T8cblpHjua2GVMQl2UQjwjrAqcF7Oy
h1c=
-----END CERTIFICATE-----`

const testPassword = "testpass123"

func TestGeneratePrivateKey(t *testing.T) {
	// Generate a 2048-bit RSA private key (same as main.go does)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Verify the key is not nil
	if privKey == nil {
		t.Fatal("Generated key is nil")
	}

	// Verify the key is 2048 bits
	if privKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", privKey.N.BitLen())
	}

	// Verify the key can be encoded to PEM
	keyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if len(keyBytes) == 0 {
		t.Fatal("Failed to marshal private key")
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if len(pemBytes) == 0 {
		t.Fatal("Failed to encode private key to PEM")
	}

	// Verify the PEM contains the expected header
	pemStr := string(pemBytes)
	if !strings.Contains(pemStr, "BEGIN RSA PRIVATE KEY") {
		t.Error("PEM does not contain expected RSA PRIVATE KEY header")
	}

	// Verify we can validate the key
	if err := privKey.Validate(); err != nil {
		t.Errorf("Generated key failed validation: %v", err)
	}
}

func TestGenerateAndSavePrivateKey_WithPassword(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_encrypted_key.pem")

	// Step 1: Generate a 2048-bit RSA private key (as main.go does)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Verify key was generated correctly
	if privKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", privKey.N.BitLen())
	}

	// Step 2: Save the generated key with password encryption
	err = saveEncryptedPrivateKey(privKey, outputPath, testPassword)
	if err != nil {
		t.Fatalf("Failed to save encrypted key: %v", err)
	}

	// Verify encrypted file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Encrypted key file was not created")
	}

	// Verify file contains ENCRYPTED marker
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "ENCRYPTED") {
		t.Error("Key file does not contain ENCRYPTED marker")
	}
	if !strings.Contains(contentStr, "BEGIN") && !strings.Contains(contentStr, "PRIVATE KEY") {
		t.Error("Key file does not contain expected PEM markers")
	}

	// Verify we can decrypt and validate the key using native Go
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	// Decrypt PKCS#8 encrypted key
	keyInterface, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to decrypt private key: %v", err)
	}

	// Verify it's an RSA key
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Decrypted key is not an RSA key")
	}

	// Verify the key is valid
	if err := rsaKey.Validate(); err != nil {
		t.Errorf("Decrypted key failed validation: %v", err)
	}

	// Verify it matches the original key
	if rsaKey.N.Cmp(privKey.N) != 0 {
		t.Error("Decrypted key does not match original key")
	}
}

func TestSavePrivateKey_WithPassword(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_key.pem")

	// Generate a test RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Save with password
	err = saveEncryptedPrivateKey(privKey, outputPath, testPassword)
	if err != nil {
		t.Fatalf("Failed to save encrypted key: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Encrypted key file was not created")
	}

	// Read the file and verify it contains encrypted marker
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "ENCRYPTED") {
		t.Error("Key file does not contain ENCRYPTED marker")
	}

	// Verify we can decrypt it using native Go
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	keyInterface, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(testPassword))
	if err != nil {
		t.Errorf("Failed to decrypt key with password: %v", err)
	}

	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		t.Error("Decrypted key is not an RSA key")
	}

	if err := rsaKey.Validate(); err != nil {
		t.Errorf("Decrypted key failed validation: %v", err)
	}
}

func TestSavePrivateKey_WithoutPassword(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_key.pem")

	// Generate a test RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Save without password (unencrypted)
	keyOut, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	keyOut.Close()
	if err != nil {
		t.Fatalf("Failed to encode key: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Unencrypted key file was not created")
	}

	// Read and verify it does NOT contain encrypted marker
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	contentStr := string(content)
	if strings.Contains(contentStr, "ENCRYPTED") {
		t.Error("Unencrypted key should not contain ENCRYPTED marker")
	}

	// Verify we can parse it directly
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse unencrypted private key: %v", err)
	}
}

func TestGenerateCSR(t *testing.T) {
	tests := []struct {
		name         string
		commonName   string
		organization string
		country      string
	}{
		{
			name:         "Standard CSR",
			commonName:   "Apple Development: Test User",
			organization: "Test Organization",
			country:      "US",
		},
		{
			name:         "Different Country",
			commonName:   "Test Certificate",
			organization: "Acme Inc",
			country:      "UK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test key
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Create CSR template
			template := x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   tt.commonName,
					Organization: []string{tt.organization},
					Country:      []string{tt.country},
				},
				SignatureAlgorithm: x509.SHA256WithRSA,
			}

			// Generate CSR
			csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
			if err != nil {
				t.Fatalf("Failed to create CSR: %v", err)
			}

			// Parse and verify CSR
			csr, err := x509.ParseCertificateRequest(csrBytes)
			if err != nil {
				t.Fatalf("Failed to parse CSR: %v", err)
			}

			// Verify subject fields
			if csr.Subject.CommonName != tt.commonName {
				t.Errorf("CommonName mismatch: got %s, want %s", csr.Subject.CommonName, tt.commonName)
			}

			if len(csr.Subject.Organization) == 0 || csr.Subject.Organization[0] != tt.organization {
				t.Errorf("Organization mismatch: got %v, want %s", csr.Subject.Organization, tt.organization)
			}

			if len(csr.Subject.Country) == 0 || csr.Subject.Country[0] != tt.country {
				t.Errorf("Country mismatch: got %v, want %s", csr.Subject.Country, tt.country)
			}

			// Verify signature algorithm
			if csr.SignatureAlgorithm != x509.SHA256WithRSA {
				t.Errorf("SignatureAlgorithm mismatch: got %v, want %v", csr.SignatureAlgorithm, x509.SHA256WithRSA)
			}

			// Verify PEM encoding
			var pemBuf []byte
			pemBuf = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
			if !strings.Contains(string(pemBuf), "BEGIN CERTIFICATE REQUEST") {
				t.Error("CSR PEM encoding is invalid")
			}
		})
	}
}

func TestCreateP12_WithPassword(t *testing.T) {
	tempDir := t.TempDir()

	// Write test fixtures to temp files
	keyPath := filepath.Join(tempDir, "test_key.pem")
	certPath := filepath.Join(tempDir, "test_cert.pem")
	p12Path := filepath.Join(tempDir, "test.p12")

	if err := os.WriteFile(keyPath, []byte(testPrivateKeyPEM), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(testCertificatePEM), 0600); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	// Create P12 with password
	err := createP12(keyPath, certPath, p12Path, testPassword)
	if err != nil {
		t.Fatalf("Failed to create P12: %v", err)
	}

	// Verify P12 file exists
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Fatal("P12 file was not created")
	}

	// Verify we can read and decode the P12 using native Go
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("Failed to read P12 file: %v", err)
	}

	privKey, cert, _, err := pkcs12.DecodeChain(pfxData, testPassword)
	if err != nil {
		t.Errorf("Failed to decode P12: %v", err)
	}

	// Verify the private key is valid
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		t.Error("P12 private key is not an RSA key")
	}

	if err := rsaKey.Validate(); err != nil {
		t.Errorf("P12 private key failed validation: %v", err)
	}

	// Verify certificate is present
	if cert == nil {
		t.Error("P12 does not contain a certificate")
	}
}

func TestCreateP12_WithoutPassword(t *testing.T) {
	tempDir := t.TempDir()

	// Write test fixtures to temp files
	keyPath := filepath.Join(tempDir, "test_key.pem")
	certPath := filepath.Join(tempDir, "test_cert.pem")
	p12Path := filepath.Join(tempDir, "test.p12")

	if err := os.WriteFile(keyPath, []byte(testPrivateKeyPEM), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(testCertificatePEM), 0600); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	// Create P12 without password (empty string)
	err := createP12(keyPath, certPath, p12Path, "")
	if err != nil {
		t.Fatalf("Failed to create P12: %v", err)
	}

	// Verify P12 file exists
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Fatal("P12 file was not created")
	}

	// Verify we can read and decode the P12 using native Go (empty password)
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("Failed to read P12 file: %v", err)
	}

	privKey, cert, _, err := pkcs12.DecodeChain(pfxData, "")
	if err != nil {
		t.Errorf("Failed to decode P12: %v", err)
	}

	// Verify the private key is valid
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		t.Error("P12 private key is not an RSA key")
	}

	if err := rsaKey.Validate(); err != nil {
		t.Errorf("P12 private key failed validation: %v", err)
	}

	// Verify certificate is present
	if cert == nil {
		t.Error("P12 does not contain a certificate")
	}
}

func TestCreateCombinedPEM_WithPassword(t *testing.T) {
	tempDir := t.TempDir()

	// First create a P12 bundle
	keyPath := filepath.Join(tempDir, "test_key.pem")
	certPath := filepath.Join(tempDir, "test_cert.pem")
	p12Path := filepath.Join(tempDir, "test.p12")
	pemPath := filepath.Join(tempDir, "combined.pem")

	if err := os.WriteFile(keyPath, []byte(testPrivateKeyPEM), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(testCertificatePEM), 0600); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	// Create P12
	if err := createP12(keyPath, certPath, p12Path, testPassword); err != nil {
		t.Fatalf("Failed to create P12: %v", err)
	}

	// Convert to combined PEM with password
	err := createCombinedPEM(p12Path, pemPath, testPassword)
	if err != nil {
		t.Fatalf("Failed to create combined PEM: %v", err)
	}

	// Verify PEM file exists
	if _, err := os.Stat(pemPath); os.IsNotExist(err) {
		t.Fatal("Combined PEM file was not created")
	}

	// Read and verify it contains both key and certificate
	content, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("Failed to read PEM file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "BEGIN") {
		t.Error("PEM file does not contain valid PEM blocks")
	}

	// Should contain encrypted private key marker
	if !strings.Contains(contentStr, "ENCRYPTED") && !strings.Contains(contentStr, "PRIVATE KEY") {
		t.Error("PEM file should contain private key")
	}

	if !strings.Contains(contentStr, "CERTIFICATE") {
		t.Error("PEM file should contain certificate")
	}
}

func TestCreateCombinedPEM_WithoutPassword(t *testing.T) {
	tempDir := t.TempDir()

	// First create a P12 bundle
	keyPath := filepath.Join(tempDir, "test_key.pem")
	certPath := filepath.Join(tempDir, "test_cert.pem")
	p12Path := filepath.Join(tempDir, "test.p12")
	pemPath := filepath.Join(tempDir, "combined.pem")

	if err := os.WriteFile(keyPath, []byte(testPrivateKeyPEM), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(testCertificatePEM), 0600); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	// Create P12 without password
	if err := createP12(keyPath, certPath, p12Path, ""); err != nil {
		t.Fatalf("Failed to create P12: %v", err)
	}

	// Convert to combined PEM without password
	err := createCombinedPEM(p12Path, pemPath, "")
	if err != nil {
		t.Fatalf("Failed to create combined PEM: %v", err)
	}

	// Verify PEM file exists
	if _, err := os.Stat(pemPath); os.IsNotExist(err) {
		t.Fatal("Combined PEM file was not created")
	}

	// Read and verify it's unencrypted
	content, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("Failed to read PEM file: %v", err)
	}

	contentStr := string(content)

	// Should NOT contain encrypted marker when no password
	if strings.Contains(contentStr, "ENCRYPTED") {
		t.Error("Unencrypted PEM should not contain ENCRYPTED marker")
	}

	// Should contain both private key and certificate
	if !strings.Contains(contentStr, "PRIVATE KEY") {
		t.Error("PEM file should contain private key")
	}

	if !strings.Contains(contentStr, "CERTIFICATE") {
		t.Error("PEM file should contain certificate")
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "Tilde expansion",
			input:    "~/test/path",
			contains: "/test/path",
		},
		{
			name:     "No tilde",
			input:    "/absolute/path",
			contains: "/absolute/path",
		},
		{
			name:     "Relative path",
			input:    "relative/path",
			contains: "relative/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("expandPath(%s) = %s, should contain %s", tt.input, result, tt.contains)
			}
		})
	}
}

func TestArtifactsExist(t *testing.T) {
	tempDir := t.TempDir()

	// Initially no artifacts
	if artifactsExist(tempDir) {
		t.Error("artifactsExist should return false for empty directory")
	}

	// Create one artifact
	artifactPath := filepath.Join(tempDir, "development_private.key")
	if err := os.WriteFile(artifactPath, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	// Now should detect artifacts
	if !artifactsExist(tempDir) {
		t.Error("artifactsExist should return true when artifacts present")
	}

	// Non-existent directory
	if artifactsExist("/nonexistent/directory") {
		t.Error("artifactsExist should return false for non-existent directory")
	}
}
