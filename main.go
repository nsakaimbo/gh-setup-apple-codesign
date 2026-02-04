package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// Output filenames
const (
	privateKeyFilename = "development_private.key"
	p12BundleFilename  = "development_bundle.p12"
	pemBundleFilename  = "development_bundle.pem"
	tempCertFilename   = ".temp_cert.pem"
)

// Command-line flags
var (
	stubMode  bool
	outputDir string
	forceMode bool
)

func main() {
	parseFlags()

	if stubMode {
		logWarning("STUB MODE ENABLED - No real API calls will be made")
	}

	config := loadConfiguration()
	validateAndConfirm(config)
	runCertificateGeneration(config)
}

// parseFlags sets up and parses command-line flags
func parseFlags() {
	programName := filepath.Base(os.Args[0])
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sApple Development Certificate Generator%s\n\n", colorCyan, colorReset)
		fmt.Fprintf(os.Stderr, "Generates an Apple Development signing certificate by creating a CSR,\n")
		fmt.Fprintf(os.Stderr, "submitting it to App Store Connect API, and bundling the result.\n\n")
		fmt.Fprintf(os.Stderr, "%sUsage:%s\n", colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  %s [flags]\n\n", programName)
		fmt.Fprintf(os.Stderr, "%sFlags:%s\n", colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  --output <dir>   Output directory for artifacts (default: signing_artifacts)\n")
		fmt.Fprintf(os.Stderr, "  --force          Overwrite existing artifacts without prompting\n")
		fmt.Fprintf(os.Stderr, "  --stub           Enable stub mode for testing (bypasses real API calls)\n")
		fmt.Fprintf(os.Stderr, "  --help           Show this help message\n\n")
		fmt.Fprintf(os.Stderr, "%sEnvironment Variables:%s\n", colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  APPLE_API_KEY_ID          Your Apple API Key ID\n")
		fmt.Fprintf(os.Stderr, "  APPLE_API_KEY_ISSUER_ID   Your Apple API Issuer ID\n")
		fmt.Fprintf(os.Stderr, "  APPLE_API_PRIVATE_KEY     Private key content (PEM format)\n")
		fmt.Fprintf(os.Stderr, "  APPLE_API_PRIVATE_KEY_PATH  Path to .p8 private key file\n")
		fmt.Fprintf(os.Stderr, "  CERT_COMMON_NAME          Certificate Common Name (CN)\n")
		fmt.Fprintf(os.Stderr, "  CERT_ORGANIZATION         Certificate Organization (O)\n")
		fmt.Fprintf(os.Stderr, "  CERT_COUNTRY              Certificate Country Code (C)\n")
		fmt.Fprintf(os.Stderr, "  CERTIFICATE_PASSWORD      Optional password to protect P12 and PEM bundles\n\n")
		fmt.Fprintf(os.Stderr, "%sExamples:%s\n", colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  # Interactive mode (prompts for missing values)\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", programName)
		fmt.Fprintf(os.Stderr, "  # With environment variables\n")
		fmt.Fprintf(os.Stderr, "  export APPLE_API_KEY_ID=XXXXXXXXXX\n")
		fmt.Fprintf(os.Stderr, "  export APPLE_API_KEY_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n")
		fmt.Fprintf(os.Stderr, "  export APPLE_API_PRIVATE_KEY_PATH=~/keys/AuthKey.p8\n")
		fmt.Fprintf(os.Stderr, "  %s --output ./my-certs\n\n", programName)
		fmt.Fprintf(os.Stderr, "  # Test mode (no API calls)\n")
		fmt.Fprintf(os.Stderr, "  %s --stub\n", programName)
	}

	flag.BoolVar(&stubMode, "stub", false, "Enable stub mode for testing (bypasses real API calls)")
	flag.StringVar(&outputDir, "output", "signing_artifacts", "Output directory for artifacts")
	flag.BoolVar(&forceMode, "force", false, "Overwrite existing artifacts without prompting")
	flag.Parse()
}

// config holds all configuration values needed for certificate generation
type config struct {
	keyID            string
	issuerID         string
	privateKeyStr    string
	certCommonName   string
	certOrganization string
	certCountry      string
	certPassword     string
}

// loadConfiguration loads configuration from environment variables and prompts for missing values
func loadConfiguration() *config {
	reader := bufio.NewReader(os.Stdin)
	cfg := &config{}

	// API credentials
	cfg.keyID = os.Getenv("APPLE_API_KEY_ID")
	if cfg.keyID == "" {
		cfg.keyID = promptForInput(reader, "APPLE_API_KEY_ID", "Enter your Apple API Key ID")
	}

	cfg.issuerID = os.Getenv("APPLE_API_KEY_ISSUER_ID")
	if cfg.issuerID == "" {
		cfg.issuerID = promptForInput(reader, "APPLE_API_KEY_ISSUER_ID", "Enter your Apple API Issuer ID")
	}

	cfg.privateKeyStr = os.Getenv("APPLE_API_PRIVATE_KEY")
	if cfg.privateKeyStr == "" {
		privateKeyPath := os.Getenv("APPLE_API_PRIVATE_KEY_PATH")
		if privateKeyPath == "" {
			privateKeyPath = promptForInput(reader, "APPLE_API_PRIVATE_KEY_PATH", "Enter the path to your Apple API Private Key file (.p8)")
		}

		if stubMode {
			cfg.privateKeyStr = "-----BEGIN PRIVATE KEY-----\nSTUB_KEY_FOR_TESTING\n-----END PRIVATE KEY-----"
		} else {
			privateKeyPath = expandPath(privateKeyPath)

			if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
				logError("Private key file not found: %s", privateKeyPath)
				os.Exit(1)
			}

			privateKeyBytes, err := os.ReadFile(privateKeyPath)
			if err != nil {
				logError("Failed to read private key file: %s", err)
				os.Exit(1)
			}
			cfg.privateKeyStr = string(privateKeyBytes)

			if !strings.Contains(cfg.privateKeyStr, "-----BEGIN PRIVATE KEY-----") {
				logError("Invalid private key file: expected PEM format with '-----BEGIN PRIVATE KEY-----'")
				os.Exit(1)
			}
		}
	}

	// Certificate subject fields
	fmt.Printf("\n%sCertificate Subject Information:%s\n", colorCyan, colorReset)

	cfg.certCommonName = os.Getenv("CERT_COMMON_NAME")
	if cfg.certCommonName == "" {
		cfg.certCommonName = promptForInput(reader, "CERT_COMMON_NAME", "Enter the Common Name (CN) for the certificate (e.g., \"Apple Development: <Team/Individual Name/Identifier>\")")
	}

	cfg.certOrganization = os.Getenv("CERT_ORGANIZATION")
	if cfg.certOrganization == "" {
		cfg.certOrganization = promptForInput(reader, "CERT_ORGANIZATION", "Enter the Organization (O) for the certificate (e.g., \"Acme Inc\" or \"Your Company Name\")")
	}

	cfg.certCountry = os.Getenv("CERT_COUNTRY")
	if cfg.certCountry == "" {
		cfg.certCountry = promptForInput(reader, "CERT_COUNTRY", "Enter the Country Code (C) for the certificate (e.g., US, UK, CA)")
	}

	// Certificate password
	cfg.certPassword = os.Getenv("CERTIFICATE_PASSWORD")
	if cfg.certPassword == "" {
		fmt.Printf("\n%sSet a password to protect the certificate bundles (or press Enter to skip):%s ", colorYellow, colorReset)
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logError("Failed to read password: %s", err)
			os.Exit(1)
		}
		fmt.Println()
		cfg.certPassword = string(passwordBytes)
		fmt.Println()
	}

	return cfg
}

// validateAndConfirm shows configuration summary and prompts for confirmation
func validateAndConfirm(cfg *config) {
	reader := bufio.NewReader(os.Stdin)

	// Show configuration summary
	fmt.Printf("\n%s── Configuration Summary ──%s\n", colorCyan, colorReset)
	fmt.Printf("  API Key ID:     %s\n", cfg.keyID)
	fmt.Printf("  Issuer ID:      %s\n", cfg.issuerID)
	fmt.Printf("  Common Name:    %s\n", cfg.certCommonName)
	fmt.Printf("  Organization:   %s\n", cfg.certOrganization)
	fmt.Printf("  Country:        %s\n", cfg.certCountry)
	fmt.Printf("  Output Dir:     %s\n", outputDir)
	if cfg.certPassword != "" {
		fmt.Printf("  Password:       %s[SET]%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("  Password:       %s[NONE - artifacts will be unencrypted]%s\n", colorYellow, colorReset)
	}
	if stubMode {
		fmt.Printf("  Mode:           %sSTUB (no real API calls)%s\n", colorYellow, colorReset)
	} else {
		fmt.Printf("  Mode:           Production\n")
	}
	fmt.Printf("%s───────────────────────────%s\n\n", colorCyan, colorReset)

	fmt.Printf("Proceed with certificate generation? [Y/n]: ")
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	if response == "n" || response == "no" {
		fmt.Println("Aborted.")
		os.Exit(0)
	}

	// Check for existing artifacts
	if !forceMode && artifactsExist(outputDir) {
		fmt.Println()
		logWarning("Output directory '%s' already contains artifacts.", outputDir)
		fmt.Printf("Overwrite existing files? (Y to overwrite, n to abort) [Y/n]: ")
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "n" || response == "no" {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}
	fmt.Println()
}

// runCertificateGeneration executes the full certificate generation workflow
func runCertificateGeneration(cfg *config) {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logError("Failed to create artifacts directory: %s", err)
		os.Exit(1)
	}

	// 1. Generate RSA private key
	logStep("Step 1: Generating RSA private key...")
	privKey, err := generateRSAKey(2048)
	if err != nil {
		logError("Failed to generate private key: %s", err)
		os.Exit(1)
	}

	// 2. Create CSR
	logStep("Step 2: Creating Certificate Signing Request (CSR)...")
	csrBytes, err := createCSR(privKey, cfg.certCommonName, cfg.certOrganization, cfg.certCountry)
	if err != nil {
		logError("Failed to create CSR: %s", err)
		os.Exit(1)
	}

	// 3. Save private key
	devPrivateKeyPath := filepath.Join(outputDir, privateKeyFilename)

	if cfg.certPassword != "" {
		err = saveEncryptedPrivateKey(privKey, devPrivateKeyPath, cfg.certPassword)
		if err != nil {
			logError("Failed to save encrypted private key: %s", err)
			os.Exit(1)
		}
		logInfo("Saved encrypted private key to %s", devPrivateKeyPath)
	} else {
		keyOut, err := os.Create(devPrivateKeyPath)
		if err != nil {
			logError("Failed to create private key file: %s", err)
			os.Exit(1)
		}
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
		keyOut.Close()
		logInfo("Saved private key to %s", devPrivateKeyPath)
	}

	// 4. Encode CSR to PEM format
	var csrPEM bytes.Buffer
	pem.Encode(&csrPEM, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	csrContent := csrPEM.String()

	// 5. Generate JWT
	logStep("Step 3: Generating JWT for Apple API authentication...")
	var jwtToken string
	if stubMode {
		jwtToken = "stub-jwt-token-for-testing"
		logInfo("[STUB] Using fake JWT token")
	} else {
		jwtToken, err = generateJWT(cfg.keyID, cfg.issuerID, cfg.privateKeyStr)
		if err != nil {
			logError("Failed to generate JWT: %s", err)
			os.Exit(1)
		}
	}

	// 6. Upload CSR and get certificate
	logStep("Step 4: Uploading CSR to Apple App Store Connect API...")
	var certBytes []byte
	if stubMode {
		certBytes, err = generateStubCertificate(privKey, cfg.certCommonName, cfg.certOrganization, cfg.certCountry)
		if err != nil {
			logError("Failed to generate stub certificate: %s", err)
			os.Exit(1)
		}
		logInfo("[STUB] Using self-signed test certificate")
	} else {
		certBytes, err = uploadCSR(jwtToken, csrContent)
		if err != nil {
			logError("Failed to upload CSR and retrieve certificate: %s", err)
			os.Exit(1)
		}
	}

	// 7. Convert certificate to PEM
	logStep("Step 5: Processing certificate...")
	pemPath := filepath.Join(outputDir, tempCertFilename)
	err = convertCertToPEM(certBytes, pemPath)
	if err != nil {
		logError("Failed to convert certificate to PEM: %s", err)
		os.Exit(1)
	}

	// 8. Create P12 bundle
	logStep("Step 6: Creating PKCS12 bundle...")
	p12Path := filepath.Join(outputDir, p12BundleFilename)

	err = createP12(devPrivateKeyPath, pemPath, p12Path, cfg.certPassword)
	if err != nil {
		logError("Failed to create P12 file: %s", err)
		os.Exit(1)
	}
	logInfo("Saved P12 bundle to %s", p12Path)

	// 9. Convert P12 to combined PEM
	logStep("Step 7: Creating combined PEM bundle...")
	combinedPemPath := filepath.Join(outputDir, pemBundleFilename)
	err = createCombinedPEM(p12Path, combinedPemPath, cfg.certPassword)
	if err != nil {
		logError("Failed to create combined PEM file: %s", err)
		os.Exit(1)
	}
	logInfo("Saved combined PEM to %s", combinedPemPath)

	// Clean up temp file
	os.Remove(pemPath)

	// Success message
	fmt.Printf("\n%s✅ Success! Apple Development Certificate generated.%s\n", colorGreen, colorReset)
	fmt.Printf("   Artifacts directory: %s/\n", outputDir)
	fmt.Printf("   - Private Key: %s\n", privateKeyFilename)
	fmt.Printf("   - PKCS12 Bundle: %s\n", p12BundleFilename)
	fmt.Printf("   - PEM Bundle: %s\n", pemBundleFilename)
	if stubMode {
		fmt.Printf("\n%s⚠️  Note: This was generated in STUB MODE with a self-signed certificate.%s\n", colorYellow, colorReset)
		fmt.Printf("   For real certificates, run without the --stub flag.\n")
	}
}
