package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type CertificateRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			CertificateType string `json:"certificateType"`
			CsrContent      string `json:"csrContent"`
		} `json:"attributes"`
	} `json:"data"`
}

type CertificateResponse struct {
	Data struct {
		Attributes struct {
			CertificateContent string `json:"certificateContent"`
		} `json:"attributes"`
	} `json:"data"`
	Errors []struct {
		Status string `json:"status"`
		Code   string `json:"code"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	} `json:"errors"`
}

func uploadCSR(jwtToken, csrContent string) ([]byte, error) {
	apiURL := "https://api.appstoreconnect.apple.com/v1/certificates"

	payload := CertificateRequest{}
	payload.Data.Type = "certificates"
	payload.Data.Attributes.CertificateType = "DEVELOPMENT"
	payload.Data.Attributes.CsrContent = csrContent

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result CertificateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API errors
	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s - %s", result.Errors[0].Code, result.Errors[0].Detail)
	}

	// Extract and decode the certificate content
	certContent := result.Data.Attributes.CertificateContent
	if certContent == "" {
		return nil, fmt.Errorf("no certificate content in response")
	}

	return base64.StdEncoding.DecodeString(certContent)
}
