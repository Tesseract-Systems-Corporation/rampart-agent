// Package platform provides detection of cloud providers and platform metadata.
package platform

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider represents a cloud provider.
type Provider string

const (
	ProviderAWS          Provider = "aws"
	ProviderGCP          Provider = "gcp"
	ProviderAzure        Provider = "azure"
	ProviderOCI          Provider = "oci"
	ProviderDigitalOcean Provider = "digitalocean"
	ProviderVultr        Provider = "vultr"
	ProviderOnPrem       Provider = "on-prem"
)

// DetectProvider attempts to detect the cloud provider by querying metadata endpoints.
// Returns "on-prem" if no cloud provider is detected.
func DetectProvider(ctx context.Context) Provider {
	// Create a client with short timeout for metadata checks
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Check providers in parallel for faster detection
	type result struct {
		provider Provider
		detected bool
	}

	results := make(chan result, 6)

	// AWS (IMDSv2) - requires token first
	go func() {
		results <- result{ProviderAWS, checkAWS(ctx, client)}
	}()

	// GCP
	go func() {
		results <- result{ProviderGCP, checkGCP(ctx, client)}
	}()

	// Azure
	go func() {
		results <- result{ProviderAzure, checkAzure(ctx, client)}
	}()

	// OCI (Oracle Cloud)
	go func() {
		results <- result{ProviderOCI, checkOCI(ctx, client)}
	}()

	// DigitalOcean
	go func() {
		results <- result{ProviderDigitalOcean, checkDigitalOcean(ctx, client)}
	}()

	// Vultr
	go func() {
		results <- result{ProviderVultr, checkVultr(ctx, client)}
	}()

	// Wait for all results
	for i := 0; i < 6; i++ {
		r := <-results
		if r.detected {
			return r.provider
		}
	}

	return ProviderOnPrem
}

// checkAWS detects AWS using IMDSv2 (token-based).
func checkAWS(ctx context.Context, client *http.Client) bool {
	// First, get a token (IMDSv2 requirement)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return false
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return false
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return false
	}

	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return false
	}
	token := string(tokenBytes)

	// Now use the token to query instance identity
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/latest/meta-data/instance-id", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// checkGCP detects Google Cloud Platform.
func checkGCP(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/id", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// checkAzure detects Microsoft Azure.
func checkAzure(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// checkOCI detects Oracle Cloud Infrastructure.
func checkOCI(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer Oracle")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// OCI returns 200 with instance metadata
	return resp.StatusCode == http.StatusOK
}

// checkDigitalOcean detects DigitalOcean droplets.
func checkDigitalOcean(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/metadata/v1/id", nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// DigitalOcean returns numeric droplet ID
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// Verify it looks like a droplet ID (numeric)
	id := strings.TrimSpace(string(body))
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(id) > 0
}

// checkVultr detects Vultr instances.
func checkVultr(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/v1/instance-v2-id", nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Vultr returns a UUID-like instance ID
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return len(strings.TrimSpace(string(body))) > 0
}
