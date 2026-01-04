package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DefaultCloudProviderCheckInterval is the default interval between cloud provider checks.
// Cloud provider doesn't change, so we only re-check periodically to confirm.
const DefaultCloudProviderCheckInterval = 24 * time.Hour

// DefaultIMDSTimeout is the timeout for IMDS requests.
const DefaultIMDSTimeout = 2 * time.Second

// CloudProviderConfig holds configuration for the CloudProvider watcher.
type CloudProviderConfig struct {
	// CheckInterval is how often to re-check the cloud provider.
	// Defaults to DefaultCloudProviderCheckInterval (24h) if zero.
	CheckInterval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// CloudProviderInfo contains detected cloud provider information.
type CloudProviderInfo struct {
	Provider                  string
	Region                    string
	InstanceID                string
	InstanceType              string
	AvailabilityZone          string
	Certifications            []string
	PhysicalSecurityInherited bool
	DataDestructionInherited  bool
	Note                      string
}

// CloudProviderWatcher detects the cloud provider and emits cloud.provider events
// with certification information for SOC 2 CC6.4/CC6.5 inherited controls.
type CloudProviderWatcher struct {
	checkInterval time.Duration
	fortressID    string
	serverID      string
	logger        *slog.Logger

	// cached result to avoid re-detection
	cacheMu    sync.RWMutex
	cachedInfo *CloudProviderInfo

	// httpClient allows injecting a mock for testing
	httpClient *http.Client
}

// NewCloudProviderWatcher creates a new CloudProviderWatcher with the given configuration.
func NewCloudProviderWatcher(cfg CloudProviderConfig) *CloudProviderWatcher {
	interval := cfg.CheckInterval
	if interval == 0 {
		interval = DefaultCloudProviderCheckInterval
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &CloudProviderWatcher{
		checkInterval: interval,
		fortressID:    cfg.FortressID,
		serverID:      cfg.ServerID,
		logger:        logger,
		httpClient: &http.Client{
			Timeout: DefaultIMDSTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: DefaultIMDSTimeout,
				}).DialContext,
			},
		},
	}
}

// Watch starts watching and returns a channel of events.
func (w *CloudProviderWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting cloud provider watcher", "interval", w.checkInterval)

		// Send immediate detection
		w.emitCloudProviderEvent(ctx, out)

		ticker := time.NewTicker(w.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("cloud provider watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.emitCloudProviderEvent(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *CloudProviderWatcher) Name() string {
	return "cloudprovider"
}

// emitCloudProviderEvent detects the cloud provider and emits an event.
func (w *CloudProviderWatcher) emitCloudProviderEvent(ctx context.Context, out chan<- event.Event) {
	info := w.detectCloudProvider(ctx)

	// Cache the result
	w.cacheMu.Lock()
	w.cachedInfo = info
	w.cacheMu.Unlock()

	payload := map[string]any{
		"provider":                    info.Provider,
		"certifications":              info.Certifications,
		"physical_security_inherited": info.PhysicalSecurityInherited,
		"data_destruction_inherited":  info.DataDestructionInherited,
	}

	if info.Region != "" {
		payload["region"] = info.Region
	}
	if info.InstanceID != "" {
		payload["instance_id"] = info.InstanceID
	}
	if info.InstanceType != "" {
		payload["instance_type"] = info.InstanceType
	}
	if info.AvailabilityZone != "" {
		payload["availability_zone"] = info.AvailabilityZone
	}
	if info.Note != "" {
		payload["note"] = info.Note
	}

	e := event.NewEvent(event.CloudProvider, w.fortressID, w.serverID, payload)

	w.logger.Info("detected cloud provider",
		"provider", info.Provider,
		"region", info.Region,
		"instance_id", info.InstanceID,
		"certifications", info.Certifications,
	)

	select {
	case <-ctx.Done():
	case out <- e:
	}
}

// detectCloudProvider attempts to detect the cloud provider using IMDS endpoints.
func (w *CloudProviderWatcher) detectCloudProvider(ctx context.Context) *CloudProviderInfo {
	// Try each provider in order of popularity/likelihood
	// The order matters - AWS and GCP are most common

	// Try AWS first (most common)
	if info := w.detectAWS(ctx); info != nil {
		return info
	}

	// Try GCP
	if info := w.detectGCP(ctx); info != nil {
		return info
	}

	// Try Azure
	if info := w.detectAzure(ctx); info != nil {
		return info
	}

	// Try OCI (Oracle Cloud Infrastructure)
	if info := w.detectOCI(ctx); info != nil {
		return info
	}

	// Try DigitalOcean
	if info := w.detectDigitalOcean(ctx); info != nil {
		return info
	}

	// Try Vultr
	if info := w.detectVultr(ctx); info != nil {
		return info
	}

	// Try Linode
	if info := w.detectLinode(ctx); info != nil {
		return info
	}

	// Try Hetzner (uses DMI, not IMDS)
	if info := w.detectHetzner(); info != nil {
		return info
	}

	// No cloud provider detected - assume bare metal/on-premises
	return &CloudProviderInfo{
		Provider:                  "bare_metal",
		Certifications:            []string{},
		PhysicalSecurityInherited: false,
		DataDestructionInherited:  false,
		Note:                      "Physical security controls must be documented separately",
	}
}

// detectAWS attempts to detect AWS using IMDSv2.
func (w *CloudProviderWatcher) detectAWS(ctx context.Context) *CloudProviderInfo {
	// Get IMDSv2 token first
	tokenReq, err := http.NewRequestWithContext(ctx, "PUT",
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return nil
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := w.httpClient.Do(tokenReq)
	if err != nil {
		return nil
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil
	}

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil
	}
	token := strings.TrimSpace(string(tokenBody))

	// Get instance identity document
	identityReq, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/latest/dynamic/instance-identity/document", nil)
	if err != nil {
		return nil
	}
	identityReq.Header.Set("X-aws-ec2-metadata-token", token)

	identityResp, err := w.httpClient.Do(identityReq)
	if err != nil {
		return nil
	}
	defer identityResp.Body.Close()

	if identityResp.StatusCode != http.StatusOK {
		return nil
	}

	var identity struct {
		Region           string `json:"region"`
		InstanceID       string `json:"instanceId"`
		InstanceType     string `json:"instanceType"`
		AvailabilityZone string `json:"availabilityZone"`
	}

	if err := json.NewDecoder(identityResp.Body).Decode(&identity); err != nil {
		return nil
	}

	// Confirm this is AWS by checking for expected fields
	if identity.InstanceID == "" || !strings.HasPrefix(identity.InstanceID, "i-") {
		return nil
	}

	return &CloudProviderInfo{
		Provider:         "aws",
		Region:           identity.Region,
		InstanceID:       identity.InstanceID,
		InstanceType:     identity.InstanceType,
		AvailabilityZone: identity.AvailabilityZone,
		Certifications: []string{
			"SOC 1",
			"SOC 2",
			"SOC 3",
			"ISO 27001",
			"ISO 27017",
			"ISO 27018",
			"FedRAMP",
			"HIPAA",
			"PCI DSS",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectGCP attempts to detect GCP using its metadata server.
func (w *CloudProviderWatcher) detectGCP(ctx context.Context) *CloudProviderInfo {
	// GCP uses metadata.google.internal or 169.254.169.254 with Metadata-Flavor header
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true", nil)
	if err != nil {
		// Try by IP as fallback
		req, err = http.NewRequestWithContext(ctx, "GET",
			"http://169.254.169.254/computeMetadata/v1/instance/?recursive=true", nil)
		if err != nil {
			return nil
		}
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Check the response header to confirm GCP
	if resp.Header.Get("Metadata-Flavor") != "Google" {
		return nil
	}

	var metadata struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		MachineType  string `json:"machineType"`
		Zone         string `json:"zone"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil
	}

	// Extract region and zone from the zone path (e.g., projects/123/zones/us-central1-a)
	zone := ""
	region := ""
	if metadata.Zone != "" {
		parts := strings.Split(metadata.Zone, "/")
		if len(parts) > 0 {
			zone = parts[len(parts)-1]
			// Extract region from zone (us-central1-a -> us-central1)
			if idx := strings.LastIndex(zone, "-"); idx > 0 {
				region = zone[:idx]
			}
		}
	}

	// Extract instance type from machineType path
	instanceType := ""
	if metadata.MachineType != "" {
		parts := strings.Split(metadata.MachineType, "/")
		if len(parts) > 0 {
			instanceType = parts[len(parts)-1]
		}
	}

	return &CloudProviderInfo{
		Provider:         "gcp",
		Region:           region,
		InstanceID:       fmt.Sprintf("%d", metadata.ID),
		InstanceType:     instanceType,
		AvailabilityZone: zone,
		Certifications: []string{
			"SOC 1",
			"SOC 2",
			"SOC 3",
			"ISO 27001",
			"ISO 27017",
			"ISO 27018",
			"FedRAMP",
			"HIPAA",
			"PCI DSS",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectAzure attempts to detect Azure using its IMDS.
func (w *CloudProviderWatcher) detectAzure(ctx context.Context) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Metadata", "true")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var metadata struct {
		Compute struct {
			Location      string `json:"location"`
			Name          string `json:"name"`
			VMID          string `json:"vmId"`
			VMSize        string `json:"vmSize"`
			Zone          string `json:"zone"`
			ResourceGroup string `json:"resourceGroupName"`
		} `json:"compute"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil
	}

	// Confirm this is Azure by checking for expected fields
	if metadata.Compute.VMID == "" {
		return nil
	}

	return &CloudProviderInfo{
		Provider:         "azure",
		Region:           metadata.Compute.Location,
		InstanceID:       metadata.Compute.VMID,
		InstanceType:     metadata.Compute.VMSize,
		AvailabilityZone: metadata.Compute.Zone,
		Certifications: []string{
			"SOC 1",
			"SOC 2",
			"SOC 3",
			"ISO 27001",
			"ISO 27017",
			"ISO 27018",
			"FedRAMP",
			"HIPAA",
			"PCI DSS",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectOCI attempts to detect Oracle Cloud Infrastructure using its IMDS.
func (w *CloudProviderWatcher) detectOCI(ctx context.Context) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer Oracle")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var metadata struct {
		ID                 string `json:"id"`
		DisplayName        string `json:"displayName"`
		Region             string `json:"region"`
		AvailabilityDomain string `json:"availabilityDomain"`
		Shape              string `json:"shape"`
		CompartmentID      string `json:"compartmentId"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil
	}

	// Confirm this is OCI by checking for expected fields
	if metadata.ID == "" || metadata.CompartmentID == "" {
		return nil
	}

	return &CloudProviderInfo{
		Provider:         "oci",
		Region:           metadata.Region,
		InstanceID:       metadata.ID,
		InstanceType:     metadata.Shape,
		AvailabilityZone: metadata.AvailabilityDomain,
		Certifications: []string{
			"SOC 1",
			"SOC 2",
			"ISO 27001",
			"ISO 27017",
			"ISO 27018",
			"FedRAMP",
			"HIPAA",
			"PCI DSS",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectDigitalOcean attempts to detect DigitalOcean using its metadata service.
func (w *CloudProviderWatcher) detectDigitalOcean(ctx context.Context) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/metadata/v1.json", nil)
	if err != nil {
		return nil
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var metadata struct {
		DropletID   int    `json:"droplet_id"`
		Hostname    string `json:"hostname"`
		Region      string `json:"region"`
		VendorData  string `json:"vendor_data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil
	}

	// Confirm this is DigitalOcean by checking for droplet_id
	if metadata.DropletID == 0 {
		return nil
	}

	return &CloudProviderInfo{
		Provider:         "digitalocean",
		Region:           metadata.Region,
		InstanceID:       fmt.Sprintf("%d", metadata.DropletID),
		Certifications: []string{
			"SOC 2",
			"SOC 3",
			"ISO 27001",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectVultr attempts to detect Vultr using its metadata service.
func (w *CloudProviderWatcher) detectVultr(ctx context.Context) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/v1.json", nil)
	if err != nil {
		return nil
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var metadata struct {
		InstanceV2ID string `json:"instanceid"` // Vultr uses instanceid
		Region       string `json:"region"`
		Hostname     string `json:"hostname"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil
	}

	// Vultr metadata should have an instanceid
	if metadata.InstanceV2ID == "" {
		return nil
	}

	return &CloudProviderInfo{
		Provider:         "vultr",
		Region:           metadata.Region,
		InstanceID:       metadata.InstanceV2ID,
		Certifications: []string{
			"SOC 2",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectLinode attempts to detect Linode using its metadata service.
func (w *CloudProviderWatcher) detectLinode(ctx context.Context) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/v1/instance", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Metadata-Token", "required") // Linode requires this header

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var metadata struct {
		ID     int    `json:"id"`
		Label  string `json:"label"`
		Region string `json:"region"`
		Type   string `json:"type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil
	}

	// Confirm this is Linode by checking for ID
	if metadata.ID == 0 {
		return nil
	}

	return &CloudProviderInfo{
		Provider:         "linode",
		Region:           metadata.Region,
		InstanceID:       fmt.Sprintf("%d", metadata.ID),
		InstanceType:     metadata.Type,
		Certifications: []string{
			"SOC 2",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// detectHetzner attempts to detect Hetzner using DMI information.
// Hetzner Cloud doesn't have an IMDS endpoint, so we check system files.
func (w *CloudProviderWatcher) detectHetzner() *CloudProviderInfo {
	// Check board vendor in DMI
	vendorPath := "/sys/class/dmi/id/board_vendor"
	vendorBytes, err := os.ReadFile(vendorPath)
	if err != nil {
		return nil
	}

	vendor := strings.TrimSpace(string(vendorBytes))
	if !strings.Contains(strings.ToLower(vendor), "hetzner") {
		return nil
	}

	// Also check product name for more info
	productPath := "/sys/class/dmi/id/product_name"
	productBytes, _ := os.ReadFile(productPath)
	productName := strings.TrimSpace(string(productBytes))

	// Try to get chassis serial as instance ID
	serialPath := "/sys/class/dmi/id/chassis_serial"
	serialBytes, _ := os.ReadFile(serialPath)
	serial := strings.TrimSpace(string(serialBytes))

	return &CloudProviderInfo{
		Provider:     "hetzner",
		InstanceID:   serial,
		InstanceType: productName,
		Certifications: []string{
			"ISO 27001",
		},
		PhysicalSecurityInherited: true,
		DataDestructionInherited:  true,
	}
}

// GetCachedInfo returns the cached cloud provider information.
// This can be used by other watchers to determine the cloud environment.
func (w *CloudProviderWatcher) GetCachedInfo() *CloudProviderInfo {
	w.cacheMu.RLock()
	defer w.cacheMu.RUnlock()
	return w.cachedInfo
}
