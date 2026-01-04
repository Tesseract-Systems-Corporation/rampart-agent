package watcher

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DefaultEncryptionInterval is the default interval between encryption snapshots.
const DefaultEncryptionInterval = 6 * time.Hour

// DefaultExpiryWarningDays is the default number of days before certificate expiry to warn.
const DefaultExpiryWarningDays = 30

// DefaultTLSProbeTimeout is the timeout for TLS probe connections.
const DefaultTLSProbeTimeout = 5 * time.Second

// DefaultCertPaths are the default paths to scan for certificates.
var DefaultCertPaths = []string{"/etc/ssl/certs", "/etc/pki"}

// TLSConfigPaths are common locations for TLS configurations.
var TLSConfigPaths = []string{"/etc/nginx", "/etc/apache2", "/etc/haproxy", "/etc/traefik", "/etc/caddy"}

// CommonTLSPorts are ports commonly used for TLS.
var CommonTLSPorts = []int{443, 8443, 8080, 3000, 5000, 9443}

// EncryptionConfig holds configuration for the Encryption watcher.
type EncryptionConfig struct {
	// SnapshotInterval is how often to check encryption state.
	// Defaults to DefaultEncryptionInterval (6 hours) if zero.
	SnapshotInterval time.Duration

	// CertPaths are paths to scan for certificates.
	// Defaults to DefaultCertPaths if empty.
	CertPaths []string

	// ExpiryWarningDays is the number of days before certificate expiry to warn.
	// Defaults to DefaultExpiryWarningDays (30) if zero.
	ExpiryWarningDays int

	// TLSProbeTimeout is the timeout for TLS probe connections.
	// Defaults to DefaultTLSProbeTimeout (5 seconds) if zero.
	TLSProbeTimeout time.Duration

	// AdditionalProbePorts are extra ports to probe for TLS beyond detected doors.
	AdditionalProbePorts []int

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// EncryptionWatcher monitors disk encryption, TLS certificates, and TLS endpoint configuration.
type EncryptionWatcher struct {
	snapshotInterval     time.Duration
	certPaths            []string
	expiryWarningDays    int
	tlsProbeTimeout      time.Duration
	additionalProbePorts []int
	fortressID           string
	serverID             string
	logger               *slog.Logger

	// doorsMu protects knownDoors
	doorsMu    sync.RWMutex
	knownDoors map[int]bool // ports we've seen as doors
}

// NewEncryptionWatcher creates a new EncryptionWatcher with the given configuration.
func NewEncryptionWatcher(cfg EncryptionConfig) *EncryptionWatcher {
	interval := cfg.SnapshotInterval
	if interval == 0 {
		interval = DefaultEncryptionInterval
	}

	certPaths := cfg.CertPaths
	if len(certPaths) == 0 {
		certPaths = DefaultCertPaths
	}

	expiryDays := cfg.ExpiryWarningDays
	if expiryDays == 0 {
		expiryDays = DefaultExpiryWarningDays
	}

	probeTimeout := cfg.TLSProbeTimeout
	if probeTimeout == 0 {
		probeTimeout = DefaultTLSProbeTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &EncryptionWatcher{
		snapshotInterval:     interval,
		certPaths:            certPaths,
		expiryWarningDays:    expiryDays,
		tlsProbeTimeout:      probeTimeout,
		additionalProbePorts: cfg.AdditionalProbePorts,
		fortressID:           cfg.FortressID,
		serverID:             cfg.ServerID,
		logger:               logger,
		knownDoors:           make(map[int]bool),
	}
}

// RegisterDoor registers a port as a known door for TLS probing.
// This is called by the network watcher when doors are detected.
func (w *EncryptionWatcher) RegisterDoor(port int) {
	w.doorsMu.Lock()
	defer w.doorsMu.Unlock()
	w.knownDoors[port] = true
}

// UnregisterDoor removes a port from known doors.
func (w *EncryptionWatcher) UnregisterDoor(port int) {
	w.doorsMu.Lock()
	defer w.doorsMu.Unlock()
	delete(w.knownDoors, port)
}

// Watch starts watching encryption state and returns a channel of events.
func (w *EncryptionWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting encryption watcher",
			"interval", w.snapshotInterval,
			"cert_paths", w.certPaths,
			"expiry_warning_days", w.expiryWarningDays,
		)

		// Send immediate snapshot
		w.emitSnapshot(ctx, out)

		ticker := time.NewTicker(w.snapshotInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("encryption watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.emitSnapshot(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *EncryptionWatcher) Name() string {
	return "encryption"
}

// emitSnapshot collects encryption state and emits events.
func (w *EncryptionWatcher) emitSnapshot(ctx context.Context, out chan<- event.Event) {
	// Collect disk encryption status
	diskEncryption := w.collectDiskEncryption()

	// Collect TLS endpoints via live probing (PRIMARY)
	tlsEndpoints := w.probeTLSEndpoints(ctx)

	// Collect certificate expiry from config parsing (SUPPLEMENTAL)
	configCerts := w.collectConfigCertificates()

	// Collect certificate expiry from file scanning (BACKUP)
	fileCerts := w.collectCertificateExpiry()

	// Merge certificates, preferring live probe data
	allCerts := w.mergeCertificates(tlsEndpoints, configCerts, fileCerts)

	// Emit snapshot event
	payload := map[string]any{
		"disk_encryption": diskEncryptionToPayload(diskEncryption),
		"tls_endpoints":   tlsEndpointsToPayload(tlsEndpoints),
		"certificates":    certsToPayload(allCerts),
	}

	e := event.NewEvent(event.EncryptionStateSnapshot, w.fortressID, w.serverID, payload)
	select {
	case <-ctx.Done():
		return
	case out <- e:
	}

	// Emit warning events for expiring certificates
	now := time.Now()
	warningThreshold := now.AddDate(0, 0, w.expiryWarningDays)

	for _, cert := range allCerts {
		if cert.NotAfter.Before(warningThreshold) {
			w.logger.Warn("certificate expiring soon",
				"subject", cert.Subject,
				"issuer", cert.Issuer,
				"expires_at", cert.NotAfter,
				"days_until_expiry", cert.DaysUntilExpiry,
				"source", cert.Source,
			)

			certPayload := map[string]any{
				"subject":           cert.Subject,
				"issuer":            cert.Issuer,
				"sans":              cert.SANs,
				"expires_at":        cert.NotAfter.Format(time.RFC3339),
				"days_until_expiry": cert.DaysUntilExpiry,
				"source":            cert.Source,
				"endpoint":          cert.Endpoint,
			}

			certEvent := event.NewEvent(event.CertificateExpiring, w.fortressID, w.serverID, certPayload)
			select {
			case <-ctx.Done():
				return
			case out <- certEvent:
			}
		}
	}
}

// TLSEndpoint represents the result of probing a TLS endpoint.
type TLSEndpoint struct {
	Address         string
	Port            int
	TLSVersion      string
	CipherSuite     string
	Certificate     *CertificateInfo
	ProbeSuccessful bool
	ProbeError      string
	ConfigSource    string // traefik, nginx, caddy, etc.
	ConfigPath      string
}

// CertificateInfo represents parsed certificate information.
type CertificateInfo struct {
	Subject         string
	Issuer          string
	SANs            []string
	NotBefore       time.Time
	NotAfter        time.Time
	DaysUntilExpiry int
	IsExpired       bool
	SerialNumber    string
	Source          string // "live_probe", "config", "file"
	Endpoint        string // e.g., "localhost:443"
	FilePath        string // for file-based certs
}

// probeTLSEndpoints probes all known TLS endpoints.
func (w *EncryptionWatcher) probeTLSEndpoints(ctx context.Context) []TLSEndpoint {
	endpoints := make([]TLSEndpoint, 0)

	// Collect ports to probe
	portsToProbe := make(map[int]bool)

	// Add common TLS ports
	for _, port := range CommonTLSPorts {
		portsToProbe[port] = true
	}

	// Add configured additional ports
	for _, port := range w.additionalProbePorts {
		portsToProbe[port] = true
	}

	// Add known doors from network watcher
	w.doorsMu.RLock()
	for port := range w.knownDoors {
		portsToProbe[port] = true
	}
	w.doorsMu.RUnlock()

	// Probe each port
	var wg sync.WaitGroup
	var mu sync.Mutex

	for port := range portsToProbe {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			endpoint := w.probeTLSPort(ctx, p)
			if endpoint != nil {
				mu.Lock()
				endpoints = append(endpoints, *endpoint)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return endpoints
}

// probeTLSPort probes a single port for TLS.
func (w *EncryptionWatcher) probeTLSPort(ctx context.Context, port int) *TLSEndpoint {
	address := fmt.Sprintf("localhost:%d", port)

	endpoint := &TLSEndpoint{
		Address: address,
		Port:    port,
	}

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: w.tlsProbeTimeout,
	}

	// Try TLS connection
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true, // We're probing, not validating trust
	})
	if err != nil {
		// Check if it's just not listening vs TLS error
		if isConnectionRefused(err) {
			return nil // Port not listening, don't report
		}
		endpoint.ProbeSuccessful = false
		endpoint.ProbeError = err.Error()
		return endpoint
	}
	defer conn.Close()

	endpoint.ProbeSuccessful = true
	state := conn.ConnectionState()

	// Extract TLS version
	endpoint.TLSVersion = tlsVersionString(state.Version)

	// Extract cipher suite
	endpoint.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Extract certificate info
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		now := time.Now()
		daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)

		endpoint.Certificate = &CertificateInfo{
			Subject:         cert.Subject.CommonName,
			Issuer:          cert.Issuer.CommonName,
			SANs:            cert.DNSNames,
			NotBefore:       cert.NotBefore,
			NotAfter:        cert.NotAfter,
			DaysUntilExpiry: daysUntil,
			IsExpired:       now.After(cert.NotAfter),
			SerialNumber:    cert.SerialNumber.String(),
			Source:          "live_probe",
			Endpoint:        address,
		}

		w.logger.Debug("probed TLS endpoint",
			"address", address,
			"tls_version", endpoint.TLSVersion,
			"cipher", endpoint.CipherSuite,
			"subject", cert.Subject.CommonName,
			"issuer", cert.Issuer.CommonName,
			"expires", cert.NotAfter,
		)
	}

	return endpoint
}

// collectConfigCertificates collects certificates from service configurations.
func (w *EncryptionWatcher) collectConfigCertificates() []CertificateInfo {
	certs := make([]CertificateInfo, 0)

	// Parse Traefik acme.json
	traefikCerts := w.parseTraefikAcmeJSON()
	certs = append(certs, traefikCerts...)

	// Parse Caddy config
	caddyCerts := w.parseCaddyConfig()
	certs = append(certs, caddyCerts...)

	return certs
}

// TraefikAcmeData represents the structure of Traefik's acme.json
type TraefikAcmeData struct {
	Account      interface{} `json:"Account"`
	Certificates []struct {
		Domain      TraefikDomain `json:"domain"`
		Certificate string        `json:"certificate"`
		Key         string        `json:"key"`
	} `json:"Certificates"`
}

type TraefikDomain struct {
	Main string   `json:"main"`
	SANs []string `json:"sans"`
}

// parseTraefikAcmeJSON parses Traefik's acme.json for Let's Encrypt certificates.
func (w *EncryptionWatcher) parseTraefikAcmeJSON() []CertificateInfo {
	certs := make([]CertificateInfo, 0)

	// Common locations for acme.json
	acmePaths := []string{
		"/etc/traefik/acme.json",
		"/data/acme.json",                      // Coolify default
		"/letsencrypt/acme.json",               // Common Docker mount
		"/var/lib/traefik/acme.json",           // Some distributions
		"/opt/coolify/proxy/acme.json",         // Coolify specific
		"/data/coolify/proxy/acme.json",        // Another Coolify location
	}

	// Also check Docker volumes if we can
	dockerAcmePaths := w.findTraefikAcmeInDocker()
	acmePaths = append(acmePaths, dockerAcmePaths...)

	for _, path := range acmePaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// acme.json can have different structures depending on Traefik version
		// Try the new format first (with resolver names as keys)
		var acmeV2 map[string]TraefikAcmeData
		if err := json.Unmarshal(data, &acmeV2); err == nil {
			for resolverName, resolver := range acmeV2 {
				for _, c := range resolver.Certificates {
					cert := w.parseTraefikCert(c.Certificate, c.Domain, path, resolverName)
					if cert != nil {
						certs = append(certs, *cert)
					}
				}
			}
			w.logger.Debug("parsed Traefik acme.json (v2 format)", "path", path, "certs", len(certs))
			continue
		}

		// Try old format (direct array)
		var acmeV1 TraefikAcmeData
		if err := json.Unmarshal(data, &acmeV1); err == nil {
			for _, c := range acmeV1.Certificates {
				cert := w.parseTraefikCert(c.Certificate, c.Domain, path, "default")
				if cert != nil {
					certs = append(certs, *cert)
				}
			}
			w.logger.Debug("parsed Traefik acme.json (v1 format)", "path", path, "certs", len(certs))
		}
	}

	return certs
}

// parseTraefikCert parses a base64-encoded certificate from Traefik.
func (w *EncryptionWatcher) parseTraefikCert(certB64 string, domain TraefikDomain, path, resolver string) *CertificateInfo {
	// Traefik stores certs as base64-encoded PEM
	certPEM, err := decodeBase64(certB64)
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	now := time.Now()
	daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)

	sans := domain.SANs
	if sans == nil {
		sans = cert.DNSNames
	}

	return &CertificateInfo{
		Subject:         domain.Main,
		Issuer:          cert.Issuer.CommonName,
		SANs:            sans,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DaysUntilExpiry: daysUntil,
		IsExpired:       now.After(cert.NotAfter),
		SerialNumber:    cert.SerialNumber.String(),
		Source:          "traefik:" + resolver,
		FilePath:        path,
	}
}

// findTraefikAcmeInDocker finds acme.json paths in Docker volumes.
func (w *EncryptionWatcher) findTraefikAcmeInDocker() []string {
	paths := make([]string, 0)

	// Try to find Traefik container and its volumes
	output, err := exec.Command("docker", "inspect",
		"--format", "{{range .Mounts}}{{.Source}}:{{.Destination}}\n{{end}}",
		"traefik").Output()
	if err != nil {
		// Also try with coolify-proxy name
		output, err = exec.Command("docker", "inspect",
			"--format", "{{range .Mounts}}{{.Source}}:{{.Destination}}\n{{end}}",
			"coolify-proxy").Output()
		if err != nil {
			return paths
		}
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hostPath := parts[0]
		containerPath := parts[1]

		// Check if this mount might contain acme.json
		if strings.Contains(containerPath, "letsencrypt") ||
			strings.Contains(containerPath, "acme") ||
			strings.Contains(containerPath, "traefik") {
			acmePath := filepath.Join(hostPath, "acme.json")
			if _, err := os.Stat(acmePath); err == nil {
				paths = append(paths, acmePath)
			}
		}
	}

	return paths
}

// parseCaddyConfig parses Caddy configuration for certificates.
func (w *EncryptionWatcher) parseCaddyConfig() []CertificateInfo {
	certs := make([]CertificateInfo, 0)

	// Caddy stores certificates in its data directory
	caddyDataPaths := []string{
		"/var/lib/caddy/.local/share/caddy/certificates",
		"/data/caddy/certificates",
		"/root/.local/share/caddy/certificates",
		"/home/caddy/.local/share/caddy/certificates",
		"/config/caddy/certificates", // Docker
	}

	for _, basePath := range caddyDataPaths {
		if _, err := os.Stat(basePath); err != nil {
			continue
		}

		// Walk the certificates directory
		err := filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			// Look for .crt files
			if !strings.HasSuffix(path, ".crt") {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			cert, err := ParseCertificate(path, data)
			if err != nil || cert == nil {
				return nil
			}

			info := CertificateInfo{
				Subject:         cert.Subject,
				Issuer:          cert.Issuer,
				SANs:            []string{}, // Would need to parse from cert
				NotBefore:       time.Time{},
				NotAfter:        cert.ExpiresAt,
				DaysUntilExpiry: cert.DaysUntilExpiry,
				IsExpired:       cert.DaysUntilExpiry < 0,
				Source:          "caddy",
				FilePath:        path,
			}
			certs = append(certs, info)

			return nil
		})

		if err != nil {
			w.logger.Debug("error walking Caddy cert path", "path", basePath, "error", err)
		}
	}

	// Also try to parse Caddyfile for domain info
	caddyfilePaths := []string{
		"/etc/caddy/Caddyfile",
		"/data/Caddyfile",
		"/config/Caddyfile",
	}

	for _, path := range caddyfilePaths {
		domains := w.parseCaddyfile(path)
		if len(domains) > 0 {
			w.logger.Debug("found domains in Caddyfile", "path", path, "domains", domains)
		}
	}

	return certs
}

// parseCaddyfile extracts domain names from a Caddyfile.
func (w *EncryptionWatcher) parseCaddyfile(path string) []string {
	domains := make([]string, 0)

	data, err := os.ReadFile(path)
	if err != nil {
		return domains
	}

	// Simple regex to find domain blocks
	// Matches: example.com { or example.com:443 { or https://example.com {
	domainRe := regexp.MustCompile(`(?m)^(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?::\d+)?\s*\{`)

	matches := domainRe.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		if len(match) > 1 {
			domains = append(domains, match[1])
		}
	}

	return domains
}

// mergeCertificates merges certificates from different sources, preferring live probe data.
func (w *EncryptionWatcher) mergeCertificates(endpoints []TLSEndpoint, configCerts, fileCerts []CertificateInfo) []CertificateInfo {
	// Use subject as key for deduplication
	certMap := make(map[string]CertificateInfo)

	// Add file certs first (lowest priority)
	for _, cert := range fileCerts {
		key := cert.Subject
		if key == "" {
			key = cert.FilePath
		}
		certMap[key] = cert
	}

	// Add config certs (medium priority)
	for _, cert := range configCerts {
		key := cert.Subject
		if key == "" {
			key = cert.FilePath
		}
		certMap[key] = cert
	}

	// Add live probe certs (highest priority)
	for _, ep := range endpoints {
		if ep.Certificate != nil {
			key := ep.Certificate.Subject
			if key == "" {
				key = ep.Address
			}
			certMap[key] = *ep.Certificate
		}
	}

	// Convert back to slice
	result := make([]CertificateInfo, 0, len(certMap))
	for _, cert := range certMap {
		result = append(result, cert)
	}

	return result
}

// DiskEncryption represents the encryption status of a disk or partition.
type DiskEncryption struct {
	Device         string
	MountPoint     string
	Encrypted      bool
	EncryptionType string
}

// CertificateExpiry represents certificate expiration information (legacy).
type CertificateExpiry struct {
	Path            string
	Subject         string
	Issuer          string
	ExpiresAt       time.Time
	DaysUntilExpiry int
}

// TLSConfiguration represents TLS configuration for a service (legacy).
type TLSConfiguration struct {
	Service         string
	Port            int
	MinVersion      string
	CipherSuites    []string
	CertificatePath string
}

// collectDiskEncryption collects disk encryption status.
func (w *EncryptionWatcher) collectDiskEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// Linux: try lsblk to get disk information
	lsblkDisks := w.parseLsblkOutput()
	if len(lsblkDisks) > 0 {
		disks = append(disks, lsblkDisks...)
	}

	// Linux: check /sys/block for dm-crypt/LUKS volumes
	sysBlockDisks := w.checkSysBlockEncryption()
	disks = append(disks, sysBlockDisks...)

	// macOS: check FileVault status
	fileVaultDisks := w.checkFileVault()
	disks = append(disks, fileVaultDisks...)

	// Cloud: check for cloud provider disk encryption
	cloudDisks := w.checkCloudDiskEncryption()
	disks = append(disks, cloudDisks...)

	// Deduplicate by device
	seen := make(map[string]bool)
	unique := make([]DiskEncryption, 0)
	for _, d := range disks {
		if !seen[d.Device] {
			seen[d.Device] = true
			unique = append(unique, d)
		}
	}

	return unique
}

// parseLsblkOutput runs lsblk and parses the output for encryption info.
func (w *EncryptionWatcher) parseLsblkOutput() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	output, err := exec.Command("lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT").Output()
	if err != nil {
		w.logger.Debug("lsblk not available", "error", err)
		return disks
	}

	return ParseLsblkOutput(string(output))
}

// ParseLsblkOutput parses lsblk output and returns disk encryption info.
// This is exported for testing.
func ParseLsblkOutput(output string) []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	scanner := bufio.NewScanner(strings.NewReader(output))
	// Skip header
	if scanner.Scan() {
		// Skip the header line
	}

	for scanner.Scan() {
		line := scanner.Text()
		disk := parseLsblkLine(line)
		if disk != nil {
			disks = append(disks, *disk)
		}
	}

	return disks
}

// parseLsblkLine parses a single line from lsblk output.
func parseLsblkLine(line string) *DiskEncryption {
	if line == "" {
		return nil
	}

	// Remove tree characters
	cleanLine := strings.TrimLeft(line, " |-`\\")
	fields := strings.Fields(cleanLine)

	if len(fields) < 1 {
		return nil
	}

	device := "/dev/" + fields[0]
	fstype := ""
	mountpoint := ""

	if len(fields) >= 2 {
		fstype = fields[1]
	}
	if len(fields) >= 3 {
		mountpoint = fields[2]
	}

	// Check if this is an encrypted volume
	encrypted := false
	encryptionType := ""

	if strings.Contains(strings.ToLower(fstype), "luks") ||
		strings.Contains(strings.ToLower(fstype), "crypto") {
		encrypted = true
		encryptionType = "LUKS"
	}

	// Also check if the device name suggests dm-crypt
	if strings.Contains(fields[0], "_crypt") ||
		strings.Contains(fields[0], "dm-") ||
		strings.HasPrefix(fields[0], "crypt") {
		encrypted = true
		if encryptionType == "" {
			encryptionType = "dm-crypt"
		}
	}

	return &DiskEncryption{
		Device:         device,
		MountPoint:     mountpoint,
		Encrypted:      encrypted,
		EncryptionType: encryptionType,
	}
}

// checkSysBlockEncryption checks /sys/block for encrypted volumes.
func (w *EncryptionWatcher) checkSysBlockEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	dmPath := "/sys/block"
	entries, err := os.ReadDir(dmPath)
	if err != nil {
		return disks
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "dm-") {
			continue
		}

		namePath := filepath.Join(dmPath, entry.Name(), "dm", "name")
		nameBytes, err := os.ReadFile(namePath)
		if err != nil {
			continue
		}

		name := strings.TrimSpace(string(nameBytes))
		encrypted := false
		encryptionType := ""

		if strings.Contains(strings.ToLower(name), "crypt") ||
			strings.Contains(strings.ToLower(name), "luks") {
			encrypted = true
			encryptionType = "LUKS"
		}

		uuidPath := filepath.Join(dmPath, entry.Name(), "dm", "uuid")
		uuidBytes, err := os.ReadFile(uuidPath)
		if err == nil {
			uuid := strings.TrimSpace(string(uuidBytes))
			if strings.HasPrefix(uuid, "CRYPT-") {
				encrypted = true
				if encryptionType == "" {
					encryptionType = "dm-crypt"
				}
			}
		}

		if encrypted {
			disks = append(disks, DiskEncryption{
				Device:         "/dev/" + entry.Name(),
				MountPoint:     "",
				Encrypted:      true,
				EncryptionType: encryptionType,
			})
		}
	}

	return disks
}

// checkFileVault checks macOS FileVault encryption status.
func (w *EncryptionWatcher) checkFileVault() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// Try fdesetup status (requires root on macOS)
	output, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		// Not macOS or not root
		w.logger.Debug("fdesetup not available", "error", err)
		return disks
	}

	status := string(output)
	encrypted := strings.Contains(status, "FileVault is On")
	encryptionState := ""
	if strings.Contains(status, "Encryption in progress") {
		encryptionState = "encrypting"
	} else if strings.Contains(status, "Decryption in progress") {
		encryptionState = "decrypting"
	}

	disk := DiskEncryption{
		Device:         "/",
		MountPoint:     "/",
		Encrypted:      encrypted,
		EncryptionType: "FileVault",
	}

	if encryptionState != "" {
		w.logger.Info("FileVault state", "state", encryptionState)
	}

	disks = append(disks, disk)

	return disks
}

// checkCloudDiskEncryption checks for cloud provider disk encryption.
// This uses IMDS (Instance Metadata Service) endpoints to detect cloud environment
// and then checks if disk encryption is enabled.
func (w *EncryptionWatcher) checkCloudDiskEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// Try AWS IMDS
	awsDisks := w.checkAWSEBSEncryption()
	disks = append(disks, awsDisks...)

	// Try Azure IMDS
	azureDisks := w.checkAzureDiskEncryption()
	disks = append(disks, azureDisks...)

	// Try GCP metadata
	gcpDisks := w.checkGCPDiskEncryption()
	disks = append(disks, gcpDisks...)

	// Try Oracle Cloud Infrastructure (OCI)
	ociDisks := w.checkOCIDiskEncryption()
	disks = append(disks, ociDisks...)

	return disks
}

// checkAWSEBSEncryption checks if we're on AWS and if EBS encryption is enabled.
func (w *EncryptionWatcher) checkAWSEBSEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// Try to get IMDSv2 token first
	client := &net.Dialer{Timeout: 1 * time.Second}
	conn, err := client.Dial("tcp", "169.254.169.254:80")
	if err != nil {
		return disks // Not on AWS or can't reach IMDS
	}
	conn.Close()

	// Get IMDSv2 token
	tokenCmd := exec.Command("curl", "-s", "-X", "PUT",
		"-H", "X-aws-ec2-metadata-token-ttl-seconds: 21600",
		"http://169.254.169.254/latest/api/token")
	tokenOutput, err := tokenCmd.Output()
	if err != nil {
		return disks
	}
	token := strings.TrimSpace(string(tokenOutput))

	// Get instance identity document
	identityCmd := exec.Command("curl", "-s",
		"-H", "X-aws-ec2-metadata-token: "+token,
		"http://169.254.169.254/latest/dynamic/instance-identity/document")
	identityOutput, err := identityCmd.Output()
	if err != nil {
		return disks
	}

	// Parse instance identity to confirm we're on AWS
	var identity struct {
		Region     string `json:"region"`
		InstanceID string `json:"instanceId"`
	}
	if err := json.Unmarshal(identityOutput, &identity); err != nil {
		return disks
	}

	// Get block device mappings
	bdmCmd := exec.Command("curl", "-s",
		"-H", "X-aws-ec2-metadata-token: "+token,
		"http://169.254.169.254/latest/meta-data/block-device-mapping/")
	bdmOutput, err := bdmCmd.Output()
	if err != nil {
		return disks
	}

	// Each line is a block device
	for _, device := range strings.Split(string(bdmOutput), "\n") {
		device = strings.TrimSpace(device)
		if device == "" {
			continue
		}

		// Get the EBS volume ID for this device
		volCmd := exec.Command("curl", "-s",
			"-H", "X-aws-ec2-metadata-token: "+token,
			"http://169.254.169.254/latest/meta-data/block-device-mapping/"+device)
		volOutput, err := volCmd.Output()
		if err != nil {
			continue
		}

		volumeID := strings.TrimSpace(string(volOutput))

		// Note: IMDS doesn't directly tell us if the volume is encrypted.
		// We can only report that this is an EBS volume.
		// For full encryption status, would need AWS API call with credentials.
		disks = append(disks, DiskEncryption{
			Device:         device,
			MountPoint:     "",
			Encrypted:      false, // Unknown - would need AWS API
			EncryptionType: "AWS-EBS:" + volumeID,
		})
	}

	w.logger.Debug("AWS EBS volumes detected", "count", len(disks), "region", identity.Region)
	return disks
}

// checkAzureDiskEncryption checks if we're on Azure and disk encryption is enabled.
func (w *EncryptionWatcher) checkAzureDiskEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// Try Azure IMDS
	client := &net.Dialer{Timeout: 1 * time.Second}
	conn, err := client.Dial("tcp", "169.254.169.254:80")
	if err != nil {
		return disks
	}
	conn.Close()

	// Get Azure compute metadata
	cmd := exec.Command("curl", "-s", "-H", "Metadata:true",
		"http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01")
	output, err := cmd.Output()
	if err != nil {
		return disks
	}

	var compute struct {
		Provider    string `json:"provider"`
		VMID        string `json:"vmId"`
		StorageProfile struct {
			DataDisks []struct {
				Name          string `json:"name"`
				Lun           string `json:"lun"`
				DiskSizeGB    string `json:"diskSizeGB"`
				ManagedDisk   struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
			} `json:"dataDisks"`
			OsDisk struct {
				Name string `json:"name"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
	}

	if err := json.Unmarshal(output, &compute); err != nil {
		return disks
	}

	// Check if this is actually Azure
	if compute.VMID == "" {
		return disks
	}

	// Check OS disk
	osDiskEncrypted := compute.StorageProfile.OsDisk.EncryptionSettings.Enabled == "true"
	disks = append(disks, DiskEncryption{
		Device:         compute.StorageProfile.OsDisk.Name,
		MountPoint:     "/",
		Encrypted:      osDiskEncrypted,
		EncryptionType: "Azure-Disk",
	})

	// Check data disks
	for _, dataDisk := range compute.StorageProfile.DataDisks {
		encrypted := dataDisk.EncryptionSettings.Enabled == "true"
		disks = append(disks, DiskEncryption{
			Device:         dataDisk.Name,
			MountPoint:     "",
			Encrypted:      encrypted,
			EncryptionType: "Azure-Disk",
		})
	}

	w.logger.Debug("Azure disks detected", "count", len(disks))
	return disks
}

// checkGCPDiskEncryption checks if we're on GCP and disk encryption is enabled.
func (w *EncryptionWatcher) checkGCPDiskEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// Try GCP metadata server
	client := &net.Dialer{Timeout: 1 * time.Second}
	conn, err := client.Dial("tcp", "metadata.google.internal:80")
	if err != nil {
		// Also try by IP
		conn, err = client.Dial("tcp", "169.254.169.254:80")
		if err != nil {
			return disks
		}
	}
	conn.Close()

	// Get instance metadata
	cmd := exec.Command("curl", "-s", "-H", "Metadata-Flavor: Google",
		"http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true")
	output, err := cmd.Output()
	if err != nil {
		return disks
	}

	var gcpDisks []struct {
		DeviceName string `json:"deviceName"`
		Index      int    `json:"index"`
		Mode       string `json:"mode"`
		Type       string `json:"type"`
	}

	if err := json.Unmarshal(output, &gcpDisks); err != nil {
		return disks
	}

	// GCP encrypts all disks at rest by default
	for _, gcpDisk := range gcpDisks {
		disks = append(disks, DiskEncryption{
			Device:         gcpDisk.DeviceName,
			MountPoint:     "",
			Encrypted:      true, // GCP encrypts all disks by default
			EncryptionType: "GCP-PD",
		})
	}

	w.logger.Debug("GCP disks detected", "count", len(disks))
	return disks
}

// checkOCIDiskEncryption checks if we're on Oracle Cloud Infrastructure.
func (w *EncryptionWatcher) checkOCIDiskEncryption() []DiskEncryption {
	disks := make([]DiskEncryption, 0)

	// OCI IMDS v2 uses 169.254.169.254 with Authorization header
	client := &net.Dialer{Timeout: 1 * time.Second}
	conn, err := client.Dial("tcp", "169.254.169.254:80")
	if err != nil {
		return disks
	}
	conn.Close()

	// Get instance metadata - OCI uses a different path structure
	cmd := exec.Command("curl", "-s",
		"-H", "Authorization: Bearer Oracle",
		"http://169.254.169.254/opc/v2/instance/")
	output, err := cmd.Output()
	if err != nil {
		return disks
	}

	var instance struct {
		ID               string `json:"id"`
		DisplayName      string `json:"displayName"`
		CompartmentID    string `json:"compartmentId"`
		AvailabilityDomain string `json:"availabilityDomain"`
		Region           string `json:"region"`
	}

	if err := json.Unmarshal(output, &instance); err != nil {
		return disks
	}

	// Check if this is actually OCI
	if instance.ID == "" || instance.CompartmentID == "" {
		return disks
	}

	// Get volume attachments
	volCmd := exec.Command("curl", "-s",
		"-H", "Authorization: Bearer Oracle",
		"http://169.254.169.254/opc/v2/volumeAttachments/")
	volOutput, err := volCmd.Output()
	if err != nil {
		// Fall back to reporting boot volume
		disks = append(disks, DiskEncryption{
			Device:         "boot-volume",
			MountPoint:     "/",
			Encrypted:      true, // OCI encrypts all block volumes by default
			EncryptionType: "OCI-Block",
		})
		w.logger.Debug("OCI instance detected", "instance_id", instance.ID)
		return disks
	}

	var volumes []struct {
		VolumeID string `json:"volumeId"`
		Device   string `json:"device"`
	}

	if err := json.Unmarshal(volOutput, &volumes); err != nil {
		// Fall back to reporting boot volume
		disks = append(disks, DiskEncryption{
			Device:         "boot-volume",
			MountPoint:     "/",
			Encrypted:      true, // OCI encrypts all block volumes by default
			EncryptionType: "OCI-Block",
		})
	} else {
		// Report each attached volume
		// OCI encrypts all block storage volumes by default using Oracle-managed keys
		for _, vol := range volumes {
			disks = append(disks, DiskEncryption{
				Device:         vol.Device,
				MountPoint:     "",
				Encrypted:      true, // OCI encrypts all block volumes by default
				EncryptionType: "OCI-Block",
			})
		}
		// Add boot volume if not in list
		if len(volumes) == 0 {
			disks = append(disks, DiskEncryption{
				Device:         "boot-volume",
				MountPoint:     "/",
				Encrypted:      true,
				EncryptionType: "OCI-Block",
			})
		}
	}

	w.logger.Debug("OCI volumes detected", "count", len(disks), "region", instance.Region)
	return disks
}

// collectCertificateExpiry scans for certificates and checks expiry dates.
func (w *EncryptionWatcher) collectCertificateExpiry() []CertificateInfo {
	certs := make([]CertificateInfo, 0)

	for _, certPath := range w.certPaths {
		pathCerts := w.scanCertificatesInPath(certPath)
		certs = append(certs, pathCerts...)
	}

	// Also scan TLS config paths for certificates
	for _, tlsPath := range TLSConfigPaths {
		pathCerts := w.scanCertificatesInPath(tlsPath)
		certs = append(certs, pathCerts...)
	}

	return certs
}

// scanCertificatesInPath scans a directory for certificate files.
func (w *EncryptionWatcher) scanCertificatesInPath(basePath string) []CertificateInfo {
	certs := make([]CertificateInfo, 0)

	err := filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".pem" && ext != ".crt" && ext != ".cer" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		cert, err := ParseCertificate(path, data)
		if err != nil || cert == nil {
			return nil
		}

		info := CertificateInfo{
			Subject:         cert.Subject,
			Issuer:          cert.Issuer,
			NotAfter:        cert.ExpiresAt,
			DaysUntilExpiry: cert.DaysUntilExpiry,
			IsExpired:       cert.DaysUntilExpiry < 0,
			Source:          "file",
			FilePath:        path,
		}
		certs = append(certs, info)

		return nil
	})

	if err != nil {
		w.logger.Debug("failed to walk certificate path", "path", basePath, "error", err)
	}

	return certs
}

// ParseCertificate parses PEM certificate data and returns expiry info.
// This is exported for testing.
func ParseCertificate(path string, data []byte) (*CertificateExpiry, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil
	}

	if block.Type != "CERTIFICATE" {
		return nil, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &CertificateExpiry{
		Path:            path,
		Subject:         cert.Subject.CommonName,
		Issuer:          cert.Issuer.CommonName,
		ExpiresAt:       cert.NotAfter,
		DaysUntilExpiry: daysUntilExpiry,
	}, nil
}

// Helper functions

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no such host") ||
		strings.Contains(err.Error(), "i/o timeout")
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Payload conversion helpers

func diskEncryptionToPayload(disks []DiskEncryption) []map[string]any {
	result := make([]map[string]any, len(disks))
	for i, d := range disks {
		result[i] = map[string]any{
			"device":          d.Device,
			"mount_point":     d.MountPoint,
			"encrypted":       d.Encrypted,
			"encryption_type": d.EncryptionType,
		}
	}
	return result
}

func tlsEndpointsToPayload(endpoints []TLSEndpoint) []map[string]any {
	result := make([]map[string]any, 0, len(endpoints))
	for _, e := range endpoints {
		if !e.ProbeSuccessful && e.ProbeError == "" {
			continue // Skip ports that aren't listening
		}

		ep := map[string]any{
			"address":          e.Address,
			"port":             e.Port,
			"probe_successful": e.ProbeSuccessful,
		}

		if e.ProbeSuccessful {
			ep["tls_version"] = e.TLSVersion
			ep["cipher_suite"] = e.CipherSuite
			if e.Certificate != nil {
				ep["certificate"] = map[string]any{
					"subject":           e.Certificate.Subject,
					"issuer":            e.Certificate.Issuer,
					"sans":              e.Certificate.SANs,
					"not_before":        e.Certificate.NotBefore.Format(time.RFC3339),
					"not_after":         e.Certificate.NotAfter.Format(time.RFC3339),
					"days_until_expiry": e.Certificate.DaysUntilExpiry,
					"is_expired":        e.Certificate.IsExpired,
				}
			}
		} else {
			ep["probe_error"] = e.ProbeError
		}

		if e.ConfigSource != "" {
			ep["config_source"] = e.ConfigSource
		}

		result = append(result, ep)
	}
	return result
}

func certsToPayload(certs []CertificateInfo) []map[string]any {
	result := make([]map[string]any, len(certs))
	for i, c := range certs {
		result[i] = map[string]any{
			"subject":           c.Subject,
			"issuer":            c.Issuer,
			"sans":              c.SANs,
			"not_after":         c.NotAfter.Format(time.RFC3339),
			"days_until_expiry": c.DaysUntilExpiry,
			"is_expired":        c.IsExpired,
			"source":            c.Source,
		}
		if c.Endpoint != "" {
			result[i]["endpoint"] = c.Endpoint
		}
		if c.FilePath != "" {
			result[i]["file_path"] = c.FilePath
		}
	}
	return result
}
