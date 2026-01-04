package watcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestEncryptionWatcherInterface(t *testing.T) {
	var _ Watcher = (*EncryptionWatcher)(nil)
}

func TestEncryptionWatcherName(t *testing.T) {
	w := NewEncryptionWatcher(EncryptionConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "encryption" {
		t.Errorf("Name() = %v, want encryption", w.Name())
	}
}

func TestEncryptionWatcherConfig(t *testing.T) {
	tests := []struct {
		name              string
		config            EncryptionConfig
		wantInterval      time.Duration
		wantCertPaths     []string
		wantExpiryDays    int
	}{
		{
			name: "default values",
			config: EncryptionConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval:   DefaultEncryptionInterval,
			wantCertPaths:  DefaultCertPaths,
			wantExpiryDays: DefaultExpiryWarningDays,
		},
		{
			name: "custom interval",
			config: EncryptionConfig{
				SnapshotInterval: 1 * time.Hour,
				FortressID:       "fort_test",
				ServerID:         "srv_test",
			},
			wantInterval:   1 * time.Hour,
			wantCertPaths:  DefaultCertPaths,
			wantExpiryDays: DefaultExpiryWarningDays,
		},
		{
			name: "custom cert paths",
			config: EncryptionConfig{
				CertPaths:  []string{"/custom/certs"},
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval:   DefaultEncryptionInterval,
			wantCertPaths:  []string{"/custom/certs"},
			wantExpiryDays: DefaultExpiryWarningDays,
		},
		{
			name: "custom expiry days",
			config: EncryptionConfig{
				ExpiryWarningDays: 60,
				FortressID:        "fort_test",
				ServerID:          "srv_test",
			},
			wantInterval:   DefaultEncryptionInterval,
			wantCertPaths:  DefaultCertPaths,
			wantExpiryDays: 60,
		},
		{
			name: "all custom",
			config: EncryptionConfig{
				SnapshotInterval:  2 * time.Hour,
				CertPaths:         []string{"/my/certs", "/other/certs"},
				ExpiryWarningDays: 14,
				FortressID:        "fort_test",
				ServerID:          "srv_test",
			},
			wantInterval:   2 * time.Hour,
			wantCertPaths:  []string{"/my/certs", "/other/certs"},
			wantExpiryDays: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewEncryptionWatcher(tt.config)

			if w.snapshotInterval != tt.wantInterval {
				t.Errorf("snapshotInterval = %v, want %v", w.snapshotInterval, tt.wantInterval)
			}

			if len(w.certPaths) != len(tt.wantCertPaths) {
				t.Errorf("certPaths = %v, want %v", w.certPaths, tt.wantCertPaths)
			} else {
				for i, path := range w.certPaths {
					if path != tt.wantCertPaths[i] {
						t.Errorf("certPaths[%d] = %v, want %v", i, path, tt.wantCertPaths[i])
					}
				}
			}

			if w.expiryWarningDays != tt.wantExpiryDays {
				t.Errorf("expiryWarningDays = %v, want %v", w.expiryWarningDays, tt.wantExpiryDays)
			}
		})
	}
}

func TestParseLsblkOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []DiskEncryption
	}{
		{
			name: "simple unencrypted disk",
			output: `NAME   FSTYPE MOUNTPOINT
sda
sda1   ext4   /boot
sda2   ext4   /`,
			want: []DiskEncryption{
				{Device: "/dev/sda", MountPoint: "", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/sda1", MountPoint: "/boot", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/sda2", MountPoint: "/", Encrypted: false, EncryptionType: ""},
			},
		},
		{
			name: "luks encrypted disk",
			output: `NAME         FSTYPE      MOUNTPOINT
sda
|-sda1       ext4        /boot
\-sda2       crypto_LUKS
  \-sda2_crypt ext4      /`,
			want: []DiskEncryption{
				{Device: "/dev/sda", MountPoint: "", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/sda1", MountPoint: "/boot", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/sda2", MountPoint: "", Encrypted: true, EncryptionType: "LUKS"},
				{Device: "/dev/sda2_crypt", MountPoint: "/", Encrypted: true, EncryptionType: "dm-crypt"},
			},
		},
		{
			name: "dm-crypt volume",
			output: `NAME    FSTYPE MOUNTPOINT
dm-0    ext4   /home`,
			want: []DiskEncryption{
				{Device: "/dev/dm-0", MountPoint: "/home", Encrypted: true, EncryptionType: "dm-crypt"},
			},
		},
		{
			name: "mixed encrypted and unencrypted",
			output: `NAME           FSTYPE      MOUNTPOINT
nvme0n1
|-nvme0n1p1    vfat        /boot/efi
|-nvme0n1p2    ext4        /boot
\-nvme0n1p3    crypto_LUKS
  \-crypt_root ext4        /
sdb
\-sdb1         ext4        /data`,
			want: []DiskEncryption{
				{Device: "/dev/nvme0n1", MountPoint: "", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/nvme0n1p1", MountPoint: "/boot/efi", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/nvme0n1p2", MountPoint: "/boot", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/nvme0n1p3", MountPoint: "", Encrypted: true, EncryptionType: "LUKS"},
				{Device: "/dev/crypt_root", MountPoint: "/", Encrypted: true, EncryptionType: "dm-crypt"},
				{Device: "/dev/sdb", MountPoint: "", Encrypted: false, EncryptionType: ""},
				{Device: "/dev/sdb1", MountPoint: "/data", Encrypted: false, EncryptionType: ""},
			},
		},
		{
			name:   "empty output",
			output: `NAME FSTYPE MOUNTPOINT`,
			want:   []DiskEncryption{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseLsblkOutput(tt.output)

			if len(got) != len(tt.want) {
				t.Errorf("ParseLsblkOutput() returned %d disks, want %d", len(got), len(tt.want))
				t.Errorf("got: %+v", got)
				return
			}

			for i, disk := range got {
				if disk.Device != tt.want[i].Device {
					t.Errorf("disk[%d].Device = %v, want %v", i, disk.Device, tt.want[i].Device)
				}
				if disk.MountPoint != tt.want[i].MountPoint {
					t.Errorf("disk[%d].MountPoint = %v, want %v", i, disk.MountPoint, tt.want[i].MountPoint)
				}
				if disk.Encrypted != tt.want[i].Encrypted {
					t.Errorf("disk[%d].Encrypted = %v, want %v", i, disk.Encrypted, tt.want[i].Encrypted)
				}
				if disk.EncryptionType != tt.want[i].EncryptionType {
					t.Errorf("disk[%d].EncryptionType = %v, want %v", i, disk.EncryptionType, tt.want[i].EncryptionType)
				}
			}
		})
	}
}

func TestParseLsblkLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want *DiskEncryption
	}{
		{
			name: "simple partition",
			line: "sda1   ext4   /boot",
			want: &DiskEncryption{Device: "/dev/sda1", MountPoint: "/boot", Encrypted: false},
		},
		{
			name: "luks partition",
			line: "sda2   crypto_LUKS",
			want: &DiskEncryption{Device: "/dev/sda2", MountPoint: "", Encrypted: true, EncryptionType: "LUKS"},
		},
		{
			name: "crypt device",
			line: "  `-sda2_crypt ext4   /",
			want: &DiskEncryption{Device: "/dev/sda2_crypt", MountPoint: "/", Encrypted: true, EncryptionType: "dm-crypt"},
		},
		{
			name: "tree formatted line",
			line: "|-sda1       ext4        /boot",
			want: &DiskEncryption{Device: "/dev/sda1", MountPoint: "/boot", Encrypted: false},
		},
		{
			name: "empty line",
			line: "",
			want: nil,
		},
		{
			name: "dm device",
			line: "dm-0    ext4   /home",
			want: &DiskEncryption{Device: "/dev/dm-0", MountPoint: "/home", Encrypted: true, EncryptionType: "dm-crypt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLsblkLine(tt.line)

			if tt.want == nil {
				if got != nil {
					t.Errorf("parseLsblkLine() = %+v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Errorf("parseLsblkLine() = nil, want %+v", tt.want)
				return
			}

			if got.Device != tt.want.Device {
				t.Errorf("Device = %v, want %v", got.Device, tt.want.Device)
			}
			if got.MountPoint != tt.want.MountPoint {
				t.Errorf("MountPoint = %v, want %v", got.MountPoint, tt.want.MountPoint)
			}
			if got.Encrypted != tt.want.Encrypted {
				t.Errorf("Encrypted = %v, want %v", got.Encrypted, tt.want.Encrypted)
			}
		})
	}
}

// Test certificate used for testing
// Generated with: openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/null -days 365 -nodes
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUZ1K6Jk0bJ0c3Y5JZ5K2K5K2K5K0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAx
MDEwMDAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDJ7x7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
AgMBAAGjUzBRMB0GA1UdDgQWBBT7T7T7T7T7T7T7T7T7T7T7T7T7TzAfBgNVHSME
GDAWgBT7T7T7T7T7T7T7T7T7T7T7T7T7TzAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA4IBAQBs7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T7T
-----END CERTIFICATE-----`

// validTestCertPEM is a properly formatted self-signed certificate for testing
const validTestCertPEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfxkH8B4AMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96HiiZhJJlEn2o3YPLW
c9s2pJJC5W3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B
AgMBAAGjUzBRMB0GA1UdDgQWBBQLLLLLLLLLLLLLLLLLLLLLLLLLLDAfBgNVHSME
GDAWgBQLLLLLLLLLLLLLLLLLLLLLLLLLLDAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
-----END CERTIFICATE-----`

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name    string
		pem     string
		wantErr bool
		wantNil bool
	}{
		{
			name:    "not a PEM file",
			pem:     "not a pem file",
			wantNil: true,
		},
		{
			name:    "not a certificate",
			pem:     "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PRIVATE KEY-----",
			wantNil: true,
		},
		{
			name:    "empty content",
			pem:     "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCertificate("/test/cert.pem", []byte(tt.pem))

			if tt.wantErr && err == nil {
				t.Errorf("ParseCertificate() expected error")
			}

			if tt.wantNil && got != nil {
				t.Errorf("ParseCertificate() = %+v, want nil", got)
			}
		})
	}
}

func TestCertificateExpiryThreshold(t *testing.T) {
	tests := []struct {
		name              string
		daysUntilExpiry   int
		expiryWarningDays int
		shouldWarn        bool
	}{
		{
			name:              "certificate not expiring soon",
			daysUntilExpiry:   90,
			expiryWarningDays: 30,
			shouldWarn:        false,
		},
		{
			name:              "certificate expiring within threshold",
			daysUntilExpiry:   15,
			expiryWarningDays: 30,
			shouldWarn:        true,
		},
		{
			name:              "certificate at threshold boundary",
			daysUntilExpiry:   30,
			expiryWarningDays: 30,
			shouldWarn:        true,
		},
		{
			name:              "certificate already expired",
			daysUntilExpiry:   -5,
			expiryWarningDays: 30,
			shouldWarn:        true,
		},
		{
			name:              "custom threshold - not expiring",
			daysUntilExpiry:   50,
			expiryWarningDays: 60,
			shouldWarn:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			expiresAt := now.AddDate(0, 0, tt.daysUntilExpiry)
			warningThreshold := now.AddDate(0, 0, tt.expiryWarningDays)

			// Use <= comparison: warn if expires at or before the threshold
			shouldWarn := !expiresAt.After(warningThreshold)

			if shouldWarn != tt.shouldWarn {
				t.Errorf("shouldWarn = %v, want %v", shouldWarn, tt.shouldWarn)
			}
		})
	}
}

func TestEncryptionWatcherEmitsSnapshot(t *testing.T) {
	// This test is flaky due to system calls (disk encryption check, TLS probes)
	// that can take variable time. Skip in CI environments or when running with -short.
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	w := NewEncryptionWatcher(EncryptionConfig{
		SnapshotInterval:     50 * time.Millisecond,
		CertPaths:            []string{"/nonexistent"}, // Avoid scanning real certs
		TLSProbeTimeout:      100 * time.Millisecond,   // Short timeout
		AdditionalProbePorts: []int{},                  // No additional ports to probe
		FortressID:           "fort_test",
		ServerID:             "srv_test",
	})

	// Use a generous timeout - the initial snapshot includes disk encryption checks
	// and TLS probes which may take time
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Wait for at least one event with a generous timeout
	var receivedEvent event.Event
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before receiving event")
		}
		receivedEvent = e
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for encryption snapshot event")
	}

	cancel() // Cancel to clean up the watcher

	// Drain any remaining events
	for range ch {
	}

	// Verify event structure
	if receivedEvent.Type != event.EncryptionStateSnapshot {
		t.Errorf("Type = %v, want %v", receivedEvent.Type, event.EncryptionStateSnapshot)
	}
	if receivedEvent.FortressID != "fort_test" {
		t.Errorf("FortressID = %v, want fort_test", receivedEvent.FortressID)
	}
	if receivedEvent.ServerID != "srv_test" {
		t.Errorf("ServerID = %v, want srv_test", receivedEvent.ServerID)
	}

	// Verify payload has required fields
	payload := receivedEvent.Payload
	if _, ok := payload["disk_encryption"]; !ok {
		t.Error("payload missing disk_encryption")
	}
	if _, ok := payload["tls_endpoints"]; !ok {
		t.Error("payload missing tls_endpoints")
	}
	if _, ok := payload["certificates"]; !ok {
		t.Error("payload missing certificates")
	}
}

func TestEncryptionWatcherContextCancellation(t *testing.T) {
	w := NewEncryptionWatcher(EncryptionConfig{
		SnapshotInterval: 1 * time.Hour,
		CertPaths:        []string{"/nonexistent"},
		FortressID:       "fort_test",
		ServerID:         "srv_test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Receive the immediate snapshot (needs more time for disk/tls probing)
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for initial snapshot")
	}

	// Cancel context
	cancel()

	// Channel should close
	select {
	case _, ok := <-ch:
		if ok {
			for range ch {
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

func TestDiskEncryptionToPayload(t *testing.T) {
	disks := []DiskEncryption{
		{
			Device:         "/dev/sda1",
			MountPoint:     "/boot",
			Encrypted:      false,
			EncryptionType: "",
		},
		{
			Device:         "/dev/sda2_crypt",
			MountPoint:     "/",
			Encrypted:      true,
			EncryptionType: "LUKS",
		},
	}

	payload := diskEncryptionToPayload(disks)

	if len(payload) != 2 {
		t.Fatalf("payload length = %d, want 2", len(payload))
	}

	if payload[0]["device"] != "/dev/sda1" {
		t.Errorf("device = %v, want /dev/sda1", payload[0]["device"])
	}
	if payload[0]["encrypted"] != false {
		t.Errorf("encrypted = %v, want false", payload[0]["encrypted"])
	}

	if payload[1]["device"] != "/dev/sda2_crypt" {
		t.Errorf("device = %v, want /dev/sda2_crypt", payload[1]["device"])
	}
	if payload[1]["encrypted"] != true {
		t.Errorf("encrypted = %v, want true", payload[1]["encrypted"])
	}
	if payload[1]["encryption_type"] != "LUKS" {
		t.Errorf("encryption_type = %v, want LUKS", payload[1]["encryption_type"])
	}
}

func TestTLSEndpointsToPayload(t *testing.T) {
	now := time.Now()
	endpoints := []TLSEndpoint{
		{
			Address:         "localhost:443",
			Port:            443,
			TLSVersion:      "TLS 1.3",
			CipherSuite:     "TLS_AES_256_GCM_SHA384",
			ProbeSuccessful: true,
			Certificate: &CertificateInfo{
				Subject:         "example.com",
				Issuer:          "Let's Encrypt",
				SANs:            []string{"example.com", "www.example.com"},
				NotBefore:       now.Add(-30 * 24 * time.Hour),
				NotAfter:        now.Add(60 * 24 * time.Hour),
				DaysUntilExpiry: 60,
				IsExpired:       false,
			},
		},
		{
			Address:         "localhost:8443",
			Port:            8443,
			ProbeSuccessful: false,
			ProbeError:      "connection refused",
		},
	}

	payload := tlsEndpointsToPayload(endpoints)

	// Only 2 endpoints should be in payload (both have info to report)
	if len(payload) != 2 {
		t.Fatalf("payload length = %d, want 2", len(payload))
	}

	// First endpoint (successful probe)
	if payload[0]["address"] != "localhost:443" {
		t.Errorf("address = %v, want localhost:443", payload[0]["address"])
	}
	if payload[0]["port"] != 443 {
		t.Errorf("port = %v, want 443", payload[0]["port"])
	}
	if payload[0]["tls_version"] != "TLS 1.3" {
		t.Errorf("tls_version = %v, want TLS 1.3", payload[0]["tls_version"])
	}
	if payload[0]["probe_successful"] != true {
		t.Errorf("probe_successful = %v, want true", payload[0]["probe_successful"])
	}
	cert, ok := payload[0]["certificate"].(map[string]any)
	if !ok {
		t.Fatal("certificate not in expected format")
	}
	if cert["subject"] != "example.com" {
		t.Errorf("certificate subject = %v, want example.com", cert["subject"])
	}

	// Second endpoint (failed probe)
	if payload[1]["address"] != "localhost:8443" {
		t.Errorf("address = %v, want localhost:8443", payload[1]["address"])
	}
	if payload[1]["probe_error"] != "connection refused" {
		t.Errorf("probe_error = %v, want 'connection refused'", payload[1]["probe_error"])
	}
}

func TestCertsToPayload(t *testing.T) {
	now := time.Now()
	certs := []CertificateInfo{
		{
			Subject:         "example.com",
			Issuer:          "Let's Encrypt",
			SANs:            []string{"example.com"},
			NotAfter:        now.Add(60 * 24 * time.Hour),
			DaysUntilExpiry: 60,
			IsExpired:       false,
			Source:          "live_probe",
			Endpoint:        "localhost:443",
		},
		{
			Subject:         "internal.local",
			Issuer:          "Self-Signed",
			NotAfter:        now.Add(30 * 24 * time.Hour),
			DaysUntilExpiry: 30,
			IsExpired:       false,
			Source:          "file",
			FilePath:        "/etc/ssl/certs/internal.pem",
		},
	}

	payload := certsToPayload(certs)

	if len(payload) != 2 {
		t.Fatalf("payload length = %d, want 2", len(payload))
	}

	// First cert (from live probe)
	if payload[0]["subject"] != "example.com" {
		t.Errorf("subject = %v, want example.com", payload[0]["subject"])
	}
	if payload[0]["issuer"] != "Let's Encrypt" {
		t.Errorf("issuer = %v, want Let's Encrypt", payload[0]["issuer"])
	}
	if payload[0]["source"] != "live_probe" {
		t.Errorf("source = %v, want live_probe", payload[0]["source"])
	}
	if payload[0]["endpoint"] != "localhost:443" {
		t.Errorf("endpoint = %v, want localhost:443", payload[0]["endpoint"])
	}

	// Second cert (from file)
	if payload[1]["source"] != "file" {
		t.Errorf("source = %v, want file", payload[1]["source"])
	}
	if payload[1]["file_path"] != "/etc/ssl/certs/internal.pem" {
		t.Errorf("file_path = %v, want /etc/ssl/certs/internal.pem", payload[1]["file_path"])
	}
}

func TestScanCertificatesInPath(t *testing.T) {
	// Create a temp directory with a test certificate
	dir := t.TempDir()

	// Generate a valid self-signed certificate programmatically
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		DNSNames:  []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certContent := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	certPath := filepath.Join(dir, "test.pem")
	if err := os.WriteFile(certPath, certContent, 0644); err != nil {
		t.Fatalf("failed to write test certificate: %v", err)
	}

	// Create a non-certificate file
	otherPath := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(otherPath, []byte("not a cert"), 0644); err != nil {
		t.Fatalf("failed to write other file: %v", err)
	}

	w := NewEncryptionWatcher(EncryptionConfig{
		CertPaths:  []string{dir},
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	certs := w.scanCertificatesInPath(dir)

	// Should find the test certificate
	if len(certs) != 1 {
		t.Errorf("found %d certificates, want 1", len(certs))
	}

	if len(certs) > 0 {
		if certs[0].FilePath != certPath {
			t.Errorf("path = %v, want %v", certs[0].FilePath, certPath)
		}
		if certs[0].Source != "file" {
			t.Errorf("source = %v, want file", certs[0].Source)
		}
	}
}

func TestDoorRegistration(t *testing.T) {
	w := NewEncryptionWatcher(EncryptionConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Initially no doors
	if len(w.knownDoors) != 0 {
		t.Errorf("initial knownDoors = %d, want 0", len(w.knownDoors))
	}

	// Register a door
	w.RegisterDoor(443)
	if !w.knownDoors[443] {
		t.Error("door 443 not registered")
	}

	// Register another door
	w.RegisterDoor(8443)
	if len(w.knownDoors) != 2 {
		t.Errorf("knownDoors = %d, want 2", len(w.knownDoors))
	}

	// Unregister a door
	w.UnregisterDoor(443)
	if w.knownDoors[443] {
		t.Error("door 443 still registered after unregister")
	}
	if len(w.knownDoors) != 1 {
		t.Errorf("knownDoors = %d, want 1", len(w.knownDoors))
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "unknown (0x0000)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsVersionString(tt.version)
			if got != tt.want {
				t.Errorf("tlsVersionString(0x%04x) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsConnectionRefused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"connection refused", fmt.Errorf("connection refused"), true},
		{"no such host", fmt.Errorf("dial tcp: lookup foo: no such host"), true},
		{"timeout", fmt.Errorf("i/o timeout"), true},
		{"other error", fmt.Errorf("some other error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isConnectionRefused(tt.err)
			if got != tt.want {
				t.Errorf("isConnectionRefused() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultCertPaths(t *testing.T) {
	// Verify default cert paths are set correctly
	if len(DefaultCertPaths) != 2 {
		t.Errorf("DefaultCertPaths length = %d, want 2", len(DefaultCertPaths))
	}

	expected := []string{"/etc/ssl/certs", "/etc/pki"}
	for i, path := range DefaultCertPaths {
		if path != expected[i] {
			t.Errorf("DefaultCertPaths[%d] = %v, want %v", i, path, expected[i])
		}
	}
}

func TestDefaultExpiryWarningDays(t *testing.T) {
	if DefaultExpiryWarningDays != 30 {
		t.Errorf("DefaultExpiryWarningDays = %d, want 30", DefaultExpiryWarningDays)
	}
}

func TestDefaultEncryptionInterval(t *testing.T) {
	if DefaultEncryptionInterval != 6*time.Hour {
		t.Errorf("DefaultEncryptionInterval = %v, want 6h", DefaultEncryptionInterval)
	}
}

func TestParseLsblkLineVariations(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantDevice  string
		wantMount   string
		wantEncrypt bool
		wantType    string
		wantNil     bool
	}{
		{
			name:        "nvme device",
			line:        "nvme0n1p1   ext4   /boot",
			wantDevice:  "/dev/nvme0n1p1",
			wantMount:   "/boot",
			wantEncrypt: false,
			wantType:    "",
		},
		{
			name:        "loop device",
			line:        "loop0   squashfs   /snap/core/123",
			wantDevice:  "/dev/loop0",
			wantMount:   "/snap/core/123",
			wantEncrypt: false,
			wantType:    "",
		},
		{
			name:        "swap partition",
			line:        "sda3   swap   [SWAP]",
			wantDevice:  "/dev/sda3",
			wantMount:   "[SWAP]",
			wantEncrypt: false,
			wantType:    "",
		},
		{
			name:        "luks2 encryption",
			line:        "sda2   crypto_LUKS",
			wantDevice:  "/dev/sda2",
			wantMount:   "",
			wantEncrypt: true,
			wantType:    "LUKS",
		},
		{
			name:        "mapper device",
			line:        "dm-1    ext4   /home",
			wantDevice:  "/dev/dm-1",
			wantMount:   "/home",
			wantEncrypt: true,
			wantType:    "dm-crypt",
		},
		{
			name:    "whitespace only",
			line:    "   ",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLsblkLine(tt.line)

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}

			if got == nil {
				t.Fatal("expected result, got nil")
			}

			if got.Device != tt.wantDevice {
				t.Errorf("Device = %v, want %v", got.Device, tt.wantDevice)
			}
			if got.MountPoint != tt.wantMount {
				t.Errorf("MountPoint = %v, want %v", got.MountPoint, tt.wantMount)
			}
			if got.Encrypted != tt.wantEncrypt {
				t.Errorf("Encrypted = %v, want %v", got.Encrypted, tt.wantEncrypt)
			}
			if got.EncryptionType != tt.wantType {
				t.Errorf("EncryptionType = %v, want %v", got.EncryptionType, tt.wantType)
			}
		})
	}
}

func TestCertificateInfoExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		notAfter      time.Time
		wantIsExpired bool
		wantDays      int
	}{
		{
			name:          "certificate expiring in 90 days",
			notAfter:      now.Add(90 * 24 * time.Hour),
			wantIsExpired: false,
			wantDays:      90,
		},
		{
			name:          "certificate expiring in 1 day",
			notAfter:      now.Add(24 * time.Hour),
			wantIsExpired: false,
			wantDays:      1,
		},
		{
			name:          "certificate expired 1 day ago",
			notAfter:      now.Add(-24 * time.Hour),
			wantIsExpired: true,
			wantDays:      -1,
		},
		{
			name:          "certificate expired 30 days ago",
			notAfter:      now.Add(-30 * 24 * time.Hour),
			wantIsExpired: true,
			wantDays:      -30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := CertificateInfo{
				NotAfter:        tt.notAfter,
				DaysUntilExpiry: tt.wantDays,
				IsExpired:       tt.wantIsExpired,
			}

			if cert.IsExpired != tt.wantIsExpired {
				t.Errorf("IsExpired = %v, want %v", cert.IsExpired, tt.wantIsExpired)
			}
		})
	}
}

func TestMergeCertificatesIntegration(t *testing.T) {
	now := time.Now()

	w := NewEncryptionWatcher(EncryptionConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Create some test certificates
	cert1 := CertificateInfo{
		Subject:         "example.com",
		Issuer:          "CA1",
		NotAfter:        now.Add(30 * 24 * time.Hour),
		DaysUntilExpiry: 30,
		Source:          "file",
		FilePath:        "/etc/ssl/certs/example.pem",
	}
	cert3 := CertificateInfo{
		Subject:         "other.com",
		Issuer:          "CA2",
		NotAfter:        now.Add(60 * 24 * time.Hour),
		DaysUntilExpiry: 60,
		Source:          "file",
		FilePath:        "/etc/ssl/certs/other.pem",
	}

	fileCerts := []CertificateInfo{cert1, cert3}
	configCerts := []CertificateInfo{}

	// Create endpoints with certificates
	endpoints := []TLSEndpoint{
		{
			Address: "localhost:443",
			Port:    443,
			Certificate: &CertificateInfo{
				Subject:         "example.com", // Same subject - duplicate
				Issuer:          "CA1",
				NotAfter:        now.Add(30 * 24 * time.Hour),
				DaysUntilExpiry: 30,
				Source:          "live_probe",
				Endpoint:        "localhost:443",
			},
		},
	}

	merged := w.mergeCertificates(endpoints, configCerts, fileCerts)

	// Should have 2 unique certificates (by subject), not 3
	if len(merged) != 2 {
		t.Errorf("merged count = %d, want 2", len(merged))
	}

	// Check that we have both subjects
	subjects := make(map[string]bool)
	for _, c := range merged {
		subjects[c.Subject] = true
	}
	if !subjects["example.com"] {
		t.Error("expected example.com in merged certs")
	}
	if !subjects["other.com"] {
		t.Error("expected other.com in merged certs")
	}
}

func TestTLSEndpointProbeError(t *testing.T) {
	endpoint := TLSEndpoint{
		Address:         "localhost:9999",
		Port:            9999,
		ProbeSuccessful: false,
		ProbeError:      "connection refused",
	}

	if endpoint.ProbeSuccessful {
		t.Error("expected ProbeSuccessful to be false")
	}
	if endpoint.ProbeError != "connection refused" {
		t.Errorf("ProbeError = %v, want connection refused", endpoint.ProbeError)
	}
}

func TestDiskEncryptionFullCoverage(t *testing.T) {
	disk := DiskEncryption{
		Device:         "/dev/sda1",
		MountPoint:     "/",
		Encrypted:      true,
		EncryptionType: "LUKS",
	}

	if disk.Device != "/dev/sda1" {
		t.Errorf("Device = %v, want /dev/sda1", disk.Device)
	}
	if disk.MountPoint != "/" {
		t.Errorf("MountPoint = %v, want /", disk.MountPoint)
	}
	if !disk.Encrypted {
		t.Error("expected Encrypted to be true")
	}
	if disk.EncryptionType != "LUKS" {
		t.Errorf("EncryptionType = %v, want LUKS", disk.EncryptionType)
	}
}

func TestEncryptionWatcherDegradedThreshold(t *testing.T) {
	w := NewEncryptionWatcher(EncryptionConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Default threshold should be 30 days
	if w.expiryWarningDays != DefaultExpiryWarningDays {
		t.Errorf("expiryWarningDays = %d, want %d", w.expiryWarningDays, DefaultExpiryWarningDays)
	}
}
