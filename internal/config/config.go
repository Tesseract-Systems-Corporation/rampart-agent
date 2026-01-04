// Package config handles loading and validating agent configuration.
package config

import (
	"crypto/rand"
	"fmt"
	"github.com/oklog/ulid/v2"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"time"
)

// Config holds the complete agent configuration.
type Config struct {
	// APIKey is the API key for authenticating with the control plane.
	APIKey string `yaml:"api_key"`
	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string `yaml:"fortress_id"`
	// ServerID is a unique identifier for this server.
	// If empty, will be auto-generated.
	ServerID string `yaml:"server_id"`
	// ServerName is a human-friendly name for this server.
	// If empty, defaults to the hostname.
	ServerName string `yaml:"server_name"`
	// ControlPlane is the URL of the control plane.
	ControlPlane string `yaml:"control_plane"`
	// Watchers contains configuration for each watcher.
	Watchers WatchersConfig `yaml:"watchers"`
	// Emitter contains configuration for the event emitter.
	Emitter EmitterConfig `yaml:"emitter"`
}

// WatchersConfig contains configuration for all watchers.
type WatchersConfig struct {
	Docker        DockerWatcherConfig        `yaml:"docker"`
	SSH           SSHWatcherConfig           `yaml:"ssh"`
	Drift         DriftWatcherConfig         `yaml:"drift"`
	Health        HealthWatcherConfig        `yaml:"health"`
	Network       NetworkWatcherConfig       `yaml:"network"`
	Connection    ConnectionWatcherConfig    `yaml:"connection"`
	EBPF          EBPFWatcherConfig          `yaml:"ebpf"`
	Logs          LogsWatcherConfig          `yaml:"logs"`
	Secrets       SecretsWatcherConfig       `yaml:"secrets"`
	Users         UsersWatcherConfig         `yaml:"users"`
	Packages      PackagesWatcherConfig      `yaml:"packages"`
	Services      ServicesWatcherConfig      `yaml:"services"`
	Firewall      FirewallWatcherConfig      `yaml:"firewall"`
	Vulnerability VulnerabilityWatcherConfig `yaml:"vulnerability"`
	Process       ProcessWatcherConfig       `yaml:"process"`
	Encryption    EncryptionWatcherConfig    `yaml:"encryption"`
	AccessReview  AccessReviewWatcherConfig  `yaml:"access_review"`
	ControlCheck  ControlCheckWatcherConfig  `yaml:"control_check"`
	Malware       MalwareWatcherConfig       `yaml:"malware"`
	Backup        BackupWatcherConfig        `yaml:"backup"`
	CloudProvider CloudProviderWatcherConfig `yaml:"cloud_provider"`
	Deployment    DeploymentWatcherConfig    `yaml:"deployment"`
}

// DockerWatcherConfig contains configuration for the Docker watcher.
type DockerWatcherConfig struct {
	Enabled bool   `yaml:"enabled"`
	Socket  string `yaml:"socket"`
}

// SSHWatcherConfig contains configuration for the SSH watcher.
type SSHWatcherConfig struct {
	Enabled bool   `yaml:"enabled"`
	LogPath string `yaml:"log_path"`
}

// DriftWatcherConfig contains configuration for the Drift watcher.
type DriftWatcherConfig struct {
	Enabled        bool     `yaml:"enabled"`
	WatchPaths     []string `yaml:"watch_paths"`
	IgnorePatterns []string `yaml:"ignore_patterns"`
}

// HealthWatcherConfig contains configuration for the Health watcher.
// Note: Interval is controlled by the control plane, not configurable locally.
type HealthWatcherConfig struct {
	Enabled bool `yaml:"enabled"`
}

// NetworkWatcherConfig contains configuration for the Network watcher.
type NetworkWatcherConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ScanInterval time.Duration `yaml:"scan_interval"`
}

// ConnectionWatcherConfig contains configuration for the Connection watcher (Embassies).
type ConnectionWatcherConfig struct {
	Enabled                bool          `yaml:"enabled"`
	ScanInterval           time.Duration `yaml:"scan_interval"`
	SnapshotInterval       time.Duration `yaml:"snapshot_interval"`
	IgnoreLocalConnections bool          `yaml:"ignore_local_connections"`
}

// EBPFWatcherConfig contains configuration for the eBPF connection tracer.
// This provides real-time connection tracking using kernel tracing, which is
// more accurate than polling-based connection watching for short-lived connections.
type EBPFWatcherConfig struct {
	Enabled bool `yaml:"enabled"`
}

// LogsWatcherConfig contains configuration for the Logs watcher.
type LogsWatcherConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ScanInterval time.Duration `yaml:"scan_interval"`
}

// SecretsWatcherConfig contains configuration for the Secrets watcher.
type SecretsWatcherConfig struct {
	Enabled        bool     `yaml:"enabled"`
	WatchPaths     []string `yaml:"watch_paths"`
	SecretPatterns []string `yaml:"secret_patterns"`
}

// UsersWatcherConfig contains configuration for the Users watcher (CC6.2).
type UsersWatcherConfig struct {
	Enabled    bool   `yaml:"enabled"`
	PasswdPath string `yaml:"passwd_path"`
	GroupPath  string `yaml:"group_path"`
	ShadowPath string `yaml:"shadow_path"`
}

// PackagesWatcherConfig contains configuration for the Packages watcher (CC8.1).
type PackagesWatcherConfig struct {
	Enabled     bool     `yaml:"enabled"`
	AptLogPaths []string `yaml:"apt_log_paths"`
	YumLogPaths []string `yaml:"yum_log_paths"`
}

// ServicesWatcherConfig contains configuration for the Services watcher (CC8.1).
type ServicesWatcherConfig struct {
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// FirewallWatcherConfig contains configuration for the Firewall watcher (CC6.6).
type FirewallWatcherConfig struct {
	Enabled          bool          `yaml:"enabled"`
	PollInterval     time.Duration `yaml:"poll_interval"`
	SnapshotInterval time.Duration `yaml:"snapshot_interval"`
}

// VulnerabilityWatcherConfig contains configuration for the Vulnerability watcher (CC7.1).
type VulnerabilityWatcherConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ScanInterval time.Duration `yaml:"scan_interval"`
	Scanner      string        `yaml:"scanner"` // trivy, grype, auto
	ScanTargets  []string      `yaml:"scan_targets"`
}

// ProcessWatcherConfig contains configuration for the Process watcher (CC7.2).
type ProcessWatcherConfig struct {
	Enabled            bool          `yaml:"enabled"`
	PollInterval       time.Duration `yaml:"poll_interval"`
	SuspiciousPatterns []string      `yaml:"suspicious_patterns"`
	WatchUsers         []string      `yaml:"watch_users"`
}

// EncryptionWatcherConfig contains configuration for the Encryption watcher (CC6.7).
type EncryptionWatcherConfig struct {
	Enabled           bool          `yaml:"enabled"`
	SnapshotInterval  time.Duration `yaml:"snapshot_interval"`
	CertPaths         []string      `yaml:"cert_paths"`
	ExpiryWarningDays int           `yaml:"expiry_warning_days"`
}

// AccessReviewWatcherConfig contains configuration for the Access Review watcher (CC6.2).
type AccessReviewWatcherConfig struct {
	Enabled          bool          `yaml:"enabled"`
	SnapshotInterval time.Duration `yaml:"snapshot_interval"`
	StaleAccountDays int           `yaml:"stale_account_days"`
}

// ControlCheckWatcherConfig contains configuration for the Control Check watcher (CC4.1).
type ControlCheckWatcherConfig struct {
	Enabled         bool          `yaml:"enabled"`
	CheckInterval   time.Duration `yaml:"check_interval"`
	EnabledControls []string      `yaml:"enabled_controls"`
}

// MalwareWatcherConfig contains configuration for the Malware watcher (CC6.8).
type MalwareWatcherConfig struct {
	Enabled          bool          `yaml:"enabled"`
	SnapshotInterval time.Duration `yaml:"snapshot_interval"`
	EnableClamAVScan bool          `yaml:"enable_clamav_scan"`
	ScanPaths        []string      `yaml:"scan_paths"`
}

// BackupWatcherConfig contains configuration for the Backup watcher (CC7.5).
type BackupWatcherConfig struct {
	Enabled          bool          `yaml:"enabled"`
	SnapshotInterval time.Duration `yaml:"snapshot_interval"`
	MaxBackupAge     time.Duration `yaml:"max_backup_age"`
	ResticRepoPath   string        `yaml:"restic_repo_path"`
	BorgRepoPath     string        `yaml:"borg_repo_path"`
}

// CloudProviderWatcherConfig contains configuration for the Cloud Provider watcher (CC6.4/CC6.5).
type CloudProviderWatcherConfig struct {
	Enabled       bool          `yaml:"enabled"`
	CheckInterval time.Duration `yaml:"check_interval"`
}

// DeploymentWatcherConfig contains configuration for the Deployment watcher (CC8.1).
type DeploymentWatcherConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MarkerDir    string        `yaml:"marker_dir"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// EmitterConfig contains configuration for the event emitter.
type EmitterConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	BufferPath    string        `yaml:"buffer_path"`
	MaxRetries    int           `yaml:"max_retries"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return cfg, nil
}

// LoadFromEnv loads configuration from environment variables.
// Environment variables override existing values.
func (c *Config) LoadFromEnv() {
	if v := os.Getenv("RAMPART_API_KEY"); v != "" {
		c.APIKey = v
	}
	if v := os.Getenv("RAMPART_FORTRESS_ID"); v != "" {
		c.FortressID = v
	}
	if v := os.Getenv("RAMPART_SERVER_ID"); v != "" {
		c.ServerID = v
	}
	if v := os.Getenv("RAMPART_SERVER_NAME"); v != "" {
		c.ServerName = v
	}
	if v := os.Getenv("RAMPART_CONTROL_PLANE"); v != "" {
		c.ControlPlane = v
	}
	if v := os.Getenv("RAMPART_BUFFER_PATH"); v != "" {
		c.Emitter.BufferPath = v
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.APIKey == "" {
		return fmt.Errorf("api_key is required")
	}
	if c.FortressID == "" {
		return fmt.Errorf("fortress_id is required")
	}
	if c.ControlPlane == "" {
		return fmt.Errorf("control_plane is required")
	}
	// Validate control plane URL
	u, err := url.Parse(c.ControlPlane)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("control_plane must be a valid URL")
	}
	return nil
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Watchers: WatchersConfig{
			Docker: DockerWatcherConfig{
				Enabled: true,
				Socket:  "/var/run/docker.sock",
			},
			SSH: SSHWatcherConfig{
				Enabled: true,
				LogPath: "/var/log/auth.log",
			},
			Drift: DriftWatcherConfig{
				Enabled: false,
			},
			Health: HealthWatcherConfig{
				Enabled: true,
			},
			Network: NetworkWatcherConfig{
				Enabled:      true,
				ScanInterval: 5 * time.Minute,
			},
			Connection: ConnectionWatcherConfig{
				Enabled:                true,
				ScanInterval:           1 * time.Minute,
				SnapshotInterval:       5 * time.Minute,
				IgnoreLocalConnections: false,
			},
			EBPF: EBPFWatcherConfig{
				Enabled: true, // Enabled by default if kernel supports it
			},
			Logs: LogsWatcherConfig{
				Enabled:      true,
				ScanInterval: time.Minute,
			},
			Secrets: SecretsWatcherConfig{
				Enabled: false,
			},
			Users: UsersWatcherConfig{
				Enabled:    true,
				PasswdPath: "/etc/passwd",
				GroupPath:  "/etc/group",
				ShadowPath: "/etc/shadow",
			},
			Packages: PackagesWatcherConfig{
				Enabled:     true,
				AptLogPaths: []string{"/var/log/apt/history.log", "/var/log/dpkg.log"},
				YumLogPaths: []string{"/var/log/yum.log", "/var/log/dnf.log"},
			},
			Services: ServicesWatcherConfig{
				Enabled:      true,
				PollInterval: 60 * time.Second,
			},
			Firewall: FirewallWatcherConfig{
				Enabled:          true,
				PollInterval:     5 * time.Minute,
				SnapshotInterval: 6 * time.Hour,
			},
			Vulnerability: VulnerabilityWatcherConfig{
				Enabled:      true,
				ScanInterval: 24 * time.Hour,
				Scanner:      "auto",
				ScanTargets:  []string{"/"},
			},
			Process: ProcessWatcherConfig{
				Enabled:      true,
				PollInterval: 5 * time.Second,
				SuspiciousPatterns: []string{
					`curl.*\|.*sh`,
					`wget.*\|.*sh`,
					`nc\s+-e`,
					`bash\s+-i`,
					`/tmp/.*\.(sh|py|pl)`,
					`xmrig|minerd|cryptonight`,
					`base64\s+-d.*\|.*sh`,
				},
			},
			Encryption: EncryptionWatcherConfig{
				Enabled:           true,
				SnapshotInterval:  6 * time.Hour,
				CertPaths:         []string{"/etc/ssl/certs", "/etc/pki/tls/certs"},
				ExpiryWarningDays: 30,
			},
			AccessReview: AccessReviewWatcherConfig{
				Enabled:          true,
				SnapshotInterval: 24 * time.Hour,
				StaleAccountDays: 90,
			},
			ControlCheck: ControlCheckWatcherConfig{
				Enabled:       true,
				CheckInterval: time.Hour,
			},
			Malware: MalwareWatcherConfig{
				Enabled:          true,
				SnapshotInterval: 6 * time.Hour,
				EnableClamAVScan: false,
				ScanPaths:        []string{"/tmp", "/var/tmp"},
			},
			Backup: BackupWatcherConfig{
				Enabled:          true,
				SnapshotInterval: time.Hour,
				MaxBackupAge:     24 * time.Hour,
			},
			CloudProvider: CloudProviderWatcherConfig{
				Enabled:       true,
				CheckInterval: 24 * time.Hour,
			},
			Deployment: DeploymentWatcherConfig{
				Enabled:      true,
				MarkerDir:    "/var/run/rampart/deployments",
				PollInterval: 5 * time.Second,
			},
		},
		Emitter: EmitterConfig{
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			BufferPath:    "/var/lib/rampart/buffer",
			MaxRetries:    3,
			RetryDelay:    time.Second,
		},
	}
}

// GenerateServerID generates a unique server ID.
func GenerateServerID() string {
	return "srv_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// MergeDefaults fills in missing values from the default config.
func (c *Config) MergeDefaults() {
	defaults := DefaultConfig()
	// Docker
	if c.Watchers.Docker.Socket == "" {
		c.Watchers.Docker.Socket = defaults.Watchers.Docker.Socket
	}
	// SSH
	if c.Watchers.SSH.LogPath == "" {
		c.Watchers.SSH.LogPath = defaults.Watchers.SSH.LogPath
	}
	// Health - interval is controlled by control plane, nothing to merge

	// Network
	if c.Watchers.Network.ScanInterval == 0 {
		c.Watchers.Network.ScanInterval = defaults.Watchers.Network.ScanInterval
	}
	// Connection
	if c.Watchers.Connection.ScanInterval == 0 {
		c.Watchers.Connection.ScanInterval = defaults.Watchers.Connection.ScanInterval
	}
	if c.Watchers.Connection.SnapshotInterval == 0 {
		c.Watchers.Connection.SnapshotInterval = defaults.Watchers.Connection.SnapshotInterval
	}
	// Logs
	if c.Watchers.Logs.ScanInterval == 0 {
		c.Watchers.Logs.ScanInterval = defaults.Watchers.Logs.ScanInterval
	}
	// Users
	if c.Watchers.Users.PasswdPath == "" {
		c.Watchers.Users.PasswdPath = defaults.Watchers.Users.PasswdPath
	}
	if c.Watchers.Users.GroupPath == "" {
		c.Watchers.Users.GroupPath = defaults.Watchers.Users.GroupPath
	}
	if c.Watchers.Users.ShadowPath == "" {
		c.Watchers.Users.ShadowPath = defaults.Watchers.Users.ShadowPath
	}
	// Packages
	if len(c.Watchers.Packages.AptLogPaths) == 0 {
		c.Watchers.Packages.AptLogPaths = defaults.Watchers.Packages.AptLogPaths
	}
	if len(c.Watchers.Packages.YumLogPaths) == 0 {
		c.Watchers.Packages.YumLogPaths = defaults.Watchers.Packages.YumLogPaths
	}
	// Services
	if c.Watchers.Services.PollInterval == 0 {
		c.Watchers.Services.PollInterval = defaults.Watchers.Services.PollInterval
	}
	// Firewall
	if c.Watchers.Firewall.PollInterval == 0 {
		c.Watchers.Firewall.PollInterval = defaults.Watchers.Firewall.PollInterval
	}
	if c.Watchers.Firewall.SnapshotInterval == 0 {
		c.Watchers.Firewall.SnapshotInterval = defaults.Watchers.Firewall.SnapshotInterval
	}
	// Vulnerability
	if c.Watchers.Vulnerability.ScanInterval == 0 {
		c.Watchers.Vulnerability.ScanInterval = defaults.Watchers.Vulnerability.ScanInterval
	}
	if c.Watchers.Vulnerability.Scanner == "" {
		c.Watchers.Vulnerability.Scanner = defaults.Watchers.Vulnerability.Scanner
	}
	if len(c.Watchers.Vulnerability.ScanTargets) == 0 {
		c.Watchers.Vulnerability.ScanTargets = defaults.Watchers.Vulnerability.ScanTargets
	}
	// Process
	if c.Watchers.Process.PollInterval == 0 {
		c.Watchers.Process.PollInterval = defaults.Watchers.Process.PollInterval
	}
	if len(c.Watchers.Process.SuspiciousPatterns) == 0 {
		c.Watchers.Process.SuspiciousPatterns = defaults.Watchers.Process.SuspiciousPatterns
	}
	// Encryption
	if c.Watchers.Encryption.SnapshotInterval == 0 {
		c.Watchers.Encryption.SnapshotInterval = defaults.Watchers.Encryption.SnapshotInterval
	}
	if len(c.Watchers.Encryption.CertPaths) == 0 {
		c.Watchers.Encryption.CertPaths = defaults.Watchers.Encryption.CertPaths
	}
	if c.Watchers.Encryption.ExpiryWarningDays == 0 {
		c.Watchers.Encryption.ExpiryWarningDays = defaults.Watchers.Encryption.ExpiryWarningDays
	}
	// AccessReview
	if c.Watchers.AccessReview.SnapshotInterval == 0 {
		c.Watchers.AccessReview.SnapshotInterval = defaults.Watchers.AccessReview.SnapshotInterval
	}
	if c.Watchers.AccessReview.StaleAccountDays == 0 {
		c.Watchers.AccessReview.StaleAccountDays = defaults.Watchers.AccessReview.StaleAccountDays
	}
	// ControlCheck
	if c.Watchers.ControlCheck.CheckInterval == 0 {
		c.Watchers.ControlCheck.CheckInterval = defaults.Watchers.ControlCheck.CheckInterval
	}
	// Deployment
	if c.Watchers.Deployment.MarkerDir == "" {
		c.Watchers.Deployment.MarkerDir = defaults.Watchers.Deployment.MarkerDir
	}
	if c.Watchers.Deployment.PollInterval == 0 {
		c.Watchers.Deployment.PollInterval = defaults.Watchers.Deployment.PollInterval
	}
	// Emitter
	if c.Emitter.BatchSize == 0 {
		c.Emitter.BatchSize = defaults.Emitter.BatchSize
	}
	if c.Emitter.FlushInterval == 0 {
		c.Emitter.FlushInterval = defaults.Emitter.FlushInterval
	}
	if c.Emitter.BufferPath == "" {
		c.Emitter.BufferPath = defaults.Emitter.BufferPath
	}
	if c.Emitter.MaxRetries == 0 {
		c.Emitter.MaxRetries = defaults.Emitter.MaxRetries
	}
	if c.Emitter.RetryDelay == 0 {
		c.Emitter.RetryDelay = defaults.Emitter.RetryDelay
	}
	// Server ID
	if c.ServerID == "" {
		c.ServerID = GenerateServerID()
	}
}
