package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")

	configYAML := `
api_key: "cl_live_test123"
fortress_id: "fort_abc123"
server_id: "srv_xyz789"
control_plane: "https://api.ramparthq.com"

watchers:
  docker:
    enabled: true
    socket: "/var/run/docker.sock"
  ssh:
    enabled: true
    log_path: "/var/log/auth.log"
  drift:
    enabled: true
    watch_paths:
      - /etc/nginx
      - /etc/ssl
    ignore_patterns:
      - "*.log"
      - "*.tmp"
  health:
    enabled: true
    interval: "30s"
  network:
    enabled: true
    scan_interval: "5m"

emitter:
  batch_size: 100
  flush_interval: "10s"
  buffer_path: "/var/lib/rampart/buffer"
  max_retries: 3
  retry_delay: "1s"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	// Verify core fields
	if cfg.APIKey != "cl_live_test123" {
		t.Errorf("APIKey = %v, want cl_live_test123", cfg.APIKey)
	}
	if cfg.FortressID != "fort_abc123" {
		t.Errorf("FortressID = %v, want fort_abc123", cfg.FortressID)
	}
	if cfg.ServerID != "srv_xyz789" {
		t.Errorf("ServerID = %v, want srv_xyz789", cfg.ServerID)
	}
	if cfg.ControlPlane != "https://api.ramparthq.com" {
		t.Errorf("ControlPlane = %v, want https://api.ramparthq.com", cfg.ControlPlane)
	}

	// Verify Docker watcher config
	if !cfg.Watchers.Docker.Enabled {
		t.Error("Docker watcher should be enabled")
	}
	if cfg.Watchers.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("Docker socket = %v, want /var/run/docker.sock", cfg.Watchers.Docker.Socket)
	}

	// Verify SSH watcher config
	if !cfg.Watchers.SSH.Enabled {
		t.Error("SSH watcher should be enabled")
	}
	if cfg.Watchers.SSH.LogPath != "/var/log/auth.log" {
		t.Errorf("SSH log path = %v, want /var/log/auth.log", cfg.Watchers.SSH.LogPath)
	}

	// Verify Drift watcher config
	if !cfg.Watchers.Drift.Enabled {
		t.Error("Drift watcher should be enabled")
	}
	if len(cfg.Watchers.Drift.WatchPaths) != 2 {
		t.Errorf("Drift watch paths = %d, want 2", len(cfg.Watchers.Drift.WatchPaths))
	}
	if len(cfg.Watchers.Drift.IgnorePatterns) != 2 {
		t.Errorf("Drift ignore patterns = %d, want 2", len(cfg.Watchers.Drift.IgnorePatterns))
	}

	// Verify Health watcher config
	if !cfg.Watchers.Health.Enabled {
		t.Error("Health watcher should be enabled")
	}

	// Verify Network watcher config
	if !cfg.Watchers.Network.Enabled {
		t.Error("Network watcher should be enabled")
	}
	if cfg.Watchers.Network.ScanInterval != 5*time.Minute {
		t.Errorf("Network scan interval = %v, want 5m", cfg.Watchers.Network.ScanInterval)
	}

	// Verify Emitter config
	if cfg.Emitter.BatchSize != 100 {
		t.Errorf("Emitter batch size = %v, want 100", cfg.Emitter.BatchSize)
	}
	if cfg.Emitter.FlushInterval != 10*time.Second {
		t.Errorf("Emitter flush interval = %v, want 10s", cfg.Emitter.FlushInterval)
	}
	if cfg.Emitter.BufferPath != "/var/lib/rampart/buffer" {
		t.Errorf("Emitter buffer path = %v, want /var/lib/rampart/buffer", cfg.Emitter.BufferPath)
	}
}

func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFromFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "invalid.yaml")

	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set environment variables
	t.Setenv("RAMPART_API_KEY", "cl_env_key123")
	t.Setenv("RAMPART_FORTRESS_ID", "fort_env123")
	t.Setenv("RAMPART_SERVER_ID", "srv_env456")
	t.Setenv("RAMPART_CONTROL_PLANE", "https://env.ramparthq.com")

	cfg := &Config{}
	cfg.LoadFromEnv()

	if cfg.APIKey != "cl_env_key123" {
		t.Errorf("APIKey = %v, want cl_env_key123", cfg.APIKey)
	}
	if cfg.FortressID != "fort_env123" {
		t.Errorf("FortressID = %v, want fort_env123", cfg.FortressID)
	}
	if cfg.ServerID != "srv_env456" {
		t.Errorf("ServerID = %v, want srv_env456", cfg.ServerID)
	}
	if cfg.ControlPlane != "https://env.ramparthq.com" {
		t.Errorf("ControlPlane = %v, want https://env.ramparthq.com", cfg.ControlPlane)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")

	configYAML := `
api_key: "file_key"
fortress_id: "file_fortress"
control_plane: "https://file.ramparthq.com"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set env vars (should override file)
	t.Setenv("RAMPART_API_KEY", "env_key")

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	cfg.LoadFromEnv()

	// API key should be from env
	if cfg.APIKey != "env_key" {
		t.Errorf("APIKey = %v, want env_key (from env)", cfg.APIKey)
	}

	// Fortress ID should be from file (no env override)
	if cfg.FortressID != "file_fortress" {
		t.Errorf("FortressID = %v, want file_fortress (from file)", cfg.FortressID)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "https://api.ramparthq.com",
			},
			wantErr: false,
		},
		{
			name: "missing API key",
			config: Config{
				FortressID:   "fort_123",
				ControlPlane: "https://api.ramparthq.com",
			},
			wantErr: true,
		},
		{
			name: "missing fortress ID",
			config: Config{
				APIKey:       "cl_test_key",
				ControlPlane: "https://api.ramparthq.com",
			},
			wantErr: true,
		},
		{
			name: "missing control plane",
			config: Config{
				APIKey:     "cl_test_key",
				FortressID: "fort_123",
			},
			wantErr: true,
		},
		{
			name: "invalid control plane URL",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "not-a-url",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Check default values
	if cfg.Watchers.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("default Docker socket = %v, want /var/run/docker.sock", cfg.Watchers.Docker.Socket)
	}
	if cfg.Watchers.SSH.LogPath != "/var/log/auth.log" {
		t.Errorf("default SSH log path = %v, want /var/log/auth.log", cfg.Watchers.SSH.LogPath)
	}
	if cfg.Watchers.Network.ScanInterval != 5*time.Minute {
		t.Errorf("default Network scan interval = %v, want 5m", cfg.Watchers.Network.ScanInterval)
	}
	if cfg.Emitter.BatchSize != 100 {
		t.Errorf("default Emitter batch size = %v, want 100", cfg.Emitter.BatchSize)
	}
	if cfg.Emitter.FlushInterval != 10*time.Second {
		t.Errorf("default Emitter flush interval = %v, want 10s", cfg.Emitter.FlushInterval)
	}
}

func TestGenerateServerID(t *testing.T) {
	id := GenerateServerID()

	// Should start with srv_
	if len(id) < 4 || id[:4] != "srv_" {
		t.Errorf("ServerID = %v, should start with srv_", id)
	}

	// Should be unique
	id2 := GenerateServerID()
	if id == id2 {
		t.Error("GenerateServerID should generate unique IDs")
	}
}

func TestMergeDefaults(t *testing.T) {
	t.Run("merges all empty values from defaults", func(t *testing.T) {
		cfg := &Config{}
		cfg.MergeDefaults()
		defaults := DefaultConfig()

		// Docker
		if cfg.Watchers.Docker.Socket != defaults.Watchers.Docker.Socket {
			t.Errorf("Docker socket = %v, want %v", cfg.Watchers.Docker.Socket, defaults.Watchers.Docker.Socket)
		}

		// SSH
		if cfg.Watchers.SSH.LogPath != defaults.Watchers.SSH.LogPath {
			t.Errorf("SSH log path = %v, want %v", cfg.Watchers.SSH.LogPath, defaults.Watchers.SSH.LogPath)
		}

		// Network
		if cfg.Watchers.Network.ScanInterval != defaults.Watchers.Network.ScanInterval {
			t.Errorf("Network scan interval = %v, want %v", cfg.Watchers.Network.ScanInterval, defaults.Watchers.Network.ScanInterval)
		}

		// Connection
		if cfg.Watchers.Connection.ScanInterval != defaults.Watchers.Connection.ScanInterval {
			t.Errorf("Connection scan interval = %v, want %v", cfg.Watchers.Connection.ScanInterval, defaults.Watchers.Connection.ScanInterval)
		}
		if cfg.Watchers.Connection.SnapshotInterval != defaults.Watchers.Connection.SnapshotInterval {
			t.Errorf("Connection snapshot interval = %v, want %v", cfg.Watchers.Connection.SnapshotInterval, defaults.Watchers.Connection.SnapshotInterval)
		}

		// Logs
		if cfg.Watchers.Logs.ScanInterval != defaults.Watchers.Logs.ScanInterval {
			t.Errorf("Logs scan interval = %v, want %v", cfg.Watchers.Logs.ScanInterval, defaults.Watchers.Logs.ScanInterval)
		}

		// Users
		if cfg.Watchers.Users.PasswdPath != defaults.Watchers.Users.PasswdPath {
			t.Errorf("Users passwd path = %v, want %v", cfg.Watchers.Users.PasswdPath, defaults.Watchers.Users.PasswdPath)
		}
		if cfg.Watchers.Users.GroupPath != defaults.Watchers.Users.GroupPath {
			t.Errorf("Users group path = %v, want %v", cfg.Watchers.Users.GroupPath, defaults.Watchers.Users.GroupPath)
		}
		if cfg.Watchers.Users.ShadowPath != defaults.Watchers.Users.ShadowPath {
			t.Errorf("Users shadow path = %v, want %v", cfg.Watchers.Users.ShadowPath, defaults.Watchers.Users.ShadowPath)
		}

		// Packages
		if len(cfg.Watchers.Packages.AptLogPaths) != len(defaults.Watchers.Packages.AptLogPaths) {
			t.Errorf("Packages apt log paths = %v, want %v", cfg.Watchers.Packages.AptLogPaths, defaults.Watchers.Packages.AptLogPaths)
		}
		if len(cfg.Watchers.Packages.YumLogPaths) != len(defaults.Watchers.Packages.YumLogPaths) {
			t.Errorf("Packages yum log paths = %v, want %v", cfg.Watchers.Packages.YumLogPaths, defaults.Watchers.Packages.YumLogPaths)
		}

		// Services
		if cfg.Watchers.Services.PollInterval != defaults.Watchers.Services.PollInterval {
			t.Errorf("Services poll interval = %v, want %v", cfg.Watchers.Services.PollInterval, defaults.Watchers.Services.PollInterval)
		}

		// Firewall
		if cfg.Watchers.Firewall.PollInterval != defaults.Watchers.Firewall.PollInterval {
			t.Errorf("Firewall poll interval = %v, want %v", cfg.Watchers.Firewall.PollInterval, defaults.Watchers.Firewall.PollInterval)
		}
		if cfg.Watchers.Firewall.SnapshotInterval != defaults.Watchers.Firewall.SnapshotInterval {
			t.Errorf("Firewall snapshot interval = %v, want %v", cfg.Watchers.Firewall.SnapshotInterval, defaults.Watchers.Firewall.SnapshotInterval)
		}

		// Vulnerability
		if cfg.Watchers.Vulnerability.ScanInterval != defaults.Watchers.Vulnerability.ScanInterval {
			t.Errorf("Vulnerability scan interval = %v, want %v", cfg.Watchers.Vulnerability.ScanInterval, defaults.Watchers.Vulnerability.ScanInterval)
		}
		if cfg.Watchers.Vulnerability.Scanner != defaults.Watchers.Vulnerability.Scanner {
			t.Errorf("Vulnerability scanner = %v, want %v", cfg.Watchers.Vulnerability.Scanner, defaults.Watchers.Vulnerability.Scanner)
		}
		if len(cfg.Watchers.Vulnerability.ScanTargets) != len(defaults.Watchers.Vulnerability.ScanTargets) {
			t.Errorf("Vulnerability scan targets = %v, want %v", cfg.Watchers.Vulnerability.ScanTargets, defaults.Watchers.Vulnerability.ScanTargets)
		}

		// Process
		if cfg.Watchers.Process.PollInterval != defaults.Watchers.Process.PollInterval {
			t.Errorf("Process poll interval = %v, want %v", cfg.Watchers.Process.PollInterval, defaults.Watchers.Process.PollInterval)
		}
		if len(cfg.Watchers.Process.SuspiciousPatterns) != len(defaults.Watchers.Process.SuspiciousPatterns) {
			t.Errorf("Process suspicious patterns = %v, want %v", cfg.Watchers.Process.SuspiciousPatterns, defaults.Watchers.Process.SuspiciousPatterns)
		}

		// Encryption
		if cfg.Watchers.Encryption.SnapshotInterval != defaults.Watchers.Encryption.SnapshotInterval {
			t.Errorf("Encryption snapshot interval = %v, want %v", cfg.Watchers.Encryption.SnapshotInterval, defaults.Watchers.Encryption.SnapshotInterval)
		}
		if len(cfg.Watchers.Encryption.CertPaths) != len(defaults.Watchers.Encryption.CertPaths) {
			t.Errorf("Encryption cert paths = %v, want %v", cfg.Watchers.Encryption.CertPaths, defaults.Watchers.Encryption.CertPaths)
		}
		if cfg.Watchers.Encryption.ExpiryWarningDays != defaults.Watchers.Encryption.ExpiryWarningDays {
			t.Errorf("Encryption expiry warning days = %v, want %v", cfg.Watchers.Encryption.ExpiryWarningDays, defaults.Watchers.Encryption.ExpiryWarningDays)
		}

		// AccessReview
		if cfg.Watchers.AccessReview.SnapshotInterval != defaults.Watchers.AccessReview.SnapshotInterval {
			t.Errorf("AccessReview snapshot interval = %v, want %v", cfg.Watchers.AccessReview.SnapshotInterval, defaults.Watchers.AccessReview.SnapshotInterval)
		}
		if cfg.Watchers.AccessReview.StaleAccountDays != defaults.Watchers.AccessReview.StaleAccountDays {
			t.Errorf("AccessReview stale account days = %v, want %v", cfg.Watchers.AccessReview.StaleAccountDays, defaults.Watchers.AccessReview.StaleAccountDays)
		}

		// ControlCheck
		if cfg.Watchers.ControlCheck.CheckInterval != defaults.Watchers.ControlCheck.CheckInterval {
			t.Errorf("ControlCheck check interval = %v, want %v", cfg.Watchers.ControlCheck.CheckInterval, defaults.Watchers.ControlCheck.CheckInterval)
		}

		// Deployment
		if cfg.Watchers.Deployment.MarkerDir != defaults.Watchers.Deployment.MarkerDir {
			t.Errorf("Deployment marker dir = %v, want %v", cfg.Watchers.Deployment.MarkerDir, defaults.Watchers.Deployment.MarkerDir)
		}
		if cfg.Watchers.Deployment.PollInterval != defaults.Watchers.Deployment.PollInterval {
			t.Errorf("Deployment poll interval = %v, want %v", cfg.Watchers.Deployment.PollInterval, defaults.Watchers.Deployment.PollInterval)
		}

		// Emitter
		if cfg.Emitter.BatchSize != defaults.Emitter.BatchSize {
			t.Errorf("Emitter batch size = %v, want %v", cfg.Emitter.BatchSize, defaults.Emitter.BatchSize)
		}
		if cfg.Emitter.FlushInterval != defaults.Emitter.FlushInterval {
			t.Errorf("Emitter flush interval = %v, want %v", cfg.Emitter.FlushInterval, defaults.Emitter.FlushInterval)
		}
		if cfg.Emitter.BufferPath != defaults.Emitter.BufferPath {
			t.Errorf("Emitter buffer path = %v, want %v", cfg.Emitter.BufferPath, defaults.Emitter.BufferPath)
		}
		if cfg.Emitter.MaxRetries != defaults.Emitter.MaxRetries {
			t.Errorf("Emitter max retries = %v, want %v", cfg.Emitter.MaxRetries, defaults.Emitter.MaxRetries)
		}
		if cfg.Emitter.RetryDelay != defaults.Emitter.RetryDelay {
			t.Errorf("Emitter retry delay = %v, want %v", cfg.Emitter.RetryDelay, defaults.Emitter.RetryDelay)
		}

		// ServerID should be auto-generated
		if cfg.ServerID == "" {
			t.Error("ServerID should be auto-generated")
		}
		if len(cfg.ServerID) < 4 || cfg.ServerID[:4] != "srv_" {
			t.Errorf("ServerID = %v, should start with srv_", cfg.ServerID)
		}
	})

	t.Run("preserves existing values", func(t *testing.T) {
		cfg := &Config{
			ServerID: "srv_existing123",
			Watchers: WatchersConfig{
				Docker: DockerWatcherConfig{
					Socket: "/custom/docker.sock",
				},
				SSH: SSHWatcherConfig{
					LogPath: "/custom/auth.log",
				},
				Network: NetworkWatcherConfig{
					ScanInterval: 10 * time.Minute,
				},
				Connection: ConnectionWatcherConfig{
					ScanInterval:     2 * time.Minute,
					SnapshotInterval: 10 * time.Minute,
				},
				Logs: LogsWatcherConfig{
					ScanInterval: 2 * time.Minute,
				},
				Users: UsersWatcherConfig{
					PasswdPath: "/custom/passwd",
					GroupPath:  "/custom/group",
					ShadowPath: "/custom/shadow",
				},
				Packages: PackagesWatcherConfig{
					AptLogPaths: []string{"/custom/apt.log"},
					YumLogPaths: []string{"/custom/yum.log"},
				},
				Services: ServicesWatcherConfig{
					PollInterval: 30 * time.Second,
				},
				Firewall: FirewallWatcherConfig{
					PollInterval:     10 * time.Minute,
					SnapshotInterval: 12 * time.Hour,
				},
				Vulnerability: VulnerabilityWatcherConfig{
					ScanInterval: 12 * time.Hour,
					Scanner:      "trivy",
					ScanTargets:  []string{"/opt"},
				},
				Process: ProcessWatcherConfig{
					PollInterval:       10 * time.Second,
					SuspiciousPatterns: []string{"custom_pattern"},
				},
				Encryption: EncryptionWatcherConfig{
					SnapshotInterval:  12 * time.Hour,
					CertPaths:         []string{"/custom/certs"},
					ExpiryWarningDays: 60,
				},
				AccessReview: AccessReviewWatcherConfig{
					SnapshotInterval: 48 * time.Hour,
					StaleAccountDays: 180,
				},
				ControlCheck: ControlCheckWatcherConfig{
					CheckInterval: 2 * time.Hour,
				},
				Deployment: DeploymentWatcherConfig{
					MarkerDir:    "/custom/deployments",
					PollInterval: 10 * time.Second,
				},
			},
			Emitter: EmitterConfig{
				BatchSize:     200,
				FlushInterval: 20 * time.Second,
				BufferPath:    "/custom/buffer",
				MaxRetries:    5,
				RetryDelay:    2 * time.Second,
			},
		}

		cfg.MergeDefaults()

		// Verify existing values are preserved
		if cfg.ServerID != "srv_existing123" {
			t.Errorf("ServerID = %v, want srv_existing123", cfg.ServerID)
		}
		if cfg.Watchers.Docker.Socket != "/custom/docker.sock" {
			t.Errorf("Docker socket = %v, want /custom/docker.sock", cfg.Watchers.Docker.Socket)
		}
		if cfg.Watchers.SSH.LogPath != "/custom/auth.log" {
			t.Errorf("SSH log path = %v, want /custom/auth.log", cfg.Watchers.SSH.LogPath)
		}
		if cfg.Watchers.Network.ScanInterval != 10*time.Minute {
			t.Errorf("Network scan interval = %v, want 10m", cfg.Watchers.Network.ScanInterval)
		}
		if cfg.Watchers.Connection.ScanInterval != 2*time.Minute {
			t.Errorf("Connection scan interval = %v, want 2m", cfg.Watchers.Connection.ScanInterval)
		}
		if cfg.Watchers.Connection.SnapshotInterval != 10*time.Minute {
			t.Errorf("Connection snapshot interval = %v, want 10m", cfg.Watchers.Connection.SnapshotInterval)
		}
		if cfg.Watchers.Logs.ScanInterval != 2*time.Minute {
			t.Errorf("Logs scan interval = %v, want 2m", cfg.Watchers.Logs.ScanInterval)
		}
		if cfg.Watchers.Users.PasswdPath != "/custom/passwd" {
			t.Errorf("Users passwd path = %v, want /custom/passwd", cfg.Watchers.Users.PasswdPath)
		}
		if cfg.Watchers.Users.GroupPath != "/custom/group" {
			t.Errorf("Users group path = %v, want /custom/group", cfg.Watchers.Users.GroupPath)
		}
		if cfg.Watchers.Users.ShadowPath != "/custom/shadow" {
			t.Errorf("Users shadow path = %v, want /custom/shadow", cfg.Watchers.Users.ShadowPath)
		}
		if len(cfg.Watchers.Packages.AptLogPaths) != 1 || cfg.Watchers.Packages.AptLogPaths[0] != "/custom/apt.log" {
			t.Errorf("Packages apt log paths = %v, want [/custom/apt.log]", cfg.Watchers.Packages.AptLogPaths)
		}
		if len(cfg.Watchers.Packages.YumLogPaths) != 1 || cfg.Watchers.Packages.YumLogPaths[0] != "/custom/yum.log" {
			t.Errorf("Packages yum log paths = %v, want [/custom/yum.log]", cfg.Watchers.Packages.YumLogPaths)
		}
		if cfg.Watchers.Services.PollInterval != 30*time.Second {
			t.Errorf("Services poll interval = %v, want 30s", cfg.Watchers.Services.PollInterval)
		}
		if cfg.Watchers.Firewall.PollInterval != 10*time.Minute {
			t.Errorf("Firewall poll interval = %v, want 10m", cfg.Watchers.Firewall.PollInterval)
		}
		if cfg.Watchers.Firewall.SnapshotInterval != 12*time.Hour {
			t.Errorf("Firewall snapshot interval = %v, want 12h", cfg.Watchers.Firewall.SnapshotInterval)
		}
		if cfg.Watchers.Vulnerability.ScanInterval != 12*time.Hour {
			t.Errorf("Vulnerability scan interval = %v, want 12h", cfg.Watchers.Vulnerability.ScanInterval)
		}
		if cfg.Watchers.Vulnerability.Scanner != "trivy" {
			t.Errorf("Vulnerability scanner = %v, want trivy", cfg.Watchers.Vulnerability.Scanner)
		}
		if len(cfg.Watchers.Vulnerability.ScanTargets) != 1 || cfg.Watchers.Vulnerability.ScanTargets[0] != "/opt" {
			t.Errorf("Vulnerability scan targets = %v, want [/opt]", cfg.Watchers.Vulnerability.ScanTargets)
		}
		if cfg.Watchers.Process.PollInterval != 10*time.Second {
			t.Errorf("Process poll interval = %v, want 10s", cfg.Watchers.Process.PollInterval)
		}
		if len(cfg.Watchers.Process.SuspiciousPatterns) != 1 || cfg.Watchers.Process.SuspiciousPatterns[0] != "custom_pattern" {
			t.Errorf("Process suspicious patterns = %v, want [custom_pattern]", cfg.Watchers.Process.SuspiciousPatterns)
		}
		if cfg.Watchers.Encryption.SnapshotInterval != 12*time.Hour {
			t.Errorf("Encryption snapshot interval = %v, want 12h", cfg.Watchers.Encryption.SnapshotInterval)
		}
		if len(cfg.Watchers.Encryption.CertPaths) != 1 || cfg.Watchers.Encryption.CertPaths[0] != "/custom/certs" {
			t.Errorf("Encryption cert paths = %v, want [/custom/certs]", cfg.Watchers.Encryption.CertPaths)
		}
		if cfg.Watchers.Encryption.ExpiryWarningDays != 60 {
			t.Errorf("Encryption expiry warning days = %v, want 60", cfg.Watchers.Encryption.ExpiryWarningDays)
		}
		if cfg.Watchers.AccessReview.SnapshotInterval != 48*time.Hour {
			t.Errorf("AccessReview snapshot interval = %v, want 48h", cfg.Watchers.AccessReview.SnapshotInterval)
		}
		if cfg.Watchers.AccessReview.StaleAccountDays != 180 {
			t.Errorf("AccessReview stale account days = %v, want 180", cfg.Watchers.AccessReview.StaleAccountDays)
		}
		if cfg.Watchers.ControlCheck.CheckInterval != 2*time.Hour {
			t.Errorf("ControlCheck check interval = %v, want 2h", cfg.Watchers.ControlCheck.CheckInterval)
		}
		if cfg.Watchers.Deployment.MarkerDir != "/custom/deployments" {
			t.Errorf("Deployment marker dir = %v, want /custom/deployments", cfg.Watchers.Deployment.MarkerDir)
		}
		if cfg.Watchers.Deployment.PollInterval != 10*time.Second {
			t.Errorf("Deployment poll interval = %v, want 10s", cfg.Watchers.Deployment.PollInterval)
		}
		if cfg.Emitter.BatchSize != 200 {
			t.Errorf("Emitter batch size = %v, want 200", cfg.Emitter.BatchSize)
		}
		if cfg.Emitter.FlushInterval != 20*time.Second {
			t.Errorf("Emitter flush interval = %v, want 20s", cfg.Emitter.FlushInterval)
		}
		if cfg.Emitter.BufferPath != "/custom/buffer" {
			t.Errorf("Emitter buffer path = %v, want /custom/buffer", cfg.Emitter.BufferPath)
		}
		if cfg.Emitter.MaxRetries != 5 {
			t.Errorf("Emitter max retries = %v, want 5", cfg.Emitter.MaxRetries)
		}
		if cfg.Emitter.RetryDelay != 2*time.Second {
			t.Errorf("Emitter retry delay = %v, want 2s", cfg.Emitter.RetryDelay)
		}
	})
}

func TestLoadFromEnv_AllVariables(t *testing.T) {
	t.Run("loads server name from env", func(t *testing.T) {
		t.Setenv("RAMPART_SERVER_NAME", "my-test-server")

		cfg := &Config{}
		cfg.LoadFromEnv()

		if cfg.ServerName != "my-test-server" {
			t.Errorf("ServerName = %v, want my-test-server", cfg.ServerName)
		}
	})

	t.Run("loads buffer path from env", func(t *testing.T) {
		t.Setenv("RAMPART_BUFFER_PATH", "/custom/buffer/path")

		cfg := &Config{}
		cfg.LoadFromEnv()

		if cfg.Emitter.BufferPath != "/custom/buffer/path" {
			t.Errorf("Emitter.BufferPath = %v, want /custom/buffer/path", cfg.Emitter.BufferPath)
		}
	})

	t.Run("does not override when env is empty", func(t *testing.T) {
		cfg := &Config{
			APIKey:     "original_key",
			FortressID: "original_fortress",
			ServerID:   "original_server",
			ServerName: "original_name",
			ControlPlane: "https://original.ramparthq.com",
			Emitter: EmitterConfig{
				BufferPath: "/original/buffer",
			},
		}

		cfg.LoadFromEnv()

		if cfg.APIKey != "original_key" {
			t.Errorf("APIKey = %v, want original_key", cfg.APIKey)
		}
		if cfg.FortressID != "original_fortress" {
			t.Errorf("FortressID = %v, want original_fortress", cfg.FortressID)
		}
		if cfg.ServerID != "original_server" {
			t.Errorf("ServerID = %v, want original_server", cfg.ServerID)
		}
		if cfg.ServerName != "original_name" {
			t.Errorf("ServerName = %v, want original_name", cfg.ServerName)
		}
		if cfg.ControlPlane != "https://original.ramparthq.com" {
			t.Errorf("ControlPlane = %v, want https://original.ramparthq.com", cfg.ControlPlane)
		}
		if cfg.Emitter.BufferPath != "/original/buffer" {
			t.Errorf("Emitter.BufferPath = %v, want /original/buffer", cfg.Emitter.BufferPath)
		}
	})
}

func TestValidate_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "URL with no scheme",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "api.ramparthq.com",
			},
			wantErr: true,
			errMsg:  "control_plane must be a valid URL",
		},
		{
			name: "URL with no host",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "https://",
			},
			wantErr: true,
			errMsg:  "control_plane must be a valid URL",
		},
		{
			name: "HTTP URL is valid",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "http://api.ramparthq.com",
			},
			wantErr: false,
		},
		{
			name: "URL with port is valid",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "https://api.ramparthq.com:8443",
			},
			wantErr: false,
		},
		{
			name: "URL with path is valid",
			config: Config{
				APIKey:       "cl_test_key",
				FortressID:   "fort_123",
				ControlPlane: "https://api.ramparthq.com/v1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if err.Error() != tt.errMsg {
					t.Errorf("Validate() error message = %v, want %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestDefaultConfig_AllValues(t *testing.T) {
	cfg := DefaultConfig()

	// Docker
	if !cfg.Watchers.Docker.Enabled {
		t.Error("Docker watcher should be enabled by default")
	}
	if cfg.Watchers.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("Docker socket = %v, want /var/run/docker.sock", cfg.Watchers.Docker.Socket)
	}

	// SSH
	if !cfg.Watchers.SSH.Enabled {
		t.Error("SSH watcher should be enabled by default")
	}
	if cfg.Watchers.SSH.LogPath != "/var/log/auth.log" {
		t.Errorf("SSH log path = %v, want /var/log/auth.log", cfg.Watchers.SSH.LogPath)
	}

	// Drift
	if cfg.Watchers.Drift.Enabled {
		t.Error("Drift watcher should be disabled by default")
	}

	// Health
	if !cfg.Watchers.Health.Enabled {
		t.Error("Health watcher should be enabled by default")
	}

	// Network
	if !cfg.Watchers.Network.Enabled {
		t.Error("Network watcher should be enabled by default")
	}
	if cfg.Watchers.Network.ScanInterval != 5*time.Minute {
		t.Errorf("Network scan interval = %v, want 5m", cfg.Watchers.Network.ScanInterval)
	}

	// Connection
	if !cfg.Watchers.Connection.Enabled {
		t.Error("Connection watcher should be enabled by default")
	}
	if cfg.Watchers.Connection.ScanInterval != 1*time.Minute {
		t.Errorf("Connection scan interval = %v, want 1m", cfg.Watchers.Connection.ScanInterval)
	}
	if cfg.Watchers.Connection.SnapshotInterval != 5*time.Minute {
		t.Errorf("Connection snapshot interval = %v, want 5m", cfg.Watchers.Connection.SnapshotInterval)
	}
	if cfg.Watchers.Connection.IgnoreLocalConnections {
		t.Error("Connection IgnoreLocalConnections should be false by default")
	}

	// EBPF
	if !cfg.Watchers.EBPF.Enabled {
		t.Error("EBPF watcher should be enabled by default")
	}

	// Logs
	if !cfg.Watchers.Logs.Enabled {
		t.Error("Logs watcher should be enabled by default")
	}
	if cfg.Watchers.Logs.ScanInterval != time.Minute {
		t.Errorf("Logs scan interval = %v, want 1m", cfg.Watchers.Logs.ScanInterval)
	}

	// Secrets
	if cfg.Watchers.Secrets.Enabled {
		t.Error("Secrets watcher should be disabled by default")
	}

	// Users
	if !cfg.Watchers.Users.Enabled {
		t.Error("Users watcher should be enabled by default")
	}
	if cfg.Watchers.Users.PasswdPath != "/etc/passwd" {
		t.Errorf("Users passwd path = %v, want /etc/passwd", cfg.Watchers.Users.PasswdPath)
	}
	if cfg.Watchers.Users.GroupPath != "/etc/group" {
		t.Errorf("Users group path = %v, want /etc/group", cfg.Watchers.Users.GroupPath)
	}
	if cfg.Watchers.Users.ShadowPath != "/etc/shadow" {
		t.Errorf("Users shadow path = %v, want /etc/shadow", cfg.Watchers.Users.ShadowPath)
	}

	// Packages
	if !cfg.Watchers.Packages.Enabled {
		t.Error("Packages watcher should be enabled by default")
	}
	expectedAptPaths := []string{"/var/log/apt/history.log", "/var/log/dpkg.log"}
	if len(cfg.Watchers.Packages.AptLogPaths) != len(expectedAptPaths) {
		t.Errorf("Packages apt log paths = %v, want %v", cfg.Watchers.Packages.AptLogPaths, expectedAptPaths)
	}
	expectedYumPaths := []string{"/var/log/yum.log", "/var/log/dnf.log"}
	if len(cfg.Watchers.Packages.YumLogPaths) != len(expectedYumPaths) {
		t.Errorf("Packages yum log paths = %v, want %v", cfg.Watchers.Packages.YumLogPaths, expectedYumPaths)
	}

	// Services
	if !cfg.Watchers.Services.Enabled {
		t.Error("Services watcher should be enabled by default")
	}
	if cfg.Watchers.Services.PollInterval != 60*time.Second {
		t.Errorf("Services poll interval = %v, want 60s", cfg.Watchers.Services.PollInterval)
	}

	// Firewall
	if !cfg.Watchers.Firewall.Enabled {
		t.Error("Firewall watcher should be enabled by default")
	}
	if cfg.Watchers.Firewall.PollInterval != 5*time.Minute {
		t.Errorf("Firewall poll interval = %v, want 5m", cfg.Watchers.Firewall.PollInterval)
	}
	if cfg.Watchers.Firewall.SnapshotInterval != 6*time.Hour {
		t.Errorf("Firewall snapshot interval = %v, want 6h", cfg.Watchers.Firewall.SnapshotInterval)
	}

	// Vulnerability
	if !cfg.Watchers.Vulnerability.Enabled {
		t.Error("Vulnerability watcher should be enabled by default")
	}
	if cfg.Watchers.Vulnerability.ScanInterval != 24*time.Hour {
		t.Errorf("Vulnerability scan interval = %v, want 24h", cfg.Watchers.Vulnerability.ScanInterval)
	}
	if cfg.Watchers.Vulnerability.Scanner != "auto" {
		t.Errorf("Vulnerability scanner = %v, want auto", cfg.Watchers.Vulnerability.Scanner)
	}
	if len(cfg.Watchers.Vulnerability.ScanTargets) != 1 || cfg.Watchers.Vulnerability.ScanTargets[0] != "/" {
		t.Errorf("Vulnerability scan targets = %v, want [/]", cfg.Watchers.Vulnerability.ScanTargets)
	}

	// Process
	if !cfg.Watchers.Process.Enabled {
		t.Error("Process watcher should be enabled by default")
	}
	if cfg.Watchers.Process.PollInterval != 5*time.Second {
		t.Errorf("Process poll interval = %v, want 5s", cfg.Watchers.Process.PollInterval)
	}
	if len(cfg.Watchers.Process.SuspiciousPatterns) != 7 {
		t.Errorf("Process suspicious patterns count = %v, want 7", len(cfg.Watchers.Process.SuspiciousPatterns))
	}

	// Encryption
	if !cfg.Watchers.Encryption.Enabled {
		t.Error("Encryption watcher should be enabled by default")
	}
	if cfg.Watchers.Encryption.SnapshotInterval != 6*time.Hour {
		t.Errorf("Encryption snapshot interval = %v, want 6h", cfg.Watchers.Encryption.SnapshotInterval)
	}
	if len(cfg.Watchers.Encryption.CertPaths) != 2 {
		t.Errorf("Encryption cert paths count = %v, want 2", len(cfg.Watchers.Encryption.CertPaths))
	}
	if cfg.Watchers.Encryption.ExpiryWarningDays != 30 {
		t.Errorf("Encryption expiry warning days = %v, want 30", cfg.Watchers.Encryption.ExpiryWarningDays)
	}

	// AccessReview
	if !cfg.Watchers.AccessReview.Enabled {
		t.Error("AccessReview watcher should be enabled by default")
	}
	if cfg.Watchers.AccessReview.SnapshotInterval != 24*time.Hour {
		t.Errorf("AccessReview snapshot interval = %v, want 24h", cfg.Watchers.AccessReview.SnapshotInterval)
	}
	if cfg.Watchers.AccessReview.StaleAccountDays != 90 {
		t.Errorf("AccessReview stale account days = %v, want 90", cfg.Watchers.AccessReview.StaleAccountDays)
	}

	// ControlCheck
	if !cfg.Watchers.ControlCheck.Enabled {
		t.Error("ControlCheck watcher should be enabled by default")
	}
	if cfg.Watchers.ControlCheck.CheckInterval != time.Hour {
		t.Errorf("ControlCheck check interval = %v, want 1h", cfg.Watchers.ControlCheck.CheckInterval)
	}

	// Malware
	if !cfg.Watchers.Malware.Enabled {
		t.Error("Malware watcher should be enabled by default")
	}
	if cfg.Watchers.Malware.SnapshotInterval != 6*time.Hour {
		t.Errorf("Malware snapshot interval = %v, want 6h", cfg.Watchers.Malware.SnapshotInterval)
	}
	if cfg.Watchers.Malware.EnableClamAVScan {
		t.Error("Malware EnableClamAVScan should be false by default")
	}
	if len(cfg.Watchers.Malware.ScanPaths) != 2 {
		t.Errorf("Malware scan paths count = %v, want 2", len(cfg.Watchers.Malware.ScanPaths))
	}

	// Backup
	if !cfg.Watchers.Backup.Enabled {
		t.Error("Backup watcher should be enabled by default")
	}
	if cfg.Watchers.Backup.SnapshotInterval != time.Hour {
		t.Errorf("Backup snapshot interval = %v, want 1h", cfg.Watchers.Backup.SnapshotInterval)
	}
	if cfg.Watchers.Backup.MaxBackupAge != 24*time.Hour {
		t.Errorf("Backup max backup age = %v, want 24h", cfg.Watchers.Backup.MaxBackupAge)
	}

	// CloudProvider
	if !cfg.Watchers.CloudProvider.Enabled {
		t.Error("CloudProvider watcher should be enabled by default")
	}
	if cfg.Watchers.CloudProvider.CheckInterval != 24*time.Hour {
		t.Errorf("CloudProvider check interval = %v, want 24h", cfg.Watchers.CloudProvider.CheckInterval)
	}

	// Deployment
	if !cfg.Watchers.Deployment.Enabled {
		t.Error("Deployment watcher should be enabled by default")
	}
	if cfg.Watchers.Deployment.MarkerDir != "/var/run/rampart/deployments" {
		t.Errorf("Deployment marker dir = %v, want /var/run/rampart/deployments", cfg.Watchers.Deployment.MarkerDir)
	}
	if cfg.Watchers.Deployment.PollInterval != 5*time.Second {
		t.Errorf("Deployment poll interval = %v, want 5s", cfg.Watchers.Deployment.PollInterval)
	}

	// Emitter
	if cfg.Emitter.BatchSize != 100 {
		t.Errorf("Emitter batch size = %v, want 100", cfg.Emitter.BatchSize)
	}
	if cfg.Emitter.FlushInterval != 10*time.Second {
		t.Errorf("Emitter flush interval = %v, want 10s", cfg.Emitter.FlushInterval)
	}
	if cfg.Emitter.BufferPath != "/var/lib/rampart/buffer" {
		t.Errorf("Emitter buffer path = %v, want /var/lib/rampart/buffer", cfg.Emitter.BufferPath)
	}
	if cfg.Emitter.MaxRetries != 3 {
		t.Errorf("Emitter max retries = %v, want 3", cfg.Emitter.MaxRetries)
	}
	if cfg.Emitter.RetryDelay != time.Second {
		t.Errorf("Emitter retry delay = %v, want 1s", cfg.Emitter.RetryDelay)
	}
}

func TestLoadFromFile_YAMLUnmarshalError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "bad.yaml")

	// Write YAML with a type mismatch (string where int is expected)
	badYAML := `
api_key: "test"
emitter:
  batch_size: "not_an_int"
`
	if err := os.WriteFile(configPath, []byte(badYAML), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("expected error for YAML unmarshal error")
	}
}
