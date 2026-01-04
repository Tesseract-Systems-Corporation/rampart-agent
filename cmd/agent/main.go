// Rampart Agent - A lightweight daemon for monitoring and governance.
//
// The agent runs on customer infrastructure and captures events like
// container lifecycle, SSH access, file drift, and health metrics.
// Events are sent to the Rampart control plane for analysis and compliance.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/config"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/emitter"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/platform"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/watcher"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/wsconn"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
	"golang.org/x/sync/errgroup"
)

var version = "dev" // Set at build time via -ldflags

func main() {
	// Parse flags
	configPath := flag.String("config", "/etc/rampart/agent.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "show version and exit")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("rampart-agent %s\n", version)
		os.Exit(0)
	}

	// Setup logging
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		// Try environment-only config
		logger.Info("config file not found, using environment variables", "path", *configPath)
		cfg = config.DefaultConfig()
	}

	// Override with environment variables
	cfg.LoadFromEnv()

	// Merge defaults and validate
	cfg.MergeDefaults()
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// Update version
	event.Version = version

	logger.Info("starting rampart agent",
		"version", version,
		"fortress_id", cfg.FortressID,
		"server_id", cfg.ServerID,
		"control_plane", cfg.ControlPlane,
	)

	// Create context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	// Run the agent
	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("agent error", "error", err)
		os.Exit(1)
	}

	logger.Info("agent stopped")
}

func run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	// Get hostname - prefer RAMPART_HOSTNAME env var for Docker deployments
	hostname := os.Getenv("RAMPART_HOSTNAME")
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
	}

	// Determine server name - prefer config, then env var, then hostname
	serverName := cfg.ServerName
	if serverName == "" {
		serverName = hostname
	}

	// Detect cloud provider
	provider := platform.DetectProvider(ctx)
	logger.Info("detected cloud provider", "provider", provider)

	// Create emitter
	// Note: Heartbeat interval is controlled by the control plane, not configured locally
	emit := emitter.New(emitter.Config{
		Endpoint:      cfg.ControlPlane,
		APIKey:        cfg.APIKey,
		ServerID:      cfg.ServerID,
		ServerName:    serverName,
		Hostname:      hostname,
		AgentVersion:  version,
		Provider:      string(provider),
		BatchSize:     cfg.Emitter.BatchSize,
		FlushInterval: cfg.Emitter.FlushInterval,
		BufferPath:    cfg.Emitter.BufferPath,
		MaxRetries:    cfg.Emitter.MaxRetries,
		RetryDelay:    cfg.Emitter.RetryDelay,
		Logger:        logger.With("component", "emitter"),
	})

	// Create watchers and get references to the vulnerability and malware watchers for on-demand scans
	watchers, vulnWatcher, malwareWatcher := createWatchersWithVuln(cfg, logger)

	if len(watchers) == 0 {
		return fmt.Errorf("no watchers enabled")
	}

	// Create multiplexer
	mux := watcher.NewMultiplexer(watchers...)

	// Create an event channel for on-demand scans triggered by control plane
	onDemandEvents := make(chan event.Event, 100)

	// Shared command handler for both HTTP heartbeat and WebSocket
	handleCommand := func(cmdType, cmdID string) {
		switch cmdType {
		case "trigger_vulnerability_scan":
			if vulnWatcher != nil {
				go vulnWatcher.TriggerScan(ctx, onDemandEvents)
			} else {
				logger.Warn("received vulnerability scan command but watcher not enabled")
			}
		case "trigger_malware_scan":
			if malwareWatcher != nil {
				go malwareWatcher.TriggerScan(ctx, onDemandEvents)
			} else {
				logger.Warn("received malware scan command but watcher not enabled")
			}
		default:
			logger.Warn("unknown command received", "command", cmdType)
		}
	}

	// Set up command handler for HTTP heartbeat commands (fallback)
	emit.SetCommandHandler(func(cmd emitter.Command) {
		handleCommand(cmd.Command, cmd.ID)
	})

	// Create WebSocket client for instant command delivery
	wsClient := wsconn.New(wsconn.Config{
		Endpoint:     cfg.ControlPlane,
		APIKey:       cfg.APIKey,
		ServerID:     cfg.ServerID,
		FortressID:   cfg.FortressID,
		Hostname:     hostname,
		AgentVersion: version,
		Provider:     string(provider),
		Logger:       logger.With("component", "ws-client"),
	})

	// Set up WebSocket command handler
	wsClient.SetCommandHandler(func(cmd wsconn.Command) {
		handleCommand(cmd.Command, cmd.ID)
	})

	g, ctx := errgroup.WithContext(ctx)

	// Start watchers
	g.Go(func() error {
		ch, err := mux.Watch(ctx)
		if err != nil {
			return fmt.Errorf("start watchers: %w", err)
		}

		for ev := range ch {
			emit.Send(ev)
		}
		return nil
	})

	// Handle on-demand events from control plane commands
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case ev := <-onDemandEvents:
				emit.Send(ev)
			}
		}
	})

	// Start emitter (HTTP-based events and heartbeat fallback)
	g.Go(func() error {
		return emit.Run(ctx)
	})

	// Start WebSocket client for instant command delivery
	g.Go(func() error {
		return wsClient.Run(ctx)
	})

	// Wait for all goroutines
	return g.Wait()
}

// detectSSHLogPath finds a readable SSH auth log file.
// Returns empty string if none found (e.g., on macOS or without permissions).
func detectSSHLogPath(configuredPath string) string {
	// Common auth log locations on different Linux distros
	candidates := []string{
		configuredPath,              // User-configured path first
		"/var/log/auth.log",         // Debian/Ubuntu
		"/var/log/secure",           // RHEL/CentOS/Fedora
		"/var/log/messages",         // Some systems log auth here
	}

	for _, path := range candidates {
		if path == "" {
			continue
		}
		// Check if file exists and is readable
		if f, err := os.Open(path); err == nil {
			f.Close()
			return path
		}
	}
	return ""
}

// createWatchersWithVuln creates all watchers and returns both the watcher slice
// and a reference to the vulnerability watcher for on-demand scanning.
func createWatchersWithVuln(cfg *config.Config, logger *slog.Logger) ([]watcher.Watcher, *watcher.VulnerabilityWatcher, *watcher.MalwareWatcher) {
	var watchers []watcher.Watcher
	var vulnWatcher *watcher.VulnerabilityWatcher
	var malwareWatcher *watcher.MalwareWatcher

	// Docker watcher
	if cfg.Watchers.Docker.Enabled {
		w := watcher.NewDockerWatcher(watcher.DockerConfig{
			SocketPath: cfg.Watchers.Docker.Socket,
			FortressID: cfg.FortressID,
			ServerID:   cfg.ServerID,
			Logger:     logger.With("watcher", "docker"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled docker watcher", "socket", cfg.Watchers.Docker.Socket)
	}

	// SSH watcher - auto-detect if log file exists
	sshLogPath := detectSSHLogPath(cfg.Watchers.SSH.LogPath)
	if cfg.Watchers.SSH.Enabled && sshLogPath != "" {
		w := watcher.NewSSHWatcher(watcher.SSHConfig{
			LogPath:    sshLogPath,
			FortressID: cfg.FortressID,
			ServerID:   cfg.ServerID,
			Logger:     logger.With("watcher", "ssh"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled ssh watcher", "log_path", sshLogPath)
	} else if cfg.Watchers.SSH.Enabled {
		logger.Info("ssh watcher disabled - no auth log found (not Linux or no permissions)")
	}

	// Health watcher
	// Note: Health watcher interval defaults to 30s, matching control plane's default
	if cfg.Watchers.Health.Enabled {
		w := watcher.NewHealthWatcher(watcher.HealthConfig{
			FortressID: cfg.FortressID,
			ServerID:   cfg.ServerID,
			Logger:     logger.With("watcher", "health"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled health watcher")
	}

	// Create encryption watcher first so we can wire it to network watcher
	var encryptionWatcher *watcher.EncryptionWatcher
	if cfg.Watchers.Encryption.Enabled {
		encryptionWatcher = watcher.NewEncryptionWatcher(watcher.EncryptionConfig{
			SnapshotInterval:  cfg.Watchers.Encryption.SnapshotInterval,
			CertPaths:         cfg.Watchers.Encryption.CertPaths,
			ExpiryWarningDays: cfg.Watchers.Encryption.ExpiryWarningDays,
			FortressID:        cfg.FortressID,
			ServerID:          cfg.ServerID,
			Logger:            logger.With("watcher", "encryption"),
		})
		// Note: encryption watcher is added to the list later after network watcher
	}

	// Network watcher (Doors - listening ports)
	if cfg.Watchers.Network.Enabled {
		// Create callback to notify encryption watcher of door changes
		var doorCallback watcher.DoorCallback
		if encryptionWatcher != nil {
			doorCallback = func(port int, opened bool) {
				if opened {
					encryptionWatcher.RegisterDoor(port)
				} else {
					encryptionWatcher.UnregisterDoor(port)
				}
			}
		}

		w := watcher.NewNetworkWatcher(watcher.NetworkConfig{
			ScanInterval: cfg.Watchers.Network.ScanInterval,
			FortressID:   cfg.FortressID,
			ServerID:     cfg.ServerID,
			Logger:       logger.With("watcher", "network"),
			OnDoorChange: doorCallback,
		})
		watchers = append(watchers, w)
		logger.Info("enabled network watcher", "scan_interval", cfg.Watchers.Network.ScanInterval)
	}

	// Add encryption watcher to the list (after network watcher setup)
	if encryptionWatcher != nil {
		watchers = append(watchers, encryptionWatcher)
		logger.Info("enabled encryption watcher", "snapshot_interval", cfg.Watchers.Encryption.SnapshotInterval)
	}

	// Connection watcher (Embassies - outbound connections, polling-based)
	if cfg.Watchers.Connection.Enabled {
		w := watcher.NewConnectionWatcher(watcher.ConnectionConfig{
			ScanInterval:           cfg.Watchers.Connection.ScanInterval,
			SnapshotInterval:       cfg.Watchers.Connection.SnapshotInterval,
			FortressID:             cfg.FortressID,
			ServerID:               cfg.ServerID,
			IgnoreLocalConnections: cfg.Watchers.Connection.IgnoreLocalConnections,
			ControlPlaneHost:       cfg.ControlPlane,
			Logger:                 logger.With("watcher", "connection"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled connection watcher",
			"scan_interval", cfg.Watchers.Connection.ScanInterval,
			"ignore_local", cfg.Watchers.Connection.IgnoreLocalConnections,
		)
	}

	// eBPF watcher (real-time connection tracking)
	if cfg.Watchers.EBPF.Enabled {
		if watcher.IsEBPFSupported() {
			w, err := watcher.NewEBPFWatcher(
				logger.With("watcher", "ebpf"),
				cfg.FortressID,
				cfg.ServerID,
				cfg.ControlPlane,
			)
			if err != nil {
				logger.Warn("failed to start eBPF watcher", "error", err)
			} else {
				watchers = append(watchers, w)
				logger.Info("enabled eBPF connection watcher")
			}
		} else {
			logger.Info("eBPF watcher disabled - not supported on this system (requires Linux with BTF and root)")
		}
	}

	// Drift watcher
	if cfg.Watchers.Drift.Enabled && len(cfg.Watchers.Drift.WatchPaths) > 0 {
		w := watcher.NewDriftWatcher(watcher.DriftConfig{
			WatchPaths:     cfg.Watchers.Drift.WatchPaths,
			IgnorePatterns: cfg.Watchers.Drift.IgnorePatterns,
			FortressID:     cfg.FortressID,
			ServerID:       cfg.ServerID,
			Logger:         logger.With("watcher", "drift"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled drift watcher", "paths", cfg.Watchers.Drift.WatchPaths)
	}

	// Logs watcher (container error rate tracking)
	if cfg.Watchers.Logs.Enabled {
		w := watcher.NewLogsWatcher(watcher.LogsConfig{
			ScanInterval: cfg.Watchers.Logs.ScanInterval,
			SocketPath:   cfg.Watchers.Docker.Socket,
			FortressID:   cfg.FortressID,
			ServerID:     cfg.ServerID,
			Logger:       logger.With("watcher", "logs"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled logs watcher", "scan_interval", cfg.Watchers.Logs.ScanInterval)
	}

	// Secrets watcher
	if cfg.Watchers.Secrets.Enabled && len(cfg.Watchers.Secrets.WatchPaths) > 0 {
		w := watcher.NewSecretsWatcher(watcher.SecretsConfig{
			WatchPaths:     cfg.Watchers.Secrets.WatchPaths,
			SecretPatterns: cfg.Watchers.Secrets.SecretPatterns,
			FortressID:     cfg.FortressID,
			ServerID:       cfg.ServerID,
			Logger:         logger.With("watcher", "secrets"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled secrets watcher", "paths", cfg.Watchers.Secrets.WatchPaths)
	}

	// Vulnerability watcher (Trivy/Grype scanning)
	if cfg.Watchers.Vulnerability.Enabled {
		scanTargets := make([]watcher.ScanTarget, 0, len(cfg.Watchers.Vulnerability.ScanTargets))
		for _, target := range cfg.Watchers.Vulnerability.ScanTargets {
			scanTargets = append(scanTargets, watcher.ScanTarget{
				Type: watcher.ScanTargetFilesystem,
				Path: target,
			})
		}

		vulnWatcher = watcher.NewVulnerabilityWatcher(watcher.VulnerabilityConfig{
			ScanInterval: cfg.Watchers.Vulnerability.ScanInterval,
			Scanner:      watcher.ScannerType(cfg.Watchers.Vulnerability.Scanner),
			ScanTargets:  scanTargets,
			FortressID:   cfg.FortressID,
			ServerID:     cfg.ServerID,
			Logger:       logger.With("watcher", "vulnerability"),
		})
		watchers = append(watchers, vulnWatcher)
		logger.Info("enabled vulnerability watcher",
			"scanner", cfg.Watchers.Vulnerability.Scanner,
			"interval", cfg.Watchers.Vulnerability.ScanInterval,
			"targets", cfg.Watchers.Vulnerability.ScanTargets,
		)
	}

	// Users watcher (CC6.2 - user account changes)
	if cfg.Watchers.Users.Enabled {
		w := watcher.NewUserAccountWatcher(watcher.UserAccountConfig{
			PasswdPath: cfg.Watchers.Users.PasswdPath,
			GroupPath:  cfg.Watchers.Users.GroupPath,
			ShadowPath: cfg.Watchers.Users.ShadowPath,
			FortressID: cfg.FortressID,
			ServerID:   cfg.ServerID,
			Logger:     logger.With("watcher", "users"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled users watcher")
	}

	// Access Review watcher (CC6.2 - periodic user snapshots)
	if cfg.Watchers.AccessReview.Enabled {
		w := watcher.NewAccessReviewWatcher(watcher.AccessReviewConfig{
			SnapshotInterval: cfg.Watchers.AccessReview.SnapshotInterval,
			StaleAccountDays: cfg.Watchers.AccessReview.StaleAccountDays,
			FortressID:       cfg.FortressID,
			ServerID:         cfg.ServerID,
			Logger:           logger.With("watcher", "accessreview"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled access review watcher", "interval", cfg.Watchers.AccessReview.SnapshotInterval)
	}

	// Firewall watcher (CC6.6 - firewall state monitoring)
	if cfg.Watchers.Firewall.Enabled {
		w := watcher.NewFirewallWatcher(watcher.FirewallConfig{
			PollInterval:     cfg.Watchers.Firewall.PollInterval,
			SnapshotInterval: cfg.Watchers.Firewall.SnapshotInterval,
			FortressID:       cfg.FortressID,
			ServerID:         cfg.ServerID,
			Logger:           logger.With("watcher", "firewall"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled firewall watcher", "snapshot_interval", cfg.Watchers.Firewall.SnapshotInterval)
	}

	// Process watcher (CC7.2 - suspicious process detection)
	if cfg.Watchers.Process.Enabled {
		w := watcher.NewProcessWatcher(watcher.ProcessConfig{
			PollInterval:       cfg.Watchers.Process.PollInterval,
			SuspiciousPatterns: cfg.Watchers.Process.SuspiciousPatterns,
			WatchUsers:         cfg.Watchers.Process.WatchUsers,
			FortressID:         cfg.FortressID,
			ServerID:           cfg.ServerID,
			Logger:             logger.With("watcher", "process"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled process watcher", "poll_interval", cfg.Watchers.Process.PollInterval)
	}

	// Package watcher (CC8.1 - package change tracking)
	if cfg.Watchers.Packages.Enabled {
		w := watcher.NewPackageWatcher(watcher.PackageConfig{
			AptLogPaths: cfg.Watchers.Packages.AptLogPaths,
			YumLogPaths: cfg.Watchers.Packages.YumLogPaths,
			FortressID:  cfg.FortressID,
			ServerID:    cfg.ServerID,
			Logger:      logger.With("watcher", "packages"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled package watcher")
	}

	// Service watcher (CC8.1 - systemd service monitoring)
	if cfg.Watchers.Services.Enabled {
		w := watcher.NewServiceWatcher(watcher.ServiceConfig{
			PollInterval: cfg.Watchers.Services.PollInterval,
			FortressID:   cfg.FortressID,
			ServerID:     cfg.ServerID,
			Logger:       logger.With("watcher", "services"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled service watcher", "poll_interval", cfg.Watchers.Services.PollInterval)
	}

	// Control Check watcher (CC4.1 - automated compliance checks)
	if cfg.Watchers.ControlCheck.Enabled {
		w := watcher.NewControlCheckWatcher(watcher.ControlCheckConfig{
			CheckInterval:   cfg.Watchers.ControlCheck.CheckInterval,
			EnabledControls: cfg.Watchers.ControlCheck.EnabledControls,
			FortressID:      cfg.FortressID,
			ServerID:        cfg.ServerID,
			Logger:          logger.With("watcher", "controlcheck"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled control check watcher", "interval", cfg.Watchers.ControlCheck.CheckInterval)
	}

	// Malware watcher (CC6.8 - malware prevention)
	if cfg.Watchers.Malware.Enabled {
		malwareWatcher = watcher.NewMalwareWatcher(watcher.MalwareConfig{
			SnapshotInterval: cfg.Watchers.Malware.SnapshotInterval,
			EnableClamAVScan: cfg.Watchers.Malware.EnableClamAVScan,
			ScanPaths:        cfg.Watchers.Malware.ScanPaths,
			FortressID:       cfg.FortressID,
			ServerID:         cfg.ServerID,
			Logger:           logger.With("watcher", "malware"),
		})
		watchers = append(watchers, malwareWatcher)
		logger.Info("enabled malware watcher", "snapshot_interval", cfg.Watchers.Malware.SnapshotInterval)
	}

	// Backup watcher (CC7.5 - recovery operations)
	if cfg.Watchers.Backup.Enabled {
		w := watcher.NewBackupWatcher(watcher.BackupConfig{
			SnapshotInterval: cfg.Watchers.Backup.SnapshotInterval,
			MaxBackupAge:     cfg.Watchers.Backup.MaxBackupAge,
			ResticRepoPath:   cfg.Watchers.Backup.ResticRepoPath,
			BorgRepoPath:     cfg.Watchers.Backup.BorgRepoPath,
			FortressID:       cfg.FortressID,
			ServerID:         cfg.ServerID,
			Logger:           logger.With("watcher", "backup"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled backup watcher", "snapshot_interval", cfg.Watchers.Backup.SnapshotInterval)
	}

	// Cloud Provider watcher (CC6.4/CC6.5 - inherited physical controls)
	if cfg.Watchers.CloudProvider.Enabled {
		w := watcher.NewCloudProviderWatcher(watcher.CloudProviderConfig{
			CheckInterval: cfg.Watchers.CloudProvider.CheckInterval,
			FortressID:    cfg.FortressID,
			ServerID:      cfg.ServerID,
			Logger:        logger.With("watcher", "cloudprovider"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled cloud provider watcher", "check_interval", cfg.Watchers.CloudProvider.CheckInterval)
	}

	// Deployment watcher (CC8.1 - deployment tracking from CI/CD markers)
	if cfg.Watchers.Deployment.Enabled {
		w := watcher.NewDeploymentWatcher(watcher.DeploymentConfig{
			MarkerDir:    cfg.Watchers.Deployment.MarkerDir,
			PollInterval: cfg.Watchers.Deployment.PollInterval,
			FortressID:   cfg.FortressID,
			ServerID:     cfg.ServerID,
			Logger:       logger.With("watcher", "deployment"),
		})
		watchers = append(watchers, w)
		logger.Info("enabled deployment watcher", "marker_dir", cfg.Watchers.Deployment.MarkerDir)
	}

	return watchers, vulnWatcher, malwareWatcher
}
