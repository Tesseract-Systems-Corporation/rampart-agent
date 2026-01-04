package watcher

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DockerConfig holds configuration for the Docker watcher.
type DockerConfig struct {
	// SocketPath is the path to the Docker socket.
	// Defaults to /var/run/docker.sock if empty.
	SocketPath string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger

	// ConnectionScanInterval is how often to scan container connections.
	// Defaults to 30 seconds. Set to 0 to disable.
	ConnectionScanInterval time.Duration
}

// ContainerInfo holds information about a running container.
type ContainerInfo struct {
	ID   string
	Name string
	PID  int
}

// ContainerConnection represents an outbound connection from a container.
type ContainerConnection struct {
	ContainerID   string
	ContainerName string
	LocalAddr     string
	LocalPort     int
	RemoteAddr    string
	RemotePort    int
	State         string
}

// Deduplication constants for Docker events
const (
	dockerDedupWindow          = 2 * time.Second
	dockerDedupCleanupInterval = 30 * time.Second
)

// DockerWatcher monitors Docker container events.
type DockerWatcher struct {
	socketPath             string
	fortressID             string
	serverID               string
	logger                 *slog.Logger
	client                 *client.Client
	connectionScanInterval time.Duration

	// Track running containers for connection scanning
	containers   map[string]ContainerInfo
	containersMu sync.RWMutex

	// Track seen connections to detect changes
	seenConnections   map[string]bool
	seenConnectionsMu sync.Mutex

	// Track recent events for deduplication
	recentEvents   map[string]time.Time
	recentEventsMu sync.Mutex
}

// NewDockerWatcher creates a new DockerWatcher with the given configuration.
func NewDockerWatcher(cfg DockerConfig) *DockerWatcher {
	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	scanInterval := cfg.ConnectionScanInterval
	if scanInterval == 0 {
		scanInterval = 30 * time.Second
	}

	return &DockerWatcher{
		socketPath:             socketPath,
		fortressID:             cfg.FortressID,
		serverID:               cfg.ServerID,
		logger:                 logger,
		connectionScanInterval: scanInterval,
		containers:             make(map[string]ContainerInfo),
		seenConnections:        make(map[string]bool),
		recentEvents:          make(map[string]time.Time),
	}
}

// Watch starts watching Docker events and returns a channel of events.
func (w *DockerWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+w.socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	w.client = cli

	out := make(chan event.Event)

	go func() {
		defer close(out)
		defer cli.Close()

		w.logger.Info("starting docker watcher", "socket", w.socketPath)

		// Initialize with existing running containers
		w.initRunningContainers(ctx)

		eventCh, errCh := cli.Events(ctx, events.ListOptions{})

		// Start connection scanner if enabled
		var scanTicker *time.Ticker
		var scanTickerC <-chan time.Time
		if w.connectionScanInterval > 0 {
			scanTicker = time.NewTicker(w.connectionScanInterval)
			scanTickerC = scanTicker.C
			defer scanTicker.Stop()

			// Do initial scan
			w.scanContainerConnections(ctx, out)
		}

		// Start dedup cleanup ticker
		dedupTicker := time.NewTicker(dockerDedupCleanupInterval)
		defer dedupTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("docker watcher stopped", "reason", ctx.Err())
				return

			case err := <-errCh:
				if err != nil {
					w.logger.Error("docker events error", "error", err)
				}
				return

			case <-dedupTicker.C:
				w.cleanupOldEvents()

			case <-scanTickerC:
				w.scanContainerConnections(ctx, out)

			case msg := <-eventCh:
				if msg.Type != events.ContainerEventType {
					continue
				}

				containerName := msg.Actor.Attributes["name"]
				image := msg.Actor.Attributes["image"]

				// Track container start/stop for connection scanning
				if msg.Action == "start" {
					w.trackContainer(ctx, msg.Actor.ID, containerName)
				} else if msg.Action == "stop" || msg.Action == "die" || msg.Action == "kill" {
					w.untrackContainer(msg.Actor.ID)
				}

				// Get deployment info and security posture from container on start
				var deployInfo *DeploymentInfo
				var securityPosture *SecurityPosture
				if msg.Action == "start" {
					deployInfo = w.getDeploymentInfo(ctx, msg.Actor.ID)
					securityPosture = w.getSecurityPosture(ctx, msg.Actor.ID)
				}

				e := parseContainerEvent(
					string(msg.Action),
					containerName,
					msg.Actor.ID,
					image,
					w.fortressID,
					w.serverID,
					msg.Actor.Attributes,
					deployInfo,
					securityPosture,
				)

				if e != nil {
					// Create dedup key: containerID + normalized event type
					// stop/die/kill all map to "stopped" for dedup purposes
					dedupAction := string(msg.Action)
					if msg.Action == "stop" || msg.Action == "die" || msg.Action == "kill" {
						dedupAction = "stopped"
					}
					dedupKey := msg.Actor.ID + ":" + dedupAction

					// Skip duplicate events
					if w.isDuplicateEvent(dedupKey) {
						w.logger.Debug("skipping duplicate container event",
							"action", msg.Action,
							"container", containerName,
						)
						continue
					}

					w.logger.Debug("container event",
						"action", msg.Action,
						"container", containerName,
						"image", image,
					)

					select {
					case <-ctx.Done():
						return
					case out <- *e:
					}
				}
			}
		}
	}()

	return out, nil
}

// initRunningContainers initializes the container map with existing running containers.
func (w *DockerWatcher) initRunningContainers(ctx context.Context) {
	if w.client == nil {
		return
	}

	containers, err := w.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		w.logger.Error("failed to list containers", "error", err)
		return
	}

	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		w.trackContainer(ctx, c.ID, name)
	}

	w.logger.Info("initialized container tracking", "count", len(containers))
}

// trackContainer adds a container to the tracking map.
func (w *DockerWatcher) trackContainer(ctx context.Context, containerID, name string) {
	if w.client == nil {
		return
	}

	info, err := w.client.ContainerInspect(ctx, containerID)
	if err != nil {
		w.logger.Debug("failed to inspect container for tracking", "id", containerID, "error", err)
		return
	}

	pid := info.State.Pid
	if pid == 0 {
		return
	}

	w.containersMu.Lock()
	w.containers[containerID] = ContainerInfo{
		ID:   containerID,
		Name: name,
		PID:  pid,
	}
	w.containersMu.Unlock()

	w.logger.Debug("tracking container", "id", containerID[:12], "name", name, "pid", pid)
}

// untrackContainer removes a container from the tracking map.
func (w *DockerWatcher) untrackContainer(containerID string) {
	w.containersMu.Lock()
	delete(w.containers, containerID)
	w.containersMu.Unlock()
}

// isDuplicateEvent checks if we've seen this event recently (within dedupWindow).
// The key should uniquely identify the event (e.g., containerID + eventType).
func (w *DockerWatcher) isDuplicateEvent(key string) bool {
	now := time.Now()
	w.recentEventsMu.Lock()
	defer w.recentEventsMu.Unlock()

	if lastSeen, exists := w.recentEvents[key]; exists {
		if now.Sub(lastSeen) < dockerDedupWindow {
			return true
		}
	}
	w.recentEvents[key] = now
	return false
}

// cleanupOldEvents removes events older than dedupWindow from the map.
func (w *DockerWatcher) cleanupOldEvents() {
	now := time.Now()
	w.recentEventsMu.Lock()
	defer w.recentEventsMu.Unlock()

	for key, ts := range w.recentEvents {
		if now.Sub(ts) > dockerDedupWindow*2 {
			delete(w.recentEvents, key)
		}
	}
}

// scanContainerConnections scans all tracked containers for outbound connections.
func (w *DockerWatcher) scanContainerConnections(ctx context.Context, out chan<- event.Event) {
	w.containersMu.RLock()
	containers := make([]ContainerInfo, 0, len(w.containers))
	for _, c := range w.containers {
		containers = append(containers, c)
	}
	w.containersMu.RUnlock()

	for _, c := range containers {
		conns := w.getContainerConnections(c)
		for _, conn := range conns {
			// Create unique key for this connection
			connKey := fmt.Sprintf("%s:%s:%d->%s:%d",
				conn.ContainerID[:12], conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)

			// Check if we've seen this connection before
			w.seenConnectionsMu.Lock()
			if w.seenConnections[connKey] {
				w.seenConnectionsMu.Unlock()
				continue
			}
			w.seenConnections[connKey] = true
			w.seenConnectionsMu.Unlock()

			// Emit connection event
			e := w.createContainerConnectionEvent(conn)

			select {
			case <-ctx.Done():
				return
			case out <- e:
			}
		}
	}
}

// getContainerConnections reads TCP connections from a container's network namespace.
func (w *DockerWatcher) getContainerConnections(c ContainerInfo) []ContainerConnection {
	var connections []ContainerConnection

	// Read /proc/<pid>/net/tcp for IPv4 connections
	tcpPath := fmt.Sprintf("/proc/%d/net/tcp", c.PID)
	conns := w.parseProcNetTCP(tcpPath, c)
	connections = append(connections, conns...)

	// Read /proc/<pid>/net/tcp6 for IPv6 connections
	tcp6Path := fmt.Sprintf("/proc/%d/net/tcp6", c.PID)
	conns6 := w.parseProcNetTCP(tcp6Path, c)
	connections = append(connections, conns6...)

	return connections
}

// parseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6 format.
func (w *DockerWatcher) parseProcNetTCP(path string, c ContainerInfo) []ContainerConnection {
	var connections []ContainerConnection

	file, err := os.Open(path)
	if err != nil {
		return connections
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}

		line := scanner.Text()
		conn := w.parseTCPLine(line, c)
		if conn != nil {
			// Only track established outbound connections (state 01 = ESTABLISHED)
			// and filter out loopback
			if conn.State == "01" && !isLoopback(conn.RemoteAddr) {
				connections = append(connections, *conn)
			}
		}
	}

	return connections
}

// parseTCPLine parses a single line from /proc/net/tcp.
// Format: sl local_address rem_address st tx_queue:rx_queue ...
func (w *DockerWatcher) parseTCPLine(line string, c ContainerInfo) *ContainerConnection {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	localAddr, localPort := parseHexAddr(fields[1])
	remoteAddr, remotePort := parseHexAddr(fields[2])
	state := fields[3]

	if localAddr == "" || remoteAddr == "" {
		return nil
	}

	return &ContainerConnection{
		ContainerID:   c.ID,
		ContainerName: c.Name,
		LocalAddr:     localAddr,
		LocalPort:     localPort,
		RemoteAddr:    remoteAddr,
		RemotePort:    remotePort,
		State:         state,
	}
}

// parseHexAddr parses a hex-encoded address:port from /proc/net/tcp.
// Format: "0100007F:0050" = 127.0.0.1:80
func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}

	addrHex := parts[0]
	portHex := parts[1]

	// Parse port
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0
	}

	// Parse address - it's stored in little-endian for IPv4
	if len(addrHex) == 8 {
		// IPv4
		addrBytes, err := hex.DecodeString(addrHex)
		if err != nil {
			return "", 0
		}
		// Reverse bytes (little-endian to big-endian)
		ip := net.IPv4(addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0])
		return ip.String(), int(port)
	} else if len(addrHex) == 32 {
		// IPv6
		addrBytes, err := hex.DecodeString(addrHex)
		if err != nil {
			return "", 0
		}
		// IPv6 is stored in groups of 4 bytes, each group in little-endian
		for i := 0; i < 16; i += 4 {
			addrBytes[i], addrBytes[i+1], addrBytes[i+2], addrBytes[i+3] =
				addrBytes[i+3], addrBytes[i+2], addrBytes[i+1], addrBytes[i]
		}
		ip := net.IP(addrBytes)
		return ip.String(), int(port)
	}

	return "", 0
}

// createContainerConnectionEvent creates an event for a container connection.
func (w *DockerWatcher) createContainerConnectionEvent(conn ContainerConnection) event.Event {
	// Try to identify the service
	serviceGuess := guessServiceByPort(conn.RemoteAddr, conn.RemotePort)

	// Try reverse DNS
	remoteHost := ""
	if names, err := net.LookupAddr(conn.RemoteAddr); err == nil && len(names) > 0 {
		remoteHost = strings.TrimSuffix(names[0], ".")
	}

	return event.NewEvent(event.ConnectionEstablished, w.fortressID, w.serverID, map[string]any{
		"container_id":   conn.ContainerID,
		"container_name": conn.ContainerName,
		"connection": map[string]any{
			"local_addr":    conn.LocalAddr,
			"local_port":    conn.LocalPort,
			"remote_addr":   conn.RemoteAddr,
			"remote_port":   conn.RemotePort,
			"protocol":      "tcp",
			"remote_host":   remoteHost,
			"service_guess": serviceGuess,
		},
		"direction": "outbound",
		"source":    "container",
	})
}

// DeploymentInfo contains enriched deployment metadata.
type DeploymentInfo struct {
	GitCommit   string
	GitRepo     string
	GitBranch   string
	Deployer    string
	Version     string
	Environment string
}

// SecurityPosture contains container security configuration.
type SecurityPosture struct {
	Privileged       bool     `json:"privileged"`
	RunAsRoot        bool     `json:"run_as_root"`
	User             string   `json:"user"`
	ReadOnlyRootfs   bool     `json:"read_only_rootfs"`
	CapabilitiesAdd  []string `json:"capabilities_add,omitempty"`
	CapabilitiesDrop []string `json:"capabilities_drop,omitempty"`
	SecurityOpts     []string `json:"security_opts,omitempty"`
	HostNetwork      bool     `json:"host_network"`
	HostPID          bool     `json:"host_pid"`
	HostIPC          bool     `json:"host_ipc"`
}

// getDeploymentInfo inspects a container and extracts deployment metadata from labels.
func (w *DockerWatcher) getDeploymentInfo(ctx context.Context, containerID string) *DeploymentInfo {
	if w.client == nil {
		return nil
	}

	info, err := w.client.ContainerInspect(ctx, containerID)
	if err != nil {
		w.logger.Debug("failed to inspect container", "id", containerID, "error", err)
		return nil
	}

	labels := info.Config.Labels
	if labels == nil {
		return nil
	}

	deploy := &DeploymentInfo{}

	// Standard OCI labels
	if v := labels["org.opencontainers.image.revision"]; v != "" {
		deploy.GitCommit = v
	}
	if v := labels["org.opencontainers.image.source"]; v != "" {
		deploy.GitRepo = v
	}
	if v := labels["org.opencontainers.image.version"]; v != "" {
		deploy.Version = v
	}

	// Coolify labels
	if v := labels["coolify.gitCommitSha"]; v != "" {
		deploy.GitCommit = v
	}
	if v := labels["coolify.gitRepository"]; v != "" {
		deploy.GitRepo = v
	}
	if v := labels["coolify.gitBranch"]; v != "" {
		deploy.GitBranch = v
	}
	if v := labels["coolify.environment"]; v != "" {
		deploy.Environment = v
	}

	// Docker Compose labels
	if v := labels["com.docker.compose.project"]; v != "" && deploy.Environment == "" {
		deploy.Environment = v
	}

	// Custom rampart labels
	if v := labels["rampart.deployer"]; v != "" {
		deploy.Deployer = v
	}
	if v := labels["rampart.git.commit"]; v != "" {
		deploy.GitCommit = v
	}
	if v := labels["rampart.git.repo"]; v != "" {
		deploy.GitRepo = v
	}
	if v := labels["rampart.git.branch"]; v != "" {
		deploy.GitBranch = v
	}

	// Check if we found anything useful
	if deploy.GitCommit == "" && deploy.GitRepo == "" && deploy.Deployer == "" {
		return nil
	}

	return deploy
}

// getSecurityPosture inspects a container and extracts security configuration.
func (w *DockerWatcher) getSecurityPosture(ctx context.Context, containerID string) *SecurityPosture {
	if w.client == nil {
		return nil
	}

	info, err := w.client.ContainerInspect(ctx, containerID)
	if err != nil {
		w.logger.Debug("failed to inspect container for security posture", "id", containerID, "error", err)
		return nil
	}

	posture := &SecurityPosture{}

	// Check privileged mode
	if info.HostConfig != nil {
		posture.Privileged = info.HostConfig.Privileged
		posture.ReadOnlyRootfs = info.HostConfig.ReadonlyRootfs

		// Host namespace sharing
		posture.HostNetwork = info.HostConfig.NetworkMode == "host"
		posture.HostPID = info.HostConfig.PidMode == "host"
		posture.HostIPC = info.HostConfig.IpcMode == "host"

		// Capabilities
		if info.HostConfig.CapAdd != nil {
			posture.CapabilitiesAdd = info.HostConfig.CapAdd
		}
		if info.HostConfig.CapDrop != nil {
			posture.CapabilitiesDrop = info.HostConfig.CapDrop
		}

		// Security options (AppArmor, Seccomp, etc.)
		if info.HostConfig.SecurityOpt != nil {
			posture.SecurityOpts = info.HostConfig.SecurityOpt
		}
	}

	// Check user configuration
	if info.Config != nil {
		posture.User = info.Config.User
		// Running as root if user is empty, "0", or "root"
		posture.RunAsRoot = posture.User == "" || posture.User == "0" || posture.User == "root" ||
			strings.HasPrefix(posture.User, "0:") || strings.HasPrefix(posture.User, "root:")
	}

	return posture
}

// Name returns the watcher name.
func (w *DockerWatcher) Name() string {
	return "docker"
}

// isAutomatedExec checks if an exec command is an automated healthcheck or similar.
// We want to filter these out and only capture real human access.
func isAutomatedExec(command string) bool {
	if command == "" {
		return false
	}

	lower := strings.ToLower(command)

	// Common healthcheck patterns
	healthcheckPatterns := []string{
		"wget -q --spider",  // Docker healthcheck wget
		"wget --spider",
		"curl -f ",          // Docker healthcheck curl
		"curl --fail",
		"curl -s ",
		"/health",           // Healthcheck endpoints
		"/healthz",
		"/ready",
		"/readyz",
		"/live",
		"/livez",
		"pg_isready",        // PostgreSQL healthcheck
		"redis-cli ping",    // Redis healthcheck
		"mysqladmin ping",   // MySQL healthcheck
		"mongo --eval",      // MongoDB healthcheck
	}

	for _, pattern := range healthcheckPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Also filter out commands that look automated (wrapped in /bin/sh -c with exit)
	if strings.Contains(command, "|| exit") || strings.Contains(command, "&& exit") {
		return true
	}

	return false
}

// parseContainerEvent converts a Docker event to a Rampart event.
// Returns nil for events we don't care about.
func parseContainerEvent(action, containerName, containerID, image, fortressID, serverID string, attributes map[string]string, deployInfo *DeploymentInfo, securityPosture *SecurityPosture) *event.Event {
	var eventType event.EventType
	payload := map[string]any{
		"container_id":   containerID,
		"container_name": containerName,
		"image":          image,
		"action":         action,
	}

	switch {
	case action == "start":
		eventType = event.ContainerStarted
		// Enrich with deployment info if available
		if deployInfo != nil {
			if deployInfo.GitCommit != "" {
				payload["git_commit"] = deployInfo.GitCommit
			}
			if deployInfo.GitRepo != "" {
				payload["git_repo"] = deployInfo.GitRepo
			}
			if deployInfo.GitBranch != "" {
				payload["git_branch"] = deployInfo.GitBranch
			}
			if deployInfo.Deployer != "" {
				payload["deployer"] = deployInfo.Deployer
			}
			if deployInfo.Version != "" {
				payload["version"] = deployInfo.Version
			}
			if deployInfo.Environment != "" {
				payload["environment"] = deployInfo.Environment
			}
		}
		// Enrich with security posture if available
		if securityPosture != nil {
			payload["security_posture"] = map[string]any{
				"privileged":        securityPosture.Privileged,
				"run_as_root":       securityPosture.RunAsRoot,
				"user":              securityPosture.User,
				"read_only_rootfs":  securityPosture.ReadOnlyRootfs,
				"capabilities_add":  securityPosture.CapabilitiesAdd,
				"capabilities_drop": securityPosture.CapabilitiesDrop,
				"security_opts":     securityPosture.SecurityOpts,
				"host_network":      securityPosture.HostNetwork,
				"host_pid":          securityPosture.HostPID,
				"host_ipc":          securityPosture.HostIPC,
			}
		}
	case action == "stop" || action == "die" || action == "kill":
		eventType = event.ContainerStopped
	case strings.HasPrefix(action, "exec_start"):
		// Someone ran docker exec on this container
		// Action format is "exec_start: <command>"

		// Extract the command from the action string
		var command string
		if parts := strings.SplitN(action, ": ", 2); len(parts) == 2 {
			command = parts[1]
		}

		// Filter out healthcheck and automated commands
		if isAutomatedExec(command) {
			return nil
		}

		eventType = event.ContainerExec
		if execID := attributes["execID"]; execID != "" {
			payload["exec_id"] = execID
		}
		if command != "" {
			payload["command"] = command
		}
		payload["description"] = "Interactive session started on container"
	default:
		// Ignore other actions (create, attach, detach, etc.)
		return nil
	}

	e := event.NewEvent(eventType, fortressID, serverID, payload)
	return &e
}
