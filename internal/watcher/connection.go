package watcher

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// ConnectionConfig holds configuration for the connection watcher.
type ConnectionConfig struct {
	ScanInterval           time.Duration
	SnapshotInterval       time.Duration
	FortressID             string
	ServerID               string
	IgnoreLocalConnections bool
	// ControlPlaneHost is the control plane address to ignore (don't log agent's own connections)
	ControlPlaneHost       string
	Logger                 *slog.Logger
}

// ConnectionWatcher monitors outbound TCP connections (Embassies).
type ConnectionWatcher struct {
	scanInterval           time.Duration
	snapshotInterval       time.Duration
	fortressID             string
	serverID               string
	ignoreLocal            bool
	controlPlaneHost       string
	logger                 *slog.Logger

	// Track seen connections to detect new ones
	seenConnections   map[string]event.ConnectionInfo
	seenConnectionsMu sync.Mutex
}

// Regex patterns for parsing ss/netstat output
var (
	connSSLineRe       = regexp.MustCompile(`^tcp\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+`)
	connIPv4AddrPortRe = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+):(\d+)$`)
	connIPv6AddrPortRe = regexp.MustCompile(`^\[([^\]]+)\]:(\d+)$`)
	connSSProcessRe    = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)
)

// NewConnectionWatcher creates a new connection watcher.
func NewConnectionWatcher(cfg ConnectionConfig) *ConnectionWatcher {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	scanInterval := cfg.ScanInterval
	if scanInterval == 0 {
		scanInterval = 30 * time.Second
	}

	snapshotInterval := cfg.SnapshotInterval
	if snapshotInterval == 0 {
		snapshotInterval = 5 * time.Minute
	}

	return &ConnectionWatcher{
		scanInterval:     scanInterval,
		snapshotInterval: snapshotInterval,
		fortressID:       cfg.FortressID,
		serverID:         cfg.ServerID,
		ignoreLocal:      cfg.IgnoreLocalConnections,
		controlPlaneHost: cfg.ControlPlaneHost,
		logger:           logger,
		seenConnections:  make(map[string]event.ConnectionInfo),
	}
}

// Name returns the watcher name.
func (w *ConnectionWatcher) Name() string {
	return "connection"
}

// Watch starts watching for outbound connections.
func (w *ConnectionWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event, 100)

	go func() {
		defer close(out)

		scanTicker := time.NewTicker(w.scanInterval)
		defer scanTicker.Stop()

		snapshotTicker := time.NewTicker(w.snapshotInterval)
		defer snapshotTicker.Stop()

		// Initial scan
		w.scan(ctx, out, false)

		for {
			select {
			case <-ctx.Done():
				return
			case <-scanTicker.C:
				w.scan(ctx, out, false)
			case <-snapshotTicker.C:
				w.scan(ctx, out, true)
			}
		}
	}()

	return out, nil
}

// scan performs a connection scan and emits events.
func (w *ConnectionWatcher) scan(ctx context.Context, out chan<- event.Event, snapshot bool) {
	connections, err := w.getConnections()
	if err != nil {
		w.logger.Error("failed to get connections", "error", err)
		return
	}

	w.seenConnectionsMu.Lock()
	defer w.seenConnectionsMu.Unlock()

	if snapshot {
		// Emit snapshot event with all current connections
		if len(connections) > 0 {
			ev := event.NewEvent(
				event.ConnectionSnapshot,
				w.fortressID,
				w.serverID,
				map[string]any{
					"connections": connections,
					"count":       len(connections),
				},
			)
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
		return
	}

	// Detect new connections - key by REMOTE endpoint only (local ports are ephemeral)
	currentRemotes := make(map[string]bool)
	for _, conn := range connections {
		// Key by remote endpoint only - we care about "what services are we connecting to"
		// not individual TCP connections (which have ephemeral local ports)
		remoteKey := fmt.Sprintf("%s:%d", conn.RemoteAddr, conn.RemotePort)
		currentRemotes[remoteKey] = true

		if _, seen := w.seenConnections[remoteKey]; !seen {
			w.seenConnections[remoteKey] = conn

			ev := event.NewEvent(
				event.ConnectionEstablished,
				w.fortressID,
				w.serverID,
				map[string]any{
					"connection": conn,
				},
			)
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}

	// Detect closed connections (no active connection to this remote endpoint)
	for remoteKey, conn := range w.seenConnections {
		if !currentRemotes[remoteKey] {
			delete(w.seenConnections, remoteKey)

			ev := event.NewEvent(
				event.ConnectionClosed,
				w.fortressID,
				w.serverID,
				map[string]any{
					"connection": conn,
				},
			)
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// getConnections returns current outbound TCP connections.
func (w *ConnectionWatcher) getConnections() ([]event.ConnectionInfo, error) {
	// Try ss first, fall back to netstat
	connections, err := w.getConnectionsSS()
	if err != nil {
		connections, err = w.getConnectionsNetstat()
		if err != nil {
			return nil, err
		}
	}
	return connections, nil
}

// getConnectionsSS uses the ss command to get connections.
func (w *ConnectionWatcher) getConnectionsSS() ([]event.ConnectionInfo, error) {
	cmd := exec.Command("ss", "-tpnH", "state", "established")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ss command failed: %w", err)
	}

	var connections []event.ConnectionInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := scanner.Text()
		conn, ok := w.parseSSLine(line)
		if !ok {
			continue
		}

		// Skip local connections if configured
		if w.ignoreLocal && w.isLocalAddress(conn.RemoteAddr) {
			continue
		}

		// Skip loopback
		if strings.HasPrefix(conn.RemoteAddr, "127.") || conn.RemoteAddr == "::1" {
			continue
		}

		// Skip control plane, kernel processes, gateway connections
		if w.shouldIgnoreConnection(conn) {
			continue
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// parseSSLine parses a line from ss output.
func (w *ConnectionWatcher) parseSSLine(line string) (event.ConnectionInfo, bool) {
	// Example: tcp   ESTAB  0      0      192.168.1.100:45678    52.94.236.248:443   users:(("curl",pid=1234,fd=3))
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return event.ConnectionInfo{}, false
	}

	localAddr, localPort, ok := parseAddrPort(fields[3])
	if !ok {
		return event.ConnectionInfo{}, false
	}

	remoteAddr, remotePort, ok := parseAddrPort(fields[4])
	if !ok {
		return event.ConnectionInfo{}, false
	}

	conn := event.ConnectionInfo{
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
		Protocol:   "tcp",
		State:      "established",
	}

	// Try to extract process info
	if len(fields) > 5 {
		processInfo := strings.Join(fields[5:], " ")
		if matches := connSSProcessRe.FindStringSubmatch(processInfo); len(matches) >= 3 {
			conn.ProcessName = matches[1]
			if pid, err := strconv.Atoi(matches[2]); err == nil {
				conn.ProcessPID = pid
			}
		}
	}

	// Try to get remote hostname
	if names, err := net.LookupAddr(remoteAddr); err == nil && len(names) > 0 {
		conn.RemoteHost = strings.TrimSuffix(names[0], ".")
	}

	// Guess service
	conn.ServiceGuess = w.guessService(remoteAddr, remotePort, conn.RemoteHost)

	return conn, true
}

// getConnectionsNetstat uses netstat as fallback.
func (w *ConnectionWatcher) getConnectionsNetstat() ([]event.ConnectionInfo, error) {
	cmd := exec.Command("netstat", "-tn")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat command failed: %w", err)
	}

	var connections []event.ConnectionInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "tcp") {
			continue
		}
		if !strings.Contains(line, "ESTABLISHED") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		localAddr, localPort, ok := parseAddrPort(fields[3])
		if !ok {
			continue
		}

		remoteAddr, remotePort, ok := parseAddrPort(fields[4])
		if !ok {
			continue
		}

		// Skip local/loopback
		if w.ignoreLocal && w.isLocalAddress(remoteAddr) {
			continue
		}
		if strings.HasPrefix(remoteAddr, "127.") || remoteAddr == "::1" {
			continue
		}

		conn := event.ConnectionInfo{
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			Protocol:   "tcp",
			State:      "established",
		}

		conn.ServiceGuess = w.guessService(remoteAddr, remotePort, "")

		// Skip control plane, kernel processes, gateway connections
		if w.shouldIgnoreConnection(conn) {
			continue
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// parseAddrPort parses "addr:port" format.
func parseAddrPort(s string) (string, int, bool) {
	// Handle IPv6 [addr]:port format
	if matches := connIPv6AddrPortRe.FindStringSubmatch(s); len(matches) == 3 {
		port, err := strconv.Atoi(matches[2])
		if err != nil {
			return "", 0, false
		}
		return matches[1], port, true
	}

	// Handle IPv4 addr:port format
	if matches := connIPv4AddrPortRe.FindStringSubmatch(s); len(matches) == 3 {
		port, err := strconv.Atoi(matches[2])
		if err != nil {
			return "", 0, false
		}
		return matches[1], port, true
	}

	// Fallback: split on last colon
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:idx], port, true
}

// shouldIgnoreConnection checks if a connection should be filtered out.
func (w *ConnectionWatcher) shouldIgnoreConnection(conn event.ConnectionInfo) bool {
	// Skip connections to control plane (agent's own outbound)
	if w.controlPlaneHost != "" {
		// Extract host from controlPlaneHost (may include port)
		cpHost := w.controlPlaneHost
		if idx := strings.LastIndex(cpHost, ":"); idx != -1 {
			// Check if it's a port (not IPv6)
			if _, err := strconv.Atoi(cpHost[idx+1:]); err == nil {
				cpHost = cpHost[:idx]
			}
		}
		// Remove protocol prefix if present
		cpHost = strings.TrimPrefix(cpHost, "http://")
		cpHost = strings.TrimPrefix(cpHost, "https://")
		if strings.HasPrefix(cpHost, conn.RemoteAddr) || conn.RemoteAddr == cpHost {
			return true
		}
	}

	// Skip kernel processes (swapper, ksoftirqd, etc.)
	if conn.ProcessName != "" {
		kernelProcesses := []string{"swapper", "ksoftirqd", "kworker", "migration", "watchdog"}
		for _, kp := range kernelProcesses {
			if strings.HasPrefix(conn.ProcessName, kp) {
				return true
			}
		}
	}

	// Skip gateway connections (VM host network)
	// The host often has trailing period like "_gateway." from DNS lookup
	host := strings.TrimSuffix(conn.RemoteHost, ".")
	if strings.Contains(host, "_gateway") || strings.HasSuffix(host, ".gateway") {
		return true
	}

	return false
}

// isLocalAddress checks if an address is local/private.
func (w *ConnectionWatcher) isLocalAddress(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	// Check for private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// guessService attempts to identify the remote service.
func (w *ConnectionWatcher) guessService(addr string, port int, hostname string) string {
	// Hostname-based identification takes priority for well-known services
	host := strings.ToLower(hostname)
	patterns := map[string]string{
		"stripe":       "stripe",
		"amazonaws":    "aws",
		"cloudfront":   "aws-cloudfront",
		"s3.":          "aws-s3",
		"rds.":         "aws-rds",
		"googleapi":    "google",
		"googleapis":   "google",
		"azure":        "azure",
		"cloudflare":   "cloudflare",
		"fastly":       "fastly",
		"akamai":       "akamai",
		"github":       "github",
		"gitlab":       "gitlab",
		"docker.io":    "docker",
		"docker.com":   "docker",
		"datadog":      "datadog",
		"sentry":       "sentry",
		"slack":        "slack",
		"twilio":       "twilio",
		"sendgrid":     "sendgrid",
		"mailgun":      "mailgun",
		"segment":      "segment",
		"intercom":     "intercom",
		"auth0":        "auth0",
		"okta":         "okta",
		"plaid":        "plaid",
		"mongodb.net":  "mongodb-atlas",
		"redis.cloud":  "redis-cloud",
		"heroku":       "heroku",
		"digitalocean": "digitalocean",
		"linode":       "linode",
		"vultr":        "vultr",
	}

	for pattern, service := range patterns {
		if strings.Contains(host, pattern) {
			return service
		}
	}

	// Fallback to port-based identification
	portServices := map[int]string{
		443:   "https",
		80:    "http",
		22:    "ssh",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
		9200:  "elasticsearch",
		8080:  "http-alt",
		8443:  "https-alt",
		53:    "dns",
		25:    "smtp",
		587:   "smtp",
		993:   "imaps",
		995:   "pop3s",
	}

	if svc, ok := portServices[port]; ok {
		return svc
	}

	return "unknown"
}
