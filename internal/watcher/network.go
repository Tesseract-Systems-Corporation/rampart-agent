package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DoorCallback is called when doors are opened or closed.
type DoorCallback func(port int, opened bool)

// NetworkConfig holds configuration for the Network watcher.
type NetworkConfig struct {
	// ScanInterval is how often to scan for listening ports.
	// Defaults to 5 minutes if zero.
	ScanInterval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger

	// OnDoorChange is called when a door opens or closes.
	// This is used to notify other watchers (e.g., encryption) of port changes.
	OnDoorChange DoorCallback

	// TrackOutbound enables tracking of outbound connections (for embassy detection).
	// Defaults to true.
	TrackOutbound *bool
}

// NetworkWatcher monitors network port exposure.
type NetworkWatcher struct {
	scanInterval        time.Duration
	fortressID          string
	serverID            string
	logger              *slog.Logger
	previousPorts       *listeningPortsSet
	previousConnections *outboundConnectionSet
	trackOutbound       bool
	mu                  sync.Mutex
	onDoorChange        DoorCallback
}

// ListeningPort represents a port that is listening for connections.
type ListeningPort struct {
	Port     int
	Protocol string // tcp, udp
	Binding  string // public, private
	Process  string
	SSL      bool
}

// OutboundConnection represents an outbound network connection.
type OutboundConnection struct {
	RemoteHost    string // IP address or hostname
	RemotePort    int
	Protocol      string // tcp, udp
	Process       string
	ContainerName string // Docker container name if applicable
	ContainerID   string // Docker container ID if applicable
}

// NewNetworkWatcher creates a new NetworkWatcher with the given configuration.
func NewNetworkWatcher(cfg NetworkConfig) *NetworkWatcher {
	scanInterval := cfg.ScanInterval
	if scanInterval == 0 {
		scanInterval = 5 * time.Minute
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Default to tracking outbound connections
	trackOutbound := true
	if cfg.TrackOutbound != nil {
		trackOutbound = *cfg.TrackOutbound
	}

	return &NetworkWatcher{
		scanInterval:        scanInterval,
		fortressID:          cfg.FortressID,
		serverID:            cfg.ServerID,
		logger:              logger,
		previousPorts:       newListeningPortsSet(),
		previousConnections: newOutboundConnectionSet(),
		trackOutbound:       trackOutbound,
		onDoorChange:        cfg.OnDoorChange,
	}
}

// Watch starts watching network ports and returns a channel of events.
func (w *NetworkWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting network watcher", "interval", w.scanInterval)

		// Initial scan
		w.scanAndEmit(ctx, out)

		ticker := time.NewTicker(w.scanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("network watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.scanAndEmit(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *NetworkWatcher) Name() string {
	return "network"
}

// GetOpenPorts returns the current list of open ports.
// This is useful for other watchers (like encryption) that need to probe TLS endpoints.
func (w *NetworkWatcher) GetOpenPorts() []int {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.previousPorts == nil {
		return nil
	}

	ports := make([]int, 0)
	for _, p := range w.previousPorts.List() {
		ports = append(ports, p.Port)
	}
	return ports
}

// scanAndEmit scans for listening ports and emits events for changes.
func (w *NetworkWatcher) scanAndEmit(ctx context.Context, out chan<- event.Event) {
	currentPorts := w.scanPorts()

	w.mu.Lock()
	opened, closed := comparePorts(w.previousPorts, currentPorts)
	w.previousPorts = currentPorts
	w.mu.Unlock()

	// Emit events for opened ports (doors)
	for _, port := range opened {
		w.logger.Info("door opened",
			"port", port.Port,
			"protocol", port.Protocol,
			"binding", port.Binding,
			"process", port.Process,
		)

		// Notify callback (e.g., encryption watcher)
		if w.onDoorChange != nil {
			w.onDoorChange(port.Port, true)
		}

		e := createNetworkEvent(event.ExposureDoorOpened, port, w.fortressID, w.serverID)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}

	// Emit events for closed ports
	for _, port := range closed {
		w.logger.Info("door closed",
			"port", port.Port,
			"protocol", port.Protocol,
		)

		// Notify callback (e.g., encryption watcher)
		if w.onDoorChange != nil {
			w.onDoorChange(port.Port, false)
		}

		e := createNetworkEvent(event.ExposureDoorClosed, port, w.fortressID, w.serverID)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}

	// Scan outbound connections if enabled
	if w.trackOutbound {
		w.scanAndEmitOutbound(ctx, out)
	}
}

// scanAndEmitOutbound scans for outbound connections and emits events for changes.
func (w *NetworkWatcher) scanAndEmitOutbound(ctx context.Context, out chan<- event.Event) {
	currentConns := w.scanOutboundConnections()

	w.mu.Lock()
	established, closed := compareConnections(w.previousConnections, currentConns)
	w.previousConnections = currentConns
	w.mu.Unlock()

	// Emit events for new outbound connections
	for _, conn := range established {
		w.logger.Info("outbound connection established",
			"remote_host", conn.RemoteHost,
			"remote_port", conn.RemotePort,
			"process", conn.Process,
			"container", conn.ContainerName,
		)

		e := createConnectionEvent(event.ConnectionEstablished, conn, w.fortressID, w.serverID)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}

	// Emit events for closed connections
	for _, conn := range closed {
		w.logger.Info("outbound connection closed",
			"remote_host", conn.RemoteHost,
			"remote_port", conn.RemotePort,
		)

		e := createConnectionEvent(event.ConnectionClosed, conn, w.fortressID, w.serverID)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}
}

// scanPorts scans for listening ports using netstat or ss.
func (w *NetworkWatcher) scanPorts() *listeningPortsSet {
	ports := newListeningPortsSet()

	// Try ss first (faster), fall back to netstat
	usingSS := true
	output, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		usingSS = false
		output, err = exec.Command("netstat", "-tlnp").Output()
		if err != nil {
			w.logger.Error("failed to scan ports", "error", err)
			return ports
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if port := parseLine(scanner.Text(), "tcp", usingSS); port != nil {
			// Check for SSL by looking at common SSL ports
			port.SSL = isSSLPort(port.Port)
			ports.Add(*port)
		}
	}

	// Also scan UDP
	output, err = exec.Command("ss", "-ulnp").Output()
	if err != nil {
		usingSS = false
		output, _ = exec.Command("netstat", "-ulnp").Output()
	} else {
		usingSS = true
	}

	scanner = bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if port := parseLine(scanner.Text(), "udp", usingSS); port != nil {
			ports.Add(*port)
		}
	}

	return ports
}

// Regex for parsing netstat/ss output
var (
	// Matches process like "1234/nginx" or "pid=1234,comm=nginx" or users:(("sshd",pid=123,fd=4))
	processRe      = regexp.MustCompile(`(?:(\d+)/(\S+)|pid=(\d+),comm=(\S+)|\(\("([^"]+)",pid=)`)
	// Matches IPv6 address like [::]:22 or [::1]:22
	ipv6AddrPortRe = regexp.MustCompile(`^\[([^\]]*)\]:(\d+)$`)
)

// parseLine parses a single line from netstat or ss output.
// protocol is the expected protocol ("tcp" or "udp") from the command flags.
// usingSS indicates if the output is from ss (true) or netstat (false).
func parseLine(line string, protocol string, usingSS bool) *ListeningPort {
	if line == "" {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	// For ss output, first field is State (LISTEN, UNCONN, etc.)
	// For netstat output, first field is protocol (tcp, udp, etc.)
	if usingSS {
		// ss format: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
		// Skip header line
		if fields[0] == "State" || fields[0] == "Netid" {
			return nil
		}
		// TCP must be in LISTEN state
		if protocol == "tcp" && fields[0] != "LISTEN" {
			return nil
		}
		// UDP shows as UNCONN for listening
		if protocol == "udp" && fields[0] != "UNCONN" {
			return nil
		}
	} else {
		// netstat format: Proto Recv-Q Send-Q Local-Address Foreign-Address State PID/Program
		// Check protocol matches
		if !strings.HasPrefix(fields[0], protocol) {
			return nil
		}
		// Check for LISTEN state (TCP only)
		if protocol == "tcp" && !strings.Contains(line, "LISTEN") {
			return nil
		}
	}

	// Find the local address field
	// For ss: field 3 (0-indexed)
	// For netstat: field 3 (0-indexed)
	localAddrIdx := 3
	if len(fields) <= localAddrIdx {
		return nil
	}
	localAddr := fields[localAddrIdx]

	// Parse port from address
	var port int
	var binding string

	// Handle IPv6 format like [::]:22 or [::1]:22
	if strings.HasPrefix(localAddr, "[") {
		matches := ipv6AddrPortRe.FindStringSubmatch(localAddr)
		if matches != nil {
			port, _ = strconv.Atoi(matches[2])
			addr := matches[1]
			if addr == "::1" || addr == "" {
				// ::1 is loopback, but [::] means all interfaces (public)
				if addr == "::1" {
					binding = "private"
				} else {
					binding = "public"
				}
			} else {
				binding = "public"
			}
		}
	} else {
		// Handle IPv4 format like 0.0.0.0:22 or 127.0.0.1:22 or 127.0.0.53%lo:53
		// Remove interface suffix like %lo (appears before the colon+port)
		// Format is ADDR%IFACE:PORT
		if idx := strings.Index(localAddr, "%"); idx != -1 {
			// Find the colon after the % to get the port
			colonIdx := strings.LastIndex(localAddr, ":")
			if colonIdx > idx {
				// Remove the %IFACE part but keep the :PORT
				localAddr = localAddr[:idx] + localAddr[colonIdx:]
			}
		}

		parts := strings.Split(localAddr, ":")
		if len(parts) >= 2 {
			portStr := parts[len(parts)-1]
			port, _ = strconv.Atoi(portStr)

			// Determine binding from address
			addr := strings.Join(parts[:len(parts)-1], ":")
			if strings.HasPrefix(addr, "127.") || addr == "::1" {
				binding = "private"
			} else if addr == "0.0.0.0" || addr == "*" || addr == "::" {
				binding = "public"
			} else {
				// Specific IP - check if it's a private range
				binding = "public" // Default to public for specific IPs
			}
		}
	}

	if port == 0 {
		return nil
	}

	// Find process name
	process := ""
	for _, field := range fields {
		if matches := processRe.FindStringSubmatch(field); matches != nil {
			if matches[2] != "" {
				process = matches[2]
			} else if matches[4] != "" {
				process = matches[4]
			} else if matches[5] != "" {
				process = matches[5]
			}
			break
		}
	}

	return &ListeningPort{
		Port:     port,
		Protocol: protocol,
		Binding:  binding,
		Process:  process,
	}
}

// isSSLPort returns true if the port is commonly used for SSL/TLS.
func isSSLPort(port int) bool {
	sslPorts := map[int]bool{
		443:  true,
		8443: true,
		993:  true, // IMAPS
		995:  true, // POP3S
		465:  true, // SMTPS
		636:  true, // LDAPS
	}
	return sslPorts[port]
}

// listeningPortsSet is a set of listening ports for easy comparison.
type listeningPortsSet struct {
	ports map[string]ListeningPort
}

func newListeningPortsSet() *listeningPortsSet {
	return &listeningPortsSet{
		ports: make(map[string]ListeningPort),
	}
}

func (s *listeningPortsSet) key(port int, protocol string) string {
	return strconv.Itoa(port) + "/" + protocol
}

func (s *listeningPortsSet) Add(p ListeningPort) {
	s.ports[s.key(p.Port, p.Protocol)] = p
}

func (s *listeningPortsSet) Contains(port int, protocol string) bool {
	_, ok := s.ports[s.key(port, protocol)]
	return ok
}

func (s *listeningPortsSet) List() []ListeningPort {
	result := make([]ListeningPort, 0, len(s.ports))
	for _, p := range s.ports {
		result = append(result, p)
	}
	return result
}

// comparePorts compares two sets of ports and returns opened and closed ports.
func comparePorts(previous, current *listeningPortsSet) (opened, closed []ListeningPort) {
	// Find newly opened ports
	for key, port := range current.ports {
		if _, exists := previous.ports[key]; !exists {
			opened = append(opened, port)
		}
	}

	// Find closed ports
	for key, port := range previous.ports {
		if _, exists := current.ports[key]; !exists {
			closed = append(closed, port)
		}
	}

	return
}

// createNetworkEvent creates an event for a port change.
func createNetworkEvent(eventType event.EventType, port ListeningPort, fortressID, serverID string) event.Event {
	return event.NewEvent(eventType, fortressID, serverID, map[string]any{
		"port":     port.Port,
		"protocol": port.Protocol,
		"binding":  port.Binding,
		"process":  port.Process,
		"tls":      port.SSL,
	})
}

// createConnectionEvent creates an event for an outbound connection change.
func createConnectionEvent(eventType event.EventType, conn OutboundConnection, fortressID, serverID string) event.Event {
	return event.NewEvent(eventType, fortressID, serverID, map[string]any{
		"remote_host":    conn.RemoteHost,
		"remote_port":    conn.RemotePort,
		"protocol":       conn.Protocol,
		"process":        conn.Process,
		"container_name": conn.ContainerName,
		"container_id":   conn.ContainerID,
		"direction":      "outbound",
	})
}

// scanOutboundConnections scans for established outbound TCP connections.
func (w *NetworkWatcher) scanOutboundConnections() *outboundConnectionSet {
	conns := newOutboundConnectionSet()

	// Use ss to get established connections with process info
	// ss -tnp state established
	output, err := exec.Command("ss", "-tnp", "state", "established").Output()
	if err != nil {
		w.logger.Error("failed to scan outbound connections", "error", err)
		return conns
	}

	// Get container PIDs for mapping
	containerPIDs := w.getContainerPIDs()

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		conn := w.parseOutboundConnection(line, containerPIDs)
		if conn != nil && !isIgnoredConnection(conn) {
			conns.Add(*conn)
		}
	}

	return conns
}

// parseOutboundConnection parses a line from ss output into an OutboundConnection.
// Format: Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
func (w *NetworkWatcher) parseOutboundConnection(line string, containerPIDs map[int]containerInfo) *OutboundConnection {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	// Skip header
	if fields[0] == "Recv-Q" {
		return nil
	}

	// Parse peer address (remote)
	peerAddr := fields[3]
	remoteHost, remotePort := parseHostPort(peerAddr)
	if remoteHost == "" || remotePort == 0 {
		return nil
	}

	// Skip localhost connections
	if isLocalhost(remoteHost) {
		return nil
	}

	// Parse process info
	process := ""
	var pid int
	if len(fields) > 4 {
		process, pid = parseProcessInfo(fields[4])
	}

	// Check if this is a container process
	var containerName, containerID string
	if pid > 0 {
		if info, ok := containerPIDs[pid]; ok {
			containerName = info.name
			containerID = info.id
		}
	}

	return &OutboundConnection{
		RemoteHost:    remoteHost,
		RemotePort:    remotePort,
		Protocol:      "tcp",
		Process:       process,
		ContainerName: containerName,
		ContainerID:   containerID,
	}
}

// parseHostPort parses an address:port string into host and port.
func parseHostPort(addr string) (string, int) {
	// Handle IPv6 format [host]:port
	if strings.HasPrefix(addr, "[") {
		matches := ipv6AddrPortRe.FindStringSubmatch(addr)
		if matches != nil {
			port, _ := strconv.Atoi(matches[2])
			return matches[1], port
		}
		return "", 0
	}

	// IPv4 format host:port
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return "", 0
	}

	host := addr[:idx]
	port, _ := strconv.Atoi(addr[idx+1:])
	return host, port
}

// parseProcessInfo extracts process name and PID from ss process field.
// Format: users:(("curl",pid=1234,fd=3))
func parseProcessInfo(field string) (string, int) {
	matches := processRe.FindStringSubmatch(field)
	if matches == nil {
		return "", 0
	}

	var name string
	var pid int

	if matches[2] != "" {
		name = matches[2]
		pid, _ = strconv.Atoi(matches[1])
	} else if matches[4] != "" {
		name = matches[4]
		pid, _ = strconv.Atoi(matches[3])
	} else if matches[5] != "" {
		name = matches[5]
		// Need to extract PID from the rest
		if pidMatch := regexp.MustCompile(`pid=(\d+)`).FindStringSubmatch(field); pidMatch != nil {
			pid, _ = strconv.Atoi(pidMatch[1])
		}
	}

	return name, pid
}

// isLocalhost returns true if the address is a localhost address.
func isLocalhost(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || strings.HasPrefix(addr, "127.")
}

// isIgnoredConnection returns true if this connection should be auto-ignored.
// This filters out system infrastructure that generates noise.
func isIgnoredConnection(conn *OutboundConnection) bool {
	// DNS (port 53)
	if conn.RemotePort == 53 {
		return true
	}

	// NTP (port 123)
	if conn.RemotePort == 123 {
		return true
	}

	// Cloud metadata service (169.254.169.254)
	if conn.RemoteHost == "169.254.169.254" {
		return true
	}

	// Link-local addresses (169.254.x.x)
	if strings.HasPrefix(conn.RemoteHost, "169.254.") {
		return true
	}

	return false
}

// containerInfo holds container identification info.
type containerInfo struct {
	id   string
	name string
}

// getContainerPIDs returns a map of PID -> container info for running containers.
func (w *NetworkWatcher) getContainerPIDs() map[int]containerInfo {
	result := make(map[int]containerInfo)

	// Try to get container info from docker
	output, err := exec.Command("docker", "ps", "-q").Output()
	if err != nil {
		return result
	}

	containerIDs := strings.Fields(string(output))
	for _, id := range containerIDs {
		// Get container name and PID
		inspect, err := exec.Command("docker", "inspect", "--format", "{{.Name}} {{.State.Pid}}", id).Output()
		if err != nil {
			continue
		}

		parts := strings.Fields(string(inspect))
		if len(parts) >= 2 {
			name := strings.TrimPrefix(parts[0], "/")
			pid, _ := strconv.Atoi(parts[1])
			if pid > 0 {
				result[pid] = containerInfo{id: id, name: name}
			}
		}
	}

	return result
}

// outboundConnectionSet is a set of outbound connections for tracking changes.
type outboundConnectionSet struct {
	conns map[string]OutboundConnection
}

func newOutboundConnectionSet() *outboundConnectionSet {
	return &outboundConnectionSet{
		conns: make(map[string]OutboundConnection),
	}
}

func (s *outboundConnectionSet) key(conn OutboundConnection) string {
	// Key by remote host:port (we don't care about local port for tracking)
	return conn.RemoteHost + ":" + strconv.Itoa(conn.RemotePort)
}

func (s *outboundConnectionSet) Add(conn OutboundConnection) {
	s.conns[s.key(conn)] = conn
}

func (s *outboundConnectionSet) List() []OutboundConnection {
	result := make([]OutboundConnection, 0, len(s.conns))
	for _, c := range s.conns {
		result = append(result, c)
	}
	return result
}

// compareConnections compares two sets of connections and returns established and closed connections.
func compareConnections(previous, current *outboundConnectionSet) (established, closed []OutboundConnection) {
	// Find newly established connections
	for key, conn := range current.conns {
		if _, exists := previous.conns[key]; !exists {
			established = append(established, conn)
		}
	}

	// Find closed connections
	for key, conn := range previous.conns {
		if _, exists := current.conns[key]; !exists {
			closed = append(closed, conn)
		}
	}

	return
}
