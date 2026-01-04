//go:build linux

package watcher

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	bpf "github.com/Tesseract-Systems-Corporation/rampart-agent/internal/watcher/ebpf"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// NOTE: Memory Safety
// This implementation uses the cilium/ebpf library which is pure Go and doesn't
// use cgo for userspace operations. The BPF C code (connect.c) runs in kernel space.
// Memory from the ring buffer is copied to Go-managed byte slices by the library.
// There's no C.free() required because:
// 1. cilium/ebpf uses Go's syscall package directly, not cgo
// 2. record.RawSample is a Go []byte, not C-allocated memory
// 3. The kernel-side bpf_ringbuf_submit() doesn't allocate userspace memory
//
// If you add cgo dependencies (e.g., for libbpf), remember:
//   ptr := C.some_call()
//   defer C.free(unsafe.Pointer(ptr))

// EBPFWatcher traces TCP connections using eBPF
type EBPFWatcher struct {
	logger           *slog.Logger
	fortressID       string
	serverID         string
	controlPlaneHost string // Host to filter out (agent's own connections)

	// Container PID mapping
	containerMu   sync.RWMutex
	containerPIDs map[uint32]ContainerInfo // PID -> container info

	// eBPF resources
	collection *ebpf.Collection
	link       link.Link
	reader     *ringbuf.Reader
}

// EBPFWatcherConfig holds configuration for the eBPF watcher
type EBPFWatcherConfig struct {
	Enabled bool `yaml:"enabled"`
}

// connEvent matches the C struct conn_event
type connEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	UID       uint32
	SaddrV4   uint32
	DaddrV4   uint32
	SaddrV6   [16]byte
	DaddrV6   [16]byte
	Sport     uint16
	Dport     uint16
	Family    uint16
	EventType uint8
	Protocol  uint8
	Comm      [16]byte
}

const (
	eventConnect = 1
	eventClose   = 2

	afINET  = 2
	afINET6 = 10
)

// NewEBPFWatcher creates a new eBPF-based connection watcher
func NewEBPFWatcher(logger *slog.Logger, fortressID, serverID, controlPlaneHost string) (*EBPFWatcher, error) {
	w := &EBPFWatcher{
		logger:           logger.With("watcher", "ebpf"),
		fortressID:       fortressID,
		serverID:         serverID,
		controlPlaneHost: controlPlaneHost,
		containerPIDs:    make(map[uint32]ContainerInfo),
	}

	if err := w.loadBPF(); err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}

	return w, nil
}

// loadBPF loads the compiled BPF program
func (w *EBPFWatcher) loadBPF() error {
	// Load the compiled BPF program
	spec, err := bpf.LoadConnect()
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	w.collection = coll

	// Attach to the tracepoint
	prog := coll.Programs["trace_tcp_state"]
	if prog == nil {
		coll.Close()
		return errors.New("BPF program 'trace_tcp_state' not found")
	}

	l, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		coll.Close()
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	w.link = l

	// Open ring buffer reader
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		l.Close()
		coll.Close()
		return errors.New("BPF map 'events' not found")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		l.Close()
		coll.Close()
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	w.reader = reader

	w.logger.Info("eBPF connection tracer loaded")
	return nil
}

// Name returns the watcher name
func (w *EBPFWatcher) Name() string {
	return "ebpf"
}

// Watch starts watching for connection events and returns a channel of events.
func (w *EBPFWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event, 100)

	go func() {
		defer close(out)
		w.logger.Info("starting eBPF connection watcher")

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := w.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				w.logger.Error("read ring buffer", "error", err)
				continue
			}

			ev, err := w.parseEvent(record.RawSample)
			if err != nil {
				w.logger.Debug("parse event failed", "error", err)
				continue
			}

			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}

// shouldFilterConnection checks if a connection should be filtered out
func (w *EBPFWatcher) shouldFilterConnection(remoteAddr, remoteHost, processName string) bool {
	// Skip connections to control plane (agent's own outbound)
	if w.controlPlaneHost != "" {
		cpHost := w.controlPlaneHost
		// Strip port if present
		if idx := strings.LastIndex(cpHost, ":"); idx != -1 {
			cpHost = cpHost[:idx]
		}
		// Strip protocol if present
		cpHost = strings.TrimPrefix(cpHost, "http://")
		cpHost = strings.TrimPrefix(cpHost, "https://")
		if strings.HasPrefix(cpHost, remoteAddr) || remoteAddr == cpHost {
			return true
		}
	}

	// Skip kernel processes (swapper, ksoftirqd, etc.)
	if processName != "" {
		kernelProcesses := []string{"swapper", "ksoftirqd", "kworker", "migration", "watchdog", "rcu_"}
		for _, kp := range kernelProcesses {
			if strings.HasPrefix(processName, kp) {
				return true
			}
		}
	}

	// Skip gateway connections (VM host network)
	if remoteHost != "" {
		host := strings.TrimSuffix(remoteHost, ".")
		if strings.Contains(host, "_gateway") || strings.HasSuffix(host, ".gateway") {
			return true
		}
	}

	// Skip loopback
	if strings.HasPrefix(remoteAddr, "127.") || remoteAddr == "::1" {
		return true
	}

	return false
}

// parseEvent converts a raw BPF event to a Rampart event
func (w *EBPFWatcher) parseEvent(data []byte) (event.Event, error) {
	if len(data) < 72 { // minimum size of conn_event
		return event.Event{}, errors.New("event too short")
	}

	var ev connEvent
	ev.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	ev.PID = binary.LittleEndian.Uint32(data[8:12])
	ev.TID = binary.LittleEndian.Uint32(data[12:16])
	ev.UID = binary.LittleEndian.Uint32(data[16:20])
	ev.SaddrV4 = binary.LittleEndian.Uint32(data[20:24])
	ev.DaddrV4 = binary.LittleEndian.Uint32(data[24:28])
	copy(ev.SaddrV6[:], data[28:44])
	copy(ev.DaddrV6[:], data[44:60])
	ev.Sport = binary.LittleEndian.Uint16(data[60:62])
	ev.Dport = binary.LittleEndian.Uint16(data[62:64])
	ev.Family = binary.LittleEndian.Uint16(data[64:66])
	ev.EventType = data[66]
	ev.Protocol = data[67]
	copy(ev.Comm[:], data[68:84])

	// Parse addresses
	var localAddr, remoteAddr string
	if ev.Family == afINET {
		localAddr = intToIP(ev.SaddrV4)
		remoteAddr = intToIP(ev.DaddrV4)
	} else if ev.Family == afINET6 {
		localAddr = net.IP(ev.SaddrV6[:]).String()
		remoteAddr = net.IP(ev.DaddrV6[:]).String()
	}

	// Get process name (null-terminated)
	comm := ""
	for i, b := range ev.Comm {
		if b == 0 {
			comm = string(ev.Comm[:i])
			break
		}
	}
	if comm == "" {
		comm = string(ev.Comm[:])
	}

	// Check if this is a container process
	containerName := ""
	containerID := ""
	w.containerMu.RLock()
	if info, ok := w.containerPIDs[ev.PID]; ok {
		containerName = info.Name
		containerID = info.ID
	}
	w.containerMu.RUnlock()

	// If not in our cache, try to detect from cgroup
	if containerName == "" {
		if cid := getContainerIDFromPID(int(ev.PID)); cid != "" {
			containerID = cid
			containerName = cid[:12] // Short ID as name fallback
		}
	}

	// Build connection info
	connInfo := event.ConnectionInfo{
		LocalAddr:   localAddr,
		LocalPort:   int(ev.Sport),
		RemoteAddr:  remoteAddr,
		RemotePort:  int(ev.Dport),
		Protocol:    "tcp",
		ProcessName: comm,
		ProcessPID:  int(ev.PID),
	}

	// Guess service
	connInfo.ServiceGuess = guessServiceByPort(remoteAddr, int(ev.Dport))

	// Try reverse DNS
	if names, err := net.LookupAddr(remoteAddr); err == nil && len(names) > 0 {
		connInfo.RemoteHost = names[0]
	}

	// Filter out noisy connections
	if w.shouldFilterConnection(remoteAddr, connInfo.RemoteHost, comm) {
		return event.Event{}, errors.New("filtered connection")
	}

	// Determine event type
	var eventType event.EventType
	if ev.EventType == eventConnect {
		eventType = event.ConnectionEstablished
	} else {
		eventType = event.ConnectionClosed
	}

	payload := map[string]any{
		"connection": connInfo,
	}
	if containerID != "" {
		payload["container_id"] = containerID
		payload["container_name"] = containerName
	}

	return event.NewEvent(
		eventType,
		w.fortressID,
		w.serverID,
		payload,
	), nil
}

// RegisterContainerPID associates a PID with a container
func (w *EBPFWatcher) RegisterContainerPID(pid uint32, info ContainerInfo) {
	w.containerMu.Lock()
	w.containerPIDs[pid] = info
	w.containerMu.Unlock()
}

// UnregisterContainerPID removes a container PID association
func (w *EBPFWatcher) UnregisterContainerPID(pid uint32) {
	w.containerMu.Lock()
	delete(w.containerPIDs, pid)
	w.containerMu.Unlock()
}

// Close releases eBPF resources
func (w *EBPFWatcher) Close() error {
	if w.reader != nil {
		w.reader.Close()
	}
	if w.link != nil {
		w.link.Close()
	}
	if w.collection != nil {
		w.collection.Close()
	}
	return nil
}

// intToIP converts a uint32 to an IP address string
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// IsEBPFSupported checks if eBPF is available on this system
func IsEBPFSupported() bool {
	// Check if we're on Linux
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false
	}
	// Check if we have CAP_BPF or are root
	if os.Geteuid() != 0 {
		// Could check capabilities more precisely, but root check is sufficient for most cases
		return false
	}
	return true
}

// getContainerIDFromPID extracts the container ID from a process's cgroup.
// Returns empty string if not in a container.
func getContainerIDFromPID(pid int) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	// Look for docker/containerd container ID patterns in cgroup paths
	// Examples:
	// - /docker/abc123...
	// - /docker.slice/docker-abc123....scope
	// - /system.slice/containerd.service/kubepods/.../abc123...
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]

		// Docker pattern: /docker/<container_id>
		if idx := strings.Index(path, "/docker/"); idx != -1 {
			id := path[idx+8:]
			if len(id) >= 12 {
				// Remove any trailing path components
				if slashIdx := strings.Index(id, "/"); slashIdx != -1 {
					id = id[:slashIdx]
				}
				return id
			}
		}

		// Docker systemd pattern: docker-<container_id>.scope
		if strings.Contains(path, "docker-") && strings.HasSuffix(path, ".scope") {
			// Extract ID from docker-<id>.scope
			start := strings.LastIndex(path, "docker-")
			if start != -1 {
				id := path[start+7:]
				if dotIdx := strings.Index(id, "."); dotIdx != -1 {
					id = id[:dotIdx]
				}
				if len(id) >= 12 {
					return id
				}
			}
		}

		// containerd/cri-containerd pattern: /<pod_id>/.../<container_id>
		if strings.Contains(path, "cri-containerd-") {
			// Extract container ID after cri-containerd-
			start := strings.Index(path, "cri-containerd-")
			if start != -1 {
				id := path[start+15:]
				if dotIdx := strings.Index(id, "."); dotIdx != -1 {
					id = id[:dotIdx]
				}
				if len(id) >= 12 {
					return id
				}
			}
		}
	}

	return ""
}
