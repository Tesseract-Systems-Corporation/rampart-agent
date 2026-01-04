package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestNetworkWatcherInterface(t *testing.T) {
	var _ Watcher = (*NetworkWatcher)(nil)
}

func TestNetworkWatcherName(t *testing.T) {
	w := NewNetworkWatcher(NetworkConfig{
		ScanInterval: 5 * time.Minute,
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})
	if w.Name() != "network" {
		t.Errorf("Name() = %v, want network", w.Name())
	}
}

func TestNetworkWatcherConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       NetworkConfig
		wantInterval time.Duration
	}{
		{
			name: "default interval",
			config: NetworkConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: 5 * time.Minute,
		},
		{
			name: "custom interval",
			config: NetworkConfig{
				ScanInterval: 10 * time.Minute,
				FortressID:   "fort_test",
				ServerID:     "srv_test",
			},
			wantInterval: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewNetworkWatcher(tt.config)
			if w.scanInterval != tt.wantInterval {
				t.Errorf("scanInterval = %v, want %v", w.scanInterval, tt.wantInterval)
			}
		})
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		protocol    string
		usingSS     bool
		wantPort    int
		wantBinding string
		wantProcess string
		wantNil     bool
	}{
		// netstat format tests
		{
			name:        "netstat tcp listening on all interfaces",
			line:        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1234/nginx",
			protocol:    "tcp",
			usingSS:     false,
			wantPort:    80,
			wantBinding: "public",
			wantProcess: "nginx",
		},
		{
			name:        "netstat tcp listening on localhost",
			line:        "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      5678/postgres",
			protocol:    "tcp",
			usingSS:     false,
			wantPort:    5432,
			wantBinding: "private",
			wantProcess: "postgres",
		},
		{
			name:        "netstat udp listening",
			line:        "udp        0      0 0.0.0.0:53              0.0.0.0:*                           9999/dnsmasq",
			protocol:    "udp",
			usingSS:     false,
			wantPort:    53,
			wantBinding: "public",
			wantProcess: "dnsmasq",
		},
		{
			name:     "netstat established connection (not listening)",
			line:     "tcp        0      0 192.168.1.10:22         192.168.1.5:54321       ESTABLISHED 1234/sshd",
			protocol: "tcp",
			usingSS:  false,
			wantNil:  true,
		},
		// ss format tests
		{
			name:        "ss tcp listening on all interfaces",
			line:        "LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*",
			protocol:    "tcp",
			usingSS:     true,
			wantPort:    22,
			wantBinding: "public",
		},
		{
			name:        "ss tcp listening on localhost",
			line:        "LISTEN 0      4096      127.0.0.54:53        0.0.0.0:*",
			protocol:    "tcp",
			usingSS:     true,
			wantPort:    53,
			wantBinding: "private",
		},
		{
			name:        "ss tcp listening with interface suffix",
			line:        "LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*",
			protocol:    "tcp",
			usingSS:     true,
			wantPort:    53,
			wantBinding: "private",
		},
		{
			name:        "ss tcp listening IPv6 all interfaces",
			line:        "LISTEN 0      4096            [::]:22           [::]:*",
			protocol:    "tcp",
			usingSS:     true,
			wantPort:    22,
			wantBinding: "public",
		},
		{
			name:        "ss tcp listening with process",
			line:        `LISTEN 0      4096         0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=1234,fd=6))`,
			protocol:    "tcp",
			usingSS:     true,
			wantPort:    80,
			wantBinding: "public",
			wantProcess: "nginx",
		},
		{
			name:     "ss header line",
			line:     "State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess",
			protocol: "tcp",
			usingSS:  true,
			wantNil:  true,
		},
		{
			name:     "ss udp unconn state",
			line:     "UNCONN 0      0            0.0.0.0:68        0.0.0.0:*",
			protocol: "udp",
			usingSS:  true,
			wantPort: 68,
			wantBinding: "public",
		},
		// Common invalid cases
		{
			name:     "invalid line",
			line:     "invalid",
			protocol: "tcp",
			usingSS:  false,
			wantNil:  true,
		},
		{
			name:     "empty line",
			line:     "",
			protocol: "tcp",
			usingSS:  false,
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLine(tt.line, tt.protocol, tt.usingSS)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected result, got nil")
			}

			if result.Port != tt.wantPort {
				t.Errorf("Port = %v, want %v", result.Port, tt.wantPort)
			}
			if result.Protocol != tt.protocol {
				t.Errorf("Protocol = %v, want %v", result.Protocol, tt.protocol)
			}
			if result.Binding != tt.wantBinding {
				t.Errorf("Binding = %v, want %v", result.Binding, tt.wantBinding)
			}
			if tt.wantProcess != "" && result.Process != tt.wantProcess {
				t.Errorf("Process = %v, want %v", result.Process, tt.wantProcess)
			}
		})
	}
}

func TestListeningPortsSet(t *testing.T) {
	ports := newListeningPortsSet()

	// Add some ports
	ports.Add(ListeningPort{Port: 80, Protocol: "tcp", Binding: "public", Process: "nginx"})
	ports.Add(ListeningPort{Port: 443, Protocol: "tcp", Binding: "public", Process: "nginx"})
	ports.Add(ListeningPort{Port: 5432, Protocol: "tcp", Binding: "private", Process: "postgres"})

	// Test Contains
	if !ports.Contains(80, "tcp") {
		t.Error("expected to contain port 80 tcp")
	}
	if !ports.Contains(443, "tcp") {
		t.Error("expected to contain port 443 tcp")
	}
	if ports.Contains(8080, "tcp") {
		t.Error("expected not to contain port 8080 tcp")
	}

	// Test List
	list := ports.List()
	if len(list) != 3 {
		t.Errorf("List() returned %d items, want 3", len(list))
	}
}

func TestComparePorts(t *testing.T) {
	previous := newListeningPortsSet()
	previous.Add(ListeningPort{Port: 80, Protocol: "tcp", Binding: "public", Process: "nginx"})
	previous.Add(ListeningPort{Port: 22, Protocol: "tcp", Binding: "public", Process: "sshd"})

	current := newListeningPortsSet()
	current.Add(ListeningPort{Port: 80, Protocol: "tcp", Binding: "public", Process: "nginx"})
	current.Add(ListeningPort{Port: 443, Protocol: "tcp", Binding: "public", Process: "nginx"})

	opened, closed := comparePorts(previous, current)

	// Should have one opened (443) and one closed (22)
	if len(opened) != 1 {
		t.Errorf("opened = %d, want 1", len(opened))
	}
	if len(opened) > 0 && opened[0].Port != 443 {
		t.Errorf("opened port = %d, want 443", opened[0].Port)
	}

	if len(closed) != 1 {
		t.Errorf("closed = %d, want 1", len(closed))
	}
	if len(closed) > 0 && closed[0].Port != 22 {
		t.Errorf("closed port = %d, want 22", closed[0].Port)
	}
}

func TestNetworkWatcherContextCancellation(t *testing.T) {
	w := NewNetworkWatcher(NetworkConfig{
		ScanInterval: 1 * time.Hour, // Long interval
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Cancel immediately
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

func TestCreateNetworkEvent(t *testing.T) {
	port := ListeningPort{
		Port:     80,
		Protocol: "tcp",
		Binding:  "public",
		Process:  "nginx",
		SSL:      true,
	}

	e := createNetworkEvent(event.ExposureDoorOpened, port, "fort_test", "srv_test")

	if e.Type != event.ExposureDoorOpened {
		t.Errorf("Type = %v, want %v", e.Type, event.ExposureDoorOpened)
	}

	payload := e.Payload
	if payload["port"] != 80 {
		t.Errorf("port = %v, want 80", payload["port"])
	}
	if payload["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp", payload["protocol"])
	}
	if payload["binding"] != "public" {
		t.Errorf("binding = %v, want public", payload["binding"])
	}
	if payload["process"] != "nginx" {
		t.Errorf("process = %v, want nginx", payload["process"])
	}
	if payload["tls"] != true {
		t.Errorf("tls = %v, want true", payload["tls"])
	}
}
