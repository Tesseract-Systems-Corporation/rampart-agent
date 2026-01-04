package watcher

import (
	"testing"
)

func TestParseAddrPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAddr string
		wantPort int
		wantOK   bool
	}{
		{
			name:     "ipv4 standard",
			input:    "192.168.1.100:8080",
			wantAddr: "192.168.1.100",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name:     "ipv4 https",
			input:    "52.94.236.248:443",
			wantAddr: "52.94.236.248",
			wantPort: 443,
			wantOK:   true,
		},
		{
			name:     "ipv6 bracketed",
			input:    "[::1]:8080",
			wantAddr: "::1",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name:     "ipv6 full bracketed",
			input:    "[2001:db8::1]:443",
			wantAddr: "2001:db8::1",
			wantPort: 443,
			wantOK:   true,
		},
		{
			name:   "invalid no port",
			input:  "192.168.1.100",
			wantOK: false,
		},
		{
			name:   "invalid port",
			input:  "192.168.1.100:abc",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, port, ok := parseAddrPort(tt.input)
			if ok != tt.wantOK {
				t.Errorf("parseAddrPort(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if addr != tt.wantAddr {
				t.Errorf("parseAddrPort(%q) addr = %q, want %q", tt.input, addr, tt.wantAddr)
			}
			if port != tt.wantPort {
				t.Errorf("parseAddrPort(%q) port = %d, want %d", tt.input, port, tt.wantPort)
			}
		})
	}
}

func TestConnectionWatcher_IsLocalAddress(t *testing.T) {
	w := &ConnectionWatcher{}

	tests := []struct {
		addr string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"8.8.8.8", false},
		{"52.94.236.248", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := w.isLocalAddress(tt.addr)
			if got != tt.want {
				t.Errorf("isLocalAddress(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestConnectionWatcher_GuessService(t *testing.T) {
	w := &ConnectionWatcher{}

	tests := []struct {
		addr     string
		port     int
		hostname string
		want     string
	}{
		{"52.94.236.248", 443, "api.stripe.com", "stripe"},
		{"1.2.3.4", 443, "", "https"},
		{"1.2.3.4", 80, "", "http"},
		{"1.2.3.4", 5432, "", "postgresql"},
		{"1.2.3.4", 6379, "", "redis"},
		{"1.2.3.4", 9999, "ec2-1-2-3-4.amazonaws.com", "aws"},
		{"1.2.3.4", 9999, "something.unknown.com", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := w.guessService(tt.addr, tt.port, tt.hostname)
			if got != tt.want {
				t.Errorf("guessService(%q, %d, %q) = %q, want %q", tt.addr, tt.port, tt.hostname, got, tt.want)
			}
		})
	}
}
