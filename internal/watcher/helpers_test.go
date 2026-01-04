package watcher

import (
	"testing"
)

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback other", "127.0.0.2", true},
		{"IPv6 loopback", "::1", true},
		{"IPv4 private", "192.168.1.1", false},
		{"IPv4 public", "8.8.8.8", false},
		{"IPv6 public", "2001:db8::1", false},
		{"empty string", "", false},
		{"invalid IP", "not-an-ip", false},
		{"0.0.0.0", "0.0.0.0", false},
		{"IPv4 loopback range", "127.255.255.255", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLoopback(tt.addr)
			if result != tt.expected {
				t.Errorf("isLoopback(%q) = %v, want %v", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestGuessServiceByPort(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		port     int
		expected string
	}{
		{"HTTPS port", "1.2.3.4", 443, "https"},
		{"HTTP port", "1.2.3.4", 80, "http"},
		{"SSH port", "1.2.3.4", 22, "ssh"},
		{"MySQL port", "1.2.3.4", 3306, "mysql"},
		{"PostgreSQL port", "1.2.3.4", 5432, "postgresql"},
		{"Redis port", "1.2.3.4", 6379, "redis"},
		{"MongoDB port", "1.2.3.4", 27017, "mongodb"},
		{"Elasticsearch port", "1.2.3.4", 9200, "elasticsearch"},
		{"HTTP alt port", "1.2.3.4", 8080, "http-alt"},
		{"HTTPS alt port", "1.2.3.4", 8443, "https-alt"},
		{"DNS port", "1.2.3.4", 53, "dns"},
		{"SMTP port 25", "1.2.3.4", 25, "smtp"},
		{"SMTP port 587", "1.2.3.4", 587, "smtp"},
		{"IMAPS port", "1.2.3.4", 993, "imaps"},
		{"POP3S port", "1.2.3.4", 995, "pop3s"},
		{"unknown port", "1.2.3.4", 12345, "unknown"},
		{"random high port", "1.2.3.4", 49152, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := guessServiceByPort(tt.addr, tt.port)
			if result != tt.expected {
				t.Errorf("guessServiceByPort(%q, %d) = %q, want %q", tt.addr, tt.port, result, tt.expected)
			}
		})
	}
}

func TestGuessServiceByHostname(t *testing.T) {
	tests := []struct {
		name            string
		host            string
		expected        []string // allow multiple valid results for hosts matching multiple patterns
	}{
		{"stripe host", "api.stripe.com", []string{"stripe"}},
		{"aws host", "ec2.us-west-2.amazonaws.com", []string{"aws"}},
		{"cloudfront host", "d1234567890.cloudfront.net", []string{"aws-cloudfront"}},
		// s3 URLs contain both "s3." and "amazonaws" so either match is valid
		{"s3 host", "bucket.s3.amazonaws.com", []string{"aws-s3", "aws"}},
		// rds URLs contain both "rds." and "amazonaws" so either match is valid
		{"rds host", "mydb.rds.amazonaws.com", []string{"aws-rds", "aws"}},
		{"google api host", "www.googleapi.com", []string{"google"}},
		{"googleapis host", "storage.googleapis.com", []string{"google"}},
		{"azure host", "myaccount.blob.core.windows.net", []string{"unknown"}},
		{"azure explicit", "some.azure.microsoft.com", []string{"azure"}},
		{"cloudflare host", "workers.cloudflare.com", []string{"cloudflare"}},
		{"fastly host", "global.ssl.fastly.net", []string{"fastly"}},
		{"github host", "api.github.com", []string{"github"}},
		{"gitlab host", "gitlab.example.com", []string{"gitlab"}},
		{"docker.io host", "registry.docker.io", []string{"docker"}},
		{"docker.com host", "hub.docker.com", []string{"docker"}},
		// datadoghq.com contains "datadog" substring
		{"datadog host", "api.datadoghq.com", []string{"datadog"}},
		{"datadog explicit", "intake.datadog.com", []string{"datadog"}},
		{"sentry host", "sentry.io", []string{"sentry"}},
		{"slack host", "hooks.slack.com", []string{"slack"}},
		{"twilio host", "api.twilio.com", []string{"twilio"}},
		{"sendgrid host", "api.sendgrid.com", []string{"sendgrid"}},
		{"auth0 host", "myapp.auth0.com", []string{"auth0"}},
		{"okta host", "myorg.okta.com", []string{"okta"}},
		{"mongodb atlas", "cluster0.abc123.mongodb.net", []string{"mongodb-atlas"}},
		{"redis cloud", "redis-12345.redis.cloud", []string{"redis-cloud"}},
		{"heroku host", "api.heroku.com", []string{"heroku"}},
		{"digitalocean host", "api.digitalocean.com", []string{"digitalocean"}},
		{"linode host", "api.linode.com", []string{"linode"}},
		{"vultr host", "api.vultr.com", []string{"vultr"}},
		{"unknown host", "example.com", []string{"unknown"}},
		{"empty host", "", []string{"unknown"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := guessServiceByHostname(tt.host)
			found := false
			for _, exp := range tt.expected {
				if result == exp {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("guessServiceByHostname(%q) = %q, want one of %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAddr   string
		wantPort   int
	}{
		{
			name:     "IPv4 localhost:80",
			input:    "0100007F:0050",
			wantAddr: "127.0.0.1",
			wantPort: 80,
		},
		{
			name:     "IPv4 0.0.0.0:22",
			input:    "00000000:0016",
			wantAddr: "0.0.0.0",
			wantPort: 22,
		},
		{
			name:     "IPv4 192.168.1.1:443",
			input:    "0101A8C0:01BB",
			wantAddr: "192.168.1.1",
			wantPort: 443,
		},
		{
			name:     "invalid format - no colon",
			input:    "0100007F0050",
			wantAddr: "",
			wantPort: 0,
		},
		{
			name:     "invalid hex in port",
			input:    "0100007F:ZZZZ",
			wantAddr: "",
			wantPort: 0,
		},
		{
			name:     "invalid hex in address",
			input:    "ZZZZZZZZ:0050",
			wantAddr: "",
			wantPort: 0,
		},
		{
			name:     "empty input",
			input:    "",
			wantAddr: "",
			wantPort: 0,
		},
		{
			name:     "IPv6 loopback",
			input:    "00000000000000000000000001000000:0050",
			wantAddr: "::1",
			wantPort: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, port := parseHexAddr(tt.input)
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestParseHexAddrIPv6(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAddr   string
		wantPort   int
	}{
		{
			name:     "IPv6 all zeros",
			input:    "00000000000000000000000000000000:0050",
			wantAddr: "::",
			wantPort: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, port := parseHexAddr(tt.input)
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}
