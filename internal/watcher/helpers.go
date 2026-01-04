package watcher

import (
	"net"
	"strings"
)

// isLoopback checks if an address is a loopback address.
func isLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// guessServiceByPort attempts to identify a service by its port and hostname.
func guessServiceByPort(addr string, port int) string {
	// Common port mappings
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

	// Try to identify by hostname patterns (if we have reverse DNS)
	if names, err := net.LookupAddr(addr); err == nil && len(names) > 0 {
		host := strings.ToLower(names[0])
		return guessServiceByHostname(host)
	}

	return "unknown"
}

// guessServiceByHostname identifies a service based on hostname patterns.
func guessServiceByHostname(host string) string {
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

	return "unknown"
}
