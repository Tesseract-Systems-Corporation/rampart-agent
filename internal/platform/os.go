package platform

import (
	"os"
	"runtime"
	"strings"
)

// OSInfo contains operating system information.
type OSInfo struct {
	// ID is the distro identifier (ubuntu, debian, centos, rhel, alpine, etc.)
	ID string `json:"id"`
	// Name is the human-readable name (e.g., "Ubuntu 22.04.3 LTS")
	Name string `json:"name"`
	// Version is the version number (e.g., "22.04")
	Version string `json:"version"`
	// VersionCodename is the release codename (e.g., "jammy")
	VersionCodename string `json:"version_codename,omitempty"`
}

// DetectOS detects the operating system and distribution.
func DetectOS() OSInfo {
	info := OSInfo{
		ID:   runtime.GOOS,
		Name: runtime.GOOS,
	}

	if runtime.GOOS != "linux" {
		return info
	}

	// Try to read /etc/os-release (standard on most Linux distros)
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return info
	}

	osRelease := parseOSRelease(string(data))

	if id, ok := osRelease["ID"]; ok {
		info.ID = strings.ToLower(id)
	}
	if name, ok := osRelease["PRETTY_NAME"]; ok {
		info.Name = name
	} else if name, ok := osRelease["NAME"]; ok {
		info.Name = name
	}
	if version, ok := osRelease["VERSION_ID"]; ok {
		info.Version = version
	}
	if codename, ok := osRelease["VERSION_CODENAME"]; ok {
		info.VersionCodename = codename
	}

	return info
}

// parseOSRelease parses /etc/os-release format (KEY=value or KEY="value")
func parseOSRelease(content string) map[string]string {
	result := make(map[string]string)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		// Remove quotes if present
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
			value = value[1 : len(value)-1]
		}

		result[key] = value
	}

	return result
}

// SecurityTrackerURL returns the URL to check CVE status for this distro.
// Returns empty string if unknown distro.
func (o OSInfo) SecurityTrackerURL(cve string) string {
	cve = strings.ToUpper(cve)
	if !strings.HasPrefix(cve, "CVE-") {
		return ""
	}

	switch o.ID {
	case "ubuntu":
		return "https://ubuntu.com/security/cves?q=" + cve
	case "debian":
		return "https://security-tracker.debian.org/tracker/" + cve
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		return "https://access.redhat.com/security/cve/" + strings.ToLower(cve)
	case "alpine":
		return "https://security.alpinelinux.org/vuln/" + cve
	case "amzn": // Amazon Linux
		return "https://alas.aws.amazon.com/cve/html/" + cve + ".html"
	default:
		return ""
	}
}

// SecurityTrackerName returns the human-readable name of the security tracker.
func (o OSInfo) SecurityTrackerName() string {
	switch o.ID {
	case "ubuntu":
		return "Ubuntu Security"
	case "debian":
		return "Debian Security Tracker"
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		return "Red Hat Security"
	case "alpine":
		return "Alpine Security"
	case "amzn":
		return "Amazon Linux Security"
	default:
		return ""
	}
}
