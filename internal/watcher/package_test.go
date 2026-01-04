package watcher

import (
	"testing"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestPackageWatcherInterface(t *testing.T) {
	// Verify PackageWatcher implements Watcher
	var _ Watcher = (*PackageWatcher)(nil)
}

func TestPackageWatcherName(t *testing.T) {
	w := NewPackageWatcher(PackageConfig{
		AptLogPaths: []string{"/var/log/dpkg.log"},
		FortressID:  "fort_test",
		ServerID:    "srv_test",
	})
	if w.Name() != "package" {
		t.Errorf("Name() = %v, want package", w.Name())
	}
}

func TestPackageWatcherConfig(t *testing.T) {
	tests := []struct {
		name            string
		config          PackageConfig
		wantAptLogPaths []string
		wantYumLogPaths []string
	}{
		{
			name: "default paths",
			config: PackageConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantAptLogPaths: []string{"/var/log/dpkg.log", "/var/log/apt/history.log"},
			wantYumLogPaths: []string{"/var/log/dnf.log", "/var/log/yum.log"},
		},
		{
			name: "custom paths",
			config: PackageConfig{
				AptLogPaths: []string{"/custom/apt.log", "/custom/dpkg.log"},
				YumLogPaths: []string{"/custom/dnf.log", "/custom/yum.log"},
				FortressID:  "fort_test",
				ServerID:    "srv_test",
			},
			wantAptLogPaths: []string{"/custom/apt.log", "/custom/dpkg.log"},
			wantYumLogPaths: []string{"/custom/dnf.log", "/custom/yum.log"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewPackageWatcher(tt.config)
			if len(w.aptLogPaths) != len(tt.wantAptLogPaths) {
				t.Errorf("aptLogPaths length = %v, want %v", len(w.aptLogPaths), len(tt.wantAptLogPaths))
			}
			for i, path := range w.aptLogPaths {
				if i < len(tt.wantAptLogPaths) && path != tt.wantAptLogPaths[i] {
					t.Errorf("aptLogPaths[%d] = %v, want %v", i, path, tt.wantAptLogPaths[i])
				}
			}
			if len(w.yumLogPaths) != len(tt.wantYumLogPaths) {
				t.Errorf("yumLogPaths length = %v, want %v", len(w.yumLogPaths), len(tt.wantYumLogPaths))
			}
			for i, path := range w.yumLogPaths {
				if i < len(tt.wantYumLogPaths) && path != tt.wantYumLogPaths[i] {
					t.Errorf("yumLogPaths[%d] = %v, want %v", i, path, tt.wantYumLogPaths[i])
				}
			}
		})
	}
}

func TestParseDpkgLogLine(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		wantType        event.EventType
		wantPackageName string
		wantPrevVersion string
		wantNewVersion  string
		wantNil         bool
	}{
		{
			name:            "install package",
			line:            "2024-01-15 10:30:45 install nginx:amd64 <none> 1.18.0-0ubuntu1",
			wantType:        event.PackageInstalled,
			wantPackageName: "nginx",
			wantPrevVersion: "",
			wantNewVersion:  "1.18.0-0ubuntu1",
		},
		{
			name:            "upgrade package",
			line:            "2024-01-15 10:31:00 upgrade openssl:amd64 1.1.1f-1ubuntu2.19 1.1.1f-1ubuntu2.20",
			wantType:        event.PackageUpgraded,
			wantPackageName: "openssl",
			wantPrevVersion: "1.1.1f-1ubuntu2.19",
			wantNewVersion:  "1.1.1f-1ubuntu2.20",
		},
		{
			name:            "remove package",
			line:            "2024-01-15 10:32:00 remove apache2:amd64 2.4.41-4ubuntu3.14 <none>",
			wantType:        event.PackageRemoved,
			wantPackageName: "apache2",
			wantPrevVersion: "2.4.41-4ubuntu3.14",
			wantNewVersion:  "",
		},
		{
			name:            "package without architecture",
			line:            "2024-01-15 10:30:45 install curl <none> 7.68.0-1ubuntu2.7",
			wantType:        event.PackageInstalled,
			wantPackageName: "curl",
			wantPrevVersion: "",
			wantNewVersion:  "7.68.0-1ubuntu2.7",
		},
		{
			name:    "unrelated log line",
			line:    "2024-01-15 10:30:45 status installed nginx:amd64 1.18.0-0ubuntu1",
			wantNil: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantNil: true,
		},
		{
			name:    "malformed line",
			line:    "not a valid dpkg log line",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDpkgLogLine(tt.line, "fort_test", "srv_test")

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}

			payload := result.Payload
			if payload["package_name"] != tt.wantPackageName {
				t.Errorf("package_name = %v, want %v", payload["package_name"], tt.wantPackageName)
			}

			if payload["package_manager"] != "apt" {
				t.Errorf("package_manager = %v, want apt", payload["package_manager"])
			}

			prevVersion, _ := payload["previous_version"].(string)
			if prevVersion != tt.wantPrevVersion {
				t.Errorf("previous_version = %v, want %v", prevVersion, tt.wantPrevVersion)
			}

			newVersion, _ := payload["new_version"].(string)
			if newVersion != tt.wantNewVersion {
				t.Errorf("new_version = %v, want %v", newVersion, tt.wantNewVersion)
			}
		})
	}
}

func TestParseYumLogLine(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		pkgManager      string
		wantType        event.EventType
		wantPackageName string
		wantPrevVersion string
		wantNewVersion  string
		wantNil         bool
	}{
		{
			name:            "install package",
			line:            "Jan 15 10:30:45 Installed: nginx-1.18.0-1.el8.x86_64",
			pkgManager:      "yum",
			wantType:        event.PackageInstalled,
			wantPackageName: "nginx",
			wantPrevVersion: "",
			wantNewVersion:  "1.18.0-1.el8",
		},
		{
			name:            "update package",
			line:            "Jan 15 10:31:00 Updated: openssl-1.1.1k-5.el8.x86_64",
			pkgManager:      "yum",
			wantType:        event.PackageUpgraded,
			wantPackageName: "openssl",
			wantPrevVersion: "",
			wantNewVersion:  "1.1.1k-5.el8",
		},
		{
			name:            "erase package",
			line:            "Jan 15 10:32:00 Erased: httpd-2.4.37-43.el8.x86_64",
			pkgManager:      "yum",
			wantType:        event.PackageRemoved,
			wantPackageName: "httpd",
			wantPrevVersion: "2.4.37-43.el8",
			wantNewVersion:  "",
		},
		{
			name:            "dnf install",
			line:            "Jan 15 10:30:45 Installed: vim-enhanced-8.0.1763-15.el8.x86_64",
			pkgManager:      "dnf",
			wantType:        event.PackageInstalled,
			wantPackageName: "vim-enhanced",
			wantPrevVersion: "",
			wantNewVersion:  "8.0.1763-15.el8",
		},
		{
			name:            "noarch package",
			line:            "Jan 15 10:30:45 Installed: epel-release-8-11.el8.noarch",
			pkgManager:      "yum",
			wantType:        event.PackageInstalled,
			wantPackageName: "epel-release",
			wantPrevVersion: "",
			wantNewVersion:  "8-11.el8",
		},
		{
			name:       "unrelated log line",
			line:       "Jan 15 10:30:45 Something else happened",
			pkgManager: "yum",
			wantNil:    true,
		},
		{
			name:       "empty line",
			line:       "",
			pkgManager: "yum",
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseYumLogLine(tt.line, "fort_test", "srv_test", tt.pkgManager)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}

			payload := result.Payload
			if payload["package_name"] != tt.wantPackageName {
				t.Errorf("package_name = %v, want %v", payload["package_name"], tt.wantPackageName)
			}

			if payload["package_manager"] != tt.pkgManager {
				t.Errorf("package_manager = %v, want %v", payload["package_manager"], tt.pkgManager)
			}

			prevVersion, _ := payload["previous_version"].(string)
			if prevVersion != tt.wantPrevVersion {
				t.Errorf("previous_version = %v, want %v", prevVersion, tt.wantPrevVersion)
			}

			newVersion, _ := payload["new_version"].(string)
			if newVersion != tt.wantNewVersion {
				t.Errorf("new_version = %v, want %v", newVersion, tt.wantNewVersion)
			}
		})
	}
}

func TestParseYumPackageString(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{
			input:       "nginx-1.18.0-1.el8.x86_64",
			wantName:    "nginx",
			wantVersion: "1.18.0-1.el8",
		},
		{
			input:       "openssl-1.1.1k-5.el8.x86_64",
			wantName:    "openssl",
			wantVersion: "1.1.1k-5.el8",
		},
		{
			input:       "vim-enhanced-8.0.1763-15.el8.x86_64",
			wantName:    "vim-enhanced",
			wantVersion: "8.0.1763-15.el8",
		},
		{
			input:       "epel-release-8-11.el8.noarch",
			wantName:    "epel-release",
			wantVersion: "8-11.el8",
		},
		{
			input:       "kernel-4.18.0-348.el8.x86_64",
			wantName:    "kernel",
			wantVersion: "4.18.0-348.el8",
		},
		{
			input:       "httpd-2.4.37-43.el8.x86_64",
			wantName:    "httpd",
			wantVersion: "2.4.37-43.el8",
		},
		{
			input:       "simple-package.i686",
			wantName:    "simple-package",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parseYumPackageString(tt.input)
			if name != tt.wantName {
				t.Errorf("name = %v, want %v", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %v, want %v", version, tt.wantVersion)
			}
		})
	}
}

func TestParseDpkgLogLineActor(t *testing.T) {
	line := "2024-01-15 10:30:45 install nginx:amd64 <none> 1.18.0-0ubuntu1"
	result := parseDpkgLogLine(line, "fort_test", "srv_test")

	if result == nil {
		t.Fatal("expected event, got nil")
	}

	if result.Actor == nil {
		t.Fatal("expected actor, got nil")
	}

	if result.Actor.Type != event.ActorTypeSystem {
		t.Errorf("Actor.Type = %v, want %v", result.Actor.Type, event.ActorTypeSystem)
	}

	if result.Actor.Name != "apt" {
		t.Errorf("Actor.Name = %v, want apt", result.Actor.Name)
	}
}

func TestParseYumLogLineActor(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		pkgManager string
		wantActor  string
	}{
		{
			name:       "yum actor",
			line:       "Jan 15 10:30:45 Installed: nginx-1.18.0-1.el8.x86_64",
			pkgManager: "yum",
			wantActor:  "yum",
		},
		{
			name:       "dnf actor",
			line:       "Jan 15 10:30:45 Installed: nginx-1.18.0-1.el8.x86_64",
			pkgManager: "dnf",
			wantActor:  "dnf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseYumLogLine(tt.line, "fort_test", "srv_test", tt.pkgManager)

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Actor == nil {
				t.Fatal("expected actor, got nil")
			}

			if result.Actor.Type != event.ActorTypeSystem {
				t.Errorf("Actor.Type = %v, want %v", result.Actor.Type, event.ActorTypeSystem)
			}

			if result.Actor.Name != tt.wantActor {
				t.Errorf("Actor.Name = %v, want %v", result.Actor.Name, tt.wantActor)
			}
		})
	}
}

func TestDpkgLogLineEventTypes(t *testing.T) {
	tests := []struct {
		action   string
		wantType event.EventType
	}{
		{"install", event.PackageInstalled},
		{"upgrade", event.PackageUpgraded},
		{"remove", event.PackageRemoved},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			line := "2024-01-15 10:30:45 " + tt.action + " test-pkg:amd64 1.0.0 2.0.0"
			result := parseDpkgLogLine(line, "fort_test", "srv_test")

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}
		})
	}
}

func TestYumLogLineEventTypes(t *testing.T) {
	tests := []struct {
		action   string
		wantType event.EventType
	}{
		{"Installed", event.PackageInstalled},
		{"Updated", event.PackageUpgraded},
		{"Erased", event.PackageRemoved},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			line := "Jan 15 10:30:45 " + tt.action + ": test-pkg-1.0.0-1.el8.x86_64"
			result := parseYumLogLine(line, "fort_test", "srv_test", "yum")

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}
		})
	}
}
