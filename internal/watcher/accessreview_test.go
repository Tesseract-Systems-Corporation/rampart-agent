package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestAccessReviewWatcherInterface(t *testing.T) {
	var _ Watcher = (*AccessReviewWatcher)(nil)
}

func TestAccessReviewWatcherName(t *testing.T) {
	w := NewAccessReviewWatcher(AccessReviewConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "accessreview" {
		t.Errorf("Name() = %v, want accessreview", w.Name())
	}
}

func TestAccessReviewWatcherConfig(t *testing.T) {
	tests := []struct {
		name             string
		config           AccessReviewConfig
		wantInterval     time.Duration
		wantStaleDays    int
		wantPasswdPath   string
	}{
		{
			name: "default values",
			config: AccessReviewConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval:   DefaultSnapshotInterval,
			wantStaleDays:  DefaultStaleAccountDays,
			wantPasswdPath: "/etc/passwd",
		},
		{
			name: "custom interval",
			config: AccessReviewConfig{
				SnapshotInterval: 12 * time.Hour,
				FortressID:       "fort_test",
				ServerID:         "srv_test",
			},
			wantInterval:   12 * time.Hour,
			wantStaleDays:  DefaultStaleAccountDays,
			wantPasswdPath: "/etc/passwd",
		},
		{
			name: "custom stale days",
			config: AccessReviewConfig{
				StaleAccountDays: 30,
				FortressID:       "fort_test",
				ServerID:         "srv_test",
			},
			wantInterval:   DefaultSnapshotInterval,
			wantStaleDays:  30,
			wantPasswdPath: "/etc/passwd",
		},
		{
			name: "custom paths",
			config: AccessReviewConfig{
				PasswdPath: "/custom/passwd",
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval:   DefaultSnapshotInterval,
			wantStaleDays:  DefaultStaleAccountDays,
			wantPasswdPath: "/custom/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewAccessReviewWatcher(tt.config)
			if w.snapshotInterval != tt.wantInterval {
				t.Errorf("snapshotInterval = %v, want %v", w.snapshotInterval, tt.wantInterval)
			}
			if w.staleAccountDays != tt.wantStaleDays {
				t.Errorf("staleAccountDays = %v, want %v", w.staleAccountDays, tt.wantStaleDays)
			}
			if w.passwdPath != tt.wantPasswdPath {
				t.Errorf("passwdPath = %v, want %v", w.passwdPath, tt.wantPasswdPath)
			}
		})
	}
}

func TestParsePasswdLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    PasswdEntry
		wantErr bool
	}{
		{
			name: "regular user",
			line: "jordan:x:1001:1001:Jordan Smith:/home/jordan:/bin/bash",
			want: PasswdEntry{
				Username: "jordan",
				UID:      1001,
				GID:      1001,
				Comment:  "Jordan Smith",
				HomeDir:  "/home/jordan",
				Shell:    "/bin/bash",
			},
			wantErr: false,
		},
		{
			name: "root user",
			line: "root:x:0:0:root:/root:/bin/bash",
			want: PasswdEntry{
				Username: "root",
				UID:      0,
				GID:      0,
				Comment:  "root",
				HomeDir:  "/root",
				Shell:    "/bin/bash",
			},
			wantErr: false,
		},
		{
			name: "system user with nologin",
			line: "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			want: PasswdEntry{
				Username: "daemon",
				UID:      1,
				GID:      1,
				Comment:  "daemon",
				HomeDir:  "/usr/sbin",
				Shell:    "/usr/sbin/nologin",
			},
			wantErr: false,
		},
		{
			name: "user with empty comment",
			line: "www-data:x:33:33::/var/www:/usr/sbin/nologin",
			want: PasswdEntry{
				Username: "www-data",
				UID:      33,
				GID:      33,
				Comment:  "",
				HomeDir:  "/var/www",
				Shell:    "/usr/sbin/nologin",
			},
			wantErr: false,
		},
		{
			name: "nobody user",
			line: "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
			want: PasswdEntry{
				Username: "nobody",
				UID:      65534,
				GID:      65534,
				Comment:  "nobody",
				HomeDir:  "/nonexistent",
				Shell:    "/usr/sbin/nologin",
			},
			wantErr: false,
		},
		{
			name:    "insufficient fields",
			line:    "invalid:x:1000",
			want:    PasswdEntry{},
			wantErr: true,
		},
		{
			name:    "invalid uid",
			line:    "invalid:x:abc:1000::/home/invalid:/bin/bash",
			want:    PasswdEntry{},
			wantErr: true,
		},
		{
			name:    "invalid gid",
			line:    "invalid:x:1000:abc::/home/invalid:/bin/bash",
			want:    PasswdEntry{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePasswdLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePasswdLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Username != tt.want.Username {
					t.Errorf("Username = %v, want %v", got.Username, tt.want.Username)
				}
				if got.UID != tt.want.UID {
					t.Errorf("UID = %v, want %v", got.UID, tt.want.UID)
				}
				if got.GID != tt.want.GID {
					t.Errorf("GID = %v, want %v", got.GID, tt.want.GID)
				}
				if got.Comment != tt.want.Comment {
					t.Errorf("Comment = %v, want %v", got.Comment, tt.want.Comment)
				}
				if got.HomeDir != tt.want.HomeDir {
					t.Errorf("HomeDir = %v, want %v", got.HomeDir, tt.want.HomeDir)
				}
				if got.Shell != tt.want.Shell {
					t.Errorf("Shell = %v, want %v", got.Shell, tt.want.Shell)
				}
			}
		})
	}
}

func TestParseGroupLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    GroupEntry
		wantErr bool
	}{
		{
			name: "group with members",
			line: "sudo:x:27:jordan,admin,ops",
			want: GroupEntry{
				Name:    "sudo",
				GID:     27,
				Members: []string{"jordan", "admin", "ops"},
			},
			wantErr: false,
		},
		{
			name: "group with single member",
			line: "docker:x:999:jordan",
			want: GroupEntry{
				Name:    "docker",
				GID:     999,
				Members: []string{"jordan"},
			},
			wantErr: false,
		},
		{
			name: "group with no members",
			line: "nogroup:x:65534:",
			want: GroupEntry{
				Name:    "nogroup",
				GID:     65534,
				Members: nil,
			},
			wantErr: false,
		},
		{
			name: "root group",
			line: "root:x:0:",
			want: GroupEntry{
				Name:    "root",
				GID:     0,
				Members: nil,
			},
			wantErr: false,
		},
		{
			name: "wheel group",
			line: "wheel:x:10:root,admin",
			want: GroupEntry{
				Name:    "wheel",
				GID:     10,
				Members: []string{"root", "admin"},
			},
			wantErr: false,
		},
		{
			name:    "insufficient fields",
			line:    "invalid:x",
			want:    GroupEntry{},
			wantErr: true,
		},
		{
			name:    "invalid gid",
			line:    "invalid:x:abc:member",
			want:    GroupEntry{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGroupLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGroupLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Name != tt.want.Name {
					t.Errorf("Name = %v, want %v", got.Name, tt.want.Name)
				}
				if got.GID != tt.want.GID {
					t.Errorf("GID = %v, want %v", got.GID, tt.want.GID)
				}
				if len(got.Members) != len(tt.want.Members) {
					t.Errorf("Members length = %v, want %v", len(got.Members), len(tt.want.Members))
				} else {
					for i, member := range got.Members {
						if member != tt.want.Members[i] {
							t.Errorf("Members[%d] = %v, want %v", i, member, tt.want.Members[i])
						}
					}
				}
			}
		})
	}
}

func TestParseSudoersContent(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantUsers  map[string]bool
		wantGroups map[string]bool
	}{
		{
			name: "basic sudo group",
			content: `# sudoers file
%sudo ALL=(ALL:ALL) ALL
`,
			wantUsers:  map[string]bool{},
			wantGroups: map[string]bool{"sudo": true},
		},
		{
			name: "wheel group",
			content: `%wheel ALL=(ALL) ALL
`,
			wantUsers:  map[string]bool{},
			wantGroups: map[string]bool{"wheel": true},
		},
		{
			name: "specific user",
			content: `jordan ALL=(ALL) NOPASSWD: ALL
`,
			wantUsers:  map[string]bool{"jordan": true},
			wantGroups: map[string]bool{},
		},
		{
			name: "root user",
			content: `root ALL=(ALL:ALL) ALL
`,
			wantUsers:  map[string]bool{"root": true},
			wantGroups: map[string]bool{},
		},
		{
			name: "multiple entries",
			content: `# Allow sudo group
%sudo ALL=(ALL:ALL) ALL

# Allow wheel group
%wheel ALL=(ALL) ALL

# Allow specific users
admin ALL=(ALL) NOPASSWD: ALL
deployer ALL=(ALL) NOPASSWD: /usr/bin/systemctl
`,
			wantUsers:  map[string]bool{"admin": true, "deployer": true},
			wantGroups: map[string]bool{"sudo": true, "wheel": true},
		},
		{
			name: "comments and defaults",
			content: `# This is a comment
Defaults env_reset
Defaults mail_badpass

%sudo ALL=(ALL:ALL) ALL
`,
			wantUsers:  map[string]bool{},
			wantGroups: map[string]bool{"sudo": true},
		},
		{
			name:       "empty file",
			content:    "",
			wantUsers:  map[string]bool{},
			wantGroups: map[string]bool{},
		},
		{
			name: "only comments",
			content: `# Just comments
# No actual rules
`,
			wantUsers:  map[string]bool{},
			wantGroups: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := make(map[string]bool)
			groups := make(map[string]bool)
			parseSudoersContent(tt.content, users, groups)

			// Check users
			if len(users) != len(tt.wantUsers) {
				t.Errorf("users count = %v, want %v", len(users), len(tt.wantUsers))
			}
			for user := range tt.wantUsers {
				if !users[user] {
					t.Errorf("expected user %q not found", user)
				}
			}

			// Check groups
			if len(groups) != len(tt.wantGroups) {
				t.Errorf("groups count = %v, want %v", len(groups), len(tt.wantGroups))
			}
			for group := range tt.wantGroups {
				if !groups[group] {
					t.Errorf("expected group %q not found", group)
				}
			}
		})
	}
}

func TestIsServiceAccount(t *testing.T) {
	tests := []struct {
		name  string
		entry PasswdEntry
		want  bool
	}{
		{
			name: "regular user",
			entry: PasswdEntry{
				Username: "jordan",
				UID:      1001,
				Shell:    "/bin/bash",
			},
			want: false,
		},
		{
			name: "root user",
			entry: PasswdEntry{
				Username: "root",
				UID:      0,
				Shell:    "/bin/bash",
			},
			want: false,
		},
		{
			name: "system user low uid",
			entry: PasswdEntry{
				Username: "daemon",
				UID:      1,
				Shell:    "/usr/sbin/nologin",
			},
			want: true,
		},
		{
			name: "system user with nologin shell",
			entry: PasswdEntry{
				Username: "www-data",
				UID:      33,
				Shell:    "/usr/sbin/nologin",
			},
			want: true,
		},
		{
			name: "user with false shell",
			entry: PasswdEntry{
				Username: "ftp",
				UID:      21,
				Shell:    "/bin/false",
			},
			want: true,
		},
		{
			name: "high uid with nologin",
			entry: PasswdEntry{
				Username: "service-account",
				UID:      1050,
				Shell:    "/usr/sbin/nologin",
			},
			want: true,
		},
		{
			name: "nobody user",
			entry: PasswdEntry{
				Username: "nobody",
				UID:      65534,
				Shell:    "/usr/sbin/nologin",
			},
			want: true,
		},
		{
			name: "uid 999",
			entry: PasswdEntry{
				Username: "systemd-network",
				UID:      999,
				Shell:    "/usr/sbin/nologin",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isServiceAccount(tt.entry)
			if got != tt.want {
				t.Errorf("isServiceAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineAccountStatus(t *testing.T) {
	tests := []struct {
		name  string
		entry PasswdEntry
		want  string
	}{
		{
			name: "active user with bash",
			entry: PasswdEntry{
				Username: "jordan",
				Shell:    "/bin/bash",
			},
			want: "active",
		},
		{
			name: "active user with zsh",
			entry: PasswdEntry{
				Username: "admin",
				Shell:    "/bin/zsh",
			},
			want: "active",
		},
		{
			name: "disabled with nologin",
			entry: PasswdEntry{
				Username: "daemon",
				Shell:    "/usr/sbin/nologin",
			},
			want: "disabled",
		},
		{
			name: "disabled with sbin nologin",
			entry: PasswdEntry{
				Username: "nobody",
				Shell:    "/sbin/nologin",
			},
			want: "disabled",
		},
		{
			name: "disabled with false",
			entry: PasswdEntry{
				Username: "ftp",
				Shell:    "/bin/false",
			},
			want: "disabled",
		},
		{
			name: "disabled with usr bin false",
			entry: PasswdEntry{
				Username: "mail",
				Shell:    "/usr/bin/false",
			},
			want: "disabled",
		},
		{
			name: "active user with sh",
			entry: PasswdEntry{
				Username: "script-user",
				Shell:    "/bin/sh",
			},
			want: "active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineAccountStatus(tt.entry)
			if got != tt.want {
				t.Errorf("determineAccountStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildGroupMembership(t *testing.T) {
	users := []PasswdEntry{
		{Username: "jordan", UID: 1001, GID: 1001},
		{Username: "admin", UID: 1002, GID: 1002},
		{Username: "root", UID: 0, GID: 0},
	}

	groups := []GroupEntry{
		{Name: "jordan", GID: 1001, Members: nil},
		{Name: "admin", GID: 1002, Members: nil},
		{Name: "root", GID: 0, Members: nil},
		{Name: "sudo", GID: 27, Members: []string{"jordan", "admin"}},
		{Name: "docker", GID: 999, Members: []string{"jordan"}},
		{Name: "wheel", GID: 10, Members: []string{"admin"}},
	}

	membership := buildGroupMembership(groups, users)

	tests := []struct {
		username string
		want     []string
	}{
		{
			username: "jordan",
			want:     []string{"jordan", "sudo", "docker"},
		},
		{
			username: "admin",
			want:     []string{"admin", "sudo", "wheel"},
		},
		{
			username: "root",
			want:     []string{"root"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			got := membership[tt.username]
			if len(got) != len(tt.want) {
				t.Errorf("membership[%s] length = %v, want %v", tt.username, len(got), len(tt.want))
				t.Logf("got: %v, want: %v", got, tt.want)
				return
			}

			// Check that all expected groups are present
			for _, wantGroup := range tt.want {
				found := false
				for _, gotGroup := range got {
					if gotGroup == wantGroup {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("membership[%s] missing group %q", tt.username, wantGroup)
				}
			}
		})
	}
}

func TestStaleAccountDetection(t *testing.T) {
	watcher := NewAccessReviewWatcher(AccessReviewConfig{
		StaleAccountDays: 90,
		FortressID:       "fort_test",
		ServerID:         "srv_test",
	})

	now := time.Now()
	tests := []struct {
		name     string
		snapshot event.UserSnapshot
		entry    PasswdEntry
		want     bool
	}{
		{
			name: "active user logged in recently",
			snapshot: event.UserSnapshot{
				Username:      "jordan",
				LastLogin:     now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
				AccountStatus: "active",
			},
			entry: PasswdEntry{
				Username: "jordan",
				UID:      1001,
				Shell:    "/bin/bash",
			},
			want: false,
		},
		{
			name: "active user logged in 100 days ago",
			snapshot: event.UserSnapshot{
				Username:      "olduser",
				LastLogin:     now.Add(-100 * 24 * time.Hour).Format(time.RFC3339),
				AccountStatus: "active",
			},
			entry: PasswdEntry{
				Username: "olduser",
				UID:      1002,
				Shell:    "/bin/bash",
			},
			want: true,
		},
		{
			name: "user never logged in",
			snapshot: event.UserSnapshot{
				Username:      "newuser",
				LastLogin:     "",
				AccountStatus: "active",
			},
			entry: PasswdEntry{
				Username: "newuser",
				UID:      1003,
				Shell:    "/bin/bash",
			},
			want: true,
		},
		{
			name: "disabled user old login",
			snapshot: event.UserSnapshot{
				Username:      "disabled",
				LastLogin:     now.Add(-200 * 24 * time.Hour).Format(time.RFC3339),
				AccountStatus: "disabled",
			},
			entry: PasswdEntry{
				Username: "disabled",
				UID:      1004,
				Shell:    "/usr/sbin/nologin",
			},
			want: false,
		},
		{
			name: "service account never logged in",
			snapshot: event.UserSnapshot{
				Username:      "daemon",
				LastLogin:     "",
				AccountStatus: "disabled",
			},
			entry: PasswdEntry{
				Username: "daemon",
				UID:      1,
				Shell:    "/usr/sbin/nologin",
			},
			want: false,
		},
		{
			name: "user logged in exactly 90 days ago",
			snapshot: event.UserSnapshot{
				Username:      "borderline",
				// Subtract a small buffer to account for test execution time
				// Since isStaleAccount uses time.Since(), we need to ensure we're clearly under threshold
				LastLogin:     now.Add(-90*24*time.Hour + 1*time.Minute).Format(time.RFC3339),
				AccountStatus: "active",
			},
			entry: PasswdEntry{
				Username: "borderline",
				UID:      1005,
				Shell:    "/bin/bash",
			},
			want: false, // 90 days minus buffer is not > 90 days
		},
		{
			name: "user logged in 91 days ago",
			snapshot: event.UserSnapshot{
				Username:      "stale",
				LastLogin:     now.Add(-91 * 24 * time.Hour).Format(time.RFC3339),
				AccountStatus: "active",
			},
			entry: PasswdEntry{
				Username: "stale",
				UID:      1006,
				Shell:    "/bin/bash",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := watcher.isStaleAccount(tt.snapshot, tt.entry)
			if got != tt.want {
				t.Errorf("isStaleAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasAuthorizedKeys(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a user directory with authorized_keys
	userWithKeys := filepath.Join(tempDir, "user_with_keys")
	sshDir := filepath.Join(userWithKeys, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("failed to create ssh dir: %v", err)
	}
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, []byte("ssh-rsa AAAAB... user@host"), 0600); err != nil {
		t.Fatalf("failed to create authorized_keys: %v", err)
	}

	// Create a user directory with empty authorized_keys
	userEmptyKeys := filepath.Join(tempDir, "user_empty_keys")
	sshDirEmpty := filepath.Join(userEmptyKeys, ".ssh")
	if err := os.MkdirAll(sshDirEmpty, 0700); err != nil {
		t.Fatalf("failed to create ssh dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDirEmpty, "authorized_keys"), []byte(""), 0600); err != nil {
		t.Fatalf("failed to create empty authorized_keys: %v", err)
	}

	// Create a user directory without ssh dir
	userNoSSH := filepath.Join(tempDir, "user_no_ssh")
	if err := os.MkdirAll(userNoSSH, 0755); err != nil {
		t.Fatalf("failed to create user dir: %v", err)
	}

	tests := []struct {
		name    string
		homeDir string
		want    bool
	}{
		{
			name:    "user with authorized_keys",
			homeDir: userWithKeys,
			want:    true,
		},
		{
			name:    "user with empty authorized_keys",
			homeDir: userEmptyKeys,
			want:    false,
		},
		{
			name:    "user without ssh directory",
			homeDir: userNoSSH,
			want:    false,
		},
		{
			name:    "nonexistent home directory",
			homeDir: "/nonexistent/path",
			want:    false,
		},
		{
			name:    "empty home directory",
			homeDir: "",
			want:    false,
		},
		{
			name:    "home is /nonexistent",
			homeDir: "/nonexistent",
			want:    false,
		},
		{
			name:    "home is /dev/null",
			homeDir: "/dev/null",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAuthorizedKeys(tt.homeDir)
			if got != tt.want {
				t.Errorf("hasAuthorizedKeys(%q) = %v, want %v", tt.homeDir, got, tt.want)
			}
		})
	}
}

func TestParseLastlogOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantLogins map[string]bool // Just check presence, not exact time
	}{
		{
			name: "normal output",
			output: `Username         Port     From             Latest
root             pts/0    192.168.1.1      Mon Dec 29 10:30:00 -0500 2025
jordan           pts/1    10.0.0.5         Sun Dec 28 14:00:00 -0500 2025
daemon                                     **Never logged in**
`,
			wantLogins: map[string]bool{
				"root":   true,
				"jordan": true,
			},
		},
		{
			name: "all never logged in",
			output: `Username         Port     From             Latest
daemon                                     **Never logged in**
nobody                                     **Never logged in**
www-data                                   **Never logged in**
`,
			wantLogins: map[string]bool{},
		},
		{
			name:       "empty output",
			output:     "",
			wantLogins: map[string]bool{},
		},
		{
			name:       "header only",
			output:     "Username         Port     From             Latest\n",
			wantLogins: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLastlogOutput(tt.output)

			for user, shouldExist := range tt.wantLogins {
				_, exists := got[user]
				if exists != shouldExist {
					t.Errorf("parseLastlogOutput() user %q exists = %v, want %v", user, exists, shouldExist)
				}
			}
		})
	}
}

func TestAccessReviewWatcherContextCancellation(t *testing.T) {
	// Create temp files for testing
	tempDir := t.TempDir()
	passwdFile := filepath.Join(tempDir, "passwd")
	groupFile := filepath.Join(tempDir, "group")

	passwdContent := "root:x:0:0:root:/root:/bin/bash\njordan:x:1001:1001::/home/jordan:/bin/bash\n"
	groupContent := "root:x:0:\njordan:x:1001:\n"

	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd file: %v", err)
	}
	if err := os.WriteFile(groupFile, []byte(groupContent), 0644); err != nil {
		t.Fatalf("failed to write group file: %v", err)
	}

	w := NewAccessReviewWatcher(AccessReviewConfig{
		SnapshotInterval: 1 * time.Hour, // Long interval
		FortressID:       "fort_test",
		ServerID:         "srv_test",
		PasswdPath:       passwdFile,
		GroupPath:        groupFile,
	})

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Receive the immediate snapshot
	select {
	case e := <-ch:
		if e.Type != event.AccessReviewSnapshot {
			t.Errorf("expected AccessReviewSnapshot event, got %v", e.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for initial snapshot")
	}

	// Cancel context
	cancel()

	// Channel should close
	select {
	case _, ok := <-ch:
		if ok {
			// Might receive one more event, drain channel
			for range ch {
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

func TestAccessReviewWatcherEmitsSnapshot(t *testing.T) {
	// Create temp files for testing
	tempDir := t.TempDir()
	passwdFile := filepath.Join(tempDir, "passwd")
	groupFile := filepath.Join(tempDir, "group")
	sudoersFile := filepath.Join(tempDir, "sudoers")

	passwdContent := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
jordan:x:1001:1001:Jordan Smith:/home/jordan:/bin/bash
admin:x:1002:1002:Admin User:/home/admin:/bin/zsh
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
`

	groupContent := `root:x:0:
daemon:x:1:
jordan:x:1001:
admin:x:1002:
www-data:x:33:
sudo:x:27:jordan,admin
docker:x:999:jordan
`

	sudoersContent := `# sudoers file
%sudo ALL=(ALL:ALL) ALL
`

	if err := os.WriteFile(passwdFile, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd file: %v", err)
	}
	if err := os.WriteFile(groupFile, []byte(groupContent), 0644); err != nil {
		t.Fatalf("failed to write group file: %v", err)
	}
	if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0644); err != nil {
		t.Fatalf("failed to write sudoers file: %v", err)
	}

	w := NewAccessReviewWatcher(AccessReviewConfig{
		SnapshotInterval: 50 * time.Millisecond,
		FortressID:       "fort_test",
		ServerID:         "srv_test",
		PasswdPath:       passwdFile,
		GroupPath:        groupFile,
		SudoersPath:      sudoersFile,
		SudoersDPath:     filepath.Join(tempDir, "sudoers.d"), // nonexistent, that's ok
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// Should have received at least 1 snapshot
	if len(events) < 1 {
		t.Errorf("received %d events, want at least 1", len(events))
	}

	// Verify event structure
	if len(events) > 0 {
		e := events[0]
		if e.Type != event.AccessReviewSnapshot {
			t.Errorf("Type = %v, want %v", e.Type, event.AccessReviewSnapshot)
		}
		if e.FortressID != "fort_test" {
			t.Errorf("FortressID = %v, want fort_test", e.FortressID)
		}
		if e.ServerID != "srv_test" {
			t.Errorf("ServerID = %v, want srv_test", e.ServerID)
		}

		// Verify payload has required fields
		payload := e.Payload
		if _, ok := payload["total_users"]; !ok {
			t.Error("payload missing total_users")
		}
		if _, ok := payload["active_users"]; !ok {
			t.Error("payload missing active_users")
		}
		if _, ok := payload["disabled_users"]; !ok {
			t.Error("payload missing disabled_users")
		}
		if _, ok := payload["service_accounts"]; !ok {
			t.Error("payload missing service_accounts")
		}
		if _, ok := payload["sudo_users"]; !ok {
			t.Error("payload missing sudo_users")
		}
		if _, ok := payload["users"]; !ok {
			t.Error("payload missing users")
		}

		// Verify counts
		totalUsers, ok := payload["total_users"].(int)
		if !ok {
			t.Error("total_users is not an int")
		} else if totalUsers != 5 {
			t.Errorf("total_users = %v, want 5", totalUsers)
		}

		// Check sudo users
		sudoUsers, ok := payload["sudo_users"].([]string)
		if !ok {
			t.Error("sudo_users is not a []string")
		} else {
			// Both jordan and admin should have sudo via %sudo group
			if len(sudoUsers) < 2 {
				t.Errorf("sudo_users length = %v, want >= 2", len(sudoUsers))
			}
		}
	}
}

func TestPayloadToMap(t *testing.T) {
	payload := event.AccessReviewPayload{
		TotalUsers:      5,
		ActiveUsers:     3,
		DisabledUsers:   2,
		ServiceAccounts: 2,
		SudoUsers:       []string{"jordan", "admin"},
		SSHKeyUsers:     []string{"jordan"},
		StaleAccounts:   []string{"olduser"},
		Users: []event.UserSnapshot{
			{
				Username:      "jordan",
				UID:           1001,
				GID:           1001,
				Groups:        []string{"jordan", "sudo"},
				Shell:         "/bin/bash",
				HomeDir:       "/home/jordan",
				HasSSHKey:     true,
				HasSudoAccess: true,
				AccountStatus: "active",
			},
		},
	}

	m := payloadToMap(payload)

	if m["total_users"] != 5 {
		t.Errorf("total_users = %v, want 5", m["total_users"])
	}
	if m["active_users"] != 3 {
		t.Errorf("active_users = %v, want 3", m["active_users"])
	}
	if m["disabled_users"] != 2 {
		t.Errorf("disabled_users = %v, want 2", m["disabled_users"])
	}
	if m["service_accounts"] != 2 {
		t.Errorf("service_accounts = %v, want 2", m["service_accounts"])
	}

	sudoUsers, ok := m["sudo_users"].([]string)
	if !ok {
		t.Error("sudo_users is not []string")
	} else if len(sudoUsers) != 2 {
		t.Errorf("sudo_users length = %v, want 2", len(sudoUsers))
	}

	users, ok := m["users"].([]any)
	if !ok {
		t.Error("users is not []any")
	} else if len(users) != 1 {
		t.Errorf("users length = %v, want 1", len(users))
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  bool
	}{
		{
			name:  "contains element",
			slice: []string{"a", "b", "c"},
			s:     "b",
			want:  true,
		},
		{
			name:  "does not contain element",
			slice: []string{"a", "b", "c"},
			s:     "d",
			want:  false,
		},
		{
			name:  "empty slice",
			slice: []string{},
			s:     "a",
			want:  false,
		},
		{
			name:  "nil slice",
			slice: nil,
			s:     "a",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsString(tt.slice, tt.s)
			if got != tt.want {
				t.Errorf("containsString() = %v, want %v", got, tt.want)
			}
		})
	}
}
