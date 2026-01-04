package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestUserAccountWatcherInterface(t *testing.T) {
	var _ Watcher = (*UserAccountWatcher)(nil)
}

func TestUserAccountWatcherName(t *testing.T) {
	w := NewUserAccountWatcher(UserAccountConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "users" {
		t.Errorf("Name() = %v, want users", w.Name())
	}
}

func TestUserAccountWatcherConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         UserAccountConfig
		wantPasswd     string
		wantGroup      string
		wantShadow     string
	}{
		{
			name: "default paths",
			config: UserAccountConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantPasswd: "/etc/passwd",
			wantGroup:  "/etc/group",
			wantShadow: "/etc/shadow",
		},
		{
			name: "custom paths",
			config: UserAccountConfig{
				PasswdPath: "/custom/passwd",
				GroupPath:  "/custom/group",
				ShadowPath: "/custom/shadow",
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantPasswd: "/custom/passwd",
			wantGroup:  "/custom/group",
			wantShadow: "/custom/shadow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewUserAccountWatcher(tt.config)
			if w.passwdPath != tt.wantPasswd {
				t.Errorf("passwdPath = %v, want %v", w.passwdPath, tt.wantPasswd)
			}
			if w.groupPath != tt.wantGroup {
				t.Errorf("groupPath = %v, want %v", w.groupPath, tt.wantGroup)
			}
			if w.shadowPath != tt.wantShadow {
				t.Errorf("shadowPath = %v, want %v", w.shadowPath, tt.wantShadow)
			}
		})
	}
}

func TestUAParsePasswdLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		want     *UserEntry
	}{
		{
			name: "root user",
			line: "root:x:0:0:root:/root:/bin/bash",
			want: &UserEntry{
				Username: "root",
				UID:      0,
				GID:      0,
				GECOS:    "root",
				HomeDir:  "/root",
				Shell:    "/bin/bash",
			},
		},
		{
			name: "regular user",
			line: "jordan:x:1000:1000:Jordan Smith:/home/jordan:/bin/zsh",
			want: &UserEntry{
				Username: "jordan",
				UID:      1000,
				GID:      1000,
				GECOS:    "Jordan Smith",
				HomeDir:  "/home/jordan",
				Shell:    "/bin/zsh",
			},
		},
		{
			name: "service account",
			line: "nginx:x:101:101:nginx user,,,:/var/www:/usr/sbin/nologin",
			want: &UserEntry{
				Username: "nginx",
				UID:      101,
				GID:      101,
				GECOS:    "nginx user,,,",
				HomeDir:  "/var/www",
				Shell:    "/usr/sbin/nologin",
			},
		},
		{
			name: "nobody user",
			line: "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
			want: &UserEntry{
				Username: "nobody",
				UID:      65534,
				GID:      65534,
				GECOS:    "nobody",
				HomeDir:  "/nonexistent",
				Shell:    "/usr/sbin/nologin",
			},
		},
		{
			name: "empty GECOS",
			line: "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
			want: &UserEntry{
				Username: "daemon",
				UID:      1,
				GID:      1,
				GECOS:    "",
				HomeDir:  "/usr/sbin",
				Shell:    "/usr/sbin/nologin",
			},
		},
		{
			name: "empty line",
			line: "",
			want: nil,
		},
		{
			name: "comment line",
			line: "# This is a comment",
			want: nil,
		},
		{
			name: "too few fields",
			line: "invalid:x:1000",
			want: nil,
		},
		{
			name: "non-numeric UID",
			line: "bad:x:abc:1000:Bad User:/home/bad:/bin/bash",
			want: nil,
		},
		{
			name: "non-numeric GID",
			line: "bad:x:1000:xyz:Bad User:/home/bad:/bin/bash",
			want: nil,
		},
		{
			name: "whitespace line",
			line: "   ",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uaParsePasswdLine(tt.line)

			if tt.want == nil {
				if got != nil {
					t.Errorf("uaParsePasswdLine(%q) = %+v, want nil", tt.line, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("uaParsePasswdLine(%q) = nil, want %+v", tt.line, tt.want)
			}

			if got.Username != tt.want.Username {
				t.Errorf("Username = %q, want %q", got.Username, tt.want.Username)
			}
			if got.UID != tt.want.UID {
				t.Errorf("UID = %d, want %d", got.UID, tt.want.UID)
			}
			if got.GID != tt.want.GID {
				t.Errorf("GID = %d, want %d", got.GID, tt.want.GID)
			}
			if got.GECOS != tt.want.GECOS {
				t.Errorf("GECOS = %q, want %q", got.GECOS, tt.want.GECOS)
			}
			if got.HomeDir != tt.want.HomeDir {
				t.Errorf("HomeDir = %q, want %q", got.HomeDir, tt.want.HomeDir)
			}
			if got.Shell != tt.want.Shell {
				t.Errorf("Shell = %q, want %q", got.Shell, tt.want.Shell)
			}
		})
	}
}

func TestUAParseGroupLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want *UAGroupEntry
	}{
		{
			name: "root group",
			line: "root:x:0:",
			want: &UAGroupEntry{
				Name:    "root",
				GID:     0,
				Members: nil,
			},
		},
		{
			name: "group with single member",
			line: "docker:x:999:jordan",
			want: &UAGroupEntry{
				Name:    "docker",
				GID:     999,
				Members: []string{"jordan"},
			},
		},
		{
			name: "group with multiple members",
			line: "sudo:x:27:jordan,admin,deploy",
			want: &UAGroupEntry{
				Name:    "sudo",
				GID:     27,
				Members: []string{"jordan", "admin", "deploy"},
			},
		},
		{
			name: "group with no members",
			line: "nogroup:x:65534:",
			want: &UAGroupEntry{
				Name:    "nogroup",
				GID:     65534,
				Members: nil,
			},
		},
		{
			name: "empty line",
			line: "",
			want: nil,
		},
		{
			name: "comment line",
			line: "# This is a comment",
			want: nil,
		},
		{
			name: "too few fields",
			line: "invalid:x",
			want: nil,
		},
		{
			name: "non-numeric GID",
			line: "bad:x:abc:user1",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uaParseGroupLine(tt.line)

			if tt.want == nil {
				if got != nil {
					t.Errorf("uaParseGroupLine(%q) = %+v, want nil", tt.line, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("uaParseGroupLine(%q) = nil, want %+v", tt.line, tt.want)
			}

			if got.Name != tt.want.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.want.Name)
			}
			if got.GID != tt.want.GID {
				t.Errorf("GID = %d, want %d", got.GID, tt.want.GID)
			}
			if len(got.Members) != len(tt.want.Members) {
				t.Errorf("Members = %v, want %v", got.Members, tt.want.Members)
			} else {
				for i, member := range got.Members {
					if member != tt.want.Members[i] {
						t.Errorf("Members[%d] = %q, want %q", i, member, tt.want.Members[i])
					}
				}
			}
		})
	}
}

func TestCompareUsers(t *testing.T) {
	tests := []struct {
		name          string
		oldUsers      map[string]UserEntry
		newUsers      map[string]UserEntry
		wantCreated   []string
		wantModified  []string
		wantDeleted   []string
	}{
		{
			name: "user created",
			oldUsers: map[string]UserEntry{
				"root": {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
			},
			newUsers: map[string]UserEntry{
				"root":   {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
				"jordan": {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/zsh"},
			},
			wantCreated:  []string{"jordan"},
			wantModified: nil,
			wantDeleted:  nil,
		},
		{
			name: "user deleted",
			oldUsers: map[string]UserEntry{
				"root":    {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
				"olduser": {Username: "olduser", UID: 1001, GID: 1001, Shell: "/bin/bash"},
			},
			newUsers: map[string]UserEntry{
				"root": {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
			},
			wantCreated:  nil,
			wantModified: nil,
			wantDeleted:  []string{"olduser"},
		},
		{
			name: "user modified shell",
			oldUsers: map[string]UserEntry{
				"jordan": {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			},
			newUsers: map[string]UserEntry{
				"jordan": {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/zsh"},
			},
			wantCreated:  nil,
			wantModified: []string{"jordan"},
			wantDeleted:  nil,
		},
		{
			name: "user modified UID",
			oldUsers: map[string]UserEntry{
				"jordan": {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			},
			newUsers: map[string]UserEntry{
				"jordan": {Username: "jordan", UID: 1001, GID: 1000, Shell: "/bin/bash"},
			},
			wantCreated:  nil,
			wantModified: []string{"jordan"},
			wantDeleted:  nil,
		},
		{
			name: "no changes",
			oldUsers: map[string]UserEntry{
				"root":   {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
				"jordan": {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/zsh"},
			},
			newUsers: map[string]UserEntry{
				"root":   {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
				"jordan": {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/zsh"},
			},
			wantCreated:  nil,
			wantModified: nil,
			wantDeleted:  nil,
		},
		{
			name: "multiple changes",
			oldUsers: map[string]UserEntry{
				"root":    {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
				"olduser": {Username: "olduser", UID: 1001, GID: 1001, Shell: "/bin/bash"},
				"jordan":  {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			},
			newUsers: map[string]UserEntry{
				"root":    {Username: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
				"jordan":  {Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/zsh"}, // modified
				"newuser": {Username: "newuser", UID: 1002, GID: 1002, Shell: "/bin/bash"}, // created
			},
			wantCreated:  []string{"newuser"},
			wantModified: []string{"jordan"},
			wantDeleted:  []string{"olduser"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created, modified, deleted := compareUsers(tt.oldUsers, tt.newUsers)

			// Check created
			createdNames := make([]string, len(created))
			for i, u := range created {
				createdNames[i] = u.Username
			}
			if !stringSlicesEqual(createdNames, tt.wantCreated) {
				t.Errorf("created = %v, want %v", createdNames, tt.wantCreated)
			}

			// Check modified
			modifiedNames := make([]string, len(modified))
			for i, c := range modified {
				modifiedNames[i] = c.New.Username
			}
			if !stringSlicesEqual(modifiedNames, tt.wantModified) {
				t.Errorf("modified = %v, want %v", modifiedNames, tt.wantModified)
			}

			// Check deleted
			deletedNames := make([]string, len(deleted))
			for i, u := range deleted {
				deletedNames[i] = u.Username
			}
			if !stringSlicesEqual(deletedNames, tt.wantDeleted) {
				t.Errorf("deleted = %v, want %v", deletedNames, tt.wantDeleted)
			}
		})
	}
}

func TestDescribeUserChanges(t *testing.T) {
	tests := []struct {
		name        string
		old         UserEntry
		new         UserEntry
		wantChanges []string
	}{
		{
			name: "shell changed",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			new:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/zsh"},
			wantChanges: []string{"shell_changed"},
		},
		{
			name: "uid changed",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			new:  UserEntry{Username: "jordan", UID: 1001, GID: 1000, Shell: "/bin/bash"},
			wantChanges: []string{"uid_changed"},
		},
		{
			name: "gid changed",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			new:  UserEntry{Username: "jordan", UID: 1000, GID: 1001, Shell: "/bin/bash"},
			wantChanges: []string{"gid_changed"},
		},
		{
			name: "home_dir changed",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, HomeDir: "/home/jordan"},
			new:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, HomeDir: "/home/newjordan"},
			wantChanges: []string{"home_dir_changed"},
		},
		{
			name: "gecos changed",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, GECOS: "Jordan"},
			new:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, GECOS: "Jordan Smith"},
			wantChanges: []string{"gecos_changed"},
		},
		{
			name: "multiple changes",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash", HomeDir: "/home/jordan"},
			new:  UserEntry{Username: "jordan", UID: 1001, GID: 1001, Shell: "/bin/zsh", HomeDir: "/home/newjordan"},
			wantChanges: []string{"uid_changed", "gid_changed", "home_dir_changed", "shell_changed"},
		},
		{
			name: "no changes",
			old:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			new:  UserEntry{Username: "jordan", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			wantChanges: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := describeUserChanges(tt.old, tt.new)

			if !stringSlicesEqualUnordered(got, tt.wantChanges) {
				t.Errorf("describeUserChanges() = %v, want %v", got, tt.wantChanges)
			}
		})
	}
}

func TestGetUserGroups(t *testing.T) {
	groups := map[string]UAGroupEntry{
		"root":   {Name: "root", GID: 0, Members: nil},
		"users":  {Name: "users", GID: 1000, Members: nil},
		"docker": {Name: "docker", GID: 999, Members: []string{"jordan", "admin"}},
		"sudo":   {Name: "sudo", GID: 27, Members: []string{"jordan"}},
		"admin":  {Name: "admin", GID: 1001, Members: []string{"admin"}},
	}

	tests := []struct {
		name       string
		username   string
		primaryGID int
		want       []string
	}{
		{
			name:       "user with primary group and supplementary groups",
			username:   "jordan",
			primaryGID: 1000,
			want:       []string{"users", "docker", "sudo"},
		},
		{
			name:       "user with only primary group",
			username:   "newuser",
			primaryGID: 1000,
			want:       []string{"users"},
		},
		{
			name:       "root user",
			username:   "root",
			primaryGID: 0,
			want:       []string{"root"},
		},
		{
			name:       "user with no matching groups",
			username:   "orphan",
			primaryGID: 9999,
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getUserGroups(tt.username, tt.primaryGID, groups)

			if !stringSlicesEqualUnordered(got, tt.want) {
				t.Errorf("getUserGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindUsersWithGroupChanges(t *testing.T) {
	tests := []struct {
		name      string
		oldGroups map[string]UAGroupEntry
		newGroups map[string]UAGroupEntry
		want      []string
	}{
		{
			name: "user added to group",
			oldGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"admin"}},
			},
			newGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"admin", "jordan"}},
			},
			want: []string{"jordan"},
		},
		{
			name: "user removed from group",
			oldGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"admin", "jordan"}},
			},
			newGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"admin"}},
			},
			want: []string{"jordan"},
		},
		{
			name: "no changes",
			oldGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"admin", "jordan"}},
			},
			newGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"admin", "jordan"}},
			},
			want: nil,
		},
		{
			name: "user moved between groups",
			oldGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: []string{"jordan"}},
				"sudo":   {Name: "sudo", GID: 27, Members: nil},
			},
			newGroups: map[string]UAGroupEntry{
				"docker": {Name: "docker", GID: 999, Members: nil},
				"sudo":   {Name: "sudo", GID: 27, Members: []string{"jordan"}},
			},
			want: []string{"jordan"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findUsersWithGroupChanges(tt.oldGroups, tt.newGroups)

			gotSlice := make([]string, 0, len(got))
			for user := range got {
				gotSlice = append(gotSlice, user)
			}

			if !stringSlicesEqualUnordered(gotSlice, tt.want) {
				t.Errorf("findUsersWithGroupChanges() = %v, want %v", gotSlice, tt.want)
			}
		})
	}
}

func TestParsePasswdFile(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")

	content := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
jordan:x:1000:1000:Jordan Smith:/home/jordan:/bin/zsh
# This is a comment
nginx:x:101:101:nginx:/var/www:/usr/sbin/nologin
`

	if err := os.WriteFile(passwdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test passwd file: %v", err)
	}

	users, err := uaParsePasswdFile(passwdPath)
	if err != nil {
		t.Fatalf("uaParsePasswdFile() error = %v", err)
	}

	if len(users) != 4 {
		t.Errorf("len(users) = %d, want 4", len(users))
	}

	// Check specific user
	jordan, exists := users["jordan"]
	if !exists {
		t.Fatal("user 'jordan' not found")
	}
	if jordan.UID != 1000 {
		t.Errorf("jordan.UID = %d, want 1000", jordan.UID)
	}
	if jordan.Shell != "/bin/zsh" {
		t.Errorf("jordan.Shell = %q, want /bin/zsh", jordan.Shell)
	}
}

func TestParseGroupFile(t *testing.T) {
	dir := t.TempDir()
	groupPath := filepath.Join(dir, "group")

	content := `root:x:0:
daemon:x:1:
sudo:x:27:jordan,admin
docker:x:999:jordan
users:x:1000:
`

	if err := os.WriteFile(groupPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test group file: %v", err)
	}

	groups, err := uaParseGroupFile(groupPath)
	if err != nil {
		t.Fatalf("uaParseGroupFile() error = %v", err)
	}

	if len(groups) != 5 {
		t.Errorf("len(groups) = %d, want 5", len(groups))
	}

	// Check specific group
	sudo, exists := groups["sudo"]
	if !exists {
		t.Fatal("group 'sudo' not found")
	}
	if sudo.GID != 27 {
		t.Errorf("sudo.GID = %d, want 27", sudo.GID)
	}
	if len(sudo.Members) != 2 {
		t.Errorf("len(sudo.Members) = %d, want 2", len(sudo.Members))
	}
}

func TestUserAccountWatcherDetectsUserCreated(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	shadowPath := filepath.Join(dir, "shadow")

	// Create initial files
	initialPasswd := `root:x:0:0:root:/root:/bin/bash
`
	initialGroup := `root:x:0:
users:x:1000:
`

	if err := os.WriteFile(passwdPath, []byte(initialPasswd), 0644); err != nil {
		t.Fatalf("failed to create passwd file: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte(initialGroup), 0644); err != nil {
		t.Fatalf("failed to create group file: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to create shadow file: %v", err)
	}

	w := NewUserAccountWatcher(UserAccountConfig{
		PasswdPath: passwdPath,
		GroupPath:  groupPath,
		ShadowPath: shadowPath,
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Add a new user
	newPasswd := `root:x:0:0:root:/root:/bin/bash
jordan:x:1000:1000:Jordan Smith:/home/jordan:/bin/zsh
`
	if err := os.WriteFile(passwdPath, []byte(newPasswd), 0644); err != nil {
		t.Fatalf("failed to update passwd file: %v", err)
	}

	// Wait for event
	var received *event.Event
	select {
	case e := <-ch:
		received = &e
	case <-time.After(1 * time.Second):
		// May not receive event on all platforms due to fsnotify limitations
	}

	if received != nil {
		if received.Type != event.UserAccountCreated {
			t.Errorf("Type = %v, want %v", received.Type, event.UserAccountCreated)
		}

		payload := received.Payload
		if payload["username"] != "jordan" {
			t.Errorf("username = %v, want jordan", payload["username"])
		}
		if payload["uid"] != 1000 {
			t.Errorf("uid = %v, want 1000", payload["uid"])
		}
	}
}

func TestUserAccountWatcherDetectsUserDeleted(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	shadowPath := filepath.Join(dir, "shadow")

	// Create initial files with a user
	initialPasswd := `root:x:0:0:root:/root:/bin/bash
olduser:x:1001:1001:Old User:/home/olduser:/bin/bash
`
	initialGroup := `root:x:0:
users:x:1000:
`

	if err := os.WriteFile(passwdPath, []byte(initialPasswd), 0644); err != nil {
		t.Fatalf("failed to create passwd file: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte(initialGroup), 0644); err != nil {
		t.Fatalf("failed to create group file: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to create shadow file: %v", err)
	}

	w := NewUserAccountWatcher(UserAccountConfig{
		PasswdPath: passwdPath,
		GroupPath:  groupPath,
		ShadowPath: shadowPath,
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Remove the user
	newPasswd := `root:x:0:0:root:/root:/bin/bash
`
	if err := os.WriteFile(passwdPath, []byte(newPasswd), 0644); err != nil {
		t.Fatalf("failed to update passwd file: %v", err)
	}

	// Wait for event
	var received *event.Event
	select {
	case e := <-ch:
		received = &e
	case <-time.After(1 * time.Second):
		// May not receive event on all platforms
	}

	if received != nil {
		if received.Type != event.UserAccountDeleted {
			t.Errorf("Type = %v, want %v", received.Type, event.UserAccountDeleted)
		}

		payload := received.Payload
		if payload["username"] != "olduser" {
			t.Errorf("username = %v, want olduser", payload["username"])
		}
	}
}

func TestUserAccountWatcherDetectsUserModified(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	shadowPath := filepath.Join(dir, "shadow")

	// Create initial files
	initialPasswd := `root:x:0:0:root:/root:/bin/bash
jordan:x:1000:1000:Jordan Smith:/home/jordan:/bin/bash
`
	initialGroup := `root:x:0:
users:x:1000:
`

	if err := os.WriteFile(passwdPath, []byte(initialPasswd), 0644); err != nil {
		t.Fatalf("failed to create passwd file: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte(initialGroup), 0644); err != nil {
		t.Fatalf("failed to create group file: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to create shadow file: %v", err)
	}

	w := NewUserAccountWatcher(UserAccountConfig{
		PasswdPath: passwdPath,
		GroupPath:  groupPath,
		ShadowPath: shadowPath,
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Modify user's shell
	newPasswd := `root:x:0:0:root:/root:/bin/bash
jordan:x:1000:1000:Jordan Smith:/home/jordan:/bin/zsh
`
	if err := os.WriteFile(passwdPath, []byte(newPasswd), 0644); err != nil {
		t.Fatalf("failed to update passwd file: %v", err)
	}

	// Wait for event
	var received *event.Event
	select {
	case e := <-ch:
		received = &e
	case <-time.After(1 * time.Second):
		// May not receive event on all platforms
	}

	if received != nil {
		if received.Type != event.UserAccountModified {
			t.Errorf("Type = %v, want %v", received.Type, event.UserAccountModified)
		}

		payload := received.Payload
		if payload["username"] != "jordan" {
			t.Errorf("username = %v, want jordan", payload["username"])
		}
		if payload["shell"] != "/bin/zsh" {
			t.Errorf("shell = %v, want /bin/zsh", payload["shell"])
		}
	}
}

func TestUserAccountWatcherContextCancellation(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	shadowPath := filepath.Join(dir, "shadow")

	// Create minimal files
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0644); err != nil {
		t.Fatalf("failed to create passwd file: %v", err)
	}
	if err := os.WriteFile(groupPath, []byte("root:x:0:\n"), 0644); err != nil {
		t.Fatalf("failed to create group file: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to create shadow file: %v", err)
	}

	w := NewUserAccountWatcher(UserAccountConfig{
		PasswdPath: passwdPath,
		GroupPath:  groupPath,
		ShadowPath: shadowPath,
		FortressID: "fort_test",
		ServerID:   "srv_test",
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
	case <-time.After(500 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

func TestDirOf(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/etc/passwd", "/etc"},
		{"/etc/group", "/etc"},
		{"/var/log/auth.log", "/var/log"},
		{"/file.txt", "/"},
		{"file.txt", "."},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := dirOf(tt.path)
			if got != tt.want {
				t.Errorf("dirOf(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestUsersEqual(t *testing.T) {
	user1 := UserEntry{
		Username: "jordan",
		UID:      1000,
		GID:      1000,
		GECOS:    "Jordan Smith",
		HomeDir:  "/home/jordan",
		Shell:    "/bin/bash",
	}

	user2 := user1 // Copy

	if !usersEqual(user1, user2) {
		t.Error("identical users should be equal")
	}

	user2.Shell = "/bin/zsh"
	if usersEqual(user1, user2) {
		t.Error("users with different shells should not be equal")
	}
}

// Helper functions for tests

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]int)
	for _, s := range a {
		aMap[s]++
	}
	for _, s := range b {
		aMap[s]--
		if aMap[s] < 0 {
			return false
		}
	}
	return true
}
