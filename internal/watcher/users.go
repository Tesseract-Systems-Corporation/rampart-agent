package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// UserAccountConfig holds configuration for the UserAccount watcher.
// This watcher monitors changes to user accounts for SOC 2 CC6.2 compliance.
type UserAccountConfig struct {
	// PasswdPath is the path to the passwd file.
	// Defaults to /etc/passwd if empty.
	PasswdPath string

	// GroupPath is the path to the group file.
	// Defaults to /etc/group if empty.
	GroupPath string

	// ShadowPath is the path to the shadow file.
	// Defaults to /etc/shadow if empty.
	ShadowPath string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// UserEntry represents a parsed /etc/passwd entry for the UserAccountWatcher.
// Note: This is distinct from PasswdEntry in accessreview.go to avoid import cycles.
type UserEntry struct {
	Username string
	UID      int
	GID      int
	GECOS    string
	HomeDir  string
	Shell    string
}

// UAGroupEntry represents a parsed /etc/group entry for the UserAccountWatcher.
// Note: Prefixed with UA to avoid conflict with GroupEntry in accessreview.go.
type UAGroupEntry struct {
	Name    string
	GID     int
	Members []string
}

// UserAccountWatcher monitors changes to system user accounts.
type UserAccountWatcher struct {
	passwdPath string
	groupPath  string
	shadowPath string
	fortressID string
	serverID   string
	logger     *slog.Logger

	// Previous state for comparison
	users  map[string]UserEntry
	groups map[string]UAGroupEntry
	mu     sync.RWMutex
}

// NewUserAccountWatcher creates a new UserAccountWatcher with the given configuration.
func NewUserAccountWatcher(cfg UserAccountConfig) *UserAccountWatcher {
	passwdPath := cfg.PasswdPath
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}

	groupPath := cfg.GroupPath
	if groupPath == "" {
		groupPath = "/etc/group"
	}

	shadowPath := cfg.ShadowPath
	if shadowPath == "" {
		shadowPath = "/etc/shadow"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &UserAccountWatcher{
		passwdPath: passwdPath,
		groupPath:  groupPath,
		shadowPath: shadowPath,
		fortressID: cfg.FortressID,
		serverID:   cfg.ServerID,
		logger:     logger,
		users:      make(map[string]UserEntry),
		groups:     make(map[string]UAGroupEntry),
	}
}

// Watch starts watching user account files and returns a channel of events.
func (w *UserAccountWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(out)
		defer watcher.Close()

		w.logger.Info("starting user account watcher",
			"passwd", w.passwdPath,
			"group", w.groupPath,
			"shadow", w.shadowPath,
		)

		// Add watches for the files (actually watch the directory since files may be replaced)
		watchPaths := []string{w.passwdPath, w.groupPath, w.shadowPath}
		dirs := make(map[string]bool)
		for _, path := range watchPaths {
			dir := dirOf(path)
			if !dirs[dir] {
				if err := watcher.Add(dir); err != nil {
					w.logger.Error("failed to add watch path", "path", dir, "error", err)
				} else {
					dirs[dir] = true
				}
			}
		}

		// Initialize state
		w.initializeState()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("user account watcher stopped", "reason", ctx.Err())
				return

			case ev, ok := <-watcher.Events:
				if !ok {
					return
				}
				w.handleEvent(ctx, out, ev)

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				w.logger.Error("fsnotify error", "error", err)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *UserAccountWatcher) Name() string {
	return "users"
}

// dirOf returns the directory portion of a path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

// initializeState reads the current state of passwd and group files.
func (w *UserAccountWatcher) initializeState() {
	w.mu.Lock()
	defer w.mu.Unlock()

	users, err := uaParsePasswdFile(w.passwdPath)
	if err != nil {
		w.logger.Error("failed to parse passwd file", "path", w.passwdPath, "error", err)
	} else {
		w.users = users
	}

	groups, err := uaParseGroupFile(w.groupPath)
	if err != nil {
		w.logger.Error("failed to parse group file", "path", w.groupPath, "error", err)
	} else {
		w.groups = groups
	}
}

// handleEvent processes a fsnotify event.
func (w *UserAccountWatcher) handleEvent(ctx context.Context, out chan<- event.Event, ev fsnotify.Event) {
	// Only care about writes and creates (file replacement)
	if !ev.Has(fsnotify.Write) && !ev.Has(fsnotify.Create) {
		return
	}

	// Check if this is one of our watched files
	name := ev.Name
	if name != w.passwdPath && name != w.groupPath && name != w.shadowPath {
		return
	}

	w.logger.Debug("user account file changed", "path", name, "op", ev.Op.String())

	// Handle based on which file changed
	switch name {
	case w.passwdPath:
		w.handlePasswdChange(ctx, out)
	case w.groupPath:
		w.handleGroupChange(ctx, out)
	case w.shadowPath:
		// Shadow changes typically accompany passwd changes
		// We emit a generic modification event since we can't read shadow without root
		w.logger.Debug("shadow file changed, may indicate password modification")
	}
}

// handlePasswdChange processes changes to /etc/passwd.
func (w *UserAccountWatcher) handlePasswdChange(ctx context.Context, out chan<- event.Event) {
	newUsers, err := uaParsePasswdFile(w.passwdPath)
	if err != nil {
		w.logger.Error("failed to parse passwd file", "error", err)
		return
	}

	w.mu.Lock()
	oldUsers := w.users
	w.users = newUsers
	w.mu.Unlock()

	// Find created, modified, and deleted users
	created, modified, deleted := compareUsers(oldUsers, newUsers)

	// Get group memberships for context
	w.mu.RLock()
	groups := w.groups
	w.mu.RUnlock()

	// Emit events for created users
	for _, user := range created {
		userGroups := getUserGroups(user.Username, user.GID, groups)

		w.logger.Info("user account created",
			"username", user.Username,
			"uid", user.UID,
			"gid", user.GID,
		)

		e := w.createUserEvent(event.UserAccountCreated, user, userGroups, nil)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}

	// Emit events for modified users
	for _, change := range modified {
		userGroups := getUserGroups(change.New.Username, change.New.GID, groups)
		changes := describeUserChanges(change.Old, change.New)

		w.logger.Info("user account modified",
			"username", change.New.Username,
			"changes", changes,
		)

		e := w.createUserEvent(event.UserAccountModified, change.New, userGroups, changes)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}

	// Emit events for deleted users
	for _, user := range deleted {
		userGroups := getUserGroups(user.Username, user.GID, groups)

		w.logger.Info("user account deleted",
			"username", user.Username,
			"uid", user.UID,
		)

		e := w.createUserEvent(event.UserAccountDeleted, user, userGroups, nil)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}
}

// handleGroupChange processes changes to /etc/group.
func (w *UserAccountWatcher) handleGroupChange(ctx context.Context, out chan<- event.Event) {
	newGroups, err := uaParseGroupFile(w.groupPath)
	if err != nil {
		w.logger.Error("failed to parse group file", "error", err)
		return
	}

	w.mu.Lock()
	oldGroups := w.groups

	// Check for users whose group memberships changed
	usersWithChangedGroups := findUsersWithGroupChanges(oldGroups, newGroups)

	w.groups = newGroups
	w.mu.Unlock()

	// Get current users
	w.mu.RLock()
	users := w.users
	w.mu.RUnlock()

	// Emit modification events for users whose group memberships changed
	for username := range usersWithChangedGroups {
		user, exists := users[username]
		if !exists {
			continue
		}

		userGroups := getUserGroups(username, user.GID, newGroups)
		changes := []string{"group_membership_changed"}

		w.logger.Info("user group membership changed",
			"username", username,
			"groups", userGroups,
		)

		e := w.createUserEvent(event.UserAccountModified, user, userGroups, changes)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}
}

// createUserEvent creates a user account event.
func (w *UserAccountWatcher) createUserEvent(eventType event.EventType, user UserEntry, groups []string, changes []string) event.Event {
	e := event.NewEvent(eventType, w.fortressID, w.serverID, map[string]any{
		"username": user.Username,
		"uid":      user.UID,
		"gid":      user.GID,
		"groups":   groups,
		"shell":    user.Shell,
		"home_dir": user.HomeDir,
	})

	if len(changes) > 0 {
		e.Payload["changes"] = changes
	}

	// Set actor as system since we can't easily determine who made the change
	// In a production environment, this could be enhanced by correlating with auth.log
	e.Actor = &event.Actor{
		Type: event.ActorTypeSystem,
		Name: "system",
	}

	return e
}

// uaParsePasswdFile reads and parses an /etc/passwd format file.
func uaParsePasswdFile(path string) (map[string]UserEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	users := make(map[string]UserEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		user := uaParsePasswdLine(line)
		if user != nil {
			users[user.Username] = *user
		}
	}

	return users, scanner.Err()
}

// uaParsePasswdLine parses a single line from /etc/passwd.
// Format: username:x:uid:gid:gecos:home:shell
func uaParsePasswdLine(line string) *UserEntry {
	// Skip empty lines and comments
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return nil
	}

	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil
	}

	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil
	}

	return &UserEntry{
		Username: fields[0],
		UID:      uid,
		GID:      gid,
		GECOS:    fields[4],
		HomeDir:  fields[5],
		Shell:    fields[6],
	}
}

// uaParseGroupFile reads and parses an /etc/group format file.
func uaParseGroupFile(path string) (map[string]UAGroupEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	groups := make(map[string]UAGroupEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		group := uaParseGroupLine(line)
		if group != nil {
			groups[group.Name] = *group
		}
	}

	return groups, scanner.Err()
}

// uaParseGroupLine parses a single line from /etc/group.
// Format: groupname:x:gid:members
func uaParseGroupLine(line string) *UAGroupEntry {
	// Skip empty lines and comments
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	fields := strings.Split(line, ":")
	if len(fields) < 4 {
		return nil
	}

	gid, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil
	}

	var members []string
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}

	return &UAGroupEntry{
		Name:    fields[0],
		GID:     gid,
		Members: members,
	}
}

// userChange represents a change to a user entry.
type userChange struct {
	Old UserEntry
	New UserEntry
}

// compareUsers compares old and new user maps and returns created, modified, and deleted users.
func compareUsers(oldUsers, newUsers map[string]UserEntry) (created []UserEntry, modified []userChange, deleted []UserEntry) {
	// Find created and modified users
	for username, newUser := range newUsers {
		oldUser, exists := oldUsers[username]
		if !exists {
			created = append(created, newUser)
		} else if !usersEqual(oldUser, newUser) {
			modified = append(modified, userChange{Old: oldUser, New: newUser})
		}
	}

	// Find deleted users
	for username, oldUser := range oldUsers {
		if _, exists := newUsers[username]; !exists {
			deleted = append(deleted, oldUser)
		}
	}

	return
}

// usersEqual checks if two user entries are equal.
func usersEqual(a, b UserEntry) bool {
	return a.Username == b.Username &&
		a.UID == b.UID &&
		a.GID == b.GID &&
		a.GECOS == b.GECOS &&
		a.HomeDir == b.HomeDir &&
		a.Shell == b.Shell
}

// describeUserChanges returns a list of what changed between two user entries.
func describeUserChanges(old, new UserEntry) []string {
	var changes []string

	if old.UID != new.UID {
		changes = append(changes, "uid_changed")
	}
	if old.GID != new.GID {
		changes = append(changes, "gid_changed")
	}
	if old.GECOS != new.GECOS {
		changes = append(changes, "gecos_changed")
	}
	if old.HomeDir != new.HomeDir {
		changes = append(changes, "home_dir_changed")
	}
	if old.Shell != new.Shell {
		changes = append(changes, "shell_changed")
	}

	return changes
}

// getUserGroups returns the list of groups a user belongs to.
func getUserGroups(username string, primaryGID int, groups map[string]UAGroupEntry) []string {
	var userGroups []string

	for name, group := range groups {
		// Check if this is the primary group
		if group.GID == primaryGID {
			userGroups = append(userGroups, name)
			continue
		}

		// Check if user is in the members list
		for _, member := range group.Members {
			if member == username {
				userGroups = append(userGroups, name)
				break
			}
		}
	}

	return userGroups
}

// findUsersWithGroupChanges finds users whose group memberships changed.
func findUsersWithGroupChanges(oldGroups, newGroups map[string]UAGroupEntry) map[string]bool {
	affected := make(map[string]bool)

	// Build old membership map: user -> groups
	oldMemberships := make(map[string]map[string]bool)
	for groupName, group := range oldGroups {
		for _, member := range group.Members {
			if oldMemberships[member] == nil {
				oldMemberships[member] = make(map[string]bool)
			}
			oldMemberships[member][groupName] = true
		}
	}

	// Build new membership map and compare
	newMemberships := make(map[string]map[string]bool)
	for groupName, group := range newGroups {
		for _, member := range group.Members {
			if newMemberships[member] == nil {
				newMemberships[member] = make(map[string]bool)
			}
			newMemberships[member][groupName] = true
		}
	}

	// Find users with changed memberships
	allUsers := make(map[string]bool)
	for user := range oldMemberships {
		allUsers[user] = true
	}
	for user := range newMemberships {
		allUsers[user] = true
	}

	for user := range allUsers {
		oldSet := oldMemberships[user]
		newSet := newMemberships[user]

		// Check if sets are different
		if len(oldSet) != len(newSet) {
			affected[user] = true
			continue
		}

		for group := range oldSet {
			if !newSet[group] {
				affected[user] = true
				break
			}
		}
	}

	return affected
}
