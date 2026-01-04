package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DefaultSnapshotInterval is the default interval between access review snapshots.
const DefaultSnapshotInterval = 24 * time.Hour

// DefaultStaleAccountDays is the default threshold for marking accounts as stale.
const DefaultStaleAccountDays = 90

// MinimumHumanUID is the minimum UID for human user accounts on most Linux systems.
const MinimumHumanUID = 1000

// AccessReviewConfig holds configuration for the AccessReview watcher.
type AccessReviewConfig struct {
	// SnapshotInterval is how often to create access review snapshots.
	// Defaults to DefaultSnapshotInterval (24 hours) if zero.
	SnapshotInterval time.Duration

	// StaleAccountDays is the number of days without login to mark an account as stale.
	// Defaults to DefaultStaleAccountDays (90 days) if zero.
	StaleAccountDays int

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger

	// PasswdPath is the path to the passwd file. Defaults to /etc/passwd.
	PasswdPath string

	// GroupPath is the path to the group file. Defaults to /etc/group.
	GroupPath string

	// SudoersPath is the path to the sudoers file. Defaults to /etc/sudoers.
	SudoersPath string

	// SudoersDPath is the path to the sudoers.d directory. Defaults to /etc/sudoers.d.
	SudoersDPath string
}

// AccessReviewWatcher creates periodic snapshots of all user accounts for SOC 2 CC6.2 compliance.
type AccessReviewWatcher struct {
	snapshotInterval time.Duration
	staleAccountDays int
	fortressID       string
	serverID         string
	logger           *slog.Logger
	passwdPath       string
	groupPath        string
	sudoersPath      string
	sudoersDPath     string
}

// PasswdEntry represents a parsed entry from /etc/passwd.
type PasswdEntry struct {
	Username string
	UID      int
	GID      int
	Comment  string
	HomeDir  string
	Shell    string
}

// GroupEntry represents a parsed entry from /etc/group.
type GroupEntry struct {
	Name    string
	GID     int
	Members []string
}

// NewAccessReviewWatcher creates a new AccessReviewWatcher with the given configuration.
func NewAccessReviewWatcher(cfg AccessReviewConfig) *AccessReviewWatcher {
	interval := cfg.SnapshotInterval
	if interval == 0 {
		interval = DefaultSnapshotInterval
	}

	staleAccountDays := cfg.StaleAccountDays
	if staleAccountDays == 0 {
		staleAccountDays = DefaultStaleAccountDays
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	passwdPath := cfg.PasswdPath
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}

	groupPath := cfg.GroupPath
	if groupPath == "" {
		groupPath = "/etc/group"
	}

	sudoersPath := cfg.SudoersPath
	if sudoersPath == "" {
		sudoersPath = "/etc/sudoers"
	}

	sudoersDPath := cfg.SudoersDPath
	if sudoersDPath == "" {
		sudoersDPath = "/etc/sudoers.d"
	}

	return &AccessReviewWatcher{
		snapshotInterval: interval,
		staleAccountDays: staleAccountDays,
		fortressID:       cfg.FortressID,
		serverID:         cfg.ServerID,
		logger:           logger,
		passwdPath:       passwdPath,
		groupPath:        groupPath,
		sudoersPath:      sudoersPath,
		sudoersDPath:     sudoersDPath,
	}
}

// Watch starts watching and creating periodic access review snapshots.
func (w *AccessReviewWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting access review watcher",
			"interval", w.snapshotInterval,
			"stale_threshold_days", w.staleAccountDays,
		)

		// Send immediate snapshot
		w.emitSnapshot(ctx, out)

		ticker := time.NewTicker(w.snapshotInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("access review watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.emitSnapshot(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *AccessReviewWatcher) Name() string {
	return "accessreview"
}

// emitSnapshot collects all user account data and emits an AccessReviewSnapshot event.
func (w *AccessReviewWatcher) emitSnapshot(ctx context.Context, out chan<- event.Event) {
	w.logger.Debug("creating access review snapshot")

	// Parse /etc/passwd
	passwdEntries, err := parsePasswdFile(w.passwdPath)
	if err != nil {
		w.logger.Error("failed to parse passwd file", "error", err)
		return
	}

	// Parse /etc/group
	groupEntries, err := parseGroupFile(w.groupPath)
	if err != nil {
		w.logger.Error("failed to parse group file", "error", err)
		// Continue with empty groups
		groupEntries = nil
	}

	// Build group membership map: username -> []groupname
	groupMembership := buildGroupMembership(groupEntries, passwdEntries)

	// Parse sudoers for sudo access
	sudoUsers := w.parseSudoAccess(groupMembership)

	// Get last login times
	lastLogins := getLastLogins()

	// Build user snapshots
	var users []event.UserSnapshot
	var activeUsers, disabledUsers, serviceAccounts int
	var sshKeyUsers, staleAccounts []string
	sudoUserList := make([]string, 0, len(sudoUsers))

	for _, entry := range passwdEntries {
		snapshot := w.buildUserSnapshot(entry, groupMembership, sudoUsers, lastLogins)
		users = append(users, snapshot)

		// Count by status
		switch snapshot.AccountStatus {
		case "active":
			activeUsers++
		case "disabled":
			disabledUsers++
		}

		// Track service accounts
		if isServiceAccount(entry) {
			serviceAccounts++
		}

		// Track SSH key users
		if snapshot.HasSSHKey {
			sshKeyUsers = append(sshKeyUsers, entry.Username)
		}

		// Track sudo users
		if snapshot.HasSudoAccess {
			sudoUserList = append(sudoUserList, entry.Username)
		}

		// Track stale accounts
		if w.isStaleAccount(snapshot, entry) {
			staleAccounts = append(staleAccounts, entry.Username)
		}
	}

	payload := event.AccessReviewPayload{
		TotalUsers:      len(users),
		ActiveUsers:     activeUsers,
		DisabledUsers:   disabledUsers,
		ServiceAccounts: serviceAccounts,
		SudoUsers:       sudoUserList,
		SSHKeyUsers:     sshKeyUsers,
		StaleAccounts:   staleAccounts,
		Users:           users,
	}

	e := event.NewEvent(event.AccessReviewSnapshot, w.fortressID, w.serverID, payloadToMap(payload))

	select {
	case <-ctx.Done():
	case out <- e:
		w.logger.Info("access review snapshot emitted",
			"total_users", payload.TotalUsers,
			"active_users", payload.ActiveUsers,
			"stale_accounts", len(staleAccounts),
			"sudo_users", len(sudoUserList),
		)
	}
}

// buildUserSnapshot creates a UserSnapshot from a passwd entry and additional data.
func (w *AccessReviewWatcher) buildUserSnapshot(
	entry PasswdEntry,
	groupMembership map[string][]string,
	sudoUsers map[string]bool,
	lastLogins map[string]time.Time,
) event.UserSnapshot {
	groups := groupMembership[entry.Username]
	if groups == nil {
		groups = []string{}
	}

	snapshot := event.UserSnapshot{
		Username:      entry.Username,
		UID:           entry.UID,
		GID:           entry.GID,
		Groups:        groups,
		Shell:         entry.Shell,
		HomeDir:       entry.HomeDir,
		HasSSHKey:     hasAuthorizedKeys(entry.HomeDir),
		HasSudoAccess: sudoUsers[entry.Username],
		AccountStatus: determineAccountStatus(entry),
	}

	// Set last login if available
	if loginTime, ok := lastLogins[entry.Username]; ok {
		snapshot.LastLogin = loginTime.Format(time.RFC3339)
	}

	return snapshot
}

// isStaleAccount determines if an account is stale based on last login.
func (w *AccessReviewWatcher) isStaleAccount(snapshot event.UserSnapshot, entry PasswdEntry) bool {
	// Service accounts are not considered stale
	if isServiceAccount(entry) {
		return false
	}

	// Disabled accounts are not considered stale
	if snapshot.AccountStatus == "disabled" {
		return false
	}

	// No login recorded - could be stale
	if snapshot.LastLogin == "" {
		return true
	}

	// Parse last login time
	lastLogin, err := time.Parse(time.RFC3339, snapshot.LastLogin)
	if err != nil {
		return true
	}

	// Check if last login exceeds threshold
	staleDuration := time.Duration(w.staleAccountDays) * 24 * time.Hour
	return time.Since(lastLogin) > staleDuration
}

// parseSudoAccess parses /etc/sudoers and /etc/sudoers.d/* to find users with sudo access.
func (w *AccessReviewWatcher) parseSudoAccess(groupMembership map[string][]string) map[string]bool {
	sudoUsers := make(map[string]bool)

	// Users and groups with sudo access
	usersWithSudo, groupsWithSudo := parseSudoersFiles(w.sudoersPath, w.sudoersDPath)

	// Add direct users
	for user := range usersWithSudo {
		sudoUsers[user] = true
	}

	// Add users from sudo groups
	for _, groups := range groupMembership {
		for _, group := range groups {
			if groupsWithSudo[group] {
				// Find all users in this group and mark them as sudo users
				for username, userGroups := range groupMembership {
					for _, ug := range userGroups {
						if ug == group {
							sudoUsers[username] = true
							break
						}
					}
				}
			}
		}
	}

	return sudoUsers
}

// parsePasswdFile parses /etc/passwd and returns all entries.
func parsePasswdFile(path string) ([]PasswdEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parsePasswd(file)
}

// parsePasswd parses passwd format from a reader.
func parsePasswd(r *os.File) ([]PasswdEntry, error) {
	var entries []PasswdEntry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parsePasswdLine(line)
		if err != nil {
			continue // Skip malformed lines
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// parsePasswdLine parses a single line from /etc/passwd.
// Format: username:password:uid:gid:comment:home:shell
func parsePasswdLine(line string) (PasswdEntry, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return PasswdEntry{}, &ParseError{Field: "passwd", Message: "insufficient fields"}
	}

	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return PasswdEntry{}, &ParseError{Field: "uid", Message: "invalid uid"}
	}

	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return PasswdEntry{}, &ParseError{Field: "gid", Message: "invalid gid"}
	}

	return PasswdEntry{
		Username: fields[0],
		UID:      uid,
		GID:      gid,
		Comment:  fields[4],
		HomeDir:  fields[5],
		Shell:    fields[6],
	}, nil
}

// ParseError represents a parsing error.
type ParseError struct {
	Field   string
	Message string
}

func (e *ParseError) Error() string {
	return e.Field + ": " + e.Message
}

// parseGroupFile parses /etc/group and returns all entries.
func parseGroupFile(path string) ([]GroupEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseGroup(file)
}

// parseGroup parses group format from a reader.
func parseGroup(r *os.File) ([]GroupEntry, error) {
	var entries []GroupEntry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseGroupLine(line)
		if err != nil {
			continue // Skip malformed lines
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// parseGroupLine parses a single line from /etc/group.
// Format: groupname:password:gid:member1,member2,...
func parseGroupLine(line string) (GroupEntry, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 4 {
		return GroupEntry{}, &ParseError{Field: "group", Message: "insufficient fields"}
	}

	gid, err := strconv.Atoi(fields[2])
	if err != nil {
		return GroupEntry{}, &ParseError{Field: "gid", Message: "invalid gid"}
	}

	var members []string
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}

	return GroupEntry{
		Name:    fields[0],
		GID:     gid,
		Members: members,
	}, nil
}

// buildGroupMembership creates a map of username -> groups from group entries.
func buildGroupMembership(groups []GroupEntry, users []PasswdEntry) map[string][]string {
	membership := make(map[string][]string)

	// Create a map of GID to group name for primary groups
	gidToGroup := make(map[int]string)
	for _, g := range groups {
		gidToGroup[g.GID] = g.Name
	}

	// Add primary groups
	for _, user := range users {
		if groupName, ok := gidToGroup[user.GID]; ok {
			membership[user.Username] = append(membership[user.Username], groupName)
		}
	}

	// Add secondary groups from /etc/group
	for _, group := range groups {
		for _, member := range group.Members {
			// Avoid duplicates
			if !containsString(membership[member], group.Name) {
				membership[member] = append(membership[member], group.Name)
			}
		}
	}

	return membership
}

// containsString checks if a slice contains a string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// parseSudoersFiles parses /etc/sudoers and /etc/sudoers.d/* for sudo access.
// Returns maps of users and groups that have sudo access.
func parseSudoersFiles(sudoersPath, sudoersDPath string) (users, groups map[string]bool) {
	users = make(map[string]bool)
	groups = make(map[string]bool)

	// Parse main sudoers file
	if content, err := os.ReadFile(sudoersPath); err == nil {
		parseSudoersContent(string(content), users, groups)
	}

	// Parse sudoers.d directory
	entries, err := os.ReadDir(sudoersDPath)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			// Skip files starting with . or ending with ~
			name := entry.Name()
			if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") {
				continue
			}

			path := filepath.Join(sudoersDPath, name)
			if content, err := os.ReadFile(path); err == nil {
				parseSudoersContent(string(content), users, groups)
			}
		}
	}

	return users, groups
}

// Regex patterns for parsing sudoers
var (
	// Matches: "username ALL=(ALL) ALL" or "username ALL=(ALL:ALL) NOPASSWD: ALL"
	sudoersUserRe = regexp.MustCompile(`^(\w+)\s+ALL=`)
	// Matches: "%groupname ALL=(ALL) ALL"
	sudoersGroupRe = regexp.MustCompile(`^%(\w+)\s+ALL=`)
)

// parseSudoersContent parses sudoers file content and adds users/groups to the maps.
func parseSudoersContent(content string, users, groups map[string]bool) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for group rules (e.g., %sudo, %wheel)
		if matches := sudoersGroupRe.FindStringSubmatch(line); matches != nil {
			groups[matches[1]] = true
			continue
		}

		// Check for user rules
		if matches := sudoersUserRe.FindStringSubmatch(line); matches != nil {
			// Exclude special keywords
			name := matches[1]
			if name != "root" && name != "Defaults" && name != "ALL" {
				users[name] = true
			} else if name == "root" {
				users["root"] = true
			}
		}
	}
}

// getLastLogins returns a map of username to last login time using the lastlog command.
func getLastLogins() map[string]time.Time {
	logins := make(map[string]time.Time)

	// Try to run lastlog command
	cmd := exec.Command("lastlog")
	output, err := cmd.Output()
	if err != nil {
		return logins
	}

	logins = parseLastlogOutput(string(output))
	return logins
}

// parseLastlogOutput parses the output of the lastlog command.
func parseLastlogOutput(output string) map[string]time.Time {
	logins := make(map[string]time.Time)
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		username := fields[0]
		// Check for "Never logged in"
		if strings.Contains(line, "Never logged in") || strings.Contains(line, "**Never logged in**") {
			continue
		}

		// Try to parse the date from the remaining fields
		// Format varies: "Mon Dec 29 10:30:00 -0500 2025"
		if len(fields) >= 9 {
			// fields[3:] should contain the date
			dateStr := strings.Join(fields[3:], " ")
			loginTime := parseLoginDate(dateStr)
			if !loginTime.IsZero() {
				logins[username] = loginTime
			}
		}
	}

	return logins
}

// parseLoginDate attempts to parse various date formats from lastlog output.
func parseLoginDate(dateStr string) time.Time {
	// Common formats from lastlog
	formats := []string{
		"Mon Jan 2 15:04:05 -0700 2006",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan  2 15:04:05 -0700 2006",
		"Mon Jan  2 15:04:05 2006",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}

	return time.Time{}
}

// hasAuthorizedKeys checks if a user has an authorized_keys file.
func hasAuthorizedKeys(homeDir string) bool {
	if homeDir == "" || homeDir == "/nonexistent" || homeDir == "/dev/null" {
		return false
	}

	authKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	info, err := os.Stat(authKeysPath)
	if err != nil {
		return false
	}

	// Check if the file is not empty
	return info.Size() > 0
}

// isServiceAccount determines if an account is a service account.
func isServiceAccount(entry PasswdEntry) bool {
	// UID less than MinimumHumanUID (typically 1000) indicates system/service account
	if entry.UID < MinimumHumanUID && entry.UID != 0 {
		return true
	}

	// Check for nologin or false shell
	shell := strings.ToLower(entry.Shell)
	noLoginShells := []string{
		"/usr/sbin/nologin",
		"/sbin/nologin",
		"/bin/false",
		"/usr/bin/false",
		"/bin/nologin",
	}

	for _, noLogin := range noLoginShells {
		if shell == noLogin {
			return true
		}
	}

	return false
}

// determineAccountStatus determines the account status based on shell and other factors.
func determineAccountStatus(entry PasswdEntry) string {
	shell := strings.ToLower(entry.Shell)

	// Check for disabled shells
	disabledShells := []string{
		"/usr/sbin/nologin",
		"/sbin/nologin",
		"/bin/false",
		"/usr/bin/false",
		"/bin/nologin",
	}

	for _, disabled := range disabledShells {
		if shell == disabled {
			return "disabled"
		}
	}

	return "active"
}

// payloadToMap converts an AccessReviewPayload to a map[string]any.
func payloadToMap(p event.AccessReviewPayload) map[string]any {
	// Convert users to []any for the map
	usersAny := make([]any, len(p.Users))
	for i, u := range p.Users {
		usersAny[i] = map[string]any{
			"username":        u.Username,
			"uid":             u.UID,
			"gid":             u.GID,
			"groups":          u.Groups,
			"shell":           u.Shell,
			"home_dir":        u.HomeDir,
			"last_login":      u.LastLogin,
			"password_age_days": u.PasswordAge,
			"has_ssh_key":     u.HasSSHKey,
			"has_sudo_access": u.HasSudoAccess,
			"account_status":  u.AccountStatus,
		}
	}

	return map[string]any{
		"total_users":      p.TotalUsers,
		"active_users":     p.ActiveUsers,
		"disabled_users":   p.DisabledUsers,
		"service_accounts": p.ServiceAccounts,
		"sudo_users":       p.SudoUsers,
		"ssh_key_users":    p.SSHKeyUsers,
		"stale_accounts":   p.StaleAccounts,
		"users":            usersAny,
	}
}
