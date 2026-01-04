package watcher

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DefaultControlCheckInterval is the default interval between compliance control checks.
const DefaultControlCheckInterval = 1 * time.Hour

// ControlCheckConfig holds configuration for the ControlCheck watcher.
type ControlCheckConfig struct {
	// CheckInterval is how often to run compliance checks.
	// Defaults to DefaultControlCheckInterval if zero.
	CheckInterval time.Duration

	// EnabledControls specifies which control IDs to check.
	// If empty, all controls are checked.
	EnabledControls []string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// ControlCheckWatcher monitors system compliance with SOC 2 controls.
type ControlCheckWatcher struct {
	checkInterval   time.Duration
	enabledControls map[string]bool
	fortressID      string
	serverID        string
	logger          *slog.Logger
}

// CheckResult represents the result of a single compliance check.
type CheckResult struct {
	Status          string // pass, fail, warning, skip
	Evidence        string
	ExpectedValue   string
	ActualValue     string
	RemediationHint string
}

// ControlCheck defines a single compliance control check.
type ControlCheck struct {
	ID    string
	Name  string
	Check func() CheckResult
}

// checks is the list of all compliance controls to check.
var checks = []ControlCheck{
	// CC6.1 - Access Control Infrastructure
	{ID: "CC6.1.1", Name: "SSH Password Auth Disabled", Check: checkSSHPasswordAuthDisabled},
	{ID: "CC6.1.2", Name: "Root Login Disabled", Check: checkRootLoginDisabled},
	{ID: "CC6.1.3", Name: "No Empty Passwords", Check: checkNoEmptyPasswords},

	// CC6.6 - Threat Protection
	{ID: "CC6.6.1", Name: "Firewall Enabled", Check: checkFirewallEnabled},
	{ID: "CC6.6.2", Name: "SELinux/AppArmor Enabled", Check: checkMACEnabled},

	// CC6.7 - Encryption
	{ID: "CC6.7.1", Name: "TLS 1.2+ Only", Check: checkTLSVersion},

	// CC7.1 - Logging
	{ID: "CC7.1.1", Name: "Audit Logging Enabled", Check: checkAuditdEnabled},
	{ID: "CC7.1.2", Name: "Syslog Running", Check: checkSyslogRunning},

	// CC8.1 - Change Management
	{ID: "CC8.1.1", Name: "Package Integrity", Check: checkPackageIntegrity},
}

// NewControlCheckWatcher creates a new ControlCheckWatcher with the given configuration.
func NewControlCheckWatcher(cfg ControlCheckConfig) *ControlCheckWatcher {
	interval := cfg.CheckInterval
	if interval == 0 {
		interval = DefaultControlCheckInterval
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Build enabled controls map
	enabledControls := make(map[string]bool)
	if len(cfg.EnabledControls) > 0 {
		for _, id := range cfg.EnabledControls {
			enabledControls[id] = true
		}
	}

	return &ControlCheckWatcher{
		checkInterval:   interval,
		enabledControls: enabledControls,
		fortressID:      cfg.FortressID,
		serverID:        cfg.ServerID,
		logger:          logger,
	}
}

// Watch starts watching and returns a channel of events.
func (w *ControlCheckWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting control check watcher", "interval", w.checkInterval)

		// Run immediate check
		w.runChecks(ctx, out)

		ticker := time.NewTicker(w.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("control check watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.runChecks(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *ControlCheckWatcher) Name() string {
	return "controlcheck"
}

// runChecks executes all enabled compliance checks and emits events.
func (w *ControlCheckWatcher) runChecks(ctx context.Context, out chan<- event.Event) {
	var passing, failing, warning int
	categoryScores := make(map[string][]bool)

	for _, check := range checks {
		// Skip if not enabled (when specific controls are configured)
		if len(w.enabledControls) > 0 && !w.enabledControls[check.ID] {
			continue
		}

		result := check.Check()

		// Extract category from control ID (e.g., "CC6.1" from "CC6.1.1")
		category := extractCategory(check.ID)

		// Track results for scoring
		switch result.Status {
		case "pass":
			passing++
			categoryScores[category] = append(categoryScores[category], true)
		case "fail":
			failing++
			categoryScores[category] = append(categoryScores[category], false)
		case "warning":
			warning++
			categoryScores[category] = append(categoryScores[category], true) // warnings count as partial pass
		}

		// Emit individual control check event
		e := event.NewEvent(event.ControlCheck, w.fortressID, w.serverID, map[string]any{
			"control_id":       check.ID,
			"check_name":       check.Name,
			"status":           result.Status,
			"evidence":         result.Evidence,
			"expected_value":   result.ExpectedValue,
			"actual_value":     result.ActualValue,
			"remediation_hint": result.RemediationHint,
		})

		select {
		case <-ctx.Done():
			return
		case out <- e:
		}

		w.logger.Debug("control check completed",
			"control_id", check.ID,
			"name", check.Name,
			"status", result.Status,
		)
	}

	// Calculate and emit overall compliance score
	totalChecks := passing + failing + warning
	if totalChecks > 0 {
		overallScore := float64(passing*100+warning*50) / float64(totalChecks)

		byCategory := make(map[string]float64)
		for cat, results := range categoryScores {
			passCount := 0
			for _, passed := range results {
				if passed {
					passCount++
				}
			}
			byCategory[cat] = float64(passCount) / float64(len(results)) * 100
		}

		scoreEvent := event.NewEvent(event.ComplianceScore, w.fortressID, w.serverID, map[string]any{
			"overall_score":    overallScore,
			"by_category":      byCategory,
			"passing_controls": passing,
			"failing_controls": failing,
			"warning_controls": warning,
		})

		select {
		case <-ctx.Done():
			return
		case out <- scoreEvent:
		}

		w.logger.Info("compliance check completed",
			"overall_score", overallScore,
			"passing", passing,
			"failing", failing,
			"warning", warning,
		)
	}
}

// extractCategory extracts the category from a control ID (e.g., "CC6.1" from "CC6.1.1").
func extractCategory(controlID string) string {
	parts := strings.Split(controlID, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return controlID
}

// isControlEnabled checks if a control should be run.
func (w *ControlCheckWatcher) isControlEnabled(controlID string) bool {
	if len(w.enabledControls) == 0 {
		return true
	}
	return w.enabledControls[controlID]
}

// CalculateScore calculates the compliance score from check results.
// Exported for testing.
func CalculateScore(passing, failing, warning int) float64 {
	total := passing + failing + warning
	if total == 0 {
		return 100
	}
	return float64(passing*100+warning*50) / float64(total)
}

// --- Individual Check Functions ---

// checkSSHPasswordAuthDisabled verifies that SSH password authentication is disabled.
func checkSSHPasswordAuthDisabled() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	content, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return CheckResult{
			Status:          "fail",
			Evidence:        fmt.Sprintf("Could not read sshd_config: %v", err),
			ExpectedValue:   "PasswordAuthentication no",
			ActualValue:     "unknown",
			RemediationHint: "Ensure /etc/ssh/sshd_config is readable",
		}
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "passwordauthentication") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.ToLower(fields[1]) == "no" {
				return CheckResult{
					Status:        "pass",
					Evidence:      "Found: " + line,
					ExpectedValue: "PasswordAuthentication no",
					ActualValue:   "PasswordAuthentication no",
				}
			}
			return CheckResult{
				Status:          "fail",
				Evidence:        "Found: " + line,
				ExpectedValue:   "PasswordAuthentication no",
				ActualValue:     line,
				RemediationHint: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd",
			}
		}
	}

	// Default is often 'yes' if not specified
	return CheckResult{
		Status:          "warning",
		Evidence:        "PasswordAuthentication not explicitly set in sshd_config",
		ExpectedValue:   "PasswordAuthentication no",
		ActualValue:     "not set (defaults to yes)",
		RemediationHint: "Explicitly set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
	}
}

// checkRootLoginDisabled verifies that root SSH login is disabled.
func checkRootLoginDisabled() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	content, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return CheckResult{
			Status:          "fail",
			Evidence:        fmt.Sprintf("Could not read sshd_config: %v", err),
			ExpectedValue:   "PermitRootLogin no",
			ActualValue:     "unknown",
			RemediationHint: "Ensure /etc/ssh/sshd_config is readable",
		}
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "permitrootlogin") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value := strings.ToLower(fields[1])
				if value == "no" {
					return CheckResult{
						Status:        "pass",
						Evidence:      "Found: " + line,
						ExpectedValue: "PermitRootLogin no",
						ActualValue:   "PermitRootLogin no",
					}
				}
				if value == "prohibit-password" || value == "without-password" {
					return CheckResult{
						Status:        "pass",
						Evidence:      "Found: " + line + " (key-only root login permitted)",
						ExpectedValue: "PermitRootLogin no or prohibit-password",
						ActualValue:   line,
					}
				}
			}
			return CheckResult{
				Status:          "fail",
				Evidence:        "Found: " + line,
				ExpectedValue:   "PermitRootLogin no",
				ActualValue:     line,
				RemediationHint: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd",
			}
		}
	}

	return CheckResult{
		Status:          "warning",
		Evidence:        "PermitRootLogin not explicitly set in sshd_config",
		ExpectedValue:   "PermitRootLogin no",
		ActualValue:     "not set (defaults may vary)",
		RemediationHint: "Explicitly set 'PermitRootLogin no' in /etc/ssh/sshd_config",
	}
}

// checkNoEmptyPasswords verifies that no user accounts have empty passwords.
func checkNoEmptyPasswords() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	file, err := os.Open("/etc/shadow")
	if err != nil {
		return CheckResult{
			Status:          "fail",
			Evidence:        fmt.Sprintf("Could not read /etc/shadow: %v", err),
			ExpectedValue:   "No empty password fields",
			ActualValue:     "unknown",
			RemediationHint: "Run this check as root or with appropriate permissions",
		}
	}
	defer file.Close()

	var emptyPassUsers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) >= 2 {
			username := fields[0]
			passwordHash := fields[1]
			// Empty string or just ":" means empty password
			if passwordHash == "" || passwordHash == ":" {
				emptyPassUsers = append(emptyPassUsers, username)
			}
		}
	}

	if len(emptyPassUsers) > 0 {
		return CheckResult{
			Status:          "fail",
			Evidence:        fmt.Sprintf("Users with empty passwords: %v", emptyPassUsers),
			ExpectedValue:   "No empty password fields",
			ActualValue:     fmt.Sprintf("%d users with empty passwords", len(emptyPassUsers)),
			RemediationHint: "Set passwords for affected users or lock accounts: passwd -l <username>",
		}
	}

	return CheckResult{
		Status:        "pass",
		Evidence:      "No users with empty passwords found in /etc/shadow",
		ExpectedValue: "No empty password fields",
		ActualValue:   "No empty password fields",
	}
}

// checkFirewallEnabled verifies that a firewall is enabled.
func checkFirewallEnabled() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	// Check iptables
	cmd := exec.Command("iptables", "-L", "-n")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		ruleCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "target") {
				ruleCount++
			}
		}
		if ruleCount > 0 {
			return CheckResult{
				Status:        "pass",
				Evidence:      fmt.Sprintf("iptables has %d rules configured", ruleCount),
				ExpectedValue: "Firewall rules configured",
				ActualValue:   fmt.Sprintf("%d iptables rules", ruleCount),
			}
		}
	}

	// Check ufw
	cmd = exec.Command("ufw", "status")
	output, err = cmd.Output()
	if err == nil && strings.Contains(string(output), "active") {
		return CheckResult{
			Status:        "pass",
			Evidence:      "UFW firewall is active",
			ExpectedValue: "Firewall enabled",
			ActualValue:   "UFW active",
		}
	}

	// Check firewalld
	cmd = exec.Command("systemctl", "is-active", "firewalld")
	output, err = cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return CheckResult{
			Status:        "pass",
			Evidence:      "firewalld is active",
			ExpectedValue: "Firewall enabled",
			ActualValue:   "firewalld active",
		}
	}

	// Check nftables
	cmd = exec.Command("nft", "list", "ruleset")
	output, err = cmd.Output()
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		return CheckResult{
			Status:        "pass",
			Evidence:      "nftables has rules configured",
			ExpectedValue: "Firewall enabled",
			ActualValue:   "nftables configured",
		}
	}

	return CheckResult{
		Status:          "fail",
		Evidence:        "No active firewall detected (checked iptables, ufw, firewalld, nftables)",
		ExpectedValue:   "Firewall enabled",
		ActualValue:     "No firewall detected",
		RemediationHint: "Enable a firewall: 'ufw enable' or 'systemctl enable --now firewalld'",
	}
}

// checkMACEnabled verifies that SELinux or AppArmor is enabled.
func checkMACEnabled() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	// Check SELinux
	if content, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(content)) == "1" {
			return CheckResult{
				Status:        "pass",
				Evidence:      "SELinux is enforcing",
				ExpectedValue: "MAC system enabled (SELinux or AppArmor)",
				ActualValue:   "SELinux enforcing",
			}
		}
		return CheckResult{
			Status:          "warning",
			Evidence:        "SELinux is installed but not enforcing",
			ExpectedValue:   "SELinux enforcing",
			ActualValue:     "SELinux permissive or disabled",
			RemediationHint: "Set SELinux to enforcing: setenforce 1",
		}
	}

	// Check AppArmor
	cmd := exec.Command("aa-status", "--enabled")
	if err := cmd.Run(); err == nil {
		return CheckResult{
			Status:        "pass",
			Evidence:      "AppArmor is enabled",
			ExpectedValue: "MAC system enabled (SELinux or AppArmor)",
			ActualValue:   "AppArmor enabled",
		}
	}

	// Check if AppArmor module is loaded
	if content, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(content)) == "Y" {
			return CheckResult{
				Status:        "pass",
				Evidence:      "AppArmor kernel module is enabled",
				ExpectedValue: "MAC system enabled (SELinux or AppArmor)",
				ActualValue:   "AppArmor enabled",
			}
		}
	}

	return CheckResult{
		Status:          "fail",
		Evidence:        "No MAC system (SELinux or AppArmor) detected as enabled",
		ExpectedValue:   "MAC system enabled",
		ActualValue:     "No MAC system enabled",
		RemediationHint: "Enable SELinux or AppArmor for mandatory access control",
	}
}

// checkTLSVersion verifies that only TLS 1.2+ is allowed.
func checkTLSVersion() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	// Check OpenSSL crypto policy on RHEL/CentOS
	if content, err := os.ReadFile("/etc/crypto-policies/state/current"); err == nil {
		policy := strings.TrimSpace(string(content))
		if policy == "FUTURE" || policy == "FIPS" || policy == "DEFAULT" {
			return CheckResult{
				Status:        "pass",
				Evidence:      fmt.Sprintf("System crypto policy set to: %s", policy),
				ExpectedValue: "TLS 1.2+ only",
				ActualValue:   fmt.Sprintf("Crypto policy: %s", policy),
			}
		}
		if policy == "LEGACY" {
			return CheckResult{
				Status:          "fail",
				Evidence:        "System crypto policy set to LEGACY (allows older TLS)",
				ExpectedValue:   "TLS 1.2+ only",
				ActualValue:     "Crypto policy: LEGACY",
				RemediationHint: "Run: update-crypto-policies --set DEFAULT",
			}
		}
	}

	// Check SSL min protocol in OpenSSL config
	if content, err := os.ReadFile("/etc/ssl/openssl.cnf"); err == nil {
		if strings.Contains(string(content), "MinProtocol = TLSv1.2") ||
			strings.Contains(string(content), "MinProtocol = TLSv1.3") {
			return CheckResult{
				Status:        "pass",
				Evidence:      "OpenSSL configured with MinProtocol >= TLSv1.2",
				ExpectedValue: "TLS 1.2+ only",
				ActualValue:   "MinProtocol >= TLSv1.2",
			}
		}
	}

	// Check common service configs for TLS settings
	// This is a simplified check - real implementation would check more services
	return CheckResult{
		Status:          "warning",
		Evidence:        "Could not definitively verify TLS version settings",
		ExpectedValue:   "TLS 1.2+ only",
		ActualValue:     "Unknown",
		RemediationHint: "Review crypto policies and service TLS configurations",
	}
}

// checkAuditdEnabled verifies that auditd is running.
func checkAuditdEnabled() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	// Check if auditd service is active
	cmd := exec.Command("systemctl", "is-active", "auditd")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		// Also check if rules are configured
		cmd = exec.Command("auditctl", "-l")
		rulesOutput, _ := cmd.Output()
		ruleCount := len(strings.Split(strings.TrimSpace(string(rulesOutput)), "\n"))

		return CheckResult{
			Status:        "pass",
			Evidence:      fmt.Sprintf("auditd is active with %d rules", ruleCount),
			ExpectedValue: "auditd running",
			ActualValue:   fmt.Sprintf("auditd active, %d rules", ruleCount),
		}
	}

	// Check if audit kernel subsystem is available
	if _, err := os.Stat("/proc/sys/kernel/audit_enabled"); err == nil {
		return CheckResult{
			Status:          "fail",
			Evidence:        "Audit subsystem available but auditd not running",
			ExpectedValue:   "auditd running",
			ActualValue:     "auditd not active",
			RemediationHint: "Enable auditd: systemctl enable --now auditd",
		}
	}

	return CheckResult{
		Status:          "fail",
		Evidence:        "auditd is not running",
		ExpectedValue:   "auditd running",
		ActualValue:     "auditd not active",
		RemediationHint: "Install and enable auditd: apt install auditd && systemctl enable --now auditd",
	}
}

// checkSyslogRunning verifies that syslog/rsyslog/journald is running.
func checkSyslogRunning() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	// Check systemd-journald (most common on modern systems)
	cmd := exec.Command("systemctl", "is-active", "systemd-journald")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return CheckResult{
			Status:        "pass",
			Evidence:      "systemd-journald is active",
			ExpectedValue: "System logging enabled",
			ActualValue:   "journald active",
		}
	}

	// Check rsyslog
	cmd = exec.Command("systemctl", "is-active", "rsyslog")
	output, err = cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return CheckResult{
			Status:        "pass",
			Evidence:      "rsyslog is active",
			ExpectedValue: "System logging enabled",
			ActualValue:   "rsyslog active",
		}
	}

	// Check syslog-ng
	cmd = exec.Command("systemctl", "is-active", "syslog-ng")
	output, err = cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return CheckResult{
			Status:        "pass",
			Evidence:      "syslog-ng is active",
			ExpectedValue: "System logging enabled",
			ActualValue:   "syslog-ng active",
		}
	}

	return CheckResult{
		Status:          "fail",
		Evidence:        "No syslog service detected (checked journald, rsyslog, syslog-ng)",
		ExpectedValue:   "System logging enabled",
		ActualValue:     "No logging service active",
		RemediationHint: "Enable system logging: systemctl enable --now rsyslog",
	}
}

// checkPackageIntegrity verifies package integrity using package manager.
func checkPackageIntegrity() CheckResult {
	if runtime.GOOS != "linux" {
		return CheckResult{
			Status:   "skip",
			Evidence: "Check only supported on Linux",
		}
	}

	// Try rpm -Va for RHEL/CentOS/Fedora
	cmd := exec.Command("rpm", "-Va", "--noconfig")
	output, err := cmd.Output()
	if err == nil || cmd.ProcessState.ExitCode() == 0 {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		// Filter out empty lines
		modifiedCount := 0
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				modifiedCount++
			}
		}
		if modifiedCount == 0 {
			return CheckResult{
				Status:        "pass",
				Evidence:      "rpm -Va found no modified packages",
				ExpectedValue: "Package integrity verified",
				ActualValue:   "No modifications detected",
			}
		}
		return CheckResult{
			Status:          "warning",
			Evidence:        fmt.Sprintf("rpm -Va found %d modified files", modifiedCount),
			ExpectedValue:   "Package integrity verified",
			ActualValue:     fmt.Sprintf("%d files modified from package defaults", modifiedCount),
			RemediationHint: "Review modified files with 'rpm -Va' and restore if unauthorized",
		}
	}

	// Try debsums for Debian/Ubuntu
	cmd = exec.Command("debsums", "-s")
	output, err = cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		if outputStr == "" {
			return CheckResult{
				Status:        "pass",
				Evidence:      "debsums found no modified packages",
				ExpectedValue: "Package integrity verified",
				ActualValue:   "No modifications detected",
			}
		}
		lines := strings.Split(outputStr, "\n")
		return CheckResult{
			Status:          "warning",
			Evidence:        fmt.Sprintf("debsums found %d modified files", len(lines)),
			ExpectedValue:   "Package integrity verified",
			ActualValue:     fmt.Sprintf("%d files modified", len(lines)),
			RemediationHint: "Review modified files with 'debsums -s' and reinstall packages if needed",
		}
	}

	// Check if apk (Alpine) is available
	cmd = exec.Command("apk", "audit")
	output, err = cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		if outputStr == "" {
			return CheckResult{
				Status:        "pass",
				Evidence:      "apk audit found no issues",
				ExpectedValue: "Package integrity verified",
				ActualValue:   "No modifications detected",
			}
		}
	}

	return CheckResult{
		Status:          "skip",
		Evidence:        "No supported package integrity tool found (rpm, debsums, apk)",
		ExpectedValue:   "Package integrity verified",
		ActualValue:     "unknown",
		RemediationHint: "Install debsums (Debian/Ubuntu) or use rpm -Va (RHEL/CentOS)",
	}
}
