package watcher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// FirewallType represents the type of firewall in use.
type FirewallType string

const (
	FirewallTypeIPTables FirewallType = "iptables"
	FirewallTypeNFTables FirewallType = "nftables"
	FirewallTypeUFW      FirewallType = "ufw"
	FirewallTypeUnknown  FirewallType = "unknown"
)

// FirewallConfig holds configuration for the Firewall watcher.
type FirewallConfig struct {
	// PollInterval is how often to check for firewall rule changes.
	// Defaults to 5 minutes if zero.
	PollInterval time.Duration

	// SnapshotInterval is how often to emit full state snapshots.
	// Defaults to 6 hours if zero.
	SnapshotInterval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// FirewallState represents the current state of the firewall.
type FirewallState struct {
	FirewallType    FirewallType
	Enabled         bool
	DefaultInbound  string
	DefaultOutbound string
	Rules           string
	RulesHash       string
	RuleCount       int
}

// FirewallWatcher monitors firewall rules and open ports for SOC 2 CC6.6 compliance.
type FirewallWatcher struct {
	pollInterval     time.Duration
	snapshotInterval time.Duration
	fortressID       string
	serverID         string
	logger           *slog.Logger

	previousState *FirewallState
	mu            sync.Mutex
}

// NewFirewallWatcher creates a new FirewallWatcher with the given configuration.
func NewFirewallWatcher(cfg FirewallConfig) *FirewallWatcher {
	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 5 * time.Minute
	}

	snapshotInterval := cfg.SnapshotInterval
	if snapshotInterval == 0 {
		snapshotInterval = 6 * time.Hour
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &FirewallWatcher{
		pollInterval:     pollInterval,
		snapshotInterval: snapshotInterval,
		fortressID:       cfg.FortressID,
		serverID:         cfg.ServerID,
		logger:           logger,
	}
}

// Watch starts watching firewall rules and returns a channel of events.
func (w *FirewallWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting firewall watcher",
			"poll_interval", w.pollInterval,
			"snapshot_interval", w.snapshotInterval,
		)

		// Initial scan and snapshot
		state := w.captureFirewallState()
		w.mu.Lock()
		w.previousState = state
		w.mu.Unlock()

		// Emit initial snapshot
		w.emitSnapshot(ctx, out, state)

		pollTicker := time.NewTicker(w.pollInterval)
		defer pollTicker.Stop()

		snapshotTicker := time.NewTicker(w.snapshotInterval)
		defer snapshotTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("firewall watcher stopped", "reason", ctx.Err())
				return

			case <-pollTicker.C:
				w.checkForChanges(ctx, out)

			case <-snapshotTicker.C:
				state := w.captureFirewallState()
				w.emitSnapshot(ctx, out, state)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *FirewallWatcher) Name() string {
	return "firewall"
}

// checkForChanges compares current state with previous and emits change events.
func (w *FirewallWatcher) checkForChanges(ctx context.Context, out chan<- event.Event) {
	currentState := w.captureFirewallState()

	w.mu.Lock()
	previousState := w.previousState
	w.previousState = currentState
	w.mu.Unlock()

	if previousState == nil {
		return
	}

	// Compare hashes to detect changes
	if previousState.RulesHash != currentState.RulesHash {
		w.logger.Info("firewall rules changed",
			"previous_hash", previousState.RulesHash,
			"current_hash", currentState.RulesHash,
			"previous_count", previousState.RuleCount,
			"current_count", currentState.RuleCount,
		)

		// Determine if rules were added or removed based on count
		if currentState.RuleCount > previousState.RuleCount {
			w.emitRuleChange(ctx, out, event.FirewallRuleAdded, currentState,
				currentState.RuleCount-previousState.RuleCount)
		} else if currentState.RuleCount < previousState.RuleCount {
			w.emitRuleChange(ctx, out, event.FirewallRuleRemoved, currentState,
				previousState.RuleCount-currentState.RuleCount)
		} else {
			// Rules changed but count is same - emit as added (modification)
			w.emitRuleChange(ctx, out, event.FirewallRuleAdded, currentState, 0)
		}
	}
}

// emitSnapshot emits a full firewall state snapshot event.
func (w *FirewallWatcher) emitSnapshot(ctx context.Context, out chan<- event.Event, state *FirewallState) {
	openPorts := w.getOpenPorts()

	payload := map[string]any{
		"firewall_type":    string(state.FirewallType),
		"enabled":          state.Enabled,
		"default_inbound":  state.DefaultInbound,
		"default_outbound": state.DefaultOutbound,
		"rule_count":       state.RuleCount,
		"rules_hash":       state.RulesHash,
		"open_ports":       openPorts,
	}

	e := event.NewEvent(event.FirewallStateSnapshot, w.fortressID, w.serverID, payload)

	select {
	case <-ctx.Done():
	case out <- e:
	}
}

// emitRuleChange emits a firewall rule change event.
func (w *FirewallWatcher) emitRuleChange(ctx context.Context, out chan<- event.Event, eventType event.EventType, state *FirewallState, changeCount int) {
	payload := map[string]any{
		"firewall_type":    string(state.FirewallType),
		"enabled":          state.Enabled,
		"default_inbound":  state.DefaultInbound,
		"default_outbound": state.DefaultOutbound,
		"rule_count":       state.RuleCount,
		"rules_hash":       state.RulesHash,
		"change_count":     changeCount,
	}

	e := event.NewEvent(eventType, w.fortressID, w.serverID, payload)

	select {
	case <-ctx.Done():
	case out <- e:
	}
}

// captureFirewallState captures the current firewall state.
func (w *FirewallWatcher) captureFirewallState() *FirewallState {
	firewallType := detectFirewallType()

	var rules string
	var enabled bool
	var defaultInbound, defaultOutbound string
	var ruleCount int

	switch firewallType {
	case FirewallTypeUFW:
		rules, enabled, defaultInbound, defaultOutbound, ruleCount = captureUFWState()
	case FirewallTypeNFTables:
		rules, enabled, defaultInbound, defaultOutbound, ruleCount = captureNFTablesState()
	case FirewallTypeIPTables:
		rules, enabled, defaultInbound, defaultOutbound, ruleCount = captureIPTablesState()
	default:
		rules = ""
		enabled = false
		defaultInbound = "unknown"
		defaultOutbound = "unknown"
		ruleCount = 0
	}

	return &FirewallState{
		FirewallType:    firewallType,
		Enabled:         enabled,
		DefaultInbound:  defaultInbound,
		DefaultOutbound: defaultOutbound,
		Rules:           rules,
		RulesHash:       hashRules(rules),
		RuleCount:       ruleCount,
	}
}

// detectFirewallType determines which firewall is in use on the system.
func detectFirewallType() FirewallType {
	// Check for UFW first (it's a frontend for iptables)
	if output, err := exec.Command("ufw", "status").Output(); err == nil {
		if strings.Contains(string(output), "Status:") {
			return FirewallTypeUFW
		}
	}

	// Check for nftables
	if _, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		return FirewallTypeNFTables
	}

	// Check for iptables
	if _, err := exec.Command("iptables-save").Output(); err == nil {
		return FirewallTypeIPTables
	}

	return FirewallTypeUnknown
}

// captureIPTablesState captures the current iptables state.
func captureIPTablesState() (rules string, enabled bool, defaultInbound, defaultOutbound string, ruleCount int) {
	output, err := exec.Command("iptables-save").Output()
	if err != nil {
		return "", false, "unknown", "unknown", 0
	}

	rules = string(output)
	enabled = len(rules) > 0
	defaultInbound, defaultOutbound, ruleCount = parseIPTablesRules(rules)

	return rules, enabled, defaultInbound, defaultOutbound, ruleCount
}

// parseIPTablesRules parses iptables-save output to extract defaults and rule count.
func parseIPTablesRules(rules string) (defaultInbound, defaultOutbound string, ruleCount int) {
	defaultInbound = "accept"
	defaultOutbound = "accept"

	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse default policies
		if strings.HasPrefix(line, ":INPUT") {
			defaultInbound = parseIPTablesPolicy(line)
		} else if strings.HasPrefix(line, ":OUTPUT") {
			defaultOutbound = parseIPTablesPolicy(line)
		}

		// Count actual rules (lines starting with -A)
		if strings.HasPrefix(line, "-A") {
			ruleCount++
		}
	}

	return defaultInbound, defaultOutbound, ruleCount
}

// parseIPTablesPolicy extracts the policy from an iptables chain definition.
func parseIPTablesPolicy(line string) string {
	// Format: ":INPUT ACCEPT [0:0]" or ":INPUT DROP [0:0]"
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		policy := strings.ToLower(fields[1])
		if policy == "accept" || policy == "drop" || policy == "reject" {
			return policy
		}
	}
	return "accept"
}

// captureNFTablesState captures the current nftables state.
func captureNFTablesState() (rules string, enabled bool, defaultInbound, defaultOutbound string, ruleCount int) {
	output, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return "", false, "unknown", "unknown", 0
	}

	rules = string(output)
	enabled = len(rules) > 0
	defaultInbound, defaultOutbound, ruleCount = parseNFTablesRules(rules)

	return rules, enabled, defaultInbound, defaultOutbound, ruleCount
}

// parseNFTablesRules parses nft list ruleset output.
func parseNFTablesRules(rules string) (defaultInbound, defaultOutbound string, ruleCount int) {
	defaultInbound = "accept"
	defaultOutbound = "accept"

	// nftables policy regex patterns
	inputPolicyRe := regexp.MustCompile(`chain\s+input\s*\{[^}]*policy\s+(accept|drop|reject)`)
	outputPolicyRe := regexp.MustCompile(`chain\s+output\s*\{[^}]*policy\s+(accept|drop|reject)`)

	rulesLower := strings.ToLower(rules)

	if matches := inputPolicyRe.FindStringSubmatch(rulesLower); len(matches) > 1 {
		defaultInbound = matches[1]
	}
	if matches := outputPolicyRe.FindStringSubmatch(rulesLower); len(matches) > 1 {
		defaultOutbound = matches[1]
	}

	// Count rules (lines containing common rule keywords)
	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Count lines that look like rules (contain actions like accept, drop, reject, counter)
		if strings.Contains(line, "accept") ||
			strings.Contains(line, "drop") ||
			strings.Contains(line, "reject") ||
			strings.Contains(line, "counter") {
			// Exclude chain policy definitions
			if !strings.HasPrefix(line, "chain") && !strings.Contains(line, "policy") {
				ruleCount++
			}
		}
	}

	return defaultInbound, defaultOutbound, ruleCount
}

// captureUFWState captures the current UFW state.
func captureUFWState() (rules string, enabled bool, defaultInbound, defaultOutbound string, ruleCount int) {
	output, err := exec.Command("ufw", "status", "verbose").Output()
	if err != nil {
		return "", false, "unknown", "unknown", 0
	}

	rules = string(output)
	enabled, defaultInbound, defaultOutbound, ruleCount = parseUFWStatus(rules)

	return rules, enabled, defaultInbound, defaultOutbound, ruleCount
}

// parseUFWStatus parses ufw status verbose output.
func parseUFWStatus(output string) (enabled bool, defaultInbound, defaultOutbound string, ruleCount int) {
	defaultInbound = "deny"
	defaultOutbound = "allow"

	scanner := bufio.NewScanner(strings.NewReader(output))
	inRulesSection := false

	for scanner.Scan() {
		line := scanner.Text()
		lineLower := strings.ToLower(line)

		// Check if enabled
		if strings.Contains(lineLower, "status: active") {
			enabled = true
		} else if strings.Contains(lineLower, "status: inactive") {
			enabled = false
		}

		// Parse default policies
		// Format: "Default: deny (incoming), allow (outgoing), disabled (routed)"
		if strings.Contains(lineLower, "default:") {
			// Parse incoming policy
			if strings.Contains(lineLower, "incoming") {
				defaultInbound = parseUFWPolicyForDirection(lineLower, "incoming")
			}
			// Parse outgoing policy (both can be on same line)
			if strings.Contains(lineLower, "outgoing") {
				defaultOutbound = parseUFWPolicyForDirection(lineLower, "outgoing")
			}
		}

		// Detect rules section (after the header line with "To", "Action", "From")
		if strings.Contains(line, "---") {
			inRulesSection = true
			continue
		}

		// Count rules in the rules section
		if inRulesSection && strings.TrimSpace(line) != "" {
			ruleCount++
		}
	}

	return enabled, defaultInbound, defaultOutbound, ruleCount
}

// parseUFWPolicyForDirection extracts the policy for a specific direction.
// Input format: "default: deny (incoming), allow (outgoing), disabled (routed)"
func parseUFWPolicyForDirection(line, direction string) string {
	// Find the pattern: "policy (direction)"
	// e.g., "deny (incoming)" or "allow (outgoing)"
	dirIdx := strings.Index(line, direction)
	if dirIdx == -1 {
		return "unknown"
	}

	// Look backwards from direction to find the policy word
	prefix := line[:dirIdx]
	// Find the last policy word before the direction
	policies := []string{"deny", "reject", "allow"}
	lastPolicyIdx := -1
	lastPolicy := "unknown"

	for _, policy := range policies {
		idx := strings.LastIndex(prefix, policy)
		if idx > lastPolicyIdx {
			lastPolicyIdx = idx
			lastPolicy = policy
		}
	}

	return lastPolicy
}

// parseUFWPolicy extracts the first policy from a UFW default line.
func parseUFWPolicy(line string) string {
	lineLower := strings.ToLower(line)

	// Find the first policy word in the line
	policies := []struct {
		name string
		idx  int
	}{
		{"deny", strings.Index(lineLower, "deny")},
		{"reject", strings.Index(lineLower, "reject")},
		{"allow", strings.Index(lineLower, "allow")},
	}

	firstPolicy := "unknown"
	firstIdx := len(lineLower) + 1

	for _, p := range policies {
		if p.idx >= 0 && p.idx < firstIdx {
			firstIdx = p.idx
			firstPolicy = p.name
		}
	}

	return firstPolicy
}

// hashRules computes a SHA256 hash of the firewall rules.
func hashRules(rules string) string {
	if rules == "" {
		return ""
	}
	h := sha256.Sum256([]byte(rules))
	return hex.EncodeToString(h[:])
}

// getOpenPorts returns a list of open ports using ss command.
// This reuses logic similar to network.go for consistency.
func (w *FirewallWatcher) getOpenPorts() []event.PortInfo {
	var ports []event.PortInfo

	// Try ss first, fall back to netstat
	output, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		output, err = exec.Command("netstat", "-tlnp").Output()
		if err != nil {
			w.logger.Debug("failed to get open ports", "error", err)
			return ports
		}
	}

	// Parse TCP ports
	ports = append(ports, parseSSOutput(string(output), "tcp")...)

	// Also get UDP ports
	output, err = exec.Command("ss", "-ulnp").Output()
	if err != nil {
		output, _ = exec.Command("netstat", "-ulnp").Output()
	}

	ports = append(ports, parseSSOutput(string(output), "udp")...)

	return ports
}

// Regex patterns for parsing ss output
var (
	ssListenAddrRe = regexp.MustCompile(`^(0\.0\.0\.0|::|\*):(\d+)$`)
	ssLocalAddrRe  = regexp.MustCompile(`^(127\.0\.0\.1|::1):(\d+)$`)
	ssProcessRe    = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)
)

// parseSSOutput parses ss command output and returns PortInfo structs.
func parseSSOutput(output string, protocol string) []event.PortInfo {
	var ports []event.PortInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if port := parseSSLine(line, protocol); port != nil {
			ports = append(ports, *port)
		}
	}

	return ports
}

// parseSSLine parses a single line from ss output.
func parseSSLine(line string, defaultProtocol string) *event.PortInfo {
	if line == "" {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	// Determine protocol
	protocol := defaultProtocol
	if strings.HasPrefix(fields[0], "tcp") {
		protocol = "tcp"
	} else if strings.HasPrefix(fields[0], "udp") {
		protocol = "udp"
	} else if fields[0] != "LISTEN" && !strings.HasPrefix(fields[0], "UNCONN") {
		// Skip header lines and non-listening entries
		if !strings.Contains(line, "LISTEN") && !strings.Contains(line, "UNCONN") {
			return nil
		}
	}

	// Find the local address field
	localAddr := ""
	for _, field := range fields {
		if strings.Contains(field, ":") && !strings.HasSuffix(field, ":*") {
			if strings.Contains(field, "0.0.0.0") ||
				strings.Contains(field, ":::") ||
				strings.Contains(field, "*:") ||
				strings.Contains(field, "127.0.0.1") ||
				strings.Contains(field, "::1") {
				localAddr = field
				break
			}
		}
	}

	if localAddr == "" {
		return nil
	}

	// Check if it's listening
	isListening := false
	for _, field := range fields {
		if field == "LISTEN" || strings.Contains(line, "LISTEN") {
			isListening = true
			break
		}
	}
	// UDP uses UNCONN state for listening
	if protocol == "udp" && (strings.Contains(line, "UNCONN") || strings.Contains(line, "*:")) {
		isListening = true
	}
	if !isListening {
		return nil
	}

	// Parse port and listen address
	var port int
	parts := strings.Split(localAddr, ":")
	if len(parts) >= 2 {
		portStr := parts[len(parts)-1]
		port, _ = strconv.Atoi(portStr)
	}

	if port == 0 {
		return nil
	}

	// Determine listen address type
	listenAddr := "0.0.0.0"
	if strings.Contains(localAddr, "127.0.0.1") {
		listenAddr = "127.0.0.1"
	} else if strings.Contains(localAddr, "::1") {
		listenAddr = "::1"
	} else if strings.Contains(localAddr, ":::") {
		listenAddr = "::"
	}

	// Parse process info
	processName := ""
	var pid int
	for _, field := range fields {
		if matches := ssProcessRe.FindStringSubmatch(field); matches != nil {
			processName = matches[1]
			pid, _ = strconv.Atoi(matches[2])
			break
		}
	}

	return &event.PortInfo{
		Port:        port,
		Protocol:    protocol,
		ListenAddr:  listenAddr,
		ProcessName: processName,
		PID:         pid,
	}
}
