// Package event defines the core event types for the Rampart agent.
// Events are the primary way the agent communicates with the control plane.
package event

import (
	"crypto/rand"
	"os"
	"time"

	"github.com/oklog/ulid/v2"
)

// EventType represents the type of event being recorded.
type EventType string

// Event types for deployment tracking
const (
	DeploymentStarted   EventType = "deployment.started"
	DeploymentCompleted EventType = "deployment.completed"
	DeploymentFailed    EventType = "deployment.failed"
)

// Event types for access tracking
const (
	AccessSSH     EventType = "access.ssh"
	AccessConsole EventType = "access.console"
	AccessAPI     EventType = "access.api"
)

// Event types for drift detection
const (
	DriftFileChanged    EventType = "drift.file_changed"
	DriftConfigModified EventType = "drift.config_modified"
)

// Event types for network exposure (Doors)
const (
	ExposureDoorOpened EventType = "exposure.door_opened"
	ExposureDoorClosed EventType = "exposure.door_closed"
)

// Event types for outbound connections (Embassies/Cables)
const (
	ConnectionEstablished EventType = "connection.established"
	ConnectionClosed      EventType = "connection.closed"
	ConnectionSnapshot    EventType = "connection.snapshot"
)

// Event types for health monitoring
const (
	HealthHeartbeat EventType = "health.heartbeat"
	HealthDegraded  EventType = "health.degraded"
	HealthRecovered EventType = "health.recovered"
)

// Event types for container lifecycle
const (
	ContainerStarted EventType = "container.started"
	ContainerStopped EventType = "container.stopped"
	ContainerExec    EventType = "container.exec"
)

// Event types for secrets monitoring
const (
	SecretCreated           EventType = "secrets.created"
	SecretRotated           EventType = "secrets.rotated"
	SecretDeleted           EventType = "secrets.deleted"
	SecretPermissionChanged EventType = "secrets.permission_changed"
	SecretAccessed          EventType = "secrets.accessed"
)

// Event types for user account monitoring (CC6.2)
const (
	UserAccountCreated  EventType = "user.created"
	UserAccountModified EventType = "user.modified"
	UserAccountDeleted  EventType = "user.deleted"
	UserAccountDisabled EventType = "user.disabled"
	UserAccountEnabled  EventType = "user.enabled"
	AccessReviewSnapshot EventType = "access.review_snapshot"
)

// Event types for package monitoring (CC8.1)
const (
	PackageInstalled EventType = "package.installed"
	PackageUpgraded  EventType = "package.upgraded"
	PackageRemoved   EventType = "package.removed"
)

// Event types for service monitoring (CC8.1)
const (
	ServiceStarted  EventType = "service.started"
	ServiceStopped  EventType = "service.stopped"
	ServiceEnabled  EventType = "service.enabled"
	ServiceDisabled EventType = "service.disabled"
	ServiceCreated  EventType = "service.created"
	ServiceDeleted  EventType = "service.deleted"
)

// Event types for firewall monitoring (CC6.6)
const (
	FirewallStateSnapshot EventType = "firewall.snapshot"
	FirewallRuleAdded     EventType = "firewall.rule_added"
	FirewallRuleRemoved   EventType = "firewall.rule_removed"
)

// Event types for vulnerability scanning (CC7.1)
const (
	VulnerabilityScanStarted EventType = "vulnerability.scan_started"
	VulnerabilityScan        EventType = "vulnerability.scan"
)

// Event types for process monitoring (CC7.2)
const (
	ProcessSuspicious EventType = "process.suspicious"
	ProcessExec       EventType = "process.exec"
)

// Event types for encryption monitoring (CC6.7)
const (
	EncryptionStateSnapshot EventType = "encryption.snapshot"
	CertificateExpiring     EventType = "certificate.expiring"
)

// Event types for compliance monitoring (CC4.1)
const (
	ControlCheck     EventType = "control.check"
	ComplianceScore  EventType = "compliance.score"
)

// Event types for anomaly detection (CC7.2)
const (
	AnomalyDetected EventType = "anomaly.detected"
)

// Event types for malware/AV monitoring (CC6.8)
const (
	MalwareScan     EventType = "malware.scan"
	MalwareDetected EventType = "malware.detected"
)

// Event types for cloud provider detection (CC6.4/CC6.5 inherited controls)
const (
	CloudProvider EventType = "cloud.provider"
)

// Event types for backup monitoring (CC9.1 / A1.2)
const (
	BackupCompleted EventType = "backup.completed"
	BackupVerified  EventType = "backup.verified"
	BackupStale     EventType = "backup.stale"
)

// ActorType represents who or what triggered an event.
type ActorType string

const (
	ActorTypeUser    ActorType = "user"
	ActorTypeSystem  ActorType = "system"
	ActorTypeService ActorType = "service"
)

// Event represents a single event captured by the agent.
// All events follow this common envelope structure.
type Event struct {
	// ID is a unique identifier for the event (ULID format)
	ID string `json:"id"`

	// Type identifies what kind of event this is
	Type EventType `json:"type"`

	// FortressID identifies which Fortress this event belongs to
	FortressID string `json:"fortress_id"`

	// ServerID identifies which server generated this event
	ServerID string `json:"server_id"`

	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// Actor identifies who or what triggered the event (optional)
	Actor *Actor `json:"actor,omitempty"`

	// Payload contains event-type-specific data
	Payload map[string]any `json:"payload"`

	// Metadata contains information about the agent itself
	Metadata Metadata `json:"metadata"`
}

// Actor represents the entity that triggered an event.
type Actor struct {
	// Type is "user", "system", or "service"
	Type ActorType `json:"type"`

	// ID is a unique identifier for the actor
	ID string `json:"id"`

	// Name is a human-readable name (optional)
	Name string `json:"name,omitempty"`

	// IP is the source IP address (optional)
	IP string `json:"ip,omitempty"`
}

// Metadata contains information about the agent that generated the event.
type Metadata struct {
	// AgentVersion is the version of the Rampart agent
	AgentVersion string `json:"agent_version"`

	// Hostname is the hostname of the server
	Hostname string `json:"hostname"`
}

// Version is set at build time
var Version = "0.1.0"

// NewEvent creates a new Event with a generated ID and current timestamp.
func NewEvent(eventType EventType, fortressID, serverID string, payload map[string]any) Event {
	hostname, _ := os.Hostname()

	return Event{
		ID:         GenerateID(),
		Type:       eventType,
		FortressID: fortressID,
		ServerID:   serverID,
		Timestamp:  time.Now().UTC(),
		Payload:    payload,
		Metadata: Metadata{
			AgentVersion: Version,
			Hostname:     hostname,
		},
	}
}

// GenerateID generates a new ULID for use as an event ID.
// ULIDs are lexicographically sortable and contain a timestamp.
func GenerateID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// DeploymentPayload contains data specific to deployment events.
type DeploymentPayload struct {
	AppName      string `json:"app_name"`
	Version      string `json:"version"`
	Image        string `json:"image,omitempty"`
	GitCommit    string `json:"git_commit,omitempty"`
	GitRepo      string `json:"git_repo,omitempty"`
	RollbackOf   string `json:"rollback_of,omitempty"`
	CheckpointID string `json:"checkpoint_id,omitempty"`
}

// AccessPayload contains data specific to access events.
type AccessPayload struct {
	User       string `json:"user"`
	SourceIP   string `json:"source_ip"`
	AuthMethod string `json:"auth_method"` // key, password, certificate
	SessionID  string `json:"session_id"`
	Success    bool   `json:"success"`
}

// DriftPayload contains data specific to drift events.
type DriftPayload struct {
	Path                  string `json:"path"`
	PreviousHash          string `json:"previous_hash"`
	CurrentHash           string `json:"current_hash"`
	ChangedBy             string `json:"changed_by,omitempty"`
	Diff                  string `json:"diff,omitempty"` // first 1000 chars
	CorrelatedDeployment  string `json:"correlated_deployment,omitempty"`
}

// ExposurePayload contains data specific to exposure events.
type ExposurePayload struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp
	Binding  string `json:"binding"`  // public, private
	Process  string `json:"process"`
	SSL      bool   `json:"ssl"`
}

// HealthPayload contains data specific to health events.
type HealthPayload struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryPercent  float64 `json:"memory_percent"`
	DiskPercent    float64 `json:"disk_percent"`
	ContainerCount int     `json:"container_count"`
	UptimeSeconds  int64   `json:"uptime_seconds"`
}

// ContainerPayload contains data specific to container events.
type ContainerPayload struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	Action        string `json:"action"` // start, stop, die, etc.
}

// UserAccountPayload contains data specific to user account events (CC6.2).
type UserAccountPayload struct {
	Username    string   `json:"username"`
	UID         int      `json:"uid"`
	GID         int      `json:"gid"`
	Groups      []string `json:"groups,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	HomeDir     string   `json:"home_dir,omitempty"`
	PerformedBy string   `json:"performed_by,omitempty"`
	Changes     []string `json:"changes,omitempty"`
}

// UserSnapshot represents a point-in-time snapshot of a user account.
type UserSnapshot struct {
	Username      string   `json:"username"`
	UID           int      `json:"uid"`
	GID           int      `json:"gid"`
	Groups        []string `json:"groups"`
	Shell         string   `json:"shell"`
	HomeDir       string   `json:"home_dir"`
	LastLogin     string   `json:"last_login,omitempty"`
	PasswordAge   int      `json:"password_age_days,omitempty"`
	HasSSHKey     bool     `json:"has_ssh_key"`
	HasSudoAccess bool     `json:"has_sudo_access"`
	AccountStatus string   `json:"account_status"` // active, disabled, locked
}

// AccessReviewPayload contains a periodic snapshot of all user accounts (CC6.2).
type AccessReviewPayload struct {
	TotalUsers      int            `json:"total_users"`
	ActiveUsers     int            `json:"active_users"`
	DisabledUsers   int            `json:"disabled_users"`
	ServiceAccounts int            `json:"service_accounts"`
	SudoUsers       []string       `json:"sudo_users"`
	SSHKeyUsers     []string       `json:"ssh_key_users"`
	StaleAccounts   []string       `json:"stale_accounts"` // no login > 90 days
	Users           []UserSnapshot `json:"users"`
}

// PackagePayload contains data specific to package events (CC8.1).
type PackagePayload struct {
	PackageManager  string `json:"package_manager"` // apt, yum, dnf, apk
	PackageName     string `json:"package_name"`
	PreviousVersion string `json:"previous_version,omitempty"`
	NewVersion      string `json:"new_version,omitempty"`
	InstalledBy     string `json:"installed_by,omitempty"`
	Repository      string `json:"repository,omitempty"`
}

// ServicePayload contains data specific to service events (CC8.1).
type ServicePayload struct {
	ServiceName   string `json:"service_name"`
	PreviousState string `json:"previous_state,omitempty"`
	NewState      string `json:"new_state"`
	ChangedBy     string `json:"changed_by,omitempty"`
	InitSystem    string `json:"init_system"` // systemd, sysvinit
	UnitFile      string `json:"unit_file,omitempty"`
}

// PortInfo describes an open port and the process using it.
type PortInfo struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"` // tcp, udp
	Service     string `json:"service,omitempty"`
	ListenAddr  string `json:"listen_addr"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessUser string `json:"process_user,omitempty"`
	PID         int    `json:"pid,omitempty"`
}

// FirewallPayload contains firewall state snapshot data (CC6.6).
type FirewallPayload struct {
	FirewallType    string     `json:"firewall_type"` // iptables, nftables, ufw
	Enabled         bool       `json:"enabled"`
	DefaultInbound  string     `json:"default_inbound"`  // accept, drop, reject
	DefaultOutbound string     `json:"default_outbound"`
	RuleCount       int        `json:"rule_count"`
	OpenPorts       []PortInfo `json:"open_ports"`
	RulesHash       string     `json:"rules_hash"`
}

// VulnerabilityItem represents a single vulnerability finding.
type VulnerabilityItem struct {
	CVE              string `json:"cve"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	Severity         string `json:"severity"` // critical, high, medium, low
	Description      string `json:"description,omitempty"`
	FilePath         string `json:"file_path,omitempty"` // Path where vulnerability was found
}

// OSInfo contains operating system information for distro-specific context.
type OSInfo struct {
	// ID is the distro identifier (ubuntu, debian, centos, rhel, alpine, etc.)
	ID string `json:"id"`
	// Name is the human-readable name (e.g., "Ubuntu 22.04.3 LTS")
	Name string `json:"name"`
	// Version is the version number (e.g., "22.04")
	Version string `json:"version,omitempty"`
	// VersionCodename is the release codename (e.g., "jammy")
	VersionCodename string `json:"version_codename,omitempty"`
}

// VulnerabilityScanPayload contains vulnerability scan results (CC7.1).
type VulnerabilityScanPayload struct {
	ScanType      string              `json:"scan_type"` // package, config, container
	Scanner       string              `json:"scanner"`   // trivy, grype
	TotalFindings int                 `json:"total_findings"`
	CriticalCount int                 `json:"critical_count"`
	HighCount     int                 `json:"high_count"`
	MediumCount   int                 `json:"medium_count"`
	LowCount      int                 `json:"low_count"`
	Findings      []VulnerabilityItem `json:"findings,omitempty"`
	OS            *OSInfo             `json:"os,omitempty"` // For distro-specific security tracker links
}

// ProcessPayload contains data for process execution events (CC7.2).
type ProcessPayload struct {
	PID             int    `json:"pid"`
	PPID            int    `json:"ppid"`
	UID             int    `json:"uid"`
	Username        string `json:"username"`
	Executable      string `json:"executable"`
	CommandLine     string `json:"command_line"`
	WorkingDir      string `json:"working_dir,omitempty"`
	ExitCode        int    `json:"exit_code,omitempty"`
	Suspicious      bool   `json:"suspicious"`
	SuspicionReason string `json:"suspicion_reason,omitempty"`
}

// DiskEncryptionInfo describes encryption status for a disk/partition.
type DiskEncryptionInfo struct {
	Device         string `json:"device"`
	MountPoint     string `json:"mount_point"`
	Encrypted      bool   `json:"encrypted"`
	EncryptionType string `json:"encryption_type,omitempty"` // LUKS, dm-crypt
}

// TLSConfigInfo describes TLS configuration for a service.
type TLSConfigInfo struct {
	Service         string   `json:"service"`
	Port            int      `json:"port"`
	MinVersion      string   `json:"min_version"` // TLS1.2, TLS1.3
	CipherSuites    []string `json:"cipher_suites,omitempty"`
	CertificatePath string   `json:"certificate_path,omitempty"`
}

// CertExpiryInfo describes certificate expiration status.
type CertExpiryInfo struct {
	Path            string `json:"path"`
	Subject         string `json:"subject"`
	Issuer          string `json:"issuer,omitempty"`
	ExpiresAt       string `json:"expires_at"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
}

// EncryptionPayload contains encryption state snapshot (CC6.7).
type EncryptionPayload struct {
	DiskEncryption    []DiskEncryptionInfo `json:"disk_encryption"`
	TLSConfigurations []TLSConfigInfo      `json:"tls_configurations,omitempty"`
	CertificateExpiry []CertExpiryInfo     `json:"certificate_expiry,omitempty"`
}

// ControlCheckPayload contains compliance control check results (CC4.1).
type ControlCheckPayload struct {
	ControlID       string `json:"control_id"`       // CC6.1, CC7.2, etc.
	CheckName       string `json:"check_name"`
	Status          string `json:"status"`           // pass, fail, warning, skip
	Evidence        string `json:"evidence"`
	ExpectedValue   string `json:"expected_value,omitempty"`
	ActualValue     string `json:"actual_value,omitempty"`
	RemediationHint string `json:"remediation_hint,omitempty"`
}

// ComplianceScorePayload contains overall compliance scoring (CC4.1).
type ComplianceScorePayload struct {
	OverallScore    float64            `json:"overall_score"` // 0-100
	ByCategory      map[string]float64 `json:"by_category"`   // CC1: 95, CC6: 87
	PassingControls int                `json:"passing_controls"`
	FailingControls int                `json:"failing_controls"`
	WarningControls int                `json:"warning_controls"`
}

// AnomalyPayload contains anomaly detection data (CC7.2).
type AnomalyPayload struct {
	AnomalyType   string   `json:"anomaly_type"` // cpu_spike, memory_leak, disk_fill
	Severity      string   `json:"severity"`     // info, warning, critical
	Component     string   `json:"component"`
	Description   string   `json:"description"`
	CurrentValue  float64  `json:"current_value"`
	BaselineValue float64  `json:"baseline_value"`
	Deviation     float64  `json:"deviation_percent"`
	RelatedEvents []string `json:"related_events,omitempty"`
}

// ConnectionInfo represents an outbound network connection (Embassy/Cable).
type ConnectionInfo struct {
	LocalAddr    string `json:"local_addr"`
	LocalPort    int    `json:"local_port"`
	RemoteAddr   string `json:"remote_addr"`
	RemotePort   int    `json:"remote_port"`
	Protocol     string `json:"protocol"` // tcp, udp
	State        string `json:"state"`    // established, time_wait, etc.
	ProcessName  string `json:"process_name,omitempty"`
	ProcessPID   int    `json:"process_pid,omitempty"`
	RemoteHost   string `json:"remote_host,omitempty"`   // resolved hostname
	ServiceGuess string `json:"service_guess,omitempty"` // AWS, GCP, external API, etc.
}

// ConnectionPayload contains data for connection events.
type ConnectionPayload struct {
	Connection ConnectionInfo `json:"connection"`
	Direction  string         `json:"direction"` // outbound, inbound
}

// ConnectionSnapshotPayload contains a periodic snapshot of all active connections.
type ConnectionSnapshotPayload struct {
	OutboundConnections []ConnectionInfo `json:"outbound_connections"`
	UniqueDestinations  int              `json:"unique_destinations"`
	TotalConnections    int              `json:"total_connections"`
}

// MalwareScanPayload contains AV/EDR status information (CC6.8).
type MalwareScanPayload struct {
	Provider           string `json:"provider"`                      // crowdstrike, sentinelone, clamav, etc.
	Status             string `json:"status"`                        // active, inactive, not_installed
	Version            string `json:"version,omitempty"`             // AV/EDR version if available
	LastScan           string `json:"last_scan,omitempty"`           // RFC3339 timestamp of last scan
	DefinitionsUpdated string `json:"definitions_updated,omitempty"` // RFC3339 timestamp of last definition update
	RealTimeProtection bool   `json:"real_time_protection"`          // Whether real-time protection is enabled
}

// MalwareDetectedPayload contains malware detection information (CC6.8).
type MalwareDetectedPayload struct {
	Scanner     string `json:"scanner"`             // Which scanner detected the malware
	MalwareName string `json:"malware_name"`        // Name/signature of the malware
	FilePath    string `json:"file_path"`           // Path to infected file
	Action      string `json:"action"`              // quarantined, deleted, detected
	Severity    string `json:"severity"`            // critical, high, medium, low
	Hash        string `json:"hash,omitempty"`      // SHA256 hash of the file
	ScanType    string `json:"scan_type,omitempty"` // on_access, scheduled, manual
}

// CloudProviderPayload contains cloud provider detection data (CC6.4/CC6.5).
// This is used to document inherited controls from cloud providers.
type CloudProviderPayload struct {
	Provider                  string   `json:"provider"`                    // aws, gcp, azure, oci, digitalocean, vultr, hetzner, linode, bare_metal
	Region                    string   `json:"region,omitempty"`            // Cloud region if available
	InstanceID                string   `json:"instance_id,omitempty"`       // Instance identifier
	InstanceType              string   `json:"instance_type,omitempty"`     // Instance type/size
	AvailabilityZone          string   `json:"availability_zone,omitempty"` // AZ if available
	Certifications            []string `json:"certifications"`              // SOC 1, SOC 2, ISO 27001, etc.
	PhysicalSecurityInherited bool     `json:"physical_security_inherited"` // CC6.4: Physical security from provider
	DataDestructionInherited  bool     `json:"data_destruction_inherited"`  // CC6.5: Data destruction from provider
	Note                      string   `json:"note,omitempty"`              // Additional notes for bare metal/on-prem
}

// BackupCompletedPayload contains backup completion information (CC9.1 / A1.2).
type BackupCompletedPayload struct {
	Provider        string `json:"provider"`                   // restic, borg, duplicity, rclone, aws_backup, veeam, acronis, rsync
	Status          string `json:"status"`                     // success, failed, in_progress
	BackupType      string `json:"backup_type"`                // full, incremental, snapshot, differential
	SizeBytes       int64  `json:"size_bytes,omitempty"`       // Size of backup if available
	DurationSeconds int64  `json:"duration_seconds,omitempty"` // How long the backup took
	Destination     string `json:"destination"`                // local, s3, gcs, azure, sftp, etc.
	Repository      string `json:"repository,omitempty"`       // Repository path/URL (sanitized)
	SnapshotID      string `json:"snapshot_id,omitempty"`      // Snapshot/backup ID if available
	FilesNew        int64  `json:"files_new,omitempty"`        // Number of new files backed up
	FilesChanged    int64  `json:"files_changed,omitempty"`    // Number of changed files
	ErrorMessage    string `json:"error_message,omitempty"`    // Error message if failed
}

// BackupVerifiedPayload contains backup verification information (CC9.1 / A1.2).
type BackupVerifiedPayload struct {
	Provider           string `json:"provider"`                      // restic, borg, duplicity, etc.
	VerificationMethod string `json:"verification_method"`           // checksum, restore_test, list, check
	Result             string `json:"result"`                        // passed, failed
	SnapshotID         string `json:"snapshot_id,omitempty"`         // Snapshot that was verified
	Repository         string `json:"repository,omitempty"`          // Repository path/URL (sanitized)
	ErrorCount         int    `json:"error_count,omitempty"`         // Number of errors found
	Details            string `json:"details,omitempty"`             // Additional details
	DurationSeconds    int64  `json:"duration_seconds,omitempty"`    // How long verification took
}

// BackupStalePayload contains stale backup warning information (CC9.1 / A1.2).
type BackupStalePayload struct {
	Provider           string `json:"provider"`                  // restic, borg, duplicity, etc.
	LastBackupTime     string `json:"last_backup_time"`          // RFC3339 timestamp of last backup
	HoursSinceBackup   int    `json:"hours_since_backup"`        // Hours since last successful backup
	MaxBackupAgeHours  int    `json:"max_backup_age_hours"`      // Configured max age threshold
	Repository         string `json:"repository,omitempty"`      // Repository path/URL (sanitized)
}
