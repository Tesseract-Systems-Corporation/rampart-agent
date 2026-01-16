// Package plugin provides a modular plugin system for the Rampart agent.
package plugin

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Manifest represents a plugin manifest file.
// Manifests define plugin metadata, configuration schema, commands, and
// optionally declarative workflows for execution.
type Manifest struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

// Metadata contains plugin identification and display information.
type Metadata struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	DisplayName string `yaml:"displayName" json:"displayName"`
	Description string `yaml:"description" json:"description"`
	Category    string `yaml:"category" json:"category"`
	Icon        string `yaml:"icon,omitempty" json:"icon,omitempty"`
	Author      string `yaml:"author,omitempty" json:"author,omitempty"`
	Signed      bool   `yaml:"signed,omitempty" json:"signed,omitempty"`
}

// Spec contains the plugin specification.
type Spec struct {
	RequiresAgent bool                       `yaml:"requiresAgent" json:"requiresAgent"`
	ConfigSchema  map[string]interface{}     `yaml:"configSchema" json:"configSchema"`
	Lookups       map[string]LookupDef       `yaml:"lookups,omitempty" json:"lookups,omitempty"`
	Form          *FormConfig                `yaml:"form,omitempty" json:"form,omitempty"`
	ListView      *ListView                  `yaml:"listView,omitempty" json:"listView,omitempty"`
	Views         []View                     `yaml:"views,omitempty" json:"views,omitempty"`
	Commands      []CommandDef               `yaml:"commands" json:"commands"`
	Events        []EventDef                 `yaml:"events" json:"events"`
	Declarative   map[string]Workflow        `yaml:"declarative,omitempty" json:"declarative,omitempty"`
}

// FormConfig defines the form/modal configuration for create/edit operations.
type FormConfig struct {
	CreateEndpoint    string `yaml:"createEndpoint" json:"createEndpoint"`
	UpdateEndpoint    string `yaml:"updateEndpoint" json:"updateEndpoint"`
	TestEndpoint      string `yaml:"testEndpoint,omitempty" json:"testEndpoint,omitempty"`
	CreateTitle       string `yaml:"createTitle,omitempty" json:"createTitle,omitempty"`
	EditTitle         string `yaml:"editTitle,omitempty" json:"editTitle,omitempty"`
	CreateSubmitLabel string `yaml:"createSubmitLabel,omitempty" json:"createSubmitLabel,omitempty"`
	EditSubmitLabel   string `yaml:"editSubmitLabel,omitempty" json:"editSubmitLabel,omitempty"`
}

// LookupDef defines a dynamic lookup for x-lookup fields.
// The UI uses these to fetch dropdown options from API endpoints.
type LookupDef struct {
	Endpoint      string           `yaml:"endpoint" json:"endpoint"`
	LabelField    string           `yaml:"labelField" json:"labelField"`
	LabelFallback string           `yaml:"labelFallback,omitempty" json:"labelFallback,omitempty"`
	LabelSuffix   string           `yaml:"labelSuffix,omitempty" json:"labelSuffix,omitempty"`
	ValueField    string           `yaml:"valueField" json:"valueField"`
	EmptyOption   *LookupEmptyOpt  `yaml:"emptyOption,omitempty" json:"emptyOption,omitempty"`
}

// LookupEmptyOpt defines an empty/default option for a lookup dropdown.
type LookupEmptyOpt struct {
	Value string `yaml:"value" json:"value"`
	Label string `yaml:"label" json:"label"`
}

// CommandDef defines a command that the plugin can handle.
type CommandDef struct {
	Name           string `yaml:"name" json:"name"`
	DisplayName    string `yaml:"displayName" json:"displayName"`
	Description    string `yaml:"description,omitempty" json:"description,omitempty"`
	Icon           string `yaml:"icon,omitempty" json:"icon,omitempty"`
	Variant        string `yaml:"variant,omitempty" json:"variant,omitempty"`
	ConfirmMessage string `yaml:"confirmMessage,omitempty" json:"confirmMessage,omitempty"`
}

// EventDef defines an event that the plugin can emit.
type EventDef struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
}

// ListView defines the table/list view configuration for the plugin.
type ListView struct {
	Columns    []ListViewColumn `yaml:"columns" json:"columns"`
	EmptyState *EmptyState      `yaml:"emptyState,omitempty" json:"emptyState,omitempty"`
}

// ListViewColumn defines a column in the list view.
type ListViewColumn struct {
	Field      string                 `yaml:"field" json:"field"`
	Title      string                 `yaml:"title" json:"title"`
	Type       string                 `yaml:"type,omitempty" json:"type,omitempty"`           // text, badge, date, bytes, duration, template
	Primary    bool                   `yaml:"primary,omitempty" json:"primary,omitempty"`
	Format     string                 `yaml:"format,omitempty" json:"format,omitempty"`       // Template string for 'template' type
	BadgeMap   map[string]BadgeConfig `yaml:"badgeMap,omitempty" json:"badgeMap,omitempty"`
	DateFormat string                 `yaml:"dateFormat,omitempty" json:"dateFormat,omitempty"` // relative or absolute
	Hidden     bool                   `yaml:"hidden,omitempty" json:"hidden,omitempty"`
	ClassName  string                 `yaml:"className,omitempty" json:"className,omitempty"`
}

// BadgeConfig defines how a badge should be rendered.
type BadgeConfig struct {
	Variant string `yaml:"variant" json:"variant"` // success, danger, warning, info, default
	Label   string `yaml:"label" json:"label"`
}

// EmptyState defines the empty state message for the list view.
type EmptyState struct {
	Icon        string `yaml:"icon,omitempty" json:"icon,omitempty"`
	Title       string `yaml:"title" json:"title"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// View defines a tab/page view for the plugin.
type View struct {
	ID          string    `yaml:"id" json:"id"`
	Label       string    `yaml:"label" json:"label"`
	Icon        string    `yaml:"icon,omitempty" json:"icon,omitempty"`
	Endpoint    string    `yaml:"endpoint" json:"endpoint"`
	ListView    *ListView `yaml:"listView,omitempty" json:"listView,omitempty"`
	Commands    []string  `yaml:"commands,omitempty" json:"commands,omitempty"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
}

// Workflow defines a declarative workflow for a command.
type Workflow struct {
	Steps []Step `yaml:"steps" json:"steps"`
}

// Step represents a single step in a declarative workflow.
type Step struct {
	Type      string            `yaml:"type" json:"type"`
	ID        string            `yaml:"id,omitempty" json:"id,omitempty"`
	Binary    string            `yaml:"binary,omitempty" json:"binary,omitempty"`
	Args      []string          `yaml:"args,omitempty" json:"args,omitempty"`
	Env       map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Timeout   string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Stdout    string            `yaml:"stdout,omitempty" json:"stdout,omitempty"`
	Input     string            `yaml:"input,omitempty" json:"input,omitempty"`
	Output    string            `yaml:"output,omitempty" json:"output,omitempty"`
	Source    string            `yaml:"source,omitempty" json:"source,omitempty"`
	Destination string          `yaml:"destination,omitempty" json:"destination,omitempty"`
	Algorithm string            `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
	URL       string            `yaml:"url,omitempty" json:"url,omitempty"`
	Method    string            `yaml:"method,omitempty" json:"method,omitempty"`
	Headers   map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body      string            `yaml:"body,omitempty" json:"body,omitempty"`
	OnSuccess *StepAction       `yaml:"onSuccess,omitempty" json:"onSuccess,omitempty"`
	OnFailure *StepAction       `yaml:"onFailure,omitempty" json:"onFailure,omitempty"`
	Progress  *StepAction       `yaml:"progress,omitempty" json:"progress,omitempty"`
}

// StepAction defines an action to take after a step completes.
type StepAction struct {
	Emit *EmitAction `yaml:"emit,omitempty" json:"emit,omitempty"`
}

// EmitAction defines an event to emit.
type EmitAction struct {
	Type    string                 `yaml:"type" json:"type"`
	Payload map[string]interface{} `yaml:"payload,omitempty" json:"payload,omitempty"`
}

// LoadManifestFromFile loads a plugin manifest from a YAML file.
func LoadManifestFromFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest file: %w", err)
	}

	return ParseManifest(data)
}

// ParseManifest parses a manifest from YAML bytes.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest YAML: %w", err)
	}

	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("validate manifest: %w", err)
	}

	return &m, nil
}

// Validate checks that the manifest has all required fields.
func (m *Manifest) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.Kind != "Plugin" {
		return fmt.Errorf("kind must be 'Plugin', got %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if m.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	if len(m.Spec.Commands) == 0 {
		return fmt.Errorf("spec.commands must have at least one command")
	}

	return nil
}

// IsDeclarative returns true if this plugin has declarative workflows
// (i.e., it's not a built-in compiled plugin).
func (m *Manifest) IsDeclarative() bool {
	return len(m.Spec.Declarative) > 0
}

// CommandNames returns the list of command names this plugin handles.
func (m *Manifest) CommandNames() []string {
	names := make([]string, len(m.Spec.Commands))
	for i, cmd := range m.Spec.Commands {
		names[i] = cmd.Name
	}
	return names
}

// ToJSON converts the manifest to JSON bytes.
func (m *Manifest) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// GetWorkflow returns the workflow for a given command, or nil if not found.
func (m *Manifest) GetWorkflow(commandName string) *Workflow {
	if m.Spec.Declarative == nil {
		return nil
	}
	if w, ok := m.Spec.Declarative[commandName]; ok {
		return &w
	}
	return nil
}
