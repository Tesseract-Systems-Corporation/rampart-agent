package plugin

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPluginDir is the default directory for user-installed plugins.
const DefaultPluginDir = "/etc/rampart/plugins"

// Loader discovers and loads plugin manifests from various sources.
type Loader struct {
	logger      *slog.Logger
	pluginDirs  []string
	embedded    embed.FS
	hasEmbedded bool
}

// LoaderOption configures the loader.
type LoaderOption func(*Loader)

// WithPluginDirs adds directories to search for plugin manifests.
func WithPluginDirs(dirs ...string) LoaderOption {
	return func(l *Loader) {
		l.pluginDirs = append(l.pluginDirs, dirs...)
	}
}

// WithEmbeddedFS adds an embedded filesystem containing built-in plugin manifests.
func WithEmbeddedFS(fs embed.FS) LoaderOption {
	return func(l *Loader) {
		l.embedded = fs
		l.hasEmbedded = true
	}
}

// NewLoader creates a new plugin loader.
func NewLoader(logger *slog.Logger, opts ...LoaderOption) *Loader {
	l := &Loader{
		logger:     logger.With("component", "plugin-loader"),
		pluginDirs: []string{DefaultPluginDir},
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// LoadedPlugin represents a loaded plugin with its manifest and source.
type LoadedPlugin struct {
	Manifest *Manifest
	Source   PluginSource
	Path     string // File path for filesystem plugins, empty for embedded
}

// PluginSource indicates where a plugin was loaded from.
type PluginSource string

const (
	SourceBuiltin PluginSource = "builtin"  // Compiled into agent
	SourceSystem  PluginSource = "system"   // From /etc/rampart/plugins
	SourceCustom  PluginSource = "custom"   // User-provided path
)

// LoadAll discovers and loads all plugin manifests.
// Built-in (embedded) plugins are loaded first, then filesystem plugins.
// Duplicate plugin names are logged as warnings; the first loaded wins.
func (l *Loader) LoadAll() ([]LoadedPlugin, error) {
	plugins := make(map[string]LoadedPlugin)

	// Load embedded plugins first (highest priority for built-ins)
	if l.hasEmbedded {
		embedded, err := l.loadEmbedded()
		if err != nil {
			l.logger.Warn("failed to load embedded plugins", "error", err)
		}
		for _, p := range embedded {
			plugins[p.Manifest.Metadata.Name] = p
			l.logger.Info("loaded built-in plugin",
				"name", p.Manifest.Metadata.Name,
				"version", p.Manifest.Metadata.Version,
			)
		}
	}

	// Load from filesystem directories
	for _, dir := range l.pluginDirs {
		fromDir, err := l.loadFromDir(dir)
		if err != nil {
			// Directory might not exist, that's OK
			if os.IsNotExist(err) {
				continue
			}
			l.logger.Warn("failed to load plugins from directory", "dir", dir, "error", err)
			continue
		}

		for _, p := range fromDir {
			name := p.Manifest.Metadata.Name
			if existing, exists := plugins[name]; exists {
				l.logger.Warn("duplicate plugin, keeping first loaded",
					"name", name,
					"existing_source", existing.Source,
					"duplicate_source", p.Source,
					"duplicate_path", p.Path,
				)
				continue
			}
			plugins[name] = p
			l.logger.Info("loaded plugin from filesystem",
				"name", name,
				"version", p.Manifest.Metadata.Version,
				"path", p.Path,
			)
		}
	}

	// Convert to slice
	result := make([]LoadedPlugin, 0, len(plugins))
	for _, p := range plugins {
		result = append(result, p)
	}

	return result, nil
}

// loadEmbedded loads plugins from the embedded filesystem.
func (l *Loader) loadEmbedded() ([]LoadedPlugin, error) {
	var plugins []LoadedPlugin

	err := fs.WalkDir(l.embedded, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !isManifestFile(path) {
			return nil
		}

		data, err := l.embedded.ReadFile(path)
		if err != nil {
			l.logger.Warn("failed to read embedded manifest", "path", path, "error", err)
			return nil
		}

		manifest, err := ParseManifest(data)
		if err != nil {
			l.logger.Warn("failed to parse embedded manifest", "path", path, "error", err)
			return nil
		}

		plugins = append(plugins, LoadedPlugin{
			Manifest: manifest,
			Source:   SourceBuiltin,
			Path:     "",
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk embedded fs: %w", err)
	}

	return plugins, nil
}

// loadFromDir loads plugins from a filesystem directory.
func (l *Loader) loadFromDir(dir string) ([]LoadedPlugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var plugins []LoadedPlugin

	for _, entry := range entries {
		if entry.IsDir() {
			// Check for manifest inside subdirectory
			subManifest := filepath.Join(dir, entry.Name(), "manifest.yaml")
			if _, err := os.Stat(subManifest); err == nil {
				p, err := l.loadManifestFile(subManifest, SourceSystem)
				if err != nil {
					l.logger.Warn("failed to load manifest", "path", subManifest, "error", err)
					continue
				}
				plugins = append(plugins, p)
			}
			continue
		}

		if !isManifestFile(entry.Name()) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		p, err := l.loadManifestFile(path, SourceSystem)
		if err != nil {
			l.logger.Warn("failed to load manifest", "path", path, "error", err)
			continue
		}
		plugins = append(plugins, p)
	}

	return plugins, nil
}

// loadManifestFile loads a single manifest file.
func (l *Loader) loadManifestFile(path string, source PluginSource) (LoadedPlugin, error) {
	manifest, err := LoadManifestFromFile(path)
	if err != nil {
		return LoadedPlugin{}, err
	}

	return LoadedPlugin{
		Manifest: manifest,
		Source:   source,
		Path:     path,
	}, nil
}

// LoadFromPath loads a single plugin manifest from a specific path.
func (l *Loader) LoadFromPath(path string) (LoadedPlugin, error) {
	return l.loadManifestFile(path, SourceCustom)
}

// isManifestFile returns true if the filename looks like a manifest file.
func isManifestFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}
