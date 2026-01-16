package operations

import (
	"bytes"
	"fmt"
	"text/template"
)

// RenderTemplate renders a Go template string with the given data.
func RenderTemplate(tmpl string, data map[string]interface{}) (string, error) {
	t, err := template.New("").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// RenderTemplateSlice renders a slice of template strings.
func RenderTemplateSlice(tmpls []string, data map[string]interface{}) ([]string, error) {
	result := make([]string, len(tmpls))
	for i, tmpl := range tmpls {
		rendered, err := RenderTemplate(tmpl, data)
		if err != nil {
			return nil, fmt.Errorf("render template at index %d: %w", i, err)
		}
		result[i] = rendered
	}
	return result, nil
}

// RenderTemplateMap renders a map of template strings.
func RenderTemplateMap(tmpls map[string]string, data map[string]interface{}) (map[string]string, error) {
	result := make(map[string]string, len(tmpls))
	for k, tmpl := range tmpls {
		rendered, err := RenderTemplate(tmpl, data)
		if err != nil {
			return nil, fmt.Errorf("render template for key %q: %w", k, err)
		}
		result[k] = rendered
	}
	return result, nil
}
