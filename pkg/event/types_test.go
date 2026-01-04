package event

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventSerialization(t *testing.T) {
	tests := []struct {
		name    string
		event   Event
		want    string
		wantErr bool
	}{
		{
			name: "deployment completed event",
			event: Event{
				ID:         "01JGXYZ123456789ABCDEF",
				Type:       DeploymentCompleted,
				FortressID: "fort_abc123",
				ServerID:   "srv_xyz789",
				Timestamp:  time.Date(2025, 12, 29, 10, 30, 0, 0, time.UTC),
				Payload: map[string]any{
					"app_name":   "civic-calendar",
					"version":    "v2.4.1",
					"git_commit": "abc123def",
				},
				Metadata: Metadata{
					AgentVersion: "0.1.0",
					Hostname:     "oci-prod-01",
				},
			},
			wantErr: false,
		},
		{
			name: "access ssh event with actor",
			event: Event{
				ID:         "01JGXYZ123456789ABCDEF",
				Type:       AccessSSH,
				FortressID: "fort_abc123",
				ServerID:   "srv_xyz789",
				Timestamp:  time.Date(2025, 12, 29, 10, 30, 0, 0, time.UTC),
				Actor: &Actor{
					Type: ActorTypeUser,
					ID:   "usr_123",
					Name: "jordan",
					IP:   "192.168.1.100",
				},
				Payload: map[string]any{
					"auth_method": "key",
					"success":     true,
				},
				Metadata: Metadata{
					AgentVersion: "0.1.0",
					Hostname:     "oci-prod-01",
				},
			},
			wantErr: false,
		},
		{
			name: "health heartbeat event",
			event: Event{
				ID:         "01JGXYZ123456789ABCDEF",
				Type:       HealthHeartbeat,
				FortressID: "fort_abc123",
				ServerID:   "srv_xyz789",
				Timestamp:  time.Date(2025, 12, 29, 10, 30, 0, 0, time.UTC),
				Payload: map[string]any{
					"cpu_percent":     45.2,
					"memory_percent":  62.8,
					"disk_percent":    34.1,
					"container_count": 6,
					"uptime_seconds":  6307200,
				},
				Metadata: Metadata{
					AgentVersion: "0.1.0",
					Hostname:     "oci-prod-01",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			data, err := json.Marshal(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Test unmarshaling back
			var got Event
			if err := json.Unmarshal(data, &got); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if got.ID != tt.event.ID {
				t.Errorf("ID = %v, want %v", got.ID, tt.event.ID)
			}
			if got.Type != tt.event.Type {
				t.Errorf("Type = %v, want %v", got.Type, tt.event.Type)
			}
			if got.FortressID != tt.event.FortressID {
				t.Errorf("FortressID = %v, want %v", got.FortressID, tt.event.FortressID)
			}
			if got.ServerID != tt.event.ServerID {
				t.Errorf("ServerID = %v, want %v", got.ServerID, tt.event.ServerID)
			}
		})
	}
}

func TestEventDeserialization(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Event
		wantErr bool
	}{
		{
			name:  "valid deployment event",
			input: `{"id":"01JGXYZ123456789ABCDEF","type":"deployment.completed","fortress_id":"fort_abc123","server_id":"srv_xyz789","timestamp":"2025-12-29T10:30:00Z","payload":{"app_name":"api"},"metadata":{"agent_version":"0.1.0","hostname":"server1"}}`,
			want: Event{
				ID:         "01JGXYZ123456789ABCDEF",
				Type:       DeploymentCompleted,
				FortressID: "fort_abc123",
				ServerID:   "srv_xyz789",
			},
			wantErr: false,
		},
		{
			name:    "invalid json",
			input:   `{not valid json}`,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Event
			err := json.Unmarshal([]byte(tt.input), &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.ID != tt.want.ID {
				t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type = %v, want %v", got.Type, tt.want.Type)
			}
		})
	}
}

func TestNewEvent(t *testing.T) {
	tests := []struct {
		name       string
		eventType  EventType
		fortressID string
		serverID   string
		payload    map[string]any
	}{
		{
			name:       "create deployment event",
			eventType:  DeploymentStarted,
			fortressID: "fort_test123",
			serverID:   "srv_test456",
			payload:    map[string]any{"app": "test-app"},
		},
		{
			name:       "create health event",
			eventType:  HealthHeartbeat,
			fortressID: "fort_test123",
			serverID:   "srv_test456",
			payload:    map[string]any{"cpu_percent": 50.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewEvent(tt.eventType, tt.fortressID, tt.serverID, tt.payload)

			// ID should be generated (ULID format, 26 chars)
			if len(got.ID) != 26 {
				t.Errorf("ID length = %v, want 26 (ULID)", len(got.ID))
			}

			if got.Type != tt.eventType {
				t.Errorf("Type = %v, want %v", got.Type, tt.eventType)
			}

			if got.FortressID != tt.fortressID {
				t.Errorf("FortressID = %v, want %v", got.FortressID, tt.fortressID)
			}

			if got.ServerID != tt.serverID {
				t.Errorf("ServerID = %v, want %v", got.ServerID, tt.serverID)
			}

			// Timestamp should be recent (within last second)
			if time.Since(got.Timestamp) > time.Second {
				t.Errorf("Timestamp too old: %v", got.Timestamp)
			}

			// Payload should match
			if got.Payload == nil {
				t.Error("Payload is nil")
			}
		})
	}
}

func TestEventTypes(t *testing.T) {
	// Verify all event type constants are defined correctly
	types := []struct {
		name string
		typ  EventType
		want string
	}{
		{"DeploymentStarted", DeploymentStarted, "deployment.started"},
		{"DeploymentCompleted", DeploymentCompleted, "deployment.completed"},
		{"DeploymentFailed", DeploymentFailed, "deployment.failed"},
		{"AccessSSH", AccessSSH, "access.ssh"},
		{"AccessConsole", AccessConsole, "access.console"},
		{"AccessAPI", AccessAPI, "access.api"},
		{"DriftFileChanged", DriftFileChanged, "drift.file_changed"},
		{"DriftConfigModified", DriftConfigModified, "drift.config_modified"},
		{"ExposureDoorOpened", ExposureDoorOpened, "exposure.door_opened"},
		{"ExposureDoorClosed", ExposureDoorClosed, "exposure.door_closed"},
		{"HealthHeartbeat", HealthHeartbeat, "health.heartbeat"},
		{"HealthDegraded", HealthDegraded, "health.degraded"},
		{"HealthRecovered", HealthRecovered, "health.recovered"},
		{"ContainerStarted", ContainerStarted, "container.started"},
		{"ContainerStopped", ContainerStopped, "container.stopped"},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.typ) != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.typ, tt.want)
			}
		})
	}
}

func TestActorTypes(t *testing.T) {
	types := []struct {
		name string
		typ  ActorType
		want string
	}{
		{"User", ActorTypeUser, "user"},
		{"System", ActorTypeSystem, "system"},
		{"Service", ActorTypeService, "service"},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.typ) != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.typ, tt.want)
			}
		})
	}
}

func TestEventWithActor(t *testing.T) {
	event := NewEvent(AccessSSH, "fort_123", "srv_456", map[string]any{
		"success": true,
	})

	actor := &Actor{
		Type: ActorTypeUser,
		ID:   "usr_789",
		Name: "testuser",
		IP:   "10.0.0.1",
	}

	event.Actor = actor

	// Verify actor is set
	if event.Actor == nil {
		t.Fatal("Actor is nil")
	}
	if event.Actor.Type != ActorTypeUser {
		t.Errorf("Actor.Type = %v, want %v", event.Actor.Type, ActorTypeUser)
	}
	if event.Actor.ID != "usr_789" {
		t.Errorf("Actor.ID = %v, want usr_789", event.Actor.ID)
	}
	if event.Actor.Name != "testuser" {
		t.Errorf("Actor.Name = %v, want testuser", event.Actor.Name)
	}
	if event.Actor.IP != "10.0.0.1" {
		t.Errorf("Actor.IP = %v, want 10.0.0.1", event.Actor.IP)
	}
}

func TestULIDGeneration(t *testing.T) {
	// Generate multiple IDs and verify uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateID()
		if len(id) != 26 {
			t.Errorf("ID length = %d, want 26", len(id))
		}
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}
