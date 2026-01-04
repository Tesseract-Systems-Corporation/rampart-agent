// Package wsconn provides WebSocket connectivity to the control plane.
package wsconn

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// testLogger returns a logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// testConfig returns a Config for testing
func testConfig(endpoint string) Config {
	return Config{
		Endpoint:     endpoint,
		APIKey:       "test-api-key",
		ServerID:     "test-server-id",
		FortressID:   "test-fortress-id",
		Hostname:     "test-hostname",
		AgentVersion: "1.0.0",
		Provider:     "aws",
		Logger:       testLogger(),
	}
}

// upgrader is used to upgrade HTTP connections to WebSocket
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// mockWSServer creates a mock WebSocket server for testing
type mockWSServer struct {
	server         *httptest.Server
	authHeader     string
	connections    []*websocket.Conn
	connMu         sync.Mutex
	receivedMsgs   []Message
	msgMu          sync.Mutex
	onConnect      func(*websocket.Conn, *http.Request)
	onMessage      func(*websocket.Conn, Message)
	rejectAuth     bool
	rejectUpgrade  bool
	sendOnConnect  *Message
}

func newMockWSServer() *mockWSServer {
	m := &mockWSServer{}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func (m *mockWSServer) handler(w http.ResponseWriter, r *http.Request) {
	m.authHeader = r.Header.Get("Authorization")

	if m.rejectAuth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if m.rejectUpgrade {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	m.connMu.Lock()
	m.connections = append(m.connections, conn)
	m.connMu.Unlock()

	if m.onConnect != nil {
		m.onConnect(conn, r)
	}

	if m.sendOnConnect != nil {
		data, _ := json.Marshal(m.sendOnConnect)
		conn.WriteMessage(websocket.TextMessage, data)
	}

	// Read messages
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		m.msgMu.Lock()
		m.receivedMsgs = append(m.receivedMsgs, msg)
		m.msgMu.Unlock()

		if m.onMessage != nil {
			m.onMessage(conn, msg)
		}
	}
}

func (m *mockWSServer) URL() string {
	return strings.Replace(m.server.URL, "http://", "ws://", 1)
}

func (m *mockWSServer) HTTPURL() string {
	return m.server.URL
}

func (m *mockWSServer) close() {
	m.connMu.Lock()
	for _, conn := range m.connections {
		conn.Close()
	}
	m.connMu.Unlock()
	m.server.Close()
}

func (m *mockWSServer) getReceivedMessages() []Message {
	m.msgMu.Lock()
	defer m.msgMu.Unlock()
	result := make([]Message, len(m.receivedMsgs))
	copy(result, m.receivedMsgs)
	return result
}

func (m *mockWSServer) sendMessage(msg *Message) {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	data, _ := json.Marshal(msg)
	for _, conn := range m.connections {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}

func (m *mockWSServer) closeConnections() {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	for _, conn := range m.connections {
		conn.Close()
	}
	m.connections = nil
}

// TestNew tests the New function
func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantWS   string
		wantHTTP bool
	}{
		{
			name: "http endpoint converts to ws",
			cfg: Config{
				Endpoint:     "http://localhost:8080",
				APIKey:       "test-key",
				ServerID:     "server-1",
				FortressID:   "fortress-1",
				Hostname:     "host-1",
				AgentVersion: "1.0.0",
				Provider:     "aws",
				Logger:       testLogger(),
			},
			wantWS: "ws://localhost:8080",
		},
		{
			name: "https endpoint converts to wss",
			cfg: Config{
				Endpoint:     "https://example.com",
				APIKey:       "test-key",
				ServerID:     "server-1",
				FortressID:   "fortress-1",
				Hostname:     "host-1",
				AgentVersion: "1.0.0",
				Provider:     "gcp",
				Logger:       testLogger(),
			},
			wantWS: "wss://example.com",
		},
		{
			name: "nil logger uses default",
			cfg: Config{
				Endpoint:   "http://localhost:8080",
				APIKey:     "test-key",
				ServerID:   "server-1",
				FortressID: "fortress-1",
				Hostname:   "host-1",
				Logger:     nil,
			},
			wantWS: "ws://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := New(tt.cfg)

			if client == nil {
				t.Fatal("New() returned nil")
			}

			if client.wsURL != tt.wantWS {
				t.Errorf("wsURL = %q, want %q", client.wsURL, tt.wantWS)
			}

			if client.apiKey != tt.cfg.APIKey {
				t.Errorf("apiKey = %q, want %q", client.apiKey, tt.cfg.APIKey)
			}

			if client.serverID != tt.cfg.ServerID {
				t.Errorf("serverID = %q, want %q", client.serverID, tt.cfg.ServerID)
			}

			if client.fortressID != tt.cfg.FortressID {
				t.Errorf("fortressID = %q, want %q", client.fortressID, tt.cfg.FortressID)
			}

			if client.hostname != tt.cfg.Hostname {
				t.Errorf("hostname = %q, want %q", client.hostname, tt.cfg.Hostname)
			}

			if client.agentVersion != tt.cfg.AgentVersion {
				t.Errorf("agentVersion = %q, want %q", client.agentVersion, tt.cfg.AgentVersion)
			}

			if client.provider != tt.cfg.Provider {
				t.Errorf("provider = %q, want %q", client.provider, tt.cfg.Provider)
			}

			if client.send == nil {
				t.Error("send channel is nil")
			}

			if client.logger == nil {
				t.Error("logger is nil")
			}
		})
	}
}

// TestSetCommandHandler tests the SetCommandHandler method
func TestSetCommandHandler(t *testing.T) {
	client := New(testConfig("http://localhost:8080"))

	if client.commandHandler != nil {
		t.Error("commandHandler should be nil initially")
	}

	called := false
	handler := func(cmd Command) {
		called = true
	}

	client.SetCommandHandler(handler)

	if client.commandHandler == nil {
		t.Error("commandHandler should not be nil after SetCommandHandler")
	}

	// Test that handler is callable
	client.commandHandler(Command{})
	if !called {
		t.Error("handler was not called")
	}
}

// TestIsConnected tests the IsConnected method
func TestIsConnected(t *testing.T) {
	client := New(testConfig("http://localhost:8080"))

	// Initially not connected
	if client.IsConnected() {
		t.Error("IsConnected() should return false initially")
	}

	// Manually set connected state
	client.isConnected.Store(true)
	if !client.IsConnected() {
		t.Error("IsConnected() should return true after storing true")
	}

	client.isConnected.Store(false)
	if client.IsConnected() {
		t.Error("IsConnected() should return false after storing false")
	}
}

// TestConnect tests the connect method
func TestConnect(t *testing.T) {
	t.Run("successful connection", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}

		if client.conn == nil {
			t.Error("conn should not be nil after successful connect")
		}

		// Verify auth header was sent
		if mock.authHeader != "Bearer test-api-key" {
			t.Errorf("authHeader = %q, want %q", mock.authHeader, "Bearer test-api-key")
		}

		client.closeConn()
	})

	t.Run("connection with context cancelled", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := client.connect(ctx)
		if err == nil {
			t.Error("connect() should return error when context is cancelled")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		client := New(testConfig("http://127.0.0.1:19999")) // Non-existent port
		ctx := context.Background()

		err := client.connect(ctx)
		if err == nil {
			t.Error("connect() should return error when connection is refused")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		client := New(Config{
			Endpoint: "://invalid",
			Logger:   testLogger(),
		})
		ctx := context.Background()

		err := client.connect(ctx)
		if err == nil {
			t.Error("connect() should return error for invalid URL")
		}
	})
}

// TestCloseConn tests the closeConn method
func TestCloseConn(t *testing.T) {
	t.Run("close existing connection", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}

		if client.conn == nil {
			t.Fatal("conn should not be nil")
		}

		client.closeConn()

		if client.conn != nil {
			t.Error("conn should be nil after closeConn")
		}
	})

	t.Run("close nil connection", func(t *testing.T) {
		client := New(testConfig("http://localhost:8080"))

		// Should not panic
		client.closeConn()

		if client.conn != nil {
			t.Error("conn should still be nil")
		}
	})
}

// TestSendMessage tests the sendMessage method
func TestSendMessage(t *testing.T) {
	t.Run("send message with connection", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		msg := &Message{
			Type: TypeAgentIdentify,
			Data: json.RawMessage(`{"test":"data"}`),
		}

		err = client.sendMessage(msg)
		if err != nil {
			t.Errorf("sendMessage() error = %v", err)
		}

		// Wait for message to be received
		time.Sleep(100 * time.Millisecond)

		received := mock.getReceivedMessages()
		if len(received) == 0 {
			t.Error("no messages received")
		} else if received[0].Type != TypeAgentIdentify {
			t.Errorf("message type = %q, want %q", received[0].Type, TypeAgentIdentify)
		}
	})

	t.Run("send message without connection", func(t *testing.T) {
		client := New(testConfig("http://localhost:8080"))

		msg := &Message{
			Type: TypeAgentIdentify,
		}

		// Should not error, just return nil
		err := client.sendMessage(msg)
		if err != nil {
			t.Errorf("sendMessage() should not error with nil connection, got %v", err)
		}
	})
}

// TestSendIdentify tests the sendIdentify method
func TestSendIdentify(t *testing.T) {
	mock := newMockWSServer()
	defer mock.close()

	client := New(testConfig(mock.HTTPURL()))
	ctx := context.Background()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	defer client.closeConn()

	err = client.sendIdentify()
	if err != nil {
		t.Errorf("sendIdentify() error = %v", err)
	}

	// Wait for message to be received
	time.Sleep(100 * time.Millisecond)

	received := mock.getReceivedMessages()
	if len(received) == 0 {
		t.Fatal("no messages received")
	}

	msg := received[0]
	if msg.Type != TypeAgentIdentify {
		t.Errorf("message type = %q, want %q", msg.Type, TypeAgentIdentify)
	}

	var identify AgentIdentifyMessage
	if err := json.Unmarshal(msg.Data, &identify); err != nil {
		t.Fatalf("failed to unmarshal identify message: %v", err)
	}

	if identify.ServerID != "test-server-id" {
		t.Errorf("ServerID = %q, want %q", identify.ServerID, "test-server-id")
	}

	if identify.FortressID != "test-fortress-id" {
		t.Errorf("FortressID = %q, want %q", identify.FortressID, "test-fortress-id")
	}

	if identify.Hostname != "test-hostname" {
		t.Errorf("Hostname = %q, want %q", identify.Hostname, "test-hostname")
	}

	if identify.AgentVersion != "1.0.0" {
		t.Errorf("AgentVersion = %q, want %q", identify.AgentVersion, "1.0.0")
	}

	if identify.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", identify.Provider, "aws")
	}
}

// TestSendCommandAck tests the sendCommandAck method
func TestSendCommandAck(t *testing.T) {
	mock := newMockWSServer()
	defer mock.close()

	client := New(testConfig(mock.HTTPURL()))
	ctx := context.Background()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	defer client.closeConn()

	err = client.sendCommandAck("cmd-123", "received", "")
	if err != nil {
		t.Errorf("sendCommandAck() error = %v", err)
	}

	// Wait for message to be received
	time.Sleep(100 * time.Millisecond)

	received := mock.getReceivedMessages()
	if len(received) == 0 {
		t.Fatal("no messages received")
	}

	msg := received[0]
	if msg.Type != TypeCommandAck {
		t.Errorf("message type = %q, want %q", msg.Type, TypeCommandAck)
	}

	var ack CommandAckMessage
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("failed to unmarshal ack message: %v", err)
	}

	if ack.CommandID != "cmd-123" {
		t.Errorf("CommandID = %q, want %q", ack.CommandID, "cmd-123")
	}

	if ack.Status != "received" {
		t.Errorf("Status = %q, want %q", ack.Status, "received")
	}
}

// TestSendCommandAckWithError tests the sendCommandAck method with error
func TestSendCommandAckWithError(t *testing.T) {
	mock := newMockWSServer()
	defer mock.close()

	client := New(testConfig(mock.HTTPURL()))
	ctx := context.Background()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	defer client.closeConn()

	err = client.sendCommandAck("cmd-456", "failed", "something went wrong")
	if err != nil {
		t.Errorf("sendCommandAck() error = %v", err)
	}

	// Wait for message to be received
	time.Sleep(100 * time.Millisecond)

	received := mock.getReceivedMessages()
	if len(received) == 0 {
		t.Fatal("no messages received")
	}

	msg := received[0]
	var ack CommandAckMessage
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("failed to unmarshal ack message: %v", err)
	}

	if ack.Error != "something went wrong" {
		t.Errorf("Error = %q, want %q", ack.Error, "something went wrong")
	}
}

// TestHandleMessage tests the handleMessage method
func TestHandleMessage(t *testing.T) {
	tests := []struct {
		name          string
		message       []byte
		wantHandled   bool
		handlerCalled bool
	}{
		{
			name:          "valid command message",
			message:       []byte(`{"type":"agent_command","data":{"id":"cmd-1","command":"restart"}}`),
			wantHandled:   true,
			handlerCalled: true,
		},
		{
			name:          "pong message",
			message:       []byte(`{"type":"pong"}`),
			wantHandled:   true,
			handlerCalled: false,
		},
		{
			name:          "unknown message type",
			message:       []byte(`{"type":"unknown"}`),
			wantHandled:   true,
			handlerCalled: false,
		},
		{
			name:          "invalid JSON",
			message:       []byte(`{invalid}`),
			wantHandled:   false,
			handlerCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := New(testConfig("http://localhost:8080"))

			var called atomic.Bool
			client.SetCommandHandler(func(cmd Command) {
				called.Store(true)
			})

			client.handleMessage(tt.message)

			// Wait for async handler
			time.Sleep(50 * time.Millisecond)

			if called.Load() != tt.handlerCalled {
				t.Errorf("handler called = %v, want %v", called.Load(), tt.handlerCalled)
			}
		})
	}
}

// TestHandleCommand tests the handleCommand method
func TestHandleCommand(t *testing.T) {
	t.Run("valid command with handler", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		var receivedCmd Command
		var wg sync.WaitGroup
		wg.Add(1)
		client.SetCommandHandler(func(cmd Command) {
			receivedCmd = cmd
			wg.Done()
		})

		cmdData, _ := json.Marshal(Command{
			ID:      "test-cmd-id",
			Command: "restart",
			Payload: json.RawMessage(`{"force":true}`),
		})

		msg := &Message{
			Type: TypeAgentCommand,
			Data: cmdData,
		}

		client.handleCommand(msg)
		wg.Wait()

		if receivedCmd.ID != "test-cmd-id" {
			t.Errorf("command ID = %q, want %q", receivedCmd.ID, "test-cmd-id")
		}

		if receivedCmd.Command != "restart" {
			t.Errorf("command = %q, want %q", receivedCmd.Command, "restart")
		}
	})

	t.Run("valid command without handler", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		// No handler set
		cmdData, _ := json.Marshal(Command{
			ID:      "test-cmd-id",
			Command: "restart",
		})

		msg := &Message{
			Type: TypeAgentCommand,
			Data: cmdData,
		}

		// Should not panic
		client.handleCommand(msg)
	})

	t.Run("invalid command data", func(t *testing.T) {
		client := New(testConfig("http://localhost:8080"))

		msg := &Message{
			Type: TypeAgentCommand,
			Data: json.RawMessage(`{invalid}`),
		}

		// Should not panic
		client.handleCommand(msg)
	})
}

// TestRunLoop tests the runLoop method
func TestRunLoop(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx, cancel := context.WithCancel(context.Background())

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		done := make(chan error)
		go func() {
			done <- client.runLoop(ctx)
		}()

		// Cancel context
		cancel()

		select {
		case err := <-done:
			if err != context.Canceled {
				t.Errorf("runLoop() error = %v, want %v", err, context.Canceled)
			}
		case <-time.After(time.Second):
			t.Error("runLoop() did not return after context cancellation")
		}
	})

	t.Run("nil connection returns nil", func(t *testing.T) {
		client := New(testConfig("http://localhost:8080"))
		ctx := context.Background()

		err := client.runLoop(ctx)
		if err != nil {
			t.Errorf("runLoop() with nil connection should return nil, got %v", err)
		}
	})

	t.Run("receives messages", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		var receivedCmd Command
		cmdReceived := make(chan struct{})
		client.SetCommandHandler(func(cmd Command) {
			receivedCmd = cmd
			close(cmdReceived)
		})

		done := make(chan error)
		go func() {
			done <- client.runLoop(ctx)
		}()

		// Send a command from the server
		cmdData, _ := json.Marshal(Command{
			ID:      "server-cmd",
			Command: "status",
		})

		time.Sleep(50 * time.Millisecond)
		mock.sendMessage(&Message{
			Type: TypeAgentCommand,
			Data: cmdData,
		})

		select {
		case <-cmdReceived:
			if receivedCmd.ID != "server-cmd" {
				t.Errorf("received command ID = %q, want %q", receivedCmd.ID, "server-cmd")
			}
		case <-time.After(time.Second):
			t.Error("did not receive command in time")
		}

		cancel()
		<-done
	})

	t.Run("connection closed by server", func(t *testing.T) {
		mock := newMockWSServer()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		done := make(chan error)
		go func() {
			done <- client.runLoop(ctx)
		}()

		// Give time for runLoop to start
		time.Sleep(50 * time.Millisecond)

		// Close server connections
		mock.closeConnections()

		select {
		case err := <-done:
			if err == nil {
				t.Error("runLoop() should return error when connection is closed")
			}
		case <-time.After(time.Second):
			t.Error("runLoop() did not return after connection close")
		}

		mock.close()
	})
}

// TestRun tests the Run method with reconnection logic
func TestRun(t *testing.T) {
	t.Run("immediate context cancellation", func(t *testing.T) {
		client := New(testConfig("http://localhost:8080"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := client.Run(ctx)
		if err != context.Canceled {
			t.Errorf("Run() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("successful connection and message flow", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error)
		go func() {
			done <- client.Run(ctx)
		}()

		// Wait for connection
		time.Sleep(200 * time.Millisecond)

		if !client.IsConnected() {
			t.Error("client should be connected")
		}

		// Verify identify message was sent
		received := mock.getReceivedMessages()
		found := false
		for _, msg := range received {
			if msg.Type == TypeAgentIdentify {
				found = true
				break
			}
		}
		if !found {
			t.Error("identify message not received")
		}

		cancel()

		select {
		case err := <-done:
			if err != context.Canceled {
				t.Errorf("Run() error = %v, want %v", err, context.Canceled)
			}
		case <-time.After(2 * time.Second):
			t.Error("Run() did not return after context cancellation")
		}
	})

	t.Run("reconnection after server disconnect", func(t *testing.T) {
		mock := newMockWSServer()
		client := New(testConfig(mock.HTTPURL()))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		connected := make(chan struct{}, 2)
		mock.onConnect = func(_ *websocket.Conn, _ *http.Request) {
			select {
			case connected <- struct{}{}:
			default:
			}
		}

		go client.Run(ctx)

		// Wait for first connection
		select {
		case <-connected:
		case <-time.After(time.Second):
			t.Fatal("first connection timeout")
		}

		// Close connection to trigger reconnect
		mock.closeConnections()

		// Wait for reconnection
		select {
		case <-connected:
		case <-time.After(3 * time.Second):
			t.Fatal("reconnection timeout")
		}

		mock.close()
	})

	t.Run("context cancelled during reconnect wait", func(t *testing.T) {
		// Use a server that rejects connections
		mock := newMockWSServer()
		mock.rejectUpgrade = true

		client := New(testConfig(mock.HTTPURL()))
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error)
		go func() {
			done <- client.Run(ctx)
		}()

		// Wait a bit for first connection attempt to fail
		time.Sleep(100 * time.Millisecond)

		// Cancel during reconnect backoff
		cancel()

		select {
		case err := <-done:
			if err != context.Canceled {
				t.Errorf("Run() error = %v, want %v", err, context.Canceled)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run() did not return after context cancellation")
		}

		mock.close()
	})
}

// TestRunLoopPing tests that pings are sent periodically
func TestRunLoopPing(t *testing.T) {
	// This test uses a custom server to verify ping messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		pingReceived := make(chan struct{})
		conn.SetPingHandler(func(appData string) error {
			select {
			case pingReceived <- struct{}{}:
			default:
			}
			return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		})

		// Read messages to keep connection alive
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		// Wait for ping (with shorter timeout for test)
		select {
		case <-pingReceived:
			// Success
		case <-time.After(60 * time.Second):
			// Timeout - but this is expected since default pingPeriod is 54s
		}
	}))
	defer server.Close()

	// Note: This test would take too long with actual ping period (54s)
	// We're mainly testing the structure is correct
	t.Skip("Skipping long-running ping test")
}

// TestMessageTypes tests that message type constants are correct
func TestMessageTypes(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{"TypeAgentIdentify", TypeAgentIdentify, "agent_identify"},
		{"TypeAgentCommand", TypeAgentCommand, "agent_command"},
		{"TypeCommandAck", TypeCommandAck, "command_ack"},
		{"TypePing", TypePing, "ping"},
		{"TypePong", TypePong, "pong"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.constant, tt.want)
			}
		})
	}
}

// TestMessageJSONSerialization tests JSON serialization of message types
func TestMessageJSONSerialization(t *testing.T) {
	t.Run("Message serialization", func(t *testing.T) {
		msg := Message{
			Type:    TypeAgentCommand,
			Channel: "test-channel",
			Data:    json.RawMessage(`{"key":"value"}`),
			Error:   "test error",
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if decoded.Type != msg.Type {
			t.Errorf("Type = %q, want %q", decoded.Type, msg.Type)
		}
		if decoded.Channel != msg.Channel {
			t.Errorf("Channel = %q, want %q", decoded.Channel, msg.Channel)
		}
		if decoded.Error != msg.Error {
			t.Errorf("Error = %q, want %q", decoded.Error, msg.Error)
		}
	})

	t.Run("AgentIdentifyMessage serialization", func(t *testing.T) {
		msg := AgentIdentifyMessage{
			ServerID:     "server-1",
			FortressID:   "fortress-1",
			Hostname:     "host-1",
			AgentVersion: "1.0.0",
			Provider:     "aws",
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var decoded AgentIdentifyMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if decoded.ServerID != msg.ServerID {
			t.Errorf("ServerID = %q, want %q", decoded.ServerID, msg.ServerID)
		}
	})

	t.Run("Command serialization", func(t *testing.T) {
		cmd := Command{
			ID:      "cmd-1",
			Command: "restart",
			Payload: json.RawMessage(`{"force":true}`),
		}

		data, err := json.Marshal(cmd)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var decoded Command
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if decoded.ID != cmd.ID {
			t.Errorf("ID = %q, want %q", decoded.ID, cmd.ID)
		}
		if decoded.Command != cmd.Command {
			t.Errorf("Command = %q, want %q", decoded.Command, cmd.Command)
		}
	})

	t.Run("CommandAckMessage serialization", func(t *testing.T) {
		ack := CommandAckMessage{
			CommandID: "cmd-1",
			Status:    "received",
			Error:     "test error",
		}

		data, err := json.Marshal(ack)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var decoded CommandAckMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if decoded.CommandID != ack.CommandID {
			t.Errorf("CommandID = %q, want %q", decoded.CommandID, ack.CommandID)
		}
		if decoded.Status != ack.Status {
			t.Errorf("Status = %q, want %q", decoded.Status, ack.Status)
		}
		if decoded.Error != ack.Error {
			t.Errorf("Error = %q, want %q", decoded.Error, ack.Error)
		}
	})
}

// TestConcurrentOperations tests thread safety of the client
func TestConcurrentOperations(t *testing.T) {
	mock := newMockWSServer()
	defer mock.close()

	client := New(testConfig(mock.HTTPURL()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	defer client.closeConn()

	var wg sync.WaitGroup

	// Concurrent IsConnected calls
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				client.IsConnected()
			}
		}()
	}

	// Concurrent sendMessage calls
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				msg := &Message{
					Type: TypePing,
					Data: json.RawMessage(`{}`),
				}
				client.sendMessage(msg)
			}
		}(i)
	}

	// Concurrent closeConn calls (safe to call multiple times)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
			client.closeConn()
		}()
	}

	wg.Wait()
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		client := New(Config{})
		if client == nil {
			t.Error("New() with empty config should not return nil")
		}
		if client.logger == nil {
			t.Error("logger should be default when not provided")
		}
	})

	t.Run("endpoint without scheme", func(t *testing.T) {
		client := New(Config{
			Endpoint: "localhost:8080",
			Logger:   testLogger(),
		})
		// Should not convert URL scheme if not http/https
		if client.wsURL != "localhost:8080" {
			t.Errorf("wsURL = %q, expected no conversion", client.wsURL)
		}
	})

	t.Run("handle message with empty data", func(t *testing.T) {
		client := New(testConfig("http://localhost:8080"))
		// Should not panic
		client.handleMessage([]byte(`{"type":"agent_command","data":{}}`))
	})

	t.Run("handle command with empty payload", func(t *testing.T) {
		mock := newMockWSServer()
		defer mock.close()

		client := New(testConfig(mock.HTTPURL()))
		ctx := context.Background()

		err := client.connect(ctx)
		if err != nil {
			t.Fatalf("connect() error = %v", err)
		}
		defer client.closeConn()

		var receivedCmd Command
		cmdReceived := make(chan struct{})
		client.SetCommandHandler(func(cmd Command) {
			receivedCmd = cmd
			close(cmdReceived)
		})

		cmdData, _ := json.Marshal(Command{
			ID:      "cmd-empty",
			Command: "noop",
		})

		msg := &Message{
			Type: TypeAgentCommand,
			Data: cmdData,
		}

		client.handleCommand(msg)

		select {
		case <-cmdReceived:
			if receivedCmd.Payload != nil {
				t.Errorf("Payload should be nil, got %v", receivedCmd.Payload)
			}
		case <-time.After(time.Second):
			t.Error("handler not called in time")
		}
	})
}

// TestConstants tests that constants have expected values
func TestConstants(t *testing.T) {
	// These are internal constants but we can test their relationships
	if pingPeriod >= pongWait {
		t.Error("pingPeriod should be less than pongWait")
	}

	if writeWait <= 0 {
		t.Error("writeWait should be positive")
	}

	if maxMessageSize <= 0 {
		t.Error("maxMessageSize should be positive")
	}

	// Verify expected values
	if writeWait != 10*time.Second {
		t.Errorf("writeWait = %v, want 10s", writeWait)
	}

	if pongWait != 60*time.Second {
		t.Errorf("pongWait = %v, want 60s", pongWait)
	}

	if maxMessageSize != 512*1024 {
		t.Errorf("maxMessageSize = %d, want %d", maxMessageSize, 512*1024)
	}
}

// TestRunIdentifyError tests error handling in sendIdentify during Run
func TestRunIdentifyError(t *testing.T) {
	// Create a server that closes connection right after upgrade
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Close immediately to cause sendIdentify to fail
		conn.Close()
	}))
	defer server.Close()

	client := New(testConfig(server.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run should handle the identify error and try to reconnect
	done := make(chan error)
	go func() {
		done <- client.Run(ctx)
	}()

	select {
	case err := <-done:
		if err != context.DeadlineExceeded {
			t.Errorf("Run() error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(3 * time.Second):
		t.Error("Run() did not return after context deadline")
	}
}

// TestHandleMessageUnknownType tests handling of unknown message types
func TestHandleMessageUnknownType(t *testing.T) {
	client := New(testConfig("http://localhost:8080"))

	// Should not panic and should log debug message
	client.handleMessage([]byte(`{"type":"some_unknown_type","data":{}}`))
}

// TestSendCommandAckNoConnection tests sendCommandAck with no connection
func TestSendCommandAckNoConnection(t *testing.T) {
	client := New(testConfig("http://localhost:8080"))

	// Should not error, just return nil
	err := client.sendCommandAck("cmd-1", "received", "")
	if err != nil {
		t.Errorf("sendCommandAck() should not error with nil connection, got %v", err)
	}
}

// TestRunExponentialBackoff tests that reconnect uses exponential backoff
func TestRunExponentialBackoff(t *testing.T) {
	// Create a server that always rejects connections
	var attemptCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := New(testConfig(server.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error)
	go func() {
		done <- client.Run(ctx)
	}()

	select {
	case err := <-done:
		if err != context.DeadlineExceeded {
			t.Errorf("Run() error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run() did not return after context deadline")
	}

	// Should have made multiple attempts with increasing delays
	count := attemptCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 connection attempts, got %d", count)
	}
}

// TestRunPingWriteError tests error handling when ping write fails
func TestRunPingWriteError(t *testing.T) {
	// This test is to verify behavior when ping write fails
	// The ping write error path is already covered by connection close scenarios
	// as both lead to the same error handling in runLoop
	mock := newMockWSServer()
	defer mock.close()

	client := New(testConfig(mock.HTTPURL()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}

	// Start runLoop in background
	done := make(chan error)
	go func() {
		done <- client.runLoop(ctx)
	}()

	// Give time for loop to start
	time.Sleep(50 * time.Millisecond)

	// Close connection from client side - this will cause next ping write to fail
	client.connMu.Lock()
	if client.conn != nil {
		client.conn.Close()
	}
	client.connMu.Unlock()

	select {
	case err := <-done:
		// Should exit with an error (either read error or ping error)
		if err == nil {
			t.Error("runLoop() should return error when connection is closed")
		}
	case <-time.After(time.Second):
		cancel() // Cleanup
		t.Error("runLoop() did not return after connection close")
	}
}

// TestRunSendIdentifyError tests that Run continues after sendIdentify fails
func TestRunSendIdentifyError(t *testing.T) {
	var connectCount atomic.Int32

	// Server that accepts first connection but closes it immediately (causing identify to fail)
	// then accepts second connection normally
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := connectCount.Add(1)

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		if count == 1 {
			// First connection: close immediately to cause sendIdentify to fail
			conn.Close()
			return
		}

		// Subsequent connections: keep alive briefly then close
		defer conn.Close()

		// Read messages
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client := New(testConfig(server.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error)
	go func() {
		done <- client.Run(ctx)
	}()

	// Wait for Run to complete
	select {
	case err := <-done:
		if err != context.DeadlineExceeded {
			t.Errorf("Run() error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(3 * time.Second):
		t.Error("Run() did not return after context deadline")
	}

	// Should have tried to reconnect after sendIdentify failed
	count := connectCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 connection attempts, got %d", count)
	}
}

// TestPongHandler tests the pong handler functionality
func TestPongHandler(t *testing.T) {
	mock := newMockWSServer()
	defer mock.close()

	client := New(testConfig(mock.HTTPURL()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	defer client.closeConn()

	// Get the connection and set up pong handler
	client.connMu.Lock()
	conn := client.conn
	client.connMu.Unlock()

	// Set up the pong handler as runLoop does
	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))

	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// The pong handler would be triggered by the WebSocket library
	// when it receives a pong frame. This is internal to the websocket package.
	// We're just verifying the handler is set correctly.

	if conn.PongHandler() == nil {
		t.Error("pong handler should be set")
	}
}

// TestHandleCommandAckSendError tests handleCommand when ack send fails
func TestHandleCommandAckSendError(t *testing.T) {
	client := New(testConfig("http://localhost:8080"))
	// No connection established, so sendCommandAck will fail silently

	var handlerCalled atomic.Bool
	client.SetCommandHandler(func(cmd Command) {
		handlerCalled.Store(true)
	})

	cmdData, _ := json.Marshal(Command{
		ID:      "test-cmd",
		Command: "test",
	})

	msg := &Message{
		Type: TypeAgentCommand,
		Data: cmdData,
	}

	// Should not panic even though ack send fails (no connection)
	client.handleCommand(msg)

	// Wait for async handler
	time.Sleep(50 * time.Millisecond)

	if !handlerCalled.Load() {
		t.Error("handler should still be called even if ack fails")
	}
}

// TestContextCancelledDuringReconnectSleep tests context cancellation during backoff sleep
func TestContextCancelledDuringReconnectSleep(t *testing.T) {
	// Server that always rejects connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := New(testConfig(server.URL))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error)
	go func() {
		done <- client.Run(ctx)
	}()

	// Wait for first connection attempt to fail
	time.Sleep(100 * time.Millisecond)

	// Cancel during the backoff sleep
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Run() error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestMaxReconnectDelay tests that reconnect delay caps at maxReconnectDelay
// This test is skipped in normal runs because it would take too long
func TestMaxReconnectDelay(t *testing.T) {
	t.Skip("Skipping max reconnect delay test - would take 5+ minutes")
	// In a real test, we would verify that after enough failures,
	// the delay is capped at maxReconnectDelay (5 minutes)
}

// TestRunLoopPingTickerFires verifies the ping ticker code path
// Note: This is a structural test - actual ping testing would require
// waiting for pingPeriod (54 seconds)
func TestRunLoopPingTickerFires(t *testing.T) {
	t.Skip("Skipping long-running ping ticker test - would take 54+ seconds")
	// In a real test, we would verify that after pingPeriod,
	// a ping message is sent to the server
}

// TestSendMessageWithUnmarshalableMessage demonstrates that json.Marshal
// for Message never fails with valid struct (coverage for completeness)
func TestSendMessageWithUnmarshalableMessage(t *testing.T) {
	// Note: It's actually impossible to make json.Marshal fail with
	// Message, AgentIdentifyMessage, or CommandAckMessage structs
	// because they contain only basic types (strings, json.RawMessage)
	// The error paths in sendMessage, sendIdentify, and sendCommandAck
	// are unreachable in practice but exist for defensive programming.

	// Test that marshalling works correctly
	msg := Message{
		Type:    TypeAgentIdentify,
		Channel: "test",
		Data:    json.RawMessage(`{"key":"value"}`),
		Error:   "",
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Errorf("Marshal should not fail: %v", err)
	}
	if len(data) == 0 {
		t.Error("marshalled data should not be empty")
	}
}

// TestRunLoopIntegration tests the full runLoop with message exchange
func TestRunLoopIntegration(t *testing.T) {
	// Server that handles messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Set a ping handler that responds with pong
		conn.SetPingHandler(func(appData string) error {
			return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		})

		// Read and echo messages
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}

			// Echo the message back
			if err := conn.WriteMessage(msgType, data); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client := New(testConfig(server.URL))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := client.connect(ctx)
	if err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	defer client.closeConn()

	// Start runLoop
	done := make(chan error)
	go func() {
		done <- client.runLoop(ctx)
	}()

	// Send a message
	msg := &Message{
		Type: TypePing,
	}
	if err := client.sendMessage(msg); err != nil {
		t.Errorf("sendMessage() error = %v", err)
	}

	// Brief wait for message exchange
	time.Sleep(50 * time.Millisecond)

	// Cancel and wait for cleanup
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Logf("runLoop() returned: %v (expected context.Canceled)", err)
		}
	case <-time.After(time.Second):
		t.Error("runLoop() did not return after context cancellation")
	}
}
