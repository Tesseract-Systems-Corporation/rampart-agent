// Package wsconn provides WebSocket connectivity to the control plane.
package wsconn

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512 * 1024 // 512KB
)

// Config holds WebSocket client configuration.
type Config struct {
	// Endpoint is the control plane HTTP endpoint (e.g., http://192.168.64.1:8080).
	// Will be converted to WebSocket URL.
	Endpoint string

	// APIKey is the API key for authentication.
	APIKey string

	// ServerID is the unique identifier for this server.
	ServerID string

	// FortressID is the fortress this server belongs to.
	FortressID string

	// Hostname is the hostname of this server.
	Hostname string

	// AgentVersion is the version of the agent.
	AgentVersion string

	// Provider is the cloud provider.
	Provider string

	// Logger is the logger to use.
	Logger *slog.Logger
}

// CommandHandler is called when a command is received from the control plane.
type CommandHandler func(cmd Command)

// Command represents a command from the control plane.
type Command struct {
	ID      string          `json:"id"`
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Client manages the WebSocket connection to the control plane.
type Client struct {
	endpoint     string
	wsURL        string
	apiKey       string
	serverID     string
	fortressID   string
	hostname     string
	agentVersion string
	provider     string
	logger       *slog.Logger

	conn   *websocket.Conn
	connMu sync.Mutex

	commandHandler CommandHandler
	isConnected    atomic.Bool

	send chan []byte
}

// Message types
const (
	TypeAgentIdentify = "agent_identify"
	TypeAgentCommand  = "agent_command"
	TypeCommandAck    = "command_ack"
	TypePing          = "ping"
	TypePong          = "pong"
)

// Message represents a WebSocket message.
type Message struct {
	Type    string          `json:"type"`
	Channel string          `json:"channel,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// AgentIdentifyMessage is sent when connecting.
type AgentIdentifyMessage struct {
	ServerID     string `json:"server_id"`
	FortressID   string `json:"fortress_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
	Provider     string `json:"provider,omitempty"`
}

// CommandAckMessage is sent to acknowledge command receipt.
type CommandAckMessage struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// New creates a new WebSocket client.
func New(cfg Config) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Convert HTTP endpoint to WebSocket URL
	wsURL := cfg.Endpoint
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	return &Client{
		endpoint:     cfg.Endpoint,
		wsURL:        wsURL,
		apiKey:       cfg.APIKey,
		serverID:     cfg.ServerID,
		fortressID:   cfg.FortressID,
		hostname:     cfg.Hostname,
		agentVersion: cfg.AgentVersion,
		provider:     cfg.Provider,
		logger:       logger.With("component", "ws-client"),
		send:         make(chan []byte, 256),
	}
}

// SetCommandHandler sets the handler for commands from the control plane.
func (c *Client) SetCommandHandler(handler CommandHandler) {
	c.commandHandler = handler
}

// IsConnected returns whether the WebSocket is currently connected.
func (c *Client) IsConnected() bool {
	return c.isConnected.Load()
}

// Run starts the WebSocket client with automatic reconnection.
func (c *Client) Run(ctx context.Context) error {
	c.logger.Info("starting WebSocket client",
		"endpoint", c.endpoint,
		"server_id", c.serverID)

	reconnectDelay := time.Second
	maxReconnectDelay := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			c.closeConn()
			return ctx.Err()
		default:
		}

		if err := c.connect(ctx); err != nil {
			c.logger.Warn("WebSocket connection failed",
				"error", err,
				"retry_in", reconnectDelay)

			c.isConnected.Store(false)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(reconnectDelay):
			}

			// Exponential backoff
			reconnectDelay = reconnectDelay * 2
			if reconnectDelay > maxReconnectDelay {
				reconnectDelay = maxReconnectDelay
			}
			continue
		}

		// Reset backoff on successful connection
		reconnectDelay = time.Second
		c.isConnected.Store(true)

		c.logger.Info("WebSocket connected to control plane")

		// Send identification message
		if err := c.sendIdentify(); err != nil {
			c.logger.Error("failed to send identify", "error", err)
			c.closeConn()
			continue
		}

		// Run read/write loops
		if err := c.runLoop(ctx); err != nil {
			c.logger.Warn("WebSocket connection lost", "error", err)
		}

		c.closeConn()
		c.isConnected.Store(false)
	}
}

// connect establishes the WebSocket connection.
func (c *Client) connect(ctx context.Context) error {
	// Build WebSocket URL with server_id query parameter
	wsURL, err := url.Parse(c.wsURL + "/agent/ws")
	if err != nil {
		return err
	}
	q := wsURL.Query()
	q.Set("server_id", c.serverID)
	wsURL.RawQuery = q.Encode()

	// Create dialer with auth header
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.apiKey)

	conn, _, err := dialer.DialContext(ctx, wsURL.String(), header)
	if err != nil {
		return err
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	return nil
}

// closeConn safely closes the WebSocket connection.
func (c *Client) closeConn() {
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()
}

// sendIdentify sends the agent identification message.
func (c *Client) sendIdentify() error {
	identify := AgentIdentifyMessage{
		ServerID:     c.serverID,
		FortressID:   c.fortressID,
		Hostname:     c.hostname,
		AgentVersion: c.agentVersion,
		Provider:     c.provider,
	}

	data, err := json.Marshal(identify)
	if err != nil {
		return err
	}

	msg := Message{
		Type: TypeAgentIdentify,
		Data: data,
	}

	return c.sendMessage(&msg)
}

// sendMessage sends a message over the WebSocket.
func (c *Client) sendMessage(msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn == nil {
		return nil
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// sendCommandAck sends a command acknowledgment.
func (c *Client) sendCommandAck(commandID, status, errMsg string) error {
	ack := CommandAckMessage{
		CommandID: commandID,
		Status:    status,
		Error:     errMsg,
	}

	data, err := json.Marshal(ack)
	if err != nil {
		return err
	}

	msg := Message{
		Type: TypeCommandAck,
		Data: data,
	}

	return c.sendMessage(&msg)
}

// runLoop handles the read/write loops for the connection.
func (c *Client) runLoop(ctx context.Context) error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return nil
	}

	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Start ping ticker
	pingTicker := time.NewTicker(pingPeriod)
	defer pingTicker.Stop()

	errChan := make(chan error, 1)

	// Read loop
	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			c.handleMessage(message)
		}
	}()

	// Main loop for pings and context cancellation
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errChan:
			return err
		case <-pingTicker.C:
			c.connMu.Lock()
			if c.conn != nil {
				c.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					c.connMu.Unlock()
					return err
				}
			}
			c.connMu.Unlock()
		}
	}
}

// handleMessage processes an incoming WebSocket message.
func (c *Client) handleMessage(data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		c.logger.Warn("failed to decode message", "error", err)
		return
	}

	switch msg.Type {
	case TypeAgentCommand:
		c.handleCommand(&msg)
	case TypePong:
		// Ignore pong messages
	default:
		c.logger.Debug("unknown message type", "type", msg.Type)
	}
}

// handleCommand processes a command from the control plane.
func (c *Client) handleCommand(msg *Message) {
	var cmd Command
	if err := json.Unmarshal(msg.Data, &cmd); err != nil {
		c.logger.Warn("failed to decode command", "error", err)
		return
	}

	c.logger.Info("received command via WebSocket",
		"command_id", cmd.ID,
		"command", cmd.Command)

	// Send acknowledgment
	if err := c.sendCommandAck(cmd.ID, "received", ""); err != nil {
		c.logger.Warn("failed to send command ack", "error", err)
	}

	// Execute command
	if c.commandHandler != nil {
		go c.commandHandler(cmd)
	}
}
