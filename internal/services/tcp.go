package services

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
)

// TCPHandler implements the Handler interface for TCP services
type TCPHandler struct {
	template  config.ServiceTemplate
	info      ServiceInfo
	responses map[string][]config.Reply
	conn      net.Conn
}

// connectionTracker wraps a net.Conn to track connection data
type connectionTracker struct {
	net.Conn
	context *ConnectionContext
}

// ConnectionContext tracks connection behavior and metadata
type ConnectionContext struct {
	Commands []string
	Warnings []string
	Metadata map[string]interface{}
}

// NewTCPHandler creates a new TCP service handler
func NewTCPHandler(tmpl config.ServiceTemplate) (*TCPHandler, error) {
	responses := make(map[string][]config.Reply)

	// Initialize responses with template commands
	for cmd, reply := range tmpl.Commands {
		responses[cmd] = []config.Reply{reply}
	}

	handler := &TCPHandler{
		template:  tmpl,
		responses: responses,
		info: ServiceInfo{
			Name:        tmpl.Name,
			Description: fmt.Sprintf("%s service emulator", tmpl.Name),
			DefaultPort: tmpl.Port,
		},
	}

	return handler, nil
}

// Handle processes a TCP connection
func (h *TCPHandler) Handle(ctx context.Context, conn net.Conn) error {
	// Send initial banner if configured
	if h.template.Banner != "" {
		if err := h.sendWithDelay(conn, h.template.Banner); err != nil {
			return fmt.Errorf("failed to send banner: %w", err)
		}
	}

	// Setup connection timeout
	deadline := time.Now().Add(5 * time.Minute)
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	reader := bufio.NewReader(conn)
	var sessionData []string
	sessionStart := time.Now()
	commandTiming := make([]time.Duration, 0)
	commandPatterns := make(map[string]int)
	suspiciousCommands := make([]string, 0)

	// Track behavioral patterns
	var (
		rapidCommandCount    int
		repeatedCommandCount int
		lastCommandTime      time.Time
		lastCommand          string
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Send prompt if configured
			if len(h.template.Prompts) > 0 {
				prompt := h.template.Prompts[rand.Intn(len(h.template.Prompts))]
				if err := h.sendWithDelay(conn, prompt); err != nil {
					return fmt.Errorf("failed to send prompt: %w", err)
				}
			}

			// Read command
			command, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					// Analyze session before returning
					h.analyzeSession(sessionData, commandTiming, commandPatterns, suspiciousCommands)
					return nil
				}
				return fmt.Errorf("failed to read command: %w", err)
			}

			now := time.Now()
			command = strings.TrimSpace(command)
			sessionData = append(sessionData, command)

			// Skip empty commands
			if command == "" {
				continue
			}

			// Update command timing and patterns
			if !lastCommandTime.IsZero() {
				timeSinceLastCommand := now.Sub(lastCommandTime)
				commandTiming = append(commandTiming, timeSinceLastCommand)

				// Check for rapid commands (less than 100ms apart)
				if timeSinceLastCommand < 100*time.Millisecond {
					rapidCommandCount++
				}

				// Check for repeated commands
				if command == lastCommand {
					repeatedCommandCount++
				}
			}
			lastCommandTime = now
			lastCommand = command

			// Get base command (first word)
			baseCmd := strings.Fields(command)[0]
			baseCmd = strings.ToUpper(baseCmd)

			// Update command patterns
			commandPatterns[baseCmd]++

			// Check for suspicious patterns
			if h.isCommandSuspicious(command) {
				suspiciousCommands = append(suspiciousCommands, command)
			}

			// Get response for command
			response := h.getResponse(baseCmd, sessionData)

			// Send response
			if err := h.sendWithDelay(conn, response.Response); err != nil {
				return fmt.Errorf("failed to send response: %w", err)
			}

			// Update connection context if available
			if tracker, ok := conn.(*connectionTracker); ok {
				tracker.context.Commands = append(tracker.context.Commands, command)

				// Add warnings for suspicious behavior
				if rapidCommandCount > 5 {
					tracker.context.Warnings = append(tracker.context.Warnings, "Rapid command execution detected")
				}
				if repeatedCommandCount > 3 {
					tracker.context.Warnings = append(tracker.context.Warnings, "Command repetition detected")
				}
				if len(suspiciousCommands) > 0 {
					tracker.context.Warnings = append(tracker.context.Warnings, "Suspicious commands detected")
				}

				// Update metadata
				tracker.context.Metadata["command_patterns"] = commandPatterns
				tracker.context.Metadata["command_timing"] = commandTiming
				tracker.context.Metadata["session_duration"] = time.Since(sessionStart)
			}

			// Close connection if specified in response
			if response.CloseConn {
				// Analyze session before closing
				h.analyzeSession(sessionData, commandTiming, commandPatterns, suspiciousCommands)
				return nil
			}

			// Update deadline
			if err := conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
				return fmt.Errorf("failed to update deadline: %w", err)
			}
		}
	}
}

// getResponse returns an appropriate response based on the command and session context
func (h *TCPHandler) getResponse(cmd string, sessionData []string) config.Reply {
	// Check if we have specific responses for this command
	if responses, exists := h.responses[cmd]; exists {
		// If we have multiple responses, choose based on context
		if len(responses) > 1 {
			return h.selectContextualResponse(responses, sessionData)
		}
		return responses[0]
	}

	// Default response for unknown commands
	return config.Reply{
		Response:  "Unknown command.\r\n",
		DelayMin:  100,
		DelayMax:  300,
		CloseConn: false,
	}
}

// selectContextualResponse chooses a response based on session context
func (h *TCPHandler) selectContextualResponse(responses []config.Reply, sessionData []string) config.Reply {
	// Analyze session behavior to choose appropriate response
	cmdCount := len(sessionData)

	// If this is a very active session, tend toward more restrictive responses
	if cmdCount > 20 {
		// Find the most restrictive response
		for _, resp := range responses {
			if resp.CloseConn {
				return resp
			}
		}
	}

	// For normal activity, choose randomly but weight toward less restrictive responses
	return responses[rand.Intn(len(responses))]
}

// sendWithDelay sends data with a realistic delay
func (h *TCPHandler) sendWithDelay(conn net.Conn, data string) error {
	delay := time.Duration(rand.Intn(200)+100) * time.Millisecond
	time.Sleep(delay)

	_, err := conn.Write([]byte(data + "\r\n"))
	return err
}

// GetServiceInfo returns information about the service
func (h *TCPHandler) GetServiceInfo() ServiceInfo {
	return h.info
}

// AddResponse adds a new response pattern
func (h *TCPHandler) AddResponse(cmd string, reply config.Reply) {
	h.responses[cmd] = append(h.responses[cmd], reply)
}

// UpdateResponse updates existing response patterns
func (h *TCPHandler) UpdateResponse(cmd string, index int, reply config.Reply) error {
	if responses, exists := h.responses[cmd]; exists {
		if index >= 0 && index < len(responses) {
			responses[index] = reply
			h.responses[cmd] = responses
			return nil
		}
		return fmt.Errorf("invalid response index")
	}
	return fmt.Errorf("command not found")
}

// RemoveResponse removes a response pattern
func (h *TCPHandler) RemoveResponse(cmd string, index int) error {
	if responses, exists := h.responses[cmd]; exists {
		if index >= 0 && index < len(responses) {
			h.responses[cmd] = append(responses[:index], responses[index+1:]...)
			return nil
		}
		return fmt.Errorf("invalid response index")
	}
	return fmt.Errorf("command not found")
}

// isCommandSuspicious checks for potentially malicious commands
func (h *TCPHandler) isCommandSuspicious(command string) bool {
	suspiciousPatterns := []string{
		"wget", "curl", "nc", "netcat", "bash", "sh", "python",
		"/dev/tcp", "/dev/udp", "base64",
		"eval", "exec", "system", "cmd.exe",
		"powershell", "download", "upload",
	}

	command = strings.ToLower(command)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}

	// Check for common exploit patterns
	exploitPatterns := []string{
		"${", "$(", "`", // Command injection
		"../", "/..", // Directory traversal
		"SELECT", "UNION", "INSERT", // SQL injection
		"<script>", "javascript:", // XSS
	}

	for _, pattern := range exploitPatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}

	return false
}

// analyzeSession analyzes the complete session for patterns
func (h *TCPHandler) analyzeSession(
	commands []string,
	timing []time.Duration,
	patterns map[string]int,
	suspicious []string,
) {
	// Calculate timing statistics
	var totalTime time.Duration
	for _, t := range timing {
		totalTime += t
	}
	avgTime := totalTime / time.Duration(len(timing))

	// Analyze command frequency
	mostFrequent := ""
	maxCount := 0
	for cmd, count := range patterns {
		if count > maxCount {
			maxCount = count
			mostFrequent = cmd
		}
	}

	// Log session analysis
	if tracker, ok := h.conn.(connectionTracker); ok {
		tracker.context.Metadata["session_analysis"] = map[string]interface{}{
			"total_commands":    len(commands),
			"unique_commands":   len(patterns),
			"avg_command_time":  avgTime,
			"most_frequent_cmd": mostFrequent,
			"suspicious_count":  len(suspicious),
			"command_variety":   float64(len(patterns)) / float64(len(commands)),
		}
	}
}
