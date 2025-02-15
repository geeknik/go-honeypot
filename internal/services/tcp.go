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

	"github.com/yourusername/go-honeypot/internal/config"
)

// TCPHandler implements the Handler interface for TCP services
type TCPHandler struct {
	template  config.ServiceTemplate
	info      ServiceInfo
	responses map[string][]config.Reply
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
					return nil
				}
				return fmt.Errorf("failed to read command: %w", err)
			}

			command = strings.TrimSpace(command)
			sessionData = append(sessionData, command)

			// Handle empty command
			if command == "" {
				continue
			}

			// Get base command (first word)
			baseCmd := strings.Fields(command)[0]
			baseCmd = strings.ToUpper(baseCmd)

			// Get response for command
			response := h.getResponse(baseCmd, sessionData)

			// Send response
			if err := h.sendWithDelay(conn, response.Response); err != nil {
				return fmt.Errorf("failed to send response: %w", err)
			}

			// Close connection if specified in response
			if response.CloseConn {
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
