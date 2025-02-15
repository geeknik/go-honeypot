package services

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
)

// UDPHandler implements the Handler interface for UDP services
type UDPHandler struct {
	template    config.ServiceTemplate
	info        ServiceInfo
	responses   map[string][]config.Reply
	connections map[string]*udpConnection
	mu          sync.RWMutex
	cleanupTick time.Duration
}

// udpConnection tracks UDP connection behavior
type udpConnection struct {
	lastSeen      time.Time
	packetsRecv   int
	bytesRecv     int64
	bytesSent     int64
	warnings      []string
	packetTypes   map[string]int
	payloadHashes map[string]int
	timingData    []time.Duration
	metadata      map[string]interface{}
}

// NewUDPHandler creates a new UDP service handler
func NewUDPHandler(tmpl config.ServiceTemplate) (*UDPHandler, error) {
	responses := make(map[string][]config.Reply)

	// Initialize responses with template commands
	for cmd, reply := range tmpl.Commands {
		responses[cmd] = []config.Reply{reply}
	}

	handler := &UDPHandler{
		template:    tmpl,
		responses:   responses,
		connections: make(map[string]*udpConnection),
		cleanupTick: time.Minute * 5,
		info: ServiceInfo{
			Name:        tmpl.Name,
			Description: fmt.Sprintf("%s UDP service emulator", tmpl.Name),
			DefaultPort: tmpl.Port,
		},
	}

	go handler.periodicCleanup(context.Background())
	return handler, nil
}

// Handle processes UDP packets
func (h *UDPHandler) Handle(ctx context.Context, conn net.Conn) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("not a UDP connection")
	}

	buffer := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Set read deadline to prevent blocking forever
			if err := udpConn.SetReadDeadline(time.Now().Add(time.Second * 30)); err != nil {
				return fmt.Errorf("failed to set read deadline: %w", err)
			}

			n, remoteAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				if strings.Contains(err.Error(), "timeout") {
					return nil
				}
				return fmt.Errorf("failed to read UDP packet: %w", err)
			}

			// Process the packet
			if err := h.processPacket(ctx, udpConn, remoteAddr, buffer[:n]); err != nil {
				return fmt.Errorf("failed to process packet: %w", err)
			}
		}
	}
}

// processPacket handles individual UDP packets
func (h *UDPHandler) processPacket(ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr, data []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ipStr := addr.IP.String()

	// Update or create connection tracking
	connTrack, exists := h.connections[ipStr]
	if !exists {
		connTrack = &udpConnection{
			lastSeen:      time.Now(),
			packetTypes:   make(map[string]int),
			payloadHashes: make(map[string]int),
			timingData:    make([]time.Duration, 0),
			metadata:      make(map[string]interface{}),
		}
		h.connections[ipStr] = connTrack
	} else {
		// Calculate timing between packets
		timeSinceLastPacket := time.Since(connTrack.lastSeen)
		connTrack.timingData = append(connTrack.timingData, timeSinceLastPacket)
	}

	// Update connection stats
	connTrack.lastSeen = time.Now()
	connTrack.packetsRecv++
	connTrack.bytesRecv += int64(len(data))

	// Check for rate limiting
	if h.shouldRateLimit(connTrack) {
		connTrack.warnings = append(connTrack.warnings, "Rate limit exceeded")
		return nil
	}

	// Calculate payload hash for pattern detection
	payloadHash := fmt.Sprintf("%x", md5.Sum(data))
	connTrack.payloadHashes[payloadHash]++

	// Analyze packet for known protocols and patterns
	protocol, payload := h.analyzePacket(data)
	connTrack.packetTypes[protocol]++

	// Check for suspicious patterns
	if h.isPacketSuspicious(protocol, payload) {
		connTrack.warnings = append(connTrack.warnings, "Suspicious packet pattern detected")
	}

	// Get appropriate response
	response := h.getResponse(protocol, payload, connTrack)

	// Check response size to prevent amplification attacks
	if len(response.Response) > len(data)*4 {
		connTrack.warnings = append(connTrack.warnings, "Possible amplification attack attempt")
		response.Response = response.Response[:len(data)*4]
	}

	// Add realistic delay
	delay := time.Duration(rand.Intn(response.DelayMax-response.DelayMin)+response.DelayMin) * time.Millisecond
	time.Sleep(delay)

	// Send response
	responseData := []byte(response.Response)
	if _, err := conn.WriteToUDP(responseData, addr); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}
	connTrack.bytesSent += int64(len(responseData))

	// Update metadata
	connTrack.metadata["last_protocol"] = protocol
	connTrack.metadata["packet_count"] = connTrack.packetsRecv
	connTrack.metadata["unique_payloads"] = len(connTrack.payloadHashes)
	connTrack.metadata["protocol_distribution"] = connTrack.packetTypes

	// Analyze timing patterns
	if len(connTrack.timingData) > 1 {
		avgTiming := h.calculateAverageTiming(connTrack.timingData)
		connTrack.metadata["avg_packet_timing"] = avgTiming
	}

	return nil
}

// analyzePacket attempts to identify the protocol and extract payload
func (h *UDPHandler) analyzePacket(data []byte) (string, []byte) {
	if len(data) < 2 {
		return "unknown", data
	}

	// Check for DNS query (standard port 53)
	if len(data) > 12 && (data[2]&0x80 == 0) {
		return "dns", data
	}

	// Check for SNMP (standard port 161)
	if len(data) > 2 && data[0] == 0x30 {
		return "snmp", data
	}

	// Check for NTP (standard port 123)
	if len(data) >= 48 && (data[0]&0x38) == 0x00 {
		return "ntp", data
	}

	// Add more protocol detection as needed
	return "unknown", data
}

// shouldRateLimit checks if the connection should be rate limited
func (h *UDPHandler) shouldRateLimit(conn *udpConnection) bool {
	// Rate limit if more than 100 packets per minute
	packetsPerMinute := float64(conn.packetsRecv) / time.Since(conn.lastSeen).Minutes()
	if packetsPerMinute > 100 {
		return true
	}

	// Rate limit if more than 1MB per minute
	bytesPerMinute := float64(conn.bytesRecv) / time.Since(conn.lastSeen).Minutes()
	if bytesPerMinute > 1024*1024 {
		return true
	}

	return false
}

// getResponse returns an appropriate response for the protocol and payload
func (h *UDPHandler) getResponse(protocol string, payload []byte, conn *udpConnection) config.Reply {
	switch protocol {
	case "dns":
		return h.handleDNS(payload)
	case "snmp":
		return h.handleSNMP(payload)
	case "ntp":
		return h.handleNTP(payload)
	default:
		// Default response for unknown protocols
		return config.Reply{
			Response:  string(payload), // Echo back for unknown protocols
			DelayMin:  50,
			DelayMax:  150,
			CloseConn: false,
		}
	}
}

// handleDNS generates appropriate DNS responses
func (h *UDPHandler) handleDNS(payload []byte) config.Reply {
	// Basic DNS response structure
	response := make([]byte, len(payload))
	copy(response, payload)

	if len(payload) > 12 {
		// Set QR bit to indicate response
		response[2] |= 0x80
		// Set RA bit
		response[3] |= 0x80
	}

	return config.Reply{
		Response:  string(response),
		DelayMin:  20,
		DelayMax:  100,
		CloseConn: false,
	}
}

// handleSNMP generates SNMP responses
func (h *UDPHandler) handleSNMP(payload []byte) config.Reply {
	// Basic SNMP response
	return config.Reply{
		Response:  "\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa2\x19",
		DelayMin:  30,
		DelayMax:  120,
		CloseConn: false,
	}
}

// handleNTP generates NTP responses
func (h *UDPHandler) handleNTP(payload []byte) config.Reply {
	// Basic NTP response
	response := make([]byte, 48)
	response[0] = 0x1c // Version 3, Mode 4 (server)

	return config.Reply{
		Response:  string(response),
		DelayMin:  10,
		DelayMax:  50,
		CloseConn: false,
	}
}

// periodicCleanup removes old connection tracking entries
func (h *UDPHandler) periodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(h.cleanupTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			now := time.Now()
			for ip, conn := range h.connections {
				if now.Sub(conn.lastSeen) > h.cleanupTick {
					delete(h.connections, ip)
				}
			}
			h.mu.Unlock()
		}
	}
}

// GetServiceInfo returns information about the service
func (h *UDPHandler) GetServiceInfo() ServiceInfo {
	return h.info
}

// isPacketSuspicious checks for potentially malicious packet patterns
func (h *UDPHandler) isPacketSuspicious(protocol string, payload []byte) bool {
	// Check for common attack patterns
	suspiciousPatterns := [][]byte{
		[]byte{0x00, 0x00, 0x00, 0x00}, // Null bytes
		[]byte("eval"),                 // Code execution
		[]byte("system"),
		[]byte("cmd"),
		[]byte("powershell"),
	}

	for _, pattern := range suspiciousPatterns {
		if bytes.Contains(payload, pattern) {
			return true
		}
	}

	// Protocol-specific checks
	switch protocol {
	case "dns":
		return h.isDNSSuspicious(payload)
	case "ntp":
		return h.isNTPSuspicious(payload)
	case "snmp":
		return h.isSNMPSuspicious(payload)
	}

	return false
}

// isDNSSuspicious checks for suspicious DNS patterns
func (h *UDPHandler) isDNSSuspicious(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}

	// Check for DNS amplification attempt
	if payload[2]&0x80 == 0 && // Query
		bytes.Contains(payload, []byte{0x00, 0xff, 0x00, 0x00, 0x00, 0x01}) { // ANY query
		return true
	}

	// Check for DNS tunneling patterns
	if bytes.Count(payload, []byte(".")) > 10 {
		return true
	}

	return false
}

// isNTPSuspicious checks for suspicious NTP patterns
func (h *UDPHandler) isNTPSuspicious(payload []byte) bool {
	if len(payload) < 48 {
		return false
	}

	// Check for NTP amplification attempt
	if payload[0]&0x3f == 0x17 { // Mode 7 (private)
		return true
	}

	return false
}

// isSNMPSuspicious checks for suspicious SNMP patterns
func (h *UDPHandler) isSNMPSuspicious(payload []byte) bool {
	if len(payload) < 10 {
		return false
	}

	// Check for SNMP amplification attempt
	if payload[0] == 0x30 && // Sequence
		bytes.Contains(payload, []byte("public")) { // Default community
		return true
	}

	return false
}

// calculateAverageTiming calculates average time between packets
func (h *UDPHandler) calculateAverageTiming(timings []time.Duration) time.Duration {
	if len(timings) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range timings {
		total += t
	}
	return total / time.Duration(len(timings))
}
