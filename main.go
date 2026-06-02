package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socks5Version = 0x05
	authNone      = 0x00
	authUserPass  = 0x02
	authNoMethods = 0xFF

	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
)

func main() {
	// R6: Accept a -port flag for the listen port (default: 1080)
	port := flag.Int("port", 1080, "Port to listen on")
	flag.Parse()

	// R7: Read authentication credentials from environment variables
	reqUser := os.Getenv("PROXY_USER")
	reqPass := os.Getenv("PROXY_PASS")

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	log.Printf("SOCKS5 proxy listening on :%d", *port)
	if reqUser != "" {
		log.Printf("Authentication required (User: %s)", reqUser)
	} else {
		log.Printf("No authentication required")
	}

	// Accept incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		// R4: Handle concurrent connections using goroutines
		go handleConnection(conn, reqUser, reqPass)
	}
}

// handleConnection orchestrates the SOCKS5 lifecycle for a single client.
func handleConnection(conn net.Conn, reqUser, reqPass string) {
	defer conn.Close()

	// Step 1 & 2: Negotiate Auth
	if err := negotiateAuth(conn, reqUser, reqPass); err != nil {
		log.Printf("Auth failed: %v", err)
		return
	}

	// Step 3 & 4: Read CONNECT request and Dial target
	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("Connect request failed: %v", err)
		return
	}
	defer target.Close()

	// Step 5: Relay data
	relay(conn, target)
}

// negotiateAuth handles the client greeting and selects the auth method.
func negotiateAuth(conn net.Conn, reqUser, reqPass string) error {
	header := make([]byte, 2) // VER, NMETHODS
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// R8: Determine required auth method based on env vars
	requiresAuth := reqUser != ""
	acceptableMethod := authNone
	if requiresAuth {
		acceptableMethod = authUserPass
	}

	// Check if client offered our acceptable method
	methodFound := false
	for _, m := range methods {
		if m == byte(acceptableMethod) {
			methodFound = true
			break
		}
	}

	if !methodFound {
		if _, err := conn.Write([]byte{socks5Version, authNoMethods}); err != nil {
			return fmt.Errorf("failed to write no-methods response: %w", err)
		}
		return fmt.Errorf("client did not offer acceptable auth method")
	}

	// Send method selection reply
	if _, err := conn.Write([]byte{socks5Version, byte(acceptableMethod)}); err != nil {
		return fmt.Errorf("failed to write method selection: %w", err)
	}

	// Sub-negotiation for Username/Password if required
	if requiresAuth {
		return authenticateUserPass(conn, reqUser, reqPass)
	}
	return nil
}

// authenticateUserPass handles RFC 1929 username/password sub-negotiation.
func authenticateUserPass(conn net.Conn, reqUser, reqPass string) error {
	header := make([]byte, 2) // VER, ULEN
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	uLen := int(header[1])
	uName := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uName); err != nil {
		return err
	}

	pLenBuf := make([]byte, 1) // PLEN
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}
	pLen := int(pLenBuf[0])
	pass := make([]byte, pLen)
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	// Validate credentials
	if string(uName) == reqUser && string(pass) == reqPass {
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return fmt.Errorf("failed to write auth success: %w", err)
		}
		return nil
	}

	if _, err := conn.Write([]byte{0x01, 0x01}); err != nil {
		return fmt.Errorf("failed to write auth failure: %w", err)
	}
	return fmt.Errorf("invalid credentials provided")
}

// handleConnect processes the client's destination request and dials the target.
func handleConnect(conn net.Conn) (net.Conn, error) {
	reqHeader := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return nil, err
	}
	if reqHeader[0] != socks5Version {
		return nil, fmt.Errorf("unsupported version in connect request")
	}

	// R1: Support CONNECT command only
	if reqHeader[1] != cmdConnect {
		sendErrorReply(conn, 0x07) // Command not supported
		return nil, fmt.Errorf("unsupported command: %d", reqHeader[1])
	}

	// Validating the Reserved byte
	if reqHeader[2] != 0x00 {
		sendErrorReply(conn, 0x01) // General SOCKS server failure
		return nil, fmt.Errorf("invalid reserved byte: 0x%02x", reqHeader[2])
	}

	atyp := reqHeader[3]
	var targetAddr string

	// R3: Parse Address Type (IPv4 or Domain)
	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			return nil, err
		}
		port := binary.BigEndian.Uint16(portBuf)
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			return nil, err
		}
		port := binary.BigEndian.Uint16(portBuf)
		targetAddr = fmt.Sprintf("%s:%d", string(domain), port)

	default:
		sendErrorReply(conn, 0x08) // Address type not supported
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Dial the target server
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendErrorReply(conn, 0x05) // Connection refused
		return nil, err
	}

	// Send successful reply (using all zeros for BND.ADDR and BND.PORT as permitted)
	successReply := []byte{socks5Version, 0x00, 0x00, atypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(successReply); err != nil {
		target.Close() // Cleanup the dialed connection if we fail to reply to the client
		return nil, fmt.Errorf("failed to write success reply: %w", err)
	}

	return target, nil
}

// relay manages bidirectional data transfer between the client and target.
func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from Target -> Client
	go func() {
		defer wg.Done()
		io.Copy(client, target)
		// Signal EOF by closing the write half of the client connection
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Copy from Client -> Target
	go func() {
		defer wg.Done()
		io.Copy(target, client)
		// Signal EOF by closing the write half of the target connection
		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait() // Wait for both streams to finish
}

// sendErrorReply is a helper to format and send a SOCKS5 error code.
func sendErrorReply(conn net.Conn, repCode byte) {
	// Best effort write, ignoring the error since we are already actively failing a request
	conn.Write([]byte{socks5Version, repCode, 0x00, atypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}