package server

import (
	"net"
	"net/netip"
	"strings"
)

// net/http's HTTP/2 logger writes through the same sampled structured logger as
// fasthttp. Do not change the process-wide standard logger.
type http2LogWriter struct{ server *Server }

func (writer *http2LogWriter) Write(data []byte) (int, error) {
	message := strings.TrimSpace(string(data))
	var remote net.Addr
	for _, prefix := range []string{"http2: server: error reading preface from client ", "http2: server connection error from ", "http2: server closing client connection; error reading frame from client ", "http2: panic serving ", "timeout waiting for SETTINGS frames from "} {
		if !strings.HasPrefix(message, prefix) {
			continue
		}
		field, _, _ := strings.Cut(strings.TrimPrefix(message, prefix), " ")
		if address, err := netip.ParseAddrPort(strings.TrimSuffix(field, ":")); err == nil {
			remote = net.TCPAddrFromAddrPort(address)
		}
		break
	}
	logger := writer.server.app.Server().Logger
	if remote == nil {
		logger.Printf("%s", message)
		return len(data), nil
	}
	var local net.Addr
	writer.server.mu.Lock()
	for conn := range writer.server.h2Conns {
		if conn.RemoteAddr().String() == remote.String() {
			local = conn.LocalAddr()
			break
		}
	}
	writer.server.mu.Unlock()
	logger.Printf("error when serving connection %q<->%q: %v", local, remote, message)
	return len(data), nil
}
