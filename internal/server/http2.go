package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/http2"
)

func (s *Server) configureHTTP2(fast *fasthttp.Server) {
	s.h2Base = &http.Server{
		ReadTimeout: s.cfg.HTTP.ReadTimeout, WriteTimeout: s.cfg.HTTP.WriteTimeout,
		IdleTimeout: s.cfg.HTTP.IdleTimeout, MaxHeaderBytes: 4096,
		ErrorLog: log.New(&http2LogWriter{server: s}, "", 0),
	}
	s.h2Conns = make(map[net.Conn]struct{})
	h2 := &http2.Server{MaxConcurrentStreams: uint32(min(s.cfg.HTTP.MaxConcurrentRequests, 1<<31-1)), IdleTimeout: s.cfg.HTTP.IdleTimeout}
	if err := http2.ConfigureServer(s.h2Base, h2); err != nil {
		panic(fmt.Sprintf("configure HTTP/2: %v", err))
	}
	// fasthttp dispatches ALPN before parsing HTTP/1, preserving its existing
	// HTTP/1 streaming/upgrades and connection admission on the same listener.
	fast.NextProto("h2", func(conn net.Conn) error {
		s.mu.Lock()
		if s.h2Stopping {
			s.mu.Unlock()
			_ = conn.Close()
			return nil
		}
		s.h2Conns[conn] = struct{}{}
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.h2Conns, conn)
			s.mu.Unlock()
			s.hostnames.Delete(connectionKey(conn.LocalAddr(), conn.RemoteAddr()))
		}()
		if state, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			s.rememberHostname(conn.LocalAddr(), conn.RemoteAddr(), state.ConnectionState().ServerName)
		}
		// With Go 1.27, passing BaseConfig clones the configured http.Server;
		// omit it so all connections share the server registered for shutdown.
		h2.ServeConn(conn, &http2.ServeConnOpts{Context: context.Background(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handleHTTP2(conn, w, r)
		})})
		return nil
	})
}

func (s *Server) handleHTTP2(conn net.Conn, writer http.ResponseWriter, request *http.Request) {
	control := http.NewResponseController(writer)
	if s.cfg.HTTP.ReadTimeout > 0 {
		_ = control.SetReadDeadline(time.Now().Add(s.cfg.HTTP.ReadTimeout))
	}
	if s.cfg.HTTP.WriteTimeout > 0 {
		_ = control.SetWriteDeadline(time.Now().Add(s.cfg.HTTP.WriteTimeout))
	}
	ctx := new(fasthttp.RequestCtx)
	ctx.Init2(conn, s.app.Server().Logger, false)
	defer func() { ctx.Response.Reset(); ctx.Request.Reset(); ctx.ResetUserValues() }()
	ctx.Request.Header.SetMethod(request.Method)
	ctx.Request.SetRequestURI(request.RequestURI)
	for name, values := range request.Header {
		for _, value := range values {
			ctx.Request.Header.Add(name, value)
		}
	}
	ctx.Request.Header.SetHost(request.Host)
	// HTTP/2 framing is already validated by x/net/http2. Fiber's internal
	// request representation accepts HTTP/1 versions; retain that representation.
	ctx.Request.Header.SetProtocol("HTTP/1.1")
	size := int(request.ContentLength)
	if int64(size) != request.ContentLength {
		c := s.app.AcquireCtx(ctx)
		_ = s.serveRequestTooLarge(c, s.bodyLimit(), false)
		s.app.ReleaseCtx(c)
	} else {
		ctx.Request.SetBodyStream(request.Body, size)
		// Reuse the same firewall, admin, metrics, body budgets and proxy routes.
		s.app.Server().Handler(ctx)
	}
	response := &ctx.Response
	response.Header.VisitAll(func(name, value []byte) {
		switch strings.ToLower(string(name)) {
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			return
		}
		writer.Header().Add(string(name), string(value))
	})
	writer.WriteHeader(response.StatusCode())
	stream := response.BodyStream()
	if response.ImmediateHeaderFlush {
		_ = control.Flush()
	}
	var writeErr error
	if !response.SkipBody && request.Method != http.MethodHead && response.StatusCode() != 204 && response.StatusCode() != 304 {
		if stream != nil {
			_, writeErr = io.Copy(http2StreamWriter{ResponseWriter: writer, control: control}, stream)
		} else {
			_, writeErr = writer.Write(response.Body())
		}
	}
	if closer, ok := stream.(fasthttp.ReadCloserWithError); ok {
		_ = closer.CloseWithError(writeErr)
	}
	_ = response.CloseBodyStream()
	if writeErr != nil {
		panic(http.ErrAbortHandler)
	}
}

type http2StreamWriter struct {
	http.ResponseWriter
	control *http.ResponseController
}

func (w http2StreamWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil {
		err = w.control.Flush()
	}
	return n, err
}
