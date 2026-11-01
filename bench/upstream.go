package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

var responseBody = bytes.Repeat([]byte("benchmark-data-"), 74)[:1024]

func upstreamHandler(defaultDelay time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set(originHeader, originValue)
		if req.URL.Path == "/ready" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if req.URL.Path != "/bench" && req.URL.Path != "/echo" {
			http.NotFound(w, req)
			return
		}
		delay := defaultDelay
		if raw := req.URL.Query().Get("delay"); raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed < 0 || parsed > 2*time.Second {
				http.Error(w, "invalid delay", 400)
				return
			}
			delay = parsed
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-req.Context().Done():
				return
			}
		}
		const limit = 32 << 20
		if req.URL.Path == "/echo" {
			body, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
			if err != nil || len(body) > limit {
				http.Error(w, "body limit", 413)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Write(body)
			return
		}
		read, err := io.Copy(io.Discard, io.LimitReader(req.Body, limit+1))
		if err != nil || read > limit {
			http.Error(w, "body limit", 413)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "1024")
		w.Write(responseBody)
	})
}

func runUpstream(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("upstream", flag.ContinueOnError)
	listen := flags.String("listen", ":8081", "local benchmark listen address")
	delay := flags.Duration("delay", 0, "default upstream delay")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *delay < 0 || *delay > 2*time.Second {
		return errors.New("delay must be between zero and 2s")
	}
	server := &http.Server{Handler: upstreamHandler(*delay), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}
