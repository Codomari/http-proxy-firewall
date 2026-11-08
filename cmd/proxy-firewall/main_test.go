package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"http-proxy-firewall/internal/config"
)

func init() {
	if os.Getenv("PF_TEST_MAIN_HELPER") == "1" {
		os.Args = []string{os.Args[0]}
		main()
	}
}

func TestAdminRestartReexecutesWithFreshYAMLAndNoUnnecessaryRestart(t *testing.T) {
	root := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(backend.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	values := map[string]string{
		"PF_LISTEN": address, "PF_TLS_ENABLED": "false", "PF_PROXY_TO": backend.URL, "PF_IPV4_REDIRECT": "",
		"PF_PPROF_ADDRESS": "", "PF_GOOGLE_RANGES_URL": "", "PF_ADMIN_ENABLED": "true", "PF_ADMIN_CREDS_FILE": ".creds",
		"GOGC": "100", "GOMEMLIMIT": "off",
	}
	var document config.Document
	for key, value := range values {
		document.Env = append(document.Env, config.EnvEntry{Key: key, Value: value})
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.DefaultYAML), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".creds"), []byte("operator:restart-test-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(root, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	command := exec.Command(os.Args[0])
	command.Dir, command.Stdout, command.Stderr = root, log, log
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PF_") || strings.HasPrefix(key, "IP_FILTER_") || strings.HasPrefix(key, "CVE_MITIGATOR_") || key == "GOGC" || key == "GOMEMLIMIT" {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "PF_TEST_MAIN_HELPER=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("application exited: %v", err)
			}
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("application failed to stop gracefully")
		}
	})
	client := &http.Client{Timeout: time.Second}
	base := "http://" + address + "/__pf/__admin"
	call := func(method, path string, payload []byte) (*http.Response, []byte, error) {
		r, _ := http.NewRequest(method, base+path, bytes.NewReader(payload))
		r.SetBasicAuth("operator", "restart-test-password")
		r.Header.Set("X-PF-Admin", "1")
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		return response, data, err
	}
	type overview struct {
		Runtime struct {
			MemoryLimit int64 `json:"gc_memory_limit_bytes"`
		} `json:"runtime"`
		Restart struct{ Required, Restarting bool } `json:"restart"`
	}
	await := func(limit int64) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			response, data, err := call("GET", "/api/overview", nil)
			var state overview
			if err == nil && response.StatusCode == 200 && json.Unmarshal(data, &state) == nil && state.Runtime.MemoryLimit == limit && !state.Restart.Required && !state.Restart.Restarting {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		logData, _ := os.ReadFile(filepath.Join(root, "process.log"))
		t.Fatalf("application did not reach expected memory limit %d: %s", limit, logData)
	}
	await(math.MaxInt64)
	response, data, err := call("POST", "/api/restart", nil)
	if err != nil || response.StatusCode != 200 || !bytes.Contains(data, []byte(`"required":false`)) {
		t.Fatalf("unnecessary restart was accepted: %v %s", err, data)
	}
	_, data, err = call("GET", "/api/general-rules", nil)
	if err != nil {
		t.Fatal(err)
	}
	var settings config.GeneralRules
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings.GCPercent, settings.GCMemoryLimit = 50, "128MiB"
	payload, _ := json.Marshal(settings)
	response, data, err = call("POST", "/api/general-rules", payload)
	if err != nil || response.StatusCode != 200 || !bytes.Contains(data, []byte(`"required":true`)) {
		t.Fatalf("GC save did not require restart: %v %s", err, data)
	}
	_, data, err = call("GET", "/api/runtime", nil)
	var state overview
	if err != nil || json.Unmarshal(data, &state) != nil || state.Runtime.MemoryLimit != math.MaxInt64 {
		t.Fatal("GC limit changed before restart")
	}
	response, data, err = call("POST", "/api/restart", nil)
	if err != nil || response.StatusCode != 202 {
		t.Fatalf("restart request failed: %v %s", err, data)
	}
	await(128 << 20)
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("restart did not preserve the process")
	}
	response, data, err = call("POST", "/api/restart", nil)
	if err != nil || response.StatusCode != 200 || !bytes.Contains(data, []byte(`"required":false`)) {
		t.Fatalf("restart flag did not clear: %v %s", err, data)
	}
}
