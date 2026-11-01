package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type workload struct {
	name, method, contentType, encoding string
	body                                []byte
	status                              int
	origin                              bool
}

func makeWorkload(name string, padding int) (workload, error) {
	w := workload{name: name, method: http.MethodGet, status: 200, origin: true}
	switch name {
	case "get", "mixed":
	case "form":
		w.method, w.contentType = http.MethodPost, "application/x-www-form-urlencoded"
		w.body = []byte(url.Values{"title": {"benchmark"}, "items[]": {"one", "two"}, "payload": {strings.Repeat("v", padding)}}.Encode())
	case "multipart":
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.SetBoundary("benchmark-valid-multipart"); err != nil {
			return workload{}, err
		}
		for part := 0; part < 20; part++ {
			size := padding / 20
			if part < padding%20 {
				size++
			}
			if err := writer.WriteField("field"+strconv.Itoa(part), strings.Repeat("v", size)); err != nil {
				return workload{}, err
			}
		}
		if err := writer.Close(); err != nil {
			return workload{}, err
		}
		w.method, w.contentType, w.body = http.MethodPost, writer.FormDataContentType(), body.Bytes()
	case "malformed-multipart":
		w.method, w.contentType = http.MethodPost, "multipart/form-data; boundary=bench-boundary"
		w.body = []byte("--bench-boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nmissing closing delimiter\r\n")
		w.status, w.origin = 400, false
	case "progress":
		w.method, w.contentType = http.MethodPost, "multipart/form-data; boundary=bench-progress"
		w.body = []byte("--bench-progress\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nbenchmark\r\n--bench-progress--\r\n")
		w.status, w.origin = 403, false
	case "get-body":
		w.body, w.contentType, w.status, w.origin = []byte("forbidden-body"), "application/octet-stream", 400, false
	case "encoded":
		w.method, w.contentType, w.encoding = http.MethodPost, "application/octet-stream", "gzip"
		w.body, w.status, w.origin = []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 415, false
	default:
		return workload{}, fmt.Errorf("unknown workload %q", name)
	}
	return w, nil
}

type attempt struct {
	status             int
	origin, challenge  bool
	bytes              uint64
	err                error
	bodyErr, oversized bool
}

func perform(ctx context.Context, client *http.Client, target string, w workload) attempt {
	req, err := http.NewRequestWithContext(ctx, w.method, target, bytes.NewReader(w.body))
	if err != nil {
		return attempt{err: err}
	}
	req.Header.Set("User-Agent", "proxy-firewall-local-benchmark/1")
	if w.contentType != "" {
		req.Header.Set("Content-Type", w.contentType)
	}
	if w.encoding != "" {
		req.Header.Set("Content-Encoding", w.encoding)
	}
	resp, err := client.Do(req)
	if err != nil {
		return attempt{err: err}
	}
	defer resp.Body.Close()
	result := attempt{status: resp.StatusCode, origin: resp.Header.Get(originHeader) == originValue}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_X-SID_" && !result.origin {
			result.challenge = true
		}
	}
	const maxResponse = 4 << 20
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse+1))
	result.bytes, result.bodyErr, result.oversized = uint64(n), readErr != nil, n > maxResponse
	return result
}

type counters struct {
	requests, completed, failures, origin, challenges uint64
	bytesRead, payloadBytes                           uint64
	statuses                                          map[string]uint64
	errors                                            map[string]uint64
	workloads                                         map[string]uint64
	latency                                           histogram
}

func newCounters() counters {
	return counters{statuses: make(map[string]uint64), errors: make(map[string]uint64), workloads: make(map[string]uint64)}
}

func (c *counters) record(result attempt, w workload, elapsed time.Duration) {
	c.requests++
	c.workloads[w.name]++
	c.payloadBytes += uint64(len(w.body))
	c.bytesRead += result.bytes
	c.latency.add(elapsed)
	failed := false
	addError := func(name string) { c.errors[name]++; failed = true }
	if result.err != nil {
		var timeout net.Error
		if errors.As(result.err, &timeout) && timeout.Timeout() {
			addError("transport_timeout")
		} else {
			addError("transport_error")
		}
	} else {
		c.statuses[strconv.Itoa(result.status)]++
		if !result.bodyErr && !result.oversized {
			c.completed++
		}
		if result.origin {
			c.origin++
		}
		if result.challenge {
			c.challenges++
		}
		if result.bodyErr {
			addError("response_body_read_error")
		}
		if result.oversized {
			addError("response_too_large")
		}
		if result.status != w.status {
			addError("unexpected_status")
		}
		if w.origin && !result.origin {
			addError("origin_marker_missing")
		}
		if !w.origin && result.origin {
			addError("rejected_request_reached_origin")
		}
		if result.challenge {
			addError("challenge_during_measurement")
		}
	}
	if failed {
		c.failures++
	}
}

func (c *counters) merge(other *counters) {
	c.requests += other.requests
	c.completed += other.completed
	c.failures += other.failures
	c.origin += other.origin
	c.challenges += other.challenges
	c.bytesRead += other.bytesRead
	c.payloadBytes += other.payloadBytes
	for k, v := range other.statuses {
		c.statuses[k] += v
	}
	for k, v := range other.errors {
		c.errors[k] += v
	}
	for k, v := range other.workloads {
		c.workloads[k] += v
	}
	c.latency.merge(&other.latency)
}

type warmupSummary struct {
	Requests       uint64  `json:"requests"`
	Challenges     uint64  `json:"challenges"`
	CookieWorkers  int     `json:"cookie_workers"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

type report struct {
	Timestamp                    string            `json:"timestamp_utc"`
	Target                       string            `json:"target"`
	Workload                     string            `json:"workload"`
	Protocol                     string            `json:"protocol"`
	Concurrency                  int               `json:"concurrency"`
	RequestedDurationSeconds     float64           `json:"requested_duration_seconds"`
	ElapsedSeconds               float64           `json:"elapsed_seconds"`
	Warmup                       warmupSummary     `json:"warmup"`
	RequireChallenge             bool              `json:"require_challenge"`
	MaliciousPercent             int               `json:"configured_malicious_percent"`
	Requests                     uint64            `json:"requests"`
	Completed                    uint64            `json:"completed_responses"`
	Failures                     uint64            `json:"failed_requests"`
	OriginResponses              uint64            `json:"origin_responses"`
	Challenges                   uint64            `json:"measured_challenges"`
	RequestsPerSecond            float64           `json:"requests_per_second"`
	ResponseBodyBytes            uint64            `json:"response_body_bytes"`
	RequestPayloadBytesAttempted uint64            `json:"request_payload_bytes_attempted"`
	ResponseBodyBytesPerSecond   float64           `json:"response_body_bytes_per_second"`
	StatusCounts                 map[string]uint64 `json:"status_counts"`
	ErrorCounts                  map[string]uint64 `json:"error_counts"`
	WorkloadCounts               map[string]uint64 `json:"workload_counts"`
	Latency                      latencySummary    `json:"latency_all_requests"`
	Success                      bool              `json:"success"`
}

func warmup(ctx context.Context, clients []*http.Client, target *url.URL, requireChallenge bool, duration time.Duration) (warmupSummary, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var requests, challenges atomic.Uint64
	get, _ := makeWorkload("get", 0)
	call := func(client *http.Client) attempt {
		result := perform(ctx, client, target.String(), get)
		requests.Add(1)
		if result.challenge {
			challenges.Add(1)
		}
		return result
	}
	if requireChallenge {
		for ctx.Err() == nil {
			result := call(clients[0])
			if result.challenge {
				break
			}
			if result.err != nil {
				select {
				case <-ctx.Done():
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
		if challenges.Load() == 0 {
			return warmupSummary{}, errors.New("no cookie challenge observed during warmup; check DOS threshold and bypass configuration")
		}
	}
	var wg sync.WaitGroup
	var cookieWorkers atomic.Int32
	var failed atomic.Bool
	for _, client := range clients {
		wg.Add(1)
		go func(client *http.Client) {
			defer wg.Done()
			ready := false
			for ctx.Err() == nil {
				result := call(client)
				if result.err == nil && result.status == 200 && result.origin && !result.bodyErr {
					hasCookie := false
					for _, cookie := range client.Jar.Cookies(target) {
						if cookie.Name == "_X-SID_" {
							hasCookie = true
						}
					}
					if hasCookie {
						cookieWorkers.Add(1)
					}
					if !requireChallenge || hasCookie {
						ready = true
						break
					}
				}
				if result.err != nil {
					select {
					case <-ctx.Done():
					case <-time.After(20 * time.Millisecond):
					}
				}
			}
			if !ready {
				failed.Store(true)
				return
			}
			until := time.Now().Add(duration)
			for time.Now().Before(until) && ctx.Err() == nil {
				call(client)
			}
		}(client)
	}
	wg.Wait()
	summary := warmupSummary{Requests: requests.Load(), Challenges: challenges.Load(), CookieWorkers: int(cookieWorkers.Load()), ElapsedSeconds: time.Since(start).Seconds()}
	if failed.Load() {
		return summary, errors.New("warmup did not reach the origin with the required cookie for every worker")
	}
	return summary, nil
}

func runLoad(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("load", flag.ContinueOnError)
	targetFlag := flags.String("url", "http://firewall:8080/bench", "isolated local target")
	path := flags.String("path", "", "optional request path and query")
	name := flags.String("workload", "get", "get|form|multipart|mixed|malformed-multipart|progress|get-body|encoded")
	concurrency := flags.Int("concurrency", 64, "closed-loop worker count")
	duration := flags.Duration("duration", 15*time.Second, "measurement duration, excluding in-flight drain")
	warmupDuration := flags.Duration("warmup", 2*time.Second, "extra warmup per worker after cookie priming")
	timeout := flags.Duration("timeout", 5*time.Second, "per-request timeout")
	requireChallenge := flags.Bool("require-challenge", true, "require observed cookie challenge and prime every worker")
	caPath := flags.String("ca", "", "trust the disposable benchmark certificate")
	insecure := flags.Bool("insecure", false, "disable TLS verification for this benchmark only")
	output := flags.String("json", "-", "JSON artifact path, or - for stdout only")
	padding := flags.Int("form-bytes", 1024, "form payload bytes, before URL encoding overhead")
	malicious := flags.Int("malicious-percent", 15, "malicious request percentage for mixed workload")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *concurrency < 1 || *concurrency > 8192 || *duration <= 0 || *duration > time.Hour || *warmupDuration < 0 || *warmupDuration > 20*time.Second || *timeout <= 0 || *timeout > time.Minute || *padding < 0 || *padding > 32<<20 || *malicious < 0 || *malicious > 100 {
		return errors.New("invalid benchmark limits")
	}
	target, err := localTarget(*targetFlag)
	if err != nil {
		return err
	}
	if *path != "" {
		parsed, err := url.Parse(*path)
		if err != nil || !strings.HasPrefix(*path, "/") || parsed.Host != "" || parsed.Scheme != "" {
			return errors.New("path must be an absolute local request path")
		}
		target.Path, target.RawPath, target.RawQuery = parsed.Path, parsed.RawPath, parsed.RawQuery
	}
	if target.Path == "" || target.Path == "/" {
		target.Path = "/bench"
	}
	w, err := makeWorkload(*name, *padding)
	if err != nil {
		return err
	}
	rejects := make([]workload, 0, 4)
	for _, name := range []string{"malformed-multipart", "progress", "get-body", "encoded"} {
		reject, _ := makeWorkload(name, 0)
		rejects = append(rejects, reject)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: *insecure} // explicit benchmark flag
	if *caPath != "" {
		data, err := os.ReadFile(*caPath)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return errors.New("benchmark CA contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		DialContext:  (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: *concurrency * 2, MaxIdleConnsPerHost: *concurrency, MaxConnsPerHost: *concurrency,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: *timeout, TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression: true, ForceAttemptHTTP2: false, TLSClientConfig: tlsConfig,
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	defer transport.CloseIdleConnections()
	clients := make([]*http.Client, *concurrency)
	for i := range clients {
		jar, _ := cookiejar.New(nil)
		clients[i] = &http.Client{Transport: transport, Jar: jar, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	warm, err := warmup(ctx, clients, target, *requireChallenge, *warmupDuration)
	if err != nil {
		return err
	}
	results := make([]counters, *concurrency)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	var end time.Time
	for worker, client := range clients {
		results[worker] = newCounters()
		wg.Add(1)
		go func(worker int, client *http.Client) {
			defer wg.Done()
			<-gate
			for iteration := 0; time.Now().Before(end) && ctx.Err() == nil; iteration++ {
				selected := w
				if *name == "mixed" {
					selected.name = "get"
					if (iteration+worker*17)%100 < *malicious {
						selected = rejects[(iteration/100+worker)%len(rejects)]
					}
				}
				started := time.Now()
				result := perform(ctx, client, target.String(), selected)
				results[worker].record(result, selected, time.Since(started))
			}
		}(worker, client)
	}
	started := time.Now()
	end = started.Add(*duration)
	close(gate)
	wg.Wait()
	elapsed := time.Since(started).Seconds()
	total := newCounters()
	for i := range results {
		total.merge(&results[i])
	}
	result := report{
		Timestamp: started.UTC().Format(time.RFC3339Nano), Target: target.String(), Workload: *name, Protocol: "HTTP/1.1", Concurrency: *concurrency,
		RequestedDurationSeconds: duration.Seconds(), ElapsedSeconds: elapsed, Warmup: warm, RequireChallenge: *requireChallenge, MaliciousPercent: *malicious,
		Requests: total.requests, Completed: total.completed, Failures: total.failures, OriginResponses: total.origin, Challenges: total.challenges,
		RequestsPerSecond: float64(total.requests) / elapsed, ResponseBodyBytes: total.bytesRead, RequestPayloadBytesAttempted: total.payloadBytes,
		ResponseBodyBytesPerSecond: float64(total.bytesRead) / elapsed, StatusCounts: total.statuses, ErrorCounts: total.errors, WorkloadCounts: total.workloads,
		Latency: total.latency.summary(), Success: total.requests > 0 && total.failures == 0,
	}
	if err := writeReport(*output, result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("%d of %d measured requests failed validation", result.Failures, result.Requests)
	}
	return nil
}

func writeReport(path string, result report) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path != "-" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".benchmark-*.json")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if _, err = file.Write(data); err != nil {
			file.Close()
			return err
		}
		if err = file.Chmod(0644); err != nil {
			file.Close()
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
		if err = os.Rename(file.Name(), path); err != nil {
			return err
		}
	}
	_, err = os.Stdout.Write(data)
	return err
}
