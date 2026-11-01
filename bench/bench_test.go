package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPrimesWorkerCookiesAndCountsOriginResponses(t *testing.T) {
	upstream := upstreamHandler(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if cookie, err := req.Cookie("_X-SID_"); err != nil || cookie.Value != "valid" {
			http.SetCookie(w, &http.Cookie{Name: "_X-SID_", Value: "valid", Path: "/"})
			io.WriteString(w, "<meta http-equiv=refresh content=0>")
			return
		}
		upstream.ServeHTTP(w, req)
	}))
	defer server.Close()
	artifact := filepath.Join(t.TempDir(), "result.json")
	if err := runLoad(context.Background(), []string{"--url", server.URL + "/bench", "--concurrency", "4", "--duration", "50ms", "--warmup", "0s", "--json", artifact}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var result report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Requests == 0 || result.Requests != result.Completed || result.Requests != result.OriginResponses || result.StatusCounts["200"] != result.Requests || result.Failures != 0 {
		t.Fatalf("bad measurement: %+v", result)
	}
	if result.Warmup.CookieWorkers != 4 || result.Warmup.Challenges < 4 || result.Challenges != 0 {
		t.Fatalf("cookies not primed: %+v", result.Warmup)
	}
	if result.ResponseBodyBytes != result.Requests*1024 || result.Latency.P50MS <= 0 {
		t.Fatal("incorrect body/latency accounting")
	}
}

func TestLoadDirectBackendCalibrationAndEcho(t *testing.T) {
	server := httptest.NewServer(upstreamHandler(0))
	defer server.Close()
	artifact := filepath.Join(t.TempDir(), "direct.json")
	if err := runLoad(context.Background(), []string{"--url", server.URL + "/bench", "--concurrency", "2", "--duration", "20ms", "--warmup", "0s", "--require-challenge=false", "--json", artifact}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(server.URL+"/echo", "application/x-www-form-urlencoded", strings.NewReader("hello=world"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "hello=world" || resp.Header.Get(originHeader) != originValue {
		t.Fatal("echo did not preserve body/origin")
	}
}

func TestWarmupRejectsAnUnchallengedBypass(t *testing.T) {
	server := httptest.NewServer(upstreamHandler(0))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := runLoad(ctx, []string{"--url", server.URL + "/bench", "--concurrency", "1", "--duration", "1ms", "--warmup", "0s"})
	if err == nil || !strings.Contains(err.Error(), "no cookie challenge") {
		t.Fatalf("bypass accepted: %v", err)
	}
}

func TestResponseValidationCountsFailedRequestsOnce(t *testing.T) {
	c := newCounters()
	w, _ := makeWorkload("get", 0)
	c.record(attempt{status: 503}, w, time.Millisecond)
	if c.failures != 1 || c.errors["unexpected_status"] != 1 || c.errors["origin_marker_missing"] != 1 || c.statuses["503"] != 1 {
		t.Fatal("bad multi-error counting")
	}
	reject, _ := makeWorkload("progress", 0)
	c.record(attempt{status: 403, origin: true}, reject, time.Millisecond)
	if c.errors["rejected_request_reached_origin"] != 1 || c.failures != 2 {
		t.Fatal("forwarded rejection accepted")
	}
}

func TestHistogramPercentilesAndMerge(t *testing.T) {
	var one, two histogram
	for i := 1; i <= 100; i++ {
		if i <= 50 {
			one.add(time.Duration(i) * time.Millisecond)
		} else {
			two.add(time.Duration(i) * time.Millisecond)
		}
	}
	one.merge(&two)
	for _, testcase := range []struct{ p, want float64 }{{.5, 50}, {.95, 95}, {.99, 99}} {
		got := one.percentile(testcase.p)
		if got < testcase.want || got > testcase.want*1.016 {
			t.Fatalf("percentile %v = %v, want %v", testcase.p, got, testcase.want)
		}
	}
	if one.count != 100 || one.summary().MeanMS != 50.5 {
		t.Fatal("bad merge")
	}
}

func TestLocalOnlyTargets(t *testing.T) {
	for _, target := range []string{"https://example.com/", "http://8.8.8.8/", "http://user:pass@firewall/", "file:///tmp/test", "http://firewall.example/"} {
		if _, err := localTarget(target); err == nil {
			t.Fatalf("external target allowed: %s", target)
		}
	}
	for _, target := range []string{"http://firewall:8080/bench", "https://backend:8443/", "http://127.0.0.1/", "http://[::1]/", "http://10.1.2.3/"} {
		if _, err := localTarget(target); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDisposableCertificateSANAndExplicitVolumePermissions(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	args := []string{"--cert", certPath, "--key", keyPath}
	if err := runCert(args); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.Leaf.VerifyHostname("firewall"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unexpected private-key permissions")
	}
	if err := runCert(append(args, "--key-mode", "0644")); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(keyPath)
	if info.Mode().Perm() != 0644 {
		t.Fatal("explicit disposable-volume key permissions not applied")
	}
}

func TestCertificateReusePreservesPairAndDefaultStillRotates(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	args := []string{"--cert", certPath, "--key", keyPath}
	if err := runCert(append(args, "--reuse")); err != nil {
		t.Fatal(err)
	}
	beforeCert, _ := os.ReadFile(certPath)
	beforeKey, _ := os.ReadFile(keyPath)
	if err := runCert(append(args, "--reuse")); err != nil {
		t.Fatal(err)
	}
	afterCert, _ := os.ReadFile(certPath)
	afterKey, _ := os.ReadFile(keyPath)
	if string(beforeCert) != string(afterCert) || string(beforeKey) != string(afterKey) {
		t.Fatal("reuse rotated the certificate pair")
	}
	if err := runCert(args); err != nil {
		t.Fatal(err)
	}
	rotated, _ := os.ReadFile(certPath)
	if string(rotated) == string(beforeCert) {
		t.Fatal("default certificate command did not generate a new pair")
	}
	if err := os.WriteFile(keyPath, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runCert(append(args, "--reuse")); err == nil {
		t.Fatal("reuse silently replaced malformed existing pair")
	}
}

func TestLegitimateMultipartContainsTwentyRegularFields(t *testing.T) {
	for _, padding := range []int{0, 1024, 1031} {
		w, err := makeWorkload("multipart", padding)
		if err != nil {
			t.Fatal(err)
		}
		if w.method != http.MethodPost || w.status != 200 || !w.origin {
			t.Fatal("multipart workload has wrong expected behavior")
		}
		media, params, err := mime.ParseMediaType(w.contentType)
		if err != nil || media != "multipart/form-data" {
			t.Fatal("invalid multipart media type")
		}
		reader := multipart.NewReader(strings.NewReader(string(w.body)), params["boundary"])
		count, total := 0, 0
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if part.FormName() == "" || part.FileName() != "" {
				t.Fatal("multipart part is not a regular form field")
			}
			value, err := io.ReadAll(part)
			if err != nil {
				t.Fatal(err)
			}
			total += len(value)
			count++
		}
		if count != 20 || total != padding {
			t.Fatalf("multipart parts=%d, values=%d, wanted20/%d", count, total, padding)
		}
	}
}
