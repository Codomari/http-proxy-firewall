package proxy

import (
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSUpstreamVerifiesCertificateAuthorities(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Host != "private.example" || r.RequestURI != "/secure%2fpath?q=%2f" {
			t.Errorf("TLS upstream request = %q %q TLS=%v", r.Host, r.RequestURI, r.TLS != nil)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "secure upstream")
	}))
	defer upstream.Close()
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	for _, trusted := range []bool{false, true} {
		name := "untrusted"
		if trusted {
			name = "trusted"
		}
		t.Run(name, func(t *testing.T) {
			address, handler := frontend(t, testConfig(upstream.URL))
			if trusted {
				// Test-only CA injection before the first request. Production uses
				// the system trust store and never disables certificate checking.
				roots := x509.NewCertPool()
				roots.AddCert(upstream.Certificate())
				handler.client.TLSConfig.RootCAs = roots
			}
			request, _ := http.NewRequest(http.MethodGet, address+"/secure%2fpath?q=%2f", nil)
			request.Host = "private.example"
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if trusted {
				if response.StatusCode != http.StatusCreated || string(body) != "secure upstream" {
					t.Errorf("trusted upstream = %d %q", response.StatusCode, body)
				}
			} else if response.StatusCode != http.StatusBadGateway {
				t.Errorf("untrusted upstream status = %d; want 502", response.StatusCode)
			}
		})
	}
}
