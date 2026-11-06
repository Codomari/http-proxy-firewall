package admin

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCertificateAPIsRequireAuthenticationAndMutationHeader(t *testing.T) {
	app, _ := adminTestApp(t, true)
	for _, tt := range []struct {
		method, path, site, auth, header string
		status                           int
	}{
		{"GET", "/api/certificates", "", "", "", 401},
		{"GET", "/api/certbot-blacklist", "", "", "", 401},
		{"GET", "/api/certbot-blacklist", "", validBasic(), "", 200},
		{"GET", "/api/certificates", "", validBasic(), "", 200},
		{"DELETE", "/api/certbot-blacklist?hostname=site.example", "", validBasic(), "", 403},
		{"DELETE", "/api/certbot-blacklist?hostname=site.example", "cross-site", validBasic(), "1", 403},
		{"POST", "/api/certificates?hostname=site.example", "", validBasic(), "", 403},
		{"POST", "/api/certificates?hostname=site.example", "cross-site", validBasic(), "1", 403},
		{"DELETE", "/api/certbot-blacklist?hostname=127.0.0.1", "", validBasic(), "1", 400},
		{"DELETE", "/api/certbot-blacklist?hostname=site.example:80", "", validBasic(), "1", 400},
		{"PUT", "/api/certificates", "", validBasic(), "1", 405},
	} {
		r := httptest.NewRequest(tt.method, "http://admin.example"+BasePath+tt.path, nil)
		r.Header.Set("Authorization", tt.auth)
		r.Header.Set("X-PF-Admin", tt.header)
		r.Header.Set("Sec-Fetch-Site", tt.site)
		response, err := app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tt.status || strings.Contains(string(body), "PRIVATE KEY") {
			t.Fatalf("%s %s status=%d want=%d", tt.method, tt.path, response.StatusCode, tt.status)
		}
	}
}
