package firewall

import "testing"

func TestCertificateCloudflareRulesUseExistingPrecedence(t *testing.T) {
	e := new(Engine)
	e.cloudflare.rules.Store(&cloudflareRules{hosts: map[string]bool{"example.com": true, "*.example.com": true, "direct.example.com": false}})
	for _, tt := range []struct {
		host string
		want bool
	}{
		{"example.com", true}, {"WWW.EXAMPLE.COM.", true}, {"deep.sub.example.com", true}, {"direct.example.com", false}, {"other.example", false},
	} {
		if got := e.BehindCloudflare(tt.host); got != tt.want {
			t.Errorf("%s behind Cloudflare=%v want=%v", tt.host, got, tt.want)
		}
	}
	e.cloudflare.rules.Store(&cloudflareRules{hosts: map[string]bool{}})
	if e.BehindCloudflare("example.com") {
		t.Fatal("Cloudflare rule removal did not apply immediately")
	}
}
