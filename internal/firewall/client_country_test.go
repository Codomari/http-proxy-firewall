package firewall

import (
	"context"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
)

type addressCountryIntelligence struct{}

func (addressCountryIntelligence) Country(_ context.Context, address netip.Addr) string {
	return address.String()
}
func (addressCountryIntelligence) IsGoogleBot(netip.Addr) bool { return false }

func TestClientCountryBeforeFirewallUsesVerifiedAddress(t *testing.T) {
	for _, tc := range []struct {
		peer    string
		trusted []string
		want    string
	}{
		{"198.51.100.1", nil, "198.51.100.1"},
		{"10.0.0.2", []string{"10.0.0.0/8"}, "203.0.113.9"},
	} {
		cfg := testConfig()
		cfg.Firewall.TrustedProxies = tc.trusted
		e := testEngine(t, cfg, addressCountryIntelligence{})
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error { return c.SendString(e.ClientCountry(c)) })
		ctx := serve(t, app, e, rawRequest("GET", "/", "", nil, false, "X-Forwarded-For: 203.0.113.9\r\n"), tc.peer)
		if string(ctx.Response.Body()) != tc.want {
			t.Fatalf("country lookup address=%s want=%s", ctx.Response.Body(), tc.want)
		}
	}
}
