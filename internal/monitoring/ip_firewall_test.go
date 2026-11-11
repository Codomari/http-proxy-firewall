package monitoring

import (
	"sync"
	"testing"

	"http-proxy-firewall/internal/config"

	"github.com/gofiber/fiber/v3"
)

func TestEarlyIPFirewallCountersRespectCapacityAndCountOnce(t *testing.T) {
	r := testRegistry(1)
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		r.RecordIPFirewallRejection(c, normalizeTestHost)
		r.RecordIPFirewallRejection(c, normalizeTestHost)
		return nil
	})
	handler := app.Handler()
	handler(requestContext("one.example", "/"))
	handler(requestContext("two.example", "/"))
	handler(requestContext("", "/"))
	totals, hosts := r.Totals(), r.Hosts()
	if totals.IPFirewallRejected != 3 || totals.Requests != 3 || totals.UntrackedRequests != 2 || totals.Rejected != 3 || totals.Errors5xx != 0 || totals.InFlight != 0 || len(hosts) != 1 || hosts[0].IPFirewallRejected != 1 || hosts[0].Requests != 1 || hosts[0].BytesIn != 0 || hosts[0].BytesOut != 0 || hosts[0].LastSeen.IsZero() {
		t.Fatalf("early 444 accounting: totals=%+v hosts=%+v", totals, hosts)
	}
}

func TestConcurrentEarlyIPFirewallCountersAndSnapshots(t *testing.T) {
	r := testRegistry(8)
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error { r.RecordIPFirewallRejection(c, normalizeTestHost); return nil })
	handler := app.Handler()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				handler(requestContext("one.example", "/"))
				r.Hosts()
				r.Totals()
			}
		})
	}
	wg.Wait()
	if totals, hosts := r.Totals(), r.Hosts(); totals.IPFirewallRejected != 800 || totals.Requests != 800 || len(hosts) != 1 || hosts[0].IPFirewallRejected != 800 {
		t.Fatalf("lost concurrent IP Firewall rejections: %+v %+v", totals, hosts)
	}
}

func TestDisabledRegistrySkipsEarlyIPFirewallAccounting(t *testing.T) {
	r := New(config.Config{})
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error { r.RecordIPFirewallRejection(c, normalizeTestHost); return nil })
	app.Handler()(requestContext("one.example", "/"))
	if r.Totals().Requests != 0 || r.Totals().IPFirewallRejected != 0 || len(r.Hosts()) != 0 {
		t.Fatal("disabled registry counted early rejections")
	}
}
