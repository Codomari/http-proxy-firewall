package firewall

import (
	"net/netip"
	"slices"
	"strings"

	"http-proxy-firewall/internal/ipfirewall"

	"github.com/gofiber/fiber/v3"
)

type ipFirewallSource interface {
	Match(netip.Addr, []string) string
	IsCloudflareWorker(netip.Addr, netip.Addr, bool) bool
	Status() ipfirewall.Status
}

const StatusIPFirewallRejected = 444

// SetIPFirewall connects the app's background worker before serving requests.
func (e *Engine) SetIPFirewall(source ipFirewallSource) { e.ipFirewall = source }

// SetIPFirewallRejectionHandler connects early-drop accounting before serving.
func (e *Engine) SetIPFirewallRejectionHandler(handler func(fiber.Ctx)) { e.ipRejection = handler }

func (e *Engine) IPFirewallStatus() ipfirewall.Status {
	if e.ipFirewall != nil {
		return e.ipFirewall.Status()
	}
	return ipfirewall.New("", nil).Status()
}

type ipFirewallDecisionKey struct{}
type ipFirewallDecision struct {
	matched, bypass bool
	blocked         bool
}

func (e *Engine) ipDecision(c fiber.Ctx) ipFirewallDecision {
	if decision, ok := c.Locals(ipFirewallDecisionKey{}).(ipFirewallDecision); ok {
		return decision
	}
	ip := e.clientAddress(c)
	rules := e.general.Load()
	matched, bypass := e.whitelistWithRules(c.Context(), ip, rules)
	decision := ipFirewallDecision{matched: matched, bypass: bypass}
	if !matched {
		decision.blocked = rules.blocked.Contains(ip)
		if !decision.blocked && e.ipFirewall != nil {
			selected := rules.settings.IPFirewallProviders
			if slices.Contains(selected, "gcp") && e.intelligence != nil && e.intelligence.IsGoogleBot(ip) {
				selected = slices.DeleteFunc(slices.Clone(selected), func(id string) bool { return id == "gcp" })
			}
			decision.blocked = e.ipFirewall.Match(ip, selected) != ""
			for _, id := range rules.settings.IPFirewallProviders {
				if id == "cloudflare_workers" {
					peer, _ := netip.AddrFromSlice(c.RequestCtx().RemoteIP())
					decision.blocked = decision.blocked || e.ipFirewall.IsCloudflareWorker(peer.Unmap(), ip, strings.TrimSpace(c.Get("CF-Worker")) != "")
				}
			}
		}
	}
	c.Locals(ipFirewallDecisionKey{}, decision)
	return decision
}

// IPFirewallHandler runs before local routes, body inspection and admission.
// A whitelist match wins even when its cookie-checkpoint switch is enabled.
func (e *Engine) IPFirewallHandler(c fiber.Ctx) error {
	if rejected, err := e.RejectIPFirewall(c); rejected {
		return err
	}
	return c.Next()
}

// RejectIPFirewall also protects responses generated before Fiber routing,
// such as restart and missing-SNI pages. The decision is shared with middleware.
func (e *Engine) RejectIPFirewall(c fiber.Ctx) (bool, error) {
	if e.ipDecision(c).blocked {
		return true, e.rejectIP(c)
	}
	return false, nil
}

func (e *Engine) rejectIP(c fiber.Ctx) error {
	if e.ipRejection != nil {
		e.ipRejection(c)
	}
	c.Response().Header.SetConnectionClose()
	c.Response().Header.SetStatusMessage([]byte("No Response"))
	c.Response().Header.SetContentLength(0)
	return c.Status(StatusIPFirewallRejected).Send(nil)
}
