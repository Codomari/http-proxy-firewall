package admin

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
)

type restartSnapshot struct {
	Required   bool     `json:"required"`
	Available  bool     `json:"available"`
	Restarting bool     `json:"restarting"`
	Reasons    []string `json:"reasons"`
	Error      string   `json:"error,omitempty"`
}

// SetRestartHandler connects graceful process replacement before serving.
func (h *Handler) SetRestartHandler(handler func() error) { h.restart = handler }

func (h *Handler) restartStatus() restartSnapshot {
	h.generalMu.Lock()
	defer h.generalMu.Unlock()
	return h.restartStatusLocked()
}

func (h *Handler) restartStatusLocked() restartSnapshot {
	result := restartSnapshot{Available: h.restart != nil, Restarting: h.restartPending, Reasons: []string{}}
	if h.startup.Source != nil {
		next, err := h.startup.Reload()
		if err != nil {
			result.Error = "Unable to validate saved configuration. Fix the YAML before restarting."
			return result
		}
		result.Reasons = h.startup.RestartChanges(next)
	} else {
		rules, err := h.generalFile.Read()
		if err != nil {
			result.Error = "Unable to read saved settings. Fix the YAML before restarting."
			return result
		}
		gc := "off"
		if rules.GCPercent >= 0 {
			gc = strconv.Itoa(rules.GCPercent)
		}
		next, err := config.RuntimeFromValues(map[string]string{"GOGC": gc, "GOMEMLIMIT": rules.GCMemoryLimit})
		if err == nil && next != h.startup.Runtime {
			result.Reasons = append(result.Reasons, "Garbage collection")
		}
		if rules.MaxBufferedBytes != h.startup.Firewall.MaxBufferedBytes {
			result.Reasons = append(result.Reasons, "Firewall startup settings")
		}
		if rules.HTTP2Enable != h.startup.HTTP.HTTP2Enable || rules.IdleRequestTimeout != h.startup.HTTP.IdleTimeout.String() {
			result.Reasons = append(result.Reasons, "HTTP listeners and timeouts")
		}
	}
	result.Required = len(result.Reasons) > 0
	return result
}

func (h *Handler) serveRestart(c fiber.Ctx) error {
	if c.Method() != fiber.MethodPost {
		c.Set("Allow", "POST")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
	if c.Get("X-PF-Admin") != "1" || c.Get("Sec-Fetch-Site") == "cross-site" {
		return c.Status(403).JSON(fiber.Map{"error": "Same-origin admin request required"})
	}
	h.generalMu.Lock()
	defer h.generalMu.Unlock()
	state := h.restartStatusLocked()
	if state.Error != "" {
		return c.Status(503).JSON(fiber.Map{"error": state.Error})
	}
	if !state.Required || state.Restarting {
		return c.JSON(state)
	}
	if h.restart == nil {
		return c.Status(503).JSON(fiber.Map{"error": "Restart is unavailable"})
	}
	if err := h.restart(); err != nil {
		return c.Status(503).JSON(fiber.Map{"error": "Unable to request a restart"})
	}
	h.restartPending, state.Restarting = true, true
	return c.Status(fiber.StatusAccepted).JSON(state)
}
