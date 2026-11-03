package admin

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/firewall"
)

type debugStatus struct {
	Enabled  bool   `json:"enabled"`
	Hostname string `json:"hostname"`
	ClientIP string `json:"client_ip"`
	File     string `json:"file"`
	Error    string `json:"error,omitempty"`
}

type debugHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type debugEntry struct {
	Timestamp string        `json:"timestamp"`
	ClientIP  string        `json:"client_ip"`
	Hostname  string        `json:"hostname"`
	Method    string        `json:"method"`
	URL       string        `json:"url"`
	Headers   []debugHeader `json:"headers"`
	Raw       *string       `json:"raw,omitempty"`
}

type debugBatch struct {
	logBatch
	Status  debugStatus  `json:"status"`
	Entries []debugEntry `json:"entries"`
}

// Parse the persisted text format so initial tails, live appends and rotated
// files all produce the same table data. Preserve any unparseable line verbatim.
func parseDebugEntry(line string) debugEntry {
	fallback := debugEntry{Raw: &line, Headers: []debugHeader{}}
	stamp, rest, ok := strings.Cut(line, "] FROM: ")
	if !ok || !strings.HasPrefix(stamp, "[") {
		return fallback
	}
	stamp = stamp[1:]
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		return fallback
	}
	ip, rest, ok := strings.Cut(rest, ", TO: ")
	if _, err := netip.ParseAddr(ip); !ok || err != nil {
		return fallback
	}
	host, rest, ok := strings.Cut(rest, ", ")
	if !ok || host == "" {
		return fallback
	}
	method, rest, ok := strings.Cut(rest, " ")
	if !ok || method == "" {
		return fallback
	}
	target, rest, ok := strings.Cut(rest, " [")
	if !ok || target == "" || !strings.HasSuffix(rest, "]") {
		return fallback
	}
	method, err := strconv.Unquote(`"` + method + `"`)
	if err != nil {
		return fallback
	}
	target, err = strconv.Unquote(`"` + target + `"`)
	if err != nil {
		return fallback
	}
	entry := debugEntry{Timestamp: stamp, ClientIP: ip, Hostname: host, Method: method, URL: target, Headers: []debugHeader{}}
	rest = rest[:len(rest)-1]
	for rest != "" {
		name, value, ok := strings.Cut(rest, ": ")
		if !ok || name == "" {
			return fallback
		}
		quoted, err := strconv.QuotedPrefix(value)
		if err != nil || !strings.HasPrefix(quoted, `"`) {
			return fallback
		}
		decoded, err := strconv.Unquote(quoted)
		if err != nil {
			return fallback
		}
		name, err = strconv.Unquote(`"` + name + `"`)
		if err != nil {
			return fallback
		}
		entry.Headers = append(entry.Headers, debugHeader{Name: name, Value: decoded})
		rest = value[len(quoted):]
		if rest != "" {
			rest, ok = strings.CutPrefix(rest, ", ")
			if !ok || rest == "" {
				return fallback
			}
		}
	}
	return entry
}

// One process-wide capture is shared by all admins and both listeners. Opening
// for each append supports rotation and leaves no descriptors to close on stop.
type debugLog struct {
	active atomic.Bool
	mu     sync.Mutex
	dir    string
	status debugStatus
	tail   *logTail
}

func debugHostname(raw string) (string, error) {
	return firewall.CanonicalHostnamePattern(raw)
}

func debugSourceIP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" {
		return "", errors.New("Source must be a single IPv4 or IPv6 address, or blank for all sources")
	}
	return address.Unmap().String(), nil
}

func debugMatches(pattern, host string) bool {
	return firewall.HostnameMatches(pattern, host)
}

func debugFilename(pattern, sourceIP string) string {
	stem := strings.NewReplacer("*", "wildcard", ".", "-").Replace(pattern)
	if sourceIP != "" {
		stem += "-from-" + strings.NewReplacer(":", "-", ".", "-").Replace(sourceIP)
	}
	// Bound the basename below filesystem NAME_MAX, and distinguish flattened
	// names such as a.b and a-b, or *.example and wildcard.example.
	if len(stem) > 200 {
		stem = stem[:200]
	}
	sum := sha256.Sum256([]byte(pattern + "\n" + sourceIP))
	return fmt.Sprintf("%s-%x.log", stem, sum[:8])
}

func openDebugLog(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("debug log must be a regular file, not a symlink")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
}

func (d *debugLog) set(raw, rawSourceIP string) (debugStatus, error) {
	name, err := debugHostname(raw)
	if err != nil {
		return debugStatus{}, err
	}
	sourceIP, err := debugSourceIP(rawSourceIP)
	if err != nil {
		return debugStatus{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(d.dir, 0700); err != nil {
		return debugStatus{}, err
	}
	path := filepath.Join(d.dir, debugFilename(name, sourceIP))
	file, err := openDebugLog(path)
	if err != nil {
		return debugStatus{}, err
	}
	if err := file.Close(); err != nil {
		return debugStatus{}, err
	}
	d.status = debugStatus{Enabled: true, Hostname: name, ClientIP: sourceIP, File: filepath.ToSlash(path)}
	d.tail = &logTail{path: path, maxLine: maxLogRead}
	d.active.Store(true)
	return d.status, nil
}

func (d *debugLog) snapshot(disable bool) debugStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	if disable {
		d.active.Store(false)
		d.status.Enabled = false
	}
	return d.status
}

// DebugMiddleware captures original request metadata before any firewall or
// upstream mutation, without reading bodies. Admin traffic is handled earlier.
func (h *Handler) DebugMiddleware(clientIP func(fiber.Ctx) string) fiber.Handler {
	return func(c fiber.Ctx) error {
		if h.debug.active.Load() {
			h.debug.capture(c, clientIP)
		}
		return c.Next()
	}
}

func (d *debugLog) capture(c fiber.Ctx, clientIP func(fiber.Ctx) string) {
	host, err := firewall.CanonicalHostname(string(c.Request().Header.Host()))
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.status.Enabled || !debugMatches(d.status.Hostname, host) {
		return
	}
	sourceIP := clientIP(c)
	if d.status.ClientIP != "" && sourceIP != d.status.ClientIP {
		return
	}
	var line strings.Builder
	fmt.Fprintf(&line, "[%s] FROM: %s, TO: %s, %s %s [", time.Now().UTC().Format(time.RFC3339Nano), sourceIP, host, debugEscape(string(c.Request().Header.Method())), debugEscape(string(c.Request().Header.RequestURI())))
	first := true
	c.Request().Header.VisitAll(func(key, value []byte) {
		if !first {
			line.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&line, "%s: %s", debugEscape(string(key)), strconv.QuoteToASCII(string(value)))
	})
	line.WriteString("]\n")
	file, err := openDebugLog(d.tail.path)
	if err == nil {
		_, err = file.WriteString(line.String())
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		d.status.Error = "Unable to append debug log; check disk space and log directory permissions."
	} else {
		d.status.Error = ""
	}
}

func debugEscape(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

func (h *Handler) serveDebug(c fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead:
		return c.JSON(h.debug.snapshot(false))
	case fiber.MethodPost, fiber.MethodDelete:
		// Browsers cannot add this header cross-origin without a CORS preflight.
		// Basic authentication alone would allow cross-site form submissions.
		if c.Get("X-PF-Admin") != "1" || c.Get("Sec-Fetch-Site") == "cross-site" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Same-origin admin request required"})
		}
		if c.Request().Header.ContentLength() != 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Debug controls do not accept request bodies"})
		}
		if c.Method() == fiber.MethodDelete {
			return c.JSON(h.debug.snapshot(true))
		}
		if _, err := debugHostname(c.Query("hostname")); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		if _, err := debugSourceIP(c.Query("client_ip")); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		status, err := h.debug.set(c.Query("hostname"), c.Query("client_ip"))
		if err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Unable to open debug log; check log directory permissions and disk space"})
		}
		return c.JSON(status)
	default:
		c.Set("Allow", "GET, HEAD, POST, DELETE")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
}

func (h *Handler) serveDebugLogs(c fiber.Ctx) error {
	h.debug.mu.Lock()
	defer h.debug.mu.Unlock()
	status := h.debug.status
	if h.debug.tail == nil {
		return c.JSON(debugBatch{logBatch: logBatch{Lines: []string{}, Reset: true}, Status: status, Entries: []debugEntry{}})
	}
	// Changing captures invalidates old cursors even when two files happen to
	// share a generation and offset. The UI also clears its history on change.
	cursor := c.Query("cursor")
	if c.Query("hostname") != status.Hostname || c.Query("client_ip") != status.ClientIP {
		cursor = ""
	}
	batch, err := h.debug.tail.read(cursor)
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Debug log is unavailable", "status": status})
	}
	entries := make([]debugEntry, 0, len(batch.Lines))
	for _, line := range batch.Lines {
		entries = append(entries, parseDebugEntry(line))
	}
	return c.JSON(debugBatch{logBatch: batch, Status: status, Entries: entries})
}
