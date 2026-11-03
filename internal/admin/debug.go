package admin

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/observability"
)

type debugStatus struct {
	Enabled  bool          `json:"enabled"`
	Hostname string        `json:"hostname"`
	ClientIP string        `json:"client_ip"`
	File     string        `json:"file"`
	Error    string        `json:"error,omitempty"`
	Captures []debugStatus `json:"captures,omitempty"`
}

type debugHeader = observability.CapturedHeader

type debugResult struct {
	DurationMS float64                        `json:"duration_ms"`
	Response   observability.CapturedResponse `json:"response"`
}

type debugEntry struct {
	Timestamp  string                          `json:"timestamp"`
	ClientIP   string                          `json:"client_ip"`
	Hostname   string                          `json:"hostname"`
	Method     string                          `json:"method"`
	URL        string                          `json:"url"`
	Headers    []debugHeader                   `json:"headers"`
	Raw        *string                         `json:"raw,omitempty"`
	DurationMS *float64                        `json:"duration_ms,omitempty"`
	Response   *observability.CapturedResponse `json:"response,omitempty"`
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
	if !ok || target == "" {
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
	for !strings.HasPrefix(rest, "]") {
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
		if !strings.HasPrefix(rest, "]") {
			rest, ok = strings.CutPrefix(rest, ", ")
			if !ok || rest == "" {
				return fallback
			}
		}
	}
	rest = rest[1:]
	if rest != "" {
		payload, ok := strings.CutPrefix(rest, " | ")
		var result debugResult
		if !ok || json.Unmarshal([]byte(payload), &result) != nil || result.DurationMS < 0 || result.Response.Status < 100 || result.Response.Status > 599 || result.Response.Headers == nil || (result.Response.BodyEncoding != "utf-8" && result.Response.BodyEncoding != "base64") {
			return fallback
		}
		entry.DurationMS, entry.Response = &result.DurationMS, &result.Response
	}
	return entry
}

// One process-wide capture is shared by all admins and both listeners. Opening
// for each append supports rotation and leaves no descriptors to close on stop.
type debugLog struct {
	active   atomic.Bool
	mu       sync.Mutex
	dir      string
	status   debugStatus
	tail     *logTail
	store    *config.YAMLStore
	captures map[string]*debugCapture
}

type debugCapture struct {
	status debugStatus
	tail   *logTail
}

func debugKey(host, source string) string { return host + "\n" + source }

func (d *debugLog) loadConfig(store *config.YAMLStore) error {
	document, err := store.Read()
	if err != nil {
		return err
	}
	d.captures = make(map[string]*debugCapture)
	for _, capture := range document.Debug {
		host, err := debugHostname(capture.Host)
		if err != nil {
			return err
		}
		source, err := debugSourceIP(capture.Source)
		if err != nil {
			return err
		}
		path := filepath.Join(d.dir, debugFilename(host, source))
		if capture.LogFile != nil && *capture.LogFile != "" {
			path = *capture.LogFile
		}
		enabled := capture.Enabled != nil && *capture.Enabled
		if enabled {
			if _, err := d.setPath(host, source, path); err != nil {
				return err
			}
		} else {
			state := &debugCapture{status: debugStatus{Hostname: host, ClientIP: source, File: filepath.ToSlash(path)}}
			if _, err := os.Stat(path); err == nil {
				state.tail = &logTail{path: path, maxLine: maxLogRead}
			}
			d.captures[debugKey(host, source)] = state
			if d.status.Hostname == "" {
				d.status, d.tail = state.status, state.tail
			}
		}
	}
	d.store = store
	return nil
}

func (d *debugLog) statusLocked(state *debugCapture) debugStatus {
	status := d.status
	if state != nil {
		status = state.status
	}
	status.Captures = []debugStatus{}
	for _, capture := range d.captures {
		status.Captures = append(status.Captures, capture.status)
	}
	sort.Slice(status.Captures, func(i, j int) bool {
		return debugKey(status.Captures[i].Hostname, status.Captures[i].ClientIP) < debugKey(status.Captures[j].Hostname, status.Captures[j].ClientIP)
	})
	return status
}

func (d *debugLog) refreshActiveLocked() {
	active := false
	for _, capture := range d.captures {
		active = active || capture.status.Enabled
	}
	d.active.Store(active)
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
	return d.setPath(raw, rawSourceIP, "")
}

func (d *debugLog) setPath(raw, rawSourceIP, path string) (debugStatus, error) {
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
	if d.captures == nil {
		d.captures = make(map[string]*debugCapture)
	}
	key := debugKey(name, sourceIP)
	if path == "" {
		if current := d.captures[key]; current != nil {
			path = current.status.File
		}
		if path == "" {
			path = filepath.Join(d.dir, debugFilename(name, sourceIP))
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return debugStatus{}, err
	}
	file, err := openDebugLog(path)
	if err != nil {
		return debugStatus{}, err
	}
	if err := file.Close(); err != nil {
		return debugStatus{}, err
	}
	if d.store != nil {
		enabled := true
		if err := d.store.SetDebug(config.DebugCapture{Host: name, Source: sourceIP, Enabled: &enabled, LogFile: &path}); err != nil {
			return debugStatus{}, err
		}
	}
	state := &debugCapture{status: debugStatus{Enabled: true, Hostname: name, ClientIP: sourceIP, File: filepath.ToSlash(path)}, tail: &logTail{path: path, maxLine: maxLogRead}}
	d.captures[key] = state
	d.status, d.tail = state.status, state.tail
	d.refreshActiveLocked()
	return d.statusLocked(state), nil
}

func (d *debugLog) snapshot(disable bool) debugStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	if disable {
		if capture := d.captures[debugKey(d.status.Hostname, d.status.ClientIP)]; capture != nil {
			capture.status.Enabled = false
			d.status = capture.status
		}
		d.refreshActiveLocked()
	}
	return d.statusLocked(nil)
}

func (d *debugLog) disable(host, source string) (debugStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if host == "" {
		host, source = d.status.Hostname, d.status.ClientIP
	}
	state := d.captures[debugKey(host, source)]
	if state == nil {
		return d.statusLocked(nil), nil
	}
	if d.store != nil {
		enabled := false
		if err := d.store.SetDebug(config.DebugCapture{Host: host, Source: source, Enabled: &enabled}); err != nil {
			return debugStatus{}, err
		}
	}
	state.status.Enabled = false
	d.status, d.tail = state.status, state.tail
	d.refreshActiveLocked()
	return d.statusLocked(state), nil
}

// DebugMiddleware snapshots original request metadata before firewall/upstream
// mutation, then logs the completed response. Admin traffic is handled earlier.
func (h *Handler) DebugMiddleware(clientIP func(fiber.Ctx) string) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !h.debug.active.Load() {
			return c.Next()
		}
		started := time.Now()
		line, tails := h.debug.capture(c, clientIP, started)
		if len(tails) == 0 {
			return c.Next()
		}
		capture := observability.CaptureResponse(c, started, func(duration time.Duration, response observability.CapturedResponse) {
			result, err := json.Marshal(debugResult{DurationMS: float64(duration) / float64(time.Millisecond), Response: response})
			if err == nil {
				for _, tail := range tails {
					h.debug.append(tail, line+" | "+string(result)+"\n")
				}
			}
		})
		err := c.Next()
		if err != nil {
			// Finalize Fiber errors before capturing their actual status and body.
			err = c.App().ErrorHandler(c, err)
		}
		capture.Prepare(c)
		return err
	}
}

func (d *debugLog) capture(c fiber.Ctx, clientIP func(fiber.Ctx) string, started time.Time) (string, []*logTail) {
	host, err := firewall.CanonicalHostname(string(c.Request().Header.Host()))
	if err != nil {
		return "", nil
	}
	sourceIP := clientIP(c)
	d.mu.Lock()
	defer d.mu.Unlock()
	var tails []*logTail
	for _, capture := range d.captures {
		status := capture.status
		if status.Enabled && debugMatches(status.Hostname, host) && (status.ClientIP == "" || status.ClientIP == sourceIP) {
			tails = append(tails, capture.tail)
		}
	}
	if len(tails) == 0 {
		return "", nil
	}
	var line strings.Builder
	fmt.Fprintf(&line, "[%s] FROM: %s, TO: %s, %s %s [", started.UTC().Format(time.RFC3339Nano), sourceIP, host, debugEscape(string(c.Request().Header.Method())), debugEscape(string(c.Request().Header.RequestURI())))
	first := true
	c.Request().Header.VisitAll(func(key, value []byte) {
		if !first {
			line.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&line, "%s: %s", debugEscape(string(key)), strconv.QuoteToASCII(string(value)))
	})
	line.WriteString("]")
	return line.String(), tails
}

func (d *debugLog) append(tail *logTail, line string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// An accepted request retains its original destination when the capture is
	// changed or disabled while an upstream response is still in flight.
	file, err := openDebugLog(tail.path)
	if err == nil {
		_, err = file.WriteString(line)
		err = errors.Join(err, file.Close())
	}
	for _, capture := range d.captures {
		if capture.tail != tail {
			continue
		}
		capture.status.Error = ""
		if err != nil {
			capture.status.Error = "Unable to append debug log; check disk space and log directory permissions."
		}
		if d.tail == tail {
			d.status = capture.status
		}
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
			host, source := c.Query("hostname"), c.Query("client_ip")
			if host != "" {
				var err error
				host, err = debugHostname(host)
				if err != nil {
					return c.Status(400).JSON(fiber.Map{"error": err.Error()})
				}
				source, err = debugSourceIP(source)
				if err != nil {
					return c.Status(400).JSON(fiber.Map{"error": err.Error()})
				}
			}
			status, err := h.debug.disable(host, source)
			if err != nil {
				return c.Status(503).JSON(fiber.Map{"error": "Unable to save debug settings to override YAML"})
			}
			return c.JSON(status)
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
	state := h.debug.captures[debugKey(c.Query("hostname"), c.Query("client_ip"))]
	status := h.debug.statusLocked(state)
	tail := h.debug.tail
	if state != nil {
		tail = state.tail
	}
	if tail == nil {
		return c.JSON(debugBatch{logBatch: logBatch{Lines: []string{}, Reset: true}, Status: status, Entries: []debugEntry{}})
	}
	cursor := c.Query("cursor")
	if c.Query("hostname") != status.Hostname || c.Query("client_ip") != status.ClientIP {
		cursor = ""
	}
	batch, err := tail.read(cursor)
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Debug log is unavailable", "status": status})
	}
	entries := make([]debugEntry, 0, len(batch.Lines))
	for _, line := range batch.Lines {
		entries = append(entries, parseDebugEntry(line))
	}
	return c.JSON(debugBatch{logBatch: batch, Status: status, Entries: entries})
}
