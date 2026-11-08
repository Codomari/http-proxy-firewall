// Package cve2026109618 bounds request parsing work to reduce exposure to PHP's
// OOM corruption paths. These limits cannot prevent application-specific OOM;
// updating PHP is the only complete mitigation.
// See https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w.
package cve2026109618

import (
	"bufio"
	"bytes"
	"errors"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
)

const DefaultMaxBodyBytes int64 = 200 << 20

var (
	ErrBodyTooLarge = errors.New("CVE-2026-109618: request body limit exceeded")
	ErrInputLimit   = errors.New("CVE-2026-109618: form parsing limit exceeded")
	ErrMalformed    = errors.New("CVE-2026-109618: malformed or ambiguous form data")
)

// Limits apply to every request, including chunked requests. Parts and headers
// include duplicates; files include empty filename controls that PHP does not
// count towards max_file_uploads. Nonpositive values select conservative defaults.
type Limits struct {
	MaxBodyBytes       int64
	MaxParts           int
	MaxFiles           int
	MaxHeadersPerPart  int
	MaxPartHeaderBytes int
	MaxInputNesting    int
}

func (l Limits) WithDefaults() Limits {
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if l.MaxParts <= 0 {
		l.MaxParts = 1000
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = 20
	}
	if l.MaxHeadersPerPart <= 0 {
		l.MaxHeadersPerPart = 16
	}
	if l.MaxPartHeaderBytes <= 0 {
		l.MaxPartHeaderBytes = 16 << 10
	}
	if l.MaxInputNesting <= 0 {
		l.MaxInputNesting = 16
	}
	return l
}

// Check validates a fully buffered, transfer-decoded body and returns non-file
// multipart field names for the session upload progress check. It never parses
// field values, decompresses data, creates temporary files or mutates the body.
func Check(body []byte, contentType string, limits Limits) ([]string, error) {
	limits = limits.WithDefaults()
	if int64(len(body)) > limits.MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	if contentType == "" {
		return nil, nil
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, ErrMalformed
	}
	switch mediaType {
	case "multipart/form-data":
		boundary := params["boundary"]
		// Use the standard library's boundary constraints (including length).
		var validator multipart.Writer
		if validator.SetBoundary(boundary) != nil {
			return nil, ErrMalformed
		}
		return checkMultipart(body, boundary, limits)
	case "application/x-www-form-urlencoded":
		return nil, checkURLEncoded(body, limits)
	default:
		if strings.HasPrefix(mediaType, "multipart/") {
			return nil, ErrMalformed
		}
		return nil, nil
	}
}

func checkURLEncoded(body []byte, limits Limits) error {
	for count := 0; len(body) > 0; {
		var field []byte
		field, body, _ = bytes.Cut(body, []byte("&"))
		if len(field) == 0 {
			continue
		}
		count++
		if count > limits.MaxParts {
			return ErrInputLimit
		}
		name, _, _ := bytes.Cut(field, []byte("="))
		decoded, err := url.QueryUnescape(string(name))
		if err != nil || strings.ContainsAny(decoded, "\x00\r\n") {
			return ErrMalformed
		}
		if strings.Count(decoded, "[") > limits.MaxInputNesting {
			return ErrInputLimit
		}
	}
	return nil
}

// Accept a strict multipart framing shared by PHP and the proxy. In particular,
// PHP may scan past a closing boundary that Go treats as EOF. Reject preambles,
// epilogues, bare LF boundaries and boundary prefixes embedded in file data
// rather than letting another parser discover uninspected parts.
func checkMultipart(body []byte, boundary string, limits Limits) ([]string, error) {
	marker := []byte("--" + boundary)
	if !bytes.HasPrefix(body, marker) {
		return nil, ErrMalformed
	}
	rest := body[len(marker):]
	separator := []byte("\n--" + boundary)
	var fields []string
	parts, files := 0, 0
	for {
		if bytes.HasPrefix(rest, []byte("--")) {
			tail := rest[2:]
			if len(tail) != 0 && !bytes.Equal(tail, []byte("\r\n")) {
				return nil, ErrMalformed
			}
			return fields, nil
		}
		if !bytes.HasPrefix(rest, []byte("\r\n")) {
			return nil, ErrMalformed
		}
		rest = rest[2:]
		end := bytes.Index(rest, separator)
		if end < 1 || rest[end-1] != '\r' {
			return nil, ErrMalformed
		}
		part := rest[:end-1]
		rest = rest[end+len(separator):]
		parts++
		if parts > limits.MaxParts {
			return nil, ErrInputLimit
		}
		name, isFile, err := checkPart(part, limits)
		if err != nil {
			return nil, err
		}
		if isFile {
			files++
			if files > limits.MaxFiles {
				return nil, ErrInputLimit
			}
		} else {
			fields = append(fields, name)
		}
	}
}

func checkPart(part []byte, limits Limits) (string, bool, error) {
	end := bytes.Index(part, []byte("\r\n\r\n"))
	if end < 0 {
		return "", false, ErrMalformed
	}
	if end+4 > limits.MaxPartHeaderBytes {
		return "", false, ErrInputLimit
	}
	headers := part[:end]
	lines := bytes.Split(headers, []byte("\r\n"))
	if len(lines) > limits.MaxHeadersPerPart {
		return "", false, ErrInputLimit
	}
	for _, line := range lines {
		// Folded headers are combined differently by PHP and MIME parsers.
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' || bytes.ContainsAny(line, "\x00\r\n") {
			return "", false, ErrMalformed
		}
	}
	parsed, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(part[:end+4]))).ReadMIMEHeader()
	if err != nil || len(parsed.Values("Content-Disposition")) != 1 || len(parsed.Values("Content-Type")) > 1 {
		return "", false, ErrMalformed
	}
	disposition := parsed.Get("Content-Disposition")
	kind, params, err := mime.ParseMediaType(disposition)
	if err != nil || kind != "form-data" || !unambiguousDisposition(disposition) {
		return "", false, ErrMalformed
	}
	name, hasName := params["name"]
	if !hasName || name == "" || strings.ContainsAny(name, "\x00\r\n") {
		return "", false, ErrMalformed
	}
	if strings.Count(name, "[") > limits.MaxInputNesting {
		return "", false, ErrInputLimit
	}
	if strings.HasPrefix(strings.ToLower(parsed.Get("Content-Type")), "multipart/") {
		return "", false, ErrMalformed
	}
	_, isFile := params["filename"] // filename="" is still a file control.
	return name, isFile, nil
}

// Restrict disposition parameters to a grammar PHP and mime.ParseMediaType
// interpret alike. PHP accepts single-quoted values and ignores RFC 2231 name*
// and filename*, whereas Go decodes them. Duplicate parameters are ambiguous.
func unambiguousDisposition(value string) bool {
	_, rest, _ := strings.Cut(value, ";")
	seen := make(map[string]bool, 2)
	for rest != "" {
		rest = strings.TrimSpace(rest)
		key, after, ok := strings.Cut(rest, "=")
		key = strings.ToLower(key)
		if !ok || (key != "name" && key != "filename") || seen[key] {
			return false
		}
		seen[key] = true
		rest = strings.TrimLeft(after, " \t")
		if strings.HasPrefix(rest, "\"") {
			rest = rest[1:]
			closed := false
			for len(rest) > 0 {
				c := rest[0]
				rest = rest[1:]
				if c == '\\' && len(rest) > 0 {
					rest = rest[1:]
				} else if c == '"' {
					closed = true
					break
				}
			}
			if !closed {
				return false
			}
		} else {
			var token string
			token, rest, _ = strings.Cut(rest, ";")
			if strings.ContainsAny(token, "'\\") {
				return false
			}
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if rest != "" {
			if rest[0] != ';' {
				return false
			}
			rest = rest[1:]
		}
	}
	return true
}
