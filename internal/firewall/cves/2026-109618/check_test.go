package cve2026109618

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const testBoundary = "test-boundary"
const testContentType = "multipart/form-data; boundary=" + testBoundary

func form(parts ...string) []byte {
	var body strings.Builder
	for _, part := range parts {
		body.WriteString("--" + testBoundary + "\r\n" + part + "\r\n")
	}
	body.WriteString("--" + testBoundary + "--\r\n")
	return []byte(body.String())
}

func field(disposition string) string {
	return "Content-Disposition: " + disposition + "\r\n\r\nvalue"
}

func TestCheckMultipartReturnsOnlyNonFileFieldNames(t *testing.T) {
	body := form(
		field(`form-data; name="title"`),
		field(`form-data; name=title`),
		field(`form-data; name="attachment"; filename="O'Brien.txt"`),
		field(`form-data; name="empty"; filename=""`),
		field(`FORM-DATA; NAME="PHP_SESSION_UPLOAD_PROGRESS"`),
	)
	before := bytes.Clone(body)
	names, err := Check(body, testContentType, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "title,title,PHP_SESSION_UPLOAD_PROGRESS" {
		t.Fatalf("unexpected non-file names: %q", names)
	}
	if !bytes.Equal(body, before) {
		t.Fatal("inspection changed the body")
	}
}

func TestCheckLimitsParsingWork(t *testing.T) {
	tests := []struct {
		name   string
		body   []byte
		limits Limits
	}{
		{"body", form(field(`form-data; name="x"`)), Limits{MaxBodyBytes: 20}},
		{"duplicate fields", form(field(`form-data; name="x"`), field(`form-data; name="x"`)), Limits{MaxParts: 1}},
		{"empty files", form(field(`form-data; name="x"; filename=""`), field(`form-data; name="x"; filename=""`)), Limits{MaxFiles: 1}},
		{"files count towards parts", form(field(`form-data; name="x"; filename="a"`), field(`form-data; name="y"; filename="b"`)), Limits{MaxParts: 1}},
		{"nesting", form(field(`form-data; name="x[a][b]"`)), Limits{MaxInputNesting: 1}},
		{"file nesting", form(field(`form-data; name="x[a][b]"; filename=""`)), Limits{MaxInputNesting: 1}},
		{"headers", form("Content-Disposition: form-data; name=\"x\"\r\nX-A: a\r\nX-B: b\r\n\r\nx"), Limits{MaxHeadersPerPart: 2}},
		{"duplicate headers", form("Content-Disposition: form-data; name=\"x\"\r\nX-A: a\r\nX-A: b\r\n\r\nx"), Limits{MaxHeadersPerPart: 2}},
		{"header bytes", form(field(`form-data; name="` + strings.Repeat("x", 50) + `"`)), Limits{MaxPartHeaderBytes: 60}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Check(tt.body, testContentType, tt.limits)
			if !errors.Is(err, ErrBodyTooLarge) && !errors.Is(err, ErrInputLimit) {
				t.Fatalf("expected resource limit, got %v", err)
			}
		})
	}
}

func TestCheckRejectsMultipartParserAmbiguities(t *testing.T) {
	ordinary := form(field(`form-data; name="x"`))
	tests := map[string][]byte{
		"preamble":                   append([]byte("preamble\r\n"), ordinary...),
		"epilogue with hidden field": append(bytes.Clone(ordinary), form(field(`form-data; name="PHP_SESSION_UPLOAD_PROGRESS"`))...),
		"truncated":                  ordinary[:len(ordinary)-10],
		"bare LF":                    bytes.ReplaceAll(ordinary, []byte("\r\n"), []byte("\n")),
		"boundary prefix in data":    form(field(`form-data; name="x"`) + "\n--" + testBoundary + "extra"),
		"folded disposition":         form("Content-Disposition: form-data;\r\n name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx"),
		"duplicate disposition":      form("Content-Disposition: form-data; name=\"x\"\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx"),
		"duplicate name":             form(field(`form-data; name="x"; name="PHP_SESSION_UPLOAD_PROGRESS"`)),
		"repeated identical name":    form(field(`form-data; name="x"; name="x"`)),
		"single quoted name":         form(field(`form-data; name='PHP_SESSION_UPLOAD_PROGRESS'`)),
		"single quote in token":      form(field(`form-data; name=x'PHP_SESSION_UPLOAD_PROGRESS'`)),
		"extended name":              form(field(`form-data; name="PHP_SESSION_UPLOAD_PROGRESS"; name*=UTF-8''safe`)),
		"extended filename":          form(field(`form-data; name="PHP_SESSION_UPLOAD_PROGRESS"; filename*=UTF-8''file.txt`)),
		"NUL in name":                form(field("form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\x00suffix\"")),
		"missing name":               form(field(`form-data; filename="file.txt"`)),
		"non-form disposition":       form(field(`attachment; name="PHP_SESSION_UPLOAD_PROGRESS"`)),
		"nested multipart":           form("Content-Disposition: form-data; name=\"x\"\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\nx"),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Check(body, testContentType, Limits{}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("expected malformed rejection, got %v", err)
			}
		})
	}
}

func TestCheckURLEncodedLimitsDecodedNames(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{"ordinary", "title=one&file=x", nil},
		{"duplicates", "x=1&x=2&x=3", ErrInputLimit},
		{"encoded nesting", "x%5Ba%5D%5Bb%5D=1", ErrInputLimit},
		{"malformed name", "x%=1", ErrMalformed},
		{"NUL name", "x%00=1", ErrMalformed},
		{"empty separators", "&&&x=1&&&", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Check([]byte(tt.body), "application/x-www-form-urlencoded", Limits{MaxParts: 2, MaxInputNesting: 1})
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, err)
			}
		})
	}
}

func TestCheckContentTypesAndExactLimits(t *testing.T) {
	for _, contentType := range []string{"", "application/json", "application/octet-stream"} {
		if _, err := Check([]byte("1234"), contentType, Limits{MaxBodyBytes: 4}); err != nil {
			t.Fatalf("exact limit with %q: %v", contentType, err)
		}
	}
	for _, contentType := range []string{"multipart/form-data", "multipart/form-data; boundary=", "multipart/mixed; boundary=b", "multipart/form-data; boundary=" + strings.Repeat("b", 71)} {
		if _, err := Check(nil, contentType, Limits{}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("expected malformed content type %q, got %v", contentType, err)
		}
	}
	if names, err := Check(form(), testContentType, Limits{}); err != nil || len(names) != 0 {
		t.Fatalf("empty multipart: %q, %v", names, err)
	}
	if _, err := Check(form(field(`form-data; name="x[a]"; filename=""`)), testContentType, Limits{MaxParts: 1, MaxFiles: 1, MaxInputNesting: 1}); err != nil {
		t.Fatalf("exact structural limits: %v", err)
	}
}
