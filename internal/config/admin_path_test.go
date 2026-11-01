package config

import (
	"io"
	"testing"
)

func TestAdminURIConfiguration(t *testing.T) {
	for value, want := range map[string]string{"": "/__pf/__admin", "__pf/__admin": "/__pf/__admin", "/ops/control/": "/ops/control", "Ops/CONTROL": "/ops/control"} {
		c, err := Parse(nil, map[string]string{"PF_ADMIN_URI": value}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		got, err := AdminPath(c.Admin.URI)
		if err != nil || got != want {
			t.Fatalf("admin URI %q: got %q", value, got)
		}
	}
	for _, value := range []string{"/", "../admin", "ops/../admin", "ops//admin", "https://example.test/admin", "ops/admin?x=1", "ops/%61dmin", "ops/\"admin", "ops/<admin>", "ops/admin\n"} {
		if _, err := Parse(nil, map[string]string{"PF_ADMIN_URI": value}, io.Discard); err == nil {
			t.Fatalf("invalid admin URI accepted: %q", value)
		}
	}
}
