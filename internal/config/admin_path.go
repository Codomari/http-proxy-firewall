package config

import (
	"errors"
	"path"
	"strings"
)

// AdminPath accepts the env form with or without surrounding slashes. Restrict
// characters so the same path is safe in routing, HTML attributes and JS strings.
func AdminPath(uri string) (string, error) {
	if uri == "" {
		uri = DefaultAdminURI
	}
	canonical := "/" + strings.Trim(uri, "/")
	if canonical == "/" || len(canonical) > 256 || path.Clean(canonical) != canonical {
		return "", errors.New("invalid PF_ADMIN_URI")
	}
	for _, ch := range canonical {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("/._-~", ch) {
			continue
		}
		return "", errors.New("invalid PF_ADMIN_URI")
	}
	return strings.ToLower(canonical), nil
}
