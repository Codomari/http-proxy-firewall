// Package buildinfo exposes the release version embedded by the Go compiler.
package buildinfo

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

var Version = strings.TrimSpace(versionFile)
