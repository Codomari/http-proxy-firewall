//go:build linux

package monitoring

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/procfs"
)

func TestProcResourceUnitsAndGuestAccounting(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"stat":    "cpu 100 20 30 400 50 6 7 8 9 10\n",
		"meminfo": "MemTotal: 1000 kB\nMemAvailable: 400 kB\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fs, err := procfs.NewFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	reading := readProcResources(fs)
	if reading.totalSeconds == nil || math.Abs(*reading.totalSeconds-6.21) > 0.00001 || *reading.idleSeconds != 4.5 || *reading.memoryBytes != 1000*1024 || *reading.availableBytes != 400*1024 {
		t.Fatalf("incorrect proc resource units or double-counted guest CPU: %+v", reading)
	}
}
