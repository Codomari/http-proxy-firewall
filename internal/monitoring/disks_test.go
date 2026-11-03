package monitoring

import (
	"math"
	"runtime"
	"testing"

	"http-proxy-firewall/internal/config"
)

func TestDiskUsageReservedBlocksAndUnavailable(t *testing.T) {
	var disk DiskSnapshot
	setDiskUsage(&disk, 100, 40, 30, 1024)
	if *disk.TotalBytes != 102400 || *disk.UsedBytes != 61440 || *disk.AvailableBytes != 30720 || math.Abs(*disk.UsedPercent-66.6666667) > 0.001 {
		t.Fatalf("wrong disk units or reserved-space percentage: %+v", disk)
	}
	var empty DiskSnapshot
	setDiskUsage(&empty, 0, 0, 0, 4096)
	if empty.TotalBytes != nil || empty.UsedPercent != nil {
		t.Fatal("virtual filesystem reported as empty disk")
	}
}

func TestNativeMountSnapshotAndCache(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("mount enumeration unsupported on this OS")
	}
	r := New(config.Defaults())
	first := r.Disks()
	if !first.Available || len(first.Mounts) == 0 {
		t.Fatal("native mount enumeration unavailable")
	}
	found := false
	for _, disk := range first.Mounts {
		if disk.Mount == "/" {
			found = true
			if disk.TotalBytes == nil || *disk.TotalBytes == 0 {
				t.Fatal("root capacity unavailable")
			}
		}
		if disk.UsedPercent != nil && (*disk.UsedPercent < 0 || *disk.UsedPercent > 100) {
			t.Fatal("invalid disk usage")
		}
	}
	if !found {
		t.Fatal("root mount missing")
	}
	at := r.disks.at
	second := r.Disks()
	if !r.disks.at.Equal(at) || len(second.Mounts) != len(first.Mounts) {
		t.Fatal("disk results not cached")
	}
}
