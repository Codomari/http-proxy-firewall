//go:build darwin

package monitoring

import (
	"sort"

	"golang.org/x/sys/unix"
)

func readDisks() DiskStatus {
	result := DiskStatus{Mounts: []DiskSnapshot{}}
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return result
	}
	stats := make([]unix.Statfs_t, n+16)
	n, err = unix.Getfsstat(stats, unix.MNT_NOWAIT)
	if err != nil {
		return result
	}
	result.Available = true
	for _, stat := range stats[:min(n, len(stats))] {
		disk := DiskSnapshot{Mount: unix.ByteSliceToString(stat.Mntonname[:]), Source: unix.ByteSliceToString(stat.Mntfromname[:]), Filesystem: unix.ByteSliceToString(stat.Fstypename[:]), ReadOnly: stat.Flags&unix.MNT_RDONLY != 0}
		setDiskUsage(&disk, stat.Blocks, stat.Bfree, stat.Bavail, uint64(stat.Bsize))
		result.Mounts = append(result.Mounts, disk)
	}
	sort.Slice(result.Mounts, func(i, j int) bool { return result.Mounts[i].Mount < result.Mounts[j].Mount })
	return result
}
