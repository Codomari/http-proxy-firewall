//go:build linux

package monitoring

import (
	"sort"
	"strings"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

func readDisks() DiskStatus {
	result := DiskStatus{Mounts: []DiskSnapshot{}}
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return result
	}
	mounts, err := fs.GetMounts()
	if err != nil {
		return result
	}
	result.Available = true
	// mountinfo escapes whitespace and backslashes using octal sequences.
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, mount := range mounts {
		_, readOnly := mount.Options["ro"]
		disk := DiskSnapshot{Mount: unescape.Replace(mount.MountPoint), Source: unescape.Replace(mount.Source), Filesystem: mount.FSType, ReadOnly: readOnly}
		var stat unix.Statfs_t
		if err := unix.Statfs(disk.Mount, &stat); err == nil && stat.Bsize > 0 {
			setDiskUsage(&disk, stat.Blocks, stat.Bfree, stat.Bavail, uint64(stat.Bsize))
		}
		result.Mounts = append(result.Mounts, disk)
	}
	sort.Slice(result.Mounts, func(i, j int) bool { return result.Mounts[i].Mount < result.Mounts[j].Mount })
	return result
}
