//go:build linux

package monitoring

import "github.com/prometheus/procfs"

func readResources() resourceReading {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return resourceReading{}
	}
	return readProcResources(fs)
}

func readProcResources(fs procfs.FS) resourceReading {
	var result resourceReading
	if process, err := fs.Self(); err == nil {
		if stat, err := process.Stat(); err == nil {
			seconds := stat.CPUTime()
			result.processSeconds = &seconds
			if resident := stat.ResidentMemory(); resident >= 0 {
				bytes := uint64(resident)
				result.residentBytes = &bytes
			}
		}
	}
	if stat, err := fs.Stat(); err == nil {
		cpu := stat.CPUTotal
		// Guest times are already included in User and Nice; do not count twice.
		total := cpu.User + cpu.Nice + cpu.System + cpu.Idle + cpu.Iowait + cpu.IRQ + cpu.SoftIRQ + cpu.Steal
		idle := cpu.Idle + cpu.Iowait
		result.totalSeconds, result.idleSeconds = &total, &idle
	}
	if memory, err := fs.Meminfo(); err == nil {
		result.memoryBytes, result.availableBytes = memory.MemTotalBytes, memory.MemAvailableBytes
	}
	return result
}
