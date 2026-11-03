//go:build !linux && !darwin

package monitoring

func readDisks() DiskStatus { return DiskStatus{Mounts: []DiskSnapshot{}} }
