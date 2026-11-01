package intelligence

import (
	"os"
	"time"
)

type DatabaseSnapshot struct {
	Loaded            bool       `json:"loaded"`
	FileExists        bool       `json:"file_exists"`
	AutoUpdateEnabled bool       `json:"auto_update_enabled"`
	Updating          bool       `json:"updating"`
	LastModified      *time.Time `json:"last_modified"`
}

// DatabaseStatus uses the installed file's modification time, not polling time.
func (s *Service) DatabaseStatus() DatabaseSnapshot {
	s.dbMu.RLock()
	loaded := s.db != nil
	s.dbMu.RUnlock()
	result := DatabaseSnapshot{Loaded: loaded, AutoUpdateEnabled: s.cfg.Intelligence.MaxMindLicenseKey != "" && s.cfg.Intelligence.DatabasePath != "", Updating: s.updating.Load()}
	if info, err := os.Stat(s.cfg.Intelligence.DatabasePath); err == nil && info.Mode().IsRegular() {
		modified := info.ModTime().UTC()
		result.FileExists, result.LastModified = true, &modified
	}
	return result
}
