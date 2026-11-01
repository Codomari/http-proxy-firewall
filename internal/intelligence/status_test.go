package intelligence

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"
)

func TestDatabaseStatusUsesActualFileModificationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.mmdb")
	s := newService(t, config.Config{Intelligence: config.Intelligence{DatabasePath: path, MaxMindLicenseKey: "private-key"}})
	if status := s.DatabaseStatus(); status.FileExists || status.LastModified != nil || !status.AutoUpdateEnabled {
		t.Fatal("missing database status incorrect")
	}
	if err := os.WriteFile(path, []byte("database fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	modified := time.Date(2026, 10, 29, 12, 30, 0, 0, time.UTC)
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	s.replaceDB(&testDatabase{})
	defer s.replaceDB(nil)
	status := s.DatabaseStatus()
	if !status.Loaded || !status.FileExists || status.LastModified == nil || !status.LastModified.Equal(modified) || status.Updating {
		t.Fatalf("wrong database metadata: %+v", status)
	}
	modified = modified.Add(time.Hour)
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	if status := s.DatabaseStatus(); status.LastModified == nil || !status.LastModified.Equal(modified) {
		t.Fatal("database timestamp was cached instead of reading file mod time")
	}
}
