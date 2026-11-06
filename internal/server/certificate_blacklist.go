package server

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"http-proxy-firewall/internal/admin"
)

func (g *certificateGuard) CertificateBlacklistEntries() []admin.CertificateBlacklistEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneBlacklist(g.now())
	entries := make([]admin.CertificateBlacklistEntry, 0, len(g.blacklist))
	for host, until := range g.blacklist {
		entries = append(entries, admin.CertificateBlacklistEntry{Hostname: host, Expires: until.UTC()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Hostname < entries[j].Hostname })
	return entries
}

func (g *certificateGuard) RemoveCertificateBlacklistHost(raw string) error {
	host, err := certificateHostname(raw)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	until, exists := g.blacklist[host]
	if !exists {
		return nil
	}
	delete(g.blacklist, host)
	if err := g.saveBlacklist(); err != nil {
		g.blacklist[host] = until
		return err
	}
	now := g.now()
	g.verified.Set(host, false, now, now)
	g.signatures.Set(host, "", now, now)
	return nil
}

func (g *certificateGuard) loadBlacklist() error {
	info, err := os.Lstat(g.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return errors.New("certificate blacklist must be a regular file of at most 4 MiB")
	}
	file, err := os.Open(g.file)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return errors.New("certificate blacklist must be a regular file of at most 4 MiB")
	}
	now := g.now()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		raw, expiry, ok := strings.Cut(line, "|expires:")
		host, hostErr := certificateHostname(raw)
		until, timeErr := time.Parse(time.RFC3339, expiry)
		if !ok || hostErr != nil || timeErr != nil {
			return errors.New("invalid certificate blacklist entry")
		}
		if until.After(now) && until.After(g.blacklist[host]) {
			g.blacklist[host] = until
		}
		if len(g.blacklist) > certificateHostLimit {
			return errors.New("certificate blacklist exceeds hostname limit")
		}
	}
	return scanner.Err()
}

func (g *certificateGuard) pruneBlacklist(now time.Time) {
	for host, until := range g.blacklist {
		if !until.After(now) {
			delete(g.blacklist, host)
		}
	}
}

// Call with g.mu held. Replace atomically so restart cannot load a partial row.
func (g *certificateGuard) saveBlacklist() error {
	g.pruneBlacklist(g.now())
	hosts := make([]string, 0, len(g.blacklist))
	for host := range g.blacklist {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	file, err := os.CreateTemp(filepath.Dir(g.file), ".certbot.blacklist-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	writer := bufio.NewWriter(file)
	for _, host := range hosts {
		if _, err := fmt.Fprintf(writer, "%s|expires:%s\n", host, g.blacklist[host].UTC().Format(time.RFC3339Nano)); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), g.file)
}
