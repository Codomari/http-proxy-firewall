package intelligence

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	maxGeoCompressedBytes   = 64 << 20
	maxGeoUncompressedBytes = 256 << 20
)

func (s *Service) refreshMaxMind(ctx context.Context) error {
	s.updating.Store(true)
	defer s.updating.Store(false)
	endpoint, err := url.Parse(s.maxMindEndpoint)
	if err != nil {
		return errors.New("invalid country database endpoint")
	}
	query := endpoint.Query()
	query.Set("edition_id", "GeoLite2-Country")
	query.Set("license_key", s.cfg.Intelligence.MaxMindLicenseKey)
	query.Set("suffix", "tar.gz")
	endpoint.RawQuery = query.Encode()
	resp, err := s.request(ctx, endpoint.String(), maxGeoCompressedBytes)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	destination := s.cfg.Intelligence.DatabasePath
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return errors.New("cannot create country database directory")
	}
	// Staging in the destination directory guarantees rename stays on one FS.
	temporary, err := os.MkdirTemp(directory, ".geo-refresh-")
	if err != nil {
		return errors.New("cannot stage country database")
	}
	defer os.RemoveAll(temporary)
	compressed := &io.LimitedReader{R: resp.Body, N: maxGeoCompressedBytes + 1}
	staged, err := extractMMDB(compressed, temporary)
	if err != nil {
		return err
	}
	if compressed.N <= 0 {
		return errors.New("compressed country database exceeds size limit")
	}
	reader, err := s.openDB(staged)
	if err != nil {
		return errors.New("downloaded country database failed validation")
	}
	if err := ctx.Err(); err != nil {
		_ = reader.Close()
		return err
	}
	if err := os.Rename(staged, destination); err != nil {
		_ = reader.Close()
		return errors.New("cannot install country database")
	}
	s.replaceDB(reader)
	return nil
}

// extractMMDB never uses archive names as filesystem paths. It rejects unsafe
// names and links, and limits both archive and individual database sizes.
func extractMMDB(source io.Reader, directory string) (string, error) {
	gz, err := gzip.NewReader(source)
	if err != nil {
		return "", errors.New("invalid country database compression")
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxGeoUncompressedBytes + 1}
	archive := tar.NewReader(limited)
	var databasePath string
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("invalid country database archive")
		}
		if !safeArchiveName(header.Name) {
			return "", errors.New("unsafe country database archive path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return "", errors.New("unsupported country database archive entry")
		}
		if path.Ext(header.Name) != ".mmdb" {
			continue
		}
		if databasePath != "" || header.Size <= 0 || header.Size > maxGeoUncompressedBytes {
			return "", errors.New("invalid country database archive contents")
		}
		databasePath = filepath.Join(directory, "database.mmdb")
		file, err := os.OpenFile(databasePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", errors.New("cannot stage extracted country database")
		}
		_, copyErr := io.CopyN(file, archive, header.Size)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			return "", errors.New("cannot write extracted country database")
		}
	}
	if limited.N <= 0 {
		return "", errors.New("expanded country database exceeds size limit")
	}
	if databasePath == "" {
		return "", errors.New("country database archive contains no database")
	}
	// Read to the gzip checksum, rejecting truncated or damaged streams even if
	// their tar end markers were complete.
	if _, err := io.Copy(io.Discard, limited); err != nil || limited.N <= 0 {
		return "", errors.New("invalid or oversized country database stream")
	}
	return databasePath, nil
}

func safeArchiveName(name string) bool {
	if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return false
		}
	}
	// Windows drive names are never legitimate archive paths for this source.
	return !strings.Contains(strings.SplitN(name, "/", 2)[0], ":")
}
